package analysis

import (
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/arbhalerao/cadutrace/internal/analysis/cfdptrack"
	"github.com/arbhalerao/cadutrace/internal/analysis/gap"
	"github.com/arbhalerao/cadutrace/internal/appdecoder"
	"github.com/arbhalerao/cadutrace/internal/appdecoder/cfdp"
	"github.com/arbhalerao/cadutrace/internal/decode"
	"github.com/arbhalerao/cadutrace/internal/decode/clcw"
	"github.com/arbhalerao/cadutrace/internal/decode/encap"
	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
	"github.com/arbhalerao/cadutrace/pkg/obs"
	"github.com/arbhalerao/cadutrace/pkg/plugin"
)

const packetSeqModulus = 1 << 14 // modulus of the 14-bit packet sequence count

// Config configures an Engine; all fields are optional
type Config struct {
	Logger    *slog.Logger
	Bus       *EventBus
	SeqWindow int // recent-value window for duplicate vs reorder (default 16)

	// Registry, when set, enables application decoding (CFDP)
	Registry *appdecoder.Registry
}

// Engine accumulates analysis state
type Engine struct {
	log    *slog.Logger
	bus    *EventBus
	window int

	frames, tmFrames, aosFrames, idleFrames uint64
	decodeErrors, caduBytes                 uint64
	crcFailures                             uint64
	suspect                                 map[vcKey]*suspectAccum

	packets, idlePackets, truncated, malformed, packetBytes uint64
	seqGaps, missing, duplicates, reorders                  uint64

	encapPackets, encapBytes uint64 // Encapsulation Packets, tracked apart from Space Packets

	apids  map[ccsdsdefs.APID]*apidAccum
	seqs   map[seqKey]*seqState
	tl     timeline
	encap  map[uint8]*encapAccum
	seenVC map[vcKey]bool
	clcw   map[vcKey]*clcwAccum

	// application decoding / CFDP (nil when no registry is configured)
	registry  *appdecoder.Registry
	decodeCtx plugin.DecodeContext
	cfdp      *cfdptrack.Tracker
}

type vcKey struct {
	scid ccsdsdefs.SCID
	vcid ccsdsdefs.VCID
}

// seqKey scopes sequence tracking to one APID on one VC, so a stream copied onto a
// second VC (e.g. realtime and playback) is checked as its own stream
type seqKey struct {
	vc   vcKey
	apid ccsdsdefs.APID
}

type seqState struct {
	tr        *gap.Tracker
	last      time.Time
	lossEpoch uint64
}

type suspectAccum struct {
	tfvn   ccsdsdefs.TFVN
	frames uint64
}

type clcwAccum struct {
	frames uint64
	last   clcw.CLCW
}

type encapAccum struct {
	count, bytes uint64
}

type apidAccum struct {
	apid              ccsdsdefs.APID
	count, bytes      uint64
	minLen, maxLen    int
	sumLen            uint64
	vcs               map[ccsdsdefs.VCID]bool
	seqGaps, missing  uint64
	duplicates, reord uint64
	onboardGaps       uint64
	onboardMissing    uint64
	lastSeq           uint16
}

// NewEngine builds an engine from cfg, filling in defaults
func NewEngine(cfg Config) *Engine {
	e := &Engine{
		log:     cfg.Logger,
		bus:     cfg.Bus,
		window:  cfg.SeqWindow,
		apids:   make(map[ccsdsdefs.APID]*apidAccum),
		seqs:    make(map[seqKey]*seqState),
		tl:      newTimeline(),
		encap:   make(map[uint8]*encapAccum),
		seenVC:  make(map[vcKey]bool),
		suspect: make(map[vcKey]*suspectAccum),
		clcw:    make(map[vcKey]*clcwAccum),
	}
	if e.log == nil {
		e.log = obs.Discard()
	}
	if e.bus == nil {
		e.bus = NewEventBus(1024)
	}
	if e.window < 1 {
		e.window = 16
	}
	if cfg.Registry != nil {
		e.registry = cfg.Registry
		e.decodeCtx = plugin.DecodeContext{Logger: e.log}
		e.cfdp = cfdptrack.New()
	}
	return e
}

// ObserveDecodeError records a frame that failed to decode
func (e *Engine) ObserveDecodeError(offset int64) {
	e.decodeErrors++
	e.publish(Event{Type: EvDecodeError, Message: "frame decode failed"})
	e.log.Debug("frame decode error", "offset", offset)
}

// ObserveCRCFailure records a frame dropped because its FECF did not match
func (e *Engine) ObserveCRCFailure(offset int64) {
	e.crcFailures++
	e.publish(Event{Type: EvCRCFailure, Message: "frame failed CRC at offset " + strconv.FormatInt(offset, 10)})
}

// ObserveSuspect records a frame dropped because its channel looks like a false decode
func (e *Engine) ObserveSuspect(tfvn ccsdsdefs.TFVN, scid ccsdsdefs.SCID, vcid ccsdsdefs.VCID) {
	k := vcKey{scid, vcid}
	a := e.suspect[k]
	if a == nil {
		a = &suspectAccum{tfvn: tfvn}
		e.suspect[k] = a
	}
	a.frames++
	e.publish(Event{Type: EvSuspectFrame, SCID: scid, VCID: vcid,
		Message: tfvn.String() + " " + subject(scid, vcid, 0, false) + " frame dropped as a likely false decode"})
}

func (e *Engine) publish(ev Event) {
	ev.Time = e.tl.now
	e.bus.Publish(ev)
}

// ObserveFrameGap records frames missing on a VC just before the current frame
func (e *Engine) ObserveFrameGap(scid ccsdsdefs.SCID, vcid ccsdsdefs.VCID, lost uint64) {
	e.tl.frameGap(vcKey{scid, vcid}, lost)
	e.publish(Event{Type: EvFrameGap, SCID: scid, VCID: vcid,
		Message: subject(scid, vcid, 0, false) + " lost " + strconv.FormatUint(lost, 10) + " frame(s)"})
}

// ObserveFrame records a decoded transfer frame at a byte offset; caduLen is the
// CADU stride for byte accounting
func (e *Engine) ObserveFrame(f decode.TransferFrame, caduLen int, offset int64) {
	e.tl.offset = offset
	e.frames++
	e.caduBytes += uint64(caduLen)

	scid := f.MasterChannel().SCID
	vcid := f.VirtualChannel()
	k := vcKey{scid, vcid}
	if !e.seenVC[k] {
		e.seenVC[k] = true
		e.publish(Event{Type: EvNewVC, SCID: scid, VCID: vcid,
			Message: subject(scid, vcid, 0, false) + " first seen"})
	}

	switch f.TFVN() {
	case ccsdsdefs.TFVNTM:
		e.tmFrames++
	case ccsdsdefs.TFVNAOS:
		e.aosFrames++
	}

	if fhp, ok := f.FirstHeaderPointer(); ok && fhp == ccsdsdefs.FHPIdleOnly {
		e.idleFrames++
	}

	// an OCF that is a CLCW reports uplink status
	if ocf := f.OperationalControl(); clcw.IsCLCW(ocf) {
		if c, err := clcw.Parse(ocf); err == nil {
			a := e.clcw[k]
			if a == nil {
				a = &clcwAccum{}
				e.clcw[k] = a
			}
			a.frames++
			a.last = c
		}
	}
}

// ObservePacket records a reconstructed packet and does per-APID stats and
// sequence-continuity tracking
func (e *Engine) ObservePacket(p *model.SpacePacket) {
	if p.Kind == model.KindEncap {
		e.observeEncap(p)
		return
	}

	k := vcKey{p.SCID, p.VCID}
	p.Time = e.tl.observe(k, p.Time)

	e.packets++
	total := p.TotalLen()
	e.packetBytes += uint64(total)

	a := e.apidFor(p.APID)
	a.count++
	a.bytes += uint64(total)
	if a.minLen == 0 || total < a.minLen {
		a.minLen = total
	}
	if total > a.maxLen {
		a.maxLen = total
	}
	a.sumLen += uint64(total)
	a.lastSeq = p.SeqCount
	a.vcs[p.VCID] = true

	if p.IsIdle() {
		e.idlePackets++
	}
	if p.Truncated {
		e.truncated++
		e.publish(Event{Type: EvTruncated, SCID: p.SCID, VCID: p.VCID, APID: p.APID,
			Message: subject(p.SCID, p.VCID, p.APID, true) + " truncated during reassembly"})
	}
	if p.Version != 0 {
		e.malformed++
		e.publish(Event{Type: EvMalformed, SCID: p.SCID, VCID: p.VCID, APID: p.APID,
			Message: subject(p.SCID, p.VCID, p.APID, true) + " malformed packet version"})
	}

	// idle packets don't participate in sequence tracking
	if p.IsIdle() {
		return
	}
	sk := seqKey{k, p.APID}
	st := e.seqs[sk]
	if st == nil {
		st = &seqState{tr: gap.New(packetSeqModulus, e.window), lossEpoch: e.tl.lossEpoch[k]}
		e.seqs[sk] = st
	}
	out, miss := st.tr.Observe(int(p.SeqCount))
	switch out {
	case gap.Gap:
		a.seqGaps++
		a.missing += uint64(miss)
		e.seqGaps++
		e.missing += uint64(miss)
		onboard := st.lossEpoch == e.tl.lossEpoch[k]
		if onboard {
			a.onboardGaps++
			a.onboardMissing += uint64(miss)
		}
		e.tl.packetGap(k, p.APID, uint64(miss), st.last, p.Time, onboard)
		msg := subject(p.SCID, p.VCID, p.APID, true) + " missing " + strconv.Itoa(miss) + " packet(s)"
		if onboard {
			msg += " with no frame loss on its VC (lost before downlink)"
		}
		e.publish(Event{Type: EvPacketGap, SCID: p.SCID, VCID: p.VCID, APID: p.APID, Message: msg})
		e.log.Debug("packet sequence gap", "apid", uint16(p.APID), "missing", miss, "seq", p.SeqCount)
	case gap.Duplicate:
		a.duplicates++
		e.duplicates++
		e.publish(Event{Type: EvPacketDuplicate, SCID: p.SCID, VCID: p.VCID, APID: p.APID,
			Message: subject(p.SCID, p.VCID, p.APID, true) + " duplicate packet"})
	case gap.Reorder:
		a.reord++
		e.reorders++
		e.publish(Event{Type: EvPacketReorder, SCID: p.SCID, VCID: p.VCID, APID: p.APID,
			Message: subject(p.SCID, p.VCID, p.APID, true) + " reordered packet"})
	}
	if !p.Time.IsZero() {
		st.last = p.Time
	}
	st.lossEpoch = e.tl.lossEpoch[k]
	if p.Truncated {
		st.lossEpoch = ^uint64(0) // loss follows a truncated packet, so its next gap is not on board
	}

	if e.registry != nil && e.registry.Handles(p.APID) {
		e.dispatch(p)
	}
}

// observeEncap counts an Encapsulation Packet by Protocol ID, excluded from the
// APID/sequence analysis
func (e *Engine) observeEncap(p *model.SpacePacket) {
	n := p.ByteLen()
	e.encapPackets++
	e.encapBytes += uint64(n)
	a := e.encap[p.ProtocolID]
	if a == nil {
		a = &encapAccum{}
		e.encap[p.ProtocolID] = a
	}
	a.count++
	a.bytes += uint64(n)
	if p.Truncated {
		e.truncated++
		e.publish(Event{Type: EvTruncated, SCID: p.SCID, VCID: p.VCID,
			Message: subject(p.SCID, p.VCID, 0, false) + " encapsulation packet truncated during reassembly"})
	}
}

// dispatch runs application decoding and feeds any CFDP PDU to the tracker
func (e *Engine) dispatch(p *model.SpacePacket) {
	res := e.registry.Dispatch(e.decodeCtx, p)
	if res == nil || res.PDU == nil {
		return
	}
	pdu, ok := res.PDU.(*cfdp.PDU)
	if !ok {
		return
	}
	for _, n := range e.cfdp.Observe(pdu) {
		e.handleCFDPNotice(n)
	}
}

func (e *Engine) handleCFDPNotice(n cfdptrack.Notice) {
	txnMsg := func(s string) string {
		return "CFDP txn " + strconv.FormatUint(n.Txn.Source, 10) + ":" + strconv.FormatUint(n.Txn.TSN, 10) + " " + s
	}
	switch n.Kind {
	case cfdptrack.NoticeStarted:
		e.publish(Event{Type: EvCFDPStarted, Message: txnMsg("started")})
	case cfdptrack.NoticeEOF:
		e.publish(Event{Type: EvCFDPEOF, Message: txnMsg("EOF received")})
	case cfdptrack.NoticeGap:
		e.publish(Event{Type: EvCFDPGap, Message: txnMsg("file gap at offset " + strconv.FormatUint(n.Offset, 10))})
	case cfdptrack.NoticeNAK:
		e.publish(Event{Type: EvCFDPNAK, Message: txnMsg("NAK")})
	case cfdptrack.NoticeComplete:
		e.publish(Event{Type: EvCFDPComplete, Message: txnMsg("complete")})
	case cfdptrack.NoticeIncomplete:
		e.publish(Event{Type: EvCFDPIncomplete, Message: txnMsg("incomplete")})
	}
}

func (e *Engine) apidFor(apid ccsdsdefs.APID) *apidAccum {
	if a, ok := e.apids[apid]; ok {
		return a
	}
	a := &apidAccum{apid: apid, vcs: make(map[ccsdsdefs.VCID]bool)}
	e.apids[apid] = a
	e.publish(Event{Type: EvNewAPID, APID: apid,
		Message: subject(0, 0, apid, true) + " first seen"})
	return a
}

// Snapshot returns a deterministic copy of the current statistics
func (e *Engine) Snapshot(vcs []*model.VirtualChannel) Statistics {
	s := Statistics{
		Frames: FrameStats{
			Total: e.frames, TM: e.tmFrames, AOS: e.aosFrames, Idle: e.idleFrames,
			DecodeErrors: e.decodeErrors, Bytes: e.caduBytes,
		},
		Packets: PacketStats{
			Total: e.packets, Idle: e.idlePackets, Truncated: e.truncated, Malformed: e.malformed,
			SequenceGaps: e.seqGaps, MissingPackets: e.missing,
			Duplicates: e.duplicates, Reorders: e.reorders, Bytes: e.packetBytes,
			Encap: e.encapPackets, EncapBytes: e.encapBytes,
		},
	}

	s.Quality = e.quality(s)
	s.Time = e.tl.stats()
	s.Gaps = append([]Gap(nil), e.tl.gaps...)
	s.Bursts = bursts(s.Gaps)

	for id, a := range e.encap {
		s.Encapsulation = append(s.Encapsulation, EncapStats{
			ProtocolID: id, Protocol: encap.ProtocolName(id), Count: a.count, Bytes: a.bytes,
		})
	}
	sort.Slice(s.Encapsulation, func(i, j int) bool {
		return s.Encapsulation[i].ProtocolID < s.Encapsulation[j].ProtocolID
	})

	s.APIDs = make([]APIDStats, 0, len(e.apids))
	for _, a := range e.apids {
		var mean float64
		if a.count > 0 {
			mean = round2(float64(a.sumLen) / float64(a.count))
		}
		vcs := make([]ccsdsdefs.VCID, 0, len(a.vcs))
		for v := range a.vcs {
			vcs = append(vcs, v)
		}
		slices.Sort(vcs)
		s.APIDs = append(s.APIDs, APIDStats{
			APID: a.apid, VCIDs: vcs, Idle: a.apid.IsIdle(), Count: a.count, Bytes: a.bytes,
			MinLength: a.minLen, MaxLength: a.maxLen, MeanLength: mean,
			SequenceGaps: a.seqGaps, MissingPackets: a.missing,
			Duplicates: a.duplicates, Reorders: a.reord, LastSeqCount: a.lastSeq,
			OnboardGaps: a.onboardGaps, OnboardMissing: a.onboardMissing,
		})
	}
	sort.Slice(s.APIDs, func(i, j int) bool { return s.APIDs[i].APID < s.APIDs[j].APID })

	s.VCs = make([]VCStats, 0, len(vcs))
	for _, vc := range vcs {
		s.VCs = append(s.VCs, VCStats{
			SCID: vc.SCID, VCID: vc.VCID, TFVN: vc.TFVN.String(),
			Frames: vc.FrameCount, FrameGaps: vc.FrameGaps, FramesLost: vc.FramesLost,
			IdleFrames: vc.IdleFrames, Packets: vc.PacketsExtracted, DataBytes: vc.DataBytes,
		})
	}
	sort.Slice(s.VCs, func(i, j int) bool {
		if s.VCs[i].SCID != s.VCs[j].SCID {
			return s.VCs[i].SCID < s.VCs[j].SCID
		}
		return s.VCs[i].VCID < s.VCs[j].VCID
	})

	// CLCW per VC, in the same sorted VC order
	for _, v := range s.VCs {
		a := e.clcw[vcKey{v.SCID, v.VCID}]
		if a == nil {
			continue
		}
		s.CLCW = append(s.CLCW, CLCWStat{
			SCID: v.SCID, VCID: v.VCID, Frames: a.frames,
			ReportedVCID: a.last.VCID, Lockout: a.last.Lockout, Wait: a.last.Wait,
			Retransmit: a.last.Retransmit, NoRF: a.last.NoRFAvailable,
			NoBitLock: a.last.NoBitLock, ReportValue: a.last.ReportValue,
		})
	}

	counts := e.bus.CountsByType()
	s.Events = make([]EventCount, 0, len(counts))
	for t, c := range counts {
		s.Events = append(s.Events, EventCount{Type: string(t), Severity: severityOf(t).String(), Count: c})
	}
	sort.Slice(s.Events, func(i, j int) bool { return s.Events[i].Type < s.Events[j].Type })

	if e.cfdp != nil {
		s.CFDP = e.cfdp.Snapshot()
	}
	return s
}

func (e *Engine) quality(s Statistics) Quality {
	q := Quality{
		FramesUsed: e.frames, CRCFailures: e.crcFailures, DecodeErrors: e.decodeErrors,
	}
	for k, a := range e.suspect {
		q.SuspectFrames += a.frames
		q.Suspect = append(q.Suspect, SuspectChannel{TFVN: a.tfvn.String(), SCID: k.scid, VCID: k.vcid, Frames: a.frames})
	}
	sort.Slice(q.Suspect, func(i, j int) bool {
		if q.Suspect[i].SCID != q.Suspect[j].SCID {
			return q.Suspect[i].SCID < q.Suspect[j].SCID
		}
		return q.Suspect[i].VCID < q.Suspect[j].VCID
	})
	q.FramesRead = q.FramesUsed + q.CRCFailures + q.DecodeErrors + q.SuspectFrames

	frac := func(n, d uint64) float64 {
		if d == 0 {
			return 0
		}
		return float64(n) / float64(d)
	}
	warn := func(format string, a ...any) { q.Warnings = append(q.Warnings, fmt.Sprintf(format, a...)) }
	const hint = "frame settings may be wrong or the capture has uncorrected errors"
	if r := frac(q.CRCFailures, q.FramesRead); r > 0.05 {
		warn("%.1f%% of frames failed CRC: %s", 100*r, hint)
	}
	if r := frac(q.DecodeErrors+q.SuspectFrames, q.FramesRead); r > 0.01 {
		warn("%.1f%% of frames have invalid or unexpected headers: %s", 100*r, hint)
	}
	if s.Packets.Total >= 100 {
		if r := frac(s.Packets.Truncated, s.Packets.Total); r > 0.05 {
			warn("%.1f%% of packets are truncated: %s", 100*r, hint)
		}
		if r := frac(s.Packets.Reorders+s.Packets.Duplicates, s.Packets.Total); r > 0.01 {
			warn("%.1f%% of packets are out of order or repeated: %s", 100*r, hint)
		}
	}
	return q
}

func round2(x float64) float64 { return math.Round(x*100) / 100 }
