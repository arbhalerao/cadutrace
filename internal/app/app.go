package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/arbhalerao/cadutrace/internal/analysis"
	"github.com/arbhalerao/cadutrace/internal/appdecoder"
	"github.com/arbhalerao/cadutrace/internal/decode"
	"github.com/arbhalerao/cadutrace/internal/decode/encap"
	"github.com/arbhalerao/cadutrace/internal/decode/fecf"
	"github.com/arbhalerao/cadutrace/internal/decode/vc"
	"github.com/arbhalerao/cadutrace/internal/detect"
	"github.com/arbhalerao/cadutrace/internal/framing"
	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// Options configures a single offline analysis run
type Options struct {
	Source         Source
	Framing        framing.Config
	Frames         decode.Config
	MaxPacketLen   int
	CollectPackets bool                 // collect the full packet list (with raw bytes)
	CollectFrames  bool                 // collect the full frame list (with raw bytes)
	Logger         *slog.Logger         // optional; defaults to a discard logger
	Registry       *appdecoder.Registry // optional; enables application decoding (CFDP)
	Bus            *analysis.EventBus   // optional; receives analysis events (for the TUI)

	// Detect, when set, infers every setting it does not mark as fixed
	Detect *detect.Fixed
	// KeepSuspect keeps frames from channels that look like false decodes
	KeepSuspect bool
	Time        TimeOptions
}

// Settings records the frame settings a run used
type Settings struct {
	Sync        string   `json:"sync"`
	CADULen     int      `json:"cadu_len"`
	FrameLen    int      `json:"frame_len"`
	RSLen       int      `json:"rs_len"`
	Derandomize bool     `json:"derandomize"`
	TMFECF      bool     `json:"tm_fecf"`
	AOSFECF     bool     `json:"aos_fecf"`
	Notes       []string `json:"notes,omitempty"`
}

// FrameInfo is a renderable summary of one transfer frame
type FrameInfo struct {
	Offset       int64          `json:"offset"`
	TFVN         string         `json:"tfvn"`
	SCID         ccsdsdefs.SCID `json:"scid"`
	VCID         ccsdsdefs.VCID `json:"vcid"`
	VCFrameCount uint32         `json:"vc_frame_count"`
	FHP          uint16         `json:"fhp"`
	HasFHP       bool           `json:"has_fhp"`
	DataLen      int            `json:"data_len"`
	Raw          []byte         `json:"-"`
}

// Source mirrors source.Source so callers can supply files or in-memory streams
type Source interface {
	Bytes() ([]byte, error)
	Name() string
	Close() error
}

// PacketInfo is a renderable summary of one reconstructed packet
type PacketInfo struct {
	SCID      ccsdsdefs.SCID       `json:"scid"`
	VCID      ccsdsdefs.VCID       `json:"vcid"`
	APID      ccsdsdefs.APID       `json:"apid"`
	Type      ccsdsdefs.PacketType `json:"type"`
	SeqFlags  ccsdsdefs.SeqFlags   `json:"seq_flags"`
	SeqCount  uint16               `json:"seq_count"`
	Length    int                  `json:"length"`
	Idle      bool                 `json:"idle"`
	Truncated bool                 `json:"truncated"`
	Time      time.Time            `json:"time,omitzero"`
	Kind      string               `json:"kind,omitempty"`     // "encap" for Encapsulation Packets
	Protocol  string               `json:"protocol,omitempty"` // encap Protocol ID name
	Raw       []byte               `json:"-"`                  // full packet bytes for the hex view
}

func packetInfo(p *model.SpacePacket) PacketInfo {
	if p.Kind == model.KindEncap {
		return PacketInfo{
			SCID: p.SCID, VCID: p.VCID, Length: p.ByteLen(),
			Truncated: p.Truncated, Kind: "encap",
			Protocol: encap.ProtocolName(p.ProtocolID), Raw: p.Raw,
		}
	}
	return PacketInfo{
		SCID: p.SCID, VCID: p.VCID, APID: p.APID, Type: p.Type,
		SeqFlags: p.SeqFlags, SeqCount: p.SeqCount, Length: p.TotalLen(),
		Idle: p.IsIdle(), Truncated: p.Truncated, Raw: p.Raw, Time: p.Time,
	}
}

// SchemaVersion identifies the JSON report schema; bump on any breaking change
const SchemaVersion = "1"

// Result is the outcome of an analysis run (the stable contract emitted by
// analyze --json): metadata + the Statistics snapshot + an optional packet list
type Result struct {
	SchemaVersion string              `json:"schema_version"`
	Source        string              `json:"source"`
	Bytes         int                 `json:"bytes"`
	CADULen       int                 `json:"cadu_len"`
	FrameLen      int                 `json:"frame_len"`
	Settings      Settings            `json:"settings"`
	Statistics    analysis.Statistics `json:"statistics"`
	PacketList    []PacketInfo        `json:"packet_list,omitempty"`
	FrameList     []FrameInfo         `json:"-"` // populated only when CollectFrames is set
}

// Run executes the pipeline to completion over an offline source
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Source == nil {
		return nil, errors.New("app: nil source")
	}
	data, err := opts.Source.Bytes()
	if err != nil {
		return nil, err
	}

	var notes []string
	if opts.Detect != nil {
		if notes, err = applyDetection(data, &opts); err != nil {
			return nil, err
		}
	}

	framer, err := framing.New(data, opts.Framing)
	if err != nil {
		return nil, err
	}
	var trusted map[detect.ChannelID]bool
	if !opts.KeepSuspect {
		if trusted, err = detect.Channels(data, opts.Framing); err != nil {
			return nil, err
		}
	}
	td, timeNotes, err := setupTime(data, opts, trusted)
	if err != nil {
		return nil, err
	}
	notes = append(notes, timeNotes...)
	dec := decode.NewFrameDecoder(opts.Frames)
	mgr := vc.New(opts.MaxPacketLen)
	engine := analysis.NewEngine(analysis.Config{
		Logger:   opts.Logger,
		Registry: opts.Registry,
		Bus:      opts.Bus,
	})
	caduLen := framer.CADULen()

	res := &Result{
		SchemaVersion: SchemaVersion,
		Source:        opts.Source.Name(),
		Bytes:         len(data),
		CADULen:       caduLen,
		FrameLen:      framer.FrameLen(),
		Settings: Settings{
			Sync: syncName(opts.Framing), CADULen: caduLen, FrameLen: framer.FrameLen(),
			RSLen: opts.Framing.RSLen, Derandomize: opts.Framing.Derandomize,
			TMFECF: opts.Frames.TM.HasFECF, AOSFECF: opts.Frames.AOS.HasFECF, Notes: notes,
		},
	}

	record := func(p *model.SpacePacket) {
		td.stamp(p)
		engine.ObservePacket(p)
		if opts.CollectPackets {
			res.PacketList = append(res.PacketList, packetInfo(p))
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := framer.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if trusted != nil && len(raw.Data) >= 6 {
			id := detect.ParseChannel(raw.Data).ID()
			if !trusted[id] {
				engine.ObserveSuspect(id.TFVN, id.SCID, id.VCID)
				continue
			}
		}
		f, derr := dec.Decode(raw.Data)
		if errors.Is(derr, fecf.ErrMismatch) {
			engine.ObserveCRCFailure(raw.Offset)
			continue
		}
		if derr != nil {
			engine.ObserveDecodeError(raw.Offset)
			continue
		}
		engine.ObserveFrame(f, caduLen, raw.Offset)
		if opts.CollectFrames {
			fhp, ok := f.FirstHeaderPointer()
			res.FrameList = append(res.FrameList, FrameInfo{
				Offset: raw.Offset, TFVN: f.TFVN().String(),
				SCID: f.MasterChannel().SCID, VCID: f.VirtualChannel(),
				VCFrameCount: f.VCCount(), FHP: fhp, HasFHP: ok,
				DataLen: len(f.Data()), Raw: raw.Data,
			})
		}
		ch, pkts, rerr := mgr.Route(f)
		if rerr != nil {
			return nil, rerr
		}
		if ch.LastLost > 0 {
			engine.ObserveFrameGap(ch.SCID, ch.VCID, ch.LastLost)
		}
		for _, p := range pkts { // consumed before the next Route (reused arena)
			record(p)
		}
	}

	// emit any packets still open at end of stream
	for _, p := range mgr.Flush() {
		record(p)
	}

	res.Statistics = engine.Snapshot(mgr.VirtualChannels())
	ts := &res.Statistics.Time
	ts.Code, ts.Epoch = td.describe()
	ts.Relative = td != nil && td.relative
	return res, nil
}

func applyDetection(data []byte, opts *Options) ([]string, error) {
	fx := *opts.Detect
	in := detect.Params{
		NoASM: opts.Framing.NoASM, ASM: opts.Framing.ASM, CADULen: opts.Framing.CADULen,
		RSLen: opts.Framing.RSLen, Derandomize: opts.Framing.Derandomize,
		FECF: opts.Frames.TM.HasFECF || opts.Frames.AOS.HasFECF,
	}
	p, notes, err := detect.Detect(data, in, fx)
	if err != nil {
		return notes, err
	}
	opts.Framing = p.Framing()
	if !fx.FECF {
		opts.Frames.TM.HasFECF = p.FECF && p.TFVN == ccsdsdefs.TFVNTM
		opts.Frames.AOS.HasFECF = p.FECF && p.TFVN == ccsdsdefs.TFVNAOS
	}
	return notes, nil
}

func syncName(c framing.Config) string {
	if c.NoASM {
		return "none"
	}
	asm := c.ASM
	if asm == 0 {
		asm = ccsdsdefs.ASMStandard
	}
	return fmt.Sprintf("%08X", asm)
}
