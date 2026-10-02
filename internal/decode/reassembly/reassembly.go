package reassembly

import (
	"github.com/arbhalerao/cadutrace/internal/decode/encap"
	"github.com/arbhalerao/cadutrace/internal/decode/spacepacket"
	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/bufpool"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

const minPacketLen = spacepacket.HeaderLen + 1 // 7 (minimum Space Packet)

// peekKind classifies a packet by the 3-bit version: 0b000 Space, 0b111 Encap
func peekKind(b0 byte) model.PacketKind {
	switch b0 >> 5 {
	case 0:
		return model.KindSpace
	case encap.PVN:
		return model.KindEncap
	default:
		return model.KindUnknown
	}
}

// headerLen is the octets needed to learn the total length (6 Space, 1/2/4/8 Encap)
func headerLen(kind model.PacketKind, b0 byte) int {
	if kind == model.KindEncap {
		return encap.HeaderLen(b0)
	}
	return spacepacket.HeaderLen
}

// resolveLen returns the total packet length once enough header octets are present
func resolveLen(kind model.PacketKind, buf []byte) (total int, ok bool) {
	if kind == model.KindEncap {
		return encap.TotalLen(buf)
	}
	if len(buf) < spacepacket.HeaderLen {
		return 0, false
	}
	return spacepacket.TotalLen(buf), true
}

// minLen is the smallest valid packet length for a kind
func minLen(kind model.PacketKind) int {
	if kind == model.KindEncap {
		return 1 // a 1-octet encapsulation idle packet
	}
	return minPacketLen
}

// parsePacket builds the reconstructed packet for a kind from its full bytes
func parsePacket(kind model.PacketKind, full []byte) model.SpacePacket {
	if kind == model.KindEncap {
		sp := model.SpacePacket{Kind: model.KindEncap, ProtocolID: encap.ProtocolID(full[0]), Raw: full}
		if hl := encap.HeaderLen(full[0]); hl <= len(full) {
			sp.Payload = full[hl:]
		}
		return sp
	}
	sp, _ := spacepacket.Parse(full) // Kind defaults to KindSpace
	sp.Raw = full
	return sp
}

// Reassembler holds the per-call result arena; per-VC state lives on the VirtualChannel
type Reassembler struct {
	maxPacketLen int
	arena        []model.SpacePacket
	scratch      []*model.SpacePacket
}

// New returns a Reassembler; maxPacketLen bounds one packet (0 = protocol max)
func New(maxPacketLen int) *Reassembler {
	if maxPacketLen <= 0 {
		maxPacketLen = ccsdsdefs.MaxSpacePacket
	}
	return &Reassembler{maxPacketLen: maxPacketLen}
}

// begin resets the arena, pre-sized so emit never reallocates mid-call (which would
// invalidate pointers already placed in scratch)
func (r *Reassembler) begin(dataLen int) {
	need := dataLen/minPacketLen + 2
	if cap(r.arena) < need {
		r.arena = make([]model.SpacePacket, 0, need)
	}
	r.arena = r.arena[:0]
	r.scratch = r.scratch[:0]
}

func (r *Reassembler) emit(sp model.SpacePacket) {
	r.arena = append(r.arena, sp)
	r.scratch = append(r.scratch, &r.arena[len(r.arena)-1])
}

// Push consumes one VC data field and returns the packets it completed
// hasFHP is false for B_PDU/VCA data, from which no packets are extracted
// lost reports that frames were missing on this VC since the previous Push, so an
// open packet is truncated rather than spliced onto unrelated bytes
func (r *Reassembler) Push(vc *model.VirtualChannel, data []byte, fhp uint16, hasFHP, lost bool) []*model.SpacePacket {
	r.begin(len(data))
	if lost && vc.Reasm.Open {
		r.emitTruncated(vc)
	}
	if !hasFHP {
		return r.scratch
	}

	pos := 0
	if vc.Reasm.Open {
		// bytes before the next packet header continue the open packet
		contEnd := len(data)
		switch {
		case fhp == ccsdsdefs.FHPNoStart:
			contEnd = len(data) // whole frame continues the open packet
		case fhp == ccsdsdefs.FHPIdleOnly:
			contEnd = 0 // only idle data; nothing continues the open packet
		case int(fhp) <= len(data):
			contEnd = int(fhp)
		}

		_, complete := fillOpen(&vc.Reasm, data[:contEnd], r.maxPacketLen)
		if complete {
			r.emitOpen(vc)
		}

		switch fhp {
		case ccsdsdefs.FHPNoStart:
			// no new header starts; any bytes after completion are idle fill
			return r.scratch
		case ccsdsdefs.FHPIdleOnly:
			if vc.Reasm.Open {
				r.emitTruncated(vc) // open packet interrupted by an idle frame
			}
			return r.scratch
		default:
			if vc.Reasm.Open {
				// a new header starts but the open packet didn't finish: data was
				// lost, so truncate and resync
				r.emitTruncated(vc)
			}
			pos = min(int(fhp), len(data))
		}
	} else {
		// not reassembling: we can only start where a header begins
		switch {
		case fhp == ccsdsdefs.FHPNoStart || fhp == ccsdsdefs.FHPIdleOnly:
			return r.scratch
		case int(fhp) <= len(data):
			pos = int(fhp)
		default:
			return r.scratch // malformed FHP: skip the frame, resync on the next
		}
	}

	// parse sequential complete packets from pos
	for pos < len(data) {
		rem := data[pos:]
		kind := peekKind(rem[0])
		if kind == model.KindUnknown {
			return r.scratch // unknown version: stop, resync on the next frame
		}
		if len(rem) < headerLen(kind, rem[0]) {
			r.startOpen(vc, rem) // header split across the frame boundary
			return r.scratch
		}
		total, _ := resolveLen(kind, rem) // resolvable: len(rem) >= headerLen
		if total < minLen(kind) || total > r.maxPacketLen {
			return r.scratch // malformed length: stop, resync on the next frame
		}
		if total <= len(rem) {
			sp := parsePacket(kind, rem[:total]) // zero-copy slice into source
			sp.SCID, sp.VCID = vc.SCID, vc.VCID
			r.emit(sp)
			pos += total
		} else {
			r.startOpen(vc, rem) // packet extends beyond this frame
			return r.scratch
		}
	}
	return r.scratch
}

// Flush emits any open (truncated) packet at end of stream
func (r *Reassembler) Flush(vc *model.VirtualChannel) []*model.SpacePacket {
	r.begin(0)
	if vc.Reasm.Open {
		r.emitTruncated(vc)
	}
	return r.scratch
}

// startOpen begins accumulating a packet from rem into a pooled buffer
func (r *Reassembler) startOpen(vc *model.VirtualChannel, rem []byte) {
	rs := &vc.Reasm
	if rs.BufPtr == nil {
		rs.BufPtr = bufpool.GetPtr()
	}
	rs.Buf = (*rs.BufPtr)[:0]
	rs.Buf = append(rs.Buf, rem...)
	rs.Open = true
	rs.Expected = 0
	rs.Kind = peekKind(rs.Buf[0])
	if rs.Kind == model.KindUnknown {
		rs.Expected = -1 // malformed; will be flushed/truncated
		return
	}
	resolveExpected(rs, r.maxPacketLen)
}

// resolveExpected sets rs.Expected once enough header octets are buffered
func resolveExpected(rs *model.ReassemblyState, maxLen int) {
	if rs.Expected != 0 || len(rs.Buf) < headerLen(rs.Kind, rs.Buf[0]) {
		return
	}
	total, ok := resolveLen(rs.Kind, rs.Buf)
	if !ok {
		return
	}
	if total < minLen(rs.Kind) || total > maxLen {
		rs.Expected = -1
		return
	}
	rs.Expected = total
}

// fillOpen appends continuation bytes, completing the header (to learn the length)
// then the body; returns bytes consumed and whether the packet is done
func fillOpen(rs *model.ReassemblyState, data []byte, maxLen int) (consumed int, complete bool) {
	if rs.Expected == 0 {
		hl := headerLen(rs.Kind, rs.Buf[0])
		need := hl - len(rs.Buf)
		if need > 0 {
			n := min(need, len(data))
			rs.Buf = append(rs.Buf, data[:n]...)
			consumed += n
			data = data[n:]
			if len(rs.Buf) < hl {
				return consumed, false // still need more header octets
			}
		}
		resolveExpected(rs, maxLen)
	}
	if rs.Expected <= 0 {
		return consumed, false
	}
	need := rs.Expected - len(rs.Buf)
	if need > 0 {
		n := min(need, len(data))
		rs.Buf = append(rs.Buf, data[:n]...)
		consumed += n
		need -= n
	}
	return consumed, need == 0
}

// emitOpen finalizes a completed multi-frame packet, copying it out of the pool
func (r *Reassembler) emitOpen(vc *model.VirtualChannel) {
	rs := &vc.Reasm
	raw := append([]byte(nil), rs.Buf[:rs.Expected]...) // own the bytes (buffer is recycled)
	sp := parsePacket(rs.Kind, raw)
	sp.SCID, sp.VCID = vc.SCID, vc.VCID
	r.emit(sp)
	r.resetReasm(vc)
}

// emitTruncated emits a best-effort packet from a partial buffer after loss or idle
func (r *Reassembler) emitTruncated(vc *model.VirtualChannel) {
	rs := &vc.Reasm
	if sp, ok := truncatedPacket(rs); ok {
		sp.SCID, sp.VCID = vc.SCID, vc.VCID
		r.emit(sp)
	}
	r.resetReasm(vc)
}

// truncatedPacket builds a best-effort packet from a partial buffer; ok=false when
// there is too little to render a header
func truncatedPacket(rs *model.ReassemblyState) (model.SpacePacket, bool) {
	if rs.Kind == model.KindEncap {
		if len(rs.Buf) < 1 {
			return model.SpacePacket{}, false
		}
		raw := append([]byte(nil), rs.Buf...)
		sp := model.SpacePacket{Kind: model.KindEncap, ProtocolID: encap.ProtocolID(raw[0]), Raw: raw, Truncated: true}
		if hl := encap.HeaderLen(raw[0]); hl <= len(raw) {
			sp.Payload = raw[hl:]
		}
		return sp, true
	}
	if len(rs.Buf) < spacepacket.HeaderLen {
		return model.SpacePacket{}, false
	}
	raw := append([]byte(nil), rs.Buf...)
	sp, _ := spacepacket.ParseHeader(raw)
	sp.Raw = raw
	sp.Payload = raw[spacepacket.HeaderLen:]
	sp.Truncated = true
	return sp, true
}

func (r *Reassembler) resetReasm(vc *model.VirtualChannel) {
	rs := &vc.Reasm
	if rs.BufPtr != nil {
		bufpool.PutPtr(rs.BufPtr)
		rs.BufPtr = nil
	}
	rs.Buf = nil
	rs.Open = false
	rs.Expected = 0
	rs.Kind = model.KindSpace
}
