package testgen

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/arbhalerao/cadutrace/internal/decode/encap"
	"github.com/arbhalerao/cadutrace/internal/decode/randomizer"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

const asmLen = 4

// VCConfig describes one virtual channel's traffic
type VCConfig struct {
	SCID       ccsdsdefs.SCID
	VCID       ccsdsdefs.VCID
	FrameType  ccsdsdefs.TFVN // must equal StreamConfig-wide type
	APIDs      []ccsdsdefs.APID
	NumPackets int
	PacketLen  int // total octets per real packet (>= 7), fixed for determinism

	// Encap, when set, makes this VC carry CCSDS 133.1 Encapsulation Packets
	// instead of Space Packets, cycling through EncapProtocols (Protocol IDs)
	// APIDs is then ignored and PacketLen must be >= 2
	Encap          bool
	EncapProtocols []uint8
}

// StreamConfig describes a whole capture
type StreamConfig struct {
	VCs          []VCConfig
	FrameType    ccsdsdefs.TFVN
	FrameDataLen int    // TM data-field length, or AOS packet-zone length
	ASM          uint32 // 0 selects the standard marker
	OCF          []byte // optional 4-octet OCF (CLCW) appended to every TM frame
	Randomize    bool   // apply the CCSDS 131.0 pseudo-randomizer to each frame
}

// Manifest is the ground truth a generated stream should decode to
type Manifest struct {
	PacketsPerAPID map[ccsdsdefs.APID]int // real (non-idle) packets
	TotalPackets   int                    // real packets across all VCs
	IdlePackets    int                    // padding idle packets added by the generator
	FramesPerVC    map[VCKey]int
	TotalFrames    int
	CADULen        int

	// Encapsulation Packets (CCSDS 133.1), populated for Encap VCs
	EncapPerProtocol map[uint8]int // real encap packets per Protocol ID
	EncapPackets     int           // real encap packets across all VCs
	EncapIdle        int           // padding idle encap packets added by the generator
}

// VCKey identifies a virtual channel in the manifest
type VCKey struct {
	SCID ccsdsdefs.SCID
	VCID ccsdsdefs.VCID
}

// Build produces a CADU stream and its manifest
func Build(cfg StreamConfig) ([]byte, Manifest, error) {
	if cfg.FrameDataLen < 7 {
		return nil, Manifest{}, fmt.Errorf("testgen: FrameDataLen must be >= 7, got %d", cfg.FrameDataLen)
	}
	asm := cfg.ASM
	if asm == 0 {
		asm = ccsdsdefs.ASMStandard
	}
	var asmBytes [asmLen]byte
	binary.BigEndian.PutUint32(asmBytes[:], asm)

	ocf := cfg.OCF
	if cfg.FrameType != ccsdsdefs.TFVNTM {
		ocf = nil // OCF injection is only wired for TM frames
	}
	caduLen := asmLen + frameTotalLen(cfg.FrameType, cfg.FrameDataLen) + len(ocf)
	man := Manifest{
		PacketsPerAPID:   map[ccsdsdefs.APID]int{},
		EncapPerProtocol: map[uint8]int{},
		FramesPerVC:      map[VCKey]int{},
		CADULen:          caduLen,
	}

	// build each VC's frame list (ASM-stripped transfer frames) independently
	channels := make([][][]byte, 0, len(cfg.VCs))

	idleSeq := uint16(0)
	for _, vc := range cfg.VCs {
		if vc.FrameType != cfg.FrameType {
			return nil, Manifest{}, fmt.Errorf("testgen: VC %d/%d frame type differs from stream", vc.SCID, vc.VCID)
		}
		minLen := 7
		if vc.Encap {
			minLen = 2
		}
		if vc.PacketLen < minLen {
			return nil, Manifest{}, fmt.Errorf("testgen: PacketLen must be >= %d, got %d", minLen, vc.PacketLen)
		}

		// concatenate real packets, recording packet-start boundaries
		var buf []byte
		var bounds []int
		seqByAPID := map[ccsdsdefs.APID]uint16{}
		for i := range vc.NumPackets {
			bounds = append(bounds, len(buf))
			if vc.Encap {
				pid := vc.EncapProtocols[i%len(vc.EncapProtocols)]
				buf = append(buf, encapPacket(pid, vc.PacketLen, byte(i))...)
				man.EncapPerProtocol[pid]++
				man.EncapPackets++
				continue
			}
			apid := vc.APIDs[i%len(vc.APIDs)]
			buf = append(buf, spacePacket(apid, seqByAPID[apid], vc.PacketLen, byte(i))...)
			seqByAPID[apid]++
			man.PacketsPerAPID[apid]++
			man.TotalPackets++
		}

		// pad to a whole number of data fields with one idle packet
		if rem := len(buf) % cfg.FrameDataLen; rem != 0 {
			pad := cfg.FrameDataLen - rem
			if pad < minLen {
				pad += cfg.FrameDataLen
			}
			bounds = append(bounds, len(buf))
			if vc.Encap {
				buf = append(buf, encapPacket(encap.ProtoIdle, pad, 0xCA)...)
				man.EncapPerProtocol[encap.ProtoIdle]++
				man.EncapIdle++
			} else {
				buf = append(buf, spacePacket(ccsdsdefs.APIDIdle, idleSeq, pad, 0xCA)...)
				idleSeq++
				man.IdlePackets++
			}
		}

		frames := packetize(buf, bounds, cfg.FrameDataLen, cfg.FrameType, vc, ocf)
		man.FramesPerVC[VCKey{vc.SCID, vc.VCID}] = len(frames)
		man.TotalFrames += len(frames)
		channels = append(channels, frames)
	}

	// interleave frames round-robin across VCs and wrap each in a CADU
	var out []byte
	idx := make([]int, len(channels))
	remaining := man.TotalFrames
	for remaining > 0 {
		for ci, frames := range channels {
			if idx[ci] >= len(frames) {
				continue
			}
			frame := frames[idx[ci]]
			if cfg.Randomize {
				frame = append([]byte(nil), frame...)
				randomizer.Apply(frame) // the ASM is appended separately, unrandomized
			}
			out = append(out, asmBytes[:]...)
			out = append(out, frame...)
			idx[ci]++
			remaining--
		}
	}
	return out, man, nil
}

func frameTotalLen(t ccsdsdefs.TFVN, dataLen int) int {
	switch t {
	case ccsdsdefs.TFVNAOS:
		return 6 + 2 + dataLen // primary header + M_PDU header + packet zone
	default:
		return 6 + dataLen // TM primary header + data field
	}
}

// SpacePacketBytes builds one space packet of total length with a deterministic
// payload pattern
func SpacePacketBytes(apid ccsdsdefs.APID, seq uint16, total int, fill byte) []byte {
	return spacePacket(apid, seq, total, fill)
}

func spacePacket(apid ccsdsdefs.APID, seq uint16, total int, fill byte) []byte {
	p := make([]byte, total)
	// version 0, type TM, no secondary header, given APID
	p[0] = byte(uint16(apid) >> 8 & 0x07)
	p[1] = byte(uint16(apid))
	// unsegmented, given sequence count
	p[2] = byte(uint16(ccsdsdefs.SeqUnsegmented)<<6) | byte(seq>>8&0x3F)
	p[3] = byte(seq)
	dataLen := total - 6 - 1 // (data field octets) - 1
	binary.BigEndian.PutUint16(p[4:6], uint16(dataLen))
	for i := 6; i < total; i++ {
		p[i] = fill + byte(i)
	}
	return p
}

// EncapPacketBytes builds one CCSDS 133.1 Encapsulation Packet of total length
// carrying protoID, with a deterministic payload pattern
func EncapPacketBytes(protoID uint8, total int, fill byte) []byte {
	return encapPacket(protoID, total, fill)
}

// encapPacket builds one Encapsulation Packet, choosing the smallest header that
// can express total: 1 octet (idle), 2 octets (8-bit length), or 4 octets (16-bit)
func encapPacket(protoID uint8, total int, fill byte) []byte {
	b0 := byte(encap.PVN<<5) | (protoID&0x07)<<2
	switch {
	case total <= 1:
		return []byte{b0} // 1-octet header, length-of-length 0 (idle/fill)
	case total <= 0xFF:
		p := make([]byte, total)
		p[0] = b0 | 0x01 // length-of-length 1: 2-octet header, 8-bit length
		p[1] = byte(total)
		for i := 2; i < total; i++ {
			p[i] = fill + byte(i)
		}
		return p
	default:
		p := make([]byte, total)
		p[0] = b0 | 0x02 // length-of-length 2: 4-octet header, 16-bit length
		binary.BigEndian.PutUint16(p[2:4], uint16(total))
		for i := 4; i < total; i++ {
			p[i] = fill + byte(i)
		}
		return p
	}
}

// packetize packs a VC byte buffer into frames, computing the FHP for each
func packetize(buf []byte, bounds []int, dataLen int, ftype ccsdsdefs.TFVN, vc VCConfig, ocf []byte) [][]byte {
	var frames [][]byte
	vcfc := uint32(0)
	for pos := 0; pos < len(buf); pos += dataLen {
		field := buf[pos : pos+dataLen]
		// FHP = offset of the first packet that starts within [pos, pos+dataLen)
		fhp := ccsdsdefs.FHPNoStart
		bi := sort.SearchInts(bounds, pos)
		if bi < len(bounds) && bounds[bi] < pos+dataLen {
			fhp = uint16(bounds[bi] - pos)
		}
		frames = append(frames, buildFrame(ftype, vc, vcfc, fhp, field, ocf))
		vcfc++
	}
	return frames
}

func buildFrame(ftype ccsdsdefs.TFVN, vc VCConfig, vcfc uint32, fhp uint16, field, ocf []byte) []byte {
	switch ftype {
	case ccsdsdefs.TFVNAOS:
		return buildAOS(vc, vcfc, fhp, field)
	default:
		return buildTM(vc, vcfc, fhp, field, ocf)
	}
}

func buildTM(vc VCConfig, vcfc uint32, fhp uint16, field, ocf []byte) []byte {
	frame := make([]byte, 6+len(field)+len(ocf))
	// TFVN(00) | SCID(10) | VCID(3) | OCF flag
	v := (uint16(vc.SCID)&0x3FF)<<4 | (uint16(vc.VCID)&0x07)<<1
	if len(ocf) > 0 {
		v |= 1 // set the OCF flag
	}
	binary.BigEndian.PutUint16(frame[0:2], v)
	frame[2] = byte(vcfc) // master channel frame count (single MC here)
	frame[3] = byte(vcfc) // virtual channel frame count
	// Sec hdr(0) | sync(0) | pkt order(0) | seg len id(11) | FHP(11)
	status := uint16(0b11)<<11 | (fhp & 0x07FF)
	binary.BigEndian.PutUint16(frame[4:6], status)
	copy(frame[6:], field)
	copy(frame[6+len(field):], ocf) // OCF sits after the data field
	return frame
}

func buildAOS(vc VCConfig, vcfc uint32, fhp uint16, field []byte) []byte {
	frame := make([]byte, 6+2+len(field))
	// TFVN(01) | SCID(8) | VCID(6)
	v := uint16(1)<<14 | (uint16(vc.SCID)&0xFF)<<6 | (uint16(vc.VCID) & 0x3F)
	binary.BigEndian.PutUint16(frame[0:2], v)
	frame[2] = byte(vcfc >> 16)
	frame[3] = byte(vcfc >> 8)
	frame[4] = byte(vcfc)
	frame[5] = 0 // signaling field
	// M_PDU header: 5 spare bits + 11-bit FHP
	binary.BigEndian.PutUint16(frame[6:8], fhp&0x07FF)
	copy(frame[8:], field)
	return frame
}
