package testgen

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// Streaming generators write CADUs straight to an io.Writer with continuous per-VC
// frame counters and bounded memory, so gigabyte captures need no full buffering
// Build (in testgen.go) is the in-memory path

// packer accumulates packet bytes and emits fixed-size data fields, computing the
// FHP for each; only the not-yet-emitted tail is retained, so memory stays bounded
type packer struct {
	dataLen int
	pending []byte
	bounds  []int // packet-start offsets within pending
}

func (p *packer) add(pkt []byte) {
	p.bounds = append(p.bounds, len(p.pending))
	p.pending = append(p.pending, pkt...)
}

func (p *packer) ready() bool { return len(p.pending) >= p.dataLen }

// field returns the next data field and its FHP, advancing past it
func (p *packer) field() (field []byte, fhp uint16) {
	fhp = ccsdsdefs.FHPNoStart
	for _, b := range p.bounds {
		if b >= 0 && b < p.dataLen {
			fhp = uint16(b)
			break
		}
	}
	field = make([]byte, p.dataLen)
	copy(field, p.pending[:p.dataLen])

	rest := p.pending[p.dataLen:]
	p.pending = append(make([]byte, 0, len(rest)+128), rest...) // compact to bound memory
	shifted := p.bounds[:0]
	for _, b := range p.bounds {
		if nb := b - p.dataLen; nb >= 0 {
			shifted = append(shifted, nb)
		}
	}
	p.bounds = shifted
	return field, fhp
}

// vcGen produces an endless cycle of packets for one virtual channel
type vcGen struct {
	cfg   VCConfig
	pk    packer
	vcfc  uint32
	i     int
	seq   map[ccsdsdefs.APID]uint16
	count map[ccsdsdefs.APID]int
}

func (g *vcGen) nextPacket() []byte {
	i := g.i
	g.i++
	if g.cfg.Encap {
		pid := g.cfg.EncapProtocols[i%len(g.cfg.EncapProtocols)]
		return encapPacket(pid, g.cfg.PacketLen, byte(i))
	}
	apid := g.cfg.APIDs[i%len(g.cfg.APIDs)]
	s := g.seq[apid]
	g.count[apid]++
	g.seq[apid] = g.cfg.nextSeq(s, g.count[apid])
	return g.cfg.packet(apid, s, byte(i), i)
}

// WriteStream writes interleaved CADUs for cfg to w until targetBytes, with
// continuous VC frame counters; if dropEveryN > 0, every Nth CADU is generated but
// not written (its counter still advances), simulating downlink loss
func WriteStream(w io.Writer, cfg StreamConfig, targetBytes int64, dropEveryN int) error {
	if cfg.FrameDataLen < 7 {
		return fmt.Errorf("testgen: FrameDataLen must be >= 7, got %d", cfg.FrameDataLen)
	}
	asm := cfg.ASM
	if asm == 0 {
		asm = ccsdsdefs.ASMStandard
	}
	var asmBytes [asmLen]byte
	binary.BigEndian.PutUint32(asmBytes[:], asm)

	ocf := cfg.OCF
	if cfg.FrameType != ccsdsdefs.TFVNTM {
		ocf = nil
	}

	gens := make([]*vcGen, 0, len(cfg.VCs))
	for _, vc := range cfg.VCs {
		if vc.FrameType != cfg.FrameType {
			return fmt.Errorf("testgen: VC %d/%d frame type differs from stream", vc.SCID, vc.VCID)
		}
		minLen := 7
		if vc.Encap {
			minLen = 2
		}
		if vc.PacketLen < minLen {
			return fmt.Errorf("testgen: PacketLen must be >= %d, got %d", minLen, vc.PacketLen)
		}
		gens = append(gens, &vcGen{cfg: vc, pk: packer{dataLen: cfg.FrameDataLen}, seq: map[ccsdsdefs.APID]uint16{}, count: map[ccsdsdefs.APID]int{}})
	}

	bw := bufio.NewWriterSize(w, 1<<20)
	var written int64
	caduCount := 0
	for written < targetBytes {
		for _, g := range gens {
			for !g.pk.ready() {
				g.pk.add(g.nextPacket())
			}
			field, fhp := g.pk.field()
			frame := buildFrame(cfg.FrameType, g.cfg, g.vcfc, fhp, field, ocf)
			g.vcfc++

			drop := dropEveryN > 0 && caduCount%dropEveryN == dropEveryN-1
			caduCount++
			if drop {
				continue // generated but "lost" in transit
			}
			frame = finish(frame, cfg)
			if _, err := bw.Write(asmBytes[:]); err != nil {
				return err
			}
			if _, err := bw.Write(frame); err != nil {
				return err
			}
			written += int64(asmLen + len(frame))
		}
	}
	return bw.Flush()
}

// WriteCFDPStream writes one CFDP transaction (Metadata, File Data over [0,fileSize)
// in chunks, EOF, Finished) to w with bounded memory; offsets in skip are omitted
func WriteCFDPStream(w io.Writer, scid ccsdsdefs.SCID, vcid ccsdsdefs.VCID, apid ccsdsdefs.APID,
	src, tsn, dst uint8, fileSize, chunk, frameDataLen int, skip map[int]bool, asmVal uint32) error {
	if asmVal == 0 {
		asmVal = ccsdsdefs.ASMStandard
	}
	var asmBytes [asmLen]byte
	binary.BigEndian.PutUint32(asmBytes[:], asmVal)

	bw := bufio.NewWriterSize(w, 1<<20)
	pk := packer{dataLen: frameDataLen}
	vc := VCConfig{SCID: scid, VCID: vcid, FrameType: ccsdsdefs.TFVNTM}
	var vcfc uint32
	seq := uint16(0)

	emitFull := func() error {
		for pk.ready() {
			field, fhp := pk.field()
			frame := buildTM(vc, vcfc, fhp, field, nil)
			vcfc++
			if _, err := bw.Write(asmBytes[:]); err != nil {
				return err
			}
			if _, err := bw.Write(frame); err != nil {
				return err
			}
		}
		return nil
	}
	push := func(pdu []byte) error {
		pk.add(spacePacketWith(apid, seq, pdu))
		seq++
		return emitFull()
	}

	if err := push(CFDPMetadata(src, tsn, dst, uint32(fileSize), "src.dat", "dst.dat")); err != nil {
		return err
	}
	for off := 0; off < fileSize; off += chunk {
		n := chunk
		if off+n > fileSize {
			n = fileSize - off
		}
		if skip[off] {
			continue
		}
		data := make([]byte, n)
		for i := range data {
			data[i] = byte((off + i) & 0xFF)
		}
		if err := push(CFDPFileData(src, tsn, dst, uint32(off), data)); err != nil {
			return err
		}
	}
	if err := push(CFDPEOF(src, tsn, dst, uint32(fileSize), 0xCAFEF00D)); err != nil {
		return err
	}
	if err := push(CFDPFinished(src, tsn, dst, 0, 0, 0)); err != nil {
		return err
	}

	// pad the final partial field with an idle packet so the last PDU is framed
	if len(pk.pending) > 0 {
		pad := pk.dataLen - len(pk.pending)%pk.dataLen
		if pad < 7 {
			pad += pk.dataLen
		}
		pk.add(spacePacket(ccsdsdefs.APIDIdle, 0, pad, 0xCA))
		if err := emitFull(); err != nil {
			return err
		}
	}
	return bw.Flush()
}
