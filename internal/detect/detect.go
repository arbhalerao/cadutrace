// Package detect infers capture settings (sync, frame length, randomization,
// FECF, Reed-Solomon length) from the bytes, and finds the channels that are
// real versus one-off false decodes
package detect

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/arbhalerao/cadutrace/internal/decode/fecf"
	"github.com/arbhalerao/cadutrace/internal/decode/randomizer"
	"github.com/arbhalerao/cadutrace/internal/framing"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

const (
	asmLen       = 4
	sampleFrames = 256
	minFrames    = 8
	maxStride    = 4096
	lockScan     = 1 << 20
	goodScore    = 0.9
	crcQuorum    = 0.5
)

// Params are the settings detection fills in
// CADULen is the stride between frame starts, including ASM and RS symbols
type Params struct {
	NoASM       bool
	ASM         uint32
	CADULen     int
	RSLen       int
	Derandomize bool
	FECF        bool
	TFVN        ccsdsdefs.TFVN
}

// Fixed marks the Params the user set explicitly; detection leaves those alone
type Fixed struct {
	Sync, CADULen, RSLen, Derandomize, FECF bool
}

// Framing returns the framer configuration for p
func (p Params) Framing() framing.Config {
	return framing.Config{CADULen: p.CADULen, ASM: p.ASM, RSLen: p.RSLen, NoASM: p.NoASM, Derandomize: p.Derandomize}
}

// Detect fills in the unfixed fields of p from data and returns notes describing
// what it inferred or could not infer
func Detect(data []byte, p Params, fixed Fixed) (Params, []string, error) {
	if p.ASM == 0 {
		p.ASM = ccsdsdefs.ASMStandard
	}
	var notes []string
	note := func(format string, a ...any) { notes = append(notes, fmt.Sprintf(format, a...)) }

	var asm [asmLen]byte
	binary.BigEndian.PutUint32(asm[:], p.ASM)

	if !fixed.Sync {
		stride, ok := lockASM(data, asm[:])
		p.NoASM = !ok
		if ok && !fixed.CADULen {
			p.CADULen = stride
		}
		if ok {
			note("sync: marker %08X every %d octets", p.ASM, p.CADULen)
		} else {
			note("sync: no marker found, reading frames back to back")
		}
	}

	derandDecided := fixed.Derandomize
	if p.NoASM && !fixed.CADULen {
		stride, derand, ok := bareStride(data, fixed.Derandomize, p.Derandomize)
		if !ok {
			return p, notes, fmt.Errorf("detect: no sync marker and no consistent frame length found; set --frame-len")
		}
		p.CADULen = stride
		if !fixed.Derandomize {
			p.Derandomize, derandDecided = derand, true
		}
		note("frame length: %d octets (from header continuity)", stride)
	}

	raw := sampleRaw(data, p)
	if len(raw) == 0 {
		return p, notes, fmt.Errorf("detect: no complete frames at the configured length")
	}

	if !derandDecided {
		plain, derand := score(headers(raw, false)), score(headers(raw, true))
		p.Derandomize = derand > plain+0.2 && derand >= 0.5
	}
	if p.Derandomize && !fixed.Derandomize {
		note("randomization: CCSDS pseudo-randomizer detected")
	}
	frames := raw
	if p.Derandomize {
		frames = make([][]byte, len(raw))
		for i, r := range raw {
			frames[i] = append([]byte(nil), r...)
			randomizer.Apply(frames[i])
		}
	}

	p.TFVN = majorityTFVN(frames)
	if s := score(headers(frames, false)); s < goodScore {
		note("warning: frame headers are inconsistent (score %.2f); results may be unreliable", s)
	}

	if !fixed.FECF || p.FECF {
		cands := []int{p.RSLen}
		if !fixed.RSLen {
			cands = rsCandidates(p.CADULen)
		}
		found := false
		for _, rs := range cands {
			if crcPassRate(frames, rs) >= crcQuorum {
				p.FECF, p.RSLen, found = true, rs, true
				break
			}
		}
		switch {
		case found && p.RSLen > 0 && !fixed.RSLen:
			note("FECF: present; %d trailing Reed-Solomon octets", p.RSLen)
		case found:
			note("FECF: present")
		case !fixed.FECF:
			p.FECF = false
			note("FECF: absent, so corrupted frames cannot be detected")
		}
	}
	return p, notes, nil
}

func lockASM(data, asm []byte) (int, bool) {
	limit := min(len(data), lockScan)
	first := bytes.Index(data[:limit], asm)
	if first < 0 {
		return 0, false
	}
	rest := data[first+asmLen:]
	next := bytes.Index(rest[:min(len(rest), maxStride+asmLen)], asm)
	if next < 0 {
		if len(data)-first <= maxStride+asmLen {
			return len(data) - first, true
		}
		return 0, false
	}
	stride := next + asmLen
	for i, pos := 0, first; i < minFrames && pos+asmLen <= len(data); i, pos = i+1, pos+stride {
		if !bytes.Equal(data[pos:pos+asmLen], asm) {
			return 0, false
		}
	}
	return stride, true
}

// bareStride finds the smallest frame length at which successive headers belong
// to one spacecraft and carry continuous frame counters
func bareStride(data []byte, fixedDerand, derand bool) (int, bool, bool) {
	modes := []bool{false, true}
	if fixedDerand {
		modes = []bool{derand}
	}
	for stride := 8; stride <= min(maxStride, len(data)/minFrames); stride++ {
		for _, d := range modes {
			n := min(sampleFrames, len(data)/stride)
			hs := make([][6]byte, n)
			for i := range hs {
				copy(hs[i][:], data[i*stride:])
				if d {
					xorPrefix(&hs[i])
				}
			}
			if score(hs) >= goodScore {
				return stride, d, true
			}
		}
	}
	return 0, false, false
}

func sampleRaw(data []byte, p Params) [][]byte {
	cfg := p.Framing()
	cfg.RSLen, cfg.Derandomize = 0, false
	fr, err := framing.New(data, cfg)
	if err != nil {
		return nil
	}
	var out [][]byte
	for len(out) < sampleFrames {
		rf, err := fr.NextRaw()
		if err != nil {
			break
		}
		out = append(out, rf.Data)
	}
	return out
}

var prefix = randomizer.Sequence()[:6]

func xorPrefix(h *[6]byte) {
	for i := range h {
		h[i] ^= prefix[i]
	}
}

func headers(frames [][]byte, derand bool) [][6]byte {
	hs := make([][6]byte, 0, len(frames))
	for _, f := range frames {
		if len(f) < 6 {
			continue
		}
		var h [6]byte
		copy(h[:], f)
		if derand {
			xorPrefix(&h)
		}
		hs = append(hs, h)
	}
	return hs
}

// score is the fraction of headers that share the dominant master channel (which
// must be TM or AOS), capped by how often a channel's frame counter advances by one
func score(hs [][6]byte) float64 {
	if len(hs) < 2 {
		return 0
	}
	mc := map[uint16]int{}
	for _, h := range hs {
		mc[mcKey(h)]++
	}
	var dom uint16
	for k, c := range mc {
		if c > mc[dom] || (c == mc[dom] && k < dom) {
			dom = k
		}
	}
	if t := ccsdsdefs.TFVN(dom >> 14); t != ccsdsdefs.TFVNTM && t != ccsdsdefs.TFVNAOS {
		return 0
	}
	consistency := float64(mc[dom]) / float64(len(hs))

	last := map[uint8]uint32{}
	steps, cont := 0, 0
	for _, h := range hs {
		if mcKey(h) != dom {
			continue
		}
		ch := ParseChannel(h[:])
		if prev, ok := last[ch.VCID]; ok {
			steps++
			if ch.Count == (prev+1)%ch.Modulus {
				cont++
			}
		}
		last[ch.VCID] = ch.Count
	}
	if steps == 0 {
		return 0
	}
	return min(consistency, float64(cont)/float64(steps))
}

func mcKey(h [6]byte) uint16 {
	v := uint16(h[0])<<8 | uint16(h[1])
	if ccsdsdefs.TFVN(h[0]>>6) == ccsdsdefs.TFVNAOS {
		return v & 0xFFC0
	}
	return v & 0xFFF0
}

func majorityTFVN(frames [][]byte) ccsdsdefs.TFVN {
	var n [4]int
	for _, f := range frames {
		n[f[0]>>6]++
	}
	if n[ccsdsdefs.TFVNAOS] > n[ccsdsdefs.TFVNTM] {
		return ccsdsdefs.TFVNAOS
	}
	return ccsdsdefs.TFVNTM
}

func rsCandidates(stride int) []int {
	c := []int{0}
	for rs := 16; rs <= 320 && rs < stride/2; rs += 16 {
		c = append(c, rs)
	}
	return c
}

func crcPassRate(frames [][]byte, rs int) float64 {
	pass := 0
	for _, f := range frames {
		if n := len(f) - rs; n > 8 && fecf.Valid(f[:n]) {
			pass++
		}
	}
	return float64(pass) / float64(len(frames))
}
