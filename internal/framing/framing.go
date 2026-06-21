package framing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/arbhalerao/cadutrace/internal/decode/randomizer"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// Config configures the framer; zero values select sensible defaults
type Config struct {
	CADULen     int    // total CADU length in octets; 0 = infer from first two ASMs
	ASM         uint32 // 4-octet sync marker; 0 selects ASMStandard
	RSLen       int    // trailing Reed-Solomon check symbols to skip per frame
	MaxSearch   int    // max octets to scan for the initial lock; 0 = whole buffer
	Derandomize bool   // XOR each frame with the CCSDS 131.0 pseudo-randomizer
}

const asmLen = 4

// RawFrame is one ASM-stripped transfer frame and its byte offset in the source
type RawFrame struct {
	Data   []byte
	Offset int64
}

// Framer walks a CADU stream
type Framer struct {
	data        []byte
	asm         [asmLen]byte
	cadu        int
	frameLen    int
	rsLen       int
	pos         int
	derandomize bool
}

// New locks onto the first ASM and infers the CADU length when not configured
func New(data []byte, cfg Config) (*Framer, error) {
	asmVal := cfg.ASM
	if asmVal == 0 {
		asmVal = ccsdsdefs.ASMStandard
	}
	f := &Framer{data: data, rsLen: cfg.RSLen, derandomize: cfg.Derandomize}
	binary.BigEndian.PutUint32(f.asm[:], asmVal)

	searchLimit := len(data)
	if cfg.MaxSearch > 0 && cfg.MaxSearch < searchLimit {
		searchLimit = cfg.MaxSearch
	}
	first := f.findASM(0, searchLimit)
	if first < 0 {
		return nil, errors.New("framing: no sync marker found")
	}
	f.pos = first

	f.cadu = cfg.CADULen
	if f.cadu == 0 {
		next := f.findASM(first+asmLen, len(data))
		if next > first {
			f.cadu = next - first
		} else {
			f.cadu = len(data) - first // single frame in the capture
		}
	}
	f.frameLen = f.cadu - asmLen - f.rsLen
	if f.frameLen <= 0 {
		return nil, fmt.Errorf("framing: non-positive frame length (cadu=%d, rs=%d)", f.cadu, f.rsLen)
	}
	return f, nil
}

// findASM returns the offset of the next sync marker in [start, limit), or -1
func (f *Framer) findASM(start, limit int) int {
	for i := start; i+asmLen <= limit; i++ {
		if f.data[i] == f.asm[0] && f.data[i+1] == f.asm[1] &&
			f.data[i+2] == f.asm[2] && f.data[i+3] == f.asm[3] {
			return i
		}
	}
	return -1
}

func (f *Framer) FrameLen() int { return f.frameLen }
func (f *Framer) CADULen() int  { return f.cadu }

// Next returns the next transfer frame, or io.EOF when the stream is exhausted
// On a sync mismatch it searches forward to re-lock
func (f *Framer) Next() (RawFrame, error) {
	for {
		if f.pos+f.cadu > len(f.data) {
			return RawFrame{}, io.EOF
		}
		if !(f.data[f.pos] == f.asm[0] && f.data[f.pos+1] == f.asm[1] &&
			f.data[f.pos+2] == f.asm[2] && f.data[f.pos+3] == f.asm[3]) {
			next := f.findASM(f.pos+1, len(f.data))
			if next < 0 {
				return RawFrame{}, io.EOF
			}
			f.pos = next
			continue
		}
		start := f.pos + asmLen
		data := f.data[start : start+f.frameLen]
		if f.derandomize {
			// own a copy so the read-only source (e.g. mmap) is never mutated and
			// the derandomized bytes outlive this call for downstream zero-copy
			owned := make([]byte, f.frameLen)
			copy(owned, data)
			randomizer.Apply(owned)
			data = owned
		}
		rf := RawFrame{Data: data, Offset: int64(f.pos)}
		f.pos += f.cadu
		return rf, nil
	}
}
