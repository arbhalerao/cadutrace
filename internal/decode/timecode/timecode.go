// Package timecode decodes CCSDS 301.0 time codes (CUC and CDS) found in packet
// secondary headers
package timecode

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Kind is the time code family
type Kind uint8

const (
	CUC Kind = iota + 1 // unsegmented: coarse seconds + binary fraction
	CDS                 // day segmented: days + ms of day + optional sub-ms
)

// Format locates and describes a time code within a packet secondary header
// For CUC, A and B are the coarse and fine octet counts; for CDS they are the day
// and sub-millisecond octet counts. PField means a one-octet P-field precedes it
type Format struct {
	Kind   Kind
	A, B   int
	PField bool
	Offset int
}

// Len is the octet length including any P-field
func (f Format) Len() int {
	n := f.A + f.B
	if f.Kind == CDS {
		n += 4
	}
	if f.PField {
		n++
	}
	return n
}

func (f Format) String() string {
	name := "cuc"
	if f.Kind == CDS {
		name = "cds"
	}
	s := fmt.Sprintf("%s%d.%d", name, f.A, f.B)
	if f.PField {
		s += "+p"
	}
	return fmt.Sprintf("%s@%d", s, f.Offset)
}

// Parse reads a format written as String does, e.g. "cuc4.2@7" or "cds2.0+p"
func Parse(s string) (Format, error) {
	var f Format
	orig := s
	s = strings.ToLower(strings.TrimSpace(s))
	if head, off, ok := strings.Cut(s, "@"); ok {
		n, err := strconv.Atoi(off)
		if err != nil || n < 0 {
			return f, fmt.Errorf("timecode: bad offset in %q", orig)
		}
		f.Offset, s = n, head
	}
	s, f.PField = strings.CutSuffix(s, "+p")
	switch {
	case strings.HasPrefix(s, "cuc"):
		f.Kind = CUC
	case strings.HasPrefix(s, "cds"):
		f.Kind = CDS
	default:
		return f, fmt.Errorf("timecode: %q is not cuc or cds", orig)
	}
	a, b, ok := strings.Cut(s[3:], ".")
	if !ok {
		return f, fmt.Errorf("timecode: %q needs a size such as cuc4.2", orig)
	}
	var err1, err2 error
	f.A, err1 = strconv.Atoi(a)
	f.B, err2 = strconv.Atoi(b)
	if err1 != nil || err2 != nil || !f.valid() {
		return f, fmt.Errorf("timecode: unsupported size in %q", orig)
	}
	return f, nil
}

func (f Format) valid() bool {
	switch f.Kind {
	case CUC:
		return f.A >= 1 && f.A <= 4 && f.B >= 0 && f.B <= 3
	case CDS:
		return (f.A == 2 || f.A == 3) && (f.B == 0 || f.B == 2 || f.B == 4)
	}
	return false
}

// pfieldOK reports whether p is a P-field CCSDS 301.0 allows for f; CUC accepts
// either epoch level
func (f Format) pfieldOK(p byte) bool {
	if p&0x80 != 0 {
		return false
	}
	id := p >> 4 & 0x07
	switch f.Kind {
	case CUC:
		return (id == 0b001 || id == 0b010) && int(p>>2&0x03)+1 == f.A && int(p&0x03) == f.B
	case CDS:
		day := 2
		if p>>2&0x01 == 1 {
			day = 3
		}
		sub := [4]int{0, 2, 4, -1}[p&0x03]
		return id == 0b100 && day == f.A && sub == f.B
	}
	return false
}

// Decode reads the time code from a secondary header as a duration since the
// epoch; ok is false when the header is too short or the bytes are not valid
func (f Format) Decode(sh []byte) (time.Duration, bool) {
	if f.Offset+f.Len() > len(sh) {
		return 0, false
	}
	b := sh[f.Offset : f.Offset+f.Len()]
	if f.PField {
		if !f.pfieldOK(b[0]) {
			return 0, false
		}
		b = b[1:]
	}
	if f.Kind == CUC {
		var coarse, fine uint64
		for _, x := range b[:f.A] {
			coarse = coarse<<8 | uint64(x)
		}
		for _, x := range b[f.A:] {
			fine = fine<<8 | uint64(x)
		}
		ns := fine * uint64(time.Second) >> (8 * f.B)
		return time.Duration(coarse)*time.Second + time.Duration(ns), true
	}
	var day uint64
	for _, x := range b[:f.A] {
		day = day<<8 | uint64(x)
	}
	b = b[f.A:]
	ms := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	if ms >= 86_400_000 {
		return 0, false
	}
	d := time.Duration(day)*24*time.Hour + time.Duration(ms)*time.Millisecond
	switch f.B {
	case 2:
		us := uint64(b[4])<<8 | uint64(b[5])
		if us >= 1000 {
			return 0, false
		}
		d += time.Duration(us) * time.Microsecond
	case 4:
		ps := uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
		if ps >= 1_000_000_000 {
			return 0, false
		}
		d += time.Duration(ps / 1000)
	}
	return d, true
}

// Encode is the inverse of Decode, filling only the time code's own octets
func (f Format) Encode(d time.Duration) []byte {
	var out []byte
	if f.PField {
		out = append(out, f.pfield())
	}
	put := func(v uint64, n int) {
		for i := n - 1; i >= 0; i-- {
			out = append(out, byte(v>>(8*i)))
		}
	}
	if f.Kind == CUC {
		sec := uint64(d / time.Second)
		frac := uint64(d % time.Second)
		put(sec, f.A)
		put(frac<<(8*f.B)/uint64(time.Second), f.B)
		return out
	}
	day := uint64(d / (24 * time.Hour))
	rest := d % (24 * time.Hour)
	put(day, f.A)
	put(uint64(rest/time.Millisecond), 4)
	sub := rest % time.Millisecond
	switch f.B {
	case 2:
		put(uint64(sub/time.Microsecond), 2)
	case 4:
		put(uint64(sub)*1000, 4)
	}
	return out
}

func (f Format) pfield() byte {
	if f.Kind == CUC {
		return 0b001<<4 | byte(f.A-1)<<2 | byte(f.B)
	}
	p := byte(0b100 << 4)
	if f.A == 3 {
		p |= 1 << 2
	}
	return p | map[int]byte{0: 0, 2: 1, 4: 2}[f.B]
}

// Common epochs; CCSDS 301.0 level 1 time codes count from 1958-01-01
var (
	EpochCCSDS = time.Date(1958, 1, 1, 0, 0, 0, 0, time.UTC)
	Epoch2000  = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	EpochGPS   = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
	EpochUnix  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
)

// ParseEpoch accepts ccsds, 2000, gps, unix, or an RFC 3339 date
func ParseEpoch(s string) (time.Time, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ccsds", "1958":
		return EpochCCSDS, nil
	case "2000", "j2000":
		return Epoch2000, nil
	case "gps", "1980":
		return EpochGPS, nil
	case "unix", "1970":
		return EpochUnix, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("timecode: unknown epoch %q", s)
}
