// Package fecf computes and checks the CCSDS Frame Error Control Field
// (CRC-16-CCITT: poly 0x1021, init 0xFFFF, no reflection, no final XOR)
package fecf

import "errors"

// ErrMismatch reports a frame whose FECF does not match its contents
var ErrMismatch = errors.New("fecf: CRC mismatch")

var table = func() (t [256]uint16) {
	for i := range t {
		c := uint16(i) << 8
		for range 8 {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return
}()

// Sum returns the CRC of b
func Sum(b []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, x := range b {
		crc = crc<<8 ^ table[byte(crc>>8)^x]
	}
	return crc
}

// Valid reports whether the last two octets of frame are the CRC of the rest
func Valid(frame []byte) bool {
	n := len(frame)
	if n < 2 {
		return false
	}
	return Sum(frame[:n-2]) == uint16(frame[n-2])<<8|uint16(frame[n-1])
}
