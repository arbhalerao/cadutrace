package clcw

import "errors"

// CLCW is a decoded Communications Link Control Word
type CLCW struct {
	VersionNumber uint8 // 00
	StatusField   uint8 // mission-specific (3 bits)
	COPInEffect   uint8 // 01 = COP-1
	VCID          uint8 // VC this CLCW reports on (6 bits)
	NoRFAvailable bool
	NoBitLock     bool
	Lockout       bool
	Wait          bool
	Retransmit    bool
	FARMBCounter  uint8 // 2 bits
	ReportValue   uint8 // next expected frame sequence number N(R)
}

var (
	ErrShort   = errors.New("clcw: need 4 octets")
	ErrNotCLCW = errors.New("clcw: control word type is not CLCW")
)

// IsCLCW reports whether a 4-octet OCF is a CLCW (control-word-type bit == 0)
func IsCLCW(ocf []byte) bool { return len(ocf) == 4 && ocf[0]&0x80 == 0 }

// Parse decodes a 4-octet OCF as a CLCW
func Parse(ocf []byte) (CLCW, error) {
	if len(ocf) != 4 {
		return CLCW{}, ErrShort
	}
	if ocf[0]&0x80 != 0 {
		return CLCW{}, ErrNotCLCW
	}
	return CLCW{
		VersionNumber: (ocf[0] >> 5) & 0x03,
		StatusField:   (ocf[0] >> 2) & 0x07,
		COPInEffect:   ocf[0] & 0x03,
		VCID:          (ocf[1] >> 2) & 0x3F,
		NoRFAvailable: ocf[2]&0x80 != 0,
		NoBitLock:     ocf[2]&0x40 != 0,
		Lockout:       ocf[2]&0x20 != 0,
		Wait:          ocf[2]&0x10 != 0,
		Retransmit:    ocf[2]&0x08 != 0,
		FARMBCounter:  (ocf[2] >> 1) & 0x03,
		ReportValue:   ocf[3],
	}, nil
}
