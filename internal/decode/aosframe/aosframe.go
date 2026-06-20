package aosframe

import (
	"fmt"

	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// PrimaryHeaderLen is the fixed AOS primary header size
const PrimaryHeaderLen = 6

// Config carries the mission-fixed AOS layout
// DataFieldType is the default for all VCs; DataFieldTypeByVCID overrides per VC
type Config struct {
	HasFHEC             bool // 2-octet Frame Header Error Control present
	InsertZoneLen       int  // length of the optional Insert Zone, 0 if absent
	HasOCF              bool // 4-octet Operational Control Field present
	HasFECF             bool // 2-octet Frame Error Control Field present
	DataFieldType       ccsdsdefs.MPDUType
	DataFieldTypeByVCID map[ccsdsdefs.VCID]ccsdsdefs.MPDUType
}

// Parse decodes an AOS frame into a fresh value (wrapper around ParseInto)
func Parse(raw []byte, cfg Config) (*model.AOSFrame, error) {
	f := &model.AOSFrame{}
	if err := ParseInto(f, raw, cfg); err != nil {
		return nil, err
	}
	return f, nil
}

// ParseInto decodes into a caller-provided value to keep the hot path allocation-free
func ParseInto(f *model.AOSFrame, raw []byte, cfg Config) error {
	if len(raw) < PrimaryHeaderLen {
		return fmt.Errorf("aosframe: short frame: %d octets", len(raw))
	}
	*f = model.AOSFrame{Raw: raw}

	// Octets 0-1: TFVN(2) | SCID(8) | VCID(6)
	f.MCID.TFVN = ccsdsdefs.TFVN(raw[0] >> 6)
	f.MCID.SCID = ccsdsdefs.SCID(uint16(raw[0]&0x3F)<<2 | uint16(raw[1]>>6))
	f.VCID = ccsdsdefs.VCID(raw[1] & 0x3F)

	// Octets 2-4: 24-bit VC frame count; octet 5: signaling field
	f.VCFrameCount = uint32(raw[2])<<16 | uint32(raw[3])<<8 | uint32(raw[4])
	f.ReplayFlag = raw[5]>>7&0x01 == 1

	off := PrimaryHeaderLen
	if cfg.HasFHEC {
		if off+2 > len(raw) {
			return fmt.Errorf("aosframe: FHEC overruns frame")
		}
		off += 2
	}
	if cfg.InsertZoneLen > 0 {
		if off+cfg.InsertZoneLen > len(raw) {
			return fmt.Errorf("aosframe: insert zone overruns frame")
		}
		f.InsertZone = raw[off : off+cfg.InsertZoneLen]
		off += cfg.InsertZoneLen
	}

	end := len(raw)
	if cfg.HasFECF {
		if end-2 < off {
			return fmt.Errorf("aosframe: FECF overruns frame")
		}
		end -= 2
	}
	if cfg.HasOCF {
		if end-4 < off {
			return fmt.Errorf("aosframe: OCF overruns frame")
		}
		f.OCF = raw[end-4 : end]
		end -= 4
	}

	dft := cfg.DataFieldType
	if cfg.DataFieldTypeByVCID != nil {
		if t, ok := cfg.DataFieldTypeByVCID[f.VCID]; ok {
			dft = t
		}
	}
	f.DataFieldType = dft

	if dft == ccsdsdefs.MPDUTypeMPDU {
		// M_PDU header: 5 spare bits + 11-bit First Header Pointer
		if off+2 > end {
			return fmt.Errorf("aosframe: M_PDU header overruns frame")
		}
		f.FHP = (uint16(raw[off])<<8 | uint16(raw[off+1])) & 0x07FF
		f.DataField = raw[off+2 : end]
	} else {
		f.DataField = raw[off:end]
	}
	return nil
}
