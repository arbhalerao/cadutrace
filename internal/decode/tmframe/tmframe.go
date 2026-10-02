package tmframe

import (
	"fmt"

	"github.com/arbhalerao/cadutrace/internal/decode/fecf"
	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// PrimaryHeaderLen is the fixed TM primary header size
const PrimaryHeaderLen = 6

// Config carries the mission-fixed layout the frame format doesn't self-describe
// (OCF and secondary-header presence come from per-frame flags)
type Config struct {
	HasFECF bool // 2-octet Frame Error Control Field present at end of frame
}

// Parse decodes a TM frame into a fresh value (wrapper around ParseInto)
func Parse(raw []byte, cfg Config) (*model.TMFrame, error) {
	f := &model.TMFrame{}
	if err := ParseInto(f, raw, cfg); err != nil {
		return nil, err
	}
	return f, nil
}

// ParseInto decodes into a caller-provided value to keep the hot path allocation-free
func ParseInto(f *model.TMFrame, raw []byte, cfg Config) error {
	if len(raw) < PrimaryHeaderLen {
		return fmt.Errorf("tmframe: short frame: %d octets", len(raw))
	}
	*f = model.TMFrame{Raw: raw}

	// Octets 0-1: TFVN(2) | SCID(10) | VCID(3) | OCF flag(1)
	f.MCID.TFVN = ccsdsdefs.TFVN(raw[0] >> 6)
	f.MCID.SCID = ccsdsdefs.SCID(uint16(raw[0]&0x3F)<<4 | uint16(raw[1]>>4))
	f.VCID = ccsdsdefs.VCID((raw[1] >> 1) & 0x07)
	ocfFlag := raw[1]&0x01 == 1

	// Octets 2-3: Master/Virtual Channel frame counts
	f.MCFrameCount = raw[2]
	f.VCFrameCount = raw[3]

	// Octets 4-5: data field status
	status := uint16(raw[4])<<8 | uint16(raw[5])
	f.SecHdrFlag = status>>15&0x01 == 1
	f.SyncFlag = status>>14&0x01 == 1
	f.FHP = status & 0x07FF

	dataStart := PrimaryHeaderLen
	if f.SecHdrFlag {
		if len(raw) < PrimaryHeaderLen+1 {
			return fmt.Errorf("tmframe: truncated secondary header")
		}
		// Secondary header: 1 ID octet (version[2] | length[6]) + length octets
		// the 6-bit length counts the octets following the ID octet
		shLen := int(raw[PrimaryHeaderLen]&0x3F) + 1
		if PrimaryHeaderLen+shLen > len(raw) {
			return fmt.Errorf("tmframe: secondary header overruns frame")
		}
		f.SecondaryHdr = raw[PrimaryHeaderLen : PrimaryHeaderLen+shLen]
		dataStart = PrimaryHeaderLen + shLen
	}

	end := len(raw)
	if cfg.HasFECF {
		if end-2 < dataStart {
			return fmt.Errorf("tmframe: FECF overruns frame")
		}
		if !fecf.Valid(raw) {
			return fecf.ErrMismatch
		}
		end -= 2
		f.HasFECF = true
	}
	if ocfFlag {
		if end-4 < dataStart {
			return fmt.Errorf("tmframe: OCF overruns frame")
		}
		f.OCF = raw[end-4 : end]
		end -= 4
	}
	f.DataField = raw[dataStart:end]
	return nil
}
