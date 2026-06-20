package decode

import (
	"errors"
	"fmt"

	"github.com/arbhalerao/cadutrace/internal/decode/aosframe"
	"github.com/arbhalerao/cadutrace/internal/decode/tmframe"
	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// TransferFrame is the common contract over TM and AOS frames
type TransferFrame interface {
	TFVN() ccsdsdefs.TFVN
	MasterChannel() model.MasterChannelID
	VirtualChannel() ccsdsdefs.VCID
	VCCount() uint32            // VC frame count, normalized to uint32
	VCCountModulus() uint32     // wrap modulus: 256 (TM) or 2^24 (AOS)
	Data() []byte               // data field (TM) or packet zone (AOS M_PDU)
	OperationalControl() []byte // 4-octet OCF (CLCW), or nil
	FirstHeaderPointer() (fhp uint16, ok bool)
}

var (
	_ TransferFrame = (*model.TMFrame)(nil)
	_ TransferFrame = (*model.AOSFrame)(nil)
)

// Config bundles the per-format parser configuration
type Config struct {
	TM  tmframe.Config
	AOS aosframe.Config
}

// FrameDecoder routes by Transfer Frame Version Number, reusing internal structs;
// the frame it returns is valid only until the next Decode and not concurrency-safe
type FrameDecoder struct {
	cfg Config
	tm  model.TMFrame
	aos model.AOSFrame
}

func NewFrameDecoder(cfg Config) *FrameDecoder { return &FrameDecoder{cfg: cfg} }

var ErrEmpty = errors.New("decode: empty frame")

// Decode parses one ASM-stripped transfer frame
func (d *FrameDecoder) Decode(raw []byte) (TransferFrame, error) {
	if len(raw) == 0 {
		return nil, ErrEmpty
	}
	switch ccsdsdefs.TFVN(raw[0] >> 6) {
	case ccsdsdefs.TFVNTM:
		if err := tmframe.ParseInto(&d.tm, raw, d.cfg.TM); err != nil {
			return nil, err
		}
		return &d.tm, nil
	case ccsdsdefs.TFVNAOS:
		if err := aosframe.ParseInto(&d.aos, raw, d.cfg.AOS); err != nil {
			return nil, err
		}
		return &d.aos, nil
	default:
		return nil, fmt.Errorf("decode: unsupported TFVN %d", raw[0]>>6)
	}
}
