package spacepacket

import (
	"encoding/binary"
	"errors"

	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// HeaderLen is the fixed primary-header size
const HeaderLen = 6

var ErrShort = errors.New("spacepacket: buffer too short")

// TotalLen returns header + data-field length; caller ensures len(b) >= HeaderLen
func TotalLen(b []byte) int {
	return HeaderLen + int(binary.BigEndian.Uint16(b[4:6])) + 1
}

// ParseHeader parses the 6-octet primary header (Payload left nil)
func ParseHeader(b []byte) (model.SpacePacket, error) {
	if len(b) < HeaderLen {
		return model.SpacePacket{}, ErrShort
	}
	b0 := b[0]
	sp := model.SpacePacket{
		Version:    b0 >> 5,
		Type:       ccsdsdefs.PacketType((b0 >> 4) & 0x01),
		SecHdrFlag: (b0>>3)&0x01 == 1,
		APID:       ccsdsdefs.APID(uint16(b0&0x07)<<8 | uint16(b[1])),
		SeqFlags:   ccsdsdefs.SeqFlags(b[2] >> 6),
		SeqCount:   uint16(b[2]&0x3F)<<8 | uint16(b[3]),
		DataLen:    binary.BigEndian.Uint16(b[4:6]),
	}
	return sp, nil
}

// Parse parses a complete packet, Payload sliced from the data field
func Parse(b []byte) (model.SpacePacket, error) {
	sp, err := ParseHeader(b)
	if err != nil {
		return sp, err
	}
	total := HeaderLen + int(sp.DataLen) + 1
	if len(b) < total {
		return sp, ErrShort
	}
	sp.Payload = b[HeaderLen:total]
	return sp, nil
}
