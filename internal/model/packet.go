package model

import (
	"time"

	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// PacketKind distinguishes the packet types that share a frame data field
type PacketKind uint8

const (
	KindSpace   PacketKind = iota // 133.0 Space Packet (version 0b000)
	KindEncap                     // 133.1 Encapsulation Packet (version 0b111)
	KindUnknown                   // unrecognized version
)

// SpacePacket is a parsed (and possibly reassembled) CCSDS 133.0 space packet
type SpacePacket struct {
	Version    uint8                `json:"version"`
	Type       ccsdsdefs.PacketType `json:"type"`
	SecHdrFlag bool                 `json:"sec_hdr_flag"`
	APID       ccsdsdefs.APID       `json:"apid"`
	SeqFlags   ccsdsdefs.SeqFlags   `json:"seq_flags"`
	SeqCount   uint16               `json:"seq_count"`
	DataLen    uint16               `json:"data_len"`
	Payload    []byte               `json:"-"` // data field, after the header
	Raw        []byte               `json:"-"` // full packet bytes
	Truncated  bool                 `json:"truncated"`

	// Kind/ProtocolID describe Encapsulation packets
	// the Space Packet fields above are meaningless when Kind == KindEncap
	Kind       PacketKind
	ProtocolID uint8

	SCID ccsdsdefs.SCID `json:"scid"`
	VCID ccsdsdefs.VCID `json:"vcid"`

	Time time.Time `json:"-"` // from the secondary header time code, zero if none
}

func (p *SpacePacket) IsIdle() bool { return p.Kind == KindSpace && p.APID.IsIdle() }

// TotalLen is the on-wire length of a Space Packet in octets
func (p *SpacePacket) TotalLen() int { return 6 + int(p.DataLen) + 1 }

// ByteLen is the on-wire length for any packet kind
func (p *SpacePacket) ByteLen() int {
	if p.Kind == KindEncap {
		return len(p.Raw)
	}
	return p.TotalLen()
}
