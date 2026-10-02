package detect

import (
	"io"

	"github.com/arbhalerao/cadutrace/internal/framing"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// Channel is a global virtual channel (TFVN, SCID, VCID) plus the frame counter
// read from one header
type Channel struct {
	TFVN    ccsdsdefs.TFVN
	SCID    ccsdsdefs.SCID
	VCID    uint8
	Count   uint32
	Modulus uint32
}

// ChannelID identifies a global virtual channel
type ChannelID struct {
	TFVN ccsdsdefs.TFVN
	SCID ccsdsdefs.SCID
	VCID ccsdsdefs.VCID
}

// ParseChannel reads the channel identity and VC frame count from a TM or AOS
// primary header (at least 6 octets); other versions are reported as TM-shaped
func ParseChannel(h []byte) Channel {
	t := ccsdsdefs.TFVN(h[0] >> 6)
	if t == ccsdsdefs.TFVNAOS {
		return Channel{
			TFVN: t, SCID: ccsdsdefs.SCID(uint16(h[0]&0x3F)<<2 | uint16(h[1]>>6)), VCID: h[1] & 0x3F,
			Count: uint32(h[2])<<16 | uint32(h[3])<<8 | uint32(h[4]), Modulus: 1 << 24,
		}
	}
	return Channel{
		TFVN: t, SCID: ccsdsdefs.SCID(uint16(h[0]&0x3F)<<4 | uint16(h[1]>>4)), VCID: (h[1] >> 1) & 0x07,
		Count: uint32(h[3]), Modulus: 1 << 8,
	}
}

func (c Channel) ID() ChannelID { return ChannelID{c.TFVN, c.SCID, ccsdsdefs.VCID(c.VCID)} }

// smallCapture is the frame count below which every channel is trusted
const smallCapture = 16

// Channels walks every frame header and returns the channels that look real: those
// whose VC frame counter advances by one at least once. A false decode carries a
// random header, so its channel practically never shows two consecutive counts
// Captures too small to judge keep every channel
func Channels(data []byte, cfg framing.Config) (map[ChannelID]bool, error) {
	derand := cfg.Derandomize
	cfg.Derandomize = false
	fr, err := framing.New(data, cfg)
	if err != nil {
		return nil, err
	}
	type acc struct {
		last uint32
		cont bool
	}
	seen := map[ChannelID]*acc{}
	total := 0
	var h [6]byte
	for {
		rf, err := fr.NextRaw()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rf.Data) < 6 {
			continue
		}
		total++
		copy(h[:], rf.Data)
		if derand {
			xorPrefix(&h)
		}
		ch := ParseChannel(h[:])
		a := seen[ch.ID()]
		if a == nil {
			seen[ch.ID()] = &acc{last: ch.Count}
			continue
		}
		if ch.Count == (a.last+1)%ch.Modulus {
			a.cont = true
		}
		a.last = ch.Count
	}
	out := make(map[ChannelID]bool, len(seen))
	for id, a := range seen {
		out[id] = a.cont || total < smallCapture
	}
	return out, nil
}
