package ccsdsdefs

import "fmt"

// TFVN is the 2-bit Transfer Frame Version Number in a transfer frame primary
// header
// It selects the frame format
type TFVN uint8

const (
	TFVNTM  TFVN = 0b00 // CCSDS 132.0-B TM Transfer Frame
	TFVNAOS TFVN = 0b01 // CCSDS 732.0-B AOS Transfer Frame
)

func (v TFVN) String() string {
	switch v {
	case TFVNTM:
		return "TM"
	case TFVNAOS:
		return "AOS"
	default:
		return fmt.Sprintf("TFVN(%d)", uint8(v))
	}
}

// SCID is a Spacecraft Identifier
// It is 10 bits for TM and 8 bits for AOS; both are normalized into this uint16
type SCID uint16

// VCID is a Virtual Channel Identifier: 3 bits for TM, 6 bits for AOS
type VCID uint8

// APID is the 11-bit Application Process Identifier in a Space Packet header
type APID uint16

// Protocol-level sentinel values
const (
	APIDIdle    APID   = 0x7FF      // idle space packet
	FHPNoStart  uint16 = 0x7FF      // First Header Pointer: no packet starts in this frame
	FHPIdleOnly uint16 = 0x7FE      // First Header Pointer: data field is only idle data
	ASMStandard uint32 = 0x1ACFFC1D // standard 4-octet Attached Sync Marker
)

// MaxSpacePacket is the largest possible space packet: 6-octet primary header plus a data field of (DataLen+1) octets, with DataLen capped at 0xFFFF
// Used as the default reassembly/spillage guard
const MaxSpacePacket = 6 + 0xFFFF + 1 // 65542

// IsIdle reports whether an APID denotes the idle pattern
func (a APID) IsIdle() bool { return a == APIDIdle }

// PacketType is the 1-bit Packet Type field: telemetry or telecommand
type PacketType uint8

const (
	PacketTypeTM PacketType = 0
	PacketTypeTC PacketType = 1
)

func (t PacketType) String() string {
	if t == PacketTypeTC {
		return "TC"
	}
	return "TM"
}

// SeqFlags is the 2-bit Sequence Flags field of a Space Packet
type SeqFlags uint8

const (
	SeqContinuation SeqFlags = 0b00
	SeqFirst        SeqFlags = 0b01
	SeqLast         SeqFlags = 0b10
	SeqUnsegmented  SeqFlags = 0b11
)

func (s SeqFlags) String() string {
	switch s {
	case SeqContinuation:
		return "cont"
	case SeqFirst:
		return "first"
	case SeqLast:
		return "last"
	case SeqUnsegmented:
		return "unseg"
	default:
		return "?"
	}
}

// MPDUType identifies how an AOS transfer frame data field is structured
// AOS frames do not self-describe this, so it comes from VC configuration
type MPDUType uint8

const (
	MPDUTypeMPDU MPDUType = iota // M_PDU: carries space packets, has a First Header Pointer
	MPDUTypeBPDU                 // B_PDU: bitstream data (no packet extraction)
	MPDUTypeVCA                  // VCA: opaque virtual channel access data
	MPDUTypeIdle                 // idle data
)

func (m MPDUType) String() string {
	switch m {
	case MPDUTypeMPDU:
		return "M_PDU"
	case MPDUTypeBPDU:
		return "B_PDU"
	case MPDUTypeVCA:
		return "VCA"
	case MPDUTypeIdle:
		return "Idle"
	default:
		return "?"
	}
}
