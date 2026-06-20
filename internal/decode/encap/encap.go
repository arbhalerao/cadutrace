package encap

import "fmt"

// PVN is the Encapsulation Packet version number (3 bits = 0b111)
const PVN = 0x7

// Protocol IDs (CCSDS 133.1-B)
const (
	ProtoIdle     = 0
	ProtoLTP      = 1
	ProtoIPE      = 2 // IP
	ProtoMission  = 6
	ProtoExtended = 7
)

// ProtocolName returns a human-readable name for a 3-bit protocol id
func ProtocolName(id uint8) string {
	switch id {
	case ProtoIdle:
		return "idle"
	case ProtoLTP:
		return "LTP"
	case ProtoIPE:
		return "IP (IPE)"
	case ProtoMission:
		return "mission"
	case ProtoExtended:
		return "extended"
	default:
		return fmt.Sprintf("proto-%d", id)
	}
}

// ProtocolID extracts the 3-bit Protocol ID from the first octet
func ProtocolID(b0 byte) uint8 { return (b0 >> 2) & 0x07 }

// HeaderLen is the header size (1/2/4/8 octets) from the 2-bit Length-of-Length field
func HeaderLen(b0 byte) int {
	return [4]int{1, 2, 4, 8}[b0&0x03]
}

// TotalLen returns the packet length and whether enough header bytes are present
// The length field's width and position depend on the Length-of-Length field
func TotalLen(b []byte) (total int, ok bool) {
	if len(b) < 1 {
		return 0, false
	}
	switch b[0] & 0x03 {
	case 0: // 1-octet header, packet is the header (idle/fill)
		return 1, true
	case 1: // 2-octet header, 8-bit length
		if len(b) < 2 {
			return 0, false
		}
		return int(b[1]), true
	case 2: // 4-octet header, 16-bit length
		if len(b) < 4 {
			return 0, false
		}
		return int(b[2])<<8 | int(b[3]), true
	default: // 8-octet header, 32-bit length
		if len(b) < 8 {
			return 0, false
		}
		return int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7]), true
	}
}
