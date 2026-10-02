package analysis

import (
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// Severity ranks an analysis event
type Severity uint8

const (
	Info Severity = iota
	Warn
	Error
)

func (s Severity) String() string {
	switch s {
	case Warn:
		return "warn"
	case Error:
		return "error"
	default:
		return "info"
	}
}

// EventType enumerates the noteworthy occurrences the engine emits
type EventType string

const (
	EvDecodeError     EventType = "decode_error"
	EvCRCFailure      EventType = "crc_failure"
	EvSuspectFrame    EventType = "suspect_frame"
	EvFrameGap        EventType = "frame_gap"
	EvPacketGap       EventType = "packet_gap"
	EvPacketDuplicate EventType = "packet_duplicate"
	EvPacketReorder   EventType = "packet_reorder"
	EvTruncated       EventType = "truncated_packet"
	EvMalformed       EventType = "malformed_packet"
	EvNewVC           EventType = "new_vc"
	EvNewAPID         EventType = "new_apid"

	EvCFDPStarted    EventType = "cfdp_txn_started"
	EvCFDPEOF        EventType = "cfdp_eof"
	EvCFDPGap        EventType = "cfdp_gap"
	EvCFDPComplete   EventType = "cfdp_txn_complete"
	EvCFDPIncomplete EventType = "cfdp_txn_incomplete"
	EvCFDPNAK        EventType = "cfdp_nak"
)

// severityOf maps an event type to its severity
func severityOf(t EventType) Severity {
	switch t {
	case EvDecodeError:
		return Error
	case EvCRCFailure, EvSuspectFrame, EvFrameGap, EvPacketGap, EvPacketDuplicate, EvPacketReorder, EvTruncated, EvMalformed,
		EvCFDPGap, EvCFDPIncomplete, EvCFDPNAK:
		return Warn
	default:
		return Info
	}
}

// Event is a single analysis occurrence
// Seq is a monotonic index from the bus, giving a deterministic order independent
// of wall-clock time so reports are reproducible
type Event struct {
	Seq      uint64
	Type     EventType
	Severity Severity
	SCID     ccsdsdefs.SCID
	VCID     ccsdsdefs.VCID
	APID     ccsdsdefs.APID
	Time     time.Time // packet time when the event was seen, zero if unknown
	Message  string
}

// EventBus collects events into a bounded ring and counts them by type; concurrency-safe
type EventBus struct {
	mu       sync.Mutex
	capacity int
	ring     []Event
	start    int // index of the oldest element when the ring is full
	full     bool
	seq      uint64
	counts   map[EventType]uint64
}

// NewEventBus returns a bus retaining up to capacity most-recent events
func NewEventBus(capacity int) *EventBus {
	if capacity < 1 {
		capacity = 256
	}
	return &EventBus{
		capacity: capacity,
		ring:     make([]Event, 0, capacity),
		counts:   make(map[EventType]uint64),
	}
}

// Publish records an event, assigning its Seq and Severity
func (b *EventBus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e.Seq = b.seq
	b.seq++
	e.Severity = severityOf(e.Type)
	b.counts[e.Type]++
	if len(b.ring) < b.capacity {
		b.ring = append(b.ring, e)
	} else {
		b.ring[b.start] = e
		b.start = (b.start + 1) % b.capacity
		b.full = true
	}
}

// CountsByType returns a copy of the per-type event counts
func (b *EventBus) CountsByType() map[EventType]uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[EventType]uint64, len(b.counts))
	maps.Copy(out, b.counts)
	return out
}

// Recent returns the retained events in chronological (Seq) order
func (b *EventBus) Recent() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, 0, len(b.ring))
	if b.full {
		out = append(out, b.ring[b.start:]...)
		out = append(out, b.ring[:b.start]...)
	} else {
		out = append(out, b.ring...)
	}
	return out
}

// subject renders a human-readable subject for an event's identifiers
func subject(scid ccsdsdefs.SCID, vcid ccsdsdefs.VCID, apid ccsdsdefs.APID, withAPID bool) string {
	if withAPID {
		return fmt.Sprintf("APID 0x%03X", uint16(apid))
	}
	return fmt.Sprintf("VC %d/%d", uint16(scid), uint8(vcid))
}
