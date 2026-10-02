package analysis

import (
	"fmt"
	"time"

	"github.com/arbhalerao/cadutrace/internal/analysis/cfdptrack"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// Statistics is a deterministic snapshot of the engine's state (the JSON report)
// Content-derived numbers only; the wall-clock rate is printed separately by the CLI
type Statistics struct {
	Quality Quality      `json:"quality"`
	Time    TimeStats    `json:"time"`
	Frames  FrameStats   `json:"frames"`
	Packets PacketStats  `json:"packets"`
	APIDs   []APIDStats  `json:"apids"`
	VCs     []VCStats    `json:"virtual_channels"`
	Events  []EventCount `json:"events"`

	Encapsulation []EncapStats                `json:"encapsulation,omitempty"`
	CLCW          []CLCWStat                  `json:"clcw,omitempty"`
	CFDP          []cfdptrack.TransactionStat `json:"cfdp,omitempty"`

	Gaps   []Gap   `json:"gaps,omitempty"`
	Bursts []Burst `json:"bursts,omitempty"`
}

// TimeStats describes the packet time found in the capture
// Relative means no epoch was known, so times only order and space events
type TimeStats struct {
	Code            string    `json:"code,omitempty"`
	Epoch           string    `json:"epoch,omitempty"`
	Relative        bool      `json:"relative,omitempty"`
	Start           time.Time `json:"start,omitzero"`
	End             time.Time `json:"end,omitzero"`
	DurationSeconds float64   `json:"duration_seconds"`
	Packets         uint64    `json:"packets"`
	Rejected        uint64    `json:"rejected"`
}

// Stamp renders t for reports: a date, or seconds from the start when relative
func (ts TimeStats) Stamp(t time.Time) string {
	switch {
	case t.IsZero():
		return "-"
	case ts.Relative:
		return fmt.Sprintf("+%.3fs", t.Sub(ts.Start).Seconds())
	default:
		return t.UTC().Format("2006-01-02 15:04:05.000")
	}
}

// Gap is one loss: frames missing on a VC, or packets missing from an APID
// Onboard marks packets missing although their VC lost no frames in between,
// i.e. lost before the downlink. Start and End bound the loss in packet time
type Gap struct {
	Kind    string         `json:"kind"`
	SCID    ccsdsdefs.SCID `json:"scid"`
	VCID    ccsdsdefs.VCID `json:"vcid"`
	APID    ccsdsdefs.APID `json:"apid"`
	Missing uint64         `json:"missing"`
	Onboard bool           `json:"onboard,omitempty"`
	Start   time.Time      `json:"start,omitzero"`
	End     time.Time      `json:"end,omitzero"`
	Offset  int64          `json:"offset"`
}

// Burst is a span of time over which frames were lost, merged across VCs
type Burst struct {
	Start           time.Time  `json:"start"`
	End             time.Time  `json:"end"`
	DurationSeconds float64    `json:"duration_seconds"`
	Frames          []VCLoss   `json:"frames"`
	Packets         []APIDLoss `json:"packets,omitempty"`
}

type VCLoss struct {
	SCID   ccsdsdefs.SCID `json:"scid"`
	VCID   ccsdsdefs.VCID `json:"vcid"`
	Frames uint64         `json:"frames"`
}

type APIDLoss struct {
	APID    ccsdsdefs.APID `json:"apid"`
	Missing uint64         `json:"missing"`
}

// Quality summarizes how much of the capture could be trusted
type Quality struct {
	FramesRead    uint64           `json:"frames_read"`
	FramesUsed    uint64           `json:"frames_used"`
	CRCFailures   uint64           `json:"crc_failures"`
	DecodeErrors  uint64           `json:"decode_errors"`
	SuspectFrames uint64           `json:"suspect_frames"`
	Suspect       []SuspectChannel `json:"suspect_channels,omitempty"`
	Warnings      []string         `json:"warnings,omitempty"`
}

// SuspectChannel is a channel whose frames were dropped as likely false decodes
type SuspectChannel struct {
	TFVN   string         `json:"tfvn"`
	SCID   ccsdsdefs.SCID `json:"scid"`
	VCID   ccsdsdefs.VCID `json:"vcid"`
	Frames uint64         `json:"frames"`
}

// EncapStats is per-Protocol-ID statistics for Encapsulation Packets (CCSDS 133.1)
type EncapStats struct {
	ProtocolID uint8  `json:"protocol_id"`
	Protocol   string `json:"protocol"`
	Count      uint64 `json:"count"`
	Bytes      uint64 `json:"bytes"`
}

// CLCWStat summarizes the CLCW on a VC's OCF (the most recent one)
type CLCWStat struct {
	SCID         ccsdsdefs.SCID `json:"scid"`
	VCID         ccsdsdefs.VCID `json:"vcid"`
	Frames       uint64         `json:"frames"`
	ReportedVCID uint8          `json:"reported_vcid"`
	Lockout      bool           `json:"lockout"`
	Wait         bool           `json:"wait"`
	Retransmit   bool           `json:"retransmit"`
	NoRF         bool           `json:"no_rf"`
	NoBitLock    bool           `json:"no_bit_lock"`
	ReportValue  uint8          `json:"report_value"`
}

// FrameStats aggregates the frame layer
type FrameStats struct {
	Total        uint64 `json:"total"`
	TM           uint64 `json:"tm"`
	AOS          uint64 `json:"aos"`
	Idle         uint64 `json:"idle"`
	DecodeErrors uint64 `json:"decode_errors"`
	Bytes        uint64 `json:"bytes"`
}

// PacketStats aggregates the packet layer
type PacketStats struct {
	Total          uint64 `json:"total"`
	Idle           uint64 `json:"idle"`
	Truncated      uint64 `json:"truncated"`
	Malformed      uint64 `json:"malformed"`
	SequenceGaps   uint64 `json:"sequence_gaps"`
	MissingPackets uint64 `json:"missing_packets"`
	Duplicates     uint64 `json:"duplicates"`
	Reorders       uint64 `json:"reorders"`
	Bytes          uint64 `json:"bytes"`
	Encap          uint64 `json:"encap,omitempty"`       // Encapsulation Packets (CCSDS 133.1)
	EncapBytes     uint64 `json:"encap_bytes,omitempty"` // bytes in Encapsulation Packets
}

// APIDStats is per-Application-Process statistics
type APIDStats struct {
	APID           ccsdsdefs.APID   `json:"apid"`
	VCIDs          []ccsdsdefs.VCID `json:"vcids"`
	Idle           bool             `json:"idle"`
	Count          uint64           `json:"count"`
	Bytes          uint64           `json:"bytes"`
	MinLength      int              `json:"min_length"`
	MaxLength      int              `json:"max_length"`
	MeanLength     float64          `json:"mean_length"`
	SequenceGaps   uint64           `json:"sequence_gaps"`
	MissingPackets uint64           `json:"missing_packets"`
	Duplicates     uint64           `json:"duplicates"`
	Reorders       uint64           `json:"reorders"`
	OnboardGaps    uint64           `json:"onboard_gaps"`
	OnboardMissing uint64           `json:"onboard_missing"`
	LastSeqCount   uint16           `json:"last_seq_count"`
}

// VCStats is per-virtual-channel statistics
type VCStats struct {
	SCID       ccsdsdefs.SCID `json:"scid"`
	VCID       ccsdsdefs.VCID `json:"vcid"`
	TFVN       string         `json:"tfvn"`
	Frames     uint64         `json:"frames"`
	FrameGaps  uint64         `json:"frame_gaps"`
	FramesLost uint64         `json:"frames_lost"`
	IdleFrames uint64         `json:"idle_frames"`
	Packets    uint64         `json:"packets"`
	DataBytes  uint64         `json:"data_bytes"`
}

// EventCount summarizes how many events of a given type occurred
type EventCount struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Count    uint64 `json:"count"`
}
