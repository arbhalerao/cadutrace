package model

import "github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"

// VirtualChannel is the per-(SCID,VCID) state that persists across frames:
// counters, gap accounting, and the in-progress reassembly state
type VirtualChannel struct {
	SCID ccsdsdefs.SCID
	VCID ccsdsdefs.VCID
	TFVN ccsdsdefs.TFVN

	FrameCount       uint64
	IdleFrames       uint64
	PacketsExtracted uint64
	DataBytes        uint64

	LastVCFrameCount uint32
	HasLast          bool
	FrameGaps        uint64 // discontinuities observed
	FramesLost       uint64 // inferred missing frames

	Reasm ReassemblyState
}

// ReassemblyState tracks one in-progress packet on a virtual channel
// Buf is the active accumulation slice; BufPtr is its pooled backing array
type ReassemblyState struct {
	Open     bool
	Kind     PacketKind
	Expected int // total length; 0 = header incomplete, <0 = malformed
	Buf      []byte
	BufPtr   *[]byte
}
