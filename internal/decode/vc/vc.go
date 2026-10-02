package vc

import (
	"github.com/arbhalerao/cadutrace/internal/decode"
	"github.com/arbhalerao/cadutrace/internal/decode/reassembly"
	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

type key struct {
	scid ccsdsdefs.SCID
	vcid ccsdsdefs.VCID
}

// Manager owns the set of virtual channels and the shared reassembler
type Manager struct {
	reasm *reassembly.Reassembler
	index map[key]*model.VirtualChannel
	order []*model.VirtualChannel // stable insertion order for deterministic reporting
}

// New returns a Manager; maxPacketLen bounds a single reassembled packet
func New(maxPacketLen int) *Manager {
	return &Manager{
		reasm: reassembly.New(maxPacketLen),
		index: make(map[key]*model.VirtualChannel),
	}
}

func (m *Manager) channel(f decode.TransferFrame) *model.VirtualChannel {
	k := key{scid: f.MasterChannel().SCID, vcid: f.VirtualChannel()}
	vc, ok := m.index[k]
	if !ok {
		vc = &model.VirtualChannel{SCID: k.scid, VCID: k.vcid, TFVN: f.TFVN()}
		m.index[k] = vc
		m.order = append(m.order, vc)
	}
	return vc
}

// Route ingests one frame and returns its virtual channel and any packets it
// completed
// The returned slice is owned by the reassembler and valid only until the next
// call to Route or Flush
func (m *Manager) Route(f decode.TransferFrame) (*model.VirtualChannel, []*model.SpacePacket, error) {
	vc := m.channel(f)
	vc.FrameCount++

	cnt, mod := f.VCCount(), f.VCCountModulus()
	lost := false
	if vc.HasLast {
		expected := (vc.LastVCFrameCount + 1) % mod
		missing := int64(cnt) - int64(expected)
		missing = (missing%int64(mod) + int64(mod)) % int64(mod)
		if missing != 0 {
			lost = true
			vc.FrameGaps++
			vc.FramesLost += uint64(missing)
		}
	}
	vc.LastVCFrameCount = cnt
	vc.HasLast = true

	fhp, hasFHP := f.FirstHeaderPointer()
	if hasFHP && fhp == ccsdsdefs.FHPIdleOnly {
		vc.IdleFrames++
	}

	data := f.Data()
	vc.DataBytes += uint64(len(data))
	pkts := m.reasm.Push(vc, data, fhp, hasFHP, lost)
	vc.PacketsExtracted += uint64(len(pkts))
	return vc, pkts, nil
}

// Flush emits any open packets across all virtual channels at end of stream,
// copied into a fresh slice so they stay valid after return
func (m *Manager) Flush() []*model.SpacePacket {
	var out []*model.SpacePacket
	for _, vc := range m.order {
		for _, sp := range m.reasm.Flush(vc) {
			cp := *sp
			out = append(out, &cp)
		}
	}
	return out
}

// VirtualChannels returns the channels in first-seen order
func (m *Manager) VirtualChannels() []*model.VirtualChannel { return m.order }
