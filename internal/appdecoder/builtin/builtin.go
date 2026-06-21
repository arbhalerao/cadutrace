package builtin

import (
	"fmt"

	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/plugin"
)

// Raw claims any packet and renders a minimal summary; it is the registry's fallback
type Raw struct{}

func (Raw) Name() string                      { return "raw" }
func (Raw) CanDecode(*model.SpacePacket) bool { return true }

func (Raw) Decode(_ plugin.DecodeContext, p *model.SpacePacket) (*plugin.Result, error) {
	proto, summary := "raw", fmt.Sprintf("APID 0x%03X, %d octets", uint16(p.APID), p.TotalLen())
	if p.IsIdle() {
		proto = "idle"
		summary = fmt.Sprintf("idle packet, %d octets", p.TotalLen())
	}
	res := &plugin.Result{Protocol: proto, Summary: summary}
	res.AddField("apid", fmt.Sprintf("0x%03X", uint16(p.APID)), 0, 2)
	res.AddField("length", fmt.Sprintf("%d", p.TotalLen()), 0, p.TotalLen())
	return res, nil
}
