package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/arbhalerao/cadutrace/internal/store"
	"github.com/arbhalerao/cadutrace/pkg/plugin"
)

// dissectMsg carries a lazily-built dissection back to the UI goroutine
type dissectMsg struct {
	index  int
	result *plugin.Result
}

// dissectCmd dissects packet i off the UI goroutine
func dissectCmd(s *store.Store, i int) tea.Cmd {
	return func() tea.Msg { return dissectMsg{index: i, result: s.Dissect(i)} }
}

type flatField struct {
	depth int
	field plugin.Field
}

// inspectorView shows a decoder result tree beside a hex view, with the
// selected field's byte range highlighted in the hex
type inspectorView struct {
	packetIndex int
	result      *plugin.Result
	fields      []flatField
	cursor      int
	hexTop      int
	height      int
}

func (v *inspectorView) open(i int) {
	v.packetIndex = i
	v.result = nil
	v.fields = nil
	v.cursor = 0
	v.hexTop = 0
}

func (v *inspectorView) setResult(i int, res *plugin.Result) {
	if i != v.packetIndex {
		return
	}
	v.result = res
	v.fields = flatten(res)
	v.cursor = 0
	v.hexTop = 0
}

func (v *inspectorView) handleKey(key string) {
	switch key {
	case "up", "k":
		v.cursor = max(v.cursor-1, 0)
	case "down", "j":
		if len(v.fields) > 0 {
			v.cursor = min(v.cursor+1, len(v.fields)-1)
		}
	}
}

// payloadBase returns the offset within the full packet at which a decoder's
// field offsets are measured: application decoders see the payload (after the
// 6-octet primary header); the raw/idle builtins describe the whole packet
func payloadBase(protocol string) int {
	if protocol == "raw" || protocol == "idle" {
		return 0
	}
	return 6
}

// highlightRange returns the byte range in the full packet for the currently
// selected field, or (-1, -1) if the field has no byte range
func (v *inspectorView) highlightRange(base int) (start, end int) {
	if v.cursor < 0 || v.cursor >= len(v.fields) {
		return -1, -1
	}
	f := v.fields[v.cursor].field
	if f.Length <= 0 {
		return -1, -1
	}
	return base + f.Offset, base + f.Offset + f.Length
}

func flatten(r *plugin.Result) []flatField {
	if r == nil {
		return nil
	}
	var out []flatField
	var walk func(res *plugin.Result, depth int)
	walk = func(res *plugin.Result, depth int) {
		for _, f := range res.Fields {
			out = append(out, flatField{depth: depth, field: f})
		}
		for _, c := range res.Children {
			out = append(out, flatField{depth: depth, field: plugin.Field{Name: "[" + c.Protocol + "]", Value: c.Summary}})
			walk(c, depth+1)
		}
	}
	walk(r, 0)
	return out
}

func (m Model) viewInspector() string {
	in := &m.inspector
	if in.packetIndex < 0 {
		return dimStyle.Render("select a packet in the Packets view and press [enter]")
	}
	if in.result == nil {
		return dimStyle.Render(fmt.Sprintf("dissecting packet %d…", in.packetIndex))
	}

	p := m.store.Packet(in.packetIndex)

	// Field tree (left pane)
	base := payloadBase(in.result.Protocol)
	hlStart, hlEnd := in.highlightRange(base)
	var tree strings.Builder
	tree.WriteString(titleStyle.Render(in.result.Protocol+": ") + in.result.Summary + "\n")
	for i, ff := range in.fields {
		indent := strings.Repeat("  ", ff.depth)
		line := fmt.Sprintf("%s%s = %s", indent, ff.field.Name, ff.field.Value)
		if i == in.cursor {
			line = selectStyle.Render(line)
		}
		tree.WriteString(line + "\n")
	}

	// Hex view (right pane), scrolled to keep the highlighted bytes visible
	rows := max(in.height-1, 1)
	if hlStart >= 0 {
		fieldRow := hlStart / hexCols
		if fieldRow < in.hexTop {
			in.hexTop = fieldRow
		} else if fieldRow >= in.hexTop+rows {
			in.hexTop = fieldRow - rows + 1
		}
	}
	hex := renderHex(p.Raw, hlStart, hlEnd, in.hexTop, rows)

	left := lipgloss.NewStyle().Width(max(m.width/2-1, 20)).Render(tree.String())
	return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", hex)
}
