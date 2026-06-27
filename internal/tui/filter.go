package tui

import (
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// filterState holds the committed filter and any in-progress edit
// One filter applies to whichever table view is active
type filterState struct {
	editing bool   // user is typing a filter
	input   string // edit buffer
	query   string // committed query ("" = no filter)
}

func (f filterState) active() bool { return f.query != "" }

// filterIndices returns the store indices whose row matches q, or nil when q is
// empty (meaning "no filter")
// text(i) is the row's plain searchable text; flags(i) are lowercased flag words
// attached to the row
// Space-separated terms are AND-ed; a term matches if it equals a flag or is a
// substring of the text
//
// This is an O(n) scan run on filter commit (not per keystroke), so it is cheap
// in practice; a very large capture pays a one-time pass when the filter changes
func filterIndices(n int, q string, text func(int) string, flags func(int) []string) []int {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	terms := strings.Fields(q)
	out := []int{}
	for i := range n {
		if matchRow(terms, strings.ToLower(text(i)), flags(i)) {
			out = append(out, i)
		}
	}
	return out
}

func matchRow(terms []string, text string, flags []string) bool {
	for _, t := range terms {
		if slices.Contains(flags, t) || strings.Contains(text, t) {
			continue
		}
		return false
	}
	return true
}

// activeTable returns the active view's table, or nil for non-table views
func (m *Model) activeTable() *vtable {
	switch m.active {
	case viewFrames:
		return &m.frames
	case viewPackets:
		return &m.packets
	case viewCFDP:
		return &m.cfdp
	case viewEvents:
		return &m.events
	default:
		return nil
	}
}

func (m Model) activeFullCount() int {
	switch m.active {
	case viewFrames:
		return m.store.FrameCount()
	case viewPackets:
		return m.store.PacketCount()
	case viewCFDP:
		return len(m.store.CFDP())
	case viewEvents:
		return len(m.store.Events())
	default:
		return 0
	}
}

// storeRow maps a visible table row to the underlying store index, accounting
// for any active filter
func (m Model) storeRow(row int) int {
	if m.matches != nil && row >= 0 && row < len(m.matches) {
		return m.matches[row]
	}
	return row
}

// refilter recomputes the active view's match set for the current query and
// resizes its table
// It is a no-op for non-table views
func (m *Model) refilter() {
	t := m.activeTable()
	if t == nil {
		m.matches = nil
		return
	}
	q := m.filter.query
	switch m.active {
	case viewFrames:
		m.matches = filterIndices(m.store.FrameCount(), q, m.frameRow, m.frameFlags)
	case viewPackets:
		m.matches = filterIndices(m.store.PacketCount(), q, m.packetRow, m.packetFlags)
	case viewCFDP:
		m.matches = filterIndices(len(m.store.CFDP()), q, m.cfdpRow, m.cfdpFlags)
	case viewEvents:
		m.matches = filterIndices(len(m.store.Events()), q, m.eventPlain, m.eventFlags)
	}
	if m.matches != nil {
		t.setTotal(len(m.matches))
	} else {
		t.setTotal(m.activeFullCount())
	}
}

// handleFilterKey edits the filter buffer while the user is typing
func (m Model) handleFilterKey(k tea.KeyMsg) Model {
	switch k.Type {
	case tea.KeyEnter:
		m.filter.query = strings.TrimSpace(m.filter.input)
		m.filter.editing = false
		m.refilter()
	case tea.KeyEsc:
		m.filter.editing = false
		m.filter.input = m.filter.query
	case tea.KeyBackspace, tea.KeyDelete:
		if n := len(m.filter.input); n > 0 {
			m.filter.input = m.filter.input[:n-1]
		}
	case tea.KeySpace:
		m.filter.input += " "
	case tea.KeyRunes:
		m.filter.input += string(k.Runes)
	}
	return m
}
