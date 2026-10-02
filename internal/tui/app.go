package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/arbhalerao/cadutrace/internal/store"
)

type viewID int

const (
	viewFrames viewID = iota
	viewPackets
	viewInspector
	viewCFDP
	viewStats
	viewEvents
	viewTimeline
	numViews
)

var viewNames = [numViews]string{"Frames", "Packets", "Inspector", "CFDP", "Stats", "Events", "Timeline"}

// Model is the root Bubble Tea model
type Model struct {
	store         *store.Store
	width, height int
	contentH      int
	active        viewID

	frames  vtable
	packets vtable
	cfdp    vtable
	events  vtable

	inspector inspectorView
	stats     statsView
	timeline  timelineView

	filter  filterState
	matches []int // active view's filtered store indices; nil = no filter
}

func New(s *store.Store) Model {
	m := Model{store: s, active: viewFrames}
	m.frames.setTotal(s.FrameCount())
	m.packets.setTotal(s.PacketCount())
	m.cfdp.setTotal(len(s.CFDP()))
	m.events.setTotal(len(s.Events()))
	m.inspector.packetIndex = -1
	m.timeline.build(s)
	return m
}

func (m Model) Init() tea.Cmd { return nil }

func (m *Model) layout() {
	// Rows: tab bar (1) + body + status bar (1)
	m.contentH = max(m.height-2, 1)
	tableH := max(m.contentH-1, 1) // minus the column header
	m.frames.setHeight(tableH)
	m.packets.setHeight(tableH)
	m.cfdp.setHeight(max(tableH-cfdpDetailRows, 1)) // reserve rows for the detail panel
	m.events.setHeight(tableH)
	m.stats.height = m.contentH
	m.inspector.height = m.contentH
	m.timeline.width, m.timeline.height = m.width, m.contentH
	m.timeline.cursor = min(m.timeline.cursor, m.timeline.cols()-1)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case dissectMsg:
		m.inspector.setResult(msg.index, msg.result)
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.filter.editing {
		return m.handleFilterKey(k), nil
	}

	switch k.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "/":
		if m.activeTable() != nil {
			m.filter.editing = true
			m.filter.input = m.filter.query
		}
		return m, nil
	case "esc":
		if m.filter.active() {
			m.filter.query = ""
			m.refilter()
		}
		return m, nil
	case "tab":
		m.active = (m.active + 1) % numViews
		m.refilter()
		return m, nil
	case "shift+tab":
		m.active = (m.active + numViews - 1) % numViews
		m.refilter()
		return m, nil
	case "1", "2", "3", "4", "5", "6", "7":
		if v := viewID(k.String()[0] - '1'); v < numViews {
			m.active = v
			m.refilter()
		}
		return m, nil
	}

	switch m.active {
	case viewFrames:
		m.frames.handleKey(k.String())
	case viewPackets:
		if k.String() == "enter" && m.packets.total > 0 {
			idx := m.storeRow(m.packets.cursor)
			m.inspector.open(idx)
			m.active = viewInspector
			return m, dissectCmd(m.store, idx)
		}
		m.packets.handleKey(k.String())
	case viewInspector:
		m.inspector.handleKey(k.String())
	case viewCFDP:
		m.cfdp.handleKey(k.String())
	case viewStats:
		m.stats.handleKey(k.String())
	case viewEvents:
		m.events.handleKey(k.String())
	case viewTimeline:
		switch k.String() {
		case "enter":
			m.jumpTo(viewEvents, m.jumpEvents())
		case "f":
			m.jumpTo(viewFrames, m.jumpFrames())
		default:
			m.timeline.handleKey(k.String())
		}
	}
	return m, nil
}

// jumpTo shows view v with its cursor on store row i, clearing any filter
func (m *Model) jumpTo(v viewID, i int) {
	m.active = v
	m.filter.query = ""
	m.refilter()
	if t := m.activeTable(); t != nil {
		t.cursor = i
		t.clamp()
	}
}

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "loading…"
	}
	var body string
	switch m.active {
	case viewFrames:
		body = m.viewFrames()
	case viewPackets:
		body = m.viewPackets()
	case viewInspector:
		body = m.viewInspector()
	case viewCFDP:
		body = m.viewCFDP()
	case viewStats:
		body = m.viewStats()
	case viewEvents:
		body = m.viewEvents()
	case viewTimeline:
		body = m.viewTimeline()
	}
	return m.renderTabs() + "\n" + body + "\n" + m.renderStatus()
}

func (m Model) renderTabs() string {
	out := ""
	for i, name := range viewNames {
		label := itoa(i+1) + ":" + name
		if viewID(i) == m.active {
			out += tabActive.Render(label)
		} else {
			out += tabInactive.Render(label)
		}
	}
	return out
}

func (m Model) renderStatus() string {
	if m.filter.editing {
		return statusStyle.Render("filter /") + m.filter.input +
			dimStyle.Render("▌  [enter] apply  [esc] cancel")
	}
	var info string
	switch m.active {
	case viewFrames:
		info = "frame " + m.frames.scrollInfo()
	case viewPackets:
		info = "packet " + m.packets.scrollInfo() + "  [enter] inspect"
	case viewCFDP:
		info = "txn " + m.cfdp.scrollInfo()
	case viewEvents:
		info = "event " + m.events.scrollInfo()
	case viewTimeline:
		info = "[←→] move  [+/-] zoom  [enter] events here  [f] frames here"
	}
	if m.filter.active() {
		info = warnStyle.Render("filter:"+m.filter.query) + "  " + info
	}
	left := statusStyle.Render(m.store.Source + "  ")
	help := dimStyle.Render("  [/] filter  [tab] switch  [q] quit")
	return left + info + help
}

func Run(s *store.Store) error {
	p := tea.NewProgram(New(s), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
