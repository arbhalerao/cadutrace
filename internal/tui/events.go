package tui

import "github.com/arbhalerao/cadutrace/internal/analysis"

var eventCols = []int{-23, -6, -20, -50}

// eventPlain renders event i as a plain table row (the filter haystack: it
// already contains the severity, type, and message)
func (m Model) eventPlain(i int) string {
	e := m.store.Events()[i]
	return row([]string{m.store.Stats().Time.Stamp(e.Time), e.Severity.String(), string(e.Type), e.Message}, eventCols)
}

// eventStyled renders event i with severity colouring
func (m Model) eventStyled(i int) string {
	line := m.eventPlain(i)
	switch m.store.Events()[i].Severity {
	case analysis.Error:
		return errStyle.Render(line)
	case analysis.Warn:
		return warnStyle.Render(line)
	default:
		return line
	}
}

func (Model) eventFlags(int) []string { return nil }

func (m Model) viewEvents() string {
	header := row([]string{"TIME", "SEV", "TYPE", "MESSAGE"}, eventCols)
	return m.events.render(header, func(r int) string { return m.eventStyled(m.storeRow(r)) })
}
