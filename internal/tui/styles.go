package tui

import "github.com/charmbracelet/lipgloss"

// Styles for the TUI
// Colours degrade gracefully on limited terminals; the ASCII profile is forced so
// View() output is escape-free and snapshot-stable
var (
	tabActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("6")).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Padding(0, 1)
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	selectStyle = lipgloss.NewStyle().Reverse(true)
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	titleStyle  = lipgloss.NewStyle().Bold(true)
	hlStyle     = lipgloss.NewStyle().Reverse(true) // hex field highlight
)
