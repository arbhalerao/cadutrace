package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// vtable is a virtualized table: it tracks a cursor and a viewport over a total
// row count and renders only the visible window by calling a row function
// This keeps navigation fast on captures with millions of rows; the model never
// materializes all rows
type vtable struct {
	cursor int
	top    int
	height int // visible data rows (excludes header)
	total  int
}

func (t *vtable) setTotal(n int) {
	t.total = n
	t.clamp()
}

func (t *vtable) setHeight(h int) {
	t.height = max(h, 1)
	t.clamp()
}

func (t *vtable) move(d int) {
	t.cursor += d
	t.clamp()
}

func (t *vtable) clamp() {
	if t.total <= 0 {
		t.cursor, t.top = 0, 0
		return
	}
	t.cursor = min(max(t.cursor, 0), t.total-1)
	if t.cursor < t.top {
		t.top = t.cursor
	}
	if t.height > 0 && t.cursor >= t.top+t.height {
		t.top = t.cursor - t.height + 1
	}
	t.top = min(max(t.top, 0), max(0, t.total-t.height))
}

// handleKey applies a navigation key, returning true if it consumed the key
func (t *vtable) handleKey(key string) bool {
	switch key {
	case "up", "k":
		t.move(-1)
	case "down", "j":
		t.move(1)
	case "pgup", "ctrl+b":
		t.move(-t.height)
	case "pgdown", "ctrl+f", " ":
		t.move(t.height)
	case "home", "g":
		t.cursor = 0
		t.clamp()
	case "end", "G":
		t.cursor = t.total - 1
		t.clamp()
	default:
		return false
	}
	return true
}

// render draws the header plus the visible rows
// rowFn returns a preformatted, fixed-width line for row i; the cursor row is
// reverse-highlighted
func (t *vtable) render(header string, rowFn func(i int) string) string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(header))
	b.WriteByte('\n')
	if t.total == 0 {
		b.WriteString(dimStyle.Render("  (no rows)"))
		return b.String()
	}
	end := min(t.top+t.height, t.total)
	for i := t.top; i < end; i++ {
		line := rowFn(i)
		if i == t.cursor {
			line = selectStyle.Render(line)
		}
		b.WriteString(line)
		if i < end-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// scrollInfo renders a compact "row N/total" indicator
func (t *vtable) scrollInfo() string {
	if t.total == 0 {
		return "0/0"
	}
	return lipgloss.NewStyle().Render(itoa(t.cursor+1) + "/" + itoa(t.total))
}
