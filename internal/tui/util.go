package tui

import (
	"strconv"
	"strings"
)

func itoa(v int) string { return strconv.Itoa(v) }

// padRight left-justifies s in a field of width w (truncating if longer)
func padRight(s string, w int) string {
	if len(s) > w {
		if w <= 1 {
			return s[:w]
		}
		return s[:w-1] + "…"
	}
	return s + strings.Repeat(" ", w-len(s))
}

// padLeft right-justifies s in a field of width w
func padLeft(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return strings.Repeat(" ", w-len(s)) + s
}

// row joins cells with single-space separators using the given widths; negative
// width left-justifies, positive right-justifies
func row(cells []string, widths []int) string {
	parts := make([]string, len(cells))
	for i, c := range cells {
		w := widths[i]
		if w < 0 {
			parts[i] = padRight(c, -w)
		} else {
			parts[i] = padLeft(c, w)
		}
	}
	return strings.Join(parts, " ")
}
