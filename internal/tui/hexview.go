package tui

import (
	"fmt"
	"strings"
)

const hexCols = 16

// hexRows returns the number of 16-byte rows a buffer occupies
func hexRows(n int) int { return (n + hexCols - 1) / hexCols }

// renderHex renders a classic hex dump of raw, highlighting bytes in the range
// [hlStart, hlEnd) (the selected field's byte range)
// It draws rows [topRow, topRow+maxRows) so the inspector can scroll to keep the
// highlighted field visible
func renderHex(raw []byte, hlStart, hlEnd, topRow, maxRows int) string {
	var b strings.Builder
	total := hexRows(len(raw))
	end := min(topRow+maxRows, total)
	for r := topRow; r < end; r++ {
		base := r * hexCols
		fmt.Fprintf(&b, "%06X  ", base)

		var ascii strings.Builder
		for c := range hexCols {
			i := base + c
			if i >= len(raw) {
				b.WriteString("   ")
				continue
			}
			cell := fmt.Sprintf("%02X ", raw[i])
			ch := "."
			if raw[i] >= 0x20 && raw[i] < 0x7F {
				ch = string(raw[i])
			}
			if i >= hlStart && i < hlEnd {
				b.WriteString(hlStyle.Render(strings.TrimRight(cell, " ")))
				b.WriteByte(' ')
				ascii.WriteString(hlStyle.Render(ch))
			} else {
				b.WriteString(cell)
				ascii.WriteString(ch)
			}
			if c == hexCols/2-1 {
				b.WriteByte(' ')
			}
		}
		b.WriteString(" |")
		b.WriteString(ascii.String())
		b.WriteByte('|')
		if r < end-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
