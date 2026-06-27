package tui

import (
	"fmt"
	"strings"

	"github.com/arbhalerao/cadutrace/internal/analysis/cfdptrack"
)

const cfdpDetailRows = 6

var cfdpCols = []int{-8, -6, -10, -5, -9, -9, -7, -7}

// cfdpRow renders transaction i as a plain table row (also the filter haystack)
func (m Model) cfdpRow(i int) string {
	c := m.store.CFDP()[i]
	done := "no"
	if c.Complete {
		done = "yes"
	}
	return row([]string{
		fmt.Sprintf("%d", c.Source),
		fmt.Sprintf("%d", c.TSN),
		c.State,
		done,
		fmt.Sprintf("%d", c.FileSize),
		fmt.Sprintf("%d", c.BytesReceived),
		fmt.Sprintf("%d", c.DataPDUs),
		fmt.Sprintf("%d", len(c.MissingRanges)),
	}, cfdpCols)
}

func (m Model) cfdpFlags(i int) []string {
	if m.store.CFDP()[i].Complete {
		return []string{"complete"}
	}
	return []string{"incomplete"}
}

func (m Model) viewCFDP() string {
	header := row([]string{"SOURCE", "TXN", "STATE", "DONE", "SIZE", "RECVD", "PDUS", "MISSING"}, cfdpCols)
	txns := m.store.CFDP()
	table := m.cfdp.render(header, func(r int) string { return m.cfdpRow(m.storeRow(r)) })

	detail := ""
	if m.cfdp.total > 0 && len(txns) > 0 {
		detail = m.cfdpDetail(txns[m.storeRow(m.cfdp.cursor)])
	}
	return table + "\n" + detail
}

func (m Model) cfdpDetail(c cfdptrack.TransactionStat) string {
	barWidth := min(max(m.width-12, 10), 80)
	var b strings.Builder
	fmt.Fprintf(&b, "txn %d:%d  state=%s  received=%d/%d  retransmit=%d  out-of-order=%d\n",
		c.Source, c.TSN, c.State, c.BytesReceived, c.FileSize, c.RetransmitBytes, c.OutOfOrder)
	b.WriteString("coverage " + coverageBar(c, barWidth) + "\n")
	if len(c.MissingRanges) == 0 {
		if c.Complete {
			b.WriteString(okStyle.Render("complete - no missing ranges"))
		} else {
			b.WriteString(dimStyle.Render("awaiting EOF"))
		}
	} else {
		parts := make([]string, 0, len(c.MissingRanges))
		for _, r := range c.MissingRanges {
			parts = append(parts, fmt.Sprintf("[%d,%d)", r.Start, r.End))
		}
		b.WriteString(warnStyle.Render("missing: " + strings.Join(parts, " ")))
	}
	return b.String()
}

// coverageBar renders a fixed-width bar where covered cells are filled and
// missing cells are marked, computed from the file size and missing ranges
func coverageBar(c cfdptrack.TransactionStat, width int) string {
	if c.FileSize == 0 || width <= 0 {
		return dimStyle.Render(strings.Repeat("·", max(width, 0)))
	}
	cells := make([]byte, width)
	for i := range cells {
		cells[i] = '#'
	}
	for _, r := range c.MissingRanges {
		lo := int(r.Start * uint64(width) / c.FileSize)
		hi := int((r.End*uint64(width) + c.FileSize - 1) / c.FileSize) // round up
		for i := lo; i < hi && i < width; i++ {
			cells[i] = '.'
		}
	}
	var b strings.Builder
	b.WriteByte('[')
	for _, ch := range cells {
		if ch == '#' {
			b.WriteString(okStyle.Render("#"))
		} else {
			b.WriteString(warnStyle.Render("."))
		}
	}
	b.WriteByte(']')
	return b.String()
}
