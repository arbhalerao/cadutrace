package tui

import "fmt"

var frameCols = []int{-10, -5, -6, -5, -9, -6, -6}

// frameRow renders frame i as a plain table row (also used as the filter haystack)
func (m Model) frameRow(i int) string {
	f := m.store.Frame(i)
	fhp := "-"
	if f.HasFHP {
		fhp = fmt.Sprintf("0x%03X", f.FHP)
	}
	return row([]string{
		fmt.Sprintf("%d", f.Offset),
		f.TFVN,
		fmt.Sprintf("%d", f.SCID),
		fmt.Sprintf("%d", f.VCID),
		fmt.Sprintf("%d", f.VCFrameCount),
		fhp,
		fmt.Sprintf("%d", f.DataLen),
	}, frameCols)
}

func (Model) frameFlags(int) []string { return nil }

func (m Model) viewFrames() string {
	header := row([]string{"OFFSET", "TYPE", "SCID", "VCID", "VCFC", "FHP", "DLEN"}, frameCols)
	return m.frames.render(header, func(r int) string { return m.frameRow(m.storeRow(r)) })
}
