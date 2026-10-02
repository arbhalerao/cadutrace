package tui

import (
	"fmt"
	"strings"
)

// statsView is a scrollable text panel projecting the analysis snapshot
type statsView struct {
	scroll int
	height int
}

func (s *statsView) handleKey(key string) {
	switch key {
	case "up", "k":
		s.scroll--
	case "down", "j":
		s.scroll++
	case "pgup":
		s.scroll -= s.height
	case "pgdown", " ":
		s.scroll += s.height
	case "home", "g":
		s.scroll = 0
	}
	if s.scroll < 0 {
		s.scroll = 0
	}
}

func (m Model) viewStats() string {
	st := m.store.Stats()
	var lines []string
	add := func(format string, a ...any) { lines = append(lines, fmt.Sprintf(format, a...)) }

	q := st.Quality
	add("%s", titleStyle.Render("Quality"))
	add("  frames read %d  used %d  crc-failed %d  invalid-header %d  suspect %d",
		q.FramesRead, q.FramesUsed, q.CRCFailures, q.DecodeErrors, q.SuspectFrames)
	for _, c := range q.Suspect {
		add("  suspect channel %s SCID %d VC %d: %d frame(s) dropped", c.TFVN, c.SCID, c.VCID, c.Frames)
	}
	for _, w := range q.Warnings {
		add("  WARNING: %s", w)
	}
	for _, n := range m.store.Notes {
		add("  detected %s", n)
	}

	if ts := st.Time; ts.Code != "" && !ts.Start.IsZero() {
		add("%s", titleStyle.Render("Time"))
		add("  code %s  epoch %s  start %s  end %s  (%.0fs)", ts.Code, ts.Epoch, ts.Stamp(ts.Start), ts.Stamp(ts.End), ts.DurationSeconds)
	}

	add("%s", titleStyle.Render("Frames"))
	add("  total %d  tm %d  aos %d  idle %d  decode-errors %d  bytes %d",
		st.Frames.Total, st.Frames.TM, st.Frames.AOS, st.Frames.Idle, st.Frames.DecodeErrors, st.Frames.Bytes)
	add("%s", titleStyle.Render("Packets"))
	add("  total %d  idle %d  truncated %d  malformed %d",
		st.Packets.Total, st.Packets.Idle, st.Packets.Truncated, st.Packets.Malformed)
	add("  seq-gaps %d  missing %d  duplicates %d  reorders %d",
		st.Packets.SequenceGaps, st.Packets.MissingPackets, st.Packets.Duplicates, st.Packets.Reorders)

	add("%s", titleStyle.Render("Virtual channels"))
	add("  " + headerStyle.Render(row([]string{"SCID", "VCID", "TYPE", "FRAMES", "GAPS", "LOST", "PKTS", "BYTES"},
		[]int{-5, -5, -5, -8, -6, -6, -7, -10})))
	for _, v := range st.VCs {
		add("  " + row([]string{
			fmt.Sprintf("%d", v.SCID), fmt.Sprintf("%d", v.VCID), v.TFVN,
			fmt.Sprintf("%d", v.Frames), fmt.Sprintf("%d", v.FrameGaps), fmt.Sprintf("%d", v.FramesLost),
			fmt.Sprintf("%d", v.Packets), fmt.Sprintf("%d", v.DataBytes),
		}, []int{-5, -5, -5, -8, -6, -6, -7, -10}))
	}

	add("%s", titleStyle.Render("APIDs"))
	add("  " + headerStyle.Render(row([]string{"APID", "VCS", "COUNT", "BYTES", "MIN", "MAX", "MEAN", "GAPS", "DUP", "REORD"},
		[]int{-7, -6, -8, -9, -5, -5, -7, -5, -5, -5})))
	for _, a := range st.APIDs {
		label := fmt.Sprintf("0x%03X", uint16(a.APID))
		vcs := make([]string, len(a.VCIDs))
		for i, v := range a.VCIDs {
			vcs[i] = fmt.Sprintf("%d", v)
		}
		add("  " + row([]string{
			label, strings.Join(vcs, ","), fmt.Sprintf("%d", a.Count), fmt.Sprintf("%d", a.Bytes),
			fmt.Sprintf("%d", a.MinLength), fmt.Sprintf("%d", a.MaxLength), fmt.Sprintf("%.1f", a.MeanLength),
			fmt.Sprintf("%d", a.SequenceGaps), fmt.Sprintf("%d", a.Duplicates), fmt.Sprintf("%d", a.Reorders),
		}, []int{-7, -6, -8, -9, -5, -5, -7, -5, -5, -5}))
	}

	if len(st.Encapsulation) > 0 {
		add("%s", titleStyle.Render("Encapsulation packets (CCSDS 133.1)"))
		add("  total %d  bytes %d", st.Packets.Encap, st.Packets.EncapBytes)
		add("  " + headerStyle.Render(row([]string{"PID", "PROTOCOL", "COUNT", "BYTES"},
			[]int{-4, -10, -8, -10})))
		for _, en := range st.Encapsulation {
			add("  " + row([]string{
				fmt.Sprintf("%d", en.ProtocolID), en.Protocol,
				fmt.Sprintf("%d", en.Count), fmt.Sprintf("%d", en.Bytes),
			}, []int{-4, -10, -8, -10}))
		}
	}

	if len(st.CLCW) > 0 {
		add("%s", titleStyle.Render("CLCW (uplink status)"))
		add("  " + headerStyle.Render(row([]string{"SCID", "VCID", "FRAMES", "LOCKOUT", "WAIT", "RETX", "REPORT"},
			[]int{-5, -5, -7, -8, -5, -5, -7})))
		for _, c := range st.CLCW {
			yn := func(b bool) string {
				if b {
					return "yes"
				}
				return "no"
			}
			add("  " + row([]string{
				fmt.Sprintf("%d", c.SCID), fmt.Sprintf("%d", c.VCID), fmt.Sprintf("%d", c.Frames),
				yn(c.Lockout), yn(c.Wait), yn(c.Retransmit), fmt.Sprintf("%d", c.ReportValue),
			}, []int{-5, -5, -7, -8, -5, -5, -7}))
		}
	}

	// Window the lines to the visible height
	if m.stats.scroll > max(len(lines)-m.stats.height, 0) {
		m.stats.scroll = max(len(lines)-m.stats.height, 0)
	}
	end := min(m.stats.scroll+m.stats.height, len(lines))
	return strings.Join(lines[m.stats.scroll:end], "\n")
}
