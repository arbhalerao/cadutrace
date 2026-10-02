package tui

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/arbhalerao/cadutrace/internal/analysis"
	"github.com/arbhalerao/cadutrace/internal/store"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

const (
	fineBuckets   = 16384
	timelineLabel = 12
	maxCursorStep = 10
)

var levels = []rune("▁▂▃▄▅▆▇█")

type tlKey struct {
	scid ccsdsdefs.SCID
	vcid ccsdsdefs.VCID
}

type tlRow struct {
	label      string
	recv, lost []float64
}

// timelineView lays the capture out along packet time (or byte offset when the
// packets carry no time), binned once into fine buckets that the screen
// aggregates at whatever zoom is shown
type timelineView struct {
	built   bool
	byTime  bool
	span    float64 // seconds or octets covered
	rows    []tlRow
	pktLost []float64
	onboard []float64
	quality []float64

	cursor int
	zoom   int
	center float64
	width  int
	height int
}

func (tv *timelineView) build(s *store.Store) {
	tv.built = true
	st := s.Stats()
	ts := st.Time
	tv.byTime = !ts.Start.IsZero() && ts.End.After(ts.Start)
	if tv.byTime {
		tv.span = ts.End.Sub(ts.Start).Seconds()
	} else {
		tv.span = float64(max(s.Bytes, 1))
	}
	tv.center = tv.span / 2

	idx := map[tlKey]int{}
	for _, v := range st.VCs {
		idx[tlKey{v.SCID, v.VCID}] = len(tv.rows)
		tv.rows = append(tv.rows, tlRow{
			label: fmt.Sprintf("%d/%d %s", v.SCID, v.VCID, v.TFVN),
			recv:  make([]float64, fineBuckets), lost: make([]float64, fineBuckets),
		})
	}
	tv.pktLost = make([]float64, fineBuckets)
	tv.onboard = make([]float64, fineBuckets)
	tv.quality = make([]float64, fineBuckets)

	for i := range s.FrameCount() {
		f := s.Frame(i)
		if r, ok := idx[tlKey{f.SCID, f.VCID}]; ok {
			tv.rows[r].recv[tv.bucket(tv.framePos(s, f.Time, f.Offset))]++
		}
	}
	for _, g := range st.Gaps {
		from, to := tv.gapPos(s, g)
		switch {
		case g.Kind == "frames":
			if r, ok := idx[tlKey{g.SCID, g.VCID}]; ok {
				spread(tv.rows[r].lost, tv.bucket(from), tv.bucket(to), float64(g.Missing))
			}
		case g.Onboard:
			tv.onboard[tv.bucket(to)] += float64(g.Missing)
		default:
			tv.pktLost[tv.bucket(to)] += float64(g.Missing)
		}
	}
	if tv.byTime {
		for _, e := range s.Events() {
			switch e.Type {
			case analysis.EvCRCFailure, analysis.EvSuspectFrame, analysis.EvDecodeError:
				if !e.Time.IsZero() {
					tv.quality[tv.bucket(e.Time.Sub(ts.Start).Seconds())]++
				}
			}
		}
	}
}

func (tv *timelineView) framePos(s *store.Store, t time.Time, offset int64) float64 {
	if !tv.byTime {
		return float64(offset)
	}
	if t.IsZero() {
		return 0
	}
	return t.Sub(s.Stats().Time.Start).Seconds()
}

func (tv *timelineView) gapPos(s *store.Store, g analysis.Gap) (float64, float64) {
	if !tv.byTime || g.Start.IsZero() && g.End.IsZero() {
		x := float64(g.Offset)
		if tv.byTime {
			x = 0
		}
		return x, x
	}
	start := s.Stats().Time.Start
	from, to := g.Start, g.End
	if from.IsZero() {
		from = to
	}
	if to.IsZero() {
		to = from
	}
	return from.Sub(start).Seconds(), to.Sub(start).Seconds()
}

func (tv *timelineView) bucket(x float64) int {
	b := int(x / tv.span * fineBuckets)
	return min(max(b, 0), fineBuckets-1)
}

func spread(dst []float64, from, to int, total float64) {
	n := float64(to - from + 1)
	for b := from; b <= to; b++ {
		dst[b] += total / n
	}
}

func (tv *timelineView) cols() int { return max(tv.width-timelineLabel-1, 10) }

func (tv *timelineView) maxZoom() int {
	return max(int(math.Log2(float64(fineBuckets)/float64(tv.cols()))), 0)
}

// window returns the visible axis range
func (tv *timelineView) window() (float64, float64) {
	w := tv.span / math.Pow(2, float64(tv.zoom))
	c := min(max(tv.center, w/2), tv.span-w/2)
	return c - w/2, c + w/2
}

// column returns the fine-bucket range [from, to) and axis range of screen column c
func (tv *timelineView) column(c int) (int, int, float64, float64) {
	ws, we := tv.window()
	step := (we - ws) / float64(tv.cols())
	x0, x1 := ws+float64(c)*step, ws+float64(c+1)*step
	from, to := tv.bucket(x0), tv.bucket(x1)
	if to <= from {
		to = from + 1
	}
	return from, min(to, fineBuckets), x0, x1
}

func sum(v []float64, from, to int) float64 {
	t := 0.0
	for _, x := range v[from:to] {
		t += x
	}
	return t
}

func (tv *timelineView) handleKey(key string) {
	ws, we := tv.window()
	step := (we - ws) / float64(tv.cols())
	switch key {
	case "left", "h":
		tv.cursor--
	case "right", "l":
		tv.cursor++
	case "shift+left", "H":
		tv.cursor -= maxCursorStep
	case "shift+right", "L":
		tv.cursor += maxCursorStep
	case "home", "g":
		tv.cursor, tv.center = 0, 0
	case "end", "G":
		tv.cursor, tv.center = tv.cols()-1, tv.span
	case "+", "=":
		if tv.zoom < tv.maxZoom() {
			tv.center = ws + (float64(tv.cursor)+0.5)*step
			tv.zoom++
			tv.cursor = tv.cols() / 2
		}
	case "-", "_":
		if tv.zoom > 0 {
			tv.center = ws + (float64(tv.cursor)+0.5)*step
			tv.zoom--
			tv.cursor = tv.cols() / 2
		}
	}
	if tv.cursor < 0 {
		tv.center += float64(tv.cursor) * step
		tv.cursor = 0
	}
	if tv.cursor >= tv.cols() {
		tv.center += float64(tv.cursor-tv.cols()+1) * step
		tv.cursor = tv.cols() - 1
	}
	ws2, we2 := tv.window()
	tv.center = (ws2 + we2) / 2
}

// cursorRange is the axis range under the cursor
func (tv *timelineView) cursorRange() (float64, float64) {
	_, _, x0, x1 := tv.column(tv.cursor)
	return x0, x1
}

func (m Model) stamp(x float64) string {
	if !m.timeline.byTime {
		return fmt.Sprintf("offset %d", int64(x))
	}
	ts := m.store.Stats().Time
	return ts.Stamp(ts.Start.Add(time.Duration(x * float64(time.Second))))
}

func (m Model) viewTimeline() string {
	tv := &m.timeline
	cols := tv.cols()
	var b strings.Builder
	line := func(label string, cells []string) {
		b.WriteString(padRight(label, timelineLabel) + " ")
		for c, cell := range cells {
			if c == tv.cursor {
				cell = selectStyle.Render(cell)
			}
			b.WriteString(cell)
		}
		b.WriteByte('\n')
	}

	ws, we := tv.window()
	left, right := m.stamp(ws), m.stamp(we)
	gap := max(cols-len(left)-len(right), 1)
	b.WriteString(strings.Repeat(" ", timelineLabel+1) + dimStyle.Render(left+strings.Repeat(" ", gap)+right) + "\n")

	for _, r := range tv.rows {
		peak := 0.0
		for c := range cols {
			from, to, _, _ := tv.column(c)
			peak = max(peak, sum(r.recv, from, to))
		}
		cells := make([]string, cols)
		for c := range cols {
			from, to, _, _ := tv.column(c)
			recv, lost := sum(r.recv, from, to), sum(r.lost, from, to)
			glyph := string(levels[0])
			if peak > 0 && recv > 0 {
				glyph = string(levels[min(int(recv/peak*float64(len(levels))), len(levels)-1)])
			}
			switch {
			case recv == 0 && lost < 0.5:
				cells[c] = dimStyle.Render("·")
			case recv == 0:
				cells[c] = errStyle.Render("×")
			case lost >= 0.5:
				cells[c] = warnStyle.Render(glyph)
			default:
				cells[c] = okStyle.Render(glyph)
			}
		}
		line(r.label, cells)
	}

	marks := func(v []float64, mark string, style func(...string) string) []string {
		cells := make([]string, cols)
		for c := range cols {
			from, to, _, _ := tv.column(c)
			if sum(v, from, to) >= 0.5 {
				cells[c] = style(mark)
			} else {
				cells[c] = " "
			}
		}
		return cells
	}
	pk := marks(tv.pktLost, "▼", warnStyle.Render)
	for c, o := range marks(tv.onboard, "!", errStyle.Render) {
		if o != " " {
			pk[c] = o
		}
	}
	line("pkts lost", pk)
	if tv.byTime {
		line("quality", marks(tv.quality, "!", errStyle.Render))
	}
	b.WriteString(dimStyle.Render(strings.Repeat(" ", timelineLabel+1)+
		"█ frames (height = rate)  "+warnStyle.Render("▄")+dimStyle.Render(" some lost  ")+
		errStyle.Render("×")+dimStyle.Render(" none arrived  ")+warnStyle.Render("▼")+dimStyle.Render(" packets missing  ")+
		errStyle.Render("!")+dimStyle.Render(" lost on board / bad frames")) + "\n\n")

	b.WriteString(m.timelineDetail())
	return b.String()
}

// timelineDetail describes what happened inside the cursor's slice of the axis
func (m Model) timelineDetail() string {
	tv := &m.timeline
	from, to, x0, x1 := tv.column(tv.cursor)
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s → %s\n", titleStyle.Render("cursor"), m.stamp(x0), m.stamp(x1))
	for _, r := range tv.rows {
		recv, lost := sum(r.recv, from, to), sum(r.lost, from, to)
		if recv == 0 && lost < 0.5 {
			continue
		}
		fmt.Fprintf(&b, "  %-12s %7.0f frames received  %7.0f lost\n", r.label, recv, lost)
	}
	if n := sum(tv.pktLost, from, to); n >= 0.5 {
		fmt.Fprintf(&b, "  %.0f packet(s) missing\n", n)
	}
	if n := sum(tv.onboard, from, to); n >= 0.5 {
		fmt.Fprintf(&b, "  %.0f packet(s) missing with no frame loss (likely lost on board)\n", n)
	}
	if n := sum(tv.quality, from, to); n >= 0.5 {
		fmt.Fprintf(&b, "  %.0f frame(s) failed CRC or looked like false decodes\n", n)
	}
	if tv.byTime {
		st := m.store.Stats()
		for _, bu := range st.Bursts {
			s0 := bu.Start.Sub(st.Time.Start).Seconds()
			s1 := bu.End.Sub(st.Time.Start).Seconds()
			if s1 < x0 || s0 > x1 {
				continue
			}
			var fr []string
			for _, f := range bu.Frames {
				mark := ""
				if f.Estimated {
					mark = "~"
				}
				fr = append(fr, fmt.Sprintf("VC%d:%s%d", f.VCID, mark, f.Frames))
			}
			fmt.Fprintf(&b, "  burst %s for %.3fs: %s frames lost\n", st.Time.Stamp(bu.Start), bu.DurationSeconds, strings.Join(fr, " "))
		}
	}
	return b.String()
}

// jumpFrames and jumpEvents find the first row at or after the cursor's slice
func (m Model) jumpFrames() int {
	x0, _ := m.timeline.cursorRange()
	n := m.store.FrameCount()
	return sort.Search(n, func(i int) bool {
		f := m.store.Frame(i)
		return m.timeline.framePos(m.store, f.Time, f.Offset) >= x0
	})
}

func (m Model) jumpEvents() int {
	x0, _ := m.timeline.cursorRange()
	ev := m.store.Events()
	start := m.store.Stats().Time.Start
	for i, e := range ev {
		if !e.Time.IsZero() && e.Time.Sub(start).Seconds() >= x0 {
			return i
		}
	}
	return len(ev) - 1
}
