package analysis

import (
	"sort"
	"time"

	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

const (
	clockBack    = time.Minute
	clockForward = time.Hour
	clockResync  = 3
	burstSlack   = time.Second
	maxGaps      = 100_000
)

// clock follows one VC's packet time and rejects stamps that jump implausibly,
// re-locking when several consecutive stamps agree on a new time
type clock struct {
	t     time.Time
	ok    bool
	pend  time.Time
	pendN int
}

func (c *clock) accept(t time.Time) bool {
	if !c.ok || (!t.Before(c.t.Add(-clockBack)) && !t.After(c.t.Add(clockForward))) {
		if !c.ok || t.After(c.t) {
			c.t = t
		}
		c.ok, c.pendN = true, 0
		return true
	}
	if c.pendN > 0 && t.Sub(c.pend).Abs() <= clockBack {
		c.pendN++
	} else {
		c.pendN = 1
	}
	c.pend = t
	if c.pendN >= clockResync {
		c.t, c.pendN = t, 0
		return true
	}
	return false
}

// timeline places loss in time: each gap is bounded by the last time seen before
// it and the first time seen after it, on the same VC when that VC carries time
type timeline struct {
	clocks      map[vcKey]*clock
	now         time.Time
	first, last time.Time
	timed       uint64
	rejected    uint64
	lossEpoch   map[vcKey]uint64
	gaps        []Gap
	dropped     uint64
	pendVC      map[vcKey][]int
	pendAny     []int
	offset      int64
}

func newTimeline() timeline {
	return timeline{clocks: map[vcKey]*clock{}, lossEpoch: map[vcKey]uint64{}, pendVC: map[vcKey][]int{}}
}

// observe vets a packet time, returning the zero time when it is rejected
func (tl *timeline) observe(k vcKey, t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	c := tl.clocks[k]
	if c == nil {
		c = &clock{}
		tl.clocks[k] = c
	}
	if !c.accept(t) {
		tl.rejected++
		return time.Time{}
	}
	tl.timed++
	if tl.first.IsZero() || t.Before(tl.first) {
		tl.first = t
	}
	if t.After(tl.last) {
		tl.last = t
	}
	if t.After(tl.now) {
		tl.now = t
	}
	for _, i := range tl.pendVC[k] {
		tl.gaps[i].End = t
	}
	delete(tl.pendVC, k)
	for _, i := range tl.pendAny {
		tl.gaps[i].End = t
	}
	tl.pendAny = tl.pendAny[:0]
	return t
}

func (tl *timeline) add(g Gap) int {
	if len(tl.gaps) >= maxGaps {
		tl.dropped++
		return -1
	}
	g.Offset = tl.offset
	tl.gaps = append(tl.gaps, g)
	return len(tl.gaps) - 1
}

func (tl *timeline) frameGap(k vcKey, lost uint64) Gap {
	tl.lossEpoch[k]++
	g := Gap{Kind: "frames", SCID: k.scid, VCID: k.vcid, Missing: lost}
	c := tl.clocks[k]
	timedVC := c != nil && c.ok
	if timedVC {
		g.Start = c.t
	} else {
		g.Start = tl.now
	}
	if i := tl.add(g); i >= 0 {
		if timedVC {
			tl.pendVC[k] = append(tl.pendVC[k], i)
		} else {
			tl.pendAny = append(tl.pendAny, i)
		}
	}
	return g
}

func (tl *timeline) packetGap(k vcKey, apid ccsdsdefs.APID, missing uint64, start, end time.Time, onboard bool) Gap {
	g := Gap{Kind: "packets", SCID: k.scid, VCID: k.vcid, APID: apid, Missing: missing,
		Onboard: onboard, Start: start, End: end}
	tl.add(g)
	return g
}

func (tl *timeline) stats() TimeStats {
	ts := TimeStats{Start: tl.first, End: tl.last, Packets: tl.timed, Rejected: tl.rejected}
	if !tl.first.IsZero() {
		ts.DurationSeconds = round2(tl.last.Sub(tl.first).Seconds())
	}
	return ts
}

// bursts merges frame gaps whose time spans overlap, across VCs, and attributes
// to each the packet gaps that fall inside it
func bursts(gaps []Gap) []Burst {
	var frames []Gap
	for _, g := range gaps {
		if g.Kind == "frames" && !g.Start.IsZero() && !g.End.IsZero() {
			frames = append(frames, g)
		}
	}
	sort.SliceStable(frames, func(i, j int) bool { return frames[i].Start.Before(frames[j].Start) })

	var out []Burst
	vcIdx := map[vcKey]int{}
	for _, g := range frames {
		if n := len(out); n == 0 || g.Start.After(out[n-1].End.Add(burstSlack)) {
			out = append(out, Burst{Start: g.Start, End: g.End})
			clear(vcIdx)
		}
		b := &out[len(out)-1]
		if g.End.After(b.End) {
			b.End = g.End
		}
		k := vcKey{g.SCID, g.VCID}
		i, ok := vcIdx[k]
		if !ok {
			i = len(b.Frames)
			vcIdx[k] = i
			b.Frames = append(b.Frames, VCLoss{SCID: g.SCID, VCID: g.VCID})
		}
		b.Frames[i].Frames += g.Missing
	}

	for _, g := range gaps {
		if g.Kind != "packets" || g.Onboard || g.End.IsZero() {
			continue
		}
		j := sort.Search(len(out), func(j int) bool { return !out[j].End.Add(burstSlack).Before(g.End) })
		if j == len(out) || g.End.Before(out[j].Start) {
			continue
		}
		b := &out[j]
		found := false
		for i := range b.Packets {
			if b.Packets[i].APID == g.APID {
				b.Packets[i].Missing += g.Missing
				found = true
			}
		}
		if !found {
			b.Packets = append(b.Packets, APIDLoss{APID: g.APID, Missing: g.Missing})
		}
	}
	for i := range out {
		out[i].DurationSeconds = round2(out[i].End.Sub(out[i].Start).Seconds())
		sort.Slice(out[i].Packets, func(a, b int) bool { return out[i].Packets[a].APID < out[i].Packets[b].APID })
	}
	return out
}
