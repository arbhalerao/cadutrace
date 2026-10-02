package timecode

import (
	"math"
	"slices"
	"sort"
	"time"
)

// Sample is the start of one packet secondary header, tagged with the stream it
// arrived on (e.g. a virtual channel) and its APID, in arrival order
type Sample struct {
	Stream uint32
	APID   uint16
	SecHdr []byte
}

// Detection is the outcome of Detect
// Epoch is zero when no common epoch puts the times in a plausible range, in which
// case times are only meaningful relative to each other
type Detection struct {
	Format Format
	Epoch  time.Time
	Score  float64
}

const (
	minSamples  = 20
	maxOffset   = 12
	minDecoded  = 0.9
	minScore    = 0.95
	minOrdered  = 0.9
	minValues   = 3
	maxBack     = time.Minute
	maxForward  = 10 * time.Minute
	minDistinct = 8
)

var (
	plausibleFrom = time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC)
	plausibleTo   = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Detect finds the time code layout that makes the samples tell one consistent
// time: consecutive packets on a stream agree to within minutes even across APIDs
// (which rules out per-APID counters), and each APID's time advances
func Detect(samples []Sample) (Detection, bool) {
	if len(samples) < minSamples {
		return Detection{}, false
	}
	type cand struct {
		Detection
		plausible bool
		scale     float64
	}
	var best []cand
	for _, f := range candidates() {
		f.B = finest(f, samples)
		ds, ok := decodeAll(f, samples)
		if !ok {
			continue
		}
		sc, period := score(ds, samples)
		if sc < minScore {
			continue
		}
		epoch, plausible := pickEpoch(ds)
		best = append(best, cand{Detection{Format: f, Epoch: epoch, Score: sc}, plausible, scaleError(period)})
	}
	if len(best) == 0 {
		return Detection{}, false
	}
	sort.SliceStable(best, func(i, j int) bool {
		a, b := best[i], best[j]
		if d := a.Score - b.Score; d > 0.01 || d < -0.01 {
			return d > 0
		}
		// an octet of misalignment scales time by 256, which moves the typical
		// packet period far from what spacecraft use
		if d := a.scale - b.scale; d > 4 || d < -4 {
			return d < 0
		}
		if a.plausible != b.plausible {
			return a.plausible
		}
		// CDS candidates have passed range checks a coincidental match rarely does
		if a.Format.Kind != b.Format.Kind {
			return a.Format.Kind == CDS
		}
		if a.Format.Offset != b.Format.Offset {
			return a.Format.Offset < b.Format.Offset
		}
		if a.Format.PField != b.Format.PField {
			return !a.Format.PField
		}
		return a.Format.A > b.Format.A
	})
	return best[0].Detection, true
}

// scaleError is how many octaves the typical per-APID packet period lies from one
// second; real housekeeping and science periods cluster within a few octaves of it
func scaleError(period time.Duration) float64 {
	if period <= 0 {
		return math.Inf(1)
	}
	return math.Abs(math.Log2(period.Seconds()))
}

// candidates lists layouts to try; implicit ones are sized later by finest, while
// a P-field states its own sizes
func candidates() []Format {
	var out []Format
	for off := 0; off <= maxOffset; off++ {
		for a := 2; a <= 4; a++ {
			out = append(out, Format{Kind: CUC, A: a, Offset: off})
			for b := 0; b <= 3; b++ {
				out = append(out, Format{Kind: CUC, A: a, B: b, PField: true, Offset: off})
			}
		}
		for _, a := range []int{2, 3} {
			out = append(out, Format{Kind: CDS, A: a, Offset: off})
			for _, b := range []int{0, 2, 4} {
				out = append(out, Format{Kind: CDS, A: a, B: b, PField: true, Offset: off})
			}
		}
	}
	return out
}

// decodeAll decodes every sample, reporting false when too few decode
// Undecodable samples are marked with -1
func decodeAll(f Format, samples []Sample) ([]time.Duration, bool) {
	ds := make([]time.Duration, len(samples))
	n := 0
	for i, s := range samples {
		d, ok := f.Decode(s.SecHdr)
		if !ok {
			ds[i] = -1
			continue
		}
		ds[i] = d
		n++
	}
	return ds, float64(n) >= minDecoded*float64(len(samples))
}

// score is the fraction of consecutive packets on a stream whose times agree; it
// is zero unless each APID's time mostly moves forward and takes several values
// period is the median forward step between consecutive packets of one APID
func score(ds []time.Duration, samples []Sample) (sc float64, period time.Duration) {
	type key struct {
		stream uint32
		apid   uint16
	}
	lastStream := map[uint32]time.Duration{}
	lastAPID := map[key]time.Duration{}
	values := map[time.Duration]bool{}
	pairs, agree, steps, ordered := 0, 0, 0, 0
	var forward []time.Duration
	for i, d := range ds {
		if d < 0 {
			continue
		}
		s := samples[i]
		if len(values) < minValues {
			values[d] = true
		}
		if prev, ok := lastStream[s.Stream]; ok {
			pairs++
			if delta := d - prev; delta >= -maxBack && delta <= maxForward {
				agree++
			}
		}
		lastStream[s.Stream] = d
		k := key{s.Stream, s.APID}
		if prev, ok := lastAPID[k]; ok {
			steps++
			if d >= prev {
				ordered++
			}
			if d > prev {
				forward = append(forward, d-prev)
			}
		}
		lastAPID[k] = d
	}
	if pairs == 0 || steps == 0 || len(values) < minValues || float64(ordered) < minOrdered*float64(steps) {
		return 0, 0
	}
	if len(forward) > 0 {
		slices.Sort(forward)
		period = forward[len(forward)/2]
	}
	return float64(agree) / float64(pairs), period
}

func pickEpoch(ds []time.Duration) (time.Time, bool) {
	var first time.Duration = -1
	for _, d := range ds {
		if d >= 0 {
			first = d
			break
		}
	}
	for _, e := range []time.Time{EpochCCSDS, Epoch2000} {
		t := e.Add(first)
		if !t.Before(plausibleFrom) && t.Before(plausibleTo) {
			return e, true
		}
	}
	return time.Time{}, false
}

// finest sizes the fraction (CUC) or sub-millisecond field (CDS) as the longest
// one whose octets all change; a constant octet belongs to the next field
func finest(f Format, samples []Sample) int {
	if f.PField {
		return f.B
	}
	start := f.Offset + f.A
	if f.Kind == CDS {
		start += 4
		for _, n := range []int{4, 2} {
			g := f
			g.B = n
			if _, ok := decodeAll(g, samples); ok && varies(samples, start, start+n) && everyOctetChanges(samples, start, start+n) {
				return n
			}
		}
		return 0
	}
	b := 0
	for n := 1; n <= 3; n++ {
		g := f
		g.B = n
		if _, ok := decodeAll(g, samples); !ok || !everyOctetChanges(samples, start+b, start+n) {
			break
		}
		b = n
	}
	return b
}

// varies reports whether octets [from, to) take several distinct values
func varies(samples []Sample, from, to int) bool {
	seen := map[string]bool{}
	for _, s := range samples {
		if to <= len(s.SecHdr) {
			seen[string(s.SecHdr[from:to])] = true
			if len(seen) >= minDistinct {
				return true
			}
		}
	}
	return false
}

// EpochFor picks the common epoch that puts f's times in a plausible range
func EpochFor(f Format, samples []Sample) (time.Time, bool) {
	ds, _ := decodeAll(f, samples)
	return pickEpoch(ds)
}

func everyOctetChanges(samples []Sample, from, to int) bool {
	for pos := from; pos < to; pos++ {
		first, changed := -1, false
		for _, s := range samples {
			if pos >= len(s.SecHdr) {
				continue
			}
			if first < 0 {
				first = int(s.SecHdr[pos])
			} else if int(s.SecHdr[pos]) != first {
				changed = true
				break
			}
		}
		if !changed {
			return false
		}
	}
	return true
}
