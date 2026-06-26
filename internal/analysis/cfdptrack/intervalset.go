package cfdptrack

// Interval is a half-open byte range [Start, End)
type Interval struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// Set is a sorted, merged, non-overlapping set of byte intervals tracking CFDP
// file coverage; insertion merges on overlap/adjacency, so completeness is a cheap
// set-subtraction against the file size
type Set struct {
	iv []Interval
}

// Add inserts [start, end) and returns the bytes that overlapped already-covered
// ranges (i.e. retransmitted bytes)
func (s *Set) Add(start, end uint64) (overlap uint64) {
	if end <= start {
		return 0
	}
	for _, iv := range s.iv {
		lo, hi := max(start, iv.Start), min(end, iv.End)
		if hi > lo {
			overlap += hi - lo
		}
	}

	merged := make([]Interval, 0, len(s.iv)+1)
	i := 0
	for i < len(s.iv) && s.iv[i].End < start { // strictly before, not adjacent
		merged = append(merged, s.iv[i])
		i++
	}
	ns, ne := start, end
	for i < len(s.iv) && s.iv[i].Start <= ne { // overlapping or adjacent
		ns = min(ns, s.iv[i].Start)
		ne = max(ne, s.iv[i].End)
		i++
	}
	merged = append(merged, Interval{Start: ns, End: ne})
	merged = append(merged, s.iv[i:]...)
	s.iv = merged
	return overlap
}

// Covered returns the total number of distinct bytes covered
func (s *Set) Covered() uint64 {
	var total uint64
	for _, iv := range s.iv {
		total += iv.End - iv.Start
	}
	return total
}

// Missing returns the gaps within [0, size) not yet covered
func (s *Set) Missing(size uint64) []Interval {
	var gaps []Interval
	var cur uint64
	for _, iv := range s.iv {
		if iv.Start >= size {
			break
		}
		if iv.Start > cur {
			gaps = append(gaps, Interval{Start: cur, End: min(iv.Start, size)})
		}
		if iv.End > cur {
			cur = iv.End
		}
	}
	if cur < size {
		gaps = append(gaps, Interval{Start: cur, End: size})
	}
	return gaps
}

// Intervals returns a copy of the covered intervals
func (s *Set) Intervals() []Interval {
	return append([]Interval(nil), s.iv...)
}
