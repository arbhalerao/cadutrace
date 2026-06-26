package gap

import "slices"

// Outcome classifies an observed counter value relative to history
type Outcome uint8

const (
	InOrder   Outcome = iota // exactly the next expected value (incl. wrap)
	Gap                      // forward jump: one or more values were skipped
	Duplicate                // exact repeat of the last value, or a recently seen value
	Reorder                  // backward jump within the window: a late/out-of-order value
	First                    // the first value observed; nothing to compare against
)

func (o Outcome) String() string {
	switch o {
	case InOrder:
		return "in_order"
	case Gap:
		return "gap"
	case Duplicate:
		return "duplicate"
	case Reorder:
		return "reorder"
	case First:
		return "first"
	default:
		return "?"
	}
}

// Tracker follows a single modular counter stream (not concurrency-safe)
type Tracker struct {
	modulus int64
	last    int64
	has     bool
	recent  []int64 // ring of recently seen values for duplicate detection
	ridx    int
}

// New returns a Tracker for a counter with the given modulus (e.g. 1<<14 for a
// packet sequence count); window is how many recent values are remembered to tell
// duplicates from reorders, defaulting to 16
func New(modulus, window int) *Tracker {
	if window < 1 {
		window = 16
	}
	return &Tracker{modulus: int64(modulus), recent: make([]int64, 0, window)}
}

// Observe records a counter value and returns its classification plus the number
// of missing values inferred (non-zero only for Gap)
func (t *Tracker) Observe(count int) (Outcome, int) {
	c := int64(count) % t.modulus
	if c < 0 {
		c += t.modulus
	}
	if !t.has {
		t.has = true
		t.last = c
		t.remember(c)
		return First, 0
	}

	// signed modular distance from the last value, in (-mod/2, mod/2]
	signed := (c - t.last) % t.modulus
	if signed < 0 {
		signed += t.modulus
	}
	if signed > t.modulus/2 {
		signed -= t.modulus
	}

	switch {
	case signed == 1:
		t.last = c
		t.remember(c)
		return InOrder, 0
	case signed == 0:
		// exact repeat; don't advance the high-water mark
		return Duplicate, 0
	case signed > 1:
		t.last = c
		t.remember(c)
		return Gap, int(signed - 1)
	default: // signed < 0: a value behind the high-water mark
		if t.seen(c) {
			return Duplicate, 0
		}
		t.remember(c)
		return Reorder, 0
	}
}

func (t *Tracker) remember(c int64) {
	if len(t.recent) < cap(t.recent) {
		t.recent = append(t.recent, c)
		return
	}
	t.recent[t.ridx] = c
	t.ridx = (t.ridx + 1) % cap(t.recent)
}

func (t *Tracker) seen(c int64) bool {
	return slices.Contains(t.recent, c)
}
