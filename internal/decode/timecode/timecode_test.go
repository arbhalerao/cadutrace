package timecode

import (
	"math/rand"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	d := 2_070_000_000*time.Second + 123_456_789
	for _, s := range []string{"cuc4.0", "cuc4.1", "cuc4.2", "cuc4.3+p", "cuc3.2@5", "cds2.0", "cds2.2+p@1", "cds3.4"} {
		f, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		if g, err := Parse(f.String()); err != nil || g != f {
			t.Fatalf("Parse(String(%v)) = %v, %v", f, g, err)
		}
		if f.Kind == CUC && f.A == 3 {
			d = 9_000_000*time.Second + 123_456_789
		}
		hdr := append(make([]byte, f.Offset), f.Encode(d)...)
		got, ok := f.Decode(hdr)
		res := time.Second
		switch {
		case f.Kind == CUC:
			res = time.Second >> (8 * f.B)
		case f.B == 0:
			res = time.Millisecond
		case f.B == 2:
			res = time.Microsecond
		default:
			res = time.Nanosecond
		}
		if !ok || got > d || d-got >= res {
			t.Errorf("%s: decoded %v (ok %v), want %v within %v", s, got, ok, d, res)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	cds, _ := Parse("cds2.0")
	if _, ok := cds.Decode([]byte{0, 1, 0xFF, 0xFF, 0xFF, 0xFF}); ok {
		t.Error("CDS with ms-of-day past midnight accepted")
	}
	p, _ := Parse("cuc4.2+p")
	bad := p.Encode(time.Hour)
	bad[0] = 0x2D // a P-field for 4.1
	if _, ok := p.Decode(bad); ok {
		t.Error("mismatched P-field accepted")
	}
	if _, ok := p.Decode([]byte{0x1E, 1, 2}); ok {
		t.Error("short header accepted")
	}
}

// headers builds interleaved APIDs whose secondary headers hold a per-APID
// counter before the time code, then the time, then a constant spare octet
func headers(f Format, epoch time.Time, start time.Time) []Sample {
	var out []Sample
	rng := rand.New(rand.NewSource(7))
	t := start.Sub(epoch)
	counters := map[uint16]uint16{}
	for i := range 600 {
		apid := uint16(0x100 + i%5)
		if _, ok := counters[apid]; !ok {
			counters[apid] = uint16(rng.Intn(1 << 16))
		}
		t += time.Duration(rng.Intn(400_000)) * time.Microsecond
		h := make([]byte, f.Offset)
		if f.Offset >= 2 {
			h[0], h[1] = byte(counters[apid]>>8), byte(counters[apid])
		}
		counters[apid] += 7
		h = append(h, f.Encode(t)...)
		h = append(h, 0, 0, 0, 0)
		out = append(out, Sample{Stream: uint32(i % 2), APID: apid, SecHdr: h})
	}
	return out
}

func TestDetect(t *testing.T) {
	when := time.Date(2023, 4, 15, 5, 33, 0, 0, time.UTC)
	cases := []struct {
		format string
		epoch  time.Time
		want   time.Time
	}{
		{"cuc4.2@0", EpochCCSDS, EpochCCSDS},
		{"cuc4.2@7", EpochCCSDS, EpochCCSDS},
		{"cuc4.3@4", Epoch2000, Epoch2000},
		{"cuc4.2@4", Epoch2000, Epoch2000},
		{"cuc4.2@9", EpochCCSDS, EpochCCSDS},
		{"cds3.4@1", EpochCCSDS, EpochCCSDS},
		{"cuc4.1+p@3", EpochCCSDS, EpochCCSDS},
		{"cds2.2@2", EpochCCSDS, EpochCCSDS},
		{"cds2.0+p@0", EpochCCSDS, EpochCCSDS},
		{"cuc4.2@3", when.AddDate(0, -1, 0), time.Time{}},
	}
	for _, tc := range cases {
		f, _ := Parse(tc.format)
		det, ok := Detect(headers(f, tc.epoch, when))
		if !ok {
			t.Errorf("%s: not detected", tc.format)
			continue
		}
		if det.Format != f || !det.Epoch.Equal(tc.want) {
			t.Errorf("%s: detected %v epoch %v, want epoch %v", tc.format, det.Format, det.Epoch, tc.want)
		}
	}
}

func TestDetectNoise(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	var s []Sample
	for i := range 500 {
		h := make([]byte, 24)
		rng.Read(h)
		s = append(s, Sample{APID: uint16(i % 4), SecHdr: h})
	}
	if det, ok := Detect(s); ok {
		t.Fatalf("detected %v in random bytes", det.Format)
	}
}
