package detect_test

import (
	"math/rand"
	"testing"

	"github.com/arbhalerao/cadutrace/internal/detect"
	"github.com/arbhalerao/cadutrace/internal/testgen"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

func stream(t *testing.T, ft ccsdsdefs.TFVN, mut func(*testgen.StreamConfig)) ([]byte, testgen.Manifest) {
	t.Helper()
	var vcs []testgen.VCConfig
	for v := range 3 {
		vcs = append(vcs, testgen.VCConfig{
			SCID: 42, VCID: ccsdsdefs.VCID(v), FrameType: ft,
			APIDs: []ccsdsdefs.APID{0x100 + ccsdsdefs.APID(v)}, NumPackets: 400, PacketLen: 90,
		})
	}
	cfg := testgen.StreamConfig{VCs: vcs, FrameType: ft, FrameDataLen: 200}
	if mut != nil {
		mut(&cfg)
	}
	data, man, err := testgen.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return data, man
}

func stripASM(data []byte, cadu int) []byte {
	var out []byte
	for i := 0; i+cadu <= len(data); i += cadu {
		out = append(out, data[i+4:i+cadu]...)
	}
	return out
}

func TestDetect(t *testing.T) {
	fecfRS := func(c *testgen.StreamConfig) { c.FECF, c.RSLen, c.Randomize = true, 32, true }
	cases := []struct {
		name  string
		ft    ccsdsdefs.TFVN
		mut   func(*testgen.StreamConfig)
		bare  bool
		want  detect.Params
		fixed detect.Fixed
		in    detect.Params
	}{
		{name: "tm", ft: ccsdsdefs.TFVNTM},
		{name: "aos", ft: ccsdsdefs.TFVNAOS, want: detect.Params{TFVN: ccsdsdefs.TFVNAOS}},
		{name: "randomized", ft: ccsdsdefs.TFVNTM, mut: func(c *testgen.StreamConfig) { c.Randomize = true },
			want: detect.Params{Derandomize: true}},
		{name: "fecf", ft: ccsdsdefs.TFVNTM, mut: func(c *testgen.StreamConfig) { c.FECF = true },
			want: detect.Params{FECF: true}},
		{name: "aos fecf", ft: ccsdsdefs.TFVNAOS, mut: func(c *testgen.StreamConfig) { c.FECF = true },
			want: detect.Params{FECF: true, TFVN: ccsdsdefs.TFVNAOS}},
		{name: "fecf rs randomized", ft: ccsdsdefs.TFVNTM, mut: fecfRS,
			want: detect.Params{FECF: true, RSLen: 32, Derandomize: true}},
		{name: "bare", ft: ccsdsdefs.TFVNTM, bare: true, want: detect.Params{NoASM: true}},
		{name: "bare fecf", ft: ccsdsdefs.TFVNTM, bare: true, mut: func(c *testgen.StreamConfig) { c.FECF = true },
			want: detect.Params{NoASM: true, FECF: true}},
		{name: "fixed settings win", ft: ccsdsdefs.TFVNTM, mut: func(c *testgen.StreamConfig) { c.FECF = true },
			fixed: detect.Fixed{FECF: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, man := stream(t, tc.ft, tc.mut)
			stride := man.CADULen
			if tc.bare {
				data = stripASM(data, man.CADULen)
				stride -= 4
			}
			got, notes, err := detect.Detect(data, tc.in, tc.fixed)
			if err != nil {
				t.Fatalf("Detect: %v (notes %q)", err, notes)
			}
			want := tc.want
			want.ASM = ccsdsdefs.ASMStandard
			want.CADULen = stride
			if got != want {
				t.Fatalf("got %+v\nwant %+v\nnotes %q", got, want, notes)
			}
		})
	}
}

func TestDetectRejectsNoise(t *testing.T) {
	noise := make([]byte, 200_000)
	rand.New(rand.NewSource(1)).Read(noise)
	if p, _, err := detect.Detect(noise, detect.Params{}, detect.Fixed{}); err == nil {
		t.Fatalf("expected an error on random bytes, got %+v", p)
	}
}

func TestChannelsFlagsOneOffHeaders(t *testing.T) {
	data, man := stream(t, ccsdsdefs.TFVNTM, nil)
	junk := data[man.CADULen*50+4:]
	junk[0], junk[1] = 0x1F, 0x3A // SCID 499, VC 5
	ch, err := detect.Channels(data, detect.Params{CADULen: man.CADULen}.Framing())
	if err != nil {
		t.Fatal(err)
	}
	for id, ok := range ch {
		real := id.SCID == 42 && id.VCID < 3
		if ok != real {
			t.Errorf("channel %+v trusted=%v, want %v", id, ok, real)
		}
	}
	if len(ch) != 4 {
		t.Errorf("saw %d channels, want 4", len(ch))
	}
}
