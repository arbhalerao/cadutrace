package app_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/arbhalerao/cadutrace/internal/app"
	"github.com/arbhalerao/cadutrace/internal/detect"
	"github.com/arbhalerao/cadutrace/internal/testgen"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

type memSource []byte

func (m memSource) Bytes() ([]byte, error) { return m, nil }
func (m memSource) Name() string           { return "mem" }
func (m memSource) Close() error           { return nil }

func config(packetLen int, mut func(*testgen.StreamConfig)) testgen.StreamConfig {
	var vcs []testgen.VCConfig
	for v := range 3 {
		vcs = append(vcs, testgen.VCConfig{
			SCID: 42, VCID: ccsdsdefs.VCID(v), FrameType: ccsdsdefs.TFVNTM,
			APIDs:      []ccsdsdefs.APID{0x100 + ccsdsdefs.APID(2*v), 0x101 + ccsdsdefs.APID(2*v)},
			NumPackets: 500, PacketLen: packetLen,
		})
	}
	cfg := testgen.StreamConfig{VCs: vcs, FrameType: ccsdsdefs.TFVNTM, FrameDataLen: 200}
	if mut != nil {
		mut(&cfg)
	}
	return cfg
}

func run(t *testing.T, data []byte) *app.Result {
	t.Helper()
	res, err := app.Run(context.Background(), app.Options{
		Source: memSource(data), Detect: &detect.Fixed{}, CollectPackets: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// checkIntact fails if any complete packet's payload breaks testgen's fill pattern,
// which is what a packet spliced from non-adjacent frames looks like
func checkIntact(t *testing.T, res *app.Result) {
	t.Helper()
	for i, p := range res.PacketList {
		if p.Truncated || len(p.Raw) <= 6 {
			continue
		}
		base := p.Raw[6] - 6
		for j := 7; j < len(p.Raw); j++ {
			if p.Raw[j] != base+byte(j) {
				t.Fatalf("packet %d (APID %#x, %d octets) has foreign bytes at offset %d", i, p.APID, len(p.Raw), j)
			}
		}
	}
}

func TestRunMatchesManifest(t *testing.T) {
	data, man, err := testgen.Build(config(700, func(c *testgen.StreamConfig) { c.FECF = true }))
	if err != nil {
		t.Fatal(err)
	}
	res := run(t, data)
	st := res.Statistics
	for _, a := range st.APIDs {
		if a.Idle {
			continue
		}
		if want := man.PacketsPerAPID[a.APID]; int(a.Count) != want {
			t.Errorf("APID %#x: %d packets, want %d", a.APID, a.Count, want)
		}
	}
	if int(st.Packets.Total-st.Packets.Idle) != man.TotalPackets {
		t.Errorf("total %d, want %d", st.Packets.Total-st.Packets.Idle, man.TotalPackets)
	}
	q := st.Quality
	if q.FramesUsed != uint64(man.TotalFrames) || q.CRCFailures+q.SuspectFrames+q.DecodeErrors != 0 || len(q.Warnings) > 0 {
		t.Errorf("unexpected quality %+v", q)
	}
	if st.Packets.Truncated+st.Packets.SequenceGaps+st.Packets.Duplicates+st.Packets.Reorders != 0 {
		t.Errorf("clean stream reported problems: %+v", st.Packets)
	}
	checkIntact(t, res)
}

func TestLostFramesDoNotSplicePackets(t *testing.T) {
	var buf bytes.Buffer
	if err := testgen.WriteStream(&buf, config(530, nil), 2_000_000, 5); err != nil {
		t.Fatal(err)
	}
	res := run(t, buf.Bytes())
	if res.Statistics.Packets.Truncated == 0 {
		t.Fatal("expected truncated packets from dropped frames")
	}
	checkIntact(t, res)
}

func TestCRCFailureDropsFrame(t *testing.T) {
	data, man, err := testgen.Build(config(700, func(c *testgen.StreamConfig) { c.FECF = true }))
	if err != nil {
		t.Fatal(err)
	}
	data[man.CADULen*30+100] ^= 0x40
	res := run(t, data)
	if q := res.Statistics.Quality; q.CRCFailures != 1 || q.FramesUsed != uint64(man.TotalFrames-1) {
		t.Fatalf("quality %+v, want exactly one CRC failure", q)
	}
	checkIntact(t, res)
}

func TestFalseDecodeIsDropped(t *testing.T) {
	data, man, err := testgen.Build(config(90, nil))
	if err != nil {
		t.Fatal(err)
	}
	hdr := data[man.CADULen*40+4:]
	hdr[0], hdr[1] = 0x1F, 0x3A
	q := run(t, data).Statistics.Quality
	if q.SuspectFrames != 1 || len(q.Suspect) != 1 || q.Suspect[0].SCID != 499 {
		t.Fatalf("quality %+v, want one suspect frame on SCID 499", q)
	}
}

func TestBareFrames(t *testing.T) {
	data, man, err := testgen.Build(config(300, nil))
	if err != nil {
		t.Fatal(err)
	}
	var bare []byte
	for i := 0; i+man.CADULen <= len(data); i += man.CADULen {
		bare = append(bare, data[i+4:i+man.CADULen]...)
	}
	res := run(t, bare)
	if res.Settings.Sync != "none" || res.FrameLen != man.CADULen-4 {
		t.Fatalf("settings %+v, frame len %d", res.Settings, res.FrameLen)
	}
	if got := res.Statistics.Packets.Total - res.Statistics.Packets.Idle; int(got) != man.TotalPackets {
		t.Fatalf("decoded %d packets, want %d", got, man.TotalPackets)
	}
}
