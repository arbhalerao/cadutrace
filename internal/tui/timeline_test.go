package tui

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/arbhalerao/cadutrace/internal/decode/timecode"
	"github.com/arbhalerao/cadutrace/internal/detect"
	"github.com/arbhalerao/cadutrace/internal/store"
	"github.com/arbhalerao/cadutrace/internal/testgen"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

type memSource []byte

func (m memSource) Bytes() ([]byte, error) { return m, nil }
func (m memSource) Name() string           { return "mem" }
func (m memSource) Close() error           { return nil }

func loadModel(t *testing.T, timed bool) tea.Model {
	t.Helper()
	var vcs []testgen.VCConfig
	tf, _ := timecode.Parse("cuc4.2@3")
	for v := range 2 {
		vc := testgen.VCConfig{SCID: 7, VCID: ccsdsdefs.VCID(v), FrameType: ccsdsdefs.TFVNTM,
			APIDs: []ccsdsdefs.APID{0x200 + ccsdsdefs.APID(v)}, PacketLen: 150}
		if timed {
			vc.Time = &testgen.TimeConfig{Format: tf, Epoch: timecode.EpochCCSDS,
				Start: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), Step: 99700 * time.Microsecond}
		}
		vcs = append(vcs, vc)
	}
	var buf bytes.Buffer
	cfg := testgen.StreamConfig{VCs: vcs, FrameType: ccsdsdefs.TFVNTM, FrameDataLen: 200}
	if err := testgen.WriteStream(&buf, cfg, 600_000, 0); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	cadu := 4 + 6 + 200
	from := (len(data) / cadu / 2) * cadu
	data = append(data[:from:from], data[from+400*cadu:]...) // an outage on both VCs

	st, err := store.Load(context.Background(), store.LoadOptions{Source: memSource(data), Detect: &detect.Fixed{}})
	if err != nil {
		t.Fatal(err)
	}
	var m tea.Model = New(st)
	m, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("7")})
	return m
}

func TestTimelineShowsOutage(t *testing.T) {
	for _, timed := range []bool{true, false} {
		m := loadModel(t, timed)
		view := m.View()
		if !strings.Contains(view, "×") {
			t.Errorf("timed=%v: outage not drawn:\n%s", timed, view)
		}
		if timed != strings.Contains(view, "2025-06-01") {
			t.Errorf("timed=%v: unexpected axis labels:\n%s", timed, view)
		}
	}
}

func TestTimelineZoomAndJump(t *testing.T) {
	m := loadModel(t, true)
	before := m.View()
	for _, k := range []string{"+", "+", "l", "l"} {
		m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
	}
	if m.View() == before {
		t.Fatal("zoom did not change the view")
	}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	mm := m.(Model)
	if mm.active != viewFrames || mm.frames.cursor == 0 {
		t.Fatalf("jump to frames: active %v cursor %d", mm.active, mm.frames.cursor)
	}
	m, _ = mm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("7")})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.(Model).active != viewEvents {
		t.Fatal("enter did not jump to events")
	}
}
