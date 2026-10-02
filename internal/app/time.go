package app

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/arbhalerao/cadutrace/internal/decode"
	"github.com/arbhalerao/cadutrace/internal/decode/timecode"
	"github.com/arbhalerao/cadutrace/internal/decode/vc"
	"github.com/arbhalerao/cadutrace/internal/detect"
	"github.com/arbhalerao/cadutrace/internal/framing"
	"github.com/arbhalerao/cadutrace/internal/model"
)

// TimeOptions configures packet time; nil Format or Epoch means detect it
type TimeOptions struct {
	Off    bool
	Format *timecode.Format
	Epoch  *time.Time
}

const (
	timeSamples     = 3000
	timeSampleBytes = 32
	timeScanFrames  = 200_000
	timeGiveUp      = 20_000 // frames without a single secondary header
)

type timeDecoder struct {
	format   timecode.Format
	base     time.Time
	relative bool
}

func (td *timeDecoder) stamp(p *model.SpacePacket) {
	if td == nil || p.Kind != model.KindSpace || !p.SecHdrFlag || p.IsIdle() {
		return
	}
	if d, ok := td.format.Decode(p.Payload); ok {
		p.Time = td.base.Add(d)
	}
}

func (td *timeDecoder) describe() (code, epoch string) {
	if td == nil {
		return "", ""
	}
	if td.relative {
		return td.format.String(), ""
	}
	return td.format.String(), td.base.Format("2006-01-02")
}

// setupTime resolves the time code and epoch, detecting what was not given
func setupTime(data []byte, opts Options, trusted map[detect.ChannelID]bool) (*timeDecoder, []string, error) {
	if opts.Time.Off {
		return nil, nil, nil
	}
	samples, err := sampleTimes(data, opts, trusted)
	if err != nil {
		return nil, nil, err
	}
	td := &timeDecoder{}
	var notes []string
	if opts.Time.Format != nil {
		td.format = *opts.Time.Format
	} else {
		if len(samples) == 0 {
			return nil, []string{"time: packets carry no secondary header"}, nil
		}
		det, ok := timecode.Detect(samples)
		if !ok {
			return nil, []string{"time: no consistent time code in packet secondary headers; set --time to read one"}, nil
		}
		td.format = det.Format
		notes = append(notes, fmt.Sprintf("time: %s in packet secondary headers", det.Format))
	}
	switch {
	case opts.Time.Epoch != nil:
		td.base = *opts.Time.Epoch
	default:
		if e, ok := timecode.EpochFor(td.format, samples); ok {
			td.base = e
			notes = append(notes, fmt.Sprintf("time: epoch assumed %s (set --epoch if wrong)", e.Format("2006-01-02")))
		} else {
			td.relative = true
			notes = append(notes, "time: epoch unknown, times shown relative to the first packet (set --epoch)")
		}
	}
	return td, notes, nil
}

// sampleTimes runs the front of the pipeline over the start of the capture and
// returns the leading secondary-header bytes of packets that carry one
func sampleTimes(data []byte, opts Options, trusted map[detect.ChannelID]bool) ([]timecode.Sample, error) {
	framer, err := framing.New(data, opts.Framing)
	if err != nil {
		return nil, err
	}
	dec := decode.NewFrameDecoder(opts.Frames)
	mgr := vc.New(opts.MaxPacketLen)
	var out []timecode.Sample
	for n := 0; n < timeScanFrames && len(out) < timeSamples && (n < timeGiveUp || len(out) > 0); n++ {
		raw, err := framer.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if trusted != nil && len(raw.Data) >= 6 && !trusted[detect.ParseChannel(raw.Data).ID()] {
			continue
		}
		f, err := dec.Decode(raw.Data)
		if err != nil {
			continue
		}
		_, pkts, err := mgr.Route(f)
		if err != nil {
			return nil, err
		}
		for _, p := range pkts {
			if p.Kind != model.KindSpace || !p.SecHdrFlag || p.IsIdle() || p.Truncated {
				continue
			}
			sh := p.Payload[:min(len(p.Payload), timeSampleBytes)]
			out = append(out, timecode.Sample{
				Stream: uint32(p.SCID)<<8 | uint32(p.VCID), APID: uint16(p.APID),
				SecHdr: append([]byte(nil), sh...),
			})
		}
	}
	return out, nil
}
