package store

import (
	"context"
	"log/slog"

	"github.com/arbhalerao/cadutrace/internal/analysis"
	"github.com/arbhalerao/cadutrace/internal/analysis/cfdptrack"
	"github.com/arbhalerao/cadutrace/internal/app"
	"github.com/arbhalerao/cadutrace/internal/appdecoder"
	"github.com/arbhalerao/cadutrace/internal/appdecoder/cfdp"
	"github.com/arbhalerao/cadutrace/internal/decode"
	"github.com/arbhalerao/cadutrace/internal/decode/spacepacket"
	"github.com/arbhalerao/cadutrace/internal/detect"
	"github.com/arbhalerao/cadutrace/internal/framing"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
	"github.com/arbhalerao/cadutrace/pkg/obs"
	"github.com/arbhalerao/cadutrace/pkg/plugin"
)

// LoadOptions configures loading a capture into a Store
type LoadOptions struct {
	Source       app.Source
	Framing      framing.Config
	Frames       decode.Config
	MaxPacketLen int
	CFDPAPIDs    []ccsdsdefs.APID
	Detect       *detect.Fixed
	KeepSuspect  bool
}

// Store holds an analyzed capture for random-access navigation
type Store struct {
	Source   string
	Bytes    int
	CADULen  int
	FrameLen int
	Notes    []string

	frames   []app.FrameInfo
	packets  []app.PacketInfo
	stats    analysis.Statistics
	events   []analysis.Event
	registry *appdecoder.Registry
	logger   *slog.Logger
}

// Load runs the decode + analysis pipeline over a capture and returns a Store
func Load(ctx context.Context, opts LoadOptions) (*Store, error) {
	reg := appdecoder.New()
	for _, a := range opts.CFDPAPIDs {
		reg.RegisterAPID(a, cfdp.Decoder{})
	}
	var appReg *appdecoder.Registry
	if len(opts.CFDPAPIDs) > 0 {
		appReg = reg
	}

	bus := analysis.NewEventBus(8192)
	res, err := app.Run(ctx, app.Options{
		Source:         opts.Source,
		Framing:        opts.Framing,
		Frames:         opts.Frames,
		MaxPacketLen:   opts.MaxPacketLen,
		CollectFrames:  true,
		CollectPackets: true,
		Registry:       appReg,
		Bus:            bus,
		Detect:         opts.Detect,
		KeepSuspect:    opts.KeepSuspect,
	})
	if err != nil {
		return nil, err
	}

	return &Store{
		Source:   res.Source,
		Bytes:    res.Bytes,
		CADULen:  res.CADULen,
		FrameLen: res.FrameLen,
		Notes:    res.Settings.Notes,
		frames:   res.FrameList,
		packets:  res.PacketList,
		stats:    res.Statistics,
		events:   bus.Recent(),
		registry: reg,
		logger:   obs.Discard(),
	}, nil
}

func (s *Store) FrameCount() int             { return len(s.frames) }
func (s *Store) Frame(i int) app.FrameInfo   { return s.frames[i] }
func (s *Store) PacketCount() int            { return len(s.packets) }
func (s *Store) Packet(i int) app.PacketInfo { return s.packets[i] }
func (s *Store) Stats() analysis.Statistics  { return s.stats }
func (s *Store) CFDP() []cfdptrack.TransactionStat {
	return s.stats.CFDP
}
func (s *Store) Events() []analysis.Event { return s.events }

// Dissect runs application decoding for packet i (lazy, off the UI goroutine)
func (s *Store) Dissect(i int) *plugin.Result {
	if i < 0 || i >= len(s.packets) {
		return nil
	}
	pi := s.packets[i]
	sp, err := spacepacket.Parse(pi.Raw)
	if err != nil {
		return &plugin.Result{Protocol: "raw", Summary: "unparseable packet"}
	}
	sp.SCID, sp.VCID = pi.SCID, pi.VCID
	return s.registry.Dispatch(plugin.DecodeContext{Logger: s.logger}, &sp)
}
