package app

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/arbhalerao/cadutrace/internal/analysis"
	"github.com/arbhalerao/cadutrace/internal/appdecoder"
	"github.com/arbhalerao/cadutrace/internal/decode"
	"github.com/arbhalerao/cadutrace/internal/decode/encap"
	"github.com/arbhalerao/cadutrace/internal/decode/vc"
	"github.com/arbhalerao/cadutrace/internal/framing"
	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// Options configures a single offline analysis run
type Options struct {
	Source         Source
	Framing        framing.Config
	Frames         decode.Config
	MaxPacketLen   int
	CollectPackets bool                 // collect the full packet list (with raw bytes)
	CollectFrames  bool                 // collect the full frame list (with raw bytes)
	Logger         *slog.Logger         // optional; defaults to a discard logger
	Registry       *appdecoder.Registry // optional; enables application decoding (CFDP)
	Bus            *analysis.EventBus   // optional; receives analysis events (for the TUI)
}

// FrameInfo is a renderable summary of one transfer frame
type FrameInfo struct {
	Offset       int64          `json:"offset"`
	TFVN         string         `json:"tfvn"`
	SCID         ccsdsdefs.SCID `json:"scid"`
	VCID         ccsdsdefs.VCID `json:"vcid"`
	VCFrameCount uint32         `json:"vc_frame_count"`
	FHP          uint16         `json:"fhp"`
	HasFHP       bool           `json:"has_fhp"`
	DataLen      int            `json:"data_len"`
	Raw          []byte         `json:"-"`
}

// Source mirrors source.Source so callers can supply files or in-memory streams
type Source interface {
	Bytes() ([]byte, error)
	Name() string
	Close() error
}

// PacketInfo is a renderable summary of one reconstructed packet
type PacketInfo struct {
	SCID      ccsdsdefs.SCID       `json:"scid"`
	VCID      ccsdsdefs.VCID       `json:"vcid"`
	APID      ccsdsdefs.APID       `json:"apid"`
	Type      ccsdsdefs.PacketType `json:"type"`
	SeqFlags  ccsdsdefs.SeqFlags   `json:"seq_flags"`
	SeqCount  uint16               `json:"seq_count"`
	Length    int                  `json:"length"`
	Idle      bool                 `json:"idle"`
	Truncated bool                 `json:"truncated"`
	Kind      string               `json:"kind,omitempty"`     // "encap" for Encapsulation Packets
	Protocol  string               `json:"protocol,omitempty"` // encap Protocol ID name
	Raw       []byte               `json:"-"`                  // full packet bytes for the hex view
}

func packetInfo(p *model.SpacePacket) PacketInfo {
	if p.Kind == model.KindEncap {
		return PacketInfo{
			SCID: p.SCID, VCID: p.VCID, Length: p.ByteLen(),
			Truncated: p.Truncated, Kind: "encap",
			Protocol: encap.ProtocolName(p.ProtocolID), Raw: p.Raw,
		}
	}
	return PacketInfo{
		SCID: p.SCID, VCID: p.VCID, APID: p.APID, Type: p.Type,
		SeqFlags: p.SeqFlags, SeqCount: p.SeqCount, Length: p.TotalLen(),
		Idle: p.IsIdle(), Truncated: p.Truncated, Raw: p.Raw,
	}
}

// SchemaVersion identifies the JSON report schema; bump on any breaking change
const SchemaVersion = "1"

// Result is the outcome of an analysis run (the stable contract emitted by
// analyze --json): metadata + the Statistics snapshot + an optional packet list
type Result struct {
	SchemaVersion string              `json:"schema_version"`
	Source        string              `json:"source"`
	Bytes         int                 `json:"bytes"`
	CADULen       int                 `json:"cadu_len"`
	FrameLen      int                 `json:"frame_len"`
	Statistics    analysis.Statistics `json:"statistics"`
	PacketList    []PacketInfo        `json:"packet_list,omitempty"`
	FrameList     []FrameInfo         `json:"-"` // populated only when CollectFrames is set
}

// Run executes the pipeline to completion over an offline source
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Source == nil {
		return nil, errors.New("app: nil source")
	}
	data, err := opts.Source.Bytes()
	if err != nil {
		return nil, err
	}

	framer, err := framing.New(data, opts.Framing)
	if err != nil {
		return nil, err
	}
	dec := decode.NewFrameDecoder(opts.Frames)
	mgr := vc.New(opts.MaxPacketLen)
	engine := analysis.NewEngine(analysis.Config{
		Logger:   opts.Logger,
		Registry: opts.Registry,
		Bus:      opts.Bus,
	})
	caduLen := framer.CADULen()

	res := &Result{
		SchemaVersion: SchemaVersion,
		Source:        opts.Source.Name(),
		Bytes:         len(data),
		CADULen:       caduLen,
		FrameLen:      framer.FrameLen(),
	}

	record := func(p *model.SpacePacket) {
		engine.ObservePacket(p)
		if opts.CollectPackets {
			res.PacketList = append(res.PacketList, packetInfo(p))
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := framer.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		f, derr := dec.Decode(raw.Data)
		if derr != nil {
			engine.ObserveDecodeError(raw.Offset)
			continue
		}
		engine.ObserveFrame(f, caduLen)
		if opts.CollectFrames {
			fhp, ok := f.FirstHeaderPointer()
			res.FrameList = append(res.FrameList, FrameInfo{
				Offset: raw.Offset, TFVN: f.TFVN().String(),
				SCID: f.MasterChannel().SCID, VCID: f.VirtualChannel(),
				VCFrameCount: f.VCCount(), FHP: fhp, HasFHP: ok,
				DataLen: len(f.Data()), Raw: raw.Data,
			})
		}
		_, pkts, rerr := mgr.Route(f)
		if rerr != nil {
			return nil, rerr
		}
		for _, p := range pkts { // consumed before the next Route (reused arena)
			record(p)
		}
	}

	// emit any packets still open at end of stream
	for _, p := range mgr.Flush() {
		record(p)
	}

	res.Statistics = engine.Snapshot(mgr.VirtualChannels())
	return res, nil
}
