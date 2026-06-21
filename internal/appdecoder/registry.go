package appdecoder

import (
	"fmt"

	"github.com/arbhalerao/cadutrace/internal/appdecoder/builtin"
	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
	"github.com/arbhalerao/cadutrace/pkg/plugin"
)

// Registry maps APIDs to decoders, with a terminal raw fallback
type Registry struct {
	byAPID   map[ccsdsdefs.APID]plugin.Decoder
	fallback plugin.Decoder
}

// New returns an empty registry with the raw fallback installed
func New() *Registry {
	return &Registry{
		byAPID:   make(map[ccsdsdefs.APID]plugin.Decoder),
		fallback: builtin.Raw{},
	}
}

// RegisterAPID binds a decoder to an exact APID
func (r *Registry) RegisterAPID(apid ccsdsdefs.APID, d plugin.Decoder) {
	r.byAPID[apid] = d
}

// Handles reports whether a dedicated decoder is mapped to the APID
// the analytics path uses this to skip raw-fallback work for unclaimed packets
func (r *Registry) Handles(apid ccsdsdefs.APID) bool {
	_, ok := r.byAPID[apid]
	return ok
}

// Dispatch routes a packet to its APID decoder, else the raw fallback (always non-nil)
func (r *Registry) Dispatch(ctx plugin.DecodeContext, p *model.SpacePacket) *plugin.Result {
	if d, ok := r.byAPID[p.APID]; ok && d.CanDecode(p) {
		if res := tryDecode(ctx, d, p); res != nil {
			return res
		}
	}
	res, _ := r.fallback.Decode(ctx, p)
	return res
}

// tryDecode runs a decoder behind a recover boundary; on panic or error it returns
// nil so Dispatch falls through to the raw fallback
func tryDecode(ctx plugin.DecodeContext, d plugin.Decoder, p *model.SpacePacket) (res *plugin.Result) {
	defer func() {
		if rec := recover(); rec != nil {
			if ctx.Logger != nil {
				ctx.Logger.Error("decoder panicked", "decoder", d.Name(), "panic", fmt.Sprint(rec))
			}
			res = nil
		}
	}()
	r, err := d.Decode(ctx, p)
	if err != nil {
		if ctx.Logger != nil {
			ctx.Logger.Warn("decoder error", "decoder", d.Name(), "err", err)
		}
		return nil
	}
	return r
}
