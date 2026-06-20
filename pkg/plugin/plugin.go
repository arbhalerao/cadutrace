package plugin

import (
	"log/slog"

	"github.com/arbhalerao/cadutrace/internal/model"
)

// Decoder dissects a space packet into a result tree
// Implementations must not panic and must not retain p.Payload beyond the call unless they copy it
type Decoder interface {
	// Name is a stable identifier, e.g. "cfdp", "acme.hk"
	Name() string
	// CanDecode lets a decoder claim a packet beyond an APID match by peeking at the payload (protocol identification)
	CanDecode(p *model.SpacePacket) bool
	// Decode parses the packet into a result tree
	Decode(ctx DecodeContext, p *model.SpacePacket) (*Result, error)
}

// DecodeContext carries per-dissection services to a decoder
type DecodeContext struct {
	Logger *slog.Logger
}

// Field is one named, renderable value with its byte range within the dissected buffer
// Byte ranges let a UI build a synchronized hex view
type Field struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

// Severity ranks a diagnostic
type Severity string

const (
	Warn  Severity = "warn"
	Error Severity = "error"
)

// Diagnostic flags a problem found during dissection (e.g. a lying length)
type Diagnostic struct {
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Offset   int      `json:"offset"`
	Length   int      `json:"length"`
}

// Result is the uniform output of any decoder: a tree of named fields, nested children, an optional typed PDU for analytics, and diagnostics
type Result struct {
	Protocol    string       `json:"protocol"`
	Summary     string       `json:"summary"`
	Fields      []Field      `json:"fields,omitempty"`
	Children    []*Result    `json:"children,omitempty"`
	PDU         any          `json:"-"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// AddField appends a named field with a byte range
func (r *Result) AddField(name, value string, offset, length int) {
	r.Fields = append(r.Fields, Field{Name: name, Value: value, Offset: offset, Length: length})
}

// Diag appends a diagnostic
func (r *Result) Diag(sev Severity, msg string, offset, length int) {
	r.Diagnostics = append(r.Diagnostics, Diagnostic{Severity: sev, Message: msg, Offset: offset, Length: length})
}
