package cfdptrack

import (
	"sort"

	"github.com/arbhalerao/cadutrace/internal/appdecoder/cfdp"
)

// State is a transaction's lifecycle state
type State uint8

const (
	Active State = iota
	EOFReceived
	Finished
	Cancelled
)

func (s State) String() string {
	switch s {
	case EOFReceived:
		return "eof_received"
	case Finished:
		return "finished"
	case Cancelled:
		return "cancelled"
	default:
		return "active"
	}
}

// Key identifies a transaction by its source entity ID and sequence number
type Key struct {
	Source uint64
	TSN    uint64
}

// Transaction is the tracked state of one CFDP transaction
type Transaction struct {
	Key       Key
	Direction cfdp.Direction
	State     State

	HasEOF        bool
	FileSize      uint64
	Checksum      uint32
	ConditionCode uint8

	coverage        Set
	DataPDUs        uint64
	RetransmitBytes uint64
	OutOfOrder      uint64
	NAKSegments     uint64

	lastOffset      uint64
	hasLast         bool
	completeEmitted bool
}

// NoticeKind enumerates what changed during Observe
type NoticeKind uint8

const (
	NoticeStarted NoticeKind = iota
	NoticeEOF
	NoticeGap
	NoticeComplete
	NoticeIncomplete
	NoticeNAK
)

// Notice reports a tracker event for the engine to surface
type Notice struct {
	Kind   NoticeKind
	Txn    Key
	Offset uint64 // for NoticeGap
	Length uint64 // for NoticeGap
}

// Tracker holds all transactions
type Tracker struct {
	txns  map[Key]*Transaction
	order []Key
}

// New returns an empty tracker
func New() *Tracker {
	return &Tracker{txns: make(map[Key]*Transaction)}
}

// Transaction returns the tracked transaction for a key, if any
func (t *Tracker) Transaction(k Key) (*Transaction, bool) {
	tx, ok := t.txns[k]
	return tx, ok
}

// Observe folds a PDU into the transaction state and returns notices
func (t *Tracker) Observe(p *cfdp.PDU) []Notice {
	k := Key{Source: p.SourceEntityID, TSN: p.TransactionSeqNum}
	tx, ok := t.txns[k]
	var notices []Notice
	if !ok {
		tx = &Transaction{Key: k, Direction: p.Direction, State: Active}
		t.txns[k] = tx
		t.order = append(t.order, k)
		notices = append(notices, Notice{Kind: NoticeStarted, Txn: k})
	}

	switch {
	case p.Type == cfdp.FileData:
		t.observeData(tx, p)
	case p.EOF != nil:
		notices = append(notices, t.observeEOF(tx, p)...)
	case p.Finished != nil:
		notices = append(notices, t.observeFinished(tx)...)
	case p.NAK != nil:
		tx.NAKSegments += uint64(len(p.NAK.Segments))
		notices = append(notices, Notice{Kind: NoticeNAK, Txn: k})
	}
	return notices
}

func (t *Tracker) observeData(tx *Transaction, p *cfdp.PDU) {
	tx.DataPDUs++
	end := p.Offset + uint64(p.FileDataLen)
	tx.RetransmitBytes += tx.coverage.Add(p.Offset, end)
	if tx.hasLast && p.Offset < tx.lastOffset {
		tx.OutOfOrder++
	}
	if p.Offset >= tx.lastOffset {
		tx.lastOffset = p.Offset
	}
	tx.hasLast = true
}

func (t *Tracker) observeEOF(tx *Transaction, p *cfdp.PDU) []Notice {
	tx.HasEOF = true
	tx.FileSize = p.EOF.FileSize
	tx.Checksum = p.EOF.Checksum
	tx.ConditionCode = p.EOF.ConditionCode
	if tx.State == Active {
		tx.State = EOFReceived
	}
	notices := []Notice{{Kind: NoticeEOF, Txn: tx.Key}}

	missing := tx.coverage.Missing(tx.FileSize)
	for _, m := range missing {
		notices = append(notices, Notice{Kind: NoticeGap, Txn: tx.Key, Offset: m.Start, Length: m.End - m.Start})
	}
	if len(missing) == 0 && !tx.completeEmitted {
		tx.completeEmitted = true
		notices = append(notices, Notice{Kind: NoticeComplete, Txn: tx.Key})
	}
	return notices
}

func (t *Tracker) observeFinished(tx *Transaction) []Notice {
	tx.State = Finished
	if tx.completeEmitted {
		return nil
	}
	if tx.HasEOF && len(tx.coverage.Missing(tx.FileSize)) == 0 && tx.ConditionCode == 0 {
		tx.completeEmitted = true
		return []Notice{{Kind: NoticeComplete, Txn: tx.Key}}
	}
	return []Notice{{Kind: NoticeIncomplete, Txn: tx.Key}}
}

// Complete reports whether a transaction's file data is fully covered
func (tx *Transaction) Complete() bool {
	return tx.HasEOF && len(tx.coverage.Missing(tx.FileSize)) == 0
}

// BytesReceived returns the distinct file bytes received
func (tx *Transaction) BytesReceived() uint64 { return tx.coverage.Covered() }

// MissingRanges returns the gaps in the file (empty once complete; nil before EOF
// when the size is unknown)
func (tx *Transaction) MissingRanges() []Interval {
	if !tx.HasEOF {
		return nil
	}
	return tx.coverage.Missing(tx.FileSize)
}

// TransactionStat is a deterministic snapshot of one transaction
type TransactionStat struct {
	Source          uint64     `json:"source_entity"`
	TSN             uint64     `json:"transaction_seq"`
	Direction       string     `json:"direction"`
	State           string     `json:"state"`
	Complete        bool       `json:"complete"`
	FileSize        uint64     `json:"file_size"`
	BytesReceived   uint64     `json:"bytes_received"`
	DataPDUs        uint64     `json:"data_pdus"`
	RetransmitBytes uint64     `json:"retransmit_bytes"`
	OutOfOrder      uint64     `json:"out_of_order"`
	NAKSegments     uint64     `json:"nak_segments"`
	MissingRanges   []Interval `json:"missing_ranges,omitempty"`
}

// Snapshot returns per-transaction stats in first-seen order, re-sorted by
// (source, TSN) for determinism
func (t *Tracker) Snapshot() []TransactionStat {
	out := make([]TransactionStat, 0, len(t.order))
	for _, k := range t.order {
		tx := t.txns[k]
		out = append(out, TransactionStat{
			Source:          tx.Key.Source,
			TSN:             tx.Key.TSN,
			Direction:       tx.Direction.String(),
			State:           tx.State.String(),
			Complete:        tx.Complete(),
			FileSize:        tx.FileSize,
			BytesReceived:   tx.BytesReceived(),
			DataPDUs:        tx.DataPDUs,
			RetransmitBytes: tx.RetransmitBytes,
			OutOfOrder:      tx.OutOfOrder,
			NAKSegments:     tx.NAKSegments,
			MissingRanges:   tx.MissingRanges(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].TSN < out[j].TSN
	})
	return out
}
