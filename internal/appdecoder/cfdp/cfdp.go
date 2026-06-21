package cfdp

import (
	"errors"
	"fmt"
)

// PDUType selects the PDU body format
type PDUType uint8

const (
	FileDirective PDUType = 0
	FileData      PDUType = 1
)

// Direction indicates which way the PDU travels
type Direction uint8

const (
	TowardReceiver Direction = 0
	TowardSender   Direction = 1
)

func (d Direction) String() string {
	if d == TowardSender {
		return "to_sender"
	}
	return "to_receiver"
}

// DirectiveCode identifies a file directive PDU
type DirectiveCode uint8

const (
	DirEOF       DirectiveCode = 0x04
	DirFinished  DirectiveCode = 0x05
	DirACK       DirectiveCode = 0x06
	DirMetadata  DirectiveCode = 0x07
	DirNAK       DirectiveCode = 0x08
	DirPrompt    DirectiveCode = 0x09
	DirKeepAlive DirectiveCode = 0x0C
)

func (c DirectiveCode) String() string {
	switch c {
	case DirEOF:
		return "EOF"
	case DirFinished:
		return "Finished"
	case DirACK:
		return "ACK"
	case DirMetadata:
		return "Metadata"
	case DirNAK:
		return "NAK"
	case DirPrompt:
		return "Prompt"
	case DirKeepAlive:
		return "KeepAlive"
	default:
		return fmt.Sprintf("Directive(0x%02X)", uint8(c))
	}
}

// PDU is a parsed CFDP Protocol Data Unit
type PDU struct {
	Version             uint8
	Type                PDUType
	Direction           Direction
	Acknowledged        bool // transmission mode 0 = acknowledged
	CRCPresent          bool
	LargeFile           bool
	SegmentationControl bool
	SegMetadataPresent  bool

	EntityIDLen       int
	SeqNumLen         int
	SourceEntityID    uint64
	TransactionSeqNum uint64
	DestEntityID      uint64

	HeaderLen    int
	DataFieldLen int // declared length of the PDU data field

	// File Data PDU
	Offset      uint64
	FileDataLen int

	// File Directive PDU
	DirectiveCode DirectiveCode
	EOF           *EOF
	Metadata      *Metadata
	Finished      *Finished
	ACK           *ACK
	NAK           *NAK
	Prompt        *Prompt
	KeepAlive     *KeepAlive
}

// EOF is the End-of-File directive content
type EOF struct {
	ConditionCode uint8
	Checksum      uint32
	FileSize      uint64
}

type Metadata struct {
	ClosureRequested bool
	ChecksumType     uint8
	FileSize         uint64
	SourceFileName   string
	DestFileName     string
}

type Finished struct {
	ConditionCode uint8
	DeliveryCode  uint8 // 0 = complete, 1 = incomplete
	FileStatus    uint8
}

// ACK is the Acknowledgement directive content
type ACK struct {
	AckedDirective DirectiveCode
	ConditionCode  uint8
	TxnStatus      uint8
}

// NAK is the Negative Acknowledgement directive content
type NAK struct {
	StartScope uint64
	EndScope   uint64
	Segments   [][2]uint64 // requested (start, end) ranges
}

type Prompt struct {
	KeepAlive bool // false = NAK prompt, true = Keep-Alive prompt
}

// KeepAlive is the Keep-Alive directive content
type KeepAlive struct {
	Progress uint64
}

var ErrShort = errors.New("cfdp: buffer too short for PDU header")

const fixedHeaderLen = 4

// Parse decodes a CFDP PDU from a space packet payload
func Parse(data []byte) (*PDU, error) {
	if len(data) < fixedHeaderLen {
		return nil, ErrShort
	}
	p := &PDU{
		Version:             data[0] >> 5,
		Type:                PDUType((data[0] >> 4) & 0x01),
		Direction:           Direction((data[0] >> 3) & 0x01),
		Acknowledged:        (data[0]>>2)&0x01 == 0,
		CRCPresent:          (data[0]>>1)&0x01 == 1,
		LargeFile:           data[0]&0x01 == 1,
		DataFieldLen:        int(data[1])<<8 | int(data[2]),
		SegmentationControl: (data[3]>>7)&0x01 == 1,
		EntityIDLen:         int((data[3]>>4)&0x07) + 1,
		SegMetadataPresent:  (data[3]>>3)&0x01 == 1,
		SeqNumLen:           int(data[3]&0x07) + 1,
	}

	p.HeaderLen = fixedHeaderLen + 2*p.EntityIDLen + p.SeqNumLen
	if len(data) < p.HeaderLen {
		return nil, fmt.Errorf("cfdp: buffer %d shorter than header %d", len(data), p.HeaderLen)
	}

	off := fixedHeaderLen
	p.SourceEntityID = beUint(data[off : off+p.EntityIDLen])
	off += p.EntityIDLen
	p.TransactionSeqNum = beUint(data[off : off+p.SeqNumLen])
	off += p.SeqNumLen
	p.DestEntityID = beUint(data[off : off+p.EntityIDLen])

	// data field: clamp the declared length to what's actually present
	end := min(p.HeaderLen+p.DataFieldLen, len(data))
	body := data[p.HeaderLen:end]
	if p.CRCPresent && len(body) >= 2 {
		body = body[:len(body)-2] // trailing CRC is not content
	}

	if p.Type == FileData {
		parseFileData(p, body)
	} else if len(body) > 0 {
		parseDirective(p, body)
	}
	return p, nil
}

func (p *PDU) offsetSize() int {
	if p.LargeFile {
		return 8
	}
	return 4
}

func parseFileData(p *PDU, body []byte) {
	cur := 0
	if p.SegMetadataPresent && len(body) >= 1 {
		segLen := int(body[0] & 0x3F)
		cur = min(1+segLen, len(body))
	}
	osz := p.offsetSize()
	if cur+osz > len(body) {
		return // malformed; leave Offset/FileDataLen zero
	}
	p.Offset = beUint(body[cur : cur+osz])
	p.FileDataLen = len(body) - cur - osz
}

func parseDirective(p *PDU, body []byte) {
	p.DirectiveCode = DirectiveCode(body[0])
	c := body[1:]
	osz := p.offsetSize()
	switch p.DirectiveCode {
	case DirEOF:
		if len(c) < 1+4+osz {
			return
		}
		p.EOF = &EOF{
			ConditionCode: c[0] >> 4,
			Checksum:      uint32(beUint(c[1:5])),
			FileSize:      beUint(c[5 : 5+osz]),
		}
	case DirFinished:
		if len(c) < 1 {
			return
		}
		p.Finished = &Finished{
			ConditionCode: c[0] >> 4,
			DeliveryCode:  (c[0] >> 2) & 0x01,
			FileStatus:    c[0] & 0x03,
		}
	case DirMetadata:
		parseMetadata(p, c, osz)
	case DirACK:
		if len(c) < 2 {
			return
		}
		p.ACK = &ACK{
			AckedDirective: DirectiveCode(c[0] >> 4),
			ConditionCode:  c[1] >> 4,
			TxnStatus:      c[1] & 0x03,
		}
	case DirNAK:
		parseNAK(p, c, osz)
	case DirPrompt:
		if len(c) < 1 {
			return
		}
		p.Prompt = &Prompt{KeepAlive: (c[0]>>7)&0x01 == 1}
	case DirKeepAlive:
		if len(c) < osz {
			return
		}
		p.KeepAlive = &KeepAlive{Progress: beUint(c[:osz])}
	}
}

func parseMetadata(p *PDU, c []byte, osz int) {
	if len(c) < 1+osz {
		return
	}
	m := &Metadata{
		ClosureRequested: (c[0]>>6)&0x01 == 1,
		ChecksumType:     c[0] & 0x0F,
		FileSize:         beUint(c[1 : 1+osz]),
	}
	cur := 1 + osz
	m.SourceFileName, cur = readLV(c, cur)
	m.DestFileName, cur = readLV(c, cur)
	_ = cur
	p.Metadata = m
}

func parseNAK(p *PDU, c []byte, osz int) {
	if len(c) < 2*osz {
		return
	}
	n := &NAK{StartScope: beUint(c[:osz]), EndScope: beUint(c[osz : 2*osz])}
	for cur := 2 * osz; cur+2*osz <= len(c); cur += 2 * osz {
		n.Segments = append(n.Segments, [2]uint64{
			beUint(c[cur : cur+osz]),
			beUint(c[cur+osz : cur+2*osz]),
		})
	}
	p.NAK = n
}

// readLV reads a length-value field (1 length octet + that many value octets) at
// cur, returning the value as a string and the new cursor; on overrun it returns
// what's available
func readLV(b []byte, cur int) (string, int) {
	if cur >= len(b) {
		return "", cur
	}
	n := int(b[cur])
	cur++
	if cur+n > len(b) {
		n = len(b) - cur
	}
	return string(b[cur : cur+n]), cur + n
}

// beUint reads up to 8 big-endian octets as an unsigned integer
func beUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// Summary renders a one-line human description of the PDU
func (p *PDU) Summary() string {
	txn := fmt.Sprintf("%d:%d", p.SourceEntityID, p.TransactionSeqNum)
	if p.Type == FileData {
		return fmt.Sprintf("CFDP FileData txn=%s offset=%d len=%d", txn, p.Offset, p.FileDataLen)
	}
	switch {
	case p.EOF != nil:
		return fmt.Sprintf("CFDP EOF txn=%s size=%d cc=%d", txn, p.EOF.FileSize, p.EOF.ConditionCode)
	case p.Finished != nil:
		return fmt.Sprintf("CFDP Finished txn=%s cc=%d delivery=%d", txn, p.Finished.ConditionCode, p.Finished.DeliveryCode)
	case p.Metadata != nil:
		return fmt.Sprintf("CFDP Metadata txn=%s size=%d src=%q dst=%q", txn, p.Metadata.FileSize, p.Metadata.SourceFileName, p.Metadata.DestFileName)
	case p.NAK != nil:
		return fmt.Sprintf("CFDP NAK txn=%s segments=%d", txn, len(p.NAK.Segments))
	default:
		return fmt.Sprintf("CFDP %s txn=%s", p.DirectiveCode, txn)
	}
}
