package cfdp

import (
	"fmt"

	"github.com/arbhalerao/cadutrace/internal/model"
	"github.com/arbhalerao/cadutrace/pkg/plugin"
)

// Decoder is the CFDP application decoder; stateless and safe to share
type Decoder struct{}

func (Decoder) Name() string { return "cfdp" }

// CanDecode gates on a minimal size; CFDP is normally routed by APID
func (Decoder) CanDecode(p *model.SpacePacket) bool {
	return len(p.Payload) >= fixedHeaderLen
}

// Decode parses the payload as a CFDP PDU; the result's PDU field carries the
// typed *PDU for the transaction tracker
func (Decoder) Decode(_ plugin.DecodeContext, p *model.SpacePacket) (*plugin.Result, error) {
	pdu, err := Parse(p.Payload)
	if err != nil {
		return nil, err
	}
	res := &plugin.Result{Protocol: "cfdp", Summary: pdu.Summary(), PDU: pdu}

	typ := "FileDirective"
	if pdu.Type == FileData {
		typ = "FileData"
	}
	res.AddField("type", typ, 0, 1)
	res.AddField("direction", pdu.Direction.String(), 0, 1)
	res.AddField("transaction", fmt.Sprintf("%d:%d", pdu.SourceEntityID, pdu.TransactionSeqNum), fixedHeaderLen, pdu.HeaderLen-fixedHeaderLen)

	switch {
	case pdu.Type == FileData:
		res.AddField("offset", fmt.Sprintf("%d", pdu.Offset), pdu.HeaderLen, pdu.offsetSize())
		res.AddField("file_data_len", fmt.Sprintf("%d", pdu.FileDataLen), 0, pdu.FileDataLen)
	case pdu.EOF != nil:
		res.AddField("directive", "EOF", pdu.HeaderLen, 1)
		res.AddField("file_size", fmt.Sprintf("%d", pdu.EOF.FileSize), 0, 0)
		res.AddField("checksum", fmt.Sprintf("0x%08X", pdu.EOF.Checksum), 0, 4)
		res.AddField("condition_code", fmt.Sprintf("%d", pdu.EOF.ConditionCode), 0, 0)
	case pdu.Metadata != nil:
		res.AddField("directive", "Metadata", pdu.HeaderLen, 1)
		res.AddField("file_size", fmt.Sprintf("%d", pdu.Metadata.FileSize), 0, 0)
		res.AddField("source_file", pdu.Metadata.SourceFileName, 0, 0)
		res.AddField("dest_file", pdu.Metadata.DestFileName, 0, 0)
	case pdu.Finished != nil:
		res.AddField("directive", "Finished", pdu.HeaderLen, 1)
		res.AddField("condition_code", fmt.Sprintf("%d", pdu.Finished.ConditionCode), 0, 0)
		res.AddField("delivery_code", fmt.Sprintf("%d", pdu.Finished.DeliveryCode), 0, 0)
	case pdu.NAK != nil:
		res.AddField("directive", "NAK", pdu.HeaderLen, 1)
		res.AddField("segments", fmt.Sprintf("%d", len(pdu.NAK.Segments)), 0, 0)
	default:
		res.AddField("directive", pdu.DirectiveCode.String(), pdu.HeaderLen, 1)
	}
	return res, nil
}
