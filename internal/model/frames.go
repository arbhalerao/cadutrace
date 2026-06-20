package model

import "github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"

// MasterChannelID identifies a master channel
type MasterChannelID struct {
	TFVN ccsdsdefs.TFVN `json:"tfvn"`
	SCID ccsdsdefs.SCID `json:"scid"`
}

// TMFrame is a parsed CCSDS 132.0-B TM transfer frame
// Its accessor methods satisfy decode.TransferFrame and are named to not collide
// with the fields
type TMFrame struct {
	MCID         MasterChannelID
	VCID         ccsdsdefs.VCID
	MCFrameCount uint8
	VCFrameCount uint8
	SecHdrFlag   bool
	SyncFlag     bool
	FHP          uint16 // 11-bit First Header Pointer, relative to DataField
	SecondaryHdr []byte // optional; slice into Raw
	DataField    []byte // slice into Raw
	OCF          []byte // optional 4-octet CLCW; slice into Raw
	HasFECF      bool
	Raw          []byte
}

func (f *TMFrame) TFVN() ccsdsdefs.TFVN           { return f.MCID.TFVN }
func (f *TMFrame) MasterChannel() MasterChannelID { return f.MCID }
func (f *TMFrame) VirtualChannel() ccsdsdefs.VCID { return f.VCID }
func (f *TMFrame) VCCount() uint32                { return uint32(f.VCFrameCount) }
func (f *TMFrame) VCCountModulus() uint32         { return 1 << 8 }
func (f *TMFrame) Data() []byte                   { return f.DataField }
func (f *TMFrame) OperationalControl() []byte     { return f.OCF }

// FirstHeaderPointer is meaningless for VCA data (signalled by the Sync Flag)
func (f *TMFrame) FirstHeaderPointer() (uint16, bool) { return f.FHP, !f.SyncFlag }

// AOSFrame is a parsed CCSDS 732.0-B AOS transfer frame
type AOSFrame struct {
	MCID          MasterChannelID
	VCID          ccsdsdefs.VCID
	VCFrameCount  uint32 // 24-bit
	ReplayFlag    bool
	InsertZone    []byte // optional; slice into Raw
	DataFieldType ccsdsdefs.MPDUType
	FHP           uint16 // 11-bit First Header Pointer (M_PDU only)
	DataField     []byte // packet zone (M_PDU) or raw data field; slice into Raw
	OCF           []byte // optional 4-octet CLCW; slice into Raw
	Raw           []byte
}

func (f *AOSFrame) TFVN() ccsdsdefs.TFVN           { return f.MCID.TFVN }
func (f *AOSFrame) MasterChannel() MasterChannelID { return f.MCID }
func (f *AOSFrame) VirtualChannel() ccsdsdefs.VCID { return f.VCID }
func (f *AOSFrame) VCCount() uint32                { return f.VCFrameCount }
func (f *AOSFrame) VCCountModulus() uint32         { return 1 << 24 }
func (f *AOSFrame) Data() []byte                   { return f.DataField }
func (f *AOSFrame) OperationalControl() []byte     { return f.OCF }

// FirstHeaderPointer is meaningful only for M_PDU data fields
func (f *AOSFrame) FirstHeaderPointer() (uint16, bool) {
	return f.FHP, f.DataFieldType == ccsdsdefs.MPDUTypeMPDU
}
