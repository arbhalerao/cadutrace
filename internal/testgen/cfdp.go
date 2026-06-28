package testgen

import (
	"encoding/binary"

	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// CFDP PDU byte builders for the sample generator
// They emit the common case: 1-octet entity IDs and sequence number, small-file
// (32-bit) offsets, unacknowledged mode, no CRC, no segment metadata

// cfdpHeader builds the CFDP PDU header for a given body length
func cfdpHeader(pduType uint8, dataFieldLen int, src, tsn, dst uint8) []byte {
	h := make([]byte, 4+1+1+1) // fixed(4) + src(1) + tsn(1) + dst(1)
	// version 0 | type | dir=0 | txmode=1 (unack) | crc=0 | large=0
	h[0] = pduType<<4 | 1<<2
	binary.BigEndian.PutUint16(h[1:3], uint16(dataFieldLen))
	// segctl=0 | entityIDLen-1=0 | segmeta=0 | seqNumLen-1=0
	h[3] = 0
	h[4], h[5], h[6] = src, tsn, dst
	return h
}

// CFDPFileData builds a File Data PDU at the given file offset
func CFDPFileData(src, tsn, dst uint8, offset uint32, data []byte) []byte {
	body := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(body[0:4], offset)
	copy(body[4:], data)
	return append(cfdpHeader(1, len(body), src, tsn, dst), body...)
}

// CFDPEOF builds an End-of-File directive PDU
func CFDPEOF(src, tsn, dst uint8, fileSize, checksum uint32) []byte {
	body := make([]byte, 1+1+4+4) // directive + cc + checksum + filesize
	body[0] = 0x04
	body[1] = 0 // condition code 0 (nominal)
	binary.BigEndian.PutUint32(body[2:6], checksum)
	binary.BigEndian.PutUint32(body[6:10], fileSize)
	return append(cfdpHeader(0, len(body), src, tsn, dst), body...)
}

// CFDPMetadata builds a Metadata directive PDU
func CFDPMetadata(src, tsn, dst uint8, fileSize uint32, srcName, dstName string) []byte {
	body := make([]byte, 0, 1+1+4+2+len(srcName)+len(dstName))
	body = append(body, 0x07) // directive
	body = append(body, 0x00) // reserved/closure/checksum-type
	var fs [4]byte
	binary.BigEndian.PutUint32(fs[:], fileSize)
	body = append(body, fs[:]...)
	body = append(body, byte(len(srcName)))
	body = append(body, srcName...)
	body = append(body, byte(len(dstName)))
	body = append(body, dstName...)
	return append(cfdpHeader(0, len(body), src, tsn, dst), body...)
}

// CFDPFinished builds a Finished directive PDU
func CFDPFinished(src, tsn, dst uint8, conditionCode, deliveryCode, fileStatus uint8) []byte {
	body := []byte{0x05, conditionCode<<4 | (deliveryCode&1)<<2 | (fileStatus & 0x03)}
	return append(cfdpHeader(0, len(body), src, tsn, dst), body...)
}

// CFDPTransaction builds the PDU stream for one file transfer: Metadata, File Data
// over [0, fileSize) in chunks (offsets in skipOffsets omitted to simulate loss),
// EOF, Finished
func CFDPTransaction(src, tsn, dst uint8, fileSize, chunk int, skipOffsets []int) [][]byte {
	skip := make(map[int]bool, len(skipOffsets))
	for _, o := range skipOffsets {
		skip[o] = true
	}
	var pdus [][]byte
	pdus = append(pdus, CFDPMetadata(src, tsn, dst, uint32(fileSize), "src.dat", "dst.dat"))
	for off := 0; off < fileSize; off += chunk {
		n := chunk
		if off+n > fileSize {
			n = fileSize - off
		}
		if skip[off] {
			continue
		}
		data := make([]byte, n)
		for i := range data {
			data[i] = byte((off + i) & 0xFF)
		}
		pdus = append(pdus, CFDPFileData(src, tsn, dst, uint32(off), data))
	}
	pdus = append(pdus, CFDPEOF(src, tsn, dst, uint32(fileSize), 0xCAFEF00D))
	pdus = append(pdus, CFDPFinished(src, tsn, dst, 0, 0, 0))
	return pdus
}

// spacePacketWith wraps an arbitrary payload in a CCSDS space packet
func spacePacketWith(apid ccsdsdefs.APID, seq uint16, payload []byte) []byte {
	p := make([]byte, 6+len(payload))
	p[0] = byte(uint16(apid) >> 8 & 0x07)
	p[1] = byte(uint16(apid))
	p[2] = byte(uint16(ccsdsdefs.SeqUnsegmented)<<6) | byte(seq>>8&0x3F)
	p[3] = byte(seq)
	binary.BigEndian.PutUint16(p[4:6], uint16(len(payload)-1))
	copy(p[6:], payload)
	return p
}

// BuildCFDPStream wraps CFDP PDUs as space packets on one TM VC and returns a
// complete CADU stream, splitting PDUs across frame boundaries
func BuildCFDPStream(scid ccsdsdefs.SCID, vcid ccsdsdefs.VCID, apid ccsdsdefs.APID, pdus [][]byte, frameDataLen int, asm uint32) []byte {
	if asm == 0 {
		asm = ccsdsdefs.ASMStandard
	}
	var asmBytes [asmLen]byte
	binary.BigEndian.PutUint32(asmBytes[:], asm)

	var buf []byte
	var bounds []int
	for i, pdu := range pdus {
		bounds = append(bounds, len(buf))
		buf = append(buf, spacePacketWith(apid, uint16(i), pdu)...)
	}
	if rem := len(buf) % frameDataLen; rem != 0 {
		pad := frameDataLen - rem
		if pad < 7 {
			pad += frameDataLen
		}
		bounds = append(bounds, len(buf))
		buf = append(buf, spacePacket(ccsdsdefs.APIDIdle, 0, pad, 0xCA)...)
	}

	vc := VCConfig{SCID: scid, VCID: vcid, FrameType: ccsdsdefs.TFVNTM}
	frames := packetize(buf, bounds, frameDataLen, ccsdsdefs.TFVNTM, vc, nil)
	var out []byte
	for _, f := range frames {
		out = append(out, asmBytes[:]...)
		out = append(out, f...)
	}
	return out
}
