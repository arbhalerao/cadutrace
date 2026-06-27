package tui

import "fmt"

var packetCols = []int{-7, -5, -5, -7, -5, -7, -6, -6}

// packetRow renders packet i as a plain table row (also the filter haystack)
func (m Model) packetRow(i int) string {
	p := m.store.Packet(i)
	flags := ""
	if p.Idle {
		flags += "I"
	}
	if p.Truncated {
		flags += "T"
	}
	// Encapsulation Packets (CCSDS 133.1) carry a protocol, not an APID/seq, so
	// the APID/TYPE/SEQ columns are repurposed to show that
	apid, typ, seq := fmt.Sprintf("0x%03X", uint16(p.APID)), p.Type.String(), fmt.Sprintf("%d", p.SeqCount)
	if p.Kind == "encap" {
		flags += "E"
		apid, typ, seq = "ENCAP", p.Protocol, "-"
	}
	if flags == "" {
		flags = "-"
	}
	return row([]string{
		fmt.Sprintf("%d", i),
		fmt.Sprintf("%d", p.SCID),
		fmt.Sprintf("%d", p.VCID),
		apid,
		typ,
		seq,
		fmt.Sprintf("%d", p.Length),
		flags,
	}, packetCols)
}

// packetFlags exposes the single-character flag columns as searchable words
func (m Model) packetFlags(i int) []string {
	p := m.store.Packet(i)
	var f []string
	if p.Idle {
		f = append(f, "idle")
	}
	if p.Truncated {
		f = append(f, "trunc", "truncated")
	}
	if p.Kind == "encap" {
		f = append(f, "encap", p.Protocol)
	}
	return f
}

func (m Model) viewPackets() string {
	header := row([]string{"INDEX", "SCID", "VCID", "APID", "TYPE", "SEQ", "LEN", "FLAGS"}, packetCols)
	return m.packets.render(header, func(r int) string { return m.packetRow(m.storeRow(r)) })
}
