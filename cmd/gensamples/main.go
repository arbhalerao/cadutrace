package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/arbhalerao/cadutrace/internal/testgen"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
)

// sample records one generated capture for the folder README
type sample struct {
	file, desc, cmd string
	bytes           int64
}

func main() {
	out := flag.String("out", "samples", "output directory for the generated captures")
	sizeStr := flag.String("size", "750MB", "approximate size per capture (e.g. 500MB, 1GB)")
	flag.Parse()

	size, err := parseSize(*sizeStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var samples []sample
	// emit streams a capture to disk via gen, then records it for the README
	emit := func(name, desc, cmd string, gen func(f *os.File) error) {
		path := filepath.Join(*out, name)
		f, err := os.Create(path)
		if err != nil {
			fail(err)
		}
		if err := gen(f); err != nil {
			fail(err)
		}
		fi, err := f.Stat()
		if err != nil {
			fail(err)
		}
		f.Close()
		samples = append(samples, sample{file: name, desc: desc, cmd: cmd, bytes: fi.Size()})
		fmt.Printf("  %-22s %7.1f MB  %s\n", name, float64(fi.Size())/(1<<20), desc)
	}

	fmt.Printf("generating demo captures (~%s each) into %s/…\n", *sizeStr, *out)

	// 1) TM, clean, three VCs, several APIDs - the baseline health report
	emit("tm_clean.cadu", "TM framing, 3 VCs, multiple APIDs, no loss",
		"analyze tm_clean.cadu",
		func(f *os.File) error { return testgen.WriteStream(f, tmMultiVC(0xAB, false), size, 0) })

	// 2) AOS, clean, three VCs (24-bit VC frame counts, M_PDU packet zone)
	emit("aos_clean.cadu", "AOS framing, 3 VCs, multiple APIDs, no loss",
		"analyze aos_clean.cadu",
		func(f *os.File) error { return testgen.WriteStream(f, aosMultiVC(0x5A), size, 0) })

	// 3) TM carrying a CLCW in the Operational Control Field (uplink status)
	clcw := tmMultiVC(0x2C, false)
	clcw.OCF = clcwOCF(0, false, false, true, 0x2A) // retransmit set, report value 0x2A
	emit("tm_clcw.cadu", "TM with a CLCW in the OCF (decoded uplink/command-link status)",
		"analyze tm_clcw.cadu",
		func(f *os.File) error { return testgen.WriteStream(f, clcw, size, 0) })

	// 4) Encapsulation packets (CCSDS 133.1) alongside Space packets
	emit("encap.cadu", "TM: Space packets on VC0, Encapsulation packets (LTP/IP/mission) on VC1",
		"analyze encap.cadu",
		func(f *os.File) error { return testgen.WriteStream(f, encapStream(0x77), size, 0) })

	// 5) Randomized frames - needs --derandomize to decode at all
	emit("randomized.cadu", "TM with CCSDS 131.0 pseudo-randomization applied to every frame",
		"analyze --derandomize randomized.cadu",
		func(f *os.File) error { return testgen.WriteStream(f, tmMultiVC(0x33, true), size, 0) })

	// 6) Large multi-frame packets - reassembly across many frames
	emit("large_packets.cadu", "TM with large packets (8-16 KB) spanning many frames; cross-frame reassembly",
		"analyze large_packets.cadu",
		func(f *os.File) error { return testgen.WriteStream(f, largePackets(0x44), size, 0) })

	// 7) Lossy stream - drop ~2.5% of CADUs for VC gaps and truncation
	emit("lossy.cadu", "TM stream with ~2.5% of CADUs dropped: VC frame gaps, missing packets, truncation",
		"analyze lossy.cadu",
		func(f *os.File) error { return testgen.WriteStream(f, tmMultiVC(0xAB, false), size, 40) })

	// 8) CFDP file transfer, complete
	emit("cfdp_complete.cadu", "CFDP file transfer that arrives complete (no missing ranges)",
		"analyze --cfdp-apid 0x7E1 cfdp_complete.cadu",
		func(f *os.File) error {
			return testgen.WriteCFDPStream(f, 0xAB, 0, 0x7E1, 1, 101, 2, cfdpFileSize(size), cfdpChunk, 1024, nil, 0)
		})

	// 9) CFDP file transfer, incomplete (a contiguous hole plus scattered drops)
	skips := map[int]bool{}
	for i := 200; i < 240; i++ {
		skips[i*cfdpChunk] = true // a contiguous run of missing chunks
	}
	for _, i := range []int{50, 600, 601} {
		skips[i*cfdpChunk] = true // scattered drops
	}
	emit("cfdp_incomplete.cadu", "CFDP file transfer with gaps: reports exact missing byte ranges",
		"analyze --cfdp-apid 0x7E1 cfdp_incomplete.cadu",
		func(f *os.File) error {
			return testgen.WriteCFDPStream(f, 0xAB, 0, 0x7E1, 1, 202, 2, cfdpFileSize(size), cfdpChunk, 1024, skips, 0)
		})

	// 10) Kitchen sink - TM, Space + Encapsulation, CLCW, with some loss
	// the richest single capture for a TUI walkthrough
	mixed := mixedStream(0xC5)
	mixed.OCF = clcwOCF(1, true, false, true, 0x11) // lockout + retransmit set
	emit("mixed.cadu", "TM kitchen sink: Space + Encapsulation packets, CLCW, and dropped CADUs",
		"analyze mixed.cadu  (or: tui mixed.cadu)",
		func(f *os.File) error { return testgen.WriteStream(f, mixed, size, 60) })

	writeReadme(*out, samples)
	fmt.Printf("\nwrote %d captures to %s/\n", len(samples), *out)
}

// stream configurations

const (
	tmFrameData = 1115 // representative TM data-field length
	cfdpChunk   = 1024
)

// cfdpFileSize picks a file size so the resulting capture is ~target bytes (framing/header overhead is a few percent), capped to the CFDP 32-bit field
func cfdpFileSize(target int64) int {
	return int(min(target*97/100, 0xFFFF_FFF0))
}

// NumPackets is ignored by WriteStream (it cycles packets until the size target is
// met); only the VC/APID/length shape matters here

func tmMultiVC(scid ccsdsdefs.SCID, randomize bool) testgen.StreamConfig {
	return testgen.StreamConfig{
		FrameType:    ccsdsdefs.TFVNTM,
		FrameDataLen: tmFrameData,
		Randomize:    randomize,
		VCs: []testgen.VCConfig{
			{SCID: scid, VCID: 0, FrameType: ccsdsdefs.TFVNTM, APIDs: []ccsdsdefs.APID{0x100, 0x101}, PacketLen: 220},
			{SCID: scid, VCID: 1, FrameType: ccsdsdefs.TFVNTM, APIDs: []ccsdsdefs.APID{0x200}, PacketLen: 512},
			{SCID: scid, VCID: 2, FrameType: ccsdsdefs.TFVNTM, APIDs: []ccsdsdefs.APID{0x300, 0x301, 0x302}, PacketLen: 96},
		},
	}
}

func aosMultiVC(scid ccsdsdefs.SCID) testgen.StreamConfig {
	return testgen.StreamConfig{
		FrameType:    ccsdsdefs.TFVNAOS,
		FrameDataLen: 1105, // packet zone (CADU minus AOS headers)
		VCs: []testgen.VCConfig{
			{SCID: scid, VCID: 0, FrameType: ccsdsdefs.TFVNAOS, APIDs: []ccsdsdefs.APID{0x100, 0x101}, PacketLen: 220},
			{SCID: scid, VCID: 1, FrameType: ccsdsdefs.TFVNAOS, APIDs: []ccsdsdefs.APID{0x200}, PacketLen: 512},
			{SCID: scid, VCID: 5, FrameType: ccsdsdefs.TFVNAOS, APIDs: []ccsdsdefs.APID{0x2A0, 0x2A1}, PacketLen: 130},
		},
	}
}

func encapStream(scid ccsdsdefs.SCID) testgen.StreamConfig {
	return testgen.StreamConfig{
		FrameType:    ccsdsdefs.TFVNTM,
		FrameDataLen: tmFrameData,
		VCs: []testgen.VCConfig{
			{SCID: scid, VCID: 0, FrameType: ccsdsdefs.TFVNTM, APIDs: []ccsdsdefs.APID{0x100, 0x101}, PacketLen: 200},
			{SCID: scid, VCID: 1, FrameType: ccsdsdefs.TFVNTM, Encap: true, EncapProtocols: []uint8{1, 2, 6}, PacketLen: 240},
		},
	}
}

func largePackets(scid ccsdsdefs.SCID) testgen.StreamConfig {
	return testgen.StreamConfig{
		FrameType:    ccsdsdefs.TFVNTM,
		FrameDataLen: tmFrameData,
		VCs: []testgen.VCConfig{
			{SCID: scid, VCID: 0, FrameType: ccsdsdefs.TFVNTM, APIDs: []ccsdsdefs.APID{0x400}, PacketLen: 8000},
			{SCID: scid, VCID: 1, FrameType: ccsdsdefs.TFVNTM, APIDs: []ccsdsdefs.APID{0x401}, PacketLen: 16000},
		},
	}
}

func mixedStream(scid ccsdsdefs.SCID) testgen.StreamConfig {
	return testgen.StreamConfig{
		FrameType:    ccsdsdefs.TFVNTM,
		FrameDataLen: tmFrameData,
		VCs: []testgen.VCConfig{
			{SCID: scid, VCID: 0, FrameType: ccsdsdefs.TFVNTM, APIDs: []ccsdsdefs.APID{0x100, 0x101, 0x102}, PacketLen: 256},
			{SCID: scid, VCID: 1, FrameType: ccsdsdefs.TFVNTM, Encap: true, EncapProtocols: []uint8{1, 2, 6}, PacketLen: 300},
			{SCID: scid, VCID: 2, FrameType: ccsdsdefs.TFVNTM, APIDs: []ccsdsdefs.APID{0x300}, PacketLen: 6000}, // multi-frame
		},
	}
}

// helpers

// clcwOCF builds a 4-octet CLCW Operational Control Field (CCSDS 232.0)
func clcwOCF(vcid uint8, lockout, wait, retransmit bool, report uint8) []byte {
	var b2 byte
	if lockout {
		b2 |= 1 << 5
	}
	if wait {
		b2 |= 1 << 4
	}
	if retransmit {
		b2 |= 1 << 3
	}
	// byte0: type=0 (CLCW), version=00, status=000, COP-in-effect=01
	return []byte{0x01, vcid << 2, b2, report}
}

// parseSize parses a human-readable size like "500MB", "1GB", "750mb", or a plain byte count
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "GB"):
		mult, s = 1<<30, strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1<<20, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		mult, s = 1<<10, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(n * float64(mult)), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func writeReadme(dir string, samples []sample) {
	sort.Slice(samples, func(i, j int) bool { return samples[i].file < samples[j].file })
	var b []byte
	add := func(s string) { b = append(b, s...) }
	add("# Demo captures\n\n")
	add("Synthetic CADU streams covering the stream types cadutrace supports.\n")
	add("Regenerate with `make samples` (override size: `go run ./cmd/gensamples -size 1GB`).\n")
	add("These files are git-ignored.\n\n")
	add("Build the binary first: `make build` (then `./bin/cadutrace …`).\n\n")
	add("| File | Demonstrates | Try |\n")
	add("|------|--------------|-----|\n")
	for _, s := range samples {
		add(fmt.Sprintf("| `%s` | %s | `%s` |\n", s.file, s.desc, s.cmd))
	}
	add("\nAll files use the standard sync marker (0x1ACFFC1D) and infer the CADU\n")
	add("length automatically. The TUI works on any of them, e.g. `tui mixed.cadu`.\n")
	_ = os.WriteFile(filepath.Join(dir, "README.md"), b, 0o644)
}
