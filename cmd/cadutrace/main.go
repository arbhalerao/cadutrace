package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arbhalerao/cadutrace/internal/app"
	"github.com/arbhalerao/cadutrace/internal/appdecoder"
	"github.com/arbhalerao/cadutrace/internal/appdecoder/cfdp"
	"github.com/arbhalerao/cadutrace/internal/decode"
	"github.com/arbhalerao/cadutrace/internal/decode/aosframe"
	"github.com/arbhalerao/cadutrace/internal/decode/tmframe"
	"github.com/arbhalerao/cadutrace/internal/framing"
	"github.com/arbhalerao/cadutrace/internal/source"
	"github.com/arbhalerao/cadutrace/internal/store"
	"github.com/arbhalerao/cadutrace/internal/tui"
	"github.com/arbhalerao/cadutrace/pkg/ccsdsdefs"
	"github.com/arbhalerao/cadutrace/pkg/obs"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "analyze":
		if err := runAnalyze(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "tui":
		if err := runTUI(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cadutrace - CCSDS protocol analyzer

Usage:
  cadutrace analyze [flags] <file.cadu>   decode and print a health report
  cadutrace tui     [flags] <file.cadu>   interactive terminal UI

Run "cadutrace <command> -h" for flags.
`)
}

func runTUI(args []string) error {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	var (
		caduLen     = fs.Int("cadu-len", 0, "CADU length in octets (0 = infer from sync markers)")
		rsLen       = fs.Int("rs-len", 0, "trailing Reed-Solomon check symbols to skip per frame")
		derandomize = fs.Bool("derandomize", false, "undo CCSDS 131.0 pseudo-randomization on each frame")
		asmHex      = fs.String("asm", "", "sync marker as hex (default 1ACFFC1D)")
		maxPkt      = fs.Int("max-packet-len", 0, "max reassembled packet length (0 = protocol max)")
		tmFECF      = fs.Bool("tm-fecf", false, "TM frames carry a Frame Error Control Field")
		aosFHEC     = fs.Bool("aos-fhec", false, "AOS frames carry a Frame Header Error Control field")
		aosOCF      = fs.Bool("aos-ocf", false, "AOS frames carry an Operational Control Field")
		aosFECF     = fs.Bool("aos-fecf", false, "AOS frames carry a Frame Error Control Field")
		aosInsert   = fs.Int("aos-insert-zone", 0, "AOS insert zone length in octets")
		cfdpAPIDs   = fs.String("cfdp-apid", "", "comma-separated APIDs carrying CFDP to decode and track")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: cadutrace tui [flags] <file.cadu>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one input file")
	}

	var asm uint32
	if *asmHex != "" {
		v, err := strconv.ParseUint(*asmHex, 16, 32)
		if err != nil {
			return fmt.Errorf("invalid --asm: %w", err)
		}
		asm = uint32(v)
	}
	var apids []ccsdsdefs.APID
	if *cfdpAPIDs != "" {
		var err error
		if apids, err = parseAPIDList(*cfdpAPIDs); err != nil {
			return err
		}
	}

	src, err := source.OpenFile(fs.Arg(0))
	if err != nil {
		return err
	}
	defer src.Close()

	fmt.Fprintf(os.Stderr, "loading %s…\n", fs.Arg(0))
	st, err := store.Load(context.Background(), store.LoadOptions{
		Source:  src,
		Framing: framing.Config{CADULen: *caduLen, ASM: asm, RSLen: *rsLen, Derandomize: *derandomize},
		Frames: decode.Config{
			TM:  tmframe.Config{HasFECF: *tmFECF},
			AOS: aosframe.Config{HasFHEC: *aosFHEC, HasOCF: *aosOCF, HasFECF: *aosFECF, InsertZoneLen: *aosInsert},
		},
		MaxPacketLen: *maxPkt,
		CFDPAPIDs:    apids,
	})
	if err != nil {
		return err
	}
	return tui.Run(st)
}

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	var (
		jsonOut     = fs.Bool("json", false, "emit a JSON report instead of a text health report")
		listPackets = fs.Bool("packets", false, "include the full packet list (with --json)")
		caduLen     = fs.Int("cadu-len", 0, "CADU length in octets (0 = infer from sync markers)")
		rsLen       = fs.Int("rs-len", 0, "trailing Reed-Solomon check symbols to skip per frame")
		derandomize = fs.Bool("derandomize", false, "undo CCSDS 131.0 pseudo-randomization on each frame")
		asmHex      = fs.String("asm", "", "sync marker as hex (default 1ACFFC1D)")
		maxPkt      = fs.Int("max-packet-len", 0, "max reassembled packet length (0 = protocol max)")
		tmFECF      = fs.Bool("tm-fecf", false, "TM frames carry a Frame Error Control Field")
		aosFHEC     = fs.Bool("aos-fhec", false, "AOS frames carry a Frame Header Error Control field")
		aosOCF      = fs.Bool("aos-ocf", false, "AOS frames carry an Operational Control Field")
		aosFECF     = fs.Bool("aos-fecf", false, "AOS frames carry a Frame Error Control Field")
		aosInsert   = fs.Int("aos-insert-zone", 0, "AOS insert zone length in octets")
		logLevel    = fs.String("log-level", "info", "log level: debug|info|warn|error")
		logFormat   = fs.String("log-format", "text", "log format: text|json")
		cfdpAPIDs   = fs.String("cfdp-apid", "", "comma-separated APIDs carrying CFDP (e.g. 0x7E1,2017) to decode and track")
		apidFilter  = fs.String("apid", "", "restrict the --packets list to these APIDs (csv, dec or 0x)")
		vcidFilter  = fs.String("vcid", "", "restrict the --packets list to these VCIDs (csv)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: cadutrace analyze [flags] <file.cadu>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one input file")
	}

	var asm uint32
	if *asmHex != "" {
		v, err := strconv.ParseUint(*asmHex, 16, 32)
		if err != nil {
			return fmt.Errorf("invalid --asm: %w", err)
		}
		asm = uint32(v)
	}

	logger := obs.NewLogger(os.Stderr, obs.ParseLevel(*logLevel), *logFormat)

	var registry *appdecoder.Registry
	if *cfdpAPIDs != "" {
		apids, err := parseAPIDList(*cfdpAPIDs)
		if err != nil {
			return err
		}
		registry = appdecoder.New()
		for _, a := range apids {
			registry.RegisterAPID(a, cfdp.Decoder{})
		}
	}

	src, err := source.OpenFile(fs.Arg(0))
	if err != nil {
		return err
	}
	defer src.Close()

	opts := app.Options{
		Source: src,
		Framing: framing.Config{
			CADULen:     *caduLen,
			ASM:         asm,
			RSLen:       *rsLen,
			Derandomize: *derandomize,
		},
		Frames: decode.Config{
			TM: tmframe.Config{HasFECF: *tmFECF},
			AOS: aosframe.Config{
				HasFHEC:       *aosFHEC,
				HasOCF:        *aosOCF,
				HasFECF:       *aosFECF,
				InsertZoneLen: *aosInsert,
			},
		},
		MaxPacketLen:   *maxPkt,
		CollectPackets: *listPackets,
		Logger:         logger,
		Registry:       registry,
	}

	start := time.Now()
	res, err := app.Run(context.Background(), opts)
	if err != nil {
		return err
	}
	elapsed := time.Since(start)

	if *listPackets && (*apidFilter != "" || *vcidFilter != "") {
		if err := filterPacketList(res, *apidFilter, *vcidFilter); err != nil {
			return err
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	printReport(res, elapsed)
	return nil
}

// filterPacketList restricts res.PacketList to the given APIDs and/or VCIDs
func filterPacketList(res *app.Result, apidCSV, vcidCSV string) error {
	var apids map[ccsdsdefs.APID]bool
	if apidCSV != "" {
		list, err := parseAPIDList(apidCSV)
		if err != nil {
			return err
		}
		apids = make(map[ccsdsdefs.APID]bool, len(list))
		for _, a := range list {
			apids[a] = true
		}
	}
	var vcids map[ccsdsdefs.VCID]bool
	if vcidCSV != "" {
		vcids = make(map[ccsdsdefs.VCID]bool)
		for _, tok := range strings.Split(vcidCSV, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			v, err := strconv.ParseUint(tok, 0, 8)
			if err != nil {
				return fmt.Errorf("invalid VCID %q: %w", tok, err)
			}
			vcids[ccsdsdefs.VCID(v)] = true
		}
	}
	kept := res.PacketList[:0]
	for _, p := range res.PacketList {
		if apids != nil && !apids[p.APID] {
			continue
		}
		if vcids != nil && !vcids[p.VCID] {
			continue
		}
		kept = append(kept, p)
	}
	res.PacketList = kept
	return nil
}

// parseAPIDList parses a comma-separated list of APIDs (decimal or 0x hex)
func parseAPIDList(s string) ([]ccsdsdefs.APID, error) {
	var out []ccsdsdefs.APID
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		v, err := strconv.ParseUint(tok, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid APID %q: %w", tok, err)
		}
		if v > 0x7FF {
			return nil, fmt.Errorf("APID %q out of range (max 0x7FF)", tok)
		}
		out = append(out, ccsdsdefs.APID(v))
	}
	return out, nil
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func printReport(r *app.Result, elapsed time.Duration) {
	st := r.Statistics
	mbps := 0.0
	if elapsed > 0 {
		mbps = float64(r.Bytes) / 1e6 / elapsed.Seconds()
	}

	fmt.Printf("Source:   %s (%d bytes)\n", r.Source, r.Bytes)
	fmt.Printf("CADU len: %d   frame len: %d\n", r.CADULen, r.FrameLen)
	fmt.Printf("Processed in %s (%.1f MB/s)\n\n", elapsed.Round(time.Microsecond), mbps)

	fmt.Println("Frames:")
	fmt.Printf("  total %d  tm %d  aos %d  idle %d  decode-errors %d  bytes %d\n\n",
		st.Frames.Total, st.Frames.TM, st.Frames.AOS, st.Frames.Idle, st.Frames.DecodeErrors, st.Frames.Bytes)

	fmt.Println("Packets:")
	fmt.Printf("  total %d  idle %d  truncated %d  malformed %d\n", st.Packets.Total, st.Packets.Idle, st.Packets.Truncated, st.Packets.Malformed)
	fmt.Printf("  sequence-gaps %d  missing %d  duplicates %d  reorders %d\n\n",
		st.Packets.SequenceGaps, st.Packets.MissingPackets, st.Packets.Duplicates, st.Packets.Reorders)

	fmt.Println("Virtual channels:")
	fmt.Printf("  %-4s %-4s %-4s %8s %6s %6s %6s %6s %10s\n", "SCID", "VCID", "TYPE", "FRAMES", "GAPS", "LOST", "IDLE", "PKTS", "BYTES")
	for _, v := range st.VCs {
		fmt.Printf("  %-4d %-4d %-4s %8d %6d %6d %6d %6d %10d\n",
			v.SCID, v.VCID, v.TFVN, v.Frames, v.FrameGaps, v.FramesLost, v.IdleFrames, v.Packets, v.DataBytes)
	}

	fmt.Println("\nAPIDs:")
	fmt.Printf("  %-7s %8s %8s %5s %5s %7s %5s %5s %5s\n", "APID", "COUNT", "BYTES", "MIN", "MAX", "MEAN", "GAPS", "DUP", "REORD")
	for _, a := range st.APIDs {
		label := fmt.Sprintf("0x%03X", uint16(a.APID))
		if a.Idle {
			label += "*"
		}
		fmt.Printf("  %-7s %8d %8d %5d %5d %7.1f %5d %5d %5d\n",
			label, a.Count, a.Bytes, a.MinLength, a.MaxLength, a.MeanLength, a.SequenceGaps, a.Duplicates, a.Reorders)
	}

	if len(st.Encapsulation) > 0 {
		fmt.Printf("\nEncapsulation packets (CCSDS 133.1): total %d  bytes %d\n",
			st.Packets.Encap, st.Packets.EncapBytes)
		fmt.Printf("  %-4s %-10s %8s %10s\n", "PID", "PROTOCOL", "COUNT", "BYTES")
		for _, en := range st.Encapsulation {
			fmt.Printf("  %-4d %-10s %8d %10d\n", en.ProtocolID, en.Protocol, en.Count, en.Bytes)
		}
	}

	if len(st.CLCW) > 0 {
		fmt.Println("\nCLCW (uplink/command-link status, from the OCF):")
		fmt.Printf("  %-4s %-4s %7s %6s %8s %5s %5s %5s %10s %7s\n",
			"SCID", "VCID", "FRAMES", "RPT-VC", "LOCKOUT", "WAIT", "RETX", "NO-RF", "NO-BITLOCK", "REPORT")
		for _, c := range st.CLCW {
			fmt.Printf("  %-4d %-4d %7d %6d %8s %5s %5s %5s %10s %7d\n",
				c.SCID, c.VCID, c.Frames, c.ReportedVCID,
				yesno(c.Lockout), yesno(c.Wait), yesno(c.Retransmit),
				yesno(c.NoRF), yesno(c.NoBitLock), c.ReportValue)
		}
	}

	if len(st.CFDP) > 0 {
		fmt.Println("\nCFDP transactions:")
		fmt.Printf("  %-12s %-12s %-10s %5s %10s %10s %8s %8s\n",
			"SOURCE", "TXN", "STATE", "DONE", "SIZE", "RECEIVED", "DATAPDU", "MISSING")
		for _, c := range st.CFDP {
			done := "no"
			if c.Complete {
				done = "yes"
			}
			fmt.Printf("  %-12d %-12d %-10s %5s %10d %10d %8d %8d\n",
				c.Source, c.TSN, c.State, done, c.FileSize, c.BytesReceived, c.DataPDUs, len(c.MissingRanges))
			for _, m := range c.MissingRanges {
				fmt.Printf("      missing [%d, %d)\n", m.Start, m.End)
			}
		}
	}

	if len(st.Events) > 0 {
		fmt.Println("\nEvents:")
		for _, e := range st.Events {
			fmt.Printf("  %-20s %-5s %d\n", e.Type, e.Severity, e.Count)
		}
	}
}
