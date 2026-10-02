# cadutrace
*Trace everything inside a CCSDS CADU*

cadutrace is an offline protocol analyzer for spacecraft telemetry.
You give it a recorded **CADU stream** and it walks the CCSDS stack
(transfer frames (TM/AOS) -> virtual channels -> reassembled space packets -> application decoders),
then prints a health report or opens an interactive terminal UI.

More detail: [`DESIGN.md`](docs/DESIGN.md)

## Build & run

```sh
make build
./bin/cadutrace analyze capture.cadu                      # text health report
./bin/cadutrace analyze --json --packets capture.cadu     # machine-readable report
./bin/cadutrace analyze --cfdp-apid 0x7E1 capture.cadu    # decode + track CFDP
./bin/cadutrace tui capture.cadu                          # interactive terminal UI
```

Settings are detected from the capture: sync marker or bare frames, frame length, randomization, FECF and Reed-Solomon length (the last only when frames carry an FECF).
Any flag you pass is used as given, and the report shows what was detected.
Frames that fail their FECF, or whose channel looks like a one-off false decode, are dropped and counted in the Quality section.

Flags (✓ = available for that command):

| Flag                | analyze |  tui  | Default  | Meaning                                                       |
| ------------------- | :-----: | :---: | -------- | ------------------------------------------------------------- |
| `--json`            |    ✓    |       | off      | emit a JSON report instead of the text report                 |
| `--packets`         |    ✓    |       | off      | include the full packet list (with `--json`)                  |
| `--no-detect`       |    ✓    |   ✓   | off      | use only the given settings; skip auto-detection              |
| `--keep-suspect`    |    ✓    |   ✓   | off      | keep frames from channels that look like false decodes        |
| `--no-asm`          |    ✓    |   ✓   | detected | frames are stored back to back without sync markers           |
| `--frame-len`       |    ✓    |   ✓   | detected | transfer frame length in octets                               |
| `--cadu-len`        |    ✓    |   ✓   | detected | CADU length in octets, including sync marker and RS symbols   |
| `--rs-len`          |    ✓    |   ✓   | detected | trailing Reed-Solomon check symbols to skip per frame         |
| `--derandomize`     |    ✓    |   ✓   | detected | undo CCSDS 131.0 pseudo-randomization on each frame           |
| `--asm`             |    ✓    |   ✓   | 1ACFFC1D | sync marker as hex                                            |
| `--max-packet-len`  |    ✓    |   ✓   | 0        | max reassembled packet length (0 = protocol max)              |
| `--tm-fecf`         |    ✓    |   ✓   | detected | TM frames carry a Frame Error Control Field                   |
| `--aos-fhec`        |    ✓    |   ✓   | off      | AOS frames carry a Frame Header Error Control field           |
| `--aos-ocf`         |    ✓    |   ✓   | off      | AOS frames carry an Operational Control Field                 |
| `--aos-fecf`        |    ✓    |   ✓   | detected | AOS frames carry a Frame Error Control Field                  |
| `--aos-insert-zone` |    ✓    |   ✓   | 0        | AOS insert zone length in octets                              |
| `--cfdp-apid`       |    ✓    |   ✓   | -        | comma-separated APIDs carrying CFDP to decode and track       |
| `--apid`            |    ✓    |       | -        | restrict the `--packets` list to these APIDs (csv, dec or 0x) |
| `--vcid`            |    ✓    |       | -        | restrict the `--packets` list to these VCIDs (csv)            |
| `--log-level`       |    ✓    |       | info     | log level: debug, info, warn, error                           |
| `--log-format`      |    ✓    |       | text     | log format: text, json                                        |

## Try it with sample data

No capture handy? Generate a corpus of synthetic ones, each exercising a different part of the stack:

```sh
make samples
```

This writes the files below to `samples/` (git-ignored) plus a matching `samples/README.md`:

| File                   | What it shows                          | analyze                                          | tui                                          |
| ---------------------- | -------------------------------------- | ------------------------------------------------ | -------------------------------------------- |
| `tm_clean.cadu`        | TM framing, 3 VCs, many APIDs          | `analyze tm_clean.cadu`                          | `tui tm_clean.cadu`                          |
| `aos_clean.cadu`       | AOS framing                            | `analyze aos_clean.cadu`                         | `tui aos_clean.cadu`                         |
| `tm_clcw.cadu`         | CLCW uplink status in the OCF          | `analyze tm_clcw.cadu`                           | `tui tm_clcw.cadu`                           |
| `encap.cadu`           | Encapsulation packets (LTP/IP/mission) | `analyze encap.cadu`                             | `tui encap.cadu`                             |
| `randomized.cadu`      | pseudo-randomized frames               | `analyze randomized.cadu`                        | `tui randomized.cadu`                        |
| `large_packets.cadu`   | packets spanning many frames           | `analyze large_packets.cadu`                     | `tui large_packets.cadu`                     |
| `lossy.cadu`           | dropped CADUs → gaps & truncation      | `analyze lossy.cadu`                             | `tui lossy.cadu`                             |
| `cfdp_complete.cadu`   | a CFDP file that arrives whole         | `analyze --cfdp-apid 0x7E1 cfdp_complete.cadu`   | `tui --cfdp-apid 0x7E1 cfdp_complete.cadu`   |
| `cfdp_incomplete.cadu` | CFDP with exact missing ranges         | `analyze --cfdp-apid 0x7E1 cfdp_incomplete.cadu` | `tui --cfdp-apid 0x7E1 cfdp_incomplete.cadu` |
| `mixed.cadu`           | everything at once (best TUI demo)     | `analyze mixed.cadu`                             | `tui mixed.cadu`                             |

In the TUI: `tab`/`1`-`6` switch panes (Frames, Packets, Inspector, CFDP, Stats, Events), `↑↓`/`jk` move, `enter` inspects a packet, `/` filters the table, `q` quits.

## Develop

```sh
make build    # build ./bin/cadutrace
make samples  # synthesize the demo corpus
make vet      # go vet
go test ./... # tests
make fmt      # gofmt -w
```
