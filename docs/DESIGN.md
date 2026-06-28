# Design notes

How cadutrace is put together and why, for when I forget.

It reads a recorded CADU file (a spacecraft downlink) and reports what's in it:
frames, virtual channels, reassembled packets, gaps, CFDP transfers.
Offline only, and it assumes RF/sync/error-correction already happened upstream, so the input is corrected, byte-aligned CADUs.
That assumption keeps everything simple.

## The stack

A capture is a stream of CADUs: each is a sync marker (ASM `0x1ACFFC1D`) + a transfer frame (TM 132.0 or AOS 732.0) + optional Reed-Solomon symbols we skip.
A frame's data field holds space packets (133.0) that can span frames, located by the First Header Pointer.
A packet's payload might be a CFDP PDU (727.0), an Encapsulation packet (133.1), or anything else.

```
CADU -> transfer frame (TM/AOS) -> virtual channel -> space packets -> app decoders
```

## Layout

```
source -> framing -> frame decode -> VC routing -> reassembly -> analysis
```

- `framing` finds ASMs, hands out frames, does optional `--derandomize`.
- `decode/{tmframe,aosframe}` parse the frame types (`decode` picks by version);
  `decode/{spacepacket,encap,clcw,randomizer}` are the small parsers.
- `decode/vc` holds per-(SCID,VCID) state; `decode/reassembly` stitches packets.
- `analysis` (+ `gap`, `cfdptrack`) turns it into counters, events, CFDP tracking.
- `appdecoder` (+ `cfdp`) is the APID-dispatched decoder registry.
- `source` (mmap), `app` (wiring), `store`+`tui` (UI), `testgen` (synthetic data).
- `pkg/*` is the reusable bits: `ccsdsdefs`, `bufpool`, `obs`, `plugin`.

## Reassembly

The one stateful part; everything else is reading fixed headers.
The First Header Pointer says where the first packet header starts in a frame, so the bytes before it finish the packet carried over from the previous frame.
Per VC I keep an optional open packet: continuation bytes finish it (or mark it truncated if a frame went missing), then I parse whole packets forward, and one that runs off the end becomes the new open packet.
Single-frame packets are zero-copy slices into the source; multi-frame ones are assembled in a pooled buffer and copied out once (about one allocation per spanning packet).
Space and Encapsulation packets are told apart by the 3-bit version and share the same walk.

## Who owns the bytes

The whole capture is mmap'd, so almost everything downstream is a slice pointing straight into that one read-only mapping, valid for the entire run and never copied - that's most of why it's fast.
Two places deliberately break the pattern.
A packet that spans frames can't be a slice, so it's gathered in a pooled buffer and copied into an owned slice once it's complete.
And the reassembler returns its results as pointers into a small reusable arena that's only valid until the next call, since the synchronous caller consumes them right away.
The rule I keep in my head: a byte slice is borrowed from the mmap unless it came from reassembling across frames.
Get that backwards and you either copy too much, or alias a buffer that's about to be reused.

## Sequence gaps

Every CCSDS counter wraps - frame counts at 256 or 2^24, packet sequence at 16384 - so "not the next value" isn't enough to call it loss.
I take the signed modular distance to the last value, folded into (-half, +half]: +1 is in order, 0 is a duplicate, more than +1 is a gap (and the distance minus one is how many went missing), and negative means it landed behind the high-water mark, so it's a reorder - unless I've seen it recently, in which case it's a duplicate.
The load-bearing assumption is that real loss is always less than half the counter's range; lose more than half (128 on the 8-bit frame counter) and a gap would masquerade as a reorder, but on a downlink that never happens.
The same code runs for all three counters, just with a different modulus.

## CFDP coverage

A file arrives as a stream of CFDP PDUs - metadata, a pile of file-data chunks at various offsets, an EOF, a finished - and the only thing that really matters is "did the whole file arrive, and if not, which bytes are missing?"
Each data chunk inserts the range `[offset, offset+len)` into a sorted, merge-on-insert interval set; overlaps just merge, and the overlapping bytes are counted as retransmission.
The EOF carries the total size, so the missing ranges are exactly `[0, size)` minus what the set covers, and completeness is "nothing left over."
Because it's set arithmetic, chunks can arrive out of order, duplicated, or overlapping and the answer still comes out right.

## Derandomizing without copying the file

The 131.0 randomizer is a fixed XOR over each frame, but the mmap is read-only so I can't undo it in place - and I don't want to duplicate the whole capture to do it.
So with `--derandomize`, each frame gets its own small copy that's XORed and passed on, while everything else stays zero-copy.
The sync marker is never randomized, so ASM search, length inference, and re-locking all still run on the raw bytes exactly as before.
That's what lets it sit as a pure per-frame payload transform, without the framer having to know anything else changed.
