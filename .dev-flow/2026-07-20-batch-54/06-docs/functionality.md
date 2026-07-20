# Functionality — batch-54 (Multi-line A2L header parsing)

## What changed
The A2L parser now correctly reads CHARACTERISTIC headers and AXIS_DESCR bodies whose mandatory parameters span multiple lines with inline `/* */` comments — the real ASAM convention that the bundled demo (and most real-world A2L) uses. Previously the parser required all 7 mandatory params on a single line, so the demo yielded **0 genuine** CHARACTERISTIC header parses (the one apparent hit was a comment token mis-read as a type). It now yields **50/50** CHARACTERISTICs with a populated `char_type`, address, and record-layout.

**How:** a small pipeline — strip comments (a linear, quote-aware scanner that never crashes on malformed input), flatten the body to one token list, then anchor on the first type keyword (`VALUE`/`CURVE`/`MAP`/…) and read the 7 mandatory params from there. The single-line path is a strict subset of this, so it is unchanged. Each AXIS_DESCR now also exposes its `MaxAxisPoints` and whether its axis is external (`AXIS_PTS_REF`) — the two inputs the batch-55 length feature needs.

## What is NOT in this batch
- **Array length** for CURVE/MAP stays unset — that is batch-55 (the inline-axis length summer), which this batch unblocks.
- **Multi-line MEASUREMENT** headers — the demo's are single-line and parse already; deferred (covered by a no-regression check).
- **The a2l.py re-freeze** — the module was temporarily unfrozen (operator-approved) for these sanctioned edits; it is re-added to the engine-guard set in a small post-merge follow-up PR.

## Safety
The comment stripper runs over untrusted file text. It is hardened: linear-time (no quadratic blow-up on a hostile file), never raises on malformed comments/quotes, preserves quoted-string bytes verbatim (no comment-payload leaking into a field), and fails closed to an unparsed header rather than a corrupted one. Newly-populated fields reach the UI only through literal text sinks — no new markup/injection path.
