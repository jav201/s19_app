# REQ-crc — CRC32 region operation

Co-located operation requirements for the **CRC_F2** operation (batch-12, the
first concrete fill-in of the batch-08 operations framework). Per the
operations-module convention, per-operation HLR/LLR live WITH the module;
app-level docs (`REQUIREMENTS.md`, `.dev-flow/2026-06-16-batch-12/`) reference
this file and do **not** inline it.

> Source of truth for the full requirement statements, EARS form, validation
> methods, and traceability is `.dev-flow/2026-06-16-batch-12/01-requirements.md`
> §3 (HLR) / §4 (LLR). This file summarizes the operation-scoped subset and
> records the decisions that bind the engine. It is not a second normative
> copy — where the two differ, the dev-flow requirements doc governs.

## Scope

A parameterized CRC32 over one or more configured memory ranges of a loaded
S19 (incl. S3/32-bit). Two stages (operator FR9):

1. **Check** (US-011, default, non-mutating) — compute per region, read the
   4-byte little-endian value stored at each region's output address,
   compare, report match/mismatch. The file is never modified.
2. **Inject** (US-012, operator-confirmed) — write each computed CRC as
   4-byte little-endian into its output address (extending the image when the
   address lands in a gap), re-emit a modified S19, verify with the
   reader-as-oracle, surface in the report.

**Out of scope:** non-S19 inputs (HEX/MAC as CRC inputs); CLI `ops`
subcommand (TUI-only); device CRC conventions other than the configured
algorithm params; storage codecs other than fixed 4-byte little-endian (a
differing device width/endianness is a NEW requirement — RK-4); work-area
containment of the operator-supplied config FILE (D-7 / RK-5 read posture).

## High-level requirements (operation scope)

| ID | Statement (summary) | Increment |
|----|---------------------|-----------|
| HLR-001 | Parameterized, headless CRC32 compute engine: per region sort ascending (FR2), filter to the region (FR3), reconstruct contiguous segments splitting on any gap (FR4/FR7), digest through one non-resetting CRC state (FR5/FR8), apply final XOR (FR9); no I/O, no parse, no mutation. | I1b |
| HLR-002 | Region check: read the stored 4-byte LE value at each output address, compare to the computed CRC, report per-region match/mismatch — non-mutating. | I2–I4 |
| HLR-003 | Operator-confirmed inject + modified-S19 emit + reader-as-oracle verify; no write without confirmation. | I5 |
| HLR-004 | External JSON config sourcing (resolve + size-cap + parse, collect-don't-abort) + a TUI editable text surface pre-filled with dummy values. | I2–I3 |
| HLR-005 | Neutral `OperationInput` contract + `OperationResult` widened with the per-region CRC payload (framework). | I1a |

## Engine decisions (bind this module)

- **D-4 — default CRC param set:** zlib/PKZIP CRC-32 — polynomial
  `0x04C11DB7`, init `0xFFFFFFFF`, `reverse=true` (refin + refout), xorout
  `0xFFFFFFFF`. With these the engine reproduces `zlib.crc32` exactly (the
  unit-test oracle). All four params are config-driven; `reverse` selects
  standard reflected-in/reflected-out semantics. The default path delegates
  to `zlib.crc32`; non-default params use a bitwise reflected MSB-first loop.
- **D-5 — 4-byte LE codec (FIXED):** the stored/written CRC is always four
  little-endian bytes — byte `i` at `addr+i` = `(crc >> (8*i)) & 0xFF`. NOT
  parameterized. The check read and the inject write are exact inverses. The
  "OPEN params" claim covers the CRC *algorithm* params only, not the storage
  codec (no contradiction).
- **FR7/FR8 — gaps insert no bytes; state does not reset between segments.**
  Implemented as: concatenate the region's contiguous segments into one
  ordered byte stream and digest it with a single CRC call — equivalent to
  threading one non-resetting register across segments, since `crc(s1 + s2)`
  from one init is exactly a non-reset chain and gap addresses contribute no
  bytes.

## I1b engine surface (`crc.py`)

Pure-compute, headless (no Textual import, no file I/O, no `mem_map`
mutation). Region membership reuses the frozen `s19_app.range_index`
primitives (import-only).

| Symbol | Role | LLR | TC |
|--------|------|-----|----|
| `crc32_stream(data, *, polynomial, init, reverse, final_xor)` | Parameterized CRC32 over an ordered byte stream; default == `zlib.crc32`. | LLR-001.1 | TC-101, TC-106 |
| `region_segments(mem_map, start, end)` | Filter to region, sort ascending, split into contiguous segments (no gap bytes). | LLR-001.2 | TC-103, TC-105 |
| `compute_region_crc(mem_map, start, end, *, params)` | One region's CRC via a single non-resetting digest over its concatenated segments. | LLR-001.2 | TC-102, TC-104 |
| `compute_region_crcs(mem_map, regions, *, params)` | Entry point: one CRC per region, config order, no mutation. Returns plain ints (payload wiring is I2). | LLR-001.3 | TC-105, entry-point no-mutation |
| `encode_le32(crc)` / `decode_le32(data)` | Fixed 4-byte LE codec (D-5), exact inverses. | LLR-002.1 / LLR-003.1 | TC-107 |

**Engine tests:** `tests/test_crc_engine.py` (TC-101 KAT anchor through
TC-107 codec round-trip + an entry-point no-mutation assertion).

## Open risks (operation scope)

- **RK-3 — non-default CRC correctness:** a hand-rolled bitwise loop is
  verified to reproduce zlib for the default convention, but a real device's
  *non-zlib* convention needs an operator-sourced reference vector before its
  computed CRC can be trusted. `assumed — verify with operator fixture`.
  TC-106 proves the params are *wired*, not that a non-default result is
  *correct*.
- **RK-4 — endianness/width:** the codec is fixed 4-byte LE; a device storing
  the CRC big-endian or at a different width is a NEW, out-of-scope
  requirement.
- **RK-5 — config/output path security:** the operator config read is
  uncontained-by-design (parity with `read_change_document`), size-capped,
  collect-don't-abort; the inject emit is work-area-contained. security-reviewer
  sign-off is mandatory at I5 before the write path merges.
