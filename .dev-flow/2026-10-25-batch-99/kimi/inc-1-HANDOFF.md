# HANDOFF — batch-99 Increment 1 (US-141 / HLR-152) — worktree `s19_app-b99-inc1`

## What was built (all in this worktree; nothing committed; no `s19_app/` file touched)
- `tests/support/__init__.py` + `tests/support/independent_reader.py` — the independent
  reader (`read_s19` / `read_hex` → `Image` with data/header/terminator/s5_count/eof_seen/
  records_after_end/errors), ported from the rw-investigation `common.py`, zero `s19_app`
  imports. HEX honours types 02 (segment base, 16-bit offset wraps mod 64 KiB), 04 (linear
  base), 05 (recorded as `("HEX05", start)`); records after terminator/EOF are counted,
  never parsed, never enter `data`; overlaps resolve last-wins with an error note.
- `tests/fixtures/synth/generate.py` — stdlib-only deterministic generator (fixed seeds,
  no timestamps/host paths). `--out <dir>` writes the corpus; `--check [--corpus <dir>]`
  regenerates, compares byte-for-byte, verifies SHA-256s, reads every S19/HEX with the
  independent reader and compares with the manifest → prints `checked 16 files` (exit 0)
  or the first differing file name (exit 1).
- `tests/fixtures/synth/` corpus — 16 files + `manifest.json` (17 artifacts, 14 445 bytes):
  S1/S2/S3 width edges (0xFFFF/0xFFFFFF), S0 header, S5 counts, S7/S8/S9 non-zero entries,
  S0-only empty image, HEX types 00/01/02/04/05 + 64 KiB-boundary record + segment wrap,
  MAC pair (one address inside, one outside), A2L pair with every PQ-4 pin
  (`a2l_expect` in the manifest: MSB 2-byte symbol `10 11`→4113; RAT_FUNC COEFFS
  `0 10 0 0 0 1` raw 300↔phys 30 stored `01 2C`; TAB_INTP step 2.5 over phys 0..62.5 with
  grid 5.0→raw 2 and off-grid 3.4→nearest raw 1/written 2.5, refused ±(−50/500); TAB_NOINTP
  10.0/15.0/20.0 with typed 13.0 refused naming 10.0 and 15.0; LINEAR_MUL_2 PHYS=2·RAW with
  explicit `BYTE_ORDER LSB_FIRST`, encode 30→`0F 00`), and 6 defect files (S19 no
  terminator / wrong S5 / data after terminator; HEX no EOF / data after EOF; S19 overlap
  with differing bytes, manifest records last-wins).
- `tests/test_b99_corpus.py` — TC-B99-01 (two `--out` runs byte-identical), TC-B99-02
  (all 25 required classes present, 6 defects), TC-B99-03 (AST census 0 `s19_app` imports +
  14 S19/HEX files byte-exact vs manifest incl. header/terminator/s5/eof/records_after_end),
  AT-B99-01 (`--check` exit 0 + `checked N files`; tampered copy → exit 1 naming the file).
- `.gitattributes` — appended `tests/fixtures/synth/** -text` (allowed by the brief).

## Verification (evidence: `.dev-flow/2026-10-25-batch-99/evidence/inc-1/`, hashes in `SHA256SUMS.txt`)
- Worktree import proven: `s19_app.__file__` inside `s19_app-b99-inc1`.
- RED first: `red-initial-collection.txt` (module absent → collection error) and
  `red-no-corpus.txt` (4 failed with tests in place, corpus absent).
- GREEN: `green-full.txt` 4 passed; per-node `green-tc_b99_01/02/03.txt` and
  `green-at_b99_01.txt` 1 passed each; regression `green-address-census.txt` 23 passed.
- C-40 mutations, all KILLED and reverted (restore proven by SHA-256, `baseline-hashes.txt`):
  `mut-LLR-152.1.txt` (timestamp into S0 text → TC-01 RED), `mut-LLR-152.2.txt`
  (`mac.pair` dropped from the manifest → TC-02 RED), `mut-LLR-152.3.txt` (reader copies S0
  payload into `data` → TC-03 RED). NOTE: the first 152.2 attempt SURVIVED because the class
  was tagged on two entries; fixed by making every coverage class single-owner, then re-run
  KILLED (declared in the packet §4).
- Packet filled: `.dev-flow/2026-10-25-batch-99/03-increments/increment-001.md`
  (§4b Independent review left `pending — orchestrator`).

## Open items / notes for the orchestrator
- Nothing blocked. Later increments consume: `tests.support.independent_reader`
  (`read_s19`/`read_hex`), the corpus paths, and the manifest's `a2l_expect` block.
- Convention to reuse: HEX type 05 → `terminator == ("HEX05", address)`.
- Do not run the full suite here (orchestrator owns it); affected files only were run.

__KIMI_UNIT_DONE__
Files changed: tests/support/__init__.py, tests/support/independent_reader.py, tests/fixtures/synth/generate.py + 16 corpus files + manifest.json, tests/test_b99_corpus.py, .gitattributes; packet increment-001.md (0 SOURCE files, no s19_app/ edit, no commit).
Tests added: 4 nodes in tests/test_b99_corpus.py (TC-B99-01/02/03, AT-B99-01).
RED/GREEN counts: RED 2 baseline transcripts + 3 mutation transcripts (4+4 nodes failing); GREEN 4 passed (test_b99_corpus.py) + 23 passed (test_address_census.py).
Mutations run: 3 C-40 mutations (LLR-152.1 timestamp, LLR-152.2 dropped class, LLR-152.3 S0-into-data), all KILLED, all restored with hash proof; one initial surviving mutant caught and fixed (single-owner classes).
Open questions: none — §4b independent review pending orchestrator; a2l_expect assumes LLR-158.3 "nearest raw + flag naming written physical" semantics (ledger-amend if Phase 3 differs).
