# Kimi brief — batch-99 Increment 1 · US-141 / HLR-152 · synthetic corpus + independent reader

Read `BRIEF-COMMON.md` in this folder first. Its rules bind this increment.

## Requirement (read these blocks in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-152, LLR-152.1, LLR-152.2 and LLR-152.3 (grep `HLR-152` / `LLR-152.`). AT-B99-01, TC-B99-01..03.

## SOURCE files: 0
This increment is tests and fixtures only. You may create:
- `tests/support/__init__.py` (if missing) and `tests/support/independent_reader.py`;
- `tests/fixtures/synth/generate.py`, `tests/fixtures/synth/manifest.json` and the generated files under `tests/fixtures/synth/`;
- `tests/test_b99_corpus.py`.

Do NOT edit anything under `s19_app/`.

## What to build
1. **Independent reader** (`tests/support/independent_reader.py`): port `mini_s19` and `mini_hex` from `.dev-flow/design/investigation-rw-2026-10-22/common.py`. Read that file by range. It must import NOTHING from `s19_app`. API:
   - `read_s19(path) -> Image`
   - `read_hex(path) -> Image`

   where `Image` holds `data: dict[int,int]` (only S1/S2/S3 or HEX type 00 bytes), `header: bytes|None` (S0 payload), `terminator: tuple[str,int]|None` (S7/S8/S9 type and address), `s5_count: int|None`, `eof_seen: bool`, `records_after_end: int`, `errors: list[str]`.
   - HEX: honour types 02 (segment base, **wrapping the 16-bit offset mod 64 KiB**) and 04 (linear base); record 05 as the start address.
   - S19: record S5/S6 counts.
   - A record after the terminator / EOF counts in `records_after_end`, and its bytes are NOT added to `data`.
2. **Generator** (`tests/fixtures/synth/generate.py`): stdlib only, deterministic (fixed seeds, no timestamps, no host paths). It writes the corpus files plus `manifest.json`:
   `{"files": [{"name", "format", "class": [...], "sha256", "data": {"0xADDR": "HEXBYTES", ...} as contiguous runs, "verdict": "ok" | "defect:<kind>", "header": ..., "terminator": ...}]}`.

   Command line:
   - `python tests/fixtures/synth/generate.py --out <dir>` writes the corpus;
   - `python tests/fixtures/synth/generate.py --check` regenerates into a temp dir, compares with the committed files byte for byte, then reads every committed file with the independent reader and compares with the manifest. It prints `checked N files` and exits 0, or prints the first differing file name and exits 1.
3. **Coverage classes** (LLR-152.2), at least one file each:
   - S19 S1-only, S2, S3 data, an S0 header, an S5 count, terminators S7/S8/S9 with a NON-ZERO entry point, and an S0-only file (0 data bytes);
   - HEX with types 00/01/02/04/05, including a record ending exactly at a 64 KiB boundary;
   - a MAC paired to an S19: copy the MAC grammar from `examples/case_01_basic_valid/*.mac` (read it). One MAC address inside the image, one outside;
   - an A2L paired to an S19. Copy the structure from `examples/case_03_overlapping_records/*.a2l` (read by range). It needs: `MOD_COMMON BYTE_ORDER MSB_FIRST`, a 2-byte CHARACTERISTIC with a RECORD_LAYOUT of `UWORD`, a RAT_FUNC COMPU_METHOD equivalent to `RAT_FUNC_DIV_10` (INT = 10·PHYS, i.e. COEFFS `0 10 0 0 0 1` per ASAM, so raw 300 ↔ phys 30), a COMPU_TAB `TAB_INTP` and a `TAB_NOINTP` symbol, and a LINEAR control (`LINEAR_MUL_2`). The S19 must hold raw 300 (`01 2C` big-endian) at the RAT_FUNC symbol's address and `10 11` at the 2-byte symbol. Record the expected physical values in the manifest (`"a2l_expect": {...}`);
   - **PDR condition PQ-4 (binding):** read the PQ-4 row of `.dev-flow/2026-10-25-batch-99/design/PDR-qa.md` (grep `PQ-4`) and satisfy every numbered item in it. It pins the COMPU_TAB table contents and geometry, the tag limits and the byte-order declarations, and records the expected raw and written physical values in `a2l_expect`. Assertions of the form "flags != []" are vacuous at HEAD; the manifest must allow exact-content assertions.
   - defect cases: S19 without a terminator; S19 with a wrong S5; S19 with data after the terminator; HEX without EOF; HEX with data after EOF; S19 overlap with differing bytes.
4. **Tests** (`tests/test_b99_corpus.py`):
   - `test_tc_b99_01_deterministic`: two `--out` runs → identical bytes.
   - `test_tc_b99_02_coverage_classes`: every required class present in the manifest.
   - `test_tc_b99_03_reader_independent_and_exact`: AST census, 0 `s19_app` imports in the reader; every manifest file read → bytes == manifest.
   - `test_at_b99_01_check_mode`: run `generate.py --check` as a subprocess → exit 0 and `checked N files`. Then copy the corpus to a temp dir, flip one byte of one file, run the check pointed at that copy → exit 1 naming that file. Add a `--corpus <dir>` option for this.

   Mutations (C-40): (a) inject a timestamp into the S0 text → TC-01 RED; (b) drop one class from the manifest → TC-02 RED; (c) make the reader copy S0 payload into `data` → TC-03 RED. Revert each one.
5. Commit the generated corpus files (keep them small: total under 200 KB). Mark them binary-safe: S19/HEX are text, but add `tests/fixtures/synth/** -text` to `.gitattributes` so line endings are never converted. That edit is allowed.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-001.md`: the seeded template is already there; fill it. The header's REQ-ID is `HLR-152`.
