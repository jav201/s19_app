# T4c — tooling and oracle-guard rows: new S0.14 (DeepSeek v4-pro)

Appended after `frontB/FB-common.md` and `units2/TA2-common.md`. Tree 2a8ab75f. Source: `TA2b-X-rulings.tsv` KEEP-NEWREQ TOOLING (rows 1-5, 16-41, 51) and the NEEDS-RULING test `tests/test_examples_pilot_gifs.py::test_case_pilot_capture_and_gif` (P-182: "wait for the T4 tooling class rows"); orchestrator decision P-173 (DF-02): one process row per guard class. Precedents for tooling rows in the canon: R-A2L-DEF.63 (generator determinism), R-PASTE.20 … .23.

## Files
- By hand: `REQUIREMENTS.md` only (one new subsection).
- By `apply_recite.py` (`../in/T4c-map.tsv`, 33 ADD rows, 6 files): `tests/test_sync_evidence.py` (all 25 tests), `tests/test_examples_pilot_gifs.py` (1), `tests/test_address_origin.py` (2), `tests/test_b99_corpus.py` (3), `tests/test_report_field_census.py` (1), `tests/test_tui_map_big.py` (1). Docstrings only.
- No product or tool file.

## Rows to write
One block, inserted directly after the line starting `| R-TST-164 |` (end of S0.13, :579), before the empty line that precedes `<a id="s1"></a>`:
```text

#### S0.14 · Test suite: tooling and oracle guards (from the batch-103 trace audit)

| Id | Form | Requirement |
|---|---|---|
| R-TST-200 | U | The system shall keep the visual-evidence tools, the pilot capture of `tests/test_examples_pilot_gifs.py` and the gallery sync of `tools/sync_evidence.py`, to the contract their docstrings and command-line help state. |
| R-TST-201 | U | The system shall keep the address-origin tool `tools/address_origin.py` to the contract its docstrings state. |
| R-TST-202 | When | When the generator `tests/fixtures/synth/generate.py` writes the synthetic corpus, the system shall give the corpus the same bytes on every run, at least one file of each coverage class and the Intel HEX extents its manifest pins. |
| R-TST-203 | If | If a report golden would keep a host path after canonicalisation, or the AT-B77-02 fixture would hold runs of equal length or a gap, then the system shall fail the guard of that oracle. |
```
Ids free at 2a8ab75f. Where each contract is written: `tools/sync_evidence.py:1-90` (the seven guards, the backups, "nothing here deletes") and `:536` (`--dry-run`: "run every guard, write nothing"); `tests/test_examples_pilot_gifs.py:1-17` (an SVG per step and a GIF per case); `tools/address_origin.py:1-40`, `:99-110`, `:151-162`; `tests/fixtures/synth/generate.py:1-22`; the guards of R-TST-203 are `tests/conftest.py:1290-1327` (A-16) and `tests/test_tui_map_big.py:1245` (AT-B77-02 fixture).

## Steps (append to `../REPORT.md` after each)
1. Header; tool regression (19 passed); N0; reverse_trace before.
2. The block into `REQUIREMENTS.md`; lint the 4 rows (`bad: 0`); `grep -c '^#### S0\.14 '` = 1 and it sits before `## S1 `.
3. Script dry run, then `--apply` -> `ADD rows: 33 (applied=33, already=0)`, 6 files.
4. Run: `tests/test_sync_evidence.py` (`-n 4`), the 2 + 3 + 1 + 1 single nodes, and ONE pilot node `tests/test_examples_pilot_gifs.py::test_case_pilot_capture_and_gif[case_01_basic_valid]` (`@slow`; if it skips for a missing image, use `[case_02_gaps_and_patch_targets]`; record which). All GREEN. The pilot node writes under the git-ignored `tests/_artifacts/`; `git status --short` must list only the 7 edited files.
5. Negative controls (own copy each):
   - R-TST-200: `tools/sync_evidence.py:115` -> `NON_EVIDENCE_NAMES = frozenset()` -> `test_desktop_ini_is_never_counted_as_evidence` RED.
   - R-TST-201: `tools/address_origin.py:110` -> `        return f"{what} in {self.file}"` -> `test_evidence_is_a_location_a_reader_can_open` RED.
   - R-TST-202: `tests/fixtures/synth/generate.py:45` -> `    rng = random.Random()` -> `test_tc_b99_01_deterministic` RED.
   - R-TST-203: `tests/conftest.py:1317` -> `    for pattern in ():` -> `test_a16_canonicaliser_residue_guard_can_actually_fire` RED (`DID NOT RAISE`).
6. After: N0 unchanged; reverse_trace after: `X 236`, `U 1`; none of the 33 tests in class X or U. End per TA2-common.

## For the checker
Laws on the unit tree: no new RED (R-DOC-CANON.6: S0.14 rows still under S0). Planted control: on a copy rename `R-TST-203` to `R-TST-164` -> `test_canon_row_ids_are_unique` RED naming it. Diff: 1 block and 33 `Traces:` lines only.
