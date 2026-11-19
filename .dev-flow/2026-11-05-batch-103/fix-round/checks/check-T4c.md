# CHECK T4c — mechanical check

- Unit: T4c
- Tree path: `~/work/zq-ta/T4c/repo`
- HEAD sha: `03d3594bcb49c3149bdeb210362a61fba9a55523`
- Start time: `2026-11-19 16:13:13 CST`
- Checker brief: `~/work/zq-ta/T4c/CHK-BRIEF.md`
- Base: `b103-fix-round` @ `03d3594b` (bundle `~/work/zq-fb/fb.bundle` → `~/work/zq-ta/chk-T4c-base`)

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-ta/T4c/repo ~/work/zq-ta/chk-T4c`, then in the copy `git diff > ../chk-T4c.diff`.

- Files changed (7, all within the brief's "Files you may edit" — `REQUIREMENTS.md` by hand + the 6 test files under "By `apply_recite.py`"):
  - `REQUIREMENTS.md`
  - `tests/test_address_origin.py`
  - `tests/test_b99_corpus.py`
  - `tests/test_examples_pilot_gifs.py`
  - `tests/test_report_field_census.py`
  - `tests/test_sync_evidence.py`
  - `tests/test_tui_map_big.py`
- CR count: `tr -cd '\r' < chk-T4c.diff | wc -c` → **0**.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: **0** (the one `skip` hit is a REQUIREMENTS.md prose line "…learn to skip the gate.").
- `def test_` names removed and not re-added: **none**. Added: **none**.
- Diff content: 1 REQUIREMENTS.md block (4 canon rows R-TST-200…R-TST-203 after `| R-TST-164 |`, before `<a id="s1">`) + 33 `Traces:` docstring lines across the 6 test files. Docstrings only; no product-code edits.

## Step 2 — GREEN vs base

Node set (brief's step 4): `tests/test_sync_evidence.py` (25 tests, `-n 4`) + the 2 + 3 + 1 + 1 single nodes + 1 pilot node (serial).

Copy (`~/work/zq-ta/chk-T4c`, HEAD 03d3594b + unit changes):
- `... pytest -p no:cacheprovider -q -n 4 tests/test_sync_evidence.py` → **25 passed in 1.63s**.
- `... pytest -p no:cacheprovider -q tests/test_address_origin.py::test_kind_of_value_names_assembly_without_proving_operand_types tests/test_address_origin.py::test_evidence_is_a_location_a_reader_can_open tests/test_b99_corpus.py::test_tc_b99_01_deterministic tests/test_b99_corpus.py::test_tc_b99_02_coverage_classes tests/test_b99_corpus.py::test_tc_b99_03b_hex_extents_literal tests/test_report_field_census.py::test_a16_canonicaliser_residue_guard_can_actually_fire tests/test_tui_map_big.py::test_b77_gapless_fixture_is_unequal_and_gapless tests/test_examples_pilot_gifs.py::test_case_pilot_capture_and_gif[case_01_basic_valid]` → **8 passed in 5.94s**.

Base (`~/work/zq-ta/chk-T4c-base`, clean `b103-fix-round` @ 03d3594b, HEAD 03d3594b):
- same `-n 4 tests/test_sync_evidence.py` → **25 passed in 1.75s**.
- same 8 single/pilot nodes → **8 passed in 5.77s**.

- Base-RED nodes: **none** (all 33 nodes GREEN at base).
- Nodes that passed at base and fail now: **none**.

## Step 3 — Negative controls are real

Second copy `~/work/zq-ta/chk-T4c-nc` (fresh `cp -a` from `chk-T4c` per mutation). All 3 go RED:

1. R-TST-200 — `tools/sync_evidence.py:115` `NON_EVIDENCE_NAMES = frozenset({"desktop.ini"})` → `frozenset()`. Node `tests/test_sync_evidence.py::test_desktop_ini_is_never_counted_as_evidence`:
   `E assert 0 == 1` (`assert counts["non_evidence"] == 1`, tests/test_sync_evidence.py:288 AssertionError). RED. ✓
2. R-TST-202 — `tests/fixtures/synth/generate.py:45` `rng = random.Random(seed)` → `random.Random()`. Node `tests/test_b99_corpus.py::test_tc_b99_01_deterministic`:
   `E AssertionError: assert ['manifest.js...seg.hex', ...] == []` (tests/test_b99_corpus.py:102 AssertionError). RED. ✓
3. R-TST-203 — `tests/conftest.py:1317` `for pattern in _HOST_PATH_RESIDUE:` → `for pattern in ():`. Node `tests/test_report_field_census.py::test_a16_canonicaliser_residue_guard_can_actually_fire`:
   `E Failed: DID NOT RAISE <class 'AssertionError'>` (tests/test_report_field_census.py:895 Failed). RED. ✓

No control stayed GREEN.

## Step 4 — Laws (serial, -n 0)

Command: `... pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`

Result: **116 passed, 2 skipped in 420.72s (0:07:00)**. No RED. ✓

## Step 5 — Worker claims (5 re-verified)

1. **Tool regression `../in/test_apply_recite.py` = 11 passed, not 19** — TRUE. `grep -c '^def test_' in/test_apply_recite.py` = 19; `--collect-only` lists 11 (`test_t1_…` … `test_t11_…`); run → `11 passed in 0.50s`. The 8 non-collected `def test_` sit inside the module-level `TEST_F = '''…'''` string literal.
2. **N0 collect-only unchanged = 9827** — TRUE. `--collect-only -q tests` on the copy → `9827 tests collected in 18.80s`.
3. **reverse_trace after = `X 236`, `U 1`** — TRUE. `reverse_trace.py --ta2` on the copy → `tests: 6959 {'O': 1560, 'K?': 625, 'S': 1215, 'K': 3322, 'U': 1, 'X': 236}`.
4. **Lint of the 4 rows = 4× ok, bad: 0** — TRUE. `grep -E '^\| (R-TST-200|…|R-TST-203) \|' REQUIREMENTS.md` + `lint_rows.py` → 4 `ok` lines, `bad: 0`.
5. **`git status --short` = exactly the 7 edited files** — TRUE. 7 entries (`REQUIREMENTS.md` + 6 test files), nothing else; `tests/_artifacts/` git-ignored. Also `grep -c '^#### S0\.14 '` = 1 at line 581, before `## S1 ` (592); each of R-TST-200…203 exactly 1 row-start.

## Step 6 — Save the diff

`cp ~/work/zq-ta/chk-T4c.diff ~/work/zq-ta/T4c/CHECK.diff`.

CHECK_DONE T4c MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. One new subsection S0.14 after R-TST-164 (end of S0.13), four rows verbatim from the brief; 33 `Traces:` lines over 6 files map as designed (R-TST-200 x26: 25 gallery-sync tests + the pilot GIF node; R-TST-201 x2 address-origin; R-TST-202 x3 synthetic corpus; R-TST-203 x2: the A-16 canonicaliser guard and the AT-B77-02 fixture guard). Docstrings only; the removed lines are the old one-line docstrings that gained a `Traces:` line. Minor (no action): R-TST-200/.201 defer their fit criteria to the tools' docstrings and help ("to the contract … state"); acceptable for process rows (precedent R-A2L-DEF.63), and each has a negative control in the worker's report.
