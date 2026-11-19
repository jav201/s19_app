# CHECK — T4a (mechanical check)

- Unit: T4a
- Tree path: `~/work/zq-ta/T4a/repo`
- HEAD sha: `03d3594bcb49c3149bdeb210362a61fba9a55523`
- Start time: `Thu Nov 19 04:05:28 PM CST 2026`
- Checker brief: `~/work/zq-ta/T4a/CHK-BRIEF.md`
- Base: `b103-fix-round` @ `03d3594b` (bundle `~/work/zq-fb/fb.bundle`)

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-ta/T4a/repo ~/work/zq-ta/chk-T4a` then in the copy `git diff > ../chk-T4a.diff`.

- Files changed (9): `REQUIREMENTS.md`, `tests/test_change_service.py`, `tests/test_checks_engine.py`, `tests/test_compare_service.py`, `tests/test_import_census.py`, `tests/test_render_format.py`, `tests/test_render_hexview.py`, `tests/test_tui_helpers.py`, `tests/test_tui_manifest_save.py`.
  - Allowed by brief: `REQUIREMENTS.md` (by hand) + the 8 test files named under "By `apply_recite.py`". All 9 are within the allowed set. ✓
- CR count: `tr -cd '\r' < ../chk-T4a.diff | wc -c` → `0`. ✓
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: none. ✓
- Removed `def test_` names: none (no added `def test_` either). ✓
- Diff content: 2 REQUIREMENTS.md blocks (R-DOC-DEV.16 after `| R-DOC-DEV.15 |`; R-DOC-ARCH.7-10 after `| R-DOC-ARCH.6 |`) + 11 `Traces:` additions across the 8 test files. No product-code edits, no stray quotes, non-ASCII docstrings intact.

## Step 2 — GREEN vs base

Command (copy `~/work/zq-ta/chk-T4a`, 11 nodes, serial): `<env line> ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q <11 nodes> < /dev/null`
Nodes: the 11 map nodes (test_change_service_module_imports_no_textual, test_no_textual_in_static_import_graph, test_module_imports_no_textual, test_manifest_writer_module_is_headless, test_tc651…, test_tc652…, test_tc653…, test_tc654…, test_tc655…, test_tui_module_has_docstring, test_tui_app_has_docstring).

- Copy (unit's working tree): `11 passed in 14.01s`.
- Base clone (`~/work/zq-ta/chk-T4a-base` @ 03d3594b, clean): `11 passed in 16.06s`.
- Base-RED nodes: none (all 11 were GREEN at base).
- Nodes GREEN at base and RED now: none. ✓

## Step 3 — Negative controls are real

Copy `~/work/zq-ta/chk-T4a-nc` (from the unit tree). Three of the worker's five mutations re-applied; each affected node went RED at the exact reported assertion:

1. R-DOC-ARCH.7 — insert `import textual  # NC` after `s19_app/tui/services/compare_service.py:27`; run `tests/test_compare_service.py::test_module_imports_no_textual`.
   RED: `E       assert not True` … `tests/test_compare_service.py:129: AssertionError` (`1 failed`).
2. R-DOC-ARCH.10 — `s19_app/render/format.py:20` `CYAN = "#7dd3fc"` → `"#7dd3fd"`; run `tests/test_render_format.py::test_tc655_render_format_values_pinned_to_frozen_origins`.
   RED: `E       AssertionError: assert '#7dd3fd' == '#7dd3fc'` … `tests/test_render_format.py:34: AssertionError` (`1 failed`).
3. R-DOC-DEV.16 — delete the class docstring line `s19_app/tui/app/core.py:145`; run `tests/test_tui_helpers.py::test_tui_app_has_docstring`.
   RED: `E       assert None` … `tests/test_tui_helpers.py:381: AssertionError` (`1 failed`).

No control stayed GREEN. Canon-row lint (brief's own check): `grep -E '^\| (…5 ids…) \|' REQUIREMENTS.md` then `python -I -B ../in/lint_rows.py` → `ok` ×5, `bad: 0`; each id `grep -c` = 1; exactly one `#### S0.9 ` and one `#### S0.10 ` heading. ✓

## Step 4 — Laws

Command (serial `-n 0`, copy root): `<env line> ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null`

Result: `116 passed, 2 skipped in 483.04s`. No RED. ✓ (matches the 03d3594b base: 116 passed, 2 skipped)

## Step 5 — Worker claims (re-verified)

1. Tool regression `test_apply_recite.py` → **11 passed** (not 19); staged file holds 11 real `def test_` (raw `grep -c "def test_"` = 20, AST top-level `test_*` FunctionDef = 11) and is byte-identical to the repo copy. **TRUE** (`11 passed in 0.49s`; `diff -q` → IDENTICAL).
2. N0 = **9827 tests collected**. **TRUE** (`9827 tests collected in 19.26s`).
3. `git diff --stat` = **9 files, 44 insertions, 5 deletions**. **TRUE** (matches step 1; 2 REQUIREMENTS.md blocks + 11 `Traces:` lines).
4. Canon lint of the 5 rows → **5 `ok`, `bad: 0`; each id count 1; one S0.9 / one S0.10 heading**. **TRUE** (step 3).
5. reverse_trace after → `tests: 6959 {'K': 3296, 'K?': 629, 'S': 1215, 'O': 1560, 'X': 257, 'U': 2}` (X 268→257, U 2). **TRUE** (re-run reproduced the exact dict; `Control result: PASS - class2 = X`).

(Also: `apply_recite.py` dry-run on the finished tree reports `ADD rows: 11 (applied=0, already=11)` — consistent with the worker's `--apply` of 11 ADD rows; the 11 `Traces:` lines are present in the diff.)

## Step 6 — Saved diff

`git diff` saved to `~/work/zq-ta/T4a/CHECK.diff` (copy of step 1's diff). CR count 0; no home path / user / host / IP.

## Verdict

Steps 1–5 all pass → MECH-GO.

CHECK_DONE T4a MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. Two S0 blocks in the canon's own shape (lead line + table): R-DOC-DEV.16 after R-DOC-DEV.15 (S0.8) and R-DOC-ARCH.7–.10 after R-DOC-ARCH.6 (S0.9); texts verbatim from the brief. Eleven `Traces:` lines over 8 test files map as designed (ARCH.7 x4 incl. the .7+.8 census, ARCH.9+.10 x1, ARCH.10 x4, DEV.16 x2); no assert, import or product change. The rows state what `docs/architecture.md` already declares (CTX-SUBMOD/CTX-IFACE), so they add no new obligation on the product.
