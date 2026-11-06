# fix13: the two failures of the Inc 13 merge

Merged tree: origin/main `b7acd4b` (Inc 11 + Inc 14) plus the local merge of Inc 13 (`d16f77c`). Both failures reproduced on LAN Linux host 2 before the fix (`2 failed in 101.61s`), both pass after it.

## 1. Address census: `test_at_b83_08_tree_holds_no_assembled_selectors`

- **Cause.** `tests/test_b101_designer_recompute.py` (the `_CoverageRun` crc_error node) passed an attribute expression, `crc_designer_view.CrcDesignerPanel`, to `query_one`. The census accepts only a literal, a name or an f-string.
- **Change.** The class is bound to a local name (`panel_cls`) first. No assertion changed.

## 2. `test_r_whelp_24_2_coverage_reads_typed_ranges` (Inc 14)

- **Cause: test side, not a product defect.** The test reuses `_coverage_preview` from `tests/test_crc_designer_view.py`. Inc 13 changed that helper to wait on the recompute count (`wait_designer_recompute`), and the count only advances under the `designer_recompute_counter` fixture, which `test_crc_designer_view.py` applies module-wide with `pytestmark`. The Inc 14 module did not request the fixture, so the count stayed 0 and the wait timed out (`count 0 (snapshot 0), pending None`: no recompute pending, so the debounced recompute had run; only the counter was absent).
- **Change.** The test requests the fixture (`@pytest.mark.usefixtures("designer_recompute_counter")`, fixture imported by name as in the other Inc 13 modules). Its assertions on the typed-range CRC (`zlib.crc32(b"12345678")` present, the whole-image CRC absent) are unchanged.

## 3. Inc 13 to Inc 14 interface update (graph-inc14 I-14)

- **README `### CRC Designer`** said the verdict "recomputes on every keystroke" (the base behaviour). It now says it recomputes 150 ms after the last keystroke in a text field, and at once on a toggle or a dropdown (`CRC_RECOMPUTE_S = 0.150`; `on_switch_changed` / `on_select_changed` recompute at once, R-CRC-DESIGNER-001.2.1 / .2.2).
- **Help section `crc_designer`** (`window_help.py`) makes no per-keystroke claim, so it and the pinned copy `tests/support/help_copy_i14.py` are unchanged.
- **No README test pins that sentence.** R-DOC-README.4 covers windows, keys, commands and files, not recompute timing, so its 11 stale phrases stay as they are.
- **Records.** The I-14 row of `inc-14/codewire/graph-inc14.md` now records the rewrite as done.
- **Not changed.** User guide ch12.4 still says "Each edit recomputes over 1.2 MiB and took about 10 s with this image (finding F-23)". That is a dated capture tied to finding F-23 and was outside this fix's scope. Left for the batch-end guide pass.

## Run

LAN Linux host 2, Python 3.11.18, `env -u NO_COLOR`, `-n 8`. Files run: `test_address_census.py`, `test_b101_help_legend_docs.py`, `test_b101_designer_recompute.py`, `test_crc_designer_view.py`, `test_window_usage_help.py`, `test_docs_canon.py`, `test_id_registry.py`, `test_suite_hygiene.py`. Result: **executed, 304 passed, 0 skipped, 0 failed** (183 s), QC-TM 0 bounds under 20 % margin. Output: `fix13-run.txt`. The full suite was not re-run (not-run).
