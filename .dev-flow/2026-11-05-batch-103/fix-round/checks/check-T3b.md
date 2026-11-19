# CHECK T3b — mechanical check

- Unit: T3b
- Tree path: ~/work/zq-ta/T3b/repo
- HEAD sha: 03d3594bcb49c3149bdeb210362a61fba9a55523
- Start time: Thu Nov 19 04:05:54 PM CST 2026

## Step 1 — Diff hygiene
- Command: `cp -a ~/work/zq-ta/T3b/repo ~/work/zq-ta/chk-T3b`; in the copy `git diff > ../chk-T3b.diff`.
- Files changed (4, all within the brief's allowed set — REQUIREMENTS.md by hand + 3 test files by apply_recite, no product file):
  - `REQUIREMENTS.md`
  - `tests/test_b101_designer_recompute.py`
  - `tests/test_tui_diff_screen.py`
  - `tests/test_tui_directionb.py`
- CR count: `tr -cd '\r' < ../chk-T3b.diff | wc -c` = **0**.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: **0**.
- `def test_` names removed (and not re-added): **none**.
- Diff content: 6 canon row lines + 6 `Traces:` docstring lines (matches brief's "For the checker"). One extra mechanical reflow in `tests/test_b101_designer_recompute.py`: the closing `"""` of the last docstring line was moved to its own line by apply_recite (docstring-only, no AST change); see Step 5 claim re: AST.

## Step 2 — GREEN vs base
- Command (copy ~/work/zq-ta/chk-T3b, env line with `-n 4`): the 6 unit nodes → **6 passed in 31.13s**.
- Base transcript (clone of ~/work/zq-fb/fb.bundle at 03d3594b, clean tree): same 6 nodes → **6 passed in 30.55s**.
- Base-RED nodes: **none** (all 6 nodes were GREEN at base; this unit only writes rows + Traces, no test was RED at base).
- Nodes that passed at base and fail now: **none**.

## Step 3 — Negative controls are real (3 re-applied from REPORT.md)
- Canon-row lint (in copy): `grep -E '^\| (R-DIFF-SCR\.21|...|R-CRC-PREVIEW-001\.14) \|' REQUIREMENTS.md | python -I -B ~/work/zq-ta/T3b/in/lint_rows.py` → 6 `ok` lines, `bad: 0`; each of the 6 ids appears exactly once as a row start (`^| <id> |`).
- NC-1 (R-DIFF-SCR.21): `ab_diff.py:1013` add `disabled=True,` after `classes="diff-run-entry",` → `test_at_b78_16_every_run_reachable_by_mouse` → **RED**: `tests/test_tui_diff_screen.py:1141: AssertionError: the mouse-reachable run set must equal the displayed run set; reached [0]` (`assert {0} == {0, 1, 2, 3, 4, 5, ...}`).
- NC-2 (R-DIFF-SCR.22): `styles.tcss:1599` `width: 1fr;` → `width: 60;` → `test_at_b78_23_no_wrapped_row_in_the_wide_regime` **RED** `tests/test_tui_diff_screen.py:2885: AssertionError` (`assert 55 >= 79`) and `test_at_b78_24_no_hex_row_wraps_in_the_fallback_regime` **RED** `tests/test_tui_diff_screen.py:4115: AssertionError` (`assert 58 >= 79`).
- NC-3 (R-CRC-PREVIEW-001.14): `crc_designer_view.py:1314` `"Cannot compute: "` → `"Cannot preview: "` → `test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named` **RED**: `tests/test_b101_designer_recompute.py:1232: AssertionError` (`'Cannot preview: ...' != 'Cannot compute: ...'`).
- All 3 controls RED → negative controls are real (no MECH-NO-GO here).

## Step 4 — Laws
- Command (copy, `-n 0`): `tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py` → **116 passed, 2 skipped in 492.30s**. Matches expected (116 passed, 2 skipped). No RED.

## Step 5 — Worker claims (5 re-verified)
1. Tool regression `~/work/zq-ta/T3b/in/test_apply_recite.py` = **11 passed** (not 19) → **TRUE** (observed `11 passed in 0.50s`; the 8 `def test_` inside the `TEST_F` string fixture are not collected — matches the worker's deviation).
2. `--collect-only -q tests` N0 = **9827** → **TRUE** (observed `9827 tests collected in 19.01s`).
3. `git diff --stat` = **4 files, +20/-1** → **TRUE** (REQUIREMENTS.md +6, test_b101_designer_recompute.py +5/-1, test_tui_diff_screen.py +8, test_tui_directionb.py +2).
4. reverse_trace after = **X 264, U 1, O 1559** and none of the 6 tests in X/U/O (2 K, 4 K?) → **TRUE** (my run: `tests: 6959 {'O': 1559, 'K?': 624, 'S': 1215, 'K': 3296, 'X': 264, 'U': 1}`; the 6 nodes are 2 K + 4 K? in the matrix).
5. apply_recite left the docstring-stripped AST of each edited test file unchanged → **TRUE** (3/3 files identical by `ast.dump` after stripping docstrings).
- (Deviation re-check) reverse_trace before at HEAD 03d3594b = **K 3294 / K? 620** (worker said so, vs brief's base-at-2a8ab75f K 3293/K? 621) → **TRUE** (my base run: `tests: 6959 {'O': 1560, 'K?': 620, 'S': 1215, 'K': 3294, 'X': 268, 'U': 2}`).

## Step 6 — Diff saved
- `~/work/zq-ta/T3b/CHECK.diff` = copy of step 1's diff (107 lines, CR count 0).

CHECK_DONE T3b MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. Six rows exactly as the brief: R-DIFF-SCR.21 (mouse reach, beside .2), R-DIFF-SCR.22/.23 (no-wrap in both regimes; one-row control rows), R-TUI-029.8 (Workarea Files list height), R-CRC-PREVIEW-001.13/.14 (the coverage CRC error branch: preview text outside the .4 refusal, window line 2). Six `Traces:` lines on the six named tests; `test_at_b78_24` (narrow-regime no-wrap) joins .22 as designed. The closing-quote reflow in `test_b101_designer_recompute.py` is docstring-only (the checker confirmed the AST). R-CRC-DESIGNER-002.5 rejection stands (it is the non-number-field row).
