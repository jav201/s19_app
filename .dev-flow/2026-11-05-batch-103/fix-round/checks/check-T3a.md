# CHECK — T3a (mechanical check)

- Unit: T3a
- Tree: ~/work/zq-ta/T3a/repo
- HEAD: 03d3594bcb49c3149bdeb210362a61fba9a55523
- Start: 2026-11-19 16:04:28 CST

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-ta/T3a/repo ~/work/zq-ta/chk-T3a`; in the copy `git diff > ../chk-T3a.diff`.

- Files changed (5, all within the brief's allowed set — REQUIREMENTS.md + 4 test files, no product file):
  - REQUIREMENTS.md
  - tests/test_diff_report_service.py
  - tests/test_flow_report_service.py
  - tests/test_tui_a2l.py
  - tests/test_tui_mac.py
- CR count: 0
- Added skip/skipif/xfail/sleep( lines: none
- Removed `def test_` names (not re-added): none

## Step 2 — GREEN vs base

Node set (the brief's 4 nodes):
`tests/test_tui_mac.py::test_parse_mac_file_emits_summary_log tests/test_tui_a2l.py::test_parse_a2l_file_emits_stage_logs tests/test_diff_report_service.py::test_generation_is_deterministic_fixed_clock tests/test_flow_report_service.py::test_tc001u_composition_is_deterministic`

- Base (clone of fb.bundle at 03d3594b, `~/work/zq-ta/chk-T3a-base`): `4 passed in 0.35s` — all 4 GREEN at base.
- Copy (`~/work/zq-ta/chk-T3a`): `4 passed in 0.38s` — all 4 GREEN now.
- Base-RED nodes and their result now: none (no node in the set was RED at base).
- Nodes GREEN at base but failing now: none.

Verdict for step 2: PASS.

## Step 3 — Negative controls are real

Second copy: `~/work/zq-ta/chk-T3a-nc` (copy of the worker's tree). Re-applied 3 of the worker's REPORT.md mutations, one at a time, running only the affected node.

1. R-MAC-012 — `s19_app/tui/mac.py:156` `rows=%d`→`records=%d`; node `tests/test_tui_mac.py::test_parse_mac_file_emits_summary_log` → RED:
   `E AssertionError: ['MAC parse summary: path=<runner-home>/.../sample.mac records=2 parse_ok=2 diagnostics=0 valid_addresses=2']` (test_tui_mac.py:27)
2. R-A2L-READ.72 — `s19_app/tui/a2l.py:4069` ` tags=%d`→` tag_count=%d`; node `tests/test_tui_a2l.py::test_parse_a2l_file_emits_stage_logs` → RED (second assert):
   `E AssertionError: ['A2L section tree built: path=<runner-home>/.../stage.a2l ...', 'A2L parse stages: path=<runner-home>/.../stage.a2l total_seconds=0.000 tag_extract_seconds=0.000 tag_count=0 measurement=0 characteristic=0 errors=0']` (test_tui_a2l.py:185)
3. R-CMP-004.16 — `s19_app/tui/services/diff_report_service.py:1805` `clock = now_fn if now_fn is not None else _default_now`→`clock = _default_now`; node `tests/test_diff_report_service.py::test_generation_is_deterministic_fixed_clock` → RED:
   `E AssertionError: assert '# Diff repor...' == '# Diff repor...'` (timestamps `:06:29.681690+00:00` vs `:06:29.681311+00:00`, test_diff_report_service.py:311)

All 3 controls went RED (none stayed GREEN). Verdict for step 3: PASS.

## Step 4 — Laws

Command (serial, `-n 0`): the six law files.

Result: `116 passed, 2 skipped in 504.81s` — all GREEN, matching the base count (116 passed, 2 skipped). No RED.

Verdict for step 4: PASS.

## Step 5 — Worker claims (5 re-verified)

1. **TRUE** — Tool regression `test_apply_recite.py` collects `11 passed` (not the brief's "19"). Re-ran: `11 passed in 0.56s`.
2. **TRUE** — Lint of the 5 rows: `ok` ×5, `bad: 0`; each of the 5 ids (`R-MAC-012`, `R-A2L-READ.71`, `R-A2L-READ.72`, `R-CMP-004.16`, `R-FLOW-RPT.15`) appears exactly once as `^| <id> |`.
3. **TRUE** — `--collect-only -q tests` = `9827 tests collected in 20.11s` (N0).
4. **TRUE** — reverse_trace after (`--ta2`): `tests: 6959 {'O': 1560, 'K?': 622, 'S': 1215, 'K': 3296, 'X': 264, 'U': 2}` → X 264, U 2. Matrix classes for the 4 tests: mac→K, a2l→K, diff→K?, flow→K? — none in X or U.
5. **TRUE** — NC-tool: the repo's own `.dev-flow/2026-11-05-batch-103/fix-round/ta/apply_recite.py --apply` on a "before step 4" copy exits **3**: `recite: tests/test_flow_report_service.py: result does not compile: invalid character '—' (U+2014) (test_flow_report_service.py, line 142)`; it wrote nothing (git status shows only REQUIREMENTS.md, test_tui_a2l.py, test_tui_mac.py modified).

All 5 claims TRUE. Verdict for step 5: PASS.

## Step 6 — Diff saved

`CHECK.diff` written (copy of step 1's diff, 7740 bytes, identical to `chk-T3a.diff`).

## Verdict

Steps 1–5 all PASS. MECH-GO.

CHECK_DONE T3a MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. The diff is the brief's, line for line: rows R-MAC-012, R-A2L-READ.71/.72 (S2.6, S2.1), R-CMP-004.16 (S14.7), R-FLOW-RPT.15 (S15.10) each after its anchor; the MAC and A2L log asserts now `fullmatch` the whole line the rows fix (canon rule E5), so a renamed field turns them RED; 4 `Traces:` lines, docstrings only otherwise. Minor (no action): the A2L stages regex pins three decimals (`\d+\.\d{3}`) where R-A2L-READ.72 leaves `<t>` unformatted — the test is stricter than the row, which only costs a re-pin if the precision ever changes.
