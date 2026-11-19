# T3a — GAP rows: MAC and A2L log lines, report determinism

- Unit: T3a
- HEAD: 03d3594bcb49c3149bdeb210362a61fba9a55523
- Start: Thu Nov 19 03:56:42 PM CST 2026
- Common files: frontB/FB-common.md, units2/TA2-common.md
- Unit brief: T3a — GAP rows (BRIEF.md)

## Step 1 — header, tool regression, collect-only, reverse_trace before

- Tool regression `../in/test_apply_recite.py`: **11 passed** (brief said "19 passed"; the file's 19 `def test_` strings include 8 embedded inside the synthetic `TEST_F` fixture, so pytest collects 11 — matches the committed `U1-REPORT.md` "11 passed").
- `--collect-only -q tests`: **9827 tests collected** (N0).
- reverse_trace before: `tests: 6959 {'O': 1560, 'K?': 620, 'S': 1215, 'K': 3294, 'X': 268, 'U': 2}` (vs base at 2a8ab75f `{'K': 3293, 'K?': 621, ...}` — the +1 K / −1 K? is commit 03d3594b's own test edit; see Deviations).


## Step 2 — rows into REQUIREMENTS.md
- Lint `lint_rows.py`: `ok` ×5, `bad: 0`; each id `^| <id> |` count = 1.

## Step 3 — assert edits + log nodes
- `tests/test_tui_mac.py::test_parse_mac_file_emits_summary_log` + `tests/test_tui_a2l.py::test_parse_a2l_file_emits_stage_logs` -> **2 passed**.

## Step 4 — apply_recite.py
- Dry run: `REPLACE 0 / ADD rows: 4 (applied=4, already=0) / NEEDS-RULING 0 / files: 4`.
- `--apply`: `ADD rows: 4 (applied=4, already=0)`; result TSV all `applied` (mac:16, a2l:172, diff:296, flow:127).

## Step 5 — NC-tool (once)
- Repo's own `.dev-flow/2026-11-05-batch-103/fix-round/ta/apply_recite.py --apply` on a "before step 4" copy exits **3**: `recite: tests/test_flow_report_service.py: result does not compile: invalid character '—' (U+2014) (test_flow_report_service.py, line 142)`. It wrote nothing (git status in the copy shows only the step 2/3 files modified). Proves the units2 fix matters.

## Per-row table

| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |
| R-MAC-012 | REQUIREMENTS.md insert; tests/test_tui_mac.py::test_parse_mac_file_emits_summary_log | add canon row + exact fullmatch regex on the whole MAC summary log line | s19_app/tui/mac.py:156 `rows=%d`→`records=%d` | pytest tests/test_tui_mac.py::test_parse_mac_file_emits_summary_log (nc copy) | `E AssertionError: ['MAC parse summary: path=<runner-home>/.../sample.mac records=2 parse_ok=2 diagnostics=0 valid_addresses=2']` | 2 passed (log nodes) | |
| R-A2L-READ.71 | REQUIREMENTS.md insert; tests/test_tui_a2l.py::test_parse_a2l_file_emits_stage_logs | add canon row + `tree_line` fullmatch regex on the whole section-tree log line | s19_app/tui/a2l.py:1065 `lines=%d`→`line_count=%d` | pytest tests/test_tui_a2l.py::test_parse_a2l_file_emits_stage_logs (nc copy) | `E AssertionError: ['A2L section tree built: path=<runner-home>/.../stage.a2l line_count=2 root_sections=1 errors=0', ...]` (first assert, test_tui_a2l.py:184) | 2 passed (log nodes) | |
| R-A2L-READ.72 | REQUIREMENTS.md insert; tests/test_tui_a2l.py::test_parse_a2l_file_emits_stage_logs | add canon row + `stages_line` fullmatch regex on the whole parse-stages log line | s19_app/tui/a2l.py:4069 ` tags=%d`→` tag_count=%d` | pytest tests/test_tui_a2l.py::test_parse_a2l_file_emits_stage_logs (nc copy) | `E AssertionError: ['A2L section tree built: ...', 'A2L parse stages: path=<runner-home>/.../stage.a2l total_seconds=0.000 tag_extract_seconds=0.000 tag_count=0 measurement=0 characteristic=0 errors=0']` (second assert, test_tui_a2l.py:185) | 2 passed (log nodes) | |
| R-CMP-004.16 | REQUIREMENTS.md insert; tests/test_diff_report_service.py::test_generation_is_deterministic_fixed_clock | add canon row + `Traces:` line (script) | s19_app/tui/services/diff_report_service.py:1805 `clock = now_fn if now_fn is not None else _default_now`→`clock = _default_now` | pytest tests/test_diff_report_service.py::test_generation_is_deterministic_fixed_clock (nc copy) | `E AssertionError: assert '# Diff repor...' == '# Diff repor...'` (timestamps `:00:31.774963+00:00` vs `:00:31.774675+00:00`, test_diff_report_service.py:311) | 4 passed (all nodes) | |
| R-FLOW-RPT.15 | REQUIREMENTS.md insert; tests/test_flow_report_service.py::test_tc001u_composition_is_deterministic | add canon row + `Traces:` line (script) | s19_app/tui/services/flow_report_service.py:427 `{generated_at.strftime(REPORT_BODY_TIMESTAMP_FORMAT)}`→`{datetime.now().isoformat()}` | pytest tests/test_flow_report_service.py::test_tc001u_composition_is_deterministic (nc copy) | `E AssertionError: assert '# Flow repor...' == '# Flow repor...'` (timestamps `:00:43.293428` vs `:00:43.293319`, test_flow_report_service.py:129) | 4 passed (all nodes) | |

## Step 6 — negative controls
All five RED under their named one-line product mutation (lines above). Each copy deleted after the run. Product code (`s19_app/`) is unchanged: `git diff --stat s19_app/` is empty.

## Step 7 — after
- 4 nodes GREEN: `4 passed in 0.32s`.
- `--collect-only -q tests`: **9827 tests collected** (N0, unchanged).
- reverse_trace after: `tests: 6959 {'O': 1560, 'K?': 622, 'S': 1215, 'K': 3296, 'X': 264, 'U': 2}` → **X 264** (before 268), **U 2** (unchanged). The 4 tests: mac→K, a2l→K, diff→K?, flow→K? — none in X or U.

## Deviations
- Tool regression count: brief said "19 passed"; the file collects **11 passed** (its 19 `def test_` strings include 8 embedded inside the synthetic `TEST_F` fixture string). Matches the committed `U1-REPORT.md` ("11 passed"), so the brief's "19" is a miscount, not a regression.
- reverse_trace "before" K/K? = 3294/620 vs the 2a8ab75f base 3293/621: HEAD here is 03d3594b (2 commits ahead of 2a8ab75f; commit 03d3594b itself edits tests), so +1 K / −1 K? is expected. X=268 and U=2 match the base exactly; the after-state delta (X 268→264, U stays 2) is unaffected.

## Open questions
- None.

## Final
- `git diff --stat`: 5 files changed, 26 insertions(+), 4 deletions(-).
- CR count (`git diff | grep -c $'\r'`): **0**.
- Final run of unit nodes: `4 passed in 0.32s`; full run of the 4 unit files (test_tui_mac.py, test_tui_a2l.py, test_diff_report_service.py, test_flow_report_service.py): `130 passed in 9.54s`.

UNIT_DONE T3a
