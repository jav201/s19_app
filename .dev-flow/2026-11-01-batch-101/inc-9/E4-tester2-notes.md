# Inc 9 E4 tester 2 (G-T2) - notes

Node file: `tests/test_b101_flow_names_ui.py`, 10 nodes (10 functions, no parametrisation). Written from `02-test-cases.md`, the graph's I-3 texts and the E3 addenda; no in-progress product diff was read (base `flow_screens.py` / `app.py` were read at `HEAD` only to find control ids and the notice widget).

RED run: base `e07fb00f` (origin/main), LAN Linux host 2 (detached worktree, `s19_app.__file__` printed inside it), one complete run. Command: `env -u NO_COLOR python -m pytest -q -p no:cacheprovider -rfs tests/test_b101_flow_names_ui.py -n 6 --dist loadfile`. Transcript (redacted, grep-checked): `.dev-flow/2026-11-01-batch-101/evidence/inc-9/red-01-tester2-base.txt`. Summary line: **9 failed, 1 passed in 72.05s**. State: `executed` (RED on base). No GREEN run (the implementation is not mine to run; E5 owns it). Remote worktree removed.

Also on the same worktree with my file present: `tests/test_address_census.py` + `tests/test_suite_hygiene.py` = 90 passed (the first attempt turned up the newest-line ratchet `test_r_tst_050`; waits now use `StatusLog.since(mark)`, the painted line is read once afterwards). No `serial_timing` node: no interval is asserted; the confirm dwell is waited on the panel's own clock (`fs._fx_clock() - panel._attention_since > fs.CONFIRM_DWELL_S + 0.1`), not a fixed sleep.

## How the nodes read and drive

- App at 118x54 on `fx_project` (FX nodes) or `flow_project` (Builder nodes), opened through the app's own load; `StatusLog` wraps `set_status` to collect messages; LOCALAPPDATA isolation is the shared conftest; no clipboard.
- Builder: palette chip `#flow_palette_source`, `#flow_ref`, `#flow_add`, `#flow_clear`, `#flow_save` -> the Save dialog (wait for the prefill, then type, `#flow_save_ok`); `load_flow` for Load....
- Flow Execution: `import_lanes` (buttons) or Import... by keys (`enter`, `down`, `tab`, `enter`) in AT-I9-1; mode switch by `enter`; `run_lanes` (Run by `enter` in AT-I9-1); Confirm by `#fx_confirm_1` (cases) or `c` after the dwell (AT-I9-1); Save Set via `#fx_set_name` + `#fx_save`; Load Set via `#fx_set_select` + `#fx_load`.
- Readers: reports from `reports/*-chain-set-report.md` (Mode line, Chains line, ledger Chain cells, markdown `\_` unescaped) and the flow report `reports/*-report.md` minus chain-set reports (first line); saved JSON from `flows/`, `flowsets/`; the status line painted in `#log_line_4` (read after the wait), `#fx_notice`, `#fx_name_strip`, `#flow_result`.
- Link arms: `_link_home` moves an existing home aside and makes `tests/b97_fixtures.make_junction` (symlink on Linux, junction on Windows) to `<tmp>/outside/<home>`.
- AT-I9-2 and AT-I9-3 collect every clause into a `problems` list before asserting, so the RED shows each base reason.

## Cases -> nodes, RED on base

| Case | Node | Base result and the reason |
|---|---|---|
| R-FLOW-CHAIN.19/1 | `test_r_flow_chain_19_1_confirm_writes_one_lane_report` | PASS (standing guard, see below) |
| R-FLOW-CHAIN.20/1 | `test_r_flow_chain_20_1_parallel_confirm_mode_line` | FAIL: re-run report reads `- **Mode:** sequential` |
| R-FLOW-CHAIN.20/2 | `test_r_flow_chain_20_2_sequential_confirm_mode_line` | FAIL: re-run report reads `- **Mode:** sequential` |
| R-FLOW-FILE.12/1 | `test_r_flow_file_12_1_save_after_clear_holds_own_name` | FAIL: `"name"` is `patch_chain`, not `tune_b` |
| R-FLOW-FILE.12/5 | `test_r_flow_file_12_5_lane_report_reads_the_saved_name` | FAIL: `flows/rep_b.json` holds `rep_a` (the report title arm is not reached; AT-I9-2 shows the title `rep\_a` on base) |
| R-FB-SAVE.8/1 | `test_r_fb_save_8_1_refused_home_status` | FAIL: status is the load line, the file landed in the outside folder |
| R-FX-SET.15/1 | `test_r_fx_set_15_1_refused_home_status` | FAIL: status is the load line, the file landed outside |
| AT-I9-1 | `test_at_i9_1_confirm_report_says_confirm_rerun` | FAIL: modes read `['parallel', 'sequential']`, no `confirm re-run` |
| AT-I9-2 | `test_at_i9_2_resaved_flow_and_long_set_keep_own_names` | FAIL, four clauses: name `rep_a`; title `rep\_a`; set name 70 characters; Load Set refused `chain-set name exceeds 64 characters` |
| AT-I9-3 | `test_at_i9_3_linked_homes_refuse_saves` | FAIL, four clauses: both status lines are not the refusals; `x.json` and `s.json` landed outside |

Tests per requirement id: R-FLOW-CHAIN.19 (1), R-FLOW-CHAIN.20 (2), R-FLOW-FILE.12 (/1, /5; /2-/4 are G-T1), R-FB-SAVE.8 (1), R-FX-SET.15 (1), AT-I9-1 .. AT-I9-3. Names are the E1 proposals, none changed. Uncovered by this file (G-T1's or E5's): R-FLOW-FILE.11/13/14, R-FLOW-SET.7-10 service arms, the Windows junction arms (`not_run` until E5), R2-1 home-swap arm (service level).

## Standing guards (pass on base) and why each still has a failure mode

- `test_r_flow_chain_19_1_confirm_writes_one_lane_report`: the case itself says it holds on base (B). It fails if the re-run ever writes zero reports, a report of the whole set (`Chains: 3`) or a ledger without `flash_chain`; AT-I9-1 repeats the `Chains: 1` and ledger clauses and is RED, so the guard is not the only reader.

## Findings for the integrator

1. No production defect found (nothing run against the implementation).
2. The status refusals on base are RED partly because the status line still shows the project-load line; the nodes wait on the action's own sign (a new `set_status` message or a file landing outside), so the base failure is the assertion, not a timeout.
3. AT-I9-2 uses the set-name box with a direct value (70 `S`), not 70 key presses; the dialog and button path are the shipped ones. Say if keystrokes are wanted.
4. 12/5's report-title clause is only exercised on base through AT-I9-2 (12/5 stops at the earlier file-name assertion); on the fixed tree both are exercised in full.
5. Link arms use a symlink on Linux (Windows: junction through `make_junction`); the nodes were not run on Windows.

## Evidence checklist

- [x] Every node named exists in `tests/test_b101_flow_names_ui.py` (10 collected).
- [x] Result from one complete run, command quoted (9 failed, 1 passed).
- [x] RED on base named (`e07fb00f`); the one passing node declared.
- [x] Assertions read painted values, files and reports, not call sequences.
- [x] Uncovered named; Windows arms `not_run`.
- [x] Fixtures synthetic; LOCALAPPDATA isolated; no clipboard; transcript redacted.
- [x] States used: executed, not-run only.
