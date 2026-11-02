# Increment 021 — Inc 12a · HLR-176 … HLR-176d / LLR-176.1x, LLR-176.2x / LLR-173.2m / sweep · the progress indicator, the labels and the sweep

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `012a` (corrected at close) |
| Lane | `main` · 2 SOURCE files (`app.py`, `styles.tcss`), of the 4-file cap (corrected at close) |
| Requirement(s) | `HLR-176` · `HLR-176a` · `HLR-176b` · `HLR-176c` · `HLR-176d` · `LLR-176.1`–`LLR-176.1s` and `LLR-176.1t` (E5) · `LLR-176.2`–`LLR-176.2d` · `LLR-173.2m` (restored) · `LLR-172.4e` · `LLR-172.4f` · `LLR-172.5i` · `LLR-172.5j` · `LLR-172.5k` · `LLR-172.6b` · `LLR-172.6c` · `LLR-173.7` (extended) · `LLR-178.2` (extended) |
| Acceptance | `AT-B100-17` (the 12a half: a worker load of a generated 8 MiB-data S19 by keys) · `TC-B100-50` (LLR-176.1 … LLR-176.1t) · `TC-B100-51` (LLR-176.2 … LLR-176.2d) · `TC-B100-41` (LLR-173.2m labels arm) · `TC-B100-66` (extension: the 7 progress labels, 19 step names, 2 token pairs) · `TC-B100-56` (extension: the project and file line as the project load's file state) · `TC-B100-37` / `TC-B100-38` / `TC-B100-39` (the sweep arms) — in `tests/test_b100_busy.py` (NEW, 52 functions / 81 items), `tests/test_b100_load_dialog.py` (3 functions), `tests/test_b100_announce.py` (1 function), `tests/test_b100_recents.py` (11 functions / 27 items), and 15 re-pinned functions (23 items) across `tests/test_report_progress.py`, `tests/test_before_after_report.py`, `tests/test_report_off_ui_thread.py`, `tests/test_tui_report_attribution.py`, `tests/test_b100_session_reset.py`, `tests/test_tui_app.py`, `tests/test_b97_key_bar.py`, `tests/test_tui_diff_screen.py`, `tests/test_tui_patch_history_strip.py`, `tests/test_b100_recents.py` and `tests/test_id_registry.py` |
| Interfaces | consumes `set_progress` / `set_file_status` / `_append_log_line` / `painted_names` / `safe_text` / `recent_kind` / `list_projects` / `_load_workarea_file` / `_TYPED_REFUSAL_TOKENS` / `_handle_load_dialog`; adds the progress seam (`begin_busy` / `step_busy` / `end_busy` / `_busy_tick` / `_busy_line` / `_busy_begin_action` / `_busy_fail`, the `_BUSY_ACTIONS` table, `_BusyRun`), `_listed_project_name`, the one `#status_text.-busy` rule in `styles.tcss`, and the `gen` keyword-only parameter on the 4 workers and the 2 main-thread end sites |
| Agent | design-first experiment (`dev-flow-v3-beta` pipeline): E1 requirements · E2 baseline + prototypes (G-A indicator / G-B labels-and-sweep) · E3 code-free design review (2 rounds: architect + security) · E4 parallel build (1 DeepSeek implementer for G-A+G-B + 1 Opus tester, then 1 Opus integration) · E5 validation (108 mutants on DeepSeek v4 Pro via pi, code + security review on Opus, one corrective pass on Opus, then a round-2 mutant kill pass on Opus) · E13 capture. Models per stage in the step table below |
| Date | `2026-10-31`–`2026-11-01` (E1 start 14:55Z through E5 round 2 02:14Z, all UTC) |
| Base | `051f586` (Inc 11 E4 merged with main); `b100-inc12a` branches from `051f586`, merges `b100-inc11` at `7ac9674` (merge `71376a3`, clean) before E5, takes the corrective pass at `4cedb23`, then merges `main` after Inc 11 closed (`9001431`). Tree at `9012835` plus the close commits at the time of writing |
| Import proof | `s19_app.__file__` printed in every transcript header (the worktree's `s19_app/__init__.py` for GREEN/guards runs, a scratch copy's for RED/mutant runs) |

---

## 1 · What changed

**The feature (HLR-176 … HLR-176d).** A long action now paints one progress line in `#status_text` — a braille spinner, the action's label, `step n/m` with the step's name, and `mm:ss` elapsed — while it runs, and clears it when it ends. The seven long actions (file load, A2L load, project load, Save project, report, diff report, before/after) each get a `_BUSY_ACTIONS` entry; the four that already run on a worker (file load, report, diff report, before/after) animate, while the three main-thread actions (A2L load, project load, Save project) paint their line and clear it within one blocked call (declared, until Inc 12b moves them). The end writes the outcome to the status log and paints the one stored file-state line; the bar clears to 0 of 100.

- **HLR-176 — a long action shows a progress line when it begins.** One progress line per begin (glyph, label, `step n/m` + name, elapsed); the 4 worker actions match the line pattern (4 of 4).
- **HLR-176a — the spinner and the elapsed time advance while a worker runs.** The 8 MiB-data S19 load (P12a-3: 2.38 s of parse) and a synthetic 1.2 s action → ≥ 1 elapsed change and ≥ 5 glyphs. Declared limit: the three main-thread actions freeze between begin and end until Inc 12b.
- **HLR-176b — the bar moves within a step that reports its progress.** `step_busy` carries `done` / `total`; the first shipped reporter is the A2L parse callback at Inc 12b (LLR-176.4).
- **HLR-176c — the end removes the indicator and shows the outcome.** 7 actions × success and failure exits (14 arms) → no glyph, bar cleared, the outcome is the log's last line, 0 timers. The old "three paints in order" is replaced by a precedence: the outcome goes to the status log, `#status_text` takes the one stored file state (Q4, A12a-06).
- **HLR-176d — `#status_text` has one owner while an action runs.** A file-state write during a run is stored, not painted, and painted at the last end (LLR-176.1h, LLR-176.1j).

**The seam (LLR-176.1 … LLR-176.1t, LLR-176.2 … LLR-176.2d).** `begin_busy` / `step_busy` / `end_busy` with a monotonically increasing generation; one 0.1 s timer for the whole app; the clamp (LLR-176.1d), the overlap rules (LLR-176.1n/.1o/.1p) and the unknown/replaced-run rule (LLR-176.1m); main-thread-only writes (LLR-176.1q); scrubbed names through `_busy_begin_action` + `painted_names` + `safe_text` (LLR-176.1r); the cleared bar and the idle row (LLR-176.1k/.1s); the control-byte choke point on every status-log line (LLR-176.1t, SE5-12a-1). The `_BUSY_ACTIONS` table maps the 24 baseline `set_progress` sites to one seam event each (LLR-176.2, LLR-176.2a, LLR-176.2b), ends every action on every success and failure exit (LLR-176.2c), and reports the Save project phases as steps (LLR-176.2d, Inc 11 ruling Q2).

**The labels (LLR-173.2m, restored from 9b ruling Q8).** The key bar and the command palette say `Load` and `Projects` (no more `Load file` / `Load project`); the Workspace button keeps `Load project (p)` (ruling Q6). The 29 pinned SVG snapshot cells that hold `Load file` change, and are regenerated only by the CI workflow after the merge (§6).

**The sweep (LLR-172.4e, LLR-172.4f, LLR-172.5i, LLR-172.5j, LLR-172.5k, LLR-172.6b, LLR-172.6c).** The project-list trailing-dot/space skip loses its `os.name == "nt"` gate (LLR-172.4e); the Workarea Files list keeps loadable suffixes only (LLR-172.4f); a typed path the OS refuses (EACCES / ENAMETOOLONG) is refused with `not found` / `check the path`, with the NUL arms as regression arms (LLR-172.5i); one project-match function returns the exact listed name first (LLR-172.5j, SE5-12a-3); the shared project refusals read one wording table (LLR-172.5k); a pick re-checks the entry (folder, junction, link) inside `go`, after the Inc 10 question, and refuses an over-cap file (LLR-172.6b, LLR-172.6c).

**Corrective pass (E5).** Both round-1 reviews passed with notes; nothing blocked, so no re-review was owed. One corrective pass (Opus) applied SE5-12a-1 (the `_append_log_line` scrub, new LLR-176.1t), SE5-12a-2 (the file-load outcome through `painted_names`; the file-state line backlogged), SE5-12a-3 (the exact listed name first) and CR12a-3 (the two re-pinned report tests renamed), plus MERGE-12a-1 (the Inc 11 arm re-pinned to the keyword-only `gen`). Round 2 (tests only, source unchanged) killed the 13 mutant survivors and added the CR12a-2 AST rule for the Save abort exits. Mutants: 108 run → 86 killed / 22 survived / 0 invalid; 13 survivors killed in round 2, 7 accepted equivalent, 2 Linux-only accepted (M-25, M-48).

**Process decision (operator override 2026-10-31).** Per increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The touched-module run and the full suite are deferred to the batch-end battery (§7). The full new file `tests/test_b100_busy.py` ran once (`green-05-busy-file.txt`).

## 2 · Files modified

Branch history: `b100-inc12a` was branched from `051f586` (Inc 11 E4 merged with main), merged `b100-inc11` at `7ac9674` (merge `71376a3`, clean) before E5, took the corrective pass at `4cedb23`, then merged `main` after Inc 11 closed (`9001431`). The mutation results and the corrective round 2 land at `9012835`.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | HLR-176 … HLR-176d · LLR-176.1 … LLR-176.1t · LLR-176.2 … LLR-176.2d · LLR-173.2m · LLR-172.4e/.4f/.5i/.5j/.5k/.6b/.6c · LLR-173.7 · LLR-178.2 | the progress seam (`begin_busy` / `step_busy` / `end_busy` / `_busy_tick` / `_busy_line` / `_busy_begin_action` / `_busy_fail`, `_BUSY_ACTIONS`, `_BusyRun`, the one `file_state`); the `gen` keyword-only parameter on the 4 workers and the 2 main-thread end sites; `set_file_status` stores-then-paints; `_append_log_line` scrubs through `safe_text` (SE5-12a-1); `load_from_path` / `load_a2l_from_path` / `_handle_load_project` / `_commit_project_save` / the 3 report kickoffs begin and end their run; `_handle_load_error` / `report_failed` / `_finish_generate_report` end it; `BINDINGS` `Load` / `Projects`; `list_projects` drops the platform gate; `refresh_files` filters through `recent_kind`; `_listed_project_name` (NEW) returns the exact listed name first; `_typed_load_route` widens its catch to `(OSError, ValueError, RuntimeError)`; `_load_workarea_file` re-checks the pick inside `go`; the SR-12a-2 `_busy_tick` guard. Final sha256[:16] `15ffc7bdbb599615` |
| `s19_app/tui/styles.tcss` | source | LLR-176.1 (look, Q9) | the one `#workspace_status_bar #status_text.-busy { color: $accent-calm; text-wrap: nowrap; }` rule. Final sha256[:16] `f7b4f75911b296a4` |
| `tests/test_b100_busy.py` | test | HLR-176 … HLR-176d · LLR-176.1 … LLR-176.1t · LLR-176.2 … LLR-176.2d · AT-B100-17 · TC-B100-50/51 | NEW module (52 functions, 81 items; 112 items with the other new arms, then the E5 corrective arms and the round-2 arms) |
| `tests/test_b100_load_dialog.py` | test | LLR-173.2m · LLR-173.7 | 3 functions: the TC-B100-41 labels arm, 2 × TC-B100-66 extension |
| `tests/test_b100_announce.py` | test | LLR-176.1j · LLR-178.2 | 1 function (TC-B100-56 extension) |
| `tests/test_b100_recents.py` | test | LLR-172.4e/.4f/.5i/.5j/.5k/.6b/.6c | 11 functions / 27 items (TC-B100-37/-38/-39 arms), plus the E5 SE5-12a-3 arms |
| `tests/test_report_progress.py` | test | LLR-176.1k | `test_report_generation_drives_progress_bar_then_clears_it` and `test_finish_generate_report_clears_bar` (renamed, CR12a-3; history lines kept) |
| `tests/test_tui_diff_screen.py` | test | LLR-173.2m | `test_at_b78_32_app_bindings_block_is_untouched` re-pinned (D-1: the two missing frozen rows and the binding count 42) |
| `tests/test_id_registry.py` | config | HLR-176 | `EXPECTED_SCANNED_TEST_FILES` 233 → 234 (measured, F-7; the bump names `tests/test_b100_busy.py`) |
| 9 re-pinned test files | test | HLR-176 … HLR-176d · LLR-173.2m | the 15 re-pinned functions (23 items) listed in `inc-12a/E4-tester-notes.md` §3 (census rows A, B, C plus A9); each keeps what it proves, changes only how it reaches the bar or the key bar |
| `AT-TC-REGISTRY.jsonl` | config | HLR-176 · LLR-176.1k | re-pin: TC-644's report-progress node names (the CR12a-3 rename) — 4cedb23 |
| `tests/test_b97_key_bar.py` | test | HLR-176 | re-pin (d7b427d) |
| `tests/test_before_after_report.py` | test | HLR-176 | re-pin (d7b427d) |
| `tests/test_report_off_ui_thread.py` | test | HLR-176 | re-pin (d7b427d) |
| `tests/test_tui_app.py` | test | HLR-176 | re-pin (d7b427d) |
| `tests/test_tui_patch_history_strip.py` | test | HLR-176 | re-pin (d7b427d) |
| `tests/test_tui_report_attribution.py` | test | HLR-176 | re-pin (d7b427d) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-160x40].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-160x40].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[diff-comfortable-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-160x40].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-160x40].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-160x40].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-160x40].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-160x40].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-120x30].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-160x40].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-80x24].svg` | generated | HLR-176 · LLR-173.2m | density snapshot regenerated for the Load / Projects labels — 4dfb5a1 (snapshot-regen run 41290253513) |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-176 … HLR-176d · LLR-176.1x/.2x · LLR-173.2m · LLR-172.x | E1/E3/E5 edits (LED .95–.97) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-176 … HLR-176d · LLR-176.1x/.2x · LLR-173.2m · LLR-172.x | LED .95 – .97 |
| `.dev-flow/BACKLOG-CODE.md` | doc | LLR-176.1r | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-12a/*` | doc | HLR-176 … HLR-176d · LLR-176.1x/.2x | the experiment records: `E1-scope.md`, `E1-rulings.md`, `E1-rulings-proposed.md`, `E2-rulings.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-021.md` | doc | HLR-176 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/*` | generated | HLR-176 | transcripts (evidence digest table at the end of §4) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | HLR-176 | orchestrator-owned: scenario `bz-busy` |

## 3 · How to test

```bash
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
# the new busy module (every node):
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_busy.py
# the re-pinned nodes (targeted):
python -m pytest -q -p no:cacheprovider tests/test_report_progress.py -k "test_report_generation_drives_progress_bar_then_clears_it or test_finish_generate_report_clears_bar"
python -m pytest -q -p no:cacheprovider tests/test_tui_diff_screen.py -k at_b78_32
# guards (the frozen-engine guard, the registry, the staging re-pin):
python -m pytest -q -p no:cacheprovider tests/test_id_registry.py tests/test_b99_staging.py tests/test_engine_unchanged.py tests/test_b100_load_question.py tests/test_b100_load_dialog.py
# mutants: evidence/inc-12a/mutation-summary.md (108 rows) + mut-r2-M-*.txt (the E5 round-2 kills)
# NOT run per increment (operator override 2026-10-31): the touched-module run and the full suite -> batch-end battery (§7)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/`. **Final source hashes** (sha256[:16], verified with `sha256sum` at close): `app.py` `15ffc7bdbb599615` · `styles.tcss` `f7b4f75911b296a4`. Branch history in §2: `b100-inc12a` branched from `051f586`, merged `b100-inc11` at `7ac9674` (merge `71376a3`), corrective pass at `4cedb23`, merged `main` after Inc 11 closed. Import proof in every header; `NO_COLOR` unset.

**Scope (operator override 2026-10-31, stated plainly):** run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The whole touched modules and the full suite are **deferred to the batch-end battery** (with fix rounds for failures found there). The full new file `tests/test_b100_busy.py` ran once (`green-05-busy-file.txt`, on the final source). Three first-run attempts are kept and reported as such: `green-01-new-run1-130arm-notrun.txt` (111 passed, 2 skipped; the 130-character arm is `not-run` under a long basetemp — not counted), `green-01-new-run2-setup-error.txt` (112 errors — **failed, environment**: the new basetemp parent folder did not exist), and `guards-01.txt` (1 failed, F-8 inherited from base and fixed on `b100-inc11`).

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | TC-B100-50/51 + AT-B100-17 (`tests/test_b100_busy.py`), the TC-B100-41 labels arm and the TC-B100-66 extension (`tests/test_b100_load_dialog.py`), the TC-B100-56 extension (`tests/test_b100_announce.py`), the TC-B100-37/-38/-39 arms (`tests/test_b100_recents.py`), and the re-pins (9 files) | `executed` — `green-01-new.txt`: **112 passed, 1 skipped** (371.5 s); `green-02-repinned.txt`: **22 passed** (148.1 s); `guards-01.txt`: **1 failed, 295 passed, 4 skipped** (1533.5 s; the 1 failed is F-8, inherited); `green-03-corrective.txt`: **9 passed, 2 skipped** (25.6 s) + the case-sensitive arm **1 passed** (3.0 s); `green-04-new-and-guards.txt`: **130 passed, 2 skipped** (471.4 s); `green-05-busy-file.txt`: **81 passed, 1 skipped** (338.2 s); `green-06-merge-repin.txt`: **2 passed** (21.2 s); `green-07-final.txt`: **147 passed, 3 skipped** (542.5 s) |
| **B · black-box** `AT-NNN` <-> story | `core` · `full` | AT-B100-17 (the 12a half: a worker load of a generated 8 MiB-data S19 by keys) | `executed`: in `green-01-new.txt` and the round-2 run; RED `red-01-vs-base.txt` fails it on `051f586` (no seam) |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| E4 tester's new tests vs base `051f586` | `red-01-vs-base.txt` | **125 failed, 9 passed, 1 skipped** (595.2 s) — the 9 passes are the declared GREEN-on-base items (the 4 NUL regression arms, the fails-closed `[vanished]` arm, the cap-boundary twin, re-pins A8/A9/B3); the 1 skip is the declared ESC/BEL arm |
| E5 corrective arms on the pre-fix source `71376a3` | `red-03-corrective.txt` | run 1 **3 failed, 2 skipped** (9.5 s) — the bidi outcome, the control-bytes arm and the exact-match unit arm FAIL; the ESC arm and the on-disk case arm skip on Windows. run 2 (case-sensitive folder) **1 failed** (3.4 s) — the on-disk `proj`/`Proj` arm |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| the progress line | `red-01-vs-base.txt`: the 4 first-line arms and AT-B100-17 fail on `051f586` (only `Ready.` / `Loaded … (S19 only)` sampled) |
| the one timer | P12a-2 executed: `set_interval(` occurs 0 times on base; M-31 (drop `timer = None`) killed by the round-2 arm `a_begin_after_the_last_end_starts_one_timer` |
| the scrub | SE5-12a-1 RED on `71376a3`: the control-bytes arm reads ESC+BEL stored and ESC painted; M-69/M-70 killed by the CR12a-2 AST rule and the round-2 abort arm |
| the cleared bar | `red-01-vs-base.txt`: base bar sequences `[10, 50, 100]`, `[15, 55, 100]` instead of `[0, …, 0]`; the re-pinned report node (D-2) |
| the one project match | P12a-4 executed: 2 functions hold the match on base; SE5-12a-3 RED on `71376a3`: `proj` returns `Proj` when both are listed |

### Mutation verdicts (C-40)

**E5 run** (`mutation-summary.md`; every transcript ends `restored = True`): **108 rows total. 86 KILLED, 22 SURVIVED, 0 INVALID, 0 TIMEOUT.**

| Verdict | Mutants | Disposition |
|---|---|---|
| KILLED | 86 | each failure read for a behavioural assertion, not only the return code |
| SURVIVED, routed to round 2 | M-09, M-20, M-28, M-31, M-44, M-69, M-70, M-79, M-82, M-89, M-101, M-102, M-105 | killed by 11 new arms and 2 existing nodes (`mut-r2-M-*.txt`), plus the CR12a-2 AST rule (M-69b) |
| SURVIVED, equivalent | M-08, M-17, M-19, M-36, M-58, M-77, M-86 | recorded, no code change (7) |
| SURVIVED, Linux-only | M-25, M-48 | the `ESC and BEL` arm (S12a-R2-3), accepted not-run here |

**Final count (E5): 86 KILLED at first, 13 survivors KILLED by round 2 (99 killed of 108), 7 equivalent, 2 Linux-only accepted, 0 INVALID, 0 non-equivalent survivors.**

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| the seam | `begin_busy` is called only inside `_busy_begin_action` (1 call site, AST); `set_progress` outside the seam → 0; `#progress_bar` query sites outside `set_progress` / `compose` → 0 (LLR-176.2a) |
| the table | `_BUSY_ACTIONS` holds 7 keys, 19 step names (`3 + 3 + 4 + 4 + 2 + 2 + 1`), 0 decision ids in the labels and step names (SR-12a-1) |
| the labels | the footer holds `^l Load` and 0 `Load file`; the palette holds `Load` and `Projects` and 0 `Load file` / `Load project` (LLR-173.2m) |
| the choke point | every status-log line goes through `safe_text(...).plain` (`_append_log_line`, SE5-12a-1); 0 C0/C1 code points in `log_lines` and the 4 log rows |

### Guards and snapshot cells

| Run | Transcript | Result |
|---|---|---|
| guards (kept) | `guards-01.txt` | **1 failed, 295 passed, 4 skipped** (1533.5 s) — `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` (F-8, the Inc 9b `IfExp` selector in `screens.py`, inherited from base and fixed on `b100-inc11`) |
| the 29 SVG snapshot cells | — | **not-run** (CI-only regen, `.github/workflows/snapshot-regen.yml`, after the merge); expected to drift until then |
| the census sweep (`-k census`) | — | **not run** (operator ruling; batch-end battery) |

### Reviewers' probes

The code reviewer executed `probe1.py` (seam behaviour under a modal, overlap, restart, a stale end: `restart moved last: ['report', 'file_load']`, the last end painted the stored `FS` with the timer `None`) and `probe2.py` (the CR12a-1 raise-after-commit scenario on the merged tree: `log since: ['Project saved + manifest verified', 'Saving project S4 failed']`, `project.json on disk: True`), and the single node `test_tc_b100_51_save_project_reports_its_phases_as_steps` (1 passed). The security reviewer executed `probe_o12a1.py`, `probe_esc_log.py` and the node `test_tc_b100_39_pick_rechecks_the_entry_after_the_question` (1 passed). The full suite and the touched modules were `not-run` in both lanes (out of scope; batch-end battery).

### Security probes

`security-increment-021.md`: SE5-12a-1 (the status log carries an ESC sequence while the progress line and the outcome are clean — MAJOR, fixed by the `_append_log_line` scrub), SE5-12a-2 = O-12a-1 (a bidi control in the file-load outcome — MINOR, fixed; the file-state line backlogged), SE5-12a-3 (the exact listed name — NIT, fixed), SE5-12a-4 (use-time `resolve_input_path` with no guard — NIT, routed to Inc 12b). The E3 mitigations were re-verified: the one label scrub, the timer lifecycle, the pick re-check mechanics, the OS-refused typed paths, the single project match, the one refusal table. Full per-question results in `security-increment-021.md`.

### E13 (C-UX-5) evidence

Orchestrator-owned captures, real Windows Terminal: scenario `bz-busy` (loads CASE01's firmware from `workarea/temp/fw.s19` with the parse step slowed ~60 s, patched in `tools/e13/run.py` only). Painted `#status_text`: `⠴ Loading fw.s19  ·  step 2/3 Parse  ·  00:02` (00:06 in the orchestrator's view), the bar at 33 / 100, log lines `[]`, the key bar `^l Load` and `p Projects`. **3 PNGs** in `evidence/inc-12a/e13/` (`bz-busy.118x54.png`, `bz-busy.220x60.png`, `bz-busy.99x54.png`), `DONE failures=0` (`E13-notes.md`). OBS-12a-1: the bar's built-in ETA readout (`33% 00:00:01`) sits beside the seam's elapsed time — two contradictory times on one row → Inc 12b integration or the batch-end fix round.

### Experiment step table (from `inc-12a/steps.log`; UTC)

| Start | End | Step | Agents | Outcome |
|---|---|---|---|---|
| 14:55 | 15:16 | E1 | 1 x Opus (parallel with 9b E3) | 38 requirements; rulings Q1–Q10 + backlog, all as recommended |
| 15:17 | 15:17 | E1 rulings | orchestrator | Q1–Q10 + backlog dispositions |
| 19:15 | 19:16 | E2 baseline | 1 x Opus | 35 nodes; Q-1 … Q-7, interfaces fixed |
| 19:16 | 19:37 | E2 prototypes | 1 x Opus | G-A 28 nodes / 75 examples, G-B 8 nodes / 37 examples; proposals ruled |
| 19:37 | 20:12 | E3 (2 rounds) | 2 x Opus (architect ∥ security) + 1 design-fix by DeepSeek v4 Pro | r1: arch PWN (0 MAJOR), sec PWN (2 MAJOR); r2: sec PWN (4 NIT); E3 closed, addenda S12a-R2-1 … -4 |
| 23:19 | 23:37 | E4 implementer | 1 x DeepSeek v4 Pro (G-A + G-B in one job) | 3 deviations declared; app `96613abc4e324376`, tcss `f7b4f75911b296a4` |
| 23:19 | 00:08 | E4 tester | 1 x Opus | 67 fn / 112 items new + 15 fn / 23 items re-pinned; RED 125/135 on `051f586`; D-1 … D-8 ruled |
| 00:08 | 00:58 | E4 integration | 1 x Opus (software-dev) | new 112 passed / 1 skip, re-pins 22 passed, guards 295 passed / 1 failed (F-8); app `ed0ee69584332172`; SR-12a-1 … 3 accepted |
| 01:00 | 01:00 | merge | — | merged `b100-inc11` `7ac9674` (merge `71376a3`, clean) |
| 01:00 | 01:56 | E5 | 1 x DeepSeek v4 Pro (mutants 108 rows) ∥ 1 x Opus (code review) ∥ 1 x Opus (security review), then 1 x Opus (corrective) | reviews PWN (CR12a-1 … 3, SE5-12a-1 … 4); 108 mutants 86/22/0; corrective SE5-12a-1 … 3, CR12a-3, MERGE-12a-1; green-05 81 passed / 1 skip; app `15ffc7bdbb599615` |
| 01:32 | 01:32 | merged smoke | — | `green-03-merged.txt`: 254 passed / 2 failed (the Inc 11 arm without `gen`) → MERGE-12a-1 |
| 01:44 | 01:44 | E13 | 1 x DeepSeek v4 Pro + 1 x Opus (visual check) | `bz-busy` 3 PNGs, failures=0; OBS-12a-1 |
| 01:56 | 02:14 | E5 round 2 | 1 x Opus (software-dev) | 13 survivors killed (11 new arms, 2 existing), CR12a-2 AST rule; green-07-final 147 passed / 3 skipped; tests only |

Note (corrected at close): times in this log are local (UTC−6), not UTC; see 05-postmortem.md Record corrections.

First step start to the last logged step: 14:55Z to 02:14Z = about 11 h 19 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 2 MAJOR in round 1 (S12a-01, S12a-02); E5 (code) caught 1 MAJOR (SE5-12a-1), 2 MINOR and 3 NIT; 1 corrective pass + 1 mutant-kill round; 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/` | SHA-256 |
|---|---|---|
| bz-busy.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.118x54.png | f79a91df623013de5bc27eb49cb8a5e03ce19edd39d6c0e12663b4c1f325b132 |
| bz-busy.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.220x60.png | 8f98aa25599a977fb4742fdf97bbb4664811f779c9077d0a2fac4f5e814ef438 |
| bz-busy.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.99x54.png | cd087f51a536c517768bf5c898b7367937e3aeb907e3846105afb85d3bf829e4 |
| bz_busy_headless_probe.py | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz_busy_headless_probe.py | 2c121d7bb2f414bc1f3ba11b08ecb3498a531517070ddea0415c33a8f3b206f1 |
| green-01-new-run1-130arm-notrun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-01-new-run1-130arm-notrun.txt | de6f56a79b0a7bf140fd5f074e9938dc098b8cdd7149b18fe2352ba5feea3f55 |
| green-01-new-run2-setup-error.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-01-new-run2-setup-error.txt | a0b63d29ae160e8a27338a28c157bc7219396f1ff145c6e3d80b6869007db7ba |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-01-new.txt | 7c406f872026a10ffb8f8dad32bca05813a63cb5068ae506c98b780e44425edf |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-02-repinned.txt | 8fb359412b33b2e263a4d7e8b2c56e942bf3408473981311f85d177deff66bfa |
| green-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-03-corrective.txt | ce743bc15559f4c57ef0cf3407c277ec89c6b045b66ef2c66a22a0d7c9f9095b |
| green-03-merged.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-03-merged.txt | a2c21d2bf288374d2380e5a35999fec50449317b09e80ac5c28269737d2c1c89 |
| green-04-new-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-04-new-and-guards.txt | 2e159fd63069e2a856d636c02c5413bfdc939db49fbc4db9ef84d5b83b766bff |
| green-05-busy-file.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-05-busy-file.txt | b7c4a7cc5dea5c9e225029c5a5d2ee0ee01453d335dea50436c27e9e5cbff5e3 |
| green-06-merge-repin.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-06-merge-repin.txt | 4470c077f0c6b5fa6dd4e4cfa4ad5b37f18834ba84e955dd5cf172a87335304d |
| green-07-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-07-final.txt | 2f7bdb4ab78a4a827ae6ab4f8013a83a872bcb80bf6d0ba4a953f929ff1bc396 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/guards-01.txt | c6d3f1a78e24c3c612922b34bbbadd450fdaace292525ba1a884d08a03b78bef |
| int-census-on-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-census-on-base.txt | ec32ee120ee8c84aee6b2c4eac86c53cb4c53c1af2a5156479fc46282d46ba4b |
| int-diag-A-busy50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-A-busy50.txt | 4a101e108053a1e5124da852b48f63f611bf0b86fd2a77989fff682e5a43b2c8 |
| int-diag-B-busy51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-B-busy51.txt | 2a35e96086189fc037cc94ed9a8342c82e39270b81c7321280159e94dfd21f2a |
| int-diag-C-new-other.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-C-new-other.txt | d403f06b300a95c597fc0ba247bd893e955194f843be617914c0e7c645281d2b |
| int-diag-D-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-D-repinned.txt | 983a90e338d8a445d0fb3e1b1fd90acd60a912df0c7ca02381a44e0107396df0 |
| int-diag-E-refail.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-E-refail.txt | 8b845af681eea4e54cd956b38ebf7ab5f1c20e296fdc4bf03d585ab980ce8810 |
| mut-M-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-01.txt | d496c06874e42937cbe80e768bb6ab595ab4feba33038dfe051f5f20935ae8b4 |
| mut-M-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-02.txt | ec9f062c75ccbdca5f5965e93e98ddd2611d674b257ef05894af9e54d7cddbaf |
| mut-M-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-03.txt | 670f2c5aca01876a6c48f69beabe75ff821b793df7584c8c836489babf83fee7 |
| mut-M-04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-04.txt | e702356c15da61fb2d9f79fe6292201346d146fb026a17a10aa5786b2508be10 |
| mut-M-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-05.txt | fffaa160a6d144403836010eb915c8374bb91469ebf9f3291e95c340d256d5cb |
| mut-M-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-06.txt | e82a4506601315f61db5fe2633c1717f3fb3bf142abf6265a96bb7ab7baa825b |
| mut-M-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-07.txt | 650589f1260007d1f44916152db7b0e86ce575f2c658ef059b01bc8d1cf48e43 |
| mut-M-08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-08.txt | 301b586f0a4377de21e748892118e370f0e6c43ba36faa4a248cfb9c90548163 |
| mut-M-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-09.txt | d812b85bf80ec09b4ee035659c8146aa9bdb1241984bf72eb4067c8deb27519f |
| mut-M-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-10.txt | dd5963177ff73fca212705f2645c2a1be8bc3fa2d6bf70dc75293aa7fcdc0b95 |
| mut-M-100.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-100.txt | 24b41171977e670646fa5e651cb44cb7aad6877748ac4cb940a0c3d2124ff18c |
| mut-M-101.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-101.txt | fcff5e2eb1300d0cbd298275927b7531cbab0a9b12c2773761e4b4ce0f1dbcce |
| mut-M-102.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-102.txt | 4d6163e8dda8c25b6fb3edc6e3a0c1600c02890d9b00a1a71465b77abdb64f34 |
| mut-M-103.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-103.txt | c3e91ce42b1952f1f4b6f440972d4e14cb5d36c907a2d38de72c9881e29a1f4c |
| mut-M-104.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-104.txt | 0ada013684d9cf86a722f09337b6192b006f4e76e00feddf33481bb21e1c1078 |
| mut-M-105.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-105.txt | 94063a6401b21970ba7dfff0a9ec0f98506a328cdd6387788526d98ffca4c00e |
| mut-M-106.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-106.txt | a4915ca14110247beb1be9d7a2db68798c97db7ce4f6061f9728a17926feaf63 |
| mut-M-107.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-107.txt | 6780e26bbdc13996934bdd468dc608039a95ce8ee87412bdec623a25af1b5065 |
| mut-M-108.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-108.txt | cf2cdfcb54b580bb8a53c6276be775c205495223a2576775de002a2ef02b76b7 |
| mut-M-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-11.txt | 3d3d9a70cfeabf7e81d39fea1cb8504151685cdf86bc8f73f6c3406c2300c3ad |
| mut-M-12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-12.txt | a7b27d50ab2113b2b31b9ba010ef79ba697f3df8e5753586bbba6105b7c7c35f |
| mut-M-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-13.txt | 10a99648ca65c4afb12f0efe0773bf668d1f014a220f00c99b00cfbb63b277cc |
| mut-M-14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-14.txt | ab38185a81e113c771416b05d51c94b36724fe5886cbf1afb4704cbf004e767a |
| mut-M-15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-15.txt | 8a4e29addec121649757b05f55e7598018ac19da59fcbec443993718f5259e65 |
| mut-M-16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-16.txt | 3afdc1e91f3f7f08ad6a69d00ae693cf994fbcf52bf6165d6c020442c449b034 |
| mut-M-17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-17.txt | 99d1e8ab30015c692e6421970c9099ef756520fb14ec2579b030bda32188757c |
| mut-M-18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-18.txt | c7e3cb2a0fdbb106a32981c726d256d3a1edb11463b6b06c2d31c1d2589ef542 |
| mut-M-19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-19.txt | 57138a8b7eee6f9a05fa56c7ad3ca2a1b6d6fe55a198dc98e0de7cd50ff9ee5f |
| mut-M-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-20.txt | 65036b4a9f827c40d0962a932774a0f10e770d82201d5012e19baf1e57eca68d |
| mut-M-21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-21.txt | 96693649f057434e53eaa66d2bc123b577ffc84affed84fcf9f5bbc2f1325934 |
| mut-M-22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-22.txt | 3dce0e290a3b12709a26fd975209340a0e6d4baedb8d170667a8c45df75dcbd2 |
| mut-M-23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-23.txt | 3b427ecccab1356e60bbedb7f24271d5601375c5975538d8f2563a5572b60d24 |
| mut-M-24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-24.txt | 77a57c2ec36e602247d1e9541c403ed55ea8b680a9583a86498dfc51796fe97b |
| mut-M-25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-25.txt | fb658f7679bfee6987921deac657781f1a7c78ac2b74528ac80c28be7b560863 |
| mut-M-26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-26.txt | d0c540c43e3d254b2780bc69c0029ca8cc72366626f9cde77158b2549b7075b5 |
| mut-M-27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-27.txt | 10613b5a6f214b5e250be28d9e0d3d3d36d0fa56e05950aa48a0cd3c3a88c4f9 |
| mut-M-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-28.txt | ce717ef5430040c294d95e2c5c6c6246a3bb2dbbd39277e454d394ecaa2fe275 |
| mut-M-29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-29.txt | c08f504339e9f14c6b5d71624c4dc18e074595bae9c5e32b878b6fac53ed9ae9 |
| mut-M-30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-30.txt | 77f5aa436c013273c69d909a6a05469b7051a6c6637e925cc4b5251d249a7eb8 |
| mut-M-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-31.txt | 5ce75c844ae1e1454c6c9a21673cea4224f8d8c478f624267ab1feac2264c6d9 |
| mut-M-32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-32.txt | 2590c24d77bf61664e887fb2e2b6dff8f405a3e19588c606ffc48fa45b0866c7 |
| mut-M-33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-33.txt | d71161956dbc071d1cea60c731e7cbf286a7d89d0b3b2f37a3cd6b3001cf9a10 |
| mut-M-34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-34.txt | ced9f8e005f14878c9e6443f064edb17ed14296519993479b66eb9c2b009e100 |
| mut-M-35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-35.txt | 9b46d62e99cb75c972b5faf4d540eaa2cd102bdb734fcbcc181c60f9bbb3c7cc |
| mut-M-36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-36.txt | 120b12d337a327643039bb29be2d3ace9447fd4bf61a477b86031bf3632c8168 |
| mut-M-37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-37.txt | 158154adeb18a348a8000e6b2e40692c65de80f1374dd622cd3f7ee3331a68a9 |
| mut-M-38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-38.txt | 9b30ac99d52c7f81c5ebf4abf1850c1c0c656186fe7e083e22920c679e2bf8e6 |
| mut-M-39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-39.txt | 645126d801f6f4bce921b60bfc32747506ba188f93d7081678f2362ca30f7ff8 |
| mut-M-40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-40.txt | dc98b50e8085b7bd3ebab54ff247ec16a0338ba74bcf1db82e508dd0c04ab148 |
| mut-M-41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-41.txt | acc78b9de0f80e115d75b223073b300a5398cfe8e09a99d5cd263b1b551e563d |
| mut-M-42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-42.txt | b6a45beef115bc3ec590f9ef7177853eee21ad0ae4b685943b5236c54c47b306 |
| mut-M-43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-43.txt | 4d6343cfe4969a2ff1baa660d6bb44c452742dafb1c116a132fb0da7332d6524 |
| mut-M-44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-44.txt | ba6df8fb9688a534653a8a53b3d9960fe0784deb3e810b9693164f0e351735a6 |
| mut-M-45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-45.txt | 368cfd4802b7ec459975ba5d56baf0086bef2fae02ced74a784772f954fff4a9 |
| mut-M-46.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-46.txt | e6595027b18d9e23ef0503335df563960569fb029cbee93494c19e87e6df7439 |
| mut-M-47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-47.txt | 361d1ce4dbaa2dca0cf998e4cf32e5612cd581e501f7385f296c420e07890601 |
| mut-M-48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-48.txt | 8bdc86194e22fe7417fc2bc7432b664863d95e431bb2a604f966350b15addefa |
| mut-M-49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-49.txt | 518d5a68fb2cd7f8e163f5376b87669aa354c34ad52838b687f15984ff04b95e |
| mut-M-50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-50.txt | fbebde87c332b37dad2846a4c7b79fddee9cb6c7588e7228e207b1401db4e14e |
| mut-M-51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-51.txt | d565901e9d12ef2c860f805f2d16fda4e1e0fb33b8580aaf6e6804a637a94608 |
| mut-M-52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-52.txt | 6d0b5743680216c44d24f6892021bd4948cc3c791e1da4378775d10473185d11 |
| mut-M-53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-53.txt | d1005f4638c6de8461298dd7802c12fa2d18f6267d4d851b21ba46fa3df3ed17 |
| mut-M-54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-54.txt | e79f267298c6798df2b5c80b7f83ef8fa8e8d2f63a66c3103b6a61e883540f0d |
| mut-M-55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-55.txt | 4b047c8abc138a7ceb3cb9bfd1fe82816fc1657f3974431f4d6c44b80b80df8d |
| mut-M-56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-56.txt | 3567650a64dd866e8916eda26205865c025c74659f0c613599daf71439b83b57 |
| mut-M-57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-57.txt | 3986aff971f88d875700672184e5bb937f4dad63971e27a240777874e7c0273e |
| mut-M-58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-58.txt | 5471fca8a19b48abd495085d084a3cc571ebd4c306170def9de98630bf0c2f8d |
| mut-M-59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-59.txt | d83b817d7e69a895e4b2ce5128bd6836beb870e763c80c23603f26afb75217f6 |
| mut-M-60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-60.txt | 5c3a97f0b9819b569a793dd9a5f09f1a2a52de76061f4dca7a301e28cc2ff05e |
| mut-M-61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-61.txt | 8e600613150eb13b7a39ca92f7b517cf250e0410097d5e8aff46ab1478d679e0 |
| mut-M-62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-62.txt | 748b8fbbf5135b6edfe818a3b8cef6be12468a4a626cfabd72da837b3f74277a |
| mut-M-63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-63.txt | 31015a7e599ebe7db616b1d40c0998c00fa590957bc0d79efbd818c35e0fef2e |
| mut-M-64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-64.txt | 68043a7eb4674421f012dbbb887aabd5ed7d39ff50a75dfed9024c07a53c8261 |
| mut-M-65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-65.txt | c1ff5c00d209c68d0cbda689a05c64a91b8ab41d887f74f08a96e42c2dcae5c2 |
| mut-M-66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-66.txt | 32a57784a7395ad873378d741756c2bcab5fb39b8f7930dabfe71d7740a6490b |
| mut-M-67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-67.txt | fd4d3f13d301c81728fdc60b2abfca4cc421d8da2b5e1c7cc2f2b36d8306683b |
| mut-M-68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-68.txt | 4d464d3fa84c8c332ee0cd650024858612f6b0fe65902727a5fc426938647c62 |
| mut-M-69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-69.txt | 35df4b5b294036117561eacf7b43362fe96fac42bfb7a877d437001ac2cb34b4 |
| mut-M-70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-70.txt | fa96dbc3fc286b151f480c259022545dc174f5df78a1310b65d1c7b34930ada6 |
| mut-M-71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-71.txt | 567f0e76a48a29d5031801cae88d87685a15e98f6f4e8647da791d9ca6a4b8b6 |
| mut-M-72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-72.txt | 4a63fd0efc6f5fc666c93dd8bbf05b8827ce1d0e91d84a985fd7f214358ae0f3 |
| mut-M-73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-73.txt | 5cbccecaa1eb5ae03214641a8846d48277deb67fbd05d7115ce1262f30977a78 |
| mut-M-74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-74.txt | d245dd48c7de750abefab54d4ede8e786339255a6ddcdcb029e3b171d5512021 |
| mut-M-75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-75.txt | 96d6d2c2be0b2cd838be866ea748efb37675eceeee953ff7280bb4a7e0ea1dc6 |
| mut-M-76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-76.txt | 329c0b69ad3eb04f9166ecda1dc343f32066ad2ed8a55a0466fc70e6aeede136 |
| mut-M-77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-77.txt | 3e750d537f0d763a8e4052ee6c91584b8e18aac37d99db514774bd4094012559 |
| mut-M-78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-78.txt | 08c220339bcfe5c9b94a245e9caa32c397466e248da588b3e1a41319ef7adfb7 |
| mut-M-79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-79.txt | d15a06112304d912eb882af31ffc06804541406f4a4676123dbc5faeabe441a4 |
| mut-M-80.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-80.txt | 2f041ef828b29495eee9473f37e9f6f9080e1cabfa8b2795ecd09e5a4ca93e9a |
| mut-M-81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-81.txt | 9111f86f511c3fcf4fa70a78d4142bb19827d2cb42b9066cd4276e8d030b8092 |
| mut-M-82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-82.txt | 4a841b13e86fc9c431cb40b3ae0e86916d7d20df419a6879d32d82cccd0099ee |
| mut-M-83.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-83.txt | dd4d80aca391daad43aa9234d418d65278014a80baf21404ae81cdebe1324eca |
| mut-M-84.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-84.txt | 0ffbbc65388e4311179cb77f56ccfbb89f4f051527574109c663f909eafc2fb5 |
| mut-M-85.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-85.txt | 853cbbe71cf0fd7e2d68d974aa60f57de0a7d800019a722a3ac4911b6731ff69 |
| mut-M-86.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-86.txt | cfb305b612305ad5d37f41b3c30e0acb7a5a50e49ce5f45ff82373404029733f |
| mut-M-87.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-87.txt | 514683153445e1be22575a35412583e7245a583f11c25aab644bd4bd500cbef9 |
| mut-M-88.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-88.txt | 80d3a53a5558f11f80351d5f4fd59f72a7e7bfe235ece6e043a54ec7e2c82686 |
| mut-M-89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-89.txt | 7133162546edebf35e04465a945f723de3d2f98c26305b801c7f4456aa423b77 |
| mut-M-90.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-90.txt | b0e89e17efdd1c649fd0d19d5f04e670176d237cb98dc9243d9e34f9d6164238 |
| mut-M-91.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-91.txt | 1de4863a168a1b429461de922dd1f810a917070cd1bece2301b0d7fde439a8d3 |
| mut-M-92.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-92.txt | bef2e18370e2973bcb32653419b3ec17671362eecacce68f99ee93e76edbad80 |
| mut-M-93.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-93.txt | 0d5574c0e435608e554cf2251e4a1a0f0967c3a221e5ecd6bddd35f86ee646f7 |
| mut-M-94.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-94.txt | 7da3c4535bf654804f66f5b9c8d292ca334010b353808ac6b367e24f00dd1aa7 |
| mut-M-95.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-95.txt | e12e3a77bd91c4c085a85354357f168226786a9deb8200c8c82b7af553c6ccbf |
| mut-M-96.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-96.txt | 1e4331a6bb47ede6948db5a97da590ff2d8f2f653a1ad6ce4ecf24baa90e2dc0 |
| mut-M-97.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-97.txt | 06f3c889a7805ef9c2735281575000bb5c3350a4bf525fd67de76bc8d54ff24a |
| mut-M-98.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-98.txt | 93d582dd185acfb0af7a12801b09dcb18897a9d587ae9a3c7492ff4bb4bf0b88 |
| mut-M-99.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-99.txt | c33307f058307ead47c7f720da1145e0922626525fb68edb5998972e020a741d |
| mut-r2-M-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-09.txt | 690989ea3b57ef0050e0bff494f2bbdb0388de0812a4baf3daeca92ba20c4957 |
| mut-r2-M-101.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-101.txt | 885ad8ecbf112e76b9da985d47aca26a5db69722ab038771ca090a97ce87135c |
| mut-r2-M-102.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-102.txt | 4bb3eee90375a365abc3f9f1e20aac2f0d3157866ea879cb8a40391e1c7f1008 |
| mut-r2-M-105.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-105.txt | 00a144f874c112c297d2290e3309cdf8d69a9629d62845dfb50922c7f9b35f7d |
| mut-r2-M-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-20.txt | d250d902cb293048e29b69c2780773882f6481fa38a6f719ea1d9344466b20bb |
| mut-r2-M-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-28.txt | d697af89f1d0903db31f40ec9379bcb04d910ee280aaca31a775e09487865fa7 |
| mut-r2-M-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-31.txt | e16247311cb2804582b9f970edc5442583287cd96cf75d7fb43969c1e8a2b151 |
| mut-r2-M-44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-44.txt | d3c1d487c72069a739498d5b0dce40d5812cc82755b21ae10358a87ce83cebb6 |
| mut-r2-M-69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-69.txt | bb558fd6bdf241c073bf36c97b77380c37c459e1872a9b59368112ccb0501891 |
| mut-r2-M-69b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-69b.txt | 56f2e4e54ae913dd3846300eabf0f724f645ff441ca22e49755a41dff8e9e89d |
| mut-r2-M-70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-70.txt | 9a00d5cbe831bc30868059c9560e53bb8558a523c4382847cc0711401546fee2 |
| mut-r2-M-79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-79.txt | 9a97ecf1910e69b3e7af5ffa50cb02a3ccfa4b443fde17b445d2ac9f5a0b8718 |
| mut-r2-M-82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-82.txt | 5c37bd51e8e1166785e845793163ef63168d3e3bee7318b1e2be518d564988d4 |
| mut-r2-M-89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-89.txt | 710e7a29cdec56cb5bf87bac83fa097eef44109eb6e729317bfbafd87f342b29 |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mutation-summary.md | 28916b986143500d24f4a4097b80661901313ffc5290f8430e9fdd47d0eba459 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/red-01-vs-base.txt | 8c057f619e5853de024d8624150c9d36c755ab3c7902d2af1641e9c90733c8b6 |
| red-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/red-03-corrective.txt | 734fc685e9d75a59660d257e9fe28b68e17ace72a62cc6d6ad5629461c150ede |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · **PASS-WITH-NOTES** (0 HIGH · 0 MAJOR · 2 MINOR · 1 NIT). CR12a-1: a raise after the save is committed logs `Saving project <name> failed` and loses the `Saved project to …` line → Inc 12b. CR12a-2: 9 of the 10 Save abort exits have no test that pins their own outcome → decided by the mutants (the AST rule + one behavioural abort arm land in round 2). CR12a-3: the two re-pinned report test names still say the bar ends at 100 → renamed. — `review-increment-021.md`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · **PASS-WITH-NOTES** (0 HIGH · 1 MAJOR · 1 MINOR · 2 NIT). SE5-12a-1 (MAJOR): the status log carries an ESC sequence through `_append_log_line`, and the ESC test cannot detect it → fixed by the one-line scrub. SE5-12a-2 = O-12a-1 (MINOR): the file-load outcome carries a bidi control → fixed, the file-state line backlogged. SE5-12a-3 (NIT): the one project-match returns the first case-insensitive match, not the exact one → fixed. SE5-12a-4 (NIT): use-time `resolve_input_path` with no guard → Inc 12b. — `security-increment-021.md`. **Design reviews (E3, code-free):** `architect` (1 round: PASS-WITH-NOTES, 0 MAJOR · 7 MINOR · 2 NIT) and `security-reviewer` (2 rounds: r1 PASS-WITH-NOTES, 2 MAJOR · 2 MINOR · 2 NIT; r2 PASS-WITH-NOTES, 4 NIT) → design approved (`inc-12a/E3-architect.md`, `E3-security.md`). **There WAS no re-review: nothing blocked** — both E5 round-1 verdicts were PASS-WITH-NOTES with no HIGH or MAJOR in source after the corrective ruling, so the corrective pass's RED/GREEN/mutant evidence is the narrow re-review. **Orchestrator (2026-11-01).** Final source hashes `app.py` `15ffc7bdbb599615`, `styles.tcss` `f7b4f75911b296a4`. Scope ruling in force: per increment, the new and modified requirement tests, the modules that exercise the changed functions and the guards only (LED .75, amended by the 2026-10-31 override); the touched-module run and the full suite are deferred to the batch-end battery. Rulings applied: Q1–Q10 (`inc-12a/E1-rulings.md`), the E2 rulings (`inc-12a/E2-rulings.md`), S12a-* / A12a-* / S12a-R2-* (`inc-12a/E3-rulings.md`), SR-12a-1/SR-12a-2/SR-12a-3 and D-1 … D-8 (`inc-12a/E4-integration-notes.md`), and the E5 rulings SE5-12a-* / CR12a-* / MERGE-12a-1 (LED .96). |

---

## 5 · Risks

- **The touched-module run and the full suite were not run for Inc 12a** (operator override 2026-10-31). A module outside the new-file/re-pinned set that calls one of the changed functions after the corrective pass has not been exercised here. The batch-end full battery is the check (§7).
- **The three main-thread actions are invisible at 12a.** A2L load, project load and Save project paint their line and clear it within one blocked call; the user-visible gain at 12a is on file loads, reports, diff reports and before/after runs. 12a and 12b land together (R-PD), so the operator never sees the half state in a release (HLR-176a, declared).
- **The 29 SVG snapshot cells drift until the CI regen.** `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot` for those 29 cells is `not-run` here and expected to drift until `.github/workflows/snapshot-regen.yml` regenerates them after the merge (§6).
- **The CR12a-1 post-commit window.** A raise after the manifest is on disk logs `Saving project <name> failed` and drops the committed line; at 12a the re-raise ends the app. Routed to Inc 12b's Save worker (S12b-03).
- **The SE5-12a-4 use-time re-resolve.** The loaders call `resolve_input_path` again at use time with no guard; a stale share or a permission change while the Inc 10 question waits can exit the app. Routed to Inc 12b (LLR-177.2).
- **The SE5-12a-2 file-state bidi line.** `Loaded fw` + U+202E + `gpj.s19 (S19 only)` still reaches `#status_text` and its log copy through `_format_coexistence_status` (base text). Routed to the batch-end (BACKLOG-CODE); the progress line and the outcome already scrub.
- **The R-GA12a mount cost.** The 0.1 s timer repaints the line 10 times per second while busy, 0 when idle (LLR-176.1e). The GIL cost of a 0.1 s label update during a 2.4 s worker parse was not measured (E3 "Not verified").
- **The OBS-12a-1 ETA readout.** The built-in ETA beside the seam's elapsed time shows two contradictory times on one row (§4, E13).
- **Declared risks (not backlog).** The B1 declaration (an 8.3 spelling of the work area paints `outside the work area`); the B2 declaration (OneDrive placeholders vanish from the lister); the G-A/G-B P-* deviations accepted at E2; the `exclusive=True` one-group-per-key rule recorded for 12b (S12a-05).
- **Model performance.** DeepSeek v4 Pro implemented G-A + G-B in one job (3 declared deviations), ran the **108** mutants (86 killed at first, 22 survived → 13 killed by the round-2 pass, 7 accepted equivalent, 2 Linux-only accepted) and did E13. Opus did E1, E2, E3 (2 rounds), the tester, the integration (1 source fix, SR-12a-2), the reviews and the corrective pass (round 1 and the round-2 mutant-kill pass).

## 6 · Pending items / spec deviations

**Backlog added at the close** (`.dev-flow/BACKLOG-CODE.md`, each with its evidence path and home):
- SE5-12a-4 (E5-rulings) — the loaders call `resolve_input_path` again at use time with no guard → **Inc 12b** (LLR-177.2).
- CR12a-1 (E5-rulings) — a raise after the save is committed logs `Saving project <name> failed` and drops `Saved project to …` → **Inc 12b** (S12b-03).
- SE5-12a-2 = O-12a-1 (E5-rulings, the corrective pass) — the file-state line keeps a bidi control from the file name → **batch-end** (BACKLOG-CODE).
- OBS-12a-1 (E13-notes) — the built-in ETA readout contradicts the seam's elapsed time → **Inc 12b integration or the batch-end fix round**.

**E1 sweep dispositions** (`inc-12a/E1-rulings.md`, `E1-rulings-proposed.md`):
- B1 (CR9-2, an 8.3 spelling of the work area) — **declared in Risks, the row kept open with no batch target**.
- B2 (CR9-5 / SEC9-8, OneDrive placeholders) — **declared and moved to the first batch that owns `workspace.py`**.
- B6 (SEC9-5 part, the store `fsync` and the stray `.recent_sources-*.tmp` sweep) — **moved to the first batch that owns `workspace.py`**.
- B8 (OBS-9a-1, the Workarea Files panel width) — **moved to a TUI layout batch**.
- B11 (batch-100 Inc 8b R12, the save-as on a worker) — **moved to Inc 12b, without the cancel** (VS-PD-2).
- B12 (Inc 10 rulings Q7 / Q8) — **routed to the next batch** when the rows are opened.
- B9 (OBS-9a-2) — **closed as not a defect** (the seed writes `project.json` with no `files` key).

**Owed elsewhere (not backlog).**
- A12-51 (the manifest-mismatch tail of Save project) has no test → **batch-end battery**.
- The 29 SVG snapshot regenerations → the CI workflow `.github/workflows/snapshot-regen.yml` after the merge, committing only those 29 files. **Pending until then.**
- D-1 fixed `tests/test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` → it **leaves the known-CI-failure list**.

**Declared (Risks, not backlog).** The B1 and B2 declarations; the three main-thread actions' invisibility (HLR-176a); the E2 G-A/G-B P-* deviations; the `exclusive=True` one-group-per-key rule recorded for 12b (S12a-05); the 80×24 elapsed-time fall-off (R-6); the mount cost of the 0.1 s timer.

**Named gaps / observations.** OBS-12a-1 (the ETA readout, above). The examples the tester could not turn into tests are listed in `inc-12a/E4-tester-notes.md` §5 (the `gen` signature check via `inspect.signature`, A12-51 without a test, the exact "log lines added" lists, the `-busy` class asserted through colour, the `_busy.timer is None` through running timers, the folded refusal-before-begin arms). M-74's kill is by an exception, not by its rows assertion (as in Inc 11's M-74). M-101's ruling text was corrected: the mutant is the pre-question look, and the ruled behaviour (F-11 / 9b B88) is that a vanished pick loads nothing silently.

**Finding → disposition (E3, code-free design review).**

| Finding | Severity | Disposition |
|---|---|---|
| S12a-01 (the typed-path catch), S12a-02 (raw outcome/pending lines), S12a-03 (stale pick re-check), S12a-04 (the scrub test cannot fail), S12a-05 (one group per key), S12a-06 (post-on-success) | MAJOR / MINOR / NIT | E3 rulings S12a-01 … S12a-06 + S12a-R2-1 … S12a-R2-4 (LED .95) |
| A12a-01 … A12a-09 (the architect findings) | MINOR / NIT | E3 rulings A12a-01 … A12a-09 (LED .95) |

**Finding → disposition (E5, code).**

| Finding | Severity / tag | Disposition |
|---|---|---|
| SE5-12a-1 the raw status-log line | MAJOR / design-gap | fixed (LLR-176.1t); `red-03-corrective.txt` + the round-1 GREEN |
| SE5-12a-2 = O-12a-1 the bidi outcome | MINOR / design-gap | fixed (LLR-176.1r); the file-state line → BACKLOG-CODE |
| SE5-12a-3 the case-insensitive-first match | NIT / design-gap | fixed (LLR-172.5j); `red-03-corrective.txt` + the case-sensitive run |
| SE5-12a-4 the use-time re-resolve | NIT / design-gap | routed → Inc 12b (LLR-177.2) |
| CR12a-1 the post-commit `Saving … failed` | MINOR / design-gap | routed → Inc 12b (S12b-03) |
| CR12a-2 the untested Save abort exits | MINOR / design-gap | fixed by the mutants (AST rule + one abort arm, LLR-176.2c/.2d) |
| CR12a-3 the stale test names | NIT / impl | fixed (renames, LLR-176.1k) |
| MERGE-12a-1 the Inc 11 arm without `gen` | — / merge | fixed (re-pin, `green-06-merge-repin.txt`) |

**Orchestrator rulings Q1–Q10** are in `inc-12a/E1-rulings.md`; the **E2 rulings** (Q-1 … Q-7, the re-pin census rows A/B/C, G-A P-1 … P-7, G-B P-B1 … P-B4) are in `inc-12a/E2-rulings.md`; the **E3 rulings S12a-* / A12a-* / S12a-R2-*** are in `inc-12a/E3-rulings.md`; the **seam rulings SR-12a-1 / SR-12a-2 / SR-12a-3** and the **ambiguity rulings D-1 … D-8** are in `inc-12a/E4-integration-notes.md`; the **E5 rulings SE5-12a-* / CR12a-* / MERGE-12a-1** are in `inc-12a/E5-rulings.md` (LED .96).

**Re-pins (test::node — what changed — requirement).** The 15 re-pinned functions (23 items) move the bar drives to the new seam, the report nodes to "the bar is cleared at the end" (D-2, CR12a-3), and the key-bar / bindings nodes to `Load` / `Projects` (LLR-173.2m). The census rows A (11), B (6 + 29 SVG) and C (1) are in `inc-12a/E4-tester-notes.md` §3; each names the old value, the new value and the requirement that changes it. `test_at_b78_32_app_bindings_block_is_untouched` (D-1) adds the two missing frozen rows and bumps `_B79_COMMITTED_APP_BINDING_COUNT` 40 → 42.

## 7 · Suggested next task

**Inc 12b of batch-100** — the busy worker and the busy refusal (HLR-177, LLR-177.1/.2, LLR-176.3, LLR-176.4 with the `a2l.py` re-freeze, AT-B100-18, AT-B100-17's parse half, TC-B100-52, TC-B100-73). Its E4 integration is in progress on `b100-inc12b`. Carried into it from this increment: CR12a-1 (the post-commit `Saving … failed`), SE5-12a-4 (the use-time re-resolve), OBS-12a-1 (the ETA readout) and the B11 save-as worker (without cancel).

**Batch-end full battery (owed once, when all increments are done — operator rulings 2026-10-30 and 2026-10-31).**
1. the touched-module run deferred by the 2026-10-31 override, every failure dispositioned against base;
2. the full reverse census / full suite on the final tree;
3. the guards and the census sweep (`-k census`) on the final bytes;
4. the mutants of every increment re-run on the final tree where a later increment touched the same function (the 108 Inc 12a mutants ran on the pre-fix and post-fix trees; the round-2 re-runs cover what E5 changed);
5. the CI run, comparing the FAILED set with the previous run;
6. A12-51 (the manifest-mismatch tail of Save project, without a test);
7. the 29 SVG snapshot regenerations through `.github/workflows/snapshot-regen.yml`, committing only those files;
8. the file-state-line bidi row (SE5-12a-2) — `painted_names` in `_format_coexistence_status`.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 of the 4-file cap (`app.py`, `styles.tcss`) — §2 |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_busy.py` (NEW, 52 functions/81 items) + the new arms in 3 files + the 15 re-pins + `test_id_registry.py` F-7 — §2, §4 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `_busy_line`, `_listed_project_name`, the clamp; the AST censuses (LLR-176.2, LLR-176.2a, LLR-172.5j, LLR-172.5k) |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01-vs-base.txt` (125 RED vs `051f586`); `red-03-corrective.txt` (SE5-12a-1/-2/-3 RED on `71376a3`) |
| 5 | Reverse census declared | `core` · `full` | ⚠ | **not run per increment — operator override 2026-10-31, batch-end full battery** (§7). The new file, the re-pinned nodes and the guards ran |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES (0 HIGH, 0 MAJOR); nothing blocked, so no re-review |
| 7 | No file from another lane touched | all | ✓ | the 2 named sources + tests / fixtures / config / records; `tools/e13/` is the orchestrator's; `prototypes/` untouched |
