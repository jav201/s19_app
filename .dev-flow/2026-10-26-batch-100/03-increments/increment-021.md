# Increment 021 — Inc 12a · HLR-176 … HLR-176d / LLR-176.1x, LLR-176.2x / LLR-173.2m / sweep · the progress indicator, the labels and the sweep

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `012` |
| Lane | `main` · 2 SOURCE files (`app.py`, `styles.tcss`), at the 4-file cap |
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
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-176 … HLR-176d · LLR-176.1x/.2x · LLR-173.2m · LLR-172.x | E1/E3/E5 edits (LED .95–.97) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-176 … HLR-176d · LLR-176.1x/.2x · LLR-173.2m · LLR-172.x | LED .95 – .97 |
| `.dev-flow/BACKLOG-CODE.md` | doc | LLR-176.1r | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-12a/*` | doc | HLR-176 … HLR-176d · LLR-176.1x/.2x | the experiment records: `E1-scope.md`, `E1-rulings.md`, `E1-rulings-proposed.md`, `E2-rulings.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-021.md` | doc | HLR-176 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/*` | generated | HLR-176 | transcripts (evidence digest table at the end of §4) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | HLR-176 | orchestrator-owned: scenario `bz-busy` |

## 3 · How to test

```bash
# from the worktree root; interpreter C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
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

First step start to the last logged step: 14:55Z to 02:14Z = about 11 h 19 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 2 MAJOR in round 1 (S12a-01, S12a-02); E5 (code) caught 1 MAJOR (SE5-12a-1), 2 MINOR and 3 NIT; 1 corrective pass + 1 mutant-kill round; 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/` | SHA-256 |
|---|---|---|
| bz-busy.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.118x54.png | f79a91df623013de5bc27eb49cb8a5e03ce19edd39d6c0e12663b4c1f325b132 |
| bz-busy.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.220x60.png | 8f98aa25599a977fb4742fdf97bbb4664811f779c9077d0a2fac4f5e814ef438 |
| bz-busy.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.99x54.png | cd087f51a536c517768bf5c898b7367937e3aeb907e3846105afb85d3bf829e4 |
| bz_busy_headless_probe.py | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz_busy_headless_probe.py | 2c121d7bb2f414bc1f3ba11b08ecb3498a531517070ddea0415c33a8f3b206f1 |
| green-01-new-run1-130arm-notrun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-01-new-run1-130arm-notrun.txt | 2c732ff0b96f4389d5c4dc684d4dc588f219889939744fee80c8c64a6cb5d0fd |
| green-01-new-run2-setup-error.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-01-new-run2-setup-error.txt | 7dde8f17a7741913ff786a91c4ac9946a52d1a7fc94d7c6236bae8155c363ea3 |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-01-new.txt | 1e8af8f750d312267f6125b5480271b44618134f1b44d5890a0a2b109b824449 |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-02-repinned.txt | aba9caae1027d1c4f251a9dbff79d668e080ad24922373381dc02d4ceb1a567b |
| green-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-03-corrective.txt | 583e634d84fb7a719bfb6b6981a8cc70ba13dfd0139c6866dc03c6b6727df0d3 |
| green-03-merged.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-03-merged.txt | 37c6ac91685b96759eeed5f037087e61286899e90e8fb9af6f7d138822de4c82 |
| green-04-new-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-04-new-and-guards.txt | 9ebc6e7d6bc4b232a62ab96525c514146496ab1a72d09ea1c68095056ab8edac |
| green-05-busy-file.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-05-busy-file.txt | b243831915a08fc078794b463552fe7e85f6171337597e836376fd56f8c57333 |
| green-06-merge-repin.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-06-merge-repin.txt | e04883771429e23d92d057e18b865f57820864400a8934a80cf350bf5c9e6aca |
| green-07-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/green-07-final.txt | d569e4ff5c31846aa29df1cc5ae1a7be95dd05aa654fdaa5bf469b847146261f |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/guards-01.txt | b1c71abf0440511e3782017e96634e12c4ba217dc202f13affa5d1695b6c5fb2 |
| int-census-on-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-census-on-base.txt | 0a856e49d53dbfbbfff853f67f7986ee4f0d3d4735560e68b9fbc8c729c5af44 |
| int-diag-A-busy50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-A-busy50.txt | f2b0c4b059c94f3c2a025a12b1fc773c9085e78bd8f04606f174b63e5e380e39 |
| int-diag-B-busy51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-B-busy51.txt | f6f90d8bb404dc1ab9148e44da79484b6cd4494eb7b62d588b40c6ed1ca9929b |
| int-diag-C-new-other.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-C-new-other.txt | 134df115995d85d1d727cede42f1305d2d06e34b914f335dd108651663cf438b |
| int-diag-D-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-D-repinned.txt | 149b3332ca32d30425223020798275eeb0b8647fb35c78799b7809c27c1f2b96 |
| int-diag-E-refail.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/int-diag-E-refail.txt | 73c2fe20a08de7175190beec2022b774323fca9a39b5f2e5dd0986b023162f3c |
| mut-M-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-01.txt | 8913bc7bbe8b9248e9377c5ac2f88647d3045181435dc09e1b6e8ad36329cb3f |
| mut-M-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-02.txt | e817c393c95515541b5737a5b15581b363e33a3c595bd7d73d48c1f9365658e7 |
| mut-M-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-03.txt | 98089e781d44904fee98089168e992d82b0e2208daeb4af87f6a7b520cfe38af |
| mut-M-04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-04.txt | 423f8bc1ce26f16bb81c332842afe92155e830024f189c5e7adb917f91f9098b |
| mut-M-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-05.txt | ad6b708d74e6986b4bd700466e601290868eb6741abb2888ab704903ee541363 |
| mut-M-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-06.txt | 62dfa2b54d29616c17aa58e10a721ca4ef299db596a38c5c44062bb90216a69a |
| mut-M-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-07.txt | 456dc7a4591a089b333e8fe1c0c18b31478b96b100874b26d9a62a0edf6af3d3 |
| mut-M-08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-08.txt | 123076bfcc2971d4380e8cb3aabca1fb4b19b6d8c7f800beb099aed74aaf3445 |
| mut-M-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-09.txt | 01e1815b6a3f660bdaf4a6b4fd96ae331a15d36e270a6cfca79057f03500640c |
| mut-M-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-10.txt | 44dee5d04f8d16ab327042fba630a35dafc51c3fb54d04d2e3a30531db5c4c36 |
| mut-M-100.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-100.txt | 64265a66cbbf8aadb63c1c031c3f858e24c234fa1b140eb3986cce0bc499ce3e |
| mut-M-101.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-101.txt | 4795986cbd83c904d9e5b8d9903fe4d088d552c458c6d469297ee337ea632989 |
| mut-M-102.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-102.txt | f7f36d6c086ade26bda089c67572ae16647331254d0e89b16946821e4364e802 |
| mut-M-103.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-103.txt | c117885e0cdeb651eb1df536d8f9d25301a0daf3e4fb6894d87cee3f5b73542b |
| mut-M-104.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-104.txt | 910723b47ca5dbe8e731d63f6c4374b18f45b57584171e061800b0188936f297 |
| mut-M-105.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-105.txt | c1eb1f5b8edb4ad3ce67b57a357f2a6070c30fe3ac5d1a7f459a6bfbd718801c |
| mut-M-106.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-106.txt | 18f1a58e45b0b91878bd9b27660a5ccd5b3fb214cd371a00d2c83940c85608e9 |
| mut-M-107.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-107.txt | 980cdba3019c3dffdef39d78409797ef1a5c156a250a5c6c5898ad8d286f0995 |
| mut-M-108.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-108.txt | defb7724ba3f879417810f5c79e112e29f61798781390e27d8a7dbbf5ab740ef |
| mut-M-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-11.txt | ec9c3e36750674472f952eed0c199484fed2eca201c3fa197e94a55d2175190f |
| mut-M-12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-12.txt | 215a4749dbcd9f2faea2aebdea893e287e5db92910fe015247bcc2031fb1f21e |
| mut-M-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-13.txt | f7ef616b2bf7ca4ceae9cde32e55fad1902834326c4385454d190caefa873cf8 |
| mut-M-14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-14.txt | e148dbff571e8c3c6bdb56f465976bf08cd78a4185ee40f2b0c0815fcfb23d08 |
| mut-M-15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-15.txt | 4aac7795cc3a474afe2b74bed05dd451514b8c06f129b4a7690246440f2838fc |
| mut-M-16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-16.txt | dfe92004e9156cff5b1c7604ba6d85ba9d3100f5a30e0cf33da63762a2ddc64f |
| mut-M-17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-17.txt | ae5b08f217a4369ab8baa3be01f03fe256d0601b4e68d9ff9824e7abb2fa3176 |
| mut-M-18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-18.txt | 1287c1cd0ab85a059be5142a64387062af322e6eba726d706505a01e4b7ce6fe |
| mut-M-19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-19.txt | d0cc1695f98cfb76713354b4fb5bcdf918b4b597ac515ca6d90cddaf9b0017e6 |
| mut-M-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-20.txt | de8eb2e001376cac1078908a2f4274936df5f1c76205880030d979137a850693 |
| mut-M-21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-21.txt | 555f9ceadb82ff750429fff84673a88c9a215cf4a4510235f5de9249364c6c8f |
| mut-M-22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-22.txt | 4459d44b76f6f820d5dcbf9c957d82a4d1a553678efff2f32a37c18951fab40f |
| mut-M-23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-23.txt | dfdce004b002285be226fd7862c38df344e51e7848ebf75a5a005b0dece2fbc6 |
| mut-M-24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-24.txt | e53ebb08039bfbc79d25ce3f4a26d9dceb9edf75669cd6962f2e077bf97036e4 |
| mut-M-25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-25.txt | 5de9acdbeae26814bff2aaedf8b5f7b4c81b16a2590f9bd0abe6c15bdc6ae025 |
| mut-M-26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-26.txt | 6e21dcea95513fb8a841c67e388355c8e054fe45badef371e32909ba6db080ab |
| mut-M-27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-27.txt | 3f4cc12415c0fe1e235f4dbdc8870cf6fa3936d0f85a54e3c8b4f5f33561e3b8 |
| mut-M-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-28.txt | 253681052bcaf31ca345186e5c6d8614056f25d4c3241e5b3fff59f186f6099c |
| mut-M-29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-29.txt | e5caa7d8f4a98188931149fa493752633a6ae3be14eeeec66296bf764f992881 |
| mut-M-30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-30.txt | a88a5b9ea875feaf48af846ba6c32c6b61a6ba4927218a3cf05d1e3a9d5d02f1 |
| mut-M-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-31.txt | 1dc4d0504f2edb88177920df0aa32acbe71628d798e2a7e7452ad9cf4b0cc33b |
| mut-M-32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-32.txt | b1d556174cb43ffb13419886bab69430f7ee3e2f4ff9009d0897a3361ef2220a |
| mut-M-33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-33.txt | 3d8b7c03cd20b97aa43b8ea4bf549108e3d466c8f2b64c58959383a2cd9acdb7 |
| mut-M-34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-34.txt | 9f35fa65d468c0307832574f3a22183760978cd53f98a89c1baa3cac0ccd809d |
| mut-M-35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-35.txt | f739c80e5a11b5f2599b754c02be08e6fdb06ed6b4e1130d6e22d65890cd4775 |
| mut-M-36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-36.txt | f1418e38c4820eafadd33d23a6b31b435ceefdf18bb8ff4fa00bf3f47613aef2 |
| mut-M-37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-37.txt | 98ba3d976c25ce5c49a4054edc1e33b527ca7cfc7ac7156b8418c4f04d5d2b28 |
| mut-M-38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-38.txt | ce30d054f99a096caf67483585495329f3b999182a45aa60a1489d0f89f57264 |
| mut-M-39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-39.txt | f857f955cdc21991687aac7afdc01ecc3a8af9e25b8f90c30da16f8806a56fe7 |
| mut-M-40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-40.txt | 2d44ee35bd2ce8c1bc11dc800531be9cd70e3fb60053c35f67ca4a7193edede0 |
| mut-M-41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-41.txt | 2a76a244988f3e01d1e0db4e788ac7309c796472fe891b52a1a41b836af6e277 |
| mut-M-42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-42.txt | 610d4442f866d5ef697da3defee5df5a5d10b8ab58b9a867f5b58ff594f907c0 |
| mut-M-43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-43.txt | 3cc5655cb1fc85558a52b366a46d8427523c1d1b61727ae91a34b756c91b94f6 |
| mut-M-44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-44.txt | 1e7b04d93f9276718dda77ef85caa4aed2a9804797f41075594ef201d6a4876d |
| mut-M-45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-45.txt | 91dcc1499a8719029441ae7732a6c68c99bf567a8673f8dfc0a56f63a5c50776 |
| mut-M-46.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-46.txt | c45852f10b6abb008bbc83fef00a82809e362c1996fd0d2dad76d1dff1c6b8c2 |
| mut-M-47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-47.txt | 7e52da8cc8fcb052715accfe1b48adae7e95072915462c5f73362d860c06d9e5 |
| mut-M-48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-48.txt | d4dc7f0d906df3becbc2a2bd8a33a67f4e6404450c01756de9f95afb5f203aa9 |
| mut-M-49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-49.txt | 2e41e74602b5232c38ecea01db7860d3525041338d714b191adaae175404796e |
| mut-M-50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-50.txt | eab509dc974d326077c22bad3e9c7918d7dad85c51b4f7dc9fbab645ce44942e |
| mut-M-51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-51.txt | 0996ba3692148ac0a5172ed2966398c811fdd70cfec7cc0375a8d2cdc587fa27 |
| mut-M-52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-52.txt | 9dfb6ae84f86352d6ffb4189c08acfda84027eafcf6a51cd179dd097d5a28305 |
| mut-M-53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-53.txt | ee9151cf27641ba0484f114e5199a3bca69521488d220919b4a51248887dfb3a |
| mut-M-54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-54.txt | 1d20c776b281ef76893494c272206691b8a651e4b2aa469fc639b1614960c568 |
| mut-M-55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-55.txt | c12bc2bf9d2f40e3492c9b147b1f86e402dfa3088089d9bde444101b9c6d0002 |
| mut-M-56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-56.txt | 4c253a8ce548f7716a35ffd029822acc3b8586e457f0c75efddb1c4d76ebed4e |
| mut-M-57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-57.txt | 2cf28764364eb778236dec034edfef4b1156f85eaf240497b77a8a5c4446cb26 |
| mut-M-58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-58.txt | 6d24713dd6162141dd4fb83f61f2cef55cc4f4beb77092b6353158bcf3823b5f |
| mut-M-59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-59.txt | 0737edd431ea68419e49b724c703c982c0a3534a6bd8b63403f883604cec8f4f |
| mut-M-60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-60.txt | 5d119e756308cd7657c58ddbd521852471982d916e9934e1deb7b3d3f94e8b14 |
| mut-M-61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-61.txt | 154e952428f2489dda9b5c41ab940f4c11a40dea45e3e57b8733b2b9d63753b8 |
| mut-M-62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-62.txt | 9b1ee5696c81df69391ac0a06285e55a8b6e86d2578b4203770f604ce9c4b6c1 |
| mut-M-63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-63.txt | 3eb61c075165704fc2d5c3054ae1353e8f170f5afcf091e69f9700909c76e734 |
| mut-M-64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-64.txt | df5354919d5581469d1f741396aa3f0d8b91d4bb7253b2e14e3db579983c5373 |
| mut-M-65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-65.txt | 64e2726ee525fdc0135eb581bc0e1383c9fe7bc1eef3a30a0c3a34318f762acf |
| mut-M-66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-66.txt | bade114d1a63bb4c6a63c56828c3b966fb16ef4f2f3ebab39d8bf6b57e3b1ff1 |
| mut-M-67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-67.txt | cecb396652dcf96c250a40a8a4a5c94dd8766dbb2062566f2402c3b1c390041c |
| mut-M-68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-68.txt | 5c479df844d670704941c150d0b48b8318666a2c00df00aa54cae677863c2302 |
| mut-M-69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-69.txt | 5349fd1d6eb1c64ae62165ee466d1f85028de5497bad2542cb489c745945cb2b |
| mut-M-70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-70.txt | cb0b67a9572f9d1c899e8df194e8aa2ecb866a19bb2ec689673830d013a8e700 |
| mut-M-71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-71.txt | 530448301820ae63a1fb96c0f5da11445a8009b84b9e4d6eb27df27f15f32e93 |
| mut-M-72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-72.txt | 243732a78242d5b0dc0cadd72fd48d47e5b9e319b26265a986688a64b9b99035 |
| mut-M-73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-73.txt | f47422944c5b1ab55934bc8f8177c8a4b41b54ddaf3e9480ab6b1f13a0164176 |
| mut-M-74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-74.txt | b3fc48a458de057aeaec32161776b2461100e548df95646072a63943333bb3a2 |
| mut-M-75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-75.txt | 898ea931b7f9f8d98b5143e1a43682a1948c0ed295c2381dc4bea5fbfc03906e |
| mut-M-76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-76.txt | 528de85664ed6c020d7c737f61eb3c2d4ec0247c283f1c62c8124e385a9c3591 |
| mut-M-77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-77.txt | f13a48d6c7a8dd91879cb17465c368ac427c47ccc8f0e0a319d4f2a56e20e8b2 |
| mut-M-78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-78.txt | 5232bc637fb984c4a38e9356d3b48295bb477b6b482d800d7f95ebaf5e2e0b1b |
| mut-M-79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-79.txt | 273f96b7d9044997d0cf61a6581a6e32a194f0824bb6c22bd52ad5aacf16192c |
| mut-M-80.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-80.txt | 8ec6ecdd6ca25f7cbd7f598fb31bc684af377c49e70ba84a0bc548aede235c1f |
| mut-M-81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-81.txt | 948f9cfe55a2e1f57e7950d59693232044f83262b02c50ecee0eccf7c8f938f6 |
| mut-M-82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-82.txt | 44dfb4d69b0ffc3e6aa6e1a3da24c90857532e4c7b1ac5a4cafa7864f6e7eef9 |
| mut-M-83.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-83.txt | be1cd02fa794bafa328e451b6bc9984705bab499ea8f39d8a33f1cdb69b848c0 |
| mut-M-84.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-84.txt | 3fbc664ad5eb1b8eba324c1872eb9bf27593653dd3ca5963eeb1838db5ebd12c |
| mut-M-85.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-85.txt | 338df93778528cfc9e08e32e9f858b7bcce56b52bab7db2ee963c4bfc3d90e81 |
| mut-M-86.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-86.txt | 2148c0ec81951f9ed7c19362b877cd81fd3e12bad248e821cd740232e2a031f5 |
| mut-M-87.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-87.txt | bf380119c244e4a732377cd8a8d70ffc7c0cb8349e011ba3b7a5096cacd71f5d |
| mut-M-88.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-88.txt | 6031c62961ab51feebf0db7666d35089eb06f5fd7e962b40c9c087ad757ae88e |
| mut-M-89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-89.txt | 639b6a83d00fd58496f3337086a44709fadd1e70982ad59bf29d1a371aadbf0a |
| mut-M-90.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-90.txt | 02646a193764c0d4543848358a07a508a13fcd270d001f5ddec2cb38d7d23f18 |
| mut-M-91.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-91.txt | 8335f6198815adb0db1cd08ff20d5930189d79174958c147c613cefb201ca26c |
| mut-M-92.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-92.txt | 050216b726530de05b82f820ff5dd745d651ed183d200ab52104631fcd515dbe |
| mut-M-93.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-93.txt | fbe6d78538d61435b13b5d7c4553ed51203438ee0f7b43756fdb20c84c8f5ed5 |
| mut-M-94.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-94.txt | e8c4fe005b1a8ed39c9f319b113902f95b878a689475ff8135d5628ca66c2c56 |
| mut-M-95.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-95.txt | 3fb94b6dd4cf87407f012299c6ca7eabacf952f641a690a4727edf4709342f8c |
| mut-M-96.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-96.txt | 119deff18995ca004403a648cad0fadd015cbf498d11183843f9f348b866ea5a |
| mut-M-97.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-97.txt | d433c7120906effd028dc03c5a0b36aba4a2ca7822f6fed1969a39a7a247c231 |
| mut-M-98.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-98.txt | 79361cb2471fb66f228e1aa5e09e38eeefdab045793a0ca62252c918604258e6 |
| mut-M-99.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-M-99.txt | 8ca292bfb8cbbf2ada0c7d7d6d7f3d9b382ccde9b8044dbeacd116868d8a1216 |
| mut-r2-M-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-09.txt | 7856dac83241924f23cb5ad94875eb5b7005de8ecf04807589eb364caad6bec7 |
| mut-r2-M-101.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-101.txt | 61679456d58421e3e70fafc30acafa13385392fb0944e8307007783640ba76b8 |
| mut-r2-M-102.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-102.txt | 488b7b2a2a2d007b7cf26235a5ce102c91b96da570c0024e33bccdb6e05b207d |
| mut-r2-M-105.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-105.txt | 2ee2c1baa2ae84ff4fab56cfd81c592cbf56ac9b18ef8f8fdf356f9c05f3b6ed |
| mut-r2-M-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-20.txt | 394dcb5aa20bb1070457a668923df86048563bbd3b2b642ec3bd01517583e059 |
| mut-r2-M-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-28.txt | c84c3eaa55fe45657f4b08fbc93364db78ba3f3b66b4dacbc5b105393a4b611a |
| mut-r2-M-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-31.txt | 54c505224c14bf98f2a2a3e15ed5c8d11b6d1dd65a2ad18edfeb22249a2e79e6 |
| mut-r2-M-44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-44.txt | 1eca3daa8c6dbd23f71483adcab7bbdf78b2da8931f8c9b5dd8c44061a1c82d6 |
| mut-r2-M-69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-69.txt | ee3f548354db3ef61bde12cfa4011cd7b870276c1a9dcbafb3e2fbd73a44799c |
| mut-r2-M-69b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-69b.txt | f78e78f2cf05878c2685585ac7cc8512287805fc19caad6ea03779fe40f2d395 |
| mut-r2-M-70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-70.txt | f6f5e6cd248e9a6ec3a3ab0d5492120edabd9353be7a64dd3dfa1b4ef500a7a3 |
| mut-r2-M-79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-79.txt | 1497996eab812f2a1eb1b9a1bb519c7c9143d54a5319b6fc3335a6eb269f678a |
| mut-r2-M-82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-82.txt | a4a8b9cf051d8b908680f1a29a1fe38e0204a466d3c76578278659f7d46975c0 |
| mut-r2-M-89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mut-r2-M-89.txt | e7d74847607c8776d23d63b3357ba0b11759dd631ccd29e3e72001d5ab843e88 |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/mutation-summary.md | a76bcaedafb5fb849e330985e25d4cf89438a14ce6c46367476f12359648a5f8 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/red-01-vs-base.txt | 10dc8877c0796fadcec16a3542936b3aad0c5b2ada223a3fa8ce6dc8d7fd7483 |
| red-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12a/red-03-corrective.txt | 22f8094404c795a9a73489ab36e1e0494d1a3a693c5791d2e806a04814463acd |

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
