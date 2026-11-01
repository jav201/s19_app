# Increment 022 — Inc 12b · HLR-177 … HLR-177c / LLR-177.x / LLR-176.3, LLR-176.4x · workers, busy refusal, quit question, A2L parse progress

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `013` |
| Lane | `main` · 2 SOURCE files (`app.py`, `a2l.py`), at the 4-file cap |
| Requirement(s) | `HLR-177` · `HLR-177a` · `HLR-177b` · `HLR-177c` · `LLR-177.1`–`LLR-177.1k` · `LLR-177.2`–`LLR-177.2c` · `LLR-177.3`–`LLR-177.3i` · `LLR-177.4`–`LLR-177.4e` · `LLR-177.5` · `LLR-177.5a` · `LLR-176.3` · `LLR-176.4` · `LLR-176.4a` · `LLR-176.4b` · extended earlier ids `LLR-165.1` · `LLR-164.4` · `LLR-165.2` · `LLR-174.4` · `LLR-176.1l` · `LLR-176.1q` · `LLR-176.2` · `LLR-176.2c` · `LLR-176.2d` · `LLR-178.3` · `LLR-173.7` |
| Acceptance | `AT-B100-18` (four halves: worker, refusal, quit, quit-confirm) · `AT-B100-17` (parse half) · `TC-B100-53` (LLR-177.1 … LLR-177.5a) · `TC-B100-54` (LLR-177.2 … LLR-177.2b) · `TC-B100-52` (LLR-176.3) · `TC-B100-73` (LLR-176.4/.4a/.4b) · extensions `TC-B100-07` (LLR-164.4 worker arm) · `TC-B100-08` (LLR-165.1) · `TC-B100-09` (LLR-165.2) · `TC-B100-50` (LLR-176.1l/.1q) · `TC-B100-51` (LLR-176.2/.2c/.2d) · `TC-B100-72` (LLR-174.4, LLR-177.3a) · `TC-B100-66` (LLR-173.7) — in `tests/test_b100_workers.py` (NEW, 44 functions / 52 items), `tests/test_b100_a2l_progress.py` (NEW, 8 functions / 9 items), `tests/support/b100_workers.py` (NEW), and the extended / re-pinned files below |
| Interfaces | consumes `begin_busy` / `step_busy` / `end_busy` / `_busy_fail` / `_busy_begin_action` / `_running_session_action` / `painted_names` / `safe_text` / `parse_a2l_cached` / `write_change_document` / `_confirm_then_load` / `_handle_load_project` / `_commit_project_save` / `_start_load_worker`; adds the three 12b workers (`_project_load_worker`, `_save_project_worker`, `_a2l_attach_worker`) with their frozen request/result dataclasses and main-thread install/failure handlers, the `_refuse_if_busy` check on the 16 entry points and the 4 continuations, `action_quit` / `_answer_quit` / `_exit_if_quit_pending`, `_QuitQuestionScreen`, `_progress_forwarder`, the `parse_a2l_file` progress callback and the `show_eta=False` on `#progress_bar`; `styles.tcss` unchanged |
| Agent | design-first experiment (`dev-flow-v3-beta` pipeline): E1 requirements · E2 baseline + prototypes (P-1 G-A/G-B, P-2 G-C/G-D) · E3 code-free design review (2 rounds: architect + security) · E4 parallel build (2 DeepSeek implementers for app.py and a2l.py + 1 Opus tester + 1 Opus integration) · E5 validation (115 mutants on DeepSeek v4 Pro via pi, code + security review on Opus, one corrective pass on Opus, then a round-2 mutant kill pass) · E13 capture. Models per stage in the step table below |
| Date | `2026-10-31`–`2026-11-01` (E1 start 14:55Z through E5 round 2 02:14Z, all UTC) |
| Base | `71376a3` (Inc 12a integrated, pre-corrective); `b100-inc12b` branches from `71376a3`, merges `b100-inc12a` at `e3b8ec2` (one conflict in `test_b100_busy.py`, resolved as a union at `ef0cdb8`), then merges `main` after Inc 12a closed (`81ac4c0`). Corrective pass round 1 at `c026bd2`, mutation run at `d4d9c1a`, round 2 + R2-F1 + E13 at `ce3a305` |
| Import proof | `s19_app.__file__` printed in every transcript header (the worktree's `s19_app/__init__.py` for GREEN/guards runs, a scratch copy's for RED/mutant runs) |

---

## 1 · What changed

**The feature (HLR-177 … HLR-177c).** The three actions that blocked the main thread — project load, Save project and the A2L attach — now run their heavy work on worker threads. A project load reads and parses the project's files on a worker and installs the result on the main thread; Save project creates the folder, places the files, writes the emitted image and writes/verifies `project.json` on a worker, then commits the session on the main thread; every A2L attach route copies and parses on a worker. While any session action runs, a second request that would write the session is refused with a busy line naming the running action, and `q` / `ctrl+q` ask a quit question (focus on Stay) instead of exiting; a confirmed quit waits for the action's end handler before it exits, so no partial save is left behind. The A2L parse reports its consumed bytes to 12a's progress indicator, and the Save worker advances the bar per file placed.

- **HLR-177 — the three actions run on worker threads.** A project load, a Save project and an A2L attach each do their heavy work on a worker thread; the event loop's timers keep ticking during the step (LLR-177.1c); the session is written only on the main thread (LLR-177.1d); a worker reads only its immutable request (LLR-177.1e). The compound HLR-177 is split into HLR-177, HLR-177a, HLR-177b, HLR-177c (LED .98).
- **HLR-177a — a second request is refused while a session action runs.** One refusal per request kind (open Load, the load guard, the variant selector, unload, Save project, Patch Editor changes), each painting the busy line and leaving the session, the focus and the screen stack unchanged (LLR-177.3 … LLR-177.3h); the report viewer's regions are stored only while no session action runs (LLR-177.3i, CR12b-3).
- **HLR-177b — quit asks first while a session action runs.** The quit question opens with the focus on Stay and names the running action (LLR-177.4, LLR-177.4a); Stay keeps the action running (LLR-177.4b); the last answer wins, so a later Stay withdraws an earlier confirmed quit (SR12b-3, C12b-26 (b)); a confirmed quit is withdrawn when a committed Save leaves in-memory work unsaved (LLR-177.4e, SE5-12b-1).
- **HLR-177c — a confirmed quit leaves no partial save.** Quit exits only after the running action's end handler has run on the main thread (LLR-177.4c); a failing save keeps the app running and keeps the entries (the failure arm clears `_quit_pending`).

**The seam (LLR-177.1 … LLR-177.1k, LLR-177.2 … LLR-177.2c).** Three `@work(thread=True)` workers with frozen request/result dataclasses; the session writes and installs stay on the main thread; a worker-step failure ends its run through its failure handler (the end is the handler's last statement), a main-thread handler that raises ends through a posted `_busy_fail`; a non-`OSError` in the Save worker rolls back and reports (LLR-177.2a, ruling Q4); an A2L attach whose open-project folder or source file is gone at the use-time look is refused before any begin (LLR-177.2c, CR12b-2 / SE5-12b-2).

**The indicator (LLR-176.3, LLR-176.4, LLR-176.4a, LLR-176.4b, LLR-177.5, LLR-177.5a).** The `parse_a2l_file` entry point takes an optional progress callback (bytes consumed, total); the parse result does not depend on the callback; `s19_app/tui/a2l.py` returns to the frozen-engine guard's `_ENGINE_PATHS`. The A2L parse step reports its bytes from the worker; the Save worker advances the bar per file placed.

**Corrective pass (E5).** Round 1: the code reviewer blocked on CR12b-1 (a pasted-document write that fails after creating its home leaves the home behind, so the rollback cannot remove the new project folder); the security reviewer's MAJOR SE5-12b-1 (a confirmed quit hides a committed save that left in-memory work unsaved). One corrective pass (Opus) applied CR12b-1, CR12b-2 / SE5-12b-2 (the two pre-begin guards), CR12b-3 (regions stored only when idle), CR12b-4 (`os.fstat` only with a callback), SE5-12b-1 (the quit withdrawal) and CI12a-1 (the reuse oracle re-pin, test-only). Re-review on `c026bd2`: code PASS-WITH-NOTES (CR12b-1 discharged; CR12b-5 NIT declared). Round 2 (tests only, source unchanged except the R2-F1 fix): 22 mutant survivors killed, 7 equivalent, 1 blocked by product defect R2-F1 (a confirmed quit during a routed project load ended in `NoMatches('#result_body')` instead of a clean exit); the orchestrator fixed R2-F1 (no result panel on a routed install when a quit is confirmed) and the final round-2 tally is 22 killed, 8 equivalent, 0 open. Mutants: 115 run → 85 killed / 30 survived / 0 invalid.

**Process decision (operator override 2026-10-31).** Per increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The touched-module run and the full suite are deferred to the batch-end battery (§7). The full new file `tests/test_b100_busy.py` ran once (`green-06-busy-full.txt`), and the guards ran whole.

## 2 · Files modified

Branch history: `b100-inc12b` was branched from `71376a3` (Inc 12a integrated, pre-corrective), merged `b100-inc12a` at `e3b8ec2` (one conflict in `test_b100_busy.py`, resolved as a union at `ef0cdb8`), then merged `main` after Inc 12a closed (`81ac4c0`). Corrective pass round 1 at `c026bd2`, mutation run at `d4d9c1a`, round 2 + R2-F1 + E13 at `ce3a305`.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | HLR-177 … HLR-177c · LLR-177.1 … LLR-177.1k · LLR-177.2 … LLR-177.2c · LLR-177.3 … LLR-177.3i · LLR-177.4 … LLR-177.4e · LLR-177.5 · LLR-177.5a | the three 12b workers and their frozen request/result dataclasses, the main-thread install/failure handlers (`_install_prepared_project`, `_on_project_loaded` / `_on_project_load_failed`, `_on_project_saved`, `_install_attached_a2l` / `_on_a2l_attach_failed`), `_refuse_if_busy` on the 16 entry points and 4 continuations, `action_quit` / `_answer_quit` / `_exit_if_quit_pending` / `_QuitQuestionScreen`, `_progress_forwarder`, `parse_a2l_cached`, `read_only` on `#patch_paste_text`, `show_eta=False`; SE5-12a-4 (the 3 guarded use-time looks), CR12a-1 (the committed tail on main), F-1 (`prepared.target_carry`), F-13 (`os.path.lexists`), CR12b-1, CR12b-2 / SE5-12b-2, CR12b-3, SE5-12b-1, R2-F1. Final sha256[:16] `a6ca42563515797b` |
| `s19_app/tui/a2l.py` | source | LLR-176.4 · LLR-176.4a · LLR-176.4b | the optional progress callback on `parse_a2l_file` / `build_section_tree` (bytes consumed, total), guarded by `if progress is not None`; CR12b-4 (`os.fstat` only with a callback). Final sha256[:16] `73c3820fe0d6ecd2` |
| `tests/test_b100_workers.py` | test | HLR-177 … HLR-177c · LLR-177.1 … LLR-177.5a · LLR-177.2 … LLR-177.2c · LLR-177.3 … LLR-177.3i · LLR-177.4 … LLR-177.4e · AT-B100-18 · AT-B100-17 · TC-B100-53/54 | NEW module (44 functions, 52 items; the routed SE5-11-3 arm and the Inc 11 O-1 xfail) |
| `tests/test_b100_a2l_progress.py` | test | LLR-176.3 · LLR-176.4 · LLR-176.4a · LLR-176.4b · TC-B100-52/73 | NEW module (8 functions, 9 items) |
| `tests/support/b100_workers.py` | test | HLR-177 (the one Q6 wait helper) | NEW module: `settle_workers(pilot)` (`wait_for_complete()` + 2 pauses) |
| `tests/test_b100_busy.py` | test | LLR-176.1l/.1q · LLR-176.2/.2c/.2d · TC-B100-50/51 | EXTENDED: 6 new TC-B100-50/-51 functions (11 items) and 9 re-pinned 12a tests, plus the 4 integration arms (SE5-12a-4 ×2, CR12a-1, OBS-12a-1) |
| `tests/test_b100_load_question.py` | test | LLR-177.3a · LLR-173.7 · TC-B100-72/66 | EXTENDED: TC-B100-72, TC-B100-66, 1 re-pin |
| `tests/test_b100_save_guards.py` | test | LLR-164.4 · TC-B100-07 · CR12b-1 | EXTENDED: the 5 worker-stage arms and the census C1 re-pin; the CR12b-1 regression arm |
| `tests/test_b100_session_reset.py` | test | LLR-165.1 · LLR-165.2 · TC-B100-08/09 | EXTENDED: TC-B100-08 (the reset call site), TC-B100-09, the `_quit_pending` exclusion |
| `tests/test_engine_unchanged.py` | test | LLR-176.4b | EDITED: `s19_app/tui/a2l.py` back in `_ENGINE_PATHS` (node T1) |
| `tests/test_id_registry.py` | config | HLR-177 | `EXPECTED_SCANNED_TEST_FILES` 234 → 237 (measured, F-20; the bump names `tests/test_b100_workers.py`, `tests/test_b100_a2l_progress.py`, `tests/support/b100_workers.py`) |
| re-pinned test files | test | HLR-177 · HLR-177a · HLR-177b · HLR-177c · LLR-177.1 · LLR-177.1k · LLR-176.3 · LLR-176.4 | the re-pinned nodes of `inc-12b/E4-tester-notes.md` §"Re-pinned tests": the 7 `_flush` files plus the 3 census misses (`_flush` → `settle_workers`), `test_b100_save_dialog.py` (6), `test_variant_execution.py`, `test_b100_project_check.py` (the 3 `_timed` wrappers + the timing bounds), `test_b100_save_image.py`, `test_help_toggle_and_a2l_panel.py`, `test_tui_app.py`, `test_tui_variants.py`, `test_b100_project_homes.py`, `test_b100_document.py`, `test_b100_reuse.py`, `test_b100_load_dialog.py`, `test_b100_recents.py`, `test_examples_pilot_gifs.py`, `test_b99_staging.py`, `test_b100_focus.py`, `tests/support/b100_projects.py` |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-177 … HLR-177c · LLR-177.x · LLR-176.3/.4x · the extended earlier ids | E1/E4/E5 edits (LED .98–.100) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-177 … HLR-177c · LLR-177.x · LLR-176.3/.4x | LED .98 – .100 |
| `.dev-flow/BACKLOG-CODE.md` | doc | LLR-177.x | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-12b/*` | doc | HLR-177 … HLR-177c · LLR-177.x · LLR-176.3/.4x | the experiment records: `E1-scope.md`, `E1-rulings.md`, `E1-requirements-draft.md`, `E2-rulings.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-022.md` | doc | HLR-177 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/*` | generated | HLR-177 | transcripts (evidence digest table at the end of §4) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | HLR-177 | orchestrator-owned: scenario `qz-quit` |

## 3 · How to test

```bash
# from the worktree root; interpreter C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
# the new worker modules (every node):
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_workers.py tests/test_b100_a2l_progress.py
# the new/extended busy arms:
python -m pytest -q -p no:cacheprovider tests/test_b100_busy.py
python -m pytest -q -p no:cacheprovider tests/test_b100_load_question.py -k "tc_b100_72 or tc_b100_66"
python -m pytest -q -p no:cacheprovider tests/test_b100_save_guards.py -k tc_b100_07
python -m pytest -q -p no:cacheprovider tests/test_b100_session_reset.py -k "tc_b100_08 or tc_b100_09"
# guards (the frozen-engine guard, the registry, the staging re-pin):
python -m pytest -q -p no:cacheprovider tests/test_id_registry.py tests/test_b99_staging.py tests/test_engine_unchanged.py tests/test_address_census.py
# mutants: evidence/inc-12b/mutation-summary.md (115 rows) + mut-r2-*.txt (the E5 round-2 kills)
# NOT run per increment (operator override 2026-10-31): the touched-module run and the full suite -> batch-end battery (§7)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/`. **Final source hashes** (sha256[:16], verified with `sha256sum` at close): `app.py` `a6ca42563515797b` · `a2l.py` `73c3820fe0d6ecd2` · `styles.tcss` `f7b4f75911b296a4` (unchanged). Branch history in §2: `b100-inc12b` branched from `71376a3`, merged `b100-inc12a` at `e3b8ec2` (union fix `ef0cdb8`), merged `main` after Inc 12a closed at `81ac4c0`. Import proof in every header; `NO_COLOR` unset.

**Scope (operator override 2026-10-31, stated plainly):** run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The whole touched modules and the full suite are **deferred to the batch-end battery** (with fix rounds for failures found there). The full new file `tests/test_b100_busy.py` ran whole once (`green-06-busy-full.txt`, on the final source); the guards ran whole. First-run failures are kept and reported as such: `green-01-new-run1-failed.txt` (the `_answer_quit` SR12b-3 alignment), `green-02-repinned-run1-failed.txt` (F-21 fixture race + the 4 timing bounds), `green-02-repinned-run2-failed.txt` (the 4 timing bounds before F-23), `guards-01-run1-failed.txt` (tc607 bound before F-20, TC-027, the recompute timing arm), `guards-01-run2-failed.txt` (F-22, the F-21 fixture, TC-027). `green-04-new-and-guards.txt` reports 1 error caused by a stray `recent_sources.json` written by a debug script (see `E5-corrective-notes.md`); the rerun `green-04b-guards-rerun.txt` is clean.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | TC-B100-53/54 + AT-B100-18/17 (`tests/test_b100_workers.py`), TC-B100-52/73 (`tests/test_b100_a2l_progress.py`), the TC-B100-50/-51/-72/-66 arms (`tests/test_b100_busy.py`, `tests/test_b100_load_question.py`), the TC-B100-07/-08/-09 arms (`tests/test_b100_save_guards.py`, `tests/test_b100_session_reset.py`), and the re-pins | `executed` — `green-01-new.txt`: **89 passed, 1 xfailed** (973.4 s); `green-02-repinned.txt`: **2 failed, 317 passed, 4 skipped** (1511.7 s; the 2 failed are a timing bound and the MAX_PATH block, both re-run); `guards-01.txt`: **2 failed, 380 passed, 7 skipped** (2704.4 s; the 2 failed are TC-027, expected on the branch, and the `last_row` scroll flake); `green-03-corrective.txt`: **8 passed** (38.1 s); `green-04-new-and-guards.txt`: **162 passed, 29 deselected, 1 xfailed, 1 error** (1346.1 s; the error is the stray debug file); `green-04b-guards-rerun.txt`: **44 passed** (94.5 s); `green-05-ci12a1-reuse.txt`: **2 passed** (94.0 s); `green-06-busy-full.txt`: **109 passed, 2 skipped** (357.5 s); `green-07-mutant-arms.txt`: **26 passed, 1 xfailed** (86.6 s); `green-08-r2f1.txt`: **8 passed** (111.2 s) |
| **B · black-box** `AT-NNN` <-> story | `core` · `full` | AT-B100-18 (four halves), AT-B100-17 (parse half) | `executed`: in `green-01-new.txt` and the round-2 run; RED `red-01-vs-base.txt` fails them on `71376a3` (no workers, no refusal, no quit question) |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| E4 tester's new tests vs base `71376a3` | `red-01-vs-base.txt` | **108 failed, 195 passed, 1 skipped, 1 xfailed** (2001.5 s) — 80 of 80 new 12b items RED (the "held step ran on the main thread — the action has no worker" family and the other behavioural reasons), 24 behaviour/structural re-pins RED by construction, 4 environment/host-load failures (the MAX_PATH block and three 1 s timing bounds on the base under host load); the 195 passes are the wait-only re-pins |
| E4 integration arms on the pre-fix source `ef0cdb8` | `red-02-integration-arms.txt` | **1 failed** (3.9 s) — the CR12a-1 arm (the committed tail still paints `Saving project S3 failed` after the F-1-only fix); the 3 other integration arms (SE5-12a-4 ×2, OBS-12a-1) are listed in the transcript |
| E5 corrective arms on the pre-fix source `81ac4c0` | `red-03-corrective.txt` | **8 failed** (38.1 s) — the 8 new test nodes, each for its intended reason (CR12b-1 home rollback, CR12b-2 both arms, CR12b-3 regions, CR12b-4 fstat, SE5-12b-1 scenarios A and B) |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| the worker thread | `red-01-vs-base.txt`: every thread-id and timer arm fails on `71376a3` (0 ticks in 8.76 s / 5.81 s, `ran on main thread True`); `_a2l_cache_*` written off the main thread on the base file-load worker (LLR-177.1d) |
| the busy refusal | `red-01-vs-base.txt`: no busy state exists on the base, so every refusal arm fails; the CR12b-3 arm is RED on `81ac4c0` (regions written during the Save) |
| the quit question | `red-01-vs-base.txt`: no `action_quit` on the base, so `q` exits with 0 questions; the SE5-12b-1 arms are RED on `81ac4c0` (the app exits over a save that left work unsaved) |
| the byte callback | `red-01-vs-base.txt`: `parse_a2l_file` / `build_section_tree` take no callback on the base (TC-73 RED); the CR12b-4 arm is RED on `81ac4c0` (the no-callback parse calls `os.fstat` and raises) |
| the `a2l.py` freeze | `red-01-vs-base.txt`: the base `_ENGINE_PATHS` lacks `a2l.py` (LLR-176.4b); TC-027 fails on the branch (CONFLICT-1, owed after the merge) |
| the CR12b-1 rollback | `red-03-corrective.txt`: `folders == ['freshd', 'patches', 'temp']` on `81ac4c0` (the created home is left behind), `['patches', 'temp']` after the fix |

### Mutation verdicts (C-40)

**E5 run on `81ac4c0`** (`mutation-summary.md`; every transcript ends `restored = True`): **115 rows total. 85 KILLED, 30 SURVIVED, 0 INVALID, 0 TIMEOUT.**

| Verdict | Mutants | Disposition |
|---|---|---|
| KILLED | 85 | each failure read for a behavioural assertion, not only the return code |
| SURVIVED, killed in round 2 | 003, 039, 042, 047, 048, 050, 054, 057, 065, 067, 071, 072, 079, 082, 087, 090, 091, 093, 099, 107, 110, 113 | killed by 20 new or strengthened arms and 2 existing tests (`mut-r2-*.txt`); 099 and 110 were called equivalent in round 1 and refuted |
| SURVIVED, equivalent | 002, 021, 022, 052, 060, 084, 103 | recorded, no code change (round 2) |
| SURVIVED, blocked by R2-F1 | 046 | the only observable difference is under a confirmed quit during a routed load, where the code itself failed (`NoMatches('#result_body')`); after the R2-F1 fix it is equivalent |

**Final count (E5): 85 KILLED at first, 22 survivors KILLED by round 2 (107 killed of 115), 8 equivalent, 0 INVALID, 0 non-equivalent survivors.** The round-2 tally is in `E5-corrective-notes.md` §"Round 2 follow-up": 22 killed, 8 equivalent (002 021 022 052 060 084 103 046), 0 open.

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| the workers | each worker takes one request argument whose class is a frozen dataclass (3 of 3); an AST census over the worker bodies and every `app.py` method they call holds 0 reads of the session attributes and 0 `self.*` writes (LLR-177.1d, LLR-177.1e) |
| the refusal | `_refuse_if_busy` is the first statement of the 16 entry points, the 4 starts, `_confirm_then_load` and the continuations (26 call sites); the busy line holds 0 decision ids (LLR-177.3f, TC-B100-66) |
| the quit question | `_QuitQuestionScreen` subclasses `ConfirmQuestionScreen`; `self.exit()` has only the 2 call sites (idle quit + `_exit_if_quit_pending`); the question paints `Quit?`, `still working: <label> — wait, or quit after it finishes`, `Quit (y)` / `Stay (n)` (LLR-177.4a) |
| the parser | `parse_a2l_file` takes the callback keyword; `build_section_tree` changes only `if progress is not None` guards and the `fstat` (CR12b-4); the no-callback parse is byte-identical to `main` (`a2l_identity.out.txt`, digests `805436eb7b0481ad` / `6f639af9b95ec67e` / `c906f5d41df95174`) |

### Guards and snapshot cells

| Run | Transcript | Result |
|---|---|---|
| guards (kept) | `guards-01.txt` | **2 failed, 380 passed, 7 skipped** (2704.4 s) — `test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` (CONFLICT-1: `failed`, expected on the branch, owed after the merge) and `test_b100_save_dialog.py::test_tc_b100_65_last_row_reachable_by_keyboard` (scroll not settled; run in parallel with `green-02`; re-run alone once passed) |
| guards re-run | `green-04b-guards-rerun.txt` | **44 passed** (94.5 s) — `test_id_registry.py` + `test_b99_staging.py` after the stray debug file was removed |
| the 29 SVG snapshot cells | — | **not-run** (CI-only regen, `.github/workflows/snapshot-regen.yml`, after the merge — SR12b-5); `show_eta=False` changes the cells that painted the idle ETA `--:--:--`, expected to drift until then |
| the census sweep (`-k census`) | — | **not run** (operator ruling; batch-end battery) |

### Reviewers' probes

The code reviewer executed `p2.py` (the CR12b-1 scenario on `81ac4c0`: `left in workarea: ['freshd', 'freshd\\patches', 'patches']`, then the re-run on `c026bd2`) and `probe_a2l.py` (the CR12b-2 `FileNotFoundError [WinError 3]` leaving `load_a2l_from_path`), plus AST censuses of the worker `self.*` reads/writes and the refusal sites. The security reviewer executed `self_reads.py`, `a2l_identity.py` (3 public fixtures, branch-no-callback == branch-callback == `main`), `probe_sr2.py` (direct + deferred-callback arms), and 2 test nodes (`6 passed in 49.55s`). The full suite and the touched modules were `not-run` in both lanes (out of scope; batch-end battery).

### Security probes

`security-increment-022.md`: SE5-12b-1 (a confirmed quit hides a committed save that left work unsaved — MAJOR, fixed by the `_quit_pending = False` withdrawal), SE5-12b-2 (the A2L attach exits the app when the open project's folder is gone — MINOR, fixed by the two pre-begin guards; the two sync helpers go to BACKLOG-CODE), SE5-12b-3 (the R-B1 time-of-check residual no longer matches its premise — NIT, re-worded at close), SE5-12b-4 (the 3 install handlers write before their generation check — NIT, documented in interfaces S-d at close). The E3 mitigations were re-verified: no session or widget write off the main thread, the immutable requests, the busy rule on every entry point, the quit question, the save rollback after `mkdir`. Full per-question results in `security-increment-022.md`.

### E13 (C-UX-5) evidence

Orchestrator-owned captures, real Windows Terminal: scenario `qz-quit` (loads project `P`, patches `place_into_workarea` so the Save worker sleeps ~60 s on its first placement, starts a Save of `P1`, then `q` with the quit question open and the Save still running). Painted: title `Quit?`, text `still working: Saving project P1 — wait, or quit after it finishes` (wraps to two lines at 99), buttons `Quit (y)` / `Stay (n)`, the focus ring on `Stay (n)`; the busy line under it `Saving project P1 · step 2/4 Place the files · 00:05` (00:06 at 220), the progress bar at 25% with NO Textual ETA (OBS-12a-1 fixed). **3 PNGs** in `evidence/inc-12b/e13/` (`qz-quit.118x54.png`, `qz-quit.220x60.png`, `qz-quit.99x54.png`), `DONE failures=0` (`E13-notes.md`). OBS-12b-1 (the stale `bz-busy` `_parse_loaded_file` override in `tools/e13/run.py`), OBS-12b-2 (the quit-question button variant) and OBS-12b-3 (the fixed-length log-row cut) → routed at the close (§6).

### Experiment step table (from `inc-12b/steps.log`; UTC)

| Start | End | Step | Agents | Outcome |
|---|---|---|---|---|
| 14:55 | 15:30 | E1 | 1 x Opus | 39 requirements; rulings Q1–Q7 |
| 15:31 | 15:31 | E1 rulings | orchestrator | Q1–Q7, all as recommended |
| 20:03 | 20:03 | E2 baseline | 1 x Opus | 58 nodes |
| 20:05 | 20:36 | E2 prototypes | 1 x Opus (P-1 G-A+G-B 39 nodes / 84 examples, P-2 G-C+G-D 27 nodes / 62 examples) | proposals ruled; interfaces-12b.md fixed |
| 20:36 | 21:19 | E3 (2 rounds) | 2 x Opus (architect ∥ security) + 1 design-fix by DeepSeek v4 Pro | r1: arch PWN (1 MAJOR census), sec PWN (1 MAJOR quit-hides-failure); r2: both PWN (0 MAJOR); E3 closed, addenda S12b-01 … S12b-07, A12b-01 … A12b-04, DF-1 … DF-13, R2-01 … R2-05, S12b-R2-1 … S12b-R2-4 |
| 01:01 | 01:24 | E4 implementer | 2 x DeepSeek v4 Pro (app.py G-C1/G-A/G-B/G-C2 ∥ a2l.py G-D) | app `89b2d043c60f3a2f` (3 deviations, +1577/-1224), a2l `d70b17982f1cee30` (2 deviations) |
| 01:01 | 02:25 | E4 tester | 1 x Opus + 1 sub-agent | 82 new items (80 RED), census re-pin; RED 108/195 on `71376a3`; A-1 … A-10 ruled |
| 02:27 | 02:27 | merge | — | merged `b100-inc12a` `9012835` at `e3b8ec2` (union fix `ef0cdb8`) |
| 02:27 | ~06:36 | E4 integration | 1 x Opus (software-dev, 325 tool uses, ~4h09m) | app.py 1 source fix set (F-1, F-13, SE5-12a-4, CR12a-1, OBS-12a-1); SR12b-1 … SR12b-7 accepted |
| 06:36 | 06:58 | E5 | 1 x DeepSeek v4 Pro (mutants, 115 rows) ∥ 1 x Opus (code review) ∥ 1 x Opus (security review), then 1 x Opus (corrective round 1) | reviews code FAIL (BLOCK-UNTIL CR12b-1) / security PWN; mutants 85/30/0; corrective CR12b-1 … 4, SE5-12b-1/2, CI12a-1; app `46f7ee6aa8a0fbfb`, a2l `73c3820fe0d6ecd2`; red-03 8 failed / green-03 8 passed / green-04 162 passed / green-06 109 passed |
| 07:22 | 07:26 | E5 re-review | 1 x Opus (code-reviewer) | PASS-WITH-NOTES on `c026bd2` (CR12b-1 discharged; CR12b-5 NIT declared) |
| 07:39 | 07:40 | E13 | 1 x DeepSeek v4 Pro + 1 x Opus (visual check) | `qz-quit` 3 PNGs, failures=0; OBS-12b-1 … 3 |
| 08:15 | 08:25 | E5 round 2 | 1 x Opus (tester, tests only) + orchestrator (R2-F1 fix) | 22 killed / 7 equivalent / 1 blocked by R2-F1; R2-F1 fixed, green-08 8 passed; 046 equivalent post-fix |

First step start to the last logged step: 14:55Z (2026-10-31) to 08:25Z (2026-11-01) = about 17 h 30 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 1 MAJOR in each round-1 review (A12b-01 census, S12b-01 quit-hides-failure); E5 (code) caught 1 MAJOR (SE5-12b-1) and blocked on 1 MAJOR (CR12b-1); 1 corrective pass + 1 mutant-kill round + 1 orchestrator fix (R2-F1); 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/` | SHA-256 |
|---|---|---|
| qz-quit.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.118x54.png | ab91bfed4bece7d3bc83c901a08fec51ba7eb1d4708744828f044aa22ef53787 |
| qz-quit.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.220x60.png | f73dc43241ed27c98a6e2c98f7450614ac5a7c59c36181a46c2ec42272d19a3e |
| qz-quit.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.99x54.png | febd8cf1a0ffb44809881997a76a98891e8303642280aa6b39d27b8d73568907 |
| green-01-new-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-01-new-run1-failed.txt | 903de92ee6366f4b654c89928c41c1efd535ca0af03933d2adb637710236a30c |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-01-new.txt | 4f585790b2fe4803d09c29817b408ba6d6da5d5ccbb2e0562cbc7caad33e7d76 |
| green-02-repinned-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-02-repinned-run1-failed.txt | 0a2c42ec30cfb7538acfd5481eb986b69f80f408adc28e8ca66fc42b202248f9 |
| green-02-repinned-run2-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-02-repinned-run2-failed.txt | 1edd1c43c0cc29f3d3d9a75da8dfea95c2eb8b692ab52fd11a3d67de890f8c04 |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-02-repinned.txt | 63e3094771b060efe254b8f017a458761019e86586502d5a6954e52bf6fe3ec1 |
| green-02-timing-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-02-timing-rerun.txt | 7c2f5c8a24fcd1d022a1e01444682e1b1f28c3e9265cb3eacb455e9728d0977d |
| green-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-03-corrective.txt | c6b4b25bae2eaeceba470c800c13b6a2aca15d2deff7c23b6bdb7a9d5f64eed3 |
| green-03-merged.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-03-merged.txt | d208a9c13a458e28e73a566c66b22c746f8ddbf7f971cf1468ca2341f27aeaae |
| green-04-new-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-04-new-and-guards.txt | 07479b04b2d2c8f63c6b0d8b81a0b7b7e19dd71d2948d130479314b5ced3fb0c |
| green-04b-guards-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-04b-guards-rerun.txt | 3202da36ff1258aa28637cd6bdd2ce0858d63dd9ef913e21a375d77d26a759a3 |
| green-05-ci12a1-reuse-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-05-ci12a1-reuse-base.txt | c0a4b9d261c49ab2103916b96f63fdd754eb490aad49bd7217ffe8a3a90318fa |
| green-05-ci12a1-reuse.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-05-ci12a1-reuse.txt | 7229ecac3fd67aaacc2ffd6c0acf8c4da2a594fa08aba2bc6bc8972afdbfdb45 |
| green-06-busy-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-06-busy-full.txt | 47c55aec176a9731b04f9a5ad203ddbd3227024502d0569d6d913cab8db54744 |
| green-07-mutant-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-07-mutant-arms.txt | e54bb4234696bfee024604996090004a66ccfaebe391522c1455873caf2c2b17 |
| green-08-r2f1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-08-r2f1.txt | 97ed0bbcae2c1e6b0e86d336f4c96d1a45a90234153bd0cd4e0e1f8b8f279be2 |
| guards-01-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/guards-01-run1-failed.txt | bf871cf81cae346a874af4a561517be810346b875ecc5c10a07ca42c3b27caff |
| guards-01-run2-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/guards-01-run2-failed.txt | 1e3746cb2b9b7176ed4a84c13da31eda7e22080ebd86c3c66d59a812e3e06cf6 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/guards-01.txt | da25c1aa66fc0535fd021dbf1e38850e5de6bebf45a4acb82c08a6496d08d743 |
| mut-001.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-001.txt | a8c3898f64a868a46797edd3dc0b3c6f09aeeff48dde09b5cc085f8a699edbe6 |
| mut-002.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-002.txt | 8df15794eea0df035089e98eb73e23ab27553adc5f02fbde971523d19fbef5c8 |
| mut-003.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-003.txt | 476fbf5e6e202788f2d0440fa732aea98111faf5b7a84355a7db4a86bbecbb08 |
| mut-004.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-004.txt | 0c970894ffc6c2bef16898e4f7f2abfef43f6146b22f396abbb21a296629c582 |
| mut-005.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-005.txt | c2ce6920e9120ba6e08ebbee8c2423230d3cb60e33011b42000826a1cc104a64 |
| mut-006.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-006.txt | 499b9a9e3c7588b0e9374fb9734e594ec5828d8240f68c905812c9f7567b7c10 |
| mut-007.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-007.txt | 689518d0e8638331579446efd88c7630d75775bbae42e07f146387477ae0265c |
| mut-008.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-008.txt | dcc8d0ffac5d85c51173b4971e04a8d0edc7b8a4eabeb503851128e6c7be2aae |
| mut-009.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-009.txt | 6e3623c2c0f37edcf9e6bbe3624e90fe080cf35a6e8a67bb155c8205baa337a0 |
| mut-010.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-010.txt | 3d53d16a6f0d98d2df0614eb05bb1883823d93b217e4813fbc52e5014f6d4f8b |
| mut-011.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-011.txt | d72b67a2987d00482c223819dad96cf9a79bc8096acba4529234056f7eaf24d8 |
| mut-012.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-012.txt | 46abab57c01e668c095de6adece38561938a70491e70996c33c86ffeccd6fb0b |
| mut-013.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-013.txt | c71318ee8b702c99a0732ab074dce507e745083b794cb9ea4622b31885261fc7 |
| mut-014.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-014.txt | 305782ddcf1ad353e4cbaff33b08854ab57c632ee81f395b6ba54faeca0ad631 |
| mut-015.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-015.txt | 75ffd1028aada832f52272a7b1749284594fa1143b29af6b0e6b67cb7e19594b |
| mut-016.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-016.txt | 4b04b017174a93eebf29ce199e521211122e5323a4ca4b92443a71ccc3774c97 |
| mut-017.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-017.txt | 276f67bc0fdd8309efd6146763d2cef3c24f830f609e46352377cfafb7f423a3 |
| mut-018.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-018.txt | edb9281b221cb42b9aa6ea2e599979137559337d0a39630bd6b9dec6ffeeddbe |
| mut-019.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-019.txt | d156b22cdcc1141786becca2b8422769c4b7b0040990e3f0f75acccc26f04327 |
| mut-020.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-020.txt | a0c2e93c09e43c808f704b8f67e7e5796cd2005ba325909d326467d9c9e06fb1 |
| mut-021.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-021.txt | 386e138f8cee127113d56d3b9441d4fc250a1c61ca9051384eac5ce1f9a58586 |
| mut-022.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-022.txt | ce86a1f4680e50a157b7b3659f9224c6b2be139b2ad5f639785b4466cc9199c5 |
| mut-023.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-023.txt | 9ff313b73418774898566399346caf782dc258f3dcdf4feb30866ccd8605dd02 |
| mut-024.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-024.txt | 45c8b2ab72e5dd8fbd2c274742cedc28009e821d28ee01c61ed57c6e9312d131 |
| mut-025.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-025.txt | 922f1ee22f6ae24fe209d2380aab9cf07aeafb40662edcbe21f1025b1c8962c5 |
| mut-026.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-026.txt | cafe8b0304a1db74276d5157540ab8e1ea22d3b6eff983a08531b7c727bb52ab |
| mut-027.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-027.txt | e35f73c0039ecb2689676140ac01157e939644ae6ddca9f673d30f375397b51e |
| mut-028.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-028.txt | 694e6594d44df78c4368e9ca9fdc87bfd8f40ffc70a71731081c26af975857b2 |
| mut-029.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-029.txt | 8444371b516485b8ca03589965af391b4cc5b3c2f4687b3e092c18e3f0f4e8f2 |
| mut-030.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-030.txt | 20d628dee49f174b8ffa627f4b0264eda2a0d6c808c600c040cf8211a311a39e |
| mut-031.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-031.txt | 17f9e0f324d4ea642a8e5dd1396e3559a8af88a0cc6c06af2bb24d86335f2737 |
| mut-032.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-032.txt | eb740499d58c01cc171fb2a672f9ada6fc4a831f67d27b7fd904c9154f7c411c |
| mut-033.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-033.txt | 1f1b3d36b441c3a5ffc031dcadad5545d7ce69eab26d8627091a43d645e156c6 |
| mut-034.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-034.txt | d0351ca0060a355cc110c164aaa7a9968cc1988f97740185201b4e54964160b8 |
| mut-035.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-035.txt | b7b7509d498ce4e10863d6fa305ca908cae13d056aa4696deefdb7d6e111a3ed |
| mut-036.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-036.txt | fbac44f2a5a984f23ab60a91261b7f28f1c1107820a59a1f0f4dcd89918a6008 |
| mut-037.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-037.txt | 18061527bc610ebb46607d489297f93d11d945ea80244bc6552ac0cd289a6429 |
| mut-038.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-038.txt | c630b91f6dabdf4ab5508f96ef08d10d17e4466018e462b8aef6c6298cf1b862 |
| mut-039.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-039.txt | 74640f252e4b6331e3cc78a778500ad351f69b40ba82593f7fb1ad16eb07e225 |
| mut-040.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-040.txt | 0ac4d9509b705f8630446d66e6308f9c7ae44326459f2ad4d84aa433a535e813 |
| mut-041.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-041.txt | 660fb625f7f7e901b4de3bb6a830abd9e085c497a2d960fac9c957b19de1caed |
| mut-042.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-042.txt | 3fbc5fa4d692d4bf518d77e88bdda6f59e745700159fc85aae67ea14bf97527b |
| mut-043.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-043.txt | 53d68c18c1871ad64317fd57f6c9f9e6807c948de66d9f17792b2ddc4329c299 |
| mut-044.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-044.txt | 6b3375ec9092f32843f68275f0bb4f50b96ce288776f9b3f6c8662803b61f948 |
| mut-045.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-045.txt | fefddd89a4fdbf10576625043480fa2a1ba13078ef5394c94e63353ed56f0e8d |
| mut-046.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-046.txt | de93759908b1ccb74c910439ba060aa46e7984958b0ba419cc2d217a85ac14f8 |
| mut-047.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-047.txt | e6ff3ec3213fbbff566685a4991bd2041105ca0498aa954a92191c88ddcd486d |
| mut-048.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-048.txt | 7f24cfa45a5531f0a97121be29473dcd2604b271557e386e0a7e1cfcf0abae6e |
| mut-049.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-049.txt | 12ff0c75bf05d58fa93e58f78c1a9c0812d194fc45177c2810bd8925ebfd9922 |
| mut-050.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-050.txt | 1b8a5dc5249d8e91decd808855157c25012f59f0a26faaac9c3d8b1e5db7f0b2 |
| mut-051.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-051.txt | 77b81c98f2a57e778e96dacff548a644a8e044890e0a3f7db7726c171e2bfaa8 |
| mut-052.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-052.txt | 1d26a6e489b321b69a8aa9f6b3104c6afc729b1106e3092a5d8f46a95d9db6b6 |
| mut-053.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-053.txt | 858e8feed56ecf50b833530f13ba0e11789679048d54f6df37b7db2203509518 |
| mut-054.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-054.txt | d7a6ae5fb7c49976208d33b30e5faf3bd1f7f7fca9fae2e775d4f8b94bc6c29f |
| mut-055.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-055.txt | ccdd3ddcbe63dc4eb1b7a2b9480a8de2dcd2b05003263b7685f515bfb9d4b37c |
| mut-056.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-056.txt | 3a67a9db6350ef6ff485ab0208772c242e91537d88a700f8737124d006bfe9d8 |
| mut-057.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-057.txt | 718a0f88df43ca1e8d9ad8c1e11f76fe235ae7452ed019262c80105993d14f7e |
| mut-058.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-058.txt | 33322d0b17f89c6c1f9f9097c464adc8c11c16199fe672df2390b8ebe0bd89ec |
| mut-059.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-059.txt | 18a7a3e59bd2c68f82879371076259d460208341be467c4d711fe9a497f71ee7 |
| mut-060.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-060.txt | 2741e94b2766973905d40f054c244821d9be8cba4cca509dc2a80fa6f0b328e1 |
| mut-061.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-061.txt | dd5054e6bb5c305d1f60f80d2b067c45a34b27c0f467075ee6e0571f43b6ca72 |
| mut-062.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-062.txt | 6f5c1d1e7109e2006531b8f359e6286b658deadf49223f75ac1738acb2df35d1 |
| mut-063.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-063.txt | bb1599baf83e9ce35086471e9273a0816f3d0073365448cc534c5652c64843f7 |
| mut-064.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-064.txt | 3e322a4fa4dc0efdfdb817e5fc984b4a13b3ec2944efb257efcb3a890a373967 |
| mut-065.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-065.txt | 308d1882e1d9f382bfe8647d43bc9724ed525a03184748405fd8eb6e3fd54ffe |
| mut-066.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-066.txt | 3d61da7aed5834d1eae4634d10ceeb41ada693c40bbda0e730e97378feae5cae |
| mut-067.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-067.txt | 2ecb9d088c640645bdca0561e0fecee3807348b08e668eb1f0fa338f131ef208 |
| mut-068.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-068.txt | 7af7793d829d5ba27a9811a4b57faa03359c9e82f16e17f16e0be4a2ebff5616 |
| mut-069.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-069.txt | dc413adfd56f84e6c0fcba2043dbb61209a9f50f9ddae2feb39f54fad9ed900c |
| mut-070.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-070.txt | 6c2ad97361dd0f246b74da7b0f188453af9ff00cba8ca73091092f6435ec0877 |
| mut-071.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-071.txt | 52c93904509c81a53a29c60209fdccae217d7410b74a4472dcb34726789996e5 |
| mut-072.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-072.txt | cc6532794a8f1f5d502bf76e76c7ed1fb5972988e9dcc9afb6677ff399b07f07 |
| mut-073.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-073.txt | c1ce4cae4844967c53dfcf9011f915cce2514bc84b69406f03c040846ff22dd1 |
| mut-074.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-074.txt | 132abac037ed8d6d77737343063a7528fdb0501aa5508579587ff452e6567a5d |
| mut-075.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-075.txt | 5afa660d04b8ba567148b3ca2cabf66e18d101cbeb06e1f0567fcfff9148713c |
| mut-076.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-076.txt | 58500561e28bb92a673baf8a62bcc814a3e762be7f73af2e5fce0fdda4af6f5c |
| mut-077.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-077.txt | 9ef0b7c1a8f278652ece8d889342444451476fdfac7845a06ceb53e857bb8bca |
| mut-078.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-078.txt | 26e42daeddee20bf1ef4ba14da7364b0c312a127d5776b564a1f90eb71cc2e49 |
| mut-079.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-079.txt | 8727211f15bfb879b50ab236c36d69686b2d6bc8b04577a5bb6743b589c8ef4c |
| mut-080.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-080.txt | e658c43366d82ff1d67e0cecde5ec85f8134ae3a3c5d6546da352dd81df646e9 |
| mut-081.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-081.txt | 3331678fe123eada91255314e9d2342252a9e1bbea85b253dade84c39693bf79 |
| mut-082.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-082.txt | 41a9945a38b99af5c1c7910131040a649f0214d2c0fac3e5b74ecd1f3746923d |
| mut-083.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-083.txt | b613cc510eb6d3fb804cb8bbca0ec9ea7cc08f928846d15ff0ed12cc374dbc69 |
| mut-084.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-084.txt | 04ba1d118b5fd0c456f19e2db6e236ce8fa8b012e32ac7a19943a54daf860952 |
| mut-085.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-085.txt | a0e3ed952710bc2a79e6348cb66c6ebb422e456a85f00e538ec1a67d4962a456 |
| mut-086.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-086.txt | 1025f9a01422d9b738db1415cfef99093fc51522b3e7312a815f68bb80805af2 |
| mut-087.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-087.txt | 67e45fbf73ab5296f30392b31033b0cae948342291e4353a913fe627aae538d1 |
| mut-088.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-088.txt | 16746a8b3c5f48cc92791ba26aa86c3b5aaaf9cc08d0129011cd6aee2b3cf396 |
| mut-089.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-089.txt | 9a5617f320eb9a7f6b2b56a64ba34eea0253a4b965635ec0165b50c50019e720 |
| mut-090.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-090.txt | c2f901dafb04266522cd20961b0aa0bb7d39b48e78604925d7ecf60324b3355b |
| mut-091.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-091.txt | d09cf1e6fa52d0b4c6fdfe3bfa8ceac64455de468a24e98a7a69752e36511f5f |
| mut-092.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-092.txt | 4007319967ef6a1ab3552392ae9cfe12fe4d2fca64e8922e67dc4140cbe6d159 |
| mut-093.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-093.txt | d0c9778f87468b8cac04bc0669602f351373b2f8f94c119a648600a8bc7037e2 |
| mut-094.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-094.txt | acf3fbaf3bcdf6b1838aa5bea7dd31be982481067bb8465a5d88fc1ba5114408 |
| mut-095.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-095.txt | cf7fc1c0a8ad57a6762416e69a5605ca7b208946913891f275260957c5be530b |
| mut-096.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-096.txt | bf51e8818eb8b6c3c3821ecd2319849e343582fab5fe921c152b96f5389a2953 |
| mut-097.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-097.txt | cd6f5abd5cfe1a4eeaedcb96f55cf6c571e52acb748e6984c33636bc95b7079e |
| mut-098.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-098.txt | 85d871e0e5244453320e4456dbe93823073a3d1adfe514d07b408f659748fbdb |
| mut-099.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-099.txt | 3992cddaf6c0aa298e85d1aa333e0c8c4fd8881e33f9ca336317d97ef8d8c126 |
| mut-100.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-100.txt | ad5f0db5e598179fe94cb34e6693401eb352a7221f99a6039ebca77fa88db52a |
| mut-101.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-101.txt | 0a625afde87e6adb0fa68f7b52974e3f993e5a0110c2603497753002f0eb8c47 |
| mut-102.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-102.txt | 880529fc775332b4eeb71bd0e4b5581571d8644698100f6e33a499f22fb3f135 |
| mut-103.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-103.txt | acbb71489bba7b9d14fac4d657cce211e1ab89be08f4bb98fac0b45fec21daa2 |
| mut-104.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-104.txt | c5a70b60c821a7a0f7746a57969247f0b8c34d5bddfad721c710b91ac0e7576a |
| mut-105.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-105.txt | 41f07feb630161c7f7642eb35b563c01bb1c693e22a93464727e49bd53b754bd |
| mut-106.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-106.txt | 2b033e8c42632fd93c6b91e7e2eda062423fca0827a6a48d68c63e2b34557bab |
| mut-107.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-107.txt | 5cfba6dbdfd5ce90e9bb2570cae14faea2ad4f9dbcdc020ed2d8112ea31498c9 |
| mut-108.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-108.txt | 9ad26496294d8e324b1484f2a3db0467c2cb5c34bfd9fec0ecb0f97d260f0ee9 |
| mut-109.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-109.txt | 14965b458b5c8e00236cad9fc2a0c339108d7467f01972c81041f2dab2d18eb1 |
| mut-110.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-110.txt | 743b7d9b52541becfc357690181a319f2c49610a254bf3f14e6b17c5eed8a003 |
| mut-111.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-111.txt | c097fb690a5de40090e6b12b008ea2cb5d7ffd9119bdf6abcc611c9194ec70d6 |
| mut-112.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-112.txt | 839296042360a1b06f7736e7f39f805c99fd39f9aafda113620e46f45b8e7c76 |
| mut-113.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-113.txt | c6157d886efdf68fb8c5d68076a3c0c76d2809136a8dd0f5fd40abbca4d3336c |
| mut-114.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-114.txt | 9c27e3fd98a4a65811d7bdbe2aef4bc3415448b8e3fab40183836faccfa05bda |
| mut-115.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-115.txt | 2c77dff7c43f59f1730335cd6b2c34d0f4f58ed2a03d9fda5fe8bf42920c482a |
| mut-r2-003.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-003.txt | 7239912884f898d04450bcc69c8b510688fe4e9e9977d80c2f74bef1a05ae6ab |
| mut-r2-039.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-039.txt | e71c42103d4ab7f00ab50ee7fb5b215334529a15856b7e2f63bf1fc44abac30b |
| mut-r2-042.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-042.txt | 6ea09a4e86e6f6166376e12930d26ba5455ab97f8bad65558cb94c3b018bccf6 |
| mut-r2-046.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-046.txt | c594e8c71290fcd1898402a568558d812b09f7446f87f7ce3ef4750e2d06364a |
| mut-r2-047.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-047.txt | a0a5cf78c4bdada657e9c507b7eca073de69210b216d56a06765563bb20f1544 |
| mut-r2-048.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-048.txt | f66bb345ded400bbff9ede0503d5dfcd8cd0e549f214144224289799749a8750 |
| mut-r2-050.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-050.txt | b938b6c1316153842c987fca97de8ee3104b17bb5437df0e92013c653a4ead3f |
| mut-r2-054.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-054.txt | 0533043c08e232d13fcc74a964edbc085aa7a546b21ec09791426b6d6420506d |
| mut-r2-057.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-057.txt | f17ed6b50cf8aad34528c3a2e0ae27dbb6d00fbac19e30b77845d4f953279709 |
| mut-r2-065.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-065.txt | 95da588d7db15884c7286dd624fe547b462bdfe451cf00508f4575780e5fa95c |
| mut-r2-067.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-067.txt | 3029fd50252a72e77fa73d9ee603b9988d710e2425ecea512cd5e92f80902576 |
| mut-r2-071.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-071.txt | d266ab200343cbbb1e4021b6686a26e53ceaebf173b4398b7730285ff58e590a |
| mut-r2-072.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-072.txt | 26d9e54a35ad9ee7023472883e76caf33902d8ab3b6f0a8bce85816fcf405617 |
| mut-r2-079.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-079.txt | 2ce6e23423e817981711acd4917c6622e7f2ff09f208dfbb1c0b0b819e9cf3ca |
| mut-r2-082.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-082.txt | f042aa4d93b27d6541b8c40e706b2fd8bd0a17970c7c48ce943218889658e9be |
| mut-r2-087.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-087.txt | 96afe41bae1fc53f792b56bfa9df0849004f3253d5f65a977d72d8f2892ecda2 |
| mut-r2-090.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-090.txt | 51d368a6d3a522e8bb4daa29fb8d673be93d2e896b3353e47b0aabe0987b439b |
| mut-r2-091.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-091.txt | c290db2ce88f1a570b4013667cc335e9475ee8d54d7025cfb306e00eaf15e813 |
| mut-r2-093.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-093.txt | 926976ddc7bcada7c6a24265d7caf4b7bdd201b6f27edd98ba04fddc43e388d1 |
| mut-r2-099.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-099.txt | 3f360499f3367d148b38229a05f04cb2c44431d4efc05720c3fc395c5e261ad8 |
| mut-r2-107.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-107.txt | a40a418c33705e1dd4112699e5e47548b0208c21e592ba5734b5db54ce37d11d |
| mut-r2-110.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-110.txt | ef92c74c637932e6f12155f50119bb0a5368847c0afb6f209601d8b5041324bb |
| mut-r2-113.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-113.txt | 8a76fd8a9cab1fbe2751f39f62384d717d55c30d6ec1edaa5ba9181d6f021c2e |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mutation-summary.md | f2ee6251e48cfccfa4045ff34711afde2cdad63aae306de153c18d0c3724ffd1 |
| project-check-repin.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/project-check-repin.txt | 6862b28b0bf382d62fb808856432b08506c8ecdd1ecc9d7140517b5a119fec48 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/red-01-vs-base.txt | 6d8aa26ad617f27f86058a515bac06f5ae2db52e85a3afe3efea8d84f6efdf93 |
| red-02-integration-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/red-02-integration-arms.txt | c45827950d2f00d18790e2d3aff5772f4f74307bae715a2602767c4992ffb607 |
| red-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/red-03-corrective.txt | 2bc1f94899d9ce9413dceae45b880ff9d02b053fcbbe6fecb102f4190685025f |
| timing-base-71376a3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/timing-base-71376a3.txt | 68415a6ca5bab37f29753807ae8425a11956da1c9fbc04a887f4a285ca4beb21 |
| timing-rerun-alone.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/timing-rerun-alone.txt | 843a41f6dff40b361604b697aae6d506999e6b54133cfa0e565681e8777132b5 |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · round 1 **FAIL** (0 HIGH, 1 MAJOR CR12b-1, 2 MINOR CR12b-2/CR12b-3, 1 NIT CR12b-4) with **BLOCK-UNTIL CR12b-1**; re-review on `c026bd2` **PASS-WITH-NOTES** (CR12b-1 discharged; 1 new NIT CR12b-5, declared) — "`BLOCK-UNTIL: CR12b-1` is discharged; I re-read the fix on the diff". — `review-increment-022.md`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · **PASS-WITH-NOTES** (0 HIGH · 1 MAJOR SE5-12b-1 · 1 MINOR SE5-12b-2 · 2 NIT SE5-12b-3/SE5-12b-4). SE5-12b-1 (MAJOR): a confirmed quit hides a committed save that left in-memory work unsaved → fixed by the `_quit_pending = False` withdrawal. SE5-12b-2 (MINOR): the A2L attach exits the app when the open project's folder is gone → fixed by the two pre-begin guards; the two sync helpers go to BACKLOG-CODE. SE5-12b-3/SE5-12b-4 (NIT): close-records only. — `security-increment-022.md`. **Design reviews (E3, code-free):** `architect` (2 rounds: r1 PASS-WITH-NOTES, 1 MAJOR · 1 MINOR · 2 NIT; r2 PASS-WITH-NOTES, 0 MAJOR · 3 MINOR · 2 NIT) and `security-reviewer` (2 rounds: r1 PASS-WITH-NOTES, 1 MAJOR · 3 MINOR · 3 NIT; r2 PASS-WITH-NOTES, 0 MAJOR) → design approved (`inc-12b/E3-architect.md`, `E3-security.md`). **There WAS a re-review (round 2), because the code reviewer blocked** on CR12b-1 (MAJOR). **Orchestrator (2026-11-01).** Final source hashes `app.py` `a6ca42563515797b`, `a2l.py` `73c3820fe0d6ecd2`. Scope ruling in force: per increment, the new and modified requirement tests, the modules that exercise the changed functions and the guards only (LED .75, amended by the 2026-10-31 override); the touched-module run and the full suite are deferred to the batch-end battery. Rulings applied: Q1–Q7 (`inc-12b/E1-rulings.md`), the E2 rulings (`inc-12b/E2-rulings.md`), S12b-* / A12b-* / DF-* / R2-* / S12b-R2-* (`inc-12b/E3-rulings.md`), SR12b-1 … SR12b-7 and the A-1 … A-10 rulings (`inc-12b/E4-integration-notes.md`), and the E5 rulings SE5-12b-* / CR12b-* / R2-F1 / R2-F2 / CI12a-1 (LED .99, LED .100). |

---

## 5 · Risks

- **The touched-module run and the full suite were not run for Inc 12b** (operator override 2026-10-31). A module outside the new-file/re-pinned set that calls one of the changed functions after the corrective pass has not been exercised here. The batch-end full battery is the check (§7).
- **The SR12b-6 residual.** `_save_project_files`' C5 tail (after the rollback `try`) is pure path arithmetic or already guarded; a raise there would paint a false `Project NOT saved …` over a committed folder, but a retry recovers (no data is lost). Both reviewers declared it residual risk, no guard; BACKLOG-CODE.
- **The 29 SVG snapshot cells drift until the CI regen.** `show_eta=False` changes the cells that painted the idle ETA `--:--:--`; `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot` for those 29 cells is `not-run` here and expected to drift until `.github/workflows/snapshot-regen.yml` regenerates them after the merge (§6, SR12b-5).
- **The SE5-12b-3 / R-B1 residual.** The work-area A2L pick's time-of-check / time-of-use window widened from "microseconds inside one synchronous main-thread call" to "milliseconds, across the worker start"; the A2L pick parses in place, with no use-time link or cap check. Hostile only if a writer already holds the work area; re-worded at close.
- **The SE5-12b-4 install-order invariant.** The 3 install handlers write the session before their closing generation check; safe today because a session run ends only through its own handler (the busy refusal blocks a second begin and the groups are non-exclusive). A later cancel, kill switch or `exclusive=True` would let a stale result reset a newer session; documented in interfaces S-d.
- **The CR12b-5 declared scope.** Any change-document line withdraws a confirmed quit, also lines about records already on disk (nothing is lost; the user quits again). Fail-safe direction, not narrowed (declared).
- **The S12b-R2-3 declared residual.** A committed save whose manifest check reports MISMATCH still exits under a confirmed quit; the files are on disk and the next load reports it. Declared.
- **The Inc 11 O-1 xfail.** A source that vanishes while the dialog is open paints the generic `could not save` instead of `source file missing`; the arm stays `xfail` ("design silent: Inc 11 O-1").
- **The R2-F2 residual.** In the committed arm of `_on_project_saved`, a raise after `for line in tail[:-1]` ends the run with `""` when `saved_painted`, so the last tail line is never painted; reachable only through a handler defect. BACKLOG-CODE.
- **Model performance.** DeepSeek v4 Pro implemented `app.py` and `a2l.py` in two parallel jobs (5 declared deviations), ran the **115** mutants (85 killed at first, 30 survived → 22 killed by the round-2 pass, 8 accepted equivalent, 0 open) and did E13. Opus did E1, E2, E3 (2 rounds), the tester, the integration (1 source fix set), the reviews and both corrective rounds.

## 6 · Pending items / spec deviations

**Backlog added at the close** (`.dev-flow/BACKLOG-CODE.md`, each with its evidence path and home):
- SR12b-6 (E4-integration-notes / E5-rulings) — the after-commit C5 path arithmetic could in theory raise and paint a false `Project NOT saved` over a committed folder; every C5 step is pure, guarded or absolute-path → **BACKLOG-CODE** (residual risk).
- R2-F2 (E5-corrective-notes) — a raise after the tail's leading lines leaves the last tail line unpainted, reachable only through a handler defect → **BACKLOG-CODE**.
- the two project sync helpers' unguarded calls (SE5-12b-2 tail) — `_sync_loaded_file_to_project` (~14593) and `_sync_loaded_a2l_to_project` (~14701) raise the same `OSError` as CR12b-2 when the open project's folder is gone (base behaviour) → **BACKLOG-CODE**.
- OBS-12b-1 (E13-notes) — `tools/e13/run.py`'s `bz-busy` `_parse_loaded_file` override is stale (`a2l_cache_out`) → **BACKLOG-CODE**.
- OBS-12b-2 (E13-notes) — the quit question's `Quit (y)` carries the primary (filled) style while the focus is on `Stay (n)` → **BACKLOG-CODE**.
- load_selected_file (E2-rulings PR-6) — 88 test calls and no product caller after 12b (`_load_a2l_data_with_cache` retired and re-pinned to `parse_a2l_cached`) → **BACKLOG-CODE**.

**Owed elsewhere (not backlog).**
- SR12b-7 (the short `pilot.pause` polling loops starving workers, F-17) and the MAX_PATH-blocked `test_b97_width.py::test_at_b97_24_breakpoint_and_below_the_range_by_key` → **batch-end battery** (re-run from a short root).
- OBS-12b-3 (the newest log row is cut at a fixed length, not the window width) → **batch-end battery** (confirm against main and route).
- The TC-027 full run (`test_engine_unchanged.py` diffs `a2l.py` against `main`) → **owed on main after the merge** (LLR-176.4b note, CONFLICT-1).
- The 29 SVG snapshot regenerations → the CI workflow `.github/workflows/snapshot-regen.yml` after the merge (SR12b-5; pending until then).
- CI9b-3 and CI9b-4 (the 9b CI run 41263643715, Linux-only: `tc_b100_43` and `tc_b100_63`[trailing dot]) → **batch-end fix round**.

**Declared (Risks, not backlog).** The SE5-12b-3 / R-B1 widened window; the SE5-12b-4 install-order invariant; CR12b-5 (the cautious quit-withdrawal scope); S12b-R2-3 (the manifest-MISMATCH save still exits); the Inc 11 O-1 xfail (design silent).

**Named gaps / observations.** OBS-12b-1 … OBS-12b-3 (above). The examples the tester could not turn into tests are listed in `inc-12b/E4-tester-notes.md` (the recent-entry route, the dropdown `LoadGuardScreen` arm, the rail focus arm, the 1-logged-traceback arm, the Windows junction-swap notes, the unit arms of the merge helpers and `_write_manifest_for_save`, the D12b-07 cost, the exact `App.exit` state). M-035, M-043 and M-101 were killed by a more relevant test than the named killer (noted in the per-mutant transcript).

**Finding → disposition (E3, code-free design review).**

| Finding | Severity | Disposition |
|---|---|---|
| S12b-01 … S12b-07 (security), A12b-01 … A12b-04 (architect), DF-1 … DF-13, R2-01 … R2-05, S12b-R2-1 … S12b-R2-4 | MAJOR / MINOR / NIT | E3 r1/r2 rulings (LED .98) |

**Finding → disposition (E5, code).**

| Finding | Severity / tag | Disposition |
|---|---|---|
| CR12b-1 the pasted-document home left behind on rollback | MAJOR / impl | fixed (LLR-164.4, A3R2-8); `red-03-corrective.txt` + the reviewer's re-read |
| CR12b-2 = SE5-12b-2 the unguarded A2L attach looks | MINOR / design-gap | fixed (new LLR-177.2c); `red-03-corrective.txt` |
| CR12b-3 the report viewer writes regions during a run | MINOR / design-gap | fixed (new LLR-177.3i) |
| CR12b-4 the callback-free parse is not strictly the base parse | NIT / impl | fixed (a2l.py, one line) |
| SE5-12b-1 the confirmed quit hides a committed save that lost work | MAJOR / design-gap | fixed (new LLR-177.4e); `red-03-corrective.txt` |
| SE5-12b-3 the R-B1 premise no longer holds | NIT / design-gap | re-worded at close |
| SE5-12b-4 the install handlers write before the generation check | NIT / design-gap | documented at close (interfaces S-d) |
| CR12b-5 the quit-withdrawal trigger is wider than the ruling | NIT / design-gap | declared (cautious scope) |
| R2-F1 the result panel over a closing app on a routed quit | MAJOR / impl | fixed by the orchestrator (green-08) |
| R2-F2 the last tail line unpainted on a handler defect | MINOR / impl | BACKLOG-CODE |
| CI12a-1 the reuse oracle stale since 12a | — / CI | fixed (test-only) |

**Orchestrator rulings Q1–Q7** are in `inc-12b/E1-rulings.md`; the **E2 rulings** (Q-a1 … Q-h1, the census, P2-1 … P2-10, PR-1 … PR-10, the worker exclusivity) are in `inc-12b/E2-rulings.md`; the **E3 rulings S12b-* / A12b-* / DF-* / R2-* / S12b-R2-*** are in `inc-12b/E3-rulings.md`; the **seam rulings SR12b-1 … SR12b-7** and the A-1 … A-10 tester rulings are in `inc-12b/E4-integration-notes.md`; the **E5 rulings SE5-12b-* / CR12b-* / R2-F1 / R2-F2 / CI12a-1** are in `inc-12b/E5-rulings.md` (LED .99).

**Re-pins (test::node — what changed — requirement).** The re-pinned nodes move the drives to the worker wait (`settle_workers` / `_drain`), the new keyword-only `gen`, the retired `_load_a2l_data_with_cache` → `parse_a2l_cached`, the moved seams (`_save_project_files`, `_write_manifest_for_save`), the removed `{exc}` lines, and the new bar values: the 7 `_flush` files + 3 census misses, the 6 `test_b100_save_dialog.py` nodes, the 3 `_timed` wrappers in `test_b100_project_check.py`, the structural re-pins C5–C9 and P1-C2–P1-C7, and the behaviour re-pins in `test_b100_busy.py`. Each names the old value, the new value and the requirement that changes it (`inc-12b/E4-tester-notes.md` §"Re-pinned tests").

## 7 · Suggested next task

**The batch-end full battery (owed once, when all increments are done — operator rulings 2026-10-30 and 2026-10-31).**
1. the touched-module run deferred by the 2026-10-31 override, every failure dispositioned against base;
2. the full reverse census / full suite on the final tree;
3. the guards and the census sweep (`-k census`) on the final bytes;
4. the mutants of every increment re-run on the final tree where a later increment touched the same function (the 115 Inc 12b mutants ran on `81ac4c0`; the corrective and round-2 re-runs cover what E5 changed);
5. the CI run, comparing the FAILED set with the previous run — including the 5 pre-existing Linux-only failures, CI9b-3/4 and CI11-1 … CI11-4, and the SR12b-7 short-pause census;
6. the fix rounds for every failure found there, and the SVG snapshot regeneration through `.github/workflows/snapshot-regen.yml` after the merge.

**After the merge:** the TC-027 full run on `main` (LLR-176.4b), and the `a2l.py` re-freeze follow-up.

**Then P4–P6 and the Obsidian sync** — the next batch-planning increments, per the batch's PLAN.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 of the 4-file cap (`app.py`, `a2l.py`); `styles.tcss` unchanged — §2 |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_workers.py` (NEW, 44 functions / 52 items) + `test_b100_a2l_progress.py` (NEW, 8 functions / 9 items) + `tests/support/b100_workers.py` (NEW) + the extended files and re-pins + `test_id_registry.py` F-20 — §2, §4 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `parse_a2l_cached`, the `a2l.py` callback, the frozen request dataclasses |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01-vs-base.txt` (108 RED vs `71376a3`); `red-02-integration-arms.txt` (CR12a-1 on `ef0cdb8`); `red-03-corrective.txt` (8 RED on `81ac4c0`) |
| 5 | Reverse census declared | `core` · `full` | ⚠ | **not run per increment — operator override 2026-10-31, batch-end full battery** (§7). The new files, the re-pinned nodes and the guards ran |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — round 1 FAIL (BLOCK-UNTIL CR12b-1), re-review PASS-WITH-NOTES |
| 7 | No file from another lane touched | all | ✓ | the 2 named sources + tests / fixtures / config / records; `tools/e13/` is the orchestrator's; `prototypes/` untouched |
