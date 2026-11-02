# Increment 022 — Inc 12b · HLR-177 … HLR-177c / LLR-177.x / LLR-176.3, LLR-176.4x · workers, busy refusal, quit question, A2L parse progress

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `012b` (corrected at close) |
| Lane | `main` · 2 SOURCE files (`app.py`, `a2l.py`), of the 4-file cap (corrected at close) |
| Requirement(s) | `HLR-177` · `HLR-177a` · `HLR-177b` · `HLR-177c` · `LLR-177.1`–`LLR-177.1k` · `LLR-177.2`–`LLR-177.2c` · `LLR-177.3`–`LLR-177.3i` · `LLR-177.4`–`LLR-177.4e` · `LLR-177.5` · `LLR-177.5a` · `LLR-176.3` · `LLR-176.4` · `LLR-176.4a` · `LLR-176.4b` · extended earlier ids `LLR-165.1` · `LLR-164.4` · `LLR-165.2` · `LLR-174.4` · `LLR-176.1l` · `LLR-176.1q` · `LLR-176.2` · `LLR-176.2c` · `LLR-176.2d` · `LLR-178.3` · `LLR-173.7` |
| Acceptance | `AT-B100-18` (four halves: worker, refusal, quit, quit-confirm) · `AT-B100-17` (parse half) · `TC-B100-53` (LLR-177.1 … LLR-177.5a) · `TC-B100-54` (LLR-177.2 … LLR-177.2b) · `TC-B100-52` (LLR-176.3) · `TC-B100-73` (LLR-176.4/.4a/.4b) · extensions `TC-B100-07` (LLR-164.4 worker arm) · `TC-B100-08` (LLR-165.1) · `TC-B100-09` (LLR-165.2) · `TC-B100-50` (LLR-176.1l/.1q) · `TC-B100-51` (LLR-176.2/.2c/.2d) · `TC-B100-72` (LLR-174.4, LLR-177.3a) · `TC-B100-66` (LLR-173.7) — in `tests/test_b100_workers.py` (NEW, 44 functions / 52 items), `tests/test_b100_a2l_progress.py` (NEW, 8 functions / 9 items), `tests/support/b100_workers.py` (NEW), and the extended / re-pinned files below |
| Interfaces | consumes `begin_busy` / `step_busy` / `end_busy` / `_busy_fail` / `_busy_begin_action` / `_running_session_action` / `painted_names` / `safe_text` / `parse_a2l_cached` / `write_change_document` / `_confirm_then_load` / `_handle_load_project` / `_commit_project_save` / `_start_load_worker`; adds the three 12b workers (`_project_load_worker`, `_save_project_worker`, `_a2l_attach_worker`) with their frozen request/result dataclasses and main-thread install/failure handlers, the `_refuse_if_busy` check on the 16 entry points and the 4 continuations, `action_quit` / `_answer_quit` / `_exit_if_quit_pending`, `_QuitQuestionScreen`, `_progress_forwarder`, the `parse_a2l_file` progress callback and the `show_eta=False` on `#progress_bar`; `styles.tcss` unchanged |
| Agent | design-first experiment (`dev-flow-v3-beta` pipeline): E1 requirements · E2 baseline + prototypes (P-1 G-A/G-B, P-2 G-C/G-D) · E3 code-free design review (2 rounds: architect + security) · E4 parallel build (2 DeepSeek implementers for app.py and a2l.py + 1 Opus tester + 1 Opus integration) · E5 validation (115 mutants on DeepSeek v4 Pro via pi, code + security review on Opus, one corrective pass on Opus, then a round-2 mutant kill pass) · E13 capture. Models per stage in the step table below |
| Date | `2026-10-31`–`2026-11-01` (E1 start 14:55Z through E5 round 2 08:25Z, all UTC) (corrected at close) |
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
| `tests/test_b97_chips_help.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_b97_flow_builder.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_b97_flow_execution.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_b97_width.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_examples_pilot_gifs.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_help_toggle_and_a2l_panel.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_memmap_entropy_merge.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_tui_app.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_tui_evidence_packs.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_tui_manifest_save.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_tui_patch_variant.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_tui_report_seam.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/test_tui_workspace_insight.py` | test | HLR-177 | re-pin (dabcd41) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-160x40].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-160x40].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[diff-comfortable-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-160x40].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-160x40].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-160x40].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-160x40].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-160x40].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-120x30].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-160x40].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-80x24].svg` | generated | HLR-176 · LLR-176.3 | density snapshot regenerated for the progress bar without ETA — 760f885 (snapshot-regen run 41319799849) |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-177 … HLR-177c · LLR-177.x · LLR-176.3/.4x · the extended earlier ids | E1/E4/E5 edits (LED .98–.100) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-177 … HLR-177c · LLR-177.x · LLR-176.3/.4x | LED .98 – .100 |
| `.dev-flow/BACKLOG-CODE.md` | doc | LLR-177.x | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-12b/*` | doc | HLR-177 … HLR-177c · LLR-177.x · LLR-176.3/.4x | the experiment records: `E1-scope.md`, `E1-rulings.md`, `E1-requirements-draft.md`, `E2-rulings.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-022.md` | doc | HLR-177 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/*` | generated | HLR-177 | transcripts (evidence digest table at the end of §4) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | HLR-177 | orchestrator-owned: scenario `qz-quit` |

## 3 · How to test

```bash
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
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

Note (corrected at close): times in this log are local (UTC−6), not UTC; see 05-postmortem.md Record corrections.

First step start to the last logged step: 14:55Z (2026-10-31) to 08:25Z (2026-11-01) = about 17 h 30 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 1 MAJOR in each round-1 review (A12b-01 census, S12b-01 quit-hides-failure); E5 (code) caught 1 MAJOR (SE5-12b-1) and blocked on 1 MAJOR (CR12b-1); 1 corrective pass + 1 mutant-kill round + 1 orchestrator fix (R2-F1); 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/` | SHA-256 |
|---|---|---|
| qz-quit.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.118x54.png | ab91bfed4bece7d3bc83c901a08fec51ba7eb1d4708744828f044aa22ef53787 |
| qz-quit.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.220x60.png | f73dc43241ed27c98a6e2c98f7450614ac5a7c59c36181a46c2ec42272d19a3e |
| qz-quit.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.99x54.png | febd8cf1a0ffb44809881997a76a98891e8303642280aa6b39d27b8d73568907 |
| green-01-new-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-01-new-run1-failed.txt | 6b89b4ad605ebec69feb5a7741b8398bc0102fbe20a7fe23f7eef312d0eb38a5 |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-01-new.txt | 2fdf7782d0dfcdccb97bb967834ea594061439c1a792558c6ed42e9133369f95 |
| green-02-repinned-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-02-repinned-run1-failed.txt | 592e0f9626658efd0f95cff12ab60809ba2c40f247fc1dde5b1cffe226ce6609 |
| green-02-repinned-run2-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-02-repinned-run2-failed.txt | 5026d70c45bb1d7919b68671f79213f699014bc8bca830492960b413fffbefbd |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-02-repinned.txt | cf2d08ec179a0c64a4999cbe3b560204cb0b3541d8dc66add094a2932ffd6e96 |
| green-02-timing-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-02-timing-rerun.txt | e74540ab52fd7407a4675ec4814c47fd7c09cca3ff8ffff4b2047a52ed97183b |
| green-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-03-corrective.txt | 4850c232728999a0badbcc2b6891dd9c7e0147eed96ba91ff87573d48c0a153a |
| green-03-merged.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-03-merged.txt | d6e68dc31e83d8afc0ac45d11c709dc806e6079ca9b329b0001d1d8dbf122971 |
| green-04-new-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-04-new-and-guards.txt | 755fbb820e4e99c2cb8659e545ea531b9f7b19b78057a0df53e8998e7c652a05 |
| green-04b-guards-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-04b-guards-rerun.txt | 3532d11b675a85ea961374de28000aeb54b3704d72addafa3e3174029520d03a |
| green-05-ci12a1-reuse-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-05-ci12a1-reuse-base.txt | d659a262c73375046ce976b78594903d5f64d6313d7623b24285bdd2ce71a57f |
| green-05-ci12a1-reuse.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-05-ci12a1-reuse.txt | 2f87dc01b9b24416f504fbc1b663d92a15173d0aa63e90754294f0fd8dc409e5 |
| green-06-busy-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-06-busy-full.txt | 9586744181b6e56dc59e66ba602d6aa4767d30344e1c85db05d3a627fd310702 |
| green-07-mutant-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-07-mutant-arms.txt | 6849791fa20270fd829fd098bbe2ee58b62e8cd4559be6147f6431b353797741 |
| green-08-r2f1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/green-08-r2f1.txt | 8d41f5e959830794f6c8c1130bab4c6bd993854ce8cc2bff6159bb978da8d38a |
| guards-01-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/guards-01-run1-failed.txt | c7df1237e11958cf826a1d406d653f12859df474ec3415ef597ac42028e0b290 |
| guards-01-run2-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/guards-01-run2-failed.txt | c2c4a78b45651a631c8f534ddc842efd7b35418e8fa6ec144f13b778ffcd7334 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/guards-01.txt | bb1736579384e5e4eb414ef0eec7f8df96208f2142b47eb96f2760b3ef94f060 |
| mut-001.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-001.txt | 73645799ddf5bf654de0a22a006719de342c20c41c88e77bf702ab792e66f3d8 |
| mut-002.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-002.txt | df96ab62b3bb0a8a69990997f937336fcf7c0c17186705c8c9366f0eb3a546a4 |
| mut-003.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-003.txt | d18bd0bdb4866566938669adfa559c15882e318286d2cbd5faaca4abbb6bc9e6 |
| mut-004.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-004.txt | 34aabc06470946b5f0016e625b6f775c40e000502602aeb4af8bee755ed47fb2 |
| mut-005.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-005.txt | 35027d33c49c5dd04d1df6af2d1732ccab7b5befdc9496ad0373d3e099994058 |
| mut-006.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-006.txt | e19c3f659b9551ca4f3cc22fcc5715efd0c43058ad191af1e4a506dfcec10e96 |
| mut-007.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-007.txt | b44e940c2aeadb8d18b05df8733995943987291d1f2ad7091b6085c7dec0aa12 |
| mut-008.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-008.txt | f34ffb2c243cf49ccbef43096b526d4a235f6c372fd6cdcc3f97df78ec1dbaac |
| mut-009.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-009.txt | 3510450b6929080b55bae22c7cb067e28d3fbecf4f89e24a35c05dc2354fdb25 |
| mut-010.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-010.txt | 3b04e99e081c4f4b9e2e5c0c930910fc61b3f3587084c988840903f543eed98f |
| mut-011.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-011.txt | f0a1da9840475d179b51fbc57e66bf9cfb13591f35846831ecb57ec884bc4573 |
| mut-012.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-012.txt | c155740ebccd2a672b5f9afcfa982d11b586739411cb1cb205947e83009e2780 |
| mut-013.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-013.txt | dc2d9ab720f38c420dc7659a6c0e3856f8fbd719a6904c6f9855cb4ccf17b954 |
| mut-014.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-014.txt | e4b0569a46dbe035f09ca5a59c609382eb27a2ccf286a900a22c6fe7019cc952 |
| mut-015.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-015.txt | 96597c09df5d2cf10d5e2971cbe22ad4d25febb7df309857fd24c954f145b5ca |
| mut-016.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-016.txt | fa80fd1d10cc9d6543f3167038b2f7b00f20ddd6dd2da3907b256a730e6bd112 |
| mut-017.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-017.txt | 23d6ab22887ce502a44c246c87f4aa9fc92eb23892e357ea74bdcdd4ac5c3cda |
| mut-018.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-018.txt | 075ef10c934e53f77b8feff9b59ea1090ac2bcbbc22f4c74df100eb90dfb9f8d |
| mut-019.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-019.txt | e72ee40f27e8939a441e97f2d91e85dc5818d284a4d5bb385852a2605c9794a3 |
| mut-020.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-020.txt | adc99c6c6e0d9e2d0d625e45cb119ed3e1b5f2d074867d75230ea6584a41e65a |
| mut-021.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-021.txt | c08261d29c58f29d02b258e971f73eaa80af414c27127a2db7753ea3b3562633 |
| mut-022.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-022.txt | fb0cc3f4ae0ab5f7e1b6a4c87c467c1a3c9b3865692128c5bdceadfb438ed9fe |
| mut-023.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-023.txt | d4f16d798d88b751436e240e35143bf7b43e57cef424a9220f80733d7ea4be5b |
| mut-024.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-024.txt | 5f950c68559de4f165b7434d079242956aff929eb14887823849ef251938ebe8 |
| mut-025.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-025.txt | 909a5778db7e2faaa4c5afe3834b41612c68a134b86ef7308c5c95df8eba6b4c |
| mut-026.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-026.txt | 81996a0d3b9ee8f7ffd830c91fe4e396233f43de5453c938740c0eaf6256b138 |
| mut-027.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-027.txt | 80624451248ffcc7884af56c19837742b444b0943b4fb52b0c45a0e0da3ddd25 |
| mut-028.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-028.txt | d2c157e011b334854bf0d74dd7523218c202ad6edcb1ab10a5d62768c0c79794 |
| mut-029.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-029.txt | 8921b01d601108ce70fef89391ef0fcce6ef602d709abff34101c27e62e191c0 |
| mut-030.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-030.txt | 9d690f0816e5c13fa7f9160ea2360ba396f8fb233c4752528e7bd4a6ff2175a2 |
| mut-031.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-031.txt | d541abe7d94052eb83783c2782292cb265ed979b6e79a60c5cbc1ddcce555d12 |
| mut-032.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-032.txt | 87919e538215283b79287b7e2b4d2c674a3bded22bc3354fa9b7eb7afc9a0a45 |
| mut-033.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-033.txt | 400416dbb8bf8d1ff43a349a4b01c905e3235d9c953ca39e8ee6b84d6172ded8 |
| mut-034.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-034.txt | 93811af4ed4e94844ba3a6fd1082ddcbb39fa0df027c86ccfaadfc9b5400c0b4 |
| mut-035.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-035.txt | 1dba3821d5a6f4587083aa8ab9956f65446b0ffd9bc61aea866d49df1e58f7bd |
| mut-036.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-036.txt | c5378461bd2af2ccc07ec569bdfe9d018b0bdf1137d8f87cc641a612810a7e10 |
| mut-037.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-037.txt | fc12c16d6cad2de04d4b6aad38d69996225c1af7dcb8fea9be2e3df3b1f944f7 |
| mut-038.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-038.txt | 5f1098ccf1f986e902fdef4b7f7a51224af0254824b787066062a73f13c5f767 |
| mut-039.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-039.txt | f47fcdd225343f58b1b89c561fe516e0c95675e6b0dcc9d8dabad7c81083e2e2 |
| mut-040.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-040.txt | 03506b6c545496d424d62824f5c753f0d8ac8389b025bdf122fabdefa2ce60b5 |
| mut-041.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-041.txt | c47a55ec992e09ded1e49b6d5f957d5f6b2d776f206e08f56052a7bc6e524217 |
| mut-042.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-042.txt | 50fa71773eb27c05b13ed27d29639bc1b89577f4608b7a151f009602382af43b |
| mut-043.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-043.txt | 59b561e942e8b0acbc479522aac1f694e76dc157f8c4d1b59989dda4ff9c0f92 |
| mut-044.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-044.txt | b549837125dde63080b537aabef2661cb840bb66bf08244c148cec48ecc451bd |
| mut-045.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-045.txt | 31c3896ec7426ee70194c615c2b9258e2e0e48606276fa1a61c218baed4ea525 |
| mut-046.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-046.txt | 1654ebc50b6990910a5ea4163bd3b6e1d70d29ff014c34a63e87404ff7065c2c |
| mut-047.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-047.txt | 8686e881e40ecf39f6aed0edc0ce30bbe1977df38c583c1172f9bed0f38bc56f |
| mut-048.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-048.txt | 65c9347884fabac7d8592616cf298ce650fd441897ed17385d445f966e291d27 |
| mut-049.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-049.txt | a674a8a9933303feca724c5a217dfca4eb9b5c90f47c59481dc72c563ab00386 |
| mut-050.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-050.txt | 34c14e30b1f79f474e60811f9c42273ada0f5912783033015ad1f19a392fd04a |
| mut-051.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-051.txt | 9ef8b1738eedf4e889e25c5577e1637def461b2ac197801ca26986c7c7365399 |
| mut-052.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-052.txt | 19d26141d6ed018546bd4c1d0f89fe81e579de64525731e701b3c19ac1ee0ea8 |
| mut-053.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-053.txt | 834cc048a1922e09ceec7bae509d312675c418b26309a20a3621e99d5b4d745f |
| mut-054.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-054.txt | 1103432b105f63ce7679e83e51064fdef4744e62887319ad217b221a492d4852 |
| mut-055.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-055.txt | d2787f1dd53e966be65727d85bfe8f88f17af86da1ffd858da45dad08e0b8961 |
| mut-056.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-056.txt | 042d8ba3b56974816d30250ed11e38333e7d5e891a618f9e3c63e78dd2345f76 |
| mut-057.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-057.txt | 29b7afb00fa58e7d60bbca5525399415676c4a6ce838a6edd0131dd65dbe99f6 |
| mut-058.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-058.txt | c2f1f6f3e66be8ba88c11808c53b512ab591b31c422253cba8f78b41c1ea9fb1 |
| mut-059.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-059.txt | a8f3d6d7f95731a1284dd33592a9dd475928fe22f6a5deda7e414fb008295414 |
| mut-060.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-060.txt | a3a70a55e0bbf8addb938bd47f06d3b5dfb1ae5453d24f3b6a45d4fbbd37037b |
| mut-061.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-061.txt | c69b99fe02c200d851dc86e69f8d0e3c258502908e5883ce5032d819f92a5b13 |
| mut-062.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-062.txt | 61a24fc243c821e6537df70105c1984a98d8c4484147f99cbd1e9e61c3886304 |
| mut-063.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-063.txt | dc4c0743117acfa7bc4922a7427c4e3e8003fb7e429e0a2462b1478e2ec410db |
| mut-064.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-064.txt | 1df3e1bcbfd071db640eeed4501090aa40c5d0901c6e359d88b17f8f2becd13f |
| mut-065.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-065.txt | 5de1e3d8ff8e533611c9b8f6eaf705200cfcb3c150ed36b48c0d34cec759216c |
| mut-066.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-066.txt | f2dd0e94644642d8f52fa8b81761e108b11b212b78bb09854c8fdb9029c4c140 |
| mut-067.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-067.txt | eb0f38c9f9231a4ea6dc875bcfa1ce93de8aec250e46efd936b4ce94912971bd |
| mut-068.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-068.txt | 9bc189b2e9314bac776131486c29312c9a287edd127f842d8b6fcd655cd4fb0f |
| mut-069.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-069.txt | 8d56d7d0698b7f3af0cdbfb349053935fcd8f9e3c76b4c72372d4f58ee3fc145 |
| mut-070.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-070.txt | dfcdd7a8dff05067251b1268da26ff16dd5ac4275aa41840a6d1a7a27c1a03be |
| mut-071.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-071.txt | 31225e9ac18d51d8e7d690ea9a5d4e86343b0aa298a9b4b321a6d7756b6d19e2 |
| mut-072.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-072.txt | be1d515a60bed03d4f377f21d2e046e3ec3416b79ca9440c9d010ffb16c5300a |
| mut-073.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-073.txt | 955c935686017723c9c343fef9723c015f5a16309c145bc46a80a238375b5c42 |
| mut-074.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-074.txt | 5e2166306070c3a518dd943d020125d818c483bc9a2d93f13a5976eb72edc630 |
| mut-075.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-075.txt | 3004ae99e7ee9228c82acc2baf3e73a8e2befd020a4bad843654b1233ab74ba5 |
| mut-076.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-076.txt | eaa578a31d9fa676009b51b1d2228fc6abdc46891b43d4e26cffddb1417e7c7f |
| mut-077.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-077.txt | ad90d4c7bfa811331aeffcc58649302b66a9f419f4c2c66e33414a27df921b35 |
| mut-078.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-078.txt | ae681a1c8842d6b03ce39bdc4740de8fd8f67c444774296c661c7b69eb85be55 |
| mut-079.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-079.txt | 884a9bca14be2fad3d7c4dc9eb64d2a130be1d5ed6f76481b9dd5059b4c33e5f |
| mut-080.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-080.txt | f34dd1e5e449110f67a28c3c84967a81151fe51413f2f78d036e7609d506f302 |
| mut-081.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-081.txt | d0729d9437d7c1692b0b84cdd18426eaa8b60a47b237f3ef4f11b23963469292 |
| mut-082.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-082.txt | 2681ddc7922dbdbfb7c836b7fc28d6f6ec3ceb9edcae8ff83d97b3513aad2d64 |
| mut-083.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-083.txt | dd1dcf7e03b9fb9eb1458a7a758034ab94b82da52d7429ad19da669dd709a1c6 |
| mut-084.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-084.txt | e60418ab9dfe2eed74e5b69a49441d12f5850c1ac944dd64368fccaab3c8035a |
| mut-085.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-085.txt | 111782268871767bfff5ef7f6ce98818045e22ab27dea83b31148b9aa8f7f20e |
| mut-086.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-086.txt | 7d714ffe6c6503e2c2f0c7c300f1c520592926ce7c418a2a0b0aa8601655fc92 |
| mut-087.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-087.txt | 0da2083148cbd74b164f019155cbe82e9aced87f771a37bd14b4faea8bbdfc2e |
| mut-088.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-088.txt | 0c8094e70d5a047256f982f6efb6bf340f382c8bef63a98bec444cf8ae761dab |
| mut-089.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-089.txt | a950cf25ca41dd0ca43d21053aa330e00d9711c4b6b3113a1c36298957c5aa15 |
| mut-090.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-090.txt | fee3ca3ba2e9a585a16fd89efc2a251d21ae7f6b2d86f99864dca511e5cc812f |
| mut-091.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-091.txt | a581348984a12078089f85278cd77e96b007ea93b81931b2bb1fc7153a042933 |
| mut-092.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-092.txt | ec853bc9f76c5bd9b35e00e809fb182baf46435782ac15242f04d5652987e21e |
| mut-093.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-093.txt | 9a080e72b19ad2476b7150420b69b1da31a0bded5e4d71aac03945226d1244c1 |
| mut-094.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-094.txt | 97055ecfdbb082b06d696a9be14275d8694aaa33da3a6ce7fdea485bcac2564f |
| mut-095.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-095.txt | af204bf972b8a230e3f0d897eef06ff68b6ed046b2afa403fde34a2a070d2994 |
| mut-096.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-096.txt | 2ddd59b678364367e2c781e6b4c846ef05a7057a7ee79a259b92ccbf858c946b |
| mut-097.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-097.txt | 58551166ffd3949b08c89ce226dde37d5f5282157068c68a11f083a58d43452d |
| mut-098.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-098.txt | 2f12d0e91fd092e7ae6b6496d439d4744f3ed3371fcdcb4c5c369ac604f5b669 |
| mut-099.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-099.txt | 810e97b8f075bb0aedd55b711e90dfae6c10c00b8024ea4f9bbad19673e508d9 |
| mut-100.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-100.txt | 16e61d5297a13373c72e6cba951ed67e21b1722a4bb7316755de25bc6314a2bb |
| mut-101.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-101.txt | e2557d313d44b80badbec04b5e4ef890bf7c53c80402732528393433d3c781cb |
| mut-102.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-102.txt | 2c5169d29d8bb3b97a01a8de41950e9a81832066d976496dadc3c3961469b457 |
| mut-103.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-103.txt | 00b9abf884d4016cbd4ec2bcc49a1da580bc8748ad11062d46c810d0bddf76c1 |
| mut-104.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-104.txt | 13b3ff55c80cfd99f2b0a4b3ec97bcfdce341d56371c163a69df3bbe7edc3ef6 |
| mut-105.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-105.txt | 71efa210e0dfdf3cb6d9eb0ef5c31875e0d00e993f9153989904e041fa5774e5 |
| mut-106.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-106.txt | c6ac8d85ad08801de1a583d886dde5a95cd1c74bf232d0027b1f28f37fa8adf1 |
| mut-107.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-107.txt | 44094816fc58cb4a9e1eee967996a3bdf882bf17a1c49a72d5d7b82c889f9c74 |
| mut-108.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-108.txt | d2deab42cbf9f6824dd3e7ac616a0de201549a0452e8ed52f33b877651b2cbcc |
| mut-109.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-109.txt | adeba5c3816550a9fee541d1ebe8383eeb6154a3d2d332fd014fe4d9e81be934 |
| mut-110.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-110.txt | 6d70e3410d67517f27eabde3b0963d1a8ab3503e3eebf89329dde55631af0849 |
| mut-111.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-111.txt | cdbd9b5ec4c95d032cf34c63a932c21014bcce902a69d1dd236e82f78df80812 |
| mut-112.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-112.txt | e8da9f9d893caf0ca9a52f74fc1b916dcef2f10076a58de5666506b09820c42b |
| mut-113.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-113.txt | de4ffe9014f38cd55d2db4f8af5a0538dd4dc09f4b203543d2671daa82536601 |
| mut-114.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-114.txt | b6c634a9834cb47a910f7df6222c5ddd461e5baba15b50f7be48b3813a5d14b8 |
| mut-115.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-115.txt | 74892286a556cddc164b689c133d013a47c904cc1e47418b9e4e6dc6a87be9b1 |
| mut-r2-003.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-003.txt | ac5468c3b1cbbf98f2593ba118333132b9b76958b57bc516c236b0d6a8ff8566 |
| mut-r2-039.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-039.txt | c70ca16a70491788bcf643d48bd42db5829407eab84c89cef9582837212aad0c |
| mut-r2-042.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-042.txt | bdab0df35bbf78befc1793ca7d3e93ef0c215c12c67c64884510d113f96d07e7 |
| mut-r2-046.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-046.txt | 568ec56e1b060c4036167b8c50c97b8078d0324f52ca75019cb693979dde7e6b |
| mut-r2-047.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-047.txt | 16e02fae721d7fd6406acd57ad76eee8ffbe3bcf8b7abd6f1a9de713a72fed99 |
| mut-r2-048.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-048.txt | 3366b3fffc68ff81929101ac5d93d9bd1ad9c837a263c1dc1d8871476c1a0ddb |
| mut-r2-050.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-050.txt | 45bd8264ac5f676a8d5287ea48251404a03a5271c95401778bbef1565d9fd19e |
| mut-r2-054.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-054.txt | f9bc64785c85ac38fe38c983b99f5cf514065d19a93b3c015440851c53c85817 |
| mut-r2-057.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-057.txt | faacde1eb0f829028b764a130720e90f6df7852b82e44a790f23629345695499 |
| mut-r2-065.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-065.txt | e8c31cef461641eb0d8f6358fa244f96188106a07873a52d570b732385382233 |
| mut-r2-067.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-067.txt | a1a15d38dc93e6d781cb373ca5d57a28f2a4f90a5efd4ad0b100532df194cf97 |
| mut-r2-071.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-071.txt | 12e545e2d4ef4cdc40c2f795a06728063129bb58a331b68697c8777fff3ebb85 |
| mut-r2-072.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-072.txt | 5f88bd7a027c1cd52d951d0fe1f83f05735c0f246066dc429f240d64c8ac96d3 |
| mut-r2-079.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-079.txt | 6d2e40a0bb458beb5e9e514ac07ee704a8a540a075826ac82447ab1bfcf42c20 |
| mut-r2-082.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-082.txt | a848ead1786f48e6d6a63f7d2f23b037a821ace0f10b19e83f7e0d5ed37c493b |
| mut-r2-087.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-087.txt | 479915510c5326a32205732b307ce58352b237d9e1601c7b3368f39e3fba0b70 |
| mut-r2-090.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-090.txt | 6acb80a16791a377bca7c62bdfdf969f080f278e66e0bbd37de1a18a4e94f7a5 |
| mut-r2-091.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-091.txt | 5ba0f3377f7bc0c4ab33a372e0b04853ff3a304f9a340386268807ce21982ddc |
| mut-r2-093.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-093.txt | a367e69fc23d320a2913063442c1ace2b2775a0f00f373d2bfae7444cb26ab45 |
| mut-r2-099.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-099.txt | 57abf00542ad916184b762614869b9505eb6e473ca5c8f0e352e468e514d526a |
| mut-r2-107.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-107.txt | 446b7d416db1484dfbfdf4d0ed3876cd520a7e810378d43de5d552cb22e50efc |
| mut-r2-110.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-110.txt | a3dd63b79886df8af086275b04b9dacf9233572c1fa9beb9dffbede071feaf59 |
| mut-r2-113.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mut-r2-113.txt | 0151392877ba27161d399ce42b8ad1e0a5b8865b812a7cbdb7716f72a8c6bd7e |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/mutation-summary.md | e1c729c59e28efa0c10fedff34ab319d54ec3effb6123ec575189d9fca33e8f3 |
| project-check-repin.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/project-check-repin.txt | d96fe65480d971ebbfb7b70cff38c3d82ced318850970981ec3ae378ad76af3e |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/red-01-vs-base.txt | 85443426a9433efa24cc9661c95e48c58c5bb9d84995e84b236881c1bc0e5d13 |
| red-02-integration-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/red-02-integration-arms.txt | 99ff55d718528a3d4136051d3d0c695eda59281d745818e05209c4db8aeebf2a |
| red-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/red-03-corrective.txt | bcd06eab6a85bd81baa8290ae7a31e39c7f40880aee257046b2ef50a0ac741df |
| timing-base-71376a3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/timing-base-71376a3.txt | e86a2d96700cf314726699e565a8d605f54e05201e2373768a6ead4e476b4dd0 |
| timing-rerun-alone.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-12b/timing-rerun-alone.txt | 5d5601f7edbf4065d4aef2b611a4b79cd35a9856eee754ffb4c4401d56332b22 |

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
