# DDR — software-dev lens — batch 2026-10-25-batch-99

- **Reviewer:** `software-dev` (spawned sub-agent; read-only on code; this file is its only write)
- **Tree reviewed:** `main` at `e7732f6` (12 increments merged one by one onto `307065f`)
- **Lens:** reverse census crossed between increments · C-18 AT→node realisation · summed test ledger
- **Method:** `git diff 307065f e7732f6 -- <file>` per shared file, read hunk by hunk; `git log 307065f..e7732f6 -- <file>` for ownership; `pytest --collect-only` for node counts; one targeted test run (no full suite — the full suite runs elsewhere).

## Verdict

**`approved with conditions`**

The merged code composes: no lost hunk, no duplicated status write that hides another increment's notice, and the placement error class is handled at every caller. Two conditions block the Phase-4 gate as the flow's rules are written. Neither one is a code defect:

1. **C-18 (HIGH, gate-blocking).** Four ATs (`AT-B99-03`, `-04`, `-08`, `-11`) are each realised across 2 to 5 on-disk nodes, and no single node joins the AT's whole named outcome. The other ten ATs realise in exactly one node.
2. **Ledger (MEDIUM).** The packets' signed-balance lines add up to **126** new nodes, but **142** are collected on disk. Incs 5, 6 and 9 added nodes in their review rounds and never updated their ledger line.

A conditional verdict is not an authorisation (§DDR). Both conditions have to be discharged by re-reading the artifacts, as listed under §Conditions.

## Crossed census — shared source files

| File | Increments (merge order) | Composition verdict | Evidence |
|---|---|---|---|
| `tui/services/flow_execution_service.py` | 9 → 8 → 3b → 5 | **composes** | Every increment touches a different arm. Inc 9: the SOURCE integrity abort comes before the `elif load_errors` advisory branch and is not lost. Inc 8: PATCH dispositions → `error` via `_record_error(detail=…)` (cause stays LAST), or `notices` + `FINDING_WARN`. Inc 3b: `_write_out_collisions` runs before any lane; verify-after-WRITE-OUT is inserted after `written_paths.append`. Inc 5: the empty-span refusal comes before `inject_crcs`, and partial coverage gives `notices` findings next to the pre-existing "CRC before PATCH" finding, which is kept and moved under `if crc_before_patch`. `ChainRunOutcome` gains `change_records`/`refusals`/`image_ranges` (Inc 8), and the D7 refusal returns before `_run_one`. Report sections compose: Inc 8 adds `## Written files`, `## Not applied`, `## Refusals` and Inc 5 adds `## Notices`, all through `md_safe`/`md_code`. Inc 5 re-pinned Inc 8's `TC-B99-19` count from 2 to 3 `none` lines (`test_b99_patch_truth.py:498-505`), so it saw the cross-lane effect. See F-3 for the redundancy this creates. |
| `tui/flow_screens.py` | 8 → 5 | **composes** | Lane terminal line riders: `_patch_not_applied_note` (Inc 8) and `_crc_absent_note` (Inc 5) each **append** a separately clipped segment (`FX_ERROR_LINE_MAX = 160`), and `wrote …` follows. Neither replaces the other. See F-2: no node drives a lane that carries both riders. |
| `tui/app.py` | 10 → 9 → 4 → 3a → 7 → 3b | **composes** | Status writes go through `set_status` → `_append_log_line`, a rolling 4-line log, so each write adds a line and replaces nothing. Inc 3b's D7 line paints only when `not record.outcomes and record.diagnostics`. Inc 4's suffix rides both verify arms (`_surface_verify_result`) after `_report_change_result`, which carries the same suffix. Inc 9's integrity text goes to `#status_text` through `set_file_status`, whose only writer is `app.py:11142`, so no later write overwrites it. Inc 3a: Save project catches `WorkareaPlacementError` **before** `WorkareaContainmentError` (subclass order correct) and removes only the folder that call created. Inc 7: `refresh_files`/`_load_from_item` read `workarea/temp` by `item.data`, and the private `temp/.staging` home of Inc 3a is excluded by the `is_file()` filter. Inc 10: A2L `n/a` cell, a disjoint hunk. Inc 4's `a2l_tags=self._compute_a2l_enriched_tags()` reads the Inc 10 decoder for linkage only (address-based). See F-4 for one crossed consequence (Inc 7 × the pre-existing save-back destination). |
| `tui/workspace.py` | 3a → 7 → 6 | **composes; duplicated logic** | Inc 3a: `_private_stage_dir`, `WorkareaPlacementError(WorkareaContainmentError)`, exclusive `O_EXCL` claim + `os.replace` fill. Inc 7: `RESERVED_WORKAREA_HOMES` (a constant block, disjoint). Inc 6: `place_group_into_workarea` (~330 lines), which re-implements Inc 3a's containment, reparse, size, staging, claim, fill and rollback sequence instead of sharing it. See F-1. |
| `tui/services/change_service.py` | 11 → 4 | **composes** | Inc 11 rewrites `parse_new_bytes` (input grammar). Inc 4 rewrites `save_patched` (re-derive from the journal) and adds `save_back_status_suffix`, `_SourceOverlayMap` and the journal helpers. The hunks are disjoint. `AT-B99-12` (Inc 11, merged before Inc 4) drives type → apply → save-back through Inc 4's re-derived save, and it passes on `e7732f6` (targeted run below). |
| `tui/segment_split_view.py` | 6 | single owner; **consumes Inc 3a** | Calls `_private_stage_dir`, `copy_into_workarea` and `place_group_into_workarea`. Every placement failure is wrapped as `ExportWriteError` (`except Exception`), and containment is caught in the window handler. The emitter always writes a terminator (`changes/io.py:1823`), so a header-only export never trips Inc 9's `S19-NO-TERMINATOR` on reload. |
| `core.py` | 2 → 9 | **composes** | Inc 2: the `_is_data_record` predicate on the three image walks, plus `S6` in the address-length table. Inc 9: the terminator, count and trailing tally in `_load`. Inc 9's `data_record_count` uses Inc 2's predicate, so the composition is direct and not merely co-located. |
| `tui/changes/apply.py`, `tui/changes/io.py` | 3a | single owner | Both moved to `_private_stage_dir` + owned `rmtree`. `save_patched_image` catches `(WorkareaContainmentError, OSError)` (`apply.py:783`), so the flow WRITE-OUT (Inc 3b verify) and the save-back (Inc 4) never see a raised placement error, only issues. |
| `tui/operations/crc.py` | 5 | single owner; consumes Inc 3a | Staging moved to `_private_stage_dir` (LLR-155.8). Adds `first_empty_target_span`/`normalized_targets`, which only the flow arm consumes. |
| `tui/services/project_gather_service.py` | 3b | single owner; consumes Inc 3a | `_gather_copy` now places through `copy_into_workarea` (`WorkareaPlacementError` is a containment subclass, so the existing callers' handling covers it). |
| `hexfile.py` · `render/hexview.py` · `tui/a2l.py` · `screens_directionb.py` · `window_help.py` · `flow_report_service.py` | 9 · 2 · 10 · 11 · 11 · 8 | single owner | No crossed edit. |

**`WorkareaPlacementError`:** it is raised only in `workspace.py` (copy and group placement). Every consumer catches it: by its own class (`app.py:8183`, Save project), by the parent class (`apply.py:783`, `io.py:1611`, the window handler in `segment_split_view.py`), or by wrapping it (`ExportWriteError`). Messages lead with the outcome ("Not saved: … Nothing written."), so the use is consistent.

**`safe_text` / `md_safe`:** report fields added by Inc 8 and Inc 5 are all `md_safe`/`md_code`. The lane riders are int- or enum-derived (a documented invariant). Status writes stay markup-off at the Label (`_append_log_line`), and notifies pass `markup=False`. Inc 6 paints `set_status(f"Export refused: {exc}")` raw but `notify(safe_text(...))`. That is safe today because the status Label is markup-off and the path in the message is a sanitised destination, but the two surfaces are inconsistent (LOW, F-5).

## C-18 — AT → on-disk node

| AT | Story | Nodes on disk | Count | C-18 |
|---|---|---|---|---|
| AT-B99-01 | US-141 | `tests/test_b99_corpus.py::test_at_b99_01_check_mode` | 1 | ✓ |
| AT-B99-02 | US-142 | `tests/test_b99_s0.py::test_at_b99_02_save_back_excludes_s0` | 1 | ✓ |
| AT-B99-03 | US-143 | `tests/test_b99_truncation.py::test_at_b99_03_pilot_status_and_issues` · `::test_at_b99_03_hostile_name_renders_literally` · `::test_at_b99_03_pilot_flow_source_fails` | 3 | ✗ load arm and flow arm split; no joined node |
| AT-B99-04 | US-144 | `tests/test_b99_staging.py::test_at_b99_04_distinct_names_parallel_regression_guard` · `::test_at_b99_04_duplicate_names_refused_nothing_written` | 2 | ✗ two outcomes in two nodes |
| AT-B99-05 | US-144 | `tests/test_b99_staging.py::test_at_b99_05_save_project_after_same_name_save_back` | 1 | ✓ |
| AT-B99-06 | HLR-156 | `tests/test_b99_patch_truth.py::test_at_b99_06_flow_execution_patch_truth` | 1 | ✓ |
| AT-B99-07 | HLR-156 | `tests/test_b99_patch_truth.py::test_at_b99_07_hostile_symbol_name_renders_literally` | 1 | ✓ |
| AT-B99-08 | US-146 | `tests/test_b99_editor_image.py::test_at_b99_08_save_back_keeps_editor_image` · `::test_at_b99_08_verify_mismatch_status_still_names_entries` | 2 | ✗ the first node appears to carry the whole named outcome; the second is a review-round arm (Inc 4 F5) under the same id |
| AT-B99-09 | US-147 | `tests/test_b99_a2l_encode.py::test_at_b99_09_a2l_window_physical_column` | 1 | ✓ |
| AT-B99-10 | US-148 | `tests/test_b99_crc_region.py::test_at_b99_10_flow_crc_region_pilot` | 1 | ✓ |
| AT-B99-11 | US-149 | `tests/test_b99_export.py::test_at_b99_11_hostile_segment_name_stays_inside_destination` · `::test_at_b99_11_mac_only_export_writes_no_data_record` · `::test_at_b99_11_second_export_after_patch_takes_next_free_name` · `::test_at_b99_11_part_way_failure_status_names_the_first_file` · `::test_at_b99_11_junctioned_project_home_shows_refusal` | 5 | ✗ three named outcomes plus two error-boundary arms, no joined node |
| AT-B99-12 | HLR-161 | `tests/test_b99_bytes_field.py::test_at_b99_12_typed_hex_run_saves_back` | 1 | ✓ |
| AT-B99-13 | US-151 | `tests/test_b99_load_project.py::test_at_b99_13_project_and_file_pickers_load_by_name` | 1 | ✓ |
| AT-B99-14 | US-152 | `tests/test_b99_a2l_encode.py::test_at_b99_14_codec_api_encode_surface` | 1 | ✓ (the declared codec-API exception) |

Source of the AT outcomes: `01-requirements.md` §3, the HLR-154/155/157/160 acceptance blocks (lines ~374, ~402-408, ~443, ~505). The split is visible in the requirements themselves. HLR-155's outcome lists three bullets for two ATs, and HLR-160's lists three outcomes for one AT. The multi-node realisation is therefore a **design** shape, not an implementation slip. That is why it belongs here and not in a P3 fix.

## Summed test ledger

| Inc | Module | Packet ledger (last stated) | Collected on `e7732f6` | Δ |
|---|---|---|---|---|
| 1 | `test_b99_corpus.py` | +5 | 5 | 0 |
| 2 | `test_b99_s0.py` | +6 | 6 | 0 |
| 3a | `test_b99_staging.py` | +23 (fix round 2: `23 = 17 − 0 + 6`) | 23 + 9 = 32 | 0 |
| 3b | `test_b99_staging.py` | +9 (`32 = 23 − 0 + 9`) | (in the 32 above) | 0 |
| 4 | `test_b99_editor_image.py` | +8 | 8 | 0 |
| 5 | `test_b99_crc_region.py` | +5 | **8** | **+3 unledgered** |
| 6 | `test_b99_export.py` | +17 | **25** | **+8 unledgered** |
| 7 | `test_b99_load_project.py` | +4 | 4 | 0 |
| 8 | `test_b99_patch_truth.py` | +19 (`19 = 18 − 0 + 1`) | 19 | 0 |
| 9 | `test_b99_truncation.py` | +20 (ledger line; fix-round prose says 23, then 25 passed) | **25** | **+5 unledgered** |
| 10 | `test_b99_a2l_encode.py` | +7 (`7 = 5 − 0 + 2`) | 7 | 0 |
| 11 | `test_b99_bytes_field.py` (+3) · `test_tui_memory_patch.py` (−1 +1 rename) | +3 net | 3 (+0 net) | 0 |
| **Σ** | | **126** | **142** | **+16** |

Pre-existing modules edited by the batch (`test_b97_chips_help`, `test_b97_flow_execution`, `test_change_service`, `test_changes_symbol_entries`, `test_copy_into_workarea_content_dedup`, `test_core_srecord_validation`, `test_crc_operation`, `test_entropy_service`, `test_flow_chainset_b94`, `test_id_registry`, `test_project_gather`, `test_report_service`, `test_segment_split_window`, `test_tui_directionb`, `test_tui_flow_execution_b94`, `test_tui_hexview`, `test_tui_memory_patch`): `def test_` counts are identical at `307065f` and `e7732f6`, so these are re-pins only. Summed batch balance: **`post = base − 1 + 143`** (the one deletion is the Inc 11 rename in `test_tui_memory_patch.py`, re-added under a new name). That is **net +142 new nodes, all in `tests/test_b99_*.py`.**

## Findings

| ID | Severity | Finding | Increments | Route |
|---|---|---|---|---|
| F-0 | **HIGH (gate)** | C-18: `AT-B99-03`, `-04`, `-08` and `-11` each realise in 2 to 5 nodes, and none of those nodes joins the AT's whole named outcome. Under `p4-validation.md` Layer B, an AT satisfied only in parts is UNREALIZED. | 3a/3b, 4, 6, 9 | Orchestrator decision at Phase 4, one of two: (a) write ONE joined node per AT that drives every named outcome in sequence (the others remain as TC-level arms, renamed off the `AT-` id); or (b) amend the AT set by ledger (iterate-to-refine), one AT per outcome, e.g. `AT-B99-03a` load / `03b` flow. Note that C-21 re-cuts the plan when the AT set changes after the P3 cut. |
| F-1 | MEDIUM | Duplicated placement logic: `place_group_into_workarea` (Inc 6, `workspace.py:695-1025`) is a near-copy of `copy_into_workarea`'s (Inc 3a) containment, reparse, size, stage, lstat-claim, verify, fill-retry and rollback sequence. A future security fix to one, such as the S-F1/S-F4/S-F6 class, will not reach the other. Behaviour today composes and both are tested. | 3a × 6 | BACKLOG-CODE: copy as the single-member case of the group placement, or a shared claim/fill helper. No change this batch. |
| F-2 | LOW | No test drives a lane that carries both terminal-line riders (PATCH not-applied, Inc 8, and CRC absent-count, Inc 5). Each rider is clipped to 160 separately, so a combined line can run to more than 320 characters plus `wrote …`. The code appends and never overwrites, but the combination was merged without being exercised. | 8 × 5 | Add one TC (lane: partial PATCH → partial CRC → WRITE-OUT) asserting both riders on the painted line. Phase-4 coverage gap, not a blocker. |
| F-3 | LOW | Report redundancy: Inc 5's `## Notices` lists every block finding, which includes Inc 8's per-entry PATCH `FINDING_WARN` lines (`0xADDR disposition`). A partial lane's not-applied addresses therefore appear in both `## Not applied` and `## Notices`. The `## Notices` cap is already in BACKLOG-CODE (Inc 5 review). | 8 × 5 | Same backlog item: scope `## Notices` to findings not already listed (or to non-PATCH blocks). |
| F-4 | LOW–MEDIUM | Crossed consequence: Inc 7 makes the Workarea Files list read only `workarea/temp` (LLR-162.3, as specified). A Patch Editor save-back with no project open still writes to the work-area **root** (`app.py:3420`, `dest_dir = self._active_project_dir() or self.workarea`, pre-existing). The pre-batch list showed that saved image and now it does not, so the user cannot reopen it from the list. No requirement states whether it should appear. | 7 × save-back (3a/4 touch the same path) | UX/architect decision, recorded in the backlog: list root images too, or move the no-project save-back home. Not a blocker: no AT covers it and LLR-162.3 is met. |
| F-5 | LOW | `segment_split_view.py` paints `Export refused: {exc}` raw to `set_status` while the matching `notify` uses `safe_text`. It is safe today (markup-off Label, sanitised destination path), but it is the one surface in the batch where the two channels disagree. | 6 | BACKLOG-CODE (it joins Inc 6's residual LOWs). |
| F-7 | LOW | `test_tc_b97_64_a_new_set_run_restarts_the_dwell` failed once under concurrent load and passed in isolation. It is a second real-time `tc_b97_64` node seen flaking in this batch, after `…_burst_on_two_waiting_lanes_confirms_one`. | 3b (re-pinned the THREE set) | Phase 4: classify against the full-suite run; if it recurs, add it to the baseline flake ledger. |
| F-6 | MEDIUM | Ledger drift: +16 collected nodes are absent from their packets' signed-balance lines (Inc 5 +3, Inc 6 +8, Inc 9 +5). | 5, 6, 9 | Before the Phase-4 `Test ledger` row: correct the three packets' ledger lines (or record the reconciliation in `04-validation.md`) so `base − D + A = post` reconciles at 142. |

## Conditions (discharge by re-reading, one by one)

1. **C-DDR-SD-1 (F-0):** for each of `AT-B99-03/04/08/11`, `04-validation.md` names ONE joined node, or the ledger carries an AT-set amendment. Re-read the AT→node table above against the tree.
2. **C-DDR-SD-2 (F-6):** the summed ledger reconciles at 142 new nodes in the packets or in `04-validation.md`.

F-1 to F-5 are not conditions. They go to BACKLOG-CODE or a Phase-4 coverage note.

## Targeted test run

- **Command:** `env -u NO_COLOR PYTHONPATH=C:\Users\jjgh8\Github\s19_app C:\Users\jjgh8\anaconda3\envs\s19env\python.exe -m pytest -q -p no:cacheprovider tests/test_b99_*.py tests/test_b97_flow_execution.py tests/test_tui_flow_execution_b94.py tests/test_flow_chainset_b94.py tests/test_crc_operation.py tests/test_change_service.py tests/test_segment_split_window.py tests/test_project_gather.py tests/test_report_service.py tests/test_core_srecord_validation.py tests/test_copy_into_workarea_content_dedup.py`, run on `e7732f6` by this reviewer, concurrently with the full suite running elsewhere.
- **Selection rationale:** every `test_b99_*` module (all 14 AT nodes and every crossed TC), plus the pre-existing modules that more than one increment re-pinned or whose symbols two increments changed.
- **Result:** `executed`. **1 failed, 412 passed in 1160.86s.** The failure is `tests/test_b97_flow_execution.py::test_tc_b97_64_a_new_set_run_restarts_the_dwell` (`AssertionError: ([(1, 2)], None)`: a real-time dwell assertion).
- **Isolated re-run:** `executed`. The same node passes alone (`1 passed in 6.75s`). It is a real-time sibling of the load-flaky `test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one` already recorded by Inc 3b and Inc 5. I classify it as timing flake under load (two suites running at once), not a composition defect. The Phase-4 full-suite run is the authority on it (F-7).
- **Not run:** the full suite (`not-run`: by instruction), lint and type checks (`not-run`).

## Evidence checklist

| Item | State | Evidence |
|---|---|---|
| Tests/type checks/lint pass (or skipped with reason) | ✓ (`executed`, 412/413; 1 timing flake green in isolation) | Targeted run above. The full suite was **not run** by this reviewer (`not-run`: it runs elsewhere, by instruction). No lint or type check was run (`not-run`: read-only review). |
| No secrets in code or output | ✓ | Only source diffs, test names and counts are quoted. No env, key or token content was read or printed. |
| No destructive commands run without approval | ✓ | Commands used: `git diff`/`log`/`show`/`status`, `grep`, `sed -n`, `pytest --collect-only`, one targeted `pytest`. No write to the repo except this file. No commit. |
| File count within cap | ✓ `n/a — review` | 0 source files edited. 1 design artifact written (this file). |
| Review packet attached | ✓ | This DDR file is the reviewer's packet for the gate. |

## Re-check — 2026-10-26 (worktree `s19_app-b99-ddr`, branch `b99-ddr` at `bab3bff` + uncommitted test-only fixes)

| Condition | Verdict | Evidence (re-read, not trusted) |
|---|---|---|
| C-DDR-SD-1 (C-18) | **discharged** | `grep "def test_at_b99"` → 14 functions, exactly one per AT-B99-01..14. Each joined node was re-read against its HLR's observable outcome. **AT-03** `test_at_b99_03_status_leads_defect_flow_source_fails` drives load → status leads with the defect → the Issues panel names the code → the flow over the same defect fails SOURCE and writes no `out.s19`. **AT-04** `test_at_b99_04_duplicate_refused_distinct_parallel_markers` covers the duplicate refusal (lanes, name, "Nothing written", inside 50 characters) and 8 parallel lane files, each holding its marker, plus the report `Mode: parallel`. **AT-08** keeps one node. **AT-11** `test_at_b99_11_sanitised_mac_only_second_export_takes_suffix` covers the sanitised name inside the destination with nothing outside, a MAC-only export with no data record, and a second export after a patch that gives `_1` with the status naming it and the first file intact. The renamed arms sit under TC ids: `test_tc_b99_10_hostile_name…`, `test_tc_b99_22_verify_mismatch…`, `test_tc_b99_41_part_way_failure…`, `test_tc_b99_29_junctioned_project_home…`. F-2 is closed by the new `test_tc_b99_18_lane_line_carries_patch_and_crc_riders`. |
| C-DDR-SD-2 (ledger) | **discharged, with one LOW wording fix** | Packets 005/006/009 now state 8 / 25 / 25, which matches the collected count at `e7732f6`. `increment-012.md` records the DDR delta (truncation −1, staging −1, export −2, patch_truth +1). Collected on the worktree: 7+3+5+8+8+23+4+20+6+31+24 = **139**. LOW: `increment-012.md:108` says "139 = 142 − 3 + 1", which comes to 140. It should read `142 − 4 + 1` (4 nodes merged away, 1 added; net −3). |
| No source change | **holds** | `git status --short -- s19_app` is empty. Only `tests/test_b99_*.py` and `.dev-flow/` changed. |
| b99 tests | `executed` | `pytest -q tests/test_b99_*.py` in the worktree (`s19_app.__file__` probed: it imports the worktree's `s19_app`) → **139 passed in 468.69s**. Full suite `not-run` (by instruction). |
