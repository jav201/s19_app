# Inc 8b — E5 corrective pass 1 (software-dev, Opus)

Base `ebe6d0c`, branch `b100-inc8b`, uncommitted. Ledger: LED .80. **5 source files: operator-approved for F2, 2026-10-31** (`variant_execution_service.py` is the 5th, beside `app.py`, `project_gather_service.py`, `workspace.py` and `screens_directionb.py`; `workspace.py` and `screens_directionb.py` are not changed by this pass). Inputs: `03-increments/review-increment-016.md` (FAIL, BLOCK-UNTIL F1), `03-increments/security-increment-016.md` (PASS-WITH-NOTES), `evidence/inc-8b/mutation-summary.md`, the orchestrator's fix list.

## Snapshot

`…/scratchpad/cp8b-1/pre/` holds the package as it was before this pass (`s19_app/`, `tests/`, `examples/`, `setup.py`, `pyproject.toml`, `AT-TC-REGISTRY.jsonl`). The sha256[:16] values match the brief: `app.py` b75f9125c9eb12c1, `project_gather_service.py` 7f1ecfefde90ee6b, `workspace.py` d9f361f3fb092ae2, `screens_directionb.py` e94f8e764f950b1a; the 5th file, `variant_execution_service.py`, is 699c38bd2cce77cd in the snapshot (unchanged since `ebe6d0c`). RED ran in `…/cp8b-1/red/`, which is that snapshot plus this pass's `tests/test_b100_project_homes.py` and `tests/support/timing.py`. The snapshot itself was not changed. `…` = `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad`.

## Per item

| Item | Status | Where (code) | Requirement | Node | Mutant |
|---|---|---|---|---|---|
| F1 (MAJOR) | fixed | `app.py` `_save_as_source_for` (new; used by `_handle_save_dialog` and `_plan_project_save`), `source_gone` and the status line after the link line | LLR-171.1n (new) | `test_tc_b100_31_open_project_folder_gone_saves_without_a_copy[gone, save as P / Q / present]` | MC01 (existence test dropped), MC02 (line dropped) |
| F2 (D-3) | fixed (operator-approved 5th source, 2026-10-31) | `variant_execution_service.py` `STEP_REPLACE_A2L` → "replace the A2L file, then Load again" in `DOCUMENT_NEXT_STEP`; `app.py` sets `step=STEP_REPLACE_A2L` on the A2L `not readable` problem | LLR-171.2g painted-next-step arm (text unchanged: it was already the true one) | `test_tc_b100_32_unreadable_a2l_row_paints_the_true_next_step` | MC15 |
| F3 | fixed | `app.py` `_apply_unload`: A2L-only branch | LLR-171.2h (new) | `test_tc_b100_32_unload_of_an_a2l_only_session_clears_the_a2l` | MC03 |
| F4 | fixed (text + node) | `app.py` reason text → "the name is not one project.json records" | LLR-171.5 threshold rewritten (CRC template `con.json` end to end; 12-row cap at the painting seam) | `test_tc_b100_31_crc_template_named_con_json_is_named_unrecorded` (Windows; holds at the snapshot, because the path already worked: P-2), `test_tc_b100_31_unrecorded_name_reason_is_not_too_long` | MC04 |
| F5 | fixed, with one correction to the reviewer's model (below) | `app.py` `_copy_project_subfolders` mismatch step; R9 rebind to the gather's landing | token row (new), LLR-171.1m arm | `test_tc_b100_31_identical_copy_mismatch_names_a_true_step`, `test_tc_b100_31_document_with_an_identical_sibling_follows_its_landing` | MC05, MC06 |
| F6 | fixed | `project_gather_service.py` `PAINTED_NAME_LIMIT` (one definition), `app.py` uses it (`_STATUS_NAME_LIMIT` removed); `proto-8b-app.md` rows 7 / 8 carry the shipped lines | §3 row note | — (no behaviour change) | — |
| F7 (a) | fixed | `app.py` `_project_folder_refusal` → `"unreadable"`; load, Save target and the save-as source each paint their own text | LLR-171.4f arm, token rows | `test_tc_b100_62_folder_check_permission_error_has_its_own_text[load / save target]` | MC07 |
| F7 (b) | routed | `.dev-flow/BACKLOG-CODE.md` (R-7) | — | — | — |
| SEC8b-1 | fixed | `app.py` `_PlacedFiles` (records `(st_dev, st_ino)` at append), `_abort_save` (reparse walk of the folder chain to the work area + identity check, one line) | LLR-171.7c (new) | `test_tc_b100_31_rollback_never_deletes_through_a_swapped_folder[junction to R / junction to itself / replaced file]` | MC08 (both checks), MC09 (reparse), MC10 (identity) |
| SEC8b-2 | fixed (option b: `_path_traverses_reparse_point(source, stop_at=workarea)`, containment kept) | `app.py` `_copy_project_subfolders._source_in_place` | LLR-171.1o (new) | `test_tc_b100_31_copy_refuses_when_p_itself_becomes_a_junction` | MC11 |
| SEC8b-3 | fixed | `app.py` `_manifest_is_link`, the save-as carry | LLR-171.1h arm | `test_tc_b100_31_linked_project_json_is_not_carried` | MC12 |
| M24 | resolved: wrong target, so a node now isolates the planner's merge / open arm with no file row (no A2L clash can mask it) | — | LLR-171.1g | `test_tc_b100_59_merge_and_open_targets_plan_no_copy` | MC13 = M24 again: KILLED |
| M35 | resolved: the test was weak, so a spy on the walker module's `sorted` and on the yield count now catches it (R16, G-5) | — | R16 / LLR-171.1j | `test_tc_b100_31_walker_stops_before_sorting_a_huge_folder` | MC14 = M35 again: KILLED |
| M46 | recorded as equivalent | — | LLR-171.2c | — | — |
| CI timing | done | `tests/support/timing.py` `timing_bound(seconds)` (×2 when env `CI` is truthy); 21 "< 1 s" asserts in 4 files; `tests/test_id_registry.py` 226 → 227 | LED .80 records the factor; the requirements stay at 1 s | — | — |

### F5: what really happens (correction to the review's model)

- (a) This matches the review. The session image `fw_2.s19` and an identical `P/fw.s19` repeat the refusal on every save. The line now ends "fw_2.s19 already holds the same bytes as fw.s19 — remove the duplicate copy from the open project folder 'P', then save again". "Save again" stays only for a mismatch that does not repeat.
- (b) This differs from the review. With the document `P/patches/changes.json` and an identical `P/patches/changes_1.json`, nothing refuses: the save **completes**. The gather reuses `Q/patches/changes_1.json` and records it as `active_document`. The R9 rebind, however, bound the Patch Editor document to the planned name `Q/patches/changes.json`, which **does not exist**. That is a wrong binding, not a refusal line. The pre-snapshot transcript is `…/cp8b-1/explore/test_explore_f5b.py` (an exploratory run) and `cp1/red-cp1.txt`. Fix: when the document row's planned landing is the matched entry and the gather recorded its landing, bind to the gather's landing (it is neither the source text nor a probe, so S3R2-5 holds). The `..` and skipped-junction arms of LLR-171.1m are unchanged (`test_e4_llr_171_1m_rebind_only_to_a_plan_entry`, in GREEN).
- The plan preview still predicts `new` for these rows. The reviewer's option 1 (predict against the tree the copy will produce) is routed to `BACKLOG-CODE.md`.

### M46 — why it is equivalent

Leaving `_variant_set` as `None` on the A2L-only branch has no observable effect. The next data-file load (`load_from_path`) runs `_activate_project_file`, which rebuilds `_variant_set` from disk (`validate_project_files` + `build_variant_set`) before `_rewrite_project_manifest` writes `active_variant`. `project.json` therefore gets `active_variant == "firmware"` whatever the A2L-only branch left. No reader of `_variant_set` runs between the A2L-only load and that rebuild in the LLR-171.2c scenario. No test is added for it.

## Design choices (declared)

- **`_PlacedFiles(list)`**: the rollback list records each path's `(st_dev, st_ino)` the moment it is appended, right after its placement returns. The alternative was to change about 12 `placed_files` call sites and the `_copy_project_subfolders` signature to carry tuples. The subclass keeps every caller unchanged. `_abort_save` reads `identity` with `getattr(…, {})`, so a plain list unlinks nothing (fail safe). Only the handler builds the list.
- **Reparse walk stop**: placed paths are resolved spellings. The walk stops at `self.workarea` when the path is under that spelling, otherwise at `self.workarea.resolve()`. That way it never walks above the work area into folders the app does not own, such as a cloud-sync folder carrying a reparse attribute.
- **`_save_as_source_for`**: one predicate for the handler and the plan. A save as needs an absent target, an open project and the open project's folder present (`lexists`, so a dangling link still reaches the S3-6 "link" refusal).
- **F1 next step**: "copy them into '<target>' if you still have them". This is true for both names (Q may equal P), and the save itself cannot recover the files.
- **F7 (a) texts**: load "'P' could not be read — check that the folder can be opened, then load again"; Save target "… then save again"; save-as source (token row 9) "the open project folder 'P' could not be read — pick a project in the list".

## Runs (operator ruling: new / modified requirement tests + modules exercising changed functions + guards; no full suite, no census)

- RED: `evidence/inc-8b/cp1/red-cp1.txt`, run on the snapshot. 17 node instances: 13 failed, 4 passed; then, appended, the F2 node: 1 failed ("replace the file, or Save project to drop it"). The 4 passes are expected: the "present" negative control, the `con.json` end-to-end node (requirement-text fix, path already working, P-2), and the M24 / M35 mutant-killing nodes, which encode behaviour the snapshot already has. Each of the 13 fails on its own assertion: data deleted, the wrong text, a wrong binding, or the outside batch carried.
- Mutants: `evidence/inc-8b/mut-cp1-MC01.txt` … `mut-cp1-MC15.txt`. Run in copy trees `…/cp8b-1/mutA|mutB|mutC`; 15 of 15 KILLED (MC15 = F2, run after the operator's approval in a refreshed `mutA`), all `restored = True`. MC10 was re-run after its node's assertion was tightened (`is_file()` before `read_bytes()`, so the kill is an assertion, not a `FileNotFoundError`).
- GREEN: `evidence/inc-8b/cp1/green-cp1.txt` (module set of `green-01`'s header).
- Guards: `evidence/inc-8b/cp1/guards-cp1.txt`.
- Probes: `evidence/inc-8b/cp1/probes-cp1.txt` (reviewer P-1 … P-5, security B3, B7, E1; unchanged copies).

## Results (all on the final sources)

Final sha256[:16]: `app.py` 87c7f9d74909138c, `project_gather_service.py` 524c3409037cae26, `workspace.py` d9f361f3fb092ae2 (unchanged), `screens_directionb.py` e94f8e764f950b1a (unchanged), `variant_execution_service.py` 8a38dde7fcd14211 (the 5th, operator-approved).

- **RED** (`cp1/red-cp1.txt`, snapshot): 18 node instances. 14 failed, each on its own assertion: 13 in the first run, plus the F2 node appended. 4 passed by design.
- **Mutants:** MC01–MC15, 15 of 15 KILLED, all `restored = True`.
- **GREEN** (`cp1/green-cp1.txt`, the 31 modules of `green-01`'s header): 1069 passed, 4 failed, 1 xfailed, in 62 min.
  - 2 failures are known at base (`base-01-two-failures.txt`): `test_tui_commandbar.py::test_at_b78_03_…` and `test_tui_report_filter_surface.py::test_at_056e_a2b_…`.
  - 2 are timing failures under load: `test_tc_b100_05_merge_keeps_a_too_large_document_under_one_second` and `test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folder_ceiling` (painted 1.031 s). Probes and guards ran concurrently with that run. Re-run alone, both pass (`cp1/green-cp1-timing-alone.txt`: 2 passed in 8.71 s). `CI` was unset, so the bound was 1 s.
  - Compared with `green-01`: `test_b100_reuse.py::test_tc_b100_01_…` now passes.
- **Guards** (`cp1/guards-cp1.txt`): 75 passed, 29 snapshots passed, 0 snapshot cells changed. `test_id_registry` passes with 227 scanned files, as measured.
- **Probes** (`cp1/probes-cp1.txt`, final run on the final sources):
  - Reviewer probes, 4 failed and 3 passed; they assert the defect, so a failure means the defect is gone.
    - P-1 (D-3): now fails, because the panel paints "replace the A2L file, then Load again".
    - P-2 passes; that path already worked.
    - P-3 (I-2): fails, because the A2L is detached with "Unloaded A2L.".
    - P-4 (F1): fails, because both saves complete. The P save paints the missing-folder line. The later save as Q copies the re-created P, so it paints no such line.
    - P-5 (R-7): not reproduced, as at E5.
  - Security probes:
    - B3: R's files deleted by the rollback = []. One "Not removed after the failed save" line. Q stays behind holding the kept files.
    - B7 (outside and other work area): refused with "changed while saving", Q absent.
    - E1: Q's `batch` = [], the outside value is not carried, and the link line names `project.json`.
    - 0 reparse points left in the scratch folder.
