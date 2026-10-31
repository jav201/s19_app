# Code-Wire baseline notes — Inc 8a slice at `dc3b314`

## Numbers

| Item | Value |
|---|---|
| Graph | `baseline-8a.md` (this folder) |
| Nodes | 25 (12 in `app.py`, 5 in `manifest_writer.py`, 3 in `variant_execution_service.py`, 2 in `project_gather_service.py`, 1 each in `screens_directionb.py`, `change_service.py`, `changes/io.py`) |
| Nodes that 8a changes (per `func:`) | 13: `_save_manifest_keys`, `_plan_project_save`, `plan_project_save`, `_handle_save_dialog`, `gather_project_artifacts`, `_write_and_verify_manifest`, `serialize_manifest`, `write_project_manifest`, `verify_written_manifest`, `project_file_records`, `read_project_manifest`, `_manifest_carry`, `_handle_load_project` (14 if `check_project_files` takes the missing-document problem) |
| Example lines | 45, each naming a TC/AT/LLR id or an existing test |
| Marks written | 25, 0 nodes without code |
| Extractor | exit 0, 0 findings, 30 real calls, 0 parse failures (Python 3.12.7) |
| Wall time | about 6 min by the shell clock (start 1793391184, end about 1793391600 epoch seconds); reading the requirements and the code was most of it |

**Interpreter deviation.** Under the requested `s19env` (Python 3.11.15) the extractor exits 1: `tools/mutation_harness.py` (an s19 file outside the slice) uses a 3.12 f-string and does not parse. The same extractor under the base Anaconda Python 3.12.7 (stdlib only) exits 0. The call table and the top-level sites are identical in both runs. Both reports are kept: `extract-baseline/diff-report.md` / `extract.json` (3.12, exit 0) and `diff-report-py311.md` / `extract-py311.json` (3.11, exit 1).

## Callers outside the slice that matter for 8a

1. **`_route_load_project` (`app.py:7119`)** is the only production caller of `_handle_load_project`. The document reopen runs on this path, and Inc 10's load question will sit in front of it.
2. **`read_project_manifest` has four readers outside the slice:** `_trigger_execute_scope` (`app.py:4751`), `_trigger_generate_report` (`app.py:5225`, `:5333`) and `execute_project_variants` (`variant_execution_service.py:2456`). When 8a adds `active_document` to `KNOWN_MANIFEST_KEYS` and lets a `patches/…` path into `files`, these readers get the new fields. AT-B100-20's Execute-scope arm reads through the first one.
3. **`write_change_document` has two callers today:** the Check Editor save (`on_check_editor_panel_action_requested`, `app.py:6052`) and `ChangeService.save` (`change_service.py:1735`). Save project becomes the third (LLR-170.2). Its M-1 dedup must give `changes_1.json` without changing the other two.
4. **`PatchEditorPanel.mark_saved` has one real caller:** the editor's own save (`on_patch_editor_panel_action_requested`, `app.py:3709`). Save project and the save-back do not call it at `dc3b314`, so LLR-167.8 adds the first Save project call.
5. **`_patch_editor_load` has three callers:** the typed-path Load (`app.py:3646`), the change-file dropdown (`:5830`) and the dirty-guard accept (`:5931`). None of them passes an A2L context. If the reopen reuses this seam, it inherits that gap (candidate C1 below).

## False call edges in the extractor report

The extractor resolves calls by name, so some edges are wrong. Do not read them as "already calls":

- `_handle_save_dialog → PatchEditorPanel.mark_saved` (`app.py:9732`), `on_patch_editor_panel_save_back_decision → PatchEditorPanel.mark_saved` (`:3860`) and `_handle_load_project → PatchEditorPanel.mark_saved` (`:13462`, via `_apply_loaded_file`) are all `self._change_service.mark_saved(...)`, which is `ChangeService.mark_saved`. Save project does **not** clear the panel flag today.
- The top-level sites `PatchEditorPanel.mark_saved` at `app.py:3075` and `:3398` are `FlowBuilderPanel.mark_saved(stem)` / the flow-execution panel (`flow_screens.py:1383`, `:2865`). They are not the Patch Editor.
- `gather_project_artifacts → ChangeService.load` (`project_gather_service.py:201`) is `json.load(handle)` inside `read_document_kind`.
- Line numbers in the report are from the marked copy: 25 mark lines shift each file. Subtract the marks above a site to get the `dc3b314` line.

## Candidates seen while writing examples (not findings: no run shows them yet)

- **C1 — no A2L context on the editor load path.** No app caller passes `a2l_context` to `ChangeService.load` (`grep "a2l_context=" s19_app/tui` → only `flow_execution_service.py`). LLR-170.3 / TC-B100-30 needs "a symbol entry → resolved against the project's A2L (0 unresolved)". Reopening through `_patch_editor_load` as it is would refuse every symbol entry. Proof owed: TC-B100-30's symbol arm, RED on the reuse.
- **C2 — the reader refuses what 8a writes.** At `dc3b314`, a `project.json` with `active_document` lands in `unknown_keys`. Then `manifest_rewrite_refusal` makes all four carry writers skip the rewrite ("holds keys this version does not know"), and Save project keeps a side copy (`manifest_keep_reason`). A `files` key `patches/boost.json` is refused with `MANIFEST-BAD-STRUCTURE` (`_recorded_file`: top-level only), so the rewrite is refused again ("holds entries that were skipped"). The reader, `_manifest_carry` and `project_file_records` / `check_project_files` must change together, or AT-B100-20 stays RED in a new way.
- **C3 — the gather does not name a document that is already in the project.** `gather_project_artifacts` skips an active document already under the project (`resolved_active.is_relative_to(resolved_project)`) and gives it no row. A pasted document written first into `P/patches/` by `write_change_document` (LLR-170.2) is therefore never named in `GatherOutcome`. `gathered` rows are also sorted per home with the composition documents, so the active document cannot be told apart. LLR-170.2's "whose `GatherOutcome` names the landed project-relative path" needs a new field or a separate path.
- **C4 — the reopen order.** `_reset_project_session` rebinds `ChangeService` before the A2L attach. The install defers `_step_a2l` / `_step_finalize` through `call_later`. A reopen placed in `_handle_load_project` after `_load_a2l_data_with_cache` runs before those deferred steps. Check that none of them resets the document.
- **C5 — a test that 8a must re-pin.** `test_b100_save_image.py::test_tc_b100_70_unwritten_document_keeps_the_flag` asserts the panel flag stays `True` after a Save project of a typed document, "written by Save project only from Inc 8a". After 8a writes the document, LLR-167.8 inverts this arm. The session-reset snapshot tests (`test_tc_b100_09_*`) compare load snapshots; a reopened document may enter that domain.

## Example sources and requirement text to check (for E1, not edited here)

- Every node has at least one example anchored to a requirement or an existing test. Two lines rest on weaker sources: `PatchEditorPanel.mark_saved` cites TC-B94-10 through the function's docstring (the test exists: `test_tui_patch_editor_b94.py:885`), and one `ChangeService.load` line cites its docstring for the `None`-context refusal (LLR-141). No 8a requirement gives these two a numeric example.
- LLR-170.1's threshold says "with an active document, the seam's `files` holds 4 keys (A-15's arm)". LLR-169.2's threshold has 4 top-level files without a document. Both can be true only if the A-15 arm uses a project with 3 top-level files. The arm does not say this, so the expected count is ambiguous.
- LLR-170.2 cites `write_change_document` as `changes/io.py:146`. Line 146 holds `DEFAULT_CHANGE_FILE_NAME = "changes.json"`. The def is at `s19_app/tui/changes/io.py:1504`.
- LLR-170.3 / HLR-170 do not say whether a missing recorded document is reported by `check_project_files` (from its `files` record, as "missing") or by `_handle_load_project`. If both report it, LLR-169.9's one-problem-per-file merge must keep only one.
