# Inc 10a — E5 rulings (orchestrator, 2026-11-06)

Inputs: `E5-code-review.md` **PASS-WITH-NOTES** (CR-1, CR-2 MEDIUM; CR-3 … CR-9 LOW); `E5-security.md` **FAIL** (SE5-1 MEDIUM; SE5-2 LOW; SE5-3 … SE5-6 INFO); `E5-coverage-audit.md` **PASS-WITH-NOTES** (QA-1 … QA-4 MINOR, QA-5 … QA-10 NIT). The mutant table (DeepSeek) runs on the pre-corrective tree; the corrective re-runs the mutants of the code it changes. Rulings:

| Finding | Ruling | Why |
|---|---|---|
| SE5-1 (MEDIUM) | **Fix (a), in `app.py`:** a save as with a project open, after the primary was unloaded, carries no top-level S19/HEX when no S19/HEX is loaded (`_plan_copies`' caller passes what is loaded; `project_gather_service.py` is not edited — if it must be, stop and report). New case R-WS-LOADED.19/3 (save as after `[u]` → the new project holds no image file; reloading it installs no primary) and control /19/4 (save as with the image loaded → carried), RED/GREEN. | R-WS-LOADED.19: an unloaded image is never written back. |
| SE5-2 | Accept: /7/3 reopens the window and asserts the hidden `a` ticked nothing, so M28 (`check_action` removed) dies; fix M28's expected result in the table. | I-6 needs a node that pins it. |
| SE5-5 | Accept: `_land_focus` returns when `_load_tree_gone()`, and its `query_one(Rail)` is guarded. | Same crash-at-exit class as E4-R5. |
| SE5-3, SE5-6 | SE5-3: fix the `check_action` docstring (the table's own arrow bindings and typed text are not refused; they write nothing). SE5-6: add the Split/Join export status and toast to backlog S-6. | Docs true; scope kept. |
| CR-1 | Accept: declare the rows cache in `__init__`, write its invalidation rule in its docstring, clear it in `_reset_session_state`; share the row list with the renderer if the graph's I-5 already allows it, else say why not. | A cache with an unwritten rule is a defect waiting. |
| CR-2 | Accept: one helper for the six failed-go-to re-render blocks, using `bisect` once. Behaviour unchanged (the existing nodes prove it). | Own new code; simpler. |
| CR-3 | Accept: the unload landing carries the window stamp (`_active_screen_key`), so `[u]` then `2`/`3` in one burst does not land on the table; I-4 "(changed at E5, CR-3)". | Same paging defect class as E4-R4/R6. |
| CR-4 | Accept I-D23 as is (Enter after `3` presses Page Prev: pages only, SE5-4 confirms nothing writes); name it in CTX-SHELL's forward line. | Better than base; documented. |
| CR-5 | Docstring fixed (with SE5-3); the hidden table's own cursor keys → backlog BL-I10-n (no write). | — |
| CR-6, CR-7, QA-4 | Accept: R-WS-LOADED.16/1 `== 0`; R-TUI-007.5/1 and R-SHELL-FOCUS.4/2 get a focus precondition and a `_land_focus` spy; R-TUI-012L.8/2, /3 assert the full newest message line. | Oracles as exact as the case. |
| CR-8 | Backlog BL-I10-n: a MAC record jump on a MAC-only spine centres with 64 context rows; no case covers it. | Edge case outside the rows. |
| CR-9 | Accept the stale comments and thin docstrings. | — |
| QA-3 | Accept: R-TUI-040.11/4 and /5 parametrised over the A2L empty/invalid and MAC empty/miss branches; split mutant M8 per branch; add M9b (A2L/MAC miss re-renders from row 0) for 040.8/2, /3. | Each branch needs a node and a mutant. |
| QA-1, QA-2 | The corrective's final runs, on the final tree: the H and F files and TC-B97-64 **three times**; R-TUI-040.12/7, R-TUI-007.3/2, the HLR-177c nodes ×3, `test_b100_focus.py`, the 7 law guards, serial_timing. (QC-BC and the other importers run at the merge verification.) | Thresholds say 3/3 on the final tree. |
| QA-5 … QA-10 | Record-level: mark partial where the audit says; executors and trees in the Result cells; fix the stale header and the empty tree lines; R-SEG-OPEN.7/3, /4: load a MAC if the threshold names one, else fix the case text. | Record hygiene. |

## Re-review rulings (2026-11-07)

Re-review of the corrective `d317138` (`E5-code-review.md`, section "Re-review of the corrective"): **FAIL** on RR-1 MEDIUM; RR-2, RR-3 LOW. Rulings:

| Finding | Ruling | Why |
|---|---|---|
| RR-1 | **Fix:** the save-as filter in `_plan_project_save` drops the open project's top-level S19/HEX whenever no S19/HEX image is loaded (`walked is not None and (loaded is None or loaded.file_type not in {"s19", "hex"})`), covering the A2L-only session after `[u]` on the primary and `[u]` primary then `[u]` MAC. **R-WS-LOADED.19 text widened** to "when no S19 or HEX image is loaded" (was: a MAC file is loaded), marked "(changed at E5, RR-1)"; new case R-WS-LOADED.19/5 (S19 + A2L project, `[u]` primary, save as → the new project holds no top-level image file; reloading installs no primary), RED under the old condition, GREEN. Forward the text change to the requirements session. | The row's intent is that an unloaded image is never written back; the MAC wording was one instance. |
| RR-2 | Narrow R-WS-LOADED.19's and /19/3's text to **top-level** image files (Split/Join exports in `splits/` are not images the load installs). | Text must match the behaviour and the oracle. |
| RR-3 | Fix the nine CR-9 doc items the re-review lists (file:line) — comments and docstrings only. | The ruling was "fix", not "accept". |
