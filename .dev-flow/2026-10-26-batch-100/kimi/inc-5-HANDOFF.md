# HANDOFF — batch-100 Increment 5 (implementer: software-dev, replacing Kimi)

Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc5`, branch `b100-inc5`, base `8d6056f`.

## Progress
- [x] Read briefs, design §5.5, contract HLR-167 / LLR-167.1–167.8, LED .45 .50 .53 .56 .60, SEC-4 probe, architecture §11 rows.
- [x] Import proof: `evidence/inc-5/import-proof.txt` (`s19_app.__file__` resolves into this worktree).
- [x] Part A code (in the working tree, uncommitted):
  - `change_service.py`: `image_differs_from_source` (I5 fast path), `mark_saved` / `differs_from_last_saved` (I18), `record_save_entries`, `rederive_for_save(copy, *, ranges, session_map, …)`, `rederived_differs_from_source`, `adopt_rederived`, `emit_and_verify(…, workarea_root, on_placed)`; `save_patched` = their composition (+ `workarea_root`).
  - `apply.py`: `render_patched_image` (exact bytes); `save_patched_image(…, workarea_root, on_placed)` stages under `_guarded_destination(dest_dir, workarea_root)` (SEC-4), places via `place_into_workarea`; `_find_workarea_ancestor` removed (dead).
  - `app.py`: `mark_saved` at a new-image install and after a successful save-back; save-back passes `workarea_root`; Save project decides on data (`_decide_project_image`), refuses blocked docs before any folder exists, emits via `emit_and_verify` (32/line, source S0), adopts the re-derived image on commit, records the saved state.
- [x] Part B code: `project_gather_service.py` `PlannedFile` / `SavePlanRow` / `SavePlan` (frozen) / `plan_project_save`; app `_plan_project_save` builds it (digests app-side); the handler executes the plan rows and checks each landing (`_plan_row_mismatch`).
- [x] CHECKPOINT (Part A + B code done). Tests `tests/test_b100_save_image.py` (39 nodes) + re-pin of `test_b99_staging.py::test_at_b99_05…` (HLR-167: the project image now carries the save-back patch) + registry 218 → 219: GREEN `evidence/inc-5/green-01-save-image.txt` (53 passed incl. registry).
- [x] RED on base 8d6056f: `red-01-new-module-vs-base.txt` (33 failed / 7 passed; behavioural vs missing-symbol classified in the packet), `red-02-at-b100-05-vs-base.txt` (P-1 message, both sizes).
- [x] Mutations: 10 run (9 declared + SEC-4), all KILLED, every restore hash-verified (`evidence/inc-5/mut-*.txt`).
- [x] Reverse census run: `census-batch-a.txt` (2 failed / 856 passed), `census-batch-b.txt` (4 failed / 632 passed, 1 xfailed). `test_b100_reuse.py::test_tc_b100_01_app_placements…` re-pinned 9 → 7 placement calls + the 2 emit calls must name `workarea_root` (GREEN `green-02-reuse-census-repin.txt`, base RED `red-03…`, mutant `mut-sec4-app-root-dropped.txt`). The other 5 failures (038b, b78_32, tc345, b78_03, 056e) are being run 5× on base and tree → `preexisting-census-{base,tree}-5runs.txt`.
- [x] 5x/15x base comparisons: b78_03, b78_32, 056e pre-existing (5/5 both trees); 038b flake under load (0/5 both); tc345 flake at base (4/15 base, 3/15 tree alternating).
- [x] Guards: `guards.txt` 75 passed + 29 snapshots (no cell changed); `guards-census.txt` 87 passed.
- [x] Packet `03-increments/increment-005.md` §1–§7 + gate checklist, §4b `pending — orchestrator`; evidence table written by devflow-evidence (31 rows). Scratch base worktree removed.

## Pre-existing finding (not fixed, out of scope)
Saving into the OPEN project that already holds its own A2L is refused ("Project already has an A2L file.") — the single-A2L guard compares suffixes, not identity. Present at base. TC-B100-59's open-project arms seed S19 + MAC only for that reason. Base evidence: `evidence/inc-5/preexisting-a2l-guard-base.txt` (probe `preexisting-a2l-guard-probe.py`). Orchestrator routes it to the backlog.

## STOP item (for the orchestrator) — LLR-167.8 panel `mark_saved`
LLR-167.8 is conditional: "After a Save project that **wrote the change or check document into the project**". In Inc 5 Save project never writes the editor's document (the pasted-document write is Inc 8a, LLR-170.2); the gather only copies the document's ON-DISK file, which differs from the editor's document whenever the panel is dirty. Clearing the dirty flag in Inc 5 would therefore hide unsaved document edits (a later Patch Load would replace the document without asking) — a silent-loss path. I did NOT call `PatchEditorPanel.mark_saved()` from Save project; `ChangeService.mark_saved` (the image record) IS called. TC-B100-70 has the refused arm and an arm pinning "document not written → flag kept". Proposal: TC-B100-70's positive arm ("entry added → Save project → load → 0 questions") moves to Inc 8a, where the document is written. RULED: accepted as proposed — LED-2026-10-26-batch-100.61 (orchestrator, main checkout ledger).

__KIMI_UNIT_DONE__
1. Files changed: app.py, services/change_service.py, services/project_gather_service.py, changes/apply.py (4/4, LED .56); tests: NEW test_b100_save_image.py, re-pins in test_b99_staging.py and test_b100_reuse.py, registry 218 -> 219.
2. Tests added: 39 nodes (TC-B100-14/15/16/17/58/59/69/70 + AT-B100-05 at 118x54 and 220x60); GREEN 53 passed (green-01), reuse 38 passed (green-02).
3. RED/GREEN: base 8d6056f -> 33 failed / 7 passed (17 behavioural, 16 missing-symbol, classified in the packet); AT-B100-05 RED with the P-1 message; SEC-4 RED shows temp/.staging in the other work area.
4. Mutations: 11 (9 declared incl. the LED .61 inverse probe, 2 SEC-4), all KILLED, all RESTORE OK; reverse census 47 files: 1 re-pin, 3 pre-existing, 2 flakes, each compared with base.
5. Open: B100-I15 re-freeze with the additive rederive_for_save keywords (ranges, session_map); plan sub-folder/merge rows at Inc 7/8a/8b; pre-existing single-A2L guard defect (routed); LED .61 panel call at Inc 8a.

## Corrective pass 1 (software-dev) — review BLOCK F1, F2 + F3–F9; LED .61–.65
Moved here from the worktree root (Inc 1–4 precedent).
- [x] Read review-increment-005.md (BLOCK F1, F2), security-increment-005.md (PASS-WITH-NOTES, SEC-7 = F1), LED .61–.65 (main checkout ledger).
- [x] Pre-fix snapshot of the 4 sources + test module in session scratch (`fix1/prefix/`); hashes equal the reviewed tree (app 2f6b4465…, apply 9cb482d5…, change_service 3623a42e…, gather a0dae134…).
- [x] Tests first: 9 new nodes + the F8 key oracle in `59_fresh_folder`. RED on the pre-fix sources: `evidence/inc-5/fix1-red-01-new-arms-vs-prefix.txt` — 5 failed (F1 ×2, F2 ×3), 5 passed (F3 ×2, F4, F5, F8 oracle pass on correct code; their RED is the mutants).
- [x] Fixes: F1 (`_emit_landed` records in on_placed + `except Exception` rollback-then-raise), F2 (decide+plan under `except OSError`, refusal `… could not be read: … Nothing written.`; `_file_digest` names the file), F6 docstrings, F7 (`save_entry_split` pure; `record_save_entries` right before the emit), F8 (`_save_manifest_keys` reads serialize_manifest; gathered excluded per LED .63), F9 (row_for + 2 constants removed, summary typed, apply.py assert removed by rendering first). F10 skipped (abort census needs `self._abort_save` attribute calls).
- [x] GREEN new arms: `fix1-green-01-new-arms.txt` 10 passed.
- [x] GREEN 5 modules `fix1-green-02-modules.txt` 138 passed; save-guards + apply engine `fix1-green-03-save-guards.txt` 84 passed.
- [x] Mutants (full module, CRLF byte anchors, RESTORE OK each): MB 2, MC 4, ME 2, MG 1, MX 1, MF2 3, MK 1 — all KILLED (`fix1-mut-*.txt`).
- [x] Guards `fix1-guards.txt` 75 passed + 29 snapshots; `-k census` 1 failed / 86 passed (`at058b`, flake), second sample 87 passed; at058b 30 alternating isolated runs: base 1/30, tree 1/30 (`fix1-at058b-base-vs-tree-30runs-alternating.txt`).
- [x] Packet: §1 corrective-pass bullets, §2 rows, §4 "Corrective pass 1" subsection, evidence table 50 rows (incl. `sec/` ×3), §5, §6 cites LED .61–.65, checklist rows 2/4/8/11/13/16; §4b left `pending — orchestrator`.
- Final source sha256 (16): app.py 8032dead73f7ee54 · apply.py 6d00f17fcefb704c · change_service.py 95da58bf3bcc27cd · project_gather_service.py 11697d6c85efb9e2 · test module 559768f390ded771.
- For the orchestrator: add `save_entry_split` to the B100-I15 freeze (LED .62); code-reviewer re-reads and re-runs P1, P2b, MC to discharge the BLOCK. Not committed.
