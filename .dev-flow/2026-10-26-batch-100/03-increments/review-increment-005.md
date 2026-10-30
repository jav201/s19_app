# Code Review — Increment 005 (batch-100, "Save project saves the image you see", HLR-167)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`. I am independent of this code: `software-dev` implemented it, not me. |
| Tree reviewed | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc5`, base `8d6056f`, uncommitted. Source sha256 (16): `app.py` `2f6b446594652dbc`, `change_service.py` `3623a42e6d1cd13e`, `apply.py` `9cb482d5e2876f00`, `project_gather_service.py` `a0dae1342b64bc14`. These equal the packet §4 hashes. The new test module is `9745926223da4d9e`. CRLF is consistent in all 5 files (for example, `app.py` 15154/15154). I did not edit the worktree. My only commands inside it were `git diff`/`git status` and a read-only `devflow-evidence.py --check`, and `git status` was unchanged afterwards. |
| Contract | `01-requirements.md`: HLR-167, LLR-167.1–167.8, LLR-163.7 and the B100-I15/I17/I18 rows. Ledger LED .45, .53 and .56 (worktree), and LED .61 (main checkout, uncommitted). `PROJECT_RULES.md` (docstring contract). Precedent: `review-increment-004.md`. |
| Interpreter proof | s19env Python 3.11. I built these trees under `…\scratchpad\r5\`:<br>• `base\` = `git archive 8d6056f`;<br>• `fixed\` = base plus the 8 changed files, hash-equal to the worktree;<br>• `mut\<id>\` = one tree per reviewer mutant.<br>Every transcript prints `s19_app.__file__` from its own tree. Runs used `PYTHONPATH` set to that tree, `NO_COLOR` unset (`env -u`), `PYTHONDONTWRITEBYTECODE=1` and `-p no:cacheprovider`. |
| **Verdict** | **FAIL (reject until fixed).** Recorded token: **`BLOCK — BLOCK-UNTIL: F1, F2`** (2 HIGH). This verdict authorises nothing. The increment does not advance until F1 and F2 are fixed and I have re-read the fixes on the diff and re-run probes P1 and P2b and mutant MC. F3 and F4 (MAJOR) should land in the same corrective pass. |

`…\scratchpad` = `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad`.

## BLUF

The design is right, and most of it is well tested.

- **What works:**
  - The emit decision is made on data.
  - A check document never counts.
  - A blocked document is refused before any folder exists.
  - The split reproduces the pre-split `save_patched` end state. I checked this by reasoning through the journal invariant, and TC-B100-69 plus `test_b99_editor_image.py` stay green.
  - The re-derived view is adopted only after `project.json` is written.
  - SEC-4 takes its staging root from the guard.
- **Mutants:** the 11 packet mutants are meaningful, and the tree-vs-plan oracle is live (my mutant MA is KILLED, 4 nodes).

Two failure paths are wrong, and both block:

- **F1. The emitted image is not on the rollback list while the emit is still running.** The `on_placed` callback appends to a local `landed` list. `placed_files` is extended only after `emit_and_verify` returns. If the verify re-read raises `OSError` after the file landed, the outer `except OSError` rolls back without that file. The project folder this save created is then left on disk holding `firmware.s19` (probe P1, executed). Mutant MC drops the emit's rollback recording entirely and leaves all 39 nodes green.
- **F2. The new digest and render work runs before the rollback `try`, and nothing guards it.** `_plan_project_save` reads the source, MAC and A2L with `_file_digest` before the folder is created. If one of them cannot be read (a byte-range lock), `PermissionError` escapes `_handle_save_dialog`. Run as an app callback, this ends the Textual session (`return_code 1`) and loses any unsaved in-memory work. On base, the same scene paints `Not saved: firmware.s19 could not be copied: [Errno 13] Permission denied. Nothing written.` and the app keeps running (probe P2b, executed on both trees). This is a regression of LLR-164.4 ("the app keeps running").

## Scope reviewed

- `s19_app/tui/app.py`, the whole diff:
  - module level: `_SAVE_MANIFEST_KEYS` `:1440`, `_ProjectImageStep` `:1449`, `_file_digest` `:1477`, `_plan_row_mismatch` `:1499`;
  - the save-back's `workarea_root` and `mark_saved` (`~:3674-3680`);
  - `_handle_save_dialog`: decide and plan `:8854-8873`, the plan-row loop `:8961-9034`, the commit `:9200-9228`;
  - `_decide_project_image` `:9243-9326` and `_plan_project_save` `:9328-9404`;
  - the install point `:12544-12550`.
- `change_service.py` `:2018-2350` (the split, the predicate and the record) and the rewritten `save_patched` `:2352-2502`. I read them against `_note_image`, `_restore_journal` and `_capture_journal` (`:1791-1890`) to check equivalence.
- `changes/apply.py`: `render_patched_image` `:629`, `save_patched_image` `:674-860`, and the removal of `_find_workarea_ancestor`.
- `project_gather_service.py` `:687-869`, read against `workspace.predict_placement`, `place_into_workarea` and `_guarded_destination`.
- `verify.py:verify_written_image` (it can raise on the re-read) and `_abort_save` `:8576-8661`.
- All 1410 lines of `tests/test_b100_save_image.py`, and the diffs of `test_b100_reuse.py`, `test_b99_staging.py` and `test_id_registry.py`.
- The packet, `HANDOFF.md`, `mutation_harness.py`, and the 11 `mut-*.txt` headers and verdicts.

## What I executed (evidence state: `executed`)

| Run (`…\scratchpad\r5\<file>`) | Result |
|---|---|
| GREEN, worktree (`green.txt`): `test_b100_save_image.py`, `test_b99_staging.py`, `test_id_registry.py`, `test_b100_reuse.py`, `test_b99_editor_image.py` | **129 passed** (351 s) |
| **P1** (`probe-rollback.txt`). Patch applied, Save project P1. `verify_written_image` raises `PermissionError` on the re-read, after the placement | The status reads `Project NOT saved: could not save — [Errno 13] probe: re-read refused …`, so the rollback ran. **But the folder `P1` still exists and holds `['firmware.s19']`** → F1 |
| P2 (`probe-rollback.txt`). No patch (copy branch); the source byte-range-locked (`msvcrt.locking`); handler called directly | Tree: `PermissionError` **escapes** `_handle_save_dialog`. Base: `Not saved: firmware.s19 could not be copied … Nothing written.`, and nothing escapes. |
| **P2b** (`probe-callback-copy.txt`). The same scene, with the handler run as an app callback (`call_next`) | **Tree: `_exception: PermissionError`, `return_code: 1`, `is_running: False`; `run_test` re-raises.** Base: the refusal is painted, the app is running and `return_code` is `None`. → F2 |
| P2b with a patch (`probe-callback.txt`) | Tree: the emit path never reads the source, so the save succeeds. Base refuses. The crash needs a copy-branch read: the image, the MAC or the A2L. |
| **MB**: `mismatch = None` (the plan-row check silenced), full module | **SURVIVED, 39 passed** → F3 |
| **MC**: the emit's `placed_files.append` removed (the emitted file is never recorded for rollback) | **SURVIVED, 39 passed** → F1 |
| **ME**: `adopt_rederived` moved before the folder creation (a failed save would change the view) | **SURVIVED, 39 passed** → F4 |
| MA: an unplanned `unplanned.txt` written after the plan loop | KILLED, 4 failed (`15_patched_s19_is_emitted` and the 3 TC-59 tree arms). The tree-vs-plan oracle is live. |
| **MG**: the install point always calls `mark_saved` (a MAC/A2L attach would hide an unsaved patch) | **SURVIVED, 39 passed** → F5 |
| Hashes and evidence | The `fixed\` tree hashes equal packet §4. I checked the evidence digests with `devflow-evidence.py --check` (read-only). Every row I compared matches the packet, for example `red-01` `2c3ab33f…` and `tc345-tree-15runs` `1c1b9906…`. The tool compares against `increment-015.md` because it picks the newest packet number. The `sec/` folder in `evidence/inc-5/` belongs to the security reviewer, who is running in parallel; it is not this packet's. |

## Findings

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **F1** | **HIGH** (rollback correctness; packet §5 claim false) | `app.py:8970-8986`; `apply.py:847-849`; `change_service.py` `emit_and_verify` (verify after the placement) | **The emitted image joins the rollback list only after `emit_and_verify` returns.** `on_placed=landed.append` records into a local list, and `placed_files` is extended at `:8984-8986`. `emit_and_verify` places the file and then runs `verify_written_image`, which re-reads the file and can raise `OSError` (for example, an AV or indexer lock on a just-written file). The outer `except OSError` then calls `_abort_save` without the emitted file. The file survives, and because the folder is not empty, the folder this save created survives too. That breaks LED .53, LLR-167.4 ("leave no folder it created") and packet §5 ("the emit's placement joins that list through `on_placed`"). No arm covers it: MC removes the recording entirely and stays 39/39 green. | P1: `P1 project folder exists after failed save: True`, `left behind: ['firmware.s19']`. MC → 39 passed. | Record at the landing: `on_placed=lambda placed: None if placed.reused else placed_files.append(placed.path)`. Keep `landed` only for the row check, and drop the post-call loop at `:8984-8986`. Add an arm: monkeypatch `change_service_module.verify_written_image` to raise `PermissionError`, run Save project with a patch, and assert the status carries `could not save` and that `project.exists()` is False. **Discharge:** I re-run P1 (no folder left) and MC (KILLED). |
| **F2** | **HIGH** (regression: crash; possible loss of unsaved work) | `app.py:8857-8862`, `:9371`, `:9374-9387` (`_file_digest`); `:1477-1496` | **An unreadable source now crashes the app.** The decide and plan steps (`_decide_project_image`, `_plan_project_save` → `_file_digest`) run before the folder exists and outside every `try`. On base, the same read happened inside `place_into_workarea`, under the handler's `except WorkareaPlacementError` / `OSError`, and gave a clean refusal. Now a `PermissionError` (or any `OSError`) on the image, MAC or A2L read escapes the dismiss callback, and Textual exits. If the session holds an applied patch and the MAC or A2L is the locked file, the emit branch still digests it, so the in-memory patch is lost with the session. | P2b: tree `return_code: 1`, `is_running: False`; base `Not saved: … could not be copied … Nothing written.` | Wrap the decide and plan block in `try … except OSError as exc:`. Paint `Project NOT saved: could not read <name> — <exc>. Nothing written.` with the error notify, as the `missing_sources` branch does, and return. No folder exists yet, so nothing needs rolling back. Add an arm: monkeypatch `app_module._file_digest` to raise `PermissionError`, then assert the refusal, that no folder exists, and that the app is still running (call the handler through `app.call_next`). **Discharge:** I re-run P2b on the fix, and the app must still be running with the refusal painted. |
| F3 | MAJOR (the mismatch path is untested) | `app.py:9014-9026`, `:1499-1522`; LLR-163.7 "a mismatch is an error naming both paths, never silent" | **No test makes the plan and the landing diverge, so silencing the check survives.** MB (`mismatch = None`) leaves 39/39 green. The packet's 167.6 mutant reaches this path only inside a mutant: it is KILLED because the extra file trips the mismatch check, not because any arm targets the check. The rollback-on-mismatch path, including the emit being recorded for rollback (F1), therefore has no behavioural evidence. | MB → 39 passed | Add an arm for a concurrent writer. Wrap `app_module.plan_project_save` (the existing `_capture_plans` spy) so that after it plans, it writes a different `firmware.s19` into a pre-existing target. Then assert the status names both paths (`the plan named …firmware.s19 (new) but the file landed at …firmware_1.s19`), that nothing this save wrote remains, and that the pre-existing file is untouched. MB must go RED. |
| F4 | MAJOR (an ordering claim with no test) | `app.py:9200-9209`; packet §5 bullet 2 ("A failed save leaves the view unchanged") | **The adopt-after-commit ordering is not pinned.** ME moves `adopt_rederived` before the folder is created and leaves 39/39 green. `TC-B100-14 deciding_writes_nothing` covers only `_decide_project_image`. The emit-refusal arm (`TC-B100-17`) checks the folder, not the view. | ME → 39 passed | In `test_tc_b100_17_emit_refusal_writes_no_manifest` (or a sibling), use a document holding an **unapplied** entry, so that adopting would change the view. Assert that the session map's bytes at that entry are still the source bytes after the refused save, and that `last_summary.saved_path` is not set. ME must go RED. |
| F5 | MINOR | `app.py:12544-12550` | **The install-point guard (`mem_map is not previous_map`) is unpinned.** MG (always `mark_saved`) survives. The code comment states the risk: a MAC/A2L attach that recorded the state would hide an unsaved patch from the Inc 10 load question. There is no consumer before Inc 10, so the impact today is nil. | MG → 39 passed | Add a TC-B100-58 arm: apply a patch, attach a MAC to the live image, then assert `differs_from_last_saved` is still True. Or carry the arm in the Inc 10 brief explicitly. |
| F6 | MINOR (convention) | `change_service.py:2023`, `:2049`, `:2073`, `:2105`, `:2190`, `:2220`, `:2265`; `apply.py:629`; `app.py:9243`, `:9328`, `:4234` | **The docstring contract is incomplete on the new public API.** `PROJECT_RULES.md` fixes Summary · Args · Returns · Raises · **Data Flow · Dependencies**. Of the 8 new public methods, only `rederive_for_save` (Data Flow only) and `plan_project_save` (both) carry the last two. `_decide_project_image` and `_plan_project_save` encode non-obvious rules (the fast path, the refusal order, the target kind), so they need the full sections. `_surface_verify_result`'s `Used by` (`:4234`) does not list Save project, which now calls it. | code read | Add Data Flow (2–5 bullets) and Dependencies (Uses / Used by) to each method, and add Save project to `_surface_verify_result`'s `Used by`. |
| F7 | MINOR (hidden coupling) | `app.py:9306`; `change_service.py:2343` | **The decision step writes service state, and the emit depends on it implicitly.** `_decide_project_image` calls `record_save_entries()`, which sets `last_save_applied` / `last_save_not_applied` before any folder exists, and nothing undoes that on a refusal or rollback. `emit_and_verify`'s message and `_surface_verify_result` read those attributes, so the Save project emit is correct only because the decide step ran first. This is harmless today (every save recomputes it), but it is temporal coupling inside the newly frozen B100-I15. | code read | Compute the split locally in `_decide_project_image` (it is pure over `document.entries` and `_applied_addresses`) and call `record_save_entries()` at the commit, next to `adopt_rederived`. Or state the precondition in `emit_and_verify`'s docstring and in the B100-I15 freeze. |
| F8 | MINOR (duplication) | `app.py:1440-1445` | **`_SAVE_MANIFEST_KEYS` hand-copies the manifest writer's key list (`manifest_writer.py:337-359`) and omits `gathered`.** The writer emits `gathered` whenever the gather places an artifact, which `TC-B100-15 check_document_only` does. So `plan.manifest_keys` can disagree with the `project.json` it describes. The plan is painted only from Inc 11, so the impact is deferred. | code read | Derive the tuple from one constant that `manifest_writer` exports, or add `gathered` when the gather is known to run. Route this to the Inc 7 / Inc 11 owner with LED .45. |
| F9 | LOW | `project_gather_service.py:694`, `:696`, `:782`; `app.py:1469`; `apply.py:828` | Small items of speculative or weak code:<br>• `PLAN_ACTION_REPLACE` / `PLAN_ACTION_MERGE` and `SavePlan.row_for` have no caller in source or tests.<br>• `_ProjectImageStep.summary` is typed `Optional[object]`; it should be `Optional[ChangeSummary]`.<br>• `assert payload is not None` sits in production code (it is stripped under `-O`). | grep | Drop `row_for` and the two constants until Inc 8a uses them, or keep the constants as the LLR-167.6 vocabulary with a one-line note. Type the field. Replace the `assert` with an explicit refusal, or narrow with `cast`. |
| F10 | LOW | `app.py` `_handle_save_dialog` (≈580 lines; 7 identical 6-argument `_abort_save(...)` calls) | This increment adds 2 more copies of the rollback call to a method that is already past `PROJECT_RULES.md`'s split trigger. The pattern itself is pre-existing. | code read | Optional: add a local `def _rollback() -> None:` closure over the 6 arguments. No behaviour change. |

Notes (no finding):

- **Split equivalence.** Here is the reasoning, step by step:
  - Pre-split order: `_note_image` → restore → capture → apply onto the session map.
  - Post-split order: restore onto a copy only when the copy's session map is bound → apply onto the copy → `adopt_rederived`, which writes `derived` at the old ∪ new journal addresses and re-journals the document spans.
  - Equivalence rests on the invariant that a non-journaled address holds its source byte. `_capture_journal`/`_restore_journal` maintain it.
  - `prior`, `variant_id` and the reuse rule read the same values in both versions.
  - `test_b99_editor_image.py` is green inside my 129.
- **Verify MISMATCH on Save project commits the save**, which is the save-back's collect-don't-abort rule (B99-I7). `_surface_verify_result` raises an error toast, so the mismatch is not silent even though the success line paints after it.
- **SEC-4.** `_guarded_destination` now also applies to `flow_execution_service`'s default `workarea_root=None` caller. That is stricter than the old resolved walk (the outermost textual anchor plus a reparse walk), and it is the intended direction. The Save project emit through a junction has no arm of its own. I hand it to `security-reviewer`.
- `HANDOFF.md` sits at the worktree root. Move it to `kimi/inc-5-HANDOFF.md` at commit, as for Inc 1–4.

## Rulings on the implementer-declared deviations

1. **B100-I15 additive parameters: justified. Re-freeze; this is not scope creep.**
   - `ranges` is needed by the apply's containment, so the frozen `rederive_for_save(copy)` could not be implemented as written.
   - `session_map` is needed because the journal binds by dict identity, and a copy has none. Without it, a newly loaded image's copy would receive the previous image's source bytes. The implementer's reason is correct.
   - `mac_records` / `a2l_tags` are LLR-167.2's own inputs.
   - Each extra helper has a real caller. `record_save_entries`, `adopt_rederived` and `rederived_differs_from_source` are used by both composition sites or by the decision. `render_patched_image` is the only way to digest the emit before placing, and the emit itself now writes through it, so there is one rendering and no duplicate.
   - Re-freeze with the exact signatures. Record F7's precondition, or remove it, in the freeze.
2. **LLR-167.3 split across two lines: acceptable, with a recommendation.**
   - The numeric threshold is met: `1 change entry, 0 applied` and `2 …, 1 applied by this save` on the success line at 220 columns, and the verify line names the entries at 118.
   - The two lines count differently. The clause counts the summary's APPLIED dispositions; the suffix counts document entries split by `_applied_addresses`. A skipped entry would appear in the suffix and not in the clause.
   - Recommendation (UX, Inc 11): put the image clause ahead of the path (`Saved project P1 — firmware.s19 + 1 change entry, 0 applied by this save (…\P1)`) so that it survives at 118. Ledger the clipping.
3. **Partial plan rows: acceptable as the declared TC-B100-59 split (Inc 7/8a/8b), but it needs two ledger lines.**
   - (a) HLR-167's "every file a Save project writes shall be the one its save plan names" is **not yet true** at Inc 5, because the gather writes `checks/`/`patches/` files that the plan does not row.
   - (b) The single-MAC/A2L refusals run after the folder is created, under a plan that already said `new`. The rollback covers that. Neither (a) nor (b) is in the split table at `01-requirements.md:1932`.

## Checks the brief named

| Check | State |
|---|---|
| Rollback on every failure path | ✓ Plan refusal: no folder (TC-17, TC-59 refused). ✓ Emit `ok=False`: folder removed (TC-17). ✓ Plan mismatch: rollback code present, **✗ but untested (F3)**. ✓ Manifest failure: pre-existing path. **✗ The verify re-read raising leaves the emitted file and the folder (F1, executed).** **✗ A read error before the folder exists escapes the handler and crashes the app (F2, executed).** |
| Ordering: adopt only after `project.json` | ✓ In code (`:9204-9209`, outside the try, after the manifest). **✗ Unpinned (F4, ME survives).** |
| Can the frozen rows drift from what runs? | ✓ The loop executes `plan.rows` in order and only them: the image row (emit with `row.landing.name`, or copy), MAC and A2L. Each landing is checked by path and reuse flag. ✓ The emit is rendered twice from the same `derived` dict, which nothing writes in between, so the planned digest and the emitted bytes are identical. ✓ An extra file is caught by the tree oracle (MA KILLED). ✗ The gather and the manifest are not executed from rows (deviation 3), and the manifest row's `new`/`rewrite` is never checked against the write. |
| Dead code | `_find_workarea_ancestor` removal is correct (no other caller; grep). `row_for` and two constants are unused (F9). |
| Duplicated logic | The rendering is single (`render_patched_image`). The manifest keys are duplicated (F8). The blocked-refusal wording exists in both `save_patched` and `_decide_project_image`; their messages differ by design (save-back and Save project). |
| Docstring convention | F6 |
| Vacuous tests | `TC-B100-70 unwritten_document_keeps_the_flag` pins the absence of a call, and the packet's inverse mutant kills it, so it is acceptable under LED .61. `TC-59 planning_writes_nothing_and_hashes_no_payload` with "files of other sizes" cannot make the planner hash in any case. The packet declares this load-bearing emptiness (gate item 10). No other vacuous arm found; the gaps are F1, F3, F4 and F5. |
| The 11 packet mutants | Meaningful. Each edits the decision it names; anchors are single-occurrence (`assert text.count(old) == 1`); transcripts end `RESTORE OK`. Caveats:<br>• `167.6-unplanned-file` is killed only through the mismatch check (F3). It places the unplanned file under the emit's own name, so it does not test the tree oracle; my MA covers that.<br>• `167.8-inverse` is an inverse probe, honestly labelled.<br>I did not re-run the 11 myself; I re-ran the module GREEN and 5 mutants of my own. |

## Evidence checklist

- [x] Diff read in full. `app.py` hunks `:43-58`, `:164-210`, `:1434-1522`, `:3671-3680`, `:8851-9405`, `:12541-12550`. `change_service.py` `:72-76`, `:912-923`, `:2015-2502`. `apply.py` `:39-62`, `:626-860`, `:927-929`. `project_gather_service.py` `:64-80`, `:682-869`. All of `tests/test_b100_save_image.py`, and the 3 test diffs.
- [x] Correctness pass: rollback on each exit (F1, F2 executed), ordering (F4), plan drift (MA, MB), split equivalence (note), SEC-4 (note).
- [x] Simplicity pass: the plan types are small and frozen; F9 lists the unused remainder.
- [x] Reuse checked: `predict_placement` / `place_into_workarea` are reused, with one rendering path. F8 is the duplicated key list.
- [x] Tests reviewed for intent: F1/MC, F3/MB, F4/ME and F5/MG are survivors, each executed.
- [x] Verdict explicit: `BLOCK — BLOCK-UNTIL: F1, F2`. Both HIGHs are open, each with executed evidence (P1, P2b).

## §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: F1, F2** (2 HIGH, 2 MAJOR, 4 MINOR, 2 LOW) · Both HIGHs are open.

- **F1:** the emitted image joins the rollback list only after `emit_and_verify` returns (`app.py:8984`). When the verify re-read raises `OSError`, the rollback leaves `P1/firmware.s19` and the folder the save created (probe P1, executed). Mutant MC, which drops the recording, keeps 39/39 green. Fix: record in `on_placed`, plus an arm.
- **F2:** the digests and render now run before the rollback `try`, and nothing guards them. An unreadable source makes `PermissionError` escape the dialog callback, and the app exits with return code 1. Base painted `Not saved: … Nothing written.` and kept running (probe P2b, executed on both trees). Fix: guard the decide and plan block, plus an arm.

Both are discharged only when I re-read the fix on the diff and re-run P1, P2b and MC.

The design is otherwise sound:

- the emit decision is made on data, and a check document never counts;
- a blocked document is refused before any folder exists;
- the split is equivalent to the pre-split `save_patched` (TC-69, and `test_b99_editor_image` green);
- the view is adopted after `project.json`;
- SEC-4 takes its root from the guard;
- GREEN: 129 passed on my run; the 11 packet mutants are meaningful, and my tree-oracle mutant MA is KILLED (4).

Open MAJORs:

- **F3:** the plan-mismatch path has no arm (MB survives).
- **F4:** the adopt-after-commit ordering has no arm (ME survives).

Rulings: the B100-I15 additive parameters are justified, so re-freeze them. The LLR-167.3 two-line split is acceptable, with a UX recommendation. The partial plan rows are acceptable, but need 2 ledger lines.

## Hand-offs

- **Orchestrator:**
  - Route F1 to F4 to `software-dev`.
  - Re-freeze B100-I15 with the exact signatures and F7's precondition.
  - Add 2 ledger lines for deviation 3: the gather writes unplanned files until Inc 7/8; the MAC/A2L refusals run after the folder exists until Inc 11.
  - Add 1 ledger line for the 118-column clipping (LLR-167.3, UX for Inc 11).
- **`qa-reviewer`:** the F1, F2, F3 and F4 arms; F5's MAC-attach arm (now, or carried in the Inc 10 brief).
- **`ux-reviewer`:** the success-line order at 118 columns (deviation 2).
- **`security-reviewer`:**
  - A Save project **emit** through a junction-opened project has no arm. Only the save-back arm exists (TC-69).
  - `flow_execution_service` still calls `save_patched_image` with `workarea_root=None`. The guard now derives the root textually, which is stricter than before; confirm that is acceptable (LED .50 backlog).
  - F2's read-before-try is a robustness issue, not a containment one; for information only.

---

# Round 2: re-read of corrective pass 1

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as round 1. I did not write the fix. |
| Tree re-read | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc5`, base `8d6056f`, uncommitted. Source sha256 (16): `app.py` `8032dead73f7ee54`, `apply.py` `6d00f17fcefb704c`, `change_service.py` `95da58bf3bcc27cd`, `project_gather_service.py` `11697d6c85efb9e2`. The test module is `559768f390ded771`. These equal the packet's "Corrective pass 1" hashes. It is still 4 SOURCE files. I diffed the round-1 tree (`…\r5\fixed\`) against this tree, file by file. I did not edit the worktree. |
| Interpreter proof | `…\r5\fixed2\` = `git archive 8d6056f` plus the 8 changed files, hash-equal to the worktree. `…\r5\mut\<id>\` = one tree per mutant. Every transcript prints `s19_app.__file__` from its own tree. `NO_COLOR` unset, s19env 3.11. |
| **Verdict** | **PASS-WITH-NOTES** (0 HIGH open). **F1 and F2 are discharged**: I re-read both fixes on the diff, re-ran P1 and P2b, and re-ran MC (KILLED). F3–F9 are closed. F10 is withdrawn with the implementer's reason. One MINOR (R2-1) and three NITs are new; none blocks. |

## What I executed in round 2 (evidence state: `executed`)

| Run (`…\scratchpad\r5\<file>`) | Result |
|---|---|
| **P1** (`r2-probes.txt`): the verify re-read raises after the emit landed | `Project NOT saved: could not save — [Errno 13] …`; **`P1 project folder exists after failed save: False`**. Round 1: `True`, holding `firmware.s19`. **F1 discharged.** |
| P2 (`r2-probes.txt`): copy branch, the image byte-range-locked, handler called directly | `Project NOT saved: firmware.s19 could not be read: Permission denied. Nothing written.`; nothing escapes; no folder. |
| **P2b** (`r2-probes.txt`): the same scene, run as an app callback | The refusal is painted, `_exception: None`, `return_code: None`, `is_running: True`. Round 1: `return_code 1`, app stopped. **F2 discharged.** |
| P2b with a patch (emit branch) | Saves normally (the emit renders from memory), as in round 1. |
| **MC** (the emit's rollback recording removed from `_emit_landed`) | **KILLED, 4 failed**: `verify_reread_failure_rolls_the_emit_back`, `non_os_error_after_the_emit…`, `failed_manifest_write_adopts_nothing`, `landing_that_differs…[emit]`. Round 1: SURVIVED 39/39. |
| MB (the mismatch check silenced) | KILLED, 2 (`landing_that_differs_from_its_row_rolls_back[emit]` / `[copy]`) |
| ME (adopt before the folder) | KILLED, 2 (`16_entry_added_after_the_apply`, `17_failed_manifest_write_adopts_nothing`) |
| MG (the install point always records) | KILLED, 1 (`58_mac_attach_keeps_an_unsaved_patch_unsaved`) |
| **MX** (mine): the new `except Exception:` re-raises before `_abort_save` | KILLED, 1 (`17_non_os_error_after_the_emit_rolls_back_then_surfaces`) |
| **MF** (mine): the F2 guard narrowed to `except ZeroDivisionError` | KILLED, 3 (`f2_unreadable…[image]`, `[a2l]`, `f2_byte_range_locked…`) |
| **MR** (mine): `record_save_entries()` before the emit removed (the F7 ordering) | KILLED, 4 (both TC-B100-16 nodes and both AT-B100-05 sizes). The call is load-bearing exactly where the pass put it. |
| GREEN, `fixed2` in parallel with the mutants (`r2-green.txt`): 5 modules | 126 passed, 12 errors. All 12 errors are `test_id_registry.py`, which raises `RuntimeError` in the scratch tree (it is not a git checkout). This is environment, not code. |
| GREEN, `fixed2` solo with `--basetemp` under the scratch folder (`r2-green-solo.txt`), plus `test_b100_save_guards.py` | 164 passed, 12 errors (the same `id_registry`), and 5 failed:<br>• `tc_b100_06` ×2 say so themselves: `tmp_path too deep for the L = 150 enabler` (environment).<br>• **`tc_b100_16` ×2 and `at_b100_05[220×60]` fail because the deeper path pushes the entry clause past the 220-column cap** → R2-1. |
| The same environment-sensitive nodes **in the worktree** with the default temp (`r2-worktree-envcheck.txt`): `test_id_registry.py`, `tc_b100_16`, `at_b100_05`, `tc_b100_06` | **19 passed.** |

## Re-read of the pass (diff `fixed` → worktree)

- **F1 (`app.py:9034-9058`).** `_emit_landed` appends the landing to `landed` and, when it was not reused, to `placed_files`. It does this before `emit_and_verify` re-reads, so every later exit sees the file. That covers the `OSError` excepts, the mismatch return, the emit-failure return, the manifest failure and the new defect clause. The post-call loop is gone. Correct.
- **The new `except Exception:` (`app.py:9269-9280`).** It sits after `WorkareaPlacementError`, `WorkareaContainmentError` and `OSError`, so it only sees non-OS defects. `_abort_save` never raises, so the re-raise surfaces the original error. `CancelledError` and `KeyboardInterrupt` are `BaseException` and pass through untouched. The early `return` paths that already rolled back cannot reach it. The session still ends on such a defect, as it did before the pass, but the disk is now clean first, and LLR-164.4 names only OS errors. Accepted as designed.
- **F2 (`app.py:8894-8925`).**
  - The decide and plan block sits inside `try … except OSError`, before `mkdir`, so no rollback is needed.
  - `_file_digest` stamps `exc.filename` when a read error carries none, so the refusal names the file.
  - The A2L arm proves the emit branch too (the patch stays in memory: `unsaved is True`).
- **F7.** `save_entry_split()` is pure. `_decide_project_image` uses it. `record_save_entries()` runs immediately before `emit_and_verify` (`:9045`), and MR shows that this ordering is load-bearing. The leftover the implementer named, a rolled-back save keeping its split in `last_save_*`, is harmless: every save-back and every emit recomputes the split first.
- **F8.** `_save_manifest_keys` serializes an empty composition through `serialize_manifest`. With an empty `batch` there can be no findings, so `json.loads` always receives text. The writer is now the one source. Leaving `gathered` out is recorded against LED .63.
- **F9.** `save_patched_image` now renders first. A refused filename or destination therefore renders the whole image before refusing. This is a negligible cost, and it is what removes the `assert`; NIT R2-4 only.
- **F6.** The docstrings carry Data Flow and Dependencies throughout. I spot-checked `emit_and_verify` (it states the `record_save_entries` precondition and the `OSError` raise), `adopt_rederived` and `_plan_project_save`.
- **F10, withdrawn.** The TC-B100-07 census recognises a rollback exit only as a `self._abort_save(...)` attribute call. Folding the calls into a closure would weaken that direct check. The implementer is right.

## Closure table — round 1 findings

| id | State | Evidence |
|---|---|---|
| **F1 HIGH** | **Discharged** (re-read and re-run) | `_emit_landed` (`app.py:9034`); P1 leaves no folder; MC KILLED (4); arm `verify_reread_failure_rolls_the_emit_back` |
| **F2 HIGH** | **Discharged** (re-read and re-run) | `try/except OSError` before the folder (`:8894-8925`); P2/P2b refuse and the app keeps running; MF KILLED (3); arms `f2_*` ×3 (one Windows-only, skipped with the named reason elsewhere) |
| F3 MAJOR | Closed | `landing_that_differs_from_its_row_rolls_back[emit/copy]`; MB KILLED (2) |
| F4 MAJOR | Closed | `failed_manifest_write_adopts_nothing` (an unapplied entry, view and summary checked); ME KILLED (2) |
| F5 MINOR | Closed | `mac_attach_keeps_an_unsaved_patch_unsaved`; MG KILLED (1) |
| F6 MINOR | Closed | docstrings (spot-checked) |
| F7 MINOR | Closed | `save_entry_split` pure; MR KILLED (4) |
| F8 MINOR | Closed | `_save_manifest_keys`; the packet's MK KILLED (1); `gathered` → LED .63 |
| F9 LOW | Closed | `row_for` and the two constants removed; `ChangeSummary` type; no `assert` |
| F10 LOW | Withdrawn | the census reason above |

## New findings — round 2

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| R2-1 | MINOR (UX; extends deviation 2) | `app.py` success line (`image_clause` after `project_dir`); `_append_log_line` (`:15240-15251`, which caps a line at the terminal width) | **The LLR-167.3 clause is lost whenever the project path is long, not only at 118 columns.** The clause follows the full project path, and the log line is cut at `self.size.width`. With a work area about 150 characters deep, the clause is gone even at 220 columns, and `tc_b100_16` ×2 and `at_b100_05[220×60]` fail. The verify line (`Saved + verified: … — 1 entry applied before this save (…)`) still names the entries, so the threshold holds in the worktree. But the success line's counts depend on where the operator keeps the work area, and the TC-16 oracles depend on the pytest temp depth. | `r2-green-solo.txt` (3 failures with a deep `--basetemp`); `r2-worktree-envcheck.txt` (green with the default temp) | Put the clause before the path: `Saved project P1 — firmware.s19 + 1 change entry, 0 applied by this save (variant 'firmware') · <path>`. Or route it to the Inc 11 status design with a ledger line that replaces "clipped at 118" with "clipped when the path is long". Either way, TC-16 should read the full message where it is set (the F3 arm already captures `set_status`), not the capped log line. |
| R2-2 | NIT | `tests/test_b100_save_image.py:1295` | The assertion message references `lines`, which this test never defines. A failure would raise `NameError` in place of the assertion text. | code read | Use `statuses` as the message. |
| R2-3 | NIT | `app.py:9341-9342` (`_decide_project_image` Returns) | "Neither the session map nor any service state is written here" is not exact: `rederive_for_save` refreshes `document.issues` (the collision findings), as the apply does. The refresh is idempotent, but the sentence overclaims. | code read | Say "no image byte and no save record is written; the document's collision findings are refreshed". |
| R2-4 | NIT | `apply.py` `save_patched_image` | The image is rendered before the filename sanitizer and the destination guard, so a refused save-back renders the whole image first. | code read | None needed; note only. |

Notes (no finding):

- The `sec/` folder under `evidence/inc-5/` belongs to `security-reviewer`, as in round 1.
- `HANDOFF.md` has moved to `kimi/inc-5-HANDOFF.md`.
- I did not re-run the reverse census or the `at058b` flake runs. Those are the packet's records.

## Verdict

**PASS-WITH-NOTES.**

- F1 and F2 (round 1 HIGHs) are **discharged** by this re-read, with executed evidence:
  - P1 leaves no folder;
  - P2b keeps the app running with the refusal painted;
  - MC is KILLED (4);
  - MF is KILLED (3).
- F3–F9 are closed with killing mutants. F10 is withdrawn.
- No HIGH is open.
- Open notes: R2-1 (MINOR: route to Inc 11 or fix now) and NITs R2-2 to R2-4.

## §4b `Independent review` cell (round 2, for the orchestrator to write)

`code-reviewer` · **PASS-WITH-NOTES** (0 HIGH open; round 2: 1 MINOR, 3 NIT new; round-1 HIGHs F1/F2 discharged) · Both round-1 HIGHs were resolved by corrective pass 1, which I re-read and re-ran on the `8032dead…` / `95da58bf…` / `6d00f17f…` / `11697d6c…` tree.

- **F1:** the emit's `on_placed` (`_emit_landed`) now puts the image on the rollback list the moment it lands. A new `except Exception:` rolls back and then re-raises. Probe P1 leaves no folder (round 1: `P1/firmware.s19` left behind), and my MC is KILLED (4 nodes).
- **F2:** decide and plan run inside `try/except OSError` before any folder exists. Probe P2b, an unreadable source with the handler run as an app callback, paints `Project NOT saved: firmware.s19 could not be read: … Nothing written.` and the app keeps running (round 1: `return_code 1`). MF is KILLED (3).

The rest of round 1 is closed: F3 (MB KILLED 2), F4 (ME KILLED 2), F5 (MG KILLED 1), F6, F7 (MR KILLED 4: the record before the emit is load-bearing), F8 and F9. F10 is withdrawn (census reason). The new defect clause is pinned by MX (KILLED 1).

Open: **R2-1 (MINOR)** — the LLR-167.3 clause follows the project path, so it is cut whenever the path is long. That is not only at 118 columns: a deep temp makes `tc_b100_16` ×2 and the 220-column AT fail. Move the clause before the path, or ledger it for Inc 11. NITs: R2-2 (an undefined `lines` in an assert message), R2-3 (a docstring overclaim), R2-4 (a render before the refusal).

## Hand-offs (round 2)

- **Orchestrator:**
  - R2-1: fix now (clause before the path, and TC-16 reads the `set_status` message), or replace the deviation-2 ledger line with "clipped whenever the path is long" and route it to Inc 11.
  - The round-1 ledger asks still stand: the B100-I15 re-freeze and the 2 lines for deviation 3.
- **`ux-reviewer`:** R2-1.
- **`security-reviewer`:** nothing new from this pass. The defect clause rolls back before re-raising. The round-1 SEC hand-offs stand.
