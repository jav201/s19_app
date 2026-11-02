# Increment 020 — Inc 11 · HLR-175 … HLR-175f / LLR-175.x · the Save project dialog shows exactly what the save will do

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `011` |
| Lane | `main` · 4 SOURCE files (`screens.py`, `styles.tcss`, `app.py`, `services/project_gather_service.py`), at the 4-file cap |
| Requirement(s) | `HLR-175` · `HLR-175a` · `HLR-175b` · `HLR-175c` · `HLR-175d` · `HLR-175e` · `HLR-175f` · `LLR-175.1`–`LLR-175.6` and their suffixes (`LLR-175.1a`–`.1p`, `LLR-175.2a`, `LLR-175.3a`–`.3j`, `LLR-175.4a`–`.4m`, `LLR-175.5a/.5b`) · `LLR-173.7` (the Save dialog's 6 scenarios) |
| Acceptance | `AT-B100-16` (open, folder, clash, escape, empty halves) · `AT-B100-21` (painted half = HLR-175, executed half = HLR-175a) · `AT-B100-02` (re-pinned: `alt+s`, no parent field, refusals read in `#save_where`) · `AT-B100-09` (re-pinned: the summary lists `flows/`, `patches/`, `reports/` before Save) · `TC-B100-47` (LLR-175.1, .1a–.1p, .6) · `TC-B100-48` (LLR-175.2, .2a) · `TC-B100-49` (LLR-175.3, .3a–.3j) · `TC-B100-65` (LLR-175.4, .4a–.4m, .5, .5a, .5b) · `TC-B100-66` (LLR-173.7 extension) — in `tests/test_b100_save_dialog.py` (NEW, 73 functions / 157 ids final), `tests/support/b100_save_dialog.py` (NEW, 35 functions), and 24 re-pinned nodes across 13 test files |
| Interfaces | consumes `_handle_save_dialog` / `_decide_project_image` / `_file_digest` / `plan_project_save` / `validate_project_files` / `sanitize_project_name` / `is_windows_device_name` / `_match_identical` / `_placed_name_candidates` / `painted_names` / `check_action`; adds `SavePreview` + `SaveProjectPayload.plan` + `SaveProjectScreen` (`#project_name` / `#save_where` / `#save_summary` / `#save_ok` / `#save_cancel`) to `screens.py`, the Q10 document-keep arm to `project_gather_service.py`, the dialog layout rules to `styles.tcss`, and `_prepare_project_save` + `_save_session_inputs` + `_current_save_session` + `_save_dialog_preview` + `_compose_save_preview` + `_confirm_project_save` + `_commit_project_save` + `_SaveSession` to `app.py` |
| Agent | design-first experiment (`dev-flow-v3-beta` pipeline): E1 requirements · E2 Code-Wire baseline + prototypes (G-A/G-B) · E3 code-free design review (3 rounds: architect + security) · E4 parallel build (2 DeepSeek implementers + Opus tester, then Opus integration) · E5 validation (80 mutants on DeepSeek v4 Pro via pi, code + security review on Opus, one corrective pass on Opus, then a narrow round-2 re-review) · E13 capture. Models per stage in the step table below |
| Date | `2026-10-31`–`2026-11-01` (E1 start 14:32Z through E13 00:40Z, all UTC) |
| Base | `1747479` (Inc 10 integrated on the corrected 9b); `b100-inc11` branches from `1747479`, merges `main` at `051f586` after 9b and Inc 10 closed (one conflict, the `test_id_registry` bound, resolved to 233), then takes the corrective pass at `24f779f`. Tree at `24f779f` plus the E13/close commits at the time of writing |
| Import proof | `s19_app.__file__` printed in every transcript header (the worktree's `s19_app/__init__.py` for GREEN/guards runs, a scratch copy's for RED/mutant runs) |

---

## 1 · What changed

**The feature (HLR-175 … HLR-175f).** The Save project dialog (`ctrl+s`) now paints exactly what the save will do before it runs: `#save_where` names the sanitised folder and its kind (`new folder`, `updates the open project`, `merges into an existing project`, `new project in an existing folder`), and `#save_summary` lists one row per file row of the plan, one row per sub-folder with its file count, one row for `project.json`, each with its landing name (and source name when the two differ) and its action word. One preparation (`_prepare_project_save`) decides what the dialog shows and what the save does, so the dialog cannot say "saves" while the handler refuses.

- **HLR-175 — the dialog paints the plan for the typed name.** 7 scenarios (fresh, pending patch, refused, `files`, document, merge, save-as) → the painted rows equal the painted plan's rows by landing name and action word at 220 columns; `a b` → `ab`, `new folder`. `SaveProjectScreen.plan` exposes the painted plan as an immutable value (LLR-175.4k).
- **HLR-175a — Save writes exactly the plan the dialog painted.** The executed plan is the painted plan object (dataclass identity), by full path and action; the active CRC template and the batch/assignment documents are copied outside the plan (A11-06). An out-of-date summary at Save repaints and does not save (LLR-175.4b).
- **HLR-175b — a refused name is explained before Save.** 15 token pairs (the 9 name refusals and the 6 save refusals) painted in `#save_where` with the dialog open and `#save_ok` still focusable (LLR-175.1a–.1p, LLR-175.3f, LLR-175.6). Before Inc 11, every one of these reached the engineer only after the dialog closed.
- **HLR-175c / HLR-175d — `escape` saves nothing; an empty Save is explained.** `escape` and `#save_cancel` dismiss with `None`; an empty/all-space Save paints `name is empty` / `type a project name` and stays open.
- **HLR-175e — only into this work area.** No `#project_parent_path`, no `#save_browse`; the payload's `parent_folder` is the work area (LLR-175.2, LLR-175.2a).
- **HLR-175f — one dialog, the five `pc_B` ids.** Opens with the focus in `#project_name`, the open project's name prefilled and selected, plain letters stay in the field, `alt+s`/`enter`/`#save_ok` save, the four app priority keys are inert, nothing-loaded paints one status line and opens no dialog (LLR-175.3d–.3j).

**The one preparation (LLR-175.6).** `sanitize_project_name`, `is_windows_device_name`, the reserved-home comparison, `PROJECT_NAME_MAX_CHARS`, `_project_folder_refusal` (target) and `_plan_project_save` are reached by Save project only inside `_prepare_project_save` (an AST census); 16 names → the dialog's painted token pair equals the direct `_handle_save_dialog` call's status-line pair.

**The per-open session (LLR-175.5, .5a, .5b, .4m).** The image decision and the session-file digests are computed once per open (the emitted image is not digested, B11-36), the first frame paints before the decision, the plan recomputes at most once per 150 ms with a trailing run, and a load that lands while the dialog is open rebuilds the stale session before any plan or confirm reuse (SE5-11-1, `image_generation`).

**Corrective pass (E5).** Both round-1 reviews blocked: the code reviewer's MAJOR CR11-F1 (a save-as inventory cached in the live session reached a later non-save-as plan and crashed the commit) and the security reviewer's HIGH SE5-11-1 (a load landing under the dialog made the save write a different image from the one painted). One corrective pass (Opus) applied SE5-11-1, CR11-F1, CR11-F2 (19 requirement-tagged comments restored), CR11-F3 (the sentinel annotated), CI9b-1 (the `IfExp` selector), CI9b-2 (`test_at042b` re-pin) and SR-11-name-cap. Round-2 re-review: code PASS (0 findings), security PASS-WITH-NOTES (1 MINOR SE5-11-3 = O-3). Mutants: 80 run → 62 killed / 18 survived / 0 invalid; 7 survivors killed by the corrective pass, 10 accepted equivalent, M-47 removed as a redundant guard.

**Process decision (operator override 2026-10-31).** Per increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The touched-module run and the full suite are deferred to the batch-end battery (§7). The full new file `tests/test_b100_save_dialog.py` ran once (`green-06`, on an intermediate state before MUT11-M-47); `green-05` covers the final source.

## 2 · Files modified

Branch history: `b100-inc11` was branched from `1747479` (Inc 10 integrated on the corrected 9b), merged `main` at `051f586` after 9b and Inc 10 closed (one conflict, the `test_id_registry` bound, resolved to 233), then took the corrective pass at `24f779f`.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens.py` | source | HLR-175 … HLR-175f · LLR-175.2 · .2a · .3 · .3a–.3i · .4 · .4b · .4h · .4i · .4k | `SavePreview` (the S-a value type), `SaveProjectPayload.plan` (read-only), `SaveProjectScreen` (keyword-only constructor, `AUTO_FOCUS`, `BINDINGS` `alt+s`/`escape`, `enter` → save, the debounced `preview` timer, `_paint`/`_mark_shown`/`_shown`, `action_save`/`action_cancel`, `_dismissed` checked first); CI9b-1 replaces the `IfExp` selector in `LoadDialog.on_mount` with two literal `query_one` calls. Final sha256[:16] `dc988721ae7b6a87` |
| `s19_app/tui/styles.tcss` | source | LLR-175.4h · .4i · .4j | the Save-dialog layout rules: `#save_summary` bounded (`max-height: 50vh`) and scrollable, rows `height: 1; nowrap; ellipsis`, the box capped at 90% height. Final sha256[:16] `038fd8dbc034373e` |
| `s19_app/tui/app.py` | source | HLR-175 … HLR-175f · LLR-175.1 · .1a–.1p · .4 · .4a–.4m · .5 · .5a · .5b · .6 | `_SaveSession` (+`image_generation`, +`digests` annotation, the sentinel key), `_save_session_inputs`, `_current_save_session`, `action_save_project`, `check_action` (`SaveProjectScreen` joins the whole-stack guard), `_prepare_project_save` (the one preparation, the moved G3–G18 body with its requirement comments restored), `_save_dialog_preview`, `_compose_save_preview`, `_confirm_project_save`, `_commit_project_save` (the split), `_plan_project_save` (the `inventory` argument used only in the walk branch, CR11-F1), the router (identity match, the per-open state clear). SR-11-1 defers the LED .52(a) rebind. Final sha256[:16] `1a3ed1e9ed0976eb` |
| `s19_app/tui/services/project_gather_service.py` | source | LLR-175.4a (Q10) | the Q10 document-keep arm: `_match_identical` over the copied files, `_placed_name_candidates` with `normcase` for the free-name walk. Final sha256[:16] `e11a5e75d7346183` |
| `tests/test_b100_save_dialog.py` | test | HLR-175 … HLR-175f · LLR-175.1…–175.6 · AT-B100-16 · AT-B100-21 · TC-B100-47/48/49/65/66 | NEW module (73 functions, 157 ids final; 154 at E4, then the corrective arms and the MUT11 arms) |
| `tests/support/b100_save_dialog.py` | test | HLR-175 … HLR-175f · LLR-175.1 … LLR-175.6 (the shared drives) | NEW module (35 functions): `SaveDialogFakes`, `bare_save_dialog`, `type_and_await_summary`, `refuse_in_open_dialog`, `save_through_dialog` |
| `tests/test_loadfilescreen_input.py` | test | LLR-175.3c | `test_at042b` re-pinned to SEC9b-1 ruling B (an over-long paste is refused → `''`); `test_ac2_paste_reaches_project_name_input` built by `bare_save_dialog` |
| `tests/test_id_registry.py` | config | HLR-175 | `EXPECTED_SCANNED_TEST_FILES` 231 → 233 (measured, F-9; the bump names `tests/test_b100_save_dialog.py` and `tests/support/b100_save_dialog.py`) |
| 13 re-pinned test files | test | HLR-175 … HLR-175f | the 24 re-pinned nodes listed in `inc-11/E4-tester-notes.md` (each keeps what it proves, changes only how it reaches the dialog) |
| `tests/test_tui_directionb.py` | test | HLR-175 | re-pin (53d08d5) |
| `tests/test_tui_manifest_save.py` | test | HLR-175 | re-pin (53d08d5) |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-175 … HLR-175f · LLR-175.x · LLR-173.7 | E1/E3/E5 edits (LED .92–.94) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-175 … HLR-175f · LLR-175.x | LED .92 – .94 |
| `.dev-flow/BACKLOG-CODE.md` | doc | HLR-175 | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-11/*` | doc | HLR-175 … HLR-175f | the experiment records: `E1-scope.md`, `E1-rulings.md`, `E2-rulings.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-020.md` | doc | HLR-175 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-11/*` | generated | HLR-175 | transcripts (evidence digest table at the end of §4) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | HLR-175 | orchestrator-owned: scenario `sd-dialog` |

## 3 · How to test

```bash
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
# the new Save-dialog module (every node):
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_save_dialog.py
# the re-pinned nodes (targeted):
python -m pytest -q -p no:cacheprovider tests/test_b99_staging.py -k "tc_b99_14 or at_b99_05 or tc_b99_ux_c10"
python -m pytest -q -p no:cacheprovider tests/test_loadfilescreen_input.py -k at042b
# guards (the frozen-engine guard, the registry, the staging re-pin):
python -m pytest -q -p no:cacheprovider tests/test_id_registry.py tests/test_b99_staging.py tests/test_engine_unchanged.py tests/test_b100_load_question.py tests/test_b100_load_dialog.py
# mutants: evidence/inc-11/mutation-summary.md (80 rows) + mut-kill-03-corrective.txt (the E5 re-runs)
# NOT run per increment (operator override 2026-10-31): the touched-module run and the full suite -> batch-end battery (§7)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-11/`. **Final source hashes** (sha256[:16], verified with `sha256sum` at close): `screens.py` `dc988721ae7b6a87` · `styles.tcss` `038fd8dbc034373e` · `app.py` `1a3ed1e9ed0976eb` · `services/project_gather_service.py` `e11a5e75d7346183`. Branch history in §2: `b100-inc11` branched from `1747479`, merged `main` at `051f586`, corrective pass at `24f779f`. Import proof in every header; `NO_COLOR` unset.

**Scope (operator override 2026-10-31, stated plainly):** run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The whole touched modules and the full suite are **deferred to the batch-end battery** (with fix rounds for failures found there). The full new file `tests/test_b100_save_dialog.py` ran once (`green-06-full-new-file.txt`, on an intermediate state before MUT11-M-47 and the MUT11 arms); `green-05-final.txt` covers the final source. Two first-run failures are kept and reported as failed: `green-01-new-run1-failed.txt` (F-8, a stale-paint race) and `guards-01-run1-failed.txt` (F-9, the registry bound).

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | TC-B100-47/48/49/65/66 + AT-B100-16/21 (`tests/test_b100_save_dialog.py`), the re-pins (`tests/test_b99_staging.py`, `tests/test_loadfilescreen_input.py`, `tests/test_id_registry.py`, and 11 more files) | `executed` — `green-01-new.txt`: **154 passed** (1472.9 s); `green-02-repinned.txt`: **35 passed** (580.4 s); `guards-01.txt`: **249 passed, 4 skipped** (1227.7 s); `green-03-corrective.txt`: **7 passed** (48.1 s); `green-04-new-and-guards.txt`: **112 passed, 2 skipped** (700.4 s) + the 2 skips re-run **2 passed** (19.1 s); `green-05-final.txt`: **68 passed** (537.5 s); `green-06-full-new-file.txt`: **157 passed** (1554.8 s) |
| **B · black-box** `AT-NNN` <-> story | `core` · `full` | AT-B100-16 (five halves), AT-B100-21 (painted + executed halves), AT-B100-02 / AT-B100-09 (re-pins) | `executed`: in `green-01-new.txt` (AT-B100-16/21) and the re-pin runs; RED `red-01-vs-base.txt` fails all 154 new-file nodes on `1747479` (no `SaveProjectScreen` preview) |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| E4 tester's new tests vs base `1747479` | `red-01-vs-base.txt` | **154 failed** (1974.1 s) — every node RED on base (no `#save_where`/`#save_summary`, the keyword constructor, no `_commit_project_save`/`_save_dialog_preview`/`plan`, no `SavePreview`) |
| E4 tester's re-pins vs base `1747479` | `red-02-repins-vs-base.txt` | **33 failed, 2 passed** (524.6 s) — the 2 passes are the base-green re-pins (no RED claimed: TC-B100-09's classification and TC-B100-57's widened census) |
| E5 corrective arms on the pre-fix source `051f586` | `red-03-corrective.txt` | Part 1 **4 failed, 3 passed** (49.6 s) — the 4 expected RED (SE5-11-1 both layouts, CR11-F1, CI9b-1); the 3 passes are the name_cap and the two at042b ids (re-pin, expected green); Part 2 the name_cap mutant run **2 failed** (25.3 s) |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| the painted plan | `red-01-vs-base.txt`: all 154 nodes fail on `1747479` (the dialog paints no summary and no where line); the `_shown` guard is killed by M-20 (`int-mut-M20.txt`: confirm got `('fresh1', SavePlan(...))`) |
| the one preparation | `test_tc_b100_47_one_preparation_ast_census` (0 other Save-path call sites); the dialog line equals the direct status line in 16 of 16 names |
| the session generation | SE5-11-1 RED on `051f586`: `derived_from.base` is `firmware.s19` (same ranges) and `KeyError: 2147549184` (other ranges); the rebuild arm GREEN on `24f779f` |
| the save-as inventory | CR11-F1 RED on `051f586`: `folder reports/ (3 files) — new` painted for `R`, then `AttributeError: 'NoneType' object has no attribute 'joinpath'`; the vanished-source arm GREEN on `24f779f` |
| the strasse clash | the single node passed (probe 3 of the security review); the `straße` merge arm follows SR-11-1 |

### Mutation verdicts (C-40)

**E5 run on `051f586`** (`mutation-summary.md`; every transcript ends `restored = True`): **80 rows total. 62 KILLED, 18 SURVIVED, 0 INVALID.**

| Verdict | Mutants | Disposition |
|---|---|---|
| KILLED | 62 | each failure read for a behavioural assertion, not only the return code |
| SURVIVED, routed to the corrective pass | M-09, M-14, M-42, M-45, M-68, M-74, M-96 | new or strengthened arms in E5, all KILLED (`mut-kill-03-corrective.txt`, 7 of 7) |
| SURVIVED, equivalent | M-01, M-02, M-05, M-29, M-31, M-44, M-55, M-87, M-88, M-92 | recorded, no code change (10) |
| SURVIVED, removed | M-47 (the blank-name guard) | removed as a redundant guard (prefer removal); covered by the existing empty-name arms |

**Final count (E5): 62 KILLED at first, 7 survivors KILLED by the corrective pass (69 killed of 80), 10 equivalent, 1 removed (M-47), 0 INVALID, 0 non-equivalent survivors.** Killed by runtime exception, standing as killed: M-11, M-21, M-52, M-66, M-70.

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| the dialog | `SaveProjectScreen` is keyword-only and computes nothing in its body; 0 calls of `_decide_project_image`/`_save_session_inputs`/`_file_digest`/`_prepare_project_save` in it; `#save_ok` and `#save_cancel` labelled `alt+s`/`esc`; `#save_box` is not `#load_dialog` |
| the plan accessor | `SaveProjectScreen.plan` is read-only (`FrozenInstanceError`, `AttributeError` on assignment/append); `None` while no plan is painted |
| the one preparation | the AST census: 0 other Save-path call sites for `sanitize_project_name`, `is_windows_device_name`, the reserved-home comparison, `PROJECT_NAME_MAX_CHARS`, `_project_folder_refusal`, `_plan_project_save` |
| the rows | action words only `new`/`keep`/`merge`/`rewrite` (no `replace`, E3 R1); names painted through `painted_names` with markup off (0 spans) |

### Guards and snapshot cells

| Run | Transcript | Result |
|---|---|---|
| guards attempt 1 (kept) | `guards-01-run1-failed.txt` | **1 failed, 248 passed, 4 skipped** (1282.7 s) — `test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` (`233 == 231`, F-9) |
| guards on the integrated bytes | `guards-01.txt` | **249 passed, 4 skipped** (1227.7 s); the 4 skips `not-run` (MAX_PATH under the scratch basetemp, the same 4 as Inc 9b's own evidence) |
| the census sweep (`-k census`) | — | **not run** (operator ruling; batch-end battery) |

### Reviewers' probes

The code reviewer executed `probe_stale_inventory.py` (the CR11-F1 scenario on `051f586`: `session_inventory_filled: True` · `R_save_as_source: None` · `R_copies: [...]` · `commit: AttributeError: 'NoneType' object has no attribute 'joinpath'`; re-run on `24f779f`: `R_copies: []`, `commit: returned`) and re-read the diff. The security reviewer executed `probe_midload.py` and `probe_midload2.py` (the SE5-11-1 layouts; round 2 re-runs: the app keeps running and the save writes the new file's image), and the single node `test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash` (passed). The full suite and the touched modules were `not-run` in both lanes (out of scope; batch-end battery).

### Security probes

`security-increment-020.md`: SE5-11-1 (the stale-session image disagreement, probes 1 and 2 — HIGH, closed), SE5-11-2 (length checks before the casefold rebind — NIT, backlog), SE5-11-3 = O-3 (the confirm→dismiss window — MINOR, backlog). The E3 mitigations were re-verified: S11-01/SR-11-1 (file identity + the deferred rebind), the links/junctions walk, time-of-check vs time-of-use, the lazy-inventory fill, the SR-11-3 sentinel, partial writes and the manifest backup, names painted from disk. Full per-question results in `security-increment-020.md`.

### E13 (C-UX-5) evidence

Orchestrator-owned captures, real Windows Terminal: scenario `sd-dialog` (loads project `P`, opens `ctrl+s`, replaces the prefilled name with `P2`, leaves the dialog open painting the new-project plan). Painted text: `P2 — new folder`, three rows (`firmware.s19 unchanged copy`, `image firmware.s19 — new`, `project.json — new`), `Save (alt+s)` / `Cancel (esc)` fully visible. **3 PNGs** in `evidence/inc-11/e13/` (`sd-dialog.118x54.png`, `sd-dialog.220x60.png`, `sd-dialog.99x54.png`), `DONE failures=0` (`E13-notes.md`). At every size the where line and every row is one line with 0 style spans, both buttons are inside the box, and nothing clips; the 80%-width cap at 99 columns leaves the Context pane visible by design. No OBS.

### Experiment step table (from `inc-11/steps.log`; UTC)

| Start | End | Step | Agents | Outcome |
|---|---|---|---|---|
| 14:32 | 14:54 | E1 | 1 x Opus | 52 requirements; rulings Q1–Q11 (Q10 accepted: `project_gather_service.py` as the 4th file) |
| 17:06 | 17:30 | E2 | 1 x Opus (baseline + prototypes) | baseline 42 nodes; prototypes G-A 16 nodes/69 examples, G-B 16 nodes/81 examples; proposals ruled |
| 17:30 | 18:20 | E3 (3 rounds) | 2 x Opus (architect ∥ security) + 2 design-fix passes by DeepSeek v4 Pro | r1: arch FAIL (6 MAJOR), sec PWN (1 MAJOR S11-01); r2: arch FAIL (3 new MAJOR), sec PWN; r3: arch PWN (0 MAJOR), sec PWN; E3 closed, addenda R3-01/R3-02 |
| 19:33 | 23:18 | E4 | 2 x DeepSeek v4 Pro (G-A + G-B) + 1 x Opus (tester), then 1 x Opus (integration) | 154 new ids RED 154/154; GREEN 154/154 new, 35/35 re-pins, 249+4skip guards; 1 source fix (SR-11-1), 7 test fixes |
| 23:20 | 00:31 | E5 | 1 x DeepSeek v4 Pro (mutants, 35 min) + 1 x Opus (code + security reviews, then corrective) | reviews FAIL (1 MAJOR + 1 HIGH); 80 mutants 62/18/0; corrective pass done; green-05 68 passed |
| 00:35 | 00:40 | E5 round 2 + E13 | 1 x Opus (round-2 re-reviews) + 1 x DeepSeek v4 Pro (E13) | code PASS, security PASS-WITH-NOTES (SE5-11-3 MINOR); `sd-dialog` 3 PNGs, failures=0 |

Note (corrected at close): times in this log are local (UTC−6), not UTC; see 05-postmortem.md Record corrections.

First step start to the last logged step: 14:32Z to 00:40Z = about 10 h 8 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 7 MAJOR in round 1 (A11-*, S11-01/S11-02) and 3 new MAJOR in round 2; E5 (code) caught 1 HIGH (SE5-11-1) and 1 MAJOR (CR11-F1); 1 corrective pass; 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-11/` | SHA-256 |
|---|---|---|
| sd-dialog.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-11/e13/sd-dialog.118x54.png | f010f6ce04e07181d7458e957cb61d269a8afa889860fa0a7a6f8400cb4077b4 |
| sd-dialog.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-11/e13/sd-dialog.220x60.png | 981226405b5f448eef60d76e424fb3d9e9d5c5f6c80407dbb78c00316192c57c |
| sd-dialog.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-11/e13/sd-dialog.99x54.png | 838e458cad183a21274a4fea7cb96e3cff59eeaa5594586f7c0068243f0f6f3c |
| green-01-new-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-01-new-run1-failed.txt | 4b26d887e111dc31ae989c54085fe9acc2d1eefe3c3a7ab3c0d328fc0def8ae1 |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-01-new.txt | 578613de9a7ae8f9afde1332b260277cd3d6785fe992764ee71c8a162c7a9155 |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-02-repinned.txt | 6c2ddb956b9b5a18fc98e10924668684a1bd9891f19ad1edd3f505ac2f82e969 |
| green-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-03-corrective.txt | 00e129b425da66851c7c39b23408c957da2a4a5075323ba577f647b7f67e4125 |
| green-04-new-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-04-new-and-guards.txt | 4008865790259e660dfa7bcf9886fa6ef7f4dd2c3716d7fc37f9e5699aa95e09 |
| green-05-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-05-final.txt | 6e8b43da85248fd56eb06008eaedf6e231f2a1284a679aebb264aa25635d823d |
| green-06-full-new-file.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-06-full-new-file.txt | 800d2e9ab4d8f0803205ca8616814acee7c4e58a5c1a2ccc84af6ae00d7a1222 |
| guards-01-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/guards-01-run1-failed.txt | 36fd5398d40ccbb9726e05179e68ba0b2dfa0e8b4a5069a6352f9668af4d7b06 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/guards-01.txt | 42bb04539f5fd2a8165e9d680044e55aa771866445a6cd260ba53c9645d94660 |
| int-mut-M20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-mut-M20.txt | 30b3e7f9c2a2db29116da90a17778e11d63224fab664e645371c82e59804685a |
| int-probe-shown.out.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-probe-shown.out.txt | a8f2b715a1ad8f240258f2ded4e8ae93fe9175a09fec9c5c17129c131e8be55c |
| int-probe-shown.py.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-probe-shown.py.txt | 2ff6f9756e7f681b352b6227cc867e387b9299f7c9ca1cd7079a1eca15aae268 |
| int-probe-strasse.out.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-probe-strasse.out.txt | 91a0368afe52474b33986ad5de370fd80f0128947c543ecf8b8faaed4f18acd0 |
| int-probe-strasse.py.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-probe-strasse.py.txt | 1bddb6db9ee463c398766ddc18afeb8bc03056a0fac8a832bbfc8b46a1dee079 |
| int-refail-diagnostic.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-refail-diagnostic.txt | 36dee204fd5a5fb4341234b1f0f6f7a6803270985a815afc6b833c9b2021d6b1 |
| mut-M-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-01.txt | 54c3edda1a2497de1de1816737b54360d9f79ec29adf8dd545e642e7da393853 |
| mut-M-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-02.txt | 1df753c1453d37d61c5bcb8d202788d39b097adb452dd77601f47d751ac2e0b6 |
| mut-M-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-03.txt | 1fba75a5addf85e0d4bd5b1fddb764fbf68a3d389b1d5d6e21836f83841efe4b |
| mut-M-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-05.txt | 3b1b5d349b76e749218283bb310783d36b867a91e96394f24af467d124ee8015 |
| mut-M-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-06.txt | 94e839bbeec42f024104b99bc0a1fc2d67c2b8873c0d77e51630dadae7257b95 |
| mut-M-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-07.txt | 485a53a46b6950d4693c635e33fc336b6a9ce0dbd77dff8baae606ca8a3dd058 |
| mut-M-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-09.txt | 08a0b3b5c2fca15db3bae94e28661fa9e76afe6f90f3554616cc1a3d1290919d |
| mut-M-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-10.txt | 3cb26ec61d202ec0d6220f36f947b78fbfc74006d5a50db9fcc83e55314ccd1d |
| mut-M-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-11.txt | 871dd611d1221dd0581bd36b937cfdf4ae07724126e68128e0b282e552d7fd45 |
| mut-M-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-13.txt | 3ecda80707039ddf1bcd904fa7105ce64f61a4d0b9fd25876620a21d933b2c6b |
| mut-M-14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-14.txt | 0a610b01340da038cdf96b66c2d9f2a6d5d1346f189ae8bd8615bdbc43d76ec1 |
| mut-M-15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-15.txt | 9526668336cbca1229115a285a8d50fc52de92b43b0818468aeaa0e0acdceed8 |
| mut-M-17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-17.txt | 4af2b1f5144ec131a9429ed6f1d14307d1827ad91529de42c6fd99b1acbc6d01 |
| mut-M-19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-19.txt | 81649b17e786b3a1d1cac3f9777df60e0f978abe9305180108898303f2a9f9cc |
| mut-M-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-20.txt | 71071685bbd6275e110c39a702bd28e517bb470b41cd265c89cf801b2974ee26 |
| mut-M-21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-21.txt | fd7539b23962869c742849991b6c4c1d6e0dcd3506dd38e9ec2754c5daeafee1 |
| mut-M-23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-23.txt | afafe110dd4a44ba4702d93e3d5e4e32e87d403632a7548ec9d732c936d84103 |
| mut-M-24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-24.txt | 4c47cd98d6ffbb4627f5ef7d4d33ac0f94d50e2bd993579c131caf2ed44ccefc |
| mut-M-26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-26.txt | d34d7517a147f1df7f78be10d45e31f90bee728ac0c3de52e096c01e115e2747 |
| mut-M-27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-27.txt | cd762280b3dce75bd874531e2a40623419a28f12a60b6c852713883b3ab798c7 |
| mut-M-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-28.txt | 05e15bc7fb1c887fac6450d0d2714cc7312493f72719cf326c08b59e132b2cc8 |
| mut-M-29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-29.txt | b7818e07a40070d2b68e55675d8df2b25b32e411a6e842aedeed9ec7744fe419 |
| mut-M-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-31.txt | c7153048e1479242ae0e3f74131509c47f2624bf320eafcf51a296124770e4f6 |
| mut-M-32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-32.txt | 274b5b01ec927a55e600687f44c4c7bb60b1300901090df2586f92eb65780d13 |
| mut-M-33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-33.txt | c62f6ba3e4d9f7e9b7f7cb2346aa3e8421f92742743d879afd23e1a26320c3b1 |
| mut-M-35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-35.txt | ba5e42f30828668d91c815d05c8de91081fca6bb4403a24c72651511b2794f57 |
| mut-M-36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-36.txt | 8dcd37847b7d0d1800b0a5023c83cc81a94cb49447edf61c81ac173dfb67b967 |
| mut-M-37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-37.txt | 30909d7e4eb6016f58079bfc2efeb9a341e0f9f4386097d003dccea2e4a9c05d |
| mut-M-38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-38.txt | a232267214887ac0ab918e98c7258f105b3a61af901995cedef20b47b0a29de6 |
| mut-M-40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-40.txt | cb41195e5d256ee3e9ee2e8bf534b6f54a27e8120feae19f8c2e3b5fa3792a93 |
| mut-M-41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-41.txt | 98cf94e59d186e4e751cdbd47882eeaa052010758d29faa11a85b00fd0a1d16e |
| mut-M-42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-42.txt | 784122461da7b25a4455d846be154d499464265c1a1dd1e4a1fa343e1b15e56f |
| mut-M-43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-43.txt | 695947c36f6d353408b685358d40f867fabcd3a8313368740898b68dc12ccf58 |
| mut-M-44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-44.txt | 64da981e7e29da3bddaf3d4b8bc7164ee75588b4fad5406f04d5ef16bf636de3 |
| mut-M-45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-45.txt | 7828cb02f3a1747c4af2349a7c304b2dbfba746de0c63cdea9e979a088109fa3 |
| mut-M-47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-47.txt | 9bcd61641bb41aea7def66aac47d4ab545da515f603852c4aed9d5ffb1b687a3 |
| mut-M-48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-48.txt | 4563477764a64c754b6745bf532db28bdf9f6c1ac3e9644d1c9938fb44ae2e29 |
| mut-M-49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-49.txt | e5aac6a9e8491e2c4e18cb3278ea0b8c2c36b6bb1bcc849a1ffa4914c6e63c0a |
| mut-M-50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-50.txt | 849f4bbf78f1b00e44e80012caf48c173f865e27dfab4ee1c8966850d4e7fe4b |
| mut-M-51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-51.txt | 59751b6b5b51caf45075340e90b573981fde6a238d10025cf50d69d7743882c5 |
| mut-M-52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-52.txt | 87c2eb262357087094ddc20bb39f01a3a347573b59f8c3bcf4d3c4b75f2fee96 |
| mut-M-53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-53.txt | 93560eb483150e24e43ece60e506b226d80ee8f70867bbe61b42ae2d17884a60 |
| mut-M-54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-54.txt | ae82b27392a2e5f7fee530271571425591388cb604b4b64dd07a444cf9d13b83 |
| mut-M-55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-55.txt | 2ceef993a1096add7005b84c9a785082554e34ec9ec0b99b854bd45112c65ea5 |
| mut-M-56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-56.txt | a3b9a9cbac83937d3c5d24dbfcc8cd1923f4ea02fb0219cda607504d3fb9365d |
| mut-M-57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-57.txt | cd09e27deb2715258c5abfaaa39990fec342d3d8e7accd1c1f8d35a928cb31b9 |
| mut-M-58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-58.txt | a54cc1fe41121a0eff814bff3c69d46d47fcca3df8d31f4f9bf639843b1230b7 |
| mut-M-59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-59.txt | 3ba1cbfb77f854fcf90aa1d26e2c30d445f412de91d1a2a38dbf7412338f92f4 |
| mut-M-60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-60.txt | e6af6745864f09ccf595939d3eee8d5b5fc05429d66f6cb96ddeab926c0438d8 |
| mut-M-61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-61.txt | 30639cb1256b2074eb42bf6d71e4359c1063a855ffa580eccf89e16c83ab6ed2 |
| mut-M-62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-62.txt | e2fa4fb5757b93132444ba239b70b15a1a9019cd621569a6a271009190cc295e |
| mut-M-63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-63.txt | bbbfe1200632c8bda14d98bf353536bd676db3db4b97dd51800776c60627b427 |
| mut-M-64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-64.txt | 21a7e674930ad1d71a414ac242e6e170e68ba6a174581ab925788922379dc6bc |
| mut-M-65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-65.txt | e5039d4eadbd97bef9ea5d03d80acd05441725dad984989990e812f121776db4 |
| mut-M-66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-66.txt | b5224c55b90156aecdffa2903c50b264013e419d9437ad6b8e77ac42e48f4901 |
| mut-M-67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-67.txt | 257d24df83e09fbc8e61f49b3a3c196d578a5e13f57d13d385166e3aabce00ad |
| mut-M-68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-68.txt | 33dd2b17cd06263f9213a789af09badc9d30f5bfeefd0ba33e64792f041f8541 |
| mut-M-70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-70.txt | 11a19410763fb3883398118d44e64a68222465cadb086afdb742ba1460c1c996 |
| mut-M-71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-71.txt | 934b15bafd4ec6013a021e57890e74e2b404ca1f4520f2714703c49656a1803f |
| mut-M-72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-72.txt | 85703c4cb3a21e6f7358aeeeb65988b70b1264ea857bf2190ddce5e37b7e254d |
| mut-M-73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-73.txt | 80353fde6643a3240d725e9dc3d942626f12c0a3616addf1ce9753592132fb6d |
| mut-M-74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-74.txt | 516edc73959c548a780755ba354d51193a6988330867d77dbfc0538d3c766509 |
| mut-M-75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-75.txt | 0123c4b60ccd394fe0274f776d5285fb340d027949164992bd74ffec37ae00a0 |
| mut-M-76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-76.txt | 0125c69a62799e1910bda4d8806f5063ef45d9111a898051d50682e989969dbc |
| mut-M-77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-77.txt | e4742f773b14b9191ffa8dd7375a3988cdd846b63e9d6a411ab5d1278ff156cd |
| mut-M-78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-78.txt | cde2745dc0a9229344973740e2b8ef752a753ff048ad3d1d6ab917b4e93b93c8 |
| mut-M-79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-79.txt | 3258ec906f906416a90a4b2314e2e171e39a0eaf7fc53f2736d1bf4cc0f6c51f |
| mut-M-80.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-80.txt | 2735345a31abe1205715ca9b61291811bff5b5cd2bc766a2f9048539825a53da |
| mut-M-81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-81.txt | ad41e445ff92da1c4ef6358d3e222d007f573e958c23ded70ae36c172d3105d2 |
| mut-M-82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-82.txt | 25bd7b9fae715f6576ba1f8b5576b18ce96541462276dc4496be979b236c8154 |
| mut-M-83.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-83.txt | e278a357b7280ea1d2d8bc34c0b6d550a7d2fad31320374e07cc034cdf24f37a |
| mut-M-85.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-85.txt | 25f852db3f6911e91bff1fae0858558bd50a875672fa0071041cb066141dfe3b |
| mut-M-86.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-86.txt | 031c5863ee4d2713212974c0e17b4840216e3094b4349754af7247da1c627195 |
| mut-M-87.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-87.txt | c2e87365e091cb83af51c0c070c2d8b9471593d22b0d857cdcc14706bb2748dd |
| mut-M-88.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-88.txt | e2e4052d18e7461d6ec25efbcd74287441de780e56c494bbc8403b9f546bead6 |
| mut-M-89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-89.txt | c41145d014a42f330dfa3c8bf5d94560049535445002e93b17f65360109b19e4 |
| mut-M-92.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-92.txt | 310435637a4c7c5a456ca338ba5919a3f695ea4f92f56bd658e435b421f4c91b |
| mut-M-93.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-93.txt | 1524af525e0a48615fe4a9bee3059594c5dbd9ae22bc27749a49697b3d6c1f35 |
| mut-M-94.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-94.txt | b1c548a0e93cf75bf77e9300d2d9404fabbdce02eda405c64bb97b994b9f3f30 |
| mut-M-96.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-96.txt | eea0e639a80207a3c481fd7465baf25befd678b925c8c8e813610a85fc808461 |
| mut-kill-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-kill-03-corrective.txt | 151d036392afa78fb9e55159da1f427a6f3e2644b2fcad3a71b84f1e4f7a2f6c |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mutation-summary.md | 942a2ce7158398f324da4b03d6f9a86f54fb4930cd5503569c78dacf50df6e72 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/red-01-vs-base.txt | 73d721bd175e2b3fd53c1b459fcfbef2d609dda435f8269a7e08cd357f38244b |
| red-02-repins-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/red-02-repins-vs-base.txt | 1b5cc5f90248c72aa34e5de8425490f17813eba2d7f5feb91e4293cbaf139638 |
| red-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/red-03-corrective.txt | d37701ed916244f3b1d840a5d2672f50faf60cf32d5bfe16753fa9b5a1aed6a8 |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · round 1 **FAIL** (0 HIGH, 1 MAJOR CR11-F1, 1 MINOR CR11-F2, 1 NIT CR11-F3); round 2 (narrow re-review of `24f779f`) **PASS** (0 HIGH, 0 MAJOR, 0 MINOR, 0 NIT) — "`BLOCK-UNTIL: F1` is discharged"; the F1 probe re-run shows `commit: returned`. — `review-increment-020.md`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · round 1 **FAIL** (1 HIGH SE5-11-1, 1 NIT SE5-11-2); round 2 **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR, 1 MINOR SE5-11-3 = O-3) — "SE5-11-1 is CLOSED (applied and verified)"; probes 1 and 2 re-run, the arm `SD::test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session` passed (2 of 2). — `security-increment-020.md`. **Design reviews (E3, code-free):** `architect` (3 rounds: r1 FAIL 6 MAJOR, r2 FAIL 3 MAJOR, r3 PASS-WITH-NOTES 0 MAJOR) and `security-reviewer` (2 rounds: r1 PASS-WITH-NOTES 1 MAJOR S11-01, r2 PASS-WITH-NOTES 0 MAJOR) → design approved (`inc-11/E3-architect.md`, `E3-security.md`). **There WAS a narrow re-review (round 2), because both round-1 verdicts blocked** — the MAJOR CR11-F1 and the HIGH SE5-11-1. **Orchestrator (2026-11-01).** Final source hashes `screens.py` `dc988721ae7b6a87`, `styles.tcss` `038fd8dbc034373e`, `app.py` `1a3ed1e9ed0976eb`, `project_gather_service.py` `e11a5e75d7346183`. Scope ruling in force: per increment, the new and modified requirement tests, the modules that exercise the changed functions and the guards only (LED .75); the touched-module run and the full suite are deferred to the batch-end battery by the 2026-10-31 override. Rulings applied: Q1–Q11 (`inc-11/E1-rulings.md`), the E2 rulings (`inc-11/E2-rulings.md`), S11-* / A11-* / R2-* / R3-* (`inc-11/E3-rulings.md`), SR-11-1/SR-11-2/SR-11-3 (`inc-11/E4-integration-notes.md`), and the E5 rulings SE5-11-* / CR11-* / CI9b-* / O-1 / O-3 (LED .93). |

---

## 5 · Risks

- **The touched-module run and the full suite were not run for Inc 11** (operator override 2026-10-31). A module outside the new-file/re-pinned set that calls one of the changed functions after the corrective pass has not been exercised here. The batch-end full battery is the check (§7).
- **The SE5-11-3 (O-3) window.** A load landing between the confirm and the router commits a fresh plan the engineer never saw (one `call_next` hop). The plan is built from the current state, so nothing is mixed or overwritten; routed to Inc 12b with a required test.
- **The O-1 source-vanish.** A source that vanishes while the dialog is open paints the generic `could not save` instead of `source file missing`; the commit rolls back and the app stays up. Routed to Inc 12b.
- **The SE5-11-2 rebind order.** Length checks run before the casefold rebind, which can then grow a name; the commit rolls back an over-long path. On base too. Routed to Inc 12a.
- **The SR-11-3 sentinel key.** The unreadable-document memo is a sentinel `Path("<unreadable-change-document>")` key in the per-open `digests` dict — it cannot collide (the real keys are absolute paths; `<`/`>` are not a valid Windows file name), is never iterated or serialised, and lives one dialog open. Declared deviation, judged safe by both reviewers (CR11-F3).
- **The R-GA11-3 mount cost.** The 2→300-row summary jump takes about 360 ms to mount; E5 measured it, and no arm needs that jump inside 300 ms.
- **Declared risks (not backlog).** The G-B 1–5 deviations (the `PurePosixPath` reading, the bare `_match_identical` import, the `occupants` values never read, the sentinel) — all accepted as harmless; the emitted-record staleness is covered by SE5-11-1's generation rebuild.
- **Model performance.** DeepSeek v4 Pro implemented G-A (3 deviations) and G-B (5 deviations), ran the **80** mutants (62 killed at first, 18 survived → 7 killed by the corrective pass, 10 accepted equivalent, M-47 removed as a redundant guard), and did the E3 design-fix passes and E13. Opus did E1, E2, E3 (3 rounds), the tester, the integration (1 source fix, SR-11-1), the reviews (2 rounds) and the corrective pass.

## 6 · Pending items / spec deviations

**Backlog added at the close** (`.dev-flow/BACKLOG-CODE.md`, each with its evidence path and home):
- G-B F-4 (E2-rulings) — the file-backed document's landing is not checked at commit → **Inc 12a sweep**.
- A11-03 (E3-rulings) — the top-level copy's landing prediction gap → **Inc 12a sweep**.
- SE5-11-2 (E5-rulings) — length checks run before the casefold rebind → **Inc 12a sweep**.
- O-1 (E5-rulings / E5-corrective-notes) — a source that vanishes while the dialog is open paints `could not save` instead of `source file missing` → **Inc 12b**.
- SE5-11-3 = O-3 (E5-rulings, round-2 security MINOR) — a load landing between confirm and dismiss commits a plan the engineer never saw → **Inc 12b** with a required test for the confirm→dismiss window.

**Owed elsewhere (not backlog).**
- CI9b-3 and CI9b-4 (the 9b CI run 41263643715, Linux-only: `tc_b100_43` and `tc_b100_63`[trailing dot]) → **batch-end fix round**.
- The docstring of `test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session` overstates "installs it into memory" → **batch close** (comment fix only).

**Declared (Risks, not backlog).** The SR-11-3 sentinel key (CR11-F3); the R-GA11-3 mount cost; the G-B 1–5 deviations.

**Named gaps / observations.** OBS-11-*: none — E13 found no defect (the list is empty). The examples the tester could not turn into tests are listed in `inc-11/E4-tester-notes.md` (performance records with no threshold, exact-geometry greps, internal call counts with no requirement threshold, the `[b]P` clash that cannot fire, the 130-character name past MAX_PATH, the 56+1 direct calls deferred by the override). B11-14 (a stale confirmed save committed by identity, not equality) is covered by `test_tc_b100_65_save_executes_the_painted_plan` (`prepared.plan is screen.plan`); M-44 is the expected survivor. M-74's kill is by an exception, not by its rows assertion (O-2).

**Finding → disposition (E3, code-free design review).**

| Finding | Severity | Disposition |
|---|---|---|
| S11-01 (samefile), S11-02 (exists in try), S11-03 (workarea OSError), S11-04 (Save before the preview is shown), S11-05 (document digest) | MAJOR / MINOR | E3 r1 rulings S11-01 … S11-12 (LED .92) |
| A11-01 … A11-17 (the architect findings) | MAJOR / MINOR / NIT | E3 r1 rulings A11-01 … A11-17 (LED .92) |
| R2-01 … R2-08, R3-01, R3-02 | MINOR / NIT | E3 r2/r3 addenda (LED .92) |

**Finding → disposition (E5, code).**

| Finding | Severity / tag | Disposition |
|---|---|---|
| SE5-11-1 the stale session after a mid-dialog load | HIGH / design-gap | fixed (LLR-175.4m); `red-03-corrective.txt` + the round-2 probes |
| CR11-F1 the save-as inventory reaching a non-save-as plan | MAJOR / impl | fixed (LLR-175.6); `red-03-corrective.txt` + the probe re-run |
| CR11-F2 the 19 removed requirement comments | MINOR / impl | fixed (comments only) |
| CR11-F3 the sentinel type annotation | NIT / design-gap | fixed (annotation + comment); SR-11-3 stands |
| SE5-11-2 the rebind order | NIT / design-gap | backlog → Inc 12a sweep |
| SE5-11-3 = O-3 the confirm→dismiss window | MINOR / design-gap | backlog → Inc 12b with a required test |
| CI9b-1 the `IfExp` selector; CI9b-2 the at042b re-pin | — / CI | fixed (screens.py; re-pin) |

**Orchestrator rulings Q1–Q11** are in `inc-11/E1-rulings.md`; the **E2 rulings** (Q-1 … Q-6, LLR-175.1n withdrawal, G-A/G-B P-1 … P-6, F-4, P-GA11-1 … P-GA11-4, R-GA11-3) are in `inc-11/E2-rulings.md`; the **E3 rulings S11-* / A11-* / R2-* / R3-*** are in `inc-11/E3-rulings.md`; the **seam rulings SR-11-1 / SR-11-2 / SR-11-3** are in `inc-11/E4-integration-notes.md`; the **E5 rulings SE5-11-* / CR11-* / CI9b-* / O-1 / O-3** are in `inc-11/E5-rulings.md` (LED .93).

**Re-pins (test::node — what changed — requirement).** The 24 re-pinned nodes move the Save-dialog drives to the new keyword constructor, the summary wait and `alt+s`: the 6 `test_b99_staging.py` nodes (the missing-source refusal read in `#save_where` with the dialog open, the summary awaited before `#save_ok`), the 2 `test_tui_manifest_save.py` nodes (the summary awaited before Save), `test_at042b` (SEC9b-1 ruling B), the 6 AT drives across `test_b100_active_variant.py` / `test_b100_document.py` / `test_b100_project_check.py` / `test_b100_project_homes.py` / `test_b100_save_image.py` / `test_b100_session_reset.py` / `test_b100_load_question.py` (clear the prefilled name, type, await the summary), `test_at_b100_02` (the refusals read in `#save_where`), the 2 `test_tui_directionb.py` modal nodes and `test_loadfilescreen_input.py` (the keyword constructor), and the 3 census nodes (TC-B100-07, TC-B100-09, TC-B100-57). Each names the old value, the new value and the requirement that changes it.

## 7 · Suggested next task

**Inc 12a of batch-100** — the busy indicator and the worker seam (`HLR-176`, `HLR-177`) — with the `dev-flow-v3-beta` pipeline; its E4 integration is in progress on `b100-inc12a`. Carried into it from this increment: the SE5-11-2, G-B F-4 and A11-03 sweep items, and the priority-key guard shared with the Load dialog.

**Inc 12b of batch-100** — the Save worker and the busy refusal — carrying O-1 and SE5-11-3 = O-3 (with the required confirm→dismiss test) from this increment.

**Batch-end full battery (owed once, when all increments are done — operator rulings 2026-10-30 and 2026-10-31).**
1. the touched-module run deferred by the 2026-10-31 override, every failure dispositioned against base;
2. the full reverse census / full suite on the final tree;
3. the guards and the census sweep (`-k census`) on the final bytes;
4. the mutants of every increment re-run on the final tree where a later increment touched the same function (the 80 Inc 11 mutants ran on `051f586`; the corrective re-runs cover what E5 changed);
5. the CI run, comparing the FAILED set with the previous run — including CI9b-3 and CI9b-4.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4 of the 4-file cap (`screens.py`, `styles.tcss`, `app.py`, `services/project_gather_service.py`) — §2 |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_save_dialog.py` (NEW, 73 functions/157 ids) + `tests/support/b100_save_dialog.py` (NEW, 35 functions) + the 24 re-pins + `test_id_registry.py` F-9 — §2, §4 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `_compose_save_preview`, the Q10 document arm in `project_gather_service.py`, `plan_project_save`'s inventory walk |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01-vs-base.txt` (154 RED vs `1747479`); `red-02-repins-vs-base.txt` (33 RED); `red-03-corrective.txt` (SE5-11-1/CR11-F1/CI9b-1 RED on `051f586`) |
| 5 | Reverse census declared | `core` · `full` | ⚠ | **not run per increment — operator override 2026-10-31, batch-end full battery** (§7). The new file, the re-pinned nodes and the guards ran |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — round 1 FAIL (1 MAJOR), round 2 PASS (0 findings) |
| 7 | No file from another lane touched | all | ✓ | the 4 named sources + tests / fixtures / config / records; `tools/e13/` is the orchestrator's; `prototypes/` untouched |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `_ENGINE_PATHS` modules untouched (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`); `screens.py` / `styles.tcss` / `app.py` / `project_gather_service.py` changes are additive |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript; the 80 E4/E5 mutants are stated as run on `051f586`, the E5 re-runs on the corrected scratch tree |
| 10 | Load-bearing emptiness declared | all | ✓ | SE5-11-1 and CR11-F1 fail on `051f586`; the `_shown` guard turns M-20 RED; the one-preparation census turns the dialog-copy mutation RED |
| 11 | Mutation verdicts declared — per arm | all | ✓ | 80 run: 62 KILLED, 18 SURVIVED, 0 INVALID; E5 re-runs: 69 killed, 10 equivalent, 1 removed (M-47), 0 INVALID, 0 surviving — §4 |
| 12 | Instrument RED-proof declared | all | ✓ | §4 Instrument RED-proof |
| 13 | Correction population declared | all | ✓ | writers of the preview/confirm/commit: `_prepare_project_save`, `_save_session_inputs`, `_current_save_session`, `_save_dialog_preview`, `_compose_save_preview`, `_confirm_project_save`, `_commit_project_save`, `_plan_project_save`, `SaveProjectScreen`, `SaveProjectPayload.plan` |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b — `code-reviewer`, `security-reviewer`, E3 `architect` and `security-reviewer` |
| 16 | Evidence files declared | all | ✓ | §4 evidence digest table (filled by the orchestrator from the staged blobs) covers `evidence/inc-11/` |
