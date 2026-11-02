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
# from the worktree root; interpreter C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
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
| green-01-new-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-01-new-run1-failed.txt | 783fc1b893859f4d995241cb1568fcc241e773c7f3c8a53569e9ad7e869f33fa |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-01-new.txt | 977178118a860e17e89f13d5f9a0f89856f5fa62b23e74f355b2ea11fc63a78b |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-02-repinned.txt | b31f9b819e41e14adb67d567350e765b0c3d49b6225e7ce1665320163844f26d |
| green-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-03-corrective.txt | 643d34e3835c6ea2e721ca96671b436a4157a7fdc637fe807efef05e12ab4b0e |
| green-04-new-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-04-new-and-guards.txt | d6fe463bf5284f16b9667b8f1b50ddea5a45bbd2eacc1ffc3bcb16f2267227bc |
| green-05-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-05-final.txt | 46784a02df98e36405ff0b162cf0f219d2e1dfa47eb352dc55c4f36e971f9591 |
| green-06-full-new-file.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/green-06-full-new-file.txt | cef82845585dfd39ad7611480df45ad13a5d7d3e83acf6f5ddd317def0e504b2 |
| guards-01-run1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/guards-01-run1-failed.txt | b5f7a4dc450bf286e94e3d1f534dded9f8a4d1e532057d322574fff0dd0d64f2 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/guards-01.txt | 7de9af7c4c69bb007a9dc9932fb4f737d656be91b9caa4dbac8450c5967a3d58 |
| int-mut-M20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-mut-M20.txt | a8d3b1890d5e5af3ea36ce3d3281b8ff38321c41ae193a24f637322a4bf04dde |
| int-probe-shown.out.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-probe-shown.out.txt | 2f856ecfdef4f477492bd2644fb0e1fdf289770d0c44cdaa39b54e32975c2b86 |
| int-probe-shown.py.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-probe-shown.py.txt | 2ff6f9756e7f681b352b6227cc867e387b9299f7c9ca1cd7079a1eca15aae268 |
| int-probe-strasse.out.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-probe-strasse.out.txt | 8d6b79ba2d2dac3eef80b122c9a2f4e0f23d3f58e61b00fd01a7c9db6a07652d |
| int-probe-strasse.py.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-probe-strasse.py.txt | 1bddb6db9ee463c398766ddc18afeb8bc03056a0fac8a832bbfc8b46a1dee079 |
| int-refail-diagnostic.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/int-refail-diagnostic.txt | f64a235ef1e6dda32219bab69c2562781cef29b16be1edae7c47d7fe8a60312b |
| mut-M-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-01.txt | c907298594519d8abcfcd594abdb92c512e676664dd9c9005f7c0c2025756ccf |
| mut-M-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-02.txt | 6b74ac55aed237ba9b7f82c33554735801911bd6ee9e5528dcc9e30e7a991548 |
| mut-M-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-03.txt | 4814e5fb0a653e1365c9bf2d142a3c076201381ffb8d5c0062239ed9f10d154b |
| mut-M-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-05.txt | de127387247cb248248828a177a31c3592f7f6c058ebfcf4a9ad971ada3c4986 |
| mut-M-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-06.txt | f37d78ec7bcf0d4ac73349c9bb6df3f87239164202ccf279e5ba6484ec136635 |
| mut-M-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-07.txt | 71a57a9a433d8abd9067ce0074b86f4833e83fc77d1e2df83ab88348bd2a60a4 |
| mut-M-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-09.txt | fb8c51bfdc1678d06886cde4747a5164f14d62ea53ed9964fb205204b471452d |
| mut-M-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-10.txt | 40e2acc4361319953efe1075ad489d17f0c8b33513e4e41b270443a9db0ab246 |
| mut-M-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-11.txt | 13b7f67bd3d756e1d433a1b9eedc1dc6b581e1d440059ea1bb370597c3ad0472 |
| mut-M-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-13.txt | 4f09deac546e1a112ad5af0b2d56fd6eff829af64561a7f83801e7b1ceea2c2d |
| mut-M-14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-14.txt | f1c6d485280947265cf67e29c339fa8d8f38a17f28aef1e1748c462bf054c92d |
| mut-M-15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-15.txt | 6dbe3fe8b0bc4fab2bc360d322b05dc90034987fe80595f6293f8081dae50ad3 |
| mut-M-17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-17.txt | 4bd7452398c22d2141686128d1f77a7867527fe7e1cba6b53b81bfe474e0eb20 |
| mut-M-19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-19.txt | f25d653ae98c5012ea2a5e27512a17192d9973b287bc537d07b7806fa4c78485 |
| mut-M-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-20.txt | cce9445e370361bc51f190598cf1766c848e0c95b50ea23fe2dd3e19326bbc41 |
| mut-M-21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-21.txt | e065c20a650ffd9384e496bb090fed9e532040b0844094be423eff8bc1c09d31 |
| mut-M-23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-23.txt | a05346d73d2edde1ad78cd956737e8541d01cfd085e79bfdc270c80046481d5d |
| mut-M-24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-24.txt | 4be7b5cb2b5d7f1facc959d50161d4227b422a51522de2eda2cc1121ae227ce0 |
| mut-M-26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-26.txt | fbd2f23a0016de79db95afe2b5e7ccd0ab6c2adfb1adf443d69689fca8a90211 |
| mut-M-27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-27.txt | 7f9f846ad7b43157c83431e545db8baf6e36eecd1a1d06c691491d0e93f7dcca |
| mut-M-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-28.txt | 29d0dee3de3d916492e6c7e041b61020ed6a5b72ce8443e7b8ceb1f3ef6c4d8c |
| mut-M-29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-29.txt | 1680684bc308217f882dda989d24d643ccb139f6d945c25a68a3529ba94f335d |
| mut-M-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-31.txt | 7bc93b3a99464b62b839458ab159b52794af851d76d28e5c4a972ff0b4e2aef3 |
| mut-M-32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-32.txt | dbf5862dab798acf7af25313e06593382e3db9e854d15615784d609f736e7db4 |
| mut-M-33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-33.txt | db6210ed6d9b5f31ee81c0c91048a4c4b41e34e85a8449ca9a844d52bda6fe57 |
| mut-M-35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-35.txt | f31d4c386675da145452580e3c14426088b4712006d3734b0f05ebc2433fefb1 |
| mut-M-36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-36.txt | feaf95b8a52bcb8598279ded5cd93f6b0e9fc799a3655a83b39f8608a5008471 |
| mut-M-37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-37.txt | 855d6b25cfccd2d29b35a630ede9c291c80c9600dde63ce8a03e3bc315bc53fc |
| mut-M-38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-38.txt | ce82a913058d0c4f2a04f3c2340adc62f8a6f2b9b4d28599741384b98a34ab9d |
| mut-M-40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-40.txt | 0e9723200ed717523043bf826ca607a39c57ff58b35bc84fd5da219e604e0bbd |
| mut-M-41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-41.txt | ab14d807b0fc4bb49b7fae97741d4567c6a454e40679d69193a28768e9ab5268 |
| mut-M-42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-42.txt | 03989734609eb43d2c7157479dcc5f0e30109b39ba86dc0cc1be51782c83345d |
| mut-M-43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-43.txt | 519fb2bff824f2dd55b318801e27f38af573731d81852940d5b6263568bdb620 |
| mut-M-44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-44.txt | d9c132171373fae657b6e8996139097d20818f812e744857aa417bad618e5aee |
| mut-M-45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-45.txt | 8879431d1497fa374fc76fd6589206db18e9b46a8b11ecb28695bbe5afff897c |
| mut-M-47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-47.txt | bea190b441f77f54dcd7c8579f2db6307f8c707be12c7a32726e0df4f9970bba |
| mut-M-48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-48.txt | afdc263d12a61147cd5919c7a96b56c827977dfaee4b84b536d8992078ae5a48 |
| mut-M-49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-49.txt | 62b9170c3c7dcce5564d4d9abbf6fa544c8951e2c0c2950f8a0244cc03a2e9e6 |
| mut-M-50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-50.txt | 24397b1bcc162a8083842b6138e91ad0a482315f036b23e38a6d394d3f9052cb |
| mut-M-51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-51.txt | d2c97c597baaf11b86a8aa5cef6598ef26d80cd9826929a2108893bfb08869f7 |
| mut-M-52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-52.txt | 9403b248201ff0df46f880af24fc6ac8850fd83c151d0dd78aa583c39acaa6f8 |
| mut-M-53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-53.txt | 6063378dd44d3ae3255c10e8b8051c7ba056b0e303f8235ab8106e842afa8c6c |
| mut-M-54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-54.txt | 755457bd0c8a8117116de769652c3dea556301808b8c4174d6cefb4b895d155d |
| mut-M-55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-55.txt | 22f0d3b39b89ffd2d9e5368f6aaf1828ba2f400ba90eb8b62f6d0e507358cf09 |
| mut-M-56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-56.txt | de97669725e9c7889b5ea3f109ca41eac77a057d2c9d1042d178f54c02d4278f |
| mut-M-57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-57.txt | 4ddaca346fa0e34950262917587d9b74085a5da13b2210ab2656c4a5e7bc27e4 |
| mut-M-58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-58.txt | 76befc5902b6af4128e51818143359c1816c029991ef6c44328bb172680c270f |
| mut-M-59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-59.txt | 49ab3e4820b067f578e02c53b414685eaabbe8edbbc1ca20f6763da3bf4f3b3f |
| mut-M-60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-60.txt | f199933cb18b3921f13e5470658c6ce3b836dbfc3851cdbbac878e209df49513 |
| mut-M-61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-61.txt | dadf19565247e8d1823f53adf31267fb60f35c17de052edb92fd1102da40f12c |
| mut-M-62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-62.txt | 769249265328b06e011ebf6660f8dbd175e7b10ec9d832cfdaaa486a43b29b99 |
| mut-M-63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-63.txt | 0aaa16639ffa303d1e02defba9568b4ecdaa547c1f1a16212a90fe31d8e58f3c |
| mut-M-64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-64.txt | fdf400650aa96797918130decfb58ea5d4cd31986ab1c00a9c7b94cff7f98379 |
| mut-M-65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-65.txt | 1f9a2c4c25babcf867fb7cf63987df6bbd5157db4d5c620a0c7fa7c46464b46b |
| mut-M-66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-66.txt | 5bb20675e72683c7f3b96c392f9d2df0919b0e6cfd87e04e6a7423572555d6f4 |
| mut-M-67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-67.txt | f8dcfbf49ddee819d03cb360e1c27b4717a4021e870a75831c09176e8c0e4abe |
| mut-M-68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-68.txt | 15d71ab6ba17890997c4649681eb1247076802649c3a9b4ce3daa15ed6a516c7 |
| mut-M-70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-70.txt | db723fed8fa10bf8680b01bf9672e8e7b716da3a9f3f11debdb3fd5960d9aba3 |
| mut-M-71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-71.txt | 906afc358e59537a755d6a77468f4779960f3f2a3e37d69ecce56c07bb7520d3 |
| mut-M-72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-72.txt | 55e1913203b4f6033c4b2f4f0f1373722f777b1f0d5703f44cfc102827f9d493 |
| mut-M-73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-73.txt | 86ad43b04b048273a29cb6ddf1ed71cc384ee47f9bab334ab63e55d12761dd95 |
| mut-M-74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-74.txt | b262454a38d6c9313c073b98d70fafd966cb60f7a1e2dd99d5e2a00f715bd300 |
| mut-M-75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-75.txt | 00418a586abd5891b48e551c318cebf16b637f28a54c4242752061856aaf056d |
| mut-M-76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-76.txt | f3bbca5f741b8d9c11d2c8bac675bc5466bdd2cd9986e22e0c0cfafbc7747260 |
| mut-M-77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-77.txt | 70153b8be4c8fd592f4dbe8176d6fa7ce71b605c668623e247b524a5fb8937d5 |
| mut-M-78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-78.txt | 61e50a6249ffc0c2ae9e76e0b2f4b9424fc58079096761a729ada31e70612d91 |
| mut-M-79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-79.txt | e2cb71f4fba2e394b5676502e9a85b2041f364b470482c767884d004b67529f1 |
| mut-M-80.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-80.txt | 49fd4ce7076114b1fd0e40e1c7319d351c41db7abdba3505f5f2afcf31417c61 |
| mut-M-81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-81.txt | 7bc6c05bdfd1da10b28f6807702ea1b3613e13de7814d803e8a92844b29f9228 |
| mut-M-82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-82.txt | bbe0e1937f41bd333f358dfaadd44c615c49672f4205e014bfa5069c972b2d27 |
| mut-M-83.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-83.txt | ca999787426755470f1fea488c97b9d90e3e691d75ae329abfe869541465354a |
| mut-M-85.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-85.txt | 253688f68707008b4134b66c81dc2c1a34fbdd45c0f25ac4b6444fefdba45745 |
| mut-M-86.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-86.txt | f9d56bbf5ca026f1da9b3c99cf7b485cf433c1ba2e1d7b5e900d15c179173ebf |
| mut-M-87.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-87.txt | beda7e77ba15b8421c026f7de56bb2e9596be58bdea2efa175cff567ea198c3b |
| mut-M-88.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-88.txt | 64d5247e9fcc71a7d1e7365993843a9d35dde0c0059152b862ef1e3cbad078e8 |
| mut-M-89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-89.txt | 73d5d2b65a91c8f4f3e6bbf6624eec7fbd5d1c09092b1238cd17e3f2d6fdf2ce |
| mut-M-92.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-92.txt | c235de5c1d9c1279adec7ee82e155672de7d03dc04bf77839999d25df716b20b |
| mut-M-93.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-93.txt | 8707a1c83c3dd28898530051c1bd04c48d414936269591fed6d54365edfe9433 |
| mut-M-94.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-94.txt | d2a4c89daadafb521d061d1b1c5fdc5761087e04bbe3834f39a90ff54f798b06 |
| mut-M-96.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-M-96.txt | 723b1bd6796292b3e2f3ee2e33c0c5a9eb06034c6789d4151655463308fab715 |
| mut-kill-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mut-kill-03-corrective.txt | 4691faeb638da9c322b4e1d80827cfccea8c580e37dfff766f6ff48bb1441081 |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-11/mutation-summary.md | bc2daf78e51d7404c91e8dd88985074d8dd2e52a4c6d55a1fdbd40bfe615b95e |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/red-01-vs-base.txt | 9545fd3cf99078c20dcbebfca5ea119ac1dc1e2ef7aa6e6ec861cd0ac55247ec |
| red-02-repins-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/red-02-repins-vs-base.txt | 7fa0630c0d3507cf3ec33e9cec8c268904b3ff3e62bb6f3ce270ca332ca48bd0 |
| red-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-11/red-03-corrective.txt | e351e141a758861eb98ff179170875a292cf5cb5b872c1fa772af9ca656e1138 |

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
