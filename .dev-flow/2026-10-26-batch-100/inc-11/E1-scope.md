# E1 — Inc 11 requirements scope and E2 slice

**Run.** Stage E1 of the design-first pipeline (`dev-flow-v3-beta` skill) for Inc 11 (PLAN.md row 11: "Save project dialog: real name, clash/reserved/pending lines, no Browse… — M-4, D7 dialog, CW-U-12/13, O-9"; sources `screens.py`, `app.py` (+ `styles.tcss`); gate P-C, verdict B, `pc_B` ids).

**Source.** The replacement text is `E1-requirements-draft.md` in this folder; nothing has been merged into `01-requirements.md`. Requirement and code reads were taken on the 9a tree (`s19_app-b100-inc9a`, `4fef292` plus 9a's uncommitted changes) until it was removed when Inc 9a merged (`e28edeb`, `8947666`). The rest was read on `s19_app-b100-inc9b` at `8947666` (clean). `app.py` line numbers are identical in both, and `SaveProjectScreen` / `SaveProjectPayload` are unchanged since `1d677ba`. Code is cited by symbol.

**Designed against.** The tree after Inc 9b and Inc 10:
- Inc 9b's `LoadDialog`, `LoadChoice`, `_handle_load_dialog` and its `check_action` guard (S-g in `inc-9b-design/codewire/interfaces-9b.md`). Inc 11 widens that guard by one screen class and touches nothing else of 9b.
- Inc 10's question modal and `_confirm_then_load`. Inc 11 does not touch them; the Save dialog never replaces the image.

**Premises in scope.** P-11 (save outside the work area), P-13 (long name), P-14 (reserved names), P-18 (escape ignored), P-19 (empty Save silent), P-30 (`pc_B` ids), P-33 (case_06 size). Routed here: Inc 9b ruling Q6 (the priority keys over the Save dialog); PDR C-UX-3 and C-QA-5; ARQ O-9.

**Counts.**
- **Before:** 5 requirements in scope (HLR-175; LLR-175.1 … LLR-175.4), holding 19 "shall"s (HLR-175 12, LLR-175.1 1, LLR-175.2 2, LLR-175.3 1, LLR-175.4 3) and about 45 behaviours. HLR-175 alone carried about 20 behaviours.
- **After E1:** 53 single-"shall" requirements, all owed new at Inc 11:
  - 7 HLRs (HLR-175, HLR-175a … HLR-175f);
  - 46 LLRs (LLR-175.1 … LLR-175.6 with their suffixes; LLR-175.1n retired, LLR-175.1o and LLR-175.1p added).
- **Outside the count:** LLR-173.7 (TC-B100-66) is extended at Inc 11 with its text unchanged (the Save dialog's 6 scenarios).

**Per EARS form (53 in scope):** event (E) 16 · state (S) 4 · ubiquitous (U) 11 · unwanted (UW) 22 · optional 0. Checked by script (`work/check_draft.py`, output `work/check_draft.out.txt`): every Statement holds exactly 1 "shall", no other field holds the word, no id is duplicated, and the ledger entry names all 53 ids one by one.

**Base probes (executed on the 9a tree, read-only; scripts and outputs in `work/`).**
- **P11-1** `probe_digest.py`: `firmware.a2l: size=37742888 best_of_5=26.1 ms` (the case_06 A2L digest).
- **P11-2** `probe_p11_base.py`, nothing loaded, 118×54:
  - `open ctrl+s -> stack: ['Screen', 'SaveProjectScreen']`;
  - `widgets #project_parent_path: 1 #save_browse: 1 #save_summary: 0 #save_where: 0`;
  - `focused at open: OsClipboardInput project_parent_path`;
  - `escape -> stack: ['Screen', 'SaveProjectScreen']`;
  - `empty Save click -> … 'name is empty'? False`;
  - `typed 'Reports' -> … 'reserved name'? False`; `typed 'a b' -> … 'ab' folder line? False`;
  - `ctrl+l over Save dialog -> stack: ['Screen', 'SaveProjectScreen', 'LoadFileScreen']`;
  - `ctrl+s over Save dialog -> stack: ['Screen', 'SaveProjectScreen', 'SaveProjectScreen']`.
- **P11-3** `probe_p11_prio.py`: `ctrl+d over Save: density classes ['density-comfortable'] -> ['density-compact']`; `ctrl+k`: stack unchanged.
- **P11-4** `probe_render.py`: `4 MiB image: render 1215 ms, payload 10485786 bytes, sha256 4.0 ms`.

## 1 · Scope list

| Id | Statement (short) | EARS | Threshold (pass) | Negative control |
|---|---|---|---|---|
| HLR-175 | While the dialog is open: the plan for the typed name in `#save_summary`, target + kind in `#save_where` | S | 7 scenarios rows = plan; `a b` → `ab`, `new folder` | P11-2 executed |
| HLR-175a | Confirm Save writes exactly the painted plan | E | 7 scenarios tree = plan; refused → 0 paths | extra-file mutant; code read (no `plan`) |
| HLR-175b | A refused name is painted before Save | UW | 15 token pairs, dialog open, 0 paths | P11-2 executed (`Reports`) |
| HLR-175c | `escape` closes, saves nothing | E | 4 focus positions | P11-2 executed; P-18 |
| HLR-175d | Empty Save explained, dialog stays | UW | 4 of 4 | P11-2 executed; P-19 |
| HLR-175e | Saves only into this work area | U | 0 + 0 widgets; parent = work area | P11-2 executed |
| HLR-175f | `ctrl+s` / palette open one dialog with the 5 `pc_B` ids | E | 2 of 2, depth 2 | P11-2 executed |
| LLR-175.1 | Target line: sanitised folder + one of 4 kinds | E | 7 of 7, 0 markup spans | P11-2; case-sensitive mutant |
| LLR-175.1a | Reserved → `reserved name` / `choose another name` | UW | 5 of 5 | P11-2; no-casefold mutant |
| LLR-175.1b | Device (raw, component, sanitised) → `device name` | UW | 6 of 6 | sanitised-only mutant |
| LLR-175.1c | Disguised clash → `already a project`, both names | UW | 3 of 3, `ab` digests same | case-sensitive mutant |
| LLR-175.1d | Over 64 → `name too long` / `shorten the name` | UW | 64 / 65 / 300 | cap-65 mutant |
| LLR-175.1e | Path too long → `path too long` | UW | L / L + 1 | suffix-dropped mutant |
| LLR-175.1f | Link / junction target → `link or junction` | UW | 1 (Windows arm) | link-check-removed mutant |
| LLR-175.1g | Target not inspectable → `could not be read` | UW | 1 | unreadable→none mutant |
| LLR-175.1h | No usable character → `name is empty` live | UW | 3 of 3 | on-Save-only mutant |
| LLR-175.1i | Plan refusal painted in place of rows | UW | 3 of 3, 0 rows | rows-without-refusal mutant |
| LLR-175.1j | Free space short → `not enough free space` | UW | short by 1 / exact | handler-only mutant |
| LLR-175.1k | Source missing → `source file missing` | UW | 1 (3 arms) | code read (after close today) |
| LLR-175.1l | Source unreadable → `could not be read` + next step | UW | 1 | no-catch mutant; no step today |
| LLR-175.1m | Blocked entries → reason, addresses, step | UW | 1 | code read (after close today) |
| LLR-175.1n | Retired (E2-rulings, Q11): image kind with no emitter, unreachable | — | — | arm declared unreachable (p11b U4 / U4b) |
| LLR-175.1o | Work area cannot be listed → `could not be read` + next step | UW | 1 | catch-removed mutant (app stops) |
| LLR-175.1p | Case-folded folder ≠ open project → `already a project`, both names | UW | 1 (Windows arm) | casefold-identity mutant (saves into `straße`) |
| LLR-175.2 | No `#project_parent_path`, no `#save_browse` | U | 0 + 0 | P11-2 executed |
| LLR-175.2a | Payload parent = this work area | E | 2 of 2 (150-char base) | `base_dir` mutant (declared) |
| LLR-175.3 | `escape` → dismiss `None` | E | 4 of 4 | P11-2 executed |
| LLR-175.3a | Cancel → dismiss `None` | E | 2 of 2 | cancel→save mutant (declared) |
| LLR-175.3b | Empty / spaces + Save → tokens, open | UW | 6 of 6 | P11-2 executed |
| LLR-175.3c | `alt+s` / `#save_ok` / `enter` with a current, valid plan → close + save | E | 3 of 3 | code read: no `BINDINGS`, no submit |
| LLR-175.3d | Focus on `#project_name` at open | E | 2 of 2 | P11-2 executed |
| LLR-175.3e | Printable keys stay in the name field | U | `sqlpvy`, depth 2 | `s`-bound mutant (declared) |
| LLR-175.3f | Save during a refusal: open, Save focusable | UW | 1 | disabled-button / dismiss mutants |
| LLR-175.3g | `ctrl+l/s/k/d` run no app action | UW | 4 of 4, depth 2 | P11-2, P11-3 executed |
| LLR-175.3h | Open project → its name prefilled, selected | S | 3 of 3 | code read: name empty |
| LLR-175.3i | Buttons show `alt+s` / `esc` | U | 2 of 2 | code read: `Save` / `Cancel` |
| LLR-175.3j | Nothing loaded → no dialog, `Nothing to save` | UW | 2 of 2 | P11-2 executed |
| LLR-175.4 | Summary rows = plan rows (files, folders, `project.json`; landing + source names) | U | 7 of 7; AST 0 | drop-`keep` mutant |
| LLR-175.4a | Executed plan = painted plan; gathered artifacts outside the plan | E | 7 equalities + document-keep arm | re-plan mutant |
| LLR-175.4b | Out-of-date summary at Save → repaint, `the summary changed` | UW | 2 of 2 | save-fresh-plan mutant |
| LLR-175.4c | Image line: + N entries, K applied / unchanged copy | U | 3 of 3 | differs-only mutant |
| LLR-175.4d | Pending line while image differs from last saved | S | 4 of 4 | `image_differs_from_source` mutant |
| LLR-175.4e | Links row, 10 then `and K more` | E | 2 of 2 (Windows) | row-omitted mutant |
| LLR-175.4f | Merge: `active variant` new and before | E | 2 + 1 | omitted / first-by-name mutants |
| LLR-175.4g | Names painted literally | U | 5 of 5 | markup-on mutant |
| LLR-175.4h | Buttons visible under a long summary | S | 300 rows at 2 sizes | no-scroll mutant |
| LLR-175.4i | Last row reachable by keyboard; tab order | U | 1 + 2 | unfocusable mutant |
| LLR-175.4j | One line per row, cut ends `…` | U | every row | wrap mutant |
| LLR-175.4k | `SaveProjectScreen.plan` immutable | U | 3 errors + `None` | mutable-copy mutant |
| LLR-175.4l | Direct payload → same preparation | E | twin equal; 58 calls green | dialog-only mutant |
| LLR-175.5 | Image decision + digests once per open; 2 s budget | E | 1 + 1 per file; 0 during typing | recompute-with-plan mutant |
| LLR-175.5a | Recompute ≤ once per 150 ms, plus a trailing run | E | ≤ 3 of 20; final ≤ 300 ms; 4 MiB emitting arm | per-key / no-trailing mutants |
| LLR-175.5b | First frame before the image decision | E | 1 | compute-before-push mutant |
| LLR-175.6 | One function decides dialog and save refusal and plan | U | AST 0 other sites; 16 of 16 equal | dialog-copy mutant |

| AT / TC | Owner | Inc 11 share |
|---|---|---|
| AT-B100-16 | HLR-175f (open half), HLR-175 (folder half), HLR-175b (clash half), HLR-175c (escape half), HLR-175d (empty half, new) | written at Inc 11: one chain — `ctrl+s`, focus in the name, `s` typed; `a b` → `ab`; with `ab` saved and P2 open, `a b` → `already a project` / `choose another name`; empty `alt+s` → `name is empty`; `escape` → no folder |
| AT-B100-21 | HLR-175 (painted half), HLR-175a (executed half) | written at Inc 11: 7 scenarios (fresh, pending patch, refused, `files`, document, merge, save-as) |
| AT-B100-02 | HLR-164 (owner); HLR-175b, HLR-175e | re-pinned: `alt+s`; no parent widget; the refusals read in `#save_where` with the dialog open (ruling Q5) |
| AT-B100-09 | HLR-171 (owner); HLR-175 | re-pinned: `alt+s`; the summary lists `flows/`, `patches/`, `reports/` with 1 file each before Save |
| TC-B100-47 | LLR-175.1, LLR-175.1a … LLR-175.1n, LLR-175.6 | full |
| TC-B100-48 | LLR-175.2, LLR-175.2a | full |
| TC-B100-49 | LLR-175.3, LLR-175.3a … LLR-175.3j | full |
| TC-B100-65 | LLR-175.4, LLR-175.4a … LLR-175.4l, LLR-175.5, LLR-175.5a, LLR-175.5b | full |
| TC-B100-66 | LLR-173.7 | extended: the Save dialog in 6 scenarios |

No TC row of §5.3 names Inc 11 in its "Extended at" column; the `#project_parent_path` census row (§5.4) does, and it is in the re-pin list below.

**29148 check.** Every requirement above is singular (1 "shall", checked by script), states a numeric threshold and a negative control, and names functions only in its trace.

Declared exceptions:
- **Shared response, several triggers.** LLR-175.3c (`alt+s` / `#save_ok` / `enter`), LLR-175.3g (four keys) and LLR-175.1b (raw, component or sanitised name) hold OR triggers with one identical response; their thresholds test each trigger.
- **RED only as a mutation.** On the 9a tree these hold already, so each RED is a mutation: LLR-175.2a (the parent field's default is the work area), LLR-175.3a (Cancel dismisses with `None`), LLR-175.3e (the modal blocks the app's non-priority letters).
- **Platform-dependent arms.** Reported not run, never passed, when the platform cannot make the fixture: the junction arms (LLR-175.1f, LLR-175.4e) and the case-insensitive arm of LLR-175.1 (`ab` / `Ab`).
- **Planned control.** LLR-175.1n's reachability is a probe owed at E2; if no loadable kind reaches it, the requirement is withdrawn by ledger (ruling Q11).
- **TC-only stubs.** LLR-175.1g (`os.lstat`), LLR-175.1j (`shutil.disk_usage`) and LLR-175.1l (`_file_digest`) use stubs inside TC nodes only; no AT stubs anything (§3 preface).

## 2 · Defects fixed in place (old → new)

| Defect | Old | New |
|---|---|---|
| HLR-175 compound | 1 statement, about 20 behaviours, 12 "shall"s, 2 ATs | HLR-175 … HLR-175f, one "shall" each; AT-B100-16 split into five halves, AT-B100-21 into two, under their ids |
| LLR-175.4 compound | 3 "shall"s, about 12 behaviours | LLR-175.4, LLR-175.4a … LLR-175.4l, LLR-175.5 … LLR-175.5b |
| Infeasible at Inc 11 | "the save then … runs on a worker under the status line with real progress (P-D A)" | removed: the busy seam is Inc 12a (B100-I12) and Save project on a worker is Inc 12b (HLR-177) |
| Over-built / against the operator's note | digest worker, `computing…` rows, an early `alt+s` that saves landing names nobody saw (LED .26, .37) | removed (ruling Q1); P11-1: 26.1 ms for the 37.7 MB A2L; P11-4: the payload digest is 4.0 ms for 4 MiB, and the 1 215 ms render stays on the main thread under HLR-177 anyway |
| Missing failure path | a Save pressed inside the 150 ms recompute window saves a plan never painted | LLR-175.4b |
| Missing failure path | the dialog and the handler could disagree on a refusal (two copies of the rules) | LLR-175.6 (one preparation) |
| Missing failure paths | plan refusals, free space, missing / unreadable sources, blocked entries reach the engineer only after the dialog closes | LLR-175.1i … LLR-175.1n |
| Missing failure path | priority keys over the Save dialog (Inc 9b Q6) | LLR-175.3g (executed RED, P11-2, P11-3) |
| Missing failure path | `ctrl+s` with nothing loaded opens a dialog whose save is then refused | LLR-175.3j (ruling Q9) |
| Weaker scrub | "names read from disk shall render through `safe_text`" | `painted_names` with markup off (LLR-175.4g), as Inc 9b corrected LLR-173.3 |
| Stale word list | action words `new`, `replace`, `keep`, `merge`, `rewrite` | `replace` is never produced (E3 R1, LLR-167.6) → 4 words |
| Stale count | HLR-175 threshold "5 scenarios" | the §5.3 index's 7 scenarios |
| Undefined kind words | "its kind (new, the open project, a merge)" | painted `new folder`, `updates the open project`, `merges into an existing project` |
| Undefined merge row | "the target's active-variant change as its own row" | LLR-175.4f: `active variant`, new and before, with an after-save equality oracle |
| Refusal text without a next step | `… could not be read: <reason>. Nothing written.` | next step appended (LLR-175.1l, ruling Q11) |
| Token table out of line with the code | table `blocked entries` / `fix or remove them in the Patch Editor`; code `1 blocked entry (…)` / `fix them in the Patch Editor` | table follows the code (ruling Q11) |
| Missing requirement | `pc_B` labels "Save (alt+s)" / "Cancel (esc)"; `pc_B` prefills the open project's name | LLR-175.3i; LLR-175.3h (ruling Q7) |
| Missing requirement | 58 direct `_handle_save_dialog` calls in 11 test files | LLR-175.4l |

## 3 · Slice for E2

Names come from the requirements and the code. **(guess)** marks a node the requirements imply but do not name. Sources: `screens.py`, `app.py`, `styles.tcss` (§5.5 row 11: 3 files). Ruling Q10's recommendation adds `project_gather_service.py` (4, at the cap).

Tests (not capped):
- `tests/test_b100_save_dialog.py` (new: TC-B100-47, -48, -49, -65; AT-B100-16, AT-B100-21);
- re-pins: `tests/test_b100_save_guards.py` (AT-B100-02), `tests/test_b100_project_homes.py` (AT-B100-09), `tests/test_b99_staging.py` (6 `#project_parent_path` nodes; plus `test_tc_b99_ux_c10_save_project_filename_renders_literally` — Q-6: no toast on the dialog path, A11-11), `tests/test_b100_reuse.py::test_tc_b100_57_export_holds_no_byte_identity_rule` (also catch `Attribute` calls of `_hash_file`, A11-03), `tests/test_tui_directionb.py:3090`, and the Save-dialog drives in the 11 `SaveProjectScreen` files (§5.4 row); `test_e4_r11_a3r2_5` is NOT re-pinned (the top-level prediction gap stays as today's refusal, A11-03). The census is re-taken on the 9b+10 tree before E4 (A11-11).
- `tests/test_b100_load_dialog.py` or its successor (TC-B100-66 extension).

### `screens.py` — 1 class rewritten (≈ 9 nodes); `SaveProjectPayload` unchanged

| # | Node | What | Requirement |
|---|---|---|---|
| S1 | `SaveProjectScreen.__init__` | the app's callables (preview for a name, the final check), the initial name, the assignment rows (Q4) | 175.6, .3h |
| S2 | `SaveProjectScreen.compose` | `#project_name`, `#save_where`, `#save_summary` (focusable scroll), assignment rows, `#save_ok` "Save (alt+s)", `#save_cancel` "Cancel (esc)"; no parent field, no Browse; markup off | 175.2, .3i, .4g, .4h, .4i |
| S3 | `SaveProjectScreen.BINDINGS` / `AUTO_FOCUS` | `escape`, `alt+s`; focus `#project_name` | 175.3, .3c, .3d, .3e |
| S4 | `SaveProjectScreen.on_mount` | prefill + select; first frame; start the first preview | 175.3h, .5b |
| S5 | `SaveProjectScreen.on_input_changed` + 150 ms timer | trailing recompute | 175.1, .5a |
| S6 | `SaveProjectScreen` save action (+ `on_input_submitted`, `#save_ok`) | empty → tokens; final check; refused → stay; out of date → repaint + tokens; else dismiss | 175.3b, .3c, .3f, .4b, .2a |
| S7 | `SaveProjectScreen` cancel action (+ `#save_cancel`) | dismiss `None` | 175.3, .3a |
| S8 | `SaveProjectScreen.plan` (property) | the painted `SavePlan`, or `None` | 175.4k |
| S9 | `SaveProjectScreen` paint method | where line + summary rows from the app's painted preview | 175.4, .4j |
| — | `_collect_composition` | unchanged (Q4) | — |

### `app.py` — 4 changed + 3 new (+1 guess)

| # | Node | What changes | Requirement |
|---|---|---|---|
| A1 | `S19TuiApp.action_save_project` | nothing loaded → status, no dialog; push with callables; session inputs after the first frame | 175.3j, .5, .5b |
| A2 | `S19TuiApp.check_action` | the Inc 9b guard also while `SaveProjectScreen` is the screen | 175.3g |
| A3 | `S19TuiApp._handle_save_dialog` | split: the refusals and the plan move to N1; the handler executes a prepared plan, or prepares one for a bare payload | 175.4a, .4l |
| A4 | `S19TuiApp._plan_project_save` | takes the per-open session inputs instead of digesting each time | 175.5 |
| N1 | `_prepare_project_save(name, session)` (NEW) | every refusal before `mkdir` in the contract's order (empty, device, reserved, 64, path, clash, target link / unreadable, missing source, plan, free space) + the carry decisions + the plan | 175.1a … .1n, .6 |
| N2 | `_save_session_inputs()` (NEW) | `_decide_project_image` + the session files' digests, once per open; `OSError` → refusal | 175.5, .1k, .1l, .1m, .1n |
| N3 | `_save_dialog_preview(name)` (NEW) | painted plain text: target line, rows, image line, pending line, links row, merge row; `painted_names` | 175.1, .4, .4c … .4g |
| G1 | `_save_refusal_tokens` (guess) | one place for the save refusal texts (status line and dialog) | 175.6, Q11 |

### `styles.tcss` — 1 changed + ≈ 4 new selectors

| # | Selector | What | Requirement |
|---|---|---|---|
| C1 | `#save_box` (new outer id) | the dialog's own width; the shared `.modal-dialog, #load_dialog` rule stays for the other modals (9b B-3) | 175f |
| C2 | `#save_summary` | scroll region with a bounded height; one-line rows | 175.4h, .4j |
| C3 | `#save_where` | height auto | 175.1 |
| C4 | `#saveproject_buttons` | pinned below the summary | 175.4h |

### `project_gather_service.py` — only if ruling Q10 accepts (4th file)

| # | Node | What | Requirement |
|---|---|---|---|
| P1 | `plan_project_save` / `_plan_copies` | predict the carried and document rows against the tree the copy produces (backlog F5 remainder) | 175.4a |

**Callers checked (merged main `8947666`).**
- `action_save_project` ← `ctrl+s` (`BINDINGS`, priority), palette entry `save_project`.
- `_handle_save_dialog` ← `action_save_project` (dismiss callback); 58 direct test calls in 11 files (LLR-175.4l).
- `_plan_project_save` ← `_handle_save_dialog` only (`app.py:9783`).
- `_decide_project_image` ← `_handle_save_dialog` only.
- `check_action` ← Textual's binding dispatch (`run_action`; a `False` lets the key fall through to the focused `Input`).
- `SaveProjectScreen` ← `action_save_project`; `s19_app/tui/__init__.py` re-exports it (unchanged name).

**Unchanged context:** `plan_project_save`, `SavePlan`, `predict_placement`, `inventory_project_tree` (unless Q10), `painted_names`, `differs_from_last_saved` (first app caller is Inc 10's question; Inc 11 adds the second), `sanitize_project_name`, `is_windows_device_name`, `RESERVED_WORKAREA_HOMES`, `_project_folder_refusal`, `_save_as_source_for`, `list_projects` (content test from Inc 9b), the commit half of `_handle_save_dialog` (mkdir, placements, manifest, rollback).

**Node count:**
- **Firm:** `screens.py` 9; `app.py` 7 (4 changed + 3 new); `styles.tcss` ≈ 5 selectors.
- **With the guess and Q10:** up to 18 code nodes.
- That is above ~8, so E2 runs by file group:
  - G-A `screens.py` + `styles.tcss` (the dialog widget and its layout: 9 nodes + CSS);
  - G-B `app.py` (A1 … A4, N1 … N3; 7–8 nodes). N1 is the heavy node: the guard chain and plan half of the 1 160-line `_handle_save_dialog` (about 440 lines) moves into it.
- **Source files:** 3, within the cap of 4. Ruling Q10's recommendation gives 4, at the cap.

**Seams to fix before E2 (in one file, by the orchestrator):**
- S-a `SavePreview` (the app → dialog value): painted plain where-lines (each with a kind: info / refusal), painted summary rows `(label, landing, action)`, `plan: Optional[SavePlan]`, `refused: bool`. `screens.py` gets no service call; it may import `SavePlan` for typing only (census of LLR-175.4's AST arm).
- S-b `SaveProjectScreen.__init__`: `preview: Callable[[str], SavePreview]`, `confirm: Callable[[str, SavePlan], Optional[SavePreview]]` (`None` = go; else repaint and stay — LLR-175.4b), `initial_name: Optional[str]`, `variants`, `candidate_files` (Q4).
- S-c How the handler finds the prepared plan: an app-side cache keyed by (name, plan) set by `confirm`, or a `plan` field on `SaveProjectPayload`. `SaveProjectPayload` is constructed by 11 test files; a new optional field defaults to `None`.
- S-d The per-open session object: who holds it (the app, for the dialog's lifetime), and that it is dropped on dismiss.
- S-e The priority-key guard: `isinstance(self.screen, (LoadDialog, SaveProjectScreen))` in the Inc 9b `check_action` branch (ruling Q3).
- S-f The outer container id `#save_box`, so the Save dialog's width rules do not reach the five modals that share `#load_dialog`.
- S-g Timer ownership: the 150 ms timer lives in the dialog (`set_timer`), and the dialog stops it on dismiss.

## 4 · Open questions

Recommendations and the alternatives are in `E1-rulings-proposed.md` (Q1 … Q11). The draft text follows each recommendation; a different ruling changes the ids named there.

## 5 · Observations

- **Inc 10 overlap.** Inc 10 edits `screens.py`, `app.py` and `styles.tcss` too. The Inc 11 slice touches `SaveProjectScreen`, the Save handler family, `action_save_project` and one branch of `check_action`; Inc 10's slice is its question modal, `_confirm_then_load` and the load routes. The only shared function is `check_action` (Inc 9b's guard), and only if Inc 10 also guards its modal (see Q3's alternative).
- **The handler's size.** `_handle_save_dialog` is one 1 160-line method (`app.py:9447` → `:10607`). Splitting it into prepare + commit is the dominant E2 risk. LLR-175.4l (58 direct calls stay green) and the TC-B100-05 / TC-B100-31 / TC-B100-59 suites are the regression net.
- **The clash loop.** `_handle_save_dialog` keeps its own "is this a project" content check for the clash. Since Inc 9b, `list_projects` carries the §1.3 content test (LLR-173.4a), so N1 could use it. The requirements do not ask for this; E2 may take it if it shrinks N1, with the TC-B100-05 clash arms as the check.
- **`outside` target reason.** After the parent equality and the sanitiser (letters, digits, `-`, `_`), `workarea / cleaned` cannot be "outside" (`_project_folder_refusal`); the arm stays in N1 as defence and has no dialog requirement.
- **Backlog items read.** None is routed to Inc 11 by name. Related:
  - F5 remainder (save-as plan predicts against an empty target) → ruling Q10.
  - R2-2 (the handler and the planner each compute the save-as source) closes as a side effect of N1 (one evaluation per save) → recorded under Q10.
  - R2-1 (`os.path.lexists` treats a `PermissionError` as gone in `_save_as_source_for`) is not changed by Inc 11 and stays in the backlog.
- **Focus after the dialog closes.** LLR-166.1 (TC-B100-12) has no Inc 11 arm in §5.3. A Save dialog `escape` returns the focus to whatever held it before; if E2 finds it lands on a hidden widget, that is an LLR-166.1 arm, not a new requirement.
- **Big patched images.** With the re-derive at dialog open, a 4 MiB patched S19 makes the summary appear about 1.2 s after the dialog (P11-4). Today the same cost is paid after Save; Inc 12b keeps the re-derive on the main thread (HLR-177). LLR-175.5b keeps the dialog visible first.
