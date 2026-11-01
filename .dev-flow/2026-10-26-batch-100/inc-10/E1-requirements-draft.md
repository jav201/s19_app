# Inc 10 E1 — replacement requirement blocks (draft, not merged)

Stage E1 of the design-first pipeline (`dev-flow-v3-beta` skill) for Inc 10, "confirm before replacing unsaved work" (PLAN.md row 10: "confirm before replacing unsaved work (image, project, dirty flow) — CW-U-5, O-3 — screens, app (+ styles) — gate P-B"; §5.5 row 10: `screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py`, 4 at the cap). Prototype verdict: P-B variant A (`pb_A` ids).

**How to merge.**
1. §A replaces the `### HLR-174 — One short question before unsaved work is lost, on every route` block in `01-requirements.md` (§3), and inserts the new HLR-174a … HLR-174d blocks right after it.
2. §B replaces the blocks `### LLR-174.1` … `### LLR-174.4` (§4) with the blocks below, in the order given.
3. §C holds the edits to blocks outside LLR-174 that Inc 10 owes: LLR-165.3 (the interim line removed), and the arm extensions of LLR-166.1, LLR-167.8 and LLR-173.7, whose statements stay unchanged.
4. §D holds the TC-index rows (§5.3), the AT-index row edits, the token-table row (§3 preface), the reverse-census rows (§5.4) and the IFC edits (§4).
5. §E is the ledger entry, numbered `LED .NN`. Every `LED-2026-10-26-batch-100.NN` below takes the number assigned at merge.

**Conventions.**
- Every Statement holds exactly one "shall". No other field uses the word.
- Function names appear only in the trace.
- "The 9a tree" means the worktree `s19_app-b100-inc9a` on 2026-10-31: `4fef292` plus 9a's uncommitted changes. That worktree was removed during this E1 run after Inc 9a merged (`e28edeb`); the same code is `8947666` in `s19_app-b100-inc9b`, and every line number cited here was re-checked there (`app.py:10576` `panel._dirty`, `:11951` the interim line). Inc 9b runs before Inc 10 and is not on that tree; this draft designs against the tree as it will be after 9b (`inc-9b-design/codewire/interfaces-9b.md`): the Load dialog is `LoadDialog`, its one router is `_handle_load_dialog`, and the work-area pick body is `_load_workarea_file`.
- Painted strings are English.
- "Painted literally" means the name goes through `painted_names([name])` (the batch's one category scrub, 8b S3R2-4) and is painted with markup off.
- **Session digest** means the tuple (`current_file.path`, SHA-256 of the installed image bytes, `current_project`, `current_a2l_path`, the MAC path), read before and after an action. **Kept work** means, in addition, the Patch Editor document's entry count, the Patch Editor dirty flag, the Flow Builder's blocks and its dirty flag, and the SHA-256 of the recent-sources store.
- **The three unsaved flags** (§1.3 "Unsaved"):
  - D, the unsaved image: the change service's saved-state predicate reports that the loaded image differs from the copy last loaded or written;
  - W, the Patch Editor dirty flag;
  - F, the Flow Builder dirty flag.
- **The three load kinds:**
  - image replacement: a data file (`.s19`, `.hex`) loaded over the session, a variant switch;
  - attach: a MAC or an A2L file;
  - project load.
- **The question** is the confirm modal of the P-B verdict A: one short question with the buttons `#confirm_yes` and `#confirm_no` (P-30).
- **The four routes** (§1.3 "Image-replacing route"): the Load dialog (each of its choices, a project row included), the Workarea Files pick, `v`, and the Load-result panel's `v`.

---

## §A — HLR blocks (replace HLR-174; insert HLR-174a … HLR-174d after it)

### HLR-174 — One question before an image-replacing route replaces unsaved work
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.17, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When an image-replacing route requests a load while unsaved work it would replace or move to another project exists (D for an image replacement; D, W or F for a project load), the system shall ask the engineer one question before the load changes the session.
- **Decomposition:**
  - LLR-174.1, LLR-174.1a, LLR-174.1b, LLR-174.1c: when the guard asks (the 24-cell table) and the public reader of the Patch Editor flag.
  - LLR-174.2, LLR-174.2a, LLR-174.2b, LLR-174.2c, LLR-174.2d, LLR-174.2e, LLR-174.2f, LLR-174.2g, LLR-174.2h, LLR-174.2j, LLR-174.2r, LLR-174.2s, LLR-174.2t: the modal, its focus, its keys, its layout, and the two unwanted-behaviour guards (a second answer; the Patch Editor's change-file dropdown).
  - LLR-174.3, LLR-174.3a, LLR-174.3b, LLR-174.3c, LLR-174.3d: the question comes before the project-session reset, never inside the project-load handler, and a cancelled variant switch leaves the pending selection unchanged.
  - LLR-174.4, LLR-174.4a, LLR-174.4b, LLR-174.4c: one load seam for every route, one question per request, the load kind of each route.
  - The compound HLR-174 (about 12 behaviours, 8 normative clauses) is split here into HLR-174 and HLR-174a … HLR-174d (LED .NN).
- **Variant slots (filled by the P-B verdict A, LED-2026-10-26-batch-100.2):** VS-PB-1 = the short question. VS-PB-2 = no "save first" key. VS-PB-3 = the `pb_A` ids (`#confirm_yes`, `#confirm_no`).
- **Rationale (informative):**
  - A load over a patched image asks nothing (P-17 on `1d677ba`; this E1's probe on the 9a tree: the Workarea pick, the Load dialog router and the variant switch each replace a patched image with the stack `['Screen']`).
  - Review sources: UX-01, UX-11, QA-03, UX-12, O-3. B-02 / QA R2-03: the Workarea pick and the variant switch bypassed the dialog's route (P-42).
  - The operator's P-B note: "Pregunta corta, hace el trabajo y crea menos dependencias."
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_confirm.py -k "tc_b100_44 or tc_b100_45 or tc_b100_72 or at_b100_15"`
- **Numeric pass threshold:**
  - With an unsaved patch (D), by keys: the Load dialog with a typed data file, a Workarea Files pick of a data file, and `v` to another variant → 3 questions, 1 per request, each pushed before the image changes (the session digest read when the question is on top equals the digest before the request).
  - The Load-result panel's `v` with D forced through a private call (declared: by keys the panel opens only right after a project load, which records the image as saved) → 1 question.
  - 4 of 4.
- **Negative control:** executed on `1d677ba` (P-17): `Load file over patched image -> stack: ['Screen'] … image still patched? False`. Executed on the 9a tree (this E1, `work/probe_p10.out.txt`): `WORKAREA pick over patch: stack ['Screen'] | … patched image kept = False`; `LOAD DIALOG router over patch: stack ['Screen']`; `VARIANT switch over patch: stack ['Screen']` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, question half) the engineer adds and applies a patch in the Patch Editor and loads another data file through Load. A question appears naming the patched image, with the focus on Cancel. A Workarea Files pick of a data file, and `v` in a project, ask the same question.
  - **Shipped surface:** Load (`l`, `#load_path`), the Workarea Files list, `v`, the question (`#confirm_yes`, `#confirm_no`).
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ boundary — the three key-reachable routes; the panel's `v` (TC arm, forced state).
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-174a — A load that would replace or move no unsaved work does not ask
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When an image-replacing route requests a load and no unsaved work it would replace or move to another project exists (D for an image replacement; D, W or F for a project load), the system shall load without the question.
- **Decomposition:** LLR-174.1, LLR-174.1a, LLR-174.1b (the cells that load).
- **Rationale (informative):** QA R2-02 (an attach loses nothing); UX-27 (Save project clears the document flag, LLR-167.8). The `pb_A` prototype asked whenever a project was open; HLR-174's approved text overrides it ("whether or not a project is open"), and this split keeps that.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_confirm.py -k "tc_b100_44 or at_b100_15"`
- **Numeric pass threshold:** 0 questions in each of these 7 scenes:
  - nothing unsaved, no project open, data load;
  - nothing unsaved, project P open, project load of Q;
  - patched → Save project → data load;
  - patched + 1 Patch Editor entry → Save project → project load;
  - patched → save-back → data load;
  - an unsaved patch, then an A2L load (the patched byte kept);
  - an unsaved patch, then a MAC load (the patched byte kept).
  - 7 of 7.
- **Negative control:** the `pb_A` prototype rule ("ask when a project is open", `_pb_common.install`) → the scene with P open asks → RED. A mutation asking on an attach when D → the A2L and MAC scenes ask → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, after-save half) after Save project, the same load that asked before asks nothing and loads.
  - **Shipped surface:** Load, Save project, the status log.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary
    - empty: nothing unsaved, with and without a project open;
    - boundary: a patch that writes the bytes already there; undo alone asks (C13); undo then Apply does not (C12); an A2L or MAC attach.
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-174b — Replace continues the load
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer answers the question with replace, the system shall run the load that asked.
- **Decomposition:** LLR-174.2c, LLR-174.2e, LLR-174.2f, LLR-174.3.
- **Rationale (informative):** VS-PB-1; `y` replaces.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_confirm.py -k "tc_b100_45 or tc_b100_72 or at_b100_15"`
- **Numeric pass threshold:** `y` on each of the 4 routes → 1 load of the requested item each (`current_file.path.name` or `current_project` equals the request), and the question closed (4 of 4).
- **Negative control:** a mutation that dismisses the question and drops `go` → 0 loads → RED. On the 9a tree there is no question (probe above) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, replace half) the engineer repeats the load and presses `y`: the new file loads.
  - **Shipped surface:** the question (`y`), the Loaded panel.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ boundary — `y` with the focus on either button; a click on `#confirm_yes`.
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-174c — Cancel keeps everything
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer cancels the question, the system shall leave the session and the kept work unchanged.
- **Decomposition:** LLR-174.2b, LLR-174.2d, LLR-174.2e, LLR-174.3a. The focus after the close is LLR-166.1 (TC-B100-12, Inc 10 arm).
- **Rationale (informative):** "Cancel" means `n`, `escape`, `enter` on the initial focus, or a click on `#confirm_no`.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_confirm.py -k "tc_b100_45 or at_b100_15"`
- **Numeric pass threshold:** a project load with D, F and W, and a data load with D; each cancelled by `n`, `escape` and an immediate `enter` → the session digest and the kept work unchanged, 0 status lines (6 of 6).
- **Negative control:** a mutation focusing `#confirm_yes` first → the immediate `enter` replaces → RED. On the 9a tree the load runs with no question (probe above) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, keep half) at the question the engineer presses `enter`: the patched image stays, and the hex view still shows the patched byte.
  - **Shipped surface:** the question (`n`, `escape`, `enter`), the hex view, the Loaded panel.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ boundary — each cancel key; a typed path whose recent entry would be recorded (the store unchanged).
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-174d — The question names every unsaved item
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall name in one question every unsaved item that made the guard ask.
- **Decomposition:** LLR-174.2i, LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2p, LLR-174.2q.
- **Rationale (informative):** "name what would be lost, all items in one question" (HLR-174 as approved). The Flow Builder item is named as holding unsaved changes; whether a project load clears it is ruling Q1.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_confirm.py -k "tc_b100_45 or at_b100_15"`
- **Numeric pass threshold:** a project load with D, F and W → 1 question whose painted text holds the image file name, `Patch Editor entries` and `flow <name>` (3 items, 1 modal); D and F only → 2 items; W only → 1 item (3 of 3).
- **Negative control:** a mutation naming only the first unsaved item → the 3-item arm finds 1 → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, items half) with a patched image and unsaved Flow Builder edits, the engineer opens a project: one question names both.
  - **Shipped surface:** the question.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ boundary — 1, 2 and 3 items.
  - **Negative control:** as above → AT-B100-15 RED.

---

## §B — LLR blocks (replace LLR-174.1 … LLR-174.4)

### LLR-174.1 — An image replacement asks exactly when the image is unsaved
- **Traceability:** HLR-174, HLR-174a · trace: `_confirm_then_load` (NEW, B100-I20), the load guard (NEW, `app.py`); `ChangeService.differs_from_last_saved` (`change_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.17, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a route requests an image replacement, the system shall ask the question if and only if the loaded image differs from the copy last loaded or written.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_confirm.py -k tc_b100_44`
- **Numeric pass threshold:**
  - The 8 image-replacement cells of the table (D × F × W) → 4 ask (D = 1), 4 load (D = 0), 8 of 8.
  - Boundaries, 0 questions each: patched → Save project → data load; patched → save-back → data load; a patch that writes the bytes already there; undo then Apply of the now-empty document (C12, the byte restored) (4 of 4).
  - Boundary, 1 question: `undo()` alone (C13, the patched byte stays) (1 of 1).
  - Boundary, 1 question: patched → Save project → patched again → data load (1 of 1).
- **Negative control:**
  - Dropping D from the rule → 4 cells wrong (executed enumeration, LED .17).
  - Executed on the 9a tree (this E1's probe): `after apply: D = True`, then the Workarea pick runs with the stack `['Screen']` → RED.
- **Boundary catalog:** ☒ boundary — every cell; the saved-then-patched cell.

### LLR-174.1a — An attach never asks
- **Traceability:** HLR-174a · trace: the load guard (NEW, `app.py`); `_merge_mac_with_existing_primary`, `load_a2l_from_path` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a route requests a MAC or A2L attach, the system shall attach the file without the question.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_confirm.py -k tc_b100_44`
- **Numeric pass threshold:**
  - The 8 attach cells → 0 ask (8 of 8).
  - An unsaved patch, then a MAC attach → the patched byte unchanged and D still true; then an A2L attach → the same (2 of 2).
- **Negative control:**
  - The round-2 rule (an attach asks on D) → 4 cells wrong (executed enumeration, LED .17).
  - Executed on the 9a tree (this E1's probe): `MAC attach over patch: stack ['Screen'] | byte kept = True | D = True` — the attach keeps the patch, so asking would be a false alarm.
- **Boundary catalog:** ☒ boundary — a MAC attach with and without a loaded image; an A2L attach.

### LLR-174.1b — A project load asks when any of the three flags is set
- **Traceability:** HLR-174, HLR-174a · trace: the load guard (NEW, `app.py`); `ChangeService.differs_from_last_saved`; `FlowBuilderPanel.is_dirty` (`flow_screens.py`, unchanged); `PatchEditorPanel.is_dirty` (NEW, LLR-174.1c)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a route requests a project load, the system shall ask the question if and only if the image is unsaved, the Flow Builder is dirty or the Patch Editor is dirty.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_confirm.py -k tc_b100_44`
- **Numeric pass threshold:**
  - The 8 project cells → 7 ask, 1 load (8 of 8). With LLR-174.1 and LLR-174.1a: 24 of 24 cells, 11 ask, 13 load.
  - Project P open, nothing unsaved, project load of Q → 0 questions (1 of 1).
  - Patched + 1 Patch Editor entry → Save project → project load → 0 questions (1 of 1).
- **Negative control:**
  - Dropping F → 1 cell wrong; dropping W → 1 cell wrong; dropping D → 1 project cell wrong (executed enumeration, LED .17).
  - The `pb_A` rule "ask when a project is open" → the P-open arm asks → RED.
- **Boundary catalog:** ☒ boundary — every cell; re-loading the open project.

### LLR-174.1c — The Patch Editor flag is read through a public reader
- **Traceability:** HLR-174 · trace: `PatchEditorPanel.is_dirty` (NEW, `screens_directionb.py`); `_handle_save_dialog` (`app.py`, the E3 R1 read at the 9a tree's `:10576`); the load guard (NEW)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall read the Patch Editor panel's dirty flag only through a public reader of that panel.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_confirm.py -k tc_b100_44`
- **Numeric pass threshold:**
  - AST census of `s19_app/` outside `screens_directionb.py`: 0 attribute reads of `_dirty` on a `PatchEditorPanel` value (1 of 1).
  - The reader follows the flag's writers: True after an entry edit, after typing in the paste buffer and after Parse pasted; False after `mark_saved` and after `mark_loaded` (5 of 5).
- **Negative control:** executed on the 9a tree (this E1's probe): `hasattr(PatchEditorPanel,'is_dirty') = False`; `private reads of panel._dirty in app.py: 1 [10576]` → RED.
- **Boundary catalog:** ☒ boundary — each of the five writers of the flag.
- **Note (premise):** P-43. The reader is the reason `screens_directionb.py` is Inc 10's fourth file (§5.5).

### LLR-174.2 — One modal with exactly two buttons
- **Traceability:** HLR-174 · trace: the question modal (NEW, `screens.py`); `_confirm_then_load` (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.38, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the guard asks, the system shall show one modal question holding exactly the two buttons `#confirm_yes` and `#confirm_no`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** one guarded data load with D → the screen stack grows by 1, the top screen holds 2 `Button` widgets with ids `confirm_yes` and `confirm_no`, 0 other buttons and 0 `Input` / `TextArea` widgets; while it is open, the question itself pushes 0 screens (VS-PB-2, no "save first" key) (4 of 4).
- **Negative control:** the `pb_B` variant (a third "Save first" button bound to `s`) → 3 buttons → RED. On the 9a tree: 0 modals (probe) → RED.
- **Boundary catalog:** ☒ boundary — one modal per request.

### LLR-174.2a — The modal takes its text and labels as parameters
- **Traceability:** HLR-174 · trace: the question modal `__init__` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.38, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall build the question modal from a title, a question text and two button labels passed to it as parameters.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** the modal built with the title `Quit?`, the text `A save is running.` and the labels `Quit (y)` / `Stay (n)` → those 4 strings painted, 0 painted `Replace`; `y` → the replace answer and `n` → the cancel answer (6 of 6).
- **Negative control:** a mutation that hard-codes `Replace (y)` → the quit arm paints `Replace (y)` → RED.
- **Boundary catalog:** ☒ boundary — the load question and the quit question (Inc 12 reuses the modal, C-UX-4).

### LLR-174.2b — The focus starts on Cancel
- **Traceability:** HLR-174c · trace: the question modal `AUTO_FOCUS` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the question opens, the system shall put the focus on `#confirm_no`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** the question pushed → `focused.id == "confirm_no"` (1 of 1; Q1-2).
- **Negative control:** a mutation with `AUTO_FOCUS = "#confirm_yes"` → RED (and HLR-174c's immediate `enter` replaces).
- **Boundary catalog:** ☒ boundary — the question pushed.

### LLR-174.2c — `y` answers replace
- **Traceability:** HLR-174b · trace: the question modal `BINDINGS` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `y` in the question, the system shall close the question with the replace answer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** `y` with the focus on `#confirm_no` and with the focus on `#confirm_yes` → the replace answer each time (2 of 2).
- **Negative control:** a mutation with no `y` binding → the question stays open → RED.
- **Boundary catalog:** ☒ boundary — the focus on either button.

### LLR-174.2d — `n` and `escape` answer cancel
- **Traceability:** HLR-174c · trace: the question modal `BINDINGS` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `n` or `escape` in the question, the system shall close the question with the cancel answer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** `n` and `escape`, each with the focus on each button → the cancel answer 4 times (4 of 4).
- **Negative control:** a mutation with no `escape` binding (the P-18 shape) → the question stays open → RED.
- **Boundary catalog:** ☒ boundary — both keys, the focus on either button.

### LLR-174.2e — `enter` acts on the focused button
- **Traceability:** HLR-174b, HLR-174c · trace: Textual `Button` (`enter` → press); the question modal `on_button_pressed` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `enter` in the question, the system shall give the answer of the focused button.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** an immediate `enter` → cancel; `tab`, then `enter` → replace; `tab`, `tab`, then `enter` → cancel (3 of 3).
- **Negative control:** a mutation that maps `enter` to replace at the screen level → the immediate `enter` replaces → RED.
- **Boundary catalog:** ☒ boundary — the focus wrapping after two `tab`s.

### LLR-174.2f — A click answers with the clicked button
- **Traceability:** HLR-174b, HLR-174c · trace: the question modal `on_button_pressed` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer clicks `#confirm_yes` or `#confirm_no`, the system shall close the question with that button's answer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** a click on `#confirm_yes` → replace; a click on `#confirm_no` → cancel (2 of 2).
- **Negative control:** a mutation that ignores `Button.Pressed` → the click leaves the question open → RED.
- **Boundary catalog:** ☒ boundary — both buttons.

### LLR-174.2g — Any other key leaves the question open
- **Traceability:** HLR-174 · trace: the question modal `BINDINGS` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer presses a key that no priority binding holds, other than `y`, `n`, `escape`, `enter`, `tab` or `shift+tab`, while the question is open, then the system shall keep the question open with the session unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** `a`, `l`, `p`, `s`, `q` and `space` → the question still the top screen and the session digest unchanged (6 of 6).
- **Negative control:** the `pb_B` binding of `s` (save first) → the `s` arm leaves the question → RED.
- **Boundary catalog:** ☒ invalid — six keys outside the set, two of them app keys (`l`, `p`) and `q` (quit).
- **Note (informative):** priority keys are LLR-174.2h's subject; `ctrl+q` and the palette's Quit under the question belong to Inc 12's quit question, and no guard is added here (A10-06).

### LLR-174.2h — The priority keys are inert under the question
- **Traceability:** HLR-174 · trace: `S19TuiApp.check_action` (`app.py`; the 9b guard `_LOAD_DIALOG_INERT_ACTIONS`); `BINDINGS` (`ctrl+k`, `ctrl+d`, `ctrl+l`, `ctrl+s`, `priority=True`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer presses `ctrl+l`, `ctrl+s`, `ctrl+k` or `ctrl+d` while the question is open, then the system shall keep the question as the top screen and run no app action.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** each of the 4 keys → the stack depth unchanged, the question on top, 0 calls of `action_load_file`, `action_save_project`, `action_focus_palette` and `action_cycle_density` (spies) (4 of 4).
- **Negative control:** code read, Textual 8.2.8: priority bindings walk the full chain, the App included, through a modal (the 9b finding behind LLR-173.2e), and 9b's guard is keyed on `LoadDialog` only → `ctrl+l` pushes a Load dialog over the question → RED. The executed probe is `planned` for the E2 baseline.
- **Boundary catalog:** ☒ invalid — the four priority keys.

### LLR-174.2i — Names are painted literally
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`); `painted_names` (`project_gather_service.py`); the question modal widgets with markup off (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint every name in the question literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** a loaded image `[b]x.s19`, a flow named `[red]f`, a project `[i]P` as the open project and as the target, and an image name holding U+202E → each painted name equals `painted_names([name])` and the painted text has 0 markup spans (5 of 5).
- **Negative control:** a mutation that paints with markup on → `[b]x.s19` paints as `x.s19` → RED.
- **Boundary catalog:** ☒ invalid — markup, a bidirectional control, a 130-character name (clipped to 120 with `…`).

### LLR-174.2j — The Patch Editor's own load keeps its guard
- **Traceability:** HLR-174 · trace: `LoadGuardScreen`, `PatchEditorPanel.DirtyLoadRequested` (`screens_directionb.py`, unchanged); `on_patch_editor_panel_dirty_load_requested` (`app.py`, unchanged)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall guard the Patch Editor's own document load with its existing dirty-load warning, not with the load question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** a dirty Patch Editor, then its Load button → 1 `LoadGuardScreen`, 0 load questions (1 of 1).
- **Negative control:** a mutation routing `DirtyLoadRequested` through the load question → 0 `LoadGuardScreen` → RED.
- **Boundary catalog:** none — one route, kept as it is.

### LLR-174.2k — The title names what is replaced
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall title the load question `Replace <current>?`, where `<current>` is the open project's name, else the loaded image's file name, else `the current session`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** project P open → `Replace P?`; no project, image `fw.s19` loaded → `Replace fw.s19?`; neither, a dirty Flow Builder, then a project load → `Replace the current session?` (3 of 3).
- **Negative control:** a mutation that always uses the image name → the P arm paints `Replace fw.s19?` → RED.
- **Boundary catalog:** ☒ boundary — project, image only, neither.

### LLR-174.2l — The unsaved image is named by its file name
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the guard asks while the image is unsaved, the system shall name the loaded image's file name in the question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** D with `fw.s19` loaded → the question text holds `fw.s19`, for a data load and for a project load (2 of 2).
- **Negative control:** a mutation that names the project instead of the image → the data-load arm (no project) misses `fw.s19` → RED.
- **Boundary catalog:** ☒ boundary — an image replacement and a project load.

### LLR-174.2m — Unsaved Patch Editor work is named
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the guard asks for a project load while the Patch Editor is dirty, the system shall name `Patch Editor entries` in the question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** W only → `Patch Editor entries` present; D only → absent (2 of 2).
- **Negative control:** a mutation that names it on D → the D-only arm holds it → RED.
- **Boundary catalog:** ☒ boundary — an entry edit; an unparsed paste buffer (both set W).

### LLR-174.2n — Unsaved Flow Builder edits are named
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`); `FlowBuilderPanel.current_flow`, `FlowBuilderPanel.is_dirty` (`flow_screens.py`, unchanged)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the guard asks for a project load while the Flow Builder is dirty, the system shall name `flow <flow name>` in the question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** F with the flow `patch_chain` → `flow patch_chain` present; F with an unnamed flow → `flow flow` (the panel's default name) present; D only → no `flow ` item (3 of 3).
- **Negative control:** a mutation that drops the flow item → the F arm misses it → RED.
- **Boundary catalog:** ☒ boundary — a named flow, the default name.

### LLR-174.2o — The load target is named
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`); `_confirm_then_load` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall end the load question with `Load <target> anyway?`, where `<target>` is `project <name>` for a project load and the file name of the requested file otherwise.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** a project row `Q` → `Load project Q anyway?`; a typed `<tmp>/b.s19` → `Load b.s19 anyway?`; a Workarea pick `x.hex` → `Load x.hex anyway?`; `v` to `firmware_b` → `Load firmware_b.s19 anyway?` (4 of 4).
- **Negative control:** a mutation that names the current file as the target → the typed arm paints the old name → RED.
- **Boundary catalog:** ☒ boundary — one target per route.

### LLR-174.2p — The load question's buttons say Replace and Cancel
- **Traceability:** HLR-174b, HLR-174c · trace: `_confirm_then_load` (NEW, `app.py`); the question modal (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall label the load question's buttons `Replace (y)` on `#confirm_yes` and `Cancel (n)` on `#confirm_no`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** 2 labels painted, each on its id (2 of 2); each shown key pressed acts (the "every shown key is verified" rule, §3 preface) (2 of 2).
- **Negative control:** a mutation that reuses `ConfirmDiscardScreen`'s labels `Discard` / `Cancel` (`screens.py:934-935`) → 0 `Replace (y)` painted → RED.
- **Boundary catalog:** none — two fixed labels.

### LLR-174.2q — The question says the items hold unsaved changes, in two sentences
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall state in the load question, in at most two sentences, that the named items hold unsaved changes.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** with 1, 2 and 3 items → the body holds the token `unsaved changes` once and at most 2 sentence ends (`.` or `?` outside names) (3 of 3).
- **Negative control:** a mutation that writes one sentence per item → the 3-item arm has 4 sentences → RED.
- **Boundary catalog:** ☒ boundary — 1, 2 and 3 items.

### LLR-174.2r — Both buttons and the body stay on screen
- **Traceability:** HLR-174 · trace: the question modal box rules (`styles.tcss`); the question modal (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall keep both buttons and the body of the question fully visible: each of the three regions equals its clipped region and lies inside the screen region.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** 3 items whose names are 120 characters long, at 99×54, 118×54 and 220×60 → both buttons and the body fully visible (each region equals its clipped region and lies inside the screen region) (3 of 3); the same at 118×54 with 1 short item (1).
- **Negative control:** a mutation setting `min-width: 120` on `#confirm_box` → at 99 columns `#confirm_no` has 0 visible columns → RED; a mutation that fixes the box height at 7 rows with `#confirm_buttons` undocked → both buttons have 0 visible rows → RED.
- **Boundary catalog:** ☒ boundary — 99, 118 and 220 columns; the longest names.

### LLR-174.2s — A second answer is ignored
- **Traceability:** HLR-174 · trace: the question modal `_close` `_dismissed` guard (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a second answer reaches the question after the first, then the system shall ignore it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** Q5-1 (`_close(True); _close(False)` in one tick) → 1 callback `True`, 1 pop, 0 exceptions; Q5-2 (`y` then `n` queued) → 1 answer; Q5-3 (the `_dismissed` flag, `escape` returns) → `CB == [False]` (3 of 3).
- **Negative control:** the `_dismissed` guard removed → `ScreenStackError` (K7, executed) → RED.
- **Boundary catalog:** ☒ error — a double answer in one tick.

### LLR-174.2t — The Patch Editor's change-file dropdown keeps the guard
- **Traceability:** HLR-174 · trace: `PatchEditorPanel.ChangeFileSelected`; `on_patch_editor_panel_change_file_selected` (`app.py`); `LoadGuardScreen` (`screens_directionb.py`, unchanged)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer picks a change file in the Patch Editor's dropdown while the panel holds unsaved entries, then the system shall show the Patch Editor's load guard before replacing them.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** dirty + pick → 1 `LoadGuardScreen`, 0 loads, the entry count and the flag unchanged; clean + pick → 0 guards and the file loads (2 of 2).
- **Negative control:** the `is_dirty` read removed → the dirty pick replaces the entries with no guard → RED.
- **Boundary catalog:** ☒ boundary — a dirty panel; a clean panel.

### LLR-174.3 — The answer comes before the project-session reset
- **Traceability:** HLR-174b · trace: `_confirm_then_load` (NEW); `_route_load_project`, `_handle_load_project`, `_reset_project_session` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer confirms a project load, the system shall run the project-session reset after the answer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_confirm.py -k tc_b100_46`
- **Numeric pass threshold:** `y` on a project load with W → 1 reset call, recorded after the question closed (an order spy on the dismiss and the reset); the same for re-loading the open project (2 of 2).
- **Negative control:** a mutation that resets before asking → the reset is recorded before the dismiss → RED.
- **Boundary catalog:** ☒ boundary — re-loading the open project.

### LLR-174.3a — A cancelled project load runs no reset
- **Traceability:** HLR-174c · trace: `_confirm_then_load` (NEW); `_reset_project_session` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer cancels the question of a project load, then the system shall not run the project-session reset.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_confirm.py -k tc_b100_46`
- **Numeric pass threshold:** `n`, `escape` and an immediate `enter` on a project load with D, F and W → 0 reset calls, the Patch Editor entry count unchanged and the Flow Builder blocks unchanged (3 of 3).
- **Negative control:** a mutation that resets before asking → the cancelled session is empty → RED.
- **Boundary catalog:** ☒ boundary — each cancel key.

### LLR-174.3b — The project-load handler asks nothing
- **Traceability:** HLR-174 · trace: `_handle_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall ask no question from inside the project-load handler.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_confirm.py -k tc_b100_46`
- **Numeric pass threshold:**
  - A direct `_handle_load_project("P")` with D, F and W → 0 questions and 1 load (`current_project == "P"`).
  - AST: the body of `_handle_load_project` holds 0 calls of `push_screen` and 0 calls of the seam (2 of 2).
- **Negative control:** a mutation that moves the guard into `_handle_load_project` → the direct call pushes 1 question (and the 13 test files that call it directly, §5.4, wait on a modal) → RED.
- **Boundary catalog:** none — a structural census plus one direct call.

### LLR-174.3c — A confirmed project load that is then refused keeps the work
- **Traceability:** HLR-174b, HLR-174c · trace: `_confirm_then_load` (NEW); `_handle_load_project` (`app.py`, the refusals before the reset)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a project load that the engineer confirmed is refused before the project-session reset, then the system shall keep the unsaved work.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_confirm.py -k tc_b100_46`
- **Numeric pass threshold:** a listed project `M2` holding 1 data file and 2 MAC files (listed by §1.3; refused by `_list_project_files`), with D and W → `y` → 1 refusal line, 0 reset calls, the session digest unchanged, D still true, the Patch Editor entry count and W unchanged (5 of 5); an A2L-only project `A2LONLY` whose one A2L cannot be read (an ACL deny-read or a lock) → `y` → 1 refusal line `No supported files in project: A2LONLY`, 0 reset calls, `current_file` unchanged, the entry count unchanged and the flag unchanged (5 of 5; probe_sec_refuse).
- **Negative control:** a mutation that clears the flags or runs the reset when `y` is pressed → D or W false after the refusal → RED; the base order (the reset before the A2L read) → the A2L arm finds `current_file` `None`, 0 entries and the flag cleared after `y` → RED.
- **Boundary catalog:** ☒ error — a project refused after the answer.

### LLR-174.3d — A cancelled variant switch leaves the pending selection unchanged
- **Traceability:** HLR-174c · trace: `_handle_select_variant` (`app.py`); `_pending_variant_id`
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer cancels the question of a variant switch, then the system shall leave the pending variant selection unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_confirm.py -k tc_b100_46`
- **Numeric pass threshold:** `n` on the C40 switch → `_pending_variant_id is None` and `0` `load_from_path` calls; then a `#files_list` pick of `other.s19` answered `y` → after the install `current_file.variant_id is None` and `_variant_set.active_id == "firmware_a"` (2 of 2; C42).
- **Negative control:** the stamp set before the seam (the base order) → `_pending_variant_id == "firmware_b"` after `n`, and the next install stamps `other.s19` as `firmware_b` → RED.
- **Boundary catalog:** ☒ boundary — a cancelled switch; the next confirmed load.

### LLR-174.4 — One load seam for every image-replacing route
- **Traceability:** HLR-174 · trace: `_confirm_then_load` (NEW, B100-I20); `_handle_load_dialog`, `_load_workarea_file`, `_load_from_item`, `_handle_select_variant`, `_route_load_project`, `_load_path_from_user_input` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.17, LED-2026-10-26-batch-100.27, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall pass every image-replacing route through one load guard before the route changes the session.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_confirm.py -k tc_b100_72`
- **Numeric pass threshold:**
  - With an unsaved patch: the Load dialog, a Workarea Files pick and `v` by keys, and the Load-result panel's `v` with D forced through a private call (declared) → 4 questions; `n` on each → the session digest unchanged (4 + 4).
  - AST census of `app.py`: every call of `load_selected_file`, `load_from_path`, `load_a2l_from_path` and `_handle_load_project` is inside a `go` passed to the load seam, inside `_handle_load_project`, or is `load_from_path`'s worker start; `_route_load_project`'s body is the project seam, so its callers are exempt (0 bypasses).
- **Negative control:** executed on the 9a tree (this E1's probe): the Workarea pick, the Load dialog router and the variant switch each replace a patched image with the stack `['Screen']`; on `1d677ba` (P-42) the same for the Workarea pick and `v` → RED.
- **Boundary catalog:** ☒ boundary — the four routes; the start-up load.
- **Note (informative):** the old text also had the seam run the worker refusal (LLR-177.1). That refusal lands at Inc 12b, which adds it to this seam; Inc 10 adds no refusal.

### LLR-174.4a — One question per load request
- **Traceability:** HLR-174 · trace: `_confirm_then_load` (NEW); `_handle_load_dialog`, `_load_path_from_user_input`, `_route_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When one load request passes the load guard, the system shall ask at most one question for that request.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_confirm.py -k tc_b100_72`
- **Numeric pass threshold:** with D and W: a typed absolute project folder (the router, the typed-path route, then the project route) → 1 question; a recent data path → 1; a project row → 1 (3 of 3). After `y`, 0 further questions until the load ends.
- **Negative control:** a mutation that guards both the dialog router and the project route → the typed project folder asks twice → RED.
- **Boundary catalog:** ☒ boundary — a request that passes two routing functions.

### LLR-174.4b — A typed or recent path takes its load kind from the typed-path classification
- **Traceability:** HLR-174, HLR-174a · trace: `_load_path_from_user_input`, `_typed_load_route` (`app.py`); `_confirm_then_load` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog closes with a `path` or `recent` choice, the system shall take the load kind from the typed-path route's classification of that text.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_confirm.py -k tc_b100_72`
- **Numeric pass threshold:** with D and W: typed `.mac` → 0 questions (attach); typed `.a2l` → 0; typed `.s19` → 1 question (image); typed `<W>/P` → 1 question naming `Patch Editor entries` (project); a typed file removed after the dialog's verdict (the classification refuses `not found`) → 0 questions and 1 refusal line (5 of 5).
- **Negative control:** a mutation that keys the kind on the dismiss kind (`path` → image) → the `.mac` arm asks → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the three kinds; a refusal found at routing time.

### LLR-174.4c — A work-area file takes its load kind from its suffix
- **Traceability:** HLR-174, HLR-174a · trace: `_load_workarea_file` (9b G1), `_load_from_item` (`app.py`); `_confirm_then_load` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer picks a work-area file, the system shall treat a MAC or A2L file as an attach and any other file as an image replacement.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_confirm.py -k tc_b100_72`
- **Numeric pass threshold:** with D: `x.mac`, `c.a2l`, `x.s19` and `x.hex`, from the Load dialog's `workarea` rows and from the Workarea Files list → 0, 0, 1 and 1 questions on each surface (8 of 8).
- **Negative control:** a suffix-blind mutation (every pick is an image replacement) → the `.mac` and `.a2l` arms ask → RED.
- **Boundary catalog:** ☒ boundary — each loadable suffix on both surfaces; a suffix in upper case (`X.MAC`).

---

## §C — Edits outside LLR-174

### C.1 — LLR-165.3: the interim line is removed (replaced by the question)

**Statement, one sentence removed.** Delete from LLR-165.3's Statement the sentence that starts "**Interim, until Inc 10 lands the question (LLR-174.x):**" and ends "its test arm is re-pinned there." Nothing else in the block changes, except:
- **Ledger:** add `LED-2026-10-26-batch-100.NN`.
- **Numeric pass threshold:** append "and a project load whose outgoing document held N > 0 entries paints 0 lines holding `Closed the Patch Editor document` (Inc 10, ruling Q2)".
- **Negative control:** append "a mutation that keeps the interim line → the Inc 10 arm finds 1 line → RED".

Why: the interim line (LED .51 as amended by LED .55(a)) stood in for the question until a public dirty-flag reader existed. From Inc 10 every shipped project load passes the seam, so unsaved Patch Editor work is asked about before the reset (LLR-174.1b, LLR-174.3), and the line would only repeat it. For a document that was saved, the line said "unsaved changes were not kept", which was false.

Observation (not fixed here, outside Inc 10's scope): the remaining Statement of LLR-165.3 still holds two normative clauses (the rebind to a new `ChangeService()`, and no reset method on the service). It belongs to Inc 3 and is left for the batch's EARS pass.

### C.2 — LLR-166.1 (TC-B100-12): the question `n` arm — statement unchanged

Inc 10 writes the arm its threshold names ("Inc 10 (question `n`)"):
- The Patch window displayed, the focus on `#patch_entry_address_input` (an `Input`), D set; `ctrl+l`, type a data file path, `enter` → the question → `n` → the focus on `patch_editor_panel` (that window's target).
- The Workspace window displayed, the focus on `#files_list`, D set; pick a data file → the question → `escape` → the focus on `files_list`.
- 2 of 2.
- Negative control: a mutation that skips the focus re-home on a cancelled question → the first arm leaves the focus on the `Input` → RED.

### C.3 — LLR-167.8 (TC-B100-70): the project-load question arm — statement unchanged

Inc 10 writes the arm the threshold defers to it:
- An entry pasted → Save project → a project load through the Load dialog → 0 questions (the flag was cleared by Save project).
- A refused Save project (the flag stays set) → a project load through the Load dialog → 1 question naming `Patch Editor entries`.
- 2 of 2.
- Negative control: a mutation that skips the panel's `mark_saved` → the first arm asks → RED.

### C.4 — LLR-173.7 (TC-B100-66): the question's painted text — statement unchanged

Inc 10 extends the scan to the load question in 3 scenes (1 item, 3 items, a project target) and the quit-parameter arm of LLR-174.2a → 0 matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-`. Negative control: the prototypes' decision-id strings (UX-18) copied into the question → RED.

### C.5 — AT-B100-03: re-pinned to answer `y` (§5.3 says so)

AT-B100-03 adds a Patch Editor entry through the panel's inputs (writer w1 sets the flag) and types a draft in the paste buffer (writer w2), then loads P2 through the Load dialog. From Inc 10 that load asks. The re-pin:
- after the project pick, wait for the question, assert it names `Patch Editor entries`, press `y`;
- delete the two assertions on `Closed the Patch Editor document (1 entries); unsaved changes were not kept` (the `_wait_for` on the freshest line and the final `in log_lines` check);
- every other assertion stays (P2's files, the empty ledger, the clean subtitle, the empty paste buffer).

---

## §D — Index, token, census and IFC rows

### D.1 — §5.3 TC index: new and changed rows

| TC arm | Written at | Extended at |
|---|---|---|
| TC-B100-44 (LLR-174.1, LLR-174.1a, LLR-174.1b, LLR-174.1c) | Inc 10: the 24-cell table by kind, the saved / save-back / saved-then-patched boundaries, an attach keeps the patch, the public reader of the Patch Editor flag (LED .NN) | — |
| TC-B100-45 (LLR-174.2, LLR-174.2a, LLR-174.2b, LLR-174.2c, LLR-174.2d, LLR-174.2e, LLR-174.2f, LLR-174.2g, LLR-174.2h, LLR-174.2i, LLR-174.2j, LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2p, LLR-174.2q, LLR-174.2r, LLR-174.2s, LLR-174.2t) | Inc 10: one modal with two buttons, the parameters (quit arm), the focus, `y`, `n` / `escape`, `enter`, clicks, other keys, the priority keys inert, literal names, the Patch Editor's own guard kept, the title, the three items, the target, the labels, two sentences, the buttons and body on screen, a second answer ignored, the change-file dropdown keeps the guard (LED .NN) | Inc 12a+12b: the quit question built through the same modal |
| TC-B100-46 (LLR-174.3, LLR-174.3a, LLR-174.3b, LLR-174.3c, LLR-174.3d) | Inc 10: the reset after the answer, no reset on cancel, the project-load handler asks nothing, a confirmed and then refused project load keeps the work, a cancelled variant switch leaves the pending selection unchanged (LED .NN) | — |
| TC-B100-72 (LLR-174.4, LLR-174.4a, LLR-174.4b, LLR-174.4c) | Inc 10: all four routes (the panel's `v` with a forced state), the seam census, one question per request, the kind of a typed or recent path, the kind of a work-area file (LED .NN) | Inc 12b: the worker refusal in the seam (LLR-177.1) |

**Edits to existing rows.**
- TC-B100-72 (LLR-174.4): replaced by the row above.
- TC-B100-12 (LLR-166.1): "Inc 10: question `n`" → "Inc 10: question `n` (an `Input` focus re-homed) and `escape` (a healthy focus kept) (LED .NN)".
- TC-B100-70 (LLR-167.8): "Inc 10: the project-load question arm" → "Inc 10: the project-load question arm — 0 questions after Save project, 1 after a refused one (LED .NN)".
- TC-B100-66 (LLR-173.7), "Extended at" (as 9b writes it): "Inc 10: the question" → "Inc 10: the question in 3 scenes and the quit-parameter arm (LED .NN)".
- New row: `TC-B100-10 (LLR-165.3) | Inc 3 | Inc 10: the interim line removed — 0 closed-document lines; test_tc_b100_10_interim_discard_notice and test_tc_b100_10_notice_names_every_discarded_entry re-pinned to that arm (LED .NN)`.

### D.2 — §5.3 AT index

- AT-B100-15: "Inc 10 (all four routes)" → "Inc 10 (the three key-reachable routes — Load, the Workarea Files pick, `v` — plus the question, keep, replace, items and after-save halves; the panel's `v` is TC-B100-72's forced-state arm, because by keys the panel opens only on an image just recorded as saved)".
- AT-B100-03: unchanged text ("Inc 10 (answers `y`: the P1 entry is unsaved)"); §C.5 states the re-pin.

### D.3 — §3 preface token table: one new row

`load question (Inc 10, LLR-174.2k, LLR-174.2o, LLR-174.2p, LLR-174.2q) | unsaved changes | Load <target> anyway? — buttons Replace (y) / Cancel (n)`

### D.4 — §5.4 reverse census

- Row `_load_from_item`, `_handle_select_variant` (Inc 10): add `_load_workarea_file` (9b G1), `_handle_load_dialog`, `_route_load_project`, `_load_path_from_user_input`. Counts on the 9a tree (`grep -rl` / `grep -r` over `tests/*.py`): `_load_from_item` 3 files / 7 references; `_handle_select_variant` 2 / 12; `action_select_variant` 3 / 7; `_handle_load_dialog` 2 / 6; `_route_load_project` 1 / 3; `_load_path_from_user_input` 4 / 19. Files that call a route AND patch or set a dirty flag (first cut, `grep -l`): `test_b100_active_variant.py`, `test_loadfilescreen_input.py`, `test_tui_patch_variant.py`. The per-node census (which nodes now meet the question) is owed at the E2 baseline.
- New row: `interim closed-document line (Inc 10, LLR-165.3) | tests/test_b100_session_reset.py: test_tc_b100_10_interim_discard_notice (:587), test_tc_b100_10_notice_names_every_discarded_entry (:629), test_at_b100_03_project_load_over_unsaved_work_saves_only_p2 (:775; the asserts at :875-882 and :943-946) | re-pinned (§C.1, §C.5); test_tc_b100_10_no_discard_notice_when_nothing_unsaved (:603) holds unchanged`.
- New row: `PatchEditorPanel._dirty read outside its module (Inc 10, LLR-174.1c) | app.py :10576 (_handle_save_dialog, E3 R1) | replaced by the public reader`.

### D.5 — §4 IFC edits

- FLOW `unsaved_work_to_question`: node "the confirm modal (screens.py)" → `in : title, question text, two labels`; `out : replace or cancel`. Add node `fn : the public dirty reader (screens_directionb.py PatchEditorPanel.is_dirty) · owner : LLR-174.1c · in : the panel's flag · out : bool`.
- COMPONENT `load_question`: `INPUTS : unsaved_items: list[str]` → `INPUTS : title: str, body: str, yes_label: str, no_label: str`; `consumers : s19_app/tui/app.py::_handle_load_dialog` → `s19_app/tui/app.py::_confirm_then_load`.

---

## §E — Ledger entry (number assigned at merge)

### LED-2026-10-26-batch-100.NN — Inc 10 E1 — requirements to strict EARS / ISO 29148
- **Requirement:** HLR-174, HLR-174a, HLR-174b, HLR-174c, HLR-174d, LLR-174.1, LLR-174.1a, LLR-174.1b, LLR-174.1c, LLR-174.2, LLR-174.2a, LLR-174.2b, LLR-174.2c, LLR-174.2d, LLR-174.2e, LLR-174.2f, LLR-174.2g, LLR-174.2h, LLR-174.2i, LLR-174.2j, LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2p, LLR-174.2q, LLR-174.2r, LLR-174.2s, LLR-174.2t, LLR-174.3, LLR-174.3a, LLR-174.3b, LLR-174.3c, LLR-174.3d, LLR-174.4, LLR-174.4a, LLR-174.4b, LLR-174.4c, LLR-165.3, LLR-166.1, LLR-167.8, LLR-173.7. New in this entry: HLR-174a, HLR-174b, HLR-174c, HLR-174d, LLR-174.1a, LLR-174.1b, LLR-174.1c, LLR-174.2a, LLR-174.2b, LLR-174.2c, LLR-174.2d, LLR-174.2e, LLR-174.2f, LLR-174.2g, LLR-174.2h, LLR-174.2i, LLR-174.2j, LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2p, LLR-174.2q, LLR-174.2r, LLR-174.2s, LLR-174.2t, LLR-174.3a, LLR-174.3b, LLR-174.3c, LLR-174.3d, LLR-174.4a, LLR-174.4b, LLR-174.4c. Also: §3 token table (1 row added); §5.3 TC index (3 rows added, 1 row replaced, 4 rows changed); §5.3 AT index (1 row changed); §5.4 reverse census (1 row extended, 2 rows added); §4 IFC (1 flow node changed, 1 node added, 1 component changed).
- **Pairing note:** a requirement split here lists on its Ledger line only this entry. The history before the split stays on its parent's Ledger line: HLR-174 (.1, .2, .3, .17), LLR-174.1 (.1, .3, .17), LLR-174.2 (.3, .38), LLR-174.3 (none), LLR-174.4 (.17, .27). LLR-174.2a also cites LED .38, whose arm it carries.
- **Date:** 2026-10-31
- **What changed:** each Inc 10 requirement was rewritten to the operator's strict standard, as in LED .76, .82 and the Inc 9b E1 entry: one EARS sentence in one of the five forms, one "shall", every failure path its own unwanted-behaviour requirement, and a numeric pass threshold and a negative control each, checked against ISO/IEC/IEEE 29148. Function names moved from the statements to the trace. Existing ids are kept; a split keeps the id for the first part and adds a suffix; nothing is renumbered or deleted. Negative controls are executed probes where one exists (P-17 on `1d677ba`; this E1's probe on the 9a tree, `inc-10-design/work/probe_p10.out.txt`), executed enumerations (LED .17), or code reads, each named. Per id:
  - **HLR-174:** 1 statement with about 12 behaviours and 8 "shall"s (when to ask, what counts as unsaved, attach never asks, the wording, `y`, `n` / `escape`, the focus, `enter`, no ask when nothing is unsaved, before the reset) → event "when a route requests a load while unsaved work it would replace or move to another project exists (D for an image replacement; D, W or F for a project load), ask one question before the load changes the session". AT-B100-15's question half. The panel's `v` arm is a forced-state TC arm: by keys the Load-result panel opens only right after a project load, which records the image as saved, and W and F do not count for an image replacement (ruling Q5).
  - **HLR-174a (new, split from HLR-174):** event "a load with no unsaved work it would replace or move to another project (D for an image replacement; D, W or F for a project load) loads without the question", whether or not a project is open. The `pb_A` prototype asked whenever a project was open; the approved text did not.
  - **HLR-174b (new):** event "replace runs the load that asked".
  - **HLR-174c (new):** event "cancel leaves the session and the kept work unchanged".
  - **HLR-174d (new):** ubiquitous "one question names every unsaved item that made the guard ask".
  - **LLR-174.1:** 1 statement holding the whole table → event per load kind: LLR-174.1 (image replacement, iff D), LLR-174.1a (new: an attach never asks; executed: a MAC attach keeps the patched byte), LLR-174.1b (new: a project load iff D, F or W).
  - **LLR-174.1c (new):** ubiquitous "the Patch Editor flag is read only through a public reader" (P-43). The 9a tree already reads the private `panel._dirty` once (`app.py:10576`, Inc 8b E3 R1, whose comment says "Inc 10 adds the panel's public dirty reader"); the census makes that read move to the reader.
  - **LLR-174.2:** 1 statement with 8 behaviours → LLR-174.2 (one modal, exactly two buttons; VS-PB-2), LLR-174.2a (new: the parameters, LED .38's quit arm), LLR-174.2b (focus), LLR-174.2c (`y`), LLR-174.2d (`n` / `escape`, one shared response), LLR-174.2e (`enter`), LLR-174.2f (new: a click), LLR-174.2g (new: any other non-priority key), LLR-174.2h (new: the priority keys, a failure path that had no requirement; ruling Q4), LLR-174.2i (literal names, corrected from `safe_text` alone to `painted_names` with markup off, the batch's one scrub), LLR-174.2j (`LoadGuardScreen` kept for the Patch Editor's own load), LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2p, LLR-174.2q (new: the question's text, made testable by tokens: the title, the three items, the target, the labels, "unsaved changes" in at most two sentences — "short" was not measurable), LLR-174.2r (new: both buttons and the body stay on screen at 99, 118 and 220 columns), LLR-174.2s (new: a second answer is ignored, E3 A10-03), LLR-174.2t (new: the Patch Editor's change-file dropdown keeps the load guard, E3 S10-02).
  - **LLR-174.3:** 2 "shall"s → LLR-174.3 (event: the reset after the answer) and LLR-174.3a (new, unwanted: no reset on cancel).
  - **LLR-174.3b (new):** ubiquitous "the project-load handler asks nothing" — moved from LLR-174.4's "`_handle_load_project` called directly by tests is not a route".
  - **LLR-174.3c (new):** unwanted "a confirmed project load that is refused before the reset keeps the work" — a failure path with no requirement: a listed folder with 2 MAC files is refused by `_list_project_files` after the answer; the E3 S10-01 arm adds an A2L-only project whose one A2L is unreadable (the A2L read and the all-`None` check now run before the reset).
  - **LLR-174.3d (new):** unwanted "a cancelled variant switch leaves the pending selection unchanged" — the `_pending_variant_id` stamp is set only inside `go` (C42; E2-rulings P-3, applied by E3).
  - **LLR-174.4:** 1 statement plus "it runs the guard and the worker refusal" → ubiquitous "every route passes one guard". The worker refusal (LLR-177.1) is Inc 12b's and leaves this text; an informative note keeps the pointer.
  - **LLR-174.4a (new):** event "one question per request" — a typed project folder passes the router, the typed-path route and the project route.
  - **LLR-174.4b, LLR-174.4c (new):** the load kind of a typed or recent path (from the classification, so a typed `.mac` is an attach) and of a work-area file (from its suffix). The old text did not say how a route knows its kind.
  - **LLR-165.3:** the interim sentence (LED .51, LED .55(a)) is removed; the closed-document line goes, and its two TC-B100-10 arms and AT-B100-03's two assertions are re-pinned (ruling Q2).
  - **LLR-166.1, LLR-167.8, LLR-173.7:** statements unchanged; the Inc 10 arms their thresholds defer are written out (§C.2, §C.3, §C.4).
- **Rulings applied:** the text follows the recommendations of `inc-10-design/E1-rulings-proposed.md` Q1 to Q8. A different ruling changes the ids each question names.
- **E3 r1 design-fix:** applied `inc-10-design/E3-rulings.md` A10-01 … S10-04 to this draft and the two prototypes: added LLR-174.2s, LLR-174.2t and LLR-174.3d; rewrote the HLR-174 / HLR-174a triggers to the unsaved flags (A10-05), LLR-174.2b's threshold to 1 of 1 (A10-04), LLR-174.2r's negative controls and "fully visible, body included" (P-GA10-2), LLR-174.3c's A2L arm and `_list_project_files` cite (S10-01, A10-10), and LLR-174.4's census clause (P-2).
