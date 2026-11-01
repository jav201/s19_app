# Inc 11 E1 — replacement requirement blocks (draft, not merged)

Stage E1 of the design-first pipeline (`dev-flow-v3-beta` skill) for Inc 11, "the Save project dialog" (PLAN.md row 11: "Save project dialog: real name, clash/reserved/pending lines, no Browse… — M-4, D7 dialog, CW-U-12/13, O-9"; sources `screens.py`, `app.py`, `styles.tcss`).

**How to merge.**
1. §A replaces the `### HLR-175 — The Save project dialog shows exactly what the save will do` block in `01-requirements.md` (§3), and inserts HLR-175a … HLR-175f right after it.
2. §B replaces the blocks `### LLR-175.1` … `### LLR-175.4` (§4) with the blocks below, in the order given.
3. §C holds the TC-index rows (§5.3), the AT-index rows, the token-table edits (§3 preface), the reverse-census edits (§5.4) and the FLOW / COMPONENT edits (§4 IFC).
4. §D is the ledger entry, numbered `LED .NN`. Every `LED-2026-10-26-batch-100.NN` below takes the number assigned at merge.

**Conventions.**
- Every Statement holds exactly one "shall". No other field uses the word.
- Function names appear only in the trace. `NEW` marks a symbol Inc 11 creates; its name is provisional until E2.
- "The 9a tree" means the worktree `s19_app-b100-inc9a` on 2026-10-31: `4fef292` plus 9a's uncommitted changes. Inc 9a was merged to `main` as `e28edeb` / `8947666` during this E1 and that worktree was removed; probes P11-1 … P11-4 ran on it before. The later reads used `s19_app-b100-inc9b` at `8947666` (clean). `SaveProjectScreen` and `SaveProjectPayload` are byte-identical to `1d677ba` there (`git diff 1d677ba -- s19_app/tui/screens.py` touches only the imports and `LoadResultScreen`), so P-18 and P-19 still hold for the Save dialog.
- Inc 11 is designed against the tree after Inc 9b and Inc 10. It does not touch `LoadDialog`, `_handle_load_dialog` or Inc 10's question modal; it extends Inc 9b's priority-key guard (`check_action`, S-g) by one screen class.
- "The dialog" means the Save project dialog. "Confirm Save" means `alt+s`, a press of `#save_ok`, or `enter` in `#project_name` (ruling Q8).
- "The plan for a name" means the `SavePlan` the one save preparation (LLR-175.6) returns for the typed text and the disk at that moment. "The painted plan" means the plan whose rows `#save_summary` shows, exposed as `SaveProjectScreen.plan` (LLR-175.4k).
- "Painted literally" means the name goes through `painted_names([name])` (the batch's one category scrub, 8b S3R2-4; LLR-172.6) and is painted with markup off. The app paints; `screens.py` receives plain text.
- A "token pair" is the reason token and the next-step token of one §3 preface row; an AT matches the tokens, the rest of the wording is free.
- **Session digest** means the tuple (`current_file.path`, SHA-256 of the image bytes, `current_project`, `current_a2l_path`, the MAC path), read before and after an action. **Work-area listing** means the sorted set of every path under `.s19tool/workarea/`, read before and after an action.
- Painted strings are English and carry no internal decision id (LLR-173.7; the prototype's "Browse is gone (D7)" line is not shipped).

**Fixtures used by the thresholds** (built by `tests/support/b100_projects.py` builders or by real saves; `project.json` only from the shipped handler, C-QA-4):
- F-fresh: no project open, `examples/case_01_basic_valid/firmware.s19` loaded.
- F-open: project `P` open (S19 + MAC), saved by a real save.
- F-merge: project `ab` saved and not open; another session loaded.
- F-saveas: `P` open holding `flows/f1.json`, `patches/boost.json`, `reports/r.md` (AT-B100-09's tree).
- F-pending: F-open plus 1 applied Patch Editor entry, not saved.
- F-document: F-fresh plus a pasted change document with 1 entry.
- F-case06: a project holding the case_06 files (37 742 888-byte A2L, P-33), plus 1 applied entry.

---

## §A — HLR blocks (replace HLR-175; insert HLR-175a … HLR-175f after it)

### HLR-175 — The Save project dialog shows exactly what the save will do
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.15, LED-2026-10-26-batch-100.31, LED-2026-10-26-batch-100.37, LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While the Save project dialog is open, the system shall paint in `#save_summary` the plan for the typed name at the plan's granularity, with the target folder and its kind in `#save_where`.
- **Decomposition:**
  - LLR-175.1: the target line (sanitised folder, kind).
  - LLR-175.4, LLR-175.4c, LLR-175.4d, LLR-175.4e, LLR-175.4f, LLR-175.4g, LLR-175.4j: the summary's rows, the image line, the pending line, the links row, the merge's active-variant row, literal names, one line per row.
  - LLR-175.5, LLR-175.5a: what is computed once per open and what per name.
  - The compound HLR-175 (about 20 behaviours, 11 normative clauses) is split here into HLR-175 and HLR-175a … HLR-175f (LED .NN).
- **Variant slots (filled by the P-C verdict B, LED-2026-10-26-batch-100.2):** VS-PC-1 = the name plus the "what will be saved" summary, at the row granularity of LLR-175.4. VS-PC-2 = during a refusal, Save stays focusable and refuses with the reason painted (LLR-175.3f). VS-PC-3 = the `pc_B` ids (`#project_name`, `#save_summary`, `#save_where`, `#save_ok`, `#save_cancel`).
- **Rationale (informative):** the base dialog paints nothing before Save (P-19; P11-2: `typed 'a b' -> dialog text has 'ab' folder line? False`). The operator's P-C note: "Un error aquí podría hacer que el trabajo del usuario se invalide o se pierda o se sobreescriba o se renombre. Mucho cuidado al popular esta información." — hence R-PC: one plan, painted and executed. M-4 ("show the sanitised name before saving"). UX-32 / QA R2-05 (granularity), UX-35 (merge row).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_47 or tc_b100_65 or at_b100_16 or at_b100_21"`
- **Numeric pass threshold:**
  - 7 scenarios (fresh, pending patch, refused, `files`, document, merge, save-as; §5.3) → for each, the painted rows equal the painted plan's rows, by landing name and action word, at 220 columns (0 differences, 7 of 7).
  - `a b` in F-fresh → `#save_where` names the folder `ab` and the kind `new folder` (1).
- **Negative control:** executed on the 9a tree (P11-2): `widgets … #save_summary: 0 #save_where: 0`; `typed 'a b' -> dialog text has 'ab' folder line? False` → AT-B100-16's folder half and AT-B100-21's painted half RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, folder half) the engineer opens Save project, types `a b` and sees `ab` as the folder, a new folder. (AT-B100-21, painted half) for each of the 7 scenarios, each painted row that is not cut at 220 columns matches its plan row by landing name and action. (AT-B100-09 re-pin) before saving P as Q, the summary lists `flows/`, `patches/` and `reports/`, 1 file each.
  - **Shipped surface:** the Save project dialog (`ctrl+s`, `#project_name`, `#save_where`, `#save_summary`; the plan through `SaveProjectScreen.plan`, the exception declared in the §3 preface).
  - **Acceptance test(s):** AT-B100-16, AT-B100-21
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid
    - empty: an empty name (no target line, no rows); an A2L-only session (no image row);
    - boundary: a 64- and a 65-character name; a target that holds the image's name; a 300-row plan;
    - invalid: hostile names on disk.
  - **Negative control:** as above → AT-B100-16 and AT-B100-21 RED.

### HLR-175a — Save writes exactly the plan the dialog painted
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer confirms Save in the Save project dialog, the system shall write exactly the files the painted plan's rows name; the active CRC template and the batch and assignment documents are copied outside the plan and are not named by its rows.
- **Decomposition:** LLR-175.3c, LLR-175.4a, LLR-175.4b, LLR-175.4k, LLR-175.4l.
- **Rationale (informative):** R-PC; the operator's P-C note. Without LLR-175.4b, a Save pressed within the 150 ms recompute window (LLR-175.5a) would save a plan nobody saw.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_65 or at_b100_21"`
- **Numeric pass threshold:** for the 7 scenarios, `alt+s` by key; then the plan read from `SaveProjectScreen.plan` equals the work-area tree written, at the plan's granularity, by full path and action (0 differences, 7 of 7); the refused scenario → 0 new paths in the work-area listing. The AT-B100-21 oracle excludes the gather homes (the active CRC template and the batch and assignment documents) by name.
- **Negative control:** a mutation where the handler places a file the plan did not name (for example, it re-plans without the document row) → 1 tree row without a plan row → RED. On the 9a tree the dialog holds no plan (code read: `SaveProjectScreen` has no `plan`) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-21, executed half) for each of the 7 scenarios, the engineer presses `alt+s`; the test then reads the dialog's plan (never calling the planner or driving the save through it) and finds its rows equal to the tree on disk.
  - **Shipped surface:** the Save project dialog (`alt+s`), `SaveProjectScreen.plan`, the work area on disk.
  - **Acceptance test(s):** AT-B100-21
  - **Boundary catalog (QC-3):** ☒ boundary ☒ error
    - boundary: `alt+s` pressed within 150 ms of the last keystroke (LLR-175.4b); a file appearing in the target after the paint;
    - error: a refused save (0 files).
  - **Negative control:** as above → AT-B100-21 RED.

### HLR-175b — A refused name is explained in the dialog before Save
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the save for the typed name would be refused, then the system shall paint the refusal's reason token and next-step token in the Save project dialog before Save is confirmed.
- **Decomposition:** LLR-175.1a, LLR-175.1b, LLR-175.1c, LLR-175.1d, LLR-175.1e, LLR-175.1f, LLR-175.1g, LLR-175.1h, LLR-175.1i, LLR-175.1j, LLR-175.1k, LLR-175.1l, LLR-175.1m, LLR-175.1o, LLR-175.1p, LLR-175.3f, LLR-175.6.
- **Rationale (informative):** O-9 ("Inc 11's dialog shows the clash before Save"); M-4; HLR-164 refusals were painted only after the dialog closed.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_47 or tc_b100_49 or at_b100_16"`, plus the AT-B100-02 re-pin `pytest tests/test_b100_save_guards.py -k at_b100_02`
- **Numeric pass threshold:** the 9 name refusals (reserved, device, disguised clash, over 64, path too long, link target, unreadable target, no usable character, a case-folded folder that is not the open project) and the 6 save refusals (plan refusal, free space, missing source, unreadable source, blocked entries, an unreadable work area) → 15 token pairs painted in the dialog with the dialog open and 0 new paths in the work-area listing (15 of 15; platform arms counted, §3 preface).
- **Negative control:** executed on the 9a tree (P11-2): `typed 'Reports' -> dialog text has 'reserved name'? False` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, clash half) with project `ab` saved and another project open, the engineer types `a b` and sees `already a project` and `choose another name` before pressing Save. (AT-B100-02 re-pin) `Reports`, `CON` and a 300-character name each paint their token pair in the dialog; `alt+s` keeps the dialog open; no folder appears.
  - **Shipped surface:** the Save project dialog (`#project_name`, `#save_where`, `alt+s`), the work area on disk.
  - **Acceptance test(s):** AT-B100-16, AT-B100-02
  - **Boundary catalog (QC-3):** ☒ boundary ☒ invalid ☒ error
    - boundary: 64 / 65 characters; the full-path limit met and exceeded by 1;
    - invalid: reserved and device names in mixed case, `con.txt`, `LPT¹`, a disguised clash, a junction target;
    - error: a source deleted after the load; a blocked document entry.
  - **Negative control:** as above → AT-B100-16 RED.

### HLR-175c — `escape` closes the dialog and saves nothing
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `escape` in the Save project dialog, the system shall close the dialog and save nothing.
- **Decomposition:** LLR-175.3, LLR-175.3a.
- **Rationale (informative):** CW-U-12 (P-18).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_49 or at_b100_16"`
- **Numeric pass threshold:** `escape` with the focus on each of `#project_name`, `#save_summary`, `#save_ok` and `#save_cancel`, with a valid name typed → 4 closes, the work-area listing and the session digest unchanged (4 of 4).
- **Negative control:** executed on the 9a tree (P11-2): `escape -> stack: ['Screen', 'SaveProjectScreen']`; and on `1d677ba` (P-18) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, escape half) after typing a valid name, `escape` closes the dialog and no folder appears.
  - **Shipped surface:** the Save project dialog, the screen stack, the work area on disk.
  - **Acceptance test(s):** AT-B100-16
  - **Boundary catalog (QC-3):** ☒ boundary — `escape` from each focus position; `escape` after a refusal was painted.
  - **Negative control:** as above → RED.

### HLR-175d — An empty Save is explained in the dialog
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer confirms Save while the name field holds no character other than spaces, then the system shall keep the dialog open and paint `name is empty` and `type a project name`.
- **Decomposition:** LLR-175.3b.
- **Rationale (informative):** CW-U-13 (P-19: an empty Save says nothing).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_49 or at_b100_16"`
- **Numeric pass threshold:** an empty and an all-space name, each with `alt+s` and with `#save_ok` → 4 token pairs, 0 dismisses, 0 new paths (4 of 4).
- **Negative control:** executed on the 9a tree (P11-2): `empty Save click -> stack: ['Screen', 'SaveProjectScreen'] | dialog text has 'name is empty'? False`; and on `1d677ba` (P-19) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, empty half, new) with the name field empty, `alt+s` paints `name is empty` and `type a project name`, and the dialog stays.
  - **Shipped surface:** the Save project dialog (`#project_name`, `#save_where`, `alt+s`).
  - **Acceptance test(s):** AT-B100-16
  - **Boundary catalog (QC-3):** ☒ empty — no character; spaces only.
  - **Negative control:** as above → RED.

### HLR-175e — The dialog saves only into this work area
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall save every project named in the Save project dialog as a direct folder of this work area.
- **Decomposition:** LLR-175.2, LLR-175.2a.
- **Rationale (informative):** D7 = `solo_workarea`, the dialog half (the handler half is LLR-171.3). P-11.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k tc_b100_48`, plus the AT-B100-02 re-pin
- **Numeric pass threshold:** 0 widgets `#project_parent_path` and 0 `#save_browse` in the dialog; a save through the dialog → the new folder's parent equals `self.workarea` (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2): `widgets #project_parent_path: 1 #save_browse: 1` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-02 re-pin) the dialog offers no parent-folder field and no Browse button; a saved project appears in the work area.
  - **Shipped surface:** the Save project dialog, the work area on disk.
  - **Acceptance test(s):** AT-B100-02
  - **Boundary catalog (QC-3):** ☒ boundary — a work area under a long base path.
  - **Negative control:** as above → RED.

### HLR-175f — Save project opens one dialog with the name, the summary and two buttons
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer asks Save project with a data file or an A2L loaded, the system shall open one dialog that holds `#project_name`, `#save_where`, `#save_summary`, `#save_ok` and `#save_cancel`.
- **Decomposition:** LLR-175.3d, LLR-175.3e, LLR-175.3g, LLR-175.3h, LLR-175.3i, LLR-175.3j, LLR-175.4h, LLR-175.4i, LLR-175.5b.
- **Rationale (informative):** VS-PC-3; UX-05 (focus); §3 preface "Keys" (`alt+<letter>` in a modal with a text field). Ruling Q6 of Inc 9b routes the priority-key exposure of this dialog here (LLR-175.3g).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_49 or at_b100_16"`
- **Numeric pass threshold:** `ctrl+s` and the palette entry `save_project`, each with F-fresh → 1 dialog on the screen stack (depth 2) holding the 5 ids, 1 each (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2): `#save_summary: 0 #save_where: 0` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, open half) `ctrl+s` opens the dialog with the focus in the name field; typing `s` puts `s` in the field.
  - **Shipped surface:** `ctrl+s`, the Save project dialog.
  - **Acceptance test(s):** AT-B100-16
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary
    - empty: nothing loaded (LLR-175.3j);
    - boundary: 118×54 and 220×60; a 300-row plan.
  - **Negative control:** as above → RED.

---

## §B — LLR blocks (replace LLR-175.1 … LLR-175.4)

### LLR-175.1 — The target line names the sanitised folder and its kind
- **Traceability:** HLR-175 · trace: `SaveProjectScreen` name-change handler (`screens.py`); `_prepare_project_save` (NEW), `_save_dialog_preview` (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the name in the Save project dialog changes, the system shall paint in `#save_where` the sanitised folder name and one kind of `new folder`, `updates the open project`, `merges into an existing project` and `new project in an existing folder`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:**
  - F-fresh: `a b` → `ab` and `new folder`; `../evil` → `evil` and `new folder`.
  - F-open (`P` open): `P` → `updates the open project`; the unsanitised form `P ` → `P` and `updates the open project`; with `P` saved on disk as `Ab` and open, `ab` typed → `Ab` and `updates the open project` (LED .52(a)).
  - F-merge: `ab` → `ab` and `merges into an existing project`.
  - an existing folder that is not a project (empty, or `notes.txt` only) → `<folder>` and `new project in an existing folder`.
  - 7 of 7, each line with 0 markup spans.
- **Negative control:** executed on the 9a tree (P11-2): `typed 'a b' -> dialog text has 'ab' folder line? False` → RED. Mutation: the kind computed with a case-sensitive comparison → the `ab` / `Ab` arm says `merges into an existing project` → RED.
- **Boundary catalog:** ☒ boundary — the open project in another case; the unsanitised form of the open project's name.

### LLR-175.1a — A reserved name is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW, the HLR-164 reserved rule moved out of `_handle_save_dialog`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the typed name's sanitised form equals a reserved work-area home compared case-folded, then the system shall paint `reserved name` and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `reports`, `CRC`, `Splits`, `FLOWS`, `Temp` → 5 token pairs in the dialog, 0 dismisses on `alt+s`, 0 new paths (5 of 5).
- **Negative control:** executed on the 9a tree (P11-2): `typed 'Reports' -> dialog text has 'reserved name'? False` → RED. Mutation: the comparison without case-folding → `Reports` paints no pair → RED.
- **Boundary catalog:** ☒ invalid — 5 spellings in mixed case.

### LLR-175.1b — A device name is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `is_windows_device_name`, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the typed name, one of its path components or its sanitised form is a Windows device name compared case-folded, then the system shall paint `device name` and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `nul`, `CON`, `com1`, `LPT¹`, `con.txt`, `C O N` → 6 token pairs, 0 dismisses on `alt+s`, 0 new paths (6 of 6).
- **Negative control:** mutation: only the sanitised form is checked → `con.txt` (sanitised `contxt`) paints no pair → RED. On the 9a tree the dialog paints nothing before Save (code read: no name-change handler) → RED.
- **Boundary catalog:** ☒ invalid — an extension, a superscript digit, spaces inside.

### LLR-175.1c — A disguised clash is refused in the dialog, naming both names
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the typed name's sanitised form equals, compared case-folded, the folder name of a project that is not open while the typed name differs from that folder name, then the system shall paint `already a project`, both names and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** F-merge with another project open: `a b` → 1 line holding `already a project`, `a b`, `ab` and `choose another name`; `AB` → the same tokens naming `AB` and `ab`; `ab` exactly → no refusal and `merges into an existing project` (3 of 3); 0 new paths and the `ab` folder's file digests unchanged after `alt+s` on each refused arm.
- **Negative control:** mutation: the clash compares without case-folding → `AB` paints `new folder` → RED. On the 9a tree the clash is painted only after the dialog closes (code read) → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — a case-only clash; the exact name (a merge, not a clash).

### LLR-175.1d — A name over 64 characters is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `PROJECT_NAME_MAX_CHARS`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the typed name's sanitised form is longer than 64 characters, then the system shall paint `name too long` and `shorten the name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** 64 characters → no refusal; 65 and 300 → 2 token pairs, the app running, 0 new paths (3 of 3).
- **Negative control:** mutation: the cap read as 65 → the 65-character arm paints no pair → RED.
- **Boundary catalog:** ☒ boundary — 64 / 65 / 300.

### LLR-175.1e — A name that makes the path too long is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `_SAVE_FULL_PATH_LIMIT`, `_SAVE_REPORT_SUFFIX_CHARS`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the typed name would make a project file path longer than the path limit, then the system shall paint `path too long` and `shorten the name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** a base path sized so that a name of length L meets the limit exactly → no refusal; length L + 1 → 1 token pair (2 of 2).
- **Negative control:** mutation: the 53-character report suffix dropped from the sum → the L + 1 arm paints no pair → RED.
- **Boundary catalog:** ☒ boundary — the limit met; exceeded by 1.

### LLR-175.1f — A target that is a link or junction is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `_project_folder_refusal`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the folder the typed name selects exists as a link or junction, then the system shall paint `link or junction` and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** a directory junction `W/jt` (made with `_winapi.CreateJunction`) and `jt` typed → 1 token pair, 0 files written through the junction after `alt+s` (1 of 1; Windows-only arm, counted).
- **Negative control:** mutation: the link check removed from the preparation → the dialog shows `merges into an existing project` for `jt` → RED.
- **Boundary catalog:** ☒ invalid — a junction; a symbolic link where the platform allows one.

### LLR-175.1g — A target that cannot be inspected is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `_project_folder_refusal`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the folder the typed name selects cannot be inspected, then the system shall paint `could not be read` and `check that the folder can be opened, then save again` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `os.lstat` raising `PermissionError` for the target (the TC-B100-62 fixture pattern) → 1 token pair, 0 dismisses on `alt+s` (1 of 1).
- **Negative control:** mutation: the `unreadable` reason mapped to "no refusal" → the dialog paints a kind → RED.
- **Boundary catalog:** ☒ error — a permission error on the target.

### LLR-175.1h — A name with no usable character is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `sanitize_project_name`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the typed name holds a character other than a space but its sanitised form is empty, then the system shall paint `name is empty` and `type a project name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `!!!`, `..`, `/` → 3 token pairs painted before Save, 0 dismisses on `alt+s` (3 of 3).
- **Negative control:** mutation: the pair painted only on Save (as for an empty field, LLR-175.3b) → `!!!` paints nothing before Save → RED.
- **Boundary catalog:** ☒ invalid — punctuation only; `..`.

### LLR-175.1i — A plan refusal is painted in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW), `_plan_project_save`, `plan_project_save` (`SavePlan.refusal`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the plan for the typed name is refused, then the system shall paint the plan's refusal text, with its reason token and next-step token, in the Save project dialog in place of the summary rows.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** a target holding a second MAC file → `already has a MAC file` and `choose another name`; a target holding a second A2L file → `already has an A2L file` and `choose another name`; a save as over 2 000 files → `too many files to copy` and `move files out of the project, then save again` (3 of 3); 0 summary rows painted and 0 new paths after `alt+s` on each.
- **Negative control:** mutation: the painter paints the rows of a refused plan and drops its refusal → 0 token pairs → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — the MAC rule, the A2L rule, the 2 000 / 2 001-file ceiling.

### LLR-175.1j — Too little free space is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; the free-space check moved out of `_handle_save_dialog`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a save to a new folder needs more bytes than the work area's volume has free, then the system shall paint `not enough free space` and `free disk space or remove files from the project` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `shutil.disk_usage` stubbed (TC only) to report `plan.total_bytes − 1` free → 1 token pair, 0 dismisses on `alt+s`; exactly `plan.total_bytes` free → no refusal (2 of 2).
- **Negative control:** mutation: the free-space check left in the handler only → the dialog paints no pair, and `alt+s` closes it before the refusal → RED.
- **Boundary catalog:** ☒ boundary — free space equal to the need; one byte short.

### LLR-175.1k — A missing source file is refused in the dialog
- **Traceability:** HLR-175b · trace: `_save_session_inputs` (NEW), `_prepare_project_save` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a file the session would save no longer exists, then the system shall paint `source file missing`, the file's name and `reload it or remove it from the project` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** F-fresh with the loaded work copy deleted, then `ctrl+s` → 1 line with the tokens and the name, 0 dismisses on `alt+s`, 0 new paths (1 of 1).
- **Negative control:** on the 9a tree this refusal is painted only after the dialog closes (code read: `_handle_save_dialog`, the LLR-155.4 arm) → RED.
- **Boundary catalog:** ☒ error — the image, the MAC or the A2L missing (3 arms).

### LLR-175.1l — An unreadable source file is refused in the dialog
- **Traceability:** HLR-175b · trace: `_save_session_inputs` (NEW; `_file_digest`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a file the session would save cannot be read, then the system shall paint `could not be read`, the file's name and `check that the file can be opened, then save again` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `_file_digest` raising `PermissionError` for the MAC (TC stub) → 1 line with the tokens and the name, 0 dismisses on `alt+s`, the app running (1 of 1).
- **Negative control:** mutation: the `OSError` not caught at dialog open → the dialog does not open, or the app raises → RED. On the 9a tree the text has no next step (`… could not be read: <reason>. Nothing written.`, `_handle_save_dialog`) → the next-step token is absent → RED (ruling Q11).
- **Boundary catalog:** ☒ error — a permission error on a source.

### LLR-175.1m — Blocked document entries are refused in the dialog
- **Traceability:** HLR-175b · trace: `_decide_project_image` (called once per open by `_save_session_inputs`, NEW)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the re-derive of the change document blocks an entry, then the system shall paint the blocked-entries reason token, the blocked addresses and the next-step token in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** the 1-blocked-entry document of TC-B100-57 (`0x8000007C`) → 1 line holding the reason token, `0x8000007C` and the next-step token; 0 dismisses on `alt+s`; 0 new paths (1 of 1). The tokens are those of the amended §3 row (ruling Q11).
- **Negative control:** on the 9a tree this refusal is painted only after the dialog closes (code read) → RED.
- **Boundary catalog:** ☒ error — 1 and 3 blocked entries.

### LLR-175.1n — A patched image that cannot be written is refused in the dialog — **Retired**
- **Retired (E2-rulings, LLR-175.1n withdrawal):** withdrawn by ledger, ruling Q11 (prefer removal). It cannot be reached: a MAC-only session's entries are `skipped-outside`, never blocked, so the arm is declared unreachable (probe p11b U4 / U4b). The `cannot be written` branch of `_decide_project_image` stays as defence, untouched; its §3 token row is removed with it.

### LLR-175.1o — A work area that cannot be listed is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW, the F-1 / P-5 arm)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the work area cannot be listed while the Save project dialog prepares a save, then the system shall paint `could not be read` and `check that the folder can be opened, then save again` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `os.listdir` (the `Path.iterdir` listing) raising `PermissionError` for the work area → 1 token pair, 0 dismisses on `alt+s`, the app running, 0 new paths (1 of 1).
- **Negative control:** mutation: the catch removed → the `PermissionError` leaves `preview()` inside the dialog's timer and the app stops → RED.
- **Boundary catalog:** ☒ error — a permission error on the work area.

### LLR-175.1p — A case-folded match that is not the open project is a disguised clash
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (G10, the file-identity test), `_plan_project_save` (the `open` kind test)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the typed name's sanitised form equals, compared case-folded, the folder name of a project folder that is not the open project's folder by file identity, while the typed name differs from that folder name, then the system shall paint `already a project`, both names and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `strasse` open with `straße` present, `strasse` typed → 1 token pair naming both names, 0 dismisses on `alt+s`, 0 files written, `straße/project.json` unchanged (1 of 1; Windows arm).
- **Negative control:** mutation: the open-project test kept on case-folding → `straße` is taken as the open project, the dialog paints `updates the open project`, and the files land in `straße` → RED.
- **Boundary catalog:** ☒ invalid — two folders equal under Python `casefold` but distinct on disk (`strasse` / `straße`, `abs` / `abſ`, `abk` / `abK`).

### LLR-175.2 — No parent field
- **Traceability:** HLR-175e · trace: `SaveProjectScreen.compose` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The Save project dialog shall compose no `#project_parent_path` widget and no `#save_browse` widget.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-48 — `pytest tests/test_b100_save_dialog.py -k tc_b100_48`
- **Numeric pass threshold:** 0 widgets with either id, at both reference sizes (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2): `widgets #project_parent_path: 1 #save_browse: 1` → RED.
- **Boundary catalog:** none — a fixed composition.

### LLR-175.2a — The dialog's payload names this work area as the parent
- **Traceability:** HLR-175e · trace: `SaveProjectScreen` save action (`screens.py`), `SaveProjectPayload.parent_folder`
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Save project dialog closes with a payload, the system shall set the payload's parent folder to this work area.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-48 — `pytest tests/test_b100_save_dialog.py -k tc_b100_48`
- **Numeric pass threshold:** a save through the dialog under a base path of 150 characters → `Path(payload.parent_folder)` equals `app.workarea` (1 equality) and the new folder's parent equals `app.workarea` (2 of 2).
- **Negative control:** mutation: the payload's parent taken from `base_dir` → the handler refuses `not the work area folder` → RED. On the 9a tree the parent comes from an editable field (code read) → declared: the default value already equals the work area, so the RED is the mutation.
- **Boundary catalog:** ☒ boundary — a long base path.

### LLR-175.3 — `escape` closes the dialog with no result
- **Traceability:** HLR-175c · trace: `SaveProjectScreen.BINDINGS`, the cancel action (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `escape` in the Save project dialog, the system shall dismiss the dialog with no result.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `escape` from each of the 4 focus positions → 4 dismisses with `None`, 0 new paths, the session digest unchanged (4 of 4).
- **Negative control:** executed on the 9a tree (P11-2): `escape -> stack: ['Screen', 'SaveProjectScreen']` → RED.
- **Boundary catalog:** ☒ boundary — each focus position; after a refusal.

### LLR-175.3a — Cancel closes the dialog with no result
- **Traceability:** HLR-175c · trace: `SaveProjectScreen.on_button_pressed` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `#save_cancel`, the system shall dismiss the Save project dialog with no result.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** a click and a focused `enter` on `#save_cancel`, each with a valid name typed → 2 dismisses with `None`, 0 new paths (2 of 2).
- **Negative control:** mutation: Cancel routed to the save action → 1 new folder → RED. Declared: on the 9a tree Cancel already dismisses with `None`, so the RED is the mutation.
- **Boundary catalog:** ☒ boundary — click and keyboard.

### LLR-175.3b — An empty Save keeps the dialog open and says why
- **Traceability:** HLR-175d · trace: `SaveProjectScreen` save action (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer confirms Save while the name field holds no character other than spaces, then the system shall keep the Save project dialog open and paint `name is empty` and `type a project name` in `#save_where`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `""` and `"   "`, each with `alt+s`, `#save_ok` and `enter` → 6 token pairs, 0 dismisses, 0 new paths (6 of 6).
- **Negative control:** executed on the 9a tree (P11-2): `empty Save click -> … 'name is empty'? False` → RED.
- **Boundary catalog:** ☒ empty — no character; spaces only.

### LLR-175.3c — Confirming Save closes the dialog and runs the save
- **Traceability:** HLR-175a · trace: `SaveProjectScreen.BINDINGS` (`alt+s`), the save action, `on_input_submitted`, `on_button_pressed` (`screens.py`); `_handle_save_dialog` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer confirms Save while the painted plan is the plan for the typed name and is not refused, the system shall close the Save project dialog and run the save.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** F-fresh, `fresh1` typed, the summary painted, then each of `alt+s`, a `#save_ok` click and `enter` in `#project_name` (3 fresh apps) → 1 dismiss each and 1 folder `fresh1` holding the plan's files (3 of 3).
- **Negative control:** code read on the 9a tree: `SaveProjectScreen` has no `BINDINGS` and no `on_input_submitted` → `alt+s` and `enter` save nothing → RED.
- **Boundary catalog:** ☒ boundary — the three triggers.

### LLR-175.3d — The dialog opens with the focus in the name field
- **Traceability:** HLR-175f · trace: `SaveProjectScreen.AUTO_FOCUS` / `on_mount` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Save project dialog opens, the system shall place the focus on `#project_name`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `ctrl+s` and the palette entry → `app.focused.id == "project_name"` (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2): `focused at open: OsClipboardInput project_parent_path` → RED.
- **Boundary catalog:** ☒ boundary — both open routes.

### LLR-175.3e — Plain letters stay in the name field
- **Traceability:** HLR-175f · trace: `SaveProjectScreen.BINDINGS` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall deliver every printable key pressed while `#project_name` has the focus to the name field.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `s`, `q`, `l`, `p`, `v`, `y` typed → the field holds `sqlpvy`, the stack depth stays 2, 0 status lines added (1 of 1).
- **Negative control:** mutation: a plain `s` bound to the save action → the field misses `s` and the dialog closes → RED. Declared: on the 9a tree the modal already blocks the app's non-priority letters, so the RED is the mutation.
- **Boundary catalog:** ☒ boundary — letters the app binds on the main screen.

### LLR-175.3f — Save during a refusal keeps the dialog open
- **Traceability:** HLR-175b · trace: `SaveProjectScreen` save action (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer confirms Save while the plan for the typed name is refused, then the system shall keep the Save project dialog open with `#save_ok` focusable and the refusal's token pair painted.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** a disguised clash, then `alt+s`, then `tab` to `#save_ok` and `enter` → 0 dismisses, `#save_ok.can_focus` is true and `#save_ok` gains the focus, the pair painted after each press, 0 new paths (1 of 1).
- **Negative control:** mutation: `#save_ok` disabled during a refusal → it cannot gain the focus → RED; mutation: the refused payload dismissed → 1 dismiss → RED.
- **Boundary catalog:** ☒ invalid — every refusal of HLR-175b keeps Save focusable (one arm per kind is in TC-B100-47).

### LLR-175.3g — App priority keys are inert while the dialog is open
- **Traceability:** HLR-175f · trace: `S19TuiApp.check_action` (`app.py`; the Inc 9b guard, S-g, widened by one screen class)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer presses `ctrl+l`, `ctrl+s`, `ctrl+k` or `ctrl+d` while the Save project dialog is open, then the system shall run no app action for that key.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** each of the 4 keys pressed with the dialog open → the screen stack stays the main screen plus the Save dialog (depth 2), the focus stays inside the dialog, the `#workspace_body` density class is unchanged and the palette stays closed (4 of 4). Declared: `ctrl+k` and `ctrl+d` then reach the name field's own line-editing bindings (Textual 8.2.8 `Input`: delete to the end, delete right), which is the field's behaviour, not an app action.
- **Negative control:** executed on the 9a tree (P11-2, P11-3): `ctrl+l over Save dialog -> stack: ['Screen', 'SaveProjectScreen', 'LoadFileScreen']`; `ctrl+s over Save dialog -> stack: ['Screen', 'SaveProjectScreen', 'SaveProjectScreen']`; `ctrl+d over Save: density classes ['density-comfortable'] -> ['density-compact']` → RED.
- **Boundary catalog:** ☒ invalid — the four priority keys.

### LLR-175.3h — The open project's name is offered, selected
- **Traceability:** HLR-175f · trace: `SaveProjectScreen.on_mount` (`screens.py`); `action_save_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While a project is open, the system shall open the Save project dialog with that project's on-disk name in `#project_name`, all of it selected.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** F-open → the field holds `P`, the selection covers all of it, `#save_where` says `updates the open project`; typing `x` → the field holds `x`; F-fresh → the field is empty (3 of 3).
- **Negative control:** code read on the 9a tree: `on_mount` fills only `#project_parent_path`; the name field starts empty → RED.
- **Boundary catalog:** ☒ boundary — no project open; a project whose on-disk name differs in case from `current_project`.

### LLR-175.3i — The buttons show their keys
- **Traceability:** HLR-175f · trace: `SaveProjectScreen.compose` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The Save project dialog shall label `#save_ok` with `alt+s` and `#save_cancel` with `esc`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** each label holds its key, and each shown key pressed by key performs its button's action (2 of 2; §3 preface "every shown key is verified by pressing it").
- **Negative control:** code read on the 9a tree: the labels are `Save` and `Cancel` → RED.
- **Boundary catalog:** none — two fixed labels.

### LLR-175.3j — Save project with nothing loaded opens no dialog
- **Traceability:** HLR-175f · trace: `action_save_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks Save project while no data file and no A2L is loaded, then the system shall open no dialog and paint `Nothing to save` and `load a data file or A2L first` in the status log.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** a fresh app, `ctrl+s` and the palette entry → stack depth 1, 1 status line with both tokens each, 0 new paths (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2, nothing loaded): `open ctrl+s -> stack: ['Screen', 'SaveProjectScreen']` → RED.
- **Boundary catalog:** ☒ empty — nothing loaded; ☒ boundary — an A2L alone loaded opens the dialog.

### LLR-175.4 — The summary rows are the plan's rows
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW, `app.py`); `SaveProjectScreen` paint method (`screens.py`); `plan_project_save` (LLR-167.6)
- **Ledger:** LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.15, LED-2026-10-26-batch-100.26, LED-2026-10-26-batch-100.31, LED-2026-10-26-batch-100.37, LED-2026-10-26-batch-100.43, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint in `#save_summary` one row per file row of the painted plan, one row per planned sub-folder with its file count and one row for `project.json`, each with its landing name (and its source name when the two differ) and its action word.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:**
  - The 7 scenarios → the painted file rows, folder rows and `project.json` row equal the painted plan's `rows` and `folders` one for one, by landing name and action word (and source name when the two differ), at 220 columns (0 differences, 7 of 7).
  - An AST census of the dialog class and `_save_dialog_preview` → 0 calls to a placement or listing function other than through the one preparation (`predict_placement`, `place_into_workarea`, `os.listdir`, `iterdir`, `list_projects`).
  - The action words painted are only `new`, `keep`, `merge` and `rewrite`; `replace` is not produced (E3 R1).
- **Negative control:** mutation: the painter drops `keep` rows → 1 row missing in the merge scenario → RED. On the 9a tree there is no summary (P11-2) → RED.
- **Boundary catalog:** ☒ boundary — the 7 scenarios; an A2L-only session.

### LLR-175.4a — Save executes the painted plan
- **Traceability:** HLR-175a · trace: `_handle_save_dialog`, `_prepare_project_save` (NEW) (`app.py`); `SaveProjectScreen` save action (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Save project dialog closes with a payload, the system shall execute the plan the dialog painted, with no file row added, removed or renamed; the active CRC template and the batch and assignment documents are copied outside the plan and are not part of its rows.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** for the 7 scenarios, the plan the handler executes (a spy on the commit step) equals `SaveProjectScreen.plan` read after `alt+s` (dataclass equality, 7 of 7), and the written tree equals that plan by full path and action (0 differences). The document arm: `P` records `patches/changes.json` beside an identical `patches/changes_1.json`; save as `Q` → the painted document row `patches/changes_1.json — keep` equals the tree (base RED: `changes.json new`). The AT-B100-21 oracle excludes the gather homes (the active CRC template and the batch and assignment documents) by name.
- **Negative control:** mutation: the handler re-plans and drops the document row → the spy's plan differs and `patches/changes.json` is written without a painted row → RED.
- **Boundary catalog:** ☒ boundary — the 7 scenarios; the document-keep arm (p11b U3).

### LLR-175.4b — A summary out of date at Save is shown again, not saved
- **Traceability:** HLR-175a · trace: `SaveProjectScreen` save action (`screens.py`); `_prepare_project_save` (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer confirms Save while the plan for the typed name differs from the painted plan, then the system shall keep the Save project dialog open, paint the current plan and paint `the summary changed` and `check it, then save again`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:**
  - `abc` typed and `alt+s` within 50 ms of the last key (before the 150 ms recompute) → 0 dismisses, the token pair painted, the summary now the plan for `abc`; a second `alt+s` → 1 dismiss and 1 folder `abc`.
  - F-merge, `ab` painted, then a test writes `ab/firmware.s19` with other bytes, then `alt+s` → 0 dismisses, the token pair, the image row now `firmware_1.s19` (`new`).
  - 0 new paths before the second press in both arms (2 of 2).
- **Negative control:** mutation: the save action dismisses with the freshly computed plan → arm 1 saves a plan never painted (1 dismiss, 0 token pairs) → RED.
- **Boundary catalog:** ☒ boundary — a pending recompute; a folder changed between paint and Save.

### LLR-175.4c — The image line says emit or copy
- **Traceability:** HLR-175 · trace: `_plan_project_save` (`SavePlan.image`), `_save_dialog_preview` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint the painted plan's image description in `#save_summary`: the source plus N change entries with K applied by this save, or an unchanged copy.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** F-pending (1 entry applied, 0 not applied) → `firmware.s19 + 1 change entry, 0 applied by this save`; F-document (1 pasted entry, not applied) → `+ 1 change entry, 1 applied by this save`; F-fresh → `firmware.s19 unchanged copy` (3 of 3).
- **Negative control:** mutation: the description built from `image_differs_from_source` alone → F-document (image unchanged, 1 entry) says `unchanged copy` → RED.
- **Boundary catalog:** ☒ boundary — applied, not applied, none; an A2L-only session (no image line).

### LLR-175.4d — The pending line marks unsaved changes
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW); `ChangeService.differs_from_last_saved` (B100-I18)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While the session image differs from the copy last loaded or saved, the system shall paint one line holding `unsaved changes` and the image's name in `#save_summary`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** F-pending → 1 line; the same session after a Save project → 0 lines; F-fresh → 0 lines; patched, saved, patched again → 1 line (4 of 4).
- **Negative control:** mutation: the line keyed on `image_differs_from_source` → after a Save project the journal still shows the patch, so the line is painted → RED.
- **Boundary catalog:** ☒ boundary — saved then patched again; a patch that writes the bytes already there (0 lines).

### LLR-175.4e — Skipped links get one row
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW); `SavePlan.skipped_links`
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the painted plan skips links or junctions, the system shall paint one row holding `links or junctions not copied` and the first 10 of their paths, followed by `and K more` when there are more.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** a save as of P holding 1 directory junction → 1 row naming it; 12 junctions → 1 row naming 10 and `and 2 more` (2 of 2; Windows-only arms, counted).
- **Negative control:** mutation: the links row omitted → 0 rows → RED.
- **Boundary catalog:** ☒ boundary — 10 / 11 / 12 links (`PAINTED_NAME_LIMIT`).

### LLR-175.4f — A merge names the active variant it sets
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW; the target's recorded `active_variant` read in the preparation, the image row's landing)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the painted plan's target is a merge with an image row, the system shall paint one row holding `active variant`, the variant the save makes active and the variant the target recorded before.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** F-merge where `ab` records `firmware` and the image lands as `firmware_1.s19` → 1 row naming `firmware_1` and `firmware`; after `alt+s`, `ab/project.json` records `active_variant == "firmware_1"` (2 of 2); a merge whose target records no active variant → 1 row naming `none recorded` (1).
- **Negative control:** mutation: the row omitted → 0 rows → RED; mutation: the row names the first variant by name → the after-save equality fails → RED.
- **Boundary catalog:** ☒ boundary — the same variant stays active; no record; a damaged manifest (`none recorded`).

### LLR-175.4g — Names in the dialog are painted literally
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW; `painted_names`), the dialog's widgets with markup off (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint every name read from disk or typed by the engineer in the Save project dialog literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** a loaded file named `[b]x.s19`, a sub-folder file `flows/[i]f.json`, a typed name `[red]a` (sanitised `reda`) and a disguised clash with a project `[b]P` → the plain text of each painted line holds the name exactly as `painted_names` returns it, with 0 markup spans; a name holding U+202E → the character absent from the painted text (5 of 5).
- **Negative control:** mutation: the summary widget with markup on → `[b]x.s19` paints `x.s19` in bold → RED. On the 9a tree there is no summary (P11-2) → RED.
- **Boundary catalog:** ☒ invalid — markup brackets, U+202E, a name of 130 characters (clipped to 120 ending in `…`).

### LLR-175.4h — Save and Cancel stay visible under a long summary
- **Traceability:** HLR-175f · trace: the dialog's layout rules (`styles.tcss`); `SaveProjectScreen.compose` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While the summary holds more rows than its region shows, the system shall keep `#save_ok` and `#save_cancel` inside the visible screen region.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** a save-as plan of 300 rows (TC builder) at 118×54 and at 220×60 → both buttons' regions inside the screen and of height ≥ 1 (2 of 2).
- **Negative control:** mutation: `#save_summary` with `height: auto` and no scroll → the buttons are pushed below the screen → RED.
- **Boundary catalog:** ☒ boundary — 300 rows; 1 row.

### LLR-175.4i — The last summary row is reachable by keyboard
- **Traceability:** HLR-175f · trace: `#save_summary` (focusable scroll region, `screens.py`); the focus order
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall let the engineer scroll `#save_summary` to its last row with the keyboard alone.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** the 300-row plan at 118×54: `tab` from `#project_name` gives the focus to `#save_summary`, then `end` → the last row's region is visible (1 of 1); `tab` order `#project_name` → `#save_summary` → `#save_ok` → `#save_cancel` → `#project_name` and the reverse with `shift+tab` (2 of 2).
- **Negative control:** mutation: `#save_summary` not focusable → `tab` skips it and `end` stays in the name field → RED.
- **Boundary catalog:** ☒ boundary — 300 rows; the focus order with and without assignment rows (ruling Q4).

### LLR-175.4j — A summary row never wraps
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW); `#save_summary` rules (`styles.tcss`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint each summary row on one line, a cut row ending with `…`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** the save-as scenario with a 120-character sub-folder file name at 118×54 → each row's region has height 1 and the cut row's text ends with `…` (all rows; 1 assertion per row).
- **Negative control:** mutation: the summary rows allowed to wrap → the long row takes 2 lines → RED.
- **Boundary catalog:** ☒ boundary — 118 and 220 columns.

### LLR-175.4k — The painted plan is exposed read-only
- **Traceability:** HLR-175a · trace: `SaveProjectScreen.plan` (NEW, read-only property, `screens.py`); `SavePlan` (frozen, `project_gather_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.31, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall expose the painted plan as `SaveProjectScreen.plan`, an immutable value.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** assigning `plan.rows`, assigning `screen.plan` and appending to `plan.rows` → 3 errors (`FrozenInstanceError`, `AttributeError`, `AttributeError` on a tuple) (3 of 3); `plan` is `None` while no plan is painted (1).
- **Negative control:** mutation: `plan` returns a mutable copy built from lists → the append succeeds → RED.
- **Boundary catalog:** ☒ boundary — before the first paint; after a refusal (`plan` is the refused plan, 0 rows).

### LLR-175.4l — A payload built without the dialog is saved through the same preparation
- **Traceability:** HLR-175a · trace: `_handle_save_dialog`, `_prepare_project_save` (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When `_handle_save_dialog` receives a payload the Save project dialog did not prepare, the system shall prepare the plan for that payload's name and execute it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`, plus the 58 direct calls in 11 test files (§5.4)
- **Numeric pass threshold:** the same name through the dialog and through a direct `SaveProjectPayload` call on a twin fixture → equal written trees and equal session digests (1 of 1); the 58 direct calls in 11 test files pass unchanged (0 new failures against the gate baseline).
- **Negative control:** mutation: the handler requires a dialog-prepared plan → every direct call refuses → RED.
- **Boundary catalog:** ☒ boundary — a payload whose parent is not the work area (LLR-171.3 still refuses).

### LLR-175.5 — The session's image decision and digests are computed once per open
- **Traceability:** HLR-175 · trace: `_save_session_inputs` (NEW), `action_save_project` (`app.py`); `_decide_project_image`, `_file_digest`
- **Ledger:** LED-2026-10-26-batch-100.26, LED-2026-10-26-batch-100.43, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Save project dialog opens, the system shall compute the image decision and the digests of the session's files once.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:**
  - F-case06: 1 dialog open and 20 keystrokes of a new name → 1 call to `_decide_project_image` and 1 `_file_digest` call per session file (image, MAC, A2L), 0 more during the keystrokes and 0 more at `alt+s` (spies).
  - F-case06: the summary painted within 2 s of `ctrl+s` on the Windows development host; the measured time is recorded in the packet (C-QA-5). P11-1 measured the A2L digest at 26.1 ms (best of 5).
- **Negative control:** mutation: the decision and digests recomputed with the plan → 20 keystrokes give ≥ 2 decisions → RED.
- **Boundary catalog:** ☒ boundary — the case_06 project; an A2L-only session (no decision).

### LLR-175.5a — The plan is recomputed at most once per 150 ms of typing
- **Traceability:** HLR-175 · trace: `SaveProjectScreen` name-change handler and its timer (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the name in the Save project dialog changes, the system shall recompute the plan no sooner than 150 ms after the previous recomputation and once after the last change.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** 20 keystrokes 10 ms apart → ≤ 3 recomputations, each keystroke echoed in `#project_name` within one frame, and the plan for the final name painted within 300 ms of the last keystroke (3 assertions). A 4 MiB emitting image (any applied entry): each recompute echoes the keystroke within one frame and the final paint ≤ 300 ms — the `emitted_record` is computed once per open, not per recompute (1 of 1).
- **Negative control:** mutation: a recomputation per keystroke → 20 recomputations → RED; mutation: no trailing recomputation → the final name's plan is never painted → RED.
- **Boundary catalog:** ☒ boundary — one keystroke; a burst; a pause longer than 150 ms between two bursts.

### LLR-175.5b — The dialog appears before the session is computed
- **Traceability:** HLR-175f · trace: `action_save_project`, `_save_session_inputs` (NEW) (`app.py`); `SaveProjectScreen.on_mount` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.26, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer asks Save project, the system shall render the dialog's first frame before it computes the image decision.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** a spy on `_decide_project_image` records, at its first call, that `app.screen` is a mounted `SaveProjectScreen` that has completed 1 refresh (1 of 1).
- **Negative control:** mutation: the decision computed in `action_save_project` before `push_screen` → at the first call the screen is the main screen → RED.
- **Boundary catalog:** ☒ boundary — F-case06 with 1 entry; a 4 MiB patched image (P11-4: render 1 215 ms).

### LLR-175.6 — One preparation decides what the dialog shows and what the save does
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW), its two callers (`_save_dialog_preview`, `_handle_save_dialog`) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall decide the Save project dialog's refusal and plan and the save's refusal and plan for a name with one function.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:**
  - An AST census of `app.py` → `sanitize_project_name`, `is_windows_device_name`, the reserved-home comparison, `PROJECT_NAME_MAX_CHARS`, `_project_folder_refusal` (target) and `_plan_project_save` are reached by Save project only inside `_prepare_project_save` (0 other Save-path call sites).
  - 16 names (the 15 refusal arms with a fixture each, plus a valid one) → the dialog's painted token pair equals the token pair a direct `_handle_save_dialog` call paints in the status log, per name (16 of 16).
- **Negative control:** mutation: the dialog side keeps its own copy of the rules without case-folding → `Reports` paints no pair in the dialog while the direct call refuses → RED.
- **Boundary catalog:** ☒ invalid — every refusal arm.

---

## §C — Index, token, census and IFC edits

### C.1 — §5.3 TC index (TC arm | Written at | Extended at)

| TC arm | Written at | Extended at |
|---|---|---|
| TC-B100-47 (LLR-175.1, LLR-175.1a, LLR-175.1b, LLR-175.1c, LLR-175.1d, LLR-175.1e, LLR-175.1f, LLR-175.1g, LLR-175.1h, LLR-175.1i, LLR-175.1j, LLR-175.1k, LLR-175.1l, LLR-175.1m, LLR-175.1o, LLR-175.1p, LLR-175.6) | Inc 11: the target line, the 15 refusals in the dialog, the one preparation | — |
| TC-B100-48 (LLR-175.2, LLR-175.2a) | Inc 11 | — |
| TC-B100-49 (LLR-175.3, LLR-175.3a, LLR-175.3b, LLR-175.3c, LLR-175.3d, LLR-175.3e, LLR-175.3f, LLR-175.3g, LLR-175.3h, LLR-175.3i, LLR-175.3j) | Inc 11: keys, focus, empty Save, Save during a refusal, the priority keys, the prefill, the labels, nothing loaded | — |
| TC-B100-65 (LLR-175.4, LLR-175.4a, LLR-175.4b, LLR-175.4c, LLR-175.4d, LLR-175.4e, LLR-175.4f, LLR-175.4g, LLR-175.4h, LLR-175.4i, LLR-175.4j, LLR-175.4k, LLR-175.4l, LLR-175.5, LLR-175.5a, LLR-175.5b) | Inc 11: rows = plan, executed = painted, the out-of-date summary, the image, pending, links and merge rows, literal names, layout, the plan accessor, the direct payload, the once-per-open cost, the 150 ms recompute, the first frame | — |
| TC-B100-66 (LLR-173.7) | Inc 9b | Inc 11: the Save dialog in 6 scenarios (fresh, open project, merge, save as, a refusal, an empty Save) → 0 decision ids |

### C.2 — §5.3 AT index rows

- AT-B100-02: `Inc 2 | Inc 11 (alt+s; no parent field)` → `Inc 2 | Inc 11 (alt+s; no parent field; the refusals read in #save_where with the dialog open — ruling Q5)`.
- AT-B100-09: `Inc 8b | Inc 9b, Inc 11` → `Inc 8b | Inc 9b, Inc 11 (alt+s; the summary lists flows/, patches/, reports/ before Save)`.
- AT-B100-16: `Inc 11 | —` → `Inc 11 (open, folder, clash, escape and empty halves; HLR-175, HLR-175b, HLR-175c, HLR-175d, HLR-175f) | —`.
- AT-B100-21: `Inc 11 (fresh, pending patch, refused, files, document, merge, save-as)` — unchanged; its owners become HLR-175 (painted half) and HLR-175a (executed half). HLR-175's old threshold said "5 scenarios"; the index's 7 governs.

### C.3 — §3 preface token table

- Row `blocked document entry | blocked entries | fix or remove them in the Patch Editor` → `blocked document entry (Inc 5; painted in the Save dialog from Inc 11, LLR-175.1m) | blocked entry / blocked entries | fix them in the Patch Editor` (ruling Q11: the table follows the shipped text, `test_b100_save_image.py:733`, `:1391`).
- New row: `the Save summary is out of date at Save (Inc 11, LLR-175.4b) | the summary changed | check it, then save again`.
- New row: `Save project with nothing loaded (Inc 11, LLR-175.3j) | Nothing to save | load a data file or A2L first` (today's text, now a token row).
- New row: `a session file is missing at save (LLR-155.4; in the Save dialog from Inc 11, LLR-175.1k) | source file missing + the file | reload it or remove it from the project` (today's text, now a token row).
- New row: `a session file cannot be read at save (LLR-164.4; Inc 11, LLR-175.1l) | could not be read + the file | check that the file can be opened, then save again` (ruling Q11: the next step is appended; "Nothing written." stays, so the 9 existing assertions on it hold).
- Row removed: `a patched image of a kind with no emitter (Inc 5; Inc 11, LLR-175.1n) | cannot be written | remove the change entries in the Patch Editor` — LLR-175.1n is withdrawn (E2-rulings, Q11); the arm is unreachable, so no token row is added.
- Rows `reserved home`, `Windows device name`, `disguised clash`, `name over 64`, `full path over the limit`, `empty name`, `Save target is a link or junction`, `Load or Save target … cannot be inspected`, `second MAC`, `second A2L`, `too large to copy`, `save as: … too many files`, `save-as larger than the free space`: add `painted in the Save dialog before Save (Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p)`.
- Informational phrases (not refusals; matched by tests): `new folder`, `updates the open project`, `merges into an existing project` (LLR-175.1), `unsaved changes` (LLR-175.4d), `active variant` (LLR-175.4f), `links or junctions not copied` (LLR-175.4e, the LLR-171.1c phrase).

### C.4 — §5.4 reverse census (to re-take at E2 on the tree after Inc 10)

- `#project_parent_path` (Inc 11, D7): the row stands; re-pin `test_b99_staging.py` (6 nodes), `test_tui_directionb.py:3090`; `test_loadfilescreen_input.py:898` is docstring text only.
- New row: `SaveProjectScreen` (Inc 11) | 11 test files reference it (`test_b100_active_variant.py`, `test_b100_document.py`, `test_b100_project_check.py`, `test_b100_project_homes.py`, `test_b100_save_guards.py`, `test_b100_save_image.py`, `test_b100_session_reset.py`, `test_b99_staging.py`, `test_loadfilescreen_input.py`, `test_tui_directionb.py`, `test_tui_manifest_save.py`) | drives that click `#save_ok` and wait for the dialog to close keep working for a valid name once the summary is painted (LLR-175.3c); drives that save a refused name and read the status log re-pin to `#save_where` with the dialog open (ruling Q5); drives that save immediately after typing wait for the summary first (LLR-175.4b).
- New row: `_handle_save_dialog(SaveProjectPayload(...))` direct calls (Inc 11) | 58 calls in 11 files (`support/b100_projects.py` 2, `test_b100_active_variant.py` 2, `test_b100_project_homes.py` 2, `test_b100_save_guards.py` 38, `test_b100_save_image.py` 3, `test_project_gather.py` 1, `test_tui_app.py` 1, `test_tui_evidence_packs.py` 1, `test_tui_manifest_save.py` 4, `test_tui_report_seam.py` 1, `test_tui_variants.py` 1) | unchanged (LLR-175.4l).
- New row: `#assign_batch` / `#assign_<n>` (Inc 11) | `test_tui_manifest_save.py` (3 nodes) | kept (ruling Q4); the focus order gains them between `#save_summary` and `#save_ok`.
- Snapshot cells (Inc 11): the census of SVG snapshots that hold the Save dialog is owed at E2; a first grep found none holding "Save project folder under".

### C.4b — §4 IFC edits

- FLOW `typed_name_to_save_dialog`: node LLR-175.1 `in : typed name + projects + image differs` → `in : typed name + the one preparation (LLR-175.6)`; node LLR-175.3 `in : escape, an empty Save` → `in : escape, Cancel, alt+s / Save / enter, an empty Save, the priority keys`; node LLR-175.4 `in : SavePlan` → `in : the painted SavePlan; out : #save_summary rows; the same plan executed (LLR-175.4a)`.
- COMPONENT `save_project_dialog`: `INPUTS : project_name: str ; work_area: Path ; image_differs: bool ; projects: list[str]` → `INPUTS : project_name: str ; preview: Callable[[str], SavePreview] (app side, painted plain text) ; initial_name: Optional[str]`; output `save_payload` unchanged, with the work area as `parent_folder` (LLR-175.2a).

---

## §D — Ledger entry (number assigned at merge)

### LED-2026-10-26-batch-100.NN — Inc 11 E1 — requirements to strict EARS / ISO 29148
- **Requirement:** HLR-175, HLR-175a, HLR-175b, HLR-175c, HLR-175d, HLR-175e, HLR-175f, LLR-175.1, LLR-175.1a, LLR-175.1b, LLR-175.1c, LLR-175.1d, LLR-175.1e, LLR-175.1f, LLR-175.1g, LLR-175.1h, LLR-175.1i, LLR-175.1j, LLR-175.1k, LLR-175.1l, LLR-175.1m, LLR-175.1o, LLR-175.1p, LLR-175.2, LLR-175.2a, LLR-175.3, LLR-175.3a, LLR-175.3b, LLR-175.3c, LLR-175.3d, LLR-175.3e, LLR-175.3f, LLR-175.3g, LLR-175.3h, LLR-175.3i, LLR-175.3j, LLR-175.4, LLR-175.4a, LLR-175.4b, LLR-175.4c, LLR-175.4d, LLR-175.4e, LLR-175.4f, LLR-175.4g, LLR-175.4h, LLR-175.4i, LLR-175.4j, LLR-175.4k, LLR-175.4l, LLR-175.5, LLR-175.5a, LLR-175.5b, LLR-175.6. New in this entry: HLR-175a, HLR-175b, HLR-175c, HLR-175d, HLR-175e, HLR-175f, and every suffixed LLR-175 id above, plus LLR-175.5, LLR-175.5a, LLR-175.5b and LLR-175.6. Also: §3 refusal-token table (1 row amended, 5 rows added, 13 rows annotated); §5.3 TC index (4 rows added, 1 row extended) and AT index (3 rows changed); §5.4 reverse census (3 rows added, 1 row noted); §4 IFC (1 FLOW, 1 COMPONENT edited). E3 design-fix: LLR-175.1n is retired (E2-rulings, Q11); LLR-175.1o and LLR-175.1p are added.
- **Pairing note:** a requirement split here lists on its Ledger line only this entry, plus the history of the clause it took over. The history before the split stays on its parent's Ledger line: HLR-175 (.1, .2, .4, .15, .31, .37), LLR-175.1 (.5), LLR-175.2 (.1), LLR-175.3 (.10), LLR-175.4 (.4, .15, .26, .31, .37, .43).
- **Date:** 2026-10-31
- **What changed:** each Inc 11 requirement was rewritten to the operator's strict standard, as in LED .76, .82 and the Inc 9b E1. That means one EARS sentence in one of the five forms, one "shall", every failure path its own unwanted-behaviour requirement, and a numeric pass threshold and a negative control each, checked against ISO/IEC/IEEE 29148. Function names moved from the statements to the trace. Existing ids are kept; a split keeps the id for the first part and adds a suffix; nothing is renumbered or deleted. Negative controls are executed probes where one exists (P-18, P-19 on `1d677ba`; P11-1 … P11-4 on the 9a tree, `inc-11-design/work/`), code reads on the 9a tree otherwise, each named. Per id:
  - **HLR-175:** 1 statement with about 20 behaviours and 11 "shall"s → state "while the dialog is open, paint the plan for the typed name in `#save_summary`, with the target and kind in `#save_where`". The "5 scenarios" of its threshold follow the AT index's 7.
  - **HLR-175a (new, split from HLR-175):** event "confirming Save writes exactly the painted plan" (R-PC; AT-B100-21's executed half).
  - **HLR-175b (new, split from HLR-175):** unwanted "a refused name is painted before Save" (O-9, M-4). It covers the HLR-164 name rules and the save refusals the handler made only after the dialog closed.
  - **HLR-175c, HLR-175d (new, split from HLR-175):** `escape` closes and saves nothing (CW-U-12); an empty Save is explained (CW-U-13).
  - **HLR-175e (new, split from HLR-175):** ubiquitous "the dialog saves only into this work area" (D7, dialog half).
  - **HLR-175f (new):** event "Save project opens one dialog with the five `pc_B` ids"; it holds the opening, the keys and the layout, as HLR-173 does for the Load dialog.
  - **LLR-175.1:** 1 statement over the folder line and 5 refusal kinds → event "the target line names the sanitised folder and its kind". Kind words named: `new folder`, `updates the open project`, `merges into an existing project`, `new project in an existing folder` (A11-17).
  - **LLR-175.1a, LLR-175.1b, LLR-175.1c, LLR-175.1d, LLR-175.1e (new):** one unwanted requirement per HLR-164 name rule, each with its token pair.
  - **LLR-175.1f, LLR-175.1g, LLR-175.1h (new):** the link target, the unreadable target and the name with no usable character. These failure paths had no dialog requirement.
  - **LLR-175.1i, LLR-175.1j (new):** a plan refusal (second MAC, second A2L, the save-as ceilings) and too little free space are painted before Save. Before, they reached the engineer only after the dialog closed.
  - **LLR-175.1k, LLR-175.1l, LLR-175.1m (new):** the session refusals (missing source, unreadable source, blocked entries). LLR-175.1l adds a next step the shipped text lacks; LLR-175.1m follows the shipped wording and amends the table row (ruling Q11). LLR-175.1n is retired here (E2-rulings, Q11: unreachable).
  - **LLR-175.1o (new, E3 design-fix, ruling P-5):** unwanted "a work area that cannot be listed is refused in the dialog" (F-1).
  - **LLR-175.1p (new, E3 design-fix, ruling S11-01):** unwanted "a case-folded match that is not the open project is a disguised clash" — the open project is decided by file identity, not by case-folding. E3 r2 design-fix (R2-03): the statement gains LLR-175.1c's two clauses — the folder is a project, and the typed name differs from that folder name — so an exact-name merge (`ab` typed with project `ab` not open) is not refused.
  - **LLR-175.2:** "no widget, and the payload's parent is the work area" → two requirements: LLR-175.2 (ubiquitous, no widget) and LLR-175.2a (new, event, the payload's parent).
  - **LLR-175.3:** 6 behaviours → LLR-175.3 (`escape`), and new LLR-175.3a (Cancel), LLR-175.3b (empty Save), LLR-175.3c (confirm saves; `enter` added by ruling Q8), LLR-175.3d (focus), LLR-175.3e (plain letters), LLR-175.3f (Save during a refusal, VS-PC-2).
  - **LLR-175.3g (new):** unwanted "the four priority keys are inert while the dialog is open". Inc 9b's ruling Q6 routed this exposure here; the 9a-tree probe shows `ctrl+l` and `ctrl+s` stacking a second modal and `ctrl+d` changing the hidden screen's density.
  - **LLR-175.3h (new):** state "with a project open, the dialog offers its name, selected" (the `pc_B` behaviour; ruling Q7).
  - **LLR-175.3i (new):** the buttons show `alt+s` and `esc`, each verified by pressing it.
  - **LLR-175.3j (new):** unwanted "Save project with nothing loaded opens no dialog" (ruling Q9). Before, the dialog opened and the save was refused only after it closed.
  - **LLR-175.4:** 4 "shall"s and about 12 behaviours → LLR-175.4 (ubiquitous, the rows are the plan's rows) plus new LLR-175.4a (the executed plan equals the painted one), LLR-175.4b (an out-of-date summary at Save is repainted, not saved), LLR-175.4c (image line), LLR-175.4d (pending line), LLR-175.4e (links row), LLR-175.4f (the merge's active-variant row), LLR-175.4g (literal names), LLR-175.4h (buttons visible), LLR-175.4i (keyboard reach), LLR-175.4j (no wrap), LLR-175.4k (the read-only accessor), LLR-175.4l (a direct payload, which keeps 58 test calls working).
    - The worker for the digests, the `computing…` rows and the early-`alt+s` arm (LED .26, .37) are removed (ruling Q1). P11-1 measured the case_06 A2L digest at 26.1 ms; P11-4 measured the payload digest at 4.0 ms for a 4 MiB image, whose render takes 1 215 ms on the main thread in any case (HLR-177 keeps the re-derive there). Removing them also removes a conflict with the operator's P-C note: an early `alt+s` saved landing names the engineer had not seen.
    - "The save then runs on a worker under the status line with real progress" is removed from Inc 11. Save project on a worker and its progress belong to Inc 12a + 12b (HLR-176, HLR-177), whose seam does not exist at Inc 11.
    - "Through `safe_text`" is corrected to the batch's one scrub, `painted_names` with markup off (8b S3R2-4, LLR-172.6), as Inc 9b corrected LLR-173.3.
    - The action word `replace` is dropped from the list: no increment produces it (E3 R1, LLR-167.6).
    - E3 design-fix: LLR-175.4 paints the source name too when a row's landing differs (A11-12); LLR-175.4a gains the p11b U3 document-keep arm and declares the gathered artifacts (active CRC template, batch and assignment documents) outside the plan (A11-04, A11-06).
  - **LLR-175.5, LLR-175.5a, LLR-175.5b (new):** the once-per-open session computation with the 2 s budget (C-QA-5), the 150 ms recompute with a trailing run, and the first frame before the session is computed. LLR-175.5a gains a 4 MiB emitting-image arm (A11-01: the `emitted_record` is computed once per open).
  - **LLR-175.6 (new):** ubiquitous "one function decides the dialog's and the save's refusal and plan". It extends R-PC from the rows to the refusals, so the dialog cannot say "saves" while the handler refuses.
- **Rulings applied:** the text follows the recommendations of `inc-11-design/E1-rulings-proposed.md` Q1 to Q11. A different ruling changes the ids each question names.
