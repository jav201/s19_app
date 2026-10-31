# Inc 9b E1 — replacement requirement blocks (draft, not merged)

Stage E1 of the design-first pipeline (`design-first-increment` skill) for Inc 9b, "the Load dialog" (PLAN.md row 9b: "Load request, D10, CW-U-12/13, markup off"; sources `screens.py`, `app.py`, `styles.tcss`).

**How to merge.**
1. §A replaces the `### HLR-173 — One Load dialog` block in `01-requirements.md` (§3), and inserts the new HLR-173a … HLR-173e blocks right after it.
2. §B replaces the blocks `### LLR-173.1` … `### LLR-173.7` (§4) with the blocks below, in the order given.
3. §C is one new block, LLR-172.1n (CR9-1). Insert it after the last `LLR-172.1*` block. If the 9a corrective pass has taken the suffix `n` by then, give it the next free suffix and rename it in §C, §D and §E. §C also gives the one line that changes in HLR-172's Decomposition.
4. §D holds the TC-index rows (§5.3 "TC arm | Written at | Extended at"), the token-table edits (§3 preface) and the reverse-census edits (§5.4).
5. §E is the ledger entry, numbered `LED .NN`. Every `LED-2026-10-26-batch-100.NN` below takes the number assigned at merge.

**Conventions.**
- Every Statement holds exactly one "shall". No other field uses the word.
- Function names appear only in the trace.
- Line numbers are given only where a line carries the argument. "The 9a tree" means the worktree `s19_app-b100-inc9a` on 2026-10-31: `4fef292` plus 9a's uncommitted changes.
- `screens.py` and `styles.tcss` are byte-identical to `4fef292` there (`git status` lists neither as modified).
- Painted strings are English.
- "Painted literally" means the name goes through `painted_names([name])` (the one category scrub, 8b S3R2-4): every Cc, Cf, Zl and Zp character is removed, an unpaired surrogate becomes U+FFFD, and the result is clipped to 120 characters ending in `…`. It is then painted with markup off through `safe_text`. The app paints. `screens.py` receives the painted text (LLR-173.6l).
- **Session digest** means the tuple (`current_file.path`, SHA-256 of the installed image bytes, `current_project`, `current_a2l_path`, the MAC path), read before and after an action.

---

## §A — HLR blocks (replace HLR-173; insert HLR-173a … HLR-173e after it)

### HLR-173 — One Load dialog lists everything that can be loaded
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.36, LED-2026-10-26-batch-100.40, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer opens Load, the system shall show one dialog that holds a typed-path field, one list of this work area's projects, the work-area files and the recent sources, and a preview pane of the highlighted row.
- **Decomposition:**
  - LLR-173.1, LLR-173.1e, LLR-173.1g: the dialog's one result and its one router.
  - LLR-173.2, LLR-173.2a, LLR-173.2b, LLR-173.2c, LLR-173.2d, LLR-173.2e, LLR-173.2j: opening, focus, keys, clicks.
  - LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.3c, LLR-173.3d: literal names.
  - LLR-173.4, LLR-173.4a, LLR-173.4b, LLR-173.4c, LLR-173.4d, LLR-173.4e, LLR-173.4f, LLR-173.4g, LLR-173.4l, LLR-173.4m: the sections.
  - LLR-173.6d, LLR-173.6f, LLR-173.6k, LLR-173.6l, LLR-173.6m, LLR-173.6n: the preview's content and the layout.
  - LLR-173.7: no internal decision id in the painted text.
  - The compound HLR-173 (about 20 behaviours) is split here into HLR-173 and HLR-173a … HLR-173e (LED .NN).
- **Variant slots (filled by the P-A verdict C, LED-2026-10-26-batch-100.2; corrected by LED-2026-10-26-batch-100.18):**
  - VS-PA-1 = two panes, preview on the right; stacked below 100 columns.
  - VS-PA-2 = a click selects; Enter loads; a double-click is not bound.
  - VS-PA-3 = the `pa_C` ids (`#load_dialog`, `#load_list`, `#load_path`, `#load_preview`, `#load_reason`, `#load_ok`, `#load_cancel`); `#project_list` and the separate Load project dialog retire.
  - VS-PA-4 = `l` and `ctrl+l` open this dialog with the focus on the path field; `p` opens it with the focus on `#load_list` and the open project's row highlighted, else the first project.
  - VS-PA-5 = the preview marks the active set with `●` for project, file and work-area rows; a recent row shows its path and kind and "checked when loaded" instead of a mark, because nothing is read before Enter.
  - VS-PA-6 = the focus order of LLR-173.2c.
- **Rationale (informative):**
  - The dialog has no list, ignores `escape`, and an empty or Enter-only Load does nothing (P-18 … P-20).
  - The operator's P-A note asks for the active-set symbol.
  - Review sources: UX-05 / QA R2-06 (focus), UX-36 (marks for every row kind), UX-37 (`p`), security R2-03 (the preview reads no image and follows no link).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_40 or tc_b100_41 or tc_b100_42 or tc_b100_43 or tc_b100_64 or tc_b100_66 or at_b100_14"`
- **Numeric pass threshold:**
  - The fixture holds 2 projects, a reserved folder, a junction folder, 2 loadable work-area files and 3 recent entries. Opening Load gives 1 dialog on the screen stack, 3 sections in the order projects, work-area files, recent sources, and 2 + 2 + 3 rows.
  - A project named `[b]P` → 1 row whose plain text is `[b]P`, with 0 markup spans.
  - At 99 columns → panes stacked; at 118 → side by side.
- **Negative control:** executed on `1d677ba` (P-20): `dialog has a list/picker widget? none`. `LoadFileScreen` is unchanged at `4fef292` and in the 9a tree (code read) → AT-B100-14's list half is RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, list half) the engineer opens Load. The dialog lists the work area's projects, its loadable work-area files and the recent sources, each in its own section, and a project named `[b]P` is listed exactly as written.
  - **Shipped surface:** the Load dialog (`l`, `ctrl+l`, `p`; `#load_list`, `#load_preview`).
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid
    - empty: no project, no file and no recent (each section paints its tokens);
    - boundary: one item per section; 99 and 100 columns;
    - invalid: hostile names, a hostile store.
  - **Negative control:** executed on `1d677ba` (P-20, above) → AT-B100-14 RED.

### HLR-173a — The preview marks the set a load installs
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall mark with `●`, in the Load dialog's preview, exactly the image variant, MAC and A2L files that loading the highlighted project or work-area file installs.
- **Decomposition:** LLR-173.6, LLR-173.6a, LLR-173.6b, LLR-173.6c, LLR-173.4n.
- **Rationale (informative):** the operator's P-A note ("the symbol for the set that will be used as the active files"); UX-36.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_64 or at_b100_14"`
- **Numeric pass threshold:** 4 projects (clean; after a save-back, so the recorded active variant is not first by name; recorded active variant missing; A2L-only), plus 1 file row with nothing loaded, 1 file row with an A2L loaded, and 1 file row with project P open. After Enter, the image, MAC and A2L paths the Loaded panel names equal the `●` rows (7 of 7).
- **Negative control:** a mutation that marks the first variant by name → the save-back project's `●` differs from the installed variant → RED. On the 9a tree no preview exists (P-20) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, preview half) the engineer highlights a project saved after a save-back. The preview marks `●` on its active image, MAC and A2L, and after Enter the Loaded panel names exactly those three.
  - **Shipped surface:** the Load dialog (`#load_list`, `#load_preview`), the Loaded panel.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ boundary ☒ error
    - boundary: recorded variant missing; A2L-only project; a project open while a file row is highlighted;
    - error: the marked variant is unreadable at install (LLR-173.6a).
  - **Negative control:** as above → AT-B100-14 RED.

### HLR-173b — A recent source reopens from the dialog
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer loads a recent row of the Load dialog, the system shall load the file at that row's recorded path.
- **Decomposition:** LLR-173.1f, LLR-173.4h, LLR-173.4i, LLR-173.4j, LLR-173.4k.
- **Rationale (informative):** the consume half of AT-B100-12's chain (9a recorded the source; 9b reopens it). A recent entry may name a network or removable drive, so nothing touches it before Enter (S-07; §6 "Known gap").
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_40 or tc_b100_43 or at_b100_14"`
- **Numeric pass threshold:** the engineer loads `examples/case_01_basic_valid/firmware.s19` by its absolute path, a new app instance starts with the same `LOCALAPPDATA`, Load opens, and Enter on that recent row → `current_file` holds a work copy whose bytes equal the example's (1 of 1), and the store's first entry is that path.
- **Negative control:** on the 9a tree, `LoadFileScreen` has no list, so no recent row can be picked (P-20, code read) → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, recent half) the engineer loads an example through Load (which records it), restarts the app, opens Load, moves to the recent source and presses Enter: that file loads.
  - **Shipped surface:** the Load dialog (`#load_list`, `#load_reason`), the per-user store, the Loaded panel.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ boundary ☒ error
    - boundary: a recent A2L (routed by kind);
    - error: a recent source missing on pick (`not found`, `check the path`; the entry stays, LLR-173.4k).
  - **Negative control:** as above → AT-B100-14 RED.

### HLR-173c — Enter loads what has the focus
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer asks the Load dialog to load, the system shall load the highlighted row if `#load_list` held the focus more recently than `#load_path`, and the typed path otherwise.
- **Decomposition:** LLR-173.1a, LLR-173.1b, LLR-173.1c, LLR-173.2f, LLR-173.2g.
- **Rationale (informative):** P-19: Enter with a typed path loads nothing today. VS-PA-2: Enter loads and a click only selects. "Asks to load" means `enter`, `alt+l` or `#load_ok`.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_40 or tc_b100_41"`
- **Numeric pass threshold:** each of the three triggers, from list focus on a project, a work-area file and a recent row → 9 loads of the highlighted item; from path focus with a typed valid file path → 3 loads of the typed file (12 of 12).
- **Negative control:** executed on `1d677ba` (P-19): `Enter with a typed path -> current_file before/after: firmware_1.s19 / firmware_1.s19` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, Enter half) the engineer highlights a project and presses Enter: the project loads. They open Load again, type a file path and press Enter: the file loads.
  - **Shipped surface:** the Load dialog (`enter`, `alt+l`, `#load_ok`), the Loaded panel.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ boundary — the focus on the preview or on a button when the request comes (the last of list / path decides).
  - **Negative control:** executed on `1d677ba` (P-19, above) → RED.

### HLR-173d — An empty or refused Load is explained inside the dialog
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load while nothing is highlighted and nothing is typed, or while the typed path is refused, then the system shall keep the dialog open with the typed text unchanged and paint the reason and the next step in `#load_reason`.
- **Decomposition:** LLR-173.2h, LLR-173.2i, LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e.
- **Rationale (informative):** CW-U-13 (P-19: an empty Load says nothing). UX-06: a refused path is explained where it was typed.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_41 or tc_b100_63 or at_b100_14"`
- **Numeric pass threshold:** an empty Load plus the 6 typed refusal reasons → 7 token pairs in `#load_reason`, 0 dismisses, the field text unchanged (7 of 7).
- **Negative control:** executed on `1d677ba` (P-19): `empty Load click -> … new status: [] | new notices: []` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, empty half) an empty Load paints `nothing selected` and `pick a row or type a path`, and the dialog stays.
  - **Shipped surface:** the Load dialog (`#load_reason`, `#load_path`).
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ empty ☒ invalid ☒ error
    - empty: no row and no text; spaces only;
    - invalid: an unsupported suffix, a relative folder, a non-project folder, an outside folder, a link;
    - error: a missing path, an unreadable folder.
  - **Negative control:** executed on `1d677ba` (P-19, above) → RED.

### HLR-173e — `escape` closes the dialog and changes nothing
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `escape` in the Load dialog, the system shall close the dialog and leave the session unchanged.
- **Decomposition:** LLR-173.2k, LLR-173.2l. The focus after the close is LLR-166.1 (TC-B100-12, Inc 9b arms).
- **Rationale (informative):** CW-U-12 (P-18).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_41 or at_b100_14"`
- **Numeric pass threshold:** `escape` with the focus on each of `#load_path`, `#load_list`, `#load_preview` and `#load_ok` → 4 closes, the session digest unchanged and the store bytes unchanged (4 of 4).
- **Negative control:** executed on `1d677ba` (P-18): `escape on LoadFileScreen -> screen: LoadFileScreen` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, escape half) `escape` closes the dialog with the session unchanged.
  - **Shipped surface:** the Load dialog, the screen stack, the Loaded panel.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ boundary — `escape` from each focus position; `escape` after a refused path was painted.
  - **Negative control:** executed on `1d677ba` (P-18, above) → RED.

---

## §B — LLR blocks (replace LLR-173.1 … LLR-173.7)

### LLR-173.1 — The dialog closes with one `LoadChoice`
- **Traceability:** HLR-173 · trace: `LoadChoice` (NEW, B100-I8), the Load dialog class (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.12, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall close the Load dialog with either no result or one `LoadChoice(kind, value)` whose `kind` is one of `project`, `workarea`, `recent` and `path`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:**
  - A load from each section and from the path field → 4 dismiss values, each a `LoadChoice` of the matching kind, `value` the on-disk project name, the on-disk work-area file name, the recorded path text or the typed text respectively (4 of 4).
  - `escape` → `None`.
- **Negative control:** code read, 9a tree: `LoadFileScreen` dismisses with a `Path` and `LoadProjectScreen` with a `str` → no `LoadChoice` → RED.
- **Boundary catalog:** ☒ boundary — each of the four kinds; no result.

### LLR-173.1a — A project choice opens the project through the project route
- **Traceability:** HLR-173c · trace: `_handle_load_dialog`, `_route_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog closes with a `project` choice, the system shall load that project through the route that opens the Load-result panel.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** `LoadChoice("project", "ab")` → `current_project == "ab"` and 1 `LoadResultScreen` on the stack (2 of 2).
- **Negative control:** a mutation that calls `_handle_load_project` directly → 0 Load-result panels → RED.
- **Boundary catalog:** ☒ boundary — a project name in another case than on disk (the listed spelling loads, LLR-172.5g).

### LLR-173.1b — A work-area choice loads that file as the list pick does
- **Traceability:** HLR-173c · trace: `_handle_load_dialog`, `_load_from_item`, `load_selected_file`, `load_a2l_from_path` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog closes with a `workarea` choice, the system shall load the named file of `workarea/temp` as the Workarea Files list's pick of that name loads it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:**
  - `LoadChoice("workarea", "x.s19")` → `current_file.path == <workarea>/temp/x.s19`, 0 calls to `copy_into_workarea` (spy, the data arm only), and the set of names in `temp/` unchanged.
  - `LoadChoice("workarea", "c.a2l")` → the same session digest as a `#files_list` pick of `c.a2l` on a twin fixture, and the set of names in `temp/` unchanged (the copy is an identical-file reuse, G-005) (2 of 2).
- **Negative control:**
  - A mutation that routes the `workarea` data choice through `load_from_path` → 1 `copy_into_workarea` call → RED.
  - Declared: since Inc 1 that copy reuses the identical file (G-005), so the name-set arm alone passes on the mutant; the spy is the RED. The A2L arm keeps the 9a `load_a2l_from_path` route (its `copy_into_workarea`, 256 MB cap and link re-check), so it carries no 0-copy spy (A9b-05).
- **Boundary catalog:** ☒ boundary — a data file and an A2L file.

### LLR-173.1c — A path choice takes the typed-path route
- **Traceability:** HLR-173c · trace: `_handle_load_dialog`, `_load_path_from_user_input`, `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog closes with a `path` choice, the system shall load the typed text through the typed-path route.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** typed `<tmp>/a.s19`, `<tmp>/b.a2l` and `<workarea>/ab` (absolute) → 1 data load, 1 A2L attach and 1 project load of `ab` (3 of 3).
- **Negative control:** a mutation that routes `path` to `load_from_path` → the `<workarea>/ab` arm loads nothing → RED.
- **Boundary catalog:** ☒ boundary — a data file, an A2L file, a project folder.

### LLR-173.1e — One router receives every Load dialog result
- **Traceability:** HLR-173 · trace: `_handle_load_dialog`, `action_load_file`, `action_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall pass every Load dialog result to one app handler.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** AST census of `s19_app/tui/app.py`: every `push_screen` call whose first argument constructs the Load dialog passes `self._handle_load_dialog` as its callback. That gives 2 sites (`action_load_file`, `action_load_project`), 2 of 2, and 0 other callbacks.
- **Negative control:**
  - Code read, 9a tree: `action_load_project` pushes `LoadProjectScreen` with `_route_load_project` → 2 callbacks → RED.
  - A mutation that gives `action_load_project` its own callback → RED.
- **Boundary catalog:** none — a structural census; its set is every push site of the dialog.
- **Note (informative):** the load question (HLR-174) is inserted at Inc 10, through the one seam (LLR-174.4) in this router. Inc 9b adds no question.

### LLR-173.1f — A recent choice loads the recorded path unchanged
- **Traceability:** HLR-173b · trace: `_handle_load_dialog`, `_load_path_from_user_input`, `load_from_path`, `load_a2l_from_path` (`app.py`); `resolve_input_path` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog closes with a `recent` choice, the system shall load the recorded path text, with no change, through the typed-path route.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:**
  - A recent `C:\…\src\fw.s19` → 1 data load, and `fw.s19`'s work copy is installed.
  - A recent `C:\…\src\cal.a2l` → 1 A2L attach.
  - After the data load, that path is the store's first entry (the 9a record, LLR-172.1b).
  - A recent `C:\…\gone\fw.s19` that is missing, while `<base>\fw.s19` exists → 0 loads (a recorded path is drive-rooted, LLR-172.2e, so the relative fallback of `resolve_input_path` never runs).
  - 4 of 4.
- **Negative control:** a mutation that loads the recent by its file name relative to the base folder → the `gone` arm loads `<base>\fw.s19` → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a data and an A2L recent; a missing recent whose name exists under the base folder.

### LLR-173.1g — An unreadable picked project paints one status line and does not crash
- **Traceability:** HLR-173 · trace: `_handle_load_project`, `validate_project_files` (`app.py`, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the picked project cannot be read (`OSError`), then the system shall paint one status line with `could not be read`, keep the session unchanged, and not crash.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** `PermissionError` injected into `validate_project_files` of a listed project, then `enter` → 1 status line holding `could not be read`, 0 raises, the session digest unchanged (1 of 1).
- **Negative control:** a mutation with no catch at `:11743` → the `OSError` leaves the dismiss callback and the app stops → RED.
- **Boundary catalog:** ☒ error — a listed project that cannot be inspected.

### LLR-173.2 — `l` and `ctrl+l` open the dialog on the path field
- **Traceability:** HLR-173 · trace: `action_load_file`, `BINDINGS` (`app.py`); the Load dialog (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.36, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `l` or `ctrl+l` on the main screen, the system shall open the Load dialog with the focus on `#load_path`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `l` → the dialog open and `focused.id == "load_path"`; `ctrl+l` → the same (2 of 2); `#load_list` exists in that dialog (1).
- **Negative control:**
  - Code read, 9a tree: `LoadFileScreen` has no `#load_list` (P-20) → RED.
  - A mutation that opens every Load on `#load_list` → the `l` arm RED.
- **Boundary catalog:** ☒ boundary — both keys.

### LLR-173.2a — `p` opens the dialog on the list
- **Traceability:** HLR-173 · trace: `action_load_project`, `on_button_pressed` (`#ws_load_project_button`) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `p` on the main screen or activates `#ws_load_project_button`, the system shall open the Load dialog with the focus on `#load_list`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `p` → `focused.id == "load_list"`; the button → the same; `p` in a work area with 0 projects → the dialog opens and the projects section paints `no projects` (3 of 3).
- **Negative control:**
  - Code read, 9a tree: `action_load_project` pushes `LoadProjectScreen` (`#project_list`), and with 0 projects it paints `No saved projects found.` and opens nothing → RED.
  - A mutation that opens the `p` dialog on `#load_path` → `p`, then `enter`, loads nothing → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — 0 projects; the key and the button.

### LLR-173.2b — The list opens on the open project
- **Traceability:** HLR-173 · trace: the Load dialog `on_mount` (`screens.py`); `current_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog opens with the focus on `#load_list`, the system shall highlight the open project's row, or the first project row when no project is open.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:**
  - Projects `A`, `P`, `Z` with `P` open, then `p` → `P`'s row highlighted.
  - No project open → `A`'s row highlighted.
  - 0 projects and 1 work-area file → the file's row highlighted (3 of 3).
- **Negative control:** a mutation that always highlights row 0 → the `P` arm highlights `A` → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — no project open; 0 projects.

### LLR-173.2c — `tab` order
- **Traceability:** HLR-173 · trace: the Load dialog compose order and focus chain (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `tab` in the Load dialog, the system shall move the focus along `#load_path`, `#load_list`, `#load_preview`, `#load_ok`, `#load_cancel` and back to `#load_path`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** from `#load_path`, 5 `tab` presses → the focused ids in that order, ending on `#load_path` (5 of 5); `shift+tab` → the reverse order (5 of 5).
- **Negative control:** a mutation that leaves `#load_preview` unfocusable → the third press lands on `#load_ok` → RED.
- **Boundary catalog:** ☒ boundary — the wrap from `#load_cancel` to `#load_path`.

### LLR-173.2d — A printable key in the list types into the path field
- **Traceability:** HLR-173 · trace: the Load dialog `on_key` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer types a printable character while `#load_list` has the focus, the system shall move the focus to `#load_path` and append that character to its text.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:**
  - Each of `p`, `l`, `q`, `s`, `r` and `?` pressed with the list focused and the field empty → `#load_path` holds that one character and has the focus.
  - The screen stack depth is unchanged and 0 app actions run (a spy on `S19TuiApp.run_action`) (6 of 6).
  - `up`, `down`, `enter` and `tab` → not redirected (4 of 4).
- **Negative control:**
  - A mutation with no key redirect → `p` leaves `#load_path` empty → RED.
  - Declared: under Textual 8.2.8 a modal screen already stops the app's non-priority bindings (`Screen._modal_binding_chain`, `textual/screen.py:449-455`), so the "0 app actions" arm passes without the redirect; the field arm is the RED.
- **Boundary catalog:** ☒ boundary — printable keys that are app bindings on the main screen; non-printable navigation keys.

### LLR-173.2e — App priority keys are inert while the dialog is open
- **Traceability:** HLR-173 · trace: `BINDINGS` (`priority=True` entries), `check_action` or the four actions (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer presses `ctrl+l`, `ctrl+s`, `ctrl+k` or `ctrl+d` while the Load dialog is open, then the system shall run no app action for that key.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** each of the 4 keys pressed with the dialog open → the screen stack stays the main screen plus the Load dialog (depth 2), the focus is inside the dialog, and the density and palette are unchanged (4 of 4); `ctrl+p` over the dialog (the command palette opens over it), then `ctrl+s` and `ctrl+l` → 0 Save pushes and 0 second dialogs (the guard reads the whole screen stack, S9b-1) (2 of 2).
- **Negative control:** code read on Textual 8.2.8 and the 9a tree. `App._check_bindings(priority=True)` walks `reversed(self.screen._binding_chain)`, App included (`textual/app.py:3978-3981`), and the four bindings are `priority=True` (`BINDINGS` in `app.py`). So `ctrl+l` pushes a second Load dialog and `ctrl+s` pushes the Save dialog over it → RED. Status: `executed` (the S9b-1 probe: after `ctrl+l`, `ctrl+p` then `ctrl+s` stacks `Save` under the old stack-top guard → RED; the whole-stack guard keeps the stack `['Screen','Dlg','CommandPalette']`).
- **Boundary catalog:** ☒ invalid — the four priority keys, and `ctrl+p` over the dialog.

### LLR-173.2f — A load asked with the list last loads the highlighted row
- **Traceability:** HLR-173c · trace: the Load dialog `action_load`, `on_button_pressed`, focus tracking (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `enter` or `alt+l`, or activates `#load_ok`, while `#load_list` held the focus more recently than `#load_path`, the system shall close the Load dialog with the highlighted row's choice.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:**
  - The 3 triggers × a project, a work-area file and a recent row highlighted → 9 dismisses with the matching `LoadChoice` (9 of 9).
  - Text in `#load_path`, then `tab` into the list, then `enter` → the row's choice (1).
- **Negative control:** a mutation that always takes the typed text → the list arms dismiss with `path` → RED.
- **Boundary catalog:** ☒ boundary — text present in the field while the list was last.

### LLR-173.2g — A load asked with the path field last loads the typed text
- **Traceability:** HLR-173c · trace: the Load dialog `action_load`, `on_input_submitted` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `enter` or `alt+l`, or activates `#load_ok`, while `#load_path` held the focus more recently than `#load_list` and holds a path the typed-path route accepts, the system shall close the Load dialog with a `path` choice of that text.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** a valid typed file path with a row highlighted → the 3 triggers give 3 `path` choices of the text (3 of 3).
- **Negative control:** a mutation that always takes the highlighted row → `path` arms dismiss with the row → RED.
- **Boundary catalog:** ☒ boundary — a row highlighted while the field was last.

### LLR-173.2h — An empty typed text is explained
- **Traceability:** HLR-173d · trace: the Load dialog `action_load` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a load is asked while `#load_path` held the focus more recently than `#load_list` and its text is empty or only spaces, then the system shall keep the Load dialog open and paint `nothing selected` and `pick a row or type a path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `""` and `"   "` → 2 token pairs, 0 dismisses, the field text unchanged (2 of 2).
- **Negative control:** executed on `1d677ba` (P-19): an empty Load gives no status and no notice → RED.
- **Boundary catalog:** ☒ empty — no text; spaces only.

### LLR-173.2i — A load with no highlighted row is explained
- **Traceability:** HLR-173d · trace: the Load dialog `action_load` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a load is asked while `#load_list` held the focus more recently than `#load_path` and no loadable row is highlighted, then the system shall keep the Load dialog open and paint `nothing selected` and `pick a row or type a path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:**
  - An empty work area, an empty temp folder and no store → `p`, then `enter` → 1 token pair, 0 dismisses.
  - A section heading or an empty-section token line highlighted → 1 token pair, 0 dismisses (2 of 2).
- **Negative control:** a mutation that dismisses with the heading row's text → 1 dismiss → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — every section empty; a heading highlighted.

### LLR-173.2j — A click selects and never loads
- **Traceability:** HLR-173 · trace: the Load dialog list message handlers (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer clicks a row of `#load_list`, the system shall highlight that row and keep the Load dialog open.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** 1 click on the second project row → that row highlighted, 0 dismisses; 2 clicks within 300 ms (a double-click) → 0 dismisses (2 of 2).
- **Negative control:** a dialog that loads on the list's selected message → 1 dismiss on the first click → RED. Textual 8.2.8 posts the same `Selected` message for a click as for `enter` (`textual/widgets/_option_list.py:721-730`), so the dialog cannot load on that message.
- **Boundary catalog:** ☒ boundary — a single and a double click.

### LLR-173.2k — `escape` closes with no result
- **Traceability:** HLR-173e · trace: the Load dialog `BINDINGS` / `action_cancel` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer presses `escape` in the Load dialog, the system shall close it with no result.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `escape` from `#load_path`, `#load_list`, `#load_preview` and `#load_ok` → 4 dismisses with `None`, the session digest unchanged and the store bytes unchanged (4 of 4).
- **Negative control:** executed on `1d677ba` (P-18): `escape on LoadFileScreen -> screen: LoadFileScreen` → RED.
- **Boundary catalog:** ☒ boundary — each focus position.

### LLR-173.2l — `#load_cancel` closes with no result
- **Traceability:** HLR-173e · trace: the Load dialog `on_button_pressed` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer activates `#load_cancel`, the system shall close the Load dialog with no result.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** a click and `enter` on `#load_cancel` → 2 dismisses with `None`, the session digest unchanged (2 of 2).
- **Negative control:** a mutation that maps `#load_cancel` to the load action → the empty-Load tokens and 0 dismisses → RED.
- **Boundary catalog:** ☒ boundary — click and key activation.

### LLR-173.3 — Project rows are painted literally (C8)
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); `painted_names` (`project_gather_service.py`); `safe_text` (`utils.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint each project row of the Load dialog literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** projects named `[b]P`, `[@click=app.bell]Q`, `x` + U+202E + `R` and `a` + U+009B + `S` → 4 rows whose plain text equals the name with the Cc / Cf characters removed, 0 spans, 0 characters of category Cc, Cf or Cs, 0 raises (4 of 4). The U+009B arm is reported not run where the volume refuses that folder name.
- **Negative control:** code read, `4fef292` and 9a tree: `screens.py:712` builds `ListItem(Label(name))` with markup on, and `[b]P` paints 1 span (QA-02 probe) → RED. A mutation that paints `safe_text(name)` (C0 / C1 only) keeps U+202E → RED.
- **Boundary catalog:** ☒ invalid — markup-shaped, bidi and C1 names.

### LLR-173.3a — Work-area file rows are painted literally (C8)
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); `painted_names`; `safe_text`
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint each work-area file row of the Load dialog literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:**
  - The six hostile names of LLR-172.6 (each given a loadable suffix) → 6 literal rows, 0 spans, 0 Cc / Cf / Cs characters.
  - A 130-character name → a 120-character label ending in `…` (7 of 7). The surrogate arm is reported not run where the name cannot be made.
- **Negative control:** a mutation that builds the row as `Label(name)` → the `[bold]x.s19` row paints 1 span → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — the hostile names; the 120-character clip.

### LLR-173.3b — Recent rows are painted literally (C8)
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); `painted_names`; `safe_text`
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint each recent row of the Load dialog literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** store entries `C:\x\[bold]a.s19`, `C:\x\[link=y]b.hex` and `C:\x\[@click=app.bell]c.a2l` (each accepted by the 9a read) → 3 rows with 0 spans whose plain text holds the literal file name (3 of 3).
- **Negative control:** a mutation that builds the row as `Label(path)` → 1 span per row → RED.
- **Boundary catalog:** ☒ invalid — markup-shaped paths the store read accepts.

### LLR-173.3c — Preview lines are painted literally (C8)
- **Traceability:** HLR-173 · trace: the preview builder (NEW, `app.py`); the Load dialog preview pane (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint literally every file, variant and problem name shown in the Load dialog's preview.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** project `P` holding `[b]v.s19`, `[i]m.mac` and `[u]c.a2l` → the preview's plain text holds the 3 literal names and 0 spans come from them; a recent `C:\x\[bold]a.s19` previewed → 0 spans (4 of 4).
- **Negative control:** a mutation that writes the preview with markup on → `[b]v.s19` paints bold → RED.
- **Boundary catalog:** ☒ invalid — markup-shaped names in every preview line kind.

### LLR-173.3d — A picked row loads the on-disk name, never the label
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); the Load dialog row data (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer loads a project or work-area file row, the system shall load the exact on-disk name that row holds.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** the `[b]P` project → `current_project == "[b]P"`; the U+009B file and the 130-character file (label clipped) → `current_file.path.name` equals each on-disk name (3 of 3).
- **Negative control:** a mutation that stores the painted label as the row's value → the U+009B and clipped arms load nothing → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — a C1 name; a clipped label.

### LLR-173.4 — The projects section is the project list
- **Traceability:** HLR-173 · trace: `list_projects`, the dialog rows builder (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.40, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog opens, the system shall list in its projects section exactly the names the project list of this work area returns, in that order.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** projects `ab` and `cd`, the reserved folders `temp` and `patches`, and a junction folder `jx` → 2 project rows, `ab` then `cd`. The junction arm is Windows only and is reported not run when no junction can be made.
- **Negative control:** a mutation that lists the work area's folders without `list_projects` → `temp`, `patches` and `jx` listed → RED.
- **Boundary catalog:** ☒ invalid — reserved homes; a junction.

### LLR-173.4a — A folder that is not a project is not listed (§1.3; 9a C4, Q9)
- **Traceability:** HLR-173 · trace: `list_projects`, `validate_project_files` (`app.py`, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a direct child folder of this work area holds no `project.json`, no data file and no A2L file, then the system shall leave it out of the Load dialog's projects section.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:**
  - An empty folder `e` and a folder `n` holding only `notes.txt` → 0 rows.
  - A folder holding only `project.json`, one holding only `x.s19` and one holding only `c.a2l` → 1 row each (5 of 5).
  - A typed `<workarea>/e` still gives `not a project` (LLR-172.5b, unchanged).
- **Negative control:** code read, 9a tree: `list_projects` appends every folder that passes the link and reserved checks and `is_dir()`, so `e` and `n` are listed → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — an empty folder; each of the three contents alone.

### LLR-173.4b — The files section is the one lister, filtered to loadable files (CR9-11, 9a C7)
- **Traceability:** HLR-173 · trace: `list_workarea_files`, `recent_kind` (`workspace.py`); the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog opens, the system shall list in its work-area files section each file `list_workarea_files` returns whose suffix maps to a load kind.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`; TC-B100-37 (the census, widened) — `pytest tests/test_b100_recents.py -k tc_b100_37`
- **Numeric pass threshold:**
  - `temp/` holding `a.s19`, `b.hex`, `c.a2l`, `d.a2l.json`, `e.txt` and the folder `.staging/` → 3 rows, `a.s19`, `b.hex`, `c.a2l`, in the lister's order.
  - The TC-B100-37 census, widened to count a string literal equal to `temp` in any letter case joined to a path expression (CR9-11) → 1 enumerating function, `list_workarea_files`.
  - A runtime spy on `os.scandir`, `os.listdir`, `Path.iterdir` and `Path.glob` during one dialog open → 1 enumeration of `temp/`, from `list_workarea_files`.
  - 3 of 3.
- **Negative control:**
  - A dialog section written as `(self.workarea / "temp").iterdir()` → the widened census finds 2 functions and the spy 2 enumerations → RED. The 9a census misses it, as CR9-11 showed.
  - A mutation with no suffix filter → 5 rows → RED.
- **Boundary catalog:** ☒ invalid — an A2L JSON dump, a text file, the staging folder.

### LLR-173.4c — The recents section is the store read
- **Traceability:** HLR-173 · trace: `read_recent_sources` (`workspace.py`); the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Load dialog opens, the system shall list in its recents section each entry the recent-sources read returns, in the returned order.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** a store of 3 entries → 3 rows in stored order; a store of 20 → 20 rows; a store of 2 valid entries among 3 the read refuses → 2 rows (3 of 3).
- **Negative control:** a mutation that sorts the rows by path → the 3-entry arm order differs → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — 20 entries; refused entries.

### LLR-173.4d — An empty projects section paints its tokens
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the project list returns no name, then the system shall paint `no projects` and `ctrl+s saves a project` in the Load dialog's projects section.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** 0 projects → 1 line holding both tokens, and that line cannot be loaded (LLR-173.2i) (1 of 1).
- **Negative control:** a mutation that paints nothing → 0 lines → RED.
- **Boundary catalog:** ☒ empty — no project.

### LLR-173.4e — An empty files section paints its tokens
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the work-area files section has no row, then the system shall paint `no work-area files` and `l loads a file` in it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** an empty `temp/`, and a `temp/` holding only `d.a2l.json` → 1 token line each (2 of 2).
- **Negative control:** a mutation that paints the tokens only when `list_workarea_files` is empty → the `d.a2l.json` arm paints nothing → RED.
- **Boundary catalog:** ☒ empty — no file; only unloadable files.

### LLR-173.4f — An empty recents section paints its token
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the recent-sources read returns no entry and no problem, then the system shall paint `no recent sources` in the Load dialog's recents section.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** no store file; and a `LOCALAPPDATA` that is unset → 1 line holding `no recent sources` each (2 of 2).
- **Negative control:** a mutation that paints nothing → 0 lines → RED.
- **Boundary catalog:** ☒ empty — no store; no usable variable.

### LLR-173.4g — A store problem is painted in the recents section
- **Traceability:** HLR-173 · trace: `read_recent_sources` (`RecentSources.problem`) (`workspace.py`); the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the recent-sources read reports a problem, then the system shall paint that problem word and its next-step token in the Load dialog's recents section.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:**
  - A 65 537-byte store → 1 line holding `too large` and `the next load starts a new list`.
  - A store whose read raises `PermissionError` (injected) → 1 line holding `could not be read` and `check that the recent-sources file can be opened`.
  - 0 recent rows each (2 of 2).
- **Negative control:** a mutation that ignores `problem` → `no recent sources` painted → RED.
- **Boundary catalog:** ☒ error — too large; unreadable.

### LLR-173.4h — A recent row shows the recorded file name and kind only
- **Traceability:** HLR-173b · trace: the dialog rows builder (NEW, `app.py`); `RecentEntry` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint each recent row as the recorded path's file name followed by the recorded kind.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** `C:\cal\v2\fw.s19` (kind `s19`) → plain text `fw.s19` then `s19`, 0 `●` (1); a 300-character recorded path → a row of 1 line (LLR-173.6n).
- **Negative control:** a mutation that adds a size or a date to the row → that value can only come from a filesystem call, so LLR-173.4j turns RED; the text arm also differs → RED.
- **Boundary catalog:** ☒ boundary — a long path.

### LLR-173.4i — A highlighted recent previews the store's facts and nothing else
- **Traceability:** HLR-173b · trace: the preview builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a recent row is highlighted, the system shall paint in the preview its full recorded path, its kind and `checked when loaded`, with no `●`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** 3 recents highlighted in turn → 3 previews, each holding the full path, the kind and `checked when loaded`, 0 `●` (3 of 3).
- **Negative control:** code read, `1d677ba` prototype `pa_C.preview_file` reads the recent's bytes on highlight (`r.path.read_bytes()`) → a dialog copied from it previews size and "same bytes" → RED here and on LLR-173.4j.
- **Boundary catalog:** ☒ boundary — each kind.

### LLR-173.4j — No filesystem call touches a recent before it is loaded
- **Traceability:** HLR-173b · trace: the dialog rows builder, the preview builder (NEW, `app.py`); the Load dialog (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall make no filesystem call on a recent entry's path before the engineer loads that row.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** the dialog opened and 3 recents highlighted (one present, one missing, one on an unassigned drive letter `Q:`) → 0 calls naming any of the 3 paths among `os.stat`, `os.lstat`, `os.scandir`, `os.listdir`, `open`, `os.path.exists` and `Path.exists` / `is_file` / `resolve` (a counting spy).
- **Negative control:** a mutation that previews a recent's size on highlight → 1 call per highlight → RED.
- **Boundary catalog:** ☒ invalid ☒ error — a missing entry; an unassigned drive.

### LLR-173.4k — A recent missing on pick is explained inside the dialog
- **Traceability:** HLR-173b · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a recent row the engineer loads names a path that does not exist, then the system shall keep the Load dialog open and paint `not found` and `check the path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** a recent whose file was deleted, then `enter` → 1 token pair, 0 dismisses, 0 loads, the store bytes unchanged (the entry stays; ruling Q3) (1 of 1).
- **Negative control:** a mutation that dismisses and lets the router paint the status line → the dialog closes → RED.
- **Boundary catalog:** ☒ error — a deleted source.

### LLR-173.4l — The list order is projects, files, recents
- **Traceability:** HLR-173 · trace: the Load dialog compose (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall order the Load dialog's list as the projects section, then the work-area files section, then the recents section, each under a heading that cannot be loaded.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** 1 item per section → 6 list lines in the order heading, project, heading, file, heading, recent (6 of 6); the headings read "Projects", "Work area" and "Recent".
- **Negative control:** a mutation that lists recents first → RED.
- **Boundary catalog:** ☒ boundary — one item per section.

### LLR-173.4m — An unreadable project list says so in the projects section
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); `list_projects` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the project list cannot be read, then the system shall paint `could not be read` and `check that the folder can be opened, then load again` in the Load dialog's projects section, and the other sections still load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** `PermissionError` injected into `list_projects` → 1 token line in the projects section, the files and recents sections built as usual, 0 raises, the dialog open (1 of 1).
- **Negative control:** a mutation with no catch in the rows builder → the exception leaves `rows()` on mount and the app stops (Textual `exit_on_error`) → RED.
- **Boundary catalog:** ☒ error — an unreadable project list.

### LLR-173.4n — A linked file in a project folder is neither listed in the Load dialog preview nor installed by a project load
- **Traceability:** HLR-173a · trace: `_list_project_files`, `_handle_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a file in a project folder is a link, then the system shall neither list it in the Load dialog preview nor install it in a project load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a project `P` holding `a.s19` and a symlink `b.s19` (to a regular file), with `active_variant` `b` → 1 preview row (`a.s19`), 1 `●`, and after `enter` 1 install (`a.s19`) and 0 opens of the link target (1 of 1).
- **Negative control:** a mutation whose scan follows links lists 2 rows → RED.
- **Boundary catalog:** ☒ invalid — a linked `.s19` beside a regular `.s19`.

### LLR-173.5 — A typed path not found is explained inside the dialog (UX-06)
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`); the Load dialog (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed path that does not exist, then the system shall keep the dialog open with the typed text unchanged and paint `not found` and `check the path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<tmp>/missing.s19` and `<workarea>/nope` → 1 token pair each, 0 dismisses, 0 status lines, the field text unchanged (2 of 2).
- **Negative control:** code read, 9a tree: `LoadFileScreen` dismisses with the `Path` and the refusal becomes a status line after the dialog has closed (LLR-172.5f) → RED.
- **Boundary catalog:** ☒ error — a missing file; a missing folder.

### LLR-173.5a — A typed unsupported file or relative folder is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed path that the typed-path route refuses as not a supported file, then the system shall keep the dialog open with the typed text unchanged and paint `not a supported file` and `check the path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<tmp>/notes.txt`, `<tmp>/fw.s19.` (trailing dot, CR9-3) and the relative `.s19tool/workarea/ab` → 1 token pair each, 0 dismisses, the field text unchanged (3 of 3).
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED.
- **Boundary catalog:** ☒ invalid — an unsupported suffix; a trailing dot; a relative folder.

### LLR-173.5b — A typed folder that is not a project is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed folder of this work area that is not a project, then the system shall keep the dialog open with the typed text unchanged and paint `not a project` and `pick a project in the list` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<workarea>/temp`, `<workarea>/TEMP`, an empty `<workarea>/e` and `<workarea>/ab/flows` → 1 token pair each, 0 dismisses, 0 session resets (4 of 4). The `TEMP` arm is Windows only.
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED.
- **Boundary catalog:** ☒ invalid — reserved homes in two cases; an empty folder; a sub-folder.

### LLR-173.5c — A typed folder outside the work area is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed folder, or a typed `project.json`, outside this work area, then the system shall keep the dialog open with the typed text unchanged and paint `outside the work area` and `copy the folder into the work area` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<tmp>/P` and `<tmp>/P/project.json` → 1 token pair each, 0 dismisses (2 of 2).
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED.
- **Boundary catalog:** ☒ invalid — an outside folder; an outside manifest.

### LLR-173.5d — A typed path through a link or junction is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed work-area folder path that passes through a link or junction, then the system shall keep the dialog open with the typed text unchanged and paint `link or junction` and `pick a project in the list` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<workarea>/jx` (a junction to `ab`) and `<workarea>/jx/project.json` → 1 token pair each, 0 dismisses, 0 resets (2 of 2). Windows only; reported not run when no junction can be made.
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED.
- **Boundary catalog:** ☒ invalid — a junction folder; a manifest through it.

### LLR-173.5e — A typed folder that cannot be read is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed work-area folder that cannot be inspected, then the system shall keep the dialog open with the typed text unchanged and paint `could not be read` and `check that the folder can be opened, then load again` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `PermissionError` injected into `os.lstat` of a walk prefix, and separately into `list_projects` → 1 token pair each, 0 dismisses, 0 raises (2 of 2). These are the CR9-6 arms painted in the dialog.
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED; a mutation that drops the classifier's `OSError` catch → the exception leaves the key handler → RED.
- **Boundary catalog:** ☒ error — a walk error; a listing error.

### LLR-173.6 — A project row's preview marks what `choose_install_set` installs
- **Traceability:** HLR-173a · trace: `choose_install_set`, `build_variant_set`, `read_project_manifest`, `manifest_is_damaged`, the project preview builder (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.34, LED-2026-10-26-batch-100.40, LED-2026-10-26-batch-100.46, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a project row is highlighted, the system shall mark with `●` in the preview the variant, MAC and A2L that the project-load install rule selects for that project with no variant known to be unreadable.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** 4 projects: clean; after a save-back (recorded active ≠ first by name); recorded active missing; A2L-only. Each highlighted, then `enter` → the `●` rows equal the Loaded panel's image, MAC and A2L paths (4 of 4). The A2L-only project marks the A2L only.
- **Negative control:** a mutation that computes the mark from the first variant by name → the save-back arm differs → RED.
- **Boundary catalog:** ☒ boundary — the four project kinds.

### LLR-173.6a — A load that installs another variant than the one marked names it
- **Traceability:** HLR-173a · trace: `_handle_load_project`, `choose_install_set` (`unreadable`), the Load-result composition (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a project load installs a variant other than the one the preview marked, then the system shall name the opened variant and the reason in the Load-result panel.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a project whose recorded active variant is a 0-byte file → the preview marks it (no image is read before Enter); after `enter` the Load-result panel names the next valid variant and `not readable` on the marked one (2 of 2).
- **Negative control:**
  - A mutation that drops the reason line from the panel → RED.
  - Declared: the panel behaviour holds since Inc 7 (LLR-169.6, HLR-178), so this arm passes on the 9a tree; the requirement fixes the one case where the mark and the install may differ, and the mutation is the RED.
- **Boundary catalog:** ☒ error — the marked variant unreadable at install.

### LLR-173.6b — A file row's preview marks the file and what the session keeps
- **Traceability:** HLR-173a · trace: the file preview builder (NEW), the install of a data or A2L load (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a work-area file row is highlighted, the system shall mark with `●` in the preview that file and the MAC and A2L the session keeps after loading it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** each case highlighted, then `enter` → the `●` rows equal the Loaded panel's image, MAC and A2L paths:
  - nothing loaded and an S19 row → 1 `●`;
  - an A2L loaded and an S19 row → 2 `●`;
  - an S19 and a MAC loaded and a HEX row → as the install keeps them;
  - an S19 loaded and an A2L row → 2 `●`.
  - 4 of 4.
- **Negative control:** a mutation that marks only the highlighted file → the second arm differs → RED.
- **Boundary catalog:** ☒ boundary — nothing loaded; A2L kept; MAC present; A2L attach.

### LLR-173.6c — With a project open, a file row's preview says it becomes the active variant
- **Traceability:** HLR-173a · trace: the file preview builder (NEW), `current_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While a project is open, the system shall paint, in the preview of a highlighted data-file row, a note that the file becomes that project's active variant.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** project `P` open, S19 row → 1 note naming `P` (painted literally); no project open → 0 notes; project `P` open, A2L row → 0 notes (3 of 3).
- **Negative control:** a mutation that paints the note whatever the state → the no-project arm RED.
- **Boundary catalog:** ☒ boundary — no project; an A2L row.

### LLR-173.6d — A project row's preview lists its variants
- **Traceability:** HLR-173 · trace: `build_variant_set`, the project preview builder (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a project row's preview read completes, the system shall list every variant of that project in the preview in `build_variant_set` order.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a project with `b.s19`, `a.s19` and `c.hex` → 3 variant lines in `build_variant_set` order, exactly one carrying `●` (1 of 1).
- **Negative control:** a mutation that lists only the marked variant → 1 line → RED.
- **Boundary catalog:** ☒ boundary — three variants of two kinds.

### LLR-173.6f — A project row's preview states the manifest
- **Traceability:** HLR-173 · trace: `read_project_manifest`, `manifest_is_damaged` (`variant_execution_service.py`, called from `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a project row's preview read completes, the system shall paint the state of that project's `project.json` as `ok`, `no project.json` or `manifest damaged`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a valid manifest → `ok`; none → `no project.json`; a 1 MiB + 1 byte manifest → `manifest damaged` (3 of 3).
- **Negative control:** a mutation that paints `ok` whenever the file exists → the over-cap arm RED.
- **Boundary catalog:** ☒ empty ☒ boundary — absent; over the 1 MiB cap.

### LLR-173.6k — A project preview that cannot be read says so
- **Traceability:** HLR-173 · trace: the project preview builder (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a project's preview read raises an `OSError`, then the system shall paint `could not be read` and `check that the folder can be opened, then load again` in the preview, with no `●`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** `PermissionError` injected into the folder listing and, separately, into the manifest read → 1 token pair each, 0 `●`, 0 raises, the dialog open (2 of 2).
- **Negative control:** a mutation with no catch in the preview builder → the builder error ends the app's run (Textual's default `exit_on_error`) → RED.
- **Boundary catalog:** ☒ error — a listing error; a manifest read error.

### LLR-173.6l — The dialog reads nothing itself
- **Traceability:** HLR-173 · trace: the Load dialog (`screens.py`); its callables (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall give the Load dialog its rows, its previews and its typed-path verdicts only through callables from `app.py`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:**
  - AST census: the Load dialog class references 0 names bound by imports from `s19_app.tui.services.*`, `s19_app.tui.workspace` or `os` / `pathlib` filesystem calls.
  - `screens.py`'s set of imported modules gains 0 modules over the 9a tree (2 of 2).
- **Negative control:** a mutation where the dialog calls `list_workarea_files` itself → census 1 and 1 new import → RED.
- **Note (defect fixed):** the old text "`screens.py` imports no service module" is false at `4fef292`. `screens.py` already imports `operation_service`, `report_service`, `entropy_service` and `report_addendum` (lines 66-73). So the census is scoped to the dialog class and to no new module.
- **Boundary catalog:** none — a structural census.

### LLR-173.6m — The panes stack below 100 columns
- **Traceability:** HLR-173 · trace: the Load dialog `on_resize` (`screens.py`); `#load_dialog` rules (`styles.tcss`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While the terminal is narrower than 100 columns, the system shall place the Load dialog's preview below its list.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** at 99 columns → the preview's region starts below the list's region (`preview.y >= list.y + list.height`); at 100 and 118 → the preview's region starts right of the list (`preview.x >= list.x + list.width`) (3 of 3); a resize from 118 to 99 with the dialog open → stacked (1).
- **Negative control:** a mutation that sets the break at 118 → the 100-column arm stacks → RED.
- **Boundary catalog:** ☒ boundary — 99, 100, 118; a live resize.

### LLR-173.6n — A list row never wraps
- **Traceability:** HLR-173 · trace: the Load dialog rows (`screens.py`); `#load_list` rules (`styles.tcss`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall paint each row of `#load_list` on one terminal line.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a 120-character project name, a 130-character file name and a 300-character recent path, at 99, 100 and 118 columns → every row's region height is 1 (9 of 9).
- **Negative control:** a mutation that allows wrapping → the 130-character row is 2 lines high at 99 columns → RED.
- **Boundary catalog:** ☒ boundary — long names at three widths.

### LLR-173.7 — Painted text carries no internal decision id
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** No string painted by a surface this batch adds or changes — the Load dialog, the load question, the Save dialog, the busy indicator, the Load-result panel and the refusal tokens — shall carry an internal decision id (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`, `HLR-…`).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-66 — `pytest tests/test_b100_load_dialog.py -k tc_b100_66` (renders each surface at 118×54 and greps its painted text)
- **Numeric pass threshold:**
  - Written at Inc 9b: the Load dialog in 6 scenarios (each section highlighted, the empty Load, a refused path, a store problem), the Load-result panel and the refusal-token constants → 0 matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-`.
  - Extended at Inc 10 (the question), Inc 11 (the Save dialog) and Inc 12a (the busy indicator).
- **Negative control:** the prototypes paint "Browse is gone (D7)" and "D10: click loads OFF" (UX-18 captures; `pa_C` via `_pa_common._paint_d10`) → a surface copied from them → RED.
- **Boundary catalog:** none — the scan has no input classes; its set is every painted string of the surfaces written so far.

---

## Retired

- **LLR-171.2e** — retired by LLR-173.4a (Q7): an empty folder is no longer a listed project.
- **LLR-173.1d** — retired (A9b-08): after 9b no product code passes a bare `Path` to `_handle_load_dialog`; its 3 test call sites re-pin to `LoadChoice("path", str(p))`.
- **LLR-173.2k (in-flight arm)** — retired (A9b-04): `escape` while a project preview read runs cannot occur once the preview is synchronous; the four focus-position arms stay.
- **LLR-173.6i** — retired (A9b-04): the synchronous preview (`preview: Callable[[LoadChoice], list[PreviewLine]]`) has no in-flight read whose result can arrive stale, so the generation check guarded a state the product cannot reach.

---

## §C — CR9-1: new block LLR-172.1n (insert after the last LLR-172.1* block)

**HLR-172 Decomposition line, one edit:** `LLR-172.1, LLR-172.1a … LLR-172.1m` → `LLR-172.1, LLR-172.1a … LLR-172.1n (… LLR-172.1n leaves out a source found only through the relative fallback, CR9-1)`. Add `LED-2026-10-26-batch-100.NN` to HLR-172's Ledger line.

### LLR-172.1n — A source found only through the relative fallback is not recorded (CR9-1)
- **Traceability:** HLR-172 · trace: `load_from_path`, `load_a2l_from_path` (`app.py`); `resolve_input_path` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a Load copies a source that the path resolver found only through its base-folder or repository-root fallback, then the system shall leave the recent-sources store unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** "found only through the fallback" means the typed text is relative and does not exist relative to the working folder. Arms:
  - Working folder `W` ≠ base folder `B`, `B\j` a junction to `R`, typed `j\x.s19` → 1 load, the store bytes unchanged, 0 `Recent sources not updated` warnings.
  - Typed `fw.s19`, present only in `B` → 1 load, the store unchanged.
  - The same relative file typed with `W` = `B` (found as typed) → 1 entry, `os.path.abspath` of the typed text (control).
  - Typed absolute `B\j\x.s19` → 1 entry `B\j\x.s19`, the link not followed (control, LLR-172.1a).
  - 4 of 4. The junction arms are Windows only and are reported not run when no junction can be made.
- **Negative control:** executed probe on the 9a tree (`review-increment-017.md` CR9-1): typed `j/x.s19` → the store holds `R\x.s19` (the link followed, against LLR-172.1a) → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — a relative path through a junction; a base-only file; the same file found as typed; an absolute path through a junction.

---

## §D — Index, token and census rows

### D.1 — §5.3 TC index: new rows (insert after the TC-B100-39 row)

| TC arm | Written at | Extended at |
|---|---|---|
| TC-B100-34 (LLR-172.1n) | Inc 9b: a source found only through the base-folder or repository-root fallback (a junction arm and a base-only arm) not recorded; a file found as typed and an absolute junction path recorded lexically (LED .NN) | — |
| TC-B100-40 (LLR-173.1, LLR-173.1a, LLR-173.1b, LLR-173.1c, LLR-173.1e, LLR-173.1f, LLR-173.1g) | Inc 9b: one `LoadChoice` per kind, the project route with the Load-result panel, the work-area file in place (copy spy), the typed-path route, the one router census, the recent's recorded path unchanged, an unreadable picked project explained (LED .NN) | Inc 10: the load question in this router (LLR-174.4) |
| TC-B100-41 (LLR-173.2, LLR-173.2a, LLR-173.2b, LLR-173.2c, LLR-173.2d, LLR-173.2e, LLR-173.2f, LLR-173.2g, LLR-173.2h, LLR-173.2i, LLR-173.2j, LLR-173.2k, LLR-173.2l) | Inc 9b: the open keys and their focus, the open project highlighted, the `tab` order, printable keys typed into the path field, the priority keys inert, the list / path precedence of a load, the two empty-Load arms, a click selects, `escape` and Cancel close (LED .NN) | — |
| TC-B100-42 (LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.3c, LLR-173.3d) | Inc 9b: project, file, recent and preview names painted literally; a pick loads the on-disk name (LED .NN) | — |
| TC-B100-43 (LLR-173.4, LLR-173.4a, LLR-173.4b, LLR-173.4c, LLR-173.4d, LLR-173.4e, LLR-173.4f, LLR-173.4g, LLR-173.4h, LLR-173.4i, LLR-173.4j, LLR-173.4k, LLR-173.4l, LLR-173.4m) | Inc 9b: the three sources and their order, a non-project folder left out, loadable files only, the empty-section and store-problem tokens, the recent row and preview, 0 filesystem calls before Enter, a missing recent explained in the dialog, an unreadable project list explained (LED .NN) | — |
| TC-B100-63 (LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e) | Inc 9b: the six typed refusal reasons painted in `#load_reason`, the dialog open, the text kept (LED .NN) | — |
| TC-B100-64 (LLR-173.6, LLR-173.6a, LLR-173.6b, LLR-173.6c, LLR-173.6d, LLR-173.6f, LLR-173.6k, LLR-173.6l, LLR-173.6m, LLR-173.6n, LLR-173.4n) | Inc 9b: the `●` marks equal the install for project and file rows, a linked `.s19` neither marked nor installed, the project-open note, the project preview's lines, a read error, the dialog import census, the stacking break and one-line rows (LED .NN) | — |
| TC-B100-66 (LLR-173.7) | Inc 9b: the Load dialog, the Load-result panel and the refusal tokens (LED .NN) | Inc 10: the question; Inc 11: the Save dialog; Inc 12a: the busy indicator |

**Edit to an existing row.** TC-B100-37 (LLR-172.4, …), "Extended at": `Inc 9b: the Load dialog's files section reads the same lister (LLR-173.4)` → `Inc 9b: the Load dialog's files section reads the same lister, the census widened to the string literal "temp" in any letter case, and a runtime enumeration spy during a dialog open (LLR-173.4b, CR9-11)`.

### D.2 — §3 preface token table

- Row `recent source missing on pick | not found | the entry was removed` → `recent source missing on pick (Inc 9b, LLR-173.4k) | not found | check the path` (ruling Q3: the entry stays).
- New row: `recent-sources store problem (Inc 9b, LLR-173.4g) | too large / could not be read | the next load starts a new list / check that the recent-sources file can be opened` (ruling Q5).
- Row `empty Load | nothing selected | pick a row or type a path`: add `(Inc 9b, LLR-173.2h, LLR-173.2i)`.
- Typed-refusal rows (`not found` / `not a supported file`; `not a project`; `outside the work area`; `link or junction`; `could not be read`): add `painted in #load_reason from the dialog (Inc 9b, LLR-173.5 … LLR-173.5e)`.

### D.3 — §5.4 reverse census (counts re-taken on the 9a tree, `grep -rc` over `tests/*.py`)

- `LoadFileScreen` / `#load_path` / `#load_ok` (Inc 9b): `4 / 10` → `13 files / 60 references to LoadFileScreen`; ids survive.
- `LoadProjectScreen` / `#project_list` / `#project_ok` (Inc 9b): `7 / 7` → `17 files / 57 references to LoadProjectScreen; 17 files / 63 references to #project_list or project_ok`. Both counts were stale.

---

## §E — Ledger entry (number assigned at merge)

### LED-2026-10-26-batch-100.NN — Inc 9b E1 — requirements to strict EARS / ISO 29148
- **Requirement:** HLR-173, HLR-173a, HLR-173b, HLR-173c, HLR-173d, HLR-173e, LLR-173.1, LLR-173.1a, LLR-173.1b, LLR-173.1c, LLR-173.1e, LLR-173.1f, LLR-173.1g, LLR-173.2, LLR-173.2a, LLR-173.2b, LLR-173.2c, LLR-173.2d, LLR-173.2e, LLR-173.2f, LLR-173.2g, LLR-173.2h, LLR-173.2i, LLR-173.2j, LLR-173.2k, LLR-173.2l, LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.3c, LLR-173.3d, LLR-173.4, LLR-173.4a, LLR-173.4b, LLR-173.4c, LLR-173.4d, LLR-173.4e, LLR-173.4f, LLR-173.4g, LLR-173.4h, LLR-173.4i, LLR-173.4j, LLR-173.4k, LLR-173.4l, LLR-173.4m, LLR-173.4n, LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e, LLR-173.6, LLR-173.6a, LLR-173.6b, LLR-173.6c, LLR-173.6d, LLR-173.6f, LLR-173.6k, LLR-173.6l, LLR-173.6m, LLR-173.6n, LLR-173.7, HLR-172, LLR-172.1n. New in this entry: HLR-173a, HLR-173b, HLR-173c, HLR-173d, HLR-173e, LLR-172.1n, and every suffixed LLR-173 id above. Also: §3 refusal-token table (1 row changed, 1 row added, 2 rows annotated); §5.3 TC index (8 rows added, 2 rows changed); §5.4 reverse census (2 rows corrected).
- **Pairing note:** a requirement split here lists on its Ledger line only this entry. The history before the split stays on its parent's Ledger line: HLR-173 (.1, .2, .10, .18, .36, .40), LLR-173.1 (.12), LLR-173.2 (.2, .18, .36), LLR-173.3 (.10), LLR-173.4 (.6, .18, .40), LLR-173.5 (.10), LLR-173.6 (.2, .18, .34, .40, .46), LLR-173.7 (.10).
- **Date:** 2026-10-31
- **What changed:** each Inc 9b requirement was rewritten to the operator's strict standard, as in LED .76 and .82. That means one EARS sentence in one of the five forms, one "shall", every failure path its own unwanted-behaviour requirement, and a numeric pass threshold and a negative control each, checked against ISO/IEC/IEEE 29148 (necessary, unambiguous, complete, singular, feasible, verifiable, correct, conforming). Function names moved from the statements to the trace. Existing ids are kept; a split keeps the id for the first part and adds a suffix; nothing is renumbered or deleted. Negative controls are executed probes where one exists (P-18, P-19, P-20 on `1d677ba`; CR9-1 on the 9a tree), code reads on the 9a tree otherwise, each named. Per id:
  - **HLR-173:** 1 statement with about 20 behaviours (layout, keys, focus, empty and refused Load, literal names, recent rows, worker preview, `LoadChoice`, in-place pick, marks = install) → event "When the engineer opens Load, show one dialog with a typed-path field, one list of projects, work-area files and recent sources, and a preview pane". AT-B100-14's list half. Singular.
  - **HLR-173a (new, split from HLR-173):** ubiquitous "mark with `●` exactly the variant, MAC and A2L a load installs". AT-B100-14's preview half.
  - **HLR-173b (new, split from HLR-173):** event "loading a recent row loads the file at its recorded path". AT-B100-14's recent half; the consume half of AT-B100-12's chain.
  - **HLR-173c (new, split from HLR-173):** event "a load loads the highlighted row when the list held the focus more recently than the path field, the typed path otherwise". The old "when the list has the focus" was ambiguous once the focus sits on the preview or a button.
  - **HLR-173d (new, split from HLR-173):** unwanted "an empty or refused Load keeps the dialog open, keeps the text and paints reason and next step in `#load_reason`".
  - **HLR-173e (new, split from HLR-173):** event "`escape` closes and leaves the session unchanged".
  - **LLR-173.1:** 4 "shall"s (dismiss type, router, `Path` compatibility, load question) → ubiquitous "close with no result or one `LoadChoice` of the four kinds". "The load question (HLR-174) runs in this router" is removed from 9b: the question and its seam are Inc 10's (LLR-174.4). Kept as an informative note on LLR-173.1e.
  - **LLR-173.1a, LLR-173.1b, LLR-173.1c (new):** one event per routed kind (project through the Load-result route, work-area file as the list pick, typed path through the typed-path route).
    - LLR-173.1b's old negative control ("a mutation routing `workarea` through `load_from_path` → 1 new copy") cannot be RED since Inc 1: the copy reuses the identical file (G-005). It is now a `copy_into_workarea` call spy on the data arm only.
    - The work-area A2L pick keeps the 9a `load_a2l_from_path` route (with its `copy_into_workarea`, 256 MB cap and link re-check) — A9b-05.
  - **LLR-173.1e (new):** ubiquitous "one handler receives every result", by an AST census of the push sites.
  - **LLR-173.1f (new):** event "a recent choice loads the recorded path text unchanged through the typed-path route". With LLR-172.2e (drive-rooted entries) this guarantees that a recent never reaches the relative fallback (CR9-1's consume side).
  - **LLR-173.1g (new, F-12):** unwanted "an `OSError` picking a listed project paints one status line `could not be read`, keeps the session unchanged, and does not crash". Pre-existing (MAJOR candidate) in the project route 9b owns.
  - **LLR-173.2:** 8 "shall"s → event "`l` / `ctrl+l` open on `#load_path`".
  - **LLR-173.2a (new):** event "`p` and `#ws_load_project_button` open on `#load_list`". New arm: 0 projects still opens the dialog (today `p` paints `No saved projects found.` and opens nothing).
  - **LLR-173.2b (new):** event "the open project's row, else the first project row, is highlighted". New arm: 0 projects.
  - **LLR-173.2c (new):** event "the `tab` order", with the wrap and `shift+tab`.
  - **LLR-173.2d (new):** event "a printable key in the list moves to the path field and types there". "Never reaching an app binding" holds on base under Textual 8.2.8 (a modal stops the app's non-priority bindings). That arm is declared, and the field arm is the RED.
  - **LLR-173.2e (new):** unwanted "`ctrl+l`, `ctrl+s`, `ctrl+k`, `ctrl+d` are inert while the dialog is open". These are priority bindings that reach the app through a modal (code read on Textual 8.2.8); the failure path had no requirement (ruling Q6).
  - **LLR-173.2f, LLR-173.2g (new):** one event per precedence case.
  - **LLR-173.2h, LLR-173.2i (new):** one unwanted requirement per empty case (empty text; no loadable row highlighted, a heading included). "Nothing selected" was undefined when a row is highlighted by default.
  - **LLR-173.2j (new):** event "a click highlights and keeps the dialog open". The feasibility note records that Textual posts the same `Selected` for a click as for `enter`.
  - **LLR-173.2k, LLR-173.2l (new):** `escape` and Cancel, one event each.
  - **LLR-173.3:** "every row and preview line … through `safe_text`" → 4 ubiquitous requirements by row kind (LLR-173.3 projects, LLR-173.3a files, LLR-173.3b recents, LLR-173.3c preview) plus LLR-173.3d (new, event: a pick loads the on-disk name). `safe_text` alone (C0 / C1) is corrected to the batch's one category scrub `painted_names` with markup off (8b S3R2-4, LLR-172.6). `safe_text` keeps U+202E and surrogates.
  - **LLR-173.4:** 6 "shall"s → event "the projects section is the project list".
  - **LLR-173.4a (new):** unwanted "a folder holding no `project.json`, data or A2L file is not listed". Decides 9a C4 / Q9 by §1.3.
  - **LLR-173.4b (new):** event "the files section is `list_workarea_files` filtered to loadable suffixes". Decides 9a C7 (an `.a2l.json` dump is not a dialog row) and CR9-11 (the census widened to the literal `"temp"`, plus a runtime spy).
  - **LLR-173.4c (new):** event "the recents section is the store read, in order".
  - **LLR-173.4d, LLR-173.4e, LLR-173.4f (new):** one unwanted requirement per empty section.
  - **LLR-173.4g (new):** unwanted "a store problem (`too large`, `could not be read`) is painted with a next step". 9a Q6 left this to 9b; it had no requirement; new token row (ruling Q5).
  - **LLR-173.4h, LLR-173.4i (new):** the recent row (file name and kind) and its preview (full path, kind, `checked when loaded`, no `●`). The row/preview split is ruling Q4.
  - **LLR-173.4j (new):** ubiquitous "no filesystem call on a recent before load", with a counting spy.
  - **LLR-173.4k (new):** unwanted "a recent missing on pick is explained in the dialog". "Drop the entry" is removed: no store function removes one entry, and `workspace.py` is outside 9b's cap (ruling Q3).
  - **LLR-173.4m (new, F-2):** unwanted "if the project list cannot be read, the projects section paints `could not be read` / `check that the folder can be opened, then load again` and the other sections still load".
  - **LLR-173.4n (new, R2-N2):** unwanted "a linked file in a project folder is neither listed nor installed". The preview and the install share `_list_project_files`, so linked children are neither marked nor installed, and the marks equal the install.
  - **LLR-173.5:** 1 statement over 4 refusal kinds, with "the matching tokens (LLR-172.5)" now stale since LED .82 → 6 unwanted requirements, one per reason (LLR-173.5 not found, LLR-173.5a not a supported file with the relative-folder and trailing-dot arms, LLR-173.5b not a project, LLR-173.5c outside, LLR-173.5d link or junction, LLR-173.5e could not be read). Each names its own token pair.
  - **LLR-173.6:** 5 "shall"s → event "a project row's `●` marks are what the install rule selects".
  - **LLR-173.6a (new):** unwanted "an install that differs from the mark names the opened variant". The preview reads no image, so a 0-byte recorded variant is marked and then skipped at install. The old "the files installed are the files the preview marked" was infeasible for that case.
  - **LLR-173.6b, LLR-173.6c (new):** the file-row marks, and the project-open note in the State form.
  - **LLR-173.6d, LLR-173.6f (new):** one event per project-preview line (variants, manifest state).
  - **LLR-173.6k (new):** a read error.
  - **LLR-173.6l (new):** ubiquitous "the dialog gets its rows, previews and verdicts only through `app.py` callables". The old census "`screens.py` imports no service module" was false at `4fef292` (`screens.py` imports four service modules) → scoped to the dialog class and to no new module.
  - **LLR-173.6m (new):** state "below 100 columns the preview sits below the list", with region-geometry oracles.
  - **LLR-173.6n (new):** ubiquitous "one line per list row".
  - **LLR-173.7:** unchanged statement. The threshold now names what is written at 9b and the increments that extend it.
  - **HLR-172:** Decomposition gains LLR-172.1n.
  - **LLR-172.1n (new, CR9-1):** unwanted "a source found only through the relative fallback is not recorded". The fallback's `resolve()` follows links, against LLR-172.1a. On a mapped drive it records a UNC path the store refuses, with 1 warning per load (executed probe in `review-increment-017.md`). The record is removed rather than guarded (skill E3 rule; ruling Q1).
- **E3 r1 amendments (design-fix):** LLR-173.1d retired (A9b-08); LLR-173.2m removed (A9b-10, the VS-PA-4 labels defer to Inc 12a); LLR-173.6e removed (S9b-3); LLR-173.6i retired and LLR-173.2k's in-flight arm retired (A9b-04); LLR-173.6b's typed-file arm retired (A9b-07).
- **E3 r2 amendments (design-fix):** LLR-173.4n added (R2-N2); `_list_project_files` and `_a2l_admission` named in G-B; the A2L admission rule lifted into one helper shared by the preview and the install (A9b-R2-6); the preview's link-safe scan and the install both use `_list_project_files`.
- **Rulings applied:** the text follows the recommendations of `inc-9b-design/E1-rulings-proposed.md` Q1 to Q10. A different ruling changes the ids each question names.
