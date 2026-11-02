# S6 — TUI shell, navigation & layout: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S6 (lines 2481–2703): R-TUI-DISCOVER-001, R-TUI-021, 022, 023, 024, 030, 031, 033, 035, 036, 003 (superseded), 016, 065.
Code: `s19_app/tui/rail.py`, `command_bar.py`, `insight_style.py`, `__init__.py`, the S6 functions of `app.py` (`BINDINGS`, `compose`, `on_mount`, `action_show_screen`, `check_action`, `on_key`, the focus re-home, density, width regime, palette, settings menu, status bar, context line), `screens_directionb.py::EmptyStatePanel`, the shell rules of `styles.tcss`, and the key handling of Textual 8.2.8 (the pinned version) where a row depends on it. Every fact from code read, with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S6.1, S6.3, S6.5, S6.8, CTX-SHELL, CTX-KEYS, CTX-BUSY and decisions D6-9, D6-20, D6-28, D6-32 … D6-46 verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-SHELL, CTX-KEYS, CTX-THEME, CTX-BUSY (batch-100).
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first**.
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Nothing is changed in the code yet.
- Absorbed from other groups: S4's "hex page size in the viewer settings" (S6.7); S2's note on the MAC View header and the A2L help text goes to S7 (window help), not here.

---

## 1. How S6 was written before

- Thirteen rows from the Direction B restyle (batch-02) and later batches. Most name widgets, functions and batch records (`find_string_in_mem`, `_handle_goto`, `color_policy.SEVERITY_CLASS_MAP`, "AST guard", "frozen engine diff = 0").
- Three rows describe a top command bar (find box, go-to box, project and A2L labels) that a later batch (79) deleted. The rows were never updated.
- R-TUI-024 and R-TUI-065 carry about 50 lines of palette history and module design (helper names, "C-17-safe by construction", which files stay frozen).
- No row states the key map as a whole, what a key does inside a text box, where the focus goes, or what the status bar shows.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-021 | Eight rail items (with "Bookmarks") on keys `1`–`8`. The code has twelve items on keys `1`–`6`, `=`, `7`, `8`, `]`, `9`, `0`, no Bookmarks, and a thirteenth window (Split / Join / Export) opened only from the palette. The ASCII glyph fallback it requires has no switch: nothing turns it on. | Rows follow the code (D6-2); fallback removed (D6-11). |
| R-TUI-022, R-TUI-033 | "A persistent top command bar … plus a find input and a go-to input"; "route submitted text to `find_string_in_mem` and `_handle_goto`". The bar row is gone (`command_bar.py:79-84`); only the palette is left, hidden until Ctrl+K. `/` and `g` now focus each window's own boxes. The function names are design. | Palette rows (S6.4); `/` rows (S6.3); search and go-to stay in S4 (R-TUI-017, R-TUI-040). |
| R-TUI-036, R-TUI-016 | Project and A2L names "in the persistent command bar" / "in the status tile". Neither surface exists; the names sit at the right of the status line (`app.py:14723-14726`). | Context-line rows (S6.5, D6-3). |
| R-TUI-031 | Lists `g`, digits `1`–`8` and `+ - , .` as the keys routed into "a command-bar input". The real rule: in any text box every printable key is typed (Textual's `Input` consumes them). `.` is bound as `period`, a name a keyboard never sends (D6-20). | One row for every text box (R-TUI-031.1). |
| R-TUI-023 | Mixes density, the 120-column breakpoint, the Workspace pane widths (S5), the A2L and MAC pane ratios (S2) and history ("since batch-06"). Ctrl+D is a global key but changes only the Workspace panes' padding (`styles.tcss:204-210`). | Density and breakpoint rows here; pane widths stay in S5 and S2; density → prototype (D6-31). |
| R-TUI-024 | Constant names (`MAC_ADDRESS_OVERLAY_STYLE`, `FOCUS_HIGHLIGHT_STYLE`), twenty lines of before/after hex values. "No light-theme variant": Ctrl+P opens Textual's own palette, whose Theme command lists light themes. | CTX-THEME holds today's values; history out (D6-5); D6-13. |
| R-TUI-065 | A module, its constants, four helper functions, "C-17-safe by construction", which files stay frozen: design. | One row: the size format (R-TUI-065.1, D6-6). |
| R-TUI-DISCOVER-001 | "The A2L screen carries the on-screen Legend button." It does not; `tests/test_discoverability.py` records that the button was dropped. "Footer-visible `?`": the footer is now the key bar (S7). | `?` rows here and in S7; the legend key `k` is S3 R-LEGEND-MODAL-001.1 (D6-4). |
| R-TUI-030 | "A neutral empty-state panel" on every rail screen. Four windows have one (S5 R-TUI-029.4); the others show their own content. | Never blank, never an error (R-TUI-030.1, .2; D6-8). |
| R-TUI-035 | "Log verbosity must not exceed the pre-batch baseline": no baseline is stated, so it cannot be checked. | One row: typed text never reaches the log (R-TUI-035.1). |
| R-TUI-003 | Superseded; history only. | Deleted (D6-7). |

---

## 3. Context notes (informative)

### CTX-SHELL · The frame, the rail and the status bar (S6.1 … S6.5)

```text
window          One of the twelve rail windows below, or Split / Join / Export.
                One window is shown at a time.
frame           Top to bottom, the same on every window:
  header        The title "Hex Edit Tool".
  palette       The command palette, hidden until Ctrl+K (S6.4).
  settings menu The viewer settings menu, hidden until "Viewer settings" (S6.7).
  rail, window  The rail on the left, the shown window on the right.
  status bar    The status line, the progress bar, the message lines.
  key bar       Two rows of keys (S7, CTX-KEYBAR).
rail            One item per rail window, in this order:
  pos  key  glyph  label            owner of the window
   1    1    ◫     Workspace         S5
   2    2    ≡     A2L Explorer      S2
   3    3    ◉     MAC View          S2
   4    4    ▤     Memory Map        S4
   5    5    !     Issues Report     S3
   6    6    ✎     Patch Editor      S10
   7    =    ✔     Check Editor      S9
   8    7    ⏚     A2B Diff          S14
   9    8    ✦     Flow Builder      S16
  10    ]    ▶     Flow Execution    S16
  11    9    ☑     Checks            S9
  12    0    ⊕     CRC Designer      S13
  Split / Join / Export (S17) has no rail item and no key; the palette opens it.
active item     The rail item of the shown window, in the accent colour.
rail key        The key of a rail item.
wide, narrow    Wide: the terminal is 120 columns or more. Narrow: less than 120.
focus target    The widget a window gives the focus to:
  Workspace         Workarea Files list      Patch Editor     the editor panel
  A2L Explorer      tag table                Check Editor     the editor panel
  MAC View          record table             A2B Diff         Compare button
  Memory Map        map panel (then the      Flow Builder     the builder panel
                    selected region row)     Flow Execution   the execution panel
  Issues Report     grouped issue list       Checks           grouped check list
  CRC Designer      the designer panel       Split/Join/Export  the range table
                Each focus target takes the focus and is not a text box.
load completes  A file, A2L or project load installs what it read.
load cancelled  The operator closes the Load dialog without a choice, or answers the
                load question with Cancel (S5, S7).
frame widget    A widget of the frame outside the windows: a rail item, the palette
                filter.
text box        A single-line or multi-line box the operator types in.
status bar      Three parts:
  status line   Left: the status text. Right: the context line.
  status text   While a long action runs: the progress line of the shown action
                (CTX-BUSY). Otherwise: the file status.
  file status   The last file status the system set (a load's load status, S5
                CTX-FILES; a project load's project line, S11). "Ready." until the
                first.
  progress bar  0 to 100 %, with the percentage beside it (bar value: CTX-BUSY).
  message lines The 4 newest messages, the newest at the bottom. "Show the status
                <text>", in every chapter, means: add <text> as the newest message.
context line    <project>, two spaces, a vertical bar, two spaces, <A2L file name>.
  <project>     "(none)"; or the project name; or "<project>:<variant> (<i>/<N>)"
                while the open project holds N > 1 variants and <variant> is the i-th.
                Open project, variant, variant order: S11 CTX-PROJECT.
  <A2L name>    The loaded A2L file name, or "(none)".
context fit     B = floor((terminal width - 4) x 0.7) - 5 columns.
                Both names fit in B: both are shown whole.
                Otherwise P = floor(B / 2). If the project fits in P, it is whole and
                the A2L gets the rest of B; else if the A2L fits in B - P, it is
                whole and the project gets the rest; else the project gets P and
                the A2L gets B - P. A shortened name ends with "…".
                Widths count terminal columns (a CJK character is 2).
```

### CTX-KEYS · The global keys (S6.3)

Keys a window adds for itself are in CTX-KEYBAR (S7) and in the window's own chapter.

```text
key            label in palette       acts on                          chapter
Ctrl+K         Palette                every window                     S6
Ctrl+D         Density                every window                     S6
Ctrl+L, l      Load                   every window                     S5, S7
Ctrl+S, s      Save project           every window                     S11
/              Find                   Workspace, A2L Explorer, MAC View S6, S4
g              Go-to                  Workspace, A2L Explorer, MAC View S4
q, Ctrl+Q      Quit                   every window                     S6
?              Help                   every window                     S6, S7
rail keys      (window label)         every window                     S6
U              Unload all             every window                     S5
r              Refresh workarea       every window                     S5
o              Open workarea          every window                     S5
p              Projects               every window                     S11
v              Select variant         every window                     S11
j              Dump A2L JSON          every window                     S2
d              Describe tag           A2L Explorer                     S2
t              View reports           every window                     S12
x              Operations             every window                     S13
k              Legend                 every window                     S3
b              Before/After report    every window                     S14
+ , -          Page+ , Page-          A2L Explorer, MAC View           S2
, (comma) , .  Hex- , Hex+            Workspace                        S4
PgDn , PgUp    Page+ , Page-          Issues Report, A2L Explorer,     S3, S2
                                      MAC View
Ctrl+Z, Ctrl+Y Undo, Redo             Patch Editor                     S10
c              Confirm                Flow Execution                   S16
Ctrl+P         palette (Textual's)    every window                     S6 (D6-13)
```

### CTX-THEME · Colours and sizes (S6.6)

The severity colours (red, pale yellow, cyan, green, grey) are S3's palette (CTX-LEGEND); they are not repeated here.

```text
dark theme      background #0a0e1b · panel #0f1525 · text #e9e9e9 ·
                border #1b233a · odd table row #131a2c
accent          #91abec: window titles, the active rail item, the palette border,
                key-bar descriptions of row 2, the status text while a long action
                runs (S6.5b).
human-readable size
                Less than 1024 bytes: "<n> B".
                Else the largest of KiB, MiB, GiB, TiB, PiB (1 KiB = 1024 bytes)
                that keeps the number under 1024, with one decimal:
                1024 -> "1.0 KiB", 0x10000 -> "64.0 KiB", 2^30 -> "1.0 GiB".
viewer settings menu
                Title "Viewer limits (max 200)", a rule, then one row per option:
                "[<mark>] <view>: <n>"  with <view> = Hex rows, A2L tags, MAC rows,
                <n> = 25, 50, 100, 150, 200, and <mark> "*" on the size in use.
```

### CTX-BUSY · Long actions, the busy line and the quit question (S6.5b, S6.8; batch-100)

The chapter of each action owns what the action does, its own steps and its outcome text: the loads S5, S2 (R-A2L-004.10 … .12, CTX-A2L-FILE) and S11, Save project S11, the project report S12 (R-RPT-LOG.1 … .4, CTX-RPT-RUN), the diff and before/after reports S14 (R-CMP-005.13 … .15, R-BEFORE-AFTER-REPORT-001.31, CTX-DIFFREPORT, CTX-BEFOREAFTER). The labels and steps below are the code's (`_BUSY_ACTIONS`, `app.py:366-400`), the same words those notes use. This note holds only the shared progress, refusal and quit terms.

```text
long action     An action that shows its progress while it runs. Seven, each with its
                label and its steps in order (* = held step):
  action          label                              steps
  file load       Loading <name>                     Copy into the work area* ·
                                                     Parse · Install*
  A2L load        Loading <name>                     Copy into the work area ·
                                                     Parse · Build the tag table*
  project load    Loading project <name>             Check the files · Parse the A2L ·
                                                     Parse the image · Install*
  Save project    Saving project <name>              Create the folder · Place the
                                                     files · Gather the project
                                                     files · Write project.json
  project report  Generating the project report      Prepare the results ·
                                                     Write the report
  diff report     Writing the diff report            Write Markdown · Write HTML
  before/after    Writing the before/after report    Compose the report
held step       A step marked * above: the screen waits for it to end (D6-35).
session action  A file load, an A2L load, a project load or Save project. The three
                reports are not session actions.
shown action    The long action whose progress the status text and the progress bar
                show.
progress        Of an action: its progress line and its bar value.
<name>          The file or project name with every control and format character
                removed (Unicode Cc, Cf, Zl, Zp), then cut to 120 characters, the
                last one "…".
progress line   <glyph> <label>  ·  step <n>/<m> <step name>  ·  <mm>:<ss>
                Between the parts: two spaces, a middle dot, two spaces.
                Example: ⠋ Loading x.s19  ·  step 1/3 Copy into the work area  ·  00:00
  <glyph>       One of ⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏; the frame after ⠏ is ⠋.
  <n>/<m>       The step reached and the number of steps of the action.
  <mm>:<ss>     Whole minutes and seconds since the action began, two digits each;
                the minutes go past 59 (4503 s is 75:03).
amount          What a step reports of its work: done of total.
                  A2L parse     bytes read of the A2L file's size.
                  Place the files (Save project)   files placed of files planned.
bar value       Step n of m with no amount: floor(100 × (n − 1) / m) %.
                Step n of m with an amount: floor(100 × (n − 1 + f) / m) %, where
                f = done / total, kept within 0 … 1, never below the step's last f.
outcome         The status an action ends with, set by its chapter (for example
                "Loaded <name>", S5 R-TUI-012L.12), or "<label> failed" (an
                unexpected error).
complete        A session action completes when it ends with its success outcome;
                otherwise it fails (a refusal found by the action counts as failed).
busy line       busy: <label> is running — wait for it to finish.
                <label> is the label of the newest running session action.
refused list    The requests the system refuses while a session action runs:
  Load          l, Ctrl+L, p, the Workspace's "Load project (p)" button, the
                palette's Load and Projects.
  load route    a Workarea Files pick; a pick in the variant selector; a choice in
                the Load dialog.
  start         a file load, an A2L load, a project load or Save project that
                reaches its start, also one asked for before the running action
                began (the Save project dialog confirmed while a load runs).
  variant       v, the palette's Select variant, v in the Load-result panel.
  unload        U, the palette's Unload all, an unload in the Loaded panel.
  Save project  s, Ctrl+S, the palette's Save project.
  Patch Editor  the requests S10 R-PE-110 lists (Add … Write file, both Edit JSON
                dialogs and their results), Ctrl+Z, Ctrl+Y, and the accept of the
                Patch Editor's unsaved-document question.
session         The loaded image, MAC and A2L files, the change document, the open
                project and its variant, the declared regions.
quit question   Title "Quit?". Text "still working: <label> — wait, or quit after it
                finishes" (<label> as in the busy line). Buttons "Quit (y)" and
                "Stay (n)"; "Stay (n)" is the emphasised button.
  Quit          y, or Enter or a click on "Quit (y)".
  Stay          n, Escape, or Enter or a click on "Stay (n)".
confirmed quit  The operator answered the quit question with Quit while a session
                action ran, and no later answer or rule withdrew it.
unsaved-work line  A line of a completed Save project (S11) that names Patch Editor
                work the save did not write: a change-document line, or
                "Change document <name> has unsaved edits — the project records the
                file as it is on disk; save it from the Patch Editor to keep them".
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested**, **Partly** / **No** with the decision.

### S6.1 · The frame and the start (CTX-SHELL)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SHELL-START.1 | U | The system shall show the frame of CTX-SHELL on every window. | Yes; tested. |
| R-SHELL-START.2 | U | The system shall show the title `Hex Edit Tool` in the header. | Yes. |
| R-SHELL-START.3 | When | When the system starts, the system shall show the Workspace. | Yes; tested. |
| R-SHELL-START.4 | When | When the system is started with `--load <path>`, the system shall load `<path>` as a typed path input (S5.3) once the frame is shown. | Yes. |
| R-SHELL-START.5 | When | When the operator presses `q` or Ctrl+Q outside a text box while no session action runs, the system shall quit. | Yes; tested (`test_tc_b100_53_quit_asks_only_while_a_session_action_runs`: idle `q`, idle Ctrl+Q, a report running alone). During a session action: R-QUIT.1 (D6-36). |

### S6.2 · The rail and the windows (CTX-SHELL)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-021.1 | U | The system shall show the rail items of CTX-SHELL, in that order, with their glyph and label. | Yes; tested. |
| R-TUI-021.2 | U | The system shall mark exactly one rail item as active: the item of the shown rail window. | Yes; tested. |
| R-TUI-021.3 | When | When the operator presses a rail key outside a text box, the system shall show that key's window. | Yes; tested (`]` and `0` only through other windows' tests). |
| R-TUI-021.4 | When | When the operator clicks a rail item, the system shall show its window. | Yes; tested. |
| R-TUI-021.5 | When | When the operator presses Enter on the focused rail item, the system shall show its window. | No: the item takes the focus but reacts to no key (D6-22). |
| R-TUI-021.6 | When | When the system shows a window, the system shall hide every other window. | Yes; tested. |
| R-TUI-021.7 | U | The system shall show each rail item's rail key beside its glyph. | No: the rail shows no keys; `=` and `]` cannot be guessed (D6-30, prototype first). |
| R-TUI-021.8 | While | While the terminal is wide, the system shall show the rail 22 columns wide. | Yes; tested. |
| R-TUI-021.9 | While | While the terminal is narrow, the system shall show the rail 4 columns wide, with each item's glyph only. | Yes; tested. |
| R-TUI-021.10 | When | When the operator runs `Split / Join / Export` from the palette, the system shall show that window in the window area. | Yes; tested. |
| R-TUI-021.11 | When | When the operator presses a rail key while Split / Join / Export is shown, the system shall close it and show that key's window. | Yes; tested. |
| R-TUI-030.1 | When | When the operator opens a window while no file is loaded, the system shall show at least one line of text in it. | Yes; tested. |
| R-TUI-030.2 | When | When the operator opens a window while no file is loaded, the system shall show no error. | Yes; tested. |

### S6.3 · Keys and focus (CTX-KEYS)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SHELL-KEYS.1 | When | When the operator presses a key of CTX-KEYS outside a text box, the system shall run its command on the windows CTX-KEYS names. | Partly: `.` (Hex+) never reaches its command from a keyboard (D6-20). |
| R-SHELL-KEYS.2 | If | If the operator presses `+`, `-`, `,`, `.` or `c` on a window that CTX-KEYS does not name for it, then the system shall do nothing. | Yes; tested. |
| R-TUI-031.1 | While | While a text box has the focus, the system shall type every printable key into it. | Yes; tested. |
| R-TUI-031.2 | While | While a text box of the shown window has the focus, the system shall run the commands of Ctrl+K, Ctrl+D, Ctrl+L and Ctrl+S. | Yes. While a dialog is open, S7 R-DLG.1 holds (D7-23). |
| R-TUI-033.1 | When | When the operator presses `/` on the Workspace, the A2L Explorer or the MAC View, the system shall put the focus in that window's search box. | Yes; tested. |
| R-TUI-033.2 | If | If the operator presses `/` on any other window, then the system shall show the status `This screen has no find input. Use the rail to switch to Workspace, A2L or MAC.` | Yes; tested. |
| R-TUI-033.3 | If | If the operator presses `g` on any window other than the Workspace, the A2L Explorer or the MAC View, then the system shall show the status `This screen has no go-to input. Use the rail to switch to Workspace, A2L or MAC.` | Yes; tested. |
| R-TUI-033.4 | When | When the operator presses Escape in a search box or a go-to box, the system shall take the focus out of the box. | Yes; tested. |
| R-SHELL-FOCUS.1 | When | When the system starts, the system shall put the focus on the active rail item. | Yes. |
| R-SHELL-FOCUS.2 | When | When the operator shows another window with a key, the system shall put the focus on that window's focus target. | No: the focus stays in the hidden window, so its keys and its `?` help still act (D6-21). |
| R-SHELL-FOCUS.3 | When | When a load completes or is cancelled while the focus behind any dialog is on a widget that is hidden, has no size, or sits in a hidden window, the system shall put the focus on the shown window's focus target. | Yes; tested (`test_tc_b100_12_load_file_tail_rehomes_focus`, `test_tc_b100_12_load_project_tail_rehomes_focus`, `test_tc_b100_12_workarea_files_pick_rehomes_focus`, `test_tc_b100_13_a2l_tail_rehomes_focus`, `test_tc_b100_13_a2l_only_load_with_no_image`, `test_tc_b100_12_every_window_load_lands_on_its_target`, `test_tc_b100_12_rehome_lands_on_the_active_windows_target`, `test_tc_b100_12_split_join_window_target_is_its_table`, `test_tc_b100_12_stale_text_input_in_a_content_window_is_rehomed`, `test_tc_b100_12_hidden_map_row_is_rehomed`, `test_tc_b100_12_bad_default_focus_is_rehomed_behind_a_modal`, `test_tc_b100_12_load_dialog_close_rehomes_a_stale_input_focus`, `test_tc_b100_12_load_dialog_close_from_the_p16_shape_lands_on_the_target`, `test_tc_b100_12_focus_target_table_matches_the_window_registry`, `test_at_b100_04_focus_lands_and_single_keys_reach_their_screens`) (D6-39). |
| R-SHELL-FOCUS.4 | When | When a load completes or is cancelled while the focus is on a shown widget of the shown window or on a frame widget, the system shall keep the focus there. | Yes; tested (`test_tc_b100_12_healthy_focus_is_not_moved`, `test_tc_b100_12_visible_find_input_keeps_its_focus`, `test_tc_b100_12_palette_input_is_never_taken`, `test_tc_b100_12_map_load_keeps_the_region_row_and_down_walks_it`, `test_tc_b100_12_cancelled_question_rehomes_the_focus`) (D6-39). |
| R-SHELL-FOCUS.5 | If | If the shown window's focus target is not shown, then the system shall put the focus on the first shown widget of that window that takes the focus and is not a text box. | Yes; tested (`test_tc_b100_12_empty_state_target_falls_back`). |
| R-SHELL-FOCUS.6 | If | If the shown window has no such widget, then the system shall put the focus on the active rail item. | Yes. |
| R-SHELL-FOCUS.7 | While | While a dialog is open, the system shall keep the dialog's focus when a load ends. | Yes; tested (`test_tc_b100_12_modal_keeps_its_focus_while_a_load_finishes`). |
| R-TUI-DISCOVER-001.1 | When | When the operator presses `?` outside a text box and outside a window that has a help section (S7), the system shall show the key panel that lists the keys active on the focused widget. | Yes; tested. |
| R-TUI-DISCOVER-001.2 | When | When the operator presses `?` while the key panel is shown, the system shall hide the key panel. | Yes; tested. |

#### S6.3b · Focus after the load dialogs (from batch-100 HLR-166, LLR-166.1, LLR-166.2)

R-SHELL-FOCUS.3 and .4 above now cover a cancelled load as well (D6-39). The Load-result panel's own focus (its problem list first) is S11's (HLR-178).

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FOCUS-LOAD.1 | When | When the operator closes the Load-result panel, the system shall return the focus to the widget that held it behind the panel. | Yes; tested (`test_tc_b100_12_panel_close_lands_on_the_windows_target`). |

### S6.4 · The command palette

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-022.1 | When | When the operator presses Ctrl+K, the system shall open the palette with an empty filter and the focus in the filter. | Yes; tested. |
| R-TUI-022.2 | U | The system shall list in the palette one command per command of CTX-KEYS, then `Viewer settings` and `Split / Join / Export`. | Yes; tested (the `Load` and `Projects` labels: `test_tc_b100_41_labels_key_bar_and_palette_say_load_and_projects`). |
| R-TUI-022.3 | U | The system shall give each palette command a label no other palette command has. | No: `Page+` and `Page-` appear twice (D6-25). |
| R-TUI-022.4 | When | When the operator types in the palette filter, the system shall list the commands whose label contains the filter text, ignoring case. | Yes; tested. |
| R-TUI-022.5 | When | When the operator clears the palette filter, the system shall list every command again. | Yes; tested. |
| R-TUI-022.6 | When | When the operator selects a palette command, the system shall close the palette and run the command. | Yes; tested. |
| R-TUI-022.7 | When | When the operator presses Enter in the palette filter, the system shall close the palette and run the first listed command. | Yes. |
| R-TUI-022.8 | If | If no command is listed when the operator presses Enter in the palette filter, then the system shall keep the palette open. | Yes. |
| R-TUI-022.9 | When | When the operator presses Escape in the palette, the system shall close the palette. | No: the palette has no close key (D6-23). |
| R-TUI-022.10 | While | While a command cannot act on the shown window, the system shall leave it out of the palette list. | No: it is listed and does nothing when chosen (D6-24). |
| R-TUI-022.11 | U | The system shall offer no command palette other than the palette of R-TUI-022.1. | No: Ctrl+P opens Textual's own palette (D6-13). |
| R-TUI-035.1 | U | The system shall not write the text typed in the palette, a search box or a go-to box to the log. | Yes; tested. |

### S6.5 · The status bar (CTX-SHELL)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SHELL-STATUS.1 | When | When the system starts, the system shall show `Ready.` as the file status. | Yes. |
| R-SHELL-STATUS.2 | U | The system shall show the 4 newest messages in the message lines, the newest at the bottom. | Yes. |
| R-SHELL-STATUS.3 | If | If a message is empty or holds only spaces, then the system shall not add it to the message lines. | Yes. |
| R-SHELL-STATUS.4 | U | The system shall show the message lines as plain text, never as markup. | Yes. |
| R-SHELL-STATUS.5 | U | The system shall show the message lines without control characters. | Yes; tested (`test_tc_b100_50_control_bytes_never_reach_the_status_log`). Fixed by batch-100 Inc 12a (D6-28). |
| R-SHELL-STATUS.6 | When | When a long action begins, the system shall set the progress bar to 0 %. | Yes; tested (`test_tc_b100_50_begin_sets_the_bar_to_zero`) (D6-44). |
| R-TUI-036.1 | U | The system shall show the context line at the right of the status line on every window. | Yes; tested. |
| R-TUI-016.1 | U | The system shall name the open project in the context line in the form of CTX-SHELL. | Yes; tested. |
| R-TUI-016.2 | U | The system shall name the loaded A2L file in the context line. | Yes; tested. |
| R-TUI-016.3 | If | If no project is open, then the system shall show `(none)` as the project in the context line. | Yes; tested. |
| R-TUI-016.4 | If | If no A2L file is loaded, then the system shall show `(none)` as the A2L file in the context line. | Yes; tested. |
| R-TUI-036.2 | If | If the context line is wider than its budget, then the system shall shorten the names by the context fit of CTX-SHELL. | Yes; tested. |
| R-TUI-036.3 | When | When the terminal is resized, the system shall fit the context line to the new width. | Yes; tested. |
| R-TUI-036.4 | U | The system shall show the context line without control characters and without markup. | Yes; tested. |

#### S6.5b · The progress of a long action (from batch-100 HLR-176, HLR-176a, HLR-176b, HLR-176c, HLR-176d; CTX-BUSY)

The look (one row in the accent colour, the glyph, the step, the elapsed time, no cancel) is the P-D prototype verdict A of batch-100; it is written here as requirements, not prototype first (D6-32).

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROGRESS-LINE.1 | When | When a long action begins, the system shall show its progress line at step 1 and `00:00` as the status text. | Yes; tested (`test_tc_b100_50_begin_paints_the_first_progress_line`, `test_tc_b100_50_each_worker_action_begins_with_a_progress_line`, `test_tc_b100_51_action_table_names_the_seven_long_actions`, `test_tc_b100_66_progress_lines_carry_no_decision_id`: the labels and steps are the CTX-BUSY words, no decision id). Per action: S12 R-RPT-LOG.1, S14 R-CMP-005.13, R-BEFORE-AFTER-REPORT-001.31. |
| R-PROGRESS-LINE.2 | While | While a long action runs, the system shall show the progress line of the shown action as the status text. | Yes; tested (`test_tc_b100_50_status_line_has_one_owner_during_a_worker_load`, `test_tc_b100_50_file_state_waits_while_a_run_is_shown`, `test_tc_b100_50_image_pick_file_state_waits_for_a_running_report`). |
| R-PROGRESS-LINE.3 | While | While the shown action runs a step that is not a held step, the system shall advance the glyph of the progress line to the next frame every 0.1 s. | Yes; tested (`test_tc_b100_50_spinner_and_elapsed_advance_while_a_worker_runs`, `test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys`, `test_tc_b100_53_case06_project_load_keeps_the_loop_free_and_reports_parse_bytes`, `test_tc_b100_53_case06_a2l_attach_keeps_the_loop_free_and_reports_parse_bytes`, `test_tc_b100_53_held_save_keeps_the_loop_free`, `test_tc_b100_53_workarea_data_pick_parses_on_the_file_load_worker`). Held steps: D6-35. A2L load: S2 R-A2L-004.10. |
| R-PROGRESS-LINE.4 | While | While the shown action runs a step that is not a held step, the system shall show in the progress line the elapsed time since the action began. | Yes; tested (`test_tc_b100_50_elapsed_is_minutes_and_seconds`, `test_tc_b100_50_spinner_and_elapsed_advance_while_a_worker_runs`, `test_at_b100_18_worker_half_case06_project_load_by_keys`). |
| R-PROGRESS-LINE.5 | When | When a long action reaches a step, the system shall show the step's number and name in the progress line before the step's work starts. | Partly: the typed file load copies the file before the screen is drawn again, so `Copy into the work area` cannot show (D6-46); tested for the other steps (`test_tc_b100_50_steps_by_index_set_the_bar`, `test_tc_b100_52_a2l_tag_table_step_is_painted_before_the_build`, `test_tc_b100_52_project_install_step_is_painted_before_the_install`). |
| R-PROGRESS-LINE.6 | If | If a long action has no work for one of its steps, then the system shall leave that step out of the progress line. | Yes; tested (`test_tc_b100_51_project_load_without_an_a2l_skips_its_step`, `test_tc_b100_53_in_place_a2l_pick_starts_at_the_parse_step`; the A2L case is S2 R-A2L-004.12). |
| R-PROGRESS-LINE.7 | If | If a long action is refused before its work begins, then the system shall show no progress line for it. | Yes; tested (`test_tc_b100_51_diff_report_without_a_comparison_begins_nothing`, `test_tc_b100_51_save_project_reports_its_phases_as_steps`: a name refused in the dialog). |
| R-PROGRESS-LINE.8 | U | The system shall show each name inside a progress line, a busy line or a quit question in the `<name>` form of CTX-BUSY. | Yes; tested (`test_tc_b100_50_names_paint_literally_through_load_from_path`, `test_tc_b100_53_busy_line_paints_a_hostile_name_literally`) (D6-41). |
| R-PROGRESS-LINE.9 | U | The system shall show the progress line as plain text, never as markup. | Yes; tested (`test_tc_b100_50_names_paint_literally_through_load_from_path`). |
| R-PROGRESS-LINE.10 | While | While a long action runs, the system shall draw the status text in the accent colour `#91abec`. | Yes; tested (`test_tc_b100_50_running_line_paints_in_the_accent`: back to the idle colour after the last end). |
| R-PROGRESS-LINE.11 | While | While a long action runs, the system shall keep the status text on one row, cutting a longer progress line with `…`. | Yes; tested (`test_tc_b100_50_long_label_stays_on_one_row`). |
| R-PROGRESS-SHOWN.1 | If | If a long action begins while another long action runs, then the system shall show the progress of the newer action. | Yes; tested (`test_tc_b100_50_a_newer_action_is_the_one_shown`). |
| R-PROGRESS-SHOWN.2 | When | When a long action ends while other long actions still run, the system shall show the progress of the most recently begun one still running. | Yes; tested (`test_tc_b100_50_the_newest_running_action_is_shown_after_an_end`, `test_tc_b100_50_ending_a_middle_run_shows_the_newest_remaining`). |
| R-PROGRESS-SHOWN.3 | If | If a long action begins while the same action already runs, then the system shall restart its progress line at step 1 and `00:00`. | Yes; tested (`test_tc_b100_50_a_begin_under_a_running_key_restarts_it`, `test_tc_b100_50_a_restarted_key_becomes_the_newest_run`). |
| R-PROGRESS-SHOWN.4 | If | If a run of a long action that a newer run of the same action replaced ends, then the system shall leave the shown progress unchanged. | Yes; tested (`test_tc_b100_50_unknown_or_replaced_run_leaves_the_indicator`). |
| R-PROGRESS-BAR.1 | When | When the shown action reaches step n of m without an amount, the system shall set the progress bar to the bar value of CTX-BUSY. | Yes; tested (`test_tc_b100_50_steps_by_index_set_the_bar`, `test_tc_b100_51_file_load_ends_once_on_success`, `test_tc_b100_51_save_project_reports_its_phases_as_steps`). Per action: S12 R-RPT-LOG.2, S14 R-CMP-005.14. |
| R-PROGRESS-BAR.2 | When | When a step of the shown action reports an amount, the system shall set the progress bar to the bar value of CTX-BUSY. | Yes; tested (`test_tc_b100_50_step_amount_moves_the_bar_within_the_step`, `test_tc_b100_50_a_falling_amount_never_lowers_the_bar`). The A2L parse's amount (bytes read): S2 R-A2L-004.11. |
| R-PROGRESS-BAR.3 | When | When Save project places one file of its save plan, the system shall report the files placed of the files planned as the amount of the step `Place the files`. | Yes; tested (`test_tc_b100_53_save_reports_each_file_placed`, `test_tc_b100_53_a_two_thousand_file_save_moves_the_bar_ten_times`, `test_tc_b100_53_save_reports_the_change_document_as_one_placed_file`). |
| R-PROGRESS-BAR.4 | U | The system shall show no time estimate beside the progress bar. | Yes; tested (`test_tc_b100_50_progress_bar_paints_no_eta`). |
| R-PROGRESS-BAR.5 | U | The system shall show the message lines at the same rows whether or not a long action runs. | Yes; tested (`test_tc_b100_50_the_bar_keeps_its_row_when_idle`). |
| R-PROGRESS-END.1 | When | When a long action ends with an outcome, the system shall show the outcome as the newest message. | Yes; tested (`test_tc_b100_50_end_writes_the_outcome_to_the_status_log`, `test_tc_b100_51_file_load_ends_once_on_success`, `test_tc_b100_51_file_load_into_an_open_project_ends_after_the_sync`, `test_tc_b100_51_report_ends_once_on_success`, `test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome`, `test_tc_b100_51_before_after_ends_once_and_logs_its_outcome`, `test_tc_b100_51_save_project_mismatch_tail_ends_with_the_mismatch`, `test_tc_b100_54_project_worker_failure_keeps_the_session`: the failure line is the newest message and no run is left). Per action: S14 R-CMP-005.15. |
| R-PROGRESS-END.2 | When | When the last running long action ends, the system shall show the file status as the status text. | Yes; tested (`test_tc_b100_50_last_end_paints_the_stored_file_state`, `test_tc_b100_50_last_end_stops_the_timer`, `test_tc_b100_50_action_shorter_than_a_tick`, `test_tc_b100_51_project_load_ends_once_on_success`). |
| R-PROGRESS-END.3 | When | When the last running long action ends, the system shall set the progress bar to 0 %. | Yes; tested (`test_tc_b100_50_last_end_clears_the_bar`, `test_tc_b100_51_report_ends_once_on_a_failure`, `test_tc_b100_51_file_load_ends_once_on_a_parse_failure`, `test_tc_b100_51_save_project_ends_once_on_a_placement_failure`, `test_tc_b100_51_file_load_ends_once_on_a_containment_refusal`, `test_tc_b100_51_project_load_ends_once_on_a_failure_after_the_begin`). Per action: S12 R-RPT-LOG.3, .4. |
| R-PROGRESS-END.4 | If | If an unexpected error stops a long action whose chapter gives no outcome for that error, then the system shall end the action with the outcome `<label> failed`. | Yes; tested (`test_tc_b100_50_kickoff_raise_ends_the_file_load_first`, `test_tc_b100_50_worker_raise_ends_the_action_first`, `test_tc_b100_50_project_raise_ends_the_action_first`, `test_tc_b100_50_twelve_b_kickoff_raise_ends_the_run_first`, `test_tc_b100_50_twelve_b_handler_raise_ends_the_run_first`, `test_tc_b100_50_project_deferred_install_raise_ends_the_run`, `test_tc_b100_50_a2l_deferred_install_raise_ends_the_run`). Where Save project gives its own line, that line ends the action and `Saving project <name> failed` is not shown (`test_tc_b100_51_save_validation_abort_ends_with_its_own_line`, `test_tc_b100_51_raise_after_the_commit_keeps_the_saved_line`, `test_tc_b100_51_raise_after_a_multi_line_tail_paints_the_saved_line_once`). |
| R-PROGRESS-END.5 | U | The system shall add no progress line and no step name to the message lines. | Yes; tested (`test_tc_b100_51_file_load_ends_once_on_success`, `test_tc_b100_51_a2l_load_ends_once_on_success`). |

### S6.6 · Layout, density and theme (CTX-THEME)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-023.1 | U | The system shall switch every window between its wide and its narrow layout at a terminal width of 120 columns. | Yes; tested. |
| R-TUI-023.2 | When | When the terminal is resized across 120 columns, the system shall switch the layout without a restart. | Yes; tested. |
| R-TUI-023.3 | U | The system shall lay out every window at 80×24, 120×30 and 160×40 as its approved captures show. | Yes; tested (snapshot baselines). |
| R-TUI-023.4 | When | When the system starts, the system shall use the comfortable density. | Yes; tested. |
| R-TUI-023.5 | When | When the operator presses Ctrl+D, the system shall switch between the comfortable and the compact density. | Yes; tested. |
| R-TUI-023.6 | When | When the density changes, the system shall show the status `Density: compact` or `Density: comfortable`. | Yes. |
| R-TUI-023.7 | While | While the density is compact, the system shall draw the Workspace panes without top and bottom padding. | Yes; only the Workspace changes (D6-31, prototype first). |
| R-TUI-024.1 | U | The system shall draw every window in the dark theme of CTX-THEME. | Yes; tested. |
| R-TUI-024.2 | U | The system shall use one accent colour, `#91abec`. | Yes; tested. |
| R-TUI-024.3 | U | The system shall offer no light theme. | Partly: Textual's Ctrl+P palette offers a Theme command with light themes (D6-13). |
| R-TUI-024.4 | U | The system shall draw the odd rows of striped tables in `#131a2c`. | Yes. |
| R-TUI-065.1 | U | The system shall write every human-readable size in the format of CTX-THEME. | Yes; tested. |

### S6.7 · Viewer settings (CTX-THEME)

Shared with S2 R-TUI-019.3 (A2L and MAC page sizes) and S4 (the main hex view's page size).

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SHELL-SETTINGS.1 | When | When the system starts, the system shall use page sizes of 200 hex rows, 200 A2L tags and 100 MAC rows. | Yes; tested. |
| R-SHELL-SETTINGS.2 | When | When the operator runs `Viewer settings` from the palette, the system shall show the viewer settings menu of CTX-THEME. | Yes. |
| R-SHELL-SETTINGS.3 | When | When the operator selects a size in the viewer settings menu, the system shall use it as that view's page size. | Yes; tested. |
| R-SHELL-SETTINGS.4 | When | When the operator selects a size in the viewer settings menu, the system shall show the status `Updated <view> to <n>.` with the menu's view name. | Partly: the status names the internal setting, `Updated hex_rows_page_size to 50.` (D6-27). |
| R-SHELL-SETTINGS.5 | When | When the operator presses Escape in the viewer settings menu, the system shall close the menu. | No: once open, the menu cannot be closed (D6-26). |

### S6.8 · Session actions: the busy refusal and the quit question (CTX-BUSY; batch-100)

What each session action does, refuses on its own and reports on failure stays in its chapter (S5, S2, S11; D6-42). This section holds what happens around it. Rows that live with their surface: the Patch Editor's refused controls and its read-only paste buffer during a project load (S10 R-PE-110, R-PE-111); Generate new report keeps the session's regions during a session action (S12 R-RPT-002.28).

#### S6.8a · Keys and refusals while a session action runs (from batch-100 HLR-177, HLR-177a)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-BUSY-RUN.1 | While | While a long action runs a step that is not a held step, the system shall act on the keys the operator presses. | Yes; tested (`test_at_b100_18_refusal_half_l_during_a_save_by_keys`, `test_tc_b100_53_load_requests_are_refused_during_a_project_load`). Held steps: D6-35. A2L load: S2 R-A2L-004.10. |
| R-BUSY-REFUSE.1 | If | If the operator makes a request of the refused list of CTX-BUSY while a session action runs, then the system shall show the busy line. | Yes; tested (`test_tc_b100_53_session_writers_are_refused_during_a_save`, `test_tc_b100_53_load_requests_are_refused_during_a_project_load`, `test_tc_b100_53_variant_unload_and_save_are_refused_while_busy`, `test_tc_b100_53_patch_editor_changes_are_refused_while_busy`, `test_tc_b100_53_patch_editor_continuations_are_refused_while_busy`, `test_tc_b100_53_action_starts_refuse_while_another_session_action_runs`, `test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit`, `test_tc_b100_53_a_running_file_load_refuses_a_project_load_and_asks_before_quitting`, `test_at_b100_18_refusal_half_l_during_a_save_by_keys`, `test_tc_b100_66_busy_line_and_quit_question_hold_no_decision_ids`). The change-file dropdown pick is not driven by a test (D6-43). Which Patch Editor requests are refused: S10 R-PE-110. |
| R-BUSY-REFUSE.2 | When | When the system refuses a request as busy, the system shall leave the session unchanged. | Yes; tested (`test_tc_b100_53_session_writers_are_refused_during_a_save`, `test_tc_b100_53_busy_line_names_the_action_and_changes_nothing`). |
| R-BUSY-REFUSE.3 | When | When the system refuses a request as busy, the system shall keep the focus on the widget that held it. | Yes; tested (`test_tc_b100_53_busy_line_names_the_action_and_changes_nothing`). |
| R-BUSY-REFUSE.4 | When | When the system refuses a request as busy, the system shall open no dialog. | Yes; tested (`test_tc_b100_53_load_requests_are_refused_during_a_project_load`, `test_tc_b100_53_variant_unload_and_save_are_refused_while_busy`). |
| R-BUSY-REFUSE.5 | When | When the system refuses a request as busy, the system shall keep the progress line as the status text. | Yes; tested (`test_tc_b100_53_busy_line_names_the_action_and_changes_nothing`). |
| R-BUSY-REFUSE.6 | If | If a load route that would ask the load question is refused as busy, then the system shall ask no load question. | Yes; tested (`test_tc_b100_72_the_load_guard_refuses_while_busy_before_it_asks`). |
| R-BUSY-REFUSE.7 | While | While a session action runs, the system shall accept a request for a project report, a diff report or a before/after report. | Yes; tested for the project report (`test_tc_b100_53_report_generate_keeps_the_regions_of_a_running_save`: the report runs during a Save); the diff and before/after entry points have no busy check (`SESSION_ACTION_KEYS`, `app.py:429-431`), untested. The regions rule of that Generate is S12 R-RPT-002.28. |
| R-BUSY-REFUSE.8 | While | While no session action runs, the system shall accept every request of the refused list of CTX-BUSY. | Yes; tested (`test_tc_b100_53_busy_line_names_the_action_and_changes_nothing`: a report running alone; `test_tc_b100_53_refusals_stop_after_each_project_load_exit`: after a success, a failure and an error). |

#### S6.8b · Quit while a session action runs (from batch-100 HLR-177b, HLR-177c)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-QUIT.1 | When | When the operator presses `q` or Ctrl+Q, or runs `Quit` from the palette, while a session action runs, the system shall show the quit question of CTX-BUSY. | Yes; tested (`test_tc_b100_53_quit_asks_only_while_a_session_action_runs`, `test_tc_b100_53_idle_quit_under_the_load_question_keeps_the_key`, `test_at_b100_18_quit_half_q_during_a_save_asks_with_stay_focused`, `test_tc_b100_66_busy_line_and_quit_question_hold_no_decision_ids`) (D6-36). |
| R-QUIT.2 | When | When the system shows the quit question, the system shall put the focus on its `Stay (n)` button. | Yes; tested (`test_at_b100_18_quit_half_q_during_a_save_asks_with_stay_focused`, `test_tc_b100_53_quit_asks_only_while_a_session_action_runs`). |
| R-QUIT.3 | U | The system shall draw `Stay (n)` as the emphasised button of the quit question. | Yes; tested (`test_tc_b100_53_quit_question_emphasises_the_safe_answer`) (D6-37). |
| R-QUIT.4 | U | The system shall show the quit question's text as plain text, never as markup. | Yes (`screens.py:1530`, `markup=False`; the label is a `<name>` form, R-PROGRESS-LINE.8). |
| R-QUIT.5 | If | If the operator asks to quit while the quit question is open, then the system shall open no second quit question. | Yes; tested (`test_tc_b100_53_quit_asks_only_while_a_session_action_runs`). |
| R-QUIT.6 | When | When the operator answers the quit question with Stay, the system shall keep running after the session action ends. | Yes; tested (`test_tc_b100_53_stay_keeps_the_save_running`, `test_tc_b100_53_quit_boundaries`: Stay after an earlier Quit). |
| R-QUIT.7 | While | While a quit is confirmed and the session action still runs, the system shall keep running. | Yes; tested (`test_tc_b100_53_confirmed_quit_waits_for_the_end`, `test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder`). |
| R-QUIT.8 | When | When a session action completes while a quit is confirmed, the system shall quit. | Yes; tested (`test_tc_b100_53_confirmed_quit_waits_for_the_end`, `test_tc_b100_53_confirmed_quit_during_a_routed_project_load_exits_cleanly`, `test_tc_b100_53_quit_boundaries`). |
| R-QUIT.9 | If | If a session action fails while a quit is confirmed, then the system shall withdraw the confirmed quit. | Yes; tested (`test_tc_b100_53_confirmed_quit_is_withdrawn_when_the_load_fails`, `test_tc_b100_53_confirmed_quit_waits_for_the_end`: the failing save). |
| R-QUIT.10 | If | If Save project completes with an unsaved-work line while a quit is confirmed, then the system shall withdraw the confirmed quit. | Yes; tested (`test_tc_b100_53_confirmed_quit_is_withdrawn_when_pasted_entries_were_not_saved`, `test_tc_b100_53_confirmed_quit_is_withdrawn_when_editor_edits_stay_unsaved`). |
| R-QUIT.11 | When | When the operator answers the quit question with Quit after the session action has ended, the system shall quit. | Yes; tested (`test_tc_b100_53_quit_boundaries`). |
| R-QUIT.12 | When | When the system quits on a confirmed quit, the system shall leave no partly written project folder in the work area. | Yes; tested (`test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder`, `test_tc_b100_53_confirmed_quit_waits_for_the_end`). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D6-1 | Batch records in the rows: batch ids, LLR traces, test ids, "AST guard", "frozen engine diff = 0", "supersedes", file and function names. | Out of the requirements; they stay in the batch records. |
| D6-2 | R-TUI-021 names eight rail items on keys `1`–`8`; the code has twelve (`app.py:265-271`, keys `app.py:1700-1716`) plus Split / Join / Export from the palette (`app.py:7360-7363`). | Rows follow the code (CTX-SHELL). |
| D6-3 | The command bar row (find, go-to, project and A2L labels) was deleted in batch 79 (`command_bar.py:79-84`); R-TUI-022, 033, 036 and 016 still require it. | Palette rows; `/` acts on the window's own box; the names move to the context line (`app.py:14723-14726`). |
| D6-4 | R-TUI-DISCOVER-001 requires an A2L Legend button; it was dropped (`tests/test_discoverability.py` docstring). `k` opens the legend on every window. | Follow the code; the legend key is S3 R-LEGEND-MODAL-001.1. |
| D6-5 | R-TUI-024 carries the palette history of batch 47 (before → after hex values). | Today's values in CTX-THEME; the history stays in the batch record. |
| D6-6 | R-TUI-065 specifies a module, constants and four helper functions. | One observable row (R-TUI-065.1); the rest is design. |
| D6-7 | R-TUI-003 is superseded history. | Deleted. |
| D6-8 | R-TUI-030 asks for an empty-state panel on every window; four windows have one (`app.py:7658-7663`), the rest show their own content. | The four stay in S5 R-TUI-029.4; here: never blank, never an error (R-TUI-030.1, .2). |
| D6-9 | `q` and Ctrl+Q quit at once, with unsaved Patch Editor or flow edits too. | Keep. A quit confirmation would be a new feature; not proposed. **Partly superseded by D6-36**: while a session action runs, quit asks first. |
| D6-10 | The window behind a key is S6's; what the key does is the window's chapter (`c` → S16 although `action_confirm_attention` is in the S6 file list). | Rule D-9: CTX-KEYS names the chapter of each command. |
| D6-32 | Batch-100 (Inc 12a `63b651d`, Inc 12b `9e4dd3b`, HLR-176 … HLR-176d, HLR-177 … HLR-177c) adds the progress of seven long actions on the status text and the bar, a busy refusal of session writers, and a quit question. The look was settled by the P-D prototype verdict A (ledger LED .2: the status line, the bar kept, no cancel) and the `bz-busy` and `qz-quit` captures. | Written as rows S6.5b, S6.8a, S6.8b; CTX-BUSY holds the action table (`app.py:366-400`), the formats (`app.py:20371-20379`, `_BUSY_LINE` `app.py:434`, the quit texts `app.py:437-439`) and the refused list. Not prototype first. |
| D6-33 | The batch text also states how: worker threads, `call_from_thread`, one 0.1 s timer object, run generations, the action table as code, frozen request objects, session writes on the main thread only, a parser callback, AST censuses, thread-id probes, timing bounds, mutation plans and ledger history. | Out of the requirements (implementation and process, as D6-1). What the operator sees stays: the line advances, the keys act, the held steps (CTX-BUSY). |
| D6-34 | Tests that verify implementation only (each id below also has nodes cited in a row): `test_tc_b100_12_rehome_lands_synchronously`; `test_tc_b100_50_begin_busy_is_called_only_from_the_one_label_helper`, `test_tc_b100_50_progress_widgets_are_written_on_the_main_thread`, `test_tc_b100_50_twelve_b_progress_reaches_the_widgets_from_workers_on_main`, `test_tc_b100_50_out_of_range_step_data_is_clamped`, `test_tc_b100_50_overlapping_runs_share_one_timer`, `test_tc_b100_50_a_begin_after_the_last_end_starts_one_timer`, `test_tc_b100_50_a_stale_failure_logs_nothing`, `test_tc_b100_50_a2l_success_posts_no_failure_end`; `test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event`, `test_tc_b100_51_only_the_seam_sets_the_bar`, `test_tc_b100_51_workers_take_the_run_generation`, `test_tc_b100_51_twelve_b_seam_sites_sit_in_the_workers_and_handlers`, `test_tc_b100_51_every_save_abort_return_ends_its_run_first`, `test_tc_b100_51_file_load_reads_the_copy_size_before_the_worker`; `test_tc_b100_53_project_load_reads_every_file_on_a_worker`, `test_tc_b100_53_every_a2l_attach_route_parses_on_a_worker`, `test_tc_b100_53_session_is_written_only_on_the_main_thread`, `test_tc_b100_53_workers_read_only_their_frozen_request`, `test_tc_b100_53_save_rederives_on_main_before_the_worker`, `test_tc_b100_53_running_session_action_ignores_reports`. | Listed, not cited in rows (D6-33). No TC/AT id of HLR-166, HLR-176* or HLR-177* is implementation-only as a whole. |
| D6-35 | Four steps hold the screen: the file load's `Copy into the work area` (typed path) and `Install`, the A2L load's `Build the tag table` (about 3.5 s for case_06) and the project load's `Install`. The glyph, the elapsed time and the keys wait until they end. Batch-100 declared this limit (HLR-176a rationale, LLR-176.3, LLR-177.1k note, E2 ruling P2-8) and shows the step name first. | Keep; rows R-PROGRESS-LINE.3, .4 and R-BUSY-RUN.1 leave the held steps out (CTX-BUSY). A later batch may move them off the screen's thread. |
| D6-36 | Quit. D6-9 kept "quit at once" and proposed no confirmation. Batch-100 HLR-177b, HLR-177c (Inc 12b, `action_quit` `app.py:20464-20482`) asks the quit question while a session action runs, and quits only after the action ends; quitting mid-save had left partial project folders. Both describe the quit key. | Batch-100 wins for that state (newer, ruled with captures). D6-9 still holds while no session action runs (quit at once, also with unsaved edits). R-SHELL-START.5 changed; R-QUIT.1 … .12 added. D6-9 marked partly superseded. |
| D6-37 | The quit question's emphasis on `Stay (n)` came from the fix-round-2 ruling OBS-12b-2 ("the safe default carries the emphasis", `app.py:442-450`, `screens.py:1532-1541`), after the `qz-quit` captures, not from a prototype round of its own. | Written as R-QUIT.3; not prototype first: the batch's captures and ruling settled it, and it reuses the load question's look. |
| D6-38 | CTX-KEYS named `Load file` (Ctrl+L, `l`) and `Load project` (`p`). Batch-100 renamed them `Load` and `Projects` (LLR-173.2m, removed at Inc 9b by its ruling Q8 and restored at Inc 12a; snapshots `4dfb5a1`; `app.py:2655`, `2660`, `2668`; `test_tc_b100_41_labels_key_bar_and_palette_say_load_and_projects`). The key panel and S7's key bar show the same labels. | CTX-KEYS follows the code. |
| D6-39 | R-SHELL-FOCUS.3, .4 said "when a load ends". Batch-100 HLR-166 (LLR-166.1, .2; LED .57 … .59) re-homes the focus only when a load completes (a failed load leaves it), and also when a load is cancelled (`app.py:8178-8180`, `15051-15052`); a frame widget (the palette filter, the rail) is never taken; the Load-result panel gives the focus back to the widget behind it (`app.py:8664-8687`). | R-SHELL-FOCUS.3, .4 changed; R-FOCUS-LOAD.1 added. |
| D6-40 | Open points re-checked at 570b4b5. (a) D6-20: Hex+ is still bound as `period` (`app.py:2704`); batch-100 did not touch it. Fix round 1's "LLR-171.1m rebind gate host-neutral" is the change-document rebind of a project row (a `..` path, `fix-round-1.md` CI11-1), not key handling. (b) Priority keys behind dialogs (S7 D7-23): Ctrl+K, Ctrl+D, Ctrl+L and Ctrl+S now do nothing while the Load dialog, a question (the load question or the quit question) or the Save project dialog is on the stack (`check_action`, `app.py:9253-9257`; Inc 9b, 10, 11). Behind every other dialog they still act (S7 counts 14 such dialogs, D7-23; a JSON edit dialog leaves Ctrl+S live: `test_tc_b100_53_patch_editor_continuations_are_refused_while_busy`). Inside the Load dialog a printable key goes into its path box (S7 R-LOADDLG.9, .10). Ctrl+Q acts behind every dialog: idle it quits, during a session action it shows the quit question. | D6-20 stays open (reproduce first). The dialog half is S7's R-DLG.1 (passed). R-TUI-031.2 unchanged. |
| D6-41 | Names in a progress line, the busy line and the quit question also lose Unicode format characters (U+202E) and are cut at 120 characters (`_busy_begin_action` `app.py:20381-20406`, `painted_names` `services/project_gather_service.py:967`). S1 R-TUI-103a keeps every character that is not a control character. | Batch-100 rule kept (LLR-176.1r): CTX-BUSY `<name>`, R-PROGRESS-LINE.8. Passed to S1 as a stricter view. |
| D6-42 | LLR-177.1f … .1k and LLR-177.2 … .2c state what a load or Save project installs, refuses and reports when its work fails (`could not be read`, `could not save`, the A2L attach's early refusals). That is each action's own behaviour. | Rule D-9: they move to S11 (project load, Save project), S5 (file load, Workarea Files pick, A2L attach failure) and S2 (A2L attach refusals); passed. S6 keeps the progress, busy and quit behaviour. |
| D6-43 | A Patch Editor JSON edit dialog whose result arrives during a session action loses the typed JSON; the busy line says why (LLR-177.3e continuations, ruling P2-5). The change-file dropdown arm is not driven by a test (tester note in `test_tc_b100_53_patch_editor_continuations_are_refused_while_busy`). | Keep (batch ruling); the refused list names the dialog results. |
| D6-44 | R-SHELL-STATUS.6 said "When a load reports progress, show it in the progress bar"; at 093a7c0 a load set fixed values (10, 50, 100 %). At 570b4b5 every long action drives the bar by its steps and returns it to 0 % (`begin_busy` / `step_busy` / `end_busy`, `app.py:20213-20355`). | R-SHELL-STATUS.6 rewritten to the begin rule; the step and end rules are R-PROGRESS-BAR.1, .2 and R-PROGRESS-END.3. |
| D6-45 | The batch-100 sweep wrote each long action's own progress rows with the action (rule D-9): S2 R-A2L-004.10 … .12 (the A2L load's responsiveness, its bytes-read bar, the in-place pick at Parse), S10 R-PE-110, R-PE-111 (the Patch Editor's busy refusals, the read-only paste buffer), S12 R-RPT-LOG.1 … .4, R-RPT-002.28 (the report's steps and bar; Generate keeps the regions during a session action), S14 R-CMP-005.13 … .15, R-BEFORE-AFTER-REPORT-001.31. S12 D12-29 and S14 D14-22 rely on S6 stating that reports are not session actions. | S6 keeps only the shared rules and cites those rows; the duplicate S6 rows for the A2L bytes-read bar, the Generate regions and the paste buffer were dropped before publication. CTX-BUSY defines the three reports as not session actions; R-BUSY-REFUSE.7, .8 state that a report is never refused and refuses nothing. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D6-11 | The rail's ASCII glyph fallback (`rail.py:47-49`, `ascii_mode`) has no switch: the app always builds the rail without it (`app.py:2322`). Only a test turns it on. | Delete it and its test. |
| D6-12 | `action_view_main` and `action_view_mac` (`app.py:8175-8185`) have no key and no caller; `_toggle_settings_menu` (`app.py:14536`) has no caller. | Delete the two actions; reuse `_toggle_settings_menu` for D6-26 or delete it. (`ScreenScaffold` is already removed by S5 D5-9.) |
| D6-13 | Ctrl+P opens Textual's own palette (`textual/app.py:441`): Theme (lists light themes, `textual/theme.py:81`), Keys (same as `?`), Quit (same as `q`), Screenshot (a developer tool). Key bar row 1 shows it as `^p palette` beside `^k Palette`: two palettes, one label. The key bar takes Textual's theme colours (`styles.tcss:3549-3580`), so a theme change recolours it. | Switch Textual's palette off; one palette (R-TUI-022.11, R-TUI-024.3). Row 1 loses `^p palette` (S7 R-KEYBAR.2). |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D6-20 | The Hex+ key is bound as `period` (`app.py:1720`; at 570b4b5 `app.py:2704`, unchanged, D6-40). Textual names the `.` key `full_stop` (`textual/keys.py:341-357`) and keeps a binding's name as written (`textual/binding.py:153-154`), so a real `.` never matches; the key bar still shows `. Hex+`. Tests press the synthetic name `period`, so they pass. Read from the code, not reproduced on a terminal. | Bind the name a keyboard sends; a test that presses `.` by character (R-SHELL-KEYS.1). Reproduce first. |
| D6-21 | A rail key hides the old window but leaves the focus in it (`app.py:7408-7486` moves no focus; `tests/test_b100_focus.py` AT-B100-04 builds this state on purpose). The hidden window's keys then act, and `?` opens the hidden window's help. | Put the focus on the new window's focus target, as the load tail does (R-SHELL-FOCUS.2). |
| D6-22 | A rail item takes the focus (`rail.py:94`, startup focus `app.py:6742`) but has no key binding; Enter does nothing. | Enter shows the item's window (R-TUI-021.5). |
| D6-23 | The palette has no Escape (`app.py:8142-8157` records it as a carry). | Escape closes it (R-TUI-022.9). |
| D6-24 | The palette lists every command; one that cannot act on the shown window (`check_action`, `app.py:7488-7513`) does nothing when chosen, with no message. The key bar leaves such keys out. | Use the key bar's check for the palette list too (R-TUI-022.10). |
| D6-25 | `+` and PgDn are both labelled `Page+`, `-` and PgUp both `Page-` (`app.py:1717-1726`): two palette entries each, with different commands. | Distinct labels, for example `Page down` and `Page up` for PgDn and PgUp (R-TUI-022.3). |
| D6-26 | `Viewer settings` opens the menu only if hidden (`app.py:8018-8023`); nothing hides it again, so it stays open (12 rows) for the session. | Escape and a second `Viewer settings` close it (R-SHELL-SETTINGS.5). |
| D6-27 | The settings status names the internal attribute (`app.py:14583`). | Use the menu name: `Updated Hex rows to 50.` (R-SHELL-SETTINGS.4). |
| D6-28 | Message lines are `markup=False` but keep control characters (`app.py:15241-15253`); messages embed file names. | Remove them; the message lines join S1's safe-text views (R-SHELL-STATUS.5). **Done** in batch-100 Inc 12a (`4cedb23`, SE5-12a-1): every message passes the safe-text scrub (`_append_log_line`, `app.py:20161-20175` at 570b4b5). |
| D6-46 | The typed file load begins its progress, then copies the file on the screen's thread before the screen is drawn again (`load_from_path`, `app.py:15117-15124`), so step 1 `Copy into the work area` cannot show; the line first shows at `Parse`. The A2L tag-table build and the project install paint their step first (`call_after_refresh`, `app.py:15311-15312`, `13656-13657`). Read from the code, not reproduced. | Paint step 1 before the copy, the same way (R-PROGRESS-LINE.5). Reproduce first. |

**Prototype first** (visual; prototype round with real captures and the operator's verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D6-30 | The rail shows glyph and label, no key (`rail.py:171-172`; its own docstring says `<position-key> <glyph>  <label>`). `=` and `]` cannot be guessed. | Where each item's key shows, wide and narrow (the narrow rail is 4 columns). |
| D6-31 | Ctrl+D is a global key on key-bar row 1 but changes only the Workspace panes' padding (`styles.tcss:204-210`). | What compact means on each window, or whether the key and its row-1 token go. |

**Passed to other groups**

- **S1**: the message lines join the safe-text views (D6-28).
- **S2**: R-TUI-020 (context paging) stays there; the viewer settings rows here set the A2L and MAC page sizes of R-TUI-019.3.
- **S4**: the `.` key defect (D6-20) breaks Hex+ paging on the Workspace; `g` stays R-TUI-040.1 and Enter in the boxes stays D4-1.
- **S5**: R-TUI-029.4 keeps the empty state of the four windows; the Loaded panel's project row is S5's.
- **S7**: the key bar (CTX-KEYBAR), the window help behind `?`, and the keys that act behind an open dialog.
- **S16**: `c` (Confirm on Flow Execution).
- Batch-100 reconciliation (2026-11-01), details in `passed-S6.md`:
  - **S1**: names in the progress line, the busy line and the quit question follow a stricter scrub than R-TUI-103a (format characters removed, cut at 120; D6-41); the message lines now drop control characters (D6-28 done).
  - **S2**, **S5**, **S11**: the load and save results and failures of LLR-177.1f … .1k and LLR-177.2 … .2c (D6-42); S5's CTX-FILES "progress line" and R-TUI-012L.6 are replaced by S6.5b; S5 R-TUI-012L.5 and D5-15 are settled by Inc 12b.
  - **S7**: R-DLG.1 / D7-23 partly settled (D6-40); the quit question is a dialog whose text and answers are here (CTX-BUSY, S6.8b); the `Load` / `Projects` labels (D6-38).
  - **S10**: R-PE-110, R-PE-111 (written by the batch-100 sweep) are cited, not repeated, by S6.8a.
  - **S12**, **S14**: R-RPT-LOG.1 … .4, R-RPT-002.28, R-CMP-005.13 … .15, R-BEFORE-AFTER-REPORT-001.31 (written by the sweep) are cited by S6.5b and S6.8a; reports are not session actions (R-BUSY-REFUSE.7, .8).

---

**Received from later groups** (after all groups were written)

- S6.1 (S2: MAC View header and `?` chip; A2L help "section tree") → covered by S7 R-WHELP.3 (D7-30) and R-WHELP.12 (D7-26); the frame rows here need no change.
- S6.2 (S4: hex page size in the viewer settings) → covered by R-SHELL-SETTINGS.1, .3 (S6.7 names S4's page size).
- S6.3 (S7: keys behind an open dialog; `.` in the key bar) → row R-TUI-031.2 now covers the text boxes of the shown window only, so it no longer contradicts S7 R-DLG.1 (D7-23); `.` stays R-SHELL-KEYS.1 (D6-20) and S7 R-KEYBAR.15.
- S6.4 (S9: Checks and Check Editor rail positions and keys) → covered by CTX-SHELL (positions 11 and 7, keys `9` and `=`), R-TUI-021.1, .3.
- S6.5 (S10: Ctrl+Z / Ctrl+Y and the key bar that dims them) → covered by CTX-KEYS and R-SHELL-KEYS.1; the dimming is S7 CTX-KEYBAR, R-KEYBAR.6.
- S6.6 (S11: R-TUI-016 cites CTX-PROJECT; keys `s`, Ctrl+S, `p`, `v`) → covered by R-TUI-016.1 … .4 (CTX-SHELL now cites S11 CTX-PROJECT) and CTX-KEYS.
- S6.7 (S12: `t` and the palette entry for Reports) → covered by CTX-KEYS (`t`, View reports), R-SHELL-KEYS.1, R-TUI-022.2.
- S6.8 (S13: `x` and `0`; "eight rail items" retired) → covered by CTX-KEYS (`x`), CTX-SHELL (position 12, key `0`); no S6 row counts rail items.
- S6.9 (S14: A2B Diff position 8, key `7`) → covered by CTX-SHELL.
- S6.10 (S16: `8`, `]`; `c` on Flow Execution only) → covered by CTX-SHELL (positions 9, 10), CTX-KEYS (`c`), R-SHELL-KEYS.2.
- S6.11 (S17: palette and rail rows of Split / Join / Export) → covered by R-TUI-021.10, .11, R-TUI-022.2; Esc is S17 R-SEG-OPEN.2.

**Reconciled with batch-100 (s19_app 570b4b5)**

- **Rows added (47)**: R-FOCUS-LOAD.1 (HLR-166); R-PROGRESS-LINE.1 … .11, R-PROGRESS-SHOWN.1 … .4, R-PROGRESS-BAR.1 … .5, R-PROGRESS-END.1 … .5 (HLR-176 … HLR-176d); R-BUSY-RUN.1, R-BUSY-REFUSE.1 … .8 (HLR-177, HLR-177a); R-QUIT.1 … .12 (HLR-177b, HLR-177c).
- **Rows changed (text)**: R-SHELL-START.5 (quit at once only while no session action runs, D6-36); R-SHELL-FOCUS.3, .4 (a load that completes or is cancelled; frame widgets kept, D6-39); R-SHELL-STATUS.6 (the bar at 0 % when a long action begins, D6-44).
- **Rows changed ("Code today")**: R-SHELL-STATUS.5 No → Yes; tested (D6-28 done); R-SHELL-FOCUS.3, .4, .5, .7 now name their tests; R-SHELL-START.5 Yes → Yes; tested.
- **Rows retired**: none.
- **Context notes**: CTX-SHELL (status text, file status, load completes / cancelled, frame widget, the bar's percentage); CTX-KEYS (`Load`, `Projects`, D6-38); CTX-THEME (accent on the running status text); CTX-BUSY new.
- **Decisions**: added D6-32 … D6-46; D6-28 marked done; D6-20 cite updated (still open); D6-9 **partly superseded by D6-36**.
- **Re-checked, unchanged by batch-100**: D6-20 (`period`), D6-21 (`action_show_screen` moves no focus), D6-11 … D6-13, D6-22 … D6-27, D6-30, D6-31.
- **Not verified**: nothing was run; the held-step paint gap (D6-46) is read from the code only.
- **Consolidation (items from S5, S11)**: CTX-BUSY "outcome" cites S5 R-TUI-012L.12 (the file load's `Loaded <name>`). Already here: the file-load label and steps (CTX-BUSY), R-BUSY-REFUSE.1, .6 (cited by S5), the focus after a cancelled load question (R-SHELL-FOCUS.4, `test_tc_b100_12_cancelled_question_rehomes_the_focus`) and after the Load-result panel closes (R-FOCUS-LOAD.1), the quit question's `Stay (n)` emphasis (CTX-BUSY; aligning the load question is S5 D5-52's prototype round). Three TC-B100-51 Save project nodes that S6 had passed uncited are now cited in R-PROGRESS-END.4 (the chapter's own line wins over `<label> failed`).

## 6. Counts

| | Old S6 | Strict |
|---|---:|---:|
| Requirement statements | 13 rows (1 superseded) | 125 rows (78 before the batch-100 reconciliation, + 47) |
| Statements the code contradicts, that cannot be verified, or that are not product behaviour | 12 (021 items and keys, 022 bar, 033 bar and functions, 036 and 016 surface, 031 key list, 023 mixed scopes, 024 history and light theme, 065 design, 030 panel on every window, 035 no baseline, DISCOVER-001 button, 003 superseded) | 0 |
| Rows by form: U / When / While / If / Where | — | 30 / 58 / 16 / 21 / 0 (before: 23 / 38 / 7 / 10 / 0) |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 39 (24 follow the code or move, 3 remove, 10 correct a defect, 2 prototype first; numbers not contiguous; before: 24) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.
