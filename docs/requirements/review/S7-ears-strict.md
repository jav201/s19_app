# S7 — Modal dialogs, input widgets & window help: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S7 (lines 2704–2855): R-TUI-043, R-TUI-044, R-HEX-HYGIENE-001.
Code: `s19_app/tui/screens.py` (the shared dialog behaviour of its 14 dialogs), `os_clipboard_input.py`, `capped_text_area.py`, `window_help.py` (help sections, help window, help chip, key bar), `screens_directionb.py::LoadGuardScreen`, `a2l_describe.py::CurveDescriptionScreen` (focus and Escape only), the dialog and key-bar rules of `styles.tcss`, and the key and paste handling of Textual 8.2.8 (the pinned version) where a row depends on it. Every fact from code read, with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S7.1, S7.2 (all of it, from batch-100 HLR-172a and HLR-173 … HLR-173e), S7.3 (CTX-PASTE, R-TUI-044.2), S7.5 (CTX-KEYBAR row 1, R-KEYBAR.4) and decisions D7-4, D7-7 … D7-9, D7-10, D7-12 … D7-16, D7-20 … D7-23, D7-28, D7-29, D7-31 … D7-35 verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-DIALOG, CTX-LOADDLG, CTX-PASTE, CTX-HELP, CTX-KEYBAR.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first**.
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Nothing is changed in the code yet.
- Absorbed from other groups: S5's load dialog, R-TUI-043 (S7.2); S2's note that the MAC View has no `?` chip (D7-30) and that the A2L help still describes a "section tree" (D7-26).
- Rows where S7 is only `second_group` stay with their primary group (D7-3): R-RPT-002, R-RPT-ADDENDUM-002, R-RPT-REGION-SKIP-001 (S12), R-OPS-003 (S13), R-PROJ-ASSIGN-UI-001 (S11), R-LEGEND-MODAL-001, R-LEGEND-GEOMETRY-001 (S3).

---

## 1. How S7 was written before

- Three rows. R-TUI-043 (about 45 lines): the load dialog's focus and a Ctrl+V paste built from three clipboard readers, with their timeouts, encodings and exception classes. R-TUI-044 (about 50 lines): a 64 Ki-character paste limit, with the helper that applies it, residual risks and a deferred design. R-HEX-HYGIENE-001: widget ids of button rows plus an exception rule of the Operations dialog.
- No row for what every dialog shares (Escape, Enter, where the focus starts), and none for the window help (`?`) or the key bar, although both ship and have tests.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-043 | Two thirds of the row is design: the readers (tkinter, ctypes, PowerShell), the thread pool, the encodings, the exception classes, the log level, "must remain a subclass of `Input`". The per-reader budgets (150 + 100 + 500 ms) are design; the operator sees only the total. | Observable rows: focus, paste, fallback, warning, time (S7.2, S7.3; D7-1). |
| R-TUI-043 | The single-key list it protects (`s e r l p j g q b t x k v o 1..8 …`) is out of date and beside the point: inside a dialog the window's single keys do not act at all; the Ctrl keys do (D7-23). | R-DLG.1 and the text-box rule S6 R-TUI-031.1. |
| R-TUI-044 | Says the project folder box is "deliberately excluded" from the OS paste. The code makes it an OS-paste box (`screens.py:550`) and a test forbids plain boxes (`tests/test_universal_paste.py::test_ac1_no_tui_module_constructs_a_stock_input`); the comment at `screens.py:561` is stale. | Every single-line box pastes the same way (R-TUI-044.1, D7-4). |
| R-TUI-044 | "Bounds the length of any clipboard value." Two paths are not bounded: the app-clipboard fallback (`os_clipboard_input.py:487-488`, named in its own record) and a terminal paste (Ctrl+Shift+V) into a single-line box — the very workaround the failure warning recommends. | One limit for every paste (R-TUI-044.2, D7-25). |
| R-HEX-HYGIENE-001 | Widget ids of button rows: design. Its second half (an internal `KeyError` reported as "unknown operation") is Operations behaviour. | Out (D7-2); the Operations half to S13. |
| Chapter intro | "The modal screens in `screens.py`": a file, not a behaviour. Eleven of its dialogs carry other chapters' features. | S7 keeps the rules all dialogs share (S7.1); each dialog's content stays with its feature (D7-3). |
| Code comments | `LoadGuardScreen` "mirrors the sibling modals' Escape bond"; `ChangeSetJsonScreen` says "every sibling modal dismisses on Escape". 11 of 16 dialogs ignore Escape. | R-DLG.2, D7-20. |
| Window help, key bar | No requirement; their rules live only in batch records (HLR-140, HLR-150). | Rows S7.4, S7.5. |
| Batch-100 HLR-172a, HLR-173 … HLR-173e (input of the 570b4b5 reconciliation) | The statements name widget ids (`#load_list`, `#load_reason`), a data class (`LoadChoice`), its kinds, the router, the callables the dialog gets, AST censuses, mutation plans and ledger rulings. | Rows keep what the operator sees and does: the parts of CTX-LOADDLG, the keys, the rows, the preview, the reason line, the status lines (S7.2; D7-7, D7-13). |

---

## 3. Context notes (informative)

### CTX-DIALOG · Dialogs (S7.1, S7.2)

```text
dialog          A window over the screen: a title, its content, a row of buttons.
                While it is open the window behind it stays visible but dim.
confirm button  The dialog's main button, drawn in the accent colour.
confirm box     A single-line box whose Enter means the confirm button: the path box
                of the Load dialog; the name box of Save project; the name box of
                Save flow.
text dialog     A dialog whose content starts with a text box: Save project,
                Save flow, Edit change-set JSON, Edit entry JSON. (The Load dialog's
                first focus depends on the key that opens it: R-TUI-043.1,
                R-LOADDLG.1.)
confirmation    A dialog that asks before work is lost or a file is written:
dialog          Unsaved changes will be lost, Discard unsaved flow edits?,
                the CRC write confirmation, the load question, the quit question.
cancel button   The button that keeps everything as it is: Cancel; on the quit
                question, Stay (n).
dialogs today (owner = the chapter of the content):
  title                                     owner  buttons                          focus today     Esc today
  Load                                      S7     Load (alt+l) · Cancel (esc)      path box or     yes
                                                                                    list (S7.2)
  Project name (Save project)               S11    Save (alt+s) · Cancel (esc)      name box        yes
  Select variant (project '<name>'):        S11    Activate · Cancel                variant list    no
  Project <name> opened[ with <n>           S11    Select variant (v) ·             result list     yes
    problem(s)] (the Load-result panel)            Close (esc)
  Replace <what>? (the load question)       S5     Replace (y) · Cancel (n)         Cancel (n)      yes
  Quit? (the quit question)                 S6     Quit (y) · Stay (n)              Stay (n)        yes
  Save flow as:                             S16    Save · Cancel                    name box        no
  Load flow:                                S16    Import… · Load · Cancel          flow list       no
  Discard unsaved flow edits?               S16    Discard · Cancel                 Discard         no
  Edit change-set JSON:                     S10    Confirm · Cancel                 text            yes
  Edit entry JSON:                          S10    Confirm · Cancel                 text            no
  Unsaved changes will be lost              S10    Accept loss and load · Cancel    Cancel          yes
  Write the computed CRC(s) into a new      S13    Width: <n> bytes/line ·          Width           no
    modified S19 under the work area?              Confirm · Cancel
  Operations:                               S13    Load config · Execute ·          operation list  no
                                                   Write CRC · Close
  Reports (project '<name>'):               S12    Generate new report · Close      report list     no
  Classification legend                     S3     Close                            Close           yes
  Parameter: <name>                         S2     Close                            Close           yes
  <help section title>                      S7     Close  esc                       Close           yes
```

### CTX-LOADDLG · The Load dialog (S7.2; from batch-100 HLR-172a, HLR-173 … HLR-173e)

```text
Load dialog     The one dialog that loads a project, a work-area file, a recent source
                or a typed path. Its layout is the prototype verdict P-A = C of
                batch-100: two panes, the preview on the right.
  at 100 columns or wider:
      Load
      ┌ left pane ───────────────────────┐ ┌ right pane ──────────────────┐
      │ path box                         │ │ preview                      │
      │ list                             │ │                              │
      └──────────────────────────────────┘ └──────────────────────────────┘
      reason line
      [Load (alt+l)]  [Cancel (esc)]
  narrower than 100 columns: the right pane below the left pane, each as wide
  as the dialog.
path box        A single-line box. Empty when the dialog opens; hint
                "C:\path\to\file.s19, .hex, .mac, .a2l, or a project folder".
                Holds at most 4,096 characters and no control character.
list            Three sections, each under its heading line:
                  Projects    project rows, or one token line
                  Work area   work-area file rows, or one token line
                  Recent      recent rows, or one token line
heading line    "Projects", "Work area", "Recent".
token line      A line that says why a section holds no row:
                  no projects — ctrl+s saves a project
                  could not be read — check that the folder can be opened, then load again
                  no work-area files — l loads a file
                  no recent sources
                  too large — the next load starts a new list
                  could not be read — check that the recent-sources file can be opened
loadable row    A project row, a work-area file row or a recent row (not a heading
                line, not a token line).
project row     <project name>                    the painted folder name
work-area       <file name>                       the painted file name
file row
recent row      <file name> (<kind>)              the painted file name of the recorded
                                                  path; the recorded kind s19, hex,
                                                  mac or a2l (S5's recent sources)
loadable file   A file that the Workarea Files list shows (S5) and whose extension
                is an S19, Intel HEX, MAC or A2L extension (S5 CTX-FILES).
painted name    A name taken from disk, shown with every character of Unicode
                category Cc, Cf, Zl or Zp removed, every unpaired surrogate as U+FFFD,
                no markup, and cut to 120 characters ending in "…".
load source     The list or the path box, whichever had the focus last. It is the path
                box when the dialog opens with l or Ctrl+L, the list when it opens
                with p. The focus on the preview or a button keeps it. A printable key
                typed on the list makes the path box the load source.
load request    Enter in the path box, in the list or in the preview; Alt+L anywhere
                in the dialog; the Load button.
accepted        A load request whose row or typed path is not refused (S7.2d).
reason line     "<reason> — <next step>" (U+2014 between), one line under the panes.

preview         Lines about the highlighted row. A marked line starts with "● ".
  project row     variant <file name>        one per variant, in variant order (S11)
                  MAC <file name>            one per MAC file of the project
                  A2L <file name>            the project's first A2L file
                  project file: <state>      ok · no project.json · manifest damaged
                                             (manifest damaged: S11 CTX-MANIFEST)
  work-area       S19 or HEX row: image <this file>; MAC <the session's MAC>;
  file row          A2L <the session's A2L>;
                    becomes the active variant of project <project name>
                  MAC row: image <the session's S19 or HEX image>; MAC <this file>;
                    A2L <the session's A2L>
                  A2L row: image <the session's S19 or HEX image>;
                    MAC <the session's MAC>; A2L <this file>
                  (a session line shows only when the session holds that file)
  recent row      <recorded path>            the whole recorded path
                  kind <kind>
                  checked when loaded
installed set   The variant, MAC and A2L files that loading the highlighted row
                installs: for a project row, S11's project-load install rule; for a
                work-area file row, the image, MAC and A2L the session holds after the
                load (S5).

typed path      The text of the path box, a recent row's recorded path, or the path
                the app is started with. Spaces and double quotes around it are
                removed first (S5 R-TUI-005.2, R-TUI-005.9).
late typed path The path the app is started with, or a typed path whose class is
                decided again after the Load dialog has closed (the folder changed
                between the load request and the load).
typed-path      The first of these that applies:
class             not found             the operating system refuses to check the
                                        text (a NUL, too long, no access), or nothing
                                        exists at it (after S5's look-up of a relative
                                        path under the start folder)
                  relative path (no drive and root):
                    a folder                                  -> not a supported file
                    an A2L extension                          -> A2L file
                    an S19, Intel HEX or MAC extension        -> data file
                    any other                                 -> not a supported file
                  absolute path outside the work area:
                    a project.json, or a folder               -> outside
                    an A2L extension                          -> A2L file
                    an S19, Intel HEX or MAC extension        -> data file
                    any other                                 -> not a supported file
                  absolute path inside the work area, each step from the work area down:
                    a step that does not exist                -> not found
                    a step that cannot be inspected           -> unreadable
                    a step that is a link or junction, when the
                      path names a data or A2L file           -> link file
                    a step that is a link or junction         -> link
                  then, for the path itself:
                    a regular file with an A2L extension      -> A2L file
                    a regular file with an S19, HEX or MAC ext -> data file
                    any other file but project.json           -> not a supported file
                    a folder (for project.json: its folder) that is
                      not one level below the work area       -> not a project
                    a project list that cannot be read        -> unreadable
                    a name the project list does not hold     -> not a project
                    a listed folder whose content cannot be read -> unreadable
                    a listed folder with no project content   -> not a project
                    any other                                 -> project
refused         Each typed-path class that is not project, data file or A2L file;
                and "nothing selected" (an empty load request).
refusal table   class                  reason line (dialog)
                nothing selected       nothing selected — pick a row or type a path
                not found              not found — check the path
                not a supported file   not a supported file — check the path
                not a project          not a project — pick a project in the list
                outside                outside the work area — copy the folder into the work area
                link                   link or junction — pick a project in the list
                link file              is a link or junction — open the file it points to
                unreadable             could not be read — check that the folder can be opened, then load again
```

### CTX-PASTE · Text boxes and paste (S7.3)

```text
single-line box  A one-line text box. Every one-line box of the app: the Load
                 dialog's path box, the search and go-to boxes, the palette filter,
                 the dialog boxes, the fields of the Patch Editor, Check Editor, Flow
                 screens, CRC Designer, A↔B diff.
multi-line box   A text box of several lines that the operator edits: the two JSON
                 editors, the Patch Editor paste buffer, the CRC config, the declared
                 regions of Reports, the manual ranges of Split / Join / Export.
OS clipboard     The operating system's clipboard (text copied in another program).
app clipboard    Text copied inside the app.
terminal paste   A paste the terminal sends itself (Ctrl+Shift+V in Windows Terminal).
paste limit      65,536 characters. (The Load dialog's path box has its own limit of
                 4,096 characters: R-LOADDLG.19.)
paste failure    The warning notice "Clipboard read failed — try Ctrl+Shift+V or type
warning          the path manually.", shown for 6 seconds.
```

### CTX-HELP · Window help (S7.4)

```text
help section    A title and numbered steps written for one window.
                Today: Workspace, A2L Explorer, Memory Map, Checks, CRC Designer,
                Patch Editor, Check Editor, Flow Builder, Flow Execution,
                Split / Join / Export, Reports (the Reports dialog), and
                Changes file notation (no window opens it).
                No section: MAC View, Issues Report, A2B Diff.
help chip       A "?" button beside a window's title, in the accent colour.
help window     A dialog:
                  <section title>
                  1. <step>
                  (blank line)
                  2. <step> …
                  (blank line)
                  <key> — <label>     one line per window key of the window's
                                      key-bar row 2 (CTX-KEYBAR), no go keys
                  [Close  esc]
key panel       The panel that lists the keys active on the focused widget (S6).
```

### CTX-KEYBAR · The key bar (S7.5)

```text
key bar         Two rows at the bottom of every window, below the status bar.
token           " <key> <label> ": <key> as the app paints it (^k for Ctrl+K, pgdn,
                esc, space …); <label> the palette label of the key's command (S6).
row 1           ^k Palette · ^d Density · ^l Load · ^s Save project ·
                x Operations · ? Help · q Quit
row 2           The shown window's name (title colours), its window keys, then
                " · go" and its go keys; "? more" ends the row when tokens were left
                out.
dimmed token    The whole token in one dim colour.
owned key       A window key that belongs to a widget; it acts while the focus is in
                that widget's window.
window keys and go keys, today:
  window             window keys                       go keys   dimmed while
  Workspace          / g , . k p o r U                 —         , . U: no image
  A2L Explorer       / g + - d k                       —
  MAC View           / g + - k                         —
  Memory Map         k                                 —
  Issues Report      pgdn pgup k                       —
  Patch Editor       ^z ^y v k                         = 9       ^z ^y: document from a
                                                                 file; v: no variants
  Check Editor       space (owned: parameter table)    6 9
  A2B Diff           k; f esc ] [ (owned: diff panel)  —
  Flow Builder       —                                 ] 6 =
  Flow Execution     c                                 8 t
  Checks             k                                 —
  CRC Designer       —                                 —
  Split/Join/Export  space a n t m g f p d e esc       —
                     (owned: the window)
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested**, **Partly** / **No** with the decision.

### S7.1 · Rules every dialog shares (CTX-DIALOG)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-DLG.1 | While | While a dialog is open, the system shall act on no key of the window behind it. | Partly: Ctrl+K, Ctrl+D, Ctrl+L and Ctrl+S are inert while the Load dialog, Save project or a question is open, also under the command palette (tested: `test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open`); they still act behind the other 14 dialogs (D7-23). |
| R-DLG.2 | When | When the operator presses Escape in a dialog, the system shall do what the dialog's Cancel or Close button does. | Partly: 8 of the 18 dialogs ignore Escape (D7-20); the Load dialog is tested (`test_tc_b100_41_escape_closes_with_no_result_from_every_focus`). |
| R-DLG.3 | When | When the operator presses Enter in a confirm box, the system shall do what its dialog's confirm button does. | Partly: the Load dialog's path box (tested: `test_tc_b100_41_load_with_the_path_last_takes_the_typed_text`) and the Save project name box do; the Save flow name box does nothing (D7-21). |
| R-DLG.4 | When | When the operator presses Enter on an item of a dialog's list, the system shall do what the confirm button does for that item. | Partly: the Load dialog's list does (tested: `test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row`); Select variant and Load flow ignore it (D7-21). |
| R-DLG.5 | When | When a text dialog opens, the system shall put the focus in its first text box. | Yes; tested for Save project (`test_tc_b100_49_open_project_name_is_offered_selected`). |
| R-DLG.6 | When | When a confirmation dialog opens, the system shall put the focus on its cancel button. | Partly: `Discard unsaved flow edits?` opens on Discard, the CRC write confirmation on Width (D7-22); the load question and the quit question open on their cancel button. |
| R-DLG.7 | When | When a dialog with a list and no text box first opens, the system shall put the focus on its list. | Yes. |
| R-DLG.8 | When | When a dialog whose only button is Close opens, the system shall put the focus on Close. | Yes; tested. |
| R-DLG.9 | When | When the operator presses a dialog's Cancel or Close button, the system shall close the dialog and change nothing more. | Yes; tested for the Load dialog (`test_tc_b100_41_cancel_closes_with_no_result`). |
| R-DLG.10 | If | If a required text box is empty when the operator presses its dialog's confirm button, then the system shall keep the dialog open. | Yes; tested for the Load dialog (`test_tc_b100_41_empty_or_spaces_text_is_explained`). |
| R-DLG.11 | U | The system shall show on each dialog button the key that presses it. | Partly: the Load dialog, Save project, the load and quit questions, the Load-result panel and the help window do; the other 12 dialogs do not (D7-31, prototype first). |
| R-DLG.12 | When | When the operator presses the key a dialog button shows, the system shall press that button. | Partly: as R-DLG.11; on the Load dialog Alt+L and Escape are tested (`test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing`) (D7-31, prototype first). |
| R-DLG.13 | U | The system shall show file and folder names in dialogs as plain text, never as markup. | Partly: the Load dialog does (R-LOADDLG.33 … .35); the Select variant and Reports lists read markup (D7-28). |

### S7.2 · The Load dialog: opening, layout and keys (CTX-LOADDLG; from batch-100 HLR-173, HLR-173e)

Escape: R-DLG.2. Cancel: R-DLG.9. Keys behind the dialog: R-DLG.1. Button keys: R-DLG.11, R-DLG.12. Names: R-DLG.13.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-043.1 | When | When the operator presses Ctrl+L, or `l` outside a text box, the system shall open the Load dialog with the focus in its path box. | Yes; tested (`test_tc_b100_41_l_and_ctrl_l_open_the_dialog_on_the_path_field`, `test_loadfilescreen_auto_focus_lands_on_input`). |
| R-LOADDLG.1 | When | When the operator presses `p` outside a text box, or presses `Load project (p)` on the Workspace, the system shall open the Load dialog with the focus on its list. | Yes; tested (`test_tc_b100_41_p_and_the_button_open_the_dialog_on_the_list`). |
| R-LOADDLG.2 | U | The system shall lay out the Load dialog as CTX-LOADDLG shows. | Yes; untested as a whole (batch-100 captures only); its parts are tested in R-LOADDLG.3, .4, .5, .7. |
| R-LOADDLG.3 | While | While the terminal is at least 100 columns wide, the system shall show the Load dialog's preview to the right of its list. | Yes; tested (`test_tc_b100_64_panes_stack_below_100_columns`). |
| R-LOADDLG.4 | While | While the terminal is narrower than 100 columns, the system shall show the Load dialog's preview below its list. | Yes; tested (`test_tc_b100_64_panes_stack_below_100_columns`, `test_tc_b100_64_panes_restack_on_a_live_resize`). |
| R-LOADDLG.5 | U | The system shall show each line of the Load dialog's list and preview on one terminal line, cut with `…` when it is wider than its pane. | Yes; tested (`test_tc_b100_64_list_rows_never_wrap`, `test_tc_b100_64_preview_line_never_wraps`). |
| R-LOADDLG.6 | U | The system shall show the whole path box hint at 118 columns. | No: at 118×54 the hint is cut after `or a` (D7-29). |
| R-LOADDLG.7 | When | When the operator presses Tab in the Load dialog, the system shall move the focus one step along the path box, the list, the preview, `Load`, `Cancel`, and from `Cancel` back to the path box. | Yes; tested (`test_tc_b100_41_tab_order_wraps_both_ways`). |
| R-LOADDLG.8 | When | When the operator presses Shift+Tab in the Load dialog, the system shall move the focus one step back along the order of R-LOADDLG.7. | Yes; tested (`test_tc_b100_41_tab_order_wraps_both_ways`). |
| R-LOADDLG.9 | When | When the operator types a printable character while the list has the focus, the system shall add the character to the end of the path box text. | Yes; tested (`test_tc_b100_41_printable_key_in_the_list_types_into_the_path_field`). |
| R-LOADDLG.10 | When | When the operator types a printable character while the list has the focus, the system shall move the focus to the path box. | Yes; tested (`test_tc_b100_41_printable_key_in_the_list_types_into_the_path_field`). |
| R-LOADDLG.11 | When | When the operator presses ↑ or ↓ while the list has the focus, the system shall keep the focus on the list. | Yes; tested (`test_tc_b100_41_navigation_keys_in_the_list_are_not_redirected`). |
| R-LOADDLG.12 | U | The system shall never highlight a heading line or a token line of the Load dialog's list. | Yes; tested (`test_tc_b100_41_headings_cannot_be_reached_by_keys`). |
| R-LOADDLG.13 | When | When the operator clicks a loadable row, the system shall highlight that row. | Yes; tested (`test_tc_b100_41_click_highlights_and_never_loads`). |
| R-LOADDLG.14 | When | When the operator clicks or double-clicks a loadable row, the system shall keep the Load dialog open. | Yes; tested (`test_tc_b100_41_click_highlights_and_never_loads`). |
| R-LOADDLG.15 | When | When the Load dialog opens, the system shall highlight the open project's row. | Yes; tested (`test_tc_b100_41_list_opens_on_the_open_project`). |
| R-LOADDLG.16 | When | When the Load dialog opens and its list holds no row of an open project, the system shall highlight the first project row. | Yes; tested (`test_tc_b100_41_open_project_highlight_falls_back_to_the_first_project`). |
| R-LOADDLG.17 | When | When the Load dialog opens and its list holds no project row, the system shall highlight the first loadable row. | Yes; tested (`test_tc_b100_41_open_project_highlight_falls_back_to_the_first_project`). |
| R-LOADDLG.18 | U | The system shall show no internal decision id (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`, `HLR-…`) in the Load dialog. | Yes; tested (`test_tc_b100_66_painted_text_carries_no_decision_id`). |
| R-LOADDLG.19 | If | If a paste or a typed key would make the path box text longer than 4,096 characters, then the system shall leave the path box text unchanged. | Partly: tested for a paste (`test_tc_b100_63_over_long_paste_is_refused_and_the_app_stays_up`, `test_at042b_ctrl_v_inserts_capped_value_via_real_read`); a printable key typed on the list can make it 4,097 characters (D7-32). |
| R-LOADDLG.20 | If | If a paste or a typed key would put a control character into the path box, then the system shall leave the path box text unchanged. | Yes; tested (`test_tc_b100_63_pasted_nul_is_not_inserted`). |
| R-TUI-043.3 | When | When the operator presses Escape or Cancel in the Load dialog, the system shall leave the session unchanged. | Yes; tested (`test_tc_b100_41_escape_closes_with_no_result_from_every_focus`, `test_tc_b100_41_cancel_closes_with_no_result`, `test_at_b100_14_one_load_dialog_from_record_to_reopen`). |

### S7.2a · Sections and rows (from batch-100 HLR-173)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-LOADDLG.21 | U | The system shall show the Load dialog's list as three sections in this order: `Projects`, `Work area`, `Recent`. | Yes; tested (`test_tc_b100_43_sections_hold_the_projects_files_and_recents`). |
| R-LOADDLG.22 | U | The system shall start each section of the Load dialog's list with its heading line. | Yes; tested (`test_tc_b100_43_sections_hold_the_projects_files_and_recents`). |
| R-LOADDLG.23 | When | When the Load dialog opens, the system shall show one project row per project of the project list (S11), in the project list's order. | Yes; tested (`test_tc_b100_43_sections_hold_the_projects_files_and_recents`, `test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed`, `test_tc_b100_43_a_reparse_project_json_alone_is_not_a_project`, `test_at_b100_14_one_load_dialog_from_record_to_reopen`). |
| R-LOADDLG.24 | If | If the project list holds no project, then the system shall show the token line `no projects — ctrl+s saves a project` in the `Projects` section. | Yes; tested (`test_tc_b100_43_empty_projects_section_paints_its_tokens`). |
| R-LOADDLG.25 | If | If the work area cannot be listed, then the system shall show the token line `could not be read — check that the folder can be opened, then load again` in the `Projects` section. | Yes; tested (`test_tc_b100_43_unreadable_project_list_says_so`). |
| R-LOADDLG.26 | If | If the work area cannot be listed, then the system shall still fill the `Work area` and `Recent` sections. | Yes; tested (`test_tc_b100_43_unreadable_project_list_says_so`). |
| R-LOADDLG.27 | When | When the Load dialog opens, the system shall show one work-area file row per loadable file, in the order of the Workarea Files list. | Yes; tested (`test_tc_b100_43_files_section_is_the_one_lister_filtered_to_loadable_files`). |
| R-LOADDLG.28 | If | If `temp/` holds no loadable file, then the system shall show the token line `no work-area files — l loads a file` in the `Work area` section. | Yes; tested (`test_tc_b100_43_empty_files_section_paints_its_tokens`). |
| R-LOADDLG.29 | When | When the Load dialog opens, the system shall show one recent row per entry of the recent-sources read (S5), in the read's order. | Yes; tested (`test_tc_b100_43_recents_section_is_the_store_read_in_order`). |
| R-LOADDLG.30 | If | If the recent-sources read returns no entry and no problem, then the system shall show the token line `no recent sources` in the `Recent` section. | Yes; tested (`test_tc_b100_43_empty_recents_section_paints_its_token`). |
| R-LOADDLG.31 | If | If the recent-sources read reports the problem `too large`, then the system shall show the token line `too large — the next load starts a new list` in the `Recent` section. | Yes; tested (`test_tc_b100_43_store_problem_is_painted_in_the_recents_section`). |
| R-LOADDLG.32 | If | If the recent-sources read reports the problem `could not be read`, then the system shall show the token line `could not be read — check that the recent-sources file can be opened` in the `Recent` section. | Yes; tested (`test_tc_b100_43_store_problem_is_painted_in_the_recents_section`). |
| R-LOADDLG.33 | U | The system shall show a project row as the painted name of the project folder. | Yes; tested (`test_tc_b100_42_project_rows_are_painted_literally`). |
| R-LOADDLG.34 | U | The system shall show a work-area file row as the painted name of the file. | Yes; tested (`test_tc_b100_42_work_area_file_rows_are_painted_literally`). |
| R-LOADDLG.35 | U | The system shall show a recent row as `<file name> (<kind>)` of CTX-LOADDLG. | Yes; tested (`test_tc_b100_43_recent_row_shows_the_file_name_and_kind_only`, `test_tc_b100_42_recent_rows_are_painted_literally`). |
| R-LOADDLG.36 | U | The system shall read nothing at a recent row's path before the operator loads that row. | Yes; tested (`test_tc_b100_43_no_filesystem_call_touches_a_recent_before_load`). |

### S7.2b · The preview and its marks (from batch-100 HLR-173, HLR-173a)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-LOADDLG.37 | When | When a loadable row is highlighted while the list is the load source, the system shall show that row's preview. | Yes; tested (`test_tc_b100_41_preview_follows_the_load_target`). |
| R-LOADDLG.38 | When | When the path box becomes the load source, the system shall clear the preview. | Yes; tested (`test_tc_b100_41_moving_to_the_path_field_clears_the_list_preview`, `test_tc_b100_41_printable_key_clears_the_preview`). |
| R-LOADDLG.39 | When | When the Load dialog opens with the focus in its path box, the system shall show an empty preview. | Yes; tested (`test_tc_b100_41_path_mode_opens_with_an_empty_preview`). |
| R-LOADDLG.40 | When | When a project row is highlighted, the system shall show in the preview one `variant <file name>` line per variant of the project, in variant order. | Yes; tested (`test_tc_b100_64_project_preview_lists_every_variant`). |
| R-LOADDLG.41 | When | When a project row is highlighted, the system shall show in the preview one `MAC <file name>` line per MAC file of the project. | Yes; tested for one MAC file (`test_tc_b100_64_project_preview_marks_equal_the_install`). |
| R-LOADDLG.42 | When | When a project row is highlighted, the system shall show in the preview an `A2L <file name>` line for the project's first A2L file. | Yes; tested (`test_tc_b100_64_project_preview_marks_equal_the_install`). |
| R-LOADDLG.43 | When | When a project row is highlighted, the system shall show in the preview the line `project file: <state>` with the state `ok`, `no project.json` or `manifest damaged` of the project's project.json. | Yes; tested (`test_tc_b100_64_project_preview_states_the_manifest`). |
| R-LOADDLG.44 | When | When a project row is highlighted, the system shall mark with `● ` the variant, MAC and A2L lines of the project's installed set. | Yes; tested (`test_tc_b100_64_project_preview_marks_equal_the_install`, `test_tc_b100_64_preview_does_not_mark_an_a2l_the_install_refuses`, `test_at_b100_14_one_load_dialog_from_record_to_reopen`). |
| R-LOADDLG.82 | If | If the project load would refuse a project's first A2L file (S11: a link or junction, too large to open, or unreadable), then the system shall show that file's `A2L <file name>` line in the preview without the mark. | Yes; tested for a file over the copy limit (`test_tc_b100_64_preview_does_not_mark_an_a2l_the_install_refuses`). The preview names no reason; S11's project-load problem rows give it after the load (D7-15). |
| R-LOADDLG.45 | If | If a project holds more than one MAC file or more than one A2L file, then the system shall mark no line of its preview. | Yes; tested (`test_tc_b100_64_more_than_one_mac_marks_nothing`). |
| R-LOADDLG.46 | If | If a file in a project folder is a link or a reparse point, then the system shall leave it out of the project's preview. | Yes; tested (`test_tc_b100_64_linked_file_in_a_project_is_neither_listed_nor_installed`, `test_tc_b100_64_reparse_file_in_a_project_is_neither_listed_nor_installed`). |
| R-LOADDLG.47 | If | If a project's folder or its project.json cannot be read, then the system shall show as the project's preview only the line `could not be read — check that the folder can be opened, then load again`. | Yes; tested (`test_tc_b100_64_project_preview_read_error_says_so`). |
| R-LOADDLG.48 | If | If a project's project.json is a link, a reparse point or not a regular file, then the system shall show as the project's preview only the line `could not be read — check that the folder can be opened, then load again`. | Yes; tested (`test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused`, `test_tc_b100_64_project_json_that_is_a_reparse_point_is_refused`). |
| R-LOADDLG.49 | When | When a work-area file row is highlighted, the system shall show in the preview the lines of CTX-LOADDLG for that file, each marked with `● `. | Yes; tested (`test_tc_b100_64_file_row_preview_marks_what_the_session_keeps`). |
| R-LOADDLG.50 | While | While a project is open, the system shall show in the preview of a highlighted S19 or Intel HEX work-area file row the line `becomes the active variant of project <project name>`. | Yes; tested (`test_tc_b100_64_open_project_note_on_a_data_file_row`). The line promises what the pick does not do today: a work-area pick adds nothing to the open project (`app.py:15619-15621`; S11 R-PROJ-002.1, D11-29). |
| R-LOADDLG.83 | When | When the open project's row is highlighted, the system shall show in the preview the load reason and the problem rows of that project's last project load (S11 CTX-LOADRES). | No: the preview shows only the project-row lines of CTX-LOADDLG; the last load result is stored (`app.py:13708`) and read by nothing; untested (D7-35). The summary line's `details: p` points here (S11 CTX-LOADRES). |
| R-LOADDLG.51 | When | When a recent row is highlighted, the system shall show in the preview the whole recorded path, the line `kind <kind>` and the line `checked when loaded`. | Yes; tested (`test_tc_b100_43_recent_preview_shows_the_store_facts_only`). |
| R-LOADDLG.52 | When | When a recent row is highlighted, the system shall mark no line of the preview. | Yes; tested (`test_tc_b100_43_recent_preview_shows_the_store_facts_only`). |
| R-LOADDLG.53 | U | The system shall show every file, variant and project name in the Load dialog's preview as a painted name. | Yes; tested (`test_tc_b100_42_preview_names_are_painted_literally`). |

### S7.2c · Loading from the dialog (from batch-100 HLR-173b, HLR-173c)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-LOADDLG.54 | When | When the operator makes a load request while the list is the load source, the system shall load the highlighted row. | Yes; tested (`test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row`, `test_tc_b100_41_text_in_the_field_then_tab_into_the_list_loads_the_row`, `test_tc_b100_41_enter_on_the_preview_loads_the_highlighted_row`). |
| R-LOADDLG.55 | When | When the operator makes a load request while the path box is the load source, the system shall load the typed path of the path box. | Yes; tested (`test_tc_b100_41_load_with_the_path_last_takes_the_typed_text`, `test_tc_b100_41_type_ahead_c_then_enter_loads_the_typed_text`). |
| R-LOADDLG.56 | When | When the system accepts a load request, the system shall close the Load dialog. | Yes; tested (`test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row`). |
| R-LOADDLG.57 | When | When the operator presses Alt+L with the focus in the path box, the system shall type nothing into the path box. | Yes; tested (`test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing`). |
| R-LOADDLG.58 | If | If a second load request arrives after the system has accepted a load request, then the system shall ignore it. | Yes; tested (`test_tc_b100_41_double_enter_dismisses_once`). |
| R-LOADDLG.59 | If | If a load request arrives after the operator has pressed Escape in the Load dialog, then the system shall ignore it. | Partly: Enter after Escape is ignored (tested: `test_tc_b100_41_type_ahead_escape_then_enter_closes_with_none`); an Alt+L queued behind Escape loads (D7-33). |
| R-LOADDLG.60 | When | When the Load dialog closes on a project row, the system shall load that project through the project load of S11. | Yes; tested (`test_tc_b100_40_project_choice_opens_the_load_result_panel`, `test_at_b100_14_one_load_dialog_from_record_to_reopen`). |
| R-LOADDLG.61 | When | When the Load dialog closes on a work-area file row, the system shall load that file as a pick of the same file in the Workarea Files list loads it (S5). | Yes; tested (`test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy`, `test_tc_b100_40_workarea_a2l_choice_equals_the_files_list_pick`). |
| R-LOADDLG.62 | When | When the Load dialog closes on a recent row, the system shall load the row's recorded path, unchanged, as a typed path. | Yes; tested (`test_tc_b100_40_recent_choice_loads_the_recorded_text_unchanged`, `test_at_b100_14_one_load_dialog_from_record_to_reopen`). |
| R-LOADDLG.63 | When | When the operator loads a project row or a work-area file row, the system shall load the name as it is on disk, not the painted name. | Yes; tested (`test_tc_b100_42_a_pick_loads_the_on_disk_name`). |
| R-LOADDLG.64 | When | When a picked or typed project name equals a name of the project list, the system shall load the project of that name. | Yes; tested (`test_tc_b100_38_one_project_match_prefers_the_exact_listed_name`, `test_tc_b100_38_picking_proj_loads_proj_when_proj_differs_by_case`). |
| R-LOADDLG.65 | When | When a picked or typed project name equals no name of the project list but matches one by the file system's letter-case rule, the system shall load that project under its listed name. | Yes; tested (`test_tc_b100_38_project_load_of_another_case_loads_the_listed_name`, `test_tc_b100_38_one_project_match_returns_the_listed_spelling`). |
| R-LOADDLG.68 | If | If the system refuses a loaded project row, then the system shall leave the session unchanged. | Yes; tested (`test_tc_b100_40_unreadable_picked_project_paints_one_status_line`, `test_tc_b100_38_project_load_of_an_unlisted_name_is_refused`). |

R-LOADDLG.66 (a project row whose name the list no longer holds: `… is not a project …`) and R-LOADDLG.67 (a project row whose folder cannot be read: `… could not be read …`) are retired: S11 R-TUI-013.18 and R-TUI-013.17 state the same status lines for every project load and now cite their tests (D7-34).

### S7.2d · An empty or refused load request (from batch-100 HLR-173d)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-LOADDLG.69 | If | If the operator makes a load request while the path box is the load source and holds no text or only spaces, then the system shall show the reason line `nothing selected — pick a row or type a path`. | Yes; tested (`test_tc_b100_41_empty_or_spaces_text_is_explained`, `test_at_b100_14_one_load_dialog_from_record_to_reopen`). |
| R-LOADDLG.70 | If | If the operator makes a load request while the list is the load source and no loadable row is highlighted, then the system shall show the reason line `nothing selected — pick a row or type a path`. | Yes; tested (`test_tc_b100_41_no_loadable_row_highlighted_is_explained`). |
| R-LOADDLG.71 | If | If the typed path of a load request is in the class `not found`, then the system shall show the reason line `not found — check the path`. | Yes; tested (`test_tc_b100_63_typed_path_not_found_is_explained`, `test_tc_b100_63_resolve_error_is_refused_not_raised`, `test_tc_b100_43_missing_recent_is_explained_inside_the_dialog`). |
| R-LOADDLG.72 | If | If the typed path of a load request is in the class `not a supported file`, then the system shall show the reason line `not a supported file — check the path`. | Yes; tested (`test_tc_b100_63_typed_unsupported_file_is_explained`). |
| R-LOADDLG.73 | If | If the typed path of a load request is in the class `not a project`, then the system shall show the reason line `not a project — pick a project in the list`. | Yes; tested (`test_tc_b100_63_typed_folder_that_is_not_a_project_is_explained`, `test_tc_b100_63_folder_named_like_a_data_file`). |
| R-LOADDLG.74 | If | If the typed path of a load request is in the class `outside`, then the system shall show the reason line `outside the work area — copy the folder into the work area`. | Yes; tested (`test_tc_b100_63_typed_folder_outside_the_work_area_is_explained`). |
| R-LOADDLG.75 | If | If the typed path of a load request is in the class `link`, then the system shall show the reason line `link or junction — pick a project in the list`. | Yes; tested (`test_tc_b100_63_typed_path_through_a_junction_is_explained`). |
| R-LOADDLG.76 | If | If the typed path of a load request is in the class `link file`, then the system shall show the reason line `is a link or junction — open the file it points to`. | Yes; tested (`test_tc_b100_63_typed_linked_file_is_explained_as_a_file`). |
| R-LOADDLG.77 | If | If the typed path of a load request is in the class `unreadable`, then the system shall show the reason line `could not be read — check that the folder can be opened, then load again`. | Yes; tested (`test_tc_b100_63_typed_folder_that_cannot_be_read_is_explained`). |
| R-LOADDLG.78 | If | If the system refuses a load request, then the system shall keep the Load dialog open. | Yes; tested (`test_tc_b100_63_typed_path_not_found_is_explained`). |
| R-LOADDLG.79 | If | If the system refuses a load request, then the system shall leave the path box text unchanged. | Yes; tested (`test_tc_b100_63_typed_path_not_found_is_explained`). |
| R-LOADDLG.80 | If | If the system refuses a load request, then the system shall show no status line. | Yes; tested (`test_tc_b100_63_typed_path_not_found_is_explained`). |
| R-LOADDLG.81 | If | If the system refuses a recent row, then the system shall keep the row's entry in the recent sources. | Yes; tested (`test_tc_b100_43_missing_recent_is_explained_inside_the_dialog`). |

### S7.2e · A typed path (from batch-100 HLR-172a)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-043.14 | U | The system shall give a typed path the first typed-path class of CTX-LOADDLG that applies. | Yes; tested (`test_tc_b100_38_route_matches_the_typed_folder_against_the_listing`, `test_tc_b100_38_typed_relative_folder_is_refused`, `test_tc_b100_38_nul_in_typed_path_is_refused`, `test_tc_b100_63_folder_named_like_a_data_file`). |
| R-TUI-043.15 | When | When the Load dialog closes on a typed path in the class `project`, the system shall load that project through the project load of S11. | Yes; tested (`test_tc_b100_38_typed_project_folder_loads_the_project`, `test_tc_b100_38_typed_project_json_loads_its_project`, `test_at_b100_12_outside_load_is_remembered_and_typed_project_path_opens`). |
| R-TUI-043.2 | When | When the Load dialog closes on a typed path in the class `data file` or `A2L file`, the system shall load that file as S5.3 and S5.4 say. | Yes; tested (`test_tc_b100_40_path_choice_takes_the_typed_route`). |
| R-TUI-043.16 | If | If the system refuses a typed path, then the system shall leave the session unchanged. | Yes; tested (`test_tc_b100_38_typed_folder_that_is_not_a_project_is_refused`). |
| R-TUI-043.17 | If | If the system refuses a typed path, then the system shall write no file. | Yes; tested (`test_tc_b100_38_typed_folder_that_is_not_a_project_is_refused`, `test_tc_b100_38_typed_folder_outside_the_work_area_is_refused`). |
| R-TUI-043.18 | If | If a late typed path is in the class `not found`, then the system shall show the status `File NOT loaded: '<path>' not found — check the path.` | Yes; tested (`test_tc_b100_38_typed_path_that_does_not_exist_is_refused`). |
| R-TUI-043.19 | If | If a late typed path is in the class `not a supported file`, then the system shall show the status `File NOT loaded: '<path>' is not a supported file — check the path.` | Yes; tested (`test_tc_b100_38_typed_unsupported_file_is_refused`, `test_tc_b100_38_typed_relative_folder_is_refused`). |
| R-TUI-043.20 | If | If a late typed path is in the class `not a project`, then the system shall show the status `Project NOT loaded: '<path>' is not a project — pick a project in the list.` | Yes; tested (`test_tc_b100_38_typed_folder_that_is_not_a_project_is_refused`). |
| R-TUI-043.21 | If | If a late typed path is in the class `outside`, then the system shall show the status `Project NOT loaded: '<path>' is outside the work area — copy the folder into the work area.` | Yes; tested (`test_tc_b100_38_typed_folder_outside_the_work_area_is_refused`). |
| R-TUI-043.22 | If | If a late typed path is in the class `link`, then the system shall show the status `Project NOT loaded: '<path>' passes through a link or junction — pick a project in the list.` | Yes; tested (`test_tc_b100_38_typed_path_through_a_junction_is_refused`). |
| R-TUI-043.23 | If | If a late typed path is in the class `link file`, then the system shall show the status `File NOT loaded: '<path>' is a link or junction — open the file it points to.` | Yes; tested (`test_tc_b100_63_typed_linked_file_is_explained_as_a_file`). |
| R-TUI-043.24 | If | If a late typed path is in the class `unreadable`, then the system shall show the status `Project NOT loaded: '<path>' could not be read — check that the folder can be opened, then load again.` | Yes; tested (`test_tc_b100_38_unreadable_folder_paints_could_not_be_read`). |

`<path>` is the painted name of the typed text; `<project name>` the painted name of the project.

### S7.3 · Paste into text boxes (CTX-PASTE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-043.4 | When | When the operator presses Ctrl+V in a single-line box, the system shall insert the first line of the OS clipboard text at the cursor. | Yes; tested. |
| R-TUI-043.5 | When | When the system pastes into a text box that holds a selection, the system shall replace the selection with the pasted text. | Yes. |
| R-TUI-043.6 | If | If the system cannot read the OS clipboard, then the system shall paste the app clipboard. | Yes; tested. |
| R-TUI-043.7 | If | If neither clipboard holds text, then the system shall show the paste failure warning. | Yes; tested. |
| R-TUI-043.8 | If | If neither clipboard holds text, then the system shall select the whole text of the box. | Yes. |
| R-TUI-043.9 | U | The system shall keep the screen responsive while it reads the OS clipboard. | Yes. |
| R-TUI-043.10 | U | The system shall end an OS clipboard read within 1 second. | Yes; untested (reader budgets 150 + 100 + 500 ms, `os_clipboard_input.py:71-75`). |
| R-TUI-043.11 | U | The system shall paste characters outside the system code page unchanged. | Yes; tested. |
| R-TUI-043.12 | If | If the system cannot read the OS clipboard, then the system shall write a WARNING line to the log. | Yes. |
| R-TUI-043.13 | U | The system shall not write clipboard text to the log. | Yes. |
| R-TUI-044.1 | U | The system shall give every single-line box the paste of R-TUI-043.4 to R-TUI-043.13. | Yes; tested. |
| R-TUI-044.2 | If | If a paste into any box but the Load dialog's path box holds more characters than the paste limit, then the system shall insert only its first 65,536 characters. | Partly: the app-clipboard fallback and a terminal paste into a single-line box are not limited (D7-25). |
| R-TUI-044.3 | When | When the operator presses Ctrl+V in a multi-line box, the system shall insert the OS clipboard text at the cursor. | No: it reads only the app clipboard, so text copied in another program does not arrive (D7-24). |
| R-TUI-044.4 | When | When the terminal sends a paste into a multi-line box, the system shall insert every line of it. | Yes; tested. |
| R-TUI-044.5 | U | The system shall show pasted text as plain text, never as markup. | Yes; tested. |

### S7.4 · Window help (CTX-HELP)

Where the help window's focus starts and how it closes: R-DLG.8, R-DLG.2, R-DLG.9.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-WHELP.1 | U | The system shall have a help section for every rail window, for Split / Join / Export and for the Reports dialog. | Partly: MAC View, Issues Report and A2B Diff have none (D7-27). |
| R-WHELP.2 | U | The system shall show a help chip beside the title of every window that has a help section. | Yes; tested. |
| R-WHELP.3 | U | The system shall show a help chip on the MAC View, the Issues Report and the A2B Diff. | No: these windows have no title row (D7-30, prototype first). |
| R-WHELP.4 | When | When the operator presses a help chip, the system shall open the help window of its window. | Yes; tested. |
| R-WHELP.5 | When | When the operator presses `?` outside a text box while the focus is in a window that has a help section, the system shall open that window's help window. | Yes; tested. |
| R-WHELP.6 | When | When the operator presses `?` in the Reports dialog outside a text box, the system shall open the Reports help window. | Yes. |
| R-WHELP.7 | When | When the system opens a help window, the system shall show the section title, the steps numbered from 1 with no gap, and the key lines, as CTX-HELP shows. | Yes; tested. |
| R-WHELP.8 | U | The system shall take a help window's key lines from the same table as the window's key-bar row 2. | Yes; tested. |
| R-WHELP.9 | When | When the operator presses ↑, ↓, PgUp, PgDn, Home or End in a help window, the system shall scroll its text. | Yes; tested. |
| R-WHELP.10 | While | While a help window's text is taller than the terminal, the system shall keep the title and `Close  esc` on screen. | Yes; tested. |
| R-WHELP.11 | U | The system shall show help text as plain text, never as markup. | Yes. |
| R-WHELP.12 | U | The system shall name in a help section only keys, controls and behaviour its window has. | Partly: the A2L Explorer section speaks of a "section tree" and says `/` jumps to a tag name; `/` searches the image's bytes (D7-26). |
| R-WHELP.13 | U | The system shall refer in a help section only to windows, folders and files the operator can open from the app. | Partly: "the folders.html board", "change 1", "change 2" (D7-26). |
| R-WHELP.14 | U | The system shall write help sections without Markdown marks. | Partly: `**…**` and `*why*` show as typed (D7-26). |
| R-WHELP.16 | U | The system shall state in the Patch Editor's help section that each Bytes token is a hex byte of 1–2 digits with an optional `0x`, and that decimals are not accepted. | Yes; tested (`test_tc_b99_33_field_and_help_state_the_hex_rule`; `window_help.py:84-85`). From S0 LLR-161.2. |
| R-WHELP.17 | U | The system shall state in the Flow Builder's help section that a run pauses at an external step until the step is confirmed in Flow Execution. | Yes; untested (`window_help.py:226-229`). From S16 D16-7. |
| R-WHELP.15 | When | When the operator opens the Patch Editor's help window, the system shall include the steps of the Changes file notation section. | No: no window opens that section (D7-11). |

### S7.5 · The key bar (CTX-KEYBAR)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-KEYBAR.1 | U | The system shall show the key bar of CTX-KEYBAR at the bottom of every window. | Yes; tested. |
| R-KEYBAR.2 | U | The system shall show in row 1 the global keys of CTX-KEYBAR, in that order, and no other key. | Partly: row 1 also shows `^p palette` (S6 D6-13). |
| R-KEYBAR.3 | U | The system shall show in row 2 the shown window's name, its window keys, then its go keys after `· go`. | Yes; tested. |
| R-KEYBAR.4 | U | The system shall label each token with the palette label of its key's command. | Yes; tested (`test_tc_b100_41_labels_key_bar_and_palette_say_load_and_projects` for `^l Load` and `p Projects`). |
| R-KEYBAR.5 | While | While a key's command is switched off on the shown window, the system shall leave its token out of row 2. | Yes; tested. |
| R-KEYBAR.6 | While | While a key's condition in CTX-KEYBAR is false, the system shall show its token dimmed. | Yes; tested. |
| R-KEYBAR.7 | While | While the focus is outside the window of an owned key, the system shall show that key's token dimmed. | Yes; tested. |
| R-KEYBAR.8 | If | If row 1 is wider than the terminal, then the system shall leave out whole tokens from its end and keep `? Help`. | Yes; tested. |
| R-KEYBAR.9 | If | If row 2 is wider than the terminal, then the system shall keep the window name, leave out whole tokens from its end and end it with `? more`. | Yes; tested. |
| R-KEYBAR.10 | When | When the operator clicks a token that is not dimmed, the system shall run its key's command. | Yes; tested. |
| R-KEYBAR.11 | When | When the operator clicks a token, the system shall type nothing into the focused text box. | Yes; tested. |
| R-KEYBAR.12 | When | When the operator clicks a dimmed token, the system shall ring the bell. | Yes. |
| R-KEYBAR.13 | When | When the operator clicks `? more`, the system shall show the key panel. | Yes. |
| R-KEYBAR.14 | When | When the focus, the shown window or a key's condition changes, the system shall repaint the key bar. | Yes; tested. |
| R-KEYBAR.15 | When | When the operator presses a key whose token is shown and not dimmed, the system shall run its command. | Partly: `.` on the Workspace (S6 D6-20). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D7-1 | R-TUI-043 and R-TUI-044 specify readers, thread use, encodings, exception classes, log level, helper names, "a subclass of `Input`", residual risks and a deferred design. | Design notes. The rows keep what the operator sees: where the paste lands, the fallback, the warning, the time, the limit. |
| D7-2 | R-HEX-HYGIENE-001 asks for unique widget ids of button rows, and that an internal `KeyError` of an operation is not reported as "unknown operation". | Ids: design, out. The error rule goes to S13 with the Operations dialog. |
| D7-3 | Eleven dialogs in `screens.py` carry other chapters' features (owner column of CTX-DIALOG); seven rows list S7 only as `second_group`. | Each dialog's content stays with its owner; S7 keeps the rules all dialogs share (S7.1) and the Load dialog (S7.2). |
| D7-4 | R-TUI-044's record says the project folder box is excluded from the OS paste; the code makes it an OS-paste box (`screens.py:550`) and a census test forbids plain boxes. | Follow the code: every single-line box pastes the same way (R-TUI-044.1). The stale comment (`screens.py:561`) goes with the next edit there. **Obsolete at 570b4b5**: batch-100 Inc 11 removed the folder box and its comment (`SaveProjectScreen.compose`, `screens.py:1026-1079`). |
| D7-5 | A paste into a single-line box keeps only the first line (`os_clipboard_input.py:509`). | Keep: the box holds one line. |
| D7-6 | `?` opens the window help while the focus is inside a window with a section, and the key panel everywhere else (`window_help.py:709-735`): one key, two meanings by focus. | Keep (the design of HLR-140); R-WHELP.5 and S6 R-TUI-DISCOVER-001.1 state both. |
| D7-7 | Batch-100 Inc 9b (HLR-173 … HLR-173e, LLR-173.x; ledger LED .2, .18, .36, .40, .86 … .88) replaced the Load file dialog and the Load project dialog with one Load dialog (`LoadDialog`, `screens.py:270-664`; opened by `action_load_file` and `action_load_project`, `app.py:7962-7976`, `app.py:8100-8114`). Its layout is the operator's prototype verdict P-A = C (two panes, preview right, stacked below 100 columns). LLR-151.1 (the Load project dialog's Load) is marked superseded in `REQUIREMENTS.md` at 570b4b5. | S7.2 is rewritten from the batch: CTX-LOADDLG, R-TUI-043.1 … .3 changed, R-TUI-043.14 … .24 and R-LOADDLG.1 … .82 added. The old CTX note "Load file dialog" and the Load file / Load project lines of CTX-DIALOG are retired. The layout is written as requirements (R-LOADDLG.2 … .5), **not** prototype first: the verdict exists. S11's Load project rows (R-TUI-013.1, .3, .4, .5) are passed to S11 for retirement. |
| D7-8 | Conflict. R-DLG.5 (review: a text dialog opens with the focus in its first text box) against batch-100 VS-PA-4 (LED .36: `p` opens the Load dialog on the list, `l` on the path box). Both describe the first focus of the Load dialog. | Batch-100 wins: it is more recent and the operator ruled it at the PDR seal. The Load dialog leaves the "text dialog" list of CTX-DIALOG; its first focus is R-TUI-043.1 and R-LOADDLG.1. R-DLG.5 stays for the other text dialogs. |
| D7-9 | Conflict. R-TUI-044.2 (review: a paste over the paste limit inserts its first 65,536 characters) against batch-100 ruling SEC9b-1 B (LED .87: the Load path box refuses, never cuts, a text over 4,096 characters; `max_length=4096`, `screens.py:363-368`; Textual's `Input.replace` refuses the whole edit). | Batch-100 wins for the Load path box (operator-authorised ruling, a crash it removed). R-TUI-044.2's condition now leaves out the Load path box; R-LOADDLG.19 and .20 state its limits. D7-25 still applies to every other box. |
| D7-12 | Conflict. D7-28 and S1 CTX-TEXT (review: dialog lists of file names join S1's safe-text views: break characters as one space, every other character unchanged) against batch-100 C8 (LLR-173.3 … .3c: names in the Load dialog are painted with every Cc, Cf, Zl and Zp character removed and cut to 120 characters; `painted_names`, `project_gather_service.py:967-1007`). Both describe how the Load dialog shows names from disk. | Batch-100 wins for the Load dialog: it is more recent, tested (TC-B100-42) and the removal of format characters (a bidi override) is the safer rule. CTX-LOADDLG defines "painted name"; R-LOADDLG.33 … .35, .53 use it. **D7-28's part "the Load project list joins S1's safe-text views" is superseded by D7-12**; its Select variant and Reports parts stay. S1 is told (Passed). |
| D7-13 | The batch's LLRs carry implementation: the `LoadChoice` value and its four kinds, the one router `_handle_load_dialog` (`app.py:15018-15069`), the three callables the dialog gets (`rows`, `verdict`, `preview`), "the dialog reads nothing itself" (an AST census), one function that matches a name to the list (`_listed_project_name`, `app.py:13922-13950`), one table of refusal words (`_TYPED_REFUSAL_TOKENS`, `app.py:303-316`), widget ids, the focus-tracking field, ledger rulings and mutation plans (LLR-173.1, .1e, .6l, LLR-172.5j, .5k). | Design, out of the requirements. The rows keep the behaviour those choices give (R-LOADDLG.54 … .65, R-TUI-043.14). **Tests that verify implementation only** (listed here, cited in no row): `test_tc_b100_40_load_choice_is_a_frozen_value_of_four_kinds`, `test_tc_b100_40_dialog_dismisses_a_load_choice_per_kind_or_none`, `test_tc_b100_40_one_router_receives_every_dialog_result`, `test_tc_b100_40_retired_load_screens_are_gone`, `test_tc_b100_41_typed_text_reaches_the_verdict_verbatim`, `test_tc_b100_64_the_dialog_reads_nothing_itself`, `test_tc_b100_38_one_project_match`, `test_tc_b100_38_one_wording_table`. No TC-B100 or AT-B100 id of S7's HLRs is implementation-only as a whole. |
| D7-14 | Batch-100 HLR-172a (Inc 9a) sends a typed absolute project path to the project load and gives every typed path a class before any load (`_typed_load_route`, `app.py:14770-14916`). A refused typed path paints the reason in the dialog (Inc 9b); a late typed path (the start-up path, or a path that changed after the request) paints a status line (`_load_path_from_user_input`, `app.py:14989-15015`; start-up call `app.py:7855-7857`). S5.3's rows `File not found: <path>` and `Unsupported file type: <extension>` (R-TUI-005.6, .8) are now reached only inside the loader, after the class check. | The typed-path rows live with the Load dialog (rule D-9): CTX-LOADDLG's typed-path classes, R-TUI-043.14 … .24, R-LOADDLG.71 … .77. S5 is told that its path rows R-TUI-005.6 … .8 no longer meet a typed Load path first (Passed). |
| D7-15 | Batch-100 LLR-172.5g and LLR-173.1g refuse a picked project row whose name the list no longer holds, or whose folder cannot be read (`_handle_load_project`, `app.py:13331-13371`). The other project-load refusals (link, outside, not found) are S11's (LLR-171.4e, .4f). LLR-173.4n's install half and LLR-173.6a (the Load-result panel names the variant it opened when it differs from the mark) are project-load and panel behaviour. | R-LOADDLG.66 … .68 stay in S7 (their trigger is the dialog's row); **R-LOADDLG.66 and .67 superseded by D7-34**. The A2L admission rule the preview shares with the project load (`_a2l_admission`, `app.py:14146-14183`: a link or junction, too large to open, could not be read) leaves the A2L line unmarked in the preview and names no reason there (R-LOADDLG.82); the reason words are S11's project-load problem rows. The install half of LLR-173.4n, LLR-173.6a and the panel that opens after every project load are passed to S11; S7 cites S11's project load in R-LOADDLG.60 and R-TUI-043.15. |
| D7-34 | Duplicate rows (consolidation of the 570b4b5 reconciliation). R-LOADDLG.66 and .67 (D7-15) and S11 R-TUI-013.18 and .17 give the same two status lines for a project load that is refused because the name is no longer a listed project or the folder cannot be read (`_handle_load_project`, `app.py:13331-13371`). The status is the project load's, whatever surface picked the name. | Rule D-9: the rows live with the project load in S11. R-LOADDLG.66 and .67 are retired; S11 R-TUI-013.18 and .17 cite their tests (`test_tc_b100_38_project_load_of_an_unlisted_name_is_refused`, `test_tc_b100_40_unreadable_picked_project_paints_one_status_line`). R-LOADDLG.68 stays (the dialog's row leaves the session unchanged). D7-15 superseded for .66 and .67. |
| D7-16 | Batch-100 LLR-173.2m (Inc 12a, LED .95) renamed the binding labels: Ctrl+L and `l` are "Load", `p` is "Projects" (`app.py:2655`, `:2660`, `:2668`); the Workspace button keeps `Load project (p)` (ruling Q6, `app.py:3444`). | CTX-KEYBAR row 1 reads `^l Load`; R-KEYBAR.4 cites the test. The palette labels are S6's (Passed). |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D7-10 | `VariantHelpScreen` and its text (`screens.py:860-929` at 570b4b5; `screens.py:397-480` at 093a7c0): its opener, the Patch Editor variant selector, went in batch 94; only a test opens it. | Delete it, its text and its test. |
| D7-11 | The `Changes file notation` section (`window_help.py:479-516`) is shipped but no chip, key or window opens it. It documents the change-set file the operator writes by hand. | Used and worth it once reachable: the Patch Editor's help window shows it (R-WHELP.15). |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D7-20 | Escape is bound on 5 dialogs only (`screens.py:282`, `screens.py:1083-1085`, `screens_directionb.py:4315`, `a2l_describe.py:56-58`, `window_help.py:610-611`); Textual gives a dialog no Escape of its own. **At 570b4b5** batch-100 added it on the Load dialog (`screens.py:334-337`), Save project (`screens.py:988-991`), the two questions (`screens.py:1502-1506`) and the Load-result panel (`screens.py:1694-1697`): 10 of 18. Still missing on Select variant, Save flow, Load flow, Discard unsaved flow edits?, Edit entry JSON, the CRC write confirmation, Operations and Reports. | Escape does what Cancel or Close does, on every dialog (R-DLG.2). |
| D7-21 | No dialog handles Enter in a text box (no `Input.Submitted` handler except Reports, `screens.py:1830`), and Load project, Select variant and Load flow handle no list selection. The operator must Tab to the button. **At 570b4b5** the Load dialog handles Enter in its path box, list and preview (`screens.py:484-503`) and Save project in its name box (`screens.py:1181-1184`); Save flow's name box, Select variant and Load flow still do not. | Enter in a confirm box or on a list item confirms (R-DLG.3, R-DLG.4). |
| D7-22 | `Discard unsaved flow edits?` and the CRC write confirmation set no first focus, so Textual focuses the first button: Discard, and Width (`screens.py:929`, `screens.py:1962-1965` at 093a7c0; `ConfirmDiscardScreen`, `screens.py:1431`, and `ConfirmWriteScreen`, `screens.py:2686`, unchanged at 570b4b5). The unsaved-changes guard opens on Cancel on purpose (`screens_directionb.py:4320`); so do the batch's two questions (`screens.py:1499`). | Every confirmation dialog opens on its cancel button (R-DLG.6). |
| D7-23 | Ctrl+K, Ctrl+D, Ctrl+L and Ctrl+S are priority keys (`app.py:1669-1672` at 093a7c0; `app.py:2653-2656` at 570b4b5); Textual checks priority keys over the whole chain up to the app even while a dialog is open (`textual/app.py:3978-3981`). So Ctrl+L inside Load file opened a second Load file dialog, Ctrl+S opens Save project over any dialog. **At 570b4b5** the four keys are inert while any screen on the stack is the Load dialog, Save project or a question (`check_action`, `app.py:9253-9257`; tested by `test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open`); the other 14 dialogs are still exposed (read from the code, not reproduced). | Reproduce, then ignore window keys while any dialog is open (R-DLG.1). |
| D7-24 | Ctrl+V in a multi-line box reads only the app clipboard (`capped_text_area.py:154-160`): text copied in another program arrives only by terminal paste. | The same OS clipboard read as single-line boxes, all lines, within the limit (R-TUI-044.3). |
| D7-25 | The paste limit misses two paths: the app-clipboard fallback (`os_clipboard_input.py:487-488`) and a terminal paste into a single-line box (Textual's `Input._on_paste`, not overridden; `textual/widgets/_input.py:756-764`). Unchanged at 570b4b5 (only a docstring changed in `os_clipboard_input.py`). | Apply the limit on every paste path (R-TUI-044.2). |
| D7-26 | Help copy: the A2L Explorer section speaks of a "section tree" and says `/` finds a name (`window_help.py:301-304`; `/` focuses the image search box, S6 R-TUI-033.1); the Workspace section points to "the folders.html board" and "Change 1" (`window_help.py:318-319`, `:325`); CRC Designer and Reports say "change 1" / "change 2" (`:166-167`, `:187`); Checks, CRC Designer, Reports and Split / Join show `**…**` and `*why*` as typed (`:138`, `:142`, `:156`, `:161`, `:178-185`, `:338-339`). | Rewrite those steps (R-WHELP.12, .13, .14). |
| D7-27 | MAC View, Issues Report and A2B Diff have no help section (`window_help.py:522-533`), so `?` there shows the key panel only. | Write their sections (R-WHELP.1); the chips need D7-30. |
| D7-28 | Dialog lists build file and folder names with markup on: Load project (`screens.py:707`), Select variant (`screens.py:977-983`), Reports (`screens.py:1660`). A name like `[red]x[/]` is styled or breaks the dialog. **At 570b4b5** the Load project list is gone; the Load dialog shows names with markup off (`OptionList(markup=False)`, `screens.py:369`). Select variant (`screens.py:1590-1606`, the title and the list) and Reports (`screens.py:2437`) still read markup. | Plain text (R-DLG.13); the Select variant and Reports lists join S1's safe-text views. The Load project part is superseded by D7-12. |
| D7-29 | The Load dialog's path box hint `C:\path\to\file.s19, .hex, .mac, .a2l, or a project folder` (`screens.py:364`) is cut after `or a` at 118×54 (batch-100 E13 observation OBS-9b-1, routed to the Inc 12a sweep, still open in `.dev-flow/BACKLOG-CODE.md` at 570b4b5). | A shorter hint that shows whole at 118 columns (R-LOADDLG.6). A text change, not a layout change. |
| D7-32 | A printable key typed on the Load dialog's list is added by setting the path box value directly (`screens.py:492-494`), which skips the 4,096-character limit, so the box can reach 4,097 characters (batch-100 SEC9b-1 observation, still open in `.dev-flow/BACKLOG-CODE.md`). | Add the key through the same edit that applies the limit and the control-character rule (R-LOADDLG.19). |
| D7-35 | Batch-100 LLR-178.3 (last sentence) says the Load dialog's preview of the open project shows the same result as the Load-result panel, and the summary line of every project load ends `details: p` to point there (S11 CTX-LOADRES). Inc 6 deferred it to Inc 9b (`increment-006.md`, "Deferred arms"); at 570b4b5 the result is stored (`_last_load_announcement`, `app.py:13708`) and nothing reads it; no test covers it. Once the panel is closed, its problems cannot be seen again. | Show the open project's last load result (load reason and problem rows) in its preview (R-LOADDLG.83). Text-only addition to a preview the P-A verdict already laid out; no new prototype round. |
| D7-33 | An Alt+L queued behind an Escape loads instead of closing (batch-100 declared risk A9b-R2-5, Inc 9b Risks; Alt+L is a priority binding, `screens.py:336`, while Escape goes through `on_key`, `screens.py:479-483`). Declared by the batch, not reproduced here. | Reproduce, then ignore every load request after Escape (R-LOADDLG.59). |

**Prototype first** (visual; prototype round with real captures and the operator's verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D7-30 | MAC View (`app.py:6704`), Issues Report (`app.py:2565`) and A2B Diff (`app.py:5345`) are bare containers: no title row, so no help chip (S2's note). | Where the title row and the `?` chip go on these three windows. |
| D7-31 | Dialog buttons show no key; only the help window's `Close  esc` does (`window_help.py:649`). The button-key standard (2026-10-20): each dialog button shows a direct key; in dialogs with text boxes, an Alt+letter. **At 570b4b5** batch-100's verdicts settled five dialogs: the Load dialog (P-A: `Load (alt+l)`, `Cancel (esc)`), Save project (P-C: `Save (alt+s)`, `Cancel (esc)`), the load question (P-B: `Replace (y)`, `Cancel (n)`), the quit question (`Quit (y)`, `Stay (n)`) and the Load-result panel (P-E: `Select variant (v)`, `Close (esc)`). | Which key per button, and how the button shows it, on the other 12 dialogs. |

**Passed to other groups**

- **S1**: the Load project, Select variant and Reports lists join the safe-text views (D7-28).
- **S6**: the keys that act behind an open dialog (D7-23) are part of the key routing; the `.` key (D6-20) also shows in the key bar (R-KEYBAR.15).
- **S10**: the unsaved-changes guard (`Unsaved changes will be lost`: accept continues the load, Cancel keeps the edits) and the two JSON editors; they follow S7.1.
- **S11**: Save project, Load project and Select variant contents (R-PROJ-ASSIGN-UI-001 stays there).
- **S12**: the Reports dialog (R-RPT-002, R-RPT-ADDENDUM-002, R-RPT-REGION-SKIP-001).
- **S13**: the Operations dialog (R-OPS-003), the CRC write confirmation, and R-HEX-HYGIENE-001's rule that an internal error is not reported as "unknown operation".
- **S16**: Save flow, Load flow and `Discard unsaved flow edits?` contents.
- **S3**: the legend dialog stays there (R-LEGEND-MODAL-001, R-LEGEND-GEOMETRY-001).
- Reconciliation with 570b4b5 (2026-11-01): the items for S1, S5, S6 and S11 are in the reconciliation's passed list (`passed-S7.md`).

---

**Received from later groups** (after all groups were written)

- S7.1 (S2: MAC View header and `?` chip; A2L "section tree") → covered by R-WHELP.3 (D7-30) and R-WHELP.12 (D7-26).
- S7.2 (S5: the load dialog) → covered by R-TUI-043.1 … .3 (S7.2).
- S7.3 (S6: key bar, window help, keys behind a dialog) → covered by S7.5, S7.4 and R-DLG.1 (D7-23); S6 R-TUI-031.2 now leaves dialogs to R-DLG.1.
- S7.4 (S9: the Check Editor's help entry) → covered by R-WHELP.1 (CTX-HELP lists the Check Editor section).
- S7.5 (S10: unsaved-changes popup, the two JSON popups, the Patch Editor help) → row R-WHELP.16 (the Bytes hex note of LLR-161.2); the popups are in CTX-DIALOG and follow S7.1, their paste limit is R-TUI-044.2, their content is S10's (R-PE-012 … 019, R-TUI-053.x, R-TUI-058.x).
- S7.6 (S11: Save, Load project and Select variant widgets and layout) → covered by D7-3 (content stays S11's; its layout round is S11 D11-40) and R-DLG.1 … .13.
- S7.7 (S12: the Reports dialog's common behaviour) → covered by R-DLG.2 (D7-20), R-DLG.7, R-DLG.11, .12 (D7-31). R-RPT-002.13 adds a status for a bad context-bytes value; R-DLG.10 is about an empty required box: no conflict.
- S7.8 (S13: Operations dialog, CRC write confirmation, HYGIENE error rule) → covered by R-DLG.2, R-DLG.6 (D7-22), D7-2; content is S13 R-OPS-003.x, R-OPS-003.11, .12, R-CRC-RECWIDTH-001.1 … .3.
- S7.9 (S14: A2B Diff help section, title row, key-bar keys) → covered by R-WHELP.1 (D7-27), R-WHELP.3 (D7-30) and CTX-KEYBAR's A2B Diff row.
- S7.10 (S16: flow dialogs, Enter on a list item, focus on Cancel, help on the external-step pause, Space on a chip) → row R-WHELP.17 (D16-7); the rest covered by R-DLG.4 (D7-21), R-DLG.6 (D7-22); Space on a chip stays S16 R-FB-RIB.4.
- S7.11 (S17: Split / Join / Export keys, help, manual box) → covered by CTX-KEYBAR (its row), CTX-HELP (its section), CTX-PASTE (the manual ranges are a multi-line box) and S6 R-TUI-031.1 (printable keys are text in a box).

**Reconciled with batch-100 (s19_app 570b4b5)**

- **Rows added**: R-LOADDLG.1 … R-LOADDLG.82 (the Load dialog, from batch-100 HLR-173 … HLR-173e); R-TUI-043.14 … R-TUI-043.24 (a typed path, from batch-100 HLR-172a). Context note CTX-LOADDLG added.
- **Rows changed**: R-TUI-043.1, R-TUI-043.2, R-TUI-043.3 (the Load file dialog became the Load dialog); R-DLG.6 and R-TUI-044.2 (text); "Code today" of R-DLG.1, .2, .3, .4, .5, .9, .10, .11, .12, .13 and R-KEYBAR.4; CTX-DIALOG (dialog table, confirm box, text dialog, confirmation dialog, cancel button), CTX-PASTE (path box, the 4,096 limit), CTX-KEYBAR (row 1 `^l Load`).
- **Rows retired**: none by id. The CTX-DIALOG note "Load file dialog" and the Load file / Load project lines of the dialog table are retired (D7-7); S11's Load project rows are passed for retirement.
- **Decisions added**: D7-7, D7-8, D7-9, D7-12, D7-13, D7-14, D7-15, D7-16 (follow / move), D7-29, D7-32, D7-33 (code change).
- **Decisions changed**: D7-3, D7-10 (cite), D7-20, D7-21, D7-22, D7-23, D7-28, D7-31 (partly settled by batch-100); D7-4 obsolete.
- **Decisions superseded**: D7-28's Load project part, superseded by D7-12. R-DLG.5's reach over the Load dialog ended by D7-8, R-TUI-044.2's reach over the Load path box by D7-9 (rows narrowed, no decision superseded).
- **Consolidation (items from S5, S6, S11)**: rows retired R-LOADDLG.66, .67 (into S11 R-TUI-013.18, .17; D7-34, which supersedes D7-15 for them). Row added R-LOADDLG.83 (the open project's preview shows its last load result, LLR-178.3; No, D7-35, code change). "Code today" of R-LOADDLG.50 names S11 D11-29 (the promised sync does not happen). Already here: the late typed-path status lines (R-TUI-043.18 … .24), the Recent store problems (R-LOADDLG.31, .32), the work-area rows loading as a Workarea Files pick (R-LOADDLG.61), R-DLG.1 partly settled (D7-23), the `Load` / `Projects` labels (D7-16), the quit question's dialog rows (CTX-DIALOG). Rows R-LOADDLG.23 and .27 carry no condition on a loaded file, so the dialog works with nothing loaded (S5 D5-44).

## 6. Counts

| | Old S7 | Strict |
|---|---:|---:|
| Requirement statements | 3 rows | 155 rows (63 before the 570b4b5 reconciliation; 156 before the consolidation: −2 retired R-LOADDLG.66, .67, +1 R-LOADDLG.83) |
| Statements the code contradicts or that are not product behaviour | 3 (043 design and stale key list, 044 design and the excluded box, HYGIENE-001 ids) | 0 |
| Rows by form: U / When / While / If / Where | — | 35 / 65 / 8 / 47 / 0 (before: 22 / 28 / 5 / 8 / 0) |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 32 (15 follow the code or move, 2 remove, 13 correct a defect, 2 prototype first; numbers not contiguous; before: 19) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.
