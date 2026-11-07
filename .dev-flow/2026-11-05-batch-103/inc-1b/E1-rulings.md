# Inc 1b — E1 rulings: scope, canon changes, decisions, overlap with batch-101

Base `e07fb00` (branch `batch-103`; product tree identical). Rows: `01-requirements.md`. Slice: `E1-slice.md`. Evidence: `evidence-e1/i1b-e1-census.py` and its transcript (C; LAN Linux host, Python 3.11.18, textual 8.2.8, the read-only clone at `e07fb00`, no display, isolated HOME / XDG / LOCALAPPDATA, every clipboard writer replaced by a recorder: nothing touched a clipboard, "total os writes recorded: 3" are the recorder's three calls from the text boxes' own copy), `evidence-e1/cw-callers-census.py` and its transcript (Code-Wire v3.1.0 callers on a throwaway copy), `evidence-e1/p1-wt-ctrl-c-probe.py` (pilot P-1, **not run**).

## 1. Scope

**In (US-103-01, the copy-out half):**
- Copy of a **view selection** made in any view, in any window or dialog, to the OS clipboard (R-COPY.1). Today every such copy reaches only the app clipboard and OSC 52 (C §3: 9 views; C §5: a real mouse drag over the hex view). OSC 52 reaches Windows only through a terminal that implements it; conhost does not (b103_ux finding C §1.5 [H] 2).
- Copy of a **whole text view** with no selection: the three hex views, the Workspace A2L summary, the Patch Editor JSON view (R-COPY.3; D-2).
- Copy of the **highlighted row's name** of the A2L tag table and the MAC table (R-COPY.4; D-4). Both are `DataTable`s with `allow_select` False (C §1), so no copy of any kind exists there today.
- The feedback of a copy: the copy notice, the cut notice, the nothing notice (R-COPY.5, .7, .9; D-5, D-6); the cap (R-COPY.8); the app clipboard (R-COPY.2, .6); the OSC 52 request (R-COPY.10); no copy without the key (R-COPY.11). The write failure warning, its log line, the held-clipboard bound and the responsiveness during a write are Inc 1a's general rows R-PASTE.9, .10, .13, .14, met by a copy outside a text box through I-1 and given cases here (/101 …), not restated.
- The copy→paste matrix rows whose source is one of these views: AT-I1b-1 … AT-I1b-7 × both field classes × both paste routes, plus the read by another program (`02-test-cases.md`). The read-back runs on WinCI only: Inc 1a's D-2 (E1 draft) gives Linux no OS clipboard.

**Out (with reason):**
- Copy, cut and paste **inside a text box** (`OsClipboardInput`, `CappedTextArea`), the read cascade, the paste latency and the text-box matrix rows: Inc 1a.
- The four other tables — Patch Editor ledger `#patch_doc_entries_table`, pickers `#patch_param_table`, `#check_param_table`, `#check_mem_table` (C §6: 6 `DataTable`s on the main screen, all `cursor=row`): D-4 recommends leaving them for later (the pickers are rebuilt by Inc 6 and Inc 8). Their selection copy is still covered: none, since `DataTable` allows no selection.
- The Flow Builder's block copy and paste (S16.4, R-FB-CLIP.*): a panel field (`FlowBuilderPanel._clipboard`, `flow_screens.py:1548`, `:2235-2271`), not the app clipboard; it is untouched by the app's copy (R). Cited only.
- The terminal copy (Shift+drag in Windows Terminal): the terminal's own feature; it never reaches the app.
- Keyboard selection inside the non-focusable views (stats pane, tag summary line, detail card): they take no focus (C §1); selection there is by mouse. Backlog BL-1b-3.
- The window help line that names Ctrl+C: D-9 recommends the backlog (BL-1b-1).

## 2. Changes to existing canon rows and notes

No existing row changes. Notes:

| Note | Change | Reason |
|---|---|---|
| CTX-COPY (S7, new, beside CTX-PASTE) | the terms of `01-requirements.md` §Definitions | R-COPY.1 … .11 cite them. |
| CTX-KEYS (S6) | one sentence above the table: "Ctrl+C and Ctrl+V act on text boxes and views (S7 CTX-PASTE, CTX-COPY); they are not palette commands." | Only under D-3 A: the copy key is not a command of CTX-KEYS, so R-TUI-022.2 (one palette command per CTX-KEYS command) adds no `Copy` command, as Ctrl+V has none today. |

Cited and unchanged: Inc 1a's E1-draft rows R-PASTE.9, .10, .13, .14 (the OS write's failure warning, log line, held-clipboard bound, responsiveness — general rows a view copy meets through I-1; cases /101 …) and R-PASTE.1 (a terminal paste into a single-line box); R-TUI-043.13 (no clipboard text in the log — read as applying to copied text too; case /101), R-TUI-043.4, -044.3, -044.4 (the paste targets of the matrix), R-SHELL-FOCUS.2 (the tag table as the A2L Explorer's focus target), R-TUI-022.2 (the palette: no new command under D-3 A), R-KEYBAR.1 … .15 (the key bar: no new token under D-3 A), R-TUI-004.1 (the row format the hex views paint).

**Observation OBS-1 (reported, not changed — outside this increment):** CTX-HEX's row format reads `<marker><address>  <16 × "XX ">|<16 text characters>|`, so one space before `|`; the code paints two (`" |"` after the 16 cells, `s19_app/render/hexview.py:383`; a painted row is 81 characters, C §5b). Either the note or the code is wrong for R-TUI-004.1. Inc 1b copies the painted text, so it depends on neither. For the requirements session.

## 3. Decisions — each **PROPOSED — awaiting orchestrator ruling**

The rows, slice and cases follow the recommendation of each.

| # | Question | Options and consequences | Recommendation and reason |
|---|---|---|---|
| D-1 | How a selection copy reaches the OS clipboard | **A** One seam for every in-app copy: the app's own copy (`copy_to_clipboard`, which the toolkit's selection copy `Screen.action_copy_text`, the stock `TextArea`/`Input` copy and the text boxes' mirror all call — textual `screen.py:985-990`, `widgets/_text_area.py:2653-2659`; `os_clipboard_input.py:764`) keeps its app clipboard and OSC 52 and adds the OS write of I-1. Covers every view, every window and every dialog, and the stock read-only JSON view, with no widget change. Needs an I-1 clause (§7) so that a text-box copy, which mirrors through the same seam, writes once and notifies once. **B** Per screen: a default-screen subclass overrides the selection copy, and the JSON view becomes a `CappedTextArea(read_only=True)` (`screens_directionb.py:5030-5035`). Dialogs keep OSC 52 only (a gap in "every window"), and B touches the file Inc 12 edits. **C** Per view: a copy action on each named view only; no general selection route; the stats pane, summaries, cards and dialogs stay on OSC 52. | **A.** One place, the widest reach, the smallest diff (`app.py` only), and the rows can be met for "outside a text box" without listing widgets. |
| D-2 | What the copy key copies in a text view with no selection | **A** the view's whole shown text (hex: notice lines and every painted row, up to the hex page size, 201 lines on the census fixture; JSON: the shown JSON, up to 5000 lines plus `showing 5000 of <N> lines`). It also gives keyboard-only users a copy of the hex views, where a `Static` cannot be selected by keys. **B** nothing: the nothing notice; copy needs a mouse selection. Keyboard-only users cannot copy hex. **C** the `> ` target row only, else nothing. A partial rule the operator has to learn; useless before a go-to. | **A.** One rule for all five text views, testable as "the painted lines", and the JSON view gains a whole-document copy (its select-all is F7, which few know; Ctrl+A moves to the line start, C §2). |
| D-3 | The copy key | **A** Ctrl+C, the key text boxes already use (textual `widgets/_input.py:139`, `_text_area.py:381`) and the toolkit's selection-copy key (`screen.py:272`). No key-bar token, no palette command (CTX-KEYS sentence, §2). Depends on P-1: Windows Terminal passes Ctrl+C on when it holds no selection of its own, and copies itself when it holds one (then the terminal copy fills the clipboard directly). **B** `y` (free: C §2, no binding; `c` is Flow Execution's Confirm and R-SHELL-KEYS.2 makes `c` do nothing elsewhere). Reaches the app always; needs a key-bar token in three windows (CTX-KEYBAR, R-KEYBAR.3), a palette command (R-TUI-022.2, CTX-KEYS) and a help line — a visible change, so a prototype round with the operator's verdict before E2. **C** both. | **A**, gated on P-1 before E4. The operator asks for copy "in every window" next to Ctrl+V; a second, app-only copy key is a convention to learn (tui-design NAVIGATION: inherit, don't invent). If P-1 fails, B with a prototype round. |
| D-4 | What a table copies, and which tables | **A** the highlighted row's name (Tag cell without its glyph and space), A2L tag table and MAC table. Pasted into a single-line box it is a usable filter, picker or list entry (the boxes keep the first line, R-TUI-043.4). **B** the row's cells as shown, tab-separated (16 cells for a tag, glyph included, C §5b): pastes well into a spreadsheet, badly into every box of the app (the filter gets `· NAME\t0x00013A00\t1\t…` and matches nothing; the bulk-list parser splits on tabs and reports 15 names not found, `a2l_parameter_picker.py:75`). **C** the name, A2L tag table only. **D** A for all six tables. | **A.** The story's main target is the app's own text boxes (operator note of 2026-11-05) and the A2L list work of Inc 7; the detail card keeps every field selectable for a full copy. A2L + MAC because both tables name tags in the same Tag column; the four editor tables are rebuilt by Inc 6/8 (backlog BL-1b-2). |
| D-5 | Feedback after a copy | **A** the copy notice `Copied <n> lines to the clipboard.` (`1 line` for one) on every copy outside a text box, after the OS write succeeds; the cut notice when the cap applied; the write failure warning (Inc 1a's R-PASTE.9) when the write fails. **B** no notice on success (the text boxes today). A copy without a visible selection (whole view, row name) then gives no sign that anything happened. **C** a notice only for the copies without a visible selection. | **A** (tui-design FEEDBACK: the outcome first, in one message). **Cross-increment:** recommend that Inc 1a's text-box copy shows the same notice, so every copy answers the same way; the orchestrator pins it in I-1 (under D-1 A the text box's mirror passes through the same seam, so one rule is also the simplest code). |
| D-6 | The copy key with nothing to copy | **A** the nothing notice `Nothing copied — select text with the mouse first.`, both clipboards unchanged. **B** keep the toolkit's quit hint `Press ctrl+q to quit the app` / `Do you want to quit?` (C §4), which answers a copy key with a quit question; `q` already quits and row 1 of the key bar shows it (R-KEYBAR.2). | **A.** Note for Inc 1a: under D-1 A a Ctrl+C in a text box with no selection also falls through to this notice (the box's copy raises `SkipAction`, `os_clipboard_input.py:861-863`); its text says "with the mouse", true for views, partial for text boxes (Shift+arrows). Inc 1a may want its own wording there (BL-1b-5); its R-PASTE.5 (no selection in a text box → the clipboards unchanged) holds either way. |
| D-7 | Where the no-selection copy lives (E2 picks the code; the rows do not depend on it) | **A** an override of the toolkit's Ctrl+C fallback action (`App.action_help_quit`, bound by the toolkit on `App`, textual `app.py:463`, `:3990-4002`): it runs only after the focused widget's copy and the selection copy have passed (C §2 chain: widget → `screen.copy_text` → `help_quit`); no new binding, no palette entry; reached under b101 Inc 12's *reach* (a toolkit binding on a toolkit base class). The name reads oddly; its docstring must say why. **B** a new `S19TuiApp` binding `ctrl+c` → a new `copy_view` action: it replaces the toolkit fallback by name, but `_build_palette_entries` (`app.py:9926-9967`) turns every `BINDINGS` entry into a palette command, so `Copy` enters the palette and CTX-KEYS (R-TUI-022.2), unless the builder learns to skip it (a further change). **C** a default-screen subclass's `action_copy_text` (with D-1 B). | **A**, by the smallest surface. |
| D-8 | Canon module for the new rows | **A** S7, a new section "S7.3b · Copy out of a view (CTX-COPY)" after S7.3, the copy beside the paste. **B** spread: hex rows to S4, table rows to S2, JSON to S10. | **A.** One mechanism for every window; S4, S2 and S10 keep what their views show. |
| D-9 | Discoverability of Ctrl+C in views | **A** a step line in the help sections of Workspace, A2L Explorer and Patch Editor ("Ctrl+C copies the selected text, the highlighted tag name or the whole view") — a third source file, `window_help.py`, and a G1-plan change. **B** backlog: the convention carries it; where `?` shows the key panel (R-TUI-DISCOVER-001.1: windows without a help section), it lists Ctrl+C as the toolkit's `Copy selected text` (it lists every active binding that is not a system one, textual `widgets/_key_panel.py:38-80`). | **B** (BL-1b-1): the plan's file list stays `app.py` (+ `screens_directionb.py` only under D-1 B). |
| D-10 | Sources of the copy→paste matrix | **A** the five plan sources + the MAC table + one dialog (7 sources × 2 classes × 2 routes = 28 cells). **B** the five plan sources only (20 cells). | **A**: the dialog cell is the cheapest proof of "every window" for D-1 A; the MAC cell follows D-4 A. |

## 4. Inputs that must reach the app (rule: cite evidence or name a pilot)

| Input | Evidence | State |
|---|---|---|
| A mouse drag selects text in a `Static` view | C §5 (headless pilot drag over `#hex_view`: 203 characters selected) | `executed` (headless, Linux). In Windows Terminal a plain drag goes to the app while it tracks the mouse; Shift+drag makes a terminal selection (WT documented behaviour, R, not verified here). |
| Ctrl+C reaches the app as a key | R: textual's Windows driver sets the console input mode to `ENABLE_VIRTUAL_TERMINAL_INPUT` alone (`drivers/win32.py:158-180`), so Ctrl+C is a byte, not a signal; C §2: the binding chain `widget copy → screen.copy_text → help_quit`. Unverified: that Windows Terminal passes Ctrl+C on when it holds no selection (its default `copy` binding acts on its own selection; b103_ux finding C F2: this PC's WT binds `ctrl+c` → `copy`). | **P-1 `planned`**: `evidence-e1/p1-wt-ctrl-c-probe.py` in Windows Terminal (and conhost, optional), by the orchestrator under the G1 exception; it touches no clipboard (no selectable text, `copy_to_clipboard` replaced, key names only). Pass = `ctrl+c` logged twice. Gates E4 of R-COPY.1, .3, .4, .5 (D-3). |
| Shift+Down, F7 in the read-only JSON view | C §2: `f7` → `TextArea:select_all`; selection keys are the toolkit's | `executed` (headless) |
| Ctrl+V reaching the app; the terminal paste (`events.Paste`) | Inc 1a's evidence (`inc-1a/evidence-e1/i1a-pilot-transcript.txt` P4, P6); b103_ux finding C §1.3 | Inc 1a's |
| A separate process reads the OS clipboard after the copy | Inc 1a's *isolated clipboard* on WinCI, read by a separate system PowerShell `Get-Clipboard -Raw` (its clipboard probe, R-PASTE.22); on Linux there is no OS clipboard under Inc 1a's D-2 (its draft), and today the Linux write fails anyway (Tk off the screen's thread, no display: Inc 1a pilot P3, P5) | `planned` on WinCI, whose clipboard is PLAN's open risk (risk 2) |

## 5. Ids checked unused

`R-COPY` (any suffix): 0 hits in `REQUIREMENTS.md`, `docs/requirements/`, `C:\Users\jjgh8\Github\s19w\review\`, every `.dev-flow/*/` folder except this one (only the id assignment in `2026-11-05-batch-103/steps.log`), `git grep` on `b101-inc9`, `b101-inc10`, `b101-inc12`, every other `b101-*` branch and `main`. `CTX-COPY`, `S7.3b`: 0 hits in the same places and `b101-canon`. `AT-I1b` (and `AT-I1B`): 0 hits on every branch, in `.dev-flow/` (outside this folder) and `tests/`; a letter-initial body, outside the `AT-TC-REGISTRY.jsonl` authority (its `_meta.governed`).

## 6. Overlap with batch-101 (Inc 10a, 10b, 12, 12b, 9) — nothing fixed twice, nothing contradicted

| b101 | What it changes | Where Inc 1b meets it | Ruling for E2–E4 |
|---|---|---|---|
| 10a | `update_hex_view`, `update_alt_hex_view`, `update_mac_hex_view`, `_row_start_for_near_top_focus`, new `_hex_view_rows`, `hex_row_bases` (window start one view row above a target, scroll reset, `> ` marker removal; R-TUI-018.1 … .4, R-TUI-040.4, .8, .11, .12, R-TUI-007.3, .5, .8) | R-COPY.3, R-COPY.7/3 and AT-I1b-1 copy the painted text of these views; Inc 1b changes none of these functions | the 201-line count and the copied rows are `e07fb00` numbers: re-measure after 10a merges; tests take the expected text from the painted view, never from literal rows. The copy keeps the 2-character marker column as painted and changes no marker. |
| 10a | focus after a rail key: `action_show_screen`, new `_land_focus` (R-SHELL-FOCUS.2 … .5); on the base the focus stays in the hidden Workspace after `2` | R-COPY.4/3 needs the tag table focused after `2`; R-COPY.5/4 covers a focus left on a hidden table | R-COPY.4/3 is RED on the base for 10a's reason and holds after it; Inc 1b does not move focus. R-COPY.3 … .6 read "shown" (the b101 Inc 12 CTX-SHELL term *shown widget*), so a hidden view is never copied. |
| 10a | R-SEG-OPEN.7: no key of a hidden Split / Join window runs | the copy fallback acts on the focused widget only | consistent: a focused widget in a hidden window is not shown → nothing notice (R-COPY.5/4). |
| 10b | `_repaint_a2l_tag_cells`, `_refresh_hex_views_after_write` (cells and hex rows repainted in place after a write; the highlighted row, window and marker kept; R-A2L-048, -049, -105, -106, R-TUI-004.7 … .9) | R-COPY.4 reads the highlighted row's painted Tag cell; R-COPY.3 the painted hex rows | consistent: a copy after a write takes what is painted then; names do not change on a write. No function in common. |
| 12 | R-SHELL-KEYS.3 (every action has a reach; census ≥ 80 actions, the six clipboard overrides reached by toolkit bindings) | D-7 A adds `S19TuiApp.action_help_quit` | reached by the toolkit's `App` binding `ctrl+c` (a toolkit base class of `S19TuiApp`), as Inc 12's *reach* defines; the census total moves 80 → 81, inside "≥ 80". Under D-7 B the new binding is the reach, and the palette grows (§3). |
| 12 | R-DLG.14 (every dialog has an opener) | Inc 1b adds no dialog | none. |
| 12 | `CheckEditorPanel.compose`, `.on_button_pressed` (`screens_directionb.py:7708-7845`, `:7912-7959`); frozen id sets `PE_IDS_9C7BEAF`, `CE_IDS_9C7BEAF` (`tests/b97_fixtures.py`) | D-1 A: no change in `screens_directionb.py`. D-1 B: `PatchEditorPanel.compose` (`:4930-5284`, the view at `:5030-5035`) | another class, no function in common; no id added or removed (B changes the class, not the id). Merge after Inc 12. |
| 12 | R-DLG.2, .15 (Escape closes the Reports dialog) | AT-I1b-7 closes a help window with Escape (R-WHELP) | consistent. |
| 12b | `flow_screens.py` only | the Flow Builder's own block copy (S16.4) | untouched (§1 Out). |
| 9 | `app.py` flow save handlers (`:3988-4572` on its base) | none | none. |

Keys: no b101 increment binds Ctrl+C, and Inc 1b binds no letter key (D-3 A).

## 7. Interface I-1 (Inc 1a → Inc 1b) — assumptions to pin before Inc 1b's E2

Inc 1a's `01-requirements.md` (E1 draft) appeared at the end of this E1 and was read, not edited; its `E1-rulings.md` (where its I-1 section will be) was not there yet. Alignment made: Inc 1a's CTX-PASTE terms (*OS clipboard* = the Windows clipboard, its D-2; *text box*; *selection*, in a text box — hence this increment's term *view selection*; *write failure warning*; *OSC 52 clipboard request*; *responsive*; *isolated clipboard*) are used as defined there; its general rows R-PASTE.9, .10, .13, .14 are cited, not restated; the AT ids follow its `AT-I1a-n` form (`AT-I1b-n`). Inc 1b assumes, from the shape of `e07fb00` and that draft:
1. **A write call** that takes the copied text, caps it at 65,536 characters, writes the OS clipboard with no cross-thread toolkit call, and tells the caller whether it wrote (today `write_os_clipboard(text) -> bool`, `os_clipboard_input.py:665-724`, run by the caller in an executor, `:769`). Inc 1b needs the boolean for R-COPY.7 and R-PASTE.9 and the cap for R-COPY.8 / .9.
2. **One copy, one write, one notice** (D-1 A): the text boxes' copy tail (`_mirror_and_write_os_clipboard`, `:727-782`; callers `capped_text_area.py:268`, `:306`, `os_clipboard_input.py:864`, `:892`, Code-Wire census) mirrors into the app clipboard through `app.copy_to_clipboard` (`:764`). If the app's copy seam writes the OS clipboard (D-1 A), that mirror must reach the toolkit's base copy (app clipboard + OSC 52) and not the app's seam, or the tail must become the seam itself; otherwise every text-box copy writes twice and notifies twice. The orchestrator pins which side changes.
3. **The failure arrangements** Inc 1a's cases use: Linux (every write fails, its D-2) and the held clipboard on WinCI (R-PASTE.13's helper), for R-PASTE.9/101 … /103, R-PASTE.13/101, R-PASTE.14/101 … /103.
4. **No X write** (Inc 1a D-2 A): every read-back case of Inc 1b runs on WinCI; on Linux they are not applicable and the Linux cases check the app clipboard, OSC 52 and the warning. If D-2 is ruled otherwise (an X write), the same cases also run on a private Xvfb display (risk 2).
5. The write failure warning's text `Clipboard write failed — copied inside the app only.` stays (R-PASTE.9).

## 8. Risks

1. **Double write / double notice** through the shared seam (§7 item 2) — design, E2.
2. **Read-back on WinCI only:** with Inc 1a's D-2 A there is no OS clipboard on Linux, so every "other program" case, every terminal-paste cell of the matrix and R-COPY.1, .3, .4, .8, .11 are verified only on the `windows-latest` job, whose clipboard availability is PLAN's open risk (Inc 1a's probe R-PASTE.22 skips them with a reason if it fails; then the operator rules on the fallback). On Linux a view copy shows the write failure warning, by that ruling.
3. **Ctrl+C pass-through in Windows Terminal** unverified (P-1); under conhost it is unknown too, and conhost has no OSC 52, so today a selection copy there never reaches Windows (b103_ux finding C §1.5 [H] 2) — D-1 A fixes that by the OS write.
4. **Privacy:** a copy puts calibration names, addresses or bytes on the OS clipboard, where Windows clipboard history or cloud sync may keep them. Only the operator's key copies (R-COPY.11), and no copied text is logged (R-TUI-043.13/101). For E3 security: whether a painted name can still carry control characters into the clipboard (the Tag cell is `safe_text` of the name with line feeds replaced, `app.py:20432`; painted text, not markup — but C0 characters other than the line feed are not shown to be removed).
5. **The quit hint goes away** (D-6 A): an operator who presses Ctrl+C to quit now reads "Nothing copied"; `q Quit` stays in row 1 of the key bar.
6. **OSC 52 and the OS write both fire** (D-1 A keeps the toolkit's copy): in Windows Terminal both write the same text; over SSH OSC 52 remains the only route. Harmless, noted for E3.

## 9. Census caveats (read with the transcript)

- C §3 on the two `DataTable`s shows a copy of 0 characters: the census called `text_select_all()` on a widget that allows no selection, and the toolkit's selection copy then copied an empty string. No operator route makes that selection (a drag on a table selects nothing); R-COPY.6's negative control names the risk.
- C §4 on `#search_input` copied 7 characters: the selection set in C §3 survived the `value` assignment. A census artifact (the text box is Inc 1a's).
- The census drives `action_show_screen` and `focus()` directly to reach each view; the cases of `02-test-cases.md` use the keys.

## 10. Backlog (from this E1)

- BL-1b-1 — a help-section line naming Ctrl+C in Workspace, A2L Explorer and Patch Editor (D-9 B).
- BL-1b-2 — copy of the Patch ledger and the three picker tables (D-4 A); revisit after Inc 6/8.
- BL-1b-3 — the stats pane, the tag summary line and the detail card take no focus: no keyboard-only copy there.
- BL-1b-4 — OBS-1, the CTX-HEX row-format space (§2), for the requirements session.
- BL-1b-5 — the nothing notice's wording for a Ctrl+C in a text box with no selection (D-6), with Inc 1a.

## Orchestrator rulings (2026-11-06T16:18:57-06:00, Opus 5.5)

| Decision | Ruling | Reason / change to the rows |
|---|---|---|
| D-1 | **A** + I-1 clause | One app-level seam. I-1: every copy writes the OS clipboard once and shows one notice (text boxes included); mechanism pinned at this increment's E2, after Inc 1a's E4. |
| D-2 | **operator** | Whole-view copy with no selection replaces the operator's clipboard on a bare Ctrl+C; that is the operator's call (asked 2026-11-06). Rows stay as written until the answer. |
| D-3 | **A, gated on P-1** | P-1 (Ctrl+C reaches the app in Windows Terminal with no terminal selection) is checked by the operator on the main PC, by hand (asked 2026-11-06). If it fails: B with a prototype round. |
| D-4 | **A** | Bare name of the highlighted row (the label-list use case). |
| D-5 | **A** | `Copied <n> lines to the clipboard.` for every copy, text boxes included, through the seam (I-1). |
| D-6 | **A, one wording** | `Nothing copied — select text first.` for views and text boxes alike ("with the mouse" is false for text boxes, Shift+arrows). BL-1b-5 closed by this. |
| D-7 | **A** | Smallest surface; docstring says why. |
| D-8 | **A** | S7.3b / CTX-COPY. |
| D-9 | **backlog** | |
| D-10 | **A** | 7 sources. |

## Operator rulings 2 (2026-11-06T18:03:39-06:00) — supersede D-2, D-3, D-6 and D-7 above

The operator ruled that Ctrl+C is the terminal's quit key and must not be the general copy key.
- **Copy from a view = right-click on a selection** (the toolkit's mouse selection). Right-click on a view with no selection does nothing (no notice). D-2 (whole-view copy) is withdrawn.
- **Ctrl+C with a selection** (a text box's or the screen's) copies it — orchestrator extension of the operator's text-box answer, for one rule everywhere; flagged to the operator.
- **Ctrl+C with no selection** opens a quit confirmation dialog: y quits, n (and Escape) closes it and changes nothing (key-letter buttons, repo modal standard). It replaces the toolkit's quit hint (D-7's override point now opens the dialog). D-6's nothing notice is withdrawn.
- **Right-click in a text box** (copy / paste) is Inc 1a's; the copy notice `Copied <n> lines to the clipboard.` (D-5) comes from this increment's seam for every copy (I-1).
- **Prototype round 2 (G2)** shows the quit dialog and the copy notice before this increment's E2 (it waits for batch-101 Inc 10a/12 anyway).
- Batch-101 Inc 12's dialog census (R-DLG.14, "every dialog has an opener"; its count of dialogs) grows by this dialog: note it for the integration.
- Action: an E1 addendum rewrites the key rows, adds the dialog rows (opener, y, n, Escape, exact title/body text), withdraws D-2/D-6 rows, and re-cuts the matrix (sources reached by right-click).
