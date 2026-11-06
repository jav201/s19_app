# Inc 1b — test cases (ISO/IEC/IEEE 29119-3), E1

One case per coverage item `<requirement id>/<n>` of `01-requirements.md`; the cases of the cited rows R-PASTE.9, .10, .13, .14 (Inc 1a's E1 draft ids) and R-TUI-043.13, numbered from 101; and the acceptance cases `AT-I1b-1` … `AT-I1b-7` (the copy→paste matrix, one cell per `/<n>`). Written at E1, before any test and before b101 Inc 10a / 12 merge (A1): **Tests** is empty, **Coverage** is `gap` and **Result** is `not_run` everywhere; testers fill them at E4. Values marked "(e07fb00)" are the census's and are re-measured on the merged tree before they enter a test; a test takes a view's expected text from the painted view, never from a literal copy of these rows.

## Common fixtures

- **WinCI** (every case that reads the OS clipboard back). Inc 1a's *isolated clipboard*: the GitHub-hosted `windows-latest` job (`GITHUB_ACTIONS` = `true`, `RUNNER_ENVIRONMENT` = `github-hosted`), asserted before the first write (Inc 1a's R-PASTE.21), skipped by its clipboard probe when the runner's clipboard is unusable (R-PASTE.22). No case runs on a desktop session; none saves or restores a clipboard. If Inc 1a's D-2 is ruled to give Linux an X clipboard, the same cases also run on a private Xvfb display started by the test session, read back by `xclip -o -selection clipboard`.
- **Linux** (the LAN host, no OS clipboard under Inc 1a D-2): the cases that need no read-back (the app clipboard, OSC 52, the notices, a failing write).
- **Separate read.** A system PowerShell `Get-Clipboard -Raw` process (absolute path), as Inc 1a's clipboard probe.
- **Seed.** Before each case the separate process writes `SEED-1b` to the OS clipboard (WinCI), and the test sets the app clipboard to `SEED-1b`.
- **Census session.** `S19TuiApp(base_dir=<tmp>)` at 118×54; `examples/case_00_public/prg.s19` and `synthetic_update_test1.mac` loaded with `load_from_path`, `ASAP2_Demo_V171.a2l` with `load_a2l_from_path` (the app's loaders, copies in `<tmp>`), as `evidence-e1/i1b-e1-census.py` does. Windows reached by their rail keys (`1` Workspace, `2` A2L Explorer, `3` MAC View, `6` Patch Editor).
- **Drag.** `pilot.mouse_down(<view>, offset)`, `pilot.hover(<view>, offset)`, `pilot.mouse_up(<view>, offset)` (C §5's route). **The selection's text** = `app.screen.get_selected_text()` read after the drag (the oracle of what the operator selected).
- **Notices.** The app's notification list after the handlers settle (message, severity), not a spy on a setter.
- **OSC 52 count.** The requests the app sends to its driver, decoded (Inc 1a's R-PASTE.15 method).
- **Failing writer / held clipboard / slow writer.** Linux: every OS layer fails by Inc 1a D-2. WinCI: a helper process holds the clipboard open for 8 s (Inc 1a's R-PASTE.13 fixture).
- **Paste routes.** *P1*: Ctrl+V pressed with the target focused (the app's own paste, Inc 1a's read path). *P2*: a terminal paste: `events.Paste(<separate read>)` posted to the App, as the driver posts it (Inc 1a's R-PASTE.1 method).
- **Targets.** *T1*: the single-line box `#a2l_tags_filter_input` (A2L Explorer, focused with `/`), empty before the paste. *T2*: the multi-line box `#patch_paste_text` (Patch Editor, JSON tab, clicked, its whole text selected with F7 so the paste replaces it, R-TUI-043.5).

## Cases

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-COPY.1/1 | Verify that a hex-view selection is written to the OS clipboard | normal | WinCI; Seed; Census session; Workspace shown | Drag over 3 rows of `#hex_view`; `ctrl+c` | separate read = the selection's text (3 lines) |  | gap | not_run |
| R-COPY.1/2 | Verify the stats pane selection | normal | as /1 | Drag over the whole `#ws_stats` (5 lines; e07fb00 the first `Coverage: 6.68%`); `ctrl+c` | separate read = the selection's text |  | gap | not_run |
| R-COPY.1/3 | Verify the A2L tag summary line | normal | as /1; A2L Explorer shown | Drag over `#a2l_tags_summary`; `ctrl+c` | separate read = the selection's text (e07fb00: `Page 1/1 \| tags 1-118 / 118 …`) |  | gap | not_run |
| R-COPY.1/4 | Verify the detail card | normal | as /3; a tag highlighted | Drag over `#a2l_detail_card`; `ctrl+c` | separate read = the selection's text |  | gap | not_run |
| R-COPY.1/5 | Verify a keyboard selection in the JSON view | normal | as /1; Patch Editor, JSON tab; `#patch_json_view` clicked | `shift+down` ×2; `ctrl+c` | separate read = the view's selected text (2 lines) |  | gap | not_run |
| R-COPY.1/6 | Verify a selection in a dialog | normal | as /1; Workspace; `?` (its help window open, R-WHELP.5) | Drag over the first two lines of the help text; `ctrl+c` | separate read = the selection's text |  | gap | not_run |
| R-COPY.2/1 | Verify that a view-selection copy fills the app clipboard | normal | Linux and WinCI; Seed; as R-COPY.1/1 | as R-COPY.1/1 | `app.clipboard` = the selection's text |  | gap | not_run |
| R-COPY.2/2 | Verify that a text-view copy fills the app clipboard | normal | Linux and WinCI; Seed; Census session; `#hex_scroll` focused, nothing selected | `ctrl+c` | `app.clipboard` = the shown text of `#hex_view` |  | gap | not_run |
| R-COPY.2/3 | Verify that a row-name copy fills the app clipboard | normal | Linux and WinCI; Census session; `2`; `down` ×2 | `ctrl+c` | `app.clipboard` = `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` |  | gap | not_run |
| R-COPY.2/4 | Verify the app clipboard when the OS write fails | robustness | Linux (Failing writer); as /3 | `ctrl+c` | `app.clipboard` = `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` |  | gap | not_run |
| R-COPY.3/1 | Verify the main hex view's whole copy | normal | WinCI; Seed; Census session; Workspace; `#hex_scroll` focused; nothing selected | `ctrl+c` | separate read = the painted lines of `#hex_view` joined by line feeds (e07fb00: 201 lines, the first `... window limited to 200 rows ...`) |  | gap | not_run |
| R-COPY.3/2 | Verify the A2L hex view | normal | as /1; A2L Explorer; `#alt_hex_scroll` focused | `ctrl+c` | separate read = the painted lines of `#alt_hex_view` |  | gap | not_run |
| R-COPY.3/3 | Verify the MAC hex view | normal | as /1; MAC View; `#mac_hex_scroll` focused | `ctrl+c` | separate read = the painted lines of `#mac_hex_view` |  | gap | not_run |
| R-COPY.3/4 | Verify the A2L summary | normal | as /1; Workspace; `#a2l_scroll` focused | `ctrl+c` | separate read = the painted lines of `#a2l_view` (e07fb00: 4 lines, the first `A2L summary lines 1-2 / 2`) |  | gap | not_run |
| R-COPY.3/5 | Verify the JSON view | normal | as /1; Patch Editor, JSON tab; `#patch_json_view` focused; no selection | `ctrl+c` | separate read = the view's whole text |  | gap | not_run |
| R-COPY.4/1 | Verify the A2L tag table's row name | normal | WinCI; Seed; Census session; `2`; `down` ×2 (the third row highlighted) | `ctrl+c` | separate read = `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` — one line, no glyph, no tab |  | gap | not_run |
| R-COPY.4/2 | Verify the MAC table's row name | normal | as /1; `3`; the record table focused; `down` ×2 | `ctrl+c` | separate read = `Curve_ExternalAxis` |  | gap | not_run |
| R-COPY.4/3 | Verify the copy right after the rail key | normal | as /1; Workspace shown | `2`; `ctrl+c` (no other key) | separate read = the first row's row name (needs b101 Inc 10a's R-SHELL-FOCUS.2; RED on e07fb00 for that reason) |  | gap | not_run |
| R-COPY.5/1 | Verify the nothing notice on a button | robustness | Linux; Census session; Workspace; `#search_button` focused; nothing selected | `ctrl+c` | one notice `Nothing copied — select text with the mouse first.`, information; no notice titled `Do you want to quit?` |  | gap | not_run |
| R-COPY.5/2 | Verify the nothing notice with no focus | robustness | as /1; no widget focused | `ctrl+c` | as /1 |  | gap | not_run |
| R-COPY.5/3 | Verify the nothing notice on an empty table | robustness | Linux; `S19TuiApp` with `prg.s19` only (no A2L); `2`; the tag table focused (0 rows) | `ctrl+c` | as /1 |  | gap | not_run |
| R-COPY.5/4 | Verify the nothing notice on a table of a hidden window | robustness | Linux; Census session; `1` (Workspace shown); the focus put on `#a2l_tags_list` (the base's hidden-focus shape) | `ctrl+c` | as /1 (the hidden table's row name is not copied) |  | gap | not_run |
| R-COPY.6/1 | Verify both clipboards unchanged on a button | robustness | Linux and WinCI; Seed; as R-COPY.5/1 | `ctrl+c` | `app.clipboard` = `SEED-1b`; on WinCI the separate read = `SEED-1b` |  | gap | not_run |
| R-COPY.6/2 | Verify with no focus | robustness | as /1; as R-COPY.5/2 | `ctrl+c` | as /1 |  | gap | not_run |
| R-COPY.6/3 | Verify on an empty table | robustness | as /1; as R-COPY.5/3 | `ctrl+c` | as /1 |  | gap | not_run |
| R-COPY.6/4 | Verify on a table of a hidden window | robustness | as /1; as R-COPY.5/4 | `ctrl+c` | as /1 |  | gap | not_run |
| R-COPY.7/1 | Verify the copy notice for one line | normal | WinCI; as R-COPY.4/1 | `ctrl+c` | exactly one notice `Copied 1 line to the clipboard.`, information |  | gap | not_run |
| R-COPY.7/2 | Verify the copy notice for 5 lines | normal | WinCI; as R-COPY.1/2 | as R-COPY.1/2 | exactly one notice `Copied 5 lines to the clipboard.` |  | gap | not_run |
| R-COPY.7/3 | Verify the copy notice for a whole hex view | normal | WinCI; as R-COPY.3/1 | `ctrl+c` | exactly one notice `Copied <n> lines to the clipboard.`, `<n>` = the painted line count (e07fb00: `201`) |  | gap | not_run |
| R-COPY.7/4 | Verify no copy notice when the write fails | robustness | Linux (Failing writer); as R-COPY.2/3 | `ctrl+c` | no notice starting `Copied`; the write failure warning once (R-PASTE.9/103) |  | gap | not_run |
| R-COPY.8/1 | Verify the cap on a whole JSON view | robustness | WinCI; Seed; Patch Editor with a loaded change document whose shown JSON is longer than 65,536 characters (E4 builds it; `<N>` its length); `#patch_json_view` focused; no selection | `ctrl+c` | `app.clipboard`, the decoded OSC 52 request and the separate read are each 65,536 characters long and equal the shown text's first 65,536 |  | gap | not_run |
| R-COPY.8/2 | Verify the cap on a whole-view selection | robustness | as /1 | `f7`; `ctrl+c` | as /1 |  | gap | not_run |
| R-COPY.9/1 | Verify the cut notice on a whole JSON view | robustness | as R-COPY.8/1 | `ctrl+c` | exactly one notice `Copied the first 65,536 characters to the clipboard (<N> in all).`, `<N>` with a comma every three digits; no copy notice |  | gap | not_run |
| R-COPY.9/2 | Verify the cut notice on a selection | robustness | as R-COPY.8/2 | `f7`; `ctrl+c` | as /1 |  | gap | not_run |
| R-COPY.10/1 | Verify the OSC 52 request of a view-selection copy | normal | Linux and WinCI; Census session; as R-COPY.1/1 | as R-COPY.1/1 | exactly 1 OSC 52 request, decoding to the selection's text |  | gap | not_run |
| R-COPY.10/2 | Verify the OSC 52 request of a text-view copy | normal | as /1; `#hex_scroll` focused, nothing selected | `ctrl+c` | exactly 1 request, decoding to the shown text of `#hex_view` |  | gap | not_run |
| R-COPY.10/3 | Verify the OSC 52 request of a row-name copy | normal | as /1; `2`; `down` ×2 | `ctrl+c` | exactly 1 request, decoding to `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` |  | gap | not_run |
| R-COPY.11/1 | Verify that a drag copies nothing | normal | WinCI; Seed; Census session; Workspace | Drag over 3 rows of `#hex_view`; no `ctrl+c` | separate read = `SEED-1b` |  | gap | not_run |
| R-COPY.11/2 | Verify that moving the highlight copies nothing | normal | WinCI; Seed; Census session; `2` | `down` ×3 | separate read = `SEED-1b` |  | gap | not_run |
| R-COPY.11/3 | Verify that F7 in the JSON view copies nothing | normal | WinCI; Seed; Census session; Patch Editor, JSON tab; `#patch_json_view` focused | `f7` | separate read = `SEED-1b` |  | gap | not_run |
| R-PASTE.9/101 | Verify the write failure warning for a view selection | robustness | Linux (Failing writer); Census session; as R-COPY.1/1 | as R-COPY.1/1 | exactly one notice `Clipboard write failed — copied inside the app only.`, warning, 6 s |  | gap | not_run |
| R-PASTE.9/102 | Verify it for a text view | robustness | Linux; Census session; `#hex_scroll` focused | `ctrl+c` | as /101 |  | gap | not_run |
| R-PASTE.9/103 | Verify it for a row name | robustness | Linux; Census session; `2`; `down` ×2 | `ctrl+c` | as /101 |  | gap | not_run |
| R-PASTE.10/101 | Verify the WARNING log line for a view copy whose write fails | robustness | Linux; Census session; the app's log captured | as R-PASTE.9/103 | ≥ 1 WARNING record of the system's logger; 0 records holding the copied text |  | gap | not_run |
| R-PASTE.13/101 | Verify that a held clipboard ends a view copy within 2.5 s | robustness | WinCI; held clipboard (8 s); Census session; `2`; `down` ×2 | `ctrl+c` | the write failure warning ≤ 2.5 s after the key (`timing_bound`: 5.0 s on CI); no copy notice |  | gap | not_run |
| R-PASTE.14/101 | Verify the screen stays responsive during a view-selection copy | normal | WinCI; held clipboard; a 50 ms interval timer of the screen; as R-COPY.1/1 | drag; `ctrl+c` | the timer fires late by ≤ 100 ms at every tick until the copy ends (`timing_bound`) |  | gap | not_run |
| R-PASTE.14/102 | Verify during a text-view copy | normal | as /101; `#hex_scroll` focused | `ctrl+c` | as /101 |  | gap | not_run |
| R-PASTE.14/103 | Verify during a row-name copy | normal | as /101; `2`; `down` ×2 | `ctrl+c` | as /101 |  | gap | not_run |
| R-TUI-043.13/101 | Verify that no copy outside a text box logs the copied text | normal | Linux and WinCI; Census session; the app's log captured at DEBUG | the copies of R-COPY.1/1, R-COPY.3/4, R-COPY.4/1 and R-PASTE.9/103 | no log record holds the copied text (nor its first 16 characters) |  | gap | not_run |

## Acceptance — the copy→paste matrix (AT-I1b-1 … AT-I1b-7)

Each case copies from one source through the keys, then pastes into each target by each route. Cells: `/1` = T1 by P1, `/2` = T1 by P2, `/3` = T2 by P1, `/4` = T2 by P2. Expected, for every cell: T1 holds the copied text's **first line**, exactly once (R-TUI-043.4 for P1, R-PASTE.1 for P2); T2 holds the copied text, every line, exactly once (R-TUI-044.3 for P1, R-TUI-044.4 for P2). Preconditions of every cell: WinCI; Seed; Census session; the copy notice of R-COPY.7 shown before the paste. On Linux (no OS clipboard, Inc 1a D-2) the P1 cells run through the app clipboard (R-TUI-043.6) and the P2 cells do not apply. Copying is the same for the four cells of a source; a test may copy once per cell. Class: normal. US-103-01.

| Case | Source (keys) | The copied text (the oracle) | Tests | Coverage | Result |
|---|---|---|---|---|---|
| AT-I1b-1/1 … /4 | Workspace: drag over 3 rows of the main hex view; `ctrl+c` | the selection's text |  | gap | not_run |
| AT-I1b-2/1 … /4 | Workspace: drag over the whole stats pane; `ctrl+c` | the selection's text (5 lines) |  | gap | not_run |
| AT-I1b-3/1 … /4 | Workspace: click the A2L summary pane (no drag); `ctrl+c` | the painted lines of `#a2l_view` |  | gap | not_run |
| AT-I1b-4/1 … /4 | `2`; `down` ×2; `ctrl+c` | `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` |  | gap | not_run |
| AT-I1b-5/1 … /4 | `3`; the record table focused; `down` ×2; `ctrl+c` | `Curve_ExternalAxis` |  | gap | not_run |
| AT-I1b-6/1 … /4 | `6`; JSON tab; click the JSON view; `shift+down` ×2; `ctrl+c` | the view's selected text (2 lines) |  | gap | not_run |
| AT-I1b-7/1 … /4 | Workspace; `?`; drag over the first two help lines; `ctrl+c`; `escape` | the selection's text |  | gap | not_run |

The read by another program is the separate read of R-COPY.1/1 … /6, R-COPY.3/1 … /5 and R-COPY.4/1 … /3 (WinCI). The P2 cells into T2 depend on Inc 1a's fix of the doubled terminal paste into a `CappedTextArea` (`../inc-1a/evidence-e1/i1a-pilot-transcript.txt` P6: `'L1\nL2L1\nL2'`); they are RED until it lands, for that reason.

Counts: 49 requirement cases (40 for R-COPY.1 … .11; 9 for the cited R-PASTE.9, .10, .13, .14 and R-TUI-043.13) and 28 acceptance cells (7 acceptance cases).
