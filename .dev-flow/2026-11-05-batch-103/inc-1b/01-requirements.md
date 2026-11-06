# Inc 1b — Clipboard: copy from every view: requirements (E1)

Batch 2026-11-05-batch-103, increment 1b. Base: branch `batch-103` = `main` `e07fb00` + batch-103 records (product tree `e07fb00`; `git diff --stat e07fb00 HEAD -- s19_app tests` is empty). Stage E1 of the design-first flow (`dev-flow-v3-beta`). **Amendment A1:** E1 only now; E2–E4 wait for batch-101 Inc 10a (hex views in `app.py`) and Inc 12 (`screens_directionb.py`) to merge. The rows state observable behaviour only; every line number in the slice is "as of `e07fb00`, re-check after b101 Inc 10a/12 merge".

Scope, decisions and reasons: `E1-rulings.md` (decisions D-1 … D-10 are **PROPOSED — awaiting orchestrator ruling**; the rows follow the E1 recommendation of each and name the decision they hang on). Slice: `E1-slice.md`. Test cases: `02-test-cases.md`. Shared interface I-1 (PLAN.md): the OS clipboard write of Inc 1a — the write a copy outside a text box goes through, capped at 65,536 characters, run off the screen's thread, telling the caller whether it wrote (`E1-rulings.md` §7). **Inc 1a's ids are cited from its E1 draft** (`../inc-1a/01-requirements.md`, read at the end of this E1, never edited): R-PASTE.1, .9, .10, .13, .14 and its CTX-PASTE terms; re-check them at Inc 1b's E2.

Form column: the canon's forms (U = ubiquitous, When = event, If = unwanted). Status: **new** = a new canon row (id checked unused, `E1-rulings.md` §5). "Base" = what `e07fb00` does today and how it is known: **C** = the E1 census, the app driven headless on the LAN Linux host with every clipboard writer replaced by a recorder (`evidence-e1/i1b-e1-census-transcript.txt`, script `evidence-e1/i1b-e1-census.py`; Python 3.11.18, textual 8.2.8, no display, isolated HOME / XDG / LOCALAPPDATA; nothing touched a clipboard); **R** = read in the code (the product at `e07fb00`; textual 8.2.8 under `~/miniconda3/envs/s19ci/lib/python3.11/site-packages/textual/` on that host); **P-1** = needs the Windows Terminal pilot of `E1-rulings.md` §4 before E4 trusts the key (script `evidence-e1/p1-wt-ctrl-c-probe.py`, not run at E1). **WinCI** = Inc 1a's *isolated clipboard* on the GitHub-hosted `windows-latest` job, read back by a separate system PowerShell `Get-Clipboard -Raw` process.

## User story

### US-103-01 — copy and paste work in every window (the copy-out half)
Commission (PLAN.md): "Text copied from any part of the TUI can be pasted into any text field of the TUI and into other Windows programs, and a paste lands at once." Operator note of 2026-11-05: "escenarios de copiar texto desde varias partes de la TUI y pegado a las ventanas de texto disponibles en la TUI". Inc 1b's part: as the operator, I want Ctrl+C to copy what I see in a view — the text I selected, the whole hex or JSON view I am in, or the tag I highlighted in a table — into the Windows clipboard, so that I can paste it into a text box of any window and into other programs. Inc 1a owns the text boxes' own copy, cut and paste.

## Definitions (new context note CTX-COPY, S7, beside CTX-PASTE; terms and formats only)

Inc 1a's CTX-PASTE terms are used as it defines them: *OS clipboard* (the Windows clipboard; Inc 1a D-2), *app clipboard*, *text box*, *selection* (in a text box), *write failure warning*, *OSC 52 clipboard request*, *responsive*.

```text
copy key        Ctrl+C.
view            Any part of a window or dialog outside a text box that shows text: a pane,
                a line, a label, a card, a list, a table.
view selection  Text the operator marks in a view: by a mouse drag, or in the JSON view also
                by Shift+arrows or F7.
text view       A view that takes the focus and shows lines of text:
                  main hex view, A2L hex, MAC hex (S4 CTX-HEX; the focus is on the pane that
                    holds the rows)
                  A2L summary (Workspace, right pane, below Coverage Stats)
                  JSON view (Patch Editor, JSON tab, the read-only view, S10 CTX-PE-JSON)
table           The A2L tag table (S2 CTX-A2L-SCREEN) and the MAC table (S2 CTX-MAC).   [D-4]
highlighted row As CTX-A2L-SCREEN: the row under the table cursor.
shown           As CTX-SHELL's "shown widget" (b101 Inc 12 / 12b; whichever merges first
                folds it): displayed, with every widget that holds it, up to its window.
shown text      The text a view paints, as the operator reads it: every painted line in order,
                its marker column, notice lines and blank cells included, the lines joined
                by a line feed, no line feed after the last line.
row name        The text of the highlighted row's Tag column after its leading glyph and the
                space that follows it: the tag name (A2L tag table), the record name (MAC table).
copied text     The text a copy outside a text box takes: a view selection, a text view's
                shown text or a row name.
both clipboards The OS clipboard and the app clipboard.
copy limit      65,536 characters (the paste limit of CTX-PASTE).
copy notice     "Copied 1 line to the clipboard." when the copied text has one line, else
                "Copied <n> lines to the clipboard.", <n> its number of lines; an
                information notice.
cut notice      "Copied the first 65,536 characters to the clipboard (<N> in all).", <N> the
                copied text's length in characters, written with a comma every three digits;
                an information notice.
nothing notice  "Nothing copied — select text with the mouse first."; an information notice.
terminal copy   A copy the terminal makes from its own selection (Shift+drag in Windows
                Terminal); it never reaches the app.
```

## Requirements

### S7 — copy out of a view (US-103-01)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-COPY.1 | When | When the operator presses the copy key while a view selection exists, the system shall write the selected text to the OS clipboard. | WinCI, per case the separate read equals the selected text: a drag over 3 rows of the main hex view; the whole stats pane (5 lines); the A2L tag summary line; the detail card; 2 lines of the JSON view selected with Shift+Down; a drag in the Workspace help window (a dialog); 6/6 | the copy writes only the app clipboard and OSC 52 (the base) → the separate read returns the seed → RED | US-103-01 | new (D-1, D-3) | **No** (C §3: a full selection in 9 views → the app clipboard and one OSC 52 request each, 0 OS writes; the JSON view is a stock `TextArea` and behaves the same; C §5: a mouse drag selects hex text, and Ctrl+C sends it to OSC 52 only). Key: P-1 (R: textual's Windows driver sets the input mode to `ENABLE_VIRTUAL_TERMINAL_INPUT` alone, `drivers/win32.py:158-180`, so Ctrl+C arrives as a key whenever the terminal passes it on) |
| R-COPY.2 | When | When the system copies text outside a text box, the system shall put the copied text in the app clipboard. | `app.clipboard` = the copied text after a view-selection copy, a text-view copy, a row-name copy and a copy whose OS write fails, on Linux and WinCI; 4/4 | the app clipboard skipped on the new paths (only the OS write) → `app.clipboard` keeps the seed → RED | US-103-01 | new | **Partly** (C §3: yes for view selections; C §4: nothing is copied without one) |
| R-COPY.3 | When | When the operator presses the copy key while a shown text view has the focus and no view selection exists, the system shall write the view's shown text to the OS clipboard. | WinCI, the separate read equals the view's painted lines: main hex view of the census fixture (201 lines on `e07fb00`: the notice line `... window limited to 200 rows ...` and 200 rows; re-measured after b101 Inc 10a merges), A2L hex, MAC hex, A2L summary (4 lines, the first `A2L summary lines 1-2 / 2`), JSON view (the shown JSON); 5/5 | the fallback writes only the first line → RED; the fallback not wired (the base: the quit hint) → RED | US-103-01 | new (D-2, D-7) | **No** (C §4: on each of the 5 focus owners `#hex_scroll`, `#alt_hex_scroll`, `#mac_hex_scroll`, `#a2l_scroll`, `#patch_json_view` → nothing copied, the toolkit's quit hint) |
| R-COPY.4 | When | When the operator presses the copy key while a shown table has the focus, a row is highlighted and no view selection exists, the system shall write the highlighted row's row name to the OS clipboard. | WinCI, separate read: A2L tag table (`ASAP2_Demo_V171.a2l`), the third row highlighted → `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` (no glyph, no tab, one line); MAC table (`synthetic_update_test1.mac`), the third row → `Curve_ExternalAxis`; `2` pressed on the Workspace, then the copy key with no other key (the focus target, S6 R-SHELL-FOCUS.2) → the first row's name; 3/3 | the row's cells copied tab-separated → RED; the glyph kept (`· ASAM…`) → RED | US-103-01 | new (D-4) | **No** (C §1: both tables are `DataTable`s, `allow_select` False; C §4: nothing copied, the quit hint; C §5b: the third rows' Tag cells read `· ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` and `⚠ Curve_ExternalAxis`) |
| R-COPY.5 | If | If the operator presses the copy key while no view selection exists and the focus is neither on a shown text view nor on a shown table with a highlighted row, then the system shall show the nothing notice. | `Nothing copied — select text with the mouse first.` shown once, information, and no `Do you want to quit?` notice: with the focus on a button (`#search_button`), with no widget focused, on an empty A2L tag table (no A2L loaded), and with the focus put on the A2L tag table while the Workspace is shown (the hidden-focus shape of the base, b101 Inc 10a); 4/4 | the toolkit's quit hint kept (the base) → `Press ctrl+q to quit the app` → RED; "shown" dropped from the condition → the hidden table's row name is copied → RED | US-103-01 | new (D-6) | **No** (C §4: `Press [b]ctrl+q[/b] to quit the app`, title `Do you want to quit?`) |
| R-COPY.6 | If | If the operator presses the copy key while no view selection exists and the focus is neither on a shown text view nor on a shown table with a highlighted row, then the system shall leave both clipboards unchanged. | the four cases of R-COPY.5: `app.clipboard` still holds the seed (Linux and WinCI), and on WinCI the separate read too; 4/4 | an empty string copied (the toolkit's selection copy with an empty selection, C caveat `E1-rulings.md` §9) → RED | US-103-01 | new | **Yes** (C §4: nothing copied) |
| R-COPY.7 | When | When the system has written the whole copied text to the OS clipboard after a copy outside a text box, the system shall show the copy notice. | WinCI, exactly one notice per copy, information: a row name → `Copied 1 line to the clipboard.`; the stats pane selected → `Copied 5 lines to the clipboard.`; the main hex view of the census fixture → `Copied 201 lines to the clipboard.` (on `e07fb00`); and no copy notice when the write fails (Linux, and the held clipboard on WinCI); 4/4 | `lines` for one line (`Copied 1 lines …`) → RED; the notice shown before the write's result → the failing case shows it → RED | US-103-01 | new (D-5) | **No** (C §3: no notice after a copy) |
| R-COPY.8 | If | If the copied text is longer than the copy limit, then the system shall copy its first 65,536 characters in its place. | a document whose shown JSON is longer than 65,536 characters: the JSON view copied whole, and selected whole with F7 then copied → `app.clipboard` and the decoded OSC 52 request (Linux and WinCI) and the separate read (WinCI) are each 65,536 characters long and equal the text's first 65,536; 2/2 | the cap removed → every character kept → RED; the cap applied to the OS write only (the toolkit's copy left uncapped) → `app.clipboard` holds every character → RED | US-103-01 | new (as Inc 1a's R-PASTE.12 for a text-box selection) | **No** for the app clipboard and OSC 52 (R: the toolkit's copy keeps every character, textual `app.py:1770-1786`); the OS write path caps every payload (R: `write_os_clipboard`, `os_clipboard_input.py:708`) |
| R-COPY.9 | If | If the system has written only the first 65,536 characters of the copied text, then the system shall show the cut notice. | the two cases of R-COPY.8: `Copied the first 65,536 characters to the clipboard (<N> in all).` with `<N>` the text's length (for example `75,210`), once, and no copy notice; 2/2 | the copy notice shown instead (`Copied 5,001 lines …`) → RED | US-103-01 | new (D-5) | **No** (no notice today) |
| R-COPY.10 | When | When the system copies text outside a text box, the system shall send the copied text to the terminal as an OSC 52 clipboard request. | exactly 1 request per copy, decoding to the copied text: a view selection, a text view, a row name; 3/3 (Linux and WinCI) | the toolkit's copy bypassed by the new seam (OS write and app clipboard only) → 0 requests → RED | US-103-01 | new (D-1 A keeps it) | **Partly** (C §3: one request per view-selection copy; C §4: none without one) |
| R-COPY.11 | When | When the operator selects text in a view or moves a table's highlighted row, the system shall leave the OS clipboard unchanged. | WinCI, the seed in the OS clipboard; a drag over the main hex view; `down` ×3 in the A2L tag table; F7 in the JSON view: the separate read returns the seed after each; 3/3 | a copy on selection (as X's primary selection) or on a highlight move → RED | US-103-01 | new | **Yes** (R: the toolkit copies only on its Ctrl+C binding, `screen.py:272`, `:985-990`; C §5: the drag copied nothing before Ctrl+C) |

Cited rows, unchanged, with cases in `02-test-cases.md` (numbered from 101, so they cannot collide with Inc 1a's cases of the same rows):
- Inc 1a's general rows on the OS write, which a copy outside a text box meets through I-1: **R-PASTE.9** (the write failure warning; cases /101 … /103: a view selection, a text view, a row name), **R-PASTE.10** (a WARNING line when the write fails; /101), **R-PASTE.13** (another program holds the clipboard: the copy ends within 2.5 s; /101, WinCI), **R-PASTE.14** (the screen stays responsive while the system writes; /101 … /103, WinCI).
- R-TUI-043.13 (S7.3: no clipboard text in the log) — a copy outside a text box writes no log record that holds the copied text (/101).
- The targets of the copy→paste matrix: **R-TUI-043.4** (Ctrl+V into a single-line box: the first line), **R-PASTE.1** (a terminal paste into a single-line box: the first line), **R-TUI-044.3**, **R-TUI-044.4** (Ctrl+V and the terminal paste into a multi-line box: every line).
- R-SHELL-FOCUS.2 (S6: the A2L Explorer's focus target is the tag table) — the precondition of R-COPY.4/3.

### Acceptance — the copy→paste matrix (US-103-01)

The acceptance cases `AT-I1b-1` … `AT-I1b-7` of `02-test-cases.md` drive the app through its keys: one case per copy source of this increment (the main hex view selection, the stats pane selection, the A2L summary whole, the A2L tag table row name, the MAC table row name, the JSON view selection, a help window selection), each pasted into both field classes (the single-line box `#a2l_tags_filter_input`, an `OsClipboardInput`; the multi-line box `#patch_paste_text`, a `CappedTextArea`) by both paste routes (Ctrl+V reaching the app; a terminal paste, `events.Paste`, carrying the text a separate process read from the OS clipboard), plus the read by another program (the separate reads of R-COPY.1, .3, .4). The cells run on WinCI; on Linux (no OS clipboard, Inc 1a D-2) the Ctrl+V cells run through the app clipboard (R-TUI-043.6) and the terminal-paste cells do not apply. Every case asserts its isolation before it writes; none touches the operator's clipboard.

## Counts

11 rows, all new (R-COPY.1 … R-COPY.11); 0 changed; 0 retired. Cited rows with cases here: R-PASTE.9 (3 cases), R-PASTE.10 (1), R-PASTE.13 (1), R-PASTE.14 (3), R-TUI-043.13 (1); cited by the acceptance cases: R-TUI-043.4, R-PASTE.1, R-TUI-044.3, R-TUI-044.4, R-SHELL-FOCUS.2. Context-note changes: CTX-COPY (new, S7); CTX-KEYS one sentence (D-3, `E1-rulings.md` §2). Acceptance cases: 7 (28 cells). Estimate in PLAN.md: ~15 rows / ~8 nodes; this E1: 11 rows, 5 new functions and 0 changed (`E1-slice.md`); no split needed.
