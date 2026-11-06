# Code changes from the requirements review (backlog for s19 batches)

The review corrects the **requirement text** only (files `S<n>-ears-strict.md`). Nothing below is changed in the code yet. Each item enters s19 through a `/dev-flow` batch, after batch-100. Each line: id · what changes · rows it makes true.

Status column: `open` until a batch takes it.

Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: statuses `done (batch-100 Inc <n>, <commit>)`, `partly done: …`, `obsolete: …` and `open (re-verified at 570b4b5)` record that pass; an item whose code did not change keeps `open` or `needs prototype`. New items D5-49, D5-51, D5-52, D6-46, D7-29, D7-32, D7-33, D7-35, D11-70 … D11-72, D15-18.

Totals (counted by script, one per id; a row with several ids counts each): 317 items in 309 rows: open 255 (44 of them re-verified at 570b4b5), needs prototype 31, partly done 9, done 13, obsolete 9.

## S0 — Project, documentation & process meta

| Id | Change | Rows | Status |
|---|---|---|---|
| D0-8 | When the new `REQUIREMENTS.md` replaces the old one, update the registry guard's exempt headings (`AT-TC-REGISTRY.jsonl` `g4_exempt_anchors`) and its scan count in `tests/test_id_registry.py` in the same change; register batch-100's AT-B100 and TC-B100 ids too (S0 D0-13) | — | done differently (batch-101 Inc 1): G4 and `g4_exempt_anchors` retired instead of updated (ruling R-3); scan count measured (R-7). AT-B100/TC-B100 ids are batch-scoped, outside the registry's authority (registry spec §2.3), so none is registered |
| D0-9 | README: describe the Check Editor, Flow Execution and Split / Join / Export; drop "ten single-context screens" | R-DOC-README.2 | open |
| D0-10 | README key table: add `=`, `]`, Ctrl+Q, `d`, `c` | R-DOC-README.3 | open |
| D0-11 | README: Operations runs `crc` only (with S13 D13-13); flows are `<project>/flows/<name>.json`, not `flow.json` | R-DOC-README.4 | open |
| D0-12 | Write the snapshot fixture rule (public synthetic fixtures only) into `docs/engineering-rules.md` | — | open |

## S1 — reading & parsing

| Id | Change | Rows | Status |
|---|---|---|---|
| D-3 | S19 reader: decode as UTF-8; an undecodable line is rejected and the load continues | R-READ-003, R-VAL-002.4 | open |
| D-4 | Intel HEX type 02: wrap at 64 KiB; the sample file becomes the test | R-HEX-002 | open |
| D-5 | Out-of-order findings carry the physical line number | R-IMG-003 | open |
| D-6 | Safe text: a run of tab / line breaks shows as one space | R-TUI-103.1 | open |
| D-7 | Sweep the screens not yet on the safe-text list (with S4) | R-TUI-103 | open |
| D-7+ | Apply the safe-text function to the views added from S6–S14 (CTX-TEXT list) | R-TUI-103, 103.1, 103a, 103b | open |
| D-8 | Remove the two checks that can never fire | — | open |
| D-11 | Remove the command-line tool (cli.py, its tests, README section) | — | open |
| D-14 | Version in one place (pyproject reads version.py) | R-VER-001 | open |
| D-15 | Remove three unused helpers | — | open |
| Q-C | HEX reader: per-field messages; length check before field checks | R-HEX-005.x, R-HEX-006 | open |
| Q-D | HEX reader: reject an unknown record type | R-HEX-008 | open |
| Q-E | HEX reader: report overlap addresses | R-IMG-002.x | open |

## S2 — A2L & MAC

| Id | Change | Rows | Status |
|---|---|---|---|
| D2-1 | Remove `get_raw_value` / `get_physical_value` / `validate_characteristic` and tests | — | open |
| D2-2 | Remove the dead "existing tag endian" step | R-A2L-024 … 027 | open |
| D2-3 | Raise `A2L_UNKNOWN_BYTE_ORDER` | R-A2L-028, R-VAL-037 | open |
| D2-5 | TAB_VERB shows the COMPU_VTAB text | R-A2L-059 | open |
| D2-6 | One unit rule (UNIT/PHYS_UNIT whole text, then conversion unit); conversion line on /begin | R-A2L-030 … 033 | open |
| D2-7 | CURVE/MAP length = whole record | R-A2L-018 | open |
| D2-8 | Datatype from the deposit name, not guessed by size | R-A2L-023 | open |
| D2-9 | Decode FLOAT16 | R-A2L-045 | open |
| D2-10 | Multi-value tags: one value per element; table shows `<n> values` | R-A2L-047, R-A2L-006.9 | open |
| D2-11 | Strip comments before sections; mismatched /end is a parse error | R-A2L-001.2, 001.5 | open |
| D2-12 | A2L summary shows errors, then sections and tags | R-A2L-076, 077 | open |
| D2-13 | `A2L loaded with <n> parse errors` | R-A2L-004.2 | open (re-verified at 570b4b5) |
| D2-14 | `Invalid` filter = red rows | R-A2L-007.7 | open |
| D2-15 | Filter / find compare the address as shown | R-A2L-007.5, R-A2L-099 | open |
| D2-16 | A2L glyphs ✓ / ⚠ / · | R-A2L-006.2 | open |
| D2-17 | One-sided limit shows `..100` | R-A2L-006.10 | open |
| D2-18 | Find brings the address near the top | R-A2L-094 | open |
| D2-19 | Active filter-mode button; `No tag matches the filter.` | R-A2L-007.9, R-TUI-068.4 | open |
| D2-20 | MAC-only session: no tag checked | R-A2L-071 | open (re-verified at 570b4b5) |
| D2-21 | MAC status order: errors first | R-MAC-030 | open |
| D2-22 | MAC summary: one count per status | R-MAC-050 | open |
| D2-23 | `MAC file has no records.` | R-MAC-053 | open |
| D2-24 | Coverage strip with no image: `MAC→S19 no image` | R-TUI-071.4 | open |
| D2-25 | JSON export: catch the write error | R-A2L-003.5 | open |
| D2-26 | Remove `overlap_conflict` | — | open |
| D2-29 | Remove the invisible per-cell accents | — | open |

## S3 — validation, issues & legend

| Id | Change | Rows | Status |
|---|---|---|---|
| D3-4 | Remove unreachable codes and the xfail `CROSS_S19_HEX_OVERLAP` test | — | open |
| D3-5 | Remove `alias_policy`; bit-field sharing is INFO | R-VAL-022 … 024 | open |
| D3-7 | Remove the dead jump-to-source code and `_format_validation_issue_line` | — | open |
| D3-8 | Remove the unused issue page-size setting and capped branch | — | open |
| D3-9 | "Only in A2L / MAC" warnings only when the other file is loaded | R-VAL-045, 046 | open |
| D3-10 | A2L structure checks in every session with an A2L | R-VAL-030 … 033 | open |
| D3-11 | Run the A2L structure rules once | — | open |
| D3-12 | Standard block names recognised; remove the display triage | R-VAL-032 | open |
| D3-13 | Broken references: check child REF/DEF/IN/OUT blocks | R-VAL-033 | open |
| D3-14 | Line diagnostics and MAC read failure become issues; integrity notices deduped | R-VAL-013, 017, 018 | open |
| D3-15 | Overlap issues from the loaded image, both formats, whole tag span | R-VAL-041, 043 | open |
| D3-16 | Tag with no length: not checked, no issue | R-VAL-042, 053 | open |
| D3-17 | Names as written; triple issue carries the A2L address | R-VAL-047, 048 | open |
| D3-18 | One palette on every surface; MAC warnings pale yellow | R-LEGEND-010, R-MAC-032 | open |
| D3-19 | Legend rows rewritten from the screens' rules | R-LEGEND-011 | open |
| D3-20 | Hex legend rows in colour; Workspace shows the Hex block | R-LEGEND-MODAL-001.7, .9 | open |
| D3-21 | Issues card text matches the real rows | R-LEGEND-MODAL-001.10 | open |
| D3-22 | Active filter button; `No issue matches the filter.` | R-TUI-025.7, .15 | open |
| D3-23 | Up/Down move between issue rows | R-TUI-025.16, .17 | open |
| D3-24 | Clear the hex peek on load | R-ISSUES-HEXPANE-001.3 | open |
| D3-25 | One definition of the overlay styles; fix the stale colour test | — | open |
| D3-26 | Map patch teal, paste-gauge magenta, JSON hues and check-outcome colours onto the one palette; legend blocks for them | R-LEGEND-010, R-LEGEND-011 | needs prototype |

## S4 — hex view & Memory Map

| Id | Change | Rows | Status |
|---|---|---|---|
| D4-1 | Enter runs search and go-to | R-TUI-017.1, R-TUI-040.2 | open |
| D4-2 | Every jump: target row second from the top, scrolled to the left edge | R-TUI-018.1, .2, R-TUI-040.4 | open |
| D4-3 | Snap to the next present row in every hex view | R-TUI-018.3 | open |
| D4-4 | One search state per hex view | R-TUI-017.5 | open |
| D4-6 | A failed go-to and every jump clear the `> ` marker | R-TUI-040.11, .12 | open |
| D4-7 | Go-to reads hexadecimal, prefix optional | R-TUI-040.3 | open |
| D4-8 | `,` / `.` page only on the Workspace | R-TUI-007.7 | open |
| D4-10 | Count MAC-added rows in paging | R-TUI-007.8 | open |
| D4-11 | Remove the dead 64 KiB limit; notice `... showing from <address> ...` | R-TUI-007.11 | open |
| D4-12 | Remove `_jump_to_tag`, `_jump_to_mac_record`, `PreparedLoad.mac_highlights` | — | open |
| D4-13 | Capture the MAC/A2L hex panes; if rows wrap, scroll sideways | R-HEX-LAYOUT.1 | open |
| D4-14 | First hex page on load | R-TUI-007.9 | open |
| D4-15 | One hex renderer; peeks mark the entry's row | R-TUI-004.1, .4, R-HEX-MARK.3 | open |
| D4-16 | `Section at <address>` status | R-TUI-009.2 | open |
| D4-21 | Map: Enter opens hex, arrows select and inspect, key line names real keys | R-TUI-062.3, .4, .10, .11 | open |
| D4-22 | Region symbol count = inspector list (extent overlap, named tags) | R-TUI-073.3 | open |
| D4-26 | Map header `No S19/HEX image loaded.` | R-TUI-060.4 | open |
| D4-28 | Remove "largest gap" | — | open |
| D4-31 | Remove the dead map code and CSS | — | open |
| D4-33 | Map header size human-readable | R-TUI-060.1 | open |
| D4-35 | No memory-strip cell beyond the span | R-TUI-067.6 | open |
| D4-23, 24, 25, 27 | Prototype round first (row widths and bar overflow, micro-bar glyph and threshold, ruler placement) | R-TUI-073.2, .4, R-TUI-103B.5, R-TUI-072.3 | needs prototype |

## S5 — workspace & file I/O

| Id | Change | Rows | Status |
| D5-49 | Remove `load_selected_file` (`app.py:17335`): no product caller since Inc 12b; tests use it as a synchronous loader | — | open |
| D5-51 | Vanished work-area pick: show `File NOT loaded: '<name>' not found — pick another file.` with no question; re-pin `test_tc_b100_39_pick_of_a_vanished_entry_asks_nothing` | R-WS-FILES.4, R-WS-FILES.11 | open |
| D5-52 | Load question: confirm the accent on `Cancel (n)` instead of `Replace (y)` (`screens.py:1501`), as ruling OBS-12b-2 did for the quit question | R-LOADQ-006.4 | needs prototype |
|---|---|---|---|
| D5-8 | Remove the repository-root fallback for relative paths | R-TUI-005.5 | open |
| D5-9 | Remove `walk_tree_no_links`, `_has_a2l`, `ScreenScaffold`, the bare `Loaded <name>` branch | — | open (re-verified at 570b4b5): `walk_tree_no_links` is now used by save as (Inc 8b, 3a4a309) and leaves the item; `_has_a2l`, `ScreenScaffold` and the bare `Loaded <name>` branch remain |
| D5-54 | The refusal reason of a placement outside the work area names the real work-area path instead of the literal `<base>/.s19tool/workarea/`; add a test that asserts the text | R-TUI-002.5 | open |
| D5-10 | Workarea Files labels as plain text | R-WS-FILES.5 | done (batch-100 Inc 9a, f1b8960) |
| D5-12 | Folder creation failure: error naming the folder, non-zero exit | R-TUI-001.5 | open |
| D5-13 | `o` checks the work area like the folder chips | R-TUI-008.4 | open |
| D5-14 | `Not a file: <path>` for a folder | R-TUI-005.7 | obsolete: the Load dialog refuses a typed folder inside the dialog (batch-100 Inc 9a f1b8960, Inc 9b 12d0f81; S5 D5-42) |
| D5-15 | Catch A2L parse errors: `Cannot load A2L: <reason>` | R-TUI-012L.10 | done (batch-100 Inc 12b, 1571f4c) with the batch text `File NOT loaded: '<name>' could not be read — check that the file can be opened, then load again.` (S5 D5-41) |
| D5-16 | Reproduce overlapping loads; newer load wins | R-TUI-012L.7 | obsolete: batch-100 Inc 12b (1571f4c) refuses any load while a session action runs (HLR-177a; S5 D5-40) |
| D5-17 | Unload messages on the status line | R-WS-LOADED.13 | open (re-verified at 570b4b5) |
| D5-18 | Slots independent: primary unload keeps the A2L; A2L slot shown without a primary | R-WS-LOADED.3, .7 | done (batch-100 Inc 8b, 3a4a309) |
| D5-19 | Primary unload drops its diagnostics, notices and path | R-WS-LOADED.16 | open (re-verified at 570b4b5) |
| D5-20 | Stats counts after the issue list is rebuilt (also on A2L load) | R-TUI-066.10 | open |
| D5-21 | Load status describes the file just loaded | R-TUI-012L.8 | open (re-verified at 570b4b5) |
| D5-22 | Primary slot labelled `HEX` for Intel HEX | R-WS-LOADED.2 | open (re-verified at 570b4b5) |
| D5-27 | Unload-all with nothing loaded: `Nothing to unload.` | R-WS-LOADED.14 | open (re-verified at 570b4b5) |
| D5-28 | Vanished file pick: `File not found: <name>` | R-WS-FILES.4 | obsolete: carried by D5-51 (same vanished pick, batch-100 text; re-verified open at 570b4b5) |
| D5-32 | Remove control characters from file names in the status line, log lines, A2L summary | R-WS-LOADED.15 | partly done: the status line and the message lines drop control characters since Inc 12a (4cedb23); the log file lines and the A2L summary were not re-checked |
| D5-33 | Files list shows loadable kinds only | R-WS-FILES.1 | done (batch-100 Inc 9b, 12d0f81) |
| D5-37 | Files list also shows loadable files written with no project open (work-area root, `splits/`, `crc/`) | R-WS-FILES.6 | obsolete: batch-100 keeps the Workarea Files list to `temp/` on purpose (LLR-172.4a, HLR-162; S5 D5-43) |
| D5-23, 24, 25 | Prototype round first (validity glyph, band glyph colour, narrow loaded panel) | R-TUI-066.3 | needs prototype |
| D5-26 | Prototype round first (left pane in empty state) | R-TUI-029.5 | obsolete: the Load dialog (Inc 9b, 12d0f81, P-A verdict) lists projects and work-area files with no file loaded (S5 D5-44) |

## S6 — TUI shell, navigation & layout

| Id | Change | Rows | Status |
| D6-46 | Typed file load: paint step 1 `Copy into the work area` before the copy on the screen's thread (`load_from_path`, `app.py:15117-15124`), with the `call_after_refresh` idiom of the A2L tag-table build and the project install; read from the code, reproduce first | R-PROGRESS-LINE.5 | open |
|---|---|---|---|
| D6-11 | Remove the rail's ASCII glyph fallback (`ascii_mode`) and its test | — | open |
| D6-12 | Remove `action_view_main`, `action_view_mac`; reuse or remove `_toggle_settings_menu` | — | open |
| D6-13 | Switch off Textual's own palette (Ctrl+P: Theme, Keys, Quit, Screenshot); drop `^p palette` from key-bar row 1 | R-TUI-022.11, R-TUI-024.3, R-KEYBAR.2 | open |
| D6-20 | Hex+ key bound as `period`, which a keyboard never sends (`full_stop`); rebind, test by character; reproduce first | R-SHELL-KEYS.1 | open (re-verified at 570b4b5) |
| D6-21 | A window switch by key moves the focus to the new window's focus target | R-SHELL-FOCUS.2 | open |
| D6-22 | Enter on the focused rail item shows its window | R-TUI-021.5 | open |
| D6-23 | Escape closes the palette | R-TUI-022.9 | open |
| D6-24 | Palette lists only commands that can act on the shown window (the key bar's check) | R-TUI-022.10 | open (re-verified at 570b4b5) |
| D6-25 | Distinct palette labels for `+`/PgDn and `-`/PgUp | R-TUI-022.3 | open (re-verified at 570b4b5) |
| D6-26 | Viewer settings menu closes on Escape and on a second `Viewer settings` | R-SHELL-SETTINGS.5 | open |
| D6-27 | Viewer settings status uses the menu name (`Updated Hex rows to 50.`) | R-SHELL-SETTINGS.4 | open |
| D6-28 | Remove control characters from the message lines (S1 safe-text list) | R-SHELL-STATUS.5 | done (batch-100 Inc 12a, 4cedb23) |
| D6-30, 31 | Prototype round first (rail item keys; what compact density means per window, or drop Ctrl+D) | R-TUI-021.7, R-TUI-023.7 | needs prototype |

## S7 — Modal dialogs, input widgets & window help

| Id | Change | Rows | Status |
| D7-29 | Shorten the Load dialog's path box hint so it shows whole at 118 columns (today cut after `or a`; batch-100 OBS-9b-1) | R-LOADDLG.6 | open |
| D7-32 | A printable key typed on the Load dialog's list goes through the edit that applies the 4,096-character limit and the control-character rule (today set directly, `screens.py:492-494`; batch-100 SEC9b-1) | R-LOADDLG.19 | open |
| D7-33 | Ignore every load request after Escape in the Load dialog (an Alt+L queued behind Escape loads; batch-100 risk A9b-R2-5); reproduce first | R-LOADDLG.59 | open |
| D7-35 | Show the open project's last load result (load reason and problem rows) in the Load dialog's preview of its row (batch-100 LLR-178.3, last sentence; the summary line's `details: p` points there; stored at `app.py:13708`, read by nothing) | R-LOADDLG.83 | open |
|---|---|---|---|
| D7-10 | Remove `VariantHelpScreen`, its text and its test (opener gone since batch 94) | — | open (re-verified at 570b4b5) |
| D7-11 | Show the `Changes file notation` steps in the Patch Editor's help window | R-WHELP.15 | open |
| D7-20 | Escape does what Cancel / Close does on every dialog (11 of 16 lack it) | R-DLG.2 | partly done: Escape added on the Load dialog (Inc 9b, 12d0f81), Save project (Inc 11, 53d08d5), the load question (Inc 10, 4eef8a3), the quit question (Inc 12b, dabcd41) and the Load-result panel (Inc 6, 948e65c); still missing on Select variant, Save flow, Load flow, Discard unsaved flow edits?, Edit entry JSON, the CRC write confirmation, Operations and Reports (8 of 18 dialogs) |
| D7-21 | Enter in a confirm box, or on a dialog list item, presses the confirm button | R-DLG.3, R-DLG.4 | partly done: the Load dialog (Inc 9b, 12d0f81) and Save project (Inc 11, 53d08d5) handle Enter; Enter in the Save flow name box, and on a Select variant or Load flow list item, still does nothing |
| D7-22 | Confirmation dialogs open on Cancel (`Discard unsaved flow edits?`, CRC write confirmation) | R-DLG.6 | open (re-verified at 570b4b5) |
| D7-23 | Ctrl+K / Ctrl+D / Ctrl+L / Ctrl+S do not act behind an open dialog; reproduce first | R-DLG.1 | partly done: inert while the Load dialog, Save project or a question is on the screen stack (Inc 9b 12d0f81, Inc 10 4eef8a3, Inc 11 53d08d5); still act behind the other 14 dialogs (reproduce first) |
| D7-24 | Ctrl+V in multi-line boxes reads the OS clipboard (all lines, within the limit) | R-TUI-044.3 | open |
| D7-25 | Paste limit on the app-clipboard fallback and on terminal paste into single-line boxes | R-TUI-044.2 | open (re-verified at 570b4b5) |
| D7-26 | Help copy: A2L section (no "section tree", `/` searches the image), no `folders.html` / "change 1/2", no Markdown marks | R-WHELP.12, .13, .14 | open |
| D7-27 | Help sections for MAC View, Issues Report, A2B Diff | R-WHELP.1 | open |
| D7-28 | Load project, Select variant and Reports lists show names as plain text (S1 safe-text list) | R-DLG.13 | partly done: the Load project list is retired and the Load dialog paints names literally (Inc 9b, 12d0f81); the Select variant title and list and the Reports list still read markup |
| D7-30 | Prototype round first (title row and `?` chip on MAC View, Issues Report, A2B Diff) | R-WHELP.3 | needs prototype |
| D7-31 | Prototype round first (a visible key on every dialog button) | R-DLG.11, R-DLG.12 | partly done: 5 dialogs settled by batch-100 prototype verdicts (Load dialog P-A, load question P-B, Save project P-C, quit question, Load-result panel P-E); the other 12 dialogs still need prototype |

## S8 — Change documents, apply & save-back

| Id | Change | Rows | Status |
|---|---|---|---|
| D8-16 | Remove `ChangeSummary.to_dict` and `CheckRunResult.to_dict` (no caller outside tests) and their tests | — | open |
| D8-17 | Remove the unreachable `<kind> save-back not supported` branch of the apply handler | — | open (re-verified at 570b4b5) |
| D8-20 | Reader: refuse a version other than `2.0` with `CHG-VERSION-UNKNOWN` | R-CHG-VER.1 | open |
| D8-21 | Reader: the address string must match whole (no trailing line feed) | R-CHG-001.29 | open |
| D8-22 | Patch Editor load and paste declare the loaded A2L for symbol entries | R-CHG-SYM.9 | open (re-verified at 570b4b5) |
| D8-23 | Load with a file or envelope defect: `Change file not loaded: <e> error(s)` | R-CHG-001.20 | open |
| D8-24 | MAC-only session: apply gives `skipped-no-image`, not `skipped-outside` | R-CHG-002.11 | open |
| D8-25 | Blocked apply names its reason (errors, or kind) | R-CHG-002.5, R-CHG-002.6 | open (re-verified at 570b4b5) |
| D8-26 | Save-back of an image with invalid ranges: write, and warn with count and first range | R-CHG-003.22 | open |
| D8-27 | Save-back keeps the source S0 at width 16 too (HLR-153) | R-S19-S0HEADER-001.1 | open (re-verified at 570b4b5) |
| D8-28 | Synthesized S0 header from the written file name, not the typed name | R-S19-S0HEADER-001.2 | open (re-verified at 570b4b5) |
| D8-29 | Save-back writes the source's terminator (start) address, not 0 | R-S19-EMIT.11 | open (re-verified at 570b4b5) |
| D8-30 | Save-back name check uses the shared device-name rule (`is_windows_device_name`) | R-CHG-003.13 | open |
| D8-31 | Verify: `mismatch` when the read-back gives any diagnostic or integrity notice | R-HEX-VERIFY-001.5 | open |
| D8-32 | Mismatch notice in plain words: missing in file / extra in file, with plurals | R-HEX-VERIFY-002.5 | open |
| D8-33 | Rename the finding code `CHG-HEX-SAVE-UNSUPPORTED` to `CHG-SAVE-UNSUPPORTED` | R-CHG-003.16 | open |
| D8-34 | Save suffix names only the entries the saved image holds | R-CHG-003.23 | open |
| D8-40 | Prototype round first (Width control on an Intel HEX save-back) | R-S19-SAVE-REUSE-001.1 | needs prototype |

## S9 — Checks

| Id | Change | Rows | Status |
|---|---|---|---|
| D9-7 | Remove `run_checks_for_project` and its test-only caller (the headless project-run test) | — | done (batch-101 Inc 4) |
| D9-8 | Remove the hidden `#check_preview_toggle_button` and its handler | — | open |
| D9-10 | One "current run" rule: the Checks tab (rows, status, strip, subtitle) and the Checks screen show the no-run state when the document or the image differs from the run's (the stamp the ledger glyphs already use); a 0-entry run shows `0 checked` | R-CHK-PE-008 … 012, R-CHKS-001, R-CHKS-004, R-CHKS-009 | open |
| D9-11 | Check Editor: a field loaded from a spec keeps the spec's expected bytes; only new fields take the image's bytes (Write and Validate) | R-CHKED-025, R-CHKED-026 | open |
| D9-12 | Check Editor: keep the included parameters the new A2L list still holds on screen entry and after Write | R-CHKED-010 | open |
| D9-13 | Check Editor JSON tab shows the document Write would write (S8 serialiser) | R-CHKED-019 | open |
| D9-14 | Check Editor Write: append `.chk.json` when the name lacks it | R-CHKED-030 | open |
| D9-15 | One check home for Write, the Spec dropdown and the chip (`<project>/checks/` with a project, else `workarea/patches/`); with S10 D10-25 | R-CHKED-031, R-CHKED-040 | open |
| D9-16 | Check Editor: refuse a non-numeric Size with `Check Editor: bad size '<text>'.` | R-CHKED-014 | open |
| D9-17 | Check Editor memory Address: `0x` + hex digits, or decimal digits only; with S10 D10-27 | R-CHKED-012 | open |
| D9-20 | One aggregate strip form for the Patch Editor Checks tab and the Checks screen | R-CHK-PE-005, R-CHKS-008 | needs prototype |

## S10 — Patch Editor

| Id | Change | Rows | Status |
|---|---|---|---|
| D10-13 | Defer: keep `add_symbol_entry`, `resolve_symbol_entry`, `list_a2l_symbol_names` and the encoder until the symbol-input round (D10-42) | — | open |
| D10-14 | Remove the never-displayed census widgets `#patch_checks_section_label`, `#patch_script_section_label`, `#patch_win_json_dock_spacer` and their census entries | — | open |
| D10-20 | Dropdown pick asks with the unsaved-changes popup while the dirty flag is set | R-PE-016 | done (batch-100 Inc 10, 5dd2249) |
| D10-21 | Dirty flag follows real document changes: not set by a refused Add/Edit/Remove; set by undo, redo and a per-entry JSON edit | R-PE-034, R-PE-035 | open (re-verified at 570b4b5) |
| D10-22 | Parse pasted refuses text with an ERROR finding and keeps the document (as Edit JSON does) | R-PATCH-PASTE-001.5 | open (re-verified at 570b4b5) |
| D10-23 | Undo, Redo, ctrl+z / ctrl+y and per-entry Edit JSON for every document; whole-set Edit JSON stays draft-only; drop the `history off` strip state | R-TUI-057.8, R-TUI-058.6, R-TUI-053.5 | open (re-verified at 570b4b5) |
| D10-24 | After a successful Save the written file becomes the document's source (ribbon names it) | R-PE-093 | open (re-verified at 570b4b5) |
| D10-25 | The File dropdown lists the change home (project patches/ and checks/ with a project); with S9 D9-15 | R-PATCH-DOC-DROPDOWN-001.1 | open (re-verified at 570b4b5) |
| D10-27 | Address field: `0x` + hex digits, or decimal digits; message `Patch Editor: bad address '<text>' - use 0x and hex digits, or decimal digits`; with S9 D9-17 | R-PE-030 | open |
| D10-28 | Edit/Remove on a missing address: status without the KeyError quotes | R-PE-028 | open |
| D10-29 | Per-entry edit status names the address (`entry at 0x<X> updated.`), not a zero-based index | R-TUI-058.4 | open (re-verified at 570b4b5) |
| D10-30 | Hide the before/after control and the save-back prompt whenever the document is replaced (dropdown, guarded load, undo, redo too) | R-TUI-049.3 | open (re-verified at 570b4b5) |
| D10-40 | Where the save-back prompt, the before/after control, Undo/Redo and Execute appear (today inside the JSON tab, out of sight after Apply) | R-HEX-VERIFY-002.3 (S8), R-TUI-049.1 | needs prototype |
| D10-41 | One target rule for Edit/Remove (typed address) and the strip / per-entry Edit JSON (highlighted row) | R-PE-024, R-PE-026, R-TUI-058.1 | needs prototype |
| D10-42 | Symbol input with A2L picker and a Symbol ledger column (HLR-141 / LLR-141.2); write the encoder rows S2 passed | — | needs prototype |
| D10-43 | Width control on the save-back prompt for an Intel HEX image (S8 D8-40) | — | needs prototype |

## S11 — Projects, variants & manifest

| Id | Change | Rows | Status |
| D11-70 | Execute scope rewrites project.json (carried records) after a run that saved `<variant id>-patched.s19`, so the next load does not list it as `not recorded` | R-PROJ-EXEC.1 | open |
| D11-71 | A project.json rewrite outside Save project paints `project.json updated + verified`, not `Project saved + manifest verified` | R-MANIFEST-VERIFY.1 | open |
| D11-72 | A load into an open project whose folder was deleted outside the app refuses with the `Project sync NOT done …` / `A2L sync NOT done …` status and creates no folder (fix round 2 observation, `mkdir(exist_ok=True)`) | R-PROJ-002.12, R-PROJ-002.13 | open |
|---|---|---|---|
| D11-13 | Remove the gather's common-library branch for composition names | — | obsolete: batch-100 LLR-171.6b uses the common-library branch to bring back a recorded composition document (Inc 8b, 3a4a309); superseded by D11-62 |
| D11-14 | Move `_session_snapshot` out of the app into the test support code | — | obsolete: batch-100 LLR-165.2 needs `_session_snapshot` for the leak check; superseded by D11-63 |
| D11-15 | Remove the unreachable `Execute: unknown scope` check | — | open |
| D11-16 | Save plan `manifest_keys` / `target_kind`: use them when the dialog paints the plan, else remove | — | obsolete: Inc 11 (53d08d5) paints the plan with `target_kind`; `manifest_keys` records the keys written; superseded by D11-64 |
| D11-20 | Re-save of the open project: refuse only an A2L other than the session's own (add the S19 + A2L re-save test) | R-PROJ-001.12 | done (batch-100 Inc 8b, 3a4a309) |
| D11-21 | Load an A2L-only project | R-TUI-013.8 | done (batch-100 Inc 8b, 3a4a309) |
| D11-22 | Load project lists only projects (not empty folders, not links) | R-TUI-013.2 | done (batch-100 Inc 8b, 3a4a309 for links; Inc 9b, 12d0f81 for folders that hold no project) |
| D11-23 | Save dialog offers the project documents of the folder, `patches/` and `checks/` | R-PROJ-ASSIGN-UI-001.3 | open (re-verified at 570b4b5) |
| D11-24 | Save dialog pre-selects the manifest's batch and assignments | R-PROJ-ASSIGN-UI-001.5 | partly done: a save with nothing selected keeps the carried `batch` / `assignments` (Inc 8b, 3a4a309); the lists still start with nothing selected |
| D11-25 | A manifest that names no file counts as no manifest for Execute scope | R-VAR-002.21, .24 | open (re-verified at 570b4b5) |
| D11-26 | Show manifest findings on project load | R-TUI-013.14 | done in the form batch-100 chose (Inc 6, 948e65c; Inc 7, 052dc3a): `manifest damaged` problems in user terms, codes to the log (D11-61) |
| D11-27 | Show gather findings as finding lines | R-PROJ-GATHER.6, .7, .8 | open (re-verified at 570b4b5) |
| D11-28 | One project load path: project files read in place, parsed on the worker (project load and variant activation) | R-VAR-001.9 (S5 R-TUI-002.2, R-TUI-012L.5) | partly done: a project load reads in place and parses on a worker (Inc 12b, dabcd41 merged in 1571f4c); variant activation still copies into `temp/` |
| D11-29 | Every load path adds S19/HEX/MAC files to the open project (Workarea Files picks too) | R-PROJ-002.1 | open (re-verified at 570b4b5); also the Load dialog's work-area preview line `becomes the active variant of project <P>` (S7 R-LOADDLG.50) |
| D11-30 | Refuse a MAC load when the open project holds another MAC: `Project already has a MAC file.` | R-PROJ-002.6 | open (re-verified at 570b4b5) |
| D11-31 | Save target always `<work area>/<clean name>`; drop the parent-folder refusal | R-TUI-012.4 | done (batch-100 Inc 8b, 3a4a309: handler refusal; Inc 11, 53d08d5: dialog without the parent box) |
| D11-32 | Execute scope saves patched Intel HEX variants as `<variant id>-patched.hex` | R-VAR-002.32 | open (re-verified at 570b4b5) |
| D11-33 | Batch save-back keeps the variant's S0 header | R-VAR-002.33 | open (re-verified at 570b4b5) |
| D11-34 | Per-variant result line printed once | R-VAR-002.36 | open (re-verified at 570b4b5) |
| D11-35 | Manifest verify compares every key written (`declared_regions` too) | R-MAN-VERIFY-001.3 | open (re-verified at 570b4b5); batch-100 added `files`, `derived_from`, `active_document` to the verified keys, not `declared_regions`; the item also covers `gathered` |
| D11-36 | Manifest write: private staging and the shared destination guard with the app's work-area root | R-MAN-WRITE-001.4, .5 | done (batch-100 Inc 7, 052dc3a) |
| D11-37 | `Closed the Patch Editor document (1 entry)` | R-PROJ-RESET.2 | obsolete: the closed-document notice was removed at Inc 10 (4eef8a3); the load question replaces it (D11-66) |
| D11-38 | Load project, Select variant and Save dialog names as plain text (with S1 safe-text list) | R-PROJ-ASSIGN-UI-001.6 | partly done: the Load dialog (Inc 9b, 12d0f81) and the Save dialog (Inc 11, 53d08d5) paint names literally; the Select variant dialog still reads markup |
| D11-39 | Execute scope and later loads into a project with more than one MAC or A2L show the rule's status | R-VAR-002.22, R-TUI-014.1, .2 | open (re-verified at 570b4b5) |
| D11-40 | Prototype round first (Save dialog without the parent box, pre-filled name, blank-name message, lists tied to the open project) | R-TUI-012.3, .4 | done (batch-100 Inc 11 prototype round and verdict, 53d08d5; D11-65) |
| D11-41 | Prototype round first (region lines in hex or decimal) | R-RPT-REGION-PERSIST-002.3 | needs prototype |
| D11-42 | Save project and the batch save-back pass the source's terminator address to the S19 writer (with D11-33 for the S0) | R-PROJ-IMAGE.9, R-VAR-002.43 | open (re-verified at 570b4b5) |

## S12 — Project reports

| Id | Change | Rows | Status |
|---|---|---|---|
| D12-11 | Remove `ReportOptions.include_legend` and `include_entropy` (never set by the product) and their off-tests; legend and Entropy always written | R-LEGEND-REPORT-001.1, R-RPT-ENT.1 | open |
| D12-12 | Remove the unreachable branches: `_format_length` hex/sign branch, `_format_address` sign branch, and their tests; length always decimal | R-TUI-102.8 | open |
| D12-13 | Move `DeclaredRegion.contains` (test-only oracle) into the tests | — | open |
| D12-20 | Reports dialog: a context-bytes value that is not a whole number shows `Report rejected: context_bytes must be an integer in 0..4096, got '<text>' - the value is rejected, not clamped` instead of doing nothing | R-RPT-002.13 | open |
| D12-21 | Filter path box: a blank submit clears the filter selection (as its hint says) and shows `Report filter: none (full report)` | R-RPT-FILTER-001.14, R-RPT-FILTER-001.7 | open |
| D12-22 | Filter confirmation: always `Report filter: <file name>` (drop the 50-character rule; the status line is width-aware) | R-RPT-FILTER-001.5 | open |
| D12-23 | Reports list: `.md` files that are not report names sorted by name, not file-system order | R-RPT-002.3 | open |
| D12-24 | Report worker: move the new variant run out of the `except ValueError` rejection branch; only the context-bytes check is `Report rejected:` | R-RPT-002.24 | open (re-verified at 570b4b5) |
| D12-25 | Log refusals before the run (no variant, nothing to report, filter refused) with `outcome=refused: <status text>` at WARNING | R-RPT-LOG.9 | open (re-verified at 570b4b5) |
| D12-26 | Hexdump block heading names the last address inside the window (inclusive), like the addendum heading; re-baseline the goldens with hexdumps once | R-RPT-001.39 | open |
| D12-27 | Report filter: match an entry's own symbol as well as its linkage symbol | R-RPT-FILTER-001.50 | open |

## S13 — Operations & CRC

| Id | Change | Rows | Status |
|---|---|---|---|
| D13-13 | Remove the `extract` and `split_by_segment` placeholders (and the status `placeholder`) from the registry and the Operations dialog; their tests go | R-OPS-002.1 | open |
| D13-14 | Remove `run_operation` (`operation_service.py:39`), `OperationResult.to_dict`, `Operation.describe`, `OperationResult.timestamp_utc`, the `CRC: no config supplied` note; keep `operation_resolver` | — | open |
| D13-15 | Remove test-only helpers `compute_region_crc`, `compute_region_crcs`, `encode_le32`, `decode_le32`, `read_crc_config`, `seed_template`; move their tests to the functions the product uses | — | open |
| D13-16 | `CrcJob` / `parse_job` / `emit_job` / flat-config up-conversion: delete unless the next CRC batch plans the join of the CRC Designer and the CRC operation | — | open |
| D13-17 | Delete `s19_app/tui/operations/requirements/REQ-crc.md` and the C-7 convention text; S13 is the one source | — | open |
| D13-20 | CRC operation engine: take `init` unreflected when `reverse` is true (parametric model); add a test with a non-symmetric init (poly 0x04C11DB7, init 0x12345678, reverse true, xorout 0xFFFFFFFF over "123456789" = 0x0F8B7431) | R-CRC-ENGINE-001.1 | open |
| D13-21 | CRC config: apply the span rules to regions as to group spans; number regions from 1 in rule texts | R-CRC-CONFIG-001.9, .13 | open |
| D13-22 | CRC config: reject `polynomial` / `init` / `final_xor` outside 0x0..0xFFFFFFFF | R-CRC-CONFIG-001.14 | open |
| D13-23 | CRC config and CRC template readers: name the field in "missing" and "not a number" reasons | R-CRC-CONFIG-001.10, .11 | open |
| D13-24 | Overlap notes for every target (regions too); example config regions end at their stored field (0x1FFFC, 0x2FFFC) in `DUMMY_CONFIG_TEXT` and `examples/crc_config.example.json`; change test_s7_scope_pin_legacy_self_overlap_stays_silent | R-CRC-GROUP-001.2, .3, R-CRC-CONFIG-001.1 | open |
| D13-25 | Keep Write CRC disabled after a check that ends with status `error` | R-CRC-WRITE-001.3 | open |
| D13-26 | Region and write lines: computed, stored and written values as 2N hex digits (field width N) | R-CRC-CHECK-001.6, R-CRC-WRITE-001.24 | open |
| D13-27 | Config error found at Confirm: first line `CRC config error - nothing was written:` | R-CRC-WRITE-001.8 | open |
| D13-28 | CRC write: pass the source's S0 header data and terminator address to the S19 writer (as the save-back, S8 D8-29) | R-CRC-WRITE-001.17, .18 | open |
| D13-29 | Show internal failures of the CRC check and write in the Operations dialog's result area, not the status line | R-OPS-003.11, .12 | open |
| D13-30 | `x` refuses unless a primary (S19 / Intel HEX) is loaded; a MAC-only session gets the no-file status | R-OPS-003.2, .3 | open |
| D13-31 | CRC Designer: `Invalid parameters: <field> is not a number: <text>` (also on Save) | R-CRC-DESIGNER-002.5, R-CRC-TEMPLATE-001.8 | open |
| D13-32 | CRC Designer Save: refuse a device name with the shared rule (`workspace.py:1803`) | R-CRC-TEMPLATE-001.7 | open |
| D13-33 | CRC Designer and Operations dialog join S1's safe-text views (control characters; S1 D-7 sweep) | R-TUI-103 (S1) | open |
| D13-40, 41, 42 | Prototype round first (Operations dialog with one operation; CRC Designer column widths so preset names read whole, toggle state word; coverage-window range colour from the S3 palette, JSON strip title without code names) | R-OPS-002.1, R-TUI-100.1 | needs prototype |

## S14 — A↔B compare & diff reports

| Id | Change | Rows | Status |
|---|---|---|---|
| D14-2 | Delete R-TUI-028 (placeholder screen) from the requirements | — | open |
| D14-8 | Remove `list_diff_reports`, the four report filename regexes and `flow_change_census_complete` (test-only) with their tests | — | open |
| D14-10 | Markdown diff report: write image labels, paths and symbol names through the Markdown escaper | R-CMP-004.9 | open |
| D14-11 | Diff report: claim the file name with an exclusive create; refuse a linked `<project>/reports/` | R-CMP-005.5, R-CMP-005.7 | open |
| D14-12 | Same-file refusal text: `Compare refused: both sides are the same file.` | R-CMP-002.6 | open |
| D14-13 | Refuse Report after a refused or failed compare (`No comparison yet — press Compare first.`) | R-CMP-006.10 | open (re-verified at 570b4b5) |
| D14-14 | Save-back offer: drop `(action: before_after_report)`, offer only with a project open; no-project refusal says `(key 7)` | R-BEFORE-AFTER-REPORT-001.1, .11 | open (re-verified at 570b4b5) |
| D14-15 | Before/after report: pass the loaded A2L and MAC so the Symbols column is filled | R-BEFORE-AFTER-REPORT-001.24 | open (re-verified at 570b4b5) |
| D14-16 | Print run ranges as first and last address (run list, window header, report End column, flow attribution) | R-CMP-006.9 | open |
| D14-17 | A2B Diff check-spec list: scan the folder the check save uses (with D9-15 / D10-25) | R-DIFF-CHK.1 | open |
| D14-18 | Flow-change attribution: also use the files the last Flow Execution run wrote | R-DIFF-FLOWCHG.1 | open |
| D14-19 | Diff and before/after reports: write through S12's encoder (UTF-8, LF on every host) | R-CMP-004.11 | open |
| D14-20 | Run-kind colours from S3's palette, same on screen and in HTML, with a legend block | — | needs prototype |
| D14-21 | Remove the unused decimal form of `format_memory_value` and its doctest | R-BEFORE-AFTER-REPORT-001.28 | open |

## S15 — Flow engine

| Id | Change | Rows | Status |
| D15-18 | Refuse to save a flow or a chain set when `flows/` or `flowsets/` resolves outside the work area (batch-100 LLR-171.4i, .4j, routed to its backlog by LED .77), with the manifest write's destination guard; add the two tests | R-FLOW-FILE.11, R-FLOW-SET.7 | open |
|---|---|---|---|
| D15-8 | Remove the multi-variant fused run (`run_flow_over_variants`, `flow_fused_report_service.py`, `FusedFlowRunResult`, `VariantRunOutcome`, `FlowContext.variant` / `defer_report`, the variant arm of `_bound_source_ref`, `FLOW_SCOPE_*`, `RunRequested.scope`, `render_fused_result`) and its three test files; delete R-TUI-099 | — | open |
| D15-10 | Flow report footprint: byte total `end − start`, print the last address; regenerate the batch-71 golden | R-FLOW-RPT.9 | open |
| D15-11 | Flow report status PAUSED for a paused run; chain-set ledger mark `□` for paused | R-FLOW-RPT.4, R-FLOW-CHAIN.16 | open |
| D15-12 | Flow, chain-set and flow-A2B reports: claim the file name with an exclusive create | R-FLOW-CHAIN.10 | open |
| D15-14 | WRITE-OUT S19: write the source's terminator address (as R-S19-EMIT.11) | R-FLOW-WRITE.4 | open |
| D15-15 | Saved flow and chain-set names: lowest free `_<N>` from 1 | R-FLOW-FILE.2, R-FLOW-SET.3 | open |
| D15-17 | External step: read a relative output path under the project folder, like the log | R-FLOW-EXT.2 | open |

## S16 — Flow Builder UI

| Id | Change | Rows | Status |
|---|---|---|---|
| D16-6 | Remove the hidden `#flow_help`, `#flow_canvas`, `#flow_blocks`, `#flow_ext_session`, `#fx_help` and their painters (`_canvas_text`, `_blocks_text`, `_flow_block_label`) | — | open |
| D16-10 | Builder: check each Add and + Add var with the flow loader's rules (refs, output names, funnel limits, block cap), as Paste does | R-FB-ADD.11, R-FB-VAR.6 | open |
| D16-11 | Builder: declare Intel HEX for LOAD / WRITE-OUT names ending in `.hex` / `.ihex` | R-FB-ADD.12 | open |
| D16-12 | Builder: refuse Run on an empty chain (`No blocks to run — add a block first.`) | R-FB-RUN.1 | open |
| D16-13 | Save flow dialog: notice `(exists — saves as <name>_<N>.json)` instead of `(overwrites existing)` | R-FB-SAVE.2 | open |
| D16-14 | Ask `Discard unsaved flow edits?` before Clear and before Load Set replaces unsaved lanes | R-FB-RUN.7, R-FX-SET.8 | open |
| D16-15 | Run flows and chain sets in a worker; keep Run disabled meanwhile | R-FB-RUN.4, R-FX-RUN.7 | open |
| D16-16 | Flow Execution: Run uses the typed set name, like Save Set and confirm | R-FX-RUN.14 | open |
| D16-17 | Reloaded lanes show `░ not run` until they run | R-FX-SET.14 | open |
| D16-18 | Run log: add `report: reports/<file>` for the chain-set report | R-FX-RUN.13 | open |
| D16-19 | Lane names: lowest free `_<N>` from 1 (with D15-15) | R-FX-LANE.3 | open |
| D16-20 | Import with no project: `import refused: no project loaded - load or save a project first` | R-FX-LANE.5 | open |
| D16-25 | Optional A2L reference input on LOAD and PATCH (S0 HLR-142) | R-FB-ADD.17 | needs prototype |
| D16-26 | REPORT chip in the Builder palette | R-FB-ADD.16 | needs prototype |
| D16-27 | One status glyph vocabulary for the Builder result, Flow Execution and the chain-set report | — | needs prototype |
| D16-28 | Flow kind and waiting colours from S3's palette | — | needs prototype |

## S17 — Split / Join / Export

| Id | Change | Rows | Status |
|---|---|---|---|
| D17-13 | Remove `segment_ops.slice_ranges` and `segment_ops.write_bin_with_sidecar` (tests only) and their tests | — | open |
| D17-14 | Sanitiser: remove the device-name prefix with the superscript normalisation and the `segment_<index>` fallback (no effect: every name starts with `<stem>_`, no row name is empty); drop their test cases | — | open |
| D17-20 | Naming sample, output label and per-file labels show the name the export writes (segment part), not the raw row name | R-SEG-PREV.4 | open |
| D17-21 | Table, naming line, output label and per-file rows: A2L names through the safe-text function (with S1 D-7) | S1 R-TUI-103 | open |
| D17-22 | Join concat: count an empty join file (state line + confirm); its BIN sidecar holds the lowest selected base | R-SEG-PREV.9, R-SEG-EXP.5, R-SEG-OUT.11 | open |
| D17-23 | Concat summary prints the real base (lowest selected base), not `0x00000000` | R-SEG-PREV.17 | open |
| D17-24 | Band in split mode: fill only with gaps fill; uncovered row span with gaps skip is absent | R-SEG-PREV.2 | open |
| D17-25 | An edit of the manual box disarms the confirm | R-SEG-EXP.9 | open |
| D17-26 | Overlapping selected rows in join mode: notice `Export aborted: rows 0x<A8>–0x<A8> and 0x<A8>–0x<A8> overlap. Nothing written.` | R-SEG-EXP.4 | open |
| D17-27 | Conflict refusal: one notice naming the count and the first address; state line shows the conflict before the guard | R-SEG-EXP.3, R-SEG-PREV.7, R-SEG-PREV.8 | open |
| D17-28 | Texts: `file(s)` plural rule in `Exported <n> …`; `Export failed:` capitalised everywhere | R-SEG-EXP.12, R-SEG-EXP.13, R-SEG-EXP.14 | open |
| D17-29 | Fill summary and overlap notice print the last address of a range, not the address after it | R-SEG-PREV.18, R-SEG-EXP.4 | open |
| D17-30 | BIN split file with gaps skip and non-contiguous covered bytes: refuse, naming the file | R-SEG-OUT.12 | open |
| D17-31 | Refuse at plan time any export file over the copy limit, before any file is written; measure fill memory use under the limit | R-SEG-PLACE.14 | open |
| D17-32 | Guard (≥ 1 MiB span, ≥ 50 % pad) also per split fill file | R-SEG-PREV.8, R-SEG-EXP.5 | open |
| D17-33 | S19 export from an S19 source carries the source's S0 data (with S8 D8-27) | R-SEG-OUT.14 | open |
| D17-34 | Warn when an export holds bytes of an invalid range: `Warning: <n> invalid source ranges exported, first at 0x<A8>` (with S8 D8-26) | R-SEG-OUT.18 | open |
| D17-35 | BIN pair reused when an identical pair exists under any shared numbered suffix, as single files are | R-SEG-PLACE.5 | open |
| D17-36 | a2l note `the A2L has no MEMORY_SEGMENT with a base and a size` when an A2L is loaded with no usable segment | R-SEG-SRC.10 | open |
| D17-37 | No a2l row for a MEMORY_SEGMENT with a size of 0 or below | R-SEG-SRC.6 | open |
| D17-38 | Reproduce: load/unload refresh focuses the hidden window's table; focus only while the window is shown | R-SEG-OPEN.6 | open (re-verified at 570b4b5) |
| D17-40 | Coverage marks: palette colour and glyph per coverage state (zero coverage is not an error) | — | needs prototype |
| D17-41 | Join concat ruler: real file addresses, or labelled offsets | — | needs prototype |
| D17-42 | One word per band class on legend, stats and state line (data / fill / conflict / context) | — | needs prototype |
| D17-43 | Pad byte always shown, or `p` acts only with gaps fill | — | needs prototype |
