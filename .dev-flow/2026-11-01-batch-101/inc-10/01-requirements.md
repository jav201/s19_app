# Inc 10 — Hex navigation, unload state, Split/Join focus, views that follow in-place writes: requirements (E1)

Batch 2026-11-01-batch-101, increment 10. Base: `98d94d7` (branch `b101-inc10`; main with Incs 1–5, 7, 8, 11, 13–16 merged; Incs 6 and 9 in flight). Stage E1 of the design-first flow (`dev-flow-v3-beta`).
Scope, canon changes and decisions: `E1-rulings.md`. Slice: `E1-slice.md`. Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc10.md`. Confirmation run (D-4 check first, then the findings): `evidence-e1/i10e1-pilot-transcript.txt` (LAN Linux host, `98d94d7`, script `evidence-e1/i10e1-pilot.py`).

Sources: plan row 10 (`PLAN.md`, `p0/PLAN-draft.md` row 10); Inc 5 ruling D-4 and its definitions (`inc-5/E1-rulings.md`, `inc-5/01-requirements.md`); `docs/user-guide/DOSSIER.md` §5 F-07, F-13, F-14, F-18 and `ch03`, `ch05`, `ch14`; `docs/requirements/review/S4`, `S5`, `S6`, `S17-ears-strict.md`; `s19w/review/CODE-CHANGES.md` D4-2, D4-6, D5-17, D5-19, D5-27, D6-21, D17-38; `.dev-flow/BACKLOG-CODE.md` SE5-12a-2; triage `p0/triage-C-views-layout-perf.md` (re-verified at `98d94d7`, `E1-rulings.md` §2).

Form column: U = ubiquitous, E = event (`When`), S = state (`While`), N = unwanted (`If … then`). "Base" = what `98d94d7` does, from the pilot where it says so. Messages are quoted exactly; `<…>` is a placeholder. No row changes a layout; what the operator can notice is listed in `E1-rulings.md` §1.

## User stories

### US-HEXNAV-1 — a jump shows me its target
As the operator, I want every go-to, search hit and section, tag, record, issue or map jump to show the target row near the top of the hex pane, scrolled to the left edge, and the `> ` marker only on a go-to I just made, so that I never scroll to find the row I asked for. (F-07, D4-2, D4-6.)

### US-UNLOAD-1 — the status line describes what is loaded
As the operator, I want the file status to say what I just unloaded, to say `Nothing to unload.` when nothing was loaded, to drop the diagnostics of an unloaded image, and to show file names without format characters, so that the status line never describes a file that is gone or a name that is not its own. (F-13, D5-17, D5-19, D5-27, SE5-12a-2.)

### US-FOCUS-2 — the keys reach the window I see
As the operator, I want the focus on the shown window after a rail key, after closing Split / Join and after an unload, so that my next key never lands in a hidden widget. (F-14, D17-38, D6-21.)

### US-FRESH-3 — views over the image follow bytes written into it
As the operator, I want the A2L tag table's values and the Split / Join preview to describe the image as it is after an apply, a save-back or a Save project commit, so that I never read a stale value or export against a stale conflict check. (Inc 5 ruling D-4 (a), (b), reproduced: `E1-rulings.md` §3.)

## Definitions

- **In-place write** (Inc 5 definition, S9 / S13; **scope widened** to S2 CTX-A2L and S17): a Patch Editor apply (whatever its status), a Patch Editor save-back (whatever its outcome), or a Save project commit that writes the image. The `current_file` object is kept; its bytes change.
- **Jump** (S4 CTX-HEX, new term): a hex view showing a new target: a go-to hit, a search hit, or a selection of a section, an A2L tag (select or tag find), a MAC record, an issue or a Memory Map cell.
- **Second row** (S4 CTX-HEX, new term): the second hex row of the view, below its notice lines.
- **Next hex page** (S4 CTX-HEX, amended): the hex page that starts at the first present row after the shown window. **Last page shown**: the shown window holds the last present row. After a jump the window starts one row above the target row and may hold fewer rows than the hex page size.
- **File status** (S6 CTX-SHELL, amended): the last file status the system set: a load's load status (S5 CTX-FILES), **an unload's unload status (R-WS-LOADED.13)**, a project load's project line (S11). `Ready.` until the first.
- **Fixture three** (test term): an S19 image of three 8-byte ranges `0x8000` (bytes `00`…`07`), `0x8010` (eight `FF`), `0x8020` (`20`…`27`). **Case 08**: `tools/synth/make_release_case.py` seed 20260001, 1.0 MB (`firmware.s19`, `firmware.a2l`, `firmware.mac`; 26 546 present rows). **Join-fill pick**: Split / Join in join mode, gap fill, pad `0xFF`, ranges `range_00` and `range_02` picked.

## Requirements

### S4 — hex views (US-HEXNAV-1)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TUI-018.1 | E | When the main, A2L or MAC hex view jumps to a target, the system shall show the target row as the second row of the view. **(changed: names the three views; "second row" defined)** | per case: the second hex row's address = the target row's base; 3/3 | the main view's page-floor start restored (`(i // page) * page`) → main cases RED | US-HEXNAV-1 | No: main goto to row 150 shows it as row 151 of a page window from `0x00000000` (viewport 28 rows); Find Next hit `0x00C00050` on line 97; section `0x00040000` on line 98; A2L go-to target is row 65 (64 context rows) |
| R-TUI-018.2 | E | When the main, A2L or MAC hex view jumps to a target, the system shall scroll the view to its first line and its left edge. **(changed: was "back to its left edge" only)** | `scroll_y` = 0 and `scroll_x` = 0 after the jump from (x 10, y 40); 3/3 | the scroll reset removed from the main view → RED | US-HEXNAV-1 | No: after a user scroll to (10, 40) a go-to leaves (10, 40) |
| R-TUI-040.4 | N | If the address is in the image, then the system shall show its target row second from the top of the hex view. **(text unchanged; = R-TUI-018.1 for a go-to)** | as R-TUI-018.1 for each of the three go-to boxes; 3/3 | as R-TUI-018.1 | US-HEXNAV-1 | No (as R-TUI-018.1) |
| R-TUI-040.8 | N | If the address is not in the image, then the system shall leave the hex view's rows unchanged. **(text unchanged; regression guard for R-TUI-040.11)** | the hex rows' plain text after the failed go-to equal those before, the marker prefix aside; 3/3 | the failed go-to re-renders from row 0 → RED | US-HEXNAV-1 | Yes (no re-render) |
| R-TUI-040.11 | N | If a go-to fails, then the system shall remove the view's `> ` marker. **(text unchanged)** | 0 lines start with `> ` after a miss, an empty box or an invalid address, in each of the three views; 3/3 | the re-render on failure removed → RED | US-HEXNAV-1 | No: after a hit on row 5 then a miss (`Address 0xFFFFFFF0 not in loaded file.`) or an invalid text (`Invalid address format.`) the marker stays on line 6 |
| R-TUI-040.12 | E | When a hex view pages, starts a new search, jumps to a new target or loads a file, the system shall remove its `> ` marker. **(text unchanged; "new target" = any jump other than the go-to's own)** | the marker address is cleared and 0 marked lines after a section, issue, map or continued-search jump in the main view and a continued search in the A2L and MAC views; 3/3 | the marker clear on a jump removed → RED | US-HEXNAV-1 | Partly: paging, a new search, tag and record jumps, a load clear it; a section jump keeps the marker address (`0x50` after the jump, pilot) |
| R-TUI-007.3 | E | When the operator presses `.` on the Workspace, the system shall show the next hex page. **(text unchanged; next hex page amended)** | after a jump to row 949 of 1 000 rows (page 200) `.` keeps the window; after a jump to row 151 `.` starts the window at row 350; 3/3 | `min(max_start, start + page)` kept → the row-949 case moves back to row 800 → RED | US-HEXNAV-1 | Yes for page-aligned windows |
| R-TUI-007.5 | N | If the operator asks for the next hex page while the last one is shown, then the system shall keep the last page. **(text unchanged; last page shown defined)** | the window start unchanged after `.`, 3 presses; 3/3 | as R-TUI-007.3 | US-HEXNAV-1 | Yes for page-aligned windows |

### S5 — unload and the file status (US-UNLOAD-1)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-WS-LOADED.18 | E | When the system unloads files, the system shall show its unload status of R-WS-LOADED.13 as the file status. **(new)** | `#status_text` = `Unloaded MAC.` after `[u]` on the MAC slot, `Unloaded all artifacts.` after `U`, `Unloaded primary image.`, `Unloaded A2L.`; 3/3 | the file-status write removed → RED | US-UNLOAD-1 | No: `Loaded firmware.mac (S19+MAC)` stays after `[u]` and after `U` |
| R-WS-LOADED.13 | E | When the system unloads files, the system shall show the status `Unloaded primary image.`, `Unloaded MAC.`, `Unloaded A2L.` or `Unloaded all artifacts.` **(text unchanged; regression)** | the newest message line is the text, once; 3/3 | the message removed → RED | US-UNLOAD-1 | Yes (`Unloaded MAC.`, `Unloaded all artifacts.`) |
| R-WS-LOADED.14 | N | If nothing is loaded when the operator asks to unload, then the system shall show the status `Nothing to unload.` **(text unchanged)** | newest message `Nothing to unload.` after `U` with nothing loaded; the file status unchanged (`Ready.`); 3/3 | the all-kind early return removed → RED | US-UNLOAD-1 | No: `U` with nothing loaded says `Unloaded all artifacts.` |
| R-WS-LOADED.16 | E | When the system unloads the primary, the system shall drop the primary's line diagnostics and integrity notices. **(text unchanged)** | primary with 1 bad-checksum line + MAC: after `[u]` on the primary, 0 loader diagnostics in the Issues Report and the loader-facts line, 0 integrity-notice codes; 3/3 | `errors` kept in the MAC-only rebuild → RED | US-UNLOAD-1 | No with a MAC loaded: 1 diagnostic and the path `bad.s19` stay after the primary unload |
| R-TUI-012L.8 | E | When a load ends, the system shall show the load status of CTX-FILES for the file just loaded. **(text unchanged; `<name>` and `<MAC file name>` are painted names)** | file `fw` U+202E `gpj.s19` → `#status_text` = `Loaded fwgpj.s19 (S19 only)`, 0 characters of category Cc, Cf, Zl, Zp; the same for the `+MAC:` and the integrity-notice arms; 3/3 | `path.name` used raw → RED | US-UNLOAD-1 | No: `Loaded fw` U+202E `gpj.s19 (S19 only)` (SE5-12a-2) |

### S6 — focus (US-FOCUS-2)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-SHELL-FOCUS.2 | E | When the operator shows another window with a key, the system shall put the focus on that window's focus target. **(text unchanged)** | focused widget id = the CTX-SHELL target after `2` from the Workspace, after Esc in Split / Join, after a rail key in Split / Join, after `]` from a rail item; 3/3 | the focus move removed → RED | US-FOCUS-2 | No: after `2` the focus is `ws_load_project_button` in the hidden Workspace (area 0); after Esc or `3` in Split / Join nothing is focused |
| R-SHELL-FOCUS.3 | E | When a load completes, a load is cancelled or an unload ends while the focus behind any dialog is on a widget that is hidden, has no size, or sits in a hidden window, the system shall put the focus on the shown window's focus target. **(changed: "or an unload ends" added)** | after `[u]` on a slot whose button the unload hides, focus = `files_list`; 3/3 | the re-home after unload removed → RED | US-FOCUS-2 | No: after `U` the focus is `sje_table` (hidden, area 0) |
| R-SHELL-FOCUS.4 | E | When a load completes, a load is cancelled or an unload ends while the focus is on a shown widget of the shown window or on a frame widget, the system shall keep the focus there. **(changed: "or an unload ends" added)** | `files_list` focused, `U` → `files_list`; rail item focused, `U` → that rail item; 3/3 | an unconditional focus move after unload → RED | US-FOCUS-2 | No: `files_list` → `sje_table` after `U` |
| R-SHELL-FOCUS.5 | N | If the shown window's focus target is not shown, then the system shall put the focus on the first shown widget of that window that takes the focus and is not a text box. **(text unchanged; now also on a rail key)** | `5` with no file loaded (Issues empty state): focus on the first shown non-text widget of Issues, else the rail item; 3/3 | the fallback skipped → RED | US-FOCUS-2 | Yes on the load path only |
| R-SEG-OPEN.6 | S | While the window is hidden, the system shall keep the focus out of it. **(text unchanged)** | 0 focused widgets inside `#screen_split_join` after a load, an unload, an in-place write while it is hidden, and after Esc or a rail key closes it; 3/3 | the unconditional `sje_table` focus in the refresh kept → RED | US-FOCUS-2 | No: `U` from `files_list` moves the focus to the hidden `sje_table` |
| R-SEG-OPEN.1 | E | When the operator opens the window, the system shall focus its table. **(text unchanged; regression)** | focus `sje_table` after the palette entry; 3/3 | the open-path focus removed → RED | US-FOCUS-2 | Yes |

### S2 and S17 — views over in-place writes (US-FRESH-3)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-A2L-048 | E | When the system writes bytes into the loaded image in place, the system shall show in the tag table each tag's raw and physical values read from the written bytes. **(new)** | case 08: `VALUE_0001` at `0x00000000` written `6C` → `93`; the tag row's Raw and Physical cells read `147`; 3/3 | the enrichment cache kept across the write → `108` → RED | US-FRESH-3 | No: the row reads `108` / `108` after the apply and a re-show (cache key unchanged; uncached value `147`) |
| R-A2L-049 | E | When the system writes bytes into the loaded image in place, the system shall keep the tag table's first shown row. **(new)** | the first shown tag before and after the write are the same tag; 3/3 | the refresh drops the anchor → RED | US-FRESH-3 | n/a (no refresh today) |
| R-SEG-PREV.21 | E | When the system writes bytes into the loaded image in place while the window is displayed, the system shall show the preview band, the stats line and the state line of the written bytes. **(new)** | fixture three, join-fill pick, `0x8013` = `AA` applied (band `data 8 · fill 11 · conflict 1 · fill 12 · data 8`); `0x8015`, `0x8016` = `BB CC` committed by Save project while displayed → band `data 8 · fill 13 · conflict 2 · fill 9 · data 8`, state `⚠ 2 B would clobber source — abort on export`; 3/3 | the window notice removed → band stays `conflict 1` at `0x8013` → RED | US-FRESH-3 | No: after the commit the band still shows `conflict 1` at `0x8013` and `⚠ 1 B would clobber source …` |
| R-SEG-PREV.22 | E | When the system shows the preview of written bytes (R-SEG-PREV.21), the system shall keep the focus where it is. **(new)** | focused widget before the commit = after it (a widget of the window or the dialog's return focus); 3/3 | the notice calls the window's open refresh (`sje_table` focused) → RED | US-FRESH-3 | n/a |

Rows considered and not added: F-18 (`t` typed into the manual box) — not reproduced (`E1-rulings.md` §3, D-3).
