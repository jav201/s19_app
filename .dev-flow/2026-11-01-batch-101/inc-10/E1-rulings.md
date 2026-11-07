# Inc 10 — E1 rulings (scope, canon changes, decisions)

Since E3 this file is Inc 10a's (`E3-rulings.md`, split): §1–§6 are the E1 record as written, with the E3 changes marked in place; §7 records the E3 correction. Inc 10b's own decisions are in `../inc-10b/E1-rulings.md`.

Base `98d94d7`. Pilot: `evidence-e1/i10e1-pilot-transcript.txt` (LAN Linux host, detached worktree at `origin/main` = `98d94d7`, Textual 8.2.8, `LOCALAPPDATA` and XDG isolated, no clipboard; worktree removed after).

## 1. Scope and what the operator can notice

In: F-07 (D4-2, D4-6), F-13 (D5-17, D5-19, D5-27), F-14 (D17-38, D6-21), SE5-12a-2, Inc 5 ruling D-4 (a) and (b) (reproduced, §3). Out: F-18 (not reproduced, D-3).

No layout changes. What changes on screen: after a jump the target row is the second hex row and the pane is scrolled to its top-left (the window may then hold fewer rows than a page near the image end); a failed go-to removes the `> `; the status line reads `Unloaded …` after an unload; file names in it lose Cf characters; after a rail key, Esc or a rail key in Split / Join the focus ring is on the window's focus target; the A2L Raw / Physical cells and the Split / Join preview follow an in-place write. None of these is among the 37 known-failed UI rows (`p0/known-failed.md`).

E3 (10a): the A2L cells and the Split / Join preview moved to 10b. Added for 10a: a jump to the first view row shows it first; a MAC record below the image counts as a row above the target and in the pages; an A2L or MAC jump to an absent address lands on the snapped row; the focus lands once the shown window is laid out, so for one refresh after a rail key no widget is focused if the old one sat in the window just hidden; the landing also follows the non-key callers of the window switch (rail clicks, palette entries, Memory Map open-in-hex, window help, `action_view_*` (removed by Inc 12, §8), the Split / Join close; A10-11); the load status clips a name over 120 characters to 120, ending `…` (`painted_names`, A10-06); the project-load line loses format characters (S-5); after a primary unload the session's file is the MAC file — the Loaded panel, the load question and Save project name it and Save project writes no image file (S-2); a primary unload keeps the MAC's own diagnostics (A10-07). Round 2 (SR2 / AR2): the hidden Split / Join EXPORT button writes nothing — `action_export` refuses while the window is hidden (SR2-1); re-showing the window already shown schedules no landing and keeps a healthy focus there (AR2-4); a load or a MAC load/unload re-anchors the stored main window index — a load resets it and a MAC change keeps the first shown address — widening D4-14 (AR2-5; **removed at E4 integration**, §9 I-D2: not built, required by no case; backlog BL-I10-1 with what the operator now notices).

## 2. Triage re-verified at `98d94d7`

Every triage claim used was checked in the code (`E1-slice.md` §2 lines): F-07 (no scroll call; main window page-floored, A2L/MAC go-to and search render 64 context rows, `FOCUS_CONTEXT_ROWS`, `render/hexview.py:21`); F-13 (`_apply_unload` writes only the message line); F-14 (`refresh_window` focuses `#sje_table` unconditionally, `segment_split_view.py:1744`; `action_show_screen` moves no focus); F-18 (`action_cycle_tab` focuses the box inside the action). Triage's F-18 mechanism did not hold in the run (§3).

## 3. Confirmation run (D-4 first)

| Item | Result | Numbers |
|---|---|---|
| **D-4 (a)** A2L explorer value column | **reproduced** | case 08 + A2L; `VALUE_0001` at `0x00000000` Raw `108` (`0x6C`); Patch Editor apply `0x0` = `93` (`Apply: 1 applied, 0 skipped, 0 blocked`; same `mem_map` object); key `2`: Raw `108`, Physical `108`; cache key unchanged; uncached enrichment `147` |
| **D-4 (b)** Split / Join | **reproduced while displayed; not while hidden** | fixture three, join-fill pick: before `ready — e exports`; write while hidden (apply `0x8013` = `AA`) then reopen: `⚠ 1 B would clobber source …` = uncached plan (1 B); write while displayed — the shipped Save project handler committing `0x8015`, `0x8016` = `BB CC` (and restoring `0x8013` = `FF`): band still `conflict 1` at offset 19, state `⚠ 1 B …`; uncached plan `fill 13 · conflict 2 · fill 9`. A posted apply while displayed gives the same staleness |
| F-07 | reproduced | 118 × 54: main go-to row 150 → line 151, viewport 28 rows; after a user scroll (10, 40) a go-to leaves (10, 40); Find Next `0x00C00050` on line 97 of a window from `0x0081FA60`; section `0x00040000` on line 98; A2L go-to → row 65 (64 context rows), viewport 37. The MAC go-to did not submit in the pilot (Tab order); its code path is the A2L one (`update_mac_hex_view` without near-top) and the guide's ch05-04 shows 64 rows above the target |
| D4-6 | reproduced | marker on line 6 after a hit stays after a miss and after an invalid address; a section jump keeps `_goto_focus_address` = `0x50` |
| F-13 / D5-17 | reproduced | `Loaded firmware.mac (S19+MAC)` stays after `[u]` MAC (message `Unloaded MAC.`) and after `U` |
| D5-27 | reproduced | `U` with nothing loaded → `Unloaded all artifacts.` |
| D5-19 | reproduced | primary with 1 bad-checksum line + MAC; after the primary unload: `file_type` `mac`, 1 diagnostic, path `bad.s19` |
| F-14 / D17-38 / D6-21 | reproduced | after `U` from `files_list`: focus `sje_table` (hidden, area 0); after `2`: `ws_load_project_button` (hidden Workspace, area 0); after Esc or `3` in Split / Join: nothing focused |
| SE5-12a-2 | reproduced | `Loaded fw` U+202E `gpj.s19 (S19 only)` on `#status_text` |
| F-18 | **not reproduced** | after the `t` that opens the manual tab the box holds `''` (focus `sje_manual`); a second `t` — typed into the focused box, R-TUI-031.1 — makes it `'t'` and the tab stays manual. The guide's driver line matches the second `t` |

## 4. Changes to canon rows (forwarded to the requirements session)

| Id | Change | Reason |
|---|---|---|
| R-TUI-018.1 | "When a hex view jumps …" → "When the main, A2L or MAC hex view jumps …"; "second from the top" → "as the second row of the view" | 29148 unambiguous: the hex peek (13 rows around), diff hex and result hex are hex views with their own rows; "second row" defined below the notice lines (CTX-HEX "notice line: a line above the rows") |
| R-TUI-018.2 | "scroll the view back to its left edge" → "scroll the view to its first line and its left edge"; three views named | the measured defect is the vertical scroll; one response (one scroll position) |
| R-SHELL-FOCUS.3, .4 | trigger "a load completes or is cancelled" → "a load completes, a load is cancelled or an unload ends" | E3: same response for the new alternative; an unload hides the `[u]` that held the focus |
| New rows: R-WS-LOADED.18, R-A2L-048, R-A2L-049, R-SEG-PREV.21, R-SEG-PREV.22 | new (ids grepped free in the canon, `s19w/review`, `docs/requirements` and the batch's increments) | F-13 / D5-17; D-4 (a); D-4 (b) and the Inc 5 focus constraint |
| Definitions | CTX-HEX: *jump*, *second row*, *next hex page* and *last page shown* (amended); CTX-SHELL: *file status* includes an unload's status; *in-place write* (Inc 5) scope widened to S2 and S17 | rows cite them (E6) |
| E3: R-TUI-018.1 | trigger narrowed: "jumps to a target row other than its first view row" | A10-05: at the first view row the window cannot start one row above |
| E3: R-TUI-040.4 | "show its target row second from the top of the hex view" → "show its target row as R-TUI-018.1 and R-TUI-018.4 place it" | A10-05, same exception for a go-to |
| E3: R-SHELL-FOCUS.3 | "… sits in a hidden window, or is removed …" | A10-01: the unload removes the `[u]` that held the focus, and Textual's own reset then picks another widget (P3) |
| E3 new rows (10a): R-TUI-018.4, R-WS-LOADED.19, R-WS-LOADED.20, R-SEG-OPEN.7, R-SHELL-STATUS.7 | new; ids grepped free in `REQUIREMENTS.md`, `docs/`, `s19w/review` and every `inc-*` record of the batch on its branch (b101-inc2 … b101-inc16, b101-canon, b101-p0) | A10-05; S-2 (two rows, one response each); S-3; S-5 |
| E3 canon rows used (text unchanged): R-TUI-018.3, R-TUI-007.8 | added to the slice's rows | A10-03 (b) snap, (a) MAC-added rows counted |
| E3 definitions | CTX-HEX: *view rows*, *first view row*; *next hex page* and *last page shown* counted in view rows | A10-03 |
| E3 moved to 10b | R-A2L-048, R-A2L-049, R-SEG-PREV.21, R-SEG-PREV.22, US-FRESH-3 | split |
| E3 addendum (Inc 12 D-2): definitions | CTX-HEX *jump*: "an issue" dropped from its list of selections | no product route runs the issue jump, and Inc 12 removes it (§8) |

Rows used with unchanged text: R-TUI-040.8, .11, .12, R-TUI-007.3, .5, R-WS-LOADED.13, .14, .16, R-TUI-012L.8, R-SHELL-FOCUS.2, .5, R-SEG-OPEN.1, .6 (E3: R-TUI-040.4 changed; R-TUI-018.3 and R-TUI-007.8 added).

## 5. Decisions

- **D-1 — F-07 by moving the window, not by scrolling inside a page.** Alternatives: (a) keep the page-floored window and scroll the container so the target is the second visible row — needs a laid-out Static, cannot reach rows near the window end, and differs from the A2L/MAC tag jumps; (b) **chosen:** every jump starts the window one row above the target (the near-top path the tag and MAC-record jumps already use) and homes the scroll. Consequence: near the image end the window holds fewer rows than a page; `.` keeps a window that holds the last row (R-TUI-007.5) and otherwise starts after the shown window. R-TUI-018.1 wins over a full last page.
- **D-2 — R-SHELL-FOCUS.2 on every rail key (D6-21), not only on Split / Join's close.** The canon row is unconditional and the base leaves the focus in the hidden window after any rail key (pilot: `ws_load_project_button`, area 0). TC-B97-64 pins "`]` moves no focus" (batch-97 PC-13); its purpose — `c` confirms on arrival — holds with the focus on `fx_panel` (`c` is an app binding). Its two arms change their expected focus; names kept. *Orchestrator: confirm, or narrow Inc 10 to the Split / Join close and the unload (then R-SHELL-FOCUS.2/1, /4, /5 move to the backlog).*
- **D-3 — F-18 closed as not reproduced; no row, no code.** The plan's "new S17 row" would pin behaviour the base already has. The real keyboard issue — `t` cannot leave the manual tab while the box has the focus (Esc closes the window) — is a key-design change: backlog candidate for a UI round, not this increment. The Windows run that produced the guide line cannot be repeated here (operator run rule).
- **D-4 — D-4 (a) by repainting at the write, keeping the anchor.** Alternatives: a byte-write term in the cache key alone (the table paints only on `update_a2l_view`, so nothing would repaint); `update_a2l_view()` (resets the anchor: R-A2L-049). Chosen: invalidate and repaint through the anchor-keeping path (`E1-slice.md` #17). Cost: one enrichment per in-place write (case 08: 462 tags), not per key.
- **D-5 — D5-19's "path" part not taken.** R-WS-LOADED.16 asks for diagnostics and notices; after F-13 the status line no longer shows the path, and no other observable reads a MAC-only spine's `path` (Split / Join has no ranges then). Reported, not changed. **Withdrawn at E3 (S-2, `E3-rulings.md`):** the premise is false — `_plan_project_save` plans `loaded.path` as the project's image (`app.py:13054-13081`), so Save project after a primary unload copied the unloaded image into the project (E3 security P6), and `_load_question_text` titled the question `Replace <unloaded name>?` (`app.py:8706`). Replaced by D-7 and rows R-WS-LOADED.19, R-WS-LOADED.20.
- **D-6 — Split / Join re-plans at the write only while displayed.** While hidden the next open re-syncs (pilot: fresh). The notice never calls `refresh_window` (Inc 5 interface note).

## 6. Findings outside the plan row (not taken; for the backlog)

- **N-1** Enter in a search or go-to box runs nothing — no `Input.Submitted` route for `#goto_input`, `#search_input` and the A2L / MAC twins (pilot: value `0x960`, no `Goto` line after Enter; the guide uses Tab, Enter). R-TUI-040.2 and R-TUI-017.1 name Enter. Not in Inc 10's row.
- **N-2** A2L / MAC near-top jumps do not snap to the next present row when the target row is absent (`_row_start_for_near_top_focus` returns `None`), unlike the main view (R-TUI-018.3).
- **N-3** The other hex views (main, A2L, MAC) were not probed for staleness after an in-place write while displayed (D-4 named only the value column and Split / Join).

## Orchestrator rulings on E1 decisions (2026-11-06)

Taken under the operator's standing commission (decide with a recorded reason).

- **D-4 check (Inc 5 ruling D-4):** reproduced for the A2L explorer value column and for a displayed Split/Join window; not for a hidden Split/Join window. Both fixes go through Inc 5's in-place-write hook and never call `refresh_window`. Taken into this increment (R-A2L-048/-049, R-SEG-PREV.21/.22).
- **D-2 → yes.** R-SHELL-FOCUS.2 applies on every rail key, including `]`; TC-B97-64's "`]` moves no focus" expectation changes with it (node name kept). Why: the pilot shows focus left on a widget of a hidden window after `2` and after `U` (F-14, D6-21); an expectation that preserves focus on a hidden widget encodes the defect.
- **D-3 → yes.** F-18 is closed as not reproduced (the box holds '' after the opening `t`); "`t` cannot leave the manual tab" goes to the UI backlog (KF-101 family). Why: no change without a reproduced cause.
- **D-5 → yes.** D5-19's path part is left out: nothing on screen reads the old path after the primary unload. Why: a requirement must be observable. **Withdrawn by the E3 ruling on S-2:** the old path is observable — in the saved project and in the load question (§5 D-5, §7 D-7).
- **N-1 → backlog.** Enter in the go-to/search boxes runs nothing. Why: outside Inc 10's rows.

## 7. E3 correction (Inc 10a, 2026-11-06)

Rulings applied (`E3-rulings.md`): A10-01 = S-4, S-2, S-3, S-5, A10-02, A10-03, A10-05, A10-06, A10-07, A10-10, A10-11, A10-13. A10-14, listed there under 10b, is applied here, where case R-SHELL-FOCUS.2/4 lives. §6 N-2 is taken by D-9 (R-TUI-018.3); N-3 is answered by E3 S-1 in 10b.

- **D-7 — after a primary unload the spine is a MAC-only load's (S-2).** `_unload_primary` sets `path` to the MAC file and `errors` to the MAC's own diagnostics (A10-07); `mem_map`, rows and ranges stay empty (AC-2 of `tests/test_unload_feature.py`). A snapshot with MAC records but no MAC file has no file to name and unloads to `None`, as a primary without a MAC does; no product route builds that shape (`_load_mac_file` sets both, `app.py:16948-16960`). Save project then plans what a fresh MAC-only session plans (`_plan_project_save` unchanged). Alternative not taken: refuse or skip the image in the save plan for a `mac` spine — the old path would stay in every other reader (the load question, the Loaded panel, `#status_context`).
- **D-8 — the focus landing after a window switch (A10-01 = S-4).** Per the ruling: one landing after the layout (`call_after_refresh`), which moves the focus only if it has not moved since the trigger, is `None`, or needs re-homing; it reads the shown window when it runs, so a later key wins. S-4's residual (keys typed before that refresh reach the widget left in the hidden window) is closed in the same call: when the focused widget sits in a window the switch just hid (an ancestor test on the `hidden` class, valid before any layout), `action_show_screen` clears the focus at once (`screen.set_focus(None)`); single keys reach the app bindings until the landing. Alternative (S-4's own): focus the declared target synchronously and re-run the fallback after the refresh — the focus would sit for a refresh on a widget with no region, the shape `_focus_needs_rehome` calls stale. The unload uses the same landing with the removal rule of R-SHELL-FOCUS.3 (the trigger widget is no longer attached).
- **D-9 — one start index, counted in view rows (A10-03).** `s19_app/render/hexview.py` gains `hex_row_bases`, the row list `_collect_hex_rows` already builds; the app's start indices, page bounds and first visible rows count in that list. The target row stays a present row (R-TUI-018.3); a jump starts one view row above it (R-TUI-018.1), or at it when it is the first view row (R-TUI-018.4). Alternative (A10-03's second option): narrow R-TUI-018.1 to present targets without MAC-added rows and send N-2 to the backlog — not taken, because R-TUI-004.3 and R-TUI-007.8 already put MAC-added rows in the three views and in the pages.
- **D-10 — one clamp for both render paths (A10-02).** `_hex_window_start` is clamped to `[0, len(view rows) − 1]` with or without a focus; the page floor leaves the render. Paging stays page-aligned from a page-aligned start (R-TUI-007.3/2).
- **D-11 — a hidden Split / Join refuses its own keys (S-3).** `SplitJoinWindow.check_action` returns `False` while the window has `hidden`; the key falls through to the app's bindings and the window's action never runs. A second layer behind the focus rows; the Patch Editor arm of S-3 is closed by D-8 (R-SHELL-FOCUS.2/6).
- **D-12 — the file status is scrubbed of Cc, Cf, Zl and Zp at its one writer (S-5).** `set_file_status` removes those categories (the filter `painted_names` applies, without its clip) before `safe_text`, so the load, unload and project-load arms are all covered. The Loaded panel, the save line and the log stay on the backlog (S-6). The composer's own `painted_names` (#14) is kept: it clips names to 120 characters (A10-06) and keeps the message line clean.
- **A10-11 census.** 69 test files call `action_show_screen` (406 calls); 17 read the focus after a switch. All 69 run at E4 integration, not only at batch end, and E4 lists the bodies that change (`E1-slice.md` §5).

## 8. E3 addendum — Inc 12 D-2 (2026-11-06, before E4)

Ruling: `E3-rulings.md`, addendum "Inc 12 D-2". Checked on `98d94d7` and main `2d1e2b1`: `_jump_to_validation_issue` has no caller, and `_jump_to_validation_issue_object` has one caller, that adapter; `on_issue_row_selected` (Enter on an issue row) calls only `_update_issues_hex_pane`.

- **Withdrawn, kept by id:** slice and graph node #11 `_jump_to_validation_issue_object` (unchanged; Inc 12 removes it); cases R-TUI-018.1/5, R-TUI-018.3/1, R-TUI-040.12/2. No requirement row is withdrawn.
- **Re-pointed:** the MAC arm of R-TUI-018.3 goes to the MAC record jump. Enter on a `#mac_records_list` row runs `on_data_table_row_selected` → `_jump_to_mac_address` → `update_mac_hex_view(address, near_top=True, reset_scroll=True)` (`app.py:15886-15888`, `:16314-16316`; same on `2d1e2b1`). That is the render the issue jump would have reached through #4 and #20. The MAC table lists records outside the image (In mem `no`), and case 08's `firmware_issues.mac` holds three of them. New case R-TUI-018.3/3. The A2L arm stays on the tag find (R-TUI-018.3/2).
- **Narrowed:** the main arm of R-TUI-018.3 has no case. Every shipped main-view jump targets a present row: a go-to requires an address in a loaded range (`_apply_goto`), and a search hit, a section start and a Memory Map run start are image bytes (the runs come from per-range entropy windows). The main view still snaps through #20. R-TUI-040.12's threshold drops "issue"; its A2L and MAC arms stay on /5 and /6.
- **Texts:** US-HEXNAV-1 and the *jump* definition drop "issue" (§4). No requirement text named the issue jump.
- **Testers:** windows are switched with the keys or `action_show_screen`, never `action_view_*`, which Inc 12 removes (`02-test-cases.md`, window-switch rule).

## 9. E4 integration (2026-11-06)

Decisions I-D1 … I-D17: `E4-integration-notes.md` §3. Stopped for the orchestrator: I-D7 (below), I-D14 (a load no longer lands the focus on the window's target from a healthy focus: HLR-166 / AT-B100-04 vs R-SHELL-FOCUS.4 / .5 once the P-16 steal is gone), I-D16 (PgDn after `2` scrolls the focused tag table instead of paging: R-TUI-020.1 vs LLR-042.1), I-D17 (a quit confirmed during a held project load crashes at exit: R-SEG-OPEN.6's guard exposes the load chain's late step). What changes for the records here:

- **AR2-5 removed (I-D2).** The `update_hex_view` clause "a load resets `_hex_window_start` and a MAC load/unload re-anchors it by the first shown address" was not built (`E4-impl-notes-app.md` §2); no coverage item of an Inc 10a row requires it, and read literally it contradicts R-TUI-007.8/1 (after the MAC load the first page starts at `0x00001000`, not at the first address shown before it). Removed from the graph node; backlog BL-I10-1.
- **STOPPED for the orchestrator (I-D7):** R-SHELL-FOCUS.4's threshold arm "`files_list` focused, `U` → `files_list`" cannot hold — after `U` nothing is loaded and the empty state hides `#workspace_panes` with `files_list` in it (LLR-002.3, `_apply_empty_state`), so the focus is no longer on a shown widget and R-SHELL-FOCUS.3 / .5 apply (the landing is the Workspace's fallback, measured `window_help_workspace`). Changing the threshold is a requirement change, not the integrator's. Proposed: "`files_list` focused, `[u]` on the MAC slot → `files_list`" (the image stays, so the panes stay shown).

Backlog:

- **BL-I10-1** (AR2-5, I-D2; with D4-14 / R-TUI-007.9): the main hex view's stored window index survives a load and a MAC load or unload. Measured (`../evidence/inc-10/int-06.txt`): after a go-to to row 949 of a 1 000-row image, loading fixture three shows only `0x00008020` under `... showing from 0x00008020 (context preserved) ...` (the index clamped to the last view row, 2); on base `2f54c7d` the page floor gave start 0 and all three rows. The operator notices it: a load after a deep jump into a smaller file shows its last rows only. A MAC load or unload with records outside the image also shifts the window by the MAC-only rows before it (the index counts view rows, I-5). The fix hooks the load tail (`_step_hex`) and the MAC-load install (`_apply_prepared_load`), outside Inc 10a's slice.
- **BL-I10-2** (tester H F-1): at 80 × 24 the Workspace `#hex_scroll` is 1 line high (A2L pane 5 lines, MAC 7, measured at E4), so no jump target can be the second row inside the main pane at the floor size; case R-TUI-018.1/13 runs its main arm at 100 × 30. A layout row of S4 / S6, not Inc 10a's.

## 10. E4 rulings applied (2026-11-07)

Rulings `E4-rulings.md` E4-R1 … R5, applied by the second E4 integrator (`E4-integration-notes.md` §6). What changes for the records here:

- **BL-I10-1 narrowed.** Its load half is fixed in Inc 10a (E4-R1): a load that installs a new image sets `_hex_window_start = 0`, so after a deep jump a smaller file is shown from its first row (R-TUI-007.9, brought in unchanged; case R-TUI-007.9/1). What stays in the backlog: a MAC load or unload with records outside the image shifts the window by the MAC-only rows before it (the index counts view rows, I-5) — AR2-5's re-anchor half, with D4-14.
- **STOPPED for the orchestrator (I-D18):** R-TUI-020.1's MAC arm — PgDn right after `3` scrolls `mac_records_list` instead of paging the MAC View (base pages it); the same mechanism as I-D16, outside E4-R4's A2L-only ruling. The MAC window has no `?` chip, so its switch landing is a new design choice.
