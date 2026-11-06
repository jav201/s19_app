# Inc 10 — E1 rulings (scope, canon changes, decisions)

Base `98d94d7`. Pilot: `evidence-e1/i10e1-pilot-transcript.txt` (LAN Linux host, detached worktree at `origin/main` = `98d94d7`, Textual 8.2.8, `LOCALAPPDATA` and XDG isolated, no clipboard; worktree removed after).

## 1. Scope and what the operator can notice

In: F-07 (D4-2, D4-6), F-13 (D5-17, D5-19, D5-27), F-14 (D17-38, D6-21), SE5-12a-2, Inc 5 ruling D-4 (a) and (b) (reproduced, §3). Out: F-18 (not reproduced, D-3).

No layout changes. What changes on screen: after a jump the target row is the second hex row and the pane is scrolled to its top-left (the window may then hold fewer rows than a page near the image end); a failed go-to removes the `> `; the status line reads `Unloaded …` after an unload; file names in it lose Cf characters; after a rail key, Esc or a rail key in Split / Join the focus ring is on the window's focus target; the A2L Raw / Physical cells and the Split / Join preview follow an in-place write. None of these is among the 37 known-failed UI rows (`p0/known-failed.md`).

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

Rows used with unchanged text: R-TUI-040.4, .8, .11, .12, R-TUI-007.3, .5, R-WS-LOADED.13, .14, .16, R-TUI-012L.8, R-SHELL-FOCUS.2, .5, R-SEG-OPEN.1, .6.

## 5. Decisions

- **D-1 — F-07 by moving the window, not by scrolling inside a page.** Alternatives: (a) keep the page-floored window and scroll the container so the target is the second visible row — needs a laid-out Static, cannot reach rows near the window end, and differs from the A2L/MAC tag jumps; (b) **chosen:** every jump starts the window one row above the target (the near-top path the tag and MAC-record jumps already use) and homes the scroll. Consequence: near the image end the window holds fewer rows than a page; `.` keeps a window that holds the last row (R-TUI-007.5) and otherwise starts after the shown window. R-TUI-018.1 wins over a full last page.
- **D-2 — R-SHELL-FOCUS.2 on every rail key (D6-21), not only on Split / Join's close.** The canon row is unconditional and the base leaves the focus in the hidden window after any rail key (pilot: `ws_load_project_button`, area 0). TC-B97-64 pins "`]` moves no focus" (batch-97 PC-13); its purpose — `c` confirms on arrival — holds with the focus on `fx_panel` (`c` is an app binding). Its two arms change their expected focus; names kept. *Orchestrator: confirm, or narrow Inc 10 to the Split / Join close and the unload (then R-SHELL-FOCUS.2/1, /4, /5 move to the backlog).*
- **D-3 — F-18 closed as not reproduced; no row, no code.** The plan's "new S17 row" would pin behaviour the base already has. The real keyboard issue — `t` cannot leave the manual tab while the box has the focus (Esc closes the window) — is a key-design change: backlog candidate for a UI round, not this increment. The Windows run that produced the guide line cannot be repeated here (operator run rule).
- **D-4 — D-4 (a) by repainting at the write, keeping the anchor.** Alternatives: a byte-write term in the cache key alone (the table paints only on `update_a2l_view`, so nothing would repaint); `update_a2l_view()` (resets the anchor: R-A2L-049). Chosen: invalidate and repaint through the anchor-keeping path (`E1-slice.md` #17). Cost: one enrichment per in-place write (case 08: 462 tags), not per key.
- **D-5 — D5-19's "path" part not taken.** R-WS-LOADED.16 asks for diagnostics and notices; after F-13 the status line no longer shows the path, and no other observable reads a MAC-only spine's `path` (Split / Join has no ranges then). Reported, not changed.
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
- **D-5 → yes.** D5-19's path part is left out: nothing on screen reads the old path after the primary unload. Why: a requirement must be observable.
- **N-1 → backlog.** Enter in the go-to/search boxes runs nothing. Why: outside Inc 10's rows.
