# Inc 10a — E5 code review

Batch 2026-11-01-batch-101, increment 10a (design-first flow). Reviewer: code-reviewer, independent of the implementers (DeepSeek v4 Pro, groups G1–G3), the testers (H, F) and the three E4 integrators. Scope: `git diff 09b4808 -- s19_app` and `git diff 09b4808 -- tests` at head `54a0eb2` of branch `b101-inc10` (worktree `<HOME>/Github/s19_app-b101-inc10`; `09b4808` is merged in). That is 3 source files (`s19_app/tui/app.py` +539/−112 incl. docstrings, `s19_app/tui/segment_split_view.py` +38, `s19_app/render/hexview.py` +74), 2 new test files (`tests/test_b101_hex_jump.py`, `tests/test_b101_unload_focus.py`) and 5 edited test files. I read all of it in full against `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc10.md` (I-1 … I-6, `_FOCUS_TARGETS`, `_SWITCH_LANDING_TARGETS`), `E3-rulings.md`, `E4-rulings.md` (E4-R1 … R6) and `E4-integration-notes.md` (I-D1 … I-D27, §6, §7). I read the helpers the change relies on: `_snapped_focus_row_index`, `_focus_needs_rehome`, `_fallback_focus_target`, `_resolve_focus_target`, `_rehome_focus_after_load`, `_apply_goto`, `_jump_to_mac_address`, `watch_current_file`, `action_open_split_join_export`, `_reset_session_state`, `_session_snapshot`, `render_hex_view_text` / `_collect_hex_rows`, `painted_names`, `_SegTable`, and Textual 8.2.8's `App.default_screen`, `MessagePump.is_attached`, `App._check_bindings` / `run_action` and `Button.BINDINGS` (source read only).

I ran nothing that imports `s19_app` (operator rule). Every statement about a run comes from the integrators' transcripts `evidence/inc-10/int-01` … `int-23`. To tie them to this head: the merge `f92fa41..54a0eb2` changes none of the increment's 9 product and test files except `tests/test_id_registry.py`, whose merge resolution keeps the value 272 that int-21/int-22 measured and words its comment differently from the run clone's (int-20-setup: the clone's blob `4729d88e`, HEAD's `11b15150`); so a temporary-index rebuild of `09b4808` + HEAD's diff gives tree `6fc60136…`, not int-21's `ba8da175…`, and the difference is that comment only. The other 9 blobs equal the ones int-20-setup staged (its "equal" lines against `f92fa41`, which the merge leaves untouched). Untracked `.mut_apply_tmp.py` / `.mut_check_tmp.py` in this folder are not mine and were not touched.

Severity is this reviewer's rubric (HIGH = correctness bug or a test that gives false confidence; MEDIUM = maintenance cost, duplication, convention break or a weak test; LOW = minor). In the house's HIGH · MAJOR · MINOR scale every finding below is MINOR.

## Verdict

**PASS-WITH-NOTES.** No HIGH finding. The product code honours I-2 … I-6 and the E4 rulings R1 … R6 as ruled; the hex window, the view rows, the landing, the unload state and the hidden-window guards are correct on every active row. Nothing leaks (no timer, no descriptor; every re-schedule is bounded by `layout_waits = 3`). Nine recommendations:

- CR-1 (MEDIUM): `_hex_view_rows`' memo has an unwritten invalidation contract, is not declared in `__init__`, keeps the old image's row list after a project reset, and is not shared with the renderer as the graph says.
- CR-2 (MEDIUM): six copies of the A2L / MAC failed-go-to re-render block, each scanning the view rows twice linearly.
- CR-3 (LOW): the unload landing is not stamped with a window, so `[u]` then `2` / `3` in one burst lands on the table and PgDn scrolls it.
- CR-4 (LOW): I-D23 — Enter right after `3` now pages back silently; acceptable, the one switch landing whose Enter changes view state.
- CR-5 (LOW): `_SegTable`'s own up/down/j/k still run the hidden window's cursor action.
- CR-6 (LOW): R-WS-LOADED.16/1 accepts a missing loader-facts line.
- CR-7 (LOW): two hold/no-op checks rest on fixed settle counts.
- CR-8 (LOW): with no image rows (a MAC-only spine), a MAC record jump still centres with 64 context rows.
- CR-9 (LOW): stale comments and docstrings.

## Checks

| # | Check | Result | Evidence state |
|---|---|---|---|
| 1 | Hex window: reset on image install only (E4-R1) | `_apply_prepared_load` sets `_hex_window_start = 0` only when `loaded.mem_map is not previous_map` (`app.py:18890-18891`), the same test the change service and Inc 6 use (`:18800`, `:18865`); `previous_map` is `None` after a reset or unload-all, so a first or project load resets. The reset sits after `current_file = loaded` and before any hex render (`watch_current_file` renders no hex view; `_step_hex` is the first). A MAC / A2L attach keeps the dict and the index (BL-I10-1, as ruled). | executed (read) |
| 2 | Clamp `[0, len(rows)−1]` | One clamp in `update_hex_view` (`:19973`); empty rows give `max(0, min(s, −1)) = 0`. Paging: `start + page < total` else stay (`:11323`), `total` from the view rows; PgUp unchanged `max(0, s − page)`. `_first_visible_hex_address("main")` bounds-checks the index against the view rows. A2L / MAC `start_row` clamped likewise (`:20081-20084`, `:20135-20138`). | executed (read) |
| 3 | `hex_row_bases` / `_collect_hex_rows` with extra addresses | Moved verbatim (`hexview.py:148-201`, `:247`): no extra → the given object; every extra row present → the given object; else `sorted(existing ∪ extra_rows)`. The one nuance (a non-list input no longer wrapped in `list`) changes no output (`E4-integration-notes.md` §2, G3). `_row_start_for_near_top_focus` snaps on the present rows and bisects that present row into the view rows (it exists there, so `j` is exact). | executed (read) |
| 4 | Rows cache invalidation | Key `(_image_generation, frozenset(MAC set))`; every install bumps the generation (`:18819`); `_apply_unload` resets the memo (`:17968`); the only three writers of `current_file` are the reset (→ `None`), the unload and the install (grep), and nothing mutates `row_bases` / `mac_records` in place (grep). Correct today; contract undocumented and reset path missing — CR-1. | executed (read, grep) |
| 5 | Focus landing (I-4) | `_land_focus` (`:10775-10877`): stale `switch` returns (`:10827`); waits while the shown container has area 0, at most 3 re-schedules (I-D3); reads `default_screen.focused` (Textual 8.2.8: the compose screen after mount, so a dialog's focus is never judged); the four move conditions as AR2-1; `_SWITCH_LANDING_TARGETS` only when `on_switch` (`:10861`), shown and focusable, else `_resolve_focus_target()`; `_note_focus_landing` after `set_focus`. `action_show_screen` reads "changed" before the swap (`:10078`), clears a focus in a now-hidden window synchronously (`:10127-10136`) and schedules only on a change (`:10137`). Load / unload targets stay `_FOCUS_TARGETS` (I-D21). Gap: CR-3. | executed (read) |
| 6 | Fallback record and the load re-home (E4-R3) | `_note_focus_landing` clears the record on the declared target, else keeps the widget; `_rehome_placeholder_focus_after_load` (`:10695-10761`) moves only a `RailItem` focus or the recorded widget (`:10744`), only to `_FOCUS_TARGETS[switch]`, only when shown; a later call for another window returns; re-checks are bounded (3) and guarded by `_load_tree_gone`. Called after `_rehome_focus_after_load` in both completed-load tails (`:19029`, `:16495`). The Map row hook still runs after the tail. | executed (read) |
| 7 | `_load_tree_gone()` in the deferred load steps (E4-R5) | All four steps return at their first line (`:18973`, `:18988`, `:19002`, `:19017`), before the `try` whose `finally` schedules the next step, so a gone tree schedules nothing further; E4-R3's re-check is guarded too (`:10732`). The condition is Textual's own (`is_attached` is False once `app._exit` is set); `default_screen` raises only before mount, where `False` keeps the headless chain test driving the steps. No step can act after exit. | executed (read; Textual source) |
| 8 | Split / Join while hidden (I-2, I-6, SR2-1) | `refresh_window` focuses `#sje_table` only without `hidden` (`segment_split_view.py:1746`); the open action un-hides before calling it. `check_action` returns `False` while hidden (`:1768`); Textual's `run_action` then returns `False` and the binding search continues to the app (read in `textual/app.py`). `action_export` returns at once while hidden (`:2086`), covering Enter / click on `#sje_export` and the `e` key. `_SegTable`'s own bindings bypass the window's check — CR-5 (non-destructive). | executed (read) |
| 9 | Unload state and status texts | `U` with nothing (no file, no A2L) → `Nothing to unload.` with the file status untouched (`:17936`); A2L-only `U` proceeds. `set_file_status(f"Unloaded {label}.")` then the unchanged `set_status` (`:18025`): one message line. `_unload_primary` keys on `mac_path` (`:1882`) and sets `path = mac_path` and `errors` from `mac_diagnostics` in the MAC-only shape. `_format_coexistence_status` paints both names through `painted_names` (`:19071`); `set_file_status` scrubs Cc / Cf / Zl / Zp with no clip (`:21702`). | executed (read) |
| 10 | Descriptor / timer leaks | No `open`, `set_timer` or `set_interval` added; the re-scheduling `call_after_refresh` loops of `_land_focus` and `_rehome_placeholder_focus_after_load` are bounded by `layout_waits`. `_focus_landing_fallback` holds one widget reference (identity only; a removed widget never matches). | executed (read) |
| 11 | Each I-n | I-1: moved to 10b, n/a. I-2, I-6, SR2-1: check 8. I-3: signatures (`*, start_row`), `start_row` wins over `near_top`, marker clear for a non-`None` differing focus, first visible = `rows[effective start]` (`:20095`, `:20149`), `update_hex_view()` keeps window (clamped), marker and scroll — honoured, except an image-less MAC view (CR-8). I-4: check 5. I-5: `hex_row_bases` signature and identity return honoured; `_hex_view_rows` built and memoised, but the render does not share it (CR-1). | executed (read) |
| 12 | I-D23 (Enter after `3` presses Page Prev) | Judged in CR-4: low user impact, not blocking; better than base (Enter pressed the hidden Workspace's Load Project button) and than the pre-E4-R6 tree for paging; worse than it for Enter and arrows. | executed (read) |
| 13 | Tests: oracles, base RED, can they fail | Both new files read in full. Oracles are painted text, scroll offsets, regions, focus ids, status lines and files on disk, each after the action's own sign. The I-D27 vacuous /2/7 is fixed (the scenario runs). Weak points: CR-6, CR-7. AR2-2's stale-switch return has no node that can fail (M23 "may survive", correctly predicted: a stale landing re-resolves the target from `_active_screen_key` at run time, so it lands where the fresh one would) — the guard is defensive, not a gap. | executed (read) |
| 14 | Edited existing nodes | TC-008 (`test_tui_commandbar.py`): "focus unchanged by `/`" is as strong as the old "no focus" once a landing exists; the three owning screens still assert their own input. TC-B97-64: named supersession, `c` still confirms 1. `hidden_map_row_is_rehomed`: the stale row is now put back by hand (D-8 closes the product route) and the precondition is asserted. `_CENSUS_AT_12B_BASE` + 2 names with reasons; `EXPECTED_SCANNED_TEST_FILES` 272 measured. No assertion weakened. | executed (read) |
| 15 | Reuse, simplicity, conventions | `hex_row_bases` is an extraction, not a copy; `painted_names` reused for the status scrub (indirect but ruled, D-12); `_SWITCH_LANDING_TARGETS` follows `_FOCUS_TARGETS`' style. Duplication: CR-2. Docstrings: CR-1, CR-9. Type hints present and consistent. | executed (read) |
| 16 | Mutant table (M1 … M30, M-R*) | Not run by me; E5's runner. M-L, M-P, M-W, M-R, M-R1, M-R3 … M-R6 ran at E4 (int-08, int-18, int-20). | not-run |

## Findings

### CR-1 — `_hex_view_rows`' memo: unwritten invalidation contract, undeclared attribute, retained rows after a reset, not shared with the render  [MEDIUM · impl (maintainability)]
- **Where:** `app.py:19941-19957` (`_hex_view_rows`), `:17968` (the unload reset), `:14199` (`_reset_session_state` S1: `current_file = None`, no cache reset), `__init__` (`:2838-2846`: the attribute is never declared; `_hex_view_rows` reads it with `getattr(..., None)`).
- **Scenario:**
  - The memo is correct only because every replacement of `current_file` either bumps `_image_generation` (install) or resets the memo by hand (unload). Nothing states that rule. A future writer that replaces `current_file` without a bump (e.g. a variant swap or a primary rebuild done with `replace(...)` outside `_apply_prepared_load`) gets the previous image's view rows: paging, the clamp and every start index then count the wrong list.
  - A project load-over runs `_reset_session_state` (`current_file = None`) and keeps the cache. If the project's install then fails, the old image's whole `row_bases` list (the same object on the no-MAC path) stays referenced by the cache until the next successful load; for a multi-million-row image that is the largest structure the app holds.
  - The graph (I-5 / node `_hex_view_rows`) says the list is "shared by the paging, the render and the first-visible reads". The render is not given it: `render_hex_view_text` is still called with `row_bases`, the MAC set and `bases_set` and rebuilds the same list through `hex_row_bases`. Start indices computed on one list index the other; they agree only because both are built from identical inputs. (The per-render sort when a MAC row lies outside the image is pre-existing, as the integrator noted.)
  - The docstring "memoised per render" is wrong (it is memoised per image generation and MAC set) and too short for a helper reused by 10 callers that carries a cache contract (`PROJECT_RULES.md` private-helper policy).
- **Fix:** declare `self._hex_view_rows_cache: Optional[Tuple[Tuple[int, FrozenSet[int]], List[int]]] = None` in `__init__` with a one-line comment, beside `_focus_landing_fallback`; reset it in `_reset_session_state` next to `self.current_file = None`; give `_hex_view_rows` the full docstring, stating the key and the rule "a writer of `current_file` that does not bump `_image_generation` must reset `_hex_view_rows_cache`". Either correct the graph's "shared by the render" or pass the view rows to the renderer (a `view_rows=` parameter of `render_hex_view_text`, in an Inc 10a file).

### CR-2 — the failed-go-to re-render is written six times, with two linear scans each  [MEDIUM · simplicity]
- **Where:** `app.py:21566-21600` (`_handle_goto_alt`, three branches) and `:21640-21674` (`_handle_goto_mac`, three branches); the main handler's three `if marker: clear; update_hex_view()` blocks (`:21507-21523`).
- **Scenario:** each failure branch runs `x in rows` and then `rows.index(x)` over the sorted view rows — two O(n) scans per failed go-to (26 546 rows on case 08; millions on the large images the hot path is written for). The six blocks differ only in two names; a fix to one (say the index lookup) has to be made six times, and Inc 10b relies on the same "painted first row" field.
- **Fix:** one helper per view pair, e.g.
  ```python
  def _drop_marker_keeping_window(self, view: str) -> None:
      if view == "alt":
          if self._alt_goto_focus_address is None:
              return
          self._alt_goto_focus_address = None
          first, render = self._alt_first_visible_address, self.update_alt_hex_view
      else:
          if self._mac_goto_focus_address is None:
              return
          self._mac_goto_focus_address = None
          first, render = self._mac_first_visible_address, self.update_mac_hex_view
      rows = self._hex_view_rows()
      start = bisect_left(rows, first) if first is not None else 0
      render(start_row=start)
  ```
  and call it from the three failure branches of both handlers (the main handler can keep its three-line form or get the same helper). `bisect_left` on a value present in the sorted list is its index; on an absent one it is the next row, which the clamp bounds.

### CR-3 — an unload landing is not stamped, so `[u]` then `2` / `3` in one burst lands on the table  [LOW · impl]
- **Where:** `app.py:18027` (`call_after_refresh(self._land_focus, trigger, None, on_switch=False)`); `_land_focus` `:10827` (only a non-`None` `switch` can be stale).
- **Scenario:** case 08 S19 + A2L + MAC; the focus on the MAC slot's `[u]`; Enter, then `2` while the unload is still rendering (it re-renders three hex views, the A2L view and the map synchronously, so the key is queued before the next refresh). The prune moves the focus to the Workspace chip; `2` clears it (the Workspace is now hidden) and schedules the switch landing. At the next refresh the unload landing runs first (FIFO): `focused is None` → move → `on_switch` is False, so `_resolve_focus_target()` → `a2l_tags_list`. The switch landing then sees a healthy focus that is not its trigger and keeps it. PgDn now scrolls the tag table instead of paging the A2L Explorer — the R-TUI-020.1 regression E4-R4 / R6 removed, back in a burst. Same for `3` (`mac_records_list`). No case covers a burst after an unload.
- **Fix:** stamp the unload landing with the window shown when it is scheduled: `self.call_after_refresh(self._land_focus, trigger, self._active_screen_key, on_switch=False)`. A switch that follows makes it stale and the switch landing decides; without a switch nothing changes. Graph I-4 and node `_apply_unload` say `switch = None`, so this needs a one-line ruling.

### CR-4 — I-D23: Enter right after `3` now presses Page Prev  [LOW · UX trade-off, within E4-R6]
- **Where:** `app.py:9960-9963` (`"mac": "mac_page_prev_button"`); `action_mac_records_page_prev` (`:11444-11470`).
- **Scenario and impact:**
  - On page 1 Enter after `3` does nothing and says nothing (it reads as a dead key); on page N > 1 it silently pages back one page, a state change the operator did not ask for (reversible with `+` / PgDn).
  - The arrows no longer move the record cursor after `3` (a `Button` binds Enter only, and the app binds no arrows there); reaching the table takes three Tabs (Page Prev → Page Next → Legend → table) or a click.
  - Compared with base this is an improvement: base's Enter after `3` pressed the hidden Workspace's `Load Project` button. Compared with the tree before E4-R6, paging is fixed and Enter / arrows are worse. The A2L switch landing (`?` chip) has the same arrow cost, but its Enter opens help, which changes no view state; Page Prev is the only switch landing whose Enter mutates the view.
  - Verdict: acceptable, not blocking. A later load moves the recorded landing to the table (E4-R3), as I-D21 records for A2L.
- **Fix (operator / UX call):** keep it and name it in CTX-SHELL's MAC line (I-D26, still unruled), or land on `mac_legend_button` (Enter opens a modal and changes nothing, like the A2L chip; PgDn / PgUp / `+` / `-` still reach the app). Worth a `ux-reviewer` look before the canon fold.

### CR-5 — the hidden window's cursor keys still run through `_SegTable`'s own bindings  [LOW · impl / record]
- **Where:** `segment_split_view.py:1238-1249` (`_SegTable.BINDINGS` up / down / k / j → `action_cursor_move` → `SplitJoinWindow.action_move`); `check_action`'s docstring `:1753-1758` ("… Esc, the arrows").
- **Scenario:** the focus on `#sje_table` while the window is hidden (R-SEG-OPEN.7/3's forced shape). Up / down / j / k resolve in the table's namespace, whose `check_action` is the default `True`, so the hidden window's cursor moves. Nothing is written (the only writer is `action_export`, guarded), but R-SEG-OPEN.7 reads "run no action of the window's keys" and the docstring claims the arrows are refused. D-8 and I-2 keep the focus out of the hidden window on every product route, so only a forced focus reaches it.
- **Fix:** `_SegTable.action_cursor_move` returns when its `SplitJoinWindow` ancestor has `hidden` (two lines), or narrow the docstring and record the residual.

### CR-6 — R-WS-LOADED.16/1 accepts a missing loader-facts line  [LOW · test]
- **Where:** `tests/test_b101_unload_focus.py:543` (`loader_error_count(app) in (0, -1)`); case `02-test-cases.md:64` ("`Loader 0 err` or absent").
- **Scenario:** `-1` means the `Loader N err` text is not painted. After a primary unload with a MAC the spine is MAC-only, and a MAC-only session paints the line (/16/3's reference reads 2). A change that stops painting the loader facts after the unload — exactly the line this row's threshold names — passes /16/1. /16/3 would catch it, but only with `firmware_issues.mac`.
- **Fix:** assert `loader_error_count(app) == 0` and drop "or absent" from the case.

### CR-7 — two hold / no-op checks rest on fixed settle counts  [LOW · test]
- **Where:** `tests/test_b101_hex_jump.py:1100-1104` (R-TUI-007.5/1: three `.` presses, each asserted at once); `tests/test_b101_unload_focus.py:1253-1254` (R-SHELL-FOCUS.4/2: `settle(pilot, 10)`, then `wait_focus` on the focus that already held before `U`).
- **Scenario:** in /7.5/1 a `.` that never reached the app's binding (say a future focus route leaves an `Input` focused after `goto()`'s Tab) looks exactly like a `.` that kept the window; M-P shows the node can fail today, but nothing pins why. In /4/2 the wait passes at once whether or not the unload landing has run; only the ten pauses make the landing run first. M25 is the row's mutant and has not been run.
- **Fix:** /7.5/1: before the presses, `assert not isinstance(app.default_screen.focused, (Input, TextArea))` (the precondition that makes a no-op meaningful). /4/2: wrap `S19TuiApp._land_focus` in a counting spy and wait until it has run once (the /6/2 recorder pattern), then assert the focus. Run M25 at E5.

### CR-8 — with no present rows, a MAC record jump still centres with 64 context rows  [LOW · impl / requirement gap]
- **Where:** `app.py:19997-20012` (`_row_start_for_near_top_focus` → `_snapped_focus_row_index(addr, [])` → `None`); `_jump_to_mac_address` `:17026`; `update_mac_hex_view` `:20149`.
- **Scenario:** a MAC-only session, or S19 + MAC after `[u]` on the primary (Inc 10a now makes that a clean MAC-only spine). The MAC view paints the MAC rows; Enter on record 150 of 200 calls `update_mac_hex_view(addr, near_top=True)`, which gets no start index, so the renderer centres with 64 context rows (the target is the 65th row), while `_mac_first_visible_address` records `rows[0]`, not the painted first row (I-3's claim). R-TUI-018.1 ("the MAC hex view … second row") is not met there; R-TUI-018.3's CTX-HEX target is undefined without present rows, and no case covers it. No consumer misbehaves today (`_apply_goto` and the search always miss on an empty image).
- **Fix:** when `row_bases` is empty, bisect the focus row base into `view_rows` (`max(0, bisect_left(view_rows, addr − addr % 16) − 1)`), or record the gap in the backlog with a ruling on what R-TUI-018.1 means without an image.

### CR-9 — stale comments and thin docstrings  [LOW · impl (doc)]
- **Where and what:**
  - `app.py:19023-19025` (`_step_finalize`) and `:10620-10623` (`_rehome_focus_after_load`'s docstring) still say `watch_current_file` re-focuses the Split / Join table on every install; I-2 removed that.
  - `:10722-10723`: `_rehome_placeholder_focus_after_load` re-schedules "only while the focus has not moved"; it re-checks "still a rail item or the recorded fallback", which is not the same.
  - `segment_split_view.py:1753-1758`: see CR-5.
  - `hexview.py:186-188`: the example output `[0x1000, 0x8000, …]` is not what the interpreter prints (`[4096, 32768, …]`); doctests are not run, so it misleads only the reader.
  - `app.py:10688`, `:10763`: `_note_focus_landing` (three callers, encodes the declared-vs-fallback rule) and `_load_tree_gone` have one-paragraph docstrings without Data Flow / Dependencies.
- **Fix:** update the texts; give `_note_focus_landing` the house sections.

## Carried, not findings

- AR2-2's stale-switch return is unobservable in the burst: the stale landing reads `_active_screen_key` at run time and, with I-D3's layout wait, lands where the fresh one would. M23 "may survive" is right; the guard is kept as defence.
- MAC attach / unload keeps `_hex_window_start` as an index while the MAC rows outside the image shift the list (BL-I10-1, ruled).
- `action_hex_page_next` still returns when `row_bases` is empty, so a MAC-only main view does not page (base behaviour; outside the slice).
- A rail item the operator tabbed onto is moved by a completing load (E4-R3 and its amended R-SHELL-FOCUS.4 text, ruled; I-D20's edge).
- The renderer's per-render sorted union when a MAC row lies outside the image is pre-existing (CR-1 only notes the graph text).

## Evidence states

- Checks 1–15: `executed` by reading and grep (product, tests, Textual 8.2.8 source); the runs cited are the integrators' (int-01 … int-23), not mine.
- Tree tie-in (temporary index, `git write-tree`; no working-tree change): `executed`.
- CR-1 … CR-9: `executed` (read). Their fixes: `planned`. CR-3's and CR-8's scenarios: `executed` by reading only, not reproduced (`not-run` as probes, operator rule on this PC).
- Mutant table: `not-run` by me.

## Evidence checklist

- [x] Diff read in full: `git diff 09b4808 -- s19_app` (`app.py` all hunks, `segment_split_view.py:1740-1771`, `:2079-2090`, `hexview.py:145-247`) and `git diff 09b4808 -- tests` (both new files 1–1168 and 1–1544; the five edited files' hunks).
- [x] Correctness pass: empty rows, MAC-only spine (CR-8), deferred steps after exit, stale and burst landings (CR-3), dialog focus, removed trigger, hidden-window bindings (CR-5).
- [x] Simplicity pass: CR-2; no speculative parameters (`layout_waits` is used by the re-schedule).
- [x] Reuse / duplication: `hex_row_bases` extracted, `painted_names` and `_resolve_focus_target` reused; CR-2.
- [x] Tests reviewed for intent: oracles painted, negatives after positive waits, I-D27 fixed; CR-6, CR-7.
- [x] Verdict explicit: PASS-WITH-NOTES. No HIGH is open.

## §4b Independent review cell

`code-reviewer · PASS-WITH-NOTES · no HIGH (none to resolve); I-2…I-6 and E4-R1…R6 honoured (reset on image install only, one [0,len−1] clamp, view-row paging, landing waits/stale/switch targets, fallback record + load re-home, all four deferred steps guarded by _load_tree_gone, hidden Split/Join keys and EXPORT refused, unload texts); no leaks; open as recommendations: CR-1 MEDIUM _hex_view_rows memo contract/declaration/reset/render-sharing, CR-2 MEDIUM six duplicated failed-go-to blocks with double linear scans, CR-3 LOW unstamped unload landing loses the switch landing in a [u]+2/3 burst, CR-4 LOW I-D23 Enter after 3 pages back silently (acceptable; Legend alternative), CR-5 LOW _SegTable cursor keys bypass the hidden check, CR-6 LOW 16/1 accepts a missing loader line, CR-7 LOW 7.5/1 and 4/2 rest on settle counts, CR-8 LOW image-less MAC jump still centres, CR-9 LOW stale comments`

## Re-review of the corrective (code + security)

Reviewer: code-reviewer, with the security lens on the changed items; independent of the corrective's author (Opus).

**Scope:** `git diff 10deda9 d317138 -- s19_app tests` (head `d317138`, branch `b101-inc10`, worktree `<HOME>/Github/s19_app-b101-inc10`) and the records it changed. Read against `E5-rulings.md` and its addendum (`E5-corrective-notes.md` §1–§4, E-1 … E-16), `E5-security.md`, `E5-coverage-audit.md` and `E5-mutants.md`.

**Read in full:**
- the product hunks (`app.py`, `segment_split_view.py`), the test hunks (`test_b101_hex_jump.py`, `test_b101_unload_focus.py`) and the graph hunks;
- the callers and callees the changes rely on: `_save_as_source_for`, `_prepare_project_save`, the copy and variant steps of `_commit_project_save`, `_plan_copies`, `inventory_project_tree`, `_unload_primary`, `_unload_mac`, `_apply_unload`, `_reset_project_session`, `update_alt_hex_view`, `update_mac_hex_view`, `_land_focus`, `_fallback_focus_target`, `_load_tree_gone` and every `action_show_screen` caller;
- Textual 8.2.8's binding dispatch (source only).

**Transcripts read:** `e5c-05`, `-06`, `-08` … `-16`, `mut-c-01` … `-14`, `-22`, `-23`, `mut-c-mutations.py.txt`.

**Tree tie-in** (git plumbing on a scratch index; the working tree is untouched):
- `09b4808` + `git diff 09b4808 d317138 -- s19_app tests docs README.md` gives tree `6cb142f1…`. That is the tree of `e5c-11` … `e5c-16` and of every `mut-c-NN` copy.
- The worktree's tracked `s19_app/` and `tests/` are clean.
- Nothing that imports `s19_app` ran on this PC. The one probe below execs extracted source text only.

### Verdict

**FAIL**, on one MEDIUM finding (RR-1). No HIGH is open, so this is not `BLOCK-UNTIL`. HIGH 0 · MEDIUM 1 · LOW 2.

- **SE5-1 is met for the MAC remainder only.** After a primary unload, the file left loaded is either a MAC spine (`file_type == "mac"`, covered) or nothing, because `_unload_primary` returns `None` when there is no MAC. In the second case an A2L can stay loaded, and a save as still carries the unloaded image; loading the new project installs it (RR-1).
- **Every other item is met as ruled:** SE5-2, SE5-5, CR-1, CR-2 (same behaviour on every reachable state), CR-3, CR-6, CR-7, QA-3, QA-4. M23 and M28 now die. My own reading supports the M-L judgement.
- **CR-9 is not done:** the pass read the ruling as "accept" (E-1). RR-3 lists what remains, for the close step.
- **No new defect** in the changed code, on the exit paths or between Windows and POSIX.
- **How it closes:** RR-1's fix plus case R-WS-LOADED.19/5, RED then GREEN. Or a ruling narrows SE5-1 to R-WS-LOADED.19's MAC state and moves the A2L-only route to the backlog; this lens is then PASS-WITH-NOTES.

### Rulings, as ruled

Line numbers are those of `d317138`.

- **SE5-1: partly met (RR-1).**
  - **Where the filter runs.** The filter (`app.py:13758-13771`) applies to a save as only: `walked` is set only when `_save_as_source_for` returns a source (`:13749-13756`).
  - **Every save route reaches it.** `action_save_project` → the Save dialog → `_prepare_project_save` → the single `_plan_project_save` call (`:12185`). The preview, the confirm and the dismiss all go through that call.
  - **Same suffix rule as `_plan_copies`.** `splitext(...)[1].lower()` (`project_gather_service.py:1493`) over `PROJECT_PRIMARY_DATA_EXTENSIONS` = `.s19 .srec .hex .ihex` (`workspace.py:126-132`).
  - **Only the filtered copy reaches the planner** (`:13918`). The session's cached inventory is not mutated: `replace` builds a new object.
  - **Preview, copy and manifest agree.** The commit copies `plan.copies` (`:12679`, `:12737-12739`) and rebuilds the variants from what is on disk (`:12932-12936`).
  - **A loaded S19 / HEX is never filtered** (`file_type` `s19` or `hex`). /19/4 is GREEN, and stays GREEN under `mut-c-01`; /19/3 is RED under `mut-c-01`.
  - **The /19/3 reload clause can fail.** It waits for `Loaded project 'P9'` (`unload_and_open`), so a P9 that fails to load cannot pass.
  - **File types left after a primary unload:** `mac` is covered; nothing, with or without an A2L, is not (RR-1).
- **SE5-2: met.**
  - /7/3 reopens the window and reads `#sje_stats` (F:1695).
  - `mut-c-04` (= M28) is RED with `4 files · 414.8 KiB data …`. This also proves that reopening keeps the selection, so the clause can fail.
- **SE5-5: met.**
  - `_land_focus` returns at its first line (`:10841-10842`); a re-scheduled wait hits the same guard.
  - In `_fallback_focus_target`, `query_one(Rail)` sits in a `try` (`:10575-10580`). `except Exception` matches the module's other teardown guards.
  - /3/3 is RED under `mut-c-03` (`the landing after exit focused ['files_list']`).
  - Both deferred focus callbacks are now guarded: this one and `_rehome_placeholder_focus_after_load` (`:10742`).
- **CR-1: met.**
  - Declared in `__init__` (`:2847-2851`); the invalidation rule is written in the docstring (`:19999-20005`).
  - Reset in `_reset_project_session` (`:14236`). The ruling's `_reset_session_state` was my naming error at E5: `_reset_project_session` is the one reset seam, and `_handle_load_project` is its only caller.
  - The unload reset is kept (`:18005`).
  - `current_file` has three writers: the reset, the unload and the install (`:14233`, `:18004`, `:18837`; grep). Nothing mutates `row_bases` or `mac_records` in place (grep).
  - The docstring's Used-by list matches the six call sites.
  - The graph text is corrected, and E-2 (not shared with the renderer) gives its reasons.
  - `mut-c-12` is RED on both nodes.
- **CR-2: met; behaviour is the same on every reachable state.**
  - The helper is `:21706-21745`. The six call sites (`:21642`, `:21648`, `:21651`, `:21692`, `:21698`, `:21701`) each call it after the same status line.
  - **Present** first visible row: the same index. The view rows are sorted and unique, because `hex_row_bases` returns `row_bases` or a sorted union.
  - **`None`**, and **no rows** (`bisect_left([], x)`): 0 in both versions.
  - **Empty box**, **invalid** and **miss** (a miss below or above the image): the same call after the same status.
  - **Absent** first visible row: the result differs (the next row instead of 0), but no path reaches this state:
    - each render sets the field to `rows[effective_start]` (`:20171`, `:20225`);
    - the view rows change only on an install, which bumps the generation and clears both markers (`:18937-18938`), or on an unload, which re-renders the three views (`:18055-18057`);
    - `_collect_mac_highlight_addresses` reads only the file.
  - **M8 split:** `mut-c-05` … `-10` each give `1 failed, 7 passed`, each on its own arm. **M9b:** `mut-c-11` is RED on 040.8/2 and /3.
  - The local `from bisect import bisect_left` follows the form already used at `:19974` and `:20083`.
- **CR-3: met.**
  - The stamp is at `:18064-18068`.
  - `[u]` exists only on the Workspace's Loaded panel (the `_apply_unload` callers are `:18161` and `:18188`), so a single-artifact unload is always stamped `workspace`.
  - `U` pressed from another window leaves nothing to page, so no switch landing is lost there.
  - `mut-c-02` and `mut-c-13` are RED on both /2/8 ids.
  - The /2/8 entry point (direct calls with no await between them) is named in the case (E-6).
- **CR-6, CR-7, QA-3, QA-4: met.**
  - **/16/1:** asserts `== 0` (F:546); `mut-c-18` RED.
  - **/7.5/1:** focus precondition (H:1120-1125); `mut-c-17` RED.
  - **/4/2:** `_land_focus` spy (F:1418-1436); `mut-c-15` RED. The spy records a call, not a decision. That is enough here, because the Workspace has its region at the first call (e5c-06: area 4128 on every Workspace landing).
  - **040.11/4 and /5:** each is parametrised over three failures (H:937, H:950).
  - **/8/2 and /8/3:** assert the full line on both sinks (F:886-888, F:906-910); `mut-c-19` and `mut-c-20` are RED at the new clauses.
- **M23 and M-L (the addendum): met.**
  - **M23** is killed by /2/8 (`mut-c-13`).
  - **M-L** survives (`mut-c-14` ×3, `-21`) and is equivalent on every reachable route. My reading confirms E-15:
    - Non-priority keys go through `screen._modal_binding_chain` (Textual 8.2.8 `app.py:3978-3982`), which stops at the topmost modal (`screen.py:449-455`). All 20 dialog classes under `s19_app/tui` are `ModalScreen`s.
    - The four priority keys (`app.py:2701-2704`) switch no window.
    - Every `action_show_screen` caller runs while the default screen is current: the 12 rail bindings (`:2732-2748`), the rail click (`:10404`), `action_view_*` (`:11054-11062`), the map open-in-hex (`:19940`), the Split / Join close (`segment_split_view.py:2233`) and the inline palette.
    - A dismiss callback runs after its screen is popped.
    - Probes e5c-09 and `mut-c-23` show that the one state where M-L changes anything is reached only by a direct call.
  - The layout wait stays as a bounded defence. As with E-9, no reachable state needs it today.
- **CR-9: not met.** E-1 read the ruling as "accept"; the ruling meant "fix". The list is in RR-3.

### Findings

#### RR-1 — the save-as filter misses the A2L-only remainder of a primary unload  [MEDIUM · impl / security (S-2 class)]

**Where:**
- The condition, `app.py:13758`: `loaded is not None and loaded.file_type == "mac"`.
- The chain that creates the state:
  - `app.py:1882-1900`: with no MAC, `_unload_primary` returns `None`.
  - `:18023`: only `all` and `a2l` clear `current_a2l_path`, so the A2L stays.
  - `:11797` and `:8907`: Save project accepts an A2L-only session.
  - `project_gather_service.py:1492-1500`: the top-level copy drops only the planned rows' names, plus the MAC / A2L suffixes when such a row is planned.

**Scenario (route 1):**
1. Project `PA` holds fixture three as `unloaded_primary.s19`, plus an A2L. The operator loads it.
2. The operator presses `[u]` on the primary. `current_file` becomes `None`, the Loaded panel shows only the A2L slot, and `PA` stays open.
3. The operator saves the project as `P9`, which is a save as. `loaded is None`, so the filter is skipped. The plan has one `a2l` row, and `_plan_copies` carries `unloaded_primary.s19`.
4. Loading `P9` installs the unloaded image as the primary.

This is SE5-1's harm, on a state the ruling names: "after the primary was unloaded … when no S19/HEX is loaded".

**Scenario (route 2):** S19 + MAC + A2L; `[u]` on the primary, then `[u]` on the MAC. On a MAC spine `_unload_mac` returns `None` (`:1832-1834`), so the same state follows.

**Evidence:**
- **Probe (executed on this PC).** Run with `python -I` from a scratch folder; not committed. It uses the AST extraction of `e5s-probe.py.txt` and imports nothing from `s19_app` (it prints `s19_app imported: False`). Inputs: an inventory of `cal.a2l` + `unloaded_primary.s19`, and one planned row, `a2l:cal.a2l`. Results:
  - with the corrective's condition, the copy list is `['unloaded_primary.s19']`;
  - with the widened condition below, it is `[]`.
- **The rest is read, not run.** The state chain and the reload come from reading the code.
- **Why the pass missed it.** E-4 took R-WS-LOADED.19's own state ("a MAC file is loaded"). Its MAC-only states ("a primary unload or a MAC-only load") never reach the remainder with no spine.

**Fix:**
```python
if walked is not None and (loaded is None or loaded.file_type not in {"s19", "hex"}):
```
- Add case **R-WS-LOADED.19/5**:
  - Steps: route 1, then Save project `P9`.
  - Expected: `P9` holds the A2L, no `.s19` or `.hex` file and no file with the image's SHA-256; after `P9` is loaded, no S19 / HEX image is installed.
  - It is RED on `6cb142f1` and GREEN with the fix.
- **The case needs a one-line ruling.** R-WS-LOADED.19's state reads "While a MAC file is loaded and no S19 or HEX image is". One of:
  - widen the state to "While no S19 or HEX image is loaded";
  - or rule that the A2L does not outlive a primary unload that leaves no spine. That is what `_unload_primary`'s own docstring says (`:1848-1853`: "a companion A2L cannot outlive it"). `_apply_unload` then clears the A2L in that case, and the save says "Nothing to save".
- **Alternative:** narrow SE5-1 to the MAC state and record this route in the backlog.

**State:** `executed` (the helper rule, by probe) · `not-run` (the chain, read) · fix `planned`.

#### RR-2 — R-WS-LOADED.19 and its case say "no .s19 or .hex file"; the fix filters the top level only  [LOW · records / requirement precision]

**Where:**
- `app.py:13762-13770` filters only `walked.top_level`.
- `project_gather_service.py:1510-1517` still copies every file in a sub-folder.
- `segment_split_view.py:1661-1670`: the Split / Join `project` destination writes S19 / HEX parts into `<project>/splits/`.

**Scenario:**
- Suppose `PS` holds a Split / Join export of its image under `splits/`. The /19/3 steps then put that `.s19` part into `P9`.
- /19/3's oracle is recursive (`project_files`, `rglob`), so it would go RED. Yet the fix does exactly what the ruling says ("top-level").
- The part is not installed on load (variants are top-level only), so S-2's harm does not follow.

**Fix (a ruling, and the records):** narrow the requirement and case text to "no S19 or HEX image file at the project's top level". Do not filter the exports: they are the operator's own files.

#### RR-3 — CR-9's stale comments and thin docstrings remain  [LOW · doc]

The list for the close step.

**From CR-9, still present:**
1. `app.py:10630-10632`, the `_rehome_focus_after_load` Summary: "``watch_current_file`` re-focuses the Split / Join table on every install…". Stale since I-2: `refresh_window` focuses `#sje_table` only while the window is shown.
2. `app.py:19064-19066`, the `_step_finalize` comment: "the install re-focused the Split / Join table through ``watch_current_file``". Stale for the same reason.
3. `app.py:10732-10733`, the `_rehome_placeholder_focus_after_load` Data Flow: it says the call re-schedules "only while the focus has not moved". The code (`:10754`) checks something else: that the focus is still a `RailItem` or the recorded fallback.
4. `s19_app/render/hexview.py:188`: the example output reads `[0x1000, 0x8000, 0x8010, 0x8020]`, but the interpreter prints `[4096, 32768, 32784, 32800]`.
5. `app.py:10698-10701`, `_note_focus_landing`: one paragraph, with no Args, Data Flow or Dependencies. It has three callers (`:10696`, `:10764`, `:10893`) and holds the declared-vs-fallback rule.
6. `app.py:10773-10778`, `_load_tree_gone`: one paragraph, with no Returns or Dependencies. It has six callers (`:10742`, `:10841`, `:19014`, `:19029`, `:19043`, `:19058`).

**Exposed by the corrective's own edits:**

7. `app.py:17951-17962`, the `_apply_unload` Data Flow names none of:
   - the view-row memo reset (`:18005`);
   - the file-status write (`:18062`);
   - the stamped focus landing (`:18064-18068`, CR-3).
8. `app.py:10539-10551`, the `_fallback_focus_target` Returns and Data Flow do not describe the teardown branch (`:10575-10580`). With no rail, it returns the given target, the one that failed the visibility check.
9. `app.py:14171-14228`, the `_reset_project_session` Summary and Data Flow list every reset except the view-row memo (`:14234-14236`). The new comment also uses single backticks where the module's comments use double ones.

**Fix:** update the texts, and give `_note_focus_landing` and `_load_tree_gone` the house sections. Docs only; no node changes.

### Checked, no finding

- **Exit paths:**
  - A landing scheduled before `App.exit` returns at the first line of `_land_focus`, and so does any re-scheduled wait.
  - The rail lookup cannot raise.
  - The four load steps and the E4-R3 re-check were already guarded.
  - /3/3 drives the landing by a direct call, named in its case: no driven route runs a landing after exit (E-6).
- **Windows vs POSIX:**
  - The save-as filter reads the POSIX `relative` text of a bare top-level name with `splitext(...)[1].lower()`. That is the rule `_plan_copies` and the project load use, so case and separators behave the same on both systems.
  - No changed line branches on the OS.
  - The new nodes use no OS-specific facility: /19/3 and /19/4 write and read files under `tmp_path` only.
- **Session cache:** the filter builds a new `ProjectInventory`. The Save session's cached inventory (`:12174-12184`) and its later re-use are unchanged.

### Evidence states

| Item | State | Basis |
|---|---|---|
| Rulings | `executed` | Read and grep, with the runs cited by id. The runs are the corrective's (`e5c-*`, `mut-c-*`), not mine; the scratch-index tree ties them to `d317138`. |
| Tree tie-in | `executed` | Git plumbing, scratch index. |
| RR-1 | `executed` · `not-run` · fix `planned` | The helper rule ran in a probe; the chain is read. |
| RR-2 | `not-run` · ruling `planned` | Read. |
| RR-3 | `executed` · fix `planned` | Read. |
| Mutants and suites | `not-run` by me | — |

### Evidence checklist

- [x] **Diff read in full:** `git diff 10deda9 d317138 -- s19_app tests` (`app.py`, 10 hunks; `segment_split_view.py:1755-1765`; H, 4 hunks; F, 11 hunks), plus the graph hunks.
- [x] **Correctness pass:** every file type left after a primary unload (RR-1); every CR-2 arm; stale and burst landings for an unload; the exit paths.
- [x] **Simplicity pass:** one helper replaces six blocks; no speculative parameter.
- [x] **Reuse:** the filter reuses `PROJECT_PRIMARY_DATA_EXTENSIONS` and `_plan_copies`' suffix rule; `bisect` follows the file's local-import form.
- [x] **Tests reviewed for intent:** each new or strengthened clause has a mutant that turns it RED (`mut-c-01` … `-20`); the attempted M-L node was dropped for the right reason (`mut-c-21`).
- [x] **Verdict explicit:** FAIL on RR-1 (MEDIUM). No HIGH is open.

### §4b Independent review cell (re-review)

`code-reviewer (re-review of the E5 corrective, code + security) · FAIL · no HIGH (none to resolve); SE5-2, SE5-5, CR-1, CR-2 (identical on every reachable arm), CR-3, CR-6/7, QA-3/4 met, M23/M28 killed, M-L equivalent on every reachable route (confirmed by reading Textual's modal binding chain and every action_show_screen caller); open: RR-1 MEDIUM the SE5-1 filter covers the MAC remainder only — a primary unload with no MAC leaves an A2L-only session whose save as still carries the unloaded image (probe executed; fix + R-WS-LOADED.19/5 or a narrowing ruling), RR-2 LOW requirement says "no .s19/.hex file" but the ruled fix is top-level only (splits/ exports), RR-3 LOW nine CR-9 doc items still to fix (listed with file:line)`
