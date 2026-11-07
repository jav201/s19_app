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
