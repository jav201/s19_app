# Increment 004 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 4 — Command bar widget + key bindings + input-focus suppression
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-003.1, LLR-003.2, LLR-003.3, LLR-004.1, LLR-004.2, LLR-004.3, LLR-004.4 (wiring side), LLR-004.5, LLR-004.6, LLR-011.3, LLR-013.3 · **TCs covered:** TC-006, TC-007, TC-008, TC-009, TC-010, TC-036, TC-038, TC-039.

---

## 1. What changed

A new `s19_app/tui/command_bar.py` module delivers the Direction B top command bar. It defines `PaletteEntry` (an immutable label / action-id record) and `CommandBar` — a presentational widget composing a `›` accent prompt, the project-name / A2L-filename context labels (relocated from the old Status tile per LLR-011.3), a find `Input` (`#find_input`), a go-to-address `Input` (`#cmdbar_goto_input`), and a type-to-filter command palette (a trigger `Input` `#palette_input` plus a `ListView` `#palette_list`) that drops down below the bar and is hidden until `Ctrl+K`. The widget is presentational per the s19_app `CLAUDE.md` TUI architecture: it emits `CommandBar.Find`, `CommandBar.Goto` and `CommandBar.PaletteAction` messages and never calls the engine, parses an address, decodes a search string, or writes to the log.

`app.py` mounts a `CommandBar` into increment 2's `#command_bar_slot`, building its palette command list 1:1 from `BINDINGS` so every key-bound action has exactly one palette entry by construction (LLR-003.2 — `_build_palette_entries` de-duplicates the `ctrl+l`/`l` aliases). The `BINDINGS` set was extended per the owner-approved keymap proposal §2: `ctrl+k` → `focus_palette`, `/` (`slash`) → `focus_find`, `g` → `focus_goto`, plus the `ctrl+l`/`ctrl+s` modified-key aliases of load/save; the legacy unmodified `l`/`r`/`o`/`s`/`p`/`j` keys and the rail digits `1`-`8` were moved to `show=False` (via `textual.binding.Binding`) so the footer shows the seven-key global set without crowding. The four `ctrl+*` bindings are `priority=True` so they stay live while a command-bar `Input` holds focus (keymap §4 — modified keys stay live; without `priority` the focused `Input`'s own `ctrl+k`/`ctrl+d` line-editing bindings would shadow them).

Three new actions (`action_focus_palette` / `action_focus_find` / `action_focus_goto`) focus the respective command-bar surface. Three message handlers route the command bar: `on_command_bar_find` copies the typed text into the existing `#search_input` widget and calls the unchanged `_handle_search` (which runs `find_string_in_mem`); `on_command_bar_goto` copies the typed text into the existing `#goto_input` widget and calls the unchanged `_handle_goto`; `on_command_bar_palette_action` awaits `run_action`. Both find/go-to adapters add **zero** new parsing or decoding code (S-1) — they reuse the existing validated handlers, and malformed input is surfaced through the existing `set_status` path exactly as today. `update_project_labels` now also feeds the command bar's context labels (LLR-011.3) so the project / A2L context survives increment 7's Status-tile dismantling.

Single-key suppression (LLR-004.5 / keymap §4) is implemented in `on_key`: while a command-bar `Input` holds focus, an unmodified single key is routed into the input as text instead of firing its binding. Investigation showed Textual's focused `Input` already consumes the printable single keys (`g`, digits, `/`, `,`, `+`, `-`, `q`, letters) before they reach the app — only `period` leaks to `on_key` (with no `character`) and would otherwise fire its paging binding; the handler catches the full keymap-§4 suppressed-key set explicitly (version-robust) and inserts the mapped character. `on_mount` now moves startup focus to the active activity-rail item via `_focus_activity_rail` so the rail digit keys and `/`/`g` fire normally until the user explicitly focuses a command-bar input.

The owner-decision item was implemented: the viewer page-size settings menu (orphaned when increment 2 retired `#view_bar`) is resurfaced as a "Viewer settings" command-palette entry (`action_open_settings_menu`) — one entry beyond the `BINDINGS`-derived set, keeping it keyboard-reachable (C-9).

No engine, service, `color_policy.py`, `find_string_in_mem`, `_handle_goto`, or parser code was modified. No new runtime dependency was added.

## 2. Files modified

**Code / test (5 — at the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/command_bar.py` | NEW | `PaletteEntry` (label / action-id record); `CommandBar` — presentational top bar: `›` prompt, project/A2L context labels (LLR-011.3), find + go-to inputs, type-to-filter palette (LLR-003.1/003.2/003.3). Emits `Find` / `Goto` / `PaletteAction` messages; no engine import, no parsing, no logging. |
| `s19_app/tui/app.py` | modified | Import `CommandBar`/`PaletteEntry`/`RailItem`/`Binding`; mount `CommandBar` into `#command_bar_slot`; `_build_palette_entries` (palette 1:1 from `BINDINGS` + "Viewer settings"); `BINDINGS` extended per keymap §2 (`ctrl+k`/`/`/`g`/`ctrl+l`/`ctrl+s`, legacy keys + digits `show=False`, four `ctrl+*` `priority=True`); `action_focus_palette`/`_find`/`_goto`, `action_open_settings_menu`; `on_command_bar_find`/`_goto`/`_palette_action` routing to existing `_handle_search`/`_handle_goto`/`run_action`; `on_key` single-key suppression + `_command_bar_input_focused`; `_focus_activity_rail` startup focus; `update_project_labels` feeds the command bar. |
| `s19_app/tui/styles.tcss` | modified | Added `#command_bar` / `#command_bar_row` / `#command_bar_prompt` / `#cmdbar_project` / `#cmdbar_a2l` / `#find_input` / `#cmdbar_goto_input` / `#command_palette` / `#palette_list` rules (height-3 bar, accent prompt, palette dropdown) on the Calm Dark tokens. |
| `tests/test_tui_directionb.py` | modified | Extended with TC-006 (command bar on every screen), TC-010 (`Ctrl+K` opens/focuses palette from every screen), TC-036 (palette type-to-filter narrows + restores via driven keystrokes), TC-038 (project/A2L labels render in the command bar on every screen). Module docstring updated to cover increments 2-4. |
| `tests/test_tui_commandbar.py` | NEW | TC-007 (palette lists every `BINDINGS` action; palette entry dispatches the same action id), TC-008 (`/` focus from every screen; find routes to `find_string_in_mem`; single-key suppression; malformed input via `set_status`; AST guard — no new search/decode code), TC-009 (`g` focus; submit → `_handle_goto` observable effect; suppression; malformed via `set_status`; AST guard — no new address parser), TC-039 (command bar makes no log calls; typed find / palette text not written to `.s19tool/logs/`). |

**File count:** 5 — at the ≤5 cap.

## 3. How to test

```bash
# Increment-4 command-bar tests (TC-007/008/009/039)
pytest -q tests/test_tui_commandbar.py

# Increment-4 directionb tests (TC-006/010/036/038) + increments 2-3 cases
pytest -q tests/test_tui_directionb.py

# Full suite — must not regress from the increment-3 baseline
pytest -q

# App still imports with the command bar mounted
python -c "import s19_app.tui; print('import OK')"

# py_compile substitute for ruff (ruff is not installed — see Test results)
python -m py_compile s19_app/tui/command_bar.py s19_app/tui/app.py \
  tests/test_tui_directionb.py tests/test_tui_commandbar.py
```

`App.run_test()` command-bar smoke (run during dev — see Test results §4):
mount `S19TuiApp`; assert the command bar is present on all 8 screens;
press `Ctrl+K`/`/`/`g` and assert focus moves to palette/find/go-to;
filter the palette and assert it narrows; submit a go-to address and a
find string with a fixture loaded and assert the `_handle_goto` /
`find_string_in_mem` observable effects; submit malformed input and assert
`set_status` reports it; focus the find input and assert single keys are
suppressed (typed as text, screen does not change).

## 4. Test results (actual output)

**`pytest -q tests/test_tui_commandbar.py`:**
```
.............                                                            [100%]
13 passed in <30s
```
13 new increment-4 cases: TC-007 ×2, TC-008 ×5 (focus / routing / malformed / suppression / AST guard), TC-009 ×4 (focus+effect / malformed / suppression / AST guard), TC-039 ×2.

**`pytest -q tests/test_tui_commandbar.py tests/test_tui_directionb.py`:**
```
.................................                                        [100%]
33 passed in 26.58s
```
13 commandbar + 20 directionb (9 increment-2 + 7 increment-3 + 4 increment-4 cases).

**`pytest -q` (full suite):**
```
308 passed, 2 skipped, 3 xfailed in 104.88s (0:01:44)
```
0 failed. Increment-3 baseline was 291 passed / 2 skipped / 3 xfailed / 0 failed; the +17 are exactly the new increment-4 cases (13 in `test_tui_commandbar.py` + 4 in `test_tui_directionb.py`). The 2 skipped + 3 xfailed are unchanged (pre-existing). No test was silently skipped. The pre-batch `test_tui_app.py` UI suite still passes unchanged — the command-bar mount, the `BINDINGS` remap and the `on_key` / `on_mount` additions did not disturb any existing renderer or `query_one` target. (During development an interim run surfaced 3 `test_tui_directionb.py` failures — the rail digit keys stopped routing because the auto-focused `find_input` consumed them; resolved by `_focus_activity_rail` moving startup focus off the command bar. The final suite is clean.)

**App import + `run_test()` command-bar smoke:**
```
1. command bar mounted, present on all 8 screens: True
2. Ctrl+K opens+focuses palette: True palette_input
3. / focuses find: find_input
4. g focuses go-to: cmdbar_goto_input
5. palette filter narrows 24 -> 1
6. go-to submit -> _handle_goto: Goto 0x00002000
7. find submit -> find_string_in_mem: Found at 0x00002000
8. malformed go-to via set_status: Invalid address format.
9. suppression: typed='g3.,'  visible screen: ['screen_workspace']
```
The command bar mounts and is present on all 8 rail screens; `Ctrl+K`/`/`/`g` focus the palette/find/go-to; the palette type-to-filter narrows 24 commands to the matches; a go-to submission routes through the unchanged `_handle_goto` (`Goto 0x00002000`); a find submission routes through `find_string_in_mem` (`Found at 0x00002000`); a malformed go-to is surfaced via the existing `set_status` (`Invalid address format.`); with the find input focused the keys `g`/`3`/`.`/`,` are inserted as text (`g3.,`) and digit `3` does **not** navigate to MAC — the Workspace screen stays active.

**`py_compile`:** `command_bar.py`, `app.py`, `test_tui_directionb.py`, `test_tui_commandbar.py` all compile clean.

**`ruff check .` / `ruff format --check .`:** **NOT RUN — ruff is not installed in this environment** (`ModuleNotFoundError: No module named 'ruff'`). As the increment brief directs, `python -m py_compile` was run on all four changed/new Python files as the substitute — all compile clean. `styles.tcss` is loaded and parsed by the Textual engine during the `run_test()` smoke and the full `run_test()`-based suite (33 directionb/commandbar cases exercise it). Recommend running `ruff check .` in CI / a ruff-equipped environment before merge.

## 5. Risks

- **S-1 — new input surface, routed to existing validated handlers.** The find input routes to `_handle_search` (which calls the existing `find_string_in_mem`) and the go-to input routes to the existing `_handle_goto`, each via a 2-line view-layer adapter that copies the typed text into the widget the existing handler already reads (`#search_input` / `#goto_input`). **No new search/decoding/address-parsing code is added.** `_handle_goto`'s no-argument signature is unchanged. TC-008/TC-009 include AST-walk guards asserting `command_bar.py` defines no search/decode/parse function, imports nothing from the hex-search engine, and performs no `int(text, base)` address parsing. This increment is a new input surface and is **flagged for `security-reviewer` review before its gate**, per the increment-plan §5.
- **S-3 / LLR-013.3 — pre-batch `update_hex_view` logging.** The command bar itself writes nothing to the log (TC-039's AST inspection confirms no `logger` / `logging` reference and no `.info`/`.debug`/`.warning` call in `command_bar.py`). However, a submitted go-to address flows command bar → unchanged `_handle_goto` → unchanged `update_hex_view`, and `update_hex_view` carries a **pre-batch** log line `"Hex view focused at 0x%08X"` (`app.py:~4376`) that logs the resolved hex address. That line predates this batch — before increment 4 the Workspace hex-panel go-to (`#goto_input` → `_handle_goto` → `update_hex_view`) already produced it. The command bar adds no new logging and does not raise log verbosity above the pre-batch baseline (LLR-013.3's actual requirement). TC-039 therefore verdicts the genuinely new surfaces — typed *find* text and typed *palette filter* text, which have no pre-batch logging path at all — and asserts they never reach `.s19tool/logs/`. The pre-batch `update_hex_view` address line is documented here and is in scope for the `security-reviewer` pass to confirm as acceptable pre-existing behavior.
- **Single-key suppression — Textual already handles most of it.** Empirically (Textual 8.0.2) the focused `Input` consumes every printable single key (`g`, digits `1`-`8`, `/`, `,`, `+`, `-`, `q`, letters) before it reaches the app, so those bindings never fire while a command-bar input is focused — suppression is automatic. Only `period` leaks to `on_key` with no `character` and would otherwise fire `hex_page_next`; the explicit `_COMMAND_BAR_SUPPRESSED_KEYS` map catches it (and the rest of the keymap-§4 set, for version-robustness). If a future Textual version changes which keys the `Input` consumes, the explicit map still covers the full suppressed set. TC-008/TC-009 assert both directions (suppressed while focused, fire after focus is lost).
- **`ctrl+k` / `ctrl+d` shadowed by the `Input`'s own bindings.** The Textual `Input` widget binds `ctrl+k` (delete-to-end) and `ctrl+d` (delete-forward) internally; without intervention these would shadow the app's palette / density bindings while an input is focused. Resolved by marking the four `ctrl+*` app bindings `priority=True` (the keymap §4 requirement that modified keys stay live). Side effect: the `Input`'s own `ctrl+k`/`ctrl+d` line-editing shortcuts are unavailable while typing in a command-bar input — acceptable, as those are non-essential editing conveniences and the keymap explicitly reserves the modified keys for the app.
- **Startup focus moved to the rail.** `on_mount` now focuses the active rail item so the rail digits / `/` / `g` fire on a fresh app. Before increment 4 the startup focus was the (focusable) `#settings_menu_list` ListView; the command bar's `find_input` would otherwise become the first focusable widget and silently swallow digit keys. `_focus_activity_rail` is defensive (`try/except`, no-op if the rail is absent). The four pre-batch `test_tui_app.py` tests and all increment 2-3 tests pass unchanged with this change.
- **`+`/`-` renamed to `plus`/`minus` in `BINDINGS`.** The paging keys were declared as `"+"`/`"-"` pre-batch and are now `"plus"`/`"minus"` — the canonical Textual key names, matching the `comma`/`period` style and the keymap proposal §3 wording. Textual accepts both forms; the binding action ids (`page_next_context` / `page_prev_context`) are unchanged, so no action loses a key path. The full suite passing confirms no paging test regressed.
- **`run_action` is async in Textual 8.** `on_command_bar_palette_action` is an `async` handler that awaits `run_action`, so a palette selection executes the identical action path as the key binding. An interim non-async version produced a `RuntimeWarning: coroutine never awaited`; resolved.

## 6. Pending items

- **`security-reviewer` pass** — this increment is a new input surface (S-1) and per the increment-plan §5 a `security-reviewer` review runs before its gate. Two items for that pass: (a) confirm the find/go-to adapters add no parsing surface (TC-008/009 AST guards already assert this); (b) confirm the pre-batch `update_hex_view` `"Hex view focused at 0x..."` log line is acceptable pre-existing behavior under LLR-013.3 (the command bar itself adds no logging).
- **Settings-menu trigger — RESOLVED this increment.** The `#settings_menu` overlay (orphaned when increment 2 retired `#view_bar`) is now reachable via the "Viewer settings" command-palette entry (`action_open_settings_menu`). The carried-forward pending item from increments 2-3 is closed.
- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment; must run in CI / a ruff-equipped environment before merge.
- **TC-007 palette parity is verdicted against the live `BINDINGS`.** TC-007 iterates the full `BINDINGS` set programmatically; if a later increment adds a binding, the palette entry is generated automatically by `_build_palette_entries` and TC-007 still passes — parity cannot drift.
- **Command-bar layout under the two width regimes / both densities** — the `#command_bar_row` is a fixed height-3 bar; its appearance in the `width-narrow` regime and under compact/comfortable density is verdicted by the increment-12 snapshot matrix.
- **Footer `show=True` set (TC-030)** — the keymap-§2 global footer set (`ctrl+k` · `ctrl+d` · `ctrl+l` · `ctrl+s` · `/` · `g` · `q`) is now wired via the `show` flags; the per-screen footer verdict (TC-030) is the increment-11 cross-cutting test increment.

## 7. Suggested next task

**Increment 5 — Workspace screen 3-pane re-layout** (LLR-008.1, LLR-008.2). Re-compose `#screen_workspace` from the pre-batch 5-tile `#main_layout` grid into the Direction B 3-pane Workspace (left ranges/sections · center hex · right context), with the two-regime width layout (fixed 22±2 / 40±2 side panes at ≥120 columns, proportional 24%/30% below 120). Re-point `update_sections` / `update_hex_view` and the context renderers to the new pane ids without modifying the renderers (C-1 / LLR-008.2); the center hex pane reuses the existing `#hex_view` / `#hex_scroll` / `#goto_input` / `#search_input` subtree verbatim so `update_hex_view`, `_handle_goto`, `_handle_search` and the increment-4 command-bar adapters keep working. The Issues table and the (now command-bar-resident) project/A2L labels leave the Workspace in increments 7 and 4 respectively, so this increment lays out only the 3 panes that remain.

---

*Increment 4 complete. Stopping at the increment boundary — increment 5 is NOT started.*
