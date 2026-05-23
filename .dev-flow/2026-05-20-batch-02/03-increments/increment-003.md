# Increment 003 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 3 — Activity rail widget + rail navigation wiring
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-001.1, LLR-001.2, LLR-001.3 · **TCs covered:** TC-001, TC-002, TC-035.

---

## 1. What changed

A new `s19_app/tui/rail.py` module delivers the Direction B activity rail. It defines `RailEntry` (an immutable screen-key / Unicode-glyph / ASCII-fallback-glyph / label record), `RAIL_ENTRIES` (the eight ordered rail items — Workspace, A2L Explorer, MAC View, Memory Map, Issues Report, Patch Editor, A2B Diff, Bookmarks — carrying the normative LLR-001.3 glyph→screen mapping `◫ ≡ ◉ ▤ ! ✎ ⏚ ✶` with ASCII fallbacks `# = @ M ! P D *`), `RailItem` (one focusable row), and `Rail` (the vertical 8-item rail). The rail is presentational per the s19_app `CLAUDE.md` TUI architecture: it takes its entries at construction, emits a `Rail.Selected` message on click, and exposes `set_active` — it never calls the engine or a service. ASCII-fallback rendering is a constructor flag (`ascii_mode`); Unicode is the default.

`app.py` mounts a `Rail(active="workspace")` into increment 2's `#rail_slot` container, so the rail slot is now populated. `action_show_screen` — already bound to keys `1`-`8` from increment 2 and the single routing entry point — now also calls `Rail.set_active(screen_key)` after toggling the `.hidden` classes, so the rail's single active marker reflects the active screen on **every** screen change regardless of how it was triggered. A new `on_rail_selected(Rail.Selected)` handler routes a rail click through that same `action_show_screen` path, so mouse-click navigation and the `1`-`8` keys share one implementation (including the active-marker move). Workspace is active at startup (the `Rail` constructor default plus increment 2's startup-visible `#screen_workspace`).

`styles.tcss` gains the `#activity_rail` / `.rail-item` / `.rail-item.-active` rules — the active item is marked with the single Calm Dark accent (`$accent-calm`) via an accent left border, accent text and bold, satisfying the LLR-001.2 single-accent-marker invariant. The increment-2 `width-narrow` collapsed-rail skeleton rule was promoted to a real collapsed-rail variant: at `<120` columns the rail collapses to an icon-only 4-column width (within the LLR-001.1 CV-02 `4±1` tolerance) and rail-item padding is dropped; the active marker is preserved in the narrow regime.

No engine, service, `color_policy.py`, or parser code was touched. No new runtime dependency was added.

## 2. Files modified

**Code / test (4 — within the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/rail.py` | NEW | `RailEntry` dataclass + `RAIL_ENTRIES` (the 8-item LLR-001.3 glyph→screen table); `RailItem` (focusable row, Unicode/ASCII glyph, `-active` marker, posts `RailItem.Selected` on click); `Rail` (composes the 8 items, `set_active` single-marker move, re-posts clicks as `Rail.Selected`). Presentational only — no engine import. |
| `s19_app/tui/app.py` | modified | Import `Rail`; mount `Rail(active="workspace")` into `#rail_slot`; `action_show_screen` now calls `Rail.set_active` so the marker tracks the active screen on every change; new `on_rail_selected(Rail.Selected)` handler routes rail clicks through `action_show_screen`; `compose` docstring `Dependencies` updated. |
| `s19_app/tui/styles.tcss` | modified | Added `#activity_rail` / `.rail-item` / `.rail-item.-active` rules (accent-marker invariant); promoted the increment-2 `width-narrow` skeleton rule into the real collapsed icon-only (4-col) rail variant. |
| `tests/test_tui_directionb.py` | modified | Extended with TC-001 (8 ordered items, keys 1-8 route through the rail), TC-002 (Workspace active at startup; single-active marker moves + clears previous across the key path and the click path), TC-035 (Unicode glyphs match the normative table, distinct defined ASCII fallbacks, ASCII-fallback mode renders the ASCII set). Module docstring updated to cover increments 2-3. |

**File count:** 4 — within the ≤5 cap.

## 3. How to test

```bash
# Increment-3 tests (TC-001 / TC-002 / TC-035) + the increment-2 cases
pytest -q tests/test_tui_directionb.py

# Full suite — must not regress from the increment-2 baseline
pytest -q

# App still imports with the rail mounted
python -c "import s19_app.tui; print('import OK')"

# py_compile substitute for ruff (ruff is not installed — see Test results)
python -m py_compile s19_app/tui/rail.py s19_app/tui/app.py tests/test_tui_directionb.py
```

`App.run_test()` rail smoke (run during dev — see Test results §4): mount
`S19TuiApp`, assert 8 rail items with Workspace active at startup, press a
digit key and assert the matching screen is visible and its rail item is
active, post a `RailItem.Selected` to drive the click path, and confirm the
single-active invariant holds across keys `1`-`8`.

## 4. Test results (actual output)

**`pytest -q tests/test_tui_directionb.py`:**
```
................                                                         [100%]
16 passed in 10.38s
```
9 increment-2 cases + 7 new increment-3 cases (TC-001 ×2, TC-002 ×2, TC-035 ×3).

**`pytest -q` (full suite):**
```
291 passed, 2 skipped, 3 xfailed in 90.87s (0:01:30)
```
0 failed. Increment-2 baseline was 284 passed / 2 skipped / 3 xfailed / 0 failed; the +7 are exactly the new `test_tui_directionb.py` increment-3 cases. The 2 skipped + 3 xfailed are unchanged (pre-existing). No test was silently skipped. The pre-batch `test_tui_app.py` UI suite still passes unchanged — the rail mount and the `Rail.set_active` call in `action_show_screen` did not disturb any existing renderer or `query_one` target.

**App import + `run_test()` rail smoke:**
```
rail item count: 8
startup active: ['workspace']
after key '5' active: ['issues'] visible: ['screen_issues']
after click 'diff' active: ['diff'] visible: ['screen_diff']
single-active invariant held across keys 1-8: True
smoke OK
```
The rail composes exactly 8 items; Workspace is the sole active item at startup; pressing digit `5` activates the Issues screen and its rail item; posting a `RailItem.Selected("diff")` (the click message chain) activates the A2B Diff screen and its rail item; exactly one rail item is active after every one of the eight digit keys.

**`py_compile`:** `rail.py`, `app.py`, `test_tui_directionb.py` all compile clean.

**`ruff check .` / `ruff format --check .`:** **NOT RUN — ruff is not installed in this environment** (`ModuleNotFoundError: No module named 'ruff'`). As the increment brief directs, `python -m py_compile` was run on all three changed/new Python files as the substitute — all compile clean. `styles.tcss` is loaded and parsed by the Textual engine during the `run_test()` smoke and the full `run_test()`-based suite (16 directionb cases exercise it). Recommend running `ruff check .` in CI / a ruff-equipped environment before merge.

## 5. Risks

- **Active-marker invariant.** Exactly one `-active` rail item must exist at all times. The invariant is held by routing **all** screen changes through `action_show_screen` → `Rail.set_active`, and `set_active` unconditionally clears `-active` from every item before setting it on the target. TC-002 asserts the invariant across the key path and the click path for all eight items. The risk would be a future code path that toggles `.hidden` directly without calling `action_show_screen`; none exists today (the legacy `action_view_main/alt/mac` aliases delegate to `action_show_screen`).
- **Unicode glyph rendering varies by terminal/font.** LLR-001.3's ASCII fallback is a constructor flag (`ascii_mode`); TC-035 exercises both Unicode-default and forced ASCII modes. The fallback is **not auto-detected** this increment — there is no runtime terminal-capability probe wiring it; `ascii_mode` defaults to `False` (Unicode). LLR-001.3's acceptance criterion says the fallback is "selectable/automatic"; this increment delivers the selectable path and the defined fallback set. Whether to add automatic detection (and how) is flagged in Pending items — it was not pinned by the LLR or the keymap proposal.
- **Rail keys `1`-`8` vs. command-bar input.** Per the increment-plan, between increment 3 and 4 the digit keys are not yet suppressed during input focus — acceptable because the command bar (the only input to type digits into) does not exist until increment 4. No runnable-app regression.
- **`width-narrow` collapsed rail is layout-only this increment.** The 4-column icon-only rule exists and the `width-narrow` class toggles on `on_resize` (increment 2), but the collapsed-regime visual is fully verdicted by the increment-12 snapshot matrix; in the 4-column regime the rail item label is clipped by design (icon-only) — the glyph remains the leading character.
- **`RailItem.Selected` vs. `Rail.Selected`.** `RailItem` posts `RailItem.Selected`; `Rail.on_rail_item_selected` stops that event and re-posts `Rail.Selected` so the app only ever sees one rail message type. A handler added to `RailItem.Selected` at the app level in a later increment would double-fire — the app handles `Rail.Selected` only, which is the documented contract.

## 6. Pending items

- **Automatic ASCII-fallback detection** — this increment delivers the *selectable* ASCII fallback (`ascii_mode` constructor flag) and the defined fallback glyph set; it does not wire automatic terminal-capability detection. LLR-001.3 phrases the fallback as "selectable/automatic". If automatic detection is wanted, it is a small follow-up (a capability probe feeding the `Rail(ascii_mode=...)` argument) — flagged for owner / `architect` decision; not in the increment-3 file set.
- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment; must run in CI / a ruff-equipped environment before merge.
- **Command-bar mount slot still empty** — `#command_bar_slot` is populated by increment 4; rail-key suppression during command-bar input focus also lands there (LLR-004.5).
- **Settings-menu trigger** — still open from increment 2 (the `#settings_menu` overlay lost its only opener with `#view_bar`); unchanged by this increment, carried forward.
- **Collapsed-rail / density snapshot verdict** — the `width-narrow` 4-column rail and the rail under both densities are verdicted by the increment-12 snapshot matrix.

## 7. Suggested next task

**Increment 4 — Command bar widget + key bindings + input-focus suppression** (LLR-003.1, LLR-003.2, LLR-003.3, LLR-004.1–004.6, LLR-011.3, LLR-013.3). Create `s19_app/tui/command_bar.py` with the `CommandBar` widget (palette trigger, find input, go-to input, project/A2L labels relocated from the old Status tile), mount it into increment 2's `#command_bar_slot`, add the `ctrl+k` / `/` / `g` focus bindings, build the palette 1:1 from `BINDINGS`, and implement the single-key suppression so `g` / `1`-`8` / `+` / `-` / `,` / `.` route as text while a command-bar `Input` holds focus. Per the increment-plan this increment is a new input surface (S-1) and should be flagged for `security-reviewer` review before merge — the find/go-to inputs must route to the existing validated `find_string_in_mem` / `_handle_goto` with zero new parsing code.

---

*Increment 3 complete. Stopping at the increment boundary — increment 4 is NOT started.*
