# Increment 002 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 2 — App shell + 8-container screen routing + density toggle
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-002.1, LLR-002.3, LLR-006.1, LLR-006.2, LLR-007.1 (skeleton) · **TCs covered:** TC-003, TC-014, TC-015, TC-037 (scoped — see §5/§6).

---

## 1. What changed

The pre-batch three-layout toggle (`#view_bar` button bar + `#main_layout` / `#alt_layout` / `#mac_layout` with `action_view_main/alt/mac`) was replaced with the Direction B app shell: a `Header`, a `#command_bar_slot` mount point (populated in increment 4), a `Horizontal` split of a `#rail_slot` mount point (populated in increment 3) and an 8-child `#workspace_body`, then a `Footer`. `#workspace_body` holds eight `.hidden`-toggled rail screen containers in keymap-proposal rail order (`#screen_workspace` … `#screen_bookmarks`). Screens 1-3 (Workspace / A2L / MAC) **wrap the existing `#main_layout` / `#alt_layout` / `#mac_layout` containers verbatim** — every inner widget id is unchanged, so no `update_*` renderer was modified; the actual 3-pane / 2-pane re-layout is increments 5-7. Screens 4-8 are neutral `ScreenScaffold` slots, each carrying an `EmptyStatePanel`; their rich content lands in increments 7-10.

A new `action_show_screen(screen_key)` action implements the rail-driven content swap by reusing the existing `.hidden`-class show/hide mechanism (LLR-002.1) — no `push_screen`, so the command bar / rail / footer stay mounted. The `BINDINGS` were remapped per the owner-approved keymap: keys `1`-`8` route screens via `show_screen('…')`, and `ctrl+d` was added for the density cycle; the legacy `1`/`2`/`3` view-toggle meaning is intentionally superseded (LLR-004.4). `action_view_main/alt/mac` were retained as thin aliases of `action_show_screen` so `_active_view_name` and the four pre-batch `test_tui_app.py` tests that monkeypatch it stay green. `action_cycle_density` toggles `density-compact` / `density-comfortable` on `#workspace_body` (LLR-006.1), `on_mount` sets `density-comfortable` as the default (LLR-006.2), and `on_resize` / `_apply_width_regime` toggle a `width-narrow` class on `#workspace_body` below the 120-column breakpoint (LLR-007.1 skeleton — the proportional pane math lands per-screen in increments 5-7). The retired `#view_bar` buttons (`view_hex/a2l/mac_button`, `settings_button`) were removed from `compose`, their `on_button_pressed` branches deleted, and the dead `#view_bar` CSS rules removed. A new `screens_directionb.py` module hosts the `EmptyStatePanel` and `ScreenScaffold` widgets — the home for all Direction B screen/widget classes built in later increments. No engine, service, `color_policy.py`, or parser code was touched.

## 2. Files modified

**Code / test (4 — within the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/app.py` | modified | Direction B `compose` (header / command-bar slot / rail+body `Horizontal` / footer); 8 `.hidden`-toggled `#screen_*` containers; `action_show_screen`; `action_cycle_density`; `on_resize` + `_apply_width_regime`; `on_mount` density default; `BINDINGS` remap (1-8 → `show_screen`, `+ctrl+d`); `action_view_*` kept as aliases; `_active_view_name` re-pointed to `#screen_a2l`/`#screen_mac`; `#view_bar` buttons + `on_button_pressed` branches removed; `events`/`Horizontal`/`ScreenScaffold` imports added. |
| `s19_app/tui/styles.tcss` | modified | Removed dead `#view_bar` rules; added `#command_bar_slot`, `#workspace_shell`, `#rail_slot`, `#workspace_body`, `.db-screen`, `.db-screen-title`, `#empty_state_panel`, `.density-compact` / `.density-comfortable` variants, and the `width-narrow` collapsed-rail skeleton rule. |
| `s19_app/tui/screens_directionb.py` | NEW | `EmptyStatePanel` (LLR-002.3 no-file prompt) and `ScreenScaffold` (neutral titled container with empty-state for rail screen slots 4-8). |
| `tests/test_tui_directionb.py` | NEW | TC-003 (rail swap — startup single-visible, `action_show_screen` per key, keys `1`-`8`), TC-014 (`Ctrl+D` cycle + `action_cycle_density` exclusive toggle), TC-015 (startup density default), TC-037 (`EmptyStatePanel` prompt, Memory Map empty state, all 5 scaffolds carry the panel). |

**File count:** 4 — within the ≤5 cap.

## 3. How to test

```bash
# Increment-2 tests (TC-003 / TC-014 / TC-015 / TC-037)
pytest -q tests/test_tui_directionb.py

# Full suite — must not regress from the increment-1 baseline
pytest -q

# App still imports with the new shell
python -c "import s19_app.tui; print('import OK')"

# Lint (see Test results — ruff is not installed in this env)
ruff check .
```

`App.run_test()` screen-routing smoke (run during dev — see Test results §4):
activates each of the 8 screen keys and asserts exactly one `#screen_*`
container is visible; cycles density; presses digit keys `1`-`8`.

## 4. Test results (actual output)

**`pytest -q tests/test_tui_directionb.py`:**
```
.........                                                                [100%]
9 passed in 5.14s
```

**`pytest -q` (full suite):**
```
284 passed, 2 skipped, 3 xfailed in 82.56s (0:01:22)
```
0 failed. Increment-1 baseline was 275 passed / 2 skipped / 3 xfailed / 0 failed; the +9 are exactly the new `test_tui_directionb.py` cases. The 2 skipped + 3 xfailed are unchanged (pre-existing). No test was silently skipped. The four `test_tui_app.py` tests that monkeypatch `_active_view_name` still pass — the method survives and still returns `main`/`alt`/`mac`.

**App import + `run_test()` screen-routing smoke:**
```
import s19_app.tui OK
startup visible: ['screen_workspace']
routing: exactly one visible for all 8 - OK
EmptyStatePanel count: 5
density cycle OK
width-narrow class present: True (terminal width 80)
```
At startup only `#screen_workspace` is visible; activating any of the 8 keys leaves exactly one screen visible; the 5 scaffolds each carry an `EmptyStatePanel`; density default is `density-comfortable` and `Ctrl+D` cycles it; `width-narrow` is correctly applied at the 80-column `run_test()` default size (confirms `on_resize` fires on mount).

**`py_compile`:** `app.py`, `screens_directionb.py`, `test_tui_directionb.py` all compile clean.

**`ruff check .` / `ruff format --check .`:** **NOT RUN — ruff is not installed in this environment** (`ModuleNotFoundError: No module named 'ruff'`). As the increment brief directs, `python -m py_compile` was run on all three changed/new Python files as the substitute — all compile clean. `styles.tcss` is loaded and parsed by the Textual engine during the `run_test()` smoke and the full `run_test()`-based suite. Recommend running `ruff check .` in CI / a ruff-equipped environment before merge.

## 5. Risks

- **TC-037 scoped to the increment-2-owned slots.** LLR-002.3's acceptance criteria name Workspace / A2L Explorer / MAC View / Memory Map as showing the empty-state panel with no file. Increment 2 delivers the `EmptyStatePanel` widget and wires it into the five rail slots it owns this increment (Memory Map, Issues, Patch, Diff, Bookmarks). The Workspace / A2L / MAC screens still wrap their **pre-batch** layouts this increment (renderers untouched — the lower-risk path), so they do not yet host an `EmptyStatePanel`; their empty-state integration lands with the per-screen re-layout in increments 5-7. TC-037 here verdicts the Memory Map empty state and the panel widget; the Workspace/A2L/MAC empty state is re-verdicted in increments 5-7. This is recorded so the LLR-002.3 verdict is not over-claimed.
- **Renderer-id stability.** The increment-plan flagged "re-point every `update_*` renderer's `query_one` target" as the highest-churn edit. This increment took the lower-risk path: screens 1-3 contain the existing `#main_layout`/`#alt_layout`/`#mac_layout` verbatim, so **no** renderer id changed and no renderer was modified. The full `test_tui_app.py` UI suite passing unchanged confirms this.
- **Settings menu has no trigger.** Retiring `#view_bar` removed `settings_button`, which was the only way to open the `#settings_menu` overlay. The menu and `_toggle_settings_menu` / `_update_settings_menu` remain composed and callable (no orphan crash; no test exercised the toggle), but there is currently no key/UI path to open it. The owner-approved keymap proposal has no settings binding. This is a consequence of the planned `#view_bar` retirement — see Pending items.
- **`width-narrow` is skeleton-only this increment.** `on_resize` toggles the class and the collapsed-rail `width: 4` skeleton rule exists, but the proportional per-screen pane widths (LLR-008.1/009.1/010.1) are not implemented until increments 5-7, and `#rail_slot` is empty until increment 3. The 80×24 regime is fully verdicted by the increment-12 snapshot matrix.
- **`screens_directionb.py` module is new.** It currently exports only `EmptyStatePanel` and `ScreenScaffold`; increments 9-10 extend it. No engine import — verified by inspection (only `textual` imports).

## 6. Pending items

- **Workspace / A2L / MAC empty-state integration** — deferred to increments 5-7 (their re-layout increments), per the scope note above. TC-037's Workspace/A2L/MAC sub-cases are re-verdicted there.
- **Settings-menu trigger** — the `#settings_menu` overlay lost its only opener with `#view_bar`. Decide in a later increment (or as a keymap addendum) whether to expose it via the command palette (increment 4) or a new binding, or to retire it. Flagged for owner / `architect` input — it is not in the increment-2 LLR set or the approved keymap.
- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment; must run in CI / a ruff-equipped environment before merge.
- **Command-bar / rail mount slots are empty placeholders** — `#command_bar_slot` and `#rail_slot` are intentionally empty this increment; populated by increments 3 (rail) and 4 (command bar).
- **TC-016 / TC-016-S layout integrity** — set up here (the `width-narrow` regime, the 8-screen body) but verdicted in increment 12 (snapshot matrix).

## 7. Suggested next task

**Increment 3 — Activity rail widget + rail navigation wiring** (LLR-001.1, LLR-001.2, LLR-001.3). Create `s19_app/tui/rail.py` with `Rail` / `RailItem` widgets — eight ordered items (Workspace … Bookmarks) on keys `1`-`8`, the normative LLR-001.3 glyph→screen mapping with ASCII fallback, a single `-active` accent marker, and a `Rail.Selected` message — then mount it in this increment's `#rail_slot` and wire `Rail.Selected` → `action_show_screen` + active-marker move, with Workspace active at startup. The `action_show_screen` routing action and the `#rail_slot` / `width-narrow` hooks delivered here are the prerequisites and are in place.

---

*Increment 2 complete. Stopping at the increment boundary — increment 3 is NOT started.*
