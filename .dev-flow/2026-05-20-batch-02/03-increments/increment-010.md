# Increment 010 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 10 — Patch Editor + A↔B Diff scaffolds
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-012.2 (Patch Editor — an inert before/after view shell: hex panes + address/bytes input fields wired to no patch-apply/undo/redo logic, plus a visible deferral notice), LLR-012.3 (A↔B Diff — a static three-column placeholder: range list + hex A + hex B filled with constant, clearly-labelled sample hex rows + a visible PLACEHOLDER marker; no second-file load path, no diff computation), LLR-012.4 (deferred-logic guard — completed for all scaffolds and extended to `pyproject.toml`). · **TCs covered:** TC-026, TC-027, TC-028 (completion).

---

## 1. What changed

The last two neutral `ScreenScaffold` slots — Patch Editor (rail item 6) and A↔B Diff (rail item 7) — were replaced with their real Direction B content. Both are pure presentational view-layer widgets; no engine, service, parser, validation, `color_policy.py` or processing code was touched, no patch engine / second-file load path / diff computation was wired, and no new dependency was added.

1. **Patch Editor** (`#screen_patch`, LLR-012.2) — a new `PatchEditorPanel` widget renders an **inert before/after view shell**: a `Horizontal` of two hex `Static` panes (`#patch_before_hex` / `#patch_after_hex`, each carrying static placeholder hex rows), an address `Input` (`#patch_address_input`) and a bytes `Input` (`#patch_bytes_input`), and a visible deferral notice (`#patch_deferral_notice`) stating that patch apply / undo / redo is deferred to a follow-up batch. The `Input` fields are composed but **wired to nothing**: `PatchEditorPanel` defines neither `on_input_submitted` nor `on_input_changed`, and exposes no apply / undo / redo / patch method, so focusing a field and typing into it changes no memory and triggers no engine call (verified by the §4 smoke — `current_file` stays `None` after typing `0x80` into the address input). The hex-pane content is module-level constant placeholder text, not sourced from any `LoadedFile`.

2. **A↔B Diff** (`#screen_diff`, LLR-012.3) — a new `AbDiffPanel` widget renders a **static three-column placeholder**: a `Horizontal` of three `Static` columns — a range list (`#diff_range_list`), a hex-A column (`#diff_hex_a`) and a hex-B column (`#diff_hex_b`) — each filled with a small fixed set of constant, clearly-labelled sample hex rows and a visible `PLACEHOLDER` caption on its first line, plus a deferral notice (`#diff_deferral_notice`) stating that diff computation and the second-file (B) load path are deferred. The three columns' rows are module-level constants, **not** data from any `LoadedFile` and **not** produced by any diff computation. There is **no control to load a second ("B") firmware file** — the screen contains no `Button` at all (verified by §4 smoke and TC-027).

The two `ScreenScaffold("screen_patch", ...)` / `ScreenScaffold("screen_diff", ...)` calls in `compose` were replaced with two new `_compose_screen_patch` / `_compose_screen_diff` builder methods (mirroring the increment-9 `_compose_screen_map` / `_compose_screen_bookmarks` pattern). `ScreenScaffold` is now no longer used by `app.py` — its import was dropped — but the class is **left intact in `screens_directionb.py`** (it remains exported and its docstring/`Example` are still referenced; removing it would be unrequested scope and would be a 5th-file churn into the test module). All eight rail screens now have their real Direction B content; no `ScreenScaffold` slot remains in the running app.

**No data-processing changes (LLR-012.4):** both new widgets are static presentational shells. A dedicated test AST-inspects `_compose_screen_patch` / `_compose_screen_diff` and asserts each builder constructs **only** `Container` / `Label` / its panel class — no patch/diff/engine helper call. Another AST-walks `screens_directionb.py` and asserts `bincopy` / `pya2l` / `crcmod` are absent from its imports; another reads `pyproject.toml` and asserts those three are absent there too (the rejected handoff-PLAN.md dependency proposal — C-2); another enumerates the `s19_app/` package root and asserts no new processing module appeared; another activates all four scaffold screens (Memory Map, Patch Editor, A↔B Diff, Bookmarks) and asserts no exception plus the presence of the Patch/Diff deferral markers.

## 2. Files modified

**Code / test (4 — under the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/screens_directionb.py` | modified | Added `PatchEditorPanel` — an inert `Container` view shell: `compose` yields a `sev-warning`-classed deferral `Static`, a `Horizontal` of two before/after hex `Static`s with constant placeholder rows, and a `Container` of two `Label` + `Input` field rows; `DEFERRAL_TEXT` and the `_BEFORE_PLACEHOLDER` / `_AFTER_PLACEHOLDER` constants. Added `AbDiffPanel` — a static `Container`: `compose` yields a `sev-warning`-classed deferral `Static` and a `Horizontal` of three placeholder `Static` columns; `DEFERRAL_TEXT` and the `_RANGE_LIST_PLACEHOLDER` / `_HEX_A_PLACEHOLDER` / `_HEX_B_PLACEHOLDER` constants. Added `Horizontal` / `Input` to the `textual` imports. Module docstring extended to increment 10. |
| `s19_app/tui/app.py` | modified | Import: dropped `ScreenScaffold`, added `AbDiffPanel` / `PatchEditorPanel`. Replaced the two `ScreenScaffold` calls in `compose` with `_compose_screen_patch()` / `_compose_screen_diff()`. Added `_compose_screen_patch` (title + `PatchEditorPanel`) and `_compose_screen_diff` (title + `AbDiffPanel`), both following the PROJECT_RULES.md docstring contract. Updated the `compose` docstring `Data Flow` (screens 6/7 are now real shells, not `ScreenScaffold` slots) and `Dependencies → Uses` (dropped the stale `ScreenScaffold` line). |
| `s19_app/tui/styles.tcss` | modified | Added the Patch Editor + A↔B Diff rules (batch-02 increment 10 block): `#patch_editor_panel` / `#ab_diff_panel` containers, the `#patch_deferral_notice` / `#diff_deferral_notice` layout rules (color comes from the `sev-warning` class — the `color_policy` severity source of truth, not a hard-coded hue), the `#patch_hex_panes` / `#diff_columns` `Horizontal`s, the before/after hex panes, the address/bytes `Input`s, the `.patch-field-label`, and the three diff columns — all on the Calm Dark `$rule` / `$bg-panel` / `$bg-base` / `$fg-base` tokens. |
| `tests/test_tui_directionb.py` | modified | Added the increment-10 block (14 tests): TC-026 ×4 (before/after hex shell renders; address/bytes `Input`s present; inputs are inert — no `on_input_submitted`/`on_input_changed`, no apply/undo/redo surface; screen states logic deferred), TC-027 ×4 (three columns render; columns carry constant labelled PLACEHOLDER hex rows; screen states diff deferred + no second-file load `Button`; panel exposes no diff/second-file surface), TC-028 completion ×6 (`screens_directionb.py` still imports no processing libs after increment 10; no new module at the `s19_app/` root; `bincopy`/`pya2l`/`crcmod` absent from `pyproject.toml`; `_compose_screen_patch` builds only the view shell; `_compose_screen_diff` builds only the view shell; all four scaffold screens activate with no error + carry deferral markers). Module docstring extended to increment 10. |

**File count:** 4 files. This is **under** the ≤5 cap. No `tests/test_tui_app.py` edit was needed — the increment-9 packet's `test_apply_prepared_load_chains_updates_via_call_later` carve-out was for a new renderer joining the deferred-load chain; increment 10 adds no renderer (the Patch Editor and A↔B Diff are static shells with no `update_*` renderer), so no headless-ordering test is affected.

**Documentation:**
- `.dev-flow/2026-05-20-batch-02/03-increments/increment-010.md` — this review packet.

## 3. How to test

```bash
# 1. Static check (ruff is NOT installed in this environment — py_compile substituted)
python -m py_compile s19_app/tui/app.py s19_app/tui/screens_directionb.py tests/test_tui_directionb.py

# 2. Import smoke
python -c "import s19_app.tui"

# 3. The new increment-10 tests (TC-026/027/028; -k tc028 also re-runs the
#    4 increment-9 scaffold-side TC-028 cases — 18 total)
python -m pytest -q tests/test_tui_directionb.py -k "tc026 or tc027 or tc028"

# 4. Full directionb + commandbar suites
python -m pytest -q tests/test_tui_directionb.py tests/test_tui_commandbar.py

# 5. Full suite — must not regress from the 359 / 2 / 3 / 0 baseline
python -m pytest -q
```

An additional `App.run_test()` smoke (run ad-hoc, see §4) activates the Patch Editor and A↔B Diff screens, asserts both render their panes/columns, focuses the Patch Editor address input and types into it to confirm the inputs are inert (no memory change, no engine call), and confirms the A↔B Diff has no second-file load `Button`.

## 4. Test results

**`python -m py_compile s19_app/tui/app.py s19_app/tui/screens_directionb.py tests/test_tui_directionb.py`** — actual output:
```
PY_COMPILE exit=0
```
Note: `ruff` is **not installed** in this environment. Per the increment instructions `python -m py_compile` was substituted as the static check and passes on all three changed Python files. `styles.tcss` is **not** a Python file — `py_compile` cannot parse it; it is validated instead by the Textual stylesheet parser on every `run_test()`-based case (98 directionb + commandbar cases + the full suite all mount it), where a malformed rule surfaces as a `StylesheetError` at mount. The suite is green, so the stylesheet parses. Recommend `ruff check .` in CI / a ruff-equipped environment before merge.

**`python -c "import s19_app.tui"`** — actual output:
```
IMPORT OK
```

**New increment-10 tests** — `python -m pytest -q tests/test_tui_directionb.py -k "tc026 or tc027 or tc028"` — actual output:
```
..................                                                       [100%]
18 passed, 67 deselected in 3.36s
```
18 cases run: the 14 new increment-10 cases (TC-026 ×4, TC-027 ×4, TC-028 completion ×6) plus the 4 increment-9 TC-028 scaffold-side cases that also match the `tc028` keyword filter. All pass.

**Directionb + commandbar suites** — `python -m pytest -q tests/test_tui_directionb.py tests/test_tui_commandbar.py` — actual output:
```
98 passed in 49.55s
```
Prior count was 84 passed (increment 9 packet); the 14 new increment-10 cases bring it to 98. No regression in any prior directionb/commandbar case.

**Full suite** — `python -m pytest -q` — actual output (tail):
```
373 passed, 2 skipped, 3 xfailed in 125.19s (0:02:05)
```
Baseline was **359 passed / 2 skipped / 3 xfailed / 0 failed**. The 14 new increment-10 tests bring the total to **373 passed** (359 + 14); the 2 skipped + 3 xfailed are unchanged (pre-existing). 0 failed — **no regression**. No test was silently skipped.

**`App.run_test()` Patch Editor + A↔B Diff smoke** — actual output:
```
--- Patch Editor ---
before/after panes present: True True
address+bytes Input present: True True
PatchEditorPanel has on_input_submitted: False
PatchEditorPanel has on_input_changed: False
apply/undo/redo methods: []
typed into address input, value= '0x80'  current_file still None: True
deferral notice text: Content('Patch apply / undo / redo is deferred. The fields below are an inert layout preview - editing is not yet available and is deferred to a follow-up batch.')
--- A2B Diff ---
3 columns present: True True True
no Button (no 2nd-file load control): True
diff notice text: Content('PLACEHOLDER - diff computation and the second-file (B) load path are deferred to a follow-up batch. The three columns below show static sample rows, not real diff output.')
SMOKE OK
```
The Patch Editor rendered both hex panes and both `Input` fields; the `PatchEditorPanel` widget carries no `on_input_submitted` / `on_input_changed` handler and no apply/undo/redo method; focusing the address input and pressing `0 x 8 0` set the input's display value to `0x80` but left `current_file` `None` — the inputs are inert, they drive no patch logic. The A↔B Diff rendered all three columns and contains no `Button` (no second-file load control). Both screens show their deferral notice.

## 5. Risks

- **`EmptyStatePanel` id duplication (pre-existing, reduced).** The increment-7/9 packets flagged that several `EmptyStatePanel` widgets in the tree share the id `#empty_state_panel`. Increment 10 converts the last two `ScreenScaffold` slots (which each carried an `EmptyStatePanel`) into the Patch Editor / A↔B Diff shells, which carry **no** `EmptyStatePanel` (they are not file-dependent — they are static deferred shells, like Bookmarks). The remaining `EmptyStatePanel` widgets are Workspace, Issues and Memory Map (3, plus the standalone one inside `_compose_screen_workspace`). `_apply_empty_state` and all tests query the panel by type scoped to a screen (`screen.query(EmptyStatePanel)`), never by the shared id, so the ambiguity is never hit. The duplication surface is now **smaller** than before this increment.
- **`ScreenScaffold` is now dead code in `app.py` but retained in `screens_directionb.py`.** No running screen uses `ScreenScaffold` anymore — all eight rail screens have real content. The class is still defined and exported (its docstring `Example` and module docstring still reference it). It was deliberately **not deleted**: removing it would touch the module docstring, the export surface and any test that references it (a 5th-file churn beyond this increment's scope). It is inert and harmless. Flagged as a candidate cleanup for the increment-11 no-regression sweep or a follow-up — not a defect.
- **Patch Editor inputs are inert by omission, not by an explicit disabled flag.** The `Input` fields are left fully interactive (focusable, type-able) — they are "inert" in the sense that *nothing is wired to their submission*. A user can type into them; the text simply goes nowhere. This matches LLR-012.2 ("input fields are present but not connected to a patch engine") and the increment-plan approach ("inert inputs"). They are deliberately not `disabled=True` because a disabled input would not convey "this is a layout preview of a future feature" as well as an editable-but-unwired field plus the explicit deferral notice. TC-026 asserts the inertness positively (no handler, no apply/undo/redo surface). If a reviewer prefers visibly-disabled inputs, that is a one-line `disabled=True` change — raise it as a follow-up, it is a UX-polish call, not a correctness issue.
- **Placeholder hex rows are illustrative, not validated hex.** The before/after and A↔B-Diff column rows are hand-written constant strings shaped to look like hex dumps (`DE AD BE EF ...`). They are clearly captioned `PLACEHOLDER` / "(placeholder)" and are never parsed — they are display text only (LLR-012.3 "static, clearly-labelled sample hex rows"). They are not real, not from a fixture, and not diff output; that is the intended design.
- **No visual / interactive verification.** All checks are headless (`App.run_test()` / `pytest`). Real-terminal rendering of the Patch Editor before/after panes, the input fields and the A↔B Diff three columns was not eyeballed. A manual TUI pass is advisable before batch close (deferred to the Phase-4 validation gate).

## 6. Pending items

- **Manual TUI pass** — launch `s19tui`, press `6` to open the Patch Editor and confirm the before/after panes, the address/bytes inputs and the deferral notice render; press `7` to confirm the A↔B Diff three columns, the PLACEHOLDER captions and the deferral notice. Deferred to the Phase-4 validation gate.
- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment; must run in CI / a ruff-equipped environment before merge.
- **`ScreenScaffold` dead-code removal** — now unused by the running app (see §5). A candidate cleanup for increment 11 or a follow-up; not removed here to stay within the file cap and scope.
- **REQUIREMENTS.md traceability** — if `R-*` rows are mapped for the Patch Editor / A↔B Diff screens (candidate `R-TUI-027` / `R-TUI-028`), they should be refreshed to cite `test_tui_directionb.py` TC-026 / TC-027 / TC-028. Not done here (out of file scope; flagged for the docs increment).
- **Snapshot baseline (increment 12)** — the Patch Editor and A↔B Diff screens are part of the 3-scaffold × 120×30 snapshot set in the increment-12 matrix; the layout-drift verdict lands there.

## 7. Suggested next task

**Increment 11 — No-regression + behavior test increment** (LLR-004.4, LLR-013.1, LLR-013.2, LLR-014.1, LLR-014.2). This is the dedicated cross-cutting regression sweep, now that all eight rail screens exist (increments 1-10 complete): TC-011 (no pre-batch `BINDINGS` action unreachable; the `1/2/3`→rail remap and `#view_bar` removal recorded as intended supersession), TC-029 (every new Direction B control — rail items, command-bar inputs, density toggle, scaffold controls — keyboard-reachable; the input-focus suppression sub-case), TC-030 (footer shows the active screen's `show=True` bindings, against increment 1's keymap proposal), TC-031 (engine modules `core.py` / `hexfile.py` / `range_index.py` / `validation/` / `a2l.py` / `mac.py` show no behavioral change — cosmetic-only rubric), TC-032 (`pytest -q` green; engine test files unmodified). Update the pre-batch `test_tui_app.py` UI tests that still assert on the old `#main_layout` / `#alt_layout` / `#mac_layout` / `#view_bar` structure to the new Direction B layout **without weakening their behavioral intent**. The single `app.py` slot is reserved only to close a keyboard-reachability gap the tests expose.

**Do not start increment 11 — this increment (10) is complete and stops here.**
