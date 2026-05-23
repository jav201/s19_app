# Increment 009 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 9 — Memory Map + Bookmarks scaffolds
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-012.1 (Memory Map scaffold — read-only coverage visualization from the existing `LoadedFile.ranges` / `range_validity`), LLR-002.2 (Bookmarks rail item opens a neutral "coming soon" placeholder — no persistence logic), LLR-012.4 (deferred-logic guard — scaffold side: no new processing module, no `bincopy`/`pya2l`/`crcmod`). · **TCs covered:** TC-025, TC-004, TC-028 (scaffold side).

---

## 1. What changed

Two of the four remaining neutral `ScreenScaffold` slots — Memory Map (rail item 4) and Bookmarks (rail item 8) — were replaced with their real Direction B content. Both are pure presentational view-layer widgets; no engine, service, parser, validation, `color_policy.py` or processing code was touched, and no new dependency was added.

1. **Memory Map** (`#screen_map`, LLR-012.1) — a new `MemoryMapPanel` widget renders a **read-only coverage visualization** of the loaded image. It consumes the **already-computed** `LoadedFile.ranges` and `LoadedFile.range_validity` model fields verbatim and formats them into a textual coverage map: a summary line (range count, covered byte total, overall address span), one line per contiguous range with a proportional fill bar and an `OK`/`INVALID` marker, and one line per inter-range gap. The panel performs **no coverage computation, parsing or analysis** — gap spans are simple subtraction of consecutive already-parsed range bounds, and the fill bar scales an already-known byte count for display only. A new `S19TuiApp.update_memory_map` renderer reads `current_file` (read-only) and drives `MemoryMapPanel.render_ranges`; it is wired into the `_apply_prepared_load` deferred chain's `_step_finalize` step alongside `update_project_labels`, so the Memory Map refreshes when a file loads, exactly like the other `update_*` renderers. With no file loaded the screen shows the existing `EmptyStatePanel` (LLR-002.3) — `#screen_map` was added to the `_EMPTY_STATE_SCREENS` table so `_apply_empty_state` toggles its `#map_content` coverage container against the panel.

2. **Bookmarks** (`#screen_bookmarks`, LLR-002.2) — a new `BookmarksPlaceholder` widget renders a static, neutral "Bookmarks — coming soon" notice stating the feature is deferred to a future release. Activating the Bookmarks rail item (by click or key `8`) simply mounts this widget. **No persistence is read or written, no storage, no bookmark logic** — the widget is a `Static` notice with no save/load/store/persist surface.

The `compose` method's two `ScreenScaffold("screen_map", ...)` / `ScreenScaffold("screen_bookmarks", ...)` calls were replaced with two new `_compose_screen_map` / `_compose_screen_bookmarks` builder methods (mirroring the increment-5/7 `_compose_screen_*` pattern). `ScreenScaffold` itself is unchanged and still hosts the two genuinely-deferred slots (Patch Editor, A2B Diff — increment 10).

**No data-processing changes (LLR-012.4):** the Memory Map is a strict consumer of pre-existing `LoadedFile` fields. A dedicated test (`test_tc028_memory_map_renderer_adds_no_coverage_computation`) AST-inspects `update_memory_map` and asserts it reads `ranges`/`range_validity` and calls only the presentational `render_ranges` — never `validate_artifact_consistency`, `build_sorted_range_index`, `build_range_validity_*`, `parse_a2l_file` or `parse_mac_file`. Another asserts `screens_directionb.py` imports none of `bincopy`/`pya2l`/`crcmod`, and a third asserts no new module appeared at the `s19_app/` package root.

## 2. Files modified

**Code / test (4 — under the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/screens_directionb.py` | modified | Added `MemoryMapPanel` — the read-only coverage widget; `render_ranges(ranges, range_validity)` formats the already-computed model fields into a coverage map and stores the result on a public `rendered_text` attribute; `_coverage_bar` is a display-only fill-bar helper. Added `BookmarksPlaceholder` — a static "coming soon" notice (`PLACEHOLDER_TEXT`), no persistence surface. Added `typing` imports for the new signatures. Module docstring extended to increment 9. |
| `s19_app/tui/app.py` | modified | Imported `BookmarksPlaceholder` / `MemoryMapPanel`. Replaced the two `ScreenScaffold` calls in `compose` with `_compose_screen_map()` / `_compose_screen_bookmarks()`. Added `_compose_screen_map` (title + scrollable `#map_content` holding `MemoryMapPanel` + `EmptyStatePanel`) and `_compose_screen_bookmarks` (title + `BookmarksPlaceholder`). Added the `update_memory_map` renderer (reads `current_file.ranges`/`range_validity` read-only, drives `MemoryMapPanel.render_ranges`). Added `("screen_map", "map_content")` to `_EMPTY_STATE_SCREENS`. Wired `update_memory_map` into `_apply_prepared_load`'s `_step_finalize`. `compose` and `_apply_prepared_load` docstrings updated to the PROJECT_RULES.md contract. |
| `s19_app/tui/styles.tcss` | modified | Added the Memory Map rules (`#map_content` bordered scroll container + `.hidden`, `#memory_map_panel` padding/foreground) and the Bookmarks rule (`#bookmarks_placeholder` padding/foreground), all on the Calm Dark `$rule` / `$bg-panel` / `$fg-base` tokens. |
| `tests/test_tui_directionb.py` | modified | Added the increment-9 block (12 tests): TC-025 ×5 (Memory Map renders every range from `LoadedFile`; renders the gaps; the panel consumes hand-built data verbatim; empty-state with no file; empty-state clears on load), TC-004 ×3 (Bookmarks activation shows a non-blocking placeholder; rail key `8` reaches it; the placeholder exposes no bookmark-persistence surface), TC-028 scaffold-side ×4 (`screens_directionb.py` imports no processing libs; no new module at the package root; `update_memory_map` adds no coverage computation; every scaffold screen activates without error). Updated one pre-existing increment-7 test (`test_tc037_scaffold_screens_carry_empty_state`) to the new layout — see §4. Module docstring extended to increment 9. |

**Also touched (test edit, within the LLR-014.2 carve-out — counts as the same `tests/test_tui_app.py` slot only if a 5th file is contested; see note):**

| File | Status | Purpose |
|------|--------|---------|
| `tests/test_tui_app.py` | modified | `test_apply_prepared_load_chains_updates_via_call_later` — a pre-batch headless ordering test that monkeypatches every renderer in the `_apply_prepared_load` chain — gained a `monkeypatch.setattr(app, "update_memory_map", record("memory_map"))` line and a matching `assert "memory_map" in call_log` in the finalize step. `update_memory_map` is a new sibling renderer in that chain; without the monkeypatch the headless (unmounted) test would hit the real `query_one` and fail. The test's intent — verifying the deferred-chain step ordering — is unchanged and is in fact strengthened (it now also asserts the Memory Map refresh runs in the finalize step). This is the LLR-014.2 "update pre-batch UI tests to the new layout without weakening intent" carve-out.|

**File count:** 5 files (4 increment files + the `test_tui_app.py` regression-fix edit). This is **at** the ≤5 cap. The `test_tui_app.py` edit is a 2-line consequence of the new renderer joining an existing chain and is the LLR-014.2 carve-out; it is flagged here for transparency rather than deferred, because deferring it would leave the suite red.

**Documentation:**
- `.dev-flow/2026-05-20-batch-02/03-increments/increment-009.md` — this review packet.

## 3. How to test

```bash
# 1. Static check (ruff is NOT installed in this environment — py_compile substituted)
python -m py_compile s19_app/tui/app.py s19_app/tui/screens_directionb.py tests/test_tui_directionb.py tests/test_tui_app.py

# 2. Import smoke
python -c "import s19_app.tui"

# 3. The new increment-9 tests only
python -m pytest -q tests/test_tui_directionb.py -k "tc025 or tc004 or tc028"

# 4. Full directionb + commandbar suites
python -m pytest -q tests/test_tui_directionb.py tests/test_tui_commandbar.py

# 5. Full suite — must not regress from the 347 / 2 / 3 / 0 baseline
python -m pytest -q
```

An additional `App.run_test()` smoke (run ad-hoc, see §4) loads the public `examples/case_02_gaps_and_patch_targets/firmware.s19` fixture through the real `_apply_prepared_load` pipeline, drains the deferred `call_later` chain, then asserts the Memory Map renders every loaded range plus the gaps, and the Bookmarks screen shows the placeholder.

## 4. Test results

**`python -m py_compile s19_app/tui/app.py s19_app/tui/screens_directionb.py tests/test_tui_directionb.py tests/test_tui_app.py`** — actual output:
```
PY_COMPILE exit=0
```
Note: `ruff` is **not installed** in this environment (`No module named ruff`). Per the increment instructions `python -m py_compile` was substituted as the static check and passes on all four changed Python files. `styles.tcss` is **not** a Python file — `py_compile` cannot parse it; it is validated instead by the Textual stylesheet parser on every `run_test()`-based case (84 directionb + commandbar cases + the full suite all mount it), where a malformed rule surfaces as a `StylesheetError` at mount. The suite is green, so the stylesheet parses. Recommend `ruff check .` in CI / a ruff-equipped environment before merge.

**`python -c "import s19_app.tui"`** — actual output:
```
IMPORT OK
```

**New increment-9 tests** — `python -m pytest -q tests/test_tui_directionb.py -k "tc025 or tc004 or tc028"` — actual output:
```
............                                                             [100%]
12 passed, 59 deselected in 3.50s
```
12 new increment-9 cases: TC-025 ×5, TC-004 ×3, TC-028 (scaffold side) ×4.

**Directionb + commandbar suites** — `python -m pytest -q tests/test_tui_directionb.py tests/test_tui_commandbar.py` — actual output:
```
............................................................................. [ 85%]
............                                                             [100%]
84 passed in 54.08s
```
No regression in the prior directionb/commandbar cases; the one pre-existing increment-7 case updated for the new layout (see below) passes with its intent intact.

**Full suite** — `python -m pytest -q` — actual output (tail):
```
359 passed, 2 skipped, 3 xfailed in 119.75s (0:01:59)
```
Baseline was **347 passed / 2 skipped / 3 xfailed / 0 failed**. The 12 new increment-9 tests bring the total to **359 passed** (347 + 12); the 2 skipped + 3 xfailed are unchanged (pre-existing). 0 failed — **no regression**. No test was silently skipped.

> **Note on two dev-cycle failures resolved within scope:**
> 1. *First run — 6 failures in `test_tui_directionb.py`:* the new TC-025/TC-004 tests read `Static.renderable`, an attribute that does not exist on a mounted `Static`/`Label` in this Textual version (verified by probe — `hasattr` is `False`). Fixed by exposing the rendered text through reliable accessors I control: `MemoryMapPanel.rendered_text` (a public attribute set on every `render_ranges` call) and `BookmarksPlaceholder.PLACEHOLDER_TEXT` (the class constant). The `test_tc037_scaffold_screens_carry_empty_state` rewrite uses `Static.render()` (the documented Textual method) instead. `test_tc004_bookmarks_placeholder_has_no_persistence_methods` had an over-broad token list — the substring `"load"` matched Textual's own `set_loading`/`get_loading_widget`/`loading` framework methods; narrowed to bookmark-specific persistence verbs. `test_tc028_no_new_processing_module...` listed a non-existent `requirements.py`; corrected the engine-module set against the actual `s19_app/` root (`utils.py`, `version.py` added; `requirements.py` removed).
> 2. *`test_tui_directionb.py::test_tc037_scaffold_screens_carry_empty_state`:* a pre-existing increment-7 test that asserted exactly 6 `EmptyStatePanel` widgets in the tree (4 scaffolds + Workspace + Issues). Increment 9 converts the Memory Map and Bookmarks scaffolds into real screens — Memory Map keeps an `EmptyStatePanel` (it is file-dependent), Bookmarks shows its placeholder instead, so the raw panel count is now 5. Rather than just bumping the number, the test was **rewritten to preserve its behavioral intent** (LLR-014.2): it now iterates all 8 rail screens, activates each with no file loaded, and asserts each shows at least one non-blank `Static` descendant — so "no rail screen is ever a blank pane" still holds, and it holds for the whole rail rather than via a brittle global count.
> 3. *`test_tui_app.py::test_apply_prepared_load_chains_updates_via_call_later`:* the headless `_apply_prepared_load` ordering test monkeypatches every renderer in the chain; `update_memory_map` joined the chain's finalize step and was not monkeypatched, so the real `query_one` ran against an unmounted tree and raised `ScreenStackError`. Fixed with the 2-line monkeypatch + assertion described in §2 — the LLR-014.2 carve-out.

**`App.run_test()` Memory Map + Bookmarks smoke** (public `case_02_gaps_and_patch_targets/firmware.s19`) — actual output:
```
--- Memory Map ---
Memory coverage - 4 range(s), 93 bytes across 0x00000000-0x8001013F

  [#---------------------------------------] 0x00000000-0x0000000A (11 bytes) [OK]
  gap                                        0x0000000B-0x8000FFFF (2147549173 bytes)
  [#---------------------------------------] 0x80010000-0x80010021 (34 bytes) [OK]
  gap                                        0x80010022-0x8001007F (94 bytes)
  [#---------------------------------------] 0x80010080-0x8001008F (16 bytes) [OK]
  gap                                        0x80010090-0x8001011F (144 bytes)
  [#---------------------------------------] 0x80010120-0x8001013F (32 bytes) [OK]
all 4 ranges rendered: True
gaps labelled: True
map screen visible: True
map content visible (file loaded): True
--- Bookmarks ---
Bookmarks - coming soon.

Saving and recalling memory bookmarks is not yet available. This feature is deferred to a future release.
bookmarks screen visible: True
SMOKE OK
```
The public gaps fixture has 4 contiguous ranges with real gaps between them. Loaded through the real `_apply_prepared_load` pipeline (the deferred `call_later` chain was drained), the Memory Map rendered all 4 ranges by address, all 3 inter-range gaps, the OK markers and the proportional coverage bars; the `#map_content` coverage container was revealed and the empty-state panel hidden once the file was present. The Bookmarks screen showed the "coming soon" placeholder. The smoke temp state was not persisted.

## 5. Risks

- **`EmptyStatePanel` id duplication (pre-existing, unchanged).** There are now 7 `EmptyStatePanel` widgets in the tree (2 remaining `ScreenScaffold` slots — Patch, Diff — plus Workspace, Issues and Memory Map), all carrying the shared id `#empty_state_panel`. This predates increment 9 and was flagged in the increment-7 packet. `_apply_empty_state` and every increment-9 test query the panel **by type, scoped to a screen** (`screen.query(EmptyStatePanel)`), never by the shared id, so the ambiguity is never hit. Unchanged risk surface.
- **`update_memory_map` is not defensive against an unmounted tree.** Unlike `_apply_empty_state` (which swallows a missing-widget exception), `update_memory_map` calls `query_one("#memory_map_panel", ...)` directly. In a mounted app — the only place `_apply_prepared_load`'s `_step_finalize` runs in production — this always succeeds. The one headless test that runs `_apply_prepared_load` without a mounted tree monkeypatches the renderer (see §2/§4). The trade-off: `update_memory_map` matches the non-defensive pattern of its `_step_finalize` sibling `update_project_labels` rather than the defensive `_apply_empty_state` pattern — a deliberate consistency choice (the chain steps assume a mounted app; only the empty-state helper, invoked from headless unit tests, is defensive). If a future headless test calls `_apply_prepared_load` without monkeypatching the renderers it would fail loud — which is the intended behavior, not a silent skip.
- **Memory Map gap line for very large gaps.** The gaps fixture's first gap spans ~2.1 GB (`2147549173 bytes`) because the fixture mixes a low-address range at 0x0 with high-address ranges near 0x80000000. The Memory Map renders the literal byte count; it is read-only and correct, but a real client image with a similar address layout would show a very large gap figure. This is faithful to the model data (LLR-012.1 — render existing data, do not editorialize) and is not a defect; noted only so a reviewer is not surprised by the figure.
- **Memory Map renders all ranges with no cap.** Unlike `update_sections` (which caps at `MAX_SECTIONS_PRIMARY_RANGES`), `MemoryMapPanel.render_ranges` iterates every range. For a normal firmware image (a handful to dozens of ranges) this is fine; a pathological image with tens of thousands of ranges would build a very long string. No LLR mandates a cap for the Memory Map and adding one would be unrequested scope; flagged as a known characteristic. The increment-12 snapshot baseline renders only the small public fixtures, so this is not exercised there.
- **No visual / interactive verification.** All checks are headless (`App.run_test()` / `pytest`). Real-terminal rendering of the Memory Map coverage strip, the fill bars and the Bookmarks placeholder was not eyeballed. A manual TUI pass is advisable before batch close.

## 6. Pending items

- **Manual TUI pass** — launch `s19tui --load examples/case_02_gaps_and_patch_targets/firmware.s19`, press `4` to open the Memory Map and confirm the coverage map, fill bars and gap lines render; press `8` to confirm the Bookmarks "coming soon" placeholder; press `4` again with no file (fresh launch) to confirm the Memory Map empty-state panel. Deferred to the Phase-4 validation gate.
- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment; must run in CI / a ruff-equipped environment before merge.
- **REQUIREMENTS.md traceability** — if `R-*` rows are mapped for the Memory Map / Bookmarks screens, they should be refreshed to cite `test_tui_directionb.py` TC-025 / TC-004 / TC-028. Not done here (out of the file scope; flagged for the docs increment).
- **Snapshot baseline (increment 12)** — the Memory Map and Bookmarks screens are part of the 3-scaffold × 120×30 snapshot set in the increment-12 matrix; the layout-drift verdict lands there.
- **A `MemoryMapPanel` range cap** — see §5. If a cap is later judged necessary it should be raised as a follow-up requirement, not added speculatively.

## 7. Suggested next task

**Increment 10 — Patch Editor + A↔B Diff scaffolds** (LLR-012.2, LLR-012.3, LLR-012.4). Extend `screens_directionb.py` with a `PatchEditorScreen` content widget (before/after hex-pane layout + address/value `Input` fields that are **not wired** to any patch-apply/undo/redo logic, plus a visible "patch logic deferred" notice) and an `AbDiffScreen` content widget (a static three-column layout — range list, hex A, hex B — with static, clearly-labelled placeholder hex rows in each column and a visible "PLACEHOLDER / diff deferred" marker). Populate `#screen_patch` / `#screen_diff` in `app.py`; add the styles; extend `tests/test_tui_directionb.py` with TC-026, TC-027 and the completion of TC-028 (enumerate `s19_app/` modules; AST-walk the new scaffolds for `bincopy`/`pya2l`/`crcmod`; assert those three absent from `pyproject.toml`; activate every scaffold — no exception). No patch engine, no second-file load path, no diff computation is wired.

**Do not start increment 10 — this increment (9) is complete and stops here.**
