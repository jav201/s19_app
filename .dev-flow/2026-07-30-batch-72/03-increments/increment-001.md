# Increment 001 — Legend two-pane layout (wide regime)

> **Scope:** LLR-072-5.1, LLR-072-5.2, LLR-072-7.1 · **Nodes:** AT-216, AT-218, TC-515, TC-516, TC-519
> Branch `claude/batch-72-design-defect-634a67`, base `54c4b29`. Artifact language: English.

## 1. What changed

**BLUF — the Legend body is now a two-pane wrapper, and every measured number in
`00-measurements.md` M-2/M-6 reproduced exactly on the shipped tree.**

| Change | Where | Effect |
|---|---|---|
| `LegendScreen.compose` yields `Horizontal(ScrollableContainer(card…, id="legend_card_pane"), ScrollableContainer(key…, id="legend_key_pane"), id="legend_body")` | `screens.py:1207-1238` | card left / key right; `#legend_body` **preserved as the wrapper** (P-12) |
| `_render_card()` / `_render_key()` called unchanged, widgets **re-parented** | same | LLR-072-7.1 — no data-layer edit; `legend.py` diff vs `origin/main` empty |
| `#legend_dialog { width: 96% }`; panes `3fr` / `2fr` + `height: 1fr` + `overflow-y: auto`; `#legend_body` `overflow-y: auto` → **`overflow: hidden`** | `styles.tcss:1535-1568` | one scroll context per pane instead of three nested |
| New test node file | `tests/test_legend_two_pane.py` (498 lines) | AT-216, AT-218 (pin), TC-515, TC-516, TC-519 |

Measured on the implemented tree (probe, mac @ `run_test(size=(120,30))` → `screen.size=Size(118,28)`):

```
body  Region(x=6, y=6, width=107, height=15) Horizontal children: 2  ids ['legend_card_pane','legend_key_pane']
card  Region(x=6, y=6, width=64,  height=15) children: 17  max_scroll_y 18
key   Region(x=70,y=6, width=43,  height=15) children: 6   max_scroll_y 0   scroll_offset Offset(x=0,y=0)
sev-warning row: Region(x=70, y=11, width=43, height=3)  contained in key pane: True
body contains key: True     body contains card: True
```

Identical to M-2 (dialog 113 / content 107 / card 64 / key 43 / body 15 / `max_scroll_y == 0`) and
M-6 (mac card 17 key 6; map card 20 key 7 — also re-measured, matches).

## 2. Files modified

| File | Status |
|---|---|
| `s19_app/tui/screens.py` | modified — `LegendScreen.compose` only (+ its docstring) |
| `s19_app/tui/styles.tcss` | modified — `#legend_dialog`, `#legend_body`, new `#legend_card_pane` / `#legend_key_pane` |
| `tests/test_legend_two_pane.py` | **new** |

3 files — within the ≤5 cap. **No** `.sev-*` / `.band-*` / `.legend-card-*` block touched (§1.2 OUT):
`git diff` on `styles.tcss` is confined to `:1535-1568`.

## 3. How to test

```bash
# the increment's own nodes
python -m pytest -q tests/test_legend_two_pane.py

# gate run (blast radius + BOTH frozen guards + C-34 render guard host), ONE run:
python -m pytest -q tests/test_legend_two_pane.py tests/test_tui_legend.py \
    tests/test_legend_n8.py tests/test_legend_scope_and_logwidth.py \
    tests/test_engine_unchanged.py tests/test_tui_directionb.py

# frozen set, direct:
git diff --name-only origin/main -- s19_app/core.py s19_app/hexfile.py \
    s19_app/range_index.py s19_app/validation s19_app/tui/a2l.py s19_app/tui/mac.py \
    s19_app/tui/color_policy.py s19_app/tui/legend.py
```

## 4. Test results

**Gate run — ONE complete run, exit code and tail read from that run's own output (C-19).**
`styles.tcss` changed ⇒ C-34 requires the FULL `tests/test_tui_directionb.py`, not a `-k` subset —
it is included below.

```
$ python -m pytest -q tests/test_legend_two_pane.py tests/test_tui_legend.py \
      tests/test_legend_n8.py tests/test_legend_scope_and_logwidth.py \
      tests/test_engine_unchanged.py tests/test_tui_directionb.py
........................................................................ [ 30%]
........................................................................ [ 60%]
........................................................................ [ 90%]
.......................                                                  [100%]
239 passed in 289.24s (0:04:49)
PYTEST_EXIT=0
```

**Frozen guards (C-27), both arms, explicit node run:**

```
$ python -m pytest -v tests/test_engine_unchanged.py -k tc027 tests/test_tui_directionb.py -k "tc031 or tc032 or tc027"
tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main PASSED
tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main PASSED
tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main PASSED
tests/test_tui_directionb.py::test_tc031_engine_imports_still_resolve PASSED
tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main PASSED
tests/test_tui_directionb.py::test_tc032_no_engine_test_function_is_skipped PASSED
tests/test_tui_directionb.py::test_tc032_directionb_tests_do_not_monkeypatch_engine_functions PASSED
===================== 11 passed, 164 deselected in 2.55s ======================
EXIT=0
```

**Frozen-set diff vs `origin/main` — empty (incl. `legend.py`, TC-519's subject):**

```
$ git diff --name-only origin/main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
      s19_app/validation s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py \
      s19_app/tui/legend.py
(no output)
$ git status --porcelain
 M s19_app/tui/screens.py
 M s19_app/tui/styles.tcss
?? tests/test_legend_two_pane.py
```

**No snapshot test failed** — consistent with premises P-2/P-3 (neither screen is snapshot-captured).

### AT-216 clause 4 — oracle mutation (C-32 discharge), executed

Mutation applied inside `_measure_key_pane`, immediately after the modal opens:

```python
legend = await _open_legend(app, pilot, "mac")
legend.query_one("#legend_key_pane").styles.display = "none"  # ORACLE MUTATION
await pilot.pause()
```

```
$ python -m pytest -q tests/test_legend_two_pane.py::test_at216_key_pane_shows_warning_row_without_scrolling
>       assert m["key_pane_in_body"], (
            f"the key pane {m['key_region']} is not inside #legend_body "
            f"{m['body_region']} - it is rendering off-dialog"
        )
E       AssertionError: the key pane Region(x=0, y=0, width=0, height=0) is not inside
E                       #legend_body Region(x=6, y=6, width=107, height=15) - it is rendering off-dialog
E       assert False
tests\test_legend_two_pane.py:201: AssertionError
=========================== short test summary info ===========================
FAILED tests/test_legend_two_pane.py::test_at216_key_pane_shows_warning_row_without_scrolling
1 failed in 1.74s
```

Mutation **reverted**; the node is green in the gate run above.

> **Reported finding, not improvised around.** The AT goes RED as required, but it goes RED on
> **clause 2b only** — the arm the Phase-2 re-gate added. Clauses 1 and 2a are **blind** to
> `display: none`, because the pane *and* its rows both collapse to `Region(0,0,0,0)` and a zero
> region trivially `contains_region` a zero region. This does not make 2a vacuous on the real tree
> (measured: row `Region(70,11,43,3)` genuinely inside key `Region(70,6,43,15)`), but it does mean
> the re-gate's N-3 addition is load-bearing under exactly this mutation. Requirement text left
> untouched; clauses implemented exactly as §3 states.

## 5. Risks

| Risk | State |
|---|---|
| **Focus traversal (§6.3 / C-16 / A-10) — flagged `assumed, verify at Phase 3`.** | **Verified, and it changed.** `on_mount` still leaves focus on `#legend_close` (measured on all 6 probed view/size combos). The tab CYCLE grew from 2 stops to 3: `focus_chain == [ScrollableContainer#legend_card_pane, ScrollableContainer#legend_key_pane, Button#legend_close]` (`ScrollableContainer.can_focus is True` on textual 8.2.8, as the requirement predicted). No test asserts a tab order, and all 3 legend files stay green. ⚠️ Not covered by any node — carried to Inc-2's re-check. |
| **AT-216 has one row of slack** (§6.3) | Live: key content 14 rows in a 15-row pane. Guarded at the cause by the `max_scroll_y == 0` clause. Any reworded MAC/map meaning can trip it. |
| `#legend_dialog` width 70% → 96% | `test_at023e` (modal-within-terminal at 80x30) re-run green; measured right/bottom stay inside the screen. |
| `overflow: hidden` on `#legend_body` | Intended (LLR-072-5.2). If a future pane loses `height: 1fr`, content silently clips instead of scrolling — TC-518 (Inc-2) pins the related `height: auto` exclusion, but nothing pins `overflow: hidden` itself. |

## 6. Pending items

- **Increment 2** (LLR-072-6.1/6.2, AT-217 + TC-517/518) — the floor regime and the runtime pane
  reorder. Until it lands, the floor stacks nothing: at 80x24 the panes stay side-by-side at
  card 40 / key 28 cols (measured), which is the pre-Inc-2 state, not a regression.
- `REQUIREMENTS.md` amendments (`R-LEGEND-MODAL-001`, `R-LEGEND-GEOMETRY-001`) are **Inc-4** work per
  the PLAN cut — not done here.
- Test ledger: `A = +5` nodes this increment (AT-216, AT-218, TC-515, TC-516, TC-519).

## 7. Suggested next task

Increment 2 — the `legend-narrow` width-regime hook (`on_mount` + `on_resize` reading
`self.app.size.width`, `move_child` reorder) and the `#legend_dialog.legend-narrow`-prefixed CSS,
with AT-217 + TC-517/518.

## Evidence checklist

- [x] Tests/type checks/lint pass — 239 passed, exit 0, one complete run (§4).
- [x] No secrets in code or output — diff is layout CSS + compose + a test file.
- [x] No destructive commands run — no `rm`, no force push, no reset; `git status` shown.
- [x] File count within cap — 3 of 5.
- [x] Review packet attached — this document.
- [x] Frozen guards both arms green + frozen-set diff empty (§4).
- [x] C-26 reverse-grep re-run for `legend_body`, `legend_card_pane`, `legend_key_pane`,
      `legend_dialog`, `legend_close`, `legend_mac_warning_sample` — the only non-test consumer of
      `#legend_dialog` geometry is `test_tui_legend.py:288` (clipping check, re-run green).
- [x] No snapshot regenerated; none failed.
