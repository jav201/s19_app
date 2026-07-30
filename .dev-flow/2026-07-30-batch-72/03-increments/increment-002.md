# Increment 002 — Legend floor regime (key first)

> **Scope:** LLR-072-6.1, LLR-072-6.2 · **Nodes:** AT-217, TC-517, TC-518
> Branch `claude/batch-72-design-defect-634a67`, base `54c4b29` (Inc-1 uncommitted in the same tree).
> Artifact language: English.

## 1. What changed

**BLUF — the modal now owns its own width regime AND its pane order, and every threshold
LLR-072-6.2 pins was reproduced exactly: at 80x24 key h=4 / card h=5, `key.max_scroll_y` 6 (mac) /
7 (map), with the wide regime unchanged at card 64 / key 43.**

| Change | Where | Why it is this and not CSS |
|---|---|---|
| `_LEGEND_NARROW_WIDTH: int = 120` module constant | `screens.py:1029-1036` | the SAME breakpoint as `app.py:6202`; cited in the comment, and the TC quotes the constant, never `120` |
| `LegendScreen._apply_width_regime(width)` — toggles `legend-narrow` on `#legend_dialog` and reorders `#legend_body` via `move_child`, idempotently | `screens.py:1247-1280` | `width-narrow` only reaches `#workspace_shell` / `#workspace_body` on the BASE screen; a pushed `ModalScreen` is a descendant of neither, and textual 8.2.8 has no CSS media queries and **no CSS ordering property** — so document order IS the stacking order |
| `on_mount` calls it with **`self.app.size.width`**; new `on_resize` does the same | `screens.py:1282-1288` | `self.size.width` is 118 under `run_test(size=(120,30))` (`Screen { padding: 1 }`) and would flip the wide case into the narrow regime |
| Three rules, **every one prefixed `#legend_dialog.legend-narrow`** | `styles.tcss:1566-1588` | unprefixed they have equal specificity to the wide rules and later source order, so they would win in BOTH regimes and push the key pane to `x=113`, outside the body |

Measured on the implemented tree (probe; `app.size` is the requested tuple, `screen.size` is 2 smaller):

```
view=mac 80x24   legend-narrow: True   body children ['legend_key_pane','legend_card_pane']
  body Region(x=6,y=6,w=68,h=9)   key Region(x=6,y=6,w=68,h=4) max_scroll_y 6   card Region(x=6,y=10,w=68,h=5)
view=map 80x24   legend-narrow: True   key h=4 max_scroll_y 7   card h=5
view=mac 120x30  legend-narrow: False  body children ['legend_card_pane','legend_key_pane']
  card Region(x=6,y=6,w=64,h=15)   key Region(x=70,y=6,w=43,h=15) max_scroll_y 0
resize 120x30 -> 80x24 : flips to narrow + key-first
resize 80x24 -> 120x30 : flips back to wide + card-first (hook is idempotent, no exception)
```

## 2. Files modified

| File | Status |
|---|---|
| `s19_app/tui/screens.py` | modified — constant, `_apply_width_regime`, `on_mount`, `on_resize`, `events` import |
| `s19_app/tui/styles.tcss` | modified — three `#legend_dialog.legend-narrow` rules appended |
| `tests/test_legend_two_pane.py` | modified — AT-217, TC-517, TC-518 added (Inc-1 created it) |

3 files — within the cap. Still **no** `.sev-*` / `.band-*` / `.legend-card-*` edit.

## 3. How to test

```bash
python -m pytest -q tests/test_legend_two_pane.py

# gate run (blast radius + BOTH frozen guards + the C-34 render guard host), ONE run:
python -m pytest -q tests/test_legend_two_pane.py tests/test_tui_legend.py \
    tests/test_legend_n8.py tests/test_legend_scope_and_logwidth.py \
    tests/test_engine_unchanged.py tests/test_tui_directionb.py
```

## 4. Test results

**Gate run — ONE complete run; exit code and tail from that run's own output (C-19).**

```
$ python -m pytest -q tests/test_legend_two_pane.py tests/test_tui_legend.py \
      tests/test_legend_n8.py tests/test_legend_scope_and_logwidth.py \
      tests/test_engine_unchanged.py tests/test_tui_directionb.py
........................................................................ [ 29%]
........................................................................ [ 59%]
........................................................................ [ 89%]
..........................                                               [100%]
242 passed in 313.46s (0:05:13)
PYTEST_EXIT=0
```

(239 at the Inc-1 gate + the 3 nodes this increment adds.)

**Frozen guards (C-27), both arms:**

```
$ python -m pytest -v tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "tc027_engine or tc031 or tc032"
tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main PASSED
tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main PASSED
tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main PASSED
tests/test_tui_directionb.py::test_tc031_engine_imports_still_resolve PASSED
tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main PASSED
tests/test_tui_directionb.py::test_tc032_no_engine_test_function_is_skipped PASSED
tests/test_tui_directionb.py::test_tc032_directionb_tests_do_not_monkeypatch_engine_functions PASSED
====================== 7 passed, 168 deselected in 0.78s ======================
EXIT=0
```

```
$ git diff --name-only origin/main -- <frozen set incl. s19_app/tui/legend.py>
(no output)
$ git status --porcelain
 M s19_app/tui/screens.py
 M s19_app/tui/styles.tcss
?? .dev-flow/2026-07-30-batch-72/03-increments/
?? tests/test_legend_two_pane.py
```

**Ledger reconciliation** (`post = base − D + A`, base **2379** @ `b556e35`, `D = 0` in these two
increments, `A = 8`):

```
$ python -m pytest --collect-only -q | tail -2
2387 tests collected in 0.79s
```

2379 + 8 = **2387** ✅.

**No snapshot test failed** — P-2/P-3 hold; nothing regenerated.

### Non-vacuity discharges (two counterfactuals, executed then reverted)

Neither was demanded by the requirement; both were run because AT-217 clause 2 is *declared* to be
the tooth and TC-517 is *declared* to distinguish "the rule fired" from "the panes collapsed" — a
declaration is not evidence.

**(a) The degenerate regime.** `#legend_dialog.legend-narrow #legend_key_pane` `height: 1fr` →
`height: auto`:

```
E  AssertionError: the card pane is starved (the degenerate `height: auto` key regime):
E                  card=Region(x=6, y=16, width=68, height=1)
E  assert 1 >= 2
FAILED tests/test_legend_two_pane.py::test_at217_floor_stacks_key_above_card_and_key_is_reachable
FAILED tests/test_legend_two_pane.py::test_tc518_key_pane_never_uses_height_auto
```

The card collapses to exactly `height=1` — M-3's measured prediction, reproduced. Clauses 1 and 3 of
AT-217 stay GREEN in that regime, so clause 2 is the *only* arm that fails: the tooth is real.

**(b) The reorder removed.** `move_child` call replaced by a no-op inside `_apply_width_regime`:

```
E  AssertionError: width-regime hook misbehaved: [..., ('one column below', True,
E     ['legend_card_pane', 'legend_key_pane']), ...]
E  At index 1 diff: (..., ['legend_card_pane','legend_key_pane']) != (..., ['legend_key_pane','legend_card_pane'])
E  AssertionError: the key pane must stack ABOVE the card at the floor:
E                  key=Region(x=6, y=10, width=68, height=5) card=Region(x=6, y=6, width=68, height=4)
FAILED tests/test_legend_two_pane.py::test_tc517_width_regime_flips_class_and_pane_order
FAILED tests/test_legend_two_pane.py::test_at217_floor_stacks_key_above_card_and_key_is_reachable
```

Note the shape of that failure: the `legend-narrow` **class still flips** (`True` at "one column
below") and the panes still stack — only the ORDER is wrong. This is exactly the re-gate's N-1
finding executed against the fix: CSS alone stacks, it cannot order.

Both mutations reverted; the gate run above is on the reverted tree.

## 5. Risks

| Risk | State |
|---|---|
| **Focus traversal (§6.3, `assumed — verify at Phase 3`)** | **Re-checked at this increment.** Initial focus is still `#legend_close` in both regimes. The tab cycle now also follows the pane ORDER: wide `[card, key, close]`, narrow `[key, card, close]` — i.e. the reorder changes tab order too, which is the desirable direction (the key is first at the floor). No test asserts a tab order anywhere; all three legend files stay green. |
| The hook fires on every `Resize` | `_apply_width_regime` is idempotent (guarded `move_child`); measured across four regime transitions with no exception and no drift. `on_resize` reads `self.app.size.width`, not `event.size`, so a screen-vs-app size confusion cannot creep back in. |
| `legend-narrow` vs `width-narrow` | Deliberately different class names. Reverse-grep shows `legend-narrow` appears only in `screens.py` + the three new `styles.tcss` rules; no rule anywhere else can match it. |
| Floor key is scroll-only | By design and by measurement (9-row budget vs a 10/11-row key) — G-4 is satisfied at ≤1 interaction, per §6.4. |
| CSS specificity | Every narrow rule is prefixed. TC-517 + AT-216 (wide, unchanged) together would catch a regression: AT-216 asserts `#legend_body.contains_region(key_pane)` at 120x30, the exact symptom the unprefixed slip produced. |

## 6. Pending items

- **Inc-3** (CRC compose) and **Inc-4** (G-1 guard + `REQUIREMENTS.md`) — not started; out of this
  session's scope.
- `REQUIREMENTS.md` `R-LEGEND-MODAL-001` / `R-LEGEND-GEOMETRY-001` amendments still owed (Inc-4).
  `R-LEGEND-GEOMETRY-001`'s Code line still documents `#legend_body { height: 1fr; overflow-y: auto }`
  — now `overflow: hidden`, with `overflow-y: auto` on the panes.
- Test ledger for the legend half: `A = +8` nodes (AT-216, AT-217, AT-218, TC-515..519).
- Nothing pins `#legend_body { overflow: hidden }` itself (carried from Inc-1's risk list).

## 7. Suggested next task

Increment 3 — the CRC Designer compose (LLR-072-1.1/1.2, 2.1-2.4, 8.1; AT-213/215/219 +
TC-510..513, including the AT-B59-05 **deletion**). It shares only `styles.tcss` with this work, so
it can start from this tree with no rebase.

## Evidence checklist

- [x] Tests/type checks/lint pass — 242 passed, exit 0, one complete run (§4).
- [x] No secrets in code or output.
- [x] No destructive commands run — mutations were file edits, both reverted and re-verified by
      `git diff --stat` / grep.
- [x] File count within cap — 3 of 5.
- [x] Review packet attached — this document.
- [x] Frozen guards both arms green; frozen-set diff vs `origin/main` empty (`legend.py` included).
- [x] C-26 reverse-grep re-run for `_LEGEND_NARROW_WIDTH`, `_apply_width_regime`, `legend-narrow`,
      `on_resize`, `legend_key_pane`, `legend_card_pane` — no consumer outside `screens.py`,
      `styles.tcss` and the new test file.
- [x] No snapshot regenerated; none failed.
