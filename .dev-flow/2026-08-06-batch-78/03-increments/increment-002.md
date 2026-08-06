# Increment 002 — HLR-122, the selectable run list

> **Scope:** §7 Inc-2 · HLR-122 / LLR-122.1 / LLR-122.2 / LLR-122.3 · the C-38 sweep · the `test_tc029` rewrite (Q-M2)
> **Nodes:** `AT-B78-15…19` (+ `TC-B78-20` riding in `AT-B78-16`), `TC-B78-17`, `TC-B78-18`, `TC-B78-19`, `TC-B78-21`, `TC-B78-22`, `TC-B78-47`, `TC-B78-48`, and `TC-029` rewritten in place
> **Gate:** C-34 + full `test_tui_diff_compare_realpath.py` + full `test_tui_patch_big.py`; `TC-011` green; **`test_tc029` reddens under `DISPLAY_MAX_RUNS 128 → 100000` after the rewrite**
> Branch `claude/batch-78-cmdbar-a2bdiff` · base `d771ab8` · artifact language: English.

---

## BLUF

**`#diff_range_list` is a real `ListView`, every run is reachable by keyboard and
by mouse, and `AT-B78-19` upgrades from PIN to GATE. Three of this increment's
findings are spec figures that did not survive execution — and two of them are
the SAME defect, in the requirements' own remedy for that defect.**

| # | Finding | Verdict |
|---|---|---|
| **F-1** | **§5.3 / Q-m2's guard-placement rule is insufficient as worded, and it cost `test_tc029` and `AT-B78-18` their gate.** The rule says the constant-quoting guard is *"evaluated **after the capture**, so the mutation reddens the **assertion** rather than raising in the guard"*. Executed: with the guard after the capture but before the substantive clauses it is still the **first assertion**, so `128 → 100000` reddened `fixture (200) must exceed the display cap (100000)` and **the capping clause never ran**. A node that fails for "I noticed the constant moved" certifies the same nothing the inert form did. The property is not *after the capture*, it is **after the substantive assertions**. Fixed; re-executed transcript in §4.5. | ❌ **spec defect — found only by executing the mutation** |
| **F-2** | **The identical defect, one node over, in `AT-B78-19` — and I wrote it.** With the structural `BINDINGS` census asserted first, §5.3's declared mutation (bind `k` on the run list) reddened the **census**, leaving *"the Legend no longer opens"* — the clause the requirement is actually about — **unproven**. Reordered behaviour-first; the mutation now reddens `'k' must still open the Legend`. | ❌ **my defect, same family as F-1** |
| **F-3** | **Inc-1's carry into Inc-2 is FALSE when executed.** It warned that per C13 the `#diff_range_list` id rule *"will outrank the new widget's `DEFAULT_CSS` — including `ListView`'s own scrolling and highlight styles"*. Measured: `overflow_y` resolves to **`auto`** (untouched) and the highlight rules live on **`ListItem`**, a different element the id selector cannot reach. A CSS id selector overrides only the properties it **declares**. **`styles.tcss` was therefore not edited — 3 files, not §7's planned 4.** | ⚠️ **carry premise refuted by measurement** |
| **F-4** | **`A-4` / `P-47` settled TRUE by execution: no interaction.** Stock `ListView` binds `up`/`down`/`enter` (plus `ScrollableContainer`'s `left`/`right`/`home`/`end`/`page*`), **all `priority=False`**; the four App `priority=True` bindings are `ctrl+k`/`ctrl+d`/`ctrl+l`/`ctrl+s` — a **disjoint** key set. Asserted live in `AT-B78-19`: `ctrl+k` opens the palette with the list focused **and** `down` moves the list's own selection in the same run. | ✅ **UNDECIDABLE → TRUE** |
| **F-5** | **`AT-B78-19` upgrades PIN → GATE.** Its precondition now holds — `set_focus` on the run list takes (`app.focused is` the `ListView`), where on the pre-change `Static` it silently landed on `RailItem(id='rail_item_workspace')`. Its declared mutation reddens it on its declared clause. | ✅ **PIN → GATE** |
| **F-6** | **Sixth silent mutation failure this batch, and it was mine.** My first `M3` re-run patched the harness's **label** and not its **value**; the applied-check passed (token present, sha moved) because the "new" token was the *previous* new token. An applied-check verifies a substitution happened, **never that it is the one you meant**. Caught by the sha being byte-identical to the prior run. | ⚠️ **process finding** |
| **F-7** | **§5.4/LLR-123.1's phantom is gone.** `_render_run_windows`'s docstring cited `on_data_table_row_selected` as a caller; that symbol has **0 definitions** in the module. Removed — it is a lie in the file this increment edits, and Inc-4 is the increment that will supply the real selection path. | ✅ removed |

**The C-38 census reproduced to the digit.** §5.3/LLR-122.1's *"`diff_range_list`
8 hits / 3 files"* is exactly what disk says today: **9 hits across 3 test
modules** (8 before Inc-1's helper line), and the third module —
`tests/test_tui_directionb.py:5711`, shared with Lane 1 — reads
`bool(screen.query("#diff_range_list"))`, which is **type-agnostic and needed no
change**. That file was not touched.

---

## 1. What changed

**`#diff_range_list` goes from `Static("Runs", …, markup=True)` to
`ListView(id="diff_range_list")`.** `_render_run_list` no longer joins lines into
one string; it rebuilds the list as widgets:

| Row kind | Widget | DOM handle | Selectable |
|---|---|---|---|
| `Runs: N`, `A artifacts: …`, `B artifacts: …`, the `showing N of M` notice | `ListItem(Label(text, markup=False), classes="diff-run-note", disabled=True)` | class only | **no** |
| one per displayed run | `ListItem(Label("[colour]idx range kind[/]", markup=True), id=f"diff_run_{i}", classes="diff-run-entry")` | `#diff_run_{i}` | **yes** |

**Three design decisions, each with its executed reason.**

1. **The context rows ride inside the same `ListView`, `disabled=True`.**
   Textual's `ListView.action_cursor_up` / `action_cursor_down` skip disabled
   children (`if not item.disabled`, verified in `textual==8.2.8` source), and a
   click on a disabled `ListItem` never posts `_ChildClicked` — so the
   keyboard- **and** mouse-reachable sets are exactly the run indices, while the
   header and the G-9 notice stay beside the runs they describe. The
   alternative — a sibling `Static` above the list — would have needed a wrapper
   container and moved the `width: 1fr` off the id the requirement names.
2. **The run index is carried by the shipped DOM id, not by a widget
   attribute.** No `ListView` subclass exists, so **C12 cannot bite** — there is
   no new widget class on which `_nodes` or `_context` could be shadowed, and
   `ListView` uses `_nodes` heavily.
3. **The note rows are `markup=False` at construction rather than
   `rich.markup.escape`d at the call site.** The artifact-usage summaries are
   the one file-derived string reaching this column (C-17 / LLR-122.1), and the
   widget-type swap is precisely where an escape call goes missing. A
   `markup=False` sink cannot lose it. `from rich.markup import escape` is gone
   from the method.

**Initial selection** is the first run entry when runs exist and `None`
otherwise, which preserves today's behaviour (`_render_run_windows(0)`) and
gives Inc-4 a coherent starting state. `_render_run_windows` is still called
only with the literal `0` — **selection does not yet drive the windows; that is
Inc-4 (LLR-123.1) and is deliberately not built here.**

### The thirteen nodes

| Node | Id(s) | Kind | Subject |
|---|---|---|---|
| `test_at_b78_15_every_run_reachable_by_keyboard` | `AT-B78-15` | **GATE** | arrows alone; reached set **set-equal** to `range(R)`, `R` from the fixture |
| `test_at_b78_16_every_run_reachable_by_mouse` | `AT-B78-16`, `TC-B78-20` | **GATE** | clicks alone, focus released; the off-viewport count is **asserted > 0** |
| `test_at_b78_17_exactly_one_entry_is_visibly_selected` | `AT-B78-17` | **GATE** | exactly one `-highlight`; resolved `(background, color, text_style)` distinct; ≥2-row guard asserted |
| `test_at_b78_18_display_caps_and_notice_survive` | `AT-B78-18` | **PIN** | painted rows `< 200`; the notice's two parsed numbers `== (painted, 200)` |
| `test_at_b78_19_app_keys_survive_run_list_focus` | `AT-B78-19` | **GATE** (was PIN) | `k` → Legend, `j` → its App action, `ctrl+k` → palette, all with the list focused; the list still navigates; census of `j/k/p/o` |
| `test_tc029_display_caps_bound_on_screen_runs` | `TC-029` | **GATE** (was INERT) | rewritten — the panel's **model** is capped while the header stays complete |
| `test_tc_b78_17_empty_comparison_has_no_selectable_entry` | `TC-B78-17` | GATE | 0 runs → 0 entries, no selection, `Runs: 0` still renders |
| `test_tc_b78_18_exactly_cap_runs_shows_no_notice` | `TC-B78-18` | GATE | exactly the cap → all painted, **no** notice |
| `test_tc_b78_19_single_run_is_selectable` | `TC-B78-19` | GATE | 1 run selectable; AT-17's style clause explicitly skipped |
| `test_tc_b78_21_zero_length_run_is_selectable` | `TC-B78-21` | GATE | `end == start` still renders both endpoints and is reachable |
| `test_tc_b78_22_keys_before_any_comparison_do_not_crash` | `TC-B78-22` | GATE | keys with no comparison: no raise, `index is None` |
| `test_tc_b78_47_arrows_at_the_ends_do_not_wrap` | `TC-B78-47` | GATE | `up` at first / `down` at last are no-ops, not wraps |
| `test_tc_b78_48_hostile_artifact_summary_renders_verbatim` | `TC-B78-48` | GATE | `[red]evil[/] [/nope] [link=…]` renders verbatim, no `MarkupError` |

**`test_tc029` and `AT-B78-18` are deliberate near-siblings on one clause, split
by observable.** LLR-122.3 requires the rewrite and forbids deleting the node
(its registry row is `LIVE` and keeps its id). Both were given a subject the
other does not cover: `test_tc029` reads `panel._runs` and the header
(**model**), `AT-B78-18` reads the painted rows and the notice's own numbers
(**view**). An implementation that caps its model but paints every run passes the
first and fails the second — executed as **M8**, where `AT-B78-18` reddens on
`says 'showing 128 of 200 runs' while 1 of 200 were painted` and `test_tc029`
stays green.

**All Inc-2 nodes run at 132×44, and that is load-bearing, not convenient.**
Inc-1 measured the diff result area at a **content** height of **0** at both
80×24 and 120×30 — the command-bar rows survive until Inc-10 — so at those sizes
no run row is painted and a mouse or scroll acceptance would be unfalsifiable.
132×44 is the only size at which HLR-122's observables exist today.

---

## 2. Files modified

| File | Status |
|---|---|
| `s19_app/tui/screens_directionb.py` | modified — **+57 / −20** (import, `compose`, `_render_run_list`, new `_run_note_item`, two docstring corrections) |
| `tests/test_tui_diff_screen.py` | modified — **+760 / −25** (Inc-2 harness, 12 new nodes, `test_tc029` rewritten, two C-38 re-points) |
| `tests/test_tui_diff_compare_realpath.py` | modified — **+21 / −3** (C-38 re-point: `_run_list_text` helper + 2 call sites) |

**3 files — §7 planned 4; `styles.tcss` was measured unnecessary (F-3). Cap is 5.**

**Not touched:** `s19_app/tui/styles.tcss`, `tests/test_tui_directionb.py`
(shared with Lane 1 — its one `#diff_range_list` reference is type-agnostic),
`.dev-flow/state.json`, `PLAN.md`, `00-measurements.md`, `01-requirements.md`,
the `02-review-*.md` files, `increment-000*` / `increment-001*`,
`AT-TC-REGISTRY.jsonl`, `prototypes/memmap2.*`, `build/`, every snapshot SVG.
**`git add -A` was never used. `git stash` was never used.**

---

## 3. How to test

```bash
# the increment's own file
python -m pytest tests/test_tui_diff_screen.py -q -p no:randomly

# gate suite + every C-26 consumer of a touched id, ONE run, FULL form
python -m pytest tests/test_tui_directionb.py tests/test_tui_commandbar.py \
    tests/test_tui_diff_screen.py tests/test_tui_variants.py \
    tests/test_tui_patch_variant.py tests/test_loadfilescreen_input.py \
    tests/test_tui_diff_compare_realpath.py tests/test_tui_report_filter_surface.py \
    tests/test_report_off_ui_thread.py tests/test_tui_patch_big.py \
    tests/test_tui_patch_json.py tests/test_id_registry.py -q -p no:randomly

# the expected drift - DO NOT regenerate locally (C9, Inc-12 owns regen)
python -m pytest tests/test_tui_snapshot.py -q -p no:randomly

# §7's declared Inc-2 gate: test_tc029 must REDDEN under the cap mutation
#   substitute `DISPLAY_MAX_RUNS = 128` -> `= 100000` in screens_directionb.py,
#   confirm the token is present and the file sha moved, run the node, restore.
```

---

## 4. Test results

### 4.1 The increment's own file

```
$ python -m pytest tests/test_tui_diff_screen.py -q -p no:randomly
......................                                                   [100%]
22 passed in 55.35s
```

### 4.2 Gate suite + C-26 consumers — ONE run, FULL form, on the settled tree

```
$ python -m pytest tests/test_tui_directionb.py tests/test_tui_commandbar.py \
    tests/test_tui_diff_screen.py tests/test_tui_variants.py \
    tests/test_tui_patch_variant.py tests/test_loadfilescreen_input.py \
    tests/test_tui_diff_compare_realpath.py tests/test_tui_report_filter_surface.py \
    tests/test_report_off_ui_thread.py tests/test_tui_patch_big.py \
    tests/test_tui_patch_json.py tests/test_id_registry.py -q -p no:randomly
........................................................................ [ 20%]
........................................................................ [ 40%]
........................................................................ [ 61%]
........................................................................ [ 81%]
................................................................         [100%]
352 passed in 475.36s (0:07:55)
```

`tests/test_tui_directionb.py` runs **whole** (C-34) — `TC-011`, the frozen
`_PRE_BATCH_BINDINGS` guard, the rail census and the markup-safety scans are all
inside that 352.

**C-26 reverse grep — every touched symbol / id / class swept across the whole
`tests/` tree.** `tests/test_tui_patch_json.py` is in the run above **because of
it**; it was not in Inc-1's 11-module set.

| touched symbol / id | consuming modules in `tests/` |
|---|---|
| `#diff_range_list` (9 hits / 3 files) | `test_tui_diff_screen.py`, `test_tui_diff_compare_realpath.py`, **`test_tui_directionb.py`** (type-agnostic, unchanged) |
| `AbDiffPanel` | + `test_tui_patch_big.py`, **`test_tui_patch_json.py`** |
| `render_comparison`, `_apply_display_caps`, `DISPLAY_MAX_RUNS`, `_render_run_list` | already in the set above |
| `.diff-run-entry`, `.diff-run-note`, `diff_run_*`, `_run_note_item` | **0** prior consumers — net-new |

### 4.3 Snapshot drift — recorded, NOT regenerated

```
$ python -m pytest tests/test_tui_snapshot.py -q -p no:randomly
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[diff-comfortable-120x30]
1 failed, 31 passed, 1 warning in 57.59s
```

**Still exactly one cell — the same one Inc-1 drifted**, `[diff-comfortable-120x30]`,
the only diff golden in the matrix (C2). **No new cell drifted**, which is the
evidence that a `ListView` mounted under `#diff_columns` did not leak into any
other screen. Regen is Inc-12's, in canonical CI only (textual 8.2.8 pin, C9).

### 4.4 Ledger

| Quantity | Value | Form |
|---|---|---|
| after Inc-1 | **2612** | derived by Inc-1 |
| deleted (`D`) | **0** | `test_tc029` was rewritten in place, not deleted — its `LIVE` registry row keeps its id, so **G2 is unaffected** |
| added (`A`) | **12** | 5 ATs + 7 TCs |
| **post = 2612 − 0 + 12** | **`2624 passed / 2 skipped / 3 xfailed`** | **derived** |
| **post, honestly, until Inc-12** | **`2623 passed / 1 FAILED / 2 skipped / 3 xfailed`** | the drifted snapshot cell is red by design |

⚠️ **The full suite was NOT executed** — the targeted 12-module set was
(7:55 vs ~26 min). The executed evidence is §4.2's **352 passed / 0 failed**
plus §4.3's **31 passed / 1 failed**, each read from **one run's own output**
(C-19). `2624` is arithmetic. Any merge before Inc-12 ships a red suite.

**Node count, against PINNED SHAs** (not `HEAD~1`):

```
$ git show d771ab8:tests/test_tui_diff_screen.py | grep -c "^def test_"           # pinned base
10
$ grep -c "^def test_" tests/test_tui_diff_screen.py                              # working tree
22
$ git show d771ab8:tests/test_tui_diff_compare_realpath.py | grep -c "^def test_"
6
$ grep -c "^def test_" tests/test_tui_diff_compare_realpath.py
6
```

### 4.5 Counterfactuals — nine mutations, each APPLIED-CHECKED, each SHA-restored

Mutations have silently failed to apply **six** times in this batch (§BLUF F-6
is the sixth and it was mine), so every run below asserts the substituted token
is present **and** that the file's sha-256 differs from the fixed tree *before*
pytest is invoked, and asserts the sha matches again after the restore.
Mutations are applied to a **copy of the fixed tree**, never to the pre-change
tree, so a red result is a red **assertion** and not an import error on an older
tree — with CF-0's stated exception.

Fixed-tree sha-256:
`screens_directionb.py` = `f74869cd773ca2f8f55387f8508f0d11655cffe5359824891b83c52835ac2c5e`
`styles.tcss` = `449fb6501f0ea2925354fa5aed1610a75f6e52865e94b7706e77e8ef0c4d8ce7` (**unchanged by this increment**)

**Per-arm verdicts (CC-1) — RED/GREEN per resolved node id, never an exit code:**

| # | Substituted VALUE | `15` | `16` | `17` | `18` | `19` | `tc029` | `47` | `48` |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **CF-0** | *(whole increment reverted — `screens_directionb.py` at `d771ab8`)* | 🔴ᵉ | 🔴ᵉ | 🔴ᵉ | 🔴ᵉ | 🔴ᵉ | 🔴ᵉ | 🔴ᵉ | 🔴ᵉ |
| **M1** | note rows' `disabled` **`True` → `False`** | **🔴** | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | **🔴** | 🟢 |
| **M2** | `#diff_range_list` `overflow-y` **`auto` → `hidden`** | 🟢 | **🔴** | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| **M3** | highlight `color` → **`$fg-base`** | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| **M3b** | highlight `(background, color, text-style)` → **`(transparent, $foreground, none)`** | 🟢 | 🟢 | **🔴** | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| **M4** | `DISPLAY_MAX_RUNS` **`128` → `100000`** — §7's declared Inc-2 gate | 🟢 | 🟢 | 🟢 | **🔴** | 🟢 | **🔴** | 🟢 | 🟢 |
| **M5** | `_render_run_list(total_runs=…)` **`len(runs)` → `len(capped)`** | 🟢 | 🟢 | 🟢 | **🔴** | 🟢 | **🔴** | 🟢 | 🟢 |
| **M6** | the run list binds **`k`** (§5.3's declared `AT-B78-19` mutation) | 🟢 | 🟢 | 🟢 | 🟢 | **🔴** | 🟢 | 🟢 | 🟢 |
| **M7** | note row `markup` **`False` → `True`** | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | **🔴** |
| **M8** | entries built from **`self._runs[:1]`** | **🔴** | **🔴** | **🔴** | **🔴** | **🔴** | 🟢 | **🔴** | 🟢 |

ᵉ = red by **exception**, not by assertion — see CF-0.
**M3 is recorded as executed and INERT** even though it was a mutation-design
error rather than a test defect (F-6): its value never reached the third
component of the triple. Recording the failed attempt is the point.

**CF-0 — RED today, all eleven, but by ERROR not assertion.** Stated rather than
dressed up: a whole-revert of a **widget-type swap** cannot fail on an
assertion, because the type-qualified query is the first thing that touches the
subject. The per-clause mutations M1–M8 are the assertion-level discharges.

```
applied: reverted to d771ab8; sha 4caa72dd9a372164 != fixed f74869cd773ca2f8
1                                          # the pre-change Static line is back
E   textual.css.query.WrongType: Node matching '#diff_range_list' is the wrong
E     type; expected type 'ListView', found Static(id='diff_range_list')
11 failed, 11 deselected in 10.01s
RESTORED sha f74869cd773ca2f8  MATCH=True
```

**M1 — `AT-B78-15`'s own subject, and it discriminates:**

```
############ MUTATION M1  note rows selectable (disabled True -> False) ############
applied: s19_app/tui/screens_directionb.py  token_present=True  sha 91eb057258045624 != fixed f74869cd773ca2f8 -> True
E   AssertionError: every keyboard stop must land on a run entry, never on a
E     header or notice row; walk was [None, None, None, 0, 1, 2, 3, 4, 5, 5]
E   AssertionError: the walk must pin at both ends; reached None and 3
2 failed, 6 passed in 20.89s
############ M1 REVERTED - sha MATCH=True ############
```

**M2 — `AT-B78-16`'s subject alone; the scroll clause is live:**

```
############ MUTATION M2  run list overflow-y auto -> hidden ############
applied: s19_app/tui/styles.tcss  token_present=True  sha 8f756db3cfed6bbf != fixed 449fb6501f0ea292 -> True
E   AssertionError: the mouse-reachable run set must equal the displayed run
E     set; reached [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
1 failed, 7 passed in 19.92s
############ M2 REVERTED - sha MATCH=True ############
```

Ten of twenty runs reachable — exactly the viewport — with `AT-B78-15` green
because six runs fit. The two nodes are not co-passengers.

**M3 → M3b — the mutation-design error, then the working substitution (F-6):**

```
############ MUTATION M3  highlight styled identically to an unselected row ############
applied: s19_app/tui/styles.tcss  token_present=True  sha 0edcb9dcae0eadd6 != fixed 449fb6501f0ea292 -> True
8 passed in 20.19s                                     <- GREEN == the value missed

  diagnosis, executed on the mutated tree:
    diff_run_0  -highlight=True   Color(0,0,0,a=0)  Color(233,233,233)  none
    diff_run_1  -highlight=False  Color(0,0,0,a=0)  Color(224,224,224)  none
  -> background and text-style matched; `color` did not. `$fg-base` is 233,233,233;
     an unselected row takes ListView's own `& > ListItem { color: $foreground }`
     = 224,224,224. The substituted VALUE was wrong, not the node.

  the second attempt patched the harness LABEL and not the VALUE, and produced a
  byte-identical sha (0edcb9dcae0eadd6) - the applied-check passed because the
  "new" token was the PREVIOUS new token. An applied-check proves a substitution
  happened, never that it is the one you meant.

############ MUTATION M3b ... (color: $foreground) ############
applied: s19_app/tui/styles.tcss  token_present=True  sha 73e7ba1e3e321a98 != fixed 449fb6501f0ea292 -> True
E   AssertionError: the selected entry must be visually distinguished: its
E     resolved (background, color, text_style) is ('Color(0, 0, 0, a=0)',
E     'Color(224, 224, 224)', 'none'), which is not distinct from every
E     unselected entry's [('Color(0, 0, 0, a=0)', 'Color(224, 224, 224)', 'none')]
1 failed, 7 passed in 20.10s
############ M3b REVERTED - sha MATCH=True ############
```

**M4 — §7's declared Inc-2 gate. First run reddened the GUARD; that is F-1:**

```
############ MUTATION M4  DISPLAY_MAX_RUNS  128 -> 100000 ############   [before the fix]
applied: s19_app/tui/screens_directionb.py  token_present=True  sha 49ac444003f9a9c3 != fixed f74869cd773ca2f8 -> True
E   AssertionError: this node's fixture (200 runs) must exceed the display cap (100000) or it tests nothing
E   AssertionError: this node's fixture (200 runs) must exceed the display cap (100000) or it tests nothing
2 failed, 6 passed          <- RED on the GUARD; the capping clause never ran

############ MUTATION M4  DISPLAY_MAX_RUNS  128 -> 100000 ############   [after the reorder]
applied: s19_app/tui/screens_directionb.py  token_present=True  sha 49ac444003f9a9c3 != fixed f74869cd773ca2f8 -> True
E   AssertionError: the panel must paint some but not all runs; painted 200 of 200
E   AssertionError: the panel must store strictly fewer runs than the comparison
E     produced; stored 200 of 200
2 failed, 6 passed in 20.56s
############ M4 REVERTED - sha MATCH=True ############
```

**M5 — `AT-B78-18`'s second declared mutation; both cap nodes redden on their
own clause:**

```
############ MUTATION M5  _render_run_list total_runs  len(runs) -> len(capped) ############
applied: s19_app/tui/screens_directionb.py  token_present=True  sha 335c1717b4cf504b != fixed f74869cd773ca2f8 -> True
E   AssertionError: the capped display must carry its 'showing N of M runs' notice
E   AssertionError: the header must report the COMPLETE run count (the file stays complete)
2 failed, 6 passed in 19.87s
############ M5 REVERTED - sha MATCH=True ############
```

**M6 — `AT-B78-19`'s declared mutation. First run reddened the CENSUS; that is F-2:**

```
############ MUTATION M6  the run list binds `k` (App Legend chip) ############
applied: s19_app/tui/screens_directionb.py  token_present=True  sha bda83998aac9bace != fixed f74869cd773ca2f8 -> True
PROBE live widget bound keys: ['ctrl+pagedown', 'ctrl+pageup', 'down', 'end',
                               'enter', 'home', 'k', 'left', 'pagedown',
                               'pageup', 'right', 'up']
PROBE 'k' bound on the run list: True                  <- applied-checked on the LIVE widget

  [before the reorder]
E   AssertionError: the run list must bind no application-level key; it binds ['k'] out of [...]
  -> red on the STRUCTURAL census; "the Legend no longer opens" stayed unproven

  [after the reorder]
E   AssertionError: 'k' must still open the Legend while the run list holds focus
1 failed, 7 passed in 19.92s
############ M6 REVERTED - sha MATCH=True ############
```

The probe is the strongest applied-check available for a binding mutation: it
reads the **live widget's** resolved `_bindings` map inside a running app.
Textual merges `BINDINGS` at class creation into `_merged_bindings` and copies
it per instance, so a class-attribute mutation applied after class creation
would have been invisible — the failure mode this batch hit five times.

**M7 — `TC-B78-48`'s subject, and it is assertion-live as well as exception-live:**

```
############ MUTATION M7  note row markup False -> True ############
applied: s19_app/tui/screens_directionb.py  token_present=True  sha a20f6da89b76795c != fixed f74869cd773ca2f8 -> True
E   textual.markup.MarkupError: closing tag '[/nope]' does not match any open tag
1 failed, 7 passed in 24.34s
############ M7 REVERTED - sha MATCH=True ############
```

The shipped payload reddens by **exception**, which is exactly the failure the
requirement names (*"renders with no `MarkupError`"*) — but an exception is not
an assertion, so the assertion limb was checked separately with a **parseable**
payload under the same mutation:

```
PROBE parseable payload under M7, rendered: 'A artifacts: evil'
PROBE the shipped assertion would hold? False
```

`[red]evil[/]` is consumed as a span and the verbatim clause fails on its
assertion. The node is live on both limbs.

**M8 — the entry-set subject; the broadest discharge, and it separates the two
cap nodes:**

```
############ MUTATION M8  entries built from self._runs[:1] ############
applied: s19_app/tui/screens_directionb.py  token_present=True  sha ... != fixed f74869cd773ca2f8 -> True
E   AssertionError: the list must present one selectable entry per displayed run; 1 entries for 6 runs
E   AssertionError: one clickable entry per displayed run; clicked 1 of 20
E   AssertionError: the style clause needs at least two rows to discriminate; got 1
E   AssertionError: the notice must name the painted count and the complete count;
E     it says 'showing 128 of 200 runs' while 1 of 200 were painted
E   AssertionError: 'down' must move the list's own selection while it holds focus; 0 -> 0
E   AssertionError: the walk must pin at both ends; reached 0 and 0
6 failed, 2 passed in 12.84s
############ M8 REVERTED - sha MATCH=True ############
```

`test_tc029` stays **green** here while `AT-B78-18` reddens — the model is
capped correctly, the view is not. That is the split the two nodes exist to
make, demonstrated rather than asserted.

**Restore proof.** After every mutation the file was overwritten from a
byte-identical backup, the sha-256 re-checked equal to the fixed tree, and the
predicates re-run. Final state:

```
$ git status --short -- s19_app/ tests/
 M s19_app/tui/screens_directionb.py
 M tests/test_tui_diff_compare_realpath.py
 M tests/test_tui_diff_screen.py
$ git diff --numstat -- s19_app/ tests/
57      20      s19_app/tui/screens_directionb.py
21      3       tests/test_tui_diff_compare_realpath.py
760     25      tests/test_tui_diff_screen.py
```

`s19_app/tui/styles.tcss` is **absent from that list** — M2 and M3b touched it
and both restored to `449fb6501f0ea292`.

### 4.6 Executed framework facts (the A-4 / P-47 evidence)

```
textual 8.2.8
ListView.BINDINGS:
  Binding(key='enter', action='select_cursor', ..., priority=False)
  Binding(key='up',    action='cursor_up',     ..., priority=False)
  Binding(key='down',  action='cursor_down',   ..., priority=False)
ListView.can_focus = True     ListItem.can_focus = False

live #diff_range_list resolved binding keys (instance `_bindings`, in-app):
  ['ctrl+pagedown', 'ctrl+pageup', 'down', 'end', 'enter', 'home',
   'left', 'pagedown', 'pageup', 'right', 'up']
  -> `j` / `k` / `p` / `o` appear ZERO times, and nothing is priority=True

App priority=True bindings (app.py:1339-1342):
  ctrl+k, ctrl+d, ctrl+l, ctrl+s      -> DISJOINT from the set above

action_cursor_down / action_cursor_up:  `if not item.disabled:` -> disabled rows skipped
_on_list_item__child_clicked:           a disabled ListItem never posts _ChildClicked
```

**Geometry at 132×44, executed on the settled tree** (6-run comparison):

```
#diff_range_list  type=ListView  can_focus=True  overflow_y=auto
                  size=(29,13)   virtual_size=(27,132) at 200 runs -> scrollable
items: 3 disabled note rows + one `#diff_run_{i}` per run, each height 1
initial index -> the first RUN row (3), not a note row
highlight triple, focused:   Color(1,120,212)          Color(255,255,255,a=0.87)  bold
unselected triple, focused:  Color(0,0,0,a=0)          Color(224,224,224)         none
```

---

## 5. Risks

| # | Risk | Severity | Mitigation / status |
|---|---|---|---|
| **R-1** | **`ListView.clear()` schedules an async remove while `extend()` mounts synchronously**, so between `render_comparison` returning and the next event-loop turn both the old and the new rows exist in `_nodes`. Every consumer in this repo pauses before reading. | medium | Verified across all 352 nodes, including `test_tui_diff_compare_realpath.py`'s single-`pause()` driver, which passes unchanged. **A future caller that reads the list synchronously inside `render_comparison` would see stale rows.** Not covered by a test — no such caller exists. |
| **R-2** | **The run list is empty before any comparison**, where the `Static` used to render the word `Runs`. | low | Deliberate — `TC-B78-22` pins the no-comparison state. The one snapshot cell that could show it is already red until Inc-12. |
| **R-3** | **Selection still does not drive the hex windows.** `_render_run_windows` is called only with the literal `0`. An operator can walk the list and the windows will not follow. | medium — **by design** | LLR-123.1 / `AT-B78-20…22` at **Inc-4**. Stated here so the increment is not read as delivering more than it does. |
| **R-4** | **`AT-B78-17` observes the resolved style triple, not painted cells.** A theme where the highlight background is distinct in the model but invisible in the terminal would pass. | low | The requirement's own numeric threshold names the triple. Going to the compositor was Inc-1's `TC-B78-37` lesson and is available if the operator wants it. |
| **R-5** | **`#diff_range_list` still carries `padding: 1` and `border: round $rule` from the shared `#diff_range_list, #diff_hex_a, #diff_hex_b` block**, so the highlight bar stops one column short of the border on each side. | low — cosmetic | Measured, not guessed. No CSS change was needed for any HLR-122 clause (F-3); changing it for looks is out of scope. |
| **R-6** | **Snapshot cell `[diff-comfortable-120x30]` is RED until Inc-12.** | low — **by design** | C9 forbids local regen. Still exactly one cell, unchanged from Inc-1 (§4.3). |
| **R-7** | **`screens_directionb.py` is edited again at Inc-4, 5, 6 and 7** (§7's file × increment map). | low | The change is confined to `compose`'s one line and `_render_run_list`; `_run_note_item` is a new private static method with one caller. |
| **R-8** | **Inc-1's `#diff_status`-at-120×30 gap (its Pending item 6) is still unguarded**, and this increment touched the panel's widget tree. | low | Measured unchanged: `#diff_columns` still paints 3 rows at 120×30 and no snapshot cell beyond the diff golden moved. Not pinned here — a node asserting today's value would false-fail Inc-5. |
| **R-9** | A parallel session is live in this worktree (`prototypes/memmap2.*`, `.dev-flow/state.json` modified). | low | Nothing outside my three files was written. No `git add -A`, no `git stash`, no force, no push. |

**Security:** presentational only. No new file I/O, no network, no credential
path, no dependency added, no secret in code or output. The one security-relevant
class a view change can carry — file-derived text reaching a rendered label — is
**strictly tightened**: the artifact-usage summaries move from
`escape()` -into-`markup=True` to `markup=False` **at construction** (C11), and
`TC-B78-48` pins it with an executed mutation (M7). The run-entry labels are
built from module constants (`_KIND_MARKUP` / `_KIND_LABEL`) and integers, never
from file content.

---

## 6. Pending items

1. **§5.3 / §5.1's guard-placement rule should be amended** from *"the guard is
   evaluated after the capture"* to *"the guard is evaluated after the
   substantive assertions"* (F-1). Not done here — I do not edit
   `01-requirements.md`. Carried as **`C-78-vii`**.
2. **§5.3's `AT-B78-19` row should be relabelled PIN → GATE** (F-5), and its
   mutation recorded as reaching the Legend clause only when the behavioural
   assertions precede the structural census (F-2).
3. **§7's Inc-2 file list should drop `styles.tcss`** (F-3), and Inc-1's carry
   into Inc-2 should be marked refuted.
4. **`A-4` can be struck from §8's `assumed — verify at Phase 3` table** —
   settled TRUE by execution (F-4).
5. **Selection → window render is NOT built** (LLR-123.1, Inc-4). The list
   maintains a selection index and posts `ListView.Highlighted` / `Selected`; no
   handler consumes them yet. `_render_run_windows`'s docstring no longer names
   a phantom handler, and now names no handler at all — Inc-4 supplies the real
   one.
6. **`TC-B78-20` shares a node with `AT-B78-16`.** Its subject (a row past the
   viewport) is asserted inside the mouse walk rather than duplicating a 20-run
   drive. Split it if the operator wants strict one-subject-one-node.
7. **`test_tc029` and `AT-B78-18` are near-siblings on one clause**, split by
   observable and demonstrated distinct under M8. If the operator prefers a
   single node, `TC-029`'s registry row is the one that must survive.
8. **`AT-B78-31` (Inc-3) will need the 200-run fixture again.** It can reuse
   `_b78_drive_compare` and `_B78_OVER_CAP_RUNS` rather than minting a third
   over-cap fixture.

## 6b. Batch carry list (additions)

| # | Item | Owner |
|---|---|---|
| **C-78-vii** | **"Fail after the capture" is not the falsifiability property; "fail on the substantive assertion" is.** §5.3's Q-m2 fix moved a constant-quoting guard from *before* the capture to *after* it, which stops the mutation raising — but leaves the guard as the **first assertion**, so the mutation still reddens the guard and the load-bearing clause never executes. Executed twice in this increment on two unrelated nodes (`test_tc029`/`AT-B78-18` under the cap mutation; `AT-B78-19` under the binding mutation), so it is not a property of caps. **General form: in any node that carries both a self-check and a subject clause, the subject clause must be asserted FIRST.** This is the batch's dominant defect class — the vacuous check — reappearing inside the requirements' own remedy for it, for the fourth time. | batch close |
| **C-78-viii** | **An applied-check proves a substitution occurred, never that it is the substitution you intended.** My `M3` re-run patched the mutation harness's *label* and not its *value*; token-present and sha-changed both passed because the "new" token was the previous new token, and the sha was **byte-identical to the prior run**. The cheap discriminator that caught it: **compare the mutated file's sha against the previous mutation's sha, not only against the fixed tree's.** Sixth silent mutation failure in batch-78. | batch close |

---

## 7. Suggested next task

**Inc-3 — `LLR-122.4` / `AT-B78-31`: report completeness observed through the
written file** (`tests/test_tui_diff_screen.py`, 1 file). It is now cheap and
well-positioned: `_b78_drive_compare` and `_B78_OVER_CAP_RUNS` already exist, and
this increment has just established by execution (M4/M5/M8) that the panel's
model **is** capped at 128 while a 200-run comparison is fed — which is exactly
the contrast `AT-B78-31` needs to make meaningful. Its gate is the
`runs=panel._runs` mutation executed and pasted; §5.3 marks it *"PIN — mutation
owed at Inc-3"*, and on this increment's evidence that mutation should drop the
file-level count from 200 to 128.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Tests / type checks / lint pass | ✓ | §4.2 — `352 passed in 475.36s`, **one run**, FULL form, 12 modules, on the settled tree. §4.1 — `22 passed`. §4.3 — `1 failed / 31 passed`, the **predicted** single snapshot cell, recorded not regenerated. Lint/type: repo runs neither in its gate suite. |
| No secrets in code or output | ✓ | Widget construction and `tmp_path` fixtures only; no env read, no path outside `tmp`, no credential surface. |
| No destructive commands without approval | ✓ | Mutations applied by file copy with a byte-identical backup taken one statement earlier; every restore verified by sha-256. One `git show d771ab8:<file> >` redirect for CF-0, restored from backup and sha-verified. **No `git add -A`, no `git stash`, no `rm`, no force, no push, no checkout of a tracked file.** |
| File count within cap | ✓ | **3 files** — §7 planned 4; `styles.tcss` measured unnecessary (F-3). Cap is 5. |
| Every node carries a spec id | ✓ | `AT-B78-15…19`, `TC-B78-17/18/19/20/21/22/47/48`, `TC-029`. **No id invented.** |
| C-38 sweep done BEFORE the change ran | ✓ | §4.2 — 9 hits / 3 modules for `#diff_range_list`; the two text readers re-pointed, the third (type-agnostic, Lane-1-shared) verified needing no change; `AbDiffPanel`'s 5 modules all in the gate run. |
| C-26 reverse grep over the whole `tests/` tree | ✓ | §4.2 — `test_tui_patch_json.py` was found by it and added to the run. |
| Nodes falsifiable, mutation applied-checked | ✓ | §4.5 — **nine** transcripts, each asserting the token present **and** the sha changed before running, each restored by sha. **`AT-B78-19`'s mutation additionally applied-checked on the LIVE widget's binding map.** **One came back INERT and is reported as a finding (F-6), not absorbed.** Per-arm RED/GREEN table (CC-1), never an exit code. |
| §7's declared Inc-2 gate discharged | ✓ | §4.5 M4 — `test_tc029` reddens under `DISPLAY_MAX_RUNS 128 → 100000` on `stored 200 of 200`, **after** the ordering fix that F-1 forced. |
| `A-4` verified by execution, not assumed | ✓ | §4.6 — disjoint key sets, plus the live `ctrl+k` / `down` arms inside `AT-B78-19`. |
| C-12/C-17 markup safety | ✓ | Summaries `markup=False` at construction; `TC-B78-48` + mutation M7, live on both the exception and the assertion limb. |
| C12 internal-name shadowing | ✓ | **No widget subclass introduced** — `#diff_range_list` is a stock `ListView`, so no `_nodes` / `_context` member can be shadowed. |
| Snapshot regen not attempted locally | ✓ | §4.3 — still exactly one cell, per-cell reason recorded; C9 respected; Inc-12 owns regen. |
| Review packet attached | ✓ | this document, §§1–7 + §6b carry list |
