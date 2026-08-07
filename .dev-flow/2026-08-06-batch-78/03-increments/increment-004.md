# Increment 004 — HLR-123, the hex windows follow the selection and are sized by the pane

**Batch:** `2026-08-06-batch-78` · **Lane:** A (`.dev-flow/BACKLOG-CODE.md`)
**Branch:** `claude/batch-78-cmdbar-a2bdiff` · **Base at kickoff:** `24d812f`
**Spec authority:** `01-requirements.md` §7 Inc-4 row · HLR-123 · LLR-123.1/.2/.3 · §5.3 rows `AT-B78-20…22` · §8 `A-6`
**ATs realized:** `AT-B78-20`, `AT-B78-21`, `AT-B78-22` (3 GATEs) · **TCs:** `TC-B78-23…28`, `TC-B78-45`, `TC-B78-50` (minted at the gate for `A-6`)
**Files:** `s19_app/tui/screens_directionb.py`, `tests/test_tui_diff_screen.py` (**2**, cap 5)

---

## BLUF

**Shipped: selection now drives both hex windows, and the row count is read off the rendered pane instead of `DISPLAY_CONTEXT_BYTES`.** All three gates are green, **seven** counterfactual mutations reddened **on their own assertions** (four at first submission, three more at the gate), and the tree was restored byte-identically (`FINAL sha == baseline`) after every one.

**Three findings, all from executing the spec rather than reading it — and a fourth, F-2, found by the gate reviewer executing THIS document's own claim.**

| # | Finding | Verdict |
|---|---|---|
| **F-1** | **HLR-123's two clauses are not jointly exact.** "Always include the run ± `DISPLAY_CONTEXT_BYTES`" and "the row count derives from the pane height" can both hold *as written* only where the pane cannot grow the window. At 132×44 the derived count is **12** rows, so §3's threshold *"the emitted row addresses are exactly `0x00000FF0, 0x00001000, 0x00001010`"* is **unsatisfiable at the gate's own size**. `AT-B78-22`'s exact arm therefore runs at **132×24** (pane content height 0, capacity 0, the floor is the whole window) and its containment arm covers 132×44. **Reported, not worked around.** | ⚠️ **spec conflict** |
| **F-2** | **`A-6` — the row-centring arithmetic did not exist to verify; it is now defined and measured.** §4's LLR-123.2 flags it `assumed — measure in Phase 3` and states no formula. Implemented as *split the surplus evenly, clamp the low edge at 0, keep the count*. Executed: at 132×60 the run row sits at index **13 of 28** (13 above / 14 below — centred to within one row); a run at address 0 windows from `0x00000000` and still fills the pane at **12** rows. | ⚠️ **CORRECTED AT THE GATE — see the addendum.** As first written this row claimed `A-6` **DISCHARGED** on the strength of those measurements, and **nothing pinned them**: both one-sided splits leave 10/10 nodes green. Discharged for real by `TC-B78-50`. |
| **F-3** | **`LLR-123.3`'s `_KIND_LABEL` citation has drifted two lines.** §4 cites `screens_directionb.py:6637-6641`; on this branch the dict is at **`:6639-6643`**. Content re-derived and correct (3 entries, `changed` / `only A` / `only B`). Inc-2's edits moved it; the spec's `assumed`-withdrawal was sound, only its coordinates are stale. | ⚠️ **stale citation** |

**Two spec figures re-derived rather than copied.** §3's HLR-123 rationale records `(132,60) → 4 emitted lines at pane h=23`. Measured on this branch **pre-change**: 4 emitted lines at pane h = **29**. The figure does not reproduce as written and *should not* — it was measured before Inc-1's compaction, which BL-2's own table says frees 6 rows (`23 + 6 = 29`). Same for 132×44: spec's pre-Inc-1 7, measured here **13**, matching BL-2's *"S-8 only (13,17)"* to the digit. **Both reproduce once the increment they were measured at is stated; neither did as a bare number.**

---

## 1. What changed

### 1.1 The defect

`_render_run_windows` had **one call site** — `render_comparison`'s literal `0` — so runs 1..N were unreachable however the list was driven. Inc-2 made the list a selectable `ListView` and deliberately left this wire unconnected; connecting it is `LLR-123.1`.

Its row count came from `DISPLAY_CONTEXT_BYTES` alone, making the window a function of the **run**, never of the **pane**. Executed on this branch before the change, same fixture, same width:

```
132x44   #diff_hex_a content pane 13 rows   ->  4 emitted lines
132x60   #diff_hex_a content pane 29 rows   ->  4 emitted lines
```

**4 == 4.** A 16-row difference in available space produced no difference in output.

### 1.2 `LLR-123.1` — selection drives the window render

New `AbDiffPanel.on_list_view_highlighted`. The run index is taken from the row's **shipped DOM id** (`diff_run_{n}`, minted by `_render_run_list`), not from its position — the list also carries three disabled context rows at the top and a display-cap notice at the bottom, so position and run index are different numbers. `item is None` (the list is mid-rebuild) and note rows (no `diff_run_` id) return without rendering.

The App-level `on_list_view_highlighted` (`app.py:7477`) was checked before wiring: it returns for every list that is not `a2l_tags_list`, and `screens.py:1981`'s belongs to `OperationsScreen`, which is not an ancestor of this panel. No handler is displaced and the event is not stopped.

### 1.3 `LLR-123.2` — the row count derives from the rendered pane

New `AbDiffPanel._window_row_capacity()` reads `size.height` off both windows at render time and returns `min(A, B) - 1`, floored at 0.

**Why `min`, and why it still satisfies "that window's rendered height".** A diff is only readable when both columns show the *same addresses on the same screen line*, so the two windows must be asked for one row list. The two are siblings under one `1fr` row and measure **equal in HEIGHT** at every size executed (132×44, 132×60, 132×24, 160×40, 120×30), so `min` *is* each window's own height wherever they agree, and is the honest bound where a layout makes them differ.

⚠️ **The gate review made this argument stronger than I made it.** I argued `min` was defensive against a *hypothetical* future divergence. The reviewer measured that the two panes **already differ — in WIDTH, at 80×24 (18 vs 19)** — so they are not the identical box I implied, and `min` is an honest bound on a real asymmetry rather than speculation. The heights happen to agree; nothing in the layout guarantees it.

**Why `- 1`.** The `Image A — Run #n …` header shares the widget with the hex rows. Without it the window emits `height + 1` lines into `height` rows and the last row is clipped away — which is the same C-32 layer confusion this batch has hit three times.

`_render_run_windows` then keeps the mandatory floor and grows it:

```python
rows = len(range(low, high, HEX_WIDTH))     # the run +/- context floor, unchanged
capacity = self._window_row_capacity()
if capacity > rows:
    low = max(0, low - ((capacity - rows) // 2) * HEX_WIDTH)
    rows = capacity
row_bases = [low + index * HEX_WIDTH for index in range(rows)]
```

The growth is **one-directional**: `if capacity > rows`. When the pane is shorter than the floor, the floor wins and the surplus overflows — bounding it into a paginable viewport is HLR-124's, built at Inc-5. This method therefore never renders **fewer** rows than the pre-batch-78 window did, which is what keeps `test_tc022`, the two `test_tui_diff_compare_realpath` hex nodes and every 120×30 consumer unmoved.

**The centring arithmetic (`A-6`).** Half the surplus above, the remainder below, `low` clamped at 0 while the **count stays `capacity`** — so the rows the clamp refuses above the run are recovered below it rather than dropped. That last clause is the one an "obvious" implementation gets wrong (subtract, clamp, then generate to the old `high`), and it is what `TC-B78-24`'s `len(rows) == content_h - 1` clause asserts.

### 1.4 `LLR-123.3` — the header names the kind

`f"Run #{i} 0x{start:08X}-0x{end:08X}"` → `… {self._KIND_LABEL.get(kind, kind)}`. `_KIND_LABEL` re-derived at **`:6639-6643`** (§4 says `:6637-6641` — F-3).

**C-17 holds unchanged:** `#diff_hex_a` / `#diff_hex_b` are constructed `markup=False` (**`:6770-6771`** - re-derived; the spec's `:6767-6768` is stale, and this packet copied it, F-5) and this increment does not touch that. The header composes integers and a constant dict's values only — no file-derived text reaches it.

### 1.5 What this increment deliberately does NOT do

| Not done | Why |
|---|---|
| An `on_resize` re-render | HLR-123's Statement says *"at render time"*. `TC-B78-30` (*"a resize across the breakpoint … the layout follows"*) is **Inc-5's**, under HLR-124. Adding it here would put regime work in the wrong increment. |
| Bound the overflow when the run exceeds the pane | HLR-124's fallback regime, Inc-5. `TC-B78-25` pins that Inc-4 does not silently truncate in the meantime. |
| Touch `prototypes/cmdbar_a2bdiff.tui_prototype.py` | Inc-2 had to (`render_comparison` became a coroutine — a breaking signature change). Inc-4's changes are internal to `_render_run_windows`; the prototype carries its own renderer and already renders the kind label. Not in Inc-4's file set. |
| Regenerate the drifted snapshot | C9 / C-30 — CI-only, Inc-12 owns it. |

---

## 2. Files modified

| File | Change | Nodes |
|---|---|---|
| `s19_app/tui/screens_directionb.py` | `on_list_view_highlighted` (new) · `_window_row_capacity` (new) · `_render_run_windows` growth + kind in the header | — |
| `tests/test_tui_diff_screen.py` | the Inc-4 block (3 ATs + **8** TCs + 4 helpers) · `_diff_result` gains an optional `paths=` so `TC-B78-26` can give the two sides different byte coverage through the **shipped loader** | +11 |

**2 files. Cap 5.** `.dev-flow/state.json`, `PLAN.md`, `00-measurements.md`, `01-requirements.md`, the `02-review-*.md` files, earlier `increment-*.md` and `AT-TC-REGISTRY.jsonl` were **read, never written**. `prototypes/memmap2.*` (the parallel session's) untouched — `git status` shows exactly the two files above plus the pre-existing untracked `build/` and `prototypes$f.png`.

**C-26 reverse-grep.** New module-level test symbols `_B78_INC4_TALL/_WIDE/_SHORT`, `_B78_AT22_RUN`, `_B78_AT22_ADDRESSES`, `_B78_HEX_ROW`, `_b78_window_text`, `_b78_window_rows`, `_b78_window_geometry`, `_b78_select_run` — each defined **exactly once**, and `_b78_window_geometry` / `_window_row_capacity` have **no consumer outside their own module**.

**`C-78-xiii` / F9 honoured — no fourth driver copy.** `_b78_drive_compare`, `_b78_press_compare`, `_b78_run_list`, `_b78_run_index` and `_b78_focus_run_list` are Inc-2's and are reused as-is. The only new driver is `_b78_select_run`, four lines, and it delegates the blur/focus discipline to Inc-2's `_b78_focus_run_list`.

---

## 3. How to test

```bash
cd C:/Users/jjgh8/Github/s19_app

# the increment's own nodes
python -m pytest tests/test_tui_diff_screen.py -k "b78_20 or b78_21 or b78_22 or b78_23 or b78_24 or b78_25 or b78_26 or b78_27 or b78_28 or b78_45" -q

# the increment's file + the other window consumer, ONE run, FULL form
python -m pytest tests/test_tui_diff_screen.py tests/test_tui_diff_compare_realpath.py -q

# the C-34 gate: the full guard host, ONE run, FULL form
python -m pytest tests/test_tui_directionb.py -q

# the expected drift - DO NOT regenerate locally (C9; Inc-12 owns regen)
python -m pytest tests/test_tui_snapshot.py -q

# the four counterfactuals, applied-checked and sha-restored
python <scratchpad>/mutate_inc4.py
```

---

## 4. Test results

### 4.1 The increment's own nodes

```
tests/test_tui_diff_screen.py -k "b78_2x or b78_45"
.........F..                                                             [100%]   <- pre-fix run: TC-B78-26 import path
1 failed, 11 passed, 22 deselected in 17.43s

after the one-line import fix (s19_app.s19 -> s19_app.tui.changes.io):
tests/test_tui_diff_screen.py -k "b78_26"
.                                                                        [100%]
1 passed, 33 deselected in 1.15s
```

The 12 selected include Inc-2's `test_tc_b78_21_zero_length_run_is_selectable` and `test_tc_b78_22_keys_before_any_comparison_do_not_crash`, which the `-k` substrings also match. **Inc-4's own nodes are 11** (10 at first submission + `TC-B78-50` at the gate).

### 4.2 The increment's file + the other window consumer — ONE run, FULL form

```
tests/test_tui_diff_screen.py tests/test_tui_diff_compare_realpath.py
........................................                                 [100%]
40 passed in 61.21s (0:01:01)
```

### 4.3 C-34 gate — ONE run, FULL form

```
tests/test_tui_directionb.py
........................................................................ [ 39%]
........................................................................ [ 78%]
.......................................                                  [100%]
183 passed in 184.90s (0:03:04)
```

### 4.4 Counterfactuals — four mutations, each applied-checked, each sha-restored

Every mutation is a **value substitution that type-checks** (`C-78-xv`). Every one is verified to have **landed** — the old token asserted absent after the write, since eight mutations have silently failed to apply in this batch — and every sha is compared against the **previous** mutation's as well as the baseline.

```
BASELINE sha=2429d588ed343e44

--- M1 / AT-B78-21 --- capacity derives from the pane -> capacity = 0 (the pre-change behaviour)
    substituted: 'capacity = self._window_row_capacity()'  ->  'capacity = 0'
    APPLIED=True  sha 2429d588ed343e44 -> 5769dc32449de815 (mutated) -> 2429d588ed343e44 (restored)
    PRE  green | 1 passed in 2.15s
    MUT  RED   | 1 failed in 2.23s
    MUT failure line: E  AssertionError: the emitted row count must DERIVE from the pane
       height: same width, panes of 13 and 29 content rows, but the windows emitted 3 and 3 rows
    POST green | 1 passed in 2.09s

--- M2 / AT-B78-22 --- high = end + DISPLAY_CONTEXT_BYTES -> high = end (spec Sec.7's declared mutation)
    substituted: 'high = end + self.DISPLAY_CONTEXT_BYTES'  ->  'high = end'
    APPLIED=True  sha 5769dc32449de815 -> 68941fa401e97fcf (mutated) -> 2429d588ed343e44 (restored)
    PRE  green | 1 passed in 2.06s
    MUT  RED   | 1 failed in 2.22s
    MUT failure line: E  AssertionError: the window must span exactly the run plus one context row
       on each side; expected ['0x00000FF0', '0x00001000', '0x00001010'],
       emitted ['0x00000FF0', '0x00001000']
    POST green | 1 passed in 1.99s

--- M3 / AT-B78-20 (LLR-123.1) --- the selection wire renders the SELECTED index -> renders 0
    substituted: 'self._render_run_windows(int(item.id[len("diff_run_") :]))'  ->  'self._render_run_windows(0)'
    APPLIED=True  sha 68941fa401e97fcf -> 61463c55db23c79b (mutated) -> 2429d588ed343e44 (restored)
    PRE  green | 1 passed in 1.65s
    MUT  RED   | 1 failed in 1.80s
    MUT failure line: E  AssertionError: the A window must RE-RENDER on a selection change;
       its header did not move off 'Image A - Run #0 0x00000000-0x00000004 only A'
    POST green | 1 passed in 1.55s

--- M4 / AT-B78-20 (LLR-123.3) --- the header names the run's kind -> names nothing
    substituted: 'f"{self._KIND_LABEL.get(kind, kind)}"'  ->  'f""'
    APPLIED=True  sha 61463c55db23c79b -> 6164dea60ea04cf3 (mutated) -> 2429d588ed343e44 (restored)
    PRE  green | 1 passed in 1.51s
    MUT  RED   | 1 failed in 1.73s
    MUT failure line: E  AssertionError: the A window header must name the run's classification
       (LLR-123.3); run kind is 'changed' and header='Image A - Run #3 0x00000300-0x00000304 '
    POST green | 1 passed in 1.66s

FINAL sha=2429d588ed343e44  baseline=2429d588ed343e44  equal=True
```

**Every one of the four failed on an `AssertionError` carrying the node's own message** — never on a `TypeError`, an import error or a collection error. That is the whole point of `C-78-xv` and of *a counterfactual must fail on its ASSERTION*: `LLR-122.4`'s declared mutation reddened Inc-3 **in the driver**, and §5.3's own `AT-B78-22` note records that the constant mutation `16 → 64` raises in the guard in both placements. The guard here is placed **after** the capture and stays true under M2, so M2 reaches the assertion.

**M1 is the honest reproduction of the pre-change state.** With `capacity = 0` the derivation collapses to the floor and both arms emit **3 and 3** rows into panes of **13 and 29** — the same shape as the spec's executed `4 == 4`, differing only because this fixture is a single 4-byte run.

**M3 restores the exact pre-change semantics** (`_render_run_windows` always called with `0`) rather than deleting the handler, so `AT-B78-20` reddens on the observable that changed, not on an absence.

### 4.5 Snapshot drift — recorded, NOT regenerated

```
tests/test_tui_snapshot.py
1 snapshot failed. 28 snapshots passed.
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[diff-comfortable-120x30]
1 failed, 31 passed, 1 warning in 56.17s
```

**Exactly one cell, and it is the one already drifted by Inc-1.** No second cell moved — checked because the header now carries the kind label, which *would* have shown in the golden had P-33b not established that the 120×30 diff golden contains **no** `Image A` / `Image B` text at all (the results area clips to zero until Inc-10). Regeneration is CI-only and is Inc-12's (C9 / C-30).

### 4.6 Ledger

| Stage | Count |
|---|---|
| Baseline | 2607 / 2 / 3 |
| Inc-0 | 2608 |
| Inc-1 | 2612 |
| Inc-2 | 2625 |
| Inc-3 | 2626 *(honestly 2625 + the one drifted cell until Inc-12)* |
| **Inc-4** | **2637** — `D = 0`, `A = 11` |

**Stated honestly:** 2637 is **arithmetic** on Inc-3's tracked figure, not a figure read off a full-suite run. Per C-19 and the increment brief the 26-minute suite was not run; the evidence is the complete targeted runs (**41** + **183** + 32 nodes post-gate-fix, each read from its own output) and a collection census showing `tests/test_tui_diff_screen.py` at **35** nodes, up from 24. Like Inc-3's, the figure is honestly 2636 + the one drifted snapshot cell until Inc-12 regenerates it.

---

## 5. Risks

| # | Risk | Severity | Mitigation / status |
|---|---|---|---|
| **R-1** | **`AT-B78-22`'s exact arm runs at a size §7 does not name** (132×24, not the gate's 132×44). | ⚠️ medium | Forced by F-1 — the threshold is unsatisfiable at 132×44 under the same requirement's own derivation clause. The tall pane is covered by a containment co-assertion in the **same node**. **Needs a coordinator ruling**, not a silent acceptance. |
| **R-2** | The containment co-assertion in `AT-B78-22` is **inert under M2** (with `high = end` the grown 132×44 window still contains all three literals). | low | Declared as a co-assertion, not the gate; M2 reddens on the exact arm. Recorded here so it is never counted as a discharged gate. |
| **R-3** | `_window_row_capacity` reads a **live widget** during render. A caller that renders before layout settles gets `capacity = 0` and the floor. | low | Not a crash path (`TC-B78-28` pins it at a genuine zero-height pane) and not silent: the floor is still the correct minimum window. Every shipped call site runs after `render_comparison`, which runs after the screen is active. |
| **R-4** | The growth reads `min(A, B)`. If a layout gives the two windows different heights, both shrink to the shorter. | low | Deliberate and documented — a diff whose columns disagree on line-to-address mapping is not a diff. Heights executed equal at all five sizes measured; the panes **already differ in width at 80×24 (18 vs 19)**, so the asymmetry is real and `min` is the honest bound, not a hedge. |
| **R-5** | `_diff_result` gained a keyword. | low | Defaulted to `(None, None)`, which is the exact pre-Inc-4 behaviour; all 24 pre-existing nodes in the module pass unchanged. |
| **R-6** | Runs longer than the pane overflow invisibly. | ⚠️ medium | **Inc-5's** (HLR-124 fallback / paginable viewport). `TC-B78-25` pins that Inc-4 does not truncate the run in the meantime. Explicitly out of scope here, not forgotten. |

**Security:** no new I/O, no network, no credential path, no external-tool surface. The only new data path is integers and a constant dict's values into a `markup=False` sink. `TC-B78-26` writes two S19 files into pytest's own `tmp_path`. No secret is read, printed or committed.

---

## 6. Pending items

1. ~~**F-1 needs a ruling.**~~ **RULED — the coordinator's Amendment D**, `01-requirements.md:890`. The threshold now reads *"exactly … at a pane whose content height is 0"* plus a containment clause at taller panes. ⚠️ **Its first wording claimed "nothing was weakened" and was corrected in `4425080`:** an exact **twelve-literal** set at 132×44 *would* have reddened under M2 (which shifts the start `0xFB0 → 0xFA0`); containment does not. What containment buys is stability under geometry change — a twelve-literal threshold is re-baselined by any increment that moves the pane a row. **A decision with a named trade, not an absence of loss.** My containment arm remains declared inert under M2 and is not counted as a discharge.
2. **Two one-line corrections owed in `01-requirements.md`** (I do not write that file): §4's LLR-123.3 cites `screens_directionb.py:6637-6641` for `_KIND_LABEL` — it is **`:6639-6643`**; and §4 / LLR-123.3's C-17 note cites `:6767-6768` for the `markup=False` constructions — they are **`:6770-6771`**. ⚠️ **This packet copied the second one while correcting the first, in the same paragraph** — the increment instantiated its own carry in the act of writing it down.
3. **`A-6` is discharged — by `TC-B78-50`, not by the measurements in §1.3.** §8 can be marked. The distinction is the whole of the gate's HIGH: a measured number in a report removes an item from scrutiny while pinning nothing. `A-1`, `A-2`, `A-3`, `A-4`, `A-5` remain with their owners; **`A-1` in particular can now be re-derived against the real implementation** (§7).
4. **Snapshot regen** — still exactly one cell, still Inc-12's, still CI-only.
5. **`F9` unchanged** — Inc-4 added no duplicate driver, but `_b78_press_compare`/`_press_compare` and `_b78_run_list_text`/`_run_list_text` remain duplicated near-copies across the two diff modules.
6. **`C-78-xiv` unchanged** — the two `TC-024` nodes still carry the unsound `press()` + `wait_for_complete()` shape. Not Inc-4's to fix.
7. **`C-78-xx` (the coordinator's) is owed an owner.** Every `| tail` / `| head` gate invocation in every batch reports the pipeline's exit status rather than the gate's. The preferred fix — moving the gate into the RC-1 pre-commit hook — is **process work, not Inc-5's**, and needs scheduling explicitly or it will be lost. **Inc-4's own harnesses are unaffected:** every verdict above is read from `subprocess.run(...).returncode`, never from a piped tail.

## 6b. Batch carry list (additions)

| Id | Carry |
|---|---|
| **🆕 `C-78-xxi`** *(renumbered at the gate, F-3: `C-78-xviii` is already taken by `01-requirements.md:898`, and `C-78-xx` by the coordinator's pipeline-exit-status carry)* | **A requirement with two exactness clauses over the same output owes the region where they are jointly satisfiable.** HLR-123 demands the window *equal* the run ± context AND *derive* from the pane height. Both are right; together they are exact only where the pane cannot grow. The threshold was written against the pre-derivation implementation and silently became unsatisfiable at the very size §7 later chose for the sibling gate. **Neither clause was wrong — their intersection was empty and nothing checked it.** |
| ~~`C-78-xix`~~ **WITHDRAWN at the gate (F-3)** | The re-derivability lesson (*a measured figure is re-derivable only with the INCREMENT it was measured at*) is **already recorded as `C-78-xviii` at `01-requirements.md:898`**, by the coordinator, from this increment's own finding. Minting a second id for it would have split one lesson across two ids and lost one at close. **Cite `C-78-xviii`; nothing is dropped.** |
| **🆕 `C-78-xx`** *(coordinator's, recorded here so it is not lost)* | **A gate invocation piped through `tail` / `head` reports the PIPELINE's exit status, not the gate's** — so a failing gate reads as a pass, silently and in the safe-looking direction. It landed on the coordinator's own amendment, which was committed over a failed propagation gate. Every `\| tail` / `\| head` gate invocation in every batch has the identical hole. **Preferred fix: move the gate into the RC-1 pre-commit hook so shell plumbing cannot arbitrate a verdict.** |

---

## 7. Suggested next task

**Inc-5 — HLR-124 in full** (`LLR-124.1` constants + regime class, `LLR-124.2` wide layout, `LLR-124.3` fallback overlay + paginated viewport, `LLR-124.4` notice regime); ATs `AT-B78-23`, `AT-B78-29`; files `screens_directionb.py`, `app.py`, `styles.tcss`, `tests/test_tui_diff_screen.py` (4).

**Three things Inc-4 hands it directly.**
1. **`A-1` (`_DIFF_MIN_H = 29`) can now be re-derived against the real implementation**, which is what §8 asked for — the simulation used `styles.height = 1`. Measured content heights of `#diff_hex_a` on this branch: `132×44 → 13` · `132×60 → 29` · `160×40 → 9` · `132×24 → 0` · `120×30 → 0`.
2. **The overflow bound is Inc-5's**, and `TC-B78-25` already names the state it must fix.
3. **`TC-B78-30`'s resize arm has no production support yet** — Inc-4 deliberately did not add an `on_resize` re-render, so Inc-5 owns it along with the regime toggle.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Tests / type checks / lint pass | ✓ | 40 passed (diff suites, one run) · 183 passed (`test_tui_directionb.py`, C-34, one run) · 10/10 Inc-4 nodes · `compileall` clean on both files |
| Every gate discharged by an executed, applied-checked mutation | ✓ | §4.4 — four mutations, `APPLIED=True` on each, each reddening on an `AssertionError` carrying the node's own message |
| Restore proof | ✓ | `FINAL sha=2429d588ed343e44 == baseline`, per-stage shas distinct, tree restored in a `finally` |
| Snapshot drift bounded and NOT regenerated | ✓ | §4.5 — exactly `[diff-comfortable-120x30]`, the cell Inc-1 already drifted; 28 of 29 pass |
| No secrets in code or output | ✓ | No credential, token or path outside `tmp_path` appears in any new line or any transcript above |
| No destructive command run without approval | ✓ | No `git stash`, no `git reset`, no `rm -rf`, no force push, no regen. Mutations restored by writing back saved bytes in a `finally`, never by `git checkout` |
| File count within cap | ✓ | 2 of 5; `state.json` / `PLAN.md` / `01-requirements.md` / `AT-TC-REGISTRY.jsonl` / `prototypes/memmap2.*` read-only |
| C-17 preserved | ✓ | `#diff_hex_a` / `#diff_hex_b` still constructed `markup=False` (**`:6770-6771`**, re-derived); the header composes integers + a constant dict only |
| C-26 reverse-grep | ✓ | Ten new module-level test symbols, each defined once; no consumer outside the owning module |
| `C-78-xvi` edge-arming | ✓ | `AT-B78-20` captures the header BEFORE the presses and requires a transition; every clause consuming it is on the post-capture read |
| `C-78-xiii` no fourth driver copy | ✓ | Inc-2's `_b78_drive_compare` / `_b78_press_compare` / `_b78_focus_run_list` reused verbatim |
| Corrected painted-height helper used, `§5.1` rule 1's form not propagated | ✓ | Inc-4 reads `size.height` (the CONTENT layer LLR-123.2 bounds on) and does not re-derive a painted metric; Inc-1's `_b78_painted_content_height` is untouched |
| Uncertainty surfaced, not hidden | ✓ | F-1 raised as a spec conflict needing a ruling (§6 item 1); R-2 declares its own co-assertion inert; §4.6 states the ledger is arithmetic, not a full-suite read |
| Review packet attached | ✓ | this document |

---

# ADDENDUM — Inc-4 gate review fixes (F-1 HIGH · F-2/F-3 MEDIUM · F-5 LOW)

**Scope:** `tests/test_tui_diff_screen.py` (1) + this document. **No production file touched, then or now** — the gate's HIGH was on a claim, not on the code, and the two centring mutations confirmed the implementation was already correct.

---

## A.1 BLUF — the HIGH was that I reported a discharge the way this batch has spent four increments learning not to

`A-6` was marked **DISCHARGED** on the strength of a number I measured and wrote down: *13 above / 14 below of 28*. The number is right — the reviewer re-measured it independently. **What was wrong is that nothing could tell if it stopped being right.** The reviewer ran the two mutations I did not:

| Mutation on the centring line | Inc-4 nodes red (pre-fix) |
|---|:-:|
| all surplus **above** (`// 2` → removed) | **0 of 10** |
| all surplus **below** (`// 2` → `0`) | **0 of 10** |

`TC-B78-24` pins the row **count**, and both one-sided splits preserve the count exactly. **The count clause cannot see position at all**, and position is the entirety of what `A-6` asks about.

**This is `C-78-xv` one layer up, and that is the finding worth carrying.** `C-78-xv` says a *declared mutation* must be a value substitution that type-checks, or it is a wish. Inc-3 shipped that. Inc-4 shipped the same defect applied to a *declared discharge*: a control asserting a property it does not test. The batch's recurring pattern is not "specs are wrong" — it is **checks that name a subject they never reach**, and it has now appeared in a spec clause (Inc-1), an acceptance (Inc-2), a driver (Inc-3) and a report (Inc-4).

---

## A.2 F-1 — the centring predicate, `TC-B78-50`

Minted at **`TC-B78-50`** (batch high-water was `TC-B78-49`, Inc-2's; `AT-TC-REGISTRY.jsonl` untouched per C14). Its own node, not a third arm on `TC-B78-24`, because **count and position are different observables** and the reviewer's table is the proof: one is invariant under the mutations that redden the other.

The observable is the imbalance around the run's own row:

```python
above = rows.index(run_row)
below = len(rows) - above - 1
assert abs(above - below) <= 1
```

`<= 1` rather than `== 0` because an odd surplus cannot split evenly — the tolerance is arithmetic, not slack.

**Two preconditions, both asserted rather than assumed**, because either one silently makes the predicate vacuous:

| Precondition | Why it is load-bearing |
|---|---|
| `len(rows) > 3` (the floor) | With no surplus there is nothing to split and the clause is trivially true. |
| `rows[0] > 0` (the address-0 clamp is not binding) | If the clamp binds, the window is pinned to 0 and a one-sided split is **indistinguishable** from a centred one — the fixture sits at `0x1000` precisely so the clamp cannot mask the split. |

Read at **both** gate sizes, per-arm (CC-1).

### The two mutations, executed

```
BASELINE sha=2429d588ed343e44   Inc-4 set: green | 11 passed, 24 deselected in 22.13s

--- R5 / A-6 centring --- ALL surplus ABOVE the run (the '// 2' split removed)
    substituted: 'low = max(0, low - ((capacity - rows) // 2) * HEX_WIDTH)'
             ->  'low = max(0, low - (capacity - rows) * HEX_WIDTH)'
    APPLIED=True  sha 2429d588ed343e44 -> 7e8241cdc92de88b -> 2429d588ed343e44 (restored)
    Inc-4 SET  RED   | 1 failed, 10 passed, 24 deselected in 23.49s
    reddened nodes: ['test_tc_b78_50_the_surplus_rows_are_split_around_the_run']
    failure: E  AssertionError: (132, 44): the surplus rows must be SPLIT around the
      selected run, not piled on one side; the run's row 0x00001000 sits at index 10
      of 12 - 10 rows above it and 1 below
    POST (restored) target node: green

--- R6 / A-6 centring --- ALL surplus BELOW the run (the lead substituted to 0)
    substituted: 'low = max(0, low - ((capacity - rows) // 2) * HEX_WIDTH)'
             ->  'low = max(0, low - 0 * HEX_WIDTH)'
    APPLIED=True  sha 7e8241cdc92de88b -> dc4cad6766dccbac -> 2429d588ed343e44 (restored)
    Inc-4 SET  RED   | 1 failed, 10 passed, 24 deselected in 23.34s
    reddened nodes: ['test_tc_b78_50_the_surplus_rows_are_split_around_the_run']
    failure: E  AssertionError: (132, 44): the surplus rows must be SPLIT around the
      selected run, not piled on one side; the run's row 0x00001000 sits at index 1
      of 12 - 1 rows above it and 10 below
    POST (restored) target node: green
```

**`reddened nodes:` is the line that matters.** Each arm ran the **whole Inc-4 set**, not just its target, so the transcript shows the reviewer's *0 of 10* becoming **1 of 11** — and shows that the one is `TC-B78-50` and nothing else. Had it reddened three nodes, the count clause and the position clause would have been entangled and the new node would not have been the thing doing the work.

**Both mutations are value substitutions that type-check** (`C-78-xv`): R6 is written `- 0 * HEX_WIDTH` rather than deleting the term, so the substituted VALUE is on the record and not merely a described deletion (*record the substituted VALUE, not the deleted operator*).

---

## A.3 F-2 — `LLR-123.3`'s "each of the three kinds", and why one kind proved nothing

`AT-B78-20` asserted `"changed" in header`. **`changed` is the one key `_KIND_LABEL` maps to itself.** The assertion therefore held for a reason that had nothing to do with the mapping: `self._KIND_LABEL.get(kind, kind)` → `kind` renders the raw key and `"changed"` is still in the header.

The fix presses `down` once more onto run 4, whose kind is `only_a` and whose label is `only A`, and asserts **both directions** — the label present, the raw key absent. Both literals are written out; deriving either from `_KIND_LABEL` would read the expectation off the class under test (spec F-6, the defect that made `AT-B78-22` inert in rev-1).

```
--- R7 / LLR-123.3 mapping --- the header renders the raw kind KEY instead of its label
    substituted: 'f"{self._KIND_LABEL.get(kind, kind)}"'  ->  'f"{kind}"'
    APPLIED=True  sha dc4cad6766dccbac -> 5bea2eabec9df1de -> 2429d588ed343e44 (restored)
    Inc-4 SET  RED   | 1 failed, 10 passed, 24 deselected in 23.91s
    reddened nodes: ['test_at_b78_20_selection_re_renders_both_windows']
    failure: E  AssertionError: the A window header must name the run's classification
      through the kind LABEL, not its raw key; expected 'only A' in
      header='Image A - Run #4 0x00000400-0x0000040...'
    POST (restored) target node: green
```

M4 in §4.4 (label → empty string) and R7 (label → raw key) are **different mutations and the pre-fix node survived exactly one of them**: blanking the label removes `changed` too, so M4 reddened; substituting the key leaves `changed` intact, so R7 would not have. *A mutation that reddens is not evidence that the clause is discriminating — only that the one you chose happened to be visible.*

**`LLR-123.3` says "each of the three kinds" and this now covers two.** `only_b` → `only B` is the same non-identity shape as `only_a` and is not separately asserted. Recorded as an honest gap, not claimed as complete.

---

## A.4 F-3 — the `C-78-xviii` collision, resolved by withdrawal rather than renumbering both

The id named two different lessons in two documents:

| Location | Lesson |
|---|---|
| `01-requirements.md:898` (coordinator's) | a measured figure is re-derivable only with the **increment** it was measured at |
| `increment-004.md:268` (mine) | a requirement with two exactness clauses owes the region where they are **jointly satisfiable** |

I cannot write `01-requirements.md`, and I had *also* minted `C-78-xix` for the re-derivability lesson — so the same lesson had two ids and one id had two lessons. Both halves resolved in this document:

- **`C-78-xix` WITHDRAWN.** The re-derivability lesson is already `C-78-xviii` at `01-requirements.md:898`, recorded by the coordinator from this increment's own finding. Nothing is dropped; the citation points there.
- **My empty-intersection carry renumbered `C-78-xxi`**, clear of the coordinator's `C-78-xx`.
- **`C-78-xx` recorded in §6b** so the pipeline-exit-status carry survives in a second place.

**No id now names two lessons and no lesson now has two ids.**

---

## A.5 F-5 — the citation, and what it cost to find

Both citations re-derived by execution, not by re-reading the spec:

| Claim | Spec / packet said | Executed |
|---|---|---|
| `_KIND_LABEL` | `:6637-6641` | **`:6639-6643`** |
| `#diff_hex_a` / `#diff_hex_b` `markup=False` | `:6767-6768` | **`:6770-6771`** |

**The reviewer's note is the finding, not the two line numbers.** The wrong `markup=False` citation was copied out of the spec **in the same paragraph that corrects the `_KIND_LABEL` citation** (§1.4). The packet instantiated its own carry in the act of writing it down — one citation was re-derived because it was the increment's subject, the neighbouring one was copied because it was "just context". *A citation is either re-derived or it is a rumour, and proximity to a corrected one confers nothing.*

---

## A.6 Files modified (addendum)

| File | Change |
|---|---|
| `tests/test_tui_diff_screen.py` | `TC-B78-50` (new node, +1) · `AT-B78-20` gains the non-identity kind arm · node-map comment updated |
| `.dev-flow/2026-08-06-batch-78/03-increments/increment-004.md` | this addendum + fifteen in-place corrections (BLUF F-2 verdict, two citations, node counts, ledger, carry ids, `min` rationale, R-4, pending items 1/2/3/7) |

**Still 2 files.** No production file touched by the addendum. `01-requirements.md`, `state.json`, `PLAN.md`, `AT-TC-REGISTRY.jsonl` and `prototypes/memmap2.*` read-only throughout.

**C-26 reverse-grep:** the addendum mints no new module-level symbol; `TC-B78-50` reuses `_b78_drive_compare`, `_b78_window_geometry`, `_diff_result`, `_B78_AT22_RUN`, `_B78_INC4_WIDE` and `_B78_INC4_TALL`. **No fourth driver copy** (`C-78-xiii` / F9).

---

## A.7 Test results (addendum)

### A.7.1 The Inc-4 node set

```
tests/test_tui_diff_screen.py -k "<the 11 Inc-4 nodes>"
11 passed, 24 deselected in 22.13s
```

### A.7.2 The increment's file + the other window consumer — ONE run, FULL form

```
tests/test_tui_diff_screen.py tests/test_tui_diff_compare_realpath.py
.........................................                                [100%]
41 passed in 92.34s (0:01:32)
```

### A.7.3 C-34 gate — re-run post-fix, ONE run, FULL form

```
tests/test_tui_directionb.py
........................................................................ [ 39%]
........................................................................ [ 78%]
.......................................                                  [100%]
183 passed in 245.50s (0:04:05)
```

### A.7.4 Restore proof

```
FINAL sha=2429d588ed343e44  baseline=2429d588ed343e44  equal=True
FINAL Inc-4 set: green | 11 passed, 24 deselected in 23.10s
```

Seven mutations across the two harnesses (M1–M4, R5–R7), each applied-checked, each sha-chained against the **previous** mutation as well as the baseline, each restored in a `finally`, **every one reddening on an `AssertionError` carrying its node's own message**. Zero `TypeError`, zero import errors, zero collection errors.

**Every verdict in both harnesses is read from `subprocess.run(...).returncode`** — never from a piped `tail`. That is `C-78-xx` avoided by construction rather than by luck, and it is worth stating explicitly now that the carry exists.

### A.7.5 Ledger

**2626 → 2637** (`D = 0`, `A = 11`). Arithmetic on Inc-3's tracked figure, per C-19; honestly 2636 + the one drifted snapshot cell until Inc-12. Snapshot state re-checked: unchanged at **1 failed, 31 passed**, still only `[diff-comfortable-120x30]` — the addendum touches no production code, so no new cell can have moved.

---

## A.8 Carries after the addendum

| Id | Carry | Status |
|---|---|---|
| **`C-78-xxi`** | A requirement with two exactness clauses over the same output owes the region where they are jointly satisfiable. | 🆕 renumbered here |
| **`C-78-xx`** | A gate invocation piped through `tail` / `head` reports the pipeline's exit status, not the gate's. Preferred fix: move the gate into the RC-1 pre-commit hook. | coordinator's; **owed an owner** |
| **`C-78-xviii`** | A measured figure is re-derivable only with the increment it was measured at. | coordinator's, `01-requirements.md:898`; my duplicate `C-78-xix` **withdrawn** |
| **🆕 `C-78-xxii`** | **A declared DISCHARGE must be a predicate that can go red, not a measurement someone recorded.** `C-78-xv` caught this shape in a declared *mutation*; this is the same defect in a declared *discharge*, and it is worse, because marking an `assumed` item discharged removes it from scrutiny permanently. Both one-sided splits of a centring arithmetic left **10 of 10** nodes green while the report called it verified. **An `assumed — verify at Phase 3` item is closed by a node, or it is not closed.** | 🆕 |
| **🆕 `C-78-xxiii`** | **A mutation that reddens does not prove the clause discriminates — only that the mutation you chose was visible.** `AT-B78-20`'s kind clause reddened under *label → empty* and would have survived *label → raw key*, because it asserted the one key that maps to itself. **When a clause tests a mapping, mutate to the IDENTITY, not to nothing.** | 🆕 |
| **`F9`** | `_b78_press_compare`/`_press_compare` and `_b78_run_list_text`/`_run_list_text` remain duplicated near-copies. The addendum added no copy. | carried, unchanged |
| **`C-78-xiv`** | The two `TC-024` nodes still carry the unsound `press()` + `wait_for_complete()` shape. | carried, unchanged |

---

## A.9 Evidence checklist (addendum)

| Item | ✓/✗ | Evidence |
|---|---|---|
| The HIGH is fixed by a predicate, not by prose | ✓ | `TC-B78-50`; R5 and R6 each redden it, each on its own `AssertionError` |
| The new node is the ONLY thing that sees the defect | ✓ | A.2 — `reddened nodes: ['test_tc_b78_50…']`, 1 of 11, both arms |
| The count clause is kept, not replaced | ✓ | `TC-B78-24`'s `len(rows) == content_h - 1` untouched; the two are different observables |
| F-2 discharged by a non-identity mapping | ✓ | A.3 — R7, `only_a` → `only A`, both directions asserted |
| F-3 leaves no id collision | ✓ | A.4 — `C-78-xix` withdrawn, mine renumbered `C-78-xxi`, `C-78-xx` recorded |
| F-5 both citations re-derived by execution | ✓ | A.5 — `:6639-6643` and `:6770-6771`, corrected at all four sites in this document |
| Gates re-run after the fix | ✓ | A.7.2 **41 passed** · A.7.3 **183 passed** · A.7.1 **11 passed** |
| Restore proof | ✓ | A.7.4 — `FINAL sha == baseline`, per-stage shas distinct, set green after restore |
| No production file touched by the addendum | ✓ | A.6 — the fix was to a claim and to a test; the implementation was already correct |
| No secrets, no destructive commands, no `git add -A`, no `git stash` | ✓ | Mutations restored by writing back saved bytes in a `finally`, never by `git checkout` |
| File count within cap | ✓ | 2 of 5, unchanged |
| Uncertainty surfaced | ✓ | A.3 records `only_b` as an honest coverage gap; A.8 carries `C-78-xx` as **owed an owner** rather than assuming Inc-5 takes it |
