# Increment 005 — HLR-124, three width/height regimes and no silently empty panel

**Batch:** `2026-08-06-batch-78` · **Lane:** A (`.dev-flow/BACKLOG-CODE.md`)
**Branch:** `claude/batch-78-cmdbar-a2bdiff` · **Base at kickoff:** `b12b205`
**Spec authority:** `01-requirements.md` §7 Inc-5 row · HLR-124 · LLR-124.1/.2/.3/.4 · §2.8 D-1 (operator ruling R-1) · §3 Acceptance · §5.3 rows `AT-B78-23`, `AT-B78-25`, `AT-B78-29` · §8 `A-1`, `A-2`
**ATs realized:** `AT-B78-23`, `AT-B78-29` (2 GATEs) · **TCs:** `TC-B78-29…33`, plus `TC-B78-51`, `TC-B78-52`, `TC-B78-53` minted here
**Files:** `s19_app/tui/screens_directionb.py`, `s19_app/tui/app.py`, `s19_app/tui/styles.tcss`, `tests/test_tui_diff_screen.py` (**4**, cap 5)

---

## BLUF

**Shipped: all four HLR-124 LLRs — the named constants and their own regime class, the wide layout, the fallback overlay with a paginable viewport, and the two-axis notice.** Both gates are green, nine counterfactuals were executed with applied-checks and sha chaining, and the tree was restored byte-identically.

**`A-1` and `A-2` are both discharged by execution, and both corrected the spec.**

| # | Finding | Verdict |
|---|---|---|
| **F-1** | **The two hex windows cannot sit side by side at ANY supported width, and the spec's own arithmetic says so without saying it.** `L + 5 + 79 + 5 ≤ C` budgets **one** window; LLR-124.2's *"a single window column holding both hex windows"* is the only reading that closes. So the windows **stack**, and the vertical budget halves — which is the whole reason `_DIFF_MIN_H` moved. | ⚠️ **spec implication, made explicit** |
| **F-2** | **`A-1`: `_DIFF_MIN_H` is 26, not 29.** Re-derived against the real implementation with the regime gate bypassed (the first sweep was circular — the constant decided its own measurement). Width-independent at W = 94, 120 and 138, so the spec's **width-independence claim reproduces exactly; only the value moved.** The spec's 29 is reproducible on this branch — as the floor with the command-bar row **still present**, which is not the state `A-1`'s own quantity is defined in. | ❌ **spec figure corrected** |
| **F-3** | **`A-2`'s premise is false: the command palette has no `escape`-to-close.** `command_bar.py` declares no `BINDINGS` and handles no `escape`; the palette closes only through `_dispatch_palette_entry` (`:295`) and `on_list_view_selected` (`:279`). Executed: `ctrl+k` then `escape` leaves `palette_is_open` **True**. There was nothing to shadow. The property `A-2` wanted — the panel's `escape` never reaching outside the panel — **is** true and is now pinned. | ❌ **premise FALSE, property discharged anyway** |
| **F-4** | **Inc-2's reachability ATs would have gone silently vacuous.** At `_B78_AT_SIZE` = 132×44 the regime is the FALLBACK one, so the run list is now an overlay. `AT-B78-16` went RED (nothing to click) — but `AT-B78-15` and `AT-B78-17` stayed **GREEN against a `display: none` list**, because `Widget.focusable` does not consult `display`. One red node was the only visible symptom of three affected. | ⚠️ **caught by the regression run** |
| **F-5** | **A probe defect of mine that read exactly like an app defect.** `bool(widget)` is `len(children) > 0` in Textual, so `app.focused if app.focused else None` reports **None** for an empty `ListView`. I recorded "the overlay does not focus the list" and wrote a code comment asserting a fix was required. Both were wrong; the comment was removed rather than shipped. | ❌ **my defect, caught before it shipped** |

**Plus one real defect the wrong probe accidentally led me to:** dismissing the overlay blurred the list and left focus at `None`, so `f` could no longer reopen it. Fixed by restoring the prior focus, and pinned by `TC-B78-51`.

---

## 1. What changed

### 1.1 The defect

The shipped three-way `1fr` split gave the run list and both hex windows a third of `#diff_columns` each — **39** cells at 160×40 and **26** at 120×30, against an emitted hex row of **79**. Every hex row wrapped at every supported width, and below the deliverable range the panel rendered an empty box and said nothing about why.

### 1.2 `LLR-124.1` — named constants, and a class of its own

Three module-level constants in `screens_directionb.py`, all **terminal** dimensions compared against `events.Resize.size`, exactly as the `_apply_width_regime` precedent does:

| Constant | Value | Basis |
|---|---|---|
| `_DIFF_WIDE_MIN` | **139** | reproduced to the column on the real implementation: 138 → window 78 (wraps), **139 → 79** (fits) |
| `_DIFF_MIN_W` | **94** | reproduced: a full-width window is 82 content cells at W = 94 and the notice boundary sits one column below |
| `_DIFF_MIN_H` | ~~26~~ → **28** | **re-derived (F-2)** — the spec's 29 was a `styles.height = 1` simulation of a layout that no longer exists. ⚠️ **Corrected at the gate:** 26 counted the window's header row; the normative metric is `LLR-125.2`'s *hex row*, which gives **28**. See the addendum's F-1. |

`AbDiffPanel.apply_regime(width, height)` sets exactly one of `diff-wide` / `diff-fallback` / `diff-notice` on `#ab_diff_panel` and refreshes the notice text. `S19TuiApp._apply_diff_regime` is two lines and delivers the terminal size from `on_resize`; the arithmetic stays in the panel. **`width-narrow` is untouched** — it is toggled at 120 and read by 11 rules across workspace, map, patch and rail.

The regime is evaluated two-axis-first and breakpoint-second, because the deliverability floors are independent of each other and the wide breakpoint is a refinement *within* deliverability.

### 1.3 `LLR-124.2` — the wide layout, and why the windows stack (F-1)

`compose` gains `Vertical(id="diff_window_column")` around the two window `Static`s. This is forced, not chosen:

```
C at 160  = 132 content cells
  run list  22 content + 5 chrome = 27
  remainder                        = 105  ->  one window of 100 content cells
```

There is no supported width at which two 79-cell windows fit beside each other — 132 is the widest `C` the snapshot matrix produces. The spec's own side-by-side bound `L + 5 + 79 + 5 ≤ C` budgets exactly **one** window, and LLR-124.2's *"a single window column holding both hex windows"* is the only reading that closes; the consequence — the vertical budget halves — is what moved `_DIFF_MIN_H`.

Executed at 160×40: `#diff_hex_a` **100** ≥ 79, run list **22** beside it.

### 1.4 `LLR-124.3` — the fallback overlay and the paginable viewport

**The overlay costs nothing, open or shut.** `#diff_columns` declares `layers: base runs` in the fallback regime and the run list sits on the `runs` layer, so it gets its own layout pass over the same region. Executed at 132×44: `#diff_hex_a` is **102** cells wide with the overlay closed and **102** with it open. That is stronger than *"no PERMANENT columns"* and is asserted as an equality, because a `>= 79` clause in both states would pass an implementation that shrinks the window by ten columns while the list is up.

Opened on `f`, dismissed on `escape`, both **widget-scoped on the panel** and both `show=False` — D-2 ruled out a new App-level binding and `AT-B78-32` pins `app.py`'s `BINDINGS` block at a zero-line diff. None of `f`, `escape`, `[`, `]` is bound at application level, so nothing is shadowed. `check_action` gates the overlay key on the fallback regime and gates `escape` on the overlay actually being open, so outside that state the panel does not claim the key at all. ⚠️ **Corrected at the gate (F-2):** the paging keys were gated the same way and must not be — overflow is a property of the run against the pane, not of the regime, and the gate stranded 65 of 66 rows at 160×40. They are now active in every regime but the notice one.

**The windows lose their border and vertical padding in this regime, and that is the whole reason it can deliver anything.** At 120×30 the results pane is 6 rows; two bordered boxes spend **8** of them on chrome. Borderless, each window gets 3 content rows — a header plus **2 hex rows**, which is exactly the viewport R-1's operator accepted. Horizontally nothing is lost that matters: 92 − 2 padding = **90** content cells against the spec's bordered estimate of 87.

**Pagination re-renders; it does not scroll.** Measured first: a `Static` with no children reports `is_scrollable == False`, so `scroll_page_down` is a silent no-op on these windows. Instead `_window_page` shifts the row list, and **page 0 is byte-identical to what Inc-4 shipped** — which is what keeps `AT-B78-22`'s exact address set sound. The page is clamped against the run's own span and written back, so `]` at the last page is a no-op rather than an empty window, and any selection change or new comparison resets it to 0.

### 1.5 `LLR-124.4` — the notice names every unsatisfied axis

`Static(id="diff_size_notice")`, displayed only in the notice regime, with `#diff_columns` hidden — *"shall not render an empty results area"* is implemented as *there is no results area to be empty*.

```
The A2B diff result windows need a larger terminal.
  width 80 - needs at least 94 columns
  height 24 - needs at least 26 rows
```

One line per **failed** axis. **SEC-F2 holds by construction:** author-constant text plus integers from the terminal geometry and the regime constants; no file path, image label or artifact name can reach it, and `AT-B78-29` asserts that rather than assuming it.

### 1.6 What this increment deliberately does NOT do

| Not done | Why |
|---|---|
| Observe the fallback regime at 120×30 | `AT-B78-24` / `AT-B78-25` / `AT-B78-26` are **Inc-10's** — they need the command-bar rows gone (§7 BL-2). §7's Inc-5 row states this split explicitly: LLR-124.3 is **built** here and **observed** there. |
| Touch `app.py`'s `BINDINGS` block | `AT-B78-32` (Inc-6) pins it at a zero-line diff. Every key added here is widget-scoped. |
| Regenerate the drifted snapshot | C9 / C-30 — CI-only, Inc-12 owns it. |
| Add a Footer chip for `f` | LLR-126.1 requires the `show and enabled` set to be set-EQUAL to its pre-change 14. The affordance naming the key is Inc-6's. |

---

## 2. Files modified

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | three module constants · `AbDiffPanel.BINDINGS` (4, all `show=False`) · `apply_regime` / `_regime_for` / `_notice_text` / `check_action` / four overlay+paging actions / `_page_windows` (new) · `compose` gains `#diff_window_column` and `#diff_size_notice` · `_render_run_windows` gains the clamped page branch · three new instance fields |
| `s19_app/tui/app.py` | `_apply_diff_regime` (new, 1 statement) · `on_resize` calls it |
| `s19_app/tui/styles.tcss` | the window column, the stacked windows, the notice, and the three regime blocks |
| `tests/test_tui_diff_screen.py` | the Inc-5 block (2 ATs + 8 TCs + 2 helpers) · `_b78_open_run_list` + its call from `_b78_drive_compare` (F-4) · `_B78_INC4_SHORT` 132×24 → 132×26 |

**4 files. Cap 5.** `.dev-flow/state.json`, `PLAN.md`, `00-measurements.md`, `01-requirements.md`, the `02-review-*.md` files, earlier `increment-*.md` and `AT-TC-REGISTRY.jsonl` were **read, never written**. `prototypes/memmap2.*` (the parallel session's) untouched; no `git add -A`, no `git stash`.

**C-26 reverse-grep.** New module-level test symbols `_B78_INC5_WIDE`, `_B78_INC5_FLOOR`, `_b78_widest_emitted_hex_row`, `_b78_regime_probe`, `_b78_open_run_list` — each defined exactly once, no consumer outside the owning module.

**`C-78-xiii` / F9 honoured — no fifth driver copy.** `_b78_drive_compare`, `_b78_press_compare`, `_b78_run_list`, `_b78_window_rows`, `_b78_window_text` and `_b78_painted_content_height` are Inc-1's / Inc-2's / Inc-4's and are reused as-is. `_b78_open_run_list` is a new **step**, not a new driver: it is called from the existing driver and adds four lines.

**`C-78-vi` honoured.** Every painted-height read goes through Inc-1's corrected `_b78_painted_content_height` (`content_region` intersected through the full ancestor chain). §5.1 rule 1's form is not propagated anywhere in the new block.

---

## 3. How to test

```bash
cd C:/Users/jjgh8/Github/s19_app

# the increment's own nodes
python -m pytest tests/test_tui_diff_screen.py -k "b78_23 or b78_29 or b78_30 or b78_31 or b78_32 or b78_33 or b78_51 or b78_52 or b78_53" -q

# the increment's file + the other diff consumer, ONE run, FULL form
python -m pytest tests/test_tui_diff_screen.py tests/test_tui_diff_compare_realpath.py -q

# the C-34 gate: the full guard host, ONE run, FULL form
python -m pytest tests/test_tui_directionb.py -q

# the expected drift - DO NOT regenerate locally (C9; Inc-12 owns regen)
python -m pytest tests/test_tui_snapshot.py -q

# the nine counterfactuals, applied-checked and sha-restored
python <scratchpad>/mutate_inc5.py
```

---

## 4. Test results

### 4.1 The increment's own nodes

```
tests/test_tui_diff_screen.py -k "b78_23 or b78_29 or ... or b78_53"
.............                                                            [100%]
13 passed, 32 deselected in 44.76s
```

The 13 selected include Inc-4's `test_tc_b78_23_zero_runs_keeps_the_no_runs_text` and `test_tc_b78_29_...`-adjacent substring matches; **Inc-5's own nodes are 10**, and the mutation harness in §4.4 runs them by exact node id.

### 4.2 The increment's file + the other diff consumer — ONE run, FULL form

```
tests/test_tui_diff_screen.py tests/test_tui_diff_compare_realpath.py
...................................................                      [100%]
51 passed in 132.29s (0:02:12)
```

### 4.3 C-34 gate — ONE run, FULL form

```
tests/test_tui_directionb.py
........................................................................ [ 39%]
........................................................................ [ 78%]
.......................................                                  [100%]
183 passed in 236.35s (0:03:56)
```

### 4.4 Counterfactuals — nine mutations, each applied-checked, each sha-chained and restored

Every mutation is a **value substitution that type-checks** (`C-78-xv`). Every one is verified to have **landed** — the old token asserted absent after the write — and every sha is chained against the **previous** mutation's as well as the baseline. Each arm runs the **whole Inc-5 node set by exact node id**, so the transcript shows *which* nodes reddened rather than only that something did (Inc-4 addendum A.2). Every verdict is read from `subprocess.run(...).returncode`, never a piped `tail` (`C-78-xx`).

```
BASELINE sha=a83738cc12b0d7a5
BASELINE Inc-5 set: green | 10 passed in 39.74s

--- M1 / AT-B78-23 --- the wide regime's fixed run-list column -> the pre-change proportional split
    file: styles.tcss
    substituted: '#ab_diff_panel.diff-wide #diff_range_list {\n    width: 26;\n}'
             ->  '#ab_diff_panel.diff-wide #diff_range_list {\n    width: 1fr;\n}'
    APPLIED=True  sha a83738cc12b0d7a5 -> 3db376394d17f812 (mutated)
    Inc-5 SET  RED | 2 failed, 8 passed in 43.07s
    reddened nodes: ['test_at_b78_23_no_wrapped_row_in_the_wide_regime',
                     'test_tc_b78_29_the_layout_flips_exactly_once']
    POST (restored): green | 10 passed in 42.89s

--- M2 / AT-B78-29 presence --- the deliverability test -> never fails, so the notice never appears
    file: screens_directionb.py
    substituted: 'if width < _DIFF_MIN_W or height < _DIFF_MIN_H:'
             ->  'if width < 0 or height < 0:'
    APPLIED=True  sha 3db376394d17f812 -> eac9df7ab6b78e0f (mutated)
    Inc-5 SET  RED | 4 failed, 6 passed in 43.04s
    reddened nodes: ['test_at_b78_29_notice_names_every_unsatisfied_axis',
                     'test_tc_b78_31_the_width_floor_is_the_notice_boundary',
                     'test_tc_b78_32_a_single_axis_failure_names_that_axis',
                     'test_tc_b78_33_the_regime_applies_with_no_comparison']
    POST (restored): green | 10 passed in 40.95s

--- M3 / AT-B78-29 mapping (C-78-xxiii) --- the failed WIDTH axis is named 'height'
    file: screens_directionb.py
    substituted: 'lines.append(f"  width {width} - needs at least {_DIFF_MIN_W} columns")'
             ->  'lines.append(f"  height {width} - needs at least {_DIFF_MIN_W} columns")'
    APPLIED=True  sha eac9df7ab6b78e0f -> dc3ef01e666c2064 (mutated)
    Inc-5 SET  RED | 3 failed, 7 passed in 38.82s
    reddened nodes: ['test_at_b78_29_notice_names_every_unsatisfied_axis',
                     'test_tc_b78_31_the_width_floor_is_the_notice_boundary',
                     'test_tc_b78_32_a_single_axis_failure_names_that_axis']
    POST (restored): green | 10 passed in 40.72s

--- M4 / TC-B78-29 --- the wide breakpoint test -> always true, so the layout never flips
    file: screens_directionb.py
    substituted: 'if width >= _DIFF_WIDE_MIN:'  ->  'if width >= 0:'
    APPLIED=True  sha dc3ef01e666c2064 -> e6923e7fb09979aa (mutated)
    Inc-5 SET  RED | 7 failed, 3 passed in 33.58s
    reddened nodes: ['test_tc_b78_29_the_layout_flips_exactly_once',
                     'test_tc_b78_30_a_resize_across_the_breakpoint_follows',
                     'test_tc_b78_31_the_width_floor_is_the_notice_boundary',
                     'test_tc_b78_33_the_regime_applies_with_no_comparison',
                     'test_tc_b78_51_escape_dismisses_without_shadowing',
                     'test_tc_b78_52_pagination_reaches_bytes_past_the_pane',
                     'test_tc_b78_53_the_overlay_reserves_no_width']
    POST (restored): green | 10 passed in 41.22s

--- M5 / TC-B78-30 --- on_resize hands the panel a CONSTANT size instead of the event's
    file: app.py
    substituted: 'self._apply_diff_regime(event.size.width, event.size.height)'
             ->  'self._apply_diff_regime(160, 40)'
    APPLIED=True  sha e6923e7fb09979aa -> 2550020276071cc1 (mutated)
    Inc-5 SET  RED | 9 failed, 1 passed in 33.57s
    reddened nodes: [all nine regime-observing nodes; only AT-B78-23 survives,
                     because 160x40 is the size the mutation pins to]
    POST (restored): green | 10 passed in 39.80s

--- M6 / TC-B78-51 arm 1 --- dismissal removes a class the panel does not carry
    file: screens_directionb.py
    substituted: 'self.remove_class(self._RUNS_OPEN)\n        restore'
             ->  'self.remove_class(self._REGIME_NOTICE)\n        restore'
    APPLIED=True  sha 2550020276071cc1 -> 728cf5a6f020b9c9 (mutated)
    Inc-5 SET  RED | 1 failed, 9 passed in 41.03s
    reddened nodes: ['test_tc_b78_51_escape_dismisses_without_shadowing']
    POST (restored): green | 10 passed in 39.63s

--- M7 / TC-B78-52 --- the page index stops moving (+direction -> +0)
    file: screens_directionb.py
    substituted: 'self._window_page = max(0, self._window_page + direction)'
             ->  'self._window_page = max(0, self._window_page + 0)'
    APPLIED=True  sha 728cf5a6f020b9c9 -> d24741542c59fccb (mutated)
    Inc-5 SET  RED | 1 failed, 9 passed in 40.68s
    reddened nodes: ['test_tc_b78_52_pagination_reaches_bytes_past_the_pane']
    POST (restored): green | 10 passed in 40.33s

--- M8 / TC-B78-53 --- the overlay leaves its own layer and re-enters the flow
    file: styles.tcss
    substituted: '    display: none;\n    layer: runs;\n    width: 32;'
             ->  '    display: none;\n    layer: base;\n    width: 32;'
    APPLIED=True  sha d24741542c59fccb -> 7586894a6a6cc807 (mutated)
    Inc-5 SET  RED | 1 failed, 9 passed in 38.52s
    reddened nodes: ['test_tc_b78_53_the_overlay_reserves_no_width']
    POST (restored): green | 10 passed in 39.39s

--- M9 / TC-B78-51 arm 2 (the PIN's attempted mutation) --- the panel's escape binding
    is made priority, to try to reach outside the panel
    file: screens_directionb.py
    substituted: 'Binding("escape", "close_run_overlay", "Close the run list", show=False)'
             ->  'Binding("escape", "close_run_overlay", "Close the run list", show=False, priority=True)'
    APPLIED=True  sha 7586894a6a6cc807 -> c8b178f77efbbc1a (mutated)
    Inc-5 SET  green (INERT) | 10 passed in 40.72s
    reddened nodes: []
    POST (restored): green | 10 passed in 40.79s

FINAL sha=a83738cc12b0d7a5  baseline=a83738cc12b0d7a5  equal=True
```

**Every reddening mutation failed on an `AssertionError` carrying the node's own message** — no `TypeError`, no import error, no collection error.

**M9 is INERT and that is the honest result, not a gap.** It is the strongest value substitution available for `TC-B78-51`'s arm 2, and `priority=True` does **not** make a widget binding fire while focus is outside that widget's subtree — Textual collects priority bindings from the screen and app namespaces, and this one is on neither. So the no-shadowing property in that direction is invariant by construction and arm 2 stays labelled a **PIN**. Recorded rather than quietly dropped, and recorded with its attempted mutation so nobody retries it.

**M4 and M5 redden broadly, and that is diagnostic rather than sloppy.** Both destroy the regime selection itself, so every node whose fixture depends on getting a particular regime goes red; the narrow mutations M1, M6, M7, M8 each redden exactly the one node that owns them, which is what shows the per-node clauses are not entangled. M5 leaves precisely `AT-B78-23` green, because 160×40 is the constant the mutation pins to — a detail worth stating, since a reader could otherwise take "9 of 10" as evidence that `AT-B78-23` is weak.

**This harness was itself run twice.** The first run was invoked as `python mutate_inc5.py 2>&1 | tail -100`, and the pipe **discarded the first eight arms' transcripts** — `C-78-xx`'s exact failure mode, committed by me, in the increment whose packet cites that carry. The verdicts survived only because the harness also prints a JSON summary at the end. The transcript above is the second, unpiped run; its per-arm verdicts reproduce the first run's JSON exactly, arm for arm.

### 4.4b Executed behaviour, per size (CC-1 per-arm)

Read off the live tree, no comparison driven. `#diff_hex_a` content width against the **79** the producer emits, and the painted content height through Inc-1's ancestor-chain helper.

| Terminal | Regime | `#diff_columns` painted | `#diff_hex_a` w × painted h | Unwrapped? | What the operator sees |
|---|---|---|---|---|---|
| **80×24** | `diff-notice` | 0 (hidden) | 0 × 0 | — | the notice, naming **both** axes: *"width 80 - needs at least 94 columns"* and *"height 24 - needs at least 26 rows"* |
| **80×30** | `diff-notice` | 0 (hidden) | 0 × 0 | — | the notice, naming **width only** — 30 ≥ 26 passes the height axis |
| **120×24** | `diff-notice` | 0 (hidden) | 0 × 0 | — | the notice, naming **height only** — 120 ≥ 94 passes the width axis |
| **120×30** | `diff-fallback` | 3 | **90** × 1 | ✅ 90 ≥ 79 | one full-width unwrapped window row; the run list is behind `f` and costs nothing. Post-Inc-10 this becomes 3 painted rows = header + **2 hex rows**, R-1's accepted viewport, to the row |
| **132×44** | `diff-fallback` | 17 | **102** × 8 | ✅ 102 ≥ 79 | a comfortable full-width fallback; the charter's own 132×44 capture is on the fallback side of its recommended line, exactly as LLR-124.2 predicted |
| **160×40** | `diff-wide` | 13 | **100** × 2 | ✅ 100 ≥ 79 | the run list **beside** a 100-cell window column — LLR-124.2's arithmetic (`132 − 27 = 105`, minus 5 chrome = 100) reproduces to the cell |

**The breakpoint reproduces to the column on the real implementation**, which the spec derived by simulation: `138×40` → `diff-fallback`, window **108**; `139×40` → `diff-wide`, window **79** — the first fit, exactly. `_DIFF_WIDE_MIN = 139` needs no correction.

### 4.5 Snapshot drift — recorded, NOT regenerated

```
tests/test_tui_snapshot.py
1 snapshot failed. 28 snapshots passed.
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[diff-comfortable-120x30]
1 failed, 31 passed, 1 warning in 68.06s (0:01:08)
```

**Exactly one cell, and it is the one Inc-1 already drifted.** No second cell moved — checked deliberately, because a regime change at 120×30 is precisely the kind of change that could move another, and the increment brief says to stop and report if it does. It did not: the other 28 cells render screens the diff panel does not appear on, and P-33b already established that the 120×30 diff golden contains no results-area text at all. Regeneration is CI-only and is Inc-12's (C9 / C-30).

### 4.6 Ledger

| Stage | Count |
|---|---|
| Baseline | 2607 |
| Inc-0 | 2608 |
| Inc-1 | 2612 |
| Inc-2 | 2625 |
| Inc-3 | 2626 |
| Inc-4 | 2637 |
| **Inc-5** | **2647** — `D = 0`, `A = 10` |

**Stated honestly:** 2647 is **arithmetic** on Inc-4's tracked figure, not a figure read off a full-suite run. Per C-19 and the increment brief the 26-minute suite was not run; the evidence is the complete targeted runs above (**51** + **183**, each read from its own output) plus a collection census — `tests/test_tui_diff_screen.py` collects **45 tests**, up from Inc-4's 35, `D = 0`. Like Inc-3's and Inc-4's, the figure is honestly 2646 + the one drifted snapshot cell until Inc-12 regenerates it.

---

## 5. Risks

| # | Risk | Severity | Mitigation / status |
|---|---|---|---|
| **R-1** | ⛔ **SUPERSEDED — see the ADDENDUM. The floor is 28.** This row said `_DIFF_MIN_H = 26` and disclosed only the *temporary* Inc-5→Inc-10 window; the gate found that 26 also ships a **permanent** 26–27 dead zone in the end state, because it counts the header row. Original wording kept for the record: *"`_DIFF_MIN_H = 26` is the POST-Inc-10 floor. As the tree stands the command-bar row still spends three rows, so the same sweep gives 29, and between Inc-5 and Inc-10 the heights 26–28 select the fallback regime while painting no hex row."* | ⛔ **was ⚠️ medium; the gate raised it to HIGH** | The **transient** disclosure was right and is retained (now heights 28–30). What it missed is that the constant's own metric was one row too weak — see the addendum's F-1. |
| **R-2** | **`AT-B78-25`'s pagination and 0-permanent-column clauses are observed at Inc-10, on a mechanism built here.** | low | This is §7's own split and BLK-A's lesson is about a mechanism with NO observing node. Both clauses have one here — `TC-B78-52` and `TC-B78-53` — at 132×44, which needs no Lane-1 work. Inc-10 still owns the 120×30 arms. |
| **R-3** | **Inc-2's reachability nodes now depend on a driver step that opens the overlay** (F-4). | ⚠️ medium | The alternative is worse: without it two of them pass over an invisible list. The step drives the shipped binding with a real `pilot.press("f")` and **asserts the list became displayed**, so a regression in the overlay reddens them rather than quietly re-vacuating them. |
| **R-4** | **`_B78_INC4_SHORT` moved 132×24 → 132×26**, changing a fixture another increment's gate uses. | low | Forced: 24 is below `_DIFF_MIN_H`, so at 132×24 the "pane whose content height is 0" that `AT-B78-22`'s docstring names no longer exists — the whole results area is hidden behind the notice. 132×26 keeps capacity 0 **and** is a state the operator is shown. `AT-B78-22` and `TC-B78-50` re-run green at the new size. ⚠️ **Not verified by me:** Inc-4's own M2 counterfactual (`high = end + ctx → high = end`) was **not** re-executed against the moved fixture. The reasoning that it still reddens — capacity is 0 at both sizes, so the floor is still the whole window and the emitted set still loses `0x00001010` — is reasoning, not a transcript. **Owed at the Inc-5 gate or by Inc-10.** |
| **R-5** | **The fallback regime drops the windows' border.** A reviewer may read this as a visual regression rather than a budget decision. | low | It is the difference between 2 hex rows and 0 at 120×30. Scoped to the fallback regime only; the wide regime keeps the bordered boxes, and the spec's own 160-column arithmetic (100 content cells) assumes them. |
| **R-6** | `f`, `[` and `]` only fire while focus is inside the panel. An operator whose focus is on the rail cannot open the overlay. | low | Correct for a widget-scoped binding and the only form D-2 permits. The panel's own controls are all in the focus chain, and the discoverability affordance naming the keys is Inc-6's. |

**Security:** no new I/O, no network, no credential path, no external-tool surface. The one new sink is `#diff_size_notice`, and it is bounded at construction (`markup=False`) **and** at composition (author-constant text plus geometry integers, asserted by `AT-B78-29`). `#diff_hex_a` / `#diff_hex_b` remain constructed `markup=False`. No secret is read, printed or committed.

---

## 6. Pending items

1. **`A-1` is discharged and the spec's figure is wrong.** `_DIFF_MIN_H` is **26**, not 29. §8's A-1 row and §2.8 D-1's *"measured floor `H ≥ 29`"*, plus LLR-124.1's *"`_DIFF_MIN_H = 29` … 28 → 0, 29 → 1"*, all need the value corrected. **I do not write `01-requirements.md`.** The width-independence claim beside it is correct and reproduced.
2. **`A-2` is discharged and its premise is false.** There is no palette `escape`-to-close to shadow. §8's A-2 row and LLR-124.3's *"must not shadow the palette's `escape`-to-close"* both rest on it, and **so does `LLR-119.3` / `AT-B78-07`, which is Inc-9's** — that increment should not assume the mechanism exists.
3. **`TC-B78-51`'s arm 2 is a PIN, labelled.** The no-shadowing property in that direction is invariant by construction; the only mutation that could redden it is structural. M9 attempted the closest value substitution available and its result is recorded in §4.4 either way.
4. **Snapshot regen** — still exactly one cell, still Inc-12's, still CI-only.
5. **`F9` unchanged** — `_b78_press_compare`/`_press_compare` and `_b78_run_list_text`/`_run_list_text` remain duplicated near-copies across the two diff modules. Inc-5 added no copy.
6. **`C-78-xiv` unchanged** — the two `TC-024` nodes still carry the unsound `press()` + `wait_for_complete()` shape.
7. **`C-78-xx` still owed an owner** — the piped-`tail` exit-status carry is process work. Inc-5's harness reads every verdict from `subprocess.run(...).returncode`.

## 6b. Batch carry list (additions)

| Id | Carry |
|---|---|
| **🆕 `C-78-xxiv`** | **A sweep whose threshold decides which branch it measures measures the threshold.** The first `_DIFF_MIN_H` re-derivation put the panel in the notice regime below the constant, so every row under it read 0 — a number produced by the constant, not by the budget, and indistinguishable from the real floor. The fix is to force the branch under test and let the sweep find where it fails. *A measurement that the thing being measured can veto is not a measurement.* |
| **🆕 `C-78-xxv`** | **A geometry constant carried across a layout change is a stale constant, however carefully it was measured.** `_DIFF_MIN_H = 29` was measured honestly, on a side-by-side layout that the same requirement's width arithmetic already made impossible. The number did not survive the layout its own document specified. **When a requirement changes the layout, every figure derived from the old one is re-derived, not re-cited** — and `A-1` was right to demand it. |
| **🆕 `C-78-xxvi`** | **A falsy container is a silent probe defect.** `bool(widget)` is `len(children) > 0` in Textual, so `x if x else None` reports None for an empty `ListView` — a reading indistinguishable from a real focus failure, which is how I came to write a code comment describing a fix for a bug that did not exist. **Probe with `is None`, never with truthiness, on anything that might be a container.** Sibling of `C-78-xxii`: the check named a subject it never reached. |

---

## 7. Suggested next task

**Inc-6 — HLR-126, discoverability** (`AT-B78-28`, `AT-B78-32`); files `screens_directionb.py`, `tests/test_tui_diff_screen.py` (2).

**Three things Inc-5 hands it directly.**
1. **The affordance now has three keys to name, not one** — `f` (run list), `[` / `]` (page the window) — and all three are `show=False` widget-scoped bindings, so the help panel and the affordance text are the *only* place an operator can learn them.
2. **`AT-B78-28`'s Footer clause is unaffected by design**: every key added here is `show=False`, so the `show and enabled` set is still the pre-change 14. Verify it, do not assume it.
3. **`AT-B78-32`'s zero-line `git diff` over `app.py:1338-1375` still holds** — Inc-5's `app.py` change is at `on_resize`, far below that block.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Tests / type checks / lint pass | ✓ | 51 passed (diff suites, one run) · 183 passed (`test_tui_directionb.py`, C-34, one run) · 10/10 Inc-5 nodes · `compileall` clean on all three source files |
| Every gate discharged by an executed, applied-checked mutation | ✓ | §4.4 |
| Restore proof | ✓ | §4.4 — `FINAL sha == baseline`, per-stage shas chained, tree restored in a `finally` |
| Snapshot drift bounded and NOT regenerated | ✓ | §4.5 — exactly `[diff-comfortable-120x30]`; no second cell moved |
| `A-1` re-derived against the real implementation | ✓ | §1.2 / F-2 — sweep with the regime gate bypassed, three widths |
| `A-2` verified by execution, both directions | ✓ | §1.4 / F-3 / `TC-B78-51` |
| No secrets in code or output | ✓ | No credential, token or path outside `tmp_path` appears in any new line or transcript |
| No destructive command run without approval | ✓ | No `git stash`, no `git reset`, no `rm -rf`, no force push, no regen. Mutations restored by writing back saved bytes in a `finally`, never by `git checkout` |
| File count within cap | ✓ | 4 of 5 |
| C-17 preserved | ✓ | `#diff_hex_a` / `#diff_hex_b` still constructed `markup=False` (`:6770-6771` pre-edit coordinates); the new `#diff_size_notice` is `markup=False` at construction and composes author text + integers only |
| No `_nodes` / `_context` members on new widgets | ✓ | The new fields are `_selected_run`, `_window_page`, `_focus_before_overlay`; no new widget subclass was created |
| `styles.tcss` id selectors own the new styling | ✓ | Every new rule is id- or class-scoped under `#ab_diff_panel`; no `DEFAULT_CSS` was added |
| `C-78-vi` corrected painted-height helper used | ✓ | `_b78_painted_content_height`, ancestor-chain form, reused unchanged |
| `C-78-xiii` / F9 no new driver copy | ✓ | §2 |
| Review packet attached | ✓ | this document |

---

# ADDENDUM — Inc-5 gate review fixes (F-1 HIGH · F-2/F-3 MEDIUM · F-4…F-7 LOW)

**Scope:** `s19_app/tui/screens_directionb.py`, `s19_app/tui/styles.tcss`, `tests/test_tui_diff_screen.py` and this document. **Still 4 files**, unchanged from the increment's own set (`app.py` needed no further edit).

---

## A.1 BLUF — the HIGH is one defect at three layers, and I shipped the weaker half of a spec conflict without saying the conflict existed

`_DIFF_MIN_H` was defined as *"the first terminal height at which a window paints a **content row**"*. But `_render_run_windows` writes `f"Image A — {header}\n{text_a}"`, so **screen line 0 of each window is the header** — a painted content height of 1 delivers **zero bytes**. I knew this: Inc-4's `_window_row_capacity` is `min(A, B) - 1` *because of that header*, and I wrote the `- 1` myself in the increment before this one. I then defined the floor on a metric that does not subtract it.

The consequence is worse than a soft edge. At H = 26–27 the panel declares the terminal deliverable, **hides the notice**, and shows a header and nothing else — **strictly worse than H = 25**, where the operator at least gets a notice explaining why. A degradation ladder whose upper rung is worse than the one below it is not a ladder.

**The root cause is a conflict inside the spec that I resolved silently.** §2.8 D-1's height axis says *"at least one visible **content** row"* → 26. Normative **`LLR-125.2`** says *"shall render at least one **hex row** of content"* → **28**. I took the non-normative one and never surfaced that the document contained both. Engineering rule 7 is *surface conflicts, don't average them*, and this batch's own **BL-3** caught this exact "green with the result area still at zero" shape once already. **`LLR-125.2` governs.**

**And the compounding half is the one worth carrying:** `TC-B78-31` does the **width** floor on both sides *and* asserts the consequence — *"`_DIFF_MIN_W` is only the right floor if the window is unwrapped AT it."* **Nothing did that for the height axis, which is the axis this increment changed.** F-1 and F-3 are the same one-row error in the constant and in the acceptance that should have caught it; the missing node is why neither caught the other. **The durable fix is the node at both sides of the floor, not the constant.**

| # | Finding | Severity | Disposition |
|---|---|---|---|
| **F-1** | the floor counts the header, so 26–27 pass deliverability and paint zero hex rows | **HIGH** | ✅ fixed — floor **28**, conflict surfaced in the docstring, `TC-B78-54` minted at both sides |
| **F-2** | `[`/`]` gated to the fallback: 65 of 66 rows unreachable at 160×40 | MEDIUM | ✅ fixed — the gate is now *not notice*; `TC-B78-52` gains a wide arm |
| **F-3** | `AT-B78-23`'s `painted >= 1` counts the header, green at zero bytes | MEDIUM | ✅ fixed — `>= _B78_WINDOW_HEADER_ROWS + 1` |
| **F-4** | Inc-2's ATs redden on the driver's guard, not their own subject | LOW | ✅ landed — the guard message now names the affected nodes and says it is the driver's |
| **F-5** | a regime change did not re-derive the window's row count | LOW | ✅ fixed — `apply_regime` re-renders on an actual regime change; `TC-B78-30` asserts it |
| **F-6** | the `LLR-119.3` correction leaves `#palette_input`'s scope unstated | LOW | ⏭ **carried to the coordinator** — it is a clause in `01-requirements.md`, which I do not write. See §A.6. |
| **F-7** | the "unpiped transcript" claim has no committed artifact | LOW / info | ⏭ acknowledged, no action — see §A.6 |

**The gap I flagged and did not close is now closed, by the reviewer.** Inc-4's `M2` against the moved `_B78_INC4_SHORT` reddens `AT-B78-22` on its own address assertion. I have re-executed it again here against the **second** move (132×28), because the fixture moved a second time under this addendum and a discharge against 132×26 does not transfer.

---

## A.2 F-1 — the corrected floor, with its executed ladder

Metric: **visible hex rows** = `min(painted content height − header rows, emitted rows)`. Measured with the fallback layout forced (so the constant cannot decide its own measurement), the command-bar row hidden (the post-Inc-10 end state `A-1`'s quantity is defined in), and a **0x400-byte run** so the window is never the binding limit — what is measured is the pane's budget, not the run's.

| H | capacity | painted | **visible hex rows** | verdict |
|---|---|---|---|---|
| 24 | 0 | 0 | **0** | notice |
| 25 | 0 | 0 | **0** | notice |
| 26 | 0 | 1 | **0** | ⛔ header only — the shipped defect |
| 27 | 0 | 1 | **0** | ⛔ header only |
| **28** | 1 | 2 | **1** | ✅ the floor |
| 29 | 1 | 2 | **1** | ✅ |
| 30 | 2 | 3 | **2** | ✅ R-1's accepted 120×30 viewport, to the row |
| 31 | 2 | 3 | **2** | ✅ |

**Identical at W = 94, 120 and 138** — the spec's width-independence claim reproduces a second time, under the corrected metric. `_DIFF_MIN_H = 28`.

The transient disclosure moves with it: as the tree stands the command-bar row still spends three rows, so **between Inc-5 and Inc-10 the heights 28–30 select the fallback regime while painting no hex row.** That is stated in the constant's docstring and is the reason `TC-B78-54` reaches the end state through `_b78_hide_command_bar` — which **asserts the reclaim landed** rather than assuming it, and which becomes a no-op branch the moment Inc-10 deletes the row.

**Knock-on, re-verified and not reasoned:** raising the floor to 28 put `_B78_INC4_SHORT = (132, 26)` back in the notice regime, so it moves again to **132×28**. Executed: `132×28` gives capacity **0** with the command bar present and **1** without it — and since the window only grows when `capacity > rows`, the run ± context floor of 3 rows is the whole window on **both** sides of Inc-10, so `AT-B78-22`'s exact three addresses hold either way. Inc-4's `M2` re-executed against the new site is `G5` in §A.3.

---

## A.3 Counterfactuals — five, applied-checked, sha-chained, restored

Same discipline as the increment's own set: value substitutions that type-check, applied-checked (old token asserted absent after the write), sha-chained against the **previous** mutation as well as the baseline, restored in a `finally`, verdicts read from `subprocess.run(...).returncode`. Each arm runs the whole **11-node** Inc-5 set by exact node id (`G5` runs the three Inc-4 window nodes instead, which are its subject).

```
BASELINE sha=f4d6cf963b515325
BASELINE Inc-5 set: green | 11 passed in 61.07s
BASELINE Inc-4 window set: green | 3 passed in 8.56s

--- G1 / TC-B78-54 (F-1) --- the corrected floor -> the shipped defect
    substituted: '_DIFF_MIN_H = 28'  ->  '_DIFF_MIN_H = 26'
    APPLIED=True  sha f4d6cf963b515325 -> 10cdb8beaea4609b (mutated)
    SET  RED | 1 failed, 10 passed in 62.10s
    reddened nodes: ['test_tc_b78_54_the_height_floor_delivers_a_hex_row']
    E  AssertionError: _DIFF_MIN_H is only the right floor if at least one HEX ROW
       is visible AT it: painted content height 1, of which 1 is the
       'Image A - Run #...' header, leaving 0 hex rows. A floor that declares a
       terminal deliverable and then shows a header and nothing else is WORSE
       than the notice it replaces
    POST (restored): green | 11 passed in 63.36s

--- G2 / TC-B78-52 wide arm (F-2) --- paging re-gated to the fallback regime
    substituted: 'return not self.has_class(self._REGIME_NOTICE)'
             ->  'return self.has_class(self._REGIME_FALLBACK)'
    APPLIED=True  sha 10cdb8beaea4609b -> a7df65db52f66dea (mutated)
    SET  RED | 1 failed, 10 passed in 62.02s
    reddened nodes: ['test_tc_b78_52_pagination_reaches_bytes_past_the_pane']
    E  AssertionError: (160, 40): paging forward must move the window onto later
       bytes; first row went 0x00000FF0 -> 0x00000FF0. A regime in which ']' is
       inactive strands 65 of 66 rows
    POST (restored): green | 11 passed in 62.01s

--- G3 / AT-B78-23 (F-3) --- MIS-TARGETED, see below
    substituted: '#ab_diff_panel.diff-fallback #diff_window_column { layer: base; }'
             ->  '... { layer: base; height: 1; }'
    APPLIED=True  sha a7df65db52f66dea -> 195e92259a876224 (mutated)
    SET  RED | 3 failed, 8 passed in 36.90s
    reddened nodes: ['test_tc_b78_30_...', 'test_tc_b78_52_...', 'test_tc_b78_54_...']
    POST (restored): green | 11 passed in 55.20s

--- G4 / TC-B78-30 (F-5) --- a regime change no longer re-derives the row count
    substituted: 'if regime != previous and self._has_result:'
             ->  'if regime != previous and False:'
    APPLIED=True  sha 195e92259a876224 -> eac33fc81b1bd946 (mutated)
    SET  RED | 1 failed, 10 passed in 55.37s
    reddened nodes: ['test_tc_b78_30_a_resize_across_the_breakpoint_follows']
    E  AssertionError: a regime change must RE-DERIVE the window's row count, not
       only swap the layout class: the new pane has a capacity of 5 rows and the
       window is still rendering 3
    POST (restored): green | 11 passed in 58.25s

--- G5 / AT-B78-22 at the MOVED fixture (Inc-4's M2, re-executed at 132x28) ---
    substituted: 'high = end + self.DISPLAY_CONTEXT_BYTES'  ->  'high = end'
    APPLIED=True  sha eac33fc81b1bd946 -> 8d6cddb14968c8bd (mutated)
    SET  RED | 2 failed, 1 passed in 8.50s
    reddened nodes: ['test_at_b78_22_window_spans_the_run_plus_context',
                     'test_tc_b78_24_address_zero_clamp_and_unaligned_start']
    E  AssertionError: the window must span exactly the run plus one context row
       on each side; expected ['0x00000FF0', '0x00001000', '0x00001010'],
       emitted ['0x00000FF0', '0x00001000']
    POST (restored): green | 3 passed in 8.96s

FINAL sha=f4d6cf963b515325  baseline=f4d6cf963b515325  equal=True
```

**G1 is the one that matters most, and it is stronger than it looks.** `TC-B78-54` derives its terminal sizes **from `_DIFF_MIN_H` itself**, so a naive reading says mutating the constant moves the fixture with it and the node cannot see the change — the F-6 shape. It reddens anyway, because the **consequence** clause is absolute: whatever the constant says, a hex row must be visible AT it. That is exactly why `TC-B78-31` was written that way for the width axis, and it is the property the missing height node lacked. **The node would have caught what I shipped.**

**G5 closes the knock-on with a transcript instead of an argument.** `AT-B78-22` reddens on its own address assertion at the twice-moved 132×28, with the message identical to the 132×24 and 132×26 forms. `TC-B78-24` reddens with it — it shares the span subject — and both restore green.

### A.3.1 G3 was mis-targeted, and that is the finding, not a footnote

**G3 reddened three nodes and NOT the one it was written for.** I scoped it to `#ab_diff_panel.diff-fallback #diff_window_column` — but `AT-B78-23` runs at **160×40, which is the WIDE regime**, so the mutation could not reach its declared subject. It is **INERT for the clause it was supposed to discharge**, and the three reds it did produce made it look discharged.

This is `C-78-xxiii` one turn further on: *a mutation that reddens is not evidence the clause discriminates — only that the mutation you chose was visible.* Here it was visible **in three other nodes**, which is a more convincing disguise than silence. The corrected form, `G6`, mutates the **shared** `#diff_window_column` rule that both regimes read:

```
--- G6 / AT-B78-23 (F-3), CORRECTED --- the SHARED window column gets one screen row
    substituted: '#diff_window_column { width: 1fr; height: 100%; }'
             ->  '#diff_window_column { width: 1fr; height: 1; }'
    APPLIED=True  sha f4d6cf963b515325 -> b8ce7eebf881f8a1 (mutated)
    SET  RED | 4 failed, 7 passed in 49.15s
    reddened nodes: ['test_at_b78_23_no_wrapped_row_in_the_wide_regime',
                     'test_tc_b78_30_...', 'test_tc_b78_52_...', 'test_tc_b78_54_...']
    E  AssertionError: an unwrapped window that paints no HEX ROW delivers
       nothing: screen line 0 is the 'Image A - Run #...' header, so a painted
       content height of 1 is ZERO bytes on the operator's screen. Painted
       height is 0
    POST (restored): green | 11 passed in 68.62s
FINAL sha=f4d6cf963b515325  baseline=f4d6cf963b515325  equal=True
```

**And G6 is still not the right discharge, which is the second half of the same lesson.** It drives the painted height to **0** — a state the *old* `>= 1` form would have caught too. It proves `AT-B78-23` has a live clause; it does **not** prove the clause was strengthened, which is the whole of F-3. The discriminating mutation gives the column **two** rows, so each stacked window paints **exactly 1** — the header and no hex row — the precise state the old form passed and the new one must not:


## A.4 F-2 — the paging inversion, measured before and after

`check_action` gated `page_window_down` / `page_window_up` on the fallback regime. Executed on a `0x400`-byte run, **before** the fix — reproducing the reviewer's table to the digit:

```
(160, 40)  diff-wide      capacity=1  emitted_rows=66  check_action(page)=False  ']' moved: False
(139, 40)  diff-wide      capacity=1  emitted_rows=66  check_action(page)=False  ']' moved: False
(132, 44)  diff-fallback  capacity=7  emitted_rows=66  check_action(page)=True   ']' moved: True
```

**The operator on the widest supported terminal saw 1 of 66 rows and had no key to reach the rest; the operator on a narrower one reached all of them.** Overflow is a property of the run against the pane, never of the regime — the wide regime's capacity is 1 at 160×40 precisely *because* the run list takes columns and the two windows still stack. The fix **removes** the condition (`return not self.has_class(self._REGIME_NOTICE)`), and `TC-B78-52` now runs both arms.

## A.5 Files modified (addendum)

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | `_DIFF_MIN_H` 26 → **28** + a docstring that states the D-1 / `LLR-125.2` conflict and which clause governs · `check_action` ungates the paging keys (F-2) · `apply_regime` re-renders the windows on a real regime change (F-5) |
| `s19_app/tui/styles.tcss` | the regime comment's floor 26 → 28 |
| `tests/test_tui_diff_screen.py` | **`TC-B78-54`** (new) · `_B78_WINDOW_HEADER_ROWS` + `_b78_hide_command_bar` (new helpers) · `AT-B78-23` `>= 1` → `>= _B78_WINDOW_HEADER_ROWS + 1` (F-3) · `TC-B78-52` gains the wide arm (F-2) · `TC-B78-30` gains the row-count clause (F-5) · `_b78_open_run_list`'s guard message names the affected nodes (F-4) · `_B78_INC4_SHORT` 132×26 → **132×28** |
| `increment-005.md` | this addendum + four in-place corrections (R-1 superseded, §1.2's constant table, §1.4's `check_action` sentence, the ledger) |

**Still 4 files.** `app.py` needed no further edit. `.dev-flow/state.json`, `PLAN.md`, `01-requirements.md`, the `02-review-*.md` files, earlier `increment-*.md` and `AT-TC-REGISTRY.jsonl` **read, never written**; `prototypes/memmap2.*` untouched; no `git add -A`, no `git stash`.

**C-26 reverse-grep:** two new module-level test symbols, `_B78_WINDOW_HEADER_ROWS` and `_b78_hide_command_bar`, each defined once, no consumer outside the owning module. **No new driver copy** — `_b78_hide_command_bar` is a `prepare`/`after` hook, not a fifth driver.

## A.6 Pending items after the addendum

1. **`_DIFF_MIN_H` is 28** — the coordinator owns the `01-requirements.md` correction. ⚠️ **Two clauses, not one:** §8's `A-1` row and LLR-124.1's value, **and** §2.8 D-1's height axis, whose *"at least one visible content row"* is the weaker metric that produced 26. Leaving D-1 as written keeps the contradiction alive for the next reader.
2. **F-6 is carried to the coordinator, not silently dropped.** `LLR-119.3` governs *"the six local inputs of LLR-119.1"*, and `#palette_input` is an `Input` that holds focus on `ctrl+k` (executed) but is **not** one of the six. Whether Inc-9's `escape`-off-input handler is meant to reach it is now unstated in both directions. **Suggested clause:** *"`#palette_input` is outside LLR-119.1's six; Inc-9 must state whether its handler reaches it."* A dropped constraint should leave a question, not a silence.
3. **F-7 acknowledged, no action.** `mutate_inc5*.py` are probes and live in the scratchpad by design (C-46 probe hygiene: probes run from outside the repo). The transcripts are corroborated, not confirmed, and the standing fix is `C-78-xx`'s — move the gate into the RC-1 pre-commit hook so shell plumbing cannot arbitrate a verdict.
4. **`AT-B78-26` at Inc-10 must inherit the `>= 2` form, not `>= 1`.** Its clause is *"≥ 1 hex row at 120×30"*, which is the same predicate F-3 corrected here. Reading it as painted content height would repeat this defect in the increment that closes the batch's headline case.
5. **Snapshot regen** — still exactly one cell, still Inc-12's, still CI-only.
6. **`F9` and `C-78-xiv`** unchanged; no copy added.

## A.7 Batch carry list (additions from the gate)

| Id | Carry |
|---|---|
| **🆕 `C-78-xxvii`** | **A geometry floor must be defined in the units the operator receives, not the units the layout reports.** `_DIFF_MIN_H` was defined on *painted content rows* while the deliverable is *hex rows*, and the two differ by the header line the window renders itself. The error was invisible because both quantities are integers measured off the same widget — and it produced a regime that is **strictly worse than the one below it**, which no single-sided threshold test can see. **Ask what the operator gets at the floor, not what the widget reports.** |
| **🆕 `C-78-xxviii`** | **A boundary constant owes a node on BOTH sides, and the upper side must assert the CONSEQUENCE.** `TC-B78-31` did this for the width axis and would have caught the height defect had it existed for the height axis. Crucially it survives mutation of the constant it is written from, because *"a hex row is visible AT the floor"* is absolute whatever the floor says. **The axis with no boundary node is the axis that ships wrong**, and the durable fix is the node, not the value. |
| **🆕 `C-78-xxix`** | **A capability gated on a MODE strands the case the mode does not predict.** Paging was gated on the fallback regime because that is where the spec's pagination clause is written; measurement showed the *wide* regime has the smaller capacity (1 vs 7), so the gate stranded 65 of 66 rows on the widest terminal. **Gate a capability on the CONDITION that makes it necessary — here overflow of run against pane — not on the mode where someone first wrote it down.** The fix removed a condition. |

```
--- G7 --- column height 2  ->  painted 0   (still not discriminating: in the WIDE
    regime the bordered window spends 4 rows on chrome, so a 2-row column leaves
    nothing at all. Recorded so the value is on the record, per *record the
    substituted VALUE*.)

--- G8 / AT-B78-23 (F-3), DISCRIMINATING --- the column gets TEN rows, so each
    bordered window box is 5 and its CONTENT is exactly 1: the header, and no hex row
    substituted: '#diff_window_column { width: 1fr; height: 100%; }'
             ->  '#diff_window_column { width: 1fr; height: 10; }'
    APPLIED=True  sha f4d6cf963b515325 -> 02e245bade18b08b (mutated)
    SET  RED | 2 failed, 9 passed in 69.94s
    reddened nodes: ['test_at_b78_23_no_wrapped_row_in_the_wide_regime',
                     'test_tc_b78_52_pagination_reaches_bytes_past_the_pane']
    E  AssertionError: an unwrapped window that paints no HEX ROW delivers
       nothing: ... Painted height is 1
```

**`Painted height is 1` is the whole discharge.** That is precisely the state the old `>= 1` form **passed** and the corrected `>= 2` form rejects — so F-3's fix is shown to be a strengthening, not merely a clause that can go red. It took **three** attempts to construct (G3 wrong regime, G7 wrong magnitude, G8 right), and each wrong one produced reds that looked like success.

## A.8 Test results (addendum), re-run on the fixed tree

```
tests/test_tui_diff_screen.py tests/test_tui_diff_compare_realpath.py
52 passed in 166.04s (0:02:46)          <- 51 + TC-B78-54

tests/test_tui_directionb.py            <- C-34 guard host, ONE run, FULL form
183 passed in 249.96s (0:04:09)

tests/test_tui_snapshot.py
1 snapshot failed. 28 snapshots passed.
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[diff-comfortable-120x30]
1 failed, 31 passed, 1 warning in 68.51s (0:01:08)
```

**Still exactly one snapshot cell**, and still the one Inc-1 drifted. Raising the floor from 26 to 28 does not move 120×30 — it is above the floor either way — so no cell changed regime.

### A.8.1 Executed behaviour at the corrected floor

Measured with the fallback forced and the command bar hidden (the post-Inc-10 end state), on a run longer than any pane:

| H | capacity | painted | visible hex rows |
|---|---|---|---|
| 26 | 0 | 1 | **0** ← was "deliverable" |
| 27 | 0 | 1 | **0** ← was "deliverable" |
| **28** | 1 | 2 | **1** ← the floor now |
| 30 | 2 | 3 | **2** |

Identical at **W = 94, 120 and 138**.

### A.8.2 Ledger

**2647 → 2648** (`D = 0`, `A = 1` — `TC-B78-54`). Collection census: `tests/test_tui_diff_screen.py` collects **46**, up from 45. Arithmetic on Inc-4's tracked figure per C-19; honestly 2647 + the one drifted snapshot cell until Inc-12.

## A.9 Evidence checklist (addendum)

| Item | ✓/✗ | Evidence |
|---|---|---|
| The HIGH is fixed by a predicate, not by prose | ✓ | `TC-B78-54`, both sides of the floor; G1 reddens it by restoring the shipped constant |
| The new node survives mutation of the constant it derives from | ✓ | §A.3 G1 — sizes come from `_DIFF_MIN_H`, the consequence clause is absolute |
| The spec conflict is SURFACED, not averaged | ✓ | the constant's own docstring names D-1 and `LLR-125.2` and says which governs |
| F-2 fixed by REMOVING a condition | ✓ | §A.4; G2 reddens the wide arm with "strands 65 of 66 rows" |
| F-3 shown to be a STRENGTHENING, not just a live clause | ✓ | §A.3 G8 — `Painted height is 1`, the exact state the old form passed |
| Knock-on re-verified by execution, not by reasoning | ✓ | §A.3 G5 — Inc-4's `M2` at 132×28 reddens `AT-B78-22` on its address assertion |
| Restore proof | ✓ | three harnesses, each `FINAL sha == baseline` (`f4d6cf963b515325`) |
| Gates re-run after the fix | ✓ | §A.8 — 52 · 183 · 1-cell snapshot drift |
| Snapshot drift unchanged and NOT regenerated | ✓ | §A.8 |
| No secrets, no destructive commands, no `git add -A`, no `git stash` | ✓ | mutations restored by writing back saved bytes in a `finally`, never `git checkout` |
| File count within cap | ✓ | the addendum's own diff is **3** files + this packet; `app.py` needed no further edit |
| Files I must not write, untouched | ✓ | `state.json`, `PLAN.md`, `01-requirements.md`, `02-review-*.md`, earlier `increment-*.md`, `AT-TC-REGISTRY.jsonl`, `BACKLOG-CODE.md`, `prototypes/memmap2.*` |
| Uncertainty surfaced | ✓ | §A.3.1 records G3 as mis-targeted and G7 as wrong-magnitude rather than quietly replacing them; §A.6 carries F-6 to the coordinator rather than deciding Inc-9's scope |
