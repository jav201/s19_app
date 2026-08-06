# Increment 001 — HLR-125, compact the diff control rows

> **Scope:** §7 Inc-1 · HLR-125 / LLR-125.1 / LLR-125.2 · **Nodes:** `AT-B78-33` (+ `TC-B78-35`), `TC-B78-34`, `TC-B78-36`, `TC-B78-37`
> **Gate:** `AT-B78-33` — `#diff_hex_a.size.height` at 132×44 strictly greater than the Inc-0 artifact's pre-change baseline
> Branch `claude/batch-78-cmdbar-a2bdiff` · base `b3b97f7` · artifact language: English.

---

## BLUF

**The compaction lands and reproduces the spec's executed ladder at all four terminal
sizes to the digit — and the spec's own declared reddening mutation for `AT-B78-33`
turned out to be INERT when executed.**

| # | Finding | Verdict |
|---|---|---|
| **F-1** | **§5.3's declared mutation for `AT-B78-33` — *"revert the row-height rule and confirm 13 → 7"* — does not redden anything.** Substituting the three rows' `height` VALUE `1` → `auto` leaves all four nodes **GREEN at 13**, because once the child chrome is gone `auto` *resolves* to 1. The row-height declaration is not what does the work; the **child** declarations are. The honest value substitution is `1` → `3` (3 being `auto`'s **pre-change resolved** value), which reddens `AT-B78-33` on its own assertion at `7 > 7`. | ⚠️ **spec defect — found by executing the stated mutation, not by reading it** |
| **F-2** | **`TC-B78-36` (a long external path must not re-expand the row) is a PIN, not a gate, and no mutation peculiar to its subject can redden it.** Executed: `#diff_path_*` `height` `1` → `3` while the row keeps `height: 1` → **all four nodes GREEN**. An explicit row height clips the child instead of growing with it, so path length cannot reach the observable. Labelled PIN in the node's docstring rather than shipped as a green tick that looks like evidence. | ⚠️ **honest downgrade, measured** |
| **F-3** | **The A/B variant `Select`s render at width 1 — and they already did on `origin/main`.** Measured pre-change `#diff_select_a size=(w=1, h=2)`, post-change `(w=1, h=1)`. `Input`'s `width: 100%` inside a `Horizontal` claims the whole row and squeezes the `Select` to one column. **Pre-existing, not caused by this increment, and out of HLR-125's scope** (a vertical-budget requirement). Carried, not silently fixed. | ⚠️ **pre-existing defect surfaced — carried as `C-78-iv`** |
| **F-4** | **At 80×24 compaction alone cannot make `#diff_status` visible.** `#ab_diff_panel`'s whole content budget is **5** rows and three compacted rows plus their `margin-bottom` separators already spend **6**. HLR-125's `#diff_status ≥ 1` threshold is parenthetically scoped to 120×30 and `TC-B78-34` asks only for the row clause, so there is no contradiction — but the residual is real and belongs to HLR-124's notice regime at Inc-5. Stated, and deliberately **not** pinned (a node asserting today's 0 would false-fail Inc-5). | ✅ no spec conflict; residual named |
| **F-5** | Snapshot drift is **exactly 1 cell**, `[diff-comfortable-120x30]` — the only diff golden (C2). 28 of 29 unchanged. **Not regenerated locally** (C9). | ✅ as predicted |

**Executed ladder — every cell matches the spec.** `#diff_hex_a` as `(content, clipped)`:

```
              spec "shipped"   MEASURED before   spec "S-8 only"   MEASURED after
120x30           (0,  0)          (0,  0)            (0,  4)          (0,  4)
132x44           (7, 11)          (7, 11)           (13, 17)         (13, 17)
160x40           (3,  7)          (3,  7)            (9, 13)          (9, 13)
 80x24           (0,  0)          (0,  0)            (0,  0)          (0,  0)
```

LLR-125.2's `#diff_columns` content ladder at 120×30 also reproduces: shipped **0**, compaction alone **3**.

---

## 1. What changed

**One CSS block, no Python.** `#diff_select_row_a` / `#diff_select_row_b` / `#diff_action_row`
resolved `height: auto` to **3** because every child carries Textual's default `tall` border
(`Input`, `Button`, and `Select`'s inner `SelectCurrent`) and `.diff-field-label` carried a
one-row top padding. Nine rows of chrome out of an `#ab_diff_panel` measuring **11** at 120×30
left `#diff_status` and `#diff_columns` with a clipped visible height of **zero**.

| Declaration | Before | After | Why |
|---|---|---|---|
| the three rows' `height` | `auto` (→ 3) | `1` | LLR-125.1's requirement, stated directly |
| `.diff-field-label` `padding` / `height` | `1 1 0 1`, auto (→ 2) | `0 1`, `1` | the label's top padding alone forced a second row |
| `#diff_select_a/_b` `height` | auto (→ 2) | `1` | — |
| `#diff_select_a/_b SelectCurrent` `border` / `height` / `padding` | `tall` (DEFAULT_CSS), auto, `0 2` | `none`, `1`, `0 1 0 0` | replicates Textual 8.2.8's own `-textual-compact` recipe, which is reachable only from a `compact` reactive on the widget — i.e. only from `compose` |
| `#diff_path_a/_b`, `#diff_report_dest` `border` / `height` / `padding` | `tall $border-blurred`, `3`, `0 2` | `none`, `1`, `0 1` | same |
| `#diff_compare_button` / `#diff_report_button` `border` / `height` / `margin-right` | `tall`, auto (→ 3), `0` | `none`, `1`, `1` | `margin-right` restores the separation the removed borders provided |

**`margin-bottom: 1` on the three rows is deliberately KEPT.** Dropping it would free three more
rows and take 132×44 to **16**, not the spec's executed **13**. The requirement is *"each control
row occupies one rendered row"*, not *"reclaim every reclaimable row"* — and the spec's expected
figure is the check on that reading. Reported, not absorbed: dropping the separators is available
to a later increment and would also make `#diff_status` visible at 80×24 (F-4).

**Why CSS only.** §7 allocates Inc-1 two files, and C13 says `styles.tcss` id selectors outrank a
widget's `DEFAULT_CSS` on shared ids — which is exactly what makes a compose-free compaction
possible. Nothing in `screens_directionb.py` moved, so `on_button_pressed` routing and the
`CompareRequested` / `ReportRequested` messages are untouched by construction (LLR-125.1's
acceptance criterion), and `test_tc021` / `test_tc024` cover them without a new node (C-18: no
duplication).

### The four nodes

| Node | Id(s) | Kind | Subject |
|---|---|---|---|
| `test_at_b78_33_compaction_enlarges_the_result_area` | `AT-B78-33`, `TC-B78-35` | **GATE** | at 132×44 `#diff_hex_a` content **and** clipped heights strictly exceed the Inc-0 freeze; in the same run the three rows paint 1 and `#diff_status` paints ≥ 1 |
| `test_tc_b78_34_control_rows_are_one_row_at_80x24` | `TC-B78-34` | **GATE** | the 1-row clause at the narrowest regime (pre-change: 3 / 2 / **0**) |
| `test_tc_b78_36_long_external_path_does_not_reexpand` | `TC-B78-36` | **PIN** (F-2) | a path longer than the terminal does not restore the row |
| `test_tc_b78_37_selects_survive_compaction_no_project` | `TC-B78-37` | GATE + **PIN** | the row paints 1 **and** the variant dropdown is still shown, still holds the sentinel, and still **opens** |

**`AT-B78-33` takes both its threshold and its terminal size from the artifact.** §5.1 rule 10
forbids an inline literal, and the pre-change height is unrecoverable once `styles.tcss` is edited.
The reader has **no fallback** — a missing artifact is a red test, never a producer substitution
(the BL-1 defect). The size comes from `baseline["terminal"]` rather than a module constant, so the
artifact is load-bearing on both axes and Inc-0's R-3 (three artifacts at three sizes) cannot bite.

**`TC-B78-37` is the anti-shortcut node.** The cheapest way to buy two rows is `display: none` on
the `Select`s — which is what this batch's own prototype did. That passes every height predicate in
the file. This node is the only thing that stops it, and its mutation is discharged and
discriminating (§4.4 mutation B: 1 failed / 3 passed).

---

## 2. Files modified

| File | Status |
|---|---|
| `s19_app/tui/styles.tcss` | modified — **+43 / −2** (one comment block + six rule blocks in the existing A↔B Diff section) |
| `tests/test_tui_diff_screen.py` | modified — **+296 / −0** (docstring map, two module helpers, four nodes) |

**2 files — §7's planned count, cap is 5.**

**Not touched:** `.dev-flow/state.json` (modified in the worktree by the parallel session — left
alone), `PLAN.md`, `00-measurements.md`, `01-requirements.md`, the `02-review-*.md` files,
`increment-000*.md`, `AT-TC-REGISTRY.jsonl`, `prototypes/memmap2.*`, `build/`, and every snapshot
SVG. `git add -A` was never used; `git stash` was never used.

---

## 3. How to test

```bash
# the increment's own nodes
python -m pytest tests/test_tui_diff_screen.py -q -p no:randomly

# gate suite + every C-26 consumer of a touched id, ONE run, FULL form
python -m pytest tests/test_tui_directionb.py tests/test_tui_commandbar.py \
    tests/test_tui_diff_screen.py tests/test_tui_variants.py \
    tests/test_tui_patch_variant.py tests/test_loadfilescreen_input.py \
    tests/test_tui_diff_compare_realpath.py tests/test_tui_report_filter_surface.py \
    tests/test_report_off_ui_thread.py tests/test_tui_patch_big.py \
    tests/test_id_registry.py -q -p no:randomly

# the expected drift — DO NOT regenerate locally (C9, Inc-12 owns regen)
python -m pytest tests/test_tui_snapshot.py -q -p no:randomly

# the gate's oracle is on disk, not in the test
grep -n "content_height" tests/test_tui_diff_screen.py     # 0 literals; only the artifact key
cat tests/goldens/batch78/at-b78-33-diff-hex-a-height.json
```

---

## 4. Test results

### 4.1 The increment's own file

```
$ python -m pytest tests/test_tui_diff_screen.py -q -p no:randomly
..........                                                               [100%]
10 passed in 9.36s
```

### 4.2 Gate suite + C-26 consumers — ONE run, FULL form (no marker filter)

```
$ python -m pytest tests/test_tui_directionb.py tests/test_tui_commandbar.py \
    tests/test_tui_diff_screen.py tests/test_tui_variants.py \
    tests/test_tui_patch_variant.py tests/test_loadfilescreen_input.py \
    tests/test_tui_diff_compare_realpath.py tests/test_tui_report_filter_surface.py \
    tests/test_report_off_ui_thread.py tests/test_tui_patch_big.py \
    tests/test_id_registry.py -q -p no:randomly
........................................................................ [ 22%]
........................................................................ [ 44%]
........................................................................ [ 66%]
........................................................................ [ 89%]
...................................                                      [100%]
323 passed in 458.08s (0:07:38)
```

**C-26 reverse grep — every touched id swept across the WHOLE `tests/` tree, not just my file.**
The four modules beyond §5.2's gate suite are in the run above because of it:

| touched id | hits | consuming modules |
|---|---|---|
| `diff_select_row_a` / `_b`, `diff_action_row`, `diff-field-label`, `diff_columns` | **0** | — |
| `diff_select_a` / `_b` | 12 / 8 | `test_tui_directionb.py`, **`test_tui_patch_big.py`** |
| `diff_path_a` / `_b` | 16 / 15 | `test_loadfilescreen_input.py`, `test_tui_diff_compare_realpath.py`, `test_tui_directionb.py`, **`test_tui_report_filter_surface.py`** |
| `diff_report_dest` | 3 | `test_loadfilescreen_input.py` |
| `diff_compare_button` / `diff_report_button` | 23 / 10 | + **`test_report_off_ui_thread.py`**, `test_tui_diff_screen.py` |
| `diff_status`, `diff_hex_a` | 13 / 17 | already in the gate suite |

### 4.3 Snapshot drift — recorded, NOT regenerated

```
$ python -m pytest tests/test_tui_snapshot.py -q -p no:randomly
1 snapshot failed. 28 snapshots passed.
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[diff-comfortable-120x30]
1 failed, 31 passed, 1 warning in 52.95s
```

**C-22 per-cell reason for the one drifted cell:** `[diff-comfortable-120x30]` is the **only** diff
golden in the matrix (C2). Its three control rows go 3 → 1 and `#diff_columns` gains 3 painted
rows, so the cell must change. The other 28 cells render no diff-panel surface and are unchanged —
which is itself the evidence that the id-scoped rules did not leak. **Regen is Inc-12's, in
canonical CI only** (textual 8.2.8 pin, C9).

### 4.4 Ledger — stated as arithmetic, with its own qualification

| Quantity | Value | Form |
|---|---|---|
| baseline | `2607 passed / 2 skipped / 3 xfailed`, exit 0 | FULL, 25:57 |
| after Inc-0 | `2608 passed` | derived |
| deleted (`D`) | **0** | — |
| added (`A`) | **4** | — |
| **post = 2608 − 0 + 4** | **`2612 passed / 2 skipped / 3 xfailed`** | **derived** |
| **post, honestly, until Inc-12** | **`2611 passed / 1 FAILED / 2 skipped / 3 xfailed`** | the drifted snapshot cell is red by design |

⚠️ **The full suite was NOT executed** — the targeted 11-module set was run instead (7:38 vs ~26
min). The executed evidence is §4.2's **323 passed / 0 failed** plus §4.3's **31 passed / 1
failed**, each from one run's own output (C-19). `2612` is arithmetic, and the honest line is the
one below it: a merge before Inc-12 sees a red suite.

**Node count, against PINNED SHAs** (not `HEAD~1`, which drifts with the commit graph):

```
$ git show b3b97f7:tests/test_tui_diff_screen.py | grep -c "^def test_"   # pinned base
6
$ grep -c "^def test_" tests/test_tui_diff_screen.py                      # working tree
10
```

### 4.5 Counterfactuals — five mutations, each APPLIED-CHECKED, each restored by SHA

Four mutations have silently failed to apply in this batch already, so every run below asserts the
substituted token is present in the file **and** that the file's SHA-256 differs from the fixed
tree before pytest is invoked, and asserts the SHA matches again after the restore. Mutations are
applied to a **copy of the fixed tree**, never to the pre-change tree, so a red result is a red
**assertion** and not an import error on an older tree.

Fixed-tree `styles.tcss` SHA-256 = `8523da931ae933560721e2f270470b9594a9f1b64a8c9c3d61cf8cda2e836ec5`.

| # | Substituted VALUE | `AT-B78-33` | `TC-B78-34` | `TC-B78-36` | `TC-B78-37` |
|---|---|:-:|:-:|:-:|:-:|
| **0** | *(the whole increment reverted — `styles.tcss` at `b3b97f7`)* | 🔴 | 🔴 | 🔴 | 🔴 |
| **A** | rows' `height` `1` → **`auto`** — §5.3's declared mutation | 🟢 | 🟢 | 🟢 | 🟢 |
| **A2** | rows' `height` `1` → **`3`** | 🔴 | 🔴 | 🔴 | 🔴 |
| **A3** | rows' `height` `1` → `auto` **and** `#diff_path_*` `height` `1` → `3`, `border` `none` → `tall $border-blurred` | 🔴 | 🔴 | 🔴 | 🔴 |
| **B** | `#diff_select_a/_b` `display` unset → **`none`** | 🟢 | 🟢 | 🟢 | **🔴** |
| **C** | `#diff_path_*` `height` `1` → **`3`** (row keeps `height: 1`) | 🟢 | 🟢 | 🟢 | 🟢 |

**Counterfactual 0 — RED today, all four, each on its ASSERTION** (the `git checkout` was of a file
I had backed up byte-for-byte one command earlier; restore verified by SHA):

```
########## CF-0: the four new nodes against the PRE-CHANGE styles.tcss ##########
applied: styles.tcss restored to b3b97f7 -> the row block reads `height: auto;`

E   AssertionError: compaction must give the freed rows to the result area:
E     #diff_hex_a content height 7 is not greater than the pre-change 7
E     captured at (132, 44) by Inc-0
E   assert 7 > 7
E   AssertionError: #diff_select_row_a must paint exactly one row at 80x24,
E     measured 3 (pre-change: 3 / 2 / 0 respectively)
E   assert 3 == 1
E   AssertionError: a long external path must not re-expand the A selection row, measured 3
E   AssertionError: the A selection row must still paint one row, measured 3
4 failed, 6 deselected in 4.05s
```

`7 > 7` is the spec's stated 13 → 7 transition, reached through the artifact rather than a literal.

**Mutation A — the spec's own declared mutation, INERT (F-1):**

```
############ MUTATION A ############
AT-B78-33's declared mutation: the three control rows' `height` VALUE
substituted `1` -> `auto` (the row-height rule reverted; every child rule left in place)
applied: True  (sha 4c0473adb5d03dc8 != fixed 8523da931ae93356)
....                                                                     [100%]
4 passed, 6 deselected in 3.73s
############ MUTATION A REVERTED ############
restore sha 8523da931ae933560721e2f270470b9594a9f1b64a8c9c3d61cf8cda2e836ec5  MATCH
4 passed, 6 deselected in 3.80s
```

**Why it is inert, and why that is a finding rather than a nuisance.** §5.3 names the row-height
rule as the subject and it is not the causal declaration. `auto` is a *function of the children*;
once the child chrome is removed it resolves to **1**, so reverting the row declaration changes
nothing. This is the same family as `AT-B78-03`'s producer circularity and `AT-B78-22`'s 4×
constant change: **a mutation named against the wrong term reports GREEN and is indistinguishable
from a passing test.** Recording it is the point — an unexecuted mutation would have shipped
`AT-B78-33` looking discharged.

**Mutation A2 — the same claim in the form that reaches the subject:**

```
############ MUTATION A2 ############
the three control rows' `height` VALUE substituted `1` -> `3`
(3 is the pre-change RESOLVED height of `auto`)
applied: True  (sha 45b6083e9d263562 != fixed 8523da931ae93356)
E   AssertionError: compaction must give the freed rows to the result area:
E     #diff_hex_a content height 7 is not greater than the pre-change 7 ...
E   assert 7 > 7
FAILED tests/test_tui_diff_screen.py::test_at_b78_33_compaction_enlarges_the_result_area
FAILED tests/test_tui_diff_screen.py::test_tc_b78_34_control_rows_are_one_row_at_80x24
FAILED tests/test_tui_diff_screen.py::test_tc_b78_36_long_external_path_does_not_reexpand
FAILED tests/test_tui_diff_screen.py::test_tc_b78_37_selects_survive_compaction_no_project
4 failed, 6 deselected in 4.23s
############ MUTATION A2 REVERTED ############
restore sha 8523da931ae933560721e2f270470b9594a9f1b64a8c9c3d61cf8cda2e836ec5  MATCH
4 passed, 6 deselected in 3.88s
```

**Mutation B — the discriminating one, and the reason `TC-B78-37` exists:**

```
############ MUTATION B ############
`#diff_select_a,#diff_select_b` `display` VALUE substituted (unset -> `none`)
- buy two rows back by deleting the variant dropdowns
applied: True  (sha df1e3c20364d47f7 != fixed 8523da931ae93356)
E   AssertionError: compaction must not hide the A variant dropdown - that
E     would buy rows by deleting the only in-project variant affordance
E   assert False
FAILED tests/test_tui_diff_screen.py::test_tc_b78_37_selects_survive_compaction_no_project
1 failed, 3 passed, 6 deselected in 3.98s
############ MUTATION B REVERTED ############
restore sha 8523da931ae933560721e2f270470b9594a9f1b64a8c9c3d61cf8cda2e836ec5  MATCH
4 passed, 6 deselected in 3.95s
```

**Mutation C — `TC-B78-36`'s only subject-specific candidate, also INERT (F-2):**

```
############ MUTATION C ############
`#diff_path_a/_b/_report_dest` `height` VALUE substituted `1` -> `3`
(the path inputs get their tall border back while the ROW keeps `height: 1`)
applied: True  (sha c8a693e78eee8eba != fixed 8523da931ae93356)
4 passed, 6 deselected in 3.96s
############ MUTATION C REVERTED ############
restore sha 8523da931ae933560721e2f270470b9594a9f1b64a8c9c3d61cf8cda2e836ec5  MATCH
```

An explicit row `height: 1` clips its children rather than growing with them, so **no** child-side
value can reach `TC-B78-36`'s observable. It is a PIN and its docstring now says so.

**Restore proof.** After every mutation the file was overwritten from a byte-identical backup, the
SHA-256 re-checked equal to the fixed tree, and the predicate re-run GREEN. Final state:

```
$ git status --short -- s19_app/ tests/
 M s19_app/tui/styles.tcss
 M tests/test_tui_diff_screen.py
$ git diff --stat -- s19_app/ tests/
 s19_app/tui/styles.tcss       |  43 +++++-
 tests/test_tui_diff_screen.py | 296 ++++++++++++++++++++++++++++++++++++++++++
```

### 4.6 Executed geometry, both layers, four sizes

`(content_height, clipped_height)`, clipped = `region ∩ #screen_diff.region` (C-32):

```
                        BEFORE (b3b97f7)              AFTER (this increment)
                 120x30  132x44  80x24  160x40   120x30  132x44  80x24  160x40
#ab_diff_panel   (11,13) (25,27) (5,7)  (21,23)  (11,13) (25,27) (5,7)  (21,23)
#diff_select_row_a (3,3)   (3,3) (3,3)    (3,3)    (1,1)   (1,1) (1,1)    (1,1)
#diff_select_row_b (3,3)   (3,3) (3,2)    (3,3)    (1,1)   (1,1) (1,1)    (1,1)
#diff_action_row   (3,3)   (3,3) (3,0)    (3,3)    (1,1)   (1,1) (1,1)    (1,1)
#diff_status       (1,0)   (1,1) (1,0)    (1,1)    (1,1)   (1,1) (1,0)    (1,1)
#diff_columns      (1,0)  (11,11)(1,0)    (7,7)    (3,3)  (17,17)(1,0)   (13,13)
#diff_hex_a        (0,0)   (7,11)(0,0)    (3,7)    (0,4)  (13,17)(0,0)    (9,13)
```

`#ab_diff_panel` is unchanged at every size — the freed rows go to `#diff_columns` and nowhere
else, which is the property HLR-125 §2.4's C-13/C-23 note asks Phase 3 to re-measure.

**What the operator now sees at 120×30** (previously the panel painted nothing at all below the
action row — P-33b: the shipped golden contains no `Runs` / `Image A` / `Image B`):

```
 ▏ ◉  MAC View        │   A   external path A
 ▏ ▤  Memory Map      │
 ▏ !  Issues Report   │   B   external path B
 ▏ ✎  Patch Editor    │
 ▏ ⏚  A2B Diff        │      Compare           Report       report destination dir (no-project only)
 ▏ ✦  Flow Builder    │
 ▏ ☑  Checks          │   Select two images and press Compare.
 ▏ ⊕  CRC Designer    │
                      │  ╭───────────────────────────╮ ╭────────────────────────────╮ ╭────────────────────────────╮
                      │  │                           │ │                            │ │                            │
                      │  │                           │ │                            │ │                            │
```

The status line and the three result boxes are now painted; the hex **content** is still 0 at
120×30 and needs the command-bar deletion, exactly as LLR-125.2 states (`compaction alone 3/0`).
At 132×44 the same screen renders 13 content rows of hex per window.

---

## 5. Risks

| # | Risk | Severity | Mitigation / status |
|---|---|---|---|
| **R-1** | **`AT-B78-33`'s spec-declared mutation is inert (F-1).** A reviewer re-running §5.3's wording will see GREEN and may read it as a passing discharge. | **medium** | Executed and recorded above with the working substitution (`1` → `3`). **§5.3's `AT-B78-33` row should be amended** — carried as `C-78-v`. |
| **R-2** | **`TC-B78-36` cannot fail for a reason peculiar to its subject (F-2).** | low — **labelled** | Marked PIN in the docstring with the executed mutation that proves it. Not shipped as a gate. |
| **R-3** | The compacted `Input`s and `Button`s lose their borders, so the **focus** affordance is now background-only. | low | Textual's own `-textual-compact` recipe does exactly this; `Input` keeps `background: $surface`, distinct from the panel. `margin-right: 1` restores button separation. **Not covered by a test** — it is perceptual, and `demo` is never acceptance (§5.1). |
| **R-4** | **The A/B `Select`s are 1 column wide (F-3)** — the dropdown is effectively invisible, though it still opens and holds the sentinel. | medium — **pre-existing** | Measured identical on `origin/main` (`w=1, h=2`). Cause: `Input`'s `width: 100%` inside a `Horizontal`. Out of HLR-125's scope; carried as `C-78-iv`. `TC-B78-37` pins that the control still *functions* so a later width fix has a green floor. |
| **R-5** | Snapshot cell `[diff-comfortable-120x30]` is RED until Inc-12. | low — **by design** | C9 forbids local regen. Recorded per-cell (§4.3). Any merge before Inc-12 ships a red suite; that is the batch's stated sequencing. |
| **R-6** | Ledger post-count is arithmetic, not executed. | low | Stated in §4.4, with the honest until-Inc-12 line beside it. |
| **R-7** | `styles.tcss` is edited again at Inc-2, 5, 7 and 10 (§7's file×increment map). Those increments rebase onto these rules. | low | The new rules are id-scoped and sit in the existing A↔B Diff block with a dated comment naming HLR-125. |
| **R-8** | A parallel session is live in this worktree (`prototypes/memmap2.*`, `.dev-flow/state.json` modified). | low | Nothing outside my two files was written. No `git add -A`, no `git stash`, no force, no push. |

**Security:** styling only. No new data path, no I/O, no network, no credential surface, no
dependency added, no secret in code or output. The one non-styling risk class a CSS change can
carry — text reaching a rendered label — is untouched: no `markup=` flag, no widget construction,
and no string moved.

---

## 6. Pending items

1. **§5.3's `AT-B78-33` mutation should be amended** from *"revert the row-height rule"* to the
   value substitution that reaches the subject, `rows' height 1 → 3` (F-1). Not done here — I do
   not edit `01-requirements.md`.
2. **`#diff_status` is still clipped to 0 at 80×24** (F-4). Compaction alone cannot fix it; it
   belongs to HLR-124's notice regime at **Inc-5**. Deliberately not pinned.
3. **`margin-bottom: 1` on the three rows is three more reclaimable rows.** Kept so 132×44 lands on
   the spec's executed **13** rather than 16. If the operator wants them, dropping the separators
   also makes `#diff_status` visible at 80×24 — a one-line change with a snapshot consequence.
4. **`TC-B78-35` shares a node with `AT-B78-33`.** §7's Inc-1 gate requires the row clauses "in the
   same run" as the height clause, and C-18 asks for one node per **AT**; the TC rides along rather
   than duplicating the same measurement at the same size. Split it if the operator wants strict
   one-subject-one-node.
5. **`TC-B78-34`'s notice half is unrealized** — its boundary text says the panel "degrades to the
   HLR-124 notice rather than to nothing", which does not exist until Inc-5. Only the row clause is
   asserted here, stated in the docstring.

## 6b. Batch carry list

| # | Item | Owner |
|---|---|---|
| **C-78-iv** | **The A/B variant `Select`s render at width 1, on `origin/main` and after this increment** (F-3). `Input`'s `width: 100%` inside a `Horizontal` claims the row. The dropdown opens and holds the right options, so it is invisible rather than broken — which is why no test caught it in ~70 batches. Needs a width budget across `Label(3) + Select + Input` in the two selection rows. **Out of HLR-125's scope** (vertical budget), so carried rather than folded in. | batch close / a Lane-2 successor |
| **C-78-v** | **§5.3's declared mutation for `AT-B78-33` is inert when executed** (F-1). The general form, and it is the third instance in this batch after `AT-B78-03` and `AT-B78-22`: **a mutation names a term, and a term that is a *function of other terms* (`height: auto`) is not a subject you can substitute.** The falsifiability table should record the RESOLVED value, not the declaration. | batch close |

---

## 7. Suggested next task

**Inc-2 — HLR-122, the selectable run list** (`screens_directionb.py`, `styles.tcss`,
`tests/test_tui_diff_screen.py`, `tests/test_tui_diff_compare_realpath.py`). It is now observable:
at 132×44 the run-list column paints **13** content rows instead of 7, so a `ListView` swap has
somewhere to render. Its gate needs the C-38 sweep first — `diff_range_list` has 8 hits across 3
files and `AbDiffPanel` 25 across 5 — and the `test_tc029` rewrite must redden under
`DISPLAY_MAX_RUNS 128 → 100000`, which today it does not.

⚠️ **Carry into Inc-2:** it edits `styles.tcss` too, and `#diff_range_list` currently inherits the
`#diff_range_list, #diff_hex_a, #diff_hex_b` block at `styles.tcss:1520`. A `ListView` swap changes
that widget's type, and per C13 the id rule will outrank the new widget's `DEFAULT_CSS` — including
`ListView`'s own scrolling and highlight styles.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Tests / type checks / lint pass | ✓ | §4.2 — `323 passed in 458.08s`, one run, FULL form, 11 modules. §4.1 — `10 passed`. §4.3 — `1 failed / 31 passed`, the **predicted** single snapshot cell, recorded not regenerated. Lint/type: repo runs neither in its gate suite. |
| No secrets in code or output | ✓ | CSS layout declarations and a `tmp_path` fixture; no env, no path outside `tmp`, no credential surface. |
| No destructive commands without approval | ✓ | `git checkout -- s19_app/tui/styles.tcss` twice, each on a file backed up byte-for-byte one command earlier and each restore verified by SHA-256. No `git add -A`, no `git stash`, no `rm`, no force, no push. |
| File count within cap | ✓ | 2 files — §7's planned count, cap is 5. |
| Every node carries a spec id | ✓ | `AT-B78-33`, `TC-B78-34`, `TC-B78-35`, `TC-B78-36`, `TC-B78-37` — all from §3 / §5.3 / §5.4. **No id invented.** |
| Gate takes its oracle from the Inc-0 artifact | ✓ | `_b78_diff_height_baseline()` reads `tests/goldens/batch78/at-b78-33-diff-hex-a-height.json`; **no fallback**, and the terminal size is read from the artifact too. Zero height literals in the module. |
| Nodes falsifiable, mutation applied-checked | ✓ | §4.5 — six transcripts, each asserting the substituted token present **and** the SHA changed before running, each restored by SHA. **Two came back INERT and are reported as findings (F-1, F-2), not absorbed.** |
| C-26 reverse grep over the whole `tests/` tree | ✓ | §4.2 — 4 modules beyond §5.2's gate suite were found by it and run. |
| Snapshot regen not attempted locally | ✓ | §4.3 — drift recorded per-cell with its reason; C9 respected; Inc-12 owns regen. |
| Review packet attached | ✓ | this document, §§1–7 + §6b carry list |
