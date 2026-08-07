# Code Review — batch-78 Increment 001 (HLR-125, compact the diff control rows)

> **Reviewer:** independent `code-reviewer` (did not author the diff)
> **Diff under review:** `b3b97f7..c09c699` — `s19_app/tui/styles.tcss` (+43/−2), `tests/test_tui_diff_screen.py` (+296)
> **Authority:** `01-requirements.md` §7 (Inc-1 row), §5.1, §5.3, HLR-125 / LLR-125.1 / LLR-125.2
> **Method:** every claim re-executed on a **throwaway copy** of the tree
> (`…/scratchpad/wt`, `PYTHONPATH`-pinned to the copy, `PYTHONDONTWRITEBYTECODE=1`).
> Nothing in `C:\Users\jjgh8\Github\s19_app` was written. No `git add -A`, no `git stash`.
> Fixed-tree `styles.tcss` SHA-256 independently reproduced as
> `8523da931ae933560721e2f270470b9594a9f1b64a8c9c3d61cf8cda2e836ec5` — matches the packet.

---

## BLUF

**PASS — no HIGH finding. The shipped CSS is correct, the gate is genuine and reddens on its
own assertion, and every one of the packet's four findings (F-1…F-4) reproduces.** The author's
geometry ladder is correct **to the digit at all four sizes on both layers**, which I re-measured
with my own probe rather than re-reading his.

The one thing self-review missed is a **coverage** gap, not a bug: of the **six** declaration
groups this diff ships, only the row-`height` group is reachable by any node. I reverted the other
three individually and **all four tests stayed GREEN** — including the case where the `Compare`
button's border comes back, which leaves the button two rows tall inside a one-row row with its
glyph on the clipped row. That is the exact hazard `TC-B78-37` exists to close for the `Select`s,
left open for the `Button`s, `Input`s and `Label`s.

| Severity | Count |
|---|---|
| **HIGH** | **0** |
| **MEDIUM** | **2** (F-A unguarded child declarations · F-B the `clipped` metric is not a paint test) |
| **LOW** | **3** (F-C · F-D · F-E) |

---

## Scope reviewed

| File | Range read | Verdict |
|---|---|---|
| `s19_app/tui/styles.tcss` | `1127–1180` (the whole new block, +43/−2) | ✅ correct, minimal, id-scoped |
| `tests/test_tui_diff_screen.py` | `1–30` (docstring map), `33–110` (harness), `397–616` (four nodes) | ✅ correct; see F-A/F-B/F-D |
| Not touched, confirmed | `screens_directionb.py`, `tests/__snapshots__/**`, `.dev-flow/state.json`, `AT-TC-REGISTRY.jsonl`, `prototypes/**` | ✅ `git status` clean on all |

**File count: 2 code files** (`§7`'s planned count, cap 5). The commit also carries
`increment-000-review.md` + `increment-001.md`; those are packet artifacts, not code.

---

## What I verified as sound

### 1. The geometry ladder — re-measured, not re-read ✅

Independent probe (`scratchpad/probe_geometry.py`), `(content_height, clipped_height)`,
clipped = `widget.region ∩ #screen_diff.region`, PRE = `b3b97f7:styles.tcss` swapped into the copy
(applied-check: 74 `height: auto;` occurrences; SHA `42e691e7…`), restored to `8523da93…` after:

```
                      120x30 BEF   AFT   132x44 BEF   AFT    80x24 BEF   AFT   160x40 BEF   AFT
#ab_diff_panel          (11, 13) (11,13)   (25, 27) (25,27)   (5, 7)  (5, 7)   (21, 23) (21,23)
#diff_select_row_a        (3, 3)  (1, 1)     (3, 3)  (1, 1)   (3, 3)  (1, 1)     (3, 3)  (1, 1)
#diff_select_row_b        (3, 3)  (1, 1)     (3, 3)  (1, 1)   (3, 2)  (1, 1)     (3, 3)  (1, 1)
#diff_action_row          (3, 3)  (1, 1)     (3, 3)  (1, 1)   (3, 0)  (1, 1)     (3, 3)  (1, 1)
#diff_status              (1, 0)  (1, 1)     (1, 1)  (1, 1)   (1, 0)  (1, 0)     (1, 1)  (1, 1)
#diff_columns             (1, 0)  (3, 3)   (11, 11) (17,17)   (1, 0)  (1, 0)      (7, 7) (13,13)
#diff_hex_a               (0, 0)  (0, 4)    (7, 11) (13,17)   (0, 0)  (0, 0)      (3, 7)  (9,13)
```

- **`#diff_hex_a` matches the packet and §7's BL-2 "S-8 only" column in all four cells.**
  `120×30 (0,0)→(0,4)` · `132×44 (7,11)→(13,17)` · `160×40 (3,7)→(9,13)` · `80×24 (0,0)→(0,0)`.
- **`#ab_diff_panel` is identical before and after at every size** — `(11,13)/(25,27)/(5,7)/(21,23)`.
  The freed rows went to `#diff_columns` (+2/+6/0/+6 content) and `#diff_status` (0→1 at 120×30);
  **nothing was taken from a sibling.** This is the property HLR-125's C-13/C-23 note asks Phase 3
  to re-measure, and it holds.
- The pre-change `80×24` row triple `3 / 2 / 0` reproduces HLR-125's own parenthetical
  ("at 80×24 `#diff_select_row_b` clips to 2") — the fixture is not vacuous.

### 2. The oracle is on disk, with no fallback and no literal ✅

`_b78_diff_height_baseline()` (`tests/test_tui_diff_screen.py:60-72`) asserts the artifact exists
and **has no `except` / no default** — a missing artifact is RED, never a producer substitution
(the BL-1 defect). The **terminal size is read from `baseline["terminal"]`** too, so Inc-0's
three-artifacts-at-three-sizes risk (R-3) cannot bite. `grep -n "content_height"` returns only the
docstring and the two artifact-key reads. The remaining numerals in the module (`== 1`, `>= 1`,
`>= 3`) are **HLR-125's own numeric pass thresholds**, not the invariance baseline — §5.1 rule 10
is satisfied. Artifact content matches the assertion:
`content_height 7 / clipped_height 11 / terminal [132,44] / widget "#diff_hex_a"`.

### 3. The counterfactuals — six re-executed, applied-checked, SHA-restored ✅

Each mutation was written into the **copy of the fixed tree**, its substituted token asserted
present, its SHA asserted different from the fixed tree **before** pytest ran, and the file
restored byte-for-byte with the SHA re-checked after. Per-node verdicts (CC-1), never an exit code:

| # | Substituted VALUE | `AT-B78-33` | `TC-B78-34` | `TC-B78-36` | `TC-B78-37` | vs packet |
|---|---|:-:|:-:|:-:|:-:|:-:|
| **CF-0** | whole `styles.tcss` at `b3b97f7` | 🔴 | 🔴 | 🔴 | 🔴 | ✅ match |
| **A** | rows' `height` `1 → auto` *(§5.3's declared mutation)* | 🟢 | 🟢 | 🟢 | 🟢 | ✅ match — **INERT** |
| **A2** | rows' `height` `1 → 3` | 🔴 | 🔴 | 🔴 | 🔴 | ✅ match |
| **B** | `#diff_select_a/_b` `display` unset `→ none` | 🟢 | 🟢 | 🟢 | **🔴** | ✅ match — discriminating |
| **C** | `#diff_path_*` `height` `1 → 3` | 🟢 | 🟢 | 🟢 | 🟢 | ✅ match — **INERT** |
| **C2** 🆕 | `#diff_path_*` `height 1→3` **and** `border none → tall $border-blurred` | 🟢 | 🟢 | 🟢 | 🟢 | reviewer-added — **still inert** |

Every restore returned `sha == 8523da93…` and the four nodes GREEN. **CF-0 and A2 fail on their
ASSERTIONS, not on an import or a guard** — verbatim from my run:

```
E   AssertionError: compaction must give the freed rows to the result area:
E     #diff_hex_a content height 7 is not greater than the pre-change 7 captured at (132, 44) by Inc-0
E   assert 7 > 7
E   AssertionError: #diff_select_row_a must paint exactly one row at 80x24, measured 3 ...
E   assert 3 == 1
4 failed, 6 deselected in 3.96s
```

**F-1 confirmed, both halves.** The spec's declared mutation really is inert, and the author's
replacement really does redden on the assertion. **F-2 confirmed and strengthened** — I added C2
(restoring the *border* as well as the height) and `TC-B78-36` still cannot redden. The PIN label
is honest, not a way to avoid fixing a gate.

**Is F-1's proposed generalisation sound?** — **Yes, with a sharpening.** The author offers
*"a term that is a function of other terms is not a subject you can substitute — record the
resolved value, not the declaration."* That is correct in substance and it does extend
`feedback_counterfactual_record_the_substituted_value`. I would state the operative rule one notch
more precisely, because "function of other terms" is not quite the discriminator:

> **When a declaration's effect is mediated by other declarations changed in the same diff, a
> partial revert is not a mutation of one subject — it is a mutation of one of N co-dependent
> subjects, and the token's denotation has changed underneath it. The falsifiability entry must
> record the value the declaration RESOLVED to on the pre-change tree (`3`), and the mutation must
> restore that resolved value.**

That form explains why `1 → 3` works and `1 → auto` does not, and it generalises to any
`auto` / `1fr` / `%` / inherited value — not only to `height`.

### 4. F-3 — the width-1 `Select` is genuinely pre-existing ✅

Checked against `origin/main`, not against the branch:

```
origin/main:s19_app/tui/styles.tcss  d3e85a6e944336279e4149c1048b28d8e3b46f32
b3b97f7   :s19_app/tui/styles.tcss  d3e85a6e944336279e4149c1048b28d8e3b46f32   ← identical
git diff --stat origin/main..b3b97f7 -- s19_app/  → (no production file differs)
```

So the PRE measurement **is** an `origin/main` measurement. `#diff_select_a` width, my probe:

```
120x30  BEFORE w=1 h=2  |  AFTER w=1 h=1
132x44  BEFORE w=1 h=2  |  AFTER w=1 h=1
 80x24  BEFORE w=1 h=2  |  AFTER w=1 h=1
160x40  BEFORE w=1 h=2  |  AFTER w=1 h=1
```

Pre-existing at every size, unchanged in width by this increment. Correctly carried as `C-78-iv`
rather than folded in — a width fix is not HLR-125's (vertical) subject, and `TC-B78-37` pins that
the control still *functions* so a later fix has a green floor. ✅ Right call.

### 5. F-4 — nothing pins today's 80×24 zero ✅

Repo-wide grep: the only geometry assertion on `#diff_status` anywhere in `tests/` is
`test_tui_diff_screen.py:457`, `>= 1`, at the **artifact terminal (132×44)**. `TC-B78-34`
(`:487`) drives 80×24 and asserts **only** the three row clauses. **No node pins a zero**, so
Inc-5's notice regime cannot be false-failed. ✅ (But see **F-C** for the other side of this.)

### 6. `margin-bottom: 1` was kept for the right reason — and the figure checks out ✅

I dropped it and re-measured (applied-check + SHA restore):

```
              #diff_hex_a (content, clipped)      vs §7's BL-2 "S-8 + S-1" column
120x30            (2,  6)                                  (2,  6)   ← identical
132x44            (16, 20)                                 (16, 20)  ← identical
 80x24            (0,  1)                                  (0,  1)   ← identical
160x40            (12, 16)                                 (12, 16)  ← identical
```

The author's **16** is exactly right, and `#diff_status` at 80×24 does become visible (clipped
1). **Keeping the separators is the correct call and stronger than the packet argues it.** Dropping
three margin rows frees precisely the three rows the command-bar deletion frees, so a
margin-dropping Inc-1 would **silently pre-satisfy LLR-125.2's 120×30 ≥1 threshold that §7 assigns
to Inc-10** — muddying Inc-10's gate rather than merely diverging from the spec's expected 13.
The spec's expected figure did real work as a check on the reading, exactly as the author says.

### 7. C-26 reverse grep — re-run independently over the whole `tests/` tree ✅

My own sweep of all 14 touched ids/classes yields this consumer union:

```
test_tui_diff_screen.py · test_tui_directionb.py · test_tui_patch_big.py ·
test_loadfilescreen_input.py · test_tui_diff_compare_realpath.py ·
test_tui_report_filter_surface.py · test_report_off_ui_thread.py · test_tui_commandbar.py
```

All eight are inside the author's 11-module run — **his set is a strict superset of mine. No
consumer was missed**, including `test_tui_commandbar.py` (the Inc-0 `#diff_hex_a` producer) and
Lane 1's `test_tui_directionb.py`. Two bookkeeping nits in his §4.2 table only: `diff_columns` is
now 1 hit (his own new file), not 0; `diff-field-label` is genuinely 0 in `tests/`. Not material.

### 8. Snapshot drift — exactly one cell, not regenerated ✅

My own run in the copy: `1 failed, 31 passed, 1 warning in 51.98s` ·
`1 snapshot failed. 28 snapshots passed.` · the failing cell is
`test_tc016s_density_layout_snapshot[diff-comfortable-120x30]` — **the only diff golden**.
`git status --short tests/__snapshots__/` in the real repo is **empty**: nothing regenerated
locally, C9 respected, Inc-12 owns regen. ✅

### 9. Ledger arithmetic — verified against pinned SHAs ✅

```
git show origin/main:tests/test_tui_commandbar.py | grep -c "^def test_"  → 13
git show b3b97f7  :tests/test_tui_commandbar.py | grep -c "^def test_"  → 14   (Inc-0: +1)
git show b3b97f7  :tests/test_tui_diff_screen.py | grep -c "^def test_"  →  6
git show c09c699  :tests/test_tui_diff_screen.py | grep -c "^def test_"  → 10   (Inc-1: +4)
```

`2607 → 2608 → 2608 − 0 + 4 = 2612`. ✅ And the executed claim is real: the 11-module set
**collects 323 tests** (`323 tests collected in 1.36s`, my run) — consistent with
`323 passed in 458.08s`. Per instruction I did not re-run the 26-minute full suite. The honest
line **`2611 passed / 1 FAILED` until Inc-12** is correct and is confirmed by §8 above.

**§7's named Inc-1 gate re-run independently.** C-34 mandates the **full** `tests/test_tui_directionb.py`
for every increment touching `styles.tcss`. My own run in the copy:

```
$ python -m pytest tests/test_tui_directionb.py -q -p no:randomly
183 passed in 180.53s (0:03:00)
```

Green, FULL form, no marker filter — including the markup-safety scans, the rail census, the footer
census and `TC-011`, which are the nodes most exposed to a stylesheet edit. ✅
The four new nodes are green on the fixed tree in the same copy (`4 passed, 6 deselected`), and the
whole module is `10 passed`.

### 10. No `DEFAULT_CSS` collision on the shared ids ✅

The trap this batch's own prototype re-hit does not recur:

- `styles.tcss` contains **no other rule** for `#diff_select_a/_b`, `#diff_path_a/_b`,
  `#diff_report_dest`, `#diff_compare_button`, `#diff_report_button`, `.diff-field-label` or
  `SelectCurrent` — the new block at `1149–1180` is the sole owner, no last-wins shadowing.
- `OsClipboardInput` (`s19_app/tui/os_clipboard_input.py:318`) defines **no** `DEFAULT_CSS`.
- The only two `DEFAULT_CSS` blocks in `screens_directionb.py` belong to `MapRuler` (`:1647`) and
  `BeforeAfterCard` (`:4185`); neither carries any of these ids.
- The intended overrides — Textual's own `Input` / `Button` / `SelectCurrent` `DEFAULT_CSS` — are
  outranked by app-level CSS by design (C13), which is what makes the compose-free compaction work.

### 11. Tests verify intent, not just behaviour ✅

Each docstring states **why** the clause matters, not what it measures. `AT-B78-33`'s names the
adversary explicitly ("shrinks the rows and leaves the result area at zero satisfies every
`height == 1` predicate and delivers NOTHING"). PINs are **labelled in the docstring** with the
executed mutation that proves the limit (`TC-B78-36`) — an honest downgrade, not a hidden one.
`TC-B78-37` is a real anti-shortcut node and MUT-B confirms it discriminates 1-of-4.

---

## Findings

### F-A — three of the six shipped declaration groups are unreachable by any node  · **MEDIUM**

- **What:** the diff changes six declaration groups. Only the row `height` group is covered.
  I reverted the other three **individually** on a copy of the fixed tree (applied-checked, SHA
  restored) and **all four nodes stayed GREEN in every case**:

  | reviewer mutation | substituted VALUE | `AT-B78-33` | `TC-B78-34` | `TC-B78-36` | `TC-B78-37` |
  |---|---|:-:|:-:|:-:|:-:|
  | **MUT-E** | `.diff-field-label` `height 1 → auto`, `padding 0 1 → 1 1 0 1` | 🟢 | 🟢 | 🟢 | 🟢 |
  | **MUT-F** | `#diff_compare_button/#diff_report_button` `border: none` **deleted** | 🟢 | 🟢 | 🟢 | 🟢 |
  | **MUT-G** | `#diff_path_a/_b/#diff_report_dest` `border: none` **deleted** | 🟢 | 🟢 | 🟢 | 🟢 |

  MUT-F is not cosmetic. With the border back, measured at 132×44:

  ```
  FIXED :  #diff_action_row y=12 h=1   #diff_compare_button y=12 h=1  line0='    Compare'
  MUT-F :  #diff_action_row y=12 h=1   #diff_compare_button y=12 h=2  line0=''   ← border edge
  ```

  The button is **two rows tall inside a one-row row**: the visible row carries the border edge and
  the `Compare` glyph sits on the clipped row below. Every height predicate in the file is green.
  That is precisely the failure mode `TC-B78-37`'s docstring names — *"a compaction that reports
  success and delivers an unusable control"* — closed for the `Select`s and open for the two
  `Button`s, the three `Input`s and the two `Label`s.
- **Where:** `tests/test_tui_diff_screen.py:397-616` (no node reads any control's rendered content);
  `s19_app/tui/styles.tcss:1149-1180` (the three uncovered groups).
- **Why it matters:** §7's file map has `styles.tcss` edited again at **Inc-2, 5, 7 and 10**. A
  later increment that restores a border — or a rebase that drops one of these lines — reverts the
  operator-visible half of HLR-125 with the whole suite green. The packet's evidence-checklist row
  *"Nodes falsifiable, mutation applied-checked ✓"* is true of the four mutations run but overstates
  coverage of the diff.
- **Suggested fix** (additive, one clause; extend the harness to return leaf content):

  ```python
  # in _b78_diff_geometry, alongside `measured`:
  painted = {
      sel: app.query_one(sel).render_line(0).text
      for sel in ("#diff_compare_button", "#diff_report_button", "#diff_path_a")
  }

  # in test_at_b78_33 (or TC-B78-37), same run:
  # Executed 2026-08-06: deleting `border: none` from #diff_compare_button leaves the
  # button 2 rows tall inside a height-1 row -- the glyph lands on the clipped row and
  # ALL FOUR height predicates in this file stay green. Compaction that hides the
  # control it compacts is the same defect TC-B78-37 forbids for the Selects.
  for sel, want in (("#diff_compare_button", "Compare"),
                    ("#diff_report_button", "Report"),
                    ("#diff_path_a", "external path A")):
      assert app.query_one(sel).region.height == 1, (
          f"{sel} must be one row tall inside a one-row control row"
      )
      assert want in painted[sel], (
          f"{sel} must still paint its own label on the one visible row; "
          f"got {painted[sel]!r}"
      )
  ```

  Discharge it with MUT-F (`border: none` deleted) as the reddening mutation and paste the
  transcript. **This is not a code change — the shipped CSS is correct.**

### F-B — the harness's `clipped` element is not a paint test, and the module already uses it as one · **MEDIUM** (binds at Inc-10, not here)

- **What:** `_b78_diff_geometry` computes `clipped = widget.region ∩ #screen_diff.region`. It does
  **not** intersect through the widget's own ancestors, so a child can report more visible rows
  than the parent that clips it. Measured on the **shipped post-Inc-1 tree at 120×30**:

  ```
  #diff_columns  (content 3, clipped 3)
  #diff_hex_a    (content 0, clipped 4)     ← child "visible" 4 > parent 3, paints NOTHING
  ```

  §5.1 rule 1 and HLR-125's *"Shipped surface"* both prescribe this exact metric as *"the painted
  layer"*, warning that `region.height` alone reads **4** at 120×30 and would ship the bug green.
  **The prescribed clipped form reads 4 there too.** The spec's stated remedy does not do what the
  spec says it does at that coordinate.
- **Where:** `tests/test_tui_diff_screen.py:96-101` (the metric) and **`:534`**, where `TC-B78-36`
  already uses `assert geometry["#diff_hex_a"][1] > 0` as a stand-in for *"the result area must
  still paint"*. At 132×44 that is true for the right reason (content 13); the identical idiom at
  120×30 is green with content **0**.
- **Why it matters:** this helper is introduced by Inc-1 and inherited by Inc-2/3/4/5/6/10 per §7's
  file map. `AT-B78-26`'s threshold — *"≥ 1 emitted hex row visible at 120×30 (today 0)"* — lands on
  exactly the coordinate where `[1]` is a false positive. An Inc-10 author reaching for the
  established idiom ships a vacuous gate. Not a defect in Inc-1's conformance (the gate asserts
  **content** `13 > 7` first, and `#diff_columns` clipped `>= 3` as its non-vacuity clause), so this
  is a **carry**, not a blocker.
- **Suggested fix:** either intersect through the ancestor chain —

  ```python
  clipped = widget.region
  node = widget.parent
  while node is not None and node is not host.parent:
      clipped = clipped.intersection(node.region)
      node = node.parent
  ```

  — or, minimally, add to the helper's docstring: *"`clipped` is the region ∩ `#screen_diff` only;
  it does NOT account for an intervening clipping parent. Executed at 120×30 the shipped tree
  reports `#diff_hex_a` clipped 4 with content 0. **For a ≥1 visibility claim assert
  `content_height`, never `[1]`.**"* Worth raising to `security-reviewer`'s peer `qa-reviewer` and
  registering as a batch carry alongside `C-78-v`.

### F-C — HLR-125's `#diff_status` clause is now satisfied at 120×30 and left unguarded for four increments · **LOW**

- **What:** HLR-125's numeric threshold names `#diff_status` clipped **≥ 1** with the parenthetical
  *"today 0 **at 120×30**"*. This increment actually achieves it there (my measurement: 120×30
  clipped **0 → 1**), but `AT-B78-33` asserts the clause only at the artifact terminal **132×44**,
  where it was **already 1 pre-change** — so within the gate node that clause is a **PIN**, not a
  gate, which the packet does not say.
- **Where:** `tests/test_tui_diff_screen.py:457`.
- **Why it matters:** the newly-won 120×30 status visibility is unpinned until `AT-B78-26` at
  **Inc-10**, while §7 has `styles.tcss` edited at Inc-2, 5 and 7. Unlike the 80×24 case (F-4,
  correctly not pinned because it is still 0), pinning **120×30** would **not** false-fail Inc-5 —
  it is true today.
- **Suggested fix:** add a 120×30 arm to `TC-B78-34`, or one line to `AT-B78-33`:
  `assert _b78_diff_geometry(tmp_path, (120, 30))["#diff_status"][1] >= 1` with a docstring note
  that this is the HLR-125 clause at the size the requirement names. Alternatively, name the gap in
  §6 "Pending items" beside the 80×24 residual — it is currently absent from both lists.

### F-D — `TC-B78-36` duplicates its terminal width as a bare literal · **LOW**

- **What:** the node drives `(132, 44)` at `:521` and then re-states the width as
  `row_width = 132` at `:525` for its applied-check.
- **Where:** `tests/test_tui_diff_screen.py:521,525`.
- **Why it matters:** if the size ever moves, the applied-check silently compares the fixture path
  against the wrong width and the node's own non-vacuity guard stops guarding — a small instance of
  the C-36 phantom this batch is otherwise disciplined about.
- **Suggested fix:**

  ```python
  size = (132, 44)
  geometry = _b78_diff_geometry(tmp_path, size, prepare=_fill)
  assert len(long_path) > size[0], (...)
  ```

### F-E — the new comment says "id-scoped" but one of the six groups is a class selector · **LOW**

- **What:** `styles.tcss:1136-1138` reads *"These are id-scoped on purpose (C13)"*.
  `.diff-field-label` (`:1149`) is a **class** selector.
- **Where:** `s19_app/tui/styles.tcss:1136-1138`, `:1149`.
- **Why it matters:** the claim is true in effect — I grepped it, the class has exactly two uses,
  `screens_directionb.py:6739` and `:6745`, both inside this panel — but a reader auditing the C13
  argument hits a selector the sentence does not describe.
- **Suggested fix:** *"These are scoped to this panel on purpose (C13) — five by id, plus
  `.diff-field-label`, which is used only by this panel's two field labels
  (`screens_directionb.py:6739,6745`)."*

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Diff read in full | ✓ | `styles.tcss:1127-1180` (+43/−2) and `tests/test_tui_diff_screen.py:1-30, 33-110, 397-616` (+296) read line by line |
| Correctness pass (edge / None / error paths) | ✓ | `_b78_diff_height_baseline` has **no** fallback (`:60-72`); artifact keys `widget` / `terminal` validated before use (`:433-438`); all four sizes re-measured incl. the 80×24 boundary |
| Simplicity pass (no premature abstraction) | ✓ | CSS-only, no `screens_directionb.py` change, one shared harness used by 3 of 4 nodes; nothing speculative. `margin-bottom` deliberately NOT reclaimed — verified as the correct restraint (§6 above) |
| Reuse / duplication checked | ✓ | `TC-021`/`TC-024` reused for the untouched handler paths (C-18, no new node); no re-implemented util; only duplication found is F-D's `row_width = 132` |
| Tests reviewed for intent, not just behaviour | ✓ | every docstring states WHY; PINs labelled with their executed inert mutation; MUT-B confirms `TC-B78-37` discriminates 1-of-4. **Gap: F-A** — no node reads any control's rendered content |
| Counterfactuals independently re-executed | ✓ | 6 mutations + CF-0, each applied-checked (token present **and** SHA ≠ fixed) before pytest, each restored to `8523da93…` after; per-node verdicts, never an exit code |
| Probe hygiene | ✓ | all mutation and measurement work in `…/scratchpad/wt` (throwaway copy). `git status --short` on the real repo shows only the parallel session's `.dev-flow/state.json` + untracked `prototypes/memmap2.*` / `build/` — untouched by me. No `git add -A`, no `git stash`, no push |
| Verdict explicit | ✓ | below |

---

## Verdict

- [ ] ~~Block — must fix HIGH findings before advancing~~ — **no HIGH finding**
- [x] **OK with the listed fixes applied first** — apply **F-A** (one additive clause + its MUT-F
      transcript) before the increment closes; it is cheap, needs no production change, and sits in
      the exact defect class this batch is tracking.
- Carry **F-B** to the batch carry list beside `C-78-v` — it binds at **Inc-10**, not here.
- **F-C / F-D / F-E** are recommendations; none blocks.

**Nothing in the shipped CSS is wrong.** The compaction is minimal, correctly scoped, conforms to
the codebase's conventions, reproduces the spec's executed ladder to the digit at all four sizes on
both layers, and its gate reddens on its own assertion against an artifact-sourced baseline with no
fallback. All four of the author's findings hold under independent re-execution, and F-1's proposed
control lesson is sound (with the sharpening offered in §3).

> Security and functional-suite coverage are out of this lane. No security-relevant surface was
> introduced (CSS layout declarations only, no I/O, no string routed to a rendered label, no
> dependency). Referred to `qa-reviewer`: F-A's coverage clause and the full-suite state
> (`2611 passed / 1 FAILED`) until Inc-12's CI-only regen.
