# Increment 06 — batch-48 · Patch Editor BIG · the history strip (R-TUI-081 / HLR-081)

**Status: COMPLETE.** 4 code/test files + this record (**5 of 5, cap held**). Scope US-P6 / HLR-081 —
LLR-081.1 (derived depths) · 081.2 (strip + C-7 parameter threading) · 081.3 (writer census) · 081.4 (C-28
disposition).

⚠ **The brief said "US-P6 / HLR-080". HLR-080 is the CARD (US-P5), which is NOT built.** The history strip is
**HLR-081 / R-TUI-081** — `01-requirements.md:307`, and `01b` §0.1 records the renumbering explicitly
(`AT-080a history position → AT-081a`). The brief's scope prose named US-P6 unambiguously, so the work is not
in doubt; the id is. Flagged because `01-requirements.md:733` warns that this exact off-by-one id clash
already misfired one Phase-2 security brief.

---

## 1. What changed

**`ChangeService.history_depths()` (NEW, `change_service.py`)** — returns `{"back", "forward", "bound"}` from
`len(_undo_stack)` / `len(_redo_stack)` / `_HISTORY_MAX`. Mirrors the `check_aggregates()` accessor precedent
exactly (canonical key tuple `HISTORY_DEPTH_KEYS`, never-partial return, all-zero default).

**The strip (`screens_directionb.py`)** — `Static#patch_history_strip`, docked as a sibling directly ABOVE
`#patch_history_controls`. Two lines:

```
↶ 1 back  ↷ 1 fwd  2/20
ctrl+z / ctrl+y
```

Disabled (the A-01 file-backed guard) renders one muted line, `history off`, and **no key hints** — the same
guard gates the bindings, so the keys are inert and a hint for them is a wrong answer, not decoration.

**The seam is `set_undo_redo_enabled(enabled, depths=None)`** — deliberately NOT a new `refresh_history`. The
strip answers "is a step back available?", which is the identical question the enable state answers; one call
means the strip and the buttons cannot disagree. A second seam is a site a future caller forgets — the
batch-38 Inc-4 F1 stale-panel shape.

**No new colour.** LABEL / VALUE / DGRAY only, per the brief's namespace constraint. Zero counts render DGRAY
("no step that way"), non-zero VALUE. A history strip is chrome, not a verdict.

## 2. ★ A REAL DEFECT the spec's own writer census would have shipped — and the fix is a 4th site

**`LLR-081.3` names THREE `set_undo_redo_enabled` sites. All three are ACTION sites.** None fires before the
analyst's first action, so a freshly-opened Patch Editor painted **`''`** — and `''` is not the empty state,
it is nothing. The empty state (`↶ 0 back  ↷ 0 fwd  0/20`) is **exactly the state a fresh screen is in**, and
AT-081b's own acceptance ("with no history it shows the empty state") is unsatisfiable without it.

Found by AT-081b's empty arm failing with `got ''` — the boundary case earning its keep on its first run.

⚠ **This is the MJ-1 shape verbatim.** `01b` §MJ-1 records that the `refresh_entries` census *also* counted
three sites and missed a mount-time fourth (`screens_directionb.py:2976`, the `on_mount` self-call). Same
seam family, same omission, one increment apart. **The census axis is "who calls this on an action" when the
question is "who renders this state".**

**Why the 4th site is app-side, not in `PatchEditorPanel.on_mount`** — where the sibling mount-time renders
(`_refresh_variant_scope_line`, `_refresh_paste_gauge`) live, both for this same never-mount-blank reason:
the panel is a view and **cannot know `_HISTORY_MAX` without importing the service layer**. A panel-side
default would have to invent a bound and render `0/0` — a wrong capacity on the surface that exists to report
capacity. C-7 decides it.

⚠ **Read-before-writing, and I only half did it.** `PatchEditorPanel.on_mount`'s existing body says *"render
the line's no-variant/default-scope initial state **so it never mounts blank**"*. The house had recorded this
exact failure mode in the function I was editing, and I still shipped a blank mount into the first test run.
The test caught it; **reading the four lines above my edit was cheaper.** Third instance of this class in the
batch (Inc-4's `microbar` docstring; Inc-5's `Static.renderable`).

## 3. ★ C-29: the budget is 38, NOT the 14 sitting in the sibling constant

**MEASURED at both regimes, with the strip mounted; nothing inherited.**

| | `#patch_history_controls` content | **strip content** | strip painted (enabled) | disabled |
|---|---|---|---|---|
| **80×24** | 64×1 | **64** | h=2 ✓ | h=1 |
| **120×30** | 38×1 | **38** | h=2 ✓ | h=1 |

**The trap this increment was walking into, named:** `_CHECK_STRIP_BAR_CELLS`'s docstring states a **14-cell**
budget at 120×30, measured three times, in the same class I was editing. **It is the CHECKS window's figure.**
At 120×30 the patch layout is a 3-column split in which the SCRIPT window is nearly 3× wider (44 vs 22), so
the SCRIPT strip's budget is **38**. Inheriting the recorded 14 would have been **the C-29 error verbatim** —
the same error Inc-4 committed and Inc-5 recorded — and the record was sitting in a sibling constant actively
inviting it.

**Line 1's worst case is bounded WITHOUT a width assumption** (the brief's "anchor to something the system
already demonstrates"): `back + forward ≤ bound` because `_push_history` evicts at `_HISTORY_MAX` and
`undo`/`redo` only MOVE snapshots between the stacks — so every count is at most 2 digits and the widest
reachable line 1 is `↶ 20 back  ↷ 0 fwd  20/20` = **25 cells**. Line 2 is 15. Both clear 38 with room.
**⇒ The two lines are a READING-ORDER choice (where you are, then how to move), not a wrap workaround** —
which is the opposite of the CHECKS strip, where two lines were forced. Recorded so the next reader does not
"fix" a wrap that was never there.

**Cross-check that my rig is honest:** it independently reproduced Inc-5's recorded `patch_checks_strip` =
`64×1 @ y=59` at 80×24. A measurement rig that disagrees with the house record is the rig.

⚠ **One measurement error of my own, caught and corrected.** My v2 script read `strip.region` *after*
flipping to the disabled state and reported **h=1** for the enabled strip — a false "the second line does not
paint" that I nearly wrote up as a CSS defect. Fixed by reading the region **per state** (v3). The rig was
wrong, not the code.

## 4. ★ The derived position: how I proved there is no off-by-one, per branch

**Position must be DERIVED — no cursor exists — and an off-by-one here does not crash and does not look
wrong.** Every functional test binds **THREE independently-computed quantities**:

> the literal the branch constructs **==** the live stack lengths **==** the numbers the strip PAINTS

The literal↔stacks edge catches a wrong derivation; the stacks↔painted edge catches a rendering off-by-one.
Asserting only the last pair lets a strip that agrees with a broken accessor pass. **M-1 (`len(_undo_stack) - 1`)
dies on the first edge; M-3 (render `back` for `back+forward`) dies on the third.**

The derivation is argued in `history_depths`'s own body against **the code's own predicates**, not a parallel
model: `undo` no-ops iff `not self._undo_stack` and otherwise pops exactly one, so steps-available **is**
`len(_undo_stack)`. `_push_history` appends the PRE-mutation document, so no "current position" snapshot sits
on either stack to discount — **that is where the off-by-one would live if the stacks held the live document;
they do not** (it is `self.document`).

| Branch | Fixture | (back, fwd) | Verified |
|---|---|---|---|
| **empty** (both no-op) | 0 adds | (0, 0) | AT-081b + TC-081.1 |
| **newest end** (redo no-ops) | 3 adds | (3, 0) | TC-081.1 |
| **oldest end** (undo no-ops) | 2 adds, 2 undos | (0, 2) | TC-081.1 |
| **mid-stack** (neither no-ops) | 3 adds, 1 undo | (2, 1) | TC-081.1 |
| **saturation** | 21 adds | (20, 0) → `20/20`, never 21 | AT-081b |

## 5. ★ The universal I certify, and how its input set is GUARDED (not hand-listed)

TC-081.1 certifies **"the derivation holds across every branch"** — a universal, so per the brief **the input
set is itself an oracle**. It is **derived from the code's only two branch predicates** (`undo` no-ops iff the
undo stack is empty; `redo` iff the redo stack is), which partition `(back, forward)` into exactly four
quadrants. `_quadrant()` computes each fixture's cell and the test **asserts the table covers all four**:

```python
assert covered == {(False, False), (True, False), (False, True), (True, True)}
```

**M-7 proves it has teeth:** deleting the `oldest_end` row → **RED**. That is the mutation class M-1..M-6
provably cannot reach — Inc-5b's HIGH-1 was exactly a real assertion with exact arithmetic quantifying over a
hand-listed set that omitted the failing case, and **every code mutation passed it**.

The other universal available here — "0 new cursor attributes on `ChangeService`" (TC-081.1's 01b threshold) —
is deliberately **not** implemented as a name-pattern grep. An oracle keyed to attribute names that *look*
cursor-ish reports on vocabulary. It is replaced by a **behavioural** oracle with no input set: poke
`_undo_stack` directly and the reported depth must follow. A cached count or a cursor would not move.

## 6. Files

| File | State |
|---|---|
| `s19_app/tui/services/change_service.py` | M — `HISTORY_DEPTH_KEYS` + `history_depths()` |
| `s19_app/tui/screens_directionb.py` | M — strip Static + `_history_strip_text` + extended seam + 3 constants |
| `s19_app/tui/app.py` | M — 3 action sites push depths **+ the 4th (`on_mount`) initial render** |
| `tests/test_tui_patch_history_strip.py` | **NEW** — AT-081a/b + TC-081.1/.2/.3/.4/.5/.6 |
| `.dev-flow/…/increment-06.md` | Mandated — this record |

**5 of 5. No 6th file taken.** `styles.tcss` was NOT needed: `.patch-docked-row` already supplies width 100% /
height auto / padding, and the strip's colours ride the `Text` (the `#patch_checks_strip` precedent).
`REQUIREMENTS.md` was NOT touched — no locked requirement is amended (see §9).

## 7. Test results — invocation NAMED, pasted verbatim

**Reduced suite: `python -m pytest -q -m "not slow" -p no:randomly`** — the REDUCED variant, per the brief.
`pytest -q` unfiltered is the FULL suite and was **NOT** run.

```
1514 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning in 939.91s (0:15:39)
```

**0 failed. xfail count unmoved at 5** — no pre-existing mark silently flipped, and no new one added (the 2
patch cells' marks are pre-existing from Inc-1).

⚠ **THE FIRST RUN OF THIS SUITE REPORTED 2 FAILED, AND THAT RESULT WAS MY OWN ARTIFACT** — disclosed in full
because a "re-ran it and it went green" with no mechanism is exactly the story this batch keeps catching:

```
FAILED tests/test_tui_directionb.py::test_tc028_memory_map_renderer_adds_no_coverage_computation
FAILED tests/test_tui_directionb.py::test_tc_042_8_strip_colour_is_pure_reuse_of_batch27_helpers
2 failed, 1512 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning in 956.02s (0:15:56)
```

**Root cause, diagnosed not assumed:** both tests use `inspect.getsource`, which resolves file content through
`linecache`. **I edited `app.py`'s `_refresh_patch_history_view` docstring ~4 minutes INTO that 16-minute run.**
That shifted `app.py` by +5 lines while the already-imported code objects kept their original
`co_firstlineno`; `linecache` re-read the changed file on mtime, so `getsource` sliced the WRONG lines and fed
garbage to `ast.parse`. Both tests pass in isolation, and the earlier 222-test census run (which included
`test_tui_directionb.py` and finished BEFORE the edit) was green.

⚠ **I had explicitly told myself that edit was safe** — "docstrings aren't `Call` nodes, so the AST census
can't see it." True and irrelevant: I reasoned about the wrong mechanism. The hazard was **line alignment**,
not AST semantics. Verified on the frozen tree:

```
$ python -c "import inspect; from s19_app.tui.app import S19TuiApp; print(repr(inspect.getsource(S19TuiApp.update_memory_map).splitlines()[0]))"
'    def update_memory_map(self) -> None:'   # aligns; co_firstlineno: 8851
```

The clean run above was then executed on a **frozen tree** (`git status` captured in its own log, no edit from
launch to completion). **1512 + 2 = 1514 reconciles exactly** against the artifact run — the same tests, two
of them mis-sliced. **Lesson, general: never edit a source file while a suite that AST-inspects it is
running.**

**Baseline — STATED HONESTLY, NOT CLAIMED.** ⚠ **I did not measure a pristine-tree baseline at `da2b3eb`
before editing, and it is not recoverable without `stash`/`checkout`, which are forbidden.** So the reduced-run
delta vs HEAD is **derived, not measured**: my new file contributes exactly 8 tests (measured alone, below),
and 0 pre-existing tests fail. The PLAN's ledger carries no comparable reduced-suite figure at `da2b3eb`
(its most recent are `6551aed` / `faa65cb`, both pre-Inc-2..5), so I have nothing valid to difference against
and **do not manufacture one**. What IS measured: **0 failed, 5 xfailed (unmoved), 2 skipped.**

**New file alone:**
```
........                                                                 [100%]
8 passed in 11.58s
```

**ruff — clean on all 4 touched code/test files:**
```
$ python -m ruff check s19_app/tui/services/change_service.py s19_app/tui/screens_directionb.py \
    s19_app/tui/app.py tests/test_tui_patch_history_strip.py
All checks passed!
```
`a2l.py:926` F841 remains the known **frozen** carry — not mine, unfixable while `a2l.py` is engine-frozen.

**C-27 dual-guard — raw frozen diff vs `main` = EMPTY:**
```
$ git diff main --stat -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
    s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```

**MUTATION LEDGER — applied to the tree, file RUN, output READ, reverted by INVERSE EDIT.**
⚠ **My predictions were wrong on FOUR of seven; the run won every time.**

| # | Mutation | Measured result |
|---|---|---|
| M-1 | `back = len(_undo_stack) - 1` (the off-by-one) | **3 FAILED** — AT-081a, AT-081b, TC-081.1. Prediction held |
| M-2 | swap `back`/`forward` keys | **2 FAILED** — AT-081b, TC-081.1. ⚠ **AT-081a PASSED; I predicted it would fail.** Its `(1,1)` fixture is a PALINDROME — value-invisible to a swap |
| M-3 | render `back` for `back + forward` | **3 FAILED** — AT-081a, TC-081.1, TC-081.6. I named only TC-081.1's two quadrants |
| M-4 | builder ignores `enabled` | **2 FAILED** — TC-081.3, TC-081.6 |
| M-5 | history site drops `depths` | **3 FAILED** — AT-081a, TC-081.1, TC-081.3 |
| M-6 | remove the `on_mount` site (ship §2's defect) | **3 FAILED** — AT-081b, TC-081.1, TC-081.3. The fix has an oracle |
| M-7 | **delete a quadrant from the INPUT SET** | **1 FAILED** — TC-081.1's coverage assert. The class code-mutation cannot reach |

⚠ **M-3's breadth proves less than it looks:** 3 tests fail for **ONE** reason (`_expect_position` spells the
format once, so every consumer inherits the discrimination). Recorded per the Inc-5 M-1 lesson — a mutation
tripping N tests for 1 reason is 1 oracle, not N.

⚠ **AT-081a's palindrome is 01b's prescribed fixture and I KEPT it** (the requirement names "2 edits → 1 undo
→ 1 back / 1 forward"). TC-081.1's asymmetric quadrants discharge the swap instead. This is the **fourth**
degenerate prescribed fixture this batch (Inc-3 AT-077d; Inc-4's 2/1/1; 01b's `['✓','✗','✓']`, twice).

**C-22 snapshot disposition:** both `patch-comfortable-{80x24,120x30}` cells ride `_batch48_patch_drift_marks`
(`xfail(strict=False)`) and **ABSORB** this repaint — **their passing is NOT evidence.** Prediction: still
exactly 2 cells, no new ones. Containment argued, not assumed: every change is inside `#patch_editor_panel`;
no CSS rule was added; no App-level `Binding` changed (TC-081.4 asserts this executably, so C-28 does not
fire). **Regen = canonical CI, post-merge. NEVER local** — and this tree's textual is 8.2.8, i.e. exactly the
pin, which is what makes a local regen *tempting* and still wrong.

**Destructive commands: NONE.** No `git checkout` / `stash` / `reset`. Every mutation reverted by inverse
edit. No process killed — none was started that needed killing.

⚠ **My own errors this increment — four, all disclosed:**
1. The M-6 revert script asserted on a non-unique anchor and **aborted before reverting**, so M-7 then ran on
   a still-mutated tree — its first result was **void**. Caught by noticing "M-6 reverted" never printed. Both
   were re-run cleanly, one at a time, with a green baseline (`8 passed`) between. The ledger is the clean run.
2. **Edited `app.py` mid-suite** → 2 phantom failures (§7). Diagnosed, not re-rolled.
3. My **v2 measurement rig** read `region` after flipping state and reported h=1 for the enabled strip — I
   nearly wrote that up as a CSS defect. The rig was wrong (§3).
4. `_write_v2_document` called with the wrong signature; and **four of seven mutation predictions were wrong**
   (§7 ledger). In every case the run won.

## 8. Risks

- **The 4th (`on_mount`) writer site reaches `query_one("#patch_editor_panel")` at app-mount time.** Verified
  to resolve (the sibling `_setup_datatable_columns` does the same there). If a future refactor mounts the
  patch panel lazily, this raises at startup — **loud, not silent**, which is the right failure.
- **`set_undo_redo_enabled` now has two jobs** (button state + strip). That is the deliberate anti-drift
  choice of §1, but it makes the method's name narrower than its behaviour. A future reader looking for
  "where is the strip rendered" will not grep `set_undo_redo_enabled`. Mitigated by the docstring; not by a
  test.
- **The strip's disabled text names no reason** ("history off", not "file-backed"). Correct today — the panel
  is told the state, not the reason — but if a second disable reason ever appears, the strip cannot
  distinguish them and the analyst gets no cue why.
- **`_HISTORY_STRIP_BUDGET_COLS = 38` is asserted as a FLOOR** (`content_region.width >= 38`), not an
  equality: it pins that the narrower regime has not silently narrowed further, and fails loud with the real
  width if the layout moves.

## 9. Pending items

1. **No §6.5 amendment is owed by this increment** — no locked requirement changed. **But LLR-081.3's
   "three sites" is now FALSE (there are four).** Whether that is an amendment or an erratum is the
   orchestrator's call; the code and TC-081.3 both say four, and the test fails loudly if a fifth appears.
2. **The brief's `HLR-080` → `HLR-081` id correction** (§ header) — worth a line in the PLAN so the next
   brief does not inherit it.
3. **C-26 census result:** consumers re-run green (§7). The census hit `test_tui_patch_chips.py::
   test_tc076_2` on a **value** (`set(parents) == set(_GROUP_BY_CONTAINER)`, an EXHAUSTIVE set over Button
   parents) — safe only because the strip is a `Static` and holds no Button. Had the strip been a chip row it
   would have tripped. **Third value-keyed hit of the batch**; the symbol-keyed seeds never named it.
4. **Remaining Batch-B story: US-P5, the live before/after card** (the headline) — the only unbuilt story.
5. Carried from Inc-5b: **F4's TC-078.4 docstring** (still a 6th file for whoever takes it).

## 10. Suggested next task

**US-P5 — the live before/after card** (the Batch-B headline, and the last story). Inc-5's recon stands and
this increment adds two facts to it: (a) **the SCRIPT window's content budget is 38 at 120×30 / 64 at 80×24,
measured with the docked stack as it now stands** — the card mounts into that same window, so AT-080d's
reachability arm must be re-measured **after** this increment's extra docked row, not before; and (b) the
`on_mount`-blank defect of §2 is a **class, not an instance** — the card has an identical no-selection initial
state and the identical "the panel cannot know the datum at mount" constraint, so budget the 4th writer site
from the start rather than discovering it at the boundary AT.

---

## Evidence checklist

- [✓] **Tests/type checks/lint pass** — reduced suite (`-m "not slow"`) **1514 passed / 0 failed / 5 xfailed**,
  pasted verbatim in §7; ruff clean on all 4 files (`a2l.py:926` = known frozen carry). ⚠ **The full
  (unfiltered) suite was NOT run**, and **no pristine-tree baseline was measured** — both stated, neither
  claimed.
- [✓] **No secrets** — synthetic addresses / byte literals only.
- [✓] **No destructive commands** — none; every mutation reverted by inverse edit. The one rig failure (M-6's
  aborted revert) is disclosed in §7 and its void result discarded.
- [✓] **File count within cap** — **5 of 5**. No 6th file taken; `styles.tcss` and `REQUIREMENTS.md` were
  each considered and shown unnecessary.
- [✓] **Review packet attached** — in-conversation.
