# Increment 02 — batch-48 · Patch Editor BIG · chip CSS + title de-dup (R-TUI-076 / HLR-076)

> Branch `feat/batch-48-patch-big` @ base `3545e64` (Inc-1b). Scope: **HLR-076 (LLR-076.1/.2/.3/.4)**
> + the **§6.5 Amendment D title de-dup** (ordering-critical) + code-review nit **F4**.
> Out of scope, untouched: glyph (Inc-3) · strip (Inc-4/5) · JSON (Inc-6) · card (Inc-7).

---

## 1. What changed

**BLUF (1) — the C-30 leak probe is MEASURED and CLEAN: exactly the 2 already-marked patch cells
drift; 0 non-patch cells moved.** **BLUF (2) — the duplicated window title is gone, deleted (not
hidden), and its oracle is restated on `border_title` in a stronger, mutation-verified form.**

Two findings below are corrections to my **own** work in this increment, both caught by mutation
testing rather than review, and both would otherwise have shipped as false-confidence tests (§4.2).

1. **HLR-076 — the chip family (the batch-47 carry).** `styles.tcss` gains a chip-button family: each
   button-bearing docked container carries a `patch-chip-{entry,apply,checks}` **group** class, each
   `Button` a `patch-chip`. The container supplies the hue (what this group of buttons *does*), the
   button the chip shape. **Every rule is `#patch_editor_panel`-rooted** (LLR-076.1) — the entire
   basis of the batch's "C-30 = N/A" verdict.
2. **LLR-076.2 — the 4 `assumed` arms resolved.** The spec named 5 of 9 containers; the other 4 were
   `assumed — Phase-3 confirms`. Resolved and recorded in source: `#patch_history_controls` → **entry**
   (undo/redo *move the entry document*); `#patch_variant_select_row` + `#patch_execute_buttons` →
   **apply** (the variant group scopes *what a run targets*); `#patch_before_after_buttons` → **apply**
   (revealed by the same save flow as the save-back row). **9/9 mapped, 0 left `assumed`.**
3. **§6.5 Amendment D — the title de-dup (ordering-critical).** Inc-1's `border_title ¹PATCH SCRIPT`
   duplicated the in-body `Label("PATCH SCRIPT")`; each window rendered its own name **twice**. The
   three Labels are **DELETED**, and the now-consumerless `.patch-window-title` CSS rule is deleted
   with them. Before/After recorded in `REQUIREMENTS.md` — R-TUI-063 names the `Label` explicitly, so
   this is a locked requirement's element being removed.
4. **F4 (LOW) — `#patch_variant_scope_line` gets `.patch-stat-line`**, not the borrowed
   `.patch-field-label`, whose `color: $fg-base` was inert there (`label_value` sets its own colours);
   only the padding was ever wanted, and the new class says exactly that.

**Palette (as instructed: reuse the `$`-vars, don't hard-code a hex that duplicates one).** ⚠ **Only
ONE relevant var exists.** The Calm Dark token set declares `$accent-calm` / `$bg-*` / `$fg-base` /
`$rule` / `$odd-row` (`styles.tcss:21-31`) — there is **no green or yellow var**. So: blue → the
`$accent-calm` **var**; green/yellow → the literal `insight_style` hex with its constant **named in the
comment**, which is this file's own established idiom for non-accent hues (`.sev-*` `:529-547`,
`.band-*` `:566`). **Declaring new vars was rejected**: it would fork the token contract (`:10-11`,
"exactly ONE accent hue") for a screen-scoped family. **Reusing `.sev-ok`/`.sev-warning` was rejected
outright**: a chip group is a **function** cue, a `sev-*` class is a **severity verdict**, and
`color_policy` is the frozen single source of truth for severity — conflating them would be a real
semantic regression dressed as reuse.

**Not a deviation (per Inc-1's lesson — don't over-report either):** the group class sits on the
button-bearing container while HLR-076/AT-076a requires *"every docked `Button` carries a class from
the chip family"*. Both are satisfied simultaneously and by design — LLR-076.2 puts the **group** on
the container, HLR-076 puts a **family class** on the button; the button carries `.patch-chip`, its
container the group. No requirement is bent, so no amendment is owed and none is claimed.

---

## 2. Files modified — **5** (cap 5 ✓)

| File | Change |
|---|---|
| `s19_app/tui/styles.tcss` | NEW chip family (4 rules, all `#patch_editor_panel`-rooted) + NEW `.patch-stat-line` (F4); **DELETED** `.patch-window-title` |
| `s19_app/tui/screens_directionb.py` | `compose`: **3 title Labels DELETED**; chip group class on 9 containers + `patch-chip` on 21 buttons; F4 class swap; docstring restated |
| `tests/test_tui_patch_chips.py` | **NEW** — AT-076a · AT-076b ★ (C-30 leak probe) · TC-076.1 · TC-076.2 + the measured RED ledger |
| `tests/test_tui_patch_layout.py` | `test_tc46_1_*`: **delete-and-restate** — the class assertion → a `border_title` assertion + a no-duplicate assertion |
| `REQUIREMENTS.md` | **§6.5 Amendment D** (Before/After) + the R-TUI-076 chip/C-30 note |

`app.py` **unchanged**. `tests/test_tui_snapshot.py` **unchanged** — no new cell drifts, so nothing new
is marked (§4.4). **Zero SVG baselines touched** (local regen forbidden).

⚠ **`tests/test_tui_patch_layout.py` is edited, so TC-076.3's *"diff vs `main` == 0 lines"* threshold
does NOT hold literally — and I am not going to claim it does.** The edit is **scope B's** (the
Amendment-D de-dup), **not the chip restyle's**. TC-076.3's intent — *the chip restyle changes classes
only; no id moves* — is fully met and separately evidenced: all **48** `_MUST_PRESERVE_IDS` present and
in role, layout suite green, and the file's chip-relevant assertions needed **no** edit. Reporting the
threshold as "met" would be false; reporting the intent as unmet would be false too.

---

## 3. How to test

```bash
pytest -q tests/test_tui_patch_chips.py                     # HLR-076: AT-076a/b + TC-076.1/.2
pytest -q tests/test_tui_patch_layout.py                    # the restated TC-46.1 + the 48-id census
pytest -q tests/test_tui_snapshot.py                        # C-30 leak probe + C-22
pytest -q tests/test_tui_theme.py                           # TC-012 token budget (a census hit)
pytest -q tests/test_engine_unchanged.py                    # C-27 arm 1
pytest -q tests/test_tui_directionb.py -k "test_tc031 or test_tc032"   # C-27 arm 2
python -m ruff check s19_app/tui/screens_directionb.py tests/test_tui_patch_chips.py tests/test_tui_patch_layout.py
```

**Reproduce the two REDs** (both are real, both were executed — §4.2):

```bash
# Mutation B — widen the chip base rule to a bare `Button` selector -> AT-076b RED (26 leaks)
# Mutation A — drop the `#patch_editor_panel` root from the chip selectors -> TC-076.1 RED
# Mutation C — re-add `Label("PATCH SCRIPT", classes="patch-window-title")` -> TC-46.1 RED
```

---

## 4. Test results — **executed, pasted verbatim**

### 4.1 ★ THE HEADLINE — the C-30 leak probe, MEASURED (not reasoned)

```
$ python -m pytest -q tests/test_tui_snapshot.py -rxX
27 snapshots passed. 2 snapshots unused.
XFAIL tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-80x24]
  - batch-48 Inc-1 R-TUI-075 US-P1: patch windows gain border titles + live subtitles ...
XFAIL tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]
  - batch-48 Inc-1 R-TUI-075 US-P1: patch windows gain border titles + live subtitles ...
30 passed, 2 xfailed, 1 warning in 52.00s
```

**Verdict: NO non-patch cell drifts. The selector scoping holds.** The inference is decisive, not
optimistic: **only the 2 patch cells carry an xfail mark**, so any other cell's drift would surface as
**FAILED**, not xfail. There are **0 FAILED**. The 2 mismatches are exactly the 2 marked patch cells,
already drifting from Inc-1.

⇒ **C-30 = N/A for batch-48 is CONFIRMED BY MEASUREMENT**, not asserted. The chip family is contained
to the Patch Editor; the restyle-LAST sequencing mandate does not bind.

### 4.2 ★★ The two corrections mutation testing forced — both were MY errors, in THIS increment

Neither was found by reading. Both would have shipped as tests that pass while the property is broken.

**(a) `AT-076b` does NOT catch an unscoped selector — my recorded RED said it did. It was FALSE.**

I wrote a RED ledger into the AT's docstring claiming that unscoping `.patch-chip` turns AT-076b red.
Then I ran it:

```
=== Mutation A: `#patch_editor_panel .patch-chip` -> `.patch-chip` ===
E  AssertionError: every chip rule must be rooted at #patch_editor_panel (LLR-076.1 - the C-30
   containment); unrooted: ['.patch-chip', '.patch-chip-entry .patch-chip',
   '.patch-chip-apply .patch-chip', '.patch-chip-checks .patch-chip']
FAILED tests/test_tui_patch_chips.py::test_tc076_1_every_chip_selector_is_panel_rooted
1 failed, 3 passed          <-- AT-076b PASSED. My ledger was wrong.
```

**Why:** the chip rules are **class**-based and this increment only applies those classes inside the
panel — so an unscoped `.patch-chip` rule still matches nothing outside. AT-076b is **structurally
blind** to it. The mutation that *does* leak is a **type** selector:

```
=== Mutation B: `#patch_editor_panel .patch-chip` -> `Button, #patch_editor_panel .patch-chip` ===
E  AssertionError: @(80, 24): C-30 LEAK - 26 chip rule/button matches OUTSIDE #patch_editor_panel.
   The chip family has gone app-wide; C-30 re-binds (§2.4-8):
   ['#ws_load_project_button <- Button, #patch_editor_panel .patch-chip',
    '#search_button <- ...', '#goto_button <- ...', '#a2l_filter_field <- ...',
    '#a2l_filter_all <- ...']
E  AssertionError: every chip rule must be rooted at #patch_editor_panel ...
   unrooted: ['Button, #patch_editor_panel .patch-chip']
2 failed, 2 passed
```

**The false claim is CORRECTED at its source, not carried** — the module docstring now states the
measured matrix. **The durable finding: AT-076b and TC-076.1 are NOT redundant, and the reason is the
opposite of intuitive.** TC-076.1 (source) catches the **latent** class of mistake — harmless today, a
live leak the day any screen reuses the class name. AT-076b (Textual's own matcher) catches the
**live** one and counts its 26 real victims. Dropping either as "the weaker probe" loses a real half.

**(b) The de-dup guard was VACUOUS — `Label` has no `.renderable` at this pin.**

My no-duplicate assertion used `str(getattr(c, "renderable", ""))`. Mutation-tested:

```
=== Mutation C: re-add Label("PATCH SCRIPT", classes="patch-window-title") ===
1 passed          <-- the duplicate is BACK and the guard says nothing.
```

Probed the pin directly:

```
$ python -c "from textual.widgets import Label; l = Label('PATCH SCRIPT'); \
             print(hasattr(l, 'renderable')); print(repr(l.render()))"
False
Content('PATCH SCRIPT')
```

**`getattr(..., "renderable", "")` silently returned `""` for every Label, so the list was always
empty and the assertion always passed.** This is precisely the false-confidence shape the increment
brief warned about — arrived at by a guessed attribute rather than a CSS `display: none`. Fixed to read
the real render path (`c.render().plain`), then re-mutated:

```
=== GREEN (shipped) ===                          1 passed
=== RED (mutation C re-applied) ===
E  AssertionError: patch_win_script carries ['Label'] in-body title Label(s) duplicating its
   border_title (§6.5 Amendment D removed them)
FAILED tests/test_tui_patch_layout.py::test_tc46_1_window_structure_layout_agnostic
=== restored ===                                 9 passed
```

**The guard now tracks the property.** Lesson recorded in-line at the assertion site so the next reader
does not re-introduce the attribute guess.

### 4.3 GREEN — the new ATs

```
$ python -m pytest -q tests/test_tui_patch_chips.py
....                                                                     [100%]
4 passed in 4.22s
```

### 4.4 C-22 snapshot — per-cell prediction MEASURED; **nothing new marked**

Predicted: the chips + de-dup repaint **only** the patch screen ⇒ drift confined to the 2 cells Inc-1
already marked ⇒ **0 new cells to mark**. Measured (§4.1): exactly that. `test_tui_snapshot.py` is
therefore **untouched this increment** — `_batch48_patch_drift_marks` already covers both cells.

**Per-cell WHY:** the 3 in-body title Labels vanish (1 row reclaimed per window) and every docked
`Button` collapses 3 rows → 1. **C-28 shared-chrome clean** — no footer/header/rail binding changed.
**Regen stays a single batch-end canonical-CI follow-up PR** (`snapshot-regen.yml`, textual==8.2.8).
**Local regen NOT performed** (`reference_snapshot_regen_env`).

### 4.5 C-26 reverse census — **ONE invocation, and it found a file the PLAN's seeds missed**

Touched: `PatchEditorPanel.compose` · `.patch-window-title` (deleted) · `.patch-field-label` (one
consumer moved off) · the 9 docked containers + 21 buttons · `styles.tcss` · `test_tc46_1_*`.

⚠ **`tests/test_tui_theme.py` is a census hit that PLAN.md's seed table does NOT list** — the seeds
were keyed on `PatchEditorPanel`, so they missed the file keyed on **`styles.tcss`**, which is exactly
what this increment edits. It is the TC-012 **theme token-budget** guard. Reverse-grepping the touched
*symbols* rather than re-using the seed list is what surfaced it.

```
$ python -m pytest -q tests/test_before_after_report.py tests/test_loadfilescreen_input.py \
    tests/test_tui_directionb.py tests/test_tui_memory_patch.py tests/test_tui_patch_big.py \
    tests/test_tui_patch_chips.py tests/test_tui_patch_editor_v2.py tests/test_tui_patch_layout.py \
    tests/test_tui_patch_variant.py tests/test_tui_report_filter_surface.py tests/test_tui_theme.py \
    tests/test_tui_variants.py tests/test_undo_redo_ux.py tests/test_variant_execution.py
389 passed in 506.25s (0:08:26)
```

**14/14 files pass; only `test_tui_patch_layout.py` needed an edit, and that is scope B's, not the
chips'.** `test_tui_patch_editor_v2.py` (the 32-hit file) passes **unedited**.

**TC-012's pass is MEANINGFUL, not vacuous** — checked rather than assumed. It asserts the stylesheet
declares exactly one `*accent*` **variable**; the chip family adds **zero** new variables (blue reuses
`$accent-calm`; green/yellow are literal hexes in the `.sev-*`/`.band-*` idiom). It also asserts the 5
`sev-*` rules are unchanged — the chip family adds none. Both properties are genuinely exercised by
this diff.

### 4.6 LLR-076.3 — "classes only" proven MECHANICALLY, not asserted

The claim *no id is added-in-place-of, renamed, moved, or re-parented* is checked against the base
rather than reasoned from the diff:

```
$ git show 3545e64:s19_app/tui/screens_directionb.py > /tmp/base_sd.py
$ diff <(grep -oE 'id="patch_[a-z_]+"' /tmp/base_sd.py            | sort -u) \
       <(grep -oE 'id="patch_[a-z_]+"' s19_app/tui/screens_directionb.py | sort -u)
(identical)
base ids:    65
current ids: 65
$ grep -c "patch-window-title" s19_app/tui/screens_directionb.py
0                                   <- the 3 title Labels are gone
```

**The id set is byte-identical.** Re-parenting is separately covered by the layout suite's
docked-sibling checks (9 passed) and the 48-id `_MUST_PRESERVE_IDS` census.

### 4.7 C-27 dual-guard — **0 frozen diff**

```
$ python -m pytest -q tests/test_engine_unchanged.py
1 passed in 0.07s
$ python -m pytest -q tests/test_tui_directionb.py -k "test_tc031 or test_tc032 or engine_unchanged"
6 passed, 168 deselected in 0.52s
$ git diff --name-only main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
      s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```

### 4.8 ruff

```
$ python -m ruff check s19_app/tui/screens_directionb.py tests/test_tui_patch_chips.py \
      tests/test_tui_patch_layout.py
All checks passed!
```

### 4.9 Full suite (`-m "not slow"`) — ONE run (C-19)

```
$ python -m pytest -q -m "not slow"
1475 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning in 956.20s (0:15:56)
$ grep -cE "^FAILED|^ERROR" full2.out
0
```

**0 failed. 0 regressions.**

⚠ **This is the SECOND run, and the first was DISCARDED — declared, not quietly dropped.** I edited a
mangled `styles.tcss` comment **while run 1 was in flight**, so its tree was not the shipped tree. A
count from a run whose inputs changed underneath it is not a measurement, and C-19 asks for ONE
complete run. Run 1 was killed and the suite re-run end-to-end against the final tree. **The number
above is from that single clean run.**

**Reconciliation — the base is MEASURED, not derived.** Inc-1b never ran the full suite (it said so),
so its passed/xfail figures could only be *computed* from Inc-1's + Inc-1b's collection claim. I
measured the real base instead, by stashing this increment's 5 files:

```
$ (base 3545e64, my changes stashed)  python -m pytest -q -m "not slow" --collect-only
1478/1498 tests collected (20 deselected)
$ (branch, restored)                  python -m pytest -q -m "not slow" --collect-only
1482/1502 tests collected (20 deselected)
$ python -m pytest -q tests/test_tui_patch_chips.py --collect-only
4 tests collected
```

| | collected | passed | skipped | xfailed |
|---|---|---|---|---|
| base `3545e64` (Inc-1b) | **1478** | 1471 | 2 | 5 |
| branch (Inc-2) | **1482** | **1475** | 2 | **5** |
| delta | **+4** = my 4 new ATs | **+4** | 0 | **0** |

1475 + 2 + 5 = 1482 ✓. **The collection delta is exactly the new AT file; xfail is UNCHANGED at 5** —
i.e. this increment marked nothing new and un-marked nothing, which is precisely the C-22 prediction
in §4.4. **Nothing else moved.**

⚠ **Honesty note on the base's `passed`/`xfailed` columns:** collected (**1478**) is measured. The
`1471 / 2 / 5` split is **inferred** from the branch run minus the 4 new ATs (which all pass and touch
no existing test). I did not spend a second 16-minute run to measure a base split that the delta
already determines — but it is inference, and it is labelled as such rather than presented as measured.

### 4.10 ⚠ Two PLAN.md recon figures are WRONG — measured, reported, not worked around

PLAN.md and LLR-076.2 state **"20 distinct Button ids across 9 docked containers"**. Measured from the
live tree at `3545e64`:

```
docked roots (.patch-docked-row/.patch-docked-group): 8
  #patch_doc_entry_buttons     Horizontal  buttons=4
  #patch_history_controls      Horizontal  buttons=2
  #patch_doc_controls          Horizontal  buttons=5
  #patch_pane_variant          Container   buttons=3
  #patch_checks_controls       Container   buttons=1
  #patch_paste_controls        Horizontal  buttons=2
  #patch_saveback_row          Container   buttons=3
  #patch_before_after_row      Container   buttons=1
TOTAL buttons under docked roots: 21
TOTAL Buttons in panel: 21
```

- **Buttons = 21, not 20.** A plain off-by-one in the recon.
- **"9 docked containers" is right but names a DIFFERENT set than it reads.** There are **8** containers
  carrying `.patch-docked-row`/`.patch-docked-group`, and **9** *button-bearing* containers (the
  immediate parents) — LLR-076.2's own symbol list is the 9. The two notions diverge because
  `#patch_pane_variant` is one docked root holding **two** button-bearing rows.

**Neither figure changes the outcome, and that is by design, not luck:** AT-076a/TC-076.2 enumerate the
live tree and never hard-code a count (the F-7/MJ-3 fold's whole point). Had they asserted "20", they
would now be RED against correct code. Reported for PLAN.md/LLR-076.2 correction (pending 1) rather
than silently absorbed.

---

## 5. Risks

| # | Risk | Sev | Disposition |
|---|---|---|---|
| **R-2-1** ⚠ | **My own RED ledger for AT-076b was false** (§4.2a) | **high** | **CLOSED** — corrected at source; the real matrix is measured and in the docstring. **The general lesson: a recorded RED is worthless unless executed.** Both probes kept, each with its measured discriminating mutation |
| **R-2-2** ⚠ | **The de-dup guard was vacuous** (`Label.renderable` does not exist at 8.2.8) (§4.2b) | **high** | **CLOSED** — reads `c.render().plain`; mutation-verified RED→GREEN. The exact false-confidence class the brief named, reached via a guessed attribute rather than CSS hiding |
| R-2-3 | C-30 leak — the chip family reaching a non-patch widget | med | **CLOSED by measurement** — §4.1 (0 non-patch snapshot drift) + AT-076b (0 matcher hits over 26 outside buttons, both regimes) + TC-076.1 (source) |
| R-2-4 | Chip height (3→1) breaks docked-row reachability (LLR-076.4 / FOLD-8 / field-audit B2) | med | **Held** — `test_tui_patch_layout.py` **9 passed** incl. AT-064a/b/c at 80×24 + 120×30. Direction is favourable: chips **reclaim** ~2 rows/row and the de-dup 1 row/window. Not the full two-axis measure — that is LLR-080.6, with the card as the real consumer (Inc-7) |
| R-2-5 | `.patch-window-title` deleted = a batch-47-HIGH-1-shaped "dead-code cleanup" | low | **Distinguished, not hand-waved.** Batch-47's defect deleted a rule that was **load-bearing** *and* its only oracle. Here the rule's **only three consumers are deleted in this same increment** (grep-verified: no other file references the class), and the behaviour it carried is **re-homed onto `border_title` and re-pinned by a mutation-verified oracle**. Cleaning up my own mess, with the guard strengthened rather than removed |
| R-2-6 | 4 `assumed` group arms resolved by my judgement, not the spec | low | Recorded in source + `_GROUP_BY_CONTAINER` with a reason each; all **5 spec-named** arms honoured verbatim. TC-076.2 fails loudly if a **new** container appears unmapped |
| R-2-7 | TC-076.3's literal "0-line diff" threshold not met | low | **Declared, not dodged** (§2). Caused by scope B; the threshold's *intent* is separately evidenced (48 ids in role, suite green) |

---

## 6. Pending items

1. **PLAN.md + LLR-076.2 recon correction** (§4.10): buttons **21, not 20**; "9 docked containers" =
   9 *button-bearing* containers (there are **8** `.patch-docked-*` roots). **Not edited from here** —
   PLAN.md is the orchestrator's artifact and `01-requirements.md` the architect's.
2. **`01-requirements.md` §6.5 Amendment A says "Deleted — none".** Amendment D now deletes the three
   title Labels + `.patch-window-title`, so Amendment A's token line is stale. Flagged for the
   architect; not edited (ownership + file cap).
3. **Snapshot regen follow-up PR** (canonical CI, batch end) — still exactly the 2 patch cells; this
   increment added **0** new ones. ⚠ **The Amendment-D de-dup has now landed BEFORE the regen**, which
   was the ordering constraint's whole point: the regen can no longer bake the duplicate into the
   baselines.
4. **Inc-1 §6 items 2-7 carry unchanged** except item 3 (**duplicate window titles — CLOSED here**):
   REQUIREMENTS.md R-TUI-075 row → Phase 6 · LLR-075.5 → Inc-7 · the batch-47 `sensor[unclosed`
   false-counterfactual carry · PLAN.md's stale baseline. **Inc-1b pending 1b-2 (`OptionList` sweep)
   also carries.**
5. **Chip `:disabled` styling** — deliberately **no rule added**: Textual's own `Button` DEFAULT_CSS
   gives `text-opacity: 0.6` on disabled and a text-based `:focus` cue, both of which survive
   `border: none`. The HLR-076 boundary ("all-disabled row → chips still render, no crash") is met by
   the framework. Recorded so a reviewer does not read the absence as an omission.

---

## 7. Suggested next task

**Inc-3 — HLR-077 check glyph folded into the `Kind` cell** (`change_service.py` `ChangeEntryRow` +
`screens_directionb.py` cell-0 span + `tests/test_tui_patch_glyphs.py`), per the US-P1 →
{P2,P3,P4,P6} → P5 order. Carries the batch's **second** wrong-answer gate pair — AT-077c (document
provenance) + AT-077e (image generation, the BL-4 branch missed at Phase 1). Watch **BL-3's free
correctness signal**: `git diff main -- tests/test_tui_patch_editor_v2.py` must stay **0 lines**; if it
does not, the fold was implemented as a column and the design — not the test — is wrong.

---

## Evidence checklist

- [x] **Tests/lint pass** — full suite **1475 passed / 0 failed / 2 skipped / 5 xfailed** from **ONE clean run** (§4.9; run 1 discarded and re-run because I edited a comment mid-flight — declared, not dropped); `test_tui_patch_chips.py` **4 passed**; C-26 census **389 passed** across 14 files in ONE invocation; snapshots **30 passed / 2 xfailed / 0 failed**; ruff **All checks passed!** on my 3 code/test files (the 1 repo-wide ruff hit is the pre-existing frozen `a2l.py:926 F841` carry — not mine, not fixable while frozen)
- [x] **RED captured FIRST / mutation-verified on every new oracle** — §4.2: Mutation A (TC-076.1 RED), Mutation B (AT-076b RED, 26 measured leaks), Mutation C (TC-46.1 RED). **Two of my own claims were falsified by these runs and corrected rather than carried**
- [x] **No secrets** — no `.env`, key, or token read or printed; fixtures are synthetic
- [x] **No destructive commands** — read-only + `Edit`/`Write` in-worktree; every mutation reverted and re-verified green; no branch switch, **no local snapshot regen** (forbidden), no commit, no push
- [x] **File count within cap** — **5** of 5 (4 modified + 1 new)
- [x] **C-27 dual-guard: 0 frozen diff** — §4.6, all three arms
- [x] **C-26 census run and reported** — §4.5, incl. **`test_tui_theme.py`, a hit PLAN.md's seeds missed**, and a check that its pass is meaningful rather than vacuous
- [x] **C-22 per-cell drift predicted + MEASURED** — §4.4; 0 new cells marked, `test_tui_snapshot.py` untouched
- [x] **C-30 leak probe measured, not reasoned** — §4.1; 0 non-patch drift ⇒ the N/A verdict is evidence
- [x] **§6.5 amendment recorded before the element was removed** — Amendment D, Before/After, in `REQUIREMENTS.md`
- [x] **Uncertainty surfaced, not hidden** — R-2-1/R-2-2 are **my own errors**, reported in full with the runs that caught them; TC-076.3's unmet literal threshold is **declared** rather than claimed; the two wrong PLAN.md figures are reported rather than absorbed; the container-vs-button class placement is explained as a **non-deviation** rather than inflated into one

---

# Inc-2b — chip family shifts to NON-VERDICT hues (operator ruling 2026-07-16)

## The defect Inc-2 shipped

Inc-2 claimed **GREEN `#54efae`** and **YELLOW `#f6ff8f`** as a *function* cue. Inc-3 concurrently
lands `_GLYPH_STYLE = {"✓": GREEN, "✗": RED, "◐": YELLOW}` as a *verdict* cue **in the same panel**.
Inside `#patch_editor_panel` that made green = "apply-path button" AND "check passed"; yellow =
"checks-group button" AND "check partial".

Inc-2 **correctly rejected** the `.sev-ok` / `.sev-warning` *classes* (frozen `color_policy.py` is
severity's source of truth) and then **reused the hue anyway**. Rejecting the class and keeping the
hue buys the coupling it was trying to avoid, with none of the traceability. That is the gap.

**Ruling: GREEN / YELLOW / RED stay RESERVED for verdicts inside this panel.** The verdict cue must
never be ambiguous — it is what tells an analyst whether a patch passed. §6.5 **Amendment F**
(batch-47: yellow ≡ warning app-wide) is one batch old and stays intact; this change protects it.

## Before / After palette

| Chip group | Before (Inc-2) | After (Inc-2b) | `insight_style` constant | Verdict hue? |
|---|---|---|---|---|
| `patch-chip-entry`  | `$accent-calm` `#91abec` | `$accent-calm` `#91abec` — **unchanged** | `HILITE` (via the `$accent-calm` var, :26) | no → no |
| `patch-chip-apply`  | `#54efae` **GREEN** | **`#b565f3`** | `PURPLE` | **YES → no** |
| `patch-chip-checks` | `#f6ff8f` **YELLOW** | **`#7dd3fc`** | `CYAN` | **YES → no** |

**No verdict hue (GREEN `#54efae` / YELLOW `#f6ff8f` / RED `#fd8383`) remains anywhere in the chip
family**, and no `sev-*` class is reused. Measured, not asserted:

```
$ awk 'NR>=924 && NR<=1000' s19_app/tui/styles.tcss | grep -nE "#54efae|#f6ff8f|#fd8383|sev-ok|sev-warning|sev-error"
NONE — no verdict hue/class in the chip family
```

**The triple is FORCED, not preferred.** Of `insight_style`'s non-verdict hues: `DGRAY` is itself a
cue (grey ≡ "not yet checked", REQUIREMENTS.md §6.5); `LBLUE #bbc8e8` is `HILITE`'s hue desaturated
(both ≈223°, indistinguishable *as a group cue*); `LABEL`/`VALUE` are body-text greys. `HILITE`
(≈223°) / `PURPLE` (≈274°) / `CYAN` (≈199°) are the only three that resolve distinctly. **No new
colour was introduced.**

⚠ **Declared, not hidden:** `CYAN #7dd3fc` is also `.sev-info` (:541). This is *not* an in-panel
collision — `PatchEditorPanel` (`screens_directionb.py:2203-3862`) mounts **no `sev-*` consumer**;
the `sev-info` status line belongs to the **separate** `AbDiffPanel` (:3863+). Verified by grep over
the panel's own line range. It is a weaker adjacency than the one being fixed (info is not a verdict,
and Inc-3's glyph set is GREEN/RED/YELLOW only), but it is real and worth recording.

## Mutation evidence (Gate 1 — AT-076a must still discriminate)

Both prior increments recorded a RED that did not discriminate. This one was **executed**, not
reasoned: `patch-chip-checks` flipped to the apply hue (`#7dd3fc` → `#b565f3`), i.e. two groups
sharing one colour — the exact regression the shift could introduce.

```
$ python -m pytest -q tests/test_tui_patch_chips.py::test_at076a_docked_buttons_are_grouped_chips
E  AssertionError: @(80, 24): the three chip groups must resolve to three DISTINCT colours;
E    got {'entry': (145, 171, 236), 'apply': (181, 101, 243), 'checks': (181, 101, 243)}
E  assert 2 == 3
1 failed in 1.49s
```

Mutation reverted; `grep -c MUTANT styles.tcss` → **0**. **AT-076a needed NO change to stay
meaningful** — it asserts three *distinct resolved RGB values*, never the literal hexes, so the
palette shift passed through it untouched. That is the oracle working as designed.

## Gates — all MEASURED

| Gate | Result |
|---|---|
| **1. AT-076a discriminates** | ✓ mutation-tested above → RED (`2 == 3`). Unchanged oracle. |
| **2. C-30 leak probe (re-run)** | ✓ **full** snapshot suite = **all 32 cells** (`test_tui_snapshot.py` is the only `snap_compare` file) → **30 passed / 2 xfailed / 0 failed**. **0 non-patch drift.** Valid because non-patch cells are unmarked strict oracles. AT-076b green at both regimes; all chip rules stay `#patch_editor_panel`-rooted (TC-076.1 green). |
| **3. C-22** | ✓ drift stayed inside the 2 already-marked cells (`patch-comfortable-80x24`, `patch-comfortable-120x30`); **0 XPASS**, **nothing new marked**, `test_tui_snapshot.py` untouched. **No local regen.** |
| **4. Four suites, ONE run** | ✓ `pytest -q tests/test_tui_patch_chips.py tests/test_tui_patch_layout.py tests/test_tui_theme.py tests/test_tui_snapshot.py` → **64 passed, 2 xfailed, 0 failed** in 112.41s. |
| **5. C-27 dual-guard + ruff** | ✓ raw `git diff main` over the frozen set = **empty**; both guard arms **7 passed**; `ruff check tests/test_tui_patch_chips.py` → **All checks passed!** |

⚠ **Confounder, declared:** the gate run executed against a tree carrying **Inc-3's uncommitted WIP**
(another agent is live in this worktree). The AT-076a colour result is purely mine. The snapshot
result is *shared* with Inc-3 — which makes the "0 non-patch drift" conclusion **stronger**, not
weaker, since it holds with both increments in the tree. The 2 patch cells were already drifting from
Inc-1 before I touched anything.

## Folded-in Inc-2 code-review nits

- **F3 [LOW] — FIXED.** `tests/test_tui_patch_chips.py`: `_in_patch_panel(node: object)` → `DOMNode`
  (`from textual.dom import DOMNode`); `_chip_rule_sets(...) -> list[object]` → `list[RuleSet]`
  (`from textual.css.model import RuleSet`). Both import paths **verified against the installed
  textual 8.2.8**, not assumed. Repo convention: hints must agree with the docstring.
- **F4 [LOW] — DELIBERATELY NOT CHANGED.** `_CHIP_CLASS in rule.selectors` substring-matches a
  hypothetical `.patch-chippy`. It **fails safe** (over-includes in a leak probe: a false positive
  would make AT-076b *stricter*, never blind). Tightening it would trade a safe-failing check for a
  cleverer one with a worse failure direction, against the brief's explicit instruction. Left as-is.

## Scope

**2 files, both in scope:** `s19_app/tui/styles.tcss`, `tests/test_tui_patch_chips.py`. Inc-3's four
WIP files (`app.py`, `screens_directionb.py`, `services/change_service.py`,
`tests/test_tui_patch_glyphs.py`) were **read-only** and remain dirty and untouched. No branch switch,
no commit, no `git stash`/`checkout`/`reset`.
