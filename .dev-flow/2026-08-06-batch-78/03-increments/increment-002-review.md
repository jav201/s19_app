# Code Review — batch-78 Increment 002 (HLR-122, the selectable run list)

> **Reviewer:** independent `code-reviewer` (did not author the increment)
> **Diff reviewed:** `d771ab8..297990c` — `s19_app/tui/screens_directionb.py` (+57/−20),
> `tests/test_tui_diff_screen.py` (+760/−25), `tests/test_tui_diff_compare_realpath.py` (+21/−3)
> **Authority:** `01-requirements.md` §7 (Inc-2 row), §5.1, §5.3, HLR-122 / LLR-122.1–122.3
> **Method:** every claim re-executed from a clean `git archive 297990c` export in the
> reviewer's scratchpad. The live repo tree was **never modified** — no `git add`, no
> `git stash`, no source edit. Verified: `git status --short -- s19_app/ tests/` is empty
> and `sha256(screens_directionb.py) = f74869cd773ca2f8…` (the packet's own fixed-tree value).

---

## BLUF

**BLOCK.** One HIGH finding: **the second press of the shipped Compare button raises
`textual._node_list.DuplicateIds` and leaves the run list unusable.** It is a regression
introduced by this increment — the pre-change tree survives the same drive — and **not one
of the 352 nodes in the gate run can see it, because no node drives Compare twice.**
The increment's own R-1 identified the mechanism (`ListView.clear()` is asynchronous while
`extend()` is not) and then drew the wrong consequence from it.

Everything else in the packet held up under re-execution, including the parts most likely
to have been self-reported optimistically: **five counterfactuals reproduced to the sha**,
`test_tc029`'s rewrite genuinely reddens, and the `test_tc029` / `AT-B78-18` split is real.

| Severity | Count |
|---|---|
| **HIGH** | **1** |
| MEDIUM | 2 |
| LOW | 3 |

---

## Findings

### F1 — the second Compare crashes on duplicate widget ids, and nothing tests it **[HIGH — BLOCKS]**

- **What:** `_render_run_list` calls `listing.clear()` and then, in the same synchronous
  turn, `listing.extend(items)`. `ListView.clear()` does `self.query("ListView > ListItem").remove()`,
  which routes to `App._prune` — and `_prune` only **posts a `Prune()` message** per node
  (`textual/app.py:4370-4415`). The old `ListItem`s are therefore **still registered** when
  `extend()` mounts the new ones, which carry the **same DOM ids** (`diff_run_0`, `diff_run_1`, …).
  Textual raises on the collision.

- **Where:** `s19_app/tui/screens_directionb.py:6989-7038` — specifically
  `listing.clear()` (`:6989`), `id=f"diff_run_{index}"` (`:7000`), `listing.extend(items)`
  and `listing.index = …` (`:7037-7038`).

- **Reproduction** (reviewer probe, `git archive 297990c`, shipped Compare button pressed twice,
  `compare_images` substituted at the app's import site exactly as `_b78_drive_compare` does):

  ```
  compare #1  [_render_run_list total=6 self._runs=6]
    settled: children=9 entries=6 notes=3 index=3 hl=diff_run_0 -highlight=['diff_run_0']

  compare #2  [_render_run_list total=4 self._runs=4]
  textual._node_list.DuplicateIds: Tried to insert a widget with ID 'diff_run_0',
    but a widget already exists with that ID (ListItem(id='diff_run_0',
    classes='diff-run-entry')); ensure all child widgets have a unique ID.

    settled: children=4 entries=1 notes=3 index=None hl=<none> -highlight=[]
    keyboard walk after re-compare: [None, None, None, None, None, None, None, None, None]
  ```

  The panel is left holding three note rows and one orphaned entry, `index is None`, and
  **every run is unreachable by keyboard** — the exact negation of HLR-122.

- **It is a regression, not pre-existing.** The same drive on `d771ab8`:

  ```
  PRE-CHANGE after compare #1: runs= 6  text head= ['Runs: 6']
  PRE-CHANGE after compare #2: runs= 4  text head= ['Runs: 4']
  PRE-CHANGE second compare completed with NO exception
  ```

  `Static.update()` is idempotent and mints no ids; the `ListView` swap introduces both.

- **A second, independent limb — removing the ids is not sufficient.** With
  `id=f"diff_run_{index}"` deleted (crash gone), the re-render is still wrong:

  ```
  EXP compare#1: children=9 entries=6 index=3 hl_pos=3 highlight=[3]
  EXP compare#2: children=7 entries=4 index=3 hl_pos=3 highlight=[]   <- NO row is highlighted
  ```

  `listing.index = 3` is assigned while the stale rows are still in `_nodes`, so
  `watch_index` sets `highlighted=True` on the **old** row at position 3, which is then
  pruned. The index value does not change (3 → 3), so `watch_index` never fires again and
  the surviving row never gains `-highlight`. **HLR-122's "the entry holding the selection
  shall be visually distinguished" is violated on every re-render** — the clause
  `AT-B78-17` exists to protect.

- **Why it matters:** changing the A/B `Select` and pressing Compare again is the panel's
  primary workflow. In `run_test` the exception propagates; in the shipped app it is a
  handler exception in `on_ab_diff_panel_compare_requested`. Either way the operator loses
  the panel. Severity is not reduced by Inc-4: Inc-4 adds a selection handler, it does not
  touch the rebuild path.

- **Why no node caught it:** every AT and TC in this increment — and every pre-existing
  consumer — drives `render_comparison` exactly **once**. `AT-B78-15…19`, `TC-B78-17/18/19/21/22/47/48`
  and both `test_tui_diff_compare_realpath.py` drivers all press Compare a single time. The
  packet's R-1 names the async-clear mechanism, then concludes *"a future caller that reads
  the list synchronously inside `render_comparison` would see stale rows … no such caller
  exists."* The hazard is not a stale **read**; it is a stale **mount**, and the caller that
  triggers it is the shipped Compare button.

- **Suggested fix.** The rebuild must not mount new rows while the old ones are still
  registered. Three routes, with what I actually verified:

  | Route | Verified | Note |
  |---|---|---|
  | **A — defer the fill** `listing.call_after_refresh(_fill)` wrapping `extend` + `index` | ✅ fixes **both** limbs (`compare#2: children=7 entries=4 index=3 highlight=[3]`) | ❌ **breaks 2 nodes as-is** — `test_tui_diff_compare_realpath.py`'s single-`pause()` drivers read an empty column (`2 failed, 26 passed`). Do not adopt without resolving that; adding a pause to a test to accommodate production timing is the wrong direction. |
  | **B — await the removal** make `_render_run_list` / `render_comparison` coroutines, `await listing.clear()` then `await listing.extend(items)`, then set the index | not executed | Correct by construction and keeps the ids. Costs an `async def on_ab_diff_panel_compare_requested` in `app.py` — a file §7 does **not** give Inc-2. Needs an operator scope call. |
  | **C — stop reusing identity + set the highlight explicitly** drop `id=f"diff_run_{index}"` (carry the index by position among `.diff-run-entry`, or as a plain attribute — no subclass, so C12 still cannot bite) **and** set `highlighted` on the new row rather than relying on `watch_index` | limb 1 verified (crash gone); limb 2 **not** verified | Narrowest file-wise, but re-points `_b78_run_index` and 8 nodes. |

  Whichever route is taken, **the increment must gain a node that presses Compare twice**
  and asserts, after the second: the entry count equals the second fixture's run count,
  `index` is the first run, and exactly one row carries `-highlight`. Without it this
  defect class is invisible again at Inc-4.

---

### F2 — the mouse half of the reachability set-equality is unverified **[MEDIUM]**

- **What:** the packet's design rationale claims *"a click on a disabled `ListItem` never
  posts `_ChildClicked` — so the keyboard- **and** mouse-reachable sets are exactly the run
  indices."* The keyboard half is genuinely two-directional: `AT-B78-15` asserts
  `None not in reached`, so a stop on a note row fails the node, and M1 reddens it. **The
  mouse half has no such clause.** `AT-B78-16` iterates `listing.query(_B78_RUN_ENTRY)` and
  clicks only those, so `reached` can never contain a note by construction — the node cannot
  distinguish "notes are unclickable" from "notes were never clicked".

- **Where:** `tests/test_tui_diff_screen.py:1249-1268` (`for item in list(listing.query(_B78_RUN_ENTRY))`).

- **Evidence it is a real hole, not a hypothetical:** M1 (`disabled True → False` — the
  mutation that makes note rows selectable) reddens `AT-B78-15`, `TC-B78-47` and
  `TC-B78-19` and leaves **`AT-B78-16` GREEN**. Reproduced independently:

  ```
  ### M1  note rows disabled True -> False: applied sha 91eb057258045624
  ###   3 failed, 19 passed
  ###   RED  test_at_b78_15_every_run_reachable_by_keyboard
  ###   RED  test_tc_b78_19_single_run_is_selectable
  ###   RED  test_tc_b78_47_arrows_at_the_ends_do_not_wrap
  ```

- **The underlying mechanism is CORRECT** — I verified it two ways, so this is a coverage
  finding, not a bug. `ListItem._on_click` posts `_ChildClicked` unconditionally
  (`textual/widgets/_list_item.py:29-30`); the block is one layer up, in
  `Widget.check_message_enabled` (`textual/widget.py:4669-4678`), which refuses mouse
  events when `_self_or_ancestors_disabled`. Executed against the shipped surface:

  ```
  PROBE notes: 3  index before: 3
    clicked a note row -> index now 3  hl id diff_run_0
    clicked a note row -> index now 3  hl id diff_run_0
    clicked a note row -> index now 3  hl id diff_run_0
  ```

  Worth recording separately: `ListView._on_list_item__child_clicked` has **no** disabled
  check of its own (`self.index = self._nodes.index(event.item)`), so the whole guarantee
  rests on that one framework layer — which is exactly why it deserves a node.

- **Suggested fix:** in `AT-B78-16`, after the entry walk, click each `.diff-run-note` row
  and assert the selection is unchanged:

  ```python
  before = _b78_run_index(listing.highlighted_child)
  for note in list(listing.query(_B78_RUN_NOTE)):
      note.scroll_visible(animate=False); await pilot.pause()
      await pilot.click(note); await pilot.pause()
  # ... assert alongside the set-equality clause:
  assert _b78_run_index(listing.highlighted_child) == before, (
      "a header / notice row must not be mouse-selectable; the selection moved "
      f"from {before} to {...}"
  )
  ```

  That makes M1 redden `AT-B78-16` too, and turns the packet's stated mouse claim into a
  checked property.

---

### F3 — the mutation harness's "the sha moved" limb is vacuous, which sharpens C-78-viii **[MEDIUM]**

- **What:** §4.5 rests every applied-check on *"the substituted token is present **and** the
  file's sha-256 differs from the fixed tree"*. The second limb does not discriminate,
  because the harness writes the mutated file with **LF** line endings while the fixed tree
  on disk is **CRLF**. A rewrite that substituted nothing at all would still move the sha.

- **Evidence (this is arithmetic, not inference).** The packet's fixed-tree sha is the
  CRLF file; every mutated sha it records is the LF file. My scratchpad export is LF
  throughout, and my mutated shas came out **identical to the packet's** while my baseline
  did not:

  | | packet | reviewer (LF export) |
  |---|---|---|
  | fixed `screens_directionb.py` | `f74869cd773ca2f8` (**CRLF**, confirmed on the live tree) | `5db6803477edcd39` (LF) |
  | M4 mutated | `49ac444003f9a9c3` | `49ac444003f9a9c3` ✅ |
  | M5 mutated | `335c1717b4cf504b` | `335c1717b4cf504b` ✅ |
  | M7 mutated | `a20f6da89b76795c` | `a20f6da89b76795c` ✅ |
  | M1 mutated | `91eb057258045624` | `91eb057258045624` ✅ |

  Four exact matches against a baseline that does **not** match is only possible if the
  harness normalised line endings on write. So `sha_mutated != sha_fixed` was guaranteed
  before the substitution was even attempted.

- **Why it matters:** this is the mechanical reason F-6 was able to happen, and it means
  **C-78-viii as proposed is necessary but not sufficient.** Comparing against the previous
  mutation's sha catches a *repeat* of the same no-op, but the *first* no-op still passes
  both limbs. The general form worth carrying is stronger:

  > An applied-check must assert the **old** token is gone **and** the **new** token is
  > present **and** the sha is one not seen in this session — and the baseline it compares
  > against must be produced by the **same writer**, or the sha limb is measuring the
  > writer, not the mutation.

- **This does not invalidate the results.** I re-executed five mutations with that stronger
  harness (old-token-absent + new-token-present + sha-unseen, restore verified by hash) and
  the per-node verdicts reproduce the packet's table exactly — see "What I verified as
  sound" below. The finding is about the *evidence discipline*, which the batch is
  explicitly trying to harden.

---

### F4 — `AT-B78-15` puts its presence co-assertion ahead of its subject clause **[LOW]**

`tests/test_tui_diff_screen.py:1214-1226` asserts `n_entries == len(runs)` before
`None not in reached` and the set equality. Under M8 (`self._runs[:1]`) it therefore fails
on *"the list must present one selectable entry per displayed run; 1 entries for 6 runs"*
and the reachability clause never runs — structurally the same masking that C-78-vii was
minted to forbid, in a node written in the same increment. It is **not** a defect: the
node's declared mutation is M1, which reddens the walk clause directly (verified), and the
count clause is itself a normative HLR-122 clause rather than a fixture self-check. But
C-78-vii as worded (*"the subject clause must be asserted FIRST"*) does not hold here, and
if that carry is going to be encoded it should say which clause is the subject when a node
has two normative ones. No change required this increment.

### F5 — five of the twelve new nodes carry no executed counterfactual **[LOW]**

`TC-B78-17`, `TC-B78-18`, `TC-B78-19`, `TC-B78-21` and `TC-B78-22` do not appear as columns
in §4.5's table; the mutation runs selected 8 nodes (`… 11 deselected`, `6 failed, 2 passed`).
Running the mutations over the **whole module** — same mutations, no extra work — shows
three of the five are in fact falsifiable and the evidence is simply unrecorded:

```
M1  -> RED  test_tc_b78_19_single_run_is_selectable
M8  -> RED  test_tc_b78_18_exactly_cap_runs_shows_no_notice
       RED  test_tc_b78_21_zero_length_run_is_selectable
       RED  test_tc022_render_shows_runs_and_hex_windows      (pre-existing node, incidental)
```

Recommend dropping the `-k` selection from the mutation harness and widening the table;
`TC-B78-17` (0 runs) and `TC-B78-22` (no comparison) remain undischarged, which is honest
for negative-boundary nodes but should be stated as such rather than omitted.

### F6 — the phantom-docstring claim is worded more strongly than it is true **[LOW]**

Removing `on_data_table_row_selected` from `_render_run_windows`'s **Used by** list is
correct and in scope (it is a false statement about the method this increment restructures).
But the packet says *"that symbol has **0 definitions** in the module"*, which reads as
"the symbol does not exist". It does exist — `s19_app/tui/app.py:7345`,
`S19TuiApp.on_data_table_row_selected` — it simply is not a caller of
`_render_run_windows` (`grep -n "_render_run_windows" s19_app/` returns only the definition
and the single literal-`0` call site at `:6924`). The accurate claim is "not a caller",
not "not defined". Cosmetic; worth fixing so the postmortem record is exact.

---

## What I verified as sound

Everything below was re-executed by the reviewer, not read.

**The counterfactuals are real, and the packet's table reproduces.** Five mutations applied
to an isolated export with a stricter applied-check (old token absent, new token present,
sha unseen this session), restored and hash-verified after each:

| Mutation | Reviewer per-node RED set (whole module) | Matches packet |
|---|---|---|
| M4 `DISPLAY_MAX_RUNS 128 → 100000` | `test_at_b78_18`, `test_tc029` | ✅ **§7's declared Inc-2 gate discharged** |
| M1 `disabled True → False` | `test_at_b78_15`, `test_tc_b78_47`, `test_tc_b78_19` | ✅ (+1 unrecorded, F5) |
| M5 `total_runs len(runs) → len(capped)` | `test_at_b78_18`, `test_tc029` | ✅ |
| M7 `note markup False → True` | `test_tc_b78_48` | ✅ |
| M8 `entries from self._runs[:1]` | 6 declared + `test_tc_b78_18`, `test_tc_b78_21`, `test_tc022` | ✅ |

- **`test_tc029`'s rewrite is a genuine gate.** Its fixture is `_B78_OVER_CAP_RUNS = 200`, a
  literal independent of the constant; its expectation `n_stored < total` reads nothing from
  `AbDiffPanel.DISPLAY_MAX_RUNS`; the constant-quoting guard is **last**. Under M4 it
  reddens on *"the panel must store strictly fewer runs than the comparison produced;
  stored 200 of 200"* — the capping clause, not the guard. The pre-batch form was inert.
- **`test_tc029` and `AT-B78-18` are genuinely distinct observables.** Under M8, `test_tc029`
  stays **GREEN** while `AT-B78-18` reddens — reproduced. The model/view split is real, not
  asserted.
- **`D = 0` and G2 is unaffected.** `AT-TC-REGISTRY.jsonl:638` — `TC-029` is `LIVE` and its
  node path `tests/test_tui_diff_screen.py::test_tc029_display_caps_bound_on_screen_runs`
  is byte-unchanged. The rewrite is in place; no id was deleted or minted.
- **Guard-placement sweep (C-78-vii).** I checked every node in the diff that quotes a
  constant or carries a structural census. `test_tc029` — guard last ✅. `AT-B78-18` —
  guard last ✅. `AT-B78-19` — behavioural clauses first, census last ✅. `TC-B78-18` reads
  the constant as its **fixture** only, which is the correct form for a boundary node, and
  its expectation (`"showing" not in range_text`) is constant-free ✅. **No sibling AT in
  this diff still has the guard first.** Both of the author's C-78-vii instances are real
  and both are fixed.
- **`AT-B78-19`'s PIN → GATE upgrade holds.** `_b78_focus_run_list` blurs, asserts
  `app.focused is None`, focuses, and asserts `app.focused is listing` — the precondition
  the pre-change `Static` could not satisfy. The declared M6 mutation reddens the node on
  its declared clause (*"'k' must still open the Legend…"*), per the packet's transcript
  with a live-widget binding probe, which is the right applied-check for a `BINDINGS`
  mutation given Textual merges bindings at class creation. I did not re-run M6 (it is the
  one mutation whose applied-check is independently strong).
- **F-3 confirmed: Inc-1's carry into Inc-2 is FALSE, and `styles.tcss` needed no edit.**
  `styles.tcss:1523-1533` declares only `width / height / border / background / color /
  padding / margin-right` on the `#diff_range_list, #diff_hex_a, #diff_hex_b` group — no
  `overflow`, and the highlight rules live on `ListItem`, which an id selector on the
  `ListView` cannot reach. **Corroborated by hash:** the live `styles.tcss` is
  `449fb6501f0ea292…`, exactly the packet's value, so M2/M3b were applied and restored
  cleanly and the file is untouched by the increment. 3 files, not §7's planned 4 — under
  the cap either way.
- **C12 cannot bite.** `git diff … | grep '^+class'` returns nothing; `_run_note_item` is a
  static factory returning a stock `ListItem`. No widget subclass, so no `_nodes` /
  `_context` shadowing surface.
- **C-26 reverse grep reproduces.** `grep -rc diff_range_list tests/*.py` →
  `test_tui_diff_compare_realpath.py:5`, `test_tui_diff_screen.py:3`,
  `test_tui_directionb.py:1` = **9 hits / 3 modules**. The third is
  `tests/test_tui_directionb.py:5711` `"range_list": bool(screen.query("#diff_range_list"))`
  — type-agnostic, correctly left untouched. The re-point in
  `test_tui_diff_compare_realpath.py` is necessary and correct: a `ListView` renders nothing
  of its own, so the old `str(widget.render())` form would have returned `""` and the `in`
  assertions would have silently stopped checking anything. Good catch by the author.
- **Snapshots.** `git status --short tests/__snapshots__/` is empty — no golden was
  regenerated locally (C9 respected). The single expected drift cell is a test failure, not
  a file change.
- **Ledger arithmetic and node counts.** `git show d771ab8:tests/test_tui_diff_screen.py |
  grep -c '^def test_'` = **10**; at `297990c` = **22** → `A = 12`.
  `test_tui_diff_compare_realpath.py` = **6 → 6**. `2612 − 0 + 12 = 2624` ✅.
  I re-ran 2 of the 12 gate modules on the restored tree: **`28 passed in 39.48s`**
  (`test_tui_diff_screen.py` 22 + `test_tui_diff_compare_realpath.py` 6), consistent with
  §4.1/§4.2. **The `352 passed in 475.36s` figure is a self-report I did not re-execute**
  (per instruction); the 12-module list matches the C-26 sweep it claims to be derived from.
- **The boundary was respected.** `grep -n "_render_run_windows" s19_app/tui/screens_directionb.py`
  → definition at `:7041`, docstring at `:6913`, and exactly one call site,
  `self._render_run_windows(0)` at `:6924`, with the literal `0`. No selection handler,
  no `on(ListView.Highlighted)`, no `on(ListView.Selected)`. LLR-123.1 did not creep in.
- **Simplicity / reuse.** The change is minimal and idiomatic: one import, one `compose`
  line, `_render_run_list` rewritten in place, one new 3-line private factory with one
  caller. No speculative abstraction, no premature generalisation, no duplicated helper —
  `_b78_run_list_text` is shared between the two test modules rather than copied. Rendering
  the note rows `markup=False` at construction instead of `escape()`-ing at the call site is
  the right call and strictly tightens C-17: the sink cannot lose the escape. `TC-B78-48`
  pins it and M7 reddens it on both the exception and the assertion limb.
- **Conventions.** Docstrings carry the repo's `Summary / Args / Returns / Dependencies`
  sections; node names carry their spec ids; the `# ORDER IS NORMATIVE` comments explain
  *why* the assertion order is what it is, which is exactly the kind of intent a future
  editor needs. Style matches the surrounding module.

---

## Verdict

- [ ] OK to advance
- [ ] OK with the listed fixes applied first
- [x] **Block — F1 must be fixed before advancing**

**Blocking:** F1 only. F2 should land in the same fix (it is four lines in a node that is
already open) because the two together are the increment's whole "reachable set" claim.
F3–F6 are recommendations; F3 belongs in the batch carry list beside C-78-viii, which it
strengthens rather than contradicts.

**Scope note for the operator:** the cleanest fix for F1 (route B) needs `async def
on_ab_diff_panel_compare_requested` in `app.py`, which §7's file × increment map assigns to
Inc-5/7/9/11, not Inc-2. Inc-2 currently sits at 3 of 5 files, so adding `app.py` stays
within the cap — but it crosses the plan's file map and is the operator's call, not the
implementer's. Route C avoids `app.py` entirely at the cost of re-pointing `_b78_run_index`.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Diff read in full | ✓ | `screens_directionb.py` `:6722-7057`; `test_tui_diff_screen.py` `:150-250, :494-560, :879-1490`; `test_tui_diff_compare_realpath.py` `:32-120, :265-290` |
| Correctness pass (edge / None / error paths) | ✓ | F1 (re-render, executed both limbs); empty-run path `listing.index = None` verified via `TC-B78-17`; `_apply_display_caps`'s `and capped` guarantees a non-empty capped list, so `first_run_position` is never orphaned |
| Simplicity pass (no premature abstraction) | ✓ | one import, one compose line, one 3-line factory with one caller; no new class, no speculative parameter |
| Reuse / duplication checked | ✓ | `_b78_run_list_text` shared across both test modules rather than copied; `_diff_result`'s new `summary` kwarg reuses the existing fixture instead of minting a second one; no existing util re-implemented |
| Tests reviewed for intent, not behaviour | ✓ | 5 counterfactuals re-executed with a stricter applied-check; `test_tc029` rewrite confirmed to redden on its clause; F2 records the one clause that encodes no discriminating negative |
| Verdict explicit | ✓ | **Block** — F1 |
| Live repo tree unmodified | ✓ | all work in an isolated `git archive 297990c` export; `git status --short -- s19_app/ tests/` empty; `sha256(screens_directionb.py)` = `f74869cd773ca2f8…`, `sha256(styles.tcss)` = `449fb6501f0ea292…`; the parallel session's `prototypes/memmap2.*` untouched |

---
---

# Code Review — Inc-2 **RE-GATE** (round 2)

> **Range:** `297990c..c59e794` (`f9b9629` the fix, `c59e794` the spec reconciliation)
> **Round 1 verdict was BLOCK on F1.** This round re-executes the fix, re-measures
> the two open questions the coordinator raised, and reports one new HIGH.
> Same method: isolated `git archive` exports (`c59e794` and, as a control arm,
> `297990c`). Live tree untouched — `git status --short -- s19_app/ tests/` empty,
> `sha256(screens_directionb.py) = 667cd9c5b2254ff4…`.

## BLUF — **BLOCK**, on a new finding, not on the old one

**F1 is properly fixed and F2 is closed.** Route B works, the regression node is a real
gate, and `CF-B` reddens it alone exactly as reported.

**F3 is WITHDRAWN — my mechanism was wrong and the author's inverse reading is right.**

**R-11 is not flakiness. It is causally connected, it is reproducible on demand, and it is
14 nodes wide, not one.** `set_status(…, "sev-ok")` and `self._diff_last_result = result`
are both written on the lines *after* the new `await panel.render_comparison(…)`, while
`Pilot.pause()` waits for **message-queue idleness**, not for an in-flight handler
coroutine to finish. The fix is correct; the drivers that observe it are not.

| Round-1 finding | Status |
|---|---|
| **F1** (HIGH) second Compare crashes | ✅ **CLOSED** — verified three ways |
| **F2** (MEDIUM) mouse negative unverified | ✅ **CLOSED** — M1 now reddens `AT-B78-16` |
| **F3** (MEDIUM) sha limb vacuous via LF/CRLF | ❌ **WITHDRAWN — mechanism measured FALSE** |
| **F4** (LOW) `AT-B78-15` clause order | ✅ carried, and C-78-vii sharpened correctly |
| **F5** (LOW) five nodes undischarged | ✅ **CLOSED** — `-k` dropped, 3 of 5 now discharged |
| **F6** (LOW) "0 definitions" over-read | ✅ **CLOSED** — corrected to "not a caller" |

| New this round | Severity |
|---|---|
| **F7** — the async change made 14 of 29 diff nodes scheduling-dependent | **HIGH — blocks** |
| **F8** — §7, the declared authority, was never reconciled; the C-21 discharge asserts a consistency that does not exist | MEDIUM |

**HIGH 1 · MEDIUM 1** this round.

---

## R-11 — VERDICT: causally connected. Do not withdraw the hypothesis; upgrade it.

### The causal link is visible in the source before any measurement

`s19_app/tui/app.py:4836-4854` — the awaited call, and then:

```python
await panel.render_comparison(...)          # NEW suspension point
...
    panel.set_status(f"Compared … {len(result.runs)} runs.", "sev-ok")   # <- 016_4 asserts this
self._diff_last_result = result                                          # <- the driver's reached_display_path
```

`tests/test_tui_diff_compare_realpath.py:_drive_compare` presses the button, does **one**
`pilot.pause()`, then reads `sev-ok` and `_diff_last_result`. **Every one of those reads is
of state written after the new await.** Pre-fix, `render_comparison` was synchronous, so
those lines executed inside the same dispatch and one pause was deterministic.

`test_at_016_4` **does** reach the newly-awaited path: it is the valid-image case, so
`result.refused` is False and control passes the early `return`. Its sibling
`test_at_016_3` asserts `sev-error`, which is set in the refusal branch **before** the
await — and it is one of the nodes that never fails under perturbation. That contrast is
the discriminator: the exposed nodes are exactly the ones whose observable is written after
the await.

### Reproduced on demand, with the reported signature

`Pilot.pause()` → `_wait_for_screen()` + `wait_for_idle(0)`. A handler suspended on
`AwaitRemove` has already **dequeued** its message, so the pump can report idle while the
coroutine is parked. Pure yields are absorbed (`await asyncio.sleep(0)` x1 and x20: 4/4 and
6/6 green) because idle-detection drains callback turns. A **timed** suspension — which is
what CPU contention on a 740-second 13-module run produces — is not:

```
CF-R11  +20 ms suspension inside the awaited path, driver's ONE pause, 4 iterations:
  iter 0: RACE LOST {'sev_ok': False, 'sev_err': False, 'last_result_set': False,
                     'status': 'Select two images and press Compare.', 'rows': 5}
  iter 1: RACE LOST {… 'status': 'Select two images and press Compare.', 'rows': 0}
  iter 3: RACE LOST {… 'status': 'Select two images and press Compare.', 'rows': 5}
  -> 1/4 green; 3 would FAIL test_at_016_4
```

`'Select two images and press Compare.'` **is the placeholder the gate reported.** The
signature matches exactly.

### Control arm — the variable is the coroutine, not the delay

The identical 20 ms delay inserted into the **pre-fix synchronous** `_render_run_list`
(export of `297990c`, where `render_comparison` is not a coroutine):

```
### CONTROL (pre-fix 297990c, SYNC handler): +20ms inside _render_run_list
extra_pauses=0: 4/4 had sev-ok after the driver's pause  -> 0 would FAIL
```

Same perturbation, same driver, same assertion: **4/4 green synchronous, 1/4 green
asynchronous.** A synchronous handler cannot be parked mid-way, so ordering is guaranteed
regardless of how slow it is. The async change is the cause.

---

## F7 — the fix made 14 of 29 diff nodes scheduling-dependent **[HIGH — BLOCKS]**

- **What:** R-11 is not confined to `test_at_016_4`. Every driver that presses Compare and
  reads post-await state behind a single `pause()` is now racy. Under the same 20 ms
  suspension, across both diff modules:

  ```
  14 failed, 15 passed in 49.24s
  FAILED test_tc021_compare_routes_through_service
  FAILED test_tc029_display_caps_bound_on_screen_runs
  FAILED test_at_b78_16_every_run_reachable_by_mouse
  FAILED test_at_b78_18_display_caps_and_notice_survive
  FAILED test_at_b78_19_app_keys_survive_run_list_focus
  FAILED test_tc_b78_17_empty_comparison_has_no_selectable_entry
  FAILED test_tc_b78_18_exactly_cap_runs_shows_no_notice
  FAILED test_tc_b78_21_zero_length_run_is_selectable
  FAILED test_tc_b78_48_hostile_artifact_summary_renders_verbatim
  FAILED test_tc_b78_49_a_second_compare_rebuilds_the_list      <- the new regression node
  FAILED test_at_016_1 / test_at_016_2 / test_at_016_4
  FAILED test_compare_hex_windows_render_the_differing_bytes
  ```

  The gate's `1 failed, 414 passed` is the visible tip of a 14-node surface, and it did not
  reproduce in six attempts because the margin is *usually* enough — which is precisely
  what makes it dangerous.

- **Why it is HIGH and not a nuisance:** the lost-race state is **the un-rendered panel**.
  A node whose observable is a *presence* fails loudly (that is why `test_at_016_4` was
  seen). A node whose observable is an **absence** passes **vacuously** — it asserts that
  something is not there while looking at a panel that has not rendered yet.
  `test_tc_b78_18`'s `assert "showing" not in range_text` is exactly that shape; it is
  saved only by its sibling `assert painted == total` in the same node, which is an
  accident of drafting, not a control. That is the false-confidence class this project
  calls its dominant defect.

- **Where:** `tests/test_tui_diff_compare_realpath.py:96-118` (`_drive_compare`) and
  `:283-290` (`_drive_compare_hex`), each with a single `await pilot.pause()` after
  `press()`; `tests/test_tui_diff_screen.py:222-226` (`_b78_drive_compare`) and `:295-301`
  (`test_tc021`), each having just **lost** their second pause;
  `tests/test_tui_diff_screen.py:1543-1555` (`TC-B78-49`, two single-pause presses).

- **On the two deleted pauses — the provenance is right, the inference is not.** I verified
  both were introduced *at Inc-2* (neither exists at `d771ab8`), so they were indeed
  compensating for the un-awaited mount and removing them is defensible. But "padding
  becoming unnecessary is evidence the fix is structural" does not follow: the same
  measurement that says they are unnecessary in a quiet run says the whole module is now
  scheduling-sensitive. They were green before removal and green after, in both cases
  because the race was won.

- **Padding is not the answer, and I measured that too.** One extra pause absorbs both a
  20 ms and a 200 ms suspension (4/4 green each). So adding pauses back would work in
  practice — but it buys *margin*, not *determinism*, and the coordinator already ruled
  against that direction. The observation must become deterministic instead.

- **Suggested fix — wait on the handler's own completion, not on idleness.** A shared
  driver helper, used by both modules:

  ```python
  async def _settle_compare(app, pilot, *, max_turns: int = 20) -> None:
      """Wait for the compare HANDLER to complete, not for the queue to go idle.

      `Pilot.pause()` waits for message-queue idleness. A handler suspended on
      `await panel.render_comparison(...)` has already dequeued its message, so
      pause can return before `sev-ok` / `_diff_last_result` / the run list have
      been written. Poll the handler's own terminal write instead.
      """
      for _ in range(max_turns):
          await pilot.pause()
          if app._diff_compare_seq == expected:      # see caveat
              return
      raise AssertionError("the compare handler did not complete within 20 turns")
  ```

  **Caveat, stated because it changes the shape of the fix:** `_diff_last_result` is the
  obvious flag but it is written **only on the non-refused branch**, so the refusal drivers
  (`test_at_016_2`, `test_at_016_3`) would hang on it. The clean form is a monotonic
  counter incremented as the last statement of *both* branches of
  `on_ab_diff_panel_compare_requested`, or a `CompareRendered` message the driver awaits —
  either is a one-line addition to `app.py`, a file Inc-2 now legitimately owns. Whichever
  is chosen, **`TC-B78-49` must use it too**: the node that exists to prove the second
  Compare rebuilds the list is itself in the exposed set.

- **A counterfactual is owed at the re-gate:** with the helper in place, re-run the 20 ms
  perturbation census. The target is **0 failed**, not 14. That measurement is the
  discharge; a green quiet run is not, and is exactly the evidence that let this through.

---

## F8 — §7 was never reconciled, and the C-21 discharge asserts otherwise **[MEDIUM]**

- **What:** the entire `01-requirements.md` change in this range is **one hunk, in §5.7**:

  ```
  $ git diff 297990c..c59e794 -- …/01-requirements.md | grep '^@@'
  @@ -766,7 +766,13 @@
  ```

  §7 — which the gate brief calls **the authority** — is untouched and now contradicts what
  shipped, at `c59e794`:

  | §7 says | Reality |
  |---|---|
  | Inc-2 Files: `screens_directionb.py`, **`styles.tcss`**, `tests/test_tui_diff_screen.py`, `tests/test_tui_diff_compare_realpath.py` **(4)** | `styles.tcss` was **never edited** (sha `449fb6501f0ea292…`, unchanged since round 1); the real set is **5**, adding `app.py` and `prototypes/cmdbar_a2bdiff.tui_prototype.py` |
  | `\| app.py \| 5, 7, 9, 11 \|` | `app.py` was edited at **Inc-2** |
  | `\| styles.tcss \| 1, 2, 5, 7, 10 \|` | Inc-2 does not edit it |
  | (no row) | `prototypes/cmdbar_a2bdiff.tui_prototype.py` is a tracked production-adjacent caller, now edited at Inc-2 |

- **Why it matters:** the §5.7 amendment states *"§7's file map is unchanged apart from the
  `app.py` cell ratified for Inc-2 … and `prototypes/…`"* — but that ratification exists
  only as prose **inside §5.7**; the cell itself was never changed. §7's map is the
  artefact the plan's own "strictly sequential, no two increments in flight" rule is
  enforced from, and Inc-4/5/6/7 all edit `screens_directionb.py` and `app.py`. A planner
  reading §7 at Inc-4 will not learn that `app.py` is already in Inc-2's blast radius. The
  `styles.tcss` cell is the **second** time this has been flagged — the round-1 packet's
  own Pending item 3 asked for it and it is still there.

- **Suggested fix:** three cell edits in §7 — Inc-2's Files cell to the real 5-file set
  (drop `styles.tcss`, add `app.py` and the prototype); `app.py` row to `2, 5, 7, 9, 11`;
  `styles.tcss` row to `1, 5, 7, 10`; add a `prototypes/cmdbar_a2bdiff.tui_prototype.py`
  row naming Inc-2. Then the C-21 discharge is true as written.

- **What I did verify about C-21:** the claim *"no other increment's AT/TC allocation
  moves"* is **correct** — the single hunk touches no other increment's ids, and the §5.7
  arithmetic is right on its own convention (32 live AT + 49 TC = 81, matching the prior
  32 + 48 = 80).

---

## F3 — WITHDRAWN. My mechanism was measured FALSE.

Re-measured through my own pipeline, as asked:

```
live worktree (c59e794)            crlf= 7114 bare_lf=    0 sha=667cd9c5b2254ff4
my rev2 export (git archive)       crlf= 7114 bare_lf=    0 sha=667cd9c5b2254ff4
my rev  export (297990c)           crlf=    0 bare_lf= 7097 sha=5db6803477edcd39

no-op read_text -> write_text round trip: before=667cd9c5b2254ff4
                                          after =667cd9c5b2254ff4  identical=True
```

**The author is right and I was wrong.** `Path.write_text(newline=None)` emits `os.linesep`
= CRLF on this host, so a no-op round trip through the harness's exact path is
**byte-identical** — the sha limb was **not** vacuous for the reason I gave.

**The actual explanation of my four matching shas is the inverse, exactly as proposed:**
my round-1 *baseline* was LF, not the harness's mutated files. I had restored that baseline
with a raw `git show 297990c:… > file` redirect, which writes the blob unmodified (LF);
my mutated files went through `Path.write_text` and came out CRLF, matching the author's
CRLF mutated files. `git archive` is not the culprit either — it produced CRLF for `rev2`
and my `rev` was LF only because I overwrote it. **The inference was mine, and the
contaminated baseline was mine.**

**What survives, and it is narrower than what I filed.** The limb the original harness
lacked was not the sha limb — it was **"the OLD token is absent after the write"**. That is
the limb that fails on a label-vs-value patch, and it is the one the implemented remedy
adds. The carry should record that and **must not** record an LF/CRLF mechanism: it would
send the next reader to a normalisation problem this host does not have. My round-1 §F3
paragraph beginning *"because the harness writes the mutated file with LF"* should be
struck from any carry text.

I used the corrected form in this round's harness (old-token-absent + new-token-present +
sha-unseen + restore-by-sha) and it behaved correctly on both mutations.

---

## What I verified as sound this round

**F1 — CLOSED, three independent ways.**

1. **Three consecutive comparisons with different run counts**, driven through the shipped
   button on the `c59e794` export:

   ```
   compare #1 (fixture  7 runs): entries= 7 index=3 -highlight=['diff_run_0']
   compare #2 (fixture  3 runs): entries= 3 index=3 -highlight=['diff_run_0']
   compare #3 (fixture 11 runs): entries=11 index=3 -highlight=['diff_run_0']
   walk after 3rd: diff_run_0 … diff_run_10          (all 11 reachable)
   ```

   No `DuplicateIds`; the entry count tracks each fixture; **exactly one** `-highlight`
   after every re-render — the second limb of F1, which removing the ids alone did not fix.

2. **`CF-B` reddens `TC-B78-49` and nothing else** — reproduced exactly as reported:

   ```
   ### CF-B  route-B awaits removed: applied sha 6b9d91cf61aa0410 != fixed 667cd9c5b2254ff4
   ###   ['1 failed, 28 passed in 63.45s']
   ###   RED  test_tc_b78_49_a_second_compare_rebuilds_the_list
   ```

   Both awaits are load-bearing and the node is a genuine gate, not a co-passenger.

3. **Route B is minimal in `app.py`.** The whole `app.py` change is two hunks: `def` to
   `async def` on the handler, and `panel.render_comparison(` to `await panel.render_comparison(`
   plus a 3-line comment. **Nothing crept in** while a file outside the increment's plan
   was open.

**`TC-B78-49` is a well-built node.** Different run counts on purpose, with the reason
asserted in the fixture guard; the state is captured **before** any key press, so it
describes what the second Compare left behind rather than what the walk created; it pins to
the top so index 0 is *reached*, not inherited. Its docstring records the crash, the
mechanism and the "removing the ids is not sufficient" limb.

**F2 — CLOSED.** `M1` (`disabled True -> False`) now reddens `AT-B78-16`, where in round 1
it stayed green:

```
### M1: 5 failed, 24 passed
###   RED  test_at_b78_15 / test_at_b78_16 / test_tc_b78_19 / test_tc_b78_47 / test_tc_b78_49
```

The added clause is the right one — it clicks every `.diff-run-note` row and asserts the
selection is unchanged — and the comment correctly records that the guarantee rests on the
single `Widget.check_message_enabled` layer.

**F4 / F5 / F6.** F4 carried, and **C-78-vii's amendment is the right sharpening**: *"when
a node carries two normative clauses, the subject is the one the node's declared mutation
targets."* That resolves the ambiguity I raised without weakening the rule. F5 closed by
dropping `-k`; `TC-B78-17` and `TC-B78-22` remain undischarged **and are stated as such**,
which is the honest disposition for negative-boundary nodes. F6 closed — the packet now
reads *"not a caller"*.

**Ledger and bookkeeping.** `git show c59e794:tests/test_tui_diff_screen.py | grep -c '^def test_'`
= **23** (from 10) so `A = 13`; realpath **6 -> 6**. `2612 − 0 + 13 = 2625` ✅.
Baseline on the export: **`29 passed in 64.85s`**, zero unexpected reds.
`git status --short tests/__snapshots__/` empty — snapshot drift is still the single
`[diff-comfortable-120x30]` cell, no golden regenerated.

**The fifth-file call was right, and the sweep is complete.**
`prototypes/cmdbar_a2bdiff.tui_prototype.py` **is** tracked (`git ls-files --error-unmatch`
succeeds), its `_drive_diff` **is** `async def` so the added `await` is legal, and a
repo-wide sweep finds no other caller of `render_comparison` outside `tests/` and
`screens_directionb.py`. Two apparent extra hits are non-source: `build/lib/…` (an
untracked stale build copy) and `.claude/worktrees/c3-d2-triage/…` (a different branch's
worktree). Neither is a missed caller — noting them so a later sweep does not re-raise them.

---

## Verdict

- [ ] OK to advance
- [ ] OK with the listed fixes applied first
- [x] **Block — F7 must be fixed before advancing**

**F1 and F2 are closed; F3 is withdrawn as my error.** The block is new and narrow: the
production fix is right, and the harness that observes it must stop depending on winning a
race. F8 should land in the same pass — it is four cell edits and it makes the C-21
discharge true.

**Discharge for the next re-gate:** the 20 ms perturbation census re-run to **0 failed**
(currently 14), plus `CF-B` still reddening `TC-B78-49` alone.

## Evidence checklist — round 2

| Item | ✓/✗ | Evidence |
|---|---|---|
| Fix diff read in full | ✓ | `app.py:4779, 4833-4841`; `screens_directionb.py:6880, 6911-6930, 6969, 6992-7031`; `test_tui_diff_screen.py` −2 pauses, `AT-B78-16` +note-click clause, `TC-B78-49`; `prototypes/cmdbar_a2bdiff.tui_prototype.py:474` |
| F1 re-verified, not accepted on report | ✓ | 3-compare transcript + `CF-B` reddening `TC-B78-49` alone + `app.py` minimality |
| R-11 causally determined | ✓ | source ordering + 20 ms reproduction with the reported placeholder signature + sync-handler control arm 4/4 vs async 1/4 |
| Blast radius measured, not assumed | ✓ | 14 failed / 15 passed under perturbation; `test_at_016_3` (pre-await branch) immune |
| F3 re-measured on my own pipeline | ✓ | round-trip byte-identical; `rev2` export CRLF; **withdrawn** |
| Correctness pass on the new code | ✓ | both awaits load-bearing (`CF-B`); `listing.index` now assigned against a settled `_nodes`; no new class, C12 still inert |
| Simplicity / reuse | ✓ | route B is 2 production lines + docstrings; no helper duplicated; `TC-B78-49` reuses `_diff_result` / `_b78_run_index` / `_b78_focus_run_list` |
| Verdict explicit | ✓ | **Block** — F7 |
| Live repo tree unmodified | ✓ | `git status --short -- s19_app/ tests/` empty; `sha256 = 667cd9c5b2254ff4…`; all mutation work in isolated exports, restored and hash-verified; `prototypes/memmap2.*` untouched |

---
---

# Code Review — Inc-2 **FINAL RE-GATE** (round 3)

> **Range:** `438fda3..7d034db` (F7 fix) and `c59e794..438fda3` (F8, §7 reconciliation)
> Isolated `git archive 7d034db` export; live tree untouched —
> `git status --short -- s19_app/ tests/` empty.

## BLUF — **PASS.** Advance Inc-2.

**F7 and F8 are closed, and I re-executed both rather than reading them.** The completion
signal is correct, total, and — the part that matters — **invariant under a 10× increase in
the perturbation**, which is the property an extra `pause()` cannot have. The control arm
genuinely reddens, so the discharge is a measurement and not an artefact of a census that
perturbs nothing.

No HIGH. No MEDIUM. **One LOW**, non-blocking, plus a correction to a statement I made in
round 1.

| Finding | Status |
|---|---|
| **F1** (HIGH, r1) second Compare crashes | ✅ CLOSED (r2) |
| **F2** (MEDIUM, r1) mouse negative unverified | ✅ CLOSED (r2) |
| **F3** (MEDIUM, r1) sha limb vacuous | ❌ WITHDRAWN — my error (r2) |
| **F4/F5/F6** (LOW, r1) | ✅ carried / closed (r2) |
| **F7** (HIGH, r2) 14-node scheduling race | ✅ **CLOSED — three arms re-run, plus a fourth I added** |
| **F8** (MEDIUM, r2) §7 never reconciled | ✅ **CLOSED — four cells right, false discharge recorded beside its correction** |
| **F9** (LOW, **new**) the wait helper is duplicated across the two modules | ⚠️ recommendation only |

---

## 1. The census, re-run independently — four arms

Applied to my own export, perturbation inserted at the same point, all files restored and
hash-verified afterwards.

| Arm | Perturbation | Completion wait | Result |
|---|---|---|---|
| **A — control** | 20 ms | **removed** | 🔴 **15 failed, 14 passed** |
| **B — discharge** | 20 ms | in place | ✅ **29 passed, 0 failed** |
| **C — determinism** | **200 ms (10×)** | in place | ✅ **29 passed, 0 failed** |
| **D — my addition:** the gate modules that press Compare and were **not** wired | 20 ms **and** 200 ms | n/a | ✅ **18 passed, 0 failed** (both) |

**Arm A is the one you flagged, and it genuinely reddens.** Stripping the wait back to
`press(); await pilot.pause()` — leaving every call site intact, so only the wait changes —
puts 15 of 29 nodes red. A census that perturbs nothing would read `0 failed` in arm A too;
this one does not.

**Arm C is the load-bearing result and it reproduces.** 10× the suspension, still `0
failed`. That is the qualitative difference from padding: I measured in round 2 that one
extra `pause()` absorbs 20 ms *and* 200 ms, so a pause-based fix would also have looked
clean at 10× — but only because the threshold moved. Here nothing is waiting on time at
all, so the arm is not a threshold test; it is a demonstration that the observable is no
longer a function of scheduling.

## 2. The 12 vs 14 — resolved. **Neither count is wrong; the set is a distribution.**

I ran arm A **three times** on one host, one tree, one command:

```
ARM A run 1: 15 failed, 14 passed
ARM A run 2: 15 failed, 14 passed
ARM A run 3: 14 failed, 15 passed

symmetric difference between two consecutive repeats: ['test_tc021_compare_routes_through_service']
```

**My own census disagrees with itself by one node between consecutive runs of identical
code.** Round 2 (on `c59e794`) gave 14; round 3 gives 15, 15, 14. The author's 12 is a
fourth sample of the same distribution.

That is the informative part you asked for: **the failing set is scheduling-determined, not
structurally determined.** A 20 ms suspension does not partition the nodes into "exposed"
and "safe" — it puts every direct-read node near a threshold, and the ones with a little
more incidental margin (an extra key press, a smaller fixture) flip run to run. `test_tc021`
is the marginal node in my samples.

**The invariant that carries the verdict is not the count.** It is: **control ≫ 0 in every
sample (12, 14, 15, 15, 14) and discharge == 0 in every sample.** A count that varied while
the *discharge* varied would be a problem; a count that varies while the discharge is
identically zero at 20 ms and 200 ms is the signature of a fix that removed the dependency
rather than moving the threshold. **No reconciliation is owed — the difference should be
recorded as "the census reports a sample, not a set," which is worth carrying.**

## 3. The `finally` really covers all four exits — driven, not reasoned

```
PROBE success    -> returned  generation 0->1  bumped=True  status='Compared A.s19 vs B.s19: 1 runs.'
PROBE refusal    -> returned  generation 0->1  bumped=True  status='Compare refused: reviewer probe: refused'
PROBE exception  -> raised RuntimeError('induced'); generation now 1  bumped=True
```

- **Refusal returns and does not hang.** This is the exit `_diff_last_result` would have
  hung on, and the module drives it (`test_at_016_3`). Your caveat carried correctly, and
  the author's statement of *why* — *a completion signal conditional on the happy path
  turns a failure into a hang* — is the right generalisation.
- **Exception bumps the counter and then propagates.** Driven two ways: through the real
  app (an induced failure inside the awaited render surfaces as a `RuntimeError`, not a
  25-second timeout) and directly against the wrapper with `_apply_compare_request` patched
  to raise, which shows `generation 0 -> 1` *before* the exception leaves. **No exit hangs.**

## 4. All nine drivers are wired — and the two that are not are provably immune

`grep -rn 'diff_compare_button' tests/` finds **11** press sites. **9 are wired**
(7 in `test_tui_diff_screen.py`, 2 in `test_tui_diff_compare_realpath.py`) — that is the
count you reported, and it is exact.

The other two — `tests/test_report_off_ui_thread.py:185` and
`tests/test_tui_report_filter_surface.py:757` — are **not** wired, and both are in the gate
suite, so I treated this as the silent hole you named and went after it. **It is not one,
and the mechanism is decidable rather than statistical:**

`MessagePump._process_messages_loop` **awaits** `_dispatch_message` for each message, and
`_on_message` does `await invoke(method, message)`. Handlers are therefore **serialized** —
a second message cannot be dispatched until the first handler coroutine returns. So:

- the exposed sites are exactly those where the **test coroutine**, which runs *outside* the
  pump, reads state directly after `pause()`;
- the two unwired sites press **another button** next, and that message is queued behind the
  compare handler. It cannot overtake it.

Measured, not assumed: **arm D is `18 passed, 0 failed` at 20 ms and again at 200 ms.**
(`_flush(pilot, count=12)` in the filter-surface module and `workers.wait_for_complete()`
in the off-UI-thread module add further margin on top.) **The wiring is complete and the
boundary is principled, not lucky.**

## 5. The extraction is a pure rename — proved by the diff itself

```
$ git diff --numstat 438fda3..7d034db -- s19_app/tui/app.py
38      0       s19_app/tui/app.py
```

**Zero deleted lines.** The new wrapper reuses the existing
`async def on_ab_diff_panel_compare_requested(\n    self, event: ...)` header and the
original `) -> None:` plus its docstring now belong to `_apply_compare_request`, so the
whole change is additive. No line of compare logic was re-indented, moved or edited — that
is not a claim I have to trust, it is what a 38/0 numstat means. This is a genuinely elegant
way to make a rename reviewable, and worth carrying as a technique.

## 6. Everything else on the list

| Item | Verified |
|---|---|
| `TC-B78-17` / `TC-B78-22` still undischarged | ✅ not upgraded — packet A-table row *"Still undischarged, still stated as such. Not upgraded."* and §B.5 give the reason per node. `TC-B78-22` never presses Compare, so it is not even in the race's reach — correctly noted |
| Ledger unchanged at **2625** | ✅ `grep -c '^def test_'` at `7d034db`: diff_screen **23**, realpath **6** — identical to `c59e794`. F7 added no node |
| Snapshot drift | ✅ `git status --short tests/__snapshots__/` empty; still the single `[diff-comfortable-120x30]` cell |
| §7's four cells | ✅ Inc-2 row now `screens_directionb.py`, **`app.py`**, both test modules, **`prototypes/cmdbar_a2bdiff.tui_prototype.py` (5)**, ATs column carries **`TC-B78-49`**, gate cell carries the CF-B discharge; `styles.tcss \| 1, 5, 7, 10` with `~~2~~` and the measured reason; `app.py \| **2**, 5, 7, 9, 11` with the ratification reason; new prototype row |
| The false C-21 discharge is recorded, not overwritten | ✅ the original sentence is struck and replaced, and a ⚠️ block **states that it was false, why, and who committed it**. It goes further than I asked by finding the root cause — `enum.py`'s tracked terms do not include §7's file-map cells — and carrying that as `C-78-xi`. That is the right escalation: the control that should have caught it is now the thing being fixed |
| Full gate suite `415 passed, 1 xfailed in 665.24s` | ⚠️ **self-report, not re-executed** (per the standing instruction on long suites). Corroborated by the 47 nodes I did execute: 29 (both diff modules, arms B and C) + 18 (arm D) |
| HEAD moving between rounds | noted, no action — your commits, and the author has consistently and correctly said it has never run `git commit` |

---

## F9 — the wait helper is duplicated across the two modules **[LOW]**

- **What:** `_b78_press_compare` (`tests/test_tui_diff_screen.py:207`) and `_press_compare`
  (`tests/test_tui_diff_compare_realpath.py:47`) are two near-identical implementations of
  the same wait. The same is true of `_b78_run_list_text` (`:185`) and `_run_list_text`
  (`:75`), added at Inc-2.

- **Why it is worth a line:** F7's defect class was *precisely* "one driver left on the old
  wait." The structural mitigation for that class is **one** helper, not two. With two, a
  future correction to the wait — a different signal, a different bound, a diagnostic — has
  to be applied twice, and the census would only look at whichever module the author was
  editing. `tests/conftest.py` already exists and already holds plain shared helper
  functions (`make_large_s19`, `_s19_data_record`, … — 1077 lines, not fixtures only), so
  there is an established home and no new convention would be invented.

- **Not blocking, and not for this increment.** Both copies are correct today, the
  docstrings are legitimately module-specific, and moving test helpers between modules is
  outside Inc-2's charter. Recommend it as a batch-close item rather than a change here.

- **Correction to round 1, since I hold the author to this standard.** In my round-1
  "verified as sound" list I wrote that `_b78_run_list_text` *"is shared between the two
  test modules rather than copied."* **That was wrong** — they were two separate helpers
  from the start, and I did not check before praising it. The reuse assessment in round 1
  should read: the C-38 re-point was correct and necessary, but it was implemented as a
  duplicated helper, not a shared one.

---

## Verdict

- [x] **OK to advance**
- [ ] OK with the listed fixes applied first
- [ ] Block

**Inc-2 passes, and passes on a clean verdict rather than an exhausted one.** I re-ran the
control arm because a discharge is only as good as the arm that proves the census can go
red, and it went red 15/15/14 across three runs. Arm C reproduces at 10×. The completion
signal is total across all four handler exits, driven not reasoned. The driver wiring is
complete and its boundary is explained by handler serialization rather than by luck. §7 is
actually reconciled and the false discharge is recorded beside its correction with the root
cause escalated.

**F9 is a recommendation for batch close, not a gate condition.**

**Two things from this increment are worth more than the fix.** The first is the shape of
the F7 remedy: the wait was put in the **driver** and made to *raise* on timeout, so the
un-rendered state is unreachable by any node built on it — **including nodes not yet
written**. That is a control, not a patch, and `C-78-xiii` states it correctly. The second
is `C-78-xi`: the §7 miss was traced to `enum.py`'s tracked-term set rather than to the
person who made it. Both are the batch's pattern — the defect was never in the shipped
code, and the fix landed one layer above where the defect showed.

## Evidence checklist — round 3

| Item | ✓/✗ | Evidence |
|---|---|---|
| Fix diff read in full | ✓ | `app.py:1508-1523, 4793-4818`; `test_tui_diff_screen.py:207-240` + 7 call sites; `test_tui_diff_compare_realpath.py:47-73` + 2 call sites |
| Census re-run, control included | ✓ | arm A 15/15/14 failed · arm B 0 · arm C (10×) 0 · arm D (unwired modules) 0 at 20 ms and 200 ms |
| 12-vs-14 settled | ✓ | three arm-A repeats on one host disagree by one node; the set is a sample, the discharge is invariant |
| `finally` coverage driven | ✓ | success / refusal / exception, all bump the counter; no exit hangs; exception path verified twice |
| All press sites accounted for | ✓ | 11 found, 9 wired, 2 immune by handler serialization (`message_pump.py:634-707`), measured at 20 ms and 200 ms |
| Extraction is a pure rename | ✓ | `git diff --numstat` = `38 0` — zero deletions |
| Correctness pass on the new code | ✓ | `before` read prior to `press()`; bounded 500-turn loop with a named failure; per-press wait in `TC-B78-49`'s double drive; counter bumped after the full handler body |
| Simplicity / reuse | ✓ with F9 | 5 production lines + one counter; helper duplicated across modules — recorded as LOW |
| Verdict explicit | ✓ | **Pass** |
| Live repo tree unmodified | ✓ | `git status --short -- s19_app/ tests/` empty; all perturbation in an isolated export, restored and hash-verified per arm; `prototypes/memmap2.*` untouched |
