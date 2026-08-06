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
