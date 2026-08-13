# Inc-6 — `HLR-126` discoverability (`LLR-126.1`)

**Batch:** `2026-08-07-batch-79` · **Base:** `829adc6` · **Files:** 2 (declared: 2)

---

## 1 · What changed

**The run list now names its own navigation keys, in the list body — and `AT-B78-32` was re-authored,
because the predicate the spec prescribed could not see 17 of the 55 lines it claimed to certify.**

Production is one constant and one list row. The substance of this increment is in the two decisions
behind them.

### The affordance rides in the BODY, not in `border_title`

`styles.tcss:1623` gives `#diff_range_list` `border: none` in the **fallback** regime. A border-hosted
affordance would therefore be present at 132×44 and **absent at 120×30** — `LLR-126.1`'s *"shall carry a
visible affordance"* unsatisfied in a supported regime, with an acceptance green at one size and inert at
the other. That is batch-78 `F-1`'s shape exactly: a regime that declares itself usable and delivers
nothing.

A body row is visible wherever the list is. It is built through the existing `_run_note_item` helper, so
it inherits `disabled=True` and `action_cursor_up` / `action_cursor_down` skip it — which is what keeps
`LLR-122.1`'s keyboard-reachable set equal to the run indices. It is placed **last** among the notes, so
it sits immediately above the runs it describes, and `first_run_position` is `len(items)`, so the run
offset follows the addition with **no second edit**. Nothing else in the tree hard-codes the note count
(`first_run_position` occurs twice, both in `screens_directionb.py`).

Rendered, measured:

```
Runs: 2
A artifacts: none
B artifacts: none
Keys: Up/Down move the selection, Enter opens
  0 0x00000000-0x0000000F changed
  1 0x00000020-0x0000002F added
```

### `AT-B78-32` is resolved from the CLASS, not from a line range

Carried from the Phase-0 premise evaluation. The spec realizes it as *"a zero-line `git diff` over
`app.py:1338-1375`"*; the block is **`app.py:1338-1392`**. This is not a drift — at `f6ff1d3` the block
was already `1338-1392` and batch-78 added zero `Binding(` lines. The range was wrong when it was
written. `screens_directionb.py:6712` carries the **correct** extent in a code comment, so the two
artifacts disagreed and the code was right.

A corrected range would not fix it: any edit **above** the block shifts it, so `1338-1392` is one
insertion away from failing the same silent way.

> ⚠️ **Correction to the Phase-0 record.** Phase 0 reported the block as carrying **31** entries. That was
> the count of lines beginning `Binding(`; the block also holds **7 bare tuples**, so it carries **38**.
> The finding is unaffected — the range still truncates the block, and 1376-1392 still holds **eight
> entries** — but the figure was partial and the frozen constant uses the correct 38.
>
> ⚠️ **Second correction, 2026-08-13 (seventh merge gate).** This paragraph said *"six real bindings"*,
> and it was the **fifth** surviving copy of that wrong figure: the true count below `:1375` is
> **eight** — 4 `Binding(` lines plus 4 bare tuples. The sweep that corrected the other four **claimed
> zero survivors and was wrong**, because its pattern matched `six real bindings` on one line and this
> occurrence is **split across a line break**. *A line-oriented sweep cannot see a wrapped phrase, and
> reporting it as exhaustive is worse than not sweeping at all.* The placement is the sharp part: the
> wrong number sat inside a block headed **"Correction"**, doing the work of justifying *"the finding
> is unaffected"*.

## 2 · Files modified

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | `_RUN_LIST_AFFORDANCE` constant + one `_run_note_item` row in `_render_run_list` |
| `tests/test_tui_diff_screen.py` | 4 nodes + 4 helpers + 2 frozen constants |

## 3 · How to test

```bash
python -m pytest tests/test_tui_diff_screen.py -k "b78_28 or b78_32 or b78_38 or b78_39" -q
```

## 4 · Test results

| Run | Result |
|---|---|
| The 4 new nodes | **6 passed** (`-k` also matches 2 siblings) |
| `tests/test_tui_diff_screen.py` (whole file) | **50 passed** in 166.71 s — was 46 |
| C-26 reverse-census observers (`test_tui_diff_compare_realpath.py`, `test_tui_directionb.py`) | **189 passed** in 273.26 s |
| C-27 frozen dual guard | `test_engine_unchanged.py` **1 passed** · `tc032` **3 passed** — BOTH run, not one |
| `ruff check` (both files) | **All checks passed** |

**Ledger, re-derived rather than carried.** A temporary worktree at the batch base `829adc6` collects
**2653** (full form); the tree now collects **2657** (full) / **2636** (lean, 21 slow deselected).
**+4 — exactly the four new nodes.** batch-78's `HANDOFF` states 2647 without naming its form, so the two
figures are **not comparable** and reconciling against it would have manufactured a discrepancy; the
baseline was re-measured instead.

### Counterfactuals (C-40) — executed, applied-checked, restored by hash

**(a) `AT-B78-32`, and this is the increment's headline evidence.** One binding inserted **in the block
tail** (line 1392, inside 1376-1392). Applied-check: `BINDINGS` 38 → 39, `MUTANT` present.

| Predicate, same mutation, same tree | Verdict |
|---|---|
| **Re-authored `AT-B78-32`** (class-resolved) | 🔴 **RED** — `observed 39`, expected 38 |
| **The spec's own predicate** — `git diff` over `app.py:1338-1375` | 🟢 **GREEN** — changed lines `[1392]`, none inside the range |

A binding was added to the App `BINDINGS` block and the prescribed guard reports *untouched*. Restored;
`sha256` returned to `0e0fd179…f39af5` and `git status` shows `app.py` clean.

**(b) `AT-B78-28` clause 1.** The affordance row removed — the deliverable-absent state. The node failed
**on `assert affordance in list_text`**, its own clause, not on an import or a setup error. Restored from
a byte copy (**not** `git checkout` — the file carries uncommitted work); `sha256` back to
`094e8f4d…59605`.

**(c) `AT-B78-28`'s negative co-assertion — it failed for real, on its first run, and that is recorded
rather than smoothed.** The section-boundary helper stripped `│` (U+2502) while the panel paints `▏`
(U+258F), so no line was ever blank, the whole panel read as **one** section, and the three positive
clauses were green against *every binding in the application*. The negative co-assertion is what caught
it. **Without that clause the node would have shipped vacuous**, which is precisely why `HLR-126`'s C-40
note requires it.

**(d) A vacuity found in my own predicate and closed before the gate.** Clause 1 reads the constant and
asserts it is in the rendered text — so an author who emptied `_RUN_LIST_AFFORDANCE` to `""` would make
`"" in list_text` trivially true and the affordance could vanish with the node green. The oracle is now
guarded against the **requirement** (*names its navigation keys* → `Up`, `Down`, `Enter`, non-empty),
not against its own current wording.

## 5 · Risks

1. **The affordance does not exist before the first Compare** — it rides with the runs it describes.
   Stated, not hidden: `TC-B78-38` asserts the discoverability surface is still *safe* in that state
   (panel mounts and paints, chip set unchanged). If `LLR-126.1` is meant to bind pre-comparison too,
   that is a requirement amendment, not a code fix.
2. The painted-Footer-children arms (**8** @80×24 · **13** @120×30 · **15** @160×40) are **not** asserted
   here. The spec labels them a PIN at the first two sizes and a GATE only at 160×40. **Carried to the
   Inc-6 gate as an open item** rather than silently dropped.
3. `_b79_painted_text` reads `app.screen._compositor.render_strips()` — a private API, matching the
   existing precedent in this module (`:872`).

## 6 · Pending

- The three painted-Footer-children arms (risk 2).
- Two stale spec citations found in passing, neither blocking: `action_show_help_panel` is at
  `app.py:5877`, cited `:5836`; the `AT-B78-32` range (fixed here).

## 7 · Suggested next task

**Inc-7 — `HLR-120`**, context onto both surfaces. *Lane 1 opens.* 4 files. Watch `test_tui_app.py`: it
monkeypatches `update_project_labels`, so it goes **blind, not red** — its green is not evidence.
