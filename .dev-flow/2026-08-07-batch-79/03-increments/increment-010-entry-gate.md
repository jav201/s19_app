# Inc-10 — entry gate (C-39 threshold pre-execution). **DELETION NOT STARTED.**

**Batch:** `2026-08-07-batch-79` · **Base:** `ae71bd6` (Inc-9) · **Tree:** clean, nothing staged

---

## 0 · BLUF

**Both of Inc-10's gate thresholds are now measured rather than predicted, and both confirm the spec.
The increment is deliberately not started, because it is the one increment in this batch that leaves the
suite RED by design and only `Inc-12` — in canonical CI — can make it green again.**

## 1 · Thresholds pre-executed (C-39)

A threshold that CAN be computed before the implementation exists MUST be, and its transcript recorded.
Both of Inc-10's are computable today.

| # | Threshold | Spec | Measured | Verdict |
|---|---|---|---|---|
| T-1 | The deletable CSS span | `styles.tcss:66-102` | **`:66-103`** — `#command_bar_row` opens at `:66`, `#command_palette` opens at `:104` | ✅ off by one blank line; immaterial |
| T-2 | Selectors inside that span | the "six deleted ids" of `LLR-121.1` | **exactly six**: `#command_bar_row`, `#command_bar_prompt`, `#cmdbar_project`, `#cmdbar_a2l`, `#find_input`, `#cmdbar_goto_input` | ✅ set matches |
| T-3 | Snapshot goldens that drift | **29 of 29** | **29 of 29** | ✅ confirmed |

### T-3 — and the first measurement of it was wrong, which is the point

Grepping the goldens for `command_bar` returns **0 of 29**, which reads like a refutation of the spec.
It is not: an SVG snapshot stores **rendered text**, not DOM ids. The instrument was wrong, not the claim.

Re-probed for what the bar actually *paints* — its context labels and button captions:

| token | goldens carrying it |
|---|---|
| `Project:` | **29 / 29** |
| `A2L:` | **29 / 29** |
| `Find` | **29 / 29** |
| `Go-to` | **29 / 29** |

**The spec's figure is right and my first pattern was wrong** — the third time in this batch that a bare
grep counted the wrong thing (the `.pyc` binaries inflating the Inc-8 gate; a docstring line counted as a
`set_context_labels` call site; now DOM ids searched in a pixel artefact). *An unstated grep pattern is
an unstated definition*, and the corollary this batch keeps re-learning is that **a plausible-looking
count is the dangerous outcome, not an implausible one.**

## 2 · Why the increment is not started here

`HLR-118` deletes `#command_bar_row`. Every one of the 29 snapshot goldens paints it, so the deletion
**drifts all 29 at once**, and they can only be regenerated in the canonical CI environment
(ubuntu / py3.11 / textual 8.2.8) — local regen drifts unrelated baselines. That regeneration is
`Inc-12`'s declared work, in its own PR.

So Inc-10 is the one increment whose *correct* completion still leaves 29 tests failing, with the fix
two increments away. Starting the deletion without room to land its six acceptances would leave the tree
in a state where red is expected and nobody can tell which red is which. Stopped before the first
deletion, with the measurements banked.

## 3 · What Inc-10 owes when it runs

- Delete `#command_bar_row` (`command_bar.py`) and CSS `:66-103`; **`#command_bar_slot` and
  `#command_bar` SURVIVE** to host the palette — deleting `:55-102` instead would remove the styling of
  the container that stays.
- `AT-B78-01…03` — palette **10/10**, **37** entries **re-read from the Inc-0 artifact**
  (`tests/goldens/batch78/at-b78-03-palette-actions.json`), palette still a direct child of
  `CommandBar`. **Never regenerate that artifact:** `AT-B78-03` was provably inert before Inc-0 because
  `CommandBar` is constructed as `CommandBar(self._build_palette_entries())` — observed and expected
  were the same producer, and the predicate stayed GREEN at `36 == 36` with a whole `Binding` removed.
  The temporal freeze is what breaks the circularity.
- `AT-B78-24`, `-25`, `-26` — the arms `BL-2` moved here, with per-arm verdicts at
  **80×24 / 120×30 / 132×44 / 160×40**.
- ⚠️ **`AT-B78-26`'s "≥ 1 hex row at 120×30" must inherit the PAINTED form.** §5.1 rule 1's metric
  measures the **border box** and does not clip through intermediate ancestors, so the clause would pass
  at three rows of border and **zero hex**. Use `_b78_painted_content_height`
  (`tests/test_tui_diff_screen.py:74`), which already implements the corrected metric — it exists and is
  in the file Inc-10 owns.

## 4 · Carried, still open

- The three painted-Footer-children arms (**8** @80×24 · **13** @120×30 · **15** @160×40), from Inc-6.
- Two §6.5 amendments owed upstream: `TC-B78-43`'s project half, and `LLR-119.2`'s
  `len(log_lines)` threshold — unmeasurable because `log_lines` is a `deque(maxlen=4)`.
- The palette's missing `escape`-to-close, deferred at Inc-9 **with the reasoning corrected**: the spec's
  suggested justification ("the bar is deleted anyway") is false, because the palette outlives Lane 1.
- **8 `.pyc` files tracked in git** despite `.gitignore` — operator decision owed.
