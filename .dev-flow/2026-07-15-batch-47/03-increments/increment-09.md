# Increment 9 — HIGH-1 fix: restore the section-row micro-bar fill floor

**Status:** GREEN · **Branch:** `claude/screen-upgrades-handoff-0874f9` · **Base HEAD:** `8bc4b92`
**Blocker:** final PR-QA HIGH-1 (PR #86) · **Requirement:** LLR-042.7 (restore — no §6.5 amendment needed)

---

## 1. What changed

**The defect.** Inc-3 switched `update_sections`' per-range micro-bar from `coverage_bar_cells` to
`insight_style.microbar`, and the old helper (+ its unit test) was then removed as "dead code". That
silently dropped a deliberate, documented invariant:

```python
# main, coverage_bar_cells (deleted): docstring "at least 1 so any non-empty range shows a bar"
return max(1, min(width, filled))
```

`microbar` has no floor (`insight_style.py:198`: `filled = round(clamped * width)`). At
`SECTIONS_COVERAGE_BAR_WIDTH = 8` (`app.py:613`), any range with `size/max_size < 0.0625` renders
**0 filled cells = an invisible bar** — e.g. a 64 B vector table or a 2 KB cal block beside a 512 KB
image, i.e. the normal firmware shape. The batch's own live AT
(`test_tui_directionb.py:7262`) asserts the invariant but passed only because case_02's ranges are
all frac 0.32–1.00 — the fixture structurally cannot produce the failing case.

**The fix** (operator decision, AskUserQuestion 2026-07-16: *restore the floor, opt-in, section rows only*):

- `microbar(frac, width, style="", floor=False) -> Text` — new **opt-in** `floor` parameter. When
  `floor=True` **and** `frac > 0` **and** `width > 0`, the fill is `max(1, min(width, round(...)))`.
  `frac <= 0` still yields 0 filled cells even with `floor=True` — an EMPTY range shows an empty bar;
  that distinction is the point. `floor=False` (default) preserves today's behavior **exactly**.
- `update_sections` (the section-row call site) passes `floor=True`.

**Deliberately NOT blanket-floored.** The MAC coverage strip (`validation_service.py:75`) legitimately
renders an empty bar for `0 of 2` / `0 of 0`, and the Memory-Map region rows
(`screens_directionb.py:1667`) keep the current unfloored proportion this batch. Both call sites are
untouched and pass the default `floor=False`.

## 2. Files modified

| File | Change |
|---|---|
| `s19_app/tui/insight_style.py` | `microbar` + `floor` param; docstring Args/Returns/Data Flow state the floor semantics + why it is opt-in |
| `s19_app/tui/app.py` | `update_sections` call site passes `floor=True`; docstring Data Flow cites `SECTIONS_COVERAGE_BAR_WIDTH` (8) / 6.25% |
| `tests/test_tui_insight_style.py` | NEW `test_microbar_floor_opt_in` (TC-065.2b) — ports the deleted `test_tc_042_7_coverage_bar_arithmetic_pure` semantics onto the new path |
| `tests/test_tui_directionb.py` | AT-040a gains the small-range counterfactual branch (64 B vs 512 KiB) |

4 files — within the ≤5 cap. **No frozen file touched.**

## 3. How to test

```bash
python -m pytest tests/test_tui_insight_style.py::test_microbar_floor_opt_in \
  "tests/test_tui_directionb.py::test_at040a_per_range_micro_bar_colour_and_width" -q
python -m pytest tests/test_tui_insight_style.py tests/test_tui_mac_coverage.py \
  tests/test_tui_map_big.py tests/test_tui_workspace_insight.py -q
python -m pytest tests/test_tui_directionb.py -k "at040 or tc_042" -q
python -m pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py \
  -k "test_engine or tc031 or tc032" -q          # C-27 dual-guard
python -m ruff check s19_app/tui/insight_style.py s19_app/tui/app.py \
  tests/test_tui_insight_style.py tests/test_tui_directionb.py
```

To see the defect by hand: load an image with one small range beside a large one; the small range's
third label line was `░░░░░░░░`, now `█░░░░░░░`.

## 4. Test results

**RED (assertions run BEFORE the source change) — the defect reproduced through the shipped render:**

```
>       assert "█" in small_bar, (
            f"a range far smaller than the largest (64 B vs 512 KiB) must STILL "
            f"render a visible micro-bar (>=1 filled cell); bar was {small_bar!r}"
        )
E       AssertionError: a range far smaller than the largest (64 B vs 512 KiB) must STILL render a visible micro-bar (>=1 filled cell); bar was '░░░░░░░░'
E       assert '█' in '░░░░░░░░'

tests\test_tui_directionb.py:7301: AssertionError
=========================== short test summary info ===========================
FAILED tests/test_tui_insight_style.py::test_microbar_floor_opt_in - TypeErro...
FAILED tests/test_tui_directionb.py::test_at040a_per_range_micro_bar_colour_and_width
2 failed in 2.63s
```

The rendered bar was `░░░░░░░░` — 8 empty cells, **zero filled**: the invisible bar, observed through
`#sections_list`, not a proxy. (`test_microbar_floor_opt_in` RED'd as `TypeError` — `floor` kwarg did
not exist yet.)

**GREEN (after the change) — exact counts, one run each:**

| Suite | Result |
|---|---|
| the two RED tests | **2 passed** in 2.62s |
| `tests/test_tui_insight_style.py` | **7 passed** in 0.22s |
| `tests/test_tui_directionb.py -k "at040 or tc_042"` | **19 passed**, 155 deselected in 20.88s |
| `tests/test_tui_mac_coverage.py` (**no-leak**) | **7 passed** in 11.88s |
| `tests/test_tui_map_big.py` (**no-leak**) | **8 passed** in 8.51s |
| `tests/test_tui_workspace_insight.py` | **14 passed** in 11.30s |
| C-27 dual-guard (`test_engine_unchanged.py` + `tc031` + `tc032`) | **7 passed**, 168 deselected in 0.57s — **0 frozen diffs** |
| `ruff check` (4 touched files) | **All checks passed!** |

**No-leak proof** (that the floor did not reach the coverage strip / map):

1. **Behavioral:** `test_tui_mac_coverage.py` 7/7 — the `0 of 2` / `0 of 0` strip **still renders an
   empty bar**. `test_tui_map_big.py` 8/8 — region rows keep the unfloored proportion.
2. **Arithmetic:** `test_microbar_floor_opt_in` asserts the default path directly —
   `microbar(0.00012, 8).plain.count("█") == 0` and the same with an explicit `floor=False`. The
   opt-in cannot leak without failing this.
3. **Static:** the other two call sites (`validation_service.py:75`,
   `screens_directionb.py:1667`) are not in the diff.

**C-27:** `test_tui_directionb.py` is not in the frozen TEST set (the tc032 guard passes with the
edit in place); no `_ENGINE_PATHS` module is in the diff.

## 5. Risks

- **Low. Visual only, one call site.** The floor slightly overstates ranges under 6.25% of the
  largest (they show 1 of 8 cells rather than a mathematically-rounded 0). That is the intended,
  previously-shipped trade: a visible row beats a proportionally-honest invisible one. AT-040a's
  strict `largest > smallest` monotonicity assertion still holds (verified GREEN).
- **Snapshot drift:** none expected — case_02/case_04 ranges are all ≥32% of the largest, so no
  existing baseline's fill count changes. The `-k "at040 or tc_042"` and workspace/map suites confirm
  no drift. If canonical CI disagrees, that is a snapshot-regen follow-up, not a logic change.
- `floor` is keyword-defaulted, so no existing caller signature breaks.

## 6. Pending items

- None for this increment. Batch-47 carries are unchanged.
- Deferred by operator decision: Memory-Map region rows keep no-floor **this batch** — revisit if the
  same invisible-bar report arrives for the map surface.

## 7. Suggested next task

Re-run the final PR-QA on PR #86 to clear HIGH-1, then merge. No further code change is queued.

---

## Evidence checklist

- [✓] Tests/type checks/lint pass — 7+19+7+8+14+7 passed across the suites above; `ruff check` → "All checks passed!"
- [✓] No secrets in code or output — pure render arithmetic; no I/O, no config touched.
- [✓] No destructive commands run without approval — read/edit/pytest/ruff only; no branch switch (HEAD stayed `8bc4b92`).
- [✓] File count within cap — 4 files (cap 5), per `git diff --stat`.
- [✓] Review packet attached — this document.
- [✓] C-27 dual-guard — 7 passed, 0 frozen-file diffs.
