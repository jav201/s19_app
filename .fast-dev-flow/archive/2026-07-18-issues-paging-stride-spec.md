# fast-dev-flow spec — Issues paging stride matches the mount cap (B1)

- **Date:** 2026-07-18
- **Batch:** issues-paging-stride (backlog B1, field-audit P0)
- **Flow:** /fast-dev-flow
- **Language:** English
- **Run mode / merge:** Autonomous through self-merge (operator-authorized for this run of prior-backlog items; per-batch). Surface any HIGH finding / scope creep.
- **Status:** Phase A — spec

---

## 1. Objective

Make the Issues screen's PgUp/PgDn actually page through every issue. Today they are a no-op on any
list of ≤200 issues, and issues at indices 40–199 of every page are **permanently unreachable**.

## 2. Root cause (grounded, reproduction confirmed)

The grouped Issues panel mounts at most `_GROUP_DISPLAY_MAX = 40` non-virtualized `IssueRow` widgets
(a deliberate DoS/perf cap — `issues_view.py:52`). But the paging **stride** is
`validation_issues_page_size = 200` (`app.py:1117`), used in four sites:
`update_validation_issues_view` (summary), `_render_validation_issues_groups` (the `filtered[start:end]`
window fed to the panel), and `action_validation_issues_page_next/prev`.

Because the stride (200) exceeds the mount cap (40):
- `_render_validation_issues_groups` slices a 200-wide window but `render_groups` mounts only its
  first 40 and truncates → rows 40–199 of the window are shown as a truncation note, never mounted.
- `page_next` advances `_validation_issues_window_start` by 200. For total ≤ 200, `max_start = 0`, so
  it clamps → **no-op**. For total > 200, page 2 starts at index 200 → rows 40–199 are skipped on
  every page. Either way, indices 40–199 are unreachable.

## 3. The fix

Tie the Issues paging stride to the mount cap so every mounted-then-paged row is reachable, and keep
it robust to the (currently fixed) `validation_issues_page_size`:

```python
def _issues_page_size(self) -> int:
    # The grouped Issues panel mounts at most _GROUP_DISPLAY_MAX rows (a DoS cap),
    # so the paging stride must not exceed it or rows past the cap become
    # unreachable (B1). Honour a smaller configured size; never a larger one.
    return min(_GROUP_DISPLAY_MAX, self._clamp_viewer_page_size(self.validation_issues_page_size))
```

Use `_issues_page_size()` in all four sites in place of
`self._clamp_viewer_page_size(self.validation_issues_page_size)`. Import `_GROUP_DISPLAY_MAX` from
`issues_view`.

## 4. Acceptance criteria (observable)

- **AC-1 (reachability — the real fix)** — With `_GROUP_DISPLAY_MAX + 5` issues, after one
  `action_validation_issues_page_next` the window start advances to `_GROUP_DISPLAY_MAX` and the
  summary reports the second page (`rows 41-45/45`), so the last 5 issues become the mounted window.
  (Pre-fix: page_next is a no-op, window stays at 0, those 5 are unreachable.)
- **AC-2 (no-op eliminated)** — With `_GROUP_DISPLAY_MAX + 5` issues at window 0, `page_next` changes
  `_validation_issues_window_start` (was unchanged pre-fix).
- **AC-3 (stride == cap)** — `_issues_page_size()` returns `_GROUP_DISPLAY_MAX` when
  `validation_issues_page_size` is its default (200), and honours a smaller value (e.g. 25 → 25).
- **AC-4 (paging math)** — `page_next`/`page_prev` advance/rewind `_validation_issues_window_start`
  by `_GROUP_DISPLAY_MAX` and clamp at the last page start.
- **AC-5** — Full gate `pytest -q -m "not slow"` green; no frozen engine test file modified.

## 5. Security flags

Scanned. No auth/secrets/external/PII/destructive-DB/network patterns. `security_required: **false**`.
The change only *tightens* how many widgets mount per page (stays ≤ the existing DoS cap).

## 6. Files (blast radius)

**Increment 1 — fix + tests (2 files):**
1. `s19_app/tui/app.py` — import `_GROUP_DISPLAY_MAX`, add `_issues_page_size()`, use it in the four
   issues paging sites.
2. `tests/test_tui_app.py` — correct the two tests that pinned the stride==configurable-size contract
   (they set 150/100 and asserted window math only, never reachability) to the mount-cap stride, and
   **add the AC-1 reachability test** the old pair never had.

**Increment 2 — docs (1 file):**
3. `REQUIREMENTS.md` — note the Issues paging stride is bounded by the mount cap.

**Frozen, preserved unchanged:** all `_ENGINE_TEST_FILES` (this is a TUI-layer change; no engine edit).

## 7. Pending / deferred

- The rest of the prior backlog (B3 A2L "two extra chars", discoverability gap, Flow Builder rail-8),
  plus the a2l P-1b / P-2 carries.

## 8. Batch status

| Current phase | Phase A — spec written |
