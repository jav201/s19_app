# Increment 003 — US-062 (B-12) Entropy viewer pagination + sort

> Batch-37 · Inc-3 · Scope = **US-062 only** (HLR-062 / LLR-062.1/.2/.3).
> Base = batch-37 working tree carrying Inc-1 + Inc-2 (untouched). Ledger base = 1373.

## 1. What changed

Made the entropy-viewer modal (`EntropyViewerScreen`) **page** through windows
beyond the 512 cap and **sort** the display by address or entropy, with a single
shared `(sort, page, row) → window` remap so the jump-list dismiss lands on the
correct window under any sort + page. The former hard truncation (first 512
windows, drop-the-rest + a `#entropy_truncated` label) is replaced by a
FIXED-512 **per-page render budget** and a `page P/Q` position indicator — every
window is now reachable.

- **Fixed-512 paging (LLR-062.1):** page size is **FIXED at 512**
  (`ENTROPY_MAX_ROWS`, read as a module global at render time so tests may
  `monkeypatch` it). Strip + jump list draw from the SAME page slice
  `display[page*512:(page+1)*512]`. `#entropy_page_prev`/`#entropy_page_next`
  buttons + `PgUp`/`PgDn` bindings move the clamped page index; a
  `#entropy_page_indicator` shows `page P/Q`. The 512-row page renders into the
  scrolling `#entropy_body`.
- **Sort (LLR-062.2):** a `#entropy_sort_button` (+ `s` binding) toggles a
  DISPLAY COPY between `address` (ascending `start`) and `entropy` (descending,
  ascending-`start` tie-break). `self._windows` (the `compute_entropy` snapshot)
  is never mutated. Toggling sort resets the page to 0.
- **Shared remap helper (LLR-062.2, Q-04):** `_window_for_row(row)` is the one
  `(sort, page, row) → window` resolver used by `on_list_view_selected`,
  preserving the `0 <= row < len(page slice)` bound (S-03). (Same helper the
  future US-063 click path will reuse.)
- **Truncation redefinition (Q-02):** both `test_tc036_5_cost_cap_and_truncation`
  and `test_tc036_5_truncation_fires_on_either_cap` were **redefined in place**
  (net 0 nodes) to assert the `page P/Q` indicator — the 512 cap still bounds
  per-page render, but the tail is reachable by paging, not dropped.

`compute_entropy` / `entropy_service` untouched — presentation-only.

## 2. Files modified (4)

| File | Change |
|---|---|
| `s19_app/tui/screens.py` | `EntropyViewerScreen`: `BINDINGS` (PgUp/PgDn/`s`), `_page_size`/`_page_count`/`_clamp_page`/`_display_windows`/`_page_slice`/`_window_for_row`/`_jump_item`/`_page_indicator_text`/`_sort_button_label`/`_refresh_view`/`_set_page`/`_sync_page_buttons`, `action_page_next`/`action_page_prev`/`action_toggle_sort`; `compose` now renders `#entropy_controls`; `on_list_view_selected` routes through `_window_for_row`; `on_button_pressed` handles the 3 new buttons; removed `TRUNCATED_TEXT`. `Binding` import added. |
| `s19_app/tui/styles.tcss` | `#entropy_controls` (height:auto) + `#entropy_controls Button` + `.entropy-page-indicator` rules. |
| `tests/test_tui_entropy_viewer.py` | +AT-062a, +AT-062b, +TC-324, +TC-325; redefined the 2 truncation nodes in place. |
| `tests/test_tui_snapshot.py` | `_batch37_entropy_drift_marks` → `xfail(strict=False)` on both entropy cells. |

`app.py`, `screens_directionb.py`, `test_before_after_report.py`,
`test_tui_patch_editor_v2.py` (Inc-1/Inc-2) — **not touched** by Inc-3.

## 3. How to test

```bash
pytest tests/test_tui_entropy_viewer.py -q                 # 17 passed
pytest tests/test_tui_snapshot.py -q -k entropy            # 2 xfailed
pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -q -k "unchanged or tc031"  # 7 passed (frozen)
ruff check s19_app/tui/screens.py tests/test_tui_entropy_viewer.py tests/test_tui_snapshot.py
```

## 4. Test results

- **RED (C-20, source reverted via `git stash push -- screens.py styles.tcss`,
  tests present):** `6 failed, 11 deselected` — AT-062a/AT-062b/TC-324/TC-325 +
  both redefined truncation nodes fail with `AttributeError: '…' has no attribute
  '_page_size'/'_display_windows'` and missing `#entropy_page_indicator`. Correct
  RED (feature absent). Source restored via `git stash pop`.
- **GREEN:** `pytest tests/test_tui_entropy_viewer.py -q` → **17 passed** (EXIT=0).
  (13 batch-26 nodes + 4 new; the 2 truncation nodes rewritten in place.)
  AT-036b (the load-bearing remap regression guard) stays green.
- **Snapshot (C-22):** `-k entropy` → **2 xfailed** (EXIT=0). Baselines NOT
  regenerated locally (canonical-CI regen at end-of-batch).
- **Frozen guards:** `7 passed`. `git diff` on the frozen set +
  `entropy_service.py` = **0 diffs** (empty).
- **Ruff:** `All checks passed!`

## 5. C-23 geometry (PILOT-MEASURED, not fr-estimated)

Page **size** is FIXED 512 (not measured). Only the CONTROLS geometry was
measured, via `App.run_test(size=…)` reading real `region`/`content_region`:

| Widget | 80x24 (region) | 120x30 (region) |
|---|---|---|
| `#entropy_dialog` | x=13 w=54 **right=67** | x=19 w=82 **right=101** |
| `#entropy_body` content_region | x=16 y=6 **w=48 h=9** | x=22 y=6 **w=76 h=15** |
| `#entropy_controls` | x=16 y=6 w=46 h=3 right=62 | x=22 y=6 w=76 h=3 right=98 |
| `#entropy_sort_button` | right=31 (label `Sort: address`) | right=37 |
| `#entropy_page_prev` | right=38 | right=44 |
| `#entropy_page_next` | right=45 | right=51 |
| `#entropy_page_indicator` | right=56 | right=62 |

**Verdict:** all controls fit **within** the dialog at BOTH sizes — controls
overflowing dialog = **NONE** (max control right=62 < dialog.right=67 @80x24;
=98 < 101 @120x30). Controls render above the fold (y=6, body top) and are
non-clipped. **No deficit** — the buttons are a real, reachable affordance at
80x24; the `PgUp`/`PgDn`/`s` key bindings are an additional compact path (used
by the ATs so they are size-robust). No fallback rung needed.

## 6. Per-LLR coverage

| LLR | Covered by |
|---|---|
| **062.1** fixed-512 paging + `page P/Q` (replaces truncation) | AT-062a (page-past-cap, both sizes), TC-324 (slice/count/clamp/indicator/union-reachable), redefined TC-036.5 ×2 |
| **062.2** sort (stable, presentation-only) + shared remap | AT-062b (entropy→row0=max, page reset, both sizes), TC-325 (desc+tie-break, no mutation, remap), AT-036b (regression guard, green) |
| **062.3** controls geometry pilot-measured @80x24 + @120x30 | §5 table (fit confirmed, no overflow) |

## 7. Discipline / evidence checklist

- [x] Tests/type checks/lint pass — 17 passed; ruff clean; type hints on all new methods.
- [x] No secrets in code or output.
- [x] No destructive commands (stash push/pop only, on tracked files; restored).
- [x] File count within cap — **4 files** (≤5).
- [x] Frozen guards 0 diffs — `entropy_service.py` + engine set untouched (`screens.py`/`styles.tcss` are NON-frozen).
- [x] C-22 per-cell snapshot drift — exactly the 2 `entropy-comfortable-{80x24,120x30}` cells xfail; no other cell touched.
- [x] C-18 — each new AT is exactly one on-disk node (AT-062a, AT-062b), each running both sizes internally.
- [x] Ledger: **post = 1373 − 0 + 4 = 1377** (full-suite `--collect-only` = 1377); A=4 new AT/TC, D=0 (truncation nodes rewritten in place).

### C-18 note
AT-062a and AT-062b are single on-disk nodes; the two-size (80x24 + 120x30)
requirement (C-18/LLR-062.3) is met by looping the sizes INSIDE each node, not
by parametrizing into extra nodes.

### Truncation-redefinition record (Q-02)
`test_tc036_5_cost_cap_and_truncation` now asserts page 0 renders ≤512 cells/rows
AND `#entropy_page_indicator` reads `page 1/Q` (Q>1) — the cap bounds per-page
cost; the tail is reachable. `test_tc036_5_truncation_fires_on_either_cap` now
monkeypatches the FIXED per-page budget smaller than the window count and asserts
`page 1/Q` where Q = ceil(n/budget) — a smaller budget yields MORE pages, never a
silent drop. Both keep their original intent (the cap still bounds render), only
the assertion is redefined; neither is blanket-xfailed.

### Deviations
None. Scope held to US-062; US-063 (legend + clickable strip) NOT implemented
(the `_window_for_row` helper is built now for its future reuse per LLR-063.2).
