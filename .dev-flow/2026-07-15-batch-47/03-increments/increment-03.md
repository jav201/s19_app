# Increment 03 — US-WS render (Workspace MID insight layer)

> batch-47 Inc-3 · branch `claude/screen-upgrades-handoff-0874f9` · English.
> Realizes LLR-066.1/066.2/066.4/066.6/066.7 + LLR-067.1/067.2/067.3 (+ .4 geometry
> via structural ATs). **Classed hex (LLR-066.3) DEFERRED** per the SPLIT rule (see §1).

---

## 1. What changed

Workspace-only render enrichment (no engine/parser/validation change; all values
already computed upstream or derived in Inc-2's `load_service`):

- **LLR-066.1 — pane border titles/subtitles.** `_compose_screen_workspace` sets
  `border_title`/`border_subtitle` on `#ws_left` (Workspace/sections),
  `#ws_center` (Hex View/bytes), `#ws_right` (Context/coverage).
- **LLR-066.4 + 066.6 — loader-facts line.** `#ws_stats` now renders, below the
  coverage block, `Loader N err · ⚠K OOO · Entry <hex-or-—>` via the NEW pure
  helper `build_loader_facts_text` (N=`len(errors)`, K=`out_of_order_count`,
  Entry=`0x%08X` of `entry_point` or `—`). `0x0` → `0x00000000` (PRESENT), `None`
  → `—` (ABSENT). Numeric/hex only — no file-derived text; `#ws_stats` stays
  `markup=False`; built as a Rich `Text` (C-17-inert by construction).
- **LLR-066.7 (MJ-1 merge-carry).** Both merge sites now carry the derived facts
  forward instead of defaulting them: `_merge_primary_with_existing_mac`
  (`app.py:6954`) copies from `primary_loaded.*`; `_merge_mac_with_existing_primary`
  (`app.py:6997`) copies from `existing.*`. (MAC-load site `6791` keeps defaults —
  correct, MAC has no OOO/entry.)
- **LLR-066.2 — enriched section rows.** Each `update_sections` row now leads with
  a `✓` in-range glyph (green) + cyan address + right-aligned humanized size
  (`insight_style.human_bytes`, binary) + the range's dominant entropy-band glyph
  + a size micro-bar (`insight_style.microbar(size/biggest)`). Severity class +
  `item.data=(start,end)` + MAC out-of-range rows + truncation caps preserved.
- **LLR-067.1/067.2/067.3 — entropy memstrip.** `update_memory_strip` colours each
  mapped `#ws_memstrip` cell by its dominant entropy band
  (`entropy_style.band_style` over `entropy_windows`), marks unmapped gaps with the
  app-supplied `╱` glyph, and **falls back** to the pre-existing valid/invalid/gap
  colouring when `entropy_windows` is empty (Amendment A). Cell-count safety
  (`cell_count_for_geometry`) unchanged.
- NEW pure module helpers in `app.py`: `dominant_band_label(windows, start, end)`
  and `build_loader_facts_text(err, ooo, entry)`.

**SPLIT (LLR-066.3 classed hex) — DEFERRED to a follow-on increment.** Rationale:
after items 1–5 the `app.py` change is already substantial (2 new documented module
helpers + 3 renderer edits + 2 merge edits); classed hex would add `hexview.py` as a
5th file and mix a second concern. It has **no dedicated AT** (white-box TC-066.6
only), so deferring orphans no acceptance test. The public hex constants are
untouched. Recommend a small dedicated Inc (hexview.py + TC-066.6) next.

## 2. Files modified (4 — within the ≤5 cap; hexview deferred)

- `s19_app/tui/app.py` — imports (band_style, insight_style helpers, EntropyWindow);
  `_STRIP_GAP_GLYPH`; `dominant_band_label` + `build_loader_facts_text` helpers;
  border titles; enriched `update_sections`; loader-facts in `update_workspace_stats`;
  entropy-banded `update_memory_strip`; MJ-1 carry in the two merge methods.
- `tests/test_tui_workspace_insight.py` — NEW black-box ATs (AT-066a/b/c/d, AT-067),
  each parametrized at 80×24 AND 120×30; render helpers `_static_plain` /
  `_stats_plain` / `_memstrip_plain` (via `Static.render()`).
- `tests/test_tui_directionb.py` — C-26 update: `test_at040b_memory_strip_valid_and_gap_cells`
  retargeted to the Amendment-A contract (covered cells → `band-*` class; gaps →
  neutral discriminator).
- `tests/test_tui_snapshot.py` — `_batch47_workspace_drift_marks` xfail(strict=False)
  for the 6 `workspace-*` cells, wired into `_RESTYLED_CELLS`.

## 3. How to test

```bash
# The new black-box ATs (both pilot sizes)
python -m pytest -q tests/test_tui_workspace_insight.py
# C-27 frozen dual-guards
python -m pytest -q tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main \
  tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main \
  tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main \
  tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main \
  tests/test_tui_directionb.py::test_tc032_no_engine_test_function_is_skipped \
  tests/test_tui_directionb.py::test_tc_042_12_memory_strip_touches_no_frozen_path
# C-26-affected files
python -m pytest -q tests/test_tui_directionb.py
python -m pytest -q tests/test_tui_app.py
# Snapshot drift census (canonical-CI regen is a separate follow-up)
python -m pytest -q tests/test_tui_snapshot.py
# Lint
python -m ruff check s19_app/tui/app.py tests/test_tui_workspace_insight.py \
  tests/test_tui_directionb.py tests/test_tui_snapshot.py
```

## 4. Test results (real output)

- **AT file:** `14 passed in 10.40s` (4 Inc-2 data TCs + 10 Inc-3 AT executions = 5 ATs × 2 sizes).
- **RED→GREEN (C-20):** with `app.py` stashed (Inc-2 baseline), the 10 new AT executions
  FAILED with genuine assertion failures — `#ws_memstrip` rendered all `█` (0 band
  glyphs, 0 `╱`) and `#ws_stats` lacked the loader-facts line: `10 failed, 4 deselected`.
  After restoring `app.py`: `14 passed`. (A first RED run surfaced a test-helper bug —
  `Static.renderable` doesn't exist in this Textual; fixed to `Static.render()`, then
  the RED was genuine assertion failures.)
- **C-27 dual-guards:** `6 passed` (tc027 + tc031×2 + tc032×2 + tc_042_12) → 0 frozen diff.
- **C-26 files:** `tests/test_tui_directionb.py` → `1 failed, 174 passed` on first run
  (the expected Amendment-A hit below), then GREEN after the update; targeted neighbor
  re-run `18 passed`. `tests/test_tui_app.py` → `61 passed, 1 xfailed` (unchanged).
- **Snapshot:** before marks `6 failed, 24 passed, 2 xfailed`; after marks
  `24 passed, 8 xfailed` (6 new batch-47 workspace + 2 pre-existing), 0 hard failures.
  (Suite exit code 1 and "2 snapshots unused" are pre-existing — present in the
  before-run too — from the plugin's unused-baseline flag, unrelated to this increment.)
- **Ruff:** `All checks passed!` on all 4 changed files.

## 5. C-22 per-cell snapshot-drift list (6 cells, all Workspace)

Reasoned per-cell (C-22), all `test_tc016s_density_layout_snapshot[...]`:

| Cell | Why it drifts |
|------|---------------|
| `workspace-compact-80x24` | border titles + loader-facts + entropy section rows + entropy memstrip |
| `workspace-compact-120x30` | same |
| `workspace-compact-160x40` | same |
| `workspace-comfortable-80x24` | same |
| `workspace-comfortable-120x30` | same |
| `workspace-comfortable-160x40` | same |

All four Workspace changes repaint the Workspace body; the snapshot `run_before`
loads a triple + calls `update_sections`/`update_memory_strip`, so section rows,
memstrip and `#ws_stats` all render the new content, and border titles render at
compose time. **Containment (C-28):** the snapshot run showed EXACTLY these 6 cells
mismatched — no `a2l/mac/issues/map/patch/diff/flow` cell moved → no Footer/Header/rail
shared-chrome change (no binding add/remove this increment). Marked
`xfail(strict=False)` via `_batch47_workspace_drift_marks`, referencing the
canonical-CI regen follow-up (batch-47 Inc-7 theme + regen). **No baselines
regenerated locally** (`reference_snapshot_regen_env`).

## 6. C-26 reverse-census result

Touched symbols grepped across `tests/`: `update_sections` · `update_memory_strip` ·
`#ws_memstrip`/`ws_memstrip` · `#ws_stats`/`ws_stats` · `_compose_screen_workspace`
(+ `build_coverage_bar_text`/`build_workspace_stats_text`). Hits in
`test_tui_directionb.py`, `test_tui_app.py`, `test_tui_snapshot.py`.

- **`test_tui_app.py`** — `61 passed, 1 xfailed`, no change needed.
- **`test_tui_directionb.py`** — one genuine hit:
  `test_at040b_memory_strip_valid_and_gap_cells` asserted the OLD contract (covered
  range → `sev-ok` cell). Under Amendment A the memstrip now colours mapped cells by
  ENTROPY BAND (`band-*`), so `sev-ok` no longer appears for a covered cell. **Updated**
  (non-frozen) to assert the new contract: `any("band-" in c)` for covered + neutral
  discriminator for gaps — INTENT preserved (covered vs gap still distinguishable). The
  `build_workspace_stats_text`/`build_coverage_bar_text` direct-call TCs and the
  `update_memory_strip` source-inspection guard (`test_tc_042_12`, `test_at042_*`)
  re-validated GREEN (the guard checks batch-27 helpers are still used + no parse/validate
  call; my added `dominant_band_label`/`band_style` are neither).
- **`test_tui_snapshot.py`** — drift-only; handled in §5.

## 7. Risks · Pending items · Suggested next task

- **Risks:** (a) The memstrip/section entropy view REPLACES validity colour with band
  colour on mapped cells when entropy is present (approved Amendment A); invalid ranges
  no longer read as red on the memstrip — still surfaced in the sections list (`sev-error`)
  and Issues. (b) 6 workspace snapshot cells are xfail'd pending canonical-CI regen — a
  real layout regression there would be masked until regen; mitigated by the black-box
  ATs asserting structural content. (c) `build_coverage_bar_text` is now unused by
  `update_sections` (replaced by `insight_style.microbar`) but retained + still covered by
  TC-042.7; not dead-removed to keep the change surgical.
- **Pending:** LLR-066.3 classed hex (deferred, see §1) — needs `hexview.py` + TC-066.6.
  Canonical-CI SVG regen of the 6 workspace cells (batch-47 Inc-7 theme+regen follow-up).
- **Suggested next task:** Inc-4 (US-A2L, HLR-068/069) OR the deferred classed-hex micro-inc
  (`hexview.py` classed bytes + TC-066.6), whichever the orchestrator sequences next.

---

## Evidence checklist

- [x] Tests/type checks/lint pass — AT file `14 passed`; C-27 `6 passed`; ruff clean on all 4 files.
- [x] No secrets in code or output — numeric/hex + public `examples/` fixtures only.
- [x] No destructive commands run without approval — only `git stash push/pop` on `app.py` for RED, restored.
- [x] File count within cap — 4 files (≤5); classed-hex split off, reported.
- [x] Review packet attached — this document.
- [x] RED→GREEN captured (C-20) — §4.
- [x] C-27 dual-guard 0 frozen diff — §4.
- [x] C-26 reverse-census performed + one non-frozen test updated — §6.
- [x] C-22 per-cell drift list + C-28 containment — §5.
- [x] AT nodes on disk match the 01b crosswalk — grep-confirmed (test_at066a_ooo /
      test_at066b_entry_present / test_at066c_entry_absent_hex /
      test_at066d_merge_preserves_facts / test_at067_memstrip), each × (80×24, 120×30).

### Gate outcome (orchestrator, 2026-07-15)
- **Independent code-review:** APPROVE-WITH-NITS, 0 HIGH / 0 MEDIUM. Re-ran + confirmed: 14 workspace-insight passed, C-27 6 passed (0-diff), tc016s 21 passed/8 xfailed (6 batch-47 workspace + 2 pre-existing, C-28 containment: only workspace cells drift), MJ-1 carries from correct sources, AT-066d a genuine counterfactual through the real handler, memstrip fallback + C-17 verified.
- **F1 (LOW) APPLIED:** removed the now-dead `build_coverage_bar_text` + `coverage_bar_cells` (+ private `_BAR_FILLED/EMPTY_GLYPH`) from app.py and the off-surface `test_tc_042_7` from test_tui_directionb.py (the section bar switched to `insight_style.microbar`; `SECTIONS_COVERAGE_BAR_WIDTH` retained — used by the new microbar path). Shipped microbar bar still black-box covered by AT-040a. Re-verified: 18 passed (incl. AT-040a + C-27).
- **F2 (LOW) NO ACTION:** unconditional green `✓` on section rows is spec-conformant (LLR-066.2 defines `✓` as a fixed in-range glyph; the `sev-error` red survives on the dash line + microbar). Noted for awareness.
- **Classed hex (LLR-066.3) DEFERRED** → Inc-7 (own hexview.py increment; no AT orphaned — white-box TC-066.6 only). HLR-066 partially closed pending Inc-7.
- **Gate axis check:** Coverage OK (AT-066a/b/c/d + AT-067 realized single-node, both regimes; classed-hex deferral tracked); Certainty OK (AT-066d true counterfactual C-12; C-29 structural invariants; C-22 6-cell drift per-cell-justified); Evidence OK (RED→GREEN + C-27 + C-28 containment reproduced). **APPROVE.** → Inc-4 (US-A2L).
