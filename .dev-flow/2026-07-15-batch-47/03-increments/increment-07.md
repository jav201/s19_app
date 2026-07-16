# Increment 7 — US-WS classed hex bytes (LLR-066.3 / TC-066.6)

> Deferred from Inc-3 (SPLIT rule). White-box only — no AT, no C-17 (hex bytes are numeric).
> HEAD at start = Inc-6 `3288ba4`. Branch `claude/screen-upgrades-handoff-0874f9`.

## 1. What changed
Each rendered hex byte in `render_hex_view_text` is now **classed by kind** via a new
pure helper `_hex_byte_style(value)`:

- `0x00` / `0xFF` → dim grey (`insight_style.DGRAY`)
- printable ASCII `0x20`–`0x7E` → cyan (`insight_style.CYAN`)
- every other byte → bright (`insight_style.VALUE`)

**Styling approach chosen:** applied **inside the renderer** (`render_hex_view_text`),
not post-styled in the view layer — lower risk, single sink, and the function already
builds a Rich `Text` per byte cell (the plain-`str` `render_hex_view` was intentionally
left untouched since a `str` cannot carry spans and the TC-023 constant-knob tests assert
its exact string content).

**Scope guards honored:**
- Classing is applied **only to the two-hex-digit byte cells**; the ASCII gutter is left
  as-is (surgical, minimizes drift).
- The existing **search/MAC highlight styles keep priority** — the class style is applied
  only when a cell carries no `FOCUS_HIGHLIGHT_STYLE` / `MAC_ADDRESS_OVERLAY_STYLE`.
- Classing **only adds `Text` spans** — `.plain` is byte-for-byte unchanged.
- Public constants `MAX_HEX_BYTES` / `MAX_HEX_ROWS` / `HEX_WIDTH` / `FOCUS_CONTEXT_ROWS` /
  `SEARCH_ENCODING` untouched (values and names).

## 2. Files modified (2 — within cap, target 2)
- `s19_app/tui/hexview.py` (NON-frozen) — new `from .insight_style import CYAN, DGRAY, VALUE`;
  new `_hex_byte_style` helper (full PROJECT_RULES docstring); one-line change in the byte-cell
  loop of `render_hex_view_text`; Data-Flow docstring note added.
- `tests/test_tui_hexview_classed.py` (NEW, non-frozen) — 6 white-box TC-066.6 cases.

No frozen file touched. No snapshot test file changed (no new drift — see §5).

## 3. How to test
```bash
python -m pytest -q tests/test_tui_hexview_classed.py
# C-27 dual-guard
python -m pytest -q "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" \
  "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main" \
  "tests/test_tui_directionb.py::test_tc031_engine_imports_still_resolve" \
  "tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main"
# C-26 census (hex-consumer tests)
python -m pytest -q tests/test_tui_hexview.py tests/test_tui_goto_marker.py \
  tests/test_tui_search_pagination.py tests/test_tui_public_api.py tests/test_tui_legend.py \
  tests/test_tui_commandbar.py tests/test_report_service.py tests/test_tui_operations_view.py \
  tests/test_tui_helpers.py
# hex peek/views still pass
python -m pytest -q tests/test_tui_workspace_insight.py tests/test_tui_a2l_detail.py \
  tests/test_tui_map_big.py tests/test_tui_mac_coverage.py
# snapshot drift
python -m pytest -q tests/test_tui_snapshot.py
```

## 4. Test results (one run each, C-19)
- **RED → GREEN (TC-066.6):** before implement → `5 failed, 1 passed` (the 5 class-style
  assertions failed with `spans == []`; the constants-unchanged case passed). After implement →
  **`6 passed`**.
- **C-27 dual-guard:** `4 passed` (0 frozen-file diff; hexview.py confirmed NOT in `_ENGINE_PATHS`).
- **C-26 census (9 files across two runs):** `67 passed, 1 xfailed` + `86 passed` — all green
  (the pre-existing 1 xfail is unrelated).
- **WS/A2L/Map/MAC insight (hex peek/views):** `35 passed`.
- **Snapshot suite:** `12 passed, 20 xfailed, 0 unexpected failures`.
- **ruff:** `All checks passed!` on both changed files.

## 5. Risks
- **Snapshot drift (C-22/C-28):** classing the shared hex renderer drifts WS/A2L/Map hex
  cells. **Result: 0 NEW drift to mark.** The snapshot run reported `0` unexpected failures —
  every drifting hex cell is already xfail(strict=False) from Inc-3/4/6, so a real mismatch on
  an un-marked cell would have surfaced as a hard FAIL and none did. **No new C-22 marks; no
  `test_tui_snapshot.py` edit.** Regen happens in canonical CI (Inc-8), not locally.
- **C-28:** no shared-chrome/footer/binding change — N/A.
- **`.plain` change:** none. Verified by TC (`00 FF 41 1B` and `|..A.` gutter present unchanged)
  and by the goto-marker prefix-alignment TC still passing.
- **Highlight priority:** verified — a search-highlighted 'A' cell keeps `bold yellow`, not cyan.

## 6. Pending items
- **Inc-8:** canonical-CI snapshot regen (`snapshot-regen.yml`, textual==8.2.8) to refresh the
  drifted hex cells and retire the accumulated xfails — batch-wide, not this increment.
- HLR-066 now fully realized (classed hex was the last deferred piece of Inc-3).

## 7. Suggested next task
Inc-8 — canonical-CI snapshot regen + xfail retirement (batch-wide), per PLAN.

---

## Evidence checklist
- [x] Tests/type checks/lint pass — TC-066.6 `6 passed`; ruff `All checks passed!` (`hexview.py`, `test_tui_hexview_classed.py`).
- [x] No secrets in code or output — pure render helper + numeric byte classing.
- [x] No destructive commands run without approval — only `pytest` / `ruff` / `git status`.
- [x] File count within cap — 2 files (`hexview.py` + new test), target 2.
- [x] Review packet attached — this document.

## C-26 census (reverse-grep `render_hex_view_text`/`render_hex_view`/`_collect_hex_rows`/`find_string_in_mem`)
8 non-frozen test files reference the hex functions; all re-validated green:
`test_tui_hexview.py`, `test_tui_goto_marker.py`, `test_tui_search_pagination.py`,
`test_tui_public_api.py`, `test_tui_operations_view.py`, `test_tui_helpers.py`,
`test_tui_commandbar.py`, `test_report_service.py`.
- **Sensitive assertions confirmed surviving:**
  - `test_tui_hexview.py:80` — `any("bold yellow" in str(span.style) …)`: uses `any`, highlight
    span still present → passes.
  - `test_tui_goto_marker.py:95-105` — asserts no styled span overlaps the leading 2-col marker
    prefix; classing spans live only on the hex byte cells (offset ≥ 14), never the prefix → passes;
    the marker-vs-marker-less body-equality check is over `.plain` (unchanged) → passes.
  - No test asserts an exact hex-`.plain` string that classing could alter (classing adds spans,
    not characters) — confirmed.
- **Frozen `test_hexfile.py` NOT touched** (it is in the C-27 frozen set; the non-frozen
  `test_tui_hexview.py` is the hexview test surface).

## C-27 result
`hexview.py` is NOT a member of `_ENGINE_PATHS` (frozen set = `core.py`, `hexfile.py`,
`range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` + 9 test
files). `git diff --stat` = only `hexview.py` modified + new test file added. All 4 dual-guard
tests pass (0 diff on the frozen src+test set).

### Gate outcome (orchestrator, 2026-07-15)
- **Independent code-review:** APPROVE-WITH-NITS, 0 HIGH / 0 MEDIUM. All 3 risks verified: (1) highlight priority PRESERVED (`byte_style = style if style is not None else _hex_byte_style(value)` — classing only when no highlight; discriminating negative test); (2) `.plain` + public constants + plain-str `render_hex_view` UNCHANGED (spans-only, TC-023 unaffected, test_tui_hexview 41 passed); (3) classing boundaries correct. C-26/C-27 clean.
- **F1 (LOW) APPLIED:** added `test_tc066_6_printable_ascii_class_boundaries` pinning the exact edges (0x1F→bright, 0x20→cyan, 0x7E→cyan, 0x7F→bright) so a `<`/`<=`/0x7F off-by-one fails. Re-verified: 7 passed, ruff clean.
- **NO new snapshot drift** — every drifting hex cell already xfail from Inc-3/4/6 (confirms theme-last sequencing kept hex-cell coverage folded into the screen increments). C-28 N/A.
- **Gate axis check:** Coverage OK (LLR-066.3 + TC-066.6 + boundary TC; no AT — white-box only per spec); Certainty OK (highlight-priority discriminating negative, exact-edge assertions); Evidence OK (RED 5→GREEN 7, C-27 0-diff reproduced). **APPROVE.** HLR-066 now FULLY closed (classed-hex was its last open clause). → Inc-8 (app-wide theme + canonical-CI regen setup).
