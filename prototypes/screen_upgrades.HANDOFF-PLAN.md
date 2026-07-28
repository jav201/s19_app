# HANDOFF PLAN — screen-upgrade implementation (operator verdict 2026-07-15)

> **For the executing session:** this is the approved scope + technical map for the next
> dev-flow batch(es). Process: **FULL `/dev-flow`** (operator rule: every change ≥
> fast-dev-flow; this is multi-screen → full flow). **Ask the operator for the run/approval
> model at kickoff** — autonomy grants are per-batch, never carried
> (`feedback_standing_auth_per_batch`). Artifact language: English.

## 1. Verdict (operator, 2026-07-15)

| Screen | Tier picked | Ships |
|---|---|---|
| Workspace | **MID** | pastel/labels/titles + entropy memstrip, section micro-bars, classed hex bytes, loader-facts in stats |
| A2L Explorer | **MID** | colored/zebra table + detail card (14 hidden fields) above right-pane hex |
| MAC View | **MID** | status-glyph column + coverage X-of-Y strip |
| Memory Map | **BIG** | pastel bands + hatch gaps + address ruler + sym-count rows + region inspector w/ hex peek |
| Patch Editor | **BIG** | (on batch-46's 3-window layout) color roles + check glyphs + pass/fail strip + JSON coloring/cap gauge + **live before/after card** + history strip |
| Issues Report | — | **PARKED** (no tier selected; do not touch) |

Tiers are **cumulative** (MID includes EASY; BIG includes MID). Reference renders:
`prototypes/out/set_<screen>_<tier>_120x30.svg` (+ `_160x42` for BIG) and
`prototypes/out/screen_upgrades.compare.html`. Working prototype code (throwaway, for
visual reference ONLY — rewrite properly): `prototypes/screen_upgrades.prototype.py`.

## 2. Batch slicing (recommended)

- **Batch A (can start immediately):** Foundation + Workspace MID + A2L MID + MAC MID + Map BIG.
- **Batch B (blocked on batch-46 merge — `feat/batch-46-patch-3col`, PR #85 lineage):**
  Patch Editor BIG. Its skeleton is the NEW `patch_win_script/_checks/_json` windows; line
  refs below WILL shift after merge — re-locate symbols, don't trust offsets.
- Both batches end with a **canonical-CI snapshot-regen follow-up PR** (see §7).

## 3. Foundation increment (do first, ~3 files)

New non-frozen module `s19_app/tui/insight_style.py` (pattern: batch-45's
`entropy_style.py`) + `styles.tcss` additions. Contents:

- **Palette constants** (dolphie-derived, operator-approved via the SVGs):
  label `#c5c7d2`, value `#e9e9e9`, green `#54efae`, yellow `#f6ff8f`, red `#fd8383`,
  hilite `#91abec`, lblue `#bbc8e8`, dgray `#969aad`, purple `#b565f3`, cyan `#7dd3fc`;
  depth stack bg `#0a0e1b` / panel `#0f1525` / odd-row `#131a2c` / border `#1b233a`.
- **Helpers** (pure, unit-testable): `human_bytes(n)`, `label_value(label, value, style)`
  → Rich `Text`; `microbar(frac, width, style)` → Text; `threshold_style(pct, warn, bad)`.
- CSS: panel `border: tall` + `border-title-*` styling, zebra vars, chip-button styles.

**Constraints:** `tui/color_policy.py` is **ENGINE-FROZEN** — do NOT touch. The `sev-*`
CSS class contract and `css_class_for_severity` round-trip must keep working; the new
palette may restyle what those classes look like in `styles.tcss`, but class NAMES and the
severity semantics (Red/Green/White/Grey + Orange for MAC) are REQUIREMENTS-level
(REQUIREMENTS.md severity conventions) — amend requirements explicitly if hues change
(§6.5 before/after record, `feedback_requirement_amendment_before_after`).

**OPEN QUESTION for kickoff (ask operator):** adopt the navy/pastel theme app-wide (what
the approved SVGs show) or scope it to the five selected screens only? Recommended:
app-wide via `styles.tcss` (it is a pure CSS change), flagged as its own increment.

## 4. Per-screen work

### 4.1 Workspace — MID
Compose: `app.py::_compose_screen_workspace` (~app.py:1324). All render-level.
1. **EASY layer:** border titles/subtitles on `#ws_left`/`#ws_center`/`#ws_right` panes;
   sections list rows → `✓` glyph + cyan address + right-aligned humanized size;
   stats pane numbers threshold-colored.
2. **Entropy memstrip:** `#ws_memstrip` colored from `LoadedFile.entropy_windows`
   (already computed on the worker thread since batch-45 — NO new parsing) with band
   glyphs `░▒▓█` + `╱` for unmapped gaps. Reuse `entropy_style.py` band mapping.
3. **Section micro-bars:** per-range size bar (`microbar(size/biggest)`) + entropy glyph
   in the sections list renderer (`update_sections` path).
4. **Classed hex bytes:** 00/FF dim-gray, printable-ASCII cyan, rest bright.
   `tui/hexview.py` is NOT in the frozen set but its constants are public API — extend
   `render_hex_view_text` styling OR post-style in the view layer; keep
   `MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`HEX_WIDTH`/`SEARCH_ENCODING` untouched.
5. **Loader facts in stats pane:** `Loader 0 err · ⚠4 OOO · Entry 0x…`.
   Data: `LoadedFile.errors` already exists; OOO via frozen-API call
   `S19File.get_out_of_order_records()` from `load_service` (non-frozen) at load time →
   new `LoadedFile` fields (e.g. `out_of_order_count`, `entry_point`). Entry point: scan
   `s19.records` for S7/S8/S9 (frozen API read). **Intel HEX limitation:** hexfile.py
   (FROZEN) discards type 03/05 records (hexfile.py:135-137) → entry = "—" for HEX loads;
   document in the requirement.

### 4.2 A2L Explorer — MID
Compose: `app.py::_compose_screen_a2l` (~app.py:3873); cells: `_build_a2l_table_cells`
(~app.py:9090). `tui/a2l.py` is FROZEN — all work is app/services-side over
`_a2l_enriched_tags` (fields already parsed: description, unit, conversion,
record_layout_name, effective_byte_order, lower/upper_limit…).
1. **EASY layer:** zebra stripes; leading ✓/· in-image glyph column; Rich `Text` cells —
   name bright, address cyan, source muted; colored in-image count in `#a2l_tags_summary`.
2. **Detail card:** new widget mounted at top of `#a2l_hex_pane`, updated on
   `DataTable.RowHighlighted` → shows description / unit·conversion / record layout /
   byte order / limits for the selected tag. Hex view shrinks below it (same pane,
   vertical split — no new pane).
3. **C-17 CRITICAL:** description/unit/conversion/display_identifier are UNTRUSTED A2L
   text → render via `safe_text` / Rich `Text` objects / `markup=False`. Never f-string
   into markup (batch-43 tooltip lesson). Add the markup-safety assert tests.

### 4.3 MAC View — MID
Compose: `app.py::_compose_screen_mac` (~app.py:3966). `tui/mac.py` FROZEN — render-side only.
1. **EASY layer:** leading status glyph column ✓ (ok+in-image) / ⚠ (parse-ok,
   out-of-image → matches existing Orange warning semantics) / ✗ (parse_error), colored;
   cyan addresses; zebra.
2. **Coverage strip** above `#mac_records_list`: `MAC→S19 X of Y ▓▓▓░░ · A2L↔MAC N addr
   matches` from `CoverageMetrics` raw fields (`mac_in_s19`, `mac_total`,
   `a2l_mac_address_matches`) — today only pct-line renders and only conditionally
   (validation_service.py:287, gate at ~app.py:8759). Show the strip whenever a MAC is
   loaded, independent of file type. MAC names are untrusted → C-17 rules apply.

### 4.4 Memory Map — BIG
Panel: `screens_directionb.py::MemoryMapPanel` (~:1039, compose ~:1145), rows `RegionRow`
(~:976); band style in non-frozen `entropy_style.py`.
1. **EASY layer:** pastel band colors + `╱` hatch texture for unmapped gaps in the
   proportional strip; humanized sizes; At-a-glance box border-titled.
2. **Address ruler** under the strip: 5 tick labels (0%/25%/50%/75%/100% of span).
3. **Region rows enriched:** size microbar + `N sym` count (count A2L enriched-tag
   addresses within region span — reuse `range_index.py` primitives, NOT linear scans,
   for many-tags×many-regions) + explicit `↵` open-in-hex affordance (action exists —
   `RegionRow.Activated`/`OpenInHexRequested`, batch-45 N3).
4. **Region inspector** in existing `#map_detail` pane: on row highlight → span, size,
   band, 3-row hex peek (`render_hex_view` plain renderer is fine).
5. **C-29 geometry:** pilot-measure the REAL panel box (both axes) at 80×24 and 120×30
   BEFORE fixing row/ruler budgets — do not inherit the prototype's assumptions.

### 4.5 Patch Editor — BIG (Batch B, after batch-46 merges)
Panel: `screens_directionb.py::PatchEditorPanel` — batch-46's three windows
`#patch_win_script/_checks/_json` + docked button rows. Re-locate all symbols post-merge.
1. **EASY layer:** window border titles `¹PATCH SCRIPT / ²CHECKS / ³JSON EDIT` (+
   subtitles: entry count · run state · schema); entries table color roles (op purple,
   address cyan, bytes bright); docked button rows styled as color-grouped chips
   (entry-actions blue / apply-path green / checks yellow); variant+scope line in
   label/value idiom. Pure CSS+markup — zero behavior change; preserve every widget id
   (batch-46 FOLD-1 ids are census/test-pinned).
2. **Check glyph column** on entries: ✓/◐/✗ from the LAST `CheckRunResult` per entry
   (`last_check_result` state; batch-40 already syncs it on undo/redo). No check run yet →
   `·` gray.
3. **CHECKS pass/fail strip:** counts + microbar from `CheckRunResult.aggregates`
   (passed/failed/uncheckable — engine already computes; today only counts-in-status).
4. **JSON window:** syntax-ish coloring of the pasted change-set preview + paste-cap
   gauge `N KB / 64KB` (cap exists — `CappedTextArea`, batch-39). Pasted JSON is
   UNTRUSTED → C-17; color via tokenizer on trusted-rendered `Text`, never markup-parse
   pasted content.
5. **Live before/after card** (headline feature): on entry-row select → before-bytes read
   from current `LoadedFile.mem_map` at entry address vs entry's patch bytes, colored.
   This surfaces live what today exists only in generated reports
   (`ChangeSummaryEntry.before/after`). Read-only preview — do NOT apply anything.
6. **History strip:** current position in the undo/redo stack (`_HISTORY_MAX=20` exists)
   as `◄ apply·2 ● now` + key hints.
7. **C-29:** re-measure window geometry with the card added, both axes, 80×24 + 120×30;
   the card must not push docked button rows below reachability (that was B2 — the exact
   defect batch-46 fixed; AT it explicitly).

## 5. Requirements traceability (Phase-1 derives; candidates)

New rows (numbering after batch-46's R-TUI-063/064): per-screen "insight layer" rows
(workspace strip/facts, a2l detail card, mac coverage strip, map ruler+inspector, patch
before/after card + check glyphs) + one palette/theme row. Amendments (§6.5 before/after):
R-TUI-041 (memory-map view: ruler/inspector extend batch-45 band-bands), severity-colour
convention rows if hues change, R-TUI-046 lineage on the patch windows. Update statuses on
rows whose Manual checks become Automated.

## 6. Acceptance tests (C-18: every AT → one on-disk node; black-box per
`feedback_blackbox_behavioral_acceptance`)

Per screen ≥2 ATs at 80×24 + 120×30 pilot sizes, e.g.: AT-ws (memstrip shows ≥2 distinct
band styles + gap glyph for a fixture with gaps; stats shows OOO count for the 4-OOO
`prg.s19`), AT-a2l (selecting a row renders that tag's description/unit in the card;
markup-injection fixture renders literally — C-17 test), AT-mac (strip shows `X of Y`
equal to CoverageMetrics for the fixture), AT-map (row highlight updates inspector hex
peek to region start; ruler ticks match span), AT-patch (before-bytes equal image bytes at
entry addr; all docked buttons reachable with card visible — reuse batch-46's
reachable-under-scroll contract at the floor). Include one golden/census sweep for report
outputs (C-24) — none expected to change (render-only), assert 0-drift.

## 7. Regression / census / snapshots

- **Snapshot drift is MASSIVE by design** — the density matrix (31 cells,
  `test_tc016s_density_layout_snapshot`) + shared-chrome cells all restyle. Run the
  C-22/C-28 census up front (Phase 1), mark expected-drift cells, and regen baselines ONLY
  in canonical CI (`snapshot-regen.yml`, textual==8.2.8) as a follow-up PR — never local
  (`reference_snapshot_regen_env`).
- **C-26 reverse census:** touched symbols (`_build_a2l_table_cells`, `update_sections`,
  `MemoryMapPanel`, `PatchEditorPanel`…) → grep tests clicking/asserting on them.
- **C-27 dual-guard:** confirm 0 frozen-file diffs (src AND tests) every increment —
  frozen set includes `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, `core.py`,
  `hexfile.py`, `range_index.py`, `validation/`.
- Full gate: `pytest -q` green (baseline ~1394 pass; TUI flake was fixed in batch-42 —
  a timeout hang is YOUR bug, not the flake).

## 8. Security review points (C-16/C-17)

All new rendered surfaces carry untrusted text: A2L description/unit/conversion, MAC
names, pasted JSON, change-file paths. Every one goes through Rich `Text` /
`safe_text` / `markup=False`. Pre-code security pass required (fast-dev-flow S-gate or
dev-flow Phase-2), plus final PR-QA. No new file-system or execution surface in this scope.

## 9. Non-goals (explicitly OUT)

Issues Report tiers (parked, no touch) · v1 chrome ideas (identity header, curated footer,
help overlay) · omni-search / linked workbench · raising the 120-col layout caps (the
160×42 exports argue for it — separate decision) · any behavior/wiring change in the Patch
Editor beyond read-only preview surfaces · Flow Builder batches (b-45+ flow.json etc.).

## 10. Kickoff checklist for the executing session

1. RC-1: fetch, confirm base = origin/main tip; **verify batch-46 merged** before Batch B.
2. Ask operator: approval model for this batch; theme scope (app-wide vs 5 screens).
3. Read: this file · `prototypes/screen_upgrades.NOTES.md` · the approved SVGs ·
   `docs/engineering-rules.md` (C-13/C-22/C-23/C-28/C-29 live there) · memory
   `project_screen_upgrades_prototype_2026-07-15` + `reference_textual_internal_name_shadowing`
   (do NOT name widget members `_context`/`_nodes` — cost an hour once already).
4. Delete `prototypes/screen_upgrades.*` + `prototypes/out/` once the batches merge
   (prototype convention: absorb then delete).
