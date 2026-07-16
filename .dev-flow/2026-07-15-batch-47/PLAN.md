# PLAN — batch-47 · screen-upgrades Batch A (living compendium)

> Living plan; updated at every gate + checkpoint. Mirror of `state.json`, human-readable.
> Origin: `prototypes/screen_upgrades.HANDOFF-PLAN.md` (operator-approved 2026-07-15).

## Where we are
- **Phase 3 — Implementation** — STARTING Inc-1 (Foundation). Autonomous per-increment gates.
- **Phase 2 — Cross-review** — APPROVE-WITH-FOLDS → folds applied → re-gate APPROVE. 0 blockers / 0 HIGH.
- **Phase 1 — Requirements** — APPROVED. **Phase 0 — DoR** — APPROVED.
- Branch `claude/screen-upgrades-handoff-0874f9` @ `19bf1eb` (== origin/main tip). RC-1 PASS.

## Phase-2 result (2026-07-15) — 02-review.md
- Triple review (architect ∥ qa ∥ security). **0 blockers, 0 HIGH security.** `safe_text`=`Text(value)` verified markup-safe.
- **MJ-1 (writer-census, MAJOR):** `LoadedFile(` merge sites `app.py:6954`/`:6997` drop the new fields → loader-facts lies after MAC attach → NEW **LLR-066.7** carry-forward + **AT-066d**.
- **MJ-2:** MAC `✗` parse-error branch → **AT-070c** + NEW fixture. **MJ-3:** A2L table-cell C-17 (7 file-derived cells → `tuple[Text,…]`) → **AT-069c** ★. **MJ-4:** C-18 AT split (065a/b, 066a/b/c/d, 072a/b).
- **MD-1 (MEDIUM):** C-17 payloads += ANSI + unbalanced `sensor[unclosed` (the `from_markup` counterfactual).
- Minors folded: glyph `·░▒▓`, entry `0x0`→present, `mac_total==0` boundary, inspector C-17 unconditional, card-compose no-f-string, fields defaulted (C-27 0-diff), Amendment-B C-26 enumeration, inline HEX builder.
- **Canonical AT registry = 19 nodes** (4 gate-blocking C-17: AT-069b/069c/070b + AT-074 sub-assert). Both `01`/`01b` consistent.
- **CARRY:** cosmetic TC-numbering divergence `01`(TC-068.1) vs `01b`(TC-067.4) for A2L table C-17 → Phase-4 V-5 reconcile.

## Increment plan (C-21 re-cut after AT-set change; theme moved LAST — see decision below) — ≤5 files each
| Inc | Story | Files (non-frozen) | # | Snapshot drift |
|---|---|---|---|---|
| 1 | US-FND helpers | insight_style.py NEW · test_tui_insight_style.py NEW | 2 | none (pure module) |
| 2 | US-WS data | models.py (2 defaulted fields) · load_service.py · test_tui_workspace_insight.py NEW | 3 | none (data) |
| 3 | US-WS render | app.py (titles·update_sections·update_memory_strip·#ws_stats·classed hex·+MJ-1 merge carry) · test | 2 | WS feature cells (C-22 mark) |
| 4 | US-A2L | app.py (_build_a2l_table_cells→tuple[Text]·detail card·row-highlight) · test_tui_a2l_detail.py NEW · a2l_injection NEW | 3 | A2L feature cells |
| 5 | US-MAC | app.py (glyph+strip) · validation_service.py (gating) · test_tui_mac_coverage.py NEW · mac_injection+parse-error NEW | 4 | MAC feature cells |
| 6 | US-MAP | screens_directionb.py (bands·ruler·RegionRow·inspector) · test_tui_map_big.py NEW | 2 | Map feature cells |
| 7 | US-WS classed hex | hexview.py (00/FF dim·ASCII cyan·rest bright, LLR-066.3, DEFERRED from Inc-3) · test | 2 | WS+A2L+Map hex cells |
| 8 | US-FND theme | styles.tcss (app-wide navy/pastel) · test_tui_theme.py NEW (AT-065a/b) · test_tui_snapshot.py (drift marks, C-22/C-28) | 3 | ALL cells (theme) → canonical-CI regen follow-up PR |

**Inc-3 note:** classed hex (LLR-066.3) SPLIT OFF from Inc-3 → new **Inc-7** (own hexview.py increment; no dedicated AT, white-box TC-066.6 only → no orphan). hexview.py is shared by WS + A2L + Map hex, so its drift is broader — done as its own increment before theme.

**DECISION (orchestrator, autonomous, 2026-07-15):** theme (styles.tcss $-vars) sequenced LAST (Inc-7),
split from the Inc-1 helpers. WHY: the app-wide theme drifts every snapshot cell; applying it last
keeps live snapshot regression-coverage through the functional increments (each drifts only its own
feature cells, marked per C-22) rather than suppressing the whole tc016s matrix under xfail from Inc-1.
Inc-7 immediately precedes the canonical-CI regen follow-up PR (local regen FORBIDDEN,
reference_snapshot_regen_env). US-FND acceptance (AT-065a palette / AT-065b sev-* round-trip) validates
at Inc-7. Deviation from architect's 6-inc cut (helpers+theme merged in Inc-1) → recorded here + state +
postmortem.

## Where we are (current increment)
- **Inc-1 — Foundation helpers** — ✅ DONE `b91e9fb`. 6 green, 0 HIGH. Binary units (§6.5 Amd D).
- **Inc-2 — US-WS data** — ✅ DONE. models.py 2 defaulted fields + load_service; 4 green, MN-6 blast-radius 222/0, 0 HIGH.
- **Inc-3 — US-WS render** — ✅ DONE. app.py titles/stats/MJ-1/sections/memstrip; 14 green (AT-066a/b/c/d + AT-067); 6-cell drift xfail (C-28 clean); F1 dead-code cleanup applied; 0 HIGH. classed-hex→Inc-7.
- **Inc-4 — US-A2L** — ✅ DONE. tuple[Text] cells + glyph + A2LDetailCard + RowHighlighted; 6 green (AT-068/069/069b★/069c★); dual review 0 HIGH (security APPROVE-CLEAN); §6.5 Amd E (accents subsumed by severity). 6 a2l cells drift.
- **Inc-5 — US-MAC** — ✅ DONE. glyph col + coverage strip + C-17; 7 green (AT-070/070b★/070c/070d/071); dual review, F1 MEDIUM fixed (glyph off in_mem, ✓=in-image; +AT-070d MAC-only ·). 4 wide mac cells drift.
- **Inc-6 — US-MAP Memory Map BIG** — ✅ DONE. bands+hatch + MapRuler + N-sym(range_index) + inspector peek; 8 ATs green; C-29 both-axes measured; code-review 0 HIGH (F3 docstring fixed). 2 map cells drift.
- **Inc-7 — US-WS classed hex** — STARTING. hexview.py 00/FF dim·ASCII cyan·rest bright (LLR-066.3, deferred from Inc-3). Small.
- Canonical AT registry: **20** (+AT-070d). Snapshot drift so far: 6 WS + 6 A2L + 4 MAC + 2 MAP = 18 cells xfail.

## Phase-1 result (2026-07-15)
- `01-requirements.md` (architect): 5 US, **10 HLR** (HLR-065..074 = R-TUI-065..074), **32 LLR**,
  **12 AT** (AT-065..074 + C-17 AT-069b/070b), ~44 provisional TC. Both traceability chains
  complete; every geometry claim `assumed`-flagged for C-29 Phase-3 both-axes measure; §6.5
  amendments A (memstrip entropy), B (map band-bands ruler/hatch/inspector extension, amends
  R-TUI-060/041), C (conditional sev-* hue restyle placeholder).
- `01b-qa-strategy-and-verification.md` (qa): 28 TC + 20 AT executions w/ executed-verification +
  numeric thresholds; **2 gate-blocking C-17 ATs**; C-10 branch ATs; real-fixture facts table.
- **RECONCILIATION DECISION (orchestrator, gate):** adopt architect's **R-TUI-065..074 + AT-065..074/
  069b/070b as CANONICAL**. qa's TC/AT BODIES stay; only their traceability column re-maps: qa
  `AT-a2l-C17→AT-069b`, `AT-mac-C17→AT-070b`; qa branch-ATs (AT-ws-03/04 entry-present/absent,
  AT-mac-02 ✓/⚠ both branches, AT-a2l-01 non-default highlight, AT-map-01 non-first region) are the
  concrete C-10 realizing nodes for architect AT-066/070/069/074. **Phase 2 folds this crosswalk into
  both docs (with §6.4 audit rows) and C-21 re-cuts increments if the AT set changes.**
- **CARRIES into Phase 2 (explicit review inputs):**
  - **T-1** `prg.s19` entry = S9 `0x0` (valid-but-zero — renders `Entry 0x00000000`, PRESENT, not
    `—`). Use `case_01_basic_valid/firmware.s19` (S7 `0x80000000`, non-zero) for the unambiguous
    entry-present AT; keep prg.s19 for the OOO=4 AT. Fold the fixture selection into AT-066.
  - **T-2** No `.hex` fixture on disk under `examples/` → the HEX `entry_point is None`→`—` B-branch
    AT needs an inline Intel-HEX builder / new NON-frozen fixture (count in Phase-3 file budget).
  - **T-5** C-17 injection fixtures (`a2l_injection`, `mac_injection`) are NEW → create in non-frozen
    locations (count in budget). T-3 (in_memory) + T-4 (RowHighlighted NEW) already in the spec.
  - **AT/req-id crosswalk** finalization (above) + `01b` filename note (architect refs
    `01b-validation.md`; actual = `01b-qa-strategy-and-verification.md` — same companion).

## Objective (BLUF)
Add a **visual data-insight layer** across five screens, keeping current skeletons — no
parser/engine change, render-level only. Foundation (app-wide navy/pastel theme + new
non-frozen `insight_style.py` helpers) + Workspace MID + A2L MID + MAC MID + Memory Map BIG.
Issues Report PARKED; Patch Editor BIG = Batch B (deferred).

## Kickoff authorization (operator, 2026-07-15, AskUserQuestion — verbatim in state.json)
1. **Scope** = Batch A only.
2. **Run mode** = AUTONOMOUS THROUGH SELF-MERGE (batch-46 gated model: 7-section packet at
   each gate, self-approve w/ named axis check → PR + CI green → final independent PR-level
   qa-reviewer pass MUST be clean → merge → sync; a HIGH final-QA finding blocks + returns).
3. **Theme** = app-wide navy/pastel via `styles.tcss` (own foundation increment).
4. **Batch B** = decide after Batch A closes.
- Decision-recording ack (via selections): every autonomous decision → this log + decisions_log
  + 05-postmortem + vault at sync.

## Guardrails (this batch)
- **Engine-frozen OFF-LIMITS** (C-27 dual-guard each increment): `_ENGINE_PATHS` (test_tc031 in
  `test_tui_directionb.py`) = core.py, hexfile.py, range_index.py, validation/, tui/a2l.py,
  tui/mac.py, **tui/color_policy.py**; `_ENGINE_TEST_FILES` (test_tc032) = 9 files
  (test_core_srecord_validation, test_hexfile, test_range_index, test_validation_a2l/engine/mac,
  test_tui_a2l, test_tui_mac, test_color_policy_round_trip). Also test_tc027 in
  test_engine_unchanged.py. Run test_tc027 + test_tc031 + test_tc032 every increment.
- **C-17** untrusted-text markup-safety on ALL new rendered surfaces (A2L description/unit/
  conversion/display_identifier, MAC names) → `safe_text` / Rich `Text` / `markup=False`; hostile
  bracket/ANSI AT per screen. Never f-string untrusted text into markup.
- **sev-* class NAMES + severity semantics are REQUIREMENTS-level** — palette may restyle hues in
  styles.tcss, but if hues change, AMEND requirements (§6.5 before/after). `color_policy.py` is
  frozen — never touched (we restyle sev-* in styles.tcss, not the map).
- **C-29 two-axis geometry**: pilot-measure BOTH width+height of the REAL boxed panel at 80x24
  AND 120x30 before fixing memstrip width / map ruler+row budgets. Never inherit the prototype's
  full-screen budget.
- **Snapshot drift is MASSIVE by design** (tc016s density matrix + shared-chrome). Regen ONLY in
  canonical CI (snapshot-regen.yml, textual==8.2.8) as a follow-up PR — NEVER local
  (reference_snapshot_regen_env). C-22 per-cell prediction / C-28 shared-chrome census.
- **C-26 reverse-census** each touched symbol across ALL tests/ (recon test census below).

## Stories (Phase 0 — DoR)
| ID | Story | Tier | Class | Black-box observable |
|---|---|---|---|---|
| US-FND | App-wide navy/pastel theme + `insight_style.py` helpers | Foundation | READY | Any screen renders new palette vars; sev-* names/semantics preserved |
| US-WS  | Workspace MID: border titles, entropy memstrip+gap glyphs, section micro-bars, classed hex, loader facts | MID | READY | memstrip ≥2 band styles + gap glyph; stats "Loader N err · ⚠K OOO · Entry 0x…" |
| US-A2L | A2L Explorer MID: zebra+colored table + in-image glyph + detail card | MID | READY | selecting a row renders its description/unit in detail card; injection text literal (C-17) |
| US-MAC | MAC View MID: status-glyph column + coverage X-of-Y strip | MID | READY | strip "MAC→S19 X of Y" == CoverageMetrics; glyph column ✓/⚠/✗ |
| US-MAP | Memory Map BIG: pastel bands+hatch gaps + address ruler + sym-count rows + region inspector w/ hex peek | BIG | READY | region activate → inspector hex peek at region start; ruler ticks match span; N sym per row |

Dependency order: **US-FND → {US-WS, US-A2L, US-MAC, US-MAP}** (four screen stories independent
of each other once foundation lands).

## Verified facts (recon, current tree — draft-time verification for Phase 1)
- **Compose:** `_compose_screen_workspace` app.py:1324 (`#ws_memstrip` 1409, `#ws_stats` 1394,
  `#sections_list`); `_compose_screen_a2l` :3873 (`#a2l_tags_list` 3931, `#a2l_hex_pane` 3954,
  `#a2l_tags_summary` 3937); `_compose_screen_mac` :3966 (`#mac_records_list` 4007,
  `#mac_records_summary` 4008).
- **Renderers:** `_build_a2l_table_cells` app.py:9090 (16-tuple); `update_sections` :8137 (section
  rows + coverage bar `build_coverage_bar_text` :8187); `update_memory_strip` :8289 (colors
  valid/invalid/gap — **NO entropy yet**, entropy strip is NEW); `update_mac_view` :8668 +
  `_populate_mac_datatable` :8771. Selection = `on_data_table_row_selected` :6038 (**no
  RowHighlighted anywhere** — A2L detail card adds a new RowHighlighted handler or reuses selection).
- **Memory Map** (`screens_directionb.py`): `MemoryMapPanel` :1039 (compose :1145, `#map_detail` /
  `#map_detail_body`, `#map_stats`, band strip `_build_band_widgets` :1284, no ruler id);
  `RegionRow` :976 (`RegionRow.Activated` :1009 via on_click :1034;
  `MemoryMapPanel.OpenInHexRequested` :1100; `on_region_row_activated` ~1620 populates detail).
- **Data:** `LoadedFile` models.py:10 has `entropy_windows`/`mem_map`/`ranges`/`errors`; NO
  `out_of_order_count`/`entry_point` (NEW). `entropy_style.band_style(label)→(class,glyph,meaning)`
  :69. `S19File.get_out_of_order_records()` core.py:542 (returns list). Entry point = scan
  `s19.records` for S7/S8/S9 `.address` (no accessor; HEX discards 03/05 hexfile.py:135-137 →
  entry "—"). `_a2l_enriched_tags` = list[dict] (app.py:882/8826); fields present, **in-image flag =
  `in_memory`** (a2l.py:1316), NOT `in_image`. `CoverageMetrics` model.py:140 has
  `mac_in_s19`/`mac_total`/`a2l_mac_address_matches`. `load_service.build_loaded_s19` :18 (construct
  61-76) / `build_loaded_hex` :79 (construct 94-108) — new fields populated here. `range_index`:
  `build_sorted_range_index`/`address_in_sorted_ranges`/`range_in_sorted_ranges`.
- **Styling:** `styles.tcss` 1427 lines; `$`-vars 26-30 (`$accent-calm`/`$bg-base`/`$bg-panel`/
  `$fg-base`/`$rule`), Screen rule :32, sev-* 499-515, band-* 529-541. `safe_text`
  screens_directionb.py:615.

## Test census (recon — C-26 reverse-census seeds)
`update_sections` → test_tui_app/directionb/snapshot (28); `MemoryMapPanel` → directionb (23);
`RegionRow` → directionb (9); `#ws_memstrip` → directionb (11); `#mac_records_list` →
app/directionb (10); `_build_a2l_table_cells` → directionb + validation_service_supplemental (2);
`#a2l_hex_pane` → directionb + mac_layout (6); `entropy_windows` → directionb (2).

## Risks / watch-items
- R1 **Massive snapshot drift** (tc016s density matrix 31 cells + shared-chrome). Mitigate: C-22
  per-cell prediction, canonical-CI regen follow-up PR.
- R2 **C-17 injection sinks** on A2L text + MAC names — new render surfaces. Pre-code security pass.
- R3 **Geometry** (C-29): memstrip width + map ruler/rows in a boxed panel; pilot-measure both axes.
- R4 **C-26 reverse-census** must cover moved/restyled leaf ids (batch-46 lesson).
- R5 Theme app-wide touches EVERY screen's snapshot (incl. parked Issues/Patch) — cosmetic only.

## Out-of-scope carries
Issues Report tiers (parked) · Patch Editor BIG (Batch B) · raising 120-col caps (separate) ·
Flow Builder · v1 chrome ideas (identity header/curated footer/help overlay).

## Decision log
- **2026-07-15 P0**: RC-1 PASS @ 19bf1eb. Kickoff auth recorded (Batch A / autonomous-self-merge /
  app-wide theme / Batch B deferred). Recon verified all touch points post batch-46 merge; frozen
  dual-guard + memstrip-is-not-entropy + in_memory/no-RowHighlighted corrections captured. 5 stories
  READY. Advancing to Phase 1 (self-approve, axis check below).

## Test ledger
Baseline `pytest -q`: ~1394 pass (per batch-46 close). To be reconciled per increment.
