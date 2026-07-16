# 02 — Phase-2 Cross-Agent Review — batch-47 (screen-upgrades Batch A)

> Triple review (architect ∥ qa-reviewer ∥ security-reviewer) over `01-requirements.md` + `01b-qa-strategy-and-verification.md`. Consolidated by the orchestrator. **Verdict: APPROVE-WITH-FOLDS — 0 blockers, 0 HIGH security.** All folds are in-spec (tighten C-17, complete C-10 branches, fix the writer-census bug, finalize the AT crosswalk); no scope creep.

## BLUF
- **architect:** APPROVE-WITH-FOLDS. ~20 `file:line` citations all hold post-batch-46. One MAJOR (F-1 writer-census). Clean ≤5-file increment plan.
- **qa-reviewer:** APPROVE-WITH-FOLDS. Two-layer discipline real; both pilot sizes on every AT. 3 MAJOR (M1/M2/M3) + 6 minors; recommended 1:1 crosswalk.
- **security-reviewer:** APPROVE-WITH-CONDITIONS. 0 HIGH. `safe_text` = `Text(value)` (not `from_markup`) — genuinely markup-safe. 2 MEDIUM (F1/F3) + 2 LOW (F2/F4). No new fs/network/exec surface.

---

## Findings & disposition

### BLOCKERS — none.

### MAJOR

**MJ-1 (architect F-1) — Writer-census incomplete: new `LoadedFile` fields dropped on MAC-merge / primary-reload paths.**
Three other `LoadedFile(` construction sites exist beyond `load_service`: `app.py:6791` (`_load_mac_file`, defaults correct — MAC has no OOO/entry), `app.py:6954` (primary-reload-preserving-MAC merge) and `app.py:6997` (`_merge_mac_with_existing_primary`) — the latter two field-copy the snapshot and would default `out_of_order_count=0`/`entry_point=None`, so after loading an S19 (OOO=4, entry=0x…) and attaching a MAC, the loader-facts line renders `⚠0 OOO · Entry —`. AT-066 (loading `prg.s19` directly) ships the bug green.
**Fold:** NEW **LLR-066.7** — `_merge_mac_with_existing_primary` (`:6997`) and the primary-reload merge (`:6954`) shall carry `out_of_order_count`/`entry_point` forward from the source payload. NEW **AT-066d** (load S19 OOO=4 → attach MAC → stats still `⚠4 OOO` + entry preserved). Record the two merge sites in §6.4 writer-census. **Must-fold before Phase 3.**

**MJ-2 (qa M1) — MAC parse-error `✗` branch has no black-box node and no fixture (C-10 three-way incomplete).**
`AT-070` asserts only `✓`/`⚠` (from `case_02`). The `✗` branch is white-box only; no parse-error MAC fixture exists.
**Fold:** NEW **AT-070c** (parse-error → `✗`, both sizes) + a NEW non-frozen parse-error MAC fixture (Phase-3 budget).

**MJ-3 (qa M2 + security F1) — A2L table-cell C-17 sink under-enumerated (distinct path from the card).**
`_build_a2l_table_cells` (`app.py:9090`) returns a 16-tuple of plain `str`; several are file-derived/untrusted (`name`, `unit`, `function_group`, `memory_region`, `raw_value`/`physical_value` can carry brackets). LLR-068.1 styles only 3 cells; LLR-068.3 enumerates only "name, source, description-derived". The gate-blocking `AT-069b` drives the payload through the CARD (`description`/`unit`), a different builder — the table cell path is untested.
**Fold:** tighten **LLR-068.1/068.3** — every file-derived A2L cell (name, source, unit, function_group, memory_region, raw_value, physical_value) rendered as Rich `Text` (via `safe_text`/equivalent), never bare `str`; `_build_a2l_table_cells` returns `tuple[Text, ...]`, aligned to TC-067.1 "every cell is Text". NEW **AT-069c** (hostile A2L name → verbatim in table cell, gate-blocking).

**MJ-4 (qa M3 + architect F-4) — C-18 one-AT→one-node: split canonical `AT-065/066/072`.**
The architect numbered one AT per HLR, but each realizes as finer C-10 nodes → "covered in parts."
**Fold:** adopt the finer granularity as canonical (letter-suffixed) per the crosswalk below; record the split in §6.4.

### MEDIUM (security)

**MD-1 (security F3) — injection fixtures omit ANSI + unbalanced-bracket payloads.**
Specified payloads are balanced markup + link only. The highest-value negative test is the **unclosed bracket** (`sensor[unclosed`) — it distinguishes correct `Text(value)` from `Text.from_markup(value)` (which passes all balanced fixtures but raises `MarkupError` on `[`).
**Fold:** `a2l_injection`/`mac_injection` payload set = `[red]…[/red]` · `[link=http://x]u[/link]` · `\x1b[31mX\x1b[0m` (ANSI) · `sensor[unclosed` (lone bracket); assert all render verbatim in `Text.plain`, no `MarkupError`/crash.

### LOW / MINOR

- **MN-1 (qa m1)** — 01b band-glyph list `░▒▓█` → reconcile to canonical `· ░ ▒ ▓` (`ENTROPY_BAND_GLYPH`, `entropy_style.py:53`); `█` is app-prose, not a band glyph.
- **MN-2 (qa m3)** — assert `prg.s19` renders `Entry 0x00000000` (present, zero) as DISTINCT from HEX `Entry —` (absent) at the render layer, not just the field value (folded into AT-066b/AT-066c contrast).
- **MN-3 (qa m4)** — `mac_total==0` → `0 of 0` boundary needs a node (NEW TC on `mac_in_s19_pct`→0.0, no divide-by-zero).
- **MN-4 (security F2)** — map region-inspector hostile-name AT made UNCONDITIONAL (A2L symbol names DO surface via `symbols_in_window`→`symbol_list_text`→`safe_text`, batch-43-hardened); AT-074 gets a C-17 sub-assertion (bracketed symbol name literal in `#map_detail_body`).
- **MN-5 (security F4)** — LLR-069.1/069.3 note: compose the detail card at the `Text` level (append/join `Text`), or any `Static` receiving a composed string sets `markup=False`; never f-string a file-derived value into a markup string.
- **MN-6 (architect F-2)** — LLR-066.5: the two new fields are added **defaulted** after `entropy_windows` (`out_of_order_count: int = 0`, `entry_point: Optional[int] = None`); ~40 non-frozen test `LoadedFile(` sites + `crc.py:1425`/`placeholders.py:67` take the defaults (no frozen test file constructs `LoadedFile` → C-27 stays 0-diff).
- **MN-7 (architect F-5)** — Amendment B (§6.5) enumerates the `MemoryMapPanel` (23 tests) / `RegionRow` (9 tests) interaction tests in `test_tui_directionb.py` for C-26 reverse-census before the map edit.
- **MN-8 (architect F-3)** — origin docs (`prototypes/screen_upgrades.HANDOFF-PLAN.md`, `.NOTES.md`, 20 SVGs) are uncommitted (exist in the main repo working dir, absent from this worktree). **Acknowledged, no-fix:** prototype scratch under the absorb-then-delete convention (handoff §10.4 deletes them post-merge); the §1.4 citations remain as documentary references.
- **MN-9 (qa m5, T-2)** — HEX `.hex` fixture mechanism = inline `IntelHexFile` builder (no `examples/*.hex` added); attaches to Inc-2b, counted in the ≤5-file budget.

---

## Canonical AT crosswalk (orchestrator-pinned — identical in `01` and `01b`)

Every AT drives the shipped screen via `App.run_test()` at **both 80×24 and 120×30**. Provisional node paths (V-5, reconciled Phase 4). Gate-blocking C-17 ATs marked ★.

| Canonical AT | Deliverable (black-box) | Provisional node | Inc |
|---|---|---|---|
| AT-065a | palette applied app-wide | `test_tui_theme.py::test_at065a_palette` | 1 |
| AT-065b | `sev-*` names + semantics preserved (round-trip) | `test_tui_theme.py::test_at065b_sev_semantics` | 1 |
| AT-066a | loader-facts OOO `⚠4 OOO` (prg.s19) | `test_tui_workspace_insight.py::test_at066a_ooo` | 2b |
| AT-066b | entry PRESENT S19 `0x80000000` (case_01); `0x0` renders `0x00000000` not `—` | `…::test_at066b_entry_present` | 2b |
| AT-066c | entry ABSENT HEX `—` (inline hex builder) | `…::test_at066c_entry_absent_hex` | 2b |
| AT-066d | **F-1**: S19 OOO=4 → attach MAC → stats still `⚠4 OOO` + entry preserved | `…::test_at066d_merge_preserves_facts` | 2b |
| AT-067 | memstrip ≥2 band styles + `╱` gap | `…::test_at067_memstrip` | 2b |
| AT-068 | A2L glyph `✓` AND `·` by content | `test_tui_a2l_detail.py::test_at068_glyph_branches` | 3 |
| AT-069 | detail card on NON-default highlight | `…::test_at069_card_highlight` | 3 |
| AT-069b ★ | C-17 A2L card description/unit literal | `…::test_at069b_c17_card` | 3 |
| AT-069c ★ | **M2**: C-17 A2L table-cell name literal | `…::test_at069c_c17_table_name` | 3 |
| AT-070 | MAC `✓` AND `⚠` by content (case_02) | `test_tui_mac_coverage.py::test_at070_glyph_branches` | 4 |
| AT-070b ★ | C-17 MAC name literal | `…::test_at070b_c17_name` | 4 |
| AT-070c | **M1**: MAC parse-error `✗` (+ NEW fixture) | `…::test_at070c_parse_error` | 4 |
| AT-071 | coverage strip `1 of 2` == CoverageMetrics | `…::test_at071_strip` | 4 |
| AT-072a | map ≥2 band styles + `╱` hatch | `test_tui_map_big.py::test_at072a_bands` | 5 |
| AT-072b | ruler exactly 5 ticks; 0%==span start, 100%==span end | `…::test_at072b_ruler` | 5 |
| AT-073 | `N sym` per region == `range_index` count + `↵` | `…::test_at073_sym_count` | 5 |
| AT-074 | inspector hex peek @ NON-first region start (+ MN-4 C-17 name literal) | `…::test_at074_inspector` | 5 |

**19 AT nodes.** C-17 payload set (MD-1) applied to `a2l_injection` + `mac_injection`: `[red]…[/red]`, `[link=http://x]u[/link]`, `\x1b[31mX\x1b[0m`, `sensor[unclosed`.

---

## Increment plan (architect, C-21 re-cut confirmed after AT-set change) — ≤5 files each

| Inc | Story | Files (all non-frozen) | Count |
|---|---|---|---|
| **1** | US-FND | `insight_style.py` NEW · `styles.tcss` · `test_tui_insight_style.py` NEW · `test_tui_theme.py` NEW | 4 |
| **2a** | US-WS data | `models.py` (2 defaulted fields, MN-6) · `services/load_service.py` · `test_tui_workspace_insight.py` NEW | 3 |
| **2b** | US-WS render | `app.py` (titles · `update_sections` · `update_memory_strip` · `#ws_stats` · classed hex · **+MJ-1 merge carry :6954/:6997**) · `test_tui_workspace_insight.py` | 2 |
| **3** | US-A2L | `app.py` (`_build_a2l_table_cells`→`tuple[Text,…]` · detail card · `on_data_table_row_highlighted`) · `test_tui_a2l_detail.py` NEW · `a2l_injection` fixture NEW | 3 |
| **4** | US-MAC | `app.py` (glyph col + coverage strip) · `services/validation_service.py` (strip gating LLR-071.2) · `test_tui_mac_coverage.py` NEW · `mac_injection` + parse-error fixtures NEW | 4 |
| **5** | US-MAP | `screens_directionb.py` (bands · ruler · `RegionRow` enrich · inspector) · `test_tui_map_big.py` NEW | 2 |

`app.py` recurs across 2b/3/4 sequentially (per-increment count governs). Classed-hex (LLR-066.3) may split into a 2c increment if 2b's `app.py` scope is heavy (view-layer styling, `hexview.py` constants untouched).

## Gate axis check
- **Coverage:** dual chains complete; MJ-4 split + MJ-1/MJ-2/MJ-3 new ATs close the C-18 / C-10 / C-17 gaps → every observable owns one node.
- **Certainty:** C-17 negative controls strengthened (MD-1 unclosed-bracket = the `from_markup` counterfactual); C-10 all branches nodalized; geometry structural-invariant.
- **Evidence:** every citation verified; MJ-1 writer-census names the exact drop sites `:6954`/`:6997`.

**Verdict: APPROVE-WITH-FOLDS.** Apply folds to `01`/`01b` (below), then Phase 3 from Inc-1.
