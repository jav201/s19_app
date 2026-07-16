# Validation — s19_app (Textual TUI) — Batch 47 (screen-upgrades Batch A)

> Phase 4 artifact. Owner: `qa-reviewer`. Executes the validation strategy fixed in Phase 1
> (`01-requirements.md` §5 + `01b-qa-strategy-and-verification.md`) against the canonical AT
> crosswalk (`02-review.md`). Artifact language: English.
> **Reconciliation basis:** orchestrator-owned CI-equivalent gate run `pytest -q -m "not slow"`,
> tree HEAD = `12c5d1c` (the same tree this file reconciles against). qa-reviewer did NOT re-run the
> full suite; it grep-reconciled every AT/TC to a real collected node and confirmed the frozen-guard
> and color_policy 0-diff at HEAD.

## ✅ Verdict (read first)

- **Result:** **PASS.** No `iterate-to-fix` / `iterate-to-refine` triggered — 0 black-box FAIL.
- **Requirements:** 10/10 HLR (065–074) pass · 0 blocker fails. Every LLR (065.1–074.3) has ≥1 green node.
- **Black-box acceptance (Layer B):** ✓ all **20 canonical ATs** observe their deliverable through the SHIPPED screen (`App.run_test`), each reconciled to **exactly one** on-disk collected node, each executed at **both 80×24 and 120×30**. Boundary + C-17 negative controls present.
- **Surface-reachability (bidirectional):** ✓ every named input dimension AND every output/deliverable exercised/observed through the handler/screen, not the service API.
- **Frozen-guard (C-27 dual-guard):** ✓ `git diff --stat main` **empty** for the frozen src set AND the 9 frozen test files at HEAD `12c5d1c`; `color_policy.py` 0-diff under the sev-* restyle.
- **Authoritative gate:** `1416 passed, 2 skipped, 20 deselected, 32 xfailed, 1 warning` — **exit 0, 0 failed** (17:35). 32 xfailed = 29 batch-47 theme-drift tc016s cells (all `xfail(strict=False)`) + 3 pre-existing.
- **Amendments:** §6.5 A–E all recorded. **Evidence checklist (qa-reviewer):** ✓ complete.

> Every line ✓. The Detail below is the reconciliation record.

---

## 1. Layer B — black-box acceptance reconciliation (the C-18 gate: one AT → one node)

Each AT drives the shipped screen via `App.run_test(size=…)` and asserts the observed deliverable in
the rendered widget content. **Both pilot sizes execute inside the single node** (verified: `_SIZES =
((80,24),(120,30))` loop in `test_tui_a2l_detail.py:43`, `test_tui_mac_coverage.py:49`,
`test_tui_map_big.py`, and per-size `@parametrize` in `test_tui_workspace_insight.py`). Every node
below was **grep-confirmed present + collected** at HEAD `12c5d1c`; each is part of the `1416 passed`
(none xfailed/skipped/deselected). No AT is "covered in parts."

| # | Canonical AT | Real `file::node` (grep-confirmed) | C-17 gate | Deliverable observed (surface) | repr·bound·neg |
|---|---|---|---|---|---|
| 1 | AT-065a | `tests/test_tui_theme.py::test_at065a_palette` (L236) | — | Screen bg == DEPTH_BG + `.db-pane` bg == DEPTH_PANEL, app boots | ✓·✓·n/a |
| 2 | AT-065b | `tests/test_tui_theme.py::test_at065b_sev_semantics` (L272) | — | live `sev-error` resolves pastel RED + `css_class_for_severity` round-trip (all 5) | ✓·✓·✓ |
| 3 | AT-066a | `tests/test_tui_workspace_insight.py::test_at066a_ooo` (L168) | — | `#ws_stats` contains `⚠4 OOO` (== 4) | ✓·✓·n/a |
| 4 | AT-066b | `…::test_at066b_entry_present` (L189) | — | `#ws_stats` renders `Entry 0x80000000`; `0x0`→`0x00000000` present-not-`—` | ✓·✓·✓ |
| 5 | AT-066c | `…::test_at066c_entry_absent_hex` (L219) | — | HEX (inline `IntelHexFile`) → `Entry —` at render layer | ✓·✓·✓ |
| 6 | AT-066d | `…::test_at066d_merge_preserves_facts` (L248) | — | S19(OOO=4)→attach MAC → `#ws_stats` STILL `⚠4 OOO` + entry preserved | ✓·✓·✓(counterfactual) |
| 7 | AT-067 | `…::test_at067_memstrip` (L290) | — | `#ws_memstrip` ≥2 band styles `{· ░ ▒ ▓}` + ≥1 `╱` gap | ✓·✓·n/a |
| 8 | AT-068 | `tests/test_tui_a2l_detail.py::test_at068_glyph_branches` (L204) | — | `#a2l_tags_list` glyph col shows `✓` on `in_memory` AND `·` on not — both branches by content | ✓·✓·✓ |
| 9 | AT-069 | `…::test_at069_card_highlight` (L225) | — | non-default row highlight → card shows THAT tag's description+unit | ✓·✓·n/a |
| 10 | **AT-069b ★** | `…::test_at069b_c17_card` (L260) | **C-17** | full MD-1 payload verbatim in card `Text.plain`, no payload span, no `MarkupError` | ✓·✓·✓ |
| 11 | **AT-069c ★** | `…::test_at069c_c17_table_name` (L294) | **C-17** | hostile A2L NAME verbatim in table cell `Text.plain` (distinct sink), `spans==[]` | ✓·✓·✓ |
| 12 | AT-070 | `tests/test_tui_mac_coverage.py::test_at070_glyph_branches` (L131) | — | `#mac_records_list` shows both `✓` (in-image) and `⚠` (out) by content (`case_02`) | ✓·✓·✓ |
| 13 | **AT-070b ★** | `…::test_at070b_c17_name` (L152) | **C-17** | hostile MAC name verbatim in `Text.plain`, no `red`/`link` span, no `MarkupError` | ✓·✓·✓ |
| 14 | AT-070c | `…::test_at070c_parse_error` (L192) | — | parse-error MAC record → `✗` glyph (NEW inline malformed fixture) | ✓·✓·✓ |
| 15 | AT-070d | `…::test_at070d_mac_only_unchecked_glyph` (L223) | — | MAC-only parse-ok record → `·` grey (not false-green `✓`) — Inc-5 C-10 4th branch | ✓·✓·✓ |
| 16 | AT-071 | `…::test_at071_strip` (L271) | — | `#mac_coverage_strip` contains `1 of 2` == `CoverageMetrics` | ✓·✓·n/a |
| 17 | AT-072a | `tests/test_tui_map_big.py::test_at072a_bands` (L92) | — | band strip ≥2 styles + ≥1 `╱` hatch (`case_02`, 4 ranges) | ✓·✓·n/a |
| 18 | AT-072b | `…::test_at072b_ruler` (L121) | — | ruler exactly 5 ticks; first==span start, last==span end | ✓·✓·n/a |
| 19 | AT-073 | `…::test_at073_sym_count` (L153) | — | per-region `N sym` == independent `range_index` oracle + `↵` | ✓·✓·✓ |
| 20 | **AT-074 ★** | `…::test_at074_inspector` (L201) | **C-17 sub** | non-first region activate → hex peek first addr==region start; bracketed A2L symbol verbatim in `#map_detail_body` | ✓·✓·✓ |

**Reconciliation result: 20/20 canonical ATs realized to exactly one collected on-disk node.** No AT
covered-in-parts; no orphan; no missing node. (Canonical set = 19 base nodes from `02-review` +
`AT-070d`, the Inc-5 C-10 fourth-branch addition self-owned by its increment — no orphan.)

**C-17 gate-blocking set — all present and green:** AT-069b (A2L card), AT-069c (A2L table cell),
AT-070b (MAC name), plus AT-074's mandatory C-17 sub-assertion (map inspector, MN-4). All four assert
the full MD-1 payload set `[red]…[/red]` · `[link=http://x]u[/link]` · `\x1b[31mX\x1b[0m` (ANSI) ·
`sensor[unclosed` (the unbalanced-bracket `Text.from_markup` counterfactual) renders **verbatim** in
`Text.plain` with no payload-derived span and no `MarkupError`. Increment packets 04/05/06 captured
the verbatim proofs (`spans==[]` on the table cell; `sensor[red]` verbatim in `#map_detail_body`).

---

## 2. Layer A — white-box functional reconciliation (every LLR has a green node)

Provisional `TC-NNN` ids from `01b` reconcile to the real nodes below. **Reconciliation note (V-5):**
the three C-17 white-box TCs (`TC-067.3`/`TC-067.4`/`TC-068.4`) and several renderer facets
(`TC-066.4`/`.5`, ruler/sym/inspector) were **folded into the black-box AT node** (one node per
observable, per C-18) rather than duplicated as separate white-box nodes. This is a fold, not a gap —
every LLR still lands on ≥1 green node.

| LLR | Green node(s) | Method |
|---|---|---|
| 065.1 | `test_tui_insight_style.py::test_palette_constants_present_and_correct` (L42) | inspection/unit |
| 065.2 | `…::test_human_bytes` (L63) · `test_microbar`/`test_microbar_returns_text` (L87/110) · `test_label_value_returns_text` (L121) · `test_threshold_style` (L139) | unit |
| 065.3 | `test_tui_theme.py` invariant guard (TC-065.5, TC-012/013 preserved) + AT-065a | inspection/pilot |
| 065.4 | `test_color_policy_round_trip.py` (FROZEN, green) + AT-065b + §6.5 Amendment C | round-trip |
| 066.1 | pane border titles — snapshot cell + AT-066 setup (WS compose) | pilot/snapshot |
| 066.2 | section rows — `test_tui_directionb.py::test_at040a` (retargeted to `insight_style.microbar`) | pilot |
| 066.3 | `test_tui_hexview_classed.py` — 7 TCs incl. `test_tc066_6_printable_ascii_class_boundaries` (edge-pinned) | pilot |
| 066.4 | AT-066a/066b/066c (loader-facts value + entry render branches) | pilot |
| 066.5 | `test_ooo_count_populated` (L86) · `test_entry_point_s19` (L98) · `test_entry_point_hex_none` (L113) · `test_fields_default_on_bare_construction` (L138, MN-6) | unit |
| 066.6 | markup=False inspection (Inc-3); loader-facts carries numeric/hex only | inspection |
| 066.7 | AT-066d `test_at066d_merge_preserves_facts` (writer-census, MJ-1) | pilot |
| 067.1/.2/.3 | AT-067 + `test_tui_directionb.py::test_at040b` (retargeted to Amendment-A band contract + fallback) | pilot |
| 067.4 | Inc-3 C-29 structural invariant (both-axes) | analysis |
| 068.1 | `test_cells_are_text_and_glyph` (L324, all-16-cells-`Text`) + AT-068 | unit/pilot |
| 068.2 | `test_summary_count` (L347) | unit |
| 068.3 | AT-069c (table-cell C-17, distinct sink) | pilot(hostile) |
| 069.1 | AT-069 + widget-name inspection (only new member `show_tag`; no `_nodes`/`_context`) | pilot/inspection |
| 069.2 | AT-069 (`on_data_table_row_highlighted` handler) | pilot |
| 069.3 | AT-069b (card C-17, composed at `Text` level) | pilot(hostile) |
| 069.4 | Inc-4 C-29 measured (`#a2l_hex_pane` card h=5, hex not occluded @80×24) | analysis |
| 070.1 | AT-070 (✓/⚠) + AT-070c (✗) + AT-070d (·) — 4-way glyph | pilot |
| 070.2 | AT-070b (MAC name C-17) | pilot(hostile) |
| 071.1 | AT-071 + `test_build_mac_coverage_strip_counts` (L299) | pilot/unit |
| 071.2 | AT-071 + `test_zero_total_no_divzero` (L290, MN-3 boundary) | pilot/unit |
| 072.1 | AT-072a (bands + `╱` hatch) | pilot |
| 072.2 | `human_bytes` unit + AT-073/074 humanized read-outs | unit/pilot |
| 072.3 | AT-072b (5-tick ruler + endpoint values) | pilot |
| 072.4 | §6.5 Amendment B (band-bands extension recorded) | inspection |
| 073.1 | AT-073 (`N sym` == independent `range_index` oracle; no linear scan) | pilot/inspection |
| 073.2 | AT-073/074 (`↵` present; `RegionRow.Activated`→`OpenInHexRequested` reused, directionb green) | pilot |
| 073.3 | Inc-6 C-29 measured (region-list `height:auto`, reachable-under-scroll) | analysis |
| 074.1 | AT-074 (inspector span/size/band + peek) | pilot |
| 074.2 | AT-074 (peek first addr == region start; ≤3 rows) | pilot |
| 074.3 | AT-074 MN-4 C-17 sub-assertion (`symbols_in_window`→`symbol_list_text`→`safe_text`) | inspection/pilot(hostile) |

**Result: 0 LLR without a green node.** Key spot-verifications confirmed: derived-field TCs
(066.5 all present + green), C-17 TCs (folded to AT-069b/069c/070b/074, green), classed-hex TC-066.6
(7 nodes incl. the boundary node `test_tc066_6_printable_ascii_class_boundaries`), and the geometry
items (067.4/069.4/073.3 realized as Phase-3 pilot measurements → structural ATs, per C-29).

---

## 3. Bidirectional surface-reachability matrix (extends A-5)

Every named input dimension AND every output/deliverable is exercised/observed **through the shipped
screen/handler** (`App.run_test`), not only the service API.

| Dir | Dimension / deliverable | Producer / handler | At surface? | Node |
|---|---|---|---|---|
| input | loader-facts — S19 entry PRESENT branch | `build_loader_facts_text` → `#ws_stats` | yes | AT-066b |
| input | loader-facts — HEX entry ABSENT branch | inline `IntelHexFile` → `#ws_stats` | yes | AT-066c |
| input | loader-facts — merge-carry (attach MAC) | `_merge_*` (app.py:6954/6997) → `#ws_stats` | yes | AT-066d |
| input | memstrip entropy bands + gap | `update_memory_strip` → `#ws_memstrip` | yes | AT-067 |
| input | A2L glyph — in_memory True/False | `_build_a2l_table_cells` → `#a2l_tags_list` | yes (both) | AT-068 |
| input | A2L row highlight (operator-selectable) | `on_data_table_row_highlighted` → card | yes | AT-069 |
| input | A2L table-cell hostile name (C-17) | `_build_a2l_table_cells` | yes | AT-069c |
| input | MAC glyph — ✓/⚠/✗/· 4-way | `_populate_mac_datatable` → `#mac_records_list` | yes (all 4) | AT-070/070c/070d |
| input | MAC hostile name (C-17) | Tag cell `Text().append` | yes | AT-070b |
| input | map region activate (non-first, selectable) | `on_region_row_activated` → `#map_detail_body` | yes | AT-074 |
| output | `#ws_stats` loader-facts line | `build_loader_facts_text` | observed | AT-066a/b/c/d |
| output | `#ws_memstrip` banded/gapped strip | `update_memory_strip` | observed | AT-067 |
| output | A2L table cells + glyph + summary | `_build_a2l_table_cells` / `#a2l_tags_summary` | observed | AT-068 / `test_summary_count` |
| output | `A2LDetailCard` body | `_a2l_detail_card_text` | observed | AT-069 / AT-069b |
| output | `#mac_coverage_strip` `X of Y` | `build_mac_coverage_strip` | observed | AT-071 |
| output | `MapRuler` 5 ticks | `MapRuler` widget | observed | AT-072b |
| output | `RegionRow` `N sym` + `↵` | `_build_region_row` | observed | AT-073 |
| output | `#map_detail_body` inspector + hex peek + C-17 | `on_region_row_activated` / `_region_hex_peek` | observed | AT-074 |
| output | app-wide theme + sev-* round-trip | `styles.tcss` + `css_class_for_severity` | observed | AT-065a / AT-065b |

**No gap in either direction.** Every input branch has a content-asserting AT; every deliverable is
observed at the mounted node (not the service return value).

---

## 4. Drift accounting

The Textual snapshot plugin reports **29 mismatched snapshots**. These are the batch-47 app-wide-theme
+ per-screen tc016s density-matrix cells, **all marked `xfail(strict=False)`** — they are **xfails, not
failures** (whole-suite `exit 0` confirms; Inc-8 snapshot run: `3 passed, 29 xfailed, 0 unexpected
failures`, **0 xpassed** → a theme-invariant cell would have xpassed; none did → the census is complete
and non-masking).

**29 batch-47 theme-drift cells (per-increment C-22 census):**

| Group | Cells | Marked in |
|---|---|---|
| workspace | 6 | Inc-3 `_batch47_workspace_drift_marks` |
| a2l | 6 | Inc-4 `_batch47_a2l_drift_marks` |
| mac | 6 (4 wide @Inc-5 + mac-80×24 ×2 @Inc-8) | Inc-5 + Inc-8 |
| map | 2 | Inc-6 `_batch47_map_drift_marks` |
| issues (parked, shared-chrome) | 6 | Inc-8 `_batch47_theme_drift_marks` |
| diff (shared-chrome) | 1 | Inc-8 |
| patch (parked, shared-chrome) | 2 | Inc-8 |
| **Total** | **29** | — |

**3 pre-existing xfails** (identified on `main`, outside the batch-47 marks): `test_tui_app.py:1784`,
`test_tui_public_api.py:162`, and `test_validation_engine.py:211` (the frozen-test known xfail). A
fourth pre-existing marker (`test_tui_snapshot.py:516`) is either deselected under `-m "not slow"` or
xpasses — the authoritative gate reconciles to exactly **32 xfailed = 29 batch-47 theme-drift + 3
pre-existing**. Exact identity of the residual 3 is not load-bearing: all pre-date batch-47 and none is
a batch-47 regression.

**Snapshot regen is a canonical-CI-only follow-up PR** (`snapshot-regen.yml`, textual==8.2.8), NOT a
batch-47 failure. Local regen is prohibited (`reference_snapshot_regen_env` — local textual drift
corrupts unrelated baselines). The 29 stale baselines still encode pre-theme hues by design; they
regenerate post-merge and retire the `_batch47_*_drift_marks` together.

---

## 5. Feedback edges

**NONE triggered.** There is no black-box FAIL: all 20 ATs are green, each realized to a single
collected node, at both pilot sizes, with boundary + C-17 negative controls. Therefore:

- **`iterate-to-refine` (P1, requirement defect):** not triggered — no AT exposed a requirement gap.
- **`iterate-to-fix` (P3, impl defect):** not triggered at the Phase-4 gate. (The two mid-increment
  iterate-to-fix loops — Inc-5 F1 false-green MAC glyph → `AT-070d`; Inc-4 severity-vs-accent →
  Amendment E — were resolved **within their increments** before the gate, not deferred here.)
- **No escaped-bug regression** required — no defect escaped the suite into Phase 4.

---

## 6. Frozen-guard + amendment closure

**C-27 dual-guard — 0-diff held at HEAD `12c5d1c` (verified this session):**
`git diff --stat main` is **empty** for the frozen src set (`core.py`, `hexfile.py`, `range_index.py`,
`validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) AND for the 9 frozen test files.
Every increment ran `test_tc027` + `test_tc031` + `test_tc032` green (Inc-1…8 packets). The sev-*
pastel restyle (Inc-8) is **CSS-only** — `color_policy.py` (the sev→class map + `css_class_for_severity`
round-trip) is **0-diff**, and `test_color_policy_round_trip.py` (frozen) stays green. Non-frozen
homes only: no NEW test landed in a frozen file (C-27 dual-guard intent held).

**§6.5 amendments recorded (A–E):**

| Amendment | Subject | Status |
|---|---|---|
| A | Workspace memstrip adds entropy coloring (HLR-067) | recorded |
| B | Memory-Map band-bands extended: ruler + hatch + humanized (HLR-072, amends R-TUI-060/041) | recorded |
| C | sev-* hue restyle to pastel (LLR-065.4) — 5 classes, families+names+`color_policy` preserved | **realized Inc-8, table filled** |
| D | `human_bytes` binary (1024, KiB/MiB) convention (LLR-065.2) | operator decision, applied Inc-1 |
| E | A2L per-cell accents subsumed by the severity contract (LLR-068.1) | surfaced Inc-4 |

No locked requirement was silently edited; each amendment carries a Before/After block with parent-HLR
re-read (`feedback_requirement_amendment_before_after`).

---

## 7. Evidence checklist — qa-reviewer

- [x] **Acceptance criteria use Given/When/Then** — `01b` §3 AT registry; each AT here traces to it.
- [x] **Test cases have explicit Expected, not vague "works"** — every AT row states the content asserted (`⚠4 OOO`, `1 of 2`, exact address, verbatim payload), not "non-empty".
- [x] **Edge cases include empty, boundary, invalid, error** — `01b` §5 per story; realized (e.g. `test_zero_total_no_divzero` boundary, AT-070c invalid/parse-error, C-17 error class).
- [x] **Regression checklist exists** — TC-FRZ.1/2 (frozen guards, 0-diff at HEAD) + TC-REG.1 (full suite green 1416 pass) + per-increment C-26 reverse-census (all green).
- [x] **Exit criteria stated** — `01-requirements.md` §5.3 / `01b` §10; all met.
- [x] **No real PII / secrets** — public `examples/` fixtures + synthetic injection payloads only.
- [x] **Test-results left blank unless actually run** — N/A: the gate WAS run (orchestrator C-25, exit 0); results are cited, not fabricated.
- [x] **Layer B black-box** — all 20 output-producing observables driven through the shipped screen (`App.run_test`) with boundary + C-17 negative evidence (§1).
- [x] **Bidirectional surface-reachability** — every input dimension AND deliverable reached/observed at the handler/screen (§3), not the service API.
- [x] **No unfilled template** — no `<…>` placeholders, no `TC-NNN` stubs; every node is a real grep-confirmed `file::node`.
- [x] **Frozen 0-diff verified** — `git diff --stat main` empty for src + 9 test files at `12c5d1c` (§6).

---

## 8. Gate verdict

**Axis check:**
- **Coverage:** ✓ 20/20 ATs realized single-node (both regimes); 100% LLR → ≥1 green node; C-10 all
  branches nodalized (entry present/absent, MAC ✓/⚠/✗/·, A2L in/out); C-17 4 sinks gate-green;
  bidirectional reachability complete.
- **Certainty:** ✓ AT-066d/AT-070d are genuine counterfactuals; C-17 ATs discriminate via the
  unbalanced-bracket `from_markup` counterfactual + `spans==[]`; C-29 geometry MEASURED both axes
  (not assumed) → structural invariants that hold at any geometry; classed-hex edges pinned.
- **Evidence:** ✓ frozen 0-diff + color_policy 0-diff verified at HEAD; gate `exit 0, 0 failed`;
  drift fully accounted (29 xfail-not-fail + 3 pre-existing); every node grep-confirmed collected.

**Phase 4 PASSES.** 0 failed, all 20 ATs realized to a single on-disk node at both pilot sizes, dual
traceability (behavioral + functional) complete, frozen guards + `color_policy` 0-diff intact, snapshot
regen correctly deferred to canonical CI. No feedback edge triggered. → Phase 5 (post-mortem).
