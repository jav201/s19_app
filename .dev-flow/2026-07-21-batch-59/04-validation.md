# Phase-4 Validation — batch-59 (CRC Designer VIEW-FIDELITY rebuild)

> Reviewer: qa-reviewer. Role here: reconcile the two V-model layers over the orchestrator-collected gate run (C-25 — I do NOT re-run the full suite). Branch `feat/batch-59-crc-view` @ `41f5a87`.
> Verdict: **PASS — 0 blockers.** All 11 ATs (AT-B59-01..11) realize to exactly one on-disk, non-vacuous, through-surface node; the F2 dirty-gap window contract is separately locked; every LLR traces to a node; the bidirectional input→deliverable matrix is complete. The only non-green in the gate run is the batch-58 pre-existing snapshot drift, which is not a batch-59 requirement.

---

## BLUF

- **Gate run (orchestrator, one complete run, C-19):** `1772 passed, 2 skipped, 3 xfailed, 19 failed`.
- **The 19 failures are 100% pre-existing batch-58 snapshot drift**, cell-for-cell, and contain **zero CRC content** — independently confirmed below (the tc016s capture set has no `crc` screen; the new `crc-*` classes are scoped to `#crc_designer_panel` with no bleed). Not a batch-59 regression; regen is canonical-CI-only.
- **11/11 ATs REALIZED** (C-18): each maps to one distinct on-disk node driving the whole chain through the shipped `#screen_crc_designer` via Pilot key `0`, and each carries an executed RED→GREEN counterfactual (no vacuous green).
- **Preservation is double-proven:** AT-B59-06 (reused `_recompute` fires through the re-nested tree) + AT-B59-07 (all 20 batch-58 CRC tests green unchanged).
- **Frozen set: 0 diffs.** `git diff main...HEAD` touches only `crc_designer_view.py`, `styles.tcss`, `tests/test_crc_designer_view.py` (+ `.dev-flow/BACKLOG.md` docs). No `core.py`/`hexfile.py`/`range_index.py`/`validation/`/`a2l.py`/`mac.py`/`color_policy.py`/frozen tests touched.

---

## 1. Frozen-set + diff-scope confirmation (recorded per coordinator)

`git diff --name-only main...HEAD`:
```
.dev-flow/BACKLOG.md
s19_app/tui/crc_designer_view.py
s19_app/tui/styles.tcss
tests/test_crc_designer_view.py
```
- **0 engine-frozen files** in the diff (statically confirmed — matches the batch-59 in-scope set §2.4).
- The frozen guards (`tc031`, `test_engine_unchanged.py`) were excluded from THIS gate run to avoid the batch-58-documented `git checkout main` worktree-stranding hazard; they ran GREEN per-increment and the 0-frozen-diff invariant is the static evidence above. **Accepted.**

## 2. The 19-failure classification (pre-existing, non-batch-59)

- **All 19 are `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[...]`:** `workspace/a2l/mac/issues × {compact,comfortable} × {120x30,160x40}` (16) + `map/patch/diff-comfortable-120x30` (3).
- **Independently confirmed CRC-free:** `grep -i crc tests/test_tui_snapshot.py` → **0 matches**. The CRC Designer screen is not in the tc016s capture set, so the new `crc-*` classes (exclusive to `#crc_designer_panel`) cannot bleed into any captured baseline.
- **Matches the batch-58 documented pre-existing drift cell-for-cell** (the 10th-rail-entry drift from batch-58's uncommitted snapshot-regen closeout). This is the SAME set that was already red before batch-59 branched.
- **CI posture:** blocking `tui-ci` (no snapshot plugin) is green; the `snapshot` job is `continue-on-error` advisory. Regen is a **canonical-CI-only follow-up** (`snapshot-regen.yml`, textual==8.2.8) — **local regen FORBIDDEN**. Carried, not a batch-59 gate failure.

---

## 3. Layer B — Behavioral realization (C-18 gate: AT → exactly one on-disk node)

Every node drives the REAL `#screen_crc_designer` through `S19TuiApp.run_test()` + `press("0")` (C-16). "Counterfactual" = the executed property that goes RED on a regression.

| AT | US | On-disk node (`tests/test_crc_designer_view.py`) | Through-surface deliverable observed | Non-vacuous counterfactual (RED when…) |
|----|----|--------------------------------------------------|--------------------------------------|-----------------------------------------|
| **AT-B59-01** | US-L1 | `test_coverage_window_renders_colored_glyphs_with_live_oracles` (:1079) | `#crc_coverage_window.render()` — glyphs + `len({span.style})>=2` + `_render_markup is False` + `.plain` contains BOTH live oracles `0x9C5BCBBD`/`0x2A8A3950` | a hardcoded-hex / monochrome / markup-on window; **wrong-oracle stub proven RED** (B2 teeth) |
| **AT-B59-02** | US-L1 | `test_coverage_window_deltas_and_repins_on_range_edit` (:1108) | window content after a 2-range→1-range edit: DIFFERS **and** re-pins `0x88AA689F` while `0x9C5BCBBD` is GONE | a range-width-only mock that deltas but keeps the stale oracle |
| **AT-B59-03** | US-L2 | `test_bench_columns_pairwise_distinct_ancestors` (:919) | walked `.parent` chain of `#crc_field_width`/`#crc_coverage_ranges`/`#crc_json_preview` → `len(distinct columns)==3` | flat form → all collapse to `crc_designer_panel` sentinel → `len==1` (revert-to-vertical guard) |
| **AT-B59-04** | US-L2 | `test_bench_reflows_to_vertical_stack_when_narrow` (:957) | REAL `run_test(size=(80,24))` toggles `#workspace_body.width-narrow`; geometric `c2.region.y >= c1.y+c1.height`; wide `(130,30)` → same-top, c2 right of c1 | a class-presence-only check; a non-reflowing (crushed) 3-col floor |
| **AT-B59-05** | US-L3 | `test_verdict_hero_center_aligned_in_hero_row` (:993) | `#crc_live_verify.styles.content_align == ("center","middle")` + under `#crc_top_right`, NOT under any bench col + `crc-hero` class + `#crc_kat_verdict` descendant | "border" proxy (every group has a border → FALSE); verdict mis-placed in a bench column |
| **AT-B59-06** | US-L4 | `test_recompute_handler_fires_through_relayout` (:1264) | `#crc_field_xorout`(in `crc_bench_c1`) edit → `#crc_kat_verdict` MATCH→MISMATCH through the re-nested tree | a handler that no longer fires post-re-nest (end-state-only would miss the transition) |
| **AT-B59-07** | US-L4 | **the full 20 batch-58 CRC nodes** (:61–:882), green unchanged in the 1772 | every `query_one("#crc_*")` resolves + every batch-58 behavior (verdict/vector/JSON/Load-Save/coverage/gap/preview-only) | any hidden ancestor-coupling broken by re-nesting (R-1) — none tripped |
| **AT-B59-08** | US-L5 | `test_bench_column_ancestry_teeth_computed` (:1299) | computed `len(bench)==3` vs `len(flat)==1` (same walk, empty column set) — teeth executed, not prose | teeth that cannot be evaluated (prose-only) |
| **AT-B59-09** | US-L1/L5 | `test_coverage_window_hostile_markup_renders_literally` (:1336) | `[link=evil]…[/]` into ranges → `.plain` verbatim + NO `link` span + `_render_markup False` + alive | crash-only boundary; an interpreted markup span (injection) |
| **AT-B59-10** | US-L1 | `test_coverage_window_empty_state_no_image` (:1147) | no `current_file` → shipped "Load an image" note, no glyphs, markup-safe, alive | a crash / glyph-compute on empty; divergent empty-state string |
| **AT-B59-11** | US-L1 | `test_coverage_window_malformed_range_markup_safe` (:1163) | inverted `0x8010-0x8000` → "Invalid coverage" markup-safe note + `mem_map` same object & unchanged | a crash / a mem_map mutation (US-V8 break) |

**Plus the F2 window abort-contract lock** (not a numbered AT but a security-realization node): `test_coverage_window_dirty_gap_abort_refuses_store` (:1229) — clean fill gap EMITS the store word; dirty+`abort` REFUSES and emits NO divergent store word (measured clean→dirty delta), so the window honors the same shipped `evaluate_target` abort contract as the sibling preview (AT-058-08). Counterfactual: a window that emits a store word divergent from the refused preview.

**Realization result: 11 / 11 ATs REALIZED. 0 UNREALIZED (no AT satisfied only "in parts").**

---

## 4. Layer A — Functional traceability (every LLR → a node)

| LLR | Statement (abbrev.) | Realizing node(s) |
|-----|---------------------|-------------------|
| LLR-L1.1 | `_render_coverage_window` builder — live glyphs + pinned oracle hexes, graceful empty note, no new math | AT-B59-01, AT-B59-02 |
| LLR-L1.2 | window widget + `_recompute` wiring (inside the `NoMatches` guard) | AT-B59-02 (delta proves re-render on edit) |
| LLR-L1.3 | color policy binds `$accent-calm` + `.sev-warning`, ≥2 distinct colors | AT-B59-01 (`len({span.style})>=2`) |
| LLR-L1.4 | new-sink boundary + hostile input (markup-safe, no crash, mem_map intact) | AT-B59-09, AT-B59-10, AT-B59-11 |
| LLR-L2.1 | bench composition — 3 columns, existing group ids preserved | AT-B59-03 |
| LLR-L2.2 | bench + reflow CSS (`layout:horizontal` / `width-narrow` → vertical) | AT-B59-04 |
| LLR-L2.3 | hero row `#crc_hero_row` = window + `#crc_top_right`(verify+warnings), NOT in bench | AT-B59-05 (`not under_bench`, `under_top_right`) |
| LLR-L2.4 | reflow driven through a REAL narrow size (no hand-added class, C-16) | AT-B59-04 |
| LLR-L3.1 | verdict-hero styling — `content-align: center middle`, `crc-hero` | AT-B59-05 |
| LLR-L4.1 | ids + handlers unchanged (surgical; only `compose`/`_recompute`+1/new render method) | git diff inspection + AT-B59-06 + AT-B59-07 |
| LLR-L4.2 | full pre-existing suite green | AT-B59-07 (20 batch-58 nodes green in the 1772) |
| LLR-L5.1 | fidelity assertions derive from the tree; pairwise-distinct-ancestor teeth | AT-B59-08 |

**No orphan LLR, no dangling AT.** Both trace chains (US→AT→outcome and US→HLR→LLR→verification) close.

---

## 5. Bidirectional surface-reachability matrix (input dimension → observed deliverable, through the panel)

| Input dimension (driven through the mounted panel) | Observed output / deliverable | Node |
|-----------------------------------------------------|-------------------------------|------|
| Preset select (`#crc_preset_select`) | algorithm fields repopulate + verdict recomputes MATCH | `test_form_and_preset…`, `test_live_verdict_every_preset…` |
| Algorithm field edit (`#crc_field_xorout`) | verdict MATCH→MISMATCH **through the re-nested tree** | AT-B59-06 (:1264) |
| Range edit (`#crc_coverage_ranges`) | coverage window glyphs + oracle hex re-pin (delta) | AT-B59-02 (:1108) |
| Two-range fill target (§3.2 fixture) | window renders live `0x9C5BCBBD`+`0x2A8A3950` + ≥2 colors | AT-B59-01 (:1079) |
| Gap-policy (`join=fill`,`on_gap_conflict=abort`) + dirty gap | window refuses, emits NO store word | F2 node (:1229) |
| Hostile markup range (`[link=evil]…`) | window `.plain` verbatim, no injected span | AT-B59-09 (:1336) |
| No image (`current_file=None`) | window shipped empty-state note, no glyphs | AT-B59-10 (:1147) |
| Malformed/inverted range | window "Invalid coverage", mem_map object unchanged | AT-B59-11 (:1163) |
| Narrow terminal resize (80×24) | bench columns stack (geometric) | AT-B59-04 (:957) |
| Load/Save buttons (col3) | template round-trip + status (batch-58 behaviors) | AT-B59-07 (batch-58 Load/Save nodes) |

Every named input reaches an observed deliverable **through `#screen_crc_designer`**; every named deliverable (window render, verdict, JSON, warnings, refusal, store word) is observed, not merely asserted-present. **Bidirectional reachability: complete.**

## 6. Feedback edges

**None required.** No black-box FAIL exists among the batch-59 set — all 11 ATs + the F2 node are GREEN in the gate run. No Layer-B failure to route back to Layer A.

---

## 7. Gate axis assessment (Coverage / Certainty / Evidence)

- **Coverage — MET.** 5 US → 5 HLR → 12 LLR → 11 AT, both trace chains closed; the bidirectional matrix exercises every input dimension against its deliverable through the shipped surface; the new sink carries empty + boundary + hostile coverage (AT-09/10/11).
- **Certainty — MET.** Every AT node is non-vacuous with an executed RED counterfactual (oracle pins, computed `len==3` vs `len==1`, geometric stacking, verbatim-`.plain`/no-span). Preservation is double-proven (AT-06 + AT-07). C-16 through-surface holds on all nodes; C-17 markup-safety on the new sink is PROVEN (AT-09), not inspection-only. My Phase-2 blockers B1/B2 and majors M1/M2/M3 + minors (AT-09/10/11, qa-m3) are all discharged in the folded spec and realized on disk.
- **Evidence — MET.** One complete gate run (1772 passed) is the primary evidence; the 19 failures are classified pre-existing/non-batch-59 with independent grep confirmation; the 0-frozen-diff invariant is statically confirmed. The RED→GREEN counterfactuals were exercised per-increment (AT-03 flat-form RED, AT-01 wrong-oracle RED, F2 revert RED).

**The bar is met on all three axes.** The single non-green (batch-58 snapshot drift) is not a batch-59 requirement and is carried as a canonical-CI-only regen follow-up.

---

## 8. Verdict

**PASS — 0 blockers, no UNREALIZED AT (11/11 realized).**

Carry-forward (not gate-blocking):
- **Snapshot regen (batch-58 pre-existing drift, 19 tc016s cells):** canonical-CI-only (`snapshot-regen.yml`, textual==8.2.8); local regen forbidden. This predates batch-59 and belongs to the batch-58 closeout carry.
- **qa-m3 (Phase-2 flag), now evidenced GREEN:** styled `rich.Text` spans DO survive `Static(…, markup=False).render()` — AT-B59-01's `len({span.style})>=2` and AT-B59-09's span inspection both pass, so the framework assumption is confirmed, not merely assumed.

Merge gate (per the standing grant): green blocking CI + this validation's PASS. No HIGH finding. Proceed to the FINAL PR-level qa pass over the whole diff before merge.

### Evidence checklist
- [x] One complete gate run recorded, not stitched — 1772/2/3/19 (C-19). ✓
- [x] 19 failures classified pre-existing + CRC-free (grep `crc` in tc016s → 0). ✓
- [x] 0 engine-frozen diffs (git diff name-only). ✓
- [x] 11/11 AT → one distinct on-disk node, through-surface, non-vacuous (C-18). ✓
- [x] Every LLR → a realizing node (Layer A). ✓
- [x] Bidirectional input→deliverable matrix complete. ✓
- [x] No feedback edge needed (no black-box FAIL). ✓
- [x] Gate axes Coverage/Certainty/Evidence all MET. ✓
- [x] No real PII / secrets in test data (synthetic mem_map fixtures). ✓
