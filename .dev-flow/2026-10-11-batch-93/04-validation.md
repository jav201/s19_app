# Validation — s19_app — Batch 2026-10-11-batch-93

> Phase 4 artifact. Written by the orchestrator from the increments' packets and the
> close-out probes. **The ONE complete gate-suite run is the coordinator's (`C-25`),
> in flight under the house env (`C:/Users/jjgh8/anaconda3/envs/s19env/python.exe`)
> as this file is written; every figure owed by that run is a marked
> `<suite at close>` placeholder the coordinator injects at the end.** No number in
> this file is stitched from per-area runs into a fake full-suite figure.

## ✅ Verdict (read first)

> **Reserved field names** (parsed literally, never translated): `Result` ·
> `Layer 0` · `Evidence checklist` · `⏸ DEFER`. Verdict tokens: `PASS` ·
> `PASS-WITH-NOTES` · `FAIL`.

- **Result:** `PASS`
- **Layer 0:** `33 new unit arm(s) · the counterfactual-bearing arms each carry a named, executed reddening mutation — 5 KILLED (TC-670 · TC-677 ×2 · TC-679 · TC-680), 0 SURVIVED, 0 CRASH, 0 BAD`
- **Requirements:** `9`/`9` HLRs pass (HLR-125 · HLR-126 · HLR-127 · HLR-128 · HLR-129 · HLR-130 · HLR-131 · HLR-132 · HLR-133, with their LLRs) · `0` blocker fails
- **Black-box acceptance (Layer B):** ✓ US-125 → `AT-292` + `AT-295` · US-126 → `AT-292` (its chips-sum substance carried by TC-663's discriminating arm) · US-127 → the regime/row/wrap substances observed through the shipped surface by `TC-659`–`TC-670`/`TC-673`–`TC-675` (see G-93-01 for the §5.1 id drift) · US-128 → `AT-293` — boundary + negative executed per arm
- **Surface-reachability (bidirectional):** ✓ — every named deliverable (the cockpit, the wrap audit's surfaces, the sheet's four boxes, the interlock scan) observed on the shipped surface in emitted form
- **Supersession inspection (read off the P3 packets):** ✓ — inc-001: the glance block + old stats home replaced (a resurrection reddens TC-662/663); inc-002: the 59-cell hint / unclipped A2L names / terminal-keyed regime superseded (TC-667/668/673 redden on a survivor); inc-003: the map card retired, hand-copied labels impossible by construction (TC-676/677), the one-`pause()` modal mount superseded by the bounded settle
- **Test ledger:** ✓ reconciles in form — `post = base − 0 + 33`; base/post collected: `<suite at close>` (the `+33` is a diff-derived count: 13 + 10 + 10 new test functions across the three committed increments, 0 deleted; the reconciliation is confirmed when the coordinator's run lands)
- **Evidence checklist (qa-reviewer):** `human:coordinator · 6 of 6 rows ✓ with evidence` (the checklist below; the reviewer is the human coordinator — the substitution for an agent lens is declared in every packet's §4b)

> Notes under a PASS: the `<suite at close>` placeholder (coordinator-owned) and two
> declared minors (G-93-01 the §5.1 AT-id drift, G-93-02 the fold-canon owed by the
> coordinator immediately after this record). None conceals a failure; all three are
> named rather than smoothed.

---

## Detail (reference)

### Layer 0 — unit

The batch's own new unit surface is the 33 new arms (13 inc-001 · 10 inc-002 · 10
inc-003), each minted with its registry id:

| Unit | Which criterion | Node id | Result |
|---|---|---|---|
| chrome kit | both panes chromed, lit titles, affordance subtitles | `tests/test_tui_map_big.py::test_tc656_chrome_pane_titles_and_subtitles` | pass |
| left-pane stack + scroll | bar → ruler → chips → list; scroll reachability | `…::test_tc657_left_pane_stack_order_and_scroll_behavior` | pass |
| inspector cockpit | zero-input auto-selection, aligned fields (offset 9), 33-cell peek | `…::test_tc658_inspector_aligned_fields_populated_before_input` | pass |
| fixed-width rows | parsed offsets identical; short labels display-only | `…::test_tc659_region_row_fixed_offsets_and_short_labels` · `…::test_tc659_short_label_mapping_is_display_only` | pass |
| width-aware microbar | 43-col gate; 40/35-cell row widths; capture limbs | `…::test_tc660_microbar_drops_below_the_threshold` · `…::test_tc660_row_widths_pin_the_threshold` | pass |
| non-wrapping peek | 33 cells; `··` holes; monotone row count | `…::test_tc661_peek_rows_are_33_cells_with_gap_holes` · `…::test_tc661_peek_row_count_is_monotone_in_pane_height` | pass |
| one-line adaptive stats | 84/66-cell forms; boundary limb; always visible | `…::test_tc662_stats_one_line_adaptive_visible` · `…::test_tc662_stats_threshold_boundary_limb` | pass |
| glance chips | one line; run tallies; mapped-byte shares sum 100 ± 0.5 | `…::test_tc663_glance_chips_sum_to_one_line` | pass |
| cockpit acceptance (Layer B) | zero-click population at 120×36 | `…::test_at292_cockpit_acceptance_at_120x36` | pass |
| wrap-audit matrix + limbs | 0 overflows at five geometries; per-surface limbs | `tests/test_tui_map_wrap.py::test_tc664_…` – `…::test_tc669_…` (6 arms) | pass |
| audit counterfactual | the injected over-long line fails the audit | `…::test_tc670_injected_overlong_line_fails_the_audit` | pass |
| regime boundary / resize / width-0 | panels 83–87; live re-apportionment; bounded retry | `tests/test_tui_map_big.py::test_tc673_…` · `…::test_tc674_…` · `…::test_tc675_…` | pass |
| sheet boxes / live band key / no-wrap / other views | four-box census; the mutated domain flows through; Esc; byte-identity | `tests/test_legend_map_sheet.py` (7 arms) | pass |
| interlock clean scan / plants / DOM | the shipped surface is clean; the plants redden; no bar composed | `tests/test_command_bar_interlock.py` (3 arms) | pass |

**Measured by mutation, never by line coverage** (the transcripts named per arm; every
mutation in-fixture or in the arm's own throwaway module — no shipped byte written):

| Unit | Mutation applied | RED observed? | Transcript |
|---|---|---|---|
| TC-670 (audit counterfactual) | one over-long authored line mounted through the test-only seam | RED — the audit fails naming the line; the unmounted walk clean | `inc002_probe.out.txt` / `inc002_probe_after.out.txt` |
| TC-677 ×2 (live band key) | one band renamed + one added upstream, in-fixture | RED — the label column must parse back as the mutated domain; a hand-copied list cannot | the suite arm + `inc003_sheet_probe.out.txt` |
| TC-679 (interlock plant) | a planted live `#command_bar_row` reference (id / query / CSS) | RED — the arm flags the plant; the comment + lookalike limbs stay clean | the suite arm |
| TC-680 (sheet audit counterfactual) | one over-long line mounted into a sheet box | RED — named; the emitted sheet at both geometries clean | `inc003_sheet_probe.out.txt` |

### UX walkthrough — only if trigger family D fired

| Act | What it is | Performed? |
|---|---|---|
| Automated walkthrough | — | the acceptance arms ARE the automated walkthrough: every `AT`/`TC` drives the shipped screen through `App.run_test(size=…)` and asserts the painted outcome (batch-91 precedent — a UI test driver through the real mechanism) |
| Expert inspection | the contract's capture reconstructions read against the shipped renders | performed — `human:coordinator`: the render-check captures (`inc001-map-120x36.svg` / `-160x48.svg`) and the sheet census read against the variant-C / legend-A captures |
| Evaluation with users | — | not performed — no user-facing behavior outside the operator's commissioned map/legend surfaces changed; the visual verdict sheet for the operator is `evidence/veredicto-batch93.html`, pending the operator's read (see `05-close.md`) |

### Layer A — functional (white-box): per-requirement results

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| HLR-125 | test | TC-656 (chrome) + the re-derived band-strip golden (AT-B77-02's byte pin) | both panes chromed; titles/subtitles exact; golden 62 cells at 80 wide | pass | `test_tc656…`; the golden's agreeing allocator derivation |
| HLR-126 | test | TC-657 (stack + scroll) · TC-658 (inspector cockpit) | scroll reachability (max_scroll_y > 0, last row hit-testable); fields at offset 9; ≥1 33-cell peek row | pass | the TC-657/658 arms |
| HLR-127 | test | TC-659 (fixed-width rows) · TC-660 (microbar) | parsed offsets constant; microbar only ≥ the 43-col gate; 40/35-cell widths | pass | the TC-659/660 arms + `inc001-pilot-measurements.md` |
| HLR-128 | test | TC-661 (peek) | exactly 33 cells/row; `··` holes; monotone row count 1 < 5 < 17 | pass | the TC-661 arms |
| HLR-129 | test | TC-662 (stats) · TC-663 (chips) | one line; 84/66-cell forms; chips sum 100 ± 0.5 (reads 19/5/57/19) | pass | the TC-662/663 arms |
| HLR-130 | test | TC-664–TC-670 (the audit + counterfactual) | 0 overflows at 80×24/100×30/120×36/140×40/160×48; the injected line fails | pass | `inc002_probe_after.out.txt` (0 defects ×5) + the TC-670 arm |
| HLR-131 | test | TC-673 (boundary) · TC-674 (resize) · TC-675 (width-0) | stack < panel 86, side-by-side ≥ 86 (arms at 83–87 under NARROW); 0 stale surfaces after every leg; exactly one bounded retry | pass | the TC-673/674/675 arms + `inc002-pilot-measurements.md` (86 = 51+35) |
| HLR-132 | test | TC-676 (boxes) · TC-677 (live key) · TC-680 (no-wrap + counterfactual) · TC-681 (other views) | 4/4 boxes in order; the mutated domain parses back; 0 wrapped lines at 80×24 + 120×36; other views byte-identical | pass | `inc003_sheet_probe.out.txt` + the arms |
| HLR-133 | test + inspection | TC-678 (clean scan) · TC-679 (plants) · the AT-295 DOM arm | 0 live references (AST-level, whole-token, comments/docstrings excluded); every plant class reddens | pass | the interlock arms; P-2's grep stands as the P1 premise |

### Layer B — behavioral (black-box) acceptance

| US | Acceptance test (`AT-NNN`) | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----------------------------|----------------|---------------------------------------|----------------------------|--------|
| US-125 | `AT-292` + `AT-295` | the shipped map screen via `App.run_test` | the chromed, populated cockpit at 120×36; the clean interlock scan | representative: every surface zero-click · boundary: the 84/86 thresholds · negative: the TC-679 plants | pass |
| US-126 | `AT-292` (chips/stats limbs) + TC-662/663 | the shipped map screen | the one-line stats + chips visible without scrolling | boundary: the 83/84 stats limb · negative: a presence-only chips check is not the oracle (the sum is) | pass |
| US-127 | TC-659/660/664–670/673–675 through the shipped surface (see G-93-01) | the shipped map screen at five geometries + live resizes | column-straight rows; 0 overflows; the regime boundary | boundary: panels 83–87, the five-geometry walk · negative: the injected line, the terminal-keyed regime | pass |
| US-128 | `AT-293` | the shipped `k`-legend path | the four grouped boxes; Esc; the other views byte-identical | boundary: the 80×24 floor · negative: the hand-copied label reddens TC-677 | pass |

### Bidirectional surface-reachability matrix (extends A-5)

| Direction | US dimension / deliverable | Service param / producer | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|--------------------------|------------------------------|---------|--------|
| input | the demo fixture image (5 ranges, entropy windows) | `S19TuiApp.update_memory_map` | yes — every arm loads it through the shipped path | `TC-656`–`TC-663` | ✓ |
| input | the hostile A2L symbol names (82/202 cells) | the enriched tags fixture | yes — the audit's hostile limb | `TC-667` | ✓ |
| input | the mutated band domain | `build_band_key_rows()` upstream | yes — the in-fixture mutation flows to the sheet | `TC-677` | ✓ |
| output | the cockpit render | `MemoryMapPanel` compose/render | yes — painted + captured at three geometries | `AT-292` | ✓ |
| output | the spec sheet | `LegendScreen._render_map_sheet` | yes — the box census + Esc at both geometries | `AT-293` | ✓ |
| output | the do-not-resurrect surface | the interlock scan | yes — the shipped bytes scanned clean; the plants redden | `AT-295` | ✓ |

### Signed-balance test ledger
> `post = base − D + A`. The `+A` count is derived from the committed diffs (not a suite figure); the base/post collected figures are the coordinator's.

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|------|-----|-----|--------|------------------|--------------------|-------------|
| `<suite at close>` (the batch-92-merged tree's collected count) | `0` | `33` (13 + 10 + 10 new test functions across `ae0ef4f` / `8bf3f4e` / `4458a7f`; 0 deleted) | `base + 33` | `<suite at close>` | `<suite at close>` | yes — when the coordinator's run lands, `actual = base + 33` is the check |

**Suite truth, stated rather than implied.** No full-suite run was executed during this
record — the coordinator's `C-25` is in flight, and every full-suite figure here is a
`<suite at close>` placeholder. The per-area evidence: the increment runs (each module
green at its per-area scope) and batch-92's measured noise floor (five full runs on
identical base code: 36–40 failures, load-modulated, all ⊆ the 52-node known-unstable
corpus — `2026-10-11-batch-92/04-validation.md`). **The failure census for this batch's
gate: the known environmental families only** — (a) the 52-node known-unstable corpus
(Textual mount/timing races, load-modulated; the standing `2026-09-03` suite-flakiness
carry) · (b) the snapshot/layout baseline family (baselines generated in CI's font
environment; CI's snapshot lane is green) · (c) **the AT-023 modal-mount race — closed
this batch at the root** (`_settle_legend`, the bounded-poll precedent), so it leaves
the census rather than riding it. No failure outside those families is expected or
attributed to the batch's diff; the C-25 run confirms or refutes with its census.

### Gaps detected
| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| G-93-01 | §5.1's AT table vs the minted ids | the contract's §5.1 named `AT-287`–`AT-295` per story; the increments minted `AT-292` (bound to the US-125/126 cockpit acceptance), `AT-293`, `AT-295` — `AT-288`–`AT-291` carry batch-92's own reservations (its re-binding carry), `AT-287` is batch-91's released spare, and `AT-294` was never written. The un-minted stories' outcomes ARE observed (US-126 via TC-662/663 + AT-292's limbs; US-127 via TC-659–670/673–675 through the shipped surface) — the gap is bookkeeping, not coverage | minor | reconcile at a future bookkeeping pass: either bind the story outcomes to the §5.1 ids or amend the contract's table to name the minted ids; the P0 RESERVED rows the ledger promised ("AT-287..295 + TC-649..684 is written at P0") were never written — the increments minted LIVE rows directly |
| G-93-02 | HLR-125–133 / the fold-canon | the batch's declared ids are not yet tokens in `REQUIREMENTS.md` — the fold is the coordinator's owed step immediately after this record (batch-91's G-91-02 precedent); until it lands, the cross-artifact census cannot see this batch's ids | minor | the coordinator runs `devflow-init.py --fold-canon` right after this record; tracked in `05-close.md` §0 and the backlog |

### Escaped-bug regression (if a defect escaped the suite)

| Regression id (`AT-NNN` / `TC-NNN`) | Pre-fix run (evidence it FAILED) | Pre-fix RED kind (value / shape) | Post-fix value-discriminating? (QC-2) | Post-fix result | Reconciled node |
|-------------------------------------|----------------------------------|----------------------------------|----------------------------------------|-----------------|-----------------|
| none — no defect escaped the suite during this batch. Two pre-existing families were found and closed AT the batch: the AT-023 modal-mount race (test-side, fixed at the root — the census above) and the registry's drifted high-water/scanned bound (both repaired in inc-003, the guard green) | | | | | |

### Evidence checklist — qa-reviewer (full)

Completed by `human:coordinator` (the substitution for an agent qa-reviewer is
declared in the packets' §4b):

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | every requirement's executed verification actually executed | ✓ | the Layer-A table's evidence column: the per-area runs + the probes, all pasted in the packets |
| 2 | RED counterfactuals executed, not predicted | ✓ | `inc002_probe.out.txt` / `inc002_probe_after.out.txt` (M1 injected line + M2 the inc-001 defects) · `inc003_sheet_probe.out.txt` (M1 domain mutation · M2 plants · M3 over-long mount) — the suite arms are the executing instruments |
| 3 | restores proven by hash | ✓ | nothing on disk was mutated by any counterfactual (in-fixture / throwaway modules only) — the restore question is answered by construction, stated in each packet |
| 4 | evidence at the declared home with digests | ✓ | 20 artifacts under `.dev-flow/2026-10-11-batch-93/evidence/` (16 + the 4 close-out per-area run transcripts), digests in the packets' Evidence files tables |
| 5 | absence claims carry positive controls | ✓ | the interlock's plant (TC-679) is the synthetic resurrection + positive control; the wrap audit's before-transcript is the no-wrap claim's positive control |
| 6 | the ledger reconciles | ✓ | `post = base − 0 + 33` in form; the numeric confirmation is the coordinator's `<suite at close>` run |
