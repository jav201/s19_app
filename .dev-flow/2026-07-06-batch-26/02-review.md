# 02 — Cross-agent review — 2026-07-06-batch-26

> **Verdict: NO BLOCKERS from any reviewer.** 3 reviewers (architect · qa-reviewer · security-reviewer), read-only, over `01-requirements.md` + `01b-validation-strategy.md`. Findings: 0 blocker · 5 major · 6 minor — **all additive spec-tightening, no derivation defect, no scope change, no new external surface.** Disposition below; all majors + minors FOLDED before Phase 3 (§Fold log). Band cutoffs verified consistent across all 4 locations; 7/7 architect citation spot-checks hold; all 16 LLRs have ≥1 covering TC.

## BLUF per reviewer
- **architect:** No blockers. Derivation clean (3 HLR↔3 US, 16 LLR all parent-traced, no orphan/overreach/double-barrel). `shall`-only grep clean (0 modal misuse). 7/7 citations hold. 2 major completeness gaps (cost-cap not normative; modal mid-view image change) + 3 minor wording.
- **qa-reviewer:** No blockers. **LLR→TC coverage audit PASSES — all 16 covered.** ATs non-vacuous (exact H/band/count), counterfactuals real, C-12 honored. Fixtures verified against `conftest.py` (all generators random-fill → tiny-dict approach sanctioned). 3 major test-tightenings + 3 minor.
- **security-reviewer:** Security-clean, 0 blocker/major. Local single-user tool; scalar/label output less sensitive than existing hexdumps; write stays handler-owned (no new I/O → no symlink vector); no free-text into entropy path (no scrub to bypass); frozen oracles untouched. 1 P3 hardening (cost-cap → `shall`, = architect major #1).

## Findings + disposition

| # | Sev | Reviewer | Location | Issue | Disposition |
|---|-----|----------|----------|-------|-------------|
| M1 | major | architect + security(F5) | R-4 / LLR-036.2 | Strip/jump cost-cap is a prose risk-note, not a normative `shall` — could be silently dropped; huge image → unbounded cells. | **FOLD** → new **LLR-036.6**: `shall` cap `ENTROPY_STRIP_MAX_CELLS` / `ENTROPY_MAX_ROWS` + truncation notice (mirror `MAX_HEX_ROWS`), with `TC-036.5` on the `large_s19` stress fixture. |
| M2 | major | architect | HLR-036 / LLR-036.2 | Modal behavior if `mem_map` reloads/clears under an open viewer is unspecified. | **FOLD** → LLR-036.2: the modal renders a **snapshot taken at push time** (does not live-track `mem_map`); recorded as explicit non-goal. |
| M3 | major | qa | LLR-036.4 | `e`-binding has black-box coverage only (AT-036a); no white-box TC pins the registration — the silent-unbind regression class that hit PRs #37/#38. | **FOLD** → new **TC-036.4**: assert `"e" in S19TuiApp.BINDINGS` → `action_show_entropy`. |
| M4 | major | qa | AT-037a / QR-4 | `capture_mem_map` mitigation defends silently-empty but not the inverse (fixture populates `result.mem_map` off the shipped chain → formatter verified, plumbing not). | **FOLD** → AT-037a: drive real variant-execution with `capture_mem_map=True` + **precondition assert** `result.mem_map` non-empty *before* report gen. |
| M5 | major | qa | TC-035.2 / QR-2 | Exact `H==7.2` not integer-constructible; "nearest constructible" blurs whether the `≤`-side at 7.2 is pinned. | **FOLD** → TC-035.2: call the band-classify function with **literal floats** `7.1999 / 7.2 / 7.2001` (decoupled from histogram) so the cutoff side is pinned exactly. |
| m1 | minor | architect | HLR-035 vs LLR-035.1 | Top band written open-ended (`H≥7.2`) in HLR but closed `(7.2, 8.000001)` in LLR — cosmetic (H≤8.0 always). | **FOLD** → LLR-035.1 note: `8.000001` is a headroom sentinel guaranteeing H==8.0 ∈ `high/random`; HLR references the `ENTROPY_BANDS` cutoffs. |
| m2 | minor | architect | LLR-037.3 | "same byte budget" — hexdump `.extend`s raw at :1146; entropy must route through `emit()` (:1130-1132) to actually consume `budget`. | **FOLD** → reword LLR-037.3 to emit via `emit()`, inserted after the `_hexdump_section` block (:1145-1147). |
| m3 | minor | architect | LLR-036.3 | C-13 `assumed per-regime` hedge under-commits; 48/76 voids if the new screen uses a different box model. | **FOLD** → LLR-036.2 **mandates** `EntropyViewerScreen` reuse the `.modal-dialog` box model exactly (invariant); R-3 re-measure kept as fallback only. |
| m4 | minor | qa | LLR-035.5 | Purity probe (`rg import textual → 0`) floats in prose, unbound to a TC id. | **FOLD** → new **TC-035.7** (purity probe) in the traceability grid. |
| m5 | minor | qa | AT-037b | Promises "byte-identical" off-branch but asserts only "byte-plausible" — weaker than LLR-037.3's threshold. | **FOLD** → AT-037b asserts byte-for-byte equality vs a pre-feature reference report when `include_entropy=False`. |
| m6 | minor | qa | §5.1 / LLR-036.1 | Method mismatch: §5.1 says `inspection` for the colour map, but §2 upgrades to `test` (TC-036.1) — the map is a pure dict, `test` is feasible. | **FOLD** → reconcile LLR-036.1 + §5.1 to `test` (TC-036.1); drop `inspection`. |

## Category clean-passes (explicit)
- **shall/should normative:** clean — 0 modal misuse inside any HLR/LLR statement (architect grep-confirmed).
- **Derivation:** clean — no orphan LLR, no US-less HLR, no double-barrelled requirement.
- **Band-cutoff consistency:** clean — half-open `[lo,hi)`, value-at-cutoff→higher band, verified across §2.6 / HLR-035 / LLR-035.1 / 01b QC-3; H==8.0 → high confirmed.
- **Citations:** 7/7 architect spot-checks hold on disk (`models.py:44/46`, `screens.py:475`, `report_service.py:197/231-235/1139-1147/1157-1158/907`, `app.py:683`+`e` absent, `core.py:503-514/676-678`, `hexview.py:317-320`).
- **LLR→TC coverage (V-5):** all 16 LLRs covered (qa audit table); 2 soft spots (035.5 purity, 036.4 binding) closed by M3+m4 folds.
- **AT vacuity (C-10):** clean — exact assertions, real counterfactuals, AT-037b correctly branch-completeness not sole gate.
- **Fixtures:** clean — `make_large_s19`/`make_ranged_s19` both random-fill; no exact-H fixture exists; tiny-dict approach sanctioned (mirrors `MEMORY_OVERLAP_PAIR`/`memory_change_factory`), not a CLAUDE.md large-builder violation.
- **Security:** clean — handler-owned write, scalar output, no free-text, no symlink vector, frozen oracles untouched.

## Control watch
- No new control encoded this batch (candidates all already-encoded rules working: C-13 measurement caught nothing new because geometry was measured; C-12 held; C-15 e-key clean). The silent-unbind class (M3) is exactly what C-15 exists for — M3 is C-15 doing its job at review time.
