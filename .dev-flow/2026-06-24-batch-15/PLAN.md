# PLAN — 2026-06-24-batch-15 (living compendium)

> Retroactive black-box acceptance closure for the batch-14 escaped-bug gap (2026-06-23 audit, memory `project_blackbox_gap_audit`). English artifacts. Supervised-incremental: ≤5 files/increment, 7-section packet per gate, stop at every boundary.

## Where we are
- **Phase 6 — Documentation (FINAL).** Phase 5 closed clean (PASS, 0 defects). **C-8 applied in-batch** (AT-016.2 fixture-durability guard — 4 ATs still green, ruff clean) + increment-001 §3 doc-fix. C-9/C-10 carried.
- Phases 0-5 done; US-016 only; US-015 deferred. Ledger 894→898; full suite 866/0; 1 production file (`app.py`); 0 frozen edits.
- **Next:** Phase-6 docs (traceability matrix / functionality / diagrams / exec summary) → on approval, state → `awaiting-sync`; then I propose a commit plan (commits still held).

## Carries (→ next batch / follow-up)
C-1 automated dev-flow-sync reject-check · **C-2 audit#2 batch-11 manifest (CONFIRMED LIVE)** · C-3 audit#3 batch-07 report seam · C-4 audit#4 batch-01 evidence · C-5 US-015 forward-feature batch · C-6 retire TC-230/231 ids · C-7 app.py ruff cleanup · C-8 AT-016.2 fixture guard · C-9 hex-window AT obs · C-10 formalize AT-subsumes-TC.

## Commits
- **HELD** per operator hard-rule (commit only when asked). Whole batch uncommitted in working tree: `01/02-requirements/review`, `PLAN.md`, `state.json`, `03-increments/`, `tests/test_tui_diff_compare_realpath.py` (NEW), `s19_app/tui/app.py` (fix), + batch-13 close-snapshot. Commit plan to be proposed at a checkpoint.
- **R-2 now RESOLVED as REACHABLE** (architect verified a concrete degenerate construction) and **D-2 confirmed correct** — the batch premise holds.
- **Sharpened root cause:** genuine fix = *detect the non-raising empty/degenerate map + override the unconditional `sev-ok`*, NOT batch-14's "stop swallowing" (a raise already refuses upstream). Phase-2 majors tighten the AT-016.2 pre-fix-RED oracle so it can't pass for the wrong reason (F-Q-03: must assert `result.refused is False` pre-fix).

## Objective
Close the audit's gap #1 by adding retroactive **black-box** acceptance tests (`AT-NNN`) that observe the user-facing outcome through the shipped surface, each shown FAILING pre-fix. Model the process-hole lesson (batch-14 passed the gate with an empty Phase-4 artifact) in Phase 5.

## Per-story status
| US | Title | Class | DoR |
|----|-------|-------|-----|
| US-016 | A↔B compare reflects genuine diffs / surfaces load failures | **escaped bug (shipped, latent defect)** | **READY → in Phase 1** |
| US-015 | Selectable 16/32 S19 record width + populated S0 | **net-new feature (never built)** | **OUT (deferred)** — own batch later |

## Key Phase-0 findings (disk-verified)
- **US-016 is the genuine escaped bug.** Compare is shipped in `main`; `compare_images`/`diff_mem_maps` are correct. Root cause (per batch-14): display-side `_diff_load_maps` swallows load exceptions → `{}` ([app.py:2181-2182](s19_app/tui/app.py:2181)), rendering a load failure as a false "no diff". The gap: **no test drives the real `#diff_compare_button` → `compare_images`**; every existing diff test fakes the service (`test_tui_diff_screen.py:96`). Surface drivable; absolute tmp paths resolve ([workspace.py:472](s19_app/tui/workspace.py:472)).
- **US-015 is NOT an escaped bug.** The emitter is hardcoded 16-byte rows + empty S0 ([io.py:1471-1473](s19_app/tui/changes/io.py:1471)); no 16/32 selector or populated-S0 path exists anywhere. Building it = new emitter params + S0 capture seam on `LoadedFile`/`load_service` + threading a selector through 2 save flows + a NEW UI control + flipping the default 16→32 (back-compat blast radius). Forward feature work, larger than a retro-AT, with no white-box tests to "escape".

## Roadmap (US-016 only — DoR-approved scope)
- **Phase 1:** derive HLR-016 + LLRs from US-016 (architect) + validation method/thresholds/provisional AT-TC ids (qa-reviewer). Re-measure suite baseline (V-7).
- **Phase 3 (provisional):** Inc 1 — retro AT(s) for US-016 through `#diff_compare_button` (real service, no monkeypatch): (a) two genuinely-different on-disk S19 → ≥1 `changed` run + `sev-ok`; (b) load-failure → `sev-error` diagnostic, no silent clean "no diff". Plus ≤1 display-side fix in `_diff_load_maps` ([app.py:2151](s19_app/tui/app.py:2151)). ≤3–4 files (new/extended test + app.py fix + REQUIREMENTS/traceability). At least one AT shown red pre-fix (evidence captured).
- **US-015 deferred** to its own forward-feature `/dev-flow` batch (batch-14 LLR-015.1–.4 preserved as its starting spec).

## Key decisions
- D-0 (init): batch-15 opened via `/dev-flow-init`; batch-13 closed-snapshot with `obsidian_synced:true` (deferred flip, carry into first commit); previous_batches extended with 13+14.
- D-1 (Phase 0): **US-015 premise corrected** — reclassified READY→REFINE on disk evidence. Scope decision owed at the DoR gate.

## Risks / watch-items
- **R-1:** US-016's "≥1 changed run + sev-ok" assertion may already PASS on `main` (runs come from the correct service, independent of the swallowed `_diff_load_maps`). The pre-fix-failing case is more likely the **load-failure → diagnostic** criterion. Phase 4 captures which fails pre-fix. The story carries BOTH criteria so at least one is red pre-fix.
- **R-2:** If US-015 is built, flipping the emitter default 16→32 may break existing round-trip tests/snapshots that assume 16-byte framing — must measure the blast radius before changing the default.
- **R-3:** Engine-frozen set must not be edited (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`). US-015 S0 emission goes in `tui/changes/io.py`; the S0-capture read uses the frozen reader read-only.

## Conventions honored
- Reader-as-oracle (re-read emitted .s19 via frozen `S19File`, with a negative control).
- Stale-main-ref hygiene: pin the real merge-base for any diff-vs-main gate.
- Behavioral story (the WHAT) + ≥1 black-box criterion before derivation.

## Out-of-scope carries (NOT this batch)
- Audit gaps #2 (batch-11 manifest wiring — confirmed LIVE in Step 0), #3 (batch-07 report-trigger seam), #4 (batch-01 evidence packs) → planned follow-up `/fast-dev-flow` batch.

## Test ledger
- Baseline: RE-MEASURE at Phase 1 (V-7). batch-13 close was 893 collected / 861 full passed — do not assume.

## Decision log (human mirror of state.json)
- 2026-06-24 — batch-15 initialized (phase 0). Stories intook; US-016 READY, US-015 REFINE (premise corrected). Awaiting DoR gate.
