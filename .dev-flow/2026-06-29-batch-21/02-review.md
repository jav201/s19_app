# 02 — Cross-agent review — batch-21 (#8 slice 1: US-026/027/029)

> Phase 2. Three reviewers in parallel (architect ∥ qa ∥ security) against Phase-1 `01-requirements.md`.
> **Outcome: 0 blockers. architect PROCEED · qa PROCEED · security GRANTED-after-fold.** 1 factual correction + 6 AT/LLR tightenings + 1 LOW security fold — all applied body-first. Reconciliation audit in §6.4.

## Verdicts
| Reviewer | Verdict | Blocker | Major | Minor/LOW |
|---|---|---|---|---|
| architect | PROCEED | 0 | 2 | 3 |
| qa-reviewer | PROCEED | 0 | 3 | 4 |
| security-reviewer | GRANTED-after-fold | 0 | 0 | 1 LOW (+3 PASS) |

## Two-layer review (blocker gate) — all PASS
- (a) every story has a black-box AT (AT-031*/030*/032*). (b) every output-producing req names its deliverable + oracle (on-disk `patches/*.json`; Select options + loaded doc; rendered label). (c) both chains present. (d) ATs are black-box (drive the shipped Patch Editor, assert deliverables, no internal symbol).

## The headline finding (architect MAJOR-1) — factual correction, no design change
Change-file saves currently land in the **workarea ROOT** (`placement(staged, workarea)` io.py:1352), NOT `temp/` (`temp/` is staging-only, cleaned). The spike's §2.5 was imprecise. Consequences folded:
- The fix is root→`patches/`, same one-liner (`placement(staged, workarea / WORKAREA_PATCHES)`).
- **R1 RESOLVED:** no existing test asserts `temp/` (or the root by exact path) — the `test_unified_write.py::test_tc018_*` placement tests assert containment under `workarea/` generically, which `patches/` satisfies → **suite stays green, zero edits**. So Inc1 **must add a NET-NEW positive placement TC** or the move is silently unverified (AT-031a's counterfactual couldn't go RED).
- R3 corrected: orphaned files are in the root (default save target), not `temp/`.

## qa findings (AT tightenings, all folded)
- **major-1:** AT-031b assert two DISTINCT on-disk names (no-clobber inherited from `copy_into_workarea` — pin it).
- **major-2:** AT-030a deterministic sort + select-by-known-filename (glob order FS-dependent).
- **major-3:** AT-030a producer = `save_doc` (change-doc write), NOT the save-back image prompt — testability trap.
- **major-4 (verified, no fold):** AT-030c guard structurally can't satisfy the C-12 gate (reverted save → AT-030a RED, AT-030c GREEN). ✓
- minors: on-screen-save refresh sub-assertion (R2); key-token-span assertion for AT-032a; method column sound.
- Harness capability grounded: `test_tui_patch_editor_v2.py` proves all needed Pilot moves (drive `save_doc`, `rglob` on-disk files, `query_one`, read `label.render()`, `Button.press`).

## security findings — GRANTED-after-fold
- **F1 (LOW):** read path (`read_change_document`→`resolve_input_path`) has NO containment/symlink guard (size-cap only) — a symlinked `patches/` entry would be followed on load. **Net-neutral vs the existing typed-path Load** (read-only, parse-only, size-capped), so LOW not blocking. **Fold (Inc2, LLR-030.3):** Select from `match.name` + `is_relative_to(patches_dir)` assert (+ optional symlink skip) before `service.load`.
- **F2 PASS:** write path stays containment-safe under `patches/` (`_safe_name` + `copy_into_workarea` unchanged).
- **F3 PASS:** Select renders raw filename (no markup injection; unlike batch-19 the string is a FS-constrained filename, not free operator text).
- **F4 PASS:** no new external-action/network/secret surface (local-FS workarea only).

## Supersession census (change-first) — CLEAR
`write_change_document` placement move → no caller/test breaks (generic containment). New `Select`/`set_change_files` → bare `PatchEditorPanel()` stays valid (empty option set). `run_checks` consumer (`app.py:1421`) untouched. `WORKAREA_PATCHES`/`set_change_files` net-new. 0 engine-frozen edits.

## Fold disposition
All folds applied body-first to `01-requirements.md` (§2.5, §3 HLR-031, §4 LLR-031.1/.2 + LLR-030.3, §5.2 AT-031b/AT-030a + functional TC, §6.2 D1, §6.3 R1/R3/R4) + audited in §6.4 with 3 Phase-3 watch-items (W1 allow_blank, W2 empty-set invariant, W3 key-token assertion). No blocker → no iterate-to-refine.
