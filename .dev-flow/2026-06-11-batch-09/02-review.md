# Review — s19_app — 2026-06-11-batch-09

Phase-2 cross-agent review of `.dev-flow/2026-06-11-batch-09/01-requirements.md` (Phase-1 iteration 2: 5 HLR / 25 LLR / TC-001..025, probes P-01..P-18, §6.4 audit F-1..F-6, risks R-1..R-9, gate-confirmables G-1..G-8). Reviewers in parallel, adversarial, 2026-06-11: architect (derivation/contradictions/audit-mechanics/contract/anchors/new-rules), qa-reviewer (testability/probe-reexec/coverage/reconciliation), security-reviewer (the routed G-5 out-of-workarea write surface + standard surfaces).

## Verdict summary

| Reviewer | Blockers | Majors | Minors | Verdict |
|---|---|---|---|---|
| architect | 0 | 1 (F-A-01) | 2 | PASS w/ 1 major to fix |
| qa-reviewer | 0 | 2 (F-Q-01, F-Q-02) | 3 | majors to fix before Phase 3 |
| security-reviewer | 0 | 2 (F-S-01, F-S-02) + 1 medium (F-S-03) | 1 | **OK-with-mitigations** |

**Consolidated: 0 blockers / 5 majors / 6 minors.** No blocker → no forced iteration per the dev-flow rule; but all 5 majors are the "claimed-but-not-landed-in-the-binding-body" class the doc's own header rules police, and all are cheap spec edits with NO design change. Orchestrator recommends iterate-to-fix.

## Majors

**M-1 (F-A-01) — LLR count stated as 22; actual is 25.** §1.5 and §5.3 say "22 LLRs" / "22 of 22 covered"; enumerating `### LLR-` headings gives 5+6+4+6+4 = **25**. The §5.2 coverage table DOES cover all 25 (coverage is fine) — but §5.3 is a gate acceptance criterion ("100% of LLRs covered"), so a wrong denominator is a count-integrity failure of the exact class the parent-HLR-reread discipline targets. **Fix:** 22→25 in §1.5 and §5.3 (and the "21 draft +1" arithmetic → "24 draft +1 = 25"; verify the draft baseline).

**M-2 (F-Q-01) — Placeholder-pinned test census (R-8 / P-16) is INCOMPLETE.** R-8 pins the supersession set to TC-027 family (`test_tui_directionb.py:3383-3487`) + AST guard (`:3606-3623`), but `test_tc028_every_scaffold_screen_activates_without_error` (`:3628-3666`) asserts `#diff_deferral_notice` present (`:3656`) — it pins the `DEFERRAL_TEXT` that LLR-005.2 removes and sits OUTSIDE both cited ranges. qa measured: 7 placeholder-pinned tests collect green; the true breaking set is 5 (4 TC-027 + this one), not the doc's named set. An unpredicted red breaks R-8's own "red state must match predicted set" gate check. **Fix:** add `:3628-3666` to R-8 + P-16 with its disposition; state whether the AST guard at :3605 stays green (it may, if rewritten `_compose_screen_diff` still only builds `AbDiffPanel`).

**M-3 (F-Q-02) — §5.3 suite-count reconciliation `≥733 + N` is incoherent with R-8 deletions/rewrites.** The lower-bound formula assumes additivity, but R-8 rewrites/deletes existing tests (rewrite-in-place adds 0; deletion subtracts). Post-batch collection can be BELOW 733+N. The doc claims it "accounts for rewrite-vs-delete" but gives no formula — the batch-07 V-3 / batch-08 DEV-1 "claimed but not mechanically pinned" class. **Fix:** restate as a signed balance `post = 733 − D + A` (D = placeholder tests deleted from the R-8 census, A = net-new functions), reconciled at Phase 4 against the I4 packet's disposition table.

**M-4 (F-S-01) — `sanitize_project_name` is a NAME-component cleaner, not a PATH validator (SECURITY).** LLR-004.6/D-8/R-9 say the G-5 destination validator "reuses the sanitization class of `sanitize_project_name` (`workspace.py:315`)". Verified LIVE: that function strips every non-`[alnum_-]` char from a single token — applied to a path it turns `C:\Users\jjgh8\out` into `CUsersjjgh8out`. It is structurally incapable of validating a directory path. This is the name-sanitizer-as-path-validator gap the surface was routed to catch — landed in the spec's own G-5 fix. **Fix:** replace the citation with a concrete algorithm: `Path(operator_input).expanduser().resolve()` (collapses `..`+symlinks) → require `is_dir()` → write `dest / <tool-generated-timestamp-filename>` (no operator string in the filename component). Drop `sanitize_project_name` from the path-validation path.

**M-5 (F-S-02) — Collision counter (LLR-004.1) not bound to the no-project / operator-path branch (SECURITY).** LLR-004.1's no-silent-overwrite counter is scoped to `<project>/reports/`; LLR-004.6 (no-project branch) does not state it applies, and TC-025 checks "exactly 1 file written" but not no-overwrite of a pre-existing Downloads file. R-9's mitigation column CLAIMS the counter applies but no §3/§4 body line binds it — the Parent-HLR-reread failure mode applied to a security guarantee. **Fix:** add to LLR-004.6 Statement that the no-project write uses the LLR-004.1 collision discipline (never overwrites); add a TC-025 sub-case (pre-create the target, assert a `-01` sibling + original untouched).

## Medium / notable

**M-6 (F-S-03, major→medium) — Downloads default is a guessed write location.** `Path.home()/"Downloads"` on this operator's OneDrive-redirected profile (worktree is under `C:\Users\jjgh8\OneDrive\…`) may resolve to the wrong-but-real dir, or be absent (the dir-exists gate safe-fails that case → refusal). Not an off-machine leak; a localized-disclosure / "where did it go" hazard. Mitigations already in spec: dir-exists gate + LLR-005.4 full-path status display. **Operator decision (G-8):** keep implicit Downloads default, or prompt-only (drop the guess — an operator-typed path is auditable, a guessed one is not). Security recommends prompt-only.

## Minors

- **m-1 (F-A-02):** `VariantDescriptor.file_type` cites `models.py:56` (class line); field is `:77`. Re-cite.
- **m-2 (F-A-03 / F-Q-05):** screen name "A2B Diff" (literal rail label `rail.py:85`) vs prose "A↔B Diff" — use the literal where any AC/test asserts the string; demo step "press 7" is correct, optionally add "(or rail `D` shortcut)".
- **m-3 (F-Q-03):** LLR-005.2 pass-condition "0 diff-placeholder hits in the AbDiffPanel block" is asserted via a whole-file `rg -c PLACEHOLDER` (pre-state 15 includes 3 non-block hits at `:23/:315/:322` that must survive). Replace with a named-constant probe: `rg -n '_RANGE_LIST_PLACEHOLDER|_HEX_A_PLACEHOLDER|_HEX_B_PLACEHOLDER|DEFERRAL_TEXT' → 0` post-Phase-3.
- **m-4 (F-Q-04):** TC-001/002/003 share LLR-001.2; pin in §5.2 which property each owns (classification set-equality / adjacency-merge / boundary cases) so Phase 3 can't collapse three into one assertion.
- **m-5 (F-S-04):** "reject path traversal" is under-specified after `resolve()` (which already collapses `..`); the no-project write is intentionally unconfined (no base), so reframe to "normalize via resolve() → require existing dir → no operator string in filename"; define the base for a relative operator path (cwd vs repo root).

## CLEAN checks (verified, with evidence)

- **Anchor hygiene:** 30+ citations grep-verified exact (architect) incl. AbDiffPanel `screens_directionb.py:849`, rail diff entry `rail.py:85` (8 entries), range_index primitives `:9/:39/:71`, report_service reuse points, workspace helpers `:315/:321/:376/:457/:469`, hexview caps, load_service builders, conftest `make_large_s19:70`; exceptions = m-1/m-2 only. NEW-flag compliance: compare.py / compare_service.py / diff_report_service.py + DIFF_REPORT_FILENAME_REGEX / list_diff_reports all absent-on-disk and NEW-flagged; no fabricated symbol asserted as existing.
- **§6.4 audit mechanical (F-1..F-6):** every "Body edit landed?" pointer resolves to real body text; F-5/F-6 correctly assert "no §3/§4 body edit (confirmation)". No dangling pointer → no blocker.
- **Contract-touch C-9 (independent re-run, both architect + qa):** ComparisonResult field set = {image_a/image_b, runs, stats, notes, diagnostics, refused} = 6 rows; the G-5 destination is a `generate_diff_report` arg/return (via `diagnostics`), NOT a result field; G-2 annotation reads existing runs/notes, adds nothing. **Field-set identity holds: 0 added, 0 removed.**
- **NEW-rule compliance (both adopted this batch):** AC-artifact rule — every AC-named artifact (examples dirs P-12, no-`.hex` P-03, make_large_s19 P-15, Downloads default P-18) carries an executed probe or NEW flag; probe-regime rule — P-10/P-11/P-17/P-18 positive controls in-regime with regime recorded.
- **Probe re-execution (qa):** P-01 (733 collected), P-03 (0 `.hex`), P-07 (15 PLACEHOLDER), P-09 (3 regex hits), P-12, P-15 (perf same order, ~10-16× headroom, @slow correctly required), P-16 cited ranges all reproduce.
- **Normative discipline:** 0 `should` inside any §3/§4 statement (independently grepped); EARS shape; every test/analysis label carries Executed verification + Numeric pass threshold; node ids flagged provisional (A-3).
- **Method viability:** rail-screen run_test pilot idiom confirmed (not modal); no TC implies a NEW SVG snapshot (CI-regen constraint respected); coverage table NO node-id drift §4↔§5.2 (no batch-08 DEV-1 recurrence).
- **Security clean surfaces (F-S-05..09, LIVE-verified):** no-logging confidentiality (LLR-004.5, `report_service.py:32-36` + 0 getLogger); input trust (externals via `resolve_input_path` read-only existence-checked, in-project via existing loaders, no new parser/encoding); no new deps/network/subprocess; render caps (REPORT_MAX_TOTAL_BYTES=2MB `:79`, per-report cap precedent `:72`, hex windows MAX_HEX_ROWS=512) bound the file; inline selector path goes through `resolve_input_path` read-only. The G-5 surface is operator-initiated with no body-byte logging.

## Gate

0 blockers → iteration NOT forced. The 5 majors (M-1..M-5) are all spec-substance "claimed-but-not-landed" edits with NO design change and NO requirement-shape change (5 HLR / 25 LLR stand); 2 of them (M-4/M-5) are security controls on the operator's G-5 write surface. One operator decision attached: M-6/G-8 — implicit Downloads default vs prompt-only. Orchestrator recommends: iterate to fix M-1..M-5 + fold the minors; operator answers G-8.

---

## Re-confirmation — iteration 3 (2026-06-11; operator: iterate + G-8 = solo-prompt)

Architect applied the full register. **11/11 findings CLOSED** (5 majors, medium/G-8, 5 minors) body-first with §6.4 audit rows F-7..F-17 (F-series continued — G-* would collide with the operator gate-confirmables).

- **M-1:** LLR count 22→25 in §1.5 + §5.3 ("25 of 25"); draft baseline corrected to 24+1. Orchestrator re-verified: `### LLR-` headings = 25, §1.5 = 25, §5.3 = 25, no live "22 of 22" (the one remaining "22" is the F-7 audit row recording the fix). F-7.
- **M-2:** R-8 + P-16 census extended with `test_tc028_every_scaffold_screen_activates_without_error` (`:3628-3666`, `#diff_deferral_notice` `:3656`); predicted-red set 4→5; AST guard `:3605` recorded as STAYS-GREEN-if-only-AbDiffPanel (not in breaking set). F-9.
- **M-3:** §5.3 reconciliation rewritten as signed balance `post = 733 − D + A`, reconciled at Phase 4 vs the I4 disposition table, off measured-733 (P-01). F-8.
- **M-4 (security):** `sanitize_project_name` REMOVED as path validator from LLR-004.6/D-8/R-9; replaced with `Path(...).expanduser().resolve()` → `is_dir()` → `dest / <tool-generated filename>` (no operator string in filename). Orchestrator re-verified all 5 remaining `sanitize_project_name` mentions are historical/explanatory (removal record, not live use). F-10.
- **M-5 (security):** LLR-004.1 collision discipline bound into LLR-004.6 statement; TC-025 sub-case (c) added (pre-create target → `-01` sibling, original untouched, 0 overwrites). F-11.
- **M-6/G-8 (operator solo-prompt):** implicit Downloads default DROPPED everywhere (HLR-004, LLR-004.6, D-8, R-9, G-5/G-8 RESOLVED, P-18 annotated historical, TC-025 branches now valid-dir / empty-or-invalid-refused / collision). Cross-platform Downloads concern is now moot. F-12.
- **m-1..m-5:** field-line re-cite (`models.py:77`), literal "A2B Diff", named-constant placeholder probe (P-07 revised, executed: 8 in-block hits pre-state), TC-001/002/003 property split, traversal reframed to resolve()+is_dir()+no-operator-filename with relative base = app cwd. F-13..F-17.

**C-9 contract re-check (M-5 touched producer LLR-004.6):** field-set identity UNCHANGED, 0 added/removed — destination/collision/diagnostic are `generate_diff_report` arg/return, not ComparisonResult fields. Canonical 6-field set holds.

**Orchestrator self-check:** 25 LLR headings = §1.5 = §5.3; 0 `should` in statements; 0 mojibake; 11 F-rows present. **0 open findings.** Document ready for the Phase-2 re-confirmation gate.
