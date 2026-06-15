# Post-mortem — s19_app — 2026-06-14-batch-11 (US-010 project.json manifest writer + verify-on-write)

Co-authored: architect (process half) + qa-reviewer (validation half), merged by orchestrator, 2026-06-15.

**One-line takeaway (lineage):** b08 AC-artifact + probe-regime · b09 census-completeness + gate-as-requirement-validation · b10 census=completeness-PRINCIPLE / ban-VERIFIED-COMPLETE / 4th guard family · **b11: the batch-10 census correctives had their first clean run (recurrence prevented, but NOT stress-tested — no b11 file was ever near the frozen set); the genuinely new lesson is SCOPE-1 — a half-delivered user story (writer supports batch/assignments, the TUI save composes none) that passed 23/23 TC + full suite because coverage was structured around the WRITER'S API, not the USER'S story. Detection must extend from structural invariants to coverage TOPOLOGY: every story-named input dimension must be exercised through the shipped surface.**

---

## PROCESS HALF (architect)

### A. What worked — the corrective-loop validation (the b10 → b11 headline)
The A-1/A-2/A-3 rules adopted from batch-10's post-mortem had their first real run, and the loop closed — with one honest caveat.
- batch-10's I1 hit a frozen-engine blocker (emitter planned into `hexfile.py`; census had no engine-frozen family) → I1 redo. batch-11 ran the change-first census at Phase 1 (§6.3.3) over the planned file list against ALL 5 families incl. (d) engine-frozen, with the A-3 new-symbol probe on the only edited existing file (`app.py`), honestly **NOT stamped "VERIFIED COMPLETE"** (named the residual (N+1)-family risk, assigned completeness to the I-gate). **Phase 3 had ZERO frozen-guard blockers** — the exact b10 recurrence prevented.
- **Honest caveat (don't over-claim):** the census was NOT stress-tested. `manifest_writer.py` was always going to be `tui/services/` (writer-home D-3), never plausibly near the frozen set; the reader oracle is also non-frozen. Loop validated as *not-broken*, not *under load*. True test = a batch whose change genuinely abuts frozen code (candidate: the CRC fill-in if it touches `core.py` checksum). → A-4.

### B. The reader-as-oracle pattern — 3rd consecutive use, now a named idiom
b09 (compare diffs vs mem_maps) · b10 (emitter round-trips vs `IntelHexFile`) · b11 (manifest writer round-trips vs `read_project_manifest`). The writer never invents its own correctness oracle — the existing reader IS the spec. Architecturally right here because the engine readers are git-frozen, so anchoring writers to them prevents representation drift. **Recurring trap (bit again at Phase 2):** the oracle's OUTPUT representation ≠ the writer's INPUT representation — b11 B-1 = relative POSIX strings vs resolved absolute Paths; if the equality threshold doesn't pin which form, the primary acceptance criterion is unpassable-or-vacuous (batch-07 B-4 class). Fix: canonical comparison form (intent resolved vs project_root before compare, `test_variant_execution.py:163` idiom) inherited into C-1/glossary/HLR-001/LLR-001.3/LLR-003.1. → A-1 (promote to named KEEP idiom).

### C. Detection shifted left (vs batch-10)
b10's analogous seam (emitter frozen placement) was caught at the **I1 GATE** (post-Phase-1/2, forced an I1 redo). b11's root seam (writer-relative vs reader-resolved-at-fixed-name) was caught at **Phase 2 cross-review**, before code. Mechanism: change-first census priming + 3 independent reviewers converging on one root seam (architect raised qa's candidate to blocker B-1; security hit the same seam from the input side → M-3; contract-touch identity confirmed keys matched, isolating representation as the variable). All 3 substantive findings (B-1+M-1+M-2) = one root seam, fixed in 1 iteration; M-3 a clean security add. → A-2 (KEEP the 3-reviewer wave on any writer-with-a-reader-oracle).

### D. SCOPE-1 — the genuine open question
Writer complete (serialize/write/verify all handle batch/assignments, TC-001a..003c). But the TUI save handler (`_persist_project_manifest`, app.py:3575-3593) calls `write_project_manifest(variant_set, project_dir, base_dir)` with NO batch/assignments kwargs → saved `project.json` carries `active_variant` + EMPTY batch/assignments. US-010's benefit ("variant/A2L/MAC COMPOSITION AND active-variant selection … from the tool") is **met at the active-variant level; the composition half is built-but-not-wired.** Honest read: a **Phase-1 requirements-completeness gap** (HLR-004's LLRs pinned "invoke + surface", not "compose batch/assignments from the save flow"), not a code defect (the impl is spec-conformant) and not creep — the V-model's traceability surfaced it cleanly. **Batch-12 disposition: IN as lead story** — smallest, highest-leverage increment to convert US-010 from half- to fully-delivered; substrate already proven. → A-3.

### E. Metrics
| Metric | Value |
|---|---|
| Iterations/phase | P1=2 (draft + B-1/M-* seam fix), P2=1+re-confirm, P3=4 increments, P4=1 |
| Phase-2 findings | 1 blocker / 3 majors / 7 minors; 11/11 closed in 1 iteration (B-1+M-1+M-2 = one root seam; M-3 security add) |
| Detection locus | Phase 2 (vs b10 I-gate) — shift-left confirmed |
| Ledger | 816→826→831→835→839, D=0; signed-balance 839=816−0+23 exact; cleanest D=0 chain in the lineage |
| File budget | I1-I4 all ≤5 (2/2/2/3) |
| Code defects | 0 (PASS-WITH-NOTES; all notes doc/product) |
| Template generation | 9th; no new failure-corrective needed — controls held; only a new IDIOM (A-1) to codify |

---

## VALIDATION HALF (qa-reviewer)

### Wins (evidence-cited)
- **W-1 M-1 two-saves-one-file** (`test_two_saves_leave_exactly_one_manifest_second_wins`): non-vacuous — the zero-`project_1.json` clause FAILS the instant the writer dedup-suffixes (the M-1 defect); tests the observable consequence (one file, fixed name, latest wins) not the mechanism, so it survives an atomic-primitive swap but catches any re-suffixing. AST census backs it (0 live copy_into_workarea, 2 os.replace).
- **W-2 R-1 reader-issues⇒mismatch** (`test_reader_issues_force_mismatch_even_if_surviving_keys_match`): plants the HARD fault — `drift==[]` (surviving keys equal) yet non-empty reader issues → asserts MISMATCH. Proves the `not drift AND not issues` conjunction is load-bearing (delete `not issues` → this test reds, all equality tests stay green). Textbook Rule-9.
- **W-3 canonical-name re-read** (`test_verify_reads_canonical_name_not_a_stray_suffixed_file`): stray `project_1.json` with a different active_variant → verify reads canonical name, returns VERIFIED ignoring the stray. Differential-by-construction (re-reading the writer-returned path would corrupt the compare).
- **W-4 escape-refusal input gate** (`test_refuse_escape_and_absolute_entries_writes_nothing`): two attack vectors (`../../x` + absolute) → `(None,[findings])`, each offending entry named, zero files written; positive control (`test_clean_composition_passes_the_gate`) proves non-trivial. Closes M-3.
- **W-5 B-1 fix is a real test** (`test_roundtrip_equals_intent_in_canonical_form`): resolved-vs-resolved equality in code (`manifest.batch == [(project_dir/e).resolve() for e in intended]`), the discriminator against the B-4 unpassable/vacuous class.
- **W-6 signed-balance D=0 exact** (839=816−0+23): cleanest in the lineage; D proven by `git show origin/main:<file> → absent`, A by per-file `--collect-only`; no fudge term.

### Leak analysis + the SCOPE-1 validation angle
0 behavior leaks. DEV-1 (V-5 renames — by design), DEV-2 (over-coverage +6 — net-positive). **SCOPE-1 is the one validation-relevant finding and it is a COVERAGE-TOPOLOGY gap:** the writer's batch/assignments coverage all enters via direct kwargs (TC-001a..003c); the I4 TUI pilots assert the save writes+verifies a manifest but NONE asserts a non-empty batch/assignments round-trip through the SAVE path. The two coverage sets are **disjoint exactly along the dimension where the gap lives** — every TC exercising batch/assignments bypassed the user surface, every TC using the user surface passed them empty. 23/23 green + full suite green precisely because coverage was structured around the writer's API, not the user's story. Catchable at Phase 1 (a missing HLR-004 "compose from save flow" LLR) → would have forced a non-empty-through-save TC at Phase 4.

### Probe & ledger practice
V-4 purity probes in import-statement form with positive baseline + negative controls (incl. the careful detail: no-logging negative control switched from app.py to a service that DOES log); regimes stated; static-import-graph guard green. Change-first census change-first + category-keyed + honestly "not stamped complete" (the direct b10 corrective). **Gap:** excellent for structural/purity invariants, but NO analogous probe for coverage topology (does every story-named dimension reach the user surface?) — the SCOPE-1 class is unprotected.

---

## MERGED ACTION REGISTER

| ID | Action | Prevents/serves | Owner / when |
|---|---|---|---|
| A-1 | **KEEP + name the "reader-as-oracle + canonical-comparison-form" idiom** in the template control set: a writer's oracle is the existing reader; the comparison representation MUST be pinned to ONE canonical form at C-1 (the oracle output rep ≠ writer input rep trap). | 3rd-use pattern; B-1 representation trap | architect — template/req draft |
| A-2 | **KEEP the 3-reviewer Phase-2 wave (architect+qa+security) on any writer-that-round-trips-a-reader** — the convergence that shifted detection to Phase 2. | B-1/M-1/M-2/M-3 caught at Phase 2 (vs b10 I-gate) | orchestrator — Phase 2 |
| A-3 | **Batch-12 LEAD story: wire save-flow composition** — the save handler shall compose `batch`/`assignments` from loaded project state and pass them to `write_project_manifest`, with a non-empty-through-save round-trip pilot. Add the HLR/LLR HLR-004 omitted. Converts US-010 to fully-delivered. | SCOPE-1 | architect→software-dev — batch-12 |
| A-4 | **Schedule a census STRESS-TEST case** — the next batch that genuinely abuts frozen code (candidate: CRC fill-in touching `core.py`) is the deliberate test of whether the Phase-1 change-first census catches near-frozen placement BEFORE the I-gate. The b11 clean run did not load-test it. | §A caveat | orchestrator — Phase 0 batch selection |
| A-5 | **NEW control candidate (operator-confirm at batch-12 Phase 0) — story-dimension coverage / surface-reachability:** (V-1) §5.3 acceptance: for each input dimension named in a source user story, ≥1 TC exercises it through the SHIPPED surface, not only via direct service kwargs; (V-2) Phase 1: when a surface HLR wires a writer accepting dimensions the handler defaults empty, decompose a COMPOSITION LLR or record the dimension out-of-scope explicitly; (V-5) a standing Phase-4 surface-reachability matrix row (handler call-site kwargs vs service signature vs story dimensions). All three target the SCOPE-1 coverage-topology class. | SCOPE-1 (a leak that passed 23/23 + full suite) | operator-confirm batch-12 Phase 0; then architect/qa |
| A-6 | **KEEP the differential-oracle test idioms** (W-1/W-2/W-4): assert the discriminating NEGATIVE (the file that must NOT exist, the mismatch equality would mask, the bytes that must NOT be written), not just the happy positive. | W-1/W-2/W-4 | qa — ongoing |
| A-7 | **KEEP the signed-balance D-term + per-file collect evidence** (cleanest D=0 chain; retired the b06/07/08 threshold-drift anti-pattern). | W-6 | qa — Phase 4 |
| A-8 | **DEV-1/DEV-2 doc reconciliation → Phase 6:** V-5 provisional→implemented node/file renames; update §5.3.1 predicted band → actual 23. | 04-validation §5 | docs-writer — Phase 6 |
| A-9 | **REQUIREMENTS.md → Phase 6:** new R-* for US-010 (serializer, atomic contained write, verify-on-write, TUI surface); reconcile the R-VAR-003 stub the I4 dev already added; record the io.py/atomic-replace + LLR-001.5 escape-refusal. | R-* coverage | docs-writer — Phase 6 |

### Status of carried items
- **CRC first-operation fill-in:** STILL QUEUED pending operator CRC definition (postponed b08→b10→b11; pairs with A-4 as the census stress case).
- **Manifest backup/atomic hardening:** DONE this batch (M-1/M-2 atomic os.replace retired R-3's no-backup worry) — removed from the open-risk list.
- **Optional E2E pilot / perf-knee:** still queued.

**Orchestrator gate disposition (2026-06-15, autonomous mode):** Phase 5 is analysis with 0 open defects; approved. A-8/A-9 are Phase-6 work (gate-assigned); A-3 (save-flow composition) is the batch-12 lead story; A-5 (story-dimension coverage — the genuinely new control, the SCOPE-1 corrective) + A-4 (census stress case) → batch-12 Phase 0 for explicit operator confirmation (the b06-b10 precedent that template/control adoption is operator-confirmed at the next batch's open). Advancing to Phase 6.
