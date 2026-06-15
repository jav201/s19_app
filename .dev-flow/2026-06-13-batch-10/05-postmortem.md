# Post-mortem — s19_app — 2026-06-13-batch-10 (US-008 Intel HEX emitter + US-009 verify-on-save)

Co-authored: architect (process half) + qa-reviewer (validation half), merged by orchestrator, 2026-06-14.

**One-line takeaway (lineage):** b05 symbols→grep · b06 measurements→regime · b07 spec's-own-checks-must-run · b08 AC-artifact + probe-regime · b09 census-completeness (ALL guard classes) + gate-as-requirement-validation · **b10: an ENUMERATED-pattern census rule is structurally incomplete — it missed a 4th guard family (engine-frozen / no-diff-vs-main) even after the b09 widening, forcing the R2 relocation at the I1 gate. The per-increment GATE, not the census, is the real completeness guarantee; the census is a cost-reduction heuristic and must never again be stamped "VERIFIED COMPLETE".**

---

## PROCESS HALF (architect)

### 1. What worked
- **W-1 — per-gate cadence + conflict-rule caught the census miss at the I1 GATE, not in Phase 4 or production.** The +119-line emitter in `hexfile.py` (per the approved G-1) tripped 3 engine-frozen guards; software-dev STOPPED (fail-loud), the orchestrator surfaced a real blocker, the operator made the R2 reversal — all in one increment cycle. Cost bounded to one relocation redo. The gate is the safety net the V-3 census failed to be.
- **W-2 — the M-1 back-compatible carrier paid off decisively (0 broken sites vs 5).** Phase-2 preserved `save_patched_image`'s 2-tuple and rode `VerifyResult` on `ChangeService.last_summary` instead of widening to a 3-tuple. The blast radius was 5 sites (not the 2 R-10-CONTRACT named: +`test_changes_apply.py:330/376/394`); the 3-tuple would have forced 5 edits incl. `variant_execution_service.py` (NOT in the I3 budget). Back-compat → 0 edits, I3 in budget, LLR-002.1 AC true. Clearest evidence the Phase-2 back-compat insistence was correct, not pedantic.
- **W-3 — signed-balance ledger exact at every gate.** 782→792→800→811→816, D=0; full-suite reconciled three ways (784+29+3=816; 763 lean+21 slow=784). M-1 (no node renamed away) is why D=0 was achievable.
- **W-4 — emitter co-location (R2) preserved the frozen-engine contract without eroding it.** Format-cohesion (D-A=(a)) was not the *wrong* call — it was blocked by an undocumented constraint. R2 (emission-purpose cohesion, both emitters in io.py) is an equally clean — arguably cleaner — division. Lesson: we picked a principle whose feasibility depended on a constraint we didn't enumerate.
- **W-5 — probe-regime + AC-artifact rules avoided the no-`.hex` trap again** (A5: `examples/**/*.hex → 0`; all HEX fixtures round-trip-built).

### 2. THE headline lesson — an enumerated-pattern census rule is structurally incomplete
**Recurrence:** b09 produced the V-3 census rule (grep 3 guard families). b10 ADOPTED it at Phase 0 — and Phase 2 even certified the census **"VERIFIED COMPLETE."** It was not. The census missed a 4TH family — engine-frozen / no-diff-vs-main guards (`test_engine_unchanged.py::test_tc027`, `test_tc031`×2, keyed on `_ENGINE_PATHS`) that freeze `hexfile.py` against ANY git diff vs main. G-1 was approved on the incomplete census; the emitter tripped all three at the I1 gate, forcing R2 via Phase-1 iteration-3 (H-5).

**Root cause (precise):** the V-3 rule enumerated families *by example* and the list was silently treated as exhaustive — "grep these N patterns" is blind to any guard whose pattern isn't listed. Same failure class as the recurring "a rule that says X with no required artifact degrades to 'I assumed'": here, **"a rule that says 'grep these patterns' degrades to 'I greped what I knew about.'"** The guards were grep-able the whole time (`rg "_ENGINE_PATHS" tests/` → 10 hits). Worse: the Phase-2 "VERIFIED COMPLETE" stamp re-ran the *3 known* families faithfully and certified *completeness* — re-running an incomplete checklist cannot detect that the checklist is incomplete.

**Corrective — two layers (honest):**
- **Layer 1 (narrow, DEV-7, do it):** add `rg -n "_ENGINE_PATHS|no_diff_vs_main|engine_modules_unchanged" tests/` to the census. Catches *this* family. Will not catch the 5th.
- **Layer 2 (the real fix):** reframe the census from a fixed grep list to a **completeness principle / change-first dry-run** — enumerate every test that asserts on a file PATH / module STRUCTURE / import GRAPH / git-DIFF, take the batch's new-or-moved file list, and check each file against each such guard (key on the *category of assertion*, not the *specific pattern*). **Deepest truth: the GATE is the completeness guarantee, not the census.** The census is a Phase-1 cost-reduction heuristic (catch it before writing 119 lines). Treat it as such: keep widening it, but NEVER let Phase-2 stamp it "COMPLETE" — only running the guards against the actual moved module proves placement-completeness, and that happens at the increment gate.

### 3. Scope evolution
- **S-1 — mid-Phase-3 requirement iteration is now a 2-batch pattern (b09 G-9, b10 G-1/H-5).** Healthy for b10: the gate did its job catching a real undocumented constraint at the cheapest point. Caveat: the miss WAS grep-discoverable at Phase 1, so it's *both* a correct gate-catch AND a census-depth gap. Watch-trigger: if a 3rd consecutive batch takes a mid-Phase-3 iteration for a Phase-1-grep-discoverable constraint, the census is systematically shallower than the gate and Phase-1 must absorb more.
- **S-2 — the 6-file I3 cap exception (model.py) was justified** (ChangeSummary is `slots=True`, the M-1 carrier field had no other home; flagged + operator-ratified). Cap rule working as designed.
- **S-3 — Phase-2's 4 majors / 8 minors closed in one iteration** (body-first, H-1..H-4, 0 reopened).

### 4. Metrics
| Metric | Value |
|---|---|
| Iterations/phase | P1=3 (incl. iter-3 mid-Phase-3 H-5 reversal), P2=1+re-confirm, P3=4 increments, P4=1, P5=1 |
| Phase-2 findings | 0 blockers / 4 majors / 8 minors; 12/12 closed in 1 iteration (H-1..H-4) |
| Ledger | 782→792→800→811→816 exact (D=0); full-suite 784+29+3=816 |
| Increment blockers | 1 (I1 engine-frozen) — caught at gate, resolved via R2 |
| File budget | I1 2-file redo; I3 6 (cap+1, ratified); I4 5 (at cap) |
| Phase-4 | PASS-WITH-NOTES; 5/5 HLR, 14/14 LLR, 35/35 targeted nodes, 9 DEV, 0 code defects |
| Full suite | 784 passed / 0 failed / 29 skipped / 3 xfailed (658.73s, exit 0) |
| Cost of the headline miss | one increment redo (hexfile.py revert-to-pristine + emitter→io.py + test re-point + branch fix); C-10 untouched; 5/14 counts preserved |

---

## VALIDATION HALF (qa-reviewer)

### A. Verification-quality wins
- **W-1 — ELA oracle pinned to the parser, not a string scan.** `test_hex_emit.py:114` asserts `sum(1 for r in reread.records if r.record_type==0x04) >= 1`, fixture base `0x08040000`; sibling asserts `>=2` across a 2nd 64K boundary. Non-vacuous: a non-ELA emitter fails both the 0x04 count AND the high-address `reread.memory==mem_map`. The m-5 Phase-2 fix landed as a real double-guarded test.
- **W-2 — verify-on-save fault model, both file_types.** `test_mutated_byte_is_mismatch_changed`/`test_dropped_byte_is_mismatch_only_a`, `@parametrize("file_type",["hex","s19"])`, real enum `KIND_CHANGED/KIND_ONLY_A`. Planted fault matches asserted kind (Rule 9 / M-4); a generic "mismatch" classifier passes status but fails `.kind`/`.length`. Non-vacuous for BOTH emitters.
- **W-3 — M-1 back-compat proven by test, not assertion.** The 3 pre-existing 2-tuple unpack tests stay UNMODIFIED as the regression oracle; if the carrier had widened the tuple they fail at unpack. The "test_save_back* stay green" AC is machine-checked, not promised.
- **W-4 — signed-balance D=0 reconciled exactly** (782−0+34=816; per-increment +10/+8/+11/+5 tracked). All-additive because of W-3.
- **W-5 — byte-stability as MEASURE not gate** (`record_property`, asserts only `isinstance bool`). Correct: Intel HEX canonicalizes; a byte-identity gate would be a false-fail magnet. Right Rule-9 instinct — don't assert behavior the spec doesn't promise.

Net: the 3 Phase-2 QA majors (M-2 non-constructible DiffRun, M-4 fault-model conflation, m-5 string-scannable ELA oracle) all landed as real non-vacuous source-verified tests.

### B. Leak analysis — 0 behavior leaks
DEV-1..9 all doc-reconciliation/cosmetic. **DEV-7 is a VALIDATION-side failure too:** the census is a verification-coverage artifact; `02-review.md` asserted it "VERIFIED COMPLETE (re-ran all 3 grep families)" — but "all 3" was the bug. A completeness assertion was made without a completeness check (the structural-test analogue of a vacuous test: it passed because it only checked cases it already knew about). A Phase-2 **change-first dry-run** (take the planned new/moved files, run their predicted git-diff against EVERY structural/path/diff guard) would have shown `hexfile.py ∈ _ENGINE_PATHS` before a line was written — family-agnostic, catches the unknown 4th family. **V-5 file-path-provisional extension reduced churn materially vs b09:** DEV-1..6 were cosmetic "expected, Phase-6 reconcile" notes (incl. DEV-4 coverage-location shift to the TUI layer), none needing a §6.4 audit row — vs b09's audited DEV-1.

### C. Probe & ledger practice
P-1..P-6 solid (V-4 form, executed pre-states, regimes, failing-then-passing pairs like P-3 6→0). P-2 correctly `superseded-pending` then discharged in-regime at Phase 4 (the `_b2_scratch` discipline). **The gap:** the I1-gate engine-frozen discovery was a suite failure, NOT a probe — P-4 even touched hexfile.py but probed for *absence of a writer*, not *whether hexfile.py was writable at all*. Any LLR placing a NEW symbol into an EXISTING file must carry a draft-time probe proving that file is mutable under all structural guards.

---

## MERGED ACTION REGISTER

| ID | Action | Prevents/serves | Owner / when |
|---|---|---|---|
| A-1 | **Census = completeness principle / change-first dry-run, not a fixed grep list** (architect §2.3 Layer 2 + qa V-1): enumerate every test asserting on PATH/STRUCTURE/import-GRAPH/git-DIFF, run the batch's new/moved file list against each. Includes DEV-7's `_ENGINE_PATHS|no_diff_vs_main|engine_modules_unchanged` grep as a SUBSET. Template-widening candidate. | DEV-7 / the 4th-family miss | architect Phase 1; operator-confirm widening at batch-11 Phase 0 |
| A-2 | **Ban "VERIFIED COMPLETE" on the census; completeness is gate-confirmed** (qa V-5). A completeness verdict must show WHY no (N+1)th family exists, or be downgraded to "best-effort + gate-confirmed." Phase-4 supersession-completeness inspection reworded accordingly. | DEV-7 false-confidence stamp | architect Phase-2 wording + qa Phase-4 inspection |
| A-3 | **New-symbol-into-existing-file mutability probe** (qa V-2): any LLR adding a NEW symbol to an EXISTING module cites a draft-time probe proving the file isn't frozen/allowlisted (`rg "_ENGINE_PATHS|no_diff_vs_main" tests/` → frozen set → assert target ∉ set). LLR-001.1 would have caught hexfile.py at draft. | the I1 blocker (suite failure, not probe) | architect Phase-1 ledger |
| A-4 | **Document the engine-frozen invariant at the placement-decision point** (architect A-6): add the frozen set (core, hexfile, range_index, validation/, a2l, mac, color_policy) + "git-frozen vs main; new code that edits them goes elsewhere" to CLAUDE.md / the placement checklist. | R2 happened because the invariant was undocumented at the D-A decision | architect Phase-1; docs-writer Phase-6 → CLAUDE.md |
| A-5 | **KEEP: per-increment gate cadence + fail-loud** (the safety net that bounded the miss to one redo). Do NOT relax to standing-autonomous on batches adding modules at new locations. | W-1 | orchestrator, every phase |
| A-6 | **KEEP: back-compatible carrier over signature widening** (W-2, M-1). | W-2 | architect Phase-1/2 contract design |
| A-7 | **KEEP: signed-balance ledger w/ D-term + V-5 file-path-provisional + the 3 landed idioms** (parser-oracle over string-scan; planted-fault-matches-kind; back-compat-via-unmodified-old-tests). | W-3/W-4/W-5, §2.2 | qa practice, ongoing |
| A-8 | **DEV-1..6 doc reconciliation → Phase 6:** provisional→implemented node-id/file renames; DEV-6 fix the `test_hex_emit.py` docstring "D-A=(a)"→"(c)"; DEV-5 stale in-file TC labels. | 04-validation §5 | docs-writer/software-dev Phase 6 |
| A-9 | **REQUIREMENTS.md + DEV-8 → Phase 6:** new R-* section for US-008/US-009 (emitter, verify-on-save, save-back, TUI surface, hygiene); re-export `emit_intel_hex_from_mem_map` from `changes/__init__.py` for symmetry (DEV-8). | R-* coverage; DEV-8 tidy | docs-writer Phase 6 |

### Batch-11 slate (operator-named/carried; merged with these actions — recorded for the close slate, NOT batch-10 actions)
- **project.json manifest writer** (queued since b09; the verify-on-save substrate now exists — a manifest writer could itself be verify-checked via `verify_written_image`).
- **CRC first-operation fill-in** — STILL queued pending operator definition of the CRC (postponed b08→b10; awaits the CRC spec).
- **Reusable substrate now available:** the emitter (`io.py`) + verify engine (`verify.py`) + `VerifyResult` carrier are the write→re-read→diff substrate any batch-11 writer can reuse.
- **batch-11 Phase 0 operator-confirm:** the A-1/A-2 census-rule reframe (template widening) + A-4 frozen-invariant doc.

**Orchestrator gate disposition (2026-06-14, per-gate cadence — AWAITING operator gate):** Phase 5 is analysis with 0 open defects; recommend approve. A-8/A-9 are Phase-6 work (already gate-assigned); A-1/A-2/A-4 template/doc widenings → batch-11 Phase 0 for explicit operator confirmation (the b06/07/08/09 precedent that template adoption is operator-confirmed at the next batch's open). On approval → Phase 6.
