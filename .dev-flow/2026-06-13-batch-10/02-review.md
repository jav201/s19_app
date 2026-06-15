# Review — s19_app — 2026-06-13-batch-10

Phase-2 cross-agent review of `.dev-flow/2026-06-13-batch-10/01-requirements.md` (US-008 Intel HEX emitter + US-009 verify-on-save; 5 HLR / 14 LLR / TC-001..013). Reviewers in parallel, adversarial, 2026-06-14: architect, qa-reviewer, security-reviewer.

## Verdict summary

| Reviewer | Blockers | Majors | Minors | Verdict |
|---|---|---|---|---|
| architect | 0 | 1 (F-A-01) | 3 | approve w/ 1 major |
| qa-reviewer | 0 | 2 (F-Q-01, F-Q-02) | 5 | majors to fix |
| security-reviewer | 0 | 0 (F-S-03 major-but-already-mitigated) | 2 | **OK to ship** |

**Consolidated: 0 blockers / 4 unique majors / ~8 minors.** No blocker → no forced iteration. All majors are spec-substance fixes with NO design change and NO new operator decision (M-1's resolution is the G-3 carrier recommendation already delegated to the orchestrator). Orchestrator recommends iterate-to-fix.

## Majors

**M-1 (F-A-01 ≡ F-Q-03 ≡ F-S-03) — the C-10 `save_patched_image` 3-tuple return has a 5-site blast radius, not 2; the back-compatible carrier resolves it to 0.** R-10-CONTRACT names 2 production callers (`change_service.py:845`, `variant_execution_service.py:711`) but the independent census found 3 MORE 2-tuple unpack sites in `tests/test_changes_apply.py:330/376/394` — and LLR-002.1's AC claims "existing test_save_back* stay green," which the 3-tuple option falsifies. I3's file budget also omits `variant_execution_service.py`. **Resolution (architect + security recommendation, and the G-3 carrier choice already delegated): pin the BACK-COMPATIBLE carrier — attach `VerifyResult` to the existing result/summary object (or a separate accessor), DO NOT widen the 2-tuple.** Blast radius → 0 sites, LLR-002.1 AC becomes true, I3 budget unaffected. Record the 5-site census + the carrier decision in a §6.4 audit row + update C-10.

**M-2 (F-Q-01) — LLR-003.2 / HLR-003 threshold `DiffRun(kind="changed", length=1)` is not constructible.** `DiffRun` (`compare.py:100`) is a dataclass with fields `(start, end, kind)`; `length` is a read-only `@property` (`:137`), not a constructor field. The pinned threshold is invalid Python (unpassable-by-impossibility, the B-4 class). **Fix:** restate as `len(runs)==1 and runs[0].kind=="changed" and runs[0].length==1` (property read), in LLR-003.2 + HLR-003 + the TC-007 threshold.

**M-3 (F-Q-02) — LLR-005.2 "narrow the existing `try`" is not implementable as written.** `screens.py:618`'s `try` body is the single call `run_operation(operation_id, self.loaded)`, and `run_operation` (`operation_service.py:90-91`) does BOTH the registry resolve (KeyError on miss) AND `execute()` (can itself raise KeyError) — so the catch cannot be narrowed inside `_execute_selected` to cover only the registry miss. **Fix:** rewrite LLR-005.2 to name the actual mechanism — call the module-level seam `operation_resolver` (`operation_service.py:35`) inside the narrow `try`, with `.execute()` outside; OR specify a dedicated registry-miss exception (`NEW — created in Phase 3`). Cite the symbol.

**M-4 (F-Q-04) — TC-007/LLR-003.2/LLR-003.3 conflate two fault models → wrong run kind.** LLR-003.3 injects an emitter that DROPS a byte; a dropped byte classifies as `only_a` in `diff_mem_maps`, but the threshold demands a `changed` run. "Exactly one changed run" and "drops a byte" cannot both hold (Rule 9: the planted fault must match the asserted kind). **Fix:** pick one fault model per TC — mutate one byte → `changed` length 1 (matches threshold); if a drop test is also wanted, give it its own `only_a` expectation.

## Minors
- **m-1 (F-A-02):** `DiffRun`/`DiffStats` cite `:99/:149` (the `@dataclass` decorator); classes are `:100/:150`.
- **m-2 (F-A-03):** `save_patched_image` return cited `apply.py:565` (docstring); annotation is `:564`.
- **m-3 (F-A-04):** `io.py:1337` round-trip-contract citation lands ~2 lines off (Data Flow ~:1339).
- **m-4 (F-Q-05):** §5.2 coverage spans drift — HLR-003 row says `TC-008..TC-011` (TC-011 is HLR-004's); HLR-004 row says `TC-011` vs children `TC-011a/b`. No LLR uncovered; fix the span cells.
- **m-5 (F-Q-06):** LLR-001.3 ELA "≥1 ELA record emitted" — pin the oracle `IntelHexFile(written).records` + `record_type==0x04` (`hexfile.py:23,84`) so a string-scan can't satisfy it.
- **m-6 (F-Q-07):** §5.3 uses additive `782 + N_new`; state the signed-balance special case `782 − 0 + N_new` (D=0) explicitly.
- **m-7 (F-S-02):** the filename sanitizer `_sanitize_s19_filename` (`apply.py:740`) hard-forces `.s19`; the HEX path needs a parametric `suffix` arg on the SINGLE sanitizer (keep the traversal/reserved-name/trailing-dot rejections in one place), not a fork.
- **m-8 (F-S-04):** add an out-of-scope note that variant-execution HEX persist (`variant_execution_service.py:724-728`) remains refused this batch.

## CLEAN checks (verified, with evidence)
- **Census-completeness (V-3/A-1) VERIFIED COMPLETE** (architect re-ran all 3 grep families): emitter in `hexfile.py` (already in the 8-module allowlist) trips ZERO guards; the package-root alternative would trip both `test_tc028` allowlists (:3191/:3565); verify-service under `tui/services/` trips nothing (root glob is non-recursive); static-import-graph purity guard (`test_checks_engine.py:400`) covered by P-1/P-2. The batch-09 I1 escape is pre-empted.
- **G-1..G-4 locked decisions correctly encoded** (emitter in hexfile.py headless; hybrid verify; dedicated verify_written_image/VerifyResult; on-disk report deferred/inline DiffStats); verify covers both s19+hex via file_type dispatch.
- **Security: OK to ship** — write containment + dedup + sanitization reuse the proven workarea path (`workspace.py:277-289` is_relative_to + reparse-point rejection; `:235` collision counter); NO firmware bytes leak via VerifyResult (DiffRun = addresses only, DiffStats = counts only, C-9 `apply.py:33` precedent); re-read uses the existing parser (no new surface); no new deps/network/subprocess (hand-rolled emitter, dep guard `:3583`); checksum pinned to the reader oracle (`hexfile.py:66-74`).
- **Probes P-1..P-6 reproduce** (both architect + qa independently): P-1 hexfile.py 0 textual (V-4 form), P-4 no writer today, P-5 8 root modules = allowlist, P-6 782 collected.
- **ELA high-address round-trip present** (LLR-001.3, fixture span 0x8003_0000..0x8004_0010 forces type-0x04). **Byte-stability correctly MEASURE-don't-assume** (no byte-identity threshold; S19 P-04 precedent). **AC-artifact:** no AC references a pre-existing `examples/*.hex` (0 measured); fixtures round-trip-built.
- **Normative:** 0 `should` in statements (re-grepped); EARS shape; every test/analysis LLR has Executed-verification + threshold; V-5 all spec-pinned identifiers flagged provisional; no new SVG snapshot. `IntelHexFile(path)` constructor + `.memory` attribute accessors correctly used.

## Gate
0 blockers → iteration NOT forced. The 4 majors are spec-substance "claimed-but-not-implementable / incomplete-census" fixes, NO design change, NO new operator decision: M-1 resolves via the back-compatible carrier (the G-3 recommendation already delegated to the orchestrator); M-2/M-3/M-4 are threshold/mechanism restatements against the real code. Orchestrator recommends: iterate to fix M-1..M-4 + fold the minors.

---

## Re-confirmation — iteration 2 (2026-06-14; operator: "iterar como recomiendas")

Architect applied the full register. **12/12 findings CLOSED** (4 majors, 8 minors) body-first with §6.4 audit rows H-1..H-4 (one per major; minors folded as no-row traceability notes since no threshold/statement changed for them beyond citation fixes).

- **M-1 (H-1):** C-10 pinned to the BACK-COMPATIBLE carrier — `save_patched_image` keeps its 2-tuple `(Optional[Path], List[ValidationIssue])` (`apply.py:564`) UNCHANGED; `VerifyResult` rides `ChangeService.last_summary` (a separate channel the callers already read). 5-site census recorded; blast radius → 0; LLR-002.1 AC ("test_save_back* stay green") now TRUE; `variant_execution_service.py` off the I3 budget. Orchestrator re-verified: `last_summary` carrier present (×3), no tuple widening.
- **M-2 (H-2):** the non-constructible `DiffRun(kind="changed", length=1)` threshold replaced with the property-read form `len(runs)==1 and runs[0].kind=="changed" and runs[0].length==1` in HLR-003 + LLR-003.2 + TC-007 (the only surviving occurrence of the old form is the H-2 audit row itself, historical). `length` is a `@property` (`compare.py:138`), fields `(start,end,kind)` (`:100`).
- **M-3 (H-3):** LLR-005.2 rewritten to the real mechanism — `operation_resolver` (`operation_service.py:35`, cited ×6) inside the narrow `try`, `.execute()` outside so an execute-internal KeyError isn't masked; TC-013 monkeypatches the seam.
- **M-4 (H-4):** fault models split — MUTATED byte → one `changed` run (HLR-003/LLR-003.2); DROPPED byte → one `only_a` run (LLR-003.3); asserted kind matches planted fault (Rule 9).
- **Minors m-1..m-8:** all landed — anchor fixes (`:100/:150`, `:564`, `io.py:1337-1339`), §5.2 coverage spans, LLR-001.3 ELA oracle (`IntelHexFile(written).records` + `record_type==0x04`), §5.3 signed-balance `782 − 0 + N_new`, single parametric-`suffix` sanitizer (`apply.py:691`), variant-execution HEX out-of-scope note.

**C-10 contract re-check (M-1 touched it):** field-set identity re-run — the 2-tuple gains 0 fields; `VerifyResult` (`{status, runs, stats, written_path}`) is a separate channel. Contract HOLDS.

**Orchestrator self-check:** 4 H-rows present; property-read form ×4; operation_resolver ×6; 0 mojibake; 0 `should` in statements (8 file-wide, all header/prose); 5 HLR / 14 LLR consistent §1.5/§5.3. **0 open findings.** Ready for the Phase-2 re-confirmation gate.
