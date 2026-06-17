# Review — s19_app — Batch 2026-06-16-batch-12 (CRC_F2)

> Phase 2 artifact. Reviewers (parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer`. Each returned findings; orchestrator assembled. (architect + qa hit a transient API-500 on the first dispatch and were re-run — second run completed clean.)

## ✅ Verdict (read first)

- **Gate:** **ITERATE → Phase 1 recommended** (no blockers, but 8 majors — several are spec-completeness gaps that will surface at implementation).
- **Findings:** **0 blocker · 8 major · 11 minor** (architect 0/3/4 · qa 0/3/4 · security 0/2/3).
- **shall/should check:** ✓ clean — 0 modal `should` inside any HLR/LLR Statement (4 hits all in preamble/rationale; independently confirmed by architect + qa).
- **Census (change-first):** ✓ done — best-effort + gate-confirmed, NOT stamped complete. **A-4 stress-test CLEAR** — both frozen lists re-verified independently (`test_engine_unchanged.py:120-127` = 6 paths; `test_tui_directionb.py::test_tc031_*` `:3738-3745` = 7 incl. `color_policy.py`); every planned file outside both; reuse import-only. Census claim is **exact**.
- **Security:** ⚠ 2 majors + 3 minors — **OK-with-mitigations, 0 blockers**. Two containment claims hand-waved against primitives that don't deliver them (fixable with LLR wording).
- **Evidence checklists:** ✓ all three reviewers returned complete checklists.

> **Root pattern:** the majors cluster on THREE seams — (1) the **report/result surface** is asserted by FR9/HLR-002/003 but has no LLR/consumer/file (F-A-01, F-Q-01, F-Q-02); (2) the **neutral-input decoupling is half-specified** — `run_operation` binding + `OperationResult.output` left unreconciled (F-A-02, F-Q-02); (3) **I1 is over the 5-file budget** and the SPIKE tripwire is mis-aimed (F-A-03). The containment majors (F-S-01/02) are the batch-10/11 "hand-waved containment" recurrence, caught at spec stage.

---

## Detail

### Findings

| ID | Reviewer | Sev | Area / Req | What | Recommendation |
|----|----------|-----|------------|------|----------------|
| **F-A-01** | architect | **major** | HLR-002/003, FR9, D-2 | "Report" surface has **no implementing LLR, no existing consumer, no file in budget**. `report_service.py` does NOT consume `OperationResult` today and isn't in §6.5; only real surface is `screens.py:639` (prints status+notes, not `crc_regions`). D-2 names a "report service" consumer that doesn't exist. | **OPERATOR DECISION** (see gate): (a) wire `crc_regions` into the existing `screens.py` operations-result view (in-scope, smaller) + add LLR + TC + strike report-service from D-2; OR (b) integrate `report_service.py` (bigger, +file). |
| **F-A-02** | architect | **major** | LLR-005.1, HLR-005 | Neutral-input decoupling **half-applied**: `run_operation(operation_id, loaded: LoadedFile, *, now_fn)` (`operation_service.py:38`) also forwards `loaded` into `execute`; if `execute` takes `OperationInput`, the service signature + `test_operations.py` callers must change too. §6.5 marks `operation_service.py` only "E (maybe)". | Promote `operation_service.py` to definite **E**; add LLR-005.1 clause migrating BOTH the `screens.py:636` call-site and the service path; pin how `test_operations.py`'s `execute(loaded,…)` calls reconcile. |
| **F-A-03** | architect | **major** | RK-1, I1 budget | **I1 is ≥7 files** (`model.py`, `crc.py`, `crc_config.py`, `REQ-crc.md`, `operation_service.py`, `placeholders.py`/`registry.py`, ≥2 test files) — exceeds the ≤5-file increment rule. RK-1's SPIKE trigger ("touching every renderer") is the wrong tripwire; the real ripple is `run_operation`+tests. | **Split I1 → I1a (contract: `OperationInput` + `OperationResult` widen + `run_operation` + `REQ-crc.md` + test adapt) and I1b (engine: `crc.py` + `crc_config.py` + engine tests)** — increments 3→4. Re-aim RK-1 trigger at the service+test rewire. |
| **F-Q-01** | qa | **major** | §5.2/§5.3 | Three LLRs (005.1, 005.2, 002.3) have **no TC id in the §5.2 table** while §5.3 claims "100% of LLRs ≥1 TC". LLR-005.2 carries hard thresholds (field-count, `STATUS_DOMAIN` equality, `to_dict`) with only prose "green post-change". | Add rows: `TC-108` (LLR-005.1 input object), `TC-109` (LLR-005.2 widen/field-count/status-domain/to_dict), `TC-116` (LLR-002.3 `@work` inspection). |
| **F-Q-02** | qa | **major** | `model.py:98`, LLR-005.x, TC-115 | `OperationResult.output: LoadedFile` is **non-optional** and never reconciled with the neutral-input decoupling. A headless CRC op must still construct a `LoadedFile` for `output`; check vs inject `output` semantics ambiguous. TC-115's `result.output.mem_map` oracle is asserting an unstated contract (Rule-9 risk). | State what `output` carries for the CRC op (recommend: check → input snapshot unchanged; inject → `LoadedFile` over injected map), OR widen `output` optional. Then pin TC-115/TC-125 assertions. |
| **F-Q-03** | qa | **major** | TC-106, RK-3 | TC-106 variant known-answer is **vacuous as written** (no reference vector) — it can only prove "params change the digest", not non-default CRC correctness. Risk: green TC-106 read as "non-default CRC verified". | Reword TC-106 intent: "non-default params change the digest (parameterization wired); absolute correctness RK-3-deferred to an operator fixture." Keep it OUT of §5.3 gating anchors (currently is — good). **RK-3 "assumed" disposition is CONFIRMED honest by both qa + architect.** |
| F-A-04 | architect | minor | D-5 vs FR1/D-3 | "Params OPEN" (FR1) vs "4-byte LE FIXED" (D-5) is latent, not actual, contradiction — never scoped. | Add to D-5: "OPEN-params = CRC algorithm params only; storage codec is fixed 4-byte LE." |
| F-A-05 | architect | minor | §6.1 | `Operation.execute` cited `model.py:227`; actual `def` is `:228` (227 = `@abstractmethod`). | Cite `:228`. |
| F-A-06 | architect | minor | LLR-003.1, D-6, RK-6 | Range-merge vs emit ordering under-specified; re-parse-equality (LLR-003.2) can't catch a mis-ordered-but-equivalent emit. | State whether ranges stay sorted/merged; if order is immaterial, say so to close RK-6 by reasoning. |
| F-A-07 | architect | minor | §5.4 | §5.4 params row says "covered" without the RK-3 assumed-vector caveat (inconsistent with honest §6.7). | Annotate the §5.4 params row with the RK-3 caveat. |
| F-Q-04 | qa | minor | §5.1 vs LLR-003.3/TC-123 | §5.1 cites `VERIFIED` (no such symbol); codebase has `STATUS_VERIFIED="verified"` (`verify.py:28`). A test vs bare `VERIFIED` fails at import. | Normalize to `verify.STATUS_VERIFIED` or the literal `"verified"`. Oracle contract itself is sound. |
| F-Q-05 | qa | minor | LLR-003.3 | "intended mem_map" must be pinned to the **injected working copy** or TC-123 risks tautology. | Add AC: `intended_mem_map` = the injected map emitted (proves round-trip, not self-compare). Negative case already guards it. |
| F-Q-06 | qa | minor | LLR-003.4, §5.4 | No existing confirm-modal pattern in the TUI; TC-125 through-handler confirm could silently collapse into a direct-service call (SCOPE-1 failure mode). | §5.4 note: TC-125's confirm must be driven via the pilot (`pilot.press`/widget), not `confirm=True` kwarg. TC-124 (headless) is solid. |
| F-Q-07 | qa | minor | TC-114 | "Suite passes without real config" is a whole-suite property, not a single assertion. | Pin TC-114: `Glob examples/**/crc*.json` returns only `crc_config.example.json` AND it parses with dummy hex (also satisfies LLR-004.1 AC-artifact probe). |
| **F-S-01** | security | **major** | LLR-003.2, D-8(c) | Emit-write containment **asserted, not bound**: `emit_s19_from_mem_map` is a pure `(mem_map,ranges)->str` serializer (`io.py:1300`) with zero file I/O / containment. "Contained work area" is unbacked — the batch-10/11 hand-waved-containment recurrence. | Bind LLR-003.2 to the real seam: stage under `.s19tool/workarea/temp/` then place via `copy_into_workarea` (`workspace.py:215`), or validate target via `_find_workarea_root` + `is_relative_to(workarea_root)` + `_path_traverses_reparse_point` (`workspace.py:278-291`). Threshold asserts on the **resolved** path, not a string prefix. |
| **F-S-02** | security | **major** | LLR-004.1, HLR-004 | Spec implies `resolve_input_path` contains the config path; it does NOT — `workspace.py:471-473` returns ANY existing absolute path verbatim (containment only on the relative branch). This is arbitrary-local-file read; blast radius bounded (JSON→typed config, collect-don't-abort) but the spec asserts a guarantee it lacks. | Correct the wording to the **actual accepted posture**: "uncontained-by-design read (parity with `read_change_document`), accepted because read-only operator-supplied JSON never written back; enforce a size cap (`READ_SIZE_CAP_BYTES`) + collect-don't-abort." True containment = NEW requirement, out of scope (note in REQ-crc.md). |
| F-S-03 | security | minor | LLR-003.2, D-6 | Overwrite/data-loss posture for the emitted S19 unspecified; naive `write_text` clobbers. | Add: "no overwrite — name-dedup on collision per `copy_into_workarea` (`workspace.py:300`)." Inherited free if F-S-01's fix routes through `copy_into_workarea`. |
| F-S-04 | security | minor | LLR-002.2/003.3, D-2 | Report/log may surface operator config path / absolute paths; batch-11's plain-text-no-markup discipline (`app.py:3606`) + log posture (`app.py:3590`) not inherited. | Add AC: config-error / verify-mismatch / write-refusal messages interpolate paths + reader-issue strings as PLAIN text (no Rich markup); state the rotating-log path-logging posture is accepted. |
| F-S-05 | security | minor | RK-5 | RK-5 mitigation cites the same unbacked containment (false-comfort row). | Once F-S-01/02 land, update RK-5 to cite the concrete `copy_into_workarea`/`is_relative_to` seam + the "uncontained-by-design, size-capped" config posture. |

### shall / should check
✓ **CLEAN.** 0 modal `should`/`debería` inside any HLR/LLR Statement. The 4 `should` hits (lines 8, 9, 34, 39) are all preamble rules / rationale prose. Independently confirmed by architect and qa.

### Supersession census (change-first)
✓ **Sound and honestly not-stamped.** Both reviewers independently re-verified the two frozen `_ENGINE_PATHS` lists against disk; the spec's "[6, no color_policy] + [7 incl color_policy]" is exact. Every planned file (`operations/crc.py`, `crc_config.py`, `model.py`, `registry.py`, `placeholders.py`, `operation_service.py`, `screens.py`, `app.py`, `examples/crc_config.example.json`, new tests, `REQUIREMENTS.md`) is OUTSIDE both frozen sets; reuse of `range_index`/`core`/`hexfile`/`io.py` is import-only. **A-4 named stress-test = CLEAR.** Structural items (`app.py`/`screens.py`/`registry.py`/`placeholders.py`) correctly marked gate-confirm at increment (A-2). Predicted-red placeholder TCs (`test_operations.py:116/171/185`) honestly flagged.

### Security review summary
**OK-with-mitigations — 0 blockers, 2 majors (F-S-01/02), 3 minors (F-S-03/04/05).** CLEAN verified: confirmation-gate integrity (no path reaches emit without confirm), config-values-as-code (no eval/exec; `int(s,16)` only), original-snapshot immutability (writes on a copy), frozen-engine clearance. The two majors are containment-claim gaps fixable in LLR wording; the I3 R-6 security sign-off is already mandated, so this does NOT block the gate.

### Orchestrator assessment
0 blockers → the gate does not FORCE iteration. But **8 majors warrant an iterate** — F-A-03 (I1 over the ≤5-file hard rule) and the report-surface/decoupling-completeness gaps (F-A-01/02, F-Q-01/02) are real and will bite at implementation. One genuine **operator decision** is embedded (F-A-01 report-surface depth); the rest are orchestrator-lockable under delegated latitude (I1a/I1b split, wording/citation fixes, containment bindings = reviewers' concrete recs). Recommend **iterate** with the operator's F-A-01 call.

### Evidence checklists
All three reviewers returned complete ✓/✗ evidence checklists with file:line evidence (in their agent transcripts; architect 6-item, qa CLEAN-list 8-item, security 5-item).

---

## Iteration-2 closure (2026-06-16) — applied to 01-requirements.md

> The operator chose **iterate** + **F-A-01 = both surfaces**. The architect subagent was blocked by a sustained API 529 (×3), so the orchestrator applied the register inline (deterministic edits; dispositions were already decided). All 19 findings are CLOSED; audit table in `01-requirements.md` §6.4 (11 cluster rows).

**Outcome:** 5 HLR / **18 LLR** (was 15) / TC-101..132 + TC-108/109/116/117/126. Each finding's landing site is in §6.4. Headlines:
- **F-A-01 (both surfaces):** +LLR-002.4 (operations-result view), +LLR-002.5 + LLR-003.5 (`report_service.py` persistent report); `report_service.py` added to the §6.5 census (outside both frozen lists; `generate_project_report:913` is `VariantExecutionResult`-based today so the CRC section is NEW wiring, gate-confirm I4); D-2 consumer table + §6.1 anchor updated; TC-117/TC-126 added.
- **F-A-02:** `operation_service.py` promoted to a definite edit; `run_operation` migrates to the neutral `OperationInput` via a `from_loaded` adapter (test reconciliation pinned).
- **F-A-03:** I1 split → I1a (contract, 5 files) / I1b (engine, 2 files); **6-increment plan, each ≤5 files** (I1a/I1b/I2=5/I3=3/I4=≤3/I5=5); RK-1 SPIKE trigger re-aimed at the service+test rewire.
- **F-Q-01/02/03:** TC-108/109/116 added; `OperationResult.output` contract stated (check=input snapshot, inject=injected map); TC-106 reworded to "params-wired-only" (RK-3-deferred correctness, kept out of §5.3 gating).
- **F-S-01/02:** emit-write bound to `copy_into_workarea`/`is_relative_to(workarea_root)` containment (resolved-path threshold); config-read posture corrected to uncontained-by-design + `READ_SIZE_CAP_BYTES` (io.py:192) cap.
- **11 minors** all landed (see §6.4).

**Orchestrator re-verification:** 5 HLR / 18 LLR (grep), 0 `should` inside any Statement, 0 mojibake, change-first census A-4 CLEAR including the new `report_service.py`, every increment ≤5 files. **0 findings open** (F-Q-03/RK-3's non-default-vector residual stays a flagged "assumed — verify in Phase 3/4" data dependency, not an open finding).

**Re-confirmation verdict:** all blockers/majors/minors resolved → **recommend PROCEED to Phase 3** at the re-confirmation gate.
