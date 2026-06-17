# Post-mortem — s19_app — Batch 2026-06-16-batch-12 (CRC_F2)

> Phase 5 artifact. Co-authors: `architect` (process/architecture, this draft) + `qa-reviewer` (validation/test-strategy retrospective, merged below). Structured for cross-batch sweeping — keep the section order. UTF-8, no BOM.

## At a glance (read first)

- **Outcome:** closed clean with one in-flight scope re-scope (J-3) — **needed 1 forced iteration** (Phase 1, after Phase-2 review). Phase 3 ran 7 increments (I4 withdrawn); Phase 4 verdict **PASS-WITH-NOTES**, 0 FAIL / 0 blockers.
- **Top 3:** ① the **named A-4 census stress-test passed under real load** — CRC genuinely abuts frozen `core.py`/`hexfile.py` and stayed out (compute+emit landed in new `operations/crc.py`); ② **communication collapsed mid-batch** during long execution stretches (operator-flagged) — corrected with a living PLAN.md + in-conversation packets; ③ **root cause of the only scope-change (J-3):** Phase-0/1/2 bound the CRC "persistent report" to `report_service` without probing its actual input contract (`VariantExecutionResult`, not `OperationResult`).
- **New control this batch:** Phase-1 increment-budgeting should account for **facade/test blast-radius** up front (two increments needed a ≤5-file exception or a forced 6th test-reconciliation file). Proposed, adopt-next-batch.
- **Open items → next batch:** 7 — biggest is the **A-3 save-flow composition** carryover (queued since b11) and **codifying the reader-as-oracle idiom** (now its 4th named use).
- **Metrics:** iterations sum **6** (`{0:1,1:2,2:1,3:1,4:1,5:1}`) · Phase-2 findings 19 opened / 19 closed (0 blocker / 8 major / 11 minor) · per-increment review findings 5 opened / 5 closed · ledger **839 → 879** collected (D=0, A=40 exact) · full suite **847 passed / 0 failed**.

> Enough to know the batch's health and what carries forward. Detail below only for the why.

---

## Detail (reference)

### What worked

- **The named A-4 census stress-test passed — and this time it was load-bearing.** Batch-11 ran the change-first census (A-1/A-2) clean but never *load-tested* it: no planned file actually threatened the frozen engine set. CRC was the named candidate that genuinely abuts the frozen readers (`core.py`/`hexfile.py` compute and re-emit firmware images). The A-1/A-2 census at Phase 1 placed every planned file outside both `_ENGINE_PATHS` lists; CRC compute + S19 re-emission went into new `s19_app/tui/operations/crc.py` (reusing `emit_s19_from_mem_map`, `range_index`, `verify_written_image` import-only); `test_engine_unchanged.py` stayed green at every increment gate and in Phase 4. The control did its job against a real adversary.

- **The KAT anchor caught a real bug.** During I1b the dev's first engine cut used `zlib.crc32(data, 0xFFFFFFFF)` — a seed error (passing the init as the running-CRC arg). The load-bearing acceptance anchor TC-101 (`crc32(b"123456789") == 0xCBF43926`) failed, the bug was found and fixed, and the anchor stayed gating through Phase 4. A green-but-self-consistent engine would have shipped without it; the anchor is exactly the "test verifies intent, not coincidence" case (engineering rule 9).

- **The A-5 / surface-reachability control worked — SCOPE-1 did NOT recur.** The batch-11 failure mode (writer API complete, but the TUI handler defaults left the dimension unreachable) was the explicit thing this control guards. All 8 US-011/US-012 input dimensions are exercised *through the shipped handler*; the two highest-risk write dimensions (inject/emit, two-stage confirm) are pilot-driven via the real `ConfirmWriteScreen` (`#confirm_write_ok`/`#confirm_write_cancel`), not a `confirm=True` kwarg. Phase-4 matrix: CLEAR.

- **Reader-as-oracle is now a 4th-use named idiom.** CRC verify-on-write re-reads the emitted S19 through the frozen `S19File` reader and diffs against the *injected* working map (non-tautological — a deliberately corrupted write produces a mismatch). This reuses the batch-10 `verify_written_image` substrate and follows b09 (compare) / b10 (IntelHexFile) / b11 (read_project_manifest). It has earned codification.

- **The ≤5-file discipline drove three clean increment splits.** I1→I1a (contract) / I1b (engine), I3→I3a (op wiring) / I3b (TUI surface), I5→I5a (headless write mechanics) / I5b (confirm surface). Each split was surfaced and stop-and-reported by software-dev rather than silently bundled.

- **Per-increment independent review caught a real issue at almost every increment, all fixed before the gate:** I1b HIGH (bitwise non-default path had zero correctness coverage → TC-106b pinned against 2 published variant KATs), I3b MEDIUM (stale in-flight worker could overwrite a config-error surface → dispatch-token guard + regression test), I5b MEDIUM (verified corrective write rendered a stale pre-write MISMATCH row → write-oriented rows + strengthened TC-125), I5a security LOW (emit outside the try → folded inside + KeyError caught). Non-autonomous mode (operator approval + independent reviewer per increment) held.

### What didn't / friction (honest)

- **(a) Communication collapsed mid-batch.** The operator explicitly flagged that comms "almost disappeared" during long execution stretches. **Corrective applied mid-batch:** a living PLAN.md (where-we-are / roadmap / reqs / risks / ledger / decision-log / next), full 7-section review packets in-conversation at each gate, and mid-implementation checkpoints (operator chose "more / more often"). Saved as the `devflow-living-compendium` feedback control. This is a recurring operator preference, not a one-off — it should be a standing dev-flow behaviour, not a per-batch rediscovery.

- **(b) The J-3 mis-binding — the one real scope change.** Phase-0 feasibility, Phase-1 derivation, and the Phase-2 iteration all bound the CRC "persistent report" to `report_service.generate_project_report` and even added LLR-002.5 / LLR-003.5 + a census row + a D-2 consumer-table entry for it. None of those passes probed `report_service`'s **actual input contract**: `generate_project_report` consumes a `VariantExecutionResult` (project/variant-scoped), not an `OperationResult` (per-file, per-operation). The mismatch — an awkward, operator-unreachable coupling, i.e. the SCOPE-1 risk class — surfaced only at I4 PREP in Phase 3, forcing the re-scope and I4 withdrawal. **Root cause:** the "report service" was treated as a known consumer from its name and the F-A-01 "both surfaces" operator call, but its `:913` signature was never read against `OperationResult`. The fix (CRC persistent record = the operation's own emitted S19 + `OperationResult`) is cleaner than the original plan — the late catch cost an increment of spec churn, not code.

- **(c) Increment sizing was optimistic.** The Phase-0 plan was 3 increments; Phase-2 split I1 (the budget violation F-A-03) to 6; I3a/b and I5a/b splits surfaced mid-flight to 7 (I4 then withdrawn). **Two increments needed a budget exception or a forced extra file:** I1a took a forced 6th file (`test_tui_operations_view.py` reconciliation — the contract change broke execute stubs; the reviewer ruled it justified mechanical), and I3a took an explicit ≤5→7-file exception (the `CrcOperation` home + facade rewire + two test files that hardcoded the placeholder contract). In both cases the over-run was **facade re-export churn + test reconciliation**, not feature code. Phase-1 budgeting counted feature files and under-counted blast-radius.

- **(d) Infra instability.** Repeated API 500/529 outages forced inline application of the Phase-1 iteration-2 register (the architect subagent 529'd ×3; deterministic edits, dispositions pre-decided), Bash/PowerShell safety-classifier outages forced retries on commits, and a **subagent `git checkout` discarded uncommitted I5b edits** — recovered by reconstructing from the diff and integrity-verified (git status, all I5b symbols + TC-124/125 present, lean 826 green). No data lost, but the recovery consumed cycles and is a latent risk whenever a subagent runs git mutations on an uncommitted tree.

- **(e) Spurious-approve replay.** After a server disconnect, a retry-replay delivered a spurious "approve" at the Phase-2 gate. The operator clarified it was an app error, not a decision; integrity was re-checked (valid JSON, 5 HLR / 18 LLR, artifacts intact, 0 mojibake) before the real gate decision. No bad gate was crossed, but the replay shows gate decisions need to be robust to transport-level duplication.

### Scope drift (planned vs actual)

| Planned | Actual | Note |
|---------|--------|------|
| 3 increments (Phase 0) | 7 increments (I4 withdrawn) | I1 split at Phase-2 (budget); I3/I5 split mid-flight |
| CRC persistent record via `report_service` (Phase 1/2, both-surfaces) | CRC record = emitted S19 + `OperationResult` in op-result view (J-3) | Only real scope-change; documented audit row §6.4 J-3 |
| LLR-002.5 (persistent project-report render) | WITHDRAWN | Check has no separate persistent artifact |
| LLR-003.5 (write record via report_service) | RE-SCOPED to operation output | No report_service binding |
| SCOPE-1 half-delivery risk (b11 carry) | PREVENTED | A-5 control worked; all 8 dims through-handler |

### Metrics (full)

| Metric | Value |
|--------|-------|
| Iterations per phase | `{0:1, 1:2, 2:1, 3:1, 4:1, 5:1, 6:0}` (sum 6) |
| Phase-2 findings opened / closed | 19 / 19 (1 iteration) |
| Phase-2 findings by severity (blocker/major/minor) | 0 / 8 / 11 |
| Per-increment review findings opened / closed | 5 / 5 (I1b HIGH, I3b MEDIUM, I5b MEDIUM, I5a sec-LOW, + I1a 2 LOW) — all fixed before each gate |
| Where caught (Phase 2 / P3 increment gates / P4) | 19 / 5 / 0 |
| Test ledger (base − D + A = post) | 839 − 0 + 40 = 879 collected (EXACT: I1a+2, I1b+9, I2+10, I3a+2, I3b+9, I5a+6, I5b+2) |
| Full suite (incl. slow) | 847 passed / 0 failed / 29 skipped / 3 xfailed (exit 0) · lean 826 |
| Files / increments / cap-trips | 7 increments; cap-trips = 0 (two ≤5-file exceptions granted: I1a forced-6th test recon, I3a explicit 7-file) |
| Frozen-set guards | green at every step; A-4 stress-test CLEAR |

### Root causes (phases that took ≥2 iterations)

- **Phase 1 (2 iterations) — 8 majors clustered on 3 seams.** (1) **Report/result surface had no LLR/consumer/file** (F-A-01): FR9 asserted a "report" but no LLR produced it, `report_service` didn't consume `OperationResult`, and D-2 named a non-existent consumer. Root cause: FR9's "surfaced in the report" was carried from the operator draft into HLR-002/003 without binding it to a concrete producer/consumer pair at derivation time. (2) **`run_operation` binding unresolved** (F-A-02): the neutral-input decoupling was half-specified — `execute` was retyped to `OperationInput` but the `operation_service.run_operation` call-site + `test_operations.py` callers were left "E (maybe)". Root cause: the contract change's ripple into the service layer and its test net was under-traced. (3) **I1 over budget** (F-A-03): the contract + engine + config + REQ doc + service + facade + tests was ≥7 files in one increment — the ≤5-file hard rule was checked against feature intent, not the actual file list. All three are "named-but-not-read" failures: a symbol/consumer/budget was asserted from plausibility rather than read against the code.

- **The J-3 late catch (Phase 3)** is the same root cause as F-A-01 surviving one more phase: the `report_service` consumer was *added* in the Phase-1 iteration to satisfy F-A-01 "both surfaces," but its `VariantExecutionResult` input contract was still never read. The control that should have caught it earlier — read the consumer's actual signature before binding a producer to it — is the same discipline as the LLR symbol-citation rule, just applied to a *consumer contract* rather than a named symbol.

### Process / workflow findings

> About the dev-flow itself (phases, gates, templates, agents, controls). Feeds workflow improvement — keep separate from product.

- **Increment budgeting must count facade/test blast-radius, not just feature files.** Both ≤5-file exceptions (I1a, I3a) were re-export churn + test reconciliation, not feature code. → Add a Phase-1 budgeting rule: when an increment touches a contract that has facade re-exports or hardcoded-contract tests, count those files into the budget at planning time (propose a "blast-radius column" in the increment plan).
- **A consumer's input contract must be read before a producer is bound to it.** J-3 root cause. → Extend the LLR symbol-citation rule to consumer contracts: any LLR that wires a producer into a named existing consumer must cite that consumer's actual input type (file:line), not just its name.
- **Living PLAN.md + in-conversation packets should be a standing behaviour, not rediscovered per batch.** The comms-collapse correction landed mid-batch and was saved as feedback memory; it should be the default dev-flow comms posture.
- **Gate decisions need transport-level idempotency.** The spurious-approve replay shows a disconnect+retry can inject a phantom decision. → Treat any gate signal arriving immediately after a disconnect as suspect; re-confirm before acting (already done ad hoc here — make it a rule).
- **Subagent git mutations on an uncommitted tree are a latent data-loss risk.** The I5b checkout incident. → Subagents should not run `git checkout`/`reset` on a dirty tree; commit or stash first, or restrict the operation.

### Product findings

> About the code/product under development.

- The CRC feature is end-to-end in the TUI: config editor → check (per-region MATCH/MISMATCH) → Write CRC → confirm modal → inject + emit contained S19 + verify → write-outcome rows; no write without confirmation (mutation-tested).
- **RK-3 residual is real and flagged:** non-default *device* CRC correctness still has no operator-sourced reference vector. TC-106b (published variant KATs) partially closes it, but a non-zlib device verdict must not be trusted without an operator device vector. Carry.
- **REQUIREMENTS.md → REQ-crc.md back-reference** is a Phase-6 docs task (the co-located doc exists; the repo-wide reference line does not yet).

### Control lineage

- **New control proposed this batch:** *facade/test blast-radius into increment budgeting* (origin: F-A-03 + the I1a/I3a ≤5-file exceptions). Status: **propose / adopt-next-batch.** Also propose extending the *symbol-citation rule to consumer input contracts* (origin: J-3). Status: **propose.**
- **Prior controls exercised:**
  - **A-4 named census stress-test** — HELD and was genuinely stress-tested for the first time (CRC abuts the frozen readers). No frozen path edited.
  - **A-5 surface-reachability matrix** — HELD; SCOPE-1 did not recur (the b11 origin failure mode).
  - **KAT anchor as gating acceptance** — HELD; caught the zlib seed bug.
  - **Reader-as-oracle idiom** — exercised a 4th time (verify-on-write); now ripe to codify.
  - **Verifiability rule + parent-HLR re-read + §6.4 audit table** — HELD (the J-3 re-scope produced a proper audit row with body-first ordering).
  - **Mandatory security sign-off on the write path** (I5) — HELD; CLEAN-to-ship, 1 LOW folded.
  - **Non-autonomous per-increment review** — HELD; caught a finding at nearly every increment.

### Open / deferred items → next batch

| Item | Type | Reason deferred | Trigger / owner |
|------|------|-----------------|-----------------|
| A-3 save-flow composition (wire batch/assignments through the TUI save flow) | product | Separate story from CRC; queued since b11 LEAD carryover | operator to confirm next batch · owner: software-dev |
| RK-3 operator *device* reference vector for non-zlib CRC | product | No operator-sourced device vector exists | operator supplies fixture → qa pins TC · owner: operator + qa-reviewer |
| CLI `ops` subcommand | product | TUI-only this batch; deferred since b08 | next batch scoping · owner: architect |
| CI trigger gap (`tui-ci.yml` fires on `main-tui`, never `main` → 3.11 gate never runs) | process | Operator-flagged 1-liner, still queued | "cuando quieras" 1-line fix · owner: software-dev |
| Codify the reader-as-oracle idiom (4th use) | process | Idiom now proven across b09/b10/b11/b12 | write it into PROJECT_RULES / template · owner: architect + docs-writer |
| Phase-1 facade/test blast-radius budgeting control | process | New control proposed this batch | adopt at next Phase-1 · owner: architect |
| Decision: should `report_service` ever carry a CRC section? | architecture | J-3 deferred the question by re-scoping away from it | record an ADR-style decision (likely NO — per-operation vs per-variant scopes differ) · owner: architect |

> **Recommended decision to record now (architect):** `report_service` should **not** carry a CRC section. It is `VariantExecutionResult`-scoped (project/variant lifecycle); CRC is a per-file, per-operation result. The two have different lifecycles and different reachability surfaces; coupling them recreates the operator-unreachable SCOPE-1 risk J-3 removed. Reversible if a future "project-level CRC summary across variants" story appears — flag that as the trigger that would change this.

### Evidence checklist — architect

| Item | ✓/✗ | Evidence |
|------|-----|----------|
| Constraints stated explicitly | ✓ | TUI-only, JSON config never-in-repo, 4-byte LE fixed, contained work area — `PLAN.md §1`, `state.json` Phase-0 lock |
| At least 2 alternatives considered (J-3) | ✓ | report_service binding vs operation-output record — `01-requirements.md §6.4 J-3` |
| Recommendation tied to constraints | ✓ | operation-output record chosen because per-file scope ≠ variant scope — §6.4 J-3 / this §Open-items decision |
| Risks listed (operational/security/cost/lock-in) | ✓ | RK-1..6 `PLAN.md §5`; J-3 root cause + git-checkout + replay this artifact |
| Cost/latency estimated where relevant | n/a | local headless CRC over firmware images; no model/API cost surface |
| Diagram included when flow non-trivial | ✗ | flow captured as the roadmap table + surface matrix; no mermaid added (linear pipeline, low ambiguity) |
| What would change the recommendation stated | ✓ | "project-level CRC summary across variants" trigger — this §Open-items decision note |

---

## Validation & test-strategy retrospective (qa-reviewer)

**BLUF — the control set earned its keep.** Five of six standing controls caught or prevented a concrete defect; the sixth (surface-reachability/A-5) prevented a recurrence of the exact batch-11 failure it was written for. The only false-comfort risk is RK-3 (non-default *device* correctness still "assumed"), honestly flagged. The one genuine test-strategy miss was structural: J-3, a coverage-topology error specced before the surface's feasibility was probed.

### What the controls caught (evidence)
1. **KAT anchor (TC-101) — paid for itself.** The "known-answer, not self-consistency" rule caught a real seed bug in I1b (`zlib.crc32(data, 0xFFFFFFFF)` vs `zlib.crc32(data)`); a self-consistent suite would have locked the wrong constant. **TC-106b closed the right gap:** the I1b HIGH was a *coverage* gap (TC-106 inequality-only; a wrong-final-reflection mutation passed it) — pinning two *published* catalog KATs (CRC-32/BZIP2 `0xFC891918`, CRC-32C `0xE3069283`) through the bitwise path is strictly stronger. It closed the *machinery* half, not the *device-convention* half (RK-3).
2. **Surface-reachability / A-5 — first real test on a write surface, and it held.** All 8 US dimensions exercised through the shipped `OperationsScreen` handler; the two write dims are **pilot-driven** through the real `ConfirmWriteScreen` (`#confirm_write_ok`/`#confirm_write_cancel`), not a `confirm=True` kwarg. The F-Q-06 "confirm must be pilot-driven or it collapses into headless TC-124" rule kept the row honest. SCOPE-1 does not recur.
3. **Reader-as-oracle (4th use) — mature enough to codify.** Re-reads the emitted S19 via the production `S19File` parser, diffs against the *injected* working map (F-Q-05), with a corrupted-write negative control proving the oracle can fail. The stable shape across 4 reuses: production reader → diff against intent → **always a corrupted negative control.**
4. **collect-don't-abort + containment — real-seam discipline, no mocking.** The over-cap config test (SizeProbe seam) and the write-outside-workarea escape test drive the production `copy_into_workarea` resolved-path check; failure modes assert `(config is None, len(errors)==1)` with no `pytest.raises`. Carry: test the real seam, assert the collected-error count, not an exception.
5. **Per-increment review caught a defect at nearly every gate — healthy.** Three of four (I3b race, I5b stale-MISMATCH, I5a emit-outside-try) are race/staleness/surface-ambiguity bugs that **cannot** surface in headless unit tests and only appear once a stateful TUI worker is wired — finding them at the review gate is the correct stage. The one to watch: the I1b HIGH was a *coverage* gap shipped at authoring (a new non-default path with only an inequality assertion, no external anchor).
6. **Signed-balance ledger held exactly.** 879 = 839 + 40 (D=0; I1a+2/I1b+9/I2+10/I3a+2/I3b+9/I5a+6/I5b+2), full-suite identity closes (847+29+3=879). No silent deletion behind a green suite.

### What the controls missed / partial comfort
- **RK-3 — non-default *device* vector still "assumed."** TC-106b closes the machinery; absolute correctness of a bespoke non-zlib convention has no operator reference vector in the tree. Correctly flagged (§5 note), but "all green" overstates assurance here — do not trust a non-default-convention verdict on real firmware until an operator device vector lands.
- **J-3 — the one structural miss.** The persistent-report surface was decomposed into LLRs/TCs against `report_service.generate_project_report` (consumes `VariantExecutionResult`, not `OperationResult`) — discovered at I4 *prep*, not draft. **Lesson:** A-5 checks a specced surface is *reached*, but nothing checked it was *feasible to reach*. A consumer-side coupling is citation surface like a code symbol — it needs a draft-time probe that the target actually consumes the producer's type.

### Carry-forward test-strategy recommendations
1. **Extend the symbol-citation rule to cross-module consumer bindings** — any LLR asserting "X is consumed/rendered by service Y" must cite a draft-time probe that Y actually consumes X's type (file:line), not just that Y exists. (Would have caught J-3 at Phase 1.)
2. **Codify reader-as-oracle as a named pattern with a mandatory corrupted negative control** (4 clean reuses).
3. **For any new alternate/non-default code path, require an *external* anchor at authoring** (not just an inequality assertion). The I1b HIGH is the recurring shape.
4. **Keep the signed-balance ledger and the pilot-driven-surface (F-Q-06) requirement verbatim** — both working; standing controls for the next operation fill-in.

---

*Drafted 2026-06-17 by architect (dev-flow Phase 5). UTF-8, no BOM.*
