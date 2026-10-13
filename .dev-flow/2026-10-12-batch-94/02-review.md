# Review — s19_app — Batch 2026-10-12-batch-94

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 2 artifact. Reviewers (in parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer` by trigger family C (always in `full`).

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/review-template.md` explains each field below and the rules that read them. It ships with the flow and is not copied into this batch.

## ✅ Verdict (read first)

- **Gate:** `approve` → Phase 3 — **self-approved under the standing authorization** (operator 2026-10-13, P0 kickoff: autonomy granted over the gates this batch commissions). Two of three lenses returned `iterate-to-refine`; the gate is `approve` — NOT iterate-to-refine — because every requirement-class major's correction was **prescribed verbatim by the reviewing lens itself** (qa-reviewer: "the fix is mechanical"; security-reviewer: "cheaply amendable at P1"), so the P1 amendment discharges them without a second full review round. `p2-review.md` §Gate permits the run to choose under the standing authorization and record why; this paragraph is that record. The requirement-class majors are discharged by the ledgered P1 amendment (`LED-2026-10-12-batch-94.1`…`.13`); the implementation-class findings are carried into Phase 3 named (Inc-001, Inc-002/003). **The decision text of this gate goes to `state.json` `decisions_log`.**
- **Out-of-scope findings:** none — 0 named and routed.

- **Findings:** 0 blocker · 4 major (qa#1 requirement-class; qa#2 implementation-class; sec#1, sec#2 requirement-class) · 12 minor — 16 raw findings across three lenses, **14 union rows** in the table below (two equivalence classes merged in-row: arch#3 ≡ sec#2; arch#4 ≡ qa#3 ≡ sec#3).
- **shall/should check:** ✓ clean — 63/63 `shall` inside HLR/LLR statements only (re-grepped after the P1 amendment); zero `should` anywhere in the contract.
- **Two-layer (blockers):** ✓ every story has an `AT` · output reqs name deliverable+observation · both trace chains complete · ATs are genuinely black-box — census on every lens: 21/21 HLR acceptance blocks complete; 42/42 LLR field sets; `AT-B94-01..24` + `TC-B94-01..31` contiguous; (a)–(d) pass.
- **Census (change-first):** done — best-effort + gate-confirmed (NEVER stamped "VERIFIED COMPLETE") — counts in §Supersession census below; the per-increment re-run obligation rides in the packets (`V43` reads each packet's `**Reverse census**` field).
- **Security:** ⚠ 4 findings (2 requirement-class majors, 2 minors) — all discharged by the P1 amendment or carried named; fresh scan verdict recorded in §Security review summary.
- **Evidence checklists (architect / qa / security):** ✓ all complete — in §Evidence checklists below.

> The gate is `approve` with every line accounted for; the Detail below is reference.

---

## Detail (reference)

### Findings
| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status (DISPOSITION) |
|----|----------|----------|------------|------|----------------|----------------------|
| qa#1 | qa-reviewer | major · requirement-class | HLR-004 Boundary catalog | Box reads `☐ empty` while the catalog text describes the empty arm — the arm is owed by nobody | "The fix is mechanical": tick the empty class | **amended at P1 via LED-2026-10-12-batch-94.1** |
| qa#2 | qa-reviewer | major · implementation-class | HLR-006 / §6.3 · Inc-001 | Variant-retirement observers uncensused: `grep -rln "patch_variant\|VariantSelected\|VariantHelpRequested" tests/` → 9 files with no rewrite vs do-not-touch split | Record the two-group census (load-bearing); Inc-001 rewrites group 1, must not delete group 2 | contract part **amended at P1 via LED-2026-10-12-batch-94.8** (§6.3 R-6); observer rewrite **carried to Phase 3 named with Inc-001** |
| qa#3 | qa-reviewer | minor | §2.6 US-003/US-007 RC-1(b) probes (≡ arch#4 ≡ sec#3) | Probe strings non-reproducing: unscoped `grep -ri "chk.json"` and `grep -ri "flowexecution\|flow_execution"` claims are false (test-side hits; service-vs-surface conflation) | Replace with the scoped, reproduced forms | **amended at P1 via LED-2026-10-12-batch-94.2 + LED-2026-10-12-batch-94.3** |
| qa#4 | qa-reviewer | minor | §2.6 US-004 Feasibility | Dependency names the operator's `software_a_2.a2l` (not in the repo) as a suite dependency | Stand-in is the executable fixture; the operator file is field-verification only | **amended at P1 via LED-2026-10-12-batch-94.13** |
| qa#5 | qa-reviewer | minor | HLR-001 Numeric pass threshold | "The existing Checks and Issues surfaces remain view-only" asserted with no numeric census of its own | Add the 0-build/apply-controls query census | **amended at P1 via LED-2026-10-12-batch-94.9** |
| qa#6 | qa-reviewer | minor | LLR-002.2 Negative control | Declared `none` — legitimate for an inspection method, but the declared-none costs a visible finding | Record it as open, owner named | **open — owned by P3** (legitimate for inspection; recorded here and in the ledger) |
| sec#1 | security-reviewer | major · requirement-class | §6.3 / B3 golden observers | The recorded probe `grep -l "flow_" tests/goldens/**/*.md` is inoperative (exit 1, matches nothing); the byte-identity observers of the two changed report producers are unnamed | Executed sweep naming the observers + packet rebaseline obligation | **amended at P1 via LED-2026-10-12-batch-94.7** (§6.3 R-7); packet-routing remainder **carried to Phase 3 named with Inc-002/003** |
| sec#4 | security-reviewer | minor | HLR-014 / HLR-019 / HLR-020 / LLR-013.1 + §1.2 / §1.4 / §2.6 US-005 | D-label attributions (`D1`, `D4`, `D5`, `D1–D5`, `D-set`) cite labels the spike NOTES files do not carry | Quote the ruling's substance, never a label; sweep all sites (C-15b) | **amended at P1 via LED-2026-10-12-batch-94.4** |
| arch#1 | architect | minor | §1.2 Scope | US-004 seam pointer names HLR-013; the seam decision lives in HLR-012 | Correct the cross-reference | **amended at P1 via LED-2026-10-12-batch-94.12** |
| arch#2 | architect | minor | LLR-019.2 | LLR→TC forward edge missing: HLR-019's field already claims TC-B94-05, the LLR named only AT-B94-21 | Name TC-B94-05 on the LLR | **amended at P1 via LED-2026-10-12-batch-94.5** |
| arch#3 | architect (≡ sec#2, merged) | major · requirement-class | §6.3 R-4 B2 census | "Known consumers" undercounted: 5 listed vs 11 measured — a hand-maintained dependant list gone short | Replace with the executed 11-file census | **amended at P1 via LED-2026-10-12-batch-94.6** |
| arch#4 | architect (≡ qa#3 ≡ sec#3, merged) | minor | §2.6 RC-1(b) probes | Same defect class as qa#3 (probe strings) | Same prescription as qa#3 | **amended at P1 via LED-2026-10-12-batch-94.2 + LED-2026-10-12-batch-94.3** |
| arch#5 | architect | minor | §4 IFC Part A, flow `rail_selection_to_panel_mount` | One mounting node owned solely by LLR-001.2 (Check Editor only) silently covered Flow Execution mounting too | Split the node: check-editor mounting → LLR-001.2; flow-execution mounting → LLR-017.1 | **amended at P1 via LED-2026-10-12-batch-94.10** |
| arch#6 | architect | minor | HLR-002 rationale + Shipped surface + §6.2 D-3 | Digit-binding citation `app.py:1362-1371` includes the `plus` binding (1371) | Correct the span to `app.py:1361-1370` | **amended at P1 via LED-2026-10-12-batch-94.11** |

**Lens verdicts:** architect `approve` (6 minors: arch#1–arch#6) · qa-reviewer `iterate-to-refine` (1 requirement major qa#1, 1 implementation major qa#2, 4 minors qa#3–qa#6) · security-reviewer `iterate-to-refine` (2 requirement majors sec#1, sec#2; 2 minors sec#3, sec#4). NO blockers from any lens.

### shall / should check
> Any modal `should` / `debería` inside an HLR/LLR statement is a writing error → blocker.

✓ clean — zero `should` in the whole contract; all 63 `shall` occurrences sit inside HLR/LLR statements (the only exceptions are the template preamble's own rule text and one §6.3 quotation, both outside statements). Re-grepped after the P1 amendment landed.

### Two-layer acceptance review (blockers)
> (a) every story has a black-box `AT`; (b) every output-producing requirement names its observable deliverable + observation method; (c) BOTH traceability chains complete (behavioral US→AT→outcome + functional US→HLR→LLR→TC); (d) each `AT` is genuinely black-box — drives the surface, asserts the outcome, references NO internal symbol.

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-001 (HLR-001/002) | yes | yes | yes | yes | ✓ |
| US-002 (HLR-003–008) | yes | yes | yes | yes | ✓ |
| US-003 (HLR-009–011) | yes | yes | yes | yes | ✓ |
| US-004 (HLR-012) | yes | yes | yes | yes | ✓ |
| US-005 (HLR-013–016) | yes | yes | yes | yes | ✓ |
| US-007 (HLR-017–021) | yes | yes | yes | yes | ✓ |

Census behind the checks: 21/21 HLR acceptance blocks complete (Observable · Shipped surface · AT id · Boundary catalog · Negative control); 42/42 LLR field sets; `AT-B94-01..24` and `TC-B94-01..31` contiguous per story; (a)–(d) pass on every lens.

### Supersession census (change-first)
> Planned new/moved/edited files checked against EVERY guard family (behavioral-placeholder · structural/placement · AST-composition · frozen-module). State reservations; the increment gate is the completeness guarantee, not this census.

Executed C-26 best-effort census (change-first: each planned touched symbol × every guard family; key reach counts):

- `PatchEditorPanel` → **19 files** · `FlowBuilderPanel` → **6** · `patch_variant`/`VariantSelected`/`VariantHelpRequested` → **9** (REWRITE vs DO-NOT-TOUCH split recorded at §6.3 R-6) · `run_flow` → **11** · `flow_execution_service` → **14** · `apply_change_document` → **8** · `read_change_document` → **9** · `safe_text` → **11** · `from_markup` → **11** (all reachers declared or NOTICE-cleared).
- Did-not-fire (C-48 named empties): `RECOGNIZED_A2L_BLOCKS` → **0** hitters beyond the frozen emitter (the view-level seam keeps the engine untouched) · `BLOCK_PATCH` → **0** beyond the flow-model definition and its existing tests.
- Reservations: B2 move census (11 files) and the flow-report golden observers are re-derived per increment and land in each packet's `**Reverse census**` field (`V43` reads it); the rail/screen census constants move with their landing increments, never before.
- Discipline line: this census is **best-effort + gate-confirmed, never "VERIFIED COMPLETE"** (A-1/A-2) — the increment gate, running the real moved/edited files against the full suite, is the completeness guarantee; a re-run of the known families cannot prove the enumeration complete.

### Security review summary

**Lenses:** three in parallel, spawned as generic subagents carrying the flow role files (runtime absence: no named reviewer roles — per SKILL.md step 5). `Independent review` attribution lines: `architect — spawned as a generic agent with agents/architect.md · approve` · `qa-reviewer — spawned as a generic agent with agents/qa-reviewer.md · iterate-to-refine` · `security-reviewer — spawned as a generic agent with agents/security-reviewer.md · iterate-to-refine`.

Family C fired **C6** (the app ingests user-supplied S19/HEX/A2L/JSON) + **C8** (file-derived text rendered in TUI surfaces and markdown reports). Controls verified on disk by the security lens:

- **Containment:** change-file writes stay inside `.s19tool/workarea/` (staged-temp + `copy_into_workarea`); flow persistence under the same idiom (`import_flow_file`).
- **Kind gate:** `apply_change_document` refuses non-`change` documents with zero writes (executed: `blocked: 2`, memory map untouched — `evidence/p1_probe_chk_roundtrip.txt`).
- **Markup safety (C-17/C-42):** `safe_text` (`utils.py:44-99`) is the only TUI render primitive for file-derived text; markdown reports escape through `markdown_safety.md_safe`/`md_code`; hostile payload identical in shape to the batch-77 sentinel (`tests/test_tui_hostile_map.py:105-107`) pinned by AT-B94-13/AT-B94-18.
- **Fail-closed reads:** `parse_change_document`/`read_change_document`/`dict_to_flow` collect-and-refuse (no partial flow mounts).
- **Dedup-suffix** on template/set saves (no silent clobber); **zero new** dependencies, network, auth, or secrets surfaces (triggers C1–C5/C7 not fired).

**Spec scan (fresh run over the amended contract, 2026-10-13, after the P1 amendment):**

```
scanner  : reads its 65 pattern(s) from its own marked block ... 128057 byte(s) read
controls : 5 row(s) for the 4 control(s) — placeholder pair counted twice
control  : positive / negative / placeholder / placeholder-unbracketed / authored-in-brackets — all ok
flags    : `hash`, `schema change`, `form`, `escape`, `expose`
security_required: true   (exit 1)
```

Same five flags as the P1-gate run (all vocabulary collisions answered in §6.3 of the contract — identity-check "hash", the stated *absence* of a schema change, C-42 "emitted form", the escape control itself, "expose no apply control"); **nothing new fired** on the amended text. Verdict: no unresolved security question; the four security findings are discharged by the P1 amendment (sec#1→LED.7, sec#2→LED.6, sec#3→LED.2/.3, sec#4→LED.4) with the golden-observer packet obligation carried to Inc-002/003.

### Evidence checklists (full) — architect · qa-reviewer · security-reviewer
> Attach each reviewer's completed evidence checklist (items in their agent files), ✓/✗ + one-line evidence.

- **architect** ✓ — derivation completeness: 6/6 READY stories derived, US-006/008/009 untouched (0 stray requirements); EARS patterns on 63/63 statements; ambiguity pass: two surfaces per rail-entry question recorded OPEN (R-11), not silently decided; contradiction pass: HLR-004 boundary box (qa#1) was the only self-contradiction; IFC: one node/two owners (arch#5) found and split.
- **qa-reviewer** ✓ — testability: every `test`/`analysis` LLR carries executed verification + numeric threshold (V4-simulation clean); boundary catalogs ticked with arms owed (empty class arm added at HLR-004); negative controls named with RED sides (LLR-002.2's declared `none` recorded open, qa#6); C-10 honored (parallel non-default arm + sequential default; two dirty-guard branches); C-12 honored (US-003 chains writer→reader→report).
- **security-reviewer** ✓ — family C walk-through: C6/C8 controls verified on disk (six items above); spec scan re-run (verdict above); hostile-input arms pinned to the batch-77 sentinel shape; new surfaces' render sinks limited to `safe_text` / `markdown_safety` (allowed dependency declared in the map §10).
