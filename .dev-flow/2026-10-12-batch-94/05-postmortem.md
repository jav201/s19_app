# Post-mortem — s19_app — Batch 2026-10-12-batch-94

> **Artifact language:** canonical English scaffold, generated in the batch's development language (`state.json` `language` = `en`).
> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. **Co-authorship method (declared): both roles were self-executed by the orchestrator via subagent delegation** — each lens was spawned as a generic subagent carrying `agents/<role>.md`, per this batch's runtime-absence declaration (no named reviewer roles; `PLAN.md` §*Gate notices and runtime absences*). Every figure below maps to a stored artifact of this batch (packets, design records, `evidence/` transcripts, `state.json`) — no figure is stitched from memory.

> **Owed in.** `core` — · `full` ✓

## 0 · Gate record — which tree this close gated

| Field | Value |
|---|---|
| Gate record | `python "C:/Users/jjgh8/.claude/skills/dev-flow/scripts/devflow-validate.py" .` from the project root · exit 1 · 5 block · 404 notice · 2026-10-19 |
| Gated tree | `5943f0c657ba1cd0bcd5d9da66c65924c487c3b9` · dirty — .dev-flow/2026-10-12-batch-94/06-docs/executive-summary.md, .dev-flow/2026-10-12-batch-94/06-docs/functionality.md, .dev-flow/2026-10-12-batch-94/06-docs/traceability-matrix.md, .dev-flow/BACKLOG-CODE.md, REQUIREMENTS.md, .dev-flow/2026-10-12-batch-94/06-docs/diagrams/ (the close record itself excluded) |

## 🔑 At a glance (read first)

- **Outcome:** closed with carry-over — P4 `PASS-WITH-NOTES`, 4/4 increments gated, 0 NEW batch-94-attributable failures at the definitive gate; 15 items carried to the next batch.
- **Top 3:** ① spike-first design + battery discipline shipped 4 increments clean against a `main` that moved 7 times mid-batch (65/65 battery node-runs RED) · ② the Inc-001 `check_spec` HTML-report TypeError escaped **three increment gates + PDR + DDR** — 16 P4 regressions, the batch's worst escape · ③ systemic root: the increment evidence suites omitted the pre-existing surface families (fill/diff/census), so the rework's geometry side-effects surfaced only at the full gate → the C-65 control proposal.
- **New control this batch:** C-65 census candidate — surface-family greps alongside symbol greps in reverse censuses (from the P4 escape; `state.json` `decisions_log` entry 12 LESSON).
- **Open items → next batch:** **15** — headline: the canonical-CI snapshot regen (29 marks) blocks any further chrome move, and the batch-95 IFC debt (5 blocks) waits on validator owners.
- **Metrics:** iterations **1** (P3, the iterate-to-fix) · findings **43 closed / 47 opened** (4 open) · ledger **2831→3045** collected (**170→180** files) · **18** decisions · **3** P4 gate runs + **2** fix rounds.

> Enough to know the batch's health and what carries forward. Detail below only for the why.

---

## Detail (reference)

### What worked

- **Spike-first design, probe-closed questions.** The PDR graduated the four operator-approved spike prototypes (the SVG winners named in the objective) into the design proposal, and the one open interaction question — R-1, the rail key bindings — was **closed by an executed probe**, not argument: `=` (Check Editor) + `]` (Flow Execution), `show=False`, 38-key census with zero collisions, verified at 80×24 and 120×30, reproduced by all five runs (author + 3 reviewers + sealer); F-keys were rejected on terminal-swallow evidence (`evidence/pdr_rail_key_probe.txt`; `PDR-2026-10-12-batch-94.md` §A row 9, §C honesty checks).
- **The two-layer contract + batch-scoped ids.** 21 HLRs / 42 LLRs / 24 ATs / 31 TCs with batch-scoped ids (`AT-B94-*`/`TC-B94-*`) — no registry reservation needed; C-35/C-39 executed; P2's two-layer acceptance review passed (a)–(d) on every lens (`01-requirements.md` §3–§5; `02-review.md` §Two-layer). Every AT realised in exactly one on-disk node per C-18 (the single exception, AT-B94-24, ratified as accepted — `DDR-2026-10-12-batch-94.md#COND-2`).
- **Battery discipline caught what authored tests could not.** The mutation batteries stayed honest under C-40/C-56: **5 inert arms** caught and re-asserted in Inc-001's fix round A; **2 test-side SURVIVED defects** caught by Inc-003's C-56 first round (the self-derived rail-order assert, the missing cancel arm) — both fixed and the full battery re-run; final roll-up **48 arms / 65 node-runs, 65/65 RED, 0 SURVIVED open, 0 CRASH open**, every arm hash-restored (`evidence/inc00{1..4}_battery.txt`; `04-validation.md` §Layer 0).
- **The P4 gate earned its keep.** The full gate caught **16 escaped regressions** the four increment suites + batteries had all passed (plus, at run TWO, the one escape fix round 1 introduced itself) — and the two-sided pristine-main probe classified every failure of all three runs deterministically (`04-validation.md` §Escaped-bug regression; `evidence/p4_gate_suite{,_run2,_run3}.txt`).
- **The coordination regime held under a moving main.** Batch-95 landed 7 increments on `main` during this batch and batch-96 opened spec-only before the close: **7 RC-1 rebases** — 6 absorbing batch-95's parallel-lane movement (3 at opening, 2 mid-Inc-001, 1 at batch-95's close) + #7 absorbing batch-96's opening — with **both lanes green at every union**; the union `run_flow` carries batch-95's change-attribution AND the A2B/chain-set arms (86 compat tests green at every gate; goldens re-captured against batch-95's batch71); `base_ref` re-stamped per RC-1's literal rule each time (`PLAN.md` §Key decisions; `state.json` `decisions_log` entries 6–8, 13).
- **The P2 gate's recorded reasoning.** Two of three lenses returned iterate-to-refine; the gate chose `approve` because every requirement-class major's correction was prescribed verbatim by the finding lens itself and discharged by the ledgered P1 amendment (LED .1–.13) — the reasoning is written on the gate, not implied (`02-review.md` §✅ Verdict).

### What didn't / friction

- **The worst escape — the Inc-001 HTML-report TypeError shipped end-to-end broken.** The `check_spec` kwargs TypeError in the A2B diff-report path (`app.py` forwards to `generate_diff_report_html`, which lacked the params) meant **any diff Report press failed** — and it passed **three increment gates + the PDR + the DDR** before the P4 gate run ONE caught it as root cause 1 of 16 (`state.json` `decisions_log` entry 12; `04-validation.md` §Escaped-bug regression row 1). No increment suite pressed the HTML report path end-to-end; the P1 emitted-form probe pinned the Markdown arm only.
- **The reverse-census keying gap.** The per-increment reverse censuses (8/9/7/7 probes) keyed on **symbol names** and missed the **surface families** — the diff screen, the patch strips, `patch_json`, the census tests themselves. The P4 probe found what 4 increment censuses did not (the LESSON of `decisions_log` entry 12).
- **A fix round introduced its own violation.** Fix round 1's Call-form `mount(before=…)` address-arg tripped the `AT-B83-08` assembled-selector census — caught **only by the next full gate** (run TWO), not by any fix-round check (`decisions_log` entry 14; fix round 2 `c18d181` hoisted the query to a name).
- **B78 fill invariants broke under the rework's auto-height.** The Inc-001 auto-height overrides defeated the json-window fill tcss — 4 fill invariants broken (`AC1`/`AC1b`/`AC3`/`AC5`). The increment suites ran the *new* acceptance but not the *pre-existing* fill-family runs: geometry changes need the families they touch, not only the new tests.
- **Flaky-family noise taxed 3 gates.** Runs ONE/TWO/THREE all needed the two-sided probe to classify the load-modulated family (identities move across runs; quiet-isolate re-run green, `evidence/p4_run3_isolate_3nodes.txt`); the family is batch-95-documented pre-existing but consumes real gate attention each time (`04-validation.md` §Gaps N-3).

### Scope drift (planned vs actual)

Declared drift only — every deviation is written in its packet's §6 or a gate decision; none was silent.

| Planned | Actual | Note |
|---------|--------|------|
| 7 stories (US-001…US-007) at intake | 6 contracted — US-001…005, US-007 | **US-006 (CRC test-vector) REFINE-parked at P0**, operator questions pending; **US-008/009 OUT** at kickoff → lane A (`PLAN.md` §Per-story) |
| Objective shorthand "pe_a/ce_b" | shipped **pe_b + ce_a** (ce_b folded) | naming flip per the operator-approved graduation call; PLAN flipped at PDR, map text at the Inc-002 map-delta (ux#5; `PDR-2026-10-12-batch-94.md` §C) |
| Rail 10 entries | rail **12** entries (`=` Check Editor · `]` Flow Execution) | R11 declared at ARQ; keys ratified at PDR by executed probe (§What worked) |
| Inc-002 budget: 4 source files | **5** source files | the B2 repoint cannot ride elsewhere; declared at the PDR; the compat re-export was rejected (two live addresses would double the census surface) (`DDR-…` §B row 7) |
| Inc-004 budget: 1 source file | **2** source files | HLR-012 binds every presentation — the strip/summary folded to the single arithmetic site; declared in-packet (`increment-004.md` §2/§6 deviation b) |
| Static `origin/main` at intake | `main` moved **7 times** mid-batch | batch-95's 7 landed increments + close, then batch-96's spec-only opening; 7 RC-1 rebases, both lanes green (§What worked) |
| Snapshot marks retired by the chrome moves | 29 marks stand **xfailed as predicted** | seeded snapshot content untouched by the triage; the canonical-CI regen retires them (`04-validation.md` §Gaps N-1) |

**The per-packet §6 registers (26 declared rows) + the fold rounds:**

- **Inc-001 §6** (7 rows): the R-6 cut reconciliation (3 tests re-derived at cut) · the Refresh supersession (dropdown-only, never re-reads the document) · the LLR-004.2 confirm-guard tightening · the US-065 title-pin re-point · the review defect-fix rounds A/B/C · the C-30-scoped latent chip-class note (→ backlog) · the editor_v2 settle-robustness follow-up (→ lane A). 5 closed in-batch; 2 carried (`increment-001.md:361`).
- **Inc-002 §6** (7 rows): the HLR-015 empty-arm reconciliation (batch-53 V4 law, fail-closed not re-opened) · the TC-B94-20 palette-census wording pin · F1 (→ lane A) · the A2B Markdown-only emission (recorded; acceptance pins the Markdown form) · the batch-95 golden re-capture naming · the flow-family count reconciliation 120→124 (the RC-1 union) · the golden-capture flake naming (tc330) (`increment-002.md:387`).
- **Inc-003 §6** (7 rows): the batch-78/79 frozen per-screen count moves (11→12) · the `?` help chip omitted (batch-95-frozen `window_help.py` → batch-95 coordination lane, zero hunks rather than forking) · the at_061a flake (batch-95-documented) · no fifth source file (at cap, PDR-declared) · the C-56 first-round catch · the L1/L2 recordings (`increment-003.md:420`).
- **Inc-004 §6** (5 rows): the KEY-FACTS 15-vs-21 reconciliation (engine count vs the curated set) · the SOURCE 1→2 fold · F1/F2 un-folded (owner ruling) · the snapshot zero-delta · the at_061a/tc330 flake family (`increment-004.md:375`).
- **Fold rounds:** Inc-001 — the F1 popup fold (duplicate `push_screen(LoadGuardScreen())` deleted from `app.py`, 13 lines, `5698947`) + the strengthened-assertion fold (`494bfe9`); Inc-004 — the `app.py` fold (strip/summary painters + `group_counts` ride the single arithmetic site; source 1→2).

### Metrics (full)

| Metric | Value |
|--------|-------|
| Iterations per station | `{P0:0, ARQ:0, P1:0, P2:0, P3:1, DDR:0, P4:0, P5:0, P6:0, PDR:0}` (`state.json:47-58`) — the `P3:1` is the P4-driven iterate-to-fix; its operational tail: **3 P4 gate runs + 2 orchestrator-owned fix rounds** (`decisions_log` entries 12–15) |
| Findings opened / closed | **47 opened · 43 closed · 4 open at close** — per-round table below |
| Findings by severity (blocker/major/minor) | **0 / 7 / 15** across the 26 severity-classed lens+packet findings (`02-review.md:15`: 0B/4M/12m raw, 14 union rows; packets §4b: Inc-001 2M+4m · Inc-002 1 · Inc-003 2 · Inc-004 1M+1m), **+1 packet-local HIGH** (Inc-001 F1) and **+3 LOW** (Inc-002 F1, Inc-003 L1/L2); the 13 design-round conditions/notes and 8 test-side battery findings carry no severity class |
| Where caught (P2 / P3 gate / P4) | **14 / 20 / 17** — P2 union findings (`02-review.md:15`) · P3 packet §4b findings (13+1+4+2) · P4 escaped *product defects* (16 + fix round 1's own 1), all closed in the 2 fix rounds (`04-validation.md:219-230`) |
| Test ledger (base − D + A = post) | collected **2831 − 0 + 214 = 3045** (definitive run: 3040 passed / 5 failed / 32 xfailed / 2 skipped / 21 deselected); scanned files **170 − 0 + 10 = 180** (`tests/test_id_registry.py:110`) — `04-validation.md:196-205` |
| Files touched · increments (cap trips) | **15 source-file slots across 4 increments (9 unique source files)**: Inc-001 4/4 at-cap ⚠ · Inc-002 5/4 over-cap (declared) · Inc-003 4/4 at-cap ⚠ · Inc-004 2/4 (fold declared); **10 net-new test files**; the four packet §2 tables complete (`V59`); increments: **4** |
| Decisions | **18** (`state.json:106-197`) — mirrored human-readable in `PLAN.md` §Key decisions |
| Gate runs | **3** P4 suite runs (ONE 3025 passed/20 failed · TWO 3040/5 · THREE 3040/5 — every run ONE orchestrator-owned per C-25) + **2** fix rounds (`d552f34`, `c18d181`); all phase / increment / PDR / DDR gates 0 block, except Inc-003's gate walked past 6 declared BLOCKs (1 station-expected V2 + 5 pre-existing batch-95 closed-record blocks, byte-equal to main since rebase #6) and Inc-004's remaining 5 = the same baseline (`PLAN.md` §Gate notices; `decisions_log` entries 8–9) |
| Mutation batteries | **48 arms / 65 node-runs, 65/65 RED, 0 SURVIVED open, 0 CRASH open**, every arm hash-restored + 4 C-20 move-asides hash-proven restored (`04-validation.md:56-65`; DDR §C) |

**Findings opened/closed, per round** (the 47/43/4 roll-up):

| Round | Opened | Closed | Open at close | The open ones → disposer |
|-------|--------|--------|---------------|--------------------------|
| P2 cross-review (`02-review.md:15,31-44`) | 16 raw / 14 union (0B/4M/12m) | 13 | **1** | **qa#6** — LLR-002.2 declared-none negative control; legitimate for an inspection method, owner P3 |
| PDR (`PDR-…md:78-97,126-129`) | 9 (R-1 carried in + C-1/C-2/C-3/C-ux-1/C-ux-2 + ux#3/ux#5/ux#6) | 9 | 0 | R-1 closed by executed probe; C-ux-1 pre-seal; C-1/C-2 at Inc-002; C-3 at Inc-003; C-ux-2 + ux#3/ux#6 at Inc-001's fold; ux#5 at the Inc-002 map-delta |
| Inc-001 §4b (`increment-001.md:312`) | 13 (F1 HIGH · F2/F3 MAJOR · F4–F7 MINOR · 5 fix-round-A inert arms · 1 architect C-17 finding) | 13 | 0 | review: BLOCK-UNTIL-F1 → fold → closing pass clean |
| Inc-002 §4b (`increment-002.md:335`) | 1 (F1 LOW) | 0 | **1** | **F1** — SaveFlowScreen overwrite-notice text → lane A (screens.py outside the file set) |
| Inc-003 §4b (`increment-003.md:355`) | 4 (L1/L2 LOW · 2 C-56 test-side SURVIVED) | 4 | 0 | L1/L2 closed as named recordings (no fix owed); C-56 defects fixed, full battery re-run |
| Inc-004 §4b (`increment-004.md:313`) | 2 (F1 MAJOR · F2 MINOR) | 0 | **2** | **F1** (`#ws_stats` raw tally — folding amends LLR-042.9-pinned behavior) · **F2** (filter chrome raw severity — needs the LLR-042.x filter-semantics decision); the HLR-012 judgment question answered: no violation on the shipped surface |
| DDR (`DDR-…md:99-122`) | 4 (COND-1 · COND-2 · F3 · F4) | 4 | 0 | COND-1 discharged pre-seal; COND-2 ratified as accepted; F3 reconciled at P4; **F4 discharged at this review into the open-items register below** |
| **Total** | **47** | **43** | **4** | qa#6 · Inc-002 F1 · Inc-004 F1 · Inc-004 F2 |

### Root causes (only if a phase took ≥2 iterations)

Phase 3 took its one recorded iteration (`state.json` `iterations_per_station.P3 = 1`) as the P4 iterate-to-fix — the chain:

1. **Gate run ONE** (2026-10-18, 1:07:40 — 3025 passed / 20 failed) reconciled by the two-sided pristine-main probe: **16 batch-94 regressions in 5 root causes** + 2 load-flakes + 2 batch-95 TC-707 (`decisions_log` entry 12). The 5 root causes: ① the `check_spec` HTML TypeError (root cause of the worst escape) · ② the new `diff_check_row` eats the diff hex area (0–5 rows at the B78 sizes — a C-13 violation) · ③ the Inc-001 auto-height overrides defeat the json-window fill tcss (4 fill invariants) · ④ the two ratified rail bindings trip the B78/81 UNSANCTIONED-bindings censuses · ⑤ four census/DOM/token reconciliations (the strip-restructure walk, `refresh_check_results` 2→3, the `safe_text` import census +flow_screens, the TC-337 token lost in the variants rewrite).
2. **Feedback edge** — black-box fails from implementation defects (requirements right) → ITERATE-TO-FIX to P3. **Fix round 1** (`d552f34`): all five closed, 16/16 B-nodes green, guard host 184; rebase #7 (batch-96 spec-only, zero conflicts) followed.
3. **Gate run TWO** (3040/5): the probe found **1 new B** — fix round 1's *own* Call-form mount escape — + 2 C flakes. **Fix round 2** (`c18d181`): the query hoisted to a name.
4. **Gate run THREE** (definitive, 0:58:06): clean — 0 NEW deterministic failures attributable to batch-94.

**The systemic root (named once):** the increment evidence suites — per-increment suites + reverse censuses + batteries — **did not include the pre-existing surface families** (the fill/diff/census families). The rework's geometry side-effects therefore escaped every increment gate and surfaced only at the full gate; and the censuses keyed on symbol names, so the surface families were invisible to them. The P4 probe caught what 4 increment censuses did not (`decisions_log` entry 12 LESSON). Secondary root: a fix round is a change like any other — fix round 1 repeated the increment pattern by checking only its own intent and re-introduced a census violation the next full gate had to catch.

### Process / workflow findings

> About the dev-flow itself. Feeds workflow improvement — kept separate from product.
- **Increment suites must re-run the pre-existing surface families a geometry change touches** (fill/diff/census) — not only the new acceptance. This is the batch's one expensive lesson; the fix is an evidence-suite obligation, not more review. (Root-cause section above.)
- **Reverse-census keying: add surface-family greps alongside symbol greps** — the C-65 control proposal below.
- **Fix rounds owe the full census discipline of an increment** — fix-round 1's own escape is the exhibit; a fix round re-runs the census families + the increment gate's own suites before it claims closed.
- **Flaky-family arbitration worked but is expensive** — the two-sided pristine-main probe + the quiet-isolate re-run classified all 3 runs correctly; the standing cost disappears only with the canonical-CI regen (N-3, item 9 below).
- **The moving-main regime is proven** — 7 RC-1 rebases with both lanes green, the union `run_flow` carrying both lanes' arms, and the base_ref re-stamp rule kept every gate honest. No process change needed; the coordination note (item 12) is the written form.

### Product findings

> About the code/product under development.
- The escaped-bug register is the batch's complete product-finding list — 16 escaped regressions in 5 root causes + fix round 1's own escape, every row with a red-pre/green-post pair and a value-discriminating post-fix assertion (`04-validation.md:219-230`). All closed by `c18d181`.
- The pre-existing load-modulated flake family (`at_061a`/`tc330`/`saveback_width_32`/`at077c`/`at064c`) — batch-95-documented, green on the quiet isolate, but a standing tax on every full run until the canonical-CI regen (N-3).
- batch-95's TC-707 pair fails identically on pristine `origin/main` — its missing `prototypes/cambios_10_12_2026/help_sections.md` is batch-95's debt, probe-verified (N-5, item 11 below).
- Carried product items: the lane-A follow-ups (items 4–6), Inc-004 F1/F2 (items 7–8), A4 (item 14).

### Control lineage

- **New control proposed this batch:** **C-65 census candidate — surface-family greps alongside symbol greps in every reverse census** (origin: the P4 escape — symbol-keyed censuses missed the diff screen / patch strips / `patch_json` / census-test surface families; `decisions_log` entry 12 LESSON). Status: **propose** — adopt or reject at the next batch's control review.
- **Prior controls exercised:** C-18 held (one AT = one node; the single exception ratified as COND-2) · C-25 held (every one of the 3 gate runs orchestrator-owned) · C-40/C-56 held and *proved* (5 inert arms + 2 test-side SURVIVED caught) · C-20 held (4 move-asides hash-proven) · C-48 held in form but **stress-tested to near-miss** (the censuses ran per increment — 8/9/7/7 probes — and still missed the surface families → C-65) · C-51 held (the legal-empty Layer 0, mutation-measured) · C-55 held (every absence arm carries its positive control) · C-57 held (authored sets frozen before reviewer dispatch) · the batch-92 gate rule held (0 NEW batch-94-attributable fails at the definitive run) · the second-editor-rebases coordination rule held (7/7 unions green).

### Open / deferred items → next batch

**15 items** — the carry-over seeds; the backlog reconciliation at close files them (lane A / owner / the coordination note).

| Item | Type (process/product) | Reason deferred | Trigger / owner |
|------|------------------------|-----------------|-----------------|
| 1. US-006 — CRC test-vector | product | operator questions pending since P0 (REFINE-parked) | the operator, then lane A |
| 2. US-008 — BlockTags | product | OUT at kickoff per the P0 gate | lane A |
| 3. US-009 — README | product | OUT at kickoff per the P0 gate | lane A |
| 4. SaveFlowScreen overwrite-notice text (Inc-002 F1, LOW) | product | `screens.py` outside the increment's five-file set | lane A |
| 5. SaveFlowScreen prefill race (`screens.py:777`, pre-existing) | product | pre-existing; outside every batch-94 file set | lane A |
| 6. editor_v2 settle hardening | product (test-hygiene) | settle timing = latent flake risk; green every run | lane A |
| 7. Inc-004 F1 — `#ws_stats` raw tally | product | folding amends LLR-042.9-pinned behavior — owner ruling | owner: this close review → lane A |
| 8. Inc-004 F2 — filter chrome raw severity | product | needs the LLR-042.x filter-semantics decision | owner decision |
| 9. Canonical-CI snapshot regen (29 marks) | process | one regen retires both generations; **must land before any further chrome move** | the canonical CI regen workflow |
| 10. batch-95 IFC debt (5 blocks: 2 V10 + 3 V14) | process | pre-existing-on-main baseline in batch-95's sealed record — crossing wants a coordination note, not a silent assumption | validator owners via the coordination note |
| 11. TC-707's missing `help_sections.md` | product (batch-95's) | fails identically on pristine main — batch-95's missing fixture | batch-95's lane |
| 12. batch-96 external-step block (in flight) | coordination | batch-96 is mid-flight; the intersection register goes in the coordination note | the coordination note |
| 13. C-65 census-keying control proposal | process | from the P4 escape lesson (surface families missed) | next batch's control review |
| 14. A4 — operator field check of `=` / `]` on a real terminal | product (field-verification) | unmeasurable headlessly; every acceptance stays key-independent per R-1, so no gate blocks on it | the operator, hands-on |
| 15. qa#6 — LLR-002.2 declared-none negative control | process | a declared `none` is legitimate for an inspection method; stays recorded-open with its owner | owner P3 → next batch |

### Working-file reconciliation (C-44) — every file this batch touched

> Sweep run against `C:/Users/jjgh8/Github/s19_app-b94` (the only repository this batch touched): `git rev-parse HEAD` = `70bebb8` · `git log @{u}..HEAD` = **59 commits** on `kimi/batch-94-flows-and-editors`, **none pushed** — `origin` exists (github.com/jav201/s19_app), the PR is P6's business. No auxiliary repo was touched (the flow bundle is a read-only mirror — the `V7` guard; `FLOW-VERSION.md` `2026-10-12-rev102`). `git status --short` was **0 lines at this artifact's intake** and shows **5 entries at completion**: this file plus four concurrent `06-docs/` edits observed mid-run (a parallel P6 docs pass — not made by, and not owned by, this artifact; recorded here per C-44, to be reconciled by the close sweep).

| Repo | File(s) | Terminal state | Landing / backlog ref |
|------|---------|----------------|-----------------------|
| `jav201/s19_app` @ `kimi/batch-94-flows-and-editors` | the batch's product + tests + `.dev-flow/2026-10-12-batch-94/` records (through `04-validation.md`) | ✅ committed (HEAD `70bebb8`) — **not yet pushed/PR'd** | the P6 PR + merge gate (`PLAN.md` §Conventions honored — PR + green CI + the final independent PR-level qa-reviewer pass before merge) |
| `jav201/s19_app` @ same | `.dev-flow/2026-10-12-batch-94/05-postmortem.md` (this file) | 📋 uncommitted at this writing | the P5 close commit (the one file this artifact's author may touch) |
| `jav201/s19_app` @ same | `06-docs/executive-summary.md` · `06-docs/functionality.md` · `06-docs/traceability-matrix.md` (modified, +201/−46) · `06-docs/diagrams/` (untracked: `architecture.md`, `sequence-*.md`) | 📋 working-tree edits by a parallel P6 docs pass, observed mid-run — **not this artifact's** | the P6 docs commit; the close sweep reconciles them |
| auxiliary repos | none | n/a — the skill bundle is not a working checkout | n/a |

- **Found before the batch:** `none recorded — the batch-open intake ran clean (V7 exit 0; PLAN.md §2.7 premises, 9 rows all TRUE); no tracked file was modified when the batch began`

**Conditional gate verdicts:** none this batch — no gate closed as *"once items 1–N land this is a PASS/MERGE"*. The P2 gate's `approve`-not-iterate call was a recorded disposition with its discharges named (LED .1–.13 + the Phase-3 named carries), not a conditional verdict.

| Conditional item | Discharged? | Verified how |
|---|---|---|
| — none — | n/a | n/a |

### Evidence checklist — architect + qa-reviewer

> Both co-authors' checklists, completed at this postmortem by re-reading the stored record (both roles self-executed via subagent delegation from the orchestrator — declared at the head of this artifact). Each ✓/✗ with one-line evidence.

**architect:**
- [x] Design decisions trace to the record (no orphan decisions). — ✓ all 18 `decisions_log` entries mirror `PLAN.md` §Key decisions; the PDR/DDR records cite their discharges by artifact line.
- [x] Frozen interfaces intact at close. — ✓ D1–D5 landed and re-verified after the fix rounds (`DDR-…md` §B row 2 + the re-walk, `decisions_log` entry 17).
- [x] Scope drift fully declared. — ✓ 26 §6 rows + the macro table above; none silent.
- [x] Cap discipline. — ✓ 15 slots / 9 unique files; the one over-cap (Inc-002 5/4) PDR-declared; reviewed at the DDR §B row 7.
- [x] Coordination regime recorded. — ✓ 7 RC-1 rebases + the union run_flow + the IFC-debt routing, all in `decisions_log`/`PLAN.md`.
- [x] The root-cause chain is evidenced, not narrated. — ✓ every run/fix round names its transcript and commit (`evidence/p4_*.txt`, `d552f34`, `c18d181`).

**qa-reviewer:**
- [x] Findings count reconciles with the record. — ✓ 47/43/4 re-counted round by round against `02-review.md`, the two design records, and the four packets' §4b.
- [x] Every finding carries a disposer. — ✓ the per-round table names each open item's owner; the closed ones name their discharge.
- [x] Severity classes stated. — ✓ 0/7/15 (+1 HIGH, +3 LOW) with the unclassed design/test-side items declared.
- [x] The test ledger reconciles. — ✓ 2831 − 0 + 214 = 3045 collected; 170 − 0 + 10 = 180 files (`04-validation.md:196-205`).
- [x] Escaped defects carry red-pre/green-post pairs. — ✓ all 17 rows of the register name pre-fix evidence, the RED kind, and the post-fix value-discriminating assertion.
- [x] Executor attribution intact. — ✓ ORCH-P3 / IMPL-P3 / the orchestrator (C-25) named per result in `04-validation.md`; no subagent claims a run it consumed.
- [x] The open-items register is complete against the record. — ✓ 15 items cross-checked against the packets' §6, the design records' §D, and `04-validation.md` §Gaps N-1…N-6.
