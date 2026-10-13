# PLAN — s19_app — Batch 2026-10-12-batch-94

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language.
> **Owed in.** `core` ✓ · `full` ✓
> Seeded by `/dev-flow-init` step 4 at both levels; the living plan is owed at every gate
> that follows (`/dev-flow` §Living plan is the rule's home).

> **Field guide:** `templates/guides/plan-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.
> **Two header labels are read literally and are never translated:** `Standing authorization` and `Last updated`; the field guide names their readers.

The living compendium of this batch: where-we-are · objective · per-story/per-station status ·
roadmap + increment plan · key decisions · risks/watch-items · conventions honored ·
out-of-scope carries · test ledger · decision log (the human-readable mirror of `state.json`).

## Header

| Field | Value |
|---|---|
| Project | s19_app |
| Batch | 2026-10-12-batch-94 |
| Objective | Cambio1-7: Flow Builder por bloques (fb_a) + Flow Execution (fx_a) + split Patch/Check Editor (pe_a/ce_b) -- A2B configurable por bloque con procedencia en el reporte, check-spec .chk.json (write/validate only), control secuencial(default)/paralelo, ruteo de cables refinado. Design input: 4 SVG ganadores en G:/My Drive/dev-flow-radiografia/Refactor_10_11_26/Prototipos/. Coordination: COORDINACION-batch92.md (overlap screens_directionb.py con batch-93 -- second-editor-rebases rule). |
| Last updated | P1 (gate closed) · 2026-10-13 |
| Standing authorization | Operator (Javier), 2026-10-13, answering the P0 gate kickoff: *"1.Si, autorizados; 2.autorizo los merges; 3.Modo full."* — read as: **(1) end-to-end autonomy** over the gates this batch commissions; **(2) merge authority granted — and the merge stays gated**: after the PR is opened and CI is green, one final independent PR-level `qa-reviewer` pass over the WHOLE merged diff vs `main` must come back clean before the agent merges; a HIGH finding blocks the merge and returns to the operator; **(3) mode `full` confirmed**. Autonomy is never silent: every autonomous decision is summarized in this PLAN's decision log, `state.json.decisions_log`, the postmortem decisions summary, and carried to the vault at `/dev-flow-sync`. Per `shared-batch.md` §Batch-kickoff authorization: per-batch, never carried from a prior batch; the `standing_authorization` key is deleted from `state.json` with this cell its one record. |
| First gate | Record-seed gate (pre-P0): exit 0 — `0 block · 374 notice · 48 n/a`; `V7` raised no finding (bundle mirror `2026-10-12-rev102` self-consistent, 57 declared files both directions). Tool-proving run, not the batch. |
| Premises / RC-1 | Verified `origin/main` tip at intake: **`1a0eff6`** (2026-10-13; RC-2 probe answered). **Second RC-1 at the P0 gate:** the legends batch `2026-10-13-batch-94` (`f86d754`) landed on main — fast-forward rebase, `base_ref` re-stamped. **Third RC-1, same day:** that batch's completion (`a2b2c33`..`348c125`, closed 0 blocks) landed before any derivation — fast-forward rebase #3 onto `origin/main`, and `base_ref` re-stamped per RC-1's literal rule to **`8e056bd`** (HEAD at the stamp; the same reading the legends batch closed with), BEFORE the next gate. Flow currency (C-45 PULL): bundle mirror at `C:/Users/jjgh8/.claude/skills/dev-flow`, not a git checkout — probe = the `V7` line + `FLOW-VERSION.md` `2026-10-12-rev102`. Premises: `01-requirements.md` §2.7 (9 rows, all TRUE — rows 7–9 appended at P1: pilot budgets, probe transcripts, id scheme). |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not. All 23 ids evaluated 2026-10-13 over the commissioned scope (US-001..US-007); family B re-evaluated at every increment cut; families C and F re-evaluated at every gate.

| Id | Verdict | Probe output |
|---|---|---|
| A1 | fired | judged — new surfaces/modules planned (Check Editor panel, Flow Execution surface + rail entry, `flow_*` execution services per the coordination file set); a boundary is created |
| A2 | fired | judged — the file set spans ≥2 modules (`screens_directionb.py`, `services/flow_*`, `changes/`, `app.py`) |
| A3 | fired | judged — the split changes `PatchEditorPanel`'s message contract consumed by `app.py`/`screens.py`; `.chk.json` is a new artifact A2B Diff consumes |
| A4 | not fired | judged — multiple increments are planned but run sequentially in one worktree, not in parallel lanes |
| B1 | fired | `grep -rl PatchEditorPanel tests/` → cross-owned assertions (guard host `test_tui_directionb.py`, `test_tui_patch_editor_v2.py`); reverse census owed per increment |
| B2 | not fired | judged at intake; **amended at ARQ** — Inc-002 moves `FlowBuilderPanel` (screens_directionb → flow_screens): B2 census owed in Inc-002's packet |
| B3 | fired | `grep -l "flow_" tests/goldens/**/*.md` → flow-report goldens capture flow-service sources; golden drift to be named per increment |
| B4 | fired | judged — `.chk.json` consumed by A2B Diff reports; flow outputs consumed downstream; C-12 output-then-consume ATs authored (AT-B94-11 chain) |
| C1–C5, C7 | not fired | judged — no auth/secrets/external-integration/sensitive-data/DB/network surface in this TUI tool |
| C6 | fired | judged — the app ingests user-supplied files; mechanized by the Phase-1 scan (run at P1: `security_required: true`, five vocabulary collisions answered in §6.3) |
| C8 | fired | judged — file-derived text rendered in TUI/markdown; scan at Phase 1 (done); hostile-input ATs authored per C-17 |
| D1 | fired | judged — the user-visible rail and three surfaces change (approved design set fb_a/fx_a/pe_a/ce_b) |
| D2 | not fired | judged — the spike prototypes were built in the target technology (Textual, truecolor) |
| E1 | fired | judged — 7 stories commissioned, 4 increments planned |
| E2 | not fired | judged — no high-risk declaration at intake; execution writes stay bounded to loaded/workspace copies |
| F1 | not fired | bundle runtime — cannot recompute `flow_hash`; probe = the `V7` line + `FLOW-VERSION.md` `2026-10-12-rev102` |
| F2 | not fired | judged — lane A last refreshed 2026-10-13 at batch-93's close; no close has superseded it |

Stations taken up by the fired A-family: **ARQ → PDR → DDR** (chain); ARQ discharged 2026-10-13; PDR/DDR ahead at P3/P4.

## Where we are

P0, ARQ and P1 gates CLOSED 2026-10-13 under the standing grant (decisions_log entries 1–3). The requirements contract is live: 21 HLRs / 42 LLRs / 24 ATs / 31 TCs (batch-scoped ids), IFC Part A ×6 + Part B ×4, five C-35/C-39 probe transcripts in evidence, the security scan answered. Current station: **P2** — the cross-agent review of the contract (architect + qa-reviewer lenses, security-reviewer by family C), reviewers spawned as generic subagents per the runtime-absence record.

## Objective

<the batch objective, restated>

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| US-001 (Cambio1, editor split) | READY → contracted | HLR-001/002, AT-B94-01/02 |
| US-002 (Cambio2, Patch Editor rework) | READY → contracted | HLR-003–008 from the six image annotations; AT-B94-03..10 |
| US-003 (Cambio3, Check Editor + `.chk.json`) | READY → contracted | HLR-009–011; C-12 chain AT-B94-11; probes pasted |
| US-004 (Cambio4, warnings triage) | READY → contracted | HLR-012/LLR-012.x — seam decided **view-level** (freeze kept; re-open condition §6.2); executed census 1 023 findings |
| US-005 (Cambio5, Flow Builder + templates) | READY → contracted | HLR-013–016; A2B provenance emitted form pasted |
| US-006 (Cambio6, CRC test-vector) | REFINE | parked — operator questions pending |
| US-007 (Cambio7, Flow Execution) | READY → contracted | HLR-017–021; sequential-default/parallel ruling in LLR-019 |
| US-008 (Cambio8, BlockTags) | OUT | file to lane A at close |
| US-009 (Cambio9, README) | OUT | file to lane A at close |
| P0 / ARQ / P1 | CLOSED 2026-10-13 | decisions_log 1–3 |
| P2 | current | cross-review of the contract — subagents |

## Roadmap + increment plan

1. **Inc-001 — Patch/Check Editor split (US-001/002/003).** `PatchEditorPanel` → pe_a patch twin + ce_b check twin; the six rework annotations; `.chk.json` write/validate; rail entries. Lands first.
2. **Inc-002 — Flow Builder (US-005).** fb_a builder; blocks patch/CRC/A2B diff; templates; `FlowBuilderPanel` → `flow_screens.py` (B2 census owed).
3. **Inc-003 — Flow Execution (US-007).** fx_a carriles + run-log; import; per-chain input rebinding; sequential(default)/parallel; set save/load.
4. **Inc-004 — Issues warnings triage (US-004).** view-level reclassification of `A2L_UNRECOGNIZED_BLOCK` (1 023-finding census pasted).
5. US-006 re-enters only when the operator answers.

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-12 | Batch opened `full`, base `ae0ef4f` | rollover from batch-93; mode full per operator's standing preference |
| 2026-10-13 | Kickoff answered at the P0 gate: autonomy granted, merge granted (stays gated on the final PR-level qa pass), mode full confirmed | the operator's three answers, quoted in the Standing authorization cell |
| 2026-10-13 | Three RC-1 rebases onto batch-93 close, legends batch close, legends completion; `base_ref` stamped to HEAD per RC-1's literal rule | main moved three times while opening; the stamp reading is peer-verified (the legends batch closed V59-clean with it) |
| 2026-10-13 | Batch-number collision declared: TWO batches numbered 94 | cite the full dated name always |
| 2026-10-13 | ARQ (self-approved): R8 flow family → `flow_screens.py`; R9 editors stay; R10 `.chk.json` = v2 grammar + suffix; R11 rail 10→12, keys open; R12 US-004 seam flagged | parallelisation-rule exit 2; `apply.py`'s kind-gate is the no-apply enforcement |
| 2026-10-13 | P1 (self-approved): the contract — 21/42/24/31, batch-scoped ids | batch-scoped `AT-B94/TC-B94` are ungoverned (registry spec 2.3) — no reservation PR needed; every AT carries boundary + negative control; probes pasted per C-35/C-39 |
| 2026-10-13 | US-004 seam = **view-level reclassification**; `rules.py`/`a2l.py` stay frozen | parser-level candidate recorded with its re-open condition (§6.2 D-1/D-2): the freeze holds unless view-level falsifies a real warning |
| 2026-10-13 | IFC Part B rail screens parented to `workspace_shell` (not a COMPONENT → balancing untestable, declared) | the first Part-B parenting to `screen_workspace` was a drafting error — batch-88's frozen contract cannot declare the new flow names; batch-87's NOTICE form is the precedent |
| 2026-10-13 | Rail key binding stays OPEN (risk R-1) | `1`–`0` exhausted; Textual `Binding` mechanics + operator muscle memory decide at PDR — no acceptance depends on specific keys |

## Risks / watch-items

- R-1 (§6.3): rail key binding open — PDR must close it before Inc-001/002 land rail entries.
- R-2 (§6.3): NEW-created-in-Phase-3 symbols (`CheckEditorPanel`, `FlowExecutionPanel`, popup screen, binding model, chain-set envelope…) — each pinned for an emitted-form paste at its increment (C-42).
- R-3 (§6.3): C-15.1 dirty-flag writer census owed at P3 (LLR-005.1).
- `screens_directionb.py` carries batch-93's Memory Map work — full `test_tui_directionb.py` guard host (C-34) at every render increment's gate.
- Layout acceptance ceilings are the measured 74×12 / 96×18 / 136×28 boxes (C-29) — any spec drift beyond them is an iterate-to-refine trigger.
- US-006 parked; Cambio8/9 OUT; lane-A items (report_service escaping etc.) flagged, not claimed.
- The legends batch shares the "94" number — cite dated names.

## Conventions honored

- **Merge gate (kickoff grant):** PR + green CI + final independent PR-level `qa-reviewer` pass over the whole merged diff before this agent merges; HIGH returns to the operator.
- **Autonomy recording (kickoff grant):** every self-approval in this PLAN + `decisions_log` + postmortem + vault sync.
- Lane routing; coordination note; operator spike rulings (schema unchanged; `.chk.json` by suffix; provenance per block; sequential-default/parallel; refined cables).
- Gate rule (batch-92 post-mortem): 0 NEW fails over the declared baseline at P4.
- Batch-scoped AT/TC ids per `engineering-rules.md`; one AT = one on-disk node (C-18); RED counterfactuals mandatory per increment.

## Out-of-scope carries

- US-008 (BlockTags), US-009 (README), US-006 (if unanswered) → lane A at close.
- Lane-A open items not claimed (registry blindness, IFC charter, report_service escaping — last may touch Inc-003's files; flagged).

## Gate notices and runtime absences

- P0/ARQ runs: each exit 0 · 0 block (V20 detour at P0 repaired by regen; recorded).
- P1 gate run: first pass **26 block** (V4 ×13 missing thresholds, V12 ×8 Part-B parenting, V20 ×5) — all repaired (13 thresholds authored; 4 blocks re-parented to the shell boundary with the could-not-be-tested declaration; atlases regenerated); re-run **exit 0 · 0 block · 377 notice · 51 n/a**. The subagent's own read of V4's regex caught a latent 14th (LLR-021.2) — fixed in the same pass.
- Runtime absences (recorded once): no named reviewer roles — P2's reviewers are spawned as generic subagents carrying `agents/*.md`; the ARQ/P1 author roles were executed by orchestrator + one coder subagent with this record as the brief; no hooks — `V7` is the guard; `V15`/`V16`/`V17` not-run (bundle); `V30` half.

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| gate: record seed / P0 / ARQ | 2026-10-13 | exit 0 · 0 block at each |
| gate: P1 first pass | 2026-10-13 | exit 1 · 26 block (V4/V12/V20) — repaired |
| gate: `--brief` at the P1 close | 2026-10-13 | exit 0 · 0 block · 377 notice · 51 n/a |
| security scan `devflow-scan-spec.py` | 2026-10-13 | exit 1 · `security_required: true` · 5 vocabulary collisions answered (§6.3) |
| P1 probes: A2L census / chk round-trip / A2B provenance / rail census | 2026-10-13 | transcripts in `evidence/p1_probe_*.txt` |
| suite baseline (batch-93 close, premise 3) | 2026-10-13 | 2 796 passed · 35 pre-existing fails; re-derived at P4 |
