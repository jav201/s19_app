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
| Last updated | P3 · increment 003 gated · 2026-10-14 |
| Standing authorization | Operator (Javier), 2026-10-13, answering the P0 gate kickoff: *"1.Si, autorizados; 2.autorizo los merges; 3.Modo full."* — read as: **(1) end-to-end autonomy** over the gates this batch commissions; **(2) merge authority granted — and the merge stays gated**: after the PR is opened and CI is green, one final independent PR-level `qa-reviewer` pass over the WHOLE merged diff vs `main` must come back clean before the agent merges; a HIGH finding blocks the merge and returns to the operator; **(3) mode `full` confirmed**. Autonomy is never silent: every autonomous decision is summarized in this PLAN's decision log, `state.json.decisions_log`, the postmortem decisions summary, and carried to the vault at `/dev-flow-sync`. Per `shared-batch.md` §Batch-kickoff authorization: per-batch, never carried from a prior batch; the `standing_authorization` key is deleted from `state.json` with this cell its one record. |
| First gate | Record-seed gate (pre-P0): exit 0 — `0 block · 374 notice · 48 n/a`; `V7` raised no finding (bundle mirror `2026-10-12-rev102` self-consistent, 57 declared files both directions). Tool-proving run, not the batch. |
| Premises / RC-1 | Verified `origin/main` tip at intake: **`1a0eff6`** (2026-10-13; RC-2 answered). Two more RC-1 rebases the same day (legends batch close + completion); `base_ref` re-stamped per RC-1's literal rule to **`8e056bd`** (HEAD at the stamp; peer-verified reading). Flow currency (C-45 PULL): bundle mirror, not a git checkout — probe = `V7` + `FLOW-VERSION.md` `2026-10-12-rev102`. Premises: `01-requirements.md` §2.7 (9 rows, all TRUE). |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not. All 23 ids evaluated 2026-10-13 over the commissioned scope (US-001..US-007); family B re-evaluated at every increment cut; families C and F re-evaluated at every gate.

| Id | Verdict | Probe output |
|---|---|---|
| A1 | fired | judged — new surfaces/modules planned; a boundary is created |
| A2 | fired | judged — the file set spans ≥2 modules |
| A3 | fired | judged — the split changes `PatchEditorPanel`'s message contract; `.chk.json` is a new artifact A2B Diff consumes |
| A4 | not fired | judged — sequential increments, one worktree |
| B1 | fired | `grep -rl PatchEditorPanel tests/` → 19 files; reverse census per increment |
| B2 | not fired at intake; **amended at ARQ** — Inc-002 moves `FlowBuilderPanel` (B2 census in its packet; R-4 11-file census, membership corrected at PDR) |
| B3 | fired | three byte-identity golden observers named (batch35 pair, batch71, addendum test); drift named per increment |
| B4 | fired | `.chk.json` consumed by A2B reports; C-12 chains authored |
| C1–C5, C7 | not fired | judged — no auth/secrets/external/DB/network surface |
| C6 | fired | Phase-1 scan run (`security_required: true`, five vocabulary collisions answered) |
| C8 | fired | file-derived text rendered; hostile-input ATs per C-17 |
| D1 | fired | rail + three surfaces change; **ux-reviewer joined the PDR** |
| D2 | not fired | spike prototypes built in the target technology (Textual) |
| E1 | fired | 7 stories, 4 increments |
| E2 | not fired | writes bounded to workspace/loaded copies |
| F1 | not fired | bundle runtime — probe = `V7` line + FLOW-VERSION |
| F2 | not fired | lane A refreshed 2026-10-13 at batch-93's close |

Stations: ARQ/PDR discharged 2026-10-13; DDR ahead at P4.

## Where we are

P0, ARQ, P1, P2, PDR gates and **increment 001** CLOSED 2026-10-13 under the standing grant (decisions_log entries 1–6). The editors shipped: pe_b rework + ce_a Check Editor + `.chk.json` + A2B addendum + rail 11 (24 AT/TC nodes). Mid-increment, batch-95 landed 4 increments on main — two RC-1 rebases absorbed them (union resolutions, both lanes green). Current: **Inc-004** (Issues warnings triage, US-004 — 1 source file, `issues_view.py`) — the LAST increment. Inc-001/002/003 are gated (decisions_log 8); the rail is complete at 12; batch-95 is CLOSED (six RC-1 rebases total, all union-resolved).

## Objective

<the batch objective, restated>

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| US-001 (Cambio1, editor split) | contracted → Inc-001 | HLR-001/002; the graduation call ratified by the contract is **pe_b + ce_a with ce_b folded** (the "pe_a/ce_b" shorthand in §2.6/older docs — naming flip recorded, map text flips at the Inc-002 map-delta per ux#5) |
| US-002 (Cambio2, Patch Editor rework) | contracted → Inc-001 | HLR-003–008 from the six image annotations |
| US-003 (Check Editor + `.chk.json`) | contracted → Inc-001 | HLR-009–011; C-12 chain; write/validate only |
| US-004 (Cambio4, warnings triage) | contracted → Inc-004 | HLR-012; view-level seam; census 1 023 pasted |
| US-005 (Cambio5, Flow Builder + templates) | contracted → Inc-002 | HLR-013–016; `flow_screens.py` move (B2) |
| US-006 (Cambio6, CRC test-vector) | REFINE | parked — operator questions pending |
| US-007 (Cambio7, Flow Execution) | contracted → Inc-003 | HLR-017–021 |
| US-008/US-009 | OUT | file to lane A at close |
| P0 / ARQ / P1 / P2 / PDR | CLOSED 2026-10-13 | decisions_log 1–5 |
| P3 | Inc-001/002/003 GATED | all packets + batteries + reviews clean (Inc-003: clean with 2 LOWs recorded); Inc-004 next |

## Roadmap + increment plan

1. **Inc-001 — Patch/Check Editor split (US-001/002/003).** 4 source files (⚠ at-cap): `screens_directionb.py` (pe_b rework + ce_a twin), `changes/io.py` (`.chk.json` suffix path), `diff_report_service.py` (the addendum), `app.py` (rail + routing). Conditions riding: C-ux-2 (apply-action definition pin), the C-17 census extension, the variant-observer split (R-6), the dirty-flag writer census (R-3).
2. **Inc-002 — Flow Builder (US-005).** 5 source files (over-cap, declared reason: the B2 repoint can't ride elsewhere): + `flow_screens.py` NEW, `flow_model.py`, `flow_persistence_service.py`, `flow_execution_service.py`, `app.py`. Conditions: C-1, C-2; C-20 move-aside RED; the map-delta (incl. the `flow_screens → flow_model` edge declaration).
3. **Inc-003 — Flow Execution (US-007).** 4 source files (⚠). Conditions: C-3; the chain-set golden drift naming.
4. **Inc-004 — Issues warnings triage (US-004).** 1 source file (`issues_view.py`).

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-12/13 | Batch opened `full`; kickoff grant (autonomy + merge-gated + full confirmed) | operator's three answers at the P0 gate |
| 2026-10-13 | Three RC-1 rebases; `base_ref` stamped to HEAD per RC-1's literal rule | main moved three times while opening; peer-verified reading |
| 2026-10-13 | Batch-number collision declared: TWO batches numbered 94 | cite the full dated name always |
| 2026-10-13 | ARQ: R8 `flow_screens.py`; R9 editors stay; R10 suffix grammar; R11 rail keys open→closed at PDR; R12 US-004 seam view-level | parallelisation-rule exit 2; apply.py kind-gate |
| 2026-10-13 | P1: the contract (21/42/24/31, batch-scoped ids); probes pasted | ungoverned id space; C-35/C-39 executed |
| 2026-10-13 | P2: approve; majors discharged via LED .1-.13 or carried to P3 | corrections prescribed verbatim by the finding lenses |
| 2026-10-13 | **PDR: rail keys `=` (Check Editor) + `]` (Flow Execution), `show=False`; help-panel discoverability; probe-verified at 80×24 + 120×30; F-keys rejected (terminal swallow)** | R-1 closed by executed probe; 38-key census, zero collisions; the contract's ATs stay key-independent |
| 2026-10-13 | PDR: freeze set D1–D5 phased (ActionRequested + `.chk.json` at Inc-001; `flow_screens` at Inc-002; template/chain-set halves Inc-002/003; rail completes at Inc-003) | the map §11 pending rows |
| 2026-10-13 | PDR: naming — the shipped twins follow the graduation call **pe_b + ce_a (ce_b folded)**; "pe_a/ce_b" remains §2.6 shorthand; PLAN flipped now, map text at the Inc-002 map-delta | contract HLR-001/003 rationales ratify the graduation call |
| 2026-10-13 | Inc-001 gated: the editors shipped (4 source files at cap; 24 AT/TC nodes; rail 10→11 with `=`); the battery 23 arms all RED (5 inert arms re-asserted in fix round A); code-review found F1 (a duplicated `push_screen(LoadGuardScreen())` — two stacked modals, execution-proven), folded and re-verified clean | HLR-001..011 realized; the union tree carries batch-95's four increments green |
| 2026-10-13 | batch-95 coordination: FIVE RC-1 rebases so far (unions in `app.py`, `flow_execution_service.py`, `diff_report_service.py`, the tc028 allow-set, corpus 173→177); both lanes green at every union | the second-editor-rebases rule, applied at each cut |
| 2026-10-13 | Inc-002 gated: fb_a shipped at `flow_screens.py` (B2 done; C-2 reproduced), A2B block additive to batch-95's shapes (86 compat green), templates with dedup; C-1 discharged; review clean (one LOW → lane A: the stale SaveFlowScreen overwrite-notice) | HLR-013..016 realized |
| 2026-10-14 | Inc-003 gated: fx_a shipped — lanes/rebind/mode/run-log, chain-set runner (barrier-proven parallel), provenance report, ChainSet envelope; rail 12 with `]` (D5 complete; C-3 discharged); battery 15/15 RED after a C-56 catch; review clean (2 LOWs) | HLR-017..021 realized; only AT-B94-14 unlanded |
| 2026-10-14 | batch-95 IFC debt declared: its closed record's 5 blocks (2 V10 + 3 V14) are pre-existing-on-main baseline; crossed with the 0-new rule; permanent fix proposed in the coordination note | V53 — no re-anchoring another lane's sealed record |

## Risks / watch-items

- PDR conditions: C-1 (Inc-002), C-2 (Inc-002 re-run), C-3 (Inc-003), C-ux-2 (Inc-001 — discharged in the fold) — each discharged by reading the named artifact at its gate.
- batch-95 is ACTIVE on main (4 increments landed during Inc-001; +3 more at gate time) — RC-1 at every Inc-002/003/004 cut; the coordination note carries the intersection register.
- Inc-002's B2 census must re-run against the rebased tree (batch-95 touched `flow_model.py`); the `BLOCK_A2B` placement re-verified against R8.
- Carried minors: ux#3 chrome dirty-indicator render assertion (Inc-001 or recorded-outside); ux#6 help-panel painted assertion (Inc-001 one-liner); qa#6 LLR-002.2 declared-none (open, P3).
- A1–A6 assumption register (proposal §6): boxed-budget fits verified per increment by TC-B94-09/AT-B94-03 (Inc-001), the canvas ATs (Inc-002), the lanes ATs (Inc-003); A4 real-terminal key delivery = operator field-check at the increment demos; A5 parallel-chains state isolation pinned by AT-B94-21's error arm; A6 emitted forms pasted per C-42.
- `screens_directionb.py` carries batch-93's Memory Map work — full `test_tui_directionb.py` guard host (C-34) at every render increment's gate; snapshot drift per-cell (C-22/C-28).
- US-006 parked; Cambio8/9 OUT; the legends batch shares the "94" number — cite dated names.

## Conventions honored

- **Merge gate (kickoff grant):** PR + green CI + final independent PR-level `qa-reviewer` pass over the whole merged diff before this agent merges; HIGH returns to the operator.
- **Autonomy recording (kickoff grant):** every self-approval in this PLAN + `decisions_log` + postmortem + vault sync.
- Lane routing; coordination note; operator spike rulings (schema unchanged; `.chk.json` by suffix; provenance per block; sequential-default/parallel; refined cables).
- Review discipline: authored set frozen before reviewer dispatch; a diff that moves under a reviewer is re-dispatched (C-57); the bump follows the verdict.
- Gate rule (batch-92 post-mortem): 0 NEW fails over the declared baseline at P4.
- Batch-scoped AT/TC ids; one AT = one on-disk node (C-18); RED counterfactuals + mutation battery per increment (C-19/C-20/C-40).

## Out-of-scope carries

- US-008 (BlockTags), US-009 (README), US-006 (if unanswered) → lane A at close.
- Lane-A open items not claimed (registry blindness, IFC charter, report_service escaping — last touches Inc-001/003 files; flagged).

## Gate notices and runtime absences

- P0/ARQ/P1/P2 runs: 0 block at each close (V20/V26 detours repaired and recorded; P1's 26-block first pass recorded in the P1 close).
- PDR seal run: exit 0 · `0 block · 382 notice · 51 n/a`.
- Runtime absences (recorded once): no named reviewer roles — all reviewers spawned as generic subagents carrying `agents/*.md`; author/sealer roles by orchestrator + briefed coder subagents; no hooks — `V7` is the guard; `V15`/`V16`/`V17` not-run (bundle); `V30` half.

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| gate: every close from P0 through the PDR seal | 2026-10-13 | exit 0 · 0 block at each |
| security scan (P1 + P2 re-run) | 2026-10-13 | exit 1 · `security_required: true` · same five flags, answered |
| P1 probes (A2L census / chk round-trip / A2B provenance / rail census) | 2026-10-13 | transcripts in `evidence/p1_probe_*.txt` |
| PDR rail-key probe (author + 3 reviewer re-runs + sealer re-run) | 2026-10-13 | exit 0 · PASS · reproduced by all five runs |
| suite baseline (batch-93 close, premise 3) | 2026-10-13 | 2 796 passed · 35 pre-existing fails; re-derived at P4 |
