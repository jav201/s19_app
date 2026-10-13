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
**Create at batch open and update at every gate and significant checkpoint** — the
orchestrator presents the full plan in-conversation at each phase gate.

## Header

| Field | Value |
|---|---|
| Project | s19_app |
| Batch | 2026-10-12-batch-94 |
| Objective | Cambio1-7: Flow Builder por bloques (fb_a) + Flow Execution (fx_a) + split Patch/Check Editor (pe_a/ce_b) -- A2B configurable por bloque con procedencia en el reporte, check-spec .chk.json (write/validate only), control secuencial(default)/paralelo, ruteo de cables refinado. Design input: 4 SVG ganadores en G:/My Drive/dev-flow-radiografia/Refactor_10_11_26/Prototipos/. Coordination: COORDINACION-batch92.md (overlap screens_directionb.py con batch-93 -- second-editor-rebases rule). |
| Last updated | P0 · 2026-10-13 |
| Standing authorization | PENDING at this gate — the kickoff questions are put to the operator at the P0 gate presentation (autonomy? merge to main at close? mode `full` confirmed?). Until answered, no gate is self-closed; state.json `standing_authorization.operator_words` records the same pending state. |
| First gate | Record-seed gate (pre-P0): exit 0 — `0 block · 374 notice · 48 n/a` on the just-seeded record; `V7` manifest-identity arm raised no finding (the run's BLOCK/NOTICE list names V7 nothing; bundle mirror `2026-10-12-rev102` proved self-consistent). This gate proves the TOOL, not the batch. |
| Premises / RC-1 | Verified `origin/main` tip: **`1a0eff6bad2fa84db96f0a8ec1fe273a57a77a5a`** (fetched 2026-10-13; RC-2 probe answered, newest commit 2026-10-13 06:49 −0600). The batch opened at `ae0ef4f` — 5+1 commits behind — and was rebased (fast-forward) onto the tip BEFORE any derivation, per RC-1; `base_ref` re-stamped. Flow currency (C-45 PULL): this runtime runs the bundle mirror at `C:/Users/jjgh8/.claude/skills/dev-flow`, **not a git checkout** — currency probe = the `V7` bundle-identity line + `FLOW-VERSION.md` → `flow_version 2026-10-12-rev102`. Premises: see `01-requirements.md` §2.7 (6 rows, all TRUE). |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not. All 23 ids evaluated 2026-10-13 over the commissioned scope (US-001..US-007); family B re-evaluated at every increment cut; families C and F re-evaluated at every gate.

| Id | Verdict | Probe output |
|---|---|---|
| A1 | fired | judged — new surfaces/modules planned (Check Editor panel, Flow Execution surface + rail entry, `flow_*` execution services per the coordination file set); a boundary is created |
| A2 | fired | judged — the file set spans ≥2 modules (`screens_directionb.py`, `services/flow_*`, `changes/`, `app.py`) |
| A3 | fired | judged — the split changes `PatchEditorPanel`'s message contract consumed by `app.py`/`screens.py`; `.chk.json` is a new artifact A2B Diff consumes |
| A4 | not fired | judged — multiple increments are planned but run sequentially in one worktree, not in parallel lanes |
| B1 | fired | `grep -rl PatchEditorPanel tests/` → cross-owned assertions (guard host `test_tui_directionb.py`, `test_tui_patch_editor_v2.py`); reverse census owed per increment |
| B2 | not fired | judged — no file moves planned (new files only); re-check at each increment cut |
| B3 | fired | `grep -l "flow_" tests/goldens/**/*.md` → flow-report goldens capture flow-service sources (`batch74/producer-bound-positive-control.md`, `batch76/document-bound-preflight.md`); golden drift to be named per increment |
| B4 | fired | judged — `.chk.json` produced by Check Editor is consumed by A2B Diff reports; flow-block outputs consumed by downstream blocks; output-then-consume ATs (C-12) owed |
| C1–C5, C7 | not fired | judged — no auth/secrets/external-integration/sensitive-data/DB/network surface in this TUI tool |
| C6 | fired | judged — the app ingests user-supplied files (S19/HEX/A2L/JSON); mechanized by the Phase-1 `devflow-scan-spec.py` scan |
| C8 | fired | judged — file-derived text is rendered in TUI surfaces and markdown reports (the C-17/C-42 lineage: reports embed file-derived text); scan at Phase 1 |
| D1 | fired | judged — the user-visible rail and three surfaces change (approved design set fb_a/fx_a/pe_a/ce_b) |
| D2 | not fired | judged — the spike prototypes were built in the target technology (Textual, truecolor); no tech gap to bridge |
| E1 | fired | judged — 7 stories commissioned, 4 increments planned |
| E2 | not fired | judged — no high-risk declaration at intake; execution writes stay bounded to loaded/workspace copies under the existing services precedent |
| F1 | not fired | bundle runtime — cannot recompute `flow_hash`; probe = the `V7` bundle-identity line (`0 block`, manifest self-consistent) + `FLOW-VERSION.md` `2026-10-12-rev102` |
| F2 | not fired | judged — lane A last refreshed 2026-10-13 at batch-93's close (`BACKLOG-CODE.md:145`); no close has superseded it |

Stations taken up by the fired A-family: **ARQ → PDR → DDR** (chain), inserted at their schema positions; their artifacts are seeded by `devflow-init.py --fired` (architecture map — already on disk, not overwritten; design proposal + PDR/DDR reviews — new).

## Where we are

P0 gate. The record is seeded (full), RC-1/RC-2 verified against `1a0eff6`, lane A read, the nine source stories classified (6 READY · 1 REFINE · 2 OUT), triggers evaluated (ARQ/PDR/DDR taken up), premises table filled. What is owed next, on approval: ARQ (the module map update, since ARQ fired) → P1 requirements derivation for US-001..005 + US-007 (US-006 parked, REFINE).

## Objective

<the batch objective, restated>

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| US-001 (Cambio1, editor split) | READY | increment 001 with US-003; design pe_a/ce_b approved |
| US-002 (Cambio2, Patch Editor rework) | READY | six image annotations → P1 HLR candidates; evidence/PatchEditor1.png |
| US-003 (Cambio3, Check Editor + `.chk.json`) | READY | approved decisions: suffix distinction, write/validate only, provenance in report |
| US-004 (Cambio4, warnings triage) | READY | bounded audit: `A2L_UNRECOGNIZED_BLOCK` class on the operator's A2L |
| US-005 (Cambio5, Flow Builder + templates) | READY | spike discharged (fb_a); blocks: patch/CRC/A2B diff |
| US-006 (Cambio6, CRC test-vector) | REFINE | parked — operator questions (purpose confirmation + the CRC algorithm description) |
| US-007 (Cambio7, Flow Execution) | READY | fx_a; sequential-default/parallel-per-chain ruling |
| US-008 (Cambio8, BlockTags) | OUT | outside the commission; file to lane A at close |
| US-009 (Cambio9, README) | OUT | docs-only; file to lane A at close |
| P0 | gate presented 2026-10-13 | this presentation |
| ARQ / P1… | pending | on P0 approval |

## Roadmap + increment plan

1. **Inc-001 — Patch/Check Editor split (US-001/002/003).** `PatchEditorPanel` → pe_a patch twin + ce_b check twin; the six rework annotations; `.chk.json` write/validate; rail entries. Lands first: it stabilizes the patch JSON shape the flow blocks consume.
2. **Inc-002 — Flow Builder (US-005).** fb_a block-diagram builder (palette/canvas/cables refined); patch, CRC, A2B diff blocks; template save. A2B block inputs: flow outputs or external files, provenance in report.
3. **Inc-003 — Flow Execution (US-007).** fx_a carriles + run-log; template import; per-chain input rebinding; sequential(default)/parallel control; set save/load.
4. **Inc-004 — Issues warnings triage (US-004).** recognize-or-reclassify audit of `A2L_UNRECOGNIZED_BLOCK`; small, slots after Inc-001 (touches `issues_view`/validation emitters, disjoint from the flow surfaces).
5. US-006 re-enters only when the operator answers (REFINE → possible Inc-005).

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-12 | Batch opened `full`, base `ae0ef4f` | rollover from batch-93; mode full per operator's standing preference — confirmation asked at this gate |
| 2026-10-13 | RC-1 rebase: ff to `1a0eff6` BEFORE derivation; `base_ref` re-stamped | batch-93 closed + operator-verified while the batch was opening |
| 2026-10-13 | Cambio8/9 recorded OUT | outside the Cambio1–7 commission; filed to lane A at close |
| 2026-10-13 | Triggers: A1/A2/A3, B1/B3/B4, C6/C8, D1, E1 fired | probes in the table above; ARQ/PDR/DDR taken up |

## Risks / watch-items

- `screens_directionb.py` carries batch-93's just-merged Memory Map work (+544 lines) — batch-94 edits it second, on the rebased tree; every render increment runs the FULL `test_tui_directionb.py` guard host (C-34) at its gate.
- Geometry budgets of the new surfaces: the spike measured full-screen prototypes at 120×30/160×40/200×52 truecolor; production boxes panels inside app chrome — C-29's non-transfer trap is LIVE; P1 owes two-axis pilot measurements (C-13/C-23/C-29) per surface.
- Snapshot drift: a new rail entry + two new surfaces move the rail census, footer bindings and per-screen cells — per-cell drift census per increment (C-22/C-28).
- AT/TC ids: re-read `AT-TC-REGISTRY.jsonl` `_meta.next_free` at P1 before reserving (post-merge high-water; batch-scoped ids preferred per `engineering-rules.md`); the batch-93 renumber debt was discharged at its close (high-water repaired to TC-681) — verified, not assumed, at P1.
- Flow Execution writes chained outputs to disk — bounded to workspace/loaded copies under the existing services precedent; no destructive paths beyond the tool's core purpose.
- US-006 parked in REFINE: if the operator's answers arrive mid-batch, it re-enters at the next gate; else it files to lane A at close.

## Conventions honored

- Lane routing (`engineering-rules.md`): lane A read at P0; Cambio8/9 + US-006 (if unanswered) file to lane A at close. Router (`BACKLOG.md`) untouched.
- Coordination note (COORDINACION-batch92.md §BATCH-94): file sets respected; the `screens_directionb.py` overlap resolved by the RC-1 rebase (batch-94 is the second editor, on top of merged batch-93).
- Operator rulings from the spike (flow_bench.NOTES.md / editor_bench.NOTES.md): changeset schema UNCHANGED (no `from`/`to`); `.chk.json` by suffix; A2B configurable per block with input provenance in the report; sequential(default)/parallel-per-chain control; refined cable routing.
- Gate rule (batch-92 post-mortem): the local suite is NOT the sharp gate — 0 NEW fails over the declared baseline, snapshots per-cell (flaky-tolerant union rule) carries into this batch's P4.
- Batch-scoped vs global AT/TC ids per `engineering-rules.md`; one AT = one on-disk node (C-18); RED counterfactuals mandatory per increment.

## Out-of-scope carries

- US-008 (BlockTags) — file to lane A at close as a chartered candidate (depends on Inc-002/003).
- US-009 (README refresh) — file to lane A at close; docs-only, no flow needed.
- US-006 (CRC test-vector) — parked REFINE; file to lane A at close if unanswered.
- No carry from the lane-A open queue is claimed by this batch (the P1 head items — registry blindness, IFC charter, report_service escaping — are noted as related but NOT in scope; `report_service` escaping may touch the same files Inc-003 touches — flagged, not claimed).

## Gate notices and runtime absences

- Record-seed gate (pre-P0, tool-proving run): exit 0 · `0 block · 374 notice · 48 n/a`. Expected notices on a just-seeded record: template placeholders (V31–V49 family), empty ledger/decisions (V27), PDR-station staging (V52), standing-authorization cell (V55 — holds PENDING until the operator answers this gate), historical census notices (V42/V53 — pre-existing, declared).
- P0 gate run (post-intake): first full run went **exit 1 · 4 BLOCK** — all V20, the derived atlases committed at seed time went stale under the intake commit's new corpus (design seeds, evidence). Repaired by `--atlas --write` + commit (`derived atlases regenerated at the P0 gate`); re-run exit 0 · `0 block · 374 notice · 50 n/a`. Standing notices read at this gate: V52 (design proposal is the untouched template — owed at PDR), V55 (grant pending this gate), V30/V15/V17 (bundle absences below), V27 (no gate decisions yet — this gate writes the first).
- Runtime absences (this bundle runtime, recorded once per `SKILL.md` step 5): no named reviewer roles — reviewers are spawned as generic subagents carrying the role files from `agents/`, or self-executed and declared; no hooks/prompt-guard — the validator (`V7`) is the guard; `V15`/`V16`/`V17` not-run (no canon tree / checkout table / wired settings here — recorded with reason); `V30` half (bundle ships 5 Python files of the floor set). The `Independent review` cell of every packet will lead with the role + how it ran.
- V25: n/a — this project HAS an origin remote and it answered (RC-2 above).

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| gate: `devflow-validate.py --brief <wt>` (record seed) | 2026-10-13 | exit 0 · 0 block · 374 notice · 48 n/a |
| gate: full + `--brief` post-intake (the P0 gate run) | 2026-10-13 | exit 0 · 0 block · 374 notice · 50 n/a · `V7`: bundle identical to the manifest it ships, BOTH DIRECTIONS (57 declared files) at `2026-10-12-rev102` |
| suite baseline (inherited from batch-93 close, premise 3) | 2026-10-13 | 2 796 passed · 35 pre-existing fails (census `c25-failure-census.txt`); re-derived at P4 |
