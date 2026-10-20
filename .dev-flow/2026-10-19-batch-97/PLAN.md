# PLAN — s19_app — Batch 2026-10-19-batch-97

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
| Batch | 2026-10-19-batch-97 |
| Objective | b94 polish: port the operator-approved prototype round (prototypes/b94_polish, verdict A on all four screens) into the four batch-94 screens -- Patch Editor = ledger + inspector with a consultable JSON tab (live or explicit Update, Load keeps populating), Check Editor = ledger + inspector, Flow Builder = pipeline rail, Flow Execution = pipeline rail; Run as the second bright element; CRC accent burnt orange (amber only for waiting-human); folder-open chip + window help on every one of the four screens (new chip families flows + session); width-adaptive layouts (118x54 minimum, ~220x60 large reference), no wrapped rows; English UI strings. Input: .dev-flow/design/HANDOFF-b94-polish-2026-10-20.md |
| Last updated | P2 · 2026-10-20 (iterate-to-refine → P1) |
| Standing authorization | Asked at the P0 gate, answered by the operator 2026-10-20 (kickoff questions put in Spanish, answers quoted as chosen). **Gates** — "Autónomo con excepciones": the agent self-approves the gates and records each one in this plan and in `state.json`, but STOPS at PDR (design) and on any HIGH finding. **Git** — "Commit y push en cada cierre": the agent commits and pushes to `main` at each close, no PR (as batch-95); a HIGH finding still blocks and returns to the operator. **DoR** — "Las seis": US-134..US-139 proceed. Commission: "Using /dev-flow vamos desde aquí: C:\Users\jjgh8\Github\s19_app\.dev-flow\design\HANDOFF-b94-polish-2026-10-20.md" |
| First gate | Exit 0 at P0 after the rollover (0 block · 462 notice · 44 n/a). `V7`: "bundle identical to the manifest it ships, BOTH DIRECTIONS (57 declared file(s) unmoved, 0 undeclared) at `2026-10-12-rev102`". The pre-rollover run exited 1 (298 block) on the closed batch-94 record — see §Gate notices. |
| Premises / RC-1 | RC-1 (a): `git fetch origin` run 2026-10-19; `origin/main` tip = `ad10fb5ce6228a2a3823e472fd8e46c09122141d`; merge-base(HEAD, origin/main) = the same commit, so no rebase was owed. Local `main` is one commit ahead (`51ee191`, the docs-only backlog routing of the Code-Wire findings, not yet pushed); `base_ref` = `51ee1914f20d1f031dbced129ce66bda750dbde9`. RC-1 (b): each story's outcome grepped on `origin/main` — 0 hits for the inspector/JSON tab, the report-fields card, the pipeline rails, the `flows`/`session` chip families and the burnt-orange token; the shipped gaps the stories close are present (`patch_win_json` 9 hits, `titled_header("Flow Execution")` with no chip 1, the Check Editor's bare `Label` 1, `_CANVAS_COLS =` 1) — no story is SATISFIED-EXTERNALLY. RC-2: `git ls-remote --exit-code --heads origin` answered (refs served); newest `origin/main` commit 2026-10-19 16:57 -0600. |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not.

| Id | Verdict | Probe output |
|---|---|---|
| A1 | not fired | judged — `docs/ARCHITECTURE.md` module table read · no module is created and no boundary moves: the work re-composes four existing panels and extends an existing service's family table |
| A2 | fired | judged — the map lists `s19_app/tui/screens_directionb.py` and `s19_app/tui/flow_screens.py` (`ARCHITECTURE.md:369`, `:380`) as separate modules, plus `s19_app/tui/services/*` and `app.py`; the batch touches all four |
| A3 | fired | judged — `folder_open_service` chip families (`CHIP_FAMILY_*`, `folder_open_service.py:57-60`) are consumed by `open_folder_chip.py` and `app.py`; two families are added. The Patch Editor panel's `refresh_entries` input (rows + mem_map only) gains the document identity (handoff §5 E-5) |
| A4 | not fired | judged — increments are planned sequential (handoff §6), no parallel lanes |
| B1 | fired | `grep -rlE "patch_doc_entries_table\|patch_win_json\|_apply_window_geometry\|PatchEditorPanel" tests/` → 86 files; `check_param_table\|CheckEditorPanel` → 1; `FlowBuilderPanel\|FlowExecutionPanel\|fx_confirm_\|flow_palette_` → 33; `OpenFolderChip\|resolve_chip_target\|CHIP_FAMILIES` → 8 — reverse census owed per increment |
| B2 | not fired | judged — no file moves; panels stay in their modules |
| B3 | fired | `tests/test_tui_snapshot.py:110` `_SCAFFOLD_SCREENS = ["map", "patch", "diff"]` — the patch screen has SVG baselines (29 `.svg` files, `test_tui_snapshot.py:20`); golden drift is owed in the census |
| B4 | not fired | judged — no new artifact format is produced; the change-set JSON and `.chk.json` writers are untouched (the JSON tab renders the document, it does not write it) |
| C1–C7 | not fired | judged at intake — no auth, secret, external integration, sensitive data, DB, new input surface beyond existing inputs, or network exposure; the P1 scan (`devflow-scan-spec.py`) re-checks the contract mechanically |
| C8 | fired | judged — new renders (inspector hex strip, report-fields ledger, pipeline cards, lane headers) paint file-derived text (A2L parameter names, change-doc and flow file names, paths); Textual `Static`/`Label` parse markup by default, so a markup-safety LLR + a hostile-input AT are owed at P1 (C-17) |
| D1 | fired | judged — the batch changes four screens the user sees and touches |
| D2 | not fired | judged — the prototype round ran the REAL app (Textual 8.2.8) with monkeypatched panels at the shipped ids (`prototypes/b94_polish/run_real.py`); same technology as the target |
| E1 | fired | judged — 6 stories, 6 planned increments |
| E2 | not fired | judged — design port with services unchanged; risk moderate (handoff §5 traps), not high |
| E3 | not fired | judged — internal tool, not a client deliverable or regulated context |
| F1 | not fired | `V7`: "bundle identical to the manifest it ships … at `2026-10-12-rev102` · `flow_hash` is not recomputable from a subset" — from a bundle F1 is `not fired` with this line as its probe |
| F2 | not fired | judged — `BACKLOG-CODE.md` last reconciled at the batch-94 close (`05886e6`) and amended since (`51ee191`) |

## Where we are

P0 closed 2026-10-20: the operator passed all six stories (US-134..US-139) through the Definition of
Ready and answered the kickoff (autonomous gates with stops at PDR and on HIGH; commit + push at each
close). The batch was opened by rollover from the closed `2026-10-12-batch-94` (decisions_log
archived, 20 entries). Now: ARQ (A2/A3 fired) -- the module-map update -- before P1 derives anything.

## Objective

Port the four chosen prototype layouts into the shipped panels (not the prototype code), resolving
the integration traps the prototypes overrode, so that the four batch-94 screens reach the quality of
the rest of the app at both 118x54 and ~220x60.

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| P0 | closed 2026-10-20 | DoR: all six READY stories proceed (operator) |
| US-134 Patch Editor | READY | JSON refresh mechanism decided at PDR |
| US-135 Check Editor | READY | — |
| US-136 Flow Builder | READY | canvas reachability decided at PDR |
| US-137 Flow Execution | READY | outcome↔lane mapping confirmed at PDR |
| US-138 Chips + help | READY | two new chip families |
| US-139 Width-adaptive | READY | sweep increment at both sizes |
| ARQ | closed 2026-10-20 | `docs/architecture.md` batch-97 section (I-1..I-4, R13-R17); 4 PDR questions |
| P1 | closed 2026-10-20 | HLR-144..149 · 38 LLR · AT-B97-01..16 · TC-B97-01..38 · 10 PDR decisions |
| P2 round 1 | iterate-to-refine 2026-10-20 | 1 blocker (Q-1) · 33 major · 31 minor — `02-review.md` |
| P1 iteration 1 | in progress | amending the contract against the P2 findings |
| PDR · P3 · DDR · P4 · P5 · P6 | not started | PDR is an operator stop |

## Roadmap + increment plan

Proposed from handoff §6; fixed at PDR. ≤4 source files each, tests uncapped.

1. Check Editor → ce_A + chip + help (US-135, US-138 part).
2. Patch Editor → pe_A + JSON tab + geometry cleanup (US-134).
3. Chip families `flows` + `session`; CRC burnt-orange token (US-138 part, R-5).
4. Flow Builder → fb_A (US-136).
5. Flow Execution → fx_A (US-137).
6. Width sweep 118 + 220, real captures, review-page rebuild (US-139).

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-19 | Batch numbered 97, not 96 | batch-96 shipped on `main` without a batch directory (commits `bd42d8d`..`ad10fb5`, `PENDIENTES-batch96.md`); its number is taken |
| 2026-10-19 | Mode `full` | the operator's standing rule (dev-flow runs full) and a four-screen design port |
| 2026-10-19 | Closed batch-95 contract repaired so the corpus gate passes | `V10` (2 nodes with two owners each, split one node per owner) and `V14` (a `consumers` value carrying prose, set to the legal `none`) BLOCKed on `.dev-flow/2026-10-13-batch-95/01-requirements.md` under rev102; meaning unchanged; the `_derived/` atlases regenerated (`V20`) |
| 2026-10-20 | P0 closed: all six stories READY, ARQ next | the operator's DoR answer "Las seis" (asked at the gate) |
| 2026-10-20 | ARQ closed: no module or boundary moved; burnt-orange is a NEW token in `insight_style.py` (no CRC colour ships today; waiting uses `#f6ff8f`) | architect's measured map; self-approved under the standing authorization |
| 2026-10-20 | P1 closed; the qa-reviewer's P1 validation-method pass is folded into the independent P2 qa lens | the architect wrote every requirement's validation method; one independent qa reading at P2 instead of two |
| 2026-10-20 | P2 round 1 → iterate-to-refine; rulings Q-5 (80x24 floor kept, reachable under scroll), Q-2 (service Spanish strings in scope), A-2/Q-8 (derive, not drop) | blocker Q-1 forces it; the rulings keep shipped behaviour and honour the operator's English rule; colour, primary action, card growth and JSON refresh stay at PDR |
| 2026-10-19 | Test ids batch-scoped (`AT-B97-NN`, `TC-B97-NN`) | `docs/engineering-rules.md` §AT/TC id allocation prefers batch-scoped ids; no global reservation PR owed |

## Risks / watch-items

- Shipped handlers re-run under a re-composed panel (handoff §5 E-1: double columns, forced heights) · high · remove the double work instead of `prevent_default()` overrides; a test asserts the column count.
- `app.py` re-applies Patch Editor geometry on every show (E-2) · high · retarget or delete; a test shows the screen twice and asserts the layout holds.
- Snapshot goldens of the patch screen move (B3) · certain · re-baseline in the increment that moves them, named in its census.
- 86 test files reach Patch Editor ids (B1) · medium · ids are kept; reverse census per increment.
- CRC vs waiting-human hue (R-5) · medium · a real capture with both on screen at acceptance.
- Concurrent all-screens review by another agent (Kimi) · medium · the second editor rebases (`COORDINACION-batch92.md` rule); this batch owns only the four screens.

## Conventions honored

- Supervised increments, ≤4 source files, review packet per increment; English for code, UI and records; Spanish in the chat.
- Nothing from `prototypes/` is promoted as-is; the harness re-captures the implementation.
- No operator name in code, tests or records.

## Out-of-scope carries

- `Fmt · Unit` column (ce_C) and the matrix density mode (fx_C) — offered, not chosen.
- Hex-viewer no-wrap rule on A2L viewer / Hex View — backlog item for the all-screens review.
- The eight Code-Wire pilot findings — `BACKLOG-CODE.md` (`51ee191`).
- Batch-96 follow-ups — untouched.

## Gate notices and runtime absences

**Runtime absences (named once).** Hooks and the prompt guard: not wired into this checkout's run;
`V15` (no canon tree beside the bundle), `V16` (the checkout table is a canon file) and `V17` (no
`settings.json` hook) are `not-run` from a bundle. `V30` runs half (the bundle ships 5 of the Python
files the floor table declares). Reviewer roles ARE available as named agents on this runtime
(`architect`, `qa-reviewer`, `code-reviewer`, `security-reviewer`, `ux-reviewer`, `tester`), so the
gates' reviews are independent, not self-executed.

**P0 gate run (after the rollover): exit 0, 0 block · 462 notice.** By rule:
- `V9` 239, `V13` 79, `V23` 96, `V22` 9, `V12` 5, `V42` 2, `V53` 1, `V8` 1 — corpus notices over closed batches' records (historical packets without a SOURCE count, unreferenced literals, citation grammar, unowned LLRs, balancing not checkable, deferral-marker spellings, the anchor census, a root-file path the map rule cannot express). None names this batch; they stand as the record of earlier batches.
- `V31`–`V38`, `V41`, `V43`–`V52`, `V54` — this batch's seeded artifacts still hold template placeholders (increment-001, 04-validation, 05-close, the design proposal, HLR-001 / §2.7 / §2.8 of the contract). Expected at P0; each is filled at its station.
- `V20` 5 — this batch's files are untracked until the rollover commit; cleared by that commit.
- `V27` — the decisions_log is empty at P0; the first gate entry fills it.
- `V30` — bundle subset (above).

**Pre-rollover run: exit 1, 298 block** — `V59` 292 (the closed batch-94's `base_ref` diff charged batch-96 commits and the untracked prototype folders to it; cleared by re-stamping `base_ref` at the rollover), `V10` 2 + `V14` 3 (batch-95 contract, repaired — Key decisions), `V20` 1 (stale `_derived/` atlas, regenerated).

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| `devflow-validate.py --brief` (P0) | 2026-10-19 | exit 0 — 0 block · 462 notice · 44 n/a |
| `pytest` (full suite, baseline) | — | owed before increment 1 |
