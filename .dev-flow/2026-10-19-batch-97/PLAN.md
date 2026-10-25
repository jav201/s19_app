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
| Last updated | P6 · 2026-10-25 (P6 documentation written: `06-docs/` traceability matrix, functionality, executive summary and three diagrams; state `awaiting-sync` -- the operator reviews at commit, pushes and runs `/dev-flow-sync`. Before: P5 · 2026-10-25, batch closed by the operator's decision "close now": DDR approved with conditions, P4 PASS-WITH-NOTES, close record `05-close.md`; all 9 increments on `main`, close commit `c899113`) |
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

Closed 2026-10-25 by the operator's decision ("batch-97: close now", `.dev-flow/BACKLOG-CODE.md` §*Decided 2026-10-25*). All nine increments are on `main` and pushed (`origin/main` = `432ecf0`). The DDR was walked by the architect (approved with conditions), P4 evaluated by the qa-reviewer (PASS-WITH-NOTES, no HIGH) and the close written in `05-close.md`. What comes next is the operator's routing: the integrity batch → the Load+projects batch (progress bar in its prototype round) → the waiting-lane scroll prototype → the batch-98 flow report. The close files are uncommitted; the operator commits, pushes and syncs.

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
| US-140 Two-row key bar | READY (added 2026-10-20) | operator verdict A on the key-bar round; Inc-8, before Inc-7 (LED-…97.9) |
| ARQ | closed 2026-10-20 | `docs/architecture.md` batch-97 section (I-1..I-4, R13-R17); 4 PDR questions |
| P1 | closed 2026-10-20 | HLR-144..149 · 38 LLR · AT-B97-01..16 · TC-B97-01..38 · 10 PDR decisions |
| P2 round 1 | iterate-to-refine 2026-10-20 | 1 blocker (Q-1) · 33 major · 31 minor — `02-review.md` |
| P1 iteration 1 | closed 2026-10-20 | LED-.2: 59 LLR · AT-B97-01..24 · TC-B97-01..59 · 16 PDR decisions |
| P2 round 2 | iterate-to-refine 2026-10-20 | 1 blocker (Q2-1) · 17 major · 27 minor |
| P1 iteration 2 | closed 2026-10-20 | LED-.3: 65 LLR · 24 AT · 65 TC · 49 premises · appendix |
| P2 round 3 | iterate-to-refine 2026-10-20, STOPPED at the soft iteration cap | 1 blocker (Q3-1) · 11 major · 15 minor; security approved. Root cause: the contract specifies test procedures at predicate level (65 LLRs, 65 TC procedures), so each amendment adds new test-design surface the next review finds defects in; findings converge (33 → 17 → 11 majors) and none reopens a decision. Operator answered 'Ultima enmienda + verificacion acotada' |
| P1 iteration 3 | closed 2026-10-20 | LED-.4: 27 round-3 rows fixed, P-50..P-60 executed |
| P2 verification (scoped) | approve 2026-10-20 | all four lenses; fold LED-.5 for two one-line contradictions |
| PDR | awaiting the operator | proposal `7d823a7`; 3 reviewers approved with conditions (0 blockers); Code-Wire annex (4 majors); 21 conditions PC-1..PC-21; review page `prototypes/b94_polish/pdr-review.html` |
| PDR | approved with conditions 2026-10-20 (`070429f`) | PC-1..PC-22; delta 2026-10-20 on the key bar: PC-22 re-routed into the batch, PC-23..PC-26 |
| P3 | closed 2026-10-23 | Inc-1 `d5d0ff9` · Inc-2 `f93dadc` · Inc-3 `98f3c84` · Inc-4 `09e44de` · Inc-5 `b514b07` · Inc-6 `9793fcd` · Inc-8 `354857c` · Inc-9 `5cb7618` (Load project dialog, added by the operator 2026-10-23) · Inc-7 `432ecf0` |
| DDR | approved with conditions 2026-10-25 | architect re-read; PC-1..PC-25 discharged, PC-26 outstanding (operator decision); DC-1..DC-5 routed to `BACKLOG-CODE.md` — `design/DDR-2026-10-19-batch-97.md` |
| P4 | PASS-WITH-NOTES 2026-10-25 | qa-reviewer; gate run = the orchestrator's Inc-7 full suite (`evidence/inc-7/suite-full.txt`, source digest-equal to `432ecf0`); 0 HIGH, 7 minor gaps — `04-validation.md` |
| P5 | closed 2026-10-25 | `05-close.md` (architect + qa-reviewer co-authored); canon folded 81 ids; carries in `BACKLOG-CODE.md` §*Routed 2026-10-25 — batch-97 (the b94 polish) close* |
| P6 | written 2026-10-25, awaiting sync | `06-docs/`: `traceability-matrix.md` (73 LLR rows, 26 AT rows, the seven P4 minor gaps), `functionality.md`, `executive-summary.md` (presentation-builder, spawned), `diagrams/` (architecture, attention-confirm, folder-chip); validator `--brief`: 0 block |

## Roadmap + increment plan

Proposed from handoff §6; fixed at PDR (`design/design-proposal.md` §6.1); Inc-8 added by the PDR delta of 2026-10-20. ≤4 source files each, tests uncapped.
**Execution order: Inc-1 → 2 → 3 → 4 → 5 → 6 → 8 → 7** (labels kept, so no PDR condition is renumbered).

1. Inc-1 — chip families `flows` + `session`, the real-directory guard, folder labels (US-138 part) — closed `d5d0ff9`.
2. Inc-2 — flow foundations: NUL refusal, English service strings, the two role tokens (US-136/137 part).
3. Inc-3 — Check Editor → ce_A + chip + help (US-135).
4. Inc-4 — Patch Editor → pe_A + JSON tab + geometry cleanup (US-134).
5. Inc-5 — Flow Builder → fb_A (US-136).
6. Inc-6 — Flow Execution → fx_A + headers close (US-137, US-138).
7. **Inc-8** — the two-row key bar on every window: `window_help.py`, `app.py`, `styles.tcss` (US-140). Runs before Inc-7 so the sweep and the snapshot regen see the final bottom rows.
8. Inc-7 — width sweep 118 + 220 on the two-row layout, real captures, review-page rebuild, snapshot regen (US-139).

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
| 2026-10-20 | Operator design decisions before the round-3 amendment (asked in chat): hue pair waiting `#e8ad3d` / CRC `#c9562b` (option A, 23.0°), notices yellow `#f6ff8f` kept with the operator's reservation to re-judge on the captures; primary action Patch = Save, Check = Write; multi-variant runs = one Builder chain per variant set up with the funnel block, run as lanes in Flow Execution (`#flow_scope` leaves the Builder, LLR-104.6 retired for the Builder); JSON tab live with a stamp, read-only, no button | operator answers 2026-10-20; colours judged on `prototypes/b94_polish/colores-espera-crc.html` |
| 2026-10-20 | Orchestrator decisions (revisable at PDR): cards grow at wide sizes; Confirm not auto-focused, scoped confirm key; chip labels name their folder; `░` after a waiting block; runs stay on the UI thread (freeze declared OUT); lanes scroll horizontally with the waiting card brought into view | UX recommendations, minor design items under the standing authorization |
| 2026-10-19 | Test ids batch-scoped (`AT-B97-NN`, `TC-B97-NN`) | `docs/engineering-rules.md` §AT/TC id allocation prefers batch-scoped ids; no global reservation PR owed |
| 2026-10-20 | Key bar folded into the batch as Inc-8 (US-140 / HLR-150, LED-…97.9), executed after Inc-6 and before Inc-7 | operator verdict on the key-bar round: A · Two rows accepted and preferred, no per-window objection (`evidence/operator-keybar-verdict-2026-10-20.json`), and the instruction "Mete el cambio al incremento"; design D26–D29, I-10, I-11; PDR PC-22 re-routed, PC-23..PC-26 |
| 2026-10-20 | Key-bar QA folded (approve with conditions); a click on a token runs the binding's action in its own namespace, never `simulate_key` (H-1) | the operator's chat decision, option (a); LED-…97.10; D10 / D16 gain the descriptions `Confirm` / `Include` (must land with Inc-6 / Inc-3); PC-24 widened to every vertical arm at 118x53 |

## Risks / watch-items

- Shipped handlers re-run under a re-composed panel (handoff §5 E-1: double columns, forced heights) · high · remove the double work instead of `prevent_default()` overrides; a test asserts the column count.
- `app.py` re-applies Patch Editor geometry on every show (E-2) · high · retarget or delete; a test shows the screen twice and asserts the layout holds.
- Snapshot goldens of the patch screen move (B3) · certain · re-baseline in the increment that moves them, named in its census.
- 86 test files reach Patch Editor ids (B1) · medium · ids are kept; reverse census per increment.
- CRC vs waiting-human hue (R-5) · medium · a real capture with both on screen at acceptance.
- Shipped `main` is red: 10 pre-existing test failures (Test ledger) · certain · each increment diffs its failures against the baseline list; the Patch Editor four are re-examined in that increment, the rest routed to the backlog at the close.
- Concurrent all-screens review by another agent (Kimi) · medium · the second editor rebases (`COORDINACION-batch92.md` rule); this batch owns only the four screens and, from Inc-8, the app-wide key bar.
- The key bar takes one row from every window (HLR-150) · certain · Inc-3..6 also check their vertical budget at 118x53 (PC-24); Inc-8 re-checks at 118x54 with the bar; the footer tests are rewritten by named supersession (PC-25).

## Conventions honored

- Supervised increments, ≤4 source files, review packet per increment; English for code, UI and records; Spanish in the chat.
- Nothing from `prototypes/` is promoted as-is; the harness re-captures the implementation.
- No operator name in code, tests or records.

## Out-of-scope carries

- `Fmt · Unit` column (ce_C) and the matrix density mode (fx_C) — offered, not chosen.
- Hex-viewer no-wrap rule on A2L viewer / Hex View — backlog item for the all-screens review.
- Go keys on row 2 of the eight windows the key-bar round did not render — a later edit of the window-key table (PC-26).
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

**Close gate run (2026-10-25, after the canon fold and `--atlas --write`): exit 0, 0 block · 494 notice · 51 n/a.** By rule:
- `V9`, `V13`, `V23`, `V12`, `V42`, `V53`, `V8` — the same corpus notices over closed batches' records as at P0; `V23` also names six citation tokens in this batch's packets, PDR and design proposal (`increment-002.md:15`, `increment-004.md:15`, the sealed PDR record's lines 180 and 182, `design-proposal.md:18` and `:464`) — sealed or narrative text, not re-anchored; the DDR's §D rows bind the same decisions in the declared grammar.
- `V22` — unowned-LLR questions (this batch's included, a question per id, never a gate) and the canon seeding backlog of earlier batches; this batch's 81 ids are folded (`canon: REQUIREMENTS.md -- 81 folded, 0 kept, 0 refused`).
- `V26` — the contract is 232 010 characters against the 54 000 budget (A3-8, carried).
- `V31`, `V32`, `V37`, `V38`, `V41`, `V43`, `V44` on `increment-009.md` and `V33`–`V35` on HLR-151 — Inc-9 ran a light packet with no AT id; routed as DDR DC-1 (integrity batch).
- `V41`, `V56` on `increment-001.md` / `increment-002.md` — their evidence rows cite bare file names, not repo-relative paths under the evidence home; the files exist under `evidence/inc-1/`, `evidence/inc-2/`. Sealed packets, not re-anchored.
- `V30` — bundle subset, as at P0. `V15`, `V16`, `V17` — `not-run` from a bundle.
- `V59` (diff limb, close gate) — the first run with `Gated tree` filled BLOCKed 369 times: 333 untracked files under `prototypes/b94_polish/`, `prototypes/keybar/`, `prototypes/external-step-block/` (never staged, by the operator's rule) → excluded locally in `.git/info/exclude` per step 5's remedy, as at the batch-95 close; 36 committed files no packet row named on its own (29 snapshot SVGs behind a `*.svg` glob row, `tests/test_tui_patch_variant.py` in a combined cell, two Inc-5 supersession test files, Inc-9's `s19_app/tui/screens.py` and its test with no §2 table, two `.fast-dev-flow/archive/` wording fixes) → one row each added to the packets of Inc-4, Inc-5, Inc-7 and Inc-9 (§2), each marked as a close-time row. The rule's own hint (re-stamp `base_ref` to `432ecf0`) was not taken: these files are this batch's own commits, pushed to `main`, not an upstream range. The added rows document changes already reviewed in their increments; no code changed.
- `V47`–`V51`, `V54` — cleared by filling `04-validation.md` and `05-close.md`. `V57` — the `Gated tree` row names `432ecf0` with the close files dirty, the declared norm at a close gate; after the operator's close commit it reads `record predates this tree`.

**Pre-rollover run: exit 1, 298 block** — `V59` 292 (the closed batch-94's `base_ref` diff charged batch-96 commits and the untracked prototype folders to it; cleared by re-stamping `base_ref` at the rollover), `V10` 2 + `V14` 3 (batch-95 contract, repaired — Key decisions), `V20` 1 (stale `_derived/` atlas, regenerated).

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| `devflow-validate.py --brief` (P0) | 2026-10-19 | exit 0 — 0 block · 462 notice · 44 n/a |
| `devflow-validate.py --brief` (close) | 2026-10-25 | exit 0 — 0 block · 494 notice · 51 n/a |
| `pytest -q -p no:cacheprovider` (full suite, the P4 gate run, orchestrator, source digest-equal to `432ecf0`) | 2026-10-23 | **11 failed, 3617 passed, 3 skipped, 3 xfailed in 2:18:54** — `evidence/inc-7/suite-full.txt`; 6 baseline, 2 test-only fixes re-run green (`post-suite-fix.txt`), 3 pre-existing flakes (`suite-nonbaseline-rerun.txt`); 4 baseline nodes now pass. Classification and ledger in `04-validation.md` |
| `pytest -q -p no:cacheprovider` (full suite, baseline at `51ee191`, code = `ad10fb5`) | 2026-10-20 | **10 failed, 3101 passed, 3 skipped, 32 xfailed in 1:09:58** — transcript `evidence/baseline-pytest-51ee191.txt`. The 10 failures pre-date the batch (found before the batch, on shipped `main`): `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact`, `test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched`, `test_tui_patch_editor_v2.py::{test_at031b_two_saves_are_distinct_no_clobber, test_at057b_regroup_wiring_and_binding_regression, test_at_batch41_escape_cancels_changeset_json_popup, test_at064c_edit_json_disabled_for_file_backed_document}`, `test_tui_patch_glyphs.py::test_at077c_stale_provenance`, `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`, `test_undo_redo_ux.py::test_ac1_checks_panel_clears_after_undo_and_redo`, `test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed`. Four sit on the Patch Editor this batch rebuilds; each increment's run compares against this list, and a failure outside it is a regression. Root cause not investigated here (batch-96 shipped on `main` without a gate). |
