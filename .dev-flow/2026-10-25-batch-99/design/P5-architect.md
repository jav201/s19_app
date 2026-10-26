# P5 post-mortem — architect half — s19_app — Batch 2026-10-25-batch-99

> Co-author input for `05-postmortem.md` (`stations/p5-postmortem.md` §Phase 5; section shape of `templates/postmortem-template.md`). Scope: design, process, scope drift, root causes of iterations, architecture outcomes, next-batch items. The quality/test half is `design/P5-qa.md`. §0 Gate record and the C-44 sweep belong to the close and are not filled here. Read-only: nothing else was edited.

## At a glance (architect view)

- **Outcome:** closed with carry-over. All 13 increments are on `main` (PLAN.md:77-93); DDR approved (`design/DDR-2026-10-25-batch-99.md:12`); P4 PASS-WITH-NOTES, no HIGH (`04-validation.md:11`, `:278`).
- **Top 3:** (1) independent review caught 15 HIGH defects that Kimi's own suites passed, in 10 of the 12 implementation increments, and every HIGH was fixed before merge. (2) The ARQ verdict was "sequential, one worktree" (`design/ARQ-batch-99.md:10`), but the Kimi sessions ran in parallel worktrees and nobody re-recorded the verdict. That caused the registry conflict on every merge. (3) The per-increment test choice (a reverse census of changed symbols) cannot reach whole-tree guards, so two stale guards waited about 8 h for the full suite (`evidence/suite-triage-e7732f6.md`, *Why the increment gates missed*).
- **New control proposed:** a fixed whole-tree guard set runs at every increment merge (see *Control lineage*).
- **Open items → next batch:** 8 architect items below; the biggest is D-3, the private staging seam with 4 cross-module importers.
- **Metrics (design/process):** P2 took 3 rounds; the contract took 8 ledger entries, 4 of them after P2 approved; 26 code-review rounds over 12 implementation increments; 29 Kimi sessions (`kimi/*.log`).

## What worked

- **Implementer separate from reviewers.** Kimi wrote every increment and fresh Claude reviewers judged it. Round 1 blocked or asked for changes in 10 of 12 increments (Inc 1, 2, 3a, 3b, 4, 5, 6, 8, 9, 10). Only Inc 7 and Inc 11 passed round 1 with notes (`03-increments/increment-007.md:260`, `increment-011.md:277`). Five of the HIGHs were regressions that Kimi's affected-set runs passed: Inc 3b F1 (re-save adds `_<N>`, LLR-138.4), Inc 4 F1 (overlapping save), Inc 8 F1 (report readers), Inc 9 F1 (HEX binary tail), Inc 10 F1 (TAB_INTP nearest entry instead of inverse interpolation). Each is cited at that packet's `Independent review` row.
- **Operator decisions on one page, recommended option preselected.** D1–D10 came back as the recommended option on all ten (`01-requirements-ledger.md:74`; `design/veredicto-b99.json` `general_notes` empty). Because the REFINE stories were written provisionally on those options (PLAN.md:107), the verdict became one ledger entry (LED .5) and unblocked Inc 3b, 8, 9, 10 and 11 at once (state.json decisions_log[10]). No re-review was needed.
- **Independent oracle.** The synthetic corpus and the independent reader (Inc 1, `a52e2be`) gave every byte assertion an oracle that does not share the repo's S0 defect (PLAN.md:110). Inc 10 uses only the manifest or the reader (`increment-010.md:66`).
- **Freezes and boundaries held.** No module was created and no boundary moved (`ARQ-batch-99.md:8`). The engine crossings (core.py, hexfile.py, a2l.py) stayed inside their LLRs. The DDR found no `segment_ops → tui.workspace` import (`DDR-architect.md:131`). B99-I1..I12 and I2a landed and froze (`docs/ARCHITECTURE.md:570-586`).
- **Implementation-time contract defects went through the ledger, not silent code.** LED .4 (`MSB_LAST`, Inc 1 F1 HIGH) and LED .7 (the immutability invariant, Inc 3a F2 HIGH) amended the contract with evidence (`01-requirements-ledger.md:62-67`, `:88-93`).

## What didn't / friction

- **De-facto parallel implementation, unrecorded.** The Kimi logs overlap. `inc-10.log` ended 16:58, before `inc-2` merged at 17:02 (`c62c842`), and `inc-3a.log` (17:23) and `inc-11.log` (17:41) ran at the same time. The packets of Inc 5, 6 and 7 each record the same bump `EXPECTED_SCANNED_TEST_FILES` 209 → 210 (`increment-005.md:53`, `increment-006.md:110`, `increment-007.md:63`), so all three branched from one tree. On `main` those bumps landed as 212→213, 211→212 and 210→211 (`git log -p 307065f..HEAD -- tests/test_id_registry.py`). Meanwhile trigger A4 still reads "not fired … re-evaluated when ARQ returns" (PLAN.md:36), and `DDR-architect.md:33` records "one lane, sequential", which is true of the merges but not of the work.
- **The registry integer conflicted at every merge.** Seven merges from `725d474` to `e7732f6` each rebased one constant. The packet §2 rows keep the worktree value, so they disagree with what landed. Inc 6 also needed a merge-time semantic fix: it extended the LLR-155.3 census allow-list after Inc 3b landed (state.json decisions_log[20]).
- **Kimi broke test-id ownership four times.** Three times it reused an id another LLR owns: Inc 1 `TC-B99-04` (`increment-001.md:278`), Inc 3a `TC-B99-40` → 44 (LED .8, `:95-100`), Inc 10 `TC-B99-26/27` → 42/43 (LED .6, `:81-86`). Once it invented an id: Inc 4 `test_tc_b99_40a_*` (`increment-004.md:191`). The brief rule (`kimi/BRIEF-COMMON.md:23`, `793c477`) came after the third collision.
- **Two Kimi sessions timed out.** Inc 6's first session timed out, and a resume session finished it (state.json decisions_log[20]; `kimi/inc-6-resume.log`). The Inc 5 fix session ended with rc=124, and the orchestrator ran the final sweep and wrote the section (`increment-005.md:327`). Neither left residue in the code (`increment-005.md:251`). Both did leave packet sections that the orchestrator wrote.
- **The orchestrator edited code after review without a further round.** It rewrote AT-B99-12 to use the Load dialog after round 2 (`increment-011.md:277`). It added the in-range ESC arm in Inc 6 (`increment-006.md:285`). It fixed a compose race in Inc 2 before review (`increment-002.md:322`). All three are test code, and the DDR's C-18 re-read covered the ATs (`DDR-2026-10-25-batch-99.md:20`), but no §4b row records a review of these edits.
- **Black-box AT discipline arrived late.** Inc 2 F1, Inc 8 F2, Inc 10 F2 and Inc 11 F2 all found non-black-box or vacuous ATs. The brief rule landed at `e5352f9` (19:18), after briefs 2, 3a, 10 and 11 were out, and the DDR still had to remove private calls from AT-04, 09 and 12 (DQ-2..DQ-4, `DDR-…batch-99.md:22`).

## Scope drift (planned vs actual)

| Planned | Actual | Note |
|---|---|---|
| 11 stories, 11 increments (PLAN.md:46) | 12 stories, 13 increments | US-152 added at P2 r2 (LED .2); Inc 3 split into 3a/3b (PDR C7); Inc 12 (DDR test fixes) and Inc 13 (P4 suite fixes) added |
| Inc 3b: `flow_execution_service.py` | + `project_gather_service.py`, `app.py` (`4ee51a6`) | gather took the LLR-155.3 violator (LED .7); `app.py` for the D7 status line (F2) |
| Inc 4: `change_service.py` (+ `models.py`) | `change_service.py`, `app.py` (`c58b02d`) | `models.py` not needed; `app.py` for the strip (F2) |
| Inc 5: 2 files | 3: + `flow_screens.py` (`e7732f6`) | budget widened at review round 1 so the count reaches the surface (`increment-005.md:59`) |
| Inc 6: + `segment_ops.py` | untouched (`87dcd3a`) | the view composes the emitters; `write_bin_with_sidecar` is left with no product caller (DDR D-5) |
| Inc 7: `app.py` | + `workspace.py` (`d62b0c1`) | `RESERVED_WORKAREA_HOMES`. Correction to the commission's list: `app.py` was planned for Inc 7, not added |
| Inc 9: 3 files | + `app.py` (`725d474`) | the UX-C7 status (LED .5) |
| Inc 10: `a2l.py` (PLAN.md:90) | + `app.py` (`9d7fb18`) | `kimi/BRIEF-inc-10.md` already allowed `app.py`; the PLAN column, not the brief, was stale |
| Encode exposed in the TUI | routed to the backlog (Q-1, LED .1) | US-152 makes the codec API the encode's surface |

Every as-built set is at or under the 4-file cap: the largest are 3a and 9 at 4/4 (PLAN.md:82, :89). Execution order differed from the plan's "decision-free first" (PLAN.md:76): 1, 2, 11, 10, 9, 4, 3a, 8, 7, 3b, 6, 5 (`DDR-architect.md:33`). The decision-gated increments ran early because the verdict arrived at 16:33 (`3d3a19c`).

## Metrics (design/process)

| Metric | Value |
|---|---|
| Iterations per station | P0 1 · ARQ 1 · P1 1 + 3 P2 amendments + 5 later ledger entries · P2 3 · PDR 1 · P3 26 code-review rounds (1:2, 2:2, 3a:3, 3b:2, 4:2, 5:2, 6:2, 7:1, 8:3, 9:3, 10:2, 11:2) plus 2+2 second-reviewer rounds on 3a and 6 · DDR 1 · P4 1 (+ Inc 13) |
| P2 findings | r1 1 blocker / 20 major / 29 minor; r2 1 / 6 / 13; r3 0 / 2 / 4 (`02-review.md:15`, `:121`; LED .3) |
| HIGH findings at the P3 gates | 15: Inc 1:1, 2:1, 3a:3, 3b:1, 4:2, 5:1, 6:1, 8:2, 9:1, 10:2; all closed before merge |
| Kimi sessions | 29 = 14 initial + 1 resume + 14 fix (3a, 8 and 9 took 2 fix rounds) |
| Ledger amendments after P2 approve | 4 (LED .4, .6, .7, .8): 2 from HIGH findings, 2 from id renames |
| Full-suite runs | 3 (`c62c842`, `e7732f6`, `75f947a`, the last still running), against PLAN.md:117's "once per increment cut" |

## Root causes (stations with ≥2 iterations)

- **P2 r1 → r3:** the first draft carried design choices that P2 then reversed: the `mem_map` census guard (LLR-157.3, retired in LED .2 because it "cannot equal any allow-list at HEAD") and the CRC staging home (LLR-159.3 → LLR-155.8, LED .1). Both came from ARQ (state.json decisions_log[1]). Root cause: ARQ stated a census as a requirement before anyone measured whether a decidable predicate existed.
- **Contract defects after P2 (LED .4, .7):** P2 read the threshold tokens and the race claim as text. A one-line probe would have shown that `_normalize_byte_order` rejects `LSB_FIRST` (`tui/a2l.py:280-286`), and the claim "no in-app writer replaces a name" was false at `project_gather_service.py:290-299`. Root cause: premises that rest on a code token or a writer census were reviewed, not executed.
- **P3 multi-round increments:** three repeating classes. (a) Neighbour regressions outside the reverse census: Inc 3b, 4, 8, 9 and 10 F1. (b) Non-black-box or vacuous ATs: Inc 2, 8, 10 and 11. (c) Platform contracts: Python 3.12's `Path` subclass in Inc 6 F1, and the Windows OSError and reparse points in Inc 3a F1/F3. Class (b) is a brief defect fixed mid-batch. Classes (a) and (c) are what independent review is for, and it caught them.
- **P4 → Inc 13:** `test_tc653_safe_text_import_census` (broken by Inc 6) and the `patch-comfortable-120x30` snapshot cell (broken by Inc 11; bisect in `suite-triage-e7732f6.md`) are whole-tree guards. A symbol census does not select them.

## Process / workflow findings

1. **An ARQ parallelisation verdict needs a re-check when the execution model changes.** Delegating to an external CLI in per-increment worktrees is a fork. Suggested change: when more than one implementer worktree is live, re-evaluate A4 and record the actual lanes in PLAN.
2. **Shared counters should not be hand-bumped integers in parallel lanes.** Suggested change: compute `EXPECTED_SCANNED_TEST_FILES` from a glob, or let the orchestrator bump it at merge only and keep it out of implementer packets.
3. **Test ids should be allocated in the brief.** Each brief names the exact ids it may use, plus the sub-node pattern for extra arms (the rule at `BRIEF-COMMON.md:23` says this only negatively).
4. **An orchestrator edit after the last review round needs a recorded re-read**, even for test-only code, or the packet should name the edit as unreviewed.
5. **Timeout handoff.** Both timeouts happened at fix-round tail. A brief should require the HANDOFF file to be written before the mutation sweep, not after (`BRIEF-COMMON.md:21`).

## Architecture outcomes / product findings

- **Landed contracts:** B99-I1..I12 + I2a, plus one new edge `segment_split_view → workspace`, decided at the PDR. ARQ had said no new edge was needed (`docs/ARCHITECTURE.md:487`; DDR D-6).
- **D-3 (debt):** the private-by-name `workspace._private_stage_dir` now has 4 importers (`changes/apply.py:57`, `changes/io.py:71`, `operations/crc.py:33`, `segment_split_view.py:80`). Each repeats stage → place → cleanup and stages twice (`DDR-architect.md:106`). Group placement duplicates Inc 3a's placement code (`DDR-…batch-99.md:29`).
- **D-5:** `segment_ops.write_bin_with_sidecar` was bypassed, not converted. It still writes directly, is allow-listed in TC-B99-39 under a comment that says "converted" (`DDR-architect.md:108`), and has no product caller.
- **F-2, F-3:** LLR-155.7's census no longer covers every deleter of private staging (`segment_split_view.py:972`). The B8 reuse rule exists in two copies (`segment_split_view.py:673-686`).
- **User-visible behaviour change (verified):** case_06 has 71,513 multi-byte tags that now decode big-endian, and software_a.a2l has 1,640 RAT_FUNC tags whose decode direction changed. These numbers are in `evidence/inc-10/example-impact.txt:2-3`, `increment-010.md:288` (F4(c)) and state.json decisions_log[13]. They are **absent** from `04-validation.md` and from every user-facing doc (`grep -rln "71,513\|71513"` over `*.md` hits only batch records). The packet line also carries a withdrawn complement figure, which `example-impact.txt:1` (total 220,040) could supply.
- `prototypes/` is untracked; the clean-worktree runs exclude it (`suite-triage-e7732f6.md:3`).

## Control lineage

- **New (propose, adopt next batch):** *whole-tree guard set at every merge.* A named list runs on each increment's merged tree: `test_import_census`, `test_tui_snapshot`, `test_id_registry`, and the engine-freeze guards. Origin: Inc 13 / `suite-triage-e7732f6.md`. Cost: Inc 13's re-run of these was 48 passed / 29 snapshots (`increment-013.md:142`), against about 2 h 20 for the full suite (PLAN.md:117).
- **Prior controls exercised:** the `pip -e` `__file__` probe held (`BRIEF-COMMON.md:9-10`). Mutation verdicts were declared in every packet. The C-18 one-node-per-AT rule was enforced at DDR (Inc 12). Near-miss: the PLAN risk mitigation "full suite once per increment cut" was not followed.

## Open / deferred items → next batch (architect)

| Item | Type | Reason deferred | Trigger / owner |
|---|---|---|---|
| D-3 deepen `_private_stage_dir` into a public bytes-in placement API; remove the double staging | product | needs its own design | Load+projects or a placement batch / architect |
| D-5 convert or delete `write_bin_with_sidecar`; fix the allow-list comment | product | outside Inc 6's file set | next batch touching `segment_ops` |
| F-2/F-3 bring the staging deleter into the census; keep one B8 rule | product | LOW at DDR | with D-3 |
| Record the user-visible change (71,513 / 1,640) in the release notes or P6 docs | product | not yet in user docs | P6 / docs-writer |
| G-005 tc018/at031b dedup-suffix vs B8 reuse | product decision | conflict predates the batch | operator, close packet (`04-validation.md:271`) |
| Whole-tree guard set at merge (control above) | process | new | next batch's PLAN |
| A4 re-evaluation and registry-by-glob for parallel CLI lanes | process | new | dev-flow / next batch's PLAN |
| G-001: the confirmation run `suite-full-75f947a.txt` is still running (the file ends mid-run; tracked-modified) | evidence | in progress | orchestrator before the close gate |

## Evidence checklist — architect

- [✓] Constraints stated: 4-file cap, frozen engine, English records, no operator name. Each was checked against the as-built sets (PLAN.md:77-93, cap held).
- [✓] 2+ alternatives where a real decision existed: D1–D10 on the decisions page (LED .5). The other decisions were `n/a — already made` by P2 or the PDR (Q-1 encode exception, D8 `sufijo`).
- [✓] Constraints that do not apply are marked: cost/latency `n/a — local TUI, no runtime cost` (`docs/ARCHITECTURE.md:502`).
- [✓] Recommendations tied to findings: each process item cites its origin (Inc 13, registry history, LED .4/.6/.7/.8).
- [✓] Risks listed: operational (parallel lanes, timeouts), maintainability (D-3, D-5, F-3); lock-in `n/a — Kimi CLI is swappable per PLAN.md:116`.
- [✓] Cost estimated where relevant: the guard set against the 2 h 20 suite.
- [✓] Diagram: `n/a — no new flow; one edge, recorded in docs/ARCHITECTURE.md:487`.
- [✓] What would change these findings: if the Kimi sessions were proven sequential, the parallelism finding falls, and the registry rebase becomes a stale-base artefact only.
- [✓] Two-layer chains: 14 ATs, one node each (`DDR-…batch-99.md:20`); US→AT and US→HLR→LLR→TC were re-checked at P2 r3 (`02-review.md:17`).
