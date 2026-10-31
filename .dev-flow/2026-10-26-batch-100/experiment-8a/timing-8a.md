# Batch-100 Inc 8a (design-first experiment): where the wall-clock and tokens went

Window: 2026-10-30 20:12:29 -> 2026-10-31 00:39:55 UTC (E1 start to last line of E5 code review r2). Total = **267.4 min (4.46 h)**. Produced by `timing8a.py` (a copy of `timing.py`: new agent list, window start 20:12:29Z, Inc 8a path rule, empty background-run inventory; attribution method unchanged) and `report8a.py`, both in this folder. Numbers only; no judgement on value.

## (a) Per-agent wall, foreground, idle-on-background, output tokens, model

| step | agent (`id`) | model | start-end (UTC) | wall min | foreground min | idle-on-bg min | tool calls | asst msgs | output tok | cache-read tok |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| E1 | E1 requirements (`a9ffa101`) | opus-5-5 | 20:13-20:24 | 11.4 | 11.3 | 0.0 | 51 | 50 | 71,280 | 6,591,887 |
| E2 | E2-baseline Code-Wire (`a846184e`) | opus-5-5 | 20:13-20:20 | 7.3 | 7.3 | 0.0 | 62 | 59 | 39,617 | 8,658,044 |
| E2 | E2 prototype A (`a846d466`) | opus-5-5 | 20:26-20:35 | 9.0 | 9.0 | 0.0 | 41 | 38 | 50,368 | 5,589,690 |
| E2 | E2 prototype B (`af6b84ee`) | opus-5-5 | 20:26-20:32 | 6.0 | 6.0 | 0.0 | 27 | 21 | 34,733 | 2,651,378 |
| E2 | E2 prototype C (`a569897d`) | opus-5-5 | 20:26-20:33 | 7.6 | 7.6 | 0.0 | 35 | 35 | 42,898 | 4,210,901 |
| E3 | E3 r1 architect (`a78d3bd3`) | opus-5-5 | 20:36-20:46 | 9.9 | 9.9 | 0.0 | 42 | 41 | 52,879 | 6,370,398 |
| E3 | E3 r1 security (`ab359899`) | opus-5-5 | 20:36-20:56 | 20.4 | 20.4 | 0.0 | 54 | 53 | 45,055 | 8,838,862 |
| E3 | E3 design pass 1 (Sonnet) (`acf078aa`) | sonnet-5-5 | 20:57-21:06 | 9.1 | 9.1 | 0.0 | 36 | 35 | 74,492 | 5,449,292 |
| E3 | E3 r2 architect (`a4c8fe02`) | opus-5-5 | 21:07-21:15 | 7.9 | 7.9 | 0.0 | 31 | 29 | 48,288 | 3,999,693 |
| E3 | E3 r2 security (`a5218196`) | opus-5-5 | 21:07-21:16 | 9.0 | 9.0 | 0.0 | 32 | 29 | 54,675 | 4,167,858 |
| E3 | E3 design pass 2 (`a44af38e`) | opus-5-5 | 21:16-21:30 | 13.1 | 13.1 | 0.0 | 119 | 59 | 79,673 | 10,921,107 |
| E3 | E3 r3 architect (`a24f8d76`) | opus-5-5 | 21:30-21:36 | 5.4 | 5.4 | 0.0 | 28 | 27 | 33,413 | 3,588,395 |
| E3 | E3 r3 security (`aeb47ee6`) | opus-5-5 | 21:30-21:36 | 6.4 | 6.4 | 0.0 | 36 | 35 | 37,541 | 3,990,328 |
| E4 | E4 implementer A (`afe880d7`) | opus-5-5 | 21:38-22:05 | 26.5 | 14.5 | 12.0 | 125 | 100 | 83,756 | 21,689,454 |
| E4 | E4 implementer B (`a2bc9cde`) | opus-5-5 | 21:38-22:06 | 28.0 | 26.9 | 1.1 | 96 | 65 | 64,872 | 11,727,929 |
| E4 | E4 implementer C (`a93d5cd3`) | opus-5-5 | 21:38-21:52 | 13.6 | 13.6 | 0.0 | 43 | 29 | 32,940 | 3,359,709 |
| E4 | E4 tester (`a98d7f72`) | opus-5-5 | 21:38-22:19 | 41.3 | 41.3 | 0.0 | 106 | 95 | 138,592 | 23,179,700 |
| E4 | E4 integration (`a8b27a8f`) | opus-5-5 | 22:20-23:04 | 43.6 | 19.6 | 24.0 | 141 | 120 | 72,384 | 18,907,921 |
| E5 | E5 mutants (`aa876710`) | opus-5-5 | 23:05-23:17 | 11.5 | 4.2 | 7.3 | 17 | 19 | 24,485 | 1,688,324 |
| E5 | E5 code review (`a81a2be2`) | opus-5-5 | 23:05-23:24 | 18.6 | 18.6 | 0.0 | 68 | 65 | 65,356 | 11,912,105 |
| E5 | E5 security review (`a1533984`) | opus-5-5 | 23:05-23:35 | 30.3 | 26.2 | 4.0 | 67 | 65 | 66,180 | 12,338,696 |
| E5 | E5 corrective pass 1 (`a1247aca`) | opus-5-5 | 23:36-00:29 | 53.5 | 32.6 | 20.9 | 112 | 102 | 117,463 | 21,100,569 |
| E5 | E5 code review r2 (`a952ee4f`) | opus-5-5 | 00:30-00:39 | 9.4 | 9.4 | 0.0 | 46 | 41 | 35,754 | 4,748,596 |

Per-step agent sums (agent-minutes, NOT deduplicated; parallel agents add up):

| step | agents | wall min | foreground min | idle-on-bg min | output tok |
|---|---:|---:|---:|---:|---:|
| E1 | 1 | 11.4 | 11.3 | 0.0 | 71,280 |
| E2 | 4 | 30.0 | 30.0 | 0.0 | 167,616 |
| E3 | 8 | 81.1 | 81.1 | 0.0 | 426,016 |
| E4 | 5 | 153.0 | 115.9 | 37.1 | 392,544 |
| E5 | 5 | 123.3 | 91.1 | 32.2 | 309,238 |
| **all** | 23 | 398.7 | 329.4 | 69.4 | **1,366,694** |

Output tokens by model: Sonnet 5.5 74,492 (E3 design pass 1 only), Opus 5.5 1,292,202 (all other agents). The main orchestrator (Opus 5.5) wrote a further 94,324 output tokens over 84 messages inside the window; it is not in the totals above (the Inc 7 baseline did not count the orchestrator either).

## (b) Wall time per step (overlaps counted once)

Step span = first start to last end of that step's agents, so orchestrator rulings between E3 rounds sit inside the E3 span. The gap before a step is orchestrator-only time (decisions, rulings, briefs) between the previous step's last agent line and this step's first. E2-baseline (Code-Wire graph, 7.3 min) ran inside E1's span in parallel and adds no time.

| step | agents | span start-end (UTC) | span min | any-agent-running min | orchestrator-only inside span min | orchestrator-only gap before step min |
|---|---:|---|---:|---:|---:|---:|
| E1 (+E2-baseline) | 2 | 20:13:00-20:24:21 | 11.4 | 11.4 | 0.0 | 0.5 |
| E2 | 3 | 20:26:16-20:35:17 | 9.0 | 9.0 | 0.0 | 1.9 |
| E3 | 8 | 20:36:16-21:36:55 | 60.7 | 57.9 | 2.7 | 1.0 |
| E4 | 5 | 21:38:33-23:04:08 | 85.6 | 84.9 | 0.7 | 1.6 |
| E5 | 5 | 23:05:30-00:39:55 | 94.4 | 93.2 | 1.2 | 1.4 |
| **total** | | | | | | steps + gaps = 267.4 = window 267.4 |

E3 internals (min, wall): reviewer round 1 20.4 (parallel pair) + design pass 1 (Sonnet) 9.1 + round 2 9.0 + design pass 2 (Opus) 13.1 + round 3 6.4 = 57.9 of agent time; the rest of the E3 span (2.7 of 60.7 min) is orchestrator rulings between them.

Stage split: design stage (window start to end of E3, 21:36:55) = 84.4 min (31.6%); code stage (E4 + E5 + the gap before E4) = 183.0 min (68.4%).

## (c) Bucket table (same 13 buckets and sweep as the Inc 7 baseline)

Whole-window sweep (as Inc 7 table (b)): each foreground activity, agents and orchestrator, counts once, equal split under overlap. 'Wait' = agents idle on background compute. No run inventory was built for 8a, so waits are labelled only by the keyword in the poll command (bucket 5 = poll commands naming GREEN, the rest 'not identified').

| # | bucket | foreground min | % of total | wait on bg min | % of total | combined min | combined % | Inc 7 combined % |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | Reading context | 6.1 | 2.3% | 0.0 | 0.0% | 6.1 | 2.3% | 0.9% |
| 2 | Source code edits | 1.1 | 0.4% | 0.0 | 0.0% | 1.1 | 0.4% | 0.4% |
| 3 | Tests/fixtures edits | 13.5 | 5.0% | 0.0 | 0.0% | 13.5 | 5.0% | 1.6% |
| 4 | RED runs on base/pre-fix tree | 1.4 | 0.5% | 0.0 | 0.0% | 1.4 | 0.5% | 2.2% |
| 5 | GREEN / targeted pytest | 12.4 | 4.6% | 30.0 | 11.2% | 42.4 | 15.9% | 17.1% |
| 6 | Mutation runs | 2.1 | 0.8% | 0.0 | 0.0% | 2.1 | 0.8% | 2.4% |
| 7 | Reverse census runs | 2.2 | 0.8% | 0.0 | 0.0% | 2.2 | 0.8% | 49.3% |
| 8 | Guards / snapshot runs | 4.8 | 1.8% | 0.0 | 0.0% | 4.8 | 1.8% | 1.1% |
| 9 | Reviewer probes | 21.6 | 8.1% | 0.0 | 0.0% | 21.6 | 8.1% | 2.8% |
| 10 | Packet/HANDOFF/review-record/evidence tool/hash | 2.3 | 0.9% | 0.0 | 0.0% | 2.3 | 0.9% | 0.2% |
| 11 | Orchestrator (brief/rulings/coordination) | 15.8 | 5.9% | 0.0 | 0.0% | 15.8 | 5.9% | 1.0% |
| 12 | Other tool work | 2.4 | 0.9% | 0.0 | 0.0% | 2.4 | 0.9% | 0.3% |
| 13 | Model reasoning/writing | 132.9 | 49.7% | 0.0 | 0.0% | 132.9 | 49.7% | 20.3% |
| - | bg wait, job not identified | 0.0 | 0.0% | 18.8 | 7.0% | 18.8 | 7.0% | 0.4% |
| - | nobody running | 0.0 | 0.0% | 0.0 | 0.0% | 0.0 | 0.0% | 0.0% |
| | **total** | **218.6** | | **48.8** | | **267.4** | | |

Row 13 (model reasoning/writing) split by the bucket of the tool call that followed each turn (whole window):

| bucket of next tool call | model min |
|---|---:|
| Reading context | 50.3 |
| Source code edits | 11.5 |
| Tests/fixtures edits | 5.5 |
| RED runs on base/pre-fix tree | 2.9 |
| GREEN / targeted pytest | 2.8 |
| Mutation runs | 5.7 |
| Reverse census runs | 1.1 |
| Guards / snapshot runs | 0.4 |
| Reviewer probes | 7.4 |
| Packet/HANDOFF/review-record/evidence tool/hash | 36.7 |
| Other tool work | 8.3 |
| turn ended without a tool call (text, hand-back) | 0.6 |

Agent-foreground only (orchestrator and waits excluded), as Inc 7 table (c): **207.4 min = 77.5% of the window**. The other 60.1 min = agents idle on bg compute 49.0 + no agent running 10.5.

| # | bucket | min | % of fg | min with model time folded in | % of fg (folded) |
|---|---|---:|---:|---:|---:|
| 1 | Reading context | 6.4 | 3.1% | 58.4 | 28.2% |
| 2 | Source code edits | 1.1 | 0.6% | 13.0 | 6.3% |
| 3 | Tests/fixtures edits | 13.7 | 6.6% | 19.3 | 9.3% |
| 4 | RED runs on base/pre-fix tree | 1.4 | 0.7% | 4.3 | 2.1% |
| 5 | GREEN / targeted pytest | 12.7 | 6.1% | 15.6 | 7.5% |
| 6 | Mutation runs | 2.1 | 1.0% | 8.3 | 4.0% |
| 7 | Reverse census runs | 2.2 | 1.0% | 3.3 | 1.6% |
| 8 | Guards / snapshot runs | 4.8 | 2.3% | 5.2 | 2.5% |
| 9 | Reviewer probes | 21.8 | 10.5% | 29.2 | 14.1% |
| 10 | Packet/HANDOFF/review-record/evidence tool/hash | 2.3 | 1.1% | 39.2 | 18.9% |
| 11 | Orchestrator (brief/rulings/coordination) | 0.0 | 0.0% | 0.0 | 0.0% |
| 12 | Other tool work | 2.5 | 1.2% | 11.0 | 5.3% |
| 13 | Model reasoning/writing | 136.4 | 65.8% | 0.6 (no following tool) | 0.3% |

Bucket 10 note: design-stage agents (E1-E3) write their whole product as .md files under `.dev-flow/`, which the classifier charges to bucket 10 (packet/record/evidence); in Inc 7 that bucket was only handoff paperwork. Folded model time before those writes is 36.7 min of the whole-window sweep.

## (d) Side by side: Inc 7 vs Inc 8a

| metric | Inc 7 | Inc 8a |
|---|---:|---:|
| total wall (window) min | 596.7 (687 with the 90-min census tail the baseline excluded) | 267.4 |
| foreground agent time, deduplicated, min | 218.8 | 207.4 |
| idle-on-background (agents waiting on bg compute) min | 373.0 whole-window sweep (377.9 agent-only window minus fg) | 49.0 (+ 10.5 min with no agent running) |
| census time (bucket 7, combined) min | 294.5 (49.3%) | 2.2 (0.8%) |
| model reasoning/writing, whole-window sweep, min | 121.1 (20.3%) | 132.9 (49.7%) |
| model reasoning/writing, agent-only sweep, min | 121.9 | 136.4 |
| orchestrator own time (bucket 11) min | 5.9 | 15.8 |
| review agents launched / wall-min sum | 4 / 83.5 (all on code) | 9 / 117.2 (6 on design, E3 r1-r3 pairs; 3 on code, E5) |
| review rounds on design / on code | 0 / 2 | 3 / 2 (E5 round 1 = code + security; round 2 = code only) |
| corrective passes on code: count / agent wall min / agent fg min | 2 (pass 2 partial) / 290.1 / 77.6 | 1 / 53.5 / 32.6 |
| design correction passes (document edits, no code): count / wall min | 0 | 2 / 22.2 (pass 1 Sonnet 9.1, pass 2 Opus 13.1) |
| full-census launches | 6 (3 complete, 2 abandoned, 1 running) | 0 (operator ruling: new/modified requirement tests only; E4-tester-notes, E5-cp1-notes) |
| mutation | 8 set-runs inside implementers/correctives | 1 mutants agent (78 mutants, 11.5 min) + 22 runs in cp1 + 7 gap mutants in integration (steps.log) |
| agents launched | 8 | 23 |
| total subagent output tokens | 889,448 | 1,366,694 |
| total subagent cache-read tokens | 201,301,236 | 205,680,836 |
| models | Opus 5.5 only | Sonnet 5.5 for 1 agent (74,492 output tok); Opus 5.5 for 22 agents |

## (e) Normalisation

| quantity | Inc 7 | Inc 8a | source |
|---|---:|---:|---|
| LLRs in scope | 10 (HLR-169: LLR-169.1-169.9, plus LLR-168.4) | 11 (full or partial; HLR-170 is 1 more HLR, 2 ATs, 11 TCs) | E1-scope.md |
| source lines changed in `s19_app` (insertions + deletions) | 2,558 (+2,247 / -311; 4 files) | 1,851 (+1,719 / -132; 4 files) | `git diff --stat` as instructed (8a: working tree vs dc3b314, uncommitted) |
| net source lines | +1,936 | +1,587 | same |
| test lines changed | +3,089 / -44 (14 files) | +1,264 / -20 (8 tracked files) + new untracked `tests/test_b100_document.py`, 1,911 lines | `git diff --stat -- tests`; `wc -l` |
| new test functions (`def test_` lines added) | 73 | 100 (31 in tracked files + 69 in the new file) | grep of the diff / new file; parametrised ids not expanded (8a RED run: 164 nodes, 160 failed on base) |
| MAJOR/HIGH findings, total | 8 | 14 | baseline; 8a below |
| ... caught at design stage (E2/E3) | 0 | 13 (architect r1 5 MAJOR + security r1 4 MAJOR + architect r2 2 MAJOR + security r2 2 MAJOR; 0 HIGH; round 3: 0) | E3-architect.md, E3-security.md |
| ... caught at code stage (E5) | 8 | 1 (code review F1 MAJOR, tagged design-gap; security 0 MAJOR/0 HIGH; round 2: 0) | review-increment-008a.md, security-increment-008a.md |
| total findings incl. MINOR/LOW, as recorded | n/a | design stage: arch r1 5/6/3 + sec r1 0H/4/5/3 + arch r2 2/3/4 + sec r2 2/2/4 + r3 3 MINOR 2 LOW + 1 MINOR 2 LOW; code stage: code review 1 MAJOR/4 MINOR/4 LOW, security 5 LOW | steps.log |

Minutes per unit (wall = whole window; fg = deduplicated agent-foreground):

| ratio | Inc 7 | Inc 8a |
|---|---:|---:|
| wall min per LLR | 59.7 (68.7 with the 90-min tail) | 24.3 |
| agent-foreground min per LLR | 21.9 | 18.9 |
| wall min per 100 changed source lines | 23.3 | 14.4 |
| agent-foreground min per 100 changed source lines | 8.6 | 11.2 |
| wall min per new test function | 8.2 | 2.7 |
| subagent output tokens per LLR | 88,945 | 124,245 |
| subagent output tokens per 100 changed source lines | 34,771 | 73,835 |
| wall min per MAJOR/HIGH finding | 74.6 | 19.1 |

## (f) Caveats

1. **Same method, different inputs.** Attribution rules are those of `timing.py` (gap before a tool_result goes to the tool, before an assistant block to model time; poll loops are idle wait; equal split under overlap). Only the agent list, window start, the 8a path regex and the background-run inventory changed.
2. **No background-run inventory for 8a.** Inc 7 labelled waits from evidence footers and chain.log. For 8a I did not rebuild it, so wait minutes are labelled only by poll-command keywords (30.0 min tagged GREEN, 18.8 min 'not identified'). Wait totals are exact; the split between run types is not. Bucket 7 (census) holds only reads of census modules and guard-module runs; no full census was launched.
3. **Windows differ in definition.** Inc 7 window ends at corrective pass 2's last line (pass 2 still running), excluding a ~90 min census tail (687 min with it). Inc 8a window ends at code review r2's last line; the close records and the E13 capture gate that follow (steps.log 00:40Z onward) are not in the window.
4. **Inc 8a includes work Inc 7 did not do:** the design stage E1-E3 (84.4 min) and the Code-Wire baseline graph. Inc 7 included the implementer, two review rounds and two correctives; E1-E3 has no Inc 7 counterpart, so totals are not like for like. The code-stage-only figure (E4 + E5 + gap) is 183.0 min.
5. **Scope normalisers are rough.** LLR counts are 10 vs 11 but 8a LLRs are mostly partial arms. Changed-line counts come from `git diff --stat` on `s19_app` only, as instructed: 8a is a working-tree diff vs dc3b314 (uncommitted, includes E5 cp1), Inc 7 is the committed range 80052cb..052dc3a (which is after two corrective passes). Test functions are counted by `def test_` lines added; parametrisation is not expanded.
6. **Findings counts are severity labels as recorded by the reviewers.** Inc 7's 8 comes from the baseline/PLAN (I did not recount it; review-increment-007.md round 1 alone lists 3 MAJOR). The 8a design-stage 13 counts findings per round per reviewer; some architect and security findings may describe one defect (e.g. R8 appears in architect and security round 2). Round-1 findings that were carried into round 2 are not double-counted. Code-stage F1 is also tagged design-gap by its reviewer, i.e. visible at design stage in hindsight.
7. **Tokens.** Output tokens are summed over unique assistant message ids from the JSONL `usage` field and may undercount the last block of a message slightly. Inc 7's total (889,448) is the sum of its baseline table. The orchestrator's own tokens are excluded on both sides.
8. **Sonnet pass.** E3 design pass 1 ran on Sonnet 5.5 (9.1 min, 74,492 output tokens). Its output was rebuilt in pass 2 on Opus (steps.log: truncated prototype file, content lost, A3R2-5). Minutes spent on the failed Sonnet attempt are in the E3 totals.
9. **Parallel agents overlap:** per-step agent sums in (a) exceed step spans in (b); the sweep in (c) counts overlap once with equal split, which cannot tell critical-path from off-path work.
10. **No judgement on value** is made here.