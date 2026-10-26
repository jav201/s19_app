# P5 post-mortem — qa-reviewer half — 2026-10-25-batch-99

> **Mode:** `validation` (post-mortem). qa-reviewer evaluated the batch's records and ran read-only counts only: `git diff --stat/--name-only 307065f..f04572c -- s19_app tests`, greps over `03-increments/`, `02-review.md`, `04-validation.md`, `BACKLOG-CODE.md`, and `find evidence -iname 'mut*'`. It ran no test. Every run cited below was executed by the agent named on it. Co-author: `design/P5-architect.md` holds the design and process half.

## BLUF

The batch shipped with **no escaped product defect** (`04-validation.md:38`, `:278-282`). The cost was review rework: 186 findings in total; 40% were caught at P2, 53% at the P3 gate and 6% at P4. Every one of the **15 HIGH findings was caught at the P3 gate, and none was caught by a test the author wrote.** Five were regressions of shipped behaviour, and four were weak test evidence (a vacuous assertion, a hook-only race, ATs that called private methods). Three controls worked as designed: RED-first, mutation (C-40) and the independent reader. Two were checked by reading only and leaked from one station to the next: the black-box AT shape and the whole-tree guards.

## 1 · Metrics (each with its source)

| Metric | Value | Source |
|---|---|---|
| Iterations per station (from `decisions_log`) | `{P0:0, ARQ:0, P1:2, P2:2, PDR:0, P3:14 review re-rounds over 11 of 14 increments, DDR:0, P4:1 (Inc-013)}` | `state.json` decisions_log (P2 "iterate-to-refine" ×2; P1 LED .1/.2); §4b rows listed in §2 |
| `iterations_per_station` as stored | `{P1:2}`, every other station `0` | `state.json` — **undercounts P2 (2) and P3 (14)**; see §6 |
| Increments | **14** packets: 001–011, 003b, 012, 013. Not 13: 001–011 is 11, plus 003b, 012, 013 | `03-increments/` (14 files) |
| SOURCE files per increment · max · cap trips | 0,2,4,3,2,3,2,2,3,4,2,3,0,0 · **max 4** (Inc 3, 9) · **0 trips**. Budgets widened within the cap: Inc-3b (2→3), Inc-5 (2→3) | `increment-*.md` `**SOURCE files**` rows (e.g. `increment-003.md:177`, `-009.md:67`, `-005.md:59`) |
| Files touched | **88** (17 SOURCE + 71 test; 32 of the test files new), +14 279 / −827 | `git diff --stat 307065f..f04572c -- s19_app tests` |
| Stories · HLR · LLR | US **12/12** ready, 12/12 covered by **14 ATs**, one node each (C-18) · HLR 11 · LLR **40 live / 40 covered** (LLR-157.3 retired) | `04-validation.md:14-15`, `:152`, `:161-176` |
| Test ledger | `3634 − 0 + 142 = 3776` (gate run `e7732f6`), then `3776 − 4 + 1 = 3773` (main, collect-only) | `04-validation.md:18`, `:245-246` |
| Mutation checks | **80** mutation transcripts in 13 evidence folders. Every declared LLR mutant is RED. One mutant survived on its first attempt (Inc-1 LLR-152.2), then was fixed and killed | `evidence/**/mut*`; `04-validation.md:62`; `increment-001.md:124-128` |
| Flakes observed | 3 non-baseline nodes in the gate run (`tc_b97_64`, `tc024_invalid_dest`, `saveback_width_32`) plus intermittent Patch Editor v2 nodes on **both** trees. One test race appears on head only (`at030c`, ≈4/20 head, 0/20 base) | `04-validation.md:36`; `evidence/suite-triage-e7732f6.md` §Patch Editor v2; `flake-at068b-at030c-x12.txt` |
| security-reviewer findings | P2 **17** (S-1..S-17: 6 major, 11 minor) · Inc-3 **6** (S-F1 MEDIUM, S-F2..F6 LOW) · Inc-6 **5** (F1 HIGH = code-reviewer F1, F2-F3 MEDIUM, F4-F5 LOW) · 5 residual LOWs routed | `02-review.md:68-78`, `:121`, `:139`; `increment-003.md:624`; `increment-006.md:285` |

## 2 · Where defects were caught

| Station | blocker / HIGH | major / MEDIUM | minor / LOW | unclassed | Total |
|---|---|---|---|---|---|
| P2 (3 rounds) | 1 (Q-1) | 26 | 48 | — | **75** (R1 50 · R2 17 new + Q-1/Q-5/Q-6 re-raised · R3 8) |
| P3 gate (code-reviewer + security-reviewer) | **15** | ≈38 | ≈43 | 3 (Inc-3 F4–F6, severity not recorded) | **≈99** |
| P4 | 0 | 0 | 12 (G-001..G-010 + 2 stale pins) | — | **12** |

- **pct_caught_p2 = 75 / 186 = 40.3%.** Counting blocker and HIGH findings only, it is **1 / 16 = 6%**. Counting blocker, major and HIGH, it is 27 / 42 = 64%. Sources: P2 counts from `02-review.md:15`, `:29-78`, `:118-149`. P3 counts from the §4b rows: `increment-001.md:278`, `-002.md:322`, `-003.md:624`, `-003b.md:346`, `-004.md:309`, `-005.md:251`, `-006.md:285`, `-007.md:260`, `-008.md:258`, `-009.md:369`, `-010.md:347`, `-011.md:277`, `-012.md:115`, `-013.md:142`. P4 counts from `04-validation.md:252-261`, `:276-279`.
- The ≈ marks on the P3 figures are real: two packets record later rounds only as "LOW notes" (`increment-003.md:624` round 3) or as unlabelled notes (`increment-004.md:309` N4, N5). Those are not counted.
- **The PDR and DDR stations sit between these columns and are not counted in them:** PDR raised 8 PQ conditions (4 major), 7 C conditions and 11 UX-C conditions (`PDR-qa.md:10-29`, `PDR-2026-10-25-batch-99.md:17-36`). DDR raised DQ-1..DQ-7 and DDR-A1..A3 (`DDR-2026-10-25-batch-99.md:14-25`).
- **What the 15 HIGH findings were:**
  - 5 regressions of shipped behaviour: Inc-3b F1 gather re-save, Inc-6 F1 3.12 crash, Inc-8 F1 report readers, Inc-9 F1 HEX binary tail, Inc-10 F1 TAB_INTP.
  - 4 weak test-evidence defects: Inc-2 F1 vacuous Memory Map assertion, Inc-3 F2 hook-only race, Inc-8 F2 and Inc-10 F2 ATs that were not black-box.
  - 6 contract or code gaps: Inc-1 F1 token, Inc-3 F1/F3, Inc-4 F1/F2, Inc-5 F1.
- **Shift-left verdict.** P2 did its job on the text: 75 contract defects were fixed before any code existed, and P4 found no product defect. The P3 HIGH findings, however, could not have been caught at P2: they are regressions and test-quality defects. The shift-left that failed is from **PDR to the author**:
  - PQ-4 said the corpus A2L was under-specified. It came back as Inc-10 F1's "corpus gap: one raw step per entry" (`increment-010.md:285`).
  - PQ-5 said "assert content, not presence". It came back as Inc-10 F3, "PQ-5 half-checked" (`increment-010.md:287`).
  - A condition copied into a brief was not a condition met.

## 3 · Findings open vs closed

| Station | Opened | Closed in batch | Open / routed |
|---|---|---|---|
| P2 | 75 | 75 (two residues split off: S-8c, S-9 → BACKLOG-CODE) | 0 (+2 residues) |
| P3 gate | ≈99 | ≈81 | ≈18 sub-items in 12 BACKLOG-CODE entries (`BACKLOG-CODE.md:1471-1508`) |
| P4 | 12 | 7 (G-004, G-007..G-010, 2 pins) | 5: G-001 (confirmation run pending), and G-002, G-003, G-005, G-006, which the records say are routed "at the close" and are not yet in BACKLOG-CODE |

**Totals:** about 163 closed of 186 opened. BACKLOG-CODE carries **18** batch-99 entries today (`BACKLOG-CODE.md:1464-1508`). With G-002, G-003 and G-005 still to be routed, the projection is **21**.

## 4 · Test-evidence controls — what held, what leaked

**Held:**
- **RED-first.** 44 executed RED counterfactual sections across the 14 packets (grep count). P4 found every RED premise flipped (`04-validation.md:278`).
- **Mutation (C-40).** It caught a vacuous arm at author time: Inc-1's first LLR-152.2 mutant survived, and the manifest arm was fixed (`increment-001.md:124-128`). Reviewers also used mutation to confirm fixes (Inc-4 F2/F5 at `increment-004.md:309`; Inc-7, three mutants re-run).
- **Independent reader as oracle.** Every file deliverable at Layer B is read through `tests/support/independent_reader.py` (`04-validation.md:163-176`). The corpus grew when a reviewer found a class it lacked: the sparse TAB_INTP symbol (`increment-010.md:285`).
- **C-18 (one node per AT).** It closed at the DDR: 14 ATs, 14 nodes (`04-validation.md:15`).

**Leaked or cost too much:**
- **Vacuous or unable-to-fail tests reached the reviewer five times:**
  - Inc-2 F1 vacuous Memory Map assertion (HIGH)
  - Inc-3 F2 hook-only race (HIGH)
  - Inc-6 round 2 ESC arm whose byte sat past the clip (`increment-006.md:285`)
  - PQ-6, a help arm already passing at HEAD (`PDR-qa.md:27`)
  - PQ-2, a mutant RED only with a half-pair on disk (`PDR-qa.md:23`)

  Each one cost a review round.
- **Private calls in ATs survived three stations:**
  - P3 flagged them in Inc-2 F2, Inc-8 F2, Inc-10 F2 and Inc-11 F2.
  - The DDR still found private calls in AT-04, AT-09 and AT-12 (DQ-2..DQ-4, `DDR-2026-10-25-batch-99.md:22`).
  - P4 still lists residuals (G-006, `04-validation.md:257`).

  The rule is enforced only by someone reading the test.
- **C-18 was checked late.** Four ATs were split across several nodes when the DDR looked (`DDR-qa.md:12`). The fix, Increment 012, changed 9 test files **after** the one gate run. So the joined nodes were never part of a complete run (G-001, `04-validation.md:252`).
- **The reverse census misses whole-tree guards.** Two guards went stale: `test_tc653_safe_text_import_census` after Inc-6, and the `patch-comfortable-120x30` snapshot after Inc-11. Only the 2-hour full run found them (`suite-triage-e7732f6.md` §Why the increment gates missed; `04-validation.md:37`). In the other direction, three engine-freeze guards that diff against `main` stayed red by requirement in every crossing increment (`increment-010.md:288`). That is noise each packet had to explain.

## 5 · Flakes

- **Pre-batch flakes.** `at068b`, `tc344` and `verify_loud_mismatch` fail on the base tree as well (`flake-at068b-at030c-x12.txt`).
- **Batch-introduced flake.** `at030c` reads the document one pause early. This is a test race, not a product fault; it is routed (`BACKLOG-CODE.md:1499`).
- **Evidence gap.** The orchestrator's standalone re-runs of `tc_b97_64` and `tc024_invalid_dest` were never written to disk (G-004). The flake verdict rests on qa-reviewer's 6/6 re-run (`evidence/p4-qa/qa-spot-flakes-31bac78.txt`).
- **Cost.** Separating flakes from real failures took one 2-hour suite run, one bisect and two base-vs-head re-run series.

## 6 · Record discrepancies found while counting (P5 inputs, not new findings)

- **The stored iteration counter disagrees with the decisions log.** `state.json` `iterations_per_station` says P2 = 0, P3 = 0. The decisions log shows two P2 `iterate-to-refine` gates and 14 P3 re-rounds. The template's "Iterations per station" row would carry the wrong figure if copied from state.
- **The decisions log miscounts the increments.** It reads "P3 closed: 12 increments on main (001, 002, 003, 003b, 004-012)". That list holds 13 ids, and Increment 012 was gated at P4.
- **The confirmation run's result is claimed before it exists.** G-001's disposition (`04-validation.md:267`) says the confirmation run's result "is on the `Gate run` line above (CONFIRMATION)". Line 12 carries no CONFIRMATION result. At 2026-10-26T03:17, `evidence/suite-full-75f947a.txt` held 5 lines: a header and the first 3% of the run. Its state is **`not-run`: launched, no result yet**. The close owes either its tail or a correction of line 267.
- **One gate checklist row is stale.** Inc-5's row 1 says "2 SOURCE files" (`increment-005.md:303`), while its file table says 3/4 after the widened budget (`:59`).

## 7 · Proposed controls (at most 3, each tied to a real defect)

1. **QC-WT — run the whole-tree guards at every increment gate.** Declare one short list of guards that read the whole tree rather than one symbol: import census, snapshot cells, id registry, address census. Every increment runs it, whatever its reverse census says. **It would have caught** TC-653 at Inc-6 and the TC-016s snapshot at Inc-11, the batch's only two P4 test failures. Increment 013 and a bisect would not have been needed.
2. **QC-AT — check AT shape mechanically at the increment gate.** Per AT id: exactly one node (C-18), and no access to private attributes (`._name`, `app._…`) inside the AT body, except where the DDR or PDR allows one. A grep is enough. **It would have caught** DQ-1 (four split ATs, `DDR-qa.md:12`) before the gate run, so G-001's post-run test churn would not have happened. It would also have caught Inc-8 F2, Inc-10 F2, DQ-2..DQ-4 and G-006 at the increment where each was written.
3. **QC-FL — a flake verdict needs its transcript.** A triage that calls a failure a flake must cite an on-disk standalone re-run, plus a base-tree run of the same node. Without both, the failure stays `failed`. **It would have caught** G-004, where two flake verdicts rested on in-session output that was never written to disk.

## 8 · Close-record §5 values (`templates/close-template.md:88-104`)

```yaml
type: dev-flow-batch
project: s19_app
batch_id: 2026-10-25-batch-99
mode: full
verdict: pass                  # P4 PASS-WITH-NOTES (04-validation.md:11)
increments: 14
source_files_max: 4
notices_raised: 19             # PLAN.md:135-140 (P0 gate only; later gates recorded no notice ids)
rework_returns: 17             # 2 P1 amendments after P2 iterate + 14 P3 re-rounds + 1 (Inc-013 after the gate run)
triggers_fired: "A2,A3,B1,B3,B4,C6,C8,D1,E1,E2"
tests_base_to_post: "3634 -> 3773"
new_control: "proposed: QC-WT, QC-AT, QC-FL (design/P5-qa.md §7) — adoption is the gate's decision"
open_items_next: 21            # 18 in BACKLOG-CODE + G-002, G-003, G-005 at the close
```

## Evidence checklist — qa-reviewer

- [✓] Mode declared: `validation`, header.
- [✓] Every metric cites its record, and each run cited names its executor (§1, header).
- [✓] Counts executed by qa-reviewer are named as such, and no test run is claimed (header).
- [✓] Absent results are stated, not implied: the confirmation run is `not-run` (§6).
- [✓] The approximations are declared: P3 ≈ counts and their cause (§2).
- [✓] Every proposed control cites a real defect (§7: TC-653/TC-016s; DQ-1, Inc-8/10 F2; G-004).
- [✓] No real PII or credentials. No person is named.
