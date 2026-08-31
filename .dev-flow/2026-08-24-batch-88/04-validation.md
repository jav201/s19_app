# Validation — s19_app — Batch `2026-08-24-batch-88`

> ## ⚠ READ THIS FIRST — THIS DOCUMENT DID NOT GATE THE MERGE
>
> **Written 2026-08-29. The batch merged 2026-08-28 at 07:27:23 -0600** as
> [PR #203](https://github.com/jav201/s19_app/pull/203), merge commit
> [`0f40624`](https://github.com/jav201/s19_app/commit/0f4062442a6d6b8fa8f4c3a30cf651911f41f679).
> This file is **one day younger than the merge it describes** and had no opportunity to stop it.
>
> **Why it is late.** Batch-88 merged **from station P3**. Its own state ledger at the merge commit
> reads `current_station: "P3"`, `phase_status: "approved"`, `obsidian_synced: false`
> (`git show 0f40624:.dev-flow/state.json`). Phase 4 never ran. The last increment says so in its
> own words — `03-increments/increment-007.md` §7 ends *"Phase 4 — write `04-validation.md` for
> batch-88, and close the batch"* — and the merge happened the next morning instead.
>
> **What this document therefore is.** A **post-hoc reconciliation** of evidence that already
> existed in the batch record, plus a small number of figures **re-derived today from git and from
> CI**, which are the two sources that survive the passage of time. It is **not** a gate, **not** a
> verification pass, and it must never be cited as one. Where a mandatory field has no evidence,
> it is marked **ABSENT** with the reason, not filled with something plausible.
>
> **What this document is NOT allowed to do.** Re-run the validator and report today's numbers as
> batch-88's. The validator has moved **three revisions** since this batch closed — rev47 (V25,
> this batch's last increment) → rev48 (V26) → **rev49**, which landed
> **2026-08-29 at 13:30:07 -0600**, minutes before this file was written
> (`~/.claude`, commit `51203c7`). Every selftest and gate figure below is **transcribed from the
> increment that measured it**, and each carries the increment and the revision it was taken at.

---

## Verdict

| | |
|---|---|
| **Verdict of this document** | **PASS-WITH-NOTES · RECONSTRUCTED, NOT GATED** |
| **What the verdict covers** | that the batch's recorded evidence is internally consistent, that the artefacts it produced are on `main`, and that CI was green on the merge commit |
| **What the verdict does NOT cover** | any live re-verification. **0** of the 9 declared acceptance tests were re-executed by this document. The validator that would execute them no longer exists at the revision this batch shipped |
| **Process defect, stated plainly** | the batch **merged without its close gate**. That is a real hole in the record, and the answer to the next reader's question *"how did this merge?"* is: **nobody ran the gate; it merged from P3 the following morning** |

### The one thing a reader should not mis-read

**The batch did NOT merge over substantive blockers.** The final gate in the record reads
**`2 block · 287 notice · 16 not applicable`, exit 1 on `V16` alone**
(`03-increments/increment-007.md:292`), and both blocks are `V16`'s *uncommitted changes* rows for
the two flow checkouts — `~/.claude` and the nested `~/.claude/skills` — not for anything in
`s19_app` (`increment-007.md:288`, `:481`). Those two cleared **on commit**, and the commit is
datable: `~/.claude/skills` commit `b7c285d` *"dev-flow rev47: V25 ships…"* is stamped
**2026-08-28 07:26:00 -0600**, **83 seconds before** the merge at 07:27:23. Both flow repos are
level with `origin/main` today.

An earlier report of this batch said it merged with blockers outstanding. **That report was wrong**
— it read a checklist snapshot taken while the tree was still dirty. The correct statement is the
one above: the blocks were repository-hygiene rows about uncommitted work, and the work was
committed before the merge.

---

## 1 · What could be re-derived today, and what could not

Three classes of evidence, kept apart on purpose.

### Class A — re-derived live by this document (strongest; independent of the record)

| # | Claim | How it was re-derived today | Result |
|---|---|---|---|
| A-1 | The batch merged from P3, Phase 4 never ran | `git show 0f40624:.dev-flow/state.json` | `current_station: "P3"` · `phase_status: "approved"` · `obsidian_synced: false` |
| A-2 | CI passed on the merge commit | `gh run view 33175465525` | `tui-ci` **success**, `snapshot` **success**, both on head `0f40624` |
| A-3 | Test ledger, post | `tui-ci` job `98862812405` log, final line | **`2697 passed, 35 skipped, 3 xfailed in 3300.46s (0:55:00)`** |
| A-4 | Test ledger, base | run `32805221981` on the merge-base `4131a38`, job `97673922393` | **`2697 passed, 35 skipped, 3 xfailed in 3330.98s (0:55:30)`** — **identical population** |
| A-5 | `pillow` resolves through the new `evidence` extra, and the freetype guard **executes** | same CI log, `Install dependencies` step | `python -m pip install -e ".[evidence]"` → `Successfully installed pillow-12.3.0 s19tool-0.1.0`, then the guard's own `print(PIL.__version__)` emits **`12.3.0`** on the next line |
| A-6 | **HLR-88.6's threshold** — the CI diff is *exactly one file* | `git diff --name-only 4131a38 0f40624 -- .github/` | **1** file: `.github/workflows/tui-ci.yml`. **Threshold met** |
| A-7 | **LLR-88.8's threshold** — the canon baseline is frozen *before* the oracle that re-measures it | `git log --reverse 4131a38..0f40624` | baseline freeze `7b7b721` at position **5**; oracle change `af4dc3d` at position **17**. **Order held** |
| A-8 | Files touched by the merge | `git diff --name-only 4131a38 0f40624 \| wc -l` | **23** (same counting method that produced batch-87's `files_touched: 17`) |
| A-9 | The nine rule fixes are **not in this repository** | `git diff --name-status 4131a38 0f40624` | **0** `.py` files changed in `s19_app`. The validator lives in `~/.claude/docs/tools/devflow-validate.py`, mirrored into `~/.claude/skills/dev-flow/scripts/` — **two separate private repos** |

> **A-4 is the load-bearing one, and it deserves a sentence.** Base and post are the *same* numbers:
> **2697 / 35 / 3**. Batch-88 added **zero** pytest tests and deleted zero. That is not an oversight
> — the record declares it in advance: *"**0 pytest files added**, and saying so is the honest form"*
> (`01-requirements.md`, §4 closing note). The batch's arms are **validator selftest arms**, which
> live in another repository and are counted separately below. Two independent sources agree, which
> is why this figure is trustworthy.

> **A-9 is the reason V16 blocked, and the reason this batch reads oddly in `s19_app`'s history.**
> The nine rule-integrity fixes and Story C's `V25` landed in the flow repos; what landed *here* was
> the batch record, the CI reroute, `pyproject.toml`'s `evidence` extra, the amended module map and
> the frozen canon-mirror baseline. Anyone reading only `s19_app`'s diff will not find the work.

### Class B — transcribed from the increment that measured it (traceable, not re-executed)

Every figure carries the increment that produced it. **None was re-measured today**, and none may
be attributed to the validator as it exists now.

| Increment | Selftest arms at exit | Independent review | Source |
|---|---|---|---|
| *(P0 baseline)* | **192**, exit 0 | — | `state.json` `decisions_log[0].notes` |
| Inc 1 — V22 census oracle → token membership | **194**, exit 0 | **BLOCK**, 1 HIGH + 5; all six taken | `increment-001.md:168` |
| Inc 2 — strict design-review grammar + harvester | **244** | **BLOCK**, 1 HIGH + 3; all four taken | `increment-002.md` |
| Inc 3 — the sentence family (V5 ledger, V8 resolver) | **288** | **BLOCK** — 3 HIGH, 5 MEDIUM, 2 LOW | `increment-003.md` |
| Inc 4 — the scope family (V2 token membership, V6 blocks) | **335** | **BLOCK** (F2a / F3 / F3′ HIGH among them) | `increment-004.md` |
| Inc 5 — the `_artifacts` loader is SCOPED, not preferring | **365 → 376** | **BLOCK** | `increment-005.md` |
| Inc 6 — `evidence` extra + CI reroute | **376 → 376** (unchanged, and *expected* unchanged) | independent review named 5 sites | `increment-006.md:363` |
| Inc 7 — V25 backup rule + computed exemption set | **402**, `SELFTEST PASSED`, exit 0 | **BLOCK at HIGH** (packet reached revision 2) | `increment-007.md:18`, evidence checklist |

**Final gate, transcribed:** `2 block · 287 notice · 16 not applicable`, exit 1 on `V16` alone
(`increment-007.md:292`). **`--map`: `24 files in table order · 24 agree · 0 differ · 0 missing`**
(`increment-007.md`). `V7` green.

**Mutation testing, transcribed from Inc 7's evidence checklist:** 49 single-edit mutations,
**47 red**, 1 measured EQUIVALENT (`R5`), 1 survivor (`D4`) whose consequence is recorded as
redundantly covered, plus 4 multi-edit controls. Earlier increments carry their own arms
(Inc 4: 37 RED · 0 survivors on the named set, then 21 mutants nobody named with **10 survivors**
on the first arm set; Inc 5: 32 built, 3 no-ops, 29 scored, **29 killed**).

### Class C — ABSENT (no evidence exists; not reconstructible)

| # | What is missing | Why it is missing | Can it be recovered? |
|---|---|---|---|
| **C-1** | **`HLR-88.1`'s per-rule enumeration.** The HLR quantifies over **seven rules** — `V2`, `V5`, `V6`, `V8`, `V22`, `V23`, `V25` — and demands, *per rule and never as a total*, one arm asserting the pass sentence and one asserting it differs from the could-not-check sentence | This enumeration was **Phase 4's first obligation** by the record's own design (`increment-007.md` §6 and §7). Phase 4 never ran. `402 arms` is a **total**, and the HLR explicitly forbids discharge by total | **Not at rev47.** Recoverable only by re-deriving the arm labels from the rev47 source, which is no longer the shipped validator |
| **C-2** | **Layer B execution.** 9 acceptance tests are declared (`AT-B88-01` … `AT-B88-09`); **6** are named somewhere in the increments (`03`, `04`, `05`, `07`, `08`, `09`); **`AT-B88-01`, `AT-B88-02` and `AT-B88-06` are named in no increment at all** | Layer B is an operator-driven pass that happens at Phase 4 | No. It required a human at the shipped surfaces, at a revision that no longer exists |
| **C-3** | **`ID-B88-08`, the source pin.** Inc 7 records it as *"unmeasured in this packet"* | It pins the shipped app, which Inc 7 did not touch; it was owed to the close gate | Partly — `git diff --stat 4131a38 0f40624 -- s19_app/ tests/` is measurable today, but that would be **today's** measurement, not the pin the batch owed at its gate |
| **C-4** | **The canon both-ways check's disk direction** (`increment-007.md` §6) | Declared open by design; closing it needs a declared set of flow files, which the record itself calls *"a design question and not a patch"* | Carried forward, not recoverable here |
| **C-5** | **`decisions_log` entries for increments 3 through 7.** The ledger's last entry is stamped **2026-08-27** and its final `P3` row is the *ledger repair itself* | The ledger froze a second time. The batch had already found and repaired this exact defect once (`0e3445a`, *"repair the state ledger (F-D)"*) — and it re-froze afterwards. **`V18` cannot see it**: it checks that the active batch is declared and on disk, never that the ledger matches what happened | The commits exist, so a narrative could be reconstructed — but it would be **written now**, not recorded then, and is therefore left absent |

---

## 2 · Layer A — per-requirement reconciliation

**Method, stated so it is not mistaken for verification.** For each requirement, the increment(s)
naming it were located by exact-token search over `03-increments/increment-00[1-7].md`, and the
declared verification method was read from the traceability table at `01-requirements.md:1235`
onward. **"evidence in record"** means the increment that owed the evidence recorded it.
**It does not mean this document re-observed it.**

### High-level requirements (8)

| Req | Method | Where its evidence lives | Status | Note |
|---|---|---|---|---|
| **HLR-88.1** | inspection | Inc 7 | ⚠ **PARTIAL — the required FORM is ABSENT** | 402 arms with `SELFTEST PASSED` is recorded; the mandated **7-of-7 per-rule enumeration is not**. See **C-1**. This is the single largest hole in the batch |
| **HLR-88.2** | test | Inc 5 (via `LLR-88.5`) | ✓ evidence in record | The `14 → 0` figure is marked **EXPIRED, must not be re-cited** in the traceability table itself: the window closed when P1 authored the requirements record. The move is recorded as **0 block → 0 block** |
| **HLR-88.3** | test | Inc 1 (via `LLR-88.6`, `LLR-88.7`) | ✓ evidence in record | Live census **302 → 306 of 570**, the **+4** verified **one id at a time** (`HLR-053`, `HLR-056`, `US-064`, `US-068`), never as a total. The earlier `276 → 280 of 544` is **superseded and preserved, not deleted** — the batch declared 26 ids of its own while the figure was being written |
| **HLR-88.4** | test | Inc 2 (via `LLR-88.9`) | ✓ evidence in record | 244 arms; 12 of 12 Markdown contexts recover the citation exactly; 10 of 10 delimiters absent from both the probe table and the superseded strip set. Two blind spots, **neither found by the author** — a pre-implementation mutation catalog written by a lens never shown the arms killed five vacuous ones |
| **HLR-88.5** | test | Inc 3 / Inc 4 (via `LLR-88.10`, `LLR-88.11`) | ✓ evidence in record | ⚠ **the HLR id itself appears in NO increment.** Its evidence resolves only through its two LLRs. A traceability gap in the record's own linking — recorded, not fixed |
| **HLR-88.6** | inspection | Inc 6 | ✓ **threshold RE-VERIFIED TODAY (A-6)** | CI diff is exactly **1** file. The threshold was **overturned by PDR condition C7** from *"empty CI diff"* — the old form could be met only by leaving the defect in place |
| **HLR-88.7** | test | Inc 7 | ✓ evidence in record | `V25`: remote answered + days since the newest commit on any remote-tracking ref, plus the INTAKE backup row (8-row table → 9 rows with it, matching `LLR-88.15`) |
| **HLR-88.8** | test | Inc 7 | ✓ evidence in record | `V7` went green after the rev47 bump — *"the one movement this increment was allowed to cause"* (`increment-007.md:288`) |

### Low-level requirements (16)

All 16 are named in at least one increment. **0 orphans.** Occurrence map, re-derived today by
exact-token count over the seven increment files:

| Req | Named in | Req | Named in |
|---|---|---|---|
| `LLR-88.1` | Inc 3, 5, 7 | `LLR-88.9` | Inc 2, 5 |
| `LLR-88.2` | Inc 3, 4 | `LLR-88.10` | Inc 3 |
| `LLR-88.3` | Inc 3, 4 | `LLR-88.11` | Inc 3 |
| `LLR-88.4` | Inc 4, 5 | `LLR-88.12` | Inc 6 |
| `LLR-88.5` | Inc 3, 4, 5 | `LLR-88.13` | Inc 6, 7 |
| `LLR-88.6` | Inc 1, 5 | `LLR-88.14` | Inc 6, 7 |
| `LLR-88.7` | Inc 1, 5 | `LLR-88.15` | Inc 6, 7 |
| `LLR-88.8` | Inc 1 — **threshold re-verified today (A-7)** | `LLR-88.16` | Inc 1, 6, 7 |

**Coverage: 16 of 16 LLRs traced to an increment (100%); 8 of 8 HLRs have evidence, one of them
(`HLR-88.1`) not in the form its own statement demands.**

---

## 3 · Layer B — acceptance

**NOT EXECUTED. Not by the batch, and not by this document.**

| AT id | Named in an increment? | Status |
|---|---|---|
| `AT-B88-01` | **no** | **ABSENT** |
| `AT-B88-02` | **no** | **ABSENT** |
| `AT-B88-03` | yes | evidence in record, **not re-observed** |
| `AT-B88-04` | yes | evidence in record, **not re-observed** |
| `AT-B88-05` | yes (the map resolver's acceptance) | evidence in record, **not re-observed** |
| `AT-B88-06` | **no** | **ABSENT** |
| `AT-B88-07` | yes | evidence in record, **not re-observed** |
| `AT-B88-08` | yes | evidence in record, **not re-observed** |
| `AT-B88-09` | yes (its error arm re-measured on both surfaces) | evidence in record, **not re-observed** |

**6 of 9 traceable · 3 with no trace anywhere · 0 executed at a gate.** Layer B is an
operator-driven pass over the shipped surfaces, and the station that runs it was skipped.

---

## 4 · Test ledger

| Key | Value | Source |
|---|---|---|
| `tests_base` | **2697** passed (+ 35 skipped, 3 xfailed) | CI run `32805221981` on the merge-base `4131a38` — **re-read today** |
| `tests_deleted` | **0** | base and post populations identical |
| `tests_added` | **0** | declared in advance at `01-requirements.md` §4 (*"0 pytest files added"*); confirmed independently by the identical CI populations |
| `tests_post` | **2697** passed (+ 35 skipped, 3 xfailed) | CI run `33175465525` job `98862812405` on the merge commit `0f40624` — **re-read today** |
| Arithmetic | `2697 = 2697 − 0 + 0` ✓ | |
| Validator selftest arms | **192 → 402** across 7 increments (**+210**) | transcribed per increment, Class B table above. **Lives in `~/.claude`, not in this repo** |
| Flaky dispositions | **none** — 0 failures in either CI run | both runs green end-to-end |

**Why there is no flaky-node section this batch, unlike batch-87.** There were no failures to
disposition. Both CI runs are clean at 2697 / 35 / 3. The 11 node ids batch-87 carried to close
remain `BACKLOG-CODE.md`'s problem and are untouched here.

---

## 5 · CI on the merge commit

| Job | Conclusion | Duration | Detail |
|---|---|---|---|
| `tui-ci` | **success** | 55m 23s (13:27:30 → 14:22:53 UTC) | full test suite on push; `2697 passed, 35 skipped, 3 xfailed` |
| `snapshot` | **success** | 1m 52s | 28 baseline cells + 2 xfail-until-baseline entropy cells |

Run [33175465525](https://github.com/jav201/s19_app/actions/runs/33175465525), head
`0f4062442a6d6b8fa8f4c3a30cf651911f41f679`, created 2026-08-28T13:27:26Z.

**The `evidence` extra did what Inc 6 said it would**, and the before/after is worth recording
because it makes the change legible:

| | merge-base `4131a38` (run `32805221981`) | merge `0f40624` (run `33175465525`) |
|---|---|---|
| install | `python -m pip install pillow` — **unpinned, unconstrained, ad-hoc step** | `python -m pip install -e ".[evidence]"` — declared in `pyproject.toml` at `pillow>=10` |
| freetype | **not asserted at all** | `assert features.check('freetype2')` — **executes**, then prints |
| resolved | `pillow-12.3.0` | `pillow-12.3.0` |

**The resolved artifact is identical.** What the increment bought was **declaration and
assertion**, not a different wheel — and saying that is more useful than implying a version moved.

---

## 6 · The gate, and the honest account of the merge

**Sequence, all timestamps re-read today:**

1. `~/.claude/skills` commit `b7c285d` *"dev-flow rev47: V25 ships…"* — **2026-08-28 07:26:00 -0600**
2. `s19_app` merge `0f40624` (PR #203) — **2026-08-28 07:27:23 -0600** *(83 s later)*
3. CI queued 13:27:26Z; both jobs green by 14:22:53Z
4. **Phase 4 never ran. Phase 5 never ran. `obsidian_synced` stayed `false`.**
5. `2026-08-28-batch-89` opened, making batch-88 no longer the active batch
6. rev48, then **rev49** (`51203c7`, 2026-08-29 13:30:07 -0600), changed the validator underneath
7. **2026-08-29** — this document and `05-close.md` written

**Step 5 is what made the hole permanent**, and it deserves naming as a process defect rather than
an accident: once the rollover happened, `state.json`'s active batch pointed at 89, and every tool
in the flow that reads *"the batch"* — `/dev-flow-sync` included — could no longer see 88.
**A batch not closed before the rollover has no supported path back.** (See `05-close.md` §4.)

---

## Evidence checklist

| | Item | Evidence |
|---|---|---|
| ✓ | Verdict stated, and its limits stated with it | **PASS-WITH-NOTES · RECONSTRUCTED, NOT GATED**, with the disclosure block at the top of this file |
| ✓ | Test ledger arithmetic reconciles | `2697 = 2697 − 0 + 0`; both endpoints re-read from CI logs today (A-3, A-4), independently corroborated by the record's own *"0 pytest files added"* |
| ✓ | Every non-trivial figure carries a source | Class A re-derived today with the exact command shown; Class B carries the increment (and `file:line` where it exists) that measured it; Class C is marked ABSENT with a reason |
| ✓ | No figure attributed to the current validator | rev49 landed 2026-08-29 13:30:07 -0600; **the validator was not run by this document at all** |
| ✓ | No secrets in this document | no token, URL, credential or path outside the two repo roots; `V25` reads `git remote get-url origin` and **never prints it** |
| ✓ | No destructive commands | read-only throughout: `git show`, `git log`, `git diff --name-only`, `gh run view`. No commit, no push, no checkout, no branch change. `prototypes/` and `build/` untouched |
| ✗ | **Layer B executed** | **NOT DONE.** 0 of 9 acceptance tests executed at a gate; 3 have no trace in any increment. See **C-2** |
| ✗ | **`HLR-88.1` discharged in its mandated form** | **NOT DONE.** The 7-of-7 per-rule enumeration does not exist. See **C-1** |
| ✗ | **`ID-B88-08` source pin measured** | **NOT DONE.** Recorded unmeasured by Inc 7 and never picked up. See **C-3** |
| ✗ | **`decisions_log` complete** | **NOT DONE.** Frozen at 2026-08-27; increments 3–7 have no ledger entries. See **C-5** |
