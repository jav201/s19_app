# 05 — Close · batch-88 · nine rule-integrity fixes + Story C (`V25`, verifiable backup)

> ## ⚠ STATUS: **CLOSED RETROACTIVELY, 2026-08-29** — the batch merged before this gate existed
>
> **The batch merged 2026-08-28 at 07:27:23 -0600** (PR #203, `0f40624`) **from station P3**, with
> `phase_status: "approved"` and `obsidian_synced: false`. Phase 4 and Phase 5 never ran. This file
> and `04-validation.md` were both written **2026-08-29**, a day after the merge, at the operator's
> explicit instruction, to give the batch a record it never got.
>
> **Neither document gated anything.** They are transcription and reconciliation of measurements
> that were genuinely taken during the batch, plus a handful of figures re-derived today from git
> and CI. Read `04-validation.md`'s disclosure block before citing any number from either file.
>
> **Status is therefore not "CLOSED COMPLETE".** It is **CLOSED WITH DECLARED GAPS** — four of
> them, enumerated in §5, and none of them recoverable now.

> **Notice convention.** `⚠` = declare and continue · `✗` = block · `✓` = satisfied **with its
> citation**.

---

## 1 · What changed

**Zero source files in `s19_app`.** Re-measured today: `git diff --name-status 4131a38 0f40624`
returns **23 files, 0 of them `.py`**. The batch's actual code changes landed in **two other
private repositories** — `~/.claude` (primary, `docs/tools/devflow-validate.py`) and its nested
`~/.claude/skills` checkout (the bundled mirror). Anyone reading only this repository's diff will
not find the work, and that is worth stating at the top rather than leaving as a puzzle.

What landed **here**, by plane:

- **The record plane** — `.dev-flow/2026-08-24-batch-88/` (12 files: `PLAN.md`,
  `01-requirements.md`, `01b-qa-validation-plan.md`, `02-review-security.md`, and 8 under
  `03-increments/`), plus the session handoff.
- **The build plane** — `pyproject.toml` gains the **`evidence` optional-dependency extra**
  (`pillow>=10`, +24 lines) and `.github/workflows/tui-ci.yml` is **rerouted through it**
  (+6/−4, net **1 file** — which is `HLR-88.6`'s threshold, and it is met).
- **The canon plane** — `docs/architecture.md` gains sections 10 (Composition-by-path) and 11
  (Interfaces-with-Frozen), +72 lines, at the ARQ station; sections 1–9 untouched. **266 tracked
  `.py` files classified into 6 non-overlapping prefixes**, which is what flipped `V8` from
  *"declares no path/** prefixes — it cannot be checked"* to checkable.
- **A new frozen artefact** — `docs/CENSUS-BASELINE-canon-mirror.md`, **1112 lines**, the canon
  baseline classified into seven classes, frozen at **Inc 0** *before* the oracle that re-measures
  it changed. That ordering is `LLR-88.8`, and it was **re-verified today**: the freeze is commit 5
  of 34 on the branch, the oracle change is commit 17.

**The nine rule-integrity fixes, in the flow repos** (rev46 → **rev47**): `V22`'s oracle
(substring → **token membership**) and its scope-naming message, landing first by operator ruling;
`V23`'s strict design-review grammar plus its harvester; `V5`'s ledger sentence and `V8`'s resolver
and root message; `V2`'s token membership and `V6`'s statement blocks; and the `_artifacts` loader
made **SCOPED rather than preferring**. **Story C** shipped `V25` — reachable remote plus days
since the newest commit on any remote-tracking ref — with the INTAKE checklist gaining its backup
row.

**Headline result, and the reason `V25` was allowed to ship in this batch at all:** its oracle is
`git ls-remote`, **external to every number this batch moves**. The scope cut of 2026-08-25 kept
Story C for exactly that reason and pushed Stories A, B and E to batch-89, because five oracle
moves were in flight and only one had been sequenced.

---

## 2 · The scope cut, and the figure that refuted its own derivation

This is the batch's most instructive episode and it should not be smoothed over.

The batch opened declaring a canon-seeding baseline of **276 of 544**, moving to **280** after the
`V22` oracle fix. Re-measured at the station-4 PDR (`PDR-2026-08-25-batch-88#D1`, `#D4`), the true
figures were **302 → 306 of 570**. The `276 → 280 / 544` pair is **superseded and preserved
verbatim** at `state.json`'s `batch_objective_superseded`, not deleted.

**Why the baseline moved and the delta did not.** The **+4 survives every re-measurement**; the
*baseline* survives none — because **batch-88 declared 26 ids of its own while the figure was being
written**. The denominator hazard bit the very number that measures it. The `+4` was verified one
id at a time (`HLR-053`, `HLR-056`, `US-064`, `US-068`), never as a total, which is why it held.

**The scope cut still stands, but its original derivation is refuted.** Of the five oracle moves,
two were still moving at the cut (`V22`'s census, `V5`'s sentences); the other three were stilled by
ordinary work rather than by design. The `_artifacts` move in particular closed from *14 block → 0*
to **0 block → 0** when P1 authored the requirements record — so its headline figure is marked
**EXPIRED, must not be re-cited**. Anyone needing these numbers must cite the re-executed table at
`01-requirements.md` §0.3, **never the objective summary**.

---

## 3 · New controls, and the one the batch found in itself

**`C7` overturned a threshold that could only be met by leaving the defect in place.** `HLR-88.6`
originally required an **empty CI diff**. The station-4 PDR found that a workflow already carrying
an ad-hoc `pip install pillow` could satisfy "empty diff" only by never being fixed. The threshold
became **"the CI diff at exactly 1 file"** — falsifiable, and **met** (re-verified today, A-6).

**The sharpest finding of the batch, from the PDR condition sweep:** batch criterion 2 thresholded
on a **hardcoded `print()` literal**. There was no synthetic-exemption list, nothing computed
membership, and the selftest's `ok` flag was never influenced by it — **the criterion could not
fail**. It was not struck; it was made **computable**, derived from `CHECKS` minus the emitted arm
labels, with its own `PASS != NOOP` arm.

**The eleventh shape of the vacuous check** (`increment-007.md`), which is this batch's contribution
to the lessons catalog and is recorded here because it generalises:

> **A typed sentence pins its WORDING and never its REFERENT.** `V25` printed a ref count drawn from
> `ls-remote origin` beside an age drawn from **every** remote on the machine, and **nine typed-
> sentence arms and six registered-rule E2E arms all passed** — because every fixture had exactly
> one remote, so the sentence's referent and the oracle's domain were the same set. `committerdate`
> → `authordate` survived for the identical reason: both date fields were written from one stamp.
>
> **The detector is not a better sentence arm. It is a fixture whose domain has two elements that
> disagree.** *A one-element domain is invisible to every assertion written over it, and each axis
> needs its own second element:* one remote became two, one branch became two, one date field became
> two that disagree.

**Controls stress-tested: 6** — the seven independent reviews (six of which returned BLOCK with
findings taken), the pre-implementation mutation catalog written by a lens never shown the arms
(Inc 2, killed five vacuous arms), the `PASS != NOOP` arm, the two-element-domain fixture, the
adversarial progress review that found the frozen ledger (F-D), and the `--map` cross-check at
`24 agree · 0 differ · 0 missing`.

**`dev-flow-lessons` catalog entry: NOT LANDED.** Inc 7 recorded that no *control* changed that
increment so none was owed there — but the eleventh vacuous shape above **is** owed to the catalog
and has not been written. Carried to §5 as gap **G5-04**.

---

## 4 · C-44 reconciliation — and a design gap in the flow itself

### The working files, reconciled

| Repo | State at the close gate | State today (re-read 2026-08-29) |
|---|---|---|
| `~/.claude` (primary flow) | uncommitted — **one of `V16`'s two blocks** | committed; `51203c7` is rev49 |
| `~/.claude/skills` (bundled mirror) | uncommitted — **the other `V16` block** | `git status -sb` reads `## main...origin/main`, **clean and level with origin** |
| `s19_app` | merged as `0f40624` | on `main`; the batch record is all present except the two files this close adds |

**`V16`'s two blocks cleared before the merge, and the timestamps prove it:** the skills-repo commit
`b7c285d` (*"dev-flow rev47: V25 ships…"*) is stamped **07:26:00 -0600**, the merge **07:27:23**.
**83 seconds.** The batch did **not** merge over substantive blockers.

### The design gap — a batch that rolls over unclosed has no path back

Discovered while syncing this batch, and recorded here because it is a defect in the flow, not in
the batch:

- `/dev-flow-sync`'s pre-requisites read **`.dev-flow/state.json`**, which is a **single-slot**
  declaration of the *active* batch. It now declares `2026-08-28-batch-89`.
- Therefore the sync **can only ever sync the active batch**. Batch-88 stopped being active when 89
  opened. **There is no supported path to sync a batch that missed its close before the rollover** —
  and the only workaround the command's own text suggests would be to roll `state.json` back, which
  would corrupt live work.
- The correct fix is a **batch-id argument** (`/dev-flow-sync <batch_id>`) that reads
  `.dev-flow/<batch_id>/` directly and treats `state.json` as the *default*, not the *only* source.

**Two further defects in the same command's copy list**, observed and **not fixed**:

| # | Defect | Consequence |
|---|---|---|
| **S-1** | Step 4 names `.dev-flow/02-review.md` and `.dev-flow/05-postmortem.md`. This project uses **`02-review-security.md`** and **`05-close.md`** | In `mode: full`, **two artifacts would be missed silently by name mismatch** — no error, no warning, just absent from the vault. Batch-86 and 87 also carry `02-review.md`, so the `05-postmortem.md` mismatch is live for every batch |
| **S-2** | `PLAN.md` and `01b-qa-validation-plan.md` are named in **no mode at all** | The P0 plan and the QA validation plan can never reach the vault by any mode. For `core` this is harmless (nothing is copied), but the copy list is wrong on its face |

Both are registered here for the operator; **neither was changed by this close.**

---

## 5 · Declared gaps — what this close cannot deliver, and why

| # | Gap | Why it cannot be closed now |
|---|---|---|
| **G5-01** | **`HLR-88.1`'s 7-of-7 per-rule enumeration.** The HLR forbids discharge by total, and `402 arms` is a total | It was Phase 4's first obligation. The validator has moved rev47 → rev48 → rev49; re-deriving arm labels today would produce **rev49's** enumeration, not batch-88's |
| **G5-02** | **Layer B never executed.** 0 of 9 `AT-B88-*` run at a gate; `AT-B88-01`, `-02`, `-06` appear in no increment at all | Operator-driven observation at surfaces that have since changed |
| **G5-03** | **`ID-B88-08`, the source pin, unmeasured** | Recorded unmeasured by Inc 7, never picked up by a later station because there was no later station |
| **G5-04** | **The `dev-flow-lessons` entry for the eleventh vacuous shape** | Not written. Owed, and still owed — the shape is transcribed in §3 so it is at least not lost |
| **G5-05** | **`decisions_log` frozen at 2026-08-27**; increments 3–7 have no ledger entries | The batch found and repaired this exact freeze once (`0e3445a`, F-D) and it re-froze. **`V18` cannot detect it** — it checks that the active batch is declared and on disk, never that the ledger matches what happened. **This is a rule-shaped gap, and the best candidate for batch-89 or later** |
| **G5-06** | **The canon both-ways check's disk direction** | Declared open by design; the record calls closing it *"a design question and not a patch"* |

**None of these was filled with a plausible value.** Each is left marked absent with its reason,
which is the only honest option available a day after the fact.

---

## 6 · Backlog reconciliation

**Lane A (`BACKLOG-CODE.md`)** — untouched by this batch; batch-87's **11 flaky node ids** remain
carried. Batch-88 added no pytest tests and produced no test failures (both CI runs clean at
2697 / 35 / 3), so it contributed nothing new to this lane.

**Lane B (process)** — batch-88 adds **6 open items**: `G5-01` through `G5-06` above, plus the two
sync-command copy-list defects `S-1` and `S-2` from §4, plus the single-slot `state.json` design gap.
**`open_items_next` = 9.**

**Honestly marked NOT DONE:** the `C-45` control landings, standing debt across batches 86, 87 and
now 88 — **still 0 landings**. Batch-88 stress-tested 6 controls and encoded **none** as a new rule
in the catalog.

---

## 7 · Batch metrics — the 12 keys of `core`

| Throughput | | Quality / shift-left | | Coverage | |
|---|---|---|---|---|---|
| stations run | **5 of 6** — P0 · ARQ · P1 · PDR · P3. **P4 and P5 skipped** | security findings | **2**, both MEDIUM, both dispositioned | HLR evidence | 8/8 (1 not in mandated form) |
| iterations | **5** (P1 ×1, PDR ×2, P3 ×2) | caught at P2 | **2** (`02-review-security.md`: *0 blockers · 0 major · 2 medium*) | LLR traced | **16/16 = 100%** |
| increments | **7** | caught at increment gate | **≥ 20** (see note) | AT executed | **0/9** |
| files touched | **23** (re-measured today) | caught at P4 | **0** — the station did not run | validator gate | `2 block · 287 notice · 16 n/a`, exit 1 on `V16` alone |
| cap trips | **0** — max 3 source files in any increment, the declared maximum, never exceeded | selftest arms | **192 → 402** (+210) | suite | `2697 passed · 35 skipped · 3 xfailed`, base **and** post |

> **`caught_p3gate` is a FLOOR, and the frontmatter value `20` should be read as one.** Only three
> increments state a review-finding total in a single sentence — Inc 1 (**6** = 1 HIGH + 5), Inc 2
> (**4** = 1 HIGH + 3), Inc 3 (**10** = 3 HIGH + 5 MEDIUM + 2 LOW). Increments **4, 5 and 7 each
> recorded a blocking review** whose findings are itemised individually but never totalled, so they
> are **not counted**. The true figure is higher; it is not inventable, so the floor is published
> instead. **`pct_caught_p2` = 2/(2+20+0) = 9.1% is consequently an UPPER bound.**

**Independent reviews: 7 across 7 increments**, per the merge commit's own subject line
(*"seven increments, seven independent reviews, seven blocks"*). Six carry a BLOCK verbatim in the
increment record (Inc 1, 2, 3, 4, 5, 7); Inc 6's is recorded as a review that **named five sites**
corrected only afterwards, rather than as a labelled verdict.

**Effort span.** `2026-08-24` → `2026-08-28` merge = **5 calendar days**. ⚠ The frontmatter's
`date_end` is **2026-08-27** and `duration_days: 4`, because the sync contract derives both from
`decisions_log`, and **the log froze on the 27th** (`G5-05`). The published duration therefore
**understates the batch by at least one day**, and the discrepancy is itself the evidence for
`G5-05`.

---

## 8 · The verdict on the flow itself (what batch-88 exposed)

Three things, in descending order of how much they should change future practice.

**1 · A ledger that no rule checks will freeze, and freezing it twice in one batch is the proof.**
The batch caught its own frozen `decisions_log` at Inc 3 via an *adversarial progress review* — the
file still declared station P1 with `iterations_per_station.P1 = 0` after two commits literally
titled *"P1 re-work"*, and held no record of the PDR, its ten conditions, four operator rulings or
two shipped increments. It was repaired. **Then it froze again**, and increments 3 through 7 are
missing from it today. `V18` verifies the ledger's *existence*, never its *correspondence*. The
missing rule is not subtle and it is the batch's clearest hand-off.

**2 · The gate is a station, and a station can be skipped without anything noticing.** Nothing in
the flow prevented a merge from P3. `phase_status: "approved"` at station P3 means *the increment*
was approved, and a reader — or an operator on the following morning — can take it for the batch.
There is no rule asserting `current_station >= P4` before a PR merges, and the cost of its absence
is exactly this document: a validation record written a day late, unable to execute a single one of
the nine acceptance tests it exists to report on, because the instrument had already moved three
revisions.

**3 · An instrument that changes under you makes retroactive verification impossible, not merely
harder.** rev47 shipped in this batch's final increment; rev49 landed **twelve minutes** before this
close was written. Every arm count, every gate line and every census figure in the record is now
un-re-runnable at the revision that produced it. **Measurements are perishable, and the gate is what
preserves them.** That is the real argument for closing on time, and batch-88 is its demonstration.
