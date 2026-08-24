# Handoff — batch-85, the IFC pilot: CLOSED UNFINISHED, and why that is the result

> **Written 2026-08-21, end of session. For a next session that opens with an ADVERSARIAL REVIEW.**
>
> **Re-derive every figure below.** The commands are named beside them. If a number here disagrees
> with what the command prints, **the command is right and this document is wrong** — that is not a
> formality, it is the single most repeated lesson of this batch.
>
> **Read §3 first if you read nothing else.** The pilot's deliverable was never the file.

---

## 0 · Verify the ground before trusting anything here

```bash
cd <worktree>
python ~/.claude/docs/tools/devflow-validate.py            # expect: 0 block · ~231 notice
python ~/.claude/docs/tools/devflow-validate.py --map --fetch   # V7 V15 V16 V17 green
python ~/.claude/docs/tools/devflow-validate.py --selftest      # expect exit 0, 140 arms
python tools/address_origin.py                             # A 14 · B 0 · C 14 · D 13 · U 0
python -m pytest tests/test_address_origin.py -q           # 21 passed
```

State at the cut:

| | |
|---|---|
| `s19_app` `main` | `a112eeb` — unchanged all session; **nothing merged** |
| working branch | `claude/batch-82-lane-a-scoping`, pushed, **PR #199 open** |
| also open | **PR #198** (D4 — the `AT-B83-06` contradiction) |
| flow | `2026.08.21-rev39`, `flow_hash ff40187576df8a2a` |
| all four repos | clean, `0/0` vs origin (`~/.claude`, `~/.claude/skills`, `~/kimi/agent-skills`, worktree) |
| batch-85 | `current_station: P5`, `phase_status: approved` — **CLOSED UNFINISHED, 0 implementation** |

> ⚠️ **CORRECTION, 2026-08-23 — the row above originally read `current_station: P2`, `phase_status: iterating` — BLOCKED.** That was false at the moment it was committed, not stale by drift: commit `7cc0390` wrote this document **and** moved `state.json` to `P5 / approved` in the same commit, with an explicit operator decision record (*"CLOSE UNFINISHED on the measurement, rather than iterate to acceptance"*). Verify with `git show 7cc0390 -- .dev-flow/state.json`. The two readings give an opening session **opposite** instructions — *resume the requirements iteration* versus *the batch is closed* — and this document's own title says CLOSED UNFINISHED, agreeing with `state.json` rather than with its own table. Corrected here rather than silently, per the rev36 convention: a record is what was believed, and the belief was wrong. **Note the `flow` row above is NOT corrected — `rev39` was true at this cut; the flow has since moved to `2026.08.23-rev41` / `a54f4289184bd018`.** Found by re-executing §0, which is what §0 asks every reader to do.

---

## 1 · What SHIPPED — read the artifact, not this summary

| Work | Where its detail lives |
|---|---|
| **flow rev38** — `_ifc_corpus`: `V10`–`V14` read and merge all 61 `01-requirements.md` | `~/.claude/docs/FLOW-VERSION.md` changelog rev38 · `claude-config d09d4e9` |
| **flow rev39** — `_artifacts` prefers the batch `state.json` declares; `V1`–`V9` stop reading a May document | changelog rev39 · `claude-config` (pushed) |
| **D4 resolved** — the `AT-B83-06` contradiction; the P1 stands, the SPEC re-worded | PR #198 |
| **D2 scoping** — two populations, not one; only 6 of 27 sites are product code | PR #199 · `.dev-flow/design/BATCH-82-LANE-A-SCOPING.md` |
| **The human-consolidated-IFC decision** | `.dev-flow/BACKLOG-CODE.md`, P1 at the head of the retrofit programme |
| **11 flow diagrams rescued** from an ephemeral scratchpad | `~/.claude/docs/diagrams/` (+ README), `claude-config c0f4e1f` |

**Both flow revisions were forced by this batch's own blockers, and both were found by adversarial
review rather than by any guard.**

---

## 2 · What batch-85 actually produced — and it is NOT the record

`.dev-flow/2026-08-21-batch-85/01-requirements.md` exists, contains the project's first IFC Part A +
Part B record, and the shipped validator reports over it:

```
V10  9 FLOW node(s), every one owned
V11  5 OUTPUT(s), each with an address and a declared consumer list
V12  1 NOTICE (balancing not checked — parent deliberately undeclared)
V13  3 NOTICEs / 4 undeclared reacher files
V14  15 declared consumer(s), every one resolved
```

**Two independent review rounds both returned BLOCK.** The record is NOT accepted, and it must not be
cited as a template for surface #2. It is a **measurement artifact**.

---

## 3 · THE RESULT — the per-surface cost, and it is not a number of hours

`US-85-4` asked what one surface costs, so the retrofit could be sized as *surfaces × per-surface*.
The scoping doc worried the surface count was disputed (27 / 31 / ~40). **That was the wrong worry.**

> **The simplest surface in the project — with a pre-paid design, a worked example in the template
> for this exact panel, and two independent expert reviewers — could not be contracted correctly.**
>
> Two review rounds. **5 blockers, then 3-of-5 not closed plus 7 new ones.** Two flow-repo fixes to
> shared assets. Seven defects authored by the orchestrator, **every one of the same class**.
> Zero lines of implementation.

**What the reviews found is more useful than what the record contains.** Selected, each reproduced by
execution:

- A `V13` threshold that was **green across the exact regression its own sub-requirement forbade** —
  demonstrated by a reviewer with a **one-character edit**. Corrected once, and the correction had
  the same defect: the discriminating object is the set of **`(output_id, file)` pairs**, and both
  the count-over-findings and the union-over-files projections erase the signal.
- **Four "executed verification" commands that cannot have produced their recorded results**: two
  naming tools that do not exist, and two running `pytest -k "b85"` which selects **zero** tests.
  `V4` is blind to all four — it is a *presence* check on the field, not an execution of it.
- A `TC` invariant (*"no `styles.tcss` comment contains a brace"*) that is **RED on the unmodified
  tree**: `styles.tcss:985` is a batch-46 design note quoting `{ width: 2fr }`.
- The stale-consumer census went **2 → 3 → 5 → 6 sites**, and was understated at every step
  *including by the batch whose subject is stale lists*.
- **A second split-line instance** (`styles.tcss:252-253`) that every single-line census missed, for
  the same reason as the first.

**The honest multiplier for the remaining surfaces is not "N hours × 26."** It is: *the author cannot
write a correct threshold for a surface without executing it first, and the executing is the work.*

---

## 4 · The method finding, and it is the actionable one

Every one of the seven orchestrator defects has the same shape: **a threshold was written, then
verification was attempted.** The flow already forbids this and it was violated all batch —

> **C-39:** *a threshold that CAN be computed before the implementation exists MUST be, and its
> transcript pasted.*

The union-over-files, the RED-on-arrival invariant, the two non-existent tools — **all three would
have died in five seconds under execute-first.** The next session should not re-attempt the record
by editing it. It should **write the probes, run them, and derive the thresholds from what they
print.**

⚠️ **A C-40 violation to not repeat.** Two review agents were dispatched concurrently and one was
instructed to mutate a file the other was reading. The mutation was restored and the tree is verified
clean — but the second reviewer transiently observed the mutated line, so **any measurement it took
across that window is suspect.** C-40: run mutations where no other session is reading.

---

## 5 · Open defects — the actionable list, from two reviews

**Do not trust these as written. Each is a claim to re-execute.**

| # | Defect | Fix direction |
|---|---|---|
| **1** | `HLR-85.1`'s `V13` threshold is over files; the signal lives in `(output_id, file)` pairs | Derive the pair set from an executed `V13`, not by reading |
| **2** | `tools/stale_consumer_census.py` and `tools/statement_modal_check.py` are cited as executed and **do not exist** | Write them, run them, paste output — or mark `NEW — created in Phase 3` and delete the pre-states they allegedly produced |
| **3** | `HLR-85.3` / `LLR-85.6` cite `pytest -k "b85"` → selects **0 tests** | Name a command that selects something today |
| **4** | `TC-B85-07`'s invariant is RED on arrival (`styles.tcss:985`) | Measure brace-in-comment count FIRST, then write the invariant |
| **5** | `§6.3` still says the reacher union is a **3**-element set; `§3` and `LLR-85.7` say **4** | One number, propagated |
| **6** | Site population says 3 / 4 / five / four / 5-in-4 across six locations | Pick one, propagate |
| **7** | `HLR-85.2`'s Statement (repo-wide *"no note"*) vs its threshold (*"0 edits to frozen batch records"*) — **unsatisfiable**; the batch-79 site is frozen and is a hit | Explicit ruling: scope `03-increments/` out by rule, or drop the frozen-records clause |
| **8** | A **third** design record (`C-54-ENCODING-RECORD.md:151`) asserts the stale count is 2 | Enumerate or scope out |
| **9** | The document **self-hits** its own census; no exclusion rule stated | State the rule |
| **10** | *"the named false positive"* is a **dangling reference** — never named | Name `tests/test_tui_legend.py:458` (Hex overlay constants — unrelated, DO NOT TOUCH) |
| **11** | `MAJOR 3`: `ifc_pilot_authoring` supplies 4 of `V10`'s 9 nodes, is cited nowhere else, and its `fn` entries are **process verbs, not functions** (`grep` → 0 hits) | Declare it in §5.4 with its cost, or delete it and restate the threshold at 5 |
| **12** | `slot_rows`' positional annotation is **false for row 5** (`_build_unload_all_row` has no kind/detail cell; arity 1↔2 by load state) | Annotate the exception or split the output |
| **13** | `F-10` marked ✅ FOLDED; `styles.tcss:197` / `:225-226` appear in **no** site list | Fold it or downgrade to deferred |
| **14** | Premise `P-2` declares `rev38 / 004ec303…`; the flow is `rev39 / ff40187576df8a2a`, announced by `F-7` in the same document | Refresh |
| **15** | `§6.3` dropped *"0 BLOCK attributable"* — **rev39 made it falsifiable and load-bearing** (it is what caught `LLR-85.7`). The batch now has no BLOCK criterion | Restore it; delete the modal-check substitute (a strict subset of `V4`) |

**Genuinely closed and verified by review:** `MAJOR 6` (D-C's cheap alternative + the retraction of
opinion-as-fact), `MAJOR 7` (the `LLR-85.6` module placement), `MAJOR 8` (validator-outside-repo
restored), and the dot-constraint's factual basis.

---

## 6 · Open decisions — none started

| # | Decision | Why it is open |
|---|---|---|
| **D-I** | **The HUMAN consolidated view of the IFC.** Operator ruling: the IFC is the *machine's* consolidated view and is not to be touched; a human view is owed, **DERIVED by command, never hand-maintained**. Registered P1 at the head of the retrofit programme, **owed BEFORE surface #2** — one-way door. Open: one document or a set? IFC only, or requirements + HLR/LLR + test cases? how do batch tags / past revisions / checklists render? which command derives it, in which phase? relation to `REQUIREMENTS.md` (6,074 lines, already the standing canon)? |
| **D-II** | **Is the pilot's record salvageable, or should surface #2 start clean?** 15 open defects on the simplest surface argues the *format* may be the problem, not the authoring. |
| **D-III** | **`V1`–`V9` vs `V10`–`V14` now use different artifact-selection semantics** (active-batch vs merged corpus). Deliberate and documented in rev39, but nobody has asked whether a third rule class will want a third. |
| **D-IV** | **`docs/ARCHITECTURE.md` declares no `path/**` prefixes**, so `V8` cannot check it and the whole **A-family of triggers has no oracle**. Same species as the loader defect: a control green because it has nothing to read. Untouched. |
| **D-V** | **D1 — the public-repo question.** Untouched all session, as instructed. `~47,400` lines of process artifacts in a public repo. |

---

## 7 · Suggested adversarial targets for the next session

Ranked by expected yield, based on what actually paid this session:

1. **Re-run §0's commands and diff against this document.** Two sessions running have now found that a
   hand-written figure disagrees with its command. Assume this one does too.
2. **Attack the two flow revisions I shipped**, `rev38` and `rev39`. They were written fast, under a
   blocker, by the same author who then produced 7 defects in the requirements doc. Specifically:
   does `_artifacts`' active-batch preference break any project WITHOUT `state.json`? Does
   `_ifc_corpus`'s merge do the right thing when two batches declare the **same** `COMPONENT` id?
   **Neither has an arm.**
3. **Attack the pilot's five-output decision (`D-A`).** The architect verified `slot_rows` is real —
   but `MAJOR G` says its annotation is false for row 5. Is the *output* right and the *annotation*
   wrong, or is the decomposition itself wrong?
4. **Attack this handoff.** The previous handoff that opened this session had two false claims in it
   (artifacts recorded as lost that were not). Assume the same rate.

---

## 8 · Working-file reconciliation (C-44)

| Repo | State |
|---|---|
| `s19_app` worktree | ✅ clean, `0/0`. All work committed and pushed to `claude/batch-82-lane-a-scoping` (**PR #199**) |
| `~/.claude` (claude-config) | ✅ clean, `0/0` — rev38, rev39, the 11 diagrams |
| `~/.claude/skills` (agent-skills) | ✅ clean, `0/0` — both mirrors |
| `~/kimi/agent-skills` | ✅ clean, `0/0` — pulled to match after each rev |
| `C:\Users\jjgh8\flow-diagrams-rescued-2026-08-18\` | 📋 **deliberate, 50 MB.** Staging only; the 11 editable sources are safely in `claude-config`. The PNGs + PDF are derivable. **Delete when satisfied.** |
| Scratchpad (`mutant.py`, `mutant2.py`, `split.py`) | 🗑️ ephemeral, deliberate — kill-mutation copies, their transcripts are in the rev38/rev39 changelog rows |

**Nothing is uncommitted. Nothing is unpushed. Two PRs are open and unmerged, deliberately.**

---

## 9 · One thing to carry forward

The batch built to close **misaddressed observables** — thresholds that measure a real property which
is *true in the failing case* — **produced three of them in its own acceptance criteria**, and each
was caught by a reviewer *running* something rather than reading it.

The first was corrected. **The correction had the same defect.** The corrected correction had it
again, in a different projection.

That is not carelessness and it is not fixable by care. It is what happens when a threshold is
authored before the thing it measures is executed. **C-39 already says so, in the flow this batch was
running.** The control existed, was in scope, was mandatory, and was skipped seven times by the agent
orchestrating the batch whose subject it was.

**Encode nothing new from this.** The control that would have prevented all seven is already written.
The finding is that it needs a *mechanical* trigger, not a paragraph — and that is a real candidate
for the next flow revision, with this batch as its measured origin.
