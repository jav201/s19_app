# batch-65 — Phase 7b — MERGE-GATE RE-GATE (QA lane)

- **Batch:** `2026-07-28-batch-65` · **Branch:** `claude/batch-65-code-lane` · **HEAD:** `4cb1602`
- **PR:** [#149](https://github.com/jav201/s19_app/pull/149) · **Base:** `origin/main` @ `f28ba45`
- **Reviewer:** qa-reviewer (independent) · **Date:** 2026-07-28
- **Scope:** the fixes only — `git diff 7dfb82c 4cb1602`. Correctness, dual traceability, byte
  identity and the frozen guards are **not** re-derived; the six files under `s19_app/` and `tests/`
  carry blob SHAs identical to `98b5b7a` and the fix commit touched no code.

## VERDICT: **BLOCK**

**HIGH-2 closed cleanly. HIGH-1 and HIGH-3 are partially closed. And the fix introduced one new
HIGH.**

The blanket `batch-64` → `batch-65` replacement was **correct on all 19 pre-existing artifacts,
`BACKLOG-CODE.md` and `REQUIREMENTS.md`** — I inspected every changed line, not a sample, and every
substitution there is a self-reference. The orchestrator's rationale holds for those files, and it
now holds *verifiedly*, not just plausibly.

**It does not hold for the 20th file.** `07-merge-gate-qa.md` was written *after* the collision and
is entirely *about* the collision. The replacement ran over it too and rewrote **24 lines**, three of
which are now **false statements about the merged batch-64** — including the sentence that attributes
PRs `#144/#145/#146` to a directory that does not exist. The batch's own merge-gate record is the one
document in the set that the mechanical rule could not safely touch, and it is the one it corrupted.

| Finding | Disposition |
|---|---|
| **HIGH-1** — renumber rewrote paths, not identity | **PARTIALLY CLOSED** |
| **HIGH-2** — `G-1/G-2/G-3` claimed in Lane A, absent | **CLOSED** |
| **HIGH-3** — `F-3` undispositioned + metrics miscount | **PARTIALLY CLOSED** |
| **NEW-HIGH-A** — the fix corrupted the merge-gate record | **OPEN (introduced by `4cb1602`)** |

---

## 1. Question 2 — the risk the blanket replacement introduced

**Lines inspected: 154 changed lines across the 21 modified files (every one, individually), plus
all 34 batch-id-bearing lines of the 386-line new file.**

```bash
git diff -U0 7dfb82c 4cb1602 -- .dev-flow/2026-07-28-batch-65/ ':!*/07-merge-gate-qa.md' | grep -c "^[+-][^+-]"   # 132
git diff -U0 7dfb82c 4cb1602 -- .dev-flow/BACKLOG-CODE.md                                  | grep -c "^[+-][^+-]"   # 16
git diff -U0 7dfb82c 4cb1602 -- REQUIREMENTS.md                                            | grep -c "^[+-][^+-]"   # 6
```

### 1a. The 19 pre-existing artifacts — **CLEAN, 66/66 substitutions correct**

Every one of the 66 `-`/`+` pairs is a reference to **this** batch:

| Class | Count | Example | Verdict |
|---|---|---|---|
| H1 headings | 14 | `# batch-64 — post-mortem` → `# batch-65 — post-mortem` | correct |
| `pre-batch-64 producer/output/order` | 8 | `01-requirements.md:366` | correct — means "before this batch" |
| `REJECTED / declined for batch-64` | 4 | X-8, ARCH-B-1 (`01-requirements.md:3092,3298,3339`) | correct — this batch's own scope rulings |
| `batch-64 must not pull it in` | 3 | `01-requirements-architect.md:906` | correct |
| `batch-64 found that batch-64 is not fixing` | 3 | `02-review-security.md:220` | correct |
| `batch-64 capped addendum (first K)` (executed transcripts) | 6 | `01-requirements.md:2640-2648` | correct |
| Branch `claude/batch-64-addendum-producer-bound` | ~14 | `01b-qa-catalog.md:3` | correct as identity, **but see NEW-MED-A** |
| Remainder (prose self-reference) | 14 | `PLAN.md:40,146,158` | correct |

**Zero corrupted.** No line in these 19 files referred to the other session's batch — they were
authored before it existed on this branch, exactly as the orchestrator reasoned. I did not accept
that reasoning; I checked it line by line and it is true.

The `US-B64-1/2` / `HLR-103` / `tests/goldens/batch64/` identifier namespace survived untouched
(`grep -c batch-64 REQUIREMENTS.md` finds none of them, because they carry no hyphen). That is the
right outcome — but it was reached by accident of the search pattern, and see **HIGH-1 (ii)** below.

### 1b. `BACKLOG-CODE.md` — **CLEAN, and the other batch is provably intact**

```
                lines   batch-64 occurrences   batch-65 occurrences
origin/main      107            4                      0
7dfb82c          127           13                      1
HEAD (4cb1602)   132            5                     14
```

All **4** `origin/main` occurrences (on 3 bullet lines) are the other session's, and all 4 survive
**byte-identical** at HEAD:

| origin/main | HEAD | Result |
|---|---|---|
| `:63` `batch-64 §7.1` (2 occurrences on the line) | `:88` | **IDENTICAL** |
| `:64` `batch-64 §7.2` | `:89` | **IDENTICAL** |
| `:86` `batch-64 §7.8` | `:111` | **IDENTICAL** |

The 5th HEAD occurrence is the header's deliberate explanation at `:5` (*"Bullets below reading
'batch-64 §7.x' belong to THAT batch, not this one"*) — which is the correct guard and prevents a
later reader from "correcting" them.

> **Correction to my own Phase-7 report.** `07-merge-gate-qa.md:153` asserts *"`origin/main`'s copy
> of this file contains **zero** `batch-64` strings, so all 13 are this batch mislabelling itself."*
> **That premise is false** — it contains four. The true split at `7dfb82c` is 13 = 4 (the other
> batch's, inherited through the merge) + 9 (this batch's). The conclusion the orchestrator acted on
> was still right, and it did **not** propagate my error: it preserved all four. But a false premise
> ships in the gate record and must be corrected in the same pass.

### 1c. `REQUIREMENTS.md` — **CLEAN, 3/3 substitutions correct**

`:4873` heading, `:4876` `pre-batch-64` ×2, `:4905` `batch-64 must not be read as having pulled it
in`. All self-references. The HIGH-1 self-contradiction (`:4873` heading vs `:5002` Status line) is
resolved — both now read `batch-65`.

### 1d. `07-merge-gate-qa.md` — **CORRUPTED, 24 lines**

`grep -c "batch-64" .dev-flow/2026-07-28-batch-65/07-merge-gate-qa.md` → **0**. The replacement was
total, and this document needed the string.

```bash
git ls-tree -r --name-only HEAD .dev-flow/2026-07-27-batch-65/ | wc -l    # → 0  (never existed)
grep -c "2026-07-27-batch-65" .dev-flow/.../07-merge-gate-qa.md           # → 6
```

**The three that are now false statements about the merged batch-64:**

| Line | Ships as | Truth |
|---|---|---|
| `:131` | ``` `.dev-flow/2026-07-27-batch-65/` is occupied by the process lane's batch, merged as #144/#145/#146 ``` | That directory **does not exist**. `#144/#145/#146` landed in `.dev-flow/2026-07-27-batch-64/`. The sentence now credits this batch's number with another batch's merged PRs. |
| `:142` | *"batch-65 is already in the vault (#146)"* | `#146` (`e47b7da`) is *"docs(dev-flow): **batch-64** — mark synced to Obsidian"*. batch-65 is **not** in the vault. |
| `:150` | ``` `claude/batch-65-addendum-producer-bound` … that branch is the **backup** of pre-migration history ``` | False. `claude/batch-65-addendum-producer-bound` = `374ad90`, a live ancestor of HEAD. The backup is `claude/batch-64-addendum-producer-bound` = `98b5b7a` — verified as the *only* ref containing `9d21d9a`. |

**The seven that turned evidence into tautology** — every one is a `batch-64` search string rewritten
to `batch-65`, so the command as printed now proves nothing (this is the vacuous-check class the
batch spent two gates removing, reintroduced into the document that certifies it):

- `:54`, `:68`, `:101` — the migration-audit commands now address `98b5b7a:.dev-flow/2026-07-27-batch-65/`, a path that never existed. `:101`'s recorded result *"→ empty"* is now vacuously true.
- `:117`, `:118` — the "does anything still reference the old batch number" grep now searches for the **new** number.
- `:120` — `grep -rc "batch-65" .dev-flow/2026-07-28-batch-65/ # → 69 occurrences across 19 files` — the defect evidence is now a count of the *correct* string in its own folder.
- `:122` — `grep -c "batch-65" # → 17 of 29 H1s` — same inversion.

**The remaining fourteen** (`:16`, `:119`, `:129`, `:132`, `:135`, `:138`, `:145`, `:149`, `:152`,
`:153`, `:231`, `:245`, `:308`, `:309`) render the HIGH-1 body and MEDIUM-1/2/LOW-1 self-defeating —
e.g. `:135` *"17 of 29 H1 headings still read `batch-65`"* describes the **desired** state as the
defect; `:145`'s *"REQUIREMENTS.md contradicts itself"* now quotes two identical strings.

**Severity: HIGH.** Not because the merge-gate record gates anything executable, but because
(1) three sentences now assert something false about an **already-merged** batch, which is the exact
harm the operator named; (2) the audit commands are no longer re-runnable, and re-runnable citation
is this gate's own standard; and (3) `/dev-flow-sync` will push this document to the vault next to
batch-64's, where `:131`/`:142` become the reader's primary account of the collision.

**Remedy:** revert `07-merge-gate-qa.md` to its pre-substitution text (restore `batch-64` on all 24
lines listed above), and fix `:153`'s false premise. Nothing else in the file changes.

---

## 2. Question 1 — per-HIGH disposition, verified independently

### HIGH-1 — **PARTIALLY CLOSED**

**Closed:** all 29 H1 headings, `REQUIREMENTS.md:4873`, the `BACKLOG-CODE.md` header and its 9 self-
references, and the recorded shipping branch (`claude/batch-65-code-lane`, PR #149).
`grep -rn "batch-64" .dev-flow/2026-07-28-batch-65/` → **0 hits**.

**Not closed — four residuals:**

1. **NEW-HIGH-A above** — the same pass corrupted the merge-gate record.
2. **The requested disclosure line does not exist.** The remedy asked for *"one line stating that the
   `B64`/`batch64` **identifiers** are retained deliberately."*
   `grep -rni "batch64|identifiers are retained|deliberately retained"` over `BACKLOG-CODE.md`,
   `REQUIREMENTS.md`, `05-postmortem.md`, `PLAN.md` → **zero hits**. `tests/goldens/batch64/` and
   `US-B64-1/2` are live in passing tests with nothing explaining why they alone kept the old number.
3. **NEW-MED-A — two branch renames produced provably false SHA-on-branch citations.** Reachability,
   executed (`git merge-base --is-ancestor`):

   | SHA | on `…batch-64-addendum-producer-bound` | on `…batch-65-addendum-producer-bound` | on HEAD |
   |---|---|---|---|
   | `082ada9` | yes | yes | yes |
   | `b09ae9a` | yes | yes | yes |
   | `ba5f09a` | **yes** | **no** | no |
   | `9d21d9a` | **yes** | **no** | no |

   So `05-postmortem.md:12` (*branch `…batch-65-addendum-producer-bound`, `082ada9` → `9d21d9a`*) and
   `06-docs/traceability-matrix.md:10` (*… · HEAD `ba5f09a`*) now name a branch that **does not
   contain** the SHA they cite. Before the fix both were stale-but-resolvable; after it they are
   false. The other ~12 renames (`082ada9`, `b09ae9a`) remain true. **The fix made MEDIUM-1 and
   MEDIUM-2 worse rather than closing them.**
4. **`state.json` was not renumbered at all** (`git diff --stat 7dfb82c 4cb1602 -- .dev-flow/state.json`
   → empty). `:9` still records *"branch `claude/batch-64-addendum-producer-bound`"*. The one
   machine-readable file in the set is now the only one still on the old identity.

### HIGH-2 — **CLOSED**

Verified by content, not by grepping for what I expected. `.dev-flow/BACKLOG-CODE.md` gained four
bullets carrying the substance and the numbers:

- **G-1** (`TC-487` white-box only, with the transitive-argument caveat stated)
- **G-2** (`TC-483` asserts `208 ≤ 607` through `_addendum_text`; names `AT-198[K_plus_1]`/`TC-480` as the black-box half that *does* exist)
- **G-3** (`≈ 11.6 kB/region` outside `TC-497`'s grep list) — **and it carries the merge-gate MEDIUM-3
  verbatim**, including *"executed mutant"*. This is the strongest part of the fix: the P3-gap carry
  absorbed an unfixed MEDIUM instead of leaving it unowned.
- **F-3** (see below)

No duplication: each appears exactly once, and the postmortem row points at them rather than
restating them.

### HIGH-3 — **PARTIALLY CLOSED**

**Closed:** `F-3` is now carried in Lane A with both halves of its evidence (`increment-003.md` §4.1
pastes `4`, the shipped document has `3`) and with the reason it went missing. The postmortem's
*"Findings carried out"* row now names `F-3` and states the correction rather than silently
rewriting the number — which is the right form.

**Not closed — the two corrections the remedy explicitly named were not made:**

- `05-postmortem.md:301` **still reads** `… · Phase 4: 3 folded, 1 carried`.
- `.dev-flow/state.json:156` **still reads** *"Four documentation-side findings, three folded, one
  carried to Lane A."*

And the fix is now internally inconsistent about it: the new text on **row 302** says *"**this row**
previously read '3 folded, 1 carried'"* — but the row that reads it is **301**, and it still reads
it. A correction note that points at a statement it did not correct, one line above itself, is the
same shape of defect as the one it is correcting.

---

## 3. Question 3 — the five MEDIUMs, re-ruled

| # | Finding | Was | Now | Ruling |
|---|---|---|---|---|
| MED-1 | postmortem cites a HEAD not on the shipping branch | MEDIUM | **worse** | **ESCALATE.** `9d21d9a` is not on the branch the fix renamed it to. Stale → false. Same one-pass fix. |
| MED-2 | `04-validation.md:13` self-contradicts | MEDIUM | changed, not fixed | **STILL MEDIUM.** The number/branch mismatch is gone; the line still names `…-addendum-producer-bound` where the shipping branch is `claude/batch-65-code-lane`. |
| MED-3 | `TC-497` greps the whole file | MEDIUM | unchanged, **now disclosed** | **DOWNGRADE to carried.** See §4. Fix is still one word. |
| MED-4 | RC-1 stale, branch 1 behind `origin/main` | MEDIUM | unchanged | **STILL MEDIUM, no merge risk.** `merge-base = e47b7da`, `origin/main = f28ba45`; the missing commit touches `prototypes/*` only, zero overlap. PR is MERGEABLE/CLEAN. |
| MED-5 | `REQUIREMENTS.md:5009` *"and nowhere else"* | MEDIUM | unchanged, **more false** | **STILL MEDIUM — see the plain ruling below.** |

### Plain ruling on `REQUIREMENTS.md:5009`

**It should NOT independently block the merge. It MUST be in the corrective pass.**

The text is:

> *"…until that reconciliation lands they are recorded in this entry and in `01-requirements.md` §10,
> **and nowhere else**"*

Three things decide it, and I want them separable:

1. **It is a superseded conditional, not a live false assertion.** The clause is governed by *"until
   that reconciliation lands"*. The reconciliation has landed, so the sentence no longer asserts its
   claim — it describes a state the reader must date. That is materially different from
   `07-merge-gate-qa.md:131`, which asserts a false fact in the indicative with no escape clause.
   This distinction is why NEW-HIGH-A blocks and this does not.
2. **It fails safe.** It *under*-advertises where the residuals live. A reader who follows it finds
   more than promised, never less. The defect class this batch exists to eliminate is the **over**-
   claim — a document asserting closure it did not achieve. This is the opposite sign, and the
   post-mortem's *"the design was right and the document kept outrunning it"* names outrunning, not
   lagging.
3. **But it is stale text in the shipped requirement, inside the section `TC-497` polices, and it now
   contradicts `BACKLOG-CODE.md:25-36` — which carries not six but ten items.** The gap widened. And
   the cost of fixing it is deleting four words in an edit pass that is now mandatory anyway.

So: I will not hold a merge for a fail-safe understatement. But since NEW-HIGH-A forces a corrective
pass regardless, leaving `:5009` in it is no longer a judgement call — it is one line in a commit
that has to happen. **Fix it.** Suggested: *"…are recorded in this entry, in `01-requirements.md`
§10, and — as of this batch's Lane-A close — in `.dev-flow/BACKLOG-CODE.md`."*

---

## 4. Question 4 — is `TC-497` still non-vacuous?

**UNCHANGED. Not worse, not better. Now disclosed rather than silent.**

The fix touched `REQUIREMENTS.md` on three lines (`:4873`, `:4876`, `:4905`); none is a guarded
figure, so the grep list's inputs are unmoved. Re-measured on the edited document:

| figure | in file | in `R-TUI-098` | **outside** |
|---|---|---|---|
| `988 B/entry` | 3 | 2 | **1** |
| `×1.68` · `×1.81` · `×1.94` · `19200 → 300` · `500 → 128000` · `+N more` | — | all | **0** |

**Leak surface: exactly 1 of 7 figures** — `988 B/entry`, whose out-of-section occurrence is at
`REQUIREMENTS.md:4870`, inside the batch-63 / `R-TUI-097` entry. Identical to the pre-fix
measurement.

**Mutant re-executed against the edited document** (both in-section occurrences removed, the out-of-
section one retained; `REQUIREMENTS.md` restored from git immediately, working tree verified clean):

```
shipped  TC-497 (figure in requirements)  ->  1 passed      GREEN  <-- the weakness
scoped variant (figure in section)        ->  missing: ['988 B/entry']   RED
```

So a guarded figure can still be deleted from `R-TUI-098` with `TC-497` green. **The G-3 carry does
not mitigate the mechanism** — it mitigates the *silence*: `BACKLOG-CODE.md` now states the weakness
in the words of the executed mutant, so the next batch inherits it as a known defect rather than
rediscovering it. That is the correct disposition for a non-blocking gap, and the fix remains one
word: `if figure in section`.

Baseline, unmutated: `TC-497` → **1 passed in 0.28s**.

---

## 5. Question 5 — is the Lane-A reconciliation intact?

**YES, on all four sub-questions. This is the cleanest part of the fix.**

| Check | Method | Result |
|---|---|---|
| The other session's three P3 bullets survive unaltered | line-for-line byte compare of `HEAD:88/89/111` against `origin/main:63/64/86` | **IDENTICAL ×3** |
| Nothing else of theirs was dropped | set-difference `origin/main` → HEAD | **exactly 1 line**, the batch-63 D1 bullet this batch legitimately closed and replaced |
| The surviving `batch-64` strings are exactly theirs + the header | occurrence enumeration | **4 occurrences on their 3 bullet lines + 1 in the header's explanation.** No stray. |
| Nothing this batch owes is stated twice or lost | set-difference `7dfb82c` → HEAD, both directions | 6 lines rewritten (all self-reference), **10 added**, **0 lost**. `G-1`/`G-2`/`G-3`/`F-3` each appear exactly once. |

The header addition is the right call and does real work: without it, a later reader applying the
same mechanical rule would have "corrected" the other batch's three bullets — precisely the failure
that occurred one file over.

---

## 6. What unblocks the merge

One editing pass. No code, no tests, no goldens, no suite re-run.

1. **NEW-HIGH-A** — restore `batch-64` on the 24 corrupted lines of `07-merge-gate-qa.md`
   (`:16 :54 :68 :101 :117 :118 :119 :120 :122 :129 :131 :132 :135 :138 :142 :145 :149 :150 :152
   :153 :231 :245 :308 :309`), and correct `:153`'s false premise to *"the only four `batch-64`
   strings in `origin/main`'s copy are the other batch's §7.x bullets, so the other nine are this
   batch mislabelling itself."*
2. **HIGH-3 residue** — correct `05-postmortem.md:301` to *"Phase 4: 2 folded, 1 carried, 1
   undispositioned (corrected at the merge gate)"*, and `state.json:156` to match. Then re-point
   row 302's *"this row previously read"* at the row that actually read it.
3. **HIGH-1 residue** — add the one-line disclosure that `US-B64-1/2` and `tests/goldens/batch64/`
   retain the old number deliberately (they are baked into passing tests and the byte-identity
   golden); and renumber `state.json:9`'s recorded branch.
4. **NEW-MED-A / MED-1 / MED-2** — `05-postmortem.md:12` and `06-docs/traceability-matrix.md:10` cite
   SHAs (`9d21d9a`, `ba5f09a`) that exist only on `claude/batch-64-addendum-producer-bound`. Either
   restore that branch name in those two citations with a note that it is the pre-migration backup,
   or re-cite reachable SHAs on `claude/batch-65-code-lane`.
5. **MED-5** — `REQUIREMENTS.md:5009`, delete/replace *"and nowhere else"*.

**Recordable as carries, not blockers:** MED-3 (`TC-497` scope — already carried as G-3) and MED-4
(re-assert RC-1; the branch is 1 commit behind on `prototypes/` only).

Everything ruled at Phase 7 as green stays green — the fix commit touched no code, no test and no
golden, and the six files under `s19_app/` and `tests/` remain blob-identical to `98b5b7a`. Once
items 1–5 land this is a **MERGE**.

## 7. Evidence checklist

- [x] Acceptance criteria use Given/When/Then — inherited; this phase is a gate, not a new AT set.
- [x] Test cases have explicit Expected — every row cites a command and its exact output.
- [x] Edge cases include empty, boundary, invalid, error — mutant (deletion), reachability matrix (negative), set-difference both directions.
- [x] Regression checklist exists — §5, the Lane-A reconciliation, executed as a byte compare.
- [x] Exit criteria stated — §6.
- [x] No real PII / secrets — documentation diff only.
- [x] Test results are REAL — `TC-497` run twice (baseline GREEN, mutant GREEN); `REQUIREMENTS.md` restored, `git status --porcelain` verified empty afterwards.
- [x] Layer B — not re-derived; the fix touched no shipped surface (blob-SHA equality vs `98b5b7a`).
- [x] Bidirectional surface-reachability — not re-derived, same reason.
- [x] No unfilled template — no placeholders in this document.
