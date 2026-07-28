# Security Review — batch-64 DELTA GATE over `b02df84`

**BLUF: OK-TO-MERGE. 0 HIGH · 0 MEDIUM · 1 LOW.**
The HIGH is discharged — I verified the tree is settled rather than taking it. F4's fix closes the
vacuity and is strictly stronger than what it replaced. **The limb-span argument holds: the arms
harness ranges over the limb spans, not the discharge, so `AT-B64-01`/`-02` do NOT need re-running.**
Nothing the F4 edit or the merge resolution introduced is adverse.

**Snapshot taken `2026-07-28T01:14:49Z`**, HEAD `b02df84`. Scope: delta over the four questions asked,
not a fresh full review. Everything cleared in `07-merge-gate-security.md` that is destination-local
and hash-unchanged carries forward — `VERIFY.md` (`3c6016fc…`), the lineage memory (`50cf146e…`) and
`docs/engineering-rules.md` (`5618029c…`) are byte-identical to what I already cleared, so I did not
re-derive them.

---

## 1. Is the HIGH discharged? — **YES**

Verified directly, not accepted:

| check | result |
|---|---|
| `MERGE_HEAD` | **ABSENT** |
| `git diff --name-only --diff-filter=U` | **0** |
| merge/rebase markers in `.git` (`MERGE_*`, `AUTO_MERGE`, `REBASE*`, `CHERRY*`) | **none** |
| `git merge-base --is-ancestor origin/main HEAD` | **YES** — `082ada9` is an ancestor |
| `git status --porcelain` | **0 lines** — clean |
| commits | `a77227f` merge · `ca36f66` coherence review · `b02df84` F4 + POST re-record |
| conflict markers in tracked files (`^<<<<<<< `, `^>>>>>>> `) | **none** |

The tree is settled and quiet. My HIGH was a **state** finding, never a content finding, so a settled
tree discharges it completely — there is no residue to carry.

**On the §6 objection.** Re-derived against the diff that actually merges:
`git diff --name-only origin/main...HEAD` → **25** files, **0** under
`s19_app tests examples pyproject.toml requirements.txt .github`, and the only non-`.dev-flow/` path
is `docs/engineering-rules.md`. The `README.md` / `.gitignore` / `docs/images/*` I flagged are indeed
`main`'s commits arriving via the merge, exactly as stated.

**One reconciliation, in your favour:** you said 24 files, I measure 25. The extra one is
`.dev-flow/2026-07-27-batch-64/07-merge-gate-security.md` — **my own gate report**, which your count
predated. Accounted for, not a discrepancy.

**Note for the record, and I want it recorded as you framed it.** The cause was orchestration, not
method, and you named the risk before it happened and re-verified rather than waving it away. That is
the right handling. `BACKLOG-PROCESS.md §7.8` correctly escalates the un-encoded `sec F5` rule — and
its **third measured occurrence landing on the security gate itself, in the batch encoding C-40**, is
the strongest possible argument for encoding it. I verified §7.8 is present and cites the rule by its
drift-proof label `(PROCESS, new — sec F5)` rather than by line number: `BACKLOG-CODE.md:86` citing
the declaration at `:85`.

---

## 2. Does the F4 wording close the vacuity? — **YES, and it is strictly stronger**

Installed text, read from the live file:

> confirming the restore in the same transcript **by the file's hash returning to its pre-mutation
> value** — `git status` alone is insufficient and is outright **vacuous for an untracked file**,
> which it reports identically whether or not the mutation was reverted

Measured: discharge region **1 888 → 2 035 B = +147 B**, matching your figure exactly.
`dev-flow.md` = 68 311 B, `sha256=21a031f707794bb1…`, **CR 276 / LF 276 / CRLF 276** in byte mode —
uniformly CRLF, held. The §5b newline defect is **not** repeated; the write was byte-mode.
Line count unchanged at 277, so the edit is in-line and introduced no new heading, fence or list item.

**I applied C-40's own LIMB 1 test to the new predicate**, since a fix to an anti-vacuity control that
is itself vacuous would be the worst possible outcome:

- **Declared subject:** "the mutation was reverted."
- **Expression:** `hash(file_now) == hash(file_pre_mutation)`.
- **Is the declared subject in the expression?** Yes — the file's bytes are the hashed input, and the
  mutation's effect on those bytes is precisely what the hash is a function of.
- **Can it go RED?** Yes. A still-applied mutation changes the bytes, changes the hash, predicate
  fails. It is **not invariant under the change it gates**.
- **Is it vacuous for an untracked file?** No. Hashing is VCS-agnostic — which was the entire defect.

**Did you trade one weak predicate for another? No.** The disjunction is gone; the confirmation method
is now singular and mandatory, and `git status` is explicitly demoted to *insufficient* with the
reason stated inline. For the **tracked** case this is also strictly stronger than before — it now
requires the hash in addition, where previously `git status` alone sufficed. The only cost is that a
tracked-file restore can no longer be confirmed by the cheaper check; that is a cost, not a risk, and
I do not think it is worth softening.

**One residual, LOW, and it does not gate.** See F-L1 below.

---

## 3. Does the limb-span argument hold? — **YES. The arms do NOT need re-running.**

You were right to flag that your earlier 4 564 B / `026bb4c6…` proof is invalidated — the discharge
sits inside the pre-`(Origin:` region, so that boundary moved. I re-established it at limb granularity
independently and then answered the question you actually asked, which is the harder half.

**Region-by-region, frozen block 1 vs installed:**

| region | frozen | installed | sha256 (both) | identical |
|---|---|---|---|---|
| pre-LIMB 1 | 460 B | 460 B | `4c0c112eb3ef5561` | ✅ |
| **LIMB 1** | **1 209 B** | **1 209 B** | **`fb24cf1796b5b9c8`** | ✅ |
| **LIMB 2** | **1 007 B** | **1 007 B** | **`791424bfe23ff975`** | ✅ |
| DISCHARGE | 1 888 B | 2 035 B | `b8ec2e44…` → `5a71e6a6…` | ✗ (the F4 edit) |
| `(Origin:…)` | 1 655 B | 1 652 B | — | ✗ (the earlier F2/F6 folds, −3 B) |

Your limb figures reproduce **exactly**. I also checked the 460 B pre-limb preamble, which you did not
claim — also byte-identical.

**The load-bearing check — what the harness actually reads.** `04-measurement-frozen.md:150-154`
defines the harness as *"Limb structure parsed from block 1's bytes"*, yielding seven features. I
located each feature's needle by region:

| harness feature | lives in |
|---|---|
| `limb1=True` | LIMB 1 |
| `keying=DECLARED` | LIMB 1 |
| `pin=True` (PIN corollary) | LIMB 1 |
| `domain_ruling(A-23)=True` | LIMB 1 |
| `semantic_governs=True` | LIMB 1 |
| `limb2=True` | LIMB 2 |
| `instance(i)=True` | LIMB 2 |
| `instance(ii)=True` | LIMB 2 |

**Zero features resolve into the DISCHARGE region.** The four mutations at `:194-197` likewise all
target limb spans — *delete LIMB 2 span* → LIMB 2; *re-key LIMB 1* → LIMB 1; *delete the A-23 domain
ruling* → LIMB 1; *corrupt both LIMB markers* → LIMB 1. None mutates the discharge.

**Conclusion: the harness ranges over the limb spans, both of which are byte-identical
frozen-vs-installed. `AT-B64-01` (9/9 CI · 8/9 full) and `AT-B64-02` (1/6 CI-normative) are measured
over an unchanged region and transfer by identity. No re-run needed.**

One nuance I checked so it is not a latent surprise: `keying=DECLARED`'s needle also occurs in the
`(Origin:…)` region, which *did* change. But the Origin edits are the four F2/F6 word-level folds
(`Five`→`Three of the five`, `string join`→`byte count`, drop `for one defect`, `:206`→`:207`), none
of which touches that phrase, and the harness parses limb structure rather than narrative. The −3 B
Origin delta is fully accounted for by those four edits.

---

## 4. Anything the F4 edit or the merge resolution introduced?

**Nothing adverse.** Checked:

- **All five POST hashes match `§5d` exactly** — `5618029c…` / `3c6016fc…` / `21a031f7…` /
  `50cf146e…` / `781c82e9…`. F2 is properly closed; the record now describes the shipped state for
  all five destinations, including the two out-of-VCS files that previously had none.
- **Block 6 survived the merge with its folds intact.** Against my own §F1 step-2 anchors:
  `test_report_document_bytes.py:266` (F3 fold) present exactly once, in `BACKLOG-CODE.md`;
  `(and \`:36\`)` (F4 fold) **absent, 0 hits** across all three backlog files;
  `batch-64 §7.2`, `§7.8`, `FOUR vacuous predicates`, `FALSE COUNTERFACTUAL`,
  `worktree-mutation hygiene` each present exactly once.
- **Three anchors were not singletons; all three are benign** and I checked each rather than reporting
  a count:
  - `PROCESS, new — sec F5` ×2 in `BACKLOG-CODE.md` — `:85` is the rule **declaration**, `:86` is
    §7.8 **citing it by label**. That is the F1 fold working as designed, and it is the same
    declaration-vs-mention distinction PP-5 tripped on.
  - `batch-64 §7.1` ×3 — **my needle was a substring**: it also matches `§7.10` and `§7.11`, which are
    my own F3 and F5 carried into `BACKLOG-PROCESS.md:33-34`. The content is correct; my predicate
    over-counted. An instance of this batch's own thesis, committed by its security reviewer, in the
    delta gate. Recording it because that is the standard the batch sets.
  - `C-10 … C-39` ×2 in the router — the header refresh line and the footer declaration carrying
    `∪ {C-40, C-42}`. Both legitimate.
- **No conflict markers** in any tracked file.
- **No production surface**: 0 files under `s19_app tests examples pyproject.toml requirements.txt
  .github`. Still `.md`/`.json` only plus the one in-repo doc.
- **F5 / §7.11 verified as written** — `BACKLOG-PROCESS.md:34` records the correction as
  conclusion-survives / rationale-was-incomplete, and explicitly attributes it as *"a reviewer
  correcting its OWN prior ruling."* That is accurate and I am content with it.

**A measurement error of my own, disclosed.** One command read `dev-flow.md` via `read_text`, which
applies universal-newline translation, and reported **CR 0**. That would have been a false finding
about the line-ending state. Re-reading in byte mode gives **CR 276 / LF 276 / CRLF 276** — the file
is fine; my first read was wrong. The failure mode is exactly C-42 mechanic 4: *assert against the
emitted encoding, not the decoded convenience form*. Caught by re-measuring rather than by luck.

---

## Findings

### F-L1 — The hash predicate presupposes a baseline that the clause does not require capturing  [Severity: LOW]

- **What.** *"the file's hash returning to its pre-mutation value"* presupposes a pre-mutation hash was
  taken. The clause does not say *record the hash before mutating*.
- **Where.** `~/.claude/commands/dev-flow.md`, C-40 DISCHARGE.
- **Why it matters — and why it is LOW.** An agent that never captured a baseline **cannot** discharge
  the clause: it has nothing to compare against. That is **fail-closed**, not a vacuous pass. Producing
  a false GREEN would require inventing a hash value, which is fabrication rather than an inert
  predicate — and the surrounding *"execute it, and paste the transcript"* obligation covers it. So
  this is a wording sharpness issue, not a hole. Batch-64 itself demonstrates the correct behaviour:
  the four `.PRE` baselines were captured before the first write, and I verified all four hashes.
- **Recommendation.** Optional, three words, whenever C-40 is next touched: *"…returning to its
  pre-mutation value **(hash the file before mutating)**"*. **Does not gate this merge.**

### Prior findings — disposition

| # | status |
|---|---|
| F1 (HIGH, live tree / moved base) | **DISCHARGED** — tree settled, verified directly |
| F2 (MEDIUM, stale POST hashes) | **CLOSED** — §5d authoritative, all five match live |
| F3 (MEDIUM, Temp-only backups) | **CARRIED** — `BACKLOG-PROCESS.md §7.10`, verified present |
| F4 (MEDIUM, vacuous disjunction) | **FIXED** — verified, and strictly stronger |
| F5 (LOW, public repo) | **CARRIED** — `BACKLOG-PROCESS.md §7.11`, verified present |

---

## Evidence checklist

- [x] Each finding has what · where · why · recommendation — F-L1.
- [x] Each finding has a severity rating — 0 HIGH, 0 MEDIUM, 1 LOW.
- [x] No secret values in this output — none present; results reported as hashes and counts.
- [x] Verdict explicit — below.
- [x] New tool/integration scope + blast radius — **none added**; re-confirmed 0 production surface.
- [x] Every "unchanged/identical" claim is a content-hash or byte-substring result, per the discipline
      note — including the byte-mode re-read that corrected my own CR/LF misread.

## Verdict

- [x] **OK TO MERGE**
- [ ] OK to ship with mitigations applied first
- [ ] Block

**OK-TO-MERGE. 0 HIGH · 0 MEDIUM · 1 LOW.**

The one LOW is a three-word wording sharpening that fails closed and does not gate. Residual risk is
genuinely low and I will say so without hedging: the tree is settled and clean, all five destinations
hash to their recorded POST values, both limb spans are byte-identical so the arms transfer by
identity, block 6 survived the merge with its folds intact, and the F4 fix closes the vacuity it
targeted without introducing a weaker check in its place.
