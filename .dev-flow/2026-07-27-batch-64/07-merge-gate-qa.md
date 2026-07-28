# batch-64 — FINAL PRE-MERGE QA GATE

**Verdict: `BLOCKED`. 3 HIGH · 6 MEDIUM · 3 LOW.**

**BLUF: the four merge-gate criteria are met on substance — zero engine-frozen diffs, zero production
or test diffs, a reproducible frozen manifest, honest traceability exclusions, and a bidirectional
census I re-derived independently. The batch is blocked on its *evidence integrity*, not its content.
Two of the three HIGHs share one root cause: the three out-of-VCS legs are not under change control,
and I proved it empirically — `~/.claude/commands/dev-flow.md` was edited by a concurrent party
DURING this gate, growing 68 164 → 68 311 B and moving C-40's normative body off the hash the batch's
transfer argument depends on. The third HIGH is a false factual claim in permanently installed global
governing text, of the exact class the code review already caught once and folded.**

Reviewer: independent `qa-reviewer`, authored none of this batch. Every figure below was re-derived by
execution, not read from an artifact.

---

## 0. Topology — the tree moved under this review

The briefing named `HEAD = 6fbbeba`, `origin/main = c779e3d`. Both had moved before I finished:

```
HEAD        = ca36f66   (6fbbeba -> a77227f merge -> ca36f66 "post-merge coherence review")
origin/main = 082ada9   ("split the backlog into a code lane and a process lane", #143)
merge-base  = 082ada9   == origin/main tip  -> RC-1 holds
```

All findings below are re-verified against `ca36f66` / `082ada9`. Working tree clean apart from the
parallel reviewer's untracked `07-merge-gate-security.md`.

`ca36f66` is a genuine improvement: `03-out-of-vcs-evidence.md §5c` handles the lane split, re-runs
`PP-5` post-merge by content rather than line number, verifies each carry present exactly once across
the three backlog files, and discloses a new finding (the global `/dev-flow` backlog rule is now stale
for this project). That section is the best-executed work in the batch.

---

## 1. The four merge-gate criteria

| # | criterion | verdict | how I verified it |
|---|---|---|---|
| 1 | Dual traceability intact | **MET** | both exclusions honest — see §2 |
| 2 | Zero engine-frozen diffs | **MET** | `git diff --stat origin/main...HEAD -- core.py hexfile.py range_index.py validation/ tui/a2l.py tui/mac.py tui/color_policy.py` → **empty** |
| 3 | No cross-increment regression | **MET on its premise** | `git diff --stat origin/main...HEAD -- s19_app tests examples pyproject.toml` → **empty**. D-5's basis (nothing added to `tests/`) is independently true, so `post = 2201 − 0 + 0` is sound. I did not re-run the ~24-min suite |
| 4 | Every gate carry discharged | **MET with defects** | all 38 source findings accounted for; two carries and one postmortem candidate reach no backlog file — M-4, M-5 |

### Criterion 1 — both exclusions are honest

**`AT-B64-11`** is excluded correctly. *"A hash proves a change, never the right one"* is a sound
reason, it is labelled in the matrix rather than dropped, and the coverage figure is stated over the
remaining set. Excluding it does not hide a gap: `HLR-B64-6` is separately observed by `LLR-B64-6.1…6.4`.

**`PP-*` instead of minted `TC` ids** is also honest, and it is the stronger call. I confirmed the
justifying property by construction: `AT-B64-08`/`-09` are pure content predicates and return
identical values on a correctly-placed and a mis-placed insert, whereas `PP-1…PP-5` separate them.
Four `shall` clauses fix within-file position; nothing else observes them. Minting `TC-NNN` ids here
would have been the template-filling the flow forbids. Not a gap.

---

## 2. HIGH findings — each blocks the merge

### HIGH-1 — the installed C-35 rider ships a superseded, hand-shaped occurrence total, in permanent global governing text

**Where:** `~/.claude/commands/dev-flow.md:145`, inside the shipped rider's `(Measured: …)` tail.
Verbatim, re-read from the live file after the concurrent edit (still present):

> `Same family, 8 occurrences enumerated across batches 60-63 in
> .dev-flow/2026-07-27-batch-64/01b-qa-catalog.md §AT-B64-04 — cite the enumeration, never a total:
> three registers disagree.`

Four independent problems, each verified:

1. **The number is the superseded one.** `01-requirements-consolidated.md:150` records amendment
   **A-18**: *"the P-3 enumeration | 8 occurrences | **9.** Executing AT-B64-04 found the enumeration
   under-drawn … **The 8 was itself a hand-shaped set**"*. `:651` — *"occurrence #9 is absent from
   QA's enumeration of 8"*. The catalog was never corrected; it still shows 8 rows and *"True count =
   8"* (`01b-qa-catalog.md:379-388`).
2. **The sentence's own anchor contradicts its own number.** It points at `§AT-B64-04`, and
   `AT-B64-04` was measured **9/9 over nine occurrences** (`04-measurement-frozen.md:91-105`). A
   future reader following the pointer gets a set this batch proved incomplete.
3. **It self-contradicts within one sentence** — it cites a total in the same breath as *"never a
   total"*. This is the identical shape to the C-40 defect the code review caught and folded as F2,
   which `03-out-of-vcs-evidence.md:130-131` argued must be fixed rather than carried precisely
   because it is *"a false factual claim in permanent global governing text read by every future
   batch, in a batch whose thesis is that a document must not assert what it does not honour."*
4. **It falsifies a recorded closure.** `01-requirements-consolidated.md:128` records **A-12** as:
   *"the encoded text carries **no occurrence total**; it enumerates"*, and `§10` item 4 repeats
   *"Reconcile all three registers or delete the totals; **the encoded text carries none (A-12)**."*
   The encoded text carries one. A-12 is closed on a false premise, and the defect is therefore
   **not** a disclosed carry — the batch affirmatively asserts the opposite.

**Aggravating:** C-40, installed one bullet away in the same file, forbids exactly this — *"LIMB 2 —
the set must come from the RULE, not from the implementation … a set derived from what the code
currently handles makes the check a tautology."* A-18 labels the 8 *"a hand-shaped set"*. So the
shipped C-35 rider directs every future batch to reuse a set the shipped C-40 forbids.

**Why it survived:** the byte-fidelity pass verified block 2 against `§3.0`'s hash — which it matches
exactly (2 411 B / `4b4e3bad…`, re-derived by me). The freeze protected the wrong number.

**Fix is cheap and disturbs no acceptance.** I measured the split: rider normative body **1 975 B**,
separator **1 B**, `(Measured:)` tail **435 B**, sum **2 411 B** = block 2. The defect is entirely in
the 435 B tail; `AT-B64-04` and `AT-B64-05` are measured over the 1 975 B body. Deleting the count —
which is what A-12 says the text should do — leaves both acceptances byte-bound and untouched.

---

### HIGH-2 — `§5b`'s byte-identity claim for C-40 is now FALSE against the live file, so `AT-B64-01`/`-02` are inadmissible under the batch's own rule

`03-out-of-vcs-evidence.md:140-145` rests the whole acceptance-transfer argument on:

> *"C-40's normative body — everything before its `(Origin:` — is **byte-identical** … **4 564 B,
> `sha256=026bb4c6709f2ed64ecc5132…`** … The arms harness parses by those limb markers, so
> `AT-B64-01` (9/9 CI · 8/9 full) and `AT-B64-02` (1/6 CI-normative) are measured over an unchanged
> region."*

**When I first measured it, the argument held completely.** I re-implemented `§3.0`'s extraction rule,
reproduced block 1 at **6 219 B / `5cb146e980deb639…`** and block 2 at **2 411 B / `4b4e3bad391c…`**,
and confirmed the body identical at **4 564 B / `026bb4c6709f2ed64ecc51323c0209d6…`**, with all
thirteen semantic elements the harness reports parsing (`**LIMB 1`, `**LIMB 2`, keying, PIN corollary,
the A-23 domain ruling, instances (i)/(ii), the DISCHARGE clause, mutation hygiene, restore, the
C-10/C-31/C-39 delta, the C-35 relation) **resident in the body and absent from the amended tail**.
The three review folds (F2, F2b, F6) all landed strictly inside the `(Origin:` tail, Δ = −3 B.

**Then it stopped holding, during this review.** Re-measured minutes later:

```
frozen body : 4564 B  sha=026bb4c6709f2ed6
live   body : 4711 B  sha=5eb453ace105dce7      <- +147 B
IDENTICAL   : False
```

The word-level diff of the live normative body vs the frozen block:

```
- confirming the restore in the same transcript (`git status` clean, or the file's hash back at its
  pre-mutation value).
+ confirming the restore in the same transcript **by returning to the file's hash ... value** —
  `git status` alone is insufficient and is outright **vacuous for an untracked file**, which it
  reports identically whether or not the mutation was reverted.
```

The edit is **substantively good** — it closes a real vacuity, and untracked files are exactly what
this batch's out-of-VCS legs are. I am not objecting to the content. I am objecting that:

- `§5b`'s claim is now false as written, and it is the sole argument that the arm figures transfer;
- by `§3.0`'s own **normative** rule — *"Any later edit to a paste block invalidates every measurement
  keyed to that block's hash and requires re-measurement"* and *"A figure is admissible only if it
  names the block hash it was taken against"* — `AT-B64-01` and `AT-B64-02` are **inadmissible** until
  re-measured against `5eb453ac…`;
- no artifact records the edit or the re-measure.

Substantively the arms will almost certainly still read 9/9 · 8/9 · 1/6 — the change sits in the
DISCHARGE clause, not in LIMB 1 or LIMB 2, and I re-confirmed all thirteen harness needles are still
body-resident. **But "almost certainly" is precisely what this batch exists to forbid.** Re-measure and
restate, or the batch ships a self-refutation.

---

### HIGH-3 — the out-of-VCS legs are not under change control, and `03` cannot detect an unintended edit

The operator asked directly whether `03-out-of-vcs-evidence.md` is sufficient to detect an unintended
edit, and asked me to verify the PRE/POST hashes against the files as they stand. **It is not, and I
demonstrated it rather than argued it.**

Re-derived POST hashes against `§2`'s table:

| file | in VCS | recorded POST | measured now | verdict |
|---|---|---|---|---|
| `docs/engineering-rules.md` | ✅ | 19 435 / `5618029c…` | 19 435 / `5618029c…` | **MATCH** |
| `~/.claude/skills/tui-design/VERIFY.md` | ❌ | 11 684 / `3c6016fc…` | 11 684 / `3c6016fc…` | **MATCH** |
| `~/.claude/commands/dev-flow.md` | ❌ | 67 891 / `85979683…` | **68 311** / `21a031f7…` | **MISMATCH, +420 B** |
| `project_devflow_control_lineage.md` | ❌ | 42 365 / `1a366bf4…` | **42 450** / `50cf146e…` | **MISMATCH, +85 B** |
| `.dev-flow/BACKLOG.md` | ✅ | 82 328 / `f6768bd0…` | **26 057** / `781c82e9…` | **MISMATCH** (lane split) |

Only the two files the review folds did not re-touch still match. `dev-flow.md` alone moved twice
during this gate: 68 164 B when I first hashed it, 68 311 B thirty minutes later. **Both movements are
invisible to the record.** `§5b` discloses that blocks 1/5/6 were amended, which is honest, but it
never restates their POST hashes — so from this point forward the audit trail has **zero** detection
power for the three files that have no other one.

This also breaks the batch's own newly-installed rule, in the very clause that was just edited: C-40
mandates running mutations where *"no other session is reading … never a tree a concurrent review or a
parallel batch is measuring."* Two merge-gate reviewers were reading `dev-flow.md` while a third party
wrote to it.

**What is genuinely sound, and I verified it:** the four PRE backups in
`…/scratchpad/b64-baselines/` match their recorded PRE hashes **exactly** (`44660d7c` / `23cf75e6` /
`d9f84f9e` / `278b808d`), so rollback is real. And diffing every live out-of-VCS file against its PRE
backup, line-ending-normalised, shows the edits are **purely additive with zero collateral**:
`dev-flow.md` = 1 inserted line + 1 in-place replacement (the C-35 bullet) and nothing else;
`VERIFY.md` +20 / −0; lineage +7 / −0; `engineering-rules.md` +12 / −0, matching `git numstat` exactly.
**The content that landed is correct.** The mechanism guarding it is not.

**Remediation:** quiesce the files, re-hash all five, restate `§2` with POST-fold hashes, and re-run
the two C-40 arms against the current body.

---

## 3. MEDIUM findings

**M-1 — `AT-B64-04`'s closure is overstated three ways.** The transcript
(`04-measurement-frozen.md:107-123`) shows **four** reddening mutations, not three:
`{D}`→6/9, `{B,G,H}`→7/9, `{C,F}`→7/9, `{A,C}`→8/9. Three artifacts say *"three"* while printing four
figures (`04-validation.md:36`, `traceability-matrix.md:11`, `03:90`). Worse, two of them say
**"disjoint clause sets"** (`04-validation.md:5-6`, `03:90`) — the clause sets are **not** disjoint,
`{C,F} ∩ {A,C} = {C}`. Only `04-measurement-frozen.md:129` uses the correct term, *"disjoint
occurrence sets"*; the downstream summaries degraded a true claim into a false one. And **occurrence
#2 has no executed reddening mutation**: the union of all lost-sets is `{1,3,4,5,6,7,8,9}`; #2's
carriers are `B + I`, deleting `B` alone returns 9/9, and clause `I` was never deleted. Separately,
the occurrence→clause mapping is hand-authored by the measurer, not derived from the rule — C-40's own
limb-2 shape, sitting inside limb 1's discharge, unnamed.
*BLOCKER-1 itself is genuinely discharged:* I confirmed block 2 is byte-exact in the destination and
its hash reproduces, so the 9/9 does bind to shipping bytes.

**M-2 — the batch's normative spec contradicts its own validation record, undisclosed.**
`01-requirements-consolidated.md` still carries a live `§4` staleness banner (*"Every arm figure in
this document is STALE"*) and declares `arch BLOCKER-1` open in four places — `:480` (*"is therefore
NOT closed"*), `:514` (*"the discharge is WITHDRAWN"*), `:987` (*"NOT DONE — blocking Inc-3 gate
condition"*), `:1136` (*"is RE-OPENED"*) — while `04-validation.md` approves. The four corrections
`04-measurement-frozen.md §7.1` listed *"to carry into Inc-0"* never landed, including `+8 631`/
`+8 630` at `:803`/`:946`/`:1045` where the measured delta is `+8 632`. No artifact discloses the
conflict.

**M-3 — `§2`'s "predicted Δ ✅" is back-fitted on 2 of 5 rows.** For the lineage, the only pre-derived
figure on record is `+5 963` (`04-measurement-frozen.md:322`, block 5 = 5 962 B + 1); `03:38` records
*"predicted +5 964 ✅"*. For `BACKLOG.md`, `:322-323` explicitly **declined** to predict three of the
four segments (*"correctly left to Inc-4 rather than predicted"*); `03:39` records *"predicted
+5 888 ✅"*. A prediction column reconciled after the fact has no detection power — the vacuous-check
defect, inside the bounded-delta check the batch calls *"a check rather than a log."*

**M-4 — the `§5b` line-ending argument is methodologically void, though its conclusion is true.**
`§5b:158-160` cites *"`git diff --stat` shows 24 insertions, 3 deletions — ordinary edits, not a
whole-file rewrite, which is what line-ending damage would look like in a diff."* This repo has
**`core.autocrlf = true`**: I confirmed both blobs are pure LF in *both* revisions (`origin/main`
`.dev-flow/BACKLOG.md` = 0 CRLF; `HEAD` = 0 CRLF), so git normalises CRLF on commit and line-ending
damage could **never** appear in that diff. The check cited as proof cannot fail on the defect it was
cited to exclude. The conclusion is nonetheless correct, which I established two other ways — blob-level
comparison, and the PRE-backup diff showing purely additive edits.

**M-5 — `§7.10` reaches no backlog file, and the postmortem asserts completeness falsely.**
`01-requirements-consolidated.md §7` enumerates **10** carries. Post-merge, `§7.1/§7.2/§7.8` are in
`BACKLOG-CODE.md` and `§7.3–§7.7`, `§7.9` in `BACKLOG-PROCESS.md` — **9**. `§7.10` (TRIM-C offered as
*"the cheapest form"* while being superseded) returns **0 hits** across all three files. Separately,
`05-postmortem.md:103` states *"All are in `.dev-flow/BACKLOG.md §7.1–7.8`"* — wrong on the count (10,
not 8) and, after `ca36f66`, wrong on the file. The postmortem's own headline candidate — *"a fix to
one finding can disarm another finding's test"* — greps **0** across the queue. This breaches the
operator's standing rule that reconciliation drops nothing.

**M-6 — `arch MAJOR-7` is a defect in permanent global text with no queue entry.** The finding is that
C-40's `EXTENDS` clause claims the *Certainty* clause alone while the rule pre-exists in three places
(`dev-flow.md:177` C-19, `VERIFY.md:40-49`). `02c` marks it PARTIAL and then counts it under *"carried
with an explicit stated reason"*; the disposition lives only in a commentary section of a spec that
does not ship. It is in no backlog file and not in `05-postmortem.md §7`.

---

## 4. LOW findings

- **L-1** — `03 §5` says the stack list *"names `C-13`, `C-32`, `C-34`, `C-37`, `C-38`"* (5). The
  shipped footer names 12. The stronger `12/12` claim in the matrix and `04-validation` is the correct
  one — I re-derived it as an **exact set match** against `engineering-rules.md`'s twelve `## C-*`
  sections: `{C-13, C-13.1, C-22, C-23, C-28, C-29, C-30, C-32, C-34, C-37, C-38, C-42}`.
- **L-2** — `04-measurement-frozen.md §4.1`'s `declared=32 (S1=11 S2=20 S3=1)` is the **pre-batch** id
  space, presented in `04-validation.md:41` beside a *"re-run after the edit"* claim. Post-edit I
  re-derived **34** (S1=12 with C-42, S2=21 with C-40, S3=1). The shipped BACKLOG footer states it
  correctly as *32 ∪ {C-40, C-42}*; only the batch artifact leaves the figure unlabelled.
- **L-3** — the HEAD commit message references `(#143)` while the PR under review is #144.

---

## 5. What I checked that could have produced a HIGH and did not

- **Engine freeze.** Zero diffs across the full `_ENGINE_PATHS` set vs the current `origin/main`.
- **Production surface.** Zero diffs in `s19_app/`, `tests/`, `examples/`, `pyproject.toml` — so D-5's
  premise for `post = 2201` is independently true, not carried.
- **Frozen manifest reproducibility.** I re-implemented `§3.0`'s extraction rule from its prose and
  reproduced block 1 (**6 219 B / `5cb146e980deb639a65fe7e494c356e666086c0c743f810fbd4294149945c9ed`**)
  and block 2 (**2 411 B / `4b4e3bad391c0962c3a8ab0fb8aa59115e3dc85d95882640de3573a6943fbdae`**)
  exactly. A fourth independent reproduction.
- **Rollback.** All four PRE backups hash-match their recorded values exactly.
- **Content confinement.** Live-vs-PRE-backup diffs show additive-only edits with zero collateral and
  zero deletions in every out-of-VCS file.
- **`AT-B64-10`, re-derived post-edit.** Encoded-minus-registered = **∅** (the C-29 back-registration
  landed); lineage-declared-minus-encoded = **exactly `{C-1}`**, matching the claim that C-1 is the
  sole carried exception; `C-41` absent from both sides, so the id is genuinely free.
- **`PP-5`, re-derived post-edit and post-merge.** Both clauses hold on the current file.
- **C-42's Origin citations.** All four resolve and support what they are cited for —
  `batch-62/04-validation.md:191-192`, `batch-63/00-measurements.md:96-98`,
  `batch-63/01-requirements-architect.md:1044-1049`, `batch-62/02-review-security.md:68`. The
  *"two of the five … impossible rather than merely wrong"* claim is corroborated by the source, which
  independently calls its own value impossible. **C-42 is the cleanest of the four installed texts.**
- **The code review's four MEDIUMs.** All folds verified present in the installed bytes: F2
  (*"Three of the five … to a byte count"*), F2b (*"for one defect"* gone), F6 (`:206`→`:207`), F1
  (re-pointed to a drift-proof label, re-pointed again at the lane split per `§5c`).
- **The `VERIFY.md` extension.** Read in full; general terminal-UI knowledge only, correctly
  de-identified, `[travels]` retained, no new `##`. No false claim found.

---

## 6. Exit criteria

- **Coverage — MET.** Every story has an executed black-box AT; Layer A exists; both exclusions honest.
- **Certainty — NOT MET.** `AT-B64-01`/`-02` are inadmissible against the live bytes (HIGH-2);
  `AT-B64-04`'s counterfactual leaves occurrence #2 uncovered and is misdescribed downstream (M-1).
- **Evidence — NOT MET.** Three of five POST hashes fail; two of five delta predictions are
  back-fitted; the normative spec contradicts the validation record.
- **Installed-text correctness — NOT MET.** HIGH-1.

## 7. Minimum path to `OK-TO-MERGE`

1. **HIGH-1** — delete the *"8 occurrences enumerated"* count from the rider's `(Measured:)` tail, per
   A-12's own stated intent. Confined to the 435 B tail; disturbs no acceptance.
2. **HIGH-3** — quiesce the three out-of-VCS files, re-hash all five, and restate `03 §2` with
   post-fold POST hashes so the trail has detection power going forward.
3. **HIGH-2** — re-run the C-40 arms against the current body (`5eb453ac…`) and restate `§5b`'s
   identity claim against the new hash.
4. **M-1/M-2** — correct *"three mutations on disjoint clause sets"* → *four mutations, disjoint
   occurrence sets*; disclose occurrence #2; retire the `§4` staleness banner and close `§10` item 1a.
5. **M-5/M-6** — land `§7.10`, the *"disarm"* candidate, and `arch MAJOR-7` in the correct lane file.

Items 1–3 are the blocking set. None requires touching production code.
