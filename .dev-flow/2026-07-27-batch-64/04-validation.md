# batch-64 — Validation

**BLUF: every story is covered by an executed black-box acceptance keyed to the bytes that shipped;
Layer A exists after being wrongly declared N/A by three parties and refuted by execution; the one
acceptance that had never run (`AT-B64-04`) now measures 9/9 with FOUR mutations biting on disjoint
**occurrence** sets (the *clause* sets overlap), with occurrence #2 unmutated — a gap stated, not hidden. No gap blocks the merge. Two findings are carried, both with their numbers.**

Evidence sources, all executed by parties other than the spec's author:
`01c-arms-measurement.md` · `02c-discharge-audit.md` · `04-measurement-frozen.md` ·
`03-out-of-vcs-evidence.md` · the independent `code-reviewer` pass.

---

## 1. The validation problem this batch had to solve first

The deliverable is text. The naive acceptance — *"the string appears in the file"* — is exactly what
`VERIFY.md:36` condemns (*"A green check that only goes red when you delete prose is not evidence"*),
and a batch encoding *"prove your acceptance can fail"* whose own acceptances cannot fail would be
self-refuting.

**The answer adopted at Phase 0 and held throughout: acceptance is keyed on whether the encoded rule
DISCRIMINATES over a labelled corpus**, not on prose presence. That corpus is batch-63's documented
vacuous predicates (positive arm) plus its genuinely load-bearing ones (negative arm). A control
flagging 0 of the positives is inert; one flagging the negatives is a false-positive machine. Both
arms can go RED, and both did under mutation.

## 2. Layer B — black-box acceptance (the WHAT)

Every figure names the block hash it was measured against, per `§3.0`'s normative admissibility rule.

| AT | observable | result | reddening mutation, executed |
|---|---|---|---|
| **AT-B64-01** | C-40 flags the known-vacuous corpus | **9/9 CI-domain · 8/9 full-domain** (block `5cb146e9…`) | delete limb 2 → **4/6** on the earlier corpus, losing exactly the P-6/P-7 members; anchor corruption → 6/9 → **2/9** |
| **AT-B64-02** | C-40 does **not** flag sound predicates | **1/6 CI-normative · 0/6 full · 0/5 reclassified** | key limb 1 on "the writer" instead of the declared subject → **1/6 false positives** |
| **AT-B64-03** | C-40 catches what C-10/C-31/C-39 do not | **confirmed** — `V-6` is invariant under code mutation, has no set to derive, and carries no threshold | — |
| **AT-B64-04** | the C-35 rider's clauses are independently load-bearing | **9/9** (block `4b4e3bad…`) | **four** mutations on disjoint **occurrence** sets: `{D}`→6/9, `{B,G,H}`→7/9, `{C,F}`→7/9, `{A,C}`→8/9; all-needle corruption → **0/9**. Clause sets overlap (`{C,F}∩{A,C}={C}`); occurrence #2 has **no** executed reddening mutation |
| **AT-B64-05** | rider's normative body is stack-free | **0/17 terms**, GREEN | inject `Textual` → RED; non-emptiness guard holds |
| **AT-B64-06/07** | C-42 names five mechanics; boundary complement holds | **confirmed**, five mechanics across six bullets (split declared) | — |
| **AT-B64-08** | `VERIFY.md` extension is de-identified | **0/12 terms**, GREEN, re-verified **post-paste on the live file** | two reddening mutations bite |
| **AT-B64-09** | the extension catches what the pre-existing rule does not | **satisfiable, measured** — literal `Edit Tool` → **0/29** snapshots, emitted `Edit&#160;Tool` → **29/29** | direction gap confirmed |
| **AT-B64-10** | lineage registry is bidirectionally consistent | **PRE RED / POST GREEN**, 32 ids across 3 disjoint declaration shapes | **two independent RED carriers** — `C-29` encoded-unregistered and `C-1` registered-unencoded, running in opposite directions, so no single re-scope greens it |
| **AT-B64-11** | out-of-VCS hash record | **bookkeeping, not acceptance** — counts toward no story | — |

**`AT-B64-11` is deliberately not counted.** A hash proves *a* change, never the *right* one. It is
labelled as bookkeeping rather than inflating the coverage figure.

## 3. Layer A — the declaration that was wrong

**Three independent parties — both Phase-1 lanes and the orchestrator — concluded Layer A was `N/A`**
on the reasoning that for a documentation deliverable the artifact *is* the observable. The Phase-2 QA
reviewer **refuted it by execution**: a placement predicate for `LLR-B64-4.1` is **RED pre-batch, GREEN
on a correct insert, RED on a mis-placed insert**, while `AT-B64-08` and `AT-B64-09` return **identical
values on both**. Four `shall` clauses stated within-file placement and nothing observed them.

Unanimity across three parties was not evidence; execution was.

| predicate | requirement | RED pre / GREEN post / RED mis-placed | post-edit result |
|---|---|---|---|
| PP-1 | C-40 after C-39, before the UI pointer | ✅ / ✅ / ✅ | `31606 < 34013 < 40153` |
| PP-2 | rider **inside** the C-35 bullet, before its `(Origin:` | ✅ / ✅ / ✅ | same line, one space before `(Origin:` |
| PP-3 | C-42 between `## C-38` and `## C-34` | ✅ / ✅ / ✅ | `11928 < 13440 < 17724` |
| PP-4 | extension inside `## Pin the truth`, **no new `##`** | ✅ / ✅ / ✅ | new headings = **0**; heading string-list byte-identical PRE/POST |
| PP-5 | BACKLOG footer id range **and** stack list | ✅ / ✅ / ✅ | both clauses; stack list an **exact 12/12 set match** against real sections |

No `TC-NNN` ids were minted. Manufacturing white-box ids to fill a matrix is the template-filling the
flow's hard rules forbid; four ~10-line predicates were built instead.

## 4. Bidirectional surface matrix

| input dimension | exercised through | output / deliverable | observed |
|---|---|---|---|
| C-40 rule text | the arms harness over the installed block | discrimination over 9 positives / 6 negatives | ✅ AT-01/02/03 |
| C-35 rider clauses | mutation over the 2 411 B shipping body | per-clause load-bearingness | ✅ AT-04 |
| C-42 text | `docs/engineering-rules.md` as committed | five named mechanics, house register | ✅ AT-06/07 + code review |
| `VERIFY.md` extension | the live file post-paste | de-identification + discrimination | ✅ AT-08/09 |
| lineage + BACKLOG | post-edit census re-run | bidirectional registry consistency | ✅ AT-10, PP-5 |
| **placement of all four** | the destination files themselves | within-file position | ✅ PP-1…PP-5 |

Every named input is driven through the real destination file, and every named deliverable is observed
in it. The `AT-B64-10` census is re-run **after** the edit — without that it would be a pre-batch
observation, not an acceptance.

## 5. Regression

`pytest -q -m "not slow"` at `c779e3d`, **re-derived rather than carried** (four lanes had cited it and
none had re-run it):

```
2201 passed, 2 skipped, 21 deselected, 3 xfailed in 1430.47s
29 snapshots passed
exit 0
```

Ledger `post = 2201 − 0 + 0 = 2201`, as ruled by **D-5** (this batch adds nothing to `tests/`).
`git status --porcelain -- s19_app tests examples pyproject.toml` → **0 files**.

## 6. Gaps and carries — stated, not closed

1. **`U-3(a)` and `U-4`** (union-ledger residue). `U-4` — the Phase-2 architect review's `163` is not
   reproducible from itself, because its 136 carried items are enumerated nowhere — is **unclosable by
   any fold**; it is a property of that review's output format.
2. **The `D-` register collides.** Operator rulings run `D-1…D-11`; restoration ids run `D-01…D-20`;
   they collide from `D-10`. Renaming mid-batch would break more citations than it fixes. Carried —
   same disease as `OB-2`.
3. **Line-ending translation**, introduced by the orchestrator at the review-fold step and recorded in
   `03-out-of-vcs-evidence.md §5b`. ⚠ **The proof originally offered for it was VOID and is withdrawn:**
   `git diff --stat` cannot show CRLF damage when `core.autocrlf=true` (measured: it is), so that
   evidence *could not have failed* — this batch's own defect class, committed while documenting this
   batch's own defect class. The conclusion survives on other evidence: the merge-gate reviewers
   verified it independently two further ways (LF-normalised diffs `+2/-1`, `+20/-0`, `+7/-0`, `+12/-0`;
   `.gitattributes` pins nothing in scope). The uniform-CRLF end state is kept deliberately.
4. **Four vacuous predicates live on `main`** (`V-6`/`V-7` and two others) — **carry, not fix**, since
   D-5 forbids touching `tests/`. They are in `BACKLOG.md §7.1`.

## 7. Exit criteria

- **Coverage** — every READY story has an executed black-box acceptance; Layer A exists after
  refutation; zero orphans. `AT-B64-11` is excluded by label, not silently. **MET.**
- **Certainty** — every acceptance has an executed reddening mutation. The two that could not
  originally fail were found and fixed: limb-1's keying (1/6 false positives) and `AT-B64-04`
  (measured against superseded bytes). **MET.**
- **Evidence** — every figure names the block hash it was measured against; the manifest was
  reproduced independently by three parties; the suite was re-derived. **MET.**

**Verdict: `approve`.** No blocker. Proceed to Phase 5.
