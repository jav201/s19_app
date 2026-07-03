# Executive summary — s19tool — Batch 24

> Phase 6 artifact. Audience: non-technical stakeholder. 1-2 pages.

## Bottom line (read first)

- **What we delivered:** Two things. First, the tool's colour-coded firmware-symbol table and its Issues list — two views of the same health information — could silently disagree. Both directions of that disagreement were real defects in the shipped tool; both are now fixed and locked in by automated tests. Second, engineers who apply a change file and save a patched firmware image can now press one key and get a **before/after evidence report**: original vs saved file, the exact byte-level differences, and a table linking every change back to the change-document entry that caused it.
- **Why it matters:** The first fix restores trust in the tool's own diagnostics — a red row now always has an explanation, and a serious problem is never listed without being visible in the table. The second turns evidence-gathering after a patch — previously a manual comparison exercise — into a single keypress, with strict protections so the report can never mix up files from different projects or sessions.
- **Quality of the evidence:** The disagreement bugs were not assumed — the acceptance tests were written first and **failed on the shipped tool exactly as reported**, then passed after the fix. That is the strongest form of proof this process produces.
- **Next step:** Merge is pending operator approval. The remaining piece of feature #12 — a data-classification (entropy) viewer — is queued as its own exploration batch.

---

## Context (reference)

### Context

s19tool is the desktop tool our engineers use to inspect and edit firmware files. When a firmware file is loaded alongside its symbol definitions (an "A2L" file), the tool shows two companion views: a **symbol table** whose rows are colour-coded by health (red means something is wrong), and an **Issues list** that names and explains each problem. Engineers rely on those two views telling the same story. Separately, when an engineer applies a change file and saves a patched firmware image, they need evidence of exactly what changed — for reviews, sign-offs, and audits.

### Problem

The two views could quietly contradict each other, in both directions:

- A row could turn **red with no explanation** — nothing in the Issues list said why.
- A serious problem — two symbols sharing the same name — could appear in the Issues list as an error while **its rows looked perfectly normal** in the table.

Both were live defects in the shipped tool, not hypotheticals. A third, hidden case made it worse: in sessions loaded **without a MAC file** (a common configuration), the tool silently discarded its own validation results — so those sessions lost their diagnostics entirely. That flaw was found during the design review of this batch, before any code was written.

On the reporting side, there was simply no one-step way to produce before/after evidence after saving a patched image; engineers had to assemble the comparison by hand.

### Solution

- **Agreement, guaranteed both ways.** Every red row now produces a matching, named entry in the Issues list, and every error-level issue about a symbol now colours that symbol's rows red. The no-MAC case is fixed too: validation results are retained in every session type. All of this is enforced by automated tests that drive the real application the way an engineer would.
- **One-key evidence report.** After applying a change file and saving the patched image, the engineer is offered a report; pressing one key writes it (in two formats) into the project's reports folder. It shows the original file, the saved file, the byte-level differences, and a linkage table tying each change to the change-document entry that caused it.
- **Provenance protections.** The report refuses to run — with a clear on-screen explanation, and writing nothing — if anything is out of step: no saved image, the original file gone, or the saved data belonging to a **different project or an earlier session**. That last protection exists because the security review caught, before implementation started, that a stale leftover from a previous project could otherwise have produced a convincing but false report.

### Outcomes / results

- **Verified end-to-end.** 33 new automated tests were added; the **full test suite passes with zero failures** (1,004 passing). Every acceptance test observes the real interface — rendered tables, on-screen messages, files actually written to disk.
- **The bugs were proven, then fixed.** For both disagreement defects, the test was run on the shipped tool first and **failed exactly as the problem was reported** — captured verbatim — then turned green with the fix. The report feature carries the same discipline: its test failed while the feature was absent, then passed once it shipped.
- **Review caught what testing could not.** The design review found two blocking flaws before a single line of product code existed: the no-MAC data loss (one layer deeper than the original analysis had looked) and the stale-report risk. Both became formal requirements and shipped inside the batch, through the recorded amendment channel — no silent scope changes.
- **Resilience under interruption.** Work was interrupted mid-batch by an external session limit. The interruption landed at a clean checkpoint, was resumed by verifying the actual state on disk rather than redoing work, and cost **zero rework**.
- **No change to the protected core.** The locked-down, sensitive parts of the tool were untouched — confirmed automatically at every stage.
- **Process improvement banked.** Four new process rules distilled from the batch's review catches and interruption handling were adopted permanently at the closing review (operator-approved): deeper pre-code verification of state handling, a provenance requirement for features that consume earlier-captured state, a formal interruption-recovery protocol, and independent re-derivation of byte-exactness baselines.

### Next steps

- **Merge (pending approval):** the pull request and merge await operator sign-off — a routine closing step, no open risks.
- **Feature #12 continues:** the remaining piece — a **data-classification (entropy) viewer** that helps engineers see what kind of content occupies each region of a firmware file — is deferred to its own exploration batch, since it is a from-scratch design rather than a fix to existing behavior.
- **Minor items** (small code-hygiene cleanups and one optional refinement) are logged in the backlog; none affect users.
