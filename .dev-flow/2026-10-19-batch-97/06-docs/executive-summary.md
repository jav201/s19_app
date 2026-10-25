# Executive summary — s19_app — Batch 2026-10-19-batch-97

> **Roles:** `presentation-builder` (this artifact). Batch `2026-10-19-batch-97`, repo `s19_app`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `presentation-builder`. Audience: non-technical stakeholder. 1-2 pages.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 Bottom line (read first)

- **What we delivered:** the "b94 polish". The four work screens that batch-94 shipped (Patch Editor, Check Editor, Flow Builder, Flow Execution) now use the layouts the operator chose in a prototype round. The batch also added a two-row key bar to all 13 windows and fixed the Load project dialog, which did not load the project the engineer picked.
- **Business outcome:** the four screens now meet the standard of the rest of the tool. Each screen shows all of its content, says where its files are and what every control does, and uses the space of any window size without wrapping rows. The key bar shows only the keys that work in the current window. Independent validation passed with notes: 81 of 81 requirements and 26 of 26 acceptance tests passed, with no high-severity finding.
- **Next step:** the operator approves these documents, then commits, pushes and syncs them. The operator also runs one snapshot-regeneration check in CI (continuous integration, the shared automated build) and decides the one open design-review item (PC-26). After that, the integrity batch starts.

---

## Context (reference)

### Context
s19_app is the terminal tool (TUI, terminal user interface) a calibration engineer uses to prepare and review software changes for ECUs (engine control units). Batch-94 shipped four new work screens. To bring them to final quality, the operator first ran a prototype round and chose layout "A" for all four screens. This batch put that choice into the real screens. The batch started on 2026-10-19, and the operator closed it on 2026-10-25 (`PLAN.md` §Header, §Where we are; `01-requirements.md` §2.6).

### Problem
The four batch-94 screens worked, but in daily use they were not as good as the rest of the app (stories US-134..US-140):

- **Hidden content and empty space.** The Patch Editor kept a JSON panel that was mostly empty. Fixed widths left half the screen empty on large terminals and pushed content past the edge on smaller ones (US-134, US-139).
- **Guesswork.** The screens did not say which folder their files are in, or what each mark and control means. In the operator's words (translated from the round-2 answer): guessing and searching for them is a problem, especially for new users (US-138).
- **Hard-to-read flows.** The engineer could not see a whole flow, or the state of each running chain, at a glance (US-136, US-137).
- **Keys that did nothing.** The key line at the bottom of the screen did not show which keys work in the current window. The operator raised this at the design review (US-140).
- **A silent defect.** On 2026-10-23, a UI (user interface) audit found that the Load project dialog did not load the project the engineer picked (HLR-151).

### Solution
What shipped, in plain terms (details: `06-docs/functionality.md`; summary: `05-close.md` §1):

- **Patch Editor:** a full-height list of entries beside an inspector. A live, read-only JSON view shows the entry count, the time and whether the file is saved.
- **Check Editor:** a parameter list beside a card that shows what the comparison report will contain.
- **Flow Builder:** one horizontal pipeline of blocks connected by cables. When the engineer adds a block, the form asks only for the inputs that block needs.
- **Flow Execution:** one pipeline per lane. The app highlights any lane that waits for the engineer. One Confirm key continues the waiting lane, and only one run can happen at a time.
- **On all four screens:** "open folder" buttons that open only folders that really exist, and window help that names every control.
- **Layouts that adapt to size:** the layout is calculated again each time the terminal is resized. Sizes from 118x54 to 220x60 characters were checked, with no wrapped rows.
- **Two-row key bar on all 13 windows:** the first row shows the global keys, and the second row shows the keys for the current window. A click on a key does the same thing as a key press.
- **Load project:** the dialog now loads the project that the engineer picks.

### Outcomes / results
The status of each claim is in brackets. These are the flow's evidence states.

- **Requirements verified [executed, approved]:** all 81 requirements pass (8 high-level, 73 low-level). The independent validation verdict is PASS-WITH-NOTES: 0 high-severity findings and 7 minor gaps (`04-validation.md` §Verdict).
- **Acceptance behaviours [executed]:** all 26 acceptance tests check the result through the shipped screens. Note: the Load project fix has one integration test but no acceptance-test id. That gap is in the backlog.
- **No regression from this batch's product code [executed, with a caveat]:** in the full test run, 3,617 tests passed and 11 failed. Of the 11 failures, 6 failed before the batch started, 3 are known intermittent ("flaky") tests, and 2 were errors in new test code. The 2 test errors were fixed in test files only, and targeted re-runs passed. A new full-suite run after those fixes was **not run**. Also, 4 tests that failed before the batch now pass.
- **Test suite growth [executed]:** the number of collected tests went from 3,146 to 3,634.
- **Delivery [executed]:** 9 increments, all pushed to `main`. The last code commit is `432ecf0`; the close records are on `main` at `c899113`; the validated tree is `14ec95b`.
- **Design review [approved with conditions]:** 25 of 26 design-review conditions are closed. PC-26 (a review page for the key bar) is still open and needs an operator decision.
- **Process cost:** the requirements review took three rounds plus a smaller final check, and it stopped at the operator's iteration limit. The requirements document is about 232 KB, against a budget of 54 KB. That item is still open (`05-close.md` §1).
- **Not done [not-run]:** there was no evaluation with real users. There was no test on the operator's own production data: the tests use synthetic and demo files, and real data is the subject of the integrity batch. There was no CI snapshot regeneration: the reference screenshots were regenerated on a local machine, which differs from design decision D17. Savings in user time, change in error rate and other business metrics: **not recorded**.

### Next steps
The order below is the operator's plan of 2026-10-25 (`.dev-flow/BACKLOG-CODE.md` §*Decided 2026-10-25*). The sources do not record target dates.

1. **Close this batch (now, operator).** Review and approve the `06-docs/` documents. Then commit, push and run `/dev-flow-sync`.
2. **Two small follow-ups (before the next screen change).** Run one CI `snapshot-regen.yml` check to confirm the reference screenshots that were regenerated locally. Decide PC-26: accept the Inc-8 screenshots as the key-bar review, or ask for the review page to be built.
3. **Integrity batch.** Confirm that the tool reads real memory images and parameter-description files correctly. The more detailed Load project tests also go to this batch.
4. **Load+projects batch.** Its prototype round includes a progress bar.
5. **Waiting-lane scroll prototype**, then the **batch-98 flow report**.

This batch left 27 open follow-up items in the backlog. The backlog lists them at priority P2 or P3, none high-severity (`05-close.md` §4–§5).
