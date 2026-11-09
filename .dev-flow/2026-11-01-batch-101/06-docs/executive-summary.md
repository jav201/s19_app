# Executive summary — s19_app — Batch 2026-11-01-batch-101

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `presentation-builder`. Audience: non-technical stakeholder. 1-2 pages.

> **Owed in.** `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch.

## 🔑 Bottom line (read first)

- **What we delivered:** the release-hardening batch for v1.0.0. The strict-EARS requirements canon replaces the old one and every later increment cites its rows; the test suite runs reliably in parallel with the timing arms run apart; change and check documents resolve `symbol` entries instead of refusing them; the CRC Designer and Check Editor stay correct after every write and responsive on the 10 MB demo image; reports write full hex windows and escape hostile names; flow and chain-set saves are contained inside the work area; A2L parsing recognises the ASAM block names; dead surfaces are removed and Escape closes the Reports viewer; and the help, legend, README and developer documents describe the app as shipped.
- **Business outcome:** v1.0.0 is releasable on its non-UI defects. Sixteen increments (18 packets with the 10 and 12 split into a/b) shipped through the design-first pipeline, closed with 0 blocker / 0 high findings, and the batch-end battery on the final tree found **no new product defect** — the six failures are the four long-known failures plus two load flakes that pass alone.
- **What users will notice:** symbols load instead of refusing; the CRC coverage is always the image they just wrote; reports are complete and never corrupt a name; a flow/chain-set save never writes a byte through a link or outside the work area; hex jumps show their target, unload clears stale state, and focus never lands in a hidden window; A2L files no longer raise "unrecognized block" noise; Escape closes Reports; and the help, legend, README and user guide match the shipped app.
- **Next step:** the operator approves the `06-docs/` documents, then commits, pushes and runs `/dev-flow-sync`; the `v1.0.0` tag is the operator's act (approved in advance, below).

---

## Context (reference)

### Context

s19_app is the terminal tool (TUI) a calibration engineer uses to prepare and review software changes for ECUs. It reads and writes memory images (S19 and Intel HEX), tracks A2L calibration tags and MAC records, and organises that work into projects. Batch-100 fixed how the engineer loads and saves projects. This batch is the release-hardening pass that makes v1.0.0 shippable: it closes the user-guide findings that block a release (F-01 … F-51), the five UX majors of batch-100's expert inspection, the Save project margin (R1-P1), the in-app help and README text that described absent features, batch-100's deferred post-close CI confirmation, and the serial marking of timing-bound tests. It started on 2026-11-01 and reached its close on 2026-11-07 (`PLAN.md` §Header).

### Problem

The release could not ship as it stood:

- **The requirement base was a patchwork.** Requirements lived in many files and the canon was not one strict-EARS sentence per row with a stable id, so a requirement could not be tested on its own and traced to its tests (US-101.1).
- **The gate had false timing failures.** Thirteen timing-bound arms failed under 8-way parallel load for reasons of the host, not the product (G-015; the R1-P1 family).
- **Documents refused symbols.** A change or check document with a `symbol` entry failed to load instead of resolving it through the loaded A2L (F-01).
- **Stale views after a write.** The CRC Designer's coverage and the hex panes did not follow bytes written by an apply, a save-back or a Save project (F-23, F-24, F-26, F-27).
- **Reports dropped data and mangled names.** Written before/after and diff reports clipped hex windows and let hostile names through Markdown (F-42, F6-1, D14-10).
- **Saves escaped the work area.** A flow or chain-set save could write through a link or land outside the work area (D15-18).
- **A2L noise.** Valid A2L files raised "unrecognized block" and the Issues screen was mis-ordered (F-02, F-03, F-21, F-29, F-39).
- **Dead surfaces and wrong docs.** Unreachable dialogs, actions and hidden widgets stayed in the tree, and the help, legend, README and developer docs described features the app did not have (F-16, F-30, F-33, F-34, F-35, F-37, F-38, F-41, F-51).

### Solution

What shipped, in plain terms (55 user stories across 16 increments):

- **One requirements canon.** `REQUIREMENTS.md` holds one strict-EARS sentence per row with a stable id, grouped under modules S0 … S17; the old canon is kept in `docs/requirements/history/` (US-101.1).
- **A gate without false failures.** The `serial_timing` marker runs the timing arms apart and serially; QC-TM reports every margin, QC-OR reads every painted line, QC-BC re-runs every node that asserts a changed observable; CI runs the same two lanes (US-TST-1 … US-TST-5).
- **Documents resolve symbols** through the loaded/project A2L, and a variant run uses the project's A2L (US-SYM-1 … US-SYM-3).
- **The CRC Designer and Check Editor follow the bytes.** Coverage recomputes after every in-place write; included parameters survive a Write; a spec comes back as written (US-CRC-FRESH-2, US-CHK-KEEP-1, US-CHK-SPEC-1).
- **The Patch Editor keeps its lifecycle** — the before/after offer only with a project, project-home writes, and a Checks tab that shows the current run (US-PE-LIFE-1 … US-PE-LIFE-4).
- **Reports are complete and inert** — full hex windows, escaped names, atomic writes, and provenance (US-BAR-1, US-HEXWIN-1, US-MDESC-1).
- **The Flow CRC block and external steps** read designer templates and this run's outputs, with the CRC model supporting reverse (US-I8-1 … US-I8-4).
- **Flow saves are named and contained** — a confirm re-run says so, a saved flow keeps its own name, and saves stay in the work area (US-I9-1 … US-I9-3).
- **Hex navigation, unload and focus** work — a jump shows its target, unload clears stale state, focus never lands in a hidden window, and views follow in-place writes (US-HEXNAV-1, US-UNLOAD-1, US-FOCUS-2, US-FRESH-3).
- **A2L parsing is quiet and ordered** — the ASAM block names parse, each issue sits under its own severity with errors first, and MEMORY_SEGMENT records read (US-I11-1 … US-I11-4).
- **Dead surfaces are gone and Escape closes Reports** (US-I12-1 … US-I12-3, US-I12b-1).
- **The CRC Designer and Split/Join stay responsive at 10 MB** (US-CRC-RESP-1, US-CRC-FRESH-1, US-SEG-RESP-1).
- **The docs describe the shipped app** — help, legend, README, SECURITY.md, the 1.0.0 release notes and the user guide (US-HELP-1, US-LEGEND-1, US-README-1, US-SEC-1, US-REL-1, US-GUIDE-1), plus documentation hygiene (US-DOC-HYG-1 … US-DOC-HYG-3) and the Windows-only test fixes (US-TST-15, US-TST-16).

### Outcomes / results

The status of each claim is in brackets.

- **Requirements verified [executed per packet, fixed at the batch-end battery].** The batch touches **273 canon rows** (234 new, 29 changed, 8 withdrawn, 2 brought in) across **55 user stories**; every increment closed with 0 blocker / 0 high open. The per-requirement tables live in each `inc-*/04-validation.md`; the batch-level roll-up is `04-validation.md` Layer 0.
- **Full-suite gate [executed, Linux, final tree].** The batch-end battery on `b982846`: lane 1 `6 failed / 6113 passed / 182 skipped / 4 xfailed` in 3540 s; lane 2 `69 passed / 2 skipped` with **QC-TM 95 bounds, 0 under 20 % margin**; combined `exit=0`. The 6 are 4 known failures plus 2 `test_tc_b100_53` load flakes that pass alone 2/2 — **no new product defect**.
- **Sibling batteries [executed, same tree].** Snapshots `31 passed + the 2 known`; doc-pass law guards `196 passed`; Inc 6 Windows arms `82 passed` with node ids; Inc 5 mutant re-run `24/24 killed`.
- **CI [read, every run the same 4 known failures].** `evidence/ci/` holds 14 runs; the final push run `42391147566` = the 4 known failures. The deferred batch-100 post-close CI `41372953464` was read in: `5 failed / 5034 passed` = the 5 batch-100 known failures, 0 new; the snapshot job `success` 29/29.
- **Mutation [executed].** ≈ 600+ mutant rows killed across the 18 packets (each `inc-*/04-validation.md` mutant table).
- **No product defect known open at HIGH.** The three residual visible gaps — BL-I10b-1, BL-I12-5, BL-I12-6 — are backlog rows accepted for 1.0.0 by the operator.

### Next steps

The sources do not record target dates.

1. **Close this batch (now, operator).** Approve the `06-docs/` documents, then commit, push and run `/dev-flow-sync`.
2. **Tag v1.0.0 (operator, approved in advance).** The package version moves `1.0.0rc1` → `1.0.0` (`pyproject.toml`, `s19_app/version.py`) in the close commit.
3. **Fold the canon (the requirements session, not this batch).** `close/FORWARD-requirements-session.md` (273 rows) is the hand-over; `devflow-init --fold-canon` folded 0 and refused the 2 template rows of the batch-level `01-requirements.md`.
4. **Route the open items.** 34 open `▸` `BL-…` rows are appended to `.dev-flow/BACKLOG-CODE.md`, grouped by source increment; the three flagged for the review page are BL-I10b-1, BL-I12-5, BL-I12-6.

## The operator's advance approval of the tag

The operator gave the go-ahead **in advance** for the v1.0.0 tag (2026-11-07), before an extended absence and without reading the review page `close/review-b101.html`. Read as: the v1.0.0 tag is approved, and the open reservations listed on that page — BL-I10b-1, BL-I12-5, BL-I12-6, R-DLG.2 `Partly`, BL-I9-9, BL-I10b-2, BL-I12-1 … BL-I12-3 — are accepted for 1.0.0 and carried in `BACKLOG-CODE.md`. The human review ledger stays at depth `none`: no human has audited the batch's records; the review page remains the instrument for that review after the fact.
