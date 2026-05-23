# Executive summary — `s19_app` audit, batch 2026-05-05-batch-01

**Date:** 2026-05-07
**Audience:** non-technical stakeholders (project lead, partner, manager)
**Detail artefacts:** `.dev-flow/05-postmortem.md`, `.dev-flow/04-validation.md`, `.dev-flow/02-review.md` §Deferrals, `.dev-flow/03-increments/increment-009.md`

---

## 1. Context

`s19_app` is an internal tool for inspecting and validating automotive memory artefacts (S-record / Intel HEX firmware images, A2L calibration descriptions, MAC tag tables) through a CLI and a Textual TUI. The tool already had a written specification (`REQUIREMENTS.md`, ~41 `R-*` rows), but coverage was uneven and several product behaviours had never been independently confirmed end-to-end. We ran a structured audit before extending the codebase, to confirm what is actually correct and to surface what is not.

## 2. Problem

Pre-audit, `REQUIREMENTS.md` mixed `Automated` rows with rows still marked `Manual` or `Partial`, several severity and validation rules were documented in prose only, and the workspace I/O surface had not been independently security-reviewed. The risk: silent regressions when the codebase is extended next, and unverified contract claims being relied on by downstream work.

## 3. Solution

We applied GRNDIA's V-model dev-flow (`/dev-flow-en`) over 16 iterations across five phases. Phases 1 and 2 (requirements + cross-agent review) were run in parallel by the `architect`, `qa-reviewer`, and `security-reviewer` agents. Phase 3 was executed by `software-dev` sequentially across nine supervised increments (≤5 files each, gated review packet after each one). Phase 4 (validation) was driven by `qa-reviewer`. Every Phase 3 increment closed with the mandatory 7-section review packet.

| Phase | Iterations | Key result |
|---|---|---|
| 1 — Requirements | 3 | 6 user stories, 9 HLRs, 19 LLRs, 60 test cases |
| 2 — Cross-agent review | 2 | 2 security blockers + 16 majors found, all closed inline |
| 3 — Implementation | 9 increments | +86 net tests, 9 inspection matrices, 18 audit findings raised |
| 4 — Validation | 1 | 49 pass / 11 gap / 0 fail; verdict = pass-with-known-gaps |
| 5 — Post-mortem | 1 | 5 follow-up batches scoped (B-2A through B-2E) |

## 4. Outcomes

- **17 requirements promoted** to automated coverage, plus **9 inspection-method audit matrices** linking every emitted validation code back to a rule and test.
- **Two security blockers closed inline** during the audit: write-path containment and symlink/junction rejection in `workspace.copy_into_workarea` (256 MB cap added).
- **No unexpected test failures**; 3 documented `xfail` rows each carrying a finding ID, so any future product fix surfaces automatically as `xpass`.
- **18 open findings, every one with a documented closure plan** (3 major, 15 minor or doc-only). Zero blocker-severity findings open at gate.

| Metric | Pre-audit | Post-audit |
|---|---|---|
| Passing tests | 173 | **259** |
| Unexpected failures | n/a | **0** |
| Security blockers closed inline | — | **2** (S-001, S-002) |
| Requirements promoted to `Automated` | baseline | **+17** |
| Open findings (with closure plan) | unknown | **18** (3 major / 15 minor) |

Detail: `.dev-flow/04-validation.md` §1–§4, `.dev-flow/05-postmortem.md` §2.A.

## 5. What's next

Five follow-up batches are scoped and ready, derived from the open-findings register — **no new requirements invented**. We recommend executing **B-2A first**: it clears the largest cluster of findings (engine completeness, including the three `xfail` rows) and is well-bounded.

| Batch | Closes | Owner | Estimate | Priority |
|---|---|---|---|---|
| B-2A — Engine completeness | F-7.2-01, F-7.2-02, F-7.7-07, F-9.07-01, F-9.03-01, F-9.03-02, F-9.09-01 | software-dev | 5–6 increments | high |
| B-2B — Workspace hardening | F-7.7-02, -03, -04, -05, -06 | software-dev | 2–3 increments | high |
| B-2C — Service-layer symmetry | F-9.04-01, -02, -03 | software-dev | 1–2 increments | medium |
| B-2D — REQUIREMENTS.md numbering | F-9.01-01, F-9.02-01..03 | docs-writer | 1 increment | medium |
| B-2E — Demo evidence + drift | TC-032 packs, TC-047 Windows stdout, 5 R-* `promote`, 2 `drift` | docs-writer + Javier | ~1 hour manual | medium |

Detail: `.dev-flow/05-postmortem.md` §3.

## 6. Risk and confidence

- **Confidence is high.** No unexpected test failures across 16 iterations, two security blockers closed *inside* the batch rather than deferred, and every open finding carries either a deferral entry in `02-review.md` §Deferrals or a §10 closure path in `increment-009.md`.
- **Residual risk is bounded and non-code.** The 11 Phase 4 gaps are demo-screenshot capture (9 packs under TC-032) and a Windows-host stdout re-attach for TC-047. Total estimated effort: ~1 hour of manual work; none gate further development.
- **One open finding to flag explicitly: F-7.7-07** — a silent data-correctness bug in `validate_characteristic` (wrong tag's enrichment is returned when the tag is not first in merge order). One-line product fix, queued as the first item of B-2A. Low blast radius but worth naming because it is the only open finding that affects the public API's correctness rather than its surface or coverage.
