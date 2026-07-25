# PLAN — batch-60 · FB-P1b: flow-run report GENERATION (living compendium)

## Where we are
- **Phase 1 done → Phase 2 (review).** Branch `feat/batch-60-fb-p1b-report-gen` off
  `origin/main` `556db0c`. RC-1 PASS (merge-base == tip; already-shipped grep confirms the
  `ReportBlock` no-op is still in place → generation is greenfield).
- **Phase 0 done:** prototype built + operator-APPROVED ("aprobado, arranca autónomo con esos
  defaults"). Artifacts `prototypes/fb_p1b_report.{prototype.py,example.md,NOTES.md}`.

## Objective
Make a flow containing a `ReportBlock` **generate report content**: a pure
`compose_flow_report` over the run state assembled so far in `FlowRunResult`, written into
the project `reports/` dir under the shipped `<ts>-report.md` convention so
`list_project_reports` + `ReportViewerScreen` surface it with **no new viewer**.

## Operator decisions (kickoff, all four OQs resolved)
- **D-1** explicit trigger — report ONLY when a `ReportBlock` is present (not implicit-always).
- **D-2** positional — reports the state UP TO the block (REPORT-last ⇒ whole pipeline).
- **D-3** reuse `<ts>-report.md` (matches `REPORT_FILENAME_REGEX` → shipped viewer).
- **D-4** N report blocks allowed, each writes its own positional report.
- **D-5** the written path surfaces in the panel ledger.
- **D-6** an aborted/empty run still writes a report (honest record).
- **Authorization:** AUTONOMOUS + self-merge, plan+prototype-first **satisfied**. Final qa
  **and** security 0-HIGH over the whole diff before self-merge.
- **Model:** Opus 5 (operator switched the session model mid-batch; the standing rule is
  "specified else inherit the session model").

## Security posture
The report embeds file-derived strings (block summaries, finding messages, written paths,
flow name) and is later rendered in a Markdown widget → the composer is a **new markup
sink**. `_md_safe` neutralises markdown structure + control bytes. This also closes the
**batch-53 qa M-3 carry** (the deferred markup-safety guard now has a concrete home + tests).

## Landing map (provisional)
New `s19_app/tui/services/flow_report_service.py` (Textual-free, C-7): `compose_flow_report`
+ `_md_safe` + `write_flow_report` (imports `report_service._report_filename` — reuse, not
fork). Wire at `flow_execution_service.py:378` (the `ReportBlock` branch; NON-frozen).
Ledger surfacing is the existing `render_result` summary line (likely 0 code change —
verify at Inc-3). **No frozen-engine file.**

## Increment plan (C-21 — each AT owns an increment)
- **Inc-1** — `flow_report_service.py` composer + `_md_safe` + unit/integration tests
  (AT-001 structure, AT-003 markup battery, AT-005 positional-shape at composer level,
  status-rollup + boundary cases).
- **Inc-2** — `write_flow_report` + wire the `run_flow` REPORT branch + tests
  (AT-002 list-consumption C-12, AT-006 no-block-no-report, AT-007 collision, AT-008
  degrade-not-abort, AT-005 end-to-end positional).
- **Inc-3** — panel ledger surfacing (AT-004 pilot, C-32) — code change only if the existing
  summary line does not already carry the path.

## Roadmap
P0 ✓ (prototype approved) → **P1 ✓** → P2 review (security + qa on the spec) → P3 impl
(≤5 files/inc, gate each) → P4 validation (full suite + base differential) → P5 postmortem
→ P6 docs + PR + self-merge → sync/backlog/memory.

## Decision log
- 2026-07-24 P0: kickoff; RC-1 PASS off `556db0c`; autonomy = autonomous+self-merge with
  plan+prototype-first; OQ-1..4 answered by the operator as D-3..D-6; prototype built
  (markup-safety self-check green) and **APPROVED**.
- 2026-07-24 P1: requirements + qa catalog authored (3 US / 3 HLR / 7 LLR / AT-001..008 /
  TC-001..013); all anchors draft-time verified; no open questions carried to P2.

## Test ledger
- base (`556db0c`): non-slow suite = 1917 passed + the known 19 `tc016s` pre-existing fails.
