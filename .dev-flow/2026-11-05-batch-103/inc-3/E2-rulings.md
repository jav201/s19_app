# Inc 3 — orchestrator rulings on the E2 graph (2026-11-06T18:35:34-06:00, Opus 5.5)

| Item | Ruling | Consequence |
|---|---|---|
| P-2 `AxisDefinition.count_datatype` (defaulted) | **accepted** | I-2 extension gains the field. |
| E2-1 (refusal order: R-A2L-DEF.81/4) | **accepted** | The MEASUREMENT datatype check moves right after MATRIX_DIM; the row's case passes as written. The correction pass records the order in the requirement's notes. |
| E2-3, E2-10 (two extra nodes, changed signatures) | **to E3** | Reviewers judge them. |
| E2-6 (DEFC VAL_BLK LINEAR 0.05) | **accepted** | |
| E2-7 (fail-closed choices where no row applies, 1 MiB record cap) | **to E3** | Each needs a row or removal; reuse Inc 2's .7.2 span rule where it applies. |
| E2-8 (one-line IF_DATA never closes) | **backlog BL-I3-11** | Frozen `a2l.py`. |
| **Rebase on Inc 2's E3 corrections** | **required before Inc 3's E3** | This graph was written against Inc 2's round-1 graph. Inc 2's E3 round 1 changed I-2 (`describe_definitions` over one walk, `Definition` carries the method record, fail-closed mask, span bound, no-raise guards, precision rule, U+FFFD; `inc-2/E3-rulings.md`). After Inc 2's round 2 passes, a targeted pass aligns this graph's 4 changed nodes and every example that depends on them; then Inc 3's E3 runs. |
