# E4R — validation record (batch close, 2026-11-20)

Batch `2026-11-18-a2l-load-performance`, E4R round, closed on the merge tree (Front A on Front B `b103-fix-round`). Orchestrator Opus 5.5 (relevo-29).

## Evidence
- Batch-end full suite and its serial triage: `../evidence/close-suite-2026-11-20.md`.
- Unit checks (scripted, MD-11): `checks/check-FA-MB.md`, `checks/check-FA-D11c.md`, `checks/check-FA-RTFIX.md`, `checks/check-FA-PRIV.md`, `checks/check-FA-FIX1.md`, and the earlier units' checks in `checks/`.
- Reverse trace of the merge tree: `checks/RT-merge-78f61c42.md`.
- Laptop measurements behind the final load bounds: the M2 report recorded in `RECORD.md` (FA-D1, FA-REQ2 rows).

## Verification against the requirements
| Requirement group | Verified by | Result |
|---|---|---|
| R-A2L-REFRESH.033/.034/.037/.049–.054, R-A2L-DEF.162–.168 (E4R rows) | the case lines of `02-test-cases.md` | timing arms in the serial shard; heavy `slow and serial_timing` arms included; no E4R node in the failing set |
| R-A2L-REFRESH.040–.042 (final per-route load bounds, FA-REQ2) | `tests/test_alp_inc3_load_responsiveness.py` | PASS in the serial shard |
| R-A2L-REFRESH.050 (UI tick ≤ 100 ms) | the `.050/1–18` cases | PASS in the serial shard |
| R-TST-011/019/026 (CI lanes, `tui-ci-heavy`) | `tests/test_suite_hygiene.py` | PASS; the real CI duration of `tui-ci-heavy` is known only after the push |
| Six repository laws | `test_suite_hygiene`, `test_requirements_canon`, `test_id_registry`, `test_address_census`, `test_import_census`, `test_no_private_tokens` | 116 passed, 0 failed |

## Trace
`trace_check` (base 6eccf0cb, Front A's own delta): 0 CASE and 0 SLICE gaps after FA-RTFIX; this record closes EVID.

## Open at close
Listed in `RECORD.md` and the close page: the 8 snapshot cells kept `xfail(strict=False)` until a canonical regen on `main`; 7 id-registry guards without a canon row; the load-sensitive nodes above (visible, not excused).
