# Increment 001 — model layer: reason vocabulary + carriage (LLR-051.1/.2, to_dict half of AT-051f)

1. **What changed** — `changes/model.py`: 6-token `CHECK_UNCHECKABLE_REASON_DOMAIN` (doc-kind, doc-fault run-blocking; entry-fault, partial, outside, no-image per-entry); `CheckRunEntry.reason_code/reason` (defaulted None — pass/fail carry no reason, AT-051d model half); `CheckRunResult.run_blocked_reason_code/run_blocked_reason` (None on runnable docs); `to_dict` additive (4 new keys; no-consumer state noted inline per Q2).
2. **Files** — s19_app/tui/changes/model.py, tests/test_checks_engine.py (2 of <=5).
3. **How to test** — `pytest tests/test_checks_engine.py -q`.
4. **Results** — engine 8 passed (7 base + TC-051.1: domain canonical order + uniqueness, defaults None, to_dict additive with the exact pre-batch-33 key set preserved). Consumer suites green unmodified: change_service 21, report_service 33, variant_execution 12. Ruff clean.
5. **Risks** — none; purely additive defaulted fields (slots-safe: defaulted fields appended after existing).
6. **Pending** — Inc-2 engine (per-entry gate + reason assignment + template caps); RED-first AT-050a-d there.
7. **Next** — Inc-2.
