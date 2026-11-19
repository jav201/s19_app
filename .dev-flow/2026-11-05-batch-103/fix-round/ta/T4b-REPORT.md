# T4b — guard tests that verify product modules: issue-list tag source, verify-on-save refusal (DeepSeek v4-pro)

Unit: T4b
Tree: branch `work`, HEAD `03d3594bcb49c3149bdeb210362a61fba9a55523` (brief names 2a8ab75f/03d3594b; this host is on 03d3594b)
Start: 2026-11-19 16:00 CST
Files read: `frontB/FB-common.md`, `units2/TA2-common.md`, unit brief `T4b` (BRIEF.md)

## Baseline
- Tool regression `pytest -q ../in/test_apply_recite.py`: **11 passed** (see Deviations #1 — brief says 19).
- N0 (`--collect-only -q tests`): **9827**.
- reverse_trace before: `tests: 6959 {'O': 1560, 'K?': 620, 'S': 1215, 'K': 3294, 'X': 268, 'U': 2}` (brief base: K 3293 / K? 621; see Deviations #2).

## Rows

| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |
|---|---|---|---|---|---|---|---|
| R-VAL-055 | tests/test_tui_services.py::test_build_validation_report_keeps_explicit_empty_enriched_tags | added `Traces: R-VAL-055.` docstring line (apply_recite ADD); new canon row R-VAL-055 after R-VAL-018 | `tags_for_validation = a2l_enriched_tags or (a2l_data or {}).get("tags", [])` at s19_app/tui/services/validation_service.py:301 | `pytest tests/test_tui_services.py::test_build_validation_report_keeps_explicit_empty_enriched_tags` | `E       AssertionError: assert [{'address': ...name': 'RAW'}] == []` | 3 passed | no |
| R-VAL-056 | tests/test_tui_services.py::test_build_validation_report_falls_back_to_raw_tags_when_enriched_is_none | added `Traces: R-VAL-056.` docstring line (apply_recite ADD); new canon row R-VAL-056 after R-VAL-055 | `tags_for_validation = []` at s19_app/tui/services/validation_service.py:299 | `pytest tests/test_tui_services.py::test_build_validation_report_falls_back_to_raw_tags_when_enriched_is_none` | `E       AssertionError: assert [] == [{'address': ...name': 'RAW'}]` | 3 passed | no |
| R-HEX-VERIFY-001.7 | tests/test_verify_on_save.py::test_unsupported_file_type_raises | added `Traces: R-HEX-VERIFY-001.7.` docstring line (apply_recite ADD); new canon row R-HEX-VERIFY-001.7 after R-HEX-VERIFY-001.6 | `return {}` at s19_app/tui/changes/verify.py:116 | `pytest tests/test_verify_on_save.py::test_unsupported_file_type_raises` | `E       Failed: DID NOT RAISE <class 'ValueError'>` | 3 passed | no |

## Steps log
- Rows 1-3 inserted into REQUIREMENTS.md at :2076/:2077 (after `| R-VAL-018 |`) and :4450 (after `| R-HEX-VERIFY-001.6 |`).
- Lint: `grep -E '^\| (R-VAL-055|R-VAL-056|R-HEX-VERIFY-001\.7) \|'` -> `ok R-VAL-055`, `ok R-VAL-056`, `ok R-HEX-VERIFY-001.7`, `bad: 0`; each id `^| <id> |` count = 1.
- apply_recite dry run then `--apply`: `ADD rows: 3 (applied=3, already=0)`, `files: 2`.
- 3 nodes GREEN: `3 passed in 0.06s`.
- Negative controls: each in `cp -a . ../scratch/nc-<row>` copy, mutated, single node run, copy deleted after. All three went RED as tabled.
- N0 after: **9827** (unchanged).
- reverse_trace after: `tests: 6959 {'O': 1560, 'K?': 621, 'S': 1215, 'K': 3296, 'X': 265, 'U': 2}`.
- None of the 3 tests in class X after: R-VAL-055 -> K, R-VAL-056 -> K, R-HEX-VERIFY-001.7 -> K? (still cites retired LLR-003.1 in its own docstring, "mixed:active+retired").

## Deviations
1. **Tool regression collected 11 tests, not the 19 the brief states.** Evidence: `grep -c '^def test_'` = 19 in both `../in/test_apply_recite.py` and the repo copy `.dev-flow/2026-11-05-batch-103/fix-round/ta/test_apply_recite.py` (md5 `6cd1ce175770c295122d596edbaf6882`, byte-identical at 2a8ab75f and HEAD), but 8 of those 19 `def test_` lines are text inside the `TEST_F` triple-quoted fixture string (e.g. `def test_replace_doc`, `def test_add_case_a`..`d`), not collectable functions. `pytest --collect-only` collects exactly 11 (`test_t1`..`test_t11`); all 11 pass. The functional regression is GREEN (0 failures); the brief's "19" counts fixture text as tests.
2. **reverse_trace base K/K? split differs by one from the brief.** Brief base "K 3293, K? 621"; this host before = "K 3294, K? 620" (X 268, U 2, S 1215, O 1560, tests 6959 all match). HEAD 03d3594b is one commit after 2a8ab75f ("tests: wait for the deferred end_busy line and drive the A2B compare to the typed files (fix round G9)"), re-classifying one test K? -> K. No effect on this unit's 3 tests (all X before, none X after).

## Open questions
- None for the unit's rows. The "19 passed" tool-regression wording in the brief appears to be a miscount of fixture-string `def test_` lines (Deviations #1).

## Final
```
 git diff --stat
  REQUIREMENTS.md              | 3 +++
  tests/test_tui_services.py   | 2 ++
  tests/test_verify_on_save.py | 5 ++++-
  3 files changed, 9 insertions(+), 1 deletion(-)
```
- `git diff | grep -c $'\r'` = **0**.
- Final run of the unit's nodes (all three): **3 passed in 0.06s**.

UNIT_DONE T4b
