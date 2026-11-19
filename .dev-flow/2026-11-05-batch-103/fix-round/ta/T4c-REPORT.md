# T4c report

unit: T4c
HEAD: 03d3594bcb49c3149bdeb210362a61fba9a55523
start: 2026-11-19 16:05 CST
brief: units2/TA2-common.md + T4c unit brief (frontB/FB-common.md)

| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |
|---|---|---|---|---|---|---|---|
| R-TST-200 | tools/sync_evidence.py + tests/test_sync_evidence.py (25 tests) + tests/test_examples_pilot_gifs.py::test_case_pilot_capture_and_gif | add S0.14 canon row + 26 `Traces:` docstring lines (25 + 1 pilot) | tools/sync_evidence.py:115 `NON_EVIDENCE_NAMES = frozenset()` | tests/test_sync_evidence.py::test_desktop_ini_is_never_counted_as_evidence | `assert counts["non_evidence"] == 1` -> `E assert 0 == 1` (tests/test_sync_evidence.py:288 AssertionError) | 25 passed (test_sync_evidence.py) + 1 passed (pilot [case_01_basic_valid]) | no |
| R-TST-201 | tools/address_origin.py + tests/test_address_origin.py (2 tests) | add S0.14 canon row + 2 `Traces:` docstring lines | tools/address_origin.py:110 `return f"{what} in {self.file}"` | tests/test_address_origin.py::test_evidence_is_a_location_a_reader_can_open | `E AssertionError: assert 'assign->concat in t/f.py' == 'assign->concat at t/f.py:12'` (tests/test_address_origin.py:411 AssertionError) | 2 passed | no |
| R-TST-202 | tests/fixtures/synth/generate.py + tests/test_b99_corpus.py (3 tests) | add S0.14 canon row + 3 `Traces:` docstring lines | tests/fixtures/synth/generate.py:45 `rng = random.Random()` | tests/test_b99_corpus.py::test_tc_b99_01_deterministic | `assert differing == []` -> `E AssertionError: assert ['manifest.js...seg.hex', ...] == []` (tests/test_b99_corpus.py:102 AssertionError) | 3 passed | no |
| R-TST-203 | tests/conftest.py:1290-1327 (A-16) + tests/test_report_field_census.py::test_a16_canonicaliser_residue_guard_can_actually_fire + tests/test_tui_map_big.py::test_b77_gapless_fixture_is_unequal_and_gapless | add S0.14 canon row + 2 `Traces:` docstring lines | tests/conftest.py:1317 `for pattern in ():` | tests/test_report_field_census.py::test_a16_canonicaliser_residue_guard_can_actually_fire | `E Failed: DID NOT RAISE <class 'AssertionError'>` (tests/test_report_field_census.py:895 Failed) | 2 passed | no |

## Deviations

1. **Tool regression count**: the brief says `pytest -q ../in/test_apply_recite.py` -> 19 passed ("the 19 `def test_` of the repo file at 2a8ab75f"). The staged file collects **11** tests, not 19. The file holds 19 `^def test_` lines, but 8 of them (`test_replace_doc`, `test_replace_comment`, `test_add_case_a/b/c/d`, `test_string_literal`, `test_case_id`) live inside the module-level `TEST_F = '''…'''` string literal and are not collected. Real run: `11 passed in 0.51s`, 0 failures. Evidence:
   - `pytest --collect-only` lists 11 (`test_t1_…` .. `test_t11_…`).
   - `ast` walk of the file finds 11 `FunctionDef` nodes named `test_*`.
   - The `../in` copy is byte-identical to the repo's `.dev-flow/2026-11-05-batch-103/fix-round/ta/test_apply_recite.py` (diff empty).
   The regression itself is GREEN (11/11); only the brief's stated count is off.

2. **reverse_trace before K/K? split vs the PC base**: TA2-common gives the 2a8ab75f base as `{'K': 3293, 'K?': 621, 'S': 1215, 'O': 1560, 'X': 268, 'U': 2}`. Measured here at 03d3594b: `tests: 6959 {'O': 1560, 'K?': 620, 'S': 1215, 'K': 3294, 'X': 268, 'U': 2}` — one test sits in K instead of K? (total 6959, and X/U identical). Consistent with the one-commit G9 delta between the two base shas; the unit's X/U target is unaffected.

## Open questions

None.

## Final

git diff --stat:
```
 REQUIREMENTS.md                   |  9 +++++
 tests/test_address_origin.py      |  7 +++-
 tests/test_b99_corpus.py          | 15 ++++++--
 tests/test_examples_pilot_gifs.py |  5 ++-
 tests/test_report_field_census.py |  2 +
 tests/test_sync_evidence.py       | 78 +++++++++++++++++++++++++++++++++------
 tests/test_tui_map_big.py         |  2 +
 7 files changed, 102 insertions(+), 16 deletions(-)
```

CR bytes in diff: `git diff | grep -c $'\r'` = 0.

Final run of the unit's files:
- `pytest -q -n 4 tests/test_sync_evidence.py` -> `25 passed in 2.70s`
- `pytest -q <2 + 3 + 1 + 1 single nodes + 1 pilot node>` -> `8 passed in 8.63s`

N0 (collect-only) unchanged: before `9827 tests collected`, after `9827 tests collected`.
reverse_trace before: `tests: 6959 {'O': 1560, 'K?': 620, 'S': 1215, 'K': 3294, 'X': 268, 'U': 2}`
reverse_trace after: `tests: 6959 {'O': 1560, 'K?': 625, 'S': 1215, 'K': 3322, 'U': 1, 'X': 236}` (X 236, U 1; none of the 33 traced tests in X or U — all 33 in class K or K?).

UNIT_DONE T4c
