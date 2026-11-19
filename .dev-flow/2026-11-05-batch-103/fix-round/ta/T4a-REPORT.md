# REPORT — T4a (design-guard rows)

- Unit: T4a
- HEAD sha: 03d3594bcb49c3149bdeb210362a61fba9a55523
- Start: 2026-11-19 15:57:16 CST
- Common files: `frontB/FB-common.md`, `units2/TA2-common.md`
- Unit brief: `T4a — design-guard rows: headless modules, render layering, batch-92 surfaces, docstrings`

## Baseline (step 1)

- Tool regression `pytest -q ../in/test_apply_recite.py`: **11 passed** in 0.48s.
  NOTE: the brief/TA2-common says "19 passed (the 19 `def test_` of the repo file at 2a8ab75f)" but the staged
  file (identical to the repo's `.dev-flow/2026-11-05-batch-103/fix-round/ta/test_apply_recite.py`) holds 11 real
  `def test_` functions at both 2a8ab75f and 03d3594b (the other 9 `def test_` grep hits live inside the `TEST_F`
  string literal). 11/11 GREEN.
- N0 (`--collect-only -q tests`): **9827 tests collected** in 19.07s.
- reverse_trace before: `tests: 6959 {'K': 3294, 'K?': 620, 'S': 1215, 'O': 1560, 'X': 268, 'U': 2}`


## Per-row results

| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |
|---|---|---|---|---|---|---|---|
| R-DOC-ARCH.7 | tests/test_compare_service.py::test_module_imports_no_textual (also test_change_service.py::test_change_service_module_imports_no_textual, test_checks_engine.py::test_no_textual_in_static_import_graph, test_tui_manifest_save.py::test_manifest_writer_module_is_headless) | REQUIREMENTS.md adds R-DOC-ARCH.7; `Traces: R-DOC-ARCH.7.` on 4 headless-import tests | s19_app/tui/services/compare_service.py:28 insert `import textual  # NC` (after :27) | `pytest -q tests/test_compare_service.py::test_module_imports_no_textual` (env line) | `assert not any(name.split(".")[0] == "textual" for name in imported_modules)` -> `E assert not True` at tests/test_compare_service.py:129 | 11/11 nodes pass | |
| R-DOC-ARCH.8 | tests/test_tui_manifest_save.py::test_manifest_writer_module_is_headless | REQUIREMENTS.md adds R-DOC-ARCH.8; `Traces: R-DOC-ARCH.7, R-DOC-ARCH.8.` on the manifest_writer headless test | s19_app/tui/services/manifest_writer.py:45 insert `import logging  # NC` (after :44) | `pytest -q tests/test_tui_manifest_save.py::test_manifest_writer_module_is_headless` (env line) | `assert not stripped.startswith("import logging"), line` -> `AssertionError: import logging  # NC` at tests/test_tui_manifest_save.py:316 | PASS | |
| R-DOC-ARCH.9 | tests/test_render_hexview.py::test_tc651_import_census_all_consumers_read_render_hexview | REQUIREMENTS.md adds R-DOC-ARCH.9; `Traces: R-DOC-ARCH.9, R-DOC-ARCH.10.` on test_tc651 | s19_app/render/format.py:94-95 append `def _nc_probe():` / `    import s19_app.tui.models  # NC` | `pytest -q tests/test_render_hexview.py::test_tc651_import_census_all_consumers_read_render_hexview` (env line) | `AssertionError: format.py imports s19_app.tui.models — render/ must be tui-free` at tests/test_render_hexview.py:202 | PASS | |
| R-DOC-ARCH.10 | tests/test_render_format.py::test_tc655_render_format_values_pinned_to_frozen_origins (also test_tc652, test_tc653, test_tc654) | REQUIREMENTS.md adds R-DOC-ARCH.10; `Traces: R-DOC-ARCH.10.` on 4 batch-92 surface tests | s19_app/render/format.py:20 `CYAN = "#7dd3fc"` -> `CYAN = "#7dd3fd"` | `pytest -q tests/test_render_format.py::test_tc655_render_format_values_pinned_to_frozen_origins` (env line) | `assert render_format.CYAN == "#7dd3fc"` -> `AssertionError: assert '#7dd3fd' == '#7dd3fc'` at tests/test_render_format.py:34 | PASS | |
| R-DOC-DEV.16 | tests/test_tui_helpers.py::test_tui_app_has_docstring (also test_tui_module_has_docstring) | REQUIREMENTS.md adds R-DOC-DEV.16; `Traces: R-DOC-DEV.16.` on 2 docstring tests | s19_app/tui/app/core.py:145 delete the class docstring line `"""Main TUI app ..."""` | `pytest -q tests/test_tui_helpers.py::test_tui_app_has_docstring` (env line) | `assert S19TuiApp.__doc__` -> `E assert None` at tests/test_tui_helpers.py:381 | PASS | |

## Deviations

1. Tool regression count: brief/TA2-common states "19 passed (the 19 `def test_` of the repo file at 2a8ab75f)". The staged `../in/test_apply_recite.py` is byte-identical to the repo's `.dev-flow/2026-11-05-batch-103/fix-round/ta/test_apply_recite.py` at BOTH 2a8ab75f and 03d3594b, and holds 11 real `def test_` functions (the other 9 `def test_` grep hits live inside the `TEST_F` triple-quoted string). Result: **11 passed**. Evidence: `grep -c "def test_" ...` = 20; `ast` count of top-level `test_*` FunctionDef = 11 (test_t1..test_t11).
2. reverse_trace before differs from the TA2-common base by one K/K? classification: brief base `{'K': 3293, 'K?': 621, 'S': 1215, 'O': 1560, 'X': 268, 'U': 2}`; measured `{'K': 3294, 'K?': 620, 'S': 1215, 'O': 1560, 'X': 268, 'U': 2}`. Totals, X and U identical.

## Open questions

- None blocking. The "19 passed" tool-regression figure in the brief does not match the staged file (11 tests); the tool itself passes all its tests and the `--apply` run was clean (stripped-AST unchanged, every file compiles, no stray quotes).

## End (TA2-common)

- reverse_trace after: `tests: 6959 {'K': 3296, 'K?': 629, 'S': 1215, 'O': 1560, 'X': 257, 'U': 2}` (X 268 -> 257, U 2; the 11 traced tests are all K or K?, none in X).
- N0 after: `9827 tests collected` (delta 0 vs N0).
- `git diff --stat`:
```
 REQUIREMENTS.md                 | 15 +++++++++++++++
 tests/test_change_service.py    |  2 ++
 tests/test_checks_engine.py     |  2 ++
 tests/test_compare_service.py   |  1 +
 tests/test_import_census.py     | 10 ++++++++--
 tests/test_render_format.py     |  5 ++++-
 tests/test_render_hexview.py    | 10 ++++++++--
 tests/test_tui_helpers.py       |  2 ++
 tests/test_tui_manifest_save.py |  2 ++
 9 files changed, 44 insertions(+), 5 deletions(-)
```
- CR count (`git diff | grep -c $'\r'`): 0.
- Final run of the unit's 8 files: **97 passed** in 75.84s.

UNIT_DONE T4a
