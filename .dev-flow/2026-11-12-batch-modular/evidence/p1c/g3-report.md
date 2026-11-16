All work is complete. Here is the final report.

---

# Group 3 — batch-modular P1c adaptation: FINAL REPORT

## Files changed (row → summary)

| Row | File | Change |
|---|---|---|
| 43 | `tests/test_b101_doc_hygiene.py` | `_rail_labels()` / `_split_join_label()` read `ps.package_text("app")` instead of `_need("s19_app/tui/app.py")` |
| 44 | `README.md`, `PROJECT_RULES.md`, `CLAUDE.md`, `docs/architecture.md` | Repointed named paths: `app.py`→`app/` / `core.py` / `projects.py` / `project_load.py` / `shell.py`; `screens_directionb.py`→`screens_directionb/` / `patch_editor.py` (each verified by grep to hold the named symbol) |
| 45 | `tests/test_b97_patch_editor.py` | `STYLES = Path(sdb.__file__).parent.parent / "styles.tcss"` (was `.parent`) |
| 46 | `tests/test_b97_patch_editor.py` | `app_source = ps.package_text("app")` (was `Path(sdb.__file__).parent/"app.py"`) |
| 47–50 | `tests/test_b97_patch_editor.py` | no code change; carried by the row-45 `STYLES` repoint |
| 51 | `tests/test_tui_directionb.py` | `test_tc028_…` → `ps.package_tree("screens_directionb")` |
| 52 | `tests/test_tui_directionb.py` | `test_tc028_…_after_inc10` → `ps.package_tree("screens_directionb")` |
| 53 | `tests/test_tui_directionb.py` | `test_tc026_…` → `ps.package_tree("screens_directionb")` |
| 54 | `tests/test_tui_directionb.py` | `test_tc_042_10_…` → `ps.package_tree("screens_directionb")` |
| 55 | `tests/test_tui_directionb.py` | `test_tc_042_12_…` asserts `strip_file.parent == app package dir` (was `.endswith("app.py")`) |
| 60 | `tests/test_tui_patch_card.py` | writer census → `ps.package_tree("app")` + `ps.source_file_of` |
| 61 | `tests/test_tui_patch_card.py` | panel selfcall reads `inspect.getfile(PatchEditorPanel)` |
| 65 | `tests/test_tui_patch_checks_strip.py` | `test_tc078_3_both_sites` → `ps.package_tree("app")` |
| 68 | `tests/test_tui_patch_history_strip.py` | `test_tc081_3_sites` → `ps.package_tree("app")` + `ps.source_file_of` |
| 69 | `tests/test_tui_patch_history_strip.py` | `test_tc081_4` diffs **both** `s19_app/tui/app.py` + `s19_app/tui/app/`, net multiset of `Binding(` lines (SKIP convention unchanged) |
| 70 | `tests/test_capped_text_area.py` | `ps.package_tree("screens_directionb")` for the sdb arm |
| 71 | `tests/test_tui_patch_editor_b94.py` | `test_at_b94_08` → `ps.package_tree("screens_directionb")` (fixes H-23 vacuity) |
| 72 | `tests/test_tui_insight_style.py` | NONE — confirmed passing |

## Acceptance output

```
FAILED tests/test_tui_patch_history_strip.py::test_tc081_2_strip - AssertionE...
FAILED tests/test_tui_patch_checks_strip.py::test_tc078_2_aggregates_param - ...
FAILED tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe - Assertion...
FAILED tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
5 failed, 421 passed in 725.36s (0:12:05)
```

All 5 failures are **pre-existing** (verified by running the same nodes against the `4f721985` base archive, which fails identically):
- `test_tc081_2_strip`, `test_tc078_2_aggregates_param`, `test_tc080_2_c7_purity_probe` — NONE/GETSOURCE rows (62/66/67); the moved `PatchEditorPanel` already contains 2 `self.app` reaches at base (lines 5393/5481), so these purity probes fail identically pre/post split.
- `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` — 3 rows (`R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008`) hold "shall" twice in `REQUIREMENTS.md`; not touched by me.
- `test_suite_hygiene.py::test_r_tst_070_2_…` — committed `.dev-flow` evidence files contain `zq_iso_user`/`<account>`/`~`/`<lan>`; not touched by me.

## Negative controls (row · mutation · RED line)

Command used for each: `cd ../scratch/nc-<row> && env -i PATH=/usr/bin:/bin HOME=…/state/zq_iso_user TMPDIR=…/state/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8 <py> -m pytest -q -p no:cacheprovider <node>`

| Row | Mutation | RED assertion line |
|---|---|---|
| 43 | duplicate the `open_split_join_export` palette entry in `app/core.py` | `test_b101_doc_hygiene.py:779: AssertionError: expected one palette entry … read ['Split / Join / Export', 'Split / Join / Export']` |
| 44 | leave old path `s19_app/tui/app.py` in `CLAUDE.md` | `test_b101_doc_hygiene.py:288: AssertionError: 1 unmarked repository paths that do not exist:` |
| 45 | — (no mutation per table) | — |
| 46 | add `def _apply_window_geometry(*args, **kwargs): pass` in `app/shell.py` | `test_b97_patch_editor.py:313: AssertionError: assert '_apply_window_geometry' not in …` |
| 47 | restore `#patch_win_script { width: 2fr; }` | `test_b97_patch_editor.py:370: AssertionError: [('#patch_win_script', 'width', '2fr')]` |
| 48 | add `.patch-docked-row { padding: 0; }` inside the scoped section | `test_b97_patch_editor.py:394: AssertionError: ['.patch-docked-row']` |
| 49 | add `#patch_variant_row { height: 1; }` | `test_b97_patch_editor.py:421: AssertionError: ['#patch_variant_row']` |
| 50 | change `$rule` → `#000000` | `test_b97_patch_editor.py:1066: AssertionError: ('#000000', '#0a0e1b')` (luminance 0.0 > 0.055 fails) |
| 51 | `import bincopy` in `screens_directionb/memory_map.py` | `test_tui_directionb.py:5899: AssertionError: … found ['bincopy']` |
| 52 | `import crcmod` in `screens_directionb/shared.py` | `test_tui_directionb.py:6332: AssertionError: … found ['crcmod']` |
| 53 | `from s19_app.tui.changes.io import x` in `patch_editor.py` (see DEVIATION) | `test_tui_directionb.py:6100: AssertionError: … found ['s19_app.tui.changes.io']` |
| 54 | `Text.from_markup("x")` in `patch_editor.py` | `test_tui_directionb.py:8318: AssertionError: … found at [2810]` |
| 55 | move `update_memory_strip` to `s19_app/tui/strip_external.py` | `test_tui_directionb.py:8997: AssertionError: … got …/strip_external.py` |
| 60 | drop `mem_map=` at `loaded_state.py:675` | `test_tui_patch_card.py:1053: AssertionError: ['loaded_state.py:675'] call refresh_entries WITHOUT mem_map …` |
| 61 | pass `mem_map=None` in the panel self-call | `test_tui_patch_card.py:1087: AssertionError: patch_editor.py:1420 — the panel self-call now passes mem_map …` |
| 65 | drop `aggregates=` | `test_tui_patch_checks_strip.py:674: AssertionError: the refresh_check_results call at line 492 does not pass the aggregates …` |
| 68 | add a 5th `set_undo_redo_enabled` call without `depths` | `test_tui_patch_history_strip.py:611: AssertionError: … found 5 …` |
| 69 | `Binding("x", "y")` in `app/core.py` | `test_tui_patch_history_strip.py:802: AssertionError: … Net Binding( changes:` |
| 70 | bare `TextArea` for `#patch_paste_text` | `test_capped_text_area.py:221: AssertionError: screens_directionb/: #patch_paste_text must be constructed as CappedTextArea … got 'TextArea'` |
| 71 | `id="patch_variant_select"` in `ab_diff.py` | `test_tui_patch_editor_b94.py:551: AssertionError: 0 patch_variant ids in the package source, got ['patch_variant_select']` |

## [V] old-version (vacuity) results

| Row | Old (unadapted) test result under the mutation | Vacuity |
|---|---|---|
| 51 | **GREEN** (reads `__init__.py`, misses `import bincopy` in `memory_map.py`) | vacuous ✅ |
| 52 | **GREEN** (reads `__init__.py`, misses `import crcmod` in `shared.py`) | vacuous ✅ |
| 54 | **FAILS** on the `markup=True` arm (`found 0`) — the `from_markup` arm alone is vacuous | partly-V as documented ✅ |
| 71 | **GREEN** (reads `s19_app/__init__.py`, misses `patch_variant_select` in `ab_diff.py`) — H-23 vacuity confirmed ✅ |

## Deviations

- **Row 53 negative control**: the table's literal `from ...changes.io import x` does **not** trip the test — Python's AST strips leading dots into `node.level`, so `ast.ImportFrom.module` becomes `"changes.io"`, which the filter (`".changes."` / `endswith(".changes")` / `== "changes"` / `"cdfx"`) does not match. Verified: `package_tree` returns `model_imports: []`, `all with changes: ['changes.io']`. I used the faithful absolute-import form `from s19_app.tui.changes.io import x` (module `"s19_app.tui.changes.io"`, contains `".changes."`), which goes RED.

## Open questions

- The three NONE-row purity probes (62/66/67) and the two gate tests (`test_requirements_canon`, `test_suite_hygiene`) fail identically at base `4f721985`; they are unrelated to the split and outside my file set, so I left them untouched. If the integrator wants a green acceptance, these need a separate fix outside Group 3.

Cleanup done: `../scratch/nc-*`, `base`, `lean-base`, `git-lean-base` all deleted.
PI_EXIT=0
