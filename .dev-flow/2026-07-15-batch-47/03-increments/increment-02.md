# Increment 02 — US-WS data layer (LLR-066.5 / MN-6)

> Batch-47 (screen-upgrades Batch A). Data-layer only: two derived `LoadedFile`
> fields + their population in `load_service` + RED-first unit tests. NO render,
> NO snapshot drift. LLR-066.7 (app.py merge-carry) is deferred to Inc-3.

## 1. What changed
- Added two DEFAULTED derived fields to the `LoadedFile` dataclass, appended
  after `entropy_windows` (MN-6 — defaulting keeps ~40 test constructors +
  `crc.py` / `placeholders.py` compiling unchanged; no frozen test file
  constructs `LoadedFile`, so C-27 stays 0-diff):
  - `out_of_order_count: int = 0`
  - `entry_point: Optional[int] = None`
- Populated both at each `load_service` construction site:
  - `build_loaded_s19`: `out_of_order_count = len(s19.get_out_of_order_records())`;
    `entry_point` = address of the FIRST record whose `.type` ∈ `{S7,S8,S9}`
    (via `next(...)`), else `None`. Both are frozen-API READS only.
  - `build_loaded_hex`: `out_of_order_count = 0` and `entry_point = None`
    (Intel-HEX has no S-record ordering; discards type 03/05 start records,
    hexfile.py:135-137). Commented at the site.
- Docstrings updated (Args on `LoadedFile`; Data Flow + Dependencies on
  `build_loaded_s19`; body note on `build_loaded_hex`).
- NEW non-frozen test file `tests/test_tui_workspace_insight.py` realizing the
  derived-field TCs.

## 2. Files modified (3, within cap)
1. `s19_app/tui/models.py` — +8 lines (2 fields + 2 Args docstring entries).
2. `s19_app/tui/services/load_service.py` — +23/-3 (populate + docstrings).
3. `tests/test_tui_workspace_insight.py` — NEW (non-frozen).

## 3. How to test
```
python -m pytest -q tests/test_tui_workspace_insight.py
ruff check s19_app/tui/models.py s19_app/tui/services/load_service.py tests/test_tui_workspace_insight.py
# C-27 dual-guard
python -m pytest -q tests/test_engine_unchanged.py \
  "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" \
  "tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main"
```

## 4. Test results (real output)
- **RED (before implement):** `4 failed in 0.41s` —
  `AttributeError: 'LoadedFile' object has no attribute 'out_of_order_count'`.
- **GREEN (after implement):** `4 passed in 0.22s`.
  - TC-066.1 `test_ooo_count_populated` — prg.s19 == 4, case_01 == 0.
  - TC-066.2 `test_entry_point_s19` — case_01 == 0x80000000 (S7); prg == 0x0 (present-not-None).
  - TC-066.3 `test_entry_point_hex_none` (MN-9) — inline `IntelHexFile` → entry_point is None, OOO == 0.
  - MN-6 `test_fields_default_on_bare_construction` — bare `LoadedFile()` → 0 / None.
- **ruff:** `All checks passed!` (3 files).
- **C-27 dual-guard:** `3 passed in 0.33s` (0 frozen src/test diff vs main).
- **MN-6 blast-radius regression** (all non-frozen `LoadedFile(` constructors +
  `load_service` callers): 12 files + `test_tui_app.py`:
  - `test_tui_services / test_compare_service / test_validation_service_supplemental /
    test_tui_commandbar / test_filename_markup_safety / test_workspace_variants /
    test_tui_search_pagination / test_tui_operations_view / test_tui_goto_marker /
    test_before_after_report / test_examples_smoke / test_flow_execution /
    test_changes_apply` → **161 passed**.
  - `test_tui_app.py` → **61 passed, 1 xfailed** (pre-existing xfail).
  - **Total: 222 passed, 1 pre-existing xfail, 0 new failures.**

## 5. Risks
- Fixture-fact coupling: assertions hard-code prg.s19 OOO==4 and case_01
  entry==0x80000000; verified live this session against the real fixtures.
- `entry_point == 0x0` (prg.s19 S9) is PRESENT-but-zero, distinct from `None`
  (HEX absent). The data layer preserves the distinction; the render `—` vs
  `0x00000000` mapping is Inc-3's responsibility (AT-066b/066c).
- The two new fields flow through the field-copy MAC-merge / primary-reload
  paths in app.py; without LLR-066.7 they would re-default on merge. That is
  the EXPLICIT scope of Inc-3 (AT-066d), not a regression introduced here.

## 6. Pending items (NOT this increment)
- LLR-066.7 — carry `out_of_order_count`/`entry_point` forward in
  `_merge_mac_with_existing_primary` (app.py:6997) + primary-reload merge
  (app.py:6954). Inc-3.
- LLR-066.4 render of `Loader N err · ⚠K OOO · Entry 0x…` in `#ws_stats`; the
  `0x0`→`0x00000000` vs HEX `—` render mapping (AT-066a..c). Inc-3.

## 7. Suggested next task
Inc-3 (US-WS render): wire `#ws_stats` loader-facts line + memstrip entropy
bands, and implement LLR-066.7 merge-carry, then land AT-066a..d + AT-067 via
`App.run_test`. Snapshot drift regen stays canonical-CI-only.

---

## Evidence checklist
- [x] Tests/type checks/lint pass — `4 passed`; ruff `All checks passed!`; C-27 `3 passed`.
- [x] No secrets in code or output — data-layer fields + public examples/ fixtures only.
- [x] No destructive commands run without approval — read/edit/pytest only.
- [x] File count within cap — 3 files (models.py, load_service.py, new test).
- [x] Review packet attached — this file.
- [x] RED→GREEN captured — RED `4 failed` (AttributeError) → GREEN `4 passed`.
- [x] C-27 dual-guard 0-diff — `test_engine_unchanged` + `test_tc031` + `test_tc032` pass.
- [x] MN-6 blast-radius — 222 passed / 1 pre-existing xfail / 0 new failures across all `LoadedFile(` constructors.

### Gate outcome (orchestrator, 2026-07-15)
- **Independent code-review:** APPROVE-WITH-NIT, 0 HIGH / 0 MEDIUM. RED→GREEN + C-27 0-diff + MN-6 blast-radius all independently reproduced (4 passed / 3 guard / 26-slice). entry_point scan semantics confirmed correct (single terminator, `.address` = parsed start addr). LOW nit F1 (HEX-None test comment implied a derivation the hard-set doesn't perform) — **APPLIED** (comment clarified: pins the constant + proves non-crash on a type-03 record; re-verified 4 passed).
- **Gate axis check:** Coverage OK (LLR-066.5 + TC-066.1/066.2/066.3 + MN-6 default proof, grep-confirmed); Certainty OK (present-but-zero `0x0` separated from absent `None`; non-tautological fixture values); Evidence OK (RED→GREEN + C-27 + blast-radius reproduced). **APPROVE.** → Inc-3 (US-WS render + LLR-066.7 merge-carry).
