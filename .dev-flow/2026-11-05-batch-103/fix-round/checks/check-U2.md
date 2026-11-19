# U2 — mechanical check (C2: U2-retire)

- **Unit:** U2-retire
- **Tree path:** `~/work/zq-ta/U2/repo`
- **HEAD sha:** `b5ca5b7277e3a0aa9683e50fdd71ebb578ee7d80` (base `b5ca5b72` + inherited U1 diff + U2 changes, uncommitted)
- **Start time:** 2026-11-19 14:18:46 CST
- **C2 "before" tree:** `~/work/zq-ta/U1/repo` (HEAD b5ca5b72 + U1 diff)
- **Checker:** C-check C2 (DeepSeek); this session did not write U2.

---

## Diff hygiene (CHK-ds step 1)

U1→U2 diff (`diff -ru -x .git U1/repo U2/repo`), saved as `CHECK.diff`:

- **Files changed: 10** — exactly the 10 of the brief (8 test files + registry + doc):
  - `tests/test_tui_helpers.py`, `tests/test_validation_mac.py`, `tests/test_tui_operations_view.py`, `tests/test_diff_report_service.py`, `tests/test_change_service.py`, `tests/test_tui_patch_editor_b94.py`, `tests/test_command_bar_interlock.py`, `tests/test_loadfilescreen_input.py`
  - `AT-TC-REGISTRY.jsonl`, `docs/requirements/review/S10-ears-strict.md`
- **CR count = 0** (`tr -cd '\r' < diff | wc -c` → 0).
- **Added `skip`/`skipif`/`xfail`/`sleep(` lines = 0** (only added lines are the 5 new registry entries and the 1 doc line).
- **Removed `def test_` names = 13**, matching `retire-list.tsv` rows 1–13 exactly (list below). No `def test_` was re-added.
- **Other removed definitions = only the allowlist** — `_shipped_surface_files`, `_TUI_DIR` (+ its 3-line `#:` comment block), and the allowlist imports: `import s19_app`, `from s19_app.tui.models import LoadedFile`, `from s19_app.tui.os_clipboard_input import OsClipboardInput`, `list_diff_reports`, `find_repo_root`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`. (Remaining removed `def`/`class` lines are nested inside the deleted test bodies, not module-level definitions.)
- **Observation (not a failure):** the worker also dropped the 3-line coverage-map docstring bullet `- AT-B94-08 — ``test_at_b94_08_variant_machinery_retired`` …` in `tests/test_tui_patch_editor_b94.py`. This is not a definition; it is a docstring-wording change, within one of the 10 allowed files, and is in fact required by the brief's step-5 grep (without it, `grep ... test_at_b94_08_variant` would match that bullet). The worker declared it as a deviation; the orchestrator's intent review judges it separately.

---

## C2 step 1 — exactly 13 tests gone

The 13 removed `def test_` names in the U1→U2 diff, in `retire-list.tsv` row order:

1. `test_resolve_input_path_falls_back_to_repo_root`
2. `test_find_repo_root_detects_marker`
3. `test_render_hex_view_includes_focus_context`
4. `test_validate_mac_records_duplicate_address_info_when_allow_policy`
5. `test_operations_view_executes_via_service`
6. `test_self_contained_listing_newest_first`
7. `test_retired_method_names_absent`
8. `test_at_b94_08_variant_machinery_retired`
9. `test_tc678_interlock_arm_shipped_surface_is_clean`
10. `test_os_clipboard_input_is_input_subclass`
11. `test_read_os_clipboard_happy_path_uses_only_first_strategy`
12. `test_powershell_layer_returns_none_on_non_windows`
13. `test_ctypes_layer_returns_none_on_non_windows`

FLAG row (`test_validate_mac_records_reports_parse_and_empty_fields`) is NOT retired — still defined at `tests/test_validation_mac.py:36`. PASS.

---

## C2 step 2 — registry

- **Exactly 5 lines differ** (U1 vs U2): `TC-011`, `TC-017`, `TC-628`, `TC-638`, `TC-678`. No other line changed.
- **Every line parses as JSON**; all 1515 lines are canonical (`json.dumps(json.loads(line), ensure_ascii=False) == line`, including the 5 changed lines).
- **Node counts** (after): TC-011 = 13, TC-017 = 8, TC-628 = 4, TC-638 = 31. ✔
- **TC-678 = `RETIRED`**, has `retired_reason` (exact text of the brief), and no `statement` / no `nodes`. ✔
- **TC-017 statement** exactly `Seeded from the existing verifier(s): _install_prg_loaded_file, test_tc017_address_is_the_canonical_hex_string_field (+6 more).` ✔
- **`test_validate_mac_records_reports_parse_and_empty_fields`** is still a TC-628 node and still defined. ✔

PASS.

---

## C2 step 3 — collect-only delta

```
--collect-only -q tests   U1 = 9834   U2 = 9821
9834 - 9821 = 13  (exactly)
```

PASS.

---

## C2 step 4 — reverse_trace (--ta2)

```
tests: 6953 {'O': 1561, 'K?': 625, 'S': 1215, 'K': 3280, 'X': 269, 'U': 3}
```

`tests: 6953 … X 269, U 3` — matches. None of the 13 retired names appears in `TA2-matrix.tsv` (grep count 0 for each). PASS.

---

## C2 step 5 — law-based negative controls (each on its own `cp -a` copy of U2, `-n 0`)

**NC-e** (re-add `tests/test_tui_helpers.py::test_find_repo_root_detects_marker` to TC-638 `nodes`; run `tests/test_id_registry.py`):
```
FAILED tests/test_id_registry.py::test_tc601_g2_live_entries_name_existing_nodes
E       AssertionError: ... rules were already red: ['G2']
        "TC-638 names node 'tests/test_tui_helpers.py::test_find_repo_root_detects_marker' but 'test_find_repo_root_detects_marker' is not defined in tests/test_tui_helpers.py"
```
RED as expected. ✔

**NC-f** (restore old S10-ears-strict.md:375 text; run `tests/test_requirements_canon.py`):
```
FAILED tests/test_requirements_canon.py::test_review_files_name_only_existing_tests
E           Failed: R-DOC-CANON.10 1 of 1113 cited test names are not defined:
E             S10-ears-strict.md:375: `test_at_b94_08_variant_machinery_retired` is not a def test_ or class Test under tests/
```
RED as expected. ✔

**NC-g** (set TC-678 back to `LIVE` with its node + statement; run `tests/test_id_registry.py`):
```
FAILED tests/test_id_registry.py::test_tc601_g2_live_entries_name_existing_nodes
E       AssertionError: ... rules were already red: ['G2']
        "TC-678 names node 'tests/test_command_bar_interlock.py::test_tc678_interlock_arm_shipped_surface_is_clean' ... is not defined in tests/test_command_bar_interlock.py"
```
RED as expected. ✔

A control that stays GREEN = MECH-NO-GO; all three went RED. The NC copies were deleted by explicit path afterwards.

---

## C2 step 6 / CHK-ds step 4 — laws on U2 (six files, serial `-n 0`)

Baseline (U0) = `~/work/zq-ta/baseline/laws-b5ca5b72.txt`.

```
U2: 2 failed, 113 passed, 2 skipped in 429.32s
RED: tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
     tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
```

U0 RED set was exactly these two (`2 failed, 113 passed, 2 skipped`). No other test is RED at U2 → **no new RED vs U0**. PASS.

---

## Worker claims (CHK-ds step 5)

1. **"`--collect-only -q tests` → N1 = 9834, N2 = 9821, delta exactly 13"** — TRUE. Re-ran collect-only on U1 (9834) and U2 (9821); 9834 − 9821 = 13.
2. **"8 touched files: 191 passed (baseline) → 178 passed after retirement, no other change"** — TRUE. Re-ran the 8 files (`-n 4`) on U2: `178 passed in 50.45s` = 191 − 13.
3. **"stale-name grep → only the TC-678 `retired_reason` matches"** — TRUE. `grep -rn "test_find_repo_root_detects_marker\|test_tc678_interlock_arm\|test_at_b94_08_variant" tests docs/requirements REQUIREMENTS.md AT-TC-REGISTRY.jsonl` → exactly one match, the TC-678 `retired_reason` line.
4. **"`git diff --stat` → 68 files, 340 insertions(+), 517 deletions(-)"** — TRUE. `git diff --shortstat` on U2 = `68 files changed, 340 insertions(+), 517 deletions(-)`.
5. **"`git diff | grep -c $'\r'` → 0"** — TRUE. CR count in the U1→U2 diff = 0.

(Additional, not a REPORT claim: registry re-serialisation proof holds — all 1515 registry lines round-trip byte-identically under `json.dumps(json.loads(line), ensure_ascii=False)`.)

---

## Verdict

Steps 1–5 (diff hygiene, C2 1–6, laws, negative controls, worker claims) all pass.

CHECK_DONE U2 MECH-GO
