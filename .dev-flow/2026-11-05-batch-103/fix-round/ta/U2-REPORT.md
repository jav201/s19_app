# U2-retire — report

**Unit:** U2-retire
**HEAD sha:** b5ca5b7277e3a0aa9683e50fdd71ebb578ee7d80
**Start time:** 2026-11-19 14:15:56 CST
**Inherited U1 diff (before this unit):** `git diff --stat` → 65 files changed, 334 insertions(+), 155 deletions(-)

---

## Step 1 — header, collect-only N1, baseline of the 8 touched files

- `--collect-only -q tests` → **N1 = 9834** tests collected.
- Ran the 8 touched files (`-n 4`): **191 passed, 0 failed** (no failed node list).

Touched files (baseline):
`tests/test_tui_helpers.py`, `tests/test_validation_mac.py`, `tests/test_tui_operations_view.py`, `tests/test_diff_report_service.py`, `tests/test_change_service.py`, `tests/test_tui_patch_editor_b94.py`, `tests/test_command_bar_interlock.py`, `tests/test_loadfilescreen_input.py`.

The 13 nodes to remove (base for step 4):
1. `tests/test_tui_helpers.py::test_resolve_input_path_falls_back_to_repo_root`
2. `tests/test_tui_helpers.py::test_find_repo_root_detects_marker`
3. `tests/test_tui_helpers.py::test_render_hex_view_includes_focus_context`
4. `tests/test_validation_mac.py::test_validate_mac_records_duplicate_address_info_when_allow_policy`
5. `tests/test_tui_operations_view.py::test_operations_view_executes_via_service`
6. `tests/test_diff_report_service.py::test_self_contained_listing_newest_first`
7. `tests/test_change_service.py::test_retired_method_names_absent`
8. `tests/test_tui_patch_editor_b94.py::test_at_b94_08_variant_machinery_retired`
9. `tests/test_command_bar_interlock.py::test_tc678_interlock_arm_shipped_surface_is_clean`
10. `tests/test_loadfilescreen_input.py::test_os_clipboard_input_is_input_subclass`
11. `tests/test_loadfilescreen_input.py::test_read_os_clipboard_happy_path_uses_only_first_strategy`
12. `tests/test_loadfilescreen_input.py::test_powershell_layer_returns_none_on_non_windows`
13. `tests/test_loadfilescreen_input.py::test_ctypes_layer_returns_none_on_non_windows`

Command template (run from the tree root, `<nodes>` replaced per step):
```
S=$(realpath ../state); mkdir -p $S~ $S/tmp $S/x; timeout 300 env -i \
  PATH=/usr/bin:/bin HOME=$S~ XDG_CONFIG_HOME=$S/x/config \
  XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp \
  PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 \
  ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q <nodes> < /dev/null
```

---

## Step 2 — dry run, then `--apply`

`retire_apply.py` (stdlib only; dry run unless `--apply`; all-or-nothing write) was run first without `--apply` (dry run), then with `--apply`. Per-step report:

```
DELETE tests/test_tui_helpers.py::test_resolve_input_path_falls_back_to_repo_root
DELETE tests/test_tui_helpers.py::test_find_repo_root_detects_marker
DELETE tests/test_tui_helpers.py::test_render_hex_view_includes_focus_context
REMOVE tests/test_tui_helpers.py: find_repo_root
REMOVE tests/test_tui_helpers.py: FOCUS_CONTEXT_ROWS
REMOVE tests/test_tui_helpers.py: HEX_WIDTH
DELETE tests/test_validation_mac.py::test_validate_mac_records_duplicate_address_info_when_allow_policy
DELETE tests/test_tui_operations_view.py::test_operations_view_executes_via_service
REMOVE tests/test_tui_operations_view.py: LoadedFile
DELETE tests/test_diff_report_service.py::test_self_contained_listing_newest_first
REMOVE tests/test_diff_report_service.py: list_diff_reports
DELETE tests/test_change_service.py::test_retired_method_names_absent
DELETE tests/test_tui_patch_editor_b94.py::test_at_b94_08_variant_machinery_retired
COVERAGE tests/test_tui_patch_editor_b94.py: drop bullet naming test_at_b94_08_variant_machinery_retired
  other unused imports tests/test_tui_patch_editor_b94.py: [('Rail', 69)]
DELETE tests/test_command_bar_interlock.py::test_tc678_interlock_arm_shipped_surface_is_clean
REMOVE tests/test_command_bar_interlock.py: _shipped_surface_files
REMOVE tests/test_command_bar_interlock.py: _TUI_DIR
REMOVE tests/test_command_bar_interlock.py: s19_app
DELETE tests/test_loadfilescreen_input.py::test_os_clipboard_input_is_input_subclass
DELETE tests/test_loadfilescreen_input.py::test_read_os_clipboard_happy_path_uses_only_first_strategy
DELETE tests/test_loadfilescreen_input.py::test_powershell_layer_returns_none_on_non_windows
DELETE tests/test_loadfilescreen_input.py::test_ctypes_layer_returns_none_on_non_windows
REMOVE tests/test_loadfilescreen_input.py: OsClipboardInput
REGISTRY TC-011: 14 -> 13 nodes
REGISTRY TC-017: 9 -> 8 nodes
REGISTRY TC-628: 5 -> 4 nodes
REGISTRY TC-638: 34 -> 31 nodes
REGISTRY TC-678 -> RETIRED (statement/nodes dropped, retired_reason added)
DOC docs/requirements/review/S10-ears-strict.md D10-4 substring swapped
APPLIED — wrote 10 files.
```

Other unused imports reported (not removed): `tests/test_tui_patch_editor_b94.py` → `Rail` (pre-existing; imported at line 72, never referenced — reported only).

Registry re-serialisation proof: for every touched entry, `json.dumps(json.loads(line), ensure_ascii=False)` reproduced the untouched line byte-for-byte, so changed entries were re-serialised; all untouched registry lines stay byte-identical.

---

## Step 3 — controls NC-a and NC-b

**NC-a (wrong name refused → exit 2, git status unchanged):** a `cp -a` copy of the tree at `../scratch/nc-a/repo`, with a copy of the script mutating `test_find_repo_root_detects_marker` → `test_find_repo_root_detects_markerX`, run with `--apply`:

```
retire_apply: test_find_repo_root_detects_markerX: missing (no such top-level function)
EXIT=2
GIT STATUS UNCHANGED   (git status --short diff before/after = empty)
```

**NC-b (idempotent):** rerun `--apply` on the applied tree:

```
STEP 1: delete functions — already
STEP 2: remove allowlisted names — already
STEP 3: registry — already
STEP 4: doc — already
EXIT=0
```

diff unchanged (nothing rewritten). `../scratch/nc-*` deleted.

---

## Step 4 — collect-only N2 and re-run of the 8 touched files

- `--collect-only -q tests` → **N2 = 9821**.
- **N1 − N2 = 9834 − 9821 = 13** (exactly the 13 removed nodes). ✔
- Re-ran the 8 touched files (`-n 4`): **178 passed** = 191 (baseline) − 13 (removed). No other change. ✔

---

## Step 5 — stale-name grep

```
grep -rn "test_find_repo_root_detects_marker\|test_tc678_interlock_arm\|test_at_b94_08_variant" \
  tests docs/requirements REQUIREMENTS.md AT-TC-REGISTRY.jsonl
```

Result: exactly one match — the TC-678 `retired_reason` in `AT-TC-REGISTRY.jsonl`:

```
AT-TC-REGISTRY.jsonl:1447:{"id": "TC-678", ... "retired_reason": "Retired in the batch-103 fix round (TR-01): its verifier tests/test_command_bar_interlock.py::test_tc678_interlock_arm_shipped_surface_is_clean was removed because the requirement it verified, HLR-133 / LLR-133.1, is retired as history in REQUIREMENTS.md S0.2 (a rule on one batch's diff: no command bar on the map). TC-679 and AT-295 were not part of this retirement."}
```

Only the TC-678 `retired_reason` matches. ✔

---

## Deviations

1. **Coverage-map docstring bullet removed (addition to the literal fixed spec).**
   The fixed spec (steps 1–5) lists only function deletion, allowlist-name removal, registry edits and the S10-ears-strict.md D10-4 swap. It does not list the module-docstring coverage map in `tests/test_tui_patch_editor_b94.py`, whose bullet `- AT-B94-08 — ``test_at_b94_08_variant_machinery_retired`` …` names the retired test. Step 5 of this brief requires the grep for `test_at_b94_08_variant` to match only the TC-678 `retired_reason`, and FB-common rule 3 sanctions updating "docstring wording that names an old seam". The script therefore also drops that one coverage bullet (lines 20–22). Evidence:
   - Before: `tests/test_tui_patch_editor_b94.py:20` matched `test_at_b94_08_variant_machinery_retired`; after the edit the grep shows only the registry line (see Step 5).
   - The surviving `TC-B94-11 — test_tc_b94_11_stale_variant_noop_and_single_binding` bullet already covers the "stale VariantSelected-shaped message is a no-op" behaviour (LLR-006.1/006.2), so no coverage is lost.

---

## Open questions

1. **Orphaned section banner** `# AT-B94-08 — variant machinery retired (HLR-006)` remains in `tests/test_tui_patch_editor_b94.py` (now immediately above the `# AT-B94-09` banner). It is not deleted because the fixed spec's deleted block is "the contiguous comment block directly above the first decorator", and that banner is separated from the deleted `def` by two blank lines. It carries no test name, so the step-5 grep is unaffected. Left as-is per spec.
2. **Pre-existing unused import** `Rail` in `tests/test_tui_patch_editor_b94.py` (reported, not removed, per the step-2 rule "report, do not remove"). It predates this unit.

---

## Final

```
git diff --stat
 68 files changed, 340 insertions(+), 517 deletions(-)
```
(65 inherited U1 files + this unit's changes; this unit's own net diff vs the inherited tree is 10 files — 8 test files, `AT-TC-REGISTRY.jsonl`, `docs/requirements/review/S10-ears-strict.md`.)

```
git diff | grep -c $'\r'
 0
```

Final run of the unit's 8 touched files (`-n 4`): **178 passed** in ~51s.

UNIT_DONE U2-retire
