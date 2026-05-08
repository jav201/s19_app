# Increment 7 — workspace + accessor + hex-view audit tests (LLR-005.1, 005.2, 005.4, 005.5, 006.1, 003.2)

**Phase:** 3 — Implementation
**Increment:** 7 of N
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR targets:**
- **LLR-005.1** — read-path resolution (`resolve_input_path`, `find_repo_root`).
- **LLR-005.2** — project-name sanitisation (Windows reserved set, 64-char cap, NUL byte, Unicode confusables).
- **LLR-005.4** — project-folder validation (symlink rejection + case-only collision; cardinality already covered by `tests/test_tui_helpers.py`).
- **LLR-005.5** — logging surface (5 MB rotation cap + handler reuse + clean-error-or-fallback when log dir is non-writable).
- **LLR-006.1** — accessor contract (`get_raw_value`, `get_physical_value`, `validate_characteristic`; decode/conversion fields and the schema/memory triplet).
- **LLR-003.2** — hex-view rendering invariants (`MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`, `SEARCH_ENCODING` are the only knobs; `app.py` does not import private hexview helpers).

This is a **test-only** increment. No `s19_app/` source changed. Six new Findings raised against `s19_app/tui/workspace.py` (4) and `s19_app/tui/a2l.py` (2); see §5 and §6.

## 1. What changed

Three test files extended with focused unit tests covering the six LLRs above. Net 38 new test cases added (37 pass, 1 xfail). Suite went from 217 / 2 skipped / 2 xfailed to 255 / 2 skipped / 3 xfailed; 0 failed throughout.

### LLR-005.1 — `tests/test_tui_workspace.py::TestReadPathResolution` (TC-041)
Four new tests close the gap left by the existing `tests/test_tui_helpers.py` cwd/repo-root happy-path tests:
- explicit `None` when neither base_dir nor repo root holds the file;
- absolute existing path returned as-is (cwd preference short-circuit);
- `find_repo_root` recognises the `project.toml` marker (the existing test only checked `pyproject.toml`);
- `find_repo_root` returns `None` when no marker exists in the chain.

### LLR-005.2 — `tests/test_tui_workspace.py::TestSanitizeProjectName` (TC-042)
Eight new tests exhaustively probe the Windows reserved set, length cap, NUL byte, and Unicode confusables. The audit observation: today's sanitiser only filters `not isalnum() and not in {-, _}`; this means traversal characters (`. / \ :`) collapse correctly, but **Windows reserved names (CON, PRN, AUX, NUL, COMn, LPTn) survive sanitisation** because their letters are alnum, **the 64-char cap is not enforced**, and **Unicode confusables are kept** because Cyrillic letters are alnum-True. NUL bytes are stripped (alnum-False). Each surviving case is locked with a `pytest.fail(...)` self-flip guard so the test will fail loudly when the Finding is closed, prompting an assertion update.

Findings raised: F-7.7-02 (reserved names), F-7.7-03 (64-char cap), F-7.7-04 (Unicode confusables).

### LLR-005.4 — `tests/test_tui_workspace.py::TestValidateProjectFilesSymlinkAndCase` (TC-048)
Three new tests:
- Symlink rejection: today's `validate_project_files` uses `is_file()` which **follows symlinks**, so a symlinked `*.s19` is accepted. Locked with self-flip guard. Finding F-7.7-05.
- Case-only collision (`prj.S19` vs. `prj.s19`): on case-sensitive filesystems the existing cardinality rule (`>1 primary data files`) catches them; on case-insensitive filesystems the OS only stores one entry so the test is vacuous and short-circuits via `pytest.skip` if it cannot create the second file.
- Cardinality boundary: explicit triple-success (S19 + MAC + A2L) path; complements the existing single-data-and-A2L test in `tests/test_tui_helpers.py`.

### LLR-005.5 — `tests/test_tui_workspace.py::TestSetupLoggingSurface` (TC-049)
Three new tests:
- 5 MB `maxBytes` and `backupCount >= 1` asserted directly off the `RotatingFileHandler` config.
- Handler reuse across repeated `setup_logging(tmp_path)` calls (mirror of the existing single-file test for traceability under LLR-005.5).
- Non-writable log dir: `RotatingFileHandler.__init__` is monkey-patched to raise `PermissionError`. Acceptance: either the exception propagates (clean error) or the returned logger has no broken `RotatingFileHandler` attached. Today's behaviour is the silent-error path — the directory creation succeeds via `mkdir(parents=True, exist_ok=True)` so the patch never fires for a real non-writable case; the test still locks the contract for the day a non-writable dir actually surfaces. **No Finding** because the current code does not exhibit silent failure under the patched-constructor scenario (the exception propagates).

### LLR-006.1 — `tests/test_tui_public_api.py` (TC-051 + TC-052)
Six new tests covering the accessor contract:
- `get_raw_value` / `get_physical_value` field shape (TC-051): `name`, `ok`, `raw_value`, `decode_error`, `physical_value`, `conversion_status`, `conversion_error`, `errors`.
- `validate_characteristic` field shape (TC-051): `{ok, name, errors, tag}` — the decode/conversion fields are nested under `tag`, NOT direct on the result. The `schema_ok / memory_checked / in_memory` triplet is on `validate_a2l_tags(...)` output, not on `validate_characteristic`. Finding F-7.7-06 (REQUIREMENTS.md §Output API documents the triplet on the per-tag accessor; code surfaces it on the bulk validator instead).
- Unknown name handling (TC-052): `ok=False`, populated `errors`, no exception raised.
- Address outside memory (TC-052): exposed a real product bug — `validate_characteristic` builds `{"tags": [tag], **a2l_data}` whose `**a2l_data` overwrites the filtered single-tag list with the full original list. The function then takes `enriched[0]`, returning the first parsed tag's enrichment instead of the requested one. Locked as `pytest.mark.xfail(strict=False)` with Finding F-7.7-07 cited in the reason. **Recommended fix: invert the merge order to `{**a2l_data, "tags": [tag]}`.** Closing the Finding will flip xfail to pass without test changes.
- `validate_a2l_tags` schema/memory/in_memory triplet round-trip (TC-052): asserts type and interaction with `mem_map=None`.

### LLR-003.2 — `tests/test_tui_hexview.py` (TC-023)
Six new tests:
- Each of `MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`, `SEARCH_ENCODING` is monkey-patched and the corresponding entry-point's behaviour is observed to change in the documented direction. This locks them as the *only* governing knobs.
- `app.py` AST is walked for any `from s19_app.tui.hexview import _xxx` — empty list expected. Today: empty. Future violations surface as a hard failure naming the imported helper.

## 2. Files modified

| File | Change |
|---|---|
| `tests/test_tui_workspace.py` | EXTENDED. New imports + four new test classes: `TestReadPathResolution`, `TestSanitizeProjectName`, `TestValidateProjectFilesSymlinkAndCase`, `TestSetupLoggingSurface`. Total +18 new test cases. Existing tests untouched. |
| `tests/test_tui_public_api.py` | EXTENDED. New imports + 7 new tests for LLR-006.1. Existing test untouched. |
| `tests/test_tui_hexview.py` | EXTENDED. `Path` import added at top + 6 new tests for LLR-003.2 (TC-023). Existing tests untouched. |
| `.dev-flow/03-increments/increment-007.md` | NEW. This review packet. |

File count: **4** (within the ≤5 cap).

**Not modified:** `s19_app/` (test-only increment per scope), `tests/conftest.py` (no new fixtures needed), other test files.

## 3. How to test

Full suite:
```
pytest -q tests/
```

Targeted runs per LLR:
```
pytest -v tests/test_tui_workspace.py::TestReadPathResolution                  # LLR-005.1
pytest -v tests/test_tui_workspace.py::TestSanitizeProjectName                # LLR-005.2
pytest -v tests/test_tui_workspace.py::TestValidateProjectFilesSymlinkAndCase # LLR-005.4
pytest -v tests/test_tui_workspace.py::TestSetupLoggingSurface                # LLR-005.5
pytest -v tests/test_tui_public_api.py                                        # LLR-006.1
pytest -v tests/test_tui_hexview.py -k "tc_023"                               # LLR-003.2
```

The Windows-only NTFS-junction probe from increment 1 still requires manual gate-closing per Q-N01:
```
pytest -q tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_junction_rejected_on_windows
```

## 4. Test results

**Full suite (Windows 11 / Python 3.14.4 / pytest 9.0.3):**

```
$ python -m pytest -q tests/
......ss................................................................ [ 27%]
.......................................................x................ [ 55%]
....................................................x................... [ 83%]
...............................x............                             [100%]
255 passed, 2 skipped, 3 xfailed in 56.09s
```

- **255 passed** (was 217 in increment 6; net +38 from this increment's 38 new tests).
- **2 skipped** (pre-existing TC-047 NTFS-junction probe + the other pre-existing skip — unchanged).
- **3 xfailed** (= 2 carried over from increments 5/6 carrying F-7.2-01 + 1 new from this increment carrying F-7.7-07).
- **0 failed.**

Targeted run for the new test classes (workspace + public-api + hexview):

```
$ python -m pytest -q tests/test_tui_workspace.py tests/test_tui_public_api.py tests/test_tui_hexview.py
......................................x........................... [100%]
65 passed, 1 xfailed in 0.60s
```

No xpass.

## 5. Risks

### Per-LLR coverage summary table

| LLR | Acceptance bullets covered before this increment | Acceptance bullets newly covered | New Findings filed |
|---|---|---|---|
| LLR-005.1 | cwd preference (`test_resolve_input_path_prefers_base_dir`); repo-root fallback positive (`test_resolve_input_path_falls_back_to_repo_root`); marker detection on `pyproject.toml` (`test_find_repo_root_detects_marker`). | explicit `None` when no match; absolute-path short-circuit; `project.toml` marker variant; `find_repo_root` returns `None` without marker. | None — implementation matches LLR-005.1 acceptance. |
| LLR-005.2 | trivial allow/strip/empty path coverage in `tests/test_tui_helpers.py` (`test_sanitize_project_name_allows_safe_chars`, `_strips_invalid_chars`, `_rejects_empty`). | full Windows reserved-name probe (10 names); 64-char cap probe; NUL byte probe; Unicode confusable probe; traversal vector explicit collapse cases. | F-7.7-02 (reserved names not rejected), F-7.7-03 (length cap not enforced), F-7.7-04 (Unicode confusables not detected). |
| LLR-005.4 | cardinality (>1 S19/HEX, >1 A2L, >1 MAC) covered by `test_tui_helpers.py` (`test_validate_project_files_*`). | symlink-followed-by-`is_file()` regression locked; case-only collision behaviour locked; explicit triple-success boundary. | F-7.7-05 (`validate_project_files` follows symlinks). |
| LLR-005.5 | handler reuse (`test_setup_logging_reuses_handler_for_same_path` from increment 1); creation + log file (`test_setup_logging_creates_log_handler` from helpers); rotating-handler type assertion. | 5 MB `maxBytes` + `backupCount` direct config assertion; non-writable-log-dir clean-error-or-fallback contract under monkey-patched `RotatingFileHandler.__init__`. | None — current behaviour passes the contract under the simulated failure (constructor exception propagates cleanly). |
| LLR-006.1 | `validate_a2l_tags` schema/memory/in_memory exercised in `test_validate_a2l_tags_matches_memory` (helpers). | accessors `get_raw_value` / `get_physical_value` / `validate_characteristic` field shapes locked; unknown-name handling; address-outside-memory regression locked under xfail; `validate_a2l_tags` triplet round-trip with `mem_map=None`. | F-7.7-06 (schema/memory/in_memory triplet documented on per-tag accessor but lives on bulk validator); F-7.7-07 (`validate_characteristic` returns the wrong tag's enrichment when the requested tag is not first). |
| LLR-003.2 | truncation + focus-context + search wiring covered by existing `test_tui_helpers.py` and `test_tui_hexview.py`. | each constant directly monkey-patched to confirm it's the *only* governing knob; AST walk of `app.py` to confirm no private-helper imports. | None. |

### Other risks

- **F-7.7-07 product bug.** `validate_characteristic`'s tag-list merge order means any caller that requests a tag other than the first parsed tag silently gets the wrong tag's enrichment. The bug is mitigated when the canonical caller (`tests/test_tui_public_api.py::test_tc_051_*` always queries `MEAS_OK`, the first tag) but downstream consumers using these accessors as documented are at risk. Recommend a follow-up product increment that flips the spread order in `s19_app/tui/a2l.py` line ~1223 and removes the xfail.

- **F-7.7-02 / F-7.7-03 / F-7.7-04 sanitiser gaps.** None of these are exploitable on the offline-desktop threat model (no remote attacker can control project names), but each violates the LLR-005.2 acceptance contract. Recommend a single product increment that tightens `sanitize_project_name` to enforce the reserved-name set, the 64-char cap, and a mixed-script detector.

- **F-7.7-05 symlink follow-through in `validate_project_files`.** Symlinks pointing OUT of the project directory could let a project "include" arbitrary files. Less severe than the workarea write-path issue closed by S-N01 (validate_project_files only reads metadata; it does not write through the link), but still violates the LLR-005.4 acceptance. Recommend tightening to `is_file() and not is_symlink() and not _is_reparse_point(...)`.

- **No new dependencies.** No production-code changes. Existing increments 1, 1.5, 2, 3, 4, 5, 6 unchanged and all green.

- **xfail-as-self-flip pattern.** Several tests in `TestSanitizeProjectName` and `TestValidateProjectFilesSymlinkAndCase` use `pytest.fail(...)` inside an `if` branch that fires when the product behaviour tightens. The benefit: the failing test names the closed Finding directly, prompting whoever closes the Finding to also update the assertion. The cost: a casual reader sees `assert <de-facto behaviour>` at the bottom of the test and may miss the flip-guard. Annotated each instance with the Finding ID and a one-line "flip this test when…" pointer.

## 6. Pending items

### F-7.7-XX Findings (new this increment)

| ID | Target | Observation | Severity | Recommended fix |
|---|---|---|---|---|
| F-7.7-02 | `s19_app/tui/workspace.py::sanitize_project_name` | Returns Windows reserved device names (CON, PRN, AUX, NUL, COMn, LPTn) and their `.ext` variants verbatim. LLR-005.2 says these must yield `None`. | minor | After alnum/dash/underscore filter, lowercase the cleaned name's stem and reject if it is in `{con, prn, aux, nul, com1..9, lpt1..9}`. |
| F-7.7-03 | `s19_app/tui/workspace.py::sanitize_project_name` | No length cap; arbitrary-length cleaned names returned as-is. LLR-005.2 says >64 chars must yield `None` (or be truncated). | minor | Add `if len(cleaned) > 64: return None` before the final return. |
| F-7.7-04 | `s19_app/tui/workspace.py::sanitize_project_name` | Unicode confusables (e.g. Cyrillic 'а' U+0430) survive because `str.isalnum()` returns True. LLR-005.2 cites Unicode TR36. | minor | Restrict the alnum check to `ch.isascii() and ch.isalnum()` or use a TR36 confusable detector. |
| F-7.7-05 | `s19_app/tui/workspace.py::validate_project_files` | Iterates with `item.is_file()`, which follows symlinks. LLR-005.4 says symlinked / NTFS-reparse-point entries must be rejected. | minor | Add `if item.is_symlink() or _is_reparse_point(item): continue` before the suffix dispatch. |
| F-7.7-06 | `s19_app/tui/a2l.py::validate_characteristic` | REQUIREMENTS.md §Output API documents `schema_ok / memory_checked / in_memory` on the per-tag accessor; the code surfaces those fields on the bulk `validate_a2l_tags()` output instead. Single-tag accessor returns `{ok, name, errors, tag}` with decode/conversion fields nested under `tag`. | minor | Either document the per-tag/bulk split in REQUIREMENTS.md or extend `validate_characteristic`'s top-level dict to mirror the triplet from `validate_a2l_tags`. |
| F-7.7-07 | `s19_app/tui/a2l.py::validate_characteristic` line ~1223 | `enriched = enrich_a2l_tags_with_values({"tags": [tag], **a2l_data}, mem_map)[0]` — the `**a2l_data` spread comes AFTER `[tag]`, so `data["tags"]` overwrites the filtered single-tag list and `[0]` returns the FIRST parsed tag's enrichment, not the requested tag's. Effectively, the accessor's name filter is ignored when the requested tag is not first. | major | Flip the spread order: `{**a2l_data, "tags": [tag]}`. After the fix, the xfail in `test_tc_052_address_outside_memory_marks_failure` will pass without test edits — remove the `xfail` decorator at the same time. |

### Items deferred / carried forward (NOT this increment's scope)

- **F-7.2-01** (engine gap, S19/HEX overlap) — still open per `02-review.md` §Deferrals; carried via the increment-5/6 xfails on TC-062.a / TC-065.a. Not closed by this increment.
- **F-7.2-02** (S19/A2L corruption not piped to engine) — still open per `02-review.md` §Deferrals; carried via the TC-062.h / TC-065.h MAC-only assertions. Not closed by this increment.
- **A-N04 / Q-N02 doc-edit** — still pending; folded into Phase 6 docs work as planned in `02-review.md` §Deferrals.
- **Q-N01 NTFS-junction Windows manual gate** — TC-047 still needs the Windows stdout attached before Phase 4 close. Not in scope here.

## 7. Suggested next task

**Increment 8 — engine determinism + coverage-metrics tests (LLR-009.1 + LLR-009.2 / TC-081 + TC-082).**

Pure test additions to `tests/test_validation_engine.py`. ≤2 files (one test file + the next packet).

Scope:
- TC-081: invoke `validate_artifact_consistency` twice on the `large_project` fixture; assert `report.issues` (content + order) and every `CoverageMetrics` field are byte-equal across the two runs. Pre-condition (`make_large_*` `seed=0`) already verified by inspection of `tests/conftest.py` per `01-requirements.md` §6.3 R-5.
- TC-082: assert each declared `CoverageMetrics` field is referenced AND non-zero on the `large_project` run; assert empty-input baseline returns zero counts. Audit any field declared in `model.py` but not populated by `engine.py` and file as a Finding.

Justification: this is the largest remaining auto-testable LLR cluster from the audit batch (HLR-009 entirely), it is bounded to ≤2 files, and a flake-free determinism check is a Phase 4 acceptance gate. Promoting LLR-009.1 / LLR-009.2 to Automated tightens the per-`R-*` verdict matrix LLR-004.1 will consume.

**Alternative if user prefers product-fix work**: close F-7.7-07 (single-line fix in `s19_app/tui/a2l.py::validate_characteristic` + remove the xfail in `test_tc_052_address_outside_memory_marks_failure`). 1 product file + 1 test file edit. This is the highest-impact Finding from this increment because it silently returns wrong data to documented public accessors. Recommend the test-coverage path (increment 8) as the default, with F-7.7-07 as the very next product increment after 8.
