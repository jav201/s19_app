# Increment 6 — panel-render snapshot tests for the 8 cross-file classes (LLR-007.4 / TC-065.a..h)

**Phase:** 3 — Implementation
**Increment:** 6 of N
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR target:**
- **LLR-007.4** — Textual snapshot tests verifying each cross-file incompatibility class is **visibly rendered** in the Issues panel of `S19TuiApp`. Locks the engine→panel co-render contract (HLR-007b) on top of the engine-side co-emission contract (HLR-007a) closed in increment 5.
- **Q-N03 closure** — TC-064 vs. TC-065 overlap. Resolved by Option A: annotate the existing harness smoke test (`test_snapshot_harness_renders_issues_panel`) as the spiritual TC-064 single-class smoke and use TC-065.a..h for the parametric per-class tests.
- Carries forward the engine-side findings from increment 5: F-7.2-01 (S19/HEX overlap engine gap) → TC-065.a is xfail by carry-through; F-7.2-02 (S19/A2L corruption not piped to engine) → TC-065.h covers MAC subset only.

## 1. What changed

Extended `tests/test_tui_app.py` with `class TestCrossFileCompatibilityPanelRender` containing **8 panel-render tests** (TC-065.a..h), one per cross-file incompatibility class. Each test:

1. Parses the per-class fixture using the same parser pipeline as the corresponding TC-062.X engine test (`S19File`, `parse_a2l_file`, `parse_mac_file`).
2. Builds a real `ValidationReport` via `validate_artifact_consistency` (same wiring as `validation_service.build_validation_report`).
3. Spins up `S19TuiApp(base_dir=tmp_path)` headlessly inside `App.run_test()` (same `asyncio.run(_drive())` sync-wrapper pattern established by the increment-2 smoke test).
4. Populates `app._validation_issues` directly from the report's `issues` list, calls `app.update_validation_issues_view()`, awaits `pilot.pause()`.
5. Reads back the rendered codes via `_query_issues_panel_codes(app)` (helper from increment 2).
6. Asserts the expected `ValidationIssue.code` is **present in the rendered set** for the class.

A test-local helper `_engine_inputs_from_paths` mirrors the one in `tests/test_validation_engine.py`; duplicated locally so the two test modules stay import-independent (the engine test file is not a public test API).

A second test-local helper `_drive_panel(tmp_path, issues)` wraps the headless app drive + panel render + readback. To make the per-class assertions hold against the multi-thousand-issue `large_project` report (≈34 500 issues), `_drive_panel` widens both `viewer_page_size_max` and `validation_issues_page_size` on the test instance so the entire issues list lands on the first page. This is test-side configuration only — no `s19_app/tui/app.py` change.

**Q-N03 closure (Option A — preferred):** A one-line comment was added immediately above `test_snapshot_harness_renders_issues_panel`:

```
# Stands in for TC-064 (single-class smoke; parametric per-class tests are TC-065.a..h).
```

This closes the TC-064/TC-065 strict-subset overlap noted in `02-review.md` §Deferrals — the existing smoke test plays the TC-064 role (single-class smoke for the harness), and the new 8 tests play the parametric TC-065.a..h role. No file rename, no new test, zero net file impact for the closure annotation.

**Per-class panel-render evidence:**

| TC | Class | Fixture | Expected `code` | Result |
|---|---|---|---|---|
| TC-065.a | S19/HEX overlap | `overlap_s19_hex` | `CROSS_S19_HEX_OVERLAP` (recommended; not yet in engine) | **xfail** (carries F-7.2-01) |
| TC-065.b | A2L tag range out of S19 | `large_project` | `CROSS_A2L_S19_OUT_OF_RANGE` | pass |
| TC-065.c | MAC out of S19 range | `large_project` | `CROSS_MAC_S19_OUT_OF_RANGE` | pass |
| TC-065.d | A2L↔MAC name/address mismatch | `large_project` | `TRIPLE_NAME_ADDRESS_MISMATCH` | pass |
| TC-065.e | symbol-only-in-MAC | `large_project` | `CROSS_MAC_ONLY_SYMBOL` | pass |
| TC-065.f | symbol-only-in-A2L | `large_project` | `CROSS_A2L_ONLY_SYMBOL` | pass |
| TC-065.g | duplicate-address alias | `duplicate_alias_mac` | `MAC_DUPLICATE_ADDRESS` | pass |
| TC-065.h | parsed-record corruption | `corrupt_records` | `MAC_PARSE_ERROR` (MAC subset only, per F-7.2-02) | pass |

No product code modified. No new pytest plugins added. No new dependencies.

## 2. Files modified

| File | Change |
|---|---|
| `tests/test_tui_app.py` | EXTENDED. Added Q-N03 stand-in comment above the existing smoke test. Added new `class TestCrossFileCompatibilityPanelRender` (8 tests + `_engine_inputs_from_paths` + `_drive_panel` helpers). ~190 LOC added at end of file. Existing tests untouched. |
| `.dev-flow/03-increments/increment-006.md` | NEW. This review packet. |

File count: **2** (well within the ≤5 cap; aim of "test extension + packet" met).

**Not modified:** `s19_app/` (per increment scope — test-only change), `tests/conftest.py` (per increment scope — fixtures from increment 2 used as-is), `tests/test_validation_engine.py` (engine-side TC-062 tests from increment 5 unchanged).

## 3. How to test

```
pytest -q tests/
```

Targeted run for the new class:

```
pytest -v tests/test_tui_app.py::TestCrossFileCompatibilityPanelRender
```

Single-class run example (TC-065.g):

```
pytest -v tests/test_tui_app.py::TestCrossFileCompatibilityPanelRender::test_tc_065_g_duplicate_address_alias_panel_render
```

## 4. Test results

**Full suite (Windows 11 / Python 3.14.4 / pytest 9.0.3):**

```
$ python -m pytest -q tests/
......ss................................................................ [ 32%]
.......................................................x................ [ 65%]
................................................................x....... [ 97%]
.....                                                                    [100%]
217 passed, 2 skipped, 2 xfailed in 51.30s
```

- **217 passed** (was 210 in increment 5; net +7 from the 7 new TC-065 tests that pass).
- **2 skipped** (pre-existing TC-047 NTFS-junction probe + the other pre-existing skip — unchanged).
- **2 xfailed** (engine-side TC-062.a from increment 5 + new panel-side TC-065.a — both carry F-7.2-01).
- **0 failed.**

**Targeted run (`TestCrossFileCompatibilityPanelRender`):**

```
test_tc_065_a_s19_hex_overlap_panel_render            XFAIL
test_tc_065_b_a2l_range_out_of_s19_panel_render       PASSED
test_tc_065_c_mac_address_out_of_s19_panel_render     PASSED
test_tc_065_d_a2l_mac_name_address_mismatch_panel_render PASSED
test_tc_065_e_symbol_only_in_mac_panel_render         PASSED
test_tc_065_f_symbol_only_in_a2l_panel_render         PASSED
test_tc_065_g_duplicate_address_alias_panel_render    PASSED
test_tc_065_h_parsed_record_corruption_panel_render   PASSED

7 passed, 1 xfailed in 34.59s
```

No xpass.

## 5. Risks

- **Pagination observation (test-design, not a Finding).** Initial run of TC-065.b..f against the `large_project` fixture failed because the panel pages at 200 issues per page (`validation_issues_page_size=200` clamped by `viewer_page_size_max=200`) and the 13 000 `MAC_PARSE_ERROR` issues from `large_mac` filled the first page entirely, so the cross-file codes (which the engine emits AFTER MAC parse errors in list order) never reached the visible window. This is **pagination behaviour**, not a panel-side filter — paging through to subsequent pages would render the missing codes. The test-side fix is to widen `viewer_page_size_max` and `validation_issues_page_size` on the test app instance so the full report fits one page. This is configuration on the test instance, not a product change. Consequence: `_drive_panel` does this widening unconditionally; the smoke test from increment 2 keeps its original behaviour (small `large_project` returns enough cross-file issues even at default page size — confirmed by the smoke remaining green).

- **TC-065.a xfail (carries F-7.2-01).** The S19/HEX overlap class still has no engine code. Marked `pytest.mark.xfail(strict=False)` with a reason that explicitly cites Finding F-7.2-01. When the engine gap is closed in a follow-up batch, the xfail decorator on TC-065.a should be removed in the same change as the matching change to TC-062.a.

- **TC-065.h asserts MAC subset only (carries F-7.2-02).** The S19 checksum-mismatch error and A2L missing-`ECU_ADDRESS` structural error from `corrupt_records` are not piped into `validate_artifact_consistency` (per F-7.2-02 in increment 5 §5), so they are absent from the panel. TC-065.h asserts only the MAC layer's `MAC_PARSE_ERROR` to match the engine-visible slice. A one-line code comment in the test documents this.

- **Headless run cost.** Each panel-render test spins up a full `S19TuiApp` under `App.run_test()`. The 8 tests added ~37 s to the suite (51 s total vs. 16 s in increment 5). This is acceptable for the per-class snapshot coverage but means the suite is now noticeably slower on cold runs. If wall-clock matters for CI later, the per-class tests could be moved behind the existing `slow` marker (`-m "not slow"` would still leave the engine-side TC-062.X tests in the default run). Not done in this increment — keep the default run honest about the engine→panel contract.

- **`pilot.pause()` with one tick is sufficient.** `update_validation_issues_view()` is synchronous (it calls `query_one` + `add_row` directly inside the same task), so a single `await pilot.pause()` is enough to flush. No multi-tick wait needed; no observed flake across local runs.

- **No new dependencies introduced.** No production-code changes. Existing increments 1, 1.5, 2, 3, 4, 5 unchanged and all green.

## 6. Pending items

### Q-N03 closure — chosen Option

**Chosen: Option Q-N03-A.** A `# Stands in for TC-064 (single-class smoke; parametric per-class tests are TC-065.a..h).` comment was added immediately above `test_snapshot_harness_renders_issues_panel` in `tests/test_tui_app.py`. The existing smoke test now plays the spiritual TC-064 role; the 8 new tests are TC-065.a..h. Net file count for the closure annotation: 0 new files; the comment is in a file already extended for the increment.

This closes Q-N03. No further work for this question.

### Items deferred / carried forward (NOT this increment's scope)

- **Q-N02 / A-N04 doc-edit** — still pending; will be folded into Phase 6 docs work as planned in `02-review.md` §Deferrals.
- **F-7.2-01 (engine gap, S19/HEX overlap)** — still open per `02-review.md` §Deferrals. This increment carries it forward via the TC-065.a xfail. Closure requires an engine-side fix (new `CROSS_S19_HEX_OVERLAP` code + rule); will land in the dedicated follow-up batch.
- **F-7.2-02 (S19/A2L corruption not piped to engine)** — still open per `02-review.md` §Deferrals. This increment carries it forward via the TC-065.h MAC-only assertion + a code comment. Closure requires either piping `S19File.get_errors()` into the engine or rewording LLR-007.2 to scope the contract to MAC only.
- **Phase 4 validation step** — once increments 7+ land enough to call this batch "feature-complete for HLR-007", update `.dev-flow/04-validation.md` with the consolidated test-results matrix (currently the matrix is split across increment-005.md §6 and increment-006.md §1).
- **Optional CI tag** — if the slower headless run becomes a CI bottleneck, mark `TestCrossFileCompatibilityPanelRender` as `slow` in a follow-up. Out of scope here; default run is the right place for the engine→panel contract today.

## 7. Suggested next task

**Increment 7 — workspace + accessor + hex-view unit tests (LLR-005.1, 005.2, 005.4, 005.5, 006.1, 003.2).**

The HLR-007 chain is now closed at the test level for the eight cross-file incompatibility classes (engine-side in increment 5 / TC-062, panel-side in increment 6 / TC-065). The next-largest LLR cluster lacking automated test coverage is the workspace + hex-view family:

- **LLR-005.1 / 005.2 / 005.4 / 005.5** — workspace path resolution (`resolve_input_path`, `find_repo_root`), project-name sanitization, and the one-S19-one-MAC-one-A2L invariant in `validate_project_files`. Currently exercised indirectly by `test_save_project_writes_under_workarea` etc., but no dedicated coverage of the corner cases (junction handling on Windows, deeply-nested cwd searches, pathological project names).
- **LLR-006.1** — `range_index` membership primitive correctness on edge cases (empty ranges, single-byte ranges, ranges that touch but don't overlap). The big-O-style perf test is in place; correctness micro-cases are not.
- **LLR-003.2** — hex-view rendering caps (`MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`, `SEARCH_ENCODING`) — verify they are respected at the `render_hex_view_text` boundary.

Scope (≤5 files):
- `tests/test_workspace.py` (new) — focused unit tests for `s19_app/tui/workspace.py`.
- `tests/test_range_index.py` (new) — micro-cases for `s19_app/range_index.py`.
- `tests/test_hexview.py` (extend) — cap-respect tests at `render_hex_view_text`.
- This packet's successor.

Justification: this is the largest remaining test-coverage gap that is (a) test-only (no product change), (b) ≤5 files, and (c) directly traceable to LLR rows currently marked `Manual` or `Partial` in `REQUIREMENTS.md`. Promotes those rows to `Automated` and tightens the Phase 4 validation matrix.

If the user prefers to close F-7.2-01 (engine gap, S19/HEX overlap) before moving on — that's a `s19_app/validation/` change with a test in `tests/test_validation_engine.py`, also ≤5 files and a higher-leverage product fix; a viable alternative for increment 7. Recommend test-coverage-first (this proposal) because the engine fix benefits from the `slow` headless infra now in place.
