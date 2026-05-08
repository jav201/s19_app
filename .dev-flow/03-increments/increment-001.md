# Increment 1 — LLR-005.3 (workspace-IO write-path hardening)

**Phase:** 3 — Implementation
**Increment:** 1 of N
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR target:** LLR-005.3 — write-path containment, symlink/reparse-point rejection, file-size cap.
**Closes:** Phase 2 blockers S-001, S-002 and major S-003.

## 1. What changed

- Introduced a new `WorkareaContainmentError(ValueError)` exception in `s19_app/tui/workspace.py`.
- Hardened `copy_into_workarea` with three pre-write guards:
  1. **Destination containment** — rejects when the resolved destination has no `.s19tool/workarea` ancestor (closes S-001).
  2. **Symlink + NTFS reparse-point rejection** — rejects when `source` is a symlink/junction, or when the destination or any parent component up to (and including) the workarea root traverses a reparse point. Uses `Path.is_symlink()` plus `os.lstat().st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT` on Windows because `Path.resolve()` silently follows junctions (closes S-002, addresses minor finding S-N01).
  3. **File-size cap** — added `max_size_bytes: int = 256 * 1024 * 1024` parameter; rejects when `source.stat().st_size` exceeds it. Inline comment captures the cap rationale per finding S-N02 (closes S-003).
- Added two private helpers `_is_reparse_point` and `_path_traverses_reparse_point`, plus `_find_workarea_root`, all inside `workspace.py` (no new module).
- Wrapped every `copy_into_workarea` call site in `s19_app/tui/app.py` with `try/except WorkareaContainmentError` that surfaces a status message via `self.set_status(...)` and writes a `logger.warning(...)` line. Six call sites updated: project save (3 calls), background project sync (3 calls), background A2L sync (1 call), temp-load main flow (1 call), temp-load A2L flow (1 call).
- Added `class TestCopyIntoWorkareaContainment` to `tests/test_tui_workspace.py` with TC-044 (size cap), TC-045 (source symlink), TC-046 (destination containment), TC-047 (NTFS junction; `pytest.mark.skipif` on non-Windows). Each test names its TC ID in a leading comment.
- Updated the pre-existing `tests/test_tui_helpers.py::test_copy_into_workarea_creates_unique_names` to write into a `.s19tool/workarea/temp` destination so the new containment check accepts it. This is a one-line change preserving the original assertion intent.

## 2. Files modified

| File | Change |
|---|---|
| `s19_app/tui/workspace.py` | New exception, three private helpers, hardened `copy_into_workarea`. |
| `s19_app/tui/app.py` | Imported `WorkareaContainmentError`; wrapped six `copy_into_workarea` call sites with try/except that surfaces status + logs warnings. |
| `tests/test_tui_workspace.py` | Added `TestCopyIntoWorkareaContainment` (TC-044/045/046/047). Existing tests untouched. |
| `tests/test_tui_helpers.py` | Updated existing `test_copy_into_workarea_creates_unique_names` destination to `.s19tool/workarea/temp` so it satisfies the new containment guard. |
| `.dev-flow/03-increments/increment-001.md` | This review packet. |

File count: **5** (within the ≤5 cap).

## 3. How to test

Verification command (Linux CI + local):
```
pytest -q tests/test_tui_workspace.py
```

Manual Windows-only run for the junction probe TC-047 (per Q-N01 deferral; required before Phase 4 gate):
```
pytest -v tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_junction_rejected_on_windows
```

Broader sanity (workspace + helpers + public-API exports):
```
pytest -q tests/test_tui_workspace.py tests/test_tui_helpers.py tests/test_tui_public_api.py
```

## 4. Test results

Run on Windows 11 / Python 3.14.4 / pytest 9.0.3 (the Linux 3.11 CI run will execute the same TCs except TC-047 which `skipif`-skips):

```
$ pytest -q tests/test_tui_workspace.py
......                                                                   [100%]
6 passed in 0.34s
```

Verbose run of the new class confirms each TC ID:
```
$ pytest -v tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment
tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_destination_outside_workarea_rejected PASSED [ 25%]
tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_source_symlink_rejected PASSED [ 50%]
tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_source_size_over_cap_rejected PASSED [ 75%]
tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_junction_rejected_on_windows PASSED [100%]
4 passed in 0.42s
```

`test_tui_helpers.py` and `test_tui_public_api.py` still green:
```
$ pytest -q tests/test_tui_helpers.py tests/test_tui_public_api.py
..............................                                           [100%]
30 passed in 0.42s
```

**Important:** TC-047 PASSES on this Windows host (so the gate-closing manual run is satisfied here). On Linux CI (`ubuntu-latest`) TC-047 will report `SKIPPED` — that is by design per Q-N01.

A pre-existing TUI app test is now red — see §5 Risks for full disclosure.

## 5. Risks

- **Pre-existing test now failing by design — `tests/test_tui_app.py::test_save_project_writes_under_chosen_parent`.** This test was asserting the very behaviour LLR-005.3 forbids: saving a project to a user-chosen parent folder *outside* `.s19tool/workarea/` (it built `tmp_path/dest/P1/...`). The test now fails with `assert False` because `_handle_save_dialog` correctly rejects the unsafe destination via `WorkareaContainmentError` and returns without writing. This is the intended product-behaviour change. Updating that test would push the file count to 6 and break the ≤5-files cap, so it is intentionally deferred — see §6.
- **Save-dialog UX change.** `_handle_save_dialog` no longer accepts arbitrary `parent_folder` inputs. After this increment, the operator must save projects under `<base>/.s19tool/workarea/<project>` (which is what the production code path already constructs when `parent_folder` happens to be the workarea). A follow-up increment should update the Save Project modal to reflect this — either by hiding the parent-folder field, defaulting it to the workarea, or warning at submit time.
- **`Path.resolve()` performance.** `_path_traverses_reparse_point` walks every parent of the destination up to the workarea root. For deep destinations under `.s19tool/workarea/<project>/...` this is at most 2-4 components in practice, so the per-call overhead is one `os.lstat` per parent. No measurable impact for the load + save flows that copy a single file.
- **Backward-compatible callers.** Internal callers in `app.py` always pass `self.workarea / WORKAREA_TEMP` or `self.workarea / cleaned`, which are inside `.s19tool/workarea/` — these continue to succeed. No external callers are exposed via `s19_app.tui.__init__.__all__` beyond the existing `copy_into_workarea` symbol.
- **Edge case not covered: source-side reparse traversal in parent components.** The current implementation rejects when `source` itself is a reparse point and when its `resolve()`-d form is a reparse point, but does not walk every parent of the source like it does for the destination. Source-side parent-junction rejection would require similar traversal and is a candidate follow-up if the threat model expands. For this batch the documented attack surface (LLR-005.3 acceptance bullets) is fully covered.

## 6. Pending items

Deferrals folded in (per `.dev-flow/02-review.md` §Deferrals):

- **A-N02 — closure criterion stated.** Increment-1 closure criterion: *"Implementation lands; TC-044/045/046 green on Linux CI; TC-047 green on a manual Windows run with stdout attached to this packet."* All four are green on this Windows host (output captured in §4). The Linux-CI portion will be confirmed by the next CI run; capture and append the Linux output to this section once available.
- **Q-N01 — CLOSED.** Canonical Windows-host re-run of TC-047 attached below. The deferred re-execution requirement from `02-review.md` §Deferrals is satisfied.

  ```text
  $ python -m pytest -v tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_junction_rejected_on_windows
  ============================= test session starts =============================
  platform win32 -- Python 3.14.4, pytest-9.0.3, pluggy-1.6.0 -- C:\Python314\python.exe
  cachedir: .pytest_cache
  rootdir: C:\Users\jjgh8\OneDrive\Documents\Github\s19_app\.claude\worktrees\lucid-margulis-a63fd4
  configfile: pyproject.toml
  collecting ... collected 1 item

  tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_junction_rejected_on_windows PASSED [100%]

  ============================== 1 passed in 0.47s ==============================
  ```

  Captured 2026-05-07 on the canonical Windows host (Windows 11, Python 3.14.4, pytest 9.0.3). PASSED, exit 0. Closes Phase 2 blocker S-002 (NTFS-junction follow-through) at the canonical level.
- **S-N01 — confirmed.** Implementation uses `Path.is_symlink()` AND `os.lstat().st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT` on Windows; not `Path.resolve()` alone. See `_is_reparse_point` and `_path_traverses_reparse_point` in `s19_app/tui/workspace.py`.
- **S-N02 — confirmed.** The 256 MB cap rationale comment is in `workspace.py` next to `DEFAULT_COPY_SIZE_CAP_BYTES`, repeating the wording from finding S-N02.
- **S-N04 — actual file count: 5.** Source/test files modified: `s19_app/tui/workspace.py`, `s19_app/tui/app.py`, `tests/test_tui_workspace.py`, `tests/test_tui_helpers.py`. Plus this review packet = 5 total. The deferral predicted ≥4 source/test files; final count is 4 source/test + 1 packet = 5. Within cap.

Items deferred to follow-up increments (NOT this increment's scope):

- **`tests/test_tui_app.py::test_save_project_writes_under_chosen_parent` — needs to be updated** to either (a) save into `<base>/.s19tool/workarea/<project>` (the new contract) or (b) be replaced with a positive test asserting `WorkareaContainmentError` propagation from the save dialog when the operator points it at an unsafe parent. Recommend (a) for minimum-viable closure. Single-file edit; ≤10 lines.
- **Save Project modal UX update.** `s19_app/tui/screens.py` exposes a `parent_folder` field; with the new containment rule that field's value is meaningful only when it points into `.s19tool/workarea/`. Deferred to a UX-only increment that does NOT touch `workspace.py`.
- **Source-side parent-component reparse walk.** As noted in §5 Risks, a defence-in-depth follow-up.

## 7. Suggested next task

**Phase 3 increment 2 — fixtures + Textual snapshot infrastructure** (per `.dev-flow/02-review.md` iter-2 §6.3 R-9 / R-7).

Scope (≤5 files):
- `tests/fixtures/overlap_s19_hex/` — minimal S19 + Intel HEX with overlapping ranges (TC-062.a).
- `tests/fixtures/duplicate_alias_mac/` — MAC file with duplicate-address alias (TC-062.g).
- `tests/fixtures/corrupt_records/` — small artefacts with intentional record corruption (TC-062.h).
- `tests/conftest.py` — register the three new fixtures alongside the existing `large_*` generators.
- `tests/test_tui_app.py` — add the snapshot harness skeleton (likely `App.run_test()` plus a query against the Issues panel widget), parametrised over the eight cross-file incompatibility classes (TC-064/065).

This unblocks the LLR-007.2 / LLR-007.4 work in increments 3 and 5. It is also a "no-behaviour-change" increment (test infrastructure only), which makes it the safest follow-up to the present product change.

The pre-existing `test_save_project_writes_under_chosen_parent` regression should be folded into one of the following increments as a single-file test fix (its breakage is documented in §5 above and does not block increment 2's scope).
