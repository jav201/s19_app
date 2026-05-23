# Increment 1.5 — Save-project test alignment with LLR-005.3

**Phase:** 3 — Implementation
**Increment:** 1.5 of N (follow-up to increment 1)
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR target:** LLR-005.3 (alignment of pre-existing test with the new contract)
**Closes:** the single test regression disclosed in `increment-001.md` §5 / §6.

## 1. What changed

- `tests/test_tui_app.py::test_save_project_writes_under_chosen_parent` was asserting the unsafe behaviour LLR-005.3 forbids (saving a project to an arbitrary parent outside `.s19tool/workarea/`). After increment 1, `_handle_save_dialog` correctly rejects such destinations via `WorkareaContainmentError`, so the test was failing.
- Renamed to `test_save_project_writes_under_workarea` and updated the test body to set `parent = ensure` (the workarea) instead of `tmp_path / "dest"`. Added a 3-line comment citing LLR-005.3 / increment 1.5 for future readers.
- Assertions unchanged in shape — `(parent / "P1" / "data.mac")` still resolves to the saved file, just now inside the workarea.

## 2. Files modified

| File | Change |
|---|---|
| `tests/test_tui_app.py` | Renamed and updated `test_save_project_writes_under_chosen_parent` → `test_save_project_writes_under_workarea`; `parent = ensure` (workarea) instead of `tmp_path / "dest"`. ~10-line diff. |
| `.dev-flow/03-increments/increment-001-5.md` | This review packet. |

File count: **2** (within the ≤5 cap).

## 3. How to test

```
pytest -q tests/
```

## 4. Test results

Run on Windows 11 / Python 3.14.4 / pytest 9.0.3:

```
$ python -m pytest -q tests/
......ss................................................................ [ 39%]
........................................................................ [ 79%]
......................................                                   [100%]
180 passed, 2 skipped in 2.56s
```

- **180 passed** (was 179 in increment 1 with 1 failure; net +1).
- **2 skipped** (TC-047 junction probe on non-Windows, and one other pre-existing skip).
- **0 failed.** Green CI restored.

## 5. Risks

- **None new.** The test now exercises the positive containment path — saving into `.s19tool/workarea/<project>` succeeds. No product behaviour was changed in this increment.
- **Save Project modal UX still pending** (per `increment-001.md` §6, deferred): the `parent_folder` field in the modal is now meaningful only when it points into `.s19tool/workarea/`. A UX-only follow-up increment can update the modal to either default to the workarea or warn at submit time. Out of scope for this increment.

## 6. Pending items

- **Save Project modal UX** — deferred (see above). Recommend folding into a future TUI-only increment, NOT increment 2 (which is fixtures + snapshot infra).
- **Linux-CI portion of TC-044/045/046** (per `increment-001.md` A-N02 closure criterion) — to be confirmed on the next CI run; capture and append to `increment-001.md` §6 when available.

## 7. Suggested next task

Unchanged from `increment-001.md` §7 — **Phase 3 increment 2: per-class fixtures + Textual snapshot infrastructure** (closes R-7 / R-9 / Q-N04). Scope and file plan documented in `increment-001.md` §7.
