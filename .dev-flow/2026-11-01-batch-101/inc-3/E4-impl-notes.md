# Inc 3 - E4 implementer notes

## Functions changed
- s19_app/tui/services/project_gather_service.py: gather_project_artifacts (composition limb) - skips a name whose exact text was already checked (set `checked_names`); check is `Path(os.path.normpath(resolved_project / name)).is_file()`, no `.resolve()`.
- s19_app/tui/app.py: S19TuiApp._sync_loaded_file_to_project - removed `project_dir.mkdir(parents=True, exist_ok=True)`.
- s19_app/tui/app.py: S19TuiApp._sync_loaded_a2l_to_project - same removal.

## Deviations
None. Files use CRLF; edits preserved it. Tests untouched. N-2 (NUL name) is a graph/doc addendum, no code change (is_file() returns False for ValueError).

## Smoke
s19_app.__file__ = this worktree. `import s19_app.tui.app` ok. Existing tests/test_project_gather.py, test_b100_workers.py, test_b100_active_variant.py: 155 passed, 1 xfailed (pre-existing xfail) in 22m50s. No failures, so TC-B100-54 (docstring-only change owed by tester) still passes. TC-B100-20 save-project 0.909 s / 1.0 s (LOW margin, run in a full non-serial run). Transcript: .dev-flow/2026-11-01-batch-101/evidence/inc-3/impl-smoke.txt. No pytest left running; nothing committed.
