# fast-dev-flow spec — batch 42 — Fix TUI logging-handler leak

- **Status:** closed 2026-07-13 (AC-1/2/3 green; full gate `1395 passed / 2 skipped / 3 xfailed / 0 failed`; RED-first shown; 0 frozen diffs; C-27 dual-guard clean; no security flags)
- **Created:** 2026-07-13
- **Branch:** `claude/batch-42-fix-logging-leak` @ `ffe7f2f` (= origin/main tip; RC-1 clean, merge-base == origin/main)
- **Route:** /fast-dev-flow · **Run mode:** autonomous + self-merge (operator-stated, batch-42 kickoff). Decisions → MEMORY.md at close.
- **security_required:** FALSE — logging-handler lifecycle only; no untrusted input/auth/secret/external surface. (`log`/`credential`/`secret` do not appear in scope in a sensitive sense.)
- **Origin:** the `/diagnose` spike (this session) root-caused the standing "pre-existing full-suite TUI global-state flake".

## 1. Objective

Fix the unbounded `RotatingFileHandler` accumulation on the process-global `s19tui` logger — the proven root cause of the intermittent full-suite TUI flake — so the handler set is bounded to one per process.

## 2. Root cause (proven by the spike, deterministic harness)

`setup_logging` ([workspace.py:53](s19_app/tui/workspace.py:53)) is called from `S19TuiApp.__init__` ([app.py:878](s19_app/tui/app.py:878)) on **every** app construction. It attaches a `RotatingFileHandler` to `logging.getLogger("s19tui")` (process-global) and its dedup guard only skips when a handler with the **same** `baseFilename` exists. Every test uses a distinct `tmp_path`, so the guard never matches → handlers accumulate 1:1 with app constructions, never removed/closed. Harness: 40 calls → 40 handlers; per-`info()` cost 15µs(N=1) → 5,765µs(N=500), linear. Across ~1000 TUI tests the logger reaches thousands of handlers → O(N) log fanout → progressive slowdown → intermittent `pilot`/`WaitForScreenTimeout` failures ("different unrelated test fails each run; passes in isolation"). Windows secondary: open handles block `tmp_path` cleanup.

## 3. Acceptance criteria (observable)

- **AC-1 (no cross-path accumulation — RED-first):** When `setup_logging` is called with N distinct `base_dir`s in one process, the `s19tui` logger retains exactly **1** `RotatingFileHandler`, pointing at the last `base_dir`. RED pre-fix: N calls → N handlers (`assert len == 1` fails, got N).
- **AC-2 (same-path idempotency preserved):** repeated `setup_logging` with the SAME `base_dir` still keeps exactly 1 handler for that path (the existing `test_setup_logging_reuses_handler_for_same_path` / `test_tc_049_handler_reuse_does_not_duplicate` stay green).
- **AC-3 (production behavior intact):** logging still writes to `base_dir/.s19tool/logs/s19tui.log`; the retained handler keeps the 5 MB `maxBytes` / `backupCount>=1` config (existing `test_tc_049_rotating_handler_config` stays green).

## 4. Validation strategy

RED-first unit test at the correct seam (`setup_logging` with N distinct base_dirs, assert handler count == 1) shown failing pre-fix, green post-fix. Existing same-path reuse + config tests confirm no regression. Full gate `pytest -q -m "not slow"` + C-27 dual-guard (workspace.py is NOT frozen — 0 frozen diffs expected). Optional: a broad TUI-file re-run to sanity-check the flake surface, but the deterministic unit AC is the primary evidence.

## 5. Non-goals

- No autouse conftest fixture to reset the logger — the production fix bounds handlers to 1, which fully resolves the leak; a test-side reset is redundant. (Noted as optional hardening if ever needed.)
- No change to log format, path, rotation size, or the `S19TuiApp.__init__` call site.
- No engine-frozen module.

## 6. Detected security flags

`security_required: false`. Logging-handler lifecycle only; no sensitive pattern fires meaningfully.

## 7. Increment plan (1 increment, 2 files)

1. **Inc-1:** `s19_app/tui/workspace.py::setup_logging` — before adding, remove+close any `RotatingFileHandler` on `s19tui` whose `baseFilename != str(log_path)` (keep same-path as idempotent no-op); add one if none matches. `tests/test_tui_workspace.py` — new RED-first `test_setup_logging_does_not_accumulate_handlers_across_distinct_base_dirs` (AC-1). AC-2/AC-3 via existing tests.

## 8. Batch status

| Field | Value |
|-------|-------|
| Current phase | closed |
| Started | 2026-07-13 |
| Closed | 2026-07-13 |
| Promoted to /dev-flow | no |
| Notes | RC-1 clean; branch in main repo dir; origin = /diagnose spike |

## 9. Close

### What changed
`setup_logging` ([workspace.py:53](s19_app/tui/workspace.py:53)) now bounds the process-global `s19tui` logger to a single `RotatingFileHandler`: before adding, it removes + closes any handler bound to a different `baseFilename` (keeping the same-path handler as an idempotent no-op). This stops the unbounded per-app-construction accumulation that was the root cause of the intermittent full-suite TUI flake. Production is unaffected (one app/process never accumulated); only the test process leaked.

### How it was tested
- RED-first: new `test_setup_logging_does_not_accumulate_handlers_across_distinct_base_dirs` failed pre-fix (`expected 1, got 10`), passes post-fix.
- Existing same-path reuse + rotating-config tests stay green (AC-2/AC-3) — `test_tui_workspace.py` 34 passed.
- Full gate `pytest -q -m "not slow"`: **1395 passed / 2 skipped / 3 xfailed / 0 failed** (+1 test). C-27 dual-guard clean (workspace.py not frozen). ruff clean.

### Open risks / pending
- None. The fix is O(1) and safe (apps are sequential in tests, single in production).

### Security flags — handling
`security_required: false`. Logging-handler lifecycle only.

### Suggested commit message
```
fix(tui): batch-42 — bound s19tui logger to one handler (fix full-suite global-state flake)
```
