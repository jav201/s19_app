# E4 notes — G-D (a2l.py progress callback)

Implementer notes for the G-D nodes of Inc 12b (proto-12b-a2l-refusal.md).
Edited file: `s19_app/tui/a2l.py` only (the brief said `s19_app/a2l.py`, which does
not exist; the canonical module is `s19_app/tui/a2l.py` — see Deviations).

## Functions changed

- `build_section_tree` — signature gains `progress: Optional[A2LProgress] = None`;
  reports `(bytes_consumed, total_bytes)` every 4 096 lines and once after the read.
- `parse_a2l_file` — signature gains `progress: Optional[A2LProgress] = None`;
  forwards it to `build_section_tree(path, progress)`; nothing else changes.
- (data) `A2LProgress = Callable[[int, int], None]` and `_PROGRESS_LINES = 4096`
  added at module level.
- (imports) `import os` added; `Callable` added to the `typing` import.

## Graph nodes -> code location

- `A2LProgress` -> `s19_app/tui/a2l.py:145` (after `logger = logging.getLogger(__name__)`).
- `_PROGRESS_LINES` -> `s19_app/tui/a2l.py:151`.
- `build_section_tree` (changed) -> `a2l.py:154` (signature and docstring);
  step (1) `total = os.fstat(handle.fileno()).st_size` -> `a2l.py:194` (first
  statement inside the `with`); step (2) the every-4096-lines report ->
  `a2l.py:196-197` (first statement of the `for` body); step (3) the final
  `progress(total, total)` -> `a2l.py:229-230` (after the loop, still inside the
  `with`, no `finally`). Docstring: `Args` gains `progress` (line 161-162),
  `Data Flow` gains the report line (line 171), `Dependencies.Uses` gains
  `os.fstat` (line 179).
- `parse_a2l_file` (changed) -> `a2l.py:2649` (signature); the call
  `build_section_tree(path, progress)` -> `a2l.py:2681`; docstring `Args` gains
  `progress` (line 2656-2657). No other change.
- `tests/test_engine_unchanged.py::_ENGINE_PATHS` -> NOT implemented here (out of
  scope for this implementer; see Deviations).

## Deviations

1. **Brief's file path.** The brief names `s19_app/a2l.py`, but that file does not
   exist. The canonical module (per interfaces-12b.md, proto-12b-a2l-refusal.md and
   CLAUDE.md) is `s19_app/tui/a2l.py`, so that is the file edited. The compile
   check ran as `py_compile s19_app/tui/a2l.py`. No `s19_app/a2l.py` was created.
2. **Test-list node out of scope.** The G-D node
   `tests/test_engine_unchanged.py::_ENGINE_PATHS` (unfreeze entry, D12b-05) is a
   test-file edit. The brief forbids editing tests ("Do NOT edit tests, other
   source files"). It is therefore left untouched and remains owed by whoever owns
   that file (LLR-176.4b). No production behaviour depends on it.
3. None other. All three implemented nodes follow the graph exactly; no silent
   divergence.

## Verification (manual, not the test suite)

- `py_compile s19_app/tui/a2l.py` -> OK.
- case_01 (1 444 B, 53 lines) with callback -> exactly 1 call `(1444, 1444)`;
  sections identical with/without callback; `parse_a2l_file` dict identical with
  and without callback (3 tags).
- case_06 (37 742 888 B) with callback -> 254 calls, first `(147456, 37742888)`,
  last `(37742888, 37742888)`, non-decreasing, totals equal (matches D12b-01).
- missing file with callback -> `errors == ['File not found.']`, 0 calls.
