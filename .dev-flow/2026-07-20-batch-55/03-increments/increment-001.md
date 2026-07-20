# Increment 1 — UNFREEZE `a2l.py` (LLR-P1b.7 / TC-141)

**BLUF: APPROVED.** `s19_app/tui/a2l.py` removed from BOTH `_ENGINE_PATHS` guard tuples; NOTE blocks swapped to batch-55 unfreeze wording; `a2l.py` itself untouched. Guard tests 11 passed / exit 0. Enables the Inc-2 summer edit in the same PR (C-27 corollary).

1. **What changed** — removed the `"s19_app/tui/a2l.py"` entry from `_ENGINE_PATHS` in both C-27 guard files + replaced the RE-FROZEN NOTE with a batch-55 UNFROZEN note.
2. **Files modified (2)** — `tests/test_engine_unchanged.py` (TC-027 source guard), `tests/test_tui_directionb.py` (TC-031 source guard). `a2l.py` NOT touched; `_ENGINE_TEST_FILES` (tc032) NOT touched.
3. **How to test** — `pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "engine or tc031 or tc032 or tc027"`.
4. **Test results** — `11 passed, 164 deselected in 2.53s`, EXIT=0. AST check: 0 `a2l.py` entries in either `_ENGINE_PATHS`. tc031/tc027 pass (a2l.py unfrozen); tc032 green (no test-file changed).
5. **Independent review (inline, orchestrator)** — diff verified: exactly the two tuple removals + NOTE swaps, nothing else; `git diff --stat -- s19_app/tui/a2l.py` empty. Proportionate inline review for a mechanical guard-list edit mirroring batch-54 Inc-1 (avoids the batch-49 hung-reviewer failure mode; C-33).
6. **Risks** — guard is OPEN on `a2l.py` until PR-B re-freeze; the post-merge re-freeze must land (batch-50 P-2 pattern).
7. **Pending** — Inc-2 (the summer + tests + REQUIREMENTS.md prose + AT-102 supersession).

**Gate axes:** Coverage (TC-141 satisfied) · Certainty (0 a2l.py entries verified 2 ways) · Evidence (pytest 11/0 exit0 + diff cited). Met → approve.
