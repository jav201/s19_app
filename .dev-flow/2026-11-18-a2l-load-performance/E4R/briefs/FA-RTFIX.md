# FA-RTFIX — close the FA-RT trace gaps on the merge tree (orchestrator · Opus edit agent)

No agent edits `~/.claude/skills`. Edit-only on the PC (no pytest, HT-01); scripted check on rtx.

## Source
FA-RT case 3 on the merge tree 78f61c42 (`checks/RT-merge-78f61c42.md`): trace_check with base 6eccf0cb (Front A's own delta on top of Front B) = 17 gaps — CASE 12 (`E4R/02-test-cases.md` cases not in `<id>/<n>` form; no case lines for R-TST-011/019/026), SLICE 4 (`core.py`, `validation/engine.py`, `issues_checks.py`, `a2l_service.py` named only in RECORD.md), EVID 1 (`E4R/04-validation.md`, written at the batch close).

## Scope (4 files)
1. `E4R/02-test-cases.md`: case lines `<id>/<n>` per verifying node, incl. R-TST-011/019/026 and R-A2L-REFRESH.054.
2. `E4R/01-requirements.md`: slice rows for the four files, mapped to the rows their Front A change implements.
3. `tests/test_alp_s19_read_once.py`: rename the node that carries the absorbed id LLR-154.1; docstring re-cites R-READ-002, R-READ-007.1, R-READ-007.3, R-PARSE-002, R-READ-006.1, R-READ-001.1.
4. `tests/test_alp_inc2_a2l_attach.py`: docstring re-cites (AT-ALP-I2-1 → .031/.035; AT-ALP-I2-3 → .037); the two HLR-176 comments get the successor row or lose the id. No assertion change.

## Done
trace_check (base 6eccf0cb) shows 0 CASE and 0 SLICE gaps; only EVID remains.
