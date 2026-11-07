# Task: write Inc 11's two E4 handoffs (DeepSeek v4 Pro)

Write two files in `C:\Users\jjgh8\Github\s19_app-b103\.dev-flow\2026-11-05-batch-103\inc-11\`:
- `E4-handoff-impl-11.md`, for the implementer;
- `E4-handoff-tests-11.md`, for an independent tester.

Copy the structure, rules and wording of the Inc 2a handoffs exactly. They are read-only templates:
- `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code\.dev-flow\2026-11-05-batch-103\inc-2\E4-handoff-impl-2a.md`
- `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code\.dev-flow\2026-11-05-batch-103\inc-2\E4-handoff-tests-2a.md`

Adapt them to Inc 11, the A2L reader (`s19_app/tui/a2l.py`, unfrozen by amendment A2), using these sources: `inc-11/01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `E2-rulings.md`, `E3-rulings.md` (all sections, the orchestrator addendum for READ.66's 256 cap and READ.69 included) and `codewire/graph-inc11.md`; plus `PLAN.md` (the Inc 11 row and amendment A2) and `design/a2l-corpus/` (derived corpus data only).

Facts each handoff must state:
- **Worktrees:**
  - implementer: `C:\Users\jjgh8\Github\s19_app-b103-inc11-code`, branch `b103-inc11-code`;
  - tester: `C:\Users\jjgh8\Github\s19_app-b103-inc11-tests`, branch `b103-inc11-tests`;
  - both start from `batch-103`.
- **Source files:** exactly those `E1-slice.md` names for Inc 11 (`a2l.py`, `a2l_extract.py`, `a2l_definition.py` where its rows say so). Respect the 4-source-file cap.
- **Runner:** cachyos-rtx only (`ssh -o BatchMode=yes javiergr@192.168.1.67 "bash -lc '…'"`), Python `/home/javiergr/miniconda3/envs/s19ci/bin/python` (an absolute path, because HOME is changed). Isolate HOME, XDG and LOCALAPPDATA in a directory named `zq_iso_user`. Kill processes by PID only. The public corpus `~/a2l-corpus/files` is read-only, and only derived numbers may leave it.
- **The operator's proprietary A2L fragment does not exist in any file, and none may be created.**
- **On this PC run only `py_compile` and `codewire_extract.py`.** Run no other Python, standalone checks included.
- **Timing:** READ.52 (≤ 1.5× on the 19.8 MB file) and every timed row use `serial_timing`, GC off, least of ≥ 15 runs, and record the host load.
- **RED/GREEN, transcripts, commits:** as the templates say. The test commit message is `batch-103 Inc 11 E4: tests (independent tester)`.

Do not edit any other file and do not commit. At the end, report in at most 100 words what you adapted and any fact you could not find.
