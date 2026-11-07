# Task: write Inc 1a's two E4 handoffs (DeepSeek v4 Pro)

Write two files in `C:\Users\jjgh8\Github\s19_app-b103\.dev-flow\2026-11-05-batch-103\inc-1a\`:
- `E4-handoff-impl-1a.md`, for the implementer;
- `E4-handoff-tests-1a.md`, for an independent tester.

Copy the structure, rules and wording of the Inc 2a handoffs exactly. They are read-only templates:
- `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code\.dev-flow\2026-11-05-batch-103\inc-2\E4-handoff-impl-2a.md`
- `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code\.dev-flow\2026-11-05-batch-103\inc-2\E4-handoff-tests-2a.md`

Adapt them to Inc 1a, the clipboard core, using these sources:
- `inc-1a/01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `E2-rulings.md`, `E3-rulings.md` (all sections) and `codewire/graph-inc1a.md` (or the graph file in `inc-1a/codewire/`);
- `PLAN.md`, the Inc 1a row, I-1 and amendment A1.

Facts each handoff must state:
- **Worktrees:**
  - implementer: `C:\Users\jjgh8\Github\s19_app-b103-inc1a-code`, branch `b103-inc1a-code`;
  - tester: `C:\Users\jjgh8\Github\s19_app-b103-inc1a-tests`, branch `b103-inc1a-tests`;
  - both start from `batch-103`.
- **Source files:** exactly those `E1-slice.md` names for 1a (`os_clipboard_input.py`, `capped_text_area.py`, `.github/workflows/tui-ci.yml`, as the slice says). Respect the 4-source-file cap.
- **Runner:** cachyos-rtx only (`ssh -o BatchMode=yes javiergr@192.168.1.67 "bash -lc '…'"`), Python `~/miniconda3/envs/s19ci/bin/python`. **Xvfb 21.1.25 and xclip 0.13 are installed.** Run every Linux clipboard test inside a **private** Xvfb display (`Xvfb :<free n>` or `xvfb-run -a`), never the host's display or clipboard. Isolate HOME, XDG and LOCALAPPDATA in a directory named `zq_iso_user`. Kill processes by PID only.
- **Never write the operator's clipboard. Never run tests on the Windows PC.** The Windows/PowerShell layer is verified only by the `windows-latest` CI job, after a redacted push that the orchestrator does later. The tester marks those cases `partial (Windows CI pending)`.
- **RED/GREEN, transcripts, commits:** as the templates say. The test commit message is `batch-103 Inc 1a E4: tests (independent tester)`.

Do not edit any other file and do not commit. At the end, report in at most 100 words what you adapted and any fact you could not find.
