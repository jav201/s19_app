# E5 brief — rules common to every batch-103 E5 agent (2026-11-07)

Stage E5 of `dev-flow-v3-beta` (`C:\Users\<user>\.claude\skills\dev-flow-v3-beta\SKILL.md` — read E4 and E5): validate the change of ONE increment. Regression belongs to the batch end.

## The change under validation
- Integrated branch and worktree: `C:\Users\<user>\Github\s19_app-b103-inc<N>-code` (branch `b103-inc<N>-code`, implementer commit + tester commit merged; the GREEN integration evidence is in `.dev-flow/2026-11-05-batch-103/inc-<N>/evidence-e4/`).
- The diff to validate: `git diff a2043cfd HEAD -- s19_app tests` in that worktree (`a2043cfd` = the base: `main` `e07fb00` product tree + batch-103 records).
- Records: `inc-<N>/01-requirements.md`, `02-test-cases.md`, `E1-rulings.md`, `E3-rulings.md`, `E1-slice.md`, `codewire/graph-inc<N>.md`.
- Integrated tree on the Linux runner: `~/work/b103-int<N>` on <runner> (`ssh -o BatchMode=yes <user>@<runner-ip> "bash -lc '…'"`, fish login shell). **Read-only for you:** copy it before any change (`cp -a ~/work/b103-int<N> /tmp/b103-e5-<N>-<role>/tree`), never edit it. Python `~/miniconda3/envs/s19ci/bin/python`. Set `HOME`, `XDG_*`, `LOCALAPPDATA` to a fresh dir whose basename is not `home` (e.g. `/tmp/b103-e5-<N>-<role>/<user>`) and `PYTHONDONTWRITEBYTECODE=1`. Print `s19_app.__file__` at the top of every transcript.

## Rules
- On this Windows PC: read, grep, `py_compile`, `codewire_extract.py` only. No pytest, no app, no script importing `s19_app`.
- Write only your own output file(s) in `inc-<N>/` of the code worktree (named in your brief) and one start + one end line in `inc-<N>/steps.log`. No git command that writes. Never push. Never touch any clipboard. Never write the operator's name.
- Every finding: a severity (CRITICAL / HIGH / MAJOR / MEDIUM / MINOR / LOW / INFO), `file:line`, the requirement or case it touches, a concrete fix, and a tag **`impl`** (the code departs from the approved design) or **`design-gap`** (the design itself misses it; the fix also updates the requirement and the graph).
- English. Evidence is tool output saved to files, never typed.
