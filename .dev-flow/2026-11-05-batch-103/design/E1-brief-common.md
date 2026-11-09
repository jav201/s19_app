# E1 brief — rules common to every batch-103 E1 agent (2026-11-06)

You write the E1 records (requirements) of ONE increment of s19_app batch-103 under `dev-flow-v3-beta`. The orchestrator (main session) rules on every open decision; you propose, you do not decide scope alone.

## Read first

1. `C:\Users\<user>\.claude\skills\dev-flow-v3-beta\SKILL.md` — whole (85 lines). E1 is your stage; read E2–E5 too so your thresholds and negative controls can be tested.
2. `.dev-flow/2026-11-05-batch-103/PLAN.md` — commission (US-103-01..05), your increment's row, shared interfaces I-1..I-5, amendment A1, test platform.
3. `CLAUDE.md`, `PROJECT_RULES.md` at the repo root.
4. `REQUIREMENTS.md` — the canon. Read its "Rules for every row" and "Modules" sections, then the module(s) your brief names. Rows use the canon's form and ids.
5. Format example (latest batch, same flow): `git show b101-inc12:.dev-flow/2026-11-01-batch-101/inc-12/01-requirements.md` (and `E1-rulings.md`, `E1-slice.md`, `02-test-cases.md` beside it). Copy the layout, not the content.

## Where you work

- Worktree `C:\Users\<user>\Github\s19_app-b103`, branch `batch-103` = `main` `e07fb00` + batch-103 records. Read-only everywhere except your own folder.
- Write ONLY in `.dev-flow/2026-11-05-batch-103/inc-<N>/` (your N is in your brief). Other E1 agents run in parallel in sibling folders; never touch them.
- Do not commit, stage or run any git command that writes (the orchestrator commits at stage end). `git show`, `git grep`, `git log` on any branch are fine; never check out a `b101-*` branch.

## Outputs (in `inc-<N>/`)

- `01-requirements.md` — user stories of the increment (each naming its US-103-xx), definitions (terms and formats only), the requirement table: Id · Form · Requirement · Threshold · Negative control · US · Status (changed / new / retired) · Base (what `e07fb00` does today, and how you know: C = census script, B = pilot run, R = read in the code).
- `02-test-cases.md` — one case per coverage item (`<requirement id>/<n>`): objective ("Verify that …"), class (normal / robustness), preconditions, inputs, expected result as the requirement's exact values or text. Leave Tests empty, Coverage `gap`, Result `not_run` — testers fill them at E4.
- `E1-rulings.md` — every change to an existing canon row with its reason, and every open decision as **PROPOSED — awaiting orchestrator ruling**: options (A/B/…), consequence of each, your recommendation.
- `E1-slice.md` — the functions to add or change, counted, each mapped to its requirement ids; for an existing function, its real callers from `python C:\Users\<user>\Github\code-wire\tools\codewire_extract.py` (Code-Wire v3.1.0; check `git -C C:\Users\<user>\Github\code-wire describe --tags` = `v3.1.0`). Line numbers are "as of `e07fb00`".
- `evidence-e1/` — any census or pilot script and its transcript (tool output, never typed by hand).
- `steps.log` — one line at start and one at end: ISO timestamp, stage, model.

## Requirement rules (non-negotiable)

- Strict EARS, five forms only, one `shall`, subject "the system", observable behaviour only (never a function, file or test name in the statement). ISO/IEC/IEEE 29148 qualities. Every failure path its own `If … then …` row. Messages fix their exact text with `<placeholders>`.
- Each row: a numeric threshold and a negative control (a mutant that turns its test RED).
- Fix defects in existing canon rows in place (split keeps the parent id with `.1`, `.2`) and record each in `E1-rulings.md`. Never change a requirement to match the code.
- New ids: use only the id family your brief assigns, and confirm each id is unused in `REQUIREMENTS.md`, `docs/requirements/review/`, `C:\Users\<user>\Github\s19w\review\`, every `.dev-flow/*/` folder, and the open batch-101 branches (`git grep <id> b101-inc9 b101-inc10 b101-inc12`).
- Before a requirement depends on an input (a key, a terminal feature, a system call), cite evidence that it reaches the app on the target platform, or mark it as a proposal that needs a pilot.
- Cap: about 80 requirements per increment. If your estimate goes past it, stop and propose a split in `E1-rulings.md`.

## Platform and safety rules (operator, 2026-11-05/06)

- **On this PC (Windows) you may only read, grep, `python -m py_compile` and run `codewire_extract.py`.** No pytest, no app, no probe, no script that imports `s19_app` here.
- Any census or pilot that imports `s19_app` or runs the app goes to the Linux runner **<runner>**:
  `ssh -o BatchMode=yes <user>@<runner-ip> "bash -lc '<cmd>'"` (login shell is fish; always wrap in `bash -lc`). Python: `~/miniconda3/envs/s19ci/bin/python` (3.11.18, textual 8.2.8). Repo clone: `~/work/s19_app`, detached at `e07fb00` — **read-only: never edit, checkout or reset it**. Put scripts and outputs in `/tmp/b103-e1-<N>/` there; copy scripts and transcripts back with `ssh … cat` into your `evidence-e1/`. Set `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` and `LOCALAPPDATA` to a fresh dir under `/tmp/b103-e1-<N>/` whose basename is NOT `home` (two law guards read the account name from `HOME`; use e.g. `<user>`). Print `s19_app.__file__` at the top of every transcript. That host has no X display and no Xvfb yet: nothing may touch any clipboard.
- Never write the OS clipboard anywhere, never use the real `%LOCALAPPDATA%`, never "save and restore" a clipboard.
- Never write the operator's name in any file; use `username_subject` if a person is needed.
- Records in English. No secrets, no keys printed.

## Stop and report

When the four records are written, stop and report (≤ 300 words): row count (new / changed / retired), slice count, the PROPOSED decisions (one line each with your recommendation), evidence files, anything you could not check, and the time you spent.
