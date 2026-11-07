# E3 brief — rules common to every batch-103 E3 reviewer (2026-11-06)

You review ONE increment's design of s19_app batch-103 under `dev-flow-v3-beta`, with no code: the requirements, the Code-Wire graph and the real callers. Goal of the stage: no open finding of MAJOR, HIGH or worse on the design.

## Read first
1. `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` (E1–E4).
2. The increment's records: `inc-<N>/01-requirements.md`, `02-test-cases.md`, `E1-rulings.md` (with every "Orchestrator rulings" / "Operator rulings" section at its end — they override the PROPOSED rows above), `E1-slice.md`, `codewire/graph-inc<N>.md`, any `E2-rulings.md`, and the evidence folders.
3. `.dev-flow/2026-11-05-batch-103/PLAN.md` (interfaces I-1..I-5, amendment A1), `REQUIREMENTS.md` "Rules for every row" and the cited modules, `CLAUDE.md`, `PROJECT_RULES.md`.
4. Code-Wire v3.1.0 core (`C:\Users\jjgh8\Github\code-wire`, `docs/Metodologia.md`): examples from the requirement, real callers from `tools/codewire_extract.py`, a test that fails before the change.
5. Format example: `git show b101-inc12:.dev-flow/2026-11-01-batch-101/inc-12/E3-architect.md` (and `E3-security.md`).

## What you check
- Every requirement: strict EARS (5 forms, one `shall`, subject "the system", observable only), ISO/IEC/IEEE 29148 qualities, a numeric threshold, a negative control that would really turn its test RED, exact message texts.
- The graph against the requirements and the base code: each node's contract matches its rows; each example follows from a row's threshold; callers are real (re-run the extractor where you doubt); interfaces are pinned and consumers (later increments named in the PLAN) can use them; nothing contradicts a canon row without a ruling.
- Test cases: each is writable as a test that fails on base and passes after; `full` is possible (the product itself produces what is asserted).
- Your lens (architect or security — your brief says which).

## Output
`inc-<N>/E3-<role>.md`: verdict first (**PASS**, **PASS-WITH-NOTES** or **FAIL**), then a findings table: id (`E3<role-letter>-NN`), severity (CRITICAL / HIGH / MAJOR / MEDIUM / MINOR / LOW / INFO), the requirement / node / case it is about with `file:line`, the defect, and a concrete fix (prefer removing a feature over guarding it). Answer every question the records route to E3 explicitly. One start and one end line in `inc-<N>/steps.log`.

## Rules
- Read-only everywhere except your one output file and the steps.log lines. No git command that writes. Do not edit the records — the orchestrator rules and a correction pass edits.
- Platform and safety: as `design/E1-brief-common.md` ("Platform and safety rules"): on this PC only read, grep, `py_compile`, `codewire_extract.py`; anything importing `s19_app` on cachyos-rtx (`/tmp/b103-e3-<N>-<role>/`), never a clipboard, never the operator's name. English.
- A correction pass may be running on the same increment's `02-test-cases.md` while you read (the orchestrator's accepted E2 case fixes); judge the cases by the graph's corrected inputs where the rulings say so.

## Report (≤ 250 words)
Verdict, count of findings by severity, the MAJOR-or-worse ones in one line each, time spent.
