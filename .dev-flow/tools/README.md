# dev-flow artifact completeness gate (`validate_phase_artifacts.py`)

A **shift-left** of the `/dev-flow-sync` template-completeness reject-check (RC-1).
That check today runs only inside the `/dev-flow-sync` skill — i.e. once, at the
very end of a batch. This gate runs the same **structural detect** at **commit
time** (as a Claude Code PreToolUse hook), so an incomplete phase artifact is
caught before it lands in a commit instead of at end-of-batch sync.

- Script: [`validate_phase_artifacts.py`](validate_phase_artifacts.py) — stdlib only, no dependencies.
- Wired in: `.claude/settings.json` → `hooks.PreToolUse` (matcher `Bash`).

## What it enforces

It runs over the batch directory named by `.dev-flow/state.json` (`batch_id`),
**only when `current_phase >= 4`** (artifacts should be filled by then). Each
artifact is checked only once its owning phase should be complete:

| Artifact | Checked when |
|----------|--------------|
| `01-requirements.md` | phase ≥ 1 |
| `02-review.md` | phase ≥ 2 |
| `04-validation.md` | phase ≥ 4 |
| `05-postmortem.md` | phase ≥ 5 |
| `06-docs/**/*.md` | phase ≥ 6 |

A file that does not exist yet is skipped — the gate never *requires* a file, it
only flags files that ARE present but structurally blank.

### Blocker rules (structural — matches unfilled *structure*, not token substrings)

1. **Empty required structure**
   - A required table reduced to its header + separator row with **zero data rows**.
   - A required `##`/`###` section whose body is empty or contains **only** the
     template's italic guidance `*(…)*`. (A pure container heading — one whose
     next heading is a deeper child, e.g. `##` → `###` — is not flagged; its
     children are checked in their own right.)
   - A `04-validation.md` carrying **no verdict token** (`PASS` / `FAIL` /
     `PASS-WITH-NOTES`) **AND no** per-requirement results table.
2. **Live placeholder tokens** — any of
   `<PROJECT>` `<BATCH_ID>` `<Short title>` `<role>` `<goal>` `<str>` `<N>`
   `<YYYY-MM-DD>` `TC-NNN` `AT-NNN`
   appearing as the **actual value** of a heading, field, or table cell.

### Anti-false-positive rule (the batch-15 `<P>` / `TC-NNN` lesson)

A placeholder token is **NOT** a blocker when it sits inside:
- an inline backtick span (`` `<role>` ``),
- a fenced code block (```` ``` ```` / `~~~`), or
- YAML frontmatter (a `schema:` example, etc.).

Those hits are stripped before matching and reported as *"quoted-token
false-positive(s) skipped"* in the run summary — never blocked on. Legitimate
prose, code fences, and frontmatter schema examples routinely quote these tokens
(e.g. the traceability matrix's `` `AT-NNN` `` column header), and must pass.

## How it behaves as a commit gate

Wired as a **PreToolUse** hook on the `Bash` tool. On every Bash tool call it:

1. Reads the tool call JSON on stdin; if the command is **not** a `git commit`,
   it allows immediately (exit 0).
2. Locates the project root (walks up for `.dev-flow/state.json`). Not a dev-flow
   project → allow.
3. If `current_phase < 4`, or the batch dir is missing → allow.
4. Best-effort checks whether the commit actually touches `.dev-flow/`
   (`git diff --cached`; also `git diff` for `-a`). If it provably does not →
   allow. If it does, or that cannot be determined → run the detect.
5. If the detect finds **real** blockers, it **blocks the commit** (exit 2) and
   prints each blocker as `file:line  reason` to Claude. Otherwise → allow.

**Fail-OPEN by design.** Anything unexpected — no `state.json`, unreadable
state, unparseable stdin, git unavailable, or any internal error — results in
*allow*. A non-dev-flow commit is never blocked. Only a genuine, positively
detected structural blocker in an in-scope artifact stops a commit.

> Scope note: this hook only intercepts commits made through **Claude Code's Bash
> tool**. It is not a git `pre-commit` hook and does not affect commits you make
> in a plain terminal.

## Manual / standalone use

```bash
# Check the current batch (reads .dev-flow/state.json; gates on current_phase)
python .dev-flow/tools/validate_phase_artifacts.py

# Check any batch dir directly (bypasses state.json; treats phase as 6)
python .dev-flow/tools/validate_phase_artifacts.py --batch-dir .dev-flow/2026-06-29-batch-20

# Override the phase gate
python .dev-flow/tools/validate_phase_artifacts.py --phase 4
```

Exit code: `0` = clean (or fail-open skip), `1` = real blocker(s) found.

## How to bypass in a genuine emergency

The gate exists to stop incomplete artifacts, so bypassing should be rare and
deliberate. In order of preference:

1. **Finish the artifact.** This is almost always the right answer — the message
   tells you the exact `file:line`.
2. **Commit from a plain terminal.** The hook only intercepts Claude Code's Bash
   tool; a `git commit` you run yourself in a terminal is not gated.
3. **Temporarily disable the hook.** Remove or comment the `PreToolUse` block in
   `.claude/settings.json` for the one commit, then restore it. (Least
   preferred — easy to forget to restore.)

## Repo-specific note: `.claude/` is gitignored

In this repo `.claude/` is listed in `.gitignore`, so `.claude/settings.json`
(the hook wiring) is a **local, uncommitted** file — the hook is active on this
machine but is not shared with the team by default. The **script** under
`.dev-flow/tools/` *is* tracked and committed. To share the hook across the team,
un-ignore `.claude/settings.json` (e.g. add `!.claude/settings.json` after the
`.claude/` line in `.gitignore`) and commit it.

The hook command in `.claude/settings.json` assumes **`python` is on PATH** and
that Claude Code runs hooks from the project root (both true here). On a machine
where the interpreter is only `py`/`python3`, edit the `command` accordingly — a
launch failure disables the gate silently (it does not block commits).

---

## Assessment: can the "no hollow iterate at gates" rule be hook-enforced? — **No.**

The **"no hollow iterate at gates"** rule (never dangle "approve or iterate?";
offer *iterate* only with a **named** exit-criteria gap) **cannot** be enforced
by a hook, and this should not be re-attempted.

**Why:** Claude Code hooks fire on **tool-call events** (PreToolUse / PostToolUse
/ etc.) and inspect tool inputs and outputs. The "no hollow iterate" rule governs
the **content of an assistant message to the user** — prose at a `/dev-flow`
gate. That prose is not a tool call, so no hook event carries it and no hook can
read or veto it. There is no "assistant-message" hook surface to match on, and
even the `Stop` hook only sees that the turn ended, not the rhetorical shape of
what was said.

It therefore stays what it is today: a **`/dev-flow` command rule + memory**
(`feedback_no_hollow_iterate_at_gates`), applied by the assistant, not a
machine-enforced gate. The structural artifact detect in this directory is
hook-enforceable precisely because it inspects **files a commit would carry** —
a tool-observable artifact — which the iterate-prose rule is not.
