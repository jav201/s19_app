# Increment 003 — `HLR-89.3` — the flow names an interpreter that exists on this machine

> ## ⚠ READ THIS FIRST — THIS PACKET DID NOT GATE THE INCREMENT
>
> **Written 2026-08-30. The increment was committed 2026-08-29 at 13:30:47 -0600** as part of
> `1d2e9fe`, together with Increment 002, and is **not merged** — `git log origin/main..HEAD`
> lists it as still only on `origin/claude/batch-89-lean-contract`.
>
> **Two increments, one commit.** The per-increment split of arm counts is not recorded and is
> marked **ABSENT** below rather than apportioned by guess. The mutant battery is the one case
> where attribution *is* recoverable: `LED-89.11` files the 13-mutant run under `HLR-89.3`,
> which is this increment.
>
> Figures are transcribed from `1d2e9fe`'s message, `FLOW-VERSION.md`'s rev49 row, and
> `LED-89.10` – `LED-89.12`. The validator is at rev50 today, so **a run now does not
> reproduce these numbers.**

| Field | Value |
|---|---|
| Batch | `2026-08-28-batch-89` |
| Increment | `003` of 6 declared — **4 built**; see the closing note of `increment-006.md` |
| Requirement(s) | `HLR-89.3` |
| Ledger | `LED-89.10` · `LED-89.11` · `LED-89.12` |
| Premise | `P-4` — TRUE, **with one path corrected**: the fourth site is in `~/.claude`, not in this repository |
| Acceptance | **no id is minted** (`R-89-7`). The arms are `INT FOUR-PLACES-agree`, `INT WIRING-collects`, `INT INTERP-parse`, `V17 BLOCK-unrunnable`, with `INT RUNS!=IS-PYTHON` and `INT PASS!=NOOP` as the two negative controls |
| Flow revision | rev48 → **rev49** (shared with Increment 002) |
| Date of the work | `2026-08-29` |
| Date of this packet | `2026-08-30` — **after the fact** |

---

## 1 · What changed

**The flow named an interpreter that does not run on this machine, and `V17` certified it.**
`python3` resolves to the Microsoft Store alias in `WindowsApps` — a real file, on `PATH`,
that `shutil.which` reports and `os.path.isfile` confirms — which prints *"Python was not
found"* and **exits 49 without starting Python**. Executing `hooks/flow-guard.py` through its
own shebang exited **49**: a silent non-run.

**`V17` could not see it because it asked the wrong question.** `_guard_path_resolves` tested
`os.path.isfile` and stopped, so `python3 ~/.claude/hooks/flow-guard.py` printed
`SKIP: guard wired on UserPromptSubmit` **while every rule the guard enforces went
unenforced.**

**"Resolves" was the wrong verb** (`LED-89.11`). `HLR-89.3` originally said `V17` must BLOCK on
an interpreter that *does not resolve*; **resolving is exactly what the defect passes.** The
requirement now says *does not start Python when executed*, and `_interpreter_runs` **executes
the token and reads back a marker**.

**Three shebangs now say `python`.** `.github/workflows/flow-selftest.yml:40` **keeps
`python3`, and that asymmetry is the ruling** (`LED-89.10`): that job runs on
`ubuntu-latest`, where `python3` is the correct name and a bare `python` may not exist. **The
runner's provision of `python` was NOT measured** — no runner is reachable from here — and an
unmeasured premise is not a licence to change a working CI line. The threshold therefore
stopped being *"0 remaining `python3` sites"* and became **agreement among the four LOCAL
sites**, which is true on both platforms.

**The correction had a population, so it was swept** (`R-88-17`, the defect Increment 001's
whole mechanism exists to close). Live `python3` claims outside this batch's own new prose:
`FLOW-VERSION.md:10` (V17's row) and `flow-selftest.yml:57` (V17's description) — both
updated; `flow-selftest.yml:40` — **kept, with a comment saying why** so a later reader does
not "unify" it; `FLOW-VERSION.md:202` — historical changelog prose quoting the lessons
catalogue, correctly untouched.

> **The sharpest line in the whole increment, and it is not about code:** *the lessons
> catalogue already carried this trap and the flow shipped `python3` anyway.* **Learning a
> lesson and encoding it are different acts.**

---

## 2 · Files modified

**Zero source files in `s19_app`.** The repair landed in `~/.claude`.

| Repo | Commit | Files | Change |
|---|---|---|---|
| `s19_app` | `1d2e9fe`, 2026-08-29 13:30:47 -0600 | **7 files, +138 / −53** (Increments 002 **and** 003 together) | `01-requirements.md`, `01-requirements-ledger.md` (+95), the 4 `_derived/ATLAS-*.md` files, and `project.toml` (deleted; **belongs to neither increment** — see `increment-002.md` §2) |
| `~/.claude` | `51203c7`, 2026-08-29 13:30:07 -0600 | **5 files, +419 / −14** | `docs/tools/devflow-validate.py` (+403, shared with Increment 002), **`hooks/flow-guard.py`** (shebang), **`hooks/install.py`** (shebang + generated hook command), **`.github/workflows/flow-selftest.yml`**, `docs/FLOW-VERSION.md` |
| `~/.claude/skills` | `7b84e0c` | mirror | `--sync-bundle` output, never hand-edited |

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 — in `s19_app`. **3 authored source files** in the flow repo (`devflow-validate.py`, `hooks/flow-guard.py`, `hooks/install.py`), one of them shared with Increment 002 |
| Test files | 0 (uncapped) — the arms live in `--selftest` |

---

## 3 · How to test

```bash
export PYTHONIOENCODING=utf-8
python ~/.claude/docs/tools/devflow-validate.py --selftest | grep -E "INT |V17 "
```

**To see the defect**, on this machine:

```bash
python3 --version ; echo "exit=$?"        # exit 49, Python never starts
```

> **⚠ Not re-executed for this packet.** The exit-49 figure below is `LED-89.11`'s, taken
> 2026-08-29.

---

## 4 · Test results

| Measure | Value | Source |
|---|---|---|
| Selftest after Increments 002 + 003 | **443 arms, 0 fail** | `1d2e9fe` message |
| Arm delta, rev49 | 431 → **443** (+12, **for both increments together**) | `FLOW-VERSION.md` rev49 |
| **Arms attributable to Increment 003 alone** | **ABSENT** | one commit, two increments, no split recorded |
| Mutants | **13 of 13 killed, against a GREEN baseline** | `LED-89.11`, filed under `HLR-89.3` |
| `python3` on this machine | resolves in `WindowsApps`; **exit 49**, Python never starts | `LED-89.11`, measured 2026-08-29 |
| `flow-guard.py` by shebang, before the fix | **exit 49** — a silent non-run | `LED-89.11` |
| `python3` sites | **4**, count held on re-measurement 2026-08-29; **one path corrected** (the CI file is `~/.claude/.github/workflows/flow-selftest.yml:40`, not under `s19_app`) | `P-4` |
| `INT INTERP-parse` domain | **5 command shapes** | `LED-89.12` |
| Gate line at this commit | **ABSENT** | not recorded in the commit message and not re-derivable at rev49 |

### 🛑 An earlier harness run had a RED baseline, and its kills were discarded rather than reported

`FLOW-VERSION.md` rev49 and `LED-89.11` both say it: *"13 of 13 mutants killed afterwards,
against a GREEN baseline — the first harness run had a red baseline and its 'kills' were
discarded rather than reported."* **A baseline that is already red cannot score anything**, and
a mutant that reddens an already-red run has proved nothing. **This is stated because the
alternative — quietly keeping the first run's numbers — is the failure mode the flow exists to
catch**, and the same trap is hit again one increment later (`increment-006.md` §4).

### 🛑 A mutant that restores the ORIGINAL defect exactly, and it SURVIVED

The first version of the dead-interpreter arm used a **temp text file** as its dead
interpreter. That fixture is not executable, so `_interpreter_runs` refuses it **from the
`OSError` branch and never evaluates its return expression** — and the mutant replacing that
expression with `return True`, **which is the original defect exactly**, *survived the full
selftest*.

Closed by `INT RUNS!=IS-PYTHON`, built with a **real program discovered at runtime** (`git`
here) that runs and is not Python; the collector fixture in `INT WIRING-collects` was switched
to it. `INT ISFILE!=RUNS` alone is recorded as **insufficient, and measured so** — it reaches
only the `OSError` branch.

### 🛑 The new rule would have false-BLOCKed most of Windows

`V17`'s existing tokenizer splits on whitespace and discards quotes — harmless for asking
whether some token ends in `flow-guard.py`, **not harmless for naming the interpreter.** The
default Windows install lives under `C:\Program Files\...`, so the correctly quoted command

```
"C:/Program Files/Py/python.exe" ~/.claude/hooks/flow-guard.py
```

yielded an interpreter of `Files/Py/python.exe` — which cannot run, **so the new `V17` would
have BLOCKed a perfectly wired machine.** That is `C-53`'s false fail, on **the one rule whose
BLOCK stops the flow**, for most of Windows.

**Found by `INT INTERP-parse` failing on its own author's expected value**, before the
increment closed: the arm was written expecting `C:/Program` and the run returned
`Files/Py/python.exe`. Fixed by adding `_cmd_tokens`, which keeps a quoted span whole;
`_guard_path_resolves` is untouched. A quoted GUARD path was added to the same domain so a
space on either side is covered, taking it to 5 shapes.

### Independent review

**ABSENT.** No `code-reviewer` verdict exists for this increment. Both defects above were
found by the increment's own arms — which is better than nothing and is **not** the
independent lens batch-88 ran at every gate.

---

## 5 · Risks

- **`V17` now EXECUTES a token read out of `settings.json`.** That is a deliberate widening of
  what the validator does, and it is the only way to tell the Store alias from Python. A
  hostile `settings.json` is a hostile local file the flow already trusts, but the rule's blast
  radius grew.
- **The CI site keeps `python3` on an unmeasured premise.** `LED-89.10` says so plainly: the
  GitHub runner's provision of `python` was never measured. If that assumption is wrong the
  asymmetry is wrong, and nothing on this machine can find out.
- **`INT FOUR-PLACES-agree` reads three sibling scripts by walking up from `__file__`.** It is
  correct inside a flow-shaped tree and reports the layout instead of the interpreters outside
  one — **which turned a mutation baseline RED one increment later** (`increment-006.md` §4).
  A real coupling, created here, paid for there.
- **The selftest asserts the four LOCAL sites AGREE, never that a name runs.** That is what
  makes the asymmetry safe and is also the bound: a machine where all four agree on a name
  that does not exist would pass.

## 6 · Pending

- **This increment is not on `main`.** `1d2e9fe` sits on `origin/claude/batch-89-lean-contract`
  only.
- **`04-validation.md` and `05-close.md` do not exist for this batch.**
- **`state.json`'s `batch_objective` still lists this increment under *"REMAINING INCREMENTS,
  NOT IMPLEMENTED"***, although it shipped 2026-08-29.

## 7 · Suggested next task

**As planned at the time: Increment 004** — the environment contract, declared as a canon row
and **derived** from the source constructs that bind it (Python 3.7 by `capture_output=` with
`text=` in `v8_module_map`; git 2.28.0 by `git init -b` in the V25 fixture builder; zero
third-party imports).

> **It was never built, and neither was Increment 005.** Both remain specified in
> `01-requirements.md` — `HLR-89.4` and `HLR-89.5`, `Validation: analysis` and `test`, with
> their acceptance declared as `owed at Increment 4` / `owed at Increment 5`. What happened
> instead is `increment-006.md`. **The numbering is not closed up**, because renumbering would
> silently rewrite what was planned.

---

## Increment gate checklist

**Reconstructed 2026-08-30. This checklist did not gate anything.**

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 0 in `s19_app`; 3 authored source files in the flow repo (`51203c7`) |
| 2 | Tests written in the same increment | ✓ | the `INT` family + `V17 BLOCK-unrunnable` in `51203c7` |
| 3 | RED counterfactual captured | ✓ | 13 of 13 mutants killed, **against a GREEN baseline** — with the discarded red-baseline run declared in §4 rather than omitted |
| 4 | Vacuous arms hunted | **⚠** | One shipped and was caught by the mutant that restores the original defect (`return True` survived the text-file fixture). Caught by the author's own battery, not by review |
| 5 | Per-increment arm attribution | **✗** | **ABSENT** — one commit, two increments |
| 6 | Independent `code-reviewer` pass | **✗** | none ran |
| 7 | No file from another lane touched | ✓ | `git show --stat 1d2e9fe` — nothing under `prototypes/` or `build/` |
| 8 | Frozen interfaces untouched | ✓ | 0 files under `s19_app/`, `tests/` or `tools/` in `1d2e9fe` |
| 9 | Packet written at the increment's gate | **✗** | **Written 2026-08-30, one day after the work** |

**An item without a citation is not satisfied — it is asserted.**
