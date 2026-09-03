# Increment 005 — `HLR-89.5` — the runtime preflight reports what the gate assumes

| Field | Value |
|---|---|
| Batch | `2026-08-28-batch-89` |
| Increment | `005` of 6 declared — **6 built** (004 and 005 built out of order, after 006) |
| Requirement(s) | `HLR-89.5` |
| Ledger | **`LED-89.24`** (new; the requirement declared `none` before this increment) |
| Premise | the requirement's own rationale — *"all three are assumed by rules that already ship, and none is reported; the selftest's own tail admits case-folding is unproven"* — **TRUE, verified by quoting the tail** |
| Acceptance | **no id is minted** (`R-89-7`). 12 arms under `PRE`; the negative control is `PRE ABSENCES-differ`, proven end to end by `PRE E2E-git-blinded` |
| Flow revision | rev54 → **rev55** (shared with Increment 004) |
| Date of the work | `2026-08-31` |
| Date of this packet | `2026-08-31` — **at the gate, before any commit** |

---

## 1 · What changed

**`run()` now prints three preflight lines before any rule runs.** Live output, this machine:

```
devflow-validate · C:\Users\jjgh8\Github\s19_app
  git · 2.49.0, at or above the 2.28.0 floor
  stdout · encoding `utf-8`, errors `backslashreplace` -- every finding is emitted verbatim
  filesystem · FOLDS CASE -- probed at C:\Users\jjgh8\AppData\Local\Temp, on the same volume as the tree under check
```

**All three were already assumed by rules that ship, and none was reported.** `V16`, `V25`,
`V27` and half the selftest talk to git — a machine without it collected three separate
absences and never the one sentence that explains them. rev49 hardened the streams *because*
the selftest could not state a verdict under a stdout it could not encode, and still never
printed what the stream IS. And case-folding stood **named in the selftest's own tail as the
last of two I/O steps left unproven** — this increment closes it and the tail now says so.

**The header line moved above the rules.** An operator reading top to bottom must meet the
assumptions **before** the first verdict, not after the last one. `hooks/flow-guard.py` is
unaffected: it selects only lines beginning `[x]` or `[!]`, and these begin `git ·`,
`stdout ·` and `filesystem ·`.

**Five git states, not two, and each owns a marker phrase no other carries.** ABSENT from
PATH · PRESENT and UNUSABLE · an unparseable version string · BELOW the floor · at-or-above.
`V25` already paid for collapsing states and bought back a third (*"no origin configured"*);
`LED-89.17` held two absences apart in `_git`; `LED-89.22` did it a third time in `V8`. This is
the fourth, and it is mechanised rather than remembered.

**Case-folding is a PROBE, never a derivation** — it is a property of the machine, and no
amount of reading this source can reach it. Which is precisely why it had stood unproven while
every other claim in the file was being derived.

---

## 2 · Files modified

**Zero source files in `s19_app`.**

| Repo | Files | Change |
|---|---|---|
| `~/.claude` | `docs/tools/devflow-validate.py` | the preflight section (`_git_version`, 3 pure sentence functions, `_casefold_probe`, `_same_volume`, `preflight_lines`); `run()` prints them first; 12 `PRE` arms; the selftest tail corrected |
| `~/.claude` | `docs/FLOW-VERSION.md` | the rev55 bump, shared with Increment 004 |
| `s19_app` | `.dev-flow/2026-08-28-batch-89/01-requirements.md` | `HLR-89.5` Acceptance + Negative-control + Ledger fields |
| `s19_app` | `.dev-flow/2026-08-28-batch-89/01-requirements-ledger.md` | `LED-89.24` appended |
| `~/.claude/skills` | `dev-flow/scripts/devflow-validate.py` · `dev-flow/FLOW-VERSION.md` | `--sync-bundle` output, never hand-edited |

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 — in `s19_app`. **1 authored source file** in the flow repo, shared with Increment 004 |
| Test files | 0 (uncapped) — the arms live in `--selftest` |

---

## 3 · How to test

```bash
export PYTHONIOENCODING=utf-8
python ~/.claude/docs/tools/devflow-validate.py ~/Github/s19_app | head -4
python ~/.claude/docs/tools/devflow-validate.py --selftest | grep "^  PRE "
```

To see the encoding branch change what it says, without changing what it does:

```bash
PYTHONIOENCODING=cp1252 python ~/.claude/docs/tools/devflow-validate.py ~/Github/s19_app | head -4
```

---

## 4 · Test results

| Measure | Value |
|---|---|
| `--selftest`, **Python 3.11.15** (`s19env`, the gate env) | **565 arms · 0 FAIL · `SELFTEST PASSED`** |
| `--selftest`, **Python 3.12.7** (base Anaconda) | **565 arms · 0 FAIL · `SELFTEST PASSED`** |
| Arms attributable to Increment 005 | **12** (`PRE *`) |
| Mutants | **14 applied · 14 KILLED · 0 survivors**, against a GREEN baseline |
| Sentinel | `SENTINEL-must-be-RED` — **KILLED** |
| Gate | preflight prints 3 lines; **0 new BLOCK** |

**Actual `PRE` arm block, 3.11.15:**

```
  PRE GIT-six-states           expected 6 injected git outcomes to name themselves, boundary 2.28.0 included · ok
  PRE ABSENCES-differ          expected each of the 5 git states to own a marker phrase no other state carries · ok
  PRE GIT-boundary-2.28.0      expected 2.27.9 to read BELOW and 2.28.0 to read at-or-above · ok
  PRE ENC-four-states          expected utf-8 and UTF_8 to read verbatim, cp1252 to say TRANSLITERATED rather than lost, and no encoding to say UNKNOWN · ok
  PRE CASE-live-probe          expected the probe to MEASURE this machine's filesystem rather than assume it · got folds=True why=None · ok
  PRE CASE-probe-is-derived    expected the verdict to FOLLOW the filesystem lookup, and the lookup to ask for the lowercased name · got [False, True, True] asking ['devflowcaseprobe'] · ok
  PRE CASE-probe-cleans-up     expected the probe to leave nothing behind in a directory of its own · got 0 leftover(s) · ok
  PRE CASE-four-states         expected folds, does-not-fold, NOT-MEASURED and a different-volume probe to render as 4 distinct sentences · ok
  PRE THREE-LINES              expected exactly 3 lines, one per assumption, each naming its measured value · got 3 · ok
  PRE PASS!=NOOP               expected 14 mutually distinct sentences over the reachable states · got 14 · ok
  PRE E2E-git-present          ... got 'git · 2.49.0, at or above the 2.28.0 floor' · ok
  PRE E2E-git-blinded          ... got 'git · ABSENT from PATH -- no version was read,' · ok
```

### The negative control, proven to differ

`PRE ABSENCES-differ` asserts **exactly-one-of-five**: each state owns a marker phrase that
appears in exactly one of the five sentences.

**The first version of that control was WRONG, and measurement replaced it.** It asserted the
five sentences share no five-word phrase. They legitimately do — git-absent and
git-below-floor both end *"a full `--selftest` cannot run"*, because both facts have that
consequence. And disjointness is simultaneously too weak: two at-or-above sentences differing
only by a version number are `!=` while telling the reader the same thing.

`PRE E2E-git-blinded` proves it end to end in a **child process** with git filtered off `PATH`,
and it asserts `shutil.which("git", path=blinded) is None` **first** — a negative control over
a PATH that still has git on it is the vacuous check this file exists to end.

### 🛑 The probe passed its first battery while being an ASSUMPTION

`N7-case-probe-is-assumed` replaces the entire probe body with `return True, None` — and
**SURVIVED** the first 12-mutant battery with every arm green, because **this machine really
does fold case**, so `CASE-live-probe`'s assertion that the verdict is `True` is satisfied by
the constant `True`. **The verdict was armed; the mechanism was not**, and no case-sensitive
volume exists here to substitute for real.

Closed by making the filesystem lookup injectable and arming **three substituted
filesystems**: the answer must FOLLOW the lookup (`False` in → `False` out), and the lookup
must ask for the **lowercased** name — the one thing separating a fold probe from a
file-was-written probe. `N12-probe-asks-for-the-name-it-wrote`, written after the fix, dies on
exactly that arm.

### The mutation battery, enumerated

| Mutant | Verdict | Killed by |
|---|---|---|
| `SENTINEL-must-be-RED` | KILLED | `GIT-six-states`, `ABSENCES-differ`, `GIT-boundary` |
| `N1-absent-collapses-into-below` | KILLED | `ABSENCES-differ`, `E2E-git-blinded` |
| `N2-unusable-collapses-into-absent` | KILLED | `ABSENCES-differ`, `PASS!=NOOP` |
| `N3-boundary-off-by-one` (`<` → `<=`) | KILLED | `GIT-boundary-2.28.0` |
| `N4-unparseable-reads-as-pass` | KILLED | `GIT-six-states`, `ABSENCES-differ` |
| `N5-FileNotFound-not-special` | KILLED | `ABSENCES-differ`, `E2E-git-blinded` |
| `N6-cp1252-says-lost` | KILLED | `ENC-four-states` |
| `N7-case-probe-is-assumed` | KILLED **(survived the first battery)** | `CASE-probe-is-derived` |
| `N12-probe-asks-for-the-name-it-wrote` | KILLED | `CASE-probe-is-derived` |
| `N13-probe-leaves-its-directory` | KILLED | `CASE-probe-cleans-up` |
| `N8-unmeasured-case-reads-as-pass` | KILLED | `CASE-four-states` |
| `N9-volume-never-named` | KILLED | `CASE-four-states` |
| `N10-preflight-drops-a-line` | KILLED | `THREE-LINES`, both `E2E-*` |
| `N11-run-never-prints-preflight` | KILLED | both `E2E-*` |

### A cross-contamination hazard found inside the battery

`CASE-probe-cleans-up` first read the **shared** temp directory, so `N13`'s leaked directories
would have reddened the arm on the run **after** `N13` and scored the wrong mutant. It now
probes a directory of its own.

### Independent review

**ABSENT.** No `code-reviewer` verdict exists for this increment.

---

## 5 · Risks

- **The case probe measures the TEMP volume, not necessarily the tree's.** It writes where it
  is allowed to write. The sentence names the volume and, when they differ, says the tree's own
  filesystem was **NOT** probed — but on a machine where they differ, the useful measurement is
  the one not taken.
- **`_casefold_probe` takes an injectable `exists`.** It exists so the probe can be told from
  an assumption; it is also a seam a future caller could pass the wrong thing through.
- **The probe writes and deletes a file on every gate run.** Inside a `tempfile.mkdtemp` it
  creates, removed in a `finally`. On a read-only temp directory it reports NOT MEASURED, which
  is a NOTICE-shaped sentence and not a pass.
- **`run()`'s output shape changed** — the header moved above the rules and three lines were
  added. `flow-guard.py` filters on `[x]`/`[!]` and is unaffected, **verified by reading it**,
  not by running the hook.
- **The three preflight lines are not FINDINGS.** They are prose above the findings, so no
  rule BLOCKs on them and `flow-guard` will never stop a command because git is absent. That
  is deliberate — reporting was the requirement — but it means the preflight informs and never
  enforces.

## 6 · Pending

- **Nothing is committed.** The gate's only 2 BLOCKs are `V16`'s *"uncommitted changes"* on
  `~/.claude` and `~/.claude/skills`, by design.
- `state.json`'s `decisions_log` has **no entry for increments 004 or 005**, so `V27` reports
  the ledger behind the newest commit on the batch. `state.json` is outside the owned set.
- `04-validation.md` and `05-close.md` still do not exist for this batch.
- **The `--map` `WHAT NOTHING HERE CHECKS` list was not extended.** The preflight closes an
  assumption the *selftest tail* named; the map's list is about the flow's identity and was
  left alone rather than widened on judgement.

## 7 · Suggested next task

**Close the batch: `04-validation.md` and `05-close.md`.** All six increments are now built and
`V28` will report batch-89 unclosed the moment a batch-90 supersedes it — which is the exact
defect `HLR-89.6` shipped a rule for one increment ago.

---

## Increment gate checklist

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 0 in `s19_app`; 1 authored source file in the flow repo, shared with Increment 004 |
| 2 | Tests written in the same increment | ✓ | 12 `PRE` arms, same edit |
| 3 | RED counterfactual captured | ✓ | 14/14 mutants killed against a **GREEN** baseline (`SELFTEST PASSED`, 565 arms, mirrored tree) |
| 4 | Detector proven able to see RED before any verdict | ✓ | `SENTINEL-must-be-RED` KILLED first, by 3 arms |
| 5 | Vacuous arms hunted | **⚠** | One shipped — `CASE-live-probe` armed the verdict and not the mechanism, and `N7` survived a whole battery on it. Caught by the battery, not by review |
| 6 | Independent `code-reviewer` pass | **✗** | none ran |
| 7 | No file from another lane touched | ✓ | `git status` shows `prototypes/` and `build/` untouched and still untracked |
| 8 | Frozen interfaces untouched | ✓ | 0 files under `s19_app/`, `tests/`, `tools/`, `.github/` |
| 9 | Packet written at the increment's gate | ✓ | written 2026-08-31, before any commit |

**An item without a citation is not satisfied — it is asserted.**
