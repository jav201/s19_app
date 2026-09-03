# Increment 004 — `HLR-89.4` — the environment contract is declared and DERIVED, never asserted

| Field | Value |
|---|---|
| Batch | `2026-08-28-batch-89` |
| Increment | `004` of 6 declared — **6 built** (004 and 005 built out of order, after 006) |
| Requirement(s) | `HLR-89.4` |
| Ledger | `LED-89.2` · `LED-89.22` · **`LED-89.23`** (new) |
| Premise | `P-6` / `P-9` — the floors re-derived at rev54 held on re-derivation today; the API floor's hit census moved from 9 () to 13 here and to **15** once Increment 005 landed — **the FLOOR held; only the census moved, and this batch's own code moved it** |
| Acceptance | **no id is minted** (`R-89-7`). 23 arms under `V30`; the two derivations are `V30 LIVE-derived` and `V30 SYNTAX-fv-is-blind`; the negative controls are the four `ROW-*-BLOCKS` and `E2E-fixture-disagrees` |
| Flow revision | rev54 → **rev55** (shared with Increment 005) |
| Date of the work | `2026-08-31` |
| Date of this packet | `2026-08-31` — **at the gate, before any commit** |

---

## 1 · What changed

**`V30` ships: the flow's environment contract is now a canon row that a rule DERIVES from the
constructs binding it, and BLOCKs when the row and the source disagree.** A floor written down
by hand is a claim; a floor derived from the construct that raises it is a measurement that
cannot rot.

**Four floors, four sentences, each naming what it was derived FROM.** Measured on the real
canon this increment:

| Floor | Declared | Derived from | Executed? |
|---|---|---|---|
| `python-executed` | `3.11` | the 3 Python files the manifest table declares parse, and `--selftest` passes, on `3.11.15` | **EXECUTED** — a lower bound *witnessed by execution* |
| `python-api` | `3.7` | **exactly two construct kinds**: `from __future__ import annotations` at `devflow-validate.py:41`, and `subprocess.run(capture_output=)` at 14 further sites — **15 catalogued hits over 3 files**, 13 of them when this increment closed and 15 after Increment 005 added two | **DOCUMENTARY, NEVER EXECUTED** |
| `git` | `2.28.0` | `git init -b` at **3 sites, all three inside `--selftest`** | reached by the selftest alone |
| `third-party-imports` | `0` | all **13** top-level modules run under `python -S -E` in a child interpreter | **EXECUTED** |

**The requirement owed TWO derivations and the second is the one that cannot be done.** An AST
walk finds stdlib-API floors and **structurally cannot see a SYNTAX floor**, because it only
ever sees what already parsed. `V30 SYNTAX-fv-is-blind` measures why the obvious substitute is
useless rather than merely weak: for every requested version 3.7 → 3.12,
`ast.parse(feature_version=)` returns **the running interpreter's own verdict**.

```
3.11.15   refuses the rev53 PEP 701 construct at 6 of 6 requested versions
3.12.7    accepts  the rev53 PEP 701 construct at 6 of 6 requested versions
```

**So the row names the interpreter that refuses the version below it, or is labelled
documentary.** `python-executed` is `3.11` because 3.11.15 runs the file set and passes.
`python-api` is `3.7` and its own printed finding carries the words *"DOCUMENTARY, NEVER
EXECUTED: no interpreter below `3.11` exists here, so every version under it is asserted by
analysis alone."* **Two interpreters are two points, not a range.**

**`sys.stdlib_module_names` was refused deliberately.** It would have been one line for the
third-party count, and it is a **3.10 API** — so using it would have raised this file's own
API floor to 3.10 **without the construct catalog being able to see it**, which is the exact
blindness `V30` exists to report. The probe runs the names under `python -S -E` instead, with
site-packages off the path.

---

## 2 · Files modified

**Zero source files in `s19_app`.** The rule lives in `~/.claude`.

| Repo | Files | Change |
|---|---|---|
| `~/.claude` | `docs/tools/devflow-validate.py` | `+ast` import; the `V30` section (rule, 4 pure helpers, 2 AST detectors, the executed import probe, `_flow_home`); registration in `CHECKS`; rows in `_RULE_COVERS` and `_RULE_SELECTOR`; 23 arms in `selftest()` |
| `~/.claude` | `docs/FLOW-VERSION.md` | new `## Environment contract` section (the canon row) + the rev55 bump, shared with Increment 005 |
| `s19_app` | `.dev-flow/2026-08-28-batch-89/01-requirements.md` | `HLR-89.4` Acceptance + Negative-control + Ledger fields |
| `s19_app` | `.dev-flow/2026-08-28-batch-89/01-requirements-ledger.md` | `LED-89.23` appended |
| `~/.claude/skills` | `dev-flow/scripts/devflow-validate.py` · `dev-flow/FLOW-VERSION.md` | `--sync-bundle` output, never hand-edited |

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 — in `s19_app`. **1 authored source file** in the flow repo |
| Test files | 0 (uncapped) — the arms live in `--selftest` |

> **`FLOW-VERSION.md` is NOT in its own hashed table**, so the new canon section does not move
> `flow_hash`. Only `devflow-validate.py`'s row was re-hashed.

---

## 3 · How to test

```bash
export PYTHONIOENCODING=utf-8
python ~/.claude/docs/tools/devflow-validate.py --selftest | grep "^  V30 "
python ~/.claude/docs/tools/devflow-validate.py ~/Github/s19_app | grep "V30 "
```

To see the second derivation's point directly, on both interpreters:

```bash
python -c "import ast,sys;s='x = f\"{\"a\"}\"';print(sys.version_info[:3]);
[print(v,(lambda:(ast.parse(s,feature_version=(3,v)),'ACCEPTS')[1])()) for v in range(7,13)]"
```

---

## 4 · Test results

| Measure | Value |
|---|---|
| `--selftest`, **Python 3.11.15** (`s19env`, the gate env) | **565 arms · 0 FAIL · `SELFTEST PASSED`** |
| `--selftest`, **Python 3.12.7** (base Anaconda) | **565 arms · 0 FAIL · `SELFTEST PASSED`** |
| Arms attributable to Increment 004 | **23** (`V30 *`) |
| Arm delta, rev55 | 530 → 565 (+35 for both increments; **23 here, 12 in Increment 005**) |
| Mutants | **13 applied · 13 KILLED · 0 survivors**, against a GREEN baseline |
| Sentinel | `SENTINEL-must-be-RED` — **KILLED** (after being repaired; see below) |
| Gate | **0 BLOCK from V30**; V30 prints 4 SKIP findings |

**Actual `V30` arm block, 3.11.15:**

```
  V30 LIVE-derived             expected the real canon's 3 Python file(s) to bind API 3.7 by exactly 2 construct kinds and git 2.28.0 at 3 sites · got API 3.7 at docs/tools/devflow-validate.py:41, git 2.28.0 at 3 site(s) · ok
  V30 CATALOG-each             · ok      V30 CATALOG-empty!=floor-0   · ok
  V30 ROW-api-below-BLOCKS     · ok      V30 ROW-api-above-BLOCKS     · ok
  V30 ROW-git-BLOCKS           · ok      V30 ROW-exec-not-a-version   · ok
  V30 ROW-third-party-BLOCKS   · ok      V30 NO-SECTION               · ok
  V30 NO-FILES                 · ok      V30 PROBE-not-measured       · ok
  V30 LOADER-absent-is-None    · ok      V30 ERROR-unparseable        · ok
  V30 EXEC-unwitnessed         · ok
  V30 SYNTAX-fv-is-blind       ... · got refuses on 3.11.15 and 6/6 agreeing · ok
  V30 GIT-both-shapes          · ok      V30 PROBE-sees-one           · ok  (2 installed, 2 refused)
  V30 PROBE-absence-has-reason · ok      V30 PASS!=NOOP               · ok  (11 distinct)
  V30 E2E-fixture-agrees       · ok      V30 E2E-no-section           · ok
  V30 E2E-fixture-disagrees    · ok      V30 E2E-live                 · ok  (['SKIP','SKIP','SKIP','SKIP'])
```

On 3.12.7 the same block is identical except `SYNTAX-fv-is-blind`, which reads
`got accepts on 3.12.7 and 6/6 agreeing`, and `PROBE-sees-one`, which finds 3 site-packages
rather than 2. **That difference is the finding, not noise.**

### 🛑 The sentinel SURVIVED the first battery, and it was right to

`SENTINEL-must-be-RED` corrupts `_V30_NO_SECTION`, and the arm meant to catch that asserted
`msg == _V30_NO_SECTION` — **the same constant on both sides, which agrees unconditionally.**
The detector had been proven blind **before a single mutant verdict was scored**, which is the
entire reason the sentinel runs first. The arm now types its sentence by hand.

### 🛑 `M9` showed that an arm over the CORE is not an arm over the LOADER

`_env_declared` returning `{}` instead of `None` for an absent section left **every core arm
green** and turned the rule into four BLOCKs about a manifest that never claimed a floor —
because the `NO-SECTION` arm feeds `_v30_outcome` a **literal `None`** and so can say nothing
about the function that decides when `None` is the answer. Closed by `LOADER-absent-is-None`
(4 manifest shapes) and `E2E-no-section` through the registered rule.

### A defect the arms found in their own author's code

`_v30_floor` sorted citations as **strings**, so `:1380` ordered ahead of `:41` and the finding
cited `capture_output=` where `from __future__ import annotations` binds the floor. Every count
stayed correct; only the one part a reader follows by hand was wrong. Caught by `LIVE-derived`
asserting the **citation**, not the number. `M7-citation-sorted-lexically` now pins it.

### The mutation battery, enumerated

| Mutant | Verdict | Killed by |
|---|---|---|
| `SENTINEL-must-be-RED` | KILLED | `NO-SECTION`, `E2E-no-section` |
| `M1-empty-becomes-floor-0` | KILLED | `CATALOG-empty!=floor-0` |
| `M2-row-always-agrees` (the duplicate oracle) | KILLED | `ROW-api-below/above-BLOCKS`, `PASS!=NOOP` |
| `M3-git-drops-call-shape` | KILLED | `LIVE-derived`, `GIT-both-shapes` |
| `M4-git-init-alone-is-enough` | KILLED | `LIVE-derived`, `GIT-both-shapes` |
| `M5-probe-not-isolated` (drops `-S -E`) | KILLED | `PROBE-sees-one` |
| `M6-probe-swallows-its-reason` | KILLED | `PROBE-absence-has-reason` |
| `M7-citation-sorted-lexically` | KILLED | `LIVE-derived`, `ROW-api-*` |
| `M8-catalog-loses-node-kinds` | KILLED | `CATALOG-each` |
| `M9-absent-section-becomes-empty-row` | KILLED | `LOADER-absent-is-None`, `E2E-no-section` |
| `M10-executed-floor-never-unwitnessed` | KILLED | `EXEC-unwitnessed`, `PASS!=NOOP` |
| `M11-registered-noop` (`return []`) | KILLED | all three `E2E-*` |
| `M12-third-party-counted-not-named` | KILLED | `ROW-third-party-BLOCKS` |

**`M6` first killed by CRASHING the selftest** (`ok &= None` raises `TypeError`) instead of
printing a FAIL line naming the arm. The arm was repaired so the kill is readable — **a kill
nobody can read is a worse kill.**

### Independent review

**ABSENT.** No `code-reviewer` verdict exists for this increment. Every defect above was found
by the increment's own sentinel and battery, which is better than nothing and is **not** an
independent lens.

---

## 5 · Risks

- **`V30`'s catalog is ENUMERATED and blind outside it.** Six constructs. A version-gated
  construct nobody catalogued raises the real floor and `V30` will not see it — the finding
  prints the catalog size so the blindness is visible, but it is a bound, not a proof.
- **`python-api` 3.7 has no interpreter behind it and says so.** 3.7–3.10 is asserted by
  analysis alone. If the claim matters operationally, install a 3.7 and execute it; nothing on
  this machine can settle it.
- **The rule EXECUTES a child interpreter** (`sys.executable -S -E`) on every gate run — a
  widening of what the validator does, ~0.2 s, and a new dependency on `sys.executable` being
  runnable.
- **`_flow_home()` reads `DEVFLOW_HOME`.** It exists so the registered rule can be armed on a
  fixture; it also means an environment variable can point `V30` at another tree.
- **`git init -b` is derived from a LITERAL ARGUMENT LIST.** A site that builds the argument
  list dynamically binds the same floor and is invisible to the detector.

## 6 · Pending

- **Nothing is committed.** `~/.claude`, `~/.claude/skills` and `s19_app` all carry
  uncommitted changes; the gate's only 2 BLOCKs are `V16`'s *"uncommitted changes"*, by design.
- `state.json`'s `decisions_log` has **no entry for this increment**, so `V27` reports the
  ledger is behind the newest commit on the batch. `state.json` is outside this increment's
  owned file set.
- `04-validation.md` and `05-close.md` still do not exist for this batch.

## 7 · Suggested next task

**Increment 005** — the runtime preflight (`HLR-89.5`), built immediately after this one and
sharing the rev55 bump. See `increment-005.md`.

---

## Increment gate checklist

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 0 in `s19_app`; 1 authored source file in the flow repo (`devflow-validate.py`) |
| 2 | Tests written in the same increment | ✓ | 23 `V30` arms, same edit |
| 3 | RED counterfactual captured | ✓ | 13/13 mutants killed against a **GREEN** baseline (`SELFTEST PASSED`, 565 arms, in the mirrored tree) |
| 4 | Detector proven able to see RED before any verdict | ✓ | `SENTINEL-must-be-RED` **survived first**, exposed a self-agreeing arm, and was KILLED only after the arm was rewritten |
| 5 | Vacuous arms hunted | **⚠** | Two shipped in the first draft — the self-agreeing `NO-SECTION` arm and the core-only loader coverage. Both caught by the battery, neither by review |
| 6 | Independent `code-reviewer` pass | **✗** | none ran |
| 7 | No file from another lane touched | ✓ | `git status` shows `prototypes/` and `build/` untouched and still untracked |
| 8 | Frozen interfaces untouched | ✓ | 0 files under `s19_app/`, `tests/`, `tools/`, `.github/` |
| 9 | Packet written at the increment's gate | ✓ | written 2026-08-31, before any commit |

**An item without a citation is not satisfied — it is asserted.**
