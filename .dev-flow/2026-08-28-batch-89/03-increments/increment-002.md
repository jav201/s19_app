# Increment 002 — `HLR-89.2` — the selftest states a verdict under any stdout encoding

> ## ⚠ READ THIS FIRST — THIS PACKET DID NOT GATE THE INCREMENT
>
> **Written 2026-08-30. The increment was committed 2026-08-29 at 13:30:47 -0600** as part of
> `1d2e9fe`, together with Increment 003. This file is **one day younger than the work it
> describes** and had no opportunity to stop it.
>
> **It is also not merged.** `git log origin/main..HEAD` lists `1d2e9fe` as still only on
> `origin/claude/batch-89-lean-contract`. **The one batch-89 commit on `main` is Increment
> 001's** (`dde935c`, PR #204). Any statement that this batch merged six increments to `main`
> is refuted by that command.
>
> **Two increments, one commit.** `1d2e9fe` carries Increments 002 and 003 together, so the
> per-increment split of arm counts and mutant tallies **was never recorded and cannot be
> recovered**. Where that bites, the field below is marked **ABSENT** with the reason rather
> than apportioned by guess.
>
> Figures are transcribed from `1d2e9fe`'s message, `FLOW-VERSION.md`'s rev49 row, and the
> batch's own ledger. The validator has moved one revision since (rev50), so **a run today
> does not reproduce these numbers.**

| Field | Value |
|---|---|
| Batch | `2026-08-28-batch-89` |
| Increment | `002` of 6 declared — **4 built**; see the closing note of `increment-006.md` |
| Requirement(s) | `HLR-89.2` |
| Ledger | `LED-89.8` · `LED-89.9` |
| Premise gated on | `P-8` — **UNDECIDABLE at Increment 001, discharged here by measurement** |
| Acceptance | **no id is minted** (`R-89-7`). The arms are `ENC VERDICT-live`, `ENC VERDICT-domain`, `ENC UTF8-lossless`, and the negative control `ENC PASS!=NOOP` |
| Flow revision | rev48 → **rev49** (shared with Increment 003) |
| Date of the work | `2026-08-29` |
| Date of this packet | `2026-08-30` — **after the fact** |

---

## 1 · What changed

**The increment was gated on OBSERVING the defect, not on inheriting it.** `P-8` was marked
UNDECIDABLE in the live contract precisely because **every run in this batch had
`PYTHONIOENCODING` pinned** and therefore avoided the crash rather than seeing it. Repairing
an unobserved defect repairs the wrong thing.

**Reproduced on two surfaces, before a line of the repair was written:**

| Surface | Result |
|---|---|
| `PYTHONIOENCODING` unset, stdout redirected to a file | exit 1, `UnicodeEncodeError: 'charmap' codec can't encode character '−'`, **12 arm lines on disk**, **no verdict** |
| `PYTHONIOENCODING=ascii` | exit 1 on `·` — the separator in **every** arm line — inside the FIRST arm, **0 arm lines**, **no verdict** |

**Neither printed a verdict, and that is the load-bearing half.** A crash prints zero FAILs
and no `SELFTEST PASSED`, which is *indistinguishable from a pass to every consumer that reads
the exit code alone* — in the one mode carrying CI authority. A truncated run and a real
failure were the same picture.

**The repair is at the STREAM, not at the fixture.** `_harden_streams` sets
`errors=backslashreplace` on stdout and stderr at `__main__`. The alternative — ASCII-ing the
V5 fixture that holds the `−` — would pin *one instance of a class*: measured over the
22 canon rows of `docs/FLOW-VERSION.md`, **534 non-cp1252 characters of 28 distinct kinds**,
and against an ASCII stdout **2,511 non-ASCII characters of 38 kinds** (`LED-89.9`).

**The consumer's ENCODING is deliberately NOT overridden.** Forcing `encoding=utf-8` would end
the crash by writing bytes a cp1252 reader misreads — **trading a loud failure for a quiet
corruption**. Changing only `errors` keeps a capable stream byte-identical (`ENC
UTF8-lossless`) and gives an incapable one a readable `−`.

**One encoding is not a domain**, and this defect demonstrates that rather than illustrating
it: cp1252 carries `·` and dies later at `−`; ASCII carries neither and dies at the
first line. `ENC VERDICT-domain` therefore sweeps **5 stdout encodings** with a probe
**harvested from the canon** rather than typed, so a new character entering any canon file
enters the arm with it.

---

## 2 · Files modified

**Zero source files in `s19_app`.** The repair landed in `~/.claude`.

| Repo | Commit | Files | Change |
|---|---|---|---|
| `s19_app` | `1d2e9fe`, 2026-08-29 13:30:47 -0600 | **7 files, +138 / −53** (Increments 002 **and** 003 together) | `01-requirements.md` (+64/−…), `01-requirements-ledger.md` (+95), the 4 `_derived/ATLAS-*.md` files, and `project.toml` (**deleted, −24**) |
| `~/.claude` | `51203c7`, 2026-08-29 13:30:07 -0600 | **5 files, +419 / −14** | `docs/tools/devflow-validate.py` (+403, shared with Increment 003), `hooks/flow-guard.py`, `hooks/install.py`, `.github/workflows/flow-selftest.yml`, `docs/FLOW-VERSION.md` |
| `~/.claude/skills` | `7b84e0c` | mirror | `--sync-bundle` output, never hand-edited |

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 — in `s19_app`. **1 authored source file** in the flow repo (`devflow-validate.py`), shared with Increment 003 |
| Test files | 0 (uncapped) — the arms live in `--selftest` |

> **⚠ `project.toml` was DELETED in this commit and belongs to neither increment.** It was a
> stray duplicate of `pyproject.toml`, present since the repository's first commit
> (`8533c72`), declaring `requires-python = ">=3.8"`. Its removal is adjacent to `ad4924a`
> (*"requires-python was false — the floor is raised to the version CI actually verifies"*,
> 2026-08-29 13:31:43, 73 seconds later) and to `R-88-7`. **It is recorded here because it is
> in this increment's landing commit, not because this increment did it.**

---

## 3 · How to test

```bash
export PYTHONIOENCODING=utf-8
python ~/.claude/docs/tools/devflow-validate.py --selftest | grep "ENC "
```

**To see the defect this increment closed**, check out `8438000` (rev48) in `~/.claude` and
run, on Windows:

```bash
env -u PYTHONIOENCODING python ~/.claude/docs/tools/devflow-validate.py --selftest > out.txt
PYTHONIOENCODING=ascii python ~/.claude/docs/tools/devflow-validate.py --selftest
```

> **⚠ Not re-executed for this packet.** The transcripts in §4 are the ones taken on
> 2026-08-29, before the repair. Re-running rev48 today would produce a fresh measurement, not
> this increment's.

---

## 4 · Test results

| Measure | Value | Source |
|---|---|---|
| Selftest after Increments 002 + 003 | **443 arms, 0 fail** | `1d2e9fe` message |
| Arm delta, rev49 | 431 → **443** (+12, **for both increments together**) | `FLOW-VERSION.md` rev49 |
| **Arms attributable to Increment 002 alone** | **ABSENT** | neither the commit message, the rev49 row nor the ledger records the split; the two increments landed in one commit |
| `V26` on the record at this commit | **27,893 chars inside budget · 15 pairings identical both ways** | `1d2e9fe` message |
| Mutants, rev49 | **13 of 13 killed against a GREEN baseline** | `FLOW-VERSION.md` rev49 |
| **Mutants attributable to Increment 002 alone** | **ABSENT** | same reason. `LED-89.11`, which cites the 13, is filed under `HLR-89.3` (Increment 003), so the battery cannot even be assumed evenly split |
| Gate line at this commit | **ABSENT** | not recorded in the commit message and not re-derivable at rev49 |

### The RED side, observed before the repair

`P-8`'s two surfaces above **are** the negative control for this requirement, and they were
taken first. The arm that holds it afterwards is `ENC PASS!=NOOP`: **the same probe text must
still KILL an unhardened stream on all 4 non-utf-8 encodings**, so the passing arms cannot
pass by the probe quietly going ASCII.

**`ENC VERDICT-live` is the arm that earned its place:** it runs a real child `--selftest`
under `PYTHONIOENCODING=cp1252` and asserts the **verdict LINE**, and it is *the only arm that
caught the mutant where `_harden_streams` exists and `__main__` never calls it*
(`FLOW-VERSION.md` rev49).

### 🛑 Three corrections to the brief that commissioned this work — all measured, all against it

**(a) The stated cause was WRONG.** The brief attributed the missing verdict to **block
buffering**. It is not: Python flushes the text buffer at interpreter shutdown even after the
exception, so bytes already encoded do reach the file. **The cause is the ENCODING**, and that
distinction is what forced the 5-encoding domain instead of a single-encoding arm
(`LED-89.8`).

**(b) The corpus figure did not reproduce, and the operator's two conflicting measurements
were BOTH correct.** The brief said *"601 non-cp1252 characters of 6 kinds"*. Measured
2026-08-29: **534 of 28 kinds** over canon alone. Sweeping canon **plus** the generated bundle
mirror gives **1,310 of 34 kinds** — *the likeliest origin of the 601 is a double count of a
duplicated tree* (`LED-89.9`). The brief's "zero arms" and "~12 arms" are likewise both real,
of different encodings.

**(c) `flow-selftest.yml` lives in `~/.claude`, not in this repository** — a path in the brief
that would have sent the edit to a file that does not exist here (`P-4`, and see
`increment-003.md`).

### Independent review

**ABSENT.** No `code-reviewer` verdict exists for this increment. batch-88 ran that lens at
every increment and its packets record the BLOCKs it returned; batch-89 ran it at none, and
this packet will not imply otherwise.

---

## 5 · Risks

- **The repair is at `__main__` only.** Anything importing this module and calling `selftest()`
  in-process inherits the caller's streams, unhardened. Not armed.
- **`backslashreplace` is lossy by design.** A cp1252 consumer now reads `−` where a
  utf-8 one reads `−`. That is the intended trade — a readable escape over a silent
  mojibake — but a downstream parser keying on the glyph would see a different string.
- **The domain is 5 encodings, not all encodings.** `ENC VERDICT-domain` harvests its probe
  from the canon, so it grows with the canon; it does not grow with the set of codecs.
- **The measured character classes are a snapshot** (534 of 28 kinds, 2026-08-29). They move
  every time a canon row is written.

## 6 · Pending

- **This increment is not on `main`.** `1d2e9fe` sits on `origin/claude/batch-89-lean-contract`
  only.
- **`04-validation.md` and `05-close.md` do not exist for this batch.**
- **`state.json`'s `batch_objective` still lists this increment under *"REMAINING INCREMENTS,
  NOT IMPLEMENTED"***, although it shipped 2026-08-29. Not repaired by the 2026-08-30 write,
  which was scoped to `decisions_log`.

## 7 · Suggested next task

**Increment 003** — `python3` is the Microsoft Store alias on this machine, and `V17`
certifies a guard whose interpreter it never runs. It shipped in the same commit as this one;
the packet beside this file records it separately because the requirements are separate.

---

## Increment gate checklist

**Reconstructed 2026-08-30. This checklist did not gate anything.**

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 0 in `s19_app`; 1 authored source file in the flow repo, shared with Increment 003 |
| 2 | Defect OBSERVED before repair | ✓ | `P-8` reproduced on two surfaces, `LED-89.8`; this is the increment's own entry gate and it was met |
| 3 | Tests written in the same increment | ✓ | 4 `ENC` arms in `51203c7`; total 431 → 443 with Increment 003 |
| 4 | RED counterfactual captured | ✓ | the two pre-repair transcripts, plus `ENC PASS!=NOOP` which re-kills an unhardened stream on 4 encodings |
| 5 | Per-increment arm and mutant attribution | **✗** | **ABSENT** — one commit, two increments, no split recorded |
| 6 | Independent `code-reviewer` pass | **✗** | none ran |
| 7 | No file from another lane touched | ✓ | `git show --stat 1d2e9fe` — nothing under `prototypes/` or `build/` |
| 8 | Every file in the landing commit accounted for | ✓ | including `project.toml`'s deletion, which is declared in §2 as belonging to neither increment |
| 9 | Packet written at the increment's gate | **✗** | **Written 2026-08-30, one day after the work.** The defect `V27` reported and this packet repairs |

**An item without a citation is not satisfied — it is asserted.**
