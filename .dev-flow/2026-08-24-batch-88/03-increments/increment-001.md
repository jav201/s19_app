# Increment 001 — `LLR-88.6` · `LLR-88.7` — the census oracle becomes token membership

| Field | Value |
|---|---|
| Batch | `2026-08-24-batch-88` |
| Increment | `001` of 7 — **lands first by operator ruling**, so the re-baseline is recorded before any canon-seeding evidence exists |
| Lane | none — single lane |
| Requirement(s) | `LLR-88.6` (oracle) · `LLR-88.7` (the notice names its population) |
| Acceptance | live `V22` census 302 → 306 of 570 with the four ids checked **one at a time**; `--selftest` 194 arms exit 0; two single-edit kill mutations |
| Date | `2026-08-26` |

---

## 1 · What changed

**`v22_canon_mirror` stopped deciding by substring.** `if rid not in canon` was true whenever a
LONGER id shared `rid`'s prefix, so the seeding backlog under-counted itself. It now tests membership
in the token set `_ATLAS_ID_REQ` harvests from the canon.

**The notice names its population** (`LLR-88.7`) — *ids DECLARED AS HEADINGS in the
`.dev-flow/**/01-requirements.md` corpus* — and states that `ATLAS-ORPHANS.md`'s heading census
**agrees** at this figure while its mention census is larger. **The agreement is the real result:**
V22 and the Atlas used to disagree (302 vs 306) because the Atlas had been using token membership all
along; this increment is what made them agree. That sentence was written after the review pointed out
the first draft named the file without stating what it now says.

**Two selftest arms**, and the shape of them is the point. The QA plan's §2.4 **rejected three
proposed arms** for this change as tautological — each rebuilt the rule's own expression inside the
test and asserted against its own recomputation, so reverting the rule left them green while the live
census moved. It declared **one arm owed**: call the census producer over a multi-batch fixture and
assert the **emitted figure**.

---

## 2 · Files modified

| File | Kind | Change |
|---|---|---|
| `~/.claude/docs/tools/devflow-validate.py` | source | the oracle, the notice, the `_v22_outcome` docstring, two arms |
| `~/.claude/skills/dev-flow/scripts/devflow-validate.py` | build output | `--sync-bundle`, byte-identical mirror, never hand-edited |
| `.dev-flow/**` + `_derived/` | doc | this packet, `LLR-88.6`'s restated threshold, Atlas regenerated at the gate |

| Count | Value |
|---|---|
| **SOURCE files** | **1 / 4** — the bundle is a declared build output, not an authored file |
| Test files | 0 (uncapped) — the arms live in the validator's own `--selftest` |

---

## 3 · How to test

```bash
export PYTHONIOENCODING=utf-8          # cp1252 otherwise; corrupts the transcript, never the numbers
python ~/.claude/docs/tools/devflow-validate.py --selftest          # PASSED, 194 arms, 9 V22
python ~/.claude/docs/tools/devflow-validate.py "C:/Users/jjgh8/Github/s19_app" | grep V22
```

---

## 4 · Test results

**Selftest:** `SELFTEST PASSED`, exit 0, **194** arm lines (192 baseline **+2**), **9** `V22` arms.

**Live census, one run each, pasted:**

```
BEFORE: 302 of 570 batch-declared ids …                       (HLR 83 · LLR 209 · US 10)
AFTER : 306 of 570 ids DECLARED AS HEADINGS in the …corpus …  (HLR 85 · LLR 209 · US 12)
```

**The +4 verified per id, never as a total** — a substring→token change that moved the count by +4
for the *wrong* four ids would pass a total and fail this:

```
HLR-053   substring-present=True   token-present=False
HLR-056   substring-present=True   token-present=False
US-064    substring-present=True   token-present=False
US-068    substring-present=True   token-present=False
```

Family arithmetic reconciles term by term: HLR 83→85 (+2), LLR 209→209 (0), US 10→12 (+2) = **+4**.
Denominator held at 570, which is the check that the edit declared no new ids.

**Independent confirmation:** `ATLAS-ORPHANS.md` bullet 3 reads `corpus heading ids never in the
canon: 306` — the Atlas computed token membership all along, so the two now agree. The notice's
agreement claim is measured, not asserted.

### Kill mutations — executed against COPIES, never the live file

| Mutant | Single edit | `ORACLE-token-rule` | `SCOPE-stated` | selftest |
|---|---|---|---|---|
| `m4_v22_substr` | `canon_ids` → `canon` | **FAIL** | ok | FAILED |
| `m14_invert` | `not in` → `in` | **FAIL** | ok | FAILED |
| `m5_pop_phrase` | drops the population phrase | ok | **FAIL** | FAILED |
| `m5b_orphan_drop` | drops the orphan-census clause | ok | **FAIL** | FAILED |

Every mutant was asserted **non-no-op at build time**, so a mutation that changed nothing was a hard
error rather than a silent green. Each reddens **exactly one** arm and leaves the other green:
orthogonal by conjunct, which is what tells the oracle's coverage apart from the message's.

### 🛑 The HIGH the independent review caught, and it is the batch's own thesis

**The first version of `ORACLE-token-rule` asserted the surfaced id with `"HLR-6" in message` — a
SUBSTRING test, inside the arm whose entire subject is the substring bug.** `HLR-6` is a substring of
`HLR-64`, so inverting the rule (`rid in canon_ids`) emitted `e.g. HLR-64` and the arm still passed.

Measured, not feared: under `m14_invert` — a **total inversion** of V22's membership test, which
would report every reflected id as backlog and drop every genuine gap — the selftest printed
**`SELFTEST PASSED`, all 194 arms green, exit 0.**

I wrote a check that could not fail, inside the increment whose purpose is removing checks that
cannot fail. It was not caught by me; it was caught by the `code-reviewer` lens, which built the
inversion mutant I had not thought to build. **My own two mutations were both real kills and both
insufficient** — they probed the oracle's *presence*, never its *direction*.

Fixed by pinning the sample to its closing delimiter (`"e.g. HLR-6)"`), and the fixture grew a third
batch so one arm exercises all three cases `LLR-88.6` names — substring-false-positive, exact-match,
**plain-absence**, which is the rule's dominant real case (304 of the 306 live entries) and had no
coverage at all.

### Five more from the same review, all taken

| # | Finding | Disposition |
|---|---|---|
| MED | `_v22_outcome`'s **docstring** still said *"batch-declared ids … 276 individual findings"* | Corrected. **This is the description-vs-behaviour family this batch closes**, and the QA plan caught the identical shape in `_artifacts` in the same batch |
| MED | An adjacent comment installed a **bare, pre-fix** figure (302, undated) | Now `306 … (measured 2026-08-25)`. `LLR-88.8` forbids a bare figure in terms; the increment wrote one three lines from a comment that obeys |
| MED | The oracle comment claimed both sides are *"tokenised by one expression"* | **False.** `_declared_ids` keeps its own copy of the id grammar. They agree today and nothing enforces it; the comment now says so |
| MED | `LLR-88.6` declared **≥ 3 arms**; **1** shipped | Threshold restated with its reason (QA §2.4's *"one arm replaces all three"*) rather than left silent |
| LOW | The comment credited all four surfaced ids to the substring bug | **Only two are.** `HLR-053`/`HLR-056` come from the range-notation phantom `HLR-053..HLR-056`; `US-064`/`US-068` exist only as `a`/`b` splits. **Not one of the four is retired by plain seeding** — and the backlog is a list people act on |

---

## 5 · Risks

- **`_ATLAS_ID_REQ` and `_declared_ids` carry the same id grammar in two places.** Numerator and
  denominator of this census now depend on them agreeing. They do today — the live delta is exactly
  the four expected ids — but by maintenance, not construction, and `_declared_ids`' own docstring
  records that pattern being wrong once already. Named in the code; the factoring is a second edit
  region and not this increment's.
- **The backlog grew by four entries that seeding cannot retire.** Recorded in the comment; the
  range-notation phantom is a separate unfixed defect (97 instances measured).
- **False positives probed and clean:** all 306 live entries checked against bold, backtick, link,
  table-cell and trailing-punctuation forms — **0** ids lost to canon formatting.

## 6 · Pending

- **`V7` is RED and stays red until Inc 7.** The flow hash moved because this increment edited the
  validator; `LLR-88.16` bumps and re-hashes **last**, by design — a bump before the final edit
  publishes a hash that lies.
- **`V16` ×2** clears when the two flow repos are committed. **Not pushed** — that is the operator's.

## 7 · Suggested next task

**Inc 2** — the V23 strict grammar **and** the citation harvester. Its oracle is already still (the
Phase-1 de-minting), so it moves no live verdict, and its evidence is necessarily synthetic.

---

## Increment gate checklist

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 1 authored + 1 declared build output |
| 2 | Tests written in the same increment | ✓ | 2 arms, both reddened by named mutations |
| 3 | Layer 0 where the criterion applies | ✓ | the arms ARE the unit layer for a validator rule |
| 4 | RED counterfactual captured | ✓ | §4 — four mutants, each non-no-op at build time, each reddening exactly one arm |
| 5 | Reverse census on every touched symbol | ✓ | message blast radius swept across `~/.claude` and s19_app: **0** rules, arms, templates or tests key on the old sentence; every other hit is a frozen run transcript |
| 6 | `code-reviewer` passed — a HIGH blocks | ✓ | ran independently, returned **BLOCK** with 1 HIGH + 5; **all six taken**, re-verified, and the HIGH's own mutant now reddens |
| 7 | No file from another lane touched | ✓ | the operator's untracked work under `prototypes/`, `build/` neither read nor written |
| 8 | Frozen interfaces untouched | ✓ | no `s19_app/`, `tests/` or `tools/` file touched |
| 9 | Coverage claims verified on disk | ✓ | every figure pasted from a run on this tree, including the BEFORE census measured pre-edit |
| 10 | Load-bearing emptiness declared | ✓ | the false-positive claim is an ABSENCE; its positive control is that the same probe **finds** 2 present-at-a-word-boundary ids (the range phantom), so its silence about the other 304 is a measurement, not a blind spot |
| 11 | Mutation verdicts per arm | ✓ | §4 table — per arm, per mutant, both directions |

**An item without a citation is not satisfied — it is asserted.**
