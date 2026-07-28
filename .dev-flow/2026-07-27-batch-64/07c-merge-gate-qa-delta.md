# batch-64 — QA merge-gate DELTA verdict over `93a0379`

**Verdict: `OK-TO-MERGE`. 0 HIGH · 3 MEDIUM (new) · 2 LOW (new).**

**BLUF: HIGH-1 is genuinely closed and HIGH-2 is genuinely discharged — both verified by measurement,
not read from the disposition. The HIGH-2 discharge is in fact *stronger* than claimed: I proved the
DISCHARGE region is the ONLY divergent region in C-40's normative body, so no re-run is required. All
four MEDIUM corrections are accurate against `04-measurement-frozen` rather than against the summary.
Three new MEDIUMs were introduced by the fixes, none blocking. One correction I must report:
the "nothing is writing to this tree" commitment did not hold — `VERIFY.md` was rewritten by an
unrelated process at 19:26 — but I re-ran the affected acceptances and the batch's shipped content is
intact and GREEN.**

## Snapshot at read time

```
HEAD        = 93a0379   (ca36f66 -> b02df84 -> 93a0379)
origin/main = 082ada9   merge-base = 082ada9  -> RC-1 holds
working tree: clean
git diff --stat origin/main...HEAD -- <_ENGINE_PATHS> s19_app tests examples pyproject.toml  -> empty
```

Criteria 2 and 3 re-confirmed unchanged: **zero engine-frozen diffs, zero production/test diffs.**

---

## 1. HIGH-1 — **CLOSED**

Measured on the live `~/.claude/commands/dev-flow.md`:

```
'8 occurrences'         hits in file : 0
'occurrences enumerated' hits in file : 0
```

The tail now reads *"Same family, enumerated (never totalled — three registers disagree, and the
enumeration itself has been re-drawn) across batches 60–63 …"*. The count is gone, the sentence no
longer forbids totals while citing one, and **A-12** (*"the encoded text carries no occurrence
total"*) is no longer falsified.

**The normative body is untouched — confirmed both ways:**

| convention | frozen block 2 | live | identical |
|---|---|---|---|
| incl. trailing separator space | **1 976 B `49cbea4bde7547a9`** | **1 976 B `49cbea4bde7547a9`** | ✅ |
| rstrip | 1 975 B `d893d16305a7fc09` | 1 975 B `d893d16305a7fc09` | ✅ |

Your `1 976 B / 49cbea4bde7547a9` is exact. `AT-B64-04` and `AT-B64-05` are measured over this body
and are **unaffected**. The fix is confined to the `(Measured:)` tail exactly as scoped.

---

## 2. HIGH-2 — **DISCHARGED. No re-run required.**

You asked whether the read-set measurement discharges it or whether the arms need re-running. **It
discharges it, and I can put it on a firmer footing than the read-set argument itself.**

I decomposed C-40's normative body into its four regions and hashed each, frozen vs installed:

| region | frozen | live | sha (frozen → live) | identical |
|---|---|---|---|---|
| preamble | 460 B | 460 B | `4c0c112eb3ef5561` | ✅ |
| **LIMB 1** | **1 209 B** | **1 209 B** | **`fb24cf1796b5b9c8`** | ✅ |
| **LIMB 2** | **1 007 B** | **1 007 B** | **`791424bfe23ff975`** | ✅ |
| DISCHARGE | 1 888 B | 2 035 B | `b8ec2e4478b45765` → `5a71e6a62f330af7` | ✗ |
| total | 4 564 B | 4 711 B | | |

**`DISCHARGE` is the only divergent region in the entire normative body.** That is a stronger claim
than "the harness reads only limb spans" — it does not depend on correctly characterising the
harness at all. Your limb figures reproduce exactly.

Supporting checks, all executed:

- Every harness feature resolves to a limb span, none to `DISCHARGE`. I confirmed six independently
  by needle: `the predicate itself declares`, `regression PIN, not a gate`, `the semantic one
  governs`, `its domain includes the platform` → **LIMB 1**; `a positive control shaped to the
  implementation`, `a consolidation that drops observables` → **LIMB 2**; **zero in DISCHARGE**.
- All four mutations at `:194-197` target limb spans. I specifically checked the third — *delete the
  A-23 domain ruling* — and confirmed that text lives inside the LIMB 1 span.
- Block 1 in the frozen manifest is still **6 219 B / `5cb146e980deb639…`**, so `AT-B64-01` /
  `AT-B64-02` remain admissible under `§3.0` against the block they name, and the block-vs-installed
  divergence is confined to a region no figure depends on.

**Do not re-run the arms.** The measurement would be over byte-identical inputs and would tell you
nothing you do not already have hash-bound.

---

## 3. The four MEDIUM corrections — **all accurate**

Checked against `04-measurement-frozen.md §2.1` directly, not against your summary:

```
delete D            -> 6/9  RED  lost=[1, 4, 6]
delete B+G+H        -> 7/9  RED  lost=[5, 9]
delete C+F          -> 7/9  RED  lost=[3, 8]
delete A+C          -> 8/9  RED  lost=[7]
```

- **`{D}`→6/9, `{B,G,H}`→7/9, `{C,F}`→7/9, `{A,C}`→8/9** — all four exact. ✅
- **Four**, not three. The three GREEN mutations (`delete B`, `delete C`, `delete G` alone, each 9/9)
  are correctly excluded from the reddening count. ✅
- Occurrence sets `{1,4,6} {5,9} {3,8} {7}` are **pairwise disjoint**. ✅
- Clause overlap `{C,F} ∩ {A,C} = {C}` — correct, and now stated. ✅
- Union = `{1,3,4,5,6,7,8,9}`; **occurrence #2 absent**, now stated as a gap in all three artifacts
  rather than implied by silence. ✅
- **`BLOCKER-1`** struck through with the discharge recorded above it and the superseded text kept —
  the reversal stays traceable. Good practice. ✅
- **Line-ending proof withdrawn as VOID** with the reason measured (`core.autocrlf=true`) and the
  conclusion preserved on independent evidence. Its cited `+2/−1` for `dev-flow.md` matches my own
  measurement (1 inserted line + 1 in-place replacement). **This is the model disposition** — the
  withdrawal is recorded, not quietly replaced. ✅

**No wrong claim was traded for another in these four.**

---

## 4. New findings introduced by the delta

### D-1 (MEDIUM) — the rider now asserts a re-draw that did not happen

The new tail says *"the enumeration itself **has been re-drawn**"* and still points at
`01b-qa-catalog.md §AT-B64-04`. That file was **not touched** by either delta commit
(`git diff --stat ca36f66..HEAD -- 01b-qa-catalog.md` → empty) and still contains **8 table rows** and
the line *"**True count = 8, spanning batches 60-63.**"* (`:388`).

The load-bearing half of HIGH-1 is genuinely fixed — the false cardinality is gone and A-12 is
honoured. What survives is the residue: a reader following the pointer lands on the same 8-row set
A-18 called *"a hand-shaped set"*, now told it has been re-drawn. **Cheapest fix: add row 9 (the
`startswith("| 0x00001")` prefix guard) to `01b`'s table** — one line, and it makes the pointer true
*and* retires the C-40 limb-2 objection entirely.

### D-2 (MEDIUM) — `§5d`'s "authoritative POST record" is stale on 2 of 5 rows at HEAD

`§5d` states *"This table is the authoritative POST record"* and *"closes the security gate's F2/F4"*.
Re-measured against the live files:

| file | §5d POST | measured at HEAD | verdict |
|---|---|---|---|
| `docs/engineering-rules.md` | 19 435 / `5618029c…` | 19 435 / `5618029c…` | ✅ |
| `project_devflow_control_lineage.md` | 42 450 / `50cf146e…` | 42 450 / `50cf146e…` | ✅ |
| `.dev-flow/BACKLOG.md` | 26 057 / `781c82e9…` | 26 057 / `781c82e9…` | ✅ |
| `~/.claude/commands/dev-flow.md` | 68 311 / `21a031f7…` | **68 391 / `e103af29…`** | **stale +80 B** |
| `~/.claude/skills/tui-design/VERIFY.md` | 11 684 / `3c6016fc…` | **21 341 / `5d7c7425…`** | **stale +9 657 B** |

`dev-flow.md` is stale by exactly your own HIGH-1 fix — `§5d` was written in `b02df84`, the fix landed
in `93a0379`, and the row was not carried forward. Bookkeeping lag, not a content problem.

`VERIFY.md` is the other matter — see §5.

**Fix: one caveat line** — *"measured at `<sha>`; the three out-of-VCS rows are not under change
control and will drift"* — converts a false claim into a true one at zero cost.

*Credit where due:* `§5d` drops the `predicted Δ` column entirely, which retires my original **M-3**
(the back-fitted prediction) by supersession.

### D-3 (MEDIUM) — `§7.10` id collision, and it masks the still-open M-5

`BACKLOG-PROCESS.md` now carries an item labelled **`batch-64 §7.10`** = the security gate's F3
(out-of-VCS backups in a session `Temp` dir). But `01-requirements-consolidated.md §7` **item 10** is
a different carry — *TRIM-C offered as "the cheapest form" while superseded* — and it still reaches no
backlog file (`TRIM-C` → **0 hits** across all three). Likewise the postmortem's own headline
candidate (`disarm` → **0 hits**) and `arch MAJOR-7` (**0 hits**), which were my M-5/M-6 and are
correctly still open.

The collision is worse than a duplicate label: **a presence check on `§7.10` now returns a false
YES.** That is a vacuous check created by renumbering, and it is the same disease as the disclosed
`D-` register collision. Fix: renumber the two new security carries to `§7.12`/`§7.13`.

### D-4 (LOW) — "seven features" contradicted by its own table one line later

`07b-merge-gate-security-delta.md:109` says the harness yields *"seven features"*; the table
immediately beneath enumerates **eight** (5 in LIMB 1 + 3 in LIMB 2), which is what I counted from the
harness block (`04-measurement-frozen.md:153-154` → 8 `=`-tokens). **The table is right; the word is
wrong.** Same self-contradiction shape as the C-40 `F2` the code review caught. It does not weaken the
discharge — the enumeration is complete and correct, and my region decomposition does not rely on the
count.

### D-5 (LOW) — duplicated clause in the shipped rider

The new tail contains *"three registers disagree"* **twice** in one sentence: once in the new
parenthetical and once in the pre-existing trailing clause. Not false, but redundant in permanent
global text.

---

## 5. Correction to the record: the tree was written to during this pass

You committed that *"nothing is writing to this tree during your pass."* That did not hold, and you
should know it rather than take my verdict as evidence it did:

```
tui-design/LANGUAGES.md   19:22
tui-design/COMPONENTS.md  19:24
tui-design/DATAVIZ.md     19:25
tui-design/DENSITY.md     19:26
tui-design/VERIFY.md      19:26   9 960 -> 21 009 B (normalised), 10 -> 12 '##' sections
```

An unrelated process rewrote the `tui-design` skill wholesale, including **`VERIFY.md` — one of this
batch's four control destinations**. This is the **fifth** occurrence of the HIGH-3 mechanism and the
first to land on a shipped control destination. It is not your doing and HIGH-3 is already carried, so
I am not raising it as a new HIGH — but it is the concrete demonstration that the carried finding is
live, not theoretical.

**I re-ran every affected acceptance on the current file. The batch's content is intact:**

- Block 4 re-derives at **1 540 B / `b1cdc97013f792d22e3bca494cf0bd6d96592583b2403421c7eee2da0a4c9e99`**
  — exactly the manifest value.
- **Block 4 is still an exact substring of the live `VERIFY.md`** (and was absent from the `.PRE`, so
  the paste is the batch's).
- **`PP-4` re-runs GREEN:** `## Pin the truth` @6224 < extension @6566 < `## Mutation-test` @8108 —
  still inside its section — and **0 new `##` inside the extension**. The two added `##` sections are
  the third party's, elsewhere in the file.
- **`AT-B64-08` re-runs GREEN:** 0/12 identifiers over block 4.

**`US-B64-4` remains covered by executed, currently-true observations.**

---

## 6. Status of my original findings

| finding | status |
|---|---|
| HIGH-1 false total in the rider | **CLOSED** (residue → D-1) |
| HIGH-2 body identity / arm admissibility | **DISCHARGED** |
| HIGH-3 out-of-VCS change control | **carried** — recurred during this pass (§5) |
| M-1 mutation count / disjointness / occ. #2 | **FIXED** in all three artifacts |
| M-2 BLOCKER-1 contradiction | **FIXED**, reversal traceable |
| M-3 back-fitted `predicted Δ` | **retired** by `§5d` superseding `§2` |
| M-4 void line-ending proof | **WITHDRAWN**, exemplary handling |
| M-5 `§7.10` TRIM-C + `disarm` uncarried | **still open**, now masked (D-3) |
| M-6 `arch MAJOR-7` uncarried | **still open** |
| L-1 / L-2 / L-3 | unchanged, non-blocking |

## 7. Verdict

**`OK-TO-MERGE` — 0 HIGH.**

Both blocking findings are closed by measurement I re-derived rather than accepted. The three new
MEDIUMs are bookkeeping and pointer accuracy; none affects shipped content, and all three have
one-line fixes. Nothing in the delta touched production code, tests, or the engine-frozen set.

Recommended before merge (cheap, none blocking): **D-1** add row 9 to `01b`; **D-2** date-stamp `§5d`;
**D-3** renumber the colliding `§7.10`.

Carried into the next batch: **HIGH-3** — the out-of-VCS legs need real change control. Section 5 of
this document is the evidence that the current arrangement does not detect edits, including edits to
text this batch shipped.
