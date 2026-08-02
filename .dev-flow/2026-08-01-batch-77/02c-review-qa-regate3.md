# batch-77 — Phase-2 QA RE-GATE of requirements revision 3

**Batch:** `2026-08-01-batch-77` · **Branch:** `claude/batch-77-memmap-variant-a` @ `9b1b744`
**Under re-review:** `01-requirements.md` **revision 3** (645 lines; rev 2 = 548, rev 1 = 578)
**Prior QA gates:** `02-review-qa.md` (4 blockers) → `02b-review-qa-regate.md` (1 blocker, 3 majors)
**Method:** every verdict executed. Inc-1 and the `safe_text` variants were implemented from the LLR text in an isolated copy of `s19_app/` and mutated there under `PYTHONDONTWRITEBYTECODE=1` (C-46). Working tree proven untouched by hash at both ends:
`screens_directionb.py` = `b11fdfcd25c52bf2fdd4d1e40272d9fa` · `styles.tcss` = `b60b1caef924e912dee914872b131f85`.
**R-10 / R-11 are settled** and reviewed for correct implementation only.

---

## BLUF

**No blockers. My revision-2 blocker is genuinely resolved by removal, and every one of the five items I was asked to re-verify is discharged by execution.** Four majors remain — **all four are trivial edits except one small scoping decision that has an exact precedent to copy.** Nothing here is new design work.

| # | Sev | Finding | Kind |
|---|---|---|---|
| **M-1** | 🟠 | HLR-111's out-of-domain honesty figures (`99.5 % unseen`, `content=1660`) are measured on the **pre-batch producer** — they reproduce byte-for-byte on pristine + CSS only. Batch-77's producer gives **95.9 %** / `content=1601` | trivial edit |
| **M-2** | 🟠 | **`AT-B77-15a` limb 1 goes RED after Inc-2 on a correct implementation** — `LLR-116.7`'s scrub removes the ESC byte, so the control payload is no longer "verbatim". Inc-2's gate is unpassable as worded | trivial edit |
| **M-3** | 🟠 | **§5.3 "Batch acceptance criteria" was deleted** between rev 2 and rev 3 — numbering jumps 5.2 → 5.4. Lost: frozen-engine diff = 0, full-suite baseline, 0-blockers-at-merge, 100 % LLR→TC | trivial edit (restore) |
| **M-4** | 🟠 | **`HLR-112` got no domain and is unsatisfiable out of domain** (802 ticks required, 8 fit); `LLR-112.2` still cites the **withdrawn** `LLR-111.8` as the thing that lowers the run count | small scoping decision, precedent = HLR-111 |

**The five mandated re-verifications, all discharged:**

| Item | Verdict |
|---|---|
| 1 · equality coverage guard | ✅ TRUE on correct code (3 fixtures × 2 regimes), FALSE under a drop-a-run mutation. My rev-2 blocker class is now **structurally impossible** |
| 2 · dangling after removal | ✅ **No orphaned AT, no increment left empty, no TC gap.** One dangling *sentence* → M-4 |
| 3 · `AT-B77-15a/15b` | ✅ 6 verdicts reproduced exactly; **P-55 confirmed**; precondition proven load-bearing; 15a's mutation real; rev-2's 15b mutation confirmed **inert**; I also **executed 15b's predicted mutation** — it holds |
| 4 · `AT-B77-02` mutation | ✅ genuinely reddens — `[49,17]→[50,16]` @66, `[37,13]→[38,12]` @50, exactly as documented |
| 5 · `AT-B77-09` PIN label | ✅ **PIN is correct.** No other §9 row wears a discharge mark over an un-executed prediction |
| 6 · `AT-B77-18` vacuity sweep | ✅ **NOT vacuous.** Both limbs GREEN on correct code, each falsifiable — though limb 2's falsification is mine, not the document's (**m-1**) |

---

## 1 · The five mandated re-verifications

### 1 ✅ The equality coverage guard is sound

Fixture heterogeneity proven **before** any verdict, with the F-1(g) trap reproduced as a control:

```
  ranges = [('0x10000', '0x11000')]  n_ranges=1
  entropy window bands = {'constant/padding': 8, 'medium': 6, 'high/random': 2}
  DISTINCT = 3   heterogeneous = True
  oracle runs from 1 range = 4
  [trap control] random.Random(3) per byte -> [121, 121, 121, 121, 121, 121] (all equal = True)
```

The guard, on correct code and under a "silently drop one run" mutation:

| Fixture | size | oracle | emitted | equality | coverage | GUARD | drop-1-run mutation |
|---|---|---|---|---|---|---|---|
| heterogeneous 1-range | 80×24 | 4 | 4 | True | True | **TRUE ✅** | eq=False → **FALSE ✅ catches** |
| heterogeneous 1-range | 120×30 | 4 | 4 | True | True | **TRUE ✅** | eq=False → **FALSE ✅ catches** |
| sparse 5-region | both | 5 | 5 | True | True | **TRUE ✅** | eq=False, cov=False → **FALSE ✅** |
| `case_08` (801 ranges) | both | 801 | 801 | True | True | **TRUE ✅** | eq=False, cov=False → **FALSE ✅** |

**My rev-2 blocker is resolved by construction, not by patching.** With `is_aggregate` gone there is no filter to empty `emitted`, so the failure I proved (2 ranges → 1 aggregate → `emitted` empty → coverage False) has no way to arise. Confirmed on the entropy-heterogeneous fixture, which is the case that broke rev 1.

*Note, not a finding:* with equality restored the coverage clause is **implied** — executed, it is never False where equality is True on any of the three fixtures. It adds no independent falsifying power. It is harmless and reads as documentation; keeping it is fine.

### 2 ✅ The aggregation removal left no orphan

```
 defined ATs : 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15a 15b 16 18   (18 live)
 AT-B77-17   : appears ONLY in withdrawal records ("withdrawn with LLR-111.8")
 ORPHANS (defined, no owning increment) : NONE
 TC ids      : n=31, 1..31, gaps in 1..31 : NONE
```

Every live AT has exactly one owning increment: Inc-1 → 01/03/**18** · Inc-2 → 15a/15b · Inc-3 → 02 · Inc-4 → 072b/04 · Inc-6 → 05/06/07 · Inc-7 → 11/12/13/14 (15a/b re-run) · Inc-8 → 08/09/16/**10**. No increment lost its content — Inc-2 was *repurposed* from aggregation to the scrub and gained real content. **`AT-B77-10` is now owned (Inc-8)**, closing my rev-2 M-3.

The one thing that *did* dangle is a sentence, not a node — see **M-4**.

### 3 ✅ `AT-B77-15a` / `AT-B77-15b` — six verdicts, precondition proven load-bearing

**P-55 reproduced exactly.** Executed through the shipped surface, per limb per size:

```
--- ZERO CLICKS (today's shipped state) ---
  size=(80,24)  body='Click a region to inspect it - double-click to open in hex'
     limb1 payload verbatim : False -> RED
     limb2 spans == []      : True  -> GREEN
     limb3 no C0/C1 in strip: True  -> GREEN   [NOT EVALUABLE — precondition (limb1) FAILED]
  size=(120,30) identical.

--- PAYLOAD RENDERED (post-HLR-116 auto-select) ---
  size=(80,24)   limb1 True -> GREEN   limb2 True -> GREEN   limb3 False -> RED  [EVALUABLE]
  size=(120,30)  limb1 True -> GREEN   limb2 True -> GREEN   limb3 False -> RED  [EVALUABLE]
```

Revision 2's "limb 3 is RED today" is **FALSE** — it is GREEN, and vacuously, because nothing renders. **The precondition is load-bearing, not ceremonial:** limb 3 flips GREEN→RED at exactly the point limb 1 flips RED→GREEN. Splitting by dischargeability and reporting per arm are both the right repairs.

**Mutations, all executed:**

| Mutation | limb1 | limb2 | limb3 | Verdict |
|---|---|---|---|---|
| `safe_text` → `Text.from_markup` (**15a's**) | True→**False** | True→**False** (spans=2) | — | ✅ **real, reddens both its limbs** |
| remove `safe_text` (**rev 2's 15b**) | GREEN | GREEN | RED→RED | ✅ **INERT, as the document says** |
| C0/C1 scrub, i.e. `LLR-116.7` (**15b's mutation, reverted**) | — | — | RED→**GREEN** | ✅ **non-inert — I executed the prediction; it holds** |

The document could only *predict* 15b's mutation (the scrub does not exist yet). I implemented `LLR-116.7` and confirmed it: reverting the filter genuinely moves limb 3. **That row's ✅ is now earned rather than predicted.**

⚠️ The same execution surfaced **M-2** — see below.

### 4 ✅ `AT-B77-02`'s replacement mutation genuinely reddens

```
######## variant=base (allocator) ########
  size=(80,24)  bar=66  n_gaps=0  GOLDEN widths=[49, 17]  sum=66
  size=(120,30) bar=50  n_gaps=0  GOLDEN widths=[37, 13]  sum=50

######## variant=round_ (plain round(bar*b/total)) ########
  size=(80,24)  bar=66  n_gaps=0  GOLDEN widths=[50, 16]  sum=66
  size=(120,30) bar=50  n_gaps=0  GOLDEN widths=[38, 12]  sum=50
```

Both regimes move; the golden reddens. Every figure matches the document exactly. `n_gaps=0` independently confirms P-58 — rev 2's "substitute the fold denominator" was multiplied by zero and could never have discharged anything.

### 5 ✅ `AT-B77-09` is correctly relabelled PIN, and §9 is honest

`RegionRow.BINDINGS` is `[]` today and `LLR-115.4` keeps it `[]`, so the predicate is GREEN before and after and is falsified only by its named mutation (`add Binding("k", …)`). **PIN is the correct label**, and rev 3 says so plainly — including the self-correction that rev 2 called it "the GATE" and implied a RED that "**will not**" be produced. §5.2 and §9 now agree with each other.

**Audit of every remaining discharge mark in `LLR-111.5` / §9:**

| Row | Claim | My check |
|---|---|---|
| `AT-B77-01`, `AT-B77-03` | ✅ executed | Sound — the shipped tree **is** the mutant, so its RED is the mutation evidence |
| `AT-B77-02` | ✅ executed | ✅ verified above |
| `AT-B77-15a` | ✅ executed | ✅ verified above |
| `AT-B77-15b` | ✅ GATE after Inc-2 | was a prediction at authoring; **I executed it — it holds** |
| `AT-B77-18` | ✅ evaluable today | ✅ verified; limb-2 mutation gap → **m-1** |
| `AT-B77-09` / `AT-B77-16` | PIN | ✅ correct, and §9 states the label rather than claiming discharge |

**No row wears a discharge mark over an un-executed prediction.** §9's two ⚠️ partial rows are accurate and name what they exclude.

### 6 ✅ `AT-B77-18` is not vacuous — executed on `case_08` at both regimes

```
case_08: n_ranges=801  ORACLE runs=801

variant=base (Inc-1 as specced)
  (80,24) bar=66   limb1 no-raise GREEN   limb2 rows 801 vs 801 GREEN
  (120,30) bar=50  limb1 no-raise GREEN   limb2 rows 801 vs 801 GREEN

variant=raise_  (the document's named mutation: allocator raises on avail < n_runs)
  (80,24)  limb1 RED  _B77AllocRaise: avail -734 < n_runs 801   limb2 RED
  (120,30) limb1 RED  same                                       limb2 RED

variant=cap  (MY mutation: region list capped at 50 rows)
  (80,24)  limb1 GREEN   limb2 rows 50 vs 801 RED
  (120,30) limb1 GREEN   limb2 rows 50 vs 801 RED
```

**Both limbs are genuinely falsifiable**, so the batch does have real evidence for the one case it admits it does not fix. Limb 2 in particular is falsified by a *plausible* wrong implementation — capping the region list is exactly what someone might do faced with 801 rows — and that mutation leaves limb 1 green, so the two limbs are independent.

⚠️ But the document names **one** mutation for **two** limbs, and that mutation reddens both. Limb 2 has no independent named falsification in the register — I had to supply one (**m-1**).

---

## 2 · MAJORS

### M-1 🟠 The out-of-domain figures are measured on the pre-batch producer

HLR-111's ⭐ domain callout — the batch's central statement of its own limitation — prints:

```
  R-7 stack CSS (batch-77)   (80,24) bar=66  segs=1601 content=1660 visible=66
                                INVISIBLE runs = 797 of 801  (99.5% unseen)  outside=1594
                             (120,30) bar=50  segs=1601 content=1660 visible=50
                                INVISIBLE runs = 800 of 801  (99.9% unseen)  outside=1600
```

**Executed on the pristine producer with only the R-7 CSS applied** — no `LLR-111.2` fold, no `LLR-111.7` bound:

```
  size=(80, 24) bar=66  segs=1601 content=1660 INVISIBLE=797 of 801 (99.5%) outside=1594  gap widths min/max=(1, 60)
  size=(120,30) bar=50  segs=1601 content=1660 INVISIBLE=800 of 801 (99.9%) outside=1600  gap widths min/max=(1, 60)
```

**Byte-for-byte identical.** The row labelled "(batch-77)" is the *shipped* producer, not batch-77's. The tell is `gap widths max = 60` — gaps are not folded. `LLR-111.2` ("shall render each unmapped gap at exactly one column") sits **before** the `While the image satisfies …` clause in HLR-111's Statement, so it applies unconditionally, including out of domain.

**Batch-77's actual producer**, executed with Inc-1 applied:

```
  (80,24)  bar=66  content=1601  INVISIBLE 768 of 801  (95.9%)
  (120,30) bar=50  content=1601  INVISIBLE 776 of 801  (96.9%)
```

Two consequences:
1. "**99.5 % of runs paint zero columns**" is the pre-change number. The shipping number is **95.9 %**.
2. "**It is not made worse either: the invisible-run count is identical with and without the R-7 widen**" compares two rows that are *both* the pre-fold producer. Against batch-77's producer it is 797 → 768 — slightly **better**, not identical.

The conclusion survives (95.9 % is still unreadable, and the bar is still a summary surface out of domain), but this is the batch's honesty claim and the baseline `C-77-l` hands to batch-78 "with every measurement already paid for". A plausible executed number measured on the wrong producer is this batch's signature defect class.

**Fix — trivial:** re-measure the row with the fold applied, or relabel it "shipped producer + R-7 CSS only" and add the batch-77 row beside it.

### M-2 🟠 `AT-B77-15a` limb 1 is RED after Inc-2 on a correct implementation

`LLR-116.7` (new at rev 3, R-11) puts the scrub **in `safe_text`**: *"shall remove every C0 and C1 control byte from its input … and shall **preserve every non-control character** of the input verbatim."* That wording is precise and correct.

But `LLR-116.6`'s threshold says *"payload verbatim in `render().plain`"*, and the `AT-B77-15a` block says *"Limbs 1–2 (**payload verbatim** ∧ `spans == []`)"* — with no non-control qualifier. Executed per payload:

```
=== POST-Inc-2 (LLR-116.7 scrub) ===
  markup-1  'sensor[red]'                             verbatim=True  spans=0
  markup-2  'x[link=file:///etc/passwd]click[/link]'   verbatim=True  spans=0
  control   'boom\x1b[31mRED\x1b[0m'                   verbatim=False spans=0
  ALL-verbatim (AT-B77-15a limb1 as worded) = False
  markup-only verbatim                      = True

=== PRE-Inc-2 (pristine) ===
  ALL-verbatim (AT-B77-15a limb1 as worded) = True
```

Inc-2's gate is "**`AT-B77-15a` + `AT-B77-15b`, per limb per size**". As literally worded, limb 1 is **RED at that gate on a correct implementation**, because the scrub Inc-2 lands is what removes the byte.

This is introduced by the corrective pass: rev 2 kept the scrub out of the batch, so "verbatim" was consistent then. R-11 pulling it in creates the conflict, and only the LLR that owns the scrub got the wording right.

**Fix — trivial:** align limb 1 to `LLR-116.7`'s own phrasing — "every **non-control** character preserved verbatim" — in `LLR-116.6`'s threshold and in the `AT-B77-15a` block. Two clauses.

### M-3 🟠 §5.3 "Batch acceptance criteria" was deleted

Revision 3's section numbering jumps **5.2 → 5.4**:

```
464:## 5. Validation strategy
466:### 5.1 Standing rules
475:### 5.2 Dual traceability — behavioural chain
501:### 5.4 IDs
```

Revision 2 (`78d3533`) had it at line 452. What is gone:

```
### 5.3 Batch acceptance criteria
- 100 % of LLRs covered by ≥1 TC with a pass result; every US has ≥1 passing AT with boundary + negative evidence.
- Every gate AT demonstrated RED pre-change, per size arm.
- Every PIN labelled PIN, with its falsifiability discharged by a post-fix mutation whose transcript is pasted.
- 0 blocker findings at the merge gate; frozen-engine diff = 0 (source AND `_ENGINE_TEST_FILES`).
- TC-011 green and unmodified. Full suite green — baseline 2514 passed / 2 skipped / 3 xfailed (FULL form).
```

**The batch now has no stated definition of done** — no frozen-engine diff gate, no full-suite baseline figure, no "0 blockers at merge", no 100 % LLR→TC rule. Nothing else in the document carries these; §5.1 is standing *method* rules and the increment table gives per-increment gates, not batch exit criteria. (The missing 100 % LLR→TC rule is also what would have caught **m-2** below.)

I believe this is collateral from the R-10 rewrite rather than a decision — nothing in §6.4's reconciliation log records dropping it.

**Fix — trivial:** restore verbatim, updating the AT list to `AT-B77-01…18` and re-confirming the baseline figure.

### M-4 🟠 `HLR-112` got no domain and is unsatisfiable out of domain; `LLR-112.2` cites a withdrawn requirement

R-10 gave `HLR-111` an explicit domain. `HLR-112` — which breaks on the *same* fixture — was left universal:

> the address ruler **shall** emit one tick label per emitted **run** start plus one label for the last mapped byte; … and **shall not** emit any tick whose rendered width is smaller than the label it carries.

On `case_08` those two clauses cannot both hold:

```
  ruler width 66: max 8-char labels that fit legibly = 8
     HLR-112 requires 1 tick per run start + last mapped byte = 802 on case_08
     satisfiable together? False
  ruler width 50: max legible = 6      satisfiable together? False
```

`LLR-112.2` half-rescues it ("retain the first and last labels in preference to any interior label **when labels must be dropped**"), but the parent Statement has no escape clause, so the HLR is contradictory as written.

**And its rationale rests on the withdrawn requirement:**

> **Interaction with R-7:** the widened bar raises the tick budget and **`LLR-111.8`'s aggregation lowers the run count the ruler must label** — but the elision predicate is what makes any residual loss visible rather than silent.

`LLR-111.8` is withdrawn (R-10). Nothing lowers the run count any more, so on `case_08` the ruler must label **801 run starts**, and the loss is not "residual" — it is essentially total. This is the only dangling reference the removal left, and it is load-bearing for the clause above it.

**Fix — small scoping decision with an exact precedent:** mirror `HLR-111`'s `While the image satisfies …` domain clause onto `HLR-112` (out of domain: retain first + last, no raise), and delete the `LLR-111.8` sentence. The pattern R-10 already established is copyable; this is not fresh design.

---

## 3 · MINORS

| # | Finding | Fix |
|---|---|---|
| **m-1** | `AT-B77-18`'s register row names **one** mutation for **two** limbs, and it reddens both. Limb 2 has no independent named falsification. Executed, `cap the region list at 50` reddens limb 2 alone (limb 1 stays GREEN) — a plausible wrong implementation given 801 rows | add that mutation to the row; one table cell |
| **m-2** | **`LLR-116.7` has no TC and is absent from the functional chain** — which reads "HLR-116 → LLR-116.1…**.6**". Its own threshold text already specifies the cases (`'sensor\x1b[31m…'` → ESC gone, `'ab\x00c'` → `'abc'`, markup/URL payloads unchanged) | mint `TC-B77-32`, extend the chain to `.7` |
| **m-3** | §5.2's `AT-B77-15b` cell reads "genuinely RED after Inc-7; GREEN by Inc-2's scrub" — but Inc-2 **precedes** Inc-7, so in the shipping sequence it is never RED; the RED is counterfactual. Ordering constraint 2 states this correctly | reword the cell |
| **m-4** | The functional chain writes `LLR-111.1…**.9**`, a range that nominally still includes the withdrawn `.8` | write `.1–.7, .9` |

---

## 4 · Mandated-check disposition

| Check | Result |
|---|---|
| Equality guard TRUE on correct / FALSE on wrong, heterogeneous fixture proven first | ✅ §1.1 — 3 fixtures × 2 regimes; drop-a-run mutation caught everywhere; F-1(g) trap reproduced as a control |
| Nothing dangling after the removal (orphan ATs, empty increments, traceability holes, C-18/C-21) | ✅ no orphan AT, no TC gap, every AT owned by exactly one increment. Two holes found: a dangling **sentence** (**M-4**) and a missing **TC** for the new `LLR-116.7` (**m-2**) |
| `AT-B77-15a/15b` per-arm (3 limbs × 2 sizes), precondition, non-inert mutations | ✅ six verdicts reproduced; P-55 confirmed; precondition proven load-bearing by execution; 15a's mutation real; rev-2's 15b mutation inert; 15b's predicted mutation **executed by me and holds** |
| `AT-B77-02` mutation genuinely reddens | ✅ `[49,17]→[50,16]` @66, `[37,13]→[38,12]` @50 — exact match; `n_gaps=0` confirms the old mutation was a no-op |
| `AT-B77-09` PIN label; no other §9 discharge mark over a prediction | ✅ PIN correct; full register audited, all marks earned |
| **`AT-B77-18` vacuity** — executed on `case_08`, both regimes, mutation per limb | ✅ **not vacuous.** Limb 1 falsified by the document's mutation (`avail -734 < n_runs 801`); limb 2 falsified independently by mine. Register gap → **m-1** |
| New-vacuity sweep on everything rev 3 added or changed | `LLR-111.7` sound (verified rev 2) · equality guard sound · `AT-B77-18` sound · `AT-B77-15a/b` split sound · `LLR-116.7` sound and executable. **Two conflicts found, both wording-level: M-2 and M-4** |
| C-40 / C-31 / C-32-C-37 applied | C-40: every predicate's subject checked in its expression; limb-level mutations executed. C-31: the quantified set is now the `_merge_band_runs` oracle, verified rule-derived on a heterogeneous fixture. C-32/C-37: limb 3 read from the **painted strip**, not `.plain`, per the document's own instruction |

---

## 5 · Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Verified by execution, not by reading the diff | ✓ | Inc-1 + 4 `safe_text` variants implemented from LLR text; 5 producer variants × up to 2 regimes |
| Fixtures validated before use | ✓ | heterogeneity proven (3 bands); F-1(g) per-byte-reseed trap reproduced as a control |
| Per-arm verdicts (CC-1) | ✓ | `AT-B77-15a/b`: 3 limbs × 2 sizes × 2 states; `AT-B77-18`: 2 limbs × 2 sizes × 4 variants |
| Hunted for what the fix introduced | ✓ | **M-2** (R-11's scrub vs "verbatim") and **M-4** (R-10 scoped HLR-111 but not HLR-112) are both corrective-pass artifacts |
| No manufactured findings | ✓ | Six items re-verified as **clean and stated plainly**; the four majors each carry an executed transcript or a quoted diff |
| Trivial-vs-design named, as asked | ✓ | M-1/M-2/M-3 and all minors are trivial edits; **M-4 alone is a scoping decision**, with `HLR-111`'s domain clause as the pattern to copy |
| Working tree untouched, proven by hash | ✓ | `b11fdfcd25c52bf2fdd4d1e40272d9fa` / `b60b1caef924e912dee914872b131f85` before **and** after; isolated tree deleted |
| Self-caught probe defect recorded | ✓ | My first Inc-1 probe (rev-2 re-gate) read `bar=0` from a pre-re-render widget reference — my own B-3 trap. All figures here come from probes that re-query after every render |
| Test-results section left blank | ✓ | none added; all figures are Phase-2 probe transcripts |

---

## 6 · Recommendation

**No blocker. Clear to proceed once four small edits land** — three are pure text, one is a scoping decision with a precedent already in the document:

1. **M-1** — re-measure the out-of-domain row with the gap fold applied (or relabel it as the pre-batch producer). The `99.5 %` becomes `95.9 %`; the "not made worse" sentence becomes "slightly better".
2. **M-2** — change "payload verbatim" to "every **non-control** character verbatim" in `LLR-116.6`'s threshold and the `AT-B77-15a` block, matching `LLR-116.7`'s own wording.
3. **M-3** — restore §5.3 Batch acceptance criteria.
4. **M-4** — give `HLR-112` the same domain clause `HLR-111` has, and delete the `LLR-111.8` sentence from `LLR-112.2`.

Plus **m-1** (record limb 2's mutation), **m-2** (mint `TC-B77-32` for `LLR-116.7`), **m-3**, **m-4**.

**Revision 3 is the strongest of the three by a wide margin.** R-10 traded a broken subsystem for a smaller, honest requirement with a stated domain — the right call, and my rev-2 blocker is gone by removal rather than by patching, which is the more durable resolution. The document also caught three of its own defects that no lane had reported (`AT-B77-02`'s no-op mutation, `AT-B77-15`'s CC-1 mis-verdict, and the false layout-perturbation rationale it had asserted to the operator twice) and withdrew them explicitly rather than quietly. The remaining majors are all in the seams the rewrite touched — which is exactly where they should be looked for, and all of them are cheap.
