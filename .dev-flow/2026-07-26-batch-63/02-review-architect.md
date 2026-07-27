# batch-63 — Phase-2 INDEPENDENT architect review

> **Reviewer:** independent architect (did not author `01-requirements-architect.md`).
> **Under review:** `01-requirements-architect.md` **REV 4** (normative), `01b-qa-catalog.md` REV 2,
> `01-requirements.md`, `PLAN.md`, `00-measurements.md`, against
> `s19_app/tui/services/report_service.py` @ `031ca8d`.
> **Method:** every threshold asserted below was **executed**, never predicted. All probes ran from
> the session scratchpad against a `git archive HEAD` export
> (`scratchpad/exp`) — the worktree was not mutated (`git status --porcelain` shows only
> `.dev-flow/`). Probe files: `scratchpad/rev63.py` (harness), `pA.py`, `pB.py`, `pC.py`.

---

## 1. BLUF

**Return to Phase 1. Five blockers.** The design *ruling* is sound — I re-derived the pair
independently and it holds — but three of the artifact's load-bearing claims do not survive
execution, and the two Phase-1 normative artifacts specify a mutually unsatisfiable implementation.

| # | class | finding | one-line evidence |
|---|---|---|---|
| **B-1** | blocker | §3's acceptance blocks (AT-170/171) mandate the **in-cell** indicator that §12.2 **withdrew** and R-TUI-091(a) **forbids** | `01-requirements-architect.md:371` vs `:458` and `:460` |
| **B-2** | blocker | The two Phase-1 artifacts disagree on **AT-166…AT-171**, on the **R-TUI ids** (qa's `R-TUI-079/080/081` are **live batch-48 ids**), and on the **LLR ids** — the US→HLR→LLR→TC chain does not close | `01b-qa-catalog.md:202,257,274,316,431`; `.dev-flow/2026-07-16-batch-48/01-requirements.md:272` |
| **B-3** | blocker | qa **TC-406** pins `CELL_BYTES >= 256` as a drift floor; the architect rules **64**. The ruled constant fails its own catalogued TC by construction | `01b-qa-catalog.md:438` vs `01-requirements-architect.md:590` |
| **B-4** | blocker | The **D-16 "index vs evidence" reframing** — the sole justification for a 64-byte cell — is **false for 3 of the 4 bounded cells**. R-TUI-091(b)'s mandated pointer would be a false statement in the document | probe `pC` §4.2 below |
| **B-5** | blocker | The **"guaranteed single-variant bound = 78.3 %"** is not a bound. The 195 487 B remainder is modelled as a **constant**; `_addendum_lines` scales with the **pre-cap** entry population × declared-region count. Measured post-batch: **1.82× budget, one variant** | probe §4.1 below |
| **M-1** | major | Cap × filter composition breaks the **audit header**: it will state `shown 520` while the table renders 500. Neither artifact mentions `_filter_section_counts` | probe §4.3 below |
| **M-2** | major | R-TUI-089/090's **unconditional** byte-identity clause is contradicted by R-TUI-091(c) | `:350` / `:361` vs `:376` |
| **M-3** | major | `LLR-093.1/.2/.3` carry **no `Traces to:`** and hang off an **undefined `R-TUI-093`**; **R-TUI-092 has no AT** in this artifact | grep output §5 |
| **m-1…m-5** | minor | see §6 | |

**What I confirmed rather than re-found** (credit, executed): the pair arithmetic, A-1's motivating
numbers, the `>`-not-`>=` security ruling, the A-2 defect, the checklist per-check multiplication,
and the `shall` confinement. Details in §3.

---

## 2. Scope note — ground I did NOT re-litigate

Per the review brief, the following are CLOSED and are not re-argued here: the `CAP = 400` floor
violation (§13.1), the `512/255` rounding-artifact correction (§13.2), the non-independence of the
two constants (D-12), the pre-existing 201-entry region-cap marker, and the 2-row golden's
inability to validate a cap. I verified each is correctly recorded and moved past it.

---

## 3. What survives execution — verified, with evidence

### 3.1 The pair `(REPORT_CELL_BYTES = 64, CAP = 500)` — re-derived independently: **HOLDS**

I rebuilt the worst-row measurement from scratch: hostile `"|" × 512` in both text cells (2.00×
`md_safe` growth), the longest `CHECK_RESULT_DOMAIN` member, byte runs driven **over** the bound,
and a **prefix-only** formatter per ruling (b).

```
$ python pA.py
worst modifications row @L=64: 2,464 B
worst checklist    row @L=64:   424 B
sum = 2,888 B   (architect claims 2,892)
  CAP=400: guaranteed 1,350,687 B = 64.4%
  CAP=500: guaranteed 1,639,487 B = 78.2%
  CAP=512: guaranteed 1,674,143 B = 79.8%
  ceiling at this remainder = 658
```

The 4 B gap is fully explained: the architect drove `Length` to 7 digits (1 048 576) where my
fixture gives 4 (2048). **Their figure is the more conservative one.** Ceiling 658 vs 657, bound
78.2 % vs 78.3 %. `400 < 500 < 657` is arithmetically true. **§13's correction of §12.4 is sound and
I endorse the value — conditional on B-5, which moves the *remainder*, not the row cost.**

### 3.2 A-1's motivating measurement — independently reproduced

```
MF_RUN_LENGTH_CEILING = 1,048,576   MF_ENTRY_COUNT_CEILING = 100,000
ONE entry at the schema ceiling -> document = 6,293,988 B = 3.00x budget; TRUNCATED markers = 0
34 rows x 10,240 B runs          -> 2,092,977 B = 1.00x budget (row cap 500 never fires)
35 rows x 10,240 B runs          -> 2,154,462 B = 1.03x budget
```

A-1 is **not** an enhancement and the accept-into-scope ruling is correct. (My figure 6 293 988 vs
the artifact's 6 291 604 — different `Length`/linkage widths; same conclusion.)

### 3.3 The option-(b) security ruling — correct, and for the right reason

`_format_bytes` is excluded from escaping by R-TUI-077 on a **closed-alphabet** premise
(`s19_app/tui/services/report_service.py:430`; pin at `tests/test_report_field_census.py:836`).
Keeping the cell pure hex preserves inertness-by-construction and amends no locked requirement.
The reasoning in §12.2 is the strongest passage in the artifact and I would not change it.

### 3.4 A-2 — the defect is real and one degree worse than "inconsistency"

`_declaration_error_lines` (`report_service.py:1006`) returns `List[str]`; the appendix is emitted
`if notes:` at `report_service.py:1674` and `notes` is fed **only** by `_hexdump_section`
(`:1265`, consumed `:1667-1669`). Verified by reading; the qa reproduction (`01b-qa-catalog.md:371`)
matches the code.

### 3.5 The checklist per-check trap — real

`_checklist_lines` loops per `check` at `report_service.py:1146` and per `check.entries` at `:1164`;
`_modifications_lines` flattens at `:963-967`. AC-4 is a genuine trap and AT-167's 4-run fixture is
the right shape.

### 3.6 `shall` confinement — verified by execution

```
$ grep -n "shall" 01-requirements-architect.md   ->  hits at
29 347 348 350 356 357 359 360 361 368 369 371 373 376 382 385 390 391 473 474
529 530 544 545 550 552 560 561 563 570 576 578 582 584 590 591 594 600 602 610
614 619 621 631 632 638 646 652 656 758
```
All normative hits fall inside §2 (`347-391`) or §5 (`529-656`); `29`, `473-474`, `758` are
meta-references to the rule. **Claim in §9 row 14 confirmed.** (One leak outside this artifact —
see m-2.)

---

## 4. The blockers, with executed evidence

### 4.1 B-5 — the "guaranteed single-variant bound" is not a bound

The artifact's central budget claim is
`500 × 2 892 + 195 487 = 1 641 487 B = 78.3 %` (`:1390`), where **195 487 B is treated as a
constant** — "hexdumps at 128 regions × ctx 4096, declaration errors at cap with 500-char messages,
legend + entropy + addendum" (`:1157-1159`).

**The remainder is not a constant. `_addendum_lines` (`report_service.py:1467`) emits one hit line
per change-summary entry per declared region — it is downstream of the *pre-cap* population the
batch is bounding, and it is multiplied by an axis with no count bound at all.**

```
$ python pB.py
=== B1: addendum scales with the UNCAPPED entry population ===
  entries=   200  addendum hit lines=   200  addendum bytes=     7,258 =   0.3% of budget
  entries=   500  addendum hit lines=   500  addendum bytes=    18,058 =   0.9% of budget
  entries=  5000  addendum hit lines=  5000  addendum bytes=   180,058 =   8.6% of budget
  entries= 20000  addendum hit lines= 20000  addendum bytes=   724,698 =  34.6% of budget
  -> 8 declared regions covering the image, at 20 000 entries:
     addendum bytes = 5,797,343 = 276.4% of budget
```

At 20 000 entries the addendum **alone** is 724 698 B — **3.7× the entire claimed remainder**.
`DeclaredRegion` carries only a *name*-length bound (`report_addendum.py:26
DECLARED_REGION_NAME_MAX = 80`); `grep -rn "DECLARED_REGION" s19_app/` returns **no count ceiling**,
and the regions are manifest-derived (`variant_execution_service.py:539
_parse_manifest_declared_regions`).

**End-to-end, post-batch, with both caps ACTIVE at 500 and the cell bound at 64, ONE variant:**

```
=== post-batch, ONE variant, caps ACTIVE, addendum on (1 declared region) ===
  entries=    500  table rows= 500 (capped)  doc=    47,549 B =  0.02x budget
  entries=   5000  table rows= 500 (capped)  doc=   214,051 B =  0.10x budget
  entries=  20000  table rows= 500 (capped)  doc=   773,693 B =  0.37x budget
  entries= 100000  table rows= 500 (capped)  doc= 3,813,695 B =  1.82x budget
```

100 000 is **`MF_ENTRY_COUNT_CEILING`** — inside the change schema's own declared input domain, the
exact standard §1.3 used to justify A-1. **After this batch ships, a single variant inside the
declared domain still produces a 1.82× document while the report prints
`report size cap: 2097152 bytes`. That is M-2 — the finding that raised this batch above resource
hygiene — unfixed on a different axis.**

This is not the accepted tail-cut carry (D-18) and it is not the variant-axis carry (M-5): both of
those concern *evidentiary loss* and *variant count*. This is the **budget guarantee itself** being
computed against a remainder that is a function of the capped input.

**Required:** either (a) state the guarantee conditionally and honestly —
*"78.3 % holds when `options.declared_regions` is empty"* — and carry the addendum axis as a named
MAJOR, or (b) bring the addendum inside scope. I do **not** recommend (b) — it widens the batch.
I recommend (a), plus re-deriving the remainder as `remainder(N, R)` rather than a scalar, because
the §7 trigger table currently says the caps "re-derive from §12.4's surface" and that surface is
missing a variable.

### 4.2 B-4 — the index-vs-evidence reframing is false for 3 of the 4 bounded cells

D-16 (`PLAN.md:150`) is made **load-bearing**: "*Without it, the bound has no principled anchor.*"
§12.3 asserts `_hexdump_section` "is the surface *designed* for byte evidence", and R-TUI-091(b)
(`:373-375`) **requires the marker to point a reader there for the full bytes**.

I tested the reframing against the code, per disposition and per cell. Fixture: one `applied` entry
(200 random `before` + 200 random `after`), one `skipped-outside` entry (200 random `after`), one
`uncheckable` check entry (200 random `expected`); post-change `mem_map` captured. The written
report's fenced hexdump was **parsed back into an address→byte map** and compared byte-for-byte.

```
hexdump carries 200 bytes, 0x1000-0x10C7
=== does the hexdump carry the bytes each table cell shows? ===
  applied.after_bytes    addr 0x1000: 200/200 addrs dumped, 200/200 bytes equal the cell's run
  applied.before_bytes   addr 0x1000: 200/200 addrs dumped,   0/200 bytes equal the cell's run
  skipped.after_bytes    addr 0x2000:   0/200 addrs dumped,   0/200 bytes equal the cell's run
  check.expected_bytes   addr 0x3000:   0/200 addrs dumped,   0/200 bytes equal the cell's run
```

| bounded cell | recoverable from `_hexdump_section`? | why |
|---|---|---|
| `Modifications.After`, disposition `applied` | **YES** | `mem_map` is the post-change image |
| `Modifications.Before` | **NO** | the hexdump renders the **post**-change map (`report_service.py:1265` docstring, `:1327` `result.mem_map`). The pre-change bytes exist **only in the table cell** |
| `Modifications.After`, any non-`applied` disposition | **NO** | `_applied_regions` (`:1213-1221`) filters `disposition == DISPOSITION_APPLIED`; the region is never dumped |
| `Checklist.Expected` / `Checklist.Actual` | **NO** | check-entry regions are not in `_applied_regions` at all; `expected_bytes` is a *declared* value that is not in the image **by definition** |

**Three of the four cells R-TUI-091 bounds have no evidence fallback anywhere in the document.**
For those, truncating at 64 bytes deletes evidence that exists nowhere else, and the marker text
mandated by LLR-091.3 — `"…full bytes in the Memory regions section."` — is a **false statement the
requirement obliges the implementation to print**. In a batch whose thesis is *"a document must not
assert what it does not honour"*, that is not a wording nit.

Two further narrowings of the surviving case, both executed:

- **The fallback stops at 128 regions.** 500 applied entries →
  `> TRUNCATED: 372 of 500 modified regions omitted (cap: 128 regions per variant).` Rows 129…500 of
  a `CAP = 500` table have no hexdump either.
- **The service API default is `capture_mem_maps: bool = False`**
  (`variant_execution_service.py:817`). With no map the section renders
  `Post-change memory map unavailable - hexdumps omitted.` (executed). The TUI path does pass
  `True` (`app.py:3517`, `:4014`), so this is a conditional, not a live TUI defect — but the
  requirement is written against the service, not the TUI.

**Required, minimum:** R-TUI-091 must be **re-scoped by cell**, not stated over "every byte run
rendered into a report table cell". Either exempt `Before` / non-applied `After` / both checklist
cells from the bound, or give them a *different* (higher) bound with its own derivation, or state
explicitly in the requirement that the batch accepts unrecoverable evidentiary loss on those cells
and delete the "full bytes in the Memory regions section" pointer from LLR-091.3. What is not
available is the current position, which claims a fallback that measurement says is absent for the
majority of cell instances.

### 4.3 M-1 — cap × filter composition breaks the audit header

Truth-table row **M8** (`:489`) leans on the audit header: *"the pre-filter count is already
disclosed by the audit header (`:1648`)"*. Neither artifact mentions `_filter_section_counts`
(`report_service.py:641`), which computes the header's `shown` figure by **re-walking the entry
population independently of the emitters**. Its own docstring states the invariant the batch breaks:
*"the same populations the section renderers filter, so shown + hidden always equals the pre-filter
count"* (`:650-651`).

```
=== D-2: audit header vs a capped table, under a filter ===
  audit header  : Modifications rows shown 520 of 600 (hidden 80)
  rows today    : 520
  rows at CAP=500: 500
  => after batch-63 the header says 'shown 520' while the table has 500
   doc: - Modifications rows: shown 520 of 600 (hidden 80)
   doc: - Applied regions: shown 520 of 600 (hidden 80)
```

The last line is the corroborating precedent: `Applied regions: shown 520` is **already** wrong
today against the 128-region hexdump cap — this surface has never been reconciled with any cap.
The batch adds two more.

On the ordering question the brief asked: **cap-after-filter IS stated normatively** — LLR-089.2
(`:544`, "shall apply the cap to the post-filter entry list"), truth rows M6/M7/M8 and K8/K9/K10,
and qa AT-170 arm 3 / TC-405. That part is correct and well-covered. What is missing is the
*consequence*: once the cap is post-filter, the header's `shown` and the table's row count are two
independently computed numbers that must agree, and they will not.

**Required:** a normative row (and an AT) for the header. Either the header reports the emitted row
count, or it gains a third figure, or LLR-089.3's marker is required to reconcile against the
header — but the choice must be ruled, not left to Phase 3.

### 4.4 B-1 — §3 mandates the mechanism the requirement forbids

| location | text |
|---|---|
| `:371-372` (R-TUI-091(a), normative) | "**No truncation indicator shall be placed inside the cell.**" |
| `:458` (AT-170, §3 Acceptance) | "…and **the cell states the exact omitted byte count**." |
| `:460-462` (AT-171, §3 Acceptance) | "**The truncation marker emitted inside a byte-run cell** is inert in the report's markdown grammar … and does not split its table cell." |

§12.2 withdrew the in-cell indicator; §13.8 then asserts "**Unchanged:** … every AT/TC id", and
§13.6 states "**The §3 acceptance blocks contain no literal `400` — and that is not luck**". The
literal sweep looked for a *number* in §3 and declared the acceptance layer clean; it never re-read
§3 for the *withdrawn mechanism*. AT-171 as written cannot go GREEN against R-TUI-091(a) — there is
no marker inside the cell to assert inertness on.

This matters beyond bookkeeping because the project's own two-layer rule makes the Acceptance block
**first-class**, and §9 row 8 marks that item ✓. The ✓ is unearned in exactly the way §13.7 names
for REV 3's row 3.

### 4.5 B-2 / B-3 — the two Phase-1 artifacts specify different, partly unsatisfiable, systems

The qa catalog is REV 2 (written 19:58); the architect artifact is REV 4 (20:19) and **cites qa's
REV-2 content** (§12.1, §12.7 "qa's AT-174"). It was revised *after* qa and did not reconcile.

**AT id space — same ids, different subjects:**

| id | architect §3 | qa catalog §2 |
|---|---|---|
| AT-166 | US-B63-1 **AC-3 byte-identity** (`:423`) | **Checklist table stops at the cap** (`:202`) |
| AT-167 | checklist AC-1+AC-4 (`:435`) | checklist cap per variant (`:209`) — *coincidentally close* |
| AT-168 | checklist AC-2 (`:440`) | checklist cut stated once (`:222`) — *coincidentally close* |
| AT-169 | checklist AC-3 (`:443`) | **byte-identity, both stories** (`:235`) |
| AT-170 | **byte-run ceiling** (`:455`) | **empty / all-filtered-out sections** (`:257`) |
| AT-171 | **in-cell marker inertness** (`:460`) | **single-variant worst case bounded** (`:274`) |
| AT-172…175 | *do not exist* | byte-run over / under, A-2 appendix, coexistence |

**Requirement id space — qa's ids are LIVE elsewhere:**
`01b-qa-catalog.md:66,431-442` keys everything to `R-TUI-079` / `R-TUI-080` / `R-TUI-081` and
`LLR-079.x` / `080.x` / `081.x`. Those three `R-TUI` ids are **already claimed by batch-48**
(`.dev-flow/2026-07-16-batch-48/01-requirements.md:272,291,307` — Patch Editor JSON colouring,
before/after card, history strip) and are mapped in `REQUIREMENTS.md`. The architect correctly
verified `R-TUI-089` as next free (`:339`). **No qa TC names any architect LLR id**, so the
functional chain `US → HLR → LLR → TC` claimed ✓ at §9 row 8 does **not close** — it terminates at
LLR-089…093 with no TC on the other side.

Batch-48 hit this exact class and recorded it as a hard lesson:
> `.dev-flow/2026-07-16-batch-48/01-requirements.md:733` — "*`R-TUI-079`, `AT-079b` … all name
> **different things** in the two docs … this is not a theoretical clash*"

**Unsatisfiable constants (B-3):**
- qa **TC-406** (`:438`): "*Plus the **drift floor**, deliberately pinned: `CELL_BYTES >= 256`*",
  reinforced in `[PARAM]` (`:163-165`) as one of only two numbers allowed to be pinned. The
  architect rules **`REPORT_CELL_BYTES = 64`** (`:590`). **A TC written as specified is RED at the
  ruled value on day one.**
- qa TC-406 / TC-409 / boundary row `:477` all assume an **in-cell indicator** ("`CELL_BYTES + 1` →
  bounded **+ indicator**"; TC-409 asserts "the chosen indicator's character set"). Withdrawn by
  §12.2.
- qa `[PARAM]` (`:137`) imports a **single** `MAX_REPORT_TABLE_ROWS_PER_VARIANT`; the architect
  defines **two** constants (`MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT`,
  `MAX_REPORT_CHECK_ROWS_PER_VARIANT`, `:529`/`:560`). qa's own note — "*name is the architect's to
  fix*" — was never actioned.

**Required:** one reconciliation pass producing a single canonical id table (as batch-48 §6.4 did),
before Phase 3. This is cheap but it is not optional: Phase 3 writes these ids into test docstrings
and `REQUIREMENTS.md`, where they become permanent.

---

## 5. Majors and the traceability audit

### M-2 — the byte-identity clauses contradict each other

R-TUI-089 (`:350`) and R-TUI-090 (`:361`) each end: "*When the entry count is at or below the cap,
the section shall be byte-identical to the pre-batch output.*" **Unconditional.** R-TUI-091(c)
(`:376`) scopes byte-identity to runs "*at or below `REPORT_CELL_BYTES`*". A 100-row table carrying
one 200-byte run satisfies R-TUI-089's antecedent and violates its consequent.

No *existing* test drifts (the corpus max document run is 4 B — census §0.7, corroborated by qa
§10.1), so this is a specification defect rather than a drift risk. Fix by scoping: "*…byte-identical
to the pre-batch output for any variant whose byte runs are within `REPORT_CELL_BYTES`*".

### M-3 — C-26 / traceability gaps

`grep -n "^\*\*LLR-\|Touched symbols\|Traces to"` over the artifact:

- **LLR-093.1** (`:646`), **LLR-093.2** (`:652`), **LLR-093.3** (`:656`) carry `Touched symbols:`
  but **no `Traces to:`** — the only three LLRs in the document without one.
- They are numbered against **`R-TUI-093`, which is never defined**. §2 defines 089–092 only.
  Three normative LLRs therefore hang off a non-existent HLR, while §9 row 8 states the chain as
  "`US → R-TUI-089…092 (§2) → LLR-089.x…093.x (§5)`" — the `093.x` term has no antecedent in that
  chain.
- **R-TUI-092 has no AT in this artifact.** §3 covers US-B63-1, US-B63-2 and R-TUI-091 only. The
  A-2 behaviour is only acceptance-covered in the qa catalog (AT-174), which B-2 shows is not
  id-reconciled. Under the project's two-layer rule an HLR without an AT is a gap.
- Every other LLR (089.1-3, 090.1-4, 091.1-4, 092.1-2) **does** name touched symbols and trace —
  that part is well done and I verified all 13.

### M-4 — which rows were truncated: recoverable, but not required

The brief's question: a per-section count does not identify the row. **It is recoverable, via the
`Length` column** — and I verified the correspondence holds for all four cells:

```
=== C-4: Length column vs the run it corroborates ===
  0x00001000  Length=200  cell0=200 tokens  cell1=200 tokens   (applied)
  0x00002000  Length=200  cell0=-           cell1=200 tokens   (skipped, before=None)
  0x00003000  Length=200  cell0=200 tokens  cell1=-            (uncheckable, actual=None)
```
`address_end − address_start` is the encoded byte length by construction
(`changes/model.py:334`, `:634`; built at `changes/apply.py:334` and `changes/check.py:368`, both
over `range(start, end)`). So `Length > REPORT_CELL_BYTES` ⟺ that row's non-`None` byte cells were
truncated. **That is a sound per-row signal and no in-cell indicator is needed — the D-15 ruling is
right.**

But it is **nowhere required**. R-TUI-091 does not state the invariant; §12.2 signal (1) mentions it
only as prose corroboration ("verified end to end (probe `p63j.py` J-3)"); no AT or TC in either
artifact pins `Length == len(run)` for the **checklist** pair (qa TC-408 pins only that `Length` is
not *derived from the rendered cell*, which is the converse). The one property that makes the
outside-the-cell ruling honest is unpinned. **Add a clause to R-TUI-091 and a TC.**

---

## 6. Minors

| # | finding | evidence |
|---|---|---|
| **m-1** | `ValidationIssue.related_artifacts` is an unbounded `list[str]`, each escaped at 512 chars — so the declaration-error section, the *largest named component of the remainder*, is itself unbounded by the same argument A-1 used against `_format_bytes`. Measured: cap × 50 related → **5 442 506 B = 259.5 % of budget**. **No live exposure** — all seven shipped producers pass 2–3 literals (`validation/engine.py:96,108,134,146,171,182,193`) — but the artifact applies the *declared-domain* standard to `_format_bytes` and the *observed-corpus* standard here | `pB.py` B2 |
| **m-2** | `shall` leaks outside HLR/LLR in the companion normative artifact: `01-requirements.md:67` ("Two check runs of ¾-cap each **shall** not yield 1.5× the cap"). The architect's rule is scoped to its own document, so this is a cross-artifact gap, not a false ✓ | `grep -n "shall" 01-requirements.md` |
| **m-3** | Truth table K2 is enumerated for `F` unset only. With a filter set and every check result carrying 0 entries, `_checklist_lines`' zero-match guard is `if total and not kept` (`report_service.py:1143`) — it does **not** early-return, and the branch is unspecified | `report_service.py:1141-1145` |
| **m-4** | LLR-091.2 types the parameter as `_format_bytes(values: Optional[Iterable[int]], limit: int)`. To satisfy LLR-091.3 the **caller** must count truncated cells, i.e. evaluate `len(values)` — not available on an `Iterable`. Either narrow the annotation to `Sequence`/`tuple` or have `_format_bytes` report the fact. All 4 shipped call sites pass tuples, so this is annotation hygiene, not a defect | `:600-608`, `report_service.py:997,998,1172,1173` |
| **m-5** | `capture_mem_maps` defaults to **`False`** at the service API (`variant_execution_service.py:817`); the hexdump section then renders `Post-change memory map unavailable - hexdumps omitted.` LLR-091.3's marker would point at that. TUI callers pass `True` (`app.py:3517`, `:4014`) | executed, §4.2 |

---

## 7. What would change this review

| if… | then… |
|---|---|
| the addendum's growth is shown bounded in practice (e.g. `declared_regions` is proven ≤ 2 and campaigns ≤ 500) | **B-5 drops to major** — the guarantee still needs its condition stated, but the risk is theoretical |
| the batch re-scopes R-TUI-091 to the **`After`-of-`applied`** cell only, or drops the "full bytes in the Memory regions section" pointer | **B-4 closes.** The bound of 64 is then defensible exactly where the reframing is true |
| a single canonical id table is produced and qa's TC-406 floor is re-derived at 64 | **B-1/B-2/B-3 close together** — they are one editorial pass, not three design problems |
| the operator rules that unrecoverable truncation of `Before` / checklist bytes is acceptable | B-4 becomes a **stated, accepted** evidentiary loss (like D-18) rather than a false claim — but it must be *stated*, and the marker wording must change |
| `REPORT_MAX_TOTAL_BYTES` or `REPORT_CELL_CHARS` moves | the whole pair re-derives; §7's existing triggers are correct and I would keep them verbatim |

---

## 8. Recommendation

**`iterate` — return to Phase 1.** Named gaps, in the order I would fix them:

1. **B-1 + B-2 + B-3** (one editorial pass, ~1 hour): re-read §3 against §12.2, produce a canonical
   AT/TC/R-TUI/LLR id table, re-derive qa's TC-406 floor at 64, settle the constant name/count.
2. **B-4** (design): re-scope R-TUI-091 per cell, or state the accepted loss and fix LLR-091.3's
   marker wording. This is the only one that could move the value of `REPORT_CELL_BYTES`.
3. **B-5** (derivation): restate the single-variant guarantee with its condition, re-derive the
   remainder as a function, carry the addendum axis as a named MAJOR.
4. **M-1** (design + AT): rule the audit-header behaviour under a cap.
5. **M-2, M-3, M-4**: scope the byte-identity clauses; give LLR-093.x a parent and a `Traces to:`;
   pin the `Length == len(run)` invariant.

I would **not** re-open: the shape ruling, the pair's arithmetic, the option-(b) security ruling,
A-1's or A-2's acceptance, the increment order, or the §13 floor correction. Those are right.

---

## 9. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|:--:|---|
| 1 | Constraints stated explicitly | ✓ | budget `report_service.py:122` = 2 097 152; `MF_ENTRY_COUNT_CEILING = 100 000` / `MF_RUN_LENGTH_CEILING = 1 048 576` executed from `changes/io.py`; `REPORT_CELL_CHARS = 512` `:115`; variant + declared-region counts **unbounded** (`grep -rn "MAX_VARIANT\|DECLARED_REGION" s19_app/` → name cap only) |
| 2 | ≥2 alternatives considered (for each finding I raise) | ✓ | B-4 offers three dispositions (re-scope per cell / higher bound with own derivation / state the loss + fix marker); B-5 offers two (condition the guarantee vs widen scope) and I recommend the narrower |
| 3 | Every asserted threshold EXECUTED, not predicted | ✓ | `pA.py` (2 888 B/row-pair, ceiling 658, 78.2 %); A-1 headline (3.00×, 34/35 rows); `pB.py` (addendum 724 698 B @20 k, 5 797 343 B @8 regions); post-batch sim (1.82× @100 k); `pC.py` (hexdump byte-for-byte coverage); audit-header (shown 520 vs 500) |
| 4 | Probe predicates validated before use (P-3) | ✓ | my first `pC` predicate used ascending byte runs and produced **false positives across all four cells**; replaced with 32 random bytes and a **parsed** address→byte reconstruction of the fenced block. The first result is recorded here rather than discarded |
| 5 | No worktree mutation | ✓ | all probes under `scratchpad/`, run against `git archive HEAD` → `scratchpad/exp`; `git status --porcelain` shows only `.dev-flow/` |
| 6 | Findings classified with a blocking rule | ✓ | §1 table; blocker = returns to Phase 1, major = must be answered before Phase 3, minor = may ride the batch |
| 7 | Risks named (evidentiary, correctness, security, cost) | ✓ | B-4 evidentiary; B-5 + M-1 correctness (document self-contradiction); §3.3 security ruling confirmed sound, no new security finding; m-1 latent resource |
| 8 | `shall`/`should` audit | ✓ | §3.6 — confinement **confirmed** in the architect artifact by grep line census; one leak found in `01-requirements.md:67` (m-2) |
| 9 | Traceability US→AT and US→HLR→LLR→TC checked | ✗ **BROKEN** | §5 M-3 + §4.5 B-2: LLR-093.x has no parent/`Traces to:`; R-TUI-092 has no AT; **no qa TC names an architect LLR id** |
| 10 | C-26 touched-symbol declaration on every LLR | ✓ *(13 of 16)* | all of LLR-089.1-3, 090.1-4, 091.1-4, 092.1-2 name touched symbols **and** trace; LLR-093.1/.2/.3 name symbols but do not trace |
| 11 | AT/TC/R-TUI id freedom re-verified independently | ✓ | `R-TUI-089…092` free (confirmed); **qa's `R-TUI-079/080/081` NOT free** — `.dev-flow/2026-07-16-batch-48/01-requirements.md:272,291,307` |
| 12 | Cross-artifact consistency checked (not just the artifact under review) | ✓ | §4.5 — six concrete divergences between REV 4 and qa REV 2 |
| 13 | Ground already covered was NOT re-found | ✓ | §2 — the 400/401 floor, the 512/255 artifact, constant non-independence, the 201-entry pre-existing marker and the 2-row golden are each verified-as-recorded and skipped |
| 14 | Diagram included when flow is non-trivial | ✗ | Deliberate, same reason the artifact gives: the composition is one linear emitter chain (`report_service.py:1661-1675`); §4.2's cell→fallback table carries the branching a diagram would blur |
| 15 | What would change the recommendation is stated | ✓ | §7, five triggers, each naming the finding it closes |
| 16 | Credit given where the artifact is right | ✓ | §3 — six verified-correct rulings, each re-executed rather than assumed |
