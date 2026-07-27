# batch-63 — Phase-1 architect requirements (HLR / LLR / acceptance / design ruling)

> ## ⚠ REVISION 4 — normative values are in §13
>
> **Normative pair: `REPORT_CELL_BYTES = 64`, `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT = 500`,
> `MAX_REPORT_CHECK_ROWS_PER_VARIANT = 500`, and the byte-cell cut is stated OUTSIDE the cell.**
>
> Revision history, nothing silently edited:
> - **§1.4 / §1.5** — revision-1 record (cap 200 by budget derivation). Superseded.
> - **§11** — A-3: operator field datum (*campaigns are "tens to ~200 entries"*) invalidated cap
>   200 → 400; `REPORT_CELL_BYTES` 256 → 128. **§11.3, §11.4, §11.6, §11.7 superseded**; the rest
>   stands.
> - **§12** — A-4: the qa-reviewer's joint surface plus a **security collision** at the byte cell.
>   `REPORT_CELL_BYTES` 128 → **64**; the in-cell truncation indicator **withdrawn** (it would have
>   invalidated locked requirement **R-TUI-077**'s premise). **§12.4's "CAP 400 is interior" claim
>   and every §12.5/§12.6 figure are superseded by §13**; the rest stands.
> - **§13** — A-5: **an arithmetic defect in my own REV-3 headline.** I asserted CAP 400 interior
>   to a window `[401, 657]` I derived in the same section. **400 ∉ [401, 657]** — the floor bound
>   and was violated by 1, asserted as verified in three places. §13 fixes the *floor's derivation*
>   (the borrowed 2.01× was a rounding artifact, not a policy) **and** moves the cap to **500**.
>
> Amendments **A-1** (byte-run bound) and **A-2** (appendix retro-wiring) are **ACCEPTED into
> scope**. Across revisions 2–4, five handed-down premises were falsified by measurement rather
> than adopted (§11.1, §12.1, §12.4) — **and two of my own** (§11.1 premise 2, §13.1).

> **Scope of this document.** Derives HLR + LLR + §3 Acceptance blocks from the two READY
> stories in `01-requirements.md` §2.6, and rules the Phase-0 open design question (PLAN D-4).
>
> **Language rules honoured.** `shall` appears ONLY inside an HLR or LLR statement. Informative
> text uses `should` / plain indicative. Every named symbol, constant or threshold is either cited
> `file:line` against the tree at `031ca8d` or flagged `assumed — verify in Phase N`.
>
> **C-39.** Every number this document keys a requirement on was produced by an executed
> derivation over the current tree during this phase. The transcripts are pasted in §0.

---

## 0. Executed derivations (C-39) — run at Phase 1, this tree

All probes are read-only against the shipped tree (no worktree mutation; scratch dir only), driving
the shipped emitters and the shipped composer.

### 0.1 — D-A: `_format_bytes` is unbounded; ONE row can exceed the whole document budget

Probe `p63c.py`. Constants read from disk: `MF_RUN_LENGTH_CEILING`
(`s19_app/tui/changes/io.py:226`), `REPORT_MAX_TOTAL_BYTES` (`report_service.py:122`).

```
  MF_RUN_LENGTH_CEILING (upstream input bound) = 1,048,576 B
  REPORT_MAX_TOTAL_BYTES                       = 2,097,152 B

  run=        4 B/entry -> ONE modifications row =         166 B (  0.00x budget) | ONE checklist row =         210 B ( 0.00x budget)
  run=    1,000 B/entry -> ONE modifications row =       6,145 B (  0.00x budget) | ONE checklist row =       6,189 B ( 0.00x budget)
  run=   10,000 B/entry -> ONE modifications row =      60,146 B (  0.03x budget) | ONE checklist row =      60,190 B ( 0.03x budget)
  run=  100,000 B/entry -> ONE modifications row =     600,147 B (  0.29x budget) | ONE checklist row =     600,191 B ( 0.29x budget)
  run=1,048,576 B/entry -> ONE modifications row =   6,291,604 B (  3.00x budget) | ONE checklist row =   6,291,648 B ( 3.00x budget)
```

**A single entry at the schema's own declared input ceiling emits a 6 291 604 B row = 3.00× the
2 MiB budget.** `_format_bytes` (`report_service.py:430`) renders every byte as three characters
with no length bound; it is the sole renderer of 4 of the 11 table cells
(`report_service.py:997,998` and `:1172,1173`).

### 0.2 — D-B: the two tables have different per-row cost LAWS

Probe `p63b.py`, each emitter called in isolation, slope taken between N=1000 and N=2000.

```
  realistic     N= 1000  modifications=  137,992 B  checklist=   54,159 B
  realistic     N= 2000  modifications=  276,992 B  checklist=  108,159 B
    -> slope: modifications   139.0 B/row  checklist    54.0 B/row
  pathological  N= 1000  modifications=  590,102 B  checklist=   54,159 B
  pathological  N= 2000  modifications=1,180,102 B  checklist=  108,159 B
    -> slope: modifications   590.0 B/row  checklist    54.0 B/row
```

| table | realistic (63-char symbol) | pathological (512-char symbol) | spread |
|---|---:|---:|---:|
| modifications | 139.0 B/row | 590.0 B/row | **4.24×** |
| checklist | 54.0 B/row | **54.0 B/row** | **1.00×** |

The checklist row is content-independent because its only text cell is `entry.result`, whose domain
is the closed 3-token `CHECK_RESULT_DOMAIN = ('pass', 'fail', 'uncheckable')`
(`s19_app/tui/changes/model.py:561`, longest member 11 chars). The modifications row is
content-dependent through `entry.linkage` and `entry.linkage_symbol`
(`report_service.py:999,990`).

### 0.3 — D-C: `md_safe` worst-case growth factor

```
md_safe('|'*512, limit=512) -> 1024 chars (2.00x growth)
```

### 0.4 — D-D: worst-case row bytes per candidate byte-run limit, and the cap that implies

Probe `p63d.py`. Worst row = 512 all-escapable chars in `linkage` AND `linkage_symbol`, longest
`CHECK_RESULT_DOMAIN` member, byte runs at the candidate limit.

```
  RUN_LIMIT=  16 B -> worst modifications row =  2,173 B | worst checklist row =    133 B | sum =  2,306 B
        row cap  200 -> both tables worst case =    461,200 B =  0.22x the 2 MiB budget ok
  RUN_LIMIT=  64 B -> worst modifications row =  2,461 B | worst checklist row =    421 B | sum =  2,882 B
        row cap  128 -> both tables worst case =    368,896 B =  0.18x the 2 MiB budget ok
        row cap  200 -> both tables worst case =    576,400 B =  0.27x the 2 MiB budget ok
        row cap  500 -> both tables worst case =  1,441,000 B =  0.69x the 2 MiB budget ok
  RUN_LIMIT= 256 B -> worst modifications row =  3,614 B | worst checklist row =  1,574 B | sum =  5,188 B
        row cap  128 -> both tables worst case =    664,064 B =  0.32x the 2 MiB budget ok
        row cap  200 -> both tables worst case =  1,037,600 B =  0.49x the 2 MiB budget ok
        row cap  500 -> both tables worst case =  2,594,000 B =  1.24x the 2 MiB budget OVER
```

### 0.5 — D-E: whole single-variant document at candidate caps (all sections on)

Probe `p63b.py` P-3, through the shipped `generate_project_report`, re-read from disk.

```
  -- realistic regime (symbol 63 chars) --
    cap=  200  doc=    44,722 B  =    2.1% of 2 MiB      cap= 2000  doc=   394,914 B  =   18.8%
    cap=  500  doc=   102,905 B  =    4.9% of 2 MiB      cap= 5000  doc=   979,933 B  =   46.7%
    cap= 1000  doc=   199,912 B  =    9.5% of 2 MiB
  -- pathological regime (symbol 512 chars) --
    cap=  200  doc=   135,232 B  =    6.4% of 2 MiB      cap= 2000  doc= 1,298,024 B  =   61.9%
    cap=  500  doc=   329,015 B  =   15.7% of 2 MiB      cap= 5000  doc= 3,232,908 B  =  154.2%  OVER
    cap= 1000  doc=   652,022 B  =   31.1% of 2 MiB
```

This **discharges the `assumed` claim** carried in `01-requirements.md` §2.6 ("with the tables
capped, a single-variant document sits well inside 2 MiB"): CONFIRMED at cap ≤ 2000 in both
regimes — but only for the 4-byte runs this probe used. §0.1 shows the claim is **false in general**
until the byte-run cell is bounded.

### 0.6 — D-F: fixture drift census over the REAL suite (not predicted)

pytest plugin `census63.py` wraps both emitters and records the real per-call populations across
**every** consumer test file (`tests/test_report_service.py`, `test_report_field_census.py`,
`test_report_symbol_escape.py`, `test_report_filter.py`, `test_report_addendum.py`,
`test_report_markup_safety.py`, `test_report_logging.py`, `test_report_progress.py`,
`test_tui_report_seam.py`, `test_tui_report_view.py`, `test_tui_report_filter_surface.py` —
the complete `grep -rl "generate_project_report\|_modifications_lines\|_checklist_lines" tests/`
set). Three runs, **364 tests, all passing**, histograms merged (77 + 238 + 49):

```
_modifications_lines calls           : 74
  MAX entries in one call            : 133
  population histogram (n -> calls)  : {0: 12, 1: 44, 2: 12, 3: 2, 128: 2, 130: 1, 133: 1}
_checklist_lines calls               : 74
  MAX rows per VARIANT (all checks)  : 3
  MAX rows in one CHECK              : 3
  MAX check results in one variant   : 2
```

| candidate row cap | modifications fixtures over cap | checklist fixtures over cap |
|---:|---:|---:|
| 128 | **2** (n=130 `test_report_service.py:443`; n=133 `test_report_field_census.py:673`) | 0 |
| **200** | **0** | **0** |
| 500 | 0 | 0 |

**Drift set at cap 200 = ∅, executed, not predicted.** Note the margin is 1.5× over the largest
existing fixture (133), not the "far under any plausible cap" the PLAN's risk-2 expected — a cap of
128 would have drifted two tests. This is the value C-39 delivered here.

### 0.7 — D-G: byte-run drift census (for the per-cell bound)

pytest plugin `census63b.py` wraps `_format_bytes`, same corpus (315 tests, all passing):

```
  calls with a byte run       : 1147
  histogram (run len -> calls): {1: 579, 2: 563, 4: 4, 256: 1}
  MAX run length in the suite : 256
  cells that a RUN_LIMIT= 64 would truncate: 1
  cells that a RUN_LIMIT=256 would truncate: 0
```

The single 256-byte call is `_format_bytes(range(256))` at
`tests/test_report_field_census.py:835` — a **direct unit call**, not a document cell. So at any
limit ≥ 256 the document-level drift set is ∅ and no golden moves.

### 0.8 — D-H: the truncation-appendix asymmetry (probe `p63e.py` P-10)

```
  declaration-error cap fired     : True
  in-document marker present      : ['> TRUNCATED: 50 of 250 declaration errors omitted (cap: 200 issues per variant).']
  '## Truncation appendix' present: False
```

`_declaration_error_lines` (`report_service.py:1006`) returns `List[str]` only; the appendix is fed
exclusively by `_hexdump_section`'s `notes` return (`report_service.py:1265`, consumed at
`:1667-1669`). **One of the two shipped cap precedents does NOT do what AC-2 asks for.**

### 0.9 — D-I: structural asymmetry between the two tables (probe `p63b.py` P-2, `p63e.py` P-9)

```
  P-9  2 change summaries x 150 entries = 300 -> emitted rows 300   (already flat per VARIANT)
  P-2   1 check file(s) x  300 entries =  300 -> emitted rows  300
        4 check file(s) x  150 entries =  600 -> emitted rows  600
       10 check file(s) x  150 entries = 1500 -> emitted rows 1500  (multiplies per CHECK FILE)
```

`_modifications_lines` flattens across change summaries before the loop
(`report_service.py:963-967`), so a row cap there is per-variant for free. `_checklist_lines` loops
per `check` (`:1146`) and again per `check.entries` (`:1164`), so a cap written inside the inner
loop would be per **check file** and 10 files × cap would ship. This is US-B63-2 AC-4's trap,
measured.

---

## 1. Design ruling (PLAN D-4) — the answer to the question I was asked to attack

### 1.1 BLUF

**The proposed shape is right and I endorse it. The proposed VALUE is right but its stated
justification is wrong and must be replaced. The proposal is NOT SUFFICIENT: shipped alone it
leaves the document unbounded and re-commits the batch's own motivating defect.**

| element of the ruling | verdict | basis |
|---|---|---|
| per-variant **row** cap (not `budget.fits()`) | **ENDORSED**, + a third rejection reason for the alternative | §1.2 |
| value **200** | **ENDORSED**, justification **REPLACED** (derived, not mirrored) | §1.4 |
| one shared constant vs. two | **TWO constants** | §1.5 |
| "the cut is stated in the document" | **ENDORSED and STRENGTHENED** — the shipped precedent it names is defective | §1.6 |
| row cap **alone** bounds the tables | **REFUTED** — one row can be 3.00× the budget | §1.3 |

### 1.2 The shape: row cap — endorsed, with a third measured reason

The Phase-0 rejection of "make the tables consult `budget.fits()`" gave two reasons (document
order starves the hexdumps; no per-variant fairness). Both hold. A third, measured:

- `tests/test_report_service.py:484` monkeypatches `REPORT_MAX_TOTAL_BYTES` to **10** to exercise
  the hexdump byte-cap marker. Any design in which the tables consult the same shared budget emits
  **zero** table rows under that monkeypatch, so a test written to pin the hexdump cap silently
  becomes a test of the table cap too, and the report body it asserts over changes shape.

I also considered a **third shape Phase-0 did not**: a *per-section, per-variant byte allowance*
independent of `_ByteBudget`. It dominates the rejected alternative on both of its stated grounds
(no document-order interaction, per-variant by construction). I still reject it, for two reasons:

1. It makes the emitted row count content-dependent, so a reader cannot predict what a report
   contains and two runs over the same variant with different symbol lengths cut at different rows.
   In an evidentiary document, "the table stops at 200" is a property a reader can state; "the table
   stops when it has spent 256 KiB" is not.
2. Once §1.3 lands, the row cap **is** a byte bound, so the allowance buys nothing.

### 1.3 REFUTATION — a row cap alone does not bound either table

`_format_bytes` (`report_service.py:430`) has no length bound and feeds 4 of the 11 table cells.
Measured (§0.1): one entry at `MF_RUN_LENGTH_CEILING = 1 048 576` (`changes/io.py:226`, the change
schema's own declared input domain) emits a **6 291 604 B single row = 3.00× the whole 2 MiB
budget**. A cap of 200 rows on a table whose first row can be 3× the budget bounds nothing.

The realistic regime is not safe either: at 10 000 bytes/entry — a whole calibration map, not a
pathological fixture — one row is 60 146 B, so **35 rows exhaust the budget** and the cap of 200
never fires.

Why this was missed at Phase 0: batch-62 explicitly **excluded** `_format_bytes` from escaping on
the (correct) ground that it emits "hex digits and spaces only" (R-TUI-077, `REQUIREMENTS.md:4780`;
pinned by `tests/test_report_field_census.py:825`). That exclusion was about **grammar**. It left
the field with no **length** limit, and the Phase-0 probe used 4-byte runs, so the axis never
appeared. This is the C-13 reuse-transfer trap in `docs/engineering-rules.md:9`: a property proven
for container A (grammar safety) is not verified for container B (size).

**Consequence for the batch:** shipping the row cap alone would produce a report that carries a
`> TRUNCATED: … (report size cap: 2097152 bytes)` marker while being multiples of that size —
which is *exactly* finding M-2, the finding that raised this batch above resource hygiene. The
per-cell byte-run bound is therefore not an enhancement; it is a precondition for US-B63-1's and
US-B63-2's own why-clauses. It is proposed as a **scope amendment** in §6, not slipped in.

### 1.4 The value 200 — endorsed, justification replaced

**The proposed justification does not survive.** Two tests:

1. **Population-type test.** `MAX_REPORT_ISSUES_PER_VARIANT = 200` (`report_service.py:90`) was
   defended for a **fault** population, mirroring `MAX_REPORT_FINDINGS_PER_BLOCK`
   (`flow_report_service.py:88`). Past ~200 distinct parse faults a reader learns nothing new from
   fault 201. A modifications row is a **payload**: row 4 999 of a calibration campaign is exactly
   as evidentiary as row 1. The two populations have opposite value curves, so mirroring the
   constant transfers a number defended for the wrong population.
2. **Field-defence test.** `REPORT_CELL_CHARS = 512` is legitimate because it is **≥ the largest
   legitimate value of the fields it governs** (`descriptor.path.name` reaches 255 —
   `report_service.py:96-101`), so it never cuts real data. The analogous field bound here is
   `MF_ENTRY_COUNT_CEILING = 100 000` (`changes/io.py:226`). **200 is 500× BELOW it.** The
   `REPORT_CELL_CHARS` defence pattern does not transfer, and any claim that it does is false.

**What does justify 200.** Once §1.3's per-cell bound lands, worst-case row bytes become
computable, so the cap can be *derived* from the budget instead of inherited. Stating the policy
as **"both tables' combined worst case ≤ 50 % of `REPORT_MAX_TOTAL_BYTES`, leaving the other half
for every other section plus a second variant"**, §0.4 gives, at a 256-byte run limit:

```
200 × (3 614 + 1 574) = 1 037 600 B = 0.495 × 2 097 152    ✔ ≤ 0.50
500 × (3 614 + 1 574) = 2 594 000 B = 1.24  × 2 097 152    ✘ over budget on its own
```

**200 is the largest round value satisfying the policy.** Same number, different provenance — and
the difference is load-bearing: the derived justification re-derives if `REPORT_CELL_CHARS` or the
run limit changes, whereas the mirrored one would keep pointing at an unrelated constant.

**Is withholding row 201 of 5 000 acceptable?** Honestly: **it is a real evidentiary loss, and no
value avoids it.** 100 000 rows is inside the declared input domain and cannot be rendered in
2 MiB under any scheme (100 000 × the *cheapest* measured row, 54 B, is 5.4 MB). Some legitimate
input is necessarily cut. The requirement therefore does not promise completeness; it promises that
the cut is **exact, stated, and attributable**, and that the full bytes of applied entries remain
reachable in the hexdump section (region-capped at 128, `report_service.py:77`). That trade must be
stated in the constant's docstring so no later reader re-derives 200 as "enough".

**Missing constraint, flagged rather than invented.** There is no field data for the real
distribution of change-entry counts: `find examples -name "*.json"` returns only
`examples/crc_config.example.json` — the shipped corpus contains **no** change or check document
(executed). If the operator has a real campaign size, it should override the derivation. Absent
that, the derived value stands.

### 1.5 One constant or two — **two**

Measured discriminator (§0.2): the checklist row's cost law is content-**independent**
(54.0 B/row in both regimes, because `CHECK_RESULT_DOMAIN` is closed) while the modifications
row's is content-**dependent** (4.24× spread). Their worst-case rows differ by **2.3×**
(3 614 vs 1 574 B at a 256-byte run limit). A single constant would make one number mean two
different byte weights, and any future adjustment would move a section it was not derived for.

The counter-argument is batch-62's own ("a reader comparing the two report kinds should not have to
learn two numbers", `report_service.py:87-89`). It applies to sections of the same shape; these two
have different cost laws **and** different enforcement points (§0.9). Recorded as a genuine
tension, resolved toward two constants, with both set to 200 today by the §1.4 derivation —
**coincidence, not coupling**, and each carries its own arithmetic so a future change is forced
through its own derivation.

### 1.6 "The cut is stated" — endorsed, and the named precedent is defective

AC-2 asks for the shipped `> TRUNCATED: N of M …` marker "plus its truncation-appendix entry".
Measured (§0.8): the declaration-error cap emits the marker and registers **no appendix note**.
Only `_hexdump_section` feeds the appendix. A reader who scans `## Truncation appendix` and finds
it absent concludes nothing was cut — the same *document asserts something it does not honour*
class as M-2. The new caps must feed the appendix; retro-wiring the declaration-error cap is
proposed as amendment A-2 (§6).

---

## 2. High-level requirements (HLR)

Next free id verified against disk: `R-TUI-089` (`grep -rl "R-TUI-089"` → 0 files; `R-TUI-088` is
claimed by `.dev-flow/2026-07-20-batch-51/01-requirements.md:380`).

### R-TUI-089 (HLR) — the per-variant modifications table is bounded and states its cut
**Traces to:** US-B63-1.

When `generate_project_report` composes a variant's Modifications section and that variant's
change summaries together carry more entries than `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT`, the
report shall contain exactly `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT` modification data rows for
that variant, taken as the first rows in document order, and shall state the cut in the document
with the exact omitted count, the exact pre-cut total, and the cap that caused it. When the entry
count is at or below the cap, the section shall be byte-identical to the pre-batch output.

### R-TUI-090 (HLR) — the per-variant checklist table is bounded and states its cut
**Traces to:** US-B63-2.

When `generate_project_report` composes a variant's Checklists section, the total number of
checklist data rows emitted for that variant across **all** of its check results shall not exceed
`MAX_REPORT_CHECK_ROWS_PER_VARIANT`, and when the bound is reached the report shall state the cut
once for the variant with the exact omitted count, the exact pre-cut variant-wide total, and the
cap that caused it. The bound shall be a per-variant bound, not a per-check-file bound. Each check
file's aggregate counts line shall continue to report its pre-cut, pre-filter values. When the
variant-wide row count is at or below the cap, the section shall be byte-identical to the pre-batch
output.

### R-TUI-091 (HLR) — a table byte-run cell is bounded, and the cut is stated outside the cell
**Traces to:** US-B63-1 *and* US-B63-2 (their why-clauses).
**Status: ACCEPTED SCOPE (amendment A-1, coordinator ruling). Values per §12.**

(a) Every byte run rendered into a report table cell shall be rendered as at most
`REPORT_CELL_BYTES` two-hex-digit tokens, and shall emit **no character outside
`"0123456789ABCDEF "`** — the closed alphabet on which locked requirement R-TUI-077 bases its
escaping exclusion (`REQUIREMENTS.md:4780-4782`). No truncation indicator shall be placed inside
the cell.
(b) When one or more byte cells in a section were rendered as a prefix, that section shall state
the cut with the exact count of affected cells, the bound that caused it, and a pointer to the
Memory regions section where the full bytes are rendered.
(c) A run at or below `REPORT_CELL_BYTES` shall render byte-identically to the pre-batch output.

### R-TUI-092 (HLR) — every firing cap is registered in the truncation appendix
**Traces to:** US-B63-1 AC-2, US-B63-2 AC-2.
**Status: ACCEPTED SCOPE, both clauses (amendment A-2, coordinator ruling).**

(a) When a cap introduced by R-TUI-089, R-TUI-090 or R-TUI-091 fires, the report shall carry a
`## Truncation appendix` entry naming the affected variant and restating the omitted count, in
addition to the in-section marker.
(b) When the `MAX_REPORT_ISSUES_PER_VARIANT` cap fires, the report shall likewise carry a
truncation-appendix entry. *(Independently reproduced by qa §10.4 and one degree worse than
revision 1 stated: with only that cap firing the `## Truncation appendix` **heading is absent from
the document entirely** — `:1674` emits it `if notes:` and `notes` is fed only by
`_hexdump_section`. A reader checking for cuts finds no appendix and concludes none happened.)*
(c) Each registered entry shall carry its own count and its own variant attribution; entries from
different mechanisms and different variants shall not be conflated.

---

## 3. Acceptance blocks (§3) — black-box, per story

AT id range verified against disk: highest existing `AT-` id repo-wide is **163**
(`grep -rohE "AT-[0-9]{3}" --include=*.md --include=*.py . | sort -n | tail -1` → 163; present in
`REQUIREMENTS.md`, `tests/`, and `.dev-flow/2026-07-25-batch-62/`). **AT-164 is free — confirmed,
the kickoff's figure is correct.** Highest existing `TC-` id is **398**
(`.dev-flow/2026-07-25-batch-62/01b-qa-catalog.md:354`); **TC-399 is free.**

All ATs observe the document produced by `generate_project_report` and **re-read from disk**, per
the story's stated surface. Every AT fixture must be provably over its cap, with the multiple
stated in the test docstring (C-31 / PLAN risk 4).

### US-B63-1 — the modifications table is bounded, and any cut is stated

| | |
|---|---|
| **Observable outcome** | A variant carrying more change entries than the cap produces a report whose Modifications table has exactly the cap's number of data rows, and the document says how many were withheld. |
| **Shipped surface** | `generate_project_report` → the written `reports/<ts>-report.md`, re-read from disk. |
| **AT ids** | **AT-164**, **AT-165**, **AT-166** |

- **AT-164** (AC-1) — Given a variant whose change summaries carry `cap × 1.5` entries **spread
  across two change summaries**, when a report is generated, then the Modifications table contains
  exactly `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT` data rows. *(The two-summary fixture is
  deliberate: §0.9 shows the flattening is what makes the cap per-variant, and a single-summary
  fixture cannot fail if a later refactor moves the cap inside a per-summary loop.)*
- **AT-165** (AC-2) — …and the document contains a `> TRUNCATED:` marker stating the exact omitted
  count, the exact pre-cut total and the cap value, **and** a `## Truncation appendix` bullet naming
  the variant. Deleting either must turn this RED.
- **AT-166** (AC-3) — Given a variant at exactly the cap and a variant one entry under it, each
  document is byte-identical to the same document generated by the pre-batch composer. *(Oracle:
  a stored pre-batch capture, NOT a golden re-captured from the code under test — batch-62 D-16.)*

### US-B63-2 — the checklist table is bounded, and any cut is stated

| | |
|---|---|
| **Observable outcome** | A variant whose check runs together carry more entries than the cap produces a report whose checklist rows total exactly the cap across all check files, and the document says how many were withheld. |
| **Shipped surface** | as above. |
| **AT ids** | **AT-167**, **AT-168**, **AT-169** |

- **AT-167** (AC-1 + **AC-4, the story's trap**) — Given a variant with **four** check results of
  `⌈0.75 × cap⌉` entries each (3.0× the cap in total, stated in the docstring), when a report is
  generated, then the **sum** of checklist data rows across every `#### Checklist:` block equals
  exactly `MAX_REPORT_CHECK_ROWS_PER_VARIANT`. A per-check-file cap yields `4 × cap` and must turn
  this RED. *(§0.9 measured 10 × 150 → 1500 rows today.)*
- **AT-168** (AC-2) — …and the document contains **exactly one** variant-level `> TRUNCATED:` marker
  for the checklist section, stating the omitted count against the **variant-wide** pre-cut total,
  plus its appendix bullet. More than one marker fails: a per-file marker implies a per-file cap.
- **AT-169** (AC-3) — Each check file's `Passed: … - Failed: … - Uncheckable: …` aggregate line is
  unchanged by the cap firing; and a variant at or under the cap is byte-identical to the pre-batch
  output.

### R-TUI-091 (ACCEPTED scope, A-1) — the byte-run cell is bounded

| | |
|---|---|
| **Observable outcome** | A single change entry carrying a very large byte run can no longer produce a report larger than the byte budget it declares. |
| **Shipped surface** | as above. |
| **AT ids** | **AT-170**, **AT-171** |

- **AT-170** — Given **one** variant with **one** applied entry whose `before_bytes` and
  `after_bytes` are each `MF_RUN_LENGTH_CEILING` long (the schema's own declared ceiling; measured
  today at 6 291 604 B for that single row = 3.00× budget), when a report is generated, then the
  document on disk is smaller than `REPORT_MAX_TOTAL_BYTES`, and the cell states the exact omitted
  byte count. **This AT is RED on `main` today and is the batch's headline regression guard.**
- **AT-171** — The truncation marker emitted inside a byte-run cell is inert in the report's
  markdown grammar (asserted on the **token stream**, not a character list — the standing P-3
  lesson, `00-measurements.md` M-6) and does not split its table cell.

---

## 4. Truth table — the cap decision per section

Prose is where phantom values hide (C-36 rider), so every branch that reaches or bypasses a cap is
enumerated with its required document output. `M` = pre-cut population; `C` = the section's cap;
`F` = a `report_filter` is set. **Branch behaviour marked "today" was executed in probe `p63e.py`
P-8/P-9 and `p63b.py` P-2.**

> **Normative status.** This table is written in the indicative, not with `shall`, because the
> `shall` rule confines that modal to §2 and §5. It is normative **by reference**: LLR-089.2,
> LLR-089.3, LLR-090.2, LLR-090.4 and LLR-091.2 each cite the rows they govern, and those LLRs
> carry the modal. A row with no LLR citing it is a specification gap, not a soft preference.

### 4.1 `_modifications_lines` (`report_service.py:923`) — governed by R-TUI-089

| # | condition | today (`main`) | required after batch-63 |
|---|---|---|---|
| M1 | no change summaries | returns `["### Modifications", "", "No change entries were executed for this variant.", ""]` (executed) | **unchanged.** The early return at `:968-970` precedes any table header; the cap is not consulted and no marker appears. |
| M2 | summaries present, all with 0 entries | identical to M1 (executed — `entries` is the flattened list, `:963`) | **unchanged**, same reason. |
| M3 | `F` unset, `0 < M < C` | `M` rows, no marker | **unchanged, byte-identical** (AC-3). |
| M4 | `F` unset, `M == C` | `M` rows, no marker | **`C` rows, no marker.** The cap is `>`, not `≥`: at exactly the cap nothing is omitted, so a marker stating "0 of C omitted" would be a false cut. Mirrors `:1043` and `:1329`. |
| M5 | `F` unset, `M > C` | `M` rows, **no bound** | **`C` rows** (first `C` in document order) **+ in-section `> TRUNCATED: {M-C} of {M} modification rows omitted (cap: {C} rows per variant).` + one appendix bullet naming the variant.** |
| M6 | `F` set, kept `K == 0`, `M > 0` | `_zero_match_notice(M)` = `filter matched 0 of {M} items`, early return at `:975-977` (executed) | **unchanged.** The cap is applied **after** this branch, on the POST-filter population — otherwise a filter that matched nothing would print a cut that did not happen. |
| M7 | `F` set, `0 < K ≤ C` | `K` rows | **`K` rows, no marker.** |
| M8 | `F` set, `K > C` | `K` rows, no bound | **`C` rows + marker stating `{K-C} of {K}`.** The marker's totals are the **post-filter** count `K`, so the omitted count and the visible rows come from the same population; the pre-filter count is already disclosed by the audit header (`:1648`). |
| M9 | `M > C` spread over ≥2 change summaries | one flat table of `M` rows (executed: 2×150 → 300) | **`C` rows total for the variant**, one marker. |
| M10 | `M ≤ C` but one entry's byte run > `REPORT_CELL_BYTES` | row emitted at full run width (up to 6 291 604 B, executed) | **row emitted with the cell truncated + its own in-cell marker** (R-TUI-091). Independent of the row cap; both may fire in one document. |

### 4.2 `_checklist_lines` (`report_service.py:1095`) — governed by R-TUI-090

`M` = Σ `len(check.entries)` over **all** of the variant's check results.

| # | condition | today (`main`) | required after batch-63 |
|---|---|---|---|
| K1 | `result.check_results` empty | `["### Checklists", "", "No checklists were executed for this variant.", ""]`, early return at `:1132-1134` | **unchanged**; cap not consulted. |
| K2 | check results present, all with 0 entries | per-file heading + aggregates + **empty table header, no rows** (no early-return branch exists for this — `:1146` still iterates) | **unchanged.** Explicitly enumerated because it is the one branch with no guard of its own. |
| K3 | `F` unset, `0 < M < C` | `M` rows | **unchanged, byte-identical.** |
| K4 | `F` unset, `M == C` | `M` rows | **`C` rows, no marker** (same `>` rule as M4). |
| K5 | `F` unset, `M > C`, **one** check file | `M` rows | **`C` rows + one variant-level marker + appendix bullet.** |
| K6 | `F` unset, `M > C`, **several** check files | `M` rows (executed: 10×150 → 1500) | **`C` rows in total.** Files are consumed in document order; the file in which the cap is reached is truncated mid-table and every subsequent file emits its heading and aggregates with **zero** rows. **Exactly one** marker, emitted once for the variant, stating `{M-C} of {M}`. |
| K7 | any file's rows omitted | — | its `Passed/Failed/Uncheckable` aggregates line stays **unchanged** (pre-cut, pre-filter). The marker is what reconciles the aggregate against the visible row count. |
| K8 | `F` set, kept `K == 0`, `M > 0` | `_zero_match_notice(M)`, early return at `:1143-1145` | **unchanged**; cap applied after, on the post-filter population. |
| K9 | `F` set, `0 < K ≤ C` | `K` rows | **`K` rows, no marker.** |
| K10 | `F` set, `K > C` | `K` rows | **`C` rows + one marker stating `{K-C} of {K}`** (post-filter totals, as M8). |
| K11 | `M ≤ C` but a run > `REPORT_CELL_BYTES` | full-width cell | **truncated cell + in-cell marker** (R-TUI-091). |

### 4.3 Cross-section composition

| # | condition | required |
|---|---|---|
| X1 | both caps fire in one variant | two independent in-section markers + **two** appendix bullets. Neither cap consumes the other's allowance. |
| X2 | a cap fires in variant A but not variant B | A's marker appears inside A's section only; B's sections are byte-identical to the uncapped output. |
| X3 | a cap fires and the hexdump region/byte caps also fire | all markers coexist; the appendix lists each on its own bullet. |
| X4 | no cap fires anywhere | **no `## Truncation appendix` heading at all** (`:1674` is conditional on `notes`) — which is precisely why R-TUI-092(b) matters: the appendix is only a sound "nothing was cut" signal once every cap feeds it. |

---

## 5. Low-level requirements (LLR)

Every LLR names the symbol(s) it touches (C-26 — the reverse-grep census depends on it). All paths
are `s19_app/tui/services/report_service.py` unless stated. Line numbers are at `031ca8d`.

### R-TUI-089 decomposition — modifications row cap

**LLR-089.1** — A module constant `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT` shall be defined with
value **500** *(A-3 → A-5; 200 → 400 → 500 — §11.4, §12.4, §13)*, and its docstring shall state
(a) the §13.2 derivation — floor **400** (2× the *soft* ~200-entry field maximum; the
`REPORT_CELL_CHARS` 512/255 ratio is a **rounding artifact of a hard 255 maximum, not a margin
policy**, and must not be transferred), cleared by 1.25× to cover `K = 2` check files over
campaigns above the stated typical maximum, and **76 % of the measured 657 ceiling** — i.e.
`400 < 500 < 657`, verified by arithmetic; (b) that it does **not** mirror
`MAX_REPORT_ISSUES_PER_VARIANT` and why the mirror does not transfer (fault vs payload
population); and (c) that it is **200× below** `MF_ENTRY_COUNT_CEILING`, so it can still cut
legitimate data at the tail — the full bytes of applied entries remain reachable in the hexdump
section, and if campaigns an order of magnitude larger appear the answer is a full-fidelity
sidecar, **not a bigger cap**.
- **Touched symbols:** *new* `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT` (near `:90`).
- **Traces to:** R-TUI-089.

**LLR-089.2** — `_modifications_lines` shall apply the cap to the post-filter entry list, after the
empty-entries early return (`:968`) and after the zero-match early return (`:975`), and shall emit
the first `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT` entries in document order.
- **Touched symbols:** `_modifications_lines` (`:923`, loop at `:985`).
- **Traces to:** R-TUI-089; truth table M1/M2/M5/M6/M8.

**LLR-089.3** — When the cap fires, `_modifications_lines` shall append the in-section marker
`> TRUNCATED: {omitted} of {total} modification rows omitted (cap: {cap} rows per variant).`
using the same wording shape as `:1087` and `:1332`. When a `report_filter` is set, `{total}` shall
be the **post-filter** row count, so the omitted count and the visible rows come from one
population.
- **Touched symbols:** `_modifications_lines`.
- **Traces to:** R-TUI-089, R-TUI-092(a); truth table M4/M5/M7/M8.

### R-TUI-090 decomposition — checklist row cap

**LLR-090.1** — A module constant `MAX_REPORT_CHECK_ROWS_PER_VARIANT` shall be defined with value
**500** *(A-3 → A-5; 200 → 400 → 500)*, and its docstring shall carry its **own** derivation
(worst checklist row **426 B** at `REPORT_CELL_BYTES = 64`, §12.4; floor `K = 2 × 200` per §13.2)
and shall state (a) that its coincidence with `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT` is not a
coupling, and (b) that the budget would admit a higher value but the checklist's legitimate
population is `K × 200` with `K` unbounded, so a larger number is a leftover rather than a
derivation (§11.5).
- **Touched symbols:** *new* `MAX_REPORT_CHECK_ROWS_PER_VARIANT`.
- **Traces to:** R-TUI-090.

**LLR-090.2** — `_checklist_lines` shall carry a row counter across the **outer** `for check in
result.check_results` loop (`:1146`), not inside the inner `for entry in check.entries` loop
(`:1164`), so the bound is per variant.
- **Touched symbols:** `_checklist_lines` (`:1095`, loops at `:1146` and `:1164`).
- **Traces to:** R-TUI-090 AC-4; truth table K6.

**LLR-090.3** — Once the counter reaches the cap, `_checklist_lines` shall continue to emit each
remaining check file's `#### Checklist:` heading, aggregates line and table header with zero data
rows, and shall not alter any aggregates value.
- **Touched symbols:** `_checklist_lines`.
- **Traces to:** R-TUI-090; truth table K6/K7.

**LLR-090.4** — `_checklist_lines` shall emit **exactly one** `> TRUNCATED:` marker per variant,
after the last check file, stating the variant-wide omitted count and total; when a `report_filter`
is set, both figures shall be the **post-filter** counts.
- **Touched symbols:** `_checklist_lines`.
- **Traces to:** R-TUI-090; truth table K4/K5/K6/K9/K10; AT-168.

### R-TUI-091 decomposition — byte-run cell bound *(A-1, ACCEPTED)*

**LLR-091.1** — A module constant `REPORT_CELL_BYTES` shall be defined with value **64**. Its
docstring shall record the three independent anchors (§12.4): `4 × hexview.HEX_WIDTH`
(`s19_app/tui/hexview.py:21`); the shipped display-cap precedent `_REASON_KIND_DISPLAY_CAP = 64`
(`s19_app/tui/changes/check.py:115`); and 16× the largest run observed in any real document cell
(4 B — 1 192 of 1 193 corpus calls are 1–4 bytes). It shall also record the §12.3 framing that
makes a display bound legitimate here: **the table is an index, `_hexdump_section` is the
evidence.**
- **Touched symbols:** *new* `REPORT_CELL_BYTES`; reads `HEX_WIDTH` (already imported at `:49`).
- **Traces to:** R-TUI-091(a).

**LLR-091.2** — `_format_bytes` shall take a **required** `limit: int` parameter — required, so no
call site inherits a cap policy by accident, exactly as `md_safe` does (`report_service.py:93-94`)
— and shall render at most `limit` tokens **and nothing else**: its output alphabet shall remain
`"0123456789ABCDEF "` (plus the existing `"-"` for `None`), preserving R-TUI-077's
inertness-by-construction premise.
- **Touched symbols:** `_format_bytes` (`:430`); its 4 call sites `:997`, `:998`, `:1172`, `:1173`
  (executed census: `grep -rn "_format_bytes" s19_app/` → exactly these 4 plus the definition and
  2 docstring mentions).
- **Traces to:** R-TUI-091(a).

**LLR-091.3** — `_modifications_lines` and `_checklist_lines` shall each count the byte cells they
rendered as a prefix and, when that count is non-zero, emit
`> TRUNCATED: {k} byte cell(s) rendered as a {REPORT_CELL_BYTES}-byte prefix (cap:
{REPORT_CELL_BYTES} bytes per cell); full bytes in the Memory regions section.` plus its appendix
note. The marker shall be emitted **outside** any table cell.
- **Touched symbols:** `_modifications_lines` (`:923`), `_checklist_lines` (`:1095`).
- **Traces to:** R-TUI-091(b); truth table M10/K11.

**LLR-091.4** — `tests/test_report_field_census.py:825
test_f17_format_bytes_is_inert_by_construction` shall be re-pointed **only** to supply the new
required `limit` argument. Its `set(rendered) <= set("0123456789ABCDEF ")` assertion at `:836`
shall be left intact and shall stay GREEN — executed at every candidate bound (§12.2, I-0).
**Drift set for this LLR: ∅ behaviourally; no locked requirement is amended.**
- **Touched symbols:** `test_f17_format_bytes_is_inert_by_construction`.
- **Traces to:** R-TUI-091(a).

*(Withdrawn at A-4: revision 2's in-cell count-bearing indicator. It would have opened the cell's
alphabet and invalidated R-TUI-077's premise — §12.2.)*

### R-TUI-092 decomposition — truncation appendix

**LLR-092.1** — `_modifications_lines` and `_checklist_lines` shall each return their truncation
notes to the composer, and `generate_project_report` shall extend `notes` with them, mirroring
`_hexdump_section`'s `Tuple[List[str], List[str]]` contract (`:1265`, consumed at `:1667-1669`).
- **Touched symbols:** `_modifications_lines` (return type), `_checklist_lines` (return type),
  `generate_project_report` (`:1542`; call sites `:1664` and `:1666`).
- **Traces to:** R-TUI-092(a); AT-165, AT-168.

**LLR-092.2** *(A-2, ACCEPTED)* — `_declaration_error_lines` shall likewise return its truncation
note, so that an absent `## Truncation appendix` is a sound "nothing was cut" signal.
- **Touched symbols:** `_declaration_error_lines` (`:1006`, marker at `:1082-1090`);
  `generate_project_report` call site `:1665`.
- **Traces to:** R-TUI-092(b).

### Documentation LLRs — required, not cosmetic

**LLR-093.1** — The `REPORT_CELL_CHARS` docstring shall be corrected. It currently states, at
`:111-114`, that capping these two tables "is a **carried follow-up**". Shipping the caps while
leaving that text makes the module assert a false fact about itself — the exact failure batch-62
corrected in this same comment.
- **Touched symbols:** `REPORT_CELL_CHARS` docstring (`:92-114`).

**LLR-093.2** — The module docstring's "Size discipline (LLR-007.6)" paragraph (`:26-30`) shall
name the new caps, since it is the module's own statement of what is bounded.
- **Touched symbols:** module docstring (`:26-30`).

**LLR-093.3** — `REQUIREMENTS.md` shall gain `R-TUI-089…092` entries with file+test mappings and
`Automated` status, per the repo's traceability convention (`CLAUDE.md` → "Requirements
traceability").
- **Touched symbols:** `REQUIREMENTS.md`.

---

## 6. Scope amendments — BOTH ACCEPTED (see §11, §12 for the amended values)

Per the project's "requirement amendment before/after" rule, neither of these edits an existing
locked requirement; both **add** scope beyond `01-requirements.md` §2.6 and therefore need an
explicit Phase-2 ruling.

### A-1 — add the per-cell byte-run bound (R-TUI-091) — **ACCEPTED (coordinator ruling)**

| | |
|---|---|
| **Before** | §2.6 scopes the batch to bounding the two tables' **row counts**. |
| **After** | …and bounding the **byte-run cell**, without which neither story's why-clause is delivered. |
| **Evidence** | §0.1 — one row = 6 291 604 B = 3.00× the whole document budget. §0.7 — drift set = 1 direct unit call, 0 documents. |
| **Cost** | 1 function + 4 call sites, all inside `report_service.py`; 1 new constant; 1 test signature. |
| **If REJECTED** | The batch ships a document that still exceeds its declared 2 MiB while printing `report size cap: 2097152 bytes` — M-2 unfixed. In that case the `_hexdump_section` marker text (`:1352-1355`) **must** be reworded to scope its claim to the hexdump blocks it actually governs, and the residual must be a named MAJOR carry. Shipping "the tables are now bounded" over an unbounded document is the worse of the two outcomes. |

### A-2 — retro-wire the declaration-error cap into the appendix (R-TUI-092(b)) — **ACCEPTED (coordinator ruling)**

| | |
|---|---|
| **Before** | Only `_hexdump_section` feeds `## Truncation appendix`. |
| **After** | Every cap feeds it, so its absence means "nothing was cut". |
| **Evidence** | §0.8 — executed: the declaration-error cap fires, the appendix heading is absent. |
| **Cost** | one return-type change + one call site (`:1665`). |
| **If REJECTED** | Carry as a MINOR; the new caps still feed the appendix, so AC-2 is met, but the appendix remains an incomplete index. |

### Out of scope, carried (unchanged from §2.6, plus one new)

- **The variant axis.** No `MAX_VARIANTS` exists (M-5, re-verified). **Carry figure (§12.6,
  superseding §0.5, qa's ~17.3 and REV 3's ~2.0/~7.2): at `CAP = 500`, ~1.6 at-cap variants
  breach the budget in the worst case, ~6.7 in the realistic regime** — a pair, both measured
  end to end with the full worst-case remainder (§13.5).
- **NEW carry (§11.5) — the checklist `K` multiplier.** A variant running `K ≥ 3` full-campaign
  check files is cut at 500 (`K = 2` is covered up to a 250-entry campaign — §13.2). `K` is
  unbounded, so no per-variant value fixes it; same unbounded-multiplier family as the variant
  axis, filed with it.
- **NEW carry (§13.8) — the sidecar conclusion.** `CAP` is **200× below**
  `MF_ENTRY_COUNT_CEILING = 100 000` and can cut legitimate data at the tail. If campaigns an
  order of magnitude larger appear, the answer is a **full-fidelity sidecar** (CSV/JSON) with the
  Markdown table as the bounded index — **not** a bigger cap.
- **NEW carry — `_hexdump_section`'s marker overclaims.** `(report size cap: {REPORT_MAX_TOTAL_BYTES} bytes)`
  (`:1354`) reads as a document-wide guarantee, but only `_hexdump_section` consults the budget.
  Even with A-1 and the variant axis fixed, the wording asserts more than the mechanism delivers.
  Reword or carry — do not leave unexamined.

---

## 7. What would change this recommendation

| if… | then… |
|---|---|
| ~~the operator supplies real campaign sizes~~ **HAPPENED** — "tens to ~200 entries" | §11 → §13: cap re-derived 200 → 400 → **500**, on a floor of 400 that 400 itself failed to clear. Trigger discharged. |
| a campaign an order of magnitude larger appears (5 000+ routine) | 500 becomes indefensible and the honest answer is a **separate full-fidelity artifact** (CSV/JSON sidecar) with the Markdown table as the bounded index — **not** a bigger cap. The ceiling at `REPORT_CELL_BYTES = 64` is 657, so there is no room to buy an order of magnitude. |
| ~~A-1 is rejected~~ **ACCEPTED** | — |
| `REPORT_MAX_TOTAL_BYTES` changes | both row caps re-derive from §12.4's surface; this is why the derivation, not the number, is the requirement. |
| a `MAX_VARIANTS` bound lands | the single-variant ceiling becomes a genuine whole-document guarantee and the caps may rise toward 657. |
| a legitimate inline byte run over 64 B is demonstrated | `REPORT_CELL_BYTES` rises and the cap ceiling falls with it (§12.4 grid) — the pair moves together, never one alone. |
| `REPORT_CELL_CHARS` is lowered | the worst modifications row shrinks and the cap could rise; the mirrored-200 justification would **not** have caught this, the derived one does. |

---

## 8. Risks

| # | risk | class | mitigation |
|---|---|---|---|
| R-1 | A cap in an evidentiary document deletes evidence, and 200 is 500× below the declared input domain. | **evidentiary / correctness** | The cut is exact, stated, attributable, and duplicated in the appendix; applied-entry bytes stay reachable in the hexdump section. Stated in the constant's docstring so it is not re-read as "enough". Reopened by §7 row 1. |
| R-2 | The checklist cap is written per check file instead of per variant. | correctness | AT-167 uses 4 files × ¾ cap; a per-file cap yields 4× and turns it RED. §0.9 is the executed baseline. |
| R-3 | Byte-identity goldens drift (C-24). | test integrity | Executed census §0.6/§0.7: drift set = ∅ at cap 200 / `REPORT_CELL_BYTES` 256. Not predicted. |
| R-4 | A cap AT whose fixture sits under its own cap proves nothing (C-31 — batch-62 shipped one 2.8× under). | test integrity | Every AT fixture states its multiple of the cap in the docstring; AT-164 = 1.5×, AT-167 = 3.0×, AT-170 drives **one** row to 3.00× budget (qa reproduced: 6 294 029 B, 0 markers). |
| R-5 | The cap is applied **before** the zero-match filter branch, printing a cut that did not happen. | correctness | Truth-table rows M6/K8 make the ordering normative; needs its own TC. |
| R-6 | `_format_bytes` gains a `limit` and a call site is missed. | correctness | The parameter is **required**, so a missed site is an immediate `TypeError`, not a silent default. Executed site census: exactly 4. |
| R-7 | ~~An in-cell truncation marker opens the byte cell's closed alphabet and invalidates R-TUI-077's inertness-by-construction premise.~~ **CLOSED by ruling (b), §12.2** | **security** | The indicator is withdrawn; the cell stays pure hex. Executed at every candidate bound (I-0): `set(rendered) <= set("0123456789ABCDEF ")` holds, and end to end through the composer **0 of 1 600 byte cells** are non-hex (J-2). `security-reviewer` should still confirm the new per-section marker text is inert. |
| R-8 | Signature changes to two emitters ripple into tests that call them directly. | test churn | Executed: `grep -rn "_modifications_lines\|_checklist_lines" tests/` → the census plugin found 6 consumer files; direct calls must be swept before Phase 3 sizes the increments. |
| R-9 | Increment budget (≤5 files) **and ordering**. | process | **Superseded by §12.7: A-2 first** (the notes contract the other caps register through), then A-1, then the modifications cap, then the checklist cap, then docs. |
| R-10 | The two constants are not independent — moving `REPORT_CELL_BYTES` moves the cap ceiling (qa §10.3). | design | §12.4 states the pair as a pair, with the ceiling per candidate bound; §7's last trigger makes the coupling explicit for future batches. |

---

## 9. Evidence checklist

| # | claim | ✓/✗ | evidence |
|---|---|:--:|---|
| 1 | Constraints stated explicitly | ✓ | Budget 2 097 152 B (`report_service.py:122`); input domain `MF_ENTRY_COUNT_CEILING = 100 000` (`changes/io.py:226`); run domain `MF_RUN_LENGTH_CEILING = 1 048 576` (`changes/io.py:232`); cell cap 512 (`report_service.py:115`); variant count **unbounded** (`grep -rn "MAX_VARIANT" s19_app/` → 0 hits). |
| 2 | ≥2 alternatives considered | ✓ | §1.2 — row cap · shared `_ByteBudget` check · per-section byte allowance (a third shape Phase-0 did not consider). Rejections reasoned, not asserted. |
| 3 | Recommendation tied to constraints | ✓ *(**was an unearned ✓ at REV 3** — §13.7)* | **§13** — pair `(REPORT_CELL_BYTES=64, CAP=500)`: corrected floor **400**, ceiling **657**, so `400 < 500 < 657` — verified by arithmetic, not asserted. Guaranteed single-variant bound `500 × 2 892 + 195 487 = 1 641 487 B = 78.3 %` of budget, slack **2.33× the measured remainder**. REV 3 marked this ✓ over a cap **one below its own derived floor**. |
| 4 | Risks listed (operational, security, cost, lock-in) | ✓ | §8, ten entries; R-7 is the security one — **raised and then CLOSED by ruling (b)** rather than mitigated (§12.2). |
| 5 | Cost/latency estimated where relevant | ✓ | §0.2 per-row slopes; §0.4 worst-case rows; §0.5 whole-document sizes at 5 candidate caps × 2 regimes. |
| 6 | Diagram included when flow is non-trivial | ✗ | Deliberate: the flow is one linear emitter chain (`report_service.py:1661-1671`); the truth tables in §4 carry the branching, which a flowchart would restate less precisely. |
| 7 | What would change the recommendation is stated | ✓ | §7, five triggers. |
| 8 | Two-layer requirements: Acceptance block + `AT-NNN` per story, both chains | ✓ | §3 — US-B63-1 → AT-164/165/166, US-B63-2 → AT-167/168/169, R-TUI-091 → AT-170/171. Functional chain: US → R-TUI-089…092 (§2) → LLR-089.x…093.x (§5) → TC-399+ (Phase 2, qa-owned). |
| 9 | AT id start verified against disk, not trusted | ✓ | Highest existing = **163** across `REQUIREMENTS.md`, `tests/`, `.dev-flow/`; `grep -rl "AT-164"` → 0. Kickoff figure confirmed. |
| 10 | TC id start verified | ✓ | Highest existing = **398** (`.dev-flow/2026-07-25-batch-62/01b-qa-catalog.md:354`); `grep -rl "TC-399"` → 0. |
| 11 | HLR id range free | ✓ | `R-TUI-089`/`090`/`091`/`092` → 0 files each; `R-TUI-088` claimed by batch-51. |
| 12 | Every threshold pre-executed (C-39) | ✓ **QUALIFIED** | §0.1–§0.9 + §11–§13, all run on this tree; nothing predicted. **But C-39 did not save REV 3:** every *threshold* was executed while the *comparison between two of them* was not (§13.1). The gap is named and a control candidate raised (§13.8). |
| 13 | Drift set executed, not predicted | ✓ | Row caps **∅ at 500**, headroom 500/133 = **3.76×** (§13.5, census re-run — max unchanged at 133). Byte bound **∅** — `test_f17…` stays GREEN at every candidate bound under ruling (b) (§12.2, I-0), so **no locked requirement is amended**. |
| 14 | `shall` confined to HLR/LLR | ✓ | `grep -n "shall"` at REV 4 → every normative hit is inside §2 (`347-391`) or §5 (`529-656`). The four remaining hits are meta-references to the rule itself (header `:29`, §4 preamble `:473-474`, this row). §4 is indicative and normative **by reference** from the LLRs that cite it. §11/§12/§13 are amendment *rationale* and carry no `shall`; they change the VALUES the §2/§5 statements bind. |
| 15 | Frozen files untouched | ✓ | Every touched symbol is in `s19_app/tui/services/report_service.py`, `tests/test_report_field_census.py`, `REQUIREMENTS.md`. None is in `_ENGINE_PATHS` (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) or `_ENGINE_TEST_FILES`. |
| 16 | No worktree mutation by this phase's probes | ✓ | All probes in the session scratchpad; `git status --porcelain` shows only `.dev-flow/` (PLAN risk 5). |
| 18 | Cross-lane numbers reconciled, not averaged | ✓ | Census scopes §12.1 (mine 8 files/1 147, qa 12 files/1 196, superset, same max). Ceiling grids §12.4 (mine 365 vs qa 570 at L=256 — two named conservatisms in mine). Variant carry §12.6 (mine ships; qa's omits escape doubling and the measured remainder). |
| 19 | An accepted amendment was WITHDRAWN when measurement contradicted it | ✓ | §12.2 — revision 2's in-cell indicator, withdrawn because it invalidates R-TUI-077's premise. Recorded Before → After (§12.8), never silently dropped. |
| 20 | Literal sweep against the defined constant (C-36) | ✓ | §13.6 — every `400` classified: 10 normative/live updated, 24 historical left as record, 6 different quantities. **§3 acceptance blocks contain no literal** — AT-164/167 are parametric (`cap × 1.5`, `4 × ceil(0.75 × cap)`), which is what kept the defect out of the acceptance layer. |
| 21 | A defect in my OWN prior revision is recorded, not quietly fixed | ✓ | §13.1 — the REV-3 headline violated its own derived floor by 1 and was asserted verified in three places incl. a ✓ row. Provenance named (an inherited value vs a newly derived constraint), Before → After in §13.8, and the **floor's derivation corrected too** rather than restated to fit. |
| 17 | Missing constraint flagged, not invented | ✓ | §1.4 — no field data on campaign sizes; `find examples -name "*.json"` returns only `crc_config.example.json`, i.e. the shipped corpus has **no** change/check document. |

---

## 10. Phase-1 gate — self-assessment

| axis | assessment |
|---|---|
| **Coverage** | MET for the two READY stories; **NOT MET for their why-clauses without amendment A-1** — §0.1 shows the row cap alone leaves the document unbounded. Recorded as a named amendment with a stated fallback, not resolved unilaterally. |
| **Certainty** | MET. Every threshold executed this phase. Three Phase-0 claims were corrected against disk: the 3.7× per-row spread is the **modifications** table's alone (checklist = 1.00×); the mirror-200 justification does not transfer; and the "truncation-appendix pattern" AC-2 cites is not implemented by the precedent it names. |
| **Evidence** | MET. §9, 17 items, 15 ✓ / 1 ✗ (declared, with reason) / 1 informational. |

**Call:** `approve with amendment` — the requirements are complete and traceable, and the one
unresolved item (A-1) is an explicit scope question for Phase 2, not an open design question.

*(Revision 1 gate call. Superseded by §11.9.)*

---
---

# §11 — AMENDMENT A-3: cap re-derivation against the operator field datum

> **Trigger.** A-1 and A-2 were accepted into scope, and the operator supplied the field datum
> that revision 1 flagged as missing (§1.4, evidence-checklist item 17): **a real campaign is
> "tens to ~200 entries"**. Revision 1's cap of 200 sits exactly *at* the top of the legitimate
> range, so a 205-entry campaign would be cut. Per the project's amendment rule, nothing above is
> silently edited: §1.4 and §1.5 stand as the revision-1 record, and this section supersedes them.
>
> **Everything below was executed at this revision.** Probes `p63f.py`, `p63g.py`, `p63h.py`
> and a re-run of the two census plugins, all from the scratchpad — `git status --porcelain`
> shows only `.dev-flow/`.

## 11.1 — Two premises in the amendment brief did not survive measurement

**Premise 1 — "your pre-A-1 figures 3 614 B / 1 574 B should drop substantially once
`_format_bytes` is bounded." → FALSE. They RISE.**

Those figures were never unbounded measurements. Probe P-7 (§0.4) constructed byte runs of
*exactly* `RUN_LIMIT` bytes, i.e. it had already simulated the bound — so 3 614 / 1 574 were the
**bounded** cost with **no marker emitted**, which makes them a **floor**, not the worst case. The
true post-A-1 worst case drives the run *over* the limit so the marker is present. Re-measured
(probe `p63f.py` R-1, marker `… +{omitted} of {total} bytes` at worst-case digit widths):

```
  HEX_WIDTH (hexview.py:21) = 16
  REPORT_CELL_BYTES=  16 ( 1 x HEX_WIDTH) -> worst mod row  2,238 B | worst chk row    198 B | sum  2,436 B
  REPORT_CELL_BYTES=  32 ( 2 x HEX_WIDTH) -> worst mod row  2,334 B | worst chk row    294 B | sum  2,628 B
  REPORT_CELL_BYTES=  64 ( 4 x HEX_WIDTH) -> worst mod row  2,526 B | worst chk row    486 B | sum  3,012 B
  REPORT_CELL_BYTES= 128 ( 8 x HEX_WIDTH) -> worst mod row  2,910 B | worst chk row    870 B | sum  3,780 B
  REPORT_CELL_BYTES= 256 (16 x HEX_WIDTH) -> worst mod row  3,678 B | worst chk row  1,638 B | sum  5,316 B

  fitted: mod_worst(L) = 2,142 + 6L      chk_worst(L) = 102 + 6L      (exact at L=16 and L=256)
```

At L=256 the worst rows are **3 678 / 1 638**, i.e. **+64 B each** over the revision-1 figures —
the marker's own width. **What A-1 collapses is not these numbers; it is the unbounded case**:
6 291 604 B → 3 678 B, a **1 710× reduction** (§0.1 vs R-1). The distinction matters because the
cap arithmetic must use the marker-inclusive figure or it under-counts by the exact amount the
amendment adds.

**Premise 2 — implicit in revision 1, not the brief: the "≤ 50 % of budget" policy. → It was
invented by me, and it is wrong by ~1.8×.**

Revision 1 §1.4 reserved half the budget for "every other section plus a second variant" without
measuring what the other sections cost. Measured (probe `p63f.py` R-2) — one variant with the
hexdump section at its own caps (128 regions × `context_bytes=4096`), declaration errors at
`MAX_REPORT_ISSUES_PER_VARIANT` with worst-case 500-char messages, legend + entropy + addendum all
on:

```
  whole worst-remainder document          :    203,783 B
  minus its own modifications table       :      8,294 B
  => REMAINDER (hexdumps 128 x ctx4096, decl-errors at cap 200,
     legend, entropy, addendum, header)   :    195,489 B = 9.3% of budget
  => bytes available for the TWO TABLES   :  1,901,663 B
```

**The real remainder is 9.3 %, not 50 %.** The invented policy was starving the tables of 1.81× the
budget they can safely have — and it is the reason revision 1 landed on 200 and then had to
rationalise it. A measured remainder replaces it.

## 11.2 — Constraints (a) and (b), solved jointly

- **(a) field margin.** The `REPORT_CELL_CHARS` discipline is *≥ the largest legitimate value, with
  margin*: 512 / 255 = **2.01×**. Applied to a field maximum of ~200 entries, the cap must be
  **≥ 400**.
- **(b) budget fit.** `cap × (mod_worst(L) + chk_worst(L)) ≤ 1 901 663 B` (R-2, measured).

Probe `p63f.py` R-3, solving (b) for each candidate `REPORT_CELL_BYTES` and testing it against (a):

```
    L=  16: sum row  2,436 B -> cap <=   780 =  3.90x the field max   [OK   vs the 2.0x precedent]
    L=  32: sum row  2,628 B -> cap <=   723 =  3.62x the field max   [OK   vs the 2.0x precedent]
    L=  64: sum row  3,012 B -> cap <=   631 =  3.15x the field max   [OK   vs the 2.0x precedent]
    L= 128: sum row  3,780 B -> cap <=   503 =  2.52x the field max   [OK   vs the 2.0x precedent]
    L= 256: sum row  5,316 B -> cap <=   357 =  1.78x the field max   [FAIL vs the 2.0x precedent]
```

**(a) and (b) ARE jointly satisfiable — but not at the working value of 256.** At
`REPORT_CELL_BYTES = 256` the budget admits at most **357** rows = 1.78× the field max, which fails
the very precedent the brief asked me to apply. **`REPORT_CELL_BYTES ≤ 128` is required**; nothing
has to give.

## 11.3 — `REPORT_CELL_BYTES` re-derived against the field, not the census

The brief asked for a field derivation rather than a census derivation. The honest position is
that **there is no operator datum for byte-run length** — the campaign datum bounds entry *count*,
not run *width* — so I will not manufacture one. What the field does give:

| anchor | value | source |
|---|---|---|
| largest run in a real **document** cell, whole corpus | **4 B** | executed census `census63b`, §0.7 — histogram `{1: 579, 2: 563, 4: 4, 256: 1}` |
| the one 256-B call | a **direct unit call**, `_format_bytes(range(256))` | `tests/test_report_field_census.py:835` — not a document cell |
| declared input domain | 1 048 576 B | `MF_RUN_LENGTH_CEILING`, `changes/io.py:232` — useless as a *display* bound |
| the module's own display grid | `HEX_WIDTH = 16` | `s19_app/tui/hexview.py:21` |
| shipped display-cap precedent in this codebase | 64 | `_REASON_KIND_DISPLAY_CAP`, `changes/check.py:115` |

**Ruling: `REPORT_CELL_BYTES = 128` = 8 × `HEX_WIDTH`.** It is **32× the largest run any real
document cell has ever carried** (4 B) — a far wider margin than the 2.01× the `REPORT_CELL_CHARS`
discipline demands — and it is the largest power-of-two multiple of the display grid that leaves
constraint (a) satisfiable. Its role is explicitly *architectural*, and that role is what makes a
display bound legitimate here at all: **the table cell is a summary; the hexdump section is the
evidence.** A 128-byte cell is already 383 characters wide and unreadable as a table cell, while
the full bytes of every applied entry remain in the hexdump section (`report_service.py:1261`).

## 11.4 — The cap: **400**, both tables

> ⚠ **SUPERSEDED BY §13.** Both the value and the floor reasoning here are wrong: 400 does not
> clear the floor it implies, and the 2.01× anchor is a rounding artifact. Normative: **500**.

`REPORT_CELL_BYTES = 128` admits up to 503. Choosing **400**:

- **= 2.00× the field maximum**, matching the `REPORT_CELL_CHARS` 2.01× precedent to two decimals.
  A 205-entry campaign — the case the brief raised — is emitted **whole**, as is a doubled one.
- **not 503**, which is a leftover, not a number: it has 0.6 % headroom against a *measured*
  remainder that could grow if a later batch adds a per-variant section.
- **guaranteed bound:** `400 × 3 780 + 195 489 = 1 707 489 B = 81.4 %` of `REPORT_MAX_TOTAL_BYTES`.
  Inside, with 18.6 % slack.

**End-to-end verification, measured through the shipped composer** (probe `p63g.py` G-1 /
`p63h.py` H-1). Input: 1 600 modification entries (4× the cap), 4 check files × 400 entries
(4× the cap), one 1 MiB byte run on each side, 512-char all-escapable `linkage` and
`linkage_symbol`, worst-case remainder sections all on:

```
  BEFORE (main, uncapped):        35,074,380 B =  16.72x budget   byte-cap marker present: True
  AFTER  (caps applied):           1,063,594 B =   0.51x budget = 50.7% of budget   INSIDE
    emitted modification rows : 400  (cap 400)
    emitted checklist rows    : 400  (cap 400, across 4 files)
    shrink factor: 33.0x
    markers: mod=True chk=True cell=True
```

**The `BEFORE` line is the defect in one number: 16.72× the budget while printing the marker that
claims the budget held.** The `AFTER` document sits at 50.7 % measured (the 81.4 % figure is the
guarantee — not every row can be simultaneously worst-case *and* coexist with the worst-case
remainder, so the arithmetic bound is conservative, which is what a bound should be).

The `checklist rows = 400 across 4 files` line is the AC-4 evidence: a per-file cap would have
emitted 1 600.

## 11.5 — Ruling on question 3: same value, still two constants

Post-A-1 the checklist row is **3.3× cheaper** than the modifications row (870 vs 2 910 B at
L=128), so the budget *would* admit a much higher checklist cap — measured (R-3): with
`cap_mod = 400`, the checklist could go to **847**. I rule against it, on three grounds:

1. **847 is a leftover, not a derivation.** It is whatever the modifications table did not spend.
   The whole point of this amendment is to stop choosing cap values by what is available.
2. **Constraint (a) is structurally unsatisfiable for the checklist, so a bigger number does not
   buy correctness.** The legitimate checklist population is `K × 200` where `K` is the number of
   check files run over the campaign, and `K` has no bound anywhere in `s19_app` (same defect
   family as the variant axis). No per-variant value can sit above an unbounded legitimate
   population; raising 400 → 847 just moves an unsatisfiable line and costs 389 000 B.
3. **No demand.** Check entries are generated against the same campaign as the change entries, so
   the per-file population tracks the same ~200. 400 covers **two** full-campaign check files.

**Two constants are retained** (independent derivations, independent evolvability — a future batch
can move one without silently moving a section it was not derived for), **with the same value
today**, and each docstring states that the coincidence is not a coupling.

**Residual, carried:** a variant running **K ≥ 3** full-campaign check files is cut at 400. Stated,
not hidden; filed with the variant-axis carry (§11.7) because it is the same unbounded-multiplier
defect.

## 11.6 — Drift census re-run at the chosen values

Both census plugins re-run at this revision over the full report-test corpus (315 tests, all
passing):

```
===== CENSUS63 =====
_modifications_lines  MAX entries in one call : 133
  population histogram : {0: 12, 1: 26, 2: 7, 3: 2, 128: 2, 130: 1, 133: 1}
_checklist_lines      MAX rows per VARIANT    : 3     MAX check results per variant : 2
===== CENSUS63B (_format_bytes run lengths) =====
  histogram (run len -> calls): {1: 579, 2: 563, 4: 4, 256: 1}
  cells that a RUN_LIMIT=128 would truncate: 1
  cells that a RUN_LIMIT=256 would truncate: 0
```

| bound | drift set | headroom over the real maximum |
|---|---|---|
| `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT = 400` | **∅** | 400 / 133 = **3.01×** (was 1.50× at cap 200) |
| `MAX_REPORT_CHECK_ROWS_PER_VARIANT = 400` | **∅** | 400 / 3 = **133×** |
| `REPORT_CELL_BYTES = 128` | **exactly 1 test**, named: `tests/test_report_field_census.py:825 test_f17_format_bytes_is_inert_by_construction` (calls `_format_bytes(range(256))` directly at `:835`) | 128 / 4 = **32×** over any real document cell; **0 documents drift** |

That single drift is **informative, not incidental**: the test asserts every emitted character is
in the hex alphabet, and the marker deliberately is not — so the test going RED *proves the marker
is emitted*. It is re-pointed by LLR-091.4 and is AT-171's subject.

**Byte-identity, verified end to end** (probe `p63g.py` G-3 — full documents generated pre- and
post-change and compared as bytes):

```
  n= 133 (suite max): byte-identical pre/post = True   (483,571 B)
  n= 200 (field max): byte-identical pre/post = True   (628,561 B)
  n= 400 (AT the cap): byte-identical pre/post = True (1,061,363 B)
```

AC-3 is discharged at the suite maximum, at the operator's field maximum, and at exactly the cap.

## 11.7 — Variant-axis carry figure, recomputed

> ⚠ **SUPERSEDED BY §13.5** (`CAP = 500`: ~1.6 worst / ~6.7 realistic). The reconciliation against
> qa's light-fixture ~17.3 still applies.

Measured at-cap single-variant documents in the **worst-case** regime (probe `p63h.py` H-2):

```
    cap  x field max   1-variant doc   % budget   variants to breach
    200        1.00x        631,124 B      30.1%                3.32
    300        1.50x        847,526 B      40.4%                2.47
    400        2.00x      1,063,926 B      50.7%                1.97
    500        2.50x      1,280,326 B      61.1%                1.64
```

**Carry figure at the chosen cap: the 2 MiB budget is breached at 1.97 at-cap variants — i.e. TWO
at-cap variants already exceed it** (1.23 against the 81.4 % guaranteed bound).

⚠ **This is not comparable to the qa-reviewer's ~17.3.** That figure comes from a *light* at-cap
fixture (default context, no legend/entropy/addendum, no declaration errors); my §0.5 light fixture
gives 15.5 at cap 200 and 6.4 at cap 500, bracketing it. A light fixture over-states the safe
variant count by ~8×, so **the carry must ship the worst-case number**. Raising the cap 200 → 400
costs 3.32 → 1.97 variants; that is the price of the field margin and it is paid on an axis that is
already unbounded and already carried.

## 11.8 — Before → After

| item | **Before** (revision 1) | **After** (this amendment) | why |
|---|---|---|---|
| A-1 byte-run bound | PROPOSED amendment | **ACCEPTED, in scope** (R-TUI-091) | coordinator ruling |
| A-2 appendix retro-wiring | PROPOSED amendment | **ACCEPTED, in scope** (R-TUI-092(b)) | coordinator ruling |
| `REPORT_CELL_BYTES` | 256 (census-derived: ≥ corpus max) | **128** (= 8 × `HEX_WIDTH`; 32× the largest real document cell) | 256 makes constraint (a) unsatisfiable — admits only 357 rows = 1.78× field max (§11.2) |
| `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT` | 200 | **400** | field datum: campaigns reach ~200, so 200 cuts legitimate data. 400 = 2.00× field max, matching the 512/255 = 2.01× precedent (§11.4) |
| `MAX_REPORT_CHECK_ROWS_PER_VARIANT` | 200 | **400** | same value, same reasoning; the cheaper row would admit 847 but that is a leftover (§11.5) |
| budget policy | "≤ 50 % of budget" (**invented**) | **measured remainder 195 489 B = 9.3 %**; tables may use 1 901 663 B | R-2 — the invented policy was wrong by 1.81× |
| worst row bytes | 3 614 / 1 574 (**floor** — no marker) | **2 910 / 870** at L=128; 3 678 / 1 638 at L=256 (**marker included**) | §11.1 premise 1 |
| guaranteed single-variant bound | not stated | **81.4 %** of budget (measured 50.7 %) | §11.4 |
| drift set | ∅ at cap 200 | **∅** at cap 400 (headroom 1.50× → **3.01×**) + **1 named test** for the cell bound | §11.6 |
| variant-axis carry | qa's ~17.3 (light fixture) | **1.97 at-cap variants** (worst case) | §11.7 |

**Unchanged by this amendment:** the *shape* ruling (per-variant row cap, not `budget.fits()` —
§1.2, including the third measured rejection reason); the two-constants ruling (§1.5, reaffirmed
in §11.5 on new evidence); the refutation that a row cap alone bounds anything (§1.3); the
truth tables (§4) — every row is value-independent; and every AT/TC id.

## 11.9 — Revised gate assessment

| axis | assessment |
|---|---|
| **Coverage** | **MET** (was "NOT MET without amendment"). A-1 and A-2 are in scope, so the stories' why-clauses are now deliverable: measured 16.72× budget → 0.51× on the same input. |
| **Certainty** | **MET.** Every value re-derived by execution at this revision. Two premises I was handed were falsified by measurement (§11.1) rather than adopted, and one of my own revision-1 policies was falsified with them. |
| **Evidence** | **MET.** §11.1–§11.7 transcripts; §9 updated. |

**Call: `approve`.** No open design question remains. Two items ship as stated carries: the
variant axis (1.97 at-cap variants) and the checklist `K ≥ 3` residual (§11.5).

**Fresh occurrence for control candidate P-3 (assert against the emitted encoding).** Probe G's
row counter used `startswith("| 0x00001")`, which matched only addresses `0x00001000-0x00001FFF`
while the fixture strides `0x400`; it reported **4** modification rows where 400 were emitted. The
artifact was correct, the predicate was wrong — the fourth occurrence in four batches
(`00-measurements.md` M-6 `chk_rows=-1`; batch-61's NBSP-entity predicate; batch-62's
`"](" not in note`). Corrected in `p63h.py` H-1 with an address-range regex. As at M-6, it was
caught because the value was **impossible** (4 rows from 1 600 entries) rather than merely low.

*(Revision-2 gate call. §11.3 and §11.6 superseded by §12; §11.9 superseded by §12.9.)*

---
---

# §12 — AMENDMENT A-4: the byte cell stays pure hex, and the pair is derived jointly

> **Trigger.** The qa-reviewer's REV-2 catalog (`01b-qa-catalog.md` §10, read directly) supplies a
> measured joint constraint surface and surfaces a collision revision 2 under-rated. Probes
> `p63i.py`, `p63j.py`, scratchpad only; `git status --porcelain` shows only `.dev-flow/`.

## 12.1 — Census reconciliation: two scopes, one maximum, no averaging

qa is right to refuse the misattributed number. The reconciliation:

| census | scope | calls | max run | max site |
|---|---|---:|---:|---|
| mine (`census63b`, §0.7) | 8 report-touching files: `test_report_service`, `test_report_field_census`, `test_report_symbol_escape`, `test_report_filter`, `test_report_addendum`, `test_report_markup_safety`, `test_report_logging`, `test_report_progress` — **315 tests** | 1 147 (+3 `None`) | **256** | `test_report_field_census.py:835` |
| qa's (§10.1) | **12** report-touching files (adds `test_tui_report_seam`, `test_tui_report_view`, `test_tui_report_filter_surface`, +1) — **376 tests** | 1 196 (+3 `None`) | **256** | same |

**The gap is fully explained: qa's set is a strict superset of mine — the 4 TUI-surface files I
excluded from the byte census because they are the slow Textual files (264 s alone).** 1 196 − 1 147
= 49 additional value-bearing calls, all from those files, none exceeding 4 bytes. **The scope is
now stated on both sides, and the two agree on every fact that matters:** max = 256, at one
direct-unit-call site, with essentially the whole population at 1–4 bytes. Nothing is averaged;
qa's wider census is the one to cite because its scope is the larger and is named.

## 12.2 — RULING on the byte-cell collision: **option (b) — the cut is stated OUTSIDE the cell**

qa is right that 256 has zero headroom, and right that `tests/test_report_field_census.py:836`
asserts `set(rendered) <= set("0123456789ABCDEF ")`. The decisive point is *why that assertion
exists*, and it is not a test detail:

**R-TUI-077 excludes `_format_bytes` from escaping on the ground that it emits "hex digits and
spaces only"** (`REQUIREMENTS.md:4780-4782`). That is **inertness by construction** — the field is
safe because its alphabet is *closed*, not because anything sanitises it. Line 836 is the pin that
makes the exclusion sound.

**Option (a) — an in-cell indicator — does not "require amending a test". It invalidates the
premise of a locked requirement.** Put `…`, `+`, or letters into that cell and the alphabet is no
longer closed, so R-TUI-077's exclusion would need a *new* safety argument where today it needs
none. Trading a proven structural invariant for a formatting convenience is precisely backwards in
a batch whose purpose is to make the document more trustworthy.

**Option (c) — raise the bound above 256 — is self-defeating**: it sets a *display* bound to
accommodate a *test fixture*, costs the most cap window (ceiling 365 at L=256, §12.4), and is
re-opened by the next fixture with a longer run.

**Option (b) is free and strictly better.** The cell renders the first `REPORT_CELL_BYTES` tokens
and nothing else; the cut is stated where every other cut in this module already lives — an
in-section `> TRUNCATED:` marker plus an appendix entry. Executed (probe `p63i.py` I-0), the exact
assertion at `:836` re-run against a prefix-only formatter at every candidate bound:

```
  L=  16: _format_bytes(range(256)) ->    47 chars, set(rendered) <= hex alphabet: True
  L=  32: _format_bytes(range(256)) ->    95 chars, set(rendered) <= hex alphabet: True
  L=  64: _format_bytes(range(256)) ->   191 chars, set(rendered) <= hex alphabet: True
  L= 128: _format_bytes(range(256)) ->   383 chars, set(rendered) <= hex alphabet: True
  L= 256: _format_bytes(range(256)) ->   767 chars, set(rendered) <= hex alphabet: True
```

**`test_f17_format_bytes_is_inert_by_construction` stays GREEN at every candidate bound, and no
locked requirement is amended.** The `>` vs `>=` booby trap dissolves with it — at L=256 the
corpus-maximum call is unchanged either way, because a prefix of 256 from 256 bytes *is* the whole
run. Revision 2's §11.6 called this drift "informative"; that was wrong, and the reason it was
wrong is that I classified a security invariant as a test artifact.

**Nothing becomes silent.** Three signals, none inside the cell:
1. the **`Length` column already carries the true run length** — verified end to end (probe
   `p63j.py` J-3): `row @0x00001000 states Length=1,048,576 while its cell renders 64 tokens`;
2. a per-section `> TRUNCATED: {k} byte cell(s) rendered as a {N}-byte prefix (cap: {N} bytes per
   cell); full bytes in the Memory regions section.` with an exact count;
3. its truncation-appendix entry.

## 12.3 — The reframing is right, and it is what makes this bound legitimate

The coordinator asked whether the byte cells are the right place for byte-level evidence. **They are
not, and saying so changes what "legitimate value" means for this bound.**

`_hexdump_section` (`report_service.py:1261`) is the surface *designed* for byte evidence: it
renders through the shared `hexview` renderer with address gutters and an ASCII column, it is
region-capped at 128, and it is the one section that already consults `budget.fits()`. The table
cells render a run as inline space-separated hex inside a Markdown cell — at 256 bytes that is a
767-character cell (measured, I-0), which no one reads.

**So the tables are an INDEX (address · length · linkage · symbol · verdict) and the hexdump is the
EVIDENCE.** Under that framing the "largest legitimate value" for a byte cell is not the largest
schema-legal run (1 048 576) but *the largest run a reader would read inline in a table row* — and
the field answers that: **1 192 of 1 193 observed calls are 1–4 bytes** (qa §10.1). This is why a
small bound costs almost no fidelity, and it is the reason the marker's wording points at the
Memory regions section rather than merely apologising.

## 12.4 — The pair, derived jointly

> ⚠ **SUPERSEDED IN PART BY §13.** The `REPORT_CELL_BYTES = 64` ruling and the ceiling of 657
> stand. The **floor of 401 is wrong** (it borrows a rounding artifact as a margin — §13.2) and the
> **`CAP = 400` interiority claim below is FALSE**: 400 is one *below* that floor. Corrected floor
> **400**, normative cap **500**.

qa's grid and mine disagree on the ceiling (qa ≈570 at `CELL_BYTES=256`; mine 365). **Reconciled,
not averaged — the gap is two conservatisms mine has and qa's does not:**

1. **Escape doubling.** My worst-case text cells are `"|" * 512`, which `md_safe` grows **2.00×** to
   1 024 chars (§0.3, measured). A hostile `linkage_symbol` is schema-legal and file-derived — it is
   the exact threat batch-62 existed for — so the worst case must include it. qa's cells are 512
   chars benign.
2. **Worst-case remainder.** I subtract a measured 195 487 B remainder (hexdumps at 128 regions ×
   `context_bytes=4096`, declaration errors at their cap with 500-char messages, legend + entropy +
   addendum). qa's per-variant marginal implies a ~2 KB remainder.

Both differences make mine the conservative side, so **mine is the one a bound should be derived
from.** qa's grid and mine agree on the shape of the surface and on the key qualitative finding —
the two constants are not independent, and the window widens fast as `CELL_BYTES` falls.

Executed (probe `p63i.py` I-1/I-2/I-3), pure-hex cells per §12.2:

```
  worst rows: mod = 2,142 + 6L    chk = 102 + 6L
  remainder  = 195,487 B (9.3% of budget)   available for both tables = 1,901,665 B
  field floor = 200 x (512/255) = 401        [the REPORT_CELL_CHARS 2.01x precedent]

      L   sum row   ceiling   x field           window   CAP=400 interior?
     16    2,316B       821     4.11x       [401, 821] yes, 49% of ceiling
     32    2,508B       758     3.79x       [401, 758] yes, 53% of ceiling
     64    2,892B       657     3.29x       [401, 657] yes, 61% of ceiling
    128    3,660B       519     2.60x       [401, 519] yes, 77% of ceiling
    256    5,196B       365     1.82x            EMPTY  NO - 400 > ceiling
```

**`REPORT_CELL_BYTES = 64`**, on three independent anchors, none of them the census alone:
- **= 4 × `HEX_WIDTH`** (`hexview.py:21`) — four rows of the module's own display grid;
- **= the shipped display-cap precedent in this codebase**, `_REASON_KIND_DISPLAY_CAP = 64`
  (`changes/check.py:115`);
- **16× the largest run any real document cell has ever carried** (4 B) — far past the 2.01×
  discipline — while 1 192 of 1 193 observed calls are untouched.

It also leaves the cap window at `[401, 657]`, so the pair is **interior to both constraints**
rather than sitting on either boundary — which is the property that matters, not maximising either
number.

**`CAP = 400`, unchanged from §11.4**, now shown interior: **2.00× the field maximum** (matching the
512/255 = 2.01× precedent to two decimals) and **61 % of the 657 ceiling**. Neither constraint
binds. A 205-entry campaign — the case that triggered A-3 — and a doubled one both emit whole.

**Guaranteed single-variant bound: `400 × 2 892 + 195 487 = 1 352 287 B = 64.5 %` of budget.**

## 12.5 — End-to-end verification at the chosen pair

> ⚠ **Figures below are at `CAP = 400`, superseded by §13.3/§13.5** (`CAP = 500`: measured
> 1 279 244 B = 61.0 %, rows 500/500, 0 of 2 000 cells non-hex). The *properties* demonstrated —
> per-variant checklist cap, closed cell alphabet, all markers present — are unchanged.

Probe `p63j.py` J-1/J-2. Input: 1 600 modification entries (4× cap), 4 check files × 400 (4× cap),
1 MiB byte runs, 512-char all-escapable text cells, worst-case remainder sections on.

```
  BEFORE:     16,200,096 B =    7.72x budget
  AFTER :      1,062,844 B =    0.51x budget = 50.7%   INSIDE
  shrink: 15.2x     rows: mod=400 chk=400
  markers present:
    > TRUNCATED: 4 byte cell(s) rendered as a 64-byte prefix (cap: 64 bytes per cell); full bytes in the Memory regions section.
    > TRUNCATED: 1200 of 1600 modification rows omitted (cap: 400 rows per variant).
    > TRUNCATED: 1200 of 1600 checklist rows omitted (cap: 400 rows per variant).
    > TRUNCATED: 1472 of 1600 modified regions omitted (cap: 128 regions per variant).
  appendix heading present: True

  byte cells inspected: 1600   non-hex cells: 0
  longest byte cell: 191 chars (= 64 tokens x 3 - 1)
```

`chk=400` **across four check files** is the AC-4 evidence — a per-file cap emits 1 600.
`non-hex cells: 0` is ruling (b) holding through the real composer, not just at the unit call.

## 12.6 — Variant-axis carry: the pair

> ⚠ **SUPERSEDED BY §13.5.** At `CAP = 500` the carry is **~1.6 worst / ~6.7 realistic**. The
> reconciliation against qa's figures below still applies.

Probe `p63j.py` J-4, at the chosen pair, both regimes measured with the **full** remainder:

```
  worst case (1 MiB runs, 512-char all-escapable text)
    1 at-cap variant =  1,062,372 B -> breach at   1.97 variants
  realistic (4 B runs, 63-char A2L symbol)
    1 at-cap variant =    291,514 B -> breach at   7.19 variants
```

**Carry ships as: ~2.0 at-cap variants (worst case) / ~7.2 (realistic).**

⚠ Divergence from qa's `~2.9 worst / ~100 realistic`, stated rather than averaged: qa's worst case
omits the escape doubling (§12.4 (1)) and both of its regimes carry a ~2 KB remainder where mine
carries the measured 195 487 B — the realistic figures differ by ~14× almost entirely because of
the remainder. **Mine is conservative on both axes, so the carry should ship mine.** qa's REV-2
correction of its own ~17.3 → ~2.9 is right in direction and understates the sharpening.

## 12.7 — Increment order: **A-2 first — I agree, and the dependency confirms it**

R-TUI-092 changes `_declaration_error_lines`, `_modifications_lines` and `_checklist_lines` from
`List[str]` to the `Tuple[List[str], List[str]]` notes contract that `_hexdump_section` already
uses (`:1265`), plus the `generate_project_report` call sites. **The two new caps register their
appendix notes *through* that contract, so it must exist before they land.**

A-2 first is also the better gate: it is the only increment that is a standalone correctness fix
on an emitter whose cap **already works**, so it exercises the new plumbing with zero new cap
logic and has its own black-box AT (qa's AT-174). Revised order:

| inc | content | why here |
|---|---|---|
| **1** | **A-2**: notes contract + `_declaration_error_lines` retro-wire + `generate_project_report` call sites | establishes the plumbing; RED→GREEN on AT-174 alone |
| 2 | A-1: `REPORT_CELL_BYTES` + `_format_bytes(limit)` (4 call sites) + the per-section byte-cell marker | independent of the row caps; its marker rides inc-1's plumbing |
| 3 | R-TUI-089 modifications cap + marker + note | |
| 4 | R-TUI-090 checklist cap (per-variant counter) + single marker + note | the AC-4 trap, on proven plumbing |
| 5 | docs: `REPORT_CELL_CHARS` docstring correction, module docstring, `REQUIREMENTS.md` | |

This supersedes §8 R-9's ordering (which put `_format_bytes` first).

## 12.8 — Before → After

| item | **Before** (revision 2, §11) | **After** (this amendment) | why |
|---|---|---|---|
| byte-cell truncation indicator | **inside the cell**, count-bearing (`… +N of M bytes`) | **WITHDRAWN — cell stays pure hex**; the cut is stated per-section + appendix, with `Length` as the per-row corroborator | an in-cell indicator invalidates the premise of locked **R-TUI-077** (inertness *by construction* via a closed alphabet), not merely a test (§12.2) |
| `REPORT_CELL_BYTES` | 128 | **64** | = 4 × `HEX_WIDTH` **and** = the shipped `_REASON_KIND_DISPLAY_CAP`; 16× the largest real document cell; widens the cap window to `[401, 657]` (§12.4) |
| worst rows | 2 910 / 870 (marker included, L=128) | **2 466 / 426** at L=64, pure hex | §12.4, I-1 |
| ceiling / interiority | not computed | ceiling **657**; CAP 400 at **61 %** of it — **interior to both constraints** | qa's finding that the two constants are not independent |
| `CAP` (both tables) | 400 | ~~**400 — unchanged**, now shown interior~~ **⚠ FALSE — SUPERSEDED BY §13**: 400 is one BELOW the 401 floor this same section derived. Normative: **500**, above a corrected floor of 400 | the interiority claim was asserted, not computed (§13.1) |
| guaranteed single-variant bound | 81.4 % | **64.5 %** | cheaper rows at L=64 |
| `test_f17…` drift | "1 test drifts, informative" | **∅ — it stays GREEN**; no locked requirement amended | §12.2, I-0 |
| variant carry | 1.97 (worst only) | **~2.0 worst / ~7.2 realistic** — a pair | §12.6 |
| increment order | `_format_bytes` first (§8 R-9) | **A-2 first** | notes-contract dependency (§12.7) |
| census citation | "my 1147-call census" | **qa's 1 196-call census over its named 12-file set**; mine is the 8-file subset, agreeing on every fact | §12.1 |

**Unchanged:** the shape ruling (§1.2), the refutation that a row cap alone bounds anything (§1.3),
the two-constants ruling (§1.5 / §11.5), the truth tables (§4 — every row is value-independent),
and every AT/TC id.

## 12.9 — Gate

| axis | assessment |
|---|---|
| **Coverage** | **MET.** A-1 and A-2 in scope; measured 7.72× budget → 0.51× on the same input, with every cut stated and the appendix present. |
| **Certainty** | **MET.** Every normative value re-derived by execution at this revision. Across revisions 2–3, four handed-down premises and one of my own were falsified by measurement rather than adopted. |
| **Evidence** | **MET.** §12.1–§12.7 transcripts; §9 updated. |

**Call: `approve`.** Carries shipping with the batch: the variant axis (~2.0 worst / ~7.2
realistic), and the checklist `K ≥ 3` full-campaign residual (§11.5).

*(Revision-3 gate call. §12.4's interiority claim and every §12.5/§12.6 figure superseded by §13;
§12.9 superseded by §13.8.)*

---
---

# §13 — AMENDMENT A-5: the REV-3 headline violated its own floor by 1

> **Trigger.** Coordinator review of REV 3. The defect is mine and it is arithmetic, so it is
> recorded plainly rather than quietly corrected. Probes from the scratchpad;
> `git status --porcelain` shows only `.dev-flow/`.

## 13.1 — The defect, stated plainly

REV 3 derived a field floor of **401** in §12.4 and then asserted `CAP = 400` **interior** to
`[401, 657]` — in the same table that printed the window. **400 ∉ [401, 657].** The floor bound,
and was violated by exactly 1. The false claim appeared in three places, one of them an
evidence-checklist row marked ✓:

| where | the false text |
|---|---|
| §12.4 grid | `L=64 … [401, 657] … CAP=400 interior? yes, 61% of ceiling` |
| §12.4 prose | "the field floor 401 and the ceiling 657 both clear it" |
| §9 row 3 (marked ✓) | "field floor 401, ceiling 657 … Both constraints satisfied, neither binding" |

**Provenance, visible in my own text.** §12.4 says `CAP = 400`, **unchanged from §11.4**, while the
floor 401 is derived *later*, in §12. **An inherited number met a newly derived constraint by
assertion instead of by arithmetic** — nobody re-ran the comparison after the constraint moved.

**Root cause, precisely.** Probe `p63i.py` I-3 printed a column headed `CAP=400 interior?` whose
computation was `("yes, %.0f%% of ceiling" % ...) if ceil_ >= 400 else "NO"` — **it compared
against the ceiling only and never against the floor it printed two columns to the left.** The
column's *label* claimed more than its *computation* tested, and I read the label. That is the same
family as this batch's recurring predicate defects (`00-measurements.md` M-6 `chk_rows=-1`; the
REV-2 `startswith("| 0x00001")` row counter): **a probe's output is only as true as the predicate
behind it, and a label is not a predicate.**

**That is C-39's failure mode committed inside the artifact that encodes C-39's lesson**, and it is
the same shape as the batch-62 drift-set prediction that would have false-failed a correct
implementation: a number that was *true when written* and never re-checked when its basis changed.
The generalisable rule this earns: **when a constraint is derived or moved, every value already
bound by it must be re-evaluated against it in the same edit** — carrying a value forward across a
revision is a re-derivation, not a copy.

## 13.2 — The floor's derivation was ALSO wrong, and that is the deeper fix

The coordinator's instruction was explicit: do not restate the floor as "~400" to make 400 fit.
Examining the anchor, it does not survive:

**`REPORT_CELL_CHARS = 512` vs 255 is not a 2.01× margin. It is a rounding artifact.** 255 is the
**hard structural maximum** of `descriptor.path.name` — an OS basename limit that nothing can
exceed. The discipline was *"clear the hard maximum"*, and 512 is simply the next power of two
above it. **The 2.01× is what fell out; it was never a designed margin.** Transferring the *ratio*
to a row count is a category error — and it is what manufactured the phantom 401.

**What the precedent legitimately transfers is its METHOD:** clear the largest legitimate value,
then round up to a natural boundary. Applied to a row count:

**Step 1 — the largest legitimate value.** Two independent derivations, because the two tables have
different legitimate populations:

- **Modifications.** The operator's stated typical maximum is ~200. Unlike 255 this is **soft** —
  the top of a described range, not a limit. A soft maximum needs a real margin where a hard one
  does not; the smallest non-arbitrary one is **2×**, covering a campaign twice the stated maximum.
  → **400**.
- **Checklist.** The legitimate population is `K × 200`, `K` = check files run over the campaign
  (§11.5). `K = 2` is entirely ordinary. → **400**.

Both land on **400 as the FLOOR** — a value to be **cleared**, not met. `CAP = 400` equals it, so a
401-entry campaign, or two check files over a 205-entry campaign, is still cut. **This is why the
old cap fails even after the floor is corrected: the number was wrong, not just its justification.**

**Step 2 — clear it, and by how much.** The margin over the floor must buy something nameable. It
buys the case the floor cannot cover: `K = 2` check files over campaigns *above* the stated typical
maximum. `CAP = 500` covers `2 × 250`.

## 13.3 — Verification of the coordinator's arithmetic: CONFIRMED, by execution

Probe `p63j.py` re-run across candidate caps at `REPORT_CELL_BYTES = 64`. `guaranteed` is the
worst-case formula; `measured` is the end-to-end document on disk (input 4× the cap on both tables,
1 MiB byte runs, 512-char all-escapable text cells, worst-case remainder sections on):

```
  CAP=400  measured 1,062,844 B = 50.7%   guaranteed 1,352,287 B = 64.5%   slack 744,865 B (35.5%)
           rows mod=400 chk=400   non-hex cells 0/1600   variants: 1.97 worst / 7.19 realistic
  CAP=450  measured 1,171,044 B = 55.8%   guaranteed 1,496,887 B = 71.4%   slack 600,265 B (28.6%)
           rows mod=450 chk=450   non-hex cells 0/1800   variants: 1.79 worst / 6.91 realistic
  CAP=500  measured 1,279,244 B = 61.0%   guaranteed 1,641,487 B = 78.3%   slack 455,665 B (21.7%)
           rows mod=500 chk=500   non-hex cells 0/2000   variants: 1.64 worst / 6.65 realistic
  CAP=512  measured 1,305,212 B = 62.2%   guaranteed 1,676,191 B = 79.9%   slack 420,961 B (20.1%)
           rows mod=512 chk=512   non-hex cells 0/2048   variants: 1.61 worst / 6.59 realistic
```

**`500 × 2 892 + 195 487 = 1 641 487 B = 78.3 %` — confirmed exactly.** 500 clears the corrected
floor of 400 and sits at **76 % of the 657 ceiling**: `400 < 500 < 657`, verified by arithmetic
this time, not asserted.

## 13.4 — "Is 78.3 % uncomfortably close?" — no, and here is the number I defend

**78.3 % is the wrong question.** The budget is whole-document and no `MAX_VARIANTS` exists, so
*any* value above 50 % means two variants breach — the guarantee is single-variant at 400 as much
as at 500. The question that matters is **how much the remainder can grow before the single-variant
guarantee breaks**:

| CAP | slack | slack ÷ current remainder (195 487 B) |
|---:|---:|---:|
| 400 | 744 865 B | **3.81×** |
| 450 | 600 265 B | **3.07×** |
| **500** | **455 665 B** | **2.33×** |
| 512 | 420 961 B | 2.15× |

At 500 a future batch could **more than double** every non-table section — hexdumps, declaration
errors, legend, entropy, addendum, header combined — before the guarantee breaks. That is the
margin I defend, and it is a stronger statement than the percentage.

**Ruling: `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT = MAX_REPORT_CHECK_ROWS_PER_VARIANT = 500`.**

*Why not 512, which is nearly identical (79.9 %, 2.15×)?* Because a power-of-two round-up would be
borrowing the `REPORT_CELL_CHARS` precedent's **shape** immediately after §13.2 argued against
borrowing its **ratio**. The floor derivation is decimal (200 → 2× → 400), so the round-up should
be decimal too. The choice between 500 and 512 is not load-bearing and I record that it is not.

## 13.5 — Every downstream number recomputed

| quantity | REV-3 value (CAP 400) | **REV-4 value (CAP 500)** |
|---|---:|---:|
| guaranteed single-variant bound | 1 352 287 B = 64.5 % | **1 641 487 B = 78.3 %** |
| slack to budget | 744 865 B (35.5 %) | **455 665 B (21.7 %)**, = 2.33× the remainder |
| measured single-variant document | 1 062 844 B = 50.7 % | **1 279 244 B = 61.0 %** |
| BEFORE → AFTER shrink | 15.2× | **13.3×** (BEFORE 16 200 096 B = 7.72× budget) |
| emitted rows at the cap | 400 / 400 | **500 / 500** (checklist across 4 files) |
| byte cells non-hex | 0 of 1 600 | **0 of 2 000** |
| drift set (row caps) | ∅ | **∅** — census max unchanged at **133** |
| drift headroom | 400 / 133 = 3.01× | **500 / 133 = 3.76×** |
| checklist headroom | 400 / 3 = 133× | **500 / 3 = 167×** |
| variant carry, worst | 1.97 | **1.64** |
| variant carry, realistic | 7.19 | **6.65** |
| floor clearance | 400 = floor (**violated**) | **500 = 1.25× floor** |
| position in window | 61 % of ceiling, **below floor** | **76 % of ceiling, above floor** |
| ratio to `MF_ENTRY_COUNT_CEILING` | 250× below | **200× below** |
| `K` covered at full campaign | K = 2 exactly | **K = 2 at campaigns up to 250** |

Drift census re-run at this revision (315 tests, all passing) — unchanged, so ∅ at 500:

```
_modifications_lines  MAX entries in one call : 133
  population histogram : {0: 12, 1: 26, 2: 7, 3: 2, 128: 2, 130: 1, 133: 1}
_checklist_lines      MAX rows per VARIANT    : 3     MAX check results per variant : 2
```

## 13.6 — Literal sweep (C-36)

`grep -n "400"` over the whole artifact, every hit classified:

| class | count | disposition |
|---|---:|---|
| **normative statements** (§2 HLR, §5 LLR-089.1 / LLR-090.1, header banner) | 5 | **updated to 500** |
| **evidence-checklist rows** (§9 rows 3, 13) | 2 | **updated + honestly re-marked** (§13.7) |
| **live carries** (§6 `K ≥ 3` residual, §7 triggers) | 3 | **updated to 500** |
| **historical record** inside §11 / §12 (their own Before → After tables, transcripts, prose) | 24 | **left as written** — they record what was decided at that revision; §13 supersedes them by pointer |
| **genuinely different quantities** (`576,400 B`, `1 048 576`, `4000`, hex addresses, dates) | 6 | untouched, verified not the cap |

**The §3 acceptance blocks contain no literal `400` — and that is not luck.** AT-164 is written as
`cap × 1.5` and AT-167 as `4 check results of ⌈0.75 × cap⌉`, i.e. **parametrically against the
constant**, exactly so a cap change cannot false-fail them. That drafting choice is what kept this
defect out of the acceptance layer, and it is the pattern Phase 3 must preserve: **an AT quotes the
constant, never its value.** Same for the qa catalog's `[PARAM]` block.

## 13.7 — Evidence-checklist rows, re-marked honestly

| row | REV-3 mark | **REV-4 mark** |
|---|---|---|
| 3 — Recommendation tied to constraints | ✓ | **was ✗, now ✓ on corrected numbers.** The REV-3 ✓ was **unearned**: it asserted "both constraints satisfied, neither binding" over a cap one below its own floor. |
| 13 — Drift set executed, not predicted | ✓ | ✓ — held. The drift census was correct at both values (max 133); only the headroom multiple moves, 3.01× → **3.76×**. |
| 12 — Every threshold pre-executed (C-39) | ✓ | **QUALIFIED.** Every threshold *was* executed; what was not executed was the **comparison between two of them**. C-39 as written covers producing numbers, not re-checking a carried number against a moved constraint — the gap §13.1 names. |

## 13.8 — Before → After, and gate

| item | **Before** (REV 3, §12) | **After** (this amendment) | why |
|---|---|---|---|
| floor derivation | 200 × (512/255) = **401**, borrowing the precedent's *ratio* | **400**, from the precedent's *method*: 2× the soft ~200 typical max (modifications) and `K = 2 × 200` (checklist), converging independently | the 2.01× is a rounding artifact of a **hard** 255 max, not a policy; a soft max needs a real margin (§13.2) |
| `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT` | 400 (**below the floor**) | **500** | clears the corrected floor by 1.25×, buying `K = 2` at campaigns above the stated typical max (§13.2 step 2) |
| `MAX_REPORT_CHECK_ROWS_PER_VARIANT` | 400 | **500** | same value, same two-constant rule (§11.5) |
| interiority claim | "interior, neither binding" — **false** | **`400 < 500 < 657`**, verified by arithmetic | §13.3 |
| guaranteed bound | 64.5 % | **78.3 %**, slack **2.33× the remainder** | §13.4 |
| variant carry | ~2.0 worst / ~7.2 realistic | **~1.6 worst / ~6.7 realistic** | §13.5 |
| `REPORT_CELL_BYTES` | 64 | **64 — unchanged** | the ceiling at L=64 is 657 and 500 clears it; §12.2's security ruling is untouched |

**Unchanged:** the shape ruling (§1.2); the refutation that a row cap alone bounds anything (§1.3);
the two-constants rule (§1.5 / §11.5); the option-(b) security ruling and the index-vs-evidence
reframing (§12.2 / §12.3); the truth tables (§4); the increment order (§12.7); every AT/TC id.

**Accepted and NOT softened, per the coordinator:** `CAP` remains **200× below**
`MF_ENTRY_COUNT_CEILING = 100 000` and **can cut legitimate data at the tail**. This ships in the
constant's docstring, and the conclusion it implies — *if campaigns an order of magnitude larger
appear, the answer is a full-fidelity sidecar with the Markdown table as the bounded index, not a
bigger cap* — ships as a BACKLOG carry.

| axis | assessment |
|---|---|
| **Coverage** | **MET.** Unchanged by this amendment; the caps still bound both tables and every cut is stated. |
| **Certainty** | **MET, with a scar.** Every value is now executed *and* every cross-constraint comparison re-run. REV 3's certainty claim was over-stated — the numbers were executed but one comparison between them was not. |
| **Evidence** | **MET.** §13.3–§13.6 transcripts; §9 corrected with the unearned ✓ named as such. |

**Call: `approve`.** No open question. Carries: the variant axis (~1.6 worst / ~6.7 realistic), the
checklist `K ≥ 3` residual, and the sidecar-not-a-bigger-cap conclusion.

**Control candidate earned here (Phase 5, operator AskUserQuestion — never self-encoded):**
*when a constraint is derived, moved, or re-derived, every value already bound by it is
re-evaluated against it in the same edit; a value carried across a revision is re-derived, not
copied.* Instance: this defect. Prior instances of the family: batch-62's predicted drift-set
thresholds (→ C-39), and C-13's reuse-transfer trap (a pattern proven for container A is not
verified for container B) — **C-39 covers producing a number, C-13 covers transferring a pattern;
neither covers re-checking a carried number when its constraint moves.**
