# batch-63 — Requirements (architect lane) — **REV 5**

> **Supersedes `01-requirements-architect.md` REV 4**, which is left untouched on disk so the
> reversal stays traceable. REV 4's mechanism (per-cell and per-row caps) is **withdrawn in full**,
> not patched — see §1.
>
> **Tree:** `claude/batch-63-report-table-caps` @ base `031ca8d`. Every threshold below was
> **EXECUTED** against a `git archive HEAD` export in the session scratchpad (C-39). The worktree
> was never mutated. Probe memory discipline: §12.

---

## 0. BLUF

**Ruled mechanism: the document byte budget is ALLOCATED before emission and enforced by
whole-row admission at each producer.** Three rules, in the order they matter:

| # | rule | what it fixes |
|---|---|---|
| **R1 — ACCOUNT** | charge what is actually *written* | `_ByteBudget` undercounts the on-disk file by `(lines−1)` bytes on Windows. **New finding, no lane found it.** Enforcing an undercounting meter is worse than not enforcing. |
| **R2 — ALLOCATE** | reserves → per-variant fair share with roll-forward → floors for *later* sections | objections (a) starvation-by-document-order and (b) no per-variant fairness |
| **R3 — ADMIT** | whole rows, by **analytic** cost, **at the producer** | a row that will not be emitted is never formatted (F5) and a population that will not be emitted is never materialised (a 559 GB memory path, also new) |

**Measured result: the declared bound now holds.** Worst case over the whole adversarial matrix —
20 000 variants × 1 000 hostile entries × 1 000 failing checks × 64 declared regions, 512-char
variant ids, 256-byte runs, `"|"×512` symbols — is **2 092 476 B = 0.998×** the 2 097 152 B budget.
On the same fixtures the shipped composer reads **8 762 013 B (4.18×)**, and at one variant
**13 087 512 B (6.24×)**. The negative control fires: the measurement reports `OVER` on 9 of 13
shipped runs, so an `ok` is evidence rather than blindness.

**What is NOT closed** (§8, with numbers): the `_modified_files_lines` path axis is a **twelfth**
unbounded axis that no lane identified and that this artifact's own prototype does not bound; the
addendum's candidate *scan* is O(regions × variants × entries) and bounding output does not bound
traversal; and the worst case sits at 0.998×, which is correct but has only 4 676 B of margin —
§6.2 rules a headroom constant rather than shipping on that.

---

## 1. §Before → After — the pivot, and its cause

### Before (REV 4, Phase-2 BLOCKED in all three lanes, 11 blockers)

> Bound the two per-variant tables with `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT = 500`,
> `MAX_REPORT_CHECK_ROWS_PER_VARIANT = 500` and a per-cell byte prefix
> `REPORT_CELL_BYTES = 64`; declare a "guaranteed single-variant bound = 78.3 % of budget".

### After (REV 5)

> Enforce the whole-document byte budget that already exists, allocated per variant and per section
> class, by admitting or rejecting **whole rows** on an analytically-computed cost. No cell is ever
> truncated. No fixed row cap exists.

### Cause of the reversal — recorded, not summarised away

**Capping cells is whack-a-mole against an unbounded document.** Every review round discovered a new
unbounded axis; six were known at the gate, and this artifact adds a seventh (`_modified_files_lines`)
and an eighth (the CRLF accounting gap, which is an axis on *every* line the document emits). The
capped design **still asserted a false bound**: at 2 variants, 2 918 330 B = 1.39× budget with the
size-cap marker firing (`02-review-security.md` F2).

Three REV-4 positions are withdrawn **by name**, because each was load-bearing:

| withdrawn | why | replaced by |
|---|---|---|
| **D-16 — "the tables are an INDEX, `_hexdump_section` is the EVIDENCE"** | **FALSE for 3 of 4 bounded cells**, measured: `applied.after_bytes` 200/200 recoverable · `applied.before_bytes` **0/200** · `skipped.after_bytes` **0** · `check.expected_bytes` **0**. It was the *sole* anchor for the value 64. | Nothing. The premise is not repaired — the mechanism that needed it is gone. **Under REV 5 no byte cell is ever truncated**, so there is no evidentiary claim to make and no fallback to point at. LLR-091.3's "…full bytes in the Memory regions section" is **deleted**, never reworded. |
| **the fixed row caps (500/500)** | a row cap cannot bound bytes: per-row cost spreads 4.24× (139→590 B) in the modifications table alone, and one row can weigh 3.00× the entire budget | analytic per-row cost + admission against an allocated allowance |
| **the per-cell byte prefix (64)** | it bounded 4 of the ~10 elastic cells and deleted evidence in 3 of them | whole-row admission: a row is emitted **complete** or omitted **and counted** |

**What survives the reversal, carried forward unchanged:** the **D-15 option-(b) ruling** — any
truncation indicator stays **OUTSIDE** the byte cell, because `_format_bytes`'s closed alphabet is
what makes R-TUI-077's escaping exclusion sound (verified across 19 input classes by the security
lane; called "the strongest passage in the artifact" by the architect lane). REV 5 **strengthens**
it: there is no in-cell indicator because there is no in-cell truncation. `_format_bytes`'s signature
and body are **untouched by this batch**.

---

## 2. Constraints

| constraint | value | source |
|---|---|---|
| declared document bound | `REPORT_MAX_TOTAL_BYTES = 2 097 152` | `report_service.py:122` |
| entry-count domain | `MF_ENTRY_COUNT_CEILING = 100 000` | `changes/io.py:226` |
| run-length domain | `MF_RUN_LENGTH_CEILING = 1 048 576` | `changes/io.py:232` |
| Mode-A cell cap | `REPORT_CELL_CHARS = 512` | `report_service.py:115` |
| variant count | **unbounded** — no `MAX_VARIANTS` anywhere | grep, re-verified |
| declared-region count | **unbounded** — only `DECLARED_REGION_NAME_MAX = 80` | `report_addendum.py:26` |
| address value | **unbounded** — `_ADDRESS_RE = ^0x[0-9A-Fa-f]+$` | `changes/io.py:235` |
| change-summary count / path length | **unbounded** / OS-bounded, **never truncated** (Mode B, deliberate) | `markdown_safety.py:255-299` |
| frozen files | `_ENGINE_PATHS` — **no intersection** with the touched set | `tests/test_engine_unchanged.py` |
| merge gate | `pytest -q -m "not slow"` on PRs | `.github/workflows/tui-ci.yml:47` — **no new node may be `slow`** |
| team / increment | ≤5 files per increment | global working method |

---

## 3. Measured basis — the findings REV 5 is built on

Every figure here was executed. Probe transcripts: §12.

### 3.1 NEW — `_ByteBudget` undercounts the written file (blocker-class; no lane found it)

The pivot's stated premise is *"the budget is accounted and never enforced; the missing half is the
check."* **That premise is false.** The accounting half is also wrong.

```
  case                                       file B  budget.used    delta
  1 variant, empty                            2,435        2,366      -69
  1 variant, 200 mods                        27,800       27,530     -270
  1 variant, 200 mods + 200 chks             36,513       36,038     -475
  3 variants, 500 mods + 500 chks           258,513      255,370   -3,143
```

The delta is **negative and grows with content** — bytes escape accounting. Cause, isolated by
predicate (`p4_crlf.py`), with the LF model driven to fail first:

```
os.linesep = '\r\n'   platform newline width = 2
  case                                file B  LF model  CRLF model   lines
  1 variant, empty                     2,435     2,365       2,435      71
  1 variant, 200 mods                 27,800    27,529      27,800     272
  3 variants, 500+500                258,513   255,369     258,513   3,145
```

`_line_bytes` charges **1** byte per line ending; `Path.write_text(..., encoding="utf-8")` opens in
**text mode**, so Windows writes **2**. The CRLF model matches the file to the byte in all three
cases; the LF model is short by exactly `lines − 1`.

**Materiality — this is not a rounding error.** It is a per-line multiplier, so it is worst exactly
where the document is most line-dense. During this artifact's own derivation, a composition that the
allocator had held to **2 051 520 B (0.978×)** measured **2 202 442 B (1.050×) OVER** on disk purely
because one probe still wrote CRLF. *The accounting gap alone breaks the bound in the
variant-dense regime.* Worst case in principle: a document of empty lines is charged 1 B/line and
occupies 2 B/line → **2.00×**.

**Ruling: pin the writer** (`newline="\n"`), not the meter. Two reasons, both verified:
1. An evidentiary artifact whose byte size depends on the host OS is itself a defect.
2. **It is golden-neutral.** `tests/conftest.py::canonical_report_bytes` already undoes CRLF→LF as
   the first step of the byte-identity canonical form (`:975-990`). Existing goldens compare in that
   canonical form, so pinning the writer changes **no** compared byte.

### 3.2 The analytic row-cost model is exact (the ruling's foundation)

R3 requires cost be known **before** the row is built. Predicate `cost(row) == len(rendered.encode())+1`,
**driven to fail on a known-bad model first** (`analytic+1` disagrees — the predicate is falsifiable):

```
  case                                          analytic  rendered  ok
  run_len=0 / 1 / 2 / 4 / 64 / 256 / 1000        exact on all 7      YES
  before=None (non-applied)                          211       211  YES
  symbol=1 / 63 / 512 / 4096 chars                exact on all 4     YES
  symbol=512x'|' (2x escape growth)                1,090     1,090  YES
  symbol=300x U+00E9 (2-byte UTF-8)                  654       654  YES
  address = 0x + 1e6 hex digits (sec F3)       1,000,116 1,000,116  YES
  ALL AGREE: True          (checklist row: 10/10 cases, ALL AGREE: True)
```

Exact across escape growth, multi-byte UTF-8, `None` runs, and the unbounded address. The two
width primitives are O(1) and never format the value:

```
  hex_digits(n) = 8 if n==0 else max(8, (n.bit_length()+3)//4)
    0x0 / 0x1 / 0xf / 0xff / 0xffffffff / 0x100000000 / 2^64-1 / 2^64
    / 2^4000-ish / 2^400000-ish    ->  ALL AGREE: True   (mutation control passed)
```

### 3.3 NEW — a schema-legal address **crashes** report generation

`sys.get_int_max_str_digits() = 4300`. `_modifications_lines:996` renders
`f"| {entry.address_end - entry.address_start} "` — a **decimal** conversion. An address literal of
100 000 hex digits (legal per `_ADDRESS_RE`) makes that raise:

```
  RAISES ValueError: Exceeds the limit (4300 digits) for integer string conversion
```

Today this is an **availability** defect, not a size defect: one crafted change document makes the
report un-generatable. Security's F3 measured the same input as a 0.48×-budget row; it is worse than
that. Under REV 5 the same input renders a 2 454 B document with the row omitted and counted (§7 A5).

### 3.4 NEW — the addendum is a **memory** exhaustion, not a large document

`_addendum_lines` (`report_service.py:1513-1537`) builds `hits: List[str]` — one **formatted** string
per (region × variant × entry) hit — **before emitting anything**. Measured small, extrapolated
analytically (building the declared-domain case *is* the crash):

```
  shipped _addendum_lines: R=4 V=10 N=5,000
    hit lines materialised = 200,000
    peak traced memory     = 17,491,135 B  (87.5 B/hit)
    wall time              = 2,405.9 ms

  declared domain R=64 V=1,000 N=100,000 -> 6,400,000,000 hit lines
    projected peak memory  = 559.7 GB
    projected wall time    = 1,283 min
```

**No output-size cap can reach this**, because the allocation happens before any output exists.
It is the reason R3 says *admission at the producer*, not *admission after collection*. This probe
is also why §12's memory discipline is not ceremony — an unbounded version of it is what crashed a
prior run of this task.

### 3.5 NEW — a twelfth unbounded axis: `_modified_files_lines`

One bullet per change summary; the path renders through `md_code`, which **truncates nothing by
design** (`markdown_safety.py:255-299` — a cap would make goldens machine-dependent, CN-6).

```
    1 summaries x     20-char path             107 B   0.000x
    1 summaries x 32,000-char path          64,067 B   0.031x
   10 summaries x 32,000-char path         640,481 B   0.305x
   64 summaries x 32,000-char path       4,098,965 B   1.955x   <-- one section, one variant
```

**This axis argues FOR the ruling.** A cell cap cannot be used here without breaking `md_code`'s
contract. Whole-**row** admission bounds it while leaving every emitted path byte-exact.

### 3.6 The full elastic inventory — 12 axes, stated once

| # | emitter | elastic in | bounded today |
|---|---|---|---|
| 1 | `_inventory_lines` | variant count | ✗ |
| 2 | `_overview_lines` | variant count | ✗ |
| 3 | the variant loop | variant count | ✗ |
| 4 | `_modified_files_lines` | summary count × path length | ✗ **(§3.5, new)** |
| 5 | `_modifications_lines` | entry count | ✗ |
| 6 | ” | byte-run length | ✗ |
| 7 | ” | address width | ✗ **(sec F3 + §3.3)** |
| 8 | `_declaration_error_lines` | `related_artifacts` length | ✗ (row count capped at 200) |
| 9 | `_checklist_lines` | check count × entry count | ✗ |
| 10 | `_addendum_lines` | regions × variants × entries | ✗ **(§3.4, memory)** |
| 11 | the truncation appendix | notes count | ✗ |
| 12 | **every line** | `len(os.linesep)` | ✗ **(§3.1, new)** |
| — | `_hexdump_section` | regions | ✓ (the only one) |
| — | `_entropy_lines` | O(bands) | ✓ by construction |

**A design that enumerates fewer than 12 axes is the REV-4 mistake repeating.**

---

## 4. Candidate designs, compared

| # | design | bound holds? | evidence loss | enforcement cost | reversibility | verdict |
|---|---|---|---|---|---|---|
| **A** | **allocated budget + analytic whole-row admission** | **YES, measured 0.998× worst** | rows omitted **whole + counted**; no cell truncated | O(1) per rejected row, flat in run length | additive; constants tunable | **RULED** |
| B | two-pass: build everything, measure, re-emit truncated | yes in principle | same | **DISQUALIFIED** — pass 1 materialises the unbounded document; §3.4 measures that path at 559.7 GB. *The enforcement would be the DoS.* | — | rejected |
| C | proportional allocation by measured demand | yes | same | requires B's pass 1 | — | rejected (same disqualifier) |
| D | REV 4: per-cell + per-row caps | **NO** — 1.39× at 2 variants with the marker firing | deletes bytes recoverable nowhere else, in 3 of 4 cells | 155.91 ms + 3 MB transient per cell if read naively | — | withdrawn |
| E | partial: enforce on the 3 measured emitters, reword the marker to scope its claim | no — bound stays false | same | low | high | **fallback**, §11.3 |

**Why A over E.** E is ~40 % of A's cost and leaves 8 axes open; it is honest only if the marker's
claim is narrowed to the hexdump blocks it governs. It remains on the table as the scope-capped
fallback, and §11.3 states exactly what its declared bound would have to say. **A is ruled because
the batch's thesis is that a document must not assert what it does not honour** — E discharges the
thesis by weakening the assertion, A by strengthening the mechanism, and the operator's pivot ruling
asked for the mechanism.

**Objections (a) and (b) from the pivot brief, resolved by construction:**

- **(a) tables precede hexdumps in document order, so a naive cut starves the hexdumps.** Resolved by
  **floors for later classes, not shares**: an earlier class may consume everything *above the sum of
  the floors reserved for classes emitted after it*. This maximises utilisation (a variant with 3
  rows wastes nothing) while making starvation structurally impossible. Measured: at 5 000 mods +
  5 000 checks the ruled mechanism emits **856 318 B with 0 cuts** — matching the shipped
  856 517 B — while an earlier fixed-share draft cut 500 rows unnecessarily at the same input.
- **(b) no per-variant fairness — variant 1 eats the allowance.** Resolved by
  `E_i = remaining_pool / remaining_variants`, evaluated **at the moment variant `i` starts**. Unused
  share rolls forward; no variant can be starved by an earlier one; `Σ ≤ pool` by induction.

---

## 5. §2 — High-level requirements (normative; `shall` appears here and in §10 only)

**Id space verified on disk, excluding this batch's own superseded reservations:**
`R-TUI` max = **R-TUI-088** · `AT` max = **AT-163** (batch-62) · `TC` max = **TC-398**.
`R-TUI-079/080/081` are **batch-48's** (`.dev-flow/2026-07-16-batch-48/01-requirements.md:272,291,307`)
and are **not** used here.

### R-TUI-089 — the declared document bound is ENFORCED
*Traces to: US-B63-1.*
The report generator **shall** produce a document whose on-disk size does not exceed
`REPORT_MAX_TOTAL_BYTES`, for every input inside the declared domain — any entry count up to
`MF_ENTRY_COUNT_CEILING`, any variant count, any declared-region count, any run length up to
`MF_RUN_LENGTH_CEILING`, and any address value. The generator **shall** account each emitted line at
the byte width it is written with, and **shall** write the document with a pinned newline so that
width is platform-independent.

### R-TUI-090 — allocation before emission
*Traces to: US-B63-1.*
The generator **shall** allocate the budget before emitting elastic content: a reserve for the
truncation appendix and the declared-region addendum, a per-variant share computed as the remaining
pool divided by the number of variants not yet rendered, and, within a variant, a floor for every
section class emitted **later** in document order. A section class **shall not** consume any part of
a floor reserved for a class emitted after it.

### R-TUI-091 — whole-row admission on analytic cost
*Traces to: US-B63-1, US-B63-3.*
Every elastic row population **shall** be emitted through admission: a row **shall** be emitted
complete or omitted entirely, and the decision **shall** be taken on a cost computed from the row's
source values without formatting the row. No byte cell, address cell, path cell or text cell
**shall** be truncated by this batch. A row whose cost cannot be represented — an address or length
requiring more than `REPORT_ADDRESS_BITS_MAX` bits — **shall** be omitted and counted, never
rendered and never allowed to raise.

### R-TUI-092 — every cut is legible, and the appendix is the oracle
*Traces to: US-B63-2.*
Every omission **shall** be stated in the document at the site of the cut, with the exact omitted
count, the exact pre-cut total, and the named cause, **and shall** register a corresponding entry in
the truncation appendix. The `## Truncation appendix` heading **shall** be emitted on every report,
carrying an explicit statement that nothing was omitted when nothing was — so its absence is never
the signal. The appendix **shall** be allocated its own reserve and **shall not** be the population
that a cut falls on; when its own reserve is exhausted it **shall** state the number of further cuts
not listed. Every file-derived value in an appendix entry **shall** be emitted inside a code span so
the entry's fixed prose cannot be forged by the value.

### R-TUI-093 — enforcement is streaming
*Traces to: US-B63-1.*
No emitter **shall** materialise its full row population, or any formatted row it will not emit,
before admission. The work an emitter performs for a rejected row **shall** be independent of that
row's byte-run length and of the size of the population behind it.

### R-TUI-094 — evidentiary ordering and byte-identity
*Traces to: US-B63-3.*
When a checklist or modifications population is cut, rows carrying a finding — a `fail` or
`uncheckable` check result, or any non-`applied` disposition — **shall** be admitted before rows that
carry none, and the admitted rows **shall** be emitted in document order. The marker **shall** state
the selection rule. When no cut fires anywhere in the document, the document **shall** be
byte-identical, in the `canonical_report_bytes` form, to the pre-batch output.

---

## 6. Constants — every value derived by execution

### 6.1 The constant set

| constant | value | derivation (all executed) |
|---|---|---|
| `REPORT_NEWLINE` | `"\n"` | §3.1. Makes the shipped `+1` charge exact on every platform; golden-neutral (`canonical_report_bytes` already undoes CRLF). |
| `REPORT_BUDGET_HEADROOM` | `32 768` | §6.2 — measured worst case leaves **4 676 B**; 32 KiB is 7.0× that. |
| `REPORT_MIN_VARIANT_ENVELOPE` | `4 096` | §6.3 |
| `REPORT_HEXDUMP_FLOOR` | `0.40` | §6.4 |
| `REPORT_CHECKLIST_FLOOR` | `0.15` | §6.4 |
| `REPORT_DECL_ERROR_FLOOR` | `0.03` | §6.4 |
| `REPORT_ENTROPY_FLOOR` | `0.02` | §6.4 |
| `REPORT_APPENDIX_RESERVE` | `0.02` | §6.5 |
| `REPORT_ADDENDUM_RESERVE` | `0.10` | §6.5 |
| `REPORT_INVENTORY_RESERVE` | `0.05` | §6.5 |
| `REPORT_ADDRESS_BITS_MAX` | `64` | §6.6 |
| `REPORT_ADDENDUM_SCAN_MAX` | `100 000` | §6.7 |

**No constant in REV 4 survives.** `MAX_REPORT_*_ROWS_PER_VARIANT` and `REPORT_CELL_BYTES` are not
introduced; `REPORT_CELL_CHARS`, `REPORT_MAX_REGIONS_PER_VARIANT`, `MAX_REPORT_ISSUES_PER_VARIANT`
and `REPORT_MAX_TOTAL_BYTES` are unchanged.

### 6.2 `REPORT_BUDGET_HEADROOM = 32 768` — and why the bound is not shipped at 0.998×

Adversarial matrix, every axis hostile at once, document written with the ruled writer and measured
with `os.stat`:

```
   variants         size  x budget  rendered   notes  appendix?
          1    1,278,605     0.610         1       4   complete
         10    1,822,825     0.869        10      22   complete
        100    1,989,657     0.949       100     202   complete
      1,000    2,056,914     0.981     1,000   1,238   overflow
      5,000    2,092,470     0.998     1,715   1,719   overflow
     20,000    2,092,476     0.998     1,715   1,719   overflow

  worst observed = 2,092,476 B = 0.998x budget    headroom = 4,676 B
```

The bound **holds at every variant count**, and the size **plateaus** once the variant axis
saturates — 20 000 variants costs the same as 5 000. But 4 676 B of margin is not an engineering
margin; it is the absence of one. `REPORT_BUDGET_HEADROOM` makes the allocator target
`REPORT_MAX_TOTAL_BYTES − 32 768` so the declared bound has demonstrable slack. **This is a
derived constraint, not a preference:** without it, any future emitter added to the document breaches
the bound on its first hostile input, and the batch's whole thesis is that a declared bound must
survive the next change.

### 6.3 `REPORT_MIN_VARIANT_ENVELOPE = 4 096`

Structural cost per variant, executed, perfectly linear and predicted to **±0 B** at n=128 and
n=1024:

```
  fixed (document chrome)  = 2,013 B
  per EMPTY variant        =   434 B   (5-char variant_id)
  MEASURED n=  128 =  57,565 B   predicted  57,565 B   err +0 B
  MEASURED n= 1024 = 446,429 B   predicted 446,429 B   err +0 B
  n_break = 4,827 empty variants  <- above this NO scheme fits one line per variant
```

A 512-char (hostile) variant id raises the per-variant structural cost ≈2.5× — measured indirectly:
at the same pool, 5-char ids render **5 694** variants and 512-char ids render **2 316**.

Without a floor, fair-share degenerates: at 20 000 variants each share is 97 B against a ~300 B
skeleton, so **zero** variants render — a bound satisfied by emitting nothing. `4 096` grants each
rendered variant ~3 KB of elastic content (~25 modification rows), so the document renders **fewer
variants with real content** and states how many it omitted. **This is a product ruling, stated
rather than defaulted:** 1 715 substantive variant sections beat 5 694 empty skeletons.

### 6.4 The floor vector — `0.40 / 0.15 / 0.03 / 0.02`

Floors are ordered by document position: `_hexdump_section` is emitted **last** among the elastic
classes and carries the highest forensic value, so it gets the largest floor. The residual
`1 − 0.40 − 0.15 − 0.03 − 0.02 = 0.40` is what the modifications table may consume.

Executed check that the floors do not over-cut a legitimate document:

```
  A2 1 variant x 1000 mods + 1000 checks   shipped=  172,517 B    rev5= 170,318 B  cuts=0
  A2 1 variant x 5000 mods + 5000 checks   shipped=  856,517 B    rev5= 846,318 B  cuts=0
```

**Zero cuts at 5 000 entries in both tables** — the realistic ceiling is far inside the floors. The
field datum from the Phase-1 operator question ("tens to ~200 entries") sits 25× under that.

### 6.5 Document reserves — `0.02 / 0.10 / 0.05`

The appendix reserve is a **fixed fraction, not a function of variant count** — REV 4's mistake one
level up. An early draft sized it as `96 × min(n,4096) × 3`, which consumed 1.18 MB of a 2.10 MB
budget and left the pool so small that **zero** variants rendered. Recorded because it is the same
failure mode as the design being replaced: a reserve that scales with the thing it is reserving
against.

### 6.6 `REPORT_ADDRESS_BITS_MAX = 64`

Closes security **F3** and §3.3 together, at the **report** layer rather than the parse layer. The
parse-layer fix (rejecting `raw_address >= 2**64` in `changes/io.py`) is cheaper but changes document
acceptance semantics — a one-way door for anyone holding such a document. The report-layer rule is
reversible, keeps `changes/io.py` untouched, and produces a *legible* outcome: the row is omitted,
counted, and attributed. `2**64` is generous — S19/HEX images are ≤32-bit — and matches the shape of
`MF_RUN_LENGTH_CEILING`.

### 6.7 `REPORT_ADDENDUM_SCAN_MAX = 100 000`

Bounding **output** does not bound **traversal**. The addendum's exact omitted count requires an
O(regions × variants × entries) scan — 6.4 × 10⁹ candidates in the declared domain (§3.4). Past
`100 000` candidates the marker states `≥ K of N+` with the cause `scan bounded at 100 000`, rather
than the report hanging. **This is the one place REV 5 knowingly emits an inexact count**, and it
says so in the document rather than rounding it into a clean-looking number.

---

## 7. §3 — Acceptance (black-box, first-class)

Every AT observes `generate_project_report` → the written `.md` **re-read from disk**. Ids start at
**AT-164** (max on disk = AT-163, batch-62). No node is `@pytest.mark.slow` (qa M-5: the PR gate
deselects `slow`).

### US-B63-1 — the report never exceeds its declared size

> **As** an engineer archiving a project report as an evidentiary record, **I want** the document to
> honour the size it declares for any input the tools accept, **so that** the truncation notice is
> proof the bound held rather than proof it did not.
>
> *(Subsumes REV 4's US-B63-1 and US-B63-2, which scoped the goal to two tables.)*

**AT-164 — the bound holds under the adversarial matrix.**
*Given* a project of `V ∈ {1, 10, 100, 1000}` variants, each carrying 1 000 change entries with
256-byte runs and `"|"×512` symbols, 1 000 failing check entries, a 512-char variant id, and 64
declared regions, *when* a report is generated, *then* the file on disk is `<= REPORT_MAX_TOTAL_BYTES`
for every `V`, and the measured size and its multiple of the budget are printed in the failure
message. **Fixture is provably over**: the same fixture through the pre-batch composer measures
`>= 2×` budget at `V = 1` — asserted in the same test, so a fixture that drifts under the cut fails
loudly (C-31).

**AT-165 — one entry at the run-length ceiling.**
*Given* a single change entry whose `after_bytes` is `MF_RUN_LENGTH_CEILING` bytes, *then* the
document is `<= REPORT_MAX_TOTAL_BYTES`, the row is absent, and the Modifications section states
`1 of 1 ... omitted`. *(Pre-batch: 3 148 355 B = 1.50×.)*

**AT-166 — an unbounded address does not crash and does not bloat.**
*Given* one entry whose `address_start` is `0x` + 1 000 000 hex digits, and a second whose
`address_end − address_start` exceeds `sys.get_int_max_str_digits()`, *then* report generation
completes without raising, the document is `<= REPORT_MAX_TOTAL_BYTES`, and both rows are stated as
omitted with the representable-range cause. *(Pre-batch: 1 002 623 B, and `ValueError` respectively.)*

**AT-167 — the variant axis saturates rather than breaching.**
*Given* 20 000 variants, *then* the document is `<= REPORT_MAX_TOTAL_BYTES`, at least one variant is
rendered with content, and the document states `K of 20000 variants omitted`. *(Pre-batch:
8 762 013 B = 4.18×.)*

**AT-168 — the accounting matches the artifact.**
*Given* any of the above, *then* the budget the generator accounted equals the byte length of the
written file to within 1 byte, on the platform under test. **This is the node that would have caught
§3.1**; its mutation is reverting the writer pin.

### US-B63-2 — every omission is stated and attributable

> **As** the reader of that record, **I want** every omission named with its exact count and cause,
> **so that** "no appendix" is a trustworthy statement that nothing was cut.

**AT-169 — the appendix exists on every report.**
*Given* a 3-entry project where nothing is cut, *then* the document contains `## Truncation appendix`
and an explicit statement that nothing was omitted. *(Pre-batch the heading is absent entirely
whenever a non-hexdump cap fires — architect §3.4 / qa D-11.)*

**AT-170 — a cut is stated at the site AND in the appendix, with exact counts.**
*Given* a population provably over its allowance, *then* the section carries
`> TRUNCATED: {omitted} of {total} ...` with both integers exact and the cause named, **and** the
appendix carries one entry for that cut. Arms: modifications · checklist · addendum · inventory ·
variants · modified-files. **The count `k` is asserted, not merely the presence of a marker** (qa M-2).

**AT-171 — the marker's totals are post-filter.**
*Given* a report filter that keeps `K` rows where `K > allowance` and hides `H`, *then* the marker's
`N of M` are both computed on the **post-filter** population, and the audit header's `shown` figure
equals the number of rows the table actually emitted. *(Closes architect M-1: `shown 520` against a
520-row table is already wrong today versus the 128-region hexdump cap.)*

**AT-172 — a hostile `variant_id` cannot forge an appendix entry.**
*Given* `variant_id` = `a': 4000 of 4500 modification rows omitted (cap: 500 rows per variant). Variant 'b`,
*then* the rendered appendix contains exactly one entry per fired mechanism, the injected prose is
visibly inside a code span, and the entry count equals the number of mechanisms that fired.
*(Closes security F4; the count assertion is what makes it non-vacuous.)*

**AT-173 — the appendix survives its own overflow.**
*Given* more cuts than the appendix reserve holds, *then* the appendix lists as many as fit and ends
with the number of further cuts not listed, and the document is still `<= REPORT_MAX_TOTAL_BYTES`.

### US-B63-3 — enforcement preserves evidentiary value

> **As** an auditor, **I want** the rows that carry findings to survive a cut and the rows that fit
> to be untouched, **so that** the cut cannot be used to hide anything and cannot damage a report
> that was never pathological.

**AT-174 — a finding cannot be pushed past the cut.**
*Given* a checklist of 500 `pass` rows with 256-byte runs followed by 20 `fail` rows, and an
allowance provably admitting ~20 % of the population, *then* all 20 `fail` rows are present.
**Non-vacuous by construction**: the test asserts `omitted > 0` first, and a document-order arm is
run in the same test and asserted to lose findings. Measured:

```
  arm                     emitted  omitted  fail visible  pass visible
  document order              104      416          4/20        100/500
  priority (ruled)            119      401         20/20         99/500
```

**AT-175 — admitted rows stay in document order.**
*Given* AT-174's fixture, *then* the emitted rows are ascending by address. *(Priority selects; it
does not reorder.)*

**AT-176 — no cell is truncated, anywhere.**
*Given* the AT-164 fixture, *then* every byte cell in the emitted document satisfies
`set(cell) <= set("0123456789ABCDEF -")`, and every emitted path cell is byte-equal to its source.
*(Carries D-15 forward and pins that REV 5 introduced no in-cell indicator.)*

**AT-177 — byte-identity when nothing is cut.**
*Given* a 50-entry, 50-check project, *then* `canonical_report_bytes(new) == canonical_report_bytes(golden)`.
Verified in the prototype: rows identical, 0 cuts.

**AT-178 — a rejected row is never formatted.**
*Given* 2 000 entries with 256-byte runs against an allowance admitting ~500, *then* the number of
`_format_bytes` invocations equals `2 ×` the number of emitted rows. **This is the observation the
security lane said no output assertion could make** — see §9.

---

## 8. What remains unbounded — the BACKLOG carry, with numbers

Stated because §3.1's whole lesson is that unstated residuals are what make markers lie.

| # | residual | measured | severity | disposition |
|---|---|---|---|---|
| **RES-1** | **`_modified_files_lines` is not admission-controlled in the prototype this artifact measured.** 64 summaries × 32 000-char paths = **4 098 965 B = 1.955×** budget from one section of one variant. | §3.5 | **MAJOR** | **IN SCOPE** — R-TUI-091 covers it and Inc-4 wires it. **But every figure in §6.2 was measured without it**, so the 0.998× worst case is *conditional on that axis being idle*. Re-measure at Inc-4 before the bound is declared. |
| **RES-2** | The addendum's candidate **scan** is O(R×V×E) — 6.4×10⁹ in the declared domain. Bounded by `REPORT_ADDENDUM_SCAN_MAX`, so the omitted count becomes `≥ K` past 100 000 candidates. | §3.4 / §6.7 | MAJOR | **Accepted and stated in the document.** The alternative — an exact count — is a 1 283-minute scan. |
| **RES-3** | Admission cost is **13 µs/row** even for rejected rows, dominated by `md_safe` on the symbol and linkage cells inside the cost function. At 100 000 entries that is ~1.3 s per table. | §9 A | MINOR | **Fixable in Inc-3**: the cost function should use an *upper bound* on the escaped width (`2 × min(len, REPORT_CELL_CHARS) + markers`) and escape only on admission. A conservative over-estimate never over-admits. Not blocking. |
| **RES-4** | `ValidationIssue.related_artifacts` is an unbounded `list[str]`; cap × 50 related = **5 442 506 B = 259.5 %**. No live producer exceeds 3 elements. | architect m-1 | MINOR | Covered by R-TUI-091 once declaration errors are row-admitted (Inc-4). |
| **RES-5** | Host-path exposure via `md_code(source_path)` — absolute operator paths in an exported document. | batch-62 D-11 | MAJOR | **UNCHANGED, carried.** Withdrawn at the batch-62 merge gate; needs a known-roots substitution design, not shape inference. |
| **RES-6** | The parse layer still accepts unbounded addresses; REV 5 bounds only their *rendering*. | sec F3(a) | MINOR | Deliberate — §6.6. A parse-layer ceiling is a one-way door on document acceptance. |

---

## 9. Enforcement cost — requirement 4, and how a TC pins it

The security lane measured format-then-slice at **155.91 ms / 3 MB transient** per cell versus
**0.02 ms / 192 B** for `islice`, **with identical output** — so no output assertion distinguishes
them. REV 5's shape is stronger than `islice` (it never formats a rejected row at all), and it is
pinned by two deterministic, non-timing observations.

```
A. 5 000 entries @256-byte runs, allowance 100 000 B
     admit (analytic cost; format only the 60 admitted)      65.59 ms
     format ALL 5 000 then slice                            445.02 ms   (8,258,890 B materialised)
     ratio = 6.8x        omitted = 4,940  (a cut MUST have fired: yes)

B. rejection cost vs run length
     run_len=     2  ->  12.05 us/row
     run_len=   256  ->  14.62 us/row
     run_len= 4,096  ->  13.96 us/row
     run_len=65,536  ->  12.12 us/row      -> FLAT in L: the run is never walked
```

**TC-401 (the F5 pin) — call-count, not timing.** Spy on `_format_bytes`; assert
`calls == 2 × emitted_rows`. Executed on the prototype:

```
  entries offered      = 2000
  rows EMITTED         = 497
  _format_bytes calls  = 994  (2 per emitted row = 994)
  rejected rows formatted? NO
  a format-then-slice implementation would call it 4000 times -- distinguishable.
```

**TC-402 (the R-TUI-093 pin) — flatness.** Assert the rejection path's `_format_bytes` call count is
**zero** across `run_len ∈ {2, 65536}`; a build-then-measure implementation calls it once per row at
both. Deterministic, no wall-clock assertion, so it cannot flake on a loaded CI box.

---

## 10. §5 — Low-level requirements (each declares touched symbols and traces — C-26)

**LLR-089.1** — `generate_project_report` **shall** write the document with `newline="\n"`.
*Touched symbols:* `generate_project_report`. *Traces to:* R-TUI-089, §3.1, AT-168.

**LLR-089.2** — `_line_bytes` **shall** document that its `+1` charge is exact only under
LLR-089.1's pinned writer, and a test **shall** assert the identity against a written file.
*Touched symbols:* `_line_bytes`. *Traces to:* R-TUI-089, AT-168.

**LLR-090.1** — a new `_Allocation` type **shall** expose `left` / `fits` / `take` and **shall** be
the only way an allowance is spent. *Touched symbols:* `_Allocation` (new), `_ByteBudget`.
*Traces to:* R-TUI-090.

**LLR-090.2** — `generate_project_report` **shall** compute reserves, then
`share_i = remaining_pool // remaining_variants` bounded below by `REPORT_MIN_VARIANT_ENVELOPE`,
and **shall** stop rendering variants when the pool cannot fund that floor.
*Touched symbols:* `generate_project_report`. *Traces to:* R-TUI-090, AT-167.

**LLR-090.3** — within a variant, each elastic class's allowance **shall** be
`envelope_left − Σ(floors of classes emitted later)`. *Touched symbols:* `generate_project_report`.
*Traces to:* R-TUI-090, §6.4.

**LLR-091.1** — a new `_admit(rows, cost_fn, fmt_fn, allocation, priority_fn=None)` **shall** return
`(lines, omitted_count)`, **shall** call `fmt_fn` only for admitted rows, and **shall** emit admitted
rows in source order regardless of `priority_fn`. *Touched symbols:* `_admit` (new).
*Traces to:* R-TUI-091, R-TUI-093, R-TUI-094, AT-175, AT-178, TC-401.

**LLR-091.2** — `_modification_row_cost` / `_checklist_row_cost` **shall** compute width from
`len()`, `int.bit_length()` and the escaped text width, and **shall not** format the row. They
**shall** return a value greater than any allowance when `address_start`, `address_end` or
`address_end − address_start` exceeds `REPORT_ADDRESS_BITS_MAX` bits.
*Touched symbols:* `_modification_row_cost` (new), `_checklist_row_cost` (new).
*Traces to:* R-TUI-091, AT-166, §3.2, §3.3.

**LLR-091.3** — `_modifications_lines` and `_checklist_lines` **shall** emit through `_admit`.
`_format_bytes` **shall not** be modified by this batch. *Touched symbols:* `_modifications_lines`,
`_checklist_lines`. *Traces to:* R-TUI-091, AT-176.

**LLR-091.4** — `_modified_files_lines`, `_declaration_error_lines`, `_inventory_lines` and
`_overview_lines` **shall** emit through `_admit`, one whole bullet or row per admission unit, so no
path or message is ever truncated. *Touched symbols:* those four.
*Traces to:* R-TUI-091, RES-1, RES-4.

**LLR-092.1** — `notes` **shall** be a composer-owned channel every admission site writes to; the
appendix **shall** be emitted unconditionally with the nothing-omitted statement when `notes` is
empty. *Touched symbols:* `generate_project_report`, `_hexdump_section`.
*Traces to:* R-TUI-092, AT-169.

**LLR-092.2** — an appendix entry **shall** render its `variant_id` inside a code span via
`md_code`, matching the shipped `check.source_path` precedent (`report_service.py:1148`).
*Touched symbols:* `generate_project_report`, `_hexdump_section`. *Traces to:* R-TUI-092, AT-172,
security F4.

**LLR-092.3** — appendix entries **shall** be admitted against `REPORT_APPENDIX_RESERVE`, with an
overflow line stating the count not listed. *Touched symbols:* `generate_project_report`.
*Traces to:* R-TUI-092, AT-173.

**LLR-092.4** — `_hexdump_section`'s size marker **shall** scope its claim to the blocks it governs
and **shall not** state a whole-document bound; the whole-document statement belongs to the
appendix. *Touched symbols:* `_hexdump_section`. *Traces to:* R-TUI-092, security F2.

**LLR-093.1** — `_addendum_lines` **shall** admit each hit as the scan produces it and **shall not**
build a hit list; the scan **shall** stop at `REPORT_ADDENDUM_SCAN_MAX` candidates and state so.
*Touched symbols:* `_addendum_lines`. *Traces to:* R-TUI-093, §3.4, §6.7.

**LLR-094.1** — `_admit`'s `priority_fn` **shall** be `fail > uncheckable > pass` for checklist rows
and `non-applied > applied` for modification rows. *Touched symbols:* `_admit`,
`_checklist_lines`, `_modifications_lines`. *Traces to:* R-TUI-094, AT-174, security F9.

**LLR-094.2** — every truncation marker **shall** state the selection rule in words.
*Touched symbols:* `_admit` callers. *Traces to:* R-TUI-094, security F9(1).

---

## 11. Increment plan, and the scope-capped fallback

### 11.1 Increments (≤5 files each; qa D-14's appendix-first order preserved)

| inc | content | why here |
|---|---|---|
| **1** | LLR-089.1/.2 (writer pin + accounting identity) · LLR-092.1/.2/.3/.4 (appendix repair) | The appendix is the oracle every later increment reports into, and the accounting is what every later increment enforces. Building on either while broken repeats REV 4. |
| **2** | LLR-090.1/.2/.3 — `_Allocation` + reserves + fair share + floors, wired with allowances large enough that behaviour is unchanged | The allocator lands and is proven inert before anything cuts. |
| **3** | LLR-091.1/.2/.3 — `_admit` + cost functions + the two tables | The measured blow-up. |
| **4** | LLR-091.4 + LLR-093.1 — the remaining 6 emitters + streaming addendum | **RES-1 lives here; §6.2's bound is re-measured at the end of this increment, not before.** |
| **5** | LLR-094.1/.2 — priority admission + marker wording | Last because it changes selection, and selection is only observable once cuts exist. |

### 11.2 Ledger

Base `2192 passed` (`-m "not slow"`, this tree, one complete run). Reserved `A = 15 AT + 12 TC = 27`,
`D = 0` → projected `post = 2219`. **No node may carry `@pytest.mark.slow`** (qa M-5).

### 11.3 If scope is capped — the honest fallback (design E)

If the operator caps this batch at design **E** (the three measured emitters only), then
**R-TUI-089 must be restated conditionally** and the document must say so:

> The declared bound holds for documents with a single variant, no declared regions, and change
> summaries whose source paths are under 4 096 characters. It does not hold on the variant,
> declared-region, or path axes; those are measured at 4.18×, 1.955× and 1.955× respectively.

and `_hexdump_section`'s marker must be reworded per LLR-092.4 regardless. **What is not available is
shipping design E while declaring R-TUI-089 unconditionally** — that is REV 4's defect with a
different mechanism.

---

## 12. Probe memory discipline — part of the evidence

A prior run of this task exhausted the host's RAM and crashed it. Discipline applied, and what it
caught:

1. **Derived analytically first, measured to spot-check.** The row-cost model (§3.2) is closed-form
   and was verified at 7 run lengths and 4 symbol lengths using **single rows** — no document.
2. **One document in memory at a time.** `h63.measure` writes to a temp file, `os.stat`s it,
   `os.remove`s it, and returns an integer. Document *text* is read back only when a probe needs it,
   never alongside a second document.
3. **Probe ceiling enforced in code, not by intent.** `h63.guard` raises `SystemExit` above 5 000
   entries. Every case above 5 000 is reached by **aliasing** one fixture across variants, so the
   fixture cost is O(1) in variant count — that is how 20 000 variants × 1 000 entries was measured
   without 20 million objects.
4. **The declared domain is reached by argument, not by allocation.** §7.5 fixes the allowance and
   varies N; emitted bytes **plateau** at 99 690 B from N=1 000 onward while omissions grow. Since
   emitted size is a function of the allowance and admission is O(1) per rejected row, no N —
   including 100 000 — can exceed it. **Building a 100 000-entry × 1 MiB-run fixture would be the
   crash, so the argument replaces it.**

   ```
        N  rows emitted  section bytes   omitted
      100           100         49,790         0
      500           200         99,690       300
    1,000           200         99,690       800  <- plateau
    2,000           200         99,690     1,800  <- plateau
    5,000           200         99,690     4,800  <- plateau
   ```
5. **The 559.7 GB figure is extrapolated from a 17.5 MB measurement**, deliberately (§3.4).
6. **One probe was killed mid-run** — `p9_worst.py` at 64 regions × 20 000 variants × 1 000 entries
   hung on the shipped addendum's eager hit list. It was stopped rather than left to complete.
   **The hang is finding §3.4**, and it is exactly the failure the memory brief warned about.
7. No probes run in parallel processes. All under `scratchpad/`, against `git archive HEAD` →
   `scratchpad/exp`. `git status --porcelain` shows only `.dev-flow/`.

---

## 13. What would change this recommendation

| if… | then… |
|---|---|
| Inc-4's re-measurement with **RES-1 active** breaches the budget | the floor vector (§6.4) re-derives, and `REPORT_MIN_VARIANT_ENVELOPE` rises. The mechanism does not change; the constants do. This is the single most likely re-derivation. |
| the operator caps scope at design **E** | §11.3 applies — R-TUI-089 becomes conditional **and the condition is printed in the document**. |
| `REPORT_MAX_TOTAL_BYTES` or `REPORT_CELL_CHARS` moves | every constant in §6 re-derives; none is independent of the budget. |
| a future emitter is added to the composer | it must route through `_admit`, or R-TUI-089 is false again. **This is the property `REPORT_BUDGET_HEADROOM` exists to protect** and it should be a review checklist item, not a hope. |
| the operator rules that omitting whole rows is worse than truncating cells | the ruling inverts — but then D-16's premise must be repaired first, and it is measurably false for 3 of 4 cells, so there is currently no honest version of that design. |
| `md_code` gains a truncation cap | RES-1 shrinks to a row-count axis; the whole-row rule still applies. |

---

## 14. Canonical id table (the reconciliation architect B-2 / qa B-2 required)

**One table. Both Phase-1 lanes renumber onto this; the qa catalog's `R-TUI-079/080/081` are
retired as batch-48's.**

| id | subject |
|---|---|
| R-TUI-089 | declared document bound is enforced; accounting matches the artifact |
| R-TUI-090 | allocation before emission: reserves · per-variant fair share · later-class floors |
| R-TUI-091 | whole-row admission on analytic cost; nothing is truncated in-cell |
| R-TUI-092 | every cut legible; appendix always emitted; appendix is the oracle |
| R-TUI-093 | streaming enforcement — nothing materialised that is not emitted |
| R-TUI-094 | evidentiary ordering + byte-identity when nothing is cut |
| AT-164…168 | US-B63-1 (bound · run-length ceiling · address · variant axis · accounting) |
| AT-169…173 | US-B63-2 (appendix exists · counts exact · post-filter totals · forgery · overflow) |
| AT-174…178 | US-B63-3 (findings survive · order · no cell cut · byte-identity · never format a rejected row) |
| TC-399…410 | white-box; TC-401/402 are the F5/R-TUI-093 pins (§9) |
| LLR-089.x…094.x | §10 — every one carries `Touched symbols:` **and** `Traces to:` |

---

## 15. Evidence checklist

| # | item | ✓/✗ | evidence — the predicate, not the label |
|---|---|:--:|---|
| 1 | Constraints stated explicitly | ✓ | §2 — 12 rows, each with a `file:line` or an executed grep |
| 2 | ≥2 alternatives considered | ✓ | §4 — five designs; B and C **disqualified by a measurement** (559.7 GB), not by preference; E retained as the costed fallback |
| 3 | Recommendation tied to constraints | ✓ | §4 — A ruled because the thesis demands the mechanism, not a weaker assertion; E's condition written out in §11.3 |
| 4 | **Every threshold EXECUTED (C-39)** | ✓ | §3.1 (CRLF, 3 cases) · §3.2 (17 cases) · §3.3 (ValueError) · §3.4 (17.5 MB→559.7 GB) · §3.5 (5 cases) · §6.2 (6 variant counts) · §6.3 (±0 B at n=128, n=1024) · §9 (A + B) |
| 5 | **Every probe driven to FAIL before being trusted** | ✓ | §3.2 mutation control (`analytic+1` disagrees) · §3.1 LF model shown short · §6.2 negative control: the shipped composer reads **OVER on 9 of 13** runs · AT-174's document-order arm loses 16/20 findings |
| 6 | **A false GREEN was found and recorded, not discarded** | ✓ | §7 AT-174's first form showed `20/20` in **both** arms — the allowance held all 520 rows, so it could not fail. C-31 against my own probe. Redone at 20 % allowance with `assert omitted > 0`. |
| 7 | **A carried number was RE-DERIVED, not copied** | ✓ | No REV-4 constant survives (§6.1). `REPORT_MIN_VARIANT_ENVELOPE` was re-derived after an early draft rendered **zero** variants (§6.3); `REPORT_APPENDIX_RESERVE` after an early draft consumed 1.18 MB (§6.5). Both failures recorded. |
| 8 | Risks listed — operational, security, cost, lock-in | ✓ | §8 six residuals with measured numbers · §9 cost · §13 six triggers. No new dependency, no external surface, no lock-in. |
| 9 | Cost / latency estimated | ✓ | §9 — 65.59 ms vs 445.02 ms; rejection flat at 12–15 µs/row; RES-3 names the 13 µs/row residual and its fix |
| 10 | Privacy / data handling addressed | ✓ | RES-5 — host paths in an exported evidentiary document, **unchanged and carried**, not silently dropped. All fixtures synthetic; no probe wrote outside `scratchpad/`. |
| 11 | Diagram included when flow is non-trivial | ✗ | Deliberate. The composition is one linear emitter chain; §3.6's 12-axis table and §6.4's floor ordering carry the structure a box diagram would blur. |
| 12 | What would change the recommendation | ✓ | §13 — six triggers, each naming what re-derives |
| 13 | Two-layer requirements: Acceptance block + `AT-NNN`, **both** chains | ✓ | §7 — 15 first-class Given/When/Then blocks; behavioural `US→AT` in §7, functional `US→R-TUI→LLR→TC` in §10 + §14. Every LLR carries `Touched symbols:` **and** `Traces to:` — the gap architect M-3 found in REV 4's LLR-093.x. |
| 14 | Ids verified on disk | ✓ | `R-TUI` max **088** · `AT` max **163** · `TC` max **398**, each grepped **excluding** batch-63's own superseded reservations. `R-TUI-079/080/081` confirmed batch-48's. |
| 15 | `shall`/`should` confined to HLR/LLR | ✓ | **Executed**, not asserted: `grep -n "shall"` → lines `271-326` (all inside §5, `271-330`), `612-679` (all inside §10, `610-683`), plus `805` = this row's own meta-reference. §7 uses Given/When/Then throughout. *Stated precisely because a label must not claim more than its predicate tested:* `must` also appears at lines `253, 376, 704, 710, 760, 761, 806` — all **prose or rationale** in §4/§6.2/§11.3/§13/§15, **none** inside a requirement statement. |
| 16 | **What remains unbounded is stated with numbers** | ✓ | §8 — RES-1 explicitly says §6.2's 0.998× **was measured without it** and must be re-measured at Inc-4. The bound is not declared closed. |
| 17 | Probe memory discipline stated | ✓ | §12 — seven measures, incl. the killed probe and the plateau argument that replaces a 100 000-entry fixture |
| 18 | Frozen-file guard | ✓ | touched set = `report_service.py`, `tests/*`, `REQUIREMENTS.md`; `_ENGINE_PATHS` has no `services/` path |
