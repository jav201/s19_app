# batch-75 — Requirements (Phase 1, **revision 2** after the Phase-2 BLOCK)

**Batch:** `2026-07-31-batch-75` · **Base:** `origin/main` = `232eb0a` · **Language:** English
**Requirement id:** `R-TUI-102` · **HLR/LLR:** `HLR-108`/`109`/`110`, `LLR-108.x`/`109.x`/`110.x`
**AT/TC range:** `AT-250`…`AT-279`, `TC-552`…`TC-599` — hard constraint (parallel Lane-B registry build).

> **Revision 2 supersedes revision 1**, which Phase 2 blocked on 4 blockers. Every change is recorded in
> **§9 (Requirement amendments, Before/After · Deleted/New)**. Two of the four blockers were in clauses I
> authored, and one was the house vacuous-fixture defect landing in the artifact meant to prevent it.

---

## §1 BLUF

| Story | What it is | Strength |
|---|---|---|
| **US-B75-1** (F4) | The emitted document has **no byte gate at all**: `emit()` accounts, never gates; and `_hexdump_section`'s `put()` does not gate either. Measured floor **15.86× budget at V=100**. | **Live defect**, wire-reachable. |
| **US-B75-2** (D2) | The inline `Length` cell raises above `sys.get_int_max_str_digits()`. | **Constructor-domain hardening — NOT wire-reachable** (P-14). |
| **US-B75-3** | An internal `ValueError` is presented as operator-input rejection. | **Live defect**, reachable (P-18 ✅). |

**Design ruling:** gate at **every** emission seam — `emit` *and* `_hexdump_section`'s `put` — with a
**per-variant byte reservation** so no variant can starve another, and a **single aggregated disclosure
block** whose line count is bounded by a closed label set.

**Three properties this buys, none of which revision 1 had:**
1. The ceiling is a **constant** — the disclosure is `O(1)` in `V`, not `O(V)`.
2. **No emitter is exempt** — revision 1's `_hexdump_section` exemption rested on a false premise.
3. **Fairness is structural** — an attacker who controls content can no longer choose whose audit record survives.

**Not claimed: residency.** `_applied_regions` is operator-fenced; the word *memory* appears in no
normative clause. This is the over-claim that killed batch-74's `HLR-106`/`AT-227` in all three lanes.

---

## §2 Premise table (C-43) — executed against `232eb0a`

### §2.1 HELD

| # | Proposition | Evidence |
|---|---|---|
| P-1 | `emit()` accounts, never gates | exactly **1** `.fits(` site vs **2** `.consume(` sites |
| P-2 | "Charge the tables to `_ByteBudget`" closes nothing | follows from P-1; the module docstring says so independently |
| P-3 | `md_safe(limit=N)` bounds INPUT chars, not emitted bytes | `md_safe('\'*600, limit=500)` → **1013** chars, **2.03×** |
| P-4 | `md_code` never truncates, deliberately | docstring: a cap would be machine-dependent and poison goldens |
| P-5 | The `Length` raise keys on decimal digits | limit 4300; `f"{10**4300}"` raises, `10**4298` does not |
| P-6 | `_format_length` does not exist | **0 hits**; must be created |
| P-7 | The two `Length` sites take disjoint inputs | `change_summaries[].entries` vs `check_results[].entries` |
| P-8 | The boundary literal is unstable | 4300 here; 831 under `-X int_max_str_digits=1000` |
| P-10 | A huge ADDRESS does not deny the report | renders in **45 chars** |
| P-11 | Operator-input `ValueError` sources are `ReportOptions.__post_init__` + the scope guard | `raise ValueError` census |
| P-12 | `generate_project_report` writes **once**, at the end | single `target.write_bytes(...)` — fail-closed by construction |
| **P-18** | `AT-262`'s rejection arm is reachable from the shipped dialog | ✅ **RESOLVED TRUE at Phase 2.** `screens.py:1569` — bare `OsClipboardInput`, **no `type=`, no validator, no clamp**; `:1714-1719` — `int(raw)` accepts any integer. `-1` → `Report rejected: context_bytes must be an integer in 0..4096, got -1`. |
| **P-21** | `_hexdump_section`'s `put()` **does not gate** | ✅ **NEW at Phase 2.** `:1748-1750` = `out.extend(...); budget.consume(...)`, no `fits`. **5 ungated `put()` sites.** |
| **P-22** | `HLR-102`/`LLR-102.x` were **live ids** | ✅ **NEW at Phase 2.** `report_service.py:608` (`LLR-102.2`), `:622` (`LLR-102.1`), `REQUIREMENTS.md:4945`. |
| **P-23** | True HLR/LLR high-water is **`HLR-107`/`LLR-107`** | ✅ **NEW.** Executed excluding batch-75's own artifacts. `HLR-107`/`LLR-107` are batch-74's split-out `Length` draft, review-only, never shipped. **Next free = `HLR-108`.** Not reused, precisely to avoid two contracts under one id — the defect P-22 names. |

### §2.2 FALSE — four, and three came from *inside* this batch

| # | Proposition | Source | What executing it showed |
|---|---|---|---|
| **P-13** | *"A schema-legal ADDRESS denies the report"* | the `BACKLOG-CODE.md` headline | ❌ Renders in 45 chars. Confirms the charter's own correction. |
| **P-14** | *"The D2 `Length` defect is WIRE-reachable"* | **the Phase-1 architect lane** | ❌ Both writers do `start, end = entry.addressed_range`, and `ChangeEntry.addressed_range` is `(address, address + len(encoded_bytes))` — so `end − start == len(encoded_bytes)` **always**, bounded by `MF_RUN_LENGTH_CEILING = 1_048_576` (enforced at `io.py:1040`, `:1078`, `:1164`) → **7 decimal digits vs a 4300 limit**. The lane computed `a − b` from two arbitrary huge addresses, a pair ingestion cannot construct. `ChangeSummaryEntry`/`CheckRunEntry` hold **independent** endpoints; `addressed_range` belongs to `ChangeEntry`, a **different class** — the category error. |
| **P-15** | *"Each check file emits **7** structural lines"* | **my own Phase-0 count** + the charter | ❌ Arm-dependent: **7** unsaturated · **6** saturated-with-kept-rows · **8** mid-file saturation · **7** saturated-with-nothing (a distinct branch colliding numerically). Three lanes gave three answers — **the term was undefined.** |
| **P-24** | *"`_hexdump_section` keeps consuming through its existing internal gate"* | **my own revision-1 `LLR-102.4`** | ❌ See P-21. Only the block loop gates. **The chartered defect survived inside the batch's own named exception.** |

> **P-14 and P-24 are the seventh and eighth false premises this area has produced, and both came from
> inside batch-75** — one from a review lane, one from me. The operator's instruction to treat the
> charter as a starting point rather than truth generalises: **treat every lane's output that way too.**

### §2.3 UNDECIDABLE — dispositioned

| # | Proposition | Disposition |
|---|---|---|
| P-16 | Whether the preamble can be refused under the shipped budget | ❓ **verify at Inc-1.** Re-opened with different arithmetic under the reservation model. If the preamble can be refused, `LLR-108.8` flips to an explicit exemption and the allowance grows — **a requirement-strength change, surfaced at the gate, never absorbed.** |
| P-17 | Capping the truncation appendix drifts no shipped golden | ❓ **verify at Inc-1.** Today's note count is 3→4; a cap above that is inert. |
| P-25 | The per-variant reservation floor does not starve a legitimate single-variant report | ❓ **verify at Inc-1** by executing the floor against the shipped example projects. |

---

## §3 User stories + Acceptance blocks (Layer B)

### US-B75-1 — the report I get is not bigger than the tool says, and every variant is documented

> As an operator generating a project report over many variants, I need the produced document to have a
> stated maximum size that does not grow with the variant count or check-file count, **and I need every
> variant to get its share of the document**, so that a large or hostile project yields a report I can
> open in which no variant's audit record has been squeezed out by another's.

**Observable outcome.** The file is at most `REPORT_MAX_TOTAL_BYTES + REPORT_DISCLOSURE_ALLOWANCE_BYTES`,
non-empty, opens, states in plain text **how many bytes** were left out, and contains a section for every
variant. ⚠️ *Subject to the generator completing: `HLR-108` bounds the produced file, not generation time
or peak memory.*
**Shipped surface.** The report action via `App.run_test()`; the file under `<project>/reports/`.

| AT | Acceptance | Kind | Fixture must exercise | Mutation (substituted expression) |
|---|---|---|---|---|
| **AT-250** | `len(read_bytes()) <= REPORT_MAX_TOTAL_BYTES + REPORT_DISCLOSURE_ALLOWANCE_BYTES`, constants **imported** | **gate** | ungated content exceeding the effective limit — **`TC-552`** | `budget.fits(n)` → `True` |
| **AT-251** | The ceiling holds at `V ∈ {1, 10, 100}` | **gate** | ≥2 variants actually dropping content — **`TC-552`** | reservation `limit // max(V,1)` → `limit` |
| **AT-252** | The ceiling holds at `F ∈ {1, 3, 10}` **against a shrunk `_ByteBudget.limit`**, expressed as `effective_limit + ALLOWANCE` | **gate** | rows/variant **under** `MAX_REPORT_ROWS_PER_VARIANT` (so batch-74's cap never fires) **AND** Σ`_line_bytes` **> `effective_limit`** — **`TC-552`** | `put`'s `if not budget.fits(n): return` → `pass` |
| **AT-253** | Every drop is disclosed, and the disclosed **BYTE** total equals `Σ _line_bytes(refused_batch)` over all refusals | **gate** | ≥1 section cut **AND** ≥1 kept | (pair) delete the disclosure · emit it unconditionally |
| **AT-254** | **Every** variant in `variant_results` has a `## Variant:` section, even when the budget is exhausted early | **gate** | exhaustion **before** the last variant — the F7 fairness property | reservation → global first-fit |
| **AT-255** | A budget-exhausted report is still usable: exists, non-empty, header present | ***PIN*** | — | header moved inside the gate |
| **AT-256** | *(regression **PIN**)* under budget, byte-identical to a pre-flight golden from the **shipped** producer | ***PIN*** | under-cap content | unconditional blank line in the gate helper |

> **PIN vs gate is now labelled, per Phase-2 M-1.** `AT-255`/`AT-256` are **green on the base tree** and
> cannot discriminate the change; they guard collateral damage. **Discriminating ATs for US-B75-1:
> `AT-250`, `AT-251`, `AT-252`, `AT-253`, `AT-254` — five.** Revision 1 claimed six and had three.
>
> **`AT-254` is new and is the F7 fairness acceptance** (operator ruling: per-variant reservation). It is
> the node that makes "who gets documented" a tested property rather than an emergent one.

### US-B75-2 — an oversized `Length` does not deny my report *(hardening, not a live defect)*

⚠️ **REACHABILITY (P-14):** **not reachable through the shipped ingestion path** —
`Length == len(encoded_bytes) ≤ 1_048_576` → 7 decimal digits. Reachable through the **constructor
domain** (both entry classes take independent endpoints and have **no `__post_init__` validation**). The
acceptance drives `generate_project_report` — a shipped API writing a real file — with **constructed**
results, and **no AT claims a change-document route.** ⚠️ **The negative-`Length` case is *also*
constructor-only** (`len(encoded_bytes) ≥ 0`), so nothing in this story is a live arm. Stated, not dressed up.

| AT | Acceptance | Kind | Mutation (substituted expression) |
|---|---|---|---|
| **AT-257** | Modifications `Length` cell **equals** a string derived independently; occurs **exactly once** in the document; the `### Checklists` section has no `Length` row | **gate** | `f"0x{value:X}"` → `f"{value:X}"` · `_format_length` → `lambda v: "0"` |
| **AT-258** | Same, at the Checklists site (`change_summaries` asserted empty) | **gate** | same |
| **AT-259** | A huge **negative** `Length` renders with its sign | **gate** | `f"-0x{abs(value):X}"` → `f"0x{abs(value):X}"` |

> **Oracle = token EQUALITY against an independently derived string.** Regex membership is refused with
> counterexamples: `^-?0x[0-9A-F]+$` is satisfied by `f"0x{abs(n):X}"` on a negative length and by
> `lambda n: "0"`. The test derives `expected` with the limit **disabled**
> (`sys.set_int_max_str_digits(0)`, restored in `finally`), never by calling product code.
>
> **The base tree is NOT the falsifier** — there these *error*, and an error is not an assertion failure.
> Falsifiability is mutation-on-a-copy-of-the-fixed-tree, recording **the substituted expression**.
> *(The in-domain negative arm is folded into `TC-566`: an f-string preserves the sign unconditionally, so
> no mutation can redden it — Phase-2 m-3.)*

### US-B75-3 — an internal failure is not blamed on me

| AT | Acceptance | Kind | Mutation (substituted expression) |
|---|---|---|---|
| **AT-260** | An injected `ValueError` from the generator yields status prefixed `Report failed:` | **gate** | move `generate_project_report` back inside the `try` guarded by `except ValueError` |
| **AT-261** | An out-of-domain `ReportOptions` field **still** yields `Report rejected:` | **gate** | `except ValueError` → `except Exception: pass` |
| **AT-262** | Neither path leaves a file in `reports/` | ***PIN*** | — (holds by construction, P-12) |
| **AT-263** | Progress resets to `0` on both branches | ***PIN*** | — (`app.py:4163` **and** `:4176` already do this today) |

> **Discriminating ATs for US-B75-3: `AT-260`, `AT-261` — two.** Revision 1 claimed four and had two.
> `AT-260`'s fixture must inject a **`ValueError`** — the same type the rejection branch legitimately
> catches; a `RuntimeError` fixture already takes the other arm today and proves nothing.

---

## §4 High-level requirements (EARS)

### HLR-108 — the emitted document is byte-bounded, `V`/`F`-invariant, and per-variant fair
> **The** report generator **shall** admit a batch of lines into the document only **when** its emitted
> byte length fits the remaining budget, **shall** measure that length on the **emitted UTF-8 form**
> rather than on any input-character cap, and **shall** bound the produced file at
> `REPORT_MAX_TOTAL_BYTES + REPORT_DISCLOSURE_ALLOWANCE_BYTES` **independently of the variant count `V`
> and the per-variant check-file count `F`**.
>
> **The** generator **shall** apportion the document budget as a **per-variant reservation**, so that no
> variant's content can consume the share of another; **and shall** emit each variant's section heading
> regardless of its reservation being spent.
>
> **When** any batch is refused, the generator **shall** record the refusal and **shall** emit, once per
> document, a single aggregated disclosure block stating per section-kind the **sections, lines and bytes**
> refused, whose line count **shall** be bounded by the cardinality of a closed label tuple.
>
> **Where** a batch does not fit, the generator **shall** refuse it **whole**, **shall not** latch, and
> **shall** continue offering subsequent batches.

Traces **US-B75-1**. Closes `R-TUI-101` non-claims (a) and (f); converts (b) from *unbounded* to *invariant*.

### HLR-109 — the `Length` cell renders, and a shortened one cannot be read as complete
> **The** report generator **shall** render every `Length` cell without raising, for every `int`
> difference constructible from the entry domain, at both emission sites.
>
> **If** the value's decimal width would exceed `sys.get_int_max_str_digits()`, **then** the generator
> **shall** render a bounded token derived **arithmetically** from `bit_length()` — never by formatting
> the value and slicing — **shall** carry the sign, and **shall** state how many digits were elided.
>
> **The** shortened rendering **shall not** equal any complete rendering of any other value, and every
> character of the emitted token **shall** lie outside `markdown_safety.MD_ESCAPE`.

Traces **US-B75-2**.

### HLR-110 — an internal failure is attributed to the tool, not to the operator
> **When** a `ValueError` escapes the report generator, the report worker **shall** report it on the
> tool-failure path and **shall not** report it on the operator-input-rejection path.
>
> **When** a `ValueError` escapes the operator-input span, the worker **shall** continue to report it on
> the operator-input-rejection path.
>
> **The** worker **shall** fail closed on both paths.

Traces **US-B75-3**.

---

## §5 Low-level requirements

**LLR-108.1** `emit` shall compute `n = _line_bytes(batch)` and admit the batch only if the active budget admits `n`; on refusal it shall **record** the refusal in an `O(1)` accumulator and shall not extend `lines`.
**LLR-108.2** Refusal shall be evaluated per call and **shall not latch**.
**LLR-108.3** `_hexdump_section`'s `put` shall gate identically to `emit`. *(Revision 1 exempted it on the false premise P-24; `put` consumes unconditionally today.)*
**LLR-108.4** The generator shall maintain a **per-variant reservation** of `REPORT_MAX_TOTAL_BYTES // max(V, 1)`, floored at `REPORT_VARIANT_RESERVATION_FLOOR_BYTES`, and each variant's admissions shall be charged against its own reservation. *(Operator ruling, F7.)*
**LLR-108.5** Each variant's `## Variant:` heading shall be emitted **outside** the reservation gate, so no variant can vanish; the heading set is `O(V)` and is charged to the allowance. *(This is the one deliberate `O(V)` term and it is named — see non-claim (j).)*
**LLR-108.6** The refusal accumulator shall be a mapping from a **closed tuple of section-kind literals** to `(sections, lines, bytes)` integers, and the disclosure block shall be emitted **once**, at the tail. No operator-derived string shall reach it **except** the integer index of a variant in `variant_results`, which shall be rendered as an integer and bounded to the first `REPORT_DISCLOSURE_VARIANTS_MAX` indices followed by `+N more`. *(Phase-2 F5: the blanket ban bought anonymity at the cost of reconciliation, and was stricter than the shipped appendix, which already interpolates `md_safe(variant_id, …)`.)*
**LLR-108.7** `REPORT_DISCLOSURE_ALLOWANCE_BYTES` shall be **derived** from the widest rendering of the closed disclosure set — using the maximum integer width read from `sys.maxsize` at call time, never a typed literal — plus the capped appendix plus the `O(V)` heading term; `TC-555` shall recompute it **independently**.
**LLR-108.8** Gating shall be uniform across all `emit` call sites including the preamble. *(Conditional on P-16.)*
**LLR-108.9** The `## Truncation appendix` shall itemise at most `REPORT_MAX_TRUNCATION_NOTES` notes selected **round-robin by variant** — at most one note per variant before any variant's second — and shall close with a summary line stating the count not itemised **and the count of distinct variants with un-itemised notes**. `REPORT_MAX_TRUNCATION_NOTES` shall be derived from the allowance, not chosen. *(Phase-2 F4: `notes[:CAP]` retains the earliest, so an attacker floods with cheap region-cap notes from variants named to sort ahead and evicts the note naming their target.)*

**LLR-109.1** `_format_length(value: int) -> str` shall be **created** in `report_service` (P-6).
**LLR-109.2** The in-domain test shall be an integer-safe upper bound on decimal width from `bit_length()` compared against `sys.get_int_max_str_digits()` read **at call time**; `0` shall mean always in-domain; `str(value)` shall not be evaluated on the untested path. *(Eliminated by measurement: "cap the rendered width" **still raises** — the int→str conversion precedes the slice.)*
**LLR-109.3** The shortened rendering shall keep the top `REPORT_LENGTH_HEX_DIGITS` hex digits obtained arithmetically, carry `-` for negatives, and append a cue stating the elided count.
**LLR-109.4** `REPORT_LENGTH_HEX_DIGITS` shall be `REPORT_ADDRESS_HEX_DIGITS` — reused, not a fourth policy number.
**LLR-109.5** Both producers shall replace the inline `f"| {entry.address_end - entry.address_start} "` with `_format_length(...)`; the two sites are accepted separately (P-7).
**LLR-109.6** **Every character of the emitted token** — sign, `0x`, hex digits and cue — shall lie outside `markdown_safety.MD_ESCAPE`, executed against the real tuple. *(Phase-2 F11: revision 1 constrained only the cue, and separately named `|`, which is already `MD_ESCAPE[2]`.)*

**LLR-110.1** The worker shall place the report generator **outside** the span guarded by `except ValueError`.
**LLR-110.2** The tool-failure branch shall be factored into a single local helper invoked by both handlers.
**LLR-110.3** Both branches shall return before any report path is surfaced (P-12).

---

## §6 Layer A — TC design

| TC | Validates | Asserts |
|---|---|---|
| **TC-552** | fixture integrity | **For each of `AT-250`/`251`/`252` separately**, Σ`_line_bytes` over that AT's own raw producers **> its own effective limit**. *(Phase-2 B-4: revision 1 scoped this to `AT-250` only and `AT-252` was vacuous.)* |
| **TC-553** | LLR-108.1/.3 | AST census over **both** `generate_project_report` **and** `_hexdump_section`: every `lines.append`/`lines.extend`/`out.extend` routes through a gate. Census asserted **non-empty**; the exclusion set asserted to have **cardinality 0**. |
| **TC-554** | census walk | Positive control: a planted ungated `lines.append` in a **copy** makes `TC-553` RED. |
| **TC-555** | LLR-108.7 | Recomputes the allowance **independently in the test**, never calling the product helper; plus a discriminating arm (a label added to the tuple must move the number). *(Phase-2 M-2: `ALLOWANCE == _derive()` cannot fail.)* |
| **TC-556** | P-3 | `_line_bytes` of a worst-case-escape cell **exceeds** its `limit=` — pins 2.03× so the allowance is never re-derived from `REPORT_CELL_CHARS`. |
| **TC-557** | LLR-108.1 | Gate-**before**-commit: a producer monkeypatched to an over-budget batch leaves `lines` ungrown. |
| **TC-558** | LLR-108.4 | **Non-latching**: a small batch emitted **after** a refused large one **is admitted**. *(Phase-2 M-4: `LLR-102.2` had no node at all.)* |
| **TC-559** | LLR-108.9 | Round-robin retention: with `CAP+k` notes from `CAP+k` variants, **every variant appears at most once before any appears twice**, and the last variant's note is **not** evicted by earlier floods. Plus `itemised + summarised == total_generated`. |
| **TC-560** | LLR-108.6 | Disclosure arithmetic: the **byte** total equals `Σ _line_bytes(refused)`; `kept > 0 and cut > 0`. |
| **TC-561** | structural lines | Per-arm count **7 / 6 / 8 / 7**, executed, stating whether the per-variant `### Checklists` header is included. *(Phase-2 m-1: revision 1 had 3 arms and no unit.)* |
| **TC-562** | LLR-109.5 | AST census: **zero** inline `entry.address_end - entry.address_start` f-strings; formatter called at both sites. |
| **TC-563** | census walk | Positive control for `TC-562`: plant an inline f-string in a copy → RED. *(Phase-2 M-3: `TC-562` asserts a census is **empty**, and a broken walk returns zero and passes.)* |
| **TC-564** | LLR-109.2 | **The C-39 node.** Under `sys.set_int_max_str_digits(1000)` (restored in `finally`, marked non-parallel) the shortened form fires at 1001 digits and **not** at 999. A typed 4300/3572 → RED. |
| **TC-565** | AT-257/258 oracle | Derives `expected` with the limit disabled, never via product code; plus an oracle-discriminates arm. |
| **TC-566** | LLR-109.3 | In-domain identity **including the in-domain negative arm**; `f"0x{abs(n):X}"` asserted **≠** expected. |
| **TC-567** | forgery | For `n = int('9'*L, 16)` the token is **not** all-digits — the bare-hex-forgeable-as-decimal counterexample, recorded with its value. |
| **TC-568** | LLR-109.2 | The formatter does not raise on `10**(L+5)`; a format-then-slice implementation still raises → RED. |
| **TC-569** | LLR-109.6 | Every character of the emitted token ∉ `MD_ESCAPE`, executed against the real tuple. *(Phase-2 M-4 orphan.)* |
| **TC-570** | LLR-110.1 | AST census of `raise ValueError` **lexically within a recorded tuple of functions** (not "reachable from", which is not statically computable); non-empty; planted raise → RED. *(Phase-2 M-3.)* |
| **TC-571** | LLR-110.3 | After the injected failure: no file in `reports/`, progress 0, log records a failure not a rejection. |
| **TC-572** | LLR-110.2 | The status/log/progress sequence occurs **once**, not duplicated across the two handlers. *(Phase-2 M-4 orphan.)* |

Unused headroom: **AT-264…AT-279**, **TC-573…TC-599**.

---

## §7 Non-claims

| # | Non-claim | Measured reason |
|---|---|---|
| **(a)** | **Whole-report RESIDENCY is not bounded; no memory claim is made.** | `_applied_regions` (peak **16,128 → 160,992 B** at `N = 2000 → 4000`) is **operator-FENCED**. Unsatisfiable until bounded (batch-74 **P-23**). Every producer is still fully evaluated before its gate can refuse it, so peak residency is `admitted_lines + max_producer_output`. |
| **(b)** | Two producers stay residency-ungated on their own. | `_modified_files_lines` (untruncated `md_code(source_path)` per summary); `_entropy_lines` (`O(len(ENTROPY_BANDS))`). Both now document-gated, producer-ungated. |
| **(c)** | The `#### Checklist:` heading path stays unbounded, **and that fix is FORECLOSED.** | `md_code` refuses truncation deliberately (P-4). Under gating the section is **refused**, so the ceiling still holds. |
| **(d)** | `V` and `F` have **no cardinality cap**. | Bytes are invariant; traversal is not. Time and residency still scale. |
| **(e)** | Every *other* per-cell cap in the module remains input-shaped. | **2.03×** (P-3). Module-wide residual. |
| **(f)** | `HLR-109` bounds the **rendering** of `Length`, not the value. | — |
| **(g)** | `HLR-110` re-routes by **call site**, not by cause. | `TC-570` is a snapshot, not a proof. **It also moves `ValueError` onto a path that writes a full traceback (host paths included) to `s19tui.log`** — matching every other exception type, deliberate; report-file redaction stays withdrawn per batch-62 D-11. *(Phase-2 F12.)* |
| **(h)** | *"Charge them to `_ByteBudget`"* (the backlog's twice-stated recommendation) is **NOT** what this batch implements. | P-1/P-2. `emit` calls `consume` only. |
| **(i)** | **US-B75-2 is not a live availability defect**, and **neither is its negative arm.** | P-14; `len(encoded_bytes) ≥ 0`. |
| **(j)** | **One deliberate `O(V)` term survives: the per-variant heading set** (`LLR-108.5`). | It is what makes `AT-254` (no variant vanishes) achievable, it is charged to the allowance, and it is named rather than emergent. `HLR-108`'s `V`-invariance is therefore *"invariant above the heading term"* — stated, not implied. |
| **(k)** | `HLR-109`'s non-collision covers shortened-vs-complete, **not shortened-vs-shortened.** | Two values sharing their top 16 hex digits **and** elided count render identically — the same honest lossiness `_format_address` ships; the cue announces incompleteness. |

---

## §8 Increment plan (≤5 files each; every AT has an owning increment — C-21)

| Inc | Scope | Files | Owns |
|---|---|---|---|
| **Inc-0** | Pre-flight golden capture from the **shipped** producer (C-12; ordering auditable via `git log --diff-filter=A`) | `tests/goldens/batch75/` | enables `AT-256` |
| **Inc-1** | `emit` + `put` gating · per-variant reservation · aggregated disclosure · capped round-robin appendix · derived allowance | `report_service.py`, `tests/test_report_document_bound.py` (new), `REQUIREMENTS.md` | **AT-250…AT-256**; TC-552…TC-561 |
| **Inc-2** | `_format_length` + both call sites | `report_service.py`, `tests/test_report_length_cell.py` (new), `REQUIREMENTS.md` | **AT-257…AT-259**; TC-562…TC-569 |
| **Inc-3** | Error re-attribution | `app.py`, `tests/test_tui_report_attribution.py` (new), `REQUIREMENTS.md` | **AT-260…AT-263**; TC-570…TC-572 |

**Ordering rationale.** Inc-2 before Inc-3: once `_format_length` lands, the natural `Length`-driven
`ValueError` is gone, so Inc-3 must **inject** its fault — making `AT-260` a *general* attribution test
rather than one welded to the D2 bug.

**Frozen set untouched.** `report_service.py`, `app.py` editable; `markdown_safety.py` **not** edited (P-4).

---

## §9 Requirement amendments (§6.5 — Before/After · Deleted/New)

| # | Before (revision 1) | After (revision 2) | Driver |
|---|---|---|---|
| **A-1** | `HLR-102`/`103`/`104`, `LLR-102.x`/`103.x`/`104.x` | **`HLR-108`/`109`/`110`, `LLR-108.x`/`109.x`/`110.x`** | **B-1.** Revision 1's ids are **live**, cited in `report_service.py:608`/`:622`. High-water re-derived: `HLR-107`/`LLR-107` (batch-74's split-out draft). **New premise P-23 added to §2.** |
| **A-2** | *"on refusal it shall append **one disclosure line**"* (per call) | **One aggregated disclosure block per document**, keyed by a closed label tuple (`LLR-108.6`) | **B-2.** Per-call disclosure is `O(V)`: ~558 lines / 45–65 kB at `V=100` against a ~1 kB allowance — `AT-251` would go RED for a **correct** implementation, and the gate becomes a per-variant emitter. |
| **A-3** | `LLR-102.4` exempted `_hexdump_section` | **`LLR-108.3`: `put` gates identically to `emit`.** Exemption **DELETED** | **B-3 / P-24.** `put` consumes unconditionally; 5 ungated sites ≈ 178 B/variant. |
| **A-4** | `AT-252` with "few rows per file", no budget mechanism | **`AT-252` runs against a shrunk `_ByteBudget.limit`**, ceiling expressed as `effective_limit + ALLOWANCE`; `TC-552` extended to guard **each** ceiling AT's fixture | **B-4.** Revision 1's fixture reached ~4 kB against a 2 MB budget — green on base, fixed, **and** a stubbed gate. |
| **A-5** | *(absent)* | **NEW `LLR-108.4` per-variant reservation + `LLR-108.5` unconditional headings + `AT-254`** | **F7, operator ruling.** First-fit over attacker-ordered input means attacker-chosen; an early 311,625 B variant blanks variants 8–100. |
| **A-6** | `AT-253`: *"counts sum to what was actually cut"* | **The disclosed BYTE total equals `Σ _line_bytes(refused)`**; disclosures carry `(sections, lines, bytes)` | **F6.** The unit was undefined — `"3 sections omitted"` satisfied it while telling an auditor nothing. |
| **A-7** | `LLR-102.3`: no operator-derived string at all | **`LLR-108.6`: the integer variant INDEX is permitted**, bounded | **F5.** The blanket ban was stricter than the shipped appendix and made disclosures unreconcilable. |
| **A-8** | `LLR-102.5`: cap the appendix, retention unspecified | **`LLR-108.9`: round-robin by variant + distinct-variant count in the tail + derived cap** | **F4.** `notes[:CAP]` retains the earliest → attacker evicts the note naming their target. |
| **A-9** | `AT-254`/`AT-260`/`AT-261` counted as coverage | **Relabelled PINs** (now `AT-255`, `AT-262`, `AT-263`); discriminating counts stated per story | **M-1.** All three are green on the base tree. |
| **A-10** | `TC-555` asserts `ALLOWANCE == _derive()` | **Recomputes independently in the test**, + discriminating arm | **M-2.** Tautology. |
| **A-11** | `TC-560` (now `TC-562`) had no positive control; `TC-567` (now `TC-570`) walked "reachable from" | **`TC-563` positive control added; `TC-570` walks a recorded tuple lexically** | **M-3.** A broken walk returning zero passes an emptiness census; reachability is not statically computable. |
| **A-12** | 4 orphan LLRs, 2 mis-traced TCs | **`TC-558` (non-latching), `TC-559` (appendix cap), `TC-569` (cue alphabet), `TC-572` (single helper) added; TCs re-traced** | **M-4.** |
| **A-13** | *"drop the `0x`"* and 3 other operator-deletion phrasings | **Every mutation cell records a substituted expression** | **M-5.** Named three different mutants; this ambiguity cost batch-73 a false BLOCKER. |
| **A-14** | `LLR-103.6` constrained the **cue** and separately named `|` | **`LLR-109.6` constrains the whole emitted token**; `|` dropped as redundant (already `MD_ESCAPE[2]`) | **F11.** |
| **A-15** | US-B75-1 promised *"a report I can open"* unconditionally | **Completion caveat added**; non-claim (j) names the surviving `O(V)` heading term | **F8, and honesty about `LLR-108.5`.** |
| **A-16** | `LLR-102.6` derivation had no fixed point | **Max integer width read from `sys.maxsize` at call time** | **F9.** |
| **A-17** | §7(i) implied the negative `Length` was the live arm | **States the negative case is also constructor-only** | **F10.** |
| **A-18** | non-claim (g) silent on logging | **States the traceback/host-path aperture widening** | **F12.** |
| **A-19** | `TC-558` had 3 arms, no unit | **`TC-561`: 4 arms + states whether the per-variant header is counted** | **m-1.** |
| **A-20** | `AT-256/257` asserted only the cell value | **Also assert the token occurs exactly once and the other section has no `Length` row** | **m-2.** |
| **A-21** | `AT-258` carried an unfalsifiable in-domain negative half | **Folded into `TC-566`** | **m-3.** |

**Deleted tokens:** `HLR-102`, `HLR-103`, `HLR-104`, `LLR-102.1`…`102.7`, `LLR-103.1`…`103.6`, `LLR-104.1`…`104.3` (all reverted to their rightful owners).
**New tokens:** `HLR-108`, `HLR-109`, `HLR-110`, `LLR-108.1`…`108.9`, `LLR-109.1`…`109.6`, `LLR-110.1`…`110.3`, `AT-254`, `AT-263`, `TC-569`, `TC-570`, `TC-571`, `TC-572`, `REPORT_VARIANT_RESERVATION_FLOOR_BYTES`, `REPORT_DISCLOSURE_VARIANTS_MAX`.

**Parent-HLR re-read:** `HLR-108`'s `V`-invariance clause is now qualified by non-claim (j) — it is
*invariant above the named heading term*, not absolutely invariant. That is the honest form, and it is the
distinction revision 1 got wrong in the opposite direction by claiming invariance while emitting `O(V)`
disclosure lines.

---

## §10 Carried into Inc-1

| # | Item | Status |
|---|---|---|
| P-16 | Can the preamble be refused? | verify at Inc-1; a requirement-strength change if TRUE |
| P-17 | Does the appendix cap drift a golden? | verify at Inc-1 |
| P-25 | Does the reservation floor starve a legitimate single-variant report? | verify at Inc-1 against the shipped example projects |
| m-4 | **Adjacent defect, out of scope:** `screens.py:1717-1719` — a **non-integer** `context_bytes` makes Generate do *nothing* (logs and returns, no status, dialog open), where an out-of-domain integer gives a clear `Report rejected:` | → `BACKLOG-CODE.md` |
