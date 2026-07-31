# batch-75 — Requirements (Phase 1)

**Batch:** `2026-07-31-batch-75` · **Base:** `origin/main` = `232eb0a` · **Language:** English
**Requirement id:** `R-TUI-102` (next free; `R-TUI-101` is batch-74's)
**Id range:** `AT-250`…`AT-279`, `TC-552`…`TC-599` — **hard constraint**, a Lane-B registry build may run in parallel.

---

## §1 BLUF

Two stories, and **they are not equally strong — saying so is the point of this section.**

| Story | What it is | Strength |
|---|---|---|
| **US-B75-1** (F4) | The emitted document has no byte gate at all: `emit()` accounts, never gates. Measured floor **15.86× budget at V=100**. | **Live defect.** Wire-reachable, operator-observable. |
| **US-B75-2** (D2) | The inline `Length` cell raises on >4300 decimal digits. | **Constructor-domain hardening only — NOT wire-reachable.** Executed below. |
| **US-B75-3** (D2b) | An internal `ValueError` is presented as operator-input rejection. | **Live defect**, independent of whether D2's raise is reachable. |

**The design ruling: gate at the `emit` seam, uniformly, with no producer exempt.** One site, one derived
allowance constant. It is the only shape that measures the **emitted** form (immune to the 2.03×
`md_safe` expansion) and the only one whose bound is inherently invariant in `V` and `F` — a per-producer
cap structurally cannot bound `O(V × F)` structural lines.

**What this requirement does NOT claim: residency.** `_applied_regions` is fenced by operator ruling, so a
whole-report residency acceptance is unsatisfiable here. The word *memory* does not appear in any
normative clause below. This is the exact over-claim that killed batch-74's `HLR-106`/`AT-227` in all
three review lanes.

---

## §2 Premise table (C-43) — every proposition executed against `232eb0a`

### §2.1 Premises that HELD

| # | Proposition | Verdict | Executed evidence |
|---|---|---|---|
| P-1 | `emit()` accounts and never gates | ✅ TRUE | `.fits(` has **exactly 1** call site (`_hexdump_section`); `.consume(` has 2. `emit` body extends then consumes. |
| P-2 | "Charge the tables to `_ByteBudget`" closes nothing | ✅ TRUE | Follows from P-1. The module's own docstring says the budget is *"consumed at hexdump-block granularity only"*. |
| P-3 | `md_safe(limit=N)` bounds INPUT chars, not emitted bytes | ✅ TRUE | `md_safe('\'*600, limit=500)` emits **1013** chars — **2.03×**. |
| P-4 | `md_code` never truncates, deliberately | ✅ TRUE | Docstring: a cap would be machine-dependent and poison goldens. **Forecloses capping the `#### Checklist:` heading.** |
| P-5 | The `Length` raise keys on decimal digits | ✅ TRUE | `sys.get_int_max_str_digits()` = 4300; `f"{10**4300}"` raises, `f"{10**4298}"` does not. |
| P-6 | `_format_length` does not exist | ✅ TRUE | **0 hits** across `s19_app/` + `tests/`. Must be **created**. |
| P-7 | The two `Length` sites take disjoint inputs | ✅ TRUE | `change_summaries[].entries` vs `check_results[].entries`. One AT cannot bind both. |
| P-8 | The boundary literal is unstable | ✅ TRUE | 4300 here; batch-74 measured 831 under `-X int_max_str_digits=1000`. **Derive it, never type it.** |
| P-9 | A negative Length is constructible | ✅ TRUE | `0x1000 - 0x2000 = -4096`. |
| P-10 | A huge ADDRESS does not deny the report | ✅ TRUE | `_format_address(int('0x'+'F'*100000,16))` renders in **45 chars** (batch-74's shipped cap + cue). |
| P-11 | Only `ReportOptions.__post_init__` + the scope guard raise `ValueError` on the operator-input span | ✅ TRUE | `raise ValueError` census; the `variant_execution_service` site is unreachable (`app.py` passes the constant). |
| P-12 | `generate_project_report` writes once, at the end | ✅ TRUE | Single `target.write_bytes(...)` after `"\n".join(lines)` — **fail-closed holds by construction**. |

### §2.2 Premises that came out FALSE — three of them, and one came from a review lane

| # | Proposition | Verdict | What executing it showed |
|---|---|---|---|
| **P-13** | *"A schema-legal ADDRESS denies the report"* — the **`BACKLOG-CODE.md` headline** | ❌ **FALSE** | Confirms the charter's own correction. It renders in 45 chars. |
| **P-14** | *"The D2 `Length` defect is WIRE-reachable; a huge-address change file denies the report"* — **asserted by the Phase-1 architect lane** | ❌ **FALSE** | **Decisive:** both writers do `start, end = entry.addressed_range`, and `ChangeEntry.addressed_range` is `(address, address + len(encoded_bytes))`. So `end − start == len(encoded_bytes)` **always**, on both wire paths, bounded by `MF_RUN_LENGTH_CEILING = 1_048_576` (enforced at `io.py:1040`, `:1078`, `:1164`) → **7 decimal digits vs a 4300 limit**. The lane computed `a − b` from two arbitrary huge addresses, a pair not constructible through ingestion. `ChangeSummaryEntry`/`CheckRunEntry` carry **independent** `address_start`/`address_end` fields; `addressed_range` belongs to `ChangeEntry`, a **different class** — that is the category error. |
| **P-15** | *"Each check file emits **7** structural lines"* — **my own Phase-0 count**, and the charter's | ❌ **FALSE as a flat number** | Arm-dependent: **7** unsaturated · **6** saturated-with-kept-rows (header+rule suppressed, drop notice added) · **8** when a file saturates mid-way (header+rule kept **and** notice). Three lanes produced three different answers, which is itself the finding: **the term was undefined.** A flat `7` repeats the `988 B/entry` defect batch-74 just corrected. |

> **P-14 is the eighth false premise this area has produced, and the first to come from a review lane
> rather than from the backlog.** It matters beyond bookkeeping: had it been accepted, `AT-254`/`AT-255`
> would have been specced to drive an oversized `Length` through a change document — **unbuildable**, and
> discovered mid-increment. It is also the reason US-B75-2 is labelled hardening below rather than a
> live defect.

### §2.3 UNDECIDABLE — dispositioned, not left open

| # | Proposition | Verdict | Disposition |
|---|---|---|---|
| P-16 | Uniform `emit` gating never drops the preamble at the shipped budget | ❓ **assumed — verify at Inc-1** | Argued from `used == 0` at the first emit; **not executed**. If FALSE, `LLR-102.7` flips to an explicit preamble exemption, the allowance acquires an `O(V)` term, and **`HLR-102`'s `V`-invariance clause must be withdrawn or restated**. That is a requirement-strength change → surfaced at the gate, never absorbed by the implementer. |
| P-17 | Capping the truncation appendix drifts no shipped golden | ❓ **assumed — verify at Inc-1** | Today's note count is 3→4; a cap above that is inert. Golden census not executed. |
| P-18 | `AT-262`'s operator-rejection arm is reachable through the shipped dialog | ❓ **assumed — verify at Inc-3** | qa lane finding F-1. If the dialog clamps `context_bytes` upstream, this arm **drops to a TC** and `HLR-104` has no black-box negative — which must be **stated**, not papered over. |

---

## §3 User stories + Acceptance blocks (Layer B — black-box)

### US-B75-1 — the report I get is not bigger than the tool says

> As an operator generating a project report over many variants, I need the produced document to have a
> stated maximum size that does not grow with the variant count or the check-file count, so that a large
> or hostile project yields a report I can open.

**Observable outcome.** The `.md` file on disk is at most `REPORT_MAX_TOTAL_BYTES + REPORT_DISCLOSURE_ALLOWANCE_BYTES`,
is non-empty, opens, and states in plain text what was left out.
**Shipped surface.** The report action driven through `App.run_test()`; the file under `<project>/reports/`.

| AT | Acceptance | Fixture must exercise | Mutation that reddens it |
|---|---|---|---|
| **AT-250** | `len(target.read_bytes()) <= REPORT_MAX_TOTAL_BYTES + REPORT_DISCLOSURE_ALLOWANCE_BYTES`, constants **imported**, never typed | ungated content **exceeding** the budget — guarded by `TC-552` | gate predicate → constant `True` |
| **AT-251** | The ceiling holds at `V ∈ {1, 10, 100}` — it does not move with `V` | ≥2 variants actually dropped | exempt per-variant content from the gate |
| **AT-252** | The ceiling holds at `F ∈ {1, 3, 10}` with **few rows per file** — the `F` axis, structural lines not rows | rows/variant **under** `MAX_REPORT_ROWS_PER_VARIANT` so batch-74's cap never fires — guarded by `TC-558` | exempt structural lines with no allowance term |
| **AT-253** | Every drop is disclosed with a numeric count, and the counts **sum to what was actually cut** | ≥1 section cut **AND** ≥1 kept | (pair) delete the notice · emit it unconditionally |
| **AT-254** | A budget-exhausted report is still a usable file: exists, non-empty, has its header and ≥1 `## Variant:` | exhaustion **before** the last variant | put the header inside the gate · abort instead of truncate |
| **AT-255** | *(regression **PIN**, labelled — not an F4 gate)* under budget, byte-identical to a golden captured pre-flight from the **shipped** producer | under-cap content | add an unconditional blank line to the gate helper |

> **`AT-255` is explicitly a PIN, not a gate.** Its subject is invariant under a correct F4 change by
> construction, so it cannot go RED for a correct implementation. It guards collateral damage. Labelling
> it prevents it being counted as F4 coverage — the C-40 corollary.

### US-B75-2 — an oversized `Length` does not deny my report *(hardening, not a live defect)*

> As an operator, I need the `Length` cell to render rather than deny the whole report, and a shortened
> `Length` to be impossible to read as the true one, so the report stays produceable and stays evidentiary.

⚠️ **REACHABILITY, stated plainly (P-14).** This condition is **not reachable through the shipped
ingestion path** — `Length == len(encoded_bytes) ≤ 1_048_576` → 7 decimal digits. It is reachable through
the **constructor domain** (`ChangeSummaryEntry`/`CheckRunEntry` take independent endpoints). The
acceptance therefore drives `generate_project_report` — a real shipped API producing a real file on disk —
with **constructed** results, and **no AT below claims a change-document route.** This is defence in depth
against a future writer that stops deriving the endpoints, and against the negative-`Length` case, which
**is** constructible. Recorded rather than dressed up.

**Observable outcome.** The report is produced; the `Length` cell holds a token that cannot be misread as a complete decimal number and states how many digits are missing; a negative length keeps its sign.
**Shipped surface.** `generate_project_report` → the `Length` column of the `### Modifications` and `#### Checklist:` tables in the written `.md`.

| AT | Acceptance | Site | Mutation that reddens it |
|---|---|---|---|
| **AT-256** | Report produced (no raise); the Modifications `Length` cell **equals** a string derived independently by the test | Modifications (`change_summaries`, `check_results` asserted empty) | `return "0"` · drop the `0x` |
| **AT-257** | Same, at the Checklists site | Checklists (`check_results`, `change_summaries` asserted empty) | same |
| **AT-258** | A negative `Length` renders with its sign, on both the in-domain and shortened paths | both | `f"0x{abs(n):X}"` (sign dropped) → RED **on this arm only** |

> **The oracle is token EQUALITY against an independently derived string — regex membership is refused,
> with counterexamples.** `^-?0x[0-9A-F]+$` is satisfied by `f"0x{abs(n):X}"` on a negative length and by
> `lambda n: "0"`. The test derives `expected` with the digit limit **disabled**
> (`sys.set_int_max_str_digits(0)`, restored in `finally`), never by calling product code.
>
> **The base tree is NOT the falsifier for AT-256/257** — there they *error* with `ValueError`, and an
> error is not an assertion failure (project rule). Falsifiability evidence is
> mutation-on-a-copy-of-the-fixed-tree, and the artifact records **the substituted value**, not "drop the guard".

### US-B75-3 — an internal failure is not blamed on me

> As an operator whose report failed for an internal reason, I need the status line to say the tool
> failed rather than that my input was rejected, so I do not spend an hour editing a file that was fine.

**Observable outcome.** Status reads `Report failed: …`, the log records `failed:`, no file is left in `reports/`, the progress bar is reset to 0.
**Shipped surface.** The real status widget text via Pilot; the `reports/` directory listing; the report log event.

| AT | Acceptance | Mutation that reddens it |
|---|---|---|
| **AT-259** | An injected `ValueError` from the report generator yields status prefixed `Report failed:` — **not** `Report rejected:` | restore the single broad `except ValueError` |
| **AT-260** | Neither path leaves any file in the project's reports directory (fail-closed preserved) | make the writer emit incrementally |
| **AT-261** | Progress is reset to `0` on both branches (the N5 contract survives the refactor) | drop the reset on the new branch |
| **AT-262** | An out-of-domain `ReportOptions` field **still** yields `Report rejected:` | `except Exception: pass` / re-word everything |

> `AT-259`'s fixture must inject a **`ValueError`** — the same type the rejection branch legitimately
> catches. A `RuntimeError` fixture proves nothing; it already takes the other arm today. `AT-262` is the
> gate against the over-broad fix. ⚠️ Its reachability is **P-18, unverified** — if the dialog clamps
> upstream, it drops to a TC and that is **stated**, not hidden.

---

## §4 High-level requirements (EARS)

### HLR-102 — the emitted document is byte-bounded, invariant in `V` and `F`
> **The** report generator **shall** admit a section into the document only **when** its emitted byte
> length fits the remaining `REPORT_MAX_TOTAL_BYTES` budget, **shall** measure that length on the
> **emitted UTF-8 form** rather than on any input-character cap, and **shall** bound the produced file at
> `REPORT_MAX_TOTAL_BYTES + REPORT_DISCLOSURE_ALLOWANCE_BYTES` **independently of the variant count `V`
> and the per-variant check-file count `F`**.
>
> **When** any section is dropped, the generator **shall** disclose the drop with a numeric count, and
> **shall** compose every disclosure from a closed set of literals carrying no operator-derived text.
>
> **Where** the remaining budget is spent, the generator **shall** drop each non-fitting section **whole**
> and **shall** continue offering subsequent sections.

Traces **US-B75-1**. Closes `R-TUI-101` non-claims (a) and (f); converts (b) from *unbounded* to *invariant*.

### HLR-103 — the `Length` cell renders, and a shortened one cannot be read as complete
> **The** report generator **shall** render every `Length` cell without raising, for every `int`
> difference constructible from the entry domain, at both emission sites.
>
> **If** the value's decimal width would exceed `sys.get_int_max_str_digits()`, **then** the generator
> **shall** render a bounded token derived **arithmetically** from the value's `bit_length()` — never by
> formatting the value and slicing the result — **shall** carry the value's sign, and **shall** state how
> many digits were elided.
>
> **The** shortened rendering **shall not** equal any complete rendering of any other value.

Traces **US-B75-2**. Mirrors `_format_address` deliberately — same policy, one fewer number to learn.

### HLR-104 — an internal failure is attributed to the tool, not to the operator
> **When** a `ValueError` escapes the report generator, the report worker **shall** report it on the
> tool-failure path and **shall not** report it on the operator-input-rejection path.
>
> **When** a `ValueError` escapes the operator-input span, the worker **shall** continue to report it on
> the operator-input-rejection path.
>
> **The** worker **shall** fail closed on both paths: no report file, partial or complete, shall remain.

Traces **US-B75-3**.

---

## §5 Low-level requirements

**LLR-102.1** `emit` shall compute `n = _line_bytes(batch)` and admit `batch` only if `budget.fits(n)`; on refusal it shall append one disclosure line and shall not extend `lines`.
**LLR-102.2** Refusal shall be evaluated per call and **shall not latch** — a later smaller batch that fits is admitted.
**LLR-102.3** The disclosure line shall be formatted from a module-level template whose only substitutions are a section label drawn from a **closed tuple of literals** and integer counts. No operator-derived string shall reach it.
**LLR-102.4** `_hexdump_section` shall keep consuming the same `_ByteBudget` through its existing internal gate; batch-75 shall not re-route it through `emit`. *(Stated as a named exception so the `TC-553` census is not a hand list wearing an AST costume — qa finding F-2.)*
**LLR-102.5** The `## Truncation appendix` shall itemise at most `REPORT_MAX_TRUNCATION_NOTES` notes and close with one summary line stating the count not itemised, so its length is a constant rather than `O(V × REPORT_MAX_REGIONS_PER_VARIANT)`. *(This promotes the charter's P2 hygiene carry into a load-bearing clause: the gate creates a new cut kind, and an undisclosed cut is silent data loss in an evidentiary document.)*
**LLR-102.6** `REPORT_DISCLOSURE_ALLOWANCE_BYTES` shall be **derived** from the widest rendering of the closed disclosure set plus the capped appendix — never chosen — and `TC-554` shall execute that equality.
**LLR-102.7** Gating shall be uniform across all `emit` call sites including the preamble. *(Rationale: the header/inventory/overview block is itself `O(V)`, so exempting it would reintroduce the `V` term this requirement removes. Conditional on **P-16**.)*

**LLR-103.1** `_format_length(value: int) -> str` shall be **created** in `report_service` (P-6: no such symbol exists).
**LLR-103.2** The in-domain test shall be an integer-safe upper bound on decimal width from `bit_length()` compared against `sys.get_int_max_str_digits()` read **at call time**; `0` (unlimited) shall mean always in-domain. `str(value)` shall not be evaluated on the untested path. *(Eliminated by measurement, do not re-propose: "cap the rendered width" **still raises** — the int→str conversion precedes the slice.)*
**LLR-103.3** The shortened rendering shall keep the top `REPORT_LENGTH_HEX_DIGITS` hex digits obtained arithmetically, carry `-` for negatives, and append a cue stating the elided count.
**LLR-103.4** `REPORT_LENGTH_HEX_DIGITS` shall be `REPORT_ADDRESS_HEX_DIGITS` — reused, not a fourth policy number.
**LLR-103.5** Both producers shall replace the inline `f"| {entry.address_end - entry.address_start} "` with `_format_length(...)`; the two sites are accepted separately (P-7).
**LLR-103.6** The cue alphabet shall contain no character in `markdown_safety.MD_ESCAPE` and no `|`, executed against the real `MD_ESCAPE`, never a hand-kept whitelist.

**LLR-104.1** The worker shall place the report generator **outside** the span guarded by `except ValueError`.
**LLR-104.2** The tool-failure branch shall be factored into a single local helper invoked by both handlers — no second copy of the status/log/progress sequence.
**LLR-104.3** Both branches shall return before any report path is surfaced; fail-closed is preserved by construction (P-12) and observed by `AT-260`.

---

## §6 Layer A — TC design

| TC | Validates | Asserts |
|---|---|---|
| **TC-552** | fixture integrity | Σ`_line_bytes` over `AT-250`'s raw producers **> `REPORT_MAX_TOTAL_BYTES``. **The anti-vacuous-fixture control — mandatory.** Without it `AT-250` is green forever on a 40 kB document. |
| **TC-553** | LLR-102.1/.4 | AST census: every `lines.append`/`lines.extend` in `generate_project_report` routes through the gate, **except** the named `LLR-102.4` exception. Census asserted **non-empty** first. |
| **TC-554** | census completeness | Positive control: a planted ungated `lines.append` in a **copy** makes `TC-553` RED. *(Code mutation cannot test a set — C-31. This tests the walk.)* |
| **TC-555** | LLR-102.6 | The allowance constant equals its own derivation. |
| **TC-556** | LLR-102.3 / P-3 | `_line_bytes` of a worst-case-escape cell **exceeds** its `limit=` — pins the 2.03× fact so the allowance can never be re-derived from `REPORT_CELL_CHARS`. |
| **TC-557** | LLR-102.1 | Gate-**before**-commit: with a producer monkeypatched to an over-budget batch, `lines` does not grow. Distinguishes the fix from today's account-after-the-fact. |
| **TC-558** | LLR-102.5 / P-15 | Structural lines per check file **per arm — 7 / 6 / 8**, executed, never a flat number. Doubles as `AT-252`'s fixture-shape control. |
| **TC-559** | LLR-102.5 | Disclosure arithmetic: dropped counts sum to what was cut; `kept > 0 and cut > 0`. |
| **TC-560** | LLR-103.5 | AST census: **zero** inline `entry.address_end - entry.address_start` f-strings remain; the formatter is called at both sites. Census non-empty on the base tree. |
| **TC-561** | LLR-103.2 | **The C-39 node — strongest in the batch.** Under `sys.set_int_max_str_digits(1000)` (restored in `finally`) the shortened form fires at 1001 digits and **not** at 999. A hard-coded 4300/3572 → RED. |
| **TC-562** | AT-256/257 oracle | The oracle derives `expected` with the limit disabled, never via product code; plus an oracle-discriminates arm (a wrong token must mismatch) so a broken oracle cannot pass everything. |
| **TC-563** | LLR-103.3 | `f"0x{abs(n):X}"` (the sign-dropping mutant's output) is asserted **≠** expected. |
| **TC-564** | forgery | For `n = int('9'*L, 16)` the shipped token is **not** all-digits — the bare-hex-forgeable-as-decimal counterexample, recorded with its value so it is not re-argued. |
| **TC-565** | LLR-103.2 | The formatter does not raise on `10**(L+5)`; a format-then-slice implementation still raises → RED on it. |
| **TC-566** | in-domain identity | In-domain `Length` cells stay decimal, byte-identical (pins the eliminated "render in hex", which changed 9/9). |
| **TC-567** | LLR-104.1 | AST census of `raise ValueError` reachable from the guarded span ≡ the recorded set; non-empty; a planted raise → RED. Converts batch-74's hand sweep into a guard. |
| **TC-568** | LLR-104.3 | After the injected failure: no file in `reports/`, progress 0, log records a failure not a rejection. |

Unused headroom: **AT-263…AT-279**, **TC-569…TC-599**.

---

## §7 Non-claims — what batch-75 does NOT close

| # | Non-claim | Measured reason |
|---|---|---|
| **(a)** | **Whole-report RESIDENCY is not bounded; no memory claim is made.** | `_applied_regions` is a third unbounded producer (peak **16,128 → 160,992 B** at `N = 2000 → 4000`), **FENCED by operator ruling at kickoff**. A residency acceptance is unsatisfiable until it is bounded (batch-74 **P-23**). `HLR-102` claims emitted bytes; the word *residency* does not appear in it. |
| **(b)** | Two producers stay residency-ungated on their own. | `_modified_files_lines` carries an untruncated `md_code(source_path)` per summary; `_entropy_lines` is `O(len(ENTROPY_BANDS))`. Both are now *document*-gated, *producer*-ungated. |
| **(c)** | The `#### Checklist:` heading path stays unbounded, **and that fix is FORECLOSED.** | `md_code` refuses truncation deliberately (P-4). Capping it would change what a Mode-B value is. Under uniform gating the section is simply **dropped**, so the ceiling still holds. |
| **(d)** | `V` and `F` still have **no cardinality cap**. | `HLR-102` makes the document's **bytes** invariant in `V`/`F`. It does not stop the generator traversing 10,000 variants. Time and residency still scale. |
| **(e)** | Every *other* per-cell cap in the module remains input-shaped. | Measured **2.03×** expansion (P-3). `HLR-102` is immune because it measures `_line_bytes`; any byte arithmetic written from `REPORT_CELL_CHARS` elsewhere is wrong by up to 2.03×. **Module-wide residual.** |
| **(f)** | `HLR-103` bounds the **rendering** of `Length`, not the value. | A wide length still exists and still traverses; only its cell is bounded. |
| **(g)** | `HLR-104` re-routes by **call site**, not by cause. | It does not enumerate internal `ValueError` sources. `TC-567`'s census is the guard — a snapshot, not a proof. |
| **(h)** | The `BACKLOG-CODE.md` recommendation *"charge them to `_ByteBudget`"* (stated **twice**) is **NOT** what this batch implements, because it closes nothing. | P-1/P-2. `emit` calls `consume` only; the producer is fully evaluated first. `HLR-102` gates with `fits` **before** extending — a different change. |
| **(i)** | **US-B75-2 is not a live availability defect.** | P-14. Not wire-reachable; `Length == len(encoded_bytes) ≤ 1_048_576` → 7 digits. Hardening + the constructible negative case. |

---

## §8 Increment plan (≤5 files each; every AT has an owning increment — C-21)

| Inc | Scope | Files | Owns |
|---|---|---|---|
| **Inc-0** | Pre-flight golden capture from the **shipped** producer (C-12 ordering auditable via `git log --diff-filter=A`) | `tests/goldens/batch75/` | enables `AT-255` |
| **Inc-1** | `emit` gate + closed-literal disclosure + capped appendix + derived allowance | `report_service.py`, `tests/test_report_document_bound.py` (new), `REQUIREMENTS.md` | **AT-250…AT-255**; TC-552…TC-559 |
| **Inc-2** | `_format_length` + both call sites | `report_service.py`, `tests/test_report_length_cell.py` (new), `REQUIREMENTS.md` | **AT-256…AT-258**; TC-560…TC-566 |
| **Inc-3** | Error re-attribution | `app.py`, `tests/test_tui_report_attribution.py` (new), `REQUIREMENTS.md` | **AT-259…AT-262**; TC-567, TC-568 |

**Ordering rationale.** Inc-2 before Inc-3 is deliberate: once `_format_length` lands, the natural
`Length`-driven `ValueError` is gone, so Inc-3 must **inject** its fault. That makes `AT-259` a *general*
attribution test rather than one welded to the D2 bug — the project's general-controls-not-narrow-patches rule.

**Frozen set untouched.** `report_service.py`, `app.py` are editable; `markdown_safety.py` is **not**
edited (P-4 forecloses it).

---

## §9 Open findings carried into Phase 2

| # | Finding | Severity |
|---|---|---|
| **F-1** | **P-16 unverified** — if uniform gating can drop the preamble at the shipped budget, `HLR-102`'s `V`-invariance clause must be withdrawn or restated. **Requirement-strength change; surface at the gate.** | HIGH if FALSE |
| **F-2** | **P-18 unverified** — `AT-262`'s reachability. If the dialog clamps upstream, the arm drops to a TC and `HLR-104` has no black-box negative. **State it, don't hide it.** | MEDIUM |
| **F-3** | **Which section is cut is emission-order-dependent.** A whole-section gate means the last variant loses everything while variant 1 keeps its hexdumps. The ATs are deliberately **policy-neutral** (they assert *disclosure of what was cut*, not *which*). If fairness across variants matters, that is a **new clause**, not something an existing AT covers. | MEDIUM — decision owed |
| **F-4** | **No F4 clause may be worded in memory terms.** Gating emitted bytes leaves residency untouched. Reject any draft saying "bounds the report's memory". | HIGH if it appears |
| **F-5** | `TC-561` mutates process-global state (`sys.set_int_max_str_digits`) — must restore in `finally` and be marked so it does not leak under parallel execution. | LOW |
