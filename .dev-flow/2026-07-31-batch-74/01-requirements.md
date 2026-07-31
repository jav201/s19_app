# batch-74 — Requirements (Phase 1, **REVISION 3 — operator re-scope**)

**Requirement id:** `R-TUI-101` · **Base:** `origin/main` = `d81cb3d` · **Lane A** · 2026-07-31

> **BLUF.** The batch is re-scoped by operator decision at the iteration cap to the **two genuinely
> wire-reachable resident-memory axes**: the producer bound on `_modifications_lines` /
> `_checklist_lines` (**OB-4**), and the **`Address` cell**, which Phase-2 measurement found is
> unbounded to **100,000 characters** and was in nobody's charter. **F4** (the `_ByteBudget` gate) and
> **D2** (the `Length` formatter) are **split into a follow-on batch** — F4 because it was the source of
> most Phase-2 blockers and cannot be honestly closed while five sibling producers stay ungated, D2
> because it is **unreachable through the shipped ingestion path** and is therefore the lowest-value of
> the three.

## 0. Re-scope record (operator decision, 2026-07-31)

Revision 2 folded 7 blockers and the discharge re-gate found **3 more that the fold itself created**,
with a diagnosable pattern: *the requirement scope moved and the AT predicate stayed behind.* Both
Phase 1 and Phase 2 stood at 2 iterations. Per the launch instruction (*"si topas el cap, escala
conmigo — no hagas loop"*) the batch was escalated rather than iterated a third time.

**Operator ruling: re-scope to OB-4 + Address; split F4 and D2.** This revision applies the reviewer's
own highest-leverage rule — **when a requirement's scope moves, the AT predicate moves with it** —
and drops roughly half the specification surface.

| Was | Now |
|---|---|
| US-B74-1 OB-4 · US-B74-2 F4 · US-B74-3 D2 | **US-B74-1 OB-4 · US-B74-2 Address** |
| 3 HLR / 20 LLR / 18 AT | **2 HLR / 9 LLR / 9 AT** |

**Split out to batch-75, with everything already measured carried forward** (§6): the `_ByteBudget`
per-row gate; the five ungated sibling producers (`_declaration_error_lines` alone = **315,912
B/variant**); the uncapped `V` and check-file count `F`; `_format_length` / D2; the `app.py` error
re-attribution. **None of this is lost** — it is written into `BACKLOG-CODE.md` at close with its
measurements, which is the only reason splitting is safe.

---

## 1. Scope

**In:** `s19_app/tui/services/report_service.py` — `_modifications_lines` (`:1031`),
`_checklist_lines` (`:1203`), `_format_bytes` (`:538`).

**Out:** the `_ByteBudget` gate (F4) · `_format_length` / D2 · `app.py` error routing · D-11 host-path
redaction · `diff_report_service` · `_applied_regions` (`:1288`, a third unbounded producer) ·
`options.declared_regions` · batch-73's `changes/apply.py`.

**Engine-frozen, untouched:** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
`tui/mac.py`, `tui/color_policy.py`, and the frozen test files.

---

## 2. User stories

**US-B74-1 (OB-4) — resident memory.** *As the operator generating a report from a change file I did
not author, I need the row producers to bound their own resident allocation, so a wire-legal file
cannot exhaust process memory before any output exists.*
Threat, executed: `MF_ENTRY_COUNT_CEILING = 100_000` entries/file × `MF_RUN_LENGTH_CEILING =
1_048_576` bytes/run; measured producer cost `≈ 92 + 6·L` B/entry, so **one row can cost ~6 MiB**.

**US-B74-2 (Address) — a truncated number must never read as a complete one.** *As the operator, I
need an oversized address bounded in the report, and I need to be able to tell at a glance that what
I am reading was shortened — because a silently shortened address in an evidentiary document is a
false statement about where firmware was written.*
Threat, executed: `_ADDRESS_RE = ^0x[0-9A-Fa-f]+$` has **no digit limit** (`changes/io.py:235`) and
`int(raw, 16)` **parses without limit** — CPython's `int_max_str_digits` does **not** apply to base-16
parsing. `int('0x'+'F'*100000, 16)` renders a **100,000-character** cell; the real ceiling is
`READ_SIZE_CAP_BYTES = 268,435,456` (`changes/io.py:224`).

### 2.7 Premise evaluation (C-43) — cumulative

Phase 0 recorded 17 (16 TRUE / 1 FALSE). Phase 1 falsified **3 of its own Phase-0 results**. The
Phase-2 re-gate falsified **2 of revision 2's**. All are retained; the table is the batch's honesty
instrument and an author who deletes their own falsified rows has removed the evidence.

| # | Premise | Verdict | Evidence |
|---|---|---|---|
| P-14 | OB-4 costs a flat `988 B/entry` | ❌ FALSE | `≈ 92 + 6·L`; 988 is the value at `L≈149` |
| P-6 | *"charging to `_ByteBudget` closes F4"* | ❌ FALSE | `emit()` **accounts, never gates** (`:2215-2217`) |
| P-18 | a cap < 415 re-baselines a golden | ❌ FALSE | 415 was a **file-wide sum over 6 documents**; max single `(document,variant)` table = **200** |
| P-19 | `md_safe(REPORT_CELL_CHARS)` on byte cells drifts nothing | ❌ FALSE | `md_safe("-")` → `'\-'`; **3/3** goldens carry a bare `-`. Also a **sink** bound — the string already exists |
| P-20 | *"a huge **address** denies the report"* | ❌ FALSE | a huge address renders fine; the raise is keyed on **`Length`**'s decimal digits |
| **P-24** | *"the `Address` cell is bounded at 3574 chars"* (**revision 2's own reassurance**) | ❌ **FALSE** | `int('0x'+'F'*100000,16)` **parses**; cell = **100,000 chars**; ceiling is `READ_SIZE_CAP_BYTES` = 268 MB. **3574 is what a decimal-limited value renders to — never a ceiling.** This is why US-B74-2 exists |
| **P-25** | *"traversal must not terminate, so the notice can state a true dropped count"* (`LLR-105.4`, revision 1+2) | ❌ **FALSE — the requirement was UNFALSIFIABLE** | `_checklist_lines:1243-1248` **already** computes a lazy filtered `kept`; one-pass and precount-then-break produce **byte-identical documents and identical memory ratios**. The clause had no observable consequence. **Dropped in revision 3** — replaced by a requirement on the *count's correctness*, which is observable (§4 LLR-105.4′) |
| P-22 | the cardinality and width axes are mutually invariant | ✅ TRUE | cap-only leaves width ratio 1.9476; width-only leaves cardinality 2.00 |
| P-23 | a whole-report residency AT is authorable | ❌ FALSE | `_applied_regions` is a third unbounded producer, out of scope |
| P-16/17 | not frozen · no test names either producer | ✅ TRUE | re-confirmed |

---

## 3. High-level requirements

### HLR-105 ← US-B74-1
> `_modifications_lines` and `_checklist_lines` **shall** bound their own resident allocation on two
> axes — admitted row cardinality, and the rendered width of every **byte-run** cell — independently of
> the per-variant entry count `E` and the per-entry byte-run length `L`; **shall** materialise no
> intermediate full-population list; and **shall** disclose in the document every bound that fires,
> with a **correct** count of what was dropped.

### HLR-106 ← US-B74-2
> The `Address` cell **shall** render at most a bounded number of characters, and any truncated
> rendering **shall not** match `^-?0x[0-9A-F]+$` — so that a shortened address is impossible to read
> as a complete one.

> **Why the form, not just the bound.** Truncating a hex address to `0xFFFF…` leaves a **well-formed
> numeral** that understates the true value silently — measured at `2^12248` for a 3572-digit address.
> Bounding without changing the form would close a memory hole by opening a forgery hole. This is the
> same principle the byte-cell cue applies, and it is why HLR-106 constrains the *shape* of the output.

---

## 4. Low-level requirements

| LLR | Statement | Touched symbol (C-26) |
|---|---|---|
| **LLR-105.1** | `_modifications_lines` **shall** admit at most `MAX_REPORT_ROWS_PER_VARIANT` rows per variant, counted at admission, and **shall** build no intermediate full-population list — the `entries` flattening (`:1071-1075`) and the `kept` filter (`:1080-1082`) **shall** be fused into the single admission pass. | `_modifications_lines` |
| **LLR-105.2** | `_checklist_lines` **shall** admit at most `MAX_REPORT_ROWS_PER_VARIANT` rows **summed across all of the variant's check files**. Once saturated, a subsequent check file **shall** render its heading and aggregates followed by a per-file `> TRUNCATED:` line, and **shall omit** the table header and rule — a reader of check file 3 must not meet an empty table with no local explanation. | `_checklist_lines` |
| **LLR-105.3** | The **byte-run** cells (`Before`/`After`, `Expected`/`Actual`) **shall** be bounded at the **source**, by the count of byte values consumed (`REPORT_BYTES_PER_CELL`), never by slicing an already-rendered string — the rendered string *is* the allocation being bounded. `max_bytes` **shall** be a **required, keyword-only** parameter of `_format_bytes`, matching the module's own policy at `:154-155`. | `_format_bytes` (**signature**; 4 call sites `:1105,:1106,:1280,:1281`) |
| **LLR-105.4′** | *(replaces the withdrawn LLR-105.4 — see P-25)* Every truncation notice **shall** state the **correct** number of rows dropped, where "correct" is the count of rows that **would have rendered** under the active `report_filter`. **No requirement is placed on how that count is obtained** — the withdrawn clause mandated a traversal strategy with no observable consequence, and a requirement whose violation is invisible is not a requirement. | both producers |
| **LLR-105.5** | Every bound that fires **shall** emit one in-document `> TRUNCATED:` notice naming the section, the governing constant and its value, the dropped count and the total. Every byte-run cell that is truncated **shall** carry an in-cell cue stating **how many byte values were not rendered**. A silently shortened byte run in an evidentiary document is a **correctness** defect, not a cosmetic one. | new format constants |
| **LLR-105.6** | The bounds **shall** be module-level named constants; no bare literal of any cap value **shall** appear in either producer body **or in any test asserting them**. | new constants |
| **LLR-105.7** | `_format_bytes` output **shall** satisfy `set(out) ⊆ HEX ∪ {" "} ∪ CUE_ALPHABET`, with `CUE_ALPHABET` a module constant. `tests/test_report_field_census.py::test_f17` **shall** be amended by **widening its closed alphabet to that constant** — never by relaxing it to a blacklist or shrinking its fixture. It is a batch-62 escaping guard that pins *why* byte cells are exempt from escaping. | `CUE_ALPHABET`, `test_f17` |
| **LLR-106.1** | The `Address` cell **shall** render at most `REPORT_ADDRESS_HEX_DIGITS` hex digits. The bound **shall** be applied **without materialising the full hex rendering** — the full string *is* the allocation being bounded — so the implementation **shall** derive the leading digits arithmetically (right-shift by `4·(total_digits − REPORT_ADDRESS_HEX_DIGITS)`) rather than formatting-then-slicing. **Executed as cheap at scale:** `bit_length()` is `O(1)` (limb count, not a scan) and `n >> k` allocates only the result's limbs — at 10⁶ hex digits, shift+format is **0.000002 s** vs **0.0014 s** for a full format. Gated by **AT-229**. | `_modifications_lines`, `_checklist_lines` |
| **LLR-106.2** | A truncated `Address` **shall** render in a form that **fails** `^-?0x[0-9A-F]+$` and **shall** state the number of hex digits elided **from the rendered value**, i.e. `(n.bit_length()+3)//4 − REPORT_ADDRESS_HEX_DIGITS` — **not** `len(raw) − 2`. `int('0x0FF…', 16)` discards wire leading zeros, so the two differ and a predicate written against the raw string mis-fires (re-gate F-3). An untruncated `Address` **shall** be byte-identical to the shipped `f"0x{n:08X}"` rendering. | both producers |
| **LLR-106.3** | `REPORT_ADDRESS_CHARS` **shall** be **derived top-down**, not chosen: `REPORT_ADDRESS_CHARS = len("0x") + REPORT_ADDRESS_HEX_DIGITS + len(cue at the maximum elided count)`. The policy number is `REPORT_ADDRESS_HEX_DIGITS`; the cell width is its consequence. **Deriving bottom-up from the golden census (widest golden Address cell = 10 chars) would put the constant near 10–32 and make AT-226 RED after a correct implementation** — N-1 reproduced on the newest requirement (re-gate F-2). | `REPORT_ADDRESS_CHARS` |
| **LLR-106.4** | The `Address` cue **shall** be inert in the same sense as the byte-run cue: the Address cell is emitted **unescaped** (`:1104`, `:1276`) and `LLR-105.7` covers `_format_bytes` only. The cue **shall not** contain `.` — which **is** in `MD_ESCAPE` (the linkify-fuzzy defuse) and appears in the natural first spelling `… (+99988 more hex digits)`. Use `…` (U+2026), already precedented by `TRUNCATION_MARKER`, and extend `CUE_ALPHABET`'s inertness claim to cover this cue (re-gate F-4). | `CUE_ALPHABET` |

**Withdrawn in revision 3, with reason (§6.5 amendment):** `LLR-105.4` (traversal strategy — P-25,
unfalsifiable) · `LLR-105.9` (cue overshoot — folded into LLR-105.5's cue clause and AT-222's predicate)
· all of `LLR-106.x` from revision 2 (the `_ByteBudget` gate → batch-75) · all of `LLR-107.x`
(D2 → batch-75).

---

## 5. Acceptance (Layer B — black-box through `generate_project_report`)

**The revision-3 authoring rule, applied to every row: the predicate's scope equals the
requirement's scope.** Revision 2's three failures (AT-222, AT-227, AT-231 RED after a *correct* fix)
were all scope mismatches, not logic errors.

| AT | Story / LLR | Observable outcome (written report file) | Reddening mutation (execute on a copy of the FIXED tree) |
|---|---|---|---|
| **AT-220** | 1 / 105.1 | `E = CAP+1` → exactly `CAP` `^\| 0x` rows in that variant's `### Modifications` scope, plus exactly one notice | `>` → `>=` (yields `CAP+1`); or raise `CAP` above `E` |
| **AT-221** | 1 / 105.2 | Same for `### Checklists`, **disjoint** `check_results[].entries` fixture, cap **summed across 2 check files** | cap per-file instead of per-variant → `2×CAP` rows |
| **AT-222** | 1 / 105.3+105.5 | With a `4·REPORT_BYTES_PER_CELL` run: the widest byte-run cell is `≤ 3·REPORT_BYTES_PER_CELL − 1 + len(cue)` — **the predicate quotes the formula, never a literal** — and the cue states the true elided byte count | remove `max_bytes` → cell becomes `3·run − 1`. *(Revision 2's `≤ REPORT_CELL_CHARS` was RED after a correct fix, because `3·171−1` already equals 512 before the cue.)* |
| **AT-223** | 1 / 105.3 | Same for `Expected`/`Actual` | same |
| **AT-224** | 1 / **105.4′** | **Count correctness.** With a `report_filter` matching a strict subset, at `E` such that kept `= CAP+137`, the notice states dropped `= 137` — the **kept** count, not the population | report `len(entries) − CAP` (the population-based count) → states a wrong number. *(This is the falsifiable residue of the withdrawn traversal clause: the count's correctness is observable; the traversal strategy is not.)* |
| **AT-225** | 1 / 105.2+105.4′ | Same, checklist, summed across ≥2 check files, **and** check file 2 under saturation renders heading + aggregates + its own `> TRUNCATED:` line with **no empty table header** | emit the header/rule anyway → an unexplained empty table |
| **AT-226** | **2** / 106.2 | A wire-legal `'0x'+'F'*100000` address renders `≤ len("0x") + REPORT_ADDRESS_HEX_DIGITS + len(cue)` — **the predicate quotes the formula, never the constant's value** (re-gate F-2: quoting `REPORT_ADDRESS_CHARS` alone would go RED after a correct Inc-2, exactly as AT-222 did in revision 2) — **and** the emitted token **fails** `^-?0x[0-9A-F]+$`, **and** its elided-digit count **equals** an independently derived `(n.bit_length()+3)//4 − REPORT_ADDRESS_HEX_DIGITS` | truncate with plain `[:n]` → the token still matches `^0x[0-9A-F]+$` while understating by `2^…`. **This is the forgery, and it is the point of the story.** Separately: state a wrong elided count → the equality reddens (re-gate F-3: revision 3 asserted the count *exists* but never that it is *correct*) |
| **AT-229** | **2** / **106.1** | **Address residency.** `peak(D_hi)/peak(D_lo) ≤ 1.15` with both `D` (hex-digit counts) above the truncation threshold — the §5.1 oracle, unchanged | `format(n,'X')[:K]` → **9.996** (executed). **Why this AT exists (re-gate F-1):** AT-226 constrains only the *emitted token*, so a format-then-slice implementation satisfies all three of its conjuncts while peaking at the full 268 MB rendering — the very transient US-B74-2 exists to close. §5.2 registered *"an Address bound with no form change"* as vacuous; **the symmetric hole — a form change with no residency gate — was unregistered until this re-gate** |
| **AT-227** | 1+2 / 105.x+106.2 | **Positive control.** An under-cap, in-domain, sub-width report is **byte-identical** to today. Golden captured from the **shipped** producer in the Inc-0 pre-flight commit | set `CAP=1` → bytes differ. Also reddens if the untruncated Address rendering changes |
| **AT-228** | 1 / 105.1 | **Resident bound.** `peak(E_hi)/peak(E_lo) ≤ 1.15` with **both** `E` above `CAP` (§5.1) | keep the `entries` flattening → **1.921**; ship unfixed → **9.887** |

### 5.1 The memory oracle — defined, and host-invariant

`peak` = `tracemalloc` peak inside a window opened immediately before the producer call and closed
immediately after, **with the fixture built outside the window**; **both** `E_lo` and `E_hi` strictly
above `MAX_REPORT_ROWS_PER_VARIANT`.

Both points above the cap is what makes it host-invariant: past the cap a correct implementation's
residency is *independent of `E`*, so the ratio is **1.000 by construction on any host**, while any
implementation still linear in `E` scales with `E_hi/E_lo`. The threshold states the property rather
than calibrating to a machine.

| Implementation | ratio at `E: 2·CAP → 20·CAP` |
|---|---|
| SHIPPED | 9.887 |
| CAP-ONLY (keeps the flattening) | 1.921 |
| FUSED (correct) | 1.000 |

**Gate `≤ 1.15`** — 92% band below the nearest defective. **`E_lo > CAP` shall be asserted in the test
body.** Inc-1 **shall** re-derive these three numbers on this tree and paste the transcript (C-39).
**Pre-declared disposition** if the CI runner (ubuntu/py3.11) puts a correct implementation above 1.15:
re-derive the threshold from that run and record the change — **never widen it until green**.

### 5.2 Rejected as vacuous — the register (carried + extended)

batch-63's `raw == document_bytes(raw.decode())` identity · consumption counters as the OB-4 gate
(invariant — traversal continuation has no observable consequence, **P-25**) · whole-report residency
(unsatisfiable, P-23) · *"a huge **address** denies the report"* (**false**, P-20) ·
`Length.startswith("0x")` (accepts `0x-1000`, rejects `-0x1000`) · `Length.isdigit()` (a bare-hex
forgery satisfies it) · hard-coded 3572 · one AT covering both axes (mutually invariant) · one AT
covering both sites (disjoint inputs) · **`AT-222 ≤ REPORT_CELL_CHARS`** (RED after a correct fix —
`3·171−1` already equals 512) · **an Address bound with no form change** (closes memory, opens forgery).

### 5.3 Decisions carried unchanged from revision 2

**D-2 cap = 200** — max single `(document,variant)` golden table is exactly 200, so **0 goldens drift**;
the module states its one-number policy twice (`:93-95`, `:107-110`). The "off-by-one sentinel is a
feature" framing stays **struck**; the coupling is recorded in the constant's docstring plus a sibling
assertion in this batch's own file. **D-3 `REPORT_BYTES_PER_CELL = (REPORT_CELL_CHARS + 1) // 3 = 171`**
— a *derived* constant, not a fourth policy number; `3·171−1 = 512` exactly. Cue form
`01 AB … (+837 more bytes)`: distinct from `TRUNCATION_MARKER`, contains no `|`, inert against
`MD_ESCAPE`, and **states a count**. **`REPORT_ADDRESS_CHARS` is NEW and its value is not yet chosen** —
Inc-2 derives it with its golden blast radius executed (widest golden Address cell is 10 chars).

---

## 6. Residual discharge — what this batch does NOT close

**This batch closes OB-4 and the Address width. Nothing else.** Any memory claim over
`report_service` as a whole would be false while these stand:

| Residual | Owner | Measured |
|---|---|---|
| **The document is not budget-bounded** — five producers stay on the ungated `emit`: `_modified_files_lines` (`:2242`), `_declaration_error_lines` (`:2244`), `_entropy_lines` (`:2250`), `_addendum_lines` (`:2252`), hexdump notes | **batch-75 (F4)** | `_declaration_error_lines` alone = **315,912 B/variant**; floor `2,097,152 + V×315,912` → **16.06× budget at V=100** |
| The variant count `V` and the per-variant check-file count `F` have **no cap anywhere** | batch-75 | `O(V×F×7)` structural lines ungated |
| **D2** — the decimal `Length` raises on a constructor-domain value, and `app.py` reports it in the **operator-input-rejection** branch | batch-75 | **Unreachable via the shipped ingestion path** (`addressed_range` bounds Length to 7 digits) — which is why it is safe to defer |
| `_applied_regions` (`:1288`) is a **third unbounded producer** | not chartered | peak `16,128 → 160,992` at `N=2000→4000` |
| `options.declared_regions` has no cardinality cap · the relocated `O(R)` walk · intra-class eviction **disclosed not prevented** | R-TUI-098 | unchanged |
| Truncation notices do not reach `## Truncation appendix` — **our new emitters make it 3 → 4** | carried | following `_declaration_error_lines`'s inline-only convention |
| **NEW:** above the cap the report is not a **complete** record of a variant's modifications, and the Modifications table has **no second sink in the report** | R-TUI-101 | the notice says so; the change summary is the complete record |
| D-11 host-path redaction · `diff_report_service` · batch-73's `apply.py` | fenced out | — |

---

## 7. Increment cut

| Inc | Files (≤5) | Content | ATs | TCs |
|---|---|---|---|---|
| **0** | `tests/goldens/batch74/` **only** | Pre-flight commit: capture AT-227's golden from the **shipped** producer. Separate commit so C-12 ordering is auditable via `git log --diff-filter=A` | — | — |
| **1** | `report_service.py`, `tests/test_report_producer_bound.py` (new), `tests/test_report_field_census.py` | Constants + `CUE_ALPHABET`; `_format_bytes(values, *, max_bytes)` **with all four call sites updated in the same commit**; `_modifications_lines` single-pass. `test_f17` amended by **widening** its closed alphabet (LLR-105.7) | 220, 222, 224, 227, 228 | **TC-521** 105.1 cap arms `{CAP−1,CAP,CAP+1}` · **TC-522** 105.3 width in/out of cap · **TC-523** 105.4′ count correctness under filter · **TC-524** 105.5 notice names the constant, its value **and the total** *(re-gate F-5: revision 3 asserted only the dropped count)* · **TC-525** 105.6 **AST/source guard: no bare cap literal in either producer body or in any new test** *(re-gate F-5 — the clause governs the producer body and had no gate)* · **TC-526** the §5.1 oracle re-derivation transcript |
| **2** | `report_service.py`, `tests/test_report_producer_bound.py` | `_checklist_lines` cap + per-file saturation rendering; `REPORT_ADDRESS_HEX_DIGITS` chosen and `REPORT_ADDRESS_CHARS` **derived from it** (LLR-106.3), then the Address bound + unforgeable form + inert cue at both sites | 221, 223, 225, 226, **229** | **TC-527** 105.2 cap summed across check files · **TC-528** 105.2 per-file saturated rendering omits header/rule · **TC-529** 106.1 arithmetic derivation, no full materialisation · **TC-530** 106.2 elided count vs `(bit_length()+3)//4`, incl. the **leading-zero** case `int('0x0FF…',16)` · **TC-531** 106.3 the constant equals its derivation · **TC-532** 106.4 cue alphabet inert, contains no `.` and no `|` |
| **3** | `REQUIREMENTS.md`, `.dev-flow/BACKLOG-CODE.md` | R-TUI-101 + its non-claims; the R-TUI-097/098 amendments; **the batch-75 split written into the backlog with every measurement above** | — | — |

**TC-533 stays** in `tests/test_report_addendum_bound.py:793` untouched, labelled **"PIN + boundary
sentinel"**. **Every AT (220-229) and every TC (521-532) has exactly one owning increment; no orphan.**

**Authoring note for AT-222 and AT-226 (re-gate check 4):** derive `len(cue)` from the *independently
known* elided count — for AT-222, `4·B − B = 3·B`; for AT-226, `(n.bit_length()+3)//4 −
REPORT_ADDRESS_HEX_DIGITS` — **never from the emitted cell**, or the predicate is circular.
