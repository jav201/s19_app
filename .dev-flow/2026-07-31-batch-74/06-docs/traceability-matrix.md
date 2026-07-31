# Traceability Matrix — s19_app — Batch 2026-07-31-batch-74

**`R-TUI-101`** · 2 US · 2 HLR · **11 LLR** · 11 AT (incl. 4 residency) · 15 TC · **LLR coverage 11/11 = 100 %**

## 0. Read first — the state of the chain

Every LLR has at least one gating node, and **every bounded surface has a residency oracle with a
paired falsifier**. That second property was **not** true when the batch reached its PR gate: three of
four surfaces were gated and `_checklist_lines`' cardinality was not. `AT-241b`/`TC-546b` closed it
before merge. The matrix below is the post-discharge state.

**Two node kinds, kept distinct.** An **output-shaped** predicate reads the written document; a
**residency** predicate reads `tracemalloc` peak. For the bounds in this batch the two are *not*
interchangeable — a `format-then-slice` implementation is byte-identical, so no output-shaped row below
can gate a "where is the bound applied" clause. Rows are marked accordingly.

## 1. Master table

| US | HLR | LLR | Nodes | Code | Test | Kind | Status |
|---|---|---|---|---|---|---|---|
| US-B74-1 | HLR-105 | **LLR-105.1** cardinality cap on `_modifications_lines`, no full-population list | AT-240, **AT-248**, TC-540, TC-545 | `report_service.py::_modifications_lines` | `test_at240_…`, `test_at248_…`, `test_tc540_cap_arms`, `test_tc545_…` | output + **residency** | pass |
| US-B74-1 | HLR-105 | **LLR-105.2** `_checklist_lines` cap SUMMED across check files; saturated file omits header/rule | AT-241, **AT-241b**, AT-245, TC-546, **TC-546b**, TC-547, TC-547b | `report_service.py::_checklist_lines` | `test_at241_…`, `test_at241b_…`, `test_at245_…`, `test_tc546_…`, `test_tc546b_…`, `test_tc547_…` (×2), `test_tc547b_…` | output + **residency** | pass |
| US-B74-1 | HLR-105 | **LLR-105.3** byte-run cells bounded at the SOURCE; `max_bytes` required + keyword-only | AT-242, AT-243, **AT-242b**, TC-541, TC-545b | `report_service.py::_format_bytes` (+ 4 call sites) | `test_at242_…`, `test_at243_…`, `test_at242b_…`, `test_tc541_…`, `test_tc545b_…` | output + **residency** | pass |
| US-B74-1 | HLR-105 | **LLR-105.4′** every notice states the CORRECT dropped count (kept, not population) | AT-244, AT-245, TC-542 | both producers | `test_at244_…`, `test_at245_…`, `test_tc542_…` | output | pass |
| US-B74-1 | HLR-105 | **LLR-105.5** one `> TRUNCATED:` notice naming section, constant, value, dropped, total; in-cell cue states the elided byte count | AT-242, TC-543 | `ROW_TRUNCATION_NOTICE_FMT`, `REPORT_BYTES_TRUNCATION_CUE_FMT` | `test_at242_…`, `test_tc543_…` | output | pass |
| US-B74-1 | HLR-105 | **LLR-105.6** bounds are module constants; no bare cap literal in the producers or their tests | TC-544 | `MAX_REPORT_ROWS_PER_VARIANT`, `REPORT_BYTES_PER_CELL` | `test_tc544_…` (AST walk, not grep) | source | pass |
| US-B74-1 | HLR-105 | **LLR-105.7** `_format_bytes` output ⊆ `HEX ∪ {" "} ∪ CUE_ALPHABET`; `test_f17` **widened**, never relaxed | `test_f17` | `CUE_ALPHABET` | `tests/test_report_field_census.py::test_f17` | closed alphabet | pass |
| US-B74-2 | HLR-106 | **LLR-106.1** `Address` bounded at `REPORT_ADDRESS_HEX_DIGITS`, derived ARITHMETICALLY | **AT-249**, TC-548 | `report_service.py::_format_address` | `test_at249_…`, `test_tc548_…` | **residency** | pass |
| US-B74-2 | HLR-106 | **LLR-106.2** truncated `Address` FAILS `^-?0x[0-9A-F]+$` and states the elided count from the VALUE; untruncated is byte-identical to `f"0x{n:08X}"` | AT-246, TC-549, TC-549b | `_format_address`, both call sites | `test_at246_…`, `test_tc549_…`, `test_tc549b_…` | output | pass |
| US-B74-2 | HLR-106 | **LLR-106.3** `REPORT_ADDRESS_CHARS` derived TOP-DOWN from the policy number | TC-550 | `REPORT_ADDRESS_CHARS`, `REPORT_ADDRESS_MAX_ELIDED_DIGITS` | `test_tc550_…` (derivation equality + anti-bottom-up census arm) | source | pass |
| US-B74-2 | HLR-106 | **LLR-106.4** the `Address` cue is inert — no `.` (in `MD_ESCAPE`), no `\|` | TC-551 | `REPORT_ADDRESS_TRUNCATION_CUE_FMT` | `test_tc551_…` (asserted against the REAL `MD_ESCAPE`) | closed alphabet | pass |
| both | — | **positive control** — an under-cap, in-domain, sub-width report is byte-identical | AT-247 | whole pipeline | `test_at247_…` vs the Inc-0 golden | byte identity | pass |

## 2. Coverage

| | |
|---|---|
| US total / ready / covered | **2 / 2 / 2** |
| HLR total / covered | **2 / 2** |
| **LLR total / covered** | **11 / 11 = 100 %** |
| AT | 11 (AT-240…249 + AT-241b/242b) |
| TC | 15 (TC-540…551 + TC-545b/546b/547b/549b) |
| **Bounded surfaces with a residency oracle** | **4 / 4** ← was 3/4 at the PR gate |

## 3. Withdrawn, with reason — recorded so nobody re-derives them

| Withdrawn | Reason |
|---|---|
| `LLR-105.4` ("traversal shall not terminate") | **UNFALSIFIABLE** (P-25): one-pass and precount-then-break produce byte-identical documents *and* identical `tracemalloc` ratios. Replaced by `LLR-105.4′`, a requirement on the count's **correctness**, which is observable |
| `LLR-105.9` (cue overshoot) | Folded into `LLR-105.5` and AT-242's predicate, which now quotes the **formula** — `3·B − 1` already equals `REPORT_CELL_CHARS`, so the old form was RED after a correct fix |
| all revision-2 `LLR-106.x` (the `_ByteBudget` gate) | Split to **batch-75** (F4) |
| all `LLR-107.x` (D2) | Split to **batch-75**; its headline premise is **FALSE** (P-20) |

## 4. The chain's own weak point, stated

**Every "pass" above is a pass against a predicate, and three independent reviews found predicates in
this batch that could not fail.** The matrix is therefore a map of what is *gated*, not a proof of what
is *correct*. The rows that carry real force are the four **residency** rows and AT-247 — the ones
whose falsifier was executed against a byte-identical defective implementation.
