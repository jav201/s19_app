# batch-74 — Close-out

**`R-TUI-101`** · merged **`537f27d`** (PR [#173](https://github.com/jav201/s19_app/pull/173), squash) ·
2026-07-31

## 1. Merge record

| | |
|---|---|
| **PR** | [#173](https://github.com/jav201/s19_app/pull/173) — `batch-74 — report producer bounding + the Address cell (R-TUI-101)` |
| **Squash** | `537f27d`, onto `093ff8e` |
| **Branch** | `claude/batch-74-s19-app-a693ff` — 18 commits, retained (not deleted) |
| **CI on the merged head** | `tui-ci` **pass 37m30s** · `snapshot` **pass 1m41s** |
| **Local gate suite** | `pytest -q` (full, `slow` included): **2436 passed, 2 skipped, 3 xfailed**, 29 snapshots, 30m38s |
| **Rebases** | **two**, both clean: onto `de905f6` (batch-73 merged) and onto `093ff8e` (PR #172). File-disjointness held exactly as predicted both times |
| **Post-merge doc integrity** | verified **on `main` itself**, not on the branch: `R-TUI-101` ×1, its heading ×1, the batch-75 charter ×1, no duplicated "Last refresh" headers |

## 2. What shipped

| | |
|---|---|
| Production files | `s19_app/tui/services/report_service.py` — **one file** |
| Test ledger | `tests/test_report_producer_bound.py` **0 → 33**; `test_report_field_census.py::test_f17` amended by **widening** a closed alphabet |
| Goldens re-baselined | **0** |
| Frozen-engine diff | **0**, both guards |
| Requirement | `R-TUI-101`, with **seven explicit non-claims**, each carrying its executed number |

## 3. Gate history — three independent passes, three BLOCKs

| Gate | Result |
|---|---|
| Phase 2 (architect · qa · security, blind to each other) | **ITERATE ×2** → iteration cap → **escalated to the operator**, who re-scoped |
| Inc-1 review | **BLOCK** — `F1` HIGH: the width axis shipped with no falsifier |
| Inc-2 review | **BLOCK** — `F1`+`F2` HIGH: **5 of 16 mutations survived** a 29-node suite |
| **Final PR gate** | **BLOCK** — `H-1` HIGH: the **fourth** bounded surface had no residency oracle |

**Every one of those BLOCKs was on an acceptance, never on the code.** No implementation bug was found
at any gate, by any reviewer, at any point in this batch.

## 4. Residuals — chartered, measured, and not lost

`.dev-flow/BACKLOG-CODE.md` carries the **batch-75 charter** with every measurement the split depends
on. Verified by the final gate as complete (`315,912` · `16.06×` · `2,097,152` · `16,128 → 160,992` ·
`3572` · `831` · the `O(V×F)` term · the truncation-appendix carry).

| Residual | Owner |
|---|---|
| **F4** — the document is not byte-bounded; `emit()` **accounts, never gates** | batch-75 |
| `V` and the per-variant check-file count `F` have no cap anywhere | batch-75 |
| **D2** — the inline `Length` cell + the `app.py` re-attribution. ⚠ **Its headline premise is FALSE** and there is **no `_format_length` symbol** — whoever takes it must CREATE the formatter | batch-75 |
| `_applied_regions` — a third unbounded producer | not chartered |
| **`TC-497` cannot tell an assertion from its refutation** — NEW MAJOR, executed | `BACKLOG-CODE.md` |
| Four `R-TUI-101` wording carve-outs found by implementing | `BACKLOG-CODE.md`, P3 |
| **Vacuous FIXTURES** as a control candidate (not encoded — needs operator approval) | `BACKLOG-PROCESS.md` |

## 5. The two things worth carrying out of this batch

**1. An output-shaped predicate cannot bound an allocation, and the gap is byte-identical.** Executed
on *three* surfaces, each time with the defective shape emitting identical output:

| Surface | Output under the defect | Residency |
|---|---|---|
| byte-run width | identical — 7 nodes green | 9,490 B → **56,683,416 B (5,973×)** |
| `Address` | identical — AT-246's *three* conjuncts green | 1.000 → **9.976** |
| checklist cardinality | identical — **all 31 nodes green** | 1.000 → **9.087** |

**2. The batch kept finding this defect one level up from wherever it had just fixed it.** Inc-1 fixed
it in the code and left it in the width acceptance. Inc-2 fixed the acceptance and left it in the
fixture *shape*. The post-mortem described the whole pattern and then **committed it in its own BLUF**,
asserting "every bound is gated" from three confirming instances without enumerating the fourth. Each
was caught by an independent pass, never by the author — including the last one, which was caught by a
reviewer that **enumerated the producers** instead of reading the claim.

## 6. Honest residue

- `REPORT_ADDRESS_HEX_DIGITS` has **no in-domain exercise** — every real address is 8 digits.
- The `services → changes.io` import is **new coupling**, taken to make `LLR-106.3`'s derivation
  reproducible.
- **`R-TUI-101` is a deliberately bounded claim.** Reading it as "the report is now memory-safe" is
  wrong: the document is still not byte-bounded, `V` and `F` are still uncapped, `_applied_regions` is
  still unbounded.
