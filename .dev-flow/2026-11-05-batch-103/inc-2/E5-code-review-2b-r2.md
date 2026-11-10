# Inc 2b E5 — code review, re-review round 2 (narrow: F-1, F-2, .138/21, .138/14)

**Verdict: PASS (narrow scope).** Both blocking findings from round 1 are resolved in the
product model at `ce1aa0ec` (fix commit "bound overlap candidate scans"; actual branch HEAD
is `8718715f`, which adds only test files — `git diff ce1aa0ec 8718715f --stat` shows
`tests/` only — so the product model under review is identical to `ce1aa0ec`). The new
hostile case `.138/21` and the strengthened `.138/14` are discriminating and correctly
pinned. Runner evidence confirms `.136` at **1.212 s**, final model **308 passed**, stub
RED **114 failed + 194 passed**. Integration is still gated on one evidence item the
runner owes: the final law-guard run is truncated and the completed run carries one
test-hygiene failure (B-1 below). Two LOW spec-precision notes (R-1, R-2) are non-blocking.

## Executed vs read-only

- **Executed:** nothing. Read-only re-review on Windows, same constraint as round 1.
- **Read (source):** `s19_app/tui/a2l_definition.py` `_shared_with` (:3543-3584) and the
  span-index build (:674-684) in the working tree; `git diff cb083d07 ce1aa0ec` and
  `git diff ce1aa0ec 8718715f` for that file; `s19_app/tui/a2l.py` `extract_declared_spans`
  (:3894-3965) and `_bounded_length` (:354-360).
- **Read (tests):** `tests/test_b103_a2l_definition.py` `.138/13`, `.138/14`, `.138/15`,
  `.138/17`-`.138/21` (:3215-3308); requirements/case-ledger rows via the working-tree
  diff of `01-requirements.md` and `codewire/graph-inc2.md`.
- **Read (runner evidence):** `evidence-e4/int2b-perf-fix-136-final.txt`,
  `int2b-run5-main.txt`, `int2b-red-stub-final4-main.txt`, `int2b-lawguards.txt`,
  `int2b-lawguards-final.txt`.

## F-1 — RESOLVED (was HIGH, blocked integration)

The working-tree `_shared_with` (`a2l_definition.py:3561-3584`, identical to `ce1aa0ec`
and to HEAD) replaces the broken page-level tail with a correct nested scan. Confirmed
point by point:

1. **Every entry visited.** The overlap test is inside `for page: for entry:` — every
   entry of every page the span touches is examined, not just each page's last entry.
   Round-1 defect 1 (the clobbered non-last neighbour) is gone.
2. **Own entry skipped exactly once.** `own_entry` flag (:3563) with a five-field tuple
   match name/kind/section/address/byte_length (:3571-3577); the flag clears after the
   first match, so a second value-identical tuple is still treated as a candidate.
   Round-1 defect 2 (self-named `shared_with`) is gone.
3. **File order within a page.** Page lists are appended during the single pre-order walk
   with monotonic positions, so each page's list is in walk order and the first
   overlapping entry per page is the file-first one. The old `candidates.sort` is gone,
   but see R-1 for the cross-page caveat.
4. **The structure matches the approved design again** — the scan is the E3-close
   "first overlapping entry" guard, and `.138/19` (`Z1`/`Z2` at 0x0) plus the strengthened
   `.138/14` pin the own-entry-skip and non-last-neighbour arms directly.

## F-2 — RESOLVED as "landed deliberately" (was MEDIUM)

The 16-byte page size is committed in `ce1aa0ec` in **both** the index build
(`:678-682`) and the lookup (`:3557-3560`) — the two sides stay consistent, so there is
no index/lookup mismatch. The round-1 correction's second option was taken: the design
record now states "Entries are filed under each 16-byte page they touch and sorted by
their section-walk position (the page size is an internal bound only; R-A2L-DEF.136 is
measured with it)" (`graph-inc2.md` `describe_definitions`), and `_shared_with`'s row
documents the single-page optimization. The attached re-measure condition is satisfied:
see `.136` below. No residual deviation.

## Requested confirmations (all checked against `:3555-3584`)

| Claim | Status |
| --- | --- |
| Every entry visited, in file order | **Yes per page** (walk-order lists, full nested scan). Cross-page order is page-ascending, not global file order — see R-1. |
| Own entry skipped exactly once | **Yes** — `own_entry` flag, first match only (:3571-3579). |
| Single-page dedup avoided | **Yes** — `multi_page = len(pages) > 1` (:3562) guards both the `seen` lookup and `seen.add`; a single-page lookup performs no set work at all. |
| Multi-page dedup uses entry position | **Yes** — `key = entry[0]` (:3567), the walk position; first occurrence wins, and position is stable across calls (stronger than the old `id(entry)`). |
| `.136` measured at 1.212 s | **Confirmed** — `int2b-perf-fix-136-final.txt`: "39.4% 1.212 s / 2.000 s R-A2L-DEF.136 describe 13990 … 1 passed". Within the ≤ 2.0 s bound with margin. |
| Final model 308 passed | **Confirmed** — `int2b-run5-main.txt` (00:38:51, after the final perf run): "308 passed in 11.06s". |
| Stub RED = 114 failed + 194 passed | **Confirmed** — `int2b-red-stub-final4-main.txt`: "114 failed, 194 passed in 23.67s" (308 total, matching the final model's test count). |

## .138/21 — the new hostile case (verified)

`test_r_a2l_def_138_21_hostile_blob_and_instance_headers` (:3288-3308) is hostile in the
right place and discriminating:

- `TYPEDEF_BLOB TB` size of 5,000 decimal digits → `_instance_length` → `_bounded_length`
  (`a2l.py:354-360`) returns `None` above 1,048,576 bytes, so `INSTANCE I1` keeps its
  declared address 0x10 with **no readable length** — a fail-closed point, filed on a
  single page. No page-range blow-up is possible anywhere: the index build's
  `range(first_page, last_page + 1)` (`:680`) only ever sees `_bounded_length`-clamped
  lengths, and `_shared_with`'s `len(pages)` is O(1) on a `range`.
- The file-order consequence is pinned three ways: `V1.shared_with == "I1"` (via the
  declared-address-inside rule for a length-less neighbour), the exact
  `A2L-DEF-OVERLAP "V1: its bytes at 0x10 are shared with I1"` message on encode, and
  `_no_exception_encode` (0 exceptions).
- The **alone arm** isolates the huge-address `BLOB B1` (`0x` + 5,000 `F`, size 2):
  `V1` encodes cleanly, proving the giant address neither lands on page 1 nor poisons
  the scan. (Doc wording imprecision noted as R-2 — the BLOB *is* indexed, on a page
  `V1`'s span never touches; the pinned behaviour is correct.)
- The requirements ledger and the `.138` graph row were updated in the same changeset
  (`21/21`, the `/21` example line), so the case is traceable.

## .138/14 — strengthened (verified)

(:3228-3238) now asserts the mutual `shared_with` (`OA`↔`OB`, `OC` `None`) **and** both
exact encode-time `A2L-DEF-OVERLAP` messages. It discriminates the round-1 bug: under the
old shape the own-entry skip fired at page level, so `ob.shared_with` was `None` instead
of `"OA"`. Under the new code `OC` (0x30, a different 16-byte page from 0x10/0x11) is not
even a candidate, which also documents the page-granularity consequence of F-2's landing.

## Remaining blockers and notes

### B-1 — law-guard evidence is not clean (evidence, blocks integration sign-off)

Round 1 deferred the law guards to the runner. The completed run
(`int2b-lawguards.txt`) shows **504 passed, 1 failed, 1 skipped**, and the single failure
is `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — a
test-suite hygiene failure (a committed evidence file carries a home path / LAN
address), **not** an engine/product regression; the engine-frozen and direction-B guards
pass. The follow-up `int2b-lawguards-final.txt` is **truncated mid-run** (6 lines, two
`F` marks in the progress dots, no summary) and cannot serve as final evidence.
**Correction:** scrub the offending path from the committed evidence, re-run the law
guards to a clean summary, and keep that file as the final record.

### R-1 — LOW: cross-page scan order is page-major, not global file order (spec precision)

`graph-inc2.md` `_shared_with` still says "the first other entry, in cross-kind file
order" and now adds "Scan in file order". The implementation scans pages ascending,
entries in walk order *within* a page. For a multi-page span with non-exempt candidates
on different touched pages, the named neighbour is the lowest-page one, not necessarily
the file-first one (the `cb083d07` global `sort` by position guaranteed it; `ce1aa0ec`
dropped it). No requirement row pins which neighbour is named when several overlap, and
every pinned `.138` case is single-page or single-candidate, so nothing observable
regresses — but the doc sentence overclaims. **Correction (either):** tighten the doc to
"first overlapping entry in scan order — pages ascending, file order within a page", or
restore the position sort for the multi-page branch only (cost is negligible next to the
dedup set).

### R-2 — LOW: `.138/21` doc wording ("is not indexed") is imprecise

`B1` *is* in the index, filed under page `0xFFF…F >> 4`; it simply never shares a page
with `V1`'s span, and `_bounded_length` keeps every page range finite. Behaviour is
correctly pinned by the test; only the one-line description in `01-requirements.md` and
the graph encode row should say "indexed out of reach of the span" rather than "not
indexed".

## Housekeeping note

The design/requirements updates answering F-2 and adding `/21` (`01-requirements.md`,
`codewire/graph-inc2.md`) are modified in the working tree but **uncommitted**; they
should be committed with the increment so the record matches the landed code.
