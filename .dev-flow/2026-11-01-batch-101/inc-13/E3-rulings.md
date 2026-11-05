# Inc 13 — E3 rulings, round 1 (orchestrator, 2026-11-05)

Inputs: E3-architect.md (FAIL: A-1, A-2 MAJOR in the test records; A-3…A-8 MINOR; product design approved, equivalence measured on the LAN Linux host), E3-security.md (PASS-WITH-NOTES: SEC-1, SEC-2, SEC-3 MEDIUM; SEC-4…SEC-7 LOW; SEC-8…SEC-10 INFO). Round 2 re-checks A-1, A-2, SEC-1, SEC-2 only.

| Id | Ruling |
|---|---|
| A-1 (MAJOR) | D-2 no longer cites R-TST-049. The evidence that the 12 nodes and 3 helpers changed only by their inserted waits is an E5 check: an AST compare of each against `b7b77c4` after stripping the inserted wait statements, delivered as a test node in the new test file (preferred) or a force-added transcript. |
| A-2 (MAJOR) | R-CRC-DESIGNER-001.2.2/1, /2 and 007.1/1 become clock-free: inject Q = 10 s to prove "not before" (count +0, timer pending); inject Q = 0.05 s and wait until the count advances to prove "after"; the burst is 5 back-to-back edits, wait for the recompute, pause 0.8 s, expect exactly +1. The quiet time is injectable (a module constant read at schedule time). Negative controls unchanged. |
| A-3 | The T6 wait is "count above a snapshot taken before the edit" with `pause_first=True`; the case text and the helper use the same definition. |
| A-4, A-5 | 002.2's Base column says ~5.2 s (fill refused on conflict abort); add one arm timing a text edit with concat active (head ~1.12 s measured) on the LAN host. |
| A-6 + SEC-2 | The image watcher marks the coverage dirty while the Designer section is hidden and recomputes when it is next shown (new row, next free id, with its case). A coverage whose total size exceeds a cap shows `Cannot preview: coverage exceeds <cap> bytes` instead of building it (new If-row with the exact text; cap value set from the LAN measurement, provisional 64 MiB). |
| SEC-1 | Line 1 of the coverage window is sized from min start / max end, and each run is capped at `_COVERAGE_WINDOW_GLYPHS`: out-of-order and hostile ranges draw a bounded line (new row with exact expected glyph counts for the reverse-typed F-23 ranges and the hostile 3-range input). This changes the drawing only for out-of-order input, which today hangs or crashes. |
| SEC-3 | D-4 (stale coverage after an in-place apply) gets integrity priority: it goes into **Inc 5** (first in the `app.py` chain) with the test "designer CRC after the apply equals `zlib.crc32` of the new bytes". Recorded in PLAN. |
| A-7 | D-1's evidence is `tests/test_crc_kernel.py:108-138` (vectors include `bytes(range(256))`), not the Inc 8 grid tests. |
| A-8 + SEC-5 | `crc_lut` uses `bytes(memoryview(data))` (an int raises `TypeError` as on base). |
| SEC-6 | `_conflict_marks` builds the pattern with `re.escape(bytes([pad]))`, documents the 0–255 precondition, and a test compares all 256 pads against `reference_conflict_marks`. |
| SEC-4, SEC-8 | `_recompute` stays argument-less, `_CoverageRun` a local; `_pending_recompute = None` is the first statement of `_recompute`. |
| SEC-7 | The alternating pad/non-pad image goes to the existing band-cell backlog item as a test input. |
| SEC-9 | The new matrix test includes a hostile Ranges state (verbatim payload). |

Runs and measurements: LAN Linux host only (operator rule).
