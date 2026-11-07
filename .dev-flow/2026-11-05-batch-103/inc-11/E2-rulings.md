# Inc 11 — orchestrator rulings on the E2 graph (2026-11-06T22:45:43-06:00, Opus 5.5)

Graph: 32 nodes (8 new, 16 changed — 15 in `a2l.py`, 1 in `app.py` —, 1 removed, 5 context, 2 test/evidence); every row exemplified; streaming lexer (the naive one failed R-A2L-READ.52 at 2.04×; this shape projects 1.37× / 1.34×); no batch-101 overlap. Corpus classes 1–7 and Latin-1 reproduced as synthetic reductions on the base reader.

| Item | Ruling |
|---|---|
| I-11.1 (section content canonical, no comments; new keys `meta_line`, `line_numbers`) | **accepted** |
| I-11.2 (`declared_spans` in the payload) | **accepted** |
| I-11.5 (`extract_a2l_tags(..., errors=None)`) | **accepted** |
| I-11.8 (Inc 2a / 2b / 3a work; Inc 2a tests on comment shapes and `UNKNOWN` flip) | **accepted:** Inc 11's E4 tester re-points every Inc 2a test that pinned a reader defect (listed in the graph), each with the row that now holds; Inc 2b and 3a pick up the canonical sections at their own E2/E4. |
| Deviations (8 new functions; streaming lexer; three helpers unchanged; `_strip_a2l_comments` kept for Inc 3) | **accepted** |
| CG-1 | **accepted** (the class reductions join READ.48/2 and the named thresholds) |
| CG-2 | **accepted:** R-A2L-016 / 017 become *cited (code to meet)* with the CTX-A2L-TAG term *datatype (CHARACTERISTIC)* = the FNC_VALUES datatype of its record layout; resolves F-E2-7 and TC READ.43/2 (F-E2-5). |
| CG-3 | **accepted:** new row **R-A2L-READ.53** as proposed. |
| CG-4 | **routed to Inc 3a** (CURVE/MAP/CUBOID/CUBE_4/CUBE_5 lengths; AXIS_DESCR header on its `/begin` line, BL-I11-2; the RECORD_LAYOUT components the fixtures lack); noted in `../inc-3/E2-rulings.md`. |
| CG-5 | **A** (no second decode: a non-UTF-8 byte is U+FFFD; inside a word READ.4's error; the E5 corpus run counts them). |
| CG-6 | **accepted** (E5 evidence run on the 158 manifest files, sha256 checked first, runner only). |
| F-E2-3 | READ.39's threshold counts what is reachable (`LENGTH -5` is not a number word): 4/4, with the reason. |
| F-E2-2 | **to E3** (how READ.50's "header" is read). |

**Next:** a short Opus E1 addendum (CG-1/2/3, F-E2-3/5 in the records), then E3 (architect + security) on Inc 11.
