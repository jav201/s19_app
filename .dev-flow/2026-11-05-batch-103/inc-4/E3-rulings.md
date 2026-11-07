# Inc 4 — E3 round 1 rulings (2026-11-06T19:14:41-06:00, orchestrator Opus 5.5)

Round 1: `E3-architect.md` **FAIL** (2 MAJOR, 2 MEDIUM, 3 MINOR, 2 LOW, 2 INFO); `E3-security.md` **FAIL** (2 MAJOR, 2 MEDIUM, 1 MINOR, 2 LOW, 1 INFO). The shape stands (I-3 suits Inc 7; compact index; total, deterministic order; D-4 / D-5 exact); the bounds held only on REF × QSET. Every finding is **accepted with its fix column**, with these rulings:

| Finding | Ruling |
|---|---|
| E3A-01 + E3S-02 MAJOR (case-exactness over unbounded groups; case_06 at 554–755 ms) | accept the measured fix: case-exactness decides ties only for the exact, prefix and substring rules (this changes R-A2L-MATCH.24's case /3 — ruled here); R-A2L-MATCH.36 gains a second reference list, the first 50,000 names of `examples/case_06_large_nested_a2l/firmware.a2l`, with the slow queries of both reviews in its query set. |
| E3A-02 MAJOR (fuzzy tier walks the trie once per query word) | accept the measured fix: per-word maps built lazily (same lists); worst 71 ms on REF, 86 ms on case_06. |
| E3S-01 MAJOR (no query length limit; 64 KiB paste → MemoryError) | accept: new row **R-A2L-MATCH.38** — `If the query text holds more than 256 characters, then the system shall return an empty list.` (threshold, negative control and cases per the fix column); the worst pasted-list shapes join the query set; the fuzzy tier stops when no candidate is left. The paste modal (Inc 7) splits a pasted list into names and ranks each name, never the whole paste as one query — note for Inc 7's E1 (PLAN). |
| E3A-07 (slice) | accept: `E1-slice.md` maps the +8 functions and +1 type. |
| E3A-05 (E2-5 in the definitions) | accept: the code-point comparisons are stated in the definitions. |
| all other findings | accept with their fix columns; INFO noted. |

**Next:** one correction pass (rows and cases; graph), then a round-2 re-check of the blocking findings by both reviewers, each re-running its probe on the corrected design's pilot.
