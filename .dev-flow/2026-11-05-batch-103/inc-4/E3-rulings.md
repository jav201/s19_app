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

## Round 2 rulings (2026-11-06T20:00:09-06:00, orchestrator Opus 5.5) — E3 done

Round 2: architect **PASS-WITH-NOTES** (E3A-01, -02 closed and measured: worst 110.0 ms REF, 78.5 ms REF6, build 1.788 s, peak 18.5 MiB, 0 oracle mismatches); security **PASS-WITH-NOTES** (E3S-01, -02 closed: 64 KiB paste → empty in 45–70 ms; 0 exceptions, 0 bad spans, 4 hash seeds identical). **E3 is done for Inc 4.** The notes are applied before E4 as addenda (records and graph, one Opus pass, no further round):

| Addendum | Findings | Ruling |
|---|---|---|
| A-1 | E3A-12 = E3S-10 | Delete "at a boundary offset" from step 6: substring case-exactness is "anywhere", as the CTX term says; add case .24/4 that tells the two apart. |
| A-2 | E3A-13 = E3S-09 | Duplicate query tokens are collapsed before ranking (same lists; ≤ 55 ms measured). **The open question is ruled:** R-A2L-MATCH.36 keeps its 200 ms bound for the fixture query sets (the realistic typed-name shapes of both reference lists); a new row **R-A2L-MATCH.40** bounds every query the system ranks: `When the system ranks a prepared name list of 50,000 names for any query of at most 256 characters, the system shall return the ranked list within 1.0 s.` (pathological shapes of both reviews — repeated, distinct near-tokens, 256-character — as its cases; measured worst after A-2 about 461 ms; negative control: no duplicate collapse → `'0 ' × 128` over REF6 > 1.0 s → RED). The UI never freezes past 1 s; the typed-name experience keeps 200 ms. |
| A-3 | E3S-11 | `_prefix_distance` is banded (1.47 s → 32 ms on the crafted A2L); the crafted shape joins R-A2L-MATCH.40's cases. |
| A-4 | all other round-2 MINOR / LOW | apply their fix columns. |
