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
- **Addenda applied** (2026-11-06T20:13:25-06:00, Opus 5.5, 25 min): 40 rows, 120 cases; measured .36 worst 66.4 ms REF / 78.4 ms REF6, .40 worst 461.7 ms. **Deviation accepted:** .40's negative controls are the band removal (1,534.6 ms, RED at 1.5×) first and the duplicate collapse removed on `'0 ' × 125 + 'chax'` (1,136.9 ms) second; the E5 mutant run records the host load beside both.

## E5 rulings (2026-11-06T22:03:21-06:00, orchestrator Opus 5.5)

E5 round 1: mutants 47/47 killed (1 not realisable: M-36c describes the pre-E3 design); coverage re-audit 120/120 agree (`full` kept: the module is product code tested at its I-3 surface; the UI route is owed by Inc 7's ATs); code review PASS-WITH-NOTES (F1 MEDIUM, F2 … F7 MINOR/LOW, all `impl`); security FAIL (E5S-01 MAJOR `design-gap`, E5S-02 MEDIUM `design-gap`, minors).
- **Design-gap pass done** (Opus, 30 min): E5S-01 applied with the measured **deviation accepted** — posting variant C (a switch at ≤ 512 name-token occurrences held by the candidates) instead of variant A (A breaks R-A2L-MATCH.36: QSET's multi-word query 264.0 ms > 200 ms); CRAFT 4 / 51 tokens 29.6 / 232.7 ms (was 16.7 s), 0.2 MiB; new case R-A2L-MATCH.40/3; E5S-02: rows .35/.37/.40 name their lists' total characters (REF 2,062,041; REF6 650,000; LONG 2,160,180; CRAFT 2,356,624); backlog BL-I4-5.
- **Corrective pass now:** code (DeepSeek) — E5S-01 variant C per the graph, F1 annotation (extractor must exit 0), F2 `_prefix_distance` early stop, `_classify` merges repeated tokens, F3–F7 where the fix column is code; tests (Sonnet tester) — R-A2L-MATCH.40/3 (CRAFT), **a new case R-A2L-MATCH.40/4 that covers the band** (the no-band control must turn it RED after the switch — use E3S-11's crafted `_prefix_distance` shape through the path that still reaches the band), and the perf run printing every margin (the E4 transcript lost the 40 lowest).
- Then: GREEN re-run, extractor exit 0, and a security re-review of E5S-01/-02 only.

## E5 round-2 rulings (2026-11-06T23:03:29-06:00, orchestrator Opus 5.5)

Security round 2 **FAIL**: E5S-01 closed (CRAFT 51 tokens 226 ms; switch boundary exact); E5S-02 superseded; **E5S-07 MAJOR design-gap** (the map path costs distinct query tokens × table size: a 76-token query over 50,000 names of 2.05 M characters takes 7.44 s and 1,470 MiB; range tables cut it to 1.35 s / 19 MiB, still over 1.0 s); **E5S-08 MEDIUM** (.37's build peak 65.9 MiB > 64 MiB for a list inside the row's scope); E5S-09 LOW. Mutant round 2 stopped (the code changes again); its partial output moved to `evidence-e5/superseded-mutants-r2/`.
- **E5S-07 — remove the multiplicative factor (prefer removing over guarding):** range tables (measured) **and** a cap: **if the query holds more than N distinct tokens, the fuzzy rule is left out** (exact, prefix, substring, token and subsequence rules still run). Long queries are pasted names; the cheap tiers find them. The design pass picks N by measurement so the worst case of R-A2L-MATCH.40's scope stays ≤ 0.5 s, reports the share of corpus and fixture names with more than N tokens (`../../design/a2l-corpus/`), and writes the row (next free R-A2L-MATCH id) with cases and a negative control.
- **E5S-08:** .37 must hold for every list in its scope: a compact build (the range tables or a cheaper staging) or, if not reachable, the scope stated by total characters with the measured bound — no silent loosening.
- Then: code (DeepSeek), tests (Sonnet), GREEN, mutant table re-run, security round 3 on E5S-07/-08.
