# Inc 3a — E3 round 1 rulings (2026-11-06T23:04:44-06:00, orchestrator Opus 5.5)

Round 1 (3a scope): architect **FAIL** (1 MAJOR, 2 MEDIUM, 7 MINOR, 9 LOW, 4 INFO; one walk re-measured 1.2–1.3 s on 2a's real code against .136's 2.0 s); security **FAIL** (2 MAJOR, 2 MEDIUM, 2 MINOR, 1 INFO; a stdlib model of 3a's rules raised 0 times over 203 files). Every finding is **accepted with its fix column**, with these rulings:

| Finding | Ruling |
|---|---|
| E3A-01 = E3S3-02 MAJOR (FIX points built at describe) | accept: `AxisDefinition` keeps only the FIX parameters (count, offset, shift / dist / list); the points are computed at decode. This changes the I-2 field D-1 pinned — **ruled here**; Inc 6 and Inc 9 read points only through decode. |
| E3S3-01 MAJOR (+ E3S3-05) | accept, fail closed: a count component (NO_AXIS_PTS_*, FIX_NO_AXIS_PTS_*) must have an integer datatype, else `A2L-DEF-LAYOUT-DATATYPE`; a negative current count is refused, not "partial". Cases from the fix column (G1/G2). |
| E3A-02 MEDIUM | accept: a MATRIX_DIM whose product is above 1 is an array whatever its leading or inner 1s (`1 6 1` → 6 elements; 512 corpus objects); a case that fails on 2a's `_object_kind`; Inc 3a's changed `_object_kind` node carries it. |
| E3A-03 MEDIUM | accept: no "element count 0 = unknown" — an unknown count is absent (no value), never 0 or 1; .73 holds; a case. |
| E3S3-03 MEDIUM | accept: I-2 consumer note — `decode_values` may return up to 1,048,576 elements (~11 s, ~200 MiB measured); a UI consumer decodes off the UI thread and pages; owed to Inc 9's E1 (PLAN row). |
| E3S3-04 MEDIUM | accept: already carried to Inc 6/9 (markup off, U+FFFD); Inc 3's new strings named in that obligation. |
| Corpus forms (architect) | accept: one FIX_AXIS_PAR `0 0 n` case and one STATIC_RECORD_LAYOUT case; CUBE_5 none. |
| CG-4 from Inc 11 (E3A-19) | accept: recorded in `E2-rulings.md`; the correction applies it (CURVE/MAP/CUBOID/CUBE lengths via 3a; AXIS_DESCR header on its `/begin` line depends on Inc 11). |
| D-2 against the ASAM text | gates **3b**, not 3a (architect). |
| all others | accept with their fix columns; INFO noted. |

**Next:** an Opus correction pass (records and graph), then a round-2 re-check of the blocking findings by both reviewers.

## Round 2 rulings (2026-11-06T23:59:07-06:00, orchestrator Opus 5.5)

Round 2: architect **PASS-WITH-NOTES** (E3A-01 … -03 closed; .142/5's 100 objects describe in 0.012 s; 1 M FIX points at decode 0.94 s / 40 MiB; 2 MINOR, 5 LOW, 1 INFO); security **FAIL** (E3S3-01, -02, -05 closed — 0 exceptions over 3.7 M count values; 7,000 FIX axes describe in 1.78 s / 8 MiB — but three new MAJORs in the nodes the correction changed). Accepted with their fix columns, ruled:
- **E3S3-09** (FIX_AXIS_PAR shift ≥ 1024 passes describe, OverflowError at decode) and **E3S3-10** (FIX_AXIS_PAR_DIST checked in floating point, computed in exact integers): **one fail-closed rule at describe** — the first and last FIX points are computed in exact integer arithmetic from the parameters, and the axis is refused (the existing FIX refusal code, its own message) when either magnitude exceeds 2^53 (the largest integer a double holds exactly) or the shift exceeds 62. Decode then cannot overflow. Cases for both shapes and the boundary (2^53 accepted, 2^53 + 1 refused).
- **E3S3-11** (each object re-reads the shared RECORD_LAYOUT / MOD_COMMON: 400 objects sharing a 256 KiB section take 5.3 s / 19.1 s): each RECORD_LAYOUT and MOD_COMMON is parsed **once per walk** (a map in `describe_definitions`'s one walk, keyed by section identity), as E3A-32 already asks for lookups; a case with 400 objects sharing one large layout (≤ the .136 budget).
- E3S3-08, the architect's notes (E3A-24 refused definitions carry no unread count; E3A-25 a PAR_LIST case): applied in the same pass; the rest are E4 addenda.
**Next:** a narrow Opus correction, then security round 3 on E3S3-09 … -11 only.
