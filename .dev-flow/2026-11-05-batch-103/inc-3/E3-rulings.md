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

## Round 3 rulings (2026-11-07T00:42:34-06:00, orchestrator Opus 5.5)

Round 3 (security): **FAIL** — E3S3-08 … -11 closed (57 FIX shapes × 10 conversions, 0 exceptions; 1 M-point axes with 0 points above 2^53; .136/arr-2 0.087 s); new **E3S3-13 MAJOR** (shared AXIS_PTS via COM_AXIS, COMPU_METHOD and COMPU_VTAB still read once per object: 400 objects × 256 KiB take 4.3–24.9 s / 5.7 s / 5.7 s — the COMPU part is in Inc 2a's code too), **E3S3-14 MEDIUM** (no rule keeps cached read forms unchanged).
- **One general rule** replaces the per-kind fixes: **every section an object references by name (RECORD_LAYOUT, MOD_COMMON, AXIS_PTS, COMPU_METHOD, COMPU_VTAB, COMPU_VTAB_RANGE) is read once per walk**, keyed by section identity; and **a cached read form is an immutable value** (tuples / frozen dataclasses), so one object's decode can never change another's. Cases: 400 objects sharing each kind (within R-A2L-DEF.136's budget); two objects sharing a curve's AXIS_PTS decode to the same values as a fresh, uncached decode.
- **Inc 2a:** the COMPU part of E3S3-13 is a design gap in Inc 2a's implemented code; it is fixed in **Inc 2a's E5** (records: a case under R-A2L-DEF.136 with 400 objects sharing one COMPU_VTAB / COMPU_METHOD; code: the read-once map) before 2a merges.
**Next:** a narrow Opus correction of Inc 3a's records/graph, then security round 4 on E3S3-13/-14 only.

## Round 4 rulings (2026-11-07T01:26:53-06:00, orchestrator Opus 5.5)

Round 4 (security): **FAIL** — E3S3-13 … -15 closed (each by-name kind read once: 400 × 256 KiB in 0.05–0.15 s; immutable forms, 0 oracle differences); new **E3S3-17 MAJOR** (every ALIGNMENT line kept in the read form and walked per object: 400 objects 2.9 s layout, 5.4–5.8 s MOD_COMMON — one entry per class gives 0 differences over 151,864 objects), **E3S3-18 MAJOR** (Inc 2a's `_resolve_datatype` re-scans the shared layout per object, 2.5 s — Inc 2a's E5), E3S3-19 LOW, E3S3-20 MEDIUM (outside 3a's scope), E3S3-21 INFO.
- **The class, closed by one rule and one test** (rounds 2–4 each found another per-object walk of shared content): **every shared section is reduced once per walk to the fixed-size form an object needs** (one entry per ALIGNMENT class; the resolved datatype of a layout; …), so describing an object costs O(1) in the size of the sections it shares. New row (next free id): describing 400 objects that share sections of 256 KiB finishes within 0.5 s, **and doubling the shared sections' size with the same 400 objects raises the time by at most 1.3×** — a scaling test that turns RED on any per-object walk of shared content, whichever node it is in. The same row is added to Inc 2a's E5 (E3S3-18).
- E3S3-17: accept the fix column (one entry per class). E3S3-19: accept. E3S3-20: noted for the owner the review names.
**Next:** a narrow Opus correction, then round 5 security — asked to run the scaling test over every 3a node path, not only the shapes found so far.
- **Round-4 correction done** (2026-11-07T01:55:25-06:00, Opus, 30 min): seven shared reads reduced to fixed forms (layout / MOD_COMMON one ALIGNMENT entry per class; AXIS_PTS its 10 header words; method record 6 fields; enum table by reference; `_resolve_datatype` skipped for arrays; the 2a parts for 2a's E5). **Ruling on R-A2L-DEF.148:** the total-time ratio cannot hold on any design (the one read of each shared section grows with it, ×1.35–1.76), so the row keeps the 0.5 s total bound and takes the **1.3× ratio on the time beyond the first object's describe** (the per-object part, which is what the class is about) — accepted as the intent of the round-4 ruling. Model: 0.017–0.144 s, ×0.93–1.13; 9/9 GREEN, 9/9 negatives RED.

## Round 5 rulings (2026-11-07, orchestrator Opus 5.5)

Round 5 (security): **FAIL**. E3S3-17 and -19 are closed, and E3S3-18 is closed for 3a's kinds: 37 of 49 paths are flat and the reduced forms differ from the walk on 0 of 6,379 corpus objects.
New findings:
- **E3S3-22 MAJOR:** one long *word* of a shared section is cleaned, scanned or copied once per object (12 describe paths, 22–100 ms per object).
- **E3S3-23 MAJOR:** each decoded enum element gets its own cleaned copy of the shared text.
- **E3S3-20:** confirmed (6 decode paths scan a shared table per element).
- **E3S3-24 MEDIUM:** .148's measure is too noisy on a shared host and blind to per-object copies.

**Closing the class.** The round-4 rule fixed the number of entries a reduced form holds but not the size of each entry. The completed rule follows; it replaces the round-4 wording.
- **Every shared section is reduced once per walk to a form of fixed size.** That means a fixed number of entries, and each word held in its final form, computed at reduction:
  - a word a message echoes is held as its echo (see R-A2L-DEF.151);
  - a text shown in a value is held cleaned once;
  - a derived value is held computed, e.g. the FORMAT's decimals in the method record.
- An object's definition and its decoded values **reference** a shared text, never copy it.
- **Decode is one lookup per element:** a dict from raw value to the first text for COMPU_VTAB, and a bisect for COMPU_VTAB_RANGE and for 3a's own TAB_INTP / TAB_NOINTP path. The frozen `a2l._table_lookup` is not called from the decode path any more. A corpus equality case pins the bisect to the frozen function's values.
- Then per object, both the work and the retained bytes are O(1) in every shared section's size.

**Rows** (next free ids, checked: .140–.149 used):
- **R-A2L-DEF.150 (U), owned by Inc 2a:** "The system shall decode each element in a time and a retained size that do not grow with the size of the conversion table it names."
  - Inc 2a's cases: scalar VALUEs, e.g. VT-3 and VT-5's VALUE form.
  - Inc 3a's cases: `.150/arr-*` (VT-1, -2, -5, -6, VR-1, -2, CT-1, -2).
  - Plus the equality case for the bisect against `a2l._table_lookup`.
- **R-A2L-DEF.151 (U), owned by Inc 2a:** "The system shall write a file word into a refusal message as at most its first 64 characters, each character outside U+0021 … U+007E written as U+FFFD, and `…` after it when the word is longer." This is READ.66's echo rule; the display text of a decoded value keeps .137. Inc 3a's .84, .85, .86 and .144 messages cite it, with cases `.151/arr-*`.
- **R-A2L-DEF.148** keeps its text and bounds and gains cases:
  - one long-word fill per echo family: RL-7, MC-7, CM-4, CM-6, CM-8, RL-15;
  - an assertion that each definition's message holds ≤ 1 KiB.

**Measure (E3S3-24): accept, for .148, .149 and .150.**
- Time only the per-object part: one walk's maps, the first name described, then the 399 remaining names, with `time.process_time()`.
- Interleave S, 2S and 8S run by run, and take the least of ≥ 15 runs.
- Pass when ×2S ≤ 1.3 and ×8S ≤ 2.0, the 0.5 s total holds, and each negative control is RED.

**Owners.**
- Inc 3a's E3 correction (Opus) covers the rule, the graph nodes (`_describe_array`, `_conversion_fields`, `_read_record_layout`'s owner-free refusal, `_module_common`, `_decode_stored`), the .148 cases and the 3a cases of .150 / .151.
- Inc 2a's lines (CM-5, CM-7, CM-9, VT-1 … -3, VR-1, VT-5, VT-6, VR-2, RL-10, RL-11, CM-2) go to a 2a gap pass, run before 2a's E5 review:
  - records: Opus;
  - code: DeepSeek;
  - tests: an independent tester.
  - It starts once the .149 tester finishes.
- CT-1 and CT-2 leave the frozen `_table_lookup` through 3a's bisect. E3S3-21 stays in the backlog (frozen file).

**Next:** after the correction, run round 6 security on the same 49-path harness. Add the long-word fills of every echo family, plus the decode paths, against the corrected model.
