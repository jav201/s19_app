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

**Round-5 correction done** (Opus, 21 min). .148 is now 15/15; cases `.150/arr-1…9` and `.151/arr-1…6`; the completed rule is in the graph. Orchestrator rulings on what it reported:
- **Echo cap 256, not 64.** This applies to R-A2L-DEF.151 and also to Inc 11's R-A2L-READ.66, one rule for both.
  - Measured on <runner> over the public corpus plus `examples/` and `tests/`, read-only, derived counts only:
    - section names longer than 64 characters: 1,993, in 28 files;
    - longer than 128: 16;
    - longer than 256: 0;
    - longest: 148 (a COMPU_METHOD);
    - reference words longer than 64: 85.
  - A 64-character echo would cut real names in the messages the operator reads to find an object, and 256 keeps every measured name whole. The cost per object is still constant in the section size.
  - Applied in place in `inc-3/` and `inc-11/` (23 lines). READ.66/1's bound becomes 312 characters: `Line <n>: /include ` + 257 + ` is not read`, with the old margin.
- **Enum index.** The public `enum_entries: tuple[EnumEntry, ...]` of I-2 stays as pinned. The dict (VTAB) and bisect keys (ranges) are a private, immutable part of the per-walk reduced enum table, shared by reference. For the 2a pass to design.
- **.151's reach:** accepted as read, meaning the shared-section words `<component>` and `<word>`. `<name>` (the object's own) and `<layout>` (a word of the object's own header) keep .137: each costs the object's own text, not a shared section.
- **The agent's `sed -i`:** checked. It was ASCII only, the file is valid UTF-8, no line starts with a stray backtick, and the diff holds only the intended lines.

**Next:** round 6 security on the corrected records.

## Round 6 rulings (2026-11-07, orchestrator Opus 5.5)

Round 6 (security): **FAIL**.
- **Closed at design:** E3S3-20, -22, -23 and -24. All 52 round-5 paths plus CT-3 and CT-4 are flat (×0.97–1.03), and the 30 negative controls are RED.
- **Corpus:** 353,626 objects give 0 verdict and 0 message changes; the longest message is 283 characters.
- **New:** E3S3-25, -27 and -28 MAJOR; E3S3-26, -29 and -30 MEDIUM; E3S3-31 MINOR; E3S3-32 LOW.

Rulings, each applying the fix column unless the ruling says otherwise:
- **E3S3-25: accept the main fix.** R-A2L-DEF.151 reaches **every file word a refusal message echoes**, `<name>` and `<layout>` included. This withdraws the orchestrator's round-5 reading that `<name>` and `<layout>` keep .137: `<layout>` of a COM_AXIS curve is a word of the shared AXIS_PTS.
  - The echo of a shared word is computed at reduction.
  - The echo of an object's own name is computed once at describe and carried by the definition.
  - No real message changes, since every measured name is ≤ 148 characters.
  - New cases: .148/16 (RL-16) and .148/17 (RL-17).
- **E3S3-26: accept.** TABLE-EMPTY goes with CONVERSION and TABLE, and `<table>` is the stored echo. New case .148/18. Inc 2a's line `:529` joins the 2a pass.
- **E3S3-27: accept.** Element refusals use the definition's name echo + `[<i>]`. `decode_values` builds an element's full name only when a caller asks. New case .150/arr-10.
- **E3S3-28: accept the primary fix.** It is a real defect, reproduced on a public corpus file.
  - Decode fails closed: a conversion result that is not an `int` or a `float` → `A2L-DEF-DECODE` `<name>: the table <ref> gives a value that is not a number`, with `<ref>` written as .151.
  - The same test goes in Inc 2a's scalar `decode_definition` (2a pass).
  - New case .150/arr-11. The describe-time alternative is not taken: the decode test is one check that covers every route.
- **E3S3-29: accept v2**, the two frozen-lookup rules pinned, still O(log n): 0 differences on 119,684 pairs.
  - .150/arr-9 gains the extended values: NaN, ±inf, 2^63, 2^64 − 1, midpoints and ±1 ulp.
  - A table whose x holds a NaN is refused at decode, with the verdict computed once per walk in the reduced form.
- **E3S3-30: accept (a) and the first option of (b).**
  - The 2a pass builds the segment index (first range in file order per segment), with the equality case and value set of the fix column. Negative control: a plain bisect → 780 differences.
  - The scalar TAB_INTP / TAB_NOINTP lookup, with v2's rules, joins the 2a pass with a .150 VALUE case, so Inc 2a is correct before Inc 3a merges.
- **E3S3-31: accept.** Each reduced form keeps the section its reference word names, resolved at reduction; no per-call name lookup of a shared word remains.
- **E3S3-32: accept.** The message bound is "1,024 characters" everywhere.

**Next:** a narrow Opus correction of Inc 3a's records, then round 7 security on the same harness plus EN-*, RL-16/17, VT-8/9 and the raise cases. The 2a items go to the running 2a gap pass 2.
- **Round-6 correction done** (Opus, 19 min). .148 is 18/18; new cases .150/arr-10 and /arr-11; arr-9 is extended. Orchestrator rulings on what it reported:
  - **The 2S bound is 1.5, not 1.3, for .148 and .150.** This is the measure ruling recorded in Inc 2a's `E3-rulings.md` ("gap pass 2 rulings"): GC off, ×2S ≤ 1.5, ×8S ≤ 2.0. Three GREEN runs of .149 on flat code measured ×1.2–1.4 at 2S with GC off; a per-object walk gives ≥ ×1.78 at 2S and ≥ ×3.2 at 8S. The orchestrator applied it in place to the current case and node texts (01:199, :318; 02:178, :315, :324; graph :66, :313, :315, :716, :717, :792). The historical quotes of the round-4 rule stay as written.
  - **The `Definition` private fields** `_name_echo` and `_table_form` were accepted in Inc 2a's P-2 ruling, as `field(compare=False, repr=False)`: I-2's public names, equality and repr are unchanged.
  - **The NaN-x message** is `<name>: the table <ref> has an x that is not a number`, the wording of Inc 2a's R-A2L-DEF.58.2/19, so it is no longer PROPOSED. Applied in place.
  - **Next:** round 7 security, on the corrected records only (RL-16/17, VT-8/9, EN-1/2, the raise cases, CT-*, and the v2 bisect equality).

## Round 7 rulings (2026-11-07, orchestrator Opus 5.5)

Round 7 (security): **FAIL**.
- **Closed at design:** E3S3-25 … -29, -31 and -32. On the model, RL-16/17, VT-8/9, EN-1/2 and CT-1 … 4 are flat (×0.97–1.06), the raise cases give 0 exceptions, and every negative that ran is RED.
- **New:** E3S3-33 MAJOR (the COMPU_TAB form keyed per method), -34 MEDIUM (a warm walk hid -33), -35 MINOR, -36 LOW, -37 INFO.
- **Evidence gap, stated plainly:** a `pkill -f` slip lost the raw round-7 transcripts. The scripts `evidence-e3/sec-r7-*` are kept, but the round-7 numbers have no transcript. The v2 bisect census and the range-index equality did **not** run. Round 8 runs both, and the correction cites round-7 numbers as "reported, transcript lost".

Rulings:
- **E3S3-33 + E3S3-36: reuse Inc 2a's form, as implemented.** Inc 2a's gap-pass-2 code (`6071a385`, `_build_tab_form`) already builds the COMPU_TAB form as the ruling asks:
  - keyed by `id()` of the COMPU_TAB entry in `reads`;
  - `xs`, `ys` as tuples;
  - the NaN-x verdict computed once;
  - `ref_echo`.

  Inc 3a's graph names that function and `_TabForm` and builds no second one. COMPU_TAB joins the read-once list (`01-requirements.md:267`, graph `:42`, `:149`) and CTX *shared section* ("names" includes a section named through a COMPU_METHOD). The TAB_VERB record holds the enum read form, not the section dict.
- **The completed rule gets an explicit, closed list.** The kinds an object reaches by name, directly or through another section, are RECORD_LAYOUT, MOD_COMMON, AXIS_PTS, COMPU_METHOD, COMPU_TAB, COMPU_VTAB and COMPU_VTAB_RANGE. **E5 code review checks that the list is closed:** every `a2l_data` section lookup in `a2l_definition.py` goes through `reads`.
- **E3S3-34: accept.** For .148 (and Inc 2a's .149), each run builds its own walk from scratch and times the 399 names described for the first time in it. Recorded for Inc 2a's tests too.
- **E3S3-35: accept the count.** Counting mappings around `record_layouts_by_name`, `compu_tables_by_name` and `compu_tabs_by_name` in .148/16 … /18 and in .150/arr-7 must show 0 lookups by the 399 names after the first. Negative control: by-name lookup per object → RED.
- **E3S3-37:** recorded for 3b's re-review.

**Next:** a narrow Opus correction, then round 8: the census and equality runs that did not happen, plus CT-5 and CT-6, with the fresh-walk measure. Every round-8 kill is by PID, never `pkill -f`.
- **Round-7 correction done** (Opus). .148 is 19/19, with CT-5 and CT-6 as .148/19; it reuses Inc 2a's `_TabForm`, `_build_tab_form` and `_EnumForm`. Orchestrator rulings on what it reported:
  1. **E3S3-35's count is scoped to lookups keyed by a word of a shared section.** That covers the COMPU_TAB_REF word of a shared method, the axis object's layout reached through a shared AXIS_PTS, and the table of a shared method. An object's lookup of its own layout by its own header word is one lookup per object, costs only its own text, and is not counted. Accepted as the agent's reading (`01-requirements.md:341`).
  2. CT-5 and CT-6 as one case, .148/19: accepted.
  3. `_conversion_fields` takes `compu_tabs_by_name`, and the method-record example shows Inc 2a's 11 keys: accepted (both follow Inc 2a's code at `6071a385`).
- **Round 8 is narrow.** The v2 lookup census and the range-index equality run on Inc 2a's **real** code in Inc 2a's E5 security review (in progress); round 8 cites that result and does not repeat it. Round 8 runs only the paths specific to Inc 3a, on the model with Inc 2a's real forms imported from `~/work/b103-int2a`: CT-5, CT-6, the counting-mapping cases, RL-16/17, EN-1/2, and one flat pass of the 54-path table with the fresh-walk measure.

## Round 8 rulings (2026-11-07, orchestrator Opus 5.5)

**Round 8 (security): FAIL, on one MAJOR.**
- **Closed:** E3S3-33 … -36, at design.
- **The reviewer states that the class "per-object work on shared content" is closed for every node of Inc 3a's graph.** Measured on Inc 2a's real forms with a fresh walk per run:
  - CT-5, CT-6, RL-16/17 and EN-1/2 are flat;
  - the counting cases make 0 lookups after the first name;
  - 8 of 8 negative controls are RED.
- **E3S3-38 MAJOR:** Inc 3a's layout read form and Inc 2a's resolved datatype share one `reads` key, `id()` of the same layout. On V171 one walk raises for 16 of 118 names. With separate keys: 0 exceptions, 0 differences (executed on the model).

Rulings:
- **E3S3-38: accept the fix as written.** Inc 3a's read forms are keyed by the form's kind and the section's identity: `("layout", id(entry))`, `("mod_common", id(section))`, `("axis_byte_order", id(section))`, and so on. Inc 2a's bare `id()` keys stay as implemented; a tuple key never equals an int key.
  - The read-once rule (`01-requirements.md:270`, graph `:156`, `:509`) becomes "keyed by the read form's kind and the section's identity; no two read forms share a key".
  - .136/arr-4 gains K1–K3: every name in one walk, in file order and reversed, 0 exceptions, every definition equal to a fresh walk's.
- **E3S3-39 INFO:** add the optional note to .148/19's measure column.
- **Measure (Inc 2a E5-3, `../inc-2/E5-rulings.md` in the 2a worktree):** every timed case of Inc 3a times `names[1:]` inside one fresh walk, through a generator passed as `names`, and never as the difference of two walks. Restate the measure text of .148 and .150/arr-*.
- **Gate:**
  - After this correction, which is records-only and applies a fix the reviewer already executed on the model, **Inc 3a's E3 closes: PASS-WITH-NOTES by orchestrator ruling.**
  - The census and range equality are taken from Inc 2a's E5 security review: 0 differences over the full corpus and 8,000 hostile tables (`../inc-2/E5-security.md` in the 2a worktree).
  - Inc 3a's E4 waits for Inc 2a to merge into `batch-103`.
- **Round-8 correction done** (Opus).
  - The reads keys are namespaced.
  - .136/arr-4 gains K1–K3.
  - The measure is restated. The agent read the decode side as follows, and the ruling accepts it, because decode stores nothing per walk (Inc 2a E5-3): `.150/arr-*` build the walk with the generator, then time the decodes of `names[1:]` as one interval; /arr-10 has one name and times its decode alone.
- **Inc 3a E3 CLOSED: PASS-WITH-NOTES by orchestrator ruling.**
  - The class is closed for every node, stated by the reviewer in round 8.
  - E3S3-38's fix was executed on the model and is now in the records.
  - The census and range equality are taken from Inc 2a's E5 security review.
  - Round 9 is not run.
  - E4 waits for Inc 2a's merge into `batch-103`.
  - Carried to E5: E3S3-03, -04, -06 and -21 (backlog: the frozen file), plus the 3b notes (E3S3-37).

## Inc 3b re-review — correction 1 (2026-11-10, orchestrator Kimi)

The first 3b re-review (`E3-architect-3b.md`, `E3-security-3b.md`) is **FAIL**. A-01/A-02/A-03 and S-01/S-02/S-03/S-04/S-05 block E4. The correction is design-first: no product or test change is authorized by this ruling alone.

1. **A-01 = S-06, accepted.** `_element_definition` must set both `name` and the private `_name_echo` to the object/axis name's bounded echo plus the element/point suffix. `A2L-DEF-INDEX`, every delegated refusal, notices and overlap use that same composition. `<layout>` and `<ref>` use `_echo`. The round-7 E3S3-37 note wins over the older `element_name` wording.
2. **A-02 = S-02, accepted.** Every STD point inherits the parent object's `shared_with`; a whole-record write cannot discard it because one point does not itself touch the neighbour. A new `.140/7` pins this.
3. **A-03 = S-04, accepted.** CLEAN may be consulted only for an entry whose section is MEASUREMENT or CHARACTERISTIC; never for AXIS_PTS, BLOB or INSTANCE. The homonymous AXIS_PTS case is `.140/4`.
4. **S-01, accepted.** The tag's provisional length is not the span of an array, curve or map. The index uses the final `Definition.byte_length` and `_entry_overlaps` uses that same value. `describe_definitions` materialises only candidates on pages touched by requested definitions: definitions already built by the walk are reused; an unrequested candidate is described once and cached. The fail-closed point remains only when the final model cannot read a length. `.140/5` covers a VALUE inside a CURVE whose tag has no length; `.140/6` covers masked neighbours with no exception and no exemption.
5. **S-03, accepted conservatively.** No CLEAN mask exemption applies when either side is array/curve/map. `mask_of` returns a mask only for a clean scalar number/enum; an array's final kind therefore prevents both a false exemption and `range(None)`. A future per-component exemption needs its own increment and is not authorised here. `.140/8` covers repeated elements, both directions, second element and a CURVE with points.
6. **S-05, accepted.** Encode uses immutable inverse forms shared per walk: enum text → first raw in file order; numeric entries reduced once and indexed by physical value, with bisect for inversion and no per-cell reconstruction or sort. The inverse path must preserve `_reverse_table_lookup`'s tolerance, endpoint, rounding, tie and error behaviour. `.131/2` measures multiple edits against a large shared table and compares results with the frozen oracle; rebuilding per cell is the negative control.
7. **A-04 = S-10, accepted.** `encode_values` has an explicit scalar branch for number/enum/text: exactly `(0,)` delegates to `encode_definition`; any other position gives A2L-DEF-INDEX. New row R-A2L-DEF.153 with one case covering all three kinds and a rejected position.
8. **A-05 = S-08, accepted.** The common order is definition refusal → A2L-DEF-PARSE → decode/A2L-DEF-ELEMENTS → positions → edits → monotony. OVERLAP remains late. `.120/3`, `.130/4` and `.130/5` pin single-array encode, missing bytes and invalid position under parse errors.
9. **S-07, accepted.** Position validation precedes unpacking or offsets. Every malformed form returns A2L-DEF-INDEX with a total, bounded formatter, never an exception. `.125/4` covers short/long axis tuples, non-integer index, `None`, a scalar non-iterable, negatives and an unknown letter.
10. **S-09, accepted as two new rows.** R-A2L-DEF.154 refuses an unknown MONOTONY rule with `A2L-DEF-MONOTONY` and the exact message `<axis name>: the monotony rule <rule> is not supported`, before bytes. R-A2L-DEF.155 propagates a necessary point's decode refusal; a valid breaking point's text is its bounded display text, preserving the numeric texts of `.129/1-9`. `.155/1` covers an invalid conversion and `/2` a long enum text, with no bytes, exception or unbounded message.
11. **Counts after correction:** 86 rows; 336 active cases = 280 3a + 56 3b. The new rows are .153, .154 and .155; the other additions are .120/3, .125/4, .130/4-5, .131/2 and .140/4-8. The 42 old 3b cases and the 5 mixed edit arms remain pending until E4.

E4 must implement the corrected graph, including the final-span index and inverse forms, and must run all 56 cases and 5 mixed arms with discriminating RED/GREEN evidence. A narrow architect/security re-review is required before any product change.

## Inc 3b re-review — correction 2 (2026-11-10, orchestrator Kimi)

The second review is **FAIL** on one shared MAJOR (`E3B3R2-A-01` = `E3B3-R2-01`) and the synchronisation/semantic findings below. Correction 1's limited materialisation is withdrawn: a provisional page index cannot bound a final span that starts on an earlier page.

1. **Cross-page completeness.** Every span candidate is materialised once per walk, reusing a definition already built when present and describing an unrequested one once with the same `reads`. The final `Definition.byte_length` is filed under **every page of the final span**, in global file order. There is no partial-page subset. `.140/9` puts a CURVE beginning at 0x20 with tag length absent and a final span ending at 0x5F beside a VALUE at 0x40, which must share and refuse. The performance oracle must compare against the old path and show no repeated describe per candidate.
2. **Inverse semantics.** `.131/3` adds a discriminating matrix for TAB_INTP and TAB_NOINTP: multiple physical entries, tolerance, ties and their file-order raw, both endpoints, nonnumeric entries, NaN, missing/empty tables, and the written-value flag. Duplicate enum texts resolve to the first raw in file order. The graph now names each branch, not just a generic bisect. `.131/2` remains the scaling oracle and uses TAB_INTP.
3. **CTX order.** The context's array encode order is definition refusal → PARSE → decode/ELEMENTS → positions → edits → monotony, with OVERLAP late.
4. **`.155/1` premise.** The conversion-invalid point is **unedited** and becomes necessary for monotony because another point is edited. This keeps scalar PRECISION from masking the required decode refusal.
5. **Naming.** `.154` uses `<axis point name>` throughout; `.154/1` therefore expects `C.X[0]: the monotony rule UNKNOWN_RULE is not supported`.
6. **Position text.** Malformed positions use the bounded `repr(position)` after the bounded object name echo and `:`, rather than destructuring. `.125/4` fixes each exact refusal text. Valid positions keep their existing element names.
7. **Record synchronisation.** Secondary totals, the 3b test list, `encode_values.req` and the E1 summary are rebased. Correction 1's E4 line is corrected to 56 cases before the new two cases.

**Final counts after correction 2:** 86 rows; **338 active cases = 280 3a + 58 3b**. Section totals are S2.7g 46 and S2.7h 52. The new cases are `.131/3` and `.140/9` in addition to correction 1's 14. E4 still requires a narrow PASS/PASS-WITH-NOTES before product changes.

## Inc 3b re-review — E4 addenda and close (2026-11-10, orchestrator Kimi)

Both round-3 reports are **PASS-WITH-NOTES**, with no HIGH/MAJOR. Their notes are discharged without changing counts:

- `.140/9` now requires one build per requested definition and one describe per unrequested candidate, cached thereafter; a duplicate describe is the negative control.
- `.131/2` is explicitly TAB_INTP. `.131/3` fixes table entries, operator inputs and exact raw/reason/flag values for duplicate physical values, tolerance, interpolation, endpoints, NaN, empty and nonnumeric tables, and duplicate enum texts.
- CTX distinguishes valid position names from malformed positions' bounded `repr`.

**Inc 3b E3 is CLOSED: PASS-WITH-NOTES.** E4 may implement the corrected graph. The cost and duplicate-describe controls are mandatory evidence, not optional optimizations.

## Inc 3b E4 implementation note — lazy candidate materialization (2026-11-10)

E4 evidence required an implementation-level refinement of correction 2. Eagerly describing every candidate made `.142/5` take 27 s and 561 MiB. The implementation instead evaluates candidates in global file order and materialises each at most once, on demand, cached by section position. Requested definitions are reused; unrequested candidates are described once with the same `reads`. Its original 1 MiB lower window was proved incomplete by E5 and is superseded by the ruling below: every declared span remains a candidate, including over-cap and earlier-page records.

This changes no refusal, exemption, span or ordering rule. The graph states the refined mechanism. After the refinement, `.142/5` passes at 0.103 s with its memory bound, and the complete functional family passes 662 tests. E5 must check the lazy implementation and its duplicate-describe oracle explicitly.


## Inc 3b E5 corrective ruling (2026-11-10, orchestrator Kimi)

E5-3B-01 … -04 and E5S-3B-01 … -08 are accepted and corrected together. No new requirement row is needed: the six added cases belong to existing .125, .131 and .140. Final counts are **86 rows, 344 cases = 280 3a + 64 3b; S2.7g 46, S2.7h 58**.

- Every declared span stays a lazy candidate. The former 1 MiB lower bound is withdrawn because length-refused spans deliberately retain their over-cap final length. MEASUREMENT with malformed multi-value MATRIX_DIM and VALUE refused by .145 use full description, never provisional tag lengths.
- `_TabForm` separates NaN-y entries and gains an immutable range-minimum tree over physical-sorted entries, keyed by file position. TAB_NOINTP returns the first file entry in tolerance and TAB_INTP the first physical-sorted entry, both in O(log M), including non-exact matches and duplicate runs; exact-first is explicitly rejected because it changes tolerance semantics. A TAB_NOINTP rejection selects its nearest two over all entries with stable file-order ties.
- **Frozen-oracle amendment:** a nonfinite interpolated raw fraction is not invertible and returns A2L-DEF-ENCODE, never `round(nan)` / `round(inf)`. The frozen helper shares the legacy defect and is intentionally not used as the oracle for `.131/4`.
- Public `element_name` delegates to the existing total `_position_label`. Ordinary and extended limits both use `_echo`; their numeric comparisons are unchanged.
- `.142/5` remains within 1.0 s after these changes (0.109 s in `write3b-family-run6.txt`); the 81-case integration and 668-case functional family are GREEN. Re-review, scale/performance repetitions, law guards and mutants remain E5 gates.
