# Inc 4 — E3 code-free design review: architect

Batch 2026-11-05-batch-103, increment 4 (label similarity matcher, a pure module). Base `e07fb00`; records commit `cfa63f67` (branch `batch-103`; the product tree equals `e07fb00`). Reviewer: Opus 5.5, architect lens, read-only on the records.

**Records read:** `01-requirements.md` (37 rows), `02-test-cases.md` (110 cases), `E1-rulings.md` (with its "Orchestrator rulings" and "Erratum"), `E1-slice.md`, `E2-rulings.md`, `codewire/graph-inc4.md` (18 nodes, 5 entities), every E2 script and transcript in `codewire/`, `codewire/extract-e2/`, and `evidence-e1/i4e1-pilot.py`, `-pilot2.py`, `-pilot3.py`, `i4e1-census-transcript.txt`. Also `PLAN.md` (US-103-03, the Inc 7 row, I-3), `REQUIREMENTS.md` (rules for every row), `CLAUDE.md`, and the format example `b101-inc12:…/inc-12/E3-architect.md`.

**Code read on the base tree:** `s19_app/tui/a2l_parameter_picker.py:75-106` (I-5 splits with `str.split()`), `s19_app/tui/changes/model.py:48` (the `(str, Enum)` precedent), `tests/test_suite_hygiene.py:60-100`, `:240-300`, `:391-482`, `:1444-1456`, `tests/support/timing.py:1-96`, `tests/support/suite_census.py:60-80`, `:260-330`, `:749-830`, `.github/workflows/tui-ci.yml`, `pyproject.toml:44`, `:112-116`, `tests/conftest.py:229-270`, `.dev-flow/2026-11-01-batch-101/*/04-validation.md` (how `trace_check.py` is run), and `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\trace_check.py`.

**Runs:** all on cachyos-rtx (Python 3.11.18, 16 cores), scratch `/tmp/b103-e3-4-architect/`, with its own HOME, XDG and LOCALAPPDATA. Clone `~/work/s19_app` at `e07fb00f`, read-only. `s19_app.__file__` is printed first in every transcript. No clipboard was touched. Case 08 was regenerated there (seed 20260001) and is byte-identical to E2's (sha256 `42ca7d40…`, `6f936293…`).
- **Re-run of the E2 pilot.** `i4e2-pilot4.py` and the three E1 pilots it loads were copied from the records (sha256 equal to the records and to `/tmp/b103-e2-4/`). Transcript: `e3-pilot4-rerun-transcript.txt`.
- **Three probes of my own:** `e3a-probe.py`, `e3a-probe2.py` and `e3a-probe3.py`, with their `-transcript.txt` files. Each loads the E2 pilot unchanged and subclasses its `IndexC`.
- **Host load** is printed in each transcript. Other sessions were running a pytest `-n 6` and a probe during probe 2 (load 6–7.5). The QSET medians on REF in that run (worst 60–64 ms) match the clean re-run (61.6 ms), so the load inflated the times by about 5 % at most.
- **Where the files are.** Scripts and transcripts are in `/tmp/b103-e3-4-architect/` and in the session scratchpad `C:\Users\jjgh8\AppData\Local\Temp\claude\107abb51e32da120\c57f44a4-8a42-42ee-9fb3-80f699575124\scratchpad\`. They are not evidence of record (this review writes nothing else into the records). To keep them, copy them into `inc-4/evidence-e3/`.

## Verdict: FAIL

2 MAJOR, 2 MEDIUM, 3 MINOR, 2 LOW, 2 INFO. No HIGH.

**The design's shape is right.** I-3 suits its consumer: the two calls, an immutable index, a rule and spans for each entry (§2.4). The compact index meets the memory row with margin. The rules, the bands and the total order are exact (§2.5, §2.6). The re-run confirms every E2 number (§3).

**What blocks.** R-A2L-MATCH.36 holds on its own fixture (REF × QSET) but not on the shapes that drive the design's cost:
- **E3A-01: large same-length groups.** On the tracked `case_06` list, the 200 ms bound is missed 3× to 4×. The graph's pinned step 6 is not even the procedure E2 measured.
- **E3A-02: several long query words.** On REF itself, a query of 5 or 6 long words takes 244–297 ms.

**Both fixes are measured and change no interface.** Each gives the same lists as before within its rows. With both applied, the worst case falls to 85.5 ms on case_06 and 71.2 ms on REF, under host load 6–7.5. They are a graph edit (steps 4 and 6), one definition edit, two changed cases and fixture additions.

## 1. Findings

| Id | Severity | Row / node / case | Finding | Proposed fix |
|---|---|---|---|---|
| E3A-01 | MAJOR | R-A2L-MATCH.36 (`01-requirements.md:140`) · .24 (`:118`) · CTX *case-exact* (`:64-65`) · `rank` step 6 (`graph-inc4.md:174`) · REF / QSET (`02-test-cases.md:14-15`), .36/1 (`:125`) | **The cost of case-exactness has no bound.** Case-exactness is decided for every member of each group the cut reaches. A group is every name with the same rule, rule key and length, so its size has no limit. For token, fuzzy and subsequence names, the E2 pilot decides it with a full raw re-classification (`i4e2-pilot4.py:291-299`). The graph's step 6 pins a raw `_classify` for every rule, even exact, prefix and substring, where the pilot uses string comparisons. **REF hides the cost.** REF's names vary in length, so QSET never builds a large group: on REF, step 6 as written still gives 61.6 ms. **case_06 shows it.** The test list is the first 50,000 names of the tracked `examples/case_06_large_nested_a2l/firmware.a2l`: every name has 13 characters, `CHAR_00000_00` / `MEAS_00000_00`; it builds in 0.49 s and takes 6.2 MiB. The E2 pilot as measured: `mesa` 675.7–717.2 ms, `cahr` 688.7 ms, `chr` 600.9–614.4 ms, `cr0` 553.6 ms, `char 1` 355.0–366.8 ms. Step 6 as written: `m` 393.4 ms, `meas_` 718.6 ms, `0` 754.5 ms, the first keystrokes included. Every one is above 200 ms (probe 1 §B/C; probe 2 "C06"). The cause is decided by elimination: the same tiers without the raw check take 15–47 ms on these queries. | **1. Narrow case-exactness to the rules where it is a string comparison.** CTX *case-exact* becomes: "A listed name with the rule `exact`, `prefix` or `substring` whose rule still holds when an uppercase letter and its lowercase letter are compared as different characters; a name listed with any other rule is not case-exact." The text of .24 and .25 does not change. Two cases change: .4/1 and .24/3. `druck_max` and `DRÜCK_MAX` are both fuzzy, 1 edit, 9 characters, so code-point order puts `DRÜCK_MAX` first. **The graph gets simpler.** Step 6 compares `==`, `startswith` and `in` against the raw stripped query. `_parse_query` loses its `fold` parameter and `[Data: _Query]` its `folded` field. `_classify` loses its raw mode, and `_prefix_distance` its "both raw" clause. **Measured:** case_06 worst 91.0 ms (`0`); REF unchanged (probe 2, `text3`). **The alternative, removing the feature:** retire .24. case_06 worst is then 82.3 ms, but more cases change (.3/3, .24/1–3, .25/3, .4/1). It loses the typed-case order of the ASAP2 twins `RPM` / `rpm`, which D-6 ruled for. **2. Cover the shape in .36.** Add a second reference list, REF6: the first 50,000 names of case_06. Its queries are `m`, `meas_`, `chr`, `mesa`, `cahr`, `cr0`, `char 1` and `0` (limit 20, median of 7). Add a negative control: "case-exactness by a raw re-classification of every member of the group at the cut" → `mesa` ≈ 700 ms → RED. |
| E3A-02 | MAJOR | R-A2L-MATCH.36 · `rank` step 4 (`graph-inc4.md:172`) · `_fuzzy_token_distances` (`:346`) · QSET (`02-test-cases.md:15`) | **Each long query word costs a full trie walk.** The fuzzy tier walks the trie once for every query token, before it checks any candidate. A token of 6 letters or more (2 edits) costs about 45 ms per walk (W: `nzukij` 45.0 ms), and a token of 3–5 letters about 3 ms. So a query costs about 45 ms per long word. A specific multi-word query finds fewer than 20 names in the text and token tiers, so it always reaches this tier. **QSET does not have the class.** No QSET query has more than one token of 6 letters or more (`Ierxjr_Eud`, `Nzukij`, `temp_sensor_max`, `pposbxiif…`). **Measured on REF itself**, words of 6+ letters with one transposition each, E2 tier: 4 words 194.9–293.9 ms, 5 words 243.7–248.3 ms, 6 words 282.6–296.8 ms (probe 2, load 6–7.5); at load about 1.6, 4 words 174.6–186.6 ms (probe 1 §A). **The paste-modal workload:** 100 REF names, each with one letter substituted, ranked at limit 3, take 9.91–10.92 s in all, at most 240.6–422.9 ms per label. | **Rewrite step 4: compute the maps lazily.** Compute the per-token maps in ascending allowed edits: 0 first, then 1, then 2. After each map, intersect the candidate names: the first map's names minus those already found, then the names of each later map. Once at most 300 candidates remain, stop walking and check the other query tokens per candidate with `_prefix_distance`, memoised per token id. **The lists are the same:** asserted equal to the E2 tier for every REF and case_06 query in probe 2, under each case-exactness variant. **Measured with E3A-01's fix:** REF worst 71.2 ms (the 4–6-word queries included; QSET's `temp_sensor_max` drops from 62.8 to 16.9 ms), case_06 85.5 ms, and the paste workload 1.28 s (at most 31.4 ms). **Fixture:** add three multi-word queries to QSET, for example `njraipjtbtu lsuakcoj hsxgibymjxu orfltalc uadvdygb zobnkw`, `votklbi fjblnabj qghque pdjxmq tiprdynotu djchlitjt` and `lmmwngodou jadkvqy khbnukc qomfrybiza evfwbqj` (probe 2 lists them). Add a negative control: "a map for every query token before the candidate check (the E2 tier)" → 296.8 ms → RED. **Pin the constant:** the graph states the 300 in the step text. |
| E3A-03 | MEDIUM | R-A2L-MATCH.37 negative control (`01-requirements.md:141`) · its graph example (`graph-inc4.md:76`) | **The control is another design, not a mutant.** It is "the pilot v3 index", a different design, so E5's mutant table cannot apply it to `label_match.py`. **One-structure mutants stay under the bound** (probe 1 §D): every `array` as a Python list 62.1 MiB, a nested-dict trie of the tokens added 50.6 MiB, a per-name tuple of token strings added 41.8 MiB. All three are GREEN at 64 MiB. **Only two together go RED** (probe 3): dict trie and token tuples 75.7 MiB; lists and token tuples 87.2 MiB. The bound therefore catches a return to a v3-class design, not one structure regressing. | **Name the product mutant:** "v3's structures added to the pinned index: a nested-dict trie of the tokens and a per-name tuple of token strings" → 79,390,164 bytes (75.7 MiB) → RED. In the Base column, record that a one-structure regression is not caught at 64 MiB. **Or tighten the bound** (an orchestrator ruling) to 32 MiB: the design at 18.1 MiB keeps a 1.77× margin, and each one-structure mutant goes RED. D-12 D offered 64 MiB only "for example". |
| E3A-04 | MEDIUM | G-T2 (`graph-inc4.md:17`, E2-4 `:405`, E4 notes `:468`, `:470`) · .35 / .36 thresholds (`01-requirements.md:139-140`) | **Three conflicts with the law guards that E5 runs.** **(a) A memory test with the timing mark.** If the .37 tracemalloc test is marked `serial_timing`, it trips R-TST-002. It compares bytes, not a clock interval, so the guard reports "serial_timing on a test that is not a timing arm" (`tests/test_suite_hygiene.py:264-269`, `:391-402`; pinned by R-TST-004, `:470-482`). E2-4's reason ("tracemalloc traces the whole process, so the memory test runs serially") does not hold: tracemalloc traces one process, and an xdist worker runs one test at a time, so the serial lane gives no extra isolation. **(b) A raw time bound.** An assertion such as `median <= 0.2` trips R-TST-040/041: "timing bound without report_margin" (`:273-278`, `:1451-1453`). **(c) The bounds also run in CI.** CI lane 2 runs `serial_timing` on `ubuntu-latest` (`.github/workflows/tui-ci.yml:67`, `:77`). There `timing_bound` doubles a bound (`tests/support/timing.py:20`, `:36-42`), while the rows name cachyos-rtx only. | **E4 notes:** write `assert median <= report_margin("R-A2L-MATCH.36 <query>", median, timing_bound(0.200))`, and the same with 5.0 for .35. The .37 test carries no `serial_timing` mark and asserts a plain byte bound. Correct E2-4's reason. **Rows .35 and .36:** add "(× 2 when `CI` is set: `tests/support/timing.py`)". |
| E3A-05 | MINOR | CTX *digit* (`01-requirements.md:30`), *whitespace* (`:25`) · E2-5 / E2-6 (`graph-inc4.md:406-407`) · cases of .1 and .11–.13 | **Code points, as E2-5 asked.** The definitions state most of E2-5's comparisons by code point: *uppercase letter*, *lowercase letter*, *letter* (above U+007F) and *separator* ("every other character"). **Two gaps.** *digit* reads "0 to 9" with no code points, so under a Unicode reading U+0663 is both a digit and, by *letter*, a letter. *whitespace* names its six characters but gives no code points. **No case pins the choice.** An implementation that uses `str.strip()` and `str.isdigit()` passes all 110 cases, because E2-6 left the derived examples optional. | **Definitions:** *digit* becomes "0 to 9 (U+0030 … U+0039)", and *whitespace* gets its code points: U+0020, U+0009, U+000A, U+000D, U+000B, U+000C. **Add two cases** (values from the E1 oracle, probe 3): **R-A2L-MATCH.1/4**: C08, U+001C followed by `VALUE_0001` → exactly [VALUE_0001 · token · (0,5),(6,10)]; with `str.strip()` it becomes `exact` → RED. **R-A2L-MATCH.12/4**: [`٣٣٣_X`], `٣٣٤` → exactly [٣٣٣_X · fuzzy · (0,3) · e1]; with `str.isdigit()` the token becomes a digit token with 0 allowed edits, so the result is [] → RED. |
| E3A-06 | MINOR | D-5 (`E1-rulings.md:51`) · CTX *edit distance* (`01-requirements.md:49-53`) · cases of .10 / .13 | **D-5's claim is wrong.** D-5 says the optimal string alignment distance (OSA) and unrestricted Damerau-Levenshtein (DL) are "never decisive at ≤ 2 edits on words". They can be. `crxuve` → `curve`: OSA prefix distance 3, DL prefix distance 2 (probe 1 §E). So over C08 the rows give [], while an implementation of DL lists CURVE_0001 … as fuzzy with 2 edits. **No case separates D-5's options A and B.** | **Add R-A2L-MATCH.13/4:** C08, `crxuve` → [] (oracle: [], probe 3). Negative control: unrestricted Damerau-Levenshtein → 20 CURVE entries, fuzzy, 2 edits → RED. Correct D-5's sentence. |
| E3A-07 | MINOR | `E1-slice.md:9-11`, `:15-30` | **The slice is out of date.** It still lists 9 functions and 3 types, with a design note (dict trie, bitmasks, "~137 MiB") that the memory row removed. E2-rulings accepted 8 more functions and 1 more type. The skill's trace runs through the slice ("every changed function maps to a requirement through the E1 slice"). `trace_check.py` is run with `--req 01-requirements.md E1-slice.md`, as in batch-101's `04-validation.md`, but it checks files only, so it will not catch this. | **Add rows** for `LabelIndex.__len__`, `_char_mask`, `_at_boundary`, `_subsequence`, `_parse_query`, `_token_range`, `_build_trie`, `_fuzzy_token_distances` and `_Query`, each with the rows of its graph `req:` line. **Update the totals:** 17 functions, 4 types, 18 nodes. **Replace the design note** with a pointer to graph E2-1. Apply E3A-01 to these rows (`_parse_query` without `fold`). |
| E3A-08 | LOW | `_tokens` (`graph-inc4.md:209`) · `_at_boundary` (`:261`) | **The cut rules are written twice.** The token cut rules are encoded as a scan (`_tokens`) and again as a test of an offset's neighbours (`_at_boundary`). X §E showed the two agree on the pilot (572,421 offsets). In product code, though, they are two places to keep in step. | Derive `_tokens` from `_at_boundary`. A token starts at each offset that is not a separator and where `_at_boundary` holds, and runs up to the next separator or the next such offset. The rules are then written once, and every example stays as it is. |
| E3A-09 | LOW | R-A2L-MATCH.29 (`01-requirements.md:128`) | **A normal case in the `If` form.** .29 uses `If` for the normal alternative of .28. A query that occurs at no boundary offset is not a defect, and the canon reserves `If` for "a defect in the input, a missing file, a bad argument" (`REQUIREMENTS.md:18`). | Rewrite it as: "When the system lists with the rule `substring` a name in which the query text occurs at no boundary offset, the system shall give it one match span over the leftmost occurrence of the query text." Cases .29/1 and /2 change from robustness to normal. |
| E3A-10 | INFO | I-3 consumer note (`graph-inc4.md:60`) · PLAN Inc 7 row | **Notes for Inc 7; I-3 stays as pinned.** **(a) Found or missing.** The paste modal's found/missing status is case-sensitive membership in `index.names`, never `rule is EXACT`: exact folds A–Z, so `rpm` is `exact` for `RPM`. **(b) Closest names cost about 0.1 s per label** with the E2 tier at 50,000 names (100 labels in 10.9 s), and about 13 ms after E3A-02. Even then they should be computed for the visible rows or in a worker. **(c) Display.** On 3.11.18, `f"{MatchRule.FUZZY}"` renders `MatchRule.FUZZY` (probe 1 §F), so render `rule.value`. **(d) Typing during the build.** At 50,000 names the build takes 1.8 s, so Inc 7 needs a "not ready" state. **(e) Names already in the list.** Leaving them out is not part of I-3. If G2 asks for it, Inc 7 proposes it at its E2. I-5 already splits a paste with `str.split()` (`a2l_parameter_picker.py:106`), so pasted labels never carry U+00A0 into `rank`. | Carry (a)–(e) into Inc 7's E1 brief. |
| E3A-11 | INFO | `[Data: LabelMatch]`, `[Data: MatchRule]` (`graph-inc4.md:30-43`) · E2-3 | **A string can pass as a rule.** `MatchRule` is a `str` mixin, so `LabelMatch(…, rule="fuzzy", …) == LabelMatch(…, rule=MatchRule.FUZZY, …)`. A whole-list `==` therefore cannot tell whether `rank` returns members or plain strings. | G-T1 adds one interface check: `type(m.rule) is MatchRule` for every entry of one ranked list. |

## 2. Answers to the questions routed to E3

### 2.1 E2-3 — the three details `E1-rulings.md` §5 left open: **all three accepted**
1. **`LabelIndex` is a frozen slots dataclass with `eq=False, repr=False`. Accepted.**
   - `eq=False` keeps identity equality and identity hashing, so Inc 7 can key a cache by index. Comparing two 50,000-name indexes by value would mean nothing.
   - `repr=False` keeps 50,000 names out of tracebacks, including Rich tracebacks that show locals.
   - `slots=True` needs Python 3.10 or later; the project requires 3.11 or later (`pyproject.toml:44`).
   - `frozen` does not freeze the `array` buffers. "Never changed after the build" is a contract, and the docstring should say so.
   - Private fields as `__init__` parameters are acceptable, since only `build_label_index` constructs the class.
2. **The query type check runs before the limit check. Accepted.** Errors come in a fixed order. An argument error is raised even where `limit < 1` would have returned `[]`, so it fails loud. `index` gets no type check. A list passed in, as in PLAN's former `rank(query, names, limit)`, raises `AttributeError` on a private field: loud enough, so no guard (prefer removing).
3. **`LabelMatch` compares by value. Accepted.** Tests can assert whole ranked lists with `==`, and Inc 7 can hash entries. A test still has to check the rule's type once (E3A-11).

### 2.2 The +8 functions and +1 type over the E1 slice: **accepted, each justified; the slice record needs updating (E3A-07)**

| Added | Reason (checked against the rows and the measurements) | Graph `req:` mapping |
|---|---|---|
| `LabelIndex.__len__` | already in the slice's `LabelIndex` row and in I-3 (`E1-rulings.md:79`) | .17, a fair mapping |
| `_build_trie`, `_fuzzy_token_distances`, `_token_range` | .37 removed the dict trie (77.9 MiB). Without the trie arrays, the walk over the bare sorted list takes 158.3 ms (B4a), a 1.26× margin. | .35–.37 · .10–.13, .36 · .8, .11, .30 |
| `_at_boundary` | replaces the per-name boundary bitmasks (.37) | .21, .28, .29 |
| `_char_mask` | the subsequence prefilter: 425 KB, about 10 lines; it lets more names through to the full check, never fewer | .9, .36 |
| `_subsequence`, `_parse_query` | each has two callers (a tier and `_classify`; the folded and the raw query) | .9, .31 · .1–.3, .8, .24 |
| `[Data: _Query]` | the parsed query | — |

18 nodes and 5 entities, under the cap of about 40. After E3A-01, `_parse_query` drops `fold` and `_Query` its `folded` field, and `_classify` keeps one mode. **Smallest design:** the two prefix-distance routines (per pair for spans; the trie walk for candidates) are both needed. One duplication can go (E3A-08). Case-exactness for token, fuzzy and subsequence is the costliest feature with the least use: the census finds 0 case twins in 234,654 fixture names (E3A-01).

### 2.3 E2-5 — are the code-point comparisons stated in the definitions?
**Partly.** *Uppercase letter*, *lowercase letter*, *letter* and *separator* are by code point, and *whitespace* names exactly six characters. *Digit* has no code points, and no case pins any of these choices (E3A-05). **E2-5's open question** is whether U+00A0 should count as a letter. Keep the definition (D-2): pasted lists reach `rank` through I-5, whose `str.split()` already drops U+00A0, so only a typed U+00A0 can arrive, and it still finds the name, as fuzzy with 1 edit.

### 2.4 Is I-3 right for Inc 7?
**Yes.**
- **Building.** Build once per A2L load generation, off the UI thread: 1.8 s at 50,000 names.
- **Ranking.** Rank once per debounced keystroke, with the dropdown's free rows as the limit. A limit below 1 gives `[]`, which is the right answer when no row is free.
- **Threads.** The index never changes after the build, so a worker can rank while the UI thread holds it.
- **Highlight.** Spans are code-point offsets into `name`, the same offsets as Rich `Text.stylize`.
- **Paste modal.** Each entry's rule and edits let the modal drop weak suggestions (for example subsequence).
- **Consumer notes:** E3A-10 (a)–(e).

### 2.5 Is the ranking a total, deterministic order?
**Yes.** `_order_key` is (rule position, key, length, case-exact, name). The last part, the name in code-point order, makes it total over distinct names. Each group is sorted, so neither set order nor input order matters (case .25/2).

The tier stop is sound. Tiers come in rule order, and each tier finds every name of its rule:
- the text tier scans every name;
- the token tier intersects the postings of contiguous token-id ranges;
- the fuzzy tier takes the union of the smallest map's postings, then checks each candidate in full;
- the subsequence tier scans with a mask that only ever lets more names through.

Re-run confirmation: 0 mismatches against the oracle (944 names, 409 queries × 4 limits) and against v3 on REF (322 queries).

**D-3** (fuzzy before subsequence) rests on the measured 46/60 against 9/60, and the order key and the rows agree. **D-6** is exact as defined. Note that case-exactness compares the rule, not the key: `count` on `DiscountCount` is case-exact although its case-exact occurrence is not at a boundary. The cost of D-6 is E3A-01.

### 2.6 Are D-4 and D-5 exact and testable?
**D-4: yes.**
- **Every token is covered.** The three bands cover every letter-token length (1–2, 3–5, 6 or more), counted in code points, and every digit token (0 edits).
- **Each band has a case on each side**, plus a mutant that moves the boundary: .11/1–3, .12/1–3, .13/1–3.
- **Real cases.** The derived U+0663 case (E3A-05) belongs with them.

**D-5: exact, but not fully separated by the cases.**
- **The definition is exact:** OSA to the nearest prefix of the name token, the empty prefix included.
- **Against Levenshtein**, the cases separate it (`cuvre`, `mpa`).
- **Against unrestricted Damerau-Levenshtein**, no case separates it (E3A-06, `crxuve`).

### 2.7 Are the three bounds measured the way the rows say, with negative controls that go RED?

| Row | As the row says? | Negative control | Note |
|---|---|---|---|
| .35 build ≤ 5.0 s | ✓ Median of 3 builds of REF, `serial_timing`, load printed. Re-run: 1.768 s (1.768, 1.737, 1.800). | Quadratic preparation, not run. It is a real mutant, but runs for minutes, so the mutant table needs a timeout. | E3A-04 (b, c) |
| .36 rank ≤ 200 ms | ✓ on its fixture: 22 QSET queries, median of 7 each. Re-run worst: 61.6 ms (`temp_sensor_max`). | "No preparation" (9.15 s) and "scan every distinct token" (about 1.2 s) are both far above the bound, so both go RED. | **The fixture misses two cost drivers:** E3A-01, E3A-02. |
| .37 index ≤ 64 MiB | ✓ tracemalloc peak during one build of REF. Re-run: 18,940,597 bytes, byte-identical to E2. | **Not a product mutant.** Mutants of one structure stay GREEN; two together go RED (E3A-03). | E3A-04 (a) |

## 3. The re-run of the E2 pilot (`codewire/i4e2-pilot4.py`)

| Claim (E2) | Re-run on cachyos-rtx (load 0.53 → 1.96) | Result |
|---|---|---|
| §1: every example of `02-test-cases.md` equals the v3 oracle | 0 mismatches and 0 disagreements between a tier and `evaluate_b`. The section-1 lists are line-for-line identical to `i4e2-pilot4-transcript.txt` (`diff` of lines 7–358 empty). | ✓ confirmed |
| §2: IndexC equals the oracle on v3's pool | 944 names, 409 queries × 4 limits: 0 mismatches | ✓ |
| §3: IndexC equals IndexB (v3) on REF | the same 77,256 tokens; 22 QSET + 300 generated queries: 0 mismatches | ✓ |
| §4: peak 18.1 MiB; v3 77.9 MiB | 18,940,597 and 81,652,763 bytes, identical to the byte | ✓ |
| §5: build median 1.798 s; worst rank median 62.6 ms | build 1.768 s; worst 61.6 ms (`temp_sensor_max`; `Nzukij` 60.5 ms) | ✓ (within 2 %) |

**What the 0-mismatch claim covers.** IndexC reuses the oracle's `tokens`, `fold`, `allowed`, `is_subseq` and `query_parts`, and it emits each entry through the oracle's `evaluate_b`. The claim therefore checks the tiers: which names they find, with which rule and key, in what order, and where they cut. It does not check those helpers. X checks them separately against the definitions. Every one of these implementations has the same author as the rows (`E1-rulings.md` §8).

## 4. Other checks

| Check | Result | Evidence |
|---|---|---|
| EARS form, one `shall`, subject "the system" | ✓ for 37/37 rows, except .29's form (E3A-09) | `01-requirements.md:80-141` |
| Each row has a numeric threshold and a negative control | ✓ 37/37. The control of .37 is not a mutant (E3A-03). | ibid. |
| Each case can fail on base and pass after, and `full` is possible | ✓ The module is new, so every case is RED on base (import), and `rank` itself produces every asserted value. | `02-test-cases.md:19-128` |
| The coverage the graph claims | ✓ 110/110 cases and 37/37 rows have an example (`i4e2-coverage-check-transcript.txt`) | ibid. |
| Real callers | ✓ No product caller changes. `parse_a2l_file` has 5 real call sites (`extract-e2/diff-report.md`) and is context only. | ibid. |
| `trace_check.py` at E5 | SLICE passes only with `--req 01-requirements.md E1-slice.md`, the batch-101 practice: `01-requirements.md` alone does not name `label_match.py`. US, CASE and TEST are as designed. | `trace_check.py:87-97`; batch-101 `inc-13/04-validation.md:65` |
| E2-7 (`build_label_index("VALUE")`) | No guard, as E2 proposed. Inc 7 passes the list of tag names, and a guard would add an error path with no row. | — |
