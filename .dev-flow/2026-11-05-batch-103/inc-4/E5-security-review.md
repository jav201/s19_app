# Inc 4 — E5 security review: label similarity matcher

Batch 2026-11-05-batch-103, increment 4, stage E5. Reviewer: security-reviewer (Opus 5.5). The change under review is `git diff a2043cfd HEAD -- s19_app tests` on branch `b103-inc4-code` (HEAD `885634bf`): `s19_app/tui/services/label_match.py` (new, 1,050 lines, sha256 `24564b32…edb9b`), `tests/test_b103_label_match.py`, `tests/test_b103_label_match_perf.py`, and `tests/test_id_registry.py` (a count, 267 → 269). The yardstick is `E3-security.md` (rounds 1–2), `E3-rulings.md` (with addenda A-1…A-4), `01-requirements.md`, `codewire/graph-inc4.md` and `E1-rulings.md` §7. This review is read-only toward the code and the records: this file, `evidence-e5/sec-e5-*` and two lines in `steps.log` are the only writes.

**Probes (state `executed`).** All runs used <runner>, Python 3.11.18, under an 8 GiB address-space cap with a per-case alarm. They imported the real module from `/tmp/b103-e5-4-sec/tree`, a `cp -a` of the read-only `~/work/b103-int4`; every transcript prints `s19_app.__file__` and the module's sha256, and all 13 show the same pair. HOME, XDG and LOCALAPPDATA pointed to `/tmp/b103-e5-4-sec/<user>`, with `PYTHONDONTWRITEBYTECODE=1`. No clipboard was touched.
- **Probe:** `evidence-e5/sec-e5-probe.py`, adapted from the E3 probes (`i4e3s-probe.py`, `sec-r2-probe.py`, `sec-r2-band.py`), with the pilot class replaced by `build_label_index` + `rank`. The runner is `sec-e5-run.sh`.
- **Fixtures:** REF, REF6, LONG, QSET, PSET and the LONG queries come from the test module's own builders, so the strings are identical.
- **Oracle:** the E1 `evaluate_b`, from an unchanged copy of the E3 pilot (sha256 equal to E3's).
- **Probe versions:** modes caps, perf, paste, mem, spans and det ran on probe sha256 `875b8fa2…`; adv and adv2 on `7b6331d6…`; fixcheck and build on the final `8700b63b…`. Each later edit changed only adv's `crafted`/`memo_query`, or added a mode, so the earlier modes' code is unchanged.
- **Host load:** 0.2–2.5 on 16 cores. Another agent's single-thread `pytest` of the perf tests shared the host during perf and adv, and each transcript prints the load.

## Verdict

**FAIL.** One MAJOR is open: **E5S-01**. R-A2L-MATCH.40 reads "any query of at most 256 characters, within 1.0 s". A crafted name list of 300 names breaks it by up to 15.8× and allocates 464 MiB in one ranking.

The cause is the design's per-candidate check in step 4, together with the re-classification in step 6, so the finding is a `design-gap`. The fix is cheap, and its parts were measured on the same list: one walk per distinct token plus a check from the maps take about 0.34 s, against 15.5 s. Step 6 then takes its edits and spans from those maps (E5S-01 fix).

Every E3 security ruling is implemented as ruled (table below). Hostile input raises nothing and every span stays inside its name. The ranking is identical across hash seeds.

Count: 0 CRITICAL, 0 HIGH, **1 MAJOR**, 1 MEDIUM, 2 MINOR, 1 LOW, 1 INFO. Every mitigation below is `planned`. This verdict covers the E5 security gate of Inc 4 only and authorizes nothing beyond it.

## Findings

| Id | Severity | Tag | Where · row | Defect (measured) | Fix |
|---|---|---|---|---|---|
| E5S-01 | **MAJOR** | design-gap | `label_match.py:433-470` (≤ 300 → per-candidate check, memo keyed `(token, token_id)` at `:456-460`), `:378` + `:818-835` (`_classify` re-scores every listed FUZZY name) · graph step 4 (`graph-inc4.md:187`) and step 6 (`:189`) · R-A2L-MATCH.40 (`01-requirements.md:147`) | **On a crafted list, the per-candidate check costs (candidates ≤ 300) × (distinct query tokens) × (tokens per candidate name), and `_classify` repeats that work for each of the `limit` listed names.**<br>• **The list:** 300 names of 1,024 characters, each with 268 tokens: one rare digit token, 50 three-letter hits and 217 junk tokens that are distinct across names, so the memo never hits. 49,700 REF names pad it to 50,000. About 300 KB of names, a normal file size.<br>• **The query:** the digit token plus *n* four-letter tokens, each 1 edit from a hit.<br>• **Measured (median of 3, limit 20; `sec-e5-adv-transcript.txt`):**<br>  – 4 tokens (21 characters): **984 ms**<br>  – 8 tokens (41 characters): 2.19 s<br>  – 16 tokens: 4.63 s<br>  – 32 tokens: 9.72 s<br>  – 51 tokens (256 characters): **15.8 s**<br>• **Calls:** one walk, 3,257,550 `_prefix_distance` calls in the tier and 273,360 in `_classify` for the 20 listed names.<br>• **Memory:** tracemalloc peak **464.0 MiB** in one ranking (16 tokens: 118.3 MiB).<br>• **Without the 300 stop** (2,000 crafted names, map path): 51 tokens take 2.52 s and 32 tokens 1.55 s.<br>• **Reachable:** a supplier A2L plus a pasted or typed name. Inc 7 ranks each pasted name separately (≤ 256 characters), in a worker that cannot be stopped, so stale rankings pile up.<br>• **Origin:** E3S-01 (c), round 1 of this review, proposed the per-candidate switch. Round 2 measured it only on REF and REF6, whose names hold at most 27 tokens. | **(a) Step 4:** always walk every distinct query token, with no 300-candidate switch. While taking each map's postings, keep each name's smallest distance per token, which costs the same as today's union. The key is then Σ count × best, and no per-candidate `_prefix_distance` call is made.<br>**Measured** (`sec-e5-fixcheck-transcript.txt`) on the same list:<br>• 51 walks take 177.9 ms and a candidate check from the maps 158.9 ms (≈ 0.34 s, against 15.5 s); 4 tokens take 11.5 + 12.0 ms.<br>• **Pin the posting variant, not that check.** A check from the maps still grows with candidates × name tokens: today's map path takes 2.52 s on 2,000 crafted names. The posting variant grows with the maps' postings only. It was **not measured**.<br>**(b) Step 6:** take a FUZZY entry's edits and spans from the step-4 maps, looking up the listed name's token ids, instead of re-running `_classify`. Today `_classify` alone takes 1,128.5 ms for 51 tokens and 81.7 ms for 4.<br>**(c) Requirement:** add case R-A2L-MATCH.40/3, this list with the 4-, 16- and 51-token queries.<br>• Negative control: today's per-candidate check → 15.5 s → RED.<br>• The graph changes step 4, step 6 and the `_classify` node, so the requirement and the graph are updated together. |
| E5S-02 | MEDIUM | design-gap | `label_match.py:298-307` (the substring key, per occurrence, over every SUBSTRING name), `:350-358` (the subsequence scan of every name), `:147-200` (build) · R-A2L-MATCH.35, .37, .40 (`01-requirements.md:143`, `:145`, `:147`) · E3S-03 (c) · `E1-rulings.md` §7 (`:99-104`) | **The E3S-03 (c) residual (cost linear in the total characters of the names) is real in the code. It breaks .35 and .40 as worded, and the backlog row the E3 ruling accepted was never written: §7 holds BL-I4-1…4 only.**<br>• **Substring key:** names `'x' + 'ab' * 509 + 'Q' + tag` (1,024 characters), query `ba`, which has about 509 occurrences per name and none at a boundary (`sec-e5-adv-transcript.txt` A3):<br>  – 5,000 such names: **1.03 s**<br>  – 50,000 names: **10.1 s**, and the build takes **26.3 s** (.35 bound: 5.0 s)<br>• **Subsequence scan:** 50,000 names of 265 characters with a 255-character query: **0.99 s** (`sec-e5-adv2-transcript.txt`).<br>• **Build memory:** 50,000 names of one random 1,024-character token each take **29.3 s** to build. RSS grows by 243 MiB, and tracemalloc measures 6.7 B per name character, so about 0.33 GiB, against .37's 64 MiB (`sec-e5-build-transcript.txt`).<br>• **No count cap:** 1,000,000 short names: build 12.5 s, `sig` 1.75 s (`sec-e5-spans-transcript.txt`).<br>• All of these stay below `MemoryError` and raise nothing. | **(a)** Write the backlog row the ruling owed: "BL-I4-5 — bound the total characters of a prepared list (E3S-03 (c))".<br>**(b)** Word the scope of .35, .37 and .40 to match what they bound: record the measured residual in their Base column, as E3S-09's ruling did for .36. Or add an `If` row that refuses a prepared list over a total-character budget.<br>**(c) Optional, to cut the constant:** compute the substring key only at the name's boundary offsets, which number at most its tokens, instead of at every occurrence. |
| E5S-03 | MINOR | impl | `_prefix_distance`, `label_match.py:609-633` · graph node `_prefix_distance` (`graph-inc4.md:247`, "never query-token length × name-token length") | **The band is right, but the loop never stops.**<br>• **Correct:** 60,000 checks against a full OSA reference show 0 differences (`sec-e5-caps-transcript.txt` E).<br>• **The cost:** the loop runs over every name-token character and allocates a list of `m + 1` cells per character, so a call costs O(name-token length) iterations and O(m × n) cell writes.<br>• **Measured:** `('aaq', 'a' * 1020, 1)` takes **241.5 µs**, against 4.0 µs for `('aaq', 'aaaa', 1)`. LONG `'aaaaaq ' × 36` ranks in 232.6 ms, through 1,440 calls in `_classify` (≈ 160 µs each). | `for j in range(1, min(n, m + cap) + 1)`. This is exact: past `m + cap` the band is empty and `new[m]` stays at `cap + 1`. Optionally, also return as soon as a column's band minimum is above `cap`. Add the example `('aaq', 'a' * 1020, 1)` → `1`, with its cell count. |
| E5S-04 | MINOR | design-gap | `_classify`, `label_match.py:805`, `:820` · graph node `_classify` (`graph-inc4.md:312`, "for each query token") · A-2 | **The A-2 collapse reached the tiers but not `_classify`.** `_classify` still scores every query-token occurrence against every name token (`sec-e5-caps-transcript.txt` C):<br>• REF6 `'0 ' × 125 + 'chax'`: 7,560 `_prefix_distance` calls for 20 listed names, where the collapse would need 60;<br>• REF `'cnt ' × 64`: 192 calls.<br>The cost on the fixtures is small (≤ 79 ms per ranking), and the lists are unchanged by the collapse. | Iterate the distinct query tokens with their counts: edits += best × count, and each token's span is added once (`_join_spans` already merges equal spans). This is subsumed by E5S-01 (b) for FUZZY entries. It still applies to the TOKEN branch. |
| E5S-05 | LOW | impl | `evidence-e4/int-green-perf.txt` | **The E4 GREEN perf transcript keeps 38 of its 78 QC-TM lines, from 92.5 % margin up.** `qc_tm_summary_lines` (`tests/support/timing.py:98-121`) prints them in ascending order, so the 40 lowest margins were cut. They include REF6 `near tokens` (684.3 ms here) and `51 typos of char` (577.2 ms). The record's "0 under 20 % margin" therefore cannot be checked from the evidence. | Re-save the whole QC-TM section (no `tail`) in the next GREEN run's transcript. |
| E5S-06 | INFO | design-gap | `build_label_index`, `label_match.py:149` · I-3 errors (`graph-inc4.md:54-56`) | `build_label_index(None)` raises `TypeError: 'NoneType' object is not iterable`. That is not a pinned I-3 text, because I-3 says nothing about a non-iterable argument. It is harmless, and it fails loudly. | Add it to I-3's error list, or leave it. |

## E3 security findings against the code

| E3 id | Ruling | In the code | State |
|---|---|---|---|
| E3S-01 (.38) | the 256 cap, before any fold or tokenising (A-4 / E3S-13) | `:267-269`, before `_parse_query` (`:270`). Every query over 256 characters makes 0 matcher calls (U+00A0 and U+0085 are counted, not stripped). Every 64 KiB paste returns `[]` in ≤ 0.016 ms with a peak of ≤ 64.3 KiB (E3 r2: 45–70 ms, 6.6 MiB) | `executed`, verified |
| E3S-02 | case-exactness for exact, prefix and substring only, by string comparison | `:366-374`; REF6's worst query is 98.8 ms (`0`) | verified |
| E3S-03 (.39) | the 1,024 name cap; the trie keeps 258 characters per token | `:152-153`, before `_fold`, `_char_mask` and `_tokens` (longest text they see: 1,024). One 10,000,000-character name plus 1,000 × 1,025-character names build in 0.5 ms. `_TRIE_PREFIX` is used at `:37` and `:922`; 1,000-character tokens give 256 trie nodes each, and the build costs 6.7 B per name character (E3 round 1, without the truncation: 23.4) | verified; residual (c) → E5S-02 |
| E3S-04, -05 | Inc 7 consumer obligations | Not in this increment. 26,401 of 26,401 listed names are the input objects, so obligations (1)–(5) stand for Inc 7 | owed by Inc 7 |
| E3S-06 | `TypeError` for a `str` or `bytes` argument | `:143-146`; every pinned text is exact (`sec-e5-spans-transcript.txt`) | verified |
| E3S-07 | `_tokens` a tuple; no buffer written after the build | `:81`, `:206`. The sha256 of the private buffers and of the argument list are unchanged after 400+ rankings | verified |
| E3S-09 / A-2 | duplicate query tokens collapsed | Token tier `:315-318` (one `_token_range` per distinct token) and fuzzy tier `:408-411` (one walk per distinct token) | verified; not in `_classify` → E5S-04 |
| E3S-10 / A-1 | substring case-exact "anywhere" | `:371-372` (`raw in name`) | verified |
| E3S-11 / A-3 | banded `_prefix_distance` | `:613-615`; 0 of 60,000 checks differ from the full OSA reference | verified; loop length → E5S-03 |
| E3S-12 | QSET reproducible | The test module writes the strings and the seed (`test_b103_label_match_perf.py:113-145`) | verified |
| E3S-14 | keep the maps until the candidates are scored | `:413-418` | verified |
| Step 4 stop | the fuzzy tier stops when no candidate is left | 1 walk when the first map is empty; 2 walks when the second intersection empties the set (16 distinct tokens); 1 walk when every candidate was already taken | verified |

## Checked and clear

- **Hostile input:** 3,123 queries × 3 limits over 57 hostile names: 26,401 entries, **0 exceptions**, **0 bad spans** (none empty, outside `[0, len(name))`, unsorted or touching) and **0 mismatches** with the E1 oracle.
  - **The names held:** markup, ESC, NUL runs, BEL, CR, C1 controls, U+2028/2029, combining marks (leading and stacked), ZWJ, BOM, U+FFFF, U+10FFFF, astral characters, lone and paired surrogates, `İ`, `ß`, `ﬁ`, U+00A0, U+001C, U+0085, `''`, `' '`, and 500- and 512-token names.
  - **Other inputs:** non-`str` elements and arguments get the pinned `TypeError` texts. `limit` of `-5`, `0` and `10**30` behave as pinned.
- **Determinism:** with PYTHONHASHSEED 0, 1, 4242 and `random`, `hash('abc')` differs every time, yet the sha256 over 1,287 rankings is identical (`b528ae21…844c`). The rankings covered REF, REF6, LONG and the hostile names (`sec-e5-det-*-transcript.txt`).
- **Fixture timings** (median of 7, limit 20; `sec-e5-perf-transcript.txt`). Every PSET and LONG query, and every E3 shape beyond the tests, is within its bound:

  | Fixture | Worst median | Bound |
  |---|---|---|
  | QSET over REF | 70.4 ms | 200 ms |
  | REF6 queries | 98.8 ms | 200 ms |
  | PSET over REF | 119.8 ms | 1.0 s |
  | PSET over REF6 | 684.3 ms | 1.0 s |
  | LONG | 79.3 ms | 1.0 s |

  The tightest real-shape margin is REF6 `near tokens` at 684.3 ms, against 461.7 ms in the E3 addenda with the pilot: 1.46× under 1.0 s, at load 1.6–1.9 with one concurrent pytest (`sec-e5-perf-transcript.txt:94-118`). `51 typos of char` takes 577.2 ms. This is the E3S-09 residual, and the bound holds.

- **Memory:**
  - REF build peak: 21.0 MiB (.37 bound: 64 MiB).
  - One ranking on the fixtures: at most 12.1 MiB (REF6 `'0 ' × 128`).
  - All of case 06 (220,040 names): built with a 36.8 MiB peak; worst REF6 query 456 ms.
- **Isolation:** the module imports `array`, `bisect`, `dataclasses`, `enum` and `typing` only, and does no file, clipboard or network I/O. The tests write only pytest's temporary directory. The increment diff holds no secret, no home path and no operator name.

## Evidence

`evidence-e5/`, with sha256 prefixes:
- **Probe and runner:** `sec-e5-probe.py` (`8700b63b`), `sec-e5-run.sh` (`9e4fcbd7`).
- **Transcripts:**
  - `sec-e5-caps-transcript.txt` (`0ecc806e`)
  - `sec-e5-perf-transcript.txt` (`4da76132`)
  - `sec-e5-paste-transcript.txt` (`029633e3`)
  - `sec-e5-mem-transcript.txt` (`03981e0e`)
  - `sec-e5-spans-transcript.txt` (`77488974`)
  - `sec-e5-det-{0,1,4242,random}-transcript.txt`
  - `sec-e5-adv-transcript.txt` (`98d4042d`)
  - `sec-e5-adv2-transcript.txt` (`112902cc`)
  - `sec-e5-fixcheck-transcript.txt` (`0fa4c8aa`)
  - `sec-e5-build-transcript.txt` (`d0d6b192`)
- **Not run:** the Windows PC and CI (the brief's rule); CPython 3.12.

## Evidence checklist

- [x] Each finding has a severity, `file:line`, the row or case, a fix and a tag: the table above.
- [x] No secret values appear here: none exist in the diff, and none were read.
- [x] The verdict is explicit: **FAIL**, with E5S-01 MAJOR open, its mitigation `planned` and its fix measured but not applied. No HIGH is present.
- [x] New tool or integration: none. The module has no external action surface. The outbound effect, suggestions feeding Check and Patch specs, stays with Inc 7 (E3S-04 (4)).

## Round 2 (2026-11-06T23:05:00-06:00)

Re-review of E5S-01 and E5S-02 as `E3-rulings.md` "## E5 rulings" rules them (posting variant C with the switch at ≤ 512 name-token occurrences; .35/.37/.40 scoped by total characters; cases .40/3 CRAFT and .40/4 BAND), against the corrected code: `label_match.py` sha256 `394bf2f9…83a0` (diff `885634bf..HEAD -- s19_app tests`, HEAD `46128ab3`). Reviewer: security-reviewer (Opus 5.5), read-only toward the code and the records.

**Probes (state `executed`).**
- **Where:** <runner>, Python 3.11.18, an 8 GiB address-space cap and a per-case alarm, against `/tmp/b103-e5-4-sec-r2/tree` (a `cp -a` of the read-only `~/work/b103-int4`). HOME, XDG and LOCALAPPDATA pointed to `/tmp/b103-e5-4-sec-r2/<user>`, with `PYTHONDONTWRITEBYTECODE=1`. Every transcript prints `s19_app.__file__` and the module's sha256, and all 19 show the same pair.
- **Round-1 probe:** `sec-e5-probe.py` (`8700b63b`, unchanged) re-ran caps, perf, paste, mem, spans, adv, and det under 4 seeds.
- **New probe:** `sec-r2-probe.py` loads the round-1 probe for its fixtures, the oracle (E1 `evaluate_b`, uncapped OSA) and the instrumentation. It builds CRAFT and BAND with the test module's own builders. It can force either fuzzy path: `_FUZZY_SWITCH_CAP` 0 runs the map path only, and 10**9 runs the per-id path right after the first walk.
- **Probe versions:** dense and fuzz ran on `86ef259a`; craft, band, switch, fixcheck, subkey and buildscope on `97ba0957`; extra on `ecda78d6` (final). Each edit only added a mode.
- **Host load:** 1.4–6.0 on 16 cores. A correctness chain (fuzz, det, caps, spans, mem), buildscope and extra ran beside the timing chain, and every transcript prints the load.

### Verdict

**FAIL.** One MAJOR is open: **E5S-07** (`design-gap`).

E5S-01's defect is gone. CRAFT's 51-token query now takes 226.0 ms (15.8 s in round 1), with a 0.21 MiB peak (464.0 MiB).

R-A2L-MATCH.40, the row E5S-01 protected, still breaks inside its reworded scope, through the map path the correction kept. On U6, 50,000 names holding 2,050,000 characters:
- a 32-token query takes 3.23 s;
- a 76-token query takes 7.44 s in the fuzzy tier alone;
- one ranking holds **1,470 MiB**.

The corrective code matches the corrected graph, so there is no `impl` defect. The gap is in the design, and it was already in the E3 map path: the same per-id loop, with every table kept. Round 1 did not measure it on lists like these. There I wrote that the posting variant "grows with the maps' postings only" and did not multiply that by the number of distinct query tokens.

Count (round 2): 0 CRITICAL, 0 HIGH, **1 MAJOR** (E5S-07), 1 MEDIUM (E5S-08), 1 LOW (E5S-09). Every new mitigation is `planned`: part (a) of E5S-07's fix is measured, and none is applied. This verdict covers the Inc 4 E5 security gate and authorizes nothing beyond it.

### Round-1 findings

| Id | State | Why (evidence) |
|---|---|---|
| E5S-01 MAJOR | **closed** (as found) | **The per-candidate check and the re-classification are gone.**<br>• **CRAFT:** 0 `_prefix_distance` calls in the tier and in `_classify`. 4/8/16/32/51 tokens: 29.1/45.2/77.6/146.2/226.0 ms; peaks 0.13/0.21 MiB; both forced paths give the same lists (`sec-r2-craft-transcript.txt`). The round-1 A1 shapes take 28.6–322.9 ms (`sec-r2-r1-adv-transcript.txt`).<br>• **The switch boundary is exact** (`sec-r2-switch-transcript.txt`). 511 and 512 occurrences: 1 walk and 345/348 `_prefix_distance` calls. 513: 4 walks and 0 calls. The lists equal the oracle's.<br>• **Per-id path** (`sec-r2-band-transcript.txt`): .40/4 BAND takes 119.9 ms. The worst shape the switch admits is 102 names × 4 tokens of 252 characters: 510 occurrences, 408 distinct long tokens. It takes 205.5 ms with a 0.08 MiB peak, and its list equals the oracle's.<br>• **But** the row it protected still breaks elsewhere → E5S-07. |
| E5S-02 MEDIUM | **open: superseded by E5S-07 and E5S-08** | **(a)** BL-I4-5 is written (`E1-rulings.md:126`).<br>**(b)** The rows now name their lists' total characters, but total characters is not what they bound. Inside the reworded scopes, .40 breaks (E5S-07) and .37 breaks (E5S-08).<br>The round-1 shapes, cut to .40's scope, hold: the substring key takes 478.3 ms and the subsequence scan 208.0 ms (`sec-r2-subkey-transcript.txt`). |
| E5S-03 MINOR | closed | `('aaq', 'a' * 1020, 1)` takes 4.5 µs (241.5 µs). 60,000 checks against the full OSA reference show 0 differences (`sec-r2-r1-caps-transcript.txt` E). |
| E5S-04 MINOR | closed | `_classify` iterates the distinct tokens and calls no `_prefix_distance` (caps C: 0 calls in `_classify` on all six shapes). |
| E5S-05 LOW | closed | `corrective-tests-fix-tree-full-perf.txt` keeps the whole QC-TM section: 81 bounds, every margin printed. |
| E5S-06 INFO | unchanged | `build_label_index(None)` still raises the unpinned `TypeError` (spans transcript). |

### New findings

| Id | Severity | Tag | Where · row | Defect (measured) | Fix |
|---|---|---|---|---|---|
| E5S-07 | **MAJOR** | design-gap | `label_match.py:1172-1173` (a pruned trie node expands into one dict entry per token id), `:584` (each table kept for step 6), `:588-590` (one Python `set.update` per token id), `:603` (one dict update per candidate per distinct token) · graph step 4 (`graph-inc4.md:192`: "the cost of a walked token is its walk and its table's postings") · R-A2L-MATCH.40 (`01-requirements.md:147`), scope "50,000 names that hold at most 2,356,624 characters" | **The map path costs, and holds in memory, the sum over the distinct query tokens of each table's ids and postings.** A query of at most 256 characters can carry up to 85 distinct 3-letter tokens (camel-joined), and each table can cover the whole vocabulary. So a list well inside .40's scope breaks it.<br>• **Lists** (50,000 names each, `sec-r2-dense-transcript.txt`):<br>  – U1: `ab` + 4 letters (300,000 characters, 50,000 distinct tokens)<br>  – U6: six such tokens per name (2,050,000 characters)<br>  – M1: half U1, half REF (1,166,622 characters)<br>  – E2: `abcd` + 4 letters, with 2-edit queries<br>• **Queries:** `abX`, `aXb` and `Xab` tokens, camel-joined. Each is within 1 edit of every `ab…` token.<br>• **Measured** (median of 3, limit 20):<br>  – U1: 52 tokens 1,406.9 ms; 76 tokens **1,959.9 ms**<br>  – U6: 16 tokens 1,619.6 ms; 32 tokens **3,229.0 ms**; 76 tokens **7,438.4 ms** in `_fuzzy_tier` alone (`sec-r2-fixcheck-transcript.txt`)<br>  – M1: 76 tokens 1,237.1 ms<br>  – E2: 36 tokens 1,007.8 ms<br>• **Where the time goes:** U6 with 32 tokens makes 9,600,000 table ids and as many `set.update` calls. cProfile puts 4.1 s in `_fuzzy_tier`'s own time.<br>• **Memory** (tracemalloc, one ranking): U6 76 tokens **1,470.4 MiB** (dense). The shipped `_fuzzy_tier` alone: 320.5 MiB (U1, 76 tokens), 627.9 MiB (U6, 32 tokens) (`sec-r2-extra-transcript.txt`).<br>• **The switch's own corner** (`sec-r2-switch-transcript.txt`): 2 candidate names of 302 occurrences each (604 > 512) keep the map path for all 76 tokens: **1,261.7 ms**. With 1 such name (302 ≤ 512) the switch fires: 11.0 ms. The E3 switch (at most 300 candidates) would have fired here. This is a case of this finding, not a separate one.<br>• **The lists are right:** 0 exceptions, 0 bad spans, and both paths agree. Only cost and memory break.<br>• **Reachable** the same way as E5S-01: a supplier A2L whose names share a two-letter token head, plus one typed or pasted name. Inc 7's worker cannot be stopped, so stale rankings stack their peaks. | **(a) Range tables** (measured: `sec-r2-fixcheck-transcript.txt`, `sec-r2-extra-transcript.txt`). A pruned node's tokens have contiguous ids, and their CSR postings form one contiguous slice. So:<br>• `_fuzzy_token_distances` returns `(lo, hi, d)` ranges;<br>• step 4 takes one `postings[ps[lo]:ps[hi]]` slice per range, and the totals are counted at C level;<br>• step 6 finds a token id's distance by bisect over the ranges.<br>Same totals on all 14 checks. Measured:<br>  – U6: 76 tokens 7,438 → 1,350 ms; 32 tokens 3,402 → 546 ms<br>  – U1, 76 tokens: 1,857 → 751 ms<br>  – M1, 76 tokens: 1,272 → 650 ms<br>  – E2: 1,035 → 556 ms<br>  – CRAFT: 195 → 198 ms<br>  – REF6 PSET shapes: ≤ 54.4 ms (one is slower: 30.3 → 54.4 ms)<br>Peaks: 18.6–19.3 MiB, against 320–1,470 MiB.<br>**(b) (a) is not enough.** U6 with 76 tokens still unions 300,000 postings per distinct token (1.35 s). The row needs a work bound or a true scope, decided together with the requirement and the graph. Either:<br>• an `If` row that bounds the fuzzy tier's work (the distinct query tokens it walks, or the postings it scans); or<br>• .40 scoped by what it bounds (distinct tokens per list, table postings), with the residual recorded and a backlog row, as E3S-09 and BL-I4-5 did.<br>Neither option was measured.<br>**(c) Case R-A2L-MATCH.40/5:** U6 (or U1) with the 76-token family query, plus a tracemalloc bound on one ranking. Negative control: the shipped tier, 7.4 s on U6 (1.96 s on U1) → RED. |
| E5S-08 | MEDIUM | design-gap | `build_label_index`, `label_match.py:169-206` (token map, sorted tuple and trie: B4c's peak is about 154 B per distinct token) · R-A2L-MATCH.37 (`01-requirements.md:145`), reworded scope "50,000 names that hold at most 2,062,041 characters" (E5S-02) | **.37's bound follows the distinct tokens, not the characters.** Lists inside the scope (`sec-r2-buildscope-transcript.txt`):<br>• B4c, 9 distinct camel 4-letter tokens per name (1,800,000 characters, 450,000 distinct tokens): peak **69,103,604 B = 65.9 MiB > 64 MiB**<br>• B4, 8 `_`-joined tokens (1,950,000 characters, 400,000 distinct): 61.2 MiB (4 % margin)<br>• U6 (2,050,000 characters, 300,000 distinct): 44.9 MiB<br>• REF (2,062,041 characters, 77,256 distinct): 20.3 MiB<br>.35 holds on all of them (1.97–2.43 s ≤ 5.0 s). | Scope .35 and .37 by distinct tokens as well (REF: 77,256). Or decide BL-I4-5 as an `If` row that refuses a list over a budget of total characters and distinct tokens. Either way, record the B4c residual in the Base column.<br>Optional: drop `token_map` before the trie is built, to cut the peak. |
| E5S-09 | LOW | design-gap | `_classify` FUZZY branch, `label_match.py:964` (each distinct query token × each name token) · `_cut` (`:480-507`) · .40 (limit 20) and Inc 7's E3S-04 obligations | **Step 6 costs limit × distinct query tokens × name tokens.** 40 names of 509 tokens with a 76-token query (`sec-r2-extra-transcript.txt`):<br>• limit 20: 311.2 ms (`_classify` 337 ms under cProfile)<br>• limit 40: 388.8 ms (`_classify` 672 ms under cProfile)<br>This is within .40 at limit 20, but it grows with the limit Inc 7 passes. | **(1)** Note in .40's scope that the bound is for limit 20.<br>**(2)** Add to Inc 7's consumer obligations that the autocomplete and the paste modal pass a limit ≤ 20, or budget the cut.<br>**(3)** With E5S-07 (a), look each token id up once per name token instead of once per (query token, name token) pair. |

### Checked and clear (round 2)

- **The lists did not change:** det under PYTHONHASHSEED 0, 1, 4242 and `random` gives sha256 `b528ae21…844c` over 1,287 rankings each. That is the round-1 value, measured on the code before the corrective (`sec-r2-r1-det-*-transcript.txt`).
- **Exceptions and spans:**
  - The hostile set (3,123 queries × 3 limits, 26,401 entries) gives 0 exceptions, 0 bad spans and 0 oracle mismatches. The I-3 `TypeError` texts are unchanged, and the private buffers are unchanged after the rankings (`sec-r2-r1-spans-transcript.txt`).
  - `_classify` now raises `ValueError` on a tier defect. It never raised in 1,400 randomized rankings over hostile, crafted, long-token and REF6 lists. In those rankings the shipped, map-only and per-id-forced paths also agreed, and matched the oracle (`sec-r2-fuzz-transcript.txt`).
- **Caps and paste:** every 64 KiB paste returns `[]` in ≤ 0.016 ms with a peak of ≤ 64.2 KiB. The 256 cap runs before any parse (`sec-r2-r1-paste-transcript.txt`, `sec-r2-r1-caps-transcript.txt`).
- **Fixtures** (`sec-r2-r1-perf-transcript.txt`, `sec-r2-r1-mem-transcript.txt`):

  | Fixture | Worst median | Bound |
  |---|---|---|
  | QSET over REF | 67.9 ms | 200 ms |
  | REF6 queries | 100.1 ms | 200 ms |
  | PSET over REF | 86.0 ms | 1.0 s |
  | PSET over REF6 | 308.4 ms | 1.0 s |
  | LONG | 59.8 ms | 1.0 s |

  One ranking on the fixtures peaks at ≤ 12.9 MiB.
- **Isolation:** the corrective adds only `typing` names (`Callable`, `Mapping`, `Sequence`), and the module does no file, clipboard or network I/O. The diff holds no secret, no home path and no operator name. `_token_range` lost its empty-prefix guard, but every caller passes a non-empty token.

### Evidence (round 2)

`evidence-e5/`, with sha256 prefixes:
- **Probe and scripts:** `sec-r2-probe.py` (`ecda78d6`), runner `sec-r2-run.sh` (`01a6306b`), chain `sec-r2-chain.sh` (`00ce5b7e`).
- **Transcripts of the new probe** (each `sec-r2-<mode>-transcript.txt`): dense (`e38dd34b`), craft (`085cd5a8`), band (`5f87a0f8`), switch (`944d1e43`), fixcheck (`ba7c0743`), extra (`7b656d22`), subkey (`33369dae`), buildscope (`01addf6e`), fuzz (`ec9e8bab`).
- **Transcripts of the round-1 probe** (each `sec-r2-r1-<mode>-transcript.txt`): caps (`5bd5da42`), perf (`146694ce`), paste (`6e8a826d`), mem (`009c5b8e`), spans (`54881201`), adv (`adb911ea`), det-{0,1,4242,random} (`f9aa0d14`, `4b75420b`, `ab6c4edc`, `0261e31d`).
- **Not run:** the Windows PC and CI (the brief's rule); CPython 3.12.

### Evidence checklist (round 2)

- [x] Each finding has a severity, `file:line`, the row, a fix and a tag: the table above.
- [x] No secret values appear here: none exist in the diff, and none were read.
- [x] The verdict is explicit: **FAIL**, with E5S-07 MAJOR open and its mitigation `planned` (part (a) measured, not applied). No HIGH is present.
- [x] New tool or integration: none. The module has no external action surface.

## Round 3 (2026-11-07T00:52:29-06:00)

Re-review of E5S-07 and E5S-08 as `E3-rulings.md` "E5 round-2 rulings" and "E5 round-2 design rulings" rule them: the N = 20 distinct-token cap (R-A2L-MATCH.41), range tables, C-level totals, the compact build, R-A2L-MATCH.40's bound at 2.0 s, .41's behavioural control and .37's ASCII scope. Code: `label_match.py` sha256 `8f396c15…a94d` (diff `7a771e59..HEAD -- s19_app tests`, HEAD `47bc083f`; GREEN `evidence-e5/green-after-corrective2.txt`). Reviewer: security-reviewer (Opus 5.5), read-only toward the code and the records.

**Probes (state `executed`).**
- **Where:** <runner>, Python 3.11.18, an 8 GiB address-space cap and a per-case alarm, against `/tmp/b103-e5r3-4-sec/tree` (a `cp -a` of the read-only `~/work/b103-int4`). HOME, XDG and LOCALAPPDATA pointed to `/tmp/b103-e5r3-4-sec/<user>`, with `PYTHONDONTWRITEBYTECODE=1`. All 20 transcripts print `s19_app.__file__` and the same module sha256.
- **New probe:** `sec-r3-probe.py` loads the round-1 probe (`sec-e5-probe.py`, `8700b63b`, unchanged) for the fixtures, the E1 oracle and the alarm. U6, D3, E2, W40, SUBO, CRAFT, BAND and B4MAX come from the test module's own builders. The oracle gets the .41 cap (past 20 distinct tokens a fuzzy row becomes the subsequence row or nothing). A node counter is an instrumented copy of the shipped `_fuzzy_token_distances` (its own source plus one counter line); every timing median uses the shipped function.
- **Probe versions:** walk, check and det3 (seed 0) ran on `eb161db9`; cap, build37 and det3 (seeds 1, 4242, random) on `174ceb23`; shapes, subs, budget, fixb and detnocap on the final `9cf29242`. Each edit only added a mode (fixb, detnocap).
- **Host load:** 1.2–10.3 on 16 cores. Another batch's probes shared the host, and the check chain ran beside the timing chain; every transcript prints the load. Timing medians are of 3 (adversarial lists) or 7 (the row's lists).

### Verdict

**FAIL.** One MAJOR is open: **E5S-10** (`design-gap`).

E5S-07's defect is gone. The postings factor is cut by the cap: a 76-token query takes 6.4–8.1 ms on U1, U6, M1 and D3 (U6 was 7.44 s and 1,470 MiB). 20 tokens take at most 384.3 ms in the quiet run (one E2 run at load 5.2: 726.7 ms), with peaks of at most 20.0 MiB. E5S-08 is closed inside .37's ASCII scope.

R-A2L-MATCH.40 still breaks inside its scope, now through the size of one walk. **The answer to "is there still a query of at most 256 characters, over a list in .40's scope, that exceeds 2.0 s?" is yes.**
- On W40, the test module's own list, `'a' * 40 + ' ' + 'a' * 39` (80 characters) takes 2,241 ms. Six such tokens (230–245 characters) take 5.6–6.6 s.
- On DEEP40, a list inside .35's and .37's scope too, one 40-letter token takes 2,295 ms and six take 12.05 s.
- On W12, exactly 20 distinct 11-letter tokens take 4.68 s.

The N = 20 cap bounds the number of walks, not what one walk visits. The design pass recorded the one-token W40 walk as "not solved by any N" (graph E5-2). The 2.0 s ruling rests on that one-walk figure (1.08–1.23 s).

Count (round 3): 0 CRITICAL, 0 HIGH, **1 MAJOR** (E5S-10), 1 MINOR (E5S-11), 1 LOW (E5S-12), 1 INFO (E5S-13). Every new mitigation is `planned`. E5S-10's fix was piloted and measured (mode fixb) but not applied. This verdict covers the Inc 4 E5 security gate and authorizes nothing beyond it.

### Round-2 findings

| Id | State | Why (evidence) |
|---|---|---|
| E5S-07 MAJOR | **closed** (as found) | **The cost of distinct tokens × postings is gone** (`sec-r3-shapes-transcript.txt`, `sec-r3-cap-transcript.txt`).<br>• **Past the cap:** U6 76 tokens 6.9 ms (round 2: 7.44 s), U1 76 tokens 6.4 ms, M1 7.7 ms, D3 8.1 ms, E2 36 tokens 7.4 ms, CRAFT 51 tokens 7.2 ms.<br>• **At the cap** (20 distinct tokens): U6 373.7–384.3 ms, D3 327.8–332.1 ms, E2 320.0–726.7 ms (the higher figure at load 5.2), U1 270.9 ms, M1 205.6 ms, CRAFT 100.7–108.7 ms.<br>• **Memory:** peaks at most 20.0 MiB (round 2: 1,470 MiB).<br>• **The boundary is exact and counts distinct tokens:** 21 distinct tokens take 6.7–15.4 ms on every list and list no fuzzy name; 20 distinct tokens plus 20 repeats still make 20 walks.<br>• **The mechanisms are in place:** the range tables (one postings slice per run) and the C-level totals.<br>• **The lists are right:** the instrumented and the shipped lists are equal, with 0 bad spans.<br>• **But** the row it protected still breaks: E5S-10. |
| E5S-08 MEDIUM | **closed** inside .37's ASCII scope | `sec-r3-build37-transcript.txt`:<br>• REF 17.8 MiB.<br>• B4MAX 58.6 MiB (the record says 56.7).<br>• **B4MIX**, built here with more distinct ASCII tokens than B4MAX in REF's 2,062,041 characters (513,699: every 2- to 4-letter camel token, every 2- to 4-digit token, then 5-digit ones): 59.5 MiB, 7.6 % under the bound.<br>• Builds take at most 3.45 s (.35).<br>• Outside the scope, a non-ASCII list is **accepted, not rejected**: see E5S-11. |
| E5S-09 LOW | not re-measured (outside this round's scope) | The design pass wrote the limit into .40's scope and moved `_classify`'s FUZZY lookup to a bisect over the runs (`label_match.py:1006-1031`). |
| E5S-02 MEDIUM | .37 part closed; .40 part continues as E5S-10 | Total characters still isn't what .40 bounds: within 2,356,624 characters the walk's trie nodes decide the cost. |
| E5S-06 INFO | unchanged | `build_label_index(None)` still raises the unpinned `TypeError`. |

### New findings

| Id | Severity | Tag | Where · row | Defect (measured) | Fix |
|---|---|---|---|---|---|
| E5S-10 | **MAJOR** | design-gap | `label_match.py:584-631` (step 4 walks each distinct token, `:620`), `:1194-1254` (`_fuzzy_token_distances`: the loop visits every trie node whose band minimum is at most `allowed` and below the best, with no bound on how many), `:568` (the cap counts walks) · graph step 4 (`graph-inc4.md:206`: "at most 20 tokens are walked"), `:195` and E5-2 (`:452`: the W40 walk "open, not solved by any N") · R-A2L-MATCH.40 (`01-requirements.md:152`; 2.0 s per `E3-rulings.md:48`) | **One walk costs the trie nodes within `allowed` edits of the query token's prefixes, and a list can make that number about as large as its characters.** At 1.33–1.84 µs per node on these walks, one walk can exceed 2.0 s by itself. A query of at most 256 characters can hold up to 6 such 40-letter tokens, or 20 such 11-letter tokens, under the cap.<br>• **Measured** (`sec-r3-walk-transcript.txt`, `sec-r3-cap-transcript.txt`; median of 3, limit 20; every list is 50,000 names inside .40's scope):<br>  – **W40** (`w40_names()`, 2,336,068 characters, 753,276 nodes): `'a' * 40` 1,098 ms; `'a' * 40`, `'a' * 39` (80 characters) **2,241 ms**; 3 tokens 3,111 ms; `'a' * 40` … `'a' * 35` (230 characters) **5,644 ms**; `'a' * 39` + `b` … `g` (245 characters) **6,580 ms** (×3.29)<br>  – **DEEP40** (the 41,250 40-letter tokens with 2 substitutions in their first 12 letters, 24 per name; 1,979,217 characters, also inside .35/.37's scope; 1,389,057 nodes): one token `'a' * 40` **2,295 ms**; 2 tokens 4,409 ms; 6 tokens **12,051 ms** (×6.03)<br>  – **DEEP258** (the 6,250 258-letter tokens with 2 substitutions in their first 5 letters, 3 per name; 1,904,162 characters; 1,647,244 nodes): `'a' * 128`, `'a' * 127` (256 characters) **2,902 ms**<br>  – **W12** (every 12-letter string within 2 substitutions of `'a' * 12`, 850,992 characters): T20, the 20 distinct tokens `'a' * 10` + `b` … `u` (239 characters), **4,676–4,722 ms** (×2.36); T16 3,754 ms; T8 1,939 ms; T21 8–10 ms (past the cap)<br>• **Where the time goes:** walks of 173,772 (W12) to 1,335,947 (DEEP40) nodes each, and 0 `_prefix_distance` calls (no switch). Only CPU breaks: the peaks are at most 3.6 MiB.<br>• **The lists are right:** 0 bad spans, and the instrumented and shipped lists are equal.<br>• **Reachable** as E5S-01 and E5S-07 were: a supplier A2L whose names share long near-identical tokens, plus a typed or pasted name. Inc 7 ranks off the UI thread (the 2.0 s ruling), but `rank` has no cancellation point. Each stale 5–12 s ranking therefore runs to its end, holding the GIL against the UI thread in pure-Python loops. | **(a) A node budget per ranking** (piloted: `sec-r3-fixb-transcript.txt`, `sec-r3-budget-transcript.txt`).<br>• **The rule:** count the trie nodes all of one ranking's walks visit. Past a budget B, the tier gives no fuzzy name, the same outcome as .41, and the subsequence tier still runs. It is deterministic, because the count depends only on the index and the query.<br>• **What it leaves alone:** the fixtures and the row's cases visit at most 68,901 nodes in one ranking (CRAFT, 20 tokens; REF 35,247; LONG 25,698; E2 24,080; REF6 43). With B = 200,000 or 400,000, none of their 132 lists changes, except W40's `'a' * 40` case (700,568 nodes). Its list changes there, and by derivation the subsequence tier then lists 20 names, as it already does for `'a' * 64`. At 800,000 it is unchanged.<br>• **What it bounds:** the adversarial rankings take 0.30–0.41 s at B = 200,000, **0.55–0.76 s at 400,000** and 1.11–1.46 s at 800,000.<br>• **Sizing:** a node costs more for a longer query token (1.84 µs at 128 letters), so size B on the dearest token of up to 256 letters, or count band cells instead of nodes.<br>**(b) Record it with the requirement and the graph:**<br>• an `If` row (next free id, e.g. R-A2L-MATCH.42): "If the fuzzy rule's trie walks for one query visit more than B nodes, then the system shall count no name as a `fuzzy` match", with B by measurement;<br>• graph step 4 and `_fuzzy_token_distances` take the running count;<br>• W40's one-token case expectation is updated if B < 700,568.<br>**(c) Cases and controls:**<br>• cases: W40 with 6 tokens, DEEP40 with `'a' * 40`, W12 with T20;<br>• a behavioural negative control, as .41's ruling prefers: a query past the budget lists no fuzzy name, and with the budget removed it lists them → RED;<br>• a timing control beside it: W12 T20 4.7 s → RED. |
| E5S-11 | MINOR | design-gap | `build_label_index`, `label_match.py:156-170` (no check on the characters of a name) · R-A2L-MATCH.37 (`01-requirements.md:150`, "ASCII names") · BL-I4-5 (`E1-rulings.md:126`) | **.37's ASCII scope is a precondition nothing enforces.** A non-ASCII list is accepted, built and ranked, with no error, and its memory has no bound (`sec-r3-build37-transcript.txt`):<br>• LAT1 (Latin-1, 400,000 distinct tokens, 1,950,000 characters): 61.3 MiB<br>• CJK2 (600,000 distinct, 1,750,000 characters): 122.7 MiB<br>• **AST1**, the case the record left unmeasured (1-character tokens above U+FFFF, 1,000,000 distinct, 1,950,000 characters): **208.0 MiB**, 112 B per character, 3.25 × 64 MiB<br>Every build stays below 5.0 s and ranks fine. The census finds no non-ASCII name in the fixtures or the corpus, so this is the adversarial-file residual. | Record AST1 (208.0 MiB) in .37's Base column and in BL-I4-5. Then make the precondition hold, either:<br>• a consumer obligation for Inc 7 / Inc 11 to drop or refuse non-ASCII names before `build_label_index`; or<br>• an `If` row in this module that leaves them out, as .39 does for long names. |
| E5S-12 | LOW | design-gap | `01-requirements.md:152` (.40: "within 1.0 s"), `:153` (.41's negative control still names the timing half, "1,219.7 ms > 1.0 s → RED") · `02-test-cases.md:143`, `:144`, `:146`, `:147` (.40/1, /2, /4, /5: "≤ 1.0 s") · against `tests/test_b103_label_match_perf.py:51` and .40/3 (`02-test-cases.md:145`: 2.0 s) | **The records lag the 2.0 s ruling.** The tests assert 2.0 s, while the row and four of its five cases still state 1.0 s. At 2.0 s, .41's timing control (1,219.7 ms) no longer turns RED, which is why the ruling made it behavioural. | Write 2.0 s in .40 and in cases /1, /2, /4 and /5. Drop the timing half of .41's negative control, keeping the behavioural one, or restate it against 2.0 s with a list that still fails. |
| E5S-13 | INFO | design-gap | `_text_tiers`, `label_match.py:366-376` (the substring key checks every occurrence until one sits at a boundary offset) · R-A2L-MATCH.40 (lists SUBO only) | **The substring key holds .40, but with the thinnest margin found** (`sec-r3-subs-transcript.txt`; 50,000 names of 47 characters, each holding the query 40 times, never at a boundary):<br>• SUBN (`é`, non-ASCII; .40 has no ASCII scope): **1,513 ms** (1.32× under 2.0 s)<br>• SUBU (upper case): 1,375 ms<br>• SUBL: 1,013 ms<br>• SUBO: 992 ms<br>Each checked occurrence costs 0.5–0.76 µs. | Optionally, apply the graph E5-2 suggestion: test only the name's boundary offsets, which number at most its tokens, instead of the occurrences. Otherwise add SUBN beside SUBO in .40's Base column. |

### Checked and clear (round 3)

- **Caps and paste** (`sec-r3-r1-paste-transcript.txt`): every 64 KiB paste returns `[]` in at most 0.018 ms, with a peak of at most 64.2 KiB. A 257-character query returns `[]` in 0.008 ms.
- **Exceptions, spans and the oracle** (`sec-r3-check-transcript.txt`):
  - **Hostile set:** 3,123 queries × 3 limits, 26,401 entries: 0 exceptions, 0 bad spans, 0 mismatches against the .41-capped oracle. The I-3 `TypeError` texts are unchanged, and the private buffers and the argument list are unchanged after the rankings.
  - **Randomized:** 1,600 rankings, 202 of them past 20 distinct tokens: 0 exceptions, 0 bad spans, 0 mismatches against the capped oracle. The shipped path, the map-only path and the per-id path forced right after the first walk give the same lists.
- **.41's behavioural control works** (C08, same transcript):
  - /1 (20 distinct tokens): 3 × `fuzzy` e20.
  - /2 (21 distinct): `[]`.
  - /3 (21 tokens, 20 distinct): 3 × `fuzzy` e21.
  - With `_FUZZY_TOKEN_CAP` removed, /2 lists 3 × `fuzzy` e21, so the control turns RED.
- **Determinism:**
  - Under PYTHONHASHSEED 0, 1, 4242 and `random`, the round-1 det set gives sha256 `132f1e9e…712e` over 1,287 rankings, and det3 (W12, CRAFT, U6, W40, DEEP258) gives `a9f935c6…38b4` over 63 rankings. Each is identical across the seeds.
  - With the cap removed, the round-1 det set gives `b528ae21…844c`, the value of rounds 1 and 2. So the .41 cap is the only change to any list of that set since round 1 (`sec-r3-detnocap-transcript.txt`).
- **Fixtures** (`sec-r3-r1-perf-transcript.txt`; the bounds printed there are the round-1 labels):

  | Fixture | Worst median | Bound |
  |---|---|---|
  | QSET over REF | 72.2 ms | 200 ms |
  | REF6 queries | 102.1 ms | 200 ms |
  | PSET over REF | 8.5 ms | 2.0 s |
  | PSET over REF6 | 77.6 ms | 2.0 s |
  | LONG | 62.5 ms | 2.0 s |
  | BAND | 116.4 ms (226 `_prefix_distance` calls) | 2.0 s |

  One ranking on the fixtures peaks at at most 11.5 MiB (`sec-r3-r1-mem-transcript.txt`).
- **Outside every row's scope**, for the record: 1,000,000 short names, `'sig'` takes 1.86 s (the BL-I4-5 residual; `sec-r3-check-transcript.txt`).
- **Isolation:** the corrective adds `collections.Counter` only. The module docstring (`label_match.py:13-14`) still lists five standard-library modules: a docstring nit, `impl`. The module does no file, clipboard or network I/O. The diff holds no secret, no home path and no operator name.

### Evidence (round 3)

`evidence-e5/`, with sha256 prefixes:
- **Probe and scripts:** `sec-r3-probe.py` (`9cf29242`), runner `sec-r3-run.sh` (`8f70dd91`), chain `sec-r3-chain.sh` (`3fe5f2b7`).
- **Transcripts of the new probe** (each `sec-r3-<mode>-transcript.txt`):
  - walk (`8c466221`), cap (`eab3d240`), shapes (`2bb6ed07`), subs (`c0b82df0`)
  - budget (`74040040`), fixb (`e2945a08`), build37 (`f5263516`)
  - check (`9d880d8d`), detnocap (`78183f0c`)
  - det3-{0,1,4242,random} (`3bac72fd`, `fdbeda10`, `79ce7cd7`, `0c2e4e2e`)
- **Transcripts of the round-1 probe** (each `sec-r3-r1-<mode>-transcript.txt`):
  - perf (`32a0f488`), paste (`79bc2423`), mem (`eda189c6`)
  - det-{0,1,4242,random} (`e57941f7`, `8bf8b135`, `7d03fd4e`, `b6bfeebc`)
- **Not run:** the Windows PC and CI (the brief's rule); CPython 3.12. The scratch `/tmp/b103-e5r3-4-sec` is kept on <runner> until this evidence is committed.

### Evidence checklist (round 3)

- [x] Each finding has a severity, `file:line`, the row, a fix and a tag: the table above.
- [x] No secret values appear here: none exist in the diff, and none were read.
- [x] The verdict is explicit: **FAIL**, with E5S-10 MAJOR open and its mitigation `planned` (piloted and measured in fixb, not applied). No HIGH is present.
- [x] New tool or integration: none. The module has no external action surface.

## Round 4 (2026-11-07T02:37:56-06:00)

Re-review of E5S-10, E5S-11 and E5S-12 as `E3-rulings.md` "E5 round-3 rulings" rules them (with its design-pass-3 line): the per-ranking budget of 400,000 trie-node visits (R-A2L-MATCH.42), non-ASCII names left out of the prepared list (R-A2L-MATCH.43), and the 2.0 s texts. Code: `label_match.py` sha256 `b97d19eb…9ecc` (corrective 3, by Sonnet; diff `1c5314ec..HEAD -- s19_app tests`, HEAD `08a703cf`). GREEN: `evidence-e5/green-after-corrective3.txt` (behaviour 145, perf 20, law guards 219). Reviewer: security-reviewer (Opus 5.5), read-only toward the code and the records.

**Probes (state `executed`).**
- **Where:** <runner>, Python 3.11.18, an 8 GiB address-space cap and a per-case alarm, against `/tmp/b103-e5r4-4-sec/tree`.
  - **The tree** is a copy of the read-only `~/work/b103-int4` without `.dev-flow/`, `docs/` and `.git`. The runner's `/tmp` had 0.7 GiB free, and the probe reads none of the three.
  - **Isolation:** HOME, XDG and LOCALAPPDATA pointed to `/tmp/b103-e5r4-4-sec/<user>`, with `PYTHONDONTWRITEBYTECODE=1`.
  - **Every transcript** prints `s19_app.__file__` and the module sha256.
- **New probe:** `sec-r4-probe.py` loads the round-3 probe (`9cf29242`, unchanged), which loads the round-1 probe (`8700b63b`, unchanged).
  - **No instrumented copy is needed:** the shipped walk now returns its own visit count.
  - **Pass-through wrappers** log each walk (token, budget passed, visits, runs) and each tier's time, on one extra ranking.
  - **Timing medians** use the unwrapped module.
- **Probe versions:**
  - `3cbaf0fb` ran shapes4, dear, cheap, boundary, nonascii, check4 and det4.
  - `21c82297` is that version plus the modes detx and rerun; no earlier mode changed.
  - **Two earlier detx runs were discarded:** one failed to load the round-3 module; the other retyped P.det's queries and lost their Unicode form. detx now calls P.det itself.
- **Host load:**
  - **1.8–4.0** for shapes4, dear, cheap (until COMBO's last query) and the check modes.
  - **14–17 from 02:15 on**, while another batch's mutant and worker-pool runs shared the host. Boundary, r1 perf, paste and mem, and rerun ran under it.
  - **Every transcript** prints the load.

### Verdict

**PASS-WITH-NOTES.** E5S-10 (MAJOR), E5S-11 and E5S-12 are closed. No new HIGH or MAJOR. Notes: E5S-13 INFO (updated), E5S-14 INFO, E5S-15 LOW.

**The closing question — is one `rank` call now bounded by a constant over every input in scope? Yes.**
- **The walks.** All of one ranking's walks share 400,000 visits, and the boundary is exact. One visit costs at most 1.96 µs measured, at m = 256 (the longest query token the 256-character cap allows). So the walks stay under about 0.8 s: 785 ms measured, DEEP40 `'a' * 256`.
- **Every other tier is bounded by the list, not by the query's shape.** The list's terms: N = 50,000 names, C ≤ 2,356,624 characters, postings P ≤ C. The caps: 256 characters, 20 distinct tokens, the 512 switch, limit 20.
  - text: one C-level `in` per name, plus a Python scan of the non-boundary occurrences in the names that contain the query (≤ C);
  - token: C-level postings slices; nested prefixes keep their sum ≤ C;
  - fuzzy postings: ≤ 20 × P, C-level;
  - the switch: ≤ 20 × 512 banded `_prefix_distance` calls;
  - subsequence: ≤ N + C `find` calls;
  - cut: ≤ N log N, plus limit × `_classify`.
- **An expensive substring tier never adds to a walk.** It lists every name it scans, so it reaches the limit and every later tier is skipped.
- **Measured worst on a quiet host** (load 2.8–4.0; `sec-r4-cheap`, `sec-r4-dear`):

  | Shape | Median | Where the time goes |
  |---|---|---|
  | SUBMAX `'a'` | 1,439.4 ms (1.39× under 2.0 s) | the substring tier; no walk |
  | COMBO | 1,233–1,258 ms | the budget + 19 walks of about 600,000 postings each |
  | INWD | 952.2 ms | the budget at m = 256 + the worst `in` |
  | DEEP40 `'a' * 256` | 857.8 ms | the budget at m = 256 |

- **The constant is the measured maximum, not a proof.** It is the worst of the shapes tried here. Each tier's own maximum needs its own share of the 2,356,624 characters, and the two shapes that combine tiers (COMBO, INWD) stay at or under 1.26 s.
- **Under host load 14–17 the same shapes take about twice as long:** E5S-14.

Count (round 4): 0 CRITICAL, 0 HIGH, 0 MAJOR, 0 MEDIUM, 0 MINOR, 1 LOW (E5S-15), 2 INFO (E5S-13 updated, E5S-14). E5S-10's and E5S-11's mitigations are `executed` and verified here. This verdict covers the Inc 4 E5 security gate and authorizes nothing beyond it.

### Round-3 findings

| Id | State | Why (evidence) |
|---|---|---|
| E5S-10 MAJOR | **closed** | **Every round-3 attack is bounded now, and removing the budget brings back the round-3 cost** (`sec-r4-shapes4`, `sec-r4-dear`, `sec-r4-boundary`).<br>• **The round-3 shapes,** medians of 7, load 1.8–3.6 (round 3 in brackets):<br>  – W40: 2 tokens 683.1 ms (2,241 ms); 6 tokens 706.7 ms (5.6–6.6 s); `'a' * 39` + b … g 631.5 ms (6,580 ms)<br>  – DEEP40: 1 token 672.6 ms (2,295 ms); 6 tokens 731.2 ms (12,051 ms)<br>  – DEEP258, `'a' * 128` + `'a' * 127`: 786.6 ms (2,902 ms)<br>  – W12 T20: 542.7 ms (4,676–4,722 ms)<br>  – the 76-token FAMQ query: U6 7.3 ms, D3 6.8 ms, U1 5.7 ms; FAMQ(20): U6 418.2 ms, D3 318.4 ms<br>• **Each spends exactly 400,000 visits.** Later walks receive what is left (W12 T20: 400,000 → 226,228 → 52,456 → 0) and the fuzzy rule lists what was found.<br>• **One visit costs 1.40–1.96 µs.** The cost grows with the query token's length: the walks take 607 ms at m = 40 and 785 ms at m = 256. On these shapes one ranking peaks at at most 1.54 MiB.<br>• **Budget removed** (`_FUZZY_NODE_BUDGET = 10**9`): W40 6 tokens 5,633 ms (3,494,116 visits), DEEP40 6 tokens 12,592 ms, W12 T20 4,770 ms, each listing `fuzzy` entries again. So the control turns RED as ruled.<br>• **The boundary is exact** (12,333 DEEP tokens; 27, 28 or 29 one-visit fillers; a sentinel token last in pre-order, `zz` + `'a' * 38`):<br>  – walks of 399,999 and 400,000 visits complete: the sentinel is listed first and the list equals the no-budget list;<br>  – a walk of 400,001 visits stops one visit short: the sentinel is missing, and the list differs;<br>  – on all three lists, the 2-token query `'a' * 40` + `'a' * 39` lists no fuzzy name: its second walk gets at most 1 visit.<br>• **Deterministic** (`sec-r4-det4-*`):<br>  – det4 (W40, DEEP40, W12, DEEP258, INWD and COMBO; 42 rankings, 13 of its 14 queries at the budget) gives `f6a86408…f2fb` under PYTHONHASHSEED 0, 1, 4242 and `random`;<br>  – 0 repeated calls differ;<br>  – .42/1–/4 equal the sha256 values the tests pin, and .42/5 is `[]`, under every seed. |
| E5S-11 MINOR | **closed** | **No non-ASCII name reaches the prepared list** (`sec-r4-nonascii`).<br>• **One such character, at the start, the middle or the end of a name, leaves the name out:** U+0080, U+00E9, U+00FF, U+0100, U+0130, U+2028, U+FEFF, U+FFFF, U+10000, U+10FFFF, a lone U+D800 and U+212A. A name with U+007F is kept.<br>• **All-non-ASCII lists:** AST1 and LAT1 (50,000 names, 1,950,000 characters each) prepare 0 names in 0.00 s, with a peak of 2,000 B (round 3: AST1 208.0 MiB).<br>• **Mixed lists keep exactly the ASCII names, in first-occurrence order:**<br>  – ONE (each name with one trailing `é`): 0 names<br>  – HALF: 25,000<br>  – REF with every 7th name made non-ASCII: 42,857 (16.5 MiB)<br>  – duplicates around non-ASCII twins: 3<br>  – a `str` subclass, an iterator and a generator behave the same<br>• **Ranking** these indexes with ASCII, non-ASCII and astral queries gives 0 exceptions, 0 bad spans and no non-ASCII name.<br>• **R-A2L-MATCH.43 is the only change of any list since round 3** (`sec-r4-detx-0`, `sec-r4-r1-det-r3tree`; P.det's own queries):<br>  – the round-3 module (`8f396c15`) still gives round 3's `132f1e9e…712e` on the hostile list as it is;<br>  – on its ASCII names only, it gives `e658b979…2d53`, the value of this code. |
| E5S-12 LOW | **closed** | **The records match the 2.0 s ruling.**<br>• R-A2L-MATCH.40 reads "within 2.0 s" (`01-requirements.md:166`), and cases .40/1–/5 read "≤ 2.0 s" (`02-test-cases.md:147-151`).<br>• .41 dropped its timing control (`01-requirements.md:167`).<br>• The "1.0 s" strings left are history notes, such as "RED against the 1.0 s of A-2". |
| E5S-13 INFO | continues, updated below | |

### New findings

| Id | Severity | Tag | Where · row | Defect (measured) | Fix |
|---|---|---|---|---|---|
| E5S-13 (updated) | INFO | design-gap | `_text_tiers`, `label_match.py:374-384` (the occurrence loop) · R-A2L-MATCH.40 (its cases name SUBO only) | **The substring tier is now the dearest path in .40's scope, and the budget does not reach it** (`sec-r4-cheap`).<br>• **Its cost** is the non-boundary occurrences in the names that contain the query: at most the list's characters.<br>• **SUBMAX** (50,000 names: a 4-letter upper-case tag + `'A' * 43`; 2,350,000 characters; 2,150,000 non-boundary occurrences of `a`): **1,439.4 ms**, median of 7 at load 2.8 (text 1,380 ms, cut 58 ms). That is 1.39× under 2.0 s, a 28 % margin.<br>• **The other substring lists:** SUBU 1,347.4 ms, SUBD (digits) 1,175.5 ms, SUBO (the row's case) 964.1 ms.<br>• **Not measured:** a 3-letter tag would add about 5 % more occurrences (an estimate).<br>• **What contains it:** the tier lists every name it scans, so it never runs beside a walk. | Optional, as in round 3: test only a name's boundary offsets (at most its tokens) instead of every occurrence. Otherwise add SUBMAX to .40's cases; its 28 % margin is above QC-TM's 20 %. |
| E5S-14 | INFO | design-gap | `rank` (no cancellation point) · R-A2L-MATCH.40 (`serial_timing`) · Inc 7 PLAN row 7 (ranking off the UI thread, stale results dropped) | **The 2.0 s bound holds on a quiet host only** (`sec-r4-rerun`, `sec-r4-boundary`, `sec-r4-r1-perf`). At load 14–17 on 16 cores:<br>• SUBMAX 2,948 ms, SUBU 2,439 ms, COMBO 2,895–2,934 ms: over 2.0 s.<br>• INWD 1,685 ms, DEEP40 `'a' * 256` 1,404 ms.<br>• One 400,000-visit walk: 1.34–1.40 s.<br>• r1 perf: REF6 `0` 226 ms, over .36's 200 ms.<br>At load 1.8–4.0 the same shapes take 0.71–1.44 s, so the code is not the cause. The ranking is bounded either way: a stale ranking now ends in about 1.5 s (quiet) to 3 s (loaded), where round 3 found 5–12 s. | For Inc 7's E1: keep the ruled off-thread ranking that drops stale results. Optionally have `rank` check a cancellation flag between tiers, so a superseded ranking stops early. No change in Inc 4. |
| E5S-15 | LOW | impl | `label_match.py:13-14` (the module docstring lists five standard-library modules; `collections.Counter` is imported at `:23`) · `rank`'s Data Flow at `:274-277` (it names .41's cap, not .42's node budget) | **The docstrings lag the code.** | Add `collections` to the module docstring. Add the node budget to `rank`'s Data Flow: "the fuzzy walks of one ranking share 400,000 trie-node visits, R-A2L-MATCH.42". |

### Checked and clear (round 4)

- **The cheap tiers, and shapes that combine them with the walk** (`sec-r4-cheap`; medians of 5–7; load 2.8–4.0, rising to 13.8 during COMBO's last query):
  - **INW** (2,114 names of 1,024 characters): INWQ (`'a' * 253 + 'b' + 'aa'`) makes `str.__contains__` compare 254 characters per window. 214.3 ms, of which the text tier takes 124 ms.
  - **INWD** (600 DEEP names + 1,538 INW names): INWQ spends the budget at m = 256, 952.2 ms; `'a' * 256` takes 907.3 ms in the substring tier.
  - **COMBO** (600 DEEP names + 49,400 names of camel `Ab` + X tokens; 602,800 postings): 19 three-letter query tokens each read every posting, then the 20th spends the budget.
    - 19 camel tokens + `'a' * 198`: 1,233.0 ms
    - the same tokens spaced, + `'a' * 180`: 1,258.1 ms
    - 10 tokens + `'a' * 225`: 1,085.9 ms
    - 19 tokens + `'a' * 40`: 1,215.1 ms, listing 20 `fuzzy` entries
  - **Peaks:** one ranking peaks at at most 26.1 MiB (COMBO). U6 FAMQ(20) peaks at 19.0 MiB.
- **Exceptions, spans and the oracle** (`sec-r4-check4`; the round-3 check, with its oracle given only the ASCII names):
  - **Hostile set:** 3,123 queries × 3 limits, 15,309 entries: 0 exceptions, 0 bad spans, 0 mismatches.
  - **Randomized:** 1,600 rankings, 202 of them past 20 distinct tokens: 0 exceptions, 0 bad spans, 0 mismatches, and the forced switch paths agree.
  - **.41's control:** with the cap removed, /2 lists 3 × `fuzzy` e21.
  - **The oracle has no budget, so the walk log checks it still applies:** no walk in these sets spent the budget. The most visits in one walk were 9,937, and at least 380,600 were left after any walk.
  - **Unchanged since round 3:** the I-3 `TypeError` texts, and the index buffers and the argument list after the rankings.
- **Paste** (`sec-r4-r1-paste`, at load 17): every 64 KiB paste that is over 256 characters after the strip returns `[]`, in at most 0.024 ms with a peak of at most 64.2 KiB. A 257-character query returns `[]` too.
- **Fixtures:**
  - **Memory** (`sec-r4-r1-mem`): the REF build peaks at 17.8 MiB; one ranking peaks at at most 11.5 MiB (REF6).
  - **Timing** (`sec-r4-r1-perf`, at load 17): every case is under 2.0 s. REF6 `0` takes 226 ms, over .36's 200 ms under that load (round 3, at a quiet time: 102.1 ms; the GREEN run passes).
  - **Determinism** (`sec-r4-r1-det-*`): the round-1 det set gives `e658b979…` under all four seeds.
- **Outside every row's scope**, for the record:
  - 1,000,000 short names: `'sig'` takes 1.85 s (BL-I4-5).
  - Limits above 20 (E5S-09).
- **Isolation:** the corrective adds no import and no I/O. Neither the diff nor the transcripts hold a secret, a home path or the operator's name.

### Evidence (round 4)

`evidence-e5/`, with sha256 prefixes:
- **Probe and scripts:** `sec-r4-probe.py` (`21c82297`), runner `sec-r4-run.sh` (`7225a0c0`), chain `sec-r4-chain.sh` (`40487054`).
- **Transcripts of the new probe** (each `sec-r4-<mode>-transcript.txt`):
  - shapes4 (`a132db6e`), dear (`0bf81eab`), cheap (`d9b3d6f1`)
  - boundary (`d81e8c9e`), rerun (`8d0f8d61`)
  - nonascii (`479d0b3b`), check4 (`e5b29e27`), detx-0 (`ec161e3c`)
  - det4-{0,1,4242,random} (`4d249391`, `259f40de`, `f39ad892`, `65625688`)
- **Transcripts of the round-1 probe** (each `sec-r4-r1-<mode>-transcript.txt`):
  - perf (`390d2450`), paste (`a02e7191`), mem (`9c0f7917`)
  - det-{0,1,4242,random} (`69af35eb`, `526b3e24`, `19a28a0a`, `f027e835`)
  - det-r3tree (`c78d90c0`), run on the round-3 tree copy, read-only
- **Not run:** the Windows PC and CI (the brief's rule); CPython 3.12. The scratch `/tmp/b103-e5r4-4-sec` is kept on <runner> until this evidence is committed.

### Evidence checklist (round 4)

- [x] Each finding has a severity, `file:line`, the row, a fix and a tag: the table above.
- [x] No secret values appear here: none exist in the diff, and none were read.
- [x] The verdict is explicit: **PASS-WITH-NOTES**, with no HIGH or MAJOR open. E5S-10's mitigation is applied (`executed`) and verified here, with its control and its exact boundary.
- [x] New tool or integration: none. The module has no external action surface.
