# Inc 4 — E5 security review: label similarity matcher

Batch 2026-11-05-batch-103, increment 4, stage E5. Reviewer: security-reviewer (Opus 5.5). The change under review is `git diff a2043cfd HEAD -- s19_app tests` on branch `b103-inc4-code` (HEAD `885634bf`): `s19_app/tui/services/label_match.py` (new, 1,050 lines, sha256 `24564b32…edb9b`), `tests/test_b103_label_match.py`, `tests/test_b103_label_match_perf.py`, and `tests/test_id_registry.py` (a count, 267 → 269). The yardstick is `E3-security.md` (rounds 1–2), `E3-rulings.md` (with addenda A-1…A-4), `01-requirements.md`, `codewire/graph-inc4.md` and `E1-rulings.md` §7. This review is read-only toward the code and the records: this file, `evidence-e5/sec-e5-*` and two lines in `steps.log` are the only writes.

**Probes (state `executed`).** All runs used cachyos-rtx, Python 3.11.18, under an 8 GiB address-space cap with a per-case alarm. They imported the real module from `/tmp/b103-e5-4-sec/tree`, a `cp -a` of the read-only `~/work/b103-int4`; every transcript prints `s19_app.__file__` and the module's sha256, and all 13 show the same pair. HOME, XDG and LOCALAPPDATA pointed to `/tmp/b103-e5-4-sec/zq_iso_user`, with `PYTHONDONTWRITEBYTECODE=1`. No clipboard was touched.
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
- **Where:** cachyos-rtx, Python 3.11.18, an 8 GiB address-space cap and a per-case alarm, against `/tmp/b103-e5-4-sec-r2/tree` (a `cp -a` of the read-only `~/work/b103-int4`). HOME, XDG and LOCALAPPDATA pointed to `/tmp/b103-e5-4-sec-r2/zq_iso_user`, with `PYTHONDONTWRITEBYTECODE=1`. Every transcript prints `s19_app.__file__` and the module's sha256, and all 19 show the same pair.
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
