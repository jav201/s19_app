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
