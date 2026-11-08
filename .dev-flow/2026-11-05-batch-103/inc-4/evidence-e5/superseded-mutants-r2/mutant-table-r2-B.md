# E5 mutant table — unit B round 2 (rows R-A2L-MATCH.21 … .40, corrected code)

Run on <runner> (Python 3.11.18), base `~/work/b103-int4` copied read-only to
`/tmp/b103-e5-4-mutr2B/base` (label_match.py sha256 `394bf2f9`). Per mutant: smallest
edit to `s19_app/tui/services/label_match.py`, then the row's tests. Evidence (unified
diff + pytest tail) in `mutants-r2-B/M-*.txt`. Result: **27 killed, 1 survived,
1 not realisable**.

| Mutant | Row | Control (as written) | Edit made | Tests run | Result | Failing test id(s) |
|---|---|---|---|---|---|---|
| M-21 | .21 | key left out (length first) → `Encounter` first | `_text_tiers`: substring `add_group` key forced to 1 (boundary detection removed) | `-k "R-A2L-MATCH.21"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.21/1]` |
| M-22 | .22 | edits left out (length first) → `CUVE` first | `rank`: fuzzy `add_group` key forced to 0 (edits ignored) | `-k "R-A2L-MATCH.22"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.22/1]` |
| M-23 | .23 | length left out → `ASCII_0001` before `MAP_0001` | `_order_key`: `len(name)` → `0` | `-k "R-A2L-MATCH.23 or rows_23_1"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.23/2]`, `test_rows_23_1_shorter_name_first` |
| M-23b | .23 | case-exactness before length → `rpm_x` first | `_order_key` swaps case-exact before length; group key `[:2]`, tie sort `[2:]` | `-k "R-A2L-MATCH.23 or rows_23_1"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.23/2]` |
| M-24 | .24 | case-exactness left out → `rpm` gives `RPM`, `Rpm`, `rpm` | `_cut`: `case_exact = False` for every rule | `-k "R-A2L-MATCH.24 or rows_24_1 or rows_24_3"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.24/4]`, `test_rows_24_1_case_exact_name_first_for_lowercase_query` |
| M-24b | .24 | `substring` case-exact only for a raw occurrence at a boundary offset → `DiscouNTCount` first | `_cut`: substring case-exact requires a boundary occurrence of raw | `-k "R-A2L-MATCH.24 or rows_24_1 or rows_24_3"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.24/4]` |
| M-25 | .25 | input order kept (stable sort, no name key) → reversed list gives `VALUE_0001` first | `_order_key`: `name` dropped (4-tuple) | `-k "R-A2L-MATCH.25 or rows_25_1 or rows_25_2"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.25/3]`, `test_rows_25_1_code_point_order_among_equals` |
| M-26 | .26 | no span → `[]` | `_classify`: exact span `()` | `-k "rows_26"` | killed | `test_rows_26_exact_span` |
| M-27 | .27 | span over the whole name → `[(0,10)]` | `_classify`: prefix span `(0, len(name))` | `-k "rows_27"` | killed | `test_rows_27_prefix_span_counts_the_query_text_not_whitespace` |
| M-28 | .28 | leftmost occurrence regardless of boundaries → `[(3,8)]` | `_classify`: substring span always leftmost (no boundary scan) | `-k "R-A2L-MATCH.28 or rows_28"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.28/1]` |
| M-29 | .29 | no span when no boundary occurrence → `[]` | `_classify`: substring with no boundary occurrence → `()` | `-k "rows_29"` | killed | `test_rows_29_span_with_no_boundary_occurrence` |
| M-30 | .30 | span over the whole name token → `00` gives `(8,12)` | `_classify`: token span `(start, end)` | `-k "rows_30"` | killed | `test_rows_30_token_spans` |
| M-31 | .31 | each key character at its rightmost possible offset | `_subsequence`: `text.rfind(ch)` per key char | `-k "rows_31"` | killed | `test_rows_31_subsequence_spans` |
| M-32 | .32 | span as long as the query token → `maesu` gives `[(0,5)]` | `_classify`: fuzzy span `(start, start+len(query_token))` | `-k "R-A2L-MATCH.32 or rows_32"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.32/1]`, `[R-A2L-MATCH.32/3]`, `test_rows_32_2_fuzzy_spans_of_two_query_tokens` |
| M-33 | .33 | total edits always 0 | `_cut`: `edits = 0` | `-k "R-A2L-MATCH.33 or rows_33"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.33/2]`, `[R-A2L-MATCH.33/3]`, `test_rows_33_1_total_edits_one` |
| M-33b | .33 | the largest edit instead of the sum → `cuvre maq` gives 1 | `_fuzzy_tier`: totals accumulate `max` instead of `+` | `-k "R-A2L-MATCH.33 or rows_33"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.33/3]` |
| M-34 | .34 | spans in query-token order → `blk val 00` gives `[(4,7),(0,3),(8,10)]` | `_join_spans`: `sorted(spans)` → `list(spans)` | `-k "R-A2L-MATCH.34 or rows_34"` | killed | `test_rows_34_spans_in_offset_order_and_joined` |
| M-34b | .34 | touching spans not joined → `[(0,3),(3,8)]` | `_join_spans`: `start <= prev_end` → `start < prev_end` | `-k "R-A2L-MATCH.34 or rows_34"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.34/1]`, `test_rows_34_spans_in_offset_order_and_joined` |
| M-35 | .35 | a preparation that computes the fuzzy distances of every name token pair (quadratic) | `build_label_index`: quadratic `_prefix_distance` over the first 6,000 distinct tokens (the full 77,256 would be ~160× longer) | `-k "a2l_match_35"` (perf) | killed | `test_r_a2l_match_35_1_preparing_50000_names` |
| M-36a | .36 | no preparation (every ranking re-reads the 50,000 names) | `rank`: `index = build_label_index(index.names)` per call | `-k "a2l_match_36"` (perf) | killed | `test_r_a2l_match_36_1_ranking_per_keystroke_over_ref`, `…_over_ref6` |
| M-36b | .36 | a fuzzy step that scans every distinct token per query token | `_fuzzy_token_distances`: linear scan over `index._tokens` (banded `_prefix_distance`) | `-k "a2l_match_36"` (perf) | killed | `test_r_a2l_match_36_1_ranking_per_keystroke_over_ref` |
| M-36c | .36 | case-exactness by a raw re-classification of every member of the group at the cut → `mesa` ≈ 700 ms | not realisable: the current `rank`/`_cut` has no group-wide re-classification pass at the cut to remove — case-exactness is decided inline, per rule, for exact/prefix/substring only (`label_match.py:486-492`, the E3A-01 fix) | — | not realisable | — |
| M-36d | .36 | a map for every query token before the candidate check (the E2 tier) → 296.8 ms | `_fuzzy_tier`: the posting switch removed (`if False`) — walk every distinct query token (C5 variant A) | `-k "a2l_match_36"` (perf) | killed | `test_r_a2l_match_36_1_ranking_per_keystroke_over_ref` |
| M-37 | .37 | nested-dict trie of the tokens + per-name tuple of token strings → 75.7 MiB | `build_label_index`: add a nested-dict trie and a per-name tuple of token strings | `-k "a2l_match_37"` (perf) | killed | `test_r_a2l_match_37_1_prepared_list_stays_within_64_mib` |
| M-38 | .38 | cap removed → the 257-character query lists `VALUE_0001` | `rank`: remove `len(raw) > 256` guard | `-k "R-A2L-MATCH.38"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.38/2]` |
| M-39 | .39 | cap removed → the 1,025-character name is listed | `build_label_index`: remove `len(name) > 1024` guard | `-k "R-A2L-MATCH.39"` | killed | `test_ranked_list_is_exactly[R-A2L-MATCH.39/2]` |
| M-40a | .40 | a range or map per query token occurrence (no collapse of duplicate query tokens) → REF6 `'0 ' * 125 + 'chax'` 1,136.9 ms | `_fuzzy_tier`: `distinct = list(query.tokens)`, `count = 1` | `-k "a2l_match_40"` (perf) | survived | — |
| M-40b | .40 | the per-candidate check restored (step 4 switching at 300 candidates, then each remaining query token against every token of each candidate, the E3 design) → CRAFT 51-token query 16.0–16.7 s | `_fuzzy_tier`: switch condition → `len(candidates) <= 300` (E3 step 4; the ≤512 token-occurrence cap dropped) | `-k "a2l_match_40"` (perf) | killed | `test_r_a2l_match_40_3_crafted_stress_list` |
| M-40c | .40 | `_prefix_distance` without the band (the E3 control; now reached via .40/4 after the E5 correction) | `_prefix_distance`: band removed (`lo = 1; hi = m`) | `-k "a2l_match_40"` (perf) | killed | `test_r_a2l_match_40_4_prefix_distance_band_after_the_switch` |

Notes:

- Perf mutants (M-35, M-36a/b/d, M-37, M-40a/b/c) ran serially; `uptime` is printed
  before and after each run in the evidence (host load ≈ 1.3–2.1 during the perf
  arms). M-40b failed at CRAFT 51 tokens (median over the 1.0 s bound); M-40c
  failed at .40/4 BAND (median 2.803 s).
- M-40a **survived**: the "no collapse" control no longer trips the 1.0 s bound on
  the corrected code (variant C). `0 x125 + chax` median 0.495 s (50.5 % margin),
  all 5 `.40` tests passed. The row's `1,136.9 ms` figure is stale — it was
  measured pre-correction (round-1 mutant M-40b killed at 1,572 ms on the
  pre-corrective tree); after variant C the duplicated `0` tokens are walked
  cheaply (allowed 0 → `_token_range`, no banded distance) and no longer blow the
  bound.
- M-23b/M-24b/M-33b/M-34b are the second controls of their rows' cells; M-40a/M-40b/M-40c
  are the three controls the .40 cell now names (the E3 addendum names the band
  removal and the duplicate collapse; the per-candidate-check control was added by
  the E5 correction, E5S-01).
- The diff is `diff -u base mutant` (the file is untracked in the base tree, so
  `git diff` cannot isolate it).
