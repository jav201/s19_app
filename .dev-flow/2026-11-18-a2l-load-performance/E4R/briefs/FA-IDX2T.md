# Unit FA-IDX2T — D3 scale cases with a node-visit counter, and the behavioural no-gather arm [deepseek-v4-pro · high]

Tree: `alp-e4r` at **`<sha after FA-IDX1>`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

You write tests only; FA-IDX2 changes the index afterwards. Arms marked "RED now" must be RED for the stated reason (counts, not an import error or a seam guard).

## Fixed diagnosis (R5-F2, R5-F8; operator D3)
- **The tree is built over section-walk position order.** It prunes well only when walk order roughly follows address order. R5 ran a counting simulation of the unmodified code: it counted reads of `index.min_first[node]` in `_occupancy_candidates`, one per visited internal node. At n = 8,000 disjoint 4-byte objects:
  - monotone: 25 visits/query;
  - shuffled: 5,814 visits/query;
  - 1,000 AXIS_PTS declared first: 7,499,500 `_entry_overlaps` calls. AXIS_PTS records are always open-ended (`entry[4]` is None).
- **The `.159_2` arm's no-gather check is a token blacklist** (`_assert_no_gather_sort`: `sorted(`, `.sort(`, `nsmallest(`, `heapify(`, `list(`). A gather written another way would survive it (R5-F8a). Operator D3 thresholds: mean visits per definition ≤ 4·log2 n + 16 (67.9 at n = 8,000) on all three layouts; dense checks ≤ 25·n = 200,000.

## Files you may edit
`tests/test_alp_a2l_occupancy.py` only.

## Rows
| row | change | expected now |
|---|---|---|
| 1 | **Visit counter helper.** Wrap the product `_build_occupancy_index` with a monkeypatch that returns `index._replace(min_first=_CountingSeq(index.min_first))`; `_CountingSeq` counts `__getitem__` calls and delegates everything else (`__len__`, iteration). Add it next to `_install_counters`, and expose `visits` in the state. Definition used: one read of an internal node's `min_first` = one index node visit (E4R definitions). | — |
| 2 | **Population builders** (one function, three layouts), n = 8,000 pairwise-disjoint 4-byte objects at `0x1000 + k·0x40 + (k%7)·4`:<br>(a) monotone: object k declared k-th;<br>(b) shuffled: declaration order = `random.Random(0x5EED)` permutation of k;<br>(c) dense: 1,000 AXIS_PTS (helper `axis_pts` + an `rl` layout with `AXIS_PTS_X`, a valid `MAX_AXIS_POINTS`, sizes chosen to stay inside each object's 0x40 slot) declared first at the lowest 1,000 slots, then 7,000 CHARACTERISTIC VALUE scalars.<br>Assert parse errors == 0 and the tag counts. | — |
| 3 | `test_r_a2l_def_167_visits_per_definition[monotone/shuffled/dense]`: `describe_definitions(all_names, a2l)` in one request; assert mean visits per described definition ≤ `4 * math.log2(8000) + 16` and print the mean. Cites R-A2L-DEF.167 (E4R). | monotone GREEN (~25); shuffled RED (~5,814); dense RED or GREEN, record which |
| 4 | `test_r_a2l_def_168_dense_overlap_checks`: the dense layout; total `_entry_overlaps` calls (existing counter) ≤ 200,000; every `shared_with` is None (disjoint). Cites R-A2L-DEF.168. | RED (~7.5 M) |
| 5 | Re-pin `test_r_a2l_def_159_2_aliases_are_not_gathered_or_sorted` (same name, same row R-A2L-DEF.159): replace `_assert_no_gather_sort` with a behavioural probe. Build an index over 4,000 same-span aliases plus a query; take one `next()` from `_occupancy_candidates`; assert visits ≤ `2 * math.log2(4000) + 4`, and that the yielded entry is the minimum-position alias. Keep the existing yield/materialization bounds. Delete `_assert_no_gather_sort` only if nothing else uses it (grep). | GREEN now |

Negative controls (scratch copy of the product):
- Row 3: make `_occupancy_candidates` ignore pruning (push both children always) → the monotone arm RED.
- Row 4: AXIS_PTS already behave as the mutation would, so RED now is the evidence.
- Row 5: insert `records_list = list(_all_leaves(...))` before the first yield (a full gather) → the visit bound RED.

## Nodes you may run (`timeout 300`)
- `tests/test_alp_a2l_occupancy.py -n 4`;
- the new nodes `-n 0`.

Report the measured mean visits and checks for every arm (these are RED-before evidence).
