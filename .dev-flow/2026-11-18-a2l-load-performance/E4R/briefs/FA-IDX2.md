# Unit FA-IDX2 — D3 index redesign: address-ordered tree, best-first by walk position, bounds tightened on materialization [deepseek-v4-pro · high; Opus diff review]

Tree: `alp-e4r` at **`<sha after FA-IDX2T>`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

## Fixed design (architect, FA-DESIGN §3.5; implement exactly; if the code contradicts it, STOP and report)
Semantics that must not change:
- `shared_with` = the name of the first non-exempt overlapping record **in section-walk position order**, own position excluded, unknown final length treated as a point;
- lazy candidate yield (R-A2L-DEF.159, .161);
- 1 index per describe request (.156);
- 1 compact interval per record (.157);
- no describe or materialize during build (.158).

1. **Build** (`_build_occupancy_index`, signature unchanged: the test counters call it positionally with 4 args):
   - `records` stays exactly as today: one `(first, last, entry)` per entry in walk order, with `last` from the FA-IDX1 rule.
   - New leaf order: `order = sorted(range(n), key=records_first)`. Use `operator.itemgetter(0)` on records via a stable sort; ties keep walk order. Do not build key tuples.
   - Complete binary tree over the leaves in that order, with three per-node arrays of size `2·leaf_offset`:
     - `min_first` (min address);
     - `max_last` (max upper end, open = `None` meaning +∞), as a **list** (mutable);
     - `min_pos` (min walk position below the node).
   - Keep `leaf_offset`. Add `order` (leaf → record index), a tuple, and keep `position_by_object`.
   - Positions are strictly increasing in `records`, so a record index is found by `bisect` on a tuple of positions. Store that tuple in the index.
2. **`_occupancy_candidates`** (signature unchanged):
   - Best-first with `heapq` over `(min_pos[node], node)`, starting at the root.
   - Each popped internal node reads `min_first[node]` **exactly once** (this is the counted visit); it is pruned when `min_first[node] > query_last` or (`max_last[node] is not None` and `max_last[node] < address`); otherwise both children are pushed with their `min_pos`.
   - A popped leaf maps through `order` to its record: skip `own_position`, drop it if `record[0] > query_last` or (`max_last[leaf] is not None` and `max_last[leaf] < address`), and otherwise `yield` the entry. Use the leaf's **current** `max_last`, never the stale `record[1]`, so a tightened bound applies. Because the heap key is a lower bound on every walk position below a node, leaves are yielded in exact walk order.
   - Never collect the full candidate set.
3. **Tighten** (new private `_tighten_occupancy(index, position, final_entry)`):
   - Find the record index by bisect and its leaf via the inverse of `order` (store `leaf_of_record` as a tuple at build).
   - Set the leaf's `max_last` to the final last (`address + len − 1`, or the point `address` when the final length is None or < 1), then recompute `max_last` up to the root (O(log n)).
   - Call it in `_shared_with` right after `entry = materialize(entry)`, before `_entry_overlaps`.
   - The new value can only be ≤ the old bound, given the FA-IDX1 rule. Guard it with `if old is not None and new > old: raise AssertionError("occupancy bound grew on materialization (D2 broken)")`.
3b. **Predicate once per entry (FA-IDX1 cost, orchestrator amendment).** At ca5ed3bc the build loop evaluates `entry[2] == "AXIS_PTS" or is_array_entry(entry)` for every entry with no cached or requested final length, and a second time in the `last = None` branch for the open-ended ones. A narrow describe of case_06's last name went from 1.82 s to 3.63 s (shared host, indicative). Restructure the loop so the predicate runs at most once per entry (the unresolved branch sets `last = None` itself); the resulting `(first, last, entry)` records must be identical. Proof: `test_r_a2l_def_166_2_equivalence_with_global_scan` and the FA-IDX1 tests stay GREEN; report the number of `is_array_entry` calls per build before and after on the three FA-IDX2T layouts (a monkeypatched counter in scratch, not a committed test). The orchestrator times it on the quiet host (M1).
4. **Docstrings.** `_OccupancyIndex` drops "Immutable after construction". It now says `max_last` tightens monotonically toward materialized final spans within the request (R-A2L-DEF.166–.168, E4R). `_build_occupancy_index` and `_occupancy_candidates` describe the address order, the best-first walk order and the counted visit.

## Files you may edit
`s19_app/tui/a2l_definition.py` (the three functions above, the new helper, the `_OccupancyIndex` fields), `tests/test_alp_a2l_occupancy.py` (re-pins only: a test that asserts leaf/tree internals of the **same row** may move to the new structure; list each re-pin with its row).

## Rows
| row | change | negative control (scratch) → RED |
|---|---|---|
| 1 | build (design 1) | keep walk-order leaves → `test_r_a2l_def_167_visits_per_definition[shuffled]` |
| 2 | best-first candidates (design 2) | use a DFS stack in address order → `test_r_a2l_def_159_1_position_not_address_selects_next` and `test_r_a2l_def_166_2_equivalence_with_global_scan` |
| 3 | tighten + its call (design 3) | remove the call in `_shared_with` → `test_r_a2l_def_168_dense_overlap_checks` |
| 3b | predicate once per entry (design 3b) | n/a (records identical); paste the `is_array_entry` call counts before/after |
| 4 | docstrings (design 4) | n/a |
| 5 | re-pins, if any | each re-pinned test must still go RED under the row-1 or row-2 mutation; show it |

## Nodes you may run (`timeout 300`)
- `tests/test_alp_a2l_occupancy.py -n 4`;
- `tests/test_alp_a2l_occupancy_perf.py -n 0 -m "not slow"` (the `.158` counters);
- `tests/test_alp_a2l_occupancy_at.py -n 4 -m "not slow and not serial_timing"`;
- `tests/test_b103_a2l_definition*.py -n 4 -m "not serial_timing"` (at most 4 files per run).

Never the `slow` case_06 nodes: the orchestrator runs `.162`–`.165` on the quiet host and gates them at ≥ 20 % margin and `.164` ≤ 64 MiB.

## Report extras
For each layout, the mean visits before (from FA-IDX2T's report) and after, the dense checks after, and the equivalence query count.
FA-IDX2T measured before (mean visits per **addressed** definition, the convention the orchestrator pinned; AXIS_PTS names resolve to `A2L-DEF-NAME` refusals and run no query): monotone 25.0, shuffled 5,800.8, dense 1,029.8; dense `_entry_overlaps` 7,000,000.
