# Unit FA-IDX2b — index memory back under 64 MiB (R-A2L-DEF.164) without changing FA-IDX2's walk [deepseek-v4-pro · high; Opus diff review]

Tree: `alp-e4r` at **`0c14129f`** (= 9c464b6a + FA-IDX2 committed locally while its check runs; speculative, P-202 O2; HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx, P-202). No agent edits `~/.claude/skills`.

## Fixed diagnosis (orchestrator, relevo-22; measured on the quiet host with tracemalloc on case_06, 220,040 entries)
- `test_r_a2l_def_164_1_case06_index_memory_bound` fails after FA-IDX2: `(1, 'retained', 76744324)` against 67,108,864. Before FA-IDX2: retained 51.6 MiB, peak 61.3 MiB.
- FA-IDX2 added about 23 MiB. The two largest items are new `int` objects, not containers:
  - `order = tuple(sorted(range(count), ...))`: 219,784 new ints, 8.4 MiB, plus a 1.7 MiB tuple;
  - `leaf_of_record` filled from `enumerate(order)`: 219,783 new ints, 5.9 MiB, plus a 1.7 MiB tuple;
  - `min_pos` 4.0 MiB (references to existing ints: fine), `positions` 1.7 MiB.
- The build's peak also counts the `tuple(...)` copies made at return (each copy of a 524,288-slot list is 4 MiB while both exist).

## Fixed design (implement exactly; if the code contradicts it, STOP and report)
Semantics, walk order, the counted visit and the tighten rule stay exactly as FA-IDX2 left them.
1. **Leaf records instead of `order`.** In `_build_occupancy_index`, build `leaf_records = sorted(records, key=operator.itemgetter(0))` (a stable sort of the existing record tuples: no new ints; ties keep walk order). Store `leaf_records` in the index in place of `order`. Fill the leaf summaries from `leaf_records[leaf]`. In `_occupancy_candidates`, a leaf maps to `leaf_records[leaf]`.
2. **No `positions`, no `leaf_of_record`.** Remove both fields. `_tighten_occupancy(index, entry, final_entry)` takes the **original** (unmaterialized) entry and finds its leaf by two keyed bisects (Python ≥ 3.11, `bisect` `key=`):
   - `lo = bisect_left(leaf_records, entry[3], key=first_of)`, `hi = bisect_right(leaf_records, entry[3], lo, key=first_of)` — the run of leaves with that first address (`records[i][0] == entry[3]` by construction);
   - inside it, `leaf = bisect_left(leaf_records, entry[0], lo, hi, key=position_of)` with `position_of = lambda record: record[2][0]` (positions increase inside a run because the sort is stable over walk order);
   - if `leaf == hi` or `leaf_records[leaf][2][0] != entry[0]`: `raise AssertionError("occupancy leaf not found")`.
   - In `_shared_with`: `original = entry; entry = materialize(entry); _tighten_occupancy(index, original, entry)`.
3. **No return-time copies of the big arrays.** `min_first`, `max_last` and `min_pos` are returned as the lists that were built (no `tuple(...)` copy). Update the `_OccupancyIndex` annotations (`list`) and docstrings (fields, the leaf lookup, "neither input map is retained"). `records` stays a tuple.

## Files you may edit
`s19_app/tui/a2l_definition.py` only. No test changes: if a test reads `order`, `positions` or `leaf_of_record`, STOP and report (the orchestrator found none at the time of this brief).

## Rows
| row | change | negative control (scratch copy) → RED |
|---|---|---|
| 1 | design 1 | put back `order = tuple(sorted(range(count), key=...))` and map leaves through it → `.164` RED (paste the retained value) |
| 2 | design 2 | make the run search use `bisect_left(leaf_records, entry[3], key=first_of)` only (first leaf of the run, ignoring the position) → `test_r_a2l_def_166_2_equivalence_with_global_scan` or `test_r_a2l_def_159_1_position_not_address_selects_next` RED (aliases share an address) |
| 3 | design 3 | n/a; report retained and peak before/after (row 4) |
| 4 | memory evidence | in `../scratch/`, a script that builds the case_06 index as `.164` does (`tests/test_alp_a2l_occupancy_perf.py::_case06_entries`, tracemalloc) and prints retained and peak MiB for 2 runs, on HEAD and on your tree |

## Nodes you may run (`timeout 300` unless stated)
- `tests/test_alp_a2l_occupancy.py -n 4`;
- `tests/test_alp_a2l_occupancy_perf.py -n 0 -k "158"` (counters);
- `tests/test_b103_a2l_definition*.py -n 4 -m "not serial_timing"` (at most 4 files per run);
- `timeout 900`: `tests/test_alp_a2l_occupancy_perf.py::test_r_a2l_def_164_1_case06_index_memory_bound -n 0` (memory, not timing; it parses case_06 once, about 2 min).
Never `.162`, `.163` or `.165` (timing: the orchestrator runs them on the quiet host).

## Report extras
Retained and peak MiB per run, HEAD vs your tree; the visit means of `test_r_a2l_def_167` for the three layouts (must stay 25.0 / 25.0 / 25.1 ± 0.5) and the dense checks of `.168` (must stay 1,000).
