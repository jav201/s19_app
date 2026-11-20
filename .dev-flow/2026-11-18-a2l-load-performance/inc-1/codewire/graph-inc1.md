# Code-Wire E2 delta — INC 1 central occupancy index

Stage E2, Code-Wire v3.2.0. E1 commit `85e68957`; product base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`. Layer `codewire/graph-baseline.md` first and this delta second. The four nodes below replace the two same-name baseline nodes and add two private helpers; `describe_definition`, `_entry_overlaps`, `_pair_exempt` and every nested closure retain their baseline contracts. The batch-103 Inc 2/Inc 3 graphs are semantic history only; their page expansion and eager candidate mechanisms are not layered into this design. No batch-100 graph node binds these functions.

Graph only: no product stub, mark, declaration or test is part of this delta. All examples are planned E4 expectations from `02-test-cases.md` or preserved known-answer fixtures, not executed E2 product results. Owner for every node and the sole source file `s19_app/tui/a2l_definition.py`: **G1 model**. Frozen I-ALP-1 is unchanged.

# Private value types and navigation contract

`OccupancyEntry` is the existing walk tuple: `(position: int, name: str, kind: str, address: int, byte_length: int | None, byte_order: str, ...)`; any AXIS_PTS fields after the first six survive unchanged for the existing `materialize` closure. Entries arrive in increasing, unique preorder section-walk `position` order.

`IntervalRecord` is `(first: int, last: int | None, entry: OccupancyEntry)`. There is exactly one record per entry. `first` is the declared address. Before choosing an upper end, the builder consults `entry_cache[position]` and `definitions_by_position[position]`, in that order, without calling `materialize`, `describe_name` or `_describe_one`. A cached or already-built final length gives an exact inclusive end; a known final `None` or length below 1 gives the existing declared-address point. `last is None` means **unbounded conservative reachability**, never a final unknown-length point, and is permitted only when neither source has a final length and existing lazy materialization can still change it (an array-like MEASUREMENT/CHARACTERISTIC under `is_array_entry`, or AXIS_PTS). A valid requested VAL_BLK whose final length is 4 therefore has `last == first + 3`, never `None`. Materialization never changes the declared address. Neither input map is retained by the completed index.

`_OccupancyIndex` is a private immutable-after-build value with:
- `records: tuple[IntervalRecord, ...]`, in position order;
- `leaf_offset: int`, the complete-binary-tree leaf base;
- `min_first: tuple[int | None, ...]` and `max_last: tuple[int | None, ...]`, two navigation summaries per active subtree, not additional occupancy or page records;
- `position_by_object: Mapping[tuple[str, str], int | None]`, keyed by `(entry name, entry kind)` solely so the public caller can obtain the walk position of its requested record. A repeated key stores `None`; the existing duplicate-name refusal has no address and does not enter overlap evaluation. A direct ambiguous call with `own_position=None` excludes nothing, fail closed. Neither name nor address nor span equality excludes a candidate.

For an active subtree, `min_first` is its least interval start. `max_last` is its greatest inclusive end, with `None` representing an unbounded member; an empty tree node has `min_first is None` and is never descended into. For query `[query_first, query_last]`, a subtree cannot overlap when `min_first > query_last`, or when `max_last is not None and max_last < query_first`. All other subtrees remain reachable. Iterative in-order traversal visits leaves by increasing `position`; it yields one original entry at a time, skips `own_position` before materialization, and resumes after a conservative false positive. It never gathers or sorts the alias population and never expands a span into pages.

The existing `entry_cache`, `materialize`, `describe_name`, `axis_span`, `mask_of`, `is_array_entry`, `_entry_overlaps` and `_pair_exempt` remain the lazy and semantic implementation. Instrumentation uses builder calls and `records` positions for construction/population, `_entry_overlaps` for final candidate checks, actual entries into `materialize` for final-span resolution, and `_describe_one` for definition builds. A private generator wrapper at `_occupancy_candidates` appends to `consumed_positions` only when `_shared_with` requests the next yield; a separate source arm rejects complete-alias gathering or sorting because a consumption counter cannot see an internal gather. No public counter or result field is added.

# Requirement examples and ownership

| Requirement | Concrete planned sources below | Owner |
|---|---|---|
| R-A2L-DEF.156 | .156/1, .156/2, .156/3 | G1 model |
| R-A2L-DEF.157 | .157/1, .157/2, .157/3 | G1 model |
| R-A2L-DEF.158 | .158/1, .158/2 | G1 model |
| R-A2L-DEF.159 | .159/1, .159/2, .159/3 | G1 model |
| R-A2L-DEF.160 | .160/1, .160/2, .160/3 | G1 model |
| R-A2L-DEF.161 | .161/1, .161/2, .161/3 | G1 model |
| R-A2L-DEF.162 | .162/1 | G1 model |
| R-A2L-DEF.163 | .163/1 | G1 model |
| R-A2L-DEF.164 | .164/1 | G1 model |
| R-A2L-DEF.165 | .165/1 | G1 model |

## Nodes

describe_definitions
req: R-A2L-DEF.136, R-A2L-DEF.138, R-A2L-DEF.139, R-A2L-DEF.140, R-A2L-DEF.156, R-A2L-DEF.157, R-A2L-DEF.158, R-A2L-DEF.161, R-A2L-DEF.162, R-A2L-DEF.164, R-A2L-DEF.165
in: Iterable[str] names; dict a2l_data
out: dict[str, Definition] definitions
func: changed: keep the public signature, one existing section walk, requested-name order and deduplication, and all existing describe/refusal behavior; after requested definitions are available, associate their already-final values with unique entry positions in request-local `definitions_by_position` without another describe, then call `_build_occupancy_index(span_entries, is_array_entry, definitions_by_position, entry_cache)` exactly once for the request; for each unique addressed result pass its `position_by_object[(name, section)]` and the same index to `_shared_with`; address-less results stay untouched, the input stays read-only, and lazy `materialize`/`entry_cache` reuse is unchanged.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.156/1) one requested name `A` in a three-object inline A2L → result keys `A`, central-index constructions `1`, per-name reconstructions `0`
examples: (R-A2L-DEF.156/2) `A` and `B` at 0x10 and disjoint `C` at 0x80, requested as `A`, `B`, `C` → result keys `A`, `B`, `C`, `A.shared_with` `B`, `B.shared_with` `A`, `C.shared_with` `None`, constructions `1`
examples: (R-A2L-DEF.156/3) names `A`, `A`, `B` at disjoint 0x10 and 0x20 → result keys `A`, `B` in that order, constructions `1`, additional construction for the repeat `0`
examples: (R-A2L-DEF.158/1) for i from `0` through `999`, name `D` + str((i * 7919) % 10007) + `_` + str(i), address `0x1000 + i * 0x40 + (i % 7) * 4`, run with length `1` scalars and valid 4-byte VAL_BLKs → each parametrization has `1000` results, every `shared_with` `None`, at most `20000` checks, total constructions `1`; known-final VAL_BLK open ends `0`, builder describes/materializations `0`
examples: (R-A2L-DEF.158/2) the same arithmetic fixture and two variants for i from `0` through `3999` → each has `4000` results, every `shared_with` `None`, at most `100000` checks, total constructions `1`; known-final VAL_BLK open ends `0`, builder describes/materializations `0`
examples: (R-A2L-DEF.161/1) one requested disjoint `V` among `4000` pairwise-disjoint scalar objects → one result `V`, additional final-span materializations `0`, per-name definition builds `1`
examples: (R-A2L-DEF.161/2) requested VALUE `V` at 0x40 inside earlier-starting CURVE `CX` at 0x20 whose unresolved final length is `64`, among `4000` objects → `V.shared_with` `CX`, additional materializations `1`, definition builds `2`
examples: (R-A2L-DEF.161/3) request `V`, `V` with `CX` declared first → one result key `V`, `V.shared_with` `CX`, additional materializations of `CX` `1`, builds of `V` `1` and `CX` `1`
examples: (R-A2L-DEF.165/1, AT-ALP-I1-1) public batch describe of every unique case_06 name after one warm-up → each of `3` measured runs returns exactly `220040` keys in request order with `0` oracle differences, median at most `30.0` seconds; planned E4 threshold, not measured here

_build_occupancy_index
req: R-A2L-DEF.140, R-A2L-DEF.156, R-A2L-DEF.157, R-A2L-DEF.158, R-A2L-DEF.162, R-A2L-DEF.164
in: Sequence[tuple] span_entries; (Callable) tuple->bool is_array_entry; Mapping[int, Definition] definitions_by_position; Mapping[int, tuple] entry_cache
out: _OccupancyIndex index
func: new private builder: in one position-order pass emit one `IntervalRecord` per entry; for each unique position read any already-materialized tuple from `entry_cache`, else any already-built definition from `definitions_by_position`, and use that final byte length for an exact bounded interval or known final point; only when neither source resolves the entry and its existing lazy route can change its length may an AXIS_PTS or array-like entry receive `last=None`; other entries use their existing final/provisional-as-final length and points; build the implicit complete tree's min/max summaries without sorting, retain every unique position, and build the unique-or-ambiguous `(name, kind)` to position lookup; never call `materialize`, `describe_name`, `_describe_one`, a page expander or a global per-entry rescan, and never retain either input map.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.157/1) one entry at position `10`, name `P`, kind `CHARACTERISTIC`, address 0x10, length `1` → exactly `1` interval record with first 0x10 and last 0x10, page-expansion records `0`
examples: (R-A2L-DEF.157/2) one entry `C` at 0x10 with length `64` → exactly `1` interval record with first 0x10 and last 0x4F across four 16-byte pages, page-expansion records `0`
examples: (R-A2L-DEF.157/3, R-A2L-DEF.140/10) over-cap `BIG` at 0x0 with length `1048577` and point `V` at 0x100000 → exactly `1` interval for `BIG`, last 0x100000, page-expansion records `0`, and `BIG` remains reachable for `V`
examples: (R-A2L-DEF.158/1) valid disjoint VAL_BLK `VB` at position `20`, address 0x40 and final length `4` already in `definitions_by_position` → last 0x43, known-final open ends `0`, builder calls to describe/materialize `0`
examples: (R-A2L-DEF.158/2) valid disjoint VAL_BLK `VC` at position `21`, address 0x80 and final length `4` already in `entry_cache` → last 0x83, known-final open ends `0`, builder calls to describe/materialize `0`
examples: (R-A2L-DEF.158/1 negative, R-A2L-DEF.158/2 negative) force `last=None` despite the available final length `4` → known-final open ends exceed `0` and the disjoint VAL_BLK checks exceed `20000` or `100000` respectively; planned RED control, not executed
examples: (R-A2L-DEF.140/9) CURVE `CX` at 0x20 absent from both final-length sources with unresolved final length and VALUE `V` at 0x40 → the `CX` record has first 0x20 and last `None`, build-time calls to `materialize` `0`, so the earlier-starting final span remains reachable
examples: (R-A2L-DEF.140/11) malformed multi-value `M` at 0x10 absent from both sources whose tag length is provisionally `4` but whose final length is `None` → its record has last `None`, not provisional last 0x13; final materialization later reduces it to point 0x10
examples: (R-A2L-DEF.162/1, AT-ALP-I1-1) one fresh index over the pinned case_06 tuple population after one warm-up → the warm-up and each of `3` runs retain exactly `220040` records and `220040` unique positions, median build at most `2.5` seconds; planned E4 threshold
examples: (R-A2L-DEF.164/1, AT-ALP-I1-1) build and retain the same case_06 index → each of `3` runs retains `220040` unique positions, traced peak additional allocation at most `67108864` bytes, page-expansion records `0`; planned E4 threshold

_occupancy_candidates
req: R-A2L-DEF.138, R-A2L-DEF.140, R-A2L-DEF.158, R-A2L-DEF.159, R-A2L-DEF.160, R-A2L-DEF.161, R-A2L-DEF.163
in: _OccupancyIndex index; Definition definition; int | None own_position
out: Iterator[tuple] candidates
func: new private lazy iterator: derive the requested inclusive final span or point from `definition`, traverse the position-ordered tree iteratively in preorder-independent in-order sequence, prune only subtrees proved disjoint by the conservative summaries, skip the entry whose position equals `own_position`, and yield each remaining selected original entry without materializing it, collecting aliases or sorting; after a yielded entry proves non-overlapping, continue with the next position. The E4 private generator wrapper at this seam counts a yield only when `_shared_with` consumes it; the independent source arm rejects gather-without-sort, which that counter alone cannot observe.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.159/1) `BIG` position `1` spans 0x10 through 0x4F, `LATE` position `2` is at 0x40 and `EARLY` position `3` at 0x20, own position `1` → consumed candidates at most `1`, first candidate `LATE`, complete-alias gathers `0`, whole-alias sorts `0`, iterator materializations `0`
examples: (R-A2L-DEF.159/2) `4000` records share one span in reverse name order, queried position `0`, next position `1` named `NEXT` → consumed candidates at most `1`, first candidate `NEXT`, complete-alias gathers `0`, whole-alias sorts `0`
examples: (R-A2L-DEF.159/3) overlapping `FREE` at position `4` and `BLOCK` at position `5` follow the queried position `3` → consumed candidates at most `2`, in order `FREE`, `BLOCK`, complete-alias gathers `0`, whole-alias sorts `0`; gather-without-sort is a planned source-arm RED
examples: (R-A2L-DEF.160/1) same-name, same-span records at positions `10` and `11`, own position `10` → only position `11` is yielded; name/address/span exclusions of position `11` `0`
examples: (R-A2L-DEF.160/2) `A` position `4` and `B` position `5` have identical address, length and byte order, own position `4` → only `B` position `5` is yielded
examples: (R-A2L-DEF.160/3) same-name `DUP` positions `10` and `11` at disjoint 0x10 and 0x80, own position `10` → no candidate is yielded and no name-based grouping occurs
examples: (R-A2L-DEF.161/2) unresolved `CX` at 0x20 with open upper reachability and requested `V` at 0x40 → `CX` is selected before any final-span materialization, candidates materialized by this iterator `0`
examples: (R-A2L-DEF.140/11) malformed `M` at 0x10 is conservative and queried `V` is at 0x12 → `M` may be yielded as a false positive, then traversal resumes at the next position after final materialization proves the point disjoint

_shared_with
req: R-A2L-DEF.138, R-A2L-DEF.140, R-A2L-DEF.158, R-A2L-DEF.159, R-A2L-DEF.160, R-A2L-DEF.161, R-A2L-DEF.163
in: Definition definition; _OccupancyIndex index; int | None own_position; (Callable) str->int|None mask_of; (Callable) tuple->tuple materialize
out: Optional[str] other
func: changed: replace both the global `span_index[None]` scan and the legacy page gather/sort with `_occupancy_candidates(index, definition, own_position)`; for each selected entry call the existing position-cached `materialize`, continue when `_entry_overlaps` is false or `_pair_exempt` is true, and otherwise return its name immediately; exhaustion or an address-less definition returns `None`, with self excluded only by position before materialization and no complete alias collection or sort.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.158/1) the `1000` non-uniform pairwise-disjoint arithmetic definitions as scalars and valid 4-byte VAL_BLKs → each variant's every result `None`, at most `20000` calls to `_entry_overlaps`, additional index constructions `0`, known-final VAL_BLK open ends `0`
examples: (R-A2L-DEF.158/2) the corresponding `4000` definitions in both variants → each variant's every result `None`, at most `100000` calls to `_entry_overlaps`, additional index constructions `0`, known-final VAL_BLK open ends `0`
examples: (R-A2L-DEF.159/1, R-A2L-DEF.138/22) `BIG` 0x10 through 0x4F overlaps lower-position `LATE` at 0x40 before higher-position `EARLY` at 0x20 → other `LATE`, consumed candidates at most `1`, final materializations at most `2`, complete-alias gathers `0`, whole-alias sorts `0`
examples: (R-A2L-DEF.159/2) queried smallest position among `4000` same-span records whose names reverse position order, with `NEXT` immediately following → other `NEXT`, consumed candidates at most `1`, final materializations at most `2`, complete-alias gathers `0`, whole-alias sorts `0`
examples: (R-A2L-DEF.159/3) first overlapping scalar pair `FREE` has clean disjoint masks and following `BLOCK` is unmasked → other `BLOCK`, consumed candidates at most `2`, final materializations at most `3`, complete-alias gathers `0`, whole-alias sorts `0`
examples: (R-A2L-DEF.160/1) same-name, same-span records at positions `10` and `11`, queried own position `10` → position `11` is evaluated as the other record and its name `DUP` is returned; only position `10` is excluded
examples: (R-A2L-DEF.160/2) different-name `A` and `B` with identical address, length and byte order, queried `A` at its own position → other `B`, so the other position is not mistaken for self
examples: (R-A2L-DEF.160/3) same-name `DUP` at disjoint 0x10 and 0x80, queried position `10` → other `None`, with no name-only exclusion or grouping
examples: (R-A2L-DEF.161/2, R-A2L-DEF.140/9) requested `V` at 0x40 and selected unresolved `CX` at 0x20 with final length `64` → other `CX`, additional materializations `1`, builds of `V` `1` and `CX` `1`
examples: (R-A2L-DEF.140/10) over-cap `BIG` at 0x0 with length `1048577` covers `V` at 0x100000 → other `BIG`; no lower-window or decode-cap prune applies
examples: (R-A2L-DEF.140/11) malformed `M` at 0x10 materializes to final point length `None` while `V` is at 0x12 → the conservative candidate fails `_entry_overlaps`, traversal continues, other `None`
examples: (R-A2L-DEF.163/1, AT-ALP-I1-1) after one case_06 index build and warm-up, resolve every position through this selector → each of `3` measured runs resolves `220040` positions with `0` `shared_with` differences from the independent source-text oracle, median at most `18.0` seconds; planned E4 threshold

## Entities

[Data: _OccupancyIndex]
in: _OccupancyIndex
desc: one request-local compact position tree; `records` holds one interval per occupancy entry, summary tuples only navigate those records, and `position_by_object` resolves the requested record's walk position without becoming candidate identity; no page expansion or eager final-span description is retained.

## Edges

describe_definition ──▶ describe_definitions
describe_definitions ──▶ _build_occupancy_index
_build_occupancy_index ──▶ [Data: _OccupancyIndex]
describe_definitions ──▶ _shared_with
[Data: _OccupancyIndex] ──▶ _occupancy_candidates
_shared_with ──▶ _occupancy_candidates
_shared_with ──▶ _entry_overlaps
_shared_with ──▶ _pair_exempt
