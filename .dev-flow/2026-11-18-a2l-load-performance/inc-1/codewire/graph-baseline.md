# Code-Wire baseline — INC 1 central occupancy index

Baseline product base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0` changes no product file. Code-Wire local commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05` (v3.2). This file records existing code only: no source marks, stubs or proposed nodes. The E1 change slice is `describe_definitions` and `_shared_with`; the other three nodes are unchanged context and semantic oracles. The existing lazy `materialize`, `describe_name`, `mask_of`, `axis_span` and `entry_cache` closures remain inside `describe_definitions` and are not separate module nodes.

The inherited graphs reviewed are batch-103 `inc-2/codewire/graph-inc2.md` and `inc-3/codewire/graph-inc3.md`. Their page-expansion and eager-materialization designs are historical, not this baseline. Current code uses the `span_index[None]` global-list route whenever `materialize` is supplied. Current final spans are lazy and cached by section-walk `position`; all declared entries remain candidates, including over-cap and earlier-starting spans.

## Nodes

describe_definition
req: R-A2L-DEF.136, R-A2L-DEF.138, R-A2L-DEF.139, R-A2L-DEF.140
in: str name; dict a2l_data
out: Definition definition
func: unchanged public entry point; returns `describe_definitions([name], a2l_data)[name]` and does not mutate its input.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.138/22) INLINE `BIG` at 0x10 with length 64, `LATE` at 0x40 declared before `EARLY` at 0x20 → `BIG.shared_with` is `LATE`
examples: (R-A2L-DEF.140/10) length-refused `BIG` at 0x0 with declared length 1048577 and UBYTE `V` at 0x100000 → `V.shared_with` is `BIG`
examples: (R-A2L-DEF.139/1) two UWORD VALUEs named `DUP` → refusal `A2L-DEF-NAME` and the duplicate-name message

describe_definitions
req: R-A2L-DEF.136, R-A2L-DEF.138, R-A2L-DEF.139, R-A2L-DEF.140
in: Iterable[str] names; dict a2l_data
out: dict[str, Definition] definitions
func: unchanged baseline; one section walk collects `span_entries`, requested definitions are built first, and each addressed result receives `_shared_with(definition, span_index, mask_of, materialize)` after `span_index[None] = span_entries`; final spans are materialized on demand and cached by position.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.140/9) CURVE `CX` at 0x20 with final length 64 and VALUE `V` at 0x40, requested as `V`, `V` → one result with `shared_with` `CX`; `_describe_one` counts are `V` `1` and `CX` `1`
examples: (E1-case06-baseline) first `1000` unique case_06 names on the E1 Windows host → `1000` results and `500000` overlap checks; first `4000` → `4000` results and `7385600` overlap checks
examples: (R-A2L-DEF.138/14) `OA` at 0x10 with length 2, `OB` at 0x11 and disjoint `OC` at 0x30 → names `OB`, `OA` and `None` respectively

_entry_overlaps
req: R-A2L-DEF.138, R-A2L-DEF.140
in: Definition definition; tuple entry
out: bool overlaps
func: unchanged semantic oracle; inclusive interval overlap, with an unreadable length on either side represented as a point at its declared address.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.140/10) `V` at 0x100000 with length 1 against `BIG` at 0x0 with length 1048577 → `True`
examples: (R-A2L-DEF.140/2) UBYTE `VS` at 0x15 against AXIS_PTS `AXS` spanning 0x10 through 0x14 → `False`
examples: (R-A2L-DEF.138/4) UBYTE at 0x10 against an unsized INSTANCE point at 0x10 → `True`

_pair_exempt
req: R-A2L-DEF.138, R-A2L-DEF.140
in: Definition definition; tuple entry; Callable mask_of
out: bool exempt
func: unchanged semantic oracle; only two clean scalar number or enum definitions with readable lengths and disjoint selected bits are exempt; arrays, curves, maps, AXIS_PTS, BLOB and INSTANCE are never exempt.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.138/17) big-endian UWORD `MW` with mask 0x000F beside UBYTE `MU` with mask 0x0F at 0x10 → `True`, so `shared_with` is `None`
examples: (R-A2L-DEF.140/4) AXIS_PTS `AXS` beside a homonymous disjoint masked VALUE → `False`; no homonymous mask is inherited

_shared_with
req: R-A2L-DEF.138, R-A2L-DEF.140
in: Definition definition; Mapping[int, tuple] span_index; Callable mask_of; Optional[Callable[[tuple], tuple]] materialize = None
out: Optional[str] other
func: unchanged baseline; when materialize is supplied and `None` is a key, scans every global entry in section-walk position order, materializes each visited entry lazily, skips the first tuple-identical own entry, and returns the first overlapping non-exempt name; the legacy page-gather/sort branch remains only for calls without that route.
module: s19_app/tui/a2l_definition.py
examples: (R-A2L-DEF.138/22) `BIG` overlaps `LATE` and `EARLY`, with `LATE` earlier in file order → `LATE`
examples: (R-A2L-DEF.138/23) BLOB or INSTANCE `B` at 0x10 and homonymous masked VALUE `B` at 0x100 beside masked `MW` at 0x10 → `B`, with no mask exemption
examples: (R-A2L-DEF.140/10) over-cap `BIG` starts at 0x0 and covers `V` at 0x100000 → `BIG`
examples: (E1-case06-baseline) current global route performs exactly `500000` checks for the first `1000` case_06 names and `7385600` for the first `4000`; these are executed observations, not new-requirement PASS results

## Edges

describe_definition ──▶ describe_definitions
describe_definitions ──▶ _shared_with
_shared_with ──▶ _entry_overlaps
_shared_with ──▶ _pair_exempt
