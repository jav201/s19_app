# INC 1 — E2 Code-Wire report

E1 commit `85e68957`; product base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`. Delta: `codewire/graph-inc1.md`. Baseline: `codewire/graph-baseline.md`. Scope is the counted four-node slice in `E1-slice.md`, owned entirely by **G1 model** in `s19_app/tui/a2l_definition.py`.

This is a graph-only prototype. No product or test function was executed as an E2 acceptance/performance check, and no functional PASS, timing PASS, memory PASS, mutant result or product defect is claimed. E2 edited no product source, product test, canon, plan, step log, requirement or frozen interface; the later E3 correction edits only INC 1's own requirements and design artifacts. No marks or extractor clone were created.

## Layering and callers

The applicable historical batch-103 Inc 2 and Inc 3 graphs were reviewed oldest first. Their semantic examples survive, but their page expansion, gathering and eager-candidate mechanisms do not enter this delta. A content search found no batch-100 graph binding `describe_definitions` or `_shared_with`. The current E1 baseline remains the code-shaped base for layering.

The E1 executed AST census remains the production caller source; E2 did not rerun extraction. A separate E2 content search of `tests/**/*.py` found no direct reference to `_shared_with`, `_occupancy_candidates` or `_build_occupancy_index`; this was a caller search, not a test run. Direct production callers of the unchanged public surface are:

| Caller | Callee | Contract used |
|---|---|---|
| `s19_app/tui/a2l_definition.py:607` — `describe_definition` | `describe_definitions` | one-name delegation; signature and result shape unchanged |
| `s19_app/tui/a2l_parameter_picker.py:629` | `describe_definitions` | one bulk describe per changed picker generation; unchanged |
| `s19_app/tui/app/patch.py:393` | `describe_definition` | one definition for patch edit; unchanged |
| `s19_app/tui/app/patch.py:458` | `describe_definition` | one definition for event validation; unchanged |

Inside the four-node slice, `describe_definitions` is the only caller of `_build_occupancy_index` and `_shared_with`; `_shared_with` is the only caller of `_occupancy_candidates`. `_shared_with` retains its calls to the unchanged `_entry_overlaps` and `_pair_exempt` semantic oracles. The builder receives the existing nested `is_array_entry` plus request-local `definitions_by_position` and `entry_cache`; it reads known final lengths by unique position without calling describe/materialize. Any genuinely unresolved final resolution still goes through the existing nested `materialize`, `entry_cache`, `describe_name` and `axis_span`. The graph's edges record these module-level paths.

## Design findings and dispositions

1. **E2-F1 — own position is not carried by `Definition`.** Source reading shows that the public frozen model has no section-walk position, while the baseline `_shared_with` compares name, kind, address, length and byte order. The delta therefore makes `own_position` an explicit private input and has the request-local index resolve a unique `(name, kind)` to its existing walk position. Candidate exclusion itself compares only `position`. A repeated key is ambiguous and maps to `None`; existing duplicate-name refusal produces an address-less definition and does not query overlap. Direct ambiguous calls exclude nothing, fail closed. This changes no public model or interface.

2. **E2-F2 — provisional lengths cannot prune lazy final spans, and known finals are not open-ended.** R-A2L-DEF.140/9, .140/10 and .140/11 show three distinct requirements: an earlier-starting CURVE can acquire its final length later, an over-cap span must remain reachable, and a malformed matrix can resolve to a declared-address point rather than its provisional span. The builder consults `entry_cache[position]` and `definitions_by_position[position]` without describe/materialize and uses exact ends for every known final length, including valid 4-byte VAL_BLKs. Only an AXIS_PTS or array-like MEASUREMENT/CHARACTERISTIC absent from both sources receives open upper reachability. This may over-select, never prune a possible final overlap. Existing materialization and `_entry_overlaps` make the final decision.

3. **E2-F3 — position order and address order differ.** R-A2L-DEF.138/22 / R-A2L-DEF.159/1 requires `LATE` at 0x40 before `EARLY` at 0x20. The index leaves are in section-walk position order and the candidate iterator performs iterative in-order traversal with conservative subtree pruning. It does not sort query results or gather all aliases. An exempt or final-nonoverlapping candidate advances to the next position.

4. **E2-F4 — instrumentation must observe work, not infer it.** The graph keeps builder invocation and `records` population inspectable, final candidate checks at `_entry_overlaps`, actual final-span work at `materialize`, and builds at `_describe_one`. A private generator wrapper at `_occupancy_candidates` records `consumed_positions` only as `_shared_with` consumes yields, with planned maxima 1, 1 and 2 for the .159 arms. A separate source arm catches complete-alias gather-without-sort, which consumption alone cannot see. Navigation comparisons are not mislabeled as candidate-overlap checks. These are planned E4 instruments; their known-bad RED proofs and all thresholds remain unexecuted here.

5. **E2-F5 — worst-case cost is not proven by the graph.** Open-ended unresolved records can produce conservative false positives, and the requirements' numeric bounds are not established by lint. E4 must execute the disjoint counters, full case_06 semantic oracle, build/query/integrated timings and memory cases exactly as planned. No asymptotic or threshold PASS is asserted from this design record.

## Private contract refinements

Within E1's explicit permission to refine private parameter and return types while retaining four nodes, the graph pins:

- `_build_occupancy_index(span_entries: Sequence[tuple], is_array_entry: Callable[[tuple], bool], definitions_by_position: Mapping[int, Definition], entry_cache: Mapping[int, tuple]) -> _OccupancyIndex`;
- `_occupancy_candidates(index: _OccupancyIndex, definition: Definition, own_position: int | None) -> Iterator[tuple]`;
- `_shared_with(definition: Definition, index: _OccupancyIndex, own_position: int | None, mask_of: Callable[[str], int | None], materialize: Callable[[tuple], tuple]) -> str | None`.

The old private page-fallback and optional-materialize route disappears from the changed `_shared_with`; the E1 production census shows only the central caller. `describe_definition(name, a2l_data)`, `describe_definitions(names, a2l_data)`, their return shapes, and `Definition.shared_with` are unchanged.

## E3 corrective dispositions

- **E3-INC1-01 — accepted.** Known final lengths now come from `definitions_by_position` and `entry_cache` by unique position, with no builder describe/materialize call. `last=None` requires absence from both sources plus a lazy route that can still change the length. Both .158 nodes add scalar and valid disjoint 4-byte VAL_BLK parametrizations, each with its original numeric check bound, 1 construction, 0 known-final open ends and 0 builder describe/materialize calls. Forcing open-ended despite known final 4 is a planned RED control.
- **E3-INC1-02 — accepted.** The candidate seam now has a private consumption wrapper. The three .159 arms assert at most 1, 1 and 2 consumed yields and 0 complete-alias gathers/sorts. Gather-without-sort is a source-arm RED; excess consumption is a runtime-counter RED.

Both corrections preserve 4 nodes, 1 source file and all public interfaces. No case id or AT was added, and no new execution is claimed.

## Findings for the conductor and interface proposals

- **Blocked product defects:** none established; no functional probe was run at E2 or during this graph-only E3 correction.
- **Requirement changes proposed:** the .158 and .159 measurement clauses are corrected in place; no new requirement id is proposed.
- **Root/frozen interface changes proposed:** none. I-ALP-1 and every other entry in `interfaces.md` remain untouched.
- **Additional interface proposal:** none. The three signatures above are the already-authorized private four-node slice, not dependencies for INC 2 or INC 3.
- **E3 status:** both supplied findings are visibly corrected in the graph; no finding from that review remains open here.

## Evidence

- Lint transcript: `evidence-e2/lint-graph-inc1.txt`.
- Machine parse: `evidence-e2/graph-inc1-parse.json`.
- E3 artifact validation: `evidence-e2/validation-e3.txt`.
- Replay from `<repo>` with `CODE_WIRE` naming the local Code-Wire checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python "$CODE_WIRE/tools/codewire_lint.py" .dev-flow/2026-11-18-a2l-load-performance/inc-1/codewire/graph-inc1.md --json .dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e2/graph-inc1-parse.json
```

The transcript, rather than this report, carries the executed lint verdict and exit status.
