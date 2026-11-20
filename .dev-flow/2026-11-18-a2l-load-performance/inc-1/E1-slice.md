# INC 1 — E1 slice

Base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0`. Requirements: `01-requirements.md`. Cases: `02-test-cases.md`. Baseline graph: `codewire/graph-baseline.md`. Mechanical source and consumer census: `evidence-e1/census.json`.

## Count and ownership

One source file, within the plan's one-source budget: `s19_app/tui/a2l_definition.py`. One implementation group owns it. No other product file is authorized.

The planned E2 slice contains 4 module-level nodes: 2 changed existing nodes and 2 new private helpers. Nested closures that remain unchanged are listed separately so the ownership census is explicit. Baseline Code-Wire has 5 existing nodes: the 2 changed nodes plus 3 unchanged context nodes (`describe_definition`, `_entry_overlaps` and `_pair_exempt`); the latter two are unchanged semantic oracles.

| Node | Disposition | Responsibility | Requirements |
|---|---|---|---|
| `describe_definitions` | changed | associate already-built definitions with unique entry positions, build the central index once after the existing walk, expose the construction-count seam, keep lazy-materialization behavior and query it for every addressed result | R-A2L-DEF.156, R-A2L-DEF.157, R-A2L-DEF.158, R-A2L-DEF.161, R-A2L-DEF.162, R-A2L-DEF.164, R-A2L-DEF.165 |
| `_shared_with` | changed | advance through index-selected candidates in position order, exclude self by position, preserve overlap/mask semantics and avoid complete alias gather/sort; consume no later candidate after an answer | R-A2L-DEF.158, R-A2L-DEF.159, R-A2L-DEF.160, R-A2L-DEF.161, R-A2L-DEF.163 |
| `_build_occupancy_index` | new private | consult `definitions_by_position` and `entry_cache` by unique position without describe/materialize, bound every known final span, retain conservative reachability only for genuinely unresolved spans and provide per-run construction/population counts | R-A2L-DEF.156, R-A2L-DEF.157, R-A2L-DEF.158, R-A2L-DEF.162, R-A2L-DEF.164 |
| `_occupancy_candidates` | new private | yield selected candidates in section-walk position order without a global scan, full alias gather/materialization or sort; expose lazy consumption through the private wrapper seam | R-A2L-DEF.158, R-A2L-DEF.159, R-A2L-DEF.160, R-A2L-DEF.161, R-A2L-DEF.163 |

The E3 private builder signature is `_build_occupancy_index(span_entries, is_array_entry, definitions_by_position, entry_cache)`. The candidate iterator and `_shared_with` signatures are unchanged. The private helper names are the E1 interface between requirements and the E2 graph, not public API. E2 may refine private types but must preserve the counted 4-node slice and 1 source file or record a ruled re-cut before implementation; the corrections for E3-INC1-01 and E3-INC1-02 preserve both.

## Unchanged code inside the owner file

| Existing symbol | Disposition and reason |
|---|---|
| `describe_definition` | unchanged public delegation at `a2l_definition.py:588-607` |
| `describe_definitions.walk` | unchanged section preorder and `span_entries` collection at `:644-732`; position assignment remains its source |
| `describe_definitions.describe_name` | unchanged requested/on-demand definition cache at `:745-767` |
| `describe_definitions.axis_span` | unchanged final AXIS_PTS length resolution at `:778-810` |
| `describe_definitions.materialize` | unchanged lazy final-span conversion at `:832-850` |
| `describe_definitions.mask_of` | unchanged clean-mask and fail-closed behavior at `:852-863` |
| `entry_cache` | unchanged cache key is entry position at `:830-850` |
| `_entry_overlaps` | unchanged inclusive final-span/point predicate at `:3818-3834` |
| `_pair_exempt` and `_selected_bits` | unchanged mask exemption and bit selection at `:3760-3815` |
| `s19_app/tui/a2l.py` and all parser modules | unchanged and outside the increment's ownership |

No existing test is edited to weaken an expectation. Planned new test files are `tests/test_alp_a2l_occupancy.py`, `tests/test_alp_a2l_occupancy_perf.py` and `tests/test_alp_a2l_occupancy_at.py`; tests do not count toward the source cap.

## Public consumers and blast radius

The executed AST census found 4 direct production calls of the two public describe functions:

1. `s19_app/tui/a2l_definition.py:607` — the single-name public function delegates to the batch function.
2. `s19_app/tui/a2l_parameter_picker.py:629` — picker population calls the batch function once per changed generation.
3. `s19_app/tui/app/patch.py:393` — patch edit describes one definition.
4. `s19_app/tui/app/patch.py:458` — patch event validation describes one definition for comparison.

The census also records all seven production modules importing `a2l_definition`. Only the public describe behavior reaches this increment; decode/encode interfaces, field order and refusal texts do not change. R-PICKER-CORRECT.018 and R-PICKER-CORRECT.019 therefore remain regression pins rather than new picker work.

## Occupancy-symbol reverse census

The direct AST census of `a2l_definition.py` found:

| Symbol | Count | Current role |
|---|---:|---|
| `span_entries` | 5 | initialized once, appended on three object-kind branches, assigned to the global route |
| `span_index` | 6 | initialized, assigned per result, passed to `_shared_with`, read by its candidate routes |
| `entry_cache` | 5 | initialized and used for position-keyed lazy materialization |
| `materialize` | 5 | defined, passed to `_shared_with`, called for each visited candidate |
| `describe_name` | 4 | defined and used for requested names, arrays and mask lookup |
| `_shared_with` | 2 | definition and its one caller |
| `_entry_overlaps` | 2 | definition and its one caller |
| `_pair_exempt` | 2 | definition and its one caller |

Every occurrence with line and load/store/definition kind is in `census.json`; the table is not a hand-maintained substitute for that full list.

## Shared contracts with later increments

- INC 2 receives unchanged describe signatures, immutable `Definition` values and current shared-section behavior; it owns post-parse worker responsiveness, not this index.
- INC 3 receives the same prepared-load interface and no second occupancy implementation.
- Existing batch-103 Inc 2 and Inc 3 graphs remain semantic references only. Their superseded page-expansion and eager-candidate mechanisms are not implementation input.
- The current batch's INC 2 and INC 3 directories are not edited by this increment.

## E2/E4 obligations

E2 writes only a delta against `codewire/graph-baseline.md`, with one concrete example for every new requirement and the four slice nodes assigned to the single source group. It must pin the compact interval types, conservative handling of unresolved final spans, position-aware self exclusion, instrumentation seams and no-gather/no-sort oracle before code. E4 implements from that graph and executes every planned negative control. E5 runs the 160-function preserved census, targeted law guards and the real acceptance cases; no unexecuted arm may be reported as PASS.
