# Code-Wire extractor report

- Marks found: 1
- Graph nodes parsed: 18
- Real calls between marked nodes: 0
- Findings: 17 (17 drift, 0 info)
- Ambiguous call resolutions (a name matched several defs): 3
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Graph node without mark (no code yet) | 17 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|

Top-level sites (no marked node above them):

- `parse_a2l_file`: s19_app/tui/app.py:948, s19_app/tui/app.py:950, s19_app/tui/services/flow_execution_service.py:381, s19_app/tui/services/flow_execution_service.py:500, s19_app/tui/services/variant_execution_service.py:2665

## Graph node without mark (no code yet)

- `s19_app/tui/services/label_match.py` — `build_label_index`
- `s19_app/tui/services/label_match.py` — `rank`
- `s19_app/tui/services/label_match.py` — `LabelIndex.__len__`
- `s19_app/tui/services/label_match.py` — `_fold`
- `s19_app/tui/services/label_match.py` — `_char_mask`
- `s19_app/tui/services/label_match.py` — `_tokens`
- `s19_app/tui/services/label_match.py` — `_allowed_edits`
- `s19_app/tui/services/label_match.py` — `_prefix_distance`
- `s19_app/tui/services/label_match.py` — `_join_spans`
- `s19_app/tui/services/label_match.py` — `_at_boundary`
- `s19_app/tui/services/label_match.py` — `_subsequence`
- `s19_app/tui/services/label_match.py` — `_parse_query`
- `s19_app/tui/services/label_match.py` — `_classify`
- `s19_app/tui/services/label_match.py` — `_order_key`
- `s19_app/tui/services/label_match.py` — `_token_range`
- `s19_app/tui/services/label_match.py` — `_build_trie`
- `s19_app/tui/services/label_match.py` — `_fuzzy_token_distances`
