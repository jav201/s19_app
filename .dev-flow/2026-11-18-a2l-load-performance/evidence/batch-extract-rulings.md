# Batch end — E2 extraction ruling (layered, whole batch)

Run: Code-Wire v3.2 tools against a clean clone at `f34b998d`, layered graphs
(baseline → inc1 → inc2 → inc3), path `s19_app`. Transcripts:
`evidence/batch-extract.txt/diff-report.md` + `extract.json`.

Marks 23, graph nodes 26, real calls between marked nodes 18,
findings 8. All findings ruled INFO — zero real drift:

| Finding | Ruling |
|---|---|
| 3 graph nodes "without code" (FileLoadRequest, ProjectLoadRequest, PreparedProjectLoad) | INFO — entity-shape declarations in the graphs; the classes exist in the code (file_load.py:123, project_load.py:85, project_load.py:109). The marks tool only places marks on module+name nodes; shape entities are never marked. No action. |
| mask_of input mismatch: graph `Callable[[str], int\|None]` vs code `Callable[[str], Optional[int]]` | INFO — type-normalisation artifact; semantically identical. No action. |
| 2 default-value mismatches (a2l_parameter_picker.py:590): graph "None (keyword-only)" vs code "None" | INFO — keyword-only is a graph call-mode annotation, not a type or default difference. No action. |
| Parse error `tools/mutation_harness.py:190` (f-string backslash) | INFO — pre-existing file outside the slice and outside `s19_app/`; never touched by this batch. No action. |
| 2 nodes replaced by a later graph (describe_definitions, _shared_with) | INFO — expected layering; replacement content identical in shape. No action. |

The extraction confirms the implemented tree matches the layered graph: all 18
real call edges land between marked nodes, and every marked node is present
in the source.
