# Inc 4 — E4 implementer notes (variant execution unit)

Unit: G2 `variant_execution_service.py` node `_execute_one_variant` (R-CHG-SYM.11, R-CHG-SYM.12).

## Functions changed per file

- `s19_app/tui/services/variant_execution_service.py`:
  - `_execute_one_variant`
    - The per-file read now passes the project's A2L as the declared A2L:
      `read_change_document(str(file_path), project_dir)` →
      `read_change_document(str(file_path), project_dir, a2l_context=a2l_data)`.
    - `a2l_data` is the parameter `_execute_one_variant` already receives from
      `execute_variant_plan`, parsed once from the project's A2L file
      (`a2l_path`); `None` when the project has none (R-CHG-SYM.12).
    - Docstring only: the `a2l_data` Args line now records its second role as
      the declared A2L for each per-file change/check document read, and the
      Data Flow line names the new keyword.

## Deviations from the graph

None. The code change is exactly the graph's `func:` for `_execute_one_variant`
(`a2l_context=a2l_data`, nothing else changed). The only addition is the two
docstring lines (Args + Data Flow) to keep the docstring accurate under the
project's fixed section-order convention; the graph's "nothing else changes"
concerns behaviour, and no signature, caller, or line outside this unit was
touched. `_resolve_manifest_entry`, `plan_variant_executions`, and
`execute_variant_plan` were not modified.

## py_compile result

`python -m py_compile s19_app/tui/services/variant_execution_service.py` → OK
(exit 0). Line endings preserved as CRLF (`file` reports CRLF before and after).
