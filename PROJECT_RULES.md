# Project Rules: Documentation and Function Design

This document defines how functions are documented and how functions should be structured so data flow stays clear and code remains easy to maintain.

## Scope

- Apply to all module-level functions and all public class methods.
- Apply to private helpers when they are non-trivial, reused, or contain invariants.
- Treat this as the default standard for all new and modified code.

## Function Docstring Contract

Use this fixed section order for consistency.

1. Summary
2. Args
3. Returns
4. Raises (if relevant)
5. Data Flow
6. Dependencies
7. Example (when needed)

### Required Content by Section

- **Summary**
  - One sentence in domain terms: what the function achieves.
- **Args**
  - Name, type, expected shape, units when relevant (address, byte length, offset).
- **Returns**
  - Type and meaning. For dictionaries/lists, describe the expected keys/structure.
- **Raises**
  - Include only contract-level or non-obvious exceptions.
- **Data Flow**
  - 2-5 bullets that show major transformations from input to output.
  - Focus on meaningful state changes, not every line.
- **Dependencies**
  - `Uses`: direct helper functions/modules called.
  - `Used by`: architecturally important callers (best-effort, not exhaustive).
- **Example**
  - Required when behavior is non-obvious or output structure is nested/complex.

### Used By Policy

`Used by` is intentionally best-effort. Document primary call paths and integration points, then rely on IDE reference tools for exhaustive usage.

## Docstring Template

```python
def function_name(arg1: Type1, arg2: Type2) -> ReturnType:
    """
    Summary:
        One-line domain summary of what this function does.

    Args:
        arg1 (Type1): Meaning, expected shape, and units if relevant.
        arg2 (Type2): Meaning and constraints.

    Returns:
        ReturnType: Meaning of the returned value and structure details.

    Raises:
        ValueError: When input is invalid in a contract-relevant way.

    Data Flow:
        - Normalize and validate incoming values.
        - Transform source structure into internal canonical form.
        - Aggregate or map canonical form into final output.

    Dependencies:
        Uses:
            - helper_a
            - helper_b
        Used by:
            - important_entrypoint
            - ui_or_cli_adapter

    Example:
        >>> function_name(sample_a, sample_b)
        expected_result
    """
```

## Inline Comments vs Docstrings

- Use docstrings for API contract, I/O meaning, dependency notes, and transformation overview.
- Use inline comments only for non-obvious rationale, invariants, or format edge cases.
- Do not narrate obvious code behavior with line-by-line comments.

## Function Granularity and Single Responsibility

Functions should be unitary: one purpose, one reason to change.

### Split Triggers

Refactor by extraction when one or more triggers appear:

- Roughly 40-60 logical lines and growing.
- Multiple nested loops/branches that represent separate stages.
- Three or more distinct side effects in one function (for example: file I/O, mutation, UI update).
- Mixed responsibilities (parse + validate + render in one block).

### Preferred Data-Flow Shape

Favor explicit pipelines at call sites so transformations are easy to trace.

```python
sections, parse_errors = build_section_tree(path)
segments = extract_memory_segments(sections)
tags = extract_a2l_tags(sections)
validated_tags = validate_a2l_tags(tags, mem_map)
```

## Private Helper Policy

- Private helpers (`_name`) may use minimal docstrings when trivial and local.
- Use full docstring sections when a helper:
  - Is reused in multiple places, or
  - Encodes non-obvious parsing/validation rules, or
  - Carries assumptions that can break callers if changed.

## Type Hints and Docstring Consistency

- Type hints are mandatory for new/updated functions.
- Args/Returns docstring types must align with annotations.
- Document dictionary/list schema in words when return types are container-heavy.

## Project-Specific Priorities

When touching these files, prioritize richer data-flow documentation and decomposition:

- `s19_app/tui/a2l.py`
  - `parse_a2l_file`
  - `extract_a2l_tags`
  - `validate_a2l_tags`
- `s19_app/tui/hexview.py` transformation pipeline functions.
- `s19_app/tui/app.py` large methods in `S19TuiApp` should be gradually decomposed into smaller, named helpers.

## Reference Example (Style Baseline)

Use this style for dense data transformations:

```python
def parse_a2l_file(path: Path) -> dict:
    """
    Summary:
        Parse an A2L file into structured sections, segments, and tag metadata.

    Args:
        path (Path): File path to the A2L source text.

    Returns:
        dict: Parsed payload with section tree, memory segments, tag entries, and parse errors.

    Data Flow:
        - Read text and build hierarchical /begin.../end section tree.
        - Extract memory-segment definitions from section nodes.
        - Derive tag records from measurement/characteristic blocks.
        - Package sections, segments, tags, and errors into a single result payload.

    Dependencies:
        Uses:
            - build_section_tree
            - extract_memory_segments
            - extract_a2l_tags
        Used by:
            - S19TuiApp A2L load actions
            - A2L rendering and validation flow
    """
```

## Adoption and Rollout Policy

- New functions and changed functions must follow this standard immediately.
- Legacy untouched functions are upgraded when they are modified for feature, bug, or refactor work.
- Refactors should stay scoped: improve structure without changing behavior unless behavior change is explicitly required.
- Prefer iterative extraction over one-shot rewrites for large modules.

## Definition of Done for Function Updates

A function update is complete when:

- Docstring follows required section order.
- Input/output meaning is clear and matches type hints.
- Data Flow section captures key transformations.
- Dependencies include important `Uses` and best-effort `Used by`.
- Function has one clear objective, or decomposition has started with named helpers.
