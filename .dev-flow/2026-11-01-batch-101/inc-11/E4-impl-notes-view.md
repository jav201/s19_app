# Inc 11 — E4 implementer notes (G2 Issues view)

Unit: G2 Issues view. Files: `s19_app/tui/issues_view.py`, `s19_app/tui/app.py`.
Scope implemented exactly as `E1-slice.md`, `codewire/graph-inc11.md` and the
binding rulings (`E1-rulings.md` §4 OR-1/OR-2, `E3-rulings.md` A-5/S-5) state.

## Changed per file

### s19_app/tui/issues_view.py

- `issues_view:module docstring` — removed the Batch-94 Inc-004 triage paragraph
  (the `CURATED_STANDARD_A2L_BLOCKS` / reclassification description).
- `issues_view:imports` — removed `import re`, `from dataclasses import replace`,
  and `Iterable` from the `typing` import; `Optional` kept (used by `IssueRow`).
- `issues_view:CURATED_STANDARD_A2L_BLOCKS` — removed.
- `issues_view:A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION` — removed.
- `issues_view:_UNRECOGNIZED_BLOCK_RE` — removed.
- `issues_view:a2l_reclassified_severity` — removed.
- `issues_view:adjust_counts_for_a2l_triage` — removed.
- `issues_view:GroupedIssuesPanel.render_groups` — changed: groups
  `window_issues` by `issue.severity` as given (no classification, no
  `dataclasses.replace`, no justification `Static`); header counts stay
  `group_counts` verbatim; the cap and the truncation note are unchanged.
  Docstring loses the Inc-004 paragraph and the removed-name references in
  Args / Data Flow / Dependencies.

### s19_app/tui/app.py

- `app:import block` — dropped `adjust_counts_for_a2l_triage`, added
  `SEVERITY_ORDER` from `.issues_view`.
- `app:_ISSUE_DISPLAY_RANK` — new module constant:
  `{severity: rank for rank, severity in enumerate(SEVERITY_ORDER)}`, i.e.
  `ERROR → 0`, `WARNING → 1`, `INFO → 2`. Placed beside
  `_A2L_ISSUE_SEVERITY_RANK` with a docstring noting the contrast (E3 A-5/S-5).
- `app:S19TuiApp.update_validation_issues_view` — `severity_counts` is the
  plain per-severity count dict of `self._validation_issues` (no wrapper);
  the Inc-004 docstring sentence and the count-triage comment are removed.
- `app:S19TuiApp._render_validation_issues_groups` — `group_counts` is the
  plain per-severity count dict of `filtered` (no wrapper); the Inc-004
  comment is removed.
- `app:S19TuiApp._filtered_validation_issues` — the filter-mode selection is
  unchanged, then the returned list is
  `sorted(filtered, key=lambda issue: _ISSUE_DISPLAY_RANK.get(issue.severity, len(SEVERITY_ORDER)))`
  (stable; ERROR 0, WARNING 1, INFO 2, any other severity — OK, NEUTRAL —
  ranks after INFO via the default `len(SEVERITY_ORDER)`), applied for every
  filter mode.

## Deviations from the graph

None. The graph pins `_ISSUE_DISPLAY_RANK`'s name and its construction from
`issues_view.SEVERITY_ORDER` but not its source location; it was placed at
module level next to `_A2L_ISSUE_SEVERITY_RANK`, which the graph itself cites
as the contrasting rank map (`app.py:733`). The sort key expression is the
graph's exact form. No layout change; both files kept their CRLF line endings.

## Verification

- `python -m py_compile s19_app/tui/issues_view.py` → OK (exit 0).
- `python -m py_compile s19_app/tui/app.py` → OK (exit 0).
- `grep` confirms no remaining reference to the five removed symbols
  (`CURATED_STANDARD_A2L_BLOCKS`, `A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION`,
  `_UNRECOGNIZED_BLOCK_RE`, `a2l_reclassified_severity`,
  `adjust_counts_for_a2l_triage`) in either file.
- Line endings verified CRLF (0 lone LF, 0 lone CR) in both files.

pytest and `import s19_app` were not run (operator rule).
