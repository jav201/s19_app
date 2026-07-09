# Increment 005 — Realize AT-043-c17 (file-derived C-17) · Phase-4 gap closure

**Scope:** Add the ONE missing black-box acceptance test the spec names (AT-043-c17,
`01-requirements.md` §3) and never realized as a single joined AT. 1 test file, no product code.

## 1. What changed

The C-17 literal-render invariant was previously proven only in parts: the retained seeded
`test_at_039e_c17_...` (`tests/test_tui_directionb.py`) drives a **constructed** hostile
`ValidationIssue`, and a service test proves the A2L parse leg — but nothing drove a **file-derived**
hostile symbol through the REAL load chain all the way to the grouped panel's rendered node. C-17
discipline requires the hostile input be file-derived, not constructed.

Added `test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal` to
`tests/test_tui_a2l_issue_recolor.py`, reusing that file's existing broken-REF fixture idiom
(`_BROKEN_REF_A2L`), its shipped-chain harness (`_drive_load` → `_parse_loaded_file` →
`_prepare_load_payload` → `_apply_prepared_load` → `update_validation_issues_view`), and its migrated
grouped-panel reader (`_issue_rows` / `query(IssueRow)`).

New module fixture `_HOSTILE_REF_A2L`: a GROUP with **two** hostile no-whitespace ghost-symbol REF
entries — `REF_MEASUREMENT MAP_Model[bold]` and `REF_MEASUREMENT x[link=file:///etc]` (qa M-1: a
single whitespace-delimited REF token can't carry spaces, so two separate tokens). Written to disk
and loaded through the real shipped chain. The test:
- opens the Issues screen, positively asserts both hostile tokens reached `issue.symbol` verbatim as
  `A2L_BROKEN_REFERENCE` issues (non-vacuous guard), then
- reads the mounted `IssueRow`s' `.issue-detail` node PLAIN text (`row.query_one(".issue-detail")
  .render().plain`) and asserts the run raised no `MarkupError` (reaching past mount proves it) and
  the literal `MAP_Model[bold]` (brackets intact) + literal `[link=file:///etc]` (token NOT
  consumed) both appear.

The seeded `test_at_039e_c17_...` is untouched (kept as the constructed companion + ANSI/code-field
coverage). The A2L colour oracle (`#a2l_tags_list`) is untouched.

## 2. Files modified
1. `tests/test_tui_a2l_issue_recolor.py` — new fixture `_HOSTILE_REF_A2L` (+ `_HOSTILE_MARKUP_REF` /
   `_HOSTILE_LINK_REF` constants) and new test `test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal`.

## 3. How tested
```
python -m pytest tests/test_tui_a2l_issue_recolor.py -q
python -m ruff check tests/test_tui_a2l_issue_recolor.py
python -m pytest tests/test_engine_unchanged.py -q
```

## 4. Result
- `tests/test_tui_a2l_issue_recolor.py`: **6 passed** (5 pre-existing + 1 new), 3.83 s.
- `ruff check`: **All checks passed!**
- `tests/test_engine_unchanged.py`: **1 passed** — 0 engine-frozen diffs.

## 5. Hostile tokens used + frozen-lexer preservation
Phase-3 probe (through `parse_a2l_file` → `validate_a2l_internal_issues`, the frozen `a2l.py` chain)
confirmed BOTH tokens round-trip VERBATIM into `issue.symbol` and `issue.message`:
- `MAP_Model[bold]` → `issue.symbol == 'MAP_Model[bold]'`, message `GROUP references unknown symbol 'MAP_Model[bold]'.`
- `x[link=file:///etc]` → `issue.symbol == 'x[link=file:///etc]'`, message `... 'x[link=file:///etc]'.`

Root cause it works: the broken-reference rule splits GROUP lines on whitespace
(`rules.py:497 raw.strip().split()`) and interpolates the token unmodified into both fields. No
fallback token was needed — the strongest hostile tokens the spec names are the ones exercised.

**Counterfactual (discriminator).** Verified in isolation that a markup-parsing node would fail both
asserts: `Text.from_markup('MAP_Model[bold]').plain == 'MAP_Model'` (bracket token consumed) and
`Text.from_markup('x[link=file:///etc]body[/link]').plain == 'xbody'` (link token consumed). So
under a markup-parsing detail node neither literal would survive → the test fails; only the shipped
`safe_text` build (issues_view.py:186) keeps them literal. The literal-bracket assertions are exactly
what discriminate the fix from the bug.

## 6. Ledger delta
Baseline **1182** (Inc4 tip). `test_tui_a2l_issue_recolor.py`: 5 → 6 = **+1** →
**1182 → 1183**. No other file changed.
