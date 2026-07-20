# Functionality — batch-50 (a2l.py F841 cleanup + re-freeze)

## What changed (PR-A)
A single dead local variable was removed from the A2L tag-extraction walk in `s19_app/tui/a2l.py`. The line `header = header_meas or header_char` (former `:942`) bound a value that was never read — the surrounding code uses `header_meas` and `header_char` directly. Removing it clears the last `ruff --select F841` finding on the module. **No behavior changes**: a dead store has no observable effect, proven by a regression test asserting the demo A2L parses to byte-identical tag output.

A new test file `tests/test_a2l_f841_cleanup.py` pins both halves of the requirement: the lint is clean (`ruff F841` = 0) and the parse is unchanged (75 tags, MEAS length/datatype and the parsing CHARACTERISTIC's char_type/length all intact through the shipped `parse_a2l_file` surface). It lives in a non-frozen sibling because `tests/test_tui_a2l.py` is guard-frozen (TC-032 / C-27).

## Follow-up (PR-B, post-merge)
`a2l.py` was deliberately unfrozen by an earlier batch (PR #92) to allow a sanctioned parsing fix. Now that its last edit (this F841 cleanup) has landed, **P-2** re-adds `a2l.py` to the C-27 engine-frozen dual-guard set (`_ENGINE_PATHS` in both `tests/test_engine_unchanged.py` and `tests/test_tui_directionb.py`), restoring its read-only-oracle status. This must be a separate post-merge PR: the guards diff `a2l.py` against `main`, so re-freezing in the same PR that edits it would self-trip the guard until merge.

## Deferred (future batch)
**P-1b** (CURVE/MAP inline-axis length derivation) was descoped after Phase-2 review found it depends on a pre-existing prerequisite the tool lacks: the A2L parser only reads **single-line** CHARACTERISTIC/AXIS_DESCR headers, so on real multi-line A2L (including the bundled ASAM demo) the fields P-1b needs are never populated — the feature would fire on nothing. The future batch must add multi-line-header parsing first, then the length summer. A verified design seed (component-summer math, real oracle values 25 B / 51 B, the position-index insight, AT corrections) is retained in `01-requirements.md §7`.
