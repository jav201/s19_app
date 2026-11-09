# Inc 12 — E5 mutant driver handoff (DeepSeek v4 Pro)

Work only in `b103-inc12-code`, and only create files under `inc-12/mutants/` plus `inc-12/E5-mutants-handoff.md`. Do not edit product, tests or capture drivers. Build a mechanical mutation runner; do not execute mutations on Windows.

The orchestrator will run it on Linux against the integrated commit. The runner must take the integrated checkout and an output directory, copy the tree to a fresh isolated directory, verify the green baseline with the selected test nodes, then apply exactly one textual mutation at a time. Every anchor must match exactly once on reachable product code; zero matches or multiple matches = BAD, not SURVIVED. Set `PYTHONDONTWRITEBYTECODE=1`, use `python -I -B`, insert the mutant checkout at `sys.path[0]`, print `s19_app.__file__`, isolate HOME/XDG/LOCALAPPDATA under `zq_iso_user`, close stdin, and restore/verify source bytes after each arm. Classify KILLED / SURVIVED / CRASH / BAD from each pytest exit code, assert the expected arm count before running, and emit one transcript per arm plus a machine-readable summary. Never mutate the real worktree.

Minimum table; use the narrowest discriminating nodes from `tests/test_b103_inc12_tag_table.py` and `tests/test_tui_a2l_detail.py`:

1. `cell_padding=0` → R-TUI-042a.2/1,/2.
2. `fixed_columns=0` → .4/2.
3. Fixed 34-cell cap ignoring measured width → .5/1,/3,/5.
4. No Tag cap → .3/1,/2,/3.
5. No post-page-build fit → .5/8,/9.
6. No table `Measured` resize fit → .5/6.
7. `_repaint_a2l_tag_cells` omits `name_width` → .5/7 (the E3A-18 Save-project route).
8. Restore raw-name `.replace("\n", " ").strip()` → .6/3's `A ` arm.
9. E2 raw-name cell-length loop → .6/1 zero-width tail exceeds the hard 1 s bound (use the smallest already specified input that discriminates; no 33 s hang on the orchestrator).
10. Raw header `Text.append` → .7.1/1,/2.
11. Raw `_card_field` value append → .7.1/3 and /7.
12. Raw unit append → .7.1/4.
13. Raw conversion append → .7.1/5.
14. Raw lower/upper limit append → .7.1/6.
15. Name line built without `_card_value_text` → .7.1/7.
16. Remove break-run mapping (bare `safe_text`) → .7.2/1,/2.
17. Remove the Name line → .8/1.
18. Tag cell uses `Text.from_markup` → AT-069c.
19. Card scrub only ESC and U+009B → .7.1 retains U+009D/U+0090.
20. Card scrub omits DEL → .7.1 retains DEL.

For each arm record the requirement/case it makes wrong, the exact node(s), result and evidence path. A green baseline alone is not proof: at least one known-bad arm must be KILLED before the runner's PASS results are believed. Do not count a non-applied mutation, collection error or fixture error as a kill. Do not weaken assertions to obtain kills.

On Windows run only `python -m py_compile` on the driver. Commit the driver and this handoff as `batch-103 Inc 12 E5: mutation runner` with `Co-Authored-By: DeepSeek V4 Pro`; do not commit generated mutant trees or results yet. Report usage and any arm that cannot be realised faithfully.
