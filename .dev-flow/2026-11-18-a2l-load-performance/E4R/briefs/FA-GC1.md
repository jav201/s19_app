# Unit FA-GC1 — break the `walk` closure cycle in `describe_definitions` [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`35d69a03`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

## Fixed diagnosis (DX-F3; the code was re-checked by the architect)
- `s19_app/tui/a2l_definition.py:644-731` defines `walk`, a recursive closure: its cell refers to the function itself. Everything it captures therefore stays alive until a cyclic collection:
  - `span_entries`;
  - the per-name lists of `object_sections_by_name` / `tags_by_name`, and so on.
- On case_06 that is about 880 k lists + 440 k tuples per describe.
- DX measured a scratch copy with `walk = None` added after the call at `:732`: cyclic garbage falls from 1,320,331 to 45 objects.

## Files you may edit
`s19_app/tui/a2l_definition.py`, `tests/test_alp_a2l_occupancy.py`.

## Rows
| row | change | negative control |
|---|---|---|
| 1 | Right after `walk(a2l_data.get("sections") or [], None)` (`:732`), add `walk = None` with a one-line comment: break the closure self-cycle so describe leaves no cyclic garbage (R-A2L-REFRESH.053, DX-F3). Grep first: if any later code in `describe_definitions` calls `walk`, STOP and report. | covered by row 2 |
| 2 | New test `test_r_a2l_refresh_053_describe_leaves_no_cyclic_garbage` in `tests/test_alp_a2l_occupancy.py`. Build an 8,000-object pairwise-disjoint A2L the way `test_r_a2l_def_161_1` does (`characteristic(...)` + `inline(tmp_path, *blocks)` from `tests/support/b103_a2l_arrays.py`, address `0x1000 + i·0x40 + (i%7)·4`). Then: `gc.collect(); gc.disable()`; `try: describe_definitions(all_names, a2l)` then `n = gc.collect()`; `finally: gc.enable()`. Assert `n < 1000`. Docstring cites R-A2L-REFRESH.053 (E4R). No wall-clock bound, so no `serial_timing`. | Scratch: delete the row-1 line → RED with n ≈ 3 × 8,000 (paste the number) |

## Nodes you may run (`timeout 300`)
- `tests/test_alp_a2l_occupancy.py -n 4`;
- `tests/test_alp_a2l_occupancy_at.py -n 4 -m "not slow and not serial_timing"`;
- `tests/test_b103_a2l_definition.py -n 4 -m "not serial_timing"` (regression, no edits).
