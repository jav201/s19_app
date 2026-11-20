# Unit FA-TICKb — the shared producer frees its private containers in slices before return [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`b5bc470b`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx). No agent edits `~/.claude/skills`. Another unit (FA-TICKac) runs in parallel on other files; never touch files outside your list.

## Fixed diagnosis (FA-TICK report, measured on the quiet reference host; facts re-grepped at b5bc470b, HT-13)
- When `describe_definitions` (`s19_app/tui/a2l_definition.py:611`, `return result` at :894) and `enrich_tags_and_render` (`s19_app/tui/services/a2l_service.py:10`, `return merged, summary_lines` at :27) return, the frame teardown frees their large private containers in one C-level dealloc each, holding the GIL: case_06 return→resume gap 0.151–0.193 s (enrich) and 0.177–0.193 s (describe), N=3, collector disabled as in the worker. That starves the 50 ms UI tick inside the R-A2L-REFRESH.050 window on every route.
- Per-local costs (FA-TICK): enrich `source_tags` 0.085 s, `check_map` 0.082 s; describe `definitions` (held by the `describe_name` closure) 0.075 s, `index` 0.034 s, `span_entries` 0.018 s, `tags_by_name` 0.013 s, `object_sections_by_name` 0.013 s.
- Emptying those containers in steps of 4096 items just before `return` removed the late ticks in a scratch copy (attach 0 late ticks, N=3).
- **Privacy of each container (checked):**
  - enrich: `source_tags` is the fresh list of fresh dicts that `enrich_a2l_tags_with_values` builds (`a2l.py:4100-4168`, one `return enriched`); `checked_tags` is the fresh `results` list of `validate_a2l_tags` (`a2l.py:4784-4834`, one `return results`); `check_map` is built here. `merged` holds new dicts (`{**tag, **check}`), never these containers.
  - describe: `definitions` (:744), `definitions_by_position` (:867), `span_entries` (:643), `tags_by_name` (:629, lists built here; the tag dicts inside belong to `a2l_data` and survive), `object_sections_by_name` (:633), `entry_cache` (:832) are built in the function; `index` (:875) is the request-local `_OccupancyIndex` NamedTuple (:3852), never returned.
  - **Never** pass a container read from `a2l_data` (`a2l_data[...]`, `record_layouts` :638, `declared_spans` :639) or `result`.
- Frozen contract 7 (PLAN.md): `s19_app/tui/a2l.py` is not edited. Contract 1: `describe_definitions` keeps its signature and one result per requested name.

## Requirement row
R-A2L-REFRESH.050: "While the system performs post-parse preparation for an image+A2L or project load, the system shall fire each due 50 ms UI timer tick no more than 100 ms late."

## Files you may edit
`s19_app/tui/a2l_definition.py`, `s19_app/tui/services/a2l_service.py`, `tests/test_alp_a2l_occupancy.py`, `tests/test_alp_inc3_load_responsiveness.py`.

## Rows
| row | change | negative control (scratch copy) → RED node |
|---|---|---|
| 1 | In `a2l_definition.py` (module level, near the other helpers), add `RELEASE_SLICE = 4096` and `def release_in_slices(*containers) -> None`: for each argument, a `list` is emptied with `while c: del c[-RELEASE_SLICE:]`; a `dict` is emptied with `while c:` + up to `RELEASE_SLICE` `c.popitem()` calls per step; any other type raises `TypeError`. Docstring (≤ 6 lines): why (one C-level free of a large container holds the GIL; slices let the UI thread run between steps; R-A2L-REFRESH.050, FA-TICK); callers pass only containers they built. | n/a (rows 2–3 controls) |
| 2 | In `describe_definitions`, just before `return result`: `release_in_slices(definitions, definitions_by_position, span_entries, tags_by_name, object_sections_by_name, entry_cache, *(f for f in index if isinstance(f, (list, dict))))`, with a one-line comment (private containers only; R-A2L-REFRESH.050). | delete the call → row 4 `describe` arm RED and row 5 `describe` arm RED |
| 3 | In `a2l_service.py`, import `release_in_slices` from `..a2l_definition`; in `enrich_tags_and_render`, just before the final `return merged, summary_lines`: `release_in_slices(source_tags, checked_tags, check_map)`, same comment. Leave the early `return [], []` alone. | delete the call → row 4 `enrich` arm RED and row 5 `enrich` arm RED |
| 4 | New test in `tests/test_alp_a2l_occupancy.py`: `test_r_a2l_refresh_050_producer_frees_private_containers_before_return`, parametrized `["describe", "enrich"]`, `ids=["R-A2L-REFRESH.050/1", "R-A2L-REFRESH.050/2"]` (not `slow`, not `serial_timing`). Fixture: the generated 8,000-object pairwise-disjoint A2L that `test_r_a2l_def_161_1` builds, parsed with `parse_a2l_file`; `enrich` gets a mem map covering the addresses (or `{}`). Oracle (deterministic):<br>- (i) with `sys.setprofile` on the calling thread (restored in `finally`), at the `return` event of the target function's frame, record `len()` of each released local from `frame.f_locals` (describe: the six names of row 2; enrich: the three of row 3): all are 0;<br>- (ii) equality: the function's result with the release active equals its result with `release_in_slices` monkeypatched to a no-op in the module that calls it (describe: whole dict `==`; enrich: `merged == merged` and `summary_lines == summary_lines`);<br>- (iii) `a2l_data["tags"]` keeps its length and the first/last tag dicts compare equal before and after.<br>Failure messages name R-A2L-REFRESH.050 and the local that stayed full. | rows 2/3 controls |
| 5 | New test in `tests/test_alp_inc3_load_responsiveness.py`: `test_r_a2l_refresh_050_case06_producer_return_gap`, parametrized `["describe", "enrich"]`, `ids=["R-A2L-REFRESH.050/3", "R-A2L-REFRESH.050/4"]`, marked `slow` and `serial_timing`. Parse case_06 (`CASE06`, `parse_a2l_file`) once per param; with `gc.disable()` (re-enabled in `finally`, as the worker does) call the function directly on the main thread (describe: all tag names; enrich: case_06 A2L with `CASE06_IMAGE`'s mem map via the file's existing loaders, or `{}` if none is at hand — say which in REPORT.md). Measure the gap from the `return` profile event of its frame (`sys.setprofile`) to the caller's next statement (`time.perf_counter()` in both). Assert `gap <= report_margin(label, gap, timing_bound(0.05))` (law 002 census: a `serial_timing` arm asserts through `report_margin`/`timing_bound`). Docstring: FA-TICK baseline 0.151–0.193 s. | rows 2/3 controls: RED indicative on rtx (the baseline gap is 3× the bound) |

## Nodes you may run (`timeout 300`)
- `-n 0`: the row 4 params; the row 5 params (named here; `slow`; about 30–60 s each on rtx; GREEN is "indicative, not decided");
- `-n 4 -m "not serial_timing and not slow"` on `tests/test_alp_a2l_occupancy.py`;
- `-n 4`: `tests/test_alp_inc3_snapshot_parity.py -m "not serial_timing and not slow"` (the producer's parity/equality nodes);
- `-n 4`: `tests/test_b103_a2l_refresh.py` and every other test file that `grep -l "describe_definitions\|enrich_tags_and_render" tests/*.py` lists, `-m "not serial_timing and not slow"`, one file per call if a call would exceed 300 s;
- `-n 0`: `tests/test_suite_hygiene.py -k "040 or 041 or 002"` (marker/timing census after the new arms).
- Never run another `slow` node.

## Known REDs that are not yours
`test_r_a2l_refresh_050_small_routes_same_oracle[image]`, `[project-pair]` (in-window late ticks on rtx; not decided here; do not run them).
