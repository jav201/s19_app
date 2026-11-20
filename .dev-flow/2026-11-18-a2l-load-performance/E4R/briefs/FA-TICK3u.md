# Unit FA-TICK3u — the validation name loop sorts in slices; the dedupe frees its key set in slices [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`e53631df`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx). No agent edits `~/.claude/skills`. **Append to `../REPORT.md` after EACH row** (a row not in REPORT.md does not exist).

## Fixed diagnosis (FA-TICK3 report, measured; facts re-grepped at e53631df, HT-13)
- On case_06 the in-window UI tick (R-A2L-REFRESH.050, 0.10 s) is late at two worker sites, both pre-existing code identical on `main`:
  - `s19_app/validation/engine.py:151` `for lowered_name in sorted(all_names):` inside `validate_artifact_consistency` (:21): one C-level `sorted()` over ~220 k names holds the GIL 0.091–0.097 s (laptop: ~0.148 s).
  - `s19_app/tui/app/issues_checks.py:114` `_deduplicate_issues`: when it returns (`return deduped`, :132) its local `seen` set (~419 k 7-tuples on case_06) is freed in one C-level dealloc, 0.066–0.071 s.
- Order-identical fix, measured in scratch (0 late ticks; output digests identical on 12+12 real runs and 56 offline cases): **the product change is fixed** — it is the FA-TICK3 scratch diff (`frontA/diffs/FA-TICK3-scratch.diff` in the orchestrator's review folder, outside the repo), copied to `../FA-TICK3-scratch.diff`. Apply it as is (`git apply ../FA-TICK3-scratch.diff`); do not change product code beyond it.
  - `release_in_slices` is `s19_app/tui/a2l_definition.py:51` (empties lists, dicts and sets in 4096-item steps; raises `TypeError` on other types). `issues_checks.py` imports it (app → domain module, as `file_load.py` and `services/a2l_service.py` already do).
  - `engine.py` gets its own `SORT_SLICE = 4096` and `_sorted_in_slices` (slice sorts + `heapq.merge`): `s19_app.validation` must not import `s19_app.tui`.
- No existing test pins the order of the cross-artifact issues (FA-TICK3 grep); row 2 adds the pin.

## Requirement row
R-A2L-REFRESH.050: "While the system performs post-parse preparation for an image+A2L or project load, the system shall fire each due 50 ms UI timer tick no more than 100 ms late."

## Files you may edit
`s19_app/validation/engine.py` and `s19_app/tui/app/issues_checks.py` (only by applying the diff), `tests/test_alp_a2l_occupancy.py` (new test functions after FA-TICKb's `test_r_a2l_refresh_050_producer_frees_private_containers_before_return`, ~:639). No new test module (so TC-607's `EXPECTED_SCANNED_TEST_FILES` stays as is).

## Rows
| row | change | negative control (scratch copy of the tree) → RED |
|---|---|---|
| 1 | Apply the diff. New test `test_r_a2l_refresh_050_validation_sorts_names_in_slices`: build `mac_records` and `a2l_tags` (plain dicts, read `validate_artifact_consistency`'s docstring and `tests/test_validation_engine.py` for the field shapes) with > 2 × `engine.SORT_SLICE` distinct names, some only in A2L, some only in MAC, some in both with equal and with different addresses; `monkeypatch.setattr(engine, "sorted", spy, raising=False)` where `spy` records `len` of each input and returns `builtins.sorted(...)`; call `validate_artifact_consistency(...)`; assert every recorded length ≤ `engine.SORT_SLICE`. Docstring: why (one long `sorted()` starved the UI tick, FA-TICK3). | replace `_sorted_in_slices(all_names)` with `sorted(all_names)` → RED |
| 2 | Same file, `test_r_a2l_refresh_050_validation_issue_order_unchanged`: same kind of input; assert the `symbol` sequence of the `CROSS_A2L_ONLY_SYMBOL` / `CROSS_MAC_ONLY_SYMBOL` / `TRIPLE_NAME_ADDRESS_MISMATCH` issues equals the order produced by iterating `sorted(all lowered names)` (compute the expected list in the test from the inputs), and the `coverage` counters equal those of a run with `engine._sorted_in_slices` monkeypatched to `lambda names: iter(sorted(names))`. | replace `heapq.merge(*runs)` with `itertools.chain(*runs)` → RED |
| 3 | Same file, `test_r_a2l_refresh_050_dedupe_frees_its_key_set_before_return`: build ≥ 10 000 `ValidationIssue` objects with duplicates; call `IssuesChecksMixin._deduplicate_issues` (read `issues_checks.py`; `self` is unused, so a minimal subclass instance or calling through the class with a dummy `self` is fine — say which); with `sys.setprofile`, at the `return` event of the `_deduplicate_issues` frame assert `frame.f_locals["seen"]` is empty; restore the profiler in `finally`. Also assert the result is the same objects in the same order as a run with `issues_checks.release_in_slices` monkeypatched to a no-op. | remove the `release_in_slices(seen)` call → RED |
| 4 | No code. Run the regression below and record it. | — |

## Nodes you may run (`timeout 300`)
- `-n 0`: the three new tests; `tests/test_alp_a2l_occupancy.py` whole file `-m "not slow and not serial_timing"`.
- `-n 4`: `tests/test_validation_engine.py tests/test_validation_service_supplemental.py tests/test_tui_services.py tests/test_examples_smoke.py tests/test_color_policy_round_trip.py tests/test_tui_directionb.py`.
- `-n 4`: `tests/test_synth_release_case.py` (3 failures are inherited: `test_a2l_zero_issues`, `test_addresses_inside_image`, `test_a2l_issues_reported`; any other failure is yours to report).
- `-n 4`: `tests/test_tui_app.py -k "valid or issue or dedup"` (`test_load_selected_file_attaches_mac_to_loaded_binary` is inherited RED if selected).
- `-n 0`: `tests/test_suite_hygiene.py -k "040 or 041 or 002"`; `tests/test_id_registry.py`.
- A failure you did not expect: re-run that node on a base clone (`git clone -q -b alp-e4r ~/work/zq-fa/fa.bundle ../scratch/base`) and record base vs yours.
- Never run a `slow` node; never run the full suite.
