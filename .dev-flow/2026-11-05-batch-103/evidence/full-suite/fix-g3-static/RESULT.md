# G3 static fixes — directed verification

Date: 2026-11-16T18:02:47-06:00
Base: `35fabb25c42d752216433c095eb0d29024027294`
Branch/worktree: `b103-g3-static-fixes`

## Scope

Only the six confirmed static defects were changed:

- `tests/test_b103_winci_gate.py`: known-bad raw/prefix artifacts are encoded and written as bytes, preserving CR, LF and CRLF on Windows.
- `tests/test_b103_clipboard_core.py`: the census pins are 42 `OsClipboardInput` and 50 total boxes for `#patch_sheet_input`; stock `Input` and editable stock `TextArea` remain pinned at zero.
- `evidence/full-suite/run_distributed.py`: XDG and local-application directories moved from `isolation/home/{config,data,cache,local}` to `isolation/{config,data,cache,local}`. HOME, path validation and source-tip guards are unchanged.
- `tests/test_b103_a2l_reader.py` and `tests/test_b103_a2l_reader_coverage.py`: text fixtures are written as exact UTF-8 bytes. The coverage newline cases reuse the first module's `_parse`/`_file` helper.
- `s19_app/tui/a2l.py`: only the unused `n = len(body)` in `_find_string_end` was removed.
- `s19_app/tui/definition_sheet.py`: `_submit_stage` retains its lazy UI-only construction and exact `StagingSheet.StageRequested` contract through `importlib`; the AST static-import edge to Textual is gone.

## Execution conditions

Windows, Python 3.12.7, Textual 8.2.8. Every pytest reproduction used `-I -B -X utf8 -n 0 -p no:cacheprovider`, closed stdin, `PYTHONDONTWRITEBYTECODE=1`, UTF-8 settings, and separate HOME/XDG/LOCALAPPDATA/TMPDIR roots below `<OUT>`. `GITHUB_ACTIONS`, `RUNNER_ENVIRONMENT` and `CI` were unset. No local WinCI probe was forced and no real clipboard route was enabled. Raw logs remain outside every clone/worktree under `<OUT>`; their local paths are intentionally not copied here.

## Directed results

- WinCI known-bad forms and artifact censuses: **181 passed, 33 deselected**. This runs every known-bad canary form, including all ten currently registered raw/prefix RED nodes, plus both census cases.
- Clipboard text-box censuses: **3 passed**. Observed contract: 42 OS clipboard inputs, 8 capped/highlighted multi-line boxes, 50 total, 0 stock `Input`, 0 editable stock `TextArea`.
- A2L newline groups: **7 passed** across the four named test functions (LF/CR/CRLF/mixed and line-comment terminators). The separate coverage writer sentinel `test_cov_read_56_cap_and_views`: **1 passed**.
- Static import graph plus `test_tc094_no_f841_finding_in_a2l`: **2 passed**.
- Formula-sheet behavior after the lazy-import change: **27 passed**.
- Distributed-runner self-test: **PASS** for static POSIX-path/source-tip controls, the complete fixture, and all five known-bad aggregator fixtures. It ran no SSH, SCP, remote pytest or app code.

## Hygiene and pre-existing RED

`test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` remains **RED: 1 failed**, with **60 inherited evidence hits**. The output contains **0 hits for `run_distributed.py`** and 0 hits for the four removed `isolation/home/...` forms. A literal tree census after the edit likewise finds 0 occurrences of the four removed home-directory forms; the previous eight were confined to `run_distributed.py`. Existing evidence findings were neither edited nor suppressed.

An initial combined F841 file run also executed the unrelated `test_at094_demo_parse_stable_after_dead_store_removal`, which failed on `len(meas_with_length) == 24` with actual 25. The identical node on the untouched head `35fabb25` failed with the same actual 25. It is pre-existing, was not fixed, and is not counted as a directed GREEN.

No full-suite rerun, performance work, regression repair, push or main operation was performed. `git diff --check` passed on the source/test edits; final diff and commit checks are recorded in the batch step line and handoff.
