# Batch-103 G3 — corrective lane A (`b103-g3-ui-a`)

Base: `21ec06b2e668b76ec62e76b9c3c6eb7cf971f2b1`. Test correction: `3cbdfd0f13ef0337de9708b8b8c9b585eff7502a`.

The correction composes the frozen `show_tab` / `click_visible` helpers, waits through `settle_workers`, reads the current Patch script / landing-pane geometry, and handles the current idle `q` modal. Product, requirements and `tests/support/b103_inc8_p.py` are unchanged.

## Commands and selection

All runs used Windows, Python 3.12.7, the repository worktree as cwd, closed stdin, isolated HOME/XDG/LOCALAPPDATA/TMPDIR, no bytecode or pytest cache, no CI/clipboard guards, no NO_COLOR/CLICOLOR, `TERM=xterm-256color` and `COLORTERM=truecolor`.

Common invocation:

```text
$HOME/anaconda3/python.exe -I -B -m pytest -q -n 0 -p no:cacheprovider --junitxml=<REDACTED_OUT>/<name>.junit.xml <selection> > <REDACTED_OUT>/<name>.log 2>&1 < /dev/null
```

Selections:

- `red-before`: the 20 nodeids below, before the correction.
- `red-regressions-final`: the same 20 nodeids after the correction.
- Nine final whole-file selections: `tests/test_b100_document.py`, `tests/test_b100_load_question.py`, `tests/test_b100_save_dialog.py`, `tests/test_b100_save_image.py`, `tests/test_b100_workers.py`, `tests/test_b99_staging.py`, `tests/test_b99_bytes_field.py`, `tests/test_b99_export.py`, `tests/test_b99_s0.py`.
- Each whole file has its own `<file-stem>.junit.xml` and `.log` here. The aggregate attempt was not used for the tally; the nine complete per-file runs are authoritative.

## Twenty known RED -> PASS nodes

`red-before.junit.xml`: **20 failed**. `red-regressions-final.junit.xml`: **20 passed**, 0 failed.

```text
tests/test_b100_document.py::test_tc_b100_29_forced_write_failure_saves_without_the_document
tests/test_b100_document.py::test_at_b100_08_saved_document_reopens_with_the_project[size1]
tests/test_b100_save_image.py::test_tc_b100_70_refused_save_keeps_the_flag
tests/test_b100_save_image.py::test_tc_b100_70_written_document_clears_the_flag
tests/test_b100_save_image.py::test_tc_b100_70_failed_document_write_keeps_the_flag
tests/test_b100_save_image.py::test_tc_b100_70_file_backed_document_from_outside_keeps_the_flag
tests/test_b100_save_image.py::test_tc_b100_70_natural_path_load_edit_save_keeps_the_flag
tests/test_b100_save_image.py::test_at_b100_05_save_project_saves_the_patched_image[size0]
tests/test_b100_save_image.py::test_at_b100_05_save_project_saves_the_patched_image[size1]
tests/test_b100_load_question.py::test_tc_b100_44_project_load_asks_iff_a_flag_is_set
tests/test_b100_load_question.py::test_tc_b100_12_cancelled_question_rehomes_the_focus
tests/test_b100_load_question.py::test_tc_b100_70_project_load_asks_only_while_the_document_is_unsaved
tests/test_b100_load_question.py::test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route
tests/test_b100_save_dialog.py::test_at_b100_21_painted_plan_is_the_saved_tree[pending]
tests/test_b100_save_dialog.py::test_at_b100_21_painted_plan_is_the_saved_tree[document]
tests/test_b99_staging.py::test_at_b99_05_save_project_after_same_name_save_back
tests/test_b100_workers.py::test_tc_b100_53_quit_asks_only_while_a_session_action_runs
tests/test_b99_export.py::test_at_b99_11_sanitised_mac_only_second_export_takes_suffix
tests/test_b99_s0.py::test_at_b99_02_save_back_excludes_s0
tests/test_b100_workers.py::test_tc_b100_53_confirmed_quit_is_withdrawn_when_editor_edits_stay_unsaved
```

## Whole-file tally

| File | Passed | Failed | Skipped | Xfailed |
|---|---:|---:|---:|---:|
| test_b100_document.py | 163 | 0 | 0 | 0 |
| test_b100_load_question.py | 59 | 0 | 0 | 0 |
| test_b100_save_dialog.py | 160 | 0 | 3 | 0 |
| test_b100_save_image.py | 78 | 0 | 0 | 0 |
| test_b100_workers.py | 79 | 3 | 0 | 1 |
| test_b99_staging.py | 32 | 0 | 0 | 0 |
| test_b99_bytes_field.py | 3 | 0 | 0 | 0 |
| test_b99_export.py | 23 | 0 | 0 | 0 |
| test_b99_s0.py | 6 | 0 | 0 | 0 |
| **Total** | **603** | **3** | **3** | **1** |

The complete selection is **610 = 603 passed + 3 failed + 3 skipped + 1 xfailed**. JUnit `skipped=4` on `test_b100_workers` is the one xfail; the other three skips are in `test_b100_save_dialog`.

## Three inherited failures: base/head proof

`inherited-base-head.tsv` preserves the nodeids, category, base/head states, signatures and timings from the residual comparison. All three are `heredado_firma_distinta`, with **base_status=failure** and **head_status=failure**:

- `test_tc_b100_53_reset_runs_after_the_worker_and_before_the_first_install`: the spy records `worker_end` and `reset@main`, but not the two expected `install` events.
- `test_at_b100_18_worker_half_case06_project_load_by_keys`: the P6 load exceeds its internal 300 s wait.
- `test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished[a2l_size]`: the `Path.stat` monkeypatch is not triggered by the current call chain, so the expected refusal line is absent.

These inherited failures remain visible; no assertion, oracle or requirement was weakened to hide them.

## Artifact integrity and redaction

`SHA256SUMS` covers RESULT, the sanitized steps, both RED/PASS JUnit/transcript pairs, all nine whole-file JUnit/transcript pairs and the inherited comparison extract. Copies were redacted for accounts, hosts, IPs and personal paths without changing nodeids, tallies, status fields or failure signatures.
