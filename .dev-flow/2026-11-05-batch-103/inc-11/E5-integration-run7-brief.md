# Inc 11 E5: functional integration after product corrections (DeepSeek)

Baseline `21a0c56b`, which includes P1–P15 and 23 green E5 nodes. Do not edit any product or test file and do not commit.

Create a fresh full Git clone of the supplied branch under `/tmp/b103-e5-11-int7/tree`. Use the Linux runner only, absolute s19ci Python, `PYTHONDONTWRITEBYTECODE=1`, closed stdin and HOME/XDG/LOCALAPPDATA under `/tmp/b103-e5-11-int7/<user>` (never a final component named `home`). Print `s19_app.__file__` at the start of every transcript. Do not use the stale `~/work/b103-int11`.

Run these groups without `serial_timing`, using `-n 8`:

- **A:** `tests/test_b103_a2l_reader.py` and `tests/test_b103_a2l_reader_e5.py`.
- **B:** `tests/test_b103_a2l_definition.py` and `tests/test_b103_synth_definitions.py`.
- **C:** `tests/test_a2l_multiline_headers.py`, `tests/test_b101_a2l_blocks_and_segments.py`, `tests/test_tui_a2l_issue_recolor.py`, `tests/test_b100_a2l_progress.py`, `tests/test_tui_directionb.py`, `tests/test_tui_issues_triage_b94.py`.
- **D:** `tests/test_address_census.py`, `tests/test_suite_hygiene.py`, `tests/test_id_registry.py`, `tests/test_engine_unchanged.py`, `tests/test_docs_canon.py`, `tests/test_b101_doc_hygiene.py`, `tests/test_b101_help_legend_docs.py`.

Copy complete transcripts with pytest exit codes into `inc-11/evidence-e5/int-green7-{a,b,c,d}.txt`. Do not run timing yet; READ.52's protocol is being corrected separately. Report every failure with file and cause and do not claim green from partial output. Remove only `/tmp/b103-e5-11-int7*` after the transcripts land. On this PC run only git/ssh/scp and py_compile, no pytest.
