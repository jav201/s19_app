# DeepSeek coverage lane A — Inc 11 E5 — disposition report

- **Owner:** DeepSeek tester, lane A (`tests/test_b103_a2l_reader_coverage.py`,
  `tests/test_b103_a2l_reader_perf.py` only).
- **Date:** 2026-11-08 (batch-103 Inc 11, E5 gate).
- **Status:** **PENDING Linux verification.** Code implemented and
  `py_compile` green on the Windows PC; the cachyos-rtx runner is unreachable
  (SSH `192.168.1.67:22` connection timed out), so no pytest/probe was run.

## Scope

The 37 partial IDs of `E5-coverage-reaudit.md` were audited against
`coverage-completion-report.md`. 35 are closable from the two files I own;
the two explicitly legacy-only items (`R-A2L-READ.48/1` and
`R-A2L-READ.49/2`) live in `tests/test_b103_a2l_reader.py` and are left to
the other lane. P17 (`test_cov_read_54_compu_vtab_named_later`) was preserved
verbatim; no product, record, or other-test file was edited; nothing was
committed.

## Per-case disposition

| ID | Disposition | Node / residual closed |
|---|---|---|
| R-A2L-READ.55/2 | closed (C) | `test_cov_read_55_zero_sections_and_tags` — binary refusal now asserts `sections == [] and tags == []` |
| R-A2L-READ.55/3 | closed (C) | same node — NUL-after-address refusal asserts zero sections/tags |
| R-A2L-READ.55/4 | closed (C) | same node — NUL-in-comment refusal asserts zero sections/tags |
| R-A2L-READ.56/1 | closed (C) | `test_cov_read_56_cap_and_views` — `data_101["errors"][:100] == data_100["errors"]` |
| R-A2L-READ.56/2 | closed (C) | same node — all first 100 entries asserted `unexpected character U+00E9` |
| R-A2L-READ.56/3 | closed (C, route) | `test_cov_read_56_views_show_capped_errors` — real Workspace `#a2l_view` and Issues `#validation_issues_groups` (≤101 error lines) |
| R-A2L-READ.66/3 | closed (C) | `test_cov_read_66_esc_in_echoed_word_exact` — exact `Line 23: /end <U+FFFD>X does not close /begin MEASUREMENT` |
| R-A2L-READ.9/2 | closed (C) | `test_cov_read_9_lone_line_end_terminator` — isolated CRLF/CR terminator (no `.replace("\n", nl)` over the embedded CRLF; no CR-CR-LF) |
| R-A2L-001.3.2/4 | closed (C) | `test_cov_001_3_2_backslash_line_end_exact` — standalone 3-line shape, `Line 3: /end without /begin` |
| R-A2L-READ.14/1 | closed (C) | `test_cov_read_14_multiline_string_one_word` — ANNOTATION_TEXT `"a\nb\nc"` asserted as one word |
| R-A2L-001.1/3 | closed (C) | `test_cov_001_1_end_after_words_closed_zero_errors` — `end_line == _line_of(text, "/end MEASUREMENT")` |
| R-A2L-READ.19/2 | closed (C) | `test_cov_read_19_endx_closes_at_own_end` — `end_line == _line_of(text, "/end MEASUREMENT")` |
| R-A2L-001.4/1 | closed (C) | `test_cov_001_4_stray_end_exact_line_30` — `/end X` on line 30 |
| R-A2L-001.4/2 | closed (C) | same node — `junk /end X` on line 30 |
| R-A2L-001.5/1 | closed (C) | `test_cov_001_5_end_name_mismatch_exact` — exact `Line 23: /end IF_DATA does not close /begin MEASUREMENT` |
| R-A2L-001.5/2 | closed (C) | same node — exact `Line 23: /end MEASUREMENT does not close /begin IF_DATA` |
| R-A2L-READ.64/1 | closed (C) | `test_cov_read_64_32_levels_exact` — 33-level multi-line arm asserts `sections == [] and tags == []` |
| R-A2L-READ.64/2 | closed (C) | same node — one-line arm asserts `sections == []` |
| R-A2L-READ.65/5 | closed (C) | `test_cov_read_65_one_line_string_one_word` — 10 MB string parses+renders and is one word |
| R-A2L-READ.65/6 | closed (P) | `test_r_a2l_read_52_words_no_exception_and_one_error` — now renders both files; `_words_file(one_line=True)` adds the 4.8M-word one-body-line variant (19.2 MB) |
| R-A2L-READ.27/1 | closed (C) | `test_cov_read_27_case07_full` — exact address/length/limits/unit per each of the 12 tags |
| R-A2L-READ.32/2 | closed (C) | `test_cov_read_32_duplicate_exact_lines` — second BYTE_ORDER on line 23 (`ECU_ADDRESS 0x10 BYTE_ORDER MSB_FIRST` / `BYTE_ORDER MSB_LAST`), exact `Line 23` + no address |
| R-A2L-READ.58/3 | closed (C) | `test_cov_read_58_matrix_dim_exact_lines` — exact `Line 22`/`Line 23` MATRIX_DIM zero/four-argument diagnostics |
| R-A2L-READ.58/5 | closed (C) | `test_cov_read_58_round2_surplus_exact` — exact `Line 22` for ECU_ADDRESS/LENGTH/BIT_MASK surplus (see note A) |
| R-A2L-READ.59/6 | closed (C) | `test_cov_read_59_no_datatype_size_shapes` — exact `Line 20` for all four shapes |
| R-A2L-READ.60/2 | closed (C) | `test_cov_read_60_no_address_all_shapes` — missing-argument arm asserts `bit_org == "0x0FF0"` |
| R-A2L-READ.60/4 | closed (C) | same node — agreeing header-address (0x2000) and agreeing BIT_MASK pair (0x10 + `.32` duplicate) |
| R-A2L-READ.60/6 | closed (C) | same node — exact `Line 23: BYTE_ORDER/BIT_MASK has 0 of its 1 arguments` |
| R-A2L-READ.60/8 | closed (C, route) | `test_cov_read_60_08_picker_lists_only_usable_address` — real Patch picker lists none of the 8 fail-closed tags, lists `XS` |
| R-A2L-READ.60/9 | closed (C) | `test_cov_read_60_byte_order_source_not_byte_order` — inherited invalid MOD_COMMON (`MSB_FRIST`) refusal + holding case on the same invalid MOD_COMMON |
| R-A2L-READ.61/1 | closed (C) | `test_cov_read_59_undeclared_layout_val_blk` — `.59/3` VAL_BLK now also asserts `length is None` |
| R-A2L-READ.61/9 | closed (C, route) | `test_cov_read_61_09_picker_and_check_editor_never_u16` — real Patch picker + Check Editor list each no-length tag as `u8` (never `u16`) |
| R-A2L-READ.50/1 | closed (C) | `test_cov_read_50_summary_exact` — full `- CHARACTERISTIC XH "one-line header" VALUE 0x00003000 RL_U32 0 CM_ID 0 100 (lines 20-21)` line |
| R-A2L-READ.39/1 | closed (C) | `test_cov_read_39_ascii_number_error` — exact `Line 20` for LENGTH 0 / 1048577 / 99999999999 and ASCII NUMBER 1000000000000 |
| R-A2L-READ.65/4 | closed (C) | `test_cov_read_65_hostile_corpus_mutations` — `executed == 160 * 1000` executed-mutant count |
| R-A2L-READ.48/1 | **left — other lane** | `tests/test_b103_a2l_reader.py` (≤120 s assertion) |
| R-A2L-READ.49/2 | **left — other lane** | `tests/test_b103_a2l_reader.py` (D5 `RL.FNC.SWORD.ROW_DIR` isolation) |

## Commands and results (this PC)

```text
$ python -m py_compile tests/test_b103_a2l_reader_coverage.py tests/test_b103_a2l_reader_perf.py
PY_COMPILE_OK

$ timeout 15 ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
    javiergr@192.168.1.67 "echo SSH_OK && hostname"
ssh: connect to host 192.168.1.67 port 22: Connection timed out
```

No pytest/probe was run on the Windows PC (batch rule). The cachyos-rtx runner
is unreachable, so per instructions I did not retry.

## Pending (blocking `verified`)

1. **Linux run of the two owned modules** with the mandated runner:
   absolute `/home/javiergr/miniconda3/envs/s19ci/bin/python`, isolated
   `/tmp/b103-e5-11-deep-a/zq_iso_user`, closed stdin,
   `PYTHONDONTWRITEBYTECODE=1`, package path printed first.
   Suggested commands (to be run only once the runner is reachable):

   ```bash
   /home/javiergr/miniconda3/envs/s19ci/bin/python -c "import sys; sys.path.insert(0, '/home/javiergr/Github/s19_app-b103-inc11-code'); print(sys.path)"
   cd /home/javiergr/Github/s19_app-b103-inc11-code && \
     PYTHONDONTWRITEBYTECODE=1 /home/javiergr/miniconda3/envs/s19ci/bin/python -m pytest \
     tests/test_b103_a2l_reader_coverage.py tests/test_b103_a2l_reader_perf.py \
     -m "not slow and not serial_timing" -q --tb=short
   ```

2. **READ.52 stays RED/not-verified** — no threshold was changed; `case_06`
   timing is still above its bound (12.714 s > 10.579 s per
   `coverage-perf.txt`) and is not claimed green.

## Notes / conflicts reported (not silently changed)

- **R-A2L-READ.58/5 round 2 line number.** `02-test-cases.md` and
  `codewire/graph-inc11.md:444` pin the round-2 LENGTH/BIT_MASK surplus
  diagnostics to `Line 22`. The naive `meas(X, ECU_ADDRESS 0x10, LENGTH 2 4)`
  full-header fixture would place LENGTH on line 23. I followed the spec's
  `Line 22` by placing each keyword as the first body word on line 22
  (full 6-word MEASUREMENT header). Flagging for the orchestrator in case the
  fixture intent was `hdr=""` (which would move ECU_ADDRESS to line 21 and
  LENGTH/BIT_MASK to line 22) — the observable asserted is the exact
  keyword-line diagnostic, not a weakened bound.
- **R-A2L-READ.56/3 route needs an image.** `build_validation_report` only runs
  `validate_a2l_internal_issues` when a primary S19/HEX is loaded, so the route
  test loads a tiny `emit_s19_from_mem_map` image before the A2L attach to make
  the A2L_STRUCTURE_ERROR issues reach the real Issues screen.
- **Route tests are structural.** They are modeled on the existing passing
  app-route tests (`test_at_b103_i11_2/3` in `test_b103_a2l_reader.py`,
  `tests/test_b102_patch_picker.py`). Their runtime behavior (picker
  population timing, `get_row_at` cell plain-text) is unverified until the
  Linux run above.
