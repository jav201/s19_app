# Inc 8 — E5 corrective notes

Batch 2026-11-01-batch-101, increment 8, stage E5 (corrective pass). Model: Opus. Worktree branch `b101-inc8`, base `e455a07`.
Scope: the rulings C-1 … C-9 of `E5-rulings.md`; the "Routed" table is not this pass's. Inputs read: `E5-code-review.md`, `E5-coverage-audit.md`, `E5-security.md`, `01-requirements.md`, `02-test-cases.md`, `E3-rulings.md`, `E4-integration-notes.md`.

## 1. Outcome

| Ruling | Outcome | Source | Tests | Records |
|---|---|---|---|---|
| C-1 (F1) | done — RED then GREEN | `crc_config.py` | 001.11/9, 001.11/10 (new) | 2 new cases |
| C-2 (F2) | done — RED then GREEN | `flow_execution_service.py` | EXT.14/4, EXT.14/5 (new) | 2 new cases; `E4-impl-notes.md` §4 marked corrected |
| C-3 (F4) | done | — | 12/10 pins the exact summary | R-FLOW-EXT.12 row text and threshold |
| C-4 | done | — | 9/3 reads run 3's WRITE-OUT image | case 9/3 |
| C-5 | done | — | 9/1, 9/2, 9/9, 9/10, 9/13, 9/14 pin 4 bytes; 9/5 pins the CRC value | 7 cases |
| C-6 | done (one case `partial`, reason given) | — | 9 new parametrize entries, 4 new tests | 11 new cases |
| C-7 | done | — | 001.11/8, 001.16/5, 001.17/2 by keys; 9/11 reads the painted lane | 4 cases |
| C-8 | done (records only) | — | — | 9/15, 12/10 `partial` with the reason |
| C-9 | done | — | `ids=` on 3 parametrizes | `02-test-cases.md` repaired (§4) |

Source files changed: 2 of the 2 allowed (`s19_app/tui/operations/crc_config.py`, `s19_app/tui/services/flow_execution_service.py`). No test function renamed or deleted; no assertion weakened (§3).

## 2. Per ruling

### C-1 — `_number_field` never raises (F1)

- **Change.** `_number_field` echoes the rejected value through a new helper `_clipped_json`, which encodes lazily with `json.JSONEncoder().iterencode` and stops once the text passes `VALUE_CLIP` (64) characters. Each nesting level adds at least one character, so the encoder never descends more than about 65 levels, whatever the value's depth. The message text is unchanged: `field '<key>' is not a number: <value>`.
- **Means differ from the ruling's parenthesis — recorded, with the reason.** The ruling suggests catching `RecursionError`/`ValueError` from the serialisation and echoing a fixed short form. A fixed form (the reviewer's `[` × 65 or `{` × 65) is the exact `<value>` only for a list whose first item nests; for an object (`{"a": {"a": …`) or a list with a leading scalar (`[0, [[…`) it would not be the first 64 characters of the JSON text, which the `<value>` definition (S-1) requires. The lazy encoder gives the exact prefix for every shape and cannot recurse, so no catch is needed (no case remains in which serialisation raises: `json.loads` output has no cycles, and `allow_nan` is on). Checked against `json.dumps` for `"zz"`, `true`, `1.5`, `null`, `[0]*10000`, `"z"*1000000`, a nested object, `[[[]]]` and `"é"` (equal), and on a 5 000-deep list (no error). The reviewer re-reads F1.
- **Tests (G1).**
  - `test_r_crc_config_001_11_9_deep_value_gives_the_reason_not_a_raise` (case R-CRC-CONFIG-001.11/9): every depth 800 … 1000 of a nested `init` gives exactly the 001.11 reason (64 × `[` + `…`) or the 001.17 reason, never an exception, and the band holds both. A band is used because the reader's limit depends on the caller's stack depth.
  - `test_r_crc_config_001_11_10_operations_execute_survives_deep_value` (case R-CRC-CONFIG-001.11/10, through keys): `x`, the path typed, Load config and Execute by `enter`; a bisection between 500 (field reason) and 1000 (nesting reason) ends on the reader's limit inside the dialog's handler. On the delivered code the bisection necessarily probes the first depth whose echo overflows, and the app exits there.
- **RED (delivered code, `e455a07` + new tests):** `evidence/inc-8/e5c-01-red-f1-f2.txt` — both tests fail with `RecursionError: maximum recursion depth exceeded while encoding a JSON object` (`json/encoder.py:258`).
- **GREEN:** `evidence/inc-8/e5c-02-green-f1-f2.txt` — 4 passed.

### C-2 — external-step check order (F2)

- **Change.** In the external-step branch of `run_flow`, the log-exists check moved up, before the output path is joined and climb-checked. Order now: log climb → log exists → output climb → output exists → copy (R-FLOW-EXT.14, the E3 addendum). `E4-impl-notes.md` §4 carries an E5 correction mark.
- **Tests (G2).** `test_r_flow_ext_14_4_both_climb_the_log_is_named` (EXT.14/4, both climb → the log's climb cause; holds on the delivered code too) and `test_r_flow_ext_14_5_missing_log_named_before_climbing_output` (EXT.14/5, `missing.log` absent inside the project + output `../../x.json` → `log 'missing.log' does not exist - the log is mandatory evidence, never optional`).
- **RED:** `e5c-01-red-f1-f2.txt` — 14/5 fails (`"output '../....e the project" == "log 'missing...ever optional"`); 14/4 passes (it does not tell the two orders apart; kept as the audit's owed case). **GREEN:** `e5c-02-green-f1-f2.txt`.

### C-3 — R-FLOW-EXT.12 states the N-2(c) placement (F4)

- Row text: "… in the order the block reads its refs, placed before the final token `unresolved` when the summary ends with that token. [A-1, A-2, S-2, N-2(c)]". Threshold "8/8" → "10/10" (adds /9 raise exit and /10 placement). This is the only requirement row changed.
- Test 12/10 keeps its assertions and adds the exact summary: `a2l reference · read step.changes_1.json in place of step.changes.json unresolved`.

### C-4 — 9/3 reads run 3's image

`test_r_flow_ext_9_3_reused_copy_is_read` keeps its `out.s19` check and adds: PATCH summary exactly `applied 1 entry`; the image named by run 3's WRITE-OUT summary (`_written_image(third)`) is `out.s19` (the identical image is reused) and holds `41 41 03 04` at 0x1000 … 0x1003.

### C-5 — the whole record and the CRC value

- 9/1, 9/2, 9/9, 9/10, 9/13, 9/14: each keeps its 2-byte assertion and adds the 4-byte one (`42 42 03 04` or `41 41 03 04` at 0x1000 … 0x1003 — the data bytes of the case's record). The ruling's wording "4 CRC bytes" is read as the record's 4 data bytes; these cases have no CRC.
- 9/5: adds the CRC value at 0x1020 … 0x1023 from the Designer engine (`crc_kernel.crc_stream`, width 32, poly 0x04C11DB7, init 0xFFFFFFFF, refin/refout, xorout 0xFFFFFFFF over `01 02 03 04` = 0xB63CFBCD), little-endian `CD FB 3C B6`.

### C-6 — clauses without a case

| Clause | New case(s) | Test | Mark |
|---|---|---|---|
| R-FLOW-CRC.4 `<first three errors, separated by "; ">` | FLOW-CRC.4/4 | `test_r_flow_crc_4_4_first_three_errors_joined` (the block's `parse_crc_config` monkeypatched to return 4 errors; cause exactly `crc config invalid: e1; e2; e3`) | **partial**: the shipped parser returns at most one error, so the join of more than one is reachable only through an injected parser. Pending for the requirements session: reword the row or keep the join as defence |
| R-FLOW-CRC.3 refused branch | FLOW-CRC.3/2 (absolute), /3 (escaping) | `test_r_flow_crc_3_2_refused_ref_exact_text[absolute|escaping]` (exact summary and cause, WRITE-OUT skipped, nothing written) | full |
| R-FLOW-CRC.9 shipped cap | FLOW-CRC.9/2 | `test_r_flow_crc_9_2_shipped_cap_named_in_the_cause` (a file extended by `truncate` to 268435457 bytes, no byte written or read, deleted after the run) | full |
| R-FLOW-EXT.14 order | EXT.14/4, /5 | see C-2 | full |
| R-FLOW-EXT.12 N-2(c), N-4 | 12/9, 12/10 | existing tests | 12/9 full; 12/10 partial (C-8) |
| R-CRC-CONFIG-001.10 required fields not exercised | 001.10/9 region `end`, /10 region `output_address`, /11 span `start` | new entries of `test_r_crc_config_001_10_missing_field_is_named` (`[region-end]`, `[region-output_address]`, `[span-start]`) | full |
| R-CRC-CONFIG-001.11 number fields not exercised | 001.11/11 region `start` `"0xG"`, /12 region `output_address` `[1]`, /13 group `output_address` `{"a": 1}`, /14 span `end` `false` | new entries of `test_r_crc_config_001_11_non_number_is_named` | full |
| R-FLOW-EXT.9 Linux halves (9/15 symlink arm, 12/10 on Linux) | none — **not-testable here**: no Linux host in this pass; the non-link Linux arm of 9/15 is routed (BACKLOG-CODE, `E5-rulings.md` Routed) | — | 9/10 records `n/a` on Linux in its case text |
| R-FLOW-EXT.9 / SR-4 junction back into the project | none — **not-testable as a requirement now**: the guard accepts it (S8-2) and Inc 9 rules whether to refuse it or correct the docstring; a case pinning today's acceptance would pin the gap Inc 9 may close | — | routed (S8-2, Inc 9) |

The thresholds of R-CRC-CONFIG-001.10 / .11 still read "8/8"; the rows now have 11 and 14 cases. The row texts were not touched (only C-3 may change a row): pending for the requirements session.

### C-7 — the through-keys ATs

- Helpers (G1): `_focus_by_tab` (moves the focus with `tab` only), `_open_crc_screen_by_keys` (`x`, asserts the dialog opens with the crc row highlighted), `_load_config_by_keys` (types the path into the empty path field, Load config by `enter`), `_execute_by_keys` (Execute by `enter`). The old method-driven helper `_open_crc_screen` was removed (no test used it after the change); `Button` is no longer imported.
- 001.11/8, 001.16/5, 001.17/2: every action by key. The editor is filled through the shipped Load config route (a file whose path is typed), because a test cannot type 100 000 brackets in reasonable time and the paste route is capped at 64 KiB. The three now also assert the status exactly (`==`, kept with the original `in`).
- 001.17/2: the later key's effect is asserted — after Execute, `tab` moves the focus past the disabled Write CRC to Close (`operations_close`).
- 9/11: Run (`enter`) and confirm (`c`) were already keys. The private `panel._lanes[0].last_outputs` read was replaced by the painted lane head (`lane_paint_plain`, the C-32 painted seam): it must read `▓ terminal · done · …`, and the image is the `.s19` name the painted head lists as written. The preconditions (project load, screen, import) stay fixture-driven; the case's annotation says so. Mark: full (the actions are keys; the auditor re-audits).

### C-8 — 9/15 and 12/10

Both `partial` in `02-test-cases.md`, with the reason: arm (b) / the refusal arm uses a junction whose target is outside the project, which the guard refuses before any rebind; a junction back into the project is accepted (S8-2, Inc 9), so the rebind cannot be tested through a link until then. S-4 is carried by arm (a) (the absolute ref). No code change.

### C-9 — `02-test-cases.md`

See §4 for every change.

## 3. Test-file changes (no rename, no delete, no weakening)

- `tests/test_b101_crc_model_and_reasons.py` (G1): `ids=` added to `test_r_crc_engine_001_1_catalogue_32_bit_checks` (`[MPEG-2]`, `[JAMCRC]`), `test_r_crc_designer_001_1_catalogue_checks` (`[ARC]` … `[MPEG-2]`) and `test_r_crc_config_001_16_designer_template_is_named` (`[saved]`, `[width16]`, `[algorithm-not-object]`) — the ids the cases cite now collect (TCP-MAP-3). 7 parametrize entries added (C-6); 2 tests added (C-1); the three dialog tests rewritten to keys with stricter assertions (C-7).
- `tests/test_b101_flow_ext_copy.py` (G2): assertions added to 9/1, 9/2, 9/3, 9/5, 9/9, 9/10, 9/13, 9/14, 12/10; 9/11's observation moved to the painted lane; 6 tests added (EXT.14/4, /5; FLOW-CRC.3/2 ×2 ids; FLOW-CRC.4/4; FLOW-CRC.9/2).
- No existing `assert` line was removed except in 9/11 (`_rerun_image` loop and its exit condition, replaced by the painted-head read that asserts more: lane done + exactly one written `.s19`) and in the dialog tests where the method calls (`action_operations_view`, `ListView.index =`, `TextArea.text =`, `Button.press()`) were replaced by keys; every expected-value assertion is kept.
- Node ids: 97 in G1 + G2 (82 + 15). Every node id cited in the Tests column of `02-test-cases.md` collects (101 cited, 0 missing; checked with `--collect-only`).
- `tests/test_id_registry.py`: unchanged — no test file was added (`EXPECTED_SCANNED_TEST_FILES` stays 248; the guard passes, §5).

## 4. Record changes (`02-test-cases.md`, `01-requirements.md`, `E4-impl-notes.md`)

`01-requirements.md`: R-FLOW-EXT.12 row text and threshold (C-3) — the only row changed.
`E4-impl-notes.md` §4: a bracketed E5 correction mark on the check order (C-2); the original text is kept.
`02-test-cases.md`:
- Intro paragraph: an E5 sentence appended. A new Count note after the E3 one (kept).
- Coverage column (TCP-TRC-4): 78 × `gap`, 3 × `covered`, 1 × `partial` → `covered` for 96 cases, `partial` for 3 (9/15, 12/10, FLOW-CRC.4/4).
- Result column: the E5 corrective final run (§5).
- Field changes, by case (column — reason):

| Case | Column | Reason |
|---|---|---|
| R-CRC-ENGINE-001.1/7 | Expected result | SR-1 (canon R-FLOW-CRC.7) |
| R-CRC-CONFIG-001.11/7 | Inputs | N-1 |
| R-CRC-CONFIG-001.11/7 | Expected result | N-1 |
| R-CRC-CONFIG-001.11/8 | Preconditions | C-7: the editor is filled by the Load config route |
| R-CRC-CONFIG-001.11/8 | Inputs | C-7: keys only |
| R-CRC-CONFIG-001.11/8 | Expected result | C-7 hardening: exact status (==) |
| R-CRC-CONFIG-001.16/5 | Inputs | C-7: keys only |
| R-CRC-CONFIG-001.16/5 | Expected result | C-7 hardening: exact status (==) |
| R-CRC-CONFIG-001.17/2 | Preconditions | C-7: the editor is filled by the Load config route (100 000 characters cannot be typed in a test or pasted: paste cap 64 KiB) |
| R-CRC-CONFIG-001.17/2 | Inputs | C-7: keys only |
| R-CRC-CONFIG-001.17/2 | Expected result | C-7: the later key's effect is asserted |
| R-FLOW-EXT.9/1 | Expected result | SR-2; C-5 (4 bytes pinned) |
| R-FLOW-EXT.9/2 | Expected result | C-5 (4 bytes pinned) |
| R-FLOW-EXT.9/3 | Expected result | C-4 (the image named by run 3's WRITE-OUT) |
| R-FLOW-EXT.9/5 | Expected result | SR-1, SR-2; C-5 (CRC value pinned) |
| R-FLOW-EXT.9/6 | Expected result | SR-2 |
| R-FLOW-EXT.9/9 | Expected result | SR-2; C-5 (4 bytes pinned) |
| R-FLOW-EXT.9/10 | Expected result | SR-2; C-5 (4 bytes pinned) |
| R-FLOW-EXT.9/11 | Expected result | SR-2; C-7 (lane status and image read from the painted lane) |
| R-FLOW-EXT.9/11 | Tests | C-7 annotation |
| R-FLOW-EXT.9/12 | Preconditions | SR-3 |
| R-FLOW-EXT.9/12 | Inputs | SR-3 |
| R-FLOW-EXT.9/13 | Expected result | C-5 (4 bytes pinned) |
| R-FLOW-EXT.9/14 | Expected result | C-5 (4 bytes pinned) |
| R-FLOW-EXT.9/15 | Preconditions | SR-4 |
| R-FLOW-EXT.9/15 | Tests | C-8 |
| R-FLOW-EXT.10/1 | Expected result | SR-5 |
| R-FLOW-EXT.10/2 | Expected result | SR-5; placeholders replaced by the exact text the test pins |
| R-FLOW-EXT.10/3 | Expected result | SR-5 |
| R-FLOW-EXT.10/4 | Preconditions | SR-3 |
| R-FLOW-EXT.10/4 | Inputs | SR-3 |
| R-FLOW-EXT.10/4 | Expected result | SR-5 |
| R-FLOW-EXT.10/5 | Preconditions | SR-3 |
| R-FLOW-EXT.10/5 | Inputs | SR-3 |
| R-FLOW-EXT.10/5 | Expected result | SR-5 |
| R-FLOW-EXT.11/2 | Expected result | SR-2 |
| R-FLOW-EXT.12/2 | Expected result | SR-6 |
| R-FLOW-EXT.12/3 | Expected result | SR-6 |
| R-FLOW-EXT.12/6 | Expected result | SR-6 |
| R-FLOW-EXT.12/6 | Tests | TCP-MAP-3: the cited node id did not collect |
| R-FLOW-EXT.13/1 | Expected result | SR-5 |
| R-FLOW-EXT.13/2 | Expected result | SR-5 |
| R-CRC-CONFIG-001.10/9 | new row | C-6: a defined required field without a case |
| R-CRC-CONFIG-001.10/10 | new row | C-6 |
| R-CRC-CONFIG-001.10/11 | new row | C-6 |
| R-CRC-CONFIG-001.11/9 | new row | C-1 |
| R-CRC-CONFIG-001.11/10 | new row | C-1 |
| R-CRC-CONFIG-001.11/11 | new row | C-6 |
| R-CRC-CONFIG-001.11/12 | new row | C-6 |
| R-CRC-CONFIG-001.11/13 | new row | C-6 |
| R-CRC-CONFIG-001.11/14 | new row | C-6 |
| R-FLOW-CRC.3/2 | new row | C-6 |
| R-FLOW-CRC.3/3 | new row | C-6 |
| R-FLOW-CRC.4/4 | new row | C-6 |
| R-FLOW-CRC.9/2 | new row | C-6 |
| R-FLOW-EXT.12/9 | new row | N-4 (owed by E4 integration §6 item 2) |
| R-FLOW-EXT.12/10 | new row | N-2(c); C-3 exact summary; C-8 |
| R-FLOW-EXT.14/4 | new row | C-2 (audit EXT.14/4) |
| R-FLOW-EXT.14/5 | new row | C-2 |
| all 82 existing rows | Coverage | TCP-TRC-4: 78 x `gap`, 3 x `covered`, 1 x `partial` -> `covered`, except R-FLOW-EXT.9/15 `partial` (C-8) |

New cases: 82 → **99** (+17). Coverage: **96 covered, 3 partial, 0 gap, 0 conflict.**

## 5. Final runs (win32, Python 3.11.15, `s19env`; transcripts redacted to `<HOME>`/`<USER>`)

Environment: `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=.`, `LOCALAPPDATA` redirected to a temp folder, `--basetemp` under a temp folder, `-p no:cacheprovider`, `timeout 1800`; `s19_app.__file__` printed first in each transcript (the worktree's). The real `%LOCALAPPDATA%\s19_app` was not used; no test touched the OS clipboard.

| Run | Transcript (`evidence/inc-8/`) | Result |
|---|---|---|
| C-1, C-2 tests on the delivered code (RED) | `e5c-01-red-f1-f2.txt` | 3 failed, 1 passed (14/4 does not tell the orders apart) |
| C-1, C-2 tests after the fix (GREEN) | `e5c-02-green-f1-f2.txt` | 4 passed |
| The two Inc 8 test files (G1, G2) | `e5c-03-new-files.txt` | **97 passed** |
| Every test file importing `crc`, `crc_config`, `flow_execution_service`, `flow_model` or `flow_report_service` — 47 files (G1, G2 included), one pytest run per file | `e5c-04-touched-module-importers.txt` | **1189 passed, 1 failed**: `test_b97_flow_execution.py::test_tc_b97_55_input_queued_during_a_run_starts_no_second_run` (2 `run_chain_set` calls for one Run) |
| That file again, whole | `e5c-06-rerun-b97-flow-execution.txt` | **75 passed** — the failure did not reproduce; the single test also passed 3/3 in isolation (not saved). Timing-sensitive (a press injected during a synchronous run); the run overlapped another session's test load on this machine. The path is a PATCH chain with no external step, which neither source change touches. Recorded as a flaky pass, not hidden |
| Law guards of the repo `CLAUDE.md`: `tests/test_id_registry.py`, `tests/test_engine_unchanged.py`, `tests/test_requirements_canon.py`, `tests/test_tui_directionb.py -k test_tc031` | `e5c-05-law-guards.txt` | **27 passed** (181 deselected: the rest of `test_tui_directionb.py`) |

`02-test-cases.md` Result column: all 99 cases `verified (win32, e5c)` — every cited full or partial node id passed in `e5c-03` or sits in a file with 0 failures in `e5c-04` (the one flaky file is cited by no case).

## 6. Not done, and why

- **No Linux run.** No host was used in this pass; the Linux halves stay as recorded (C-6 table).
- **The graph** (`codewire/graph-inc8.md`, node `_number_field`) still prescribes a whole `json.dumps`; not in C-1 … C-9, left for the requirements/graph session.
- **R-CRC-CONFIG-001.10 / .11 thresholds** ("8/8") and **R-FLOW-CRC.4**'s three-error wording (the parser gives one): row texts outside C-3, left for the requirements session.
- **Audit hardening not ruled:** 9/7 "run 1: none" and the seven owed black-box ATs (A-1 … A-7 of the audit) — not in the rulings; untouched.
- Re-review owed (per `E5-rulings.md`): the code reviewer re-reads F1 and F2; the coverage auditor re-audits the changed cases only.
