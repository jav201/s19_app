# CHECK — FA-TICK2u (orchestrator-scripted mechanical check; the orchestrator did not write this unit)

- unit: FA-TICK2u; worker DeepSeek v4-pro (medium), PI_EXIT=0, per-row REPORT (`FA-TICK2u-REPORT.md` copy in the orchestrator's review folder)
- tree: fresh clone of `alp-e4r` 7f2286db + the integration diff, host `<host>` (rtx), HT-02 environment
- script: `tools25/chk_tick2u.sh` + `chk_tick2u_mut.py` (orchestrator tools, outside the repo), the CHK-ds-fa-rtx steps; no model judgement in the run
- why scripted: FA-TICKb's DeepSeek CHK-ds timed out after step 1 (P-247); this run takes ~20 min

## Transcript (diff md5 051b530b = worker diff + the comment rewrap, before the TC-607 fix)
```
start 03:00:45 load 0.67 0.90 1.21
HEAD 7f2286db diff-md5 051b530b
## step1
s19_app/core.py
tests/test_alp_inc3_load_responsiveness.py
tests/test_alp_s19_read_once.py
 3 files changed, 141 insertions(+), 1 deletion(-)
CR=0 added-skip/xfail/sleep=0
removed-tests=0
## step2 green
unit 5 passed in 42.20s
42.1%  0.058 s / 0.100 s  R-A2L-REFRESH.050 small project-pair R-A2L-REFRESH.050 in-window tick lateness  tests/test_alp
43.0%  0.057 s / 0.100 s  R-A2L-REFRESH.050 small a2l-only R-A2L-REFRESH.050 in-window tick lateness  tests/test_alp_inc
49.1%  0.051 s / 0.100 s  R-A2L-REFRESH.050 small image R-A2L-REFRESH.050 in-window tick lateness  tests/test_alp_inc3_l
S19File test files: 58
reg rc=1 8 failed, 1962 passed, 6 skipped, 11 xfailed in 511.95s (0:08:31)
FAILED tests/test_changes_symbol_entries.py::test_tc718_battery_refused_encode_limbs_named[Drifty-210-limb_fragments3]
FAILED tests/test_synth_release_case.py::test_a2l_issues_reported
FAILED tests/test_synth_release_case.py::test_a2l_zero_issues
FAILED tests/test_synth_release_case.py::test_addresses_inside_image
FAILED tests/test_tui_app.py::test_load_selected_file_attaches_mac_to_loaded_binary
9 passed, 58 deselected in 155.79s (0:02:35)
## base re-run of the failing nodes (7f2286db)
FAILED tests/test_changes_symbol_entries.py::test_tc718_battery_refused_encode_limbs_named[Drifty-210-limb_fragments3]
FAILED tests/test_tui_app.py::test_load_selected_file_attaches_mac_to_loaded_binary
FAILED tests/test_synth_release_case.py::test_a2l_zero_issues
FAILED tests/test_synth_release_case.py::test_addresses_inside_image
FAILED tests/test_synth_release_case.py::test_a2l_issues_reported
5 failed in 2.91s
## step3 controls
control c1 applied
~/work/zq-fa/chk2-FA-TICK2u-nc/tests/test_alp_s19_read_once.py:78: AssertionError: 295
1 failed in 1.20s
control c2 applied
~/work/zq-fa/chk2-FA-TICK2u-nc/tests/test_alp_s19_read_once.py:117: AssertionError: assert [('S0', 0), ('S9', 0)] == [('S0', 0), (...2), ('S9', 0)]
1 failed in 0.05s
## step4 laws
laws rc=1 5 failed, 112 passed in 413.07s (0:06:53)
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
FAILED tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once
FAILED tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
FAILED tests/test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token
E     line 1373 R-A2L-DEF.153: 'shall' appears 2 times
E     line 4248 R-PICKER-CORRECT.004: 'shall' appears 2 times
E     line 4252 R-PICKER-CORRECT.008: 'shall' appears 2 times
end 03:20:22
CHK2U_DONE
```
Notes:
- Step 2: the five regression failures fail identically on the base clone 7f2286db (inherited; `test_synth_release_case.py` was passed twice to the run, hence 8 failure lines for 5 nodes). The small-route QC-TM lines are rtx, load 0.67: indicative, decided in M2.
- Step 3: c1 (row-1 revert) → the read-once node RED (295 raw reads); c2 (`open(..., newline='')`) → the LLR-154.1 pin RED (the lone-CR line merges with the next one), so the pin has power over line splitting. Row 4's control (no `gc.disable()` in the gate) is a race: not re-run here; the small arms ×3 on the quiet laptop decide it.
- Step 4: **MECH-NO-GO, real**: law `test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` — "the guard scanned 373 test modules, not the declared 372 … bump EXPECTED_SCANNED_TEST_FILES in the same PR". The other four REDs are the inherited set (canon offenders R-A2L-DEF.153, R-PICKER-CORRECT.004/.008 only).

## Orchestrator fix (DF-04 a) and re-verification
- `tests/test_id_registry.py`: `EXPECTED_SCANNED_TEST_FILES` 372 → 373, with one history comment line (`+1 tests/test_alp_s19_read_once.py`), as the law's message asks. The new module is the brief's own file (row 2–3).
- Integration diff now: 4 files, +143/−2, CR 0, md5 c3302422.
- Fresh clone 7f2286db + that diff (`tools25/tick2u_v2.sh`): `tests/test_id_registry.py tests/test_alp_s19_read_once.py` `-n 0` → `14 passed`. The six laws are therefore the inherited four REDs.
- Verdict after the fix: **MECH-GO**.

## Orchestrator intent review (Opus, relevo-25)
GO. The diff is the brief's ruling from FA-TICK2 (P-240): one behaviour-preserving product change and one test-instrument fix. Nothing else moves.
- **Row 1 (`core.py`, FA-TICK2 cause a).** `S19File._load` reads the text once (`io.StringIO(f.read())`) inside the same `with open(self.path, 'r')`. `f.read()` applies the same universal-newline translation as iterating the stream, and `StringIO` then splits on `\n` only, so line splitting and numbering are unchanged. Both `except` branches still re-raise, so a decode error still aborts the constructor. Cost: one transient copy of the text (the file plus its `StringIO`), freed when `_load` returns. `core.py` is shared with main; the change is a pre-existing-code fix (DF-04 a). Integration adjustment: the one-line comment (169 cols) was rewrapped to two lines (comment-only).
- **Row 2 (read-once oracle).** A counting `FileIO` under a real `TextIOWrapper(BufferedReader(...))` asserts ≤ 2 raw reads and record equality with an unpatched parse. It is RED on the base loop (295 raw reads), so it can fail when the cause returns.
- **Row 3 (LLR-154.1 semantics pin).** CRLF, lone-CR, blank lines, a damaged `S1`, an S5 count and a record after S9. The literals come from the base tree at 7f2286db (recorded). It stays GREEN under the row-1 revert, by design. Its power over line splitting is shown by the check's control c2 (`newline=''` merges the lone-CR line).
- **Row 4 (`TimedGate`, FA-TICK2 cause b).** The gate disables the collector when it holds at producer entry, as the producer's own first statement does (D-13, `file_load.py:1065`). It re-enables on its own timeout; on release the producer's `finally` re-enables. `gate_started` is still taken at the same point, so the window start does not move. The product is not changed (P-240 ruling: no product `gc.disable()` before the producer call).
- **Residual.** Row 4's control is a race (a main-thread gen2 collection must land inside the 0.20 s hold); it stayed GREEN 1× on rtx. The small-route arms ×3 on the quiet laptop in M2 decide `.050` for `[image]` and `[project-pair]`.
