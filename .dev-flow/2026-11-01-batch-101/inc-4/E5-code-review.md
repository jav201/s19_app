# Inc 4 — E5 code review

Batch 2026-11-01-batch-101, increment 4. Reviewer: code-reviewer (independent of the implementer, the tester and the integrator). Scope: `git diff main...HEAD` at `149e3bf` (4 source files, 1 new test file, 3 edited test files, `AT-TC-REGISTRY.jsonl`, two files under `docs/requirements/review/`). I ran no tests or probes on the Windows PC (operator rule). Evidence comes from reading the code and the integrator's transcripts `evidence/inc-4/int-01` … `int-28`.

## Verdict

**PASS-WITH-NOTES.** No BLOCKER or MAJOR findings. Three MINOR findings are about test strength, and two NITs are about records. None of them changes product behaviour. Every finding below is a recommendation.

## Checks

| # | Check | Result | Evidence state |
|---|---|---|---|
| 1 | Code = graph | All 13 units match `codewire/graph-inc4.md` exactly: the six `a2l_context=self.current_a2l_data` sites (`app.py:4811`, `:5405`, `:5531-5533`, `:7129`, `:7460-7462`, `:7788-7790`), the R-TUI-058.9 condition (`app.py:5535-5547`; it has the graph's three conjuncts and the fixed text), `edit_entry_json(…, a2l_context=None)` forwarded (`change_service.py:1439-1508`), `run_checks_for_project` deleted with its docstring paragraph and the 7 imports only it used (I grepped each one: 0 remaining uses), `_execute_one_variant` reading with `a2l_context=a2l_data` (`variant_execution_service.py:2558-2560`), `_symbol_name_index` (the base loop moved unchanged, `io.py:1083-1123`), `_resolve_symbol_tag` on the index with byte-identical reasons (`io.py:1158-1173`), and `SYMBOL_NO_A2L_CONTEXT_TEXT` (`io.py:253`). | executed (read) |
| 1a | Index built at most once per read, never for a document with no symbol entry | `io.py:900-913`. The `index_built` flag is set on the first in-ceiling dict entry whose `symbol` is a `str`, and the index is built at most once. With an A2L, it is built once. With no A2L, `_symbol_name_index` runs once and returns `None`, so every later symbol entry gets the R-CHG-SYM.2 reason, which is correct. With no string symbol, nothing is built. Entries past `MF_ENTRY_COUNT_CEILING` are not iterated. The integrator's edit (`git diff 906d022 149e3bf`) is exactly the flag. For a dict context it behaves the same as the implementer's `symbol_index is None` check; for a `None` context it removes O(1) repeat calls. Correct, but no test pins it (F1). | executed (read) |
| 2 | Every product read gets the right A2L | Census at HEAD (`grep` of `read_change_document(`, `parse_change_document(`, `.load(`, `.load_text(`, `edit_entry_json(` over `s19_app`): the six session sites use the session A2L, and `_execute_one_variant` uses the project's A2L file. That one function serves both Execute scope (`execute_project_variants` → `validate_project_files`) and the report run. `recorded_document_state` (`app.py:2521`) and the flow reads (`flow_execution_service.py:178`, `:182`, `:522`, `:803`) already declared an A2L and are unchanged. `ChangeService.load` / `load_text` forward theirs. No read was missed. `flow_model.py` and `screens_directionb.py:8140` mention the reader in docstrings only. | executed (read) |
| 2a | R-TUI-058.9 only with `current_a2l_data is None` and the R-CHG-SYM.2 finding | `app.py:5535-5547`: `not result.ok and self.current_a2l_data is None and any(code == "CHG-SYMBOL-UNRESOLVED" and SYMBOL_NO_A2L_CONTEXT_TEXT in message)`. Painted after `_report_change_result`, so it is the last line. Pinned by R-TUI-058.9/1 (exact 3-line list), /2 (code-only mutant) and /3 arm b (guard-dropped mutant). | executed (read); verified (linux, int-28) |
| 2b | Escaping of `ChangeEntry.symbol` (S4-6) | The diff adds no paint of `entry.symbol`. The paints that now become reachable all escape already: `diff_report_service.py:694` `_md_text`, `:2096` `_esc(_strip_ctl(...))`, `report_service.py:1919` `md_safe`. Finding lines keep their `repr` quoting. | executed (read) |
| 3 | Drift check still refuses an address/length mismatch | `io.py:1050-1080` is unchanged and reads `resolved_tag` from the index exactly as base did. `tests/test_changes_symbol_entries.py::test_tc712_symbol_on_string_entry_and_drift_refused_named` (address drift and length drift → `CHG-SYMBOL-VALUE`) passed in int-07, whose only failure is `tc1802` (E-1, environment). R-CHG-SYM.13/1 also asserts 0 issues on 1 000 non-drifting entries. | executed (int-07, int-26/27) |
| 4 | Tests assert exact results, can fail, and were not weakened | The 24 nodes assert exact lines, counts, bytes (read with the independent S19 reader) and call counts. The tester's base run reports 15 RED for behavioural reasons (`red-01-tester-base.txt`). The integrator's test edits: F-1 renamed two tests and changed no assertion. F-4 tightened the bound from 2 × 1.0 s to `timing_bound(1.0)`. The `EXPECTED_SCANNED_TEST_FILES` value 251 was measured by the guard. The `**kwargs` on the two spies forwards the keyword unchanged. `test_headless_project_run` was deleted as D-1 ordered. Nothing was weakened. Strength gaps: F1, F2, F3. | executed (read); verified (linux, int-26/27/28) |
| 5 | SR-1 edit of `docs/requirements/review/` | Minimal and correct, with notes (section SR-1 below). | executed (read) |

## Findings

### F1 — the integrator's `index_built` fix has no test  [MINOR · impl (test)]
- **Where:** `io.py:900-909`; `tests/test_b101_symbol_reads.py:1089-1118`.
- **Scenario:** revert the flag to the implementer's `symbol_index is None`. A read of `demo_patch` with `a2l_context=None` then calls `_symbol_name_index` twice, and all 24 tests still pass, because every counter test passes a context. So the claim in `E4-integration-notes.md` §8 ("M-10 / M-15 now also cover the no-context path") is not backed by any test. The product impact is nil, because the `None` path is O(1). That is why this is MINOR.
- **Suggested fix (software-dev / tester):** add an arm to R-CHG-SYM.13/2: `before = len(calls); doc = parse_change_document(doc_text(case08, PATCH), a2l_context=None); assert len(calls) - before == 1; assert [i.code for i in doc.issues].count("CHG-SYMBOL-UNRESOLVED") == 2`.

### F2 — R-CHG-SYM.11/3 asserts `>= 2` applied and does not assert 0 blocked  [MINOR · impl (test)]
- **Where:** `tests/test_b101_symbol_reads.py:915-917`.
- **Scenario:** case R-CHG-SYM.11/3 expects "both symbol entries applied and 0 entries `blocked`". The tester's own note (§5.5) says 7 applied are expected. A run that applies the 2 symbol entries and blocks some address-only entries would still pass.
- **Suggested fix:** `assert int(match.group(1)) == 7`. Also assert that the change section has no `blocked` disposition, or that the overview's blocked column is `0`.

### F3 — R-CHG-SYM.12/2 does not pin `0 error(s)`, so its negative control rests on an unasserted premise  [MINOR · impl (test)]
- **Where:** `tests/test_b101_symbol_reads.py:988`.
- **Scenario:** the test removes the A2L copy that the attach placed in the project folder (OR-1). It then asserts only the prefix `Execute: scope 'all' finished - 1 variant(s),` and that no patched file exists. If the run errored before the document read, the result would also be "no patched file", and mutant M-14 (the session A2L fed to the run) could not turn it RED. On base, a blocked change document still ends `0 error(s)` (tester notes, R-CHG-SYM.11/2 row), so asserting that is cheap.
- **Suggested fix:** `assert "Execute: scope 'all' finished - 1 variant(s), 0 error(s)" in lines`.

### F4 — the `CODE-CHANGES.md` Totals line was not recounted  [NIT · records]
- **Where:** `docs/requirements/review/CODE-CHANGES.md:9`.
- **Scenario:** D9-7 moved from open to done. The rows now count `done` 14 / `open` 244, while line 9 still says done 13 / open 255. The line is "counted by script", and it already drifted at `main` (the Inc 1 `done differently` row fits none of its categories). So this is the requirements session's recount, not Inc 4's.

### F5 — the R-CHG-SYM.10/4 arm accepts either tail  [NIT · test]
- **Where:** `tests/test_b101_symbol_reads.py:647` `assert lines[2:] in ([], [PLAIN])`.
- **Scenario:** this was tolerant on purpose so the arm holds on base. R-TUI-058.9/1 pins the exact tail, so nothing is lost. Tightening it to `[PLAIN]` is optional.

## SR-1 — the edit to the requirements-session files

**Judgement: minimal and correct. The requirements session should confirm it, as the integrator already recorded.**
- The guard R-DOC-CANON.10 (`test_review_files_name_only_existing_tests`) refuses a code-span citation of a test that does not exist. D-1 (orchestrator) deletes the test. One of the two had to give way, and weakening the guard would be wrong.
- The three edits (`CODE-CHANGES.md:222`, `S9-ears-strict.md:26`, `:288`) remove only the dead name and keep each row's meaning. "Only a test called it … both deleted in batch-101 Inc 4" is accurate. The D9-7 status flip to `done (batch-101 Inc 4)` is the one A-8 forwarded "at integration". The format has no commit hash, matching the Inc 1 row in the same file.
- Nothing else in `docs/requirements/review/` was touched. `docs/requirements/history/` keeps the old name, which is correct for history. The `AT-TC-REGISTRY.jsonl` TC-023 edit drops only the node (10 nodes remain) and leaves the provenance `statement` alone.
- Note for the orchestrator: `S9-ears-strict.md` belongs to the parallel requirements re-write session. Relay the two-line diff to it before its next pass, so the two sessions do not conflict when merging.

## Evidence checklist

- ✓ Diff read in full: `s19_app/` (4 files), `tests/test_b101_symbol_reads.py:1-1279`, the three edited test files, the registry line, and the two review files.
- ✓ Correctness pass: index flag with an A2L, without an A2L, and with no symbol entries; entry ceiling; `{}` context (index `{}` gives R-CHG-SYM.3, same as base); R-TUI-058.9 guard arms; drift limb unchanged.
- ✓ Simplicity pass: no new abstraction beyond the one index function the graph names; the deletion removed 7 imports.
- ✓ Reuse: the index loop was moved, not copied; one shared constant (I-1).
- ✓ Tests reviewed for intent: F1–F3 recorded; no weakening found in the integrator's edits.
- ✓ Verdict explicit: PASS-WITH-NOTES; no HIGH open.

Forwarded (not code-review lane): the stale `run_checks_for_project` docstring mention at `s19_app/tui/changes/check.py:278` (already on the integrator's list); there is nothing for `security-reviewer`.
