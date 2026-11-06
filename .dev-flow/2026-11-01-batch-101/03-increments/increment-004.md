# Increment 004 — Inc 4 · R-CHG-SYM.9…13, R-TUI-058.9 · documents resolve symbols through the loaded A2L; variant and report runs use the project's A2L; lazy name index; headless entry point deleted

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-4/`: `01-requirements.md` (US-SYM-1 … 3, R-CHG-SYM.9 … .13, R-TUI-058.9), `02-test-cases.md` (23 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md`, `E3-rulings.md`, `E3-security.md`, `E4-impl-notes-{app,core,variant}.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc4.md`, and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-4/`. Branch `b101-inc4` from `main` (base `b7b77c4`), head `200cc69` plus the uncommitted E5 records and this packet.

Models per stage (from `steps.log` and the orchestrator's assignment): Opus — E1–E3 (requirements, rulings, both design reviews, the E3 corrective), the E4 integration step, the E5 code and security reviews, the coverage audit and the E5 corrective pass; DeepSeek v4 Pro — the E4 implementers (3 units), the E5 mutant battery, and this record; Sonnet — the E4 independent tester.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `004` |
| Lane (if the batch forked) | none — single lane |
| Requirement(s) | R-CHG-SYM.9 · .10 · .11 · .12 · .13 · R-TUI-058.9 (stories US-SYM-1, US-SYM-2, US-SYM-3) |
| Acceptance | the 23 cases of `02-test-cases.md`; black-box by keys and dialogs: R-CHG-SYM.9/1, /5, R-CHG-SYM.11/2, /3, R-CHG-SYM.12/2 · white-box: the six session reads, the variant/report run and the two call-counter nodes · unit: the 13 changed units of `E1-slice.md` §1 (codewire graph nodes) |
| Agent | `software-dev` |
| Date | 2026-11-06 |

---

## 1 · What changed

A change or check document that the operator loads, pastes, edits as JSON or picks as a check spec now resolves its `symbol` entries against the A2L the session holds, and a variant run (Execute scope or the project report run) resolves them against the project's A2L file — and against nothing implicit. The six session-read sites (`app.py` load, paste, whole-document Edit JSON pre-check, per-entry Edit JSON, Check Editor spec pick, A2B Diff check-spec pick) pass `a2l_context=self.current_a2l_data` into the readers they already call; `ChangeService.edit_entry_json` gains the keyword and forwards it; `_execute_one_variant` passes the project's parsed A2L. To keep a production-size A2L from stalling the screen thread, the tag-name index is now built lazily — at most once per read, on the first entry whose `symbol` is a string, and never for a document with none — inside `changes/io.py` (`_symbol_name_index`, shared constant `SYMBOL_NO_A2L_CONTEXT_TEXT`). When a per-entry Edit JSON confirm records the R-CHG-SYM.2 finding with no A2L loaded, one plain-language line is painted last (R-TUI-058.9). The dead headless entry point `run_checks_for_project` is deleted (D-1 / D9-7) with its test and its 7 now-unused imports.

## 2 · Files modified

Committed: `git diff --stat main...HEAD` (98 files, +8 908 / −213). Uncommitted: the E5 re-audit/re-review edits (`02-test-cases.md`, `E5-corrective-notes.md`, `E5-coverage-audit.md`) and the two new records below (`04-validation.md`, this packet). SOURCE files: **4 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | US-SYM-1 · US-SYM-3 | the six session-read sites pass `a2l_context=self.current_a2l_data` (`_patch_editor_load`, the `parse_paste` arm, `_apply_changeset_json_edit` pre-check, `_apply_entry_json_edit` → `edit_entry_json`, the Check Editor and A2B Diff pick handlers); `_apply_entry_json_edit` paints the R-TUI-058.9 line after `_report_change_result` when the confirm fails, no A2L is loaded and the R-CHG-SYM.2 reason is present |
| `s19_app/tui/changes/io.py` | source | US-SYM-1 | new `_symbol_name_index(a2l_context)` and `SYMBOL_NO_A2L_CONTEXT_TEXT`; `_parse_entries` builds the index lazily via the `index_built` flag (at most once per read, never for a symbol-free document); `_parse_entry` / `_resolve_symbol_tag` look the symbol up in the index instead of rebuilding it |
| `s19_app/tui/services/change_service.py` | source | US-SYM-1 · US-SYM-3 | `edit_entry_json(…, a2l_context: Optional[dict] = None)` added and forwarded to `parse_change_document`; `run_checks_for_project`, its module-docstring paragraph and its 7 imports-only-it-used deleted (D-1 / D9-7) |
| `s19_app/tui/services/variant_execution_service.py` | source | US-SYM-2 | `_execute_one_variant` reads the document with `a2l_context=a2l_data` (the project's A2L file parsed once by the plan) |
| `tests/test_b101_symbol_reads.py` | test | US-SYM-1 · US-SYM-2 · US-SYM-3 | new file: 24 nodes (18 functions, parametrized R-CHG-SYM.10 ×6, R-CHG-SYM.11/2 ×2 arms, R-TUI-058.9/3 ×2 arms); the R-CHG-SYM.13 timing tests renamed `…_of_1000_entries…` (F-1), the R-CHG-SYM.13/3 bound `timing_bound(1.0)` (F-4), the E5 corrective gesture drives and strengthened assertions (C-1 … C-8) |
| `tests/test_checks_engine.py` | test | US-SYM-1 | `test_headless_project_run`, its `run_checks_for_project` import and the `PUBLIC_EXAMPLES` constant deleted (D-1 / A-1 / OR-3); the module docstring's TC-023 bullet and section header reworded |
| `tests/test_id_registry.py` | test | US-SYM-1 | `EXPECTED_SCANNED_TEST_FILES` 250 → 251 (one new test module, measured) |
| `tests/test_tui_patch_editor_v2.py` | test | US-SYM-1 · US-SYM-3 | the two `ChangeService.load` / `load_text` spies accept and forward `**kwargs`; assertions unchanged |
| `AT-TC-REGISTRY.jsonl` | config | US-SYM-1 | TC-023 `nodes` drops the deleted headless project-run test node (D-1); the other 10 nodes stay, TC-023 stays `LIVE` |
| `docs/requirements/review/CODE-CHANGES.md` | doc |  | D9-7 marked `done (batch-101 Inc 4)` and its text reworded to drop the dead test name (SR-1 / F-3) |
| `docs/requirements/review/S9-ears-strict.md` | doc |  | the R-CHK-001 note and D9-7 text reworded without the dead test name (SR-1 / F-3); forwarded to the requirements session 2026-11-05 |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | batch-101 Inc 4 rows appended: S4-1/E5S4-1, E5S4-3, T-02 open, `check.py:278` docstring, `tc1802` clean-clone and b100 save waits |
| `.dev-flow/2026-11-01-batch-101/inc-4/01-requirements.md` | doc |  | EARS requirements: 6 rows (R-CHG-SYM.9, .10 amended; .11, .12, .13, R-TUI-058.9 new) + Definitions (session read, loaded A2L, the project's A2L file, case 08) + US-SYM-1 … 3 |
| `.dev-flow/2026-11-01-batch-101/inc-4/02-test-cases.md` | doc |  | 23 ISO 29119-3 cases over 6 requirements; audited and re-audited at E5 (uncommitted re-audit wording edits) |
| `.dev-flow/2026-11-01-batch-101/inc-4/E1-rulings.md` | doc |  | E1 scope census, canon changes, decisions D-1 … D-4 and the orchestrator rulings |
| `.dev-flow/2026-11-01-batch-101/inc-4/E1-slice.md` | doc |  | E1 implementation slice: 13 units in 4 source files, callers census, tests touched |
| `.dev-flow/2026-11-01-batch-101/inc-4/E3-architect.md` | doc |  | E3 design review: PASS-WITH-NOTES, A-1 HIGH, A-2 … A-4 MAJOR, A-5 … A-9 MINOR |
| `.dev-flow/2026-11-01-batch-101/inc-4/E3-rulings.md` | doc |  | E3 orchestrator rulings A-1 … A-9, S4-1 … S4-8 folded as the E4 addendum |
| `.dev-flow/2026-11-01-batch-101/inc-4/E3-security.md` | doc |  | E3 design security review: PASS-WITH-NOTES, S4-1, S4-2 LOW, S4-3 … S4-9 INFO |
| `.dev-flow/2026-11-01-batch-101/inc-4/E4-impl-notes-app.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, app unit) |
| `.dev-flow/2026-11-01-batch-101/inc-4/E4-impl-notes-core.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, io/change_service core unit) |
| `.dev-flow/2026-11-01-batch-101/inc-4/E4-impl-notes-variant.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, variant unit) |
| `.dev-flow/2026-11-01-batch-101/inc-4/E4-integration-notes.md` | doc |  | E4 integration (Opus): GREEN on the LAN Linux host, F-1 … F-4, L-1, E-1, T-1, OR-1 … OR-4, SR-1, SR-2, §5 timings |
| `.dev-flow/2026-11-01-batch-101/inc-4/E4-tester-notes.md` | doc |  | E4 independent tester (Sonnet) notes: test→case map, RED on base, ambiguities |
| `.dev-flow/2026-11-01-batch-101/inc-4/E5-code-review.md` | doc |  | E5 code review: PASS-WITH-NOTES, F1–F3 MINOR, F4–F5 NIT, SR-1 (uncommitted Re-review section) |
| `.dev-flow/2026-11-01-batch-101/inc-4/E5-corrective-notes.md` | doc |  | E5 corrective pass C-1 … C-8: strengthened tests, gesture drives, final runs and timings (uncommitted `<HOME>` redaction edit) |
| `.dev-flow/2026-11-01-batch-101/inc-4/E5-coverage-audit.md` | doc |  | E5 coverage audit (11/22 changed) + Re-audit (23 cases, all covered; uncommitted section) |
| `.dev-flow/2026-11-01-batch-101/inc-4/E5-mutants.md` | doc |  | E5 mutant table: M-1 … M-15, 15/15 KILLED, no survivors |
| `.dev-flow/2026-11-01-batch-101/inc-4/E5-rulings.md` | doc |  | E5 orchestrator rulings C-1 … C-8 and the routed backlog rows |
| `.dev-flow/2026-11-01-batch-101/inc-4/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES, E5S4-1 LOW, E5S4-2 … 5 INFO |
| `.dev-flow/2026-11-01-batch-101/inc-4/codewire/graph-inc4.md` | doc |  | Code-wire graph of Inc 4: 20 nodes, 3 entities, 0 edges (codewire_lint clean) |
| `.dev-flow/2026-11-01-batch-101/inc-4/steps.log` | doc |  | Stage log, models and UTC stamps (E5 end appended at close) |
| `.dev-flow/2026-11-01-batch-101/inc-4/04-validation.md` | doc |  | This increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-004.md` | doc |  | This packet (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-01.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E5 corrective: the new test file `-n 4 -m "not serial_timing"`, 22 passed (all 22 non-timing nodes named) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-02.txt` | generated | US-SYM-1 | E5 corrective: serial lane `-s`, host load 3.6, 2 passed (record; superseded by e5c-05) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-03-00.txt` … `e5c-03-11.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E5 corrective: importer census, 12 chunks of 8 files (90 files total), `-n 4 -m "not serial_timing"`, 2 737 passed / 1 failed (tc1802) / 97 skipped / 1 xfailed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-03-aborted-3chunk.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E5 corrective: first importer attempt in 3 chunks of 30, killed by its 2400 s timeout; no result drawn |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-04.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E5 corrective: the law guards, 379 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-05.txt` | generated | US-SYM-1 | E5 corrective: quiet serial lane of the new file (load 1.34), 2 passed; the final R-CHG-SYM.13 timings |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-06.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E5 corrective: serial lane over the 90 importer files + `test_suite_hygiene` + `test_id_registry`, 53 passed, 2 skipped; QC-TM 80 bounds, 0 under 20 % |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-mut16.txt` | generated | US-SYM-1 | E5 corrective mutant M-16 (`symbol_index is None`, `io.py:904`): KILLED, "2 time(s), expected exactly 1", `RESTORE_OK` |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-mut17.txt` | generated | US-SYM-1 · US-SYM-3 | E5 corrective mutant M-17 (per-entry confirm returns without reading/replacing, `app.py:5529`): KILLED, `(164,) != (254,)`, `RESTORE_OK` |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-01.txt` … `int-20.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E4 integration lane 1: 20 chunks of 5 files, `-n 8 -m "not serial_timing"`, 3 036 passed / 11 failed / 97 skipped / 1 xfailed (3145 nodes) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-21.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E4 integration: guards + the new file after fix F-1, 126 passed, 1 failed (F-3 found here) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-22.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E4 integration: the 7 non-Inc-4 lane-1 failures serial on the Inc 4 tree, 19 passed, 1 failed (tc1802) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-23.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E4 integration: the same 7 on a clean `origin/main` tree, 18 passed, 2 failed (tc1802 + one b100 under load) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-24.txt` | generated | US-SYM-1 | E4 integration: `test_requirements_canon`, `test_id_registry` after F-3, 23 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-25.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E4 integration: serial lane on a loaded host (load 12), invalid as a measurement |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-26.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E4 integration: serial lane quiet (load 1.28), 53 passed, 2 skipped; R-CHG-SYM.13/1 0.183–0.186 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-27.txt` | generated | US-SYM-1 | E4 integration: the new file's serial nodes with the OR-2 bound (load 0.78), 2 passed; 13/3 addition 0.395 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-28.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E4 integration final: the new file + guards `-n 8 -m "not serial_timing"`, 179 passed, 0 failed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-load.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | E4 integration: host-load record (7–19) that motivated the 20-chunk split |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/mut-00-base.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | Mutant control: the unmutated new file, 22 + 2 passed, all green |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/mut-01.txt` … `mut-15.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | Mutants M-1 … M-15, one per requirement row, each KILLED (restore by sha256, `RESTORE_OK`) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-4/red-01-tester-base.txt` | generated | US-SYM-1 · US-SYM-2 · US-SYM-3 | Tester RED-proof: the 24 nodes on base, 15 failed, 12 passed (the 12 hold on base by design) |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** |
| Test files | 4 (1 new, 3 changed; uncapped) |
| Config files | 1 (`AT-TC-REGISTRY.jsonl`) |
| Doc files | 25 (`.dev-flow` records, the two review files, the backlog; outside the count) |
| Generated | 66 transcripts under `evidence/inc-4/` |

- ⚠ **At exactly 4 source files:** this increment could not be cut smaller. `app.py` owns all six session-read sites; `change_service.py` owns the `edit_entry_json` parameter and the deleted headless function; `variant_execution_service.py` owns the variant/report read; `io.py` owns the reader's lazy index (D-2, ruled in). No ruling pushed the slice past 4, and the E5 corrective pass changed **0** source files.

## 3 · How to test

```bash
# the new file, non-timing lane (LAN Linux host, s19ci Python 3.11)
python -m pytest -q -n 4 -m "not serial_timing" tests/test_b101_symbol_reads.py
# its serial-timing lane, quiet host
python -m pytest -q -s -m serial_timing tests/test_b101_symbol_reads.py
# the law guards of the repo CLAUDE.md
python -m pytest -q -n 4 -m "not serial_timing" tests/test_id_registry.py tests/test_suite_hygiene.py \
  tests/test_engine_unchanged.py tests/test_requirements_canon.py tests/test_tui_patch_editor_v2.py \
  tests/test_checks_engine.py tests/test_tui_directionb.py tests/test_changes_schema.py
# every test file that imports changes.io / change_service / variant_execution_service,
# in chunks of 8 files (the e5c-03-* split), and the serial lane over the same set (e5c-06)
```

All of these ran on the LAN Linux host only (operator rule); nothing ran on the Windows PC. The transcripts are `evidence/inc-4/e5c-01.txt` … `e5c-06.txt`.

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | `tests/test_b101_symbol_reads.py` (24 nodes) | **22 passed** (`e5c-01`) + **2 passed** serial (`e5c-05`); 23 cases, 23 covered / 0 partial / 0 gap after the re-audit |
| **A · neighbours** | every test file importing `changes.io`, `change_service` or `variant_execution_service` (90 files) | **2 737 passed, 1 failed, 97 skipped, 1 xfailed** (`e5c-03-*`); the failure is `tc1802` (E-1, environment, routed) |
| **B · black-box** (keys and dialogs) | R-CHG-SYM.9/1, /5, 11/2, /3, 12/2 end to end | passed in `e5c-01` |
| **Guards** | `test_id_registry`, `test_suite_hygiene`, `test_engine_unchanged`, `test_requirements_canon`, `test_tui_patch_editor_v2`, `test_checks_engine`, `test_tui_directionb`, `test_changes_schema` | **379 passed** (`e5c-04`); serial lane **53 passed, 2 skipped** (`e5c-06`) |

Details: `inc-4/04-validation.md`.

### RED counterfactual

| Field | Value |
|---|---|
| **RED counterfactual** | The 24 nodes of `tests/test_b101_symbol_reads.py` on base `b7b77c4`: **15 failed, 12 passed in 412 s** — every failure is behavioural, and the 12 passes are the design's holds-on-base negative controls (`red-01-tester-base.txt`). The E5 corrective additions each went RED against their own mutation: the M-16 revert (`symbol_index is None`, `io.py:904`) made the new R-CHG-SYM.13/2 no-A2L arm fail ("a read with no declared A2L called the index builder 2 time(s), expected exactly 1") and the M-17 mutation (per-entry confirm returns without reading or replacing, `app.py:5529`) made the new R-CHG-SYM.9/4 second-confirm assertion fail (`(164,) != (254,)`) — `e5c-mut16.txt`, `e5c-mut17.txt`, both `RESTORE_OK` (sha256). |

| Field | Value |
|---|---|
| **Mutation verdicts** | 17 mutants, per-node verdicts in `E5-mutants.md` (M-1 … M-15) and `E5-corrective-notes.md` (M-16, M-17): **17 KILLED, 0 SURVIVED, 0 BAD**. Control `mut-00-base.txt` 22 + 2 passed. Each mutant applied to a detached copy of the four slice files, run, then restored byte-exact (sha256 vs the pre-mutant value, `RESTORE_OK`). No arm stayed GREEN that the row names; M-10 (index rebuilt per entry) failed on the call counter (1 000×, 64 s), M-15 (eager build) failed the address-only counter (1 instead of 0). Transcripts `evidence/inc-4/mut-01.txt` … `mut-15.txt`, `e5c-mut16.txt`, `e5c-mut17.txt`. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their PASS was believed: the new test file on base (15 failed — `red-01-tester-base.txt`); the mutant harness (unmutated copy 22 + 2 passed, every mutant non-zero — `mut-00-base.txt`); the `_symbol_name_index` call counter (M-10 → "index built 1 000×", M-15 → 1 on an address-only read); the coverage audit (first pass changed 11 of 22 cases and found the missing row R-CHG-SYM.13/3 — `E5-coverage-audit.md`). |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts asserted against the form the product emits: the patched variant bytes (R-CHG-SYM.11/2 and /3 assert the project folder holds `firmware-patched.s19` whose bytes at `<tag 2>`'s and `<tag 3>`'s addresses equal `demo_patch` entries 2 and 3, read with the independent S19 reader); the rendered report (R-CHG-SYM.11/3 asserts the overview applied `== 7` and the Modifications table's 7 rows with no Before `-`); the painted status lines, exact (R-CHG-SYM.9/* loads, R-CHG-SYM.10/* refusals, R-TUI-058.9/* exact line lists). All passed in `e5c-01` / `e5c-05`. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 (`sha256sum`) of the bytes at the cited path, taken 2026-11-06. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-4/`, the home `artifact_homes.evidence` declares.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| e5c-01.txt | evidence/inc-4/e5c-01.txt | 5e9f7d9ccf6fe7fc37276e856db1ec9cd8dda078df10df05ca002a360cc3722d |
| e5c-02.txt | evidence/inc-4/e5c-02.txt | 8ae4b27055a7d1469bd4405fb2ae7d0c2cea4ae42d20ff73c72c90ccedf16287 |
| e5c-03-00.txt | evidence/inc-4/e5c-03-00.txt | 1af64dacc3a940e9734d580515cb6d8db569cc6522670e2137596b37f325da34 |
| e5c-03-01.txt | evidence/inc-4/e5c-03-01.txt | d6d0356f76707d20b8673b98ae276ff626e4f3d973257f9d87f29cf4ff5500c5 |
| e5c-03-02.txt | evidence/inc-4/e5c-03-02.txt | 6b6f950aab0e540d033406bed0aeb1ca1c9d678464035c2ddde21885038e92c0 |
| e5c-03-03.txt | evidence/inc-4/e5c-03-03.txt | c4808d06bee4c44cf377b64b3aca1dcbd2f10463bac6793cc3994b6a4a8e134e |
| e5c-03-04.txt | evidence/inc-4/e5c-03-04.txt | 40125dbd669e977957dd913a4bd876c5d99c76038058a4b8c3d13d4c4f071500 |
| e5c-03-05.txt | evidence/inc-4/e5c-03-05.txt | 39c4a49f6219ad4c1c923817108894818cc2e0271f15021fb99952830c9b5809 |
| e5c-03-06.txt | evidence/inc-4/e5c-03-06.txt | 228077e2c170b1b1fddd6f495311b2cfd1e24421f5a9fb65b9db9660ed173d9a |
| e5c-03-07.txt | evidence/inc-4/e5c-03-07.txt | 935f4451acc175c601a0b3f34f8c1ef2928697daa29d0eb5217bd800515b6248 |
| e5c-03-08.txt | evidence/inc-4/e5c-03-08.txt | b2f2a4365a5d3f987dadc5f3509fd9e83ac38417af91704db83b006e2dc33963 |
| e5c-03-09.txt | evidence/inc-4/e5c-03-09.txt | 53e4fa73f5d2f03bc50831ee8c52113746caed49dca2e68fc04a0bab189f1015 |
| e5c-03-10.txt | evidence/inc-4/e5c-03-10.txt | 8509644735a7da2c2fba3212a1ce1544d1226591454477a96f5e06760f63c2ca |
| e5c-03-11.txt | evidence/inc-4/e5c-03-11.txt | 1bf32da29f21906239e23329de39a9e8103c37b1be2d6e52441e40b594829ae5 |
| e5c-03-aborted-3chunk.txt | evidence/inc-4/e5c-03-aborted-3chunk.txt | f217015f4beb6b34bd476b3adf145af628d9be0e58dec67c3d56c436780fdac8 |
| e5c-04.txt | evidence/inc-4/e5c-04.txt | bc2f7bb9da2341beaefb96a136559fd5c3aebd74e353bc638ba5ea9b74321a31 |
| e5c-05.txt | evidence/inc-4/e5c-05.txt | 144a321e345e908bd15d64e5e216e8ced190464a3f3fb70b81ac2ab662bcd58a |
| e5c-06.txt | evidence/inc-4/e5c-06.txt | 51c33e8ed35f7bfc913f0c3882cf1421c2b169e36b03319d89f322e901b1e695 |
| e5c-mut16.txt | evidence/inc-4/e5c-mut16.txt | f5a68c86f2a5736068db685250391c8e51ba872816031955c08076fe35625b56 |
| e5c-mut17.txt | evidence/inc-4/e5c-mut17.txt | dc6d67d889ce7c7df34bf50e12a9f0cd49f409c9343d2f960520852b07e60f5a |
| int-01.txt | evidence/inc-4/int-01.txt | fc0ad4ed68b7fac94bc86bd72d020a6360d832fe48ff6856880b2b060fd7edba |
| int-02.txt | evidence/inc-4/int-02.txt | 1c553bc64b1e4b14e65c56d9ea98153e8a23a869029a4e41e0538cd09cf1e3bc |
| int-03.txt | evidence/inc-4/int-03.txt | 0bc2a0e8e076f35a2fcdf76ad00108b1a85bc0897478439e809899ea48cf85bf |
| int-04.txt | evidence/inc-4/int-04.txt | 64041b76eb759304576c2bd33e099eb3b5eae85474f23bb5505f5805d488b501 |
| int-05.txt | evidence/inc-4/int-05.txt | 81a84312af0ed5373054b17f4747a7a73be9295ec835c161093ffe22f3960b45 |
| int-06.txt | evidence/inc-4/int-06.txt | cee718fe884791c17164a25c7a755b151b5bc48f0a705782e2a857a535c3a6de |
| int-07.txt | evidence/inc-4/int-07.txt | 9515382d390656c363ade6d49ef56c278cea208e7777d510eb1b024341ca22a8 |
| int-08.txt | evidence/inc-4/int-08.txt | 1df1dd98d21be3503ee0cca6668e6230226c8491cd71d9b8eabd80b5862d6c7e |
| int-09.txt | evidence/inc-4/int-09.txt | 8086cebfdd4818761dd69abb1bfface59d6e3b199f4b0ec3881fc6d386066e9f |
| int-10.txt | evidence/inc-4/int-10.txt | c19474ce70e06e3e190c9e9756e7e4b1f9021de6b5bf983cc94a2fbc62e362a6 |
| int-11.txt | evidence/inc-4/int-11.txt | f305fc3f05bfb0bf4503b90142b3ef3cbb7bca94418ae77d74fd9a203700d49c |
| int-12.txt | evidence/inc-4/int-12.txt | 13d1cc17ed367728eb2f98cd443a159d6508ce9e651b627c30ce8af435031244 |
| int-13.txt | evidence/inc-4/int-13.txt | b307943a0dce1e439c0321543038661b91892844942a482ea8480ebbea2fd72b |
| int-14.txt | evidence/inc-4/int-14.txt | bd8fc280d98a3a7139e1afecf36eb95ce7c52215d7d4ca14435a29389f79fe74 |
| int-15.txt | evidence/inc-4/int-15.txt | 9192c9cf6a2ef1d3aeb7fa1f8673b318de8802b8db0f189f1e17cc1fac750a7d |
| int-16.txt | evidence/inc-4/int-16.txt | 86dc824f0b9e4dc432ac71300fe2b2b00a8a929589f9c4a98fd5c07f4f5b075a |
| int-17.txt | evidence/inc-4/int-17.txt | 42ed1ad4b65c5aaaac87cccdbc641cc9275b702acc7055b3a22af0aa3c0d1dcc |
| int-18.txt | evidence/inc-4/int-18.txt | ed8e99d6292d79f458a4f24f8298a61c644334ced2d7b43e8408e1ebd4c50927 |
| int-19.txt | evidence/inc-4/int-19.txt | 992cbae09596886555fa436b94c87895344671bbd295295dd653bb9972950cde |
| int-20.txt | evidence/inc-4/int-20.txt | ef378302f58500977e70628f108d578ae2c6951b6a76cd9f6d56166cecd1e126 |
| int-21.txt | evidence/inc-4/int-21.txt | 236ab19298385b0c0085493da332ddd995b1dfd1a903a9dc3c22e88a60d69410 |
| int-22.txt | evidence/inc-4/int-22.txt | 0b03e4732845cbabcc2c5878465947fc0e28f268516fd1983bd875aded1e6f0b |
| int-23.txt | evidence/inc-4/int-23.txt | 0dd8cc5aa6fc8642cf7763fd77bab3e918ed8023a694d1884b20658641b2d394 |
| int-24.txt | evidence/inc-4/int-24.txt | d788b8df303cc374ae5709f544dca7a52b7d24a5a7b08c0ae3f21a22d7bf3954 |
| int-25.txt | evidence/inc-4/int-25.txt | d4b936de10f9195e74a0986511255797f165edfba4f57db1faf2d77638e1fdd |
| int-26.txt | evidence/inc-4/int-26.txt | 2244f024b0ac0411fd3888dab151c9ba0aefbb5bbfb1d153b7e3b9025b134e8f |
| int-27.txt | evidence/inc-4/int-27.txt | f708af7e2128d4c054902a00ea7c06953eece098b9f5294a4c00e3101bd1cfd2 |
| int-28.txt | evidence/inc-4/int-28.txt | bb04517b8cfbcc7bb7d98875c7edb3a4588458d4302ff0c540a9edbd6ced31a3 |
| int-load.txt | evidence/inc-4/int-load.txt | b466205a356b050ac165470f2bb4213208756791c2d2889f1df89fceb5d62bca |
| mut-00-base.txt | evidence/inc-4/mut-00-base.txt | 09403669b449eb6981ce232a7c51d863eca2432c519a9b3b7a95412ceae2554b |
| mut-01.txt | evidence/inc-4/mut-01.txt | 3909b615dc7d4fd2442a39649264375554bd84ceb09a89152262f7b5e1fdbbb5 |
| mut-02.txt | evidence/inc-4/mut-02.txt | f7c71696be037d055c3e8b7bc13de1866f68e81ef2a7d6151d43dfa7c9775e89 |
| mut-03.txt | evidence/inc-4/mut-03.txt | 484e14020acc74588a35ae2848c03ed94650a3b06837965f602cba3c94f222e9 |
| mut-04.txt | evidence/inc-4/mut-04.txt | 2aa043b693d91a510eff99ca33fb7eb218c02abab693c82a0ff076c77ac64f5c |
| mut-05.txt | evidence/inc-4/mut-05.txt | 3948f90841f1168c48076a49d9a3f7f18c097239f9f511474c022418d752a086 |
| mut-06.txt | evidence/inc-4/mut-06.txt | e3620f0c1c86cc3271b1ebb0d62eeedead337a13b8c3a5e240aa9c039ce5ae0a |
| mut-07.txt | evidence/inc-4/mut-07.txt | 7d172b4525ca2c1847e334935ab2ee8f2f3b9452ddfbdbfb3989de19d0261ef2 |
| mut-08.txt | evidence/inc-4/mut-08.txt | 18f6b13da56979c620d8146257278ef84164c8630dcc0d0a58ed531defb57341 |
| mut-09.txt | evidence/inc-4/mut-09.txt | 04af5072a06f5b57aa7f5ffbabcb5d4473fbc13c162a3c60f04a792dd982f51c |
| mut-10.txt | evidence/inc-4/mut-10.txt | aff21eeb2dfa1a3e601e7f5c77fba1ef20c52cd69e3475693d4de40a946dc8d0 |
| mut-11.txt | evidence/inc-4/mut-11.txt | 017198934650eb829313eeea76542c77a306b15e736ec6b59b2d450a059f4ff2 |
| mut-12.txt | evidence/inc-4/mut-12.txt | 97aa9bbcb3e22de4397fe2f4c007403f4ff150761766848054af175b0dbc3049 |
| mut-13.txt | evidence/inc-4/mut-13.txt | 607f5dbc8bde7063d4b063570e2e30a322372580eeac0de882f8c4cc2e9dd689 |
| mut-14.txt | evidence/inc-4/mut-14.txt | 7f74315999553022165bfdf69de4485a68862a4c569a4be59eec827ce40c3bae |
| mut-15.txt | evidence/inc-4/mut-15.txt | a1901d77bcff015a07139f016dd07899f4ed5660f8a2ee2c141cdb8cc3228c20 |
| red-01-tester-base.txt | evidence/inc-4/red-01-tester-base.txt | f8097c045070b504d4068bbebe2040da37f042950ea01a9eaac9716c781920fb |

| Field | Value |
|---|---|
| **Evidence files** | 66 transcripts, each cited with the digest of its stored bytes, all under the home `artifact_homes.evidence` names |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: "no product code changed in the E5 corrective pass" (0 source files) and "no read missed the A2L parameter" (the E1/E3 call census finds no other product call that turns document text into a `ChangeDocument`) |
| If the result is an ABSENCE, what made the search wide enough | the read census `grep -rnE "read_change_document\(|parse_change_document\(|\.load_text\(|service\.load\(" s19_app` (docstrings excluded) — 10 sites enumerated in `E1-rulings.md` §1 and re-checked by the code review's `grep` over `s19_app` |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_r_chg_sym_13_read_without_symbol_entries_builds_no_index` (the 13/2 arm: a no-A2L read calls `_symbol_name_index` at most once — M-16 pins it); `test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` (the spelling-through-the-shared-reader clause) |
| Conjunctive criteria: one mutation per conjunct | R-TUI-058.9's condition has three conjuncts; M-11 (code alone) and M-13 (guard dropped) each kill one, M-12 kills the line — one mutation per conjunct |
| Synthetic instance of the absent case | the planted 220 040-tag context and 1 000-entry document of R-CHG-SYM.13/1 and /3 (case_06's tag count) |
| **Positive control for every probe that returned an ABSENCE** | M-10 (index rebuilt per entry) turned the counter to 1 000 and M-15 (eager build) turned the address-only counter to 1 — the same counter probe that reads 0/1 on head (`mut-10.txt`, `mut-15.txt`) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | every test file importing `changes.io`, `change_service` or `variant_execution_service`, one run each (90 files, grep at the tree fingerprint) | 2 737 passed, 1 failed (tc1802, environment), 97 skipped, 1 xfailed (`e5c-03-*`) |
| B2 file moved on disk | no file moved; `run_checks_for_project` (a function, not a file) deleted | 0 product readers; the stale docstring `s19_app/tui/changes/check.py:278` remains (backlog row); the test's own docstring reworded |
| B3 byte-identical golden captures this source | `grep` over `tests/goldens/**` for the four changed sources | no hit — no golden captures `app.py`, `io.py`, `change_service.py` or `variant_execution_service.py` |
| B4 artifact produced here is consumed elsewhere | the patched variant file and the report the variant/report run writes | consumed by the R-CHG-SYM.11/2, /3 tests (independent S19 reader) and the report worker (`app.py:6566`) |
| A3 interface consumed by another module changed | `ChangeService.edit_entry_json(…, a2l_context=None)` (additive keyword); `run_checks_for_project` deleted; `_execute_one_variant` signature unchanged | `grep -rn "run_checks_for_project(" s19_app`: only the definition (now deleted) and docstrings; the one `edit_entry_json` caller passes the keyword |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict: B1 re-validated every hit by running it (the one failure is the routed environment failure tc1802); B2 found only the stale docstring; B3 no hits; B4 the two test consumers; A3 the additive keyword and the deleted function with no caller. |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| case records that no longer matched the strengthened tests or the audit | every `02-test-cases.md` row whose Expected, Tests or Coverage no longer matches its test | the coverage audit's row-by-row read (`E5-coverage-audit.md` §2, C-1 … C-13) | 11 substantive + the record-wide Coverage vocabulary fix (all 22 rows) + 1 missing row (R-CHG-SYM.13/3) | all, by the E5 corrective pass (rulings C-1 … C-8) | none; re-audit: 23 cases, 23 covered, 0 partial, 0 gap |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated by the audit (§2 C-1 … C-13) before the corrective pass edited its first site: 11 substantive case-record changes + the Coverage-column vocabulary fix across all 22 rows + the missing R-CHG-SYM.13/3 row. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `251 = 250 − 0 + 1` (`tests/test_id_registry.py`, measured). Test cases `23 = 19 + 3 + 1` (E1 19, E3 +11/3 +12/2 +13/2, E5 +13/3). One test node deleted (`test_headless_project_run`, D-1) and 24 nodes added in the new file; no other function renamed or deleted, no assertion weakened (`E5-corrective-notes.md` §1).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** (0 HIGH; F1–F3 MINOR on test strength, F4–F5 NIT on records, SR-1 judged minimal and correct — all folded by the corrective pass and re-read in the Re-review) — `inc-4/E5-code-review.md`. `security-reviewer` · **PASS-WITH-NOTES** (0 HIGH; E5S4-1 LOW, E5S4-2 … 5 INFO; no new permission, trigger, action, sink or secret) — `inc-4/E5-security.md`. `qa-reviewer` coverage audit (11/22 changed, 4 full → partial, + the missing R-CHG-SYM.13/3) and re-audit (23 cases, 23 covered, 0 partial, 0 gap, 17/17 mutants, 0 black-box ATs owed) — `inc-4/E5-coverage-audit.md`. **Design reviews (E3, code-free):** `architect` **PASS-WITH-NOTES** (A-1 HIGH folded into the records by `E3-rulings.md`, A-2 … A-4 MAJOR, A-5 … A-9 MINOR) · `security-reviewer` **PASS-WITH-NOTES** (S4-1, S4-2 LOW, S4-3 … S4-9 INFO) — `inc-4/E3-architect.md`, `inc-4/E3-security.md`. The independent `tester` (E4, Sonnet) wrote the 24 nodes from the design records only and ran them RED on base — `inc-4/E4-tester-notes.md`. |

## 5 · Risks

- **A variant run now writes `<variant>-patched.s19` where a symbol document was blocked before** (R-CHG-SYM.11, A-4): the save-back path is unchanged, but this is a new observable side effect on Execute scope and the report run.
- **The O(n²) collision check remains** at the 100 000-entry ceiling (`changes/validate.py:45`, E5S4-3): ~12 min projected on the screen thread, same as base; a hostile change document at the ceiling freezes the TUI.
- **A link or reparse point named `*.a2l` in the project folder is still accepted** (S4-1/E5S4-1, LOW): a hostile linked A2L can refuse entries but cannot move a write (the drift limb holds); the `lstat` refusal is routed to Inc 9.
- **A session read uses whatever A2L the session holds**, even one that does not belong to the loaded image (S4-8): it only changes which entries are admitted, never what is written; the variant run re-reads against the project's A2L, so editor and run can disagree.
- **`tc1802` fails on clean clones** (reads an untracked, excluded prototype file) and the b100 save/save-dialog pilot waits flake under host load (L-1): both are environment, not Inc 4.

## 6 · Pending

- **`tc1802` on clean clones** — routed to the backlog; **Inc 14 re-bodies it**.
- **The full suite at batch end** — this increment ran its slice, every importer and every law guard in lanes, but not all 3 000+ nodes in one lane.
- **Cross-ownership edit** — `docs/requirements/review/S9-ears-strict.md` and `CODE-CHANGES.md` (the dead test-name rewording and D9-7 `done`) are forwarded to the requirements session 2026-11-05 for confirmation; `docs/requirements/history/` keeps the old name.
- **S4-1 / E5S4-1** (refuse a link/reparse point as the project's A2L) — routed with Inc 9 (S8-1/S8-2).
- **E5S4-3** (sort-and-sweep collision check) and **T-02** (open after Inc 4, needs `check.py`) and the stale `check.py:278` docstring — backlog rows.
- **Uncommitted records** — this packet, `04-validation.md`, the E5 re-audit/re-review sections and the corrective-note redaction edit are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 4; run the full suite at batch end; hand the `S9-ears-strict.md` / `CODE-CHANGES.md` wording to the requirements session; open Inc 9 with S4-1/E5S4-1 in its first slice.
