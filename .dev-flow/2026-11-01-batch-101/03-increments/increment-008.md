# Increment 008 — Inc 8 · R-FLOW-EXT, R-FLOW-CRC, R-CRC-CONFIG · external-step copy and in-place reads, CRC model and refusal reasons

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-8/`: `01-requirements.md` (US-I8-1 … 4, 18 requirement rows), `02-test-cases.md` (99 cases), `E1-rulings.md`, `E1-slice.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E3-r2.md`, `E4-impl-notes.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `release-note-crc.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc8.md`, and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-8/`. Branch `b101-inc8` from `main` (`e266395`), head `dff4304` plus the uncommitted records listed in §2.

Models per stage (from `steps.log` and the orchestrator's assignment): Opus — E1–E3 (requirements, rulings, both design reviews, the E3 corrective), the E4 integration step, the E5 code and security reviews, the coverage audit and re-audit, and the E5 corrective pass; Kimi K2.8 — the E4 implementer and the independent tester (the Kimi weekly quota was exhausted on 2026-11-05: the E5 mutant run was refused with a 429 and rerouted); Sonnet — the E5 mutant battery and this record.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `008` |
| Requirement(s) | R-CRC-ENGINE-001.1, R-CRC-ENGINE-002.2, R-CRC-DESIGNER-001.1, R-CRC-CONFIG-001.10, .11, .16, .17, R-FLOW-CRC.1, .3, .4, .9, R-FLOW-EXT.2, .9, .10, .11, .12, .13, .14 |
| Acceptance | 99 cases of `02-test-cases.md`; nodes in `tests/test_b101_crc_model_and_reasons.py` (G1) and `tests/test_b101_flow_ext_copy.py` (G2); 7 black-box ATs owed (§6) |
| Agent | `software-dev` (Kimi K2.8 implementer), independent `tester` (Kimi K2.8) |
| Date | 2026-11-05 |

## 1. What changed

Two operator-visible fixes and one new behaviour. (1) **D13-20, a wrong-result fix:** the CRC operation (Operations check and write) and the Flow CRC block now compute the CRC by the parametric model: the register starts at `init` as written. Earlier versions bit-reversed `init` first when `reverse` was true; only a config with `reverse: true` and an init that is not bit-symmetric changes (KAT message, poly `0x04C11DB7`, init `0x12345678`, final XOR `0xFFFFFFFF`: `0x18026B2A` before, `0x0F8B7431` now, equal to the CRC Designer). (2) **Config reasons (F-28, D13-23):** a missing or non-numeric CRC config field is named (`field 'reverse' is missing`, `field 'init' is not a number: "zz"`, the value clipped to 64 characters), a CRC Designer template given to a CRC block is refused as such, and a config that nests too deep gives a reason instead of an exit. (3) **External-step outputs (F-49, D15-17):** a relative log or output path is read under the project folder (and refused when it climbs above it); a later block of the same run that names the output file reads the copy of this run's output, and says so with the read suffix ` · read <copy> in place of <ref>` in its summary, the flow and chain-set reports and the chain-set input provenance. The Flow CRC block reads its config through the size-bounded reader. The release note for (1) is `inc-8/release-note-crc.md`.

## 2. Files modified

Committed: `git diff --stat main...HEAD` (59 files, +11 417 / −55). Uncommitted: the E5 re-review and re-audit sections, the graph correction, the backlog rows, `04-validation.md` and this packet. SOURCE files: **4 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/operations/crc.py` | source | US-I8-3 | `crc32_stream` seeds the register with `init` as given (one line); docstring updated (+3 / −2) |
| `s19_app/tui/operations/crc_config.py` | source | US-I8-1, US-I8-2 | named-field reasons, 64-character `_clipped_json` echo (lazy encoder, F1), Designer-template refusal, `RecursionError` reason (+140 / −29) |
| `s19_app/tui/services/flow_execution_service.py` | source | US-I8-1, US-I8-4 | CRC block reads through `read_crc_config_text`; external-step branch (relative paths under the project, climb refusal, log-then-output order, rebind of later refs to the copy, read suffix, provenance) (+251 / −23) |
| `s19_app/tui/services/flow_model.py` | source | US-I8-4 | `FlowRunResult.in_place_reads` (additive field, default empty) (+6) |
| `tests/test_b101_crc_model_and_reasons.py` | test | US-I8-1, US-I8-2, US-I8-3 | New G1 file (+769): CRC grid against the Designer engine, catalogue checks, reasons, template, nesting, dialog tests by keys |
| `tests/test_b101_flow_ext_copy.py` | test | US-I8-1, US-I8-4 | New G2 file (+1734): rebind, suffix, reports, provenance, climb and order, shipped cap, 18.9 path |
| `tests/test_id_registry.py` | test | US-I8-3, US-I8-4 | `EXPECTED_SCANNED_TEST_FILES` 246 → 248 (the two new files; measured) |
| `tests/test_flow_crc_block.py` | test | US-I8-2 | One-line docstring naming R-FLOW-CRC.1 on the existing `test_at123_crc_computed_and_injected_at_output_address` (trace link; no assertion changed) |
| `.dev-flow/2026-11-01-batch-101/inc-8/01-requirements.md` | doc |  | EARS requirements: 4 user stories, 18 rows (R-CRC-ENGINE, R-CRC-DESIGNER, R-CRC-CONFIG, R-FLOW-CRC, R-FLOW-EXT), definitions, operator-facing changes |
| `.dev-flow/2026-11-01-batch-101/inc-8/02-test-cases.md` | doc |  | 99 ISO 29119-3 cases over 18 requirements (82 at E1/E3, 17 added by the E5 corrective pass); coverage 96 covered, 3 partial after the re-audit |
| `.dev-flow/2026-11-01-batch-101/inc-8/E1-rulings.md` | doc |  | E1 rulings (scope, decisions and reasons) and the orchestrator rulings |
| `.dev-flow/2026-11-01-batch-101/inc-8/E1-slice.md` | doc |  | E1 implementation slice: the nodes and the owed tests |
| `.dev-flow/2026-11-01-batch-101/inc-8/E3-architect.md` | doc |  | E3 design review round 1: FAIL, A-1 and A-2 MAJOR, A-3 ... A-8 MINOR; the CRC model verified independently |
| `.dev-flow/2026-11-01-batch-101/inc-8/E3-r2.md` | doc |  | E3 round 2 (architect): PASS-WITH-NOTES, A-1, A-2, S-1, S-2 closed; N-1 ... N-4 |
| `.dev-flow/2026-11-01-batch-101/inc-8/E3-rulings.md` | doc |  | E3 round 1 rulings and E4 addenda; slice at 4 source files |
| `.dev-flow/2026-11-01-batch-101/inc-8/E3-security.md` | doc |  | E3 security review round 1: FAIL, S-1 and S-2 MAJOR, S-3 ... S-8 MINOR |
| `.dev-flow/2026-11-01-batch-101/inc-8/E4-impl-notes.md` | doc |  | E4 implementer (Kimi K2.8) notes, per node |
| `.dev-flow/2026-11-01-batch-101/inc-8/E4-integration-notes.md` | doc |  | E4 integration (Opus): 22 first-run failures, 0 source fixes, GREEN 1218 on 51 files, RED on base 64/18; SR-1 ... SR-6 |
| `.dev-flow/2026-11-01-batch-101/inc-8/E4-tester-notes.md` | doc |  | E4 independent tester (Kimi K2.8) notes: the tests, RED on base |
| `.dev-flow/2026-11-01-batch-101/inc-8/E5-code-review.md` | doc |  | E5 code review: FAIL, BLOCK-UNTIL F1, F2; Re-review: PASS (uncommitted section) |
| `.dev-flow/2026-11-01-batch-101/inc-8/E5-corrective-notes.md` | doc |  | E5 corrective pass C-1 ... C-9: outcomes, test-file changes, record changes, final runs |
| `.dev-flow/2026-11-01-batch-101/inc-8/E5-coverage-audit.md` | doc |  | E5 coverage audit and Re-audit: 99 cases, 96 covered, 3 partial, 0 gap (uncommitted section) |
| `.dev-flow/2026-11-01-batch-101/inc-8/E5-mutants.md` | doc |  | E5 mutant table: 20 mutants, 20/20 KILLED, no survivors |
| `.dev-flow/2026-11-01-batch-101/inc-8/E5-rulings.md` | doc |  | E5 orchestrator rulings C-1 ... C-9 and the routed rows |
| `.dev-flow/2026-11-01-batch-101/inc-8/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES, S8-1 ... S8-4 |
| `.dev-flow/2026-11-01-batch-101/inc-8/codewire/graph-inc8.md` | doc |  | Code-wire graph of Inc 8; node `_number_field` corrected to `_clipped_json` (E5 F1, uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-8/release-note-crc.md` | doc |  | Release note: CRC init with `reverse` (v1.0.0), detection rule and exact migration |
| `.dev-flow/2026-11-01-batch-101/inc-8/steps.log` | doc |  | Stage log, models and UTC stamps (E5 end appended) |
| `.dev-flow/2026-11-01-batch-101/inc-8/04-validation.md` | doc |  | This increment's validation record (uncommitted) |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | 10 rows appended after the batch-101 P0 rows (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-008.md` | doc |  | This packet (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/red-01-tester-base.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | Tester RED-proof: the two new files on base e266395, 64 failed, 18 passed in 40.33 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/int-01-new-tests-first.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | Integration: the files as delivered on the merged tree, 22 failed, 60 passed in 43.79 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/int-02-new-tests-premerge.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | Integration: the same files on pre-merge 499d15d, the same 22 failed, 60 passed in 43.46 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/int-03-red-on-main.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | Integration RED on base: corrected files on origin/main f11b3f4, 64 failed, 18 passed in 46.25 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/int-04-tree-touched-and-neighbours.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | Integration GREEN: 51 files one by one, 1218 passed, 1 skipped, 0 failed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/impl-smoke.txt` | generated | US-I8-1, US-I8-2 | E4 implementer smoke transcript (redacted), probes of the new reasons |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-00-base.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | Mutant control run on the unmutated copy: 82 passed in 26.57 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M01.txt` | generated | US-I8-3 | M01 crc32_stream seeds the reflected init: KILLED, 7 failed, 75 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M02.txt` | generated | US-I8-3 | M02 Designer engines reflect the init: KILLED, 4 failed, 78 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M03.txt` | generated | US-I8-2 | M03 reason from the bare key: KILLED, 10 failed, 72 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M04.txt` | generated | US-I8-2 | M04 parser's own message passed through: KILLED, 8 failed, 74 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M05.txt` | generated | US-I8-2 | M05 64-character clip removed: KILLED, 1 failed, 81 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M06.txt` | generated | US-I8-1 | M06 (and M10) Designer-template check deleted: KILLED, 5 failed, 77 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M07.txt` | generated | US-I8-2 | M07 RecursionError dropped from the reader's caught faults: KILLED, 2 failed, 80 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M08.txt` | generated | US-I8-1 | M08 CRC block skips inject_crcs: KILLED, 2 failed, 80 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M09.txt` | generated | US-I8-1 | M09 summary text `config unresolved` changed: KILLED, 1 failed, 81 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M11.txt` | generated | US-I8-1 | M11 CRC config read with no cap: KILLED, 1 failed, 81 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M12.txt` | generated | US-I8-4 | M12 relative output read against the working directory: KILLED, 2 failed, 80 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M13.txt` | generated | US-I8-4 | M13 later refs resolved without the copy: KILLED, 26 failed, 56 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M14.txt` | generated | US-I8-4 | M14 rebind lookup before the project-ref guard: KILLED, 1 failed, 81 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M15a.txt` | generated | US-I8-4 | M15a change records keep the declared document ref: KILLED, 2 failed, 80 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M15b.txt` | generated | US-I8-4 | M15b A2L refs keep the declared ref: KILLED, 2 failed, 80 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M16.txt` | generated | US-I8-4 | M16 read suffix dropped: KILLED, 14 failed, 68 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M17.txt` | generated | US-I8-4 | M17 provenance keeps the pre-run input: KILLED, 1 failed, 81 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M18.txt` | generated | US-I8-4 | M18 climb check always False: KILLED, 2 failed, 80 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/mut-M19.txt` | generated | US-I8-4 | M19 rotate (earlier copy renamed): KILLED, 23 failed, 59 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/e5c-01-red-f1-f2.txt` | generated | US-I8-2, US-I8-4 | E5 corrective RED: F1 and F2 tests on the delivered code, 3 failed, 1 passed in 166.01 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/e5c-02-green-f1-f2.txt` | generated | US-I8-2, US-I8-4 | E5 corrective GREEN: the same four tests, 4 passed in 24.36 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/e5c-03-new-files.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | E5 corrective: the two Inc 8 files, 97 passed in 54.37 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/e5c-04-touched-module-importers.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | E5 corrective: 47 importer files, one run each, 1189 passed, 1 failed (tc_b97_55, flaky) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/e5c-05-law-guards.txt` | generated | US-I8-3 | E5 corrective: law guards, 27 passed, 181 deselected |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-8/e5c-06-rerun-b97-flow-execution.txt` | generated | US-I8-1, US-I8-2, US-I8-3, US-I8-4 | E5 corrective: test_b97_flow_execution.py whole again, 75 passed in 438.18 s |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** |
| Test files | 3 (2 new, 1 changed; uncapped) |
| Doc files | 23 (`.dev-flow` records and the backlog; outside the count) |
| Generated | 32 transcripts under `evidence/inc-8/` |

- ⚠ **At exactly 4 source files:** this increment could not be cut smaller. `crc.py` is the one-line model fix; `crc_config.py` owns the reasons; `flow_execution_service.py` owns the CRC block and the external-step branch; `flow_model.py` joined at E3 round 1 (`FlowRunResult.in_place_reads`) because the chain-set report must name the copy (S-2) and no other increment owns that file. No ruling pushed the slice past 4 (`E3-rulings.md` §1). The E5 corrective pass touched two of the four (`crc_config.py`, `flow_execution_service.py`).

## 3. How to test

```bash
# the two Inc 8 files (Windows; 97 passed)
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. \
  python -m pytest -q tests/test_b101_crc_model_and_reasons.py tests/test_b101_flow_ext_copy.py
# the law guards of the repo CLAUDE.md (27 passed)
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. \
  python -m pytest -q tests/test_id_registry.py tests/test_engine_unchanged.py tests/test_requirements_canon.py
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. \
  python -m pytest -q tests/test_tui_directionb.py -k test_tc031
# every test file that imports a touched module: one pytest run per file (47 files at e5c-04)
```

The guard run is `evidence/inc-8/e5c-05-law-guards.txt`. Run the touched-module importers one file per run, as `e5c-04` did; a single combined run was not made. The transcripts also redirected `LOCALAPPDATA` and `--basetemp` to a temporary folder and used `-p no:cacheprovider`; do the same. These commands were run on Windows only; on Linux they are untested.

## 4. Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | G1 `test_b101_crc_model_and_reasons.py`, G2 `test_b101_flow_ext_copy.py` | **97 passed in 54.37 s** (`e5c-03`); 99 cases, 96 covered / 3 partial / 0 gap after the re-audit |
| **A · neighbours** | 47 importer files, one run each | **1189 passed, 1 failed** (`e5c-04`): `tc_b97_55`, flaky; whole file 75 passed on rerun (`e5c-06`). Earlier GREEN: 1218 passed, 1 skipped on 51 files (`int-04`) |
| **B · black-box** (keys and dialogs) | 001.11/8, 001.11/10, 001.16/5, 001.17/2 by keys; 9/11 Run and confirm by keys, lane read as painted | passed in `e5c-03`; ATs A-2 … A-7 owed (§6) |
| **Guards** | `test_id_registry`, `test_engine_unchanged`, `test_requirements_canon`, `test_tc031` | **27 passed, 181 deselected** (`e5c-05`) |

Windows only (win32, Python 3.11.15). No Linux run. Details: `inc-8/04-validation.md`.

### RED counterfactual

| Field | Value |
|---|---|
| **RED counterfactual** | The two new files on base `e266395`: **64 failed, 18 passed** (the 18 are the design's holds-on-base controls) — `evidence/inc-8/red-01-tester-base.txt`; again on `origin/main` `f11b3f4` after the integration fixes: 64 failed, 18 passed — `int-03-red-on-main.txt`. The E5 tests for F1 and F2 on the delivered code: **3 failed, 1 passed** (RecursionError at json/encoder.py:258; 14/5 on the cause), GREEN after the fix: 4 passed — `e5c-01-red-f1-f2.txt`, `e5c-02-green-f1-f2.txt`. The mutation that made each new assertion fail is in the next row. |

| Field | Value |
|---|---|
| **Mutation verdicts** | 20 mutants M01 … M19 (M10 shares M06's edit), per-node verdicts in `E5-mutants.md`: **20 KILLED, 0 SURVIVED, 0 BAD**; control `mut-00-base.txt` 82 passed. Each mutant applied to a detached copy of `e455a07`; the file restored byte-exact (`git diff --quiet` true after each). No arm stayed GREEN that the row names (M13 and M19 are broad, 26 and 23 failures; single-purpose kills: M14 → 9/15 by the absolute-ref arm, M17 → 13, M09, M11, M05). Transcripts `evidence/inc-8/mut-M01.txt` … `mut-M19.txt` (digests below). Not re-run on the corrective head. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 3 instruments shown RED first: the two test files on base (64 failed); the E5 F1/F2 tests on the delivered code (3 failed); the mutant harness (the unmutated copy gave 82 passed, every mutant a non-zero failed count, `mut-00-base.txt`). The independent CRC oracles are three implementations that import nothing from the project: the architect's Rocksoft model, the reviewer's right-shift model (both 0x0F8B7431, 0xCBF43926) and the auditor's `zlib.crc32` (CRC-32 of `01 02 03 04` = 0xB63CFBCD). |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts asserted against the form the product emits: the written image bytes (001.1/7: `31 74 8B 0F` at 0x1010; 9/5: `CD FB 3C B6` at 0x1020 from the Designer engine); the block summaries with the read suffix (12/1 … 12/10, the exact summary in 12/10) and the report cells and provenance lines in their escaped form (10/1, 10/2, 13/1); the refusal reasons and causes as exact text (001.10/*, 001.11/*, FLOW-CRC.3/4/9, EXT.14/*). All passed in `evidence/inc-8/e5c-03-new-files.txt`. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 (`sha256sum`) of the bytes at the cited path, taken 2026-11-05. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-8/`, the home `artifact_homes.evidence` declares.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| red-01-tester-base.txt | evidence/inc-8/red-01-tester-base.txt | c1f32d7a65f7fb5f2fe025a0e84afd15b3ae50e569a62a9c867c88c345959d47 |
| int-01-new-tests-first.txt | evidence/inc-8/int-01-new-tests-first.txt | 02c127e3375776992948ce8fe044cf400d88a1a1b83aaba31a2aee226385360e |
| int-02-new-tests-premerge.txt | evidence/inc-8/int-02-new-tests-premerge.txt | 468787793ab75bc70a9c96ea116a98ad0c53a1c0bb39c2c6db3c923c4fe0d859 |
| int-03-red-on-main.txt | evidence/inc-8/int-03-red-on-main.txt | 1b7b6b54cac17c40c4f3663fec740deb73ec1a4689ee159c38616c62cc1e3427 |
| int-04-tree-touched-and-neighbours.txt | evidence/inc-8/int-04-tree-touched-and-neighbours.txt | abff102f09aef7d2bc8d34868a8831f7b8c4fe1c9fbeeb4e7e73299bab4a0cac |
| impl-smoke.txt | evidence/inc-8/impl-smoke.txt | 020e7d2085f3690548e839f6cb03dbd90d4a222c383ca4d56b294d5263a5cc12 |
| mut-00-base.txt | evidence/inc-8/mut-00-base.txt | 6c549a27d6dd3460c7ec4787c7f623477e331c611baed44b1948454b3b995a55 |
| mut-M01.txt | evidence/inc-8/mut-M01.txt | fcbf5248048bbf254e15319f7116dfd665657f39faef5b04b05ec936163c6673 |
| mut-M02.txt | evidence/inc-8/mut-M02.txt | 5776a2ba333e153320b69c0c93243e1acdd1aeeaa8e7cbd307ae93c8ac83bbb7 |
| mut-M03.txt | evidence/inc-8/mut-M03.txt | 472742b00722161e7163f72bf94a9e28433b50f643aeb5dd2b20cbbe5bd269cd |
| mut-M04.txt | evidence/inc-8/mut-M04.txt | 7d0b3250896f6268b09649a405fe69f43bef5779b36351e384f163e748b26703 |
| mut-M05.txt | evidence/inc-8/mut-M05.txt | b4d0b353886efd4c4e0e56abf3a1f01fef9ff9d3848b9d343d347e7792eb47bf |
| mut-M06.txt | evidence/inc-8/mut-M06.txt | 89dacd37dd006bb88a645e906e9cae38d5983d5dd6c1769a633d0d968264c308 |
| mut-M07.txt | evidence/inc-8/mut-M07.txt | 16f91becf965f1fb3e47118b8f115992075777a3d5a2abf93f5a3e059bcefa74 |
| mut-M08.txt | evidence/inc-8/mut-M08.txt | 95326d3e0e963f1125baeb098e9adc85f44a716287db1909eddc90aafbe01e94 |
| mut-M09.txt | evidence/inc-8/mut-M09.txt | aeae373c4b4853ac5ad7a6dbb66d6a33681b0f8cf4924a425b6eaa279e0a9c06 |
| mut-M11.txt | evidence/inc-8/mut-M11.txt | abe775ac65b79a18b277a9bcb96e32fdf7111b044a4cd81f7a310d37b85d4ac8 |
| mut-M12.txt | evidence/inc-8/mut-M12.txt | 72d2bdbc8c321b98bc437d1583e4932e3d236ba2611bf452c742e4e5c36a9b2d |
| mut-M13.txt | evidence/inc-8/mut-M13.txt | 2ff5371d1354cf28e413f75d7f3c4b5d71d8d48f5bd1c88363b211271174db03 |
| mut-M14.txt | evidence/inc-8/mut-M14.txt | c1dffff295d42f1f08002003aa6743739e771db2e815790dd6db5539a75c1e02 |
| mut-M15a.txt | evidence/inc-8/mut-M15a.txt | 302c234b60d5ddebcbe0f69aff61217301cf7e30bb52fd00406a29b1f23c7609 |
| mut-M15b.txt | evidence/inc-8/mut-M15b.txt | 9aa8a8ebc076f173bd096407ed4e6da237c46986e452b266581a618331968c4f |
| mut-M16.txt | evidence/inc-8/mut-M16.txt | 4277a573760b165e5c309b88ad89c418b5bb191a321c56fadab00e7ffb7e6c76 |
| mut-M17.txt | evidence/inc-8/mut-M17.txt | 96f3730737d7f890381d18b69bc789dd87009e3bedf9e796fc9d1b4c12c4fd34 |
| mut-M18.txt | evidence/inc-8/mut-M18.txt | a9f65aacdbe6dae52379f1a97a32116610c6fbf1e8a774af659bbfb76d54caf9 |
| mut-M19.txt | evidence/inc-8/mut-M19.txt | f2480e242b0d722381ed12620d0a1977ad95720a423a901f43b6b0672f1571f2 |
| e5c-01-red-f1-f2.txt | evidence/inc-8/e5c-01-red-f1-f2.txt | 39b9ea1395a5f3f3a60884a67696df9d6083edf65ec8c60d23afafe0995ad2b3 |
| e5c-02-green-f1-f2.txt | evidence/inc-8/e5c-02-green-f1-f2.txt | b1f7c68099ea3fb1a52c5bd1d19bb6c9b35a28bd43a0784d4d43c12a14281d01 |
| e5c-03-new-files.txt | evidence/inc-8/e5c-03-new-files.txt | 1b545377170452fbc01e3a7ab08f20859a1285f60d18facf584c6abce83869fc |
| e5c-04-touched-module-importers.txt | evidence/inc-8/e5c-04-touched-module-importers.txt | 7fb695ffd5ec2f3db7068a8b5411eb1477c5a6b32e9145d91d051f593e8cca54 |
| e5c-05-law-guards.txt | evidence/inc-8/e5c-05-law-guards.txt | b7161d7ed97512c6fe06a54d3515c7c2f83d0927b1ce6598fbe3d400b181c2d9 |
| e5c-06-rerun-b97-flow-execution.txt | evidence/inc-8/e5c-06-rerun-b97-flow-execution.txt | 79be063c3ad2ad56839a5cf7bca64f628b5c56387b2e73fd54b52285f49e3712 |

| Field | Value |
|---|---|
| **Evidence files** | 32 transcripts, each cited with the digest of its stored bytes, all under the home `artifact_homes.evidence` names |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | yes: "`_number_field` cannot raise for any value `json.loads` returns" (F1 re-review: 0 exceptions escaped over six number fields × three shapes × depths 60–69 and 850–1000 × six caller stack depths) and "0 gap, 0 conflict" in the coverage re-audit |
| If the result is an ABSENCE, what made the search wide enough | the sweep varied field, value shape, nesting depth and caller stack depth; the lazy encoder stops at 65 characters, so the bound does not depend on the depth probed |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_r_crc_config_001_11_9_deep_value_gives_the_reason_not_a_raise` and `test_r_crc_config_001_11_10_operations_execute_survives_deep_value` (the reader's limit falls inside their bands on win32; on another platform they fail loudly, they do not pass vacuously; backlog row) |
| Conjunctive criteria: one mutation per conjunct | R-FLOW-EXT.14: M18 (climb check) kills 14 log and 14 output; the order conjunct is pinned by 14/5 alone (14/4 passes on either order), no mutation of the order was run |
| Synthetic instance of the absent case | the 5 000 000-item list, the 1 000 000-key object and the 100 000-bracket text of the reviewer's probes; `[` × 100 000 in 001.17/1 |
| **Positive control for every probe that returned an ABSENCE** | the same probe on the delivered code raised `RecursionError` at depth 993 (`e5c-01-red-f1-f2.txt`: json/encoder.py:258); the same sweep on head returned the 001.11 or 001.17 reason each time |

### Reverse census

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | every test file importing `crc`, `crc_config`, `flow_execution_service`, `flow_model` or `flow_report_service`, one pytest run per file | 47 files, 1189 passed, 1 failed (flaky, unrelated: a PATCH chain with no external step); earlier 51 files, 1218 passed, 1 skipped |
| B2 file moved on disk | no file moved or renamed | n/a |
| B3 byte-identical golden captures this source | no probe on record | not run |
| B4 artifact produced here is consumed elsewhere | the summary and report sinks: `flow_screens._failure_detail` (`endswith("unresolved")`, covered by the suffix placement N-2), `flow_report_service`, `flow_fused_report_service`, chain-set provenance | read by the code and security reviewers; every sink escapes (`md_safe`, `md_code`, `safe_text` with markup off, `_esc`) |
| A3 interface consumed by another module changed | `FlowRunResult.in_place_reads` and `ChainRunOutcome.in_place_inputs` are additive with defaults; `crc32_stream` signature unchanged; no other place reflects an init (grep) | E3 round 2 §2 (constructors use keywords); code review grep |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes considered: B1, B4 and A3 run; B2 n/a (nothing moved); B3 not run; B1 re-validated every hit by running it; the one failing node is the flaky `tc_b97_55`, rerun whole 75 passed. |

### Correction population

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| coverage column wrong | case rows listing a passing full test but marked `gap` | the auditor's row-by-row read of `02-test-cases.md` against INT-04 | 79 of 82 (78 marked `gap`, 1 `partial` that should be `covered`) | all, by the corrective pass C-9 | none; re-audit: 96 covered, 3 partial, 0 gap |
| node ids that do not collect | ids in the Tests column | `pytest --collect-only` over the two files (82 ids, then 144 over the six cited files) | 12 | `ids=` added to the parametrizes or the real ids cited | none; 0 of 101 cited ids missing |
| case text differing from the pinned value | cases after SR-1 … SR-6 and N-1 | the auditor's per-case comparison | 21 | all | none |

| Field | Value |
|---|---|
| **Correction population** | 3 corrections, each enumerated by the audit before the corrective pass edited its first site (counts above). |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `248 = 246 − 0 + 2` (`tests/test_id_registry.py`, measured). Test cases `99 = 82 + 17`. No test function renamed or deleted, no assertion weakened (`E5-corrective-notes.md` §3; the code review diffed the assert lines of the integration fixes).

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS** (re-review of F1, F2) — round 1 FAIL, BLOCK-UNTIL F1 (MAJOR: a deeply nested number field crashed the Operations dialog) and F2 (the external-step checks ran in an order that differed from R-FLOW-EXT.14); both discharged on the corrected diff, RED on the old code, GREEN on head, probes found 0 escapes; F3 … F7 (MINOR, NIT) routed — `inc-8/E5-code-review.md`. `security-reviewer` · **PASS-WITH-NOTES** — no HIGH or MEDIUM; S8-1, S8-2 LOW to Inc 9, S8-3, S8-4 INFO to the backlog — `inc-8/E5-security.md`. The independent `tester` (Kimi K2.8) wrote the tests and ran them RED on base only; the integration found the 22 failures. `qa-reviewer` coverage audit and re-audit — 99 cases, 96 covered / 3 partial / 0 gap — `inc-8/E5-coverage-audit.md`. **Design reviews (E3, code-free):** `architect` round 1 FAIL (A-1, A-2 MAJOR) and `security-reviewer` round 1 FAIL (S-1, S-2 MAJOR) → round 2 PASS-WITH-NOTES, all four closed — `inc-8/E3-r2.md`. |

## 5. Risks

- **No Linux run** of the two Inc 8 test files; 9/10, 9/15 and 12/10 skip off Windows, and 001.11/9 and /10 depend on the platform's stack depth. The first Linux run can fail them without a product defect.
- **A saved CRC config with `reverse: true` and an init that is not bit-symmetric changes meaning**: an image written by an earlier version now checks MISMATCH (decision D-3, no runtime notice). Mitigation: `release-note-crc.md` gives the detection rule and the exact migration (init `0x12345678` → `0x1E6A2C48`); it must reach the operator's release page.
- **A junction can still carry a path past the project folder checks** (S8-1, S8-2, LOW, routed to Inc 9): the reach equals an absolute path, a human confirms, the read suffix names the copy.
- **A bench output replaces a same-name project file for later refs, a first run included** (E3 finding A-2, accepted): visible through the read suffix, truncated in a 240-character ledger cell when long (S8-3).
- The mutants ran on `e455a07`, before the corrective changes (F1, F2, 17 new cases); the corrective tests were checked RED then GREEN, not by new mutants.
- `tc_b97_55` failed once under load and passed on rerun; it is a timing arm outside the Inc 8 paths, and a repeat in a gate run would be that flake, not a regression.

## 6. Pending

- **Routed to Inc 9 (D15-18):** S8-1 (a relative output or log through an outside junction) and S8-2 (a link back into the project is accepted); when closed, 9/15 arm (b) and 12/10 can move from partial to covered.
- **Backlog rows appended to `.dev-flow/BACKLOG-CODE.md` (2026-11-05):** S8-1/S8-2; S8-3; S8-4; F5 … F7; the 9/15 Linux non-link arm; 9/11 does not check the name `terminal_out_1.s19`; 001.11/9 and /10 stack-depth bands; the audit's open ATs A-2 … A-7 and the 9/7 hardening; 14/4 passes on either order (only 14/5 pins it); the `tc_b97_55` flake.
- **Partial cases:** 9/15, 12/10, FLOW-CRC.4/4 (the shipped parser returns at most one error; reword the row or keep the join as defence).
- **Requirements session:** the thresholds "8/8" of R-CRC-CONFIG-001.10 and .11 (now 11 and 14 cases).
- **Owed at the batch end:** the full suite; a Linux run of the two files; the release note `release-note-crc.md` on the operator's release page.
- **Uncommitted records** (this packet, `04-validation.md`, the E5 re-review and re-audit sections, the graph correction, the backlog rows) are for the orchestrator to commit; nothing here is committed by this record. The backlog rows insert at the same place as batch-101 Inc 2's rows on `main`, so expect a text conflict at merge.

## 7. Suggested next task

Commit the records, merge Inc 8, and open Inc 9 (D15-18, manifest and path rules) with S8-1 and S8-2 in its first slice; run the two Inc 8 files on the Linux host before the batch-end gate.
