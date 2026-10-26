# Increment 009 — HLR-154 · `truncated and inconsistent images are reported`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `009` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-143 / HLR-154 / LLR-154.1 · LLR-154.2 · LLR-154.3` (PDR conditions UX-C2, UX-C7, UX-C10; map row B99-I10) |
| Acceptance | `AT-B99-03` · white-box `TC-B99-08 · TC-B99-09 · TC-B99-10` · unit `see TC layers` |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: a cut transfer no longer loads as `ok` with its tail missing (P-10). The
S19 loader (`s19_app/core.py::_load`) now (LLR-154.1) attaches one
`load_errors` notice per defect kind whose `error` text leads with a stable
code: `S19-NO-TERMINATOR` when the file has no S7/S8/S9 record,
`S19-COUNT-MISMATCH` when an S5 count differs from the data-record count
(compared only while that count fits the 16-bit field) or an S6 count differs
(compared while it fits the 24-bit field; S6 records now parse — previously
`SRecord` rejected them outright), and `S19-AFTER-TERMINATOR` stating the
count when non-empty lines follow the first terminator — those lines are
counted, never parsed, never imaged, with no per-line issue. The HEX loader
(`s19_app/hexfile.py::_load`, LLR-154.2) attaches `HEX-NO-EOF` when no type-01
record exists and `HEX-AFTER-EOF` stating the count for non-empty lines after
the first EOF (counted, never parsed, never imaged).

The flow SOURCE arm (`flow_execution_service.py`, LLR-154.3) splits loader
errors: exactly the five codes end the SOURCE block `error` — every diagnostic
(so the painted LAST one, UX-C2) names `[code] file: message` — and abort the
chain, so no file is written; every other load notice keeps the advisory
`notices` mapping (LLR-085.2) and a clean image keeps `ok`.

The interactive load (UX-C7): `_format_coexistence_status` now LEADS with the
defect — `Loaded firmware.s19 with integrity notices: S19-NO-TERMINATOR` —
never a plain `Loaded <name> (S19 only)`, and the Issues panel carries one
ERROR issue per code naming it (the file-derived text reaches the
`markup=False` `#status_text`, so a hostile file name renders literally,
UX-C10). Code sets live at the producers (`S19_INTEGRITY_NOTICE_CODES` in
`core.py`, `HEX_INTEGRITY_NOTICE_CODES` in `hexfile.py`); both consumers match
through `load_notice_code` (`core.py`).

Shipped surface the user reaches: Load file (`l`) + the Issues panel; Flow
Execution run (`#fx_run`).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/core.py` | SOURCE | HLR-154, LLR-154.1 | `SRecord.ADDRESS_LENGTH_MAP` gains `S6` (3-byte count field); `_load` rewritten: terminator gate (post-terminator lines counted, never parsed/imaged), data-record/S5/S6 counting, the three S19 notices; new `S19_INTEGRITY_NOTICE_CODES` + `load_notice_code` |
| `s19_app/hexfile.py` | SOURCE | HLR-154, LLR-154.2 | `_load` rewritten: EOF gate (post-EOF lines counted, never parsed/imaged), `HEX-NO-EOF` / `HEX-AFTER-EOF` notices; new `HEX_INTEGRITY_NOTICE_CODES` |
| `s19_app/tui/services/flow_execution_service.py` | SOURCE | HLR-154, LLR-154.3, UX-C2 | `SOURCE_INTEGRITY_CODES` frozenset; the SOURCE arm maps the five codes to a `BLOCK_STATUS_ERROR` (diagnostics `[code] file: message`, last = painted cause) + chain abort; other notices keep `notices` |
| `s19_app/tui/app.py` | SOURCE | HLR-154, UX-C7, UX-C10 | `_integrity_notice_codes` helper; `_format_coexistence_status` leads with `Loaded <name> with integrity notices: <codes>`; `_compute_mac_view_payload` appends one ERROR `ValidationIssue` per integrity code so the Issues panel names it |
| `tests/test_b99_truncation.py` | test | HLR-154 | new: TC-B99-08 ×7 nodes (incl. 3 parametrized defect arms), TC-B99-09 ×4 (incl. 2), TC-B99-10 ×6 (incl. 5), AT-B99-03 ×3 pilot nodes |
| `tests/test_core_srecord_validation.py` | test | LLR-154.1 | re-pin: `test_s19file_collects_errors` expects the trailing `S19-NO-TERMINATOR` integrity notice (`[3, 4]` → `[3, 4, None]`) |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-009.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-9/*` | doc | — | transcripts, hashes (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** |
| Test files | 1 (uncapped) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched.

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # must print a path inside the worktree
pytest tests/test_b99_truncation.py -q                 # -> 20 passed
pytest tests/test_b99_truncation.py -k tc_b99_08       # -> 7 passed
pytest tests/test_b99_truncation.py -k tc_b99_09       # -> 4 passed
pytest tests/test_b99_truncation.py -k tc_b99_10       # -> 6 passed
pytest tests/test_b99_truncation.py -k at_b99_03       # -> 3 passed
pytest tests/test_address_census.py -q                 # -> 23 passed
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-B99-08` ↔ LLR-154.1 | `core` · `full` | `test_tc_b99_08_defect_files[3]` · `test_tc_b99_08_examples_and_corpus_controls` · `test_tc_b99_08_junk_tail_counted_not_parsed` · `test_tc_b99_08_trailing_blank_lines_no_notice` · `test_tc_b99_08_wide_s6_image_no_notice` | 7 passed |
| **A · white-box** `TC-B99-09` ↔ LLR-154.2 | `core` · `full` | `test_tc_b99_09_defect_files[2]` · `test_tc_b99_09_well_formed_corpus_controls` · `test_tc_b99_09_junk_tail_counted_not_parsed` | 4 passed |
| **A · integration** `TC-B99-10` ↔ LLR-154.3 | `core` · `full` | `test_tc_b99_10_source_error_no_file[5]` · `test_tc_b99_10_clean_source_still_writes` | 6 passed |
| **B · black-box** `AT-B99-03` ↔ US-143, through the Textual pilot (`l` → Load dialog → `#status_text`/Issues panel; `#fx_run`) | `core` · `full` | `test_at_b99_03_pilot_status_and_issues` · `test_at_b99_03_hostile_name_renders_literally` · `test_at_b99_03_pilot_flow_source_fails` | 3 passed |

Regression companions (all affected-file census, this tree):
`tests/test_b99_truncation.py` 20 passed · `tests/test_address_census.py`
23 passed · regression batch (15 files: b99_corpus, b99_s0,
flow_execution_service, flow_execution, flow_chainset_b94,
flow_multi_image, unified_read, hex_emit, changes_apply, memory_display,
tui_hostile_map, filename_markup_safety, cli, variant_execution) 149 passed ·
`test_core_srecord_validation` + `test_before_after_report` 25 passed ·
census batch 2 (11 files: b97_flow_execution, flow_a2b_b94, flow_funnel_b96,
flow_external_step_b96, flow_report_ac6_golden, compare_service,
project_gather, changes_symbol_entries, crc_operation, flow_crc_block,
validation_service_supplemental) 235 passed · `tests/test_tui_app.py`
62 passed + 1 xfailed (pre-existing).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | three, one per LLR (see Mutation verdicts below); baseline RED first: the whole new file run against the UNMODIFIED tree |
| Instrument | project code: the implementer's own hand via the Edit tool; restore checked by SHA-256 against `baseline-hashes.txt` |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc9`), run by the implementer |
| Transcript | `evidence/inc-9/red-initial.txt` (16 failed, 4 controls passed — the passing four are pure boundary controls: trailing-blank-lines, well-formed HEX controls, the examples/corpus zero-code control and the clean-source flow control) · `mut-LLR-154.1.txt` · `mut-LLR-154.2.txt` · `mut-LLR-154.3.txt` |
| Restore proven by | core.py → `123eda01…` · hexfile.py → `c9761efb…` · flow_execution_service.py → `9feeecb7…` (all back to their pre-mutation digests recorded in `baseline-hashes.txt`; app.py untouched by mutations at `029b8bc5…`) |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | the RED baseline resolves all 20 nodes (16 fail); each mutation run resolves exactly its `-k` subset (1 / 1 / 5 nodes) |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | none in any mutation run; the 4 control arms that pass at baseline also pass under each mutation (they pin behaviours the mutation does not touch) |

| Field | Value |
|---|---|
| **RED counterfactual** | baseline RED `red-initial.txt`: 16 failed — every defect arm and every AT fails on the unmodified tree (P-10 exactly: `s19_truncated_no_terminator` loads `ok` with 0 notices; the S6 boundary arm also fails because the engine rejected S6 outright, which LLR-154.1's S6-count comparison requires parsing). GREEN after the fix: `green-full.txt` 20 passed. |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-154.1 · TC-B99-08: S19 terminator check dropped (`if not terminator_seen:` → `if terminator_seen:`) · KILLED — `test_tc_b99_08_defect_files[synth_no_terminator.s19]` FAILED with 0 notices (`mut-LLR-154.1.txt`) · restore `123eda01…` ‖ LLR-154.2 · TC-B99-09: HEX EOF check dropped (`if not eof_seen:` → `if eof_seen:`) · KILLED — `test_tc_b99_09_defect_files[synth_hex_no_eof.hex]` FAILED (`mut-LLR-154.2.txt`) · restore `c9761efb…` ‖ LLR-154.3 · TC-B99-10: the five codes mapped back to the advisory `notices` path (`if integrity_errors:` → `if False and integrity_errors:`) · KILLED — all 5 `test_tc_b99_10_source_error_no_file` arms FAILED (SOURCE stayed `notices`, a file was written) (`mut-LLR-154.3.txt`) · restore `9feeecb7…` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the unmodified tree (tests in, fix out) | 16 failed — every defect/flow/AT arm (`red-initial.txt`) |
| Textual pilot (AT layer) | same unmodified tree | the 3 AT-B99-03 nodes failed — status never led with the defect, flow lane wrote the file (`red-initial.txt`) |
| Flow engine via `run_flow` (TC-B99-10) | same unmodified tree | SOURCE came back `ok`/`notices` and WRITE-OUT wrote `out.s19` (`red-initial.txt`) |
| C-40 mutation loop | each of the three LLR mutations on the fixed tree | one FAILED node (154.1, 154.2) / five FAILED nodes (154.3) per transcript, restored by hash |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the loader's notice dicts (emitted by `S19File._load` / `IntelHexFile._load`) | `errors[0]["error"] ==` the exact emitted message per defect file (e.g. `S19-AFTER-TERMINATOR: 1 record(s) after the terminator were ignored`; the 100 000-line tails pin `100000 record(s)…` verbatim) | 3+2 defect arms + 2 junk-tail arms pass (`green-tc_b99_08.txt`, `green-tc_b99_09.txt`) |
| the flow block's diagnostics (emitted by the SOURCE arm) | `source.diagnostics[-1].startswith("[S19-NO-TERMINATOR]")` and names the file, per code | 5 arms pass (`green-tc_b99_10.txt`) |
| the painted status line (emitted by `_format_coexistence_status` → `#status_text`) | the pilot asserts the painted text contains `Loaded firmware.s19 with integrity notices: S19-NO-TERMINATOR` and never `(S19 only)`; the hostile arm asserts the literal `[@click=app.quit]cut.s19` reaches the screen | 3 AT nodes pass (`green-at_b99_03.txt`); probe capture in `probe_status.py` output shows the exact painted label |
| the written-image rule | `run_flow` over each defect source: `written_paths == []` and no `out.*` on disk (observed with the filesystem) | 5 arms pass (`green-tc_b99_10.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-9/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED baseline, unmodified tree (16 failed, 4 controls passed) | `red-initial.txt` | `828d4761cce5eee3819255cdad3056148b148c55b57cd7d76a132dab24d18168` |
| GREEN full run (20 passed) | `green-full.txt` | `e9ae1fd20406757b80df7492aa25be75473bcacd9c4b5e97f6084933dffe710a` |
| GREEN TC-B99-08 (7 passed) | `green-tc_b99_08.txt` | `b968dcff3240636ff01c475c82ec78fb75f9317eb55812ca3d4c26fa87c542a5` |
| GREEN TC-B99-09 (4 passed) | `green-tc_b99_09.txt` | `f62dd37b6450b0dbe550e8ac3b26d332177712d4c0c6b3cc2ae22012d4f7a41d` |
| GREEN TC-B99-10 (6 passed) | `green-tc_b99_10.txt` | `d571851c5a42e67b239dabf3b55fc61c388e34e0f2c532544bbb55d1ea2d42d0` |
| GREEN AT-B99-03 (3 passed) | `green-at_b99_03.txt` | `24e10f99e505e22cd1150c5742795a0cb24e9844828e0bc589ee79e5fab9b0ff` |
| GREEN regression companion (23 passed) | `green-address-census.txt` | `4a27499e77fb79a9525a0d10462c32ce7e71a1d9c3bc4a13430590ca170c338a` |
| GREEN core_srecord + before_after (25 passed) | `green-core-srecord-before-after.txt` | `5fcbd65127e6e12d17a90ff65d18301bef9bf8ae167ed505bacc680aab6a0aeb` |
| GREEN regression batch (149 passed) | `green-regression-batch.txt` | `644f76692e5003ab4f47db8fc4c4e952ffea335c666d1c9ada72f9a76cabb3b8` |
| GREEN census batch 2 (235 passed) | `green-census-batch-2.txt` | `4e8c286951b58cc685e3919b86f1f1c046ad9b930827c722a17e490130f520ee` |
| GREEN test_tui_app (62 passed, 1 xfailed) | `green-tui-app.txt` | `dd8e569ad4268cf42e350ebba55ee428a784addd701ad4ed5980eedd28983e75` |
| Mutation LLR-154.1 (KILLED) | `mut-LLR-154.1.txt` | `205fe11e89928a06be9be70c52f33541ae06fa66ce1be9793e660b6b71f1ff17` |
| Mutation LLR-154.2 (KILLED) | `mut-LLR-154.2.txt` | `8792007c6c7c090f03038033a28b5a33bb7ede110b317624a0e0844c8272b70f` |
| Mutation LLR-154.3 (KILLED, 5 arms) | `mut-LLR-154.3.txt` | `a32d03b5c782930735a893b987487536144559d2a8de193c0ccb15523429519d` |
| Reverse census probes | `reverse-census.txt` | `784b3eff3bffd220908af92dec658a3a7dc5d8f3466fa1d87bbbc5114a0d5d48` |
| Pre-mutation hashes (4 SOURCE files + new test) | `baseline-hashes.txt` | `d85aeb367c12af8ba60e6a4e5c365555942edbe9e28af1b85e8f9fef205a4921` |
| Painted-status probe (diagnostic) | `probe_status.py` | working-tree diagnostic script (not a transcript) |

| Field | Value |
|---|---|
| **Evidence files** | 15 transcripts, each at the declared home and cited with the digest of its stored bytes |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) the control claim "every `examples/**/*.s19` and every well-formed corpus file carries ZERO of the five codes"; (2) the width-gate claim "no S5/S6 mismatch fires outside the gated widths" |
| If the result is an ABSENCE, what made the search wide enough | (1) the arm iterates ALL 16 `examples/**/*.s19` files (glob, not a sample) plus every manifest entry with `verdict == "ok"`, and asserts the full error list is empty for the corpus files; (2) the boundary arm generates a >65 535-record S6 image with a deliberately WRONG S5 count into tmp and asserts zero notices — the gate, not the fixture population, is what is pinned |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b99_08_examples_and_corpus_controls` — the zero-code assertion is its own named node; `test_tc_b99_08_wide_s6_image_no_notice` — the width gate is its own named node |
| Conjunctive criteria: one mutation per conjunct | no conjunctive criterion — each guard is a single assertion with its own mutation (154.1 terminator, 154.2 EOF, 154.3 mapping) |
| Synthetic instance of the absent case | the mutants are the synthetic instances (a loader that drops the terminator/EOF check); the junk-tail arms synthesise 100 000-line non-empty tails |
| **Positive control for every probe that returned an ABSENCE** | (1) the same control arm sees all 3 S19 defect files produce their codes (non-absent output of the identical probe); (2) `synth_wrong_s5.s19` (2 records, S5 count 3) makes the identical count probe return `S19-COUNT-MISMATCH` inside the gate |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "S7\|S8\|S9\|terminator\|EOF\|_load(" tests/` (51 files) + focused pins | behaviour pins found and re-validated: `_format_coexistence_status` (test_tui_app 4 nodes with `errors=[]` fixtures — unchanged, pass; test_filename_markup_safety — unchanged, pass); `SRecord` rejection pin is S4-only (`test_srecord_unsupported_type_raises`) — S6 was pinned nowhere; loader round-trips (`changes_apply`, `hex_emit`, `unified_read`, `memory_display`, `before_after_report`, `flow_*`, `b97_flow_execution`, `compare_service`, `project_gather`, `crc_operation`, `validation_service_supplemental`) — all re-run GREEN on this tree (149 + 235 + 25 passed) |
| B2 file moved on disk | n/a — no pre-existing file moved | no readers found |
| B3 byte-identical golden captures this source | n/a — no golden captures the changed surfaces | no re-pin |
| A3 interface consumed by another module changed | the notice dict shape keeps the existing 4-key `load_errors` form (only the `segment` value `integrity` and the message text are new); `_load_error_message` and `LoadedFile.errors` consumers re-validated via the flow/UI batches | no foreign breakage |

Re-pins (requirement LLR-154.1 changes the pinned behaviour — recorded per BRIEF-inc-9; citation corrected in review round 1, finding F4d):
`tests/test_core_srecord_validation.py::test_s19file_collects_errors` — expected error line_numbers `[3, 4]` → `[3, 4, None]` plus the trailing `S19-NO-TERMINATOR` integrity dict — LLR-154.1 (the fixture has no terminator; the loader now reports it). Also declared: the batch-99 baseline probes (`rw-p04` `s19_data_after_term` keeping `0x2000`) pin the OLD post-terminator behaviour that LLR-154.1 deliberately changes — superseded by this increment's defect arm, which pins the new behaviour with the manifest oracle.

Pre-existing flakes observed, NOT re-pinned (timing races that pre-date this increment; both in `test_before_after_report.py`, which is otherwise green in `green-core-srecord-before-after.txt`): `test_at_061a_*` races one `pilot.pause()` against the `@work` report worker (failed 1 of 3 consecutive runs on this tree, passed the other 2 — including in the final batch); `test_tc330_*` showed a teardown `NoMatches` in the crowded batch and passed in isolation and in the final batch.

| Field | Value |
|---|---|
| **Reverse census** | broad probe 51 files; focused behaviour pins re-validated by re-run (3 batches, 409 tests); 1 re-pin recorded with reason; 2 pre-existing flakes declared |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| post-terminator S19 records no longer enter the image | every test fixture in the repo lacking a terminator or carrying records after the terminator | pre-edit scan of `examples/**` + `tests/fixtures/**` (`*.s19`/`*.hex`): only the 4 committed defect files lack a clean end; no S5/S6 records exist outside the synth corpus | 1 re-pin (`test_s19file_collects_errors`); 0 other sites — every other fixture load either only reads the image (still fine) or asserts nothing about notice counts | `core.py`, `hexfile.py` | n/a |

| Field | Value |
|---|---|
| **Correction population** | 1 population, enumerated pre-edit by scan; 1 test re-pinned with reason; no silent survivors (the examples/corpus control arm iterates every file) |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| `rw-p04` `s19_data_after_term … out_ranges=[('0x1000','0x1010'),('0x2000','0x2010')]` (premise evidence, pre-batch) | pinned old behaviour only in `.dev-flow/**` premise records and P-10 row | n/a — historical premise evidence, not a live assertion; the new behaviour is pinned by `test_tc_b99_08_defect_files[synth_after_terminator.s19]` | `tests/test_b99_truncation.py` (image == manifest `data`, which holds only `0x6000`) |

### Signed-balance test ledger

`post = base − deleted + added` → `25 = 0 − 0 + 25` ✓ reconciles — **DDR-corrected
2026-10-26** (DDR finding F-6): the line below stated 20 and never took up the
5 review-round nodes (round 1: `test_tc_b99_08_trailing_blank_lines_no_notice`,
`test_tc_b99_08_wide_s6_image_no_notice`; round 2: `test_tc_b99_08_s6_mismatch_wide_image`,
`test_tc_b99_08_damaged_data_line_no_false_count_mismatch`; round 3: `test_tc_b99_09_line_endings_cr_lf_crlf`).
(`tests/test_b99_truncation.py`: 0 baseline nodes — new file — 0 deleted, 25 added:
TC-B99-08 ×9, TC-B99-09 ×7, TC-B99-10 ×6, AT-B99-03 ×3 — parametrized arms
counted per collected node). Count command: `pytest --collect-only -q tests/test_b99_truncation.py | grep -c "::"`
→ 25 (`git show HEAD:tests/test_b99_truncation.py | grep -c "^def test_"` → 18 defs + 7 parametrized expansions).
Re-pin ledger: `tests/test_core_srecord_validation.py` 6 → 6 nodes (0 added, 0
deleted; assertions updated in `test_s19file_collects_errors` per HLR-154).

---

### Review round 1 fixes (code-reviewer F1–F4, 2026-10-25)

Second pass over this increment per `kimi/BRIEF-inc-9-fix.md`. The fixes touch
2 SOURCE files (`s19_app/hexfile.py`, `s19_app/core.py`) and 1 test file
(`tests/test_b99_truncation.py`) — no new source files; the increment stays at
4/4 inside the budget.

| Finding | Fix | Arm / evidence |
|---|---|---|
| **F1 [HIGH]** — a HEX file with a binary tail failed to load (`UnicodeDecodeError` out of the strict utf-8 text handle, "Load failed") instead of loading with a `HEX-AFTER-EOF` notice | `IntelHexFile._load` now opens the file `"rb"`. Lines are decoded strictly only up to and including the first EOF record; after it, non-empty lines are counted by stripping the BYTES and are never decoded. A non-empty line before the EOF that is not valid UTF-8 now records one per-line `format` issue instead of aborting the whole load (per-record error collection, as the docstring always promised). S19 left on its locale-codec read by decision: the byte-strip rule is not a small change inside `_load`'s post-terminator branch there (that branch still feeds text records through `SRecord`), and the S19 locale-codec weakness predates this batch — routed to the backlog by the orchestrator | NEW `test_tc_b99_09_binary_tail_after_eof`: the reviewer's case (valid 272-data-byte HEX + 50 000 newlines + `0xFF` padding) loads its 272 bytes with ONE `HEX-AFTER-EOF: 1 record(s)…` notice, image == independent-reader oracle. RED on the unmodified tree: `UnicodeDecodeError` (`red-fix-tests.txt`). Mutation (decode the tail) → KILLED (`mut-F1.txt`), restore by hash `c26a7540…` |
| **F2 [MEDIUM]** — the S6 mismatch was never tested | NEW `test_tc_b99_08_s6_mismatch_wide_image`: a generated >65 535-data-record S19 with a WRONG S6 count → exactly one `S19-COUNT-MISMATCH` naming the S6 count and the real tally (the S5 width gate skips the wrong S5 on the same image). The comparison code already shipped; the arm is the fix and its mutation is the load-bearing check: deleting the S6 comparison → the arm goes RED while the matching-count control (`test_tc_b99_08_wide_s6_image_no_notice`) stays GREEN (`mut-F2.txt`), restore by hash `5b286130…` |
| **F3 [MEDIUM]** — AT-B99-03's flow arm was not fully black-box | `test_at_b99_03_pilot_flow_source_fails` rewritten: only the project folder (with its flow file) is prepared on disk; the project loads through the Load project dialog by keys and clicks (`p` → `#project_list` pick → `#project_ok`, the CW-U-1-fixed path), Flow Execution opens on its rail key (`]`), the flow imports through its picker (`#fx_import` → item click → `#flow_load_ok`), the run starts with `pilot.click("#fx_run")`. Assertions read painted text (`#status_context`, `#fx_log`) and the filesystem only — no `app._handle_load_project`, no `action_show_screen`, no `Button.press()`, no `b97_fixtures` drive helpers (`write_flow` remains as on-disk preparation only). Stability: 8/8 consecutive runs, 3 passed each (`stability-at03.txt`) |
| **F4 [LOW]** | (a) the status assertion is now `status.startswith("Loaded firmware.s19 with integrity notices: S19-NO-TERMINATOR")` — UX-C7 "leads with". (b) the parsed-record tally reuses `_is_data_record(record)` instead of the duplicated `{"S1","S2","S3"}` predicate (semantics identical; `grep -rl _is_data_record tests/` finds no direct test pin). (c) the S5/S6 tally now counts the parsed data records PLUS the unparseable lines that start `S1`/`S2`/`S3`, so a damaged data line gives its own parse issue and no false count mismatch — NEW `test_tc_b99_08_damaged_data_line_no_false_count_mismatch` (RED on the unmodified tree: the false `S19-COUNT-MISMATCH` fired; mutation deleting the tally → KILLED, `mut-F4c.txt`). (d) the §4 re-pin record now cites LLR-154.1, not HLR-154 | 

RED counterfactual (fix round): `red-fix-tests.txt` — the two source-dependent
arms fail on the unmodified tree (the binary tail raises `UnicodeDecodeError`;
the damaged-line arm sees the false `S19-COUNT-MISMATCH`); the S6 arm and the
rewritten flow arm pass there (a coverage gap and a test-quality gap
respectively — the S6 arm is mutation-backed, the flow arm asserts painted
text only).

GREEN (fix round): `tests/test_b99_truncation.py` **23 passed**
(`green-fix-full.txt`; 20 → 23 nodes: +`test_tc_b99_08_s6_mismatch_wide_image`,
+`test_tc_b99_08_damaged_data_line_no_false_count_mismatch`,
+`test_tc_b99_09_binary_tail_after_eof`); loader census (`test_hexfile`,
`test_core_srecord_validation`, `test_b99_s0`, `test_flow_execution_service`,
`test_address_census`) **68 passed with 1 expected failure**
(`green-fix-loaders.txt`): `test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main`
fails loud naming exactly `s19_app/core.py` + `s19_app/hexfile.py` — the
engine crossing NAMED in LLR-154.1/154.2 (gate item 8). That failure predates
this fix round (the increment-9 engine changes are uncommitted working-tree
changes, so `git diff main` sees them) and is the guard working as designed,
not a regression. Final post-mutation confirmation: `test_b99_truncation.py` +
`test_b97_load_project_dialog.py` **24 passed** (`green-fix-final.txt`).

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED fix round (2 failed — the two source arms; 4 passed) | `red-fix-tests.txt` | `608f058ee3b68e51b5d531d6fa89ccf98526ab165ccaf957855a31c7ecacc2cc` |
| GREEN full truncation file (23 passed) | `green-fix-full.txt` | `c69c5a7d16ad4c3a52e6e04ea41a7e69a2cf73878a23e4ad708133731ce96393` |
| GREEN loader census (68 passed + 1 expected engine-guard failure) | `green-fix-loaders.txt` | `3806f5f90d805b62c0676d0562afe52f7c7d8e4fb274105f88035b5105302f27` |
| GREEN final post-mutation (24 passed) | `green-fix-final.txt` | `84c219a4036d24581cf326fe1be4883d64652514d407e68681447ebfd17dbc4d` |
| AT-B99-03 stability ×8 (3 passed each) | `stability-at03.txt` | `1c70d3e54c7e75d97f6d370abbdd7379b1ffc56ab2a949638488075898c952e8` |
| Mutation F1 (decode the tail) — KILLED | `mut-F1.txt` | `c80ca7205477b75500b2f001fb31b43bb983bf8f438b322fecd40ac334b746af` |
| Mutation F2 (S6 comparison deleted) — KILLED | `mut-F2.txt` | `91deb68bf7b6add6d220f4f94f5a753f804ccb0763018a706f8f2262a51afe04` |
| Mutation F4c (damaged-line tally deleted) — KILLED | `mut-F4c.txt` | `c3787b93ed7f64b406e3584afe1cc9089c4c039f9d323ed1fbae842ed99ae382` |
| Fix-round baseline hashes (restore proof) | `fix-baseline-hashes.txt` | `5966d134c12a4d74f7bb675913983b1c0a2e2be2b0691256116bf2324724efca` |

Restore proof: core.py → `5b286130…` · hexfile.py → `c26a7540…` — both back
to the digests recorded in `fix-baseline-hashes.txt` before the mutations; no
mutant left in place.

---

### Review round 2 fixes (code-reviewer N1 + LOW, 2026-10-25)

Third pass over this increment per `kimi/BRIEF-inc-9-fix2.md`. The fixes
touch 1 SOURCE file (`s19_app/hexfile.py`) and 2 test files
(`tests/test_b99_truncation.py`, the `EXPECTED_SCANNED_TEST_FILES` bump in
`tests/test_id_registry.py`) — the increment stays at 4/4 inside the budget.

| Finding | Fix | Arm / evidence |
|---|---|---|
| **N1 [MEDIUM]** — a HEX file with CR-only line endings loaded 0 bytes and reported a false `HEX-NO-EOF`: binary mode split lines only on `\n`, so the whole file arrived as one line (`:020000040001F9\r:80FF…`, 627 chars → `Length mismatch`, no EOF record ever parsed) | `IntelHexFile._load` now reads the bytes once and iterates `data.splitlines()` — bytes `splitlines` splits on `\r`, `\n` and `\r\n` alike — keeping the round-1 rule intact: lines are decoded strictly only up to and including the first EOF record; after it, non-empty lines are counted by stripping the BYTES, never decoded | NEW `test_tc_b99_09_line_endings_cr_lf_crlf`: the same HEX content saved CR-only, LF-only and CRLF loads the same 272-byte image (independent-reader oracle) with ZERO notices in all three encodings. NEW `test_tc_b99_09_cr_only_binary_tail_after_eof`: a CR-only HEX followed by raw `0xFF` padding loads with exactly ONE `HEX-AFTER-EOF: 1 record(s)…` notice and the oracle image. RED on the pre-fix tree: `red-fix2.txt` (2 failed — both arms; the LF and CRLF variants inside the first arm pass, so only the CR-only encoding is broken, exactly the review's HEAD observation). Mutation (`splitlines()` → `split(b"\n")`) → KILLED: both CR-only arms RED while the other 5 TC-B99-09 nodes stay GREEN (`mut-N1.txt`); restore by hash — fixed-tree hexfile.py `a51ec5d9…` |
| **LOW** — AT-B99-03's flow arm still picked the project row by assigning `listing.index` directly | the row pick is now a CLICK on the painted `#project_list ListItem` (the flow-picker idiom already used later in the same test), located by its rendered label; the `ListView` local import is gone | `test_at_b99_03_pilot_flow_source_fails` — black-box only; stability 8/8 consecutive runs, 3 passed each (`stability-fix2-at03.txt`) |

Registry guard: `EXPECTED_SCANNED_TEST_FILES` 199 → **205**, measured two
independent ways that agree (`scanned_test_files()` and `shopt -s globstar; ls
tests/*.py tests/**/*.py | sort -u | wc -l`). The increment adds
`tests/test_b99_truncation.py`; the bump also absorbs the five batch-99
Inc-1/2 modules committed on this base without a bound bump
(`tests/test_b99_corpus.py`, `tests/test_b99_s0.py`,
`tests/support/__init__.py`, `tests/support/independent_reader.py`,
`tests/fixtures/synth/generate.py`). The guard caught the drift on this
run — it was red at 205-vs-199 before the bump (`green-fix2-census-
registry.txt` is green at 36 passed after it).

Reverse census (fix 2): `grep -rln "IntelHexFile\|hexfile" tests/` → 15
files, all re-run (below); a targeted pin scan for line-ending/splitting
behaviour in `tests/test_hexfile.py` finds no old pin (no re-pin; the new
behaviour was previously pinned nowhere). No test pinned the `\n`-only
split — the mutation transcript is the load-bearing check.

GREEN (fix 2): `tests/test_b99_truncation.py` **25 passed**
(`green-fix2-full.txt`; 23 → 25 nodes: +`test_tc_b99_09_line_endings_cr_lf_crlf`,
+`test_tc_b99_09_cr_only_binary_tail_after_eof`); HEX-loader census (the
15 `grep -rln "IntelHexFile\|hexfile"` files): **522 passed, 1 xfailed, 6
failed** (`green-fix2-hexloaders.txt`) — the six failures are all declared,
none a regression: 4 are the engine/test-file guards vs `main`
(`test_tc027` + the three `test_tc031/32` direction-b guards) failing loud on
this increment's uncommitted `core.py`/`hexfile.py` changes and the
round-1 re-pin of `tests/test_core_srecord_validation.py` — the guard working
as designed, declared since round 1; `test_at031b_two_saves_are_distinct_no_
clobber` fails identically on the pristine `main` checkout (pre-existing,
HEX-loader-independent — it never loads a HEX file); `test_at068b_…` passed
in isolation (5.6 s, same run as at031b) — a crowded-batch flake of the kind
declared in round 1;
`tests/test_address_census.py` + `tests/test_id_registry.py` **36 passed**
(`green-fix2-census-registry.txt`); AT-B99-03 **8/8 runs × 3 passed**
(`stability-fix2-at03.txt`).

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED fix round 2 (2 failed — both new arms on the pre-fix tree) | `red-fix2.txt` | `2c4dbf320bf8343c12fde78a87f0e54fe45dc4e55636fa50bc1c08184087957d` |
| GREEN full truncation file (25 passed) | `green-fix2-full.txt` | `be62d5a54261a2c9d302d2eec90a155ea89103b0a5040f835aa9cb243a88f89e` |
| GREEN HEX-loader census (15 files: 522 passed, 6 declared failures — 4 engine guards, at031b pre-existing on main, at068b green in isolation) | `green-fix2-hexloaders.txt` | `4aceb65b1c7c744a53b8b6f4081bb1647e32019959d08ea61aedaac4cc4dd5a3` |
| GREEN address census + id registry (36 passed) | `green-fix2-census-registry.txt` | `90fb312b9c69a36524d85c17946193e41a18ab4096792aed3c4c8468ac4d2ed1` |
| AT-B99-03 stability ×8 (3 passed each) | `stability-fix2-at03.txt` | `e296824f90e6db1826672035ffb25d867034ec0ad9b078d3d7dfeb715e21fad8` |
| Mutation N1 (splitlines → split(b"\n")) — KILLED | `mut-N1.txt` | `148a2a9e17d708b1afb5cb1a8402277297fe02389561604f0adfecdfd5740f76` |
| Fix-2 baseline hashes (pre-mutation digests) | `fix2-baseline-hashes.txt` | `2cc1d2408f205e82b4f701e1a3ef6175ddb6500a2bedba8ce37e1d53fa1aabbe` |

Restore proof: hexfile.py → `a51ec5d9…` — the fixed-tree digest after the
`split(b"\n")` mutant was reverted; CRLF preserved (254 `\r\n` lines before
and after). No mutant left in place.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: BLOCK (F1 HIGH: a HEX with a binary tail failed to load — regression; F2, F3 MEDIUM; F4 LOW) · round 2: OK to advance, F1–F4 closed; N1 MEDIUM (CR-only HEX loaded 0 bytes) fixed in round 3 by Kimi and verified by the orchestrator (CR, LF, CRLF each load the same 4 bytes with 0 notices; 35 passed) |

---

## 5 · Risks

- The S19 loader now treats the FIRST S7/S8/S9 as the end of the image: a file
  with records after its terminator loses them from the interactive image
  (today they were kept — `rw-p04` `s19_data_after_term` ranges included
  `0x2000`). HLR-154 decides this; tests that relied on the old behaviour were
  re-pinned (see Reverse census).
- `SRecord` now accepts S6 lines (count field). A malformed S6 that previously
  surfaced as a parse error now parses structurally; its count check only
  fires outside the width gate, matching LLR-154.1.
- The Issues panel gains ERROR issues for the five codes only; plain parser
  errors (bad checksums etc.) stay out of the panel exactly as before.
- The five notice codes are matched by a leading-token regex
  (`load_notice_code`); a plain parser error whose text starts with
  `S19-…`/`HEX-…` would be misclassified — no current parser diagnostic has
  that shape, and the producers own the code vocabulary.

---

## 6 · Pending items / spec deviations

- None blocking. Declared: S6 parse support is new engine behaviour required
  by LLR-154.1's S6-count arm (the engine previously rejected S6 outright;
  the boundary arm generates a >65 535-record S6 image into tmp at test time).

---

## 7 · Suggested next task

Batch-99 Increment 10 (per the batch plan / `BRIEF-inc-10.md`).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4 SOURCE files (`git status` — `core.py`, `hexfile.py`, `flow_execution_service.py`, `app.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_truncation.py` (25 nodes after the review rounds — DDR-corrected 2026-10-26, see the signed-balance ledger) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | LLR-154.1/154.2 are engine-layer and are verified by the TC layer (the repo convention: engine crossing named in the LLR, verified through the loader's public parse); no separate layer-0 node is required by the LLRs' validation fields (`test (unit)` / `test (integration)` = the TCs) |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: `red-initial.txt` (16 failed on the unmodified tree) + 3 mutation transcripts with hash-verified restores |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 51-file probe, focused pins re-run (409 tests green), 1 re-pin recorded, 2 pre-existing flakes declared |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — only the 4 SOURCE files + new test + `.dev-flow/**` evidence/packet + 1 re-pinned test |
| 8 | Frozen interfaces untouched | all | ✓ | the engine change is the crossing NAMED in LLR-154.1/154.2 ("Crosses the frozen engine layer, §7; named here"); the notice dict keeps the existing `load_errors` 4-key shape |
| 9 | Coverage claims verified **on disk** | all | ✓ | TC arms read the committed corpus files and `manifest.json` from disk; the examples control globs `examples/**/*.s19` from disk |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (defect files under the identical probe; in-gate `synth_wrong_s5` count probe) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: per-arm KILLED, inert arms named (controls stay green under each mutation) |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 4 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: pre-edit scan, 1 re-pin, no silent survivors |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 4 artifacts asserted in emitted form (notice dicts, block diagnostics, painted status, written-file rule) |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` (the one published form for a not-yet-reviewed packet) |
| 16 | **Evidence files** declared | all | ✓ | §4: 15 transcripts with stored-byte SHA-256 digests |
