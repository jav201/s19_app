# Validation — s19_app — Batch 2026-10-25-batch-99

> Phase 4 artifact. Written by the orchestrator (the one writer, `stations/shared-homes-roles.md` §Delegation) from the rows `qa-reviewer` returned in `design/P4-qa-draft.md`.
> `qa-reviewer` ran as a sub-agent with `agents/qa-reviewer.md`, in validation mode. It evaluated the results and executed only the spot checks it names. The gate run, the triage, the flake comparison and the flip table were executed by the orchestrator.
> Shape: `templates/validation-template.md`. Every state word is one of the seven in `stations/shared-evidence.md` §Evidence states.

**`Mode`:** `validation`

## ✅ Verdict (read first)

- **Result:** `PASS-WITH-NOTES`
- **Gate run:** `python -m pytest -q -p no:cacheprovider` (whole suite, a superset of CI's `pytest -q -m "not slow"`) · exit 1 (`__SUITE_DONE__ rc=1`; 14 failed / 3756 passed / 3 skipped / 3 xfailed, 2:05:30) · `e7732f6` in the clean worktree `s19_app-b99-suite` (the commit is attested by `evidence/suite-triage-e7732f6.md` and the worktree path in the tracebacks; the transcript has no header line naming the command or the commit — G-008) · executed by the orchestrator. Transcript: `evidence/suite-full-e7732f6.txt`. **Binding:** `git diff e7732f6 31bac78 --stat -- s19_app` is empty, so the product the run measured is the product on main. `tests/` differs in 9 files (Increment 012's C-18 joins and black-box entries, Increment 013's two re-pins). Those changed nodes were never in a complete run. Their GREEN comes from targeted runs on the final tree (G-001). **CONFIRMATION (closes G-001):** the same command on the final tree `75f947a` · exit 1 (`__SUITE_DONE__ rc=1`; **12 failed / 3755 passed / 3 skipped / 3 xfailed**, 1:58:07; 12 + 3755 + 3 + 3 = 3773 = the collection on main) · clean worktree `s19_app-b99-suite`, header lines name the command, tree and start time · executed by the orchestrator. Transcript: `evidence/suite-full-75f947a.txt`; triage: `evidence/suite-triage-75f947a.md`. 8 baseline ids fail for their recorded causes; the two stale pins of Increment 013 pass; 4 intermittent nodes fail, each failing on `a293213` too or passing in isolation on both trees. One of them, `at057b`, is a single-pause test race that fails more often on head (10/15 vs 3/15); a patient probe delivers every step on both trees (`evidence/probe-at057b-patient.txt`). No product defect, no HIGH.
- **Layer 0:** `3 unit(s) met the criterion · 3 carry a named reddening mutation`
- **Requirements:** `51`/`51` pass (11 HLR + 40 live LLR; LLR-157.3 retired in LED .2) · `0` blocker fails
- **Black-box acceptance (Layer B):** ✓ every story US-141..US-152 has one AT node that observes its outcome through the shipped surface (14 of 14 ATs, each exactly one node on disk, C-18). Every story has a negative arm at the surface except US-150 (G-002). Several boundary arms are realised only at TC level (G-002, minor).
- **Surface-reachability (bidirectional):** ⚠ `3` minor gaps: the HEX input dimension of US-143, the chain-set report's not-applied listing of US-145 (seen only at the service API), and the Bytes-field refusal message of US-150 (seen only at the unit). All three are G-002/G-003.
- **Supersession inspection (read off the P3 packets):** ✓ every packet with a superseded marker shows its surviving refs negative (Inc 3, 3b, 5, 7, 8, 9, 10, 11). Inc-6 carries a Correction population row but no V-3 table. A grep on main shows the export path calls only `sanitize_export_segment` / `build_export_basename` (`segment_split_view.py:651, 796-811`), so nothing survives (note G-009). Incs 12 and 13 are tests-only.
- **Test ledger:** ✓ reconciles by collection: `3634 − 0 + 142 = 3776` (baseline `a293213` → gate run `e7732f6`), then `3776 − 4 + 1 = 3773` (Inc-12 merges and one addition), equal to `pytest --collect-only` on main = **3773** (qa-reviewer, executed). The b99 files alone collect **139**.
- **Evidence checklist (qa-reviewer):** `qa-reviewer · 11 of 11 rows ✓ with evidence` (two rows carry notes: G-001, G-002)

**Who did what.**
- **Orchestrator:** the gate run on `e7732f6`; the triage; the flip table on `e7732f6` (`evidence/p4-premises/`); the flake re-runs (`evidence/flake-*.txt`); the Inc-5 final sweep after the Kimi fix session timed out (`inc-5/green-fix-sweep.txt`, `stability-at10.txt`).
- **The increment implementer (Kimi K2.8, briefs `kimi/BRIEF-*.md`):** every `evidence/inc-*/` transcript, `evidence/ddr/` (Increment 012) and `evidence/inc-13/`. Each packet says "run by the implementer" in its worktree.
- **Independent reviewers** (`code-reviewer` for Incs 1–11 and 13; `qa-reviewer` and `software-dev` for Inc 12): each packet's §4b.
- **qa-reviewer (this draft) executed only these spot-checks:**
  - `pytest --collect-only` on main (3773 / 139);
  - one targeted run of the 11 b99 test files, `tests/test_import_census.py` and the re-pinned snapshot cell, on main HEAD `75f947a`. That commit is `31bac78` plus one `.dev-flow/BACKLOG-CODE.md` line; `s19_app/` and `tests/` are identical (`git diff 31bac78 75f947a --stat -- s19_app tests` is empty). Result: **142 passed in 7:25, exit 0** (139 b99 nodes + 2 import-census nodes + 1 snapshot cell), every node named `PASSED` under `-rA`, all 14 `test_at_b99_*` among them. Transcript: `evidence/p4-qa/qa-spot-b99-31bac78.txt`;
  - three standalone re-runs of `test_tc_b97_64_…` and `test_tc024_report_trigger_invalid_dest_refused` on main: 6 of 6 passed (`evidence/p4-qa/qa-spot-flakes-31bac78.txt`);
  - one execution probe of `parse_new_bytes` (P-16) and a read of `list_projects` / `_load_from_item` (P-19, P-20).

  It ran none of the gate, increment or flip-table evidence it cites.

**Gate-run classification against `evidence/baseline-pytest-a293213.txt`** (the triage, spot-checked line by line against both transcripts' `E` lines):
- **Baseline ids (11).** 9 fail with the same cause on both trees. The cause line is byte-identical apart from the worktree path, e.g. `prototypes\cambios_10_12_2026\help_sections.md` absent (both runs used a clean worktree); `two saves must keep two files … 1 == 2`; `the second save silently clobbered the first`; `baseline wrote []`; `Compared A.s19 vs B.s19: 1 runs.`; the same palette and BINDINGS drift. The other 2 baseline ids (`test_tc328_…`, `test_at063c_…`) now pass.
- **Non-baseline (5).**
  - 3 are load or ordering flakes, re-run alone and passing: `test_tc_b97_64_…`, `test_tc024_report_trigger_invalid_dest_refused`, `test_saveback_width_32_…`. `saveback_width_32` also fails on the base tree, in `flake-patch-editor-v2-base-vs-head.txt` run 1 at `a293213`. For `tc_b97_64` and `tc024_invalid_dest` the batch's evidence holds no standalone re-run transcript (G-004).
  - 2 were real stale test pins, fixed tests-only in Increment 013 (`1a59d3b`), each with RED and GREEN: `test_tc653_safe_text_import_census` and `test_tc016s_density_layout_snapshot[patch-comfortable-120x30]`.
  - No product defect.

> Any ⚠ above → read the matching Gap row.

---

## Detail (reference)

### Layer 0 — unit

| Unit | Which criterion | Node id | Result |
|---|---|---|---|
| `_is_data_record` (S19 data-record predicate, `core.py`) | boundary (record type S0 vs S1/S2/S3) | `tests/test_b99_s0.py::test_tc_b99_04_predicate_feeds_every_walk`, `::test_tc_b99_04_boundary_s0_alongside_data_at_zero` | pass — `executed` (implementer, `evidence/inc-2/green-tc_b99_04_predicate.txt`, `green-tc_b99_04_boundary.txt`; again in the gate run, orchestrator) |
| `sanitize_export_segment` / `build_export_basename` (`segment_split_view.py:592, 630`) | boundary + cyclomatic ≥ 3 (allowlist, reserved device names, 100/200-char caps, empty result) | `tests/test_b99_export.py::test_tc_b99_28_sanitiser_hostile_set_and_boundaries` | pass — `executed` (implementer, `evidence/inc-6/green-tc_b99_28.txt`; post-Inc-12 `evidence/ddr/green-export.txt`) |
| `parse_new_bytes` hex-only grammar (`change_service.py:281`) | boundary + invalid input (1–2 hex digits, `0x`, `100`, `G1`) | `tests/test_b99_bytes_field.py::test_tc_b99_32_hex_only_token_grammar` | pass — `executed` (implementer, `evidence/inc-11/green-tc_b99_32.txt`; `evidence/ddr/green-bytes.txt`); qa-reviewer probe on main: `0F 10 1F 20 → [0xf,0x10,0x1f,0x20]`, `G1` and `100` refused naming the token |

Excluded under C-51, as each packet's row 3 declares: the other LLRs are integration- or service-layer and are verified by their TCs (Inc 1, 3a, 3b, 4, 5, 7, 8, 9, 10).

| Unit | Mutation applied | RED observed? | Transcript |
|---|---|---|---|
| `_is_data_record` | re-admit S0 in the predicate (LLR-153.1/153.2/153.3) | yes — KILLED, `6 failed` (TC-04, 05, 06, 07) | `.dev-flow/2026-10-25-batch-99/evidence/inc-2/mut-LLR-153.1.txt` |
| sanitiser | bypass the sanitiser (`mapped = name[:100]`) | yes — KILLED, `1 failed` (`../` survived) | `.dev-flow/2026-10-25-batch-99/evidence/inc-6/mut-LLR-160.1.txt`, `mut-fix-LLR-160.1.txt` |
| `parse_new_bytes` | restore `int(token, 0)` first | yes — KILLED, `1 failed` | `.dev-flow/2026-10-25-batch-99/evidence/inc-11/mut-LLR-161.1.txt`, `mut-LLR-161.1-fix.txt` |

**Every declared LLR mutation (§5.2) has a RED transcript:** 152.1/.2/.3 (`inc-1/mut-LLR-152.*`) · 153.1–.3 (`inc-2/mut-LLR-153.1`) · 154.1/.2/.3 (`inc-9/mut-LLR-154.*`) · 155.3 (`inc-3a/mut-155.3-*`, `inc-3b/mut-LLR-155.3`) · 155.5, 155.6 (`inc-3b/mut-LLR-155.5/.6`) · 155.7 (`inc-3a/mut-155.7-rederived-unlink`) · 155.8 (`inc-5/mut-LLR-155.8`) · 157.2, 157.4 (`inc-4/mut-LLR-157.2/.4`) · 160.1, 160.5 (`inc-6/mut-LLR-160.1/.5`) · 161.2 (`inc-11/mut-LLR-161.2`, `ddr/mut-PQ6`) · 162.1, 162.3 (`inc-7/mut-LLR-162.1/.3`). The LLRs whose negative control is an executed premise RED also carry extra mutants: 156.1, 156.2, 156.4, 158.1–.3, 159.1, 160.2–.4, 162.2. Executor: the implementer, each re-checked in the increment's §4b review.

### UX walkthrough — trigger family D fired (D1)

| Criterion (when the user does X, they observe Y) | Driven with the REAL mechanism | Painted result asserted | Verdict |
|---|---|---|---|
| UX-C1: a lane whose PATCH ends notices/error names what was not applied on its terminal log line | Textual pilot, `#fx_run` click | `PATCH: 1 of 2 entries not applied (0x00020000 skipped-outside)` (AT-B99-06); both PATCH and CRC riders on one line (TC-B99-18 riders node) | pass — `executed` |
| UX-C2: the last diagnostic is the cause (code plus address or count) | pilot, `#fx_run` | `applied 0 of 1 entries: 0x00020000 skipped-outside` + `chain halted` (AT-06); `CRC region 0x20000-0x30000 holds 0 image bytes - nothing written` (AT-10); `S19-NO-TERMINATOR` in the lane log (AT-03) | pass — `executed` |
| UX-C4: outcome first, inside 50 characters | pilot, `#fx_run` | `Chain set not run` at index < 50 on `#fx_log` and `#log_line_4`, both lanes and the file named, `Nothing written` (AT-04) | pass — `executed` |
| UX-C5: the placement-error text names file, folder, cause and next step | TC level only (forced `PermissionError`) | `test_tc_b99_12_forced_permission_error_refuses_cleanly` | pass — `executed`, not through the surface |
| UX-C6: the final status after save-back names the not-applied entry next to the verify word | pilot, Patch Editor clicks | `Saved + verified: at_b99_08.s19` + `includes 1 entry not applied before this save` + `0x0000EB60`, with no `overwritten by:` (AT-08) | pass — `executed` |
| UX-C7: the load status line leads with the integrity code | pilot, `l`, typed path, `#load_ok` | `Loaded cut.s19 with integrity notices: S19-NO-TERMINATOR`, Issues chip names it (AT-03) | pass — `executed` |
| UX-C8: A2L `n/a` with its reason | pilot, Load dialog, A2L window `2`, describe `d` | `n/a` cell and `Scalar value: n/a (rat_func_no_real_root)` at 118×40 and 80×24 (AT-09) | pass — `executed` |
| UX-C9: placeholder and help state the hex rule | pilot (placeholder read off the mounted Input) | TC-B99-33 (and `ddr/mut-PQ6.txt` RED) | pass — `executed` |
| UX-C10: file-derived text renders literally | pilot, `#fx_run` | 0 markup spans, 0 control bytes, raw payload absent from the report (AT-07); TC-B99-10 hostile name; TC-B99-29 hostile segment name | pass — `executed` |
| UX-C11: export status leads with the outcome and says `wrote` / `reused` and the `_<N>` name | pilot, Split/Join/Export window | `_1`, `wrote`, `reused` in the painted status (AT-11) | pass — `executed` |
| UX-C3: no new glyph, status word or colour class | inspection | Inc-8 packet row 8: "the five UX-C3a maps are byte-identical in the diff" | `approved` by the Inc-8 reviewer (inspection, not a test) |

**Mechanism used:** `a UI test driver` (Textual `run_test` pilot keys and clicks; files on disk read by `tests/support/independent_reader.py`)

| Act | What it is | Performed? |
|---|---|---|
| Automated walkthrough | the criteria above, driven through the REAL mechanism | `performed` |
| Expert inspection | a cognitive walkthrough against declared criteria, by a reviewer and not a user | `performed` — at design time only (`design/PDR-ux.md`, UX-C1..C11); no post-build cognitive walkthrough at P4 |
| Evaluation with users | real users of the system, doing the tasks named in the context of use | `not performed — internal tool batch; no user session was planned in §5` |

- **Method:** automated pilot drives at the batch's reference geometries (118×40, 120×40, 80×24, 280×60 for the long rider line).
- **Participants or population:** none — no human participant.
- **Evidence of the evaluation:** the AT transcripts below; `design/PDR-ux.md`.
- **Limits:** the pilot proves the text is painted, not that an engineer reads it correctly. No human saw the refusal wording in context.

### Layer A — functional (white-box): per-requirement results

> Result column: state per §Evidence states. "impl" = the increment implementer (Kimi K2.8) in its worktree. Every node below exists on disk (checked by `grep -rhoE "def test_tc_b99_NN…" tests/` on main). "GATE" = in the orchestrator's gate run on `e7732f6` with its node unchanged since. "DDR" = the node changed in Increment 012, so its post-change GREEN is `evidence/ddr/green-<file>.txt` (impl; re-checked 139/152 passed by software-dev / qa-reviewer, §4b). "SPOT" = this reviewer's targeted run on main (142 passed, exit 0, on main `75f947a` = `31bac78` for `s19_app/` and `tests/`; transcript `qa-spot-b99-31bac78.txt`, to be copied to `evidence/p4-qa/`).

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| HLR-152 | test | `tests/test_b99_corpus.py` (5 nodes) | 2 runs → 0 differing bytes; 0 manifest mismatches; 0 missing classes | `executed` pass | impl `inc-1/green-full.txt`; GATE; SPOT |
| LLR-152.1 | test | TC-B99-01 `test_tc_b99_01_deterministic` | 0 differing bytes | `executed` pass | impl `inc-1/green-tc_b99_01.txt`; RED `mut-LLR-152.1.txt`; GATE; SPOT |
| LLR-152.2 | test | TC-B99-02 `test_tc_b99_02_coverage_classes` | 0 missing classes | `executed` pass | impl `inc-1/green-tc_b99_02.txt`; RED `mut-LLR-152.2.txt`; GATE; SPOT |
| LLR-152.3 | test | TC-B99-03 `…_03_reader_independence_and_exact`, `…_03b_hex_extents_literal` | AST import census clean; 0 byte mismatches | `executed` pass | impl `inc-1/green-tc_b99_03.txt`; RED `mut-LLR-152.3.txt`; GATE; SPOT |
| HLR-153 | test | `tests/test_b99_s0.py` (6 nodes) | written data == source data; 0 extra addresses; 0x0 patch skipped | `executed` pass | impl `inc-2/green-fix-b99_s0.txt`; GATE; SPOT |
| LLR-153.1 | test | TC-B99-04 `…_04_predicate_feeds_every_walk`, `…_04_boundary_s0_alongside_data_at_zero` | 0 S0 bytes in any walk | `executed` pass | impl `inc-2/green-tc_b99_04_*.txt`, RED `red-tc_b99_04_*.txt`; GATE; SPOT |
| LLR-153.2 | test | TC-B99-05 `…_05_hexview_builders_use_same_predicate` | as above | `executed` pass | impl `inc-2/green-tc_b99_05.txt`, RED `red-tc_b99_05.txt`; GATE; SPOT |
| LLR-153.3 | test | TC-B99-06 `…_06_written_images_carry_s0_as_header_only` | 0 data at 0x0 (independent reader) | `executed` pass | impl `inc-2/green-tc_b99_06.txt`; GATE; SPOT |
| LLR-153.4 | test | TC-B99-07 `…_07_patch_at_s0_address_is_outside` | disposition `skipped-outside`, 0 bytes at 0x0 | `executed` pass | impl `inc-2/green-tc_b99_07.txt`, RED `red-tc_b99_07.txt`; GATE; SPOT |
| HLR-154 | test | `tests/test_b99_truncation.py` (25 collected) | 5 defect files → 5 notices; 5 flows → SOURCE error, 0 files; controls 0 notices | `executed` pass | impl `inc-9/green-fix2-full.txt`; DDR `green-truncation.txt` (24 passed — AT-03 sits outside that per-file count's split; see `green-b99.txt` 175 passed); SPOT |
| LLR-154.1 | test | TC-B99-08 (7 functions, 7 parametrised expansions) | defect → named notice; controls (examples, wide S6, trailing blanks) → 0 | `executed` pass | impl `inc-9/green-tc_b99_08.txt`; RED `mut-LLR-154.1.txt`; DDR; SPOT |
| LLR-154.2 | test | TC-B99-09 (6 functions: EOF, binary tail, CR/LF/CRLF) | as above for HEX | `executed` pass | impl `inc-9/green-tc_b99_09.txt`; RED `mut-LLR-154.2.txt`; DDR; SPOT |
| LLR-154.3 | test | TC-B99-10 `…_source_error_no_file`, `…_clean_source_still_writes`, `…_hostile_name_renders_literally` (renamed from an AT arm in Inc 12) | SOURCE `error`, 0 files | `executed` pass | impl `inc-9/green-tc_b99_10.txt`; RED `mut-LLR-154.3.txt`; DDR; SPOT |
| HLR-155 | test | `tests/test_b99_staging.py` (31 functions) | 8×20 → 0 foreign markers; work copy kept; dup set refused; corrupted write → error; source bytes and mtime unchanged; forced error → `WorkareaPlacementError` | `executed` pass | impl `inc-3a/green-final.txt`, `inc-3b/green-full-staging.txt`; DDR `green-staging.txt` (31 passed); SPOT |
| LLR-155.1 | test | TC-B99-11 (3 functions), TC-B99-44 (2 functions, LED .8) | private staging; junction at `temp/.staging` refused | `executed` pass | impl `inc-3a/green-tc_b99_11.txt`; RED `mut-155.1-shared-staging.txt`; TC-44: DDR `green-staging.txt`, RED `inc-3a/mut-fix2-f3-temp-staging.txt`; SPOT |
| LLR-155.2 | test | TC-B99-12 (7 functions incl. 8 writers × 1 name × 20 trials) | 0 mismatches | `executed` pass | impl `inc-3a/green-tc_b99_12.txt`; RED `mut-155.2-check-then-copy.txt` (35/68 mismatches); DDR; SPOT |
| LLR-155.3 | test | TC-B99-13 (6 functions) | race-free reuse, own bytes returned | `executed` pass | impl `inc-3a/green-tc_b99_13.txt`; RED `mut-155.3-*`, `inc-3b/mut-LLR-155.3.txt`; DDR; SPOT |
| LLR-155.4 | test | TC-B99-14 (3 functions) | notice naming the file; app running | `executed` pass | impl `inc-3a/green-tc_b99_14.txt`, RED `red-tc_b99_14.txt`; DDR; SPOT |
| LLR-155.5 | test | TC-B99-15 (2 functions) | dup set refused, 0 files | `executed` pass | impl `inc-3b/green-tc15-16-census.txt`; RED `mut-LLR-155.5.txt`; DDR; SPOT |
| LLR-155.6 | test | TC-B99-16 (2 functions) | corrupted write → WRITE-OUT `error` naming the address | `executed` pass | impl `inc-3b/green-tc15-16-census.txt`; RED `mut-LLR-155.6.txt`; DDR; SPOT |
| LLR-155.7 | test | TC-B99-39 (AST census of delete calls) | every delete tied to its creating call | `executed` pass | impl `inc-3a/green-tc_b99_39.txt`; RED `mut-155.7-rederived-unlink.txt`; DDR; SPOT |
| LLR-155.8 | test | TC-B99-38 `…_38_concurrent_crc_writes_of_the_same_stem` | each file's CRC == its own (independent reader) | `executed` pass | impl `inc-5/green-b99_crc_region.txt`, orchestrator `inc-5/green-fix-sweep.txt`; RED `mut-LLR-155.8.txt`; GATE; SPOT |
| HLR-156 | test | `tests/test_b99_patch_truth.py` (13 functions) + re-pinned TC-714 | 8-case matrix; 0 WRITE-OUT for error; 100 % non-applied named; 0 `CLEAN`; 0 markup spans | `executed` pass | impl `inc-8/green-tc17-20-at06-07.txt`, `green-repins.txt`; DDR `green-patch-truth.txt` (20 passed); SPOT |
| LLR-156.1 | test | TC-B99-17 (6 functions, the 8-case matrix) | `error,error,notices,error,error,error,error,ok` | `executed` pass | impl `inc-8/green-tc17-20-at06-07.txt`; RED `mut-LLR-156.1.txt` (3 failed); DDR; SPOT |
| LLR-156.2 | test | TC-B99-18 (3 functions incl. the Inc-12 dual-rider node) | outcome carries change records and refusals | `executed` pass | impl as above; RED `mut-LLR-156.2.txt`; DDR `green-tc18-riders.txt`; SPOT |
| LLR-156.3 | test | TC-B99-19 `…_19_chain_set_report_lists_what_was_not_applied` | report names every non-applied address | `executed` pass (service level; G-003) | impl `inc-8/green-tc17-20-at06-07.txt`, RED `red-tc17-20-at06-07.txt`; DDR; SPOT |
| LLR-156.4 | test | TC-B99-20 `…_20_flow_report_lists_what_was_not_applied` | 0 `CLEAN` on non-ok runs | `executed` pass | impl as above; RED `mut-LLR-156.4.txt`; DDR; SPOT |
| HLR-157 | test | `tests/test_b99_editor_image.py` (8 functions) | file @0xEB10 == source, @0xEB40 == `01 02`; 0 stale bytes | `executed` pass | impl `inc-4/green-editor-image.txt`; DDR (rename only); SPOT |
| LLR-157.1 | test | TC-B99-21 `…_21_editor_image_is_source_plus_document` | image == source + document | `executed` pass | impl `inc-4/green-tc_b99_21.txt`; RED `mut-LLR-157.1*.txt`; SPOT |
| LLR-157.2 | test | TC-B99-22 (3 functions; one renamed from an AT arm in Inc 12) | 0 stale bytes after remove/edit/undo | `executed` pass | impl `inc-4/green-tc_b99_22.txt`; RED `mut-LLR-157.2.txt`; DDR; SPOT |
| LLR-157.4 | test | TC-B99-40 (3 functions) | strip shows the source byte as before | `executed` pass | impl `inc-4/green-tc_b99_40.txt`; RED `mut-LLR-157.4.txt`; SPOT |
| HLR-158 | test | `tests/test_b99_a2l_encode.py` (7 functions) | MSB 4113 ↔ `10 11`; RAT_FUNC 30 ↔ raw 300; COMPU_TAB refusals and flags; LINEAR unchanged | `executed` pass | impl `inc-10/green-full.txt`; DDR `green-a2l.txt` (7 passed); SPOT |
| LLR-158.1 | test | TC-B99-23, TC-B99-42 (per-module `MOD_COMMON`, LED .6) | effective order `big` under MSB_FIRST | `executed` pass | impl `inc-10/green-tc_b99_23.txt`, `green-fix-new-module.txt`; RED `mut-LLR-158.1.txt`, `mut-LOWa-first-module-wins.txt`; DDR; SPOT |
| LLR-158.2 | test | TC-B99-24, TC-B99-43 (zero-denominator root, LED .6) | 30 → raw 300; raw 300 → 30.0 | `executed` pass | impl `inc-10/green-tc_b99_24.txt`; RED `mut-LLR-158.2.txt`, `mut-LOWb-denominator-check.txt`; DDR; SPOT |
| LLR-158.3 | test | TC-B99-25 `…_25_compu_tab_refusals_and_flags` | NOINTP 13.0 refused naming neighbours; INTP 500/−50 refused naming range; off-grid flagged | `executed` pass | impl `inc-10/green-tc_b99_25.txt`; RED `mut-LLR-158.3.txt`, `mut-F1-nearest-entry.txt`; DDR; SPOT |
| HLR-159 | test | `tests/test_b99_crc_region.py` (8 functions) | empty → error, 0 files; gap → notices with exact count; full → CRC == independent CRC | `executed` pass | impl `inc-5/green-b99_crc_region.txt`; orchestrator `inc-5/green-fix-sweep.txt`; GATE; SPOT |
| LLR-159.1 | test | TC-B99-26 (2 functions) | `error`, 0 files, note last and only | `executed` pass | as HLR-159; RED `mut-LLR-159.1.txt`; GATE; SPOT |
| LLR-159.2 | test | TC-B99-27 (4 functions incl. 1-byte boundary, R23 count) | `notices` with the exact absent count | `executed` pass | as HLR-159; RED `inc-5/mut-f1.txt`; GATE; SPOT |
| HLR-160 | test | `tests/test_b99_export.py` (23 functions) | hostile set → 0 outside; collision refused; junction refused; MAC-only 0 data; `_1` pair; ≤ 200 chars | `executed` pass | impl `inc-6/green-review2.txt`, `green-fix-export-py311/py312.txt`; DDR `green-export.txt` (23 passed); SPOT |
| LLR-160.1 | test (unit) | TC-B99-28 | segment part matches `^[A-Za-z0-9_-]{1,100}$`, never a device name | `executed` pass | impl `inc-6/green-tc_b99_28.txt`; RED `mut-LLR-160.1.txt`; DDR; SPOT |
| LLR-160.2 | test | TC-B99-29 (5 functions incl. junctioned project home, renamed from an AT arm) | 0 files outside the root; link refused | `executed` pass | impl `inc-6/green-tc_b99_29.txt`; RED `mut-LLR-160.2.txt`, `mut-F1-py312.txt`; DDR; SPOT |
| LLR-160.5 | test | TC-B99-41 (9 functions) | collision refused before any write | `executed` pass | impl `inc-6/green-tc_b99_41.txt`; RED `mut-LLR-160.5.txt`; DDR; SPOT |
| LLR-160.3 | test | TC-B99-30 `…_30_mac_only_export_writes_no_data_record` | 0 data records | `executed` pass | impl `inc-6/green-tc_b99_30.txt`; RED `mut-LLR-160.3.txt`; DDR; SPOT |
| LLR-160.4 | test | TC-B99-31 (6 functions) | `<name>_1` (pair under one suffix); first intact; rollback of own claims | `executed` pass | impl `inc-6/green-tc_b99_31.txt`; RED `mut-LLR-160.4.txt`, `ddr/mut-PQ2c.txt`; DDR; SPOT |
| HLR-161 | test | `tests/test_b99_bytes_field.py` (3 functions) | `0F 10 1F 20` → `[0x0F,0x10,0x1F,0x20]`; `G1`, `100` refused naming the token | `executed` pass | impl `inc-11/green-fix-b99_bytes_field.txt`; DDR `green-bytes.txt` (3 passed); SPOT; qa probe on main |
| LLR-161.1 | test (unit) | TC-B99-32 | as HLR-161 | `executed` pass | impl `inc-11/green-tc_b99_32.txt`; RED `mut-LLR-161.1*.txt`; DDR; SPOT |
| LLR-161.2 | test | TC-B99-33 | placeholder and help contain the rule | `executed` pass | impl `inc-11/green-tc_b99_33.txt`; RED `mut-LLR-161.2.txt`, `ddr/mut-PQ6.txt`; DDR; snapshot re-pin `inc-13/green-snapshot.txt`; SPOT |
| HLR-162 | test | `tests/test_b99_load_project.py` (4 functions) | 3 pick paths → 3 loads; Workarea pick → 1 load; 0 reserved homes | `executed` pass | impl `inc-7/green-load-project.txt`; GATE; SPOT |
| LLR-162.1 | test | TC-B99-34 `…_34_pick_loads_the_picked_file_name` | the named file loads | `executed` pass | impl `inc-7/green-tc_b99_34.txt`; RED `mut-LLR-162.1.txt`; GATE; SPOT |
| LLR-162.2 | test | TC-B99-35 `…_35_reserved_homes_are_not_projects` | 0 reserved homes | `executed` pass | impl `inc-7/green-tc_b99_35.txt`; RED `mut-LLR-162.2.txt`; GATE; SPOT |
| LLR-162.3 | test | TC-B99-36 `…_36_workarea_files_reads_the_load_folder` | list == load folder, no `.staging` | `executed` pass | impl `inc-7/green-tc_b99_36.txt`; RED `mut-LLR-162.3.txt`; GATE; SPOT |

**Coverage census:**
- 40 of 40 live LLRs have at least one live TC node on disk with a GREEN transcript. No LLR is without a TC.
- 43 live TC ids: TC-B99-01..36 and 38..44. TC-B99-37 was retired with LLR-157.3 (LED .2), and no `tc_b99_37` node exists.
- No orphan `tc_b99_NN` id was found on disk outside this set.
- The per-TC increment transcripts are `-q`, so they name only failures. Name-level GREEN per node on the final tree is SPOT's `-rA` listing.

### Layer B — behavioral (black-box) acceptance

> One node per AT, checked by `grep -rnE "def test_at_b99_[0-9]+" tests/` on main: 14 hits, 14 distinct ids, one each (C-18). I read every AT body for private entry. Residual non-surface reads are named in the row.

| US | Acceptance test (`AT-NNN`) | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----------------------------|----------------|---------------------------------------|----------------------------|--------|
| US-141 | AT-B99-01 `tests/test_b99_corpus.py::test_at_b99_01_check_mode` | generator CLI subprocess `generate.py --check` | exit code 0 + `checked N files`; tampered copy → exit 1 naming `synth_s1.s19` | repr ✓ (committed corpus) · boundary ✓ (the check covers the empty/width-edge classes of LLR-152.2) · negative ✓ (tampered byte) | `executed` pass — impl `inc-1/green-at_b99_01.txt`; GATE; SPOT |
| US-142 | AT-B99-02 `tests/test_b99_s0.py::test_at_b99_02_save_back_excludes_s0` | pilot: `l`, typed path, `#load_ok`; Patch Editor clicks; save-back | written file via the independent reader: no byte at 0x0..0xB, data == source, header == source; Memory Map painted rows (no `0x00000000`); status `0 applied, 1 skipped` | repr ✓ · boundary ⚠ (S0-only and equal-length-S0 boundaries at TC-B99-04 only) · negative ✓ (0x0-only document → skipped) | `executed` pass — impl `inc-2/green-at_b99_02.txt`, RED `red-at_b99_02.txt`; GATE; SPOT. Residual: `type(app.screen).__name__` as a branch predicate |
| US-143 | AT-B99-03 `tests/test_b99_truncation.py::test_at_b99_03_status_leads_defect_flow_source_fails` | pilot: `l`, typed path; `p` dialog row click + `#project_ok`; `]`; `#fx_import`; `#fx_run` | status `Loaded cut.s19 with integrity notices: S19-NO-TERMINATOR`; Issues chip; lane log names the code and file; `out.s19` absent | repr/negative ✓ (cut S19) · boundary ⚠ (well-formed and trailing-blank controls, >65 535 records: TC-B99-08 only) · HEX defects ⚠ (TC-B99-09 only, G-002) | `executed` pass — DDR joined node, `ddr/green-at03-8x.txt` (8/8); SPOT. Pre-join halves: impl `inc-9/green-at_b99_03.txt` |
| US-144 | AT-B99-04 `tests/test_b99_staging.py::test_at_b99_04_duplicate_refused_distinct_parallel_markers` | pilot: `p` dialog, `#fx_import` clicks, `#fx_mode` "parallel" click, `#fx_run` | 8 lane files byte-equal to their markers (reader); chain-set report `- **Mode:** parallel`; refusal in `#fx_log` and `#log_line_4` inside 50 chars, both lanes + `same.s19` named; nothing new on disk | repr ✓ (8 distinct) · boundary ✓ (8 writers; `same`/`SAME` case-folded) · negative ✓ (dup refused) | `executed` pass — DDR `ddr/green-at04-8x.txt` (8/8); SPOT. No private entry (DQ-2 discharged; re-read) |
| US-144 | AT-B99-05 `tests/test_b99_staging.py::test_at_b99_05_save_project_after_same_name_save_back` | pilot: Load dialog, Patch Editor clicks, save-back confirm click, Save project dialog clicks | work copy present and byte-equal; app running; status `Project saved…` naming `firmware`; project folder holds the image `{0x1000:0x11, 0x2000:0x00}` | repr ✓ · error arms (missing source, locked target) ⚠ at TC-B99-14 / TC-B99-12 only | `executed` pass — impl `inc-3a/green-at_b99_05.txt`, RED P-15; DDR `green-staging.txt`; SPOT |
| US-145 | AT-B99-06 `tests/test_b99_patch_truth.py::test_at_b99_06_flow_execution_patch_truth` | pilot: Load project dialog, rail key, flow picker, `#fx_run` click | lane head `✗`, PATCH cell `error`/`notices`; log lines; `out_outside.s19` / `out_bad.s19` absent; `mix` output holds only 0xEB10 (reader); 3 flow reports, 0 `CLEAN`, name `0x00020000`, `skipped-outside`, `MF-JSON-PARSE` | repr ✓ (partial) · boundary ✓ (1 applied + 1 skipped) · negative ✓ (outside, malformed) · empty document ⚠ (TC-B99-17) · chain-set report content ⚠ (service level, G-003) | `executed` pass — impl `inc-8/green-tc17-20-at06-07.txt`, `green-at-8x.txt`; DDR; SPOT |
| US-145 | AT-B99-07 `tests/test_b99_patch_truth.py::test_at_b99_07_hostile_symbol_name_renders_literally` | as AT-06 | painted log/cells: 0 markup spans, 0 control bytes; report: `CHG-SYMBOL-UNRESOLVED`, raw payload absent; no output file | negative ✓ (hostile markup); a markup-on painted mutant is RED (`inc-8/mut-f4-painted.txt`) | `executed` pass — impl as AT-06; DDR; SPOT |
| US-146 | AT-B99-08 `tests/test_b99_editor_image.py::test_at_b99_08_save_back_keeps_editor_image` | pilot: Patch Editor Add / Apply / Undo / Add / Apply / Add / save-back clicks | file via reader: source at 0xEB10, `01 02` at 0xEB40, `05 06` at 0xEB60; status `Saved + verified … includes 1 entry not applied before this save` | repr ✓ · boundary ⚠ (overlap of undone and kept entries, all-undone empty: TC-B99-21/22) · negative ✓ (add-without-apply named) | `executed` pass — impl `inc-4/green-at_b99_08.txt`, `green-at_b99_08-x8.txt`, RED P-6; DDR; SPOT |
| US-147 | AT-B99-09 `tests/test_b99_a2l_encode.py::test_at_b99_09_a2l_window_physical_column` | pilot: `l`, typed path, `#load_ok` (DQ-3 discharged), A2L window `2`, describe `d` | painted rows `30.0`, `4113`, `40.0`, `n/a` vs blank; modal `Scalar value: n/a (rat_func_no_real_root)`; at 118×40 AND 80×24 | repr ✓ · boundary ✓ (two widths; sparse table) · negative ✓ (undecodable → `n/a`) | `executed` pass — impl `inc-10/green-at_b99_09.txt`; DDR `green-a2l.txt`; SPOT. Residual: reads the painted screen through Textual's private `screen._compositor.render_strips()` (painted text, not product state) |
| US-148 | AT-B99-10 `tests/test_b99_crc_region.py::test_at_b99_10_flow_crc_region_pilot` | pilot: Load project dialog, `#fx_run` | CRC card `✗ error`, `out_empty.s19` absent, cause line; gap lane `◇ notices`, `466 of 512 region bytes absent (0xFA00-0xFC00)`; slot == `zlib.crc32` over the reader's present bytes | repr ✓ (gap) · boundary ⚠ (exactly 1 present byte: TC-B99-27) · negative/error ✓ (empty region) | `executed` pass — orchestrator `inc-5/stability-at10.txt` (8×); GATE; SPOT. Residual: `app.workarea` for fixture staging |
| US-149 | AT-B99-11 `tests/test_b99_export.py::test_at_b99_11_sanitised_mac_only_second_export_takes_suffix` | pilot: Load project dialog, Split/Join/Export window, `#sje_table` clicks, Load dialog for the MAC file, Patch Editor | `prg_x__________ESCAPED.s19` inside dest, nothing outside; MAC-only file with 0 data (reader); `<name>_1.s19`, first file byte-identical, status `_1` / `wrote` / `reused` | repr ✓ · boundary ✓ (MAC-only empty session) · negative ✓ (hostile name) · junction ⚠ (TC-B99-29) | `executed` pass — DDR joined node `ddr/green-at11-8x.txt` (8/8); SPOT |
| US-150 | AT-B99-12 `tests/test_b99_bytes_field.py::test_at_b99_12_typed_hex_run_saves_back` | pilot: `l`, typed path, `#load_ok`; `6`; keys into the address and Bytes inputs; Add and Apply clicked; save-back confirm `Button.press()` (DQ-4 geometry justification) | file via reader holds `0F 10 1F 20` at 0x100 | repr ✓ · boundary ⚠ (`00`/`FF`: TC-B99-32 unit) · negative ⚠ (`G1`/`100` refusal: TC-B99-32 unit only, G-002) | `executed` pass — impl `inc-11/green-at_b99_12.txt`; DDR `green-bytes.txt`; SPOT. Residual: `Input.focus()` before typing; one `Button.press()` |
| US-151 | AT-B99-13 `tests/test_b99_load_project.py::test_at_b99_13_project_and_file_pickers_load_by_name` | pilot: Load project dialog (3 pick paths), Workarea Files list click | dialog lists `P1`, `P2` only (`patches` present); status names `P2`; Files list shows `a.s19` and loads it | repr ✓ · boundary ✓ (empty: no project → current file stays) · negative ✓ (reserved `patches` not listed) | `executed` pass — impl `inc-7/green-at_b99_13.txt`; GATE; SPOT. Residual: reads `app.screen` type and `app.workarea` (already in BACKLOG, Inc-7 F3) |
| US-152 | AT-B99-14 `tests/test_b99_a2l_encode.py::test_at_b99_14_codec_api_encode_surface` | codec API `encode_physical_to_raw_bytes` (declared US-152 / P-22 exception) | returned tuple only: `(0x01,0x2C)`; `10 11` from the manifest; 500 → `None` + error naming `[0.0, 62.5]` | repr ✓ · boundary ⚠ (table endpoints: TC-B99-25) · negative ✓ (500 refused) | `executed` pass — impl `inc-10/green-at_b99_14.txt`; DDR `green-a2l.txt`; SPOT |

**Story coverage: 12 of 12 stories have at least one black-box deliverable observation through their shipped surface.** No Phase-4 blocker.

**C-18:** 14 of 14 ATs realise in exactly one on-disk node, and none is realised in parts.
- Increment 012 joined AT-03, AT-04 and AT-11 into one node each and designated AT-08's existing node; the leftover arms were renamed onto their TCs.
- The joined nodes have no base-commit RED of their own: they re-pack coverage that each half had already shown RED in its increment. That was declared in the Inc-12 packet, and I accept it.

### Bidirectional surface-reachability matrix (extends A-5)

| Direction | US dimension / deliverable | Service param / producer | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|--------------------------|------------------------------|---------|--------|
| input | corpus files + tamper (US-141) | `generate.py --check` | yes (CLI) | AT-B99-01 | ✓ |
| input | S19 file via Load dialog (US-142/143/150) | `load_selected_file` | yes | AT-02, AT-03, AT-12 | ✓ |
| input | Intel HEX file with a defect (US-143) | HEX loader EOF check | no — loader-level TCs only | TC-B99-09 | gap (G-002, minor) |
| input | patch entry address + bytes typed (US-142/146/150) | `ChangeService.add_entry` / `parse_new_bytes` | yes (keys into Inputs) | AT-02, AT-05, AT-08, AT-12 | ✓ |
| input | invalid Bytes token `G1`/`100` (US-150) | `parse_new_bytes` refusal | no — unit only | TC-B99-32 | gap (G-002, minor) |
| input | chain-set lanes, output names, parallel mode (US-144) | `run_chain_set` | yes (`#fx_import`, `#fx_mode`, `#fx_run`) | AT-B99-04 | ✓ |
| input | Save project dialog fields (US-144) | `SaveProjectScreen` | yes (clicks + keys) | AT-B99-05 | ✓ |
| input | missing source / locked target at Save project (US-144) | `copy_into_workarea` error path | no — TC arms set `.value` and call `action_save_project` | TC-B99-14, TC-B99-12 | gap (minor, within G-002) |
| input | change document: outside / partial / malformed / hostile (US-145) | flow PATCH block | yes (`#fx_run`) | AT-06, AT-07 | ✓ |
| input | A2L + S19 (US-147) | A2L decode | yes | AT-B99-09 | ✓ |
| input | CRC region empty / gap (US-148) | flow CRC block | yes | AT-B99-10 | ✓ |
| input | hostile segment name, MAC-only session, second export (US-149) | `SegmentSplitView` export | yes | AT-B99-11 | ✓ |
| input | project pick (3 paths), Workarea Files pick (US-151) | `LoadProjectScreen`, `_load_from_item` | yes | AT-B99-13 | ✓ |
| input | physical value + symbol (US-152) | `encode_physical_to_raw_bytes` | yes (declared API surface) | AT-B99-14 | ✓ |
| output | written S19 after save-back (US-142/146/150) | `save_patched_image` | yes (independent reader) | AT-02, AT-08, AT-12 | ✓ |
| output | Memory Map rows (US-142) | `get_memory_ranges` | yes (painted) | AT-B99-02 | ✓ |
| output | load status line + Issues chip (US-143) | load notice | yes (painted) | AT-B99-03 | ✓ |
| output | lane cells, run log, no file on error (US-143/145/148) | Flow Execution panel | yes (painted, disk) | AT-03, AT-06, AT-10 | ✓ |
| output | 8 lane files + chain-set report mode (US-144) | WRITE-OUT placement, chain-set report | yes (reader, report file) | AT-B99-04 | ✓ |
| output | project folder image + status (US-144) | Save project | yes | AT-B99-05 | ✓ |
| output | flow report naming non-applied entries / refusals (US-145) | `flow_report_service` | yes (report file) | AT-06, AT-07 | ✓ |
| output | chain-set report listing non-applied entries and lane files (US-145) | `compose_chain_set_report` | no — `run_chain_set` + `compose_chain_set_report` called directly | TC-B99-19, TC-B99-27 | gap (G-003, minor) |
| output | A2L physical column + describe modal (US-147) | A2L window | yes (painted) | AT-B99-09 | ✓ |
| output | CRC slot bytes in the written file (US-148) | CRC injection | yes (reader + independent CRC) | AT-B99-10 | ✓ |
| output | export files inside dest, `_1`, status (US-149) | export placement | yes (disk, reader, painted) | AT-B99-11 | ✓ |
| output | project list, file list, load status (US-151) | dialogs | yes (painted) | AT-B99-13 | ✓ |
| output | `(raw_bytes, error, flags)` (US-152) | codec | yes | AT-B99-14 | ✓ |

### Premise flip table — reconciled (§5.2 third bullet)

| Premise (RED side of) | Flipped on main? | Executed by | The node that now holds it |
|---|---|---|---|
| P-1 S0 phantom (AT-02) | yes — `32 OK, 0 BAD` (`p4-premises/rw-p03…`) | orchestrator, `e7732f6` | AT-B99-02, TC-B99-04/05/06 |
| P-2 patch at 0x0 (LLR-153.4) | yes — `patch error 'applied 0 of 1 entries'`, `skipped-outside` (`rw-p13a…`, adapted) | orchestrator | TC-B99-07, AT-02 negative arm |
| P-4 PATCH always ok (AT-06/07) | yes — `run=error … wrote=[]`; malformed `run=error` (`rw-p01…`) | orchestrator | AT-06, TC-B99-17 |
| P-5 shared staging (AT-04) | yes, two halves: the probe's shared-name set is refused by D7 and writes 0 files, and the concurrency mechanism holds 0 mismatches over 8 × 20 (TC-B99-12, RED 35/68 under the mutant). The table states this honestly (DQ-7) | orchestrator; impl | AT-04, TC-B99-12, TC-B99-15 |
| P-6 editor undo (AT-08) | yes — `@0xEB10 = 20417070`; status names 0x0000EB40 (`rw-p05…`) | orchestrator | AT-08, TC-B99-21/22 |
| P-7 byte order (LLR-158.1) | yes — `effective_byte_order = big`; 4113 → `1011` (`rw-p06a…`) | orchestrator | TC-B99-23/42, AT-09/14 |
| P-8 COMPU_TAB (LLR-158.3) | yes — 500.0 refused naming `[0.0, 20.0]`; 13.0 refused naming 10.0 and 20.0 | orchestrator | TC-B99-25, AT-14 |
| P-9 CRC empty region (AT-10) | yes — `run=error crc=error:'empty CRC region'`, nothing written (`rw-p07…`) | orchestrator | AT-10, TC-B99-26/27 |
| P-10 truncated images (AT-03) | yes — `run=error source=error … out_bytes=0` for both S19 and HEX (`rw-p04…`) | orchestrator | AT-03, TC-B99-08/09/10 |
| P-11 export containment (AT-11) | yes — `inside dest: True`; first intact, second `prg_range_00_1.s19` (`rw-p10a…`; the probe's original "first content survived" line now compares the new path and is superseded by the adapted check — read and accepted) | orchestrator | AT-11, TC-B99-29/31 |
| P-14 run records (LLR-156.3/156.4) | yes — `outcome status: error`; `rw-p09` reports `COMPLETED WITH ISSUES` / `FAILED`, not `CLEAN` | orchestrator | TC-B99-18/19/20, AT-06 |
| P-15 PH-3 (AT-05) | yes — `work copy exists after save-back: True`; `return_code: None` (`proj-p08.txt`) | orchestrator | AT-05, TC-B99-11/14 |
| P-12 emitters exact (axiom) | unchanged — `mismatches = 0` | orchestrator | — (axiom held) |
| P-16 decimal tokens (LLR-161.1) | yes — not in FLIP-TABLE (code-read premise) | qa-reviewer probe on main: `0F 10 1F 20 → [0xf,0x10,0x1f,0x20]`; `G1`, `100` refused | TC-B99-32, AT-12 (G-007) |
| P-17 RAT_FUNC direction (LLR-158.2) | yes — not in FLIP-TABLE (audit premise) | impl: TC-B99-24 GREEN, RED `mut-LLR-158.2.txt`; AT-14 asserts raw 300 for 30 | TC-B99-24/43, AT-09/14 (G-007) |
| P-18 MAC phantom byte (LLR-160.3) | yes — not in FLIP-TABLE | impl: TC-B99-30; AT-11 MAC-only arm `image_b.data == {}` | TC-B99-30, AT-11 (G-007) |
| P-19 `str(label)` in `_load_from_item` (LLR-162.1) | yes — read on main: `app.py:9021-9031` reads `item.data`, no `str(label_widget)`; Inc-7 V-3 grep 0 hits | qa-reviewer (inspection) | TC-B99-34, AT-13 (G-007) |
| P-20 reserved homes listed (LLR-162.2) | yes — read on main: `app.py:8519-8524` filters `RESERVED_WORKAREA_HOMES` (`workspace.py:40-50`, 9 homes) | qa-reviewer (inspection) | TC-B99-35, AT-13 (G-007) |
| P-21 0 HEX fixtures (HLR-152) | yes — the corpus ships HEX files checked by AT-01 / TC-B99-03b | impl | AT-01, TC-B99-02/03 |
| P-3, P-13, P-22, P-23 | not RED sides (oracle choice, classification axiom, AT exception, save-back precondition) | — | n/a — no flip owed; P-22's exception is what AT-14 rests on |

### Signed-balance test ledger

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|------|-----|-----|--------|------------------|--------------------|-------------|
| 3634 (`a293213`: 11 failed + 3617 passed + 3 skipped + 3 xfailed) | 0 | 142 (b99 files at `e7732f6`; packets 005/006/009 corrected at the DDR, F-6) | 3776 | 3776 in the gate run (14 + 3756 + 3 + 3) | gate run 3756 passed / 14 failed (9 baseline, 3 flakes, 2 stale pins fixed in Inc 13) | yes |
| 3776 (`e7732f6`) | 4 (Inc-12 merges: truncation −1, staging −1, export −2) | 1 (Inc-12 TC-B99-18 riders node) | 3773 | 3773 (`pytest --collect-only -q` on main, qa-reviewer); b99 files 139 | confirmation run on `75f947a` (= `31bac78` for `s19_app/` and `tests/`): 3755 passed / 12 failed / 3 skipped / 3 xfailed = 3773 (8 baseline, 4 intermittent, `evidence/suite-triage-75f947a.md`); b99 + census + snapshot: 142 / 142 passed (SPOT) | yes |

### Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| G-001 | all (evidence binding) | The one gate run is on `e7732f6`. Increments 012 and 013 then changed 9 test files: the C-18 joined nodes AT-03/04/11, the black-box entries of AT-04/09/12, the renames, the census and the snapshot re-pin. **`s19_app/` is unchanged.** The changed nodes were never in a complete run. Their GREEN comes from: `evidence/ddr/green-b99.txt` (175 passed, b99 files + address census + id registry, the `b99-ddr` worktree); the per-file `ddr/green-*.txt`; `inc-13/green-*.txt`; and SPOT on main. Cross-check: no non-b99 test imports a b99 file except `tests/test_id_registry.py` (scanned, run in `green-b99.txt` and `inc-13/green-id-registry.txt`). | minor | Accept with this line on `Gate run`. Optionally, one confirmation run on main if the operator wants the 3773 nodes in a single transcript. |
| G-002 | HLR-153, 154, 155, 157, 158, 161 | Layer-B boundary and some negative arms are realised at TC level, not through the surface. US-142 S0-only; US-143 well-formed controls and **every HEX defect**; US-144 missing source and locked target; US-146 overlap and all-undone; US-150 `00`/`FF` and the **`G1`/`100` refusal message** (no surface negative for US-150); US-152 table endpoints. Every story still has a surface observation, and every arm is GREEN at TC level. | minor | BACKLOG-CODE: add surface arms. A HEX cut file through `l` (US-143), and a typed `G1` in the Bytes field asserting the painted refusal (US-150), are the two with the most value. |
| G-003 | HLR-156 / LLR-156.3 | The chain-set report's not-applied listing and lane-file list are observed only by calling `run_chain_set` and `compose_chain_set_report` (TC-B99-19, TC-B99-27). AT-06 excludes `chain-set` reports (`_fx_reports` filter, `test_b99_patch_truth.py:673-678`). AT-04 proves the TUI writes a chain-set report, but reads only its `Mode` line. | minor | BACKLOG-CODE: extend AT-06 to read the chain-set report it already produces and assert `0x00020000 skipped-outside` and the lane's written file. |
| G-004 | gate-run triage | The triage says `test_tc_b97_64_…` and `test_tc024_report_trigger_invalid_dest_refused` pass when re-run alone, but `evidence/` holds no standalone re-run transcript for either. `saveback_width_32` is covered by `flake-patch-editor-v2-base-vs-head.txt`. | minor | Orchestrator: add the two re-run transcripts to `evidence/`, or cite where they live. qa-reviewer re-ran both alone on main ×3: 6 of 6 `PASSED` (`qa-spot-flakes-31bac78.txt`, to be copied to `evidence/p4-qa/`); that settles the claim, but the triage's own re-run is still uncited. |
| G-005 | out of scope (baseline) | Deterministic baseline failures have no BACKLOG-CODE entry by id: `test_unified_write::test_tc018_existing_name_is_dedup_suffixed` and `test_tui_patch_editor_v2::test_at031b_two_saves_are_distinct_no_clobber` (a requirement conflict: an older dedup-suffix expectation against the B8 / LLR-155.3 byte-identical reuse, `increment-003.md:516-521`); `test_at_056e_…`; `test_at_b78_03_…`; `test_at_b78_32_…`; `test_tc1802_…` (the same missing `help_sections.md` as TC-707, which is deferred). | minor | Route to BACKLOG-CODE at the close. tc018/at031b as a decision: keep reuse and re-pin, or restore the suffix (surface the conflict, do not average it). |
| G-006 | AT-09, 12, 13 | Residual non-surface calls inside AT nodes. AT-12: `Input.focus()` before typing, and one `Button.press()` on the hidden confirm (allowed by DDR DQ-4 with a probed justification). AT-09: painted text read through Textual's private `screen._compositor.render_strips()`. AT-13: `app.screen` / `app.workarea` reads (already in BACKLOG, Inc-7 F3). None writes product state. | minor | Leave as routed. Add the AT-09 private-renderer read to the existing AT-hardening backlog line. |
| G-007 | P-16..P-21 | `evidence/p4-premises/FLIP-TABLE.md` lists only the probe-backed premises. The code-read and audit RED sides P-16, P-17, P-18, P-19 and P-20, and P-21, are absent. Each has flipped (see the table above), but the flip is not recorded in the flip table. | minor | Orchestrator: append the six rows (node + transcript) to FLIP-TABLE.md. |
| G-008 | Gate run | The gate transcript has no header naming the command or the commit; the commit is attested only by the triage and the worktree path. Same as batch-97 G-001. | minor | Have the run script echo `git rev-parse HEAD` and the command line as its first lines. |
| G-009 | supersession (V-3) | Inc-6 carries a Correction population row but no V-3 supersession table. By grep, the export path uses only the one sanitiser on main, so there is no live dependency. | minor | Note in 04-validation; no action on code. |
| G-010 | PLAN.md | `PLAN.md` §Where we are and §Per-story status still read P1 / "not started". | minor | Orchestrator: refresh at the P4 gate. |

**Orchestrator disposition of the gaps (P4 gate):**

| ID | Disposition |
|---|---|
| G-001 | A confirmation full run on the final tree was launched: `evidence/suite-full-75f947a.txt`. Its result is on the `Gate run` line above (CONFIRMATION). |
| G-002 | Routed to BACKLOG-CODE at the close. The two most valuable surface arms come first: a HEX cut file loaded through `l` (US-143), and a typed `G1` in the Bytes field with its painted refusal (US-150). |
| G-003 | Routed to BACKLOG-CODE at the close: AT-06 reads the chain-set report it already produces. |
| G-004 | The orchestrator's standalone re-runs were in-session tool output and are not on disk; this record says so instead of implying they are. The claim rests on qa-reviewer's 6/6 re-run (`evidence/p4-qa/qa-spot-flakes-31bac78.txt`) and, for `saveback_width_32`, on `evidence/flake-patch-editor-v2-base-vs-head.txt`. |
| G-005 | Routed to BACKLOG-CODE at the close, by id. tc018/at031b go in as an open decision (keep byte-identical reuse and re-pin, or restore the suffix). Both failed before this batch (baseline `a293213`), so the batch neither caused nor settled the conflict. The question goes to the operator in the close packet. |
| G-006 | Added to the existing AT-hardening backlog line at the close. |
| G-007 | Done: rows P-16..P-21 appended to `evidence/p4-premises/FLIP-TABLE.md`. |
| G-008 | Done for the confirmation run, whose transcript opens with the command, the tree and the start time. |
| G-009 | Noted. No code action: the export path uses one sanitiser on main. |
| G-010 | Done: `PLAN.md` refreshed at this gate. |

No blocker, no HIGH. No requirement was found unmet by the product: every HLR clause I read against its node is asserted, and every RED premise has flipped.

### Escaped-bug regression (if a defect escaped the suite)

No product defect escaped. The suite caught two stale test pins that the increment gates' reverse census could not reach: a module-import census and a rendered-text snapshot. Both were re-pinned tests-only in Increment 013, with RED and GREEN.

| Regression id (`AT-NNN` / `TC-NNN`) | Pre-fix run (evidence it FAILED) | Pre-fix RED kind (value / shape) | Post-fix value-discriminating? (QC-2) | Post-fix result | Reconciled node |
|-------------------------------------|----------------------------------|----------------------------------|----------------------------------------|-----------------|-----------------|
| TC-653 (batch-era census; LLR-160.2 measured in) | gate run line 830 + `inc-13/red-tc653.txt` (`extra=['s19_app.tui.segment_split_view']`) | value | yes — `inc-13/mut-F1.txt`: removing the set entry → FAILED | `executed` pass — `inc-13/green-tc653.txt` (impl); SPOT | `tests/test_import_census.py::test_tc653_safe_text_import_census` |
| TC-016s cell `patch-comfortable-120x30` (LLR-161.2 placeholder) | gate run line 838 + `inc-13/red-snapshot.txt`; bisect: first red at `5021bb6` (triage) | value (painted placeholder text, `snapshot-text-diff.txt`) | yes — `inc-13/mut-F2.txt`: old SVG restored → FAILED | `executed` pass — `inc-13/green-snapshot.txt` (33 passed, impl); SPOT | `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]` |

### Evidence checklist — qa-reviewer (full)

- [✓] **Acceptance criteria use Given/When/Then** — the batch's ATs are written as HLR "Observable outcome" + shipped surface + boundary catalog (01-requirements §3), the project's established equivalent; each AT docstring states drive → observe.
- [✓] **Test cases have explicit Expected, not vague "works"** — every LLR carries a numeric pass threshold (01-requirements §4); every Layer-A row above quotes it.
- [✓] **Edge cases include empty, boundary, invalid, error** — each HLR's QC-3 catalog ticks them or justifies N/A in writing; all are GREEN at TC level; surface-level gaps named in G-002.
- [✓] **Regression checklist exists** — the full gate run against the 11-id baseline set (PLAN test ledger), plus each increment's reverse census; reconciled above.
- [✓] **Exit criteria stated** — 01-requirements §5.2 (four bullets); each is answered: 40/40 LLR, every declared mutant RED, 12/12 stories, premises flipped (G-007 records six by node, not by table), 0 blockers, no new failure against the baseline after Inc 13.
- [✓] **No real PII / secrets** — fixtures are synthetic (`tests/fixtures/synth/`) and `examples/`; this draft names no person.
- [✓] **Mode declared** — `validation`, at the top.
- [✓] **Validation mode: every case carries a result or one of the seven states, and each executed result names its executor** — orchestrator / impl (Kimi K2.8) / qa-reviewer named per row; the one item stated `not-run` at P4 (a complete run of the final tree, ledger row 2, G-001) was then executed by the confirmation run on `75f947a`.
- [✓] **Layer B (black-box)** — 14 ATs drive the shipped surface (pilot keys and clicks, CLI, declared codec API) and observe files via `tests/support/independent_reader.py`, painted text or report files; boundary + negative per row, with the TC-only arms named (G-002).
- [✓] **Bidirectional surface-reachability** — matrix above: 13 of 16 inputs and 13 of 14 outputs reached at the surface; the 3 gaps are named (G-002, G-003) and are minor because each has a GREEN TC and the surface producer is otherwise driven.
- [✓] **No unfilled template** — no `<...>` placeholder, no unassigned TC id, no empty Steps / Expected in this draft (the spot-check results are filled in).
