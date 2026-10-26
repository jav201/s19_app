# Traceability Matrix — s19_app — Batch 2026-10-25-batch-99

> **Roles:** `docs-writer` (this artifact). Batch `2026-10-25-batch-99`, repo `s19_app`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Verdict source:** every `Status` below is the Layer A / Layer B verdict of `04-validation.md`: `Result: PASS-WITH-NOTES`, `Requirements: 51/51 pass (11 HLR + 40 live LLR; LLR-157.3 retired in LED .2) · 0 blocker fails`, and 14 of 14 ATs, each realised in exactly one node (C-18). The gate run is the orchestrator's full suite on `e7732f6`: 14 failed / 3756 passed / 3 skipped / 3 xfailed (`evidence/suite-full-e7732f6.txt`). It has no product defect: 9 baseline ids, 3 flakes, and 2 stale pins re-measured in Increment 013 (`evidence/suite-triage-e7732f6.md`). Name-level GREEN on the final tree comes from qa-reviewer's targeted run on `75f947a`: 142 passed (`evidence/p4-qa/qa-spot-b99-31bac78.txt`). The contract for the requirement topology (US → HLR → LLR → TC/AT) is `01-requirements.md` §2.6 / §3 / §4 as amended by `01-requirements-ledger.md` LED .1–.8. Increment attribution comes from the packets' §2 tables (`03-increments/increment-001…013.md`) and the `PLAN.md` roadmap.
> **Anchors:** `File:line` is the implementing symbol, measured on the tree at `bf3917d` (the P5 commit). `git diff 31bac78 bf3917d -- s19_app tests` is empty, and `git diff e7732f6 31bac78 -- s19_app` is empty, so these lines are the lines of the gated product. `Notes` gives the TC's first test node (`file:line` on the same tree), the increment and commit, and the evidence from `04-validation.md` §Layer A. Evidence tags: **impl** is the increment implementer's transcript under `evidence/inc-*/`; **RED** is the mutation or premise transcript; **DDR** is the post-Increment-012 transcript under `evidence/ddr/`; **GATE** means the node was in the `e7732f6` gate run and has not changed since; **SPOT** is the qa-reviewer run on `75f947a`.

> **Artifact language:** canonical English scaffold. Generate the artifact in the batch's development language (`state.json` `language`); for Spanish batches **translate the prose, never a label**. This document mints no field a rule keys on — its ids (`US-`/`HLR-`/`LLR-`/`AT-`/`TC-`/`R-`) are read by the Atlas id-scanner and are not words in any language — so it carries no reserved-field block; what it must not do is order the translation of somebody else's.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row. ⚠ **This template is seeded by a BULLET under that table rather than by a row**, because `06-docs/` exists only in `full` — the same fact `V39`'s `_V39_OWED_IN["P6"]` carries.

> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.

---

## 1. Master table — functional chain (white-box)

> One row per live LLR: 40 rows, 43 live TC ids. Each TC id appears exactly once. LLR-155.1, LLR-158.1 and LLR-158.2 each carry two TCs (LED .8, LED .6).
> Short paths: `core` = `s19_app/core.py`, `hexfile` = `s19_app/hexfile.py`, `hexview` = `s19_app/render/hexview.py`, `ws` = `s19_app/tui/workspace.py`, `app` = `s19_app/tui/app.py`, `fes` = `s19_app/tui/services/flow_execution_service.py`, `frs` = `s19_app/tui/services/flow_report_service.py`, `fs` = `s19_app/tui/flow_screens.py`, `cs` = `s19_app/tui/services/change_service.py`, `a2l` = `s19_app/tui/a2l.py`, `crc` = `s19_app/tui/operations/crc.py`, `ssv` = `s19_app/tui/segment_split_view.py`, `pgs` = `s19_app/tui/services/project_gather_service.py`.
> Test files are `tests/test_b99_<name>.py`, written below as `<name>.py`.

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| **Inc-1 (`a52e2be`): synthetic corpus and independent reader (tests only, 0 SOURCE files)** | | | | | | |
| US-141 | HLR-152 | LLR-152.1 | TC-B99-01 | `tests/fixtures/synth/generate.py:299` (`build_corpus`) · `:481` (`write_corpus`) | pass | `corpus.py:87` · impl `inc-1/green-tc_b99_01.txt`; RED `mut-LLR-152.1.txt`; GATE; SPOT |
| US-141 | HLR-152 | LLR-152.2 | TC-B99-02 | `generate.py:299` (coverage classes per manifest entry) · `tests/fixtures/synth/manifest.json` | pass | `corpus.py:102` · impl `green-tc_b99_02.txt`; RED `mut-LLR-152.2.txt` (the first mutant survived; the arm was fixed, then the mutant was KILLED); GATE; SPOT |
| US-141 | HLR-152 | LLR-152.3 | TC-B99-03 | `tests/support/independent_reader.py:68` (`read_s19`) · `:120` (`read_hex`) | pass | `corpus.py:114` (+ `03b` HEX extents) · AST import census clean; impl `green-tc_b99_03.txt`; RED `mut-LLR-152.3.txt`; GATE; SPOT |
| **Inc-2 (`c62c842`): S0 is not image data** | | | | | | |
| US-142 | HLR-153 | LLR-153.1 | TC-B99-04 | `core:220` (`_is_data_record`) · `core:609` (`get_memory_map`) · `:556` (`get_record_for_address`) · `:574` (`_build_overlap_map`) | pass | `s0.py:105` · Layer 0; RED `inc-2/mut-LLR-153.1.txt` KILLED (6 failed); GATE; SPOT |
| US-142 | HLR-153 | LLR-153.2 | TC-B99-05 | `hexview:60` (`build_mem_map_s19`) · `hexview:71` (`build_range_validity_s19`) | pass | `s0.py:168` · impl `green-tc_b99_05.txt`, RED `red-tc_b99_05.txt`; GATE; SPOT |
| US-142 | HLR-153 | LLR-153.3 | TC-B99-06 | `core:220` (S0 excluded from the image); the S0 text keeps travelling as a header (`LoadedFile.source_s0_header` → the S19 emitter, unchanged code) | pass | `s0.py:214` · independent reader: 0 data at `0x0`; impl `green-tc_b99_06.txt`; GATE; SPOT |
| US-142 | HLR-153 | LLR-153.4 | TC-B99-07 | `core:609` (the image holds no S0 byte), so the existing OUTSIDE mapping applies (`s19_app/tui/changes/model.py:290`, `DISPOSITION_SKIPPED_OUTSIDE`) | pass | `s0.py:318` · disposition `skipped-outside`, 0 bytes at `0x0`; RED `red-tc_b99_07.txt`; GATE; SPOT |
| **Inc-9 (`725d474`): truncated and inconsistent images are reported** | | | | | | |
| US-143 | HLR-154 | LLR-154.1 | TC-B99-08 | `core:289` (`_load`) · `core:241` (`S19_INTEGRITY_NOTICE_CODES`) · `core:248` (`load_notice_code`) · `core:75` (`ADDRESS_LENGTH_MAP`, S6 added) | pass | `truncation.py:155` · impl `inc-9/green-tc_b99_08.txt`; RED `mut-LLR-154.1.txt`; DDR; SPOT |
| US-143 | HLR-154 | LLR-154.2 | TC-B99-09 | `hexfile:36` (`_load`) · `hexfile:12` (`HEX_INTEGRITY_NOTICE_CODES`) | pass | `truncation.py:293` · impl `green-tc_b99_09.txt`; RED `mut-LLR-154.2.txt`; DDR; SPOT. HEX defects observed at TC level only (G-002) |
| US-143 | HLR-154 | LLR-154.3 | TC-B99-10 | `fes:135` (`SOURCE_INTEGRITY_CODES`) · `fes:377` (SOURCE arm) · `app:11210` (`_format_coexistence_status`) · `app:971` (`_integrity_notice_codes`) | pass | `truncation.py:424` · SOURCE `error`, 0 files; impl `green-tc_b99_10.txt`; RED `mut-LLR-154.3.txt`; DDR; SPOT |
| **Inc-3a (`f1ba70c`) + Inc-3b (`4ee51a6`) + Inc-5 (`e7732f6`): every write lands in its own file, placed atomically** | | | | | | |
| US-144 | HLR-155 | LLR-155.1 | TC-B99-11, TC-B99-44 | `ws:298` (`_private_stage_dir`) · `ws:24` (`WORKAREA_STAGING_DIRNAME`) · `s19_app/tui/changes/apply.py:626` (`save_patched_image`) · `s19_app/tui/changes/io.py:1504` (`write_change_document`) | pass | TC-11 `staging.py:253`, TC-44 `staging.py:998` · Inc-3a; impl `inc-3a/green-tc_b99_11.txt`; RED `mut-155.1-shared-staging.txt`; TC-44 (LED .8): DDR `green-staging.txt`, RED `inc-3a/mut-fix2-f3-temp-staging.txt`; SPOT |
| US-144 | HLR-155 | LLR-155.2 | TC-B99-12 | `ws:402` (`copy_into_workarea`: O_EXCL claim, next free `_<N>`, `os.replace` with ≤ 5 retries) · `ws:62` (`WorkareaPlacementError`) | pass | `staging.py:403` · 8 writers × 1 name × 20 trials, 0 mismatches; RED `mut-155.2-check-then-copy.txt` (35/68 mismatches); DDR; SPOT |
| US-144 | HLR-155 | LLR-155.3 | TC-B99-13 | `ws:402` (byte-identical reuse; a 0-byte target is never reused) · `pgs:291` (`_gather_copy`, Inc-3b) · `pgs:255` (`_same_artifact_name`) | pass | `staging.py:653` · Inc-3a + Inc-3b (LED .7 immutability invariant); RED `mut-155.3-*`, `inc-3b/mut-LLR-155.3.txt`; DDR; SPOT |
| US-144 | HLR-155 | LLR-155.4 | TC-B99-14 | `app:8087` (`_handle_save_dialog`) · `app:8076` (`_remove_created_project_dir`) | pass | `staging.py:1108` · Inc-3a; RED `red-tc_b99_14.txt`; DDR; SPOT. Missing-source and locked-target arms observed at TC level only (G-002) |
| US-144 | HLR-155 | LLR-155.5 | TC-B99-15 | `fes:1702` (`_write_out_collisions`) · `fes:1734` (`run_chain_set`) · `app:2795` (`on_flow_execution_panel_run_requested`, status line) | pass | `staging.py:1770` · Inc-3b; impl `inc-3b/green-tc15-16-census.txt`; RED `mut-LLR-155.5.txt`; DDR; SPOT |
| US-144 | HLR-155 | LLR-155.6 | TC-B99-16 | `fes:698` (WRITE-OUT arm: `verify_written_image` read-back, `first difference at 0x…`) | pass | `staging.py:1847` · Inc-3b; TC-only by design (no surface can corrupt a file between write and read-back); RED `mut-LLR-155.6.txt`; DDR; SPOT |
| US-144 | HLR-155 | LLR-155.7 | TC-B99-39 | `ws:298` and the owned-staging cleanup in each census writer (`apply.py:626`, `io.py:1504`, `crc:1375`, `ws:402`, `ws:695`) | pass | `staging.py:970` · AST census of delete calls; Inc-3a, extended by Inc-5 (CRC exception removed) and Inc-6 (`place_group_into_workarea`); RED `mut-155.7-rederived-unlink.txt`; DDR; SPOT |
| US-144 | HLR-155 | LLR-155.8 | TC-B99-38 | `crc:1375` (`write_crc_image`, staged through `_private_stage_dir`) | pass | `crc_region.py:467` · Inc-5; impl `inc-5/green-b99_crc_region.txt`, orchestrator `inc-5/green-fix-sweep.txt`; RED `mut-LLR-155.8.txt`; GATE; SPOT |
| **Inc-8 (`7ffad92`): PATCH status and run records say what was not applied** | | | | | | |
| US-145 | HLR-156 | LLR-156.1 | TC-B99-17 | `fes:537` (PATCH arm status from dispositions) · `fes:1510` (`_record_error`, stops before WRITE-OUT) | pass | `patch_truth.py:159` · the 8-case matrix `error,error,notices,error,error,error,error,ok`; RED `mut-LLR-156.1.txt` (3 failed); DDR; SPOT |
| US-145 | HLR-156 | LLR-156.2 | TC-B99-18 | `fes:1587` (`ChainRunOutcome`; `change_records` / `refusals` / `image_ranges` at `:1631-1633`) · `fs:3376` (`_patch_not_applied_note`) · `fs:3290` (`_log_lines`) | pass | `patch_truth.py:427` (+ Inc-12 dual-rider node) · RED `mut-LLR-156.2.txt`; DDR `green-tc18-riders.txt`; SPOT |
| US-145 | HLR-156 | LLR-156.3 | TC-B99-19 | `fes:1884` (`compose_chain_set_report`: Written files / Not applied / Refusals) | pass | `patch_truth.py:544` · service level only (G-003); re-pinned in Inc-5 (`## Notices` section); RED `red-tc17-20-at06-07.txt`; DDR; SPOT |
| US-145 | HLR-156 | LLR-156.4 | TC-B99-20 | `frs:125` (`SECTION_HEADINGS`) · `frs:189` (`FlowReportState.refusals`) · `frs:282` (`_provisional_status`) | pass | `patch_truth.py:611` · 0 `CLEAN` on non-ok runs; RED `mut-LLR-156.4.txt`; DDR; SPOT |
| **Inc-4 (`c58b02d`): the Patch Editor image is the source plus the document** | | | | | | |
| US-146 | HLR-157 | LLR-157.1 | TC-B99-21 | `cs:1923` (`apply`) · `cs:2009` (`save_patched`) · `cs:1782` / `:1816` / `:1842` (`_note_image` / `_restore_journal` / `_capture_journal`) | pass | `editor_image.py:186` · impl `inc-4/green-tc_b99_21.txt`; RED `mut-LLR-157.1*.txt`; SPOT |
| US-146 | HLR-157 | LLR-157.2 | TC-B99-22 | `cs:1816` (`_restore_journal`) · `cs:905` (`_applied_addresses` invalidated on undo, redo, remove, edit and load) | pass | `editor_image.py:257` · 0 stale bytes; RED `mut-LLR-157.2.txt`; DDR; SPOT |
| US-146 | HLR-157 | LLR-157.4 | TC-B99-40 | `cs:1878` (`source_image_view`) · `cs:184` (`_SourceOverlayMap`) · `app:3917` (`_strip_source_map`) | pass | `editor_image.py:372` · the strip shows the source byte as `before`; RED `mut-LLR-157.4.txt`; SPOT |
| **Inc-10 (`9d7fb18`): A2L values encode and decode as the A2L declares** | | | | | | |
| US-147, US-152 | HLR-158 | LLR-158.1 | TC-B99-23, TC-B99-42 | `a2l:2402` (`extract_a2l_tags` fallback chain) · `a2l:2414` (`_module_byte_order`, per MODULE) · `a2l:280` (`_normalize_byte_order`) | pass | TC-23 `a2l_encode.py:189`, TC-42 `:237` (LED .6) · LED .4 (`MSB_LAST` control); RED `mut-LLR-158.1.txt`, `mut-LOWa-first-module-wins.txt`; DDR; SPOT |
| US-147, US-152 | HLR-158 | LLR-158.2 | TC-B99-24, TC-B99-43 | `a2l:1774` (`_eval_rat_func`, encode) · `a2l:1794` (`_invert_rat_func`, decode) · `a2l:1721` (`_apply_compu_method`, `limits`) | pass | TC-24 `a2l_encode.py:263`, TC-43 `:316` (LED .6) · 30 → raw 300, raw 300 → 30.0; RED `mut-LLR-158.2.txt`, `mut-LOWb-denominator-check.txt`; DDR; SPOT |
| US-152 | HLR-158 | LLR-158.3 | TC-B99-25 | `a2l:1861` (`_reverse_table_lookup`) · `a2l:1936` (`_invert_physical_to_raw`) · `a2l:2198` (`encode_physical_to_raw_bytes`) | pass | `a2l_encode.py:359` · NOINTP 13.0 refused naming 10.0 and 15.0; INTP 500 / −50 refused naming the range; RED `mut-LLR-158.3.txt`, `mut-F1-nearest-entry.txt`; DDR; SPOT |
| **Inc-5 (`e7732f6`): a CRC never covers an empty region** | | | | | | |
| US-148 | HLR-159 | LLR-159.1 | TC-B99-26 | `crc:830` (`check_regions`) · `crc:55` (`CrcCoverageResult`) · `crc:87` (`first_empty_target_span`) · `crc:1618` (`CrcOperation.execute`) · `fes:836` (flow CRC arm) | pass | `crc_region.py:127` · `error`, 0 files, the cause is the last note; RED `mut-LLR-159.1.txt`; GATE; SPOT |
| US-148 | HLR-159 | LLR-159.2 | TC-B99-27 | `crc:948` (`crc_diagnostics`) · `fes:868` (partial coverage → `notices`) · `fs:3353` (`_crc_absent_note`) | pass | `crc_region.py:205` · exact absent count, 1-byte boundary; RED `inc-5/mut-f1.txt`; GATE; SPOT |
| **Inc-6 (`87dcd3a`): exports stay inside their destination and invent no byte** | | | | | | |
| US-149 | HLR-160 | LLR-160.1 | TC-B99-28 | `ssv:592` (`sanitize_export_segment`) · `ssv:630` (`build_export_basename`) | pass | `export.py:136` · Layer 0; RED `mut-LLR-160.1.txt` KILLED; DDR; SPOT |
| US-149 | HLR-160 | LLR-160.2 | TC-B99-29 | `ssv:715` (`write_split_join_export`) → `pgs:206` (`_check_home_contained`) | pass | `export.py:189` · 0 files outside the root; link refused; RED `mut-LLR-160.2.txt`, `mut-F1-py312.txt`; DDR; SPOT. The `safe_text` import census was re-measured in Inc-13 (`1a59d3b`) |
| US-149 | HLR-160 | LLR-160.5 | TC-B99-41 | `ssv:715` (Phase A plan pass) · `ssv:547` (`ExportRefusedError`) · `ssv:659` (`_refusal_text`) | pass | `export.py:649` · collision refused before any write; RED `mut-LLR-160.5.txt`; DDR; SPOT |
| US-149 | HLR-160 | LLR-160.3 | TC-B99-30 | `ssv:689` (`_filter_declared_ranges`) | pass | `export.py:308` · MAC-only → 0 data records (independent reader); RED `mut-LLR-160.3.txt`; DDR; SPOT |
| US-149 | HLR-160 | LLR-160.4 | TC-B99-31 | `ws:695` (`place_group_into_workarea`, map row B99-I2a) · `ssv:673` (`_export_reuse_target`) | pass | `export.py:375` · `<name>_1` for the pair; RED `mut-LLR-160.4.txt`, `ddr/mut-PQ2c.txt`; DDR; SPOT |
| **Inc-11 (`5021bb6`): the Bytes field reads one base** | | | | | | |
| US-150 | HLR-161 | LLR-161.1 | TC-B99-32 | `cs:281` (`parse_new_bytes`) | pass | `bytes_field.py:36` · Layer 0; RED `mut-LLR-161.1*.txt`; DDR; SPOT; qa probe on main. The refusal message is observed at the unit only (G-002) |
| US-150 | HLR-161 | LLR-161.2 | TC-B99-33 | `s19_app/tui/screens_directionb.py:4941` (placeholder) · `s19_app/tui/window_help.py:85` (help line) | pass | `bytes_field.py:66` · RED `mut-LLR-161.2.txt`, `ddr/mut-PQ6.txt`; snapshot cell re-pinned in Inc-13 (`inc-13/green-snapshot.txt`); SPOT |
| **Inc-7 (`d62b0c1`): project and work-area pickers load by name** | | | | | | |
| US-151 | HLR-162 | LLR-162.1 | TC-B99-34 | `app:9021` (`_load_from_item` reads `item.data`) | pass | `load_project.py:131` · RED `mut-LLR-162.1.txt`; GATE; SPOT |
| US-151 | HLR-162 | LLR-162.2 | TC-B99-35 | `ws:40` (`RESERVED_WORKAREA_HOMES`) · `app:8519` (`list_projects`) | pass | `load_project.py:154` · 0 reserved homes; RED `mut-LLR-162.2.txt`; GATE; SPOT |
| US-151 | HLR-162 | LLR-162.3 | TC-B99-36 | `app:6543` (`refresh_files` reads `workarea/temp`) | pass | `load_project.py:175` · list == load folder, no `.staging`; RED `mut-LLR-162.3.txt`; GATE; SPOT |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | HLR-001 | LLR-001.1 | TC-001 | `src/foo.ts:42` | pass | |
| *(example)* US-001 | HLR-001 | LLR-001.2 | TC-002 | `src/foo.ts:78` | pass | |
| *(example)* US-001 | HLR-002 | LLR-002.1 | TC-003 | `src/bar.ts:15` | pass | |
| *(example)* US-002 | HLR-003 | LLR-003.1 | TC-004 | `src/baz.ts:90` | fail | See gap G-001 |
```

### 1c. Retired ids (listed once, not live)

| Id | Retired by | What happened | On disk |
|----|------------|---------------|---------|
| LLR-157.3 | LED-2026-10-25-batch-99.2 (A2-1 / Q-5) | A name-based census over `mem_map` could not equal any allow-list at HEAD, in either direction. The guard was dropped rather than made soft. ARQ §2.1's census stays as PDR evidence | no node |
| TC-B99-37 | LED-2026-10-25-batch-99.2, with LLR-157.3 | — | no `tc_b99_37` node (grep on `bf3917d`) |
| LLR-159.3 | LED-2026-10-25-batch-99.1 (A-18) | The CRC staging clause moved to HLR-155 as LLR-155.8. TC-B99-38 was kept and re-homed | TC-B99-38 lives under LLR-155.8 |

Implementer numbering collisions were renumbered before merge, so none of these temporary numbers is a contract id. The first Kimi TC-B99-26/27 for LLR-158 became TC-B99-42/43 (LED .6). The first TC-B99-40 for LLR-155.1 became TC-B99-44 (LED .8). Inc-4's invented `tc_b99_40a` no longer exists on disk.

## 1b. Behavioral chain (black-box)

> One row per acceptance test, grouped by story. All 14 ATs pass. Each is exactly one node on disk (`grep -rnE "def test_at_b99_[0-9]+" tests/`, 14 hits on `bf3917d`). Increment 012 (`c1d088a`) joined AT-03, AT-04 and AT-11 into one node each, designated AT-08's existing node, and removed the private calls from AT-04, AT-09 and AT-12 (DDR DQ-2..DQ-4). The residual non-surface reads in AT-09, AT-12 and AT-13 are routed (G-006).

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-141 | AT-B99-01 (`corpus.py:190`) | `generate.py --check` (maintainer CLI) | exit 0 and `checked N files`; a tampered copy → exit 1 naming `synth_s1.s19` | pass — impl `inc-1/green-at_b99_01.txt`; GATE; SPOT |
| US-142 | AT-B99-02 (`s0.py:369`) | Load file `l`; Patch Editor; save-back; Memory Map | written file (independent reader): no byte at `0x0..0xB`, data == source; no Memory Map row at `0x00000000`; a document whose only entry is at `0x0` → `0 applied, 1 skipped` | pass — impl `inc-2/green-at_b99_02.txt`, RED `red-at_b99_02.txt`; GATE; SPOT |
| US-143 | AT-B99-03 (`truncation.py:523`) | Load file `l`; Load project `p`; Flow Execution `#fx_run` | status `Loaded cut.s19 with integrity notices: S19-NO-TERMINATOR`; the Issues chip names it; the lane log names the code and file; `out.s19` absent | pass — DDR joined node `ddr/green-at03-8x.txt` (8/8); SPOT. HEX defects at TC level only (G-002) |
| US-144 | AT-B99-04 (`staging.py:1480`) | Load project dialog; `#fx_import`; `#fx_mode` parallel; `#fx_run` | 8 lane files byte-equal to their markers; chain-set report `- **Mode:** parallel`; a duplicate `same.s19` set refused inside 50 characters in `#fx_log` and `#log_line_4`, both lanes named, nothing written | pass — DDR `ddr/green-at04-8x.txt` (8/8); SPOT |
| US-144 | AT-B99-05 (`staging.py:1309`) | Load dialog; Patch Editor save-back; Save project dialog | the work copy is present and byte-equal; the app keeps running; status `Project saved…` naming `firmware`; the project folder holds the image | pass — impl `inc-3a/green-at_b99_05.txt`, RED P-15; DDR; SPOT |
| US-145 | AT-B99-06 (`patch_truth.py:819`) | Load project; flow picker; `#fx_run` | lane `✗`, PATCH cell `error` / `notices`; no output for outside / malformed; the `mix` output holds only `0xEB10`; 3 flow reports, 0 `CLEAN`, naming `0x00020000`, `skipped-outside`, `MF-JSON-PARSE` | pass — impl `inc-8/green-at-8x.txt`; DDR; SPOT. Chain-set report content at service level only (G-003) |
| US-145 | AT-B99-07 (`patch_truth.py:898`) | as AT-06, with a hostile symbol name | painted log and cells: 0 markup spans, 0 control bytes; report `CHG-SYMBOL-UNRESOLVED`, raw payload absent; no output file | pass — impl as AT-06; painted mutant RED `inc-8/mut-f4-painted.txt`; DDR; SPOT |
| US-146 | AT-B99-08 (`editor_image.py:529`) | Patch Editor Add / Apply / Undo / Add / Apply / Add / save-back | file: source at `0xEB10`, `01 02` at `0xEB40`, `05 06` at `0xEB60`; status `Saved + verified … includes 1 entry not applied before this save` | pass — impl `inc-4/green-at_b99_08-x8.txt`, RED P-6; DDR; SPOT |
| US-147 | AT-B99-09 (`a2l_encode.py:614`) | Load `l`; A2L window `2`; describe `d` | rows `30.0`, `4113`, `40.0`, and `n/a` distinct from blank; modal `Scalar value: n/a (rat_func_no_real_root)`; at 118×40 and 80×24 | pass — impl `inc-10/green-at_b99_09.txt`; DDR `green-a2l.txt`; SPOT |
| US-148 | AT-B99-10 (`crc_region.py:541`) | Load project; `#fx_run` | CRC card `✗ error`, `out_empty.s19` absent, cause line; gap lane `◇ notices` with `466 of 512 region bytes absent (0xFA00-0xFC00)`; the slot equals `zlib.crc32` over the present bytes | pass — orchestrator `inc-5/stability-at10.txt` (8×); GATE; SPOT |
| US-149 | AT-B99-11 (`export.py:983`) | Split / Join / Export window; Load dialog (MAC); Patch Editor | `prg_x__________ESCAPED.s19` inside the destination, nothing outside; MAC-only file with 0 data; `<name>_1.s19` with the first file byte-identical; status `_1` / `wrote` / `reused` | pass — DDR joined node `ddr/green-at11-8x.txt` (8/8); SPOT |
| US-150 | AT-B99-12 (`bytes_field.py:128`) | Load `l`; Patch Editor; typed address and Bytes; Add, Apply; save-back | the file holds `0F 10 1F 20` at `0x100` (independent reader) | pass — impl `inc-11/green-at_b99_12.txt`; DDR `green-bytes.txt`; SPOT. No negative arm at the surface (G-002) |
| US-151 | AT-B99-13 (`load_project.py:224`) | Load project dialog (3 pick paths); Workarea Files list | the dialog lists `P1` and `P2` only (`patches` present); the status names `P2`; the Files list shows `a.s19` and loads it | pass — impl `inc-7/green-at_b99_13.txt`; GATE; SPOT |
| US-152 | AT-B99-14 (`a2l_encode.py:452`) | codec API `encode_physical_to_raw_bytes` (the declared US-152 / P-22 exception) | `(0x01,0x2C)` for 30; `10 11` for 4113; 500 → `None` and an error naming `[0.0, 62.5]` | pass — impl `inc-10/green-at_b99_14.txt`; DDR `green-a2l.txt`; SPOT |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | AT-001 | `<handler/screen/CLI>` | `<outcome / file:path>` | pass |
```

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | `12` (US-141…US-152; US-152 was added at P2 round 2, LED .2) |
| Covered user stories | `12` (`100%`): each story has one passing AT and a complete functional chain |
| Total HLR | `11` (HLR-152…HLR-162) |
| Implemented HLR | `11` (`100%`) |
| Total LLR | `40` live (+ 2 retired: LLR-157.3, LLR-159.3; §1c) |
| Implemented LLR | `40` (`100%`) |
| Test cases | `43` live ids (TC-B99-01…44 except TC-B99-37) |
| TC pass | `43` |
| TC fail | `0` |
| TC pending | `0` |
| Acceptance tests | `14` ids (AT-B99-01…14), `14` pass, one node each |
| Test nodes | the 11 `tests/test_b99_*.py` files collect 139 nodes (125 functions); the suite collects 3773 on main (`3634 − 0 + 142 = 3776`, then `− 4 + 1 = 3773`) |
| Layer 0 | 3 units (`_is_data_record`, the export sanitiser, `parse_new_bytes`), each with a named reddening mutation |

> Executor attribution per `04-validation.md`. The increment implementer (Kimi K2.8) ran every `evidence/inc-*/` and `evidence/ddr/` transcript in its worktree. The orchestrator ran the gate run, the triage, the flip table and the Inc-5 final sweep. qa-reviewer ran only the collection count, the SPOT run and two flake re-runs. The independent reviewers of each increment are named in its packet's §4b.

---

## 3. Detected gaps

> **The requirement chain has no gap.** Every live US, HLR, LLR, TC and AT id appears once in §1 / §1b, and each one resolves to a node on disk with a GREEN transcript. Every retired id is listed with its ledger entry (§1c). The rows below are the open minor gaps from `04-validation.md` §Gaps detected (0 blocker, 0 HIGH), plus two record notes found while writing this matrix.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| G-001 | evidence binding | The one complete gate run is on `e7732f6`. Increments 012 and 013 then changed 9 test files (`s19_app/` unchanged), and their GREEN rests on targeted runs (DDR transcripts, `inc-13/`, SPOT). The confirmation run `evidence/suite-full-75f947a.txt` has since finished on the final tree: 12 failed / 3755 passed / 3 skipped / 3 xfailed = 3773, no product defect (`evidence/suite-triage-75f947a.md`) | closed: the result is on the `Gate run` line of `04-validation.md` (CONFIRMATION) |
| G-002 | surface arm | Some boundary and negative arms exist at TC level only: every HEX defect (US-143); missing source and locked target (US-144); overlap and all-undone (US-146); the `G1` / `100` refusal (US-150, which has no surface negative); the table endpoints (US-152) | routed in the working-tree `BACKLOG-CODE.md` (`origin batch-99 P4 G-002`) |
| G-003 | surface arm | The chain-set report's not-applied listing and lane-file list are observed only at the service (TC-B99-19, TC-B99-27) | routed in the working-tree `BACKLOG-CODE.md` (`G-003`) |
| G-005 | baseline conflict | `test_tc018_existing_name_is_dedup_suffixed` and `test_at031b_…` expect a dedup suffix, which contradicts the byte-identical reuse rule (LLR-155.3). Both failed before the batch too | operator decision, routed as `DECISION` in the working-tree `BACKLOG-CODE.md` |
| G-006 | AT shape | Residual non-surface reads: AT-09 reads Textual's private `render_strips()`; AT-12 calls `Input.focus()` and one `Button.press()`; AT-13 reads `app.screen` / `app.workarea` | routed (AT-hardening line) |
| R-1 | record note | `01-requirements.md` §5.1 (line 1282) still lists Layer A as `TC-B99-01..41 except TC-B99-37`. The LLR blocks name TC-B99-42/43/44 (LED .6, LED .8), so the chain is intact, but that summary line is stale | fold at the next requirements touch; the LLR blocks are authoritative |
| R-2 | record note | The batch-99 rows of the requirements canon (`REQUIREMENTS.md`, 51 rows tagged `2026-10-25-batch-99`) are in the working tree only (`git status`: modified), not in `bf3917d` | lands with the close commit |

Closed at P4 and not repeated here: G-004 (flake re-runs rest on `qa-spot-flakes-31bac78.txt`), G-007 (flip-table rows P-16..P-21 appended), G-008, G-009, G-010.

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* G-001 | TC fail | TC-004 fails on condition X | See post-mortem phase 5 |
| *(example)* G-002 | no coverage | LLR-005.2 has no associated TC | Move to next batch |
```

---

## 4. Changes from previous batch

*(What was added, modified or closed since the previous batch: `2026-10-19-batch-97`, close commit `c899113`; batch base `307065f`.)*

| Type | Item | Detail |
|------|------|--------|
| new | HLR-152…162 · LLR-152.1…162.3 (40 live) | the batch-99 requirement set; 51 ids staged into `REQUIREMENTS.md` in the working tree (R-2) |
| new | synthetic corpus + independent reader | `tests/fixtures/synth/` (16 files + `manifest.json`, `generate.py --check`) and `tests/support/independent_reader.py`, with zero `s19_app` imports. Every byte oracle in the batch uses it |
| modified | S19 memory-map contract (B99-I1) | the image, ranges, record lookup, overlap and validity maps come from S1/S2/S3 only; S0 is header text |
| new | loader integrity notices (B99-I10) | `S19-NO-TERMINATOR`, `S19-COUNT-MISMATCH`, `S19-AFTER-TERMINATOR`, `HEX-NO-EOF`, `HEX-AFTER-EOF`; S6 records now parse |
| modified | write placement (B99-I2, B99-I2a) | private `mkdtemp` staging under `temp/.staging/`; O_EXCL claim; next free `_<N>`; `WorkareaPlacementError`; new `place_group_into_workarea` for BIN + `.addr` pairs |
| new | chain-set start check, WRITE-OUT verify (B99-I11, B99-I12) | D7 duplicate-name refusal; D9 read-back after placement |
| modified | PATCH status and run records (B99-I3) | the status comes from dispositions; `ChainRunOutcome` gains `change_records`, `refusals`, `image_ranges`; both reports gain Not applied / Refusals sections; no `CLEAN` with either |
| modified | editor image (B99-I7) | a journal keeps the image equal to the source plus the document; `before_bytes` is the source byte |
| modified | A2L codec (B99-I4) | byte order falls back to the module's `MOD_COMMON`; RAT_FUNC direction per ASAM; COMPU_TAB refusals and flags; `n/a` with a reason in the A2L window |
| modified | CRC coverage (B99-I5) | an empty region is an `error`; partial coverage gives `notices` with the absent count |
| modified | export writer (B99-I6) | one sanitiser, a plan-time collision pass, containment at the work-area root, declared ranges only, `_<N>` placement, `wrote` / `reused` status |
| modified | Bytes grammar (B99-I8) | hex only; amends batch-07 LLR-001.2 |
| modified | pickers (B99-I9) | `RESERVED_WORKAREA_HOMES`; `refresh_files` reads `workarea/temp`; `_load_from_item` reads `item.data` |
| new | module edge | `tui/segment_split_view → tui/workspace`, decided at the PDR (`docs/architecture.md:487`) |
| re-pinned | tests and goldens asserting the old behaviour | e.g. 16 snapshot SVGs (S0 range gone, Inc-2), batch35 before/after goldens, TC-714, TC-702, the `patch-comfortable-120x30` snapshot cell and the `safe_text` import census (Inc-13). Each re-pin is named in its packet's reverse census |
| closed | 2 baseline failures | `test_tc328_…` and `test_at063c_…` pass on `e7732f6` (`04-validation.md:34`) |
| carried | D-3, D-5, F-2/F-3, G-002/003/005/006, QC-WT / QC-AT / QC-FL | `05-postmortem.md` open items → `BACKLOG-CODE.md` / `BACKLOG-PROCESS.md` (working tree, uncommitted at this writing) |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-141** (corpus) → HLR-152 → LLR-152.1…152.3 → TC-B99-01…03 · AT-B99-01
- **US-142** (S0) → HLR-153 → LLR-153.1…153.4 → TC-B99-04…07 · AT-B99-02
- **US-143** (truncation) → HLR-154 → LLR-154.1…154.3 → TC-B99-08…10 · AT-B99-03
- **US-144** (placement) → HLR-155 → LLR-155.1…155.8 → TC-B99-11…16, 38, 39, 44 · AT-B99-04, AT-B99-05
- **US-145** (PATCH truth) → HLR-156 → LLR-156.1…156.4 → TC-B99-17…20 · AT-B99-06, AT-B99-07
- **US-146** (editor image) → HLR-157 → LLR-157.1, 157.2, 157.4 → TC-B99-21, 22, 40 · AT-B99-08
- **US-147** (A2L decode) → HLR-158 → LLR-158.1, 158.2 → TC-B99-23, 24, 42, 43 · AT-B99-09
- **US-152** (A2L encode) → HLR-158 → LLR-158.1…158.3 → TC-B99-23…25, 42, 43 · AT-B99-14
- **US-148** (CRC) → HLR-159 → LLR-159.1, 159.2 → TC-B99-26, 27 · AT-B99-10
- **US-149** (export) → HLR-160 → LLR-160.1…160.5 → TC-B99-28…31, 41 · AT-B99-11
- **US-150** (Bytes field) → HLR-161 → LLR-161.1, 161.2 → TC-B99-32, 33 · AT-B99-12
- **US-151** (pickers) → HLR-162 → LLR-162.1…162.3 → TC-B99-34…36 · AT-B99-13

### 5.2 By code file
- `s19_app/core.py` → LLR-153.1, 153.3, 153.4, LLR-154.1 → TC-B99-04, 06, 07, 08 (Inc-2, Inc-9)
- `s19_app/render/hexview.py` → LLR-153.2 → TC-B99-05 (Inc-2)
- `s19_app/hexfile.py` → LLR-154.2 → TC-B99-09 (Inc-9)
- `s19_app/tui/workspace.py` → LLR-155.1, 155.2, 155.3, 155.7, LLR-160.4, LLR-162.2 → TC-B99-11, 12, 13, 39, 44, 31, 35 (Inc-3a, Inc-6, Inc-7)
- `s19_app/tui/changes/apply.py` · `s19_app/tui/changes/io.py` → LLR-155.1, 155.7 → TC-B99-11, 39, 44 (Inc-3a)
- `s19_app/tui/services/project_gather_service.py` → LLR-155.3 (LED .7), LLR-160.2 (`_check_home_contained`, reused unchanged) → TC-B99-13, 29 (Inc-3b)
- `s19_app/tui/services/flow_execution_service.py` → LLR-154.3, LLR-155.5, 155.6, LLR-156.1, 156.2, 156.3, LLR-159.1, 159.2 → TC-B99-10, 15, 16, 17, 18, 19, 26, 27 (Inc-3b, Inc-5, Inc-8, Inc-9)
- `s19_app/tui/services/flow_report_service.py` → LLR-156.4 → TC-B99-20 (Inc-8)
- `s19_app/tui/flow_screens.py` → LLR-156.2 (PATCH rider), LLR-159.2 (CRC rider) → TC-B99-18, 27 (Inc-5, Inc-8)
- `s19_app/tui/operations/crc.py` → LLR-155.8, LLR-159.1, 159.2 → TC-B99-38, 26, 27 (Inc-5)
- `s19_app/tui/services/change_service.py` → LLR-157.1, 157.2, 157.4, LLR-161.1 → TC-B99-21, 22, 40, 32 (Inc-4, Inc-11)
- `s19_app/tui/a2l.py` → LLR-158.1, 158.2, 158.3 → TC-B99-23, 42, 24, 43, 25 (Inc-10)
- `s19_app/tui/segment_split_view.py` → LLR-160.1, 160.2, 160.3, 160.4, 160.5 → TC-B99-28, 29, 30, 31, 41 (Inc-6)
- `s19_app/tui/screens_directionb.py` · `s19_app/tui/window_help.py` → LLR-161.2 → TC-B99-33 (Inc-11)
- `s19_app/tui/app.py` → LLR-154.3 (UX-C7 status), LLR-155.4, 155.5 (status line), LLR-157.4 (strip), HLR-158 (A2L `n/a` cell, `app:12710` `_build_a2l_table_cells`), LLR-162.1, 162.2, 162.3 → TC-B99-10, 14, 15, 40, AT-B99-09, TC-B99-34, 35, 36 (Inc-3a, 3b, 4, 7, 9, 10)
- Tests only: `tests/fixtures/synth/generate.py`, `tests/support/independent_reader.py` → LLR-152.1…152.3 → TC-B99-01…03 (Inc-1); Inc-12 (`c1d088a`) and Inc-13 (`1a59d3b`) changed tests only

> Source: the packets' §2 `Traces to` column (`03-increments/increment-001…013.md`). As built, the largest SOURCE set is 4 of 4 (Inc-3a, Inc-9), and no increment exceeded the cap.

**Worked examples of both maps — text to read, never lines of your record:**

```text
- *(example)* **US-001** → HLR-001, HLR-002 → LLR-001.1, LLR-001.2, LLR-002.1 → TC-001, TC-002, TC-003
- *(example)* `src/foo.ts` → LLR-001.1, LLR-001.2 → TC-001, TC-002
- *(example)* `src/bar.ts` → LLR-002.1 → TC-003
```

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-10-25-batch-99` |
| Closing date | `2026-10-26` (opened 2026-10-25; P5 commit `bf3917d` on `main`; this P6 artifact written 2026-10-26) |
| Total iterations (sum of phases) | counted from the record (`05-postmortem.md` Part A §Metrics): P0 1 · ARQ 1 · P1 1, with 8 ledger entries · P2 3 rounds · PDR 1 · P3 14 increment packets (001–011, 003b, 012, 013) with 26 code-review rounds · DDR 1 · P4 1 (+ Inc-013) · P5 1 · P6 1. `state.json`'s `iterations_per_station` undercounts P2 and P3 (`05-postmortem.md` §Record corrections) |
| Validation passed | yes — `PASS-WITH-NOTES` (0 blocker, 0 HIGH; §3) |
| Synced to Obsidian | no — the operator commits, pushes and runs `/dev-flow-sync` |
