# P2 review: qa-reviewer, batch 2026-10-25-batch-99

**Mode:** `plan`. This is a Phase-2 testability review of `01-requirements.md` (1180 lines, read in full). Every AT and TC named below is `planned`; I claim no run of them. I ran a few read-only checks myself, at HEAD `307065f`, to confirm premises. Each is labelled `inspection-executed (qa-reviewer)`. Nothing else is claimed as run.

**Verdict input (for `02-review.md`):** 1 blocker · 6 major · 10 minor. The blocker (Q-1) is a requirement defect, so this reviewer's input to the gate is `iterate-to-refine`.

---

## Findings

| ID | Severity | Req | What | Recommendation |
|----|----------|-----|------|----------------|
| Q-1 | blocker | US-147 / HLR-158 / AT-B99-09 (LLR-158.1..3 encode limbs) | **The AT's driver does not exist at HEAD.** HLR-158 names "Patch Editor symbol entry (`#patch_symbol_*`)" as the shipped surface. No widget id `patch_symbol*` exists anywhere in `s19_app/`. The Patch Editor's entry form has only Address / String / Bytes inputs (`screens_directionb.py:4938-4941`). `resolve_symbol_entry`, `ChangeService.add_symbol_entry` and `encode_physical_to_raw_bytes` have **no caller outside `services/change_service.py` / `a2l.py`** (grep across `s19_app/`). Change documents carry symbol + raw bytes; `changes/io.py:1068` says the physical→raw encode is "the authoring-time half and lives in `a2l.py`". So no key, click or document load in the shipped TUI encodes a physical value. Two-layer (a)/(d) therefore fail for the encode limbs: the AT cannot drive a surface, so it would have to call the service, which (d) forbids. The decode limb ("A2L window shows 30") *is* observable, because the A2L window paints `physical_value` (`app.py:12522-12543`). US-147 itself ("entering physical values from the A2L") describes a capability the TUI does not ship. ARQ RC-4 ("the picker (`change_service.py`, `screens_directionb.py`)") assumes the same missing picker. | P1 chooses and records one of three options. (i) Declare the encode limbs' surface to be the service API (`resolve_symbol_entry`) as a recorded Layer-B exception with its reason; keep the decode limb black-box via the A2L window; reword US-147 to match. (ii) Add a symbol-entry surface to the Patch Editor. That is new UI and needs the prototype round first, so it probably belongs to another batch. (iii) Drop the encode limbs from this batch. Whichever is chosen, AT-B99-09 must name a surface that exists, and the ARQ RC-4 split must be re-derived. |
| Q-2 | major | HLR-155 / AT-B99-04 | **The negative control does not match the AT arm.** The AT's parallel arm runs 8 lanes with *distinct* output names. P-5 (`rw-p02`) measured lanes that all claim `same.s19`. With distinct names, today's `temp/<name>` staging is not shared, so that arm is very likely GREEN on `307065f`. "Both ATs RED today" is therefore unsupported for the arm as written. Under D7 = `rechazar`, the only RED arm of AT-B99-04 is the duplicate-name refusal. | Pin the RED claim on the duplicate-name refusal arm and record it as executed for the AT as written. Keep the distinct-name parallel arm as a regression guard with no RED claim. If D7 lands on `_<N>`, make the same-name parallel arm the RED arm instead. |
| Q-3 | major | HLR-159 / AT-B99-10 / US-148 | **The oracle contradicts itself.** The AT says the step "shows the CRC cell failed and **writes nothing**". The threshold says "output slot bytes == source slot bytes", and US-148 says "the output bytes unchanged"; both imply an output file is written. At HEAD a block `error` aborts the flow only through `_record_error` (`flow_execution_service.py:948-977`), and HLR-159 does not say whether a CRC `error` stops a later WRITE-OUT. HLR-156 does say this for PATCH. | State whether a CRC `error` stops the flow before WRITE-OUT, then make the statement, the AT, the threshold and US-148 say the same thing. |
| Q-4 | major | HLR-153 / AT-B99-02 (also HLR-157's empty boundary) | **AT step cannot be driven.** Patch Editor save-back is offered only when `counts["applied"] > 0` (`app.py:3238-3241`). "Saving it back unchanged" is not reachable. The `0x0` patch arm applies 0 entries under LLR-153.4, so no save prompt appears. HLR-157's boundary "undo of every entry → saved file == source" has the same problem. | Drive AT-B99-02 with one applied in-image entry, e.g. identical bytes rewritten at a data address. Assert that `0x0..0xB` is absent and that only that entry differs. Alternatively use the flow SOURCE→WRITE-OUT identity, which is P-1's own surface. Move HLR-157's all-undone boundary to TC-B99-21 or name its UI path. |
| Q-5 | major | LLR-157.3 / TC-B99-37 | **The threshold cannot be measured as defined.** A "`LoadedFile`-typed name" cannot be decided from an AST. The obvious name-based census (`mem_map[...] =` / `mem_map.update(`) finds **3** sites at HEAD, not 1: `core.py:493`, `render/hexview.py:65`, `tui/changes/apply.py:337`. `apply.py:337` writes to a *parameter* named `mem_map`. The negative control mutates "a scratch copy of `app.py`", which is outside the scanned tree unless it is placed under `s19_app/`. | Define the predicate. Either (a) writes through names bound from a `.mem_map` attribute, or (b) name-based with an explicit allowlist of the two builders that construct fresh maps. Pin the expected set exactly. Mutate in place under a sha256-verified restore. |
| Q-6 | major | HLR-158 / LLR-158.3 (provisional D4) | **"Within the method's tolerance" is undefined.** An ASAP2 COMPU_TAB declares no tolerance. A `TAB_INTP` value inside the table range, between two points, can fail an exact round-trip through an integer raw value. The boundary "a value just outside" also depends on the tolerance. As written, the threshold cannot decide those arms. | Define the tolerance, e.g. exact equality for `TAB_NOINTP`, and for `TAB_INTP` half the physical step of one raw LSB at that point. Add an in-range interpolated arm, both accepted and refused, to the threshold. |
| Q-7 | major | §5.1 / §5.2 regression criterion | **The baseline is not this batch's.** `evidence/baseline-pytest-51ee191.txt` does not exist in this batch. It is batch-97's file, run at `51ee191`, not at `base_ref` `307065f`. The cited counts mix two runs ("10 failed, 3101 passed" + "3617 passed"). As a result, "no new failure against the baseline" cannot be measured. | Before Inc 1, capture one full-suite baseline at `307065f` into this batch's `evidence/`, and cite its counts and failing node ids. |
| Q-8 | minor | HLR-154 shipped surface | Names "Flow Execution run (`#flow_run_*`)". `#flow_run` is the Flow **Builder** Run (`flow_screens.py:1297`); Flow Execution runs with `#fx_run` (`:2793`). | Name the driver actually used. |
| Q-9 | minor | HLR-154 / LLR-154.1 | The HLR names `S5` only, while the LLR adds `S6`. The image content after an S19 terminator is unspecified. Today the S19 loader keeps those records (`rw-p04` `s19_data_after_term` ranges include `0x2000`), while the HEX loader drops records after EOF (`hexfile.py:99-100`). The boundary catalog has no count-field arm (an `S5` past 0xFFFF records, which needs `S6`). | Align S5/S6 between HLR and LLR. State whether post-terminator S19 records stay in the image of an interactive load. Add the count-width boundary. |
| Q-10 | minor | LLR-162.2 / TC-B99-35 | "Each other home the work area creates" is open-ended, so the threshold "0 reserved homes listed" has no closed set to test. The source creates `temp`, `patches`, `splits` and `crc` under the work area (grep of `workarea / …`). | Enumerate the set, or point to one constant tuple that the test imports. |
| Q-11 | minor | HLR-162 boundary (empty) | "OK disabled or a notice" leaves the oracle undecided. | Pick one observable. |
| Q-12 | minor | HLR-156 status rule | The precedence is open for a document with ≥1 applied entry plus one entry-level ERROR issue, such as `CHG-SYMBOL-UNRESOLVED` on one entry of several. Is that `error` ("carries an ERROR refusal") or `notices` ("one blocked, one applied")? §1.3's definition of *Refusal* ("stops a document") does not settle it. §6.3 promises a hostile-name arm for HLR-156's AT, but that arm is missing from its AT, boundary and threshold. | Add the mixed case to the 7-case matrix with its expected status. Add the hostile-name arm to AT-B99-06/07. |
| Q-13 | minor | LLR-152.2 | The corpus class "S19 overlap with differing bytes" has no consuming requirement; it loads `ok` with 0 notices today (`rw-p04`). Its manifest "expected bytes" needs a rule for which byte wins. | Name its consumer or mark it oracle-only. State the overlap rule the manifest records. |
| Q-14 | minor | HLR-155 / LLR-155.2 scope | The statement covers *image* writes. LLR-155.2 edits `copy_into_workarea`, which report, manifest and check-spec writers share (14 test files reference it). Whether those writers move to private staging is not stated, and the answer decides which observers change (see census, HLR-155 row). | State the scope: images only, or every caller of `copy_into_workarea`. |
| Q-15 | minor | LLR-156.4 + golden (C-24) | Not stated: does the flow report render the new not-applied / refusal sections when they are empty (`none`, as LLR-156.3 does for the chain-set report) or omit them? That decides whether `tests/goldens/batch71/ac6-unscoped-flow-report.md` drifts. TC-716 sets a precedent of "empty, never absent". | State it. If the sections are always present, name the golden rebaseline in the owning increment. |
| Q-16 | minor | HLR-156 / AT-B99-06/07 | A flow report exists only when the flow carries a REPORT block ("Blocks reported: N (up to the report block)", `rw-p09`). The AT does not say that its flow fixture includes one. Clause-level ATs are also missing for D8 (`replaced` status) and D9 (verify-after-write); those are TC-only and hook-forced. | Name the REPORT block in the AT fixture. State explicitly that the D8/D9 clauses are TC-only, with the reason. |
| Q-17 | minor | HLR-155 statement | "It shall never delete a file it did not create" is a universal claim that a single arm checks (same-name save-back). | Narrow it to the writes this batch touches, or add a census arm, e.g. no `unlink` outside the staging path in the touched writers. |

## Negative-control spot-checks (premise vs evidence vs HEAD)

| Premise | Claim | Checked against | Result |
|---|---|---|---|
| P-1 | 15/16 example S19 gain bytes at `0x0` | `rw-p03`: 30 `BAD` lines (15 files × S19+HEX), `prg.s19` `OK`; `find examples` shows 15 of 16 S19 files carry `S0` | consistent |
| P-4 / P-13 | PATCH `ok` for all 6 cases, dispositions correct | `rw-p01` (6 rows, all `patch=ok`, `wrote=[…]`) | consistent; AT-B99-06/07 RED today |
| P-5 | parallel same-name race | `rw-p02`: every lane claims `same.s19` | consistent for same names; **not** for AT-B99-04's distinct-name arm (Q-2) |
| P-6 | undone entry reaches file | `rw-p05` at service level; UI drivers `#patch_undo_button`, `#patch_doc_apply_button`, `#patch_saveback_*` exist | consistent; AT-B99-08 drivable |
| P-9 | CRC empty region `ok` + `00000000` | `rw-p07` | consistent; oracle conflict separately (Q-3) |
| P-10 | truncation loads `ok`, HEX after-EOF dropped | `rw-p04` (`hex_data_after_eof out_bytes=32` == good file; the `0x2000` record is dropped); `hexfile.py:99-100` `break` at type 01 | consistent |
| P-11 | export escapes dest | `rw-p10` `inside dest: False` | consistent |
| P-14 | chain-set report names nothing | `rw-p02` report body; `rw-p09` `Status: CLEAN` | consistent |
| P-15 | save-back deletes work copy, app exits | `proj-p08:76-79` | consistent |
| P-16 | digit tokens read as decimal | inspection-executed (qa-reviewer): `parse_new_bytes('0F 10 1F 20')` → `0xf 0xa 0x1f 0x14`; `'11 22'` → `[11, 22]` | consistent; AT-B99-12 RED today |
| P-19 | Textual 8.2.8 `Label` has no `.text` | inspection-executed (qa-reviewer): `8.2.8 False Label()`; `app.py:8816-8821` | consistent |
| P-20 | `list_projects` filters only `temp` | `app.py:8314-8319` | consistent (code read) |
| CW-U-3 | Workarea Files reads the root, while loads go to `temp/` | `app.py:6419-6426` `refresh_files` globs `self.workarea`; docstring says "temp folder" | consistent; AT-B99-13 RED today |

## AT driver feasibility at HEAD

| AT | Surface needed | Present at HEAD? | Evidence |
|---|---|---|---|
| AT-B99-01 | `generate.py --check` CLI | NEW (planned) | n/a |
| AT-B99-02 | Load file, Patch Editor save-back, Memory Map | yes, but no save-back without an applied entry (Q-4) | `app.py:3238`; `rail.py:84` (`map`) |
| AT-B99-03 | issues panel; flow run | yes (driver name wrong, Q-8) | `#fx_run`, `#flow_run` |
| AT-B99-04 | chain set, parallel mode | yes | `ModeToggle` `#fx_mode` (`flow_screens.py:981-1056`); TC-B97-24 already runs a parallel set by pilot |
| AT-B99-05 | save-back by name, Save project | yes | `#patch_saveback_name_input`; `SaveProjectScreen` (`screens.py:483`) |
| AT-B99-06/07 | flow lane cells, reports | yes (REPORT block needed, Q-16) | `fx_lane_*`, `write_chain_set_report` |
| AT-B99-08 | Add / Apply / Undo / Save-back | yes | `#patch_entry_add_button`, `#patch_doc_apply_button`, `#patch_undo_button`, `#patch_saveback_confirm_button` |
| AT-B99-09 | Patch Editor symbol entry | **no** (Q-1) | no `patch_symbol*` id; no UI caller of `resolve_symbol_entry` |
| AT-B99-10 | flow CRC step | yes | flow CRC arm |
| AT-B99-11 | Split/Join/Export | yes | `#sje_dest`, `#sje_export` (`segment_split_view.py:1088,1099`) |
| AT-B99-12 | Bytes field + save-back | yes | `#patch_entry_bytes_input` |
| AT-B99-13 | Load project dialog; Workarea Files | yes | `#project_list`, `#project_ok` (`screens.py:706-711`); `#files_list` (`app.py:2138`) |

## Two-layer review (per story)

| Story | HLR | (a) AT present | (b) deliverable + method named | (c) both chains | (d) black-box pure / drivable | Status |
|---|---|---|---|---|---|---|
| US-141 | 152 | AT-B99-01 | yes: exit code + named file | yes (LLR-152.1..3 → TC 01..03) | yes (CLI) | ✓ |
| US-142 | 153 | AT-B99-02 | yes: file via independent reader, Memory Map, status | yes (153.1..4 → TC 04..07) | references no internal symbol, but one step is not drivable (Q-4) | ✓ (major Q-4) |
| US-143 | 154 | AT-B99-03 | yes: notice text, SOURCE cell, no file | yes (154.1..3 → TC 08..10) | yes (driver name, Q-8) | ✓ |
| US-144 | 155 | AT-B99-04, -05 | yes: files per lane, refusal text, app running | yes (155.1..6 → TC 11..16) | yes; RED claim mismatched (Q-2) | ✓ (major Q-2) |
| US-145 | 156 | AT-B99-06, -07 | yes: lane cell, report files | yes (156.1..4 → TC 17..20) | yes | ✓ |
| US-146 | 157 | AT-B99-08 | yes: file via independent reader + status | yes (157.1..3 → TC 21, 22, 37) | yes | ✓ |
| US-147 | 158 | AT-B99-09 (named) | encode limbs: no observable surface; decode: A2L window | yes on paper (158.1..3 → TC 23..25) | **no**: encode surface absent (Q-1) | **blocker** |
| US-148 | 159 | AT-B99-10 | yes, but conflicting ("writes nothing" vs slot bytes equal) | yes (159.1..3 → TC 26, 27, 38) | yes | ✓ (major Q-3) |
| US-149 | 160 | AT-B99-11 | yes: file location + 0 data records | yes (160.1..4 → TC 28..31) | yes | ✓ |
| US-150 | 161 | AT-B99-12 | yes: file bytes via independent reader | yes (161.1..2 → TC 32, 33) | yes | ✓ |
| US-151 | 162 | AT-B99-13 | yes: dialog list, status, loaded file | yes (162.1..3 → TC 34..36) | yes | ✓ |

TC ids TC-B99-01..38 are all assigned (38 unique). AT ids AT-B99-01..13 are all referenced. 0 orphans in either direction.

## Supersession census (change-first): best-effort + gate-confirmed

This census is not complete. The increment gate's full-suite run is the completeness guarantee. Method: C-26 reverse grep (`grep -rl <symbol> tests/ --include=*.py`) for each touched symbol named in the LLRs; C-14 sweep of save-observing tests (`glob`/`rglob` and `temp/` paths); C-24 sweep of `tests/goldens/**`.

| Change | Touched symbols / surface | Observers found (tests/) | Expected to legitimately change |
|---|---|---|---|
| S0 excluded (LLR-153.x) | `get_memory_ranges` (6 files), `get_memory_map` (11), `build_mem_map_s19` (3), `source_s0_header` (4) | `test_changes_apply`, `test_color_policy_round_trip`, `test_patch_dual_entry`, `test_segment_split_window`, `test_tui_app`, `test_validation_engine`, `test_render_hexview`, `test_report_service`, `test_tui_hexview`, `test_memmap_entropy_merge`, `test_tui_patch_editor_v2`, `test_unload_feature`; S0 literal + ranges/map: `conftest`, `test_before_after_report`, `test_crc_operation`, `test_entropy_service`, `test_tui_directionb`, `test_tui_helpers`, `test_workspace_variants`; pilots/snapshots over S0-bearing examples: `test_tui_snapshot` (`__snapshots__/test_tui_snapshot`), `test_examples_smoke`, `test_examples_pilot_gifs`, `test_tui_map_big`, `test_tui_workspace_layout` | every range count / first range / byte count / painted map row on an S0-bearing fixture (one range fewer, no `0x0` start). SVG snapshots that paint a Memory Map or range count of a `case_0x` example drift. |
| Integrity notices (LLR-154.x) | S19/HEX `_load`, flow SOURCE arm | coarse grep: files with inline S19 data and **no** `S7/S8/S9` anywhere: `test_cli.py`, `test_copy_into_workarea_content_dedup.py`; files that mix both kinds of fixture are not separated by this grep | any `errors == []` / `notices == 0` / flow `ok` assertion on a fixture without a terminator. Under D6 = `flujo_para`, any flow test whose SOURCE fixture lacks a terminator now errors and writes nothing. All 16 `examples/**/*.s19` have a terminator and no `S5`, so they are safe. |
| Private staging / placement (LLR-155.1..3) | `save_patched_image` (5), `copy_into_workarea` (14), `temp/<name>` | `test_changes_apply`, `test_flow_execution`, `test_flow_execution_service`, `test_tui_flow_execution_b94`, `test_variant_execution`; temp-path observers: `b97_fixtures.staging_block` → `test_b97_chips_help:967, 2322`; `test_manifest_writer:406`; `test_tui_crc_surface:577`; `test_unified_write:396, 465`; `_1.s19` suffix observers: `test_before_after_report`, `test_copy_into_workarea_content_dedup`, `test_diff_report_service` | depends on Q-14's scope. If `copy_into_workarea` staging changes for every caller, the `staging_block` arms (which block `temp/spec.chk.json` by name) and `test_manifest_writer:406` no longer block or observe anything and must be re-pinned. |
| Save project survives missing source (LLR-155.4) | `_handle_save_dialog` (6) | `test_project_gather`, `test_tui_app`, `test_tui_evidence_packs`, `test_tui_manifest_save`, `test_tui_report_seam`, `test_tui_variants` | expected to survive (new branch); confirm at gate |
| Duplicate lane names refused (LLR-155.5, D7) | `run_chain_set` (5) | `test_b97_chips_help`, `test_b97_flow_builder`, `test_b97_flow_execution`, `test_flow_chainset_b94`, `test_flow_external_step_b96` | any fixture whose lanes share a WRITE-OUT name is now refused (e.g. `rw-p02`'s rerun pattern) |
| PATCH truth + run records (LLR-156.x) | PATCH arm, `ChainRunOutcome` (0 direct refs), `compose_chain_set_report` (1), `compose_flow_report` (3), `STATUS_CLEAN` (1) | **TC-714** `test_changes_symbol_entries.py::test_tc714_no_declared_ref_refuses_symbol_entries_no_implicit_a2l` asserts `patch.summary == "applied 0 entries"` and reads `result.written_paths[0]`. Under HLR-156 that becomes PATCH `error` with no WRITE-OUT, so this is a certain re-pin. TC-718 battery arms in the same file. `test_flow_chainset_b94` (report rows). `test_flow_report_service`, `test_flow_report_fusion`, `test_flow_report_ac6_golden` | TC-714 (certain); chain-set report row assertions; flow-report section assertions; any flow test with a skipped / blocked / v1 / malformed patch asserting `ok`, `CLEAN` or a written path |
| Golden (C-24) | flow report composer | `tests/goldens/batch71/ac6-unscoped-flow-report.md` (PATCH `applied 1 entry`, CRC region `0x1000–0x1004` half-open and fully covered (`crc_config.py:136`), S9 present) | stays byte-identical **only if** the new sections are omitted when empty (Q-15). Not affected by HLR-154 (S9 present) or HLR-159 (full coverage). The other goldens (batch35/64/74/76/77/78) are project, diff and UI captures and do not flow from the touched composers in this sweep. Gate to confirm. |
| Editor image (LLR-157.x) | `ChangeService.apply` / `undo` / `remove_entry` / `edit_entry` | `test_change_service`, `test_tui_patch_history_strip`, `test_tui_patch_editor_v2`, `test_b97_patch_editor` | assertions that rely on the stale-byte behaviour (none identified yet); the gate confirms |
| A2L codec (LLR-158.x) | `_apply_compu_method` (3), `encode_physical_to_raw_bytes` (2), `effective_byte_order` (2), `_invert_rat_func` (0) | `test_a2l_curve_description`, `test_changes_symbol_entries` (TC-712/713 round-trips), `test_tui_public_api`, `test_a2l_record_layout_walker`, `test_tui_a2l_detail` | RAT_FUNC decoded values (D2); MSB_FIRST decode in A2L display tests (D3) |
| CRC (LLR-159.x) | `crc.py` region coverage, `EMITTED_NAME_SUFFIX` (0) | `test_crc_operation`, `test_tui_crc_surface`, `test_crc_config`; temp observer `test_tui_crc_surface:577` | any CRC fixture over a gap or an empty region that asserts `ok` |
| Export (LLR-160.x) | `SegmentSplitView` (0 by class name), `_write` | `test_segment_split_window` | export file naming; second-export behaviour (D8 replaces where today's behaviour overwrites in place) |
| Bytes grammar (LLR-161.x) | `parse_new_bytes` (2), Bytes placeholder | `test_change_service:600-603` (values still pass); `test_tui_memory_patch:134-144` (`..._accepts_hex_decimal_and_bare_hex`, where `"1, 2, 3"` still parses but the stated intent changes); placeholder / `"DE AD BE EF"` observers: `test_changes_schema`, `test_patch_dual_entry`, `test_tui_patch_editor_b94`, `test_tui_patch_editor_v2`, `test_unified_write`, `test_checks_engine` | the decimal-intent test (rename / re-pin with batch-07 LLR-001.2's amendment); the error message `"... or decimal"` if any test asserts it; placeholder text |
| Pickers (LLR-162.x) | `list_projects` (2), `_load_from_item` (0), `#files_list` (2) | `test_tui_app:367-377`, `test_tui_helpers:132-143` (survive: no reserved home in their fixtures); `test_tui_directionb:8923` (geometry, survives); `test_tui_snapshot:414` (Workspace left pane) | the snapshot drifts if a fixture loads a file before capture (the list stops being empty) |

**Reservations:** the S0 and terminator rows can be bounded only by running the suite, because fixture builders and inline strings vary per test function. Symbols with 0 test references (`ChainRunOutcome`, `_invert_rat_func`, `_load_from_item`, `EMITTED_NAME_SUFFIX`, `SegmentSplitView`) are still observed indirectly through their callers, and the gate run covers them.

## Evidence checklist (qa-reviewer)

| Item | ✓/✗ | Evidence |
|---|---|---|
| Acceptance criteria use Given/When/Then | n/a | Phase-2 review of a requirements template that uses *Statement* + *Observable outcome*, not authored GWT. Every HLR carries an observable outcome (§3). |
| Test cases have explicit Expected, not vague "works" | ✗ | Numeric thresholds are on every HLR/LLR, except LLR-157.3 (Q-5) and LLR-158.3's tolerance (Q-6), which cannot be measured as written |
| Edge cases include empty, boundary, invalid, error | ✓ | every HLR has a QC-3 catalog with each N/A justified; gaps in Q-9, Q-11, Q-12 |
| Regression checklist exists | ✓ | census section above (C-14 / C-24 / C-26) |
| Exit criteria stated | ✓ | §5.2 states them; its baseline is mis-sourced (Q-7) |
| No real PII / secrets | ✓ | fixtures are synthetic or `examples/`; no credentials |
| Mode declared | ✓ | `plan`, at the top of this file |
| Plan mode: results declared `planned` | ✓ | every AT/TC is `planned`; the only executed checks are labelled inspection-executed (qa-reviewer) |
| Layer B: deliverable observed through the shipped surface | ✗ | US-147 encode limbs have no shipped surface (Q-1); the other 10 stories ✓ |
| Bidirectional surface-reachability | ✗ | the US-147 input dimension (a physical value) cannot be reached through any handler (Q-1); the other inputs and outputs are reachable (driver table) |
| No unfilled template | ✓ | grep: no `<...>`, `TC-NNN` or `TBD`; 38 TC ids and 13 AT ids assigned |

---

## Round 2 (2026-10-25)

**Mode:** `plan`. This round re-reviews the amended contract (`01-requirements.md`, 1327 lines) against ledger entry LED-2026-10-25-batch-99.1. I read the changed blocks in full: HLR-153..160, HLR-162 and their LLRs, LLR-155.7/155.8/157.4/160.5, the AT re-pins, §5 and IFC Part B. I checked the claims against the tree at `a293213`. That commit differs from `307065f` only in `.dev-flow/**`, `.gitattributes` (a batch-99 evidence line) and `docs/architecture.md`; no source changed. Read-only greps are labelled inspection-executed (qa-reviewer). I claim no AT or TC run.

**Round-2 tally:** 1 blocker · 2 major · 5 minor. Of the 17 round-1 findings, 14 are closed and 3 are not (Q-1, Q-5, Q-6).

### Round-1 findings: closure

| ID | Sev (r1) | Closed? | The line that closes it, or why it is not closed |
|----|----------|---------|-----------------------------------------------|
| Q-1 | blocker | **not closed: still a blocker, narrowed** | The AT is now drivable and RED today. AT-B99-09 observes the decode in the A2L window (line 456: 30 for raw 300, 4113 for `10 11`). The window paints `physical_value` (`app.py:12522-12543`), and P-7/P-17 make both arms RED at HEAD (line 460). The *substance* of the exception is sound: TC-only encode plus a black-box decode is the right verification, given P-22 (line 289). **What is still wrong: the two-layer rule as written has no exception clause.** It reads "(a) every story has a black-box AT … (d) assert the outcome", and the Layer-B item reads "every output-producing story's deliverable is observed through the shipped surface". US-147 still promises an outcome no AT observes and no user can perform. Line 118: "As the calibration engineer **entering physical values** … so that **the raw bytes written mean the value I typed**". Line 209: *Evaluability*: "when the user enters 30 km/h … the entry reads `2C 01`". So AT-B99-09 observes something other than its story's deliverable. **Fix (text only, P1):** restate US-147 so its user outcome is what AT-B99-09 observes ("the A2L window shows the physical value the A2L declares, in the declared byte order and RAT_FUNC direction"). Move the encode limbs to a maintainer-level story, either a split US-147b or a clause like US-141's, whose declared shipped surface is the codec API (`resolve_symbol_entry`), just as US-141's is the generator CLI. Its *Evaluability* would be service-level. With that restatement, the rule is satisfied as written and the blocker closes. |
| Q-2 | major | closed | Lines 395-396 (refusal arm; distinct-name arm is a "regression guard; no RED claim"); line 401 (RED arm named; same-name concurrency RED moved to TC-B99-12); line 386 and LLR-155.2 line 661 ("8 threads requesting ONE name"). |
| Q-3 | major | closed | Line 465 ("stop the flow before any later WRITE-OUT, so no file is written"); line 469 ("0 files written by the flow"); line 472; US-148 rows (lines 119, 222); LLR-159.1 line 842. |
| Q-4 | major | closed | Line 350 (one applied in-image entry, citing P-23); P-23 at line 290; line 437 (all-undone boundary moved to TC-B99-21); LLR-157.1 line 772. |
| Q-5 | major | **not closed** | LLR-157.3 (line 789) now counts "every subscript assignment, `update`/`pop`/`clear`/`setdefault` call **or rebind** of a name or attribute called `mem_map`". Its threshold is "census set == the allow-list, exactly" (line 792). At `a293213` the predicate and the allow-list disagree in both directions (inspection-executed (qa-reviewer): statement-level `mem_map … =` grep over `s19_app/`). **(1) Rebinds outside the allow-list:** `app.py:3162, 5423, 6803, 9698, 11063, 12242`; `crc_designer_view.py:981, 1050`; `flow_execution_service.py:316`; `load_service.py:59, 107`; `report_service.py:2464`; `variant_execution_service.py:766`; `core.py:586, 622`. **(2) Allow-listed sites the predicate cannot find:** `hexfile.py` has no `mem_map` name (its map is `memory`); `crc.py` has no subscript or mutator write on `mem_map`, only the keyword `mem_map=op_input.mem_map` at `:1526`. The subscript writes are exactly `core.py:493`, `render/hexview.py:65` and `changes/apply.py:337`. As written, TC-B99-37 is RED at HEAD and stays RED after a correct implementation. **Recommendation:** drop "rebind" and count only in-place mutation (subscript store, `del`, mutator calls). Set the allow-list to what that predicate finds (the three subscript sites), or name each rebind as an allowed alias. Re-run the census and cite the found set in the LLR. |
| Q-6 | major | **not closed: replaced by a new defect** | The tolerance is now defined (line 445: `TAB_INTP` … \|decode(encode(x)) − x\| exceeds half the physical step between the two adjacent raw integers at x). But under the shipped encoder, which rounds to the nearest raw value (P-8 / `rw-p06`: nearest / clamped), every in-range `x` satisfies that bound by construction. Rounding to the nearer of two adjacent raw integers leaves an error of at most half their physical step. So the threshold arm "an in-range off-grid value … **one beyond refused**" (line 452; LLR-158.3 line 832) cannot be built from an honest fixture, and the in-range clause of the refusal rule is dead. **Recommendation:** state the encoder's rounding. If it is nearest, delete the in-range refusal clause and its arm, so that `TAB_INTP` refuses only out-of-range values. If a real in-range refusal case exists (a non-monotonic or flat table segment, or a floor encoder), name it and build the arm from it. |
| Q-7 | major | closed in the contract; evidence pending | §5.1 Regression line: "against this batch's own baseline `evidence/baseline-pytest-a293213.txt` … counts and failing node ids are cited in PLAN's test ledger". The file exists but was still being written when I read it (progress lines at 5 %), so its counts are `not-run` from this reviewer's view. Note: "differs from `base_ref` in batch records only" is true for source; the non-record diff is `docs/architecture.md`, which `tests/test_docs_canon.py` reads, and the baseline at `a293213` already includes it. |
| Q-8 | minor | closed | Line 367 (`#fx_run`). |
| Q-9 | minor | closed | Line 359 (S5 or S6; records after the end never enter the image; count stated); line 369 (blank-tail and `S6` > 65 535 boundaries); LLR-154.1 line 615 (count widths, count-only tail, one notice per kind); line 618 (100 000-line junk tail). |
| Q-10 | minor | closed | LLR-162.2 line 941 (closed tuple `RESERVED_WORKAREA_HOMES`); line 944 (the test imports the tuple). |
| Q-11 | minor | closed | Line 528 ("pressing Load loads nothing and the current file stays loaded"). |
| Q-12 | minor | closed | Lines 407-409 (first match wins; entry-level `blocked` → `notices`; document-level → `error`); line 415 (8-case matrix incl. the mixed symbol case and a hostile-name arm). |
| Q-13 | minor | closed | LLR-152.2 line 555 (oracle-only; last-wins bytes). |
| Q-14 | minor | closed | Line 375 (every `copy_into_workarea` caller is in scope). |
| Q-15 | minor | closed | LLR-156.4 line 759 (always present, `none` when empty; golden rebaseline named for Inc 8). |
| Q-16 | minor | closed (D8 part is new finding Q-20) | Line 419 (REPORT block in the AT fixture); line 401 (D9 TC-only, with reason). |
| Q-17 | minor | closed | Lines 378-379; LLR-155.7 line 709. |

### New findings (changed blocks only)

| ID | Severity | Req | What | Recommendation |
|----|----------|-----|------|----------------|
| Q-18 | minor | LLR-156.1 / TC-B99-17 | The *Executed verification* still says "(the 7-case matrix)" (line 731), but HLR-156's threshold is now an 8-case matrix (line 415). | Say 8. |
| Q-19 | minor | IFC Part B, `patch_bytes_input` | Names the id `patch_entry_bytes` and the address `query("#patch_entry_bytes")`. The shipped id is `patch_entry_bytes_input` (`screens_directionb.py:4941`), so a C-26 reverse census keyed on the declared id matches only by substring. | Use the real id. |
| Q-20 | minor | HLR-160 D8 clause | The ledger says the D8/D9 clauses are "TC-only with reasons", but HLR-160 gives no reason for D8. D8 *is* drivable: export twice from `SegmentSplitView`, read the status, list the destination. | Add a second-export arm to AT-B99-11 (status names `<name>_1`, both files intact), or state why it is TC-only. |
| Q-21 | minor | LLR-155.7 / TC-B99-39 | "Every `unlink`/`rmtree`/`os.remove` shall target a path held by an ownership flag the same call set" (line 709) is a semantic property. The AST census needs a decidable predicate. | Define it, e.g.: the deleted expression is a name bound in the same function from the `mkdtemp` / `O_EXCL` result, and the delete is guarded by a boolean assigned right after that creation. Pin the RED site `apply.py:776-778` (`finally: staged.unlink()`). |
| Q-22 | minor | §6.3 (informative) | The *Atomic writes* bullet still says "Staging files are created exclusively under `<workarea>/temp/` with generated names". HLR-155 / LLR-155.1 now say a private `mkdtemp` directory under `temp/.staging/` holding the *requested* name. | Align the text so security reviewers read the current design. |

### Census delta (best-effort + gate-confirmed)

This adds to the round-1 census, for symbols the amendment newly touches (inspection-executed (qa-reviewer), `grep -rl <symbol> tests --include=*.py`):
- `build_range_validity_s19` (LLR-153.2): `test_render_hexview`, `test_tui_directionb`, `test_tui_hexview`. Validity maps of S0-bearing fixtures lose the S0 keys.
- `get_record_for_address`, `_build_overlap_map` (LLR-153.1): 0 direct test refs; observed through callers.
- `before_bytes` (LLR-157.4): `test_before_after_report` (+ goldens `batch35/at054b-before-after-report.{md,html}`, C-24), `test_changes_apply`, `test_changes_linkage`, `test_changes_symbol_entries`, `test_diff_report_service`, `test_report_addendum_bound`, `test_report_document_bound`, `test_report_length_cell`, `test_report_producer_bound`, `test_report_service`, `test_report_symbol_escape`, `test_tui_report_attribution`. Only repeated-apply scenarios change. The batch35 goldens drift only if their fixture applies twice; the gate confirms.
- `refresh_files` (LLR-162.1/162.3): `test_loadfilescreen_input`, `test_tui_app`, `test_tui_diff_screen`, `test_tui_directionb` (key-binding rows survive; list-content assertions change).
- Every `copy_into_workarea` caller is now in scope (Q-14 closed). The round-1 temp-path observers become certain re-pins: `b97_fixtures.staging_block` → `test_b97_chips_help:967, 2322`; `test_manifest_writer:406`; `test_unified_write:396, 465`; `test_tui_crc_surface:577`.
- Golden `batch71/ac6-unscoped-flow-report.md`: a certain drift, rebaselined in Inc 8 (LLR-156.4).

### Two-layer review (per story), round 2

| Story | HLR | (a) AT present | (b) deliverable + method named | (c) both chains | (d) black-box pure / drivable | Status |
|---|---|---|---|---|---|---|
| US-141 | 152 | AT-B99-01 | yes | yes (TC 01..03) | yes (CLI) | ✓ |
| US-142 | 153 | AT-B99-02 | yes | yes (TC 04..07) | yes: one applied in-image entry (P-23) | ✓ |
| US-143 | 154 | AT-B99-03 | yes (notice codes) | yes (TC 08..10) | yes (`#fx_run`) | ✓ |
| US-144 | 155 | AT-B99-04, -05 | yes | yes (TC 11..16, 39; 38 via LLR-155.8) | yes; RED arm correctly pinned | ✓ |
| US-145 | 156 | AT-B99-06, -07 | yes (REPORT block named) | yes (TC 17..20) | yes | ✓ |
| US-146 | 157 | AT-B99-08 | yes | yes (TC 21, 22, 37, 40) | yes | ✓ (LLR-157.3 threshold, Q-5) |
| US-147 | 158 | AT-B99-09 (decode) | decode yes; the encode deliverable that the story promises is TC-only | yes (TC 23..25) | the AT is black-box, but it observes a different outcome than its story states (Q-1) | **blocker until US-147 is restated** |
| US-148 | 159 | AT-B99-10 | yes ("writes nothing" now consistent) | yes (TC 26, 27) | yes | ✓ |
| US-149 | 160 | AT-B99-11 | yes | yes (TC 28..31, 41) | yes (D8 arm missing, Q-20) | ✓ |
| US-150 | 161 | AT-B99-12 | yes | yes (TC 32, 33) | yes | ✓ |
| US-151 | 162 | AT-B99-13 | yes | yes (TC 34..36) | yes | ✓ |

TC-B99-01..41 are all assigned (LLR-159.3 retired; TC-B99-38 kept under LLR-155.8). AT-B99-01..13 are all referenced. 0 orphans.

### Evidence checklist (round 2 deltas)

| Item | ✓/✗ | Evidence |
|---|---|---|
| Test cases have explicit Expected | ✗ | LLR-157.3's predicate disagrees with its allow-list at HEAD (Q-5); LLR-158.3's in-range refusal arm cannot be built (Q-6) |
| Edge cases include empty, boundary, invalid, error | ✓ | Q-9 and Q-11 closed (lines 369, 528); HLR-160 boundary now 100 / 101 characters |
| Exit criteria stated | ✓ | §5.1 and §5.2 amended; baseline file still being written (`not-run` from this reviewer's view) |
| Layer B: deliverable observed through the shipped surface | ✗ | US-147 story still promises an encode deliverable (lines 118, 209) that AT-B99-09 does not observe (Q-1) |
| Bidirectional surface-reachability | ✗ | same: the US-147 input dimension (typed physical value) is unreachable (P-22); the other stories ✓ |
| No unfilled template | ✓ | 41 TC ids and 13 AT ids assigned; no `<...>` |
| Mode declared · plan results `planned` · no PII | ✓ | unchanged from round 1 |
