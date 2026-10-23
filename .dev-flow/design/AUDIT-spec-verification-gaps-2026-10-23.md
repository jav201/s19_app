# Audit — why the integrity and project round-trip defects escaped requirements and verification (2026-10-23)

**Mode:** validation-of-claim, read-only process audit (qa-reviewer). Nothing was edited except this file. Nothing was run except `grep`, `sed` and `git log`/`git show`/`git status`. **No pytest run was made or consumed.** Every row below is `inspection` (code and document reading), never `executed`.
**Tree:** `main` @ `9793fcd` plus the live working tree. `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl` and the cited non-b97 tests are unmodified against HEAD (`git status --short`). Batch-97 files and `tests/test_b97_*.py` carry uncommitted edits by another agent, so their line numbers are the live tree's.
**Claim under test:** "the defects found by the two investigations must have been missing from the requirements or the test cases; the SE documentation and verification stages are not complete or properly defined."
**Inputs read:** `design/INVESTIGATION-read-write-integrity-2026-10-22.md` (I-H/I-M below), `design/INVESTIGATION-project-roundtrip-2026-10-23.md` (P-H/P-M below), `BACKLOG-CODE.md:1413-1440`, `REQUIREMENTS.md` (the living canon), `AT-TC-REGISTRY.jsonl`, the batch folders cited per row, `.fast-dev-flow/archive/2026-07-14-batch44-flow-builder-spec.md`, and the cited tests. The flow under audit: `~/.claude/skills/dev-flow/` (`stations/p1-requirements.md`, `p2-review.md`, `p4-validation.md`, `shared-controls.md`, `shared-evidence.md`, `commands/dev-flow.md`, `templates/req-template.md`, `templates/guides/req-template.part2.md`, `templates/guides/increment-template.md`, `templates/close-template.md`) and `~/.claude/skills/dev-flow-lessons/SKILL.md`.

---

## 1. Summary verdict

**The claim is CONFIRMED, with one correction: the defects were mostly in the requirements, not in the test cases.** Of 15 HIGH findings, 12 trace to a requirement that was never written (3) or was written without the failure, fidelity or isolation clause that would have demanded the behaviour (9). **No HIGH is a plain "requirement exists, test missing" escape.** Where tests did exist, they could not fail. One test checks against the project's own reader, which shares the defect (H-1). Others run on fixtures that cannot show it: the one S0-less example, tag-level instead of module-level byte order, parallel lanes with distinct output names (H-1, H-3, H-5, H-6). TC-714 pins the defective behaviour (H-2).
**Project side:** the defect behind I-H-1 was **seen and ratified** in batch-14. Amendment B narrowed the oracle and called it "reader behaviour, out of emitter scope", and nothing was routed to the backlog. Batch-95 closed with 17 validator blocks. Its 9 black-box ATs were never minted, and 7 increments ran without packets. The flow forbids each of these. Batch-96 shipped without a batch record.
**Flow side:** the flow never asks a requirement to state what is reported when an operation only partly succeeds. It also does not require a save/load feature to declare which state it persists and restores. Further gaps:
- No requirement class for concurrency or shared resources.
- No "representative real input" boundary class.
- The flow's own reader-as-oracle lesson prescribes round-tripping through the project's existing reader, which is the circular check that hid H-1.

---

## 2. Per-finding classification

Escape classes:
1. no requirement
2. requirement exists but is ambiguous or incomplete
3. requirement exists, no test
4. test is vacuous or pins the wrong behaviour
5. test ran on a fixture that cannot reveal the defect
6. regression after a later change

A row may name one primary class and contributing classes.

### 2.1 Integrity investigation — HIGH

| ID | Governing requirement (file:line) | Tests that cover the behaviour (file:line) | Class | Evidence |
|---|---|---|---|---|
| **I-H-1** S0 bytes become data at `0x0` | `R-S19-S0HEADER-001` `REQUIREMENTS.md:3212-3245`; batch-14 LLR-015.2 + **Amendment B** `.dev-flow/2026-06-23-batch-14/01-requirements.md:393-405`; `LLR-122.1` `REQUIREMENTS.md:6246` ("parse S0–S9 … and the memory map"; it does not say which record types feed the map) | `test_tc215_…` `tests/test_changes_apply.py:683`, `test_saveback_width_32_preserves_source_s0_header` `tests/test_tui_patch_editor_v2.py:1211` (assert on a `_data_record_map`, S1/S2/S3 only); `test_emit_s19_roundtrips_public_example_file` `tests/test_changes_apply.py:303-314` | **4** (+5, +1) | Batch-14 found the defect. Amendment B (`01-requirements.md:396`) records that `get_memory_map` "folds every record's data … including the S0 header at address 0". The threshold was then rewritten to "the re-parsed **data-record map**" (`:400`), and the canon calls the S0 "cosmetic … sits at low addresses that never collide" (`REQUIREMENTS.md:3240-3242`). The postmortem lists this as a success (`05-postmortem.md:15,24`), and `BACKLOG-CODE.md` has no S0-as-data item before 2026-10-23. Contributing class 5: the public round-trip test uses `examples/case_00_public/prg.s19` (`tests/test_changes_apply.py:42-44`), which the investigation identifies as the only one of 16 S19 examples without an S0. Its oracle is the same `S19File` reader, so it cannot see the bytes even on an S0 file. |
| **I-H-2** PATCH block always `ok` | `R-TUI-059` `REQUIREMENTS.md:4169-4197` ("collect-don't-abort … never raises"; no PATCH status rule); batch-44 spec `.fast-dev-flow/archive/2026-07-14-batch44-flow-builder-spec.md:21-24` (AC-1 happy path, AC-2 missing source only); batch-51 `LLR-085.2` / `LLR-086.4` `.dev-flow/2026-07-20-batch-51/01-requirements.md:449-466, 519-548` (add `notices` for SOURCE and CHECK only, never PATCH) | `test_tc714_no_declared_ref_refuses_symbol_entries_no_implicit_a2l` `tests/test_changes_symbol_entries.py:768-795` | **2** (+4) | No requirement maps a `skipped-*`/`blocked` disposition, or a refused document, to a block status. The engine's own requirement `R-CHG-002` (`REQUIREMENTS.md:1797-1812`) defines all five dispositions, so the information existed. TC-714 asserts `patch.summary == "applied 0 entries"` and reads `result.written_paths[0]`. It requires WRITE-OUT to run after a refused patch, a behaviour no requirement mandates (class 4). Batch-44 ran under the retired fast-dev-flow, with no P2 review of requirements. |
| **I-H-3** parallel lanes overwrite each other | `HLR-019` / `LLR-019.2` `.dev-flow/2026-10-12-batch-94/01-requirements.md:974-981` ("isolate a chain's **failure** to its own lane"); staging is unspecified for `save_patched_image`, and `R-MAN-WRITE-001` `REQUIREMENTS.md:2612-2625` prescribes staging in the shared `workarea/temp/` | `test_tc_b94_05_parallel_dispatch_runs_chains_concurrently` `tests/test_flow_chainset_b94.py:132`; `test_at_b94_21_…` `tests/test_tui_flow_execution_b94.py:620`; `test_at_b97_22_parallel_rebind_runs_each_lane_on_its_own_image` `tests/test_b97_flow_execution.py:2243-2280` | **6** (+2, +5) | The `temp/<name>` staging dates from batch-07 (`git log -S temp -- s19_app/tui/changes/apply.py` → `3e00739`, 2026-06-10) and was safe while there was one writer. Batch-94 added concurrency over it. LLR-019.2's threshold measures overlapping time windows and failure isolation, not output isolation, and its boundary catalog has no shared-output arm. Batch-96 B8 (`bd42d8d`) added the check-then-reuse in `copy_into_workarea`. Every parallel test writes **distinct** output names (`fw_app_patched.s19` vs `fw_b.s19`, `tests/test_b97_flow_execution.py:2266-2267`), so the collision the investigation reproduces (same template imported twice) is never exercised. |
| **I-H-4** undo does not revert the image | `R-TUI-057` `REQUIREMENTS.md:4095-4112` (undo replaces the **document** only; it says nothing about bytes already applied to the image) | `test_tc339_…` `tests/test_change_service.py:692`; `test_at068a_undo_redo_roundtrip_through_surface` `tests/test_tui_patch_editor_v2.py:3570` (entries field-for-field; no apply→undo→save→read-back) | **2** | The requirement defines undo over the change set and is silent on the image. No AT chains apply → undo → apply → save → re-read. The save verify (`R-HEX-VERIFY-001` `REQUIREMENTS.md:2469-2479`) compares against the same mutated map, so it cannot see the defect either. |
| **I-H-5** big-endian encode written little-endian | `REQUIREMENTS.md:179-184` (byte-order precedence: tag → layout → tag fallback → **default little-endian**; `MOD_COMMON BYTE_ORDER` absent); `LLR-141.1` `.dev-flow/2026-10-13-batch-95/01-requirements.md:655-660` ("encode round-trips the shipped decode (0 diffs)") | `test_tc712_physical_raw_encode_roundtrips_shipped_decode` `tests/test_changes_symbol_entries.py:317-350` | **2** (+5) | The canon's precedence list itself omits the module default, so a correct implementation of that text has the defect. TC-712's big-endian arm puts `BYTE_ORDER MSB_FIRST` **on the tag** (`tests/test_changes_symbol_entries.py:219-223`), a form the code honours. All 10 real example A2Ls use `MOD_COMMON BYTE_ORDER MSB_FIRST` (`grep -rln` over `examples/`). The test packs with the tag's `effective_byte_order` (`:336-338`), so it uses the implementation's resolution as its own oracle. The round-trip partner (decode) shares the fallback, which is backlog H-7. |
| **I-H-6** COMPU_TAB inversion silently writes another value | `LLR-141.1` (as above; its boundary catalog names only "a value outside the tag's limits", `:660`) | `test_tc712_physical_raw_encode_roundtrips_shipped_decode` `tests/test_changes_symbol_entries.py:331` (`("TabVal", 2)  # TAB_NOINTP exact reverse`) | **5** (+2) | The test runs raw → physical → raw from a seed **in** the table, so it never asks for a physical value the table cannot represent. The user enters physical values, so the arm runs in the opposite direction from the user's. The LLR's "round-trips the decode (0 diffs)" clause would have caught the defect if checked from the physical side, but no input class names that side. |
| **I-H-7** CRC over an empty region injects `00000000` | `R-CRC-ENGINE-001` `REQUIREMENTS.md:2731-2741` (silent on zero present bytes); `R-CRC-GROUP-001` `REQUIREMENTS.md:2869-2879` ("gap-coverage … legacy regions **stay silent**") | `test_gap_splits_segments_no_inserted_bytes` `tests/test_crc_engine.py:66` (not found after searching `tests/test_crc_*.py`: any zero-coverage arm) | **2** | The requirement mandates silence for legacy regions and never names the empty region. |
| **I-H-8** truncated S19/HEX load as `ok` | none. `R-READ-001`, `R-PARSE-001..005`, `R-VAL-001..002`, `R-HEX-001..003` (`REQUIREMENTS.md:59-140`) cover per-record syntax only. The only EOF requirement is on the **emitter** (`R-HEX-EMIT-001` `:2420-2428`) | none. Not found after `grep -i "eof\|terminator\|truncat\|S5"` over `tests/test_hexfile.py`, `tests/test_core*.py`, `tests/test_load*.py` | **1** | File-level validity (terminator, EOF, S5 count, data after end) was never specified. These reader requirements predate the flow, and the reader is engine-frozen (`CLAUDE.md:58`). |
| **I-H-9** A2L segment name writes outside the work area | `HLR-137` / `LLR-137.4` (extractor admits any quoted name) `.dev-flow/2026-10-13-batch-95/01-requirements.md:276, 552-555`; `LLR-136.5` naming `:503-510`, **`Boundary catalog: none`** | AT-297 (export bytes) is **RESERVED, never minted** (`AT-TC-REGISTRY.jsonl`, `reserved_by: batch-95`) | **2** (+3) | No containment or sanitising clause on a file name built from file-derived text. Security review was "not run — core; family C did not fire" (`.dev-flow/2026-10-13-batch-95/02-review.md:122-128`). That decision rested on the judgement "file writes confined to the change-1 homes", with no probe. |
| **I-H-10** no record shows what was not applied | batch-60 `LLR-001.1/.2` `.dev-flow/2026-07-24-batch-60/01-requirements.md:61-77` (report sections, with no non-applied or refusal section; status mirrors the run's); `LLR-020.2` `.dev-flow/2026-10-12-batch-94/01-requirements.md:991-998` (chain-set report = **inputs only**); AT-304 statement "names every **applied** change" (`AT-TC-REGISTRY.jsonl`) | AT-304 **RESERVED, never minted** | **2** (+3) | Each report requirement lists what to show and none asks for the complement. Even the AT that was written scopes itself to "applied". |

### 2.2 Project round-trip investigation — HIGH

| ID | Governing requirement | Tests | Class | Evidence |
|---|---|---|---|---|
| **P-H-1** Save project saves the file, not the patched image | `R-TUI-012` `REQUIREMENTS.md:1244-1245` ("Saving a project must **copy the loaded file**"); `R-PROJ-001` `:1286-1287`; `R-MAN-SER-001` `:2575-2589` (the manifest round-trips **itself** against its reader, which is what "manifest verified" means) | `test_save_project_creates_project_folder_on_disk` `tests/test_tui_evidence_packs.py:87`; `test_project_save_writes_and_verifies_manifest` `tests/test_tui_manifest_save.py:94` | **2** | The requirement prescribes copying the file. No clause states that the project equals the session, or that unsaved edits are refused or named. The status "manifest verified" honestly reports a narrow check that a user reads as a wide one. |
| **P-H-2** loading P2 over P1 leaks A2L, MAC and change doc | `R-TUI-013` `REQUIREMENTS.md:1258-1266` (Validation **Partial**: "still verify loading a selected project manually"); `R-RPT-REGION-PERSIST-002` `:3535` ("so a prior project's regions never leak", **for declared regions only**) | `test_load_seed_guard` `tests/test_tui_report_seam.py:958` (regions only) | **2** | The isolation concern was recognised once, for one field, and not generalised to the session. |
| **P-H-3** same-name save-back deletes the work copy; next save crashes | none for staging isolation. `R-CHG-003` `REQUIREMENTS.md:1870-1881` (persist under a sanitised name, contained); `R-TUI-012` has no failure clause | none (not found: a save-back named like the loaded file followed by Save project) | **1** | No requirement says a write may not overwrite or delete a file the session holds. The crash path (`FileNotFoundError` outside the caught `WorkareaContainmentError`) has no unwanted-behaviour requirement. Only manifest-write refusal has a no-crash test (`tests/test_tui_manifest_save.py:214`). |
| **P-H-4** after a save-back into a project, Load opens the original | none for the active variant after a save-back. `R-CHG-003` (destination), `R-PROJ-002` `REQUIREMENTS.md:1295-1301` (Validation **Manual**) | `test_load_project_honors_manifest_active_variant` `tests/test_variant_execution.py:173` (honours the manifest; never after a save-back) | **1** | What a save-back into an open project means was never decided. The investigation marks it "decide in P1". |
| **P-H-5** Load reports success over a corrupt manifest, an empty image or drift | `R-VAR-002` `REQUIREMENTS.md:2032-2046` (the reader collects issues); `R-TUI-013` (no unwanted-behaviour clause); `R-MAN-SER-001` (no per-file digest) | `test_load_project_unknown_active_variant_falls_back` `tests/test_variant_execution.py:207` (the one loud case) | **2** | The reader's issues exist, but no requirement makes Load surface them, and no requirement stores a digest to detect drift. |

### 2.3 MEDIUM rows (classified where cheap)

| ID | Governing requirement | Tests | Class | Evidence (one line) |
|---|---|---|---|---|
| I-M-1 terminator entry point → 0 | `LLR-122.1` `REQUIREMENTS.md:6246`, `R-CHG-003` | map-equality round-trips only | 2 | "Round-trip" is defined on the memory map, so record-level fidelity (the terminator address) is outside every oracle. |
| I-M-2 overlaps last-wins silently | `LLR-122.1` (overlap *detection* exists) | none on flow SOURCE | 2 | Detection is specified; surfacing it in the flow is not. |
| I-M-3 a lossy load still writes | `LLR-085.2` batch-51 `01-requirements.md:449-461` ("every downstream block ran") | `…load_integrity_notices` | 2 | The requirement **mandates** the defect: notices, then WRITE-OUT. |
| I-M-4 flow WRITE-OUT never verifies | none for the flow writer (`R-HEX-VERIFY-001` covers save-back only) | none | 1 | Verify-on-save was not carried to the second writer. |
| I-M-5 a re-run leaves stale output | none | none | 1 | — |
| I-M-6 CHECK passes vacuously | `LLR-086.4/.5` batch-51 `01-requirements.md:519-560` (unreadable doc only) | `…check_never_aborts_chain` | 2 | `uncheckable > 0` and `kind != check` are not in the truth table. |
| I-M-7 HEX row crosses 64 KiB without ELA | `R-HEX-EMIT-001` `REQUIREMENTS.md:2420-2428` (ELA "whenever the active upper-16 of the **next data address** changes") | `test_ela_record_emitted_per_upper16_change` | 2 (+5) | The wording keys on the start of a record, not a crossing inside it. The round-trip oracle reads linearly. |
| I-M-8 type-02 offsets not wrapped | `R-HEX-002` `REQUIREMENTS.md:128-133` | `test_hex_extended_segment_address` `tests/test_hexfile.py:33-45` | 5 | The fixture is a 1-byte record at offset `0x0020`, far from the wrap. |
| I-M-9 duplicate JSON keys last-wins | none | none | 1 | — |
| I-M-10 variant execution `ok` regardless | `R-VAR-002` `REQUIREMENTS.md:2032-2046` (one summary per variant; no status rule) | `test_failing_variant_never_aborts_the_rest` | 2 | Same gap as I-H-2 on the variant path. |
| P-M-1 dedup compares only the bare name | none. Batch-96 B8 `bd42d8d` has no `.dev-flow` record | `tests/test_copy_into_workarea_content_dedup.py` (B8's own) | 1 | The commit message says "the pre-existing helper test that encoded the bug adjusted", so a test was changed without a requirement. |
| P-M-2 gathered change doc not reopened | `HLR-138` batch-95 `01-requirements.md:289-303` (save side only; AT-299 "self-contained snapshot") | AT-299 **RESERVED, never minted** | 2 (+3) | The save is specified and the load is not. |
| P-M-3 "save as" drops sub-folders | none | none | 1 | — |
| P-M-4 names that sanitise alike merge | `R-TUI-012` | `test_sanitize_project_name_*` | 2 | Sanitising is specified; collision is not. |
| P-M-5 project outside the work area cannot be loaded | `R-TUI-013` (lists work-area children only) | `test_list_projects_*` | 2 | Save and Load have no shared root requirement. The batch that added the Browse parent picker was not traced. |
| P-M-6 A2L-only project saved but not loadable | `R-VAR-001` `REQUIREMENTS.md:2004` (a project = N ≥ 1 S19/HEX) vs `R-PROJ-001` (Save) | none | 2 | Load enforces the definition; Save has no unwanted-behaviour clause. |
| P-M-7 300-char name crashes Save | `R-TUI-012` | none | 1 | No failure behaviour specified for Save. |

---

## 3. Counts per escape class

| Class | HIGH primary (15) | MEDIUM primary (17) | Contributing (any severity) |
|---|---|---|---|
| 1 no requirement | **3** (I-H-8, P-H-3, P-H-4) | 6 | 1 (I-H-1) |
| 2 requirement incomplete/ambiguous | **9** (I-H-2, -4, -5, -7, -9, -10; P-H-1, -2, -5) | 10 | 2 (I-H-3, I-H-6) |
| 3 requirement, no test | **0** | 0 | 3 (I-H-9, I-H-10, P-M-2: ATs RESERVED and never minted) |
| 4 vacuous / pins the wrong behaviour | **1** (I-H-1) | 0 | 1 (I-H-2, TC-714) |
| 5 fixture cannot reveal | **1** (I-H-6) | 1 | 4 (I-H-1, I-H-3, I-H-5, I-M-7) |
| 6 regression after a later change | **1** (I-H-3) | 0 | 0 |

**Reading:** 12 of 15 HIGHs (80 %) escaped at **requirements** (classes 1 + 2). The 3 others, plus 6 contributing tags, are verification defects of one kind: a test existed and could not fail. A missing test (class 3) is never the primary cause.

---

## 4. Process gaps, ranked

Each gap names the findings it explains, the evidence, and who owns the miss: **project-side** (the flow demands it and the project skipped it) or **flow-side** (the flow does not demand it). Each ends with a concrete control.

### G1 — Requirements do not have to state the outcome and the report for partial success or refusal (honesty)
**Explains:** I-H-2, I-H-7, I-H-10, I-M-3, I-M-6, I-M-10, P-H-1, P-H-5, P-M-6 (9 rows, 5 of them HIGH).
**Evidence:**
- R-CHG-002 defines five dispositions (`REQUIREMENTS.md:1797-1812`), yet no block, report or variant requirement says what status each disposition produces.
- Batch-51 defined `notices` for SOURCE and CHECK and never for PATCH (`batch-51/01-requirements.md:449-548`).
- Batch-60's report requirement lists sections with no "not applied" section (`batch-60/01-requirements.md:61-77`).
- AT-304 itself says "every **applied** change".

**Flow-side:**
- The EARS *Unwanted behavior* pattern is one optional pattern among six (`templates/guides/req-template.part2.md:128`).
- The boundary catalog's `error` class asks for an error **input** arm (`templates/req-template.md:109`), not the **reported outcome**.
- P1's deliverable rule asks for "file at path + non-empty + required content" (`stations/p1-requirements.md:24`), which an output with silently missing content passes.
- C-36's truth-table rider (`p1-requirements.md:43`) fires only when an AT keys on a multi-axis decision. Nothing forces the status mapping to be written as one.

**Project-side:** batch-44 ran under fast-dev-flow with two ACs (happy path, missing source; `.fast-dev-flow/archive/2026-07-14-batch44-flow-builder-spec.md:21-24`).
**Control:**
- **Template (flow):** add an `Outcome honesty` field, mandatory on every requirement whose operation can partly succeed. It is a truth table: {all applied · some · none · input refused · input unparseable} × {status token · what the record/report names · whether downstream writes proceed}. P2 blocker if absent.
- **Validation (flow):** Layer B owes one AT per non-success row that observes the **report** (not only the image).
- **Project:** re-specify PATCH, CRC, CHECK, variant execution, flow report and chain-set report status as one truth table before fixing H-2/H-10.

### G2 — Self-referential oracles: writers are verified with the project's own reader, which is frozen and never independently validated
**Explains:** I-H-1 (and why verify-on-save, A2B and diffs are blind to it), I-H-4 (verify compares against the mutated map), I-H-5 (TC-712 uses the implementation's `effective_byte_order`), I-M-7.
**Evidence:**
- Batch-14 recorded the defect and rewrote the threshold to the data-record map, calling the rest "reader behavior, out of emitter scope" (`batch-14/01-requirements.md:396-405`).
- The canon still says the S0 bytes "never collide" (`REQUIREMENTS.md:3240-3242`).
- `R-HEX-VERIFY-001` diffs the re-read against the "intended" map from the same loader (`REQUIREMENTS.md:2469-2479`).
- The project freezes `core.py` and `hexfile.py` as "reader/oracle only" (`CLAUDE.md:58`; `REQUIREMENTS.md:2416-2418`). They cannot be edited, and no batch ever validated them against an external reference.

**Flow-side:**
- `dev-flow-lessons` *reader-as-oracle* prescribes "round-tripping its output through the **existing trusted reader**" (`dev-flow-lessons/SKILL.md:529-540`). Its negative control (corrupt bytes must be rejected) checks that the reader *rejects*, not that it *reads correctly*.
- C-40 limb 1 (`p1-requirements.md:45`) catches a predicate that is invariant under the change. It does not catch an oracle that **shares** the defect.

**Project-side:** an observed defect was ratified without a backlog route. P2's rule that anything outside the batch's classes is "NAMED in the review's findings table with the station that owns it" (`stations/p2-review.md:74`) was not applied at P3. The flow's Phase-3 amendment rule (`p3-implementation.md:103`) records the spec change but does not require routing the underlying defect.
**Control:**
- **Flow:** reader-as-oracle requires (a) the reader's own known-answer validation against an **independent** reference (spec-derived KAT files or an independent minimal parser), and (b) a declared "shared-defect blind spot" line naming what the oracle cannot see.
- **Flow:** any premise correction that reveals a defect in an out-of-scope or frozen module must be routed to the backlog with a severity in the same increment. "Out of scope" is never a disposition for a defect.
- **Project:** promote the investigation's independent `mini_s19`/`mini_hex` (`design/investigation-rw-2026-10-22/common.py`) to a test oracle, and add a frozen-module validation suite over `examples/**`.

### G3 — Persistence and round-trip obligations are scoped to a sub-artifact, never to the user's whole state
**Explains:** P-H-1, P-H-2, P-H-4, P-M-2, P-M-3, I-M-1, I-H-4.
**Evidence:**
- `R-TUI-012` "copy the loaded file" (`REQUIREMENTS.md:1244`).
- `R-MAN-SER-001` round-trips the manifest only (`:2575-2589`).
- `HLR-138`'s AT checks the saved tree and never reloads it.
- Every S19 round-trip compares memory maps only.

**Project-side:** the flow already demands an output-then-consume AT (C-12, `commands/dev-flow.md:79`; trigger B4, `stations/shared-controls.md:87`), which would have forced save → Load project → compare.
- Batch-95's only increment file is the unfilled template. Its B4 row still reads `<who reads the path/format written>` (`.dev-flow/2026-10-13-batch-95/03-increments/increment-001.md:154`), for 7 committed increments.
- AT-299 was never minted.
- `R-TUI-013` / `R-PROJ-002` stay at Validation `Partial` / `Manual` (`REQUIREMENTS.md:1263, 1301`).

**Flow-side:** C-12 asks that the consumer read the produced artifact. It does not require an **inventory** of the state a save must capture, nor that the restored state equal the saved state.
**Control:**
- **Template (flow):** a `Persistence inventory` table on any save/load/export requirement: state element × saved? × restored? × verified by. An element marked "not kept" must be named to the user at save time.
- **AT (flow):** save → load in a fresh process → state digest equal, plus one arm with unsaved in-memory edits.
- **Project:** move every `Manual`/`Partial` requirement on a data path (R-TUI-013, R-PROJ-002, R-TUI-016) to an automated AT.

### G4 — Fixtures are not representative of real inputs or of the direction the user works in
**Explains:** I-H-1 (round-trip on the only S0-less example), I-H-3 (parallel tests use distinct output names, while the intended use repeats one template), I-H-5 (tag-level byte order, while all 10 example A2Ls use `MOD_COMMON`), I-H-6 (raw → physical → raw seed in the table), I-M-8 (segment fixture at `0x0020`).
**Flow-side:**
- The boundary catalog's classes are `empty · boundary · invalid · error` (`templates/req-template.md:109, 127`), with no "representative (real corpus)" class and no "user's input direction" class.
- "Representative" appears only for Layer B ATs (`stations/p4-validation.md:96`).
- C-57 (`templates/guides/increment-template.md:83-87`) covers a fixture whose symmetry collapses a distinction, not a fixture that lacks the real-world feature.
- C-31 (`commands/dev-flow.md:80`) covers input sets for universals.

**Project-side:** the repo ships a real corpus (`examples/`, 16 S19 and 10 big-endian A2Ls), and no rule makes reader or writer tests sweep it.
**Control:**
- **Template (flow):** add `☐ representative — <named real-corpus file and the feature it carries>` and, for transforms, `☐ user direction — <the side the user enters>`. A unit-built fixture must state which real-world feature it omits.
- **Project:** a corpus-sweep test: every reader and writer over `examples/**`, checked by the independent oracle from G2.

### G5 — Batches closed with unrealised black-box ATs, without increment packets, or without a record at all (project skipped what the flow demands)
**Explains:** why I-H-9, I-H-10 and P-M-2 had no Layer B net, and why the B4/C-12 control never fired for project save.
**Evidence:**
- Batch-95 closed at `exit 1 · 17 block`, including `V2 ×9` (AT-296..304 have no node; `.dev-flow/2026-10-13-batch-95/05-close.md:16`), citing "the batch-93 precedent".
- The registry holds **30 AT + 45 TC RESERVED**, 22 of them batch-95's (`AT-TC-REGISTRY.jsonl`).
- Batch-95's 7 increments have no packets ("commit messages stand in for the unseeded packets — the batch-94 precedent", `05-close.md:225`).
- Batch-96 (B8 dedup, curve encode, external step) has **no `.dev-flow` folder** (`git log --grep=batch-96`).
- The data-path work of batches 30, 31, 34, 39-44, 61 and 67-69 lives only as fast-dev-flow specs (`.fast-dev-flow/archive/`), including batch-44's PATCH tracer.

**Flow demands it:**
- `templates/close-template.md:30` ("the exit code … and 0 block").
- `stations/p4-validation.md:96` (C-18: an AT satisfied only in parts is UNREALIZED and "blocks the gate") and `:101`.
- `stations/shared-evidence.md:45` (every `US → AT` chain GREEN).

**Flow-side residue:** nothing stops "precedent" from becoming a standing waiver.
**Control:**
- **Flow:** `V2` blocks at close with no precedent clause. A RESERVED id older than one closed batch fails CI. A batch with commits and no folder is a `V`-rule BLOCK on the next batch's P0.
- **Project:** mint or retire the 30 + 45 reserved ids before the integrity batch's P1.

### G6 — Concurrency, shared resources and new callers of old writers are no requirement class or trigger
**Explains:** I-H-3 (class 6), P-H-3, I-M-5, L-4.
**Evidence:**
- LLR-019.2 isolates "failure" only (`batch-94/01-requirements.md:977`).
- `R-MAN-WRITE-001` puts every stage in the shared `temp/` (`REQUIREMENTS.md:2612-2614`).
- Batch-94 never touched `save_patched_image`, so the symbol-keyed reverse census (C-26, `stations/p2-review.md:70`; B1, `shared-controls.md:84`) had nothing to fire on.

**Flow-side:** no family-A to family-F trigger fires on "introduces concurrency" or "adds a caller of an existing writer" (`stations/shared-controls.md:80-96`). The flow's only concurrency text is about concurrent **batches** (`shared-batch.md:45-49`).
**Control:**
- **Flow trigger** (e.g. A5): "the change adds concurrent execution, or a new call site of an existing writer". It turns on a **resource census** (every path, directory and state the concurrent path writes, and who else writes it) and an isolation AT with **colliding** inputs (same output name, same source).
- **Template:** writer requirements declare who owns their staging and target paths.

### G7 — State isolation on load/open/switch is not demanded
**Explains:** P-H-2, and the shape of P-H-4 and L-2.
**Evidence:** the canon recognised the leak once ("a prior project's regions never leak", `REQUIREMENTS.md:3535`) and never generalised it.
**Flow-side:** absent (`grep -i "isolation\|leak"` over the stations finds only process-level uses).
**Control:**
- **Template:** a load/open requirement declares the session state it resets.
- **AT:** load B after A equals a cold load of B, as a digest over the state inventory from G3.

### G8 — Legacy canon on data paths was never re-derived, though later batches build on it
**Explains:** I-H-8, I-M-9, and the shallowness behind P-H-1/P-H-2.
**Evidence:**
- Sections 1 and 7 of `REQUIREMENTS.md` hold one-line rules ("read line-by-line and ignore empty lines", `:59-60`; "copy the loaded file", `:1244`) with `Partial`/`Manual` validation.
- The reader is frozen as an oracle (G2), so no batch re-opened it.

**Flow-side:** no control re-baselines requirements written before the flow when a batch builds on them. C-26 re-validates **tests** that assert a touched symbol, not the parent requirement's adequacy.
**Control:**
- **Flow:** at P1, every requirement a new LLR *depends on* (not only those it amends) that has `Validation: Manual/Partial` or no boundary catalog is listed and either re-derived or declared a named risk.
- **Project:** a one-time canon audit of sections 1, 7, 11 and 17.

### G9 — A test that pins current behaviour is not checked against a requirement
**Explains:** I-H-2 (TC-714), I-H-1 (Amendment B oracle), P-M-1 (B8 "adjusted" a test that "encoded the bug").
**Flow-side:** C-40's corollary asks that a pin be **labelled** a pin (`stations/p1-requirements.md:46`), not that a failure-path assertion cite the clause that mandates it. TC-714 carries no such label.
**Control:**
- **Flow:** every assertion on a refusal, error or partial-outcome path cites its requirement clause. One that cannot cite a clause is labelled `PIN-unspecified` and routed to P1 as a requirement question.
- **Flow:** editing a test "that encoded the bug" requires a ledger entry.

### G10 — The security trigger does not cover filesystem paths built from file-derived text
**Explains:** I-H-9.
**Evidence:** batch-95 security review "not run" on judgement (`02-review.md:122-128`).
**Flow-side:** family C's input-surface keywords (`scripts/devflow-scan-spec.py:86`: user input, file upload, form, sanitize, escape, …) have no `path`, `filename`, `join` or `traversal`. C8 covers markup rendering only (`stations/shared-controls.md:92`).
**Project-side:** non-activation was judged without the executed probe that `shared-controls.md:78` (rule 4) requires.
**Control:**
- **Flow:** add C9, "a filesystem path or file name derived from loaded-file content". It mandates a containment LLR and a hostile-name AT (`../`, absolute, reserved device name, over-long).

### G11 — A premise can be marked TRUE on a matching outcome produced by a different cause
**Explains:** the misfiled P-31 premise. `batch-97/01-requirements.md:195` reads `✅ TRUE … outcome 2 error ['ok','error','skipped','skipped']`, while the integrity report §5 shows PATCH never returns `error` there. This delayed H-2.
**Flow-side:** C-43's TRUE means "sustained by an executed probe" (`stations/shared-evidence.md:51-60`). Nothing requires the probe to attribute the outcome to the claimed cause.
**Control:**
- **Flow:** a premise about a cause needs a discriminating counter-arm, where removing the claimed cause changes the outcome, recorded beside the TRUE.

### Ownership summary

| Gap | Project skipped what the flow demands | The flow does not demand it |
|---|---|---|
| G1 honesty | partly (batch-44 under fast-dev-flow) | **yes** |
| G2 self-oracle | **yes** (defect ratified, not routed) | **yes** (lesson prescribes the existing reader) |
| G3 persistence | **yes** (C-12/B4 unfilled; AT-299 unminted) | partly (no state inventory) |
| G4 fixtures | partly (corpus unused) | **yes** (no representative class) |
| G5 unrealised ATs / missing records | **yes** | partly (precedent waivers possible) |
| G6 concurrency | — | **yes** |
| G7 state isolation | — | **yes** |
| G8 legacy canon | partly | **yes** |
| G9 pins | partly | **yes** |
| G10 path security | partly (judged without a probe) | **yes** |
| G11 premise cause | — | **yes** |

---

## 5. What could not be checked

- **No execution.** A full pytest suite was running in this tree. No test, probe or validator was run, so every class assignment is `inspection`. The investigations' probes were not re-run; their `executed` results are consumed as reported, executed by the security-reviewer (2026-10-22) and the qa-reviewer (2026-10-23).
- **Vault-held records.** The PDR and DDR records and the post-mortems that live in the vault (`artifact_homes.design_pdr`) were not read. A design decision recorded only there may qualify a class-2 row.
- **Batches without a `.dev-flow` folder.** Batches 30, 31, 34, 39-44, 61 and 67-69 (fast-dev-flow archive specs only; only batch-44's spec was read) and batch-96 (no record). Batches 45-90 were searched by `grep`, not read in full.
- **I-H-3 timeline.** Read from `git log -S` on two strings. Whether the batch-94 increment that introduced parallel dispatch ran a reverse census over `save_patched_image` was not confirmed: batch-94 increment packets 001-004 were not opened.
- **P-M-5 origin.** The batch that added the Save dialog's Browse parent picker was not traced, so a class-6 reading is possible and unverified.
- **Live-tree drift.** Batch-97 requirement files and `tests/test_b97_*.py` carry another agent's uncommitted edits. Citations into them (`batch-97/01-requirements.md:195`, `tests/test_b97_flow_execution.py:2243-2280`) are live-tree lines and may move.
- **Low-severity rows.** I-L-1..7 and P-L-1..4 were not classified.
