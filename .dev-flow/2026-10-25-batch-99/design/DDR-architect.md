# DDR — architect — s19_app — Batch 2026-10-25-batch-99

> Detailed Design Review, architect lens (`stations/p4-validation.md` §DDR). Staged here. Its canonical home is the vault (`artifact_homes.design_ddr`), and `/dev-flow-sync` publishes it.

| Field | Value |
|---|---|
| Reviewed | as-built `307065f..e7732f6` (`git diff -- s19_app/`, 18 product files) against `design/design-proposal-b99.md`, `design/PDR-2026-10-25-batch-99.md` and its reviewer files (`PDR-architect.md`, `PDR-qa.md`, `PDR-ux.md`), `docs/architecture.md` §10/§11 batch-99 rows B99-I1..I12 + I2a, packets `03-increments/increment-*.md` §1/§6, ledger LED .1–.7 |
| Method | Re-read code and tests for every condition at `e7732f6`. Measured interfaces, consumers and import edges with `git grep` at both `307065f` and `e7732f6`. No test executed by this lens. The full suite runs elsewhere (`evidence/suite-full-e7732f6.txt`, still in progress when this was read). |
| **Verdict** | **approved with conditions** |

## BLUF

The as-built design matches the PDR. The deviations have a declared reason, and none moves a boundary. Every engine crossing stays inside the LLRs that name it. `segment_ops` gains no import (the file is untouched). Code and tests discharge every PDR condition on C1–C6, PQ-1..PQ-8 and UX-C1..UX-C11. Two items are still open, and both are documentation only:

- **C7** was marked ✓ in the PDR record, but only half of it was applied. The PLAN and the map still show the pre-PDR file sets and the "candidate" edge.
- **C3(f)**: the map half is undone. ARCH B99-I2a still lists `segment_ops.write_bin_with_sidecar` as a consumer.

The map in `docs/architecture.md` is also still at its ARQ text ("declared at ARQ, nothing landed"). It must record the drift listed in §3. These conditions do not send the batch back to design. They are owed by the orchestrator in the map update before batch close (P6 docs).

## 1 · What changed against the PDR, and why

| Item | PDR / proposal said | As built | Why (source) | Architect read |
|---|---|---|---|---|
| Inc 3 cut | one Inc 3 | 3a (`apply.py`, `workspace.py`, `app.py`, `changes/io.py`) + 3b (`flow_execution_service.py`, `project_gather_service.py`, `app.py`) | PDR C7 split. LED .7 moved the `project_gather_service.py:290-299` delete-and-recopy into 3b. 3b review F2 added the `app.py` status paint | sound: LED .7 replaces a window argument that could not hold with an immutability invariant |
| LLR-155.3 basis | "narrower window" | immutability invariant: no in-app path replaces or deletes a placed final name. The gather violator is converted (`project_gather_service.py:364` now places through `copy_into_workarea`) | LED .7 (Inc-3a review F2) | sound. The invariant is pinned by `test_tc_b99_13_no_final_name_replace_outside_placement` (`tests/test_b99_staging.py:1975`) with an allow-list at `:1866` |
| Inc 4 files | `change_service.py` only ("no `app.py` change", ARCH §10 Inc-4) | + `app.py` (final save-back status) | UX-C6 allowed `app.py` against Inc 4 (`PDR-ux.md` UX-C6) | declared. The map row is stale |
| Inc 5 files | `crc.py`, `flow_execution_service.py` | + `flow_screens.py` (`_crc_absent_note`, `flow_screens.py:3353`) | the HLR-159 lane rider follows the UX-C1 pattern | declared in the packet. The map row is stale |
| Inc 6 files | `segment_split_view.py`, `segment_ops.py`, `workspace.py` | `segment_split_view.py`, `workspace.py`. **`segment_ops.py` untouched** | PDR C3(f): bytes come from `emit_bin_from_mem_map` / `bin_addr_sidecar` (`segment_split_view.py:780-781`), and the view writes them into the private staging dir | sound: a stricter boundary than the proposal's "segment_ops writes into the staging dir" |
| Inc 9 files | `core.py`, `hexfile.py`, `flow_execution_service.py` (if D6 ≠ notice) | + `app.py` (interactive load status, `app.py:11239`) | D6 = `flujo_para`, and UX-C7 folded into HLR-154 (LED .5) | declared |
| Inc 10 files | `a2l.py` (+ `change_service.py` only if D4 = flag) | `a2l.py` + `app.py` (the `n/a` cell, `app.py:12762`). No `change_service.py` | UX-C8; C7 bullet 3 (encoder flags already become WARNING issues) | declared |
| S6 parsing | not in the proposal | `SRecord` now parses S6 (`core.py`, address-length table) | LLR-154.1's S6-count arm needs it (Inc 9 §6) | inside the named crossing |
| B99-I2a signature | PDR C3(a) recommended bytes in. The proposal chose paths in | `place_group_into_workarea(sources: Sequence[Path], destination: Path, *, max_size_bytes: Optional[int] = None) -> list[Path]` (`workspace.py:695`) | proposal §4 row B99-I2a | matches the proposal. Consequence in §3 D-3 |
| Increment order | 1..11 | merged in the order 1, 2, 11, 10, 9, 4, 3a, 8, 7, 3b, 6, 5 (`git log 307065f..e7732f6`) | decision-free work first; the operator verdict (LED .5) unblocked the rest | one lane, sequential. Re-pins are carried per packet |

No as-built change contradicts a PDR decision. Each file outside the planned set has a ledger entry, a PDR condition or a review finding behind it, and every increment stays within 4 source files.

## 2 · Per-condition discharge (re-read at `e7732f6`)

| Condition | What it required | Where verified (file:line) | ✓/✗ |
|---|---|---|---|
| C1(a) | B8 never reuses a 0-byte target | `s19_app/tui/workspace.py:578` (`st_size > 0` on reuse); group form `:858`; test `tests/test_b99_staging.py:703` | ✓ |
| C1(b) | race closure stated; TC-B99-13 models a concurrent in-app placement | invariant comment `workspace.py:561-573`; LED .7; `tests/test_b99_staging.py:648` (threads running `copy_into_workarea`, nonzero RED `parallel mismatches: 68`, `03-increments/increment-003.md:335`) | ✓ |
| C1(c) | both staging levels reparse-checked | proposal §3 step 1 (`design-proposal-b99.md:39`); `workspace.py:356` (`temp`), `:361` (`temp/.staging`), post-mkdtemp re-check `:386` (S-F2); tests `tests/test_b99_staging.py:281`, `:314` | ✓ |
| C2 | `changes/io.py` 14th path: convert or backlog | converted: `s19_app/tui/changes/io.py:1602-1624` (private stage, owned-flag cleanup); test `tests/test_b99_staging.py:993` | ✓ |
| C3(a) | signature | `workspace.py:695` = proposal §4 | ✓ |
| C3(b) | building increment | Inc 6 (`87dcd3a`, `workspace.py` +333) | ✓ |
| C3(c) | partial failure: no orphan member, no 0-byte claim | rollback loops `workspace.py:910`, `:930`, `:939`, `:964`, `:996`; tests `tests/test_b99_export.py:542`, `:595` | ✓ (see F-1, LOW) |
| C3(d) | the new function in TC-B99-39's census | `tests/test_b99_staging.py` `_CENSUS_TARGETS` (lists `place_group_into_workarea`) and the test at `:965` | ✓ (see F-2) |
| C3(e) | same containment, reparse and size checks; reuse at the requested stem only | `workspace.py:785-826` (root, reparse walk, per-member reparse, cap `:798`); group reuse `:850-866` (requested names only, all-or-none) | ✓ |
| C3(f) | `segment_ops` gains no `tui.workspace` import; `write_bin_with_sidecar` out of the I2a consumer list | `s19_app/segment_ops.py` not in the diff (its imports `:29-33`: `pathlib`, `typing`, `.tui.changes.io`, `.tui.operations.crc_designer_model`, unchanged). Proposal row fixed (`design-proposal-b99.md:80`). **`docs/architecture.md` B99-I2a row still lists `segment_ops.write_bin_with_sidecar`** | ✓ code / **✗ map** |
| C3(g) | Inc-6 brief cites the real file | LLR-160.2 names `segment_split_view.py` `_write` and `write_split_join_export` (`01-requirements.md:876`) | ✓ |
| C4 | proposal §4 repaired (rows, LLR column, 40) | `design-proposal-b99.md:9` (40), `:76-90` (LLR column, I2/I2a rows separate) | ✓ |
| C5 | R23: coverage on the region result, one number, three readers | carrier `s19_app/tui/operations/crc.py:55`, `:84`; readers: flow arm `flow_execution_service.py:843`, `:882`; `write_crc_image` `crc.py:1463`; operation path `crc.py:1714`; test `tests/test_b99_crc_region.py:265` | ✓ |
| C6 | LLR-158.3 title matches the rule | `01-requirements.md:831` ("values outside the table are refused, in-range values are flagged") | ✓ |
| C7 | file sets synced; the `segment_split_view → workspace` edge recorded as decided | PLAN has 3a/3b and Inc 6 + `workspace.py` (`PLAN.md:76-81`). **Not applied:** PLAN Inc 4 still says `(+ models.py)` and Inc 7 still lists `app.py` only (`PLAN.md:79`, `:82`). ARCH §10 Inc-7/Inc-10 rows unchanged. The ARCH "Dependencies" paragraph still calls the edge a **candidate** | **✗** |
| PQ-1 | = C3 | as C3 | ✓ |
| PQ-2 | orphan `_1.addr`, mismatched-sidecar and forced-failure arms | `tests/test_b99_export.py:460`, `:499`, `:542` | ✓ |
| PQ-3 | group function in TC-B99-39 | as C3(d) | ✓ |
| PQ-4 | corpus pins COMPU_TAB, limits, byte orders | `tests/fixtures/synth/generate.py:122-128` (MOD_COMMON `MSB_FIRST`), `:150-182` (TAB_INTP / TAB_NOINTP tables), `:194-204` (limits `-10 100`, `0 30`; `MSB_LAST` control per LED .4) | ✓ |
| PQ-5 | flag and reason by content | `tests/test_b99_a2l_encode.py` TC-B99-25 (`:360`): `"2.5" in flags[0]`, `"3.4" in flags[0]`, exact `"the nearest table values are 10.0 and 15.0"` | ✓ |
| PQ-6 / UX-C9 | re-pin the help oracle; state the rule | `tests/test_b99_bytes_field.py:66` asserts `"decimal"` and `"not accepted"` (RED at HEAD); `s19_app/tui/window_help.py:84-85`; placeholder `screens_directionb.py` ("hex bytes, e.g. DE AD BE EF"); refusal names token and rule `change_service.py:340` | ✓ |
| PQ-7 | the markup arm has a mutant | `evidence/inc-8/mut-PQ7.txt` (md_safe removed → KILLED), `mut-f4-painted.txt` (painted sink → KILLED); `03-increments/increment-008.md:394-395` | ✓ |
| PQ-8 | race REDs carry a nonzero count | `evidence/inc-3a/red-tc_b99_12.txt` (`parallel mismatches: 140`); `evidence/inc-5/red-baseline.txt` (`20 of 40 concurrent writes landed another image's bytes`) | ✓ |
| UX-C1 | lane line names PATCH, count, first address, disposition | `s19_app/tui/flow_screens.py:3330` (rider) and `_patch_not_applied_note` (`PATCH: k of n entries not applied (0x… disp)`); LED .5 amended LLR-156.2 | ✓ |
| UX-C2 | the last diagnostic of an `error` block is the cause | `_record_error` appends the note last (`flow_execution_service.py:1527-1529`); PATCH `:587`, `:611-612`; CRC `:846-849`; SOURCE `:383-388`; WRITE-OUT `:707`; tests `tests/test_b99_patch_truth.py:182`, `tests/test_b99_crc_region.py:164` | ✓ |
| UX-C3 | no new glyph, word or colour; umbrella word "not applied" | `flow_screens.py` diff adds two static methods and the rider only. `_BLOCK_STATUS_GLYPH`, `_FX_BLOCK_STYLE`, `_FX_STATUS_STYLE`, `FX_CABLE_GLYPHS` and `_FLOW_STATUS_BANNER` are untouched. Summary `flow_execution_service.py:625` ("not applied") | ✓ |
| UX-C4 | outcome within the first 50 characters | `Chain set not run:` `flow_execution_service.py:1819` (painted on `#log_line_4`, `app.py:2851`); `Project NOT saved:` `app.py:8120`; `Not saved: …` at `workspace.py` placement errors | ✓ |
| UX-C5 | placement text: file, folder, cause, next step, "Nothing written"; census column | `workspace.py` lock-exhaustion message ("still locked after 5 retries, another program may hold it — close it and retry. Nothing written."); census with the user-seen-text column `03-increments/increment-003.md:296`. Note: the flow-import caller paints only `import refused: WorkareaPlacementError` (`s19_app/tui/screens.py:890`). It is declared in the census, but the cause is not shown (handed to the ux lens) | ✓ |
| UX-C6 | verify status does not overwrite the not-applied naming | `app.py:4012-4019` (suffix inside `_surface_verify_result`, both arms); `save_back_status_suffix` `change_service.py:131`; tests `tests/test_b99_editor_image.py:529`, `:699` | ✓ |
| UX-C7 | a truncated interactive load does not paint a plain `Loaded X` | `app.py:11239` (`Loaded … with integrity notices: <code>`); test `tests/test_b99_truncation.py:491` | ✓ |
| UX-C8 | `n/a` distinct from blank; short enum reason | `app.py:12762`; `a2l.py:3152-3172` (`_DECODE_REASON_TOKENS`), `:2901` | ✓ |
| UX-C10 | one hostile-name TC per new sink | `tests/test_b99_staging.py:1494`, `:1537`, `:2125`; `tests/test_b99_export.py:269`; `tests/test_b99_truncation.py:531`; `tests/test_b99_patch_truth.py:823` | ✓ |
| UX-C11 | export status: outcome first, `wrote` / `reused`, real names, part-way names | `segment_split_view.py:2099-2113`; part-way `:956-969`; tests `tests/test_b99_export.py:866`, `:1195` | ✓ (see F-3) |

**Frozen-engine crossings (§7).** All three stay inside their LLRs:

- **`core.py`:** `_is_data_record` plus three walk filters (LLR-153.1). `_load` gains the terminator, count and trailing logic, the three codes, `load_notice_code` and S6 parsing (LLR-154.1).
- **`hexfile.py`:** `_load` gains the EOF flag, the trailing count and two codes (LLR-154.2). Nothing else changes.
- **`a2l.py`:** the hunks touch only `_table_lookup`, `_apply_compu_method`, `_invert_rat_func`, `_reverse_table_lookup`, `_invert_physical_to_raw`, encode paths, the MOD_COMMON pre-pass in `extract_a2l_tags`, enrichment and the curve-description reason (LLR-158.1..158.3 + UX-C8).

The diff-vs-main freeze guards (`test_tc031_*`, `test_tc027_*`) were flagged at Inc 2 §6 as failing by design until merge. With main at `e7732f6`, the crossing is classified by its LLRs.

**Interfaces as declared** (consumers measured with `git grep` at `e7732f6`):

- B99-I1: names unchanged. `render/hexview.py:8` imports `_is_data_record` (R18).
- B99-I2: `copy_into_workarea` keeps its parameters and its `Path` return. `WorkareaPlacementError(WorkareaContainmentError)` is at `workspace.py:62`. Every reachable `app.py` caller sits under a containment `except` (`app.py:8632`, `:8654`, `:8756`, `:8827`; `:8183` catches the subclass).
- B99-I3: `ChainRunOutcome` gains `change_records` / `refusals` / `image_ranges` with default factories, read by `flow_screens.py`.
- B99-I5: the `CrcCoverageResult(CrcRegionResult)` subclass is the carrier.
- B99-I6: `write_split_join_export` returns `List[PlacedExport]` and takes a `declared_ranges` keyword. Its consumers are its own view handler and tests only.
- B99-I10: `S19_INTEGRITY_NOTICE_CODES`, `HEX_INTEGRITY_NOTICE_CODES` and `load_notice_code`, consumed by `flow_execution_service.py:44`, `:377` and `app.py:33`, `:989`, `:10657`.

**Dependency directions:**

- Only one new module edge: `tui/segment_split_view → tui/workspace`, the PDR-confirmed candidate.
- `segment_split_view → services/project_gather_service._check_home_contained` was declared in B99-I6.
- `flow_screens → changes.model` (`DISPOSITION_APPLIED`) runs view → model, a permitted direction.
- `apply.py`, `io.py` and `crc.py` already imported `workspace` at `307065f`. Only the symbol `_private_stage_dir` is new.
- No service imports a view. `segment_ops` imports are unchanged (C3(f)).

## 3 · Drift the map must record (feeds the open conditions)

| Id | Drift | Evidence | Map change owed |
|---|---|---|---|
| D-1 | §10/§11 batch-99 text still reads "declared at ARQ, nothing landed / none frozen yet" | `docs/architecture.md` §10 header; §11 amendment header | mark landed at `e7732f6`; set the freeze state per row |
| D-2 | §10 Inc table: the file sets differ from the as-built ones (3a/3b split; Inc 3b + `project_gather_service.py`; Inc 4/9/10 + `app.py`; Inc 5 + `flow_screens.py`; Inc 6 − `segment_ops.py`; Inc 7 + `workspace.py`) | per-commit `git show --stat` | rewrite the rows as-built (C7) |
| D-3 | `workspace._private_stage_dir` (private by name) is now a cross-module seam with 4 importers (`changes/apply.py:57`, `changes/io.py:71`, `operations/crc.py:33`, `segment_split_view.py:80`). Each repeats stage → `copy_into_workarea` → owned cleanup, which stages twice. `_is_reparse_point`, `_find_workarea_root` and `WORKAREA_STAGING_DIRNAME` also cross into the view. This is the consequence of the paths-in signature (C3(a) recommended bytes in) | `git grep` above | declare it in B99-I2 as part of the placement contract, or open a backlog item for a bytes-in placement entry point that retires the four duplicated blocks |
| D-4 | B99-I2 consumers: the map lists 13. As built there are 15 direct `copy_into_workarea(` sites plus the injected `changes/io.py` path; the new ones are `segment_split_view.py:940` and `project_gather_service.py:364` | `git grep "copy_into_workarea("` | update the consumer list |
| D-5 | B99-I2a consumers: the map lists `segment_ops.write_bin_with_sidecar`. As built, the only caller is `segment_split_view.py:949`. `write_bin_with_sidecar` now has **no product caller**: only `tests/test_segment_ops.py` uses it. It is still a direct writer, allow-listed at `tests/test_b99_staging.py:1896`, under a comment that says it was "converted by Inc 6" (`:1859`), but it was bypassed, not converted | `git grep write_bin_with_sidecar` at both commits | fix the row (C3(f)); record the function as headless engine API outside HLR-155 placement; correct the census comment in the next code-touching increment |
| D-6 | the "Dependencies" paragraph still calls `segment_split_view → workspace` a candidate. As built it is an edge | `segment_split_view.py:72-83` | record it as decided (C7) |
| D-7 | R19 text describes "a unique temp in the destination" / `mkdtemp(dir=<workarea>/temp)`. As built: `temp/.staging/stage-*` with both levels checked. R23 still reads "Candidate" | `workspace.py:298-381`; PDR C5 | amend R19 to the LLR-155.1 home; mark R23 decided |
| D-8 | additive public surface not in the proposal's "API unchanged": `ChangeService.source_image_view` (`change_service.py:1878`, consumer `app.py:3950`), `last_save_applied` / `last_save_not_applied` (`:912-913`), `save_back_status_suffix` (`:131`); `PlacedExport` / `ExportRefusedError` / `ExportWriteError` (`segment_split_view.py:547-590`); `FlowReportState.refusals` | `git grep` | list them under B99-I7 / B99-I6 / B99-I3 |

## 4 · Findings (non-blocking; backlog candidates)

| Id | Severity | Finding | Evidence |
|---|---|---|---|
| F-1 | LOW | In `place_group_into_workarea`, the post-claim `os.lstat(claim_path)` is not wrapped. An `OSError` there (a claim that vanishes between `os.close` and `lstat`) escapes as a raw `OSError`, not `WorkareaPlacementError`, and skips the rollback of claims already made. The single-file twin wraps it (`:629`). The export handler catches `Exception`, so the user still sees a refusal, but a 0-byte claim can be left behind | `s19_app/tui/workspace.py:952` vs `:629` |
| F-2 | LOW | `write_split_join_export` deletes staging (`shutil.rmtree(stage_dir)`, `segment_split_view.py:972`) without the owned-flag idiom, and it is outside TC-B99-39's `_CENSUS_TARGETS`. It is correct by construction today (`stage_dir` is bound before the `try`), but LLR-155.7's census no longer covers every deleter of private staging | `tests/test_b99_staging.py` `_CENSUS_TARGETS` |
| F-3 | LOW | The export status word (`wrote` / `reused`) comes from `_export_reuse_target`, a copy of the seam's B8 rule taken before placement. Two rule copies can diverge silently. TC-B99-31 / AT-B99-11 pin the covered cases | `segment_split_view.py:673-686`, `:938-954` |
| F-4 | INFO | When a group placement fails, the rollback unlinks members it has already placed. A concurrent identical export could have B8-reused one of them in that window. This is within the LED .7 invariant's wording (the placement owns its claims) but is a theoretical lost-reference case | `workspace.py:964-1003` |

## 5 · Evidence checklist (architect role)

- [✓] Constraints stated: 4 source files per increment (`executed`: every commit ≤ 4, `git show --stat`); frozen engine §7 (`executed`: §2 crossings); one lane (`executed`, proposal §8); public-repo wording (`executed`); cost/latency `n/a — local TUI, no runtime cost`.
- [✓] 2+ alternatives where a real decision exists: `n/a — the DDR reviews decisions the PDR already made`. The one as-built choice between options (paths in vs bytes in for B99-I2a) is assessed in D-3.
- [✓] Constraints that do not apply are marked `n/a — <reason>` (cost, fork / cross-lane census: single lane, proposal §8).
- [✓] Recommendation tied to constraints: approve, because every condition except C7 and the map half of C3(f) re-reads ✓ (§2 table). The open items are documentation and cannot change behaviour.
- [✓] Risks listed: F-1..F-4 (operational, concurrency); D-3 (maintainability); D-5 (dead direct writer); no cost or lock-in risk.
- [✓] Cost / latency: `n/a — local TUI`. The double staging (D-3) costs one extra local file copy per write.
- [✓] Diagram: `n/a — no new edge beyond the PDR-confirmed one`. The proposal §3 diagrams still describe the as-built flow, with two corrections: step 1's double reparse check is implemented, and B8 reuse rests on the invariant (LED .7).
- [✓] What would change the verdict: `rejected` if a crossing went beyond its LLRs, `segment_ops` imported `tui.workspace`, or a PDR condition failed in code. None did. It becomes `approved` once C7 and the map half of C3(f) are re-read as applied in `docs/architecture.md` and `PLAN.md`.
- [✓] Two-layer requirements: `n/a for this lens at DDR` — this lens verified the US→HLR→LLR mapping of the B99-I rows (proposal §4). The AT↔node uniqueness (C-18) and the summed test ledger belong to the `qa-reviewer` DDR lens.
- Evidence states: code and test re-reads `executed`; test runs by this lens `not-run` (the full suite runs elsewhere); map update `planned` (orchestrator, P6).

## 6 · Open conditions

| Id | Condition | Owner | Re-read by |
|---|---|---|---|
| DDR-A1 (= C7 remainder) | `PLAN.md` and `docs/architecture.md` §10: the as-built file set per increment (D-2); record the `segment_split_view → workspace` edge as decided (D-6) | orchestrator, before batch close | architect |
| DDR-A2 (= C3(f) map half) | `docs/architecture.md` B99-I2a consumers = `segment_split_view.py` only; record `write_bin_with_sidecar` as headless engine API outside placement (D-5) | orchestrator, before batch close | architect |
| DDR-A3 | `docs/architecture.md` records D-1, D-3, D-4, D-7, D-8 (state, seam, consumers, R19/R23, additive surface) | orchestrator, before batch close | architect |

F-1..F-3 go to the backlog. They are not conditions on this gate.
