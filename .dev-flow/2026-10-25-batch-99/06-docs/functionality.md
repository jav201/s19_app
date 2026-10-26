# Functionality — s19_app — Batch 2026-10-25-batch-99

> **Roles:** `docs-writer` (this artifact). Batch `2026-10-25-batch-99`, repo `s19_app`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder (engineers and leads who use or maintain the tool). Purpose: understand what the tool now does differently, and what users will notice.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 At a glance (read first)

- **What this batch added:** the read/write integrity fixes. Every image, report and run record the tool writes now says what was and was not applied, and every loaded image holds only the bytes its file declares. The batch closes the ten HIGH findings of the 2026-10-22 read/write investigation (H-1..H-10), the project round-trip crash PH-3, and the Code-Wire data HIGHs CW-D-4, CW-D-7 and CW-D-10. It also adds deeper tests of the Load project fix (CW-U-1) and CW-U-3, and a synthetic corpus with an independent reader as the byte oracle (`PLAN.md` Objective; `05-postmortem.md` Synthesis).
- **Capabilities:**
  - S0 header text is never image data.
  - Truncated or inconsistent S19/HEX files are flagged on load and stop a flow.
  - Every write goes through private staging and an atomic, exclusive placement.
  - PATCH steps and reports name each entry that was not applied.
  - The Patch Editor saves exactly the source plus the current document.
  - A2L values decode, and encode, in the declared byte order and ASAM direction.
  - A CRC over an empty region is refused.
  - Exports stay inside the work area and invent no byte.
  - The Bytes field is hex only.
  - Both pickers load by name.
- **How to use it:** nothing new to learn. The same TUI (`S19TuiApp`) and the same windows (Load `l`, Patch Editor, Flow Execution, A2L window `2`, Split / Join / Export, Load project `p`, Save project `s`) now refuse or warn where they used to report success. See §*Visible behaviour changes* for what users will notice first.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Visible behaviour changes

> These are changes a user can see on existing data. Each one is `approved` at P4 (`04-validation.md`, `PASS-WITH-NOTES`) through the AT or TC named. The two A2L counts were measured by `evidence/inc-10/example_impact.py` on the shipped examples. Its output, `evidence/inc-10/example-impact.txt`, reads verbatim:
> ```text
> case_06 tags total: 220040 (multi-byte: 71513)
> case_06 multi-byte tags now decoding big-endian (were not on main): 71513
> examples\case_00_public\software_a.a2l: tags 13990, RAT_FUNC tags whose decode direction changed: 1640
> ```

### A2L values that will read differently (HLR-158, Inc-10)

| Example | What changes | Why | Seen in |
|---|---|---|---|
| `examples/case_06_large_nested_a2l/firmware.a2l` | **71,513** tags now decode **big-endian**. That is every multi-byte tag in the file, which has 220,040 tags in all. Before the batch these tags decoded little-endian | The byte-order fallback now reads the module's `MOD_COMMON BYTE_ORDER` before falling back to little-endian. Before, `MOD_COMMON` was never read | A2L window physical column and describe modal; the same values feed every encode |
| `examples/case_00_public/software_a.a2l` | **1,640** of its 13,990 tags use a RAT_FUNC conversion. They now convert in the ASAM direction: encode evaluates INT = f(PHYS), and decode solves f(PHYS) = raw for PHYS | ASAM MCD-2 MC defines RAT_FUNC as INT = f(PHYS). The tool used to apply f to the raw value when decoding | A2L window physical column; a raw value with no real root shows `n/a` |

**Consequence:** a physical value read in the A2L window for these tags will differ from what a pre-batch session or report showed. The new value is the one the bytes mean, per the A2L. On the synthetic corpus, raw `10 11` under `MSB_FIRST` now reads 4113, and raw 300 under `RAT_FUNC_DIV_10` reads 30.0. Before the batch these read byte-swapped and 3000.0 (premises P-7, P-17).

### Refusals, warnings and status lines users will now see

| Area | Before the batch | Now (message as painted) | Requirement · evidence |
|---|---|---|---|
| **Bytes field is hex only** | `0F 10 1F 20` was written as `0F 0A 1F 14`: digit-only tokens were read as decimal | Every token is read as hex (1–2 digits, `0x` optional). Anything else is refused: `invalid byte token '100' - every token is 1-2 hex digits with an optional 0x prefix; decimals are not accepted`. The placeholder reads `hex bytes, e.g. DE AD BE EF`, and the window help states the rule. String (value) entries are unchanged | HLR-161 · AT-B99-12, TC-B99-32/33 |
| **Duplicate output names refused** | Two parallel lanes writing `same.s19` raced on one shared staging path. 35 lane/file mismatches were measured in 5×8 runs | The chain set does not start, e.g. `Chain set not run: lanes 'a', 'b' both write 'same.s19' — give each lane its own output name. Nothing written.` The names are compared case-folded. The refusal appears in the run log and on the status line, and no lane runs | HLR-155 (D7) · AT-B99-04, TC-B99-15 |
| **PATCH status `error` / `notices` when entries are skipped** | PATCH always reported `ok` (`applied 0 entries`), and the flow went on to write the output | `error` when nothing applied, the document was unreadable, or the document was refused. The cause names the first address: `applied 0 of 1 entries: 0x00020000 skipped-outside`. The flow stops before WRITE-OUT and writes no file. `notices` when some entries applied: the summary is `applied 1 of 2 entries, 1 not applied`, and the lane's last log line reads `PATCH: 1 of 2 entries not applied (0x00020000 skipped-outside)` | HLR-156 (D5) · AT-B99-06, TC-B99-17/18 |
| **Reports no longer say `CLEAN` over a dropped write** | The chain-set and flow reports dropped dispositions and could head a run `CLEAN` | The flow report gains **Not applied** and **Refusals** sections, always present (`- none` when empty). The chain-set report gains **Written files**, **Not applied** and **Refusals** per lane. A run holding either kind of entry heads itself `COMPLETED WITH ISSUES` or `FAILED`, never `CLEAN`. File-derived text renders literally | HLR-156 · AT-B99-06/07, TC-B99-19/20 |
| **Truncated images reported** | A cut transfer loaded as `ok` with its tail missing | The load status leads with the defect: `Loaded cut.s19 with integrity notices: S19-NO-TERMINATOR`. The Issues panel names the code. The five codes are `S19-NO-TERMINATOR`, `S19-COUNT-MISMATCH`, `S19-AFTER-TERMINATOR`, `HEX-NO-EOF` and `HEX-AFTER-EOF`. Lines after the end are counted, never loaded. A flow over such a file ends SOURCE `error` (`[code] file: message`) and writes nothing | HLR-154 (D6) · AT-B99-03, TC-B99-08/09/10 |
| **Export names sanitised, `_1` suffix** | An A2L segment named `../` escaped the work area. A MAC-only export wrote a placeholder byte as data | Names keep `[A-Za-z0-9_-]` only, and Windows device names get a `_` prefix: `x/../../../ESCAPED` becomes `prg_x__________ESCAPED.s19`, inside the destination. Collisions, over-long paths and links are refused before any write (`Export refused: …`). A changed re-export lands at `<name>_1`; a BIN and its `.addr` take the same `_<N>`; identical bytes are reused. The status reads `Exported N files: …` with `wrote` / `reused`. A MAC-only export writes a header-only file | HLR-160 (D8) · AT-B99-11, TC-B99-28..31/41 |
| **CRC over an empty region refused** | `00000000` was written over live bytes with status `ok` | The CRC step ends `error` and injects nothing, and the flow writes no file: `CRC region 0x20000-0x30000 holds 0 image bytes - nothing written`. Partial coverage gives `notices` with the exact count, e.g. `466 of 512 region bytes absent (0xFA00-0xFC00)`, on the lane line too | HLR-159 · AT-B99-10, TC-B99-26/27 |
| **Save-back keeps the work copy** | A save-back under the image's own name overwrote and then **deleted** the loaded work copy, and Save project then exited the app (code 1) | Each write stages in its own private directory under `temp/.staging/`. The work copy stays present and byte-equal, Save project completes (`Project saved…`), and the app keeps running | HLR-155 (PH-3) · AT-B99-05, TC-B99-11/14 |
| Save project with a missing source | (crashed with PH-3; otherwise undefined) | `Project NOT saved: source file missing: <file> — reload it or remove it from the project.` No empty project folder is left behind, and the app keeps running | LLR-155.4 · TC-B99-14 |
| Placement failure | a raw `OSError` could reach callers | Outcome first, naming the file and folder, e.g. `… is still locked after 5 retries, another program may hold it — close it and retry. Nothing written.` No zero-byte file is left | LLR-155.2 · TC-B99-12 |
| Flow WRITE-OUT verify | the written file was not read back | WRITE-OUT reads the file back. A mismatch ends the step `error`, naming `first difference at 0x…` | LLR-155.6 (D9) · TC-B99-16 |
| S0 header bytes | 15 of 16 example S19 files gained 6–18 phantom bytes at `0x0` on a round-trip. A patch at `0x0` landed on header text | The Memory Map shows no range at `0x0` for these files, written images hold no data at `0x0`, and a patch at `0x0` is `skipped-outside`. Range, coverage and entropy figures for S0-bearing files change, because the S0 bytes no longer count | HLR-153 · AT-B99-02, TC-B99-04..07 |
| Patch Editor save-back status | an undone entry still reached the file, and verify said `verified` | The file holds the source plus the current entries only. The final status names them: `Saved + verified: <file> — 1 entry applied before this save (0x0000EB40)`, plus `; includes N entries not applied before this save (…)` when entries were added after the last apply. The before/after strip's `was` is the source byte | HLR-157 · AT-B99-08, TC-B99-21/22/40 |
| A2L value that cannot decode | a number was shown anyway | `n/a`, distinct from a blank cell (no bytes). The describe modal reads `Scalar value: n/a (rat_func_no_real_root)` | HLR-158 · AT-B99-09 |
| Load project dialog and Workarea Files list | `patches` (and other reserved homes) were listed as projects. The Files list read a folder loads never write to, and a pick loaded nothing | Reserved homes (`temp`, `patches`, `templates`, `logs`, `crc`, `flows`, `flowsets`, `splits`, `reports`) are hidden. The Files list shows the files under `workarea/temp`, and a pick loads that file by name | HLR-162 · AT-B99-13, TC-B99-34..36 |
| Save project re-gather | a drifted artifact was deleted and re-copied under the same name | A drifted artifact lands at the next free `_<N>`, and placed files are never replaced. An unchanged re-save adds no copy | LLR-155.3 (LED .7) · TC-B99-13 |

---

## Detail (reference)

> Line anchors are measured on the tree at `bf3917d`, where `s19_app/` is byte-identical to the gated `e7732f6`. The full per-requirement trace is in `traceability-matrix.md`. Every behaviour below is `approved` at P4 unless its line says otherwise.

### How it works (flow)

The batch changes behaviour under every writer the tool has. No screen and no module was added, and one module edge was added (`segment_split_view → workspace`, decided at the PDR). There were 14 increments. Their execution order differed from the plan because the operator's verdict arrived early: 1, 2, 11, 10, 9, 4, 3a, 8, 7, 3b, 6, 5, then 12 and 13 (`05-postmortem.md` §Scope drift).

1. **Synthetic corpus and independent reader (US-141 / HLR-152, Inc-1).** `tests/fixtures/synth/generate.py` writes 16 fixture files (S19, Intel HEX, MAC, A2L) and `manifest.json` with each file's SHA-256, coverage classes, expected bytes and verdict. `generate.py --check` regenerates the corpus, compares it with the committed files, reads every S19/HEX file with `tests/support/independent_reader.py` (zero `s19_app` imports), and prints `checked 16 files` or names the first differing file. Every byte assertion in the batch uses this reader or the manifest, never the tool's own loader, because the tool's verify shared the S0 defect (premise P-3).
2. **S0 is not image data (US-142 / HLR-153, Inc-2).** One predicate, `_is_data_record` (`core.py:220`), admits only S1/S2/S3 records. `get_memory_map`, `get_record_for_address`, `_build_overlap_map` and the hex-view builders (`render/hexview.py:60`, `:71`) all filter through it. The S0 text still travels as a header record on save-back and WRITE-OUT.
3. **Truncation reported (US-143 / HLR-154, Inc-9).** The S19 and HEX loaders (`core.py:289`, `hexfile.py:36`) attach one notice per defect kind, each with a stable code. S6 count records now parse. The flow SOURCE arm treats exactly those five codes as `error` (`flow_execution_service.py:135`, `:377`). Other load notices stay advisory.
4. **Private staging and atomic placement (US-144 / HLR-155, Inc-3a, Inc-3b, Inc-5).** `copy_into_workarea` (`workspace.py:402`) and `save_patched_image` stage in a private `mkdtemp` directory under `temp/.staging/`, created by `_private_stage_dir` (`:298`) with both levels checked for reparse points. They claim the final name with `O_EXCL`, or the next free `_<N>`, and fill it with `os.replace`. They never touch the source and delete only their own staging. Before any lane runs, `run_chain_set` refuses duplicate output names. WRITE-OUT re-reads what it wrote. The CRC write uses the same staging. See `diagrams/write-path.md`.
5. **PATCH truth (US-145 / HLR-156, Inc-8).** The PATCH arm derives its status from dispositions and refusals, first match wins: `error`, then `notices`, then `ok`. An `error` aborts the chain before WRITE-OUT. `ChainRunOutcome` (`flow_execution_service.py:1587`) carries `change_records`, `refusals` and `image_ranges`, so the lane painter and both reports list what was not applied. See `diagrams/run-record-dispositions.md`.
6. **Editor image (US-146 / HLR-157, Inc-4).** `ChangeService` keeps a journal (address → source byte). Every apply restores the journal in place, then applies the current document, and every save re-derives the image the same way. An undo, remove or edit therefore never leaves stale bytes. `source_image_view` (`change_service.py:1878`) feeds the before/after strip.
7. **A2L codec (US-147 decode, US-152 encode / HLR-158, Inc-10).** The byte order falls back from tag to RECORD_LAYOUT to the tag's own endian to its module's `MOD_COMMON` (per MODULE, `a2l.py:2414`), and only then to little-endian. RAT_FUNC encode evaluates f; decode solves for the physical value, takes the root inside the tag's limits, and reports no real root as `n/a`. COMPU_TAB encoding refuses or flags values the table cannot represent. The encoder has no TUI caller today (P-22), so its refusals are visible through the codec API only. See `diagrams/a2l-codec-decisions.md`.
8. **CRC coverage (US-148 / HLR-159, Inc-5).** `check_regions` (`crc.py:830`) computes the absent-byte count once and carries it on `CrcCoverageResult`. The flow CRC arm, `write_crc_image` and `CrcOperation.execute` all read that one number.
9. **Export containment (US-149 / HLR-160, Inc-6).** `write_split_join_export` (`segment_split_view.py:715`) plans every name through `sanitize_export_segment` (`:592`) before any write, checks collisions case-folded and path lengths, anchors containment at the work-area root (`_check_home_contained`), and takes bytes from declared ranges only. Pairs are placed by `place_group_into_workarea` (`workspace.py:695`).
10. **Bytes grammar (US-150 / HLR-161, Inc-11).** `parse_new_bytes` (`change_service.py:281`) accepts `(?:0[xX])?[0-9A-Fa-f]{1,2}` per token (ASCII only). This amends batch-07 LLR-001.2.
11. **Pickers (US-151 / HLR-162, Inc-7).** `RESERVED_WORKAREA_HOMES` (`workspace.py:40`) filters `list_projects`. `refresh_files` lists `workarea/temp` and stores each file name on `item.data`, which `_load_from_item` reads back. It no longer reads `str(Label)`, which resolved every pick to `"Label()"`.

### Operator rulings honoured (D1–D10)

The operator chose the recommended option on all ten decisions (`design/veredicto-b99.json`, applied in LED .5):

| Decision | Ruling | Effect |
|---|---|---|
| D1 | `hex` | Bytes field tokens are always hex; decimals are refused |
| D2 | `asam` | RAT_FUNC is INT = f(PHYS): encode evaluates, decode solves |
| D3 | `modulo` | byte-order fallback reads the module's `MOD_COMMON` |
| D4 | `rechazar` | COMPU_TAB: `TAB_NOINTP` exact, else refused naming the two nearest values. `TAB_INTP` out of range is refused naming the range; in range it encodes the nearest raw value, with a flag naming the written value (amended in LED .2) |
| D5 | `mixta` | PATCH `error` / `notices` / `ok` from dispositions |
| D6 | `flujo_para` | a flow stops at SOURCE on an integrity notice |
| D7 | `rechazar` | duplicate lane output names refuse the chain set |
| D8 | `sufijo` | an export onto a changed existing name takes `_<N>` |
| D9 | `si` | WRITE-OUT reads back what it wrote |
| D10 | `diferir` | enter-to-load in the Load project dialog is deferred to the Load+projects batch |

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/core.py` · `s19_app/render/hexview.py` | `_is_data_record` predicate on every S19 image walk (Inc-2); loader notices, S6 parsing, `load_notice_code` (Inc-9) |
| `s19_app/hexfile.py` | EOF gate and the two HEX notices (Inc-9) |
| `s19_app/tui/workspace.py` | private staging, O_EXCL placement, `WorkareaPlacementError` (Inc-3a); `place_group_into_workarea` (Inc-6); `RESERVED_WORKAREA_HOMES` (Inc-7) |
| `s19_app/tui/changes/apply.py` · `changes/io.py` | `save_patched_image` and `write_change_document` stage privately (Inc-3a) |
| `s19_app/tui/services/project_gather_service.py` | drifted re-gather placed at `_<N>`, never overwritten (Inc-3b) |
| `s19_app/tui/services/flow_execution_service.py` | D7 start check, D9 verify (Inc-3b); CRC arm (Inc-5); PATCH status, `ChainRunOutcome` fields, chain-set report sections (Inc-8); SOURCE integrity arm (Inc-9) |
| `s19_app/tui/services/flow_report_service.py` | Not applied / Refusals sections; no `CLEAN` with either (Inc-8) |
| `s19_app/tui/flow_screens.py` | lane-line riders for CRC absent count (Inc-5) and PATCH not-applied (Inc-8); no glyph, word or colour class changed |
| `s19_app/tui/operations/crc.py` | `CrcCoverageResult`, empty-region refusal, private staging (Inc-5) |
| `s19_app/tui/services/change_service.py` | editor-image journal and save-back status (Inc-4); hex-only `parse_new_bytes` (Inc-11) |
| `s19_app/tui/a2l.py` | byte order, RAT_FUNC direction, COMPU_TAB refusals, `n/a` reasons (Inc-10) |
| `s19_app/tui/segment_split_view.py` | sanitiser, plan pass, containment, declared ranges, `_<N>` status (Inc-6) |
| `s19_app/tui/screens_directionb.py` · `window_help.py` | Bytes placeholder and help line (Inc-11) |
| `s19_app/tui/app.py` | Save project pre-flight, D7 status line, editor strip, integrity-led load status, A2L `n/a` cell, pickers (Inc-3a, 3b, 4, 7, 9, 10) |

Source budget: every increment stayed at or under 4 SOURCE files; the largest are Inc-3a and Inc-9 at 4 of 4. Inc-1, Inc-12 and Inc-13 changed tests only.

### Usage / examples

```bash
# corpus oracle (maintainer CLI, the AT-B99-01 surface)
python tests/fixtures/synth/generate.py --check     # prints "checked 16 files", exit 0

# the batch's own verification (the packets' section 3 and 04-validation.md Layer A)
pytest tests/test_b99_corpus.py        # HLR-152
pytest tests/test_b99_s0.py            # HLR-153
pytest tests/test_b99_truncation.py    # HLR-154
pytest tests/test_b99_staging.py       # HLR-155
pytest tests/test_b99_patch_truth.py   # HLR-156
pytest tests/test_b99_editor_image.py  # HLR-157
pytest tests/test_b99_a2l_encode.py    # HLR-158
pytest tests/test_b99_crc_region.py    # HLR-159
pytest tests/test_b99_export.py        # HLR-160
pytest tests/test_b99_bytes_field.py   # HLR-161
pytest tests/test_b99_load_project.py  # HLR-162
```

These are the commands the packets and `04-validation.md` record. This document did not re-run them: the P4 gate run and the SPOT run are the evidence (139 b99 nodes passed on `75f947a`). Run them from the repository root in the project environment, and do not set `NO_COLOR`, because the pilot tests read painted text. To reproduce the A2L impact counts, run `python .dev-flow/2026-10-25-batch-99/evidence/inc-10/example_impact.py` (read-only; it writes nothing).

### Risks / limitations (from the record)

- **No evaluation with real users.** The automated pilot proves the text is painted, not that an engineer reads it correctly (`04-validation.md` §UX walkthrough).
- **Some refusals are verified at TC level only.** These are the HEX defect notices through `l`, the Bytes-field refusal message as painted, the Save project error arms, and the chain-set report's not-applied listing (G-002, G-003; routed to `BACKLOG-CODE.md`).
- **The encoder's refusals are not visible in the TUI.** No shipped surface calls `encode_physical_to_raw_bytes` (P-22). The COMPU_TAB refusals and flags reach a user only once a symbol-entry surface exists (routed as a feature).
- **Values change on existing A2L data** (§Visible behaviour changes). Values compared against pre-batch reports for case_06-style `MOD_COMMON MSB_FIRST` files or for RAT_FUNC tags will differ.
- **Placement is not yet everywhere.** `flow_persistence_service.save_flow_json` and `save_chain_set` keep the existing `exists()` + counter dedup (declared exceptions, Inc-3b F4a). `segment_ops.write_bin_with_sidecar` was bypassed, not converted (DDR D-5). The private staging seam `_private_stage_dir` has 4 cross-module importers (D-3).
- **There is an open decision on duplicate-name saves.** Two baseline tests (`test_tc018_…`, `test_at031b_…`) still expect a dedup suffix that conflicts with byte-identical reuse (G-005, an operator decision).
- **The complete suite run on the final tree is the confirmation run on `75f947a`:** 3755 passed, 12 failed. 8 failures predate the batch, and 4 are intermittent tests that fail on the pre-batch tree too or pass in isolation on both trees (G-001, `evidence/suite-triage-75f947a.md`).

### Diagrams

- `06-docs/diagrams/write-path.md`: a write from staging through atomic placement to the WRITE-OUT verify.
- `06-docs/diagrams/run-record-dispositions.md`: PATCH dispositions to the block status, then to the lane, the chain-set report and the flow report.
- `06-docs/diagrams/a2l-codec-decisions.md`: the A2L byte-order, RAT_FUNC and COMPU_TAB decisions.

### Evidence checklist — docs-writer
> Attach `docs-writer`'s completed evidence checklist (items in `agents/docs-writer.md`), ✓/✗ + one-line evidence.

- [x] Audience and purpose declared at the top of the doc (or implicit and obvious). — ✓ header: technical stakeholder; understand the changes and what users will notice.
- [x] Structure follows the relevant template (or a justified deviation is noted). — ✓ `templates/functionality-template.md` sections kept. Added "Visible behaviour changes" (owed by the P5 synthesis), "Operator rulings" and "Risks / limitations", as batch-97 did.
- [x] Code/CLI snippets actually run (or marked "untested"). — ✓ the commands are the packets' and `04-validation.md`'s own; marked above as not re-run by this document.
- [x] Assumptions listed. — ✓ the anchor tree (`bf3917d`, product equal to `e7732f6`); the D1–D10 rulings; the evidence states of `04-validation.md`.
- [x] Risks / limitations called out. — ✓ "Risks / limitations (from the record)".
- [x] Next steps stated. — ✓ `traceability-matrix.md` §3 (owner per gap) and `05-postmortem.md` open items; `executive-summary.md` (presentation-builder).
- [x] Diagrams included where flow is non-trivial. — ✓ three Mermaid diagrams under `06-docs/diagrams/`.
- [x] No invented APIs / version numbers / metrics. — ✓ the A2L counts were read from `evidence/inc-10/example-impact.txt`; messages were grepped from `s19_app/` on `bf3917d`; other figures come from `04-validation.md`, `05-postmortem.md` and the packets.
