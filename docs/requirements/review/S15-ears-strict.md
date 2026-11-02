# S15 — Flow engine: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S15 (lines 6597–6672): R-TUI-099 only. Also the engine half of R-TUI-059 (S16 owns the row, S15 is second: rule D-9), the flow rows of S0's table (HLR-014, 015, 019, 020, 021, 142, 143, 156, 159 and LLR-013.3, 014.1, 014.2, 015.1, 015.2, 018.2, 019.1, 019.2, 020.2, 021.1, 021.2, 142.1, 143.1, 154.3, 155.5, 155.6, 156.1 … 156.4, 159.2), and the items S8, S9 passed (the flow's declared A2L, WRITE-OUT through S8.7 with its verify, the CHECK engine, the S19 terminator). R-TUI-097 (S12, flow report encoder) is cited, not rewritten.
Code: `tui/services/flow_model.py`, `flow_execution_service.py`, `flow_persistence_service.py`, `flow_report_service.py`, `flow_fused_report_service.py`; the run and file handlers of `app.py` (`:2843-2994`, `:3008-3340`). Read directly, every fact with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows R-FLOW-FILE.11, R-FLOW-SET.7 and decision D15-18 verified at 570b4b5 (`flow_persistence_service.py` unchanged since 093a7c0); other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-FLOW, CTX-FLOWFILE, CTX-CHAIN, CTX-FLOWREPORT.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. The chapter had one row for a feature the operator can no longer reach; almost every row here is **NEW** (D15-2), marked at the start of "Code today". Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied. No visual change is decided here (the screens are S16).
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S15.md`. Nothing is changed in the code yet.

---

## 1. How S15 was written before

- One row, R-TUI-099 (batch-70): run a saved flow once per project variant and fuse the results into one report. ~60 lines, most of them a batch record: "where the binding actually is", "why the binding is a project-relative ref", three "deliberately does NOT claim" paragraphs, a table of acceptance nodes, a golden measurement, a falsifiability note.
- The engine itself had no requirement in this chapter: the block kinds, how a run threads the image, when a block stops the flow, the run status, flow files, chain sets, the flow report and the chain-set report. R-TUI-059 (S16) named three block kinds as the "tracer"; S0's table carried the rest as batch HLR/LLR rows.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-099 | The operator cannot reach it: batch-97 removed the Builder's scope selector and the app's variant branch (`app.py:2857-2861`, `flow_screens.py:2032`); only tests call `run_flow_over_variants`. Multi-variant runs now run in Flow Execution, one lane per variant. | Deleted with its code (D15-8). |
| R-TUI-099 | "Where the binding actually is", "Why the binding is a project-relative ref", "What this requirement deliberately does NOT claim", the node table, "AC-6 is now carried by a byte-golden": process records. | Out (D15-1). |
| R-TUI-059 (engine half) | `run_flow(flow, ctx)` "mirroring `variant_execution_service._execute_one_variant`", "`len(block_results) == len(flow.blocks)`", "never raises": design. "SOURCE → PATCH → WRITE-OUT": eight block kinds exist now. | Observable rows S15.1 … S15.9 (D15-3). |
| (nothing) | The flow report's Image footprint counts one byte too many per range and prints the end one past the last byte; the shipped golden pins `0x00001000–0x00001004  (5 bytes)` for a 4-byte record. | R-FLOW-RPT.9 (D15-10). |
| (nothing) | A REPORT block in a run paused at an external step reports `Status: CLEAN`. | R-FLOW-RPT.4 (D15-11). |
| (S0 HLR-019) | "the run controls shall offer a per-run mode that runs the chains in parallel": the parallel lanes run on threads, but the whole set runs on the screen's thread, so the screen freezes either way (S16 D16-15). Two lanes writing a report in the same second can pick one name. | R-FLOW-CHAIN.4; D15-12. |
| (S0 HLR-142) | "the Flow Builder shall ask for the A2L reference": the engine reads `a2l_ref`, the Builder has no field for it. | Engine rows here; the field is S16's (D16-25). |
| (S0 HLR-155, S8 D8-29) | WRITE-OUT writes every S19 terminator with address 0; S8 asked S15 to decide. | Source terminator address (R-FLOW-WRITE.4, D15-14). |
| External step | The output path, when relative, is read from the start folder, while the log path, when relative, is read from the project folder. | Both from the project folder (D15-17). |

Context notes that would have carried behaviour (E6): none were written before.

---

## 3. Context notes (informative)

### CTX-FLOW · Blocks, refs and statuses (S15.1 … S15.10)

```text
flow            A name, an ordered list of blocks and a variable table (the funnel).
block kinds     Kind (file tag)   shown as   what it does
                source            LOAD       reads an image file: the working image
                patch             PATCH      applies a change document (S8) to the image
                check             CHECK      runs a check document (S9) on the image
                crc               CRC        computes and writes a CRC (S13) into the image
                write_out         WRITE-OUT  writes the image to a file
                a2b               A2B-DIFF   writes a diff report of two images (S14)
                external_step     EXT-STEP   waits for a human step outside the app
                report            REPORT     writes the flow report
working image   The image a run carries from block to block; a LOAD sets it.
project ref     A file name a block carries, read under the open project folder by
                S11's manifest-entry rules: no NUL, not absolute, no escape, no link.
                A refused ref gives one finding [MANIFEST-PATH-ESCAPE] <message>.
block result    Status, summary, findings (warnings) and diagnostics; the last
                diagnostic is the cause.
block status    ok · notices · error · skipped · waiting
stop the flow   End the block error and skip every later block that is not a REPORT
                block, with the summary "skipped (upstream error)".
pause the flow  End the block waiting and skip every later block that is not a REPORT
                block, with the summary "skipped (waiting on external step)".
run status      ok (shown CLEAN) · completed-with-issues · error (shown FAILED) ·
                paused
written files   The files WRITE-OUT blocks and confirmed external steps wrote; reports
                are not written files.
integrity codes The integrity notices of S1 (S19 and Intel HEX).
funnel          Up to 32 pairs NAME = value; NAME is [A-Z0-9_], 1 to 32 characters;
                value 1 to 256 characters. A placeholder is the exact text ${NAME}.
```

### CTX-FLOWFILE · Flow files (S15.12)

```text
flows home      <project>/flows/
flow file       <flows home>/<name>.json: {"schema_version": 1, "name", "blocks": [...],
                ["funnel": [[NAME, value], ...]]}; each block {"kind", its fields};
                refs stored as typed.
block fields    source: image_ref, file_type (s19|hex), [a2l_ref]
                patch: change_doc_ref, [a2l_ref]
                check: check_doc_ref, gating (advisory|block-own-op)
                crc: config_ref        write_out: output_name, fmt (s19|hex)
                a2b: image_a, image_b, each {"source": flow|file, "ref"}
                external_step: mode (terminal|manual), instruction, log_ref, output_path
                report: no field
limits          At most 1 MiB; 1 to 64 blocks; name at most 64 characters.
saved name      The typed name cleaned as S11 cleans a project name; on a clash
                <name>_<N>.json, the lowest free N.
load findings   Each refused rule gives one finding, code then message:
  FLOW-SIZE-CAP           flow file is <n> bytes, over the 1048576-byte cap - not loaded
  FLOW-JSON-PARSE         flow file is not well-formed JSON - <error type>
  FLOW-BAD-STRUCTURE      top level not an object · blocks not an array · no blocks ·
                          over 64 blocks · a block not an object
  FLOW-SCHEMA-UNSUPPORTED schema_version other than 1
  FLOW-UNKNOWN-KIND       a kind not in the list above
  FLOW-BAD-FIELD          an unknown or missing field · an enum value not allowed · a
                          bad name · a bad funnel
  FLOW-UNSAFE-REF         a ref with NUL · a Windows drive-relative ref
  FLOW-UNSAFE-OUTPUT-NAME an output_name with a separator, "..", an absolute path or a
                          leading "."
  MANIFEST-PATH-ESCAPE    a read ref that S11's rules refuse
```

### CTX-CHAIN · Chain sets (S15.13 … S15.15)

```text
chain set       Lanes run together in Flow Execution (S16), with a set name.
lane            A flow loaded from a flow file (its template), a lane name, and the
                LOAD refs bound for this lane (the template's own refs where not bound).
mode            sequential (one lane after the other, in lane order) · parallel (all
                lanes at once, each on its own working image).
flowsets home   <project>/flowsets/
chain-set file  <flowsets home>/<name>.json: name and, per lane: chain (lane name),
                template (a flows/ file name), inputs ([LOAD index, ref] pairs),
                outputs (the files its last run wrote).
                Limits: 1 to 32 lanes; names at most 64 characters; at most 64 inputs and
                64 outputs per lane; template a plain file name; refs as project refs.
                Saved name and clash rule as a flow file. Refusal codes: CHAIN-SET-SIZE-CAP,
                CHAIN-SET-JSON-PARSE, CHAIN-SET-BAD-STRUCTURE, CHAIN-SET-SCHEMA-UNSUPPORTED,
                CHAIN-SET-BAD-FIELD, CHAIN-SET-UNSAFE-REF.
```

### CTX-FLOWREPORT · The flow report and the chain-set report (S15.11, S15.14)

```text
reports home    <project>/reports/
flow report     <ts>-report.md (S12's project report name, so the Reports dialog lists
                it). Sections in order:
  header        "# Flow report — <flow name>", Generated (YYYY-MM-DD HH:MM:SS UTC),
                Status, "Blocks reported: <n> (up to the report block)"
  Pipeline ledger      # · Block · Status · Summary, one row per block before the report
  Change attribution   Patch · Change document · Address · Length · Before · After ·
                       Symbol · A2L reference, one row per applied entry; or
                       "- (no changes applied)"
  Not applied          Patch · Change document · Address · Disposition; or "- none"
  Refusals             Patch · Change document · Code · Detail; or "- none"
  Findings             "- **[<KIND> #<i>]** (<severity>) <text>" per finding and
                       "(diagnostic) <text>" per diagnostic; left out when there is none
  Image footprint      "Before CRC" (after a CRC ran) and "Final": ranges and byte total
  Written files        paths relative to the project folder; or "- (none)"
report status   CLEAN · COMPLETED WITH ISSUES · FAILED
report limits   A cell at most 240 characters; at most 200 findings per block, then
                "*<k> more findings omitted (per-block cap 200).*"; the document at most
                S12's report byte budget, then "> **Truncated:** … omitted section(s): …".
chain-set report  <ts>-chain-set-report.md (clash: <ts>-<NN>-chain-set-report.md).
                "# Chain-set report — <set name>", Generated, Mode, Chains; then the
                sections Chain ledger (# · Chain · Template · Status · Blocks · Elapsed),
                Input provenance ("- Chain <lane> input <j>: <ref> [bound] path=`<path>`"),
                Written files, Not applied, Refusals, Notices — each lane "none" when it
                has nothing.
flow-A2B report  <ts>-flow-a2b.md: a diff report (S14 CTX-DIFFREPORT), Markdown only.
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested** (test named), **Partly** / **No** with the decision; a leading **NEW** marks a row for behaviour no requirement named before (D15-2).

### S15.1 · Running a flow (CTX-FLOW; engine half of R-TUI-059)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-059.1 | When | When a flow runs, the system shall run its blocks in order on one working image. | Yes; tested (`test_run_flow_source_patch_writeout_happy_path`). |
| R-TUI-059.2 | When | When a flow runs, the system shall give every block exactly one block result. | Yes; tested (`test_run_flow_missing_source_isolates_and_writes_nothing`). |
| R-TUI-059.3 | If | If a block raises an error, then the system shall stop the flow with the summary `error` and the cause `<error type>: <message>`. | Yes (`flow_execution_service.py:1203-1208`). |
| R-TUI-059.4 | If | If a block stops the flow, then the system shall still run every later REPORT block. | Yes; tested (`test_at009_aborted_run_still_writes_a_failed_report`). |
| R-TUI-059.5 | U | The system shall read every ref of a block as a project ref before it opens the file. | Yes; tested (`test_run_flow_path_escape_ref_is_blocked`, `test_at127a_absolute_config_ref_rejected`). |
| R-TUI-059.6 | If | If a project ref is refused, then the system shall add its finding to the block's diagnostics before the cause. | Yes (`flow_execution_service.py:1527-1529`). |
| R-FLOW-RUN.1 | U | The system shall leave the flow and its file unchanged by a run. | **NEW** · Yes (`flow_execution_service.py:1660-1676`). |
| R-FLOW-RUN.2 | U | The system shall read no A2L or MAC loaded in the session during a flow run. | **NEW** · Yes (`app.py:2896`, `:3111`; D15-7). |

### S15.2 · LOAD (from S0 LLR-154.3, HLR-142, LLR-142.1)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-SRC.1 | When | When a LOAD block runs, the system shall replace the working image with the image of its file. | **NEW** · Yes; tested (`test_run_flow_source_patch_writeout_happy_path`). |
| R-FLOW-SRC.2 | When | When a LOAD block declares Intel HEX, the system shall read its file as Intel HEX. | **NEW** · Yes; tested (`test_run_flow_writeout_hex_and_s19_formats`). |
| R-FLOW-SRC.3 | When | When a LOAD block declares S19, the system shall read its file as S19. | **NEW** · Yes. |
| R-FLOW-SRC.4 | If | If a LOAD block's file is refused or does not exist, then the system shall stop the flow with the summary `source unresolved` and the cause `source image not found or not inside the project`. | **NEW** · Yes; tested (`test_at085b_unresolvable_source_stops_and_skips`). |
| R-FLOW-SRC.5 | If | If the loaded image carries a notice with an integrity code, then the system shall stop the flow with the summary `loaded <file> with integrity notices` and one diagnostic `[<code>] <file>: <message>` per such notice. | **NEW** · Yes (`flow_execution_service.py:379-397`). |
| R-FLOW-SRC.6 | If | If the load rejected lines and carries no integrity code, then the system shall end the block notices with the summary `loaded <file> (<n> ranges, <k> integrity notice(s))` and one finding `line <n>: <message>` per rejected line. | **NEW** · Yes; tested (`test_at085a_load_notices_downstream_runs`, `test_tc085_3_findings_count_matches_load_errors`). |
| R-FLOW-SRC.7 | When | When a LOAD reads its file with no rejected line, the system shall end the block ok with the summary `loaded <file> (<n> ranges)`. | **NEW** · Yes; tested (`test_tc085_2_zero_error_image_stays_ok`). |
| R-FLOW-SRC.8 | When | When a LOAD block declares an A2L reference, the system shall read that A2L file as the run's symbol context before any PATCH applies. | **NEW** · Yes; tested (`test_tc715_project_mode_resolves_project_root_a2l`). |
| R-FLOW-SRC.9 | If | If a LOAD block's A2L reference is refused or does not exist, then the system shall stop the flow with the summary `a2l reference unresolved` and the cause `a2l reference '<ref>' not found or not inside the project`. | **NEW** · Yes; tested (`test_tc715_reference_in_neither_home_refuses_run_naming_it`, `test_tc715_reference_outside_guard_refused_like_any_ref`). |
| R-FLOW-SRC.10 | If | If a LOAD block's A2L reference cannot be read, then the system shall stop the flow with the summary `a2l reference unreadable` and the cause `a2l reference '<ref>' could not be read: <error type>`. | **NEW** · Yes; untested. |

### S15.3 · PATCH and the funnel (from S0 HLR-156, LLR-156.1, HLR-142, LLR-143.1)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-PATCH.1 | When | When a PATCH block runs, the system shall apply its change document to the working image as S8 applies a document. | **NEW** · Yes; tested (`test_run_flow_source_patch_writeout_happy_path`). |
| R-FLOW-PATCH.2 | If | If no LOAD has run before a PATCH, CRC or WRITE-OUT block, then the system shall stop the flow with the cause `<kind> block has no upstream <source image or image>`. | **NEW** · Yes (`flow_execution_service.py:420-425`, `:669-674`, `:791-796`). |
| R-FLOW-PATCH.3 | If | If the change document is refused or does not exist, then the system shall stop the flow with the summary `change doc unresolved` and the cause `change document not found or not inside the project`. | **NEW** · Yes. |
| R-FLOW-PATCH.4 | When | When a PATCH block reads symbol entries, the system shall resolve them against its own A2L reference, else the LOAD block's, else none (S8 R-CHG-SYM.2 … .4). | **NEW** · Yes; tested (`test_tc715_project_mode_resolves_project_root_a2l`). |
| R-FLOW-PATCH.5 | If | If a PATCH block's own A2L reference is refused, missing or unreadable, then the system shall stop the flow as R-FLOW-SRC.9 and .10 state for a LOAD. | **NEW** · Yes. |
| R-FLOW-PATCH.6 | If | If the change document cannot be read, then the system shall stop the flow with the summary `change document unreadable` and the cause `[<first code>] <message>`. | **NEW** · Yes (`flow_execution_service.py:550-579`). |
| R-FLOW-PATCH.7 | If | If every entry of the document is blocked, then the system shall stop the flow with the summary `change document blocked` and the cause `[<first refusal code>] <message>`. | **NEW** · Yes (`flow_execution_service.py:580-606`). |
| R-FLOW-PATCH.8 | If | If the document applied 0 of at least 1 entry, then the system shall stop the flow with the summary `applied 0 of <n> entries` and the cause `applied 0 of <n> entries: 0x<address> <disposition>`. | **NEW** · Yes (`flow_execution_service.py:607-619`). |
| R-FLOW-PATCH.9 | If | If some entries were applied and some were not, then the system shall end the block notices with the summary `applied <k> of <n> entries, <m> not applied` and one finding `0x<address> <disposition>` per entry not applied. | **NEW** · Yes (`flow_execution_service.py:620-652`). |
| R-FLOW-PATCH.10 | When | When every entry is applied, the system shall end the block ok with the summary `applied <n> entries` (`applied 1 entry` for one). | **NEW** · Yes; tested (`test_tc_b94_22_patch_write_out_run_records_per_block_results`). |
| R-FLOW-PATCH.11 | When | When a PATCH block ends, the system shall record each entry it read (document, A2L reference, type, symbol, address range, disposition, bytes before and after) and each refusal (code, symbol, address, message) for the run's reports. | **NEW** · Yes; tested (`test_tc716_summary_entry_carries_symbol`). |
| R-FLOW-FUNNEL.1 | When | When a flow with a funnel runs a PATCH block, the system shall replace each `${NAME}` the funnel declares by its value in the document text before reading it. | **NEW** · Yes; tested (`test_tc1817_execution_substitution_and_named_notice`). |
| R-FLOW-FUNNEL.2 | If | If the document holds a `${NAME}` the funnel does not declare, then the system shall leave it unchanged and end the block notices with the finding `funnel: ${<NAME>} is not declared in the flow — the placeholder stays intact`. | **NEW** · Yes; tested (`test_tc1817_execution_substitution_and_named_notice`). |
| R-FLOW-FUNNEL.3 | While | While a flow has no funnel, the system shall read change documents unchanged. | **NEW** · Yes; tested (`test_tc1817_no_funnel_doc_passes_unchanged`). |

### S15.4 · CHECK

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-CHECK.1 | When | When a CHECK block runs, the system shall run its check document on the working image as S9 runs a check document. | **NEW** · Yes; tested (`test_tc086_2_check_reports_counts_image_intact`). |
| R-FLOW-CHECK.2 | U | The system shall leave the working image unchanged by a CHECK block. | **NEW** · Yes; tested (`test_at086a_check_passthrough_bytes_identical`). |
| R-FLOW-CHECK.3 | U | The system shall never stop the flow at a CHECK block. | **NEW** · Yes; tested (`test_tc086_4_chain_never_blocked_matrix`, `test_tc086_6_check_body_exception_never_aborts_chain`). |
| R-FLOW-CHECK.4 | When | When a CHECK block runs, the system shall give it the summary `passed=<p> failed=<f> uncheckable=<u>`. | **NEW** · Yes; tested (`test_tc086_2_check_reports_counts_image_intact`). |
| R-FLOW-CHECK.5 | If | If a check entry failed, then the system shall end the CHECK block notices with the finding `<f> check entries failed` (`1 check entry failed` for one). | **NEW** · Yes. |
| R-FLOW-CHECK.6 | If | If a CHECK block cannot run its document and its gating is advisory, then the system shall end it notices with the summary `could not check`. | **NEW** · Yes; tested (`test_tc086_5_unreadable_check_doc_non_aborting`). |
| R-FLOW-CHECK.7 | If | If a CHECK block cannot run its document and its gating is block-own-op, then the system shall end it error with the summary `check operation invalid`. | **NEW** · Yes; tested (`test_at086c_gating_flag_drives_observable_status_change`). |

### S15.5 · CRC (from S0 HLR-159, LLR-159.2; the CRC itself is S13's)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-CRC.1 | When | When a CRC block runs, the system shall compute its CRCs as S13.2 computes them, from a template read as S13 CTX-CRCCONFIG, over the working image as it stands after the blocks before it. | **NEW** · Yes; tested (`test_tc347_crc_computed_over_post_patch_image`). |
| R-FLOW-CRC.2 | When | When a CRC block writes a CRC outside the image's ranges, the system shall add those addresses to the working image. | **NEW** · Yes; tested (`test_at124a_crc_grows_image_when_output_outside_ranges`). |
| R-FLOW-CRC.3 | If | If the CRC template is refused or does not exist, then the system shall stop the flow with the summary `config unresolved` and the cause `crc config not found or not inside the project`. | **NEW** · Yes; tested (`test_at127b_escape_config_ref_rejected`). |
| R-FLOW-CRC.4 | If | If the CRC template is invalid, then the system shall stop the flow with the summary `config malformed` and the cause `crc config invalid: <first three errors, separated by "; ">`. | **NEW** · Yes; tested (`test_at126_malformed_config_fails_closed`). |
| R-FLOW-CRC.5 | If | If a CRC region holds no image byte, then the system shall stop the flow, writing no CRC, with the cause `CRC region 0x<start>-0x<end> holds 0 image bytes - nothing written`. | **NEW** · Yes (`flow_execution_service.py:843-851`). |
| R-FLOW-CRC.6 | If | If a CRC region holds some but not all of its bytes, then the system shall end the block notices with the finding `CRC: <k> of <n> region bytes absent (0x<start>-0x<end>) - the CRC covers present bytes only`. | **NEW** · Yes (`flow_execution_service.py:876-913`). |
| R-FLOW-CRC.7 | If | If a CRC block comes before every PATCH block, or the flow has none, then the system shall end it notices with the finding `CRC before PATCH: the image is finalized before any patch is applied`. | **NEW** · Yes; tested (`test_at125a_crc_before_patch_warns_but_still_runs`, `test_tc351_crc_only_flow_no_patch_warns`). |
| R-FLOW-CRC.8 | When | When a CRC block ends with no notice, the system shall end it ok with the summary `injected <n> CRC regions` (`region` for one). | **NEW** · Yes; tested (`test_at125b_crc_after_patch_does_not_warn`). |

### S15.6 · WRITE-OUT (from S0 LLR-155.6; the writing is S8.7)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-WRITE.1 | When | When a WRITE-OUT block runs, the system shall write the working image into the open project folder in its declared format, as S8.7 writes an image file. | **NEW** · Yes; tested (`test_run_flow_writeout_hex_and_s19_formats`). |
| R-FLOW-WRITE.2 | When | When a WRITE-OUT block writes S19, the system shall write 32 data bytes per record. | **NEW** · Yes (`flow_execution_service.py:681`). |
| R-FLOW-WRITE.3 | When | When a WRITE-OUT block writes S19 from an S19 source with an S0 record, the system shall write that S0 record. | **NEW** · Yes (`flow_execution_service.py:682`). |
| R-FLOW-WRITE.4 | When | When a WRITE-OUT block writes S19 from an S19 source with a terminator, the system shall write the source's terminator address in the terminator. | **NEW** · No: address 0 is written (D15-14). |
| R-FLOW-WRITE.5 | If | If the file cannot be written, then the system shall stop the flow with the summary `write failed` and the cause `write-out produced no file`. | **NEW** · Yes. |
| R-FLOW-WRITE.6 | When | When a WRITE-OUT block has written its file, the system shall read the file back and compare it with the working image. | **NEW** · Yes (`flow_execution_service.py:698`). |
| R-FLOW-WRITE.7 | If | If the file read back differs from the working image, then the system shall stop the flow with the summary `wrote <file> but read-back differs`, one diagnostic per differing run and the cause `first difference at 0x<address>`. | **NEW** · Yes (`flow_execution_service.py:699-717`). |
| R-FLOW-WRITE.8 | When | When the read-back matches, the system shall end the block ok with the summary `wrote <file>`. | **NEW** · Yes; tested (`test_run_flow_source_patch_writeout_happy_path`). |

### S15.7 · A2B diff block (from S0 HLR-014, LLR-013.3, LLR-014.1, LLR-014.2)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-A2B.1 | U | The system shall bind each A2B input either to the image after an earlier block of the same flow (`#<n>`, 1-based) or to a project ref. | **NEW** · Yes; tested (`test_tc_b94_23_binding_text_grammar`). |
| R-FLOW-A2B.2 | If | If both A2B inputs are files, then the system shall refuse the block with the reason `at least one A2B input must come from the current flow (both-external pairs would false the report)`. | **NEW** · Yes; tested (`test_tc_b94_23_binding_validation_matrix`). |
| R-FLOW-A2B.3 | If | If an A2B input names a block that is not earlier in the flow, then the system shall refuse the block with the reason `<image_a or image_b>: flow binding references block <n>, but only <k> upstream block(s) exist in this flow`. | **NEW** · Yes; tested (`test_tc_b94_23_binding_validation_matrix`). |
| R-FLOW-A2B.4 | If | If an A2B input names an A2B-DIFF, EXT-STEP or REPORT block, then the system shall refuse the block with the reason `<image_a or image_b>: block <n> (<kind>) produces no image output`. | **NEW** · Yes; tested (`test_tc_b94_23_binding_validation_matrix`). |
| R-FLOW-A2B.5 | When | When an A2B block runs, the system shall write a flow-A2B report of image A against image B into `<project>/reports/`. | **NEW** · Yes; tested (`test_tc_b94_24_a2b_report_states_each_inputs_provenance`). |
| R-FLOW-A2B.6 | U | The system shall name in the flow-A2B report each input's origin: the file's name and path, or `block <n> (<kind>).out`. | **NEW** · Yes; tested (`test_tc_b94_24_a2b_report_states_each_inputs_provenance`, `test_tc_b94_25_hostile_file_name_in_emitted_report`). |
| R-FLOW-A2B.7 | U | The system shall leave the working image unchanged by an A2B block. | **NEW** · Yes (`flow_execution_service.py:920-1058`). |
| R-FLOW-A2B.8 | If | If an A2B input file is refused, missing or unreadable, then the system shall stop the flow with the cause `A2B image <A or B> file not found or not inside the project` or `A2B image <A or B>: <error type>: <message>`. | **NEW** · Yes (`flow_execution_service.py:946-973`; D15-5). |
| R-FLOW-A2B.9 | If | If the block an A2B input names produced no image, then the system shall stop the flow with the cause `A2B image <A or B>: flow block <n> produced no image (failed or skipped upstream)`. | **NEW** · Yes; tested (`test_tc_b94_24_upstream_failure_yields_no_report`). |
| R-FLOW-A2B.10 | If | If the flow-A2B report cannot be written, then the system shall end the block error with the summary `report write failed` and keep the flow running. | **NEW** · Yes (`flow_execution_service.py:1041-1053`; D15-5). |
| R-FLOW-A2B.11 | When | When the flow-A2B report is written, the system shall end the block ok with the summary `wrote reports/<file>`. | **NEW** · Yes. |

### S15.8 · External step

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-EXT.1 | If | If an external step is not confirmed, then the system shall pause the flow with the summary `paused - waiting for a human: <command or instruction> '<text>' \| LOG '<log>' + OUTPUT '<output>' pending`. | **NEW** · Yes; tested (`test_tc1804_unconfirmed_run_pauses_and_skips_downstream`). |
| R-FLOW-EXT.2 | When | When a confirmed external step runs, the system shall read a relative log path and a relative output path under the open project folder. | **NEW** · Partly: a relative output path is read from the start folder (D15-17). |
| R-FLOW-EXT.3 | If | If a confirmed step's log file does not exist, then the system shall stop the flow with the summary `external step refused` and the cause `log '<log>' does not exist - the log is mandatory evidence, never optional`. | **NEW** · Yes; tested (`test_tc1804_confirmed_run_refuses_missing_evidence`). |
| R-FLOW-EXT.4 | If | If a confirmed step's output file does not exist, then the system shall stop the flow with the summary `external step refused` and the cause `output '<output>' does not exist - run the external step before confirming`. | **NEW** · Yes; tested (`test_tc1804_confirmed_run_refuses_missing_evidence`). |
| R-FLOW-EXT.5 | When | When a confirmed step's log and output exist, the system shall copy the output into the open project folder as S5 copies a file. | **NEW** · Yes; tested (`test_tc1804_confirmed_run_copies_output_into_session`). |
| R-FLOW-EXT.6 | If | If the copy is refused, then the system shall stop the flow with the summary `external step copy failed` and the cause `<error type>: <message>`. | **NEW** · Yes. |
| R-FLOW-EXT.7 | When | When the copy succeeds, the system shall end the block ok with the summary `log '<log file>' received · output copied to <copy name> (session)`. | **NEW** · Yes; tested (`test_tc1804_confirmed_run_copies_output_into_session`). |
| R-FLOW-EXT.8 | U | The system shall leave the working image unchanged by an external step. | **NEW** · Yes. |

### S15.9 · Run status (CTX-FLOW)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-STATUS.1 | If | If a block stopped the flow, then the system shall end the run error. | **NEW** · Yes; tested (`test_tc087_2_three_way_rollup`). |
| R-FLOW-STATUS.2 | If | If no block stopped the flow and a block paused it, then the system shall end the run paused. | **NEW** · Yes; tested (`test_tc1804_unconfirmed_run_pauses_and_skips_downstream`). |
| R-FLOW-STATUS.3 | If | If the flow neither stopped nor paused and a block ended notices or error or has a finding, then the system shall end the run completed-with-issues. | **NEW** · Yes; tested (`test_at087a_issues_distinct_from_failed`). |
| R-FLOW-STATUS.4 | When | When the flow neither stopped nor paused and every block ended ok without a finding, the system shall end the run ok. | **NEW** · Yes; tested (`test_at087b_clean_run_is_ok`). |
| R-FLOW-STATUS.5 | When | When a run ends, the system shall record the working image's ranges, and the ranges before the first CRC block. | **NEW** · Yes; tested (`test_tc088_image_ranges_carries_final_footprint`). |

### S15.10 · The flow report (CTX-FLOWREPORT; from S0 LLR-143.1, LLR-156.4)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-RPT.1 | When | When a REPORT block runs, the system shall write a flow report of the blocks before it into `<project>/reports/`. | **NEW** · Yes; tested (`test_at001_report_written_naming_every_executed_block`, `test_at005_report_covers_only_blocks_before_it`). |
| R-FLOW-RPT.2 | U | The system shall write the sections of CTX-FLOWREPORT in their order. | **NEW** · Yes; tested (`test_tc001u_sections_present_in_order`). |
| R-FLOW-RPT.3 | If | If the flow stopped before the REPORT block, then the system shall give the report the status FAILED. | **NEW** · Yes; tested (`test_tc013a_record_error_shaped_abort_is_failed`, `test_at009_aborted_run_still_writes_a_failed_report`). |
| R-FLOW-RPT.13 | If | If the flow did not stop and a block before the report ended notices or error, has a finding, or left an entry not applied or refused, then the system shall give the report the status COMPLETED WITH ISSUES. | **NEW** · Yes; tested (`test_tc013b_non_aborting_error_is_issues_not_failed`, `test_tc013_clean_and_issues_labels`). |
| R-FLOW-RPT.14 | When | When every block before the report ended ok without a finding and no entry was left unapplied or refused, the system shall give the report the status CLEAN. | **NEW** · Yes; tested (`test_tc013_clean_and_issues_labels`). |
| R-FLOW-RPT.4 | If | If the flow is paused when a REPORT block runs, then the system shall give the report the status PAUSED. | **NEW** · No: the report says CLEAN (D15-11). |
| R-FLOW-RPT.5 | U | The system shall list every applied entry in Change attribution, every entry not applied in Not applied and every refusal in Refusals. | **NEW** · Yes; tested (`test_tc716_flow_report_change_attribution_section`, `test_tc716_change_attribution_empty_renders_never_absent`). |
| R-FLOW-RPT.6 | U | The system shall write every text taken from a file or typed by the operator into the report as inert Markdown. | **NEW** · Yes; tested (`test_tc004_hostile_payload_injects_no_live_structure`, `test_tc004_ledger_row_column_count_preserved_under_hostile_summary`). |
| R-FLOW-RPT.7 | U | The system shall write paths into the flow report relative to the project folder, never absolute. | **NEW** · Yes; tested (`test_tc016_written_paths_render_relative_not_absolute`, `test_tc016b_exception_diagnostics_do_not_leak_absolute_paths`). |
| R-FLOW-RPT.8 | U | The system shall keep the flow report within the limits of CTX-FLOWREPORT. | **NEW** · Yes; tested (`test_tc015_cell_truncation_boundary_pair`, `test_tc015_findings_cap_suppresses_with_a_visible_note`, `test_tc015_budget_actually_fires_and_reports_the_truncation`). |
| R-FLOW-RPT.9 | U | The system shall write each footprint range as its first and last address and the byte total as the number of bytes in the ranges. | **NEW** · No: the end is one past the last byte and each range counts one extra byte (D15-10). |
| R-FLOW-RPT.10 | If | If the flow report cannot be written, then the system shall end the REPORT block error with the summary `report write failed` and keep the flow running. | **NEW** · Yes; tested (`test_at008_report_write_failure_degrades_without_aborting`). |
| R-FLOW-RPT.11 | When | When the flow report is written, the system shall end the REPORT block ok with the summary `wrote reports/<file>`. | **NEW** · Yes; tested (`test_at004_ledger_shows_the_written_report_path`). |
| R-FLOW-RPT.12 | U | The system shall write the flow report and the chain-set report as S12 R-TUI-097.1 states: UTF-8 with LF line ends on every host. | **NEW** · Yes; tested (`test_at173b_flow_report_bytes_equal_the_encoder_output`). |

### S15.11 · Flow files (CTX-FLOWFILE; from S0 HLR-015, LLR-015.1, LLR-015.2)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-FILE.1 | When | When the operator saves a flow, the system shall write it as a flow file under its saved name. | **NEW** · Yes; tested (`test_save_flow_json_sanitises_and_roundtrips`). |
| R-FLOW-FILE.2 | If | If a flow file of that saved name exists, then the system shall save under `<name>_<N>.json` with the lowest free N from 1. | **NEW** · Partly: N starts at 2 (D15-15); tested (`test_tc_b94_04_template_save_reload_and_dedup`). |
| R-FLOW-FILE.3 | If | If the typed name is empty after cleaning, then the system shall write no file. | **NEW** · Yes; tested (`test_save_flow_json_empty_after_clean_writes_nothing`). |
| R-FLOW-FILE.4 | U | The system shall keep every field of every block kind through a save and a load. | **NEW** · Yes; tested (`test_roundtrip_all_kinds_field_by_field`, `test_tc_b94_21_roundtrip_one_of_each_kind_incl_a2b`). |
| R-FLOW-FILE.5 | If | If a flow file breaks a rule of CTX-FLOWFILE, then the system shall load nothing from it. | **NEW** · Yes; tested (`test_security_battery_dict`, `test_security_battery_file`, `test_tc_b97_62_nul_in_each_block_field_refuses_the_flow`). |
| R-FLOW-FILE.6 | If | If a flow file breaks rules of CTX-FLOWFILE, then the system shall give one finding per broken rule with its code. | **NEW** · Yes; tested (`test_reject_arm_census`). |
| R-FLOW-FILE.7 | When | When the system loads a flow file, the system shall check its size before it reads it. | **NEW** · Yes; tested (`test_size_probed_before_parse`). |
| R-FLOW-FILE.8 | When | When the system loads a flow file, the system shall open none of the files its refs name. | **NEW** · Yes; tested (`test_no_open_nonexistent_but_safe_ref`). |
| R-FLOW-FILE.9 | When | When the operator imports a flow file, the system shall copy it into the flows home as S5 copies a file, with a 1 MiB limit. | **NEW** · Yes; tested (`test_import_copies_then_loads_the_copy_not_the_source`, `test_import_over_size_cap_refused_at_copy_step`). |
| R-FLOW-FILE.10 | U | The system shall list the saved flows as the file names of the flows home without `.json`, sorted. | **NEW** · Yes; tested (`test_list_saved_flows_returns_sorted_stems`). |

**(from batch-100 HLR-171b: LLR-171.4i)**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-FILE.11 | If | If the flows home resolves to a folder outside the work area, then the system shall save no flow file. | No: the save creates the flows home and writes with no containment check (`flow_persistence_service.py:1022-1032`, unchanged since 093a7c0), so a `flows/` link or junction to an outside folder receives the file; untested (D15-18). |

### S15.12 · Chain-set runs (CTX-CHAIN; from S0 HLR-019, LLR-018.2, LLR-019.1, LLR-019.2, LLR-155.5)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-CHAIN.1 | When | When a chain set runs, the system shall run each lane's flow with that lane's bound LOAD refs. | **NEW** · Yes; tested (`test_tc_b94_28_run_consumes_each_chains_own_bindings`). |
| R-FLOW-CHAIN.2 | U | The system shall leave the lane's flow file unchanged by its bound refs. | **NEW** · Yes (`flow_execution_service.py:1660-1676`). |
| R-FLOW-CHAIN.3 | When | When a chain set runs in sequential mode, the system shall run the lanes one after the other in lane order. | **NEW** · Yes; tested (`test_at_b94_22_default_run_is_strictly_sequential`). |
| R-FLOW-CHAIN.4 | When | When a chain set runs in parallel mode, the system shall start every lane before it waits for any. | **NEW** · Yes; tested (`test_tc_b94_05_parallel_dispatch_runs_chains_concurrently`, `test_at_b94_21_parallel_mode_overlaps_isolates_and_captures`). |
| R-FLOW-CHAIN.5 | If | If a lane stops or raises, then the system shall still run the other lanes. | **NEW** · Yes; tested (`test_at_b94_21_parallel_mode_overlaps_isolates_and_captures`). |
| R-FLOW-CHAIN.6 | U | The system shall report the lanes' outcomes in lane order. | **NEW** · Yes (`flow_execution_service.py:1866-1871`). |
| R-FLOW-CHAIN.7 | If | If two or more lanes write a WRITE-OUT file of the same name, ignoring case, then the system shall run no lane and give the reason `Chain set not run: lanes '<lane>', '<lane>' <both or all> write '<name>' — give each lane its own output name. Nothing written.` | **NEW** · Yes (`flow_execution_service.py:1813-1823`). |
| R-FLOW-CHAIN.8 | If | If a chain set has no lane, then the system shall run nothing and give the reason `no chains in set - nothing was executed`. | **NEW** · Yes. |
| R-FLOW-CHAIN.9 | When | When the operator confirms a lane's external step, the system shall run that lane again with every step confirmed so far in its current wait. | **NEW** · Yes; tested (`test_tc1804_fx_lane_pause_confirm_rerun`). |
| R-FLOW-CHAIN.10 | U | The system shall give each report of a run a name no other file holds, also when lanes write reports in the same second. | **NEW** · No: names are probed, then written (D15-12). |

### S15.13 · The chain-set report (CTX-FLOWREPORT; from S0 HLR-020, LLR-020.2, LLR-156.3)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-CHAIN.11 | When | When a chain set has run, the system shall write a chain-set report into `<project>/reports/`. | **NEW** · Yes; tested (`test_tc_b94_30_chain_set_report_provenance_lines`). |
| R-FLOW-CHAIN.12 | U | The system shall write the sections of the chain-set report of CTX-FLOWREPORT in their order. | **NEW** · Yes; tested (`test_tc_b94_30_compose_is_deterministic_and_md_safe`). |
| R-FLOW-CHAIN.13 | U | The system shall write one Input provenance line per LOAD ref each lane read, with its resolved path, or an empty path when the ref was refused. | **NEW** · Yes; tested (`test_tc_b94_30_chain_set_report_provenance_lines`). |
| R-FLOW-CHAIN.14 | U | The system shall record the run's mode in the chain-set report. | **NEW** · Yes; tested (`test_tc_b94_05_mode_capture_in_run_record_and_report`). |
| R-FLOW-CHAIN.15 | U | The system shall list per lane its written files, its entries not applied, its refusals and its findings, or `none`. | **NEW** · Yes (`flow_execution_service.py:1961-2016`). |
| R-FLOW-CHAIN.16 | U | The system shall show each lane's status in the Chain ledger with the mark `✓` ok, `◈` completed-with-issues, `✗` error or `□` paused. | **NEW** · Partly: paused shows `·` (D15-11). |
| R-FLOW-CHAIN.17 | U | The system shall write every lane name, set name, ref and message into the chain-set report as inert Markdown. | **NEW** · Yes; tested (`test_tc_b94_30_compose_is_deterministic_and_md_safe`). |
| R-FLOW-CHAIN.18 | If | If the chain-set report cannot be written, then the system shall keep the lanes' outcomes and give the reason `chain-set report write failed: <error type>: <message>`. | **NEW** · Yes. |

### S15.14 · Chain-set files (CTX-CHAIN; from S0 HLR-021, LLR-021.1, LLR-021.2)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-SET.1 | When | When the operator saves a chain set, the system shall write a chain-set file with each lane's name, template, bound LOAD refs and last written files. | **NEW** · Yes; tested (`test_tc_b94_31_chain_set_serializer_round_trip`). |
| R-FLOW-SET.2 | If | If the chain set has no lane or its name is empty after cleaning, then the system shall write no file. | **NEW** · Yes; tested (`test_tc_b94_31_empty_set_and_hostile_sets_fail_closed`). |
| R-FLOW-SET.3 | If | If a chain-set file of that saved name exists, then the system shall save under `<name>_<N>.json` with the lowest free N from 1. | **NEW** · Partly: N starts at 2 (D15-15). |
| R-FLOW-SET.4 | If | If a chain-set file breaks a rule of CTX-CHAIN, then the system shall load nothing from it. | **NEW** · Yes; tested (`test_tc_b94_31_empty_set_and_hostile_sets_fail_closed`, `test_tc_b97_62_p36_nul_input_ref_refuses_the_set`). |
| R-FLOW-SET.5 | When | When the system loads a chain-set file, the system shall load each lane's template from the flows home. | **NEW** · Yes; tested (`test_at_b94_24_service_half_reloaded_set_reruns`). |
| R-FLOW-SET.6 | U | The system shall list the saved chain sets as the file names of the flowsets home without `.json`, sorted. | **NEW** · Yes (`flow_persistence_service.py:1555-1560`). |

**(from batch-100 HLR-171b: LLR-171.4j)**

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FLOW-SET.7 | If | If the flowsets home resolves to a folder outside the work area, then the system shall save no chain-set file. | No: the save creates the flowsets home and writes with no containment check (`flow_persistence_service.py:1498-1508`, unchanged since 093a7c0); untested (D15-18). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D15-1 | R-TUI-099's batch record: the binding story, the non-claims, the node table, the golden and falsifiability notes, "Frozen-engine diff = 0". | Out of the requirements; they stay in the batch records. |
| D15-2 | The chapter was incomplete: one row, for a feature the operator cannot reach, while the engine runs eight block kinds, three reports, flow files and chain sets. S0's table held the rest as batch rows. | NEW rows S15.1 … S15.14, marked **NEW**; S0's rows they restate are listed in each sub-heading. |
| D15-3 | R-TUI-059 names the run engine and the model; rule D-9 puts them with the behaviour. | Engine rows R-TUI-059.1 … .6 here; the screen rows stay in S16. |
| D15-4 | WRITE-OUT writes into the project folder itself (`flow_execution_service.py:679-683`), and a confirmed external step copies its output there (`:1107-1110`). An S19 or Intel HEX file there is a project variant (S11 CTX-PROJECT). | Keep; rows say "the open project folder" (R-FLOW-WRITE.1, R-FLOW-EXT.5). S11 is told. |
| D15-5 | An A2B input that fails stops the flow (`:946-1002`); a flow-A2B report that fails to write does not (`:1041-1053`). | Keep both: a missing input is a wrong flow; a failed report write is not (R-FLOW-A2B.8, .10). |
| D15-6 | Lanes sharing a WRITE-OUT name are refused in both modes (`:1813-1823`), although only parallel lanes overwrite each other. | Keep (one rule is simpler; R-FLOW-CHAIN.7). |
| D15-7 | Runs get no session A2L or MAC (`app.py:2896`, `:3111`): symbol entries resolve only against a declared A2L reference (S0 HLR-142: no implicit A2L). | Keep (R-FLOW-RUN.2). |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D15-8 | R-TUI-099: `run_flow_over_variants`, `flow_fused_report_service.py`, `FusedFlowRunResult`, `VariantRunOutcome`, `FlowContext.variant` / `defer_report`, `_bound_source_ref`'s variant arm, `FLOW_SCOPE_*`, `FlowBuilderPanel.RunRequested.scope` and `render_fused_result` are reachable only from tests since batch-97 (`app.py:2857-2861`). One lane per variant in Flow Execution replaces it. | Delete the requirement, the code and `test_flow_multi_image.py`, `test_flow_multi_image_ui.py`, `test_flow_report_fusion.py` (not used). |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D15-10 | The flow report's footprint (`flow_report_service.py:229-235`) adds `end − start + 1` for ranges whose end is already one past the last byte (S1 CTX-IMAGE), and prints that end. The golden `tests/goldens/batch71/ac6-unscoped-flow-report.md:33-34` pins `0x00001000–0x00001004  (5 bytes)` for the 4-byte record of `test_flow_report_ac6_golden.py:64-65`. | Count `end − start`, print the last address; regenerate the golden (R-FLOW-RPT.9). |
| D15-11 | A REPORT block runs while the flow is paused (`flow_execution_service.py:289`), and the report status has no paused arm (`flow_report_service.py:282-302`), so it says CLEAN while blocks were skipped. The chain-set ledger has no glyph for paused (`flow_execution_service.py:1557-1561`) and prints `·`. | Report status PAUSED; ledger mark `□` (R-FLOW-RPT.4, R-FLOW-CHAIN.16). |
| D15-12 | The flow report (`flow_report_service.py:613-614`), the chain-set report (`flow_execution_service.py:2034-2041`, `:2089-2090`) and the flow-A2B report probe for a free name, then write. Parallel lanes that report in the same second can pick the same name and one report replaces the other. | Claim the name with an exclusive create, as S0 HLR-155's placement does (R-FLOW-CHAIN.10). |
| D15-14 | WRITE-OUT passes the source's S0 record but not its terminator address (`flow_execution_service.py:679-683`), so every S19 output starts at 0 (S8 D8-29 left this to S15). | Write the source's terminator address, as S8 R-S19-EMIT.11 does for save-back (R-FLOW-WRITE.4). |
| D15-15 | Saved flow and chain-set names take `_2`, `_3` … on a clash (`flow_persistence_service.py:1026-1030`, `:1501-1506`); every other copy in the app takes the lowest free number from 1 (S5 numbered name). | From 1, as S5 (R-FLOW-FILE.2, R-FLOW-SET.3). |
| D15-18 | Batch-100 LLR-171.4i and .4j (HLR-171b, from its security finding SEC-5) require that a flow and a chain set are not saved outside this work area. The batch left them out of Inc 8b (ledger LED .77, orchestrator ruling Q1) and routed them to its code backlog; at 570b4b5 `save_flow_json` and `save_chain_set` are unchanged: `mkdir(parents=True, exist_ok=True)` then `write_text` under `<project>/flows/` and `<project>/flowsets/` with no containment check (`flow_persistence_service.py:1022-1032`, `:1498-1508`). A `flows/` junction to an outside folder receives the file (the batch's own probe). TC-B100-62 holds no node for them (its nodes test the manifest write). | Refuse the save when the home resolves outside the work area, with the shared destination guard the manifest write uses (S11 R-MAN-WRITE-001.5), and add the two tests (R-FLOW-FILE.11, R-FLOW-SET.7). The refusal's status text is written with the change, in the style of the project refusals (S11 CTX-SAVE). |
| D15-17 | A confirmed external step reads a relative log path under the project folder (`flow_execution_service.py:1089-1091`) but a relative output path from the start folder (`:1092`). | Both under the project folder (R-FLOW-EXT.2). |

**Prototype first**: none (the engine has no screen; S16 holds the visual decisions).

**Passed to other groups**

- **S8**: WRITE-OUT writes through S8.7 and verifies (R-FLOW-WRITE.1, .6); the terminator decision for flows is D15-14.
- **S9**: CHECK runs the S9.1 engine (R-FLOW-CHECK.1).
- **S11**: flow outputs and confirmed external outputs land in the project folder and become variants (D15-4); the project-ref rules are S11's manifest-entry rules; `flows/`, `flowsets/`, `reports/` are among S11's reserved homes.
- **S12** (absorbed): R-TUI-097.1 (UTF-8, LF) is S12's and is cited (R-FLOW-RPT.12); the flow report uses S12's report name and byte budget, so the Reports dialog lists it.
- **S13** (absorbed): the flow CRC arm reads S13's template (CTX-CRCCONFIG), computes by S13.2 and gives S13.4b's coverage notes (R-FLOW-CRC.1 … .8); S13's D13-20, 21, 22 and 24 change its results too, with no row change here.
- **S14**: the flow-A2B report is a diff report (S14 CTX-DIFFREPORT); the last chain-set run's written files feed D14-18.
- **S16**: every screen that starts these runs, shows their results and edits flows and chain sets; the A2L reference field (S0 HLR-142) and the file-format choice are S16's (D16-25, D16-11).
- **S0**: pointers from HLR-014, 015, 019, 020, 021, 142, 143 (LLR-143.1), 156, 159 (flow arm) and LLR-013.3, 014.1, 014.2, 015.1, 015.2, 018.2, 019.1, 019.2, 020.2, 021.1, 021.2, 142.1, 154.3, 155.5, 155.6, 156.1 … 156.4, 159.2 to S15; R-TUI-099 is deleted (D15-8).

---

**Received from later groups** (after all groups were written)

- S15.1 (S8: the flow's A2L for symbol entries; WRITE-OUT through S8.7 with verify) → covered by R-FLOW-PATCH.4, R-FLOW-WRITE.1, .6.
- S15.2 (S9: the CHECK step runs the S9 engine) → covered by R-FLOW-CHECK.1.
- S15.3 (S12: UTF-8 / LF for the flow report) → covered by R-FLOW-RPT.12.
- S15.4 (S14: the flow-A2B report row; the last run's written files) → covered by R-FLOW-A2B.5, .11 and CTX-FLOWREPORT; each Flow Execution lane keeps the files its last run wrote (`flow_screens.py:3455`) and shows them in its head (S16 CTX-FXSCREEN, R-FX-RUN.8).
- S15.5 (S16: run, file and report behaviour; the Intel HEX choice and the add-time check) → covered: S16 R-FB-ADD.11 (D16-10) and R-FB-ADD.12 (D16-11) apply S15 CTX-FLOWFILE.

**Reconciled with batch-100 (s19_app 570b4b5)**

- From the sweep (batch-100 LLR-171.4i, .4j, not implemented at 570b4b5): rows added R-FLOW-FILE.11 and R-FLOW-SET.7 (a flow or a chain set is not saved outside the work area), both No; decision D15-18 (code change). `flow_persistence_service.py` did not change between 093a7c0 and 570b4b5; the other S15 rows keep their cells.
- Rows changed or retired: none. Decisions superseded: none.

## 6. Counts

| | Old S15 | Strict |
|---|---:|---:|
| Requirement statements | 1 row (+ the engine half of R-TUI-059) | 129 rows (121 NEW, 2 from batch-100) |
| Statements the code contradicts or that are not product behaviour | 1 (R-TUI-099 unreachable) | 0 |
| Rows by form: U / When / While / If / Where | — | 28 / 44 / 1 / 56 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 15 (7 follow the code or move, 1 remove, 7 correct a defect; numbers not contiguous) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.
