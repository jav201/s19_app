# CRC check + operator-confirmed write flow — batch-12 (CRC_F2)

> Phase 6 diagram (docs-writer). Covers BOTH paths: the non-mutating **check** (US-011) and the operator-confirmed **write/inject** (US-012). Symbols verified against `s19_app/tui/operations/crc.py`, `crc_config.py`, and `screens.py` (2026-06-17).

```mermaid
flowchart TD
    start([Operator: Operations modal -> CRC]) --> cfg[/"Edit JSON config in #operation_config<br/>pre-filled with DUMMY_CONFIG_TEXT"/]
    cfg --> exec{{"Execute"}}

    %% ---- CHECK PATH (non-mutating, US-011) ----
    exec --> parse["parse_crc_config(text)<br/>(collect-don't-abort)"]
    parse -->|"one error -> (None, [err])"| cfgerr["Surface 1 notice<br/>run NO computation"]
    cfgerr --> stop1([Stop: nothing checked])
    parse -->|"valid CrcConfig"| worker["_run_crc_worker<br/>@work(thread=True, group=crc_operation)"]
    worker --> compute["compute_region_crc per region<br/>(engine: crc32_stream / region_segments)"]
    compute --> readstored["read_stored_crc_le<br/>(4-byte LE at output_address)"]
    readstored --> compare{"stored == computed ?"}
    compare -->|"present & equal"| rowmatch["CrcRegionResult matched=True"]
    compare -->|"present & differ"| rowmiss["CrcRegionResult matched=False"]
    compare -->|"any of 4 bytes absent"| rownone["CrcRegionResult matched=None<br/>(no stored value)"]
    rowmatch --> rows["Per-region rows in op-result view<br/>(LLR-002.4); mem_map UNCHANGED"]
    rowmiss --> rows
    rownone --> rows

    %% ---- WRITE PATH (operator-confirmed, US-012) ----
    rows --> writebtn{{"Write CRC button"}}
    writebtn --> confirm{"ConfirmWriteScreen<br/>(#confirm_write_ok / #confirm_write_cancel)"}
    confirm -->|"Cancel / decline"| nowrite["Write NO file<br/>loaded snapshot unchanged"]
    nowrite --> stop2([Stop: 0 files written])
    confirm -->|"Confirm"| inject["inject_crcs -> WORKING COPY<br/>4-byte LE at output_address;<br/>extend mem_map+ranges on gap<br/>(original never mutated)"]
    inject --> emit["emit_s19_from_mem_map(working_mem, working_ranges)<br/>stage under workarea/temp/"]
    emit --> place["copy_into_workarea(staged, crc/)<br/>containment + name-dedup"]
    place -->|"escapes work area"| contain["1 collected finding<br/>write NO file"]
    contain --> stop3([Stop: refused, 0 files])
    place -->|"contained"| verify["verify_written_image(placed, working_mem, s19)<br/>reader-as-oracle vs INJECTED map"]
    verify --> verdict{"VerifyResult.status"}
    verdict -->|"verified (empty runs)"| okrows["Outcome rows: emitted path +<br/>written=True + verified"]
    verdict -->|"mismatch (>=1 run)"| missrows["Outcome rows: emitted path +<br/>mismatch + drift named"]
    okrows --> done([Persistent record =<br/>emitted modified S19 + OperationResult])
    missrows --> done
```

## Guard-rails (callout)

- **No write without confirmation.** The inject path runs only after an explicit per-execution **Confirm** on `ConfirmWriteScreen` (`screens.py:502`, buttons `#confirm_write_ok` / `#confirm_write_cancel`). Decline → 0 files, loaded snapshot untouched (LLR-003.4 / TC-124).
- **Check never mutates.** The check path reads `mem_map` only; `output.mem_map == input.mem_map` is asserted (LLR-002.2). Inject works on a fresh working copy — the originally loaded `mem_map`/`ranges` are never mutated (LLR-003.1).
- **Contained write path only.** The emit is staged under `.s19tool/workarea/temp/` and placed via `copy_into_workarea`, which enforces the real containment seam (`is_relative_to(workarea_root)` + reparse-point check) and name-dedups on collision. A target outside the work area is a collected finding with no file written — collect-don't-abort (LLR-003.2 / `test_write_outside_workarea_collects_finding_and_writes_no_file`).
- **Reader-as-oracle, not self-compare.** Verify re-reads the emitted S19 with the production parser and diffs against the **injected** working copy (the same map handed to `emit_s19_from_mem_map`), so `verified` proves the round-trip; a corrupted write yields `mismatch` with non-empty diff runs (LLR-003.3 / TC-123).
- **Frozen engine reused import-only.** `range_index`, `emit_s19_from_mem_map`, `verify_written_image`, and the workspace containment helpers are imported, never edited; `test_engine_unchanged.py` is CLEAR.
- **Worker-thread, not UI-thread (R-6).** CRC compute runs on `@work(thread=True, group="crc_operation")` (`_run_crc_worker`, `screens.py:878`); a stale/superseded worker result is dropped via the dispatch token, not surfaced over a newer error.

*UTF-8, no BOM. Phase 6 (docs-writer).*
