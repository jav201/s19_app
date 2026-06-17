# Functionality — s19_app — Batch 2026-06-16-batch-12 (CRC_F2)

> Phase 6 artifact. Owner: `docs-writer`. Audience: operator (calibration/firmware engineer) + technical stakeholder. Purpose: understand what the CRC operation does, how to drive it in the TUI, and where its honest boundaries are.

## At a glance (read first)

- **What this batch added:** the first real *operation* in the s19_app operations framework — **CRC_F2**, a CRC32 region check-and-inject tool for loaded Motorola S19 files. It computes a CRC32 over one or more configured memory regions, compares each against the 4-byte value already stored in the file (the **check**), and — only on explicit operator confirmation — writes the computed CRCs back, emits a modified S19, and re-reads it to prove the write (the **inject**).
- **Capabilities:** non-mutating per-region CRC **check** (US-011) · operator-confirmed **inject + modified-S19 emit + verify** (US-012) · external JSON config for all CRC parameters + region geometry · dummy-pre-filled, editable config surface in the TUI.
- **How to reach it:** launch `s19tui`, load an S19, open the Operations modal, pick **CRC**, edit the pre-filled JSON config, **Execute** to check, then optionally **Write CRC** → confirm.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Detail (reference)

### What the operation does

CRC_F2 answers two operator questions about a loaded S19 firmware image:

1. **Check (default, US-011):** "Are this file's CRC fields already correct?" For each configured region it CRCs the region's present bytes and compares the result against the 4-byte little-endian value the file currently stores at that region's *output address*. It reports `MATCH` / `MISMATCH` / `no stored value` per region and **changes nothing** — zero mutation is the safety guarantee that makes the check risk-free.
2. **Inject (operator-confirmed, US-012):** "Produce a corrected image." On an explicit confirmation it writes each computed CRC as 4 little-endian bytes at its output address (extending the image if the address sits in a gap), emits a *new* modified S19 into a contained work area, then re-reads that file with the production parser and confirms the bytes round-tripped. The check is non-destructive; the inject is gated behind a two-stage confirmation and never overwrites the loaded snapshot.

The CRC engine follows the operator's FR1–FR9 draft exactly: ascending-address ordering (FR2), region filtering (FR3), contiguous-segment reconstruction splitting on any gap with no bytes inserted for gaps (FR4/FR7), a single non-resetting CRC state across the concatenated segments (FR5/FR8), and a final XOR (FR9). The default convention is zlib/PKZIP CRC-32, so with default parameters the engine reproduces `zlib.crc32` exactly — that equality is the gating known-answer test (`crc32(b"123456789") == 0xCBF43926`).

### How to use it in the TUI

The operation is **TUI-only** this batch (the CLI `ops` subcommand stays deferred):

1. `s19tui --load examples/case_00_public/prg.s19` (or load from inside the app).
2. Open the **Operations** modal and select **CRC** (`OperationsScreen`, operation id `"crc"`). Only the CRC operation shows the config editor + Write button; the placeholder operations don't.
3. The config editor (`#operation_config`) is **pre-filled with `DUMMY_CONFIG_TEXT`** — fake poly/init/ranges/output-addresses that parse cleanly, there purely as format guidance. Edit the fields to your firmware's real values (or paste a real config — see config schema below).
4. **Execute** → the edited JSON is parsed (`parse_crc_config`); on a parse/structure error the surface shows one notice and runs **no** computation. On success the CRC runs on a background **worker thread** (R-6, `@work(thread=True)`), and one **per-region row** appears showing the output address, computed CRC, stored value, and the `MATCH` / `MISMATCH` verdict.
5. To inject: press **Write CRC**. A **`ConfirmWriteScreen`** modal appears (Confirm / Cancel).
   - **Cancel** → no file is written, the loaded image is untouched.
   - **Confirm** → the computed CRCs are injected into a working copy, a modified S19 is emitted into the contained work area, the file is re-read and verified, and the outcome rows (emitted path + `written` + `verified`/`mismatch`) render in the result surface.

### Config schema (`CrcConfig` / `CrcRegion`)

All CRC parameters and region geometry come from JSON — never hard-coded, never committed real. Parsed by `read_crc_config` (file path) or `parse_crc_config` (TUI editor text) into a frozen `CrcConfig`. Integer fields accept a hex string (`"0x04C11DB7"`) or a native JSON integer.

| Field | Type | Meaning |
|-------|------|---------|
| `polynomial` | int (hex or int) | CRC generator polynomial. Default `0x04C11DB7`. |
| `init` | int | Initial register value. Default `0xFFFFFFFF`. |
| `reverse` | bool | `true` = standard reflected-input/reflected-output (refin/refout) — the zlib/PKZIP convention. |
| `final_xor` | int | Value XORed into the final register (xorout). Default `0xFFFFFFFF`. |
| `regions` | list of `CrcRegion` (≥1) | The CRC regions, in file order. |
| `regions[].start` | int | Inclusive region start address. |
| `regions[].end` | int | Exclusive region upper bound (half-open, matching `LoadedFile.ranges`). |
| `regions[].output_address` | int | Where the region's 4-byte LE CRC is read (check) or written (inject). |

Dummy template (committed at `examples/crc_config.example.json`, fake values only):

```json
{
  "polynomial": "0x04C11DB7",
  "init": "0xFFFFFFFF",
  "reverse": true,
  "final_xor": "0xFFFFFFFF",
  "regions": [
    { "start": "0x00010000", "end": "0x00020000", "output_address": "0x0001FFFC" },
    { "start": "0x00020000", "end": "0x00030000", "output_address": "0x0002FFFC" }
  ]
}
```

The 4-byte little-endian storage codec is **fixed** (not parameterized): byte `i` at `output_address + i` is `(crc >> (8*i)) & 0xFF`.

### Config sourcing posture (honest)

- The config file is resolved via `workspace.resolve_input_path` and read under the shared `READ_SIZE_CAP_BYTES` (256 MB) cap, mirroring `read_change_document`.
- The reader is **collect-don't-abort**: an unresolvable path, an over-cap file, malformed JSON, or a missing/invalid field each returns exactly one collected error and **no** config — it never raises and never runs the CRC.
- The config *file read* is **uncontained by design** (F-S-02): an absolute path is honored verbatim, the same posture as `read_change_document`, accepted because it is read-only, operator-supplied, size-capped, and never written back. (Contrast the *write* path below, which **is** contained.)

### Seams / extension points

| Seam | Where | Why it matters |
|------|-------|----------------|
| Headless CRC engine | `crc.py` (`crc32_stream`, `region_segments`, `compute_region_crc(s)`, `check_regions`, `inject_crcs`, `write_crc_image`) | Pure compute + I/O, no Textual import — exhaustively unit-testable against `zlib.crc32`, reusable by both check and inject. |
| Neutral input contract | `model.py::OperationInput` (+ `OperationInput.from_loaded`) | Operations receive `mem_map` + `ranges` + metadata, not the Textual `LoadedFile` — resolves batch-08 C-7/R-2. New operations build against this, not the UI snapshot. |
| Widened result | `model.py::OperationResult.crc_regions` (+ `CrcRegionResult`) | One optional structured payload field; the 7 original fields + closed `STATUS_DOMAIN` are untouched, so the three placeholder operations and their tests still pass (R-3). |
| Reader-as-oracle verify | `verify_written_image` / `VerifyResult` (import-only from `tui/changes/verify.py`) | The 4th reuse of the proven re-read-and-diff idiom; the inject's intended map is the *injected* working copy (not a self-compare). |
| Contained work-area write | `emit_s19_from_mem_map` (`tui/changes/io.py`) staged under `temp/` then placed via `workspace.copy_into_workarea` | Containment + name-dedup-on-collision for free; a target outside the work area yields one finding and writes no file. |

### Honest boundaries

- **TUI-only.** No CLI `ops` subcommand (deferred at batch-08).
- **S19 input only.** No HEX/MAC as CRC inputs; A2L not in scope.
- **No config in the repo.** Only the dummy template + synthetic fixtures are committed; real per-firmware poly/init/ranges/output-addresses never land in version control.
- **RK-3 — non-default device convention is "assumed."** Parameters are proven *wired* (a non-default param changes the digest) and the bitwise path is anchored against *published* variant KATs, but there is no operator-sourced *device* reference vector in-tree. Do not trust a non-zlib device verdict without one.
- **No `report_service` surface (J-3).** The check has no separate persistent artifact — its surface is the op-result view. The write's durable record is its own output: the emitted modified S19 (the FR9 artifact) plus the `OperationResult`. `report_service.py` is untouched this batch.
- **Frozen engine reuse is import-only.** `range_index`, `emit_s19_from_mem_map`, `verify_written_image`, and the workspace containment helpers are imported, never edited; `test_engine_unchanged.py` is the backstop (CLEAR).

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/operations/crc.py` (NEW) | Headless CRC32 engine + check + inject + emit + verify (`CrcOperation`, `CrcWriteResult`). |
| `s19_app/tui/operations/crc_config.py` (NEW) | External JSON config reader + text parser (`CrcConfig`, `CrcRegion`, `DUMMY_CONFIG_TEXT`). |
| `s19_app/tui/operations/model.py` | `OperationInput` (NEW), `OperationResult.crc_regions` widening, `CrcRegionResult` (NEW). |
| `s19_app/tui/operations/requirements/REQ-crc.md` (NEW) | Co-located operation requirements (C-7). |
| `s19_app/tui/services/operation_service.py` | `run_operation` builds the neutral `OperationInput`. |
| `s19_app/tui/screens.py` | CRC config editor, worker dispatch, per-region rows, `ConfirmWriteScreen`, write-outcome rendering. |
| `examples/crc_config.example.json` (NEW) | Dummy config template (fake values). |

### Usage / examples

```bash
# Launch the TUI with an S19 pre-loaded
s19tui --load examples/case_00_public/prg.s19
# → Operations modal → CRC → edit the pre-filled JSON config →
#   Execute (check, per-region MATCH/MISMATCH) →
#   Write CRC → Confirm (emit modified S19 + verify) / Cancel (no write)

# Run the CRC test subset
python -m pytest -q tests/test_crc_engine.py tests/test_crc_config.py \
  tests/test_crc_operation.py tests/test_tui_crc_surface.py tests/test_operations.py
# → 48 passed (2026-06-17)
```

### Diagrams

- [CRC check + operator-confirmed write flow](diagrams/crc-check-write-flow.md) — the check path and the confirmed write path, with the guard-rails.

### Evidence checklist — docs-writer

| # | Item | ✓/✗ | Evidence |
|---|------|-----|----------|
| 1 | Audience + purpose declared at top | ✓ | "Audience: operator + technical stakeholder. Purpose: …" header. |
| 2 | Structure follows template (functionality scaffold) | ✓ | At-a-glance + Detail/components/usage/diagrams retained. |
| 3 | Code/CLI snippets run | ✓ | `pytest` subset = 48 passed on disk 2026-06-17; `s19tui --load` is the documented entry point in CLAUDE.md. |
| 4 | Assumptions listed | ✓ | "Honest boundaries" — RK-3 assumed device vector; config-not-in-repo assumption. |
| 5 | Risks / limitations called out | ✓ | TUI-only, S19-only, RK-3, no `report_service` (J-3). |
| 6 | Next steps stated | ✓ | RK-3 device vector + `REQUIREMENTS.md` back-ref deferred (matrix §3). |
| 7 | Diagrams where flow non-trivial | ✓ | `diagrams/crc-check-write-flow.md` (check + confirmed-write Mermaid). |
| 8 | No invented APIs / versions / metrics | ✓ | Every symbol grep-verified against `crc.py`/`crc_config.py`/`model.py`/`screens.py`; node ids from `04-validation.md` §2. |

*UTF-8, no BOM. Phase 6 (docs-writer). Symbols verified against the real tree 2026-06-17.*
