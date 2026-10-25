# Requirements Document — s19_app — Batch 2026-10-25-batch-99

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development language (`state.json` `language`). For Spanish batches, translate the **prose** — section headers and guidance — **and never a label**, and use `deberá` as the normative keyword (≡ `shall`). The normative RULES in this preamble are **language-independent** and enforced regardless of artifact language.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/req-template.md` and its part 2, `templates/guides/req-template.part2.md`, explain each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Validation` · `Acceptance test(s)` · `Boundary catalog` · `Negative control` · `Premise evaluation` · `Fork preconditions` · `Ledger` · `Requirement` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

---

## 1. Introduction

### 1.1 Purpose
This document states what the read/write integrity batch obliges: every image, report and run
record the tool writes says what was and was not applied, and every loaded image holds only what
its file declares. It derives from three executed investigations on `9793fcd` / `432ecf0` and their
re-run on this batch's base `307065f` (§2.7).

### 1.2 Scope
**In:** the ten HIGH findings H-1..H-10 of `.dev-flow/design/INVESTIGATION-read-write-integrity-2026-10-22.md`;
PH-3 of `.dev-flow/design/INVESTIGATION-project-roundtrip-2026-10-23.md` (same root as H-3); the
Code-Wire data HIGHs CW-D-4, CW-D-7 and CW-D-10 of `.dev-flow/design/AUDIT-codewire-data-2026-10-23.md`;
deeper tests of the CW-U-1 fix (batch-97 Inc-9) and its sibling in `_load_from_item`; a generated
synthetic fixture corpus with an independent reader as the oracle for all of the above.

**Out (with where each lives):** PH-1, PH-2, PH-4, PH-5 and the Load-file picker go to the Load+projects
batch (`BACKLOG-CODE.md` §*read/write integrity investigation*, last two bullets). CW-U-2 (focus moves to the
hidden Split/Join table) goes to the same batch. The MEDIUM rows M-1..M-10 and LOW rows L-1..L-7 stay in
`BACKLOG-CODE.md` §*read/write integrity investigation*, except where a requirement below names one.
The progress bar (N5) goes to the Load+projects prototype round. No new file format is added.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Image | The in-memory address→byte map of a loaded S19/SREC, Intel HEX or MAC file (`LoadedFile.mem_map`). |
| Data record | An S19 `S1`/`S2`/`S3` record or an Intel HEX type `00` record. These are the only records that carry image bytes. |
| Header record | An S19 `S0` record. It carries a header text, never image bytes. |
| Terminator | An S19 `S7`/`S8`/`S9` record, or the Intel HEX type `01` (EOF) record. |
| Disposition | The per-entry outcome of applying a change document: `applied`, `skipped-outside`, `skipped-partial`, `skipped-no-image` or `blocked`. |
| Refusal | A reader or apply-time issue at ERROR severity that stops a document (e.g. `MF-JSON-PARSE`, `CHG-V1-FORMAT`). |
| Staging file | The temporary file a writer fills before placing the result under its final name. |
| Independent reader | A test-side S19/HEX parser that shares no code with `s19_app` (`tests/support/independent_reader.py`, NEW). |
| Corpus | The generated synthetic fixture set and its manifest of expected bytes and verdicts (`tests/fixtures/synth/`, NEW). |
| Round-trip | load → (optional apply) → write → read back, compared byte by byte. |

### 1.4 References
- `.dev-flow/design/INVESTIGATION-read-write-integrity-2026-10-22.md` (security-reviewer; probes in `investigation-rw-2026-10-22/`).
- `.dev-flow/design/INVESTIGATION-project-roundtrip-2026-10-23.md` (qa-reviewer; probes in `investigation-projects-2026-10-23/`).
- `.dev-flow/design/AUDIT-codewire-data-2026-10-23.md` and `AUDIT-codewire-ui-2026-10-23.md` (Code-Wire v2.6).
- `.dev-flow/BACKLOG-CODE.md`: §*Routed 2026-10-23 — read/write integrity investigation*, §*Code-Wire audits* and §*synthetic fixture corpus*.
- Motorola S-record format (S0..S9); Intel HEX (types 00–05); ASAM MCD-2 MC (ASAP2) for COMPU_METHOD, RECORD_LAYOUT and MOD_COMMON semantics.
- Operator decisions and plan page: `.dev-flow/2026-10-25-batch-99/design/plan-b99.html`, which exports `veredicto-b99.json`.

### 1.5 Document overview
§2 holds the stories, the premise re-run and the fork verdict. §3 has one HLR per story, §4 the LLRs
and §5 the validation strategy. Ids: US-141..US-151, HLR-152..HLR-162, AT-B99-NN, TC-B99-NN.

---

## 2. Overall description

### 2.1 Product perspective
The change sits under every writer the tool has:
- the S19/HEX loaders (`s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/render/hexview.py`);
- the change-document apply and save path (`tui/changes/apply.py`, `tui/workspace.py`, `tui/services/change_service.py`);
- the flow runner and its reports (`tui/services/flow_execution_service.py`, `flow_report_service.py`, `flow_screens.py`);
- the A2L physical↔raw codec (`tui/a2l.py`);
- the CRC operation (`tui/operations/crc.py`);
- the Split/Join/Export writer (`tui/segment_split_view.py`, `segment_ops.py`).

No new screen is added.

### 2.2 Product functions
- Load only declared data, and report truncated or inconsistent images.
- Write every file through a private staging file, then place it under its final name atomically, never sharing that path.
- Report, at every layer, every entry that was not applied and every refusal.
- Keep the editor's image equal to the source plus the current document.
- Encode A2L physical values in the declared byte order and conversion direction, and refuse values that do not round-trip.
- Refuse a CRC over a region with no bytes, and keep every export path inside its destination.

### 2.3 User characteristics
Calibration and test engineers who load ECU images, patch them, run flows and flash the result.
They trust the status line and the reports. They do not read the bytes back with another tool.

### 2.4 Constraints
- Python 3.11 / Textual 8.2.8; Windows first (CRLF sources).
- At most 4 SOURCE files per increment; tests and fixtures are not capped.
- The repo is public: records describe the extraction feature only as memory-region extraction.
- Every UI string is in English.

### 2.5 Assumptions and dependencies
- The S19/HEX emitters are byte-exact for any address map (investigation §1: 200 random maps, 0 mismatches). Re-checked as premise P-12.
- `apply_change_document` classifies dispositions correctly (investigation §1). Re-checked as premise P-13.
- If either assumption fails, the batch's write-side requirements are re-derived.

### 2.6 Source user stories

Every story comes from the operator's commission of 2026-10-25 (`state.json` `standing_authorization`)
and from the investigations in §1.4. Decisions the operator still owes are marked `D-n` and listed on
the decisions page (§1.4). A story that depends on one is `REFINE` until it is answered.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-141 | As the maintainer of the read/write paths, I want a generated synthetic corpus of S19, Intel HEX, MAC and A2L files, each with a manifest of its expected bytes and verdict, checked by a reader that shares no code with the tool, so that every integrity test compares the tool with data that holds its own oracle. | backlog §*synthetic fixture corpus*; spec-gap audit 2026-10-23 | READY |
| US-142 | As the calibration engineer, I want a loaded S19 image to hold only the bytes of its data records, never the S0 header text, so that what I patch and flash is exactly what the file declares. | H-1 | READY |
| US-143 | As the calibration engineer, I want to be told when an image file is truncated or inconsistent (no terminator or EOF, an S5 count that disagrees, records after the terminator or EOF), so that a failed transfer is never patched and written as `ok`. | H-8 | REFINE — D6 |
| US-144 | As the engineer running chain sets and saving patched images, I want every write to land in its own file, placed atomically, so that parallel lanes never write each other's image, and a save-back under the image's own name neither deletes the work copy nor crashes Save project. | H-3, PH-3 | READY (D7 and D9 refine two sub-clauses) |
| US-145 | As the engineer running flows, I want the PATCH step and every run record (lane status, chain-set report, flow report) to show each entry that was not applied and each refusal, and the run to stop before writing when the patch applied nothing, so that no `ok` or `CLEAN` hides a dropped write. | H-2, H-10 | REFINE — D5 |
| US-146 | As the calibration engineer using the Patch Editor, I want the image I save to always equal the source plus the entries currently in my document, so that an undone or removed entry never reaches the file. | H-4 | READY |
| US-147 | As the calibration engineer entering physical values from the A2L, I want them encoded in the module's byte order and in the conversion direction ASAM defines, and refused when the table cannot represent them, so that the raw bytes written mean the value I typed. | H-5, H-6, CW-D-10 | REFINE — D2, D3, D4 |
| US-148 | As the engineer running a CRC step, I want a CRC over a region that holds no image bytes to fail, and a partly covered region to say how much was absent, so that a meaningless CRC is never written over live bytes. | H-7 | READY |
| US-149 | As the engineer exporting memory segments, I want every exported file to stay inside the chosen destination whatever the A2L segment is called, and a MAC-only export to write the header-only file its confirm promises, so that an export never writes outside the work area or invents a byte. | H-9, CW-D-7 | READY (D8 refines the overwrite clause) |
| US-150 | As the calibration engineer typing or pasting a hex dump into the Patch Editor Bytes field, I want every token read in one base, so that `11 22` is written as `11 22`. | CW-D-4 | REFINE — D1 |
| US-151 | As the engineer opening a saved project, I want the Load project dialog and the Workarea Files list to load the item I picked, by name, and the project list to show only projects, so that the CW-U-1 fix holds whichever way I pick. | CW-U-1 (batch-97 Inc-9); its `_load_from_item` sibling; the `patches` folder listed as a project; CW-U-3 (the Workarea Files list reads a folder loads never write to, so the sibling cannot be observed without it) | READY |

**Ledger pairing:** stories live in this table. Ledger entries name the HLR or LLR they amend.

#### Refinement log (one block per story)

**US-141 — synthetic corpus and independent reader**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):**
  - user = the maintainer, and every later test;
  - outcome = deterministic files per format, with their expected bytes;
  - why = today the writer is checked by its own reader (investigation p14), and there are 0 `.hex` fixtures;
  - out of scope = new formats (CDFX, ELF), and flow-file corpora beyond what H-2, H-3 and H-7 need.
- **Feasibility (E, S):**
  - path = a generator script and a manifest under `tests/fixtures/synth/`, plus the probes' `mini_s19` / `mini_hex` ported to `tests/support/independent_reader.py`;
  - unknowns = none;
  - fits one batch = yes.
- **Evaluability (T):** when the generator runs twice, the files are byte-identical; when the independent reader reads each file, it yields exactly the manifest's bytes.
- **Open questions:** none.
- **Classification:** `READY`.

**US-142 — S0 is not image data**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - user = the calibration engineer;
  - outcome = no bytes at the S0 address after a load and a write, and a patch at `0x0` of an image with no data there is `skipped-outside`;
  - why = 15 of the 16 example S19 files gain 6–18 bytes at `0x0` on a round-trip;
  - out of scope = keeping the entry point (M-1).
- **Feasibility:**
  - path = only data records feed `build_mem_map_s19` and `S19File.get_memory_map` / `get_memory_ranges`, and S0 stays in `source_s0_header`;
  - unknowns = how many existing tests count ranges on S0-bearing fixtures (P1 census);
  - fits one batch = yes.
- **Evaluability:** when `case_01` is loaded and written unchanged, the independent reader finds no byte at `0x0..0xB` in the output; a patch at `0x0` reports the entry as skipped.
- **Open questions:** none.
- **Classification:** `READY`.

**US-143 — truncated and inconsistent images are reported**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = a load notice naming the defect, which the flow SOURCE step carries;
  - why = a cut transfer loads as `ok` with its tail missing;
  - out of scope = refusing WRITE-OUT after a lossy load in general (M-3).
- **Feasibility:** path = terminator, EOF and S5 checks in `core.py` `_load` and `hexfile.py` `_load`; fits one batch = yes.
- **Evaluability:** when a corpus file with no terminator is loaded, the user reads a notice naming the missing terminator.
- **Open questions:** **D6**: what the defect does to a run that writes — a notice only, the flow stops before WRITE-OUT, or the load is refused.
- **Classification:** `REFINE` — D6.

**US-144 — isolated, atomic writes**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = each lane's file holds that lane's bytes; a save-back under the image's own name keeps the work copy; Save project after it does not crash;
  - why = 35 mismatches over 5 trials of 8 parallel lanes (re-run at `307065f`), and the app exits with code 1 (PH-3);
  - out of scope = the re-run replacement policy (M-5).
- **Feasibility:** path = a unique staging file (`tempfile.mkstemp` in `temp/`), a create-exclusive placement plus `os.replace`, and Save project handles a missing source with a notice; fits one batch = yes.
- **Evaluability:** when 8 parallel lanes write the same output name, each lane's reported file holds its own marker; after a save-back named like the image, Save project completes and the app keeps running.
- **Open questions:**
  - **D7**: refuse duplicate output names across one set's lanes at run start, or let each lane take its own `_<N>` name.
  - **D9**: add verify-after-write to the flow WRITE-OUT step in this story (backlog L-4 / M-4).
- **Classification:** `READY` for the staging and crash clauses; the D7 and D9 clauses wait.

**US-145 — truthful PATCH and run records**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = the PATCH status follows its dispositions; lanes, the chain-set report and the flow report list each non-applied entry and each refusal; the chain-set report lists the written paths;
  - why = PATCH has been `ok` for every outcome since batch-44;
  - out of scope = CHECK gating (M-6) and variant execution (M-10).
- **Feasibility:** path = the `flow_execution_service.py` PATCH arm and `ChainRunOutcome` fields, `flow_report_service.py`, the chain-set report and the lane painter, with TC-714 re-pinned; fits one batch = yes.
- **Evaluability:** when a flow patches only addresses outside the image, the user sees the run stop before WRITE-OUT and the report name each skipped address.
- **Open questions:** **D5**: the status rule — a partial skip gives notices and WRITE-OUT goes on, while 0 applied, blocked or unreadable gives an error and stops; or any skip stops the run.
- **Classification:** `REFINE` — D5.

**US-146 — editor image = source + document**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = after apply → undo → apply → save, the file holds only the current entries;
  - why = verify says `verified` over the undone write;
  - out of scope = Save project of an unsaved patch (PH-1, the Load+projects batch).
- **Feasibility:** path = apply re-derives the image from a pristine snapshot taken at load plus the current document; a P1 premise checks every other in-place writer of `mem_map` (CRC inject, symbol entries); fits one batch = yes.
- **Evaluability:** when the investigation's p05 sequence runs, the saved file at `0xEB10` equals the source.
- **Open questions:** none. The observable rule is fixed; the mechanism is a design choice recorded at PDR.
- **Classification:** `READY`.

**US-147 — A2L physical→raw encoding**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = big-endian modules encode and decode big-endian; RAT_FUNC follows INT = f(PHYS); a COMPU_TAB value that does not round-trip is refused (or flagged);
  - why = byte-swapped entries, values converted in the wrong direction, and a silent nearest-value or clamp;
  - out of scope = other COMPU_METHOD kinds.
- **Feasibility:** path = `tui/a2l.py` (`effective_byte_order`, the encode pack, `_apply_compu_method`, `_invert_rat_func`, the COMPU_TAB inversion); fits one batch = yes.
- **Evaluability:** when the user enters 30 km/h for `RAT_FUNC_DIV_10`, the entry reads `2C 01`; under `MSB_FIRST`, physical 4113 on a 2-byte value reads `10 11`.
- **Open questions:** **D2**: the RAT_FUNC direction. **D3**: the source of the byte-order default, and whether decode changes with encode. **D4**: COMPU_TAB — refuse or flag.
- **Classification:** `REFINE` — D2, D3, D4.

**US-148 — CRC over an empty region fails**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = 0 present bytes gives `error` and nothing is written; partial coverage gives `notices` naming the absent count;
  - why = `00000000` is written over live bytes, with `ok`;
  - out of scope = CRC Designer template writes.
- **Feasibility:** path = the coverage check in `crc.py` and the flow CRC arm; fits one batch = yes.
- **Evaluability:** when a flow CRC step covers `0x20000–0x30000` of `prg.s19`, the user sees the step fail and the output bytes unchanged.
- **Open questions:** none.
- **Classification:** `READY`.

**US-149 — export containment and MAC-only header**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = every exported path resolves under the destination; segment names are sanitised; a MAC-only export writes a header-only S19/HEX;
  - why = a `../` in the segment name escapes the work area, and a phantom `0x00` is written at `0x80000000`;
  - out of scope = the Split/Join S0 header and entry point (CW-D-8/9).
- **Feasibility:** path = the name build and writer in `segment_split_view.py`, and `segment_ops.py`; fits one batch = yes.
- **Evaluability:** when an A2L segment named `x/../../../ESCAPED` is exported, the user finds the file inside the destination under a sanitised name.
- **Open questions:** **D8**: a second export under the same name — replace it atomically, or write `_<N>`.
- **Classification:** `READY`; the overwrite clause waits for D8.

**US-150 — one base in the Bytes field**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = `0F 10 1F 20` is written as `0F 10 1F 20`;
  - why = digit-only tokens are read as decimal, and the save still says `Saved + verified`;
  - out of scope = the symbol picker's physical values.
- **Feasibility:** path = the token parse in `change_service.py` (`:210-223`) and the placeholder / help text; fits one batch = yes.
- **Evaluability:** when the user types `11 22` and saves, the file holds `11 22`.
- **Open questions:** **D1**: bare tokens are always hex (decimal refused), hex with an explicit decimal prefix, or decimal kept with a warning. The answer amends batch-07 LLR-001.2.
- **Classification:** `REFINE` — D1.

**US-151 — Load project and Workarea Files load by name**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:**
  - outcome = the picked project or file loads, and `patches` is not listed;
  - why = Inc-9 fixed the dialog, but no test covers each way of picking, and `_load_from_item` keeps the `Label()` pattern;
  - out of scope = enter-to-load and the dialog redesign (D10 recommends the Load+projects batch).
- **Feasibility:** path = tests that press `#project_ok`, click and highlight; the name extraction in `_load_from_item`; the `list_projects` filter; fits one batch = yes.
- **Evaluability:** when the user highlights `P2` and presses Load, the status names `P2`; when a Workarea Files item is picked, that file loads.
- **Open questions:** **D10**: keep the enter/click semantics for the Load+projects batch (recommended), or decide now.
- **Classification:** `READY`.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

Probes executed 2026-10-25 on `307065f` (this batch's `base_ref`) with
`S19_WT=C:/Users/jjgh8/Github/s19_app`, `PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1`, `NO_COLOR` unset,
interpreter `s19env`. Full transcripts: `.dev-flow/2026-10-25-batch-99/evidence/p0-premises/` (one file per probe, `rw-pNN_*.txt`, `proj-p08_*.txt`).

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence (decisive output) | Disposition |
|---|---|---|---|---|---|
| P-1 | An identity SOURCE→WRITE-OUT of an S0-bearing example S19 writes bytes at `0x0` that the source never declared as data (H-1). | premise | ✅ TRUE | `rw-p03`: `case_01_basic_valid\firmware.s19 s19 run=ok src_bytes=97 out_bytes=109 extra=12@0x0..0xb`; 15 of 16 S19 sources `BAD`, only `prg.s19` `OK` | RED side of AT-B99-02 |
| P-2 | A patch at `0x0` of `case_01` is reported `applied` and lands on the header bytes (H-1). | premise | ✅ TRUE | `rw-p13`: `('patch','ok','applied 1 entry')` | RED side of LLR-153.4 |
| P-3 | The repo's own verify and diff cannot see the S0 phantom (shared reader). | premise | ✅ TRUE | `rw-p14`: `repo diff source vs written: runs = 0 | verify_written_image: verified` | the independent reader (HLR-152) is the oracle |
| P-4 | The flow PATCH block reports `ok` for out-of-image, straddling, blocked, v1 and malformed documents, and WRITE-OUT still writes (H-2). | premise | ✅ TRUE | `rw-p01`: `outside_0x20000 run=ok patch=ok:'applied 0 entries' dispositions=['skipped-outside']`; `malformed_json run=ok … refusals=['MF-JSON-PARSE'] wrote=['out_malformed_json.s19']` | RED side of AT-B99-06/07 |
| P-5 | Parallel chain-set lanes sharing an output name write each other's image (H-3). | premise | ✅ TRUE | `rw-p02`: `parallel mismatches: 35 files now: ['same.s19']` (5 trials × 8 lanes) | RED side of AT-B99-04 |
| P-6 | Patch Editor apply → undo → apply → save writes the undone entry and verify says `verified` (H-4). | premise | ✅ TRUE | `rw-p05`: `verify: verified`; `file @0xEB10 = deadbeef (source: 20417070 ) — summary of the saved apply lists only ['0xeb40']` | RED side of AT-B99-08 |
| P-7 | Under `MOD_COMMON BYTE_ORDER MSB_FIRST` the effective byte order is `little` (H-5). | premise | ✅ TRUE | `rw-p06`: `OVER_A: datatype/length/effective_byte_order = None 2 little` | RED side of LLR-158.1 |
| P-8 | COMPU_TAB inversion writes the nearest / clamped value with no error or flag (H-6). | premise | ✅ TRUE | `rw-p06`: `TAB_INTP physical 500.0 -> raw 02 (decodes back to 20.0) err=None flags=[]`; `TAB_NOINTP physical 13.0 -> raw 01 (decodes back to 10.0)` | RED side of LLR-158.3 |
| P-9 | A flow CRC over a region with no image bytes writes `00000000` and reports `ok` (H-7). | premise | ✅ TRUE | `rw-p07`: `region_no_bytes run=ok crc=ok:'injected 1 CRC region' findings=[] slot_bytes=00000000`; `region_over_gap run=ok … findings=[]` | RED side of AT-B99-10 |
| P-10 | Truncated / inconsistent S19 and HEX files load as `ok` with 0 notices, and HEX data after EOF is dropped (H-8). | premise | ✅ TRUE | `rw-p04`: `s19_truncated_no_terminator run=ok source=ok notices=0`; `s19_count_S5_mismatch … notices=0`; `s19_data_after_term … notices=0`; `hex_no_eof_truncated … notices=0`; `hex_data_after_eof … out_bytes=32` | RED side of AT-B99-03 |
| P-11 | An A2L `MEMORY_SEGMENT` named `x/../../../ESCAPED` makes the export write outside the destination, and a second export overwrites the first (H-9). | premise | ✅ TRUE | `rw-p10`: `resolved: …\.s19tool\ESCAPED.s19 | inside dest: False`; `second export path == first: True | first content survived: False` | RED side of AT-B99-11 |
| P-12 | The S19/HEX emitters are byte-exact for random sparse maps. | axiom | ✅ TRUE | `rw-p12`: `random round trips (200, S19+HEX, repo loader + independent parser): mismatches = 0` | §2.5 assumption holds |
| P-13 | `apply_change_document` classifies dispositions correctly; the defect is in the layers above it. | premise | ✅ TRUE | `rw-p01`: the `dispositions=` column lists `skipped-outside`, `skipped-partial`, `blocked` for the matching cases | HLR-156 reads the summary, it does not reclassify |
| P-14 | No run record shows a non-applied entry: the chain-set outcome is `ok` with `applied 0 entries` (H-10). | premise | ✅ TRUE | `rw-p02`: `outcome status: ok [('source', 'ok', …), ('patch', 'ok', 'applied 0 entries'), ('write_out', 'ok', 'wrote bad_out.s19')]`; `rw-p09` `Status: CLEAN` | RED side of LLR-156.3/156.4 |
| P-15 | A Patch Editor save-back under the loaded image's own name deletes its work copy, and the next Save project exits the app with code 1 (PH-3). | premise | ✅ TRUE | `proj-p08`: `work copy exists after save-back: False | app still holds: temp/firmware.s19`; `after Save-project dismiss: app running? False | return_code: 1` | RED side of AT-B99-05 |
| P-16 | `parse_new_bytes` reads a digit-only token as decimal (CW-D-4). | premise | ✅ TRUE | `change_service.py:213-217`: `int(token, 0)` first, `int(token, 16)` only on `ValueError`; audit T2 t2b `"0F 10 1F 20"` → `0F 0A 1F 14` | RED side of LLR-161.1 |
| P-17 | RAT_FUNC decodes PHYS = f(raw) and encodes by inverting that, opposite to ASAP2's INT = f(PHYS) (CW-D-10). | premise | ✅ TRUE | `a2l.py:1736-1744`, `:1766-1798`; audit T4 t4a `RAT_FUNC_DIV_10` 30 → `03 00`, t4b raw 300 → `3000.0` | RED side of LLR-158.2 |
| P-18 | A MAC-only session's Split/Export writes one placeholder byte as a data record while its plan says packed 0 (CW-D-7). | premise | ✅ TRUE | audit T6 t6b: plan `{packed 0, empty True}`, written `S306800000000079` | RED side of LLR-160.3 |
| P-19 | `_load_from_item` builds the file name with `label.text if hasattr(...) else str(label)`; Textual 8.2.8 `Label` has no `.text`. | premise | ✅ TRUE | `app.py:8816-8821`; batch-97 Inc-9 re-confirmation of the same pattern in `LoadProjectScreen` (LED-…97.42) | RED side of LLR-162.1 |
| P-20 | `list_projects` lists every work-area folder except `temp`, so `patches` (and any other reserved home) shows as a project. | premise | ✅ TRUE | `app.py:8314-8319`: `if item.is_dir() and item.name != WORKAREA_TEMP` | RED side of LLR-162.2 |
| P-21 | There are 0 Intel HEX fixtures in `examples/` and `tests/`. | premise | ✅ TRUE | backlog §*synthetic fixture corpus* count re-run: `16 .s19, 34 .a2l, 14 .mac, 0 .hex/.ihex/.srec` | HLR-152 |

- **Premise evaluation:** 21 premises · ✅ 21 TRUE · ❌ 0 FALSE · ❓ 0 UNDECIDABLE. Every finding the batch closes reproduces on its base.

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

| # | Condition (`C-52`) | Discharged? | The executed evidence |
|---|---|---|---|
| 1 | **Frozen contract** — no shared interface is touched inside a lane; one that must change returns to the trunk (trigger A3) | ✅ | n/a — one lane: B99-I1..I9 (`docs/ARCHITECTURE.md` §11, *Batch-99 interface amendments*) are changed by this trunk batch in sequence |
| 2 | **Disjoint FILE sets**, not just modules — two lanes may not edit the same file, not even different regions | ✅ | n/a — one lane. ARQ's matrix (`design/ARQ-batch-99.md` §3) finds four sharing pairs: 2∩9 `core.py`, 3∩7 `app.py`, 4∩11 `change_service.py`, 5∩8 `flow_execution_service.py`. That is why the batch does not fork |
| 3 | **Crossed reverse census** — family B run per lane and **shared before starting**; the trunk's act, impossible from inside a lane | ✅ | n/a — one lane; the reverse census runs per increment |
| 4 | **One owner of the trunk** — requirements, traceability, backlog and spec are never written from a lane | ✅ | the orchestrator owns the trunk; Kimi works one increment at a time in a throwaway worktree and never commits |

- **Fork preconditions:** none — this batch runs one lane (ARQ verdict: sequential, no fork; `design/ARQ-batch-99.md` §3)

---

## 3. High-level requirements (HLR)

> **What every acceptance test may observe.** An acceptance test drives the shipped surface:
> Textual pilot keys and clicks on `S19TuiApp` (headless `run_test`), or the corpus generator's
> command line for HLR-152. It observes only these:
> - files written on disk, read back with the **independent reader** (HLR-152), never with `s19_app`'s loaders;
> - painted text (status line, lane cells, the issues panel, dialog text);
> - report files under the work area.
>
> It never observes an internal attribute or a wrapped service. Test paths and `-k` selectors are
> provisional until Phase 3 and are reconciled from the real tree at Phase 4.
>
> **Provisional derivations.** HLR-154, HLR-156, HLR-158, HLR-161 and the D7, D8, D9 clauses of
> HLR-155 and HLR-160 are derived on the option the decisions page recommends (`plan-b99.html` §2).
> They enter Phase 3 only after the operator's verdict. A verdict that differs is written as a ledger
> amendment and re-reviewed at P2 for the clauses it touches.

### HLR-152 — Synthetic corpus with an independent oracle
- **Traceability:** US-141
- **Ledger:** none
- **Statement:** When the corpus generator runs, the system shall write a deterministic set of S19, Intel HEX, MAC and A2L fixture files together with a manifest that records, for each file, its SHA-256, its expected data bytes (address → byte) and its expected load verdict. When run in check mode, the generator shall exit non-zero, naming the file, if any committed file differs from what it generates or if the independent reader's bytes for any file differ from the manifest.
- **Rationale (informative):** the writer is verified today by its own reader, which shares the S0 mistake (P-3), and no HEX fixture exists (P-21).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_corpus.py`
- **Numeric pass threshold:** 2 generator runs → 0 differing bytes; every manifest file → 0 byte mismatches against the independent reader; the coverage census (LLR-152.2) → 0 missing classes.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** `generate.py --check` prints the file count and exits 0 on the committed corpus. With one byte of one committed file changed, it exits non-zero and names that file.
  - **Shipped surface:** `tests/fixtures/synth/generate.py` (NEW), the maintainer's command line.
  - **Acceptance test(s):** AT-B99-01
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: an S19 holding only S0+terminator (0 data bytes); boundary: S1/S2/S3 width edges (`0xFFFF`, `0xFFFFFF`), a HEX record ending at a 64 KiB boundary; invalid: the defect cases of LLR-152.2. Error: N/A — the generator takes no user input.
  - **Negative control:** the tampered-byte arm of AT-B99-01 (one byte flipped in a copy of a corpus file) → non-zero exit naming that file.

### HLR-153 — An S19 image holds only its data records
- **Traceability:** US-142
- **Ledger:** none
- **Statement:** When an S19 file is loaded, the system shall build the image, its ranges and every count derived from them from `S1`, `S2` and `S3` records only. When an image loaded from an S19 is written, the system shall emit its S0 header as a header record and emit no data record at any address the source did not declare in a data record.
- **Rationale (informative):** 15 of 16 example S19 files gain 6–18 bytes at `0x0` on a round-trip (P-1), and a patch at `0x0` lands on header text (P-2).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_s0.py`
- **Numeric pass threshold:** over every S0-bearing corpus S19 and `examples/**/*.s19`: written data bytes == source data bytes (independent reader), 0 extra addresses; a patch at `0x0` of `case_01` → disposition `skipped-outside`, 0 bytes written at `0x0`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** after loading `examples/case_01_basic_valid/firmware.s19` and saving it back unchanged from the Patch Editor, the written file read by the independent reader has no byte at `0x0..0xB`. The Memory Map lists no range starting at `0x0`. A patch entry at `0x0` is reported as skipped in the status line.
  - **Shipped surface:** Load file (`l`) → Patch Editor (`p`) save-back (`#patch_saveback_*`), and the Memory Map window.
  - **Acceptance test(s):** AT-B99-02
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: an S0-only file loads as an empty image; boundary: an S0 whose payload length equals a data record's. Invalid/error: N/A — no parse change.
  - **Negative control:** executed on `307065f` (P-1): `extra=12@0x0..0xb` → AT-B99-02 is RED today.

### HLR-154 — Truncated and inconsistent images are reported *(provisional: D6 = `flujo_para`)*
- **Traceability:** US-143
- **Ledger:** none
- **Statement:** When an S19 file has no terminator, an `S5` count different from its number of data records, or any record after its terminator, the system shall attach a load notice naming the defect. When an Intel HEX file has no EOF record, or any record after its first EOF, it shall attach a load notice naming the defect and the count of records ignored. While a flow's SOURCE image carries such a notice, the flow shall end the SOURCE step with status `error` and write no file.
- **Rationale (informative):** a cut transfer loads as `ok` with its tail missing (P-10).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_truncation.py`
- **Numeric pass threshold:** 5 defect corpus files → 5 notices whose text names the defect; 5 flow runs → SOURCE `error`, 0 files written; 2 well-formed controls → 0 notices.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** loading a corpus S19 with no terminator shows a notice naming the missing terminator. A flow over it shows the SOURCE step failed and writes nothing.
  - **Shipped surface:** Load file (`l`), the issues panel; Flow Execution run (`#flow_run_*`).
  - **Acceptance test(s):** AT-B99-03
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: a file whose last line is the terminator (control, no notice); invalid: the five defect files. Empty/error: N/A — an empty file is already refused (`EMPTY`).
  - **Negative control:** executed on `307065f` (P-10): `s19_truncated_no_terminator run=ok source=ok notices=0` → RED today.

### HLR-155 — Every write lands in its own file, placed atomically
- **Traceability:** US-144
- **Ledger:** none
- **Statement:** When the system writes an image, it shall fill a staging file whose name no other write can share, and place it under the final name so that the final file always holds exactly the bytes of the write that reports it. It shall never delete a file it did not create. When Save project finds a source file missing, the system shall report a notice naming the file and keep running. *(D7, provisional `rechazar`:)* When a chain set is started with two or more lanes naming the same output file, the system shall refuse to start and name those lanes. *(D9, provisional `si`:)* When a flow WRITE-OUT step has written a file, the system shall read it back and end the step with status `error` if its bytes differ from the image.
- **Rationale (informative):** 35 lane/file mismatches in 5×8 parallel runs (P-5); the app exits with code 1 after a same-name save-back (P-15).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_staging.py`
- **Numeric pass threshold:** 8 parallel lanes × 20 trials → 0 lanes whose reported file holds another lane's marker; after a same-name save-back: work copy present and byte-equal to its pre-save content, Save project → app running, return code unset; duplicate-name set → refused, 0 files written; corrupted write → WRITE-OUT `error`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a chain set of 8 lanes with distinct output names, run in parallel, writes 8 files, each holding its own lane's marker. A set with two lanes named `same.s19` is refused with both lane names shown. After loading `firmware.s19`, applying a patch and saving back as `firmware.s19`, Save project completes, the app keeps running and the project folder holds the image.
  - **Shipped surface:** Flow Execution (chain set run, parallel mode); Patch Editor save-back; Save project dialog (`SaveProjectScreen`).
  - **Acceptance test(s):** AT-B99-04, AT-B99-05
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☒ error — boundary: 1 lane (no contention) and 8 lanes; invalid: duplicate output names; error: a missing source at Save project.
  - **Negative control:** executed on `307065f`: P-5 (`parallel mismatches: 35`) and P-15 (`return_code: 1`) → both ATs RED today.

### HLR-156 — PATCH status and run records say what was not applied *(provisional: D5 = `mixta`)*
- **Traceability:** US-145
- **Ledger:** none
- **Statement:** When a flow PATCH step finishes, the system shall set its status from the step's dispositions and refusals:
  - `error` when the document could not be read, carries an ERROR refusal, is blocked, or applied 0 of at least 1 entry;
  - `notices` when at least one entry was skipped or blocked and at least one applied;
  - `ok` only when every entry was applied.

  A PATCH `error` shall stop the flow before any later WRITE-OUT. Every run record — the Flow Execution lane, the chain-set report and the flow report — shall list each non-applied entry (address and disposition) and each refusal (code and message). The chain-set report shall list the files each lane wrote. No report shall say `CLEAN` for a run that holds a non-applied entry or a refusal.
- **Rationale (informative):** PATCH has reported `ok` for every outcome since batch-44 (P-4); the outcome and both reports drop dispositions (P-14).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_patch_truth.py`, plus the re-pinned TC-714 in `tests/test_changes_symbol_entries.py`.
- **Numeric pass threshold:** the 7-case matrix of `rw-p01` / `p06b` → statuses `error, error, notices, error, error, error, error` (outside, straddle, one-in-one-out, blocked, v1, malformed, unresolved symbol); 0 WRITE-OUT files for `error` cases; reports name 100 % of the non-applied addresses and refusal codes; 0 `CLEAN` headers on those runs.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** running a flow whose patch lies entirely outside the image shows the PATCH cell failed, writes no output file, and the flow report names the skipped address and `skipped-outside`. A flow with one applied and one skipped entry shows notices, writes a file that holds only the applied entry, and its report names the skipped address. A flow with a malformed change document shows an error and a report that names `MF-JSON-PARSE`.
  - **Shipped surface:** Flow Execution (`FlowExecutionPanel`, lane cells), the flow report and the chain-set report under the work area.
  - **Acceptance test(s):** AT-B99-06, AT-B99-07
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: a document with 0 entries (status `ok`, nothing applied, nothing to report); boundary: 1 applied + 1 skipped; invalid: v1 and wrong-kind documents; error: malformed JSON.
  - **Negative control:** executed on `307065f` (P-4): `outside_0x20000 run=ok patch=ok:'applied 0 entries'` → RED today.

### HLR-157 — The Patch Editor's image is the source plus the current document
- **Traceability:** US-146
- **Ledger:** none
- **Statement:** While a change document is open in the Patch Editor, the system shall keep the image equal to the pristine source image plus the current document's applied entries. When an applied entry is undone, removed or edited, its bytes shall return to the source's bytes before any later save. A save-back shall write that image, and its summary shall list exactly the entries the image holds.
- **Rationale (informative):** after apply → undo → apply → save, the undone write reaches the file and verify says `verified` (P-6).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_editor_image.py`
- **Numeric pass threshold:** the p05 sequence → file at `0xEB10..0xEB13` == source bytes (`20417070`), file at `0xEB40..0xEB41` == `01 02`, summary lists 1 entry; remove-after-apply and edit-after-apply arms → 0 stale bytes.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** in the Patch Editor the engineer adds `0xEB10 DE AD BE EF`, applies, undoes, adds `0xEB40 01 02`, applies and saves back. The written file read by the independent reader holds the source bytes at `0xEB10` and `01 02` at `0xEB40`, and the status names one applied entry.
  - **Shipped surface:** Patch Editor (`PatchEditorPanel`) Add / Apply / Undo / Save-back controls.
  - **Acceptance test(s):** AT-B99-08
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: undo of every entry → saved file == source; boundary: an undone entry overlapping a kept one. Invalid/error: N/A — no new input.
  - **Negative control:** executed on `307065f` (P-6): `file @0xEB10 = deadbeef` → RED today.

### HLR-158 — A2L physical values encode and decode as the A2L declares *(provisional: D2 = `asam`, D3 = `modulo`, D4 = `rechazar`)*
- **Traceability:** US-147
- **Ledger:** none
- **Statement:** When the system converts between a physical value and raw bytes for an A2L symbol, it shall use the symbol's byte order, else its RECORD_LAYOUT's, else the module's `MOD_COMMON BYTE_ORDER`, and only then little-endian. It shall apply a RAT_FUNC as INT = f(PHYS) when encoding and as its inverse when decoding. When a physical value encoded through a COMPU_TAB does not decode back to itself within the method's tolerance, it shall refuse the value with a message naming the nearest representable physical values.
- **Rationale (informative):** byte-swapped entries under MSB_FIRST (P-7), silent nearest/clamp (P-8), RAT_FUNC in the wrong direction (P-17).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_a2l_encode.py`
- **Numeric pass threshold:** MSB_FIRST 2-byte: encode 4113 → `10 11`, decode `10 11` → 4113; `RAT_FUNC_DIV_10`: 30 → `2C 01`, 25 → `FA 00`, raw 300 → 30.0; COMPU_TAB: 500 and 13.0 refused, 10.0 accepted; LINEAR control unchanged (30 → `0F 00`).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** through the Patch Editor's symbol entry, with the corpus A2L, 30 km/h on the RAT_FUNC symbol becomes an entry reading `2C 01`; 500 on the COMPU_TAB symbol is refused with the nearest values shown; 4113 on the MSB_FIRST 2-byte symbol becomes `10 11`. The A2L window shows 30 for the symbol whose raw bytes are 300.
  - **Shipped surface:** Patch Editor symbol entry (`#patch_symbol_*`); the A2L window.
  - **Acceptance test(s):** AT-B99-09
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: a table endpoint value (accepted) and a value just outside it (refused); invalid: a non-integral RAT_FUNC result (refused, existing). Empty/error: N/A.
  - **Negative control:** executed on `307065f`: P-7 (`little`), P-8 (`err=None flags=[]`), P-17 (30 → `03 00`) → RED today.

### HLR-159 — A CRC never covers an empty region
- **Traceability:** US-148
- **Ledger:** none
- **Statement:** When a CRC operation's region holds no image byte, the system shall end the operation with status `error` and write nothing. When the region holds some image bytes but not all, it shall end with status `notices` naming the number of absent bytes, for every region form, including legacy regions on the flow CRC arm. The CRC operation's own file write shall use the private staging of HLR-155.
- **Rationale (informative):** `00000000` is written over live bytes with `ok` (P-9).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_crc_region.py`
- **Numeric pass threshold:** empty region → `error`, output slot bytes == source slot bytes; region over a gap → `notices` with the exact absent count; fully covered region → `ok`, CRC equal to an independent CRC computation.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a flow whose CRC step covers `0x20000–0x30000` of `prg.s19` shows the CRC cell failed and writes nothing. A step over a gap shows notices naming how many bytes were absent.
  - **Shipped surface:** Flow Execution lane cells and the written output.
  - **Acceptance test(s):** AT-B99-10
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: 0 present bytes; boundary: exactly 1 present byte; error: the empty-region refusal. Invalid: N/A — the region grammar is unchanged.
  - **Negative control:** executed on `307065f` (P-9): `region_no_bytes run=ok crc=ok … slot_bytes=00000000` → RED today.

### HLR-160 — Exports stay inside their destination and invent no byte
- **Traceability:** US-149
- **Ledger:** none
- **Statement:** When Split/Join/Export writes a file, the system shall:
  - build the file name from a sanitised segment name;
  - refuse, writing nothing, any path that does not resolve under the destination directory;
  - write only image bytes the source declared.

  In a MAC-only session it shall write a header-only S19/HEX file. *(D8, provisional `reemplazar`:)* When an export's final name already exists, it shall replace that file atomically and say `replaced` in the status.
- **Rationale (informative):** a `../` segment name escapes the work area (P-11); a MAC placeholder byte is written as data (P-18).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_export.py`
- **Numeric pass threshold:** hostile names (`../`, `..\`, absolute, drive-letter, reserved device names) → 0 files outside the destination; MAC-only export → 0 data records (independent reader); second export → the destination holds 1 file with the second export's bytes.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** with an A2L whose segment is named `x/../../../ESCAPED`, the export writes its file inside the destination under a sanitised name, and nothing appears outside it. A MAC-only export writes a file holding no data record.
  - **Shipped surface:** the Split / Join / Export window (`SegmentSplitView`) export action.
  - **Acceptance test(s):** AT-B99-11
  - **Boundary catalog (QC-3):** ☒ empty ☐ boundary ☒ invalid ☒ error — empty: the MAC-only session; invalid: the hostile names; error: the containment refusal. Boundary: N/A — no numeric limit is involved.
  - **Negative control:** executed on `307065f` (P-11): `inside dest: False` → RED today.

### HLR-161 — The Bytes field reads one base *(provisional: D1 = `hex`)*
- **Traceability:** US-150
- **Ledger:** none — amends batch-07 LLR-001.2 (decimals in the TUI byte grammar) once the verdict lands; that amendment will be ledger entry LED-2026-10-25-batch-99.1.
- **Statement:** When the Patch Editor reads the Bytes field, it shall read every token as hexadecimal, with or without a `0x` prefix, and refuse any token that is not 1–2 hex digits, with a message naming the token. The field's placeholder and the window help shall say that tokens are hex.
- **Rationale (informative):** digit-only tokens are read as decimal inside a hex dump (P-16).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_bytes_field.py`
- **Numeric pass threshold:** `0F 10 1F 20` → `[0x0F,0x10,0x1F,0x20]`; `11 22` → `[0x11,0x22]`; `0x0A ff` → `[0x0A,0xFF]`; `G1` and `100` refused with the token named.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** typing `0F 10 1F 20` at an address, adding and saving back writes `0F 10 1F 20` (independent reader).
  - **Shipped surface:** the Patch Editor Bytes field and save-back.
  - **Acceptance test(s):** AT-B99-12
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: `00`, `FF`; invalid: `100`, `G1`. Empty/error: N/A — the empty field is already refused.
  - **Negative control:** executed on `307065f` (P-16): `0F 10 1F 20` → `0F 0A 1F 14` → RED today.

### HLR-162 — Project and work-area pickers load by name
- **Traceability:** US-151
- **Ledger:** none
- **Statement:** When the operator picks a project in the Load project dialog, by keyboard or by mouse, and confirms, the system shall load the project of that name. When the operator picks an item in the Workarea Files list, it shall load the file of that name from the folder the list reads. The project list shall hold no reserved work-area home (`temp`, `patches` and the other reserved homes). The Workarea Files list shall list the folder that loads write into (CW-U-3).
- **Rationale (informative):** Inc-9 fixed the dialog without a test per pick path; `_load_from_item` keeps the `Label()` pattern (P-19); reserved homes are listed as projects (P-20); the Workarea Files list reads a folder that loads never write to, so the sibling cannot be observed (CW-U-3).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b99_load_project.py`
- **Numeric pass threshold:** 3 pick paths (keyboard highlight + `#project_ok`; click + `#project_ok`; keyboard highlight + `enter` on the button) → 3 loads of the named project; Workarea Files pick → 1 load of the named file; 0 reserved homes in the project list.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** with projects `P1`, `P2` and a `patches` folder, the dialog lists `P1` and `P2` only. Picking `P2` either way and pressing Load shows the status naming `P2`. After a file load, the Workarea Files list shows that file, and picking it loads it.
  - **Shipped surface:** `LoadProjectScreen` (`#project_ok`), the Workarea Files list.
  - **Acceptance test(s):** AT-B99-13
  - **Boundary catalog (QC-3):** ☒ empty ☐ boundary ☒ invalid ☐ error — empty: no project (empty-state, OK disabled or a notice); invalid: only reserved folders present. Boundary/error: N/A.
  - **Negative control:** a mutant restoring `str(label_widget)` in `_load_from_item` → the Workarea pick loads nothing → RED (C-40, Phase 3).

---

## 4. Low-level requirements (LLR)

> Ids `LLR-<HLR>.<M>`. TC ids are `TC-B99-NN`. Each LLR's mutation (Negative control) is run at Phase 3 (C-40).

### LLR-152.1 — Deterministic generation
- **Traceability:** HLR-152
- **Ledger:** none
- **Statement:** The corpus generator shall produce byte-identical files and manifest on every run, from fixed seeds, with no timestamp or host path in any output.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-01 — `pytest tests/test_b99_corpus.py -k tc_b99_01`
- **Numeric pass threshold:** two runs into two temp dirs → 0 differing files.
- **Negative control:** inject `datetime.now()` into the S0 text (mutation) → differing files, RED.
- **Boundary catalog:** none — the generator takes no input.

### LLR-152.2 — Coverage classes
- **Traceability:** HLR-152
- **Ledger:** none
- **Statement:** The manifest shall contain at least one file for each class:
  - S19 with `S1`, with `S2` and with `S3` data; with an S0 header; with an `S5` count; with `S7`, `S8` and `S9` terminators carrying a non-zero entry point;
  - Intel HEX with record types 00, 01, 02, 04 and 05, including a record ending exactly at a 64 KiB boundary;
  - a MAC paired to an S19;
  - an A2L paired to an S19, declaring `MOD_COMMON BYTE_ORDER MSB_FIRST` with a 2-byte symbol, a RAT_FUNC symbol, a COMPU_TAB (`TAB_INTP` and `TAB_NOINTP`) symbol and a LINEAR control;
  - defect cases: S19 without a terminator, S19 with a wrong `S5`, S19 with data after the terminator, HEX without EOF, HEX with data after EOF, an S19 overlap with differing bytes.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-02 — `pytest tests/test_b99_corpus.py -k tc_b99_02`
- **Numeric pass threshold:** 0 classes without a file.
- **Negative control:** delete one class's file from the manifest (mutation) → that class is reported missing, RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — boundary and defect classes are themselves the catalog.

### LLR-152.3 — The independent reader
- **Traceability:** HLR-152
- **Ledger:** none
- **Statement:** `tests/support/independent_reader.py` shall parse S19 and Intel HEX into address → byte maps plus header, terminator and EOF facts, import nothing from `s19_app`, and yield each corpus file's manifest bytes exactly.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-03 — `pytest tests/test_b99_corpus.py -k tc_b99_03` (AST import census + manifest comparison).
- **Numeric pass threshold:** 0 `s19_app` imports; 0 byte mismatches over the corpus.
- **Negative control:** make the reader copy S0 payload into the map (mutation) → mismatches on every S0-bearing file, RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — width edges; defect files parse to the manifest's partial bytes.

### LLR-153.1 — `S19File` maps and ranges exclude S0
- **Traceability:** HLR-153
- **Ledger:** none
- **Statement:** `S19File.get_memory_map` and `S19File.get_memory_ranges` (`s19_app/core.py`) shall include bytes of `S1`/`S2`/`S3` records only. *(Crosses the frozen engine layer, `docs/ARCHITECTURE.md` §7. That rule allows it when the crossing is named; this is the naming, and B99-I3 records the contract change.)*
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-04 — `pytest tests/test_b99_s0.py -k tc_b99_04`
- **Numeric pass threshold:** for every S0-bearing corpus S19: map keys == manifest data addresses; 0 range starting at the S0 address unless a data record declares it.
- **Negative control:** re-admit S0 in the record filter (mutation) → extra keys, RED.
- **Boundary catalog:** ☒ empty ☒ boundary — S0-only file → empty map; an S0 alongside data at `0x0` (data kept, header not).

### LLR-153.2 — `build_mem_map_s19` excludes S0
- **Traceability:** HLR-153
- **Ledger:** none
- **Statement:** `build_mem_map_s19` (`s19_app/render/hexview.py`) shall build its map from `S1`/`S2`/`S3` records only.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-05 — `pytest tests/test_b99_s0.py -k tc_b99_05`
- **Numeric pass threshold:** map == `S19File.get_memory_map()` == manifest bytes for every corpus S19.
- **Negative control:** mutation as LLR-153.1 → RED.
- **Boundary catalog:** ☒ empty — S0-only file.

### LLR-153.3 — Written images carry S0 as header only
- **Traceability:** HLR-153
- **Ledger:** none
- **Statement:** An image loaded from an S19 and written by `save_patched_image` or the flow WRITE-OUT step shall carry the source's S0 as an `S0` record and no data record that the source lacked.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-06 — `pytest tests/test_b99_s0.py -k tc_b99_06` (independent reader).
- **Numeric pass threshold:** written S0 text == source S0 text; written data bytes == source data bytes.
- **Negative control:** mutation as LLR-153.1 → extra data at `0x0`, RED.
- **Boundary catalog:** ☒ boundary — S19 and HEX output of the same source.

### LLR-153.4 — A patch at the S0 address is outside the image
- **Traceability:** HLR-153
- **Ledger:** none
- **Statement:** A change entry at an address covered only by the S0 payload shall get disposition `skipped-outside`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-07 — `pytest tests/test_b99_s0.py -k tc_b99_07`
- **Numeric pass threshold:** `case_01`, entry `0x0 AA BB` → `skipped-outside`, 0 bytes written at `0x0`.
- **Negative control:** executed on `307065f` (P-2): `applied 1 entry` → RED.
- **Boundary catalog:** ☒ boundary — the last S0 payload address.

### LLR-154.1 — S19 terminator and count checks *(provisional, D6)*
- **Traceability:** HLR-154
- **Ledger:** none
- **Statement:** *(Crosses the frozen engine layer, `docs/ARCHITECTURE.md` §7; named here.)* The S19 loader (`s19_app/core.py` `_load`) shall attach a notice when the file has no `S7`/`S8`/`S9` record, when an `S5`/`S6` count differs from the number of data records, and when any record follows the terminator. Each notice shall name its defect.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-08 — `pytest tests/test_b99_truncation.py -k tc_b99_08`
- **Numeric pass threshold:** 3 defect files → 3 notices with the defect named; well-formed corpus S19 → 0 notices.
- **Negative control:** drop the terminator check (mutation) → 0 notices on the cut file, RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — terminator as the last line (control); the three defects.

### LLR-154.2 — HEX EOF checks *(provisional, D6)*
- **Traceability:** HLR-154
- **Ledger:** none
- **Statement:** *(Crosses the frozen engine layer, §7; named here.)* The HEX loader (`s19_app/hexfile.py` `_load`) shall attach a notice when the file has no type-01 record, and a notice naming the count of records ignored after the first EOF.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-09 — `pytest tests/test_b99_truncation.py -k tc_b99_09`
- **Numeric pass threshold:** 2 defect files → 2 notices; the after-EOF notice states the ignored record count.
- **Negative control:** drop the EOF check (mutation) → 0 notices, RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — EOF as the last line; the two defects.

### LLR-154.3 — SOURCE fails on an integrity notice *(provisional, D6)*
- **Traceability:** HLR-154
- **Ledger:** none
- **Statement:** The flow SOURCE step (`flow_execution_service.py`) shall end with status `error` when the loaded image carries a notice of LLR-154.1 or LLR-154.2, and the flow shall write no file.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-10 — `pytest tests/test_b99_truncation.py -k tc_b99_10`
- **Numeric pass threshold:** 5 defect sources → 5 SOURCE `error`, 0 files written.
- **Negative control:** map the notice to `notices` (mutation) → a file is written, RED.
- **Boundary catalog:** ☒ error — the refusal itself.

### LLR-155.1 — Private staging file
- **Traceability:** HLR-155
- **Ledger:** none
- **Statement:** `save_patched_image` (`tui/changes/apply.py`) shall stage each write in a file created exclusively under `<workarea>/temp/` with a unique generated name, never `temp/<user name>`, and shall remove only that staging file.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-11 — `pytest tests/test_b99_staging.py -k tc_b99_11`
- **Numeric pass threshold:** a same-name save-back → the loaded work copy exists and is byte-equal to its pre-save bytes; 0 leftover staging files.
- **Negative control:** executed on `307065f` (P-15): `work copy exists after save-back: False` → RED.
- **Boundary catalog:** ☒ boundary — the user name equal to the work copy's name.

### LLR-155.2 — Atomic, non-shared placement
- **Traceability:** HLR-155
- **Ledger:** none
- **Statement:** The final placement (`save_patched_image` with `copy_into_workarea`, `tui/workspace.py`) shall reserve the final name with an exclusive create and fill it by atomic replace from the private staging file, so that concurrent writers never share a target.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-12 — `pytest tests/test_b99_staging.py -k tc_b99_12` (8 threads × 20 trials, distinct markers, independent reader).
- **Numeric pass threshold:** 0 files whose bytes differ from the writer that reported them; 0 exceptions.
- **Negative control:** executed on `307065f` (P-5): `parallel mismatches: 35` → RED.
- **Boundary catalog:** ☒ boundary — 1 writer and 8 writers.

### LLR-155.3 — Byte-identical reuse stays race-free
- **Traceability:** HLR-155
- **Ledger:** none
- **Statement:** `copy_into_workarea`'s reuse of a byte-identical existing target (B8) shall compare and reuse without a window in which another writer can replace the target between the check and the reuse.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-13 — `pytest tests/test_b99_staging.py -k tc_b99_13`
- **Numeric pass threshold:** a target replaced between check and reuse (forced by a hook) → the caller receives a path whose bytes equal its own.
- **Negative control:** restore check-then-copy (mutation) → mismatching bytes, RED.
- **Boundary catalog:** ☒ boundary — identical bytes (reuse) vs different bytes (new name).

### LLR-155.4 — Save project survives a missing source
- **Traceability:** HLR-155
- **Ledger:** none
- **Statement:** `_handle_save_dialog` (`tui/app.py`) shall catch a missing source file, report a notice naming it, and leave the app running with no partial project folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-14 — `pytest tests/test_b99_staging.py -k tc_b99_14`
- **Numeric pass threshold:** app running after the dismiss; 1 notice naming the file; 0 empty project folders left.
- **Negative control:** executed on `307065f` (P-15): `return_code: 1` → RED.
- **Boundary catalog:** ☒ error — the missing file.

### LLR-155.5 — Duplicate output names are refused at start *(provisional, D7)*
- **Traceability:** HLR-155
- **Ledger:** none
- **Statement:** `run_chain_set` shall refuse to start when two or more lanes resolve to the same WRITE-OUT file name, returning an error that names those lanes, and shall write nothing.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-15 — `pytest tests/test_b99_staging.py -k tc_b99_15`
- **Numeric pass threshold:** 2 lanes named `same.s19` → refused, both lane names in the message, 0 files.
- **Negative control:** remove the check (mutation) → files written, RED.
- **Boundary catalog:** ☒ invalid — duplicate names; distinct names (control).

### LLR-155.6 — WRITE-OUT verifies what it wrote *(provisional, D9)*
- **Traceability:** HLR-155
- **Ledger:** none
- **Statement:** The flow WRITE-OUT step shall call `verify_written_image` on the written file and end with status `error`, naming the first differing address, when it reports a mismatch.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-16 — `pytest tests/test_b99_staging.py -k tc_b99_16`
- **Numeric pass threshold:** a write corrupted after placement (forced by a hook) → `error`; an intact write → `ok`.
- **Negative control:** skip the verify call (mutation) → `ok` on the corrupted write, RED.
- **Boundary catalog:** ☒ error — the mismatch.

### LLR-156.1 — PATCH status from dispositions *(provisional, D5)*
- **Traceability:** HLR-156
- **Ledger:** none
- **Statement:** The flow PATCH arm (`flow_execution_service.py`) shall derive its status as HLR-156 states. Its summary shall name each non-applied address with its disposition and each refusal code. A PATCH `error` shall stop the flow before any later WRITE-OUT step.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-17 — `pytest tests/test_b99_patch_truth.py -k tc_b99_17` (the 7-case matrix).
- **Numeric pass threshold:** statuses as HLR-156's threshold; 0 WRITE-OUT files after `error`.
- **Negative control:** executed on `307065f` (P-4): every case `ok` → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☒ error — as HLR-156.

### LLR-156.2 — The chain outcome carries dispositions
- **Traceability:** HLR-156
- **Ledger:** none
- **Statement:** `ChainRunOutcome` shall carry the run's `change_records` and `refusals`, and the Flow Execution lane shall paint each lane's PATCH cell from its block status, so that `notices` and `error` are visible.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-18 — `pytest tests/test_b99_patch_truth.py -k tc_b99_18`
- **Numeric pass threshold:** malformed-doc lane → outcome holds `MF-JSON-PARSE` in `refusals`; lane cell glyph is the error glyph.
- **Negative control:** executed on `307065f` (P-14): `outcome status: ok` → RED.
- **Boundary catalog:** ☒ error — the malformed lane.

### LLR-156.3 — The chain-set report lists what was not applied
- **Traceability:** HLR-156
- **Ledger:** none
- **Statement:** `compose_chain_set_report` shall list, per lane, the written file paths, each non-applied entry (address and disposition) and each refusal (code and message).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-19 — `pytest tests/test_b99_patch_truth.py -k tc_b99_19`
- **Numeric pass threshold:** 100 % of non-applied addresses, refusal codes and written paths of the fixture set appear in the report text.
- **Negative control:** executed on `307065f` (P-14): the row `| 1 | badlane | t | ✓ ok | 3 |` names none → RED.
- **Boundary catalog:** ☒ empty — a clean lane lists `none`.

### LLR-156.4 — The flow report lists what was not applied
- **Traceability:** HLR-156
- **Ledger:** none
- **Statement:** The flow report (`flow_report_service.py`) shall list each non-applied record and each refusal, and shall not say `CLEAN` when either list is non-empty.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-20 — `pytest tests/test_b99_patch_truth.py -k tc_b99_20`
- **Numeric pass threshold:** `mix.json` → the report names `0x20000` and `skipped-outside`; `bad.json` → names `MF-JSON-PARSE`; neither says `CLEAN`.
- **Negative control:** executed on `307065f` (`rw-p09`): `Status: CLEAN` → RED.
- **Boundary catalog:** ☒ empty ☒ error — clean run (still `CLEAN`); malformed.

### LLR-157.1 — Pristine snapshot plus current document
- **Traceability:** HLR-157
- **Ledger:** none
- **Statement:** `ChangeService.apply` (`tui/services/change_service.py`) shall leave the image equal to the source bytes plus the current document's entries. Before it applies, it shall restore to their source values the bytes that an earlier apply wrote for entries the document no longer holds. ARQ recommends a journal of original bytes kept in `ChangeService` (`design/ARQ-batch-99.md` §2); PDR fixes the mechanism.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-21 — `pytest tests/test_b99_editor_image.py -k tc_b99_21`
- **Numeric pass threshold:** the p05 sequence → image at `0xEB10` == source; 1 entry in the summary.
- **Negative control:** executed on `307065f` (P-6): `deadbeef` → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — all entries undone; overlapping entries.

### LLR-157.2 — Undo, remove and edit revert applied bytes
- **Traceability:** HLR-157
- **Ledger:** none
- **Statement:** When `undo`, `redo`, `remove_entry` or `edit_entry` changes an applied entry, `ChangeService` shall re-derive the image per LLR-157.1 before the next save, and the save summary shall list exactly the entries the image holds.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-22 — `pytest tests/test_b99_editor_image.py -k tc_b99_22`
- **Numeric pass threshold:** remove-after-apply and edit-after-apply arms → 0 stale bytes; summary count == entries in the image.
- **Negative control:** skip the re-derive on remove (mutation) → stale bytes, RED.
- **Boundary catalog:** ☒ boundary — redo after undo.

### LLR-157.3 — The change engine is the only in-place writer of the editor image
- **Traceability:** HLR-157
- **Ledger:** none
- **Statement:** No code path other than the change engine's apply (`tui/changes/apply.py`, reached through `ChangeService.apply`) shall write `LoadedFile.mem_map` in place. Every other writer (the CRC inject, flow and variant runs) shall write a copy. ARQ's census at `307065f` finds exactly that one in-place site (`apply.py:337`), so restoring from source loses no mutation (`design/ARQ-batch-99.md` §2).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-37 — `pytest tests/test_b99_editor_image.py -k tc_b99_37` (AST census of subscript or `update` writes to a `mem_map` attribute of a `LoadedFile`-typed name across `s19_app/`).
- **Numeric pass threshold:** exactly 1 in-place write site, in `tui/changes/apply.py`.
- **Negative control:** add `self.current_file.mem_map[0] = 0` in a scratch copy of `app.py` (mutation) → 2 sites, RED.
- **Boundary catalog:** none — a static census with no input.

### LLR-158.1 — Byte-order fallback reads `MOD_COMMON` *(provisional, D3)*
- **Traceability:** HLR-158
- **Ledger:** none
- **Statement:** *(LLR-158.1..158.3 cross the frozen engine layer — `tui/a2l.py`, `docs/ARCHITECTURE.md` §7; named here.)* The effective byte order (`tui/a2l.py`) shall fall back tag → RECORD_LAYOUT → tag endian → `MOD_COMMON BYTE_ORDER` → `little`, and `encode_physical_to_raw_bytes` and the decode path shall both use it.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-23 — `pytest tests/test_b99_a2l_encode.py -k tc_b99_23`
- **Numeric pass threshold:** MSB_FIRST 2-byte: encode 4113 → `10 11`; decode `10 11` → 4113; LSB_FIRST control unchanged.
- **Negative control:** executed on `307065f` (P-7): `little` → RED.
- **Boundary catalog:** ☒ boundary — 1-byte value (order irrelevant), 2- and 4-byte values.

### LLR-158.2 — RAT_FUNC direction *(provisional, D2)*
- **Traceability:** HLR-158
- **Ledger:** none
- **Statement:** `_apply_compu_method` shall decode a RAT_FUNC by solving INT = f(PHYS) for PHYS, and the encoder shall compute INT = f(PHYS) directly.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-24 — `pytest tests/test_b99_a2l_encode.py -k tc_b99_24`
- **Numeric pass threshold:** `RAT_FUNC_DIV_10`: 30 → raw 300; 25 → raw 250; raw 300 → 30.0; LINEAR control unchanged.
- **Negative control:** executed on `307065f` (P-17): 30 → `03 00` → RED.
- **Boundary catalog:** ☒ invalid — a coefficient set with no inverse is refused (existing message kept).

### LLR-158.3 — COMPU_TAB values that do not round-trip are refused *(provisional, D4)*
- **Traceability:** HLR-158
- **Ledger:** none
- **Statement:** The COMPU_TAB inversion shall refuse a physical value whose encoded raw value decodes to a different physical value, beyond the method's tolerance, returning an error that names the nearest representable physical values.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-25 — `pytest tests/test_b99_a2l_encode.py -k tc_b99_25`
- **Numeric pass threshold:** `TAB_NOINTP` 13.0 refused (names 10.0 and the next entry); `TAB_INTP` 500.0 and -50.0 refused; table values accepted.
- **Negative control:** executed on `307065f` (P-8): `err=None` → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — table endpoints; out-of-table values.

### LLR-159.1 — Empty region is an error
- **Traceability:** HLR-159
- **Ledger:** none
- **Statement:** The CRC operation (`tui/operations/crc.py`) shall return an error and no injection when its region holds 0 image bytes.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-26 — `pytest tests/test_b99_crc_region.py -k tc_b99_26`
- **Numeric pass threshold:** `0x20000–0x30000` on `prg.s19` → error; slot bytes unchanged.
- **Negative control:** executed on `307065f` (P-9): `slot_bytes=00000000` → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — 0 and 1 present byte.

### LLR-159.2 — Partial coverage is a notice on the flow arm
- **Traceability:** HLR-159
- **Ledger:** none
- **Statement:** The flow CRC arm shall end with status `notices` naming the absent byte count when the region is partly covered, for legacy and new region forms alike.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-27 — `pytest tests/test_b99_crc_region.py -k tc_b99_27`
- **Numeric pass threshold:** region over a gap → `notices`, count == independent count of absent addresses.
- **Negative control:** executed on `307065f` (P-9): `region_over_gap run=ok … findings=[]` → RED.
- **Boundary catalog:** ☒ boundary — full coverage (control `ok`).

### LLR-159.3 — The CRC write stages privately
- **Traceability:** HLR-159
- **Ledger:** none
- **Statement:** The CRC operation's write of `<stem>-crc.s19` (`tui/operations/crc.py`, `EMITTED_NAME_SUFFIX`) shall go through the private staging and atomic placement of LLR-155.1/155.2, never through a shared `temp/<name>` staging path.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-38 — `pytest tests/test_b99_crc_region.py -k tc_b99_38` (two concurrent CRC writes of the same stem, each file checked by the independent reader against its own CRC).
- **Numeric pass threshold:** 0 files whose CRC slot differs from the write that reported them, over 20 trials.
- **Negative control:** restore the shared `temp/<name>` staging (mutation) → mismatches, RED.
- **Boundary catalog:** ☒ boundary — 1 writer and 2 writers.

### LLR-160.1 — Sanitised segment names
- **Traceability:** HLR-160
- **Ledger:** none
- **Statement:** `SegmentSplitView` shall build export file names from segment names passed through the work area's file-name sanitiser (the grammar `sanitize_project_name` / `_sanitize_s19_filename` use).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-28 — `pytest tests/test_b99_export.py -k tc_b99_28`
- **Numeric pass threshold:** hostile names → names free of `/`, `\`, `..`, `:` and reserved device names.
- **Negative control:** bypass the sanitiser (mutation) → a separator survives, RED.
- **Boundary catalog:** ☒ invalid — the hostile set of HLR-160.

### LLR-160.2 — Containment check before writing
- **Traceability:** HLR-160
- **Ledger:** none
- **Statement:** The export writer (`segment_split_view.py` `_write`, `s19_app/segment_ops.py`) shall resolve each final path and refuse to write when it is not inside the resolved destination directory.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-29 — `pytest tests/test_b99_export.py -k tc_b99_29`
- **Numeric pass threshold:** 0 files outside the destination for the hostile set; refusal message names the segment.
- **Negative control:** executed on `307065f` (P-11): `inside dest: False` → RED.
- **Boundary catalog:** ☒ error — the refusal.

### LLR-160.3 — MAC-only export is header-only
- **Traceability:** HLR-160
- **Ledger:** none
- **Statement:** The export writer shall take its bytes from the image's declared ranges, not from MAC placeholder entries, so a MAC-only session writes an S19/HEX with no data record.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-30 — `pytest tests/test_b99_export.py -k tc_b99_30`
- **Numeric pass threshold:** 0 data records (independent reader).
- **Negative control:** executed (P-18): `S306800000000079` written → RED.
- **Boundary catalog:** ☒ empty — the MAC-only session.

### LLR-160.4 — A second export replaces atomically *(provisional, D8)*
- **Traceability:** HLR-160
- **Ledger:** none
- **Statement:** When an export's final name exists, the writer shall write a private staging file and `os.replace` it onto the final name, and the status shall say `replaced`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-31 — `pytest tests/test_b99_export.py -k tc_b99_31`
- **Numeric pass threshold:** 1 file holding the second export's bytes; status contains `replaced`.
- **Negative control:** write in place (mutation) with an interrupted write → truncated file, RED.
- **Boundary catalog:** ☒ boundary — first export (no `replaced`).

### LLR-161.1 — Hex-only token grammar *(provisional, D1)*
- **Traceability:** HLR-161
- **Ledger:** none
- **Statement:** `parse_new_bytes` (`tui/services/change_service.py`) shall read each token as base 16 with an optional `0x` prefix, accept 1–2 hex digits, and raise a `ValueError` naming any other token.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-32 — `pytest tests/test_b99_bytes_field.py -k tc_b99_32`
- **Numeric pass threshold:** as HLR-161's threshold.
- **Negative control:** executed (P-16): `0F 10 1F 20` → `0F 0A 1F 14` → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — `00`, `FF`; `100`, `G1`.

### LLR-161.2 — The field says it is hex *(provisional, D1)*
- **Traceability:** HLR-161
- **Ledger:** none
- **Statement:** The Bytes field's placeholder and the Patch Editor's window help entry shall state that tokens are hex.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-33 — `pytest tests/test_b99_bytes_field.py -k tc_b99_33`
- **Numeric pass threshold:** both texts contain `hex`.
- **Negative control:** revert the help text (mutation) → RED.
- **Boundary catalog:** none — static text.

### LLR-162.1 — `_load_from_item` reads the item's name
- **Traceability:** HLR-162
- **Ledger:** none
- **Statement:** `_load_from_item` (`tui/app.py`) shall obtain the file name from the item's stored name (as the Inc-9 dialog fix does), never from `str(Label)`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-34 — `pytest tests/test_b99_load_project.py -k tc_b99_34`
- **Numeric pass threshold:** picking `a.s19` loads `a.s19`.
- **Negative control:** restore `str(label_widget)` (mutation) → nothing loads, RED.
- **Boundary catalog:** ☒ boundary — a name with spaces.

### LLR-162.2 — Reserved homes are not projects
- **Traceability:** HLR-162
- **Ledger:** none
- **Statement:** `list_projects` shall omit every reserved work-area home (`temp`, `patches` and each other home the work area creates).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B99-35 — `pytest tests/test_b99_load_project.py -k tc_b99_35`
- **Numeric pass threshold:** 0 reserved homes listed; every user project listed.
- **Negative control:** executed (P-20): `patches` listed → RED.
- **Boundary catalog:** ☒ empty — only reserved homes present.

### LLR-162.3 — The Workarea Files list reads the load folder (CW-U-3)
- **Traceability:** HLR-162
- **Ledger:** none
- **Statement:** The Workarea Files list shall list the folder that file loads copy into, and `_load_from_item` shall resolve picked names against that same folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B99-36 — `pytest tests/test_b99_load_project.py -k tc_b99_36`
- **Numeric pass threshold:** after one file load, the list holds that file; picking it loads it.
- **Negative control:** read the work-area root (mutation, today's behaviour) → empty list, RED.
- **Boundary catalog:** ☒ empty — no file loaded yet.

### Information Flow Contract (IFC) — C-54

- **Part A — flows:**

```
FLOW: s19_file_to_written_image
  SOURCE : an S19 file on disk (corpus or examples/)
  NODES  :
    - fn    : S19File._load / get_memory_map / get_memory_ranges (core.py)
      owner : LLR-153.1
      in    : the file's records
      out   : address → byte map of S1/S2/S3 data, S0 kept as header text
    - fn    : build_mem_map_s19 (render/hexview.py)
      owner : LLR-153.2
      in    : S19File
      out   : the same map
    - fn    : save_patched_image / flow WRITE-OUT emit (changes/apply.py, flow_execution_service.py)
      owner : LLR-153.3
      in    : image + S0 header text
      out   : the written S19/HEX file
  SINK   : the written file, read by the independent reader
```

```
FLOW: loader_integrity_notice_to_flow_status
  SOURCE : an S19 or HEX file with a missing terminator / EOF, an S5 mismatch or records after the end
  NODES  :
    - fn    : S19 loader checks (core.py _load)
      owner : LLR-154.1
      in    : records
      out   : load notices naming the defect
    - fn    : HEX loader checks (hexfile.py _load)
      owner : LLR-154.2
      in    : records
      out   : load notices naming the defect and the ignored count
    - fn    : flow SOURCE arm (flow_execution_service.py)
      owner : LLR-154.3
      in    : the loaded image's notices
      out   : SOURCE status error; no WRITE-OUT
  SINK   : the Flow Execution lane cell and the issues panel
```

```
FLOW: image_to_final_file
  SOURCE : an image to write (Patch Editor save-back, flow WRITE-OUT, chain-set lanes)
  NODES  :
    - fn    : save_patched_image staging (changes/apply.py)
      owner : LLR-155.1
      in    : image bytes + the requested name
      out   : a private staging file under temp/
    - fn    : exclusive reservation + atomic replace (workspace.py copy_into_workarea)
      owner : LLR-155.2
      in    : the staging file
      out   : the final file, owned by this write
    - fn    : byte-identical reuse (workspace.py)
      owner : LLR-155.3
      in    : the staging file + an existing target
      out   : the reused path or a new name
    - fn    : WRITE-OUT verify (flow_execution_service.py)
      owner : LLR-155.6
      in    : the final file + the image
      out   : WRITE-OUT status
  SINK   : the file the step reports
```

```
FLOW: change_dispositions_to_run_records
  SOURCE : a change document applied by a flow PATCH step
  NODES  :
    - fn    : apply_change_document (changes/apply.py; unchanged, P-13)
      owner : LLR-156.1
      in    : document + image
      out   : ChangeSummary with per-entry dispositions + refusals
    - fn    : flow PATCH arm status (flow_execution_service.py)
      owner : LLR-156.1
      in    : ChangeSummary
      out   : BlockResult status + summary naming non-applied addresses
    - fn    : ChainRunOutcome (flow_execution_service.py)
      owner : LLR-156.2
      in    : FlowRunResult change_records + refusals
      out   : outcome carrying them
    - fn    : compose_chain_set_report (flow_execution_service.py)
      owner : LLR-156.3
      in    : ChainRunOutcome list
      out   : report rows with written paths, non-applied entries, refusals
    - fn    : flow report composer (flow_report_service.py)
      owner : LLR-156.4
      in    : FlowRunResult
      out   : report text, status not CLEAN when non-empty
  SINK   : the lane cell, the chain-set report file, the flow report file
```

```
FLOW: editor_document_to_saved_image
  SOURCE : the Patch Editor's change document and the loaded source image
  NODES  :
    - fn    : ChangeService.apply (change_service.py)
      owner : LLR-157.1
      in    : pristine source map + document
      out   : the image
    - fn    : ChangeService undo / redo / remove_entry / edit_entry
      owner : LLR-157.2
      in    : the document change
      out   : the re-derived image
    - fn    : in-place writer census (every `mem_map` write in s19_app/)
      owner : LLR-157.3
      in    : the source tree
      out   : exactly one in-place site
  SINK   : the save-back file and its summary
```

```
FLOW: physical_value_to_raw_bytes
  SOURCE : a physical value typed for an A2L symbol in the Patch Editor
  NODES  :
    - fn    : effective byte order (a2l.py)
      owner : LLR-158.1
      in    : tag, RECORD_LAYOUT, MOD_COMMON
      out   : byte order
    - fn    : RAT_FUNC encode / decode (a2l.py)
      owner : LLR-158.2
      in    : physical or raw value + coefficients
      out   : raw or physical value
    - fn    : COMPU_TAB inversion (a2l.py)
      owner : LLR-158.3
      in    : physical value + table
      out   : raw value or refusal naming the nearest values
  SINK   : the change entry's bytes, and the A2L window's physical column
```

```
FLOW: crc_region_to_slot
  SOURCE : a flow CRC step's region and output slot
  NODES  :
    - fn    : region coverage (operations/crc.py)
      owner : LLR-159.1
      in    : image + region
      out   : present-byte stream or an empty-region error
    - fn    : flow CRC arm (flow_execution_service.py)
      owner : LLR-159.2
      in    : coverage
      out   : status ok / notices (absent count) / error
    - fn    : CRC output write (operations/crc.py, `<stem>-crc.s19`)
      owner : LLR-159.3
      in    : the injected image
      out   : the written file, privately staged
  SINK   : the slot bytes in the written image and the lane cell
```

```
FLOW: segment_name_to_export_file
  SOURCE : an A2L MEMORY_SEGMENT name, or a MAC-only session's map
  NODES  :
    - fn    : row name build (segment_split_view.py)
      owner : LLR-160.1
      in    : segment name
      out   : sanitised file name
    - fn    : export writer containment (segment_split_view.py _write, segment_ops.py)
      owner : LLR-160.2
      in    : destination + file name
      out   : a contained path or a refusal
    - fn    : export byte source (segment_split_view.py)
      owner : LLR-160.3
      in    : declared ranges
      out   : the bytes written (none for MAC-only)
    - fn    : atomic replace (segment_split_view.py)
      owner : LLR-160.4
      in    : staging file + existing target
      out   : the replaced file
  SINK   : the export file on disk
```

```
FLOW: bytes_field_to_entry
  SOURCE : the text of the Patch Editor Bytes field
  NODES  :
    - fn    : parse_new_bytes (change_service.py)
      owner : LLR-161.1
      in    : tokens
      out   : byte values or an error naming the token
    - fn    : Bytes placeholder + window help (screens_directionb.py, window_help.py)
      owner : LLR-161.2
      in    : —
      out   : the text that tells the user tokens are hex
  SINK   : the change entry and the saved file
```

```
FLOW: picked_item_to_loaded_file
  SOURCE : an item picked in the Load project dialog or the Workarea Files list
  NODES  :
    - fn    : list_projects (app.py)
      owner : LLR-162.2
      in    : work-area folders
      out   : project names, reserved homes omitted
    - fn    : Workarea Files list source (app.py)
      owner : LLR-162.3
      in    : the load folder
      out   : file items
    - fn    : _load_from_item (app.py)
      owner : LLR-162.1
      in    : the picked item
      out   : the loaded file
  SINK   : the status line and the loaded image
```

```
FLOW: corpus_to_manifest
  SOURCE : the generator's fixed seeds
  NODES  :
    - fn    : generate.py (tests/fixtures/synth/)
      owner : LLR-152.1
      in    : seeds
      out   : files + manifest
    - fn    : coverage census
      owner : LLR-152.2
      in    : manifest
      out   : missing classes (0)
    - fn    : independent_reader (tests/support/)
      owner : LLR-152.3
      in    : each file
      out   : bytes compared with the manifest
  SINK   : `generate.py --check` exit code
```

- **Part B — boundary decomposition:** no — the batch changes no component a consumer addresses independently; every flow above ends at a file on disk or a painted cell.

---

## 5. Validation strategy

### 5.1 Methods

- **Layer A — white-box / functional:** TC-B99-01..38 (`test (unit)` / `test (integration)`), each named in its LLR, with a mutation run at Phase 3 (C-40) for every LLR that declares one.
- **Layer B — black-box acceptance:** AT-B99-01..13. Each one drives the shipped surface and observes files through the independent reader, painted text or report files. AT drivers live beside the TCs in `tests/test_b99_*.py` and are marked `at_b99_NN`.
- **Oracle:** every byte comparison uses the corpus manifest or the independent reader, never `s19_app`'s loader (P-3).
- **Regression:** the full suite once per increment cut, against `evidence/baseline-pytest-51ee191.txt` (10 failed, 3101 passed) plus batch-97's additions (3617 passed). Existing tests that assert today's wrong behaviour (e.g. TC-714, range counts on S0-bearing fixtures) are re-pinned in the increment that changes the behaviour, each named in that packet's reverse census.

### 5.2 Batch acceptance criteria
- 100 % of LLRs covered by at least one passing TC; every declared mutation goes RED.
- Every story has at least one passing AT-B99 observing its outcome through the shipped surface, with its boundary and negative evidence.
- Every premise probe of §2.7 that served as a RED side is re-run at Phase 4 and its decisive line has flipped (e.g. `parallel mismatches: 0`, `inside dest: True`).
- 0 blocker findings open at Phase 4; full suite with no new failure against the baseline.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
### 6.2 Relevant design decisions
### 6.3 Open risks

**Security questions (`devflow-scan-spec.py` flags `token`, `session`, `user input`, `form`; `security_required: true`):**
- **Input surface (C6).** The batch changes four parsers of untrusted files: the S19 loader, the HEX loader, the A2L codec and the change-document Bytes grammar. It also changes one path built from file content (the A2L `MEMORY_SEGMENT` name → export file name, H-9). Every new check refuses or notices; none widens what is accepted, except D1 option `prefijo`, which adds one syntax. H-9 is a path-containment fix on a local writer: LLR-160.1/160.2 sanitise the name and check the resolved path before writing. The `security-reviewer` at P2 reviews the hostile-name set and the containment test.
- **"token" / "session" / "form"** here mean a byte token in the Bytes field, a TUI editing session and a dialog form. No authentication, credential, network or secret is involved.
- **File-derived text in painted cells (C8).** HLR-156 paints refusal messages and addresses into lane cells and reports. Those messages can echo file content (e.g. a symbol name), so they render through the existing markup-safe path (`safe_text` / literal rendering, batch-97 LLR-144.7). The AT for HLR-156 adds a hostile-name arm.
- **Atomic writes (H-3).** Staging files are created exclusively under `<workarea>/temp/` with generated names, so no user-chosen name reaches the staging path.

**Other risks:**
- Re-pinning tests that assert today's wrong behaviour (S0 ranges, TC-714) could hide a real regression. Mitigation: each re-pin is named in the increment's reverse census with the old value, the new value and the requirement that changes it.
- The A2L direction change (D2) changes the displayed physical values of RAT_FUNC symbols. Any patch file a user already wrote with the old direction held wrong values. The release note says so.
### 6.4 Phase-1 reconciliation log — moved to the ledger (§7)

### 6.5 Requirement amendments — moved to the ledger (§7)

---

## 7. The ledger — authored as a SEPARATE FILE

The fence below is the ledger's seed: `devflow-init.py` writes it to `01-requirements-ledger.md`. The shape of an entry is in the field guide.

```markdown
# Requirements ledger — s19_app — Batch 2026-10-25-batch-99

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```
