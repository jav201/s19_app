# S13 — Operations & CRC: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S13 (lines 5830–6365): 13 primary rows in 14 blocks — R-OPS-001, 002, 003, R-CRC-ENGINE-001, 002, R-CRC-CHECK-001, R-CRC-WRITE-001, R-CRC-CONFIG-001, R-CRC-GROUP-001, R-CRC-WIDTH-001 (twice: two unrelated blocks share the id), R-CRC-CONTRACT-001, R-CRC-CONFIGLOAD-001, R-TUI-100 — plus the "per-operation requirements convention (C-7)". Also absorbed: the CRC-operation parts of S0's HLR-159 / LLR-159.1 and LLR-155.8, the CRC Designer behaviour of S0's LLR-122.4 (kernel, presets, templates) and the CRC Designer part of HLR-139; the items S7, S8 and S11 passed (section 5, last block). R-HEX-HYGIENE-001 stays S7's; only its error rule is here (R-OPS-003.11, .12).
Code: `s19_app/tui/operations/` (`registry.py`, `model.py`, `placeholders.py`, `crc.py`, `crc_config.py`, `crc_kernel.py`, `crc_designer_model.py`, `crc_template.py`), `services/operation_service.py`, `crc_designer_view.py`, `screens.py::OperationsScreen` / `ConfirmWriteScreen`, the S13 functions of `app.py` (`action_operations_view`, `record_template_load`, `_compose_screen_crc_designer`), the `#crc_*` rules of `styles.tcss`. Read directly, every fact with `file:line`. No test was run. One pure-math check was run on copied formulas (D13-20).
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: the "Code today" cell of R-CRC-TEMPLATE-001.12 verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-OPS, CTX-CRC (the CRC model and every algorithm by its parameters), CTX-CRCCONFIG, CTX-CRCRESULT, CTX-DESIGNER. They cover the six ambiguity families of `review/weak-point-check.md` (C1 spans, C2 two parameter models, C3 stored field, C4 three widths, C5 stage words, C6 two CRC surfaces).
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first** (TUI rule).
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S13.md` (to be merged into `review/CODE-CHANGES.md`). Nothing is changed in the code yet.

---

## 1. How S13 was written before

- About 535 lines for 13 rows from batches 08, 10, 12, 13, 17, 32 and 72. Most of the text is process: batch status lines, validation verdicts and suite counts, "scope boundaries (honest)", amendment history, a falsifiability transcript, and pointers to `.dev-flow/` documents and to `operations/requirements/REQ-crc.md` as "the normative source".
- R-OPS-001 … 003 and R-CRC-CONTRACT-001 are code contracts: class names, signatures, dataclass fields, a registry seam, import bans, widget ids, a pinned argument tuple.
- The CRC rows never define the CRC model: no span convention, two parameter vocabularies (`reverse` vs `refin`/`refout`), "width" in three senses, and no byte layout of the stored value beyond "4-byte little-endian".
- R-TUI-100 is one long statement of widget ids and geometry predicates, followed by its rationale, what it "deliberately does NOT claim", and test history.
- The CRC Designer's behaviour (presets, self-test, custom vector, coverage preview, templates) has no row; only S0's LLR-122.4 names it.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-CRC-WIDTH-001 | Two unrelated blocks share the id: the stored field width (batch-32) and the S19 record width of the CRC write (batch-17). | Field width keeps R-CRC-WIDTH-001.x; record width becomes R-CRC-RECWIDTH-001.x (D13-5). |
| R-OPS-001 | Requires `CrcOperation` to be a placeholder with status `placeholder`. The registry holds the real CRC operation (`registry.py:9`, `:16`; `crc.py:1567`). | Follows the code (D13-4). |
| R-OPS-003 vs R-CRC-CHECK-001 | R-OPS-003: execution "synchronously on the UI thread … no worker". R-CRC-CHECK-001 cites the worker, and the code runs the CRC check and write on workers (`screens.py:2376`, `:2651`). | One observable row: the screen stays responsive (R-OPS-003.7, D13-3). |
| R-OPS-003 | "execute … exclusively through the `run_operation` service seam". The dialog never calls `run_operation`: it resolves the operation and calls `execute` itself (`screens.py:2329`, `:2369`, `:2373`). | `run_operation` removed (D13-14). |
| R-OPS-003 | "The activity rail stays at exactly eight items … `rail.py` unmodified by the batch". The rail has 12 items (S6 CTX-SHELL). Batch history. | Out (D13-12). |
| R-OPS-003 | The guard checks only that some file is loaded (`app.py:7097`). With only a MAC loaded the snapshot is a MAC-only copy with no image (`app.py:1379-1414`), so the dialog opens on an empty image. | Refuse unless a primary is loaded (R-OPS-003.2, .3; D13-30). |
| R-CRC-ENGINE-001 / 002 | "the result equals `zlib.crc32`"; `reverse` is one flag for refin and refout; no span convention. R-CRC-ENGINE-002 is a risk note (RK-3), not a requirement. | CTX-CRC defines the model and the algorithms; the risk note is out (D13-1). |
| R-CRC-ENGINE-002 | "corroborated against published variant KATs": the published variants used have init 0 or all ones. With `reverse` true the engine reflects init before the first byte (`crc.py:211`); the CRC Designer does not (`crc_kernel.py:131`), which is the catalogue model. Same parameters, two results (D13-20). | R-CRC-ENGINE-001.1 Partly. |
| R-CRC-CHECK-001 | "the 4-byte little-endian value": groups use 1, 2, 4 or 8 bytes. "whether the stored value matches": there are three outcomes. | CTX-CRC stored field; one row per verdict. |
| R-CRC-WRITE-001 | Seven responses in one sentence (inject, extend, emit, re-read, record, write nothing on decline, keep the original). "into the contained work area": no folder, no name. The S0 header and the terminator address of the written file are not stated. | Split (S13.5); `crc/<stem>-crc.s19`; header and terminator D13-28. |
| R-CRC-CONFIG-001 | "present the config … pre-filled with dummy values" plus a repository rule ("real per-firmware config values are never committed"). The tolerant parse of regions (no bounds at all) is recorded only as an amendment note. | Example config in CTX-CRCCONFIG; repository rule out (D13-1); one set of span rules (D13-21). |
| R-CRC-GROUP-001 | "legacy-only pairs stay silent — the committed dummy config's legacy regions self-overlap by design". The example teaches the trap the group warning exists for: each example region contains its own stored field, so a write changes the CRC it just stored. | One overlap rule for every target; example fixed (D13-24). |
| R-CRC-CONFIGLOAD-001 | `Where` used for "the CRC operation is the selected operation" (a screen state, E4); five responses. | `When` / `If` rows (S13.3). |
| R-CRC-CONTRACT-001 | `OperationInput`, `crc_regions`, field counts: design. | Non-mutation rows (R-CRC-CONTRACT-001.1, .2; D13-2). |
| R-TUI-100 | Widget ids, `region.y` predicates, `_render_markup is False`, a module-level tuple; then rationale and history. | Layout rows against CTX-DESIGNER (S13.9; D13-1, D13-2). |
| C-7 convention | "Operation requirements live in `operations/requirements/REQ-<id>.md`": a second source that is already stale (fixed 4-byte codec "NOT parameterized", no groups). | This chapter is the one source (D13-17). |
| (nothing) | Presets, self-test, custom vector, coverage preview and templates of the CRC Designer: no row. | S13.6 … S13.8 (from S0 LLR-122.4). |

---

## 3. Context notes (informative)

### CTX-OPS · The Operations dialog (S13.1, S13.3 … S13.5)

```text
Operations dialog   A dialog (S7 CTX-DIALOG), title "Operations:". From the top:
  operation list    One row per operation, "<id> - <title>":
                      crc - CRC
  CRC controls      Shown while the crc row is selected:
                      label "CRC config (editable JSON):"
                      config path box   hint "config file path (.json)"
                      Load config button
                      config editor     multi-line text box (S7 CTX-PASTE)
  result area       The result text, then a hex view (S4) of at most 512 rows.
  buttons           Execute (confirm button) · Write CRC · Close
load error text     "CRC config load error:", then the reason on the next line.
config error text   "CRC config error - no check was run:", then the reason on the
                    next line.
CRC write           Dialog titled "Write the computed CRC(s) into a new modified S19
confirmation        under the work area?"; buttons "Width: <n> bytes/line" · Confirm ·
                    Cancel.
record width        Data bytes per S19 data record of the written file: 32 or 16.
internal error      A fault that is none of the reasons this chapter lists (a program
                    defect).
```

### CTX-CRC · The CRC model and the algorithms (S13.2, S13.6, S13.7)

```text
parametric model  Every CRC here is defined by these parameters:
  width           register size in bits
  poly            generator polynomial, normal form (the top bit is left out)
  init            register value before the first byte, not reflected
  refin           true: each input byte is taken low bit first
  refout          true: the register is reflected before the final XOR
  xorout          value XORed into the register at the end
  check           the CRC of the 9 ASCII bytes "123456789" (0x31 … 0x39)
algorithms
  name                width  poly                init                refin  refout xorout              check
  CRC-8/SMBUS            8   0x07                0x00                false  false  0x00                0xF4
  CRC-16/CCITT-FALSE    16   0x1021              0xFFFF              false  false  0x0000              0x29B1
  CRC-16/MODBUS         16   0x8005              0xFFFF              true   true   0x0000              0x4B37
  CRC-16/XMODEM         16   0x1021              0x0000              false  false  0x0000              0x31C3
  CRC-32/ISO-HDLC       32   0x04C11DB7          0xFFFFFFFF          true   true   0xFFFFFFFF          0xCBF43926
  CRC-32C/Castagnoli    32   0x1EDC6F41          0xFFFFFFFF          true   true   0xFFFFFFFF          0xE3069283
  CRC-64/XZ             64   0x42F0E1EBA9EA3693  0xFFFFFFFFFFFFFFFF  true   true   0xFFFFFFFFFFFFFFFF  0x995DC9BBDF1939FA
  CRC-32/BZIP2          32   0x04C11DB7          0xFFFFFFFF          false  false  0xFFFFFFFF          0xFC891918
  The first seven are the CRC Designer's presets, in its order. CRC-32/BZIP2 is a
  reference only (no preset). CRC-32/ISO-HDLC is the zlib / PKZIP CRC-32.
operation model   The CRC operation: width 32; config key polynomial = poly, init = init,
                  reverse = refin and refout together, final_xor = xorout. Defaults:
                  CRC-32/ISO-HDLC.
Designer model    The CRC Designer: width 8 to 64; refin and refout set one by one.
                  The two surfaces share no setting: a CRC Designer template is not a
                  CRC config, and the CRC operation cannot use one.
span              A half-open address range [start, end): start is in it, end is not.
present byte      An address of a span that holds a byte in the image.
absent byte       An address of a span that holds no byte in the image.
CRC input         Of a span: its present bytes in ascending address order; nothing for
                  an absent byte. Of a target (CTX-CRCCONFIG): the CRC inputs of its
                  spans in declared order, as one byte stream.
stored field      N bytes from the output address up: byte i is at output address + i
                  and holds bits 8i … 8i+7 (little-endian, low byte first).
                  N is the field width (CTX-CRCCONFIG).
stored value      The number the N bytes of the stored field hold, low byte first;
                  none while one of the N bytes is absent.
field value       The CRC's low 8N bits: the low byte(s) for N = 1 or 2, the CRC for
                  N = 4, the CRC with four 0x00 high bytes for N = 8.
field hex         0x and 2N uppercase hexadecimal digits.
widths            Three different widths:
                  CRC width      bits of the register, 8 to 64 (32 in the operation)
                  field width    N, bytes of the stored field, 1, 2, 4 or 8
                  record width   S19 data bytes per record of a written file, 16 or 32
stage words       check   compute and compare with the stored value; changes nothing
                  write   put the field values into a copy and write it as a file
                  verify  read the written file back (S8.8)
                  self-test  the CRC Designer's comparison of Check with the CRC of
                          "123456789" (not the S9 Checks)
```

### CTX-CRCCONFIG · The CRC config (S13.3)

```text
CRC config        A JSON object:
  polynomial      number, required
  init            number, required
  reverse         true or false, required
  final_xor       number, required
  regions         list of regions; may be empty or left out
  groups          list of groups; may be empty or left out
                  At least one of regions and groups holds an entry.
region            {"start", "end", "output_address"}: one span, field width 4.
group             {"regions": list of {"start", "end"} spans (at least one),
                   "output_address", "output_bytes"}: one CRC over all its spans.
                  output_bytes is 1, 2, 4 or 8; 4 when left out.
target            A region or a group: one CRC, one stored field at output_address.
target order      The regions in config order, then the groups in config order.
number            A JSON integer (decimal), or a JSON string of hexadecimal digits with
                  or without 0x (the string "10" is 16).
span rules        start ≥ 0; end > start; end ≤ 0x100000000;
                  output_address ≥ 0; output_address + N ≤ 0x100000000.
span limit        At most 4096 spans in all (regions plus group spans).
parameter range   polynomial, init and final_xor: 0x0 … 0xFFFFFFFF.
read limit        256 MiB (268,435,456 bytes), the same as S5's copy limit.
example config    The text the config editor starts with (a copy is
                  examples/crc_config.example.json). All values are dummies:
                  CRC-32/ISO-HDLC parameters;
                  regions [0x10000, 0x1FFFC) → field at 0x1FFFC,
                          [0x20000, 0x2FFFC) → field at 0x2FFFC;
                  one group of [0x30000, 0x34000) and [0x40000, 0x42000) → field at
                  0x42000, 4 bytes.
rule texts        The <rule text> of R-CRC-CONFIG-001.10. <where> is "region <i>" or
                  "group <k> span <j>"; i, k and j count from 1.
  field 'reverse' must be a boolean
  field 'regions' must be a list
  field 'groups' must be a list
  at least one of 'regions' / 'groups' must be present and non-empty
  region <i> must be a JSON object
  group <k> must be a JSON object
  group <k>: field 'regions' must be a list
  group <k>: field 'regions' must not be empty
  group <k> span <j> must be a JSON object
  group <k> span <j>: 'output_address' is not allowed inside a group span (a group has exactly one output_address)
  <where>: 'start' must be non-negative
  <where>: 'end' (0x<end>) exceeds the 32-bit address space
  <where>: 'end' (0x<end>) must be greater than 'start' (0x<start>)
  group <k>: 'output_bytes' must be one of [1, 2, 4, 8], got <value>
  region <i> / group <k>: 'output_address' must be non-negative
  region <i> / group <k>: output window [0x<address>, 0x<address>+<N>) exceeds the 32-bit address space
  config declares <n> spans, over the 4096-span ceiling
```

### CTX-CRCRESULT · What the result area shows (S13.4, S13.5)

```text
check result      status: ok   or   status: error
                  CRC: <n> region(s): <m> matched, <k> mismatched, <j> no-stored-value
                  the notes, in this order: coverage notes, truncation notes, overlap
                  notes, the empty-target note
                  one region line per target, in target order
region line       region @ 0x<output address, 8 digits>: computed <field hex of the
                  CRC>, stored <stored> -> <verdict>
  <stored>        the field hex of the stored value, or (absent)
  <verdict>       MATCH · MISMATCH · no stored value
write result      verified   status: ok
                             wrote <path> (verified)
                             one write line per target
                  mismatch   VERIFY MISMATCH - the written image did not verify:
                             wrote <path> but it did not verify (verify status: mismatch)
                             one write line per target
                  failed     WRITE FAILED - no file was written:
                             <finding>
                             one region line per target (the check's verdicts)
write line        region @ 0x<output address, 8 digits>: wrote <field hex of the field
                  value> (<N> LE bytes)
CRC file          <work area>/crc/<stem of the primary>-crc.s19, or its numbered name
                  (S5 CTX-WORKAREA).
```

### CTX-DESIGNER · The CRC Designer (S13.6 … S13.9)

```text
CRC Designer      Rail screen (S6: key 0). Header "CRC Designer" with the ? chip and the
                  📂 Open templates/ chip (S5, S7). Then, from the top:
  help line       CRC Designer (preview-only): pick a preset or edit the parameters;
                  presets are read-only starting points.
  top row         the coverage window (two thirds of the width) · the Warnings group
  bench           three columns:
                    1  Algorithm: Preset · Width (bits) · Polynomial · Init ·
                       Reflection  in [toggle]  out [toggle] · XOR out · Check ·
                       Self-test  123456789  <verdict>
                    2  Coverage · preview-only: Ranges · Intra gap · Join gaps ·
                       Pad byte · On conflict · the coverage preview;
                       Store placement: Address · Bytes · Store endianness
                    3  Custom test vector: Mode · Vector · CRC;
                       Template: Name · Aliases;
                       Load / Save: Load path · Save · Load · the Load / Save status
  JSON strip      Full width, below the bench: the template file of the form.
narrow            While the terminal is narrow (S6), the top row and the three columns
                  stack one under the other.
result surfaces   The self-test verdict, the custom-vector CRC, the JSON strip, the
                  Warnings, the coverage preview and the coverage window.
verdict           ✓ MATCH (green) · ✗ MISMATCH (red) · ○ NO-EXPECTED (grey); S3 palette.
fields            Width: decimal. Polynomial, Init, XOR out, Check, Address, Pad byte:
                  hexadecimal, 0x optional; empty reads as 0, except Check (empty = no
                  expected value) and Pad byte (empty = 0xFF).
shown CRC         0x and uppercase hexadecimal, 2 digits per byte of ceil(width / 8)
                  bytes (coverage values: per byte of Bytes).
coverage target   Ranges: "start-end, start-end, …", hexadecimal spans in declared
                  order, with:
  Intra gap       skip: absent bytes inside a range are left out
                  fill: they read as the pad byte
  Join gaps       concat: the ranges follow one another
                  fill: the addresses between two ranges read as the pad byte
  On conflict     abort · warn · ignore: what to do on a gap conflict
  Store placement the preview's stored field: Address, Bytes (1 to 8), Store
                  endianness (little or big)
  coverage rules  the span rules of CTX-CRCCONFIG; pad byte 0x00 … 0xFF; Bytes 1 … 8
gap conflict      A present byte in a space Join gaps fills, whose value differs from
                  the pad byte.
concat CRC        The coverage target's CRC with Join gaps = concat.
fill CRC          The coverage target's CRC with Join gaps = fill.
coverage window   Line 1: one bar of block glyphs, ranges in the accent colour and gaps
                  in grey (concat) or pale yellow (fill), scaled so the whole target
                  takes at most about 48 glyphs.
                  Line 2: concat <concat CRC>   fill <fill CRC>
                  Line 3: store <stored-field bytes of the active CRC, hex pairs>
template          A CRC Designer algorithm with a name and aliases.
template file     <clean name (S11 CTX-SAVE)>.crc.json:
                  {"schema_version": 1, "name", "aliases": [...], "operation": "crc",
                   "algorithm": {"width", "poly", "init", "refin", "refout", "xorout",
                   "check" (or null)}}; numbers as 0x hexadecimal strings.
template home     <project>/templates/ while a project is open; otherwise
                  .s19tool/templates/ (beside the work area, S5 CTX-WORKAREA).
template reasons  CRC template path could not be resolved: '<path>'
                  CRC template file is over the 268435456-byte read cap — not read
                  CRC template file could not be read: <reason>
                  CRC template is not valid JSON: <parser message>
                  CRC template top level must be a JSON object
                  CRC template is structurally invalid: <rule>
                    (rules: a non-empty name; width 8 to 64; refin and refout true or
                    false; every algorithm field present)
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested** (test named), **Partly** / **No** with the decision.

### S13.1 · The Operations dialog (CTX-OPS)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-OPS-003.1 | When | When the operator presses `x` while a primary is loaded, the system shall open the Operations dialog. | Yes; tested (test_operations_view_lists_registry_ids). |
| R-OPS-003.2 | If | If no primary is loaded when the operator presses `x`, then the system shall show the status `Operations: no file loaded - load a file first.` | Partly: with only a MAC loaded the dialog opens on an empty image (D13-30). Tested with nothing loaded. |
| R-OPS-003.3 | If | If no primary is loaded when the operator presses `x`, then the system shall open no dialog. | Partly: same as R-OPS-003.2 (D13-30). Tested with nothing loaded (test_operations_view_lists_registry_ids). |
| R-OPS-002.1 | U | The system shall list in the operation list one row per operation of CTX-OPS. | Partly: two more rows, `extract - Extract` and `split_by_segment - Split by segment`, run nothing (D13-13). Tested (test_operations_view_lists_registry_ids). |
| R-OPS-003.4 | When | When the Operations dialog opens, the system shall select the first row of the operation list. | Yes. |
| R-OPS-003.5 | While | While the crc row is selected, the system shall show the CRC controls of CTX-OPS. | Yes; tested (test_crc_config_load_widgets_present_and_toggle). |
| R-OPS-003.6 | When | When a CRC check ends, the system shall show under the result text the hex view (S4) of the primary's image. | Yes. |
| R-OPS-003.7 | U | The system shall keep the screen responsive while it runs a CRC check or a CRC write. | Yes; tested (test_crc_execute_path_uses_thread_worker). |
| R-OPS-003.8 | If | If the operator presses Execute while a CRC check runs, then the system shall show only the result of the later press. | Yes; tested (test_stale_crc_worker_result_does_not_overwrite_error). |
| R-OPS-003.9 | If | If the operator confirms a CRC write while another CRC write runs, then the system shall show only the result of the later write. | Yes. |
| R-OPS-003.11 | If | If a CRC check fails with an internal error, then the system shall show `CRC operation failed: <error type>: <message>` in the result area. | Partly: it goes to the status line behind the dialog (`screens.py:2427-2430`) (D13-29). |
| R-OPS-003.12 | If | If a CRC write fails with an internal error, then the system shall show `CRC write failed: <error type>: <message>` in the result area. | Partly: it goes to the status line behind the dialog (`screens.py:2702-2705`) (D13-29). |
| R-OPS-003.13 | U | The system shall show file-derived text in the Operations dialog as plain text, never as markup. | Yes; tested (test_at047e_hostile_config_value_renders_literal). |

### S13.2 · Computing a CRC (CTX-CRC)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CRC-ENGINE-001.1 | U | The system shall compute each CRC of the CRC operation by the parametric model of CTX-CRC, with width 32 and the parameters of the CRC config. | Partly: with `reverse` true the init value is reflected before the first byte (`crc.py:211`), so an init that is not bit-symmetric gives another CRC than the model and the CRC Designer (`crc_kernel.py:131`) (D13-20). |
| R-CRC-ENGINE-002.1 | U | The system shall give, for the parameters of each 32-bit algorithm of CTX-CRC, that algorithm's check value as the CRC of "123456789". | Yes; tested (test_known_answer_vector, test_bitwise_path_reproduces_published_variant_kats). |
| R-CRC-ENGINE-001.2 | U | The system shall take into the CRC input of a span only the span's present bytes. | Yes; tested (test_region_filter_excludes_out_of_range). |
| R-CRC-ENGINE-001.3 | U | The system shall take the present bytes of a span in ascending address order. | Yes; tested (test_ascending_address_ordering). |
| R-CRC-ENGINE-001.4 | U | The system shall add no byte to the CRC input for an absent byte. | Yes; tested (test_gap_splits_segments_no_inserted_bytes). |
| R-CRC-ENGINE-001.5 | U | The system shall compute one CRC per target over the CRC inputs of its spans in declared order, without restarting between spans. | Yes; tested (test_segment_chaining_does_not_reset_state, test_at045b_declared_order_not_address_order). |
| R-CRC-GROUP-001.1 | U | The system shall take a span into a group's CRC input once for each time the group declares it. | Yes; tested (test_at045f_duplicate_span_digested_each_time). |
| R-CRC-CONTRACT-001.1 | When | When the system checks CRCs, the system shall leave every byte of the loaded image unchanged. | Yes; tested (test_check_reports_match_nonmutating). |
| R-CRC-CONTRACT-001.2 | When | When the system writes CRCs, the system shall leave every byte of the loaded image unchanged. | Yes; tested (test_inject_writes_le_at_output_address). |

### S13.3 · The CRC config (CTX-CRCCONFIG)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CRC-CONFIG-001.1 | When | When the Operations dialog opens, the system shall fill the config editor with the example config of CTX-CRCCONFIG. | Partly: the example's regions end at 0x20000 and 0x30000, so each holds its own stored field (D13-24). |
| R-CRC-CONFIGLOAD-001.1 | When | When the operator presses Load config with a path in the config path box, the system shall replace the config editor's text with the text of the file. | Yes; tested (test_crc_config_load_ok_populates_editor_via_handler). |
| R-CRC-CONFIGLOAD-001.2 | When | When the system has loaded a config file into the editor, the system shall show `Loaded CRC config from <path as typed>` in the result area. | Yes. |
| R-CRC-CONFIGLOAD-001.3 | When | When the operator presses Load config, the system shall run no CRC check. | Yes; tested (test_crc_config_load_fault_surfaces_error_and_no_check). |
| R-CRC-CONFIGLOAD-001.4 | U | The system shall find the config file the way S5.3 finds a path input. | Yes (same function, `workspace.py:1990`; S5's removal of the repository-root search, D5-8, applies here too). |
| R-CRC-CONFIGLOAD-001.5 | If | If the config path box is empty when the operator presses Load config, then the system shall show `CRC config load: enter a config file path first.` in the result area. | Yes. |
| R-CRC-CONFIGLOAD-001.6 | If | If no file matches the config path, then the system shall show the load error text with the reason `CRC config path could not be resolved: '<path>'`. | Yes; tested (test_read_crc_config_text_unresolvable_path_collects_one_error). |
| R-CRC-CONFIGLOAD-001.7 | If | If the config file is larger than the read limit, then the system shall show the load error text with the reason `CRC config file is <n> bytes, over the 268435456-byte read cap — the file was not read`. | Yes; tested (test_read_crc_config_text_over_cap_collects_one_error_without_reading). |
| R-CRC-CONFIGLOAD-001.8 | If | If the config file is larger than the read limit, then the system shall read none of it. | Yes; tested (test_read_crc_config_text_over_cap_collects_one_error_without_reading). |
| R-CRC-CONFIGLOAD-001.9 | If | If the config file cannot be read, then the system shall show the load error text with the reason `CRC config file could not be read: <reason>`. | Yes. |
| R-CRC-CONFIGLOAD-001.10 | If | If the config file cannot be loaded, then the system shall leave the config editor's text unchanged. | Yes; tested (test_crc_config_load_fault_surfaces_error_and_no_check). |
| R-CRC-CONFIG-001.2 | When | When the operator presses Execute, the system shall read the CRC config from the config editor's text. | Yes; tested (test_crc_check_reaches_result_surface_via_handler). |
| R-CRC-CONFIG-001.3 | U | The system shall read a number given as a JSON string as hexadecimal, with or without `0x`. | Yes; tested (test_at044b_group_values_round_trip_hex_and_int). |
| R-CRC-WIDTH-001.1 | U | The system shall give each region a field width of 4. | Yes; tested (test_tc202_8_normalized_targets_order_and_widening). |
| R-CRC-WIDTH-001.2 | U | The system shall give each group the field width its `output_bytes` names, or 4 when `output_bytes` is left out. | Yes; tested (test_at044b_output_bytes_defaults_to_4_when_omitted, test_at044b_allowed_output_bytes_all_parse). |
| R-CRC-CONFIG-001.4 | If | If the config editor's text is not a valid CRC config when the operator presses Execute, then the system shall show the config error text of CTX-OPS with one reason. | Yes; tested (test_crc_config_error_surfaces_error_and_no_match). |
| R-CRC-CONFIG-001.5 | If | If the config editor's text is not a valid CRC config when the operator presses Execute, then the system shall run no CRC check. | Yes; tested (test_crc_config_error_surfaces_error_and_no_match). |
| R-CRC-CONFIG-001.6 | If | If the config editor's text is not a valid CRC config when the operator presses Execute, then the system shall show no hex view in the result area. | Yes. |
| R-CRC-CONFIG-001.7 | If | If the config text is not JSON, then the system shall give the reason `CRC config is not valid JSON: <parser message>`. | Yes; tested (test_parse_crc_config_malformed_text_collects_one_error). |
| R-CRC-CONFIG-001.8 | If | If the top level of the config text is not a JSON object, then the system shall give the reason `CRC config top level must be a JSON object`. | Yes; tested (test_parse_crc_config_non_object_top_level_collects_one_error). |
| R-CRC-CONFIG-001.9 | If | If the CRC config breaks a rule of CTX-CRCCONFIG, then the system shall give the reason `CRC config is structurally invalid: <rule text>` with that rule's text. | Partly: regions count from 0 (D13-21). Tested for groups (test_at044d_parse_rejections_one_named_error). |
| R-CRC-CONFIG-001.10 | If | If a required field is missing, then the system shall give the reason `CRC config is structurally invalid: field '<name>' is missing`. | Partly: the reason ends with the bare key, `'<name>'` (D13-23). Tested for one error (test_parse_crc_config_missing_field_collects_one_error). |
| R-CRC-CONFIG-001.11 | If | If a number field holds something other than a number of CTX-CRCCONFIG, then the system shall give the reason `CRC config is structurally invalid: field '<name>' is not a number: <value>`. | Partly: the reason is Python's `invalid literal for int() with base 16: '<value>'`, which names no field (D13-23). |
| R-CRC-CONFIG-001.12 | If | If the CRC config breaks more than one rule, then the system shall give the reason of the first rule it finds only. | Yes; tested (test_at044d_parse_rejections_one_named_error). |
| R-CRC-CONFIG-001.13 | If | If a region breaks a span rule of CTX-CRCCONFIG, then the system shall reject the config with that rule's text. | No: a region takes any number; only group spans are checked (`crc_config.py:505-515` vs `:600-643`) (D13-21). |
| R-CRC-CONFIG-001.14 | If | If polynomial, init or final_xor is outside the parameter range, then the system shall give the reason `CRC config is structurally invalid: field '<name>' must be 0x0..0xFFFFFFFF`. | No: the low 32 bits are used with no message (`crc_config.py:529-532`, `crc.py:211-224`) (D13-22). |
| R-CRC-CONFIG-001.15 | If | If the config declares more spans than the span limit, then the system shall give the reason `CRC config is structurally invalid: config declares <n> spans, over the 4096-span ceiling`. | Yes; tested (test_at044d_parse_rejections_one_named_error). |

### S13.4 · The CRC check (CTX-CRCRESULT)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CRC-CHECK-001.1 | When | When the operator presses Execute with a valid CRC config, the system shall compute one CRC per target, in target order. | Yes; tested (test_check_multi_region_order, test_at047a_mixed_check_per_target_verdicts_and_order). |
| R-CRC-CHECK-001.2 | If | If a byte of a target's stored field is absent, then the system shall give the target the verdict `no stored value`. | Yes; tested (test_read_stored_missing_returns_none, test_at046d_check_absent_stored_byte_tri_state_operation_half). |
| R-CRC-CHECK-001.3 | When | When a target's stored value equals its field value, the system shall give the target the verdict `MATCH`. | Yes; tested (test_check_reports_match_nonmutating, test_at046b_truncated_compare_matches_low_bytes). |
| R-CRC-CHECK-001.4 | If | If a target's stored value differs from its field value, then the system shall give the target the verdict `MISMATCH`. | Yes; tested (test_check_reports_mismatch). |
| R-CRC-CHECK-001.5 | When | When a CRC check ends, the system shall show the check result of CTX-CRCRESULT in the result area. | Yes; tested (test_crc_check_reaches_result_surface_via_handler, test_execute_with_config_populates_crc_regions). |
| R-CRC-CHECK-001.6 | When | When a CRC check ends, the system shall show each region line with the field hex of the CRC and of the stored value. | Partly: both always show 8 digits, so a 1- or 2-byte field shows the whole 32-bit CRC beside its stored byte(s) (`screens.py:2554`) (D13-26). |
| R-CRC-WIDTH-001.3 | If | If a target's field width is less than 4, then the system shall add the note `CRC target at 0x<output address, 8 digits>: output bytes <N> truncates the 32-bit CRC to the low byte(s) — weakened error detection`. | Yes; tested (test_at046b_truncation_note_per_narrow_width). |
| R-CRC-GROUP-001.2 | If | If a target's stored field overlaps one of its own spans, then the system shall add the note `CRC target at 0x<output address, 8 digits>: output window overlaps one of its own input spans — a write invalidates the just-computed CRC`. | Partly: regions get no note (`crc.py:1081`) (D13-24). Tested for groups (test_at047c_group_self_overlap_warns_and_completes). |
| R-CRC-GROUP-001.3 | If | If a target's stored field overlaps a span of another target, then the system shall add for each such target the note `CRC target at 0x<output address, 8 digits>: output window overlaps another target's input span — that target's stored-vs-computed comparison becomes flash-order-dependent`. | Partly: no note when both targets are regions (`crc.py:1088`) (D13-24). Tested for groups (test_at047g_cross_target_overlap_distinct_warning). |
| R-CRC-WRITE-001.1 | When | When the Operations dialog opens, the system shall disable Write CRC. | Yes. |
| R-CRC-WRITE-001.2 | When | When a CRC check ends with status `ok`, the system shall enable Write CRC. | Yes; tested (test_no_write_without_confirmation). |
| R-CRC-WRITE-001.3 | If | If a CRC check ends with status `error`, then the system shall disable Write CRC. | No: Write CRC is enabled after any check that returns target results (`screens.py:2501`, `crc.py:1721`) (D13-25). |
| R-CRC-WRITE-001.4 | If | If the config is invalid when the operator presses Execute, then the system shall disable Write CRC. | Yes. |

#### S13.4b · Coverage of a target (from S0 HLR-159 / LLR-159.1)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CRC-CHECK-002.1 | If | If a region's span holds some of its bytes but not all, then the system shall add the note `CRC region 0x<start>-0x<end>: <n> absent byte(s) - the CRC covers present bytes only`. | Yes; tested (test_tc_b99_27_partial_region_notices_name_absent_count). |
| R-CRC-CHECK-002.2 | If | If a group's spans hold some of their bytes but not all, then the system shall add the note `CRC group <k>: <n> absent byte(s) in declared span(s) <spans> — the CRC covers present bytes only`, <spans> being each span with an absent byte as `[0x<start>, 0x<end>)`, comma-separated. | Yes; tested (test_at045c_gap_note_names_group_and_count_legacy_stays_silent). |
| R-CRC-CHECK-002.3 | If | If a target's spans hold no present byte, then the system shall end the check with status `error`. | Yes; tested (test_tc_b99_26_empty_region_errors_and_writes_nothing). |
| R-CRC-CHECK-002.4 | If | If a target's spans hold no present byte, then the system shall add as last note `CRC region 0x<start>-0x<end> holds 0 image bytes - nothing written`, with the first span of the first such target. | Yes; tested (test_tc_b99_26_empty_region_error_note_is_last_and_only). |

### S13.5 · The CRC write (CTX-CRCRESULT; from S0 LLR-155.8)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CRC-WRITE-001.5 | When | When the operator presses Write CRC, the system shall open the CRC write confirmation of CTX-OPS. | Yes; tested (test_no_write_without_confirmation). |
| R-CRC-RECWIDTH-001.1 | When | When the CRC write confirmation opens, the system shall set the record width to 32. | Yes; tested (test_confirm_write_width_selector_cycles). |
| R-CRC-RECWIDTH-001.2 | When | When the operator presses the Width button, the system shall switch the record width between 32 and 16. | Yes; tested (test_confirm_write_width_selector_cycles). |
| R-CRC-RECWIDTH-001.3 | When | When the record width changes, the system shall show the button label `Width: <record width> bytes/line`. | Yes; tested (test_confirm_write_width_selector_cycles). |
| R-CRC-WRITE-001.6 | When | When the operator presses Cancel in the CRC write confirmation, the system shall write no file. | Yes; tested (test_no_write_without_confirmation). |
| R-CRC-WRITE-001.7 | When | When the operator presses Confirm, the system shall read the CRC config from the config editor's text again. | Yes. |
| R-CRC-WRITE-001.8 | If | If the config editor's text is not a valid CRC config when the operator presses Confirm, then the system shall show `CRC config error - nothing was written:` with the reason on the next line. | Partly: the first line is `CRC config error - no check was run:` (`screens.py:2641`) (D13-27). |
| R-CRC-WRITE-001.9 | If | If the config editor's text is not a valid CRC config when the operator presses Confirm, then the system shall write no file. | Yes. |
| R-CRC-WRITE-001.10 | When | When the operator confirms with a valid CRC config, the system shall compute the targets' CRCs again over the primary's image. | Yes. |
| R-CRC-WRITE-001.11 | If | If a target's spans hold no present byte when the operator confirms, then the system shall write no file. | Yes; tested (test_tc_b99_26_empty_region_errors_and_writes_nothing). |
| R-CRC-WRITE-001.12 | When | When the system writes CRCs, the system shall put each target's field value into its stored field in a copy of the primary's image. | Yes; tested (test_inject_writes_le_at_output_address, test_at046a_inject_width8_zero_extends_and_extends_ranges). |
| R-CRC-WRITE-001.13 | If | If a stored field's addresses are outside every range of the image, then the system shall add them to the ranges of the copy. | Yes; tested (test_inject_into_gap_extends_ranges). |
| R-CRC-WRITE-001.14 | When | When the system writes CRCs, the system shall write the copy as an S19 file (S8.7) under the CRC file name of CTX-CRCRESULT. | Yes; tested (test_write_result_records_emitted_path_and_verdict). |
| R-CRC-RECWIDTH-001.4 | When | When the system writes a CRC file, the system shall put at most the record width in data bytes in each data record. | Yes; tested (test_crc_write_honours_selected_16_width_through_confirm, test_crc_write_emits_32_byte_records). |
| R-CRC-WRITE-001.15 | If | If `crc/` holds a file with the same content under the CRC file's name or a numbered name, then the system shall use that file and write nothing. | Yes. |
| R-CRC-WRITE-001.16 | If | If the CRC file's name is taken in `crc/` by a different content, then the system shall write under the lowest free numbered name. | Yes. |
| R-CRC-WRITE-001.17 | When | When the system writes a CRC file of a primary whose S0 record has data, the system shall use that data as header data. | No: the S0 record is written empty (`crc.py:1493-1495` passes no header) (D13-28). |
| R-CRC-WRITE-001.18 | When | When the system writes a CRC file of a primary that has a terminator, the system shall write the address of the primary's terminator in the terminator. | No: address 0 is written (D13-28; S8 D8-29). |
| R-CRC-WRITE-001.19 | When | When the system has written a CRC file, the system shall verify it against the copy as S8.8 says. | Yes; tested (test_modified_s19_reread_matches_intent). |
| R-CRC-WRITE-001.20 | When | When the verify marks the CRC file verified, the system shall show the write result `verified` of CTX-CRCRESULT. | Yes; tested (test_crc_inject_reaches_surface_via_handler). |
| R-CRC-WRITE-001.21 | If | If the verify marks the CRC file mismatch, then the system shall show the write result `mismatch` of CTX-CRCRESULT. | Yes. |
| R-CRC-WRITE-001.22 | If | If the system cannot place the CRC file, then the system shall show the write result `failed` with the finding `CRC write failed — no file was written: <error type>: <message>`. | Yes; tested (test_write_outside_workarea_collects_finding_and_writes_no_file). |
| R-CRC-WRITE-001.23 | If | If a target's spans hold no present byte when the operator confirms, then the system shall show the write result `failed` with the finding `CRC region 0x<start>-0x<end> holds 0 image bytes - nothing written`. | Yes; tested (test_tc_b99_26_empty_region_errors_and_writes_nothing). |
| R-CRC-WRITE-001.24 | When | When the system shows a write line, the system shall show in it the field hex of the field value written. | Partly: it shows the whole 32-bit CRC with 8 digits, also for a 1- or 2-byte field (`screens.py:2778`) (D13-26). Tested for `(<N> LE bytes)` (test_at047h_group_confirm_write_flow_and_row_text). |
| R-CRC-WRITE-001.25 | When | When the system has written a CRC file, the system shall show under the result text the hex view of the copy. | Yes. |
| R-CRC-WRITE-001.26 | If | If no CRC file is written, then the system shall keep the hex view of the check. | Yes. |

### S13.6 · The CRC Designer: algorithm and self-test (CTX-CRC, CTX-DESIGNER; from S0 LLR-122.4)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CRC-PRESET-001.1 | U | The system shall offer as presets the first seven algorithms of CTX-CRC, in that order. | Yes; tested (test_every_preset_reproduces_its_catalogue_check). |
| R-CRC-PRESET-001.2 | When | When the CRC Designer is first shown, the system shall fill the algorithm fields with CRC-32/ISO-HDLC. | Yes; tested (test_form_and_preset_populates_off_seed_without_mutating_catalogue). |
| R-CRC-PRESET-001.3 | When | When the operator picks a preset, the system shall fill the algorithm fields with the preset's parameters. | Yes; tested (test_form_and_preset_populates_off_seed_without_mutating_catalogue). |
| R-CRC-PRESET-001.4 | When | When the operator picks a preset, the system shall fill Name with the preset's name. | Yes. |
| R-CRC-PRESET-001.5 | When | When the operator picks a preset, the system shall empty Aliases. | Yes. |
| R-CRC-PRESET-001.6 | When | When the operator picks a preset, the system shall set Bytes to ceil(width / 8) of the preset. | Yes. |
| R-CRC-PRESET-001.7 | When | When the operator picks a preset, the system shall keep Address and Store endianness as they are. | Yes. |
| R-CRC-PRESET-001.8 | When | When the operator edits a field filled from a preset, the system shall leave the preset unchanged. | Yes; tested (test_form_and_preset_populates_off_seed_without_mutating_catalogue). |
| R-CRC-DESIGNER-001.1 | U | The system shall compute every CRC of the CRC Designer by the parametric model of CTX-CRC. | Yes; tested (test_every_preset_reproduces_its_catalogue_check, test_independent_refin_refout_is_wired). |
| R-CRC-DESIGNER-001.2 | When | When the operator changes a field of the CRC Designer, the system shall recompute every result surface of CTX-DESIGNER. | Yes; tested (test_live_verdict_transitions_on_single_field_events). |
| R-CRC-DESIGNER-002.1 | While | While Check holds the CRC of "123456789" under the form's algorithm, the system shall show the verdict `✓ MATCH`. | Yes; tested (test_live_verdict_every_preset_reads_match). |
| R-CRC-DESIGNER-002.2 | While | While Check holds another value, the system shall show the verdict `✗ MISMATCH`. | Yes; tested (test_live_verdict_transitions_on_single_field_events). |
| R-CRC-DESIGNER-002.3 | While | While Check is empty, the system shall show the verdict `○ NO-EXPECTED`. | Yes. |
| R-CRC-DESIGNER-002.4 | If | If Width is outside 8 to 64, then the system shall show the verdict `⚠ Cannot compute: width <width> out of range [8, 64]`. | Yes; tested (test_verdict_fault_guard_out_of_range_width). |
| R-CRC-DESIGNER-002.5 | If | If an algorithm field does not hold a number, then the system shall show `Invalid parameters: <field> is not a number: <text>` in the self-test, the JSON strip, the coverage preview and the coverage window. | Partly: the text is `Invalid parameters: <Python's message>`, which names no field (`crc_designer_view.py:1157`) (D13-31). |
| R-CRC-DESIGNER-003.1 | While | While Mode is `ascii`, the system shall show as custom-vector CRC the CRC of the UTF-8 bytes of Vector. | Yes; tested (test_custom_vector_ascii_and_hex_reproduce_kat). |
| R-CRC-DESIGNER-003.2 | While | While Mode is `hex`, the system shall show as custom-vector CRC the CRC of the bytes the hexadecimal pairs of Vector give, whitespace left out. | Yes; tested (test_custom_vector_ascii_and_hex_reproduce_kat). |
| R-CRC-DESIGNER-003.3 | If | If Mode is `hex` and Vector is not whole hexadecimal pairs, then the system shall show `Invalid vector: <reason>` as custom-vector CRC. | Yes. |
| R-CRC-DESIGNER-004.1 | U | The system shall show in the JSON strip the template file of the current form. | Yes; tested (test_json_preview_roundtrips_through_mounted_widget). |
| R-CRC-DESIGNER-005.1 | If | If Bytes is less than ceil(width / 8), then the system shall show in Warnings `⚠ store width <Bytes> bytes < required <ceil(width / 8)> bytes (ceil(width/8)); the stored CRC will be truncated`. | Yes; tested (test_store_width_too_small_warns_live). |
| R-CRC-DESIGNER-005.2 | If | If Intra gap or Join gaps is `fill` while Pad byte is empty, then the system shall show in Warnings `⚠ fill policy selected but pad_byte is unset; the filled bytes default to 0xFF — set an explicit pad byte`. | Yes; tested (test_three_warn_conditions_through_view). |
| R-CRC-DESIGNER-005.3 | While | While no warning of the CRC Designer applies, the system shall show `✓ none` in Warnings. | Yes. |

### S13.7 · The CRC Designer: coverage preview (CTX-DESIGNER)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CRC-PREVIEW-001.1 | If | If no image is loaded, then the system shall show `Load an image to preview coverage CRCs over real bytes.` in the coverage preview and the coverage window. | Yes; tested (test_coverage_no_image_shows_empty_state, test_coverage_window_empty_state_no_image). |
| R-CRC-PREVIEW-001.2 | While | While an image is loaded, the system shall show in the coverage preview the three lines `Active policy: join=<Join gaps>`, `concat: <concat CRC>`, `fill: <fill CRC>`. | Yes; tested (test_coverage_preview_shows_both_policy_oracles). |
| R-CRC-PREVIEW-001.3 | While | While an image is loaded, the system shall show the coverage window of CTX-DESIGNER. | Yes; tested (test_coverage_window_renders_colored_glyphs_with_live_oracles). |
| R-CRC-PREVIEW-001.4 | If | If Join gaps is `fill` with a gap conflict while On conflict is `abort`, then the system shall show in the coverage preview `Preview refused (on_gap_conflict=abort): <n> present byte(s) at <first 8 addresses as 0x<address>, comma-separated> conflict with a filled gap; no CRC shown.` | Yes; tested (test_gap_conflict_clean_previews_dirty_abort_refuses). |
| R-CRC-PREVIEW-001.5 | If | If Join gaps is `fill` with a gap conflict while On conflict is `abort`, then the system shall show `store — refused (on_gap_conflict=abort)` as line 3 of the coverage window. | Yes; tested (test_coverage_window_dirty_gap_abort_refuses_store). |
| R-CRC-PREVIEW-001.6 | If | If Join gaps is `fill` with a gap conflict while On conflict is `warn`, then the system shall add `gap-safety: <n> present byte(s) at <addresses> in a filled gap differ from pad_byte 0x<pad byte> — proceeding (on_gap_conflict=warn)` to the coverage preview. | Yes; tested (test_evaluate_target_warn_proceeds_with_diagnostic). |
| R-CRC-PREVIEW-001.7 | If | If Join gaps is `fill` with a gap conflict while On conflict is `ignore`, then the system shall show the coverage preview with no gap note. | Yes; tested (test_evaluate_target_ignore_is_silent). |
| R-CRC-PREVIEW-001.8 | If | If a coverage field breaks a coverage rule of CTX-DESIGNER, then the system shall show `Invalid coverage: <reason>` in the coverage preview and the coverage window. | Yes; tested (test_coverage_inverted_range_warns_not_crash, test_coverage_window_malformed_range_markup_safe). |
| R-CRC-PREVIEW-001.9 | U | The system shall change no byte of the loaded image from the CRC Designer. | Yes; tested (test_preview_only_mem_map_unchanged). |
| R-CRC-PREVIEW-001.10 | U | The system shall write no image file from the CRC Designer. | Yes. |

### S13.8 · The CRC Designer: templates (CTX-DESIGNER; from S0 LLR-122.4 and HLR-139)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CRC-TEMPLATE-001.1 | When | When the operator presses Save, the system shall write the template file of the form to `<template home>/<clean name>.crc.json`. | Yes; tested (test_save_then_load_roundtrip_through_view). |
| R-CRC-TEMPLATE-001.2 | When | When the system has saved a template, the system shall show `Saved template to <file name>` in the Load / Save status. | Yes. |
| R-CRC-TEMPLATE-001.3 | When | When the operator saves a template whose file name exists in the template home, the system shall replace that file. | Yes. |
| R-CRC-TEMPLATE-001.4 | If | If Check holds a value other than the CRC of "123456789" when the operator presses Save, then the system shall show `Saved <file name> with warning: check does not match the computed CRC of 123456789 (saved anyway)`. | Yes; tested (test_save_check_mismatch_warns_but_still_writes). |
| R-CRC-TEMPLATE-001.5 | If | If the clean name of Name is empty when the operator presses Save, then the system shall show `Cannot save: template name is empty after sanitization; nothing written.` | Yes; tested (test_save_all_symbol_name_writes_nothing_and_warns). |
| R-CRC-TEMPLATE-001.6 | If | If the clean name of Name is empty when the operator presses Save, then the system shall write no file. | Yes; tested (test_save_all_symbol_name_writes_nothing_and_warns). |
| R-CRC-TEMPLATE-001.7 | If | If the clean name of Name is a device name (S11 CTX-SAVE) when the operator presses Save, then the system shall show `Cannot save: <clean name> is a reserved device name; nothing written.` | No: the name is not checked (`crc_designer_view.py:1227-1257`) (D13-32). |
| R-CRC-TEMPLATE-001.8 | If | If an algorithm field does not hold a number when the operator presses Save, then the system shall show `Cannot save: invalid parameters: <field> is not a number: <text>`. | Partly: Python's message, no field named (D13-31). |
| R-CRC-TEMPLATE-001.9 | If | If the template file cannot be written, then the system shall show `Cannot save: <reason>`. | Yes. |
| R-CRC-TEMPLATE-001.10 | When | When the operator presses Load with a path in Load path, the system shall fill the algorithm fields, Name and Aliases from the template file. | Yes; tested (test_save_then_load_roundtrip_through_view). |
| R-CRC-TEMPLATE-001.11 | When | When the system has loaded a template, the system shall show `Loaded template from file.` in the Load / Save status. | Yes. |
| R-CRC-TEMPLATE-001.12 | When | When the system has loaded a template, the system shall record its file as the used template (S11 CTX-SAVE). | Yes; tested in S11 (test_tc701_used_template_gathered_into_project_templates). Save project copies it into `templates/`; a name project.json cannot record gets the status of S11 R-PROJ-GATHER.10 (batch-100 LLR-171.5). |
| R-CRC-TEMPLATE-001.13 | U | The system shall find the template file the way S5.3 finds a path input. | Yes (same function, `workspace.py:1990`). |
| R-CRC-TEMPLATE-001.14 | If | If Load path is empty when the operator presses Load, then the system shall show `Cannot load: enter a template path.` | Yes. |
| R-CRC-TEMPLATE-001.15 | If | If the template file cannot be read, then the system shall show `Load failed: <reason>` with the first template reason of CTX-DESIGNER. | Yes; tested (test_load_malformed_file_surfaces_one_error). |
| R-CRC-TEMPLATE-001.16 | If | If the template file cannot be read, then the system shall leave the form unchanged. | Yes; tested (test_load_malformed_file_surfaces_one_error). |
| R-CRC-TEMPLATE-001.17 | When | When the operator presses the 📂 Open templates/ chip, the system shall open the template home in the system's file manager. | Yes. |

### S13.9 · The CRC Designer: layout and text (CTX-DESIGNER)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-100.1 | U | The system shall lay out the CRC Designer as CTX-DESIGNER shows. | Yes; tested (test_bench_columns_pairwise_distinct_ancestors, test_right_column_widgets_reachable_and_json_full_width, test_hero_right_column_holds_warnings_only). |
| R-TUI-100.2 | U | The system shall show the two Reflection toggles on one row, each after its own label `in` or `out`. | Yes; tested (test_reflection_pair_row_shares_one_band_and_drives_the_kernel, test_reflection_row_structure). |
| R-TUI-100.3 | U | The system shall show the Self-test row directly below Check. | Yes; tested (test_kat_verdict_demoted_to_self_test_row_under_check). |
| R-TUI-100.4 | U | The system shall place no toggle of the CRC Designer directly below another toggle. | Yes; tested (test_at214_no_two_switches_render_vertically_abutting). |
| R-TUI-100.5 | While | While the terminal is narrow, the system shall stack the top row and the three bench columns one under the other. | Yes; tested (test_bench_reflows_to_vertical_stack_when_narrow). |
| R-CRC-DESIGNER-006.1 | U | The system shall show file-derived text in the CRC Designer as plain text, never as markup. | Yes; tested (test_hostile_template_renders_literally_at_preview, test_coverage_window_hostile_markup_renders_literally). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D13-1 | Process records inside the rows: batch status lines, validation verdicts and suite counts, "scope boundaries", amendment notes, R-CRC-ENGINE-002's risk note RK-3, R-TUI-100's rationale, "does NOT claim" list and falsifiability transcript, "frozen-engine diff = 0", the repository rule that only dummy configs are committed. | Out of the requirements; they stay in their batch records. |
| D13-2 | Code contracts: `Operation` / `OperationResult` / `OperationInput` fields, the registry seam, import bans, widget ids, the pinned hex-render arguments, `_RECOMPUTE_SURFACE_IDS`, `_render_markup`. | Design notes, out. Their observable effects are rows: R-CRC-CONTRACT-001.1, .2 (no change to the image), R-OPS-003.13 and R-CRC-DESIGNER-006.1 (plain text). |
| D13-3 | R-OPS-003 asks for execution on the UI thread; the CRC check and write run on workers (`screens.py:2376`, `:2651`). | Follow the code: the screen stays responsive, the later result wins (R-OPS-003.7 … .9). |
| D13-4 | R-OPS-001 asks for a placeholder CRC operation; the CRC operation is real (`registry.py:16`, `crc.py:1567`). | Follow the code (S13.2 … S13.5). |
| D13-5 | Two blocks carry the id R-CRC-WIDTH-001. | The stored field width keeps R-CRC-WIDTH-001.x; the record width of the CRC write is R-CRC-RECWIDTH-001.x (second group S8, as `groups.csv` notes). |
| D13-6 | "CRC inputs are S19 only": the dialog takes any primary, S19 or Intel HEX (`app.py:7097`), and always writes S19 (`crc.py:1151`, `:1493`). | Follow the code; the CRC file name says `.s19`. Writing Intel HEX would be a new feature; not proposed. |
| D13-7 | Two CRC surfaces: the operation (32-bit, one `reverse` flag, JSON config) and the CRC Designer (8–64 bits, refin and refout apart, templates). They share no setting (`crc_kernel.py:17-18`: "Integration … is a later /dev-flow step"). | Keep both; CTX-CRC defines them by one model and says they share nothing. Joining them is a new feature, deferred (D13-16). |
| D13-8 | Save replaces a template of the same name without asking (`crc_designer_view.py:1259`). | Keep: Save updates the template of that name (R-CRC-TEMPLATE-001.3). |
| D13-9 | Load needs a typed path; the template home is not searched. | Keep; the 📂 Open templates/ chip shows the folder. A picker would be a new feature; not proposed. |
| D13-10 | The config path and the template path use S5's path function, including the repository-root search S5 removes (D5-8). | Cite S5.3 (R-CRC-CONFIGLOAD-001.4, R-CRC-TEMPLATE-001.13); D5-8 applies, no separate change. |
| D13-11 | S0 rows describe S13 behaviour: HLR-159 / LLR-159.1 (empty and partly covered targets of the CRC operation), LLR-155.8 (where the CRC write places its file), LLR-122.4 (Designer kernel, presets, templates), HLR-139 (the Designer's 📂 chip). | Moved into S13 (S13.4b, S13.5, S13.6 … S13.8); pointers left in S0 (rule D-9). The flow parts of HLR-159 / LLR-159.2 stay with S16. |
| D13-12 | R-OPS-003 says the rail "stays at exactly eight items"; it has 12 (S6 CTX-SHELL). | Out: the rail is S6's. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D13-13 | The placeholders `extract` and `split_by_segment` are listed in the Operations dialog and run nothing; their result says `placeholder: <id> not yet implemented` (`placeholders.py:23-87`). Split / Join / Export (S17) extracts and splits. | Delete them, with the status `placeholder`. The operation list keeps `crc` (R-OPS-002.1). |
| D13-14 | `run_operation` (`operation_service.py:39`) has no product caller: the dialog resolves and runs the operation itself. Only `run_operation` reaches the note `CRC: no config supplied — nothing to check`. `OperationResult.to_dict`, `Operation.describe` and `timestamp_utc` are read only by tests. | Delete them. The resolver seam `operation_resolver` stays (the dialog uses it, `screens.py:2329`). |
| D13-15 | Helpers used only by tests: `compute_region_crc`, `compute_region_crcs`, `encode_le32`, `decode_le32` (`crc.py`), `read_crc_config` (`crc_config.py`), `seed_template` (`crc_designer_model.py`). | Delete; their tests move to the functions the product uses (`compute_group_crc`, `encode_le`, `decode_le`, `read_crc_config_text` + `parse_crc_config`). |
| D13-16 | `CrcJob`, `parse_job`, `emit_job` and the flat-config up-conversion (`crc_designer_model.py:134`, `:686`, `:830`) were built for the join of the two surfaces; nothing in the product calls them. | Defer: they belong to the join (D13-7). No rows. Backlog item: delete them unless the next CRC batch plans the join. |
| D13-17 | Convention C-7 makes `operations/requirements/REQ-crc.md` the normative CRC source. It is stale (D-5 "fixed 4-byte codec … NOT parameterized", no groups) and contradicts this chapter. | This chapter is the one source (D-9). Delete `REQ-crc.md` and the convention text. |
| D13-18 | The `Operations error: unknown operation <id>` guard (`screens.py:2328-2333`): the list comes from the registry, so the operator cannot reach it. | Keep in the code; no requirement (it guards callers, like S8 D8-18). |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D13-20 | With `reverse` true, the operation engine reflects init before the first byte (`crc.py:211`); the parametric model and the CRC Designer take init as it is (`crc_kernel.py:131`). A copied-formula check gives, for poly 0x04C11DB7, init 0x12345678, reverse true, xorout 0xFFFFFFFF over "123456789": operation 0x18026B2A, model 0x0F8B7431. The same model gives the catalogue check of CRC-16/RIELLO (init 0xB2AA, refin true): 0x63D0. Inits 0 and 0xFFFFFFFF are not affected, so every shipped default and test still agrees. | Take init unreflected; add a test with an init that is not bit-symmetric (R-CRC-ENGINE-001.1). |
| D13-21 | Regions take any number (negative, end ≤ start, above 32 bits, a stored field past 0xFFFFFFFF) while group spans are checked (`crc_config.py:505-515` vs `:600-643`); region rule texts count from 0, group texts from 1. | One set of span rules for regions and group spans, numbered from 1 (R-CRC-CONFIG-001.9, .13). |
| D13-22 | polynomial, init and final_xor above 32 bits or negative are cut to their low 32 bits with no message (`crc_config.py:529-532`, `crc.py:211-224`). | Reject them (R-CRC-CONFIG-001.14). |
| D13-23 | A missing field gives `CRC config is structurally invalid: 'reverse'` (the bare key); a non-number gives Python's `invalid literal for int() with base 16: …`. The template reader does the same. | Name the field: `field '<name>' is missing`, `field '<name>' is not a number: <value>`, in both readers (R-CRC-CONFIG-001.10, .11). |
| D13-24 | The overlap notes fire only when a group is involved (`crc.py:1081`, `:1088`); each region of the example config holds its own stored field ([0x10000, 0x20000) → 0x1FFFC), so a write changes the CRC it just stored and the next check reads MISMATCH. A test pins the silence (test_s7_scope_pin_legacy_self_overlap_stays_silent). Conflict surfaced: the group rule (batch-32) is newer and states the hazard; the region silence exists only to keep the example quiet. | One overlap rule for every target (R-CRC-GROUP-001.2, .3); the example's regions end where their fields start (R-CRC-CONFIG-001.1); the silence test changes. |
| D13-25 | A check that ends with status `error` (a target with no byte) still enables Write CRC (`screens.py:2501`); the write then refuses. | Keep Write CRC disabled after a check with status `error` (R-CRC-WRITE-001.3). |
| D13-26 | Region and write lines show values with 8 digits: a 1- or 2-byte field shows `computed 0x12345678, stored 0x00000078 -> MATCH`, and `wrote 0x12345678 (1 LE bytes)` although one byte was written (`screens.py:2554`, `:2778`). | Show the field value and the stored value as field hex, 2N digits (R-CRC-CHECK-001.6, R-CRC-WRITE-001.24). |
| D13-27 | A config error found at Confirm says `CRC config error - no check was run:` (`screens.py:2641`); the operator asked for a write. | `CRC config error - nothing was written:` on the write path (R-CRC-WRITE-001.8). |
| D13-28 | The CRC write passes no header to the S19 writer (`crc.py:1493-1495`): the source's S0 data is lost and the terminator address is 0. S8 asked S13 to decide (D8-29). | The CRC file is the same firmware with its CRC fields set: keep the source's S0 data and terminator address, as S8's save-back does (R-CRC-WRITE-001.17, .18). |
| D13-29 | An internal failure of the CRC check or write is written to the status line behind the dialog (`screens.py:2427-2430`, `:2702-2705`), not to the result area the operator reads. | Show it in the result area (R-OPS-003.11, .12). |
| D13-30 | `x` with only a MAC loaded opens the dialog on an empty image (`app.py:7097` checks only for no snapshot; a MAC-only snapshot has no image, `app.py:1379-1414`); every CRC target then holds no byte. | Refuse as with nothing loaded (R-OPS-003.2, .3). |
| D13-31 | A Designer field that is not a number gives `Invalid parameters: invalid literal for int() with base 16: '<text>'` (`crc_designer_view.py:1157`), naming no field. | `Invalid parameters: <field> is not a number: <text>`, also on Save (R-CRC-DESIGNER-002.5, R-CRC-TEMPLATE-001.8). |
| D13-32 | Save cleans the name (`crc_designer_view.py:1227`) but does not apply the shared device-name rule (`workspace.py:1803`); on Windows a name like `NUL` can address a device instead of a file. | Refuse a device name (R-CRC-TEMPLATE-001.7). |
| D13-33 | The CRC Designer (Name, Aliases, the JSON strip, the Load / Save status) and the Operations dialog (result area, load messages) show file-derived text without markup, but keep control characters. | Add both to S1's safe-text views; the control-character part follows S1's sweep (S1 D-7). |

**Prototype first** (visual; prototype round with real captures and your verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D13-40 | After D13-13 the operation list holds one row, `crc - CRC`. | What the Operations dialog shows when one operation remains: keep the list, or open on the CRC controls. |
| D13-41 | R-TUI-100 records that at the bench's pane width the preset list shows `CRC-32/ISO-HDLC` as `CRC-32/I`, with no ellipsis or marker; the largest-to-smallest tile ratio is 2.54:1 against a 6:1 design rule; the screen at 80 × 24 is unmeasured; a toggle's state is shown by position only. | Column widths at narrow and wide terminals so preset names read whole; whether toggles carry a state word. |
| D13-42 | The coverage window paints ranges in `#91abec` (`crc_designer_view.py:1074`, `insight_style.py:68`), a colour outside the S3 palette (CTX-LEGEND). The JSON strip's title is `Template JSON · round-trips through parse_template`, the name of a code function. | The palette colour for ranges in the coverage window; a title without code names. |

**Passed to other groups**

- **S0**: pointers for HLR-159 / LLR-159.1 (CRC-operation part), LLR-155.8, LLR-122.4 and the CRC Designer part of HLR-139: now S13.4b, S13.5, S13.6 … S13.8 (D13-11).
- **S1**: the CRC Designer (Name, Aliases, JSON strip, Load / Save status) and the Operations dialog (result area) join the safe-text views (D13-33).
- **S5**: the config path and the template path use S5.3's path rules (D5-8 applies, D13-10); the CRC write places its file through the shared placement and numbered names (R-CRC-WRITE-001.15, .16); the 📂 Open templates/ chip follows the chip rules (HLR-139).
- **S6**: the keys `x` (Operations) and `0` (CRC Designer); R-OPS-003's "eight rail items" is retired (D13-12).
- **S7**: the Operations dialog and the CRC write confirmation follow R-DLG.x (Escape, first focus on Cancel, D7-22); their content rows stay here. R-HEX-HYGIENE-001's error rule is absorbed as R-OPS-003.11, .12; its button-row ids stay out (D7-2).
- **S8**: the CRC write uses the S19 writer (S8.7) and the verify (S8.8); its terminator address and S0 header are decided as the save-back's (D13-28, answering D8-29). R-CRC-RECWIDTH-001 is S13's, second group S8.
- **S11**: the used template of the gather is the template last loaded in the CRC Designer (R-CRC-TEMPLATE-001.12); the template home with a project is `<project>/templates/`.
- **S16**: the flow CRC arm reads the same config (CTX-CRCCONFIG), computes by S13.2 and gives the coverage notes of S13.4b; its rows cite them. D13-20, 21, 22 and 24 change its results too.
- **S17**: Split / Join / Export is the extract and split the deleted placeholders promised (D13-13).

---

**Received from later groups** (after all groups were written)

- S13.1 (S7: Operations dialog, CRC write confirmation, the HYGIENE error rule) → covered by S13.1 (R-OPS-003.x; the error rule is R-OPS-003.11, .12, D13-29) and R-CRC-RECWIDTH-001.1 … .3; Escape and first focus are S7 R-DLG.2, R-DLG.6.
- S13.2 (S8: writer, verify, R-CRC-WIDTH-001, terminator) → covered by R-CRC-RECWIDTH-001.4 and R-CRC-WRITE-001.17, .18 (D13-28); R-CRC-WIDTH-001 stays here.
- S13.3 (S11: the last loaded template that the gather copies) → covered by R-CRC-TEMPLATE-001.12.
- S13.4 (S15, absorbed: the flow CRC arm) → covered: S15 R-FLOW-CRC.1 … .8 cite CTX-CRCCONFIG, S13.2 and S13.4b; no S13 row changes.

**Reconciled with batch-100 (s19_app 570b4b5)**

- From S11 and the sweep: R-CRC-TEMPLATE-001.12 cites S11 R-PROJ-GATHER.10 (the `copied but not recorded` status of a used template whose name project.json cannot record, batch-100 LLR-171.5). Cell change only.
- From S5: a CRC file in `crc/` is not listed in the Workarea Files list; batch-100 keeps that list to `temp/` on purpose (S5 D5-43), so the file is reloaded by its typed path. No S13 row says otherwise; no change.
- No row added, changed in text or retired; no decision added or superseded.

## 6. Counts

| | Old S13 | Strict |
|---|---:|---:|
| Requirement statements | 13 rows in 14 blocks + 1 convention | 147 rows |
| Statements the code contradicts or that are not product behaviour | 7 (R-OPS-001 placeholder; R-OPS-003 thread, service seam, rail; R-CRC-ENGINE-002 risk note; duplicate R-CRC-WIDTH-001; C-7) | 0 |
| Rows by form: U / When / While / If / Where | — | 25 / 47 / 10 / 65 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 35 (12 follow the code or move, 6 remove, 14 correct a defect, 3 prototype first; numbers not contiguous) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", a final period, no repeated id across the review files.
