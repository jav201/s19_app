# S8 — Change documents, apply & save-back: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S8 (lines 2856–3688): 33 primary rows — R-CDFX-001 … 015, 017, 018 and R-MEM-001 … 005 (historical), R-CHG-001 … 003, R-HEX-EMIT-001, R-HEX-SAVE-001, R-HEX-VERIFY-001 / 002, R-S19-WIDTH-001, R-S19-S0HEADER-001, R-S19-SAVE-REUSE-001, R-PATCH-SAVE-FOLDER-001. Also absorbed: HLR-153 statement 2 (passed from S1, D-10), the S8 parts of HLR-155 / HLR-157 / LLR-141.1 / LLR-153.3 / LLR-153.4 / LLR-157.1 / LLR-157.4 (S0 table). Cited, not rewritten: R-CRC-WIDTH-001 (S13), R-PATCH-PASTE-001 and R-PATCH-WRITE-REUSE-001 (S10).
Code: `s19_app/tui/changes/` (`__init__.py`, `model.py`, `io.py`, `validate.py`, `apply.py`, `verify.py`, `display.py`); the S8 functions of `app.py` (`_synth_s0_header_from_filename`, `on_patch_editor_panel_save_back_decision`, `_surface_verify_result`, `_verify_mismatch_summary`); behaviour read in `services/change_service.py` (`load`, `load_text`, `validate`, `save`, `apply`, `save_patched`, `emit_and_verify`, `save_back_status_suffix`), the apply branch of `app.py::on_patch_editor_panel_action_requested`, `workspace.py` placement, `services/load_service.py`. Every fact read with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S8.4 (R-PATCH-SAVE-FOLDER-001.5, .6) and S8.6 (the save-back rows; `on_patch_editor_panel_save_back_decision` is `app.py:4648`) verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-CHGDOC, CTX-FINDING, CTX-APPLY, CTX-SAVEBACK, CTX-WRITE, CTX-VERIFY.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; one visual change marked **prototype first**.
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S8.md` (backlog). Nothing is changed in the code yet.

---

## 1. How S8 was written before

- **22 historical rows** (R-CDFX-001 … 018 except 016, R-MEM-001 … 005): the CDFX parameter flow and the v1 unified change-set of batches 03/04. Each says "Superseded" or "Evolved"; the `cdfx/` package they name was deleted in batch-07 and three of them say their tests are gone too.
- **R-CHG-001 / 002 / 003**: three paragraphs that each pack a format, a reader, a rule set, an engine and a save path into one sentence, with function names, class fields and a batch-73 amendment table (before/after, "why", "not adopted", "scope").
- **R-HEX-EMIT/SAVE/VERIFY, R-S19-WIDTH/S0HEADER/SAVE-REUSE**: rows with signatures, line numbers, return-tuple shapes, an "emitter location" design note, engine-frozen guards and "A-5 surface reachability".
- **R-PATCH-SAVE-FOLDER-001**: one row, outdated by the project homes of batch-95.
- **Missing**: no message text anywhere, no check order for entry faults, no rule for what a save-back writes after the document changes (that rule sits in S0, HLR-157).

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-CDFX-*, R-MEM-* | History, not requirements: the code was deleted in batch-07; no live verifier for several. | Out of the chapter (D8-13, D8-14). |
| R-CHG-001 | "collect every … finding" with no message text: no test can check a message. | One row per defect with its exact message (S8.1 … S8.3). |
| R-CHG-001 | "with no symbolic addressing field": false since batch-95 (`symbol`). | Symbol rows S8.3, moved from LLR-141.1 (D8-5). |
| R-CHG-001 | `version` is listed as a format field, but the reader never checks it: `"version": "9.9"` reads as v2. | Row R-CHG-VER.1 (D8-20). |
| R-CHG-001 | No check order: an entry with two faults satisfies two rows, but the reader records one finding. | Entry defects in check order (CTX-CHGDOC); first one wins (R-CHG-001.24). |
| R-CHG-001 | "skipped" entries read as harmless, but every entry finding is an ERROR, so the whole apply is blocked. | Both stated: R-CHG-001.22 and R-CHG-002.3 (D8-11). |
| R-CHG-002 | "computed via the sorted-range primitives", "`to_dict()` under an injectable UTC clock", field names: design. `to_dict` has no caller outside tests. | Observable rows; `to_dict` deleted (D8-16). |
| R-CHG-002 amendment | A history table; the rule itself (first-by-start) is one sentence. | Rule kept (R-CHG-LINK.3); history out (D8-7). |
| R-CHG-003 | "persist to `.s19tool/workarea/<project>/`": with no project the file goes to the work-area root. "S19-only this batch": R-HEX-SAVE-001 reversed it. | Rows follow the code (D8-1, D8-2). |
| R-CHG-003 | "persist the patched image": since batch-99 the save writes the source plus the current document, not the image of the last apply. | R-CHG-003.8 (D8-3). |
| R-HEX-VERIFY-002 | "While a save-back completes": an event, not a state (E4). The notice text is not given. | When / If rows with exact text. |
| R-HEX-VERIFY-001 | "post-write certainty", but a written file whose records fail their checksum still verifies (only the bytes are compared). | R-HEX-VERIFY-001.5 (D8-31). |
| R-S19-S0HEADER-001 vs HLR-153 | Conflict: "16-byte mode keeps the legacy empty S0" vs "written as S19, the system shall emit its S0 header". The code drops the source S0 at width 16. | HLR-153 wins (more recent); R-S19-S0HEADER-001.1 (D8-27). |
| R-S19-SAVE-REUSE-001 | No behaviour: which functions carry the width. | One observable row (R-S19-SAVE-REUSE-001.1); the rest out (D8-15). |
| R-PATCH-SAVE-FOLDER-001 | "global patches/ … never the root": with a project open, saves go to `<project>/patches/` or `<project>/checks/`. "Two saves shall not clobber": two identical saves reuse one file. | Rows follow the code (D8-4). |
| R-HEX-EMIT-001 | "pure, stdlib only, lives in io.py": design. | Out (D8-15). |
| (nothing) | The S19 terminator of every written file has address 0: the source's start address is lost. No row says so. | R-S19-EMIT.11 (D8-29). |
| (nothing) | S1 D-2 asked: should a save-back stop on a range with a bad checksum? Today it writes those bytes with new, valid checksums, silently. | R-CHG-003.22 (D8-26). |

---

## 3. Context notes (informative)

### CTX-CHGDOC · The change document (S8.1 … S8.4)

```text
change document   A JSON file or pasted JSON text in the format below.
                  kind "change": entries to write into the image.
                  kind "check": expected values (S9). Same format.
envelope          The top-level JSON object. Fields:
  format            "s19app-changeset"
  version           "2.0"
  kind              "change" or "check"
  encoding          The name of a text codec, for example "utf-8". It turns string
                    values into bytes.
  value_mode        "text" or "codes"
  entries           A JSON array of entries.
entry             A JSON object. Fields:
  type              "bytes" or "string"
  address           Address form: a JSON string "0x" + one or more hexadecimal digits
                    (either case), or a JSON integer 0 or more (not true/false).
                    A byte address.
  bytes             (type "bytes") Byte tokens separated by whitespace. A byte token is
                    exactly two hexadecimal digits.
  value             (type "string") value_mode "text": a JSON string.
                    value_mode "codes": a JSON array of Unicode code points.
  symbol            (optional) The name of an A2L tag, beside the address, never in
                    its place.
encoded bytes     The bytes an entry writes: its byte tokens, or its value encoded
                  with the document's encoding.
span              address … address + number of encoded bytes (end not included).
v1 document       A JSON object whose format is "s19app-unified-changeset", or that has
                  both a "parameters" and a "memory" field.
declared A2L      The A2L the reader resolves symbols against.
read cap          268,435,456 bytes (256 MiB) per change file.
entry ceiling     100,000 entries per document.
run ceiling       1,048,576 bytes per entry; for a string value also 1,048,576
                  characters or code points before encoding.
Example (fake values):
  {"format": "s19app-changeset", "version": "2.0", "kind": "change",
   "encoding": "utf-8", "value_mode": "text",
   "entries": [{"type": "bytes", "address": "0x00000000", "bytes": "DE AD BE EF"},
               {"type": "string", "address": "0x00000010", "value": "ABC"}]}

File defects (each ends the read):
  F-1  the path names no file.
  F-2  the file is larger than the read cap.
  F-3  the file cannot be opened.
  F-4  the text is not JSON: not well-formed, nested deeper than the JSON reader
       allows, or not valid UTF-8.
  F-5  the top level is not a JSON object.
  F-6  the text is a v1 document.
Envelope defects (each one is reported):
  M-1  format is not "s19app-changeset".
  M-2  kind is not "change" or "check".
  M-3  encoding is not the name of a text codec.
  M-4  value_mode is not "text" or "codes".
  M-5  entries is missing or is not an array.
  M-6  version is not "2.0" (D8-20).
Entry defects, in check order:
  C-1  the entry is not a JSON object.
  C-2  type is not "string" or "bytes".
  C-3  address is not an address form.
  C-4  symbol is present but is not text, or is blank.
  C-5  symbol names no usable tag: no declared A2L, no tag of that name, or a tag
       without an address or a length.
  C-6  symbol is present and type is "string".
  C-7  (string) value is missing, empty, or of the wrong JSON type for value_mode.
  C-8  (string) value has more characters or code points than the run ceiling.
  C-9  (string) value cannot be encoded with the encoding.
  C-10 (string) the encoded value is longer than the run ceiling.
  C-11 (bytes) bytes is missing, not text, or blank.
  C-12 (bytes) a token is not a byte token.
  C-13 (bytes) there are more tokens than the run ceiling.
  C-14 the symbol's tag has another address, or another length than the encoded bytes.
collision         Two entries whose spans share an address.
```

### CTX-FINDING · Findings and status texts (S8.1 … S8.8)

```text
finding        A code, a severity (error or warning) and a message about a change
               document or a save. The same shape as an issue (S3 CTX-ISSUE), with
               artifact "changes".
finding line   [<code>] <severity>: <message>
               e.g. [CHG-COLLISION] error: change entry 0 at address 0x100 (4 bytes) …
<i>            The entry's position in the entries array, from 0.
<A>, <B>, <T>  An address: uppercase hexadecimal digits, no leading zeros.
<A8>           An address: 8 uppercase hexadecimal digits.
quoted value   <path>, <format>, <version>, <kind>, <encoding>, <value_mode>, <type>,
               <symbol>, <tag>, <typed name>, <image kind>: the value as found —
               text in single quotes, a number as its digits, a missing field or
               null as None.
<error type>   The name of the error the system got from the file system or the JSON
               reader, for example PermissionError or JSONDecodeError.
<reason>       The refusal text of the placement (S5 CTX-WORKAREA refusals).
<n> entries    "entry" when the count is 1, "entries" otherwise.
```

### CTX-APPLY · Applying a change document (S8.5)

```text
source image      The image as loaded from the primary file (S1), before any apply.
source byte       The byte the source image holds at an address.
containment       Where an entry's span lies in the image:
  inside            every address of the span is in one range.
  partial           some address is in a range, but no single range holds the whole
                    span (it crosses a range end or a gap).
  outside           no address of the span is in the image.
  no image          no primary image is loaded.
disposition       applied (inside, written) · skipped-partial · skipped-outside ·
                  skipped-no-image · blocked.
blocked document  A change document with an error finding, or whose kind is not
                  "change".
MAC span          One address: that of a MAC record that parsed and has an address (S2).
A2L span          A tag's address … address + length; 1 byte when the tag has no
                  length or a length below 1.
owner             Among the spans of one kind that hold an address: the one with the
                  lowest start; on equal starts, the one declared first.
linkage           mac-linked (the span shares an address with a MAC span) ·
                  a2l-linked (with an A2L span) · both · standalone (neither).
lowest linked address  The lowest address of the entry's span that a span of that
                  kind holds.
change summary    Per entry, in document order: span, bytes before (applied entries
                  only), encoded bytes, disposition, linkage, linkage symbol, the
                  entry's own symbol. Per document: the count of each disposition,
                  the findings, the time of the apply (UTC, ISO 8601).
```

### CTX-SAVEBACK · Save-back (S8.6)

```text
save-back         Writing the Patch Editor's image to a new file after an apply.
save-back prompt  The row "Save patched image as:" with a name box and the controls
                  "Width: <w> bytes/line", "Write file" and "Don't save" (layout: S10).
width             Data bytes per S19 record: 32 or 16.
suggested name    <stem of the loaded file>-patched.s19, or …-patched.hex for an
                  Intel HEX image.
save name         The confirmed name reduced to its last path part (either separator;
                  a drive removed), without the spaces around it.
kind suffix       .s19 for an S19 image, .hex for an Intel HEX image.
reserved device name  A name whose part before the first dot, without trailing dots and
                  spaces, compared case-folded with ¹ ² ³ read as 1 2 3, is CON, PRN,
                  AUX, NUL, CONIN$, CONOUT$, COM0 … COM9 or LPT0 … LPT9 (the shared
                  rule of the project names, S11).
destination       The open project's folder; the work area (.s19tool/workarea/) when no
                  project is open.
saved image       The source image plus the encoded bytes of every inside entry of the
                  open change document.
invalid range     A range that holds a byte of an invalid record (S1 R-VAL-001b).
header data       The data of the S0 record of a written S19 file.
save suffix       " — <n> entries applied before this save (<A8>, …)", then, when the
                  saved image holds entries the last apply did not apply,
                  "; includes <m> entries not applied before this save (<A8>, …)".
                  No parentheses when n is 0. Addresses in document order.
```

### CTX-WRITE · Image files the system writes (S8.7)

```text
S19 record types by the highest address of the image:
  up to 0xFFFF       data S1, terminator S9
  up to 0xFFFFFF     data S2, terminator S8
  above 0xFFFFFF     data S3, terminator S7
S19 record rules     S1 CTX-S19 (count, address width, checksum rule).
Intel HEX records    type 04 (upper 16 address bits), type 00 (data), type 01 (end of
                     file, the line :00000001FF). Record rules: S1 CTX-HEX.
```

### CTX-VERIFY · Verify on save (S8.8)

```text
verify            Reading a written file back and comparing its image with the saved
                  image.
difference kinds  changed (both hold the address, the bytes differ) ·
                  missing in file (the saved image holds the address, the file does not) ·
                  extra in file (the file holds the address, the saved image does not).
run               A longest run of consecutive addresses of one difference kind.
mismatch summary  changed <r> run(s) / <b> byte(s), missing in file <r> run(s) / <b>
                  byte(s), extra in file <r> run(s) / <b> byte(s)
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested**, **Partly** / **No** with the decision. "Code only" = the test checks the finding code, not the message text.

### S8.1 · Reading a change document: file and envelope (CTX-CHGDOC, CTX-FINDING)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHG-001.1 | When | When the system reads pasted change-document text, the system shall apply the same rules as to a change file, except file defects F-1, F-2 and F-3. | Yes; tested (test_parse_from_string_matches_file_read). |
| R-CHG-001.2 | When | When the operator loads a change file by its path, the system shall find the file by the path-input rules of S5.3. | Partly: also searches up to 6 parent folders for a repository root (D5-8, S5). |
| R-CHG-001.3 | If | If the path names no file, then the system shall record the finding `MF-PATH-UNRESOLVED` with the message `the change-file path could not be resolved — no file was opened: <path>`. | Yes; tested (code only, test_resource_ceilings_path_unresolved). |
| R-CHG-001.4 | If | If the change file is larger than the read cap, then the system shall record the finding `MF-SIZE-CAP` with the message `the change file is <n> bytes, over the 268435456-byte read cap — the file was not loaded into memory`. | Yes; tested (code only). |
| R-CHG-001.5 | If | If the change file is larger than the read cap, then the system shall read none of its content. | Yes; tested (test_resource_ceilings_size_cap_before_parse). |
| R-CHG-001.6 | If | If the change file cannot be opened, then the system shall record the finding `MF-PATH-UNRESOLVED` with the message `the change file could not be opened — no document was loaded: <error type>`. | Yes; untested. |
| R-CHG-001.7 | If | If the text is not JSON, then the system shall record the finding `MF-JSON-PARSE` with the message `the change file is not well-formed JSON — the load produced an empty document: <error type>`. | Yes; tested (code only, test_parse_malformed_json_emits_mf_json_parse). |
| R-CHG-001.8 | If | If the top level of the text is not a JSON object, then the system shall record the finding `MF-BAD-STRUCTURE` with the message `the change file is well-formed JSON but its top level is not a JSON object — the load produced an empty document`. | Yes; tested (code only). |
| R-CHG-001.9 | If | If the text is a v1 document, then the system shall record the finding `CHG-V1-FORMAT` with the message `this is a retired v1 unified change-set document — the v2 format is 's19app-changeset' version '2.0'; v1 files are not supported and are not migrated`. | Yes; tested (code only, test_v1_rejected). |
| R-CHG-001.10 | If | If the text has a file defect, then the system shall give a document with no entries. | Yes; tested. |
| R-CHG-001.11 | If | If the text has a file defect, then the system shall record no finding other than the one of that defect. | Yes; tested (test_v1_rejected: no `CHG-FORMAT`). |
| R-CHG-001.12 | If | If the envelope has an envelope defect, then the system shall read none of its entries. | Yes; tested (test_metadata_faults). |
| R-CHG-001.13 | If | If the envelope has more than one envelope defect, then the system shall record one finding for each of them. | Yes; untested. |
| R-CHG-001.14 | If | If the envelope has defect M-1, then the system shall record the finding `CHG-FORMAT` with the message `the change file declares format <format>, not the v2 format 's19app-changeset' — no entries were read`. | Yes; tested (code only). |
| R-CHG-001.15 | If | If the envelope has defect M-2, then the system shall record the finding `CHG-KIND-UNKNOWN` with the message `the change file declares kind <kind>, not one of 'change' / 'check' — no entries were read`. | Yes; tested (code only). |
| R-CHG-001.16 | If | If the envelope has defect M-3, then the system shall record the finding `CHG-ENCODING-UNKNOWN` with the message `the change file declares encoding <encoding>, which does not resolve to a text codec — no entries were read`. | Yes; tested (code only; a codec that is not a text codec too). |
| R-CHG-001.17 | If | If the envelope has defect M-4, then the system shall record the finding `CHG-VALUE-MODE-UNKNOWN` with the message `the change file declares value_mode <value_mode>, not one of 'text' / 'codes' — no entries were read`. | Yes; tested (code only). |
| R-CHG-001.18 | If | If the envelope has defect M-5, then the system shall record the finding `MF-BAD-STRUCTURE` with the message `the change file's 'entries' field is absent or not a JSON array — no entries were read`. | Yes; tested (code only). |
| R-CHG-VER.1 | If | If the envelope has defect M-6, then the system shall record the finding `CHG-VERSION-UNKNOWN` with the message `the change file declares version <version>, not the v2 version '2.0' — no entries were read`. | No: the version is never checked (D8-20). |
| R-CHG-001.19 | When | When the operator loads a change document that has no file or envelope defect, the system shall show the status `Loaded <kind>: <n> entries, <e> error(s)`. | Yes. |
| R-CHG-001.20 | If | If a change document the operator loads has a file or envelope defect, then the system shall show the status `Change file not loaded: <e> error(s)`. | No: shows `Loaded <kind>: 0 entries, <e> error(s)`, with an empty kind after a file defect (D8-23). |
| R-CHG-001.21 | When | When the operator loads a change document, the system shall show a finding line for each of its findings after the status. | Yes. |

### S8.2 · Reading entries (CTX-CHGDOC)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHG-001.22 | If | If an entry has an entry defect, then the system shall leave the entry out of the document. | Yes; tested (test_entry_faults). |
| R-CHG-001.23 | If | If an entry has an entry defect, then the system shall go on reading the entries that follow it. | Yes; tested (test_entry_faults). |
| R-CHG-001.24 | If | If an entry has more than one entry defect, then the system shall record only the finding of the first one in check order. | Yes; untested. |
| R-CHG-001.25 | If | If the entries array holds more than the entry ceiling, then the system shall read only the first 100,000 entries. | Yes; tested (test_resource_ceilings_entry_count). |
| R-CHG-001.26 | If | If the entries array holds more than the entry ceiling, then the system shall record the finding `MF-ENTRY-LIMIT` with the message `the change file declares <n> entries, over the 100000-entry ceiling — the <m> entries past the ceiling were dropped`. | Yes; tested (code only). |
| R-CHG-001.27 | If | If an entry has defect C-1, then the system shall record the finding `CHG-DECL-STRUCTURE` with the message `entry <i> is not a JSON object — the entry was skipped`. | Yes; tested (code only, test_at050b_skipped_declarations_taint_nothing). |
| R-CHG-001.28 | If | If an entry has defect C-2, then the system shall record the finding `CHG-DECL-STRUCTURE` with the message `entry <i> declares type <type>, not one of 'string' / 'bytes' — the entry was skipped`. | Yes; untested. |
| R-CHG-001.29 | If | If an entry has defect C-3, then the system shall record the finding `CHG-ADDRESS-SYNTAX` with the message `entry <i> has no valid address — expected a '0x...' hex string or a non-negative integer — the entry was skipped`. | Partly: an address string ending in a line feed (`"0x10\n"`) is accepted (D8-21). Code tested. |
| R-CHG-001.30 | If | If an entry has defect C-7, then the system shall record the finding `CHG-VALUE-EMPTY` with the message `the string entry at address 0x<A> has a missing, empty, or wrong-typed 'value' field — the entry was skipped`. | Yes; tested (code only). |
| R-CHG-001.31 | If | If an entry has defect C-8, then the system shall record the finding `MF-ENTRY-LIMIT` with the message `the string entry at address 0x<A> declares a raw value of <n> characters/code points, over the 1048576 run-length ceiling — the entry was dropped before encoding`. | Yes; tested (code only, test_resource_ceilings_pre_encode_guard). |
| R-CHG-001.32 | If | If an entry has defect C-9, then the system shall record the finding `CHG-ENCODE-FAIL` with the message `the string entry at address 0x<A> could not be encoded with <encoding>: <error type> — the entry was skipped`. | Yes; tested (code only). |
| R-CHG-001.33 | If | If an entry has defect C-10, then the system shall record the finding `MF-ENTRY-LIMIT` with the message `the string entry at address 0x<A> encodes to <n> bytes, over the 1048576-byte run-length ceiling — the entry was dropped`. | Yes; tested (code only, test_resource_ceilings_encoded_run_length). |
| R-CHG-001.34 | If | If an entry has defect C-11, then the system shall record the finding `CHG-VALUE-EMPTY` with the message `the bytes entry at address 0x<A> has a missing or empty 'bytes' field — the entry was skipped`. | Yes; tested (code only). |
| R-CHG-001.35 | If | If an entry has defect C-12, then the system shall record the finding `CHG-BYTES-SYNTAX` with the message `the bytes entry at address 0x<A> has a token outside the wire grammar (whitespace-separated two-hex-digit tokens only) — the entry was skipped`. | Yes; tested (code only). |
| R-CHG-001.36 | If | If an entry has defect C-13, then the system shall record the finding `MF-ENTRY-LIMIT` with the message `the bytes entry at address 0x<A> declares <n> bytes, over the 1048576-byte run-length ceiling — the entry was dropped`. | Yes; untested. |
| R-CHG-001.37 | U | The system shall read the hexadecimal digits a–f of an address or a byte token as the same values as A–F. | Yes; tested (test_entry_shapes, accept-bytes-lowercase-token). |
| R-CHG-001.38 | U | The system shall measure the span of an entry in encoded bytes. | Yes; tested (test_collision_uses_encoded_length_not_char_count). |
| R-CHG-001.39 | U | The system shall put in no finding message the value or the bytes that an entry declares. | Yes; tested (test_entry_faults). |
| R-CHG-001.40 | If | If the spans of two entries share an address, then the system shall record the error finding `CHG-COLLISION` for each of the two entries. | Yes; tested (test_collision_geometries). |
| R-CHG-001.41 | If | If an entry collides, then the system shall give its collision finding the message `change entry <i> at address 0x<A> (<n> bytes) collides with the entry at address 0x<B> — two declarations target the same memory`, with <B> the first entry in document order that it collides with. | Yes; tested (both addresses, test_collision_messages_name_both_addresses). |
| R-CHG-001.42 | If | If an entry collides with more than one entry, then the system shall record one collision finding for it. | Yes; tested (test_collision_three_entry_chain). |
| R-CHG-001.43 | U | The system shall read the example of CTX-CHGDOC as a change document with two entries and no finding. | Yes; untested (`changes/io.py:161-173`; the doctest at `:546` checks the kind only). |
| R-CHG-001.44 | When | When the system reads the text of a per-entry edit (S10 R-TUI-058.2), the system shall read it as the only entry of a document with the open document's format, version, kind, encoding and value_mode. | Yes; tested (test_tc342_edit_entry_json_mutates_only_the_selected_index, test_tc343_edit_entry_json_rejects_malformed_without_mutation; `services/change_service.py:1506-1517`). |

### S8.3 · Symbol entries (CTX-CHGDOC; from LLR-141.1)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHG-SYM.1 | If | If an entry has defect C-4, then the system shall record the finding `CHG-SYMBOL-UNRESOLVED` with the message `entry <i> declares a 'symbol' that is not a tag name string — the entry was skipped`. | Yes; untested. |
| R-CHG-SYM.2 | If | If an entry has a symbol and the read has no declared A2L, then the system shall record the finding `CHG-SYMBOL-UNRESOLVED` with the message `entry <i>: the symbol <symbol> cannot be resolved — no A2L context is declared for this change-set — the entry was skipped`. | Yes; tested (code, test_tc712_no_context_refuses_symbol_entry_no_implicit_a2l). |
| R-CHG-SYM.3 | If | If an entry's symbol names no tag of the declared A2L, then the system shall record the finding `CHG-SYMBOL-UNRESOLVED` with the message `entry <i>: the symbol <symbol> resolves to no tag in the declared A2L — the entry was skipped`. | Yes; tested (test_tc712_unresolved_symbol_refused_at_load_naming_it). |
| R-CHG-SYM.4 | If | If an entry's symbol names a tag without an address or a length, then the system shall record the finding `CHG-SYMBOL-UNRESOLVED` with the message `entry <i>: the symbol <symbol> resolves to a tag without an address or length — the entry was skipped`. | Yes; tested (test_tc712_tag_without_address_or_length_refused_named). |
| R-CHG-SYM.5 | If | If an entry has defect C-6, then the system shall record the finding `CHG-SYMBOL-VALUE` with the message `the symbol entry at address 0x<A> (<tag>) declares a string 'value' — symbol-referenced entries carry their value as encoded bytes — the entry was skipped`. | Yes; tested (test_tc712_symbol_on_string_entry_and_drift_refused_named). |
| R-CHG-SYM.6 | If | If an entry has defect C-14, then the system shall record the finding `CHG-SYMBOL-VALUE` with the message `the symbol <tag> resolves to address 0x<T> length <L>, which drifts from the declared address 0x<A> / <n> encoded bytes — the entry was skipped`. | Yes; tested (test_tc712_symbol_on_string_entry_and_drift_refused_named). |
| R-CHG-SYM.7 | When | When the system resolves a symbol, the system shall match tag names without regard to case. | Yes. |
| R-CHG-SYM.8 | When | When the system resolves a symbol, the system shall store the tag's own spelling as the entry's symbol. | Yes. |
| R-CHG-SYM.9 | When | When the operator loads or pastes a change document while an A2L is loaded, the system shall use that A2L as the declared A2L. | No: the Patch Editor declares no A2L, so every symbol entry is refused (D8-22). |
| R-CHG-SYM.10 | If | If no A2L is loaded when the operator loads or pastes a change document, then the system shall read the document with no declared A2L. | Yes. |

### S8.4 · Writing and saving a change document (CTX-CHGDOC)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHG-WRITE.1 | When | When the system writes a change document, the system shall write the envelope fields in the order format, version, kind, encoding, value_mode, entries. | Yes. |
| R-CHG-WRITE.2 | When | When the system writes a change document, the system shall write each address as `0x` and uppercase hexadecimal digits with no leading zeros. | Yes; tested (test_tc017_address_is_the_canonical_hex_string_field). |
| R-CHG-WRITE.3 | When | When the system writes a change document, the system shall write the bytes of a bytes entry as uppercase byte tokens separated by one space. | Yes. |
| R-CHG-WRITE.4 | When | When the system writes a change document, the system shall write the value of a string entry as it was declared. | Yes. |
| R-CHG-WRITE.5 | When | When the system writes an entry that has a symbol, the system shall write its symbol field after its other fields. | Yes; tested (test_tc712_canonical_writer_emits_symbol_and_resolved_address). |
| R-CHG-WRITE.6 | When | When the system writes a change document, the system shall write the entries in document order. | Yes; tested (test_tc017_entries_preserve_insertion_order). |
| R-CHG-WRITE.7 | When | When the system writes a change document, the system shall indent the JSON by 2 spaces. | Yes; untested. |
| R-CHG-WRITE.8 | When | When the system writes a change document, the system shall write each character outside ASCII as a JSON `\u` escape. | Yes; untested. |
| R-CHG-WRITE.9 | When | When the system writes a change document, the system shall end the file with a line feed. | Yes; untested. |
| R-CHG-WRITE.10 | When | When the system writes the same change document twice, the system shall write the same bytes. | Yes; tested (test_tc015_serialize_is_byte_deterministic). |
| R-CHG-WRITE.11 | When | When the system reads a change document it wrote, the system shall read the same envelope and entries. | Yes; tested (test_metadata_roundtrip, test_v2_save_load_round_trip). |
| R-PATCH-SAVE-FOLDER-001.1 | When | When the operator saves the open change document with no project open, the system shall place the file in `patches/` of the work area. | Yes; tested (test_at031a_save_doc_lands_in_patches_folder). |
| R-PATCH-SAVE-FOLDER-001.2 | When | When the operator saves an open change document of kind change with a project open, the system shall place the file in `<project>/patches/`. | Yes; tested (test_scoped_home_patch_save_with_project_lands_in_project). |
| R-PATCH-SAVE-FOLDER-001.3 | When | When the operator saves an open change document of kind check with a project open, the system shall place the file in `<project>/checks/`. | Yes; tested (test_scoped_home_patch_save_with_project_lands_in_project). |
| R-PATCH-SAVE-FOLDER-001.4 | When | When the operator saves the open change document, the system shall name the file `changes.json`. | Yes. |
| R-PATCH-SAVE-FOLDER-001.5 | If | If the folder holds a file with the same content under that name or a numbered name, then the system shall use that file and write nothing. | Yes; tested (test_at031b_two_saves_are_distinct_no_clobber, test_tc018_existing_name_is_dedup_suffixed: the identical arm of each, LLR-163.3, D8-36). |
| R-PATCH-SAVE-FOLDER-001.6 | If | If the name is taken in the folder by a file with different content, then the system shall name the new file with the lowest free numbered name. | Yes; tested (test_tc018_existing_name_is_dedup_suffixed, test_at031b_two_saves_are_distinct_no_clobber: the differing arm of each, D8-36). |
| R-PATCH-SAVE-FOLDER-001.7 | When | When the system has saved the change document, the system shall show the status `Saved change-set to <name>`. | Yes. |
| R-PATCH-SAVE-FOLDER-001.8 | If | If the system cannot place the change document, then the system shall record the warning finding `MF-WRITE-CONTAINMENT` with the message `the change-file write target failed work-area containment validation — no file was written: <error type>: <reason>`. | Yes; tested (code only, test_tc018_containment_rejection_surfaces_issue_not_exception). |
| R-PATCH-SAVE-FOLDER-001.9 | If | If the system cannot place the change document, then the system shall show the status `Change-set write rejected - see issues`. | Yes. |
| R-PATCH-SAVE-FOLDER-001.10 | When | When a change-document save ends, the system shall leave no staging file in the work area. | Yes; tested (test_tc018_no_temp_file_is_left_behind_after_a_clean_write). |

### S8.5 · Validating and applying (CTX-APPLY)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHG-VAL.1 | When | When the operator validates the open change document, the system shall recompute its collision findings from its current entries. | Yes; tested (test_validate_flags_interactive_collision, test_clean_revalidate_clears_stale_collision_faults). |
| R-CHG-VAL.2 | When | When the operator validates the open change document, the system shall keep its other findings. | Yes. |
| R-CHG-VAL.3 | When | When the operator validates the open change document, the system shall set the containment of each entry against the image. | Yes. |
| R-CHG-VAL.4 | When | When a validation ends, the system shall show the status `Validate: <n> entries, <e> error(s), <w> warning(s)`. | Yes; tested (prefix only). |
| R-CHG-002.1 | When | When the operator applies the open change document, the system shall first set every address that an earlier apply changed back to its source byte. | Yes; tested (test_tc_b99_21_editor_image_is_source_plus_document). |
| R-CHG-002.2 | When | When the operator applies the open change document, the system shall recompute its collision findings from its current entries. | Yes. |
| R-CHG-002.3 | If | If the document is a blocked document, then the system shall give every entry the disposition `blocked`. | Yes; tested (test_error_blocks_apply_zero_writes_all_blocked, test_non_change_kind_blocks_apply). |
| R-CHG-002.4 | If | If the document is a blocked document, then the system shall write no byte into the image. | Yes; tested (test_error_blocks_apply_zero_writes_all_blocked). |
| R-CHG-002.5 | If | If the document has an error finding when the operator applies it, then the system shall show the status `Apply blocked: the document has <e> error(s)`. | No: only `Apply: 0 applied, 0 skipped, <n> blocked` (D8-25). |
| R-CHG-002.6 | If | If the document's kind is not change when the operator applies it, then the system shall show the status `Apply blocked: kind <kind> cannot be applied`. | No: as R-CHG-002.5 (D8-25). |
| R-CHG-002.7 | When | When the system applies a document that is not blocked, the system shall write the encoded bytes of each inside entry at its span. | Yes; tested (test_dispositions_inside_partial_outside). |
| R-CHG-002.8 | When | When the system applies a document that is not blocked, the system shall give each inside entry the disposition `applied`. | Yes; tested (test_dispositions_inside_partial_outside). |
| R-CHG-002.9 | If | If an entry of a document that is not blocked is partial, then the system shall give it the disposition `skipped-partial`. | Yes; tested (test_dispositions_inside_partial_outside). |
| R-CHG-002.10 | If | If an entry of a document that is not blocked is outside, then the system shall give it the disposition `skipped-outside`. | Yes; tested (test_dispositions_inside_partial_outside). |
| R-CHG-002.11 | If | If no primary image is loaded when the operator applies a document that is not blocked, then the system shall give every entry the disposition `skipped-no-image`. | Partly: in a MAC-only session every entry is `skipped-outside` (D8-24). Tested with no file loaded (test_disposition_no_image). |
| R-CHG-002.12 | If | If an entry is not inside, then the system shall write none of its bytes. | Yes; tested (test_before_after_capture_exact_tuples_outside_keys_unchanged). |
| R-CHG-002.13 | U | The system shall add no address to the image when it applies a change document. | Yes; tested (test_tc_b99_07_patch_at_s0_address_is_outside). |
| R-CHG-002.14 | When | When the system applies a change document, the system shall record the change summary of CTX-APPLY. | Yes; tested (test_summary_shape_and_serialization_determinism). |
| R-CHG-002.15 | When | When the system applies an entry, the system shall record its source bytes as its bytes before. | Yes; tested (test_tc_b99_40_before_bytes_is_source). |
| R-CHG-002.16 | When | When an apply ends, the system shall show the status `Apply: <a> applied, <s> skipped, <b> blocked`, with <s> the number of entries of the three skipped dispositions. | Yes; tested (prefix only, test_at057b_regroup_wiring_and_binding_regression). |
| R-CHG-LINK.1 | When | When the system applies a change document, the system shall give each entry its linkage. | Yes; tested (test_four_linkage_classifications_with_symbols). |
| R-CHG-LINK.2 | U | The system shall give an entry the same disposition whatever its linkage. | Yes; tested (test_both_linked_outside_entry_is_still_skipped). |
| R-CHG-LINK.3 | When | When the system gives an entry the linkage mac-linked or a2l-linked, the system shall take as its linkage symbol the name of the owner of its lowest linked address. | Yes; tested (test_at220_tc521_nested_overlap_resolves_first_by_start, test_at223_tc524_duplicate_mac_addresses_resolve_to_first_declared). |
| R-CHG-LINK.4 | When | When the system gives an entry the linkage both, the system shall take the MAC owner's name as its linkage symbol. | Yes; tested (test_four_linkage_classifications_with_symbols). |
| R-CHG-LINK.5 | If | If an entry's linkage is both and its MAC owner has no name, then the system shall take the A2L owner's name as its linkage symbol. | Yes; untested. |
| R-CHG-LINK.6 | When | When the system gives an entry the linkage standalone, the system shall give it no linkage symbol. | Yes; tested (test_four_linkage_classifications_with_symbols). |

### S8.6 · Save-back (CTX-SAVEBACK)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHG-003.1 | When | When an apply ends with at least one applied entry on an S19 or Intel HEX image, the system shall show the save-back prompt. | Yes; tested (test_save_back_prompt). |
| R-HEX-VERIFY-002.3 | When | When the system shows the save-back prompt, the system shall fill the name box with the suggested name. | Yes; tested (test_save_back_prompt, test_save_back_suggestion_is_format_aware). |
| R-S19-WIDTH-001.1 | When | When the system shows the save-back prompt, the system shall set the width to 32. | Yes; tested (test_saveback_width_32_packs_wide_records_and_populates_s0). The save-back half of LLR-015.3 (D8-35). |
| R-S19-WIDTH-001.2 | When | When the operator presses the Width control, the system shall switch the width between 32 and 16. | Yes; tested (test_saveback_width_32_packs_wide_records_and_populates_s0). |
| R-CHG-003.2 | When | When the operator presses `Don't save`, the system shall hide the save-back prompt. | Yes; tested (test_save_back_prompt). |
| R-CHG-003.3 | When | When the operator presses `Don't save`, the system shall write no file. | Yes; tested (test_save_back_prompt). |
| R-CHG-003.4 | When | When the operator presses `Don't save`, the system shall show the status `Patch Editor: save-back declined`. | Yes. |
| R-CHG-003.5 | When | When the operator presses `Write file`, the system shall hide the save-back prompt. | Yes. |
| R-CHG-003.6 | If | If no image is loaded when the operator presses `Write file`, then the system shall write no file. | Yes. |
| R-CHG-003.7 | If | If no image is loaded when the operator presses `Write file`, then the system shall show the status `Patch Editor: no image loaded - nothing saved`. | Yes. |
| R-CHG-003.8 | When | When the operator presses `Write file`, the system shall write the saved image to a new file in the destination. | Yes; tested (test_tc_b99_22_save_rederives_and_names_not_applied, test_at_b99_08_save_back_keeps_editor_image; destination: test_tc_b100_19_save_back_becomes_the_active_variant for the project folder, test_tc_b100_19_save_back_with_no_project_writes_no_manifest for the work area). A save-back into the open project also becomes its active variant (S11 R-PROJ-SAVEBACK.1, .2, .3, R-PROJ-002.10; D8-37). |
| R-HEX-SAVE-001.1 | When | When the system writes a save-back, the system shall write the file in the kind of the loaded image, S19 or Intel HEX. | Yes; tested (test_hex_save_writes_hex_file_that_reparses_to_post_apply_map). |
| R-CHG-003.9 | If | If the open change document is a blocked document when the operator presses `Write file`, then the system shall write no file. | Yes; tested (test_tc_b99_22_save_blocks_overlapping_entries). |
| R-CHG-003.10 | If | If the open change document is a blocked document when the operator presses `Write file`, then the system shall show the status `Patched image not saved - <n> entries blocked - see issues`. | Yes; tested (test_tc_b99_22_save_blocks_overlapping_entries). |
| R-CHG-003.11 | When | When the system writes a save-back, the system shall use the save name as the file name. | Yes; tested (test_save_back_adversarial_filenames_contained_or_refused). |
| R-HEX-SAVE-001.2 | If | If the save name does not end with the kind suffix in any letter case, then the system shall add the kind suffix. | Yes; tested (test_hex_save_forces_hex_suffix_when_name_lacks_it, test_s19_save_still_forces_s19_suffix). |
| R-CHG-003.12 | If | If the save name is empty or ends with a dot, then the system shall refuse the save-back with the warning finding `MF-WRITE-CONTAINMENT` and the message `the requested save-back filename is empty or ends with a dot or space after sanitization — the patched image was not written: <typed name>`. | Yes; tested (test_save_back_adversarial_filenames_contained_or_refused). |
| R-CHG-003.13 | If | If the save name is a reserved device name, then the system shall refuse the save-back with the warning finding `MF-WRITE-CONTAINMENT` and the message `the requested save-back filename is a Windows reserved device name — the patched image was not written: <typed name>`. | Partly: its own list misses COM0, LPT0, CONIN$, CONOUT$ and ¹ ² ³ (D8-30). Tested for CON-type names. |
| R-CHG-003.14 | If | If the destination is not inside the work area, then the system shall refuse the save-back with the warning finding `MF-WRITE-CONTAINMENT` and the message `the save-back destination is not inside this .s19tool/workarea/ tree — the patched image was not written: <reason>`. | Yes. |
| R-CHG-003.15 | If | If the system cannot place the save-back file, then the system shall refuse the save-back with the warning finding `MF-WRITE-CONTAINMENT` and the message `the save-back target failed work-area containment validation — the patched image was not written: <reason>`. | Yes. |
| R-CHG-003.16 | If | If the loaded image is neither S19 nor Intel HEX, then the system shall refuse the save-back with the warning finding `CHG-SAVE-UNSUPPORTED` and the message `save-back is not supported for a <image kind> source — only an S19- or Intel HEX-loaded image can be persisted; the patched image was not written`. | Partly: the code is named `CHG-HEX-SAVE-UNSUPPORTED` (D8-33). Tested (test_save_back_unsupported_source_refused_with_clear_issue). |
| R-CHG-003.17 | If | If the system refuses a save-back, then the system shall show the status `Patched image not saved - see issues`. | Yes; tested (test_b100_save_image.py). |
| R-CHG-003.18 | If | If the destination holds a file with the same content under the save name or a numbered name, then the system shall use that file and write nothing. | Yes. |
| R-CHG-003.19 | If | If the save name is taken in the destination by a file with different content, then the system shall name the new file with the lowest free numbered name. | Yes; tested (test_tc_b100_19_save_back_becomes_the_active_variant, arm A: `firmware.s19` lands as `firmware_1.s19`). |
| R-CHG-003.20 | U | The system shall leave the copy of the loaded file unchanged when it writes a save-back. | Yes; tested (test_tc_b99_11_same_name_save_back_keeps_work_copy; the loaded image keeps its path after a save-back into a project: test_tc_b100_19_save_back_becomes_the_active_variant). |
| R-CHG-003.21 | When | When the system has written a save-back, the system shall show the status `Patched image saved as <name><save suffix>`. | Yes; tested (test_tc_b99_22_save_rederives_and_names_not_applied). |
| R-CHG-003.22 | If | If the saved image holds an invalid range, then the system shall show the status `Warning: <n> invalid source ranges written with new checksums, first at 0x<A8>`. | No: the bytes are written with valid checksums and nothing is said (D8-26). |
| R-CHG-003.23 | If | If an entry of the open document is not inside when the system writes a save-back, then the system shall leave its address out of the save suffix. | Partly: an entry skipped by the save is named under "includes … not applied before this save" (D8-34). |
| R-S19-SAVE-REUSE-001.1 | When | When the system writes a save-back of an Intel HEX image, the system shall put at most 16 data bytes in each record whatever the width. | Yes; tested (test_tc220b_hex_save_unaffected_by_s19_only_kwargs). |
| R-S19-S0HEADER-001.1 | When | When the system writes a save-back of an S19 image whose source has an S0 record with data, the system shall use that data as header data. | Partly: at width 16 the header is written empty (D8-27). Tested at width 32 (test_saveback_width_32_preserves_source_s0_header). |
| R-S19-S0HEADER-001.2 | When | When the system writes at width 32 a save-back of an S19 image whose source has no S0 record with data, the system shall use as header data the written file name without its non-ASCII characters, cut to 252 bytes. | Partly: the name as typed is used, not the written name (D8-28). Tested non-empty only. |
| R-S19-S0HEADER-001.3 | When | When the system writes at width 16 a save-back of an S19 image whose source has no S0 record with data, the system shall write empty header data. | Yes; tested (test_saveback_width_16_caps_records_and_empties_s0). |
| R-S19-EMIT.11 | When | When the system writes a save-back of an S19 image whose source has a terminator, the system shall write the address of the source's terminator in the terminator. | No: address 0 is always written (D8-29). |

### S8.7 · Writing an image file (CTX-WRITE; HLR-153 statement 2)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-IMG-WRITE.1 | U | The system shall write into an image file only the addresses of the image. | Yes; tested (test_tc_b99_06_written_images_carry_s0_as_header_only). |
| R-IMG-WRITE.2 | U | The system shall write image files that its own reader (S1) reads back to the same image with no diagnostic. | Yes; tested (test_emit_s19_roundtrips_public_example_file, test_public_example_roundtrips_as_hex). |
| R-IMG-WRITE.3 | When | When the system writes a save-back file, the system shall end each line with CR LF on Windows and with LF on other systems. | Yes; untested. |
| R-S19-EMIT.1 | When | When the system writes an image as S19, the system shall write an S0 record first, with address 0 and the header data. | Yes; tested (test_tc213_bytes_per_line_16_back_compat_byte_identical, test_tc215_populated_s0_is_inert_to_data_and_empty_when_none). |
| R-S19-EMIT.2 | When | When the system writes an image as S19, the system shall write the data records in ascending address order. | Yes (the load gives the ranges in that order). |
| R-S19-EMIT.3 | When | When the system writes as S19 an image whose highest address is at most 0xFFFF, the system shall write S1 data records. | Yes. |
| R-S19-EMIT.4 | When | When the system writes as S19 an image whose highest address is above 0xFFFF and at most 0xFFFFFF, the system shall write S2 data records. | Yes. |
| R-S19-EMIT.5 | When | When the system writes as S19 an image whose highest address is above 0xFFFFFF, the system shall write S3 data records. | Yes; tested (test_saveback_width_32_packs_wide_records_and_populates_s0). |
| R-S19-EMIT.6 | When | When the system writes an image as S19, the system shall write as last record the terminator of CTX-WRITE that matches the data record type. | Yes; tested (S7, test_tc213_bytes_per_line_16_back_compat_byte_identical). |
| R-S19-EMIT.7 | When | When the system writes an image as S19, the system shall put at most the width in data bytes in each data record. | Yes; tested (test_tc212_default_emit_packs_32_byte_rows, test_tc213_bytes_per_line_16_back_compat_byte_identical). |
| R-S19-EMIT.8 | When | When the system writes an image as S19, the system shall start a new data record at the start of each range. | Yes. |
| R-S19-EMIT.9 | When | When the system writes an image as S19, the system shall make every record follow the checksum rule of S1 CTX-S19. | Yes; tested (test_emit_s19_reparses_to_equal_mem_map). |
| R-S19-EMIT.10 | When | When the system writes an image as S19, the system shall write the records in uppercase hexadecimal. | Yes; tested (test_tc213_bytes_per_line_16_back_compat_byte_identical). |
| R-S19-EMIT.12 | When | When the system writes an S19 file with no source terminator address, the system shall write address 0 in the terminator. | Yes; tested (test_tc213_bytes_per_line_16_back_compat_byte_identical). |
| R-HEX-EMIT-001.1 | When | When the system writes an image as Intel HEX, the system shall put at most 16 data bytes in each type-00 record. | Yes; tested (test_data_records_max_16_bytes_and_checksum). |
| R-HEX-EMIT-001.2 | When | When the system writes an image as Intel HEX, the system shall write a type-04 record before the first data record. | Yes; untested (test_low_address_roundtrip checks the bytes only). |
| R-HEX-EMIT-001.3 | When | When the system writes an image as Intel HEX, the system shall write a type-04 record before each data record whose upper 16 address bits differ from those of the data record before it. | Yes; tested (test_ela_record_emitted_per_upper16_change). |
| R-HEX-EMIT-001.4 | When | When the system writes an image as Intel HEX, the system shall write the data records in ascending address order. | Yes. |
| R-HEX-EMIT-001.5 | When | When the system writes an image as Intel HEX, the system shall start a new data record at the start of each range. | Yes. |
| R-HEX-EMIT-001.6 | When | When the system writes an image as Intel HEX, the system shall make every record follow the checksum rule of S1 CTX-HEX. | Yes; tested (test_data_records_max_16_bytes_and_checksum). |
| R-HEX-EMIT-001.7 | When | When the system writes an image as Intel HEX, the system shall write `:00000001FF` as the last line. | Yes; tested (test_output_terminates_with_single_eof). |
| R-HEX-EMIT-001.8 | When | When the system writes an image as Intel HEX, the system shall write no other type-01 record. | Yes; tested (test_output_terminates_with_single_eof). |
| R-HEX-EMIT-001.9 | When | When the system writes an empty image as Intel HEX, the system shall write only the line `:00000001FF`. | Yes; tested (test_empty_mem_map_emits_eof_only). |
| R-HEX-EMIT-001.10 | When | When the system writes an image as Intel HEX, the system shall write the records in uppercase hexadecimal. | Yes. |

### S8.8 · Verify on save (CTX-VERIFY)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-HEX-VERIFY-001.1 | When | When the system has written a save-back file, the system shall read the file back with the S1 reader of its kind. | Yes; tested (test_identity_write_is_verified). |
| R-HEX-VERIFY-001.2 | When | When the system has read a save-back file back, the system shall compare its image with the saved image. | Yes; tested (test_identity_write_is_verified). |
| R-HEX-VERIFY-001.3 | When | When the image read back equals the saved image, the system shall mark the save `verified`. | Yes; tested (test_identity_write_is_verified). |
| R-HEX-VERIFY-001.4 | If | If the image read back differs from the saved image, then the system shall mark the save `mismatch`. | Yes; tested (test_mutated_byte_is_mismatch_changed, test_dropped_byte_is_mismatch_only_a). |
| R-HEX-VERIFY-001.5 | If | If the file read back has a diagnostic or an integrity notice, then the system shall mark the save `mismatch`. | No: only the bytes are compared (D8-31). |
| R-HEX-VERIFY-001.6 | If | If the save is marked `mismatch`, then the system shall keep the written file. | Yes; tested (test_verify_on_dropped_byte_is_mismatch_file_kept). |
| R-HEX-VERIFY-002.1 | When | When the system marks a save `verified`, the system shall show the status `Saved + verified: <name><save suffix>`. | Yes; tested (test_verify_quiet_pass_on_faithful_hex_save). |
| R-HEX-VERIFY-002.2 | When | When the system marks a save `verified`, the system shall show no notice. | Yes; tested (test_verify_quiet_pass_on_faithful_hex_save). |
| R-HEX-VERIFY-002.4 | If | If the save is marked `mismatch`, then the system shall show the status `Verify MISMATCH: <name><save suffix>`. | Yes; tested (test_verify_loud_mismatch_notice, test_tc_b99_22_verify_mismatch_status_still_names_entries). |
| R-HEX-VERIFY-002.5 | If | If the save is marked `mismatch`, then the system shall show an error notice titled `Verify mismatch - file may not match` with the text `<name>: <mismatch summary>`. | Partly: the summary says `only_a` / `only_b` and `run` / `byte` for every count (D8-32). Tested (test_verify_loud_mismatch_notice). |
| R-HEX-VERIFY-002.6 | If | If the save is marked `mismatch`, then the system shall show the notice for 10 seconds. | Yes; untested. |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D8-1 | R-CHG-003 says the save-back lands in `.s19tool/workarea/<project>/`. With no project the code writes to the work-area root, which no files list shows. | Keep: destination = project folder, else the work area (CTX-SAVEBACK). S5 is told the file is not listed. |
| D8-2 | R-CHG-003 "save-back is S19-only"; R-HEX-SAVE-001 added Intel HEX. | One rule: the kind of the loaded image (R-HEX-SAVE-001.1). |
| D8-3 | Since batch-99 a save-back writes the source plus the current document (HLR-157, S0), not the image of the last apply. | Rows R-CHG-002.1, R-CHG-003.8, .21, .23 here; S0 drops the save-back half of HLR-157 when its review comes. |
| D8-4 | R-PATCH-SAVE-FOLDER-001 "global `patches/`, never the root; two saves never clobber". Batch-95 sends saves into the project; identical saves reuse one file. | Rows .1 … .6 follow the code. The file is always named `changes.json` (numbered on clash); a name field would be a new feature, not proposed. |
| D8-5 | R-CHG-001 "no symbolic addressing field"; batch-95 added `symbol` (LLR-141.1, S0 table). | Symbol rows S8.3 live here (D-9: with the behaviour). |
| D8-6 | HLR-153 statement 2 (how an image is written), passed from S1 (D-10). | R-IMG-WRITE.1 and R-S19-S0HEADER-001.1. |
| D8-7 | The batch-73 amendment table on overlapping linkage spans. | The rule stays (owner = lowest start, then first declared: CTX-APPLY, R-CHG-LINK.3); the table, "why" and "not adopted" go to the batch records. |
| D8-8 | Save-back files end lines with the operating system's line end; change documents always with LF. | Keep: S1 reads CR, LF and CR LF alike (R-READ-002). |
| D8-9 | The Intel HEX writer always uses type-04 records (also below 64 KiB) and 16 bytes per record; it writes no type 02, 03 or 05. | Keep (rows R-HEX-EMIT-001.x). No start address can be kept: the reader drops type 03/05 (S1 R-HEX-003.1). |
| D8-10 | The S19 record type follows the highest address of the image, not the source file's type: an S3 file with low addresses is written as S1. | Keep (R-S19-EMIT.3 … .5). |
| D8-11 | An entry defect "skips" one entry, but every entry finding is an error, so the whole apply is blocked. | Keep: a document with a defect is not applied by half. Both rows stated (R-CHG-001.22, R-CHG-002.3). |
| D8-12 | Load, validate, apply and save-back are document behaviours, but they run behind Patch Editor controls (S10). | Rows here; S10 keeps the controls and layout. |
| D8-35 | Batch-100 LED .13 amends LLR-015.3 (batch-14): the save-back keeps a {16, 32} width selector, default 32; Save project emits at 32 bytes per line with the source S0 and shows no selector (O-5). The save-back half is what R-S19-WIDTH-001.1, .2 already state (`screens_directionb.py:4578`, `:5692`; the prompt's width reaches `save_patched`, `app.py:4716-4730`). | No row change here. The Save project half is S11's (R-PROJ-IMAGE.7, .8, .11, which cite S8.7; S11 D11-53). |
| D8-36 | Batch-100 LLR-163.3 (Inc 1, before 093a7c0) re-pinned TC-018 and AT-031b as two pairs each, and reads R-PATCH-SAVE-FOLDER-001's old "two distinct saves shall not clobber" as two saves of distinct content (QA-27): identical bytes reuse the one file, different bytes take the next numbered name. | Rows .5 and .6 already state this (D8-4); their cells now name the arm of each test that verifies them. |
| D8-37 | Batch-100 HLR-168 (Inc 6, `eedbb2f`): a save-back into the open project becomes the project's active variant in the session and in `project.json`, records what it derives from, and leaves the loaded image's path unchanged (`app.py:4743-4757`). The save-back itself (name, numbered name, destination, statuses, verify) is unchanged. | The active-variant and manifest rows are S11's (HLR-168): R-PROJ-SAVEBACK.1 (active variant), .2 (derived_from), .3 (no project open, no project.json) and R-PROJ-002.10 (the project.json rewrite with the carried records); S8.6 cites them in R-CHG-003.8. The busy refusal Inc 12b added at the top of the handler (`app.py:4704-4705`) is S10's R-PE-110 (Write file is a Patch Editor action). |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D8-13 | R-CDFX-001 … 015, 017, 018: the CDFX flow, deleted with the `cdfx/` package in batch-07; several name tests that are gone. | Delete from the requirements (not used). They stay in the batch-03 records. R-CDFX-016 is S10's. |
| D8-14 | R-MEM-001 … 005: the v1 memory-change list, container, export. Superseded; what survived is in R-CHG rows. | Delete. The hex/ASCII/decimal display helper (`changes/display.py`) survives, used only by the diff report: its rows go to S14. |
| D8-15 | Process records: batch narratives, the emitter-location design note, engine-frozen guards, "A-5 surface reachability", function signatures, return tuples, "headless, no Textual", test lists, R-S19-SAVE-REUSE-001's "no new write surface". | Out of the requirements; they stay in the batch records. |
| D8-16 | `ChangeSummary.to_dict` and `CheckRunResult.to_dict` (`changes/model.py:482`, `:773`) have no caller outside tests; the code itself says so for the second. | Delete both and their tests (not used). |
| D8-17 | The apply handler's `<kind> save-back not supported` status (`app.py:3561`) cannot be reached: a session with no primary has no range, so no entry is applied. | Delete the branch. |
| D8-18 | The writers raise on a width other than 16/32 and on header data over 252 bytes. These guard callers, not the operator. | Keep in the code; no requirement. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D8-20 | `version` is never checked (`io.py:740-796`): any version reads as v2. | Refuse a version other than `2.0` with `CHG-VERSION-UNKNOWN` (R-CHG-VER.1). |
| D8-21 | The address check uses `^…$` with `match` (`io.py:270`, `:1157`), so `"0x10\n"` passes and reads as 0x10. | Match the whole text (R-CHG-001.29). |
| D8-22 | The Patch Editor loads and pastes with no declared A2L (`app.py:5691`, `:3516`), so every symbol entry is refused even with an A2L loaded. HLR-141 (S0) asks for A2L symbol references from the Patch Editor too. | Declare the loaded A2L (R-CHG-SYM.9); with none loaded, refuse as today (R-CHG-SYM.10). |
| D8-23 | A load with a file defect shows `Loaded : 0 entries, 1 error(s)` (`change_service.py:1599`). | `Change file not loaded: <e> error(s)` (R-CHG-001.20). |
| D8-24 | In a MAC-only session the image has an empty range list (`app.py:11535` on a MAC load, `:1418` after a primary unload), so apply says `skipped-outside` for every entry. | Treat a session with no primary as no image: `skipped-no-image` (R-CHG-002.11). |
| D8-25 | A blocked apply only says `Apply: 0 applied, 0 skipped, <n> blocked` (`app.py:3552`): no reason. | Name the reason (R-CHG-002.5, .6). |
| D8-26 | S1 D-2 asked. A record with a wrong checksum keeps its bytes in the image (S1 R-VAL-001a); the save-back writes them with new, valid checksums (`io.py:1857-1862`), silently. Refusing would also block the repair of such a record by a patch. | Write, and warn naming the count and the first invalid range (R-CHG-003.22). |
| D8-27 | At width 16 the save-back writes an empty S0 (`app.py:3696-3697`), dropping the source's; HLR-153 (batch-99, newer) says the source S0 is always kept. | Keep the source S0 at both widths (R-S19-S0HEADER-001.1); synthesize only at 32 when the source has none (.2, .3). |
| D8-28 | The synthesized header uses the name as typed (`app.py:3693-3695`), for example `..\x` or a name without suffix, not the name written. | Use the written file name (R-S19-S0HEADER-001.2). |
| D8-29 | Every S19 terminator is written with address 0 (`io.py:1823`); the source's start address (`LoadedFile.entry_point`, `load_service.py:65-68`) is lost. A flasher that uses it starts at 0. | Write the source's terminator address on save-back (R-S19-EMIT.11); other writers keep 0 until their groups decide (S11, S13, S15, S17). |
| D8-30 | The save-back name check has its own device list (`apply.py:111-115`): no COM0, LPT0, CONIN$, CONOUT$, no ¹ ² ³. The shared rule (`workspace.py:1803`) has them all. | Use the shared rule (R-CHG-003.13). Conflict surfaced: the shared rule is newer and tested (LLR-164.1). |
| D8-31 | Verify compares bytes only (`verify.py:163-165`): a written file whose records fail their checksum would still be `verified`. | `mismatch` when the read-back gives any diagnostic or integrity notice (R-HEX-VERIFY-001.5). |
| D8-32 | The mismatch notice says `changed 1 run / 1 byte, only_a 0 run / 0 byte, only_b …` (`app.py:4515-4521`): internal tokens, no plural. | The mismatch summary of CTX-VERIFY (R-HEX-VERIFY-002.5). |
| D8-33 | The finding code `CHG-HEX-SAVE-UNSUPPORTED` (`apply.py:98`) now refuses non-HEX sources (MAC). | Rename it `CHG-SAVE-UNSUPPORTED` (R-CHG-003.16). |
| D8-34 | The save suffix splits the document by "applied in the last apply" (`change_service.py:2168-2178`), so an entry that is outside is named under "includes … not applied before this save", though the file does not hold it. | Name only entries the saved image holds (R-CHG-003.23). |

**Prototype first** (visual; prototype round with real captures and your verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D8-40 | The save-back prompt shows `Width: 32 bytes/line` for an Intel HEX image (`screens_directionb.py:5080`), where it changes nothing (R-S19-SAVE-REUSE-001.1). | Hide, disable or relabel the Width control for an Intel HEX image. |

**Passed to other groups**

- **S0**: HLR-153 statement 2, the save-back parts of HLR-155 / HLR-157, LLR-141.1 (reader part), LLR-153.3 / .4, LLR-157.1 / .4 are restated in S8 rows (D8-3, D8-5, D8-6); S0 drops them in its review.
- **S1**: the verify-mismatch notice shows a name derived from the loaded file: add it to the safe-text views. Answer to D-2: D8-26 (write and warn).
- **S5**: save-back placement uses S5's same-content and numbered-name rules (R-TUI-006.1, .2); with no project the saved image lands at the work-area root, which the Workarea Files list does not show (D8-1); batch-100 keeps the list to `temp/` on purpose, so the image is reloaded by its typed path (S5 D5-43).
- **S9**: check documents share CTX-CHGDOC and the linkage rule (R-CHG-LINK.3); `CheckRunResult.to_dict` goes (D8-16).
- **S10**: `ChangeService.add_symbol_entry` has no UI caller (the symbol input of LLR-141.2 is not wired); the Patch Editor declaration-fault list shows file-derived text (symbol, kind) and should join S1's safe-text views; the Width control round (D8-40); R-PATCH-PASTE-001 uses R-CHG-001.1. Conflict to settle: S10's R-PE-084 keeps the `<file kind> save-back not supported` status that D8-17 finds unreachable (delete it there too); S10's R-PE-085 restates R-HEX-VERIFY-002.3 (suggested name) — keep one, here (S8 owns R-HEX-VERIFY-002).
- **S11**: Save project writes the image through S8.7 (width 32, source S0) and verifies through S8.8; decide its terminator address (D8-29). D11-33 (batch save-back keeps the S0) agrees with D8-27.
- **S13**: the CRC write uses the S19 writer (S8.7) and the verify (S8.8); R-CRC-WIDTH-001 stays S13's; decide its terminator address (D8-29).
- **S14**: `changes/display.py::format_memory_value` is used only by the diff report: its rows go there. The before/after report offered after a save-back (`app.py:3729-3734`) is S14's.
- **S15**: the flow declares the A2L for symbol entries (R-CHG-SYM.2 … .4); WRITE-OUT writes through S8.7 and verifies (LLR-155.6).
- **S17**: export writes through S8.7 with an empty S0 even when the source has one (HLR-153 statement 2 was addressed to S8/S17) and terminator address 0 (D8-29).

---

**Received from later groups** (after all groups were written)

- S8.1 (S9: containment, linkage, finding codes, wire form, the apply gate for a check document; `.chk.json`) → covered by CTX-APPLY, R-CHG-LINK.1 … .6, CTX-FINDING, CTX-CHGDOC, R-CHG-002.3, .6; the `.chk.json` suffix stays S9 R-CHKED-030 (D9-14).
- S8.2 (S10: the example text and the per-entry JSON read) → rows R-CHG-001.43, .44.
- S8.3 (S11: Save project writes through S8.7 and verifies through S8.8; terminator) → covered by S11 R-PROJ-IMAGE.6 … .9, which cite S8.7 and S8.8; the terminator is S11 D11-42; D11-33 agrees with D8-27.
- S8.4 (S13: the CRC write) → covered by S13 R-CRC-RECWIDTH-001.4, R-CRC-WRITE-001.17, .18 (D13-28).
- S8.5 (S15: WRITE-OUT) → covered by S15 R-FLOW-WRITE.1, .4, .6 (D15-14).
- S8.6 (S17: export S0 and terminator) → covered by S17 R-SEG-OUT.14 (D17-33) and D17-8; the export writes 32 data bytes per record (R-S19-EMIT.7) and has no Width control.
- D8-29 is now answered by every whole-image writer: the source's terminator address is kept by save-back (R-S19-EMIT.11), Save project and the batch save-back (S11 D11-42), the CRC write (S13 D13-28) and WRITE-OUT (S15 D15-14); Split / Join / Export keeps 0 (S17 D17-8).

**Reconciled with batch-100 (s19_app 570b4b5)**

- Rows added: none. Rows retired: none.
- Cells changed (cites only, no text change): R-PATCH-SAVE-FOLDER-001.5, .6 (LLR-163.3 arms, D8-36); R-S19-WIDTH-001.1 (LLR-015.3, D8-35); R-CHG-003.8, .19, .20 (TC-B100-19 arms, D8-37).
- Cells re-checked at 570b4b5, unchanged: every S8.6 row (the save-back handler changed only by the active-variant tail and the busy check, D8-37); S8.1 … S8.5 code (`changes/`, `change_service.py`) did not change.
- Decisions added: D8-35, D8-36, D8-37. Decisions superseded: none.
- Passed (scratch `passed-sweep.md`): S11 (the save-back's active-variant rows and the Save project width half of LLR-015.3), S5 (a successful save-back records the image as saved, so a later image load asks nothing).
- Consolidation (items from S5, S11): R-CHG-003.8, D8-37 and D8-35 name the S11 rows (R-PROJ-SAVEBACK.1 … .3, R-PROJ-002.10; R-PROJ-IMAGE.7, .8, .11); the "Passed to other groups" bullet for S5 points to S5 D5-43 (the Workarea Files list stays `temp/`). No row text changed.

## 6. Counts

| | Old S8 | Strict |
|---|---:|---:|
| Requirement statements | 33 rows (22 historical, 11 active) + 1 amendment block + 1 design note | 170 rows |
| Statements the code contradicts or that are not product behaviour | 27 (22 historical; R-CHG-001 "no symbolic field"; R-CHG-003 destination and S19-only; R-S19-S0HEADER-001 vs HLR-153; R-S19-SAVE-REUSE-001 no behaviour; R-PATCH-SAVE-FOLDER-001 homes) | 0 |
| Rows by form: U / When / While / If / Where | — | 9 / 84 / 0 / 77 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 37 (15 follow the code or move, 6 remove, 15 correct a defect, 1 prototype first; numbers not contiguous) |

Checked by script: one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.
