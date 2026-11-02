# Inc 8 — E3 code-free design review (architect)

Base `5aac5c9` (records) on code `e266395`. Reviewer: architect (Opus), read-only. Read: `01-requirements.md`, `E1-rulings.md` (with the orchestrator rulings), `E1-slice.md`, `02-test-cases.md`, `codewire/graph-inc8.md`, the canon rows cited in `REQUIREMENTS.md`, and the code in scope and its callers.

**Verdict: FAIL** — 2 MAJOR, 0 BLOCKER/HIGH. The CRC fix, the template refusal and the D-2 decision are sound. Both MAJORs are about the flow rebind and are cheap to fix in the records (one row, two cases). Once they are fixed and the MINORs go to E4 as addenda, this review would pass.

## 1. The CRC model claim (D13-20): verified independently

I wrote my own implementation of the Rocksoft parametric model in the session scratchpad (`e3arch/kat.py`): a direct MSB-first register seeded with `init` as given, with input and output reflection. As a second check I also wrote a right-shift reflected form. Both use the s19env interpreter and import nothing from the project.

| Check | Result |
|---|---|
| Catalogue checks on "123456789": ARC 0xBB3D, MODBUS 0x4B37, RIELLO 0x63D0, TMS37157 0x26B1, ISO-HDLC 0xCBF43926, MPEG-2 0x0376E6E7, BZIP2 0xFC891918, JAMCRC 0x340BC6D9, CD-ROM-EDC 0x6EC2EDC4 | 9/9 equal. The right-shift form agrees on all 7 reflected ones. RIELLO and TMS37157, the reflected algorithms whose init is not bit-symmetric, settle it: init is **not** reflected (CTX-CRC `REQUIREMENTS.md:5319`) |
| Config K (init 0x12345678, reverse true, xorout 0xFFFFFFFF) | model 0x0F8B7431; model with the bit-reversed init 0x18026B2A |
| Base `crc32_stream`, imported from the worktree (`…/s19_app-b101-inc8/s19_app/tui/operations/crc.py`) | 0x18026B2A (it confirms the defect) |
| init 0x00000001 / 0x80000000, reverse true, xorout 0 | 0x334D3950 / 0x3A8639CB (as in the graph) |
| init 0xB2AAB2AA, reverse true, xorout 0 | new 0x6679B987, base 0x7C7DCA7E (as in the graph) |
| 24-set grid of R-CRC-ENGINE-002.2/1 | 8 of 24 differ between base and model (as claimed) |
| 300 random sets (data 0–199 B, random poly/init/xorout/reverse) | base `crc32_stream` = model with the bit-reversed init **300/300** (the D-3 migration is exact); `crc_kernel.crc_stream` = model **300/300** |
| 0x0FF00FF0 bit-symmetric | yes (example in the definition is correct) |

The fix in D-6 (seed `init & _MASK32` for both values of `reverse`) is correct and minimal. The zlib fast path is gated on `init == 0xFFFFFFFF`, which is bit-symmetric, so it is unaffected.

## 2. Callers of `crc32_stream`: which outputs change

The only callers are `compute_region_crc` (`crc.py:335`) and `compute_group_crc` (`crc.py:544`). Their only product caller is `check_regions` (`crc.py:906`), which feeds three routes:

| Route | Output that changes (only reverse=true with a non-bit-symmetric init) | Unchanged |
|---|---|---|
| Operations CRC check: `CrcOperation.execute` → `check_regions` (`crc.py:1702`) → `screens.py:3329` region lines | `computed 0x…`, so the MATCH / MISMATCH verdict | `crc_diagnostics` notes (counts and addresses only) |
| Operations CRC write: `screens.py:3471` → `write_crc_image` (`crc.py:1458`) → `inject_crcs` | the written field bytes in the saved image | refusals, write texts |
| Flow CRC block: `flow_execution_service.py:835`, and through `run_flow` also chain sets and fused runs | injected bytes, hence WRITE-OUT images, downstream CHECK results and A2B reports | block summary `injected <n> CRC region(s)` |

- `OperationResult.to_dict` (`model.py:342`) serializes `computed_crc`, but no product path persists it.
- The CRC Designer (`crc_kernel`) and its flat-config job path (`crc_designer_model._upconvert_flat_algorithm`, `:579-618`, `init` as given) already follow the model. After the fix the two engines agree on the same config file.
- Tests: every init in `tests/` and `examples/` is 0x0, 0x0000, 0xFFFF or 0xFFFFFFFF. 0xB704CE is a Designer preset, not the operation engine. No existing test or golden changes value. E1 §4 is confirmed.

## 3. D-2: rebind vs rotate — **rebind upheld**

- Rotate renames a placed file. That breaks the invariant `workspace.py:1112-1115` relies on for race-freeness ("no in-app writer replaces or deletes a placed file", LLR-155.3/LED .7). It also adds a writer to `workspace.py`, a file shared by 15 call sites, and retroactively re-points every earlier report that names the output file name. Overwrite is worse on every count.
- Rebind adds no writer. It matches the model contract (`flow_model.py:487`, "downstream blocks reference THAT copy"). It is per-run state, and every confirmed run re-copies (reuse or claim), so the binding is always rebuilt from the current output.
- Key consistency checked:
  - `place_into_workarea` claims `resolved_source.name` unchanged (`workspace.py:1201`, `:1231`), with no sanitising.
  - The destination and `_resolve_manifest_entry` are both `.resolve()`d, so one `normcase(str())` key compares like with like.
- `R-FLOW-EXT.11` correctly pins the decision.
- Two consequences of rebind are not yet in the records or the reports. They are findings F-1 and F-2 below.

## 4. Do R-FLOW-EXT.10 / .11 (and D15-17) change a report or golden that a test pins? **No.**

Rebind fires only when the copy lands on a name other than the output file name. Every existing confirmed external-step run copies onto the plain name:
- `test_flow_external_step_b96.py:293/328/341` → `salida.s19`
- `test_b97_flow_execution.py:147` → `flashed.s19`
- the FX `flash_chain` fixture → `b97_fixtures.py:625`. Its output lies inside the project, so placement reuses the file itself.

The `chg_0_1.json` / `chk_1.json` names in `tests/goldens/batch64` are unrelated save-folder names. No test asserts `structurally invalid` (grep over `tests/`).

D15-17: every confirmed run in `tests/` uses an absolute output. The relative outputs (`test_b97_flow_builder.py:115`, `test_flow_external_step_b96.py:109`, `test_flow_funnel_b96.py:353`, `HOSTILE_NAME`) appear only in builder, persistence and copy-paste tests that never confirm.

## 5. Findings

| Id | Severity | Row / node | Finding | Proposed fix |
|---|---|---|---|---|
| A-1 | MAJOR | R-FLOW-EXT.10, I-4, `run_flow` PATCH branch | When an A2L is read in place, the report still names the typed A2L ref. R-FLOW-EXT.9/12 puts A2L rebinding in scope, but the change record's `a2l_ref` stays `effective_a2l_ref = block.a2l_ref or source_a2l_ref` (`flow_execution_service.py:366`, `:497`, `:503`, `:520`). The flow report prints it in its A2L column (`flow_report_service.py:355`). So the report names `cal.a2l` while the addresses came from `cal_1.a2l`: the same report-integrity defect R-FLOW-EXT.10 fixes for the change document, and D-2's own argument. | Extend R-FLOW-EXT.10 to "the change document and the A2L". Record `a2l_ref` = the copy's name when that A2L (the PATCH's own, or the SOURCE block's it inherits) was read in place. Add a case R-FLOW-EXT.10/4 (flow report A2L cell names `cal_1.a2l`) and extend I-4 to name `a2l_ref`. |
| A-2 | MAJOR | R-FLOW-EXT.9 (Base column, "What changes"), `02-test-cases.md` | Rebind also changes the **first** run, and the records do not admit it. Case: the project already holds a different file under the output file name. On base, the copy lands as `_1` and later blocks read the pre-existing file; with Inc 8 they read the copy. The Base column says only "run 2 …", and no case covers this. For CHECK and CRC blocks, the in-place read shows in no block summary (`passed=… failed=…`, `injected n CRC regions`) and in no report. Only the EXT summary's copy name hints at it. | (a) Admit it in the R-FLOW-EXT.9 Base column and in "What changes for an operator". (b) Add case R-FLOW-EXT.9/13: a pre-existing `step.changes.json` with Doc(`CC`), first run with Doc(`AA`), copy `_1`, out.s19 holds `41 41`. (c) Orchestrator option for visibility, not required for PASS: when the copy name differs from the output file name, the EXT summary adds ` - later blocks read it for <output file name>`. That changes R-FLOW-EXT.7 only for that case, which no existing test pins (§4). |
| A-3 | MINOR | R-CRC-ENGINE-001.1/5, /6 | /5's expected result quotes the Operations region line, which `screens.py:3329` builds, but its input is the bare `check_regions`. /6 calls `inject_crcs` instead of the Operations write route `write_crc_image` (`screens.py:3471`). Under E4's "full" rule both are partial. | /5: drive the Operations dialog, or assert `computed_crc` only. /6: call `write_crc_image` and read the written bytes. |
| A-4 | MINOR | R-CRC-CONFIG-001.11 (status "canon") | `_number_field` keeps `_parse_int` = `int(s, 16)`, which accepts strings that are not CTX-CRCCONFIG numbers ("hexadecimal digits with or without 0x"). Probed: `" 10 "`, `"+10"`, `"1_0"`, `"0x_1"` → accepted; `"-1"` → -1. "The code is brought to the row" overclaims. | Record the residual on the row ("named reasons only; the lenient string grammar stays") and add it to the D13-21/22/24 backlog family. Do not widen this increment. |
| A-5 | MINOR | Definition "Designer template shape", R-CRC-CONFIG-001.16 | The shape (`algorithm` present, no `polynomial`) also matches the evolved CRC job shape that `crc_designer_model.emit_job` writes (`algorithm` + `targets`). For that shape "it has no regions or groups" is misleading, and an `algorithm_ref` job falls to `field 'reverse' is missing`. Not reachable today: `emit_job` / `parse_job` have no caller in `s19_app/` outside the model. | Note it as a known limit under D-1. No row change. |
| A-6 | MINOR | CTX-CRCCONFIG (C-2 edits it) | The pre-existing line "rule texts — The <rule text> of R-CRC-CONFIG-001.10" (`REQUIREMENTS.md:5398`) points at the wrong row: `<rule text>` is used by R-CRC-CONFIG-001.9. | Correct the cross-reference to .9 in the same C-2 edit. |
| A-7 | MINOR | BL-I8-3 | The guide still shows the F-28 base text at `docs/user-guide/ch17-flow-builder.md:62` (`… structurally invalid: 'reverse'`), and `docs/user-guide/DOSSIER.md:737`, `:758` list F-28 / F-49 as live. BL-I8-3 names only ch17.11 / ch18.9. | Add ch17:62 and the two DOSSIER rows to BL-I8-3. |
| A-8 | MINOR | R-FLOW-EXT.9 "the same run" | "Run" is undefined for a chain set: one Run press executes several chains, one `run_flow` each (`run_chain_set`). A later chain that names an earlier chain's output is not rebound. | Add to the C-4 terms: *run* = one flow's execution (one chain). Say that cross-chain refs are not rebound (with F-48). |

Notes, not findings:
- O-1 (no read limit on the Flow CRC config read) and O-2 (`<value>` has no length bound) belong to the security reviewer's lens. I agree with deferring O-1 as BL-I8-5.
- R-CRC-ENGINE-002.2 follows logically from R-CRC-ENGINE-001.1 plus R-CRC-DESIGNER-001.1. It is kept as an engine-agreement test, which is acceptable.

## 6. Other checks (no finding)

- **Slice.** The 7 resolutions (`:315`, `:345`, `:427`, `:448`, `:734`, `:798`, `:942`) are all the read-refs in `run_flow`. `_chain_inputs` correctly stays out of scope. 3 source files.
- **Interfaces.**
  - Inc 7 (`diff_report_service.py:1166`, `:1243`) and Inc 9 (`flow_execution_service.py:1983`) only print `change_doc_ref`. The `_md_cell` / `md_safe` escaping applies unchanged, and the census check at `:1243-1253` stays self-consistent.
  - The A2B file input shows the copy through `path.stem` / `path` on its own (`:977-983`), which is consistent with rebind.
- **Template refusal.**
  - The Designer saves into the project's `templates/` (`crc_designer_view.py:1248-1257`), so F-28 reaches R-FLOW-CRC.4 and not R-FLOW-CRC.3. The AT route is sound.
  - `parse_crc_config` already turns `ValueError` into `structurally invalid: <exc>` (`crc_config.py:440-443`).
  - `_parse_int` raises only `ValueError` (`:221-227`), so `_number_field`'s single `except ValueError` covers bool, float and None.
- **D-3, D-5, D-6, D-7.** Upheld. D-3 is a one-way door for deployed configs and is flagged as one. Its exact migration is verified (300/300).
- **Arithmetic.** The S19 records in the cases were checked by hand: `S107100001020304DE`, `S1071000414103045F`, `S1071000424203045D` have valid checksums. LE bytes `31 74 8B 0F` = 0x0F8B7431.

## Evidence checklist

- ✓ Constraints: from `E1-rulings.md` §1 (no UI work, cap 4 source files, P0 ruling). No new ones.
- ✓ Alternatives where a real decision exists: D-2 (rebind / rotate / overwrite) re-checked against `workspace.py:1112-1115` and `flow_model.py:487`. D-1, D-6 checked.
- ✓ Recommendation tied to constraints: §3.
- ✓ Risks: A-1, A-2 (report integrity, first-run collision); D-3 one-way door.
- ✓ Cost / latency: n/a, because the seed fix leaves the loop cost unchanged and rebind is one dict lookup per resolved ref.
- n/a Diagram: no new flow; the graph's edges suffice.
- ✓ What would change the rebind call: a requirement that the folder look "current" by file name (the rotate advantage), or F-48's explicit version refs landing first.
- ✓ Two-layer requirements: each US has rows and cases; ATs R-CRC-CONFIG-001.16/5, R-FLOW-EXT.9/11 present.
- ✓ CRC KAT: executed (scratchpad `e3arch/kat.py`, `e3arch/base_probe.py`; s19env Python; worktree import confirmed by `__file__`).
