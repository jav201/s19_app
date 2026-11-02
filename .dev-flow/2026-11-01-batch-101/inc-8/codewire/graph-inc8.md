# Code-Wire graph — Inc 8 (Flow CRC block and CRC configs, CRC init with reverse, external-step outputs), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `e266395`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (`<HOME>/Github/code-wire/docs/Notation-Grammar.md`), as in `../../inc-2/codewire/graph-inc2.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Context nodes (unchanged) are here because a changed node calls them, or because their examples are the oracle of a row.
- Example sources are the test-case ids of `02-test-cases.md`; `B` = a probe of the base tree run at E1 from the session scratchpad. Every example states the Inc 8 target unless it says "holds on base".
- `<proj>` = `<tmp>/.s19tool/workarea/proj` (fixture flow X of `02-test-cases.md`). KAT = the 9 bytes `123456789`.

### Oracle of the CRC model (D13-20)

> The model of CTX-CRC (Williams "Rocksoft" parametric model, the one the reveng catalogue uses): the register starts at `init` as written; `refin` reverses each input byte; `refout` reverses the register before `xorout`. Checked at E1 three ways on the KAT message: the Designer engine `crc_kernel.crc_stream`, an independent right-shift implementation whose register starts at the bit-reversed init (the same model, written the other way round), and the published catalogue check. All three agree for CRC-16/ARC 0xBB3D, CRC-16/MODBUS 0x4B37, CRC-16/RIELLO 0x63D0, CRC-16/TMS37157 0x26B1, CRC-32/ISO-HDLC 0xCBF43926, CRC-32/MPEG-2 0x0376E6E7, CRC-32/BZIP2 0xFC891918, CRC-32/JAMCRC 0x340BC6D9, CRC-32/CD-ROM-EDC 0x6EC2EDC4.
> RIELLO and TMS37157 are the catalogue's reflected algorithms with an init that is not bit-symmetric, so they decide the question: under the model, init is **not** reflected. Every 32-bit reflected catalogue algorithm has init 0 or 0xFFFFFFFF, which is why no shipped preset or test showed D13-20.
> The operation engine (`crc.py:211`) seeds `_reflect(init, 32)` when `reverse` is true, which equals the model with the bit-reversed init (B: 200/200 random inputs). That is the wrong result, and also the exact way to reproduce an old result (`E1-rulings.md` D-3).

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G1 CRC | `s19_app/tui/operations/crc.py`, `s19_app/tui/operations/crc_config.py`; tests `tests/test_b101_crc_model_and_reasons.py` | `crc32_stream`, `_required_field`, `_number_field`, `_build_config`, `_build_group`, `parse_crc_config` |
| G2 Flow | `s19_app/tui/services/flow_execution_service.py`, `s19_app/tui/services/flow_model.py` [S-2]; tests `tests/test_b101_flow_ext_copy.py` | `run_flow`, `_resolve_block_ref`, `run_chain_set`, `compose_chain_set_report`, `[Data: FlowRunResult.in_place_reads]`, `[Data: ChainRunOutcome.in_place_inputs]` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 template reason | `crc_config.DESIGNER_TEMPLATE_RULE = "a CRC Designer template is not a CRC config - it has no regions or groups"`; reaches callers as `CRC config is structurally invalid: <rule>` through `parse_crc_config` | G1 → G2 (R-FLOW-CRC.4 cause), the Operations dialog |
| I-2 named-field reasons | `field '<key>' is missing`; `field '<key>' is not a number: <clip>` with `<clip>` = `json.dumps(value)` cut to 64 characters + `…` when longer (`crc_config.VALUE_CLIP = 64`) [S-1]; `CRC config is not valid JSON: nesting too deep` [S-6] | G1 → G2, the Operations dialog |
| I-3 engine call form | `crc32_stream(data, *, polynomial, init, reverse, final_xor) -> int` unchanged; only its value changes | G1 → `compute_region_crc`, `compute_group_crc` (Operations check / write, Flow CRC block) |
| I-4 change-record values [A-1] | `FlowChangeRecord.change_doc_ref` / `FlowRefusal.change_doc_ref` = the copy's file name (`copy.name`) when the PATCH document was read in place, else the block's ref as typed; `FlowChangeRecord.a2l_ref` / `FlowRefusal.a2l_ref` = the copy's file name when the effective A2L (the PATCH's own `a2l_ref`, or the LOAD's it inherits) was read in place, else as today (`block.a2l_ref or source_a2l_ref`) | G2 → flow report (Change document and A2L reference columns, `flow_report_service.py:355`), chain-set report (Inc 9 edits `run_chain_set` / `write_chain_set_report` after Inc 8), flow-A2B change census (`diff_report_service.py`, Inc 7) |
| I-5 placement | `copy_into_workarea(source, destination) -> Path` unchanged (D-2: no rename, no overwrite) | `workspace.py` (not edited) → G2 |
| I-6 in-place reads [S-2] | `FlowRunResult.in_place_reads: List[Tuple[int, str, str, Path]]` — (block index, resolution label such as `SourceBlock.image_ref`, typed ref, copy), default `[]`, in read order; `ChainRunOutcome.in_place_inputs: Dict[int, str]` — 1-based input index → copy file name, default `{}` | `run_flow` → the summary suffix (same function), `run_chain_set._run_one` → `compose_chain_set_report`. Inc 9 works in `run_chain_set` / `write_chain_set_report` after Inc 8 and must keep both fields |
| I-7 read suffix [A-1, A-2, S-2] | `" · read " + copy.name + " in place of " + ref` (ref as typed), appended to the block's summary once per in-place read | G2 → every surface that paints a block summary (lane terminal line, run log, flow report Pipeline ledger) |

Order inside E4: G1 and G2 in parallel; G2's R-FLOW-CRC.4 / .9 tests need G1's I-1 / I-2 at integration.

## Nodes

crc32_stream
req: R-CRC-ENGINE-001.1, R-CRC-ENGINE-002.2
in: bytes data; int polynomial = 0x04C11DB7; int init = 0xFFFFFFFF; bool reverse = True; int final_xor = 0xFFFFFFFF
out: int crc
func: changed. was: default parameters → `zlib.crc32`; else the register starts at `_reflect(init, 32)` when `reverse`, at `init & 0xFFFFFFFF` otherwise; MSB-first division with each byte reflected when `reverse`; the register reflected when `reverse`; XOR `final_xor`. / now: the same, except the register starts at `init & 0xFFFFFFFF` for both values of `reverse` (CTX-CRC: init not reflected).
module: s19_app/tui/operations/crc.py
oracle: REQUIREMENTS.md CTX-CRC "parametric model" (init: register value before the first byte, not reflected); reveng CRC catalogue check values (see the oracle note above)
examples: (R-CRC-ENGINE-001.1/1) data "123456789", polynomial 0x04C11DB7, init 0x12345678, reverse `True`, final_xor 0xFFFFFFFF → crc 0x0F8B7431 (base 0x18026B2A, B)
examples: (R-CRC-ENGINE-001.1/2) data "123456789", polynomial 0x04C11DB7, init 0x00000001, reverse `True`, final_xor 0x00000000 → crc 0x334D3950 (base 0x3A8639CB, B)
examples: (R-CRC-ENGINE-001.1/2) the same with init 0x80000000 → crc 0x3A8639CB (base 0x334D3950, B: the base engine swaps the two)
examples: (R-CRC-ENGINE-001.1/3) data "123456789", polynomial 0x04C11DB7, init 0xFFFFFFFF, reverse `False`, final_xor 0x00000000 → crc 0x0376E6E7 (CRC-32/MPEG-2; holds on base)
examples: (R-CRC-ENGINE-001.1/4) data "123456789", polynomial 0x04C11DB7, init 0xFFFFFFFF, reverse `True`, final_xor 0x00000000 → crc 0x340BC6D9 (CRC-32/JAMCRC, loop path; holds on base)
examples: (R-CRC-ENGINE-002.1, holds on base) data "123456789" with the defaults → crc 0xCBF43926 (zlib fast path, unchanged)
examples: (R-CRC-ENGINE-002.2/1) init 0xB2AAB2AA, reverse `True`, final_xor 0x00000000 → crc 0x6679B987 = `crc_stream` width 32, refin/refout `True` (base 0x7C7DCA7E, B)
examples: (R-CRC-ENGINE-001.1/1 neg) mutant: register starts at the reflected init → 0x18026B2A → RED

crc_stream
req: R-CRC-DESIGNER-001.1, R-CRC-ENGINE-002.2
in: bytes data; int width; int poly; int init; bool refin; bool refout; int xorout
out: int crc
func: unchanged. The CRC Designer's engine and the model's reference: the register starts at `init & mask`; MSB-first division; byte reflected when `refin`; register reflected when `refout`; XOR `xorout`. `crc_lut` is its table form (equal results, `tests/test_crc_kernel.py`).
module: s19_app/tui/operations/crc_kernel.py
oracle: reveng CRC catalogue (check = CRC of "123456789")
examples: (R-CRC-DESIGNER-001.1/1) data "123456789", width `16`, poly 0x8005, init 0x0000, refin `True`, refout `True`, xorout 0x0000 → crc 0xBB3D (CRC-16/ARC; holds on base)
examples: (R-CRC-DESIGNER-001.1/2) width `16`, poly 0x8005, init 0xFFFF, refin `True`, refout `True`, xorout 0x0000 → crc 0x4B37 (CRC-16/MODBUS; holds on base)
examples: (R-CRC-DESIGNER-001.1/3) width `16`, poly 0x1021, init 0xB2AA, refin `True`, refout `True`, xorout 0x0000 → crc 0x63D0 (CRC-16/RIELLO; holds on base)
examples: (R-CRC-DESIGNER-001.1/4) width `16`, poly 0x1021, init 0x89EC, refin `True`, refout `True`, xorout 0x0000 → crc 0x26B1 (CRC-16/TMS37157; holds on base)
examples: (R-CRC-DESIGNER-001.1/5) width `32`, poly 0x04C11DB7, init 0xFFFFFFFF, refin `True`, refout `True`, xorout 0xFFFFFFFF → crc 0xCBF43926 (CRC-32/ISO-HDLC; holds on base)
examples: (R-CRC-DESIGNER-001.1/6) width `32`, poly 0x04C11DB7, init 0xFFFFFFFF, refin `False`, refout `False`, xorout 0x00000000 → crc 0x0376E6E7 (CRC-32/MPEG-2; holds on base)
examples: (R-CRC-ENGINE-002.2/1) width `32`, poly 0x04C11DB7, init 0x12345678, refin `True`, refout `True`, xorout 0xFFFFFFFF → crc 0x0F8B7431 (the value `crc32_stream` must give)

check_regions
req: R-CRC-ENGINE-001.1
in: OperationInput op_input; CrcConfig config
out: list[CrcRegionResult] crc_regions
func: unchanged. One result per target in target order: computed CRC (through `compute_region_crc` / `compute_group_crc` → `crc32_stream`), stored value, verdict. The Operations CRC check and the Flow CRC block both call it.
module: s19_app/tui/operations/crc.py
examples: (R-CRC-ENGINE-001.1/5) image "123456789" at 0x1000 … 0x1008, Config K (init 0x12345678, reverse `True`) → one region, output address 0x1010, computed 0x0F8B7431, no stored value (base computed 0x18026B2A, B)

inject_crcs
req: R-CRC-ENGINE-001.1
in: OperationInput op_input; list[CrcRegionResult] crc_regions
out: tuple(dict mem_map, list ranges, list written_regions)
func: unchanged. Builds a working copy of the image and writes each target's field value, low byte first, growing the ranges when the field lies outside them. The Operations CRC write and the Flow CRC block both call it.
module: s19_app/tui/operations/crc.py
examples: (R-CRC-ENGINE-001.1/6) the regions of the /5 example → mem_map 0x1010: 0x31, 0x1011: 0x74, 0x1012: 0x8B, 0x1013: 0x0F

_required_field
req: R-CRC-CONFIG-001.10
in: dict container; str key
out: Any value
func: new. Returns `container[key]`; a missing key raises `ValueError("field '<key>' is missing")`.
module: s19_app/tui/operations/crc_config.py
examples: (R-CRC-CONFIG-001.10/1) container = Config V without "reverse", key "reverse" → raises ValueError "field 'reverse' is missing"
examples: (R-CRC-CONFIG-001.10/7) container {"output_address": "0x30"}, key "regions" → raises ValueError "field 'regions' is missing"
examples: (R-CRC-CONFIG-001.10/1 pos) container = Config V, key "reverse" → value `True`

_number_field
req: R-CRC-CONFIG-001.10, R-CRC-CONFIG-001.11
in: dict container; str key
out: int value
func: new. `raw = _required_field(container, key)`; returns `_parse_int(raw)` (unchanged: bool refused, int as is, str as hexadecimal); a `ValueError` from `_parse_int` becomes `ValueError(f"field '{key}' is not a number: {clip}")`, `text = json.dumps(raw)`, `clip = text if len(text) <= VALUE_CLIP else text[:VALUE_CLIP] + "…"`, `VALUE_CLIP = 64` [S-1].
module: s19_app/tui/operations/crc_config.py
examples: (R-CRC-CONFIG-001.11/1) {"init": "zz"}, key "init" → raises ValueError "field 'init' is not a number: \"zz\"" (base text: "invalid literal for int() with base 16: 'zz'", B)
examples: (R-CRC-CONFIG-001.11/2) {"init": true}, key "init" → raises ValueError "field 'init' is not a number: true" (base: "expected an integer, got a boolean", B)
examples: (R-CRC-CONFIG-001.11/3) {"polynomial": 1.5}, key "polynomial" → raises ValueError "field 'polynomial' is not a number: 1.5"
examples: (R-CRC-CONFIG-001.11/4) {"final_xor": null}, key "final_xor" → raises ValueError "field 'final_xor' is not a number: null"
examples: (R-CRC-CONFIG-001.10/3) {} , key "init" → raises ValueError "field 'init' is missing"
examples: (R-CRC-CONFIG-001.11/1 pos) {"init": "0x12345678"}, key "init" → value `305419896`; {"start": 4096}, key "start" → value `4096`
examples: (R-CRC-CONFIG-001.11/7) {"init": 1 000 000 × "a"}, key "init" → raises ValueError "field 'init' is not a number: " + `"` + 63 × "a" + "…" (base: CPython's own 200-character clip inside "invalid literal …", security probe)
examples: (R-CRC-CONFIG-001.11/7) {"polynomial": [0] × 10 000}, key "polynomial" → raises ValueError "field 'polynomial' is not a number: " + the first `64` characters of "[0, 0, 0, …" + "…"
examples: (R-CRC-CONFIG-001.11/8) {"init": "[/]"}, key "init" → raises ValueError "field 'init' is not a number: \"[/]\"" (shown as plain text by the Operations result area, `screens.py:2887` `markup=False`)

_build_config
req: R-CRC-CONFIG-001.10, R-CRC-CONFIG-001.11, R-CRC-CONFIG-001.16
in: dict data
out: CrcConfig config
func: changed. was: reads `data["reverse"]` first (a `KeyError` becomes the bare key `'reverse'`), then `regions` / `groups`, the region fields by `raw_region[...]` + `_parse_int`, the groups by `_build_group`, the span ceiling, and last `polynomial` / `init` / `final_xor` by `data[...]` + `_parse_int`. / now: first, when `"algorithm" in data and "polynomial" not in data`, raises `ValueError(DESIGNER_TEMPLATE_RULE)`; then the same order, with `_required_field(data, "reverse")` and `_number_field` for the region fields and for `polynomial`, `init`, `final_xor`. Every other rule text unchanged.
module: s19_app/tui/operations/crc_config.py
examples: (R-CRC-CONFIG-001.16/1) data = the CRC Designer's saved seed template (keys "schema_version", "name", "aliases", "operation", "algorithm") → raises ValueError "a CRC Designer template is not a CRC config - it has no regions or groups" (base: KeyError 'reverse', B)
examples: (R-CRC-CONFIG-001.16/3) data {"algorithm": 5} → raises ValueError "a CRC Designer template is not a CRC config - it has no regions or groups"
examples: (R-CRC-CONFIG-001.16/4) data = Config V plus "algorithm": {"width": 32} → config polynomial `79764919`, reverse `True`
examples: (R-CRC-CONFIG-001.10/5) Config V, region 1 without "start" → raises ValueError "field 'start' is missing" (base: KeyError 'start', B)
examples: (R-CRC-CONFIG-001.11/5) Config V, region 1 "end": "0xQ" → raises ValueError "field 'end' is not a number: \"0xQ\""
examples: (R-CRC-CONFIG-001.10/2) Config V without "polynomial" → raises ValueError "field 'polynomial' is missing" (the region and group checks pass first)

_build_group
req: R-CRC-CONFIG-001.10, R-CRC-CONFIG-001.11
in: int index; Any raw_group
out: CrcGroup group
func: changed. was: `raw_group["regions"]`, `raw_span["start"]`, `raw_span["end"]`, `raw_group["output_address"]` with `_parse_int` (bare key / Python text). / now: `_required_field(raw_group, "regions")`; `_number_field` for span `start`, `end` and the group's `output_address`. `output_bytes`, the span rules, the N6 tripwire and the address-space rules keep their texts and order.
module: s19_app/tui/operations/crc_config.py
examples: (R-CRC-CONFIG-001.10/6) index `0`, {"regions": [{"start": "0x20", "end": "0x24"}]} → raises ValueError "field 'output_address' is missing"
examples: (R-CRC-CONFIG-001.10/7) index `0`, {"output_address": "0x30"} → raises ValueError "field 'regions' is missing"
examples: (R-CRC-CONFIG-001.10/8) index `0`, {"regions": [{"start": "0x20"}], "output_address": "0x30"} → raises ValueError "field 'end' is missing"
examples: (R-CRC-CONFIG-001.11/6) index `0`, {"regions": [{"start": "x", "end": "0x24"}], "output_address": "0x30"} → raises ValueError "field 'start' is not a number: \"x\""
examples: (test_at044d_parse_rejections_one_named_error[output_bytes_nonint], holds on base) "output_bytes": "four" → raises ValueError "group 1: 'output_bytes' must be one of [1, 2, 4, 8], got 'four'"

parse_crc_config
req: R-CRC-CONFIG-001.10, R-CRC-CONFIG-001.11, R-CRC-CONFIG-001.16, R-CRC-CONFIG-001.17
in: str text
out: tuple(CrcConfig? config, list[str] errors)
func: changed [S-6]. was: `json.loads` inside `except (JSONDecodeError, UnicodeDecodeError)` (→ `CRC config is not valid JSON: …`); a `RecursionError` escapes to the caller (the Operations Execute handler, `screens.py:3113`, does not catch it). / now: `RecursionError` is also caught and gives `CRC config is not valid JSON: nesting too deep`. Then the object guard and `_build_config` inside `except (KeyError, TypeError, ValueError)` → `CRC config is structurally invalid: <exc>`, unchanged; the new reasons pass through it.
module: s19_app/tui/operations/crc_config.py
examples: (R-CRC-CONFIG-001.16/1) text = `emit_template(seed_template())` → config `None`; errors ["CRC config is structurally invalid: a CRC Designer template is not a CRC config - it has no regions or groups"] (base ["CRC config is structurally invalid: 'reverse'"], B)
examples: (R-CRC-CONFIG-001.10/1) Config V without "reverse" → errors ["CRC config is structurally invalid: field 'reverse' is missing"]
examples: (R-CRC-CONFIG-001.11/1) Config V with "init": "zz" → errors ["CRC config is structurally invalid: field 'init' is not a number: \"zz\""]
examples: (R-CRC-CONFIG-001.17/1) text "[" × 100 000 → config `None`; errors ["CRC config is not valid JSON: nesting too deep"] (base: raises RecursionError, security probe)

emit_template
req: R-CRC-CONFIG-001.16, R-FLOW-CRC.4
in: CrcTemplate template
out: str text
func: unchanged. The CRC Designer's Save text: {"schema_version", "name", "aliases", "operation": "crc", "algorithm": {"width", "poly", "init", "refin", "refout", "xorout", "check"}}. The producer of F-28's input (PLAN B4: output-then-consume).
module: s19_app/tui/operations/crc_designer_model.py
examples: (R-CRC-CONFIG-001.16/1) `seed_template()` → text holds "\"algorithm\": {" and no "polynomial"

run_flow
req: R-FLOW-CRC.1, R-FLOW-CRC.3, R-FLOW-CRC.4, R-FLOW-CRC.9, R-FLOW-EXT.2, R-FLOW-EXT.9, R-FLOW-EXT.10, R-FLOW-EXT.11, R-FLOW-EXT.12, R-FLOW-EXT.14, R-CRC-ENGINE-001.1
in: Flow flow; FlowContext ctx
out: FlowRunResult result
func: changed. was: each block branch resolves its refs with `_resolve_manifest_entry`; the PATCH branch records `change_doc_ref=block.change_doc_ref` and `a2l_ref=effective_a2l_ref` (`block.a2l_ref or source_a2l_ref`, `:366`, `:497`); the CRC branch reads its config with `path.read_text` (no limit, `:810-812`); the external-step branch joins a relative log under `ctx.project_dir` but reads a relative output as given (working directory), copies it with `copy_into_workarea` and records the copy only in `written_paths`. / now: (1) a per-run `rebinds: dict[str, Path]` starts empty; (2) the 7 block-branch resolutions (LOAD image and A2L, PATCH document and A2L, CHECK document, CRC config, A2B file inputs) go through `_resolve_block_ref(..., rebinds)`; each in-place read is appended to `result.in_place_reads` as `(index, label, ref, copy)` [S-2]; (3) the PATCH branch records `change_doc_ref = path.name` when its document was read in place, else `block.change_doc_ref`, and `a2l_ref` = the copy's name when the effective A2L was read in place — the PATCH's own (`:448`) or the LOAD's, kept as `source_a2l_ref = copy.name` at `:366` — else as today [A-1]; (4) the external-step branch first refuses a relative log, then a relative output, that climbs above the project folder (summary `external step refused`, cause `<log or output> '<path as given>' climbs above the project folder - give an absolute path for a file outside the project`, checked by text: `os.path.normpath` of the joined path must stay under `os.path.normpath(project_dir)`) [S-3]; it joins a relative output under `ctx.project_dir` like the log, and after the copy sets `rebinds[os.path.normcase(str(copied.parent / Path(source_path).resolve().name))] = copied`; (5) the CRC branch reads its config with `read_crc_config_text(str(path), ctx.project_dir)`; a read error becomes the R-FLOW-CRC.4 / .9 summary `config malformed` and cause `crc config invalid: <reason>`, else `parse_crc_config(text)` as today [S-5]; (6) once per block, whatever path ended it (normal end, `continue`, the per-block `except`), the block's `BlockResult.summary` gets `" · read " + copy.name + " in place of " + ref` for each of its `in_place_reads`, in read order [A-1, A-2, S-2]. Every other summary and cause text unchanged.
module: s19_app/tui/services/flow_execution_service.py
modify: [Data: run_flow.rebinds] (replace); [Data: FlowRunResult.in_place_reads] (append); result (append)
examples: (R-FLOW-CRC.4/1) LOAD "firmware.s19" → CRC "templates/demo-crc32.crc.json" (the Designer's saved file) → WRITE-OUT "out.s19" → block 1 status "error", summary "config malformed", cause "crc config invalid: CRC config is structurally invalid: a CRC Designer template is not a CRC config - it has no regions or groups"; block 2 summary "skipped (upstream error)"; status "error"; written_paths [] (base cause "crc config invalid: CRC config is structurally invalid: 'reverse'", guide ch17-05)
examples: (R-FLOW-CRC.4/2) a config without "reverse" → summary "config malformed", cause "crc config invalid: CRC config is structurally invalid: field 'reverse' is missing"
examples: (R-FLOW-CRC.3/1) CRC "crc.json" absent → summary "config unresolved", cause "crc config not found or not inside the project" (holds on base)
examples: (R-CRC-ENGINE-001.1/7) LOAD "k.s19" (KAT at 0x1000) → CRC "templates/k.json" (Config K) → WRITE-OUT "out.s19" → CRC block summary "injected 1 CRC region"; out.s19 bytes 0x1010 … 0x1013 = 0x31 0x74 0x8B 0x0F
examples: (R-FLOW-EXT.2/2) flow X with output "bench/rel.changes.json" under <proj>, working directory <tmp> → EXT summary "log 'step.log' received · output copied to rel.changes.json (session)" (base: cause "output 'bench/rel.changes.json' does not exist - run the external step before confirming", B)
examples: (R-FLOW-EXT.9/1) flow X, run 1 Doc("AA") done; run 2 Doc("BB") → EXT summary "log 'step.log' received · output copied to step.changes_1.json (session)"; PATCH summary "applied 1 entry · read step.changes_1.json in place of step.changes.json" [A-1]; result.in_place_reads [(`2`, "PatchBlock.change_doc_ref", "step.changes.json", <proj>/step.changes_1.json)]; out.s19 data record "S1071000424203045D" (base "S1071000414103045F", B)
examples: (R-FLOW-EXT.9/3) run 3 Doc("AA") → EXT summary "… output copied to step.changes.json (session)" (reused); out.s19 "S1071000414103045F" (B: the reuse lands on the output file name)
examples: (R-FLOW-EXT.9/9) LOAD → PATCH "step.changes.json" → EXT → PATCH "step.changes.json" → WRITE-OUT, run 2 Doc("BB") → change records: block 1 after-bytes 0x41 0x41, block 3 after-bytes 0x42 0x42; out.s19 "S1071000424203045D"
examples: (R-FLOW-EXT.10/1) flow X + REPORT, run 2 → change record change_doc_ref "step.changes_1.json"; the flow report's Change attribution row names "step.changes_1.json"
examples: (R-FLOW-EXT.10/3) PATCH ref "./step.changes.json", run 1 → change_doc_ref "./step.changes.json" (as typed)
examples: (R-FLOW-EXT.11/1) after run 2 → <proj>/step.changes.json holds Doc("AA") bytes; folder entries "base.s19", "out.s19", "step.changes.json", "step.changes_1.json"
examples: (R-FLOW-EXT.9/13) <proj>/step.changes.json holds Doc("CC") before any run; run 1 Doc("AA") → EXT summary "… output copied to step.changes_1.json (session)"; PATCH summary "applied 1 entry · read step.changes_1.json in place of step.changes.json"; out.s19 "S1071000414103045F" (base "S1071000434303045B", the file that was there) [A-2]
examples: (R-FLOW-EXT.10/4) LOAD → EXT (output "cal.a2l") → PATCH (a2l_ref "cal.a2l") → REPORT, run 2 with A2L v2 → change record a2l_ref "cal_1.a2l"; flow report A2L reference cell "cal_1.a2l" (base "cal.a2l") [A-1]
examples: (R-FLOW-EXT.10/5) EXT (output "cal.a2l") → LOAD (a2l_ref "cal.a2l") → PATCH (no a2l_ref) → REPORT, run 2 → PATCH change record a2l_ref "cal_1.a2l"; LOAD summary ends " · read cal_1.a2l in place of cal.a2l" [A-1]
examples: (R-FLOW-EXT.12/3) the 9/5 flow, run 2 → CRC summary "injected 1 CRC region · read step_1.crc.json in place of step.crc.json"
examples: (R-FLOW-EXT.12/6) the 9/5 flow, run 2 with a bench config without "reverse" → CRC summary "config malformed · read step_1.crc.json in place of step.crc.json"; cause "crc config invalid: CRC config is structurally invalid: field 'reverse' is missing"
examples: (R-FLOW-EXT.12/7) EXT1 (cal.a2l) → LOAD → EXT2 (step.changes.json) → PATCH (both refs), run 2 → PATCH summary "applied 1 entry · read step.changes_1.json in place of step.changes.json · read cal_1.a2l in place of cal.a2l"
examples: (R-FLOW-EXT.12/8) flow X, run 1 into an empty folder → PATCH summary "applied 1 entry"; result.in_place_reads []
examples: (R-FLOW-EXT.14/1) log "../step.log" → EXT status "error", summary "external step refused", cause "log '../step.log' climbs above the project folder - give an absolute path for a file outside the project"; written_paths [] [S-3]
examples: (R-FLOW-EXT.14/2) output "bench/../../x.json" → summary "external step refused", cause "output 'bench/../../x.json' climbs above the project folder - give an absolute path for a file outside the project"; no file added to <proj> [S-3]
examples: (R-FLOW-EXT.14/3) output "bench/../rel.changes.json" → EXT summary "log 'step.log' received · output copied to rel.changes.json (session)"
examples: (R-FLOW-CRC.9/1) read cap lowered to 16, a 32-byte "crc.json" → CRC summary "config malformed", cause "crc config invalid: CRC config file is 32 bytes, over the 16-byte read cap — the file was not read" [S-5]
examples: (R-FLOW-EXT.9/15) run 2 with PATCH ref "<proj>/step.changes.json" (absolute) → PATCH summary "change doc unresolved", cause "change document not found or not inside the project", one [MANIFEST-PATH-ESCAPE] finding (the guard runs before the rebind lookup) [S-4]

_resolve_block_ref
req: R-FLOW-EXT.9, R-FLOW-EXT.10, R-FLOW-EXT.12
in: Path project_dir; str ref; str label; list[ValidationIssue] issues; dict[str, Path] rebinds
out: tuple(Path? path, bool in_place)
func: new. `path = _resolve_manifest_entry(project_dir, ref, label, issues)` on the typed ref **first** (so an absolute, escaping or linked ref is refused before any rebind) [S-4]; `None` → `(None, False)`; `copy = rebinds.get(os.path.normcase(str(path)))`; when `copy` is not `None` and `os.path.normcase(str(copy)) != os.path.normcase(str(path))`: `checked = _resolve_manifest_entry(project_dir, copy.name, label, issues)` (the same per-read link check every ref gets; the copy lies in the project folder) [S-4] — `None` → `(None, False)`, else `(checked, True)`; otherwise `(path, False)`. Never raises beyond what `_resolve_manifest_entry` raises (nothing).
module: s19_app/tui/services/flow_execution_service.py
examples: (R-FLOW-EXT.9/1) ref "step.changes.json", rebinds {normcase("<proj>/step.changes.json"): <proj>/step.changes_1.json} → path "<proj>/step.changes_1.json", in_place `True`
examples: (R-FLOW-EXT.9/2) ref "step.changes.json", rebinds {normcase("<proj>/step.changes.json"): <proj>/step.changes.json} → path "<proj>/step.changes.json", in_place `False`
examples: (R-FLOW-EXT.9/8) ref "patches/other.changes.json", the same rebinds → path "<proj>/patches/other.changes.json", in_place `False`
examples: (R-FLOW-EXT.9/10, Windows) ref "STEP.CHANGES.JSON", rebinds of /1 → path "<proj>/step.changes_1.json", in_place `True`
examples: (R-FLOW-CRC.3/1 family) ref "C:/elsewhere/x.json" (absolute) → path `None`, in_place `False`; issues gets one [MANIFEST-PATH-ESCAPE] finding (as `_resolve_manifest_entry` on base)
examples: (R-FLOW-EXT.9/15) ref "<proj>/step.changes.json" (absolute), rebinds of /1 → path `None`, in_place `False`; one [MANIFEST-PATH-ESCAPE] finding [S-4]
examples: (R-FLOW-EXT.9/15) ref "jl/step.changes.json" where "jl" is a junction to <proj>, rebinds of /1 → path `None`, in_place `False`; one [MANIFEST-PATH-ESCAPE] finding [S-4]
examples: (R-FLOW-EXT.9/15 neg) mutant: rebinds looked up by the typed text before the guard → the absolute ref returns the copy → RED

run_chain_set
req: R-FLOW-EXT.13, R-FLOW-EXT.9
in: Sequence[ChainSpec] chains; FlowContext ctx; str mode = CHAIN_RUN_SEQUENTIAL; str set_name = "chain-set"; (Callable) Flow,FlowContext->FlowRunResult run_one = None; (Callable) ->float clock = None
out: ChainSetRunRecord record
func: changed [S-2] (nested `_run_one` only). was: `inputs = _chain_inputs(ctx, blocks)` before `execute`, copied into `ChainRunOutcome.inputs`. / now: after `execute`, for the j-th LOAD block (1-based input index j, block index b) with an entry `(b, "SourceBlock.image_ref", ref, copy)` in `result.in_place_reads`, `inputs[j-1] = (ref, str(copy))` and `in_place_inputs[j] = copy.name`; every other input as before. Each chain is its own run: no rebind crosses chains [A-8].
module: s19_app/tui/services/flow_execution_service.py
modify: [Data: ChainRunOutcome.in_place_inputs] (replace)
examples: (R-FLOW-EXT.13/1) one chain EXT (output fw.s19) → LOAD "fw.s19" → WRITE-OUT, run 2 (copy fw_1.s19) → outcome.inputs [("fw.s19", "<proj>/fw_1.s19")]; outcome.in_place_inputs {`1`: "fw_1.s19"}
examples: (R-FLOW-EXT.9/14) chain A copies step.changes_1.json; chain B's PATCH "step.changes.json" → chain B summary "applied 1 entry" (no suffix); b.s19 "S1071000414103045F" [A-8]

compose_chain_set_report
req: R-FLOW-EXT.13
in: ChainSetRunRecord record; str set_name; datetime generated_at
out: str markdown
func: changed [S-2]. was: one Input provenance line per input, "- Chain <name> input <j>: <ref> [bound] path=`<resolved>`". / now: the same line, ending with " · read " + md_safe(copy) + " in place of " + md_safe(ref) when j is in `outcome.in_place_inputs`. Every other line unchanged.
module: s19_app/tui/services/flow_execution_service.py
examples: (R-FLOW-EXT.13/1) the /1 outcome → line "- Chain <name> input 1: fw.s19 [bound] path=`<proj>/fw_1.s19` · read fw_1.s19 in place of fw.s19"
examples: (R-FLOW-EXT.13/2, holds on base) an outcome with in_place_inputs {} → line "- Chain <name> input 1: base.s19 [bound] path=`<proj>/base.s19`" (TC-B94-30 form)

_resolve_manifest_entry
req: R-FLOW-EXT.9
in: Path project_root; object raw_entry; str context; list[ValidationIssue] issues; str mode = ENTRY_MODE_DEFAULT; _EntryWalk? walk = None
out: Path? path
func: unchanged. The project-ref guard of CTX-FLOW: refuses NUL, absolute, escaping and linked refs with one finding; else `(project_root / entry).resolve()`.
module: s19_app/tui/services/variant_execution_service.py
examples: (R-FLOW-EXT.9/1, holds on base) project_root <proj>, raw_entry "step.changes.json" → path "<proj>/step.changes.json" (resolved, absolute)

place_into_workarea
req: R-FLOW-EXT.9, R-FLOW-EXT.11
in: Path source; Path destination; int max_size_bytes = DEFAULT_COPY_SIZE_CAP_BYTES; Path? workarea_root = None
out: PlacementResult placement
func: unchanged (D-2). Guards, private staging, byte-identity reuse over the output file name and every `<stem>_<N><suffix>`, else an exclusive claim of the lowest free name; never renames, replaces or deletes a placed file (LLR-155.3 / LED .7). `copy_into_workarea` returns its `.path`.
module: s19_app/tui/workspace.py
examples: (R-FLOW-EXT.9/1, holds on base) source <tmp>/bench/step.changes.json (Doc "BB"), destination <proj> holding step.changes.json (Doc "AA") → path "<proj>/step.changes_1.json", reused `False`
examples: (R-FLOW-EXT.9/3, holds on base) source Doc "AA" again → path "<proj>/step.changes.json", reused `True`
examples: (R-FLOW-EXT.11/1, holds on base) after the /1 call → <proj>/step.changes.json still holds Doc "AA"

## Entities

[Data: run_flow.rebinds]
in: dict[str, Path]
desc: one per `run_flow` call, empty at its start; key = `os.path.normcase` of "<copy folder>/<output file name>", value = the path the copy landed on. A later external step with the same output file name replaces the entry. Never shared between lanes or runs.
sequence:
  confirmedRun: run_flow (EXT branch) wins → _resolve_block_ref (each later block)

[Data: FlowRunResult.in_place_reads]
in: List[Tuple[int, str, str, Path]]
desc: [S-2] new field of `FlowRunResult` (`flow_model.py:748`), default `[]`: one entry per in-place read of the run — (block index, resolution label, typed ref, copy) — in read order. Read by the summary suffix step of `run_flow` and by `run_chain_set._run_one`.
sequence:
  blockRead: _resolve_block_ref → run_flow (append) wins → run_flow (summary suffix) → run_chain_set (provenance)

[Data: ChainRunOutcome.in_place_inputs]
in: Dict[int, str]
desc: [S-2] new field of `ChainRunOutcome` (`flow_execution_service.py:1587`), default `{}`: 1-based input index → the copy's file name for a LOAD input read in place. `inputs` keeps its `(ref, path)` 2-tuples.

[I/O: project folder]
desc: `<project>/`, the copy destination of an external step (`copy_into_workarea(source, ctx.project_dir)`). Placed files are immutable (LLR-155.3): a differing output gets the lowest free `_<N>`; an identical one reuses the file.

[I/O: external output]
desc: the file the human produced, outside the project as a rule (absolute path preferred); a relative path is joined under the project folder (D15-17), and refused when it climbs above it (R-FLOW-EXT.14) [S-3]. Read only.

[I/O: CRC config file]
desc: the file a CRC block names (`CrcBlock.config_ref`), read with `read_crc_config_text` (256 MiB read limit) [S-5] and `parse_crc_config`; a CRC Designer template file is refused with R-CRC-CONFIG-001.16.

[Interface: flow report Change document column]
desc: Change attribution, Not applied and Refusals of the flow report; Not applied and Refusals of the chain-set report; the flow-A2B change census. Each prints `FlowChangeRecord.change_doc_ref` / `FlowRefusal.change_doc_ref`, and the flow report's A2L reference column prints `FlowChangeRecord.a2l_ref` (I-4) [A-1].

[Interface: block summary]
desc: [A-1, A-2, S-2] the lane terminal line, the run log and the flow report Pipeline ledger paint `BlockResult.summary`; a block that read a copy in place ends it with the read suffix (I-7).

[Interface: chain-set Input provenance]
desc: [S-2] one line per LOAD input of each chain; a rebound input names the copy's path and ends with the read suffix (R-FLOW-EXT.13).

## Edges

run_flow ──▶ [Data: run_flow.rebinds]
when: a confirmed external step's copy succeeds
[Data: run_flow.rebinds] ──▶ _resolve_block_ref
run_flow ──▶ [Interface: flow report Change document column]
[I/O: external output] ──▶ place_into_workarea
place_into_workarea ──▶ [I/O: project folder]
[I/O: CRC config file] ──▶ parse_crc_config
run_flow ──▶ [Data: FlowRunResult.in_place_reads]
[Data: FlowRunResult.in_place_reads] ──▶ run_chain_set
run_chain_set ──▶ [Data: ChainRunOutcome.in_place_inputs]
[Data: ChainRunOutcome.in_place_inputs] ──▶ compose_chain_set_report
run_flow ──▶ [Interface: block summary]
compose_chain_set_report ──▶ [Interface: chain-set Input provenance]

## Findings

> E2-1 (for E3). `run_flow` reads the CRC config file without the 256 MiB read limit and decodes UTF-8 inside the block's `try` (`flow_execution_service.py:810-812`); the Operations dialog uses `read_crc_config_text`. **E3 round 1 [S-5]: folded in** — the CRC branch now reads through `read_crc_config_text` (R-FLOW-CRC.9); the decode half stays with BL-I8-5 (per-block isolation catches it).
> E3 round 1 coverage additions: R-CRC-CONFIG-001.17 (`parse_crc_config`); R-FLOW-CRC.9, R-FLOW-EXT.12, R-FLOW-EXT.14 (`run_flow`); R-FLOW-EXT.13 (`run_chain_set`, `compose_chain_set_report`); R-FLOW-EXT.10 widened to the A2L (`run_flow` examples /4, /5).
> E2-2 (for E3). Rebind is by name: the key is the copy folder plus the output file name as the placement asks for it (`resolved_source.name`, `workspace.py:1201`, `:1231`). A ref that names `<stem>_1<suffix>` explicitly is not rebound (R-FLOW-EXT.9/8 family). E3 rules D-2 against rotate / overwrite.
> E2-3. Coverage of the requirement → node map: every row of `01-requirements.md` has at least one example above (R-CRC-ENGINE-001.1: `crc32_stream`, `check_regions`, `inject_crcs`, `run_flow`; R-CRC-ENGINE-002.2: `crc32_stream`, `crc_stream`; R-CRC-DESIGNER-001.1: `crc_stream`; R-CRC-CONFIG-001.10 / .11: `_required_field`, `_number_field`, `_build_config`, `_build_group`, `parse_crc_config`; R-CRC-CONFIG-001.16: `_build_config`, `parse_crc_config`, `emit_template`; R-FLOW-CRC.1 / .3 / .4, R-FLOW-EXT.2 / .9 / .10 / .11: `run_flow`, `_resolve_block_ref`, `place_into_workarea`).
