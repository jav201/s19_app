# Inc 8 — E4 implementation notes (G1 + G2, one implementer)

Batch 2026-11-01-batch-101, increment 8. Base `e266395` (branch `b101-inc8`).
Records implemented exactly: `01-requirements.md`, `E1-slice.md`,
`codewire/graph-inc8.md`, `E1-rulings.md`, `E3-rulings.md` (incl. E3 round 2
addenda N-1 … N-4). No requirement changed; no existing message text changed
except where a row changes it (R-CRC-CONFIG-001.10/.11/.16/.17 reasons,
R-FLOW-CRC.9 cause, R-FLOW-EXT.14 cause — all new/changed texts pinned by the
records). No test written or edited. No commit made.

## Functions changed, per file (file:function)

### s19_app/tui/operations/crc.py (G1)

- `crc.py:crc32_stream` — the loop seed is now `reg = init & _MASK32` for both
  values of `reverse` (was `_reflect(init, 32)` when `reverse`). The zlib fast
  path, the byte/output reflection and the rest of the loop are untouched
  (D-6). Docstring `init` arg and Data Flow updated to the model (init used as
  given). Verified against the graph oracle: KAT, poly 0x04C11DB7,
  init 0x12345678, reverse true, xorout 0xFFFFFFFF → 0x0F8B7431; defaults →
  0xCBF43926 (zlib path).

### s19_app/tui/operations/crc_config.py (G1)

- `crc_config.py:DESIGNER_TEMPLATE_RULE` (new constant) — the R-CRC-CONFIG-001.16
  rule text, single-sourced for the parser and the flow cause (I-1).
- `crc_config.py:VALUE_CLIP` (new constant) = 64 — the `<value>` clip bound (S-1).
- `crc_config.py:_required_field` (new) — missing key →
  `ValueError("field '<key>' is missing")`.
- `crc_config.py:_number_field` (new) — `_required_field` then `_parse_int`;
  a `ValueError` becomes `field '<key>' is not a number: <clip>` with
  `<clip>` = `json.dumps(raw)` whole up to 64 characters, else first 64 + `…`
  (U+2026). `_parse_int` itself untouched (A-4 leniency preserved).
- `crc_config.py:_build_config` (changed) — first statement: a Designer
  template shape (`"algorithm" in data and "polynomial" not in data`) raises
  `ValueError(DESIGNER_TEMPLATE_RULE)`; `reverse` reads through
  `_required_field`; region `start`/`end`/`output_address` and
  `polynomial`/`init`/`final_xor` through `_number_field`. Check order
  otherwise unchanged (reverse → regions/groups presence → regions → groups →
  span ceiling → flat parameters).
- `crc_config.py:_build_group` (changed) — `regions` through `_required_field`;
  span `start`/`end` and `output_address` through `_number_field`;
  `output_bytes` keeps its own rule text and order (span shape, N6 tripwire,
  N5, address-space rules all unchanged).
- `crc_config.py:parse_crc_config` (changed, [S-6]) — `json.loads` now also
  catches `RecursionError` → `CRC config is not valid JSON: nesting too deep`;
  the object guard and the `(KeyError, TypeError, ValueError)` →
  `CRC config is structurally invalid: <exc>` pass-through are unchanged, so
  every new reason reaches callers through the existing seam.

Probed at E4: template refusal text; `field 'reverse' is missing`;
`field 'polynomial' is not a number: "zz"`; `[` × 100 000 →
`nesting too deep`; group `field 'regions' is missing` /
`field 'start' is not a number: "x"`. All match the graph examples.

### s19_app/tui/services/flow_model.py (G2, [S-2])

- `flow_model.py:FlowRunResult` (changed, one field) — new
  `in_place_reads: List[Tuple[int, str, str, Path]] = field(default_factory=list)`
  (I-6, N-3): (block index, resolution label, typed ref, copy), read order.

### s19_app/tui/services/flow_execution_service.py (G2)

- `flow_execution_service.py:run_flow` (changed):
  1. per-run `rebinds: Dict[str, Path]` (normcase "<copy folder>/<output file
     name>" → the copy), never shared;
  2. all seven block-branch ref resolutions (`SourceBlock.image_ref`,
     `SourceBlock.a2l_ref`, `PatchBlock.change_doc_ref`, `PatchBlock.a2l_ref`,
     `CheckBlock.check_doc_ref`, `CrcBlock.config_ref`, `A2BBlock.image_a/b`)
     go through `_resolve_block_ref`; each in-place read appends
     `(index, label, typed ref, copy)` to `result.in_place_reads` (read
     order);
  3. PATCH branch: `change_doc_name = path.name if doc_in_place else
     block.change_doc_ref` feeds `FlowChangeRecord.change_doc_ref` and
     `FlowRefusal.change_doc_ref`; `effective_a2l_ref` is the copy's name when
     the PATCH's own A2L was read in place, else `block.a2l_ref or
     source_a2l_ref`; the SOURCE branch keeps `source_a2l_ref = a2l_path.name
     when a2l_in_place else block.a2l_ref` (I-4, A-1);
  4. external-step branch: order log climb → log exists → output climb →
     output exists → copy (E4 addendum); a relative log or output that climbs
     above the project folder stops the block with summary
     `external step refused` and the R-FLOW-EXT.14 cause (`<log or output>
     '<path as given>' climbs above the project folder - give an absolute path
     for a file outside the project`), checked by text
     (`_climbs_above_project`, normpath, no link followed); a relative output
     is joined under `ctx.project_dir` like the log (D15-17); after the copy,
     `rebinds[normcase(str(copied.parent / Path(source_path).resolve().name))]
     = copied`;
  5. CRC branch: the config is read with `read_crc_config_text(str(path),
     ctx.project_dir)` (256 MiB cap, R-FLOW-CRC.9); a read error goes the
     R-FLOW-CRC.4 way (`config malformed` / `crc config invalid: <reason>`);
     then `parse_crc_config` as before;
  6. the per-block `try` gained a `finally` calling
     `_apply_block_read_suffixes(result, index)` (N-4): normal end, `continue`
     and the per-block `except` all carry the suffix.
- `flow_execution_service.py:_resolve_block_ref` (new) — typed ref through
  `_resolve_manifest_entry` FIRST (a refused ref stays refused, [S-4]); then
  the rebind map; a found copy that is another file passes the same per-read
  link check on `copy.name` and returns `(checked, True)`; otherwise
  `(path, False)`. Never raises.
- `flow_execution_service.py:_apply_block_read_suffixes` (new) — appends
  `" · read " + copy.name + " in place of " + ref` once per in-place read of
  the block, in read order (I-7). N-2: a summary ending with a
  suffix-matched refusal/status token (`unresolved`, the only token a
  consumer matches by suffix — `flow_screens._failure_detail`) gets the suffix
  inserted BEFORE the token so it stays last; every other summary gets the
  suffix appended.
- `flow_execution_service.py:_climbs_above_project` (new) — normpath text
  containment under the normalised project folder.
- `flow_execution_service.py:ChainRunOutcome` (changed, one field, [S-2]) —
  new `in_place_inputs: Dict[int, str] = field(default_factory=dict)` (I-6,
  N-3); `inputs` keeps its `(ref, path)` 2-tuples.
- `flow_execution_service.py:run_chain_set._run_one` (changed, [S-2]) — after
  `execute`, each LOAD input (1-based index j over the chain's SourceBlocks)
  with an `(b, "SourceBlock.image_ref", ref, copy)` entry in
  `result.in_place_reads` gets `inputs[j-1] = (ref, str(copy))` and
   `in_place_inputs[j] = copy.name`; `_chain_inputs` itself untouched
  (resolves before the run, as ruled).
- `flow_execution_service.py:compose_chain_set_report` (changed, [S-2]) — an
  Input provenance line whose index is in `in_place_inputs` ends with
  ` · read <md_safe(copy)> in place of <md_safe(ref)>`; unbound lines keep the
  TC-B94-30 form byte-for-byte.

## Deviations from the graph

None known. Two implementation choices inside the ruled space, recorded for
the tester:

1. `_apply_block_read_suffixes` matches the block's `BlockResult` as the LAST
   entry of `result.block_results` with `block_result.index == index` — every
   branch appends exactly one result per block, so this is the block's own
   result on every exit path.
2. The N-2 guarded-token set is exactly `("unresolved",)`: it is the only
   suffix a consumer matches on a block summary (verified by grep over
   `s19_app/tui`). If a later increment adds another, extend
   `_SUFFIX_GUARDED_TOKENS`.

## Smoke result

Transcript (redacted): `.dev-flow/2026-11-01-batch-101/evidence/inc-8/impl-smoke.txt`.

- `import s19_app` prints this worktree's `s19_app/__init__.py`;
  `import s19_app.tui.app` OK.
- Existing tests of the touched modules, run once with the pinned env
  (`--basetemp <TEMP>/s19e4n8/bt`, cache provider off): **479 passed, 0 failed**
  in two batches — batch 1 (14 files: test_crc_engine, test_crc_config,
  test_crc_operation, test_crc_template_loader, test_crc_job_upconvert,
  test_flow_crc_block, test_flow_execution_service, test_flow_model,
  test_flow_external_step_b96, test_flow_chainset_b94, test_flow_execution,
  test_flow_funnel_b96, test_flow_a2b_b94, test_b99_crc_region): 183 passed.
  Batch 2 (13 files, indirect coverage: test_flow_report_service/wire/fusion,
  test_b97_flow_execution, test_flow_multi_image, test_flow_crc_ui,
  test_flow_crc_ribbon, test_tui_crc_surface, test_b99_patch_truth/staging/
  truncation, test_changes_symbol_entries, test_flow_report_ui): 296 passed.
- **No existing test whose expectations the design changes failed — nothing
  to list.** Every other result passing matches the E1 slice §4 census.
- E4 functional probe (scratch script under the temp dir, not the repo):
  flow X run twice — run 2's PATCH reads the copy in place with the exact
  read suffix, the change record names `step.changes_1.json`, the written
  image holds the V2 bytes (`S1071000424203045D`), the file under the output
  file name keeps run 1's bytes (R-FLOW-EXT.11); the climbing-output refusal,
  the normalised inside path, and the CRC read-cap cause all match the graph
  texts. `PROBE_ALL_OK`.
- No pytest left running; no commit made.
