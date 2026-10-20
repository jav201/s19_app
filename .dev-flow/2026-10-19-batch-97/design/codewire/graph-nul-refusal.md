# Code-Wire graph: a NUL or unsafe ref, from flow, chain-set or lane binding to refusal (batch-97, PDR)

> Format B, Code-Wire draft v2.5, forward direction (PDR baseline). The node name is the code qualname (C11 rule of this project).
> Design source: `design/design-proposal.md` I-6 and §2 (`flow_persistence_service.py`, `variant_execution_service.py`). Requirements: HLR-146, LLR-146.14, LLR-148.9 (the NUL lane arm of AT-B97-23).
> `run_chain_set` and `S19TuiApp.on_flow_execution_panel_run_requested` are declared in `graph-confirm-key.md`. Run the extractor with both files.
> Threads, recorded at `7d823a7` (`extract/trace-nul-*.json`): `TC-B94-31` (`tests/test_flow_chainset_b94.py::test_tc_b94_31_empty_set_and_hostile_sets_fail_closed`, chain-set input `../outside.s19` and template `../evil`), and the security battery of `tests/test_flow_persistence.py` (`BAT-traversal`, `BAT-drive-rel`, `BAT-output-name`). A NUL ref raises today (P-36, P-50), so every NUL line is `synthetic`.
> Convention: an edge from a node with no port to a port means that the node computes that value in its own body (annex, M-3).

## Nodes

load_flow_json
req: LLR-146.14, HLR-146
in: Path flow_path; Path project_dir
out: tuple(Flow? flow, List[ValidationIssue] findings)
func: probes the file size, parses the JSON and builds the flow. The `stat()` guard catches `ValueError` as well as `OSError`. It never raises
module: s19_app/tui/services/flow_persistence_service.py
inner: dict_to_flow
examples: (TC-B97-62, synthetic) flow_path with a NUL in its name → (flow None, findings 1 of 1, a refusal that names the path)

dict_to_flow
req: LLR-146.14
in: Any payload; Path project_dir
out: tuple(Flow? flow, List[ValidationIssue] findings)
func: validates the envelope block by block. Each read ref goes through the shared containment guard. A refused block refuses the flow
module: s19_app/tui/services/flow_persistence_service.py
open: payload — parsed JSON of unknown shape; this node is the validator of that shape
inner: _parse_a2b_entry, _parse_external_step_entry, _resolve_manifest_entry
examples: (BAT-traversal) payload blocks[3].config_ref "../../other/secrets.json" → (flow None, findings 1 of 1 code "MANIFEST-PATH-ESCAPE")
examples: (BAT-drive-rel) payload blocks[0].image_ref "C:relative_evil.s19" → (flow None, findings code "FLOW-UNSAFE-REF")
examples: (BAT-output-name) payload blocks[4].output_name with a traversal to "escape.s19" → (flow None, findings code "FLOW-UNSAFE-OUTPUT-NAME")
examples: (TC-B97-62, synthetic) payload blocks[1].change_doc_ref "calib\x00.json" → (flow None, findings 1 of 1 code "FLOW-UNSAFE-REF" naming change_doc_ref)

_parse_a2b_entry
req: LLR-146.14
in: Dict[str, Any] entry; str label; Path project_root; List[FlowBlock] upstream_blocks; List[ValidationIssue] findings
out: A2BBlock? block
func: validates the two bindings of an A2B block. A file binding ref is normalised, pre-rejected by shape, then sent to the shared guard
module: s19_app/tui/services/flow_persistence_service.py
modify: findings (append)
open: entry — one parsed block object; this node validates its keys
inner: _resolve_manifest_entry
examples: (TC-B97-62, synthetic) entry image_a {source "file", ref "a\x00.s19"} → block None; findings gains 1 refusal naming image_a.ref

_parse_external_step_entry
req: LLR-146.14
in: Dict[str, Any] entry; str label; List[ValidationIssue] findings
out: ExternalStepBlock? block
func: validates an external-step block: instruction, mandatory log ref, output path shape
module: s19_app/tui/services/flow_persistence_service.py
modify: findings (append)
open: entry — one parsed block object; this node validates its keys
examples: (TC-B97-62, synthetic) entry log_ref "run\x00.log" → block None; findings gains 1 code "FLOW-UNSAFE-REF" naming log_ref
examples: (P-36, inferred) on `main` the same entry loads: `log_ref` is checked for non-empty only (`flow_persistence_service.py:819-825`), so it is accepted, not raised

load_chain_set
req: LLR-146.14, HLR-146
in: Path set_path; Path project_dir
out: tuple(ChainSet? chain_set, List[ValidationIssue] findings)
func: probes the size, parses the JSON and builds the chain set. The `stat()` guard catches `ValueError` as well as `OSError`. It never raises
module: s19_app/tui/services/flow_persistence_service.py
inner: dict_to_chain_set
examples: (TC-B94-31) set_path ".../flowsets/escape.json" → (chain_set None, findings code "MANIFEST-PATH-ESCAPE")
examples: (TC-B97-62, synthetic) set_path with a NUL in its name → (chain_set None, findings 1 of 1); the `stat()` guard catches the `ValueError`

dict_to_chain_set
req: LLR-146.14
in: Any payload; Path project_dir
out: tuple(ChainSet? chain_set, List[ValidationIssue] findings)
func: validates the set envelope. A template must be a plain flow stem. Each bound input ref goes through the shared guard
module: s19_app/tui/services/flow_persistence_service.py
open: payload — parsed JSON of unknown shape; this node is the validator of that shape
inner: _resolve_manifest_entry
examples: (TC-B94-31) payload chains[0].inputs [[0, "../outside.s19"]] → (chain_set None, findings code "MANIFEST-PATH-ESCAPE")
examples: (TC-B94-31) payload chains[0].template "../evil" → (chain_set None, findings code "CHAIN-SET-UNSAFE-REF")
examples: (TC-B97-62, synthetic) payload chains[0].template "base\x00" → (chain_set None, findings 1 of 1 code "CHAIN-SET-UNSAFE-REF")

_resolve_manifest_entry
req: LLR-146.14, LLR-148.9
in: Path project_root; object raw_entry; str context; list[ValidationIssue] issues
out: Path? resolved
func: the shared containment guard: rejects an absolute, escaping, reparse-point or NUL entry with one MANIFEST-PATH-ESCAPE finding, else returns the resolved path
module: s19_app/tui/services/variant_execution_service.py
modify: issues (append)
inner: _path_traverses_reparse_point
examples: (TC-B94-31) raw_entry "../outside.s19"; context "chains[0].inputs.ref" → resolved None; issues gains `escapes the project directory`
examples: (AT-B97-23, synthetic) raw_entry "base\x00.s19"; context "SourceBlock.image_ref" → resolved None; issues gains 1 code "MANIFEST-PATH-ESCAPE"

read_project_manifest
req: LLR-146.14
in: Path project_dir; SizeProbe? size_probe = None
out: ProjectManifest? manifest
func: reads the project manifest. Each batch and assignment entry goes through the shared guard. An unsafe entry is skipped with its finding
module: s19_app/tui/services/variant_execution_service.py
inner: _resolve_manifest_entry
examples: (TC-B97-62, inferred) manifest batch entry "a\x00.s19" → that entry skipped, 1 MANIFEST-PATH-ESCAPE finding, the others kept

run_flow
req: LLR-146.14, LLR-148.9
in: Flow flow; FlowContext ctx
out: FlowRunResult result {status, block_results, written_paths}
func: runs the blocks in order. Each ref that a block reads at run time goes through the shared guard. A refused ref is a block error, not a raise
module: s19_app/tui/services/flow_execution_service.py
inner: _resolve_manifest_entry, _path_traverses_reparse_point
examples: (P-50, inferred) lane 0 bound to "base\x00.s19" → on `main` `ValueError: embedded null character` at `variant_execution_service.py:273`
examples: (AT-B97-23, inferred) the same binding → result {status "error", block 1 "source unresolved"}; the run log names MANIFEST-PATH-ESCAPE in 1 English line

_chain_inputs
req: LLR-146.14
in: FlowContext ctx; Sequence[FlowBlock] blocks
out: List[Tuple[str, str]] inputs
func: lists the resolved input files of one chain for the run record (provenance), through the shared guard
module: s19_app/tui/services/flow_execution_service.py
inner: _resolve_manifest_entry
examples: (AT-B97-23, inferred) a SOURCE bound to "base\x00.s19" → that input left out; no raise

## Entities

[I/O: flow file]
in: bytes
desc: `flows/<name>.json`, schema v1

[I/O: chain-set file]
in: bytes
desc: `flowsets/<name>.json`

[I/O: manifest file]
in: bytes
desc: the project manifest that `read_project_manifest` reads

[I/O: project tree]
in: Path
desc: the project directory on disk. The guard resolves against it and walks it for reparse points

[Interface: Flow Execution lanes]
in: str
desc: `#fx_in_<i>_<j>` and its Bind. The bound ref reaches the run through the run request

## Edges

[I/O: flow file] ──▶ load_flow_json.flow_path
[I/O: chain-set file] ──▶ load_chain_set.set_path
[I/O: manifest file] ──▶ read_project_manifest
[I/O: project tree] ──▶ _resolve_manifest_entry
load_flow_json ──▶ dict_to_flow.payload
load_chain_set ──▶ dict_to_chain_set.payload
dict_to_flow ──▶ _parse_a2b_entry.entry
dict_to_flow ──▶ _parse_external_step_entry.entry
dict_to_flow ──▶ _resolve_manifest_entry.raw_entry
when: the field is a read ref (image_ref, change_doc_ref, check_doc_ref, config_ref, a2l_ref)
_parse_a2b_entry ──▶ _resolve_manifest_entry.raw_entry
when: the binding source is a file
dict_to_chain_set ──▶ _resolve_manifest_entry.raw_entry
read_project_manifest ──▶ _resolve_manifest_entry.raw_entry
run_flow ──▶ _resolve_manifest_entry.raw_entry
_chain_inputs ──▶ _resolve_manifest_entry.raw_entry
dict_to_flow.flow ──▶ load_flow_json.flow
dict_to_chain_set.chain_set ──▶ load_chain_set.chain_set
[Interface: Flow Execution lanes] ──▶ S19TuiApp.on_flow_execution_panel_run_requested.event
run_chain_set ──▶ run_flow.flow
run_chain_set ──▶ _chain_inputs.blocks

## Findings

H-N1
anchor: dict_to_flow ──▶ _resolve_manifest_entry.raw_entry
what: for every unsafe read ref the shipped loaders give the code of the shared guard, MANIFEST-PATH-ESCAPE. LLR-146.14 asks FLOW-UNSAFE-REF (flow) and CHAIN-SET-UNSAFE-REF (set) for a NUL in the same fields
evidence: recorded BAT-traversal (`config_ref` → MANIFEST-PATH-ESCAPE) and TC-B94-31 (input ref → MANIFEST-PATH-ESCAPE); `tests/test_flow_persistence.py:144-147`; `tests/test_flow_chainset_b94.py:458-460` accepts either code; the comment "MANIFEST-* verbatim" at `flow_persistence_service.py:557`
consequence: I-6 also puts the NUL refusal in `_resolve_manifest_entry`. If the check is only there (the one place that raises today, P-36), the read-ref arms of TC-B97-62 get MANIFEST-PATH-ESCAPE and stay RED. If a pre-reject goes before the delegation, a NUL gets a code that no other unsafe read ref in the same file gets
decision: changes I-6: state the placement and the code for each field family, or amend LLR-146.14 to MANIFEST-PATH-ESCAPE for read refs (the TC-B94-31 rule)

H-N2
anchor: dict_to_flow
what: an unsafe `output_name` has its own shipped code, FLOW-UNSAFE-OUTPUT-NAME. LLR-146.14 asks FLOW-UNSAFE-REF for a NUL in that field
evidence: recorded BAT-output-name; `tests/test_flow_persistence.py:155`
consequence: one field, two refusal codes for two kinds of unsafe value
decision: same decision as H-N1 (one row in I-6)

H-N3
anchor: _parse_external_step_entry
what: I-6 names `load_flow_json`, `load_chain_set` and `_resolve_manifest_entry`. The field checks live in four other functions. For `log_ref` and `output_path` today a NUL is accepted, not raised
evidence: `flow_persistence_service.py:819-825` (`log_ref`: non-empty only) and `:840-849` (`output_path`: string shape tests); `load_flow_json` only probes and parses (`:895-924`)
consequence: the Inc-2 change set is `dict_to_flow`, `_parse_a2b_entry`, `_parse_external_step_entry`, `dict_to_chain_set` and the two `stat()` guards. The negative control "4 of the 5 arms raise" does not describe the two EXT-STEP fields, which are RED by acceptance
decision: no new D. I-6 lists the real owner functions. The NC of LLR-146.14 names the acceptance arms
