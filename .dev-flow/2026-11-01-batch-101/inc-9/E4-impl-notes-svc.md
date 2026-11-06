# Inc 9 — E4 implementation notes (G1 services)
Batch 2026-11-01-batch-101, increment 9. Implementer G1 services (E4). Files touched:
- `s19_app/tui/services/flow_execution_service.py`
- `s19_app/tui/services/flow_persistence_service.py`
- `tests/test_b99_staging.py`

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| `s19_app/tui/services/flow_execution_service.py` | `CHAIN_RUN_CONFIRM_RERUN` (new constant) | `[Data: CHAIN_RUN_CONFIRM_RERUN]` | Added `"confirm re-run"` beside `CHAIN_RUN_MODES`; not added to `CHAIN_RUN_MODES` (the switch keeps its two modes). |
| `s19_app/tui/services/flow_execution_service.py` | `run_chain_set` | `run_chain_set` | The mode check now accepts `CHAIN_RUN_CONFIRM_RERUN` beside `CHAIN_RUN_MODES` (any other token still raises `ValueError`); dispatch unchanged (the non-`parallel` arm runs lanes in order); `record.mode` keeps the token. Three docstrings name the new token beside the two modes (E3A-07): `ChainSetRunRecord.mode`, `run_chain_set` Args `mode`, and its Raises entry. |
| `s19_app/tui/services/flow_persistence_service.py` | `_create_new_json` (new private helper) | `_create_new_json` | The house claim of `place_into_workarea` (E3 S-1 / I-7), shared by both saves: `lexists` name check → payload rendered before the claim → `os.open(O_CREAT\|O_EXCL\|O_WRONLY\|O_BINARY)` → post-claim check (regular file, not a reparse point, `samestat(fstat(fd), lstat)`, `contained_in_workarea(realpath, resolved_home)`) before any byte → write through `os.fdopen`; own-claim unlink (best-effort) on check/write failure. |
| `s19_app/tui/services/flow_persistence_service.py` | `save_flow_json` | `save_flow_json` | New keyword `workarea_root`; `_guarded_destination(flows_dir, workarea_root)` before the `mkdir` (raises `WorkareaContainmentError`, nothing created); then `_create_new_json` with `render(stem) = json.dumps(flow_to_dict(replace(flow, name=stem[:FLOW_MAX_NAME_LEN])), indent=2)`. The base `exists()` loop and `write_text` are gone. |
| `s19_app/tui/services/flow_persistence_service.py` | `save_chain_set` | `save_chain_set` | As `save_flow_json` for `flowsets/`; `render(stem) = json.dumps(chain_set_to_dict(replace(chain_set, name=stem[:CHAIN_SET_MAX_NAME_LEN])), indent=2)` (E3A-04). |
| `tests/test_b99_staging.py` | `_FINAL_NAME_ALLOWLIST`, `_FINAL_NAME_DECLARED_EXCEPTIONS` | TC-B99-13 census (E3A-09) | Added `s19_app/tui/services/flow_persistence_service.py` → `frozenset({"_create_new_json"})` to the allow-list (comment states the three facts: exclusive create of a new name; no byte before the post-claim check; unlink only of its own same-stat claim). Removed the `flow_persistence_service.py` key from the declared exceptions (the two saves no longer call a censused primitive). |

## 2. Deviations from the graph

None.

## 3. Open questions for the integrator

None.

## 4. Checks

Byte-compilation only (operator rule: no pytest / no `s19_app` import on this Windows PC).

```
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/services/flow_execution_service.py s19_app/tui/services/flow_persistence_service.py tests/test_b99_staging.py
```

Result: exit code 0, no output (success) for all three files.
