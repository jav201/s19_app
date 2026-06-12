# Operations flow — batch 2026-06-11-batch-08

> TUI operations pipeline: key `x` → guard → `OperationsScreen` → `run_operation` service → registry → placeholder `execute` → `OperationResult` → status/notes + pinned hex render.
> Anchors grep-verified 2026-06-11 against HEAD (34fc43a). Guard rails annotated below the diagram.

```mermaid
flowchart TD
    K["Key 'x' / palette: Operations<br/><i>Binding app.py:502</i>"] --> A["action_operations_view<br/><i>app.py:2314 — no @work decorator</i>"]
    A --> G{"current_file is None?<br/><i>guard app.py:2344-2347</i>"}
    G -- "yes" --> SL["Status line: 'no file loaded'<br/>no screen push, no service call"]
    G -- "no" --> OPT["Pre-compute (id, title) options<br/>via list_operation_ids() + get_operation().title<br/><i>app.py:2348-2351</i>"]
    OPT --> SCR["push_screen OperationsScreen(options, current_file)<br/><i>app.py:2355 → screens.py:484</i><br/>modal, no callback — execution is modal-internal"]
    SCR --> SEL["Operator selects row by LIST INDEX<br/>(never label parsing) + Execute<br/><i>screens.py:611-615</i>"]
    SEL --> RUN["run_operation(operation_id, loaded)<br/><i>SYNCHRONOUS call, screens.py:618<br/>service: operation_service.py:38</i>"]
    RUN --> REG["registry.get_operation(operation_id)<br/><i>registry.py:44 — static dict, deterministic,<br/>no model routing</i>"]
    REG -- "unknown id" --> KE["KeyError 'unknown operation id: …'<br/><i>registry.py:74</i>"]
    KE --> EH["Status line: 'Operations error: unknown operation …'<br/>never a crash<br/><i>screens.py:619-622</i>"]
    REG -- "resolved" --> EX["placeholder execute(loaded, *, now_fn)<br/><i>placeholders.py — identity passthrough:<br/>output IS the input snapshot, nothing mutated</i>"]
    EX --> RES["OperationResult<br/>{operation_id, status='placeholder', input_path,<br/>variant_id, output, notes, timestamp_utc}<br/><i>model.py:27 — closed STATUS_DOMAIN model.py:23</i>"]
    RES --> ST["status + notes →<br/>#operation_result_status<br/><i>screens.py:548, :625</i>"]
    RES --> HX["render_hex_view_text(result.output.mem_map,<br/>focus_address=None, row_bases=None, highlight=None,<br/>mac_highlight_addresses=None, max_rows=MAX_HEX_ROWS)<br/><i>PINNED argument tuple — screens.py:628-635;<br/>renderer hexview.py:324, MAX_HEX_ROWS=512 hexview.py:22</i>"]
    HX --> W["#operation_result_hex widget<br/><i>screens.py:550, update :636</i><br/>render of the UNCHANGED image =<br/>the end-to-end acceptance demo (TC-012)"]

    style SL fill:none,stroke-dasharray: 5 5
    style EH fill:none,stroke-dasharray: 5 5
```

## Guard rails (enforced, not advisory)

| Rail | Mechanism | Evidence |
|------|-----------|----------|
| **No reverse imports** | `s19_app/tui/operations/*` and `operation_service.py` import no Textual modules and no view modules (`app`/`screens`, absolute or relative form). The view imports the service — never the reverse. | Widened LLR-003.2 probe (TC-008): 0 hits, regime-correct positive/negative controls on record (04-validation §2.1-2.2) |
| **No I/O — probe P11** | The operations package + service contain zero filesystem calls (`open(`, `write_text`, `write_bytes`, `mkdir`, `shutil`, `os.remove`, `emit_s19_from_mem_map`). Load-bearing: this is what justifies synchronous UI-thread execution. | P11 probe: 0 hits on targets; positive control 7 hits on `changes/io.py` (04-validation §2.3) |
| **Service-only execution** | No direct `.execute(` call exists in `app.py` or `screens.py`; the sole execution route is `run_operation` through its injectable resolver seam. | Probe P8: 0 hits (04-validation §3 criterion 5); seam substitution proven in TC-011 |
| **Pinned render args** | The result hex render uses EXACTLY the pinned tuple with `max_rows=MAX_HEX_ROWS` (binding row cap, not default-only); the existing app call site with focus/highlight state is deliberately NOT this shape. | Inspection of `screens.py:628-635` (04-validation §2.4); TC-012 independent-baseline equality |
| **Sync execution + R-6 migration note** | Execution is synchronous on the UI thread — 0 `@work` decorators on HLR-004 paths. Valid ONLY while placeholders do no I/O and no parsing (LLR-004.4 declares itself INVALIDATED by real work). The fill-in batch MUST migrate to the `execute_scope` thread-worker pattern (`app.py:1489` baseline) and add per-execution confirmation + path sanitization for any side-effectful operation. | 04-validation §2.5; risk R-6, `01-requirements.md` §6.3 |
