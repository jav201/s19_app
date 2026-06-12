# Functionality — s19_app — 2026-06-11-batch-08

> **Audience:** technical stakeholder (operator / future fill-in implementer). **Purpose:** understand what batch-08 delivers functionally, how to exercise it, and where the seams are for the next batch. Not a review document — the verification record lives in `04-validation.md` and the per-requirement mapping in `traceability-matrix.md`.

## 1. What this batch delivers in one paragraph

Batch-08 wires an **operation framework** into s19tool: three named operations — `crc`, `extract`, `split_by_segment` — that you can select and execute from the TUI against a loaded S19/HEX image. None of them does real work yet, by design: each is a **placeholder** that returns the image exactly as it received it, stamped `status: placeholder`. What you are buying with this batch is the plumbing — when an operation gets its real definition later, implementing it means changing **one class body**, not re-plumbing the app.

## 2. The operation framework

### What a placeholder operation IS

A placeholder operation takes the loaded image snapshot (the same `LoadedFile` object every renderer in the TUI reads) and returns it **untouched** — same object, same memory map, same ranges, same error list. This is verified down to deep-copy equality in the unit tests. What it adds is an **envelope** around that passthrough: an `OperationResult` carrying

- `operation_id` — which operation ran,
- `status` — one of a closed set: `placeholder`, `ok`, `error` (closed NOW so a real operation can report success/failure later without a schema change),
- `notes` — human-readable lines; today exactly one: `placeholder: <id> not yet implemented`,
- `input_path`, `variant_id`, `timestamp_utc` — provenance metadata,
- `output` — the resulting image (today: the input itself).

### Why the envelope exists

The operator's original working example was "a function that returns its input." That shape was deliberately rejected (design decision C-1): a real CRC does not return an image — it returns a computed value plus metadata; a real split returns multiple artifacts. If the placeholders were bare passthrough functions, filling one in would change its signature and therefore every caller — exactly the re-plumbing the story exists to avoid. The envelope absorbs that future variation: **filling in one operation later means changing one class body** in `s19_app/tui/operations/placeholders.py` (plus its tests), nothing else. The serialized form (`to_dict()`) is deliberately size-bounded — it reports the output as path/type/byte-count, never the raw memory content, so results can go to logs or reports without leaking a memory dump.

### The registry

A small, static, code-driven table in `s19_app/tui/operations/registry.py`: it lists exactly `["crc", "extract", "split_by_segment"]` in a fixed order and resolves an id to its operation instance. No reflection, no scanning, no model-driven routing — dispatch is greppable and deterministic. An unknown id fails loudly with a `KeyError` naming the id; there is no fuzzy matching and no default operation.

### The headless service

`run_operation(operation_id, loaded)` in `s19_app/tui/services/operation_service.py` is the single execution entry point: resolve via the registry, call `execute`, return the result. It imports nothing from Textual and nothing from the view modules (structurally enforced — import probes run at 0 hits), performs no file I/O and no parsing. That means a follow-up batch — or a future CLI subcommand, or a test — can run any operation with no TUI at all. The TUI is just one consumer of this service.

## 3. The TUI flow — how to try it

```bash
# Launch with a file pre-loaded
s19tui --load examples/case_00_public/prg.s19
```

1. With the file loaded, press **`x`** (also reachable from the command palette as "Operations").
2. A modal lists the three registered operations by title. Pick one and press **Execute**.
3. The result panel shows `status: placeholder` plus the note line, and below it a **hex render of the resulting image** — produced by the same hex renderer the workspace uses. Since placeholders are identity passthroughs, this render is byte-for-byte the same text you would get rendering the input image: that equality IS the acceptance demo, proving the select → registry → service → result → render pipeline end-to-end.
4. Press `x` with **no file loaded** and you get a status-line message ("Operations: no file loaded - load a file first.") — the modal never opens and the service is never called.

The same flow works for Intel HEX images (`s19tui` then load a `.hex` via the load screen); both image kinds satisfy identical identity guarantees.

## 4. What it does NOT do yet — and where the extension points are

### Not in this batch (deliberate, operator-decided)

- **No real CRC / extract / split logic.** The operator's gate rationale, recorded verbatim in the requirements: the operations are real future work needing proper definition before implementation; this batch builds only the control/log plumbing around them.
- **No file output.** Operations write nothing to disk — no S19/HEX re-emission (the repo has no Intel HEX writer, and the S19 emitter canonicalizes formatting, so byte-identical re-emission is not even achievable — measured in probe P4).
- **No CLI subcommand.** `s19tool <file> ops ...` stays deferred to the fill-in batch.
- **No result export, operation history, parameters, or progress UI.**

### Extension points for the fill-in batch

| Seam | What it gives you |
|------|-------------------|
| **C-7 co-located requirements** | Each operation's REAL behavior gets its own requirements set at `s19_app/tui/operations/requirements/REQ-<operation_id>.md`, created by that operation's fill-in batch. Requirements travel with the module (the operator's portability intent: operations may be reused in other applications), and the application-level documents only reference them. |
| **The registry** | The fill-in batch finds its target by id (`crc`, `extract`, `split_by_segment` — stable lookup keys); adding a fourth operation is one class + one registry line. |
| **C-2 contract widening (risk R-3)** | A real operation will likely need a payload field (computed CRC value, emitted artifacts) beyond today's 7 fields. That widening is designed-for: it re-opens the `OperationResult` contract table under the contract-touch rule — a contract edit, budgeted, not a surprise. |
| **R-6 mandatory inheritances** | Two obligations the fill-in batch inherits as MANDATORY, not advisory: (1) migrate execution off the UI thread to the existing `execute_scope` worker pattern the moment an operation does real work (today's synchronous execution is valid only because placeholders do no I/O and no parsing); (2) any side-effectful operation (file emission, export) requires per-execution operator confirmation in the view plus sanitized/validated output paths. |
| **Input contract (risk R-2, deferred)** | `execute` currently binds to `LoadedFile` — the module's only remaining application coupling. The first fill-in batch's local requirements set defines the neutral input contract and lands the adaptation once. |

## 5. Assumptions, risks, next steps (summary)

- **Assumption:** exactly one placeholder receives real requirements in a follow-up batch (operator-committed); the abstraction is sized for that, not for a plugin ecosystem.
- **Risk accepted:** an ABC + registry for three no-ops is more structure than strictly needed today; if the follow-up were cancelled, the package is dead code removable in one commit.
- **Next steps:** (1) fill-in batch for the first real operation (own REQ doc per C-7, worker migration per R-6, contract widening per R-3); (2) optional CLI `ops` subcommand; (3) hygiene: rename the reused `load_buttons` widget id in `OperationsScreen` (carried note N-3). US-006 (hex compare mode) remains the queued sibling story.
