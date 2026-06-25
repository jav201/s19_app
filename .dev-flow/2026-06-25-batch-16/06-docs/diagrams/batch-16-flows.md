# Flow Diagrams — Per-variant File-Assignment at Project Save (US-017)

**Batch:** `2026-06-25-batch-16`. Closes batch-11 SCOPE-1.

**Legend:**
- **NEW** (batch-16) — the UI rows, the `SaveProjectPayload.batch`/`assignments` fields, and the handler threading (`_write_and_verify_manifest(*, batch, assignments)`).
- **REUSED** (substrate, edit-free) — the writer / verifier / reader / consumer that already accepted `batch`/`assignments` (`manifest_writer.py`, `variant_execution_service.py`); these are consumed unchanged. **0 engine-frozen edits.**

---

## 1. Save path — assignment → manifest → consumer

```mermaid
flowchart TD
    A["action_save_project (app.py:2637)<br/>passes variant ids + workarea .json candidates"]:::new
    B["SaveProjectScreen<br/>per-variant assignment rows + project-wide batch input"]:::new
    C["_collect_composition (screens.py:298-303)<br/>keys each row from variant_id (no Path.stem)"]:::new
    D["SaveProjectPayload<br/>+ batch: tuple[str]<br/>+ assignments: dict[vid, tuple[str]]"]:::new
    E["_handle_save_dialog (app.py)<br/>holds the payload"]:::new
    F["_write_and_verify_manifest(*, batch, assignments)<br/>NEW keyword pair, threaded from payload"]:::new

    G["write_project_manifest(... batch=, assignments=)<br/>app.py:3785/3786 carry the kwargs<br/>_reject_unsafe_entry gate (sole path-safety authority)"]:::reuse
    H["verify_written_manifest(... batch=, assignments=)<br/>app.py:3803/3804 — SAME values (R1)"]:::reuse
    I["project.json on disk<br/>active_variant + batch + assignments[vid]"]:::artifact
    J["read_project_manifest<br/>re-read, issues == [], 0 drift"]:::reuse
    K["plan_variant_executions(scope='all')<br/>variant tuple = batch + assignments[variant_id]"]:::reuse

    A --> B --> C --> D --> E --> F
    F -->|write-intent| G
    F -->|verify-intent == write-intent| H
    G --> I
    I --> J
    H -.verifies.-> J
    J --> K

    classDef new fill:#1f6feb,stroke:#0b3d91,color:#fff;
    classDef reuse fill:#2ea043,stroke:#176f2c,color:#fff;
    classDef artifact fill:#8957e5,stroke:#553098,color:#fff;
```

The **NEW** path (blue) is the SCOPE-1 closure: the assignment UI → payload fields → handler threading. Everything green (writer/verifier/reader/consumer) is **REUSED** substrate, edit-free. `project.json` (purple) is the observed deliverable.

---

## 2. Write-intent == verify-intent (R1 invariant)

```mermaid
sequenceDiagram
    participant H as _handle_save_dialog (NEW)
    participant WV as _write_and_verify_manifest (NEW)
    participant W as write_project_manifest (REUSED)
    participant V as verify_written_manifest (REUSED)
    participant FS as project.json (disk)

    H->>WV: batch=payload.batch, assignments=payload.assignments
    WV->>W: write(... batch=, assignments=)   %% app.py:3785/3786
    W->>FS: serialize active_variant + batch + assignments
    WV->>V: verify(... batch=, assignments=)   %% app.py:3803/3804 — SAME values
    V->>FS: re-read
    FS-->>V: re-read manifest
    V-->>WV: 0 drift (verify-intent == write-intent)
    WV-->>H: success notice
```

If write-intent and verify-intent differed, `verify_written_manifest` would report spurious drift (open risk R1). TC-302/303 asserts `verify_calls[-1] == write_calls[-1]` for both `batch` and `assignments`.

---

## 3. Refusal path — escaping entry (security boundary)

```mermaid
flowchart LR
    P["SaveProjectPayload<br/>batch/assignments hold an absolute/escaping entry"]:::new
    H["_handle_save_dialog → _write_and_verify_manifest"]:::new
    R["_reject_unsafe_entry (manifest_writer.py:178)<br/>sole path-safety authority"]:::reuse
    N["POSITIVE refusal notice<br/>'Manifest write failed'"]:::artifact
    X["project.json NOT written<br/>(no escaping entry persisted)"]:::artifact

    P --> H --> R
    R -->|refuse| N
    R -->|no file| X

    classDef new fill:#1f6feb,stroke:#0b3d91,color:#fff;
    classDef reuse fill:#2ea043,stroke:#176f2c,color:#fff;
    classDef artifact fill:#8957e5,stroke:#553098,color:#fff;
```

The UI's workarea restriction is convenience; `_reject_unsafe_entry` is the **enforcement point**, now reached end-to-end through the handler. AT-017.4 asserts the refusal notice is present AND `project.json` is not written.

---

## 4. `variant_id` keying — stem-collision (D-KEY)

```mermaid
flowchart TD
    VS["ProjectVariantSet.variants[*].variant_id"]:::reuse
    N1["normal case<br/>variant_id = filename stem (e.g. fw_a)"]:::reuse
    C1["stem-collision: fw.s19 + fw.hex<br/>variant_id = FULL filename (fw.s19 / fw.hex)"]:::reuse
    UI["_collect_composition keys each row from variant_id<br/>NEVER recomputes Path.stem"]:::new
    M["assignments == {'fw.hex': (...)}"]:::artifact
    CN["plan_variant_executions: assignments.get('fw.hex')<br/>picked up, not silently dropped"]:::reuse

    VS --> N1
    VS --> C1
    N1 --> UI
    C1 --> UI
    UI --> M --> CN

    classDef new fill:#1f6feb,stroke:#0b3d91,color:#fff;
    classDef reuse fill:#2ea043,stroke:#176f2c,color:#fff;
    classDef artifact fill:#8957e5,stroke:#553098,color:#fff;
```

A recomputed `Path.stem` on a colliding pair would key both variants to `fw`, and the consumer's `assignments.get(variant_id)` would silently drop the assignment. AT-017.5 proves the full-filename round-trip and pickup.

---

## NEW vs REUSED summary

| Element | Status | Where |
|---------|--------|-------|
| Per-variant assignment rows + project-wide batch input | **NEW** | `SaveProjectScreen` (`screens.py`) |
| `_collect_composition` (keys from `variant_id`) | **NEW** | `screens.py:298-303` |
| `SaveProjectPayload.batch` / `.assignments` fields | **NEW** | `screens.py` (default-empty) |
| `_write_and_verify_manifest(*, batch, assignments)` threading | **NEW** | `app.py` (write `:3785/3786`, verify `:3803/3804`) |
| `action_save_project` passes variant ids + candidates | **NEW** | `app.py:2637` |
| `write_project_manifest` / `_reject_unsafe_entry` | **REUSED** (edit-free) | `manifest_writer.py` |
| `verify_written_manifest` / `read_project_manifest` | **REUSED** (edit-free) | `manifest_writer.py` / `variant_execution_service.py` |
| `plan_variant_executions` consumer | **REUSED** (edit-free) | `variant_execution_service.py:526` |

**0 engine-frozen edits; writer + consumer substrate edit-free** (`git diff --name-only origin/main` over both = empty, per `04-validation.md` STEP 3.4).
