# Batch 2026-06-24-batch-15 — A<->B Diff compare flow (US-016)

> Fixed compare handler: a side whose source file has content but maps to an empty image is now caught and surfaced as a RED `sev-error`, instead of slipping through as a GREEN `sev-ok` verdict. New / changed nodes are marked with the `changed` class.

```mermaid
flowchart TD
    A["#diff_compare_button pressed"] --> B["on_ab_diff_panel_compare_requested"]
    B --> C["compare_images(A_path, B_path)"]
    C --> D{"refused?<br/>(path unresolved / unreadable)"}
    D -->|yes| E["sev-error: refusal"]:::existing
    D -->|no| F["_diff_load_maps:<br/>re-parse each side"]
    F --> G{"NEW: any side with<br/>non-empty source file<br/>but EMPTY memory map?"}:::changed
    G -->|yes| H["collect failed_sides"]:::changed
    H --> I["sev-error:<br/>'Compare failed: &lt;side&gt; loaded no image<br/>(file has content but no valid records).'"]:::changed
    G -->|no| J["sev-ok:<br/>render differing runs"]:::existing

    classDef existing fill:#1f6f3f,stroke:#0d3,color:#fff;
    classDef changed fill:#7a1f1f,stroke:#f44,color:#fff,stroke-width:2px;
```

**Caption:** The new load-failure decision (red nodes) sits between the existing refusal check and the existing `sev-ok` render path, so a non-empty file that maps to nothing is reported by name instead of passing as a clean compare.
