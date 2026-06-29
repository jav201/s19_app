# Diagrams — batch-19 (Feature #10 issues-report addendum)

## 1. Declared region: dialog → report addendum (US-020c)

```mermaid
flowchart LR
    TA["ReportViewerScreen<br/>#report_declared_regions TextArea"] -->|Generate| P["_parse_declared_regions<br/>(name,start,end; hex/dec; skip malformed)"]
    P --> GR["GenerateRequested.declared_regions"]
    GR --> H["app: handler → _trigger → worker<br/>(4-hop thread)"]
    H --> RO["ReportOptions.declared_regions"]
    RO --> AL["_addendum_lines<br/>(per region: mods + issues whose address ∈ [start,end])"]
    AL --> RPT["reports/&lt;ts&gt;-report.md<br/>## Addendum: declared regions"]
    VI["ValidationIssue.address<br/>(frozen, read-only)"] -.same source.-> AL
    VI -.same source.-> DE["_declaration_error_lines<br/>(issue enrichment, US-020d)"]
    DE --> RPT
```

## 2. DeclaredRegion construction (security-F1 + bounds)

```mermaid
flowchart TD
    IN["DeclaredRegion(name, start, end)"] --> SCRUB["name = _scrub_issue_message(name, cap 80)<br/>(strip control/ANSI, length-cap — security-F1)"]
    SCRUB --> V{validate}
    V -->|name empty after scrub| E1["ValueError"]
    V -->|start &lt; 0| E2["ValueError"]
    V -->|start &gt; end| E3["ValueError"]
    V -->|ok| OK["frozen DeclaredRegion<br/>contains(addr) = start ≤ addr ≤ end (INCLUSIVE)<br/>(≠ CrcRegion half-open — architect-M1)"]
```

## 3. Persistence roundtrip (US-020c, LLR-026.1)

```mermaid
flowchart LR
    R["declared_regions"] --> SER["serialize_manifest<br/>(optional key, ONLY when non-empty → back-compat)"]
    SER --> PJ["project.json<br/>declared_regions: [{name,start,end}]"]
    PJ --> RD["read_project_manifest →<br/>_parse_manifest_declared_regions"]
    RD -->|absent/empty| EMPTY["() — no finding"]
    RD -->|malformed/invalid entry| ISS["+ MANIFEST-BAD-STRUCTURE issue, skip<br/>(collect-don't-abort)"]
    RD -->|valid| OUT["ProjectManifest.declared_regions<br/>(name re-scrubbed on read)"]
```
