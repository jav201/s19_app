# US-066 — Oversized A2L address WARNING data flow (R-TUI-055)

> A2L load → `validation_service` → `GroupedIssuesPanel`. Accurate to `s19_app/tui/services/validation_service.py` (`supplemental_a2l_oversized_address_issues:111`, code `A2L_ADDRESS_EXCEEDS_32BIT:179`, merged into both branches of `build_validation_report`) and the markup-safe render in `s19_app/tui/issues_view.py`.

```mermaid
sequenceDiagram
    autonumber
    actor U as Operator
    participant App as S19TuiApp (load handler)
    participant VS as validation_service.build_validation_report
    participant Prod as supplemental_a2l_oversized_address_issues
    participant Model as ValidationIssue (validation/model.py, frozen)
    participant Panel as GroupedIssuesPanel
    participant Safe as issues_view.safe_text (markup-safe)

    U->>App: Load A2L (contains tag @ 0x100000000)
    App->>VS: build_validation_report(...)
    VS->>Prod: for each effective A2L tag
    Note over Prod: address is int AND > 0xFFFFFFFF ?
    alt address > 0xFFFFFFFF (e.g. 0x100000000)
        Prod->>Model: ValidationIssue(code="A2L_ADDRESS_EXCEEDS_32BIT",<br/>severity=WARNING, artifact="a2l",<br/>symbol=tag_name, address=addr)
        Model-->>Prod: issue (message scrubbed: control/ANSI stripped,<br/>brackets kept literal)
    else address == 0xFFFFFFFF | None | non-int
        Prod-->>VS: no issue (boundary exclusive)
    end
    Prod-->>VS: [oversized WARNINGs]
    Note over VS: merge into BOTH branches<br/>(MAC-only + primary-backed) before dedupe_issues
    VS-->>App: ValidationReport(issues=[... WARNING ...])
    App->>Panel: update_validation_issues_view(report.issues)
    Panel->>Safe: render symbol / address / message as literal Text
    Note over Safe: css_class_for_severity(WARNING) -> sev-warning;<br/>hostile tag name renders verbatim, 0 MarkupError (C-17)
    Panel-->>U: WARNING row under the WARNING group,<br/>naming the offending tag
```
