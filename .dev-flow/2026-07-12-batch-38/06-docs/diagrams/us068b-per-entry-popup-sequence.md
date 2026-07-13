# US-068b — Per-entry JSON edit popup (R-TUI-058)

> select row → `EntryJsonScreen` → `edit_entry_json` → refresh. Accurate to `#patch_entry_edit_json_button` (`screens_directionb.py:1971`), `EntryJsonScreen` (`screens.py:255`), and `ChangeService.edit_entry_json:738` (routed through the validated `parse_change_document` seam). A-01 guard: control disabled when `document.source_path is not None`.

```mermaid
sequenceDiagram
    autonumber
    actor U as Operator
    participant Panel as PatchEditorPanel
    participant App as S19TuiApp (handler)
    participant CS as ChangeService
    participant Modal as EntryJsonScreen (single-entry)
    participant Parse as parse_change_document (validated seam)

    Note over Panel: A-01 guard — set_entry_edit_json_enabled(source_path is None);<br/>control DISABLED for a file-backed document

    U->>Panel: select entry i in #patch_doc_entries_table
    U->>Panel: click "Edit JSON" (#patch_entry_edit_json_button)
    Panel->>App: EntryEditJsonRequested(index=i)
    App->>CS: entry_seed_json(i)
    CS-->>App: single-entry JSON (no "entries" key)
    App->>Modal: push_screen(EntryJsonScreen(seed), callback)
    Modal-->>U: popup seeded with entry i's JSON only

    alt Confirm with edited text
        Modal-->>App: dismiss(edited_text)
        App->>CS: edit_entry_json(i, edited_text)
        CS->>CS: _push_history(snapshot)  %% history-eligible
        CS->>Parse: one-entry envelope (live header + edited entry)
        alt parses to exactly one valid entry
            Parse-->>CS: parsed entry
            CS->>CS: replace entries[i] only (siblings byte-identical)
            CS-->>App: ok result
            App->>Panel: refresh_entries() -> row i reflects edit
        else malformed / rejected
            Parse-->>CS: ERROR (MF-JSON-PARSE)
            CS-->>App: not-ok result, document UNCHANGED (no mutation, no crash)
            App-->>U: collect-don't-abort finding surfaced
        end
    else Cancel
        Modal-->>App: dismiss(None)
        Note over App: no mutation
    end
```
