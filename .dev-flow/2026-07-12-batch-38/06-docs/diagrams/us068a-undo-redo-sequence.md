# US-068a — Change-set undo/redo (R-TUI-057)

> edit → push snapshot → undo → restore. Accurate to `s19_app/tui/services/change_service.py` (`_HISTORY_MAX=20:92`, `_push_history`, `undo:445`, `redo:474`) and the `#patch_undo_button` / `#patch_redo_button` wiring in `screens_directionb.py` + `app.py`. A-01 guard: controls disabled when `document.source_path is not None`.

```mermaid
sequenceDiagram
    autonumber
    actor U as Operator
    participant Panel as PatchEditorPanel
    participant App as S19TuiApp (handlers)
    participant CS as ChangeService
    participant UndoS as _undo_stack (bounded _HISTORY_MAX=20)
    participant RedoS as _redo_stack

    Note over Panel: A-01 guard — set_undo_redo_enabled(source_path is None);<br/>Undo/Redo DISABLED for a file-backed document

    U->>Panel: Edit change-set (add / edit / remove / paste-load)
    Panel->>App: (mutation message)
    App->>CS: add_entry / edit_entry / remove_entry / load_text
    CS->>UndoS: _push_history(deep-copy snapshot of prior document)
    Note over UndoS: evict oldest past _HISTORY_MAX
    CS->>RedoS: clear (fresh mutation invalidates redo)
    CS-->>App: mutated document
    App->>Panel: refresh_entries() -> table shows N+1 rows

    U->>Panel: click Undo (#patch_undo_button)
    Panel->>App: UndoRequested
    App->>CS: undo()
    alt _undo_stack non-empty
        CS->>RedoS: push current document
        CS->>UndoS: pop -> restore prior snapshot as document
        CS-->>App: prior document (true deep copy, no alias)
        App->>Panel: refresh_entries() -> table back to N rows
    else empty history
        CS-->>App: document unchanged (no-op)
    end

    U->>Panel: click Redo (#patch_redo_button)
    Panel->>App: RedoRequested
    App->>CS: redo()
    alt _redo_stack non-empty
        CS->>UndoS: push current document
        CS->>RedoS: pop -> re-apply snapshot as document
        CS-->>App: re-applied document
        App->>Panel: refresh_entries() -> table back to N+1 rows
    else empty redo
        CS-->>App: document unchanged (no-op)
    end
```
