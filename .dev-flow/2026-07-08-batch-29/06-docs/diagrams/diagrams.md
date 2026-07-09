# Diagrams · batch-29 — clipboard read cap + Issues DataTable retirement

## 1. Clipboard cascade + read cap (US-042 · R-TUI-044)

The cascade order is unchanged (R-TUI-043); batch-29 adds the single `_bound_clipboard_text` funnel so
every layer's result is length-capped before it is logged, returned, or pasted.

```mermaid
flowchart TD
  KV["User presses Ctrl+V in Load dialog"] --> AP["OsClipboardInput.action_paste (async)"]
  AP --> ROC["read_os_clipboard(strategies=None → _STRATEGIES)"]
  ROC --> S1{"tk: tkinter.Tk().clipboard_get()"}
  S1 -->|non-None| CAP
  S1 -->|None| S2{"ctypes: Win32 GetClipboardData(CF_UNICODETEXT)"}
  S2 -->|non-None| CAP
  S2 -->|None| S3{"powershell.exe Get-Clipboard -Raw"}
  S3 -->|non-None| CAP
  S3 -->|None / all fail| RN["return None"]
  CAP["_bound_clipboard_text: text[:65536] (CAP)"] --> LOG["debug-log len=%d (post-cap length)"]
  LOG --> RET["return capped prefix (never None)"]
  RET --> SL["action_paste inserts splitlines()[0] of the bounded value"]
  SL --> VAL["OsClipboardInput.value = bounded first line"]
  RN --> FB["fallback: App.clipboard buffer"]
  FB -->|empty| WARN["app.notify(severity=warning): use Ctrl+Shift+V / type path"]
```

**Note (R-044-1).** The cap is a bound on all *downstream* use. Each reader (tk/ctypes/PS) still
transiently materializes the full OS-clipboard string before `_bound_clipboard_text` applies — the true
source bound is the deferred, named-not-built LLR-044.6.

---

## 2. Issues screen: before → after (US-043 · extends R-TUI-042)

batch-28 left the legacy DataTable mounted as a `display:none` shim beside the grouped panel; batch-29
removes it so `GroupedIssuesPanel` is the sole surface.

```mermaid
flowchart LR
  subgraph B["BEFORE (batch-28)"]
    B0["#issues_list_stack"] --> B1["#validation_issues_list<br/>DataTable (display:none, hidden shim)"]
    B0 --> B2["GroupedIssuesPanel<br/>#validation_issues_groups"]
  end
  subgraph A["AFTER (batch-29)"]
    A0["#issues_list_stack"] --> A2["GroupedIssuesPanel<br/>#validation_issues_groups (sole surface)"]
  end
  B -->|"remove DataTable compose + CSS + column-init<br/>+ populate + row-key map + row-select branch<br/>(0 source hits of #validation_issues_list)"| A
```

### `IssueRow` node structure (after)

Each `IssueRow.compose` yields three `safe_text` (literal `rich.text.Text`) nodes. The `.issue-related`
node is restored in batch-29 (invisible since batch-28).

```mermaid
flowchart LR
  IR["IssueRow.compose (issues_view.py)"] --> C1[".issue-code-chip<br/>safe_text(issue.code or '-')"]
  IR --> C2[".issue-detail<br/>safe_text(symbol · address · message)"]
  IR --> C3[".issue-related  ← RESTORED<br/>safe_text(', '.join(related_artifacts) or '-')"]
  C1 -. sev-* .-> POL["frozen css_class_for_severity"]
  C3 -. safe_text = literal Text, no markup .-> SAFE["C-17: brackets / [link] render literal"]
```

---

## 3. Load → issue → grouped render → hex peek (sequence)

Preserved end-to-end after the retirement: summary and paging never depended on the DataTable, and
selection still drives the hex peek through `on_issue_row_selected`.

```mermaid
sequenceDiagram
    participant U as User
    participant W as Load worker
    participant M as LoadedFile snapshot
    participant V as update_validation_issues_view
    participant G as _render_validation_issues_groups
    participant P as GroupedIssuesPanel
    participant H as #issues_hex_pane

    U->>W: load S19/A2L/MAC (through frozen parsers + validation engine)
    W->>M: _validation_issues + ranges (no new parse on UI thread)
    M->>V: apply on UI thread
    V->>V: compute #validation_issues_summary counts
    V->>G: render (empty + populated paths)
    G->>P: IssueGroupHeader × severity (whole-filtered count)
    G->>P: IssueRow × windowed issue (<= _GROUP_DISPLAY_MAX = 40)
    Note over P: each IssueRow = code chip · detail · .issue-related (all safe_text)
    U->>P: select an IssueRow (click / Enter)
    P->>V: IssueRow.Selected → on_issue_row_selected
    V->>H: _update_issues_hex_pane
    alt issue carries an address
        H-->>U: repaint bytes at 0x… (changes)
    else address is None
        H-->>U: neutral placeholder (no stale bytes)
    end
```
