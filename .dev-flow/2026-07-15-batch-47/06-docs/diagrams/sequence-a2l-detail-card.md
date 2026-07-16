# Diagram — Sequence: A2L row highlight → detail card (C-17-safe render)

> **Why this flow.** It is the batch's most representative path: a NEW handler, a NEW widget, a
> pre-computed data read, and a **gate-blocking C-17 sink** — all in one interaction. Accurate to the
> shipped code at HEAD `12c5d1c`. Requirement: HLR-069 / R-TUI-069 (LLR-069.1–069.4). ATs: `AT-069`,
> `AT-069b ★`, `AT-069c ★`.

## 1. Main flow — highlight a tag row

```mermaid
sequenceDiagram
    actor An as Firmware analyst
    participant DT as DataTable<br/>#a2l_tags_list
    participant App as S19TuiApp<br/>(app.py)
    participant Tags as _a2l_enriched_tags<br/>list[dict] (pre-computed)
    participant Card as A2LDetailCard<br/>#a2l_detail_card (app.py:734)
    participant Txt as _a2l_detail_card_text<br/>(app.py:668) + _card_field
    participant Safe as safe_text = Text(value)<br/>(screens_directionb.py:615)

    Note over DT,Card: Table cells were already built C-17-safe at populate time —<br/>_build_a2l_table_cells (app.py:9542) returns tuple[Text, ...]<br/>(all 16 cells are Rich Text, never str) — AT-069c ★

    An->>DT: move cursor (arrow key / click)
    DT-->>App: DataTable.RowHighlighted(cursor_row)
    Note right of App: NEW handler (LLR-069.2).<br/>RowHighlighted, not RowSelected —<br/>live feedback on cursor move.
    App->>App: on_data_table_row_highlighted (app.py:6345)
    App->>App: guard — is the event from #a2l_tags_list?
    alt event from another table
        App-->>DT: return (inert — no card update)
    else event from #a2l_tags_list
        App->>Tags: resolve tag dict for the highlighted row
        Note right of Tags: READ ONLY of a pre-computed list.<br/>No parse, no enrichment, no engine call.
        Tags-->>App: tag: dict | None
        App->>Card: show_tag(tag)
        Note right of Card: The widget's ONLY new member is show_tag.<br/>set(dir(Widget)) ∩ {show_tag} == ∅ →<br/>no _nodes / _context shadowing (C6 / R4).
        Card->>Txt: _a2l_detail_card_text(tag)

        alt tag is None
            Txt-->>Card: Text(placeholder / hint)
        else tag present
            loop for each field: description, unit·conversion,<br/>record layout, byte order, limits
                Txt->>Safe: safe_text(field_value)
                Note right of Safe: ⚠️ file-derived + UNTRUSTED.<br/>Text(value) — NEVER Text.from_markup,<br/>NEVER an f-string into markup (MN-5 / F4).
                Safe-->>Txt: Text (no markup to parse)
                Txt->>Txt: _card_field → text.append(label) + append(Text)
                Note right of Txt: Composition happens AT THE Text LEVEL.<br/>A str would be markup-parsed by Textual.
            end
            Txt-->>Card: Text (composed)
        end

        Card->>Card: update(text)
        Card-->>An: card renders the highlighted tag's metadata
        Note over Card,An: Hex view sits BELOW the card in the same #a2l_hex_pane —<br/>no new pane. C-29-measured: card h=5, hex not occluded @80×24 (LLR-069.4).
    end
```

## 2. The C-17 negative control (`AT-069b ★`) — same path, hostile input

```mermaid
sequenceDiagram
    participant Fx as Hostile A2L fixture
    participant Txt as _a2l_detail_card_text
    participant Safe as safe_text = Text(value)
    participant Card as A2LDetailCard
    participant AT as AT-069b ★<br/>test_tui_a2l_detail.py::test_at069b_c17_card

    Fx->>Txt: description = "[red]X[/red] [link=http://x]u[/link]<br/>\x1b[31mX\x1b[0m sensor[unclosed"
    Txt->>Safe: safe_text(description)
    Safe-->>Txt: Text — payload stored as LITERAL characters
    Txt-->>Card: composed Text
    Card->>AT: rendered card content

    AT->>AT: assert full MD-1 payload verbatim in Text.plain
    AT->>AT: assert NO payload-derived span
    AT->>AT: assert NO MarkupError raised

    Note over AT: "sensor[unclosed" is the DISCRIMINATING counterfactual —<br/>under Text.from_markup it would raise or mis-span.<br/>That is what makes this AT genuine, not vacuous.
```

## 3. What the flow demonstrates about the batch

| Property | Where it shows up above |
|---|---|
| **Render-only** | The handler *resolves* a tag from `_a2l_enriched_tags`. It never parses, enriches, or calls the engine. |
| **Safe by construction, not by patching** | `safe_text = Text(value)` at every field; composition stays at the `Text` level end-to-end. There is no point in the path where a `str` could be markup-parsed. |
| **Two distinct sinks, two ATs** | The **card** (`AT-069b`) and the **table cell** (`AT-069c`) are separate sinks. Neither AT covers the other — the table cells were already `Text` at populate time, before this flow begins. |
| **Geometry measured, not assumed (C-29)** | The card's height (5) and the surviving hex rows were pilot-measured in the real `#a2l_hex_pane` at both 80×24 and 120×30 before the split was fixed. |
| **Shadowing checked (C6)** | `show_tag` is the widget's only new member — a `_nodes`/`_context` collision would have produced a silent mount crash with no traceback. |
