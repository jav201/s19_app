# Diagram (b) — data flow: parse → summer → A2L row severity

**What it shows:** how a derived `length` flows from `parse_a2l_file` through the post-axis-walk summer, into `tag["length"]`, through `enrich_tags_and_render`, and finally into the A2L view row's colour via `_a2l_tag_row_severity`. This is the output-then-consume chain that AT-108 exercises.

```mermaid
sequenceDiagram
    autonumber
    participant Caller as A2L service / caller
    participant Parse as parse_a2l_file / extract_a2l_tags
    participant Axis as axis_meta build loop
    participant Inline as _inline_axis_counts
    participant Span as _record_layout_full_span
    participant Tag as tag dict (length field)
    participant Enrich as enrich_tags_and_render (+ mem_map)
    participant Sev as _a2l_tag_row_severity
    participant Row as A2L view row

    Caller->>Parse: parse_a2l_file(path)
    Parse->>Axis: walk CHARACTERISTIC, build axis_meta[]
    Note over Axis: char_type, record_layout_name,<br/>per-axis kind / max_axis_points / external

    Parse->>Parse: gate — char_type in CURVE,MAP<br/>AND length is None?
    Parse->>Inline: _inline_axis_counts(axis_meta)
    alt derivable (STD_AXIS / FIX_AXIS, numeric)
        Inline-->>Parse: [n_x, n_y, ...]
        Parse->>Span: _record_layout_full_span(layout, counts)
        alt every line classifies, within 1 MiB cap
            Span-->>Tag: length = total (25 / 51 / 12)
        else unclassifiable / ALIGNMENT / over-cap
            Span-->>Tag: length = None (grey)
        end
    else external / empty / non-numeric
        Inline-->>Tag: length stays None (grey)
    end

    Tag-->>Caller: tags[] with length populated
    Caller->>Enrich: enrich_tags_and_render(a2l_data, mem_map)
    Note over Enrich: length + covering mem_map<br/>=> byte-range memory check applicable
    Enrich->>Sev: validated tag (memory_checked?)
    alt length derived AND image covers the bytes
        Sev-->>Row: OK (green) — memory-checked, present
    else length None (or bytes absent)
        Sev-->>Row: NEUTRAL (grey) — not memory-checked
    end
```

**Reading it:**
- The summer sits **inside the parse walk**, upstream of every consumer — so no service or view code changed; they all just read the now-populated `tag["length"]`.
- `enrich_tags_and_render` alone does **not** set the `sev-*` colour — the row severity comes from `_a2l_tag_row_severity` (app.py). A derived `length` is what makes the byte-range memory check *applicable*; a covering `mem_map` is what flips the row grey → green. AT-108 pins exactly this: revert the length to `None` over the same covering map and the row falls back to `memory_checked = False` / not-OK.
