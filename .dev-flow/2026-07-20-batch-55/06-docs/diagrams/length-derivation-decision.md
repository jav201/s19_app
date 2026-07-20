# Diagram (a) — length-derivation decision path

**What it shows:** the decision logic that sets a CURVE/MAP tag's `length`, from the char_type gate through the inline-axis check, the external gate, the RECORD_LAYOUT span sum, the 1 MiB cap, and the final value-or-None. Mirrors `_inline_axis_counts` + `_record_layout_full_span` + the post-axis-walk wiring in `s19_app/tui/a2l.py`.

```mermaid
flowchart TD
    A["CHARACTERISTIC parsed<br/>axis_meta built"] --> B{"char_type in CURVE, MAP<br/>AND length is None?"}
    B -->|no| Z1["keep existing length<br/>(VALUE / MEAS / already-sized<br/>/ CUBOID / no-kind untouched)"]
    B -->|yes| C["axis_counts = _inline_axis_counts(axis_meta)"]

    C --> D{"axis_meta empty?"}
    D -->|yes| N1["length = None (grey)"]
    D -->|no| E{"every axis kind in<br/>_DERIVABLE_AXIS_KINDS<br/>(STD_AXIS / FIX_AXIS)?"}
    E -->|no — external kind| N2["length = None (grey)<br/>COM_AXIS / RES_AXIS / CURVE_AXIS"]
    E -->|yes| F{"any axis external flag?<br/>(AXIS_PTS_REF)"}
    F -->|yes| N3["length = None (grey)<br/>storage in separate AXIS_PTS record"]
    F -->|no| G["base-10 int(max_axis_points)<br/>inside try/except"]

    G --> H{"cast ok AND count > 0?"}
    H -->|no — 'x' / '9'*5000 / '0' / None| N4["length = None (grey)<br/>no exception (collect-don't-abort)"]
    H -->|yes — '08' -> 8| I["axis_counts ready<br/>resolve RECORD_LAYOUT by name"]

    I --> J{"layout present?"}
    J -->|no| N5["length = None (grey)"]
    J -->|yes| K["_record_layout_full_span:<br/>iterate layout lines"]

    K --> L{"line classification"}
    L -->|empty / whitespace| K
    L -->|NO_AXIS_PTS_* -> 1<br/>AXIS_PTS_X/Y/Z -> n_x/n_y/n_z<br/>FNC_VALUES -> prod(counts)| M{"datatype token[2]<br/>in DATATYPE_SIZES?<br/>(needed axis count present?)"}
    L -->|"any other non-empty line<br/>(ALIGNMENT_* / unknown component)"| N6["length = None (grey)<br/>full-span-or-None: never under-report"]
    M -->|no| N6
    M -->|yes| O["total += size * element_count"]

    O --> P{"total > MAX_A2L_DECODE_BYTES<br/>(1 MiB)?"}
    P -->|yes| N7["length = None (grey)<br/>DoS cap"]
    P -->|no, more lines| K
    P -->|no, done| Q{"any component contributed?"}
    Q -->|no| N8["length = None (grey)"]
    Q -->|yes| R["length = total<br/>(25 / 51 / 12 ...) -> memory-checkable"]
```

**Reading it:**
- The **left/early exits** (`Z1`) preserve the no-regression contract — the summer only ever fills a still-`None` CURVE/MAP length.
- Every `N*` node is an **honest grey** outcome, never a wrong number. The external gate (`N2`/`N3`) is the false-green anchor (AT-106).
- The single **green/value** exit `R` is reached only when every axis and every component classifies (full-span-or-None).
