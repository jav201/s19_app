# Diagram — Patch Editor responsive-regime state (batch-46)

> Accurate to `styles.tcss:800-840` and the existing App toggle `_apply_width_regime`/`on_resize`
> (`app.py:4903-4940`). The switch is **pure CSS** reusing the existing `width-narrow` class — `app.py`
> diff = 0, no new breakpoint, resize handler, or `TabbedContent`. The regime is keyed on terminal width
> crossing 120 columns, which toggles `width-narrow` on `#workspace_body`; the patch CSS selectors fire
> automatically because `#patch_editor_panel` is a `#workspace_body` descendant.

```mermaid
stateDiagram-v2
    [*] --> WIDE

    WIDE: WIDE regime (>= 120 cols)
    WIDE: #patch_editor_panel { layout: horizontal }
    WIDE: 3 windows side-by-side, PATCH SCRIPT 2fr / CHECKS 1fr / JSON 1fr
    WIDE: each .patch-window height 100%, its body scrolls internally
    WIDE: AT-063a → 3 distinct region.x, no overlap, no right-edge clip

    NARROW: NARROW regime (< 120 cols, incl. 80x24 floor)
    NARROW: #workspace_body.width-narrow #patch_editor_panel { layout: vertical; overflow-y: auto }
    NARROW: .patch-window width 100%, height auto — windows stack, the PANEL scrolls
    NARROW: AT-063b → 1 distinct region.x, 3 ascending region.y

    WIDE --> NARROW: on_resize width < 120<br/>→ add .width-narrow (app.py:4930)
    NARROW --> WIDE: on_resize width >= 120<br/>→ remove .width-narrow

    note right of WIDE
        Buttons docked as body siblings.
        @120x30: strict target off == [] at scroll 0
        (D-3 fallback ladder available; not needed).
    end note

    note right of NARROW
        @80x24: FOLD-8 reachable-under-scroll —
        each button visible once its window scrolls
        into the ~5-row panel viewport; none trapped
        below an inner-body fold.
    end note
```

**How to read it.** There is exactly one boolean of layout state: the presence of the `width-narrow` class,
driven entirely by the pre-existing App resize handler (no batch-46 Python). Crossing 120 columns flips the
regime declaratively — reverting the whole feature is deleting the CSS rules. The docked-button structure is
identical in both regimes (buttons are always body siblings); only the acceptance threshold differs, because
the frozen app viewport gives the narrow floor only ~5 rows (hence FOLD-8 reachable-under-scroll) versus the
strict all-visible target at the wide 120×30 regime.
