# Executive Summary — batch-45 — Memory-Map entropy view

**Context.** During a field test on a real client firmware image, the Memory Map read as "mostly grey"
— it coloured cells only by validation status, telling the operator nothing about what each region
*contains*. A throwaway prototype explored three visualizations; the operator chose the "Band-Bands"
design.

**Problem.** The map's most valuable signal for a firmware engineer — entropy (is this region code,
calibration data, tables, or padding?) — was computed by the tool but never surfaced on the map. A
separate entropy pop-up existed but was easy to miss and showed one page at a time.

**Solution.** The map now visualizes entropy directly: a proportional band bar + a per-region list
(address · size · band), each colour- and texture-coded, plus a docked "at a glance" histogram and
sparkline. Clicking a region jumps straight to it in the hex view. The redundant entropy pop-up was
retired — its function now lives, always visible, in the map itself.

**Outcome.** Shipped as 6 supervised increments with zero high-severity findings, zero scope drift,
and zero changes to the frozen parsing/validation engine. The full test suite is green (1374 passed,
0 failed); nine black-box acceptance tests exercise the feature end-to-end through the real UI. Net
≈ −2100 lines of code (the retirement removed more than the feature added).

**Next steps.** A routine post-merge step regenerates ~20 visual snapshot baselines in the canonical
CI environment. The related field-audit items (a responsive patch-editor layout, Issues-panel paging
and filters) are queued as separate batches.
