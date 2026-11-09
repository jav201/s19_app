# Inc 12 — independent E4 code pre-review

Read-only review by an independent Kimi explore agent of `24030a6d` against the eight requirements, graph and rulings. No code or tests executed.

Initial verdict: **FAIL** — one MEDIUM impl and one LOW impl.

- MEDIUM: `_build_a2l_table_cells` normalized the raw name with `.replace("\n", " ").strip()` before the U+FFFD projection, deleting characters R-TUI-042a.6 retains. Routed in `E4-review-rulings.md`; a discriminating `A ` arm was added to `.6/3`.
- LOW: three stale docstrings in `_compose_screen_a2l`, `update_a2l_tags_view` and `_repaint_a2l_tag_cells`.

Targeted re-review of `2e441e16` by the same independent reviewer: **PASS**. The raw name reaches `_shorten_tag_name` unchanged; no markup, control or width regression was found. All three docstrings are corrected.

Security pre-review by a separate independent Kimi explore agent: **PASS-WITH-NOTES**, read-only. It confirmed O(width) slicing, the full C0/DEL/C1 card scrub, break-run mapping, every card append site and the Name-line condition. It left the exact hostile-tail, screen-output, break and Name-line executions to the suite and mutants; those are not claimed by this static verdict.
