# Increment 6 — REQUIREMENTS.md traceability amendments (§6.5) — PHASE 3 CLOSE

1. **What changed (doc-only):** ADD R-TUI-060 (band bar + textured region list + legend), R-TUI-061
   (At-a-glance histogram + sparkline), R-TUI-062 (single-click region→hex) — each Code/Validation
   (Automated, real test names)/Status. AMEND R-TUI-041 with a §6.5 Before→After block (cell colour
   validity→entropy band; two-step→single-click; stats strip RETAINED in #map_stats; render-only +
   width-narrow + R-3 A2L naming preserved). RETIRE R-TUI-050 (paging/sort) + R-TUI-051 (legend +
   clickable strip) with Before→After + historical record kept.
2. **Files (1):** REQUIREMENTS.md.
3. **How to test:** grep gates + markdown structure + batch-surface sanity.
4. **Results:** 62 R-TUI rows; R-TUI-060/061/062 present w/ Code+Validation+Status; R-TUI-050/051
   `RETIRED/Superseded`; R-TUI-041 `Amended`; `EntropyViewerScreen` only in the 2 retired rows (never
   live). Sanity `pytest -k "at069 or at072 or at074 or at075"` = 4 passed.
5. **Risks:** none (doc-only; retired rows keep historical Code/Validation by convention).
6. **Pending:** post-merge canonical-CI snapshot regen (2 map cells); frozen a2l.py:926 ruff carry
   (unrelated).
7. **Next:** Phase 4 validation gate (orchestrator-owned full-suite run, C-25).

Review: orchestrator (doc-only, before/after discipline verified). APPROVE. **PHASE 3 CLOSED:** 6
increments (Inc-2 split 2a/2b, Inc-5 split 5a/5b), 0 HIGH batch-wide, 0 frozen diffs, C-17 preserved
on a live path.
