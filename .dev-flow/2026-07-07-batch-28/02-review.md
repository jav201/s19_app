# 02 — Cross-agent review · batch-28 (R-TUI-042 v2)

**BLUF:** Three parallel reviewers (architect · qa-reviewer · security-reviewer) — **0 blockers**,
**8 majors**, **8 minors**. The requirements are fundamentally sound (traceability intact,
normative keywords clean, C-17 design correct + verified against source, C-13 arithmetic sound).
Majors are spec gaps in the two *reused-machinery* stories (Issues grouping vs the existing
filter/paging; A2L fixed-header feasibility + a vacuous AT). All accepted majors folded into
`01-requirements.md` v2.1 (§6.5) → Phase-2 gate approved under standing authorization.

## Findings & disposition

| # | Src | Sev | Finding | Disposition |
|---|-----|-----|---------|-------------|
| S1 | sec | major | Issues grouped view has no bounded-render/paging requirement → hostile file with O(N) bad records mounts O(N) chip widgets → TUI DoS. The current flat render pages `_validation_issues` (`app.py:5605-5608`). | **ACCEPTED** → new **LLR-042.6** preserves the existing paging window / caps mounted rows; new **AT-039f** seeds large-N, asserts bounded mount. |
| A2 | arch | major | Grouping collides with the existing severity filter (`issues_filter_all/error/warning`, `app.py:1298-1300`) — unspecified interaction. | **ACCEPTED** → LLR-042.6: the filter is preserved and **scopes** which issues the grouped view renders; groups/counts reflect the filtered set. |
| A3 | arch | major | Grouping vs existing paging + count scope unspecified (whole-list vs per-page count). | **ACCEPTED** → LLR-042.6: per-group header count = whole (filtered) list; paging window bounds mounted rows; truncation note beyond the window. |
| Q1/A4 | qa/arch | major | AT-038a vacuous (columns always in model; header fixed by default) + LLR-042.1 mis-cites `#a2l_scroll` (that is the Workspace context pane, not the `#a2l_tags_list` DataTable). Fixed-header feasibility hinges on the DataTable (not an outer scroll) owning row scrolling. | **ACCEPTED** → LLR-042.1 reframed verify-not-build (DataTable owns scroll); AT-038a drives a **real** `pilot.press("pagedown")` on the focused table, asserts `scroll_offset.y > 0` **and** header still shown. |
| Q2 | qa | major | AT-039b asserts errors→warnings→info order but the cited `_make_issues` seeds only ERROR+WARNING — the INFO branch is unverifiable. | **ACCEPTED** → AT-039b seeds a set with ≥1 INFO (extend seeder); assert all 3 headers in order. |
| Q3 | qa | major | AT-039a "code as a chip" collapses to a substring check unless the grouped view exposes queryable nodes. | **ACCEPTED** → LLR-042.6 exposes `.issue-group-header` (severity + integer count) + `.issue-code-chip` nodes; AT-039a asserts the structural elements. |
| A1 | arch | minor | BLUF/§6.5 say "4 HLR" but §3 defines 6 `shall` clauses (3 story-anchors). | FIXED — state "3 HLR anchors / 6 clauses". |
| A5/Q | arch/qa | minor | "coverage micro-bar" is a misnomer (per-range bar = range-magnitude + validity, not covered-fraction; the stat-pane coverage % IS real coverage). | FIXED — labelled "range-magnitude bar (not covered-fraction)" at first use. |
| A6 | arch | minor | §4 note mislabels LLR-042.11 as "the frozen invariant" (that is .12); old→new map incomplete. | FIXED. |
| A7 | arch | minor | Citation drift: `_validation_issues` at `:766` (not 764); A2L populate at `:7862` (not 7827). | FIXED — anchors corrected; re-verify in Phase 3. |
| Q4 | qa | minor | AT-038b density: measure the density **class** (`.has_class("density-compact")`), not a row-height metric. | ACCEPTED → AT-038b asserts the density class on a queryable container. |
| Q5 | qa | minor | TC-042.1 confirm-default — add the positive `scroll_offset.y > 0` evidence so it can fail. | ACCEPTED (folded with Q1). |
| S2 | sec | minor | AT-039e should explicitly assert **no OSC-8 hyperlink escape** from `[link=file:///etc]` (distinct from CSI styling). | ACCEPTED → AT-039e wording tightened. |
| S3 | sec | minor | US-038 density refactor could accidentally flip `markup=False→True` (batch-27 B-1 class); nothing guards it. | ACCEPTED → TC-042.2 asserts A2L cells remain `Text` instances (markup not enabled) after the polish. |
| A8 | arch | minor | Empty-state ATs (039d/040d) not row-traced — optional. | NOTED as cross-cutting empty-state guards. |

## Clean axes (explicitly affirmed by ≥1 reviewer)
- **Normative keywords** — no `should`/`debería` inside any HLR/LLR statement (architect, BLOCKER axis clean).
- **Derivation** — every HLR→US, every LLR→parent, no orphan, no US-less HLR (architect).
- **C-17 core** — scrubber verified (`model.py:71-72,137`): `.message` ANSI-only, `.symbol`/`.code` unscrubbed → render layer is the sole defense; LLR-042.10 names all 3 fields explicit-`Text`; AT-039e exercises all 3 + ANSI on code/symbol (qa + security, "strong").
- **File-derived census COMPLETE** — only Code/Symbol/Message are file-influenced; Artifact/Related app-controlled; Address/Line numeric; A2L table already `Text`-safe (`app.py:7896`); Workspace surfaces numeric (security).
- **Engine-frozen integrity** — 0-diff mandated, fix panel-side, colour via read-only policy (security).
- **No external-write/outbound surface**; memory-strip + micro-bar DoS-clean (bounded/reused) (security).
- **C-16** — AT-039c drives real click/select, non-default, asserts changed + address-None branch (qa).
- **C-13 geometry** — 76/98 body arithmetic checks out; micro-bar risk correctly flagged+constrained; vertical flags placed (architect).

## Evidence checklist
- ✓ architect: derivation/keywords/§6.5/geometry verified against §3-6 + spot-checked disk.
- ✓ qa: surfaces + helpers (`_seed_issues_screen`, `_update_issues_hex_pane`, `coverage_stats`, `cell_status`, density precedent) probed present; C-16/C-17 scoping confirmed.
- ✓ security: scrubber read at source; census complete; frozen integrity + DoS assessed.
- ✓ 0 blockers; 8 majors accepted+folded; 8 minors fixed/accepted; dispositions cited.
