# PLAN — batch-29 (2026-07-08) · clipboard cap + legacy DataTable retirement

**Living compendium.** Updated at every gate + significant checkpoint. Human-readable mirror of `state.json`.

## Where we are
- **Phase 3 COMPLETE (all 4 increments self-gated under standing auth); Phase 4 validation in progress.** DataTable retired (Inc4), GroupedIssuesPanel sole Issues surface, related-artifacts restored (R8). **Full suite: 1157 passed / 2 skipped / 23 xfailed / 0 failed** (18 min); 0 frozen diffs; `#validation_issues_list` gone from source. Ledger **1171 → 1182**. All 13 LLR covered on disk.
- **Operator asleep — standing auth:** finish Phase 4/5/6 + commit → PR → review → MERGE → /dev-flow-sync autonomously; report decisions at end.

## Increment outcomes
| Inc | Scope | Review | Result |
|-----|-------|--------|--------|
| 1 | US-042 clipboard cap | 0 HIGH/0 MED | 1171→1180; B-1 fix honored |
| 2 | US-043 restore `.issue-related` (R8) | 0 HIGH/1 MED (fixed) | 1180→1181 |
| 3 | US-043 migrate census readers | 0 HIGH/0 MED | 1181 (in-place); async trap fixed |
| 4 | US-043 remove DataTable (R1–R7) | 0 HIGH/0 MED | 1181→1182; full suite green |

## Objective
Fix the two clipboard/UI items that block or burden tool functionality (operator-scoped):
- **US-042** — bound the PowerShell clipboard read against oversized clipboards (backlog #1). `_read_via_powershell` uses `subprocess.run(capture_output=True)` → reads ALL of stdout into memory; `_POWERSHELL_TIMEOUT_S=0.5` bounds wall-clock, **not memory**. A huge clipboard can spike memory / hang Ctrl+V in the Load dialog.
- **US-043** — fully retire the hidden legacy `#validation_issues_list` DataTable (batch-28 left it `display:none`, still mounted + populated) so `GroupedIssuesPanel` is the sole Issues surface.

Out of scope (operator-filtered): backlog #2 (`<1s` benchmark — CI guard, not a functional blocker), backlog #3 (empty-vs-None per layer — borderline correctness). Not selected.

## Per-story status
| Story | Title | DoR | Phase 1 | Phase 3 | Phase 4 |
|-------|-------|-----|---------|---------|---------|
| US-042 | Clipboard read size-cap | READY ✓ | deriving | — | — |
| US-043 | Retire legacy Issues DataTable | READY ✓ | deriving | — | — |

## Roadmap / increment plan (provisional — firmed in Phase 3)
- **US-042** — small (~2–3 files): `tui/os_clipboard_input.py` + tests. Likely 1 increment.
- **US-043** — multi-increment (blast radius = **5 test files**):
  - Inc: remove DataTable from compose + CSS + population; wire summary/paging through grouped panel; remove `on_data_table_row_selected` routing for `validation_issues_list`.
  - Inc: re-point `test_tui_issues_view.py` + `test_tui_app.py` (monkeypatched `query_one` + selection).
  - Inc: re-point `test_tui_directionb.py` (8 sites) + the **two recolor-oracle** suites (`test_tui_a2l_issue_recolor.py`, `test_validation_service_supplemental.py`) at `IssueRow._sev_class`, accounting for `_GROUP_DISPLAY_MAX=40`.

## Key decisions
- **Backlog triage** — only #1 selected (blocks functionality); #2/#3 dropped by operator.
- **Legacy finding** = DataTable retirement (operator supplied prescriptive task).
- **No standing authorization** this session — supervised, explicit gate approvals.

## Open decisions for Phase 1
- **Q1 (US-042 cap approach):** PS-stdout-only bound vs a single post-read length cap in `read_os_clipboard`/`action_paste` covering all 3 layers. *Recommendation: the all-layers post-read cap — simpler, also covers tk/ctypes (which materialize the whole string), and only the first line is ever inserted.* Architect resolves.
- **Q2 (US-043 recolor-oracle migration):** the two batch-24 suites read the DataTable via `get_row_at` as the severity-colour oracle. Re-point to `IssueRow._sev_class`; suites seeding >40 issues must reseed ≤ cap or assert on header counts. qa-reviewer designs the faithful migration.

## Risks / watch-items
- **C-14 location/surface-move census (primary risk):** removing an on-disk/screen-observed widget. The census MUST sweep all 5 reading test files, not the 2 the operator brief named (**briefings under-credit** — verify, don't trust).
- **C-17 markup-safety must not regress** — `IssueRow` already builds via `safe_text`; keep a hostile-symbol render check in the retirement AT.
- `update_validation_issues_view` is intertwined (row-key `issue:<index>` jump, paging, summary). Removal must preserve selection/paging/summary through the grouped panel.
- `_GROUP_DISPLAY_MAX=40` cap means the grouped panel is not a 1:1 oracle for large lists — tests must account for it.

## Conventions honored
- Engine-frozen set untouched (0 diffs target). `issues_view.py` imports `css_class_for_severity` as reader only.
- Docstring section order; type hints; `shall`/`should` discipline.
- Snapshot regen = canonical CI only (local FORBIDDEN); xfail-until-baseline for shifted Issues cells.

## Out-of-scope carries
- Backlog #2 (`<1s` benchmark) + #3 (empty-vs-None) — deferred, not this batch.
- 20 batch-28 snapshot xfail cells await canonical-CI regen (operator).
- Bookmarks placeholder + A2B Diff placeholder (other legacy TUI gaps) — not this batch.

## Test ledger
- Baseline re-anchored at Phase-3 entry (verify-don't-trust): **1171** collected on `e07507c` (not the stale 1151 from batch-28 close — clipboard PRs #51–54 added ~20 tests).
- Inc1: **1171 → 1180 (+9)** (AT-042a–f, TC-042.1–.3). F841 fix = net 0 (one line removed, no test change).

## Decision log (mirror)
- 2026-07-08 P0 — batch-29 initialized; RC-1 PASS @ e07507c; backlog triaged (only #1 in).
- 2026-07-08 P0 — DoR APPROVED (US-042 + US-043 READY); blast-radius correction accepted.
- 2026-07-08 P1 — architect + qa-reviewer dispatched.
- 2026-07-08 P1 — derivation merged into 01-requirements.md. Q1 (clip cap) = 64 KiB central. Fork A = restore related-artifacts on IssueRow (LLR-043.R8). Fork B = keep precompute as orphan. qa corrected: recolor colour oracle is on #a2l_tags_list (not retired). P1 gate APPROVED.
- 2026-07-08 P2 — tri-agent cross-review → 02-review.md. 1 blocker (B-1 AT-042b bypassed the cap), 5 major, 5 minor, 2 sec-minor. ALL folded into 01-requirements.md v2 §6.6 (AT-042b→_STRATEGIES; HLR overclaim reworded; +TC-043-restore.1; precompute dead-write predicate; AT-043-c17 multi-REF; count-guard→≤40). 9 TC now. AWAITING P2 gate.
