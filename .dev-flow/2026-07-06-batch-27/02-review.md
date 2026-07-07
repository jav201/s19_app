# 02 — Cross-agent Review — 2026-07-06-batch-27 — R-TUI-041

> **BLUF:** The requirements are sound and disk-grounded, but Phase 2 surfaced **1 blocker** (Rich-markup injection from file-derived issue text into the now-`markup=True` panel) + **4 majors** + minors. Per dev-flow, the blocker forces **iterate-to-refine** (amend Phase 1). All fixes are requirements-doc edits (add 1 LLR + its TC/AT, 4 small edits); no design invalidated. Reviewers: architect (completeness/derivation/C-15/C-13), qa-reviewer (testability/R-2/snapshot), security-reviewer (markup injection).

## Verdict per reviewer
| Reviewer | Verdict | Blockers | Majors | Minors |
|---|---|:--:|:--:|:--:|
| architect | Approvable w/ fixes | 0 | 2 (MAJOR-1 markup escaping, MAJOR-2 `may` modal) | 3 |
| qa-reviewer | Approve w/ fixes | 0 | 2 (M-1 AT-036d path, M-2 80x24 snapshot) | 4 |
| security-reviewer | **BLOCK on F1** | 1 (F1 markup injection) | 1 (F2 `.symbol` unsanitized → folds into F1) | 0 |

MAJOR-1 (architect) and F1 (security) are the **same** finding → treated as the single blocker below.

---

## BLOCKER

### B-1 (security F1 / architect MAJOR-1) — Rich-markup injection from file-derived text — HIGH
- **What:** Coloring the panel requires `markup=False → markup=True` (`screens_directionb.py:187`). The panel then renders file-derived strings (`ValidationIssue.message`, `.symbol`, `.code`, region names) via Rich markup. Rich parses `[...]` as style tags → a loaded A2L/MAC symbol like `sensor[red]`, `foo[/]`, or `x[link=file:///…]` corrupts the render, injects styling/hyperlinks, or raises `rich.errors.MarkupError` crashing the Memory Map screen on load.
- **Verified sources (file-derived, raw):** `rules.py:465/467` (`message=f"A2L symbol '{name}'…"`, `symbol=name`), `:476/478`, `:509/511`, `:360/362` (MAC symbol). `_scrub_issue_message` (`model.py:25-84`) strips ANSI + control chars only — `[`(0x5B)/`]`(0x5D) survive — and `__post_init__` (`model.py:137`) scrubs ONLY `.message`, never `.symbol`. `_scrub_issue_message` is engine-frozen → NOT the fix site.
- **Why it matters:** The tool's core job is loading untrusted third-party firmware+A2L+MAC. A malformed A2L (a duplicate/mis-addressed symbol — the very case that generates these issues) with a bracket in its name crashes or corrupts the screen on the ordinary load path. Low effort, no privilege.
- **Fix (requirements):** Add **LLR-041.11 — markup-safe rendering of file-derived text**: every file-derived string reaching the `markup=True` panel (`.message`, `.symbol`, `.code`, region name) shall be rendered markup-safe via `rich.text.Text` with explicit styles (preferred — also neutralizes ANSI in `.symbol`, folding in F2) or `rich.markup.escape`. NOT via `_scrub_issue_message` (frozen). Add **TC-041.11** (unit: a `symbol`/`message` containing `[red]`/`[/]`/`[link=…]` renders literally, no `MarkupError`, no style leak) and **AT-036f** (load/seed a bracket-bearing symbol → panel renders without crash, shows literal brackets). Fix lives in `screens_directionb.py` (panel-side), 0 frozen-path diff.

---

## MAJORS

### MAJOR-2 (architect) — stray `may` modal inside LLR-041.4
- LLR-041.4 ends "A2L-symbol naming deferred, `may`." — a modal in requirement-statement material, breaching the `shall`-only convention. Only stray modal in the doc (all HLR/LLR operative verbs are `shall`). **Fix:** reword to a non-modal deferral note (R-3 at line ~185 already states it cleanly). Evidence: `01-requirements.md:109`.

### M-1 (qa) — pin AT-036d to the seed-issue path only
- AT-036d offers two mitigations ("install full triple OR seed `_validation_issues`"). Full-triple address placement is incidental (both `address=` sites in `rules.py` are MAC-only, `:119/:384`) and non-deterministic vs cell auto-scale. **Fix:** pin AT-036d to the seed-issue path (deterministic, single-fixture: set `app._validation_issues=[ValidationIssue(code=…,severity=ERROR,address=<in known invalid cell>)]`, call shipped `update_memory_map()`, observe `#map_detail`). Drop the full-triple alternative.

### M-2 (qa) — add a `map-comfortable-80x24` snapshot cell
- The narrow-regime reflow (LLR-041.10, a NEW two-regime layout) is un-snapshotted if only `map-comfortable-120x30` is locked → a narrow-layout regression passes CI silently. **Fix:** add `map-comfortable-80x24` (xfail-until-baseline), exactly as batch-22 added the patch 80x24 floor cell (`test_tui_snapshot.py:376-378`). Upgrades the doc's "optional" note to a firm add.

---

## MINORS (Phase-3 refinements unless noted)
- **arch MINOR-1:** citation drift — `_apply_width_regime` `def` is `app.py:3919`, `:3946` is the `narrow=width<120` line; align references. (doc edit, trivial)
- **arch MINOR-3 / stats source:** name ONE canonical issue source for the strip — `_validation_issues` (the list passed in), not `_validation_report.coverage`/`.issues` re-derived. (add a clarifying clause to LLR-041.8)
- **qa m-3:** Phase-3 must hand-compute + pin the exact stat literals for `case_02` (covered bytes, coverage %, gap count, largest-gap), not assert `>0`.
- **qa m-4:** AT-036b must assert the **rendered hex row** (behavioral), not a mock-call on `update_hex_view` (that would be white-box).
- **qa m-5 / R-1:** add a negative assertion that a fully address-less issue appears in NEITHER the cell list NOR the region count (locks the operator-confirmed R-1 default).
- **qa m-6:** TC-041.2 should assert cell-count from an injected/measured geometry, not live `panel.size`, for version-stability (batch-25 unpinned-renderer lesson).

---

## Axis checks that PASSED (no action)
- **Normative convention:** clean except MAJOR-2. **Derivation:** every HLR→US, LLR→HLR, no orphan/uncovered (arch).
- **C-15 severity identity:** `ERROR→sev-error`, `OK→sev-ok`, `NEUTRAL→sev-neutral` round-trip verbatim (`color_policy.py:5-19`) — no mis-color risk (arch).
- **C-13 geometry:** rail=22 (`styles.tcss:941`), body=1fr (`:131`), rail is a sibling OUTSIDE the map body; 120: 98−36=62>0; one fixed sibling only — sound (arch).
- **Draft-time citations:** 5/5 spot-checks hold (arch); current `_compose_screen_map` genuinely lacks `#map_grid`/`#map_detail`/`#map_stats`/Open → every AT's RED is genuine (qa).
- **R-2 (issue-address density):** premise confirmed real; seed-issue mitigation black-box-valid & C-12-compliant (qa).
- **Render-only (LLR-041.7):** join is on already-computed `_validation_issues`, no new validation call (arch, qa).
- **Security F3/F4/F5/F6:** address int-format safe; Open-in-Hex target bounded; fixtures public; engine-frozen scope compliant (security).

## Iterate-to-refine plan (Phase-1 amendments, §6.5)
1. ADD LLR-041.11 (markup-safe rendering) + TC-041.11 + AT-036f. [B-1]
2. REWORD LLR-041.4 `may` → non-modal deferral. [MAJOR-2]
3. PIN AT-036d to seed-issue path; drop full-triple alt. [M-1]
4. ADD `map-comfortable-80x24` to the snapshot plan (xfail-until-baseline). [M-2]
5. Minor edits: citation alignment; canonical stats source clause; m-4 behavioral hex assertion; m-5 address-less negative AT. (m-3/m-6 are Phase-3 execution notes.)

## Evidence checklist (Phase-2 gate)
- ✓ Findings classified blocker/major/minor with `file:line` — above.
- ✓ Two-layer review — every US has AT; every output-producing req names deliverable+observation; both chains complete; ATs black-box (qa).
- ✓ Supersession/engine-frozen census — planned files all outside frozen set; fix stays panel-side (security F6, arch #5).
- ✓ Scope-change re-routing — no new external-write surface added (the render change is local); security re-reviewed the render path.
- ✗ B-1 blocker open → iterate-to-refine before Phase 3.
