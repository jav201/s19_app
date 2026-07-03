# Functionality — A2L↔Issues Reconcile + Before/After Report (US-032/033/034) — Batch 2026-07-02-batch-24

> **Audience:** technical stakeholder (engineer or reviewer familiar with the s19tui workspace, A2L/Issues views, and the patch editor). **Purpose:** understand what shipped, how it works, and its deliberate limits.
>
> **BLUF: two things shipped. (1) The A2L table's red rows and the Issues view now guarantee each other — every red row has a matching ERROR issue, and every ERROR-severity A2L issue reds its rows; as part of this, sessions without a MAC file no longer lose their validation report (a live shipped bug, fixed). (2) After applying a change document and saving the patched image back, one keypress (`b`) writes a before/after diff report pair — Markdown + self-contained HTML — proving on disk what changed between the original file and the saved patched file, with provenance guarded by four refusal classes. This closes feature #12 slices (a) and (c); the entropy slice (b) is deferred to its own batch.**

---

## 1. The reconcile — red rows and the Issues view can no longer disagree

Before this batch, the A2L table's row colouring and the validation Issues surface were computed independently and diverged in **both directions** on the shipped tree (both captured as failing tests pre-fix — the batch's premise was fact, not belief):

- **Direction 1 (red row, no issue):** a non-virtual characteristic missing its address/length rendered red (`schema_ok=False` from the frozen A2L enricher) while the validation engine emitted nothing for it — the operator saw a red row with an empty Issues view.
- **Direction 2 (issue, no red row):** `A2L_DUPLICATE_SYMBOL` is an ERROR-severity issue, but row severity never consulted issues — duplicate-symbol rows rendered normal, violating the REQUIREMENTS.md severity convention.

**What now holds, and how:**

- **Red ⇒ issue (US-032).** When the validation report is built, a supplemental TUI-side rule (`supplemental_a2l_row_issues`) emits one `A2L_TAG_SCHEMA_INCOMPLETE` ERROR per tag whose `schema_ok` is exactly `False`, naming the symbol and the reason. Dedup prevents double-reporting: a tag already covered by an existing symbol-bearing A2L ERROR (`A2L_INVALID_ADDRESS`, `A2L_DUPLICATE_SYMBOL`) gains no second issue. The rule lives at the open `validation_service` seam and merges into **both** report branches before dedupe — the engine-frozen `validation/` package and `tui/a2l.py` are untouched, and no existing issue code was renamed (public contract).
- **Issue ⇒ red (US-033).** At render time the app builds a casefolded symbol → max-severity map from the current issue list (`_a2l_issue_severity_map`); `_a2l_tag_row_severity` now consults it and returns ERROR (red) for any tag whose name maps to an ERROR-severity A2L issue. So both rows of a duplicated symbol render red while the issue list itself is unchanged. The render order was also fixed so the map is fresh on the **first** frame of the sync-fallback load path (validation computed after enrichment, before rows render).
- **The no-MAC fix (LLR-037.4 — blocker-born, a shipped-product bug).** `update_mac_view` previously **wiped** the validation report and issue list in every session without MAC records — meaning any S19+A2L session (no MAC) ended issue-less regardless of what the engine computed, and the Issues view was permanently empty there. Now: with a primary file loaded, the no-MAC branch computes/retains the report for the primary+A2L pair through the existing cache mechanism (worker-precomputed reports register as cache hits — never wipe-then-recompute); sessions with no primary file keep the historical clear. **Operator consequence: loading an S19 + A2L without a MAC now populates the Issues view (rail screen 5) like any other session.**

**WARNING policy (deliberate):** only **ERROR** recolours A2L rows. A WARNING-severity issue (e.g. `A2L_BROKEN_REFERENCE`) never changes row colour — the REQUIREMENTS.md A2L palette is Red/Green/White/Grey only; orange is a MAC-view convention. Recolouring on WARNING would invent a fifth A2L state with no requirements basis (design decision D-2, guarded by a dedicated test).

## 2. The before/after report — one action proves what a patch changed on disk

### Operator flow

1. In the patch editor, **apply** a change document, then accept the **save-back** prompt (writes the patched image; name collisions get a `_<N>` dedup suffix, never a clobber).
2. On a successful save the app **offers the report** in an information notify naming the action and its key (the offer appears after the verify-result notice, so a verify mismatch is never masked — and does not suppress the offer: the report is an honest disk-to-disk comparison of what was actually written).
3. Press **`b`** (`action_before_after_report`). The composer re-parses **both files fresh from disk** — the original loaded file and the saved patched file — via the proven compare engine, and writes a **Markdown + self-contained HTML report pair** into the active project's `reports/` directory. The status line surfaces the written paths (or the refusal diagnostic).

The manual A↔B compare/report path is unchanged and remains the route for sessions without an active project.

### What the report contains

- **Before/after provenance header:** original path · saved path (the actual **post-dedup** on-disk identity, read from the stamped `saved_path` — never an echo of the name the dialog displayed) · apply timestamp (UTC) · change-document origin (`(in-memory document)` when none).
- **Change-entry linkage table:** one row per applied summary entry — entry type, address range, disposition (incl. skipped/failed), linkage, linkage symbol, before/after bytes. `before_bytes=None` (create-into-hole) renders an explicit `(none - created into hole)` marker, never fabricated bytes. Zero entries renders `No entries.`
- **Diff fences:** the inherited batch-09 diff-report body — per-run hex windows and ```diff blocks showing pre-patch bytes as `-` lines and patched bytes as `+` lines at each changed address.
- **Filenames:** `<UTC timestamp>(-NN)?-before-after-report.md|.html`, owned by the module's own regexes (the shared diff-report scheme is untouched — default diff-report output is **byte-identical** to pre-batch, pinned by a double-proven golden test).
- **Injection hygiene:** parsed-artifact values (A2L/MAC symbols, paths) are pipe-escaped and control-character-stripped in Markdown cells (`_md_cell`); the HTML side is escaped and identically ctl-stripped (`_esc(_strip_ctl(...))`).

### The refusal classes — provenance protection (never a wrong report, never a silent write)

The composer validates five preconditions **in order** and refuses — one human-readable diagnostic, **zero files written**, app keeps running — when any fails:

| # | Refusal | Protects against |
|---|---------|-------------------|
| 1 | No apply/save summary exists | trigger with nothing to report |
| 2 | Save was declined/refused (`saved_path` never stamped) | reporting an unsaved image |
| 3 | Either source file no longer on disk | comparing against a deleted/moved file |
| 4a | **Stale summary** — the loaded file is not the image the summary was saved from (`source_image_path` provenance stamp, recorded at save time) | the B-2 hole: apply+save in project A, open project B, press `b` → a false-provenance report pairing B's file against A's patch |
| 4b | **Containment** — the saved path no longer resolves inside the current project dir/workarea | cross-project writes |
| — | No active project → refusal naming the manual A↔B path · symlinked `reports/` destination → refused | destination discipline |

The provenance stamp (`ChangeSummary.source_image_path`) is runtime-only — deliberately excluded from `to_dict`, so serialized change summaries remain byte-stable.

### Where reports land

Always `<active project>/reports/` — gitignored **when** the project lives in the default `.s19tool/` workarea (projects may live outside it; gitignore coverage is a default-layout property, not a guarantee). No report body content, symbols, or bytes ever reach the log; the status line carries paths and diagnostics only.

## 3. Key seams (current tree, re-verified at docs time)

| Seam | Location |
|------|----------|
| Supplemental rule + both-branch merge | `s19_app/tui/services/validation_service.py:20` (`supplemental_a2l_row_issues`), `:111` (`build_validation_report`) |
| Severity rank + symbol→severity map | `s19_app/tui/app.py:224` (`_A2L_ISSUE_SEVERITY_RANK`), `:234` (`_a2l_issue_severity_map`) |
| Row severity (map consult, ERROR-only precedence) | `app.py:295` (`_a2l_tag_row_severity`); map built once per render in `update_a2l_tags_view` (`:7730`) |
| Render-order fix (issues fresh before first row render) | `app.py:7668` (`update_a2l_view` A2L-present branch) |
| No-MAC retention (B-1 fix) | `app.py:6053` (`_refresh_no_mac_validation`), `:6000` (`_mac_view_cache_key_for`), rewired branches in `update_mac_view` (`:7403`) |
| Generator kwargs (provenance/linkage/stem, default-off) | `s19_app/tui/services/diff_report_service.py:939` / `:1353`; `BeforeAfterProvenance` `:184`; `_md_cell` `:254`; `_strip_ctl` `:226` |
| Composer (preconditions, compare, refusals, own regexes) | `s19_app/tui/services/before_after_service.py:182` (`compose_before_after_report`), `:72` (filename regex), `:88` (result type) |
| Provenance stamp | `s19_app/tui/changes/model.py:464` (field, off `to_dict`) · `s19_app/tui/services/change_service.py:933` (stamped beside `saved_path`) |
| Trigger surface | `app.py:684` (`Binding("b", "before_after_report", …)`), `:1710` (`action_before_after_report`), `:1639` (handler passes `source_image_path=loaded.path`) |

## 4. What changed for the operator

1. **A2L triage:** a red row in the A2L table always has a named ERROR in the Issues view (rail screen 5) and the issues report; duplicated symbols now render red. Loading S19+A2L **without a MAC** keeps the validation report — the Issues view is no longer empty in those sessions.
2. **Patching:** apply a change doc → save back → the notify offers the report → press `b`. Read the written md/html pair under `<project>/reports/`; the header names the original and the actually-written (dedup-suffixed) file, the linkage table maps every entry, and the diff fences show the byte-level before/after.
3. If the trigger refuses (no save, missing file, stale/cross-project summary, no project), the status line says exactly why and nothing is written.

## 5. Assumptions, limitations, next steps

- **Assumptions:** enriched tags carry `schema_ok` whenever an image is loaded (verified on all live paths; absent-key tags are deliberately issue-free). Textual `notify` severity literals runtime-verified against the installed version.
- **Limitations (accepted by design):** sessions with an A2L but **no loaded primary file** never build a validation report (issues cleared — documented limitation A-2, out of scope). WARNING issues never recolour rows (D-2). AT-037b's inertness is single-shot per session (spec-accepted). A refused HTML write after a successful md write could orphan the md (theoretical branch, BACKLOG I4-F1). `_strip_ctl` covers C0 + 0x7F only (C1 range optional LOW). No-project save-backs must use the manual A↔B report path (D-3).
- **Next steps:** #12(b) entropy trio (US-035/036/037) as its own spike batch — queue head for #12 completion; ruff F401 hygiene sweep candidates; re-derive AT-038d if a future batch invalidates `last_summary` on real project switch (F3).

**Evidence:** 33/33 new nodes green (Phase-4 independent runs 26/26 + 45/45 + guard 1/1); full non-slow suite **1004 passed / 0 failed** at the I4 gate; engine-frozen set 0-diff ×5 gates; 3 RED counterfactuals captured, **2 of them live shipped bugs**. Full chains: `traceability-matrix.md`; flows: `diagrams/batch-24-flows.md`.
