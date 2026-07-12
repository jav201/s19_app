# 06 — Traceability matrix — 2026-07-11-batch-37

> **BLUF: 0 gaps.** Every one of the 5 stories (US-061/062/063/064a/064b) traces forward to a
> black-box acceptance test AND down through HLR → LLR → white-box test case, and every AT / TC
> reconciles to EXACTLY ONE on-disk node (C-18) that ran green in Phase 4. All node ids below are
> the RECONCILED ids from `04-validation.md` §2/§3, verified against the worktree tree. Status of
> every row = **Automated**.
>
> Sources: `.dev-flow/2026-07-11-batch-37/01-requirements.md` (§3 acceptance, §4 HLR/LLR, §5
> traceability), `04-validation.md` (§2 white-box nodes, §3 black-box nodes, §7 TC-319 fix).
> Batch base `978a900` (= origin/main tip, batch-36 merged). Ledger `--collect-only` = 1385.

---

## 1. Story → requirement → node summary

| Story (B-item) | HLR | Ledger row | Black-box AT(s) | White-box TC(s) | Status |
|----------------|-----|-----------|-----------------|-----------------|--------|
| US-061 (B-11) — persistent before/after-report surface | HLR-061 | R-TUI-049 | AT-061a | TC-330 | Automated |
| US-062 (B-12) — entropy paging + sort | HLR-062 | R-TUI-050 | AT-062a, AT-062b | TC-324, TC-325, **AT-036b** (regression guard) | Automated |
| US-063 (B-13) — entropy legend + clickable strip | HLR-063 | R-TUI-051 | AT-063a, AT-063b | TC-326, TC-327 | Automated |
| US-064a (B-14) — patch refresh | HLR-064a | R-TUI-052 | AT-064a | TC-328, **TC-319** (cross-file census, updated) | Automated |
| US-064b (B-14) — JSON popup + file-loaded disable-guard | HLR-064b | R-TUI-053 | AT-064b, AT-064c | TC-329, TC-331 | Automated |

**Counts:** 5 US → 5 HLR → 15 LLR → **8 new ATs** (AT-061a/062a/062b/063a/063b/064a/064b/064c) +
**8 new TCs** (TC-324..331) + **2 updated/reused** existing nodes (TC-319 census updated, AT-036b
reused as the LLR-062.2 remap regression guard). US-064 split into US-064a + US-064b at Phase 1
(`01-requirements.md:107`).

---

## 2. Behavioral chain (US → AT → observable outcome, black-box)

Each AT drives the SHIPPED surface with a real click/key, asserts the DELIVERABLE content (C-10),
and reconciles to exactly ONE on-disk node (C-18). Every AT has a recorded RED counterfactual
(C-20) in `04-validation.md` §3.

| US | Observable outcome (WHAT) | AT | On-disk node (file:line) | Counterfactual (C-20 RED) |
|----|---------------------------|----|--------------------------|---------------------------|
| US-061 | After a successful save-back a **persistent** report control is present (survives the notify TTL + an unrelated re-render); activating it writes the same before/after `*.md`+`*.html` pair the `b` path writes; clear-on-context re-hides it | AT-061a | `tests/test_before_after_report.py:1108` (`test_at_061a_persistent_control_survives_then_writes_pair_and_clears`) | `NoMatches: '#patch_before_after_row'` — a transient `notify` cannot satisfy the node |
| US-062 | A window with index ≥ 512 is reachable via paging and **dismisses with its address** | AT-062a | `tests/test_tui_entropy_viewer.py:475` (`test_at062a_page_past_cap_reaches_later_window`) | `AttributeError: no attribute '_page_size'/'_display_windows'`; `#entropy_page_indicator` absent |
| US-062 | Entropy-descending sort puts the **max-entropy** window at row 0; strip cell order follows the same permutation; page resets to 0 | AT-062b | `tests/test_tui_entropy_viewer.py:551` (`test_at062b_sort_entropy_top_row_is_max`) | same sort/`_page_size` AttributeError set (sort absent) |
| US-063 | Legend maps **each** of the four `ENTROPY_BAND_COLOUR` bands to its meaning + the low-confidence dim cue | AT-063a | `tests/test_tui_entropy_viewer.py:708` (`test_at063a_band_legend_present_with_meanings`) | `#entropy_legend NoMatches` / no `_legend_lines` attr |
| US-063 | A **real pointer click** on a strip cell dismisses with THAT cell's window `start` (C-16, per-cell widget, no offset math) | AT-063b | `tests/test_tui_entropy_viewer.py:761` (`test_at063b_click_strip_cell_dismisses_with_address`) | `#entropy_cell_k` absent; `action_jump` not callable |
| US-064a | After an external on-disk edit + Refresh (re-read over `document.source_path`), the editor shows the NEW content (C-12) | AT-064a | `tests/test_tui_patch_editor_v2.py:2556` (`test_at064a_refresh_rereads_edited_file_into_editor`) | `NoMatches: '#patch_doc_refresh_button'` |
| US-064b | JSON popup (paste-authored doc) shows the current change-set; edit + **Confirm** updates the change document (C-12); Cancel leaves it unchanged | AT-064b | `tests/test_tui_patch_editor_v2.py:2737` (`test_at064b_json_popup_edit_confirm_cancel_and_geometry`) | `NoMatches: '#patch_edit_json_button'` |
| US-064b | "Edit JSON" is **DISABLED** for a file-backed document → popup cannot open, no `load_text` clobber (A-01 data-loss guard); enabled for paste-authored | AT-064c | `tests/test_tui_patch_editor_v2.py:2865` (`test_at064c_edit_json_disabled_for_file_backed_document`) | `NoMatches: '#patch_edit_json_button'` (guard/button absent) |

---

## 3. Functional chain (US → HLR → LLR → TC/AT, white-box)

Every HLR traces to exactly one US; every LLR to its parent HLR; every LLR has an executed
verification. Geometry-only LLRs are verified by the same AT run at BOTH 80x24 and 120x30 inside
one node (C-18-compliant size loop, not extra nodes).

| US | HLR | LLR | Verifying node(s) | On-disk node (file:line) | Intent verified |
|----|-----|-----|-------------------|--------------------------|-----------------|
| US-061 | HLR-061 | LLR-061.1 | AT-061a + TC-330 | `test_before_after_report.py:1108` / `:1258` (`test_tc330_before_after_row_reveal_hide_state_machine`) | persistent `#patch_before_after_row` revealed on `result.ok`; hidden when declined; re-hidden on new load; button → `BeforeAfterReportRequested` routing |
| US-061 | HLR-061 | LLR-061.2 | AT-061a | `test_before_after_report.py:1108` | C-12: activation → real `action_before_after_report` writes the pair; report reread off disk asserts content; `b` accelerator retained |
| US-061 | HLR-061 | LLR-061.3 | AT-061a (both widths) + C-24 census | `test_before_after_report.py:1108` | before/after goldens SURVIVE unchanged (composer untouched); C-23 geometry pilot-measured; persistence (not above-fold) is the acceptance |
| US-062 | HLR-062 | LLR-062.1 | AT-062a + TC-324 | `test_tui_entropy_viewer.py:475` / `:626` (`test_tc324_page_slice_math`) | FIXED 512 page size; page slices cover all windows (union-reachable); index ≥ 512 reachable on page 2; `page P/Q` indicator replaces both former truncation nodes |
| US-062 | HLR-062 | LLR-062.2 | AT-062b + AT-036b + TC-325 | `test_tui_entropy_viewer.py:551` / `:139` (`test_at036b_jump_second_row_moves_focus`) / `:670` (`test_tc325_sort_key_no_mutation_and_remap`) | entropy sort desc + address tie-break; `self._windows` not mutated (display copy); page reset to 0; `(sort,page,row)→window` shared remap helper; **AT-036b is the load-bearing regression guard** (2-window addr sort, page 0, row 1 → `0x4000`) |
| US-062 | HLR-062 | LLR-062.3 | AT-062a/AT-062b (both widths) | `test_tui_entropy_viewer.py:475` / `:551` | C-23: sort/page CONTROL + legend placement pilot-measured at 80x24 AND 120x30; page size FIXED-512 (NOT measured) |
| US-063 | HLR-063 | LLR-063.1 | AT-063a + TC-326 | `test_tui_entropy_viewer.py:708` / `:816` (`test_tc326_legend_derived_from_band_colour`) | `#entropy_legend` rows DERIVED from `ENTROPY_BAND_COLOUR` (single source); `set(legend)==set(ENTROPY_BAND_COLOUR)`; non-blank; no `[`/`]`; NOT `LEGEND_TABLE` |
| US-063 | HLR-063 | LLR-063.2 | AT-063b + TC-327 | `test_tui_entropy_viewer.py:761` / `:851` (`test_tc327_action_jump_remap_and_bound`) | C-16 real click → dismiss-with-address; rung-2 per-cell widget (`#entropy_cell_k`) BASELINE; `_window_for_row` shared helper; S-03 out-of-range index → no-op |
| US-063 | HLR-063 | LLR-063.3 | AT-063a (both widths) | `test_tui_entropy_viewer.py:708` | C-23: legend / body split pilot-measured (shared capture with LLR-062.3) |
| US-064a | HLR-064a | LLR-064a.1 | AT-064a + TC-328 | `test_tui_patch_editor_v2.py:2556` / `:2622` (`test_tc328_refresh_uses_source_path_not_widget_and_noops_when_unloaded`) | refresh re-invokes `ChangeService.load` over `document.source_path` (A-03: source_path, NOT the widget path-input); `source_path is None` None-guard |
| US-064a | HLR-064a | LLR-064a.2 | AT-064a + TC-319 (updated) | `test_tui_patch_editor_v2.py:2556` / `test_tui_patch_layout.py:351` (`test_tc319_regroup_section_structure_census`) | existing 15-id census survives + one new `#patch_doc_refresh_button`; existing wiring intact; **TC-319 sibling census updated to the shipped Load/Refresh/… child order (Phase-4 fix, §7)** |
| US-064b | HLR-064b | LLR-064b.1 | AT-064b + TC-329 | `test_tui_patch_editor_v2.py:2737` / `:2961` (`test_tc329_popup_seed_and_load_text_apply_seam`) | `ChangeSetJsonScreen` seeded from `#patch_paste_text` buffer; scope = paste-buffer edit (MVP) |
| US-064b | HLR-064b | LLR-064b.2 | AT-064b + TC-329 | `test_tui_patch_editor_v2.py:2737` / `:2961` | C-12: Confirm → real `parse_paste`→`load_text` → document reflects edit; Cancel → 0 mutation |
| US-064b | HLR-064b | LLR-064b.3 | AT-064b (both widths) | `test_tui_patch_editor_v2.py:2737` | C-23: popup `TextArea` editable lines pilot-measured — N_80 ≥ 7 / N_120 ≥ 13 (the readability the in-panel box could not give at 80x24, batch-36 F-01) |
| US-064b | HLR-064b | LLR-064b.4 | AT-064c + TC-331 | `test_tui_patch_editor_v2.py:2865` / `:3041` (`test_tc331_disable_guard_predicate_tracks_source_path`) | A-01 data-loss guard: "Edit JSON" DISABLED when `document.source_path is not None`; enabled for paste-authored; predicate tracks `source_path` live |

---

## 4. Gap audit

| Direction | Check | Result |
|-----------|-------|--------|
| Forward (US → AT) | every US has ≥ 1 black-box AT observing its outcome through the shipped surface | ✓ 5/5 (US-062/063/064b each have 2) |
| Forward (US → HLR → LLR) | every US decomposes to ≥ 1 HLR and each HLR to ≥ 1 LLR | ✓ 5 US → 5 HLR → 15 LLR |
| Down (LLR → TC/AT) | every LLR has an executed verifying node | ✓ 15/15 (geometry LLRs verified by both-width AT loops) |
| Back (AT → US) | every AT traces to exactly one owning US | ✓ 8/8 |
| Back (TC → LLR) | every TC traces to its parent LLR | ✓ TC-324→062.1, TC-325→062.2, TC-326→063.1, TC-327→063.2, TC-328→064a.1, TC-329→064b.1/.2, TC-330→061.1, TC-331→064b.4 |
| C-18 (AT → node) | every AT reconciles to exactly ONE on-disk node, no fan-out, no split | ✓ 8 ATs → 8 distinct nodes |
| Regression | pre-existing dismiss contract preserved under the new sort/page remap | ✓ AT-036b green (`test_tui_entropy_viewer.py:139`) |
| Cross-file census | sibling layout census re-swept for the added `#patch_doc_refresh_button` | ✓ TC-319 updated (`test_tui_patch_layout.py:351`) — Phase-4 finding, orchestrator-fixed |

**No unmatched story, HLR, LLR, AT, or TC. Traceability is complete — 0 gaps.**

---

## 5. Residuals (not traceability gaps — recorded for the reader)

- **2 entropy snapshot cells** (`test_tc036s_entropy_modal_snapshot[entropy-comfortable-80x24 / -120x30]`,
  `test_tui_snapshot.py:613-634`) are `xfail(strict=False)` pending **canonical-CI baseline regen
  post-merge** (local regen forbidden — `reference_snapshot_regen_env`). They snapshot the entropy
  modal's new `#entropy_controls` / `#entropy_legend` / `#entropy_cell_k` surface; not a coverage gap.
- **~9 LOW review carries** (per-increment, reviewer-accepted) and the pre-existing native
  bracketed-paste 64 KiB cap gap are enumerated in `05-postmortem.md` §6 and carried in `BACKLOG.md`
  — none is an untraced requirement.
