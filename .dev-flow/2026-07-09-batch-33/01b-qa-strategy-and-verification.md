# 01b — Phase-1 QA deliverable · batch-33 (citation re-verification + validation strategy)

> Produced by the qa-reviewer agent 2026-07-09 on feat/batch-33-check-reasons (= main dd91941).
> Full text preserved verbatim below; the PROMINENT items are folded into 01-requirements.md at the
> Phase-1 gate (fold record there).

**BLUF.** R-B02-1 is CLOSED: all engine/service citations verify exactly on merged main — batch-30/31/32
touched none of `tui/changes/*`, `change_service.py`, `report_service.py`; the only PatchEditorPanel
changes are batch-31 Input→OsClipboardInput swaps (no checks-surface semantics). Two citations drifted
(REQUIREMENTS.md R-PATCH-CHECKS-CLARITY-001 3132→3188-3193; R-CHK-001 span 1631→1654;
refresh_check_results →2258), zero changed in content. C-17 driver CONFIRMED by quote: the status
label `#patch_checks_status` updates through a markup-enabled default `Label.update`
(screens_directionb.py:2286; constructed plain at :1898).

## PROMINENT findings (design-relevant)

1. **P1 — AT-051b surface unimplementable as drafted:** `_append_log_line` caps lines at 50 chars
   (app.py:8884 `line = trimmed[:50]`); the ~100-char `doc-kind` reason cannot be asserted on
   `app.log_lines`. AT-051b must assert the FULL reason on `#patch_checks_status` (receives the
   untruncated `result.message` via `refresh_check_results`) and only the `Checks:` prefix on
   log_lines. Touches LLR-051.4 message design.
2. **P2 — markup-safety census incomplete:** the reason reaches THREE render surfaces:
   (1) result rows `Static(markup=False)` (:2290) ✓; (2) `#patch_checks_status` markup-enabled
   (:2286) — named by the draft ✓; (3) `set_status` → `#log_line_1..4` markup-enabled `Label.update`
   (app.py:1932 → 8892-8895) — UNNAMED by the draft yet mandated by LLR-051.7. AT-051e must assert
   surface (3) too; the 50-char truncation can bisect a markup token (`[bol…`) — a distinct
   MarkupError vector. **Bonus pre-existing exposure:** `CHG-KIND-UNKNOWN`'s message embeds
   `kind {kind!r}` verbatim (io.py:695-701) and flows through `_report_change_result` (app.py:1935)
   to the markup-enabled log labels on TODAY'S load path.
3. **Counts/fixtures:** the draft defines 12 ATs (not 13). AT-050a must specify collision-PAIR taint
   (both partners tainted — two findings, two addresses; healthy entries at non-colliding
   addresses). R-B02-4 blocked-run aggregates have NO owner — add TC-051.5 (blocked run →
   `{passed:0, failed:0, uncheckable:N}` + report Checklists renders; include the zero-entry
   envelope-fault `{0,0,0}` boundary). AT-051f must state its no-consumer status (`to_dict` has zero
   production consumers; report_service reads dataclass attributes directly). US-050 needs one
   Pilot-level observation — run AT-050a's fixture through the real Run-checks button idiom
   (test_tui_patch_editor_v2.py:749-816 pattern).
4. **Anchor refreshes** for the lock: R-PATCH-CHECKS-CLARITY-001 → :3188-3193; R-CHK-001 →
   :1631-1654; refresh_check_results → :2258.

## Citation table verdicts (Task A)
36 claims re-verified: 33 OK exact · 3 DRIFTED (line-only, content identical: rows 14, 26, 27) ·
0 CHANGED. Batch-31's only diff to test_tui_patch_editor_v2.py is appended at :1878+ (prior
numbering stable). `-k check` collects 8 batch-32 CRC tests by keyword collision — not real
checks-path consumers (verified). No new aggregates/check_rows/to_dict consumers in batches 30-32.

## Validation methods (Task B1)
All requirements method=test except LLR-050.4 (existing engine-frozen guard cited as evidence),
LLR-052.3 (analysis: 80×24 geometry re-check; snapshot cells xfail-until-canonical-regen), and the
AT-032a token guard half of AT-052a (inspection-adjacent, rides the existing harness).

## C-10 per-AT audit (Task B2)
AT-050a PASS (fixture: collision-pair semantics, non-colliding healthy entries; pre-change RED
pinned by test_checks_engine.py:203-229 + the :406 literal). AT-050b PASS. AT-050c PASS
(declared negative; assert exact aggregates). AT-050d PASS (declared regression; apply-gate
insurance). AT-051a PASS (owns partial/outside/no-image — must assert each reason string on its
specific row). AT-051b CONDITIONAL (P1). AT-051c PASS (composed-path fixture feasible via
change_service.py:478; NO shipped test exercises add-entry-onto-faulted-envelope — Phase-2 must
smoke before building on it). AT-051d PASS (declared boundary-negative). AT-051e CONDITIONAL (P2;
feasibility confirmed — io.py:600-609 `_text("kind")` passes the hostile token verbatim onto
`ChangeDocument.kind`). AT-051f PASS (state no-consumer). AT-052a PASS (three distinct token
spans). AT-052b PASS.

Reason-code ownership: doc-kind→AT-051b/e · doc-fault→AT-051c · entry-fault→AT-050a ·
partial/outside/no-image→AT-051a · unknown-code-blocks fail-safe→TC-050.1 (engine-internal, named).
Unowned until TC-051.5 lands: blocked-run aggregates; zero-entry blocked run.

## C-12 chains (Task B3)
Engine→rows→panel satisfied IF the ATs press the real Run-checks button (:749-816 idiom — no stub).
`to_dict` is produce-without-consume this batch (only tests consume; report_service reads
attributes) — stated, not faked. Reason→log chain observed via AT-051b's prefix-only log assertion.

## Boundary/negative inventory (Task B4)
Zero-entry blocked run {0,0,0} (TC-051.5); clean-doc zero entries (existing); 50-char truncation
(shapes AT-051b); collision-pair + same-address multi-fault + address-0x0 falsy-membership
(TC-050.2); MF-ENTRY-LIMIT address-less no-taint (TC-050.2); hostile kind on 3 surfaces (AT-051e);
unknown-code blocks (TC-050.1); declared negatives AT-050c/d, AT-051d. Concurrency N/A (justified).

## Ledger baseline (Task B5, collect-only @ dd91941)
Full suite 1241 collected. Touched-file anchors: test_checks_engine 7 · test_change_service 21 ·
test_tui_patch_editor_v2 28 · test_report_service 33 · test_variant_execution 12 (sum 101).

## QA evidence checklist
All items ✓ except one condition: **Layer B for US-050** — engine-level ATs only; fold the Pilot
companion (item 3 above). No results claimed beyond collect-only. No PII. No template placeholders.
