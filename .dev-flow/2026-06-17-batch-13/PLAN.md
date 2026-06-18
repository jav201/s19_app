# Batch-13 — Living Plan / Compendium

> Living doc. Updated at every gate + significant checkpoint. BLUF: where we are, what's next, why.

## Where we are
- **Phase 6 (Documentation) — awaiting gate (FINAL).** REQUIREMENTS.md §19 (3 R-*, Automated) + 06-docs (traceability/functionality/2 Mermaid diagrams/exec-summary). Verified: node ids real, 0 mojibake. On approval → awaiting-sync.
- (done) Phase 5 close-batch (2ad5126); Phase 4 PASS (c6d1440); Phase 3 (…/5197169); Phase 0-2; batch-12 sync.
- **On close:** push branch → PR to main → review/CI → merge → `/dev-flow-sync`. (CI trigger gap RESOLVED since b06 — do not re-flag.)

## Objective
Surface two existing-substrate TUI capabilities (no new engine math):
- **US-013** — Load the CRC config JSON from a file in the CRC surface (`read_crc_config` + dummy stays pre-loaded). GENUINE GAP.
- **US-014 (re-scoped/trimmed)** — Add a paste-full-changeset textarea + dummy change-document pre-load to the **already-working** Patch Editor (CRC parity). Everything else US-014 originally listed is ALREADY SHIPPED.

## Phase-0 headline finding (the one that changed the batch)
The brief's premise that the Patch Editor is "un SHELL INERTE" is **false** — it traces to a stale docstring at `app.py:938`. Disk truth: `PatchEditorPanel` + `ChangeService` + app.py handlers already ship load-from-file / apply / INSIDE-PARTIAL-OUTSIDE / contained-emit (`copy_into_workarea`, no clobber) / `verify_written_image` reader-as-oracle. Operator chose **"Trim to the real gap"** → US-014 = paste + dummy only. Stale docstring to be corrected surgically.

## Story status
| US | Title | Status | Genuine delta |
|----|-------|--------|---------------|
| US-013 | CRC config from file | READY | path Input + "Load config" button → read into `#operation_config` TextArea; errors surface, no auto-run |
| US-014 | Paste change-doc + dummy in Patch Editor | READY (trimmed) | paste TextArea + `DUMMY_CHANGESET_TEXT` + text→document parse seam; reuse shipped apply/verify/save-back |

## Roadmap
- ✅ Phase 0 — DoR gate APPROVED.
- ✅ Phase 1 — Requirements engineering. 2 HLR / 6 LLR / TC-201..208 (awaiting gate). Increment plan below.
- Phase 2 — Cross-review (architect + qa + security). Confirm whether security sign-off on US-014 is mandatory (write-path) or advisory (input-parse only — shipped write reused, 0 new write surface).
- Phase 3 — Implementation (3 increments, ≤5 files each, code-reviewer each gate).
- Phase 4 — Validation (A-5 surface-reachability matrix; reconcile provisional TC node ids V-5; 0-new-write-paths diff-vs-main row).
- Phase 5 — Post-mortem.
- Phase 6 — Docs.

## Increment plan (Phase 1)
- **Inc 1 — US-013** (HLR-013): `crc_config.py` (+`read_crc_config_text`) + `screens.py` (CRC path Input + Load button) + `test_tui_crc_surface.py`. 3 files.
- **Inc 2 — US-014 data layer** (LLR-014.1/.2): `changes/io.py` (+`parse_change_document`, +`DUMMY_CHANGESET_TEXT`, refactor reader to delegate, `__all__`) + `change_service.py` (+`load_text`) + `test_changes_schema.py`. 3 files.
- **Inc 3 — US-014 UI wiring** (LLR-014.1/.2/.3): `screens_directionb.py` (paste TextArea + `ActionRequested.paste_text`) + `app.py` (`PATCH_ACTIONS_V2` + router + fix stale :938 docstring) + `test_tui_patch_editor_v2.py`. 3 files. Blast-radius: 4 fixed-set edit points all in budget.

## Key decisions
- D0 (Phase-0 gate): US-014 trimmed to paste+dummy ergonomic; shipped write path untouched.
- D1 (Phase-1): US-013 seam = **add `read_crc_config_text`** (raw text into editor); `read_crc_config` returns parsed (wrong type for TextArea). SETTLED.
- D2 (Phase-1): US-014 seam = **add `parse_change_document(text)`** to non-frozen `changes/io.py` (factor io.py:414-458, `json.load`→`json.loads`, `read_change_document` delegates) + `ChangeService.load_text`. `changes/io` had NO parse-from-string. SETTLED.

## Risks / watch-items
- ~~**R-A** US-014 text-parse seam~~ — **SETTLED (D2):** seam absent; add `parse_change_document` in non-frozen `changes/io.py`.
- **R-B** PATCH_ACTIONS_V2 fixed set asserted at `test_tui_patch_editor_v2.py:184` — 4 edit points budgeted in Inc 3 (def app.py:126 + router app.py:1301 + ActionRequested field + test assertion); no `__init__` facade re-exports. Watch in Phase 3.
- **R-C** Frozen-engine set intact — re-verified: all 6 prod files outside `_ENGINE_PATHS` (test_engine_unchanged.py:120). Confirm again at each Inc gate (change-first census).
- ~~**R-D** security sign-off on US-014~~ — **RESOLVED (Phase-2): ADVISORY.** US-014 = 2 input-parse surfaces + 0 new write surface (shipped write path reused unmodified; pasted changeset as contained as file-loaded). Standing obligation: diff-vs-main "0 new write paths" is a HARD Phase-4 gate row (F-S-03), elevated bc Inc 2 edits io.py/change_service.py near emit/save_patched.
- **R-E** (Phase-3) D2 refactor fidelity: `parse_change_document` must re-home the MF-JSON-PARSE 3-exception catch + delegation-guard + source_path=None + parity oracle precision (Phase-2 Cluster 1; pin as Inc-2/3 gate ACs).

## Conventions honored (b12 lessons)
- Consumer-input-contract citation (would have caught b12 J-3).
- Facade/test blast-radius budgeting in Phase 1.
- reader-as-oracle for any write (already present in the shipped path; US-014 adds no new write).
- config/patch JSON NEVER in repo — dummy templates (FAKE values) + synthetic fixtures only; tripwire `examples/**/crc*.json` (TC-114) respected; US-014 dummy is FAKE-valued.
- Living PLAN.md + 7-section review packets in-conversation at each gate + mid-increment checkpoints.
- **Requirement amendments during an increment are recorded with explicit Before → After + Deleted / New** (01-requirements.md §6.5), never silently edited (operator convention, batch-13).

## Out of scope (separate carries — do NOT pull in)
A-3 save-flow composition (b11 LEAD), RK-3 non-zlib device vector, CLI 'ops', CODIFY reader-as-oracle in PROJECT_RULES, ADR report_service-CRC. RESOLVED — do NOT re-flag: CI trigger gap (fires on main since b06).

## Loose end — RESOLVED
~~batch-12 `obsidian_synced` false~~ → CLEARED 2026-06-17: `/dev-flow-sync` confirmed batch-12 already fully synced to G: vault (8 artifacts + README + Dashboard; EOL-only diff vs main); flag flipped true in the batch-12 close snapshot.

## Test ledger
- Baseline CONFIRMED (V-7): **879 collected** (matches b12 close).
- Inc 1 (US-013): +7 (TC-202 ×4 unit + TC-201/203/204 ×3 surface) → **886 collected**. Signed: post = 879 − 0 + 7 = 886 EXACT.
- Inc 2 (US-014 data): +5 (TC-206/207/209/210/211) → **891 collected**. Signed: post = 886 − 0 + 5 = 891 EXACT.
- Inc 3 (US-014 UI): +2 (TC-205/208; action-pin renamed = REUSE, net 0) → **893 collected**. Signed: post = 891 − 0 + 2 = 893 EXACT.
- **Phase-3 total: 879 → 893 (+14: I1 +7, I2 +5, I3 +2).**

## Decision log (mirror of state.json, human-readable)
- 2026-06-17 — Phase 0 init: batch-13 scaffolded; batch-12 close snapshot written.
- 2026-06-17 — Phase 0 gate APPROVED: premise correction on US-014; operator "Trim to the real gap"; both READY.
- 2026-06-17 — batch-12 `/dev-flow-sync`: verified complete, flag flipped.
- 2026-06-17 — Phase 1 derivation: 2 HLR / 6 LLR / TC-201..208; both seams settled (D1/D2); census clean; awaiting gate.
- 2026-06-17 — `/dev-flow` command updated: communication rules (living PLAN + in-conversation packets + checkpoints) now encoded durably.
