# Quick Spec — s19_app — audit-gaps follow-up (gaps #3/#4; #2 premise-corrected)

> `/fast-dev-flow` batch on branch `claude/audit-gaps-followup` (off merged main `d3c9cfe`). Follow-up to batch-15 (gap #1/US-016, merged PR #20). Retroactive black-box acceptance closure for the remaining 2026-06-23 audit gaps. English.

## 1. Objective (1 line)
Close the remaining audit black-box-acceptance gaps by adding Pilot e2e + artifact-on-disk tests that observe each user-facing deliverable through the shipped surface — gap #3 (report-generation seam) and gap #4 (demo evidence packs); **gap #2 is premise-corrected and pulled out (see §5).**

## 2. User stories
- **US-A (gap #3, batch-07):** As an operator, when I trigger report generation from the Reports screen on a project, I want a real timestamped report file written under the project's `reports/` dir, its path shown in the status line, and the just-generated report rendered in the viewer — so I can trust the in-app report trigger end-to-end.
- **US-B (gap #4, batch-01):** As an operator, when I save a project / dump A2L JSON, I want the on-disk artifact to actually appear (a project folder under `.s19tool/workarea/<project>/`; an `<name>.a2l.json` file) — so the demo-evidence claims are observed, not assumed.

## 3. Acceptance criteria (observable)
**US-A — report-generation seam (gap #3):**
- **AC-A1:** When the operator opens Reports (`t` → `action_view_reports`) on a saved project and triggers generation (`ReportViewerScreen.GenerateRequested` → `_trigger_generate_report`), the system shall write a real `<timestamp>-*.md` (or the actual naming) file under `.s19tool/workarea/<project>/reports/` — asserted to exist + be non-empty on disk via Pilot.
- **AC-A2:** After generation, the status line (or the screen's surfaced path) shall show the written report path.
- **AC-A3:** The just-generated report shall be rendered in `ReportViewerScreen` (observed through the screen, not a hand-built fixture).
- *(If the seam already works pre-existing → these lock it as a regression; the AT still demonstrates the deliverable is observed through the surface. If any leg is broken → minimal fix + the failing leg shown red pre-fix.)*

**US-B — evidence packs (gap #4):**
- **AC-B1:** When the operator saves a project (`action_save_project` flow), a project folder shall appear under `.s19tool/workarea/<project>/` containing the saved primary — asserted on disk via Pilot.
- **AC-B2:** When the operator dumps A2L JSON (`j` → `action_dump_a2l_json`), an `<name>.a2l.json` file shall be written and exist non-empty on disk — asserted via Pilot.

## 4. Validation strategy (1 paragraph)
Textual Pilot `App.run_test()` drives each real action/binding on a synthetic project (reuse `tests/conftest.py` generators + `tmp_path` as `base_dir`); each test asserts the deliverable on disk (file exists + non-empty) and/or through the rendered screen — never via a faked service. Run `pytest -q` for the suite; confirm engine-frozen guards still pass. Where a leg is already green, the test is a locked regression (state so explicitly); where a leg is red, capture the failing run before the fix. Promote the corresponding `REQUIREMENTS.md` R-* rows from Manual/Partial → Automated for the legs that become covered.

## 5. Non-goals (what is OUT)
- **GAP #2 (batch-11 manifest composition) — PULLED OUT, premise-corrected.** Disk verification (this Phase A) shows the TUI save path holds **no** `batch`/`assignments` state and there is **no operator surface** to assign per-variant files; `assignments` semantics = *additional* per-variant files (not the primary image), so deriving them from the variant set is semantically wrong. The execution service *does* consume `manifest.batch`/`assignments` (variant_execution_service.py:586-602), but a TUI save legitimately has none to record today. Making a save persist non-empty batch/assignments is **net-new feature work** (a per-variant file-assignment surface + persistence), not a wiring fix — so the audit's "drive save with non-empty batch/assignments → assert round-trip" cannot be honestly grounded. **Recommend deferring gap #2 to its own forward-feature `/dev-flow` batch** (parallels the US-015 deferral in batch-15). Operator decision requested at the Phase-A gate.
- C-1 (automated `dev-flow-sync` unfilled-template reject-check) — global `~/.claude` config, separate task.
- US-015 (16/32 S19 record width + S0) — its own forward-feature batch.
- No engine-frozen edits (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`).
- No new report/export *behavior* — only tests that observe the existing shipped writes (+ minimal fix only if a leg is genuinely broken).

## 6. Detected security flags
- Scanned objective + criteria + description for the sensitive-pattern list. Matches: "export" / file-write (A2L JSON, report.md) — but these are **existing shipped writes into the contained `.s19tool/workarea/`** being *observed by tests*, not new write/exec/network/auth/secret/PII surfaces. No new external surface, no auth, no secrets, no destructive DB.
- **`security_required: false`.** (Tests write only synthetic fixtures into a `tmp_path` work area.)

## 7. Batch status
| Field | Value |
|-------|-------|
| Current phase | **closed** |
| Scope | gaps #3 + #4 (2 increments, both locked-regression); gap #2 DEFERRED to its own /dev-flow batch (operator decision, premise-corrected) |
| Started | 2026-06-24 |
| Closed | 2026-06-24 |
| security_required | false |
| Branch | claude/audit-gaps-followup (off main d3c9cfe) |
| Outcome | PASS — 5 black-box ATs (3 report-seam + 2 evidence), all already-working/locked-regression; 0 source edits; REQUIREMENTS.md: R-A2L-003/R-TUI-012/R-PROJ-001 → Automated, R-RPT-001/002 augmented; suite sweep 18 passed; engine-frozen guards green |
