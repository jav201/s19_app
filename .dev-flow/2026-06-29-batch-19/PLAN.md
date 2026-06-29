# PLAN.md — batch-19 (living compendium)

## Where we are
**▶ Phases 0–6 DONE; awaiting commit/PR gate.** Branch `claude/batch-19` off `origin/main 8654df5` (RC-1 PASS). Phase 4 PASS (908→926, +18, 0 fail). Phase 5 post-mortem + Phase 6 docs written; REQUIREMENTS §25 added; BACKLOG updated (US-020c/d DONE; D-1 UI-wiring + D-2 malformed-feedback follow-ons logged). **ALL WORK UNCOMMITTED on `claude/batch-19`** (commit/PR at operator approval). Artifacts: 01/02/04/05 + 06-docs/* + diagrams/batch-19-flows.md. No §6.5 amendment (C-13 measured PASS). 4 increments, each operator-gated + code-reviewer APPROVE.

### Resume cheat-sheet
- **Objective:** US-020c (report **addendum** for operator-declared memory locations) + US-020d (validation issues → report). `/dev-flow`, operator-approved sequence US-020c/d → #8 → #12.
- **THE open question (DoR gate):** what does "declared memory locations" MEAN? 3 interpretations below — operator must pick before HLR derivation.
- **Driven manually** from the pedantic-bose session against `gifted-ramanujan-6d30eb` (claude/batch-19) via absolute paths; `/dev-flow` Skill NOT used (wrong cwd). Same gates by hand.
- **Carry (rides batch-19 first commit):** batch-18 obsidian flip (`state.json`) + BACKLOG refresh + `2026-06-26-batch-18/state-snapshot-at-close.json` + the batch-19 scaffold.

## Spike findings (surface map — disk-verified)
| Area | Finding | Anchor | Verdict |
|------|---------|--------|---------|
| Report already shows issues? | Yes — a **"### Declaration errors"** section renders `- [{code}] {severity}: {message}`, pulling from `change_summaries[].issues` + `check_results[].issues`. It **drops** `address` / `symbol` / `related_artifacts`. | `report_service.py::_declaration_error_lines` ~681-717 (verified :700-716) | US-020d "enrich issues" = **augment existing section** (small), independent of the addendum |
| Report-gen INPUT home | `ReportViewerScreen` has a "Context bytes" `Input` + "Generate new report" button → `GenerateRequested` msg → `app.py::_start_generate_report_worker` builds `ReportOptions` (app.py ~:2014). | `screens.py::ReportViewerScreen` ~542-738; `app.py` ~1823-2031 | Addendum INPUT form's home = **extend ReportViewerScreen** + thread through `GenerateRequested` → `ReportOptions` |
| ValidationIssue fields | `code, severity, message, artifact, symbol, address:Optional[int], line_number, related_artifacts:list, details:dict` — **address-bearing already**. | `validation/model.py:121-129` (**FROZEN — read-only**) | **Reuse** `ValidationIssue.address`; never edit the model |
| Existing "declared locations"? | **None.** Bookmarks = "coming soon" placeholder; `CrcRegion(start,end,output_address)` (from external `crc_config.json`) + MAC `TAG=hexaddr` are the closest patterns but operation/artifact-specific. | `screens_directionb.py:296`; `crc_config.py:61`; `mac.py:95` | **NET-NEW** declared-location model |
| Persistence pattern | `project.json` envelope (`schema_version, active_variant, batch, assignments`) via `manifest_writer.serialize_manifest`/`write_project_manifest` (atomic `os.replace`); read in `variant_execution_service.read_project_manifest`. **manifest_writer.py is NOT frozen.** | `manifest_writer.py:224-444`; `variant_execution_service.py:84,293` | Addendum persists by **extending the envelope** (optional `addendum` key; bump `schema_version`) |

## Reframe (vs the batch-17 deferral premise)
The deferral assumed "(d) depends on (c)." The spike found **two distinct candidate meanings** for US-020d "issues→report integration":
- **(d-i) Enrich the existing report issues section** with the richer fields (address/symbol/related) — the same enrichment batch-17 US-020b gave the TUI. Small, READY, **independent of the addendum**.
- **(d-ii) Cross-reference the declared-locations addendum against issues** (which issues fall in declared regions) — **depends on US-020c** + the chosen semantics.
Both can be in scope; they're not exclusive. Surfaced for the operator, not silently merged.

## The DoR gate — "declared memory locations" interpretations
- **A — Expected-zone annotation (recommended):** operator declares named regions `(name, start, end)`; addendum lists them + cross-references which modifications and `ValidationIssue.address`es fall inside/outside each. "What happened in the regions I care about?" Clean model echoing `CrcRegion`.
- **B — Coverage/expectation assertion:** declared locations that SHOULD be touched; addendum reports per-location touched / untouched / has-issue. "Did we patch everything intended, and only that?" More detection logic.
- **C — Address-anchored notes:** `(address|range, note)` pairs printed as operator commentary, optional hexdump (reuse `_hexdump_section`). Mostly documentation; smallest.

## Proposed story shape (pending the pick)
- **US-020d** (issue-rendering enrichment, d-i): **READY now** — augment `_declaration_error_lines` to surface address/symbol/related. Smallest; could be Increment 1 (independent of semantics).
- **US-020c** (declared-locations addendum): **REFINE → READY** after the semantic pick — new model + ReportViewerScreen input + `project.json` persistence + addendum section + (per interpretation) the cross-ref. d-ii rides on top.

## Conventions / controls in force
RC-1 (held off 8654df5), engine-frozen OFF-LIMITS (validation/model.py read-only), two-layer AT/TC + C-10/C-12, C-13/C-13.1 geometry (ReportViewerScreen input row budget), ≤5 files/increment, commits/PRs on approval, living PLAN.md + review packets.

## DoR gate — RESOLVED (operator, 2026-06-29)
- **US-020c semantics = A (Expected-zone annotation):** declared region = `(name, start, end)`; addendum lists regions + cross-references modifications and `ValidationIssue.address`es inside/outside each.
- **US-020d scope = Both:** enrich the existing issue rendering (address/symbol/related) AND cross-ref declared regions against issues.
- Both stories now **READY**.

## Phase-1 derivation (DONE — formal spec in [01-requirements.md](01-requirements.md))

### HLR (EARS, §3)
- **HLR-024** (US-020c): *When* the operator generates a report with ≥1 declared region, the system *shall* emit an addendum listing each `(name,start,end)` and, per region, the modifications + issues whose `address ∈ [start,end]`.
- **HLR-025** (US-020d): the report *shall* render each issue's address (hex)/symbol/related, beyond code/severity/message.
- **HLR-026** (US-020c): declared regions *shall* persist in `project.json` and reload on read; pre-field manifests read back as 0 (back-compat).

### LLR → target → increment (§4)
| LLR | Statement (short) | Target file(s) — disk-verified | Increment (files) |
|-----|-------------------|--------------------------------|-------------------|
| **LLR-025.1** | enrich `_declaration_error_lines` (`@0x{addr}`/symbol/related) | `report_service.py:~700` | **Inc1** (report_service.py, tests/test_report_service.py) — 2 files |
| **LLR-024.1** `[NEW]` | `DeclaredRegion(name,start,end)` frozen dataclass, `start≤end` validated | NEW `tui/services/report_addendum.py` (echoes `CrcRegion` crc_config.py:61) | **Inc2** |
| **LLR-024.2** | `_addendum_lines(regions,results)` + `ReportOptions.declared_regions=()` | `report_service.py` (`ReportOptions:141`, emit ~:960) | **Inc2** (report_addendum.py NEW, report_service.py, tests/test_report_addendum.py) — 3 files |
| **LLR-024.3** | `ReportViewerScreen` region input → `GenerateRequested` → `ReportOptions` | `screens.py:~542`, `app.py:~2014` | **Inc3** (screens.py, app.py, tests/test_tui_report_addendum.py) — 3 files · **C-13** |
| **LLR-026.1** | optional `declared_regions` in `project.json` (serialize + read, back-compat) | `manifest_writer.py:224`, `variant_execution_service.py:293` | **Inc4** (manifest_writer.py, variant_execution_service.py, tests/test_manifest_writer.py) — 3 files |

### Dual traceability (§5.2)
- **US-020c** → HLR-024(/026) → LLR-024.1/.2/.3(/026.1) → TC-024.1–.6 / TC-026.1–.2 · **AT-024a** (addendum content) + **AT-024b** (zero-hit boundary) + **AT-024c** (input→report, C-12) + **AT-026a** (persist→reload).
- **US-020d** → HLR-025 → LLR-025.1 → TC-025.1 · **AT-025a** (enriched line) + **AT-025b** (no-address negative).
- **TC-S3** anti-drift: issue rendering ↔ addendum cross-ref both read `ValidationIssue.address` (no divergent membership).

### Scope/decisions locked
- DoR: **A Expected-zone** · US-020d **Both** · persistence **in-scope** (operator, 2026-06-29). 4 increments, each ≤5 files.
- Engine-frozen untouched (`ValidationIssue` read-only); `git diff` frozen set must = 0. Each AT shown RED under a counterfactual (QC-2).
- **Open risks** (01-requirements §6.3): addendum placement in report order (Phase-3); C-13 ReportViewerScreen input-row budget (`assumed — measure`); manifest back-compat (additive key, no version bump — confirm Phase 3); cross-variant aggregation.

## Decision log (mirror)
- 2026-06-29 — batch-19 init (US-020c/d); RC-1 PASS off 8654df5; Phase-0 spike done (surface map disk-verified). DoR gate RESOLVED (A + Both). Proposed 4-increment decomposition. Next: Phase-1 derivation → Phase-1 gate.
