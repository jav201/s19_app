# Traceability Matrix — s19_app — Batch 2026-10-12-batch-94

> **Roles:** `docs-writer` (this artifact). Batch `2026-10-12-batch-94`, repo `s19_app-b94`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Verdict source:** every `Status` below is the reconciled Layer A / Layer B verdict of `04-validation.md` (the definitive gate run THREE, tree `c18d181` on `origin/main 121feaa` — `Result: PASS-WITH-NOTES`, `Requirements: 31/31 TC ids pass · 24/24 AT ids pass · 21/21 HLRs with their 42 LLRs`). Requirement topology (US → HLR → LLR → AT, shipped surfaces, file:line anchors) is the contract `01-requirements.md` §2.6/§3/§4/§5. Increment attribution per packet §1/§2 (`03-increments/increment-001…004`).

> **Artifact language:** canonical English scaffold. Generate the artifact in the batch's development language (`state.json` `language`); for Spanish batches **translate the prose, never a label**. This document mints no field a rule keys on — its ids (`US-`/`HLR-`/`LLR-`/`AT-`/`TC-`/`R-`) are read by the Atlas id-scanner and are not words in any language — so it carries no reserved-field block; what it must not do is order the translation of somebody else's.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row. ⚠ **This template is seeded by a BULLET under that table rather than by a row**, because `06-docs/` exists only in `full` — the same fact `V39`'s `_V39_OWED_IN["P6"]` carries.

> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.

---

## 1. Master table — functional chain (white-box)

> One row per LLR (42 rows). `TC` = the executed white-box node id from `04-validation.md` §Layer A; where the contract's validation method for the LLR is `inspection` or `test (e2e)` through the shipped surface, the cell names that method honestly (three LLRs ride AT arms or inspection rather than a dedicated TC id — each is marked). `File:line` = the shipped implementation anchor named by the contract §3/§4. `Status` = the Layer A verdict (all pass). `Notes` = the battery arm / transcript.

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| **Inc-001 (ORCH-P3) — the editors split + Patch Editor rework + `.chk.json`** | | | | | | |
| US-001 | HLR-001 | LLR-001.1 | TC-B94-06 | `s19_app/tui/screens_directionb.py` (`CheckEditorPanel`, NEW) | pass | arm 10 · `inc001_battery.txt` — 0 actionable apply controls; the struck-APPLY ghost is an inert Static |
| US-001 | HLR-001 | LLR-001.2 | TC-B94-07 | `s19_app/tui/app.py:2529` (route) · `app.py:2245` (mount) | pass | arm 01 · `pdr_rail_key_probe.txt` — the `=` binding resolves, zero collisions; write routing lands on the Check Editor |
| US-001 · US-007 | HLR-002 | LLR-002.1 | TC-B94-08 | `s19_app/tui/rail.py` (`RAIL_ENTRIES`, 12) · `app.py:1361-1370` | pass | arm 01 · `inc003_rail12_probe.txt` — 12 entries, ordered; 12 ≤ 21 rows at 80×24 |
| US-001 · US-007 | HLR-002 | LLR-002.2 | — (inspection) | `tests/test_tui_directionb.py:137-169` · `:468-479` | pass | inspection per contract §4 — the census constants moved WITH the landing increments (11 at Inc-001, 12 at Inc-003), never before |
| US-002 | HLR-003 | LLR-003.1 | TC-B94-09 | `s19_app/tui/screens_directionb.py:5054` (`PatchEditorPanel` rework) | pass | arm 02 · e2e ×2 pilot sizes — the expanded `JsonHighlightTextArea` is the primary edit surface |
| US-002 | HLR-004 | LLR-004.1 | TC-B94-01 | `s19_app/tui/changes/io.py:440` · `screens_directionb.py:6639` | pass | arms 03/13 · valid text merges 100% of declared entries in document order |
| US-002 | HLR-004 | LLR-004.2 | TC-B94-01 | `s19_app/tui/changes/io.py:440` (collected issues) | pass | arms 04/14 · invalid text leaves the table byte-identical, ≥1 issue displayed |
| US-002 | HLR-005 | LLR-005.1 | TC-B94-10 | `s19_app/tui/screens_directionb.py` (dirty-flag writers w1–w4) | pass | arms 05/09/16 — edit-table→set, edit-text→set, save→clear, load-success→clear |
| US-002 | HLR-005 | LLR-005.2 | — (via AT-B94-06/07) | `LoadGuardScreen` (`s19_app/tui/screens.py` modal idiom) | pass | arms 05/06 + fold round · `inc001_fold_popup_probe.txt` — exactly one popup; accept-loss and cancel branches both driven |
| US-002 | HLR-006 | LLR-006.1 | TC-B94-11 | `s19_app/tui/screens_directionb.py` (variant retirement) | pass | arms 07/17 v2 · 0 live variant symbols; a stale `VariantSelected`-shaped post is a no-op |
| US-002 | HLR-006 | LLR-006.2 | TC-B94-11 | `s19_app/tui/screens_directionb.py` (single-document binding) | pass | two consecutive Loads leave exactly one document bound |
| US-002 | HLR-007 | LLR-007.1 | TC-B94-02 | `s19_app/tui/apply.py:226` (gate `:320`) | pass | arm 14 · `p1_probe_chk_roundtrip.txt` — a check spec through the same gate → `blocked: 2`, `mem_map` untouched |
| US-002 | HLR-007 | LLR-007.2 | TC-B94-12 | `s19_app/tui/screens_directionb.py:5891` (`patch_doc_apply_button`) | pass | arm 18 — "Apply loaded changes" wording only; 0 legacy bare-"Apply" labels |
| US-002 | HLR-008 | LLR-008.1 | TC-B94-03 | `s19_app/tui/changes/io.py:296` · `screens_directionb.py:5800-5806` | pass | arm 15 — Load reads the adjacent path input; empty path → 1 collected issue, nothing loaded |
| US-002 | HLR-008 | LLR-008.2 | TC-B94-03 | `s19_app/tui/app.py:4413` (`_scan_patch_change_files`) | pass | Refresh repopulates the dropdown from the folder scan; the loaded document hash-equal before/after |
| US-003 | HLR-009 | LLR-009.1 | TC-B94-13 | `s19_app/tui/changes/io.py:1285` (`write_change_document`; `_safe_name` `:1406-1411`) | pass | arm 19 — the `.chk.json` double suffix survives `_safe_name`; the written file re-reads |
| US-003 | HLR-009 | LLR-009.2 | TC-B94-14 | `s19_app/tui/changes/check.py:194` (`run_check_document`) | pass | one verdict per entry (`pass` / `uncheckable` with reason `outside`) |
| US-003 | HLR-009 | LLR-009.3 | TC-B94-06 | `s19_app/tui/apply.py:320` (the kind gate) | pass | arms 10/14 · 0 apply controls in the composition; the gate probe is the executed negative control |
| US-003 | HLR-010 | LLR-010.1 | TC-B94-15 | `s19_app/tui/app.py:4413-4457` (scan idiom) + `AbDiffPanel` (`screens_directionb.py:7443`) | pass | check specs listed suffix-distinguished from patch files |
| US-003 | HLR-010 | LLR-010.2 | TC-B94-16 | `s19_app/tui/services/diff_report_service.py:1216` (`_check_addendum_lines`) | pass | arm 22 · `p1_probe_diff_report_emitted.txt` — 100% of declared names in the emitted `## Checks` table |
| US-003 | HLR-011 | LLR-011.1 | TC-B94-17 | `s19_app/utils.py:44-99` (`safe_text`) | pass | arm 23 — 0 markup-parsed constructions; the hostile payload renders with 0 control bytes |
| US-003 | HLR-011 | LLR-011.2 | TC-B94-17 | `CheckEditorPanel` render paths (`screens_directionb.py`) | pass | hostile symbol + file name render literally in the collector, the dropdown, and the addendum |
| **Inc-002 (IMPL-P3) — fb_a Flow Builder + A2B block + templates** | | | | | | |
| US-005 | HLR-013 | LLR-013.1 | TC-B94-20 | `s19_app/tui/flow_screens.py` (palette + canvas + `_Grid`) | pass | arm 01 — 3 placeable palette types; the palette+canvas compose inside the boxed budgets |
| US-005 | HLR-013 | LLR-013.2 | TC-B94-21 | `flow_persistence_service.py:175`/`:248` + `flow_model.py` (`BLOCK_A2B`) | pass | arm 06 — one-of-each-kind round-trip; the loader refuses the A2B binding arm |
| US-005 | HLR-013 | LLR-013.3 | TC-B94-22 | `s19_app/tui/services/flow_execution_service.py:86` (`run_flow`, A2B arm) | pass | arm 07 (the C-1 re-arm) — 0 image files written when an upstream block fails; per-block results recorded |
| US-005 | HLR-014 | LLR-014.1 | TC-B94-21 · TC-B94-23 | `flow_model.py` (`parse_a2b_binding` / `validate_a2b_bindings`) | pass | arm 02 — the accept/refuse matrix; the both-external pair refused (0 reports for refused bindings) |
| US-005 | HLR-014 | LLR-014.2 | TC-B94-24 | the flow-a2b report arm (`flow_execution_service.py` → `generate_diff_report`) | pass | arm 08 · `inc002_smoke_probe.txt` — both provenance lines emitted verbatim; no report on an upstream failure |
| US-005 | HLR-015 | LLR-015.1 | TC-B94-04 | `flow_persistence_service.py:522` (`save_flow_json`) | pass | arm 03 — the v1 envelope round-trips; a second same-name save lands under the dedup suffix (0 clobbers) |
| US-005 | HLR-015 | LLR-015.2 | TC-B94-04 | `flow_persistence_service.py:248` (`dict_to_flow`) | pass | the zero-block reload refusal stays `FLOW-BAD-STRUCTURE` — V1–V7 fail-closed, never re-opened |
| US-005 | HLR-016 | LLR-016.1 | TC-B94-25 | `flow_screens.py` via `utils.safe_text` + `services/markdown_safety.py` | pass | arm 05 — the Mode-A escaper holds; a hostile file name renders inert in the report |
| **Inc-003 (IMPL-P3) — fx_a Flow Execution + chain-sets + rail 12** | | | | | | |
| US-007 | HLR-017 | LLR-017.1 | TC-B94-26 | `FlowExecutionPanel` (`flow_screens.py`) over `flow_persistence_service.py:570`/`:463` | pass | arm 02 — one lane per template; cancel adds 0 lanes; corrupt refused; duplicates uniquify `_<N>` |
| US-007 | HLR-017 | LLR-017.2 | TC-B94-26 | `FlowExecutionPanel` lane container (`flow_screens.py`) | pass | two 46-cell lanes in the 96×18 workspace at 120×30; the 80×24 fallback scrolls inside `#fx_lanes_scroll` |
| US-007 | HLR-018 | LLR-018.1 | TC-B94-27 | `_FxLane.bindings` (`flow_screens.py`) | pass | arm 03 — editing lane A writes only lane A's record |
| US-007 | HLR-018 | LLR-018.2 | TC-B94-28 | `lane_specs()` → the runner (`flow_execution_service.py`) | pass | arm 09 — the run consumes each chain's own bindings; a stale input is never named after a rebind |
| US-007 | HLR-019 | LLR-019.1 | TC-B94-05 (+ AT-B94-22) | `run_chain_set` (`flow_execution_service.py`; sequential precedent `:133`) | pass | arms 04/05 — the untouched default never changes the mode; strictly sequential dispatch pinned |
| US-007 | HLR-019 | LLR-019.2 | TC-B94-05 (+ AT-B94-21) | `run_chain_set` parallel dispatch (`flow_execution_service.py`) | pass | parallel dispatch overlaps lanes with per-lane failure isolation; the mode is captured in the run record |
| US-007 | HLR-020 | LLR-020.1 | TC-B94-29 | the RUN LOG strip (`render_run`, `flow_screens.py`) | pass | arms 06/07 — one `▶ … started` + one terminal line per chain; the all-clean arm invents no failure |
| US-007 | HLR-020 | LLR-020.2 | TC-B94-30 | the `ChainSetRunRecord` report composer (`flow_execution_service.py`) | pass | one `- Chain <name> input <i>: <ref> [bound] path=…` line per bound input; deterministic, markup-safe |
| US-007 | HLR-021 | LLR-021.1 | TC-B94-31 | `save_chain_set` (`flow_persistence_service.py`) | pass | arm 10 — the v1 envelope round-trips chains + bound inputs + recorded outputs; empty/hostile sets write NOTHING |
| US-007 | HLR-021 | LLR-021.2 | TC-B94-31 (+ AT-B94-24) | `load_chain_set` / `dict_to_chain_set` (`flow_persistence_service.py`) | pass | the reload REPLACES the lanes; a moved bound input mounts the provenance-mismatch notice; a gone template is skipped and NAMED |
| **Inc-004 (IMPL-P3) — Issues warnings triage** | | | | | | |
| US-004 | HLR-012 | LLR-012.1 | TC-B94-18 | `issues_view.py` (the curated-set constant + the predicate) | pass | arms 05/06 · `inc004_battery.txt` — the curated set is exactly the 21 executed families (1 023 findings); 0 engine hunks vs `main` |
| US-004 | HLR-012 | LLR-012.2 | TC-B94-19 | `GroupedIssuesPanel.render_groups` + `adjust_counts_for_a2l_triage` (`issues_view.py`) | pass | arms 01/02/04 — the INFO/WARNING split remaps rows only (the caller's list is never mutated); the hostile `[red]` payload renders with 0 spans |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | HLR-001 | LLR-001.1 | TC-001 | `src/foo.ts:42` | pass | |
| *(example)* US-001 | HLR-001 | LLR-001.2 | TC-002 | `src/foo.ts:78` | pass | |
| *(example)* US-001 | HLR-002 | LLR-002.1 | TC-003 | `src/bar.ts:15` | pass | |
| *(example)* US-002 | HLR-003 | LLR-003.1 | TC-004 | `src/baz.ts:90` | fail | See gap G-001 |
```

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface. All 24 rows pass per `04-validation.md` §Layer B (`24/24` ids, one on-disk node each per `C-18` — with the single ratified two-node exception on the `AT-B94-24` row, `DDR-2026-10-12-batch-94#COND-2`).

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-001 | AT-B94-01 | the rail + pilot; the `=` binding pressed through the pilot | the mounted `CheckEditorPanel` twin (the composed panel census) | pass — arm 01 · `inc001_battery.txt` |
| US-001 (HLR-002) | AT-B94-02 | the shipped rail at 120×30 / 80×24 / 160×40 | 12 ordered entries painted; `]` mounts `FlowExecutionPanel`; the footer does not drift (12 ≤ 21 rows at 80×24) | pass — `inc003_rail12_probe.txt` (`PROBE: PASS`) · arm 01 |
| US-002 | AT-B94-03 | the reworked Patch Editor under the pilot at both sizes | the expanded `JsonHighlightTextArea` as the primary edit surface (widget census on `render().plain`) | pass — arm 02 |
| US-002 | AT-B94-04 | Edit-JSON + validate through the panel | 100% of the declared entries merged into the entries table in document order | pass — arm 03 |
| US-002 | AT-B94-05 | invalid Edit-JSON text | the collected issues surface; the entries table byte-identical | pass — arm 04 |
| US-002 | AT-B94-06 | Load with unsaved edits | the `LoadGuardScreen` popup; the accept-loss branch; exactly one popup and the stack drains empty | pass — arm 05 + fold round · `inc001_fold_popup_probe.txt` |
| US-002 | AT-B94-07 | the cancel branch (clean load = `AT-B94-07b`, pops nothing) | the loaded document is kept on cancel | pass — arm 06 |
| US-002 | AT-B94-08 | the retired selector's seam | a stale `VariantSelected`-shaped post is a no-op; 0 live variant symbols in the editor surfaces | pass |
| US-002 | AT-B94-09 | Apply presented as "Apply loaded changes" | exactly the loaded document's entries applied through the existing gate; skips never counted as applied | pass |
| US-002 | AT-B94-10 | Load (adjacent path input) + Refresh | Load reads the path input; Refresh repopulates the dropdown from the folder scan, the loaded document untouched | pass — arms 09/15/16 |
| US-003 | AT-B94-11 | the Check Editor's write / validate controls | the written `.chk.json` (v2 `kind="check"`, the 315-byte emitted form re-read); 0 actionable apply controls | pass — arms 10/14 · `p1_probe_chk_roundtrip.txt` |
| US-003 | AT-B94-12 | the A2B Diff dropdown | check specs listed suffix-distinguished from patch files; the C-12 chain runs writer → THAT file → the report | pass — arm 11 |
| US-003 (HLR-011) | AT-B94-13 | the shipped Check Editor fed a hostile symbol + file name | the `safe_text`-scrubbed render: 0 spans / 0 control bytes survive | pass — arm 12 |
| US-004 | AT-B94-14 | the live app chrome on the 13 990-tag fixture through the real engine path, 120×30 pilot | `#issues_severity_strip` `Warnings 0 · Info 1023`; `#validation_issues_summary` `errors=0 · warnings=0 · info=1023`; the group headers agree | pass — arms 01–05/07 · `inc004_battery.txt` |
| US-005 | AT-B94-15 | the fb_a palette + canvas under the pilot | the box-drawn canvas render paste (`┌─┐` frames, `┤├` typed stubs, `└┐` bends, `·` dots; every line ≤ 88 cells) + the empty-state arm | pass — arm 01 · `inc002_smoke_probe.txt` |
| US-005 | AT-B94-16 | the real Add control with `#flow_ref_a` / `#flow_ref_b` bindings | the wiring-refusal notice through the real control; the accepted (flow,file)/(flow,flow) arms produce the report with provenance lines | pass — arm 02 · `inc002_smoke_probe.txt` |
| US-005 | AT-B94-17 | Save template + the listing + re-import | the v1 envelope on disk; a second same-name save lands under the dedup suffix — 0 clobbers | pass — arm 03 |
| US-005 | AT-B94-18 | hostile block / file names through the canvas | names render literally (the canvas-label scrub); the `from_markup` AST census stays 0 | pass — arm 04 |
| US-007 | AT-B94-19 | Import… through the reused `LoadFlowScreen` picker | one lane per template, mounted side by side; a cancelled picker adds 0 lanes; a corrupt template is refused; duplicate imports uniquify — 0 duplicate lanes | pass — arm 02 |
| US-007 | AT-B94-20 | the per-lane Bind control | the Bind writes only its own lane; the run reads each chain's own inputs | pass — arms 03/09 |
| US-007 | AT-B94-21 | the mode Select (parallel-per-chain) | overlapping time windows across lanes + per-lane failure isolation + the mode captured in the record and the report | pass — arms 04/05 |
| US-007 | AT-B94-22 | the untouched default run | strictly sequential dispatch — the mechanism pinned, not only the timing | pass |
| US-007 | AT-B94-23 | Run over a set with a failing chain | the RUN LOG strip: one `▶ … started` + one terminal line per chain; the inline `✗` names the failed chain's block and its missing config; the report's provenance lines | pass — arms 06/07 · `inc003_smoke_probe.txt` |
| US-007 | AT-B94-24 | Save Set / Load Set + the re-run | `flowsets/<name>.json` written (chains + bound inputs + recorded outputs); the reload REPLACES the lanes; both outputs regenerate on the reloaded re-run; a moved bound input mounts the per-lane provenance-mismatch notice; a chain whose template is gone is skipped and NAMED | pass — arms 08/10 · **two-node realization ratified as accepted, `DDR-2026-10-12-batch-94#COND-2`** — the UI node `tests/test_tui_flow_execution_b94.py:846` drives the whole named chain end-to-end; the service node `tests/test_flow_chainset_b94.py:484` is the declared supplementary arm |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | AT-001 | `<handler/screen/CLI>` | `<outcome / file:path>` | pass |
```

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | `6` commissioned (US-001…US-005, US-007 — US-006 parked `REFINE` awaiting operator answers; US-008/US-009 OUT per contract §2.6) |
| Covered user stories | `6` (`100%`) — every commissioned story has ≥1 passing AT and a complete functional chain |
| Total HLR | `21` |
| Implemented HLR | `21` (`100%`) |
| Total LLR | `42` |
| Implemented LLR | `42` (`100%`) — each with an executed verification + numeric threshold (contract §5.2 criterion 1) |
| Test cases | `31` |
| TC pass | `31` |
| TC fail | `0` |
| TC pending | `0` |

> Layer A executor attribution per `04-validation.md`: Inc-001 = ORCH-P3 · Inc-002/003/004 = IMPL-P3. Layer B: 24/24 ids pass, one on-disk node each per `C-18` (the `AT-B94-24` two-node realization the one ratified exception — `DDR-2026-10-12-batch-94#COND-2`).

---

## 3. Detected gaps

> Incomplete rows, requirements without TC, or TCs without code mapping. **None — no gap.** All 42 LLRs carry an executed verification with a numeric threshold; all 31 TC ids and all 24 AT ids pass; every TC/AT maps to a shipped file:line anchor in §1/§1b. Three LLRs are verified by inspection or by AT arms rather than a dedicated TC id (LLR-002.2 inspection — the census constants move with the landing increments; LLR-005.2 and LLR-019.1 via their AT arms) — each is marked on its row and is a method choice, not a coverage gap.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| *(none — no gap)* | | | |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* G-001 | TC fail | TC-004 fails on condition X | See post-mortem phase 5 |
| *(example)* G-002 | no coverage | LLR-005.2 has no associated TC | Move to next batch |
```

---

## 4. Changes from previous batch

*(What was added, modified, or closed since the previous batch — `2026-10-06-batch-93` close.)*

| Type | Item | Detail |
|------|------|--------|
| new | HLR-001…021 · LLR-001.1…021.2 | The whole batch-94 requirement set — Cambio1–7 commission (contract §3/§4) |
| new | `s19_app/tui/flow_screens.py` | NEW module (R8) — the fb_a Flow Builder (moved address, B2) + the fx_a Flow Execution panel; `docs/architecture.md` §10 batch-94 declarations |
| new | `.chk.json` artifact + `## Checks` addendum | The check-spec file type (suffix on the unchanged v2 grammar, R10) and the A2B Diff report addendum (`_check_addendum_lines`) |
| new | rail entries + bindings | Rail grew 10→12: Check Editor on `=`, Flow Execution on `]`, both `show=False` (PDR-ratified, `pdr_rail_key_probe.txt`); census constants moved with the landing increments (LLR-002.2) |
| new | chain-set artifact | `flowsets/<name>.json` — chains + bound inputs + recorded outputs (US-007); the chain-set report with per-run input provenance |
| modified | `PatchEditorPanel` | pe_b rework in place — expanded editor, Edit-JSON + validate, dirty-guarded Load, variant selector retired, "Apply loaded changes" (HLR-003…008) |
| modified | Issues surface (US-004) | View-level reclassification of curated `A2L_UNRECOGNIZED_BLOCK` findings to INFO with justification — engine (`rules.py`, `a2l.py`) frozen (D-1); 1 023→0 WARNING on the stand-in fixture |
| closed | the carried notes N-1…N-6 | Not coverage gaps — the `04-validation.md` named notes with owners: N-4 discharged in-batch; N-1 (the 29 snapshot marks await the canonical-CI regen), N-2 (batch-95 IFC baseline → coordination note), N-3 (the load-flaky family's standing status), N-5 (the carried owner items — Inc-004 F1/F2 rulings, the A4 `=`/`]` field check, TC-707 → batch-95), N-6 (the Layer-0 legal empty, `C-51`) |
| carried | US-006 (CRC test-vector) | Parked `REFINE` — operator questions pending; does not block US-001…005/007 (contract §2.6) |
| carried | US-008 / US-009 | OUT of the Cambio1–7 commission — filed to lane A at close (contract §2.6) |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-001** (Cambio1, editor split) → HLR-001, HLR-002 → LLR-001.1, LLR-001.2, LLR-002.1, LLR-002.2 → TC-B94-06/07/08 · AT-B94-01/02
- **US-002** (Cambio2, Patch Editor rework) → HLR-003…008 → LLR-003.1, LLR-004.1/.2, LLR-005.1/.2, LLR-006.1/.2, LLR-007.1/.2, LLR-008.1/.2 → TC-B94-01/02/03/09/10/11/12 · AT-B94-03…10
- **US-003** (Cambio3, Check Editor + `.chk.json`) → HLR-009, HLR-010, HLR-011 → LLR-009.1/.2/.3, LLR-010.1/.2, LLR-011.1/.2 → TC-B94-06/13/14/15/16/17 · AT-B94-11/12/13
- **US-004** (Cambio4, Issues triage) → HLR-012 → LLR-012.1, LLR-012.2 → TC-B94-18/19 · AT-B94-14
- **US-005** (Cambio5, Flow Builder + templates) → HLR-013…016 → LLR-013.1/.2/.3, LLR-014.1/.2, LLR-015.1/.2, LLR-016.1 → TC-B94-04/20/21/22/23/24/25 · AT-B94-15…18
- **US-007** (Cambio7, Flow Execution + chain-sets) → HLR-002 (census half), HLR-017…021 → LLR-017.1/.2, LLR-018.1/.2, LLR-019.1/.2, LLR-020.1/.2, LLR-021.1/.2 → TC-B94-05/08/26/27/28/29/30/31 · AT-B94-02/19…24

### 5.2 By code file
- `s19_app/tui/screens_directionb.py` → LLR-001.1/.2, LLR-003.1, LLR-004.1/.2, LLR-005.1/.2, LLR-006.1/.2, LLR-007.1/.2, LLR-008.1/.2, LLR-011.2 → TC-B94-01/02/03/06/07/09/10/11/12 · AT-B94-01/03…10/13
- `s19_app/tui/changes/io.py` → LLR-009.1, LLR-010.1 → TC-B94-13/15 · AT-B94-11/12
- `s19_app/tui/services/diff_report_service.py` → LLR-010.2 → TC-B94-16
- `s19_app/tui/apply.py` (untouched; the kind gate) → LLR-007.1, LLR-009.3 → TC-B94-02 (gate probe)
- `s19_app/tui/app.py` → LLR-001.2, LLR-002.1/.2, LLR-005.2 (handler), LLR-008.2 (scan), LLR-012.2 (the counts fold) → TC-B94-08 · AT-B94-02/14
- `s19_app/tui/flow_screens.py` → LLR-013.1, LLR-014.1, LLR-016.1, LLR-017.1/.2, LLR-018.1, LLR-020.1 → TC-B94-20/23/26/27/29 · AT-B94-15/16/18/19/20/21/22/23/24
- `s19_app/tui/services/flow_model.py` → LLR-013.2, LLR-014.1 → TC-B94-21/23
- `s19_app/tui/services/flow_persistence_service.py` → LLR-013.2, LLR-015.1/.2, LLR-021.1/.2 → TC-B94-04/31
- `s19_app/tui/services/flow_execution_service.py` → LLR-013.3, LLR-014.2, LLR-018.2, LLR-019.1/.2, LLR-020.2 → TC-B94-05/22/24/28/30
- `s19_app/tui/issues_view.py` → LLR-012.1, LLR-012.2 → TC-B94-18/19 · AT-B94-14
- `s19_app/utils.py` (untouched; the safety primitive) → LLR-011.1 → TC-B94-17

**Worked examples of both maps — text to read, never lines of your record:**

```text
- *(example)* **US-001** → HLR-001, HLR-002 → LLR-001.1, LLR-001.2, LLR-002.1 → TC-001, TC-002, TC-003
- *(example)* `src/foo.ts` → LLR-001.1, LLR-001.2 → TC-001, TC-002
- *(example)* `src/bar.ts` → LLR-002.1 → TC-003
```

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-10-12-batch-94` |
| Closing date | `2026-10-18` (opened 2026-10-12; gates through P5 closed 2026-10-18; this P6 artifact written at the P6 station) |
| Total iterations (sum of phases) | `13` station-runs — P0 · ARQ · P1 · P2 · PDR · P3 ×4 increments · DDR · P4 (+2 fix rounds at the P4 iterate-to-fix) · P5 · P6 |
| Validation passed | yes — `PASS-WITH-NOTES` (the notes are the named N-1…N-6 carries with owners, not coverage gaps) |
| Synced to Obsidian | no — awaits the PR merge + `/dev-flow-sync` (per `p6-documentation.md`: documentation ready, then sync after merge) |
