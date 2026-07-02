# 02 — Cross-agent review — 2026-07-01-batch-23 (US-028)

> **Verdict: PROCEED ×3 (architect APPROVE-WITH-FIXES · qa APPROVE · security OK-with-mitigation). 1 BLOCKER (rule-triggered, resolved-by-verification at this gate) · 5 MAJOR · 9 MINOR — ALL FOLDED body-first into 01-requirements.md / 01b-validation-strategy.md before this gate (§6.4 log). No design change: Option B, the increment plan, and the census all stand.** *(Count corrected 4→5 MAJOR at Phase-5 audit — the register below was always right: F-4, F-2, F-3, SEC-F2, qa-M1.)*
>
> Reviewers: architect ∥ qa-reviewer ∥ security-reviewer (parallel, independent). Targets: 01-requirements.md + 01b-validation-strategy.md. Every disposition below names its fold location.

## 1. Findings register

| ID | Sev | Source | Finding (one line) | Disposition (folded where) |
|---|---|---|---|---|
| F-1 | **BLOCKER** | architect | "Same-value `Select` emits no `Changed`" stated as fact, uncited/unflagged (rule: unverified-and-unflagged claim) | Verified TRUE on installed textual 8.2.5 (`_select.py:362`, watcher `:600-617`) → version-pinned citations in 01b §2/§5 + §6.1 **A-5 VERIFIED** row. RESOLVED |
| F-4 | MAJOR | architect | `set_options` RESETS selection to BLANK + fires watcher (`_select.py:559-575`) → every repopulate emits `Changed(BLANK)`+`Changed(active_id)`; value-not-in-options raises (`:594`). Batch-22-R1-class framework surprise, unstated | Verified framework note added to LLR-035.3 (order: `set_options` strictly before value assignment); .4 short-circuits now normatively tied to this pair; TC-035.3/.4 updated |
| F-2 | MAJOR | architect | N==1 contradiction: LLR-035.3 "value == active_id on repopulate" vs .5/AT-035c(ii) disabled+BLANK | .3 scoped to N≥2; N<2 → `set_variants([])` + BLANK, no preselection; thresholds aligned |
| F-3 | MAJOR | architect | Disabled/enabled TRANSITION owner unassigned (falls between .3 and .5); stale state on project switch while patch shown | Trigger set added to .3: (a) patch-screen activation AND (b) variant-set change while shown |
| SEC-F2 | MAJOR | security | Switch-during-load race: single unguarded `_pending_variant_id` slot (`app.py:3049/6138-6146/6506`) — rapid A→B can mislabel state and side-door a phantom variant copy into the project dir (`app.py:6508-6509/4250-4262`), persisted at next save. Inline Select materially amplifies (modal made spam impractical) | **NEW LLR-035.7** (suppress-while-loading OR generation-checked stamp) + **TC-035.7** (rapid double-switch: label==content, 0 files created) + §6.3 security row amended |
| qa-M1 | MAJOR | qa | 01b had NO authoring rows for canonical TC-035.1 (compose) and TC-035.6 (no-write/Q2) — the orchestrator reconciliation note's fold-in claim was incomplete; the Q2 invariant test could plausibly not get written | Both rows added to 01b §3 (copy-down of §4 thresholds + counterfactuals) |
| F-7/qa-M2 | MINOR | both | Dual live TC numbering = Phase-4 mis-key trap | 01b §3 mechanically renumbered to canonical LLR-aligned ids; header note updated |
| qa-M3 | MINOR | qa | LLR-035.2 "≥1 row overlap" satisfiable by an inoperable border-only sliver | Threshold tightened: Select's FIRST row within visible content_region at scroll 0 |
| F-5/qa-M4 | MINOR | both | `manifest_writer.py` cited without `services/` path | Full path in §2.5 (module unique; cosmetic) |
| F-6/qa-M6 | MINOR | both | Hex-view hosting caveat unbound; R-1 unresolved in AT-035a | **R-1 RESOLVED**: CommandBar app-persistent (`app.py:1014-1017`) → label no-hop; hex on workspace screen → exact hop step bound in 01b AT-035a + §3 Acceptance note |
| F-8 | MINOR | architect | Initial `disabled` at construction unstated | `disabled=True` added to LLR-035.1 statement |
| qa-M5 | MINOR | qa | Private-method DRIVES (`_handle_save_dialog`/`_handle_load_project`) vs the house black-box ban | Drive-level exception sentence added to 01b §2 (ban applies to ASSERTS; drives are the ratified idiom) |
| SEC-F1 | MINOR | security | Symlinked `.s19` in project dir lists as a dead dropdown option (fails safely at `copy_into_workarea`); pre-existing in the modal too | OUT of US-028 scope — optional parity hardening (scan `is_symlink()` skip) logged to BACKLOG |
| SEC-F3 | none | security | Log/notify scrub NOT required — variant ids are filesystem-derived (not free text), no new sink | No action (recorded in §6.3 amendment) |

## 2. Key audit verdicts (evidence in the agents' reports)

- **Draft-time verification:** 14/15 cited anchors verified exactly on disk; the 15th (F-1) verified true after flagging. C-13 numbers consistent with the committed batch-22 measurement (`styles.tcss:558-559`).
- **C-10 PASS (qa):** AT-035a genuinely drives off the default (`a`→`b`, pinned by `test_project_load_activates_first_variant`); `select.value = "b"` proven equivalent to a user pick (reactive → watcher → same `Changed` path; precedent asserts the downstream service effect). Caveats (same-value no-emit; assignment bypasses `disabled`) both already handled in the AT designs.
- **C-12 PASS (qa):** AT-035b chain genuine (handler pipeline → shipped save → RAW `json.loads` disk re-read → fresh-app unmodified consume); counterfactual discriminating (`a` sorts first); `tests/test_variant_execution.py:173` correctly barred from gating (zero counterfactual power).
- **Security containment (decisive Q): NO US-026-F1 analogue needed** — provenance is a directory scan (`workspace.py:360-365, 438-445`), never manifest paths; every activation is forced through `copy_into_workarea` (`app.py:4470` → `workspace.py:268-299`: symlink-reject + containment + 256 MB cap) — a STRONGER chokepoint than F1; forged Select ids die at the unknown-id guard (`app.py:3036-3039`) as lookup keys, never paths; manifest `active_variant` consumed as a validated id (`app.py:4147-4150`).
- **Census PASS (architect, concrete):** only `tests/test_tui_patch_layout.py` references the pane — AT-033a/b assert pane REGIONS (fixed 1fr grid cells; an inner group cannot move them) → survive; AT-033c and `test_tc_pane_styles_and_grid` assert untouched widgets/styles → survive. No bare `query(Select)` in tests/ (0 hits). US-026's `on_select_changed` early-returns on id mismatch (`screens_directionb.py:929-931`) → no event leakage either way; Phase 3 extends that dispatch. Snapshot cells stay xfail (no baseline). AST probe + modal test stay green.
- **Two-layer blocker checks (qa):** (a) black-box ATs ✓ (b) deliverable+observation named ✓ (c) both chains complete ✓ (d) gate asserts genuinely black-box, zero private-attr reads ✓.

## 3. `shall`/`should` audit

0 `should`-as-modal across both artifacts (re-scanned post-fold); all new normative text (LLR-035.3 rewrite, LLR-035.7) uses `shall` inside statements only.

## 4. Evidence checklists

All three reviewers returned completed checklists (architect 8/9 ✓ + F-1 ✗→fixed; qa 9/10 ✓ + M1 ✗→fixed; security 5/5 ✓) — full text in the agent reports; folded items re-verified by the orchestrator at fold time.

## 5. Gate

- **Blockers:** 1 raised (F-1) → resolved at this gate by verification + citation (the claim was TRUE; the rule violation was the missing flag). No unresolved blocker remains.
- **Iteration accounting:** folds were requirement-text refinements fully specified by reviewers; no re-derivation, no design change → recorded as Phase-2 folds (§6.4), not a Phase-1 re-run (batch-22 R1 precedent).
- **Exit-criteria axes:** Coverage — chains complete incl. new LLR-035.7→TC-035.7 ✓ · Certainty — the one unverified claim now verified+pinned; all ATs non-vacuous with stated counterfactuals ✓ · Evidence — every finding and fold carries file:line ✓.
