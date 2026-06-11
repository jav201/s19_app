# Validation — s19_app — Batch 2026-06-10-batch-07

> Phase 4 executed 2026-06-11 by qa-reviewer. Run-ownership per post-mortem A-6: qa-reviewer ran every per-LLR targeted suite + all inspections (this document); the orchestrator owns the lean and slow full passes — lean cited verbatim from the E8 gate, slow appended by the orchestrator below.

---

## 1. Executive verdict

**PASS-WITH-NOTES.**

- **All 9 targeted test clusters pass: 196/196 tests, 0 failures** (suites re-run in this worktree at HEAD b1cde0c, evidence verbatim in §2).
- **All structural inspections pass** (retirement probe 0 hits, `cdfx/` empty, no-Textual probes clean, rail diff empty, F-S-01/F-S-06 pins present, app.py orchestration-only).
- **Suite-count reconciliation balances EXACTLY** — to the single test, at every increment checkpoint — once the collection basis is corrected (§4). No unexplained terms remain.
- **No blocker-level FAIL. No Phase-3 iteration required.**

The "NOTES" qualifying the pass:
1. **CI-1 is NOT yet in the tree** (§3 criterion 5): `.github/workflows/tui-ci.yml` at HEAD still runs plain `pytest -q`; the two-tier gate (PR `-m "not slow"` / full on `main` push) is a pending ~3-line edit that MUST ride the batch PR. Open item, not a code defect.
2. One spec↔code test-name drift found during execution (HLR-008's named node id) — doc-only, registered in §5 (DEV-8).
3. The `patch-comfortable-120x30` snapshot cell remains `xfail(strict=False)` pending the CI-env baseline regen (by design — project memory forbids local regen).
4. Slow-marker suite and full Python 3.11 confirmation are orchestrator/CI-owned (markers below).

---

## 2. Per-HLR/LLR-cluster results

All commands executed from the worktree root (`C:\Users\jjgh8\OneDrive\Documents\Github\s19_app\.claude\worktrees\sweet-yonath-bd8bd2`, branch `claude/batch-07`, HEAD b1cde0c) with `python -m pytest`. Evidence lines are verbatim tool output.

| # | Cluster (HLRs / LLRs) | TCs | Command | Verbatim evidence | Verdict |
|---|---|---|---|---|---|
| 1 | HLR-001 — v2 format + reader/validator (LLR-001.1–.5, .7, .8) | TC-001..005, 007, 008 | `pytest -q tests/test_changes_schema.py tests/test_changes_collision.py` | `42 passed in 0.68s` | **PASS** |
| 2 | HLR-002 + LLR-001.6 — apply engine, summary, linkage, containment (LLR-002.1–.6, engine half of .7) | TC-006, TC-009..014, TC-051-engine | `pytest -q tests/test_changes_apply.py tests/test_changes_linkage.py tests/test_changes_containment.py` | `23 passed in 0.43s` | **PASS** |
| 3 | HLR-003 + UI halves of 002.7/002.8 — Patch Editor v2 + change_service (LLR-003.1, .2, .4, .5; 002.7-UI; 002.8; 004.5) | TC-015, 016, 019, 024, TC-051-UI, TC-052 | `pytest -q tests/test_tui_patch_editor_v2.py tests/test_change_service.py` | `24 passed in 6.09s` | **PASS** |
| 4 | HLR-004 — check engine (LLR-004.1–.4) | TC-020..023 | `pytest -q tests/test_checks_engine.py` | `7 passed in 0.59s` | **PASS** |
| 5 | HLR-005 — multi-variant workspace + TUI (LLR-005.1–.6) | TC-025..030 | `pytest -q tests/test_workspace_variants.py tests/test_tui_variants.py -m "not slow"` | `20 passed in 9.65s` | **PASS** |
| 6 | HLR-006 — manifest + batch/per-variant execution (LLR-006.1–.5) | TC-031..035 | `pytest -q tests/test_variant_execution.py -m "not slow"` | `11 passed in 2.58s` | **PASS** |
| 7 | HLR-007 — report generator (LLR-007.1–.8, .x) | TC-037..044 | `pytest -q tests/test_report_service.py -m "not slow"` | `13 passed, 1 deselected in 0.43s` (the 1 deselected = the E7 slow measurement test, orchestrator-owned) | **PASS** |
| 8 | HLR-008 — report viewer + headless generation (LLR-008.1–.5) | TC-045..049 | `pytest -q tests/test_report_service.py::test_generation_is_headless_no_app tests/test_tui_report_view.py -m "not slow"` | `9 passed in 9.92s` | **PASS** (node-id drift vs spec — see DEV-8) |
| 9a | §5.3 engine read-only guard (relocated TC-027) | TC-027-guard | `pytest -q tests/test_engine_unchanged.py` | `1 passed in 0.04s` | **PASS** |
| 9b | Migrated/surviving stack (§6.6 SURVIVES + in-place REWRITE) | §6.6 enactment | `pytest -q tests/test_memory_display.py tests/test_memory_changelist.py tests/test_memory_validate.py tests/test_unified_read.py tests/test_unified_write.py tests/test_unified_rules.py tests/test_unified_roundtrip.py` | `87 passed in 0.67s` | **PASS** |
| 10 | TC-053 roll-up — full lean suite | TC-053 | **Orchestrator-owned** (A-6); cited from the E8 gate run | `670 passed, 29 skipped, 20 deselected, 3 xfailed` — 0 failures | **PASS** (orchestrator) |
| 11 | Slow-marker suite (`-m slow`) | — | **Orchestrator-owned** (A-6) | `20 passed, 702 deselected in 460.57s (0:07:40)` — 0 failures (19 pre-batch + 1 E7 measurement = 20; 20+702=722 collected, matching §4) | **PASS** (orchestrator) |

Targeted-suite total run by qa-reviewer: **196 passed / 0 failed** (42+23+24+7+20+11+13+9+1+87, with the headless-no-app node counted once inside cluster 8).

Note on cluster 8: HLR-008's verification line names `test_generate_report_headless_no_app`; the implemented test is `tests/test_report_service.py::test_generation_is_headless_no_app` (same intent — `App.__init__` monkeypatched to raise per F-Q-07, docstring cites LLR-008.4). First invocation with the spec's literal id returned `ERROR: not found`; corrected run passed. Registered as deviation DEV-8.

Demo criteria (HLR-008 viewer scroll; LLR-006.6 no-freeze): observable procedures executed at the E6/E8 gates per the packets (F-Q-18 status-line states asserted by `test_variant_execution.py`/pilots; viewer pilots in `test_tui_report_view.py` cover listing/render/refusal). The operator-facing demo pass is recorded in the E6/E8 packets; no re-demo was needed at Phase 4.

### Inspection register (all executed this session)

| Inspection | LLR | Command / probe | Result | Verdict |
|---|---|---|---|---|
| Retirement symbol probe | 003.3 | `grep -rE "read_cdfx\|write_cdfx\|ChangeListEntry\|export_unified" s19_app/` | **0 hits** (probe self-test recorded at E3b: 164 pre-delete hits → live) | **PASS** |
| Package emptiness | 003.3 | `git ls-files s19_app/tui/cdfx/` | empty output | **PASS** |
| No-Textual: `changes/` package | 002.4, 004.4 | `grep -rn "textual" s19_app/tui/changes/` | 0 hits | **PASS** |
| No-Textual: 3 new services | 006.3, 007.1 | `grep -n "textual" services/change_service.py services/variant_execution_service.py services/report_service.py` | 0 hits | **PASS** |
| Rail untouched (8 items) | 008.2 | `git diff main..HEAD --stat -- s19_app/tui/rail.py` | empty diff | **PASS** |
| F-S-06 `open_links=False` pin | 008.1 | grep code + test | `screens.py:375` `Markdown("", open_links=False, id="report_markdown")`; `test_tui_report_view.py:224` `assert open_links is False` | **PASS** |
| F-S-01 sanitizer adversarial cases | 002.7 | grep tests | `test_changes_apply.py:364-367` params `..\escape.s19` / `C:\Windows\Temp\escape.s19` / `CON.s19` / trailing-dot; `test_tui_patch_editor_v2.py:456,470` TUI prompt cases | **PASS** |
| app.py orchestration-only | §5.3 / 008.5 | `grep -n "REPORT_MODE\|align16\|CHG-" s19_app/tui/app.py` | exactly 2 hits, both the allowed constant reference: `:68` import + `:1821` use of `EXECUTION_SCOPE_TO_REPORT_MODE`; zero `align16`/`CHG-` hits | **PASS** |
| Engine read-only guard | §5.3 | `pytest -q tests/test_engine_unchanged.py` | `1 passed` (`test_tc027_engine_modules_unchanged_vs_main`) | **PASS** |
| 0 local SVG baseline regens | §5.3 | `git diff main..HEAD --stat -- "*.svg"` | empty; only `tests/test_tui_snapshot.py` touched (the xfail pin at `:386`) | **PASS** |
| CI-1 two-tier gate | §5.3 / CI-1 | `cat .github/workflows/tui-ci.yml` + `git diff main..HEAD -- .github/workflows/` | Workflow at HEAD still runs plain `pytest -q`; diff vs main carries only pre-batch edits (PR-to-main trigger + Pillow). **Two-tier gate absent from the tree.** | **OPEN — must ride the batch PR** |

---

## 3. §5.3 batch acceptance criteria checklist

| # | Criterion | Evidence | Status |
|---|---|---|---|
| 1 | 100% of LLRs covered by ≥1 passing TC; 0 blocker fails | §2 clusters 1–9: every LLR's named executed verification maps into a passing cluster; 196/196 targeted + lean 670/0 (orchestrator, E8) | **MET** |
| 2 | §6.6 disposition table fully enacted at E3b | Ledger §4: all 229 RETIRE removed (215 via 15 whole-file deletions + 14 in-file); REWRITE: 28 of 50 re-pinned in place + 22 enacted as folds with named targets (ratified at the E3b gate — DEV-4); SURVIVES: 63 passing unchanged + 6 ratified re-dispositions (DEV-2), §2 cluster 9b `87 passed`; all 7 DEPENDS-ON-DESIGN resolved (D1/D2 at the 2026-06-10 gate, D3 by E3a measurement, cross-cutting via LLR-001.8) | **MET** (with ratified notes) |
| 3 | Suite-count reconciliation balances exactly | §4 — balances to the single test at all 3 measured checkpoints (915, 662, 722) | **MET** |
| 4 | Engine read-only guard green | `tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` → `1 passed` (relocated from `test_cdfx_unchanged.py` per E3b; §5.3's original path is the pre-relocation name) | **MET** |
| 5 | CI-1 landed: PR gate `-m "not slow"` + full suite on `main` push, both green | **NOT in tree at HEAD b1cde0c** — workflow still single-tier `pytest -q` (inspection above). Plan said "CI-1 rides the first PR"; the batch PR is not yet open. | **OPEN** — required action: include the ~3-line two-tier workflow edit in the batch PR; confirm both jobs green on the PR (also the full Python 3.11 confirmation point) |
| 6 | 0 SVG baselines regenerated locally; exactly 1 (`patch-comfortable-120x30`) regenerated in CI env | 0 local regens (inspection above); the 1 CI-env regen is pending — cell pinned `xfail(strict=False)` (`test_tui_snapshot.py:386`) until the canonical CI env regenerates it | **MET (local half)** / CI half pending by design |
| 7 | No report-assembly/JSON-I/O logic in `app.py` | Inspection: 2 hits, both `EXECUTION_SCOPE_TO_REPORT_MODE` constant references (the F-A-17 wiring deliberately housed in `report_service.py`); no schema codes, no window math | **MET** |

---

## 4. Suite-count reconciliation (named check, F-Q-14 exact ledger)

**Measured:** `python -m pytest --collect-only -q` → **`722 tests collected in 0.54s`**.

### 4.1 Basis correction (required for the equation to close)

The pre-batch figure circulated as "794 (775 lean + 19 slow)" counts only *passed* lean tests and omits collected-but-not-passed items. Collection = passed + skipped + xfailed + deselected. Cross-check against the E8 lean line: 670 + 29 + 3 + 20 = **722** = measured collect-only ✓ exact. Applying the same identity to the batch-06 close (`775 passed, 29 skipped, 19 deselected, 3 xfailed`):

**True pre-batch collection = 775 + 29 + 3 + 19 = 826.**

Independent confirmation: the E3b packet measured pre-delete collection **915** = 826 + 42 (E1) + 23 (E2) + 24 (E3a) ✓ exact. On the 794 basis the chain misses by exactly 32 (= 29 skipped + 3 xfailed) at every checkpoint — the discrepancy is fully explained and closed.

### 4.2 Per-increment N_i ledger (measured per-file collection at HEAD, `--collect-only -q` grouped by file)

| Increment | New test files | N_i (collected) |
|---|---|---|
| E1 | `test_changes_schema.py` 33 + `test_changes_collision.py` 9 | 42 |
| E2 | `test_changes_apply.py` 16 + `test_changes_linkage.py` 2 + `test_changes_containment.py` 5 | 23 |
| E3a | `test_tui_patch_editor_v2.py` 8 + `test_change_service.py` 16 | 24 |
| E4 | `test_checks_engine.py` 7 | 7 |
| E5a | `test_workspace_variants.py` 12 | 12 |
| E5b | `test_tui_variants.py` 8 | 8 |
| E6 | `test_variant_execution.py` 11 | 11 |
| E7 | `test_report_service.py` 14 (13 lean + 1 slow; slow deselected count 19→20 ✓) | 14 |
| E8 | `test_tui_report_view.py` 8 | 8 |
| **ΣN_i** | 13 files | **149** |

Every N_i equals the packet-ledger value at its gate (no post-gate drift in the new files).

### 4.3 E3b enactment arithmetic (measured per-file, §6.6 pre-count vs HEAD collection)

| Surviving file | §6.6 pre | HEAD | Δ | Attribution |
|---|---|---|---|---|
| `test_memory_changelist.py` | 20 | 20 | 0 | 18 SURVIVES + 2 D1-REWRITE in place |
| `test_memory_validate.py` | 19 | 18 | −1 | 4 D2-REWRITE in place; of the 6 ratified SURVIVES→REWRITE re-dispositions, **1 folded** (the 23rd fold — resolves the packet's "23 folds" vs "22 folded with named targets") |
| `test_memory_display.py` | 12 | 12 | 0 | 12 SURVIVES (re-pointed to `changes/display.py`) |
| `test_unified_read.py` | 15 | 11 | −4 | 4 REWRITE folded; 8 in place + 3 SURVIVES |
| `test_unified_write.py` | 19 | 16 | −3 | 3 RETIRE; all 7 REWRITE in place + 9 SURVIVES |
| `test_unified_rules.py` | 10 | 5 | −5 | 5 REWRITE folded; 2 in place + 3 SURVIVES |
| `test_unified_roundtrip.py` | 9 | 5 | −4 | 4 RETIRE; 5 REWRITE in place |
| `test_tui_memory_patch.py` | 17 | 6 | −11 | 4 RETIRE + 1 D3-resolved + 6 REWRITE folded; 2 in place + 4 SURVIVES |
| directionb strays | 10 | 7 | −3 | 3 RETIRE; 3 REWRITE in place + 4 SURVIVES |
| snapshot patch cell | 1 | 1 | 0 | REWRITE in place (xfail pending CI regen) |
| `test_engine_unchanged.py` (NEW) | 0 | 1 | +1 | TC-027 relocation (count-neutral net: −1 with its deleted host file, +1 here) |
| 15 whole-file deletions | 223 | 0 | −223 | 215 RETIRE + 7 REWRITE folded + 1 TC-027 (relocated) |

Cross-foots: RETIRE 215+14 = **229** ✓ · folds 7+15+1 = **23** ✓ · D3 = **1** ✓ · relocation net **0** ✓ · E3b net Δ = −223 −31 +1 = **−253** = 915 → 662 ✓ exact.
**R (REWRITE returning in place) = 8+7+2+5+2+3+1 in surviving files + 0 in deleted = 28 = 50 − 22 folded** ✓ matches the E3b ledger exactly.

### 4.4 The full equation (zero unexplained terms)

```
  826   pre-batch collection (775 lean passed + 29 skipped + 3 xfailed + 19 slow)
+ 149   ΣN_i (per-increment ledger, §4.2)
− 229   RETIRE (all enacted at E3b)
−   1   D3-resolved (export-button geometry row, retired by E3a measurement)
−  23   folds (22 REWRITE-with-named-targets + 1 re-dispositioned row)
−   1   TC-027 leaves with its deleted host file (test_cdfx_unchanged.py)
+   1   TC-027 returns relocated (test_engine_unchanged.py)
= 722   == measured `pytest --collect-only -q`  ✓ EXACT
```

Checkpoint identities: 826+89 = 915 ✓ (E3b pre-delete) · 915−253 = 662 ✓ (E3b post) · 662+60 = 722 ✓ (E4..E8). R is count-neutral by definition (in-place rewrites) and reconciles as 50 = 28 + 22 ✓. **The reconciliation balances exactly; no `~` terms remain.**

---

## 5. Deviation register (consolidated) with Phase-6 actions

| ID | Increment | Deviation | Status | Phase-6 doc-reconciliation action |
|---|---|---|---|---|
| DEV-1 | E3a | LLR-002.7 HEX wording: "the prompt shall state HEX save-back not supported" implemented as a **status-line message** instead of a dead prompt (no prompt shown for HEX images) | Accepted at the E3a gate | Amend LLR-002.7 wording in `01-requirements.md` (and the REQUIREMENTS.md R-row this feeds) to "status-line statement"; behavior already test-pinned |
| DEV-2 | E3b | 6 §6.6 rows re-dispositioned SURVIVES → intent-preserving REWRITE (`test_memory_validate.py:113/:128/:140/:166/:178/:217` — `MEMV-OUTSIDE`/`MEMV-PARTIAL` WARNINGs eliminated by design: containment became apply *dispositions* per LLR-001.6/002.2); 1 of the 6 folded (§4.3) | Ratified at the E3b gate per the STOP rule | Annotate the §6.6 table archive note with the re-disposition + the 23-fold composition (this §4.3 is the source) |
| DEV-3 | E3b | One production edit beyond the deletion budget: `changes/io.py` containment-failure message names the exception type — required by the surviving S57-02 test (loosening the assertion forbidden by CLAUDE.md rule 9) | Ratified at the E3b gate | None (process record only; already in the packet) |
| DEV-4 | E3b | `test_unified_changeset.py`/`test_unified_export.py` carried 6 REWRITE rows but were enacted as whole-file deletes with **folds to named targets** (e.g. save-back containment → `test_changes_apply.py` adversarial params + `test_tui_patch_editor_v2.py::test_save_back_prompt`) | Ratified at the E3b gate | Same §6.6 archive annotation as DEV-2 |
| DEV-5 | E5a | 3 legacy cardinality-lock tests flipped (test-only): `test_tui_helpers.py` rejects-multiple-data → accepts; `test_tui_directionb.py::tc034` two-S19 block; `test_tui_workspace.py::tc048` case-collision — newer requirement (LLR-005.1) supersedes batch-06-era locks | Ratified at the E5a gate | Note the supersession in REQUIREMENTS.md rows that cited those tests |
| DEV-6 | E6 | File-cap 7 vs ≤6 — the 2 extra were contract-mandated test-pin updates (8→9 action set per F-A-15; duplicate-stem ids) | Surfaced and accepted at the E6 gate | None (process record) |
| DEV-7 | E7 | Window upper clamp: increment contract's image-top clamp vs LLR-007.2's unclamped wording — implemented the **clamped** form (reconciles both; gap convention covers partial rows) | Surfaced and accepted at the E7 gate | Align LLR-007.2 wording in `01-requirements.md` to the clamped formula |
| DEV-8 | Phase 4 (new) | HLR-008 verification names node id `test_generate_report_headless_no_app`; implemented as `tests/test_report_service.py::test_generation_is_headless_no_app` (intent identical — LLR-008.4/F-Q-07 monkeypatched `App.__init__`). Spec-literal invocation → `ERROR: not found`; corrected run passes | Found and resolved this phase | Fix the node id in HLR-008's verification line in `01-requirements.md` |

Open process items (not deviations): CI-1 workflow edit pending the batch PR (§3-5); CI-env regen of `patch-comfortable-120x30` then drop the xfail; manifest is read-only this batch (writer = E8-candidate-deferred → batch-08); Intel HEX emitter = batch-08 candidate (D-1).

---

## 6. Caveats

1. **Local Python is 3.14.4**, not the CI-pinned 3.11. All Phase-4 evidence in this document was produced on 3.14.4; the packets' per-gate numbers were produced in the same local env. Full 3.11 confirmation happens on the batch PR's CI run — which is also where CI-1's two jobs must first turn green.
2. **CI-1 not yet enacted in-tree** (see §3-5) — the single open §5.3 criterion. Without the workflow edit on the PR, criterion 5 fails at merge time.
3. **Slow suite** is orchestrator-owned and pending at the marker in §2 row 11; the only batch-07-added slow test is the E7 007.6 measurement (it passed at the E7 gate: both `REPORT_MAX_*` constants held with measured 106,848 B / 0.011 s default-context render).
4. **Snapshot cell** `patch-comfortable-120x30` is `xfail(strict=False)` pending regen in the canonical CI env (project memory: never regenerate locally). Counted inside the 3 xfailed of every lean line.
5. Demo criteria (LLR-006.6, HLR-008) were operator-observed at their increment gates; Phase 4 verified their pilot-test proxies only.
6. Local `main` ref is stale relative to the batch branch's base (two pre-batch CI commits sit in `main..HEAD`); the rail/SVG/workflow diff inspections account for this — none of the extra diff touches batch-07 surfaces.
