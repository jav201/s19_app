# Review closure — qa-reviewer — Batch 2026-10-11-batch-92 (P2 → P1-amendment verification)

**Lens:** qa-reviewer (closure). **Mode:** verify the P1 contract amendments closed the five P2 findings; standing checks re-run. **Independence:** read-only on the contract; this file is the only write. Contract read in full (541 lines); every check below was executed against the worktree at `410cde5` on 2026-10-12.

## Verdict

**`iterate-to-refine`** — F-QA-2/3/4/5 are CLOSED. F-QA-1 is closed in the contract text but its evidence artifact carries a NEW gate-relevant defect (F-QA-6, MAJOR) plus a path-anchoring gap (F-QA-7, MINOR). Both fixes are one-liners; recommend re-review of only the evidence file, not the contract.

## Finding-by-finding verification

### F-QA-1 (HIGH, baseline pin) — contract CLOSED; evidence artifact defective (see F-QA-6)

- **Baseline file:** `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt` holds exactly **44 node-id lines** = 29 `test_tc016s_density_layout_snapshot[...]` cells (verified: 29 full parametrized ids, e.g. `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[a2l-comfortable-120x30]`) + 15 non-family ids. Header documents the 38/36/40 instability and names the per-run evidence (`baseline-run2-ids.txt` / `baseline-run3-ids.txt`). ✓ for structure.
- **Gate rule (§5.2, line 497):** flaky-tolerant, exactly as required — (1) every node OUTSIDE the union must pass (stable-pass→fail = functionality loss); (2) in-union flips recorded, not counted; (3) TC-651..TC-655 + repointed TCs pass; (4) AT-288 sole byte-identity oracle; "**never a count comparison**" stated verbatim.
- **8 amended sites confirmed**, all referencing the union rule: §1.3 glossary (:53), premise 3 (:152), HLR-001 Ledger (:169 — now names LED-…92.11), HLR-001 Executed verification (:173), HLR-001 Numeric pass threshold (:174), HLR-001 Acceptance block (:179), §5.2 (:497), §6.3 baseline-drift risk (:517).
- **Staleness sweep:** `grep -in "set-equality\|40 pre-existing\|exact set\|36 failed\|38 failed\|never a count"` → the only "set-equality" hits are the census TCs (correct — that is the F-QA-2 fix, a different rule); no site asserts exact failure-set equality as the gate rule; the only bare counts are recorded *measurements* in premise 3 (explicitly labelled "never a count comparison"). No "40 pre-existing" anywhere. ✓
- **Ledger:** LED-2026-10-11-batch-92.11 documents 38/36/40 across three executions with evidence paths; LED-…92.6 (the superseded strict 36-set) is preserved with its correction note. ✓
- **BUT:** 2 of the 44 ids are truncated (see F-QA-6) and the contract's evidence path is unanchored (see F-QA-7).

### F-QA-2 (MAJOR, census input-set oracle) — CLOSED

- **TC-651 / LLR-001.4 (:275):** "shall derive the importer set from the live tree at run time — an **AST walk** (`ast.parse` import-census over `s19_app/`, covering all aliased/plain import forms) — and assert **set-equality** against the declared measured set". ✓ Declared set = the 8 product sites, all verified live at exactly the cited lines: `tui/app.py:37`, `tui/__init__.py:17`, `tui/screens.py:34`, `tui/screens_directionb.py:3336,7581`, `tui/services/load_service.py:8`, `report_service.py:58`, `diff_report_service.py:96` (8/8). ✓
- **Test-import forms (:181):** 3 forms enumerated with the real 8 files — `from s19_app.tui.hexview import …` (`test_report_service.py:595` labelled as a source-census *string* assertion + 5 real importers), `import s19_app.tui.hexview as …` (`test_tui_hexview.py` locals), `from s19_app.tui import hexview …` (`test_tui_directionb.py:1172,1191`, `test_tui_search_pagination.py:19`). Live grep over `tests/*.py` for the three forms returns exactly the 7 real importers + the string assertion = 8 files. Consistent with code-lens C3 / LED-…92.7. ✓
- **TC-653 / LLR-003.3 (:335):** AST walk over `s19_app/` + set-equality vs declared set; declared consumers verified live — `checks_view.py:41`, `issues_view.py:40` (direct), `app.py:79` (`safe_text` inside the `from .screens_directionb import (…)` block — confirmed by `sed -n '70,82p'`). ✓
- **TC-654 / LLR-004.3 (:365):** AST walk + set-equality vs declared set; `validation_service.py:17` old edge verified live (`from ..insight_style import GREEN, LABEL, VALUE, microbar`). ✓

### F-QA-3 (MAJOR, snapshot observer) — CLOSED (one historical-text note, non-blocking)

- Every normative occurrence of the snapshot criterion is now the chartered rule: §1.3 glossary row defines "Snapshot byte-identity" as the §5.2 flaky-tolerant gate rule + AT-288 sole byte-identity oracle (:53); HLR-001 threshold/verification (:173-174, :179); §5.2 rule (4) (:497); LLR-004.3 "snapshot identity per HLR-001 gate" (:368). No un-chartered "every snapshot byte-identical" normative text remains; no chartered probe/manifest text survives (the un-chartered hash-manifest idea was dropped in favour of option 2, per LED-…92.8). ✓
- **Note (non-blocking):** the US-92-1 refinement-log Evaluability line (:106) still quotes the Phase-0 phrase "every test green and every TUI snapshot byte-identical to the pre-move capture". It is pre-amendment INVEST prose, and the term it uses is now defined in §1.3; normative text is clean. Left as-is; flag for awareness only.

### F-QA-4 (MINOR, AT-291 node ids) — CLOSED

AT-291 (:227) names `tests/test_tui_mac_coverage.py::test_at071_strip`, `::test_build_mac_coverage_strip_counts`, `::test_zero_total_no_divzero`. All three exist on disk at :271, :299, :290 respectively (ledger LED-…92.9 cited the same lines). ✓

### F-QA-5 (MINOR, AT-288 fixture/params) — CLOSED

AT-288 (:179) names the `large_s19` fixture — `tests/conftest.py:302` verified (`def large_s19(tmp_path: Path) -> Path:` at :302), built by `make_large_s19` at `tests/conftest.py:71` verified — and requires non-default parameters: non-default `focus_address`, match `highlight` range, non-empty `mac_highlight_addresses`, `row_bases` spanning ≥2 disjoint ranges, "a default-only image is not acceptable evidence". ✓

## Standing checks on the amended text

- **EARS:** `grep -in "should\|debería\|deberia" 01-requirements.md` → 0 hits (exit 1). ✓
- **Dual traceability, TC-655 (new id):** appears in the §5.2 TC plan (:495 "TC-651, TC-652, TC-653, TC-654 … and TC-655"), in three LLR verification lines (LLR-001.1 :247, LLR-001.2 :257, LLR-004.1 :347), and in `AT-TC-REGISTRY.jsonl:1426` — row exists, `"status": "RESERVED"`, statement matches the LED-…92.5 amendment. Ledger LED-…92.5 ↔ LLR-001.1 name each other (V26 pair intact). ✓
- **Registry re-check:** TC-651..654 still RESERVED at `AT-TC-REGISTRY.jsonl:1422-1425`; TC-655 at :1426. ✓
- **Numeric thresholds:** every "Numeric pass threshold" line carries a measurable count or a set-rule (1 passed; 0 failures; 8/8, 5/5, 7/7, 3/3, 10/10, 65/65, 2/2 assertions; the 44-id out/in-union rule). No threshold is qualitative. ✓

## New findings

| ID | Severity | Location | Finding | Required action |
|----|----------|----------|---------|-----------------|
| F-QA-6 | MAJOR | `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt:23,30` (also propagated into `baseline-run2-ids.txt` / `baseline-run3-ids.txt`) | **Two of the 44 pinned reference ids are truncated pytest `-rf` capture lines**, not node ids: `tests/test_tui_legend.py::test_at023c_issues_legend_button_opens - tex...` (:23) and `tests/test_tui_patch_layout.py::test_at063c_reparent_safety_at_80 - te...` (:30) (executed: `grep -n '\.\.\.'` → both lines). A gate tool doing exact-id membership lookup cannot match either id, so if these flaky nodes fail at the gate they resolve as OUTSIDE the union → spurious functionality-loss gate failure — precisely the mechanical-decidability defect F-QA-1 closed, re-introduced inside the evidence artifact. The truncation also exists in both per-run id logs, so the full ids are NOT recoverable from the evidence chain. | Rewrite the two lines as clean node ids, re-derived from the suite (e.g. `python -m pytest tests/ -q --co -k "test_at023c_issues_legend_button_opens or test_at063c_reparent_safety_at_80"`); fix the same two lines in `baseline-run2-ids.txt` / `baseline-run3-ids.txt`. Append a ledger entry. Contract text needs no edit. |
| F-QA-7 | MINOR | `01-requirements.md` refs at :53, :152, :173, :174, :179, :497, :517 | **Unanchored evidence path.** The contract names the reference as `evidence/baseline-failing-set.txt`; the artifact actually lives at `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt` and NO worktree-root `evidence/` dir exists (executed: root `ls evidence/` → ENOENT). Anchored references in the same document (`design/module-map-delta.md` is cited with its full `.dev-flow/2026-10-11-batch-92/` prefix) show the convention; the evidence refs omit it. A gate script resolving from the repo root will not find the pinned reference. | Either anchor all 7 refs to `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt`, or state once in §5.2 that batch-relative paths resolve against the batch directory. Ledger entry. |

## Gate recommendation

**`iterate-to-refine`** — scoped: F-QA-6 and F-QA-7 touch only the evidence artifact and path anchoring; the contract's amended text is otherwise clean (F-QA-2/3/4/5 closed, F-QA-1 closed modulo its artifact). Fix the two truncated ids (re-derivation command above), fix the same two lines in the per-run logs, anchor the path, append one ledger entry; no re-review of the requirement statements needed. If the orchestrator prefers to proceed, F-QA-6 is the only finding with gate-blocking potential at Phase 4.
