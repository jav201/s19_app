# Increment 2 — US-033 (issue ⇒ red-row) — LLR-037.1/.2/.3 + I1 F1 fold

> Batch `2026-07-02-batch-24` · branch `claude/batch-24-feat12` · base `origin/main 9d2123c` · agent: software-dev · 2026-07-02 · STRICT dependency on I1 (LLR-037.4 makes AT-037a's map source real) — honoured, I1 present in the working tree.

---

## 1. What changed

- **LLR-037.1** — NEW module-level `_a2l_issue_severity_map(issues)` in `s19_app/tui/app.py`, beside `_a2l_tag_row_severity`: derives a casefolded-symbol → max-severity dict from a `ValidationIssue` list, filtered to `artifact == "a2l"` + non-empty `symbol` (symbol-less codes like `A2L_STRUCTURE_ERROR` never map). Ordering via NEW `_A2L_ISSUE_SEVERITY_RANK` (ERROR=4 above all; order-independent max). Pure function, no widget access, O(issues) build; full PROJECT_RULES docstring.
- **LLR-037.2** — `_a2l_tag_row_severity(tag, issue_severity_map)`: gains the map as a REQUIRED second parameter (`Mapping[str, ValidationSeverity]`; a future call site that forgets the map fails loudly rather than silently rendering stale). Returns ERROR when the tag's casefolded name maps to ERROR; in every other case (no entry, WARNING entry — D-2) the existing schema/memory ladder is byte-identical. The single production caller `update_a2l_tags_view` (verified on disk, now app.py:7724 area) BUILDS the map once per render from `self._validation_issues` and passes it per row (A-m4 ownership clause). Map check placed before the `schema_ok` check — both arms return ERROR, so the LLR's "otherwise unchanged" contract is unaffected.
- **LLR-037.3** — `update_a2l_view` A2L-present branch reordered: `update_mac_view()` moved from LAST to immediately AFTER `_compute_a2l_enriched_tags()` and BEFORE `_refresh_a2l_filtered_tags` (line positions verified on disk pre-edit: compute at :7650, refresh at :7653, mac at :7655 in the I1-shifted tree — same shape the spec cited at :7413/:7416/:7418). After-enrichment pin honoured (A-m1: `_build_mac_view_cache` consumes `self._a2l_enriched_tags`); idempotence rides `_mac_view_cache_key` so the reorder adds no recomputation (TC-037.4 from I1 still green). `update_a2l_view` docstring upgraded from a one-liner to full section order (changed function, PROJECT_RULES).
- **I1 code-review F1 fold** — `validation_service.py`: dead `or []` dropped (`for tag in tags_for_validation:`). ⚠️ The gate addendum cited `:153`; the only dead `or []` on disk is at **:80** inside `supplemental_a2l_row_issues` (`:153` is a docstring line; `:159 or set()` / `:185 or []` guard genuine `Optional`s). Fixed the `:80` one — flagging the citation mismatch for the gate.
- **REQUIREMENTS.md §30** — NEW `R-A2L-ISSUE-RECONCILE-002` (US-033, status `Automated`, full node list); §30 blockquote widened to "both directions"; 001's "direction 2 lands in increment 2" status line resolved. Closes feature #12(c).
- **Tests** — NEW `tests/test_tui_a2l_issue_recolor.py` (5 tests): AT-037a (GATE) + AT-037b (Layer B, shipped load chain under Pilot, MAC-less fixtures, semantic ERROR-style anchor) + TC-037.1/.2/.3 (Layer A; new-symbol imports lazy so the module collected on the pre-fix tree). Existing ladder unit set `tests/test_tui_app.py::test_a2l_tag_row_severity_matches_updated_policy` updated IN PLACE — 5 calls gain `{}` (net-0 test rewrites: same test, same 5 assertions, ladder semantics unchanged).

## 2. Files modified

| File | Change | LOC (I2-only) |
|---|---|---|
| `s19_app/tui/app.py` | `_A2L_ISSUE_SEVERITY_RANK` + `_a2l_issue_severity_map` + `_a2l_tag_row_severity` signature/docstring + `update_a2l_tags_view` map build + `update_a2l_view` reorder/docstring | ≈ +165/−12 |
| `s19_app/tui/services/validation_service.py` | F1 fold: drop dead `or []` (:80) | 1 line |
| `tests/test_tui_a2l_issue_recolor.py` | NEW — 2 AT + 3 TC | +393 (new file) |
| `tests/test_tui_app.py` | unit set :49-56 updated in place (`{}` second arg + pointer comment) | +7/−5 |
| `REQUIREMENTS.md` | §30 blockquote + R-A2L-ISSUE-RECONCILE-002 + 001 status line | +17/−2 |

5 files — at the ≤5 hard cap (as the increment scope predicted once the F1 fold was included). Engine-frozen set untouched (guards green, §4c). Note: `git diff --stat` on the working tree shows I1+I2 combined (I1 landed uncommitted); the LOC column above is I2's own edits.

## 3. How to test

```bash
python -m pytest tests/test_tui_a2l_issue_recolor.py -v
python -m pytest "tests/test_tui_app.py::test_a2l_tag_row_severity_matches_updated_policy" -v
python -m pytest tests/test_tui_app.py tests/test_validation_service_supplemental.py tests/test_tui_issues_view.py tests/test_tui_directionb.py tests/test_engine_unchanged.py tests/test_tui_snapshot.py tests/test_tui_a2l_issue_recolor.py -q
python -m ruff check s19_app/tui/app.py s19_app/tui/services/validation_service.py tests/test_tui_a2l_issue_recolor.py
```

Manual (optional): `s19tui`, load an S19 + an A2L defining the same symbol twice → both rows red in the A2L table; rail screen 5 still shows exactly one `A2L_DUPLICATE_SYMBOL` ERROR.

## 4. Test results (real output)

### 4a. AT-037a RED capture — pre-implementation, verbatim (the counterfactual IS the reported divergence)

Run: `python -m pytest tests/test_tui_a2l_issue_recolor.py -k at_037a -v` on the pre-I2 tree (I1 present, zero I2 product edits; new-symbol imports lazy so collection succeeded). The fixture's both-rows-retained precondition PASSED (`len(dup_rows) == 2`); observable 1 failed — duplicate rows non-red while the `A2L_DUPLICATE_SYMBOL` ERROR existed:

```
        # Observable 1 - BOTH duplicate rows ERROR-styled (case-folded match,
        # mirroring the engine's name.lower() duplicate grouping).
        for cells in dup_rows:
>           assert all(cell.style == error_style for cell in cells), (
                "duplicate-symbol row is not ERROR-styled "
                "(ERROR issue does not recolour its rows - the HLR-037 divergence)"
            )
E           AssertionError: duplicate-symbol row is not ERROR-styled (ERROR issue does not recolour its rows - the HLR-037 divergence)
E           assert False
E            +  where False = all(<generator object ...>)

tests\test_tui_a2l_issue_recolor.py:187: AssertionError
=========================== short test summary info ===========================
FAILED tests/test_tui_a2l_issue_recolor.py::test_at_037a_duplicate_symbol_error_issue_reds_both_rows
======================= 1 failed, 4 deselected in 1.37s =======================
```

### 4b. Post-implementation — new + updated nodes all green

```
tests/test_tui_a2l_issue_recolor.py::test_at_037a_duplicate_symbol_error_issue_reds_both_rows PASSED [ 16%]
tests/test_tui_a2l_issue_recolor.py::test_at_037b_absent_from_table_issue_symbol_is_inert PASSED [ 33%]
tests/test_tui_a2l_issue_recolor.py::test_tc_037_1_issue_severity_map_build_and_filter_semantics PASSED [ 50%]
tests/test_tui_a2l_issue_recolor.py::test_tc_037_2_row_severity_precedence_matrix_and_warning_guard PASSED [ 66%]
tests/test_tui_a2l_issue_recolor.py::test_tc_037_3_sync_fallback_first_render_is_fresh PASSED [ 83%]
tests/test_tui_app.py::test_a2l_tag_row_severity_matches_updated_policy PASSED [100%]

============================== 6 passed in 3.19s ==============================
```

AT-037a red→green flip: I2 gate condition met, including first-render freshness (TC-037.3) on the sync path.

### 4c. Targeted regression (instructed set + the new file)

```
python -m pytest tests/test_tui_app.py tests/test_validation_service_supplemental.py tests/test_tui_issues_view.py tests/test_tui_directionb.py tests/test_engine_unchanged.py tests/test_tui_snapshot.py tests/test_tui_a2l_issue_recolor.py -q
.........................................................x.............. [ 33%]
........................................................................ [ 66%]
....................................ssssssssssssssssssssssssssss........ [100%]
187 passed, 28 skipped, 1 xfailed in 126.52s (0:02:06)
```

- **0 failures.** Engine-frozen guards (`test_engine_unchanged.py` + TC-031 in `test_tui_directionb.py`) green — 0 frozen-path diffs.
- I1's 11 tests (incl. TC-037.4 cache idempotence, which the reorder interacts with) all still pass.
- 28 skips = SVG snapshot skip-local policy; 1 xfail = the known TC-065.a carry. Both pre-existing.
- Full suite NOT run (orchestrator runs it at the gate, per increment instructions).

### 4d. Lint

```
python -m ruff check s19_app/tui/app.py s19_app/tui/services/validation_service.py tests/test_tui_a2l_issue_recolor.py
All checks passed!
```

⚠️ `tests/test_tui_app.py` carries a PRE-EXISTING `F401` (`from s19_app.tui import app as app_module` unused, :1599 at HEAD — verified via `git show HEAD:... | ruff check --stdin-filename`, fails identically on the untouched file). Outside my hunk; left untouched per the surgical rule. Candidate one-liner for I5 close or the standing ruff-cleanup line.

## 5. LLR → node coverage table

| LLR | Implementation node | Test node(s) | Result |
|---|---|---|---|
| LLR-037.1 | `app.py::_a2l_issue_severity_map` + `_A2L_ISSUE_SEVERITY_RANK` | TC-037.1 (filter/casefold/max/order-independence/empty), AT-037a | PASS |
| LLR-037.2 | `app.py::_a2l_tag_row_severity` (map param, ERROR-only precedence) + `update_a2l_tags_view` once-per-render build | TC-037.2 (matrix: empty-map ladder ×5, ERROR×5 incl. green→red, WARNING-GUARD ×5, unmapped ×5, nameless), AT-037a (both rows + control), updated ladder unit set | PASS |
| LLR-037.3 | `app.py::update_a2l_view` reorder (post-enrichment, pre-row-render) | TC-037.3 (sync-fallback first-frame red), I1 TC-037.4 ×3 (idempotence unbroken, §4c) | PASS |
| HLR-037 (gate) | render-side composition | AT-037a (RED §4a → GREEN §4b), AT-037b (absent-symbol boundary, natural `A2L_BROKEN_REFERENCE`) | PASS |

WARNING-no-recolour lives in TC-037.2 as the Layer-A GUARD over constructed issues (A-M1 split) — not an AT, per the amended HLR-037.

## 6. Ledger delta

| | collected (non-slow) |
|---|---|
| After I1 | 1015 |
| After I2 | **1020** (`1020/1041 tests collected (21 deselected)`) |
| Delta | +5 (new file: 2 AT + 3 TC) |

Net-0 rewrites: 1 — `test_a2l_tag_row_severity_matches_updated_policy` updated in place (5 calls gain `{}`; same test id, same ladder assertions).

## 7. Risks

- **Per-render map rebuild:** `_a2l_issue_severity_map` runs on every `update_a2l_tags_view` call (paging/filter included), O(issues) each. Bounded: the paged table renders ≤ page_size rows and issue lists are already paged elsewhere; no caching added (simplicity first — a stale-cache bug would be worse than the linear pass).
- **Casefold vs lower():** the engine groups duplicates by `name.lower()`; the map uses `casefold()` (matching I1's dedup key). For ASCII A2L symbols these agree; a divergence would need non-ASCII symbols with asymmetric folding — accepted, consistent with I1.
- **Required-parameter signature:** any out-of-tree caller of `_a2l_tag_row_severity` breaks loudly. Census executed (§2 + R-2): production caller = 1 (`update_a2l_tags_view`), tests = the two files updated here. Private underscore helper — no public contract.

## 8. Pending items

- **I3 (next):** US-034 service half + provenance stamp (LLR-038.1 + B-2 stamp) per §6.6 — independent of I1/I2.
- Full-suite + guards run at the orchestrator gate.
- V-5 id reconcile + §30/§29 rollup at I5 close.
- Pre-existing `tests/test_tui_app.py` F401 (§4d) — flagged, untouched.

## 9. Suggested next task

Increment 3 (US-034 service half) per §6.6: `tui/services/diff_report_service.py`, `tests/test_diff_report_service.py`, `tui/changes/model.py`, `tui/services/change_service.py`, `tests/test_change_service.py`.

## 10. Deviations from spec (§6.5-style notes — no requirement-changing deviations)

- **D-note-1 (F1 citation mismatch):** the dead `or []` sat at `validation_service.py:80`, not the `:153` the gate addendum cited (that line is docstring text; the other `or`-defaults guard genuine `Optional`s). Fixed the one real occurrence — one token, as instructed.
- **D-note-2 (test placement, explicitly delegated call):** new sibling file `tests/test_tui_a2l_issue_recolor.py` instead of growing `tests/test_tui_app.py` (2032 lines, and its module-level import of `_a2l_tag_row_severity` would have broken pre-fix collection for the RED run). `tests/` is not a package, so the small drive/read-back helpers are duplicated from I1's file (attributed in the module docstring) rather than cross-imported. §3/§4 "Executed verification" selectors were provisional per V-5; actual node ids recorded in REQUIREMENTS §30/002.
- **D-note-3 (within-latitude):** map consult placed BEFORE the `schema_ok` check in `_a2l_tag_row_severity` — both return ERROR, so the LLR-037.2 "otherwise existing ladder unchanged" contract is order-invariant here (TC-037.2's schema-bad × ERROR row pins no-flicker).

## Evidence checklist

- [✓] Tests/type checks/lint pass — §4b/§4c/§4d pasted output; full suite deferred to the gate by instruction; pre-existing F401 in an adjacent file surfaced, not hidden (§4d).
- [✓] No secrets in code or output — synthetic RPM/rpm/TORQUE/GHOST_TAG fixtures only (`tests/test_tui_a2l_issue_recolor.py`).
- [✓] No destructive commands run — file edits + pytest/ruff/git-status/git-show only.
- [✓] File count within cap — 5 files (§2), cap 5.
- [✓] Review packet attached — this document.

---

## Orchestrator gate addendum (2026-07-02)

- **Independent code review: OK-TO-ADVANCE** — 0 HIGH/MEDIUM, 2 LOW informational (AT-037b double-inertness = spec-accepted limitation, seen+recorded; per-render map rebuild accepted). All LLR traces held on disk incl. the reorder final order (:7652→:7656→:7659) and the D-note-3 neutrality proof. Census independently confirmed (no missed caller; net-0 rewrite verified).
- **Full non-slow suite (orchestrator-run): see tail below — 0 FAILED.** Ledger: 1015 − 0 + 5 = **1020** ✓.
- **Frozen set: 0-diff** (git status touches only the 5 planned files + state.json).
