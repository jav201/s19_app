# Increment 1 — US-032 (red-row ⇒ ERROR issue) + LLR-037.4 no-MAC retention (B-1a)

> Batch `2026-07-02-batch-24` · branch `claude/batch-24-feat12` · base `origin/main 9d2123c` · agent: software-dev · 2026-07-02

---

## 1. What changed

- **LLR-036.1** — NEW `supplemental_a2l_row_issues(tags_for_validation, collected_issues)` in `s19_app/tui/services/validation_service.py`: emits one `A2L_TAG_SCHEMA_INCOMPLETE` ERROR (`artifact="a2l"`, symbol/address/reason populated; message scrubbed by the `ValidationIssue` constructor — frozen module consumed, not edited) per tag whose `schema_ok` **is exactly `False`**. Absent-key / `None` tags gain nothing (A-M2 keying sentence honoured — raw/schema-complete fixtures stay issue-free).
- **LLR-036.2** — dedup inside the same function: covered-symbol set = casefolded `symbol` of collected issues with `artifact=="a2l"` × `severity==ERROR` × non-empty symbol. Symbol-less `A2L_STRUCTURE_ERROR` never suppresses; WARNING and non-a2l issues never suppress.
- **LLR-036.3** — `build_validation_report` merges the supplemental output **before** `dedupe_issues` in BOTH branches (MAC-only and primary-backed), only when the effective tag list is non-empty.
- **LLR-037.4 (B-1a fix)** — `update_mac_view`'s two no-MAC branches (former wipe sites app.py:7162-7163 / :7176-7177 behind guards :7160/:7174 — line positions verified on disk before editing, unchanged from the spec) now call NEW `_refresh_no_mac_validation()`: with NO primary file the historical clear is kept verbatim (all four validation members); with a primary present the validation report for the primary+A2L pair is computed/retained **through the cache mechanism**, never wiped.
- **Cache-substitute choice (documented in the `_mac_view_cache_key_for` docstring):** the key shape is unchanged except the first component — `id(records)` when records exist (previous behavior byte-for-byte), `id(loaded)` when records are empty. The `LoadedFile` identity is shared by the worker (`loaded`) and the renderer (`self.current_file`), so I additionally routed the worker key at `_prepare_load_payload` (former inline tuple, app.py:6524-6531) through the same NEW helper `_mac_view_cache_key_for` — this makes worker-precomputed no-MAC reports register as cache **HITS** in the fixed branch (the LLR's "RETAINS it (cache-hit no-op), never wipe-then-recompute" clause), which a renderer-only key change could not deliver (the worker's `id(fresh [])` never matches anything). TC-037.4 proves it: **0** `_build_mac_view_cache` calls on a worker-path re-render, exactly **1** on the sync-fallback path.
- **REQUIREMENTS.md** — NEW §30 `R-A2L-ISSUE-RECONCILE-001` (US-032 + LLR-037.4, status `Automated`, §28/§29 format) + TOC line 26.
- **Tests** — NEW `tests/test_validation_service_supplemental.py` (11 tests): AT-036a (GATE) / AT-036b / AT-036c×2 (Layer B, shipped load chain under Pilot, sync `asyncio.run` wrappers, MAC-less fixtures per the HLR-036 discipline, semantic ERROR-style anchor — no raw `"red"` literal) + TC-036.1-.4 + TC-037.4×3 (Layer A).

## 2. Files modified

| File | Change | LOC (± per `git diff --stat`) |
|---|---|---|
| `s19_app/tui/services/validation_service.py` | NEW `supplemental_a2l_row_issues` + both-branch merge + docstring updates | +106/−2 |
| `s19_app/tui/app.py` | NEW `_mac_view_cache_key_for` + `_refresh_no_mac_validation`; both no-MAC branches rewired; worker key routed through the helper; `update_mac_view` docstring | +136/−26 (net) |
| `tests/test_validation_service_supplemental.py` | NEW — 11 tests (4 AT + 7 TC) | +532 (new file) |
| `REQUIREMENTS.md` | §30 + TOC entry | +12 |

4 files — within the ≤5 hard cap. Engine-frozen set untouched (`tests/test_engine_unchanged.py` + TC-031 green, §5 below).

## 3. How to test

```bash
pytest tests/test_validation_service_supplemental.py -v
pytest tests/test_tui_services.py tests/test_validation_a2l.py tests/test_tui_app.py tests/test_tui_issues_view.py tests/test_engine_unchanged.py tests/test_tui_snapshot.py -q
python -m ruff check s19_app/tui/services/validation_service.py s19_app/tui/app.py tests/test_validation_service_supplemental.py
```

Manual (optional): `s19tui`, load an S19 + an A2L containing a non-virtual characteristic with no `ECU_ADDRESS` → the tag row is red AND rail screen 5 (Issues) shows an `A2L_TAG_SCHEMA_INCOMPLETE` ERROR naming the symbol.

## 4. Test results (real output)

### 4a. AT-036a RED capture — pre-implementation, verbatim (the counterfactual IS the reported bug)

Run: `python -m pytest tests/test_validation_service_supplemental.py -k at_036a -v` on the pre-fix tree (before any product edit; the new-symbol import is lazy so collection succeeded). Observable 1 (red rows) PASSED — execution reached observable 2, which failed with an **empty rendered Issues table** (both B-1a causes visible: no supplemental rule + the no-MAC wipe):

```
        app.action_show_screen("issues")
        await pilot.pause()
        issue_rows = _issue_rows(app)
        supplemental = [row for row in issue_rows if row[_CODE] == SUPPLEMENTAL_CODE]
        broken = [row for row in supplemental if row[_SYMBOL] == "BROKEN_CHAR"]
        nolen = [row for row in supplemental if row[_SYMBOL] == "NOLEN_CHAR"]
>       assert broken, (
            f"Issues surface has no {SUPPLEMENTAL_CODE} row naming BROKEN_CHAR "
            f"(red row without an issue - the HLR-036 divergence). "
            f"Rendered issue rows: {issue_rows!r}"
        )
E       AssertionError: Issues surface has no A2L_TAG_SCHEMA_INCOMPLETE row naming BROKEN_CHAR (red row without an issue - the HLR-036 divergence). Rendered issue rows: []
E       assert []

tests\test_validation_service_supplemental.py:221: AssertionError
=========================== short test summary info ===========================
FAILED tests/test_validation_service_supplemental.py::test_at_036a_missing_schema_red_row_has_matching_error_issue
====================== 1 failed, 10 deselected in 1.47s =======================
```

### 4b. Post-implementation — new file all green

```
tests/test_validation_service_supplemental.py::test_at_036a_missing_schema_red_row_has_matching_error_issue PASSED [  9%]
tests/test_validation_service_supplemental.py::test_at_036b_already_covered_symbol_gains_no_second_error PASSED [ 18%]
tests/test_validation_service_supplemental.py::test_at_036c_clean_a2l_yields_zero_supplemental_issues PASSED [ 27%]
tests/test_validation_service_supplemental.py::test_at_036c_empty_tag_set_yields_zero_supplemental_issues PASSED [ 36%]
tests/test_validation_service_supplemental.py::test_tc_036_1_one_error_per_schema_bad_tag_keyed_on_is_false PASSED [ 45%]
tests/test_validation_service_supplemental.py::test_tc_036_2_dedup_casefolded_symbol_a2l_error_only PASSED [ 54%]
tests/test_validation_service_supplemental.py::test_tc_036_3_merge_in_both_report_branches PASSED [ 63%]
tests/test_validation_service_supplemental.py::test_tc_036_4_nameless_schema_bad_tag_falls_back_to_context PASSED [ 72%]
tests/test_validation_service_supplemental.py::test_tc_037_4_worker_path_retains_report_without_mac PASSED [ 81%]
tests/test_validation_service_supplemental.py::test_tc_037_4_sync_path_computes_once_and_caches PASSED [ 90%]
tests/test_validation_service_supplemental.py::test_tc_037_4_no_primary_session_keeps_the_clear PASSED [100%]
============================= 11 passed in 6.75s ==============================
```

AT-036a red→green flip on BOTH observables: I1 gate condition met.

### 4c. Targeted regression (census-named at-risk set, §6.3 R-1)

```
python -m pytest tests/test_tui_services.py tests/test_validation_a2l.py tests/test_tui_app.py tests/test_tui_issues_view.py tests/test_engine_unchanged.py tests/test_tui_snapshot.py -q
................................................................x.......
....ssssssssssssssssssssssssssss...
78 passed, 28 skipped, 1 xfailed in 42.64s
```

- **0 failures.** Engine-frozen guard green (0 frozen-path diffs).
- 28 skips = the SVG snapshot matrix's skip-local policy (canonical-CI-only baselines — expected, not new).
- 1 xfail = the known TC-065.a carry (`CROSS_S19_HEX_OVERLAP` engine gap, pre-existing).
- The 3 no-op `update_mac_view` monkeypatches (`tests/test_tui_app.py:121,158,230`, B-1a census) passed unchanged — net-0 rewrites, as the census predicted.
- Full suite NOT run here (orchestrator runs it at the gate, per increment instructions).

### 4d. Lint

```
python -m ruff check s19_app/tui/services/validation_service.py s19_app/tui/app.py tests/test_validation_service_supplemental.py
All checks passed!
```

## 5. LLR → node coverage table

| LLR | Implementation node | Test node(s) | Result |
|---|---|---|---|
| LLR-036.1 | `validation_service.py::supplemental_a2l_row_issues` (predicate `schema_ok is False`, fields, scrub) | TC-036.1, TC-036.4 (nameless boundary), AT-036a | PASS |
| LLR-036.2 | same function — covered-symbol set (casefold × a2l × ERROR) | TC-036.2, AT-036b | PASS |
| LLR-036.3 | `validation_service.py::build_validation_report` — both-branch pre-dedupe merge, non-empty-tags gate | TC-036.3, AT-036c×2 (negative/empty) | PASS |
| LLR-037.4 | `app.py::_refresh_no_mac_validation` + `_mac_view_cache_key_for` + both no-MAC branch rewires + `_prepare_load_payload` shared key | TC-037.4×3 (worker cache-hit no-op / sync compute-once / no-primary clear), AT-036a Issues observable (gating per HLR-036 Acceptance) | PASS |
| HLR-036 (gate) | seam composition | AT-036a (RED pre-fix captured §4a, GREEN post-fix) | PASS |

## 6. Ledger delta

| | collected (non-slow) |
|---|---|
| Base (I1 start) | 1004 |
| After I1 | **1015** (`1015/1036 tests collected (21 deselected)`) |
| Delta | +11 (= the new file's 4 AT + 7 TC) |

## 7. Risks

- **Cache-key collision window (theoretical):** the empty-records identity substitute `id(loaded)` shares the id-space with the non-empty `id(records)` component; a stale-hit would additionally require equal record length (0 vs >0 — impossible across the empty/non-empty boundary) plus equal a2l-identity/file-type/ranges/mem-map-len. Same risk profile as the pre-existing id-based key; no new class of staleness.
- **Issues-pane volume:** schema-broken A2Ls now produce one ERROR per bad tag. Bounded by tag count; paging already handles multi-thousand-issue reports. The executed R-1 sweep found no count-pinning tests over `schema_ok=False` dicts; gate-confirmed at the full-suite run (A-2: best-effort here, gate is the guarantee).
- **`_a2l_enriched_tags` staleness in the no-MAC compute:** `_build_mac_view_cache` consumes `self._a2l_enriched_tags`; the shipped chain orders enrichment (`update_a2l_view:7413`) before `update_mac_view` (:7418), so the sync-path compute sees fresh tags. The cache-key-omits-enrichment caveat is pre-existing and is the subject of LLR-037.3 (I2), not widened here.

## 8. Pending items

- **I2 (next, STRICT dependency on this increment):** US-033 / LLR-037.1-.3 — `_a2l_issue_severity_map`, `_a2l_tag_row_severity` map consult, `update_mac_view()` reorder in `update_a2l_view`; AT-037a/b + TC-037.1-.3. AT-037a's map source (`_validation_issues`) is now real thanks to LLR-037.4.
- Full-suite + guards run at the orchestrator gate (not run in-increment by instruction).
- V-5 id reconcile + §30 rollup extension happen at I5 close.

## 9. Suggested next task

Increment 2 (US-033, issue-implies-red-row) per §6.6 — `tui/app.py` + `tests/test_tui_app.py` (or sibling) + `REQUIREMENTS.md`.

## 10. Deviations from spec (§6.5-style note)

**No requirement-changing deviations.** One implementation-latitude note, flagged loudly for the gate:

- **D-note-1 (within the LLR's explicit Phase-3 latitude, but an extra edit SITE inside an in-scope file):** LLR-037.4 says "route through the existing `_mac_view_cache_key` mechanism … substitute a stable identity … exact key shape decided at Phase 3" and requires the worker path to be a cache-hit no-op. A renderer-only substitution cannot match the worker's key (the worker hashed `id()` of a per-call fresh `[]`), so the worker key construction in `_prepare_load_payload` (app.py, same file, already in the I1 file set) was routed through the same new helper. Non-empty-records keys are value-identical to before (same tuple components, same `id(records)` first element) — pure refactor there; only the empty-records case changes, which is exactly the LLR's target. Proven by TC-037.4 (worker re-render: 0 rebuilds) and the 0-failure regression set.

## Evidence checklist

- [✓] Tests/type checks/lint pass — §4b/§4c/§4d pasted output (full suite deferred to the gate by instruction).
- [✓] No secrets in code or output — synthetic RPM/TORQUE/BROKEN_CHAR fixtures only (file: `tests/test_validation_service_supplemental.py`).
- [✓] No destructive commands run — file edits + pytest/ruff/git-status only.
- [✓] File count within cap — 4 files (§2), cap 5.
- [✓] Review packet attached — this document.

---

## Orchestrator gate addendum (2026-07-02)

- **Independent code review: APPROVE** — 3 LOW (F1 dead `or []` → fold into I2; F2 set-then-build mirrors existing convention, note-only; F3 pre-existing TOC drift, out of scope). All 4 LLR traces HELD; D-note-1 audited sound (no false-cache-hit path: invalidate-on-apply bounds key validity + live-object ids can't recycle; worker routing necessary per the LLR's cache-hit clause; docstring honest).
- **Full non-slow suite (orchestrator-run): 982 passed / 30 skipped / 3 xfailed / 0 FAILED (439s).** Ledger: 1004 − 0 + 11 = **1015** ✓ reconciled (971→982 passed).
- **Frozen set: 0-diff** vs origin/main (verified directly). Diff = exactly the 4 planned files + state.json bookkeeping.
- **RED capture verified credible** by the reviewer: pre-impl trace reached observable 2 (`Rendered issue rows: []`) with observable 1 (red rows) passing — the reported bug captured live before the fix.
