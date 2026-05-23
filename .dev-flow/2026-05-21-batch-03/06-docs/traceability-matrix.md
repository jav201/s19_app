# Traceability Matrix — s19_app — Batch 2026-05-21-batch-03

> Full chain: **User Story → HLR → LLR → Test Case → Increment → Validation verdict**.
> Every row is complete at batch close (Phase 6). Incomplete rows = coverage gaps and are listed in the gaps section.

This matrix is the consolidated traceability artefact for batch `2026-05-21-batch-03` — the **functional Patch Editor + ASAM CDFX (`.cdfx`) read/write** feature of the `s19tui` Textual TUI. Source artefacts:

- [`.dev-flow/2026-05-21-batch-03/01-requirements.md`](../01-requirements.md) §2.6 (US), §3 (HLR), §4 (LLR), §5.2/§5.3 (TC IDs + methods), §5.7 (TC catalogue)
- [`.dev-flow/2026-05-21-batch-03/02-review.md`](../02-review.md) §Phase-2 closure (28 findings closed, CV-01..CV-04, OQ-1..OQ-6 resolved)
- [`.dev-flow/2026-05-21-batch-03/03-increments/increment-001.md`](../03-increments/increment-001.md) … [`increment-011.md`](../03-increments/increment-011.md) + [`increment-plan.md`](../03-increments/increment-plan.md)
- [`.dev-flow/2026-05-21-batch-03/04-validation.md`](../04-validation.md) §5 (per-TC verdicts), §6 (per-requirement verdicts), §7 (§5.9 acceptance criteria), §8 (gaps)
- [`.dev-flow/2026-05-21-batch-03/05-postmortem.md`](../05-postmortem.md)
- [`.dev-flow/2026-05-21-batch-03/design-input/cdfx-research.md`](../design-input/cdfx-research.md) — the CDFX structure + the `W-*`/`R-*` rule set (§7)

Unlike batch-02 (a view-layer-only restyle on a frozen engine), this batch **deliberately adds a data-processing layer**: the `s19_app/tui/cdfx/` package (change-list model + CDFX read/write handler) and the `s19_app/tui/services/cdfx_service.py` service seam. The expansion was approved and expected ([`01-requirements.md`](../01-requirements.md) §1.1). The engine remains frozen — the Phase-4 `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` is empty (zero bytes changed); the CDFX feature is purely additive new files.

---

## 1. Master table

One row per US → HLR → LLR → TC tuple. `Increment` cites the Phase-3 increment that built the feature and shipped the asserting test (the 11-increment sequence — increments 1–4 shipped the model/resolution/display/writer, increments 5–11 the `Optional[int]` migration, writer-coalescing rework, reader, XML-safety, functional screen, round-trip hardening and integration tests; see [`increment-plan.md`](../03-increments/increment-plan.md)). `Verdict` is the Phase-4 per-TC verdict from [`04-validation.md`](../04-validation.md) §5: `pass` = an asserting test is green in the Phase-4 evidence run / the inspection checklist is fully satisfied. All 7 US, 8 HLR, 44 LLR and 47 TC are traced — see §3 for the no-gap confirmation.

| US | HLR | LLR | TC | Method | Increment | Verdict | Evidence (Phase 4) |
|----|-----|-----|-----|--------|-----------|---------|--------------------|
| US-001, US-007 | HLR-001 | LLR-001.1 | TC-001 | U | 1, 5 | pass | `test_cdfx_changelist.py` — entry reports its four fields; scalar/ASCII entries carry `array_index is None`, an array-element entry an integer; `(name,None)` ≠ `(name,0)` identities. Migrated to `Optional[int]` in increment 5. |
| US-001, US-007 | HLR-001 | LLR-001.2 | TC-002 | U | 1, 5 | pass | `test_cdfx_changelist.py` — add-then-remove empties the list; edit mutates only the targeted entry. |
| US-001, US-007 | HLR-001 | LLR-001.3 | TC-001, TC-002 | U | 1, 5 | pass | `test_cdfx_changelist.py` — `(parameter_name, array_index)` is the entry identity; adding `PARAM[0]` twice updates in place (one entry, latest value); `(name,None)` and `(name,0)` are distinct identities. |
| US-001, US-007 | HLR-001 | LLR-001.4 | TC-003 | U | 1 | pass | `test_cdfx_changelist.py` — two writes of the same change-list produce identical `SW-INSTANCE` order (deterministic ordering). |
| US-002 | HLR-002 | LLR-002.1 | TC-004 | U | 2 | pass | `test_cdfx_resolve.py` — a name in the synthetic A2L resolves with `datatype` / `element_count` / section; resolution runs the **enriched** A2L pipeline (C-1), no A2L re-parse. |
| US-002 | HLR-002 | LLR-002.2 | TC-005 | U | 2 | pass | `test_cdfx_resolve.py` — an unknown name yields an `unresolved` entry; no exception; list stays usable. |
| US-002 | HLR-002 | LLR-002.3 | TC-006 | U | 2, 5 | pass | `test_cdfx_resolve.py` — integer index 5 on a 3-element array → `index-out-of-range`; a scalar entry (`array_index is None`) against a scalar A2L parameter resolves, not range-checked. Range check made integer-only in increment 5. |
| US-002 | HLR-002 | LLR-002.4 | TC-007 | U | 2 | pass | `test_cdfx_resolve.py` — with no A2L every entry is `unresolved-no-a2l`; no exception. |
| US-003 | HLR-003 | LLR-003.1 | TC-008 | U | 3 | pass | `test_cdfx_display.py` — `UBYTE` 23 → `23`/`0x17`; negative `SWORD` signed; `FLOAT32_IEEE` / `FLOAT16_IEEE` fractional; large `A_UINT64` near `2**64-1` decimal + `0x`; `ASCII` quoted. |
| US-003 | HLR-003 | LLR-003.2 | TC-009 | U | 3 | pass | `test_cdfx_display.py` — an unresolved entry's value renders as plain decimal, no exception. |
| US-003 | HLR-003 | LLR-003.3 | TC-010 | U | 1, 3 | pass | `test_cdfx_display.py` + `test_cdfx_changelist.py` — stored value equals the entered physical value; hex/ASCII rendering does not mutate it. |
| US-004 | HLR-004 | LLR-004.1 | TC-011 | U | 4 | pass | `test_cdfx_writer.py` — root `MSRSW`, `CATEGORY=CDF20`, the `SW-SYSTEMS…SW-INSTANCE-TREE` chain each with a `SHORT-NAME`. |
| US-004 | HLR-004 | LLR-004.2 | TC-012 | U | 4, 6 | pass | `test_cdfx_writer.py` — scalar entry → `SW-INSTANCE` `CATEGORY=VALUE`, `SHORT-NAME` = parameter name; exactly one instance per distinct resolved name. Coalescing reworked in increment 6. |
| US-004 | HLR-004 | LLR-004.3 | TC-013 | U | 4, 6 | pass | `test_cdfx_writer.py` — scalar → one bare `V`; 3-element array → `VG` with three positional `V` in index order; string → one `VT`; no `SW-ARRAY-INDEX` emitted. |
| US-004 | HLR-004 | LLR-004.4 | TC-014 | U | 4 | pass | `test_cdfx_writer.py` — written file carries an XML declaration, re-parses via `ElementTree` without exception. |
| US-004 | HLR-004, HLR-006 | LLR-004.5 | TC-019d | U | 4 | pass | `test_cdfx_w_rules.py` / `test_cdfx_writer.py` — an unresolved entry → no `SW-INSTANCE` + one `W-INSTANCE-EXCLUDED` warning; valid sibling still written. |
| US-004 | HLR-004, HLR-006 | LLR-004.6 | TC-019h | U | 4, 6 | pass | `test_cdfx_w_rules.py` / `test_cdfx_writer.py` — literally-empty change-list → valid backbone-only `MSRSW` + one `W-EMPTY-CHANGELIST`; two-entry all-unresolved → backbone-only + two `W-INSTANCE-EXCLUDED` + one `W-EMPTY-CHANGELIST`. |
| US-004 | HLR-004 | LLR-004.7 | TC-014, TC-032 | U | 4 | pass | `test_cdfx_writer.py` — a written `.cdfx` carries a leading `Created with s19_app CDF 2.0 Writer` XML comment; document remains well-formed, re-parses via `ElementTree`. |
| US-004 | HLR-004 | LLR-004.8 | TC-033, TC-024 | U, RT | 4, 10 | pass | `test_cdfx_roundtrip.py` / `test_cdfx_writer.py` — each adversarial float (`0.1`, denormal `5e-324`, 17-digit) written then re-read compares **exactly equal**, no float tolerance. |
| US-004 | HLR-004 | LLR-004.9 | TC-038, TC-024 | U, RT | 6, 10 | pass | `test_cdfx_writer.py` / `test_cdfx_w_rules.py` — `PARAM[0..2]` → exactly one `VAL_BLK` `SW-INSTANCE` with one ascending-index three-`V` `VG`; a gap group / non-zero-based group each → no `SW-INSTANCE` + one `W-ARRAY-SPARSE`; no `V` synthesized for a missing index. |
| US-005, US-006 | HLR-005 | LLR-005.1 | TC-015, TC-024 | U, RT | 7, 10 | pass | `test_cdfx_reader.py` — `make_minimal_cdfx` parses to the expected entries; TC-024 round-trip is the corroborating verdict. |
| US-005, US-006 | HLR-005 | LLR-005.2 | TC-016, TC-027a, TC-027b | U | 7, 8 | pass | `test_cdfx_reader.py` / `test_cdfx_r_rules.py` / `test_cdfx_safety.py` — a truncated/garbage or `DOCTYPE`-bearing file → exactly one `R-XML-PARSE` error issue, empty change-list, no exception. |
| US-005, US-006 | HLR-005 | LLR-005.3 | TC-017 | U | 7 | pass | `test_cdfx_reader.py` — `ADMIN-DATA` / `SW-CS-HISTORY` / `SW-CS-FLAGS` siblings, a declared `xmlns`, a leading tool note — every `SW-INSTANCE` still read; a `SW-INSTANCE` outside the backbone is not absorbed. |
| US-005, US-006 | HLR-005 | LLR-005.4 | TC-018 | U | 7 | pass | `test_cdfx_reader.py` — `<V>0x17</V>`→23, `<V>1.5e1</V>`→15.0, decimal decode; `0b101` asserted only as a tolerant-superset case (OQ-7, non-normative). |
| US-005, US-006 | HLR-005 | LLR-005.5 | TC-037 | U | 8 | pass | `test_cdfx_reader.py` / `test_cdfx_safety.py` / `test_cdfx_path_containment.py` — a valid `.cdfx` path is resolved through `workspace.resolve_input_path`; an unresolvable path → exactly one `R-XML-PARSE` issue, no file opened (no-open spy). |
| US-005, US-006 | HLR-005 | LLR-005.6 | TC-039, TC-024 | U, RT | 7, 10 | pass | `test_cdfx_reader.py` — a `VAL_BLK` `SW-INSTANCE` with an N-`V` `VG` expands to N entries `(name,0)…(name,N-1)`; a `VALUE`/`BOOLEAN` instance → one scalar entry (`array_index is None`); an `ASCII` instance → one string entry (`array_index is None`). |
| US-006 | HLR-006 | LLR-006.1 | TC-019a..TC-019h, TC-038 | U, analysis | 4, 6 | pass | `test_cdfx_w_rules.py` — the eight `W-*` structural codes provoked via the standalone validator; `W-INSTANCE-EXCLUDED` (TC-019d) + `W-ARRAY-SPARSE` (TC-038) writer-behavior codes exercised through the real writer. |
| US-006 | HLR-006 | LLR-006.2 | TC-020, TC-021, TC-023 | U | 7 | pass | `test_cdfx_r_rules.py` — each of `R-ROOT-MSRSW`, `R-BACKBONE-MISSING`, `R-INSTANCE-NO-NAME`, `R-INSTANCE-NO-VALUE`, `R-CATEGORY-VALUE-MISMATCH`, `R-VALUE-NOT-NUMERIC` provoked; load does not abort; valid sibling recovered. |
| US-006 | HLR-006 | LLR-006.3 | TC-022 | U | 7 | pass | `test_cdfx_r_rules.py` — every CDFX finding is a `ValidationIssue` with `artifact == "cdfx"`; severity round-trips through `css_class_for_severity` to a valid `sev-*` class. |
| US-006 | HLR-006 | LLR-006.4 | TC-021 | U | 7 | pass | `test_cdfx_r_rules.py` — a `CDF21` `.cdfx` reads its instances + produces exactly one `R-VERSION-UNKNOWN` info issue. |
| US-006 | HLR-006 | LLR-006.5 | TC-023 | U | 7 | pass | `test_cdfx_r_rules.py` — a `MAP` `SW-INSTANCE` loads read-only with exactly one `R-CATEGORY-UNSUPPORTED` warning; no exception. |
| US-006 | HLR-006 | LLR-006.6 | TC-027a, TC-027b | U, analysis | 8 | pass | `test_cdfx_safety.py` — a billion-laughs (`DOCTYPE` + nested internal `<!ENTITY>`) and an external-entity (`SYSTEM`) `.cdfx` each → exactly one `R-XML-PARSE` issue, empty change-list, no entity expansion, no external file read. |
| US-006 | HLR-006 | LLR-006.7 | TC-017, TC-034 | U | 7 | pass | `test_cdfx_reader.py` — a `.cdfx` carrying a leading `Created with …` XML comment reads every `SW-INSTANCE`, emits zero comment-related issues. |
| US-006 | HLR-006 | LLR-006.8 | TC-035 | U | 8 | pass | `test_cdfx_safety.py` — with the size-probe stubbed over the 256 MB cap, exactly one `R-XML-PARSE` issue, `ElementTree.parse` never reached; a deeply-nested variant → one `R-XML-PARSE` issue, no unbounded recursion. |
| US-007 | HLR-007 | LLR-007.1 | TC-025 | I | 9 | pass | `test_tui_patch_editor.py` (under `App.run_test()`) — adding an entry adds a visible change-list row; the `R-TUI-027` deferral notice is absent. |
| US-007 | HLR-007 | LLR-007.2 | TC-025 | I | 9 | pass | `test_tui_patch_editor.py` — submitting name/index/value inputs mutates the change-list and re-renders the rows; edit/remove update rows. |
| US-007, US-004 | HLR-007 | LLR-007.3 | TC-026 | I | 9, 11 | pass | `test_tui_patch_editor.py` — a screen-driven `"save"` writes a `.cdfx` under `.s19tool/workarea/`; write issues surface on `app.log_lines`. |
| US-007, US-005 | HLR-007 | LLR-007.4 | TC-026, TC-027a | I | 9, 11 | pass | `test_tui_patch_editor.py` — loading a valid `.cdfx` populates visible rows; loading a malformed/malicious one surfaces issues, does not crash; a `VAL_BLK` `.cdfx` load expands to per-element rows. |
| US-007 | HLR-007 | LLR-007.5 | TC-028 | INSP | 9 | pass | [`04-validation.md`](../04-validation.md) §4 — all four §5.6 checklist items pass; `test_tc028_app_py_holds_no_cdfx_xml_logic` + `test_tc028_patch_action_handler_routes_through_the_service` green. |
| US-007 | HLR-007 | LLR-007.6 | TC-025 | I | 9 | pass | `test_tui_patch_editor.py` — an empty Patch Editor shows the neutral add-or-load prompt, not a blank pane or error. |
| US-007, US-004 | HLR-007 | LLR-007.7 | TC-036 | I | 8, 11 | pass | `test_tui_patch_containment.py` + `test_cdfx_path_containment.py` — a screen `"save"` resolves under `.s19tool/workarea/`; a repeated save dedup-suffixes; a symlinked work-area save is rejected with `W-WRITE-CONTAINMENT`. |
| US-002, US-005, US-006 | HLR-008 | LLR-008.1 | TC-029 | U | 7 | pass | `test_cdfx_r_rules.py` — with an A2L loaded, a `SW-INSTANCE` named for a non-existent A2L parameter yields exactly one `R-NAME-NOT-IN-A2L` warning. |
| US-002, US-005, US-006 | HLR-008 | LLR-008.2 | TC-030 | U | 7 | pass | `test_cdfx_r_rules.py` — a 4-element array `SW-INSTANCE` against a 3-element A2L parameter yields exactly one `R-ARRAY-LEN-MISMATCH` warning. |
| US-002, US-005, US-006 | HLR-008 | LLR-008.3 | TC-031 | U | 7 | pass | `test_cdfx_r_rules.py` — with no A2L, a `.cdfx` parses into entries and emits zero `R-NAME-NOT-IN-A2L` / `R-ARRAY-LEN-MISMATCH` issues. |

**Row count:** 44 traceability rows covering all 44 LLR and all 47 TC. LLRs covered by more than one TC (LLR-001.3, LLR-003.3, LLR-004.6 ↔ TC-019h, LLR-004.7/008/009, LLR-005.1/002/006, LLR-006.1, LLR-007.3/004/007) cite each covering TC on a single row; the eight `W-*` sub-cases TC-019a..TC-019h all roll up under LLR-006.1. Every distinct US, HLR, LLR and TC is present at least once — see §3.

---

## 2. Coverage summary

Counts folded from [`04-validation.md`](../04-validation.md) §0, §5, §6, §7.

| Metric | Value |
|--------|-------|
| Total user stories | 7 (US-001..US-007) |
| Covered user stories | 7 (100%) |
| Total HLR | 8 (HLR-001..HLR-008) |
| HLR with verdict `pass` | 8 (100%) |
| Total LLR | 44 |
| LLR with verdict `pass` | 44 (100%) |
| Total test cases | 47 (TC-001..TC-018, TC-019a..h, TC-020..TC-026, TC-027a/b, TC-028..TC-039) |
| TC pass | 47 (100%) |
| TC partial | 0 |
| TC fail (blocker) | 0 |
| TC fail (non-blocker) | 0 |
| §5.9 batch acceptance criteria (1..11) | 11 met / 0 not-met |
| Open blocker findings at the gate | 0 |
| pytest baseline at gate (full suite) | **611 passed / 0 failed / 3 xfailed / 2 skipped**; 27 snapshots passed |
| pytest baseline (CDFX + Patch subset, 12 files) | 192 passed / 0 failed |
| Engine `git diff main` | empty — zero bytes changed across `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` |
| Phase 4 verdict | `pass-with-gaps` (0 blockers; 4 documentary/environmental gaps) |

### 2.1 Coverage by validation method

| Method | TC count | Notes |
|--------|----------|-------|
| test (unit) — U | 41 | Change-list model, A2L resolution, display, writer, reader, `W-*`/`R-*` rule sets, cross-checks, XML-safety, path containment. Includes the eight TC-019a..h sub-cases and TC-027a/b. |
| test (integration) — I | 4 | TC-025, TC-026, TC-036 (and TC-027a's integration arm) — Patch Editor build/edit/save/load driven via `App.run_test()`. |
| test (round-trip) — RT | 1 | TC-024 — write→read structural equality including the `Optional[int]` key shape and the three adversarial floats. |
| inspection — INSP | 1 | TC-028 — the §5.6 module-placement checklist (CDFX logic outside `app.py`, no XML in `app.py`, no new dependency). |
| analysis | (corroborating) | TC-019a/b/c/g (writer-cannot-provoke), TC-027a/b (DOCTYPE-rejection argument) — a corroborating method only, counted once above under the primary method. |
| **Total** | **47** | No retired TC this batch. |

### 2.2 Suite trajectory across Phase 3 increments

| Increment | Title | Suite total | Δ |
|-----------|-------|-------------|---|
| baseline | (batch-02 close) | 419 | — |
| 1 | Change-list model | 435 | +16 |
| 2 | A2L parameter resolution | 449 | +14 |
| 3 | Type-driven value display | 466 | +17 |
| 4 | CDFX writer + `W-*` validator | 499 | +33 |
| 5 | `Optional[int]` model + resolver migration | 499 | +0 (re-verifies existing TCs) |
| 6 | Writer coalescing rework + `W-ARRAY-SPARSE` | (added TC-038) | + |
| 7 | CDFX reader + `R-*` validation + `VAL_BLK` expansion | — | + |
| 8 | XML-safety + load/write path containment | — | + |
| 9 | Functional Patch Editor screen | — | + |
| 10 | Round-trip + adversarial-float hardening | — | + |
| 11 | Integration save/load + containment UI tests | 611 | +10 (integration tests) |

The progression reconciles: increments 1–4 took the suite from the 419 batch-02 baseline to 499; increment 5 is a contract migration that re-verifies existing TCs at 499 with no count change; increments 6–11 add the writer rework, reader, safety layer, functional screen and integration tests, closing at **611 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots passed** ([`04-validation.md`](../04-validation.md) §1.1). The CDFX + Patch Editor subset (12 test files) is **192 passed / 0 failed** ([`04-validation.md`](../04-validation.md) §1.2). The 3 xfails and 2 skips are pre-existing batch-01/batch-02 baseline cases — not CDFX cases, unchanged through all 11 increments.

---

## 3. Detected gaps

> Incomplete rows, requirements without a TC, or open findings carrying into a follow-up batch.

**Traceability completeness: NO GAPS.** Every one of the 7 US, 8 HLR, 44 LLR and 47 TC is traced end-to-end in §1 and carries a Phase-4 `pass` verdict. The §5.7 reverse-traceability check reconciles: the LLR-by-HLR-group tally is 4 (001.x) + 4 (002.x) + 3 (003.x) + 9 (004.x) + 6 (005.x) + 8 (006.x) + 7 (007.x) + 3 (008.x) = **44**; the catalogue holds **47 test cases**. There is **no requirement without a validation method, no LLR without a passing TC, and no TC without a recorded verdict** — this satisfies §5.9 acceptance criteria #1 and #2 ([`04-validation.md`](../04-validation.md) §7).

The four items below are the `-with-gaps` qualifiers from the Phase-4 verdict ([`04-validation.md`](../04-validation.md) §8). **None is a correctness defect, none is a blocker, none gates the batch.** They are documentary / environmental / accepted-residual-risk items carried to Phase 5/6.

| ID | Type | Severity | Description | Disposition |
|----|------|----------|-------------|-------------|
| G-1 | Environmental — residual risk (RK-1) | medium | No client `.cdfx` sample is bundled (constraint C-9 forbids it anyway). All CDFX structure is from public documentation (`design-input/cdfx-research.md`); producer-specific variation (namespaces, `ADMIN-DATA`, history blocks) cannot be fully verified against real-world output without a sample. | Accepted residual risk. Mitigated — `make_variant_cdfx` / `make_tool_note_cdfx` synthesize the known producer-variation surface; TC-017 / TC-034 exercise it. Optional: add one public CDF 2.0 sample under a redistributable license as a supplementary TC-017 fixture. |
| G-2 | Environmental — residual risk (RK-2) | medium | vCDM interop is asserted from Vector documentation, not tested against a live vCDM instance (no license, no sample — A-5). | Out of automated scope by design. The achievable acceptance criterion is "structurally valid CDF 2.0 per the §7 `W-*`/`R-*` rule set" — which the test cases verify (C-3, OQ-1/OQ-4: XSD conformance is a deferred non-goal). Real vCDM round-trip stays a client-side manual check; flag it in the Phase-6 demo / hand-off notes. |
| G-3 | CI hygiene | low | `ruff check` / `ruff format --check` not executed for increments 1–11 — `ruff` not installed in the Phase-3/4 environment; each increment substituted `python -m py_compile`. | Deferred to CI. Mitigated — every CDFX module compiles; the 192-pass subset and 611-pass full suite import and exercise every module. Recommended: run `ruff` in `.github/workflows/tui-ci.yml` before merge; no code change anticipated. |
| G-4 | Environmental | low | Manual real-terminal Patch Editor verification not performed — Phase-3/4 ran headless (`App.run_test()` / `pytest`). The increment-11 packet hands off a manual Patch-Editor test plan (no-A2L empty-save edge, load-replaces-change-list, `W-ARRAY-SPARSE` / `W-WRITE-CONTAINMENT` fail-loud behaviors). | Deferred. Mitigated — TC-025/026/036 and the TC-027a integration arm drive the full screen → `app.py` handler → `CdfxService` → `cdfx` package → `DataTable` path under `App.run_test()`; the named behaviors are all test-pinned. Recommended: Javier runs a ~10-minute manual pass before merge. |

**Other items recorded, no Phase 4 action ([`04-validation.md`](../04-validation.md) §8):**

- The `_compute_a2l_enriched_tags` stub couples the integration tests to a method name — a rename would break the tests loudly and locally; recorded, benign.
- `app.log_lines` is a `deque(maxlen=4)` truncated to 50 chars — the status assertions search within the retained window; recorded so a future status-volume change is read correctly.
- CV-01 (the §6.3 OQ-3 "containment" vs "resolution" wording) — a one-line editorial item with no natural touch-point; surfaced once more for the Phase-6 docs sweep.

---

## 4. Changes from previous batch

This is **batch 3** of the s19_app dev-flow.

| Field | Value |
|-------|-------|
| Previous batch | `2026-05-20-batch-02` (Direction B "Rail + Command" view-layer restyle) |
| Carried-forward findings closed by this batch | `R-TUI-027` — the inert Patch Editor view shell delivered by batch-02 is **superseded** by the functional Patch Editor (HLR-007 / `R-CDFX-016`). batch-02 delivered the screen as a non-functional preview with a visible deferral notice; batch-03 replaces it with a working tool. |
| `R-*` traceability rows added to the living `REQUIREMENTS.md` | **18 new `R-CDFX-001`..`R-CDFX-018`** (synthesized from the 8 HLR / 44 LLR / 47 TC of [`01-requirements.md`](../01-requirements.md) — see the living [`REQUIREMENTS.md`](../../../REQUIREMENTS.md), section "CDFX / Patch Editor (batch 2026-05-21-batch-03)"). |
| `R-*` rows superseded by this batch | `R-TUI-027` (inert Patch Editor shell) — marked **Superseded** by `R-CDFX-016` (functional Patch Editor). The `R-TUI-027` row is retained for history. |
| `R-*` rows protected and confirmed not regressed | The engine `R-*` set — `R-READ-*`, `R-PARSE-*`, `R-VAL-*`, `R-HEX-*`, `R-A2L-*` — is untouched (`git diff main` empty, [`04-validation.md`](../04-validation.md) §2); the batch-02 `R-TUI-021`..`R-TUI-037` rows are not regressed (the CDFX feature is purely additive new files, and `app.py`/`screens_directionb.py` carry the Patch Editor wiring on top of the batch-02 restyle). |
| Engine status | Frozen — zero bytes changed across `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`. The CDFX feature is purely additive (new package `s19_app/tui/cdfx/`, new service `cdfx_service.py`, new tests). `ValidationIssue` is reused as-is with `artifact="cdfx"` — no model edit. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story

- **US-001 / US-007 (build a change-list)** → HLR-001 → LLR-001.1/001.2/001.3/001.4 → TC-001, TC-002, TC-003
- **US-002 (parameter resolution)** → HLR-002 → LLR-002.1/002.2/002.3/002.4 → TC-004..TC-007
- **US-003 (type-driven value display)** → HLR-003 → LLR-003.1/003.2/003.3 → TC-008, TC-009, TC-010
- **US-004 (save a `.cdfx`)** → HLR-004 → LLR-004.1..004.9 → TC-011..TC-014, TC-019d, TC-019h, TC-032, TC-033, TC-038, TC-024
- **US-005 / US-006 (load + validate a `.cdfx`)** → HLR-005, HLR-006 → LLR-005.1..005.6, LLR-006.1..006.8 → TC-015..TC-023, TC-027a/b, TC-034, TC-035, TC-037, TC-039
- **US-007 (functional Patch Editor screen)** → HLR-007 → LLR-007.1..007.7 → TC-025, TC-026, TC-028, TC-036
- **US-002 / US-005 / US-006 (A2L cross-check on load)** → HLR-008 → LLR-008.1/008.2/008.3 → TC-029, TC-030, TC-031

### 5.2 By code file

The CDFX feature is a new package plus a new service plus the Patch Editor wiring. New files created this batch are marked **(new)**.

| Code file | LLR(s) / role | Increment | Test(s) |
|-----------|---------------|-----------|---------|
| `s19_app/tui/cdfx/__init__.py` **(new)** | Narrow public import surface — re-exports `ChangeList` / `ChangeListEntry` / `ResolutionStatus` / `read_cdfx` / `write_cdfx` / `write_cdfx_to_workarea` / `validate_w_rules` | 1, 7 | (import surface; exercised by all CDFX test files) |
| `s19_app/tui/cdfx/changelist.py` **(new)** | LLR-001.1..001.4, LLR-003.3 (storage arm) — the pure change-list model; `ChangeListEntry` / `ChangeList` / `ResolutionStatus`; `array_index` is `Optional[int]` | 1, 5 | `tests/test_cdfx_changelist.py` |
| `s19_app/tui/cdfx/resolve.py` **(new)** | LLR-002.1..002.4 — A2L parameter resolution against the **enriched** A2L payload (C-1) | 2, 5 | `tests/test_cdfx_resolve.py` |
| `s19_app/tui/cdfx/display.py` **(new)** | LLR-003.1, 003.2, 003.3 (display arm) — type-driven value display formatting | 3 | `tests/test_cdfx_display.py` |
| `s19_app/tui/cdfx/writer.py` **(new)** | LLR-004.1..004.9, LLR-006.1, LLR-007.7 — CDFX writer (`write_cdfx` / `write_cdfx_to_workarea`), array coalescing, the standalone `W-*` validator (`validate_w_rules`) | 4, 6, 8 | `tests/test_cdfx_writer.py`, `tests/test_cdfx_w_rules.py` |
| `s19_app/tui/cdfx/reader.py` **(new)** | LLR-005.1..005.6, LLR-006.2..006.8, LLR-008.1..008.3 — CDFX reader (`read_cdfx`), `VAL_BLK` expansion, `R-*` validation, XML-safety (`DOCTYPE`/entity rejection, size/depth bound), A2L cross-check | 7, 8 | `tests/test_cdfx_reader.py`, `tests/test_cdfx_r_rules.py`, `tests/test_cdfx_safety.py`, `tests/test_cdfx_path_containment.py` |
| `s19_app/tui/services/cdfx_service.py` **(new)** | LLR-007.1..007.4 (orchestration arm) — the `CdfxService` seam between the Patch Editor / `app.py` and the `cdfx` package; `parse_array_index` / `parse_value` | 9 | `tests/test_tui_patch_editor.py` |
| `s19_app/tui/screens_directionb.py` | LLR-007.1, 007.2, 007.6 — `PatchEditorPanel` made functional: change-list rows, wired add/edit/remove inputs, save/load actions, neutral empty state (supersedes the `R-TUI-027` inert shell) | 9 | `tests/test_tui_patch_editor.py` |
| `s19_app/tui/app.py` | LLR-007.3, 007.4, 007.5 — UI-state wiring only: the Patch Editor action handler routes through `_cdfx_service`; **no XML, no model logic** (C-8 / TC-028) | 9 | `tests/test_tui_patch_editor.py` (TC-028) |
| `s19_app/tui/workspace.py` | LLR-005.5, 007.7 — **reused read-only**: `resolve_input_path` (load path), `copy_into_workarea` / `_path_traverses_reparse_point` / `DEFAULT_COPY_SIZE_CAP_BYTES` (write-path containment + 256 MB cap) | — | `tests/test_cdfx_path_containment.py`, `tests/test_tui_patch_containment.py` |
| `s19_app/validation/model.py` | LLR-006.3 — **reused as-is**, zero bytes changed; CDFX findings are `ValidationIssue` with `artifact="cdfx"` passed as a string argument (no model edit needed) | — | `tests/test_cdfx_r_rules.py` (TC-022) |
| `s19_app/core.py`, `hexfile.py`, `range_index.py`, `tui/a2l.py`, `tui/mac.py`, `validation/` | **frozen engine surface** — `git diff main` empty; `tui/a2l.py` (`enrich_a2l_tags_with_values`, `DATATYPE_SIZES`) is consumed read-only by `resolve.py` | — | engine test files unchanged from batch-02 |

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-05-21-batch-03` |
| Batch title | Functional Patch Editor + ASAM CDFX (`.cdfx`) read/write |
| Branch | `dev-flow/batch-02-direction-b-restyle` @ `701a849` (the 11 batch-03 increments present as new/untracked source) |
| Closing date | Phase 4 validated `2026-05-21`; Phase 6 docs delivered `2026-05-21` |
| Total iterations | Phase 1: 3 iterations + Phase-3 amendment · Phase 2: `pass` (0 blockers, 28 findings closed, OQ-1..OQ-6 resolved) · Phase 3: 11 increments · Phase 4: 1 · Phase 5: 1 |
| Validation passed | yes — `pass-with-gaps` (0 blockers; 4 documentary/environmental gaps G-1..G-4) |
| pytest baseline at gate | 611 passed / 0 failed / 3 xfailed / 2 skipped; 27 snapshots passed (Windows 11, Python 3.12.7, pytest 8.4.2, textual 8.0.2); CDFX + Patch subset 192 passed / 0 failed |
| Engine freeze | verified — `git diff main` empty across `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`; the CDFX feature is purely additive new files |
| Traceability completeness | NO GAPS — 7 US / 8 HLR / 44 LLR / 47 TC all traced and `pass` |
| `R-*` rows added to living `REQUIREMENTS.md` | 18 (`R-CDFX-001`..`R-CDFX-018`); `R-TUI-027` marked Superseded |
| Synced to Obsidian | (post-merge — `/dev-flow-sync-en` after PR close) |
