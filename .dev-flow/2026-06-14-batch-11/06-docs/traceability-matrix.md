# Traceability Matrix — s19_app — Batch 2026-06-14-batch-11

> Full chain: **User Story → HLR → LLR → Test Case → File:line**.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.

> **Feature:** US-010 — the tool WRITEs the project manifest (`project.json`) — previously read-only / hand-authored — and verify-checks the write (re-read → compare against intent), mirroring batch-10 verify-on-save for firmware images.
>
> **Node-id provenance:** every TC node id below is the REAL implemented function name read from the test files on the current tree (grep-verified, see §7), NOT the provisional `-k` selectors the spec pinned (`-k envelope_keys`, `-k roundtrip`, …). Those provisional tokens were reconciled to the implemented names per `04-validation.md` DEV-1 (V-5 provisional-identifier scope rule).

---

## 1. Master table

> `File:line` cites the production symbol that implements the LLR (grep-verified on the current worktree). The TC column carries the implemented pytest node id. All TCs PASS (23/23 targeted, `04-validation.md` §1).

| US | HLR | LLR | TC (implemented node id) | File:line | Status |
|----|-----|-----|--------------------------|-----------|--------|
| US-010 | HLR-001 | LLR-001.1 | `tests/test_manifest_writer.py::test_envelope_keys_and_active_variant` | `s19_app/tui/services/manifest_writer.py:224` (`serialize_manifest`) | pass |
| US-010 | HLR-001 | LLR-001.1 (AC: empty project) | `tests/test_manifest_writer.py::test_envelope_empty_project_active_variant_is_null` | `s19_app/tui/services/manifest_writer.py:312` (`active_variant = variant_set.active_id`) | pass |
| US-010 | HLR-001 | LLR-001.2 | `tests/test_manifest_writer.py::test_relative_paths_resolve_with_no_escape` | `s19_app/tui/services/manifest_writer.py:152` (`_posix_entries`) | pass |
| US-010 | HLR-001 | LLR-001.2 (AC: backslash) | `tests/test_manifest_writer.py::test_windows_backslashes_normalized_to_forward_slash` | `s19_app/tui/services/manifest_writer.py:175` (`.replace("\\", "/")`) | pass |
| US-010 | HLR-001 | LLR-001.3 | `tests/test_manifest_writer.py::test_roundtrip_equals_intent_in_canonical_form` | `s19_app/tui/services/manifest_writer.py:319` (`json.dumps` envelope) | pass |
| US-010 | HLR-001 | LLR-001.3 (AC: schema_version) | `tests/test_manifest_writer.py::test_roundtrip_schema_version_survives` | `s19_app/tui/services/manifest_writer.py:311` (`"schema_version": schema_version`) | pass |
| US-010 | HLR-001 | LLR-001.4 | `tests/test_manifest_writer.py::test_deterministic_byte_identical_output` | `s19_app/tui/services/manifest_writer.py:319` (`json.dumps(..., indent=2)`, stable order) | pass |
| US-010 | HLR-001 | LLR-001.5 | `tests/test_manifest_writer.py::test_refuse_escape_and_absolute_entries_writes_nothing` | `s19_app/tui/services/manifest_writer.py:178` (`_reject_unsafe_entry`) / `:308` (`return None, findings`) | pass |
| US-010 | HLR-001 | LLR-001.5 (threshold: clean passes) | `tests/test_manifest_writer.py::test_clean_composition_passes_the_gate` | `s19_app/tui/services/manifest_writer.py:307` (`if findings:` gate) | pass |
| US-010 | HLR-001 ∩ HLR-002 | LLR-001.5 (write-side short-circuit) | `tests/test_manifest_writer.py::test_refusal_emits_no_file_when_caller_would_write` | `s19_app/tui/services/manifest_writer.py:452` (`if text is None: return None, findings`) | pass |
| US-010 | HLR-002 | LLR-002.1 | `tests/test_manifest_writer.py::test_write_places_manifest_and_reads_back` | `s19_app/tui/services/manifest_writer.py:370` (`write_project_manifest`) | pass |
| US-010 | HLR-002 | LLR-002.1 (M-1: two-saves-one-file) | `tests/test_manifest_writer.py::test_two_saves_leave_exactly_one_manifest_second_wins` | `s19_app/tui/services/manifest_writer.py:463` (`os.replace(staged, destination)`) | pass |
| US-010 | HLR-002 | LLR-002.2 | `tests/test_manifest_writer.py::test_fixed_name_and_staged_temp_removed` | `s19_app/tui/services/manifest_writer.py:455` (`destination = project_root / PROJECT_MANIFEST_NAME`) / `:472` (`finally: staged.unlink()`) | pass |
| US-010 | HLR-002 | LLR-002.3 | `tests/test_manifest_writer.py::test_destination_outside_workarea_returns_finding` | `s19_app/tui/services/manifest_writer.py:465` (`except (WorkareaContainmentError, OSError)`) / `:120` (`_manifest_write_containment_issue`) | pass |
| US-010 | HLR-002 ∩ HLR-001 | LLR-002.3 (refused serialize short-circuits) | `tests/test_manifest_writer.py::test_refused_serialize_short_circuits_without_writing` | `s19_app/tui/services/manifest_writer.py:452` (`if text is None`) | pass |
| US-010 | HLR-003 | LLR-003.1 | `tests/test_manifest_verify.py::test_faithful_write_verifies` | `s19_app/tui/services/manifest_writer.py:580` (`verify_written_manifest`) / `:649` (`read_project_manifest(project_dir)`) | pass |
| US-010 | HLR-003 | LLR-003.1 (M-1: canonical-name re-read) | `tests/test_manifest_verify.py::test_verify_reads_canonical_name_not_a_stray_suffixed_file` | `s19_app/tui/services/manifest_writer.py:647` (`canonical_path = project_dir / PROJECT_MANIFEST_NAME`) | pass |
| US-010 | HLR-003 | LLR-003.2 | `tests/test_manifest_verify.py::test_tampered_active_variant_mismatches_naming_the_key` | `s19_app/tui/services/manifest_writer.py:665`–`:671` (`drift.append(...)`) | pass |
| US-010 | HLR-003 | LLR-003.3 (R-1: reader-issues ⇒ mismatch) | `tests/test_manifest_verify.py::test_reader_issues_force_mismatch_even_if_surviving_keys_match` | `s19_app/tui/services/manifest_writer.py:673`–`:677` (`if not drift and not manifest.issues`) | pass |
| US-010 | HLR-004 | LLR-004.1 | `tests/test_tui_manifest_save.py::test_project_save_writes_and_verifies_manifest` | `s19_app/tui/app.py:3539` (`_write_and_verify_manifest`) / `:3578` (`write_project_manifest`) / `:3592` (`verify_written_manifest`) | pass |
| US-010 | HLR-004 | LLR-004.2 (mismatch loud) | `tests/test_tui_manifest_save.py::test_manifest_mismatch_surfaces_loud_notice_naming_drift` | `s19_app/tui/app.py:3595` (`_surface_manifest_verify_result`) / `:3637` (mismatch notice) | pass |
| US-010 | HLR-004 | LLR-004.2 (refusal error notice) | `tests/test_tui_manifest_save.py::test_manifest_write_refusal_surfaces_error_notice_no_crash` | `s19_app/tui/app.py:3581`–`:3590` (write-refusal error notice) | pass |
| US-010 | HLR-004 | LLR-004.3 (headless) | `tests/test_tui_manifest_save.py::test_manifest_writer_module_is_headless` | `s19_app/tui/services/manifest_writer.py:41`–`:63` (stdlib + sibling imports only; no `textual`, no `logging`) | pass |

**Master-table count: 23 rows = 23 implemented TC nodes, all `pass`.** (10 in `test_manifest_writer.py` serialize-side rows + 5 write-side = 15; 4 in `test_manifest_verify.py`; 4 in `test_tui_manifest_save.py`.)

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 1 (US-010) |
| Covered user stories | 1 (100%) |
| Total HLR | 4 (HLR-001..004) |
| Implemented HLR | 4 (100%) |
| Total LLR | 14 (LLR-001.1..001.5, 002.1..002.3, 003.1..003.3, 004.1..004.3) |
| Implemented LLR | 14 (100%) |
| Test cases (implemented nodes) | 23 |
| TC pass | 23 |
| TC fail | 0 |
| TC pending | 0 |

> LLR → TC roll-up (`04-validation.md` §1.1): 14/14 LLRs each covered by ≥1 passing TC. The 23 implemented nodes exceed the 14 LLRs because several TCs carry multiple AC-level assertion tests (over-coverage, `04-validation.md` DEV-2) — not a duplication.

---

## 3. Detected gaps

> No coverage holes in what was specced: every HLR-004 LLR (004.1/004.2/004.3) is covered and passing. The single recorded item below is a **scope boundary**, not a missing-test gap.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| SCOPE-1 | Scope boundary (not a coverage hole) | The TUI save handler `_write_and_verify_manifest` (`s19_app/tui/app.py:3578`) calls `write_project_manifest(variant_set, project_dir, self.base_dir)` with **no `batch=` / `assignments=` kwargs** — they default to empty. So a TUI save today persists `active_variant` only; `batch`/`assignments` are written EMPTY because the current save flow composes none. The **writer fully supports and tests** `batch`/`assignments` composition (TC-001a..003c all pass explicit kwargs — see master-table rows for LLR-001.2/001.3/001.5/003.x). HLR-004's LLRs (004.1/004.2/004.3) pin "invoke the pipeline + surface the outcome", which the handler does — they did NOT pin save-flow composition of `batch`/`assignments`. So this is a **spec-conformant boundary**, fully covered for what was specced. | Route to **batch-12**: decide whether the save flow should compose `batch`/`assignments` from the loaded project state to fully realize US-010's composition benefit at the file-list level (today realized at the active-variant level). Recorded in `04-validation.md` SCOPE-1 + Phase-5 post-mortem. NOT a Phase-4 failure. |

---

## 4. Changes from previous batch

*(Batch-11 vs batch-10. Batch-10 added verify-on-save for firmware IMAGES; batch-11 adds the JSON-manifest analogue.)*

| Type | Item | Detail |
|------|------|--------|
| new | US-010 | First user story for the WRITE side of `project.json` (the manifest was read-only / hand-authored through batch-10). |
| new | HLR-001 / LLR-001.1–001.5 | Serialize a project composition to the canonical reader-accepted envelope (`serialize_manifest`); LLR-001.5 is the security input gate (refuse absolute/escaping entries), added at the Phase-1 iteration. |
| new | HLR-002 / LLR-002.1–002.3 | Contained atomic write (`write_project_manifest`): stage → reuse `copy_into_workarea` containment CHECKS → atomic `os.replace` at the fixed name, NOT the dedup body. |
| new | HLR-003 / LLR-003.1–003.3 | Verify-on-write (`verify_written_manifest` + `ManifestVerifyResult`): re-read canonical name → compare key-wise → reader-issues ⇒ mismatch. The JSON analogue of batch-10's `verify_written_image`. |
| new | HLR-004 / LLR-004.1–004.3 | TUI save-flow wiring (`_write_and_verify_manifest` + `_surface_manifest_verify_result`, `app.py`) + headless-module contract. |
| new (file) | `s19_app/tui/services/manifest_writer.py` | New headless service module (serialize + write + verify). Lives in `tui/services/` — outside the engine-frozen set and outside the `s19_app/` package root. |
| new (tests) | `tests/test_manifest_writer.py`, `tests/test_manifest_verify.py`, `tests/test_tui_manifest_save.py` | 15 + 4 + 4 = 23 nodes. |
| modified | `s19_app/tui/app.py` | Save handler wired (orchestration-only); pre-existing file-copy save behavior unchanged. |
| reused | batch-10 verify-on-save substrate | `ManifestVerifyResult` mirrors `VerifyResult`'s shape (status / drift / issues / written_path) but compares key-wise over a JSON dict — NOT `diff_mem_maps` (a manifest is not a mem_map; design decision D-1). |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-010** → HLR-001, HLR-002, HLR-003, HLR-004 → LLR-001.1..001.5, LLR-002.1..002.3, LLR-003.1..003.3, LLR-004.1..004.3 → 23 implemented TC nodes across `test_manifest_writer.py`, `test_manifest_verify.py`, `test_tui_manifest_save.py`.

### 5.2 By code file
- `s19_app/tui/services/manifest_writer.py` → LLR-001.1..001.5 (`serialize_manifest`, `_reject_unsafe_entry`, `_posix_entries`), LLR-002.1..002.3 (`write_project_manifest`, `_check_destination_contained`, `os.replace`), LLR-003.1..003.3 (`verify_written_manifest`, `ManifestVerifyResult`, `_resolve_intended_entries`), LLR-004.3 (headless import surface) → `test_manifest_writer.py`, `test_manifest_verify.py`, `test_tui_manifest_save.py::test_manifest_writer_module_is_headless`.
- `s19_app/tui/app.py` → LLR-004.1 (`_write_and_verify_manifest`), LLR-004.2 (`_surface_manifest_verify_result`) → `test_tui_manifest_save.py`.

### 5.3 By oracle (unchanged this batch)
- `s19_app/tui/services/variant_execution_service.py` — `read_project_manifest` (the reader/oracle), `_resolve_manifest_entry`, `PROJECT_MANIFEST_NAME`, `ProjectManifest`. The writer round-trips against it; it is NOT modified this batch (assumption A-1).

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-14-batch-11` |
| Closing date | `2026-06-15` |
| Total iterations (sum of phases) | Phase-1 ITERATION 2 (one reconciliation iteration, applying the Phase-2 fix register B-1 / M-1 / M-2 / M-3 / m-1..m-7); Phases 3–4 single-pass. |
| Validation passed | yes — PASS-WITH-NOTES (`04-validation.md` §6); 23/23 targeted TC pass; all 7 owned §5.3 acceptance criteria pass; lean suite 786/0, full suite 807/0, collection reconciled 839 exact. |
| Notes (not failures) | SCOPE-1 (active-variant-only TUI save → batch-12); DEV-1 (V-5 node/selector renames, reconciled here); DEV-2 (+6 over-coverage vs predicted addition band). |
| Synced to Obsidian | no (run `/dev-flow-sync-en` after merge) |

---

## 7. Anchor verification log

> Every `file:line` anchor in the master table was grep-verified against the current worktree (`competent-clarke-1e8940`) on 2026-06-15.

- **Production symbols (`s19_app/tui/services/manifest_writer.py`)** — grep-confirmed line anchors: `_posix_entries:152`, `_reject_unsafe_entry:178`, `serialize_manifest:224`, `return None, findings:308`, `:311` schema_version key, `:312` active_variant, `:319` `json.dumps`, `_check_destination_contained:322`, `write_project_manifest:370`, `:452` `if text is None`, `:455` destination fixed name, `:463` `os.replace`, `:465` except clause, `:472` `finally`/unlink, `MANIFEST_VERIFIED:481`, `MANIFEST_MISMATCH:486`, `ManifestVerifyResult:490`, `_resolve_intended_entries:543`, `verify_written_manifest:580`, `:647` canonical_path, `:649` `read_project_manifest`, `:665`–`:671` drift, `:673`–`:677` status. (24 production anchors.)
- **TUI handler (`s19_app/tui/app.py`)** — grep-confirmed: `_handle_save_dialog:3443`, call site `:3535`, `_write_and_verify_manifest:3539`, `write_project_manifest:3578`, refusal notice `:3581`–`:3590`, `verify_written_manifest:3592`, `_surface_manifest_verify_result:3595`, mismatch notice `:3637`. (NOTE: `04-validation.md` named the handler `_persist_project_manifest` at `app.py:3575-3593`; the REAL implemented name on the tree is `_write_and_verify_manifest` at `:3539` — this matrix cites the real symbol.)
- **Test nodes** — all 23 `def test_*` confirmed present at the file:line shown in the master table (`test_manifest_writer.py` 15 nodes, `test_manifest_verify.py` 4 nodes, `test_tui_manifest_save.py` 4 nodes). Provisional `-k` selectors carry no residue here — every TC cell is a real node id.
- **Total file:line anchors grep-verified: 24 production + 8 handler + 23 test = 55.**
