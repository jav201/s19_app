# Traceability Matrix — s19_app — Batch 2026-07-02-batch-24

> Two chains (Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
>
> **Batch scope:** feature #12, slice **(a)+(c)** — US-032/US-033 (the A2L red-row ↔ Issues reconcile, both directions, incl. the blocker-born no-MAC retention fix LLR-037.4) and US-034 (the before/after report on save-back, incl. the blocker-born B-2 provenance preconditions). Entropy slice (b) (US-035/036/037) deferred whole to its own batch. All node names below are the **V-5 reconciled** real on-disk pytest node ids (04-validation.md §1.1: 24 provisional ids → 33 collected nodes, 0 orphans; partition 26 new-file + 7 extended-file nodes). Frozen-engine set: **0-diff at all five gates** (I1–I4 increment gates + the Phase-4 direct `git diff main` re-check).
>
> **Executed results carried by every row:** 3 new test files **26/26 PASSED** (Phase-4 reviewer's own run, `26 passed in 15.65s`); 2 extended files **45/45 PASSED** (`45 passed in 0.74s`); engine guard `1 passed`. Full non-slow suite at the I4 gate (orchestrator run, no code changed since — increment-5.md §4): **1004 passed / 0 failed**, ledger **1004 → 1037** (+33 / −0).
>
> *File:line citations re-verified against the current tree at docs time (grep, 2026-07-02). Batch artifacts cite pre-fold positions for several app.py symbols (e.g. `_a2l_tag_row_severity` at `:223` in 01-requirements → now `:295`; `update_a2l_tags_view` at `:7482` → now `:7730`). Symbols, not line numbers, are the stable anchors.*

---

## 1. Master table — functional chain (white-box)

Test files: `tests/test_validation_service_supplemental.py` (=`supplemental`), `tests/test_tui_a2l_issue_recolor.py` (=`recolor`), `tests/test_before_after_report.py` (=`before_after`), `tests/test_diff_report_service.py` (=`diff_report`), `tests/test_change_service.py` (=`change_svc`).

| US | HLR | LLR | TC node(s) | File:line (re-verified) | Result | Notes |
|----|-----|-----|------------|--------------------------|--------|-------|
| US-032 | HLR-036 | LLR-036.1 (supplemental `A2L_TAG_SCHEMA_INCOMPLETE` ERROR per `schema_ok is False` tag; constructor scrub; absent-key tags gain nothing — A-M2 keying) | `supplemental::test_tc_036_1_one_error_per_schema_bad_tag_keyed_on_is_false` · `::test_tc_036_4_nameless_schema_bad_tag_falls_back_to_context` | `s19_app/tui/services/validation_service.py:20` (`supplemental_a2l_row_issues`) | **PASSED** | Exactly-N assert (list equality on symbols, not `>=`); nameless tag → `symbol=None`, address/`unnamed` message fallback; issue code NEW (P-4: 0 prior hits), emitted only from this open-seam module (QR-8) |
| US-032 | HLR-036 | LLR-036.2 (dedup: casefolded symbol × `artifact=="a2l"` × ERROR; symbol-less/WARNING/non-a2l never suppress) | `supplemental::test_tc_036_2_dedup_casefolded_symbol_a2l_error_only` | same function (covered-symbol set) | **PASSED** | `Bad_Tag` vs `BAD_TAG` casefold → `== []`; `A2L_STRUCTURE_ERROR` (symbol-less) asserted non-suppressing |
| US-032 | HLR-036 | LLR-036.3 (merge before `dedupe_issues` in BOTH report branches, non-empty tag list only) | `supplemental::test_tc_036_3_merge_in_both_report_branches` | `validation_service.py:111` (`build_validation_report`) | **PASSED** | Present for both `primary_file=None` and primary-backed invocations; empty tag list → absent in both |
| US-032 + US-033 | HLR-036 + HLR-037 (shared substrate, AM-1) | LLR-037.4 (no-MAC sessions retain the validation report; no-primary keeps the clear; cache-routed, stable key) | `supplemental::test_tc_037_4_worker_path_retains_report_without_mac` · `::test_tc_037_4_sync_path_computes_once_and_caches` · `::test_tc_037_4_no_primary_session_keeps_the_clear` | `s19_app/tui/app.py:6053` (`_refresh_no_mac_validation`), `:6000` (`_mac_view_cache_key_for` — `id(loaded)` substitute for empty records), `:7403` (`update_mac_view`, both former wipe sites rewired) | **PASSED** | Worker path: `calls["n"] == 0` on re-render (cache-hit no-op, counter-enforced); sync path: exactly 1; no-primary: clear kept verbatim. Blocker-born (B-1, AM-1 — footnote §7); also gated black-box by AT-036a's Issues-pane observable |
| US-033 | HLR-037 | LLR-037.1 (symbol→max-severity map: a2l + non-empty symbol only; ERROR ranks above all) | `recolor::test_tc_037_1_issue_severity_map_build_and_filter_semantics` | `app.py:224` (`_A2L_ISSUE_SEVERITY_RANK`), `:234` (`_a2l_issue_severity_map`) | **PASSED** | Exact dict equality; casefold keys; order-independence re-asserted reversed; `[] → {}` |
| US-033 | HLR-037 | LLR-037.2 (row severity consults the map; ERROR-only precedence — WARNING never recolours, D-2) | `recolor::test_tc_037_2_row_severity_precedence_matrix_and_warning_guard` **(GUARD: WARNING no-recolour, constructed issues — A-M1 split)** · `tests/test_tui_app.py::test_a2l_tag_row_severity_matches_updated_policy` (net-0 in-place update) | `app.py:295` (`_a2l_tag_row_severity`, map now a REQUIRED param), `:7730` (`update_a2l_tags_view` — map BUILD ownership, A-m4) | **PASSED** | Full matrix: empty-map ladder ×5 byte-identical · ERROR-map ×5 all→ERROR (incl. green memory-checked candidate) · WARNING-map ×5 unchanged · unmapped ×5 unchanged · nameless never consults |
| US-033 | HLR-037 | LLR-037.3 (issues installed before tag rows render, after enrichment — `update_mac_view()` reordered; A-m1 pin) | `recolor::test_tc_037_3_sync_fallback_first_render_is_fresh` (+ TC-037.4 idempotence unbroken) | `app.py:7668` (`update_a2l_view`, A2L-present branch reorder) | **PASSED** | Sync-fallback drive; duplicate rows ERROR-styled on FIRST render, no manual re-render; worker path ordered by construction (P-10) |
| US-034 | HLR-038 | LLR-038.1 (generator provenance/linkage/stem kwargs, default-off; byte-identical default; `_md_cell` pipe/ctl escaping S-F2; `before_bytes=None` marker R-4) | `diff_report::test_provenance_and_linkage_render_in_both_formats` · `::test_default_kwargs_output_byte_identical_pre_change_golden` · `::test_zero_entries_linkage_states_no_entries` · `::test_pipe_bearing_symbol_md_escaped_html_intact` | `s19_app/tui/services/diff_report_service.py:184` (`BeforeAfterProvenance`), `:226` (`_strip_ctl`, I4 factoring), `:254` (`_md_cell`), `:396` (`_diff_report_filename` stem), `:939` / `:1353` (both generators) | **PASSED** | Golden = raw `read_bytes()` equality, `os.linesep`-expanded (both platforms), **double-proven**: independently re-derived by the I3 reviewer from a detached worktree @origin/main (2437B md / 2386B html byte-match); survived the I4 `_strip_ctl` factoring untouched |
| US-034 | HLR-038 | LLR-038.2 (composer: preconditions 1–5 incl. B-2 provenance match + containment; `SOURCE_EXTERNAL` compare; own filename regexes; S-F4 symlink refusal; no Textual import; B-2 stamp: `source_image_path` field off `to_dict`, stamped by `save_patched`) | `before_after::test_tc_038_3_composer_happy_path_and_regex_ownership` · `::test_tc_038_3_symlink_reports_destination_refused` · `::test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair` · `change_svc::test_save_patched_stamps_source_image_path` · `::test_save_patched_without_kwarg_leaves_source_image_path_none` · `::test_to_dict_excludes_source_image_path_and_stays_byte_stable` | `s19_app/tui/services/before_after_service.py:182` (`compose_before_after_report`), `:72` (`BEFORE_AFTER_REPORT_FILENAME_REGEX`), `:88` (`BeforeAfterReportResult`); stamp: `s19_app/tui/changes/model.py:464` + `s19_app/tui/services/change_service.py:933` | **PASSED** | Regex ownership asserted BOTH directions (own regexes match, diff-report/shared regexes don't); `to_dict` JSON byte-equal before/after stamping. B-2 blocker-born (AM-2 — footnote §7) |
| US-034 | HLR-038 | LLR-038.3 (offer notify after `_surface_verify_result`; key `b` → `action_before_after_report`; surfaced written paths / refusal; verify-mismatch does not suppress the offer, A-m2) | asserted inside `before_after::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` (offer severity `"information"`, names the action + `"press b"`; real `pilot.press("b")`) | `app.py:684` (`Binding("b", "before_after_report", …)`), `:1710` (`action_before_after_report`), `:1639` (handler passes `source_image_path=loaded.path`) | **PASSED** | The P-6 provisional key `b` held — no re-choice. C-13 N/A (notify + binding only, zero geometry) |
| US-034 | HLR-038 | LLR-038.4 (4 refusal classes = refusals, never writes; no-project refusal names the manual A↔B path, D-3) | `before_after::test_tc_038_4_all_refusal_classes_write_no_files` (all 4 classes, both class-3 and class-4 arms) · `::test_tc_038_4_no_project_refusal_names_manual_ab_path` (+ AT-038b/c/d, §1b) | composer refusal ladder in `before_after_service.py:182` ff.; handler surfacing `app.py:1710` | **PASSED** | Per-class: positive diagnostic needle + `reports/` listing `== set()` — 0 files asserted by directory listing, exactly the threshold |
| US-034 | HLR-038 | LLR-038.5 (confidentiality: `<project>/reports/` destination construction; no logging; surfaced text carries paths/diagnostics only — S-F3/S-F5) | `before_after::test_tc_038_5_module_imports_no_textual_and_no_logging` (automated inspection) + AT-038a's S-F5 no-byte-leak sweep + Phase-4 reviewer read of the handler | `before_after_service.py` (no `logging`/`getLogger`/Textual import — `inspect.getsource` asserted); `app.py:1710` handler | **PASSED** | Gitignore coverage stated as a default-layout property, not a guarantee (S-F3 rewording) |

All 12 LLR rows: numeric thresholds **audited in-assert** by the Phase-4 validator (04-validation.md §2.2 — all 12 read from the test code, none vacuous; two lazy-reading disagreements checked and resolved).

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test observing the outcome through the shipped surface, plus its counterfactual (RED) evidence. **Two of the three GATE REDs were live shipped bugs** — the divergence the stories claimed was captured failing verbatim on the pre-fix tree, then flipped green. Fixtures for US-032/033 are deliberately **MAC-less** (B-1a discipline: adding a MAC would have greened the ATs while the shipped bug persisted — the C-12-family masking class).

| US | Acceptance test (node in its file) | Class | Shipped surface | Observed outcome / deliverable | Counterfactual (RED) evidence | Result |
|----|------------------------------------|-------|-----------------|--------------------------------|-------------------------------|--------|
| US-032 | `supplemental::test_at_036a_missing_schema_red_row_has_matching_error_issue` | **GATE** | Pilot: shipped load chain → `#a2l_tags_list` styles + `#validation_issues_list` rows | Missing-address/length non-virtual tags red AND named `A2L_TAG_SCHEMA_INCOMPLETE` ERRORs rendered on the Issues surface; virtual tag exempt-by-construction | **LIVE BUG RED** — pre-I1 verbatim capture, `03-increments/increment-1.md` §4a: observable 1 (red rows) PASSED, observable 2 FAILED `Rendered issue rows: []` (both B-1 causes visible); reviewer-verified credible | **PASSED** |
| US-032 | `supplemental::test_at_036b_already_covered_symbol_gains_no_second_error` | AT | same | Duplicate-symbol tag: exactly 1 ERROR (`A2L_DUPLICATE_SYMBOL`), 0 supplemental for that symbol — no double-report | n/a (dedup boundary) | **PASSED** |
| US-032 | `supplemental::test_at_036c_clean_a2l_yields_zero_supplemental_issues` · `::test_at_036c_empty_tag_set_yields_zero_supplemental_issues` | AT (negative ×2) | same | Clean / zero-tag A2L → 0 supplemental issues, no red rows | n/a (negatives) | **PASSED** |
| US-033 | `recolor::test_at_037a_duplicate_symbol_error_issue_reds_both_rows` | **GATE** | Pilot: `#a2l_tags_list` cell styles (semantic `_severity_style(ERROR)` anchor) | BOTH duplicate-symbol rows red (case-fold `RPM`/`rpm`), control row non-red, issue list unchanged (exactly 1 dup ERROR) | **LIVE BUG RED** — pre-I2 verbatim capture, `03-increments/increment-2.md` §4a: both rows retained but NOT ERROR-styled while the ERROR issue existed | **PASSED** |
| US-033 | `recolor::test_at_037b_absent_from_table_issue_symbol_is_inert` | AT (boundary) | same | Issue symbol absent from the rendered tag set (natural `A2L_BROKEN_REFERENCE`) → no crash, no row change; positive assert that the shipped chain produced the issue | n/a (WARNING-no-recolour deliberately NOT an AT — unbuildable black-box, lives as the TC-037.2 Layer-A GUARD per A-M1/AM-3) | **PASSED** |
| US-034 | `before_after::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` | **GATE, C-10 + C-12** | Pilot: patch apply → save-back prompt → offer notify → `pilot.press("b")` → status line → disk | Q-M1 chain: reports-dir snapshot → dir-diff (exactly 1 md + 1 html new) → surfaced path `==` the new file → content asserts on a **re-read of THE SURFACED path** (`-` pre-patch / `+` after bytes at the patched address, linkage row, both path names); C-10 collision drive: header "after" pinned to literal `img-patched_1.s19` (typed name not a substring — Q-M2) | RED = absent deliverable, `03-increments/increment-4.md` §0: `5 failed, 5 passed` on the interruption-checkpoint tree (key bound, action missing → `new_files == []`, no surfaced refusal) — the specced trigger-absent counterfactual, preserved by the I4 interruption | **PASSED** |
| US-034 | `before_after::test_at_038b_declined_saveback_trigger_refuses_and_writes_nothing` | **GUARD-class** (Q-m1) | shipped decline button → trigger | Positive refusal diagnostic (`"no saved patched image"`) + 0 files by listing | part of the I4 §0 five-fail RED | **PASSED** |
| US-034 | `before_after::test_at_038c_missing_original_trigger_refuses_and_writes_nothing` | **GUARD-class** | real `unlink` of the original post-save → trigger | Positive diagnostic (`"img.s19"` + `"no longer on disk"`) + 0 files; app keeps running | part of the I4 §0 RED | **PASSED** |
| US-034 | `before_after::test_at_038d_stale_summary_cross_project_refusal_writes_nothing` | **GUARD-class, B-2** | state-level project switch (ratified idiom — F3 note, footnote §7) → trigger | Stale-summary refusal (`"stale"` + `"imgB.s19"`) + 0 files in project B's `reports/` — the cross-project false-provenance hole closed | part of the I4 §0 RED; the AT itself is blocker-born (AM-2) | **PASSED** |

GUARD accounting: **4 GUARD-class nodes batch-wide** — 3 Layer-B (AT-038b/c/d, each with a load-bearing positive-diagnostic assert so none passes vacuously) + 1 Layer-A (TC-037.2's WARNING-no-recolour over constructed issues). Gate asserts are fully black-box: rendered DataTable content/styles, handler-written disk artifacts re-read through the surfaced path, status-line text. TC-037.4 reads private members under a declared white-box header — never a gate (04-validation §3.1).

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 3 (US-032/033/034) — covered 3/3 (100%) |
| Total HLR | 3 (HLR-036/037/038) — implemented 3/3 (100%) |
| Total LLR | 12 (036.1–.3 · 037.1–.4 · 038.1–.5; 037.4 and the 038.2 provenance preconditions blocker-born at Phase 2) — implemented 12/12 (100%) |
| Acceptance tests (AT) | 9 ids / 10 nodes (AT-036c ×2), all PASSED — 3 GATE + 3 GUARD-class + 3 boundary/negative; 3 RED captures on file (2 live shipped bugs) |
| Functional test cases (TC) | 14 ids / 23 nodes (V-5 ×N expansions per 04-validation §1.1), all PASSED |
| Total new nodes | **33** (ledger 1004 → 1037, +33 / −0, per-increment chain 1015/1020/1027/1037 reconciled; net-0 rewrites: 1 in-place update + 3 surviving no-op monkeypatches) |
| Full non-slow suite | **1004 passed / 0 failed** at the I4 gate (no code changed since); Phase-4 independent re-runs: 26/26 + 45/45 + engine guard 1/1 |
| QC-3 boundary/negative catalogs | 3/3 complete — every row → node, 0 gaps (04-validation §3.2) |
| Bidirectional reachability matrix | 0 empty required cells; **1 soft cell honestly classified** (footnote §7) |
| Engine-frozen set | **0-diff ×5 gates** (I1–I4 + Phase-4 direct check); no existing issue code renamed (P-13 grep: 5/5 still present) |
| fail / pending | 0 / 0 |

---

## 3. Detected gaps

> **ZERO gaps, both chains.** Every LLR has ≥1 passing TC with its numeric threshold audited in-assert; every US has passing black-box AT(s) observing the outcome through the shipped surface with boundary + negative evidence; V-5 bound all 24 provisional ids onto the 33 collected nodes with 0 orphans.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | (none) | — |

**Tracked follow-ons (not gaps):** I4-F1 orphan-md-on-html-refusal hygiene (BACKLOG, theoretical branch) · 3 pre-existing ruff F401s (`change_service.py:38`, `tests/test_diff_report_service.py:67`, `tests/test_tui_app.py:1599` — flagged I2/I3, untouched per surgical rule) · optional `_strip_ctl` C1-range widening (LOW) · AT-037b single-shot inertness (spec-accepted limitation) · F3 re-derive trigger (footnote §7).

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-036 / US-032 | Red-row ⇒ ERROR-issue reconcile: supplemental `A2L_TAG_SCHEMA_INCOMPLETE` rule merged at the open `validation_service` seam (frozen `validation/` + `tui/a2l.py` untouched) |
| new | HLR-037 / US-033 | Issue ⇒ red-row reconcile: `_a2l_issue_severity_map` + ERROR-only row precedence + render-order fix; closes feature #12(c) both directions |
| new | LLR-037.4 | No-MAC sessions retain the validation report — **shipped-product fix born from Phase-2 BLOCKER B-1** (every S19+A2L-without-MAC session previously lost its issues) |
| new | HLR-038 / US-034 | Before/after report on save-back over the batch-09 compare/diff-report backbone; closes feature #12(a) |
| new | B-2 provenance | `ChangeSummary.source_image_path` runtime stamp + stale-summary/containment refusals + AT-038d — born from Phase-2 BLOCKER B-2 (security) |
| new | `R-A2L-ISSUE-RECONCILE-001/-002` · `R-BEFORE-AFTER-REPORT-001` | REQUIREMENTS.md §30 (`REQUIREMENTS.md:2919`) and §31 (`:2935`), all status `Automated` |
| deferred | US-035/036/037 (entropy trio, #12(b)) | Own spike batch (greenfield model + surface + geometry); queue head for #12 completion |
| mid-batch | I4 session-limit interruption | Absorbed at a clean RED checkpoint (the `5 failed, 5 passed` state WAS the specced counterfactual); split authorship credited in increment-4.md; cross-agent seam independently reviewed clean |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-032** → HLR-036 → LLR-036.1/.2/.3 (+ shared LLR-037.4) → TC-036.1–.4, TC-037.4×3 (functional) + AT-036a/b/c×2 (behavioral)
- **US-033** → HLR-037 → LLR-037.1/.2/.3 (+ shared LLR-037.4) → TC-037.1–.3 + net-0 ladder update (functional) + AT-037a/b (behavioral)
- **US-034** → HLR-038 → LLR-038.1–.5 → TC-038.1×2/.2/.3×3/.4×2/.5/.6 + 3 stamp TCs (functional) + AT-038a/b/c/d (behavioral)

### 5.2 By code file
- `s19_app/tui/services/validation_service.py` → LLR-036.1/.2 (`supplemental_a2l_row_issues` :20), LLR-036.3 (`build_validation_report` :111)
- `s19_app/tui/app.py` → LLR-037.1 (:224/:234), LLR-037.2 (:295 + map build :7730), LLR-037.3 (:7668), LLR-037.4 (:6000/:6053/:7403), LLR-038.3 (:684/:1710/:1639)
- `s19_app/tui/services/diff_report_service.py` → LLR-038.1 (:184/:226/:254/:396/:939/:1353)
- `s19_app/tui/services/before_after_service.py` (NEW) → LLR-038.2/.4/.5 (:72/:88/:182)
- `s19_app/tui/changes/model.py` + `s19_app/tui/services/change_service.py` → LLR-038.2 B-2 stamp (:464 / :933)

### 5.3 Boundary / safety nodes
- **AT-038a** is the **C-12 disk gate** — surfaced-path → dir-diff → re-read chain; the only test that goes RED on a silently-absent report or an unsurfaced/echoed path.
- **AT-038d + TC-038.4 class 4** are the **B-2 provenance safety nodes** — cross-project stale summary refused, 0 files.
- **TC-037.4 ×3** are the **B-1a retention nodes** — no-MAC report kept (worker cache-hit counted, sync compute-once counted), no-primary clear kept.
- **TC-038.1 golden** is the **byte-identical regression net** for every future diff-report change (double-proven at mint).
- **TC-038.6 + the ctl-pair TC** are the **S-F2 injection nodes** — pipe-bearing/ctl-bearing parsed symbols escaped in md, stripped identically in the html pair.

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-07-02-batch-24 |
| Closing date | 2026-07-02 |
| Iterations per phase (0–4) | 1 / **2** / 1 / 1 / 1 — the single re-iteration was the forced Phase-1 fold of all 18 Phase-2 findings (2 BLOCKER + 4 MAJOR + 12 minor) in one pass |
| Validation passed | **yes — PASS** per §5.3 batch acceptance criteria, **zero Phase-4 gaps** (04-validation.md §7) |
| Phase-2 findings | 18 — both BLOCKERs were real shipped-product defects caught by reading (B-1 no-MAC wipe, B-2 false provenance); both became normative requirements |
| Caught-at-P2 | 54.5% strict / **85.7%** excluding execute-to-discover items (05b §1.2 — the strict denominator is inflated by latitude notes and post-P2-born code; zero functional escapes reached P3/P4) |
| Code reviews | 4 independent — 0 HIGH / 0 MEDIUM / 10 LOW, all dispositioned |
| Control decision (Phase 5) | **4 encoded**: C-15.1 writer-census probe rule · state-lifetime provenance template question · interruption protocol (re-verify tree, checkpoint-at-RED) · golden double-proof at mint time. Batch-22 overclaim watch stays at 2 |
| Synced to Obsidian | pending post-merge (`/dev-flow-sync`) |

---

## 7. Footnotes — §6.5 amendments, F3 note, soft cell, REQUIREMENTS cross-reference

**§6.5 requirement amendments (01-requirements.md §6.5)** — all four recorded Before/After, Phase-4-verified present in code (04-validation §5.1):

- **AM-1 (BLOCKER B-1, operator option (a) fix-the-wipe):** NEW LLR-037.4 — `update_mac_view`'s no-MAC branches previously wiped `_validation_report`/`_validation_issues` in EVERY session without MAC records, making HLR-036's "cannot disagree" silently false there and the MAC-less ATs unobservable. Fix ships in I1; I1→I2 became a STRICT dependency; the MAC-less-fixture discipline is stated inside the ATs (adding a MAC to green them is forbidden — masking class).
- **AM-2 (BLOCKER B-2, security):** LLR-038.2 preconditions gained (4) `LoadedFile.path == summary.source_image_path` (NEW runtime-only field, off `to_dict`, byte-stability proven) and (5) current-project containment; LLR-038.4 gained refusal class 4 (stale summary); AT-038d added. Closed the cross-project false-provenance report hole that every then-specced AT would have passed over.
- **AM-3 (A-M1):** AT-037b split — absent-from-table symbol stays black-box (naturally producible via `A2L_BROKEN_REFERENCE`); WARNING-no-recolour moved to Layer-A TC-037.2 as a GUARD over constructed issues (unbuildable through the shipped chain; injection banned for ATs).
- **AM-4 (I4-F2, folded at I5):** HLR-038's C-10 sentence reconciled to the shipped drive — the pre-planted COLLISION (not a typed non-default name) is the non-default drive; discriminator (`img-patched_1.s19` header equality) unchanged.

**F3 traceability note (01-requirements, after §6.5):** AT-038d's "open project B" step is **state-level** (`current_project` assignment + the ratified `_load_image` drive), not the LoadProjectScreen path — valid because `last_summary` is never cleared on a real project switch in the shipped app. **Re-derive trigger:** if a future batch adds last-summary invalidation to the real project-switch path, re-derive this AT.

**The one soft matrix cell (04-validation §4):** "project.json untouched-by-batch" is covered **by-construction with supporting TC** (files-modified census names no project.json seam; `ChangeSummary.to_dict` byte-stability TC; full suite includes batch-20's round-trip ATs) — honestly classified, not test-observed. No requirement in §3/§4 names project.json.

**REQUIREMENTS.md cross-reference:** §30 "A2L red-row ↔ Issues reconcile (batch-24)" (`REQUIREMENTS.md:2919`) — `R-A2L-ISSUE-RECONCILE-001` (US-032 + LLR-037.4) and `-002` (US-033), both `Automated`. §31 "Before/after save-back report (batch-24)" (`:2935`) — `R-BEFORE-AFTER-REPORT-001`, `Automated`. *Known cosmetic drift, pre-existing class (I1-review F3): the REQUIREMENTS.md TOC numbers these entries 26/27 while the section headers are §30/§31.*
