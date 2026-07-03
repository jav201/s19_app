# 04 — Validation — 2026-07-02-batch-24

> **Verdict: PASS** (per §5.3 — detail in §7). Batch `2026-07-02-batch-24` · branch `claude/batch-24-feat12` · base `origin/main 9d2123c` · Phase-3 work uncommitted in the tree · ledger **1037** collected non-slow.
> Author: qa-reviewer (Phase 4, 2026-07-02). Every run below executed by this reviewer in this worktree unless explicitly cited as an orchestrator-gate run; every threshold claim verified by READING the assert, not by trusting the increment packets.

---

## 1. V-5 reconciliation — provisional id → real collected node

Collection run (this reviewer): `python -m pytest tests/test_validation_service_supplemental.py tests/test_tui_a2l_issue_recolor.py tests/test_before_after_report.py --collect-only -q` → **26 tests collected in 0.44s**. Plus the 7 new nodes in the 2 extended files (verified by `--collect-only` + reading the functions): 26 + 7 = **33 batch nodes**, matching the I5 census and the ledger arithmetic 1004 → 1037 (+33, −0).

### 1.1 Binding table

| Provisional id | Real node id | Layer |
|---|---|---|
| AT-036a (GATE) | `tests/test_validation_service_supplemental.py::test_at_036a_missing_schema_red_row_has_matching_error_issue` | B |
| AT-036b | `tests/test_validation_service_supplemental.py::test_at_036b_already_covered_symbol_gains_no_second_error` | B |
| AT-036c (×2: clean + empty) | `tests/test_validation_service_supplemental.py::test_at_036c_clean_a2l_yields_zero_supplemental_issues` · `::test_at_036c_empty_tag_set_yields_zero_supplemental_issues` | B |
| TC-036.1 | `tests/test_validation_service_supplemental.py::test_tc_036_1_one_error_per_schema_bad_tag_keyed_on_is_false` | A |
| TC-036.2 | `tests/test_validation_service_supplemental.py::test_tc_036_2_dedup_casefolded_symbol_a2l_error_only` | A |
| TC-036.3 | `tests/test_validation_service_supplemental.py::test_tc_036_3_merge_in_both_report_branches` | A |
| TC-036.4 | `tests/test_validation_service_supplemental.py::test_tc_036_4_nameless_schema_bad_tag_falls_back_to_context` | A |
| TC-037.1 | `tests/test_tui_a2l_issue_recolor.py::test_tc_037_1_issue_severity_map_build_and_filter_semantics` | A |
| TC-037.2 (incl. WARNING GUARD) | `tests/test_tui_a2l_issue_recolor.py::test_tc_037_2_row_severity_precedence_matrix_and_warning_guard` | A (GUARD) |
| TC-037.3 | `tests/test_tui_a2l_issue_recolor.py::test_tc_037_3_sync_fallback_first_render_is_fresh` | A |
| TC-037.4 (×3) | `tests/test_validation_service_supplemental.py::test_tc_037_4_worker_path_retains_report_without_mac` · `::test_tc_037_4_sync_path_computes_once_and_caches` · `::test_tc_037_4_no_primary_session_keeps_the_clear` | A |
| AT-037a (GATE) | `tests/test_tui_a2l_issue_recolor.py::test_at_037a_duplicate_symbol_error_issue_reds_both_rows` | B |
| AT-037b | `tests/test_tui_a2l_issue_recolor.py::test_at_037b_absent_from_table_issue_symbol_is_inert` | B |
| AT-038a (GATE, C-10+C-12) | `tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` | B |
| AT-038b (GUARD-class) | `tests/test_before_after_report.py::test_at_038b_declined_saveback_trigger_refuses_and_writes_nothing` | B |
| AT-038c (GUARD-class) | `tests/test_before_after_report.py::test_at_038c_missing_original_trigger_refuses_and_writes_nothing` | B |
| AT-038d (GUARD-class, B-2) | `tests/test_before_after_report.py::test_at_038d_stale_summary_cross_project_refusal_writes_nothing` | B |
| TC-038.1 (kwargs render + byte-identical) | `tests/test_diff_report_service.py::test_provenance_and_linkage_render_in_both_formats` · `::test_default_kwargs_output_byte_identical_pre_change_golden` | A |
| TC-038.2 | `tests/test_diff_report_service.py::test_zero_entries_linkage_states_no_entries` | A |
| TC-038.3 (×3: happy/regex + symlink + ctl-pair) | `tests/test_before_after_report.py::test_tc_038_3_composer_happy_path_and_regex_ownership` · `::test_tc_038_3_symlink_reports_destination_refused` · `::test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair` | A |
| TC-038.4 (×2: 4 classes + no-project D-3) | `tests/test_before_after_report.py::test_tc_038_4_all_refusal_classes_write_no_files` · `::test_tc_038_4_no_project_refusal_names_manual_ab_path` | A |
| TC-038.5 (inspection, automated) | `tests/test_before_after_report.py::test_tc_038_5_module_imports_no_textual_and_no_logging` | A |
| TC-038.6 | `tests/test_diff_report_service.py::test_pipe_bearing_symbol_md_escaped_html_intact` | A |
| B-2 stamp TCs (LLR-038.2, un-numbered in §5.2 "stamp TC") | `tests/test_change_service.py::test_save_patched_stamps_source_image_path` · `::test_save_patched_without_kwarg_leaves_source_image_path_none` · `::test_to_dict_excludes_source_image_path_and_stays_byte_stable` | A |
| (net-0 rewrite, LLR-037.2 unit set) | `tests/test_tui_app.py::test_a2l_tag_row_severity_matches_updated_policy` (updated in place, I2) | A |

Every provisional id from §3/§5.2/01b binds to ≥1 real collected node; no orphan nodes among the 33 (the 26 + 7 partition matches the table exactly).

### 1.2 RED-capture evidence locations (against the reconciled nodes)

| Reconciled node | RED evidence | What the RED showed |
|---|---|---|
| `test_at_036a_missing_schema_red_row_has_matching_error_issue` | `03-increments/increment-1.md` §4a (verbatim pytest output) | Pre-fix: observable 1 (red rows) PASSED, observable 2 FAILED with `Rendered issue rows: []` — the live HLR-036 divergence, both B-1a causes visible |
| `test_at_037a_duplicate_symbol_error_issue_reds_both_rows` | `03-increments/increment-2.md` §4a (verbatim pytest output) | Pre-I2: both duplicate rows retained but NOT ERROR-styled while the `A2L_DUPLICATE_SYMBOL` ERROR existed — the live HLR-037 divergence |
| `test_at_038a…` + `test_at_038b…` + `test_at_038c…` + `test_at_038d…` + `test_tc_038_3_ctl_symbol…` | `03-increments/increment-4.md` §0 (verbatim `5 failed, 5 passed` tail) | Trigger absent (key bound, action missing) → no file, no surfaced refusal — the absent deliverable IS the RED (C-10 family); ctl-RED = the HTML-only `\x01` leak, pinpointed before fixing |

All three captures were taken on pre-fix trees BEFORE the corresponding product edits (lazy imports made pre-fix collection possible — verified in the test files' module docstrings and confirmed credible by the I1/I4 independent reviewers).

---

## 2. Layer A — LLR coverage, executed runs, threshold verification

### 2.1 Executed runs (this reviewer, this worktree)

Three new files, `-v` (verbatim tail):

```
tests/test_before_after_report.py::test_tc_038_4_all_refusal_classes_write_no_files PASSED [ 92%]
tests/test_before_after_report.py::test_tc_038_4_no_project_refusal_names_manual_ab_path PASSED [ 96%]
tests/test_before_after_report.py::test_tc_038_5_module_imports_no_textual_and_no_logging PASSED [100%]

============================= 26 passed in 15.65s =============================
```

(All 26 nodes PASSED — full `-v` listing observed; 11 supplemental + 5 recolor + 10 before-after.)

Two extended files (verbatim tail):

```
.............................................                            [100%]
45 passed in 0.74s
```

(45 = 38 pre-existing diff-report + 4 new, plus change-service incl. the 3 new stamp TCs.)

Engine-frozen guard (targeted): `pytest tests/test_engine_unchanged.py -q` → `1 passed in 0.13s`. Frozen-set diff vs `main` (`git diff main --name-only` over the 7 frozen paths) → **empty, 0-diff**.

### 2.2 LLR → covering node → threshold-as-read (ALL 12 asserts read by this reviewer, none taken on the increment docs' word)

| LLR | Covering node(s) | Threshold genuinely asserted? (what the assert literally does) | Result |
|---|---|---|---|
| LLR-036.1 | TC-036.1, TC-036.4, AT-036a | ✓ `assert [issue.symbol …] == ["BAD1", "BAD2"]` — exactly N issues for N `schema_ok is False` tags; `GOOD`/`RAW_NO_KEY`/`NONE_KEY` gain nothing (the A-M2 `is False` keying is directly exercised); code/severity/artifact/symbol-in-message/reason-in-message each asserted; constructor scrub proven by `"\x1b" not in message` (test file :331-364) | PASS |
| LLR-036.2 | TC-036.2, AT-036b | ✓ covered symbol (`Bad_Tag` vs `BAD_TAG`, casefold) → `== []`; WARNING / non-a2l / symbol-less `A2L_STRUCTURE_ERROR` each asserted NON-suppressing (`len == 1`) (:390-406); AT-036b asserts `len(dup_errors) == 1` on the RENDERED Issues table with code `A2L_DUPLICATE_SYMBOL` and 0 supplemental for that symbol (:266-274) | PASS |
| LLR-036.3 | TC-036.3, AT-036c×2 | ✓ supplemental code present in returned issues for BOTH `primary_file=None` and primary-backed invocations; empty tag list → absent in both branches (:426-466) — exactly the numeric pass threshold ("present in both … 0 failures") | PASS |
| LLR-037.1 | TC-037.1 | ✓ exact dict equality: non-a2l + symbol-less + empty-string-symbol filtered, keys casefolded, ERROR-max wins over later WARNING; order-independence re-asserted reversed; `_a2l_issue_severity_map([]) == {}` (:281-296) | PASS |
| LLR-037.2 | TC-037.2, AT-037a, updated ladder unit set | ✓ full precedence matrix: empty-map ladder ×5 byte-identical, ERROR-map ×5 all → ERROR (incl. the green memory-checked candidate), WARNING-map ×5 unchanged (the D-2 GUARD), unmapped ×5 unchanged, nameless-tag never consults (:325-356) — the exact "ERROR×{4 states} / WARNING×same" matrix from the numeric threshold | PASS |
| LLR-037.3 | TC-037.3 (+ I1 TC-037.4 idempotence unbroken) | ✓ sync-fallback drive (`_apply_loaded_file`, no worker precompute); duplicate rows asserted ERROR-styled on the rendered table with NO manual re-render — a stale first frame would persist and fail (:368-393) | PASS |
| LLR-037.4 | TC-037.4 ×3, AT-036a Issues observable (gating per HLR-036 Acceptance) | ✓ worker path: issues non-empty post-load, then `calls["n"] == 0` on re-render (cache-hit no-op — the "never wipe-then-recompute" clause counted, not assumed) with key + issues identity re-asserted; sync path: `calls["n"] == 1` exactly, repeat render still 1; no-primary: sentinel wiped, `_validation_issues == []` + report `None` (:505-598) | PASS |
| LLR-038.1 | TC-038.1 ×2, TC-038.2, TC-038.6 | ✓ golden: `read_bytes() ==` the pre-change capture (version-templated, `os.linesep`-expanded — true byte identity both platforms), new headings absent from default output, default filenames pinned (diff-report test :731-775); kwargs case: every provenance field + all 3 entries + all dispositions + `(none - created into hole)` marker with real after-bytes, exact md row literals, html script/CDN-free (:778-857); 0-entries: heading + `No entries.` + NO table header (:860-883); S-F2: `EVIL\|SYM<b>END` escaped literal, `\x01` absent, **10 unescaped structural pipes counted** (9-cell row intact), html `_esc` form (:886-923) | PASS |
| LLR-038.2 | TC-038.3 ×3, stamp TCs ×3, TC-038.4 | ✓ happy path: pair under `<project>/reports/`, own regexes match AND diff-report/shared regexes DON'T (ownership both directions); symlink `reports/` → refused + `list(elsewhere.iterdir()) == []`; ctl-pair md/html identical-stripped; stamp: `summary.source_image_path == original` beside `saved_path`, `None` when omitted, `to_dict` JSON byte-equal before/after stamping + key absent | PASS |
| LLR-038.3 | AT-038a (offer + trigger asserts inside) | ✓ offer notify severity `"information"`, message names `before_after_report` + `"press b"`; trigger = real `pilot.press("b")` through the shipped binding; surfaced-path chain per Q-M1 (§3) | PASS |
| LLR-038.4 | TC-038.4 ×2, AT-038b/c/d | ✓ all 4 classes + both class-3 arms + both class-4 arms (provenance mismatch AND out-of-project containment): `not result.written`, `md_path is None and html_path is None`, POSITIVE needle in diagnostics per class, `reports/` listing `== set()` per class; no-project: `"a<->b"` + `"no active project"` needles + `rglob == []` — 0 files across all classes is asserted by directory listing, exactly the threshold | PASS |
| LLR-038.5 | TC-038.5 + AT-038a S-F5 sweep + reviewer inspection | ✓ automated: `inspect.getsource` — no `import textual`/`from textual`/`import logging`/`getLogger`; `REPORTS_DIR_NAME` construction asserted (S-F3: construction, not gitignoredness); AT-038a sweeps every captured notify/status message for the entry bytes `"AA BB"`; **reviewer inspection executed**: read `app.py::action_before_after_report` (:1710-1758) — surfaced text is `"Before/after report written: <md> | <html>"` or `"refused: <diagnostics>"`, paths/diagnostics only, no logging call, no byte content | PASS |

**Threshold spot-check verdict:** all 12 LLR thresholds are genuinely asserted (counted, equality-compared, or needle-positive) — no vacuous assert found. Two disagreements with lazy readings were checked and resolved: (a) TC-037.4's cache-hit claim is enforced by an actual call-counter monkeypatch, not by state inspection alone; (b) the golden test compares raw `read_bytes()`, not normalized text.

---

## 3. Layer B — AT-per-story vs the QC-3 catalogs

### 3.1 Gates are black-box; GUARD marks honored

- **AT-036a/b/c, AT-037a/b** observe ONLY rendered `#a2l_tags_list` / `#validation_issues_list` DataTable content and Rich cell styles via the semantic `_severity_style(ERROR)` anchor (no raw `"red"` literal — QR-1 honored); issues PRODUCED through the shipped load chain (`_parse_loaded_file` → `_prepare_load_payload` → `_apply_prepared_load`), never injected. Fixtures MAC-less per the HLR-036/037 discipline (B-1a — verified in the fixture texts: no MAC anywhere in either file).
- **AT-038a** is the C-12 gate: reports-dir snapshot BEFORE → `pilot.press("b")` → dir-diff (exactly 1 md + 1 html new) → surfaced status path `==` the dir-diff file → content asserts on a **re-read of THE SURFACED path** (Q-M1 chain literal in the test, :223-289). `last_summary.saved_path` appears ONLY inside failure-message diagnostics (:221, :242) — the Q-M2 demotion honored. C-10 collision drive real: `img-patched.s19` pre-planted, header "after" asserted `== "img-patched_1.s19"` (typed name is not a substring — discriminates an echo).
- **AT-038b/c/d GUARD-class marks honored:** each carries the load-bearing POSITIVE surfaced-refusal assert (`"no saved patched image"` / `"img.s19" + "no longer on disk"` / `"stale" + "imgB.s19"`) before the 0-file listing — none can pass vacuously. **TC-037.2-WARNING GUARD honored:** constructed-issue Layer-A only, never claimed as an AT (A-M1).
- TC-037.4 reads private members (`_validation_issues`, `_mac_view_cache_key`) — declared white-box scope in its section header; not a gate. No gate reads internals as an expected operand.

### 3.2 QC-3 boundary-catalog mapping (every row → node or explicit gap)

**HLR-036 catalog:**

| Catalog row | Covering node | Note |
|---|---|---|
| empty — zero-tag A2L → no new issues | `test_at_036c_empty_tag_set_yields_zero_supplemental_issues` | rendered table `row_count == 0` + 0 supplemental on Issues surface |
| boundary — virtual/no-address exempt | `test_at_036a…` (VIRT_CHAR non-red + no supplemental) AND `test_at_036c_clean…` (VIRTUAL TORQUE non-red, 0 supplemental) | catalog credited AT-036c; the sharper per-symbol assert actually lives in AT-036a — covered in both, noted for precision, no gap |
| invalid — missing-address non-virtual; nameless → symbol=None fallback | `test_at_036a…` (BROKEN_CHAR + the missing-length arm NOLEN_CHAR) · `test_tc_036_4…` (symbol None, `0x30` in message, `unnamed` fallback) | |
| error/already-covered — duplicate symbol, no double-report | `test_at_036b…` (`len == 1`, code = existing `A2L_DUPLICATE_SYMBOL`) | |

**HLR-037 catalog:**

| Catalog row | Covering node | Note |
|---|---|---|
| empty — no issues → existing behavior | `test_tc_037_2…` (empty-map ladder ×5 byte-identical) | |
| boundary — WARNING-only symbol → unchanged | `test_tc_037_2…` WARNING-map block | Layer-A GUARD per A-M1/D-2, as specced |
| invalid — issue symbol absent from table → inert | `test_at_037b…` (natural `A2L_BROKEN_REFERENCE`/GHOST_TAG; positive assert that the shipped chain really produced the issue) | I2-review LOW: single-shot "double-inertness" is a spec-accepted limitation, recorded |
| error — ERROR symbol × green candidate → red wins | `test_tc_037_2…` (ERROR-map × memory-checked-present OK row) + `test_at_037a…` (schema-complete valid-address duplicates red through the shipped chain, TORQUE control non-red) | |

**HLR-038 catalog:**

| Catalog row | Covering node | Note |
|---|---|---|
| empty — 0 applied entries → report written, "no entries" | `test_zero_entries_linkage_states_no_entries` | |
| boundary — collision → dedup-suffixed "after" identity | `test_at_038a…` (pinned literal `img-patched_1.s19`) | |
| invalid — no summary / `saved_path` None | `test_tc_038_4_all_refusal_classes…` classes 1-2 + `test_at_038b…` (shipped decline button) | |
| error — original missing post-save | class 3 both arms (TC-038.4) + `test_at_038c…` (shipped chain, real `unlink`) | |
| stale summary (B-2, preconditions 4-5) | class 4 both arms (TC-038.4) + `test_at_038d…` (shipped-state project switch; F3 traceability note recorded §5) | |
| no active project → refusal naming manual A↔B | `test_tc_038_4_no_project_refusal_names_manual_ab_path` | |

**No catalog row is uncovered. Zero gaps in Layer B.** Deliverable observations confirmed: rendered rows/styles (036/037), surfaced-path → dir-diff → re-read chain (038a), refusal 0-file listings with positive diagnostics (038b/c/d + TC-038.4).

---

## 4. Bidirectional surface-reachability matrix

Inputs exercised through the shipped surface (handler/load chain/Pilot), outputs observed through the shipped surface (rendered widgets / disk / status line):

| Input ↓ \ Output → | A2L row styles | Issues rows | Report file pair | Surfaced paths | Refusal diagnostics | Byte-identical default reports | project.json untouched |
|---|---|---|---|---|---|---|---|
| Defect fixture: missing-address/length A2L | AT-036a (red both arms) | AT-036a (2 named ERRORs) | n/a | n/a | n/a | n/a | — |
| Duplicate symbol + case-fold variant (`RPM`/`rpm`) | AT-037a (both red, control non-red); AT-036b (schema-bad dups red) | AT-037a (exactly 1 dup ERROR, list unchanged); AT-036b (dedup, 1 ERROR) | n/a | n/a | n/a | n/a | — |
| Nameless / BLANK tag (symbol N/A) | TC-037.2 nameless (never consults map) | TC-036.4 (symbol=None, address/`unnamed` fallback) | n/a | n/a | n/a | n/a | — |
| Clean / zero-tag A2L (negatives) | AT-036c (non-red) | AT-036c ×2 (0 supplemental) | n/a | n/a | n/a | n/a | — |
| Broken-reference (absent-from-table symbol) | AT-037b (no recolour) | AT-037b (positive: WARNING issue present) | n/a | n/a | n/a | n/a | — |
| No-MAC session (every US-032/033 fixture) | AT-036a/037a first-render fresh (TC-037.3) | retained, not wiped (TC-037.4 worker/sync); no-primary keeps clear (TC-037.4) | n/a | n/a | n/a | n/a | — |
| Patch apply + save-back + collision drive | n/a | n/a | AT-038a (dir-diff: exactly md+html; dedup "after" identity; -/+ bytes; linkage row) | AT-038a (status path == dir-diff file, re-read gate) | n/a | n/a | — |
| Refusal state ×4 (no summary / declined / missing source ×2 / stale ×2) | n/a | n/a | 0 files by listing (TC-038.4 per class; AT-038b/c/d) | n/a | AT-038b/c/d + TC-038.4 (positive needle per class) | n/a | — |
| No-project session | n/a | n/a | 0 files (`rglob == []`) | n/a | TC-038.4 no-project (names manual A↔B) | n/a | — |
| Default (kwargs omitted) diff-report invocation | n/a | n/a | n/a | n/a | n/a | TC-038.1 golden (`read_bytes()` equality, both formats, both platforms) | — |
| Change-doc serialization (`to_dict`) | — | — | — | — | — | — | ✓ by construction + stamp TC-3: batch touches no project.json read/write site (files-modified census I1-I4: `validation_service.py`, `app.py`, `diff_report_service.py`, `changes/model.py`, `change_service.py`, `before_after_service.py` + tests + REQUIREMENTS.md — none is the workspace project.json seam); the nearest serialization surface, `ChangeSummary.to_dict`, is proven byte-stable (`test_to_dict_excludes_source_image_path_and_stays_byte_stable`) |

**Explicit gap accounting:** the "project.json untouched-by-batch" cell is covered by census-plus-adjacent-TC rather than a dedicated node — classified honestly as *by-construction with supporting TC*, not test-observed. Acceptable: no requirement in §3/§4 names project.json, and the full-suite gate (which includes the batch-20 project.json round-trip ATs, e.g. AT-028a) ran 0-fail at I4. All other cells are direct node observations. No empty required cell.

---

## 5. Deviations / amendments record

### 5.1 §6.5 amendments — all recorded, each verified present in the artifact

| Amendment | Recorded? | Verified against code |
|---|---|---|
| AM-1 (B-1a → LLR-037.4 + Acceptance gating) | ✓ §6.5 full Before/After/Deleted/New | `_refresh_no_mac_validation` + `_mac_view_cache_key_for` on disk; TC-037.4 ×3 green; MAC-less fixtures confirmed in both AT files |
| AM-2 (B-2 → preconditions 4-5, stamp, AT-038d) | ✓ §6.5 | `source_image_path` field off `to_dict` (byte-stable TC); composer class-4 refusals; AT-038d green |
| AM-3 (A-M1 → AT-037b split) | ✓ §6.5 | AT-037b = absent-symbol only; WARNING GUARD lives in TC-037.2 — exactly as amended |
| AM-4 (I5/F2 → C-10 wording reconciled) | ✓ §6.5 | AT-038a's drive matches the amended wording: suggested name confirmed against a pre-planted collision; discriminator `img-patched_1.s19` unchanged |

### 5.2 Increment D-notes / findings — dispositions confirmed

| Item | Disposition | Confirmed |
|---|---|---|
| I1 D-note-1 (worker key routed through `_mac_view_cache_key_for` — extra edit site, within LLR latitude) | Flagged in packet §10; audited sound by the I1 independent review (no false-cache-hit path) | ✓ — TC-037.4 worker-path counter (0 rebuilds) is the behavioral proof |
| I2 D-note-1 (F1 `or []` citation `:153` → real site `:80`) | Fixed the one real occurrence; mismatch flagged for the gate | ✓ recorded |
| I2 D-note-2 (sibling test file, helper duplication — tests/ not a package) | Recorded; attributed in module docstring | ✓ read in the file header |
| I2 D-note-3 (map consult before `schema_ok` — order-invariant) | Recorded; TC-037.2 schema-bad × ERROR row pins no-flicker | ✓ assert read |
| I4 F1 (orphan-md-on-html-refusal hygiene) | BACKLOG carry (I5 §1) — theoretical branch | ✓ recorded |
| I4 F2 (HLR-038 "NON-DEFAULT" wording) | → AM-4, folded at I5 | ✓ |
| I4 F3 (AT-038d state-level switch, not LoadProjectScreen) | → traceability note in 01-requirements (after §6.5); re-derive trigger named | ✓ recorded; noted here for Phase-6 |
| I4 §2 (5th file `diff_report_service.py` beyond the roadmap's 4) | Flagged in packet; gate-addendum-instructed (`_strip_ctl`), within ≤5 cap | ✓ recorded |

### 5.3 No other unrecorded spec-vs-code drift (reviewer spot-checks beyond the increment docs)

- **Issue-code contract:** `A2L_TAG_SCHEMA_INCOMPLETE` emitted ONLY from `s19_app/tui/services/validation_service.py` (QR-8 honored — not from frozen `rules.py`); all 5 P-13 codes still present in `validation/rules.py` (grep: 5 hits), none renamed.
- **Trigger surface as specced:** `Binding("b", "before_after_report", …)` at `app.py:684`; `action_before_after_report` at `app.py:1710` — the P-6 provisional key held, no re-choice to record.
- **Frozen set:** `git diff main` over the 7 frozen paths → empty; `test_engine_unchanged.py` → 1 passed (my run).
- **Threshold re-reads beyond the first pass:** (1) LLR-036.1's "exactly N pre-dedup" — TC-036.1 asserts list-equality on symbols, not `>=`; (2) LLR-037.4's "exactly 1 on sync-fallback" — a counted `calls["n"] == 1` with a repeat-render re-check; (3) LLR-038.4's "0 files across all four classes" — per-class `_report_names(...) == set()`, not a single end-state check. All three match spec exactly. **No unrecorded drift found.**

---

## 6. Regression evidence

- **Full non-slow suite — orchestrator I4 gate run (cited, NOT re-run per Phase-4 instruction): 1004 passed / 0 failed**, ledger **1037** collected (`1037/1058, 21 deselected`) ✓ reconciled 1004 = 971 base-passed + 33 batch nodes; increment-5.md §4 confirms no code change since that run, and this reviewer's targeted runs (26 + 45 + 1 nodes, §2.1) all pass on the same tree.
- **Ledger chain:** 1004 → 1015 (I1, +11) → 1020 (I2, +5) → 1027 (I3, +7) → 1037 (I4, +10); +33 total, 0 removed; net-0 rewrites: 1 in-place update (`test_a2l_tag_row_severity_matches_updated_policy`) + the 3 no-op `update_mac_view` monkeypatches surviving unchanged (B-1a census held).
- **Golden double-proven at I3:** the byte-identical capture was independently RE-DERIVED by the I3 reviewer from a detached worktree @origin/main (2437B md / 2386B html byte-match), then held again after the I4 `_strip_ctl` factoring (my §2.1 run includes it green).
- **Engine-frozen guards:** green at every increment gate + this reviewer's targeted run + direct 0-diff check (§5.3).
- **§5.3 batch acceptance criteria:** 100% LLRs covered ≥1 passing TC ✓ (§2.2) · every US ≥1 passing AT through the shipped surface with boundary+negative ✓ (§3) · AT-038a target = handler-written file re-read ✓ · 0 new failures ✓ · byte-identical regression ✓ · no renamed issue code ✓.

---

## 7. Verdict — **PASS**

All three stories meet §5.3: every LLR has ≥1 passing white-box TC with its numeric threshold genuinely asserted (all 12 read); every story has passing black-box AT(s) observing the deliverable through the shipped surface with captured pre-fix RED counterfactuals (3 captures, locations §1.2); every QC-3 catalog row maps to a node (§3.2); no blocker condition triggered (no story without a black-box deliverable observation; no unfilled template — this artifact and all five increment packets are fully populated; no catalog row without a node).

**Non-blocking carries for Phase 5/6:** I4-F1 orphan-md hygiene (BACKLOG) · pre-existing ruff F401 pair (`change_service.py:38`, `test_diff_report_service.py:67`) + `test_tui_app.py:1599` F401 (flagged I2/I3, untouched per surgical rule) · optional C1-range `_strip_ctl` widening (LOW) · AT-037b single-shot inertness limitation (spec-accepted, recorded) · F3 re-derive trigger if a future batch invalidates `last_summary` on real project switch.

### QA evidence checklist

- [✓] Acceptance criteria use Given/When/Then — every AT in 01b states fixture/drive/observables; carried into the shipped tests (docstrings cite intent + threshold; e.g. `test_at_038a` docstring).
- [✓] Test cases have explicit Expected — byte literals (`00 00`→`AA BB`), exact filenames (`20260702T120000Z-before-after-report.md`), pinned dedup literal, exact issue codes (§2.2 column 3).
- [✓] Edge cases include empty, boundary, invalid, error — §3.2: all three QC-3 catalogs fully mapped (empty A2L, virtual-exempt, nameless, case-fold, collision, 4 refusal classes, no-project).
- [✓] Regression checklist exists — §6: golden byte-identical, issue-code grep-guard, frozen-set 0-diff, net-0 rewrite census, full-suite 1004/0.
- [✓] Exit criteria stated — §5.3 of 01-requirements, discharged item-by-item in §6.
- [✓] No real PII / secrets — synthetic RPM/TORQUE/BROKEN_CHAR/GHOST_TAG/EVIL|SYM fixtures only; reports land under gitignored `.s19tool/` default layout (S-F3 construction asserted).
- [✓] Test results are REAL — §2.1 runs executed by this reviewer (26/26, 45/45, 1/1 verbatim tails); full-suite figure cited to the orchestrator I4 gate run, explicitly not re-run.
- [✓] Layer B black-box — 3 GATE ATs observe rendered tables / handler-written disk artifacts through Pilot; C-12 chain literal in AT-038a; GUARD marks honored (§3.1).
- [✓] Bidirectional surface-reachability — §4 matrix: every named input dimension and every named output/deliverable exercised/observed through the handler; one cell honestly classified by-construction (project.json), justified.
- [✓] No unfilled template — no `<...>` placeholders, no unbound provisional ids (all 24 provisional ids bound in §1.1), no empty required rows.
