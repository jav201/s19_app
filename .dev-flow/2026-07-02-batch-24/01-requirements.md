# 01 — Requirements — 2026-07-02-batch-24

> **Batch objective:** Feature #12 — (a) before/after report · (b) entropy/data-classification viewer · (c) A2L-colour ↔ issues reconcile. Phase 0 = decomposition (architect consult, read-only, every claim cited) → operator slice selection at the DoR gate.
>
> Language: **en** · Flow: `/dev-flow` · Branch: `claude/batch-24-feat12` off `origin/main 9d2123c` (RC-1 PASS).

---

## 2.5 Context (architect Phase-0 consult — key verified seams, file:line cited)

- **Before/after bytes already captured per applied entry:** `ChangeSummaryEntry.before_bytes/after_bytes` (`s19_app/tui/changes/model.py:365-372`), read from the mem_map immediately pre-mutation (`tui/changes/apply.py:329-347`), stored as `ChangeService.last_summary` (`change_service.py:849-858`), already rendered in the project report's modifications table (`report_service.py:641-690`).
- **Whole-file "before" exists only on disk** — apply mutates `LoadedFile.mem_map` in place (`change_service.py:811-813`); `save_patched` verify-on-saves and stamps `saved_path` (`change_service.py:921-936`).
- **(a)'s backbone already shipped:** `compare_service.compare_images` parses two sources FRESH from disk (`compare_service.py:4-16`); `diff_report_service` writes complete Markdown + self-contained-HTML diff reports with per-run hex windows and ```diff blocks into `<project>/reports/` (`diff_report_service.py:8-30, 43-64`). Missing for (a): a one-action trigger, the change-entry linkage table, a before/after header. **Flagged unknown: can `save_patched_image` clobber the original source file?** (micro-spike).
- **(c) divergence CONFIRMED in both directions:** (1) red row with NO issue — `_a2l_tag_row_severity` reds any `schema_ok=False` tag (`app.py:223-232`; frozen `tui/a2l.py:1290-1291` sets it for missing address/length) while `validate_a2l_structure` emits `A2L_INVALID_ADDRESS` only for non-int-but-present addresses (`validation/rules.py:460-469`) → a missing-address tag is red with zero issues, TODAY. (2) ERROR issue with NO red row — `A2L_DUPLICATE_SYMBOL` is ERROR (`rules.py:470-480`) but row severity never consults issues → duplicate-symbol rows render normal, arguably violating REQUIREMENTS.md:364. Fix locality: the open merge point `validation_service.py:76-91` + `app.py` row severity; frozen modules untouched.
- **(b) substrate:** `LoadedFile.mem_map + ranges` (`models.py:44-46`) suffices; entropy computation must live TUI-side (new `tui/services/entropy_service.py` — engine-frozen constraint); surface candidates = modal / rail screen / report-section-first (zero geometry).

## 2.6 Story intake & refinement (Phase 0)

### Decomposition (6 stories; (a)/(b)/(c) mutually independent)

**US-032 — Red-row-implies-issue (c, direction 1) — `READY`**
> As an operator triaging an A2L, every red row in the A2L table has a corresponding ERROR `ValidationIssue` in the Issues view and report, so the two surfaces cannot disagree.
- INVEST: independent ✓ small (1–2 inc) ✓ testable ✓ — **AC:** load an A2L with a non-virtual characteristic missing its address → row renders red AND the Issues table + issues report carry an ERROR naming that symbol (shown failing pre-fix). Divergence proven at intake (no spike needed).
- Seam: supplemental TUI-side rule merged at `validation_service.py:83-91` (e.g. `A2L_TAG_SCHEMA_INCOMPLETE`), frozen modules untouched.

**US-033 — Issue-implies-row-colour (c, direction 2) — `READY`**
> As an operator, a tag whose symbol carries an ERROR-severity A2L issue (e.g. duplicate symbol) renders red, honoring REQUIREMENTS.md:364.
- INVEST: independent ✓ small (1 inc) ✓ testable ✓ — **AC:** A2L with a duplicated symbol → both rows red; issue list unchanged. Risk: touches the `app.py` render path (two functions; per-row lookup trivial).

**US-034 — Before/after report on save-back (a) — `READY` (with a micro-spike inside Phase 1)**
> As an operator who applied a change document and saved the patched image, one action produces a report proving what changed between the ORIGINAL file and the SAVED patched file.
- INVEST: independent ✓ medium (2–3 inc) ✓ testable ✓ — **AC (C-12):** apply doc → save-back → trigger → a report file exists under `reports/` whose diff block shows pre-patch bytes as `-` and the entry's `after_bytes` as `+` at the patched address, observed by re-reading the WRITTEN report; plus the change-entry linkage table.
- Reuse: `compare_images(original_path, saved_path)` + `generate_diff_report(_html)` + `last_summary`. New write surface inherits diff-report containment/no-clobber discipline. **Micro-spike: verify save-back cannot clobber the original (hour-scale, Phase-1 draft-time).**

**US-035 — Entropy/classification service, headless (b-1) — `SPIKE`**
> A service computes per-window Shannon entropy over the loaded image's ranges and classifies windows into bands (constant/padding · low · medium · high/random-encrypted).
- Greenfield model; spike needed: window size, estimator, band thresholds; ambition question (bands-only vs semantic code/data classification — heuristic accuracy risk). New `tui/services/entropy_service.py`, no UI. Prerequisite for US-036/037.

**US-036 — Entropy viewer surface (b-2) — `SPIKE`**
> An operator can open an entropy view of the loaded image (strip per window, colour by band, jump-to-address).
- HIGH geometry risk (C-13 measurement mandatory); surface choice spike (modal / rail screen / `/prototype` per the BACKLOG UI-focus note). Depends on US-035.

**US-037 — Entropy section in the project report (b-3) — `READY`-dependent (blocked by US-035)**
> The project report gains an entropy/classification section per variant.
- Cheap (1 inc), zero geometry, reuses report budgets. Depends on US-035.

### DoR decisions (RESOLVED at gate, 2026-07-02 — operator)

- **Slice = US-032 + US-033 + US-034** (architect's recommendation confirmed). **US-035/036/037 deferred** to their own batch with a measurement/algorithm spike (BACKLOG at close).
- **US-034 report flavor = diff-report + patch header/linkage table:** reuse the proven diff-report format (Markdown + self-contained HTML, hex windows, ```diff blocks) with a before/after header + the change-entry linkage table (address → entry → disposition) appended; own filename scheme (the diff-report owns-its-own-regex precedent).
- **US-034 trigger = offer after save-back:** after a successful save-back the app offers/generates the report in-flow (notify/keybinding — C-13 N/A, no new button row); the manual compare path remains.
- **Micro-spike RESOLVED (2026-07-02):** save-back CANNOT clobber the original — `save_patched_image` dedup-suffixes name collisions (`tui/changes/apply.py:574` contract, F-S-01 sanitizer). Consequence: the report's "after" side is `last_summary.saved_path` (the actual post-dedup written path, already stamped `change_service.py:921-922`); the "before" side (`LoadedFile.path`) is structurally safe.

### Out of scope (this batch, regardless of slice)

- Any edit to the engine-frozen set (the (c) reconcile lives at the open merge point; `color_policy` read-only).
- Semantic code/data classification claims beyond entropy bands (if (b) enters, ambition is decided first).
- Report retention/rotation policy changes (existing budgets/locations inherited).

---

## 2.7 Draft-time probe ledger (Phase 1, 2026-07-02 — probe self-test + C-15)

All probes executed against this worktree (branch `claude/batch-24-feat12` @ `origin/main 9d2123c`). Regime: repo root, `grep -r` over `s19_app/` + `tests/`; Python probes via `python -c` importing the installed editable package (runtime identity, not `hasattr`).

| # | Probe (executed) | Result (pre-state) | Consequence |
|---|------------------|--------------------|-------------|
| P-1 | `python -c` import `ValidationSeverity`; enumerate members | `ERROR=error, WARNING=warning, INFO=info, OK=ok, NEUTRAL=neutral` — runtime-verified | Severity identities cited in §3/§4 are real (C-15) |
| P-2 | `python -c` `css_class_for_severity(ValidationSeverity.ERROR)` | `"sev-error"` (`color_policy.py:5-19`) | Red-row CSS/style chain grounded |
| P-3 | `python -c` `inspect.signature(App.notify)` + `typing.get_args(SeverityLevel)` | `severity: 'SeverityLevel' = 'information'`; args = `('information', 'warning', 'error')` | Textual notify severity literals runtime-verified (C-15 framework constant) |
| P-4 | `grep -rc "A2L_TAG_SCHEMA_INCOMPLETE" s19_app tests` | **0 hits** | Issue code is `NEW — created in Phase 3`; no collision with the public issue-code contract |
| P-5 | `ls s19_app/tui/services/` | no `before_after_service.py` | Composer module is `NEW — created in Phase 3` |
| P-6 | `grep -n '("b",' / 'Binding("b"' s19_app/tui/app.py` | 0 hits in `BINDINGS` (app.py:548-578 read; used keys: ctrl+k/d/l/s, /, g, q, l, r, o, s, p, v, j, t, x, k, 1-8, +, -, comma, period) | Key `b` free for the US-034 trigger (`provisional — Phase 3 may re-choose`) |
| P-7 | Read `tests/test_engine_unchanged.py:120-127` (`_ENGINE_PATHS`) | frozen set = `core.py, hexfile.py, range_index.py, validation/ (whole dir), tui/a2l.py, tui/mac.py`; `color_policy.py` guarded by TC-031 (`tests/test_tui_directionb.py`) | **Census (change-first):** every planned file — `tui/services/validation_service.py`, `tui/app.py`, `tui/services/diff_report_service.py`, NEW `tui/services/before_after_service.py`, tests, REQUIREMENTS.md — is OUTSIDE both guard sets. New-symbol-into-existing-file probe (A-3) discharged for `validation_service.py`, `diff_report_service.py`, `app.py` (none frozen/allowlisted). Best-effort + gate-confirmed (A-2). |
| P-8 | `python -c` dataclass fields of `ChangeSummary` | `[..., entries, issues, saved_path, verify_result]` (`model.py:365-372, 404-413`) | US-034 linkage/provenance fields runtime-verified |
| P-9 | `ls tests/` for compare/diff/validation test files | `test_compare_service.py`, `test_diff_report_service.py`, `test_tui_diff_compare_realpath.py` exist; **no** `test_validation_service*.py` | Executed-verification file names in §4 are provisional (V-5); US-032's test file is NEW |
| P-10 | Read `s19_app/tui/app.py:7395-7418` (`update_a2l_view`) | A2L-present branch renders tag rows (`_refresh_a2l_filtered_tags`, :7416) **BEFORE** `update_mac_view()` (:7418, the sync-fallback validation computation) | US-033 needs the LLR-037.3 refresh-order requirement; the precomputed worker path is already ordered (`_apply_loaded_file` installs `_validation_issues` at app.py:6316 before `_step_a2l` at :6368-6373) |
| P-11 | Read `s19_app/tui/a2l.py:1283-1292` (`_tag_schema_and_applicability`) | `virtual=True` + `address is None` → `schema_ok=True` (a2l.py:1288-1289) | Virtual tags are NATURALLY exempt from US-032 (never red via schema); no special-casing required — boundary AT covers it |
| P-12 | Read `.gitignore:7` | `.s19tool/` gitignored | US-034 confidentiality inheritance grounded (reports land under `.s19tool/` project trees) |
| P-13 | `grep 'code="A2L_\|MAC_"' validation/rules.py` | A2L ERROR emitters with `symbol` set: `A2L_INVALID_ADDRESS` (:463, symbol=name), `A2L_DUPLICATE_SYMBOL` (:474, symbol=entries[0].name); `A2L_STRUCTURE_ERROR` (:444, NO symbol); WARNINGs: `A2L_UNRECOGNIZED_BLOCK` (:487), `A2L_BROKEN_REFERENCE` (:507) | US-032 dedup key defined over symbol-bearing a2l ERROR issues; §6.2 D-4 |

---

## 3. High-level requirements (HLR)

### HLR-036 — Red-row-implies-issue (A2L ↔ Issues reconcile, direction 1)
- **Traceability:** US-032
- **Statement:** When the validation report is built for a session whose effective A2L tag set contains a tag with `schema_ok=False` (the condition that renders its row red — `_a2l_tag_row_severity`, `app.py:223-225`), the system shall include in the report's issue list an ERROR-severity `ValidationIssue` identifying that tag, unless an ERROR-severity A2L issue for the same symbol is already present.
- **Rationale (informative):** Divergence confirmed at intake: a non-virtual tag with a missing address is red TODAY with zero issues (`tui/a2l.py:1290-1291` sets `schema_ok=False`; `validation/rules.py:460-469` emits `A2L_INVALID_ADDRESS` only for present-but-non-int addresses). The Issues surface and the A2L table must not disagree. The fix is a supplemental TUI-side rule merged at the open seam `validation_service.build_validation_report` — the frozen `validation/` engine and `tui/a2l.py` are untouched (P-7). Adding a NEW issue code is contract-safe; renaming existing codes is forbidden.
- **Validation:** test
- **Executed verification:** `pytest tests/test_validation_service_supplemental.py -q` (file NEW, name provisional per V-5)
- **Numeric pass threshold:** 0 failures; existing full suite `pytest -q -m "not slow"` 0 new failures
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome:**
  - **Observable outcome:** every red row in the A2L table has a matching ERROR entry (naming the same symbol) visible in the Issues surface; the two surfaces cannot disagree in direction red→issue.
  - **Shipped surface:** Textual Pilot (`App.run_test()`) — load an S19 + A2L where one non-virtual characteristic is missing its address; read the A2L DataTable (`#a2l_tags_list`) row styles and the Issues DataTable (`#validation_issues_list`, rendered by `update_validation_issues_view`, `app.py:5304` — the same `_validation_issues` list backs both the workspace Issues pane and the `5` Issues-Report screen, `app.py:1151-1192`).
  - **Deliverable + observation:** rendered Issues row whose code/symbol match the red tag; asserted through widget content, not internal maps.
  - **Acceptance test(s):** `AT-036a` (red row ⇒ ERROR issue for that symbol, shown FAILING pre-fix — pre-state proven by P-4 + intake divergence), `AT-036b` (dedup: a tag that already earns `A2L_DUPLICATE_SYMBOL` or `A2L_INVALID_ADDRESS` gains NO second ERROR for the same symbol — issue count for that symbol == 1 per code family), `AT-036c` (negative: clean A2L → zero `A2L_TAG_SCHEMA_INCOMPLETE` issues). Ids provisional (V-5).
  - **MAC-less fixture discipline (B-1a):** these ATs' fixtures are deliberately MAC-LESS (S19 + A2L only) and therefore ALSO gate the LLR-037.4 no-MAC retention fix — pre-fix, `update_mac_view` wipes `_validation_report`/`_validation_issues` in every no-MAC session (wipe sites `app.py:7162-7163` and `:7176-7177` behind guards `:7160`/`:7174`), so AT-036a's Issues-pane observable is unobservable until LLR-037.4 lands; LLR-037.4 consequently ships in I1 (§6.6). Adding a MAC to these fixtures would green the ATs while the shipped divergence persisted (C-12-family masking) and is forbidden.
  - **Boundary catalog (QC-3):** ☑ empty — A2L with zero tags → no new issues (`AT-036c` variant) · ☑ boundary — virtual tag with no address: `schema_ok=True` by `a2l.py:1288-1289` → NOT red, NO issue (exempt-by-construction, asserted in `AT-036c`) · ☑ invalid — missing-address non-virtual tag (`AT-036a`); nameless `schema_ok=False` tag → issue emitted with `symbol=None`, message falls back to line/address (`TC-036.4`) · ☑ error/already-covered — duplicate-symbol tag → NO double-report (`AT-036b`).

### HLR-037 — Issue-implies-red-row (A2L ↔ Issues reconcile, direction 2)
- **Traceability:** US-033
- **Statement:** While the current validation issue list contains an ERROR-severity A2L issue carrying a symbol, the system shall render every A2L table row whose tag name matches that symbol with ERROR (red) severity, honoring REQUIREMENTS.md:364 ("Red: structural/schema failure … and duplicate symbol when configured as a hard error" — line read + cited 2026-07-02).
- **Rationale (informative):** Direction-2 divergence: `A2L_DUPLICATE_SYMBOL` is ERROR (`rules.py:470-480`) but `_a2l_tag_row_severity` (`app.py:223-232`) never consults issues, so duplicate-symbol rows render normal today. Duplicate detection lives in the frozen engine and cannot be re-derived row-side; the row-severity function must consult a symbol→severity map derived from the report.
- **Validation:** test
- **Executed verification:** `pytest tests/test_tui_app.py -q -k a2l_row_severity` (selector provisional per V-5)
- **Numeric pass threshold:** 0 failures; full suite 0 new failures
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** loading an A2L containing a duplicated symbol renders BOTH duplicate rows red in the A2L table; the issue list itself is unchanged (count and codes identical to pre-change).
  - **Shipped surface:** Textual Pilot — load S19 + A2L with a duplicated characteristic name; read `#a2l_tags_list` cell styles.
  - **Deliverable + observation:** rendered red style on both duplicate rows (Rich style `"red"` per `_SEVERITY_TO_RICH_STYLE[ERROR]`, `app.py:386-392`).
  - **Acceptance test(s):** `AT-037a` (duplicate symbol → both rows red; FAILS pre-fix), `AT-037b` (boundary: an issue symbol absent from the rendered tag set — naturally producible through the shipped chain via `A2L_BROKEN_REFERENCE`, `rules.py:507` — changes nothing: no crash, no row change). The "WARNING does not recolour" check is NOT an AT (A-M1 split): the only shipped-chain a2l WARNING emitters are symbol-less or never match a rendered row, so it is unbuildable black-box; it lives as the Layer-A `TC-037.2` GUARD over constructed issues. Ids provisional (V-5). Fixtures deliberately MAC-less: AT-037a's map source (`_validation_issues`) requires the LLR-037.4 retention fix from I1 — I1 → I2 is a STRICT dependency (§6.6).
  - **Boundary catalog (QC-3):** ☑ empty — no issues → map empty → severity function reduces to existing behavior (`TC-037.2`) · ☑ boundary — WARNING-only symbol → row colour unchanged (`TC-037.2`, Layer-A GUARD over constructed issues — unbuildable through the shipped chain, A-M1; policy §6.2 D-2) · ☑ invalid — issue symbol not present in the rendered tag set → no crash, no row change (`AT-037b`, naturally produced via `A2L_BROKEN_REFERENCE`) · ☑ error — ERROR symbol + memory-checked-present tag (green candidate) → red wins (`TC-037.2` precedence case).

### HLR-038 — Before/after report on save-back
- **Traceability:** US-034
- **Statement:** When a change document has been applied and the patched image saved back successfully (a `ChangeSummary` with non-`None` `saved_path`, `change_service.py:921-922`), upon the operator invoking the offered report action the system shall write a before/after diff report pair (Markdown + self-contained HTML) comparing the ORIGINAL loaded file (`LoadedFile.path`, `models.py:42`) against the SAVED patched file (`last_summary.saved_path` — the actual post-dedup written path), containing a before/after provenance header and a per-entry change-linkage table derived from `last_summary.entries` (`ChangeSummaryEntry.before_bytes/after_bytes`, `model.py:365-372`), under the active project's `reports/` directory.
- **Rationale (informative):** The backbone shipped in batch-09: `compare_images` parses both sources fresh from disk (`compare_service.py:451-465`), `generate_diff_report(_html)` writes complete reports with hex windows + ```diff blocks (`diff_report_service.py:720-731, 1015-1026`). Missing: the one-action trigger, the linkage table, the provenance header. Micro-spike RESOLVED: save-back cannot clobber the original — `save_patched_image` stages + places via `copy_into_workarea` with dedup-suffix, never a silent overwrite (`apply.py:574-646`, return contract :628-633), so the (original, saved) pair is structurally well-defined.
- **Validation:** test
- **Executed verification:** `pytest tests/test_before_after_report.py -q` (file NEW, name provisional per V-5)
- **Numeric pass threshold:** 0 failures; full suite 0 new failures
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** after apply → save-back → trigger, a report file exists under `<project>/reports/` whose ```diff block shows the pre-patch bytes as `-` lines and the entry's `after_bytes` as `+` lines at the patched address, plus a linkage table row per applied entry (address range → disposition → linkage symbol) and a header naming both the original path and the saved (post-dedup) path.
  - **Shipped surface:** Textual Pilot — drive the Patch Editor apply + save-back prompt (`on_patch_editor_panel_save_back_decision`, `app.py:1448-1518`), then invoke the offered report action; NO new button row (C-13 N/A per DoR).
  - **Deliverable + observation (C-12 GATE, Q-M1 observation chain):** the AT snapshots the reports-directory listing BEFORE the trigger, captures the app's surfaced notify/status text after it, asserts the SURFACED path equals the single new file in the post-trigger directory diff, then re-reads THAT path from disk for the content asserts (`-`/`+` lines at the patched address, linkage row, both path names) — surfaced-text → dir-diff → re-read, never a glob reconstruction, so LLR-038.3's path surfacing is itself observed. The AT FAILS if the file is silently absent or the surfaced path names anything else. A direct `before_after_service` call test is a white-box TC/guard, never the gate. C-10: the AT confirms the SUGGESTED save-back name against a pre-planted COLLIDING file (amended I5/F2 — the collision, not the typing, is the non-default drive: the on-disk identity differs from what the dialog displayed), so the report's "after" identity must show the dedup-suffixed basename (pinned literal `img-patched_1.s19` for the `img-patched.s19` drive — `_<N>` scheme, `workspace.py:237-238`; the typed name is not a substring of the suffixed one, so the assert discriminates an echo) — proving the header reads `saved_path`, not the typed name.
  - **Acceptance test(s):** `AT-038a` (happy path + collision-dedup drive, C-10+C-12 — the ONLY counterfactual carrier for US-034: pre-fix the trigger does not exist, so the absent deliverable is the RED), `AT-038b` (GUARD-class, Q-m1: trigger with no successful save-back → graceful notice, NO file written — the POSITIVE surfaced-refusal-diagnostic assert is load-bearing; directory-listing emptiness alone would pass vacuously pre-implementation), `AT-038c` (GUARD-class: original deleted between save and trigger → surfaced refusal diagnostic, no write, app keeps running), `AT-038d` (GUARD-class, B-2 stale-summary: apply + save-back in project A → open project B → trigger → stale-summary refusal surfaced, 0 files in B's `reports/` dir asserted by directory listing; the positive refusal-diagnostic assert is load-bearing per Q-m1's convention). Ids provisional (V-5).
  - **Boundary catalog (QC-3):** ☑ empty — apply with 0 applied entries → report still written; linkage section states "no entries"; diff runs may be empty (no-diff report precedent, PR #20) (`TC-038.2`) · ☑ boundary — filename collision → dedup-suffixed "after" identity in header (`AT-038a`) · ☑ invalid — `last_summary is None` or `saved_path is None` (declined/refused save) → graceful refusal, no write (`AT-038b`) · ☑ error — original missing on disk post-save → `compare_images` per-source failure → refused result surfaced, no write (`AT-038c`); stale summary — `LoadedFile.path` ≠ `summary.source_image_path`, or `saved_path` outside the current project dir/workarea (LLR-038.2 preconditions 4-5) → refusal, 0 files (`AT-038d`); no active project → refusal naming the manual A↔B path (§6.2 D-3, `TC-038.4`).

---

## 4. Low-level requirements (LLR)

### LLR-036.1 — Supplemental schema-incomplete rule
- **Traceability:** HLR-036
- **Statement:** The `validation_service` module shall provide a function (`supplemental_a2l_row_issues` — NEW, created in Phase 3) that, given the effective A2L tag list (the `tags_for_validation` resolved at `validation_service.py:60-63`), returns one `ValidationIssue` with code `A2L_TAG_SCHEMA_INCOMPLETE` (NEW — P-4: 0 hits today), severity `ValidationSeverity.ERROR` (P-1), `artifact="a2l"`, and the tag's `symbol`/`address`/`reason` populated, for every tag whose `schema_ok` field is `False`.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_validation_service_supplemental.py -q -k schema_incomplete` (provisional, V-5)
- **Numeric pass threshold:** 0 failures; for a fixture with N schema-bad tags exactly N issues pre-dedup
- **Acceptance criteria:** message names the symbol and the tag's `reason` (e.g. "missing address/length", `a2l.py:1291`); message passes through the constructor scrub automatically (`_scrub_issue_message`, `validation/model.py:137` — frozen module consumed, not edited); a nameless tag yields `symbol=None` with the message falling back to address/line context. The predicate keys on `schema_ok is False` explicitly — a tag dict WITHOUT the key (raw/un-enriched or schema-complete test fixtures, e.g. `tests/test_tui_services.py`) yields NO issue, so existing issue-count-pinning tests over such dicts stay green (A-M2 executed-sweep consequence, §6.3 R-1).

### LLR-036.2 — Normative dedup (no double-reporting)
- **Traceability:** HLR-036
- **Statement:** The supplemental rule shall NOT emit `A2L_TAG_SCHEMA_INCOMPLETE` for a tag whose casefolded name matches the casefolded `symbol` of any already-collected ERROR-severity issue with `artifact="a2l"` (existing symbol-bearing ERROR emitters: `A2L_INVALID_ADDRESS` `rules.py:463-468`; `A2L_DUPLICATE_SYMBOL` `rules.py:474-479` — P-13).
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_validation_service_supplemental.py -q -k dedup` (provisional, V-5)
- **Numeric pass threshold:** for a tag covered by an existing a2l ERROR, 0 supplemental issues for that symbol
- **Acceptance criteria:** dedup is by (casefolded symbol, artifact, severity==ERROR), NOT by full identity tuple — the existing `_deduplicate_issues` (`app.py:5267-5285`) dedups exact duplicates only and cannot provide this; symbol-less existing issues (`A2L_STRUCTURE_ERROR`, `rules.py:444` — no symbol) never suppress a supplemental issue.

### LLR-036.3 — Merge at both report branches
- **Traceability:** HLR-036
- **Statement:** `build_validation_report` shall merge the supplemental issues into its issue list before the `dedupe_issues` call in BOTH branches — the MAC-only branch (`validation_service.py:65-75`) and the primary-backed branch (`validation_service.py:76-91`) — whenever the effective tag list is non-empty.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_validation_service_supplemental.py -q -k branches` (provisional, V-5)
- **Numeric pass threshold:** supplemental issue present in returned `issues` for both a `primary_file=None` and a primary-backed invocation; 0 failures
- **Acceptance criteria (informative):** sessions with an A2L but NO loaded file never reach `build_validation_report` (issues cleared at `app.py:7408-7411`) — documented limitation, §6.1 A-2, out of scope.

### LLR-037.1 — Symbol→severity map builder
- **Traceability:** HLR-037
- **Statement:** The app module shall provide a module-level helper (`_a2l_issue_severity_map` — NEW, created in Phase 3) that derives, from a `ValidationIssue` list, a dict mapping each casefolded issue `symbol` (issues with `artifact=="a2l"` and a non-empty symbol only) to the maximum severity observed for that symbol, where the ordering ranks `ERROR` above all other members (P-1).
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_tui_app.py -q -k issue_severity_map` (provisional, V-5)
- **Numeric pass threshold:** 0 failures; map excludes non-a2l artifacts and symbol-less issues
- **Acceptance criteria:** pure function, no widget access; O(issues) build, consulted O(1) per row (paged table renders ≤ page_size rows, `app.py:7473-7476` — no per-row scan of the issue list).

### LLR-037.2 — Row severity consults the map; ERROR-only precedence
- **Traceability:** HLR-037
- **Statement:** `_a2l_tag_row_severity` (`app.py:223-232`) shall accept the symbol→severity map and shall return `ValidationSeverity.ERROR` when the tag's casefolded name maps to `ERROR`; in every other case (no map entry, or a mapped severity below ERROR — i.e. WARNING) it shall return the existing severity unchanged (`schema_ok` red at :224-225, green/white/grey ladder at :226-232).
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_tui_app.py -q -k a2l_row_severity` (provisional, V-5)
- **Numeric pass threshold:** 0 failures across the precedence matrix (ERROR-issue × {schema-bad, green, white, grey} → all ERROR; WARNING-issue × same → unchanged)
- **Acceptance criteria:** max-severity-wins reduces to "issue-ERROR overrides everything; otherwise prior logic" because ERROR is the only issue level that recolours (§6.2 D-2: the REQUIREMENTS.md:362-367 A2L palette defines Red/Green/White/Grey ONLY — orange is a MAC-view convention, so an A2L WARNING must not recolour); the single production caller `update_a2l_tags_view` (`app.py:7482`) OWNS the map BUILD (A-m4): it constructs the map from `self._validation_issues` via `_a2l_issue_severity_map` once per render and passes it per row; signature change censused — callers are :7482 + tests only (P-7 grep regime).

### LLR-037.3 — Map freshness at render time
- **Traceability:** HLR-037
- **Statement:** When `update_a2l_view` executes its A2L-present branch, the system shall compute/install the validation issue list BEFORE the tag rows render and AFTER tag enrichment — i.e. the `update_mac_view()` call currently at `app.py:7418` shall move to immediately after `_compute_a2l_enriched_tags()` (`app.py:7413`) and before `_refresh_a2l_filtered_tags` (currently `app.py:7416`) — so the map read at row-render time reflects the current file pair, computed through the LLR-037.4-fixed no-MAC branch. The after-enrichment pin is load-bearing (A-m1): the MAC view cache key (`app.py:7187-7194`) omits enrichment state while `_build_mac_view_cache` consumes `self._a2l_enriched_tags` (`app.py:6002`) — installing the issues before enrichment would cache a report built from stale tags.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_tui_app.py -q -k a2l_refresh_order` (provisional, V-5)
- **Numeric pass threshold:** 0 failures; on the sync-fallback load path the duplicate-symbol rows are red on FIRST render (no stale frame)
- **Acceptance criteria (informative):** the precomputed worker path is already ordered (`_validation_issues` installed at `app.py:6316` before `_step_a2l` renders at :6368-6373 — P-10); later re-renders (filter/paging handlers calling `update_a2l_tags_view`) read the already-fresh list; `update_mac_view` is idempotent over the cache key (the `_mac_view_cache_key` check, `app.py:7195-7197` — anchor corrected per A-m3), so the reorder adds no recomputation.

### LLR-037.4 — No-MAC sessions retain the validation report (B-1a)
- **Traceability:** HLR-036 + HLR-037 (shared substrate — both stories' MAC-less ATs gate it; ships in I1, §6.6)
- **Statement:** When a primary file is loaded (`self.current_file` is not `None`), the `update_mac_view` no-MAC branch — guard `app.py:7160` (`current_file` falsy or `mac_records` falsy) and guard `app.py:7174` (`records` empty after normalization) — shall compute and retain the validation report for the primary+A2L pair (the `build_validation_report` output `_compute_mac_view_payload` already produces for any `loaded is not None`, `app.py:5940-5960`) instead of clearing `_validation_report`/`_validation_issues` (the two wipe sites, `app.py:7162-7163` and `app.py:7176-7177`); sessions with NO primary file shall keep the existing clear-and-return behavior.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_validation_service_supplemental.py -q -k no_mac_retention` (provisional, V-5)
- **Numeric pass threshold:** 0 failures; an S19+A2L (no MAC) session ends with `_validation_issues` non-empty when the pair carries issues, on BOTH the worker path and the sync-fallback path
- **Acceptance criteria:** the no-MAC compute routes through the existing `_mac_view_cache_key` mechanism (`app.py:7187-7197`), NOT a per-render recompute — per-render is not cheap: the payload's overlap-set step re-parses the S19 from disk (`app.py:5943-5951`). The empty-records case needs a STABLE key: the current `id(records)` component churns when `mac_records or []` constructs a fresh list each call — substitute a stable identity for that component (e.g. `id(self.current_file)`) when records are empty; exact key shape decided at Phase 3. On the worker path the report is already precomputed and installed (`_compute_mac_view_payload` at `app.py:6488` → install at `:6316`) — the fixed branch RETAINS it (cache-hit no-op), never wipe-then-recompute. The branch's MAC table/summary rendering ("No MAC loaded." / "No MAC records parsed.") is unchanged; only the validation-member clearing moves behind the no-primary condition.

### LLR-038.1 — Diff-report generators accept provenance + linkage content
- **Traceability:** HLR-038
- **Statement:** `generate_diff_report` (`diff_report_service.py:720-731`) and `generate_diff_report_html` (`diff_report_service.py:1015-1026`) shall accept optional keyword arguments — a before/after provenance block (original path, saved path, apply timestamp `ChangeSummary.timestamp_utc`, change-doc `source_path`; field names NEW, created in Phase 3), a linkage-entry sequence (`ChangeSummaryEntry` data: `entry_type`, `address_start/end`, `disposition`, `linkage`, `linkage_symbol` — `model.py:365-372`, runtime-verified P-8), and a filename stem — rendering, when provided, a header section and a per-entry linkage table in the written file; when the new kwargs are omitted the written output shall be byte-identical to the current behavior.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_diff_report_service.py -q -k before_after or linkage or byte_identical` (file exists — P-9; selector provisional, V-5)
- **Numeric pass threshold:** 0 failures; omitted-kwargs regression case byte-identical (fixed `now_fn`, existing injectable clock `diff_report_service.py:123-141`)
- **Acceptance criteria:** the linkage table renders `before_bytes=None` (create-into-hole entries) as an explicit marker, never fabricated bytes; content rules inherited — no logging (F-S-07 module discipline, `diff_report_service.py:66-69`), HTML values `html.escape`-d. Every parsed-artifact value rendered into a Markdown table cell (linkage symbols, entry fields, paths) passes through a `_md_cell()` helper that escapes `|` and strips control characters (S-F2 — parsed A2L/MAC symbols are otherwise unscrubbed into table syntax; the HTML side is already safe via `_esc`, `diff_report_service.py:826-828`); a pipe-bearing symbol renders escaped with table structure intact (`TC-038.6`).

### LLR-038.2 — Before/after composer service
- **Traceability:** HLR-038
- **Statement:** A new module `s19_app/tui/services/before_after_service.py` (NEW — P-5) shall compose the report: validate preconditions — (1) summary present, (2) `saved_path` non-`None`, (3) both paths existing files, (4) `LoadedFile.path` equals `summary.source_image_path` (the image the summary was actually saved from — B-2), and (5) `saved_path` resolves inside the CURRENT `_active_project_dir()` (or the workarea root when no project was active at save time — the `dest_dir` fallback, `app.py:1499`) at trigger time — then call `compare_images` with two `SOURCE_EXTERNAL` `ImageSource`s (`compare_service.py:451-465`, discriminator `compare_service.py:47`) for `(original=LoadedFile.path, patched=saved_path)`, re-load both maps through the headless loaders (the `_diff_load_maps` pattern, `app.py:2569-2633`), invoke both LLR-038.1 generators with the provenance/linkage kwargs and its OWN filename stem, and return a result object carrying written paths or refusal diagnostics — never raising for a missing/refused input.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_before_after_report.py -q` (NEW file, provisional V-5)
- **Numeric pass threshold:** 0 failures; refusal cases write 0 files (asserted by directory listing)
- **Acceptance criteria:** owns `BEFORE_AFTER_REPORT_FILENAME_REGEX` / `_HTML_` twins for the `<UTC %Y%m%dT%H%M%SZ>(-NN)?-before-after-report.md|.html` scheme (the diff-report owns-its-own-regex precedent, `diff_report_service.py:99-113`; shared `REPORT_FILENAME_REGEX` untouched); imports no Textual symbol (the `compare_service.py:18-22` service-layer purity precedent; probe form per V-4: `rg -n "import textual|from textual" s19_app/tui/services/before_after_service.py` → 0). Provenance-stamp mechanism (B-2): `ChangeSummary.source_image_path` is a NEW `Optional[Path]` field (`changes/model.py:376` — `changes/` is NOT engine-frozen, P-7), stamped by `ChangeService.save_patched` via a new `source_image_path` keyword beside the existing `saved_path` stamp (`change_service.py:921-922`; the handler passes `loaded.path`, `app.py:1507-1515`) — service-side stamping keeps the provenance write in the same seam as `saved_path` and headless-testable, chosen over a handler-side stamp; the field mirrors `verify_result`'s runtime-only treatment (kept OFF `to_dict`, `model.py:454-498`) so the serialized summary stays byte-stable. Additionally the composer refuses when the resolved `reports/` destination `is_symlink()` (S-F4 — cheap containment hardening on the write side).

### LLR-038.3 — Trigger UX (offer after save-back)
- **Traceability:** HLR-038
- **Statement:** When `save_patched` returns `ok=True` (the `result.ok` branch, `app.py:1517-1518`), the app shall offer the report in-flow — a `notify` with `severity="information"` (literal runtime-verified, P-3) naming the report action and its key — and shall expose an `action_before_after_report` bound to key `b` (free per P-6; key choice provisional — Phase 3 may re-choose within the free set) that invokes the LLR-038.2 composer with the active project dir and surfaces the written paths or the refusal diagnostic on the status line; the manual A↔B compare/report path (`on_ab_diff_panel_report_requested`, `app.py:2635-2699`) shall remain unchanged.
- **Validation:** test (e2e / pilot)
- **Executed verification:** `pytest tests/test_before_after_report.py -q -k trigger` (provisional, V-5)
- **Numeric pass threshold:** 0 failures; AT-038a re-read gate passes (C-12)
- **Acceptance criteria:** no new button row or layout change — C-13 N/A confirmed (notify + binding only, zero geometry); the offer appears after `_surface_verify_result` (`app.py:1520-1573`) so a verify-mismatch error notice is never masked. A verify MISMATCH does not suppress the offer (A-m2): `ok=True` with a mismatch still stamps `saved_path` (`change_service.py:934-936`), so the offer INTENTIONALLY appears after the error notice — the resulting report stays honest because it is a disk-to-disk comparison of what was actually written, not of the intended map.

### LLR-038.4 — Failure modes are refusals, never writes
- **Traceability:** HLR-038
- **Statement:** If the report action is invoked when (1) `last_summary` is `None`, or (2) `saved_path` is `None` (declined/refused save — `change_service.py:923-928` leaves it stamped `None`), or (3) either source path no longer exists on disk, or (4) the summary is STALE — `LoadedFile.path` does not equal `summary.source_image_path`, or `saved_path` fails the current-project containment check (LLR-038.2 preconditions 4-5, B-2) — then the system shall surface one human-readable refusal (status line or notify), shall write no file, and shall keep the app running.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_before_after_report.py -q -k refusal` (provisional, V-5)
- **Numeric pass threshold:** 0 files written across all four refusal classes; 0 unhandled exceptions
- **Acceptance criteria:** a missing-on-disk source is detected by `compare_images`' per-source diagnostic capture (`compare_service.py:12-16` refused-result contract) — the composer does not pre-duplicate the engine's checks beyond the cheap existence guard; with no active project the action refuses with a diagnostic pointing at the manual A↔B path (§6.2 D-3); the stale-summary refusal (class 4) names the mismatch so a project-switch survivor (`last_summary` persists across project switch and file load — B-2 origin) is diagnosable, not silent.

### LLR-038.5 — Confidentiality inheritance
- **Traceability:** HLR-038
- **Statement:** The before/after reports shall be written only under the active project's `reports/` directory (destination discipline of `diff_report_service.py:42-64`) — gitignored when the project lives in the default `.s19tool/` workarea (`.gitignore:7` — P-12; projects MAY live outside `.s19tool/`, external parent dirs are accepted at `app.py:4017-4027`, so gitignore coverage is a default-layout property, not a guarantee — S-F3) — and the composer/trigger code shall log no report body content (the F-S-07 no-logging discipline, `diff_report_service.py:66-69`).
- **Validation:** inspection
- **Executed verification:** inspect `before_after_service.py` for `logging`/`logger` usage + destination construction (`rg -n "logging|getLogger" s19_app/tui/services/before_after_service.py`); ALSO inspect the `app.py` trigger handler (`action_before_after_report` + its notify/status calls, S-F5): surfaced text carries paths and refusal diagnostics only, never entry byte content
- **Numeric pass threshold:** 0 logging imports/calls in the new module; destination always constructed as `<project_dir>/reports/` (the TC asserts the destination CONSTRUCTION, not gitignoredness — S-F3); 0 report-body/byte-content substrings in trigger-handler notify/status strings
- **Acceptance criteria:** report content (raw bytes, symbols) never reaches `.s19tool/logs/s19tui.log`; linkage symbols originate from A2L/MAC artifacts already rendered in diff reports — no operator-typed free text enters the report body from this feature (the batch-19 region-name scrub concern does not arise; noted §6.1 A-4).

---

## 5. Validation strategy

### 5.1 Methods

Two layers per the headline rule. Layer A (white-box `TC-NNN`, LLR-aligned ids `TC-<LLR>`): unit/integration tests named per-LLR above. Layer B (black-box `AT-NNN`): Textual Pilot e2e driving the shipped surfaces — A2L/Issues DataTables (US-032/033) and the Patch-Editor save-back → report trigger with on-disk re-read (US-034). All file paths / `-k` selectors / node ids provisional-until-Phase-3 (V-5). Testing stack cross-check: pytest + Textual `App.run_test()` is the ratified, installed path (CI `pytest -q`; existing pilot tests, e.g. `tests/test_tui_diff_compare_realpath.py` — P-9); no new runtime.

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-032 | Every red A2L row has a matching ERROR issue in the Issues surface; no double-report for already-covered symbols | `#a2l_tags_list` + `#validation_issues_list` via Pilot | AT-036a, AT-036b, AT-036c | Phase 4 |
| US-033 | Duplicate-symbol (ERROR-issue) rows render red; absent-from-table issue symbols are inert; issue list unchanged (WARNING no-recolour = Layer-A `TC-037.2` GUARD, A-M1) | `#a2l_tags_list` cell styles via Pilot | AT-037a, AT-037b | Phase 4 |
| US-034 | One action after save-back writes a report pair under `reports/` with -/+ bytes at the patched address, linkage table, and post-dedup "after" identity; refusals (incl. stale-summary cross-project, B-2) write nothing | Patch-Editor save-back flow + `b` action; surfaced path → dir-diff → file re-read from disk (C-12 gate, Q-M1 chain) | AT-038a, AT-038b, AT-038c, AT-038d | Phase 4 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case | Notes |
|-------------|--------|-----------|-------|
| HLR-036 | test (pilot) | AT-036a/b/c | gate |
| LLR-036.1 | test (unit) | TC-036.1 | N-issues count; scrub via constructor |
| LLR-036.2 | test (unit) | TC-036.2 | dedup key = casefolded symbol × a2l × ERROR |
| LLR-036.3 | test (integration) | TC-036.3 | both branches of `build_validation_report` |
| LLR-036.1 (nameless boundary) | test (unit) | TC-036.4 | symbol=None fallback |
| HLR-037 | test (pilot) | AT-037a/b | gate |
| LLR-037.1 | test (unit) | TC-037.1 | map build/filter semantics |
| LLR-037.2 | test (unit) | TC-037.2 | precedence matrix incl. green×ERROR |
| LLR-037.3 | test (integration) | TC-037.3 | first-render freshness, sync path |
| LLR-037.4 | test (integration) | TC-037.4 | no-MAC retention: primary+A2L keeps report (worker + sync paths); no-primary keeps clear; cache-key stability (B-1a) |
| HLR-038 | test (pilot) | AT-038a/b/c/d | gate (C-10 + C-12; b/c/d GUARD-class, Q-m1) |
| LLR-038.1 | test (unit) | TC-038.1 | + byte-identical regression case |
| LLR-038.1 (0-entries) | test (unit) | TC-038.2 | "no entries" linkage section |
| LLR-038.1 (md-cell escaping) | test (unit) | TC-038.6 | pipe-bearing symbol escaped, ctl chars stripped, table intact (S-F2) |
| LLR-038.2 | test (integration) | TC-038.3 | composer happy + regex ownership + provenance stamp (`source_image_path`) + symlink refusal (S-F4) |
| LLR-038.3 / 038.4 | test (integration) | TC-038.4 | trigger + 4 refusal classes (incl. stale-summary, B-2) + no-project refusal |
| LLR-038.5 | inspection | TC-038.5 | no-logging + destination-construction inspection, incl. the app.py trigger handler (S-F3/S-F5) |

### 5.3 Batch acceptance criteria
- 100 % of LLRs covered by ≥1 passing TC; every US has ≥1 passing AT observing the outcome through the shipped surface with boundary + negative evidence.
- AT-038a's assertion target is the handler-written file re-read from disk (C-12); it fails on a silently-absent file.
- `pytest -q -m "not slow"` — 0 new failures; engine-frozen guards (TC-027 / TC-031) green (0 frozen-path diffs).
- Byte-identical regression: default-kwargs diff-report output unchanged (TC-038.1).
- No renamed/removed existing issue code (public contract): `rg` for each code in P-13 still hits `validation/rules.py` unchanged.

---

## 6. Appendices

### 6.1 Assumptions
- **A-1:** The enriched tag dicts reaching `build_validation_report` carry `schema_ok` (they do when enrichment ran — `validate_a2l_tags`, `a2l.py:1295-1354`; raw un-enriched tags lack the key and `tag.get("schema_ok", True)` defaults safe). `assumed — verify in Phase 3` that every `tags_for_validation` producer path passes enriched tags when an image is loaded (`app.py:5953-5957` passes `a2l_enriched_tags`).
- **A-2:** Sessions with an A2L but no loaded file never reach `build_validation_report` (`app.py:7408-7411` clears issues); direction-1 reconcile is scoped to sessions where validation runs. Documented limitation, not a regression.
- **A-3:** `compare_images` handles two `SOURCE_EXTERNAL` absolute paths without a project variant set (signature defaults, `compare_service.py:451-465`). Verified by signature read; behavior `assumed — verify in Phase 3` via TC-038.3.
- **A-4:** No operator-typed free text enters the US-034 report body (filenames pass F-S-01; linkage symbols come from parsed artifacts) — re-checked at Phase-2 security lens.

### 6.2 Relevant design decisions
- **D-1 — US-034 composer = thin NEW service + optional-kwarg extension of the generators.** The header/linkage must appear INSIDE the written files, so pure orchestration cannot avoid touching `diff_report_service`; but composition (preconditions, compare, map loads, trigger contract) does not belong in a 1.4k-LOC renderer nor in `app.py` (orchestration-only rule). Alternatives rejected: (a) new standalone generator module — duplicates the proven complete-report/destination/collision machinery; (b) all-in-app.py — violates the decomposition rule. Reversible; default-off kwargs keep the diff-report path byte-identical.
- **D-2 — WARNING does not recolour A2L rows.** REQUIREMENTS.md:362-367 defines the A2L palette as Red/Green/White/Grey only; orange is a MAC-view convention (REQUIREMENTS.md §"MAC ... Criteria", CLAUDE.md severity conventions). Recolouring on WARNING would invent a fifth A2L state without a requirements basis. Consequence: precedence collapses to "issue-ERROR overrides; else existing ladder".
- **D-3 — No-project save-back sessions: the report action refuses and names the manual A↔B path.** The generators' no-project branch requires an operator-typed destination (`diff_report_service.py:48-58`); offering that inline would add input UI (C-13 territory) for a rare flow. The manual path already covers it. Reversible (a dest prompt can be added later).
- **D-4 — US-032 dedup key = casefolded symbol × `artifact=="a2l"` × ERROR.** Matches the engine's own duplicate grouping (`by_name[name.lower()]`, `rules.py:458-470`); symbol-less `A2L_STRUCTURE_ERROR` never suppresses (file-level, not tag-level). New code name `A2L_TAG_SCHEMA_INCOMPLETE` collision-free (P-4).
- **D-5 — US-033 map lives app-side (module-level helper beside `_a2l_tag_row_severity`).** The map is render-plumbing over an already-computed report; putting it in `validation_service` would export a UI concern from a headless service. Pure function, unit-testable.

### 6.3 Open risks
- **R-1 (US-032, low — downgraded from medium at Phase-2, A-M2):** new ERROR issues change Issues-pane counts/summaries some tests may pin. The EXECUTED issue-count sweep (02-review §2 — replacing the earlier P-7 mis-anchor, which was the frozen-set probe, not a count sweep) found exposure LOW: `tests/test_tui_services.py` uses schema-complete/raw dicts — safe because LLR-036.1 keys on `schema_ok is False` and absent-key inputs gain no issues; the render tests inject issues directly; the gif test asserts nothing on counts. Residual risk gate-confirmed at I1 (A-2 ban: best-effort, gate is the guarantee). B-1a census additions: the 3 no-op `update_mac_view` monkeypatches (`tests/test_tui_app.py:121,158,230`) neutralize the fixed branch and survive unchanged (net-0 rewrites); the SVG snapshot matrix (`tests/test_tui_snapshot.py`) is relevant since B-1a changes `update_mac_view` — exposure nil-in-expectation (`large_a2l` is schema-clean, so no new red rows/issues enter snapshot frames; A-m5), verified at the I1 full-suite gate.
- **R-2 (US-033, low):** `_a2l_tag_row_severity` signature change — callers censused (app.py:7482 + tests); direct-import tests updated in the same increment (C-14 sweep: `rg -n "_a2l_tag_row_severity" tests/` at Phase 3).
- **R-3 (US-034, medium):** Pilot-driving the full apply→save→trigger chain is the longest e2e in the batch; stall risk on long runs (batch-20/21 precedent) — checkpoint before the long run; orchestrator may run verification directly.
- **R-4 (US-034, low):** `before_bytes=None` create-into-hole entries must not render fabricated "-" bytes — TC-038.1 covers.
- **R-5 (US-033, low):** re-render sites other than `update_a2l_tags_view` (paging/filter) read the map after load — freshness relies on issues being installed at load; TC-037.3 pins the sync path, the worker path is ordered by construction (P-10).

### 6.4 Phase-1 reconciliation log

Iterate-to-refine fold of the 02-review findings register (2026-07-02, operator decisions locked: B-1 = option (a) fix-the-wipe). One row per fold; body-first, audit-trail second.

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|---|---|---|---|
| B-1a (BLOCKER, opt a) | NEW LLR-037.4 (no-MAC retention, cache-routed, wipe sites/guards cited); HLR-036 + HLR-037 Acceptance gain the MAC-less-fixture discipline + gating note; I1 restructured to carry the fix (4 files); I1→I2 now STRICT; census additions in R-1 (3 monkeypatches + snapshot matrix) | ✓ HLR-036 + HLR-037 | ✓ (§4 LLR-037.4; §3 both Acceptance blocks; §5.2; §6.6; §6.3 R-1; §6.5 entry) |
| B-2 (BLOCKER) | LLR-038.2 preconditions gain (4) `source_image_path` match + (5) current-project containment; stamp mechanism defined (service-side kwarg beside the `saved_path` stamp, field off `to_dict`); LLR-038.4 refusal class 4 = stale-summary; NEW AT-038d in HLR-038 Acceptance; stamp lands in I3, handler pass in I4 | ✓ HLR-038 | ✓ (§4 LLR-038.2/.4; §3 HLR-038; §5.2; §6.6; §6.5 entry) |
| A-M1 (MAJOR) | AT-037b split: absent-from-table symbol stays (naturally via `A2L_BROKEN_REFERENCE`); WARNING-no-recolour moved to Layer-A `TC-037.2` GUARD (constructed issues); HLR-037 boundary catalog + §5.2 amended | ✓ HLR-037 | ✓ (§3 HLR-037 AT list + boundary catalog; §5.2; §6.5 entry) |
| A-M2 (MAJOR) | §6.3 R-1 re-anchored to the EXECUTED sweep (P-7 mis-anchor removed; exposure LOW, downgraded medium→low); LLR-036.1 gains the explicit `schema_ok is False` keying sentence | ✓ HLR-036 | ✓ (§6.3 R-1; §4 LLR-036.1) |
| Q-M1 (MAJOR) | HLR-038 Deliverable+observation rewritten to the surfaced-path → dir-diff → re-read observation chain (no glob reconstruction) | ✓ HLR-038 | ✓ (§3 HLR-038; mirrored in 01b AT-038a observable 1) |
| Q-M2 (MAJOR) | AT-038a "after" identity pinned to the literal `img-patched_1.s19` (collision drive); `last_summary.saved_path` demoted to diagnostic | ✓ HLR-038 | ✓ (§3 HLR-038 C-10 clause; 01b AT-038a observable 4) |
| S-F2 (minor) | LLR-038.1 gains the `_md_cell()` pipe/ctl-char escape requirement; TC-038.6 added (§5.2) | ✓ HLR-038 | ✓ |
| S-F3 (minor) | LLR-038.5 reworded: gitignored only in the default workarea layout (`app.py:4017-4027` external parents); TC asserts destination construction | ✓ HLR-038 | ✓ |
| S-F4 (minor) | LLR-038.2 acceptance gains the `reports/` `is_symlink()` refusal | ✓ HLR-038 | ✓ |
| S-F5 (minor) | LLR-038.5 inspection extended to the app.py trigger handler (paths + refusal diagnostics only in notify/status) | ✓ HLR-038 | ✓ |
| Q-m1 (minor) | AT-038b/c/d marked GUARD-class explicitly (positive-diagnostic asserts load-bearing); US-034 counterfactual = AT-038a alone | ✓ HLR-038 | ✓ (§3 HLR-038; 01b) |
| Q-m2 (minor) | 01b placeholder `action_generate_saveback_report` renamed `action_before_after_report` (matches LLR-038.3) | n/a (01b editorial) | ✓ (01b) |
| Q-m3 (minor) | 01b risk family prefixed `QR-*` (namespace collision with this file's R-1..R-5 removed) | n/a (01b editorial) | ✓ (01b) |
| Q-m4 / A-m3 (minor) | Citation anchors corrected: 01b regex anchor → `diff_report_service.py:103-113`; LLR-037.3 idempotence anchor → `app.py:7195-7197` | n/a (citations) | ✓ (both files) |
| A-m1 (minor) | LLR-037.3 pins the reorder insertion point AFTER `_compute_a2l_enriched_tags()` (`:7413`) with the cache-key-omits-enrichment rationale | ✓ HLR-037 | ✓ |
| A-m2 (minor) | LLR-038.3 gains the verify-mismatch × offer sentence (offer intentionally after the error notice; report honest disk-to-disk) | ✓ HLR-038 | ✓ |
| A-m4 (minor) | LLR-037.2 gains the map-BUILD ownership clause (`update_a2l_tags_view` builds from `self._validation_issues` + passes) | ✓ HLR-037 | ✓ |
| A-m5 (minor) | Snapshot matrix (`tests/test_tui_snapshot.py`) added to the B-1a census in R-1; exposure nil-in-expectation (`large_a2l` schema-clean) | ✓ HLR-036/037 (B-1a scope) | ✓ (§6.3 R-1) |

C-15 sweep-back executed after folding (superseded-text grep over both artifacts: old precondition list, old WARNING boundary line, `action_generate_saveback_report`, old R-1 anchor phrasing, `:5996-6009`, `:37-39` regex anchor, bare `R-N` ids in 01b) — 0 stale occurrences. `should`-as-modal scan re-run — 0 in both artifacts.

### 6.5 Requirement amendments (Before / After · Deleted / New)

Iterate-to-refine amendments, 2026-07-02 (requirement-changing folds only; editorial/citation folds are §6.4 rows without an entry here).

**AM-1 — B-1a (operator option a): NEW LLR-037.4 + Acceptance-gating change to HLR-036/HLR-037**
- **Before:** no requirement governed `update_mac_view`'s no-MAC branch; it clears `_validation_report`/`_validation_issues` and early-returns for EVERY session without MAC records (`app.py:7160-7186`), so S19+A2L sessions end issue-less regardless of what the validation engine computed. HLR-036's "cannot disagree" outcome and HLR-037's map source were both silently false in no-MAC sessions; LLR-037.3's reorder would have moved the wipe AHEAD of row-render, making it strictly worse. AT-036a/AT-037a fixtures (MAC-less by design) could never observe their outcomes.
- **After:** NEW LLR-037.4 — a loaded primary keeps/computes the validation report through the no-MAC branch (cache-routed, stable key; no-primary sessions keep the clear). HLR-036/HLR-037 Acceptance blocks now state the MAC-less fixture discipline and that their ATs gate the fix; the fix ships in I1 (which makes AT-036a's Issues-pane observable real) and I1→I2 became strict.
- **Deleted:** nothing (no prior requirement text existed for the branch — the wipe was unspecified behavior).
- **New:** LLR-037.4; TC-037.4; census additions (3 no-op monkeypatches `tests/test_tui_app.py:121,158,230`; snapshot matrix `tests/test_tui_snapshot.py`).

**AM-2 — B-2: provenance preconditions on LLR-038.2/.4 + AT-038d**
- **Before:** LLR-038.2 preconditions were "(summary present, `saved_path` non-`None`, both paths existing files)"; LLR-038.4 had three refusal classes; `ChangeSummary` recorded WHERE the patched image was written but not WHICH image it was patched from — a `last_summary` surviving a project switch would pair project B's loaded file against project A's patched image and write a false-provenance report into B's tree, with all then-specced ATs green.
- **After:** LLR-038.2 preconditions gain (4) `LoadedFile.path == summary.source_image_path` (NEW runtime-only field, stamped by `save_patched` beside `saved_path`, off `to_dict`) and (5) `saved_path` containment in the current `_active_project_dir()`/workarea at trigger time, plus the S-F4 symlink refusal; LLR-038.4 gains refusal class (4) stale-summary; HLR-038 Acceptance gains AT-038d (cross-project refusal, GUARD-class, 0 files by directory listing).
- **Deleted:** the three-class refusal enumeration ("all three refusal classes" → "all four").
- **New:** `ChangeSummary.source_image_path` (I3); AT-038d (I4).

**AM-3 — A-M1: AT-037b split**
- **Before:** AT-037b bundled two checks: "a WARNING-only symbol does NOT turn its row red" + "a symbol present in the issue map but absent from the table changes nothing"; the boundary catalog credited the WARNING check to `AT-037b`.
- **After:** AT-037b keeps only the absent-from-table symbol check (naturally producible through the shipped chain via `A2L_BROKEN_REFERENCE`, `rules.py:507`); the WARNING-no-recolour check moved to Layer-A `TC-037.2` as a GUARD over constructed issues — the only shipped-chain a2l WARNING emitters are symbol-less or never match a rendered row, so a black-box WARNING-on-rendered-row fixture is unbuildable and would have forced injection (banned for ATs).
- **Deleted:** the WARNING-recolour clause from AT-037b and its `AT-037b` boundary-catalog attribution.
- **New:** the `TC-037.2` GUARD scope now explicitly includes the WARNING no-recolour case (§5.2 unchanged in id, widened in note).

**AM-4 (I5/F2) — HLR-038 C-10 wording reconciled to the shipped drive.**
- **Before:** "the AT drives a NON-DEFAULT save-back filename that COLLIDES with a pre-planted file".
- **After:** "the AT confirms the SUGGESTED save-back name against a pre-planted COLLIDING file" — the collision is the non-default drive (on-disk identity differs from the displayed name); the discriminator (header equality on `img-patched_1.s19`) is unchanged and fails on any name echo.
- **Why:** I4 review F2 — the spec's own parenthetical always pinned the `img-patched.s19` suggested-name drive; the sentence was internally inconsistent. Deleted: none. New: none. Parent HLR re-read: no other impact.

**Traceability note (I5/F3):** AT-038d's "open project B" step is state-level (`current_project` assignment + the ratified `_load_image` drive), not the LoadProjectScreen path — the guarded state is verified reachable in the shipped app (single `ChangeService`, `last_summary` never cleared on switch). If a future batch adds last-summary invalidation to the real project-switch path, re-derive this AT. Recorded for Phase-4/6 traceability.

### 6.6 Increment roadmap (proposed — ≤5 files each, each story independently gateable)

| Inc | Story | Content | Files (≤5) | Gate |
|-----|-------|---------|------------|------|
| I1 | US-032 + B-1a | LLR-036.1/.2/.3 supplemental rule + merge; LLR-037.4 no-MAC retention fix (`update_mac_view`); TC-036.1-4 + TC-037.4 + AT-036a/b/c | `tui/services/validation_service.py`, `tui/app.py`, `tests/test_validation_service_supplemental.py` (NEW), `REQUIREMENTS.md` — 4 files | AT-036a red→green flip on BOTH observables (the Issues-pane observable requires LLR-037.4); TC-037.4 retention green; suite 0 new fails; TC-027/031 green |
| I2 | US-033 | LLR-037.1/.2/.3 map + precedence + reorder; TC-037.1-3 + AT-037a/b | `tui/app.py`, `tests/test_tui_app.py` (or sibling), `REQUIREMENTS.md` | AT-037a flip; duplicate rows red on first render |
| I3 | US-034 (service half + provenance stamp) | LLR-038.1 generator kwargs + byte-identical regression + `_md_cell()` (S-F2); B-2 stamp (`ChangeSummary.source_image_path` field + `save_patched` kwarg); TC-038.1/.2/.6 + stamp TC | `tui/services/diff_report_service.py`, `tests/test_diff_report_service.py`, `tui/changes/model.py`, `tui/services/change_service.py`, `tests/test_change_service.py` — 5 files | byte-identical case green; linkage/header/escape render green; stamp TC green |
| I4 | US-034 (composer + trigger) | LLR-038.2/.3/.4/.5; TC-038.3-5 + AT-038a/b/c/d | `tui/services/before_after_service.py` (NEW), `tui/app.py` (trigger + handler passes `source_image_path`), `tests/test_before_after_report.py` (NEW), `REQUIREMENTS.md` — 4 files | AT-038a C-12 surfaced-path→dir-diff→re-read gate; 4 refusal classes write 0 files (incl. AT-038d stale-summary) |
| I5 | close | Traceability reconciliation (V-5 id reconcile), REQUIREMENTS §30/§31 coherence, docs *(pointer corrected at Phase 6 — originally said §29, batch-23's section)* | `REQUIREMENTS.md`, batch artifacts | full suite + guards green |

Dependency: **I1 → I2 STRICT** (B-1a: LLR-037.4 ships in I1, and AT-037a's map source `_validation_issues` is wiped pre-fix in every MAC-less session — I2's gate cannot pass without it); I3 → I4 strict; US-034 (I3/I4) independent of I1/I2.

---

## Architect evidence checklist (Phase-1 gate)

- [✓] **Constraints stated explicitly** — §2.5/§2.6 DoR block + hard constraints (frozen set P-7, C-13 N/A, ≤5 files §6.6, public issue-code contract HLR-036 rationale).
- [✓] **≥2 alternatives considered** — §6.2 D-1 (composer placement, 3 options), D-2 (WARNING policy), D-3 (no-project trigger).
- [✓] **Recommendation tied to constraints** — D-1 ties to orchestration-only + byte-identical regression; D-2 ties to REQUIREMENTS.md:362-367.
- [✓] **Risks listed** — §6.3 R-1…R-5 (operational, contract, e2e-stall, security A-4).
- [✓] **Cost/latency estimated where relevant** — LLR-037.1 acceptance (O(issues) build, O(1)/row over ≤ page_size rows); no LLM/API cost surface in this batch.
- [✓] **Diagram** — N/A with reason: no new cross-component flow; both reconcile directions are single-seam merges and US-034 reuses the batch-09 documented pipeline (`compare_service.py:1-23` module map).
- [✓] **What would change the recommendation** — if Phase 3 finds `tags_for_validation` un-enriched on any live path (A-1 fails), LLR-036.1 moves its predicate to the enrichment output in `a2l_service`; if REQUIREMENTS owners later ratify an A2L orange, D-2 reopens via §6.5.
- [✓] **Two-layer requirements** — every story has a first-class Acceptance block + AT-036*/037*/038*, and both chains exist (§5.2 behavioral + functional).
