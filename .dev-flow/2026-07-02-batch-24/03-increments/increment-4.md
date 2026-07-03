# Increment 4 — US-034 composer + trigger — LLR-038.2 / 038.3 / 038.4 / 038.5 + AT-038a/b/c/d

> Batch `2026-07-02-batch-24` · branch `claude/batch-24-feat12` · base `origin/main 9d2123c` · agent: software-dev · 2026-07-02 · I1-I3 present uncommitted and green (ledger 1027 at I3 close).
>
> **Split-authorship note (interruption credit):** this increment was executed by TWO software-dev agent sessions. Agent A (died mid-increment on a session limit) authored: `before_after_service.py` complete (354 lines), `tests/test_before_after_report.py` complete (10 nodes), AND — more than the orchestrator's tree-state briefing credited — most of the app.py wiring: the `source_image_path=loaded.path` B-2 handler pass, the key-`b` `Binding` (app.py:684), the LLR-038.3 offer notify after `_surface_verify_result` (app.py:1642-1653), the composer import (app.py:66), and the save-back handler docstring. Agent B (this session) verified all of that on disk instead of regenerating it, then completed: the RED capture, the missing `action_before_after_report` method, the `_strip_ctl` factoring, REQUIREMENTS.md §31, and this document. Agent A's mid-flight checkpoint made the RED capture below possible.

---

## 0. RED capture (AT-038a story counterfactual — captured on the pre-completion tree)

Run BEFORE any Agent-B edit (`python -m pytest tests/test_before_after_report.py -q`), verbatim tail:

```
FAILED tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path
FAILED tests/test_before_after_report.py::test_at_038b_declined_saveback_trigger_refuses_and_writes_nothing
FAILED tests/test_before_after_report.py::test_at_038c_missing_original_trigger_refuses_and_writes_nothing
FAILED tests/test_before_after_report.py::test_at_038d_stale_summary_cross_project_refusal_writes_nothing
FAILED tests/test_before_after_report.py::test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair
5 failed, 5 passed in 5.53s
```

- **AT-038a/b/c/d RED = trigger absent.** Key `b` was bound but `action_before_after_report` did not exist → pressing `b` produced no file (AT-038a dir-diff assert failed with `new_files == []`) and no surfaced refusal (b/c/d positive-diagnostic asserts failed). Exactly the specced counterfactual: the absent deliverable IS the RED.
- **TC-038.3-ctl RED = HTML-only leak.** Pinpointed by a debug script before editing: the `\x01` in `CTL\x01SYM` reached ONLY the html file (`<td>CTL\x01SYM</td>` at offset 1468 — `_esc` escapes markup but does not strip); the md file was ALREADY clean via `_md_cell`. (The raw pytest multi-operand display suggested both formats leaked; that read was wrong — verified, not assumed.) This is precisely the increment-3 reviewer's named I4 recommendation.
- The 5 already-passing nodes were Agent A's composer-seam TCs (TC-038.3 happy/symlink, TC-038.4 ×2, TC-038.5) — the composer service was complete and correct as left.

## 1. What changed

**Agent A's half (pre-existing on the tree, verified — not regenerated):**
- **LLR-038.2 — `s19_app/tui/services/before_after_service.py` (NEW, 354 lines):** `compose_before_after_report` validating the five preconditions in order (summary present → `saved_path` stamped → both paths on disk → B-2 `source_image_path` match → B-2 containment in project dir/workarea), D-3 no-project refusal naming the manual A↔B path, S-F4 `reports/` symlink refusal, `compare_images` over two `SOURCE_EXTERNAL` sources, headless `_load_map` re-parse (the `_diff_load_maps` pattern service-side), both LLR-038.1 generators invoked with provenance/linkage + the owned `before-after-report` stem; owned `BEFORE_AFTER_REPORT_FILENAME_REGEX`/`_HTML_` twins; `BeforeAfterReportResult` (paths | diagnostics, never raises, never writes on refusal). No Textual import, no logging (LLR-038.5 / F-S-07).
- **`tests/test_before_after_report.py` (NEW, 694 lines, 10 nodes):** AT-038a (C-10 collision drive pinning `img-patched_1.s19` + C-12 surfaced-path → dir-diff → re-read chain + S-F5 no-byte-leak sweep), AT-038b/c/d (GUARD-class, Q-m1 positive-diagnostic asserts), TC-038.3 ×3, TC-038.4 ×2, TC-038.5. Composer imported lazily so the file collects on the pre-implementation tree — the property that made the RED capture possible.
- **app.py trigger wiring (except the action):** `source_image_path=loaded.path` pass into `save_patched` (B-2 handler half), `Binding("b", "before_after_report", ...)` (key verified still free — the P-6 provisional choice held), offer notify (`severity="information"`, names `before_after_report` + "press b") placed AFTER `_surface_verify_result` so a verify-mismatch error notice is never masked (A-m2).

**Agent B's half (this session):**
- **LLR-038.3 — `app.py::action_before_after_report` (the missing piece):** invokes the composer with `last_summary`, `loaded.path`, `_active_project_dir()`, `self.workarea`; surfaces `"Before/after report written: <md> | <html>"` or `"Before/after report refused: <diagnostics>"` on the status line — paths/diagnostics only, never entry byte content (LLR-038.5 / S-F5). No precondition pre-duplication: the composer owns all refusal classes. Inserted beside `_surface_verify_result` to keep the LLR-038.3 code together; PROJECT_RULES docstring with LLR refs.
- **`_strip_ctl` factoring — `diff_report_service.py` (increment-3 reviewer recommendation, exactly as scoped):** the ctl-strip half of `_md_cell` factored into a shared `_strip_ctl(value) -> str`; applied INSIDE the two new html helpers only (`_html_provenance`, `_html_linkage` — every parsed-artifact value now `_esc(_strip_ctl(...))`; `_bytes_cell` output is generated hex, left through `_esc` alone). The default diff-report path never reaches these helpers → golden untouched (proven green, §4a).
- **REQUIREMENTS.md §31** — `R-BEFORE-AFTER-REPORT-001` (Automated, real node names, §29/§30 format) + subsystem-list entry 27.
- No test expectation was bent and no spec deviation was needed: all 10 nodes went green against the code as specced (the 5 failures were authored-to-spec RED, not authoring errors).

## 2. Files modified

| File | Change | Author | LOC |
|---|---|---|---|
| `s19_app/tui/services/before_after_service.py` | NEW — LLR-038.2 composer | Agent A | +354 (new file) |
| `tests/test_before_after_report.py` | NEW — AT-038a-d + TC-038.3/.4/.5 | Agent A | +694 (new file) |
| `s19_app/tui/app.py` | B-2 pass + binding + offer notify (A) · `action_before_after_report` (B) | A + B | A: ~+25 · B: +49 |
| `s19_app/tui/services/diff_report_service.py` | `_strip_ctl` factored out of `_md_cell`, applied in `_html_provenance`/`_html_linkage` | Agent B | +44/−28 |
| `REQUIREMENTS.md` | §31 + subsystem-list entry | Agent B | +14 |

**5 files — at the hard cap, ONE over the roadmap's stated 4.** Deviation flagged: §6.6's I4 row predates the increment-3 gate addendum, which NAMED the `_strip_ctl`-in-html-helpers work as an I4 recommendation and the orchestrator's resume brief instructed it as Step 2 — `diff_report_service.py` is that instructed addition. Within the ≤5 cap; no approval breach. Engine-frozen set untouched (guard suite green, §4b).

## 3. How to test

```bash
python -m pytest tests/test_before_after_report.py tests/test_diff_report_service.py tests/test_change_service.py -q
python -m pytest tests/test_tui_patch_editor_v2.py tests/test_tui_diff_compare_realpath.py tests/test_engine_unchanged.py -q
python -m ruff check s19_app/tui/app.py s19_app/tui/services/diff_report_service.py s19_app/tui/services/before_after_service.py tests/test_before_after_report.py
```

## 4. Test results (real output)

### 4a. Target suites — all green, golden byte-identical intact

```
$ python -m pytest tests/test_before_after_report.py tests/test_diff_report_service.py tests/test_change_service.py -q
.......................................................                  [100%]
55 passed in 5.26s
```

(10 before-after — the 5 RED flipped green, 5 stayed green — + 42 diff-report incl. `test_default_kwargs_output_byte_identical_pre_change_golden` + `test_pipe_bearing_symbol_md_escaped_html_intact`, + 3 change-service B-2 stamp TCs. The `_strip_ctl` factoring perturbed neither the golden nor the md pipeline.)

### 4b. Targeted regression (instructed set) — incl. engine-frozen guard

```
$ python -m pytest tests/test_tui_patch_editor_v2.py tests/test_tui_diff_compare_realpath.py tests/test_engine_unchanged.py -q
..................................                                       [100%]
34 passed in 30.23s
```

### 4c. Ruff — clean on all 4 touched code files

```
$ python -m ruff check s19_app/tui/app.py s19_app/tui/services/diff_report_service.py s19_app/tui/services/before_after_service.py tests/test_before_after_report.py
All checks passed!
```

(The two pre-existing F401s noted at I3 §4c live in `change_service.py`/`test_diff_report_service.py` — outside this increment's touched set; still the batch-close hygiene candidate.)

### 4d. Ledger delta

`pytest -q -m "not slow" --collect-only` → **1037/1058 collected (21 deselected)** — was 1027 → **+10** (the 10 `test_before_after_report.py` nodes), 0 removed, 0 rewritten.

Full suite deliberately NOT run per scope instruction ("NOT the full suite") — that is the I5/close gate.

## 5. Risks

- **`\x01`-class chars below 0x20 vs C1 range (0x80-0x9F):** `_strip_ctl` strips C0 + 0x7F only (the I3 reviewer's optional C1-range LOW finding stands unaddressed, unchanged in scope). Cosmetic exposure; both formats now behave identically.
- **Status-line format is now a de-facto contract:** AT-038a parses `"Before/after report written: <md> | <html>"` by splitting on `|`. A future path containing `|` would break the parse — impossible for the F-S-01-sanitized filenames and workarea paths in play, noted for awareness.
- **Missing-action window:** between Agent A's binding landing and Agent B's action method, key `b` was bound to a nonexistent action (benign at runtime — the RED run showed no crash, just no effect). No such window survives on the tree.

## 6. Pending items

- I5 (close): traceability reconciliation (V-5 id reconcile), full non-slow suite + guards at the gate, batch artifacts, REQUIREMENTS §30/§31 rollup cross-check.
- Batch-close hygiene candidates carried from I3: pre-existing F401 pair; optional C1-range strip (LOW).

## 7. Suggested next task

I5 — batch close: full `pytest -q -m "not slow"` + TC-027/TC-031 frozen guards, V-5 provisional-id reconciliation across 01/01b, close snapshot + PR.

---

## Coverage table (I4 scope)

| Requirement | AT/TC | Test node (`tests/test_before_after_report.py`) | Result |
|---|---|---|---|
| HLR-038 story gate (C-10 + C-12, Q-M1 chain) | AT-038a | `test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` | RED (§0) → **PASS** |
| LLR-038.4 class 2 (declined save) | AT-038b | `test_at_038b_declined_saveback_trigger_refuses_and_writes_nothing` | RED → **PASS** |
| LLR-038.4 class 3 (original gone) | AT-038c | `test_at_038c_missing_original_trigger_refuses_and_writes_nothing` | RED → **PASS** |
| LLR-038.2 pre-4/5 + LLR-038.4 class 4 (B-2 stale) | AT-038d | `test_at_038d_stale_summary_cross_project_refusal_writes_nothing` | RED → **PASS** |
| LLR-038.2 happy + regex ownership | TC-038.3 | `test_tc_038_3_composer_happy_path_and_regex_ownership` | PASS |
| LLR-038.2 S-F4 symlink refusal | TC-038.3 | `test_tc_038_3_symlink_reports_destination_refused` | PASS |
| LLR-038.1 `_strip_ctl` md/html pair consistency | TC-038.3 | `test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair` | RED (html-only leak) → **PASS** |
| LLR-038.4 classes 1-4 + containment (0 files each) | TC-038.4 | `test_tc_038_4_all_refusal_classes_write_no_files` | PASS |
| LLR-038.4 / D-3 no-project refusal | TC-038.4 | `test_tc_038_4_no_project_refusal_names_manual_ab_path` | PASS |
| LLR-038.5 purity + destination construction (S-F3, V-4) | TC-038.5 | `test_tc_038_5_module_imports_no_textual_and_no_logging` | PASS |
| LLR-038.3 offer notify + key `b` + S-F5 no-byte-leak | (asserted inside AT-038a) | offer/severity/"press b" + byte-leak sweep asserts in AT-038a | PASS |
| LLR-038.2/.5 confidentiality of surfaced text (S-F5) | inspection | handler surfaces paths/diagnostics only (`action_before_after_report`, verified + AT-038a sweep) | PASS |

(LLR-038.1's own TC-038.1/.2/.6 + the B-2 stamp TCs remain green under I3's nodes — re-run in §4a's 55.)

## Evidence checklist

- [✓] Tests/type checks/lint pass — §4a/4b real output (89 passed across the two runs); ruff clean (§4c); full suite deliberately deferred to I5 per scope.
- [✓] No secrets in code or output — synthetic fixtures only; TC-038.5 pins no-logging/no-Textual; S-F5 byte-leak sweep green inside AT-038a.
- [✓] No destructive commands run without approval — read/edit/pytest/ruff only; no stash, no reset, `image_path.unlink()` happens only inside AT-038c's tmp_path sandbox.
- [✓] File count within cap — 5/5; the 5th (`diff_report_service.py`) is the gate-addendum-instructed `_strip_ctl` factoring, flagged in §2.
- [✓] Review packet attached — this document.

---

## Orchestrator gate addendum (2026-07-03)

- **Independent code review: OK-TO-ADVANCE** — 0 HIGH/MEDIUM, 3 LOW carried to I5 (F1 orphan-md-on-html-refusal optional hygiene; F2 HLR-038 "NON-DEFAULT" wording vs the spec's own pinned suggested-name drive — one-line V-5 reconcile; F3 AT-038d state-level switch note). Composer conformant clause-for-clause (containment = resolve()+is_relative_to); cross-agent seam clean (no mismatch/phantom/dead params); AT-038a audited genuine C-10+C-12 with credible RED; _strip_ctl applied only in the 2 html helpers; golden confirmed green by construction + run.
- **Full non-slow suite (orchestrator-run): 0 FAILED** (tail above). Ledger: 1027 − 0 + 10 = **1037** ✓.
- **Frozen set: 0-diff** (reviewer-confirmed; test_engine_unchanged green).
