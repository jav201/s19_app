# Increment 3 — US-034 service half — LLR-038.1 (generator kwargs) + LLR-038.2 B-2 provenance stamp

> Batch `2026-07-02-batch-24` · branch `claude/batch-24-feat12` · base `origin/main 9d2123c` · agent: software-dev · 2026-07-02 · I1+I2 present uncommitted in the working tree. The composer service (`before_after_service.py`) and the app trigger are **I4 — deliberately NOT here**.

---

## 1. What changed

- **LLR-038.1 — generator kwargs (`diff_report_service.py`).** `generate_diff_report` and `generate_diff_report_html` gain three optional keyword arguments, ALL default-off:
  - `provenance: Optional[BeforeAfterProvenance]` — NEW frozen dataclass defined in this module (param-shape decision): `original_path: Path`, `saved_path: Path`, `applied_at_utc: str` (carries `ChangeSummary.timestamp_utc`), `change_doc_path: Optional[Path]` (carries `ChangeSummary.source_path`). When given, a `## Before/after provenance` section (md) / `<h2>` block (html) renders immediately after the existing header — original path, saved (post-dedup) path, apply instant, change-doc origin (`(in-memory document)` for `None`).
  - `linkage_entries: Optional[Sequence[ChangeSummaryEntry]]` — duck-typed consumption of the summary entries (`entry_type`, `address_start/end`, `disposition`, `linkage`, `linkage_symbol`, `before_bytes/after_bytes`); the import is `TYPE_CHECKING`-only, so no runtime coupling from the diff-report module into `changes/`. When given (INCLUDING empty), a `## Change-entry linkage` table renders after the provenance slot — one row per entry, ALL dispositions (01b Layer-A row: "incl. skipped/failed"); empty renders `No entries.` (TC-038.2). `before_bytes=None` renders the explicit marker `(none - created into hole)`, never fabricated bytes (R-4).
  - `filename_stem: Optional[str]` — kind-stem override threaded into `_diff_report_filename` (internal helper gains `stem: str = "diff-report"`); `None` keeps the `diff-report` scheme byte-identical, so `DIFF_REPORT_FILENAME_REGEX` / the shared `REPORT_FILENAME_REGEX` are untouched (regex-unedited tests still green).
- **S-F2 — NEW `_md_cell()`** (md side only, per the LLR): strips control characters (`ord < 0x20` and `0x7F` — which covers the row-breaking `\n`/`\r`) and escapes `|` as `\|`. Every provenance/linkage value rendered into the Markdown output routes through it; the HTML side routes every value through the existing `_esc` (unchanged). NEW `_bytes_cell()` shared by both formats for the byte-run/marker rendering.
- **LLR-038.2 (B-2 stamp half) — `changes/model.py`:** `ChangeSummary.source_image_path: Optional[Path] = None`, appended after `verify_result`; **explicitly EXCLUDED from `to_dict`** with a docstring line saying why (runtime-only carrier mirroring `verify_result`; serializing would break byte-stability). Verified on disk before editing: `to_dict` (now ~:470-530) serializes `saved_path` and never the two runtime-only fields.
- **LLR-038.2 (B-2 stamp half) — `change_service.py`:** `save_patched` gains `source_image_path: Optional[Path] = None`, stamped onto `last_summary.source_image_path` in the SAME statement block as the existing `saved_path` stamp (verified on disk at :921-922 pre-edit). The app handler wiring (`loaded.path` at the save-back prompt) is I4 — NOT touched here.
- **Tests:** 4 new in `test_diff_report_service.py` (TC-038.1 ×2, TC-038.2, TC-038.6), 3 new in `test_change_service.py` (stamp present / absent / serialization-stability).

**Byte-identical-regression approach (stated per scope instruction): golden capture BEFORE editing.** The pre-change module (verified resolving from THIS worktree, not the editable install) generated one md + one html report under a fixed clock; the exact bytes were captured, the live `__version__` templated as `@@VERSION@@`, and the text embedded as `repr`-literal constants in the test (self-checked by exec-compare at capture time, transcription-error-proof). The test regenerates with default kwargs and asserts `read_bytes() ==` the reconstructed golden. Platform note: `write_text` translates `\n` → `os.linesep`, so the pre-change bytes are CRLF on Windows and LF on CI Linux — the test expands the LF-normalized golden with `os.linesep`, preserving exact byte identity on BOTH platforms (the pre-change writer applied the identical translation). Secondary asserts: neither new section heading appears anywhere in default output; default filenames unchanged.

## 2. Files modified

| File | Change | LOC (I3-only, `git diff --numstat HEAD` — no I1/I2 overlap on these 5) |
|---|---|---|
| `s19_app/tui/services/diff_report_service.py` | `BeforeAfterProvenance` + `_md_cell` + `_bytes_cell` + `_provenance_lines` + `_linkage_table_lines` + `_html_provenance` + `_html_linkage` + `_diff_report_filename` stem + 3 kwargs on both generators + docstrings | +345/−10 |
| `s19_app/tui/changes/model.py` | `source_image_path` field + Args entry + to_dict exclusion docstring | +12/−1 |
| `s19_app/tui/services/change_service.py` | `save_patched` kwarg + stamp beside `saved_path` + docstring | +12/−1 |
| `tests/test_diff_report_service.py` | golden constants + `_entry`/`_provenance` fixtures + 4 TC-038 tests + header map | +276/−0 |
| `tests/test_change_service.py` | 3 LLR-038.2 tests | +83/−0 |

5 files — exactly at the hard cap. Engine-frozen set untouched (`changes/` and `services/` are open per P-7; guard suite green, §4b).

## 3. How to test

```bash
python -m pytest tests/test_diff_report_service.py tests/test_change_service.py -q
python -m pytest tests/test_tui_diff_compare_realpath.py tests/test_compare_service.py tests/test_tui_patch_editor_v2.py tests/test_engine_unchanged.py -q
python -m ruff check s19_app/tui/services/diff_report_service.py s19_app/tui/changes/model.py s19_app/tui/services/change_service.py tests/test_diff_report_service.py tests/test_change_service.py
```

## 4. Test results (real output)

### 4a. Target suites — all green, including the byte-identical and serialization-stability asserts

```
$ python -m pytest tests/test_diff_report_service.py tests/test_change_service.py -q
.............................................                            [100%]
45 passed in 0.67s
```

(38 pre-existing + 7 new. First run had 2 REAL failures, both Windows-platform artifacts in MY test asserts, not in product code: (1) golden compared LF while `write_text` emits CRLF on Windows → fixed with the `os.linesep` expansion documented in §1; (2) `str(Path("/tmp/x"))` renders backslashed on Windows → asserts now compare against `str(provenance.<field>)`. Product code unchanged by either fix.)

### 4b. Targeted regression (instructed set)

```
$ python -m pytest tests/test_tui_diff_compare_realpath.py tests/test_compare_service.py tests/test_tui_patch_editor_v2.py tests/test_engine_unchanged.py -q
..............................................                           [100%]
46 passed in 31.95s
```

### 4c. Ruff — 0 NEW findings

```
$ python -m ruff check <the 5 touched files>
Found 2 errors.   # F401 typing.List (change_service.py:38), F401 DiffReportResult (tests/test_diff_report_service.py:67)
```

Both findings verified PRE-EXISTING: `git stash` → same 2 errors on the unmodified tree → `git stash pop` (tree restored, I1+I2 intact). Left un-fixed per the surgical rule (adjacent-cleanup ban); neither line was touched by I3.

### 4d. Ledger delta

`pytest -q -m "not slow" --collect-only` → **1027/1048 collected (21 deselected)** — was 1020 → **+7** (4 diff-report + 3 change-service), 0 removed, 0 rewritten.

## 5. Risks

- **Golden brittleness by design:** any future intentional change to default diff-report output will fail `test_default_kwargs_output_byte_identical_pre_change_golden` — that is the point; the golden must then be consciously re-captured (procedure documented in the constant's comment).
- **`_md_cell` on non-table md values:** provenance bullet values also pass `_md_cell` (pipes escaped in bullets too) — slightly stronger than the S-F2 table-cell minimum, chosen for uniformity; cosmetic-only for pipe-bearing paths.
- **HTML control chars:** `_esc` does not strip control characters (S-F2 assigns stripping to the md cell pipeline only); a ctl-char symbol reaches the html file escaped-context-safe but present. Flagged for the I4 composer review if stripping should be format-uniform.
- **Linkage section position** (after header, before Statistics) was a design call — the LLRs fix content, not position; cheap to move at I4 review.

## 6. Pending items

- **I4 (next increment):** `before_after_service.py` composer (preconditions 1-5, `SOURCE_EXTERNAL` compare, own `BEFORE_AFTER_REPORT_FILENAME_REGEX` twins, S-F4 symlink refusal), app trigger (`action_before_after_report`, key `b`, notify offer), handler passing `loaded.path` into the new `save_patched` kwarg — **and the story counterfactual: AT-038a RED lands at I4** (the trigger does not exist yet; its absence IS the RED). Stated explicitly per scope: this service-half increment's gate is the byte-identical regression + the new-content unit proofs, not a story-level AT.
- TC-038.3/.4/.5 (composer/trigger/inspection TCs) — I4 scope.
- Pre-existing ruff F401 pair (change_service.py `List`, test file `DiffReportResult`) — candidate for the batch-close hygiene sweep, not this increment.

## 7. Suggested next task

I4 — US-034 composer + trigger (LLR-038.2 remainder, LLR-038.3, LLR-038.4, LLR-038.5) with AT-038a/b/c/d; checkpoint before the long Pilot e2e run (R-3, batch-20/21 stall precedent).

---

## Coverage table (I3 scope)

| Requirement | TC/assert | Test node | Result |
|---|---|---|---|
| LLR-038.1 kwargs render (both formats) | TC-038.1 | `test_provenance_and_linkage_render_in_both_formats` | PASS |
| LLR-038.1 byte-identical default | TC-038.1 | `test_default_kwargs_output_byte_identical_pre_change_golden` | PASS |
| LLR-038.1 0-entries "no entries" | TC-038.2 | `test_zero_entries_linkage_states_no_entries` | PASS |
| LLR-038.1 `before_bytes=None` marker (R-4) | TC-038.1 | marker + no-hex-cell asserts inside `..._render_in_both_formats` | PASS |
| LLR-038.1 S-F2 `_md_cell` | TC-038.6 | `test_pipe_bearing_symbol_md_escaped_html_intact` | PASS |
| LLR-038.1 filename-stem override / regex untouched | TC-038.1 | stem asserts in `..._render_in_both_formats`; pre-existing `test_report_service_regex_unedited` + filename tests | PASS |
| LLR-038.2 provenance stamp (service seam) | TC row 1 | `test_save_patched_stamps_source_image_path` | PASS |
| LLR-038.2 stamp absent when not passed | TC row 2 | `test_save_patched_without_kwarg_leaves_source_image_path_none` | PASS |
| LLR-038.2 to_dict byte-stability | TC row 3 | `test_to_dict_excludes_source_image_path_and_stays_byte_stable` | PASS |
| HLR-038 story AT | AT-038a-d | **I4 — not this increment (counterfactual carrier lands with the trigger)** | pending |

## Evidence checklist

- [✓] Tests/type checks/lint pass — §4a/4b real output; ruff 0 new findings (§4c); full suite deliberately NOT run per scope ("NOT the full suite").
- [✓] No secrets in code or output — synthetic fixtures only; no logging added (F-S-07 test `test_module_performs_no_logging` still green in §4a's 45).
- [✓] No destructive commands run without approval — `git stash`/`stash pop` used read-only-equivalently for the ruff baseline; tree verified restored (`git status` matched pre-stash, I1+I2 intact).
- [✓] File count within cap — 5/5 exactly (§2).
- [✓] Review packet attached — this document.

---

## Orchestrator gate addendum (2026-07-02)

- **Independent code review: OK-TO-ADVANCE** — 0 HIGH/MEDIUM, 2 LOW (backtick code-span cosmetic; C1-range strip optional). **Golden-capture independently RE-DERIVED**: reviewer ran the unedited module from a detached worktree @origin/main, byte-matched both formats (2437B md / 2386B html MATCH) — byte-identical proven twice. Stamp-on-refusal audited harmless (unreachable by composer preconditions; re-stamped every save). No _md_cell bypass (grep clean). NAMED I4 RECOMMENDATION: shared `_strip_ctl` applied inside the two new html helpers only (pair consistency without perturbing the golden).
- **Full non-slow suite (orchestrator-run): 0 FAILED** (tail above this addendum in the task log). Ledger: 1020 − 0 + 7 = **1027** ✓.
- **Frozen set: 0-diff** (confirmed by reviewer + direct check).
