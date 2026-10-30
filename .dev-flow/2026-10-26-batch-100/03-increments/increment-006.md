# Increment 006 — HLR-168 / HLR-178 · `save-back active variant, manifest carry, the Load-result panel (PH-4, D2, O-1, O-10, P-E)`

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `006` |
| Lane | `main` · 4 SOURCE files (⚠ at cap, design proposal §5.6) |
| Requirement(s) | `HLR-168 · LLR-168.1 · LLR-168.2 · LLR-168.3` · `HLR-178 · LLR-178.1 · LLR-178.2 · LLR-178.3` · `LLR-166.1` (TC-B100-12 panel arms) · US-158 · US-168 |
| Acceptance | `AT-B100-06 · AT-B100-19 · AT-B100-20` (new) · `AT-B100-04` (Inc 6 arm: dismiss the panel first) · `AT-B100-05` (Inc 6 arm: panel oracle) · white-box `TC-B100-18 · -19 · -20 · -55 (reasons, counts) · -56 · -67 · -12 (panel arms)` |
| Interfaces | freezes B100-I2 (`gathered`) and B100-I7 (the carry); consumes B100-I13 (`place_into_workarea`) and the Inc 5 seam `_write_and_verify_manifest` |
| Agent | `software-dev` (Claude, replacing Kimi; briefs `kimi/BRIEF-COMMON.md`, `kimi/BRIEF-inc-6.md`) |
| Date | `2026-10-29` |
| Base | `main` `093a7c0` (Inc 1–5 + hotfix 3b merged) |
| Import proof | `C:\Users\jjgh8\Github\s19_app-b100-inc6\s19_app\__init__.py` — `.dev-flow/2026-10-26-batch-100/evidence/inc-6/import-proof.txt` |

---

## 1 · What changed

BLUF: a save-back into the open project now becomes the project's active variant, in the session and in `project.json`, so Load reopens the patched image (P-3 closed). Every in-project writer (save-back, Load-file variant append, MAC sync, A2L sync) rewrites `project.json` through the one seam and carries the keys it does not own. A project load composes an announcement: one summary line in the status log, the project + opened file as the last `#status_text`, and — on the Load project dialog route — the Load-result panel (P-E verdict B).

**The reader (LLR-168.1, B100-I2) — `variant_execution_service.py`.**
- `ProjectManifest.gathered: dict[str, list[Path]]`, parsed like `assignments`: each entry through `_resolve_manifest_entry` (context `gathered[<home>]`); a non-object value or a non-array home gives one `MANIFEST-BAD-STRUCTURE` and is skipped; an absent key gives `{}` and no issue.

**The carry (LLR-168.2 / LLR-168.3, B100-I7) — `app.py`.**
- `_manifest_carry(project_dir) -> dict` reads the manifest back and converts `batch`, `assignments`, `gathered` from the reader's absolute paths to project-relative POSIX strings (relative to the same resolved root the reader used) and passes `declared_regions` through. It returns `{}` when the project has no `project.json`.
- `_activate_project_file(project_dir, landed) -> Optional[str]` rebuilds the variant set, activates the landed file's variant (filename match, the E6 duplicate-id rule) and stamps `current_file.variant_id`. The append's inline block moved here unchanged in behaviour.
- **Save-back:** after a successful `save_patched` into the open project, `_activate_project_file(..., last_summary.saved_path)` then `_write_and_verify_manifest(project_dir, **_manifest_carry(project_dir))`. `current_file.path` is not touched. No project open → no manifest write.
- **Variant append:** after the placement, `_activate_project_file`, the seam with the carry, and the status line `Project '<P>' now opens <file>` (painted before the existing `Added variant …` / `Variant … already in project` line, so that line stays the newest — the Inc 1 pins hold).
- **MAC and A2L syncs:** the three `copy_into_workarea` calls became `place_into_workarea` (with `workarea_root`), and a sync that placed a file ends in the seam with the carry.
- **What the carry holds at Inc 6:** the four keys the writer emits today (`batch`, `assignments`, `declared_regions`, `gathered`). `derived_from` (Inc 7) and `active_document` (Inc 8a) are not yet serialized, so they cannot be carried; their carry arms land with them (§6).

**The announcement (LLR-178.1) — `variant_execution_service.py`.**
- `compose_load_announcement(project_name, variant_set, manifest, *, mac_name, a2l_name) -> LoadAnnouncement` (pure). Reason: no manifest → `no-manifest`; size cap / JSON parse / top level not an object → `manifest-damaged`; no `active_variant` → `none-recorded`; recorded == opened → `recorded`; otherwise `next-valid` plus a `Missing variant` problem.
- `LoadAnnouncement` (frozen): `project, opened, position, count, reason, latest, others, mac, a2l, problems`; `reason_text` (user terms, `LOAD_REASON_TEXT`), `status_line()`, `summary_line(width=118)` (names clipped, never the counts, so `details: p` stays inside 118 columns).
- `LoadProblem(label, file, detail, rank)`. Manifest findings map to user terms by code (`Manifest damaged` / `Manifest entry skipped`, each with its next step); the code and the finding message (which can carry an exception class name) never reach the panel. `latest` is true only for `recorded` — never from file times.
- The top-level "not a JSON object" message became a module constant (`_MANIFEST_TOP_LEVEL_MESSAGE`) so the composer recognises a damaged manifest without parsing text; the message is byte-identical. *(Superseded in corrective pass 1: the constant is removed and the finding carries a `scope` mark — F5b.)*

**The summary line and `#status_text` (LLR-178.2) — `app.py`.**
- `_handle_load_project` composes the announcement after the loads, keeps it as `_last_load_announcement` (in `_SESSION_SNAPSHOT_NAMES`), writes `safe_text(summary_line()).plain` to the status log IN PLACE OF the old `Loaded project 'P' -> x` line (the summary keeps that prefix), then sets `#status_text` to `safe_text(status_line())`. The loads are synchronous and no later step writes `#status_text`, so this is its last writer until Inc 12's `end_busy`.
- Example: `Loaded project 'P' -> firmware_1.s19 - variant 2 of 2, 0 problems - details: p`.

**The Load-result panel (LLR-178.3) — `screens.py` + `styles.tcss`.**
- `LoadResultScreen(ModalScreen)` on the `pe_B` ids: `#result_body` (a `VerticalScroll`: summary block, heading, one `.result-problem` `Static` per problem, no truncation), `#result_variant` ("Select variant (v)", reached by its key, not by `tab`), `#result_ok` ("Close (esc)"). Focus starts on `#result_body`; `escape` closes from anywhere; `enter` closes only on `#result_ok` (the button's own press); `v` dismisses with `LOAD_RESULT_SELECT_VARIANT`. Every disk name renders through `safe_text`.
- `app.py`: the Load project dialog's callback is now `_route_load_project`, which runs `_handle_load_project` and pushes the panel when that load composed a new announcement; `_handle_load_result` runs `action_select_variant` on `v`. A direct `_handle_load_project` call meets no modal (contract §5.4).
- Focus after the panel closes (TC-B100-12 panel arms): the load tail already re-homes the main screen's focus behind the modal, and closing the panel restores it — no extra call (an explicit re-home in the callback was tried and removed: the arms pass with and without it, §4).
- `styles.tcss`: `#load_result_dialog` capped at 90 % height, docked title, `#result_body` takes the rest and scrolls (the window-help idiom).

### Corrective pass 1 (2026-10-30) — review F1–F5, SEC6-1 / SEC6-4 / SEC6-6, orchestrator UX-1..UX-3

BLUF: a damaged `project.json` is never rewritten by an in-project writer any more (F1 / SEC6-1, HIGH); "now opens" follows only a written and verified manifest (F2 / SEC6-4); the panel paints the prototype's severity colours, names each skipped entry and hangs every wrapped line under its column (UX-1..UX-3).

- **F1 / SEC6-1, OQ-1 ruling (b) — `app.py`.** `_rewrite_project_manifest(project_dir, placed) -> bool` is the one rewrite of the four in-project writers (save-back, variant append, MAC sync, A2L sync). It reads the manifest ONCE. When `manifest_is_damaged` (over the size cap; not well-formed JSON, an `OSError` on open included; a top level that is not an object) it writes nothing, keeps the placed file, paints `project.json in project '<P>' is damaged and was not rewritten - <file> stays in the project; Save project rewrites it` (through `safe_text(...).plain`) and returns False. Otherwise it builds the carry from that same read (`_manifest_carry(project_dir, manifest)`) and calls the seam. OQ-1 (a) unchanged: no `project.json` -> one is written. Save project (Inc 5) is untouched and stays the recovery path. The session-side activation still happens (the reviewer's ruling allows it).
- **F2 / SEC6-4 — `app.py`.** The append paints `Project '<P>' now opens <file>` only when the helper returned True. The helper returns True only when the seam wrote AND the verify reported `verified` — SEC6-4's stricter form, so a verify MISMATCH does not claim it either.
- **SEC6-6 — `app.py`.** Kept the pre-existing `Manifest active_variant '<x>' not found - activating the first variant.` line (decision: keep — on a direct `_handle_load_project` it is the only status-log line naming the missing recorded id; the summary line only counts problems) and routed it through `safe_text(...).plain`.
- **F5b — `variant_execution_service.py`.** The reader marks its findings in `ValidationIssue.details`: `{"scope": "manifest"}` on the top-level-not-an-object finding and `{"entry": <recorded string>}` on every skipped entry. `manifest_is_damaged` (public; was `_manifest_damaged`) and `_manifest_problems` read the marks, never the message text. `_MANIFEST_TOP_LEVEL_MESSAGE` is removed and the message is back to its base form (byte-identical). Nothing else reads `details` of a manifest issue (grep), so no other output changes.
- **UX-2 — the service + `screens.py`.** Each skipped-entry row names its recorded entry (`! Manifest entry skipped: ../escape_03.json  a recorded entry points outside the project; Save project rewrites it`); a non-string entry shows its JSON form clipped to 60 characters; every name still renders through `safe_text`. 30 escaping entries are 30 distinct rows.
- **UX-1 / UX-3 and the UX-2 hang — `screens.py`.** `LoadResultScreen` paints the summary as a Rich `Table.grid` (a 10-cell label column, dim; a value column that wraps under itself) and each problem as a two-column grid (the `"  ! "` mark, then the text — a wrapped row hangs under its label, never under the `!`). Colours come from `insight_style` (the app's palette; the prototype `_lp_common.py` uses the same hex values): the fallback reason, the "Problems found" heading, the mark and the label in `YELLOW` (warning); the recorded reason and "No problems found." in `GREEN` (OK); details, labels and `(none)` in `DGRAY`; the opened name bold. `Text` styles only, never markup. `styles.tcss` unchanged in this pass.
- **UX-1 "not readable" mark in the error colour — not done.** Inc 6 has no "not readable" state to mark: readability arrives with HLR-169's problem kinds at Inc 7 (§6), and the `RED` mark lands with it. The word appears today only inside the `next-valid` reason text, which is a fallback and paints in the warning colour.
- **F3.** Data Flow on `_route_load_project` (the identity rule) and `_activate_project_file` (file-name match, stem fallback); full docstrings on `_manifest_problems`, `manifest_is_damaged` and `_rewrite_project_manifest`; Dependencies on `summary_line`; `_problem_row(problem: "LoadProblem")`.
- **F5a — tests.** `tests/support/b100_projects.dismiss_load_result_panel(pilot, app)` replaces the six pasted 11-line blocks; its closing wait raises `the Load-result panel did not close on esc`.
- **Test instruments.** The panel's `Static`s now render a `Table`, whose `str()` is not its text, so every panel oracle reads the PAINTED lines (`painted_lines`, `load_result_panel_text`, `read_load_result_panel` — which waits until the panel is laid out; `flat()` for phrase oracles that may wrap). Column oracles (`Opened    firmware.s19`) stay on the raw painted lines.

### Corrective pass 2 (2026-10-30) — SEC6-7 (MAJOR, security round 2)

BLUF: a manifest entry the OS cannot resolve (on Windows, a path over ~32 760 characters) no longer crashes the app on Load or in a writer: it becomes one skipped-entry row, and every entry a finding names is clipped to 120 characters.

- **The fix — `variant_execution_service.py`, `_resolve_manifest_entry`.** `resolve()`, the containment test and the reparse walk run inside one `try`; `OSError` / `ValueError` record one `MANIFEST-PATH-ESCAPE` finding ("entry is not a usable path (<exception class>) - entry skipped"; the message goes to the log only) and the entry is skipped. The panel row is the same kind as an escaping entry: `! Manifest entry skipped: <entry>  a recorded entry points outside the project; Save project rewrites it`. Base crashed the same way for `batch` / `assignments`; Inc 6 added `gathered` and the four writers' re-read, so all of them are covered by the one guard.
- **The clip.** `_entry_mark(entry)` builds every finding's `details["entry"]`, clipped to `_ENTRY_CLIP = 120` characters with an ellipsis, for string and non-string entries alike (pass 1 clipped only non-strings, at 60). The finding message was already length-capped by `ValidationIssue`.
- **The writers.** The carry is built from the reader's kept entries, so a skipped over-long entry is not carried into the rewritten `project.json` (reported and skipped, never trusted — HLR-169), the same rule as any other skipped entry.
- **Packet hygiene.** §2's original service row no longer lists `_MANIFEST_TOP_LEVEL_MESSAGE` (removed in pass 1); §1's original bullet about it is marked superseded.

### Corrective pass 3 (2026-10-30) — SEC6-7 remainder (MAJOR), SEC6-8 (MINOR), security round 3

BLUF: two more inputs that crashed Load and the writers are now findings: a manifest entry through a junction that points to itself, and a `project.json` holding an integer over Python's digit limit. One file changed (`variant_execution_service.py`), two catch lists widened.

- **SEC6-7 remainder.** `_resolve_manifest_entry`'s guard now catches `RuntimeError` too: `Path.resolve()` raises `RuntimeError: Symlink loop` for an entry such as `loop/x.json` where `loop` is a junction to itself (creatable without elevation, `mklink /J loop loop`). The entry becomes one `Manifest entry skipped` row, like pass 2's over-long entry; the variant append (which re-reads the manifest after placing) keeps the placed file and carries the rest.
- **SEC6-8 (pre-existing).** `read_project_manifest`'s parse now catches a plain `ValueError` beside `JSONDecodeError`: `json.load` raises `ValueError` (not `JSONDecodeError`) for an integer over 4 300 digits. The file is one `MANIFEST-JSON-PARSE` finding, so the panel says `Manifest damaged` and `manifest_is_damaged` is True — SEC6-1's skip path applies and no writer rewrites it.
- Docstrings: the resolver's and the reader's Data Flow name the two new cases.

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | HLR-168 · LLR-168.2 · LLR-168.3 · HLR-178 · LLR-178.2 · LLR-178.3 | `_manifest_carry`, `_activate_project_file`, `_route_load_project`, `_handle_load_result` (NEW); save-back activates + rewrites; append / MAC / A2L place through `place_into_workarea` and rewrite; `_handle_load_project` summary + `#status_text`; `_last_load_announcement` |
| `s19_app/tui/services/variant_execution_service.py` | source | LLR-168.1 · LLR-178.1 | `ProjectManifest.gathered` + parse; `LoadProblem`, `LoadAnnouncement`, `compose_load_announcement`, `LOAD_REASON_*`, `LOAD_REASON_TEXT`, `LOAD_SUMMARY_WIDTH`, `manifest_is_damaged`, the `details` marks (`_ISSUE_ENTRY` / `_ISSUE_SCOPE` / `_SCOPE_MANIFEST`, `_entry_mark`, `_ENTRY_CLIP`) (NEW); the `resolve()` guard in `_resolve_manifest_entry` (pass 2, SEC6-7) |
| `s19_app/tui/screens.py` | source | LLR-178.3 | `LoadResultScreen`, `LOAD_RESULT_SELECT_VARIANT` (NEW); imports `VerticalScroll`, `rich.text.Text`, `safe_text` |
| `s19_app/tui/styles.tcss` | source | LLR-178.3 | the panel's rules (`#load_result_dialog`, `#result_body`, `.result-heading`, `.result-problem`) |
| `tests/test_b100_active_variant.py` | test | HLR-168 · LLR-168.1 · LLR-168.2 · LLR-168.3 | NEW, 18 nodes: TC-B100-18 ×5, -19 ×3, -20 ×4, AT-B100-06 ×4, AT-B100-20 ×2 |
| `tests/test_b100_announce.py` | test | HLR-178 · LLR-178.1 · LLR-178.2 · LLR-178.3 | NEW, 20 nodes: TC-B100-55 ×9, -56 ×3, -67 ×6, AT-B100-19 ×2 |
| `tests/support/b100_projects.py` | fixture | HLR-168 (enabler E4, Inc 6 slice) | NEW: `p02` A/B save-back names, a project seeded with every not-owned key (compact JSON), stdlib manifest readers |
| `tests/test_b100_focus.py` | test | LLR-166.1 · HLR-178 | AT-B100-04 re-pin (dismiss the panel first); TC-B100-12 panel arms ×2 (NEW) |
| `tests/test_b100_save_image.py` | test | HLR-167 · HLR-178 | AT-B100-05 Inc 6 arm: the panel oracle on reopen, then `esc` |
| `tests/test_id_registry.py` | config | HLR-168 | `EXPECTED_SCANNED_TEST_FILES` 219 → 222 |
| `tests/test_import_census.py` | config | LLR-178.3 | `MEASURED_SAFE_TEXT_CONSUMERS` += `s19_app.tui.screens` (measured in, §6) |
| `tests/test_b99_crc_region.py` · `tests/test_b99_staging.py` · `tests/test_b100_reuse.py` · `tests/test_b99_patch_truth.py` · `tests/test_b99_export.py` · `tests/test_b99_truncation.py` · `tests/test_b100_session_reset.py` | test | HLR-178 · LLR-178.2 · LLR-168.3 | re-pins (§4 reverse census) |
| `HANDOFF.md` | doc | HLR-168 | implementer checkpoint (Part A, end); corrective pass 1 appended |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1_mutation_harness.py` | test | HLR-168 · HLR-178 | corrective pass 1 mutation harness (evidence) |

**Corrective pass 1 — files touched** (same 4-source budget; `styles.tcss` not touched in this pass):

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | LLR-168.3 · LLR-178.2 | `_rewrite_project_manifest` (NEW, F1/F2); the four writers call it; `_manifest_carry(project_dir, manifest)`; SEC6-6 `safe_text`; F3 docstrings |
| `s19_app/tui/services/variant_execution_service.py` | source | LLR-178.1 | `details` marks (`entry`, `scope`); `manifest_is_damaged` (public); `_manifest_problems` names the entry; F3 docstrings; `_MANIFEST_TOP_LEVEL_MESSAGE` removed |
| `s19_app/tui/screens.py` | source | LLR-178.3 | the label/value grid, the mark/text problem grid, `insight_style` colours |
| `tests/test_b100_active_variant.py` | test | LLR-168.3 | +13 nodes: TC-B100-20 damaged ×12 (4 writers × 3 kinds), TC-B100-20 now-opens ×1; panel read through `read_load_result_panel` |
| `tests/test_b100_announce.py` | test | LLR-178.2 · LLR-178.3 | +4 nodes: TC-B100-56 control bytes; TC-B100-67 warning colour, OK colour, hanging indent; TC-67 thirty asserts 30 distinct rows; painted-text oracles |
| `tests/support/b100_projects.py` | fixture | HLR-178 | `dismiss_load_result_panel`, `painted_lines`, `load_result_panel_text`, `read_load_result_panel`, `flat` |
| `tests/test_b100_save_image.py` | test | HLR-178 | AT-B100-05 reads the painted panel |
| `tests/test_b99_crc_region.py` · `tests/test_b99_staging.py` · `tests/test_b100_reuse.py` · `tests/test_b99_patch_truth.py` · `tests/test_b99_truncation.py` · `tests/test_b99_export.py` | test | HLR-178 | F5a: the pasted dismissal block -> `dismiss_load_result_panel` |

**Corrective pass 2 — files touched** (1 source; same 4-source budget):

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/variant_execution_service.py` | source | LLR-168.1 · LLR-178.1 | `_resolve_manifest_entry`: `OSError` / `ValueError` around `resolve()` + containment + reparse walk -> one skipped-entry finding; `_entry_mark` / `_ENTRY_CLIP` (120) for every entry |
| `tests/test_b100_announce.py` | test | LLR-178.3 | +1 node: TC-B100-67 over-long entries (`batch`, `assignments`, `gathered`, 40 000 chars each) through the Load project dialog |
| `tests/test_b100_active_variant.py` | test | LLR-168.3 | +1 node: TC-B100-20 A2L sync on a manifest with over-long entries |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2_mutation_harness.py` | test | LLR-168.1 | corrective pass 2 mutation harness (evidence) |
| `.dev-flow/2026-10-26-batch-100/03-increments/increment-006.md` | doc | HLR-168 · HLR-178 | §2 stale row fixed; "Corrective pass 2" subsections |

**Corrective pass 3 — files touched** (1 source; same 4-source budget):

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/variant_execution_service.py` | source | LLR-168.1 · LLR-178.1 | the resolver guard catches `RuntimeError` (SEC6-7 remainder); the manifest parse catches `ValueError` (SEC6-8); Data Flow lines |
| `tests/test_b100_announce.py` | test | LLR-178.3 | +2 nodes: TC-B100-67 junction-loop entry (Windows-only, skips off Windows), TC-B100-67 5 000-digit integer, both through the Load project dialog |
| `tests/test_b100_active_variant.py` | test | LLR-168.3 | +5 nodes: TC-B100-20 variant append with a junction-loop entry (Windows-only); TC-B100-20 damaged `int-over-digit-limit` × 4 writers |
| `tests/support/b100_projects.py` | fixture | HLR-168 · HLR-178 | `create_junction_loop` (`cmd /c mklink /J`; callers remove it with `os.rmdir`), `OVERLONG_INT_MANIFEST` |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3_mutation_harness.py` | test | LLR-168.1 · LLR-178.1 | corrective pass 3 mutation harness (evidence) |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** (declared at cap, design proposal §5.6) |
| Test / fixture / config files | 14 |
| Evidence | `.dev-flow/2026-10-26-batch-100/evidence/inc-6/` |

## 3 · How to test

```bash
# interpreter: C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_active_variant.py tests/test_b100_announce.py \
  tests/test_b100_focus.py tests/test_b100_save_image.py
# guards: the 6 guard files; then -k census tests; mutations:
python .dev-flow/2026-10-26-batch-100/evidence/inc-6/mutation_harness.py <worktree> <id> ...
# corrective pass 1 mutations:
python .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1_mutation_harness.py <worktree> <id> ...
```

Manual, corrective pass 1: open P; truncate its `project.json` by one character; Load an A2L -> the status says `project.json in project 'P' is damaged and was not rewritten - firmware.a2l stays in the project; Save project rewrites it` and `project.json` is unchanged. Reopen P through `p` at 99×54 -> the reason wraps under the value column, the problem row under its label, both in yellow.

Manual (both reference sizes): Load file `firmware.s19` → `ctrl+s` P → Patch Editor add + Apply → save back with the default name → quit; restart → `p` → P → the panel names `firmware-patched.s19`, "recorded as the active variant (the latest saved)", 2 variants; `esc` closes; the status log's newest line ends `details: p`.

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-6/`. **Final source hashes after corrective pass 3** (printed in every `fix3-*` transcript header): `variant_execution_service.py` `76b276077ded9717`; `app.py` `762d1a98c8a65903` · `screens.py` `ea549ab4bd9d3ef4` · `styles.tcss` `781f04ed2cc30897` unchanged since pass 1. No source byte changed after the first `fix3-*` GREEN transcript. After corrective pass 2 (16 chars, printed in every `fix2-*` transcript header) they were: `app.py` `762d1a98c8a65903` · `screens.py` `ea549ab4bd9d3ef4` · `variant_execution_service.py` `e494c50cd7266bff` · `styles.tcss` `781f04ed2cc30897`. After corrective pass 1 they were `app.py` `762d1a98c8a65903` · `screens.py` `ea549ab4bd9d3ef4` · `variant_execution_service.py` `395dcbde3b28851b` · `styles.tcss` `781f04ed2cc30897` (the `fix1-*` transcripts). The reviewed (pre-pass) hashes were `app.py` `d37ee857f64b202d` · `screens.py` `a957b576658777b0` · `variant_execution_service.py` `8e2e8cf059eb48aa` · `styles.tcss` `781f04ed2cc30897`; the tables below this paragraph up to "Corrective pass 1" record that reviewed tree. 

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | TC-B100-18 (5) · -19 (3) · -20 (4) · -55 (9) · -56 (3) · -67 (6) · -12 panel arms (2) | all passed — `green-01-new-and-b100-modules.txt` (**138 passed**: the two new modules + `test_b100_focus.py` + `test_b100_save_image.py` + `test_b100_session_reset.py`) |
| **B · black-box** `AT-NNN` ↔ story | `core` · `full` | AT-B100-06 (2 sizes × `p02` A/B = 4) · AT-B100-19 (2) · AT-B100-20 (2) · AT-B100-04 re-pin (2) · AT-B100-05 Inc 6 arm (2); all at 118×54 and 220×60, notifications on | all passed — inside `green-01` |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| Final `test_b100_active_variant.py` vs base `093a7c0` | `red-04-active-variant-final-vs-base.txt` | **17 failed, 1 passed.** Behavioural: TC-19 ×2 `active_variant 'firmware'` (P-3); TC-20 ×4 `project.json was not rewritten` / the MAC and A2L rewrite never comes; AT-06 ×4 `'-> firmware_1.s19' in "Loaded project 'P' -> firmware.s19"` (P-3's RELOAD line); AT-20 ×2 `timed out waiting for firmware_1.s19 placed and project.json rewritten` (the carry never happens). **Missing-attribute, not behavioural:** TC-18 ×5 (`ProjectManifest` has no `gathered`) — the behavioural RED is the contract's own negative control, `mut-168.1-ignore-gathered` (TC-20 ×4 RED). The 1 pass is the no-project boundary arm (base writes no manifest either — by design) |
| Part A first pass vs base (before the save-back prompt fix) | `red-01-active-variant-partA-vs-base.txt` | 15 failed, 1 passed; AT-06 ×2 failed there on `click missed` (the prompt sits in the JSON tab) — superseded by `red-04` |
| `test_b100_announce.py` + AT-20 + TC-12 panel arms + AT-04 / AT-05 arms vs base | `red-02-partB-vs-base.txt` | **27 failed, 1 passed.** Behavioural: TC-56 one-line (`['Loaded firmware_1.s19 (S19 only)', "Loaded project 'P' -> firmware_1.s19"]`, no `details: p`), TC-67 ×6 / AT-19 ×2 / TC-12 panel ×2 / AT-04 ×2 / AT-05 ×2 (no Load-result panel opens). **Missing-symbol:** TC-55 ×9, TC-56 long-names (the new pure composer) — behavioural RED by `mut-178.1-*`. AT-20 there failed on the panel wait (superseded by `red-03`). The 1 pass (TC-56 hostile) was strengthened → `red-03` |
| TC-56 hostile (strengthened) + AT-20 (opening tolerant of the panel) vs base | `red-03-tc56-hostile-and-at20-vs-base.txt` | **3 failed**: `Loaded project 'P' -> [b]x.s19` has no summary tail; AT-20 ×2 carry timeout |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| "project.json was rewritten" (TC-20) | seed in compact JSON; the seam writes `indent=2` → a byte change; base: `assert b'…' != b'…'` RED (`red-04`) |
| "rewritten" with unchanged bytes (AT-20 MAC / A2L steps) | file identity `(st_ino, st_mtime_ns)` of the staged-then-moved file; base: timeout RED (`red-04`) |
| "last row visible after `end`" (TC-67, AT-19) | `#result_body.region.contains_region(row.region)` is asserted **False before** `end` at 118×54 (30 rows) and True after; a widget scrolled out keeps a non-zero `region`, so `region.area` was rejected as an oracle (geometry probe during authoring) |
| panel open / closed | `#result_ok` present on the active screen; base RED (`red-02`) |
| 0 spans | `Label.render().spans == []` on `#log_line_4` and `#status_text`; `mut-178.2-markup-on` RED |

### Mutation verdicts (C-40) — restored and hash-verified (`mutation_harness.py`; every transcript ends `RESTORE OK`)

| Mutation | LLR | Transcript | Verdict — killing nodes |
|---|---|---|---|
| the reader ignores `gathered` | 168.1 | `mut-168.1-ignore-gathered.txt` | KILLED 8: TC-18 ×4, TC-20 ×4 (the rewrite drops `gathered` — the contract's control) |
| the save-back does not activate / rewrite | 168.2 | `mut-168.2-saveback-not-activated.txt` | KILLED 3: TC-19 A, B; TC-20 save-back |
| the seam call removed from the variant append | 168.3 | `mut-168.3-append-no-seam-call.txt` | KILLED 1: TC-20 append (`active_variant` stale) |
| the carry passes the reader's absolute `batch` (A-03) | 168.3 | `mut-168.3-absolute-batch.txt` | KILLED 4: TC-20 ×4 (`serialize_manifest` refuses, no manifest written) |
| the composer says "recorded" for the fallback | 178.1 | `mut-178.1-fallback-called-recorded.txt` | KILLED 4: TC-55 next-valid, TC-55 latest/file-times, AT-19 ×2 |
| `#status_text` painted with markup on | 178.2 | `mut-178.2-markup-on.txt` | KILLED 1: TC-56 hostile |
| ordering: the project + file line written BEFORE the loads | 178.2 | `mut-178.2-status-before-load.txt` | KILLED 1: TC-56 one-line (the install's line wins) |
| the panel's focus starts on `#result_ok` | 178.3 | `mut-178.3-focus-on-close.txt` | KILLED 3: TC-67 focus+enter, tab, thirty |
| the list truncated at 10 rows | 178.3 | `mut-178.3-truncate-10.txt` | KILLED 1: TC-67 thirty (`20 problems missing`) |

| MA (reviewer): `_handle_load_result` -> `if True: self.action_select_variant()` | LLR-166.1 (TC-B100-12 panel arms) | `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\r6\mut-MA.txt` (sha256 `b481d97219603b29418e7c922299c3bac37895dba5da92a47e9ae4afae2905c8`) | KILLED 2: `tc_b100_12_panel_*` ×2 (`last painted focus: ListView#variant_list`) |
| MB (reviewer): `self.screen.set_focus(None)` at the top of `_handle_load_result` | LLR-166.1 (TC-B100-12 panel arms) | `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\r6\mut-MB.txt` (sha256 `7895551aec840c8230f5405f12ea7c78128d85878acdfd0a53b6e68b7175d30f`) | KILLED 2: `tc_b100_12_panel_*` ×2 (`last painted focus: OsClipboardInput#palette_input`) |

Not run at Inc 6 (declared): TC-55's "first variant by name" arm (moves to Inc 7, ARCH-PDR-3, per the ledger entry for TC-B100-55). The TC-B100-12 panel arms are killed by the reviewer's mutants MA and MB above (transcripts in the reviewer's scratch, cited by path and digest; `_handle_load_result` is unchanged by corrective pass 1).

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| `project.json` | parsed by the stdlib `json` (`tests/support/b100_projects.py`), never the app's reader: the four not-owned keys JSON-equal to the seed, 0 absolute strings anywhere (both separator conventions), `active_variant` value |
| the saved-back image | `tests/support/independent_reader.py` `read_s19`: `DE AD BE EF` at `0x8000007C` (AT-06) |
| the status line / `#status_text` | the painted `#log_line_4` / `#status_text` renders and their spans |
| the panel | the painted `Static` / `Label` renders of `#load_result_dialog` |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 greps (the brief's three + a fourth over the symbols this increment changed) | `reverse-census-grep.txt` (commands inside) | 39 paths: 38 test files + `tests/b97_fixtures.py` (a helper; its users are in the list; it calls `_handle_load_project` directly, so it meets no modal) |
| B1 re-validation, first pass on the tree (4 parallel shards, distinct `--basetemp`) | `census-tree-shard0..3.txt` | shard0 **4 failed, 269 passed** · shard1 **5 failed, 376 passed** · shard2 **5 failed, 382 passed** · shard3 **2 failed, 219 passed** — 16 failures, every one dispositioned below |
| Re-pinned files re-run in full on the final tree | `green-01-new-and-b100-modules.txt`, `green-02-repinned-b99-and-reuse.txt` | **138 passed** · **144 passed** |
| B3 snapshot cells | `tests/test_tui_snapshot.py` in the guards | `guards.txt`: **75 passed, 29 snapshots passed** — no cell changed (no snapshot scenario uses the Load project dialog) |
| Guards census sweep | `guards-census.txt` | **87 passed, 3905 deselected** |

| Node(s) | Disposition | Evidence (base vs tree) |
|---|---|---|
| `test_b99_crc_region.py::test_at_b99_10_flow_crc_region_pilot`; `test_b99_staging.py::test_at_b99_04_duplicate_refused_distinct_parallel_markers`; `test_b100_reuse.py::test_at_b100_01_repeated_loads_reuse_and_name_existing_variant` ×2; `test_b99_patch_truth.py::test_tc_b99_18_lane_line_carries_patch_and_crc_riders`, `::test_at_b99_06_flow_execution_patch_truth`, `::test_at_b99_07_hostile_symbol_name_renders_literally`; `test_b99_export.py::test_tc_b99_29_junctioned_project_home_shows_refusal`; `test_b99_truncation.py::test_at_b99_03_status_leads_defect_flow_source_fails`; `test_b100_session_reset.py::test_at_b100_03_project_load_over_unsaved_work_saves_only_p2` ×2 | **Re-pinned — dismiss the panel first.** Each opens a project through the Load project dialog, and the Load-result panel now holds the screen (`NoMatches … on LoadResultScreen()` / a focus or dialog wait timing out). Old → new: dialog → keys reach the main screen ⇒ dialog → panel → `esc` → keys reach the main screen — HLR-178 / LLR-178.3 | base, original form: **all PASSED** (`census-base-repinned-nodes-original-form.txt`, `census-base-shard1-nodes.txt`); tree, original form: FAILED (`census-tree-shard*.txt`); tree, re-pinned: passed (`green-01`, `green-02`) |
| `test_b99_export.py::test_at_b99_11_sanitised_mac_only_second_export_takes_suffix` | **Re-pinned (2 changes).** (a) the panel dismissal as above; (b) its MAC-load wait read `#log_line_4` for `firmware.mac`; the MAC sync into the open project now rewrites `project.json`, and the seam's `Project saved + manifest verified` line is painted after the load line, so the wait reads the four painted log lines. Old → new: `"firmware.mac" in #log_line_4` ⇒ `in #log_line_1..4` — LLR-168.3 | same three transcripts |
| `test_b100_session_reset.py::test_tc_b100_10_no_discard_notice_when_nothing_unsaved` | **Re-pinned.** Old → new: `lines[-1] == "Loaded project 'P2' -> prg.s19"` ⇒ `== "Loaded project 'P2' -> prg.s19 - variant 1 of 1, 1 problem - details: p"` (P2 has no `project.json` → 1 "No manifest" problem) — LLR-178.2 | base PASSED (`census-base-shard1-nodes.txt`); tree original FAILED (`census-tree-shard1.txt`); re-pinned passed (`green-01`) |
| `test_b100_focus.py::test_at_b100_04_…` ×2; `test_b100_save_image.py::test_at_b100_05_…` ×2 | **Planned Inc 6 arms** (contract §5.3): AT-04 "dismiss the panel first"; AT-05 "panel oracle" (the panel names `firmware.s19`, recorded as active, then `esc`) | base RED with the arms (`red-02`); tree passed (`green-01`) |
| `test_tui_commandbar.py::test_at_b78_03_…`; `test_tui_diff_screen.py::test_at_b78_32_…`; `test_tui_report_filter_surface.py::test_at_056e_a2b_…` | **Pre-existing at base** (the Inc 3/5 packets' known set); untouched by this increment | base FAILED: `census-base-b78_03.txt`, `census-base-shard1-nodes.txt` |
| `test_import_census.py::test_tc653_safe_text_import_census` (guard) | **Measured in** (see §6): `screens.py` now imports `safe_text` from `s19_app.utils` — LLR-178.3 requires every disk name in the panel to render through it. `MEASURED_SAFE_TEXT_CONSUMERS` += `s19_app.tui.screens`, with the census's own "measured in" comment | first run `guards-01-first-run.txt` (1 failed: `extra=['s19_app.tui.screens']`); `guards.txt` 75 passed |

### Signed-balance test ledger

Scanned files: `222 = 219 − 0 + 3` (`test_b100_active_variant.py`, `test_b100_announce.py`, `tests/support/b100_projects.py` — the registry scans the support module too; measured: a first bump to 221 failed with `scanned 222`). New nodes: 38 (18 + 20) + 2 TC-12 panel arms in `test_b100_focus.py`. Re-pinned: 13 nodes in 7 files (table above) + the planned AT-04 / AT-05 arms (4 nodes). Removed: 0.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-6/` | SHA-256 |
|---|---|---|
| census-base-b78_03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/census-base-b78_03.txt | 387ea35e747fefa7df43b311a73da2c3986cb57f4175c6b5a53b6ba3c358a754 |
| census-base-repinned-nodes-original-form.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/census-base-repinned-nodes-original-form.txt | a8e5247a471e5857f258b8f9725a7c016be1646cc705385d0239f73af57423c1 |
| census-base-shard1-nodes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/census-base-shard1-nodes.txt | dff79e18d2b9aa54a241d54f23502f35f76b6c10aaeb5ba1d5b5aea6306f88d6 |
| census-tree-shard0.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/census-tree-shard0.txt | dfae896dfbf83fb422afa022b6e527dc1646bf1ed828a8f69c7ffff79be011ed |
| census-tree-shard1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/census-tree-shard1.txt | fe99c49c3726d5dea876b337d9ba55e019f110799a2c41cb7f70895edca16ec8 |
| census-tree-shard2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/census-tree-shard2.txt | bd5e14dc42a7ad4dfea40927f1114209cdd4b6e762011c32635eb5a90d876e12 |
| census-tree-shard3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/census-tree-shard3.txt | be7be3c74af07732d531b874304bbe8c0a23a61d7814b770e7eccbb02bcd6f0a |
| green-01-new-and-b100-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/green-01-new-and-b100-modules.txt | 5d4220e10cc24ff3b454f7cafffa618e12fd46ee334a1c137a4d99e983e26118 |
| green-02-repinned-b99-and-reuse.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/green-02-repinned-b99-and-reuse.txt | 90c60c1148f5b9a44c8f22665dd667b4ef7c448b3799d6204ebc88578273a88f |
| guards-01-first-run.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/guards-01-first-run.txt | 8d71d806be07f9d038d52fa8de39f15cea529a9d1bf7139fb0032095cdd8dc01 |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/guards-census.txt | 7e44dcfde481b043b0fe154c89918213a97ff3b3b25b20a70d7417a08b80e23a |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/guards.txt | fe0f0f21fd7e45ee23f9ff1fe724c0ab8a16309fa4734128df67fcd0aa5687eb |
| import-proof.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/import-proof.txt | df57a304bf2dd2a84aad9a38d5ecfc3ccfd34037841998579c272e1b2d85056c |
| mut-168.1-ignore-gathered.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-168.1-ignore-gathered.txt | 323bede1984b572e05b4175d650eeaf50468d65a488499fe85ced4c986e0a418 |
| mut-168.2-saveback-not-activated.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-168.2-saveback-not-activated.txt | 4556a8deeae72924398726f22f09141baedea63a0d03b6b2c845d16be90f052b |
| mut-168.3-absolute-batch.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-168.3-absolute-batch.txt | 87ec85d2c9f8b55431852316f5f65cf98eb0dbbd08f88bb87a2210be85a81eb5 |
| mut-168.3-append-no-seam-call.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-168.3-append-no-seam-call.txt | a3b994017e27c1232523592abca0ec6984bfb10f21bd7e24c2b2774806888ea3 |
| mut-178.1-fallback-called-recorded.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-178.1-fallback-called-recorded.txt | 4b04a9d92c7598bcef994c8955685946fe6cb365ca73c86639ae791f4a9ea57b |
| mut-178.2-markup-on.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-178.2-markup-on.txt | f853bea18edc1e6fd95dbc8334dacd0be72aee9b65f441d834af2ee3bf68616c |
| mut-178.2-status-before-load.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-178.2-status-before-load.txt | dfb0765b3b60b3e4e84db7e70590a43b12cdcc4e04f58a7d6a7688b369fa1013 |
| mut-178.3-focus-on-close.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-178.3-focus-on-close.txt | 34fe9dd2ed825884e2823e8087d2e5ed84e1b40932f9f69a5294dd7f50bb4a57 |
| mut-178.3-truncate-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mut-178.3-truncate-10.txt | 1ccae66d22aa5a3d903c463d16a69555c5a4d4b522e4ffa6818e9835435dbf72 |
| mutation_harness.py | .dev-flow/2026-10-26-batch-100/evidence/inc-6/mutation_harness.py | 67af605fd77d5b21cbb7e7a56c52e8f8660a54a2ade0829f7cba3d9aac2d1cf0 |
| red-01-active-variant-partA-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/red-01-active-variant-partA-vs-base.txt | 72efac5cae6e615b3e3d12fdb5f4196f45e8ff5d5a0995567fc824d7935b6f80 |
| red-02-partB-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/red-02-partB-vs-base.txt | 15bfb6c45c4ee4452466eefee623dbdc4e1a2d1fc8a4f48ed64afda0f0b3afbb |
| red-03-tc56-hostile-and-at20-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/red-03-tc56-hostile-and-at20-vs-base.txt | 9326f33f74d576f0394cdc2c463053ffcbc8fe3d4deb7907a0e1dfa67db35d80 |
| red-04-active-variant-final-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/red-04-active-variant-final-vs-base.txt | cdce7e0212475513a60ef3b782f6b5e6cca5de4daad13eb6b097dfe4e7460987 |
| reverse-census-grep.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/reverse-census-grep.txt | 3895cd0e39d6ce0dd9ffbbfc82174c925713263faa616bac8c3634c7c34598d6 |
| orch-census-batch-a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/orch-census-batch-a.txt | b06b42334ff63f9eb751c6ce0367358ab6390820aeb632a7545cec5445f533d7 |
| orch-census-batch-b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/orch-census-batch-b.txt | 3fa0de09183a1d7018f66098084d546aeaa64a151e29b16bb43fa976bd0143fc |
| orch-census-k.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/orch-census-k.txt | d238207f95f940bd9eaaeda056f2b038fc42cb6f8bdacd8985e0457a4835c32d |
| orch-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/orch-guards.txt | c925d5dc36229b3fab96052fa0105507cd4d8b8bfadbdb0635c4af41fd78a7a4 |
| orch-isolation-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/orch-isolation-rerun.txt | ac87767faf2c08bbe993a53531d03a9513f3e4e085b28ea7897a8dce8e13f9e1 |
| pe-clean.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-clean.118x54.png | 09b1bffd8691917e3485089a110f50bed8efeb4327979522d73f40363c457ada |
| pe-clean.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-clean.220x60.png | 30484bfd756ac475e7992844597c5c4d2da237a1b67619a2f9dd9ca106bd9ea7 |
| pe-clean.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-clean.99x54.png | 8de6f847541e3c34d79c4bc76c20590ab9921b3fdfce0136e46c6b490bc76750 |
| pe-damaged.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-damaged.118x54.png | 709e67565a492070459d8254cd0fed967a6e7e9dceb11166b064827861d13661 |
| pe-damaged.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-damaged.220x60.png | 50df0af719c6d889843459933a1a16394b45a7f0e0d65c16c6d9a111433c6121 |
| pe-damaged.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-damaged.99x54.png | 4b1930c09892b334fbb8d10a6eb0a167dcada721203d2757294bd44377ebdee3 |
| pe-problems.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-problems.118x54.png | aad845873030b8a80adc25ea6d7f0a64fe9d70da38f85d7ad2981f72af8304fe |
| pe-problems.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-problems.220x60.png | ef0c4dbbdd4d9f8a746e2d8975cad5a5e646978f58f396597629da57629a6e6c |
| pe-problems.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-problems.99x54.png | 8409309e81ecbff6c9c37fcec8e14386def4906649f5d411bcea7aa6eacf6ac5 |
| pe-saveback-closed.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-saveback-closed.118x54.png | 9be17a826c46be590380e8e1b800313f5f7e2d65892aa78cfcf2a6324a3a04ec |
| pe-saveback-closed.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-saveback-closed.220x60.png | 4159f8d23847a2c66309c59ea78d88daaa53d5241562934437e72c01f1cf7024 |
| pe-saveback-closed.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-saveback-closed.99x54.png | 48e39a99f9496785571f7824ace987bd5f62e94245d29af2f1a4eaf2fff32895 |
| pe-saveback.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-saveback.118x54.png | 29a353a06b6ba05d7f8927f6895a3145fecbe3fed4303e94523284a38d528a1c |
| pe-saveback.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-saveback.220x60.png | 64b6b85f8941ec1e09b1c104bbdcd3c8ea0eb47afbdbe99d1c9f4bbc283dc213 |
| pe-saveback.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-6/e13/pe-saveback.99x54.png | 403dc977e87c7ac230e6cfcb2f6e8bb2eb9fe9f0a5e22144fb74cc0262f0c324 |
| green-fixed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/green-fixed.txt | 0c427b90eee60f48c9579980ce2270f701a73772b7386947704e136f86301357 |
| mut-MA.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/mut-MA.txt | b481d97219603b29418e7c922299c3bac37895dba5da92a47e9ae4afae2905c8 |
| mut-MB.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/mut-MB.txt | 7895551aec840c8230f5405f12ea7c78128d85878acdfd0a53b6e68b7175d30f |
| mut-MD.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/mut-MD.txt | 301c08a334cfd11ceb1fcdd7aaa1ad8f06575d37faf5f622b02f11d1dda10526 |
| mut-ME.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/mut-ME.txt | 1281893e2b0dbbee0227a1a3c9f8ca712c8c7df01bd336bdcfa9b0c6c4d8d134 |
| probe-p1-p3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/probe-p1-p3.txt | 8c679d14c0ef1e15dca65c71db9545d4bebccfcccc68d10702b082a2e06e33f7 |
| r2-green-fixed2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/r2-green-fixed2.txt | aed809ee81c0a1043fcb70af02def3a949c318722706211cf01e131d0076be21 |
| r2-id-registry.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/r2-id-registry.txt | d2b64c545330c1fde37c4fea8112cf4b2fb5d1b8b626a476d3c25c4995875f9c |
| r2-mut-MA.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/r2-mut-MA.txt | 9c5310452021330b8842457fa8ff41c2b3598f51489b6513e51c2cfaa292b695 |
| r2-mut-MB.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/r2-mut-MB.txt | 9db1e2ce857b7caf9ab4a6ada9b3687603d5a6d806e62934c11220bfebb431e1 |
| r2-mut-MV.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/r2-mut-MV.txt | b7300d873b1311d9da3f3c828bf66294df61b4d640c7bc6183efb1fbdaf0ee38 |
| r2-probe-p1-p3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/r2-probe-p1-p3.txt | 3ca1ed12c0dc7ccc465d97da7d29fd06b1ef8f8687b36ac07d4f9f00e1accca1 |
| test_r6_probes.py | .dev-flow/2026-10-26-batch-100/evidence/inc-6/review/probes/test_r6_probes.py | 7c8a6a140bd6e4fb8cda497ef71eecbfd3de0e96aa9be0570d4ef5d0ac0d2bdc |

### Corrective pass 1 — test results (evidence state: `executed`)

Every `fix1-*` transcript header names the command, the tree, the 4 source hashes, `PYTHONPATH` (the tree under test) and `NO_COLOR=unset`, and prints `s19_app.__file__` from that tree.

| Run | Transcript | Result |
|---|---|---|
| RED: the 18 new arms vs the REVIEWED tree (`d37ee857` set, rebuilt by replaying this pass's edit scripts in reverse; the rebuilt hashes equal the packet's, printed in the header) | `fix1-red-01-new-arms-vs-reviewed-tree.txt` | **18 failed** — all behavioural: TC-20 damaged ×12 `the damaged project.json was rewritten` (bytes now `{"schema_version": 1, …, "batch": [], "assignments": {}}`); TC-20 now-opens `["Project 'P' now opens firmware_1.s19"]` after `Manifest write failed`; TC-56 control bytes (raw ESC / BEL in the log); TC-67 thirty `1 == 30` distinct rows (all `project.json`); TC-67 colours `#e9e9e9 != #f6ff8f` / `!= #54efae`; TC-67 hang `'be read)'` at column 0 |
| GREEN: the Inc 6 modules (`test_b100_active_variant.py`, `test_b100_announce.py`, `test_b100_focus.py`, `test_b100_save_image.py`, `test_b100_session_reset.py`) | `fix1-green-01-inc6-modules.txt` | **155 passed** (138 before the pass + the 17 new nodes) |
| first GREEN attempt (kept): AT-B100-05 / AT-B100-20 at 118×54 read the panel the instant `#result_ok` existed, before layout -> empty painted text; fixed in the TEST instrument (`read_load_result_panel` waits until the summary has a height), no source change | `fix1-green-00-first-run-panel-read-before-paint.txt` | 2 failed, 153 passed |
| GREEN: the 6 re-pinned files after F5a (`test_b99_crc_region`, `test_b99_staging`, `test_b100_reuse`, `test_b99_patch_truth`, `test_b99_truncation`, `test_b99_export`) | `fix1-green-02-repinned-files.txt` | **144 passed** |
| Reverse census of this pass's symbols (`_manifest_issue` `details`, the removed message constant, `_manifest_damaged` -> `manifest_is_damaged`, `_manifest_carry`'s signature, the panel renderables): the 11 other modules that read manifests / manifest issues | `fix1-census-manifest-readers.txt` | **265 passed** (`test_b97_flow_builder`, `test_changes_symbol_entries`, `test_flow_multi_image`, `test_flow_multi_image_ui`, `test_flow_persistence`, `test_manifest_verify`, `test_manifest_writer`, `test_project_gather`, `test_tui_manifest_save`, `test_tui_report_seam`, `test_variant_execution`). Other grep hits: `.details` in `test_tui_services` / `test_validation_*` (validation-engine issues, not manifest issues); `result_summary` in two report tests (an unrelated function name) |
| Guards (the packet's command) | `fix1-guards.txt` | **75 passed, 29 snapshots passed** — no snapshot cell changed |
| Census sweep `-k census tests` | `fix1-guards-census.txt` | **87 passed, 3922 deselected** (3905 + the 17 new nodes) |

Self-inflicted guard failure, not evidence: a first guards run with `--basetemp=…\f1gd` failed `test_tc016s_snapshot_setup_loads_only_public_fixtures` (the guard requires a pytest-named temp dir); re-run without `--basetemp` as the packet's command -> `fix1-guards.txt`. That run's transcript was moved out of the evidence folder.

**Corrective pass 1 mutations** (`fix1_mutation_harness.py`; one exact single-occurrence edit each, restored and SHA-verified — every transcript ends `RESTORE OK`):

| Mutation | Finding | Transcript | Verdict — killing nodes |
|---|---|---|---|
| the rewrite helper drops the damaged check (`if False:`) | F1 / SEC6-1 | `fix1-mut-F1-no-damaged-check.txt` | KILLED 12: TC-20 damaged, every writer × damage kind (`the damaged project.json was rewritten`) |
| `manifest_is_damaged` ignores the `scope` mark | F5b | `fix1-mut-F5b-scope-mark-ignored.txt` | KILLED 4: TC-20 damaged `not-an-object` × 4 writers |
| the append paints "now opens" unconditionally (`… or True`) | F2 / SEC6-4 | `fix1-mut-F2-now-opens-unconditional.txt` | KILLED 4: TC-20 now-opens (read-only), TC-20 damaged `variant-append` ×3 |
| the append no longer rewrites (`if False:`) | LLR-168.3 | `fix1-mut-168.3-append-no-rewrite.txt` | KILLED 5: TC-20 append carry, TC-20 now-opens, TC-20 damaged `variant-append` ×3 |
| the recorded `active_variant` unscrubbed | SEC6-6 | `fix1-mut-SEC6-6-raw-active-variant.txt` | KILLED 1: TC-56 control bytes |
| every manifest row names `project.json` | UX-2 | `fix1-mut-UX2-entry-not-named.txt` | KILLED 1: TC-67 thirty (`not distinct`) |
| the problem label loses its colour | UX-1 | `fix1-mut-UX1-label-uncoloured.txt` | KILLED 1: TC-67 warning colour |
| the fallback reason painted in the OK colour | UX-1 | `fix1-mut-UX1-reason-always-ok.txt` | KILLED 1: TC-67 warning colour |

UX-3 (the hanging indent) has no isolating mutant; its counterfactual is the executed RED on the reviewed tree (`fix1-red-01`, continuation `'be read)'` at column 0). The packet's earlier mutants were run on the reviewed tree and not re-run: their anchors in `_handle_load_result`, the composer, the panel's focus and row list are unchanged by this pass; `168.3-append-no-seam-call`'s anchor changed and is superseded by `168.3-append-no-rewrite` above.

Test ledger, corrective pass 1: scanned files unchanged (222; no new test module). New nodes 17 (13 in `test_b100_active_variant.py`, 4 in `test_b100_announce.py`); changed oracles: TC-67 thirty (+30 distinct rows), the panel text read as painted in `test_b100_announce.py` / `test_b100_active_variant.py` (AT-20) / `test_b100_save_image.py` (AT-05); phrase oracles flattened. Removed: 0.

Ordering note: `tests/support/b100_projects.py` gained `read_load_result_panel` after `fix1-red-01`, `fix1-green-02`, the guards and the census runs; none of those runs uses it (the RED arms and the 6 re-pinned files use only `painted_lines` / `dismiss_load_result_panel`, unchanged), and no source byte changed.

| Evidence artifact (corrective pass 1) | Path | SHA-256 |
|---|---|---|
| fix1-census-manifest-readers.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-census-manifest-readers.txt | 1852a93fcee7b830df4c4c1fbfed67a0a1f20f0fcd98a0de7cc19e16eee03a80 |
| fix1-green-00-first-run-panel-read-before-paint.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-green-00-first-run-panel-read-before-paint.txt | b4f1e7940c83ee262915f5ccd7cbfd042c0370c1460def7ecdf0235e3b643bbd |
| fix1-green-01-inc6-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-green-01-inc6-modules.txt | b69fcd6113712e920c83d7ea49dd9112962a2cd82cb6e53116579720c47dbe22 |
| fix1-green-02-repinned-files.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-green-02-repinned-files.txt | f93f0127c8463c4fd8cf0e166d34447c067824dbe4d5c1cf279c2f80f1fd9539 |
| fix1-guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-guards-census.txt | 5ee5805d7d79516e3d8ebcd00c58112c37ba3b43ba7c4a52136c7e2d558353d6 |
| fix1-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-guards.txt | 166d51e12f9196ffaf127954b70acd9d8aa0c906d14683d505a49536f9d9b381 |
| fix1-mut-168.3-append-no-rewrite.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-mut-168.3-append-no-rewrite.txt | e78245ef3cd7584d0449f4d4a240e58918d232bdad14fef452f173b7b539dc90 |
| fix1-mut-F1-no-damaged-check.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-mut-F1-no-damaged-check.txt | 41a4f12e9287212c2c0cfce001b00a9e86612cba74defb4d3131f892ed38f4b4 |
| fix1-mut-F2-now-opens-unconditional.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-mut-F2-now-opens-unconditional.txt | 8a080e38f5338a63d01af37de3747dca3e16bcff1ca8c83edba718f14a0938c8 |
| fix1-mut-F5b-scope-mark-ignored.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-mut-F5b-scope-mark-ignored.txt | 3884da0dbc674c6cca83eec2610f107e1e5e2f51edbd576ef8b811c8231b5fbe |
| fix1-mut-SEC6-6-raw-active-variant.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-mut-SEC6-6-raw-active-variant.txt | f1933fc3a3affa7f0443b356957576451362b1324d84349444f11290e832c646 |
| fix1-mut-UX1-label-uncoloured.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-mut-UX1-label-uncoloured.txt | 5f62001c0a84d42cf5ba03b3b558e454f57f60be09b5ff258f17724e9ef62293 |
| fix1-mut-UX1-reason-always-ok.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-mut-UX1-reason-always-ok.txt | 8f7e8bb38e2d828b730696ff101e0373816efd1a7ffa170ae28171613ca20602 |
| fix1-mut-UX2-entry-not-named.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-mut-UX2-entry-not-named.txt | c0e0e41590c2b9541e3527c71fa825f967cc3fa2e506cd195c7a191cce7ac1c4 |
| fix1-red-01-new-arms-vs-reviewed-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1-red-01-new-arms-vs-reviewed-tree.txt | 4f6d1be933d1788e0cc3833870b07d1c7cbb7a3f75cc3ee1377b30a82c96922a |
| fix1_mutation_harness.py | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix1_mutation_harness.py | 8ba207c6f4fdd831fcf0a654358e12218deeea90b33d82649eba06e2352712ea |

### Corrective pass 2 — test results (evidence state: `executed`)

| Run | Transcript | Result |
|---|---|---|
| RED: the 2 new arms vs the corrective-pass-1 tree (`395dcbde`, copied before this pass; hashes in the header) | `fix2-red-01-overlong-vs-pass1-tree.txt` | **2 failed** — behavioural: `ValueError: stat: path too long for Windows` out of `Path.resolve()` (the A2L-sync arm at the project load; the dialog arm: the app exits and the panel never opens — `timed out waiting for the Load-result panel holding a focus`) |
| GREEN: the 5 Inc 6 modules | `fix2-green-01-inc6-modules.txt` | **157 passed** (155 + the 2 new nodes) |
| GREEN: the 6 b99 / reuse re-pinned files | `fix2-green-02-repinned-files.txt` | **144 passed** |
| Reverse census of `_resolve_manifest_entry`: the 11 other manifest-reader modules | `fix2-census-manifest-readers.txt` | **265 passed** |
| Guards (the packet's command) | `fix2-guards.txt` | **75 passed, 29 snapshots passed** — no snapshot cell changed |
| Census sweep `-k census tests` | `fix2-guards-census.txt` | **87 passed, 3924 deselected** (3922 + the 2 new nodes) |

| Mutation | Finding | Transcript | Verdict — killing nodes |
|---|---|---|---|
| the resolver catches nothing (`except () as exc:`) | SEC6-7 | `fix2-mut-SEC6-7-no-resolve-catch.txt` | KILLED 2: TC-67 over-long entries, TC-20 A2L sync over-long (`ValueError: stat: path too long for Windows`); RESTORE OK |

Test ledger, corrective pass 2: scanned files unchanged (222). New nodes 2. Changed oracles 0. Removed 0. The harness decodes pytest output as UTF-8 (`fix2_mutation_harness.py`): a first attempt decoded it as cp1252, crashed on the "…" before writing a transcript, and restored the source (hash verified unchanged).

| Evidence artifact (corrective pass 2) | Path | SHA-256 |
|---|---|---|
| fix2-census-manifest-readers.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2-census-manifest-readers.txt | 189d321a52eb7dae8807fd3c3859695749be31db51f8c883e991c1d662124447 |
| fix2-green-01-inc6-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2-green-01-inc6-modules.txt | 3cc11b33ee2fb04e9df0c96c641cef023f8a9ca17762845ae05c76c240dd3d38 |
| fix2-green-02-repinned-files.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2-green-02-repinned-files.txt | 94150c42f85f7d46ef7d06847fe0d50424c0e52a33c79661ba0426417667d770 |
| fix2-guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2-guards-census.txt | af9c577e513eac24c08fbdb8998c112bd0a01d007761e5ef2d19c55c61abfb9b |
| fix2-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2-guards.txt | abacc3c683dbe711916659659f4fb7376224fa303097f2a47ddb62fed1f22c02 |
| fix2-mut-SEC6-7-no-resolve-catch.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2-mut-SEC6-7-no-resolve-catch.txt | be46061cfab7d2a536d03f8c8a87d353baf5e6273534b673c85644b720e463a7 |
| fix2-red-01-overlong-vs-pass1-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2-red-01-overlong-vs-pass1-tree.txt | e64faa1784271dd5ff48234aa948722aee592a6983b3fd0910e68204af88ea6f |
| fix2_mutation_harness.py | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix2_mutation_harness.py | c7a1325fbadfbf3a464e5cb4b867125d37c5fa91b4327cd9649de882e8cf3121 |

### Corrective pass 3 — test results (evidence state: `executed`)

| Run | Transcript | Result |
|---|---|---|
| RED: the 7 new arms vs the corrective-pass-2 tree (`e494c50c`, copied before this pass; hashes in the header) | `fix3-red-01-loop-and-digits-vs-pass2-tree.txt` | **7 failed** — behavioural crashes: `RuntimeError: Symlink loop` ×2 (dialog arm: the panel never opens; append arm at the project load), `ValueError: Exceeds the limit (4300 digits) for integer string conversion` ×5 (dialog arm + the 4 writer arms at the project load). The `OSError: [WinError 1921]` line in that transcript is the chained cause inside the `RuntimeError` traceback |
| GREEN: the 5 Inc 6 modules | `fix3-green-01-inc6-modules.txt` | **164 passed** (157 + the 7 new nodes) |
| GREEN: the 6 b99 / reuse re-pinned files | `fix3-green-02-repinned-files.txt` | **144 passed** |
| Reverse census of the reader's parse and the resolver: the 11 other manifest-reader modules | `fix3-census-manifest-readers.txt` | **265 passed** |
| Guards (the packet's command) | `fix3-guards.txt` | **75 passed, 29 snapshots passed** — no snapshot cell changed |
| Census sweep `-k census tests` | `fix3-guards-census.txt` | **87 passed, 3931 deselected** (3924 + the 7 new nodes) |

| Mutation | Finding | Transcript | Verdict — killing nodes |
|---|---|---|---|
| the resolver guard drops `RuntimeError` | SEC6-7 remainder | `fix3-mut-SEC6-7-loop-not-caught.txt` | KILLED 2: TC-67 junction loop, TC-20 append junction loop (`RuntimeError: Symlink loop`); RESTORE OK |
| the parse drops `ValueError` | SEC6-8 | `fix3-mut-SEC6-8-plain-valueerror-not-caught.txt` | KILLED 5: TC-67 digit limit, TC-20 damaged `int-over-digit-limit` × 4 (`ValueError: Exceeds the limit (4300 digits)`); RESTORE OK |

Junction hygiene: each junction-loop arm removes `loop` with `os.rmdir` in a `finally` (also when the arm fails, as in the RED and mutant runs); after every run no `loop` junction remained under that run's temp folder (checked with `find`). Windows-only: both junction arms skip off Windows with the named reason from `b100_links.require_junctions` (PDR C-QA-6); here they ran.

Test ledger, corrective pass 3: scanned files unchanged (222). New nodes 7. Changed oracles 0. Removed 0.

| Evidence artifact (corrective pass 3) | Path | SHA-256 |
|---|---|---|
| fix3-census-manifest-readers.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3-census-manifest-readers.txt | 2848f9d1813f58e6b24903740e274bcebeef52129c6d6aea493905e3715d1302 |
| fix3-green-01-inc6-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3-green-01-inc6-modules.txt | 60fd8688aeaf0e2c53eb2f3cb2ec159af8b56d5b32e9ac661851055fb07c015c |
| fix3-green-02-repinned-files.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3-green-02-repinned-files.txt | de633b5fb48e47b3cf5df3d82dc8ff2023ad0efd98c28ae86de1f2f007f4a900 |
| fix3-guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3-guards-census.txt | 458cdd5c124809acd6ba2c47afa464daa03c9eb9efd502844895d82bea5df515 |
| fix3-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3-guards.txt | a393f8be72686f1762a8d2f31af3579d1dfbe10a245b9b055a8f1e40d192d476 |
| fix3-mut-SEC6-7-loop-not-caught.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3-mut-SEC6-7-loop-not-caught.txt | 14a8c53e12ba00afa1e401b43ccbaefd723880096920c31a74532c7af6d94ec0 |
| fix3-mut-SEC6-8-plain-valueerror-not-caught.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3-mut-SEC6-8-plain-valueerror-not-caught.txt | e2046c522a6bcbabd6b52bb26c40f76fead9700488bac05272669ab4fe5308cf |
| fix3-red-01-loop-and-digits-vs-pass2-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3-red-01-loop-and-digits-vs-pass2-tree.txt | 05cad4f50aaecb93a4a54f09bb714346271877c7b406a682219198cbe785b34e |
| fix3_mutation_harness.py | .dev-flow/2026-10-26-batch-100/evidence/inc-6/fix3_mutation_harness.py | 955fd13b05c15ed001f96451650c76b816ebdb079f679d4bfa40c8de1e0b4a5b |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · PASS-WITH-NOTES after 2 rounds (r1 FAIL `BLOCK — BLOCK-UNTIL: F1`: F1 HIGH an in-project writer rewrote a damaged `project.json`, F2 MAJOR "now opens" painted after `Manifest write failed`, F3 MINOR docstrings, F4 MINOR wording, F5 LOW duplication; r2 PASS-WITH-NOTES: F1 discharged — the four writers share `_rewrite_project_manifest`, a damaged `project.json` is never rewritten, the placed file stays and the status says so; the reviewer re-ran probe P1 12/12 (3 damage kinds × 4 writers) and the packet's F1 mutant is KILLED 12; F2 discharged in the stricter form — `now opens` only after a written and verified manifest (P2 re-run); F3, F5 closed; F4 open → Inc 11; the panel-reading helpers are not vacuous (reviewer mutant MV KILLED 9), TC-12 panel arms killable (MA, MB KILLED)) — `review-increment-006.md`, transcripts under `evidence/inc-6/review/`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · PASS-WITH-NOTES after 4 rounds, 0 HIGH / 0 MAJOR open (`security-increment-006.md`): SEC6-1 discharged (12/12 damaged manifests byte-identical across the 4 writers); SEC6-4, SEC6-6 closed; SEC6-7 discharged (a 40 003-character entry and a junction loop → one skipped-entry row, no crash, through the real Load dialog and a variant append); SEC6-8 closed (a 5 000-digit integer → "Manifest damaged", writers leave `project.json` byte-identical); SEC6-2, SEC6-5 → Inc 7; SEC6-3 → LED .50 backlog with SEC-9 (LED .67, .68). Probe scripts were deleted with the reviewer's scratch per its brief; their hashes are in the record. Rulings: OQ-1 (a) create a missing manifest, (b) never rewrite a damaged one (LED .67); the `safe_text` guard measured in (accepted by both reviewers; LED .68). Orchestrator re-run on the final tree (`app.py` `762d1a98c8a65903`, `variant_execution_service.py` `76b276077ded9717`): reverse census batch A 1 failed / 936 passed (`orch-census-batch-a`); batch B 6 failed / 672 passed / 1 xfailed (`orch-census-batch-b`) — 3 are the known main failures b78_03, b78_32, 056e; the other 4 non-known names (tc330, tc_b94_27, tc344, at057b) were re-run in isolation twice: tc330, tc_b94_27, tc344 pass 2/2; at057b passes 1/2 on the tree and 1/2 on base `093a7c0` — a pre-existing timing flake, not introduced here (`orch-isolation-rerun`); guards 75 passed + 29 snapshots (`orch-guards`); census sweep 87 passed (`orch-census-k`). E13 (C-UX-5) re-captured on the final tree at 118×54, 220×60, 99×54 for 5 plans (`evidence/inc-6/e13/`, 15 PNGs, real Windows Terminal, truecolor); `tools/e13/capture.ps1` made DPI-aware in this close, because the earlier captures were cropped to the logical window rect. |

---

## 5 · Risks

- **A writer now creates `project.json` in a project that had none (OQ-1).** HLR-168 says every in-project writer rewrites the manifest through the seam; `_manifest_carry` returns `{}` when there is no manifest and the seam writes one. Consequence: such a project's Execute moves from "no manifest → the loaded document over every variant" to "manifest present" (`_trigger_execute_scope`). Projects made by Save project always had a manifest; only hand-made folders are affected. Orchestrator ruling requested.
- ~~A damaged `project.json` is replaced~~ — **resolved in corrective pass 1** (OQ-1 ruling (b)): a damaged `project.json` is never rewritten by an in-project writer; the status says so and the placed file stays. Residual: until the user runs Save project, the session's active variant can differ from the damaged file on disk (the status names the recovery).
- **Corrective pass 1, the session vs disk after a failed write.** When the write fails or the verify mismatches, the session has switched to the appended / saved-back variant while `project.json` still names the old one; "now opens" is no longer claimed, and `Manifest write failed` / `Manifest verify MISMATCH` stays on screen.
- **Corrective pass 1, the panel now renders Rich `Table` grids.** A test reading a panel `Static` with `str(widget.render())` gets no text; the support helpers read the painted strips instead.
- **Entries the reader skipped are not carried** (unsafe or malformed); the serializer would refuse them anyway. A path the reader normalised (`a/../b.json`) is carried in its resolved form.
- **`Project saved + manifest verified` after a variant append / MAC / A2L sync.** The seam's verify line now follows every writer; "Project saved" is the seam's wording, slightly off for a sync, and it is the newest line after a MAC / A2L sync (the AT-B99-11 re-pin). A UX note for Inc 11 (status design); the seam's text is not changed here.
- **The summary line is composed for 118 columns**; the log caps each line at the terminal width, so at `run_test`'s 80-column default the `details: p` tail is clipped (visible in `census-tree-shard1.txt`, P1's line). The contract's threshold is "inside 118 columns".
- **App single keys behind the panel.** Like the existing modals, app bindings (e.g. `p`) still reach the app while the panel is open. Not changed.

## 6 · Pending items / spec deviations

- **OQ-1 — ruled and implemented (corrective pass 1):** (a) a writer creates `project.json` where none exists — kept; (b) a damaged one is never rewritten by the four in-project writers — implemented (`_rewrite_project_manifest`); Save project stays the recovery path.
- **Deferred from the Inc 6 reviews (not implemented here, by ruling):**
  - **F4** — the seam's `Project saved + manifest verified` wording after a MAC / A2L sync or a variant append -> **Inc 11** (status design).
  - **SEC6-2** — unknown top-level keys and a newer `schema_version` dropped by an in-project rewrite -> **Inc 7** (manifest-keys mode, LLR-168.4 / HLR-169).
  - **SEC6-3** — the manifest writer resolves before its containment check (junction swap race) -> the **LED .50 backlog** item with SEC-9 (`manifest_writer.py` would be a fifth source file).
  - **SEC6-5** — one panel row per manifest issue, no cap (6 000 entries -> ~10 s) -> **Inc 7** (1 MiB / 1 000-entry caps, one problem per file).
  - **"details: p"** in the summary line points at the Load dialog's preview of the open project, which arrives at **Inc 9b**.
  - **UX-1's "not readable" mark** in the error colour -> **Inc 7** (no readability state exists before HLR-169's problem kinds).
- **SEC6-7 — fixed in corrective pass 2** (an unresolvable entry is one skipped-entry row, never a crash; every entry clipped to 120 characters). Not covered: POSIX `resolve()` limits were not exercised (Windows only ran).
- **SEC6-7 remainder (junction loop -> `RuntimeError`) and SEC6-8 (an integer over the digit limit -> plain `ValueError`) — fixed in corrective pass 3.** Not covered: a POSIX symlink loop (`ELOOP` maps to the same `RuntimeError` in `pathlib`, reasoned, not executed).
- **Guard measured in, not stopped (declared deviation from BRIEF-COMMON step 5).** `test_import_census.py::MEASURED_SAFE_TEXT_CONSUMERS` gained `s19_app.tui.screens`. The guard's own comment prescribes "measured in" for a new consumer, and LLR-178.3 requires `safe_text` in the panel. If the orchestrator prefers a STOP, revert that one test change and rule.
- **Deferred arms, each to the increment the contract index names:** the "patched, N bytes differ" line and the `derived_from` carry (Inc 7); the `active_document` carry and AT-B100-20's document and Execute-scope arms (Inc 8a / 9b); the Load dialog's preview of the open project showing the same announcement (LLR-178.3's last sentence; TC-B100-67 "the preview lists the same 30") — the Load dialog with a preview arrives at Inc 9b, and `_last_load_announcement` is kept for it; TC-B100-55's "first variant by name" mutation arm (Inc 7, ARCH-PDR-3).
- **"not readable"** detection for the `next-valid` reason arrives with HLR-169's problem kinds (Inc 7); at Inc 6 the reason fires when the recorded variant is missing.
- **Problems at Inc 6** are the manifest findings in user terms plus the missing recorded variant (and "No manifest"); HLR-169's per-file kinds and the one-per-file merge are Inc 7. The precedence ranks are local constants Inc 7 extends.
- **Existing status kept:** `Manifest active_variant '<x>' not found - activating the first variant.` still precedes the summary line.
- **LED .63 respected:** `gathered` is not added to `_save_manifest_keys()` / the Save project plan; Inc 6 only reads and carries it.
- **Scratch note:** a same-named runner `scratchpad/py.sh` from an earlier session (the scratchpad is shared) may have been overwritten before this session moved its runner under `scratchpad/inc6-impl/`.

## 7 · Suggested next task

Re-review of corrective pass 1: `code-reviewer` re-reads `_rewrite_project_manifest` on the diff and re-runs probe P1 (F1 discharge); `security-reviewer` re-runs scenario A (SEC6-1) and the SEC6-4 / SEC6-6 probes; the orchestrator re-captures the panel at 99×54 / 118×54 / 220×60 against `pe_B.pe-problems.118.png` (UX-1..UX-3). Corrective pass 2: `security-reviewer` re-runs the SEC6-7 probe (a 40 003-character `gathered` entry through the real Load dialog). Corrective pass 3: `security-reviewer` re-runs the junction-loop and 5 000-digit probes. Then Increment 7.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4/4, declared at cap (design proposal §5.6) — §2 |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_active_variant.py` (18), `test_b100_announce.py` (20), TC-12 panel arms (2) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | TC-55 (pure composer, 9 nodes), TC-18 (reader, 5) |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-02`, `red-03`, `red-04` |
| 5 | Reverse census declared | `core` · `full` | ✓ | §4: 38 files, 16 census failures dispositioned (13 re-pinned nodes in 7 files + 3 pre-existing at base), base vs tree for each; plus the guard measured in |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES r2 |
| 7 | No file from another lane touched | all | ✓ | the 4 named sources + tests / fixtures / config |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | B100-I2 (`gathered`) and B100-I7 frozen here as specified; B100-I13 consumed unchanged |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript |
| 10 | Load-bearing emptiness declared | all | ✓ | TC-19 no-project arm (0 manifests) rests on the save-back landing in the work-area root — asserted (`out.s19` exists) |
| 11 | Mutation verdicts declared — per arm | all | ✓ | 9 mutations, all KILLED; TC-12 panel arms killed by the reviewer's MA / MB; corrective pass 1: 8 more, all KILLED (UX-3 by its executed RED); corrective pass 2: 1 more, KILLED; corrective pass 3: 2 more, KILLED |
| 12 | Instrument RED-proof declared | all | ✓ | §4 Instrument RED-proof |
| 13 | Correction population declared | all | ✓ | the in-project writers: save-back, append, MAC data-file sync, attached-MAC sync, A2L sync (5 call sites, all rewrite); Save project already used the seam. The bypassing writers (flow WRITE-OUT, external step, variant execution) stay as B100-I7 records them |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b — `code-reviewer`, `security-reviewer` |
| 16 | Evidence files declared | all | ✓ | §4 evidence table |
