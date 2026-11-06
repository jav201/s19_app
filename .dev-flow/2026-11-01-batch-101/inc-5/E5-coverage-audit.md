# Inc 5 — E5 coverage audit

Batch 2026-11-01-batch-101, increment 5, stage E5. Worktree head `8fc3cd3` (branch `b101-inc5`). Role: coverage auditor (qa-reviewer). I did not write the cases, the tests or the integration. Mode: **validation** of the coverage records. This file is the only file I wrote; `02-test-cases.md` is not edited.

**Inputs read:** `01-requirements.md` (12 active rows), `02-test-cases.md` (34 cases), `E4-tester1-notes.md`, `E4-tester2-notes.md`, `E4-integration-notes.md` (I-D1 … I-D7, mutant table M1 … M24), `E3-rulings.md` (round 2 NOTEs), `E1-rulings.md` (E1-D3, E1-D5); transcripts `evidence/inc-5/red-01-tester1-base.txt`, `red-01-tester2-base.txt`, `int-01.txt`, `int-08.txt` (headers of the others); the test bodies `tests/test_b101_designer_writes.py` (10 nodes), `tests/test_b101_check_spec_keep.py` (26 nodes), `tests/test_b101_symbol_reads.py::test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` and the drive helpers they import (`test_b101_symbol_reads.py` helpers, `tests/support/b101_designer.py`, `b100_projects.py`, `b100_save_dialog.py`); product code only to settle "does the product produce this observable" (`crc_designer_view.py` `_on_image_changed` / `note_image_bytes_written` / `on_show`, `app.py:7520` spec-pick status). Rules: TCP-MAP-1, -3, -5, -6, -7, TCP-TRC-4, TCP-EVD-1 … -4 from `s19w/test-cases/TC-PROFILE.md`, and the flow's E4 rule (stand-in, painted style, pre-shown fixture, entry with no product caller → partial).

**Evidence:**
- **Executed by this auditor (Windows PC, no import of `s19_app`):** `git rev-parse` of every source and test file in the tested index tree `10e1b162` against `8fc3cd3` — all 8 code, test and guide blobs are identical; `git diff 10e1b162 8fc3cd3` touches only `.dev-flow` records. So int-01 and int-08 hold for this commit. No test, no `--collect-only` (it would import `s19_app`).
- **Inspection (cannot show behaviour):** node counts — 10 + 26 + 22 non-`serial_timing` nodes of `test_b101_symbol_reads.py` = **58**, the count int-01 and int-08 report as passed (no class-based tests; xdist does not print the 2 deselected timing nodes).
- **Not executed by this auditor:** every pass and fail below. Executed by the E4 integrator (Opus) on the LAN Linux host: `int-01` (58 passed) and `int-08` (399 passed, 4 Windows-only skips in other files; the same three files included). Base RED executed by E4 tester 1 (`red-01-tester1-base`, 8 failed / 2 passed) and tester 2 (`red-01-tester2-base`, 21 failed / 6 passed). No mutant has run; the battery is running now (`E5-mutants.md` pending).

## 1. Summary

| Count | Value |
|---|---|
| Cases audited | 34 (7 CRC Designer, 27 Check Editor) |
| Tests mark `full` → `partial` | **7**: R-CRC-PREVIEW-002.5/3, /4, /7, /8; R-CHKED-056/1, /2, /3 |
| Coverage `covered` → `partial` | **10**: the 7 above plus 002.5/6, 041.3/5, 041.3/6 (their only node was already `partial`; TCP-TRC-4) |
| Tests-column label only: `full` → `full (output); drive partial` | 16 cases (002.5/4, /7 and 14 Check Editor cases, §2) — 11 of them changed by nothing else |
| Result column (record-wide R-1) | 27 Check Editor cases: `verified (linux, int-01)` → `verified 2 of 3 runs (linux, int-01, int-08); 1 run owed` |
| Case-text changes (Inputs / Preconditions) | 002.5/8 (Inputs, I-D3); 056/1, /2, /3 (Preconditions); 002.5/4, /7, /8 (Preconditions wording) |
| Cited node ids that do not resolve | 0 (but "N" names a file that no longer exists, R-3) |
| Result for this commit | backed: int-01 and int-08 ran the tree whose code and tests equal `8fc3cd3` (verified by me); Linux only |
| **Substantive changes (mark or coverage)** | **10 of 34 = 29.4 %** |
| With the drive labels | 21 of 34 = 61.8 % |
| Any column, with the record-wide Result fix | 32 of 34 = 94.1 % (unchanged: 002.1/6, 002.5/5) |
| Requirement clauses with no discriminating case | 4 (§4) |
| Rows whose negative control nothing exercises yet | 4 (010/1, 025/1, 027/1, the byte clause of 056) plus 041.3/1 until M12's list is extended (§5) |
| Black-box ATs owed (keys and dialogs) | 4 (§6) |

### Top issues
1. **R-CHKED-056/1–/3 do not discriminate "the expected bytes of its spec entry".** The image is never patched, so the spec's bytes equal the image's at every address the cases read (the row's own Base column says so). A demotion that creates a plain session memory row, which reads the image, writes the same `0x0 6C` and passes. No other case combines a demotion with a changed image, and no mutant targets it. TCP-MAP-6 / -5(c) → `partial`. Fix: patch `0x0` to `93` before the pick (as `patched_pick` already does for 026); the expected `0x0 6C` stays.
2. **"0 recomputes before key `0`" is read from a snapshot taken after the write settled** in 002.5/3, /4, /6, /7, /8 (`before = designer_recomputes()` follows `_apply` / `_save_back` and their pauses). A recompute run inside the write is outside the window. M4 is still killed (through the refresh wait timing out when the hidden recompute clears the stale flag), but a hook that recomputes and then marks stale passes. /5 and 002.1/6 take the snapshot before the trigger and are exact. TCP-MAP-1 → `partial`. Fix: move the snapshot above the trigger — one line per node.
3. **The Check Editor half runs each case once per pytest run; its thresholds say 3/3.** Tester 1 loops 3 fresh apps per node (`REPS = 3`); tester 2 does not. On record: int-01 and int-08, so 2 of 3 runs. One more run at `8fc3cd3` (or a 3-rep loop) closes it.
4. **The record's Drive definition and its marks disagree.** The header says "a direct message post or a seam call makes the case `partial`", yet 16 cases marked `full` press the trigger with `Button.press()` (which posts `Button.Pressed`) and set `Input.value`. Per CLAUDE.md rule 7, I pick one: the flow's E4 rule and this batch's Inc 4 and Inc 13 audits (`Button.press()` / `Input.value` are on the product route — a click calls `press()` — so the output stays `full`; the drive is partial and a black-box AT is owed). Reword the header (R-2); the other reading would turn all 16 `partial`.
5. **No AT exists for Write, Validate, the memory-row Add or the save-back confirm through keys and clicks.** Tester 1 records that the save-back confirm sits under the status bar's clip at 160×54, so the pilot cannot click it — whether an operator can reach it by keys is untested (§6, AT-I5-4).

## 2. Per-case table

Tests = the strongest node's mark. Neg. control: `red-on-base` = executed in `red-01-testerN` (base `c2cba35`); `M#` = the integration mutant table, all **pending mutants**. Result source: int-01 (and int-08), executed by the E4 integrator.

| Case | Tests (old → new) | Coverage (old → new) | Result (old → new) | Neg. control | Reason (one line) |
|---|---|---|---|---|---|
| R-CRC-PREVIEW-002.1/6 | full | covered | verified (linux, int-01) | red-on-base (both limbs); M3 pending mutants | (a) Q 10 s set after the setup display; snapshot before `ctrl+s`; delta 0 and `_pending_recompute` set after 2 pauses. (b) snapshot before the commit; +1, exact three lines, crc32 of `mem_map`, literal BB, window line 2. 3 reps. Commit by the real Save dialog (`ctrl+s`, typed name, `#save_ok` click). |
| R-CRC-PREVIEW-002.5/3 | full → **partial** | covered → **partial** | verified | red-on-base; M1, M4 pending mutants | Drive fully real (Load dialog, typed path, clicks, keys). Snapshot after the apply settles (top issue 2). Every other clause exact. |
| R-CRC-PREVIEW-002.5/4 | full → **partial**; drive partial | covered → **partial** | verified | red-on-base; M2, M4 pending mutants | Snapshot after `_save_back` (top issue 2). The trigger (save-back confirm) is `Button.press()`. The setup display is made fresh by a Ranges spelling edit, not by key `0` alone. |
| R-CRC-PREVIEW-002.5/5 | full | covered | verified | red-on-base; M3, M4 pending mutants | Snapshot before `ctrl+s`; commit through the dialog; exact. Project opened by the shipped handler (precondition only). |
| R-CRC-PREVIEW-002.5/6 | partial (fault injected) | covered → **partial** | verified | red-on-base; M1, M4, M5 pending mutants | TCP-TRC-4: no `full` node. Also snapshot after the apply (top issue 2) — add to the "what". |
| R-CRC-PREVIEW-002.5/7 | full → **partial**; drive partial | covered → **partial** | verified | red-on-base; M2, M4, M6 pending mutants | Snapshot after the blocked save-back (top issue 2); confirm by `Button.press()`. Exact status, no file, `02`/`03`, PRE. |
| R-CRC-PREVIEW-002.5/8 | full → **partial** | covered → **partial** | verified | red-on-base; M1, M4, M7 pending mutants | Snapshot after the second apply (top issue 2). Inputs differ from the case: Remove `0x8003` + Add `0x9000 = AA` (I-D3); correct the case text (C-4). |
| R-CHKED-010/1 | full | covered | verified → 2 of 3 runs | base GREEN (standing guard); **no mutant** (M8 is not reached on a plain return) → none-recorded | Keys `1`, `=`; picks, both ✓ cells, head line exact. Add M25 (§5). |
| R-CHKED-010/2 | full | covered | → 2 of 3 runs | red-on-base; M8 pending mutants | Reload confirmed by `_a2l_view_generation`, so a silent no-op reload cannot pass. |
| R-CHKED-010/3 | full | covered | → 2 of 3 runs | red-on-base; M8 pending mutants | Reload confirmed by `_image_generation`. |
| R-CHKED-055/1 | full → full (output); drive partial | covered | → 2 of 3 runs | red-on-base; M9 (+M8) pending mutants | All four clauses exact; the Write clause is `Input.value` + `Button.press()`. |
| R-CHKED-054/1 | full → full (output); drive partial | covered | → 2 of 3 runs | base GREEN; M10 pending mutants | The trigger (Write) is `Button.press()` with the name set by `Input.value`. |
| R-CHKED-041.1/1 | full | covered | → 2 of 3 runs | base GREEN; M11, M12 pending mutants | Pick by click, arrows, enter; status `lines[-1]` exact; 3 fields; none of the old ones. |
| R-CHKED-041.2/1 | full | covered | → 2 of 3 runs | red-on-base; M12, M13 pending mutants | Exact four Fields lines and both ✓. The "in entry order" clause is not discriminated (§4). |
| R-CHKED-041.2/2 | full | covered | → 2 of 3 runs | red-on-base; M13 pending mutants | Exact status; symbol tag (from the generated doc) included; picks + rows = 3. |
| R-CHKED-041.2/3 | full | covered | → 2 of 3 runs | red-on-base; M13, M14 pending mutants | `[BETA]`, 0 rows; twin A2L through the Load dialog. |
| R-CHKED-041.3/1 | full | covered | → 2 of 3 runs | base GREEN; **no listed mutant** (M12 would kill it: add 041_3_1 to its list) | 0 included, 3 rows, `—` labels, lines end `memory row`. |
| R-CHKED-041.3/2 | full | covered | → 2 of 3 runs | red-on-base; M13 (not listed; add) pending mutants | `—` label exact; the included pair proves resolution ran. |
| R-CHKED-041.3/3 | full | covered | → 2 of 3 runs | red-on-base (via the control); M15 pending mutants | Row exact incl. `u8`; same-session positive control. |
| R-CHKED-041.3/4 | full | covered | → 2 of 3 runs | red-on-base (via the control); M16 pending mutants | Row exact; positive control `[BETA]`. |
| R-CHKED-041.3/5 | partial (seam) | covered → **partial** (or ruled `not-testable` per E3 round-2 NOTE) | → 2 of 3 runs | red-on-base; M17 pending mutants | TCP-TRC-4. The status clause `… (2 fields).` is not asserted: the pick handler (`app.py:7520`) paints it, `load_spec` does not — say so in the "what". |
| R-CHKED-041.3/6 | partial (seam) | covered → **partial** | → 2 of 3 runs | red-on-base (via the control); M18 pending mutants | TCP-TRC-4; ledger and item both through panel methods, as the case states (E1-D3). |
| R-CHKED-025/1 | full → full (output); drive partial | covered | → 2 of 3 runs | base GREEN; **no mutant** → none-recorded | Include by `space` (cursor placed by `move_cursor`); Write by `press()`. Add M26 (§5). |
| R-CHKED-025/2 | full → full (output); drive partial | covered | → 2 of 3 runs | red-on-base; M19 pending mutants | Image patched first, so `93` vs `6C` discriminates. |
| R-CHKED-025/3 | full → full (output); drive partial | covered | → 2 of 3 runs | red-on-base; M24 (+M8) pending mutants | *A*'s byte ≠ `6C` by construction; 4 entries in order. Its `0x0 6C` entry has top issue 1's blind spot, but that clause belongs to 056. |
| R-CHKED-026/1 | full → full (output); drive partial | covered | → 2 of 3 runs | red-on-base; M20 pending mutants | `0x0 6C` vs image `93`. |
| R-CHKED-026/2 | full → full (output); drive partial | covered | → 2 of 3 runs | red-on-base; M20 pending mutants | Status and painted result row exact; Validate by `press()`. |
| R-CHKED-026/3 | full → full (output); drive partial | covered | → 2 of 3 runs | red-on-base; M20 pending mutants | `FF FF FF FF` vs patched `00 00 00 00`. |
| R-CHKED-026/4 | full → full (output); drive partial | covered | → 2 of 3 runs | red-on-base; M20, M21, M8 pending mutants | Same-range reload confirmed by generation; spec bytes vs `93`. |
| R-CHKED-027/1 | full → full (output); drive partial | covered | → 2 of 3 runs | base GREEN; **no mutant** → none-recorded | Status exact; inside-row control makes "left out" selective. Add M27 (§5). |
| R-CHKED-027/2 | full → full (output); drive partial | covered | → 2 of 3 runs | red-on-base; M20 pending mutants | Image unloaded by a `[u]` click; no image bytes exist, so the spec's bytes are discriminated. |
| R-CHKED-056/1 | full → **partial**; drive partial | covered → **partial** | → 2 of 3 runs | red-on-base; M13, M22, M24 pending mutants; byte clause: none | Address, order, labels, head, status, none at *A*: exact. Spec-bytes clause undiscriminated (top issue 1). |
| R-CHKED-056/2 | full → **partial**; drive partial | covered → **partial** | → 2 of 3 runs | red-on-base; M13, M22, M24 pending mutants; byte clause: none | As /1; `VALUE_0001_R` not included. |
| R-CHKED-056/3 | full → **partial**; drive partial | covered → **partial** | → 2 of 3 runs | red-on-base; M13, M22, M23, M24 pending mutants; byte clause: none | The size clause discriminates (A2L says 2 bytes); the bytes do not (top issue 1). |

## 3. Proposed changes (old → new, why) — for the record's owner

| # | Where | Old → new | Why |
|---|---|---|---|
| C-1 | `02-test-cases.md` 002.5/3, /4, /7, /8: Tests, Coverage | full → partial; covered → partial (back to full once C-2 lands) | Top issue 2 (TCP-MAP-1). |
| C-2 | `test_b101_designer_writes.py` /3, /4, /6, /7, /8 | `before = designer_recomputes()` after the write → before the trigger (above `_apply(...)` in /3, /6, /8's second apply; above `_save_back(...)` in /4, /7) | Makes "0 recomputes before key `0`" exact, as /5 and 002.1/6 already are. The setup display has settled (pending `None`) before every trigger, so nothing else moves the count. |
| C-3 | 002.5/6, 041.3/5, 041.3/6: Coverage | covered → partial (041.3/5 may instead be ruled `not-testable`, E3 round-2 NOTE) | TCP-TRC-4: `covered` needs a `full` node. 041.3/5's "what": add "status clause not asserted (painted by the pick handler, not `load_spec`)". |
| C-4 | 002.5/8: Inputs | "the entry's address edited to `0x9000`" → "the `0x8003` entry removed and a `0x9000` = `AA` entry added (same document)" | I-D3: the entry editor cannot move an address; the test does Remove + Add. Fold the same wording into row R-CRC-PREVIEW-002.5's threshold at the canon fold. |
| C-5 | 002.5/4, /7, /8: Preconditions | "key `0` once (`concat: 0x08DAAFB7`)" → "key `0` and a Ranges spelling edit, recompute settled (`0x08DAAFB7`); no display before the apply" | What the tests do (tester 1 note): the setup display must not depend on /3's behaviour. Wording only. |
| C-6 | 056/1, /2, /3: Preconditions; Tests, Coverage | add "a Patch Editor apply set `0x0` to `93`" before the pick; full → partial, covered → partial until C-7 lands | Top issue 1 (TCP-MAP-6). Same change to row R-CHKED-056's threshold; its Base note already admits the blind spot. |
| C-7 | `test_b101_check_spec_keep.py` `relayout_and_write` | add `await apply_bytes(pilot, app, log, tmp_path, f.v1.address, bytes([PATCH_BYTE]))` before `pick_spec`; expected stays `0x0 6C` | Makes the spec-bytes clause RED for a demoted row that reads the image. |
| C-8 | 14 Check Editor cases + 002.5/4, /7: Tests | full → full (output); drive partial (`Button.press()` / `Input.value`) | Top issue 4; Inc 4 audit precedent (C-5 … C-7 there). |
| R-1 | 27 Check Editor cases: Result | `verified (linux, int-01)` → `verified 2 of 3 runs (linux, int-01, int-08); 1 run owed` | Thresholds say 3/3; one app per node; two runs on record. Close with one more run of `test_b101_check_spec_keep.py` + the symbol-reads node at `8fc3cd3`, or a 3-rep loop as in the designer file. |
| R-2 | `02-test-cases.md` header, **Drive** | "a direct message post or a seam call makes the case `partial`" → "`Button.press()` on a shipped button or an `Input.value` set is the product route for the output (`full`) but makes the drive partial; a message posted to the app, a panel method called directly, or an injected fault makes the case `partial`" | Top issue 4: the record's sentence and its own marks conflict. |
| R-3 | `02-test-cases.md` Tests column | "N `test_…`" → `tests/test_b101_designer_writes.py::…` / `tests/test_b101_check_spec_keep.py::…` (or define D and C) | TCP-MAP-3: N names the planned file that the orchestrator split. |
| R-4 | `02-test-cases.md` header and footer | drop "**Result** is `not_run` everywhere" and "Covered by an existing node today: none fully …" | Stale since E4 integration set the columns. |
| R-5 | Result column | add `windows: not_run (operator rule)` | TCP-EVD-3: verification per platform. |
| R-6 | Evidence note | int-01 / int-08 are `-q` runs with no node ids and no junit; the per-node pass is inferred from 58 = 10 + 26 + 22 | TCP-EVD-1. Accepted here (no failure, count matches); the batch-end run should emit junit. |

## 4. Requirement clauses with no discriminating case

1. **R-CHKED-056 "expected bytes of its spec entry"** — no case changes the image before a demotion (top issue 1; C-6, C-7).
2. **R-CHKED-041.2 "in entry order"** — every spec in the cases lists its named parameters in A2L (address) order, so a build that includes them in ledger order passes. Add 041.2/4: a spec whose entries are `VALUE_0002` then `VALUE_0001` → included `[VALUE_0002, VALUE_0001]`, Fields lines in that order.
3. **Loaded image changes, "a save-back … whatever its outcome"** — success (/4) and blocked (/7) are covered; a save-back that raises after it adopted the re-derived bytes is not (integration-notes observation; the hook would not run). Add a robustness case or rule it with the reviewers.
4. **R-CHKED-010 / *still lists* for a field included in this session** — only the name counts for such a field, so a parameter included by `space` that a new A2L moves must stay included at its new address. No case covers it (055/1 covers "not listed"; 025/3 includes after the move, not before).

## 5. Negative controls

- **Exercised so far:** RED on base for 29 nodes (8 designer, 21 Check Editor), executed by the testers. Every mutant row is **pending mutants**.
- **No control on record yet (standing guards with no mutant):** propose
  - **M25** — `_prefill_check_editor`: `panel._picker.clear_picks()` at entry → C 010_1 (and 010_2, 010_3, 054_1). M8 cannot reach 010/1: a plain return reuses the signature and never calls `set_a2l_parameters`.
  - **M26** — `_check_items_to_document`: a session field's expected bytes = `bytes(size)` → C 025_1, 025_2, 025_3, 027_1.
  - **M27** — the declared-field test skipped (every field declared) → C 027_1 (entry at `0xF000000` or no status).
  - **M28** (needs C-7) — `_demote_moved_spec_params`: append the row with spec bytes `None` → C 056_1, 056_2, 056_3.
- **Expected lists to extend** (so a RED is not read as unexpected): M12 → 041_3_1; M13 → 041_3_2 … 041_3_6 (resolution gone; the positive controls of /3, /4, /6 fail).
- **M4 note:** in /3, /4, /6, /7, /8 the RED may come from the refresh wait timing out rather than from "a hidden CRC Designer recomputed", depending on whether the 0.05 s timer fires before the snapshot. Either is a kill; after C-2 it is the named assertion.

## 6. Black-box ATs owed (keys and dialogs)

Already black-box for the trigger: 002.5/3 and /8 (Load dialog, typed path, clicks, rail keys), 002.5/5 and 002.1/6 (`ctrl+s` dialog), and every Check Editor pick (click, arrows, enter), A2L/image load (dialog) and return (keys `1`, `=`). Accepted setup seams: the Ranges `Input.value` set, the project opened by its handler, the ledger cursor placed by `move_cursor` before a real `space`, specs staged by file copy.

Not reached by keys or clicks anywhere: **Write**, **Validate**, the **memory-row Add** (`Input.value` + `Button.press()`), and the **save-back confirm** (`Button.press()`). Owed:

1. **AT-I5-1 (US-CHK-KEEP-1):** key `=`; arrows + `space` on two ledger rows; type address, label and size and click Add; type the file name; click Write (or focus + enter) → `Check Editor: wrote pilot_fields.chk.json (3 fields, kind=check).`, painted head line and ✓ cells unchanged; then key `1`, `l`, typed A2L path, Load click, key `=` → head line and ✓ unchanged (054/1 + 010/2).
2. **AT-I5-2 (US-CHK-SPEC-1, F-27 + D9-11):** key `6`, typed change-document path, Load and Apply clicks (`0x0` → `93`); key `=`; pilot spec picked by keys → painted Fields lines with names (041.2/1); type name, click Write → file `0x0 6C` (026/1); click Validate → `Checks: 2 passed, 1 failed, 0 uncheckable` and the painted drift row (026/2).
3. **AT-I5-3 (SEC5-1):** as AT-I5-2 to the pick; key `1`; the moved A2L through the Load dialog; key `=` → painted memory table and head line; Write by click → `0x14 A0 BE`, `0xC00FFC FF FF FF FF`, `0x0 6C` with the image at `0x0` = `93` (056/1 with C-6).
4. **AT-I5-4 (US-CRC-FRESH-2, save-back):** 002.5/4 and /7 with the confirm reached by keys (focus + enter) or by a click at a size where the row is visible. Tester 1 reports the row clipped by the status bar at 160×54; if no key reaches it there, that is a product finding, not a test choice.

## 7. Totals (as they should stand)

| Count | E4 record | This audit |
|---|---|---|
| Covered | 34 | **24** |
| Partial | 0 | **10** (002.5/3, /4, /6, /7, /8; 041.3/5, /6; 056/1, /2, /3) |
| Gap / conflict / not-testable | 0 | 0 (041.3/5 may be ruled not-testable) |
| Result | 34 verified (linux, int-01) | 7 designer verified (2 runs × 3 reps); 27 Check Editor verified 2 of 3 runs, 1 run owed; windows not_run |
| Negative controls | — | red-on-base 29 nodes executed; M1 … M24 pending mutants; 4 rows with none (M25 … M28 proposed) |
| Cases changed | — | substantive 10/34 = **29.4 %**; with drive labels 21/34 = 61.8 %; any column 32/34 = 94.1 % |
