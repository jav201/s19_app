# Inc 5 — E5 security review (implemented code, probed)

Batch 2026-11-01-batch-101, increment 5, branch `b101-inc5`, head `8fc3cd3`, base `c2cba35`. Reviewer: security-reviewer, independent of the implementers, the testers and the integrator. Scope: `git diff c2cba35 8fc3cd3 -- s19_app tests docs` (3 source files: `app.py`, `crc_designer_view.py`, `screens_directionb.py`; the guide `ch10-check-editor.md`; 4 test files). Records read: `E3-security.md` (SEC5-1 … SEC5-6, Round 2: R2-1, R2-N1, R2-N2), `E3-rulings.md` (both rounds), `E1-rulings.md` §1, E1-D5, §6, `E4-impl-notes-app.md`, `E4-impl-notes-ched.md`, `E4-integration-notes.md` (incl. its mutant table), `E4-tester1-notes.md`, `E4-tester2-notes.md`.

Lens (as at E3): a stale or wrong CRC or check verdict an operator would copy into a release; declared bytes never judged at a moved address; untrusted A2L / `.chk.json` names painted only through escapers; the meaning of saved files unchanged except as ruled; no new file write outside the existing writers; no clipboard.

## Verdict

**PASS-WITH-NOTES.** HIGH 0, MEDIUM 1, LOW 0, INFO 2.

- Every E3 mitigation ruled into this increment is `executed` in the code and `approved`: its cases are GREEN on the integrated tree, and the negative control named for it turns them RED for the stated reason. That covers SEC5-1, SEC5-2, A-2 and the D-4 hook placement. The record-only rulings are `executed` in the records: SEC5-3, SEC5-4, SEC5-5 and R2-1.
- SEC5-1 (HIGH at E3) is closed in code. The name-only key is the E1 design and the ruled negative control. As a mutant it turns R-CHKED-056/1, /2, /3 and R-CHKED-025/3 RED (4 of 4).
- One new MEDIUM, E5-S1 (`design-gap`). After a Validate, the Check Editor keeps painting its verdict rows under `validation complete` through later image writes. The probe showed a stale `-> pass` where a fresh Validate reports `fail`. Not blocking; the orchestrator rules it.
- This clearance covers the security lens of the E5 gate only. It is not the operator's authorization to merge.

## How it was probed

- **Host.** LAN Linux host 2 only (env `s19ci`, Python 3.11).
- **Tree.** A detached worktree `<HOME>/work/s19_i5s` at `m4fix-main` (= `c2cba35`, checked) with `git diff --binary c2cba35 8fc3cd3 -- s19_app tests docs` applied and staged. The staged subtrees equal `8fc3cd3`'s: `s19_app` `f4537bf`, `tests` `1c15bac`, `docs` `9dd3f31`. `s19_app.__file__` = the worktree.
- **Helpers.** Prefixed `i5s-`: a mutant script that changes text only and imports nothing from the project, a runner script, and one temporary probe test. The worktree and every helper were removed afterwards; `git worktree list` shows 0 `s19_i5s` entries.
  - The `git worktree prune` at teardown found the directories of `s19_m4fix` and `s19_merge4` already gone: another session removed them during the run. Prune only drops admin entries for missing directories, so nothing of theirs was deleted here.
- **Windows.** Nothing that imports `s19_app` ran on the Windows PC.
- **Run 1 — base.** Both new test files on the integrated tree: **36 passed** (3:17).
- **Run 2 — mutants.** One at a time from the E4 mutant table (ids as there; each described by its operation, not spelled out here). Only the security-relevant ones, and only the nodes each one claims. The original files were copied back after each mutant. After the last mutant, `git diff --stat` against the staged increment is empty, so the tree came back. Every RED below fails on an assertion about the behaviour, never at import or by timeout. The assertion texts are quoted in the table.
- **Run 3 — probe `i5s-stale-verdict`.** For E5-S1, see below.

### Mutant results (security subset)

| Id | Operation | Nodes run | Result | RED reason (assertion) |
|---|---|---|---|---|
| M24 | SEC5-1 negative control: the spec-bytes key by name only (no demotion, prune and collected-items range tests removed) | 056/1, 056/2, 056/3, 025/3 | **KILLED 4/4** | included `[VALUE_0001, VALUE_0002]` ≠ `[VALUE_0002]`; memory rows lack the `0x00000000 — u8` row |
| M22 | demotion appends no memory row (the R-CHKED-055 drop applied to a spec field) | 056/1, 056/2, 056/3 | **KILLED 3/3** | memory rows `[0x00C00FFC — u32]` only |
| M23 | byte count left out of the range key (3 places) | 056/3 | **KILLED 1/1** | resized `VALUE_0001` stays included |
| M20 | spec bytes branch of the document builder disabled (base: image re-read) | 026/1, 026/2, 026/3, 026/4, 027/2 | **KILLED 5/5** | entry `0x0` `93` instead of `6C`; `Checks: 3 passed, 0 failed` instead of `2 passed, 1 failed`; `3 field(s) outside the loaded image` |
| M21 | spec bytes cleared on every repopulation | 026/4 | **KILLED 1/1** | entry `0x0` `93` |
| M19 | no prune on an include/exclude toggle | 025/2 | **KILLED 1/1** | entry `0x0` keeps `6C` after the re-baseline |
| M1 | apply-site hook removed | 002.5/3, /6, /8 | **KILLED 3/3** | "the CRC Designer never recomputed … stale coverage" |
| M5 | apply hook only inside the success arm | 002.5/6 (/8 also run) | **KILLED** /6; /8 GREEN (expected: no raise in /8) | /6 stale coverage |
| M7 | apply hook gated on applied > 0 (E3 A-2) | 002.5/8, /6 | **KILLED 2/2** | /8 paints `0x08DAAFB7`, the session gives `0x9C5BCBBD` |
| M2 | save-back hook removed | 002.5/4, /7 | **KILLED 2/2** | stale coverage after the save-back and after the blocked save-back |
| M6 | save-back hook under `result.ok` (E3 SEC5-2) | 002.5/7 | **KILLED 1/1** | blocked save-back: paints `0x08DAAFB7`, the session gives `0x9C5BCBBD` |
| M3 | project-save hook removed | 002.5/5, 002.1/6 (both limbs) | **KILLED 3/3** | "no recompute is pending after the Save project commit" |

The CRC oracle is independent of the product: `zlib.crc32` of the session range bytes. `test_oracle_constants_are_the_crc32_of_the_stated_byte_states` pins the literals, and it passed in Run 1. The other mutants of the E4 table (M4, M8–M18) are functional controls and are left to the E5 mutant pass.

## Mitigations ruled at E3 — state in the code

| E3 item | Ruled mitigation | State | Code location | Evidence |
|---|---|---|---|---|
| SEC5-1 (HIGH) — key | A spec's bytes keyed by (name, address, size) | `executed` · `approved` | `screens_directionb.py:7231-7233` (`_spec_bytes`: name → (address, size, bytes)); `load_spec` :7308-7356 | M24, M23 KILLED |
| SEC5-1 — no bytes move | Bytes used only while the current ledger lists the name at the spec entry's range. Three range tests. | `executed` · `approved` | `_collected_items` :7480-7517 (`spec[:2] == (address, size)`); `_prune_spec_bytes` :7439-7448; `_demote_moved_spec_params` :7408-7437 | M24 KILLED. Per R2-N1, single range-test deletions are equivalent end to end and were not counted. |
| SEC5-1 — demotion | A moved, renamed or resized spec parameter becomes an unlabelled memory row at the spec entry's own address, size and bytes; the image is not read | `executed` · `approved` | `_demote_moved_spec_params` :7408-7437, called from `set_a2l_parameters` :7277-7306 (picks captured before the no-op check) | 056/1–3 GREEN; M22 KILLED. The written file holds `0x0` `6C` and nothing at *A*. |
| SEC5-1 — Write and Validate use the declared bytes | A field loaded from a spec is declared with the spec's bytes, without reading the image; the bytes are used only at the length of the field's range | `executed` · `approved` | `app.py:7324-7332` (`_check_items_to_document`); spec-pick items carry `expected` and `symbol` :7511-7517 | M20 KILLED (026/2: Validate reports the drift `expected [6C] actual [93] -> fail`) |
| A-6 | Address rule matches address **and** size; a listed symbol at another range takes no address fallback | `executed` | `_named_parameter` :7371-7406; `by_key` keyed `(address, size)` in `load_spec` | 041.3/3, 041.3/6 GREEN (int-01). M15 and M18 are left to the E5 mutant pass. |
| SEC5-2 (MAJOR) | Save-back hook whatever `result.ok`; placed right after `save_patched` returns | `executed` · `approved` | `app.py:5042-5046`, before `_report_change_result` | 002.5/7 GREEN; M2, M6 KILLED |
| A-2 | Apply hook after the `try`/`except`, keyed on the action and not on `applied > 0` | `executed` · `approved` | `app.py:4909-4914` | 002.5/6 and /8 GREEN; M1, M5, M7 KILLED |
| D-4 (project save) | Hook inside `if request.image is not None:` after `adopt_rederived` | `executed` · `approved` | `app.py:12633-12636` | 002.5/5, 002.1/6 GREEN; M3 KILLED |
| D-4 (helper) | Query the panel inside the `try`; delegate outside it, so a fault in the panel stays loud; no focus move | `executed` | `app.py:17904-17939`; `crc_designer_view.py:704-724` (one statement, `_on_image_changed`) | Read. Nothing computes synchronously; the panel schedules after the quiet time when displayed and marks stale otherwise. |
| SEC5-3 (MAJOR) | §1 (5)–(7) stated; guide §10.6–§10.8 updated, text only; backlog row for a provenance cue | `executed` (records + guide) | `E1-rulings.md` §1 and §6; `docs/user-guide/ch10-check-editor.md` §10.6–§10.8 | The guide text matches the code: no re-baseline on Write; re-baseline by exclude and include; parameters listed first; the `▪` demotion at the spec's address |
| SEC5-4 (MINOR) | Fast exclude-then-include race recorded as a known limitation | `executed` (records) | `E1-rulings.md` E1-D5 | M19 KILLED: the slow toggle path re-baselines. The prune is skipped when nothing is re-included (`set_a2l_parameters` :7299-7301), so a race-left entry can survive a repopulation. It is range-keyed, so it can only come back at its own spec range. Same limitation, no new exposure. |
| SEC5-5 (MINOR) | Backlog row: scrub Cf/Zl/Zp in A2L names | `executed` (records); the gap stays open (pre-existing) | `E1-rulings.md` §6 | Re-checked at head: no string from the spec file reaches a painted surface. `symbol` is only a ledger-key lookup and is returned only when it equals a key (:7399-7402). Names are painted through `safe_text` / `Text.append` (`_fields_lines_text`, `_addendum_preview_text`, `_rebuild_memory_table`). The JSON tab is `json.dumps`, ASCII. Verdict rows are `Static(…, markup=False)`. |
| SEC5-6 (INFO) | Census of in-place writers | re-verified at head | `app.py:4848` (`service.apply`), `:5025` (`save_patched`), `:12630` (`adopt_rederived`) are the only app callers. `_restore_journal` is called only inside `apply`; `adopt_rederived` only by `save_patched` and `_on_project_saved`. | Each call site is followed by the hook. The D-4 sibling probe (A2L explorer value column, Split/Join) stays routed before Inc 10's E1; this review does not close it. |
| R2-1 (MINOR) | Backlog row: run the collision rule on the Check Editor's Write and Validate | `executed` (ruling); `not-executed` in code (by ruling) | `E3-rulings.md` Round 2 | See E5-S3: the row is not in the §6 list the orchestrator copies to the batch backlog |
| R2-N1 | Use the name-only key as SEC5-1's negative control | `executed` | this review, M24 | — |

**Other constraints of the lens:**

- **Saved-file meaning.** Unchanged except as ruled in §1 (5)–(7). Write still emits only `bytes` entries through the existing `write_change_document`, which never overwrites a picked spec (lowest free `_<N>`). A rewritten spec asserts the same (address, bytes) set as the picked one.
- **No new writer and no clipboard.** The added source lines contain no file open or write, no `unlink`, `rename`, `subprocess` or clipboard call (grep of the `+` lines). The new tests use `tmp_path` and the suite's LOCALAPPDATA isolation, and touch no clipboard.

## Findings

| Id | Tag | Severity | Where | What · why | Recommendation |
|---|---|---|---|---|---|
| E5-S1 | design-gap | MEDIUM | `CheckEditorPanel.refresh_check_results` (`screens_directionb.py:8006-8023`) is the only writer of `#check_results` / `#check_status`, and it runs only on Validate and on a refused Write. `load_spec`, `set_a2l_parameters`, the collector toggles, `_note_image_bytes_written` and the `current_file` change never clear the rows. | **What.** Once Validate has run, its verdict rows stay painted under `validation complete` through every later image write, image load, spec pick, A2L load and collector change. **Probe `i5s-stale-verdict` (`executed`).** Case 08 and its A2L loaded, the pilot spec picked, then Validate: `Checks: 3 passed, 0 failed, 0 uncheckable`, row `0x0-0x0 expected [6C] actual [6C] -> pass`. A Patch Editor apply then set `0x0` to `93`, and the operator returned to the Check Editor (key `=`). The card still read `validation complete` with `0x0-0x0 expected [6C] actual [6C] -> pass`. Validate pressed again: `Checks: 2 passed, 1 failed`, `0x0-0x0 expected [6C] actual [93] -> fail`. **Why it is new.** The mechanism is pre-existing. On base, though, every Validate compared the image with itself, so a stale `pass` matched what a fresh run would say. Inc 5 makes `pass` / `fail` carry information (R-CHKED-026), so a stale row is now a false `pass` on screen. That is the CRC Designer defect D-4 fixed, in the Check Editor. **Why MEDIUM, not HIGH.** No file or report carries it: Write and the A2B `## Checks` section recompute. One Validate press corrects it. It needs the operator to trust a card from before the change. Neither the E3 census nor I at E3 covered displayed verdicts; the census covered computed values. | Orchestrator rules between two options. **(a) Fold into Inc 5 (recommended).** The rows go back to their mount state (empty rows, empty status, no new text) whenever what they judged changes: in `load_spec`; on a real repopulation in `set_a2l_parameters`; in the selection-changed and memory-row add/remove handlers; and from the app on every in-place write (`_note_image_bytes_written` also tells the Check Editor) and on a `current_file` change. One row (event-driven form) and one case: this probe's sequence → no `-> pass` row after the apply. Negative control: no clear → the stale `-> pass` row survives → RED. **(b)** If the operator wants a visible "out of date" cue instead of clearing, that is new text: a backlog row with a prototype round first (KF-101 family), and §1 records the limitation now. |
| E5-S2 | impl | INFO | `app.py:5025-5046` | Answers the E4 integration observation. If `save_patched` raised after it adopted the re-derived bytes (`verify_written_image` or an unexpected error in `save_patched_image`), the save-back hook would not run. The exception is not caught in the handler, so Textual ends the app and no stale CRC display survives. Same shape as `_on_project_saved` (CR12a-1, Q-d1). Read only (`not-run`). | None. |
| E5-S3 | design-gap (records) | INFO | `E1-rulings.md` §6 "Backlog rows opened (the orchestrator copies them to the batch backlog)"; `E3-rulings.md` Round 2 | The R2-1 ruling ("→ backlog row") is not in the §6 list. Only the SEC5-3 and SEC5-5 rows are, so the R2-1 row (the Check Editor's Write and Validate run the collision rule; Write refuses through LLR-148.9's path) can be lost when the batch backlog is assembled. | Add the R2-1 row to §6 (or straight to the batch backlog) at the E5 rulings. |

## Items from E4 that touch security

- I-D3 (002.5/8 driven by Remove plus Add): the state the case depends on is the requirement's, and M7 kills /8. Concur.
- The F-01 sentence in guide §10.8 ("a spec with `symbol` entries … is refused") has been stale since Inc 4. It tells the operator less than the product does, not more, and it is routed to the batch-end doc pass (Inc 14 D-8). No security impact.
- 041.3/5 is marked `partial` (I-D5), as the E3 Round 2 NOTE allowed. Concur.

## Evidence checklist

- [x] Each finding has what · where · why · recommendation (table above).
- [x] Each finding has a severity and a tag (`impl` / `design-gap`).
- [x] No secret values: no credentials involved. The host is named only as "LAN Linux host 2", and home paths are redacted.
- [x] Verdict explicit: PASS-WITH-NOTES, HIGH 0. SEC5-1 (the E3 HIGH) is `executed` and `approved` in code, with its negative control M24 KILLED 4/4.
- [x] No new external tool or integration (n/a — local TUI change). No new file writer and no clipboard use.

## Re-review

Scope: only what `E5-rulings.md` ruled for this reviewer's lens, C-10 (E5-S1) and C-2 (code-review F1). Read: `E5-rulings.md`, `E5-corrective-notes.md`, `E5-code-review.md` F1, `git diff 8fc3cd3 22cfd4c -- s19_app tests`, R-CHKED-057 and the Definitions *in-place write* and *validation results* in `01-requirements.md`, cases 057/1 … /3, 056/1 … /3 and 025/3 in `02-test-cases.md`, transcripts `../evidence/inc-5/e5c-01` … `e5c-05`, `e5c-09`. Read-only; nothing ran here (nothing that imports `s19_app` on Windows). The evidence trees (`s19_app` `397a3b2`, `tests` `2dad0b4`, `docs` `172ff6f`, printed in e5c-02 … -04) equal both `22cfd4c` and the head `ab8558b`. The worktree is clean.

### Verdict

**E5-S1: closed** (`executed` · `approved`). **F1: closed** (`executed` · `approved`). HIGH 0, MEDIUM 0. Two INFO notes and one NIT follow; none blocks. This clearance covers the security lens of E5 only. It is not the operator's authorization to merge.

### (a) E5-S1 — R-CHKED-057

| Check | Result | State · evidence |
|---|---|---|
| Every in-place write reaches the clear | The clear lives in `_note_image_bytes_written` (`app.py:17910-17955`). Its three call sites are unchanged: apply at `:4913-4914`, after the `try`/`except` and keyed on the action only, so it covers a raise and 0 applied; save-back at `:5046`, unconditional before `_report_change_result`, so it covers the refused save-back; project save at `:12642`, inside `if request.image is not None:`. The census of writers (SEC5-6) is unchanged. | `executed` (read). Per path: M1, M5, M7, M2, M6, M3 KILLED (first review). The clear in the helper: M29 KILLED 3/3 (e5c-09: stale `validation complete` and `-> pass` on 057/1, /2, /3). |
| Independent of the designer | The two panels are queried separately; a missing designer skips only its own notice. A fault inside either panel stays loud (both delegations sit outside the `try`). | `executed` (read) |
| No tab switch, no focus move | `CheckEditorPanel.clear_check_results` (`screens_directionb.py:8027-8050`) does two statements: it sets `#check_status` to `_STATUS_HINT` and calls `remove_children()` on `#check_results`. It makes no `_show_tab`, `focus` or `refresh_window` call. | `executed` (read) |
| Cleared = R-CHKED-057's state | `_STATUS_HINT` = `Validate compares fields to the image` (`:7168`), the text the label is composed with (`:7775-7781`), and 0 rows, which matches the Definition *validation results*. The tests assert `(status, rows) == (HINT, [])` exactly, plus no `validation complete` and no `-> pass` row. | `approved`: GREEN e5c-02 (68 passed), e5c-03 and e5c-04 (33 passed each, including 057/1); RED on base e5c-01 (057/1, /2, /3 keep `validation complete` and `-> pass`) |
| No stale `pass` can come back | Validate is synchronous in the handler (`app.py:7429-7474`, no worker or timer), so no Validate in flight can repaint after the clear. | `executed` (read) |
| Nothing else cleared | The clear touches neither the picks, nor `_spec_bytes`, nor `_memory_rows`, nor the JSON or addendum previews. 057/1's second Validate reports `2 passed, 1 failed` with `0x0-0x0 expected [6C] actual [93] -> fail`. The 3 fields survive, so the picks survive. `6C` is the spec's byte, since the image now holds `93`, so the spec bytes survive. | `approved` (057/1, e5c-02 … -04) |
| Remainder | The other triggers of E5-S1 (image load, spec pick, A2L load, collector change) are not ruled in. They are recorded as a backlog row in `E1-rulings.md` §6 (line 105). | `executed` (records) |

### (b) F1 — R-CHKED-056 bytes clause

- **The precondition now decides.** `relayout_and_write` (`tests/test_b101_check_spec_keep.py:1199-1214`), shared by 056/1, /2 and /3, and the 025/3 scenario (`:1033-1045`) apply `0x0` = `93` before the spec pick. The expected entry is `facts.image_bytes(...)`, which comes from the generated file and is `6C`, so a demoted row that reads the session image fails. The requirement row and the three cases carry the new precondition. Their expected results are unchanged. `executed`.
- **M25 is a real RED.** e5c-05 shows M25 KILLED 5/5 (056/1, /2, /3, 025/3, AT-I5-3). Each failure is an assertion on the targeted defect: `At index 2 diff: (0, b'\x93') != (0, b'l')` (index 3 for 025/3). None fails at import or by timeout. On the GREEN tree all five pass 3/3 (e5c-02 … -04). `approved`.

### Notes

| Id | Severity | What · recommendation |
|---|---|---|
| RR-1 | INFO | The mutant transcripts (e5c-05, e5c-09) end in `Files … differ`, not in the mutant text. The operation is stated only in `E5-corrective-notes.md` §5. Each RED reason is exactly the signature of its stated operation, so this is accepted. For future batteries, print `diff -u` in the transcript. |
| RR-2 | INFO | No 057 case drives the refused save-back, the raising apply or the 0-applied apply. They are covered transitively: the clear sits in the one helper, whose call on each of those paths M2, M6, M1, M5 and M7 kill. No action needed. |
| RR-3 | NIT (records) | R-CHKED-056's Base column still reads "its written entries match only because the image still holds the spec's bytes". After C-2 the image holds `93`. The base is still RED through the head line. Reword at the canon fold. |

### Evidence checklist (re-review)

- [x] Each finding and note has what, where, why and a recommendation, with a severity.
- [x] No secret values: none are involved, and home paths stay redacted as in the transcripts.
- [x] Verdict explicit: E5-S1 and F1 closed; HIGH 0.
- [x] No new tool or integration (n/a); no new writer and no clipboard use in the corrective diff (its `+` lines grepped).
