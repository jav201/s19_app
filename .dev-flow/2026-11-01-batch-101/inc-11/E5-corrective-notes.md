# Inc 11 — E5 corrective notes

Batch 2026-11-01-batch-101, increment 11, stage E5 corrective pass (`dev-flow-v3-beta`). Agent model: opus. Input: `E5-rulings.md` (C-1 … C-8 and the Routed list), with `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-mutants.md`. Every test and mutant ran on the LAN Linux host 2 (Python 3.11.18, Textual 8.2.8, pytest-xdist, pytest-textual-snapshot 1.1.0) in an own detached worktree `<HOME>/work/s19_c11` at `origin/main` `f9f3cb09` with `git diff b7b77c4` of branch `b101-inc11` (`s19_app`, `tests`, `docs`) applied uncommitted; nothing ran on the Windows PC. Each transcript prints `s19_app.__file__` (`<HOME>/work/s19_c11/s19_app/__init__.py`) and the tree fingerprint (sha256 of `git diff`) at start and end.

## Verdict

All eight rulings are done. **No product code changed**: no strengthened test exposed a deviation from the design. The final runs show only the known failures: the OR-3 freeze guards (by design until the merge) and six snapshot nodes. Two of those snapshot nodes also fail on base; the other four are the owed re-record of the D-8 value changes. Coverage after the pass: **78 cases, covered 76, partial 2, gap 0**.

## Ruling → change

| Ruling | Change | Files | State |
|---|---|---|---|
| C-1 (F1, A-8) | Screen table row 5 now says that each issue is shown under its own severity and that Inc 11 removed the batch-94 view triage. The US-004 seam paragraph has a "Superseded by batch-101 Inc 11" note: the view re-labelling is gone and the recognition lives in `validate_a2l_structure` (R-VAL-032.1 … .3). R12 is closed (the seam moved to the parser). Text only | `docs/architecture.md:39, :398, :416` | done |
| C-2 (F2: N-1, N-3, N-4, N-2; E5-3) | R-A2L-036.2's trigger and R-A2L-036.4 now include the 2^32 bound (N-1). R-A2L-036.5's withdrawal text says "anchored rule … kept or dropped together" (N-4). R-A2L-036.6 says "Number" (N-4). D-5 records the accepted residuals N-2, N-3 and E5-3 | `01-requirements.md` (4 rows), `E1-rulings.md` D-5 | done |
| C-3 (F3) | The acceptance docstring now names the file's own `wait_until`, built on `timing.POLL_S`, which rides out `WaitForScreenTimeout` | `tests/test_b101_inc11_acceptance.py:14` | done |
| C-3 (F4) | New pin `test_r_a2l_036_4_non_ascii_digit_word_is_skipped_by_the_anchor`: `S11b "" DATA FLASH INTERN ٣ 0x10 0x20` gives base 0x10, size 0x20 (the reader anchors on `0x10`; the N-2 residual) | G1 | done |
| C-3 (F5) | `DEMO_A2L_SECTIONS` now uses unquoted names (`AscetCode ""` …), as `memorysegment.a2l` does. **Not applied** to `test_tc710_split_from_each_source_naming`'s `'PrgCode'`: that test asserts `prg__PrgCode_`, which pins the sanitiser's apostrophe mapping (HLR-160). Unquoting it would change a pinned expected value and drop that check. F5 was optional | `tests/test_segment_split_window.py:127-139` | done (partial, reason given) |
| C-4 (R-TUI-042b.4/1) | The test now asserts the painted colour: each row and its code chip have `styles.color` `#F6FF8F` (after a composed-row wait, SR-2). The detail span is painted in the foreground colour `#FFFFFF`, as on base (the row and chip carry the class, the detail does not). So the assertion covers the row and the chip | G2 `test_r_tui_042b_4_…` | done → covered |
| C-4 (AT-I11-4, R-SEG-SRC.6/1) | Each painted row line is parsed to (name, base): `[(boot, 0x00000000), (app, 0x00040000), (cal, 0x00800000), (config, 0x00C00000)]` in paint order. The old substring checks stay. Sizes are not painted at 120×36: the table is in its narrow tier, which drops the size column | G3 | done → covered |
| C-5 | Case corrections in `02-test-cases.md`: AT-I11-1's key is `p`; AT-I11-4's route is `ctrl+k`/`join`/Enter, then `t`, Tab, `t`; AT-I11-5's route is by keys; the missing clauses of R-A2L-036.7/1, R-TUI-042b.5/2 and R-SEG-SRC.6/2 are added. The 11 non-id Tests entries are now node ids. R-A2L-120/1 cites `test_r_a2l_122_rows_carry_no_note`. R-VAL-032.3/3 drops TC-B94-18. The vocabulary is `covered`/`partial` and `verified (linux py3.11, e5c-0n)`. The E1/E4 preamble and the Count paragraph are replaced | `02-test-cases.md` | done |
| C-6 | Each of the 21 base-passing cases now names its killing mutant in the Result column. 13 cases are killed by existing `E5-mutants.md` transcripts. For the other 8, mutants were run on LAN host 2 (table below): 7 KILLED. R-A2L-036.4/10 could only be killed after adding `S10b` (`0x000001000`, 9 hex digits with a small value), because `S10`'s value is above 2^32 and the bound masks the 8-digit limit. One mutant was SURVIVED as equivalent (see the table) | G1 (`S10b` ids), `02-test-cases.md`, `evidence/inc-11/e5c-mut-*.txt` | done |
| C-7 | Clauses with no case: R-A2L-036.7's "Split / Join lists no row" now has G2 `test_r_a2l_036_7_split_join_lists_no_row_for_empty_segment` (chip `a2l(1)`, one painted row `Good`). That test injects the A2L, so the case stays **partial** (TCP-MAP-7). R-TUI-042b.4's colour is covered by C-4. R-TUI-042b.5's error-filter clause is now stated in case /2. Owed ATs: (1) new **AT-I11-7** `test_at_i11_7_split_join_lists_software_a_segments`: `prg.s19` + `software_a.a2l` loaded through the Load dialog, Split / Join from the palette, keys to the a2l tab, `a2l(3)` and three painted (clamped name, base) rows; (2) AT-I11-5 now reaches the CURVE row with Tab then Down/Up, not `move_cursor` (Down alone failed at first because the focus was on a hidden Workspace button, `e5c-00a`); (3) AT-I11-4's pairing (C-4) | G2, G3, `02-test-cases.md` | done |
| C-8 (E5-4 in `E5-security.md`; the ruling calls it E5-6) | The C-17 hostile arm's name is now `EVIL[red]\x1b[31m[/b]\x07`. It also asserts that `[/b]` stays literal and that no C0 byte or DEL is in `rendered.plain`. The existing `[red]` and `spans == []` assertions are kept | `tests/test_tui_issues_triage_b94.py` (`test_tc_b94_19_panel_reclassification_matrix`) | done |
| Routed | Six bullets appended to `.dev-flow/BACKLOG-CODE.md` after the batch-101 Inc 3 block (grep first: no existing row for any of them). E5-1 is the fill-export size cap; E5-2 is the record-word cost; E5-5 + O-6 are one modal title/body scrub item (same fix; the rulings list it as "E5-4"); E5-6 is OK/NEUTRAL issues rendered in no group (the rulings list it as "E5-5"); O-4 is the iterative parser; O-5 is the `/end` name check | `.dev-flow/BACKLOG-CODE.md` | done |

**Id note.** The ids in the rulings for the security items are shifted by one against `E5-security.md`: C-8's "E5-6 hostile-name test" is E5-4 there, and the Routed "E5-4, E5-5" are E5-5 and E5-6 there. Each change above follows the description in the ruling and cites the `E5-security.md` id.

## Mutants run in this pass (C-6, C-4)

Method: `/tmp/c11e5_mutate.py` on the host copies the file, applies one exact string edit (count must be 1), runs the cited nodes, restores the copy, and checks the sha256. Each transcript prints the baseline hash, the mutated hash, the failing nodes and the restored hash with `ok=True`. The tree fingerprint was `3095a2c7fd8b4a6b` before and after every mutant.

| Mutant | Edit | Case(s) | Nodes RED | Result | Transcript |
|---|---|---|---|---|---|
| `m-036-2-comment` | `/* */` not skipped in the record words | R-A2L-036.2/4 | `test_r_a2l_036_comment_words_are_skipped` (16, 32, None) ≠ (4096, 512, −1) | KILLED | `e5c-mut-036-2-comment.txt` |
| `m-036-4-default0` | no address word → base 0, size 0 | R-A2L-036.4/2 | all 24 `no_base` ids incl. `[none-*]` | KILLED | `e5c-mut-036-4-default0.txt` |
| `m-036-4-quoted` | a quoted word may anchor / be the size | R-A2L-036.4/8 | `[quoted_words-*]` (base 1) | KILLED | `e5c-mut-036-4-quoted.txt` |
| `m-036-4-int0` | Number read with `int(w, 0)` | R-A2L-036.4/9 (and /10 via S10b) | `[underscore-*]`, `[nine_hex_digits_small-*]` (base 4096) | KILLED | `e5c-mut-036-4-int0.txt` |
| `m-036-4-hex8` | 8-hex-digit limit dropped | R-A2L-036.4/10 | `[nine_hex_digits_small-*]` only; `[nine_hex_digits-*]` passes (the bound rejects `0x123456789 + 0x10`) | KILLED (by S10b) | `e5c-mut-036-4-hex8.txt` |
| `m-121-nopoints` | index note emitted outside `if points:` | R-A2L-121/2 | `test_r_a2l_121_no_line_without_points`, `test_r_a2l_121_index_note_once_above_header` | KILLED | `e5c-mut-121-nopoints.txt` |
| `m-042b-1-rev` | groups painted in reversed `SEVERITY_ORDER` | R-TUI-042b.1/1 | `test_r_tui_042b_1_groups_ordered_whatever_the_list_order` | KILLED | `e5c-mut-042b-1-rev.txt` |
| `m-042b-1-enc` | groups painted in list-encounter order | R-TUI-042b.1/1 | none | SURVIVED (equivalent: `_filtered_validation_issues` sorts by rank before the panel sees the list, R-TUI-042b.5) | `e5c-mut-042b-1-enc.txt` |
| `m-042b-4-colour` | `.sev-warning` colour → `#d9a35b` (class kept) | R-TUI-042b.4/1 | `test_r_tui_042b_4_…` `#D9A35B` ≠ `#F6FF8F` | KILLED (the old class-only assertion would pass) | `e5c-mut-042b-4-colour.txt` |

Not run: no mutant targets AT-I11-4's pairing check (a name-base mismatch would need an edit in `segment_split_view.py`, outside the slice). Its discrimination is shown by construction: the old substring checks pass for any assignment of names to rows, and the new check compares exact (name, base) pairs per line.

## Final runs (LAN Linux host 2)

| Transcript | Set | Result |
|---|---|---|
| `e5c-01-new-repinned-guards.txt` | the 3 new files, `test_tui_issues_triage_b94.py`, `test_synth_release_case.py`, `test_segment_split_window.py`, `test_engine_unchanged.py`, `test_id_registry.py`, `test_suite_hygiene.py`, `test_requirements_canon.py`; `-n 8 -m "not serial_timing"` | **2 failed, 331 passed**: TC-027 and TC-B94-18's freeze arm (OR-3, by design). 331 = E4's 326 + 5 new nodes (`S10b` ×2, `S11b` pin, R-A2L-036.7 Split / Join, AT-I11-7) |
| `e5c-02-serial-lane.txt` | `-m serial_timing` over the same set | **1 passed**, 333 deselected |
| `e5c-03-importers-app-directionb-snapshot.txt` | the 28 importer files of E4 int-08 + `test_tui_app.py`, `test_tui_directionb.py`, `test_tui_snapshot.py`; `-n 8 -m "not serial_timing"` | **8 failed, 758 passed**, 17 skipped, 3 xfailed: TC-031 ×2 (OR-3) and 6 `test_tc016s_density_layout_snapshot` nodes (below). `tc_b100_52[case_06]` passed (E4 item 3) |
| `e5c-04-snapshot-branch.txt` / `e5c-05-snapshot-base.txt` | `test_tui_snapshot.py`, default basetemp, branch / pristine `f9f3cb09` (own worktree reset, then re-synced) | branch 6 failed, 27 passed; base **2 failed** (`patch-comfortable-80x24`, `-120x30`), 31 passed |
| `e5c-06-snapshot-text-diffs.txt` | SVG text diff, baseline vs actual | `a2l-*`: Region `unknown` → `flash` (D-8 / A-3, owed re-record); `map-*`: status `60 iss` → `59 iss` (one fewer `A2L_UNRECOGNIZED_BLOCK` in the snapshot fixture, D-8 Issues counts); `patch-*`: a new `A2L` tab on the Patch Editor, pre-existing on base |

Fingerprint of the tree in all final runs: `d6cb4d5789b7571b` at start and at end. Superseded development runs: `e5c-00a` (2 failed: the colour test queried the chip before compose; AT-I11-5's Down keys had no table focus) and `e5c-00b` (the detail span is `#FFFFFF` by design, so the assertion was narrowed to the row and the chip). Both causes were in the test, not in the product.

Snapshot plugin: E4 recorded `pytest-textual-snapshot` as absent on the host. It is now installed (1.1.0, syrupy 4.8.0), so `test_tui_snapshot.py` runs instead of skipping.

## Case count and coverage totals

- **78 cases**: 71 requirement cases over 28 active rows (4 [OR-2]) and 7 acceptance cases (AT-I11-7 is new).
- Coverage: **covered 76 · partial 2 · gap 0 · conflict 0** (E5 audit: covered 71 · partial 6). Partial: R-A2L-036.7/1 (Split / Join clause through injected state) and R-SEG-SRC.6/2 (G2 reads names and sizes white-box; the black-box AT-I11-7 paints clamped names and no size).
- Negative controls: 22 cases name their killing mutant (the 21 of the audit plus R-TUI-042b.4/1).
- Code coverage (line or branch) was not measured: `not-run`.

## What I could not do / left open

- **OR-3 freeze guards** (TC-027, TC-B94-18's freeze arm, TC-031 ×2) are RED by design. Recorded, not fixed; they go GREEN only on the merged tree.
- **Snapshot baselines**: the 2 `a2l-*` and 2 `map-*` nodes need the owed re-record of the D-8 value changes (E3 A-3, E4 item 2), and the before/after belongs on the batch-end review page. Not done: no C-ruling covers it. The 2 `patch-*` nodes fail on base too and are not Inc 11's.
- **F5 for `tc710`** kept `'PrgCode'` (reason in the table above).
- **R-A2L-036.7/1** and **R-SEG-SRC.6/2** stay partial. A black-box route for the empty-segment clause would need one more Load-dialog AT. I judged that out of scope for C-7, which asks to add each clause.
- The **R-VAL-032.2/3 corpus oracle** still walks the parser's tree (audit §3 recommendation). No ruling covers it; it is noted in the O-5 backlog bullet.
- **Remote clean-up not done:** after the last run the LAN host 2 stopped answering on port 22 (ssh connection timed out repeatedly over about 20 minutes). Still on the host: the worktree `<HOME>/work/s19_c11` (detached `f9f3cb09` + the uncommitted branch diff), the helpers `/tmp/c11e5_mutate.py`, `/tmp/c11e5_svgdiff.py`, `/tmp/c11e5_bak` and the basetemp `/tmp/pytest-s19c11`. To remove them: `git -C ~/work/s19_app worktree remove --force ~/work/s19_c11 && git -C ~/work/s19_app worktree prune` and `rm -rf /tmp/c11e5_* /tmp/pytest-s19c11`. Local helpers (`c11e5_*`) stay in the session scratchpad, outside the repository.

## Evidence checklist

- [x] Tests run with real output: `e5c-01`, `e5c-02`, `e5c-03` (executed); the failures are named and classified.
- [x] No secrets in code or output; transcripts redacted (`<HOME>`, `<USER>`, `<IP>`, "LAN Linux host 2"); grep for account, host and IP strings found none.
- [x] No destructive command outside the own remote worktree. `git reset --hard` and `git clean` ran only in `<HOME>/work/s19_c11` for the re-syncs and the base snapshot run. `<HOME>/work/s19_app` and `<HOME>/work/s19_m13` were not touched.
- [x] Source cap: 0 product source files changed. Changed: 5 test files, 1 doc and records.
- [x] Records: this file, `02-test-cases.md` (Result filled), `01-requirements.md`, `E1-rulings.md`, `.dev-flow/BACKLOG-CODE.md`, `steps.log`.
