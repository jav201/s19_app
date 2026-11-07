# Increment 012 — Inc 12 · R-DLG.14, R-SHELL-KEYS.3, R-CHKED-058, R-DLG.15 (new) and R-DLG.2 (changed) · Every dialog and action reachable, every Check Editor widget shown, Escape closes the Reports dialog

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-12/`: `01-requirements.md` (US-I12-1 … 3, the rows above), `02-test-cases.md` (22 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md`, `E3-rulings.md`, `E3-security.md`, `E3-ux.md`, `E4-impl-notes-app.md`, `E4-impl-notes-check.md`, `E4-impl-notes-dialogs.md`, `E4-tester-g-t1-notes.md`, `E4-tester-g-t2-notes.md`, `E4-integration-notes.md`, `E5-review.md`, `E5-coverage-audit.md`, `E5-mutants.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc12.md`, the pilot and census under `evidence-e1/` and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-12/`. Branch `b101-inc12` from `main` (base `6f1743c`, product base `e07fb00`), head `3f207a75` plus the uncommitted E5 close records, this packet and `04-validation.md`. Inc 12b (`inc-12b/`) is merged history (the `flow_screens.py` half of F-35, D16-6): none of its records belong to this packet; Inc 12 merges last in the `app.py` chain and owns the DOSSIER F-35 mark and `_FIXED`.

Models per stage (from `steps.log` and the orchestrator's assignment): **Opus** — E1–E3 (requirements, rulings, the three code-free design reviews `architect` / `security-reviewer` / `ux-reviewer`, the E3 correction and the D-5 B split), the E4 integration step, the E5 code + security review, and the coverage audit (as the `qa-reviewer`); **DeepSeek v4 Pro** — the E4 implementers (3 groups: G1 dialogs + docs, G2 app, G3 Check Editor), the E5 mutant battery (M1 … M17), and this record; **Sonnet** — the E4 testers ×2 (G-T1 reach censuses + Reports Escape + passages + existing-test edits; G-T2 Check Editor walk) and the E5 corrective pass.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `012` |
| Lane (if the batch forked) | none — single lane (last in the `app.py` chain, after 10a and 10b; the `flow_screens.py` half is Inc 12b, merged before) |
| Requirement(s) | R-DLG.14, R-SHELL-KEYS.3, R-CHKED-058, R-DLG.15 (new) · R-DLG.2 (changed) (stories US-I12-1 … 3); cited R-DOC-GUIDE.1 (/13, /14) and R-DOC-GUIDE.2 (`_FIXED` 13 → 17) |
| Acceptance | the 22 cases of `02-test-cases.md`; black-box through the shipped controls (the Reports `t` / `escape` / `enter` / `down` / `tab`, the rail keys `1` / `2` / `3` / `5`, the Check Editor `=`) · unit: the censuses and the walk of `E1-slice.md` §6 (codewire graph nodes) |
| Agent | `software-dev` |
| Date | 2026-11-07 |

---

## 1 · What changed

The Reports dialog now answers Escape as Close does: a plain, non-priority `escape` binding on `ReportViewerScreen` and a new `action_close_reports` that logs a fixed string and calls `dismiss(None)`, posting nothing — so no report is written and no typed filter path is applied, from all 12 focus places and on the empty dialog. An open dropdown list keeps its own Escape (closing only the list, choosing nothing), and the help window over the dialog keeps its own. The dead surface is removed with no visible change: `VariantHelpScreen` and `VARIANT_HELP_TEXT` (F-33, no opener); the aliases `action_view_main`, `action_view_alt`, `action_view_mac`, `action_a2l_tag_find_next` and the D3-7 jump trio (`_jump_to_validation_issue`, `_jump_to_validation_issue_object`, `_format_validation_issue_line`) (F-34, no reach); and the hidden Check Editor `Addendum preview` button `#check_preview_toggle_button` with its handler branch (F-35), its function kept on the Addendum tab chip. Two new tests hold the censuses (21 dialogs each with an opener, 80 actions each with a reach, the six clipboard overrides reached through the toolkit) and the Check Editor walk (51 ids each shown in a named state), plus the 12 Reports Escape cases, the 2 dropdown cases and the 3 acceptance cases. The docs mark DOSSIER F-33, F-34, F-35, F-51 `fixed in 1.0.0`, split the ch16 Close row, and rewrite the ch18 close sentence; the requirements ledger records D3-7, D7-10, D9-8 done, D6-12 partly, and Reports done in D7-20.

## 2 · Files modified

Committed: `git diff --stat 6f1743c HEAD -- s19_app tests docs README.md AT-TC-REGISTRY.jsonl` (19 files, +1 392 / −349). Uncommitted: this packet and `04-validation.md`. **SOURCE files: 3 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens.py` | source | US-I12-1 · US-I12-3 | `VARIANT_HELP_TEXT` and `VariantHelpScreen` removed (D-1 A); `ReportViewerScreen.BINDINGS` gains the plain `Binding("escape", "close_reports", "Close", show=False)` (not `priority`, I-1); new `ReportViewerScreen.action_close_reports` logs a fixed string and `dismiss(None)` (posts nothing); the comment above the binding gains the Escape line (I-D1 a) |
| `s19_app/tui/app.py` | source | US-I12-1 | `action_view_main`, `action_view_alt`, `action_view_mac`, `action_a2l_tag_find_next`, `_jump_to_validation_issue`, `_jump_to_validation_issue_object`, `_format_validation_issue_line` removed (D-2 A, D3-7, E3A-R2-1); `_handle_a2l_tag_find_next` and `_update_issues_hex_pane` docstrings/comment only ("Used by" and the no-mounted-screen comment, I-D1 b); no module-level change |
| `s19_app/tui/screens_directionb.py` | source | US-I12-2 | `CheckEditorPanel.compose`: the hidden `Addendum preview` button `#check_preview_toggle_button` and its docstring sentence removed, `#check_actions_row2` keeps `#check_fields_count`; `on_button_pressed`: the toggle branch removed, the tab chips keep `_show_tab`; the compose docstring reworded at the corrective (R-2) |
| `tests/test_b101_reach_and_reports_escape.py` | test | US-I12-1 · US-I12-3 | new file, 18 nodes: the dialog and action censuses (R-DLG.14/1, R-SHELL-KEYS.3/1), the 12 Reports Escape cases (R-DLG.2/1 … /12), the 2 dropdown cases (R-DLG.15/1, /2), AT-I12-1 and AT-I12-2; the QA-1 `#sections_list` focus oracle and the QA-3/QA-4/QA-5 oracles added at the corrective |
| `tests/test_b101_shown_widgets.py` | test | US-I12-2 | new file, 2 nodes: the Check Editor walk (R-CHKED-058/1) and AT-I12-3, with its own walk helper |
| `tests/b97_fixtures.py` | test | US-I12-2 | `CE_IDS_9C7BEAF` 36 → 35 ids (drops `check_preview_toggle_button`), its guard `len == 35` |
| `tests/test_b101_help_legend_docs.py` | test | US-I12-1 · US-I12-2 · US-I12-3 | `_FIXED` 13 → 17 by named supersession (F-33, F-34, F-35, F-51); `_GUIDE_PASSAGES` gains `passage-12` (ch16 Close row) and `passage-13` (ch18 `esc` sentence); `len(_FIXED) == 17` |
| `tests/test_b97_check_editor.py` | test | US-I12-2 | TC-B97-61 drops the toggle's query, `toggle_displayed` and "mounted, not displayed" assertion (`typed` is the shipped set, `len == 16 and typed <= column`); TC-B97-08 36 → 35 |
| `tests/test_id_registry.py` | test | US-I12-1 · US-I12-2 | `EXPECTED_SCANNED_TEST_FILES` 272 → 274 (two new test modules, measured; resolves to 275 on the tree after Inc 10b) |
| `tests/test_tui_app.py` | test | US-I12-1 | `test_jump_to_validation_issue_prefers_address` removed (dead code); `test_validation_issue_filtering_and_format` loses its 3 formatter lines and is renamed `test_validation_issue_filtering` at the corrective (R-6) |
| `tests/test_tui_directionb.py` | test | US-I12-1 | TC-011 docstring and comment reworded (the aliases are gone); the dead `hasattr` arm dropped at the corrective (R-3) |
| `tests/test_tui_goto_marker.py` | test | US-I12-1 | `test_goto_focus_not_cleared_on_tab_switch` switches windows with `action_show_screen("a2l" / "mac" / "workspace")` in place of the removed aliases |
| `tests/test_tui_variants.py` | test | US-I12-1 | `test_variant_help_modal_fits_at_both_sizes` and `_VARIANT_HELP_TOKENS` removed; the two retirement nodes stay; the comment reworded at the corrective (R-6) |
| `tests/test_window_usage_help.py` | test | US-I12-3 | TC-706's pinned `ReportViewerScreen.BINDINGS` list gains `("escape", "close_reports", False)`; the module docstring reworded without the removed class name |
| `docs/user-guide/DOSSIER.md` | doc | US-I12-1 · US-I12-2 · US-I12-3 | §5 rows F-33, F-34, F-35, F-51 gain ` · fixed in 1.0.0`; W05 row 8 and W24 row 10 stay as found (U-5) |
| `docs/user-guide/ch16-reports.md` | doc | US-I12-3 | the features table gives Close its own row (Feature `Close`, How `button / `esc``, Capture 16.1); the existing row keeps `Open reports/, `?`` with How `chips` (R-DOC-GUIDE.1/13) |
| `docs/user-guide/ch18-flow-execution.md` | doc | US-I12-3 | step 5 reads "Close it with **Close** or `esc`." (the finding id leaves the user's text, R-DOC-GUIDE.1/14) |
| `docs/requirements/review/CODE-CHANGES.md` | doc | US-I12-1 · US-I12-2 · US-I12-3 | D3-7, D7-10, D9-8 `done (batch-101 Inc 12)`; D6-12 `partly done`; D7-20 adds Reports to the done list and drops it from the missing list (R-1) |
| `AT-TC-REGISTRY.jsonl` | doc | US-I12-1 | entry `AT-067a` `nodes` drops the two removed variant-help nodes (I-D2) |
| `.dev-flow/2026-11-01-batch-101/inc-12/*.md` | doc | US-I12-1 · US-I12-2 · US-I12-3 | the E1–E5 records, the codewire graph, `04-validation.md` and `steps.log` (uncommitted records listed here) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-12/*.txt` and `inc-12/evidence-e1/` | generated | US-I12-1 · US-I12-2 · US-I12-3 | 46 transcripts (int-00 … int-08, e5c-02 … e5c-15, mut-01 … mut-17, red-01 ×2, and the two E1 pilot/census transcripts) |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** |
| Test files | 11 (2 new, 9 changed; uncapped) |
| Doc files | 4 product/record docs + the `.dev-flow` records (outside the count) |
| Generated | 46 (44 committed transcripts under `evidence/inc-12/` + 2 E1 transcripts under `inc-12/evidence-e1/`) |

- ⚠ **At 3 source files (of the 4 allowed):** `screens.py` owns the Escape binding and `action_close_reports` and the `VariantHelpScreen` removal; `app.py` owns the four alias removals and the D3-7 jump trio; `screens_directionb.py` owns the Check Editor toggle removal. The E5 corrective touched only a `screens_directionb.py` docstring (R-2) and no other source.

## 3 · How to test

```bash
# the two new files and the edited nodes (LAN Linux hosts, Python 3.11)
python -m pytest -q -n 8 -m "not serial_timing" tests/test_b101_reach_and_reports_escape.py \
  tests/test_b101_shown_widgets.py tests/test_b101_help_legend_docs.py tests/test_b97_check_editor.py \
  tests/test_id_registry.py tests/test_tui_app.py tests/test_tui_directionb.py \
  tests/test_tui_goto_marker.py tests/test_tui_variants.py tests/test_window_usage_help.py
# the law guards
python -m pytest -q -n 8 -m "not serial_timing" tests/test_address_census.py tests/test_suite_hygiene.py \
  tests/test_id_registry.py tests/test_engine_unchanged.py tests/test_docs_canon.py \
  tests/test_b101_doc_hygiene.py tests/test_b101_help_legend_docs.py
# the serial-timing lane over the touched files
python -m pytest -q -m serial_timing -p no:xdist tests/test_b101_reach_and_reports_escape.py \
  tests/test_b101_shown_widgets.py
```

All of these ran on LAN Linux host 2 only (operator rule); the Windows PC ran nothing (no Windows-only arm in this increment). The transcripts are `evidence/inc-12/int-00-grep.txt` … `int-08.txt`, `e5c-02-qa1-m14.txt` … `e5c-15-grep.txt`, `mut-01.txt` … `mut-17.txt`, `red-01-g-t1-base.txt`, `red-01-g-t2-base.txt`.

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | `tests/test_b101_reach_and_reports_escape.py` (18) + `tests/test_b101_shown_widgets.py` (2) + the passages and `_FIXED` of `test_b101_help_legend_docs.py` + 9 edited existing modules | **444 passed, 1 xfailed, 0 failed, 0 skipped** (e5c-12, final tree); 22 cases, 22 covered / 0 partial / 0 gap |
| **A · neighbours** | the QC-BC set (43 files) + the 51 other importers + the law guards | **1517 passed, 27 skipped, 1 xfailed, 2 failed** (int-02) · **1603 passed, 131 skipped, 2 failed** (int-03) · **220 passed** (int-04); serial lane **58 passed, 2 skipped** (int-05). The 4 failures are the batch's known ones, failing with the same text on base (int-07-base) |
| **B · black-box** (keys and dialogs) | `t`, `escape`, `enter`, `down`, `tab`, the rail keys `1`/`2`/`3`/`5`, the Check Editor `=` (AT-I12-1 … AT-I12-3) | passed in int-01 / e5c-12; base RED for the censuses, R-DLG.2/1 … /11, R-DLG.15/1 (second Escape), the passages, the `_FIXED` pair and AT-I12-1 |

Details: `inc-12/04-validation.md`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | the shipped nodes run on base `6f1743c` (before the fix) and the E5 mutants applied one at a time in a copy |
| Instrument | project code: the testers' own nodes; the corrective's staged-tree copy; restore checked by the transcript's tree fingerprint and the mutant copy's `diff -u` |
| Where it ran | LAN Linux host 2 (testers, integration, corrective, mutants); the trees are the commits (recomputed with git plumbing) |
| Transcript | `red-01-g-t1-base.txt` (20 failed / 194 passed / 1 xfailed), `red-01-g-t2-base.txt` (1 failed / 1 passed), `mut-01.txt` … `mut-17.txt` (each mutant RED on its target nodes), `e5c-02-qa1-m14.txt` … `e5c-11-qa4-file.txt` (each corrective mutant RED) |
| Restore proven by | each mutant copy restored byte-exact and deleted; `git worktree list` clean after |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (mutants) |
| Arms resolved at baseline | 22 new nodes (18 + 2 + passages + `_FIXED`) + 9 edited modules, every node named in the transcripts' PASSED / FAILED lines or in the case map |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | the declared standing guards (R-DLG.2/12, R-DLG.15/2, AT-I12-2, AT-I12-3) — each named in `E4-tester-g-t1-notes.md` / `E4-tester-g-t2-notes.md` |

| Field | Value |
|---|---|
| **RED counterfactual** | The 20 new + edited nodes were RED on base for behavioural reasons (G-T1: 20 failed — the two censuses on the base's dead entries, R-DLG.2/1 … /11 with the dialog still open, R-DLG.15/1 at its second Escape, AT-I12-1 at its first, passages 12/13, the `_FIXED` pair, TC-706; G-T2: the walk lists `check_preview_toggle_button`). The corrective mutants (M14, M14b, the `down` removal, the status / Generate / stray-file shapes, the late pop) each turned their target nodes RED before the final GREEN (e5c-02 … e5c-11). |

| Field | Value |
|---|---|
| **Mutation verdicts** | 17 mutants on the final tree, one at a time in a copy: **17 KILLED** (M1 … M17), 0 survived. The two censuses also carry their synthetic mutants inside their nodes (asserted exact failure lists and one positive control per reach arm). Transcripts `evidence/inc-12/mut-01.txt` … `mut-17.txt`. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their PASS was believed: the new test files on base (20 + 1 failed, `red-01-*`); the mutant harness (each mutant's target nodes GREEN on the unmutated copy first, then the mutant RED, `mut-01` … `mut-17`); the corrective oracles (M14b, QA-3/QA-4/QA-5 mutants RED, `e5c-02` … `e5c-11`); the coverage audit (first pass found the QA-1 focus-oracle gap and QA-2's seven unrun mutants) — `E5-coverage-audit.md` §7. |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 emitted forms asserted exactly: the Escape binding is plain and non-priority, its action `close_reports` (R-DLG.15/1 keeps the list closing first, and TC-706's exact binding tuple `("escape", "close_reports", False)`); Escape posts nothing — 2 files in `reports/`, 0 folder-spy calls, 0 files and no status line on the empty dialog (R-DLG.2/7, /9, /11, AT-I12-1); the focus returns to the recorded `#sections_list` widget (R-DLG.2/1, AT-I12-1, the QA-1 oracle); the Addendum preview paints text starting `## Checks` (AT-I12-3). The removed names are asserted by the censuses' empty failure lists and the pinned I-3 grep (exactly 3 lines). All passed in `e5c-12` / `e5c-14` / `e5c-15`. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-07. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-12/` and the E1 pilot and census in `inc-12/evidence-e1/`. Each transcript prints the base commit, the staged tree, `s19_app.__file__` and (the corrective/mutants) the exact command line; home paths and account names are redacted.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| e5c-02-qa1-m14.txt | evidence/inc-12/e5c-02-qa1-m14.txt | 5bb2dfdafcbb8bb586601422929b391abacc82afc73ab4d75a49c3599ed63431 |
| e5c-03-qa1-m14-old-tests.txt | evidence/inc-12/e5c-03-qa1-m14-old-tests.txt | e8afe454cfd305d678ff8d88353ef7b0585abdadd5616b46a4f61a1f1b8792b7 |
| e5c-04-qa3-no-down.txt | evidence/inc-12/e5c-04-qa3-no-down.txt | fc8494a66a21c8702b71b4e09145ec09f46cf47b78d6c103baa236918e4e097b |
| e5c-05-qa4-status.txt | evidence/inc-12/e5c-05-qa4-status.txt | 71e006fad78e86f03df4b38f59d3a0398caa214bc6351d858991924b6c9e7100 |
| e5c-06-qa4-generate.txt | evidence/inc-12/e5c-06-qa4-generate.txt | 98ab7e6dc5e2856564e973e998bcd978b544884cb38b6093b6986816b521f7bb |
| e5c-07-qa5-late-pop.txt | evidence/inc-12/e5c-07-qa5-late-pop.txt | e6f0e82011d0368a85b2c9b2d638e7d2746cc2d505ce4550f09ccb6cb57e32be |
| e5c-08-qa5-late-pop-old-test.txt | evidence/inc-12/e5c-08-qa5-late-pop-old-test.txt | 764c83f344b7cc7fad4988608ec7380595cd99aa64f557d1718fcad2e347c626 |
| e5c-09-qa1-m14b-new.txt | evidence/inc-12/e5c-09-qa1-m14b-new.txt | 04f4af8030ff4de703e467eb4f280cfb99566561f2bf11011aa7a7f768e1d3ad |
| e5c-10-qa1-m14b-old-tests.txt | evidence/inc-12/e5c-10-qa1-m14b-old-tests.txt | 50678bb8b861376f0f236b3ec1337c94de1f75f3107d0064635a44364e124502 |
| e5c-11-qa4-file.txt | evidence/inc-12/e5c-11-qa4-file.txt | a7c3161f4ea325ea951e15ca8a6dbd88470c37d56f8bf1636fc266e8d05d9bc8 |
| e5c-12-files.txt | evidence/inc-12/e5c-12-files.txt | e8386ab39efefd524a5a2324ff4869328d6769724c70f46cf94b8ac68fecc905 |
| e5c-13-guards.txt | evidence/inc-12/e5c-13-guards.txt | 3eec309d4121a219d55fc073a9aaee3ab87e5321f5926844cc04d2d6cfe91240 |
| e5c-14-serial.txt | evidence/inc-12/e5c-14-serial.txt | 54f8f73ca0a72c392a2df567bdb4da02907b1681ffb9542bffd300161450a2ba |
| e5c-15-grep.txt | evidence/inc-12/e5c-15-grep.txt | f0570140f34f5aa30de29a3307b2c1b0925c818dd07db1ef41a986e068cb1c0d |
| int-00-grep.txt | evidence/inc-12/int-00-grep.txt | d0cfa690aa21c1b167a98deb22539a8df0d7d9e3541bcf669758da3f64411cda |
| int-00-measure.txt | evidence/inc-12/int-00-measure.txt | 836a662f515bda2b2e2af36f00f8812e29e2af9099859ebb6fa239728ad737fa |
| int-01.txt | evidence/inc-12/int-01.txt | d29065aac83704dd913cef9da226b16598b8c25777f511a6a4c6ba40635602ab |
| int-02.txt | evidence/inc-12/int-02.txt | 182cde9fd06e788e6792d91cbf3e5dfc70d759ca275abeed0ac8b9f734650eeb |
| int-03.txt | evidence/inc-12/int-03.txt | 015b73a6358f16cf7d56aa1bfe1b45cb05a458a8abef9ab16c92cdb9e7cb2c2b |
| int-04.txt | evidence/inc-12/int-04.txt | 4a3b8a0689c6a64da8396fdf4765ad461ca6b58bad57552e3b72a221dd19a2e6 |
| int-05.txt | evidence/inc-12/int-05.txt | 6b2156849652a09232be596a10c1c4cb3ff3962d61f94980a8b2366756276bb1 |
| int-06.txt | evidence/inc-12/int-06.txt | 7dcb3180081ff90c8264a29cc019febf8b3bfd3dfe5c4eef77670f0342b17121 |
| int-06-measure.py.txt | evidence/inc-12/int-06-measure.py.txt | 02b1df50266ea0a0e935b19b775ec49f5535532c3bacd348842dce1287c2d339 |
| int-07-base.txt | evidence/inc-12/int-07-base.txt | 4d8f22c0daed41fef56e0e468cb519415d6e9dabcc73374eee8be8b09c2fb516 |
| int-08.txt | evidence/inc-12/int-08.txt | 2e13a9d3d7efb0902493d741a570bbca72ab00b1f43315b832b247e8c014e407 |
| mut-01.txt | evidence/inc-12/mut-01.txt | ff8fd34bc468b8da9d9c32f7e62ffba365da20a51371e15f02951c0f8fcbc1e9 |
| mut-02.txt | evidence/inc-12/mut-02.txt | 2ed6d49090ba397bfb673677bf4140c9b6acbbb7212cad105be5a5fa9513704f |
| mut-03.txt | evidence/inc-12/mut-03.txt | b708ba2cad34e420e2b4655f3cf9531d7498571aecdde24a03f2c3ed3b5609ba |
| mut-04.txt | evidence/inc-12/mut-04.txt | 829e43646b680f5fadf0e4e39ba2480ddc374a3d5099e4a62399b075ee02707d |
| mut-05.txt | evidence/inc-12/mut-05.txt | 9e46f3a363056553782378738ccb4cb750769eea13d7e775ae4737d734a65f1b |
| mut-06.txt | evidence/inc-12/mut-06.txt | 4a648882fbe3cd41070adf486bce48f15f4eba7f02701d786e233731c7da3bde |
| mut-07.txt | evidence/inc-12/mut-07.txt | 32035b0c6eeed491839a3dfaf41630fd45cded9fc977227c4a511101f86bfc05 |
| mut-08.txt | evidence/inc-12/mut-08.txt | 1d12474c009aeb44bf3e9e37624101c5e2bd4e557970d15a238dcbd69a1f8cce |
| mut-09.txt | evidence/inc-12/mut-09.txt | d9d508a0036f388096a45e784e850066257b57883f9e7cea4470f4d8b4bfbf70 |
| mut-10.txt | evidence/inc-12/mut-10.txt | d97ebe7eaed5ddb45ac2901be300a843f520774e1407c631b1c73637ae79aed2 |
| mut-11.txt | evidence/inc-12/mut-11.txt | e9cc950283ef137ab3f172dacad0c8648937ac82e6b6c2c2c800b12696895259 |
| mut-12.txt | evidence/inc-12/mut-12.txt | 2f5f143ddc595b9b6e7c9a1e0f3dbd1ab58701b8898620ad2e4b17c93b63cfbb |
| mut-13.txt | evidence/inc-12/mut-13.txt | ea028f68e87a7cfdd9cf33c7436f1a30e55e3d11e660b9d8ab872b0f9c436032 |
| mut-14.txt | evidence/inc-12/mut-14.txt | edeacb130c22fc42620ec9b6a95ce3db1755245c403ffbe8f7bb67893230546f |
| mut-15.txt | evidence/inc-12/mut-15.txt | 5f4f90e3e1a2b9502b04b40b87d55f96565126059c2c2d531cbbd360621dd93e |
| mut-16.txt | evidence/inc-12/mut-16.txt | f7770768b1089c7be34af653fd2c169d889a65cb842123313279b616643e27f7 |
| mut-17.txt | evidence/inc-12/mut-17.txt | 3844ce47d081e435357ef1d25efcfd4182250e5b6066a508e2d9b9342866947a |
| red-01-g-t1-base.txt | evidence/inc-12/red-01-g-t1-base.txt | d3c0388270fa15eecf5e3e29a63b02ab3c4a33cfc74d3504841c3e23c6c19c36 |
| red-01-g-t2-base.txt | evidence/inc-12/red-01-g-t2-base.txt | 5d92ba71a3fb392dbb5ecc55dfee4efd9c925587499b70401a4079cfb615bc74 |
| i12e1-census-transcript.txt | inc-12/evidence-e1/i12e1-census-transcript.txt | e4625ebfc1eaccbff01515023de3246d878f84e0bf994ecad802a75f337a351e |
| i12e1-pilot-transcript.txt | inc-12/evidence-e1/i12e1-pilot-transcript.txt | e4e75a8541f5ae3a8792c9ef118263ac55374b142204c2c3b65543d145e7a62a |

| Field | Value |
|---|---|
| **Evidence files** | 46 transcripts at the declared home, each printing the base commit and the staged tree; the two E1 transcripts sit under `inc-12/evidence-e1/`. |
| i12e1-census.py | inc-12/evidence-e1/i12e1-census.py | 24d17bdec39b18240b080d16656ce903ed21f3fc82985a20852dc791d6aaf853 |
| i12e1-pilot.py | inc-12/evidence-e1/i12e1-pilot.py | d34237597c302bf3a386c05cb26491450205b21c9b72c1b4b268088968008087 |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: "no dead dialog, action or hidden Check Editor widget remains" (the census and walk absence) and "Escape cannot write a report or apply a typed filter path" (the security lens) |
| If the result is an ABSENCE, what made the search wide enough | the censuses read `s19_app/**/*.py` with `ast` (dialogs as every `ModalScreen` subclass, actions as every `action_*` method, reached-function fixpoint); the walk keys widgets by identity over the whole `#screen_check_editor` window; the pinned I-3 grep (`git grep -n -w` of the removed names over `s19_app tests`) returns exactly the 3 `window_help.py` docstring lines (BL-I12-1); the engine-frozen guards (`test_engine_unchanged`, `test_tui_directionb`) confirm no frozen module moved |
| Guard labelled as protecting a CONCLUSION, not a behaviour | the censuses' empty failure lists (`dialogs_without_opener == []`, `actions_without_reach == []`) and `never_shown() == []`, each asserted after its population floor (≥ 21, ≥ 80, ≥ 45) |
| Conjunctive criteria: one mutation per conjunct | each reach arm has its own positive control; M2/M3/M5 (each restored alias), M4 (the unbound `action_copy`), M1 (the restored dialog), M6 (the restored toggle), M7 (the binding removed), M9 (priority), M10 (the list applies the highlight) each isolate one conjunct |
| Synthetic instance of the absent case | the censuses' synthetic modules (an orphan dialog, a dialog built only in an unreached function, a dead chain alias, a lone alias, an unbound `action_copy`, an action named only by a widget id and a comparison); the real restores M1 … M5 |
| **Positive control for every probe that returned an ABSENCE** | each real restore turns the census RED with the restored item's name; M7 turns R-DLG.2/1 … /11 and AT-I12-1 RED; M6 turns the walk RED with the toggle's id |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | the QC-BC grep (I-D8) + the 43-file QC-BC run + the 51 importers + the law guards | int-02 1517 passed (27 skipped, 1 xfailed, 2 known failures), int-03 1603 passed (131 skipped, 2 known failures), int-04 220 passed |
| B2 file moved on disk | no file moved; removed code deleted in place; the three docs edited in place | 0 readers of a moved path; the help/docs pins hold in int-04 |
| B3 byte-identical golden captures this source | `grep` over `tests/goldens/**` for the three changed sources | no golden captures `screens.py`, `app.py` or `screens_directionb.py` |
| B4 artifact produced here is consumed elsewhere | the Escape binding (consumed by the Reports dialog and TC-706's census); the removed names (no consumer — the pinned I-3 grep); the docs (consumed by `_GUIDE_PASSAGES` and `_FIXED`) | asserted in the two new files and the help/docs pins |
| A3 interface consumed by another module changed | no function signature changed — removals plus one new method and one binding; the removed aliases' one test caller re-pointed to `action_show_screen` | `tests/test_tui_goto_marker.py` re-pointed; the rail keys `1`/`2`/`3` keep `show_screen(...)` |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict: B1 re-validated every hit by running it; B2 no moved file; B3 no golden hit; B4 the dialog / docs consumers and the no-consumer grep; A3 no signature changed, the one caller re-pointed. |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| records, docstrings and test oracles that no longer matched the strengthened tests or the audit | every R-* / QA-* finding of the E5 review and audit | the review's read of the diff and the audit's row-by-row read (`E5-review.md` R-1 … R-7; `E5-coverage-audit.md` QA-1 … QA-8) | R-1 … R-7 (7) + QA-1, QA-3, QA-4, QA-5, QA-8 (5) applied; QA-2 closed by the mutant table, QA-6 record-only, QA-7 folded into I-5 | all, by the E5 corrective and this close unit | none; re-audit: 22 covered, 0 partial, 0 gap |

| Field | Value |
|---|---|
| **Correction population** | 12 findings applied, enumerated by the review and the audit before the corrective edited its first site: R-1 … R-7 and QA-1, QA-3, QA-4, QA-5, QA-8, plus QA-7's seed-list fold into I-5; QA-2 closed by the mutant table, QA-6 record-only. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `274 = 272 − 0 + 2` (`tests/test_id_registry.py`, measured; two new modules; resolves to 275 on the tree after Inc 10b). Cases `22 = 22 + 0` (the E3 correction 21 → 22; none added or withdrawn at E5). The two removed nodes (`test_variant_help_modal_fits_at_both_sizes`, `test_jump_to_validation_issue_prefers_address`) and the three formatter assertions tested only dead code (D-1 A, D-2 A); no live assertion was weakened (`E5-corrective-notes.md` §1, `E4-integration-notes.md` §5).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` (code + security lens) · **PASS-WITH-NOTES** (0 HIGH; R-1 MEDIUM CODE-CHANGES ledger still open; R-2 … R-7 LOW) — `inc-12/E5-review.md`. The corrective applied every finding and its verdicts are GREEN (e5c-12 … e5c-15). `security-reviewer` · **PASS-WITH-NOTES** (0 HIGH; none of the removed items was a guard, a confirmation, a containment check or the only way to clear state; Escape cannot land between Generate's post and its dismiss) — `inc-12/E5-review.md` checks 9, 10. `qa-reviewer` · coverage audit (22 `full`, 0 `partial`, 0 `gap`; QA-1, QA-2 MINOR closed by the mutant run; QA-3 … QA-8 NIT) — `inc-12/E5-coverage-audit.md`. **Design reviews (E3, code-free):** `architect` **FAIL** (1 MAJOR E3A-01, 7 MINOR) → round 2 **FAIL** (1 MAJOR E3A-R2-1) → PDR closed E3 · `security-reviewer` **PASS-WITH-NOTES** (3 MINOR) → round 2 **PASS-WITH-NOTES** (S2-1, S2-2 LOW) · `ux-reviewer` **PASS-WITH-NOTES** (1 MEDIUM, 3 LOW, 3 INFO) — `inc-12/E3-architect.md`, `inc-12/E3-security.md`, `inc-12/E3-ux.md`, `inc-12/E3-rulings.md`. The independent `testers` (E4, Sonnet ×2) wrote the 20 new nodes from the design records only and ran them RED on base — `inc-12/E4-tester-g-t1-notes.md`, `inc-12/E4-tester-g-t2-notes.md`. |

## 5 · Risks

- **The two censuses become project-wide guards.** Any later increment that adds a dialog or an action before its opener, or an action reachable only by a dead caller, turns the census RED. The reached-function fixpoint counts references (a `call_later(self.action_x)` counts), and the stated limit is that every arm but the toolkit one matches by name, not class — so a dead action that shares a live action's name (only the dialogs' `cancel` on base) can slip through; R-DLG.2's own Escape work has no such shared name.
- **Escape closes Reports with no visible key** (BL-I12-3, BL-I12-5). The Close button shows no key and the Reports help section has no keys block, so nothing in the app tells the operator `esc` works; seven other dialogs still ignore Escape, so R-DLG.2 stays `Partly` in the canon.
- **The empty dialog's focus is undecided** (BL-I12-2). A project with no report opens Reports focused on its `?` chip; no canon row decides where it should land, and this increment leaves it as is.
- **The pre-existing double-dismiss race now has one more trigger on Reports** (BL-I12-6). A Generate press in flight when Escape lands, or a double click on Generate, writes a report and then raises `ScreenStackError`; a toolkit-wide guard (return early when the screen is no longer active) is backlog, not owed by this increment.

## 6 · Pending

- **Merge verification** — per the operator's order (2026-11-06), no full suite runs per increment: this increment ran its slice, the QC-BC set, the other importers, the law guards and the serial lane on LAN Linux host 2; the full suite runs once at batch end, when the batch's increments are all on `main`.
- **Canon ids to forward to the requirements session** — the 4 new rows (R-DLG.14, R-DLG.15, R-SHELL-KEYS.3, R-CHKED-058), the 1 changed row (R-DLG.2, recorded `Partly` after Inc 12), and the context-note changes (CTX-DIALOG *opener* / *dropdown list* / the Reports Esc and focus rows; CTX-KEYS *action* / *reach* / *reached function*; CTX-SHELL *shown widget* / *state of a window*, carried with identical text in Inc 12b) go into `REQUIREMENTS.md` at the batch-end requirements session. CODE-CHANGES: D3-7, D7-10, D9-8 done; D6-12 partly (first half; `_toggle_settings_menu` still open); D7-20 Reports done. Inc 12 marks DOSSIER F-33, F-34, F-35, F-51 and owns `_FIXED` (17).
- **Backlog** — BL-I12-1 … BL-I12-6 carried into the batch backlog, each named in `04-validation.md` §Owed. BL-I12-4 is moot (D-2 A taken). BL-I12-6 (dismissing handlers returning early when the screen is no longer active) is flagged for the review page with D7-20's remaining dialogs.
- **Uncommitted records** — this packet and `04-validation.md` are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 12; run the full suite once at batch end; forward the 4 new / 1 changed canon ids and the CODE-CHANGES marks to the requirements session; carry BL-I12-1 … BL-I12-6 into the backlog; open the next increment on the batch plan.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 / 4 — `screens.py`, `app.py`, `screens_directionb.py`; reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b101_reach_and_reports_escape.py` (18), `tests/test_b101_shown_widgets.py` (2) + the passages / `_FIXED` of `test_b101_help_legend_docs.py` + 9 edited files |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the slice units traced node-for-node in `codewire/graph-inc12.md`; e5c-12 444 passed |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 — base RED 20 + 1 failed, mutants 17/17 killed, corrective mutants RED |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 — B1·B2·B3·B4·A3, each with command and verdict |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES, 0 HIGH |
| 7 | No file from another lane touched | all | ✓ | single lane (Inc 12b is the `flow_screens.py` half, merged before) |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | the 3 slice files are outside the frozen engine set; `test_engine_unchanged` / `test_tui_directionb` pass (int-04 / e5c-13) |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | 22 covered, 0 partial, 0 gap — `E5-coverage-audit.md` |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 — the census absence, the pinned I-3 grep, the real restores M1 … M5 |
| 11 | **Mutation verdicts** declared | all | ✓ | §4 — 17/17 killed |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 — 4 instruments |
| 13 | **Correction population** declared | all | ✓ | §4 — 12 findings, enumerated before editing |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 — 4 emitted forms |
| 15 | **Independent review** names somebody | all | ✓ | §4b — code-reviewer, security-reviewer, qa-reviewer, architect, security-reviewer, ux-reviewer, testers ×2 |
| 16 | **Evidence files** declared | all | ✓ | §4 — 46 transcripts at the declared home |
