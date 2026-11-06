# Inc 14 — E4 tester notes

Tester: independent of the implementers; tested the approved design only. Edited no source file. Tests ran on the LAN Linux host only (operator rule), never on this PC. Base: origin/main `4648972c` (code identical to `b7b77c4`; the commits above it touch only `.dev-flow/`).

## Files

- New: `tests/test_b101_help_legend_docs.py` (G, 65 collected cases), `tests/support/help_copy_i14.py` (Help copy I14 and Legend copy I14, pinned).
- Re-bodied, names unchanged: `tests/test_window_usage_help.py` (4 tc707 nodes), `tests/test_changes_file_notation_help.py::test_tc1802_nine_md_sections_intact_tenth_section_added`, `tests/test_docs_canon.py::test_at285_every_readme_named_key_exists_in_the_seat` (helpers extended). No test reads `help_sections.md` any more.
- Registry: `EXPECTED_SCANNED_TEST_FILES` grows by 1 at integration (G; the support module is not a test file). No AT-/TC- token in the new files.

## RED on base (`evidence/inc-14/red-01-tester-base.txt`)

72 nodes run: 56 failed, 16 passed.

- RED for a behavioural reason (stale help copy / legend line / missing README, SECURITY, CHANGELOG, guide and findings text): every `*_1_*` copy case, 12/3, 13/1, 13/2, 14/1, all README, SECURITY, RELNOTE, GUIDE cases, 062.10.1/1, LEGEND-011/1 and /2, tc707 copy and numbering (step counts of `checks`, `a2l`, `split_join_export`), AT-285 (README lacks `Ctrl+P`, `=`, `]`), 12/1 (only 6 of 8 expected sections quote keys on base).
- GREEN on base, honestly (the claim already holds in the product, so the test is an acceptance check, not a regression): 12/2 (39 controls), 18/2, 19/2, 19/3, 20/2, 21/2, 22/2, 23/2, 24/2, 062.10.1/2, RELNOTE 1/2 and 2/2 (engine values), and the Inc 8 test for 26/2. Their teeth: each help claim was proved to hold, and 062.10.1/2 was shown RED when Enter is mutated to post `chain=2` (host-only mutation plugin).
- GREEN on base, guards (nothing to fail on base): tc707 census, tc707 boundary, tc1802. Each carries in-test negative controls (a section cut to 2 steps, blank step, empty title, missing or extra key) that I saw report a defect.

## Harness validation (host-only scratch, removed)

- A plugin that patches the six sections, six Flow steps and the two legend constants to the approved copy turned all help and legend nodes of G, and all of `test_window_usage_help.py` and `test_changes_file_notation_help.py` (42 nodes), GREEN.
- Synthetic README, SECURITY, CHANGELOG, guide passages and findings marks written from the requirement text turned all 40 document nodes (including AT-285) GREEN; 16 case mutations (the cases' own negative controls) each turned the named node RED and restoring turned it GREEN.

## Test → case mapping

All as in `02-test-cases.md` (names kept); tests column updated only for: guide ids `[passage-<n>]`, 23/2, 26/2, SECURITY.1/1. Full everywhere except:

| Case | Status | Reason |
|---|---|---|
| R-WHELP.12/2 | full except one control | the ranges "coverage column" has no label; pinned as the row mark + byte count pattern (`✓ 256 B`) |
| R-WHELP.23/2 | full | G test; `test_tc084_1_*` is partial (order derived from `CHECK_GROUP_ORDER`) |
| R-WHELP.26/2 | covered | `tests/test_b101_flow_ext_copy.py::test_r_flow_crc_4_designer_template_is_named_in_the_flow`, GREEN on base |
| R-DOC-SECURITY.1/2 | not testable | `gh api` is E5 evidence; no network in tests |
| R-DOC-RELNOTE.8 | partial | "no text says how the climb could be used" is not expressible as a scan |
| R-DOC-RELNOTE.6 | partial | only the named absent phrase is scanned, not "0 claims" in general |
| R-WHELP.18/2, 19/2 | partial fixtures | uses the reportable synthetic project of `test_tui_report_seam.py` (a change doc is needed to generate), not Project P built from Image F; the P0 arm loads A2L F after the project |
| SECURITY group (N-2) | identifiable | `test_r_doc_security_*` (3 tests, incl. `…_1_3_readme_links_the_policy`, the README link arm); `…readme_4_2…` checks only the CHANGELOG link, so holding the group out leaves it GREEN |

## Ambiguities and record errors (not resolved from the implementation)

1. R-WHELP.19/2 expected `cfg,12582912,12586999` is wrong arithmetic: `0x00C00FFF` = 12587007. The test uses 12587007 (the product already writes it). The case row needs the same fix (expected-result column, not mine to edit).
2. CHANGELOG, SECURITY and guide checks pin the exact substrings quoted in the cases (e.g. "the register starts at `init` exactly as written", copied from `release-note-crc.md`). A paraphrase by the document writers reddens them; that is intended but should be known.
3. R-DOC-SECURITY.2: read as one row for `1.0.x` with fixes, and rows (one or two) covering `0.x` and the release candidates without fixes.
4. AT-285 `_readme_keys` only collects single-key cells, so a paired cell such as `` `q` / `Ctrl+Q` `` is not guarded there (unchanged behaviour). The AT-285 negative control therefore requires `Ctrl+P`, `=`, `]` as single-key cells; the paired cells are guarded by R-DOC-README.3/1. Strengthening the extractor is outside the rulings.
5. N-1 is modelled in `_keys_acting_on`: `/`, `g` only on Workspace, A2L, MAC; `pgdn`, `pgup` only on A2L, MAC, Issues.
