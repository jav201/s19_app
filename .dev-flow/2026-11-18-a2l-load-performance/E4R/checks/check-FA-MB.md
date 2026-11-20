# check-FA-MB — merge of b103-fix-round (Front B) into alp-e4r (FA-D1 close 1)

Orchestrator Opus 5.5 (relevo-29). Scripted check (MD-11) on the reference Linux host (rtx), 1-min load 1.09–1.20 before the runs (HT-08).

## Tree
- Merge commit `2f01232b`, parents `0a0c5e7c` (alp-e4r) and `6eccf0cb` (b103-fix-round = PR #214 head). Merge base `f44e8bc4`; 34 commits on each side.
- Conflicts: 4 hunks. Ruling DF-04 a: the alp-e4r side in all four (approved FA-C7 design, a superset of Front B's G2 hunk).
  - `s19_app/tui/app/patch.py` (1): alp's I-ALP-2.3 snapshot arms; every arm threads `a2l_data` as G2 does.
  - `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` (2): the result is byte-equal to alp-e4r.
  - `tests/test_b103_picker_model.py` (1): comment wording only.
- `REQUIREMENTS.md` auto-merged. A row-diff script over base / alp / Front B / merge: 3059 rows = 2851 + 39 (alp) + 169 (Front B); 0 duplicate ids; 0 rows changed by both sides; the 18 E4R rows (R-A2L-REFRESH .033/.034/.037/.040–.042/.049–.053, R-A2L-DEF.162–.168) equal alp-e4r's text.
- Staged CR: 152, all in three `-text` evidence files whose blobs equal b103-fix-round's byte for byte (inherited bytes). The resolved files and the canon: 0 CR.

## Verification (HT-12: touched tests + importers + six laws; HT-14: law 070)
Test set: the picker/patch test files either side touched since the merge base, plus the direct importers of the conflicted modules and the attach suite (11 files): `test_b102_parameter_picker.py`, `test_b102_patch_picker.py`, `test_b103_picker_editor.py`, `test_b103_picker_model.py`, `test_tui_patch_editor_b94.py`, `test_tui_patch_editor_v2.py`, `test_tui_patch_history_strip.py`, `test_tui_patch_json.py`, `test_alp_inc2_a2l_attach.py`, `test_b103_inc8_a2_app.py`, `test_b103_inc9_a9.py`. All 11 exist in the tree; `s19_app` imported from the clone (HT-03).

| Step | Selection | Result |
|---|---|---|
| A | `-n 8 -m "not serial_timing"` | 283 passed, 1 skipped (334 s) |
| B | `-n 0 -m "serial_timing and not slow"` | 11 passed, 287 deselected (136 s) |
| Base re-run | failing nodes on both parents | not needed: 0 failing nodes |
| Six laws | `test_suite_hygiene`, `test_requirements_canon`, `test_id_registry`, `test_address_census`, `test_import_census`, `test_no_private_tokens` (`-n 0`) | 115 passed, 2 skipped, 1 failed: `test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token` |
| Law 070 (HT-14) | `-k 070 tests/test_suite_hygiene.py` | 3 passed; 070_2 offender lines 0 (0 under E4R) |

- The one law failure is one of the inherited base-alp four (FA-0 `laws.txt`; P-280: 070_2, canon obligation word, at_b83_08, no_private_tokens). Front B's fixes turned the other three GREEN on the merge tree. `no_private_tokens` is FA-PRIV's scope (alp delta account-name hits).
- Not run here: the `slow` heavy arms (`slow and serial_timing`, ~41 min on the laptop); they run in the batch-end suite (DF-08), serially on the quiet laptop.
- The skip reason in step A was not captured (`-rfE`); it is visible in the batch-end suite.

## Verdict
MECH-GO. Opus intent: GO — the conflicted behaviour is alp's approved FA-C7 design, Front B's G2 change is contained in it, and the canon keeps every E4R sentence.
