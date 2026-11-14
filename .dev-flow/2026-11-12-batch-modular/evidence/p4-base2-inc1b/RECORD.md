# P4 base2: Inc 1b final carried into the modular base

Branch `b103-base2` (local only, no push), worktree `s19_app-b103-base2`.
Base `a95d0ea9` (batch-modular `2dbd7d5a` + the patch_editor split). Merged branch
`b103-inc1b-push`: first at `99075449` (merge `d8555d03`), then its records-only close
commit `aba3b947` (merge `c3760226`). Brief: R11 (P-011 local half).

## State / next step

- DONE (R11 complete): merge, port, retarget, merge-prediction check, AST identity check,
  check (a), negative controls NC-1/NC-2, check (b), D-R11-1/2, full suite (c) with every
  difference explained, PP-02 scan, rtx scratch deleted.
- NEXT (orchestrator): D-R11-2 (HOME basename rule), D-R11-3 (intermittent cap arm, pre-existing);
  pushing `b103-base2` / rebuilding `batch-modular` needs the operator's OK (P-011, P-012).
- For Inc 7 E4: base = `b103-base2` tip. App code lives in `s19_app/tui/app/<mixin>.py`, not
  `app.py`; source-reading tests use `tests/support/package_source.py` (H-12), seam patches go on
  `app_module.deps`, and every retarget carries a negative control.

## Why the merge is small

`a95d0ea9` already carries Inc 1b up to `541a3d50`: main's `645253ba` is the squash of the
Inc 1b integration branch, and its patch over `0c3a6bd4` equals `541a3d50`'s patch over
`dc44b364` line for line (`git diff` of the two patches, `index` lines dropped: 0 lines).
`541a3d50` and `645253ba` differ only by main's three redaction commits (44 paths,
none touched by Inc 1b afterwards). So the effective merge base is `541a3d50`, not the
graph base `dc44b364`.

Resolution rule for every conflict: `git merge-file ours=a95d0ea9 base=541a3d50
theirs=<inc1b tip>`. Main's redacted text and batch-modular's retargets therefore win
wherever Inc 1b did not change the text after `541a3d50` (P-012).

`merge-prediction.txt`: of 320 paths changed on either side since `541a3d50`,
316 equal that prediction (270 ours only, 45 theirs only, 1 both with a clean
three-way). The four deliberate differences:

| Path | Why |
|---|---|
| `s19_app/tui/app.py` | stays deleted (modify/delete); its late hunk is ported (below) |
| `s19_app/tui/app/a2l_view.py` | receives the P-002 guard (R-COPY.26) |
| `tests/test_b103_clipboard_tail.py` | one seam retarget (below) |
| `tests/test_id_registry.py` | count conflict: 311 (modular) + 1 (`test_b103_a2l_filter_teardown.py`) = 312 |

Conflicts git reported (15 plus app.py): `inc-1b/01-requirements.md`, `02-test-cases.md`,
`steps.log`, `evidence-e4/{matrix,tail}/SHA256SUMS`, `tests/support/b103_{artifact_safety,clipboard,winci_gate}.py`,
`b103_winci_manifest.json`, `test_b103_{clipboard_tail,copy_paste_matrix,copy_quit_dialog,copy_views,winci_gate}.py`,
`test_id_registry.py`. All but `test_id_registry.py` resolved cleanly with the rule above.

Tracked `.pyc` (PF-03): 0 at `a95d0ea9`, 0 after both merges; the merge brought none in
(base `dc44b364` and the Inc 1b side agree on the 8 files main deleted), so no `git rm --cached` was needed.

## Hunk -> module table

`hunk-to-module.tsv`: the 18 hunks of `git diff dc44b364 <inc1b tip> -- s19_app/tui/app.py`
(23 rows: a hunk spanning several members gets one row each). 21 rows were already in
`a95d0ea9`; 2 rows (one hunk pair: docstring + guard of `_schedule_a2l_filter_refresh`) are
ported here into `s19_app/tui/app/a2l_view.py`. No new method, no new import.

`ast-identity.txt` (AST only, nothing imported): the set of members whose AST changed
Inc 1b `541a3d50` -> tip `app.py` is `{_schedule_a2l_filter_refresh}`, and the set changed
`a95d0ea9` -> merged package is the same; 434 tip members, none missing in the package;
the 15 members whose AST differs between `app.py` and the package differ identically on
both pairings (function-local relative imports one level deeper, from batch-modular).

## Test retargets (H-12 / deps seam)

No Inc 1b test reads `app.py` source, AST or path (`git grep` count of `tui/app.py` in
tests/.github/tools/s19_app equal before and after). One late Inc 1b test edit patched the
package root:

- `tests/test_b103_clipboard_tail.py::_r13_diag_install` (R-PASTE.13/101 diagnostic,
  WinCI-only test): `for module in (clipboard_module, app_module, capped_module)` ->
  `app_module.deps`. Same test names and ids. Without it the diagnostic's `tail_mark`
  lands on the root re-export, which no product code reads (CLAUDE.md deps seam), and the
  WinCI diagnostic loses its `tail_start`/`tail_end` events. Negative control: see below.

## Checks (rtx, Linux)

Environment for every targeted run: scratch `~/work/zq-base2/`, clones from a bundle
of named branches, the isolated env of the runner rules (empty env, HOME under the
scratch, XDG/TMPDIR isolated, `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`,
`< /dev/null`), `s19_app.__file__` printed first, `timeout` per run (`tools/run_t.sh`).
Captured outputs in `runs/` are redacted: home path -> `~`, pytest temp folder ->
`pytest-of-<user>`, the isolated HOME basename -> `<iso-home>` (see D-R11-2), CR removed.
The tool copies in `tools/` carry the same `<iso-home>` redaction.

### (a) Inc 1b's Linux suite: PASS, identical to the Inc 1b tip

Files: `test_b103_copy_views.py`, `test_b103_clipboard_tail.py`,
`test_b103_copy_quit_dialog.py`, `test_b103_copy_paste_matrix.py`,
`test_b103_a2l_filter_teardown.py`; serial, both trees at once (load 3 -> 8).

| Tree | Result | QC-TM |
|---|---|---|
| merged `c3760226` | 124 passed, 23 skipped (24 min) | 6 bounds, 0 under 20 % margin |
| Inc 1b tip `99075449` | 124 passed, 23 skipped (24 min) | 6 bounds, 0 under 20 % margin |

`runs/a-tip-vs-merged.txt`: 147 nodes each, **0 differing**. Against `e8f8e3d1`
(122 passed, 19 skipped, 141 nodes): +1 passed R-COPY.26/1 (the teardown test), +1
passed and +4 skipped from tail tests added after `e8f8e3d1` (R-PASTE.14 C1 `[key|right|row]`
and C2 skip on Linux, WinCI-only). The 23 skips: 14 P2 matrix cells (terminal paste, not on
Linux), 8 WinCI-only tail nodes (R-PASTE.13/101, R-PASTE.14/101-103, C1 x3, C2) and
AT-I1b-8 (manual).

### Negative controls (scratch clones, never the worktree)

| Id | Mutation | Expected | Result |
|---|---|---|---|
| NC-1 | remove the two ported guard lines from `app/a2l_view.py` | R-COPY.26/1 RED | RED: `NoMatches: No nodes match '#a2l_tags_list'` (the P-002 signature), `runs/nc-guard.txt` |
| NC-2 green | probe `tools/test_zq_nc_diag_seam.py` on the merged tree | GREEN | 1 passed, `runs/nc-diag-green.txt` |
| NC-2 red | same probe, tuple back to `app_module` | RED | `assert '_mirror_and_..._os_clipboard' == 'tail_mark'`, `runs/nc-diag-red.txt` |

### (b) Laws: merged vs base `a95d0ea9`

`test_no_private_tokens`, `test_package_source_helper`, `test_suite_hygiene`,
`test_requirements_canon`, `test_import_census`, `test_deps_seam_law`,
`test_engine_unchanged`, `test_id_registry` (`-n 4`), and `test_tui_directionb.py -k tc031`.

| Tree | Result |
|---|---|
| merged `c3760226` | 2 failed, 109 passed; tc031 3 passed |
| base `a95d0ea9` | 1 failed, 110 passed; tc031 3 passed |

- `test_requirements_canon::test_canon_rows_hold_the_obligation_word_once`: identical on
  both (R-A2L-DEF.153, R-PICKER-CORRECT.004/.008, PENDING P-031). Pre-existing.
- `test_no_private_tokens`: GREEN on merged (P-012 condition met).
- `test_suite_hygiene::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`:
  RED on merged only. `runs/l070-*.txt` and the same node on the Inc 1b tip show both causes
  are inherited from the Inc 1b lineage (the tip fails them too, plus its unredacted
  inc-12/inc-2 records that main's versions replace on this branch):
  1. `inc-1b/E5-winci-43438310100-diagnosis.md`: the example path `C:/Users/` + the word "person" (in a
     negative-control description) matches "user-profile path" with any HOME. Fixed
     forward, D-R11-1.
  2. Three Inc 1b records name the isolated HOME basename itself; the law adopts
     `Path.home().name` as a local identity, so they are RED only under that basename
     (GREEN with an unused one: `runs/l070-merged-qhome7.txt` lists cause 1 only). Not
     edited, D-R11-2.

### Decisions

- **D-R11-1 (fix forward, PP-06).** `inc-1b/E5-winci-43438310100-diagnosis.md` line 37:
  the word after `C:/Users/` becomes `<person>` (the records' placeholder spelling). One
  word, own commit, meaning unchanged (it describes a control that uses a person-account
  path). Not covered by any SHA256SUMS manifest.
- **D-R11-2 (not edited; for the orchestrator).** `inc-1b/E5-rereview-final.md`,
  `inc-1b/evidence-e5-r2/p001-linux.txt` and `p002-linux.txt` (the last two are captured
  evidence) name the isolated HOME basename the runner rules prescribe. That name is not
  an account, so the records are not redacted; but while they exist, law 070_2 is RED
  under that exact basename on every branch that carries Inc 1b's records. The rule's
  basename has to change to one no record names (or those records redacted forward);
  rule change left to the orchestrator. This record and its runs avoid writing the name.
- **D-R11-3 (pre-existing intermittent, not this merge; for the batch close).**
  `test_b100_project_check.py::test_r_tst_111_112_arm_values_equal_the_product_stamps[cap]`
  fails intermittently with `AssertionError: []` (the arm recorded no label), timings well
  inside the bound. Measured alone, interleaved, load ~3: base `a95d0ea9` 2/10, merged
  `66544e8e` 1/10 (`full-suite/rep.tsv`), plus 1/1 after in `rerun.tsv`. Same on both
  trees, so not caused by the merge; not called flaky (HT-07), recorded as an intermittent
  test defect with its measured rate.

### (c) Full suite vs the a95d0ea9 baseline: COMPARE FAIL, every difference explained

`tools/modularize/run_suite.sh` (the committed copy, byte-identical to the one used for the
baseline), `-n 8`, bundle of `b103-base2` only (as the baseline: no local `main`, so the
engine guard skips on both), tree `66544e8e`, shared host (load ~10-13 during the run).
Baseline = the P-904 run of the split tree (`a95d0ea9` differs from it only in records;
outputs kept on the runner).

| | failed | passed | skipped (+xfailed) | nodes | rc |
|---|---|---|---|---|---|
| before `a95d0ea9` | 75 | 8144 | 289 + 4 | 8512 | 1 |
| after `66544e8e` | 78 | 8146 | 293 + 4 | 8521 | 1 |

`compare_outcomes.py --before-rc --after-rc` (no flaky excusals): `COMPARE FAIL`,
missing 0, new 9, outcome_diff 11 (`full-suite/cmp.txt`).

- **9 new nodes, all Inc 1b's own:** R-COPY.26/1 teardown test (passed);
  R-PASTE.14 C1 `[key|right|row]` and C2 (skipped: WinCI-only); and four
  `test_b103_winci_gate.py` artifact-scanner nodes for the hosted-runner exception (passed).
- **11 outcome swaps (B2), each re-run alone on both trees at load ~3 (`full-suite/rerun.tsv`):**
  4 failed->passed and 6 passed->failed pass alone on both trees: load-sensitive under the
  shared `-n 8` run (several are timing/perf nodes: R-A2L-READ.52, R-A2L-MATCH.36/1,
  R-CHG-SYM.13, R-TUI-043.10), not called flaky. The 11th,
  `test_r_tst_111_112_arm_values_equal_the_product_stamps[cap]`, is D-R11-3 (intermittent on
  both trees).
- **Failures common to both:** 71 (75 - 4 = 78 - 7). They include the canon shall-twice row
  (P-031) and law 070_2, which under `run_suite.sh`'s HOME basename fails on both trees only on
  that basename (3,943 hits of it, no other form: D-R11-1 removed the placeholder-path hit).
- WinCI-only nodes skip on Linux by design (R-PASTE.13/101, R-PASTE.14/101-103, C1, C2,
  `test_b103_clipboard_windows.py`).

### Final re-check on the record tip `422a836d` and PP-02

- Laws `test_no_private_tokens`, `test_suite_hygiene`, `test_id_registry`,
  `test_requirements_canon`, `test_deps_seam_law` (`-n 4`): with an unused HOME basename
  97 passed, 1 failed (canon shall-twice, P-031, pre-existing); with the runner rules'
  basename 96 passed, 2 failed (plus 070_2, hits only the three Inc 1b records of D-R11-2;
  none from this folder).
- PP-02 on `git diff a95d0ea9..HEAD` and its commit messages: pattern hits 0 / 0; needle
  hits 0 / 0 (7 needles, counts only). Added lines with CR: 0. No push made.
