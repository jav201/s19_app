# P4 base2: Inc 1b final carried into the modular base

Branch `b103-base2` (local only, no push), worktree `s19_app-b103-base2`.
Base `a95d0ea9` (batch-modular `2dbd7d5a` + the patch_editor split). Merged branch
`b103-inc1b-push`: first at `99075449` (merge `d8555d03`), then its records-only close
commit `aba3b947` (merge `c3760226`). Brief: R11 (P-011 local half).

## State / next step

- DONE: merge, port, retarget, merge-prediction check, AST identity check.
- RUNNING: check (a) on rtx (merged and Inc 1b tip, same five files, serial).
- NEXT: negative controls, check (b) laws on merged and on a95d0ea9, full suite vs the
  a95d0ea9 baseline, PP-02 scan, scratch deletion.

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

## Checks

Pending.
