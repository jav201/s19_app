# Inc 12 — E3 rulings (orchestrator, 2026-11-06)

Round 1: `E3-architect.md` **FAIL** (1 MAJOR, 7 MINOR); `E3-security.md` **PASS-WITH-NOTES** (3 MINOR); `E3-ux.md` **PASS-WITH-NOTES** (1 MEDIUM, 3 LOW, 3 INFO). The design stands; the blockers are record defects. The correction pass also applies **D-5 B: the split into Inc 12 (`screens.py`, `app.py`, `screens_directionb.py`) and Inc 12b (`flow_screens.py` alone)**, using the architect's split map (`E3-architect.md`). Rulings under the operator's standing commission:

| Finding | Ruling | Why |
|---|---|---|
| E3A-01 (MAJOR) | Accept: *Reach* and I-5 redefined — an action is reached only by its exact action string in a binding, the palette or a call from a function that is itself reached; message text never counts. Base becomes 3 of 83. Add the negative control: `action_view_alt` restored with its dead callers → the census is RED. | A census that a restored dead caller keeps GREEN cannot guard F-34. |
| E3A-02 | Accept: the same reach rule for R-DLG.14's openers. | Same gap, same fix. |
| E3A-03 | Accept: the widget rows say "every widget with an id" and pin the population (the driven states named in the row). | The row must say what the walk counts. |
| E3A-04 + U-1 | Accept: **Inc 12 owns the DOSSIER marks and `_FIXED`** (`tests/test_b101_help_legend_docs.py`, named supersession: F-33, F-34, F-35, F-51); Inc 12b marks no DOSSIER row. F-35 is marked `fixed in 1.0.0` by Inc 12 because Inc 12 merges last (after 12b); if the order ever flips, the increment that merges second marks it. Add one docs case each for the ch16 and ch18 sentences (U-5 wording). | One owner for a pinned set; F-35 is fixed only when both halves are in. |
| E3A-05 | Accept (12b): G-T3's re-point list is 39 nodes in 13 files, including Inc 9's helper `_add_load_block` (`tests/test_b101_flow_names_ui.py`), on the tree after Inc 9 merges. | Inc 9 adds a reader of `#flow_kind`. |
| E3A-06 | Accept: R-DLG.2's threshold covers the Reports dialog; the canon fold records "Partly"; backlog BL-I12-5 for the 7 dialogs that ignore Escape. | Out of the four findings' scope. |
| E3A-07 | AT-I12-2: re-point the fixture case 10a withdrew. The 10a addendum is committed (`d68cb9f` on `b101-inc10`): closed. | — |
| E3A-08, U-3 | Accept: R-DLG.15/1 moves the highlight (`down`) before Escape and asserts the selection unchanged, the dropdown blank and no `Report filter:` status. | The case must be able to fail. |
| U-2 | Accept: R-DLG.2/1 and AT-I12-1 assert the focus returns to the widget focused before `t`, with one Close press as the reference. | Escape must equal Close, focus included. |
| U-4 | Accept: add R-DLG.15/2 on the Flow Builder's block edit dialog (`FlowBlockEditScreen`), in Inc 12 (test only; no source change in `flow_screens.py`). | The row is general; one more dialog with a dropdown proves it. |
| U-5, U-6 | Accept the exact wording and the CTX-DIALOG "focus today" correction. | — |
| U-7, U-8 | Agree; BL-I12-2 as is, BL-I12-3 widened (nothing shows `esc` for Reports). | — |
| S-1 | Accept (12b): the kind state accepts only `_KIND_OPTIONS` values (a chip id outside them is ignored); add a case. | The removed Select was the only check. |
| S-2 | Accept (12b): every re-pointed security node keeps its hostile input and its painted-text assertion; E5 mutants `nul_add_refusal → None` and refs painted with `Text.from_markup`. | Re-pointing must not weaken them. |
| S-3 | Closed for the commit (`d68cb9f`); at Inc 12's integration, grep the merged tree for every removed name (I-3 list) before the GREEN run. | The census cannot see a dangling call. |

Correction: one Opus design-correction agent (targeted edits plus the split). Round 2: the architect re-checks E3A-01 … -05 and the split, and confirms U-1 … U-4 applied; the security reviewer re-checks S-1, S-2 in 12b.

## Round 2 (2026-11-06)

Architect: **Inc 12 FAIL** (E3A-R2-1 MAJOR), **Inc 12b PASS-WITH-NOTES**. Security: **PASS-WITH-NOTES** (S-1, S-2, S-3 closed; S2-1, S2-2 LOW). Rulings:

| Finding | Ruling | Why |
|---|---|---|
| E3A-R2-1 (MAJOR, Inc 12) | Accept: **remove `S19TuiApp.action_a2l_tag_find_next`** (orchestrator verified on main `2d1e2b1`: no binding or palette entry names it; the Find-next button calls `_handle_a2l_tag_find_next()` directly, `app.py:21010`), as D-2 A. *Reach* counts only binding, palette, `run_action` and `@click=` positions (a widget id literal is not a reach). Base = 4 of 83; add the control "restore it → R-SHELL-KEYS.3 RED". Fix the docstrings that list it as a caller (`app.py` near `:16671`). | A dead action the census cannot see defeats F-34's guard. |
| E3A-R2-2 | Accept: the after count includes `action_close_reports` (80 with R2-1). | Counts must add up. |
| E3A-R2-3 | Accept: state the limit in full (every arm but the toolkit one matches by name, with the `select_variant` example; no instance on base). | Records must not under-state a limit. |
| E3A-R2-4 (12b) + S2-1 | Accept: each I-3 grep pins `git grep -w` on the bare ids and names, narrows `_layout` to `FlowBuilderPanel`, and lists the expected remaining lines (e.g. the 3 `window_help.py` docstrings of BL-I12-1). | An "empty result" that can never be empty is not a check. |
| S2-2 (12b) | Accept: a re-pointed hostile input stays whole when it fits a card; otherwise it keeps one of each hostile kind (markup tag, C0 / C1 / DEL bytes, sentinel). | The control-byte checks must still be able to fail. |

Correction: one Opus pass (targeted edits). E3 closes for 12b after it; for Inc 12 the orchestrator checks R2-1's application (PDR) and closes E3.

## Round-2 correction check (orchestrator PDR, 2026-11-06) — E3 closed for Inc 12 and Inc 12b

The correction (`82b8c3b`) applied E3A-R2-1 … R2-4, S2-1, S2-2. Orchestrator check of E3A-R2-1: the removed node `action_a2l_tag_find_next` is in the graph, the slice (with the overlap on Inc 10a's #10, `_handle_a2l_tag_find_next`, separate hunk), the requirement census (base 4 of 83, after 80) and the restore-it control case. **Ruled on the correction's open choice:** tests stop spelling the removed names (the by-name absence clauses of R-DLG.14/1 and R-SHELL-KEYS.3/1, TC-B97-61's toggle lines, 12b's "assert hidden" checks) so the pinned I-3 greps return exactly their listed lines — accepted: the censuses and the widget walks fail on any re-added dead entry, so the dropped clauses added no failure mode. No round 3: the MAJOR is a removal the orchestrator verified on main, and its application is checked above. **E3 closed** for Inc 12 and Inc 12b.
