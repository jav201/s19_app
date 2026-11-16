# Inc 7 E5 — review (X7: one reviewer, one pass, code and security; DF-03)

Reviewer claude-opus-5-5. Tree `b103-inc7`, base `63791549`, reviewed diff `git diff 63791549..11bdeb98 -- s19_app tests` (23 files), then this pass's fixes. Captures: `E5-captures.md`. Runs and verdict: `04-validation.md`.

## Findings

| Id | Sev | Kind | Finding | Disposition |
|---|---|---|---|---|
| F-X7-1 | MAJOR | impl (layout) | **R-A2L-LIST.083 broken at 120×30**: the real terminal shows the table header and no row (capture `layout.120x30`); the list columns are wider than the 50-column short tags pane, so a horizontal scrollbar takes the table's one body row. The test helper counted `table.size.height`, which includes the scrollbar row, so `test_r_a2l_list_083_1` passed (vacuous for this). 160×40 and 118×54 show 10 rows, not the 11 the cases state. | Fixed test-first: the helper counts `scrollable_content_region.height` (rows inside the scrollbars): RED 0 / 10 / 10 on the tree; the short body hides the table's horizontal scrollbar (`styles.tcss`; ← / → still scroll, capture `scrolled.80x54` scroll_x 8): GREEN. Case /3 (118×54, stacked) re-stated to the built ≥ 10 rows (DF-04 b; the E3R2 value counted the scrollbar row). |
| F-X7-3 | MAJOR | security | **A hostile A2L name reached the terminal raw.** A2L tag names may hold ESC, NUL and bidi controls (the parser kept `H[red]<ESC>Q<U+202E>Z<U+200B>_0003`, capture `hostile.*`). Tab in the filter dropdown copies the name itself into the filter box (I-3 obligation 3, R-A2L-LIST.069), enter on the add line appends it to the text area (.057), and the list-mode prefill (.041) writes the viewer's names into the text area; a stock Textual `Input` and `TextArea` paint their value as is (runner probe: ESC, U+202E and NUL present in the painted strips). | Fixed test-first (3 nodes, RED on the tree): the filter box keeps the name itself as its value (I-3 obligation 3, `test_r_a2l_list_069_control…` still green) and paints its display text; the add-line append and the prefill write the display text (a name holding a control then resolves as missing, visibly). R-A2L-LIST.076's surfaces gain the filter box and the text area (wording, DF-04 b). The base app's other boxes are not reached by an A2L name (typed keys and the stripped paste routes only). |
| F-X7-2 | MINOR | design-gap | The list-mode `Tag` cell paints the whole name (R-A2L-LIST.077 caps only the missing line, similar line, dropdown row and card). `#` and `Tag` are fixed columns (D-4 A, .010), so one name longer than the pane leaves `Status` … `Limits` unreachable for every row (capture `hostile.118x54`: a 300-character missing name). | DF-04 (c), new: not fixed. Proposal for the operator page: shorten the list-mode `Tag` cell by R-TUI-042a.5's measured-width rule (as text mode does). PENDING. |
| F-X7-4 | MINOR | design-gap | The filter dropdown stays open when the focus leaves the filter box (capture `text.118x54`: table focused, the dropdown covers the chips and 9 table rows and takes their clicks); only esc or tab closes it (.069, .070). | DF-04 (c), new. Proposal: close it on blur. PENDING, operator-visible. |
| F-X7-5 | MINOR | impl (layout) | Paste window at 118×54: the add line (37 columns) is overlapped by the counts/preview column; its placeholder is cut at `part of a name — start, middle,` (capture `window.118x54`). | PENDING (visual only; the box takes keys, hit at its centre). |
| F-X7-6 | MINOR | impl (security, base-identical in text mode) | The found-row card (the shipped `_a2l_detail_card_text`, `shared.py`) paints U+202E and U+200B of a tag name raw (ESC is removed): capture `hostile.220x60` card line `✓ H[red]Q<U+202E>Z<U+200B>_0003`. In list mode this is a pasted name on the card, against R-A2L-LIST.076's statement (its case /2 covers only the `✗` line). | Not fixed: the builder is outside Inc 7's files and is the text-mode card too. PENDING: `display_text` in `_a2l_detail_card_text`'s name line. |
| MU33 | MINOR | test gap | `_work` swallowing `call_from_thread`'s `RuntimeError` survives every node. | Ruled MINOR, accepted: the error exists only after the app stopped, on a worker of a finished app (`exit_on_error=False`), with no observable product effect; a node would test Textual's worker bookkeeping. PENDING (optional thread-exception node). |
| WinCI | — | test (census) | `test_r_dlg_14_101…` asserted 22 dialogs; Inc 7's `LabelListPasteModal` is the 23rd. The census (AST, runner) gives 23 dialogs, `LabelListPasteModal` among them, `dialogs_without_opener == []`: its openers are `A2LExplorerBody.action_paste_list` (alt+p) and the `Paste list…` button, so R-DLG.14 holds. | Census updated to the built list (23, named). The seed canary (`VIOLATION CONTROL_CANARY id=seed`) leaked only through the failing node's traceback locals (`clipboard = _ClipboardRecorder(os_value='SEED-1b', …)`), not by itself. |

Code reviewed with no finding: the I-1 hook placement (`os_clipboard_input.py`: after the cap, after the empty check in `action_paste`, only without `restrict`, stripped multi-line text; default `False`); the P-002 guard `if not self.is_running: return` kept in `_schedule_a2l_filter_refresh` (teardown test green); `_a2l_mode_keeps` is the one mode predicate (`_filter_a2l_tags`, the list resolution and the mode line call it; equivalent to base's inline test; P-087 b closed); the empty-filter summary goes through `safe_text`; every chips, missing, ribbon, counts, similar and dropdown text is a `Text` from `display_text`; the `LabelRanker` drops stale tokens and generations and never ranks on the UI thread. One note (no finding): a waiting ranking is dropped if a new A2L generation starts while the key's ranking runs; the next keystroke re-requests.

## Mutants (MU7)

42 / 50 killed (5 by the 3 new nodes), 7 equivalent (argued, accepted), 1 MINOR (MU33, above). `EXPECTED_SCANNED_TEST_FILES` 316 → 317 confirmed by `test_id_registry.py` on the clone (04-validation). **D-4:** `test_r_a2l_list_010_1` alone does not separate MU07a (header reordered), `test_r_a2l_list_009_1` does, and both are in the file: D-4 A is pinned by the pair (order: 009, fixed `#`/`Tag`: 010); no sharper node needed.

## Wording (P-089 list; DF-04 b)

Fixed in `01-requirements.md` (case text, meaning unchanged): R-A2L-LIST.076 (U+0085 only on A2L-fed surfaces), .025/3 (an A2L with no tag of that name), R-TUI-069.7 (the height cap), .083/3 (≥ 10 at 118×54, F-X7-1); `Files` paragraph names `window_help.py` (F-I7-5; trace_check SLICE). Changes meaning, listed for the canon fold, not edited here: R-A2L-LIST.015 ("a missing name" → "a missing name or a duplicate of one", F-I7-4); R-A2L-LIST.076 surfaces + the filter box and the text area (F-X7-3); R-PASTE.19/1 and E3A-01 rows 6/7: 47 → 49 text boxes (41 single-line, 8 multi-line); R-TUI-042a.5 (Inc 12 canon) cases /3 /4 /6 at the Inc 7 pane widths (118 arm at 118×30, *w* = 29; 220 *w* = 78 / 73).

## Operator items (provisional, P-059)

Each row: option kept now, reason, capture files (`evidence/e5/captures/`). All provisional, awaiting the operator's confirmation on the final page.

| Id | Option kept | Reason | Captures |
|---|---|---|---|
| D-2 / CV-1 | A (stacked < 180, wide ≥ 180, short below 110×32) | every hex row whole at 118 and 220 (.080/.081); cost: 3 hex rows at 118×54 (base 27, scene 9) and none at 120×30 | `layout.*` |
| CV-1 E3R2 | (a) built; **(b) recommended** | (a) leaves the filter and find boxes 0 columns wide (text invisible) and cuts `Find next` / `Page Prev` / `Page Next` at every size; the scene's two compact rows show them all; (b) is a design change for a later increment | `layout.*`, `f2-typed.*`, `base-f2-typed.*`, scene `av_mix.av-list.118.png` |
| F-I7-1 | reported, not redesigned | find box clipped (0 visible columns) at 120×30, 160×40, 80×24, 80×54; visible at 118×54 and 220×60; its buttons cut everywhere; the keys `/`, `+`, `-` still work | `layout.*` |
| F-I7-2 | reported | filter and find boxes 6 cells, 0 content columns, tree and base; a typed or pasted text is never shown | `f2-typed.*`, `base-f2-typed.*`, `drop-cuvre.*` |
| BL-I7-6 | 80×24 floor accepted as is | body 9 rows: 0 table rows and 0 hex rows (base: 0 table rows too); folding the chips is a new design | `layout.80x24` |
| D-3 / CV-2 | A (`name` or `all`) | `synthetic demo` in field `all` → a list of 2 missing names, as stated | `field-all.*` |
| D-4 / CV-3 | A (`#`, `Tag` first and fixed in list mode; Inc 12's Address/Length kept in text mode) | the later approval (G2); a missing row keeps its identity in view; long names: F-X7-2 | `layout.*`, `text.*`, `scrolled.80x54` |
| D-6 / CV-4 | A (`8 of 20+ similar names`) | nearest to the approved text within R-A2L-MATCH.40 | `drop-cuvre.*`, `drop-0017.*`, `drop-zzzz.*` |
| P-087 a | position accepted | the dropdown opens directly under the filter row from the pane's left edge, over the chips lines; F-X7-4 (stays open) | `drop-*.*`, `text.*` |
| D-7 / CV-6 | A (prefill) | the approved hint `alt+p edit the list` stays true | `window.*` |
| D-8 / CV-7 | A (first 10, cut line) | bounded work, the cut is visible | `similar-11.*`, `window.*` |
| D-9 / CV-8 | A (20 names then ` +<k>`) | bounded text; but the one-line cut shows 6 names at 220×60, so ` +<k>` and the duplicates part are off screen | `missing-25.*` |
| D-10 / CV-7 | A (`none (digits must match exactly)`) | approved text; BL-I7-2 stays | `window.*`, `similar-11.*` |
| D-11 | A, **P-1 not run** | alt+p / alt+f / esc reached the app through Textual's key path in the captures; real Windows Terminal key events were not injected (they would go to the operator's desktop session); P-1 stays open | `window.*`, `add-*.*` |
| D-12 / CV-9 | A (`✗ … not in this A2L`, `pasted #`, `closest`) | the scene's card; I-3 ranks off the UI thread | `card-missing.*`, `card-dup.*`, `mode-invalid.*` |
| CV-5 | kept | TEXT and LIST chips, mode line, hidden count as specified; each line one screen line cut with `…` | `text.*`, `mode-invalid.*` |
| CV-10 | kept | `0042 val` → `VALUE_0042 token`; enter appends it | `add-drop.*`, `add-enter.*` |
| CV-11 | kept with F-X7-3 fixed, F-X7-2 / F-X7-6 open | literal brackets, U+FFFD, 63 + `…` caps on the capped surfaces | `hostile.*`, `long-drop.*`, `unit300.*`, `hostile-drop.*` |
| F-I7-5 / P-095 | new help text kept | the help names the box by its painted placeholder (R-WHELP.12). Old: `Filter tags narrows the table to the tags that match; All, Invalid and In-Memory choose …`. New: `The box that says type part of a name — or paste a list narrows the table to the tags that match; All, Invalid and In-Memory choose …` | — |
| F-X7-1 fix | short body without a horizontal scrollbar row | the one table row at 120×30 (.083); horizontal scroll by ← / → | `layout.120x30` (before the fix) |
| F-X7-3 fix | names with controls enter boxes as display text | security over exact matching for such names; they then show as missing | `hostile.*` |

## Checks not run, and why

- P-1 real-key pilot (D-11): no OS key injection on the operator's desktop.
- The capture driver's two text-area paste scenes were re-taken after a driver fix (a `Paste` event posted to the widget bubbled and was inserted twice; posted to the app it is inserted once, like a terminal paste); filter-box pastes were unaffected (the hook stops the event).
- A U+0085 A2L name on screen: the parser case is covered by `test_r_a2l_list_076_6`; not captured.
