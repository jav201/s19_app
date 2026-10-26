# PDR · UX lens — batch-100 (Load + projects)

- **Reviewer:** `ux-reviewer`, because trigger D1 fired. Rules: `stations/p3-implementation.md` §PDR, design-review row 9 (interaction design). Read-only: I edited and committed nothing.
- **Under review:** `design/design-proposal-b100.md` at `a1cad7e`.
- **Reviewed against:**
  - `01-requirements.md` with the ledger up to LED .34;
  - the operator's verdict `design/veredicto-load-projects.json` (P-A C, P-B A, P-C B, P-D A, P-E B);
  - the round's real captures in `prototypes/load_projects/png/` (pa_C, pb_A, pc_B, pd_A and pe_B at 118×54, read in P2).

## Verdict

**`approved with conditions`.** There are 9 conditions. Each can be discharged on its own and has an owner and an increment. No HIGH.

The design follows the chosen variants on every surface:
- pa_C, with `●` through `choose_install_set`;
- pb_A, with the focus on No;
- pc_B, painted only from the frozen `SavePlan`;
- pd_A in `#status_text`;
- the pe_B panel.

It also carries my P2 conditions C-1, C-2 and C-3 (LED .24–.26).

**What is not covered:**
1. **The "real progress" premise of the operator's P-D verdict cannot be met for the A2L parse with the declared files.** `parse_a2l_file` is a single call with no progress hook, `tui/a2l.py` is a frozen engine file, and Inc 12 touches only `app.py` and `styles.tcss`. See C-UX-1.
2. **`p` followed by `enter` would load nothing.** The design starts the focus on the path field, so `enter` reads the empty typed text instead of the highlighted project. See C-UX-2.
3. **Four visible elements the round never showed:** `computing…` rows, the quit question, the "Close (esc)" label and the stacked P-A layout. They need operator sight before they ship, not a new round. See C-UX-3, C-UX-4, C-UX-5 and C-UX-6.
4. **The Phase-4 real-terminal inspection is required by the contract (§5.1) but absent from the proposal.** It has no enabler and no consumer row. See C-UX-5.

## Findings and conditions

| id | sev | where | finding | evidence | condition: owner · increment |
|---|---|---|---|---|---|
| C-UX-1 | MAJOR | §5.14 Inc 12 ("within-step progress from byte counts"); LLR-176.1 ("when the step reports bytes (copy, read, parse)") | **The parse step cannot report bytes with Inc 12's file set.** `parse_a2l_file` builds the section tree and extracts the tags in one call, with no callback. The app calls it once, through `_load_a2l_data_with_cache`. `tui/a2l.py` is a frozen engine file (§7), and the proposal declares that no frozen file is touched. So for case_06 the bar stays still for the whole ≈5 s parse, the longest step, while TC-B100-50 passes on a synthetic "1 MiB in 4 chunks" step and AT-B100-17 passes on step transitions. The operator's P-D verdict was conditional on the bar "realmente hace su trabajo". | `a2l.py:2627-2660`; `app.py:8841-8845`; `docs/ARCHITECTURE.md` §7 (`s19_app/tui/a2l.py` frozen); proposal §1 "No frozen-engine file … is touched"; Inc 12 = `app.py`, `styles.tcss`. | Pick one, before Inc 12 opens. **(a)** Name the frozen-engine crossing: add a progress callback to `parse_a2l_file`/`build_section_tree` (needs a contract amendment, and Inc 12 goes to 3 files). **(b)** Amend LLR-176.1 to list the parse as an indivisible step (spinner and elapsed time move; the bar holds), and show the operator one real capture of that state for acknowledgment. In both cases, add an AT-B100-17 arm that observes the bar *during* the parse step, not only between steps. **Owner:** orchestrator + operator · before Inc 12. |
| C-UX-2 | MAJOR | §5.11 Inc 9b ("the focus starts on `#load_path`"; "`enter` … load the row or the typed path by last focus"); VS-PA-4 (`p` highlights the open project's row) | **`p` + `enter` loads nothing.** `p` opens the dialog with a project row highlighted, but the focus starts on the empty path field and the list never had the focus. By LLR-173.2's precedence, `enter` then reads the empty typed text and paints `nothing selected`. That breaks the most common keyboard path, "open project", and the ATs that drive "`p`, the project row, `enter`" (AT-B100-03/04 per §5.3). | LLR-173.2 statement; VS-PA-4; contract §5.3 re-pins "project picks re-pinned to `#load_list` + `enter`". | `p` opens the dialog with the focus on `#load_list` and the project row highlighted; `l` and `ctrl+l` focus `#load_path`. TC-B100-41 gets an arm: `p`, `enter` → that project loads. **Owner:** Inc 9b. |
| C-UX-3 | MAJOR | §5.13 Inc 11; LED .26 (`computing…` rows; "`alt+s` … waits under the busy indicator") | **Two visible behaviours the round did not show.** (a) `computing…` is a new status word in the pc_B summary. (b) What the user sees after an early `alt+s` is unstated. If the dialog stays open, the only feedback is the status line behind the modal and a second press is likely. If it closes, the summary the operator asked to be "extra cuidadoso" about disappears before its digests arrive. | Proposal §5.13; LED .26; operator P-C note. | State it: on `alt+s` with no refusal pending, the dialog closes at once, the save runs under the pd_A status line (the outcome names what was written), and a second `alt+s` cannot arrive. Or, if it stays open, the Save button shows its waiting state. Before Inc 11 merges, show the operator one real capture of pc_B with the `computing…` rows (and of the waiting state, if one is chosen). Not a new round. **Owner:** Inc 11 · orchestrator for the capture. |
| C-UX-4 | MAJOR | §5.14 Inc 12 ("quit asks through the Inc 10 confirm modal, which takes its question text as a parameter") | **The quit question would show pb_A's verbs.** Only the question text is a parameter, so the buttons would still read "Replace (y)" / "Cancel (n)" over a quit question. The round never showed a quit question. | `png/pb_A.pb.118.png` (buttons "Replace (y)", "Cancel (n)"); proposal §5.14. | Inc 10 builds the modal with the question **and** both button labels as parameters (for quit, for example "Quit (y)" / "Keep working (n)"), with the focus still on No. TC-B100-53 presses the shown keys. Add the quit capture to C-UX-5's inspection. **Owner:** Inc 10 (modal), Inc 12 (use). |
| C-UX-5 | MAJOR | Proposal §7 and §5 enablers; contract §5.1 (Phase-4 expert inspection) and §5.2 ("recorded with no open HIGH") | **The Phase-4 real-terminal inspection is not planned in the proposal.** It has no enabler and no consumer row. The round's capture tools live in `prototypes/`, which is never committed. The visual claims that only that inspection can settle are: the panel's last row visible, Save/Cancel pinned, no row wrapped, the P-A stacking below 100 columns (never captured in the round), and the new elements in C-UX-3, C-UX-4 and C-UX-6. | Proposal grep: no "inspection", "capture" or "real terminal"; `prototypes/` never committed (contract §2.4). | Add a §7 row "Phase-4 expert inspection → `04-validation.md` §UX walkthrough", plus enabler **E13**: a capture script outside `prototypes/` (repo `tests/support/` or the session scratch) that runs the shipped app in Windows Terminal in truecolor, with `NO_COLOR` unset, at 118×54, 220×60 and 99×54, and closes every window it opens. The scenarios: P-A per row kind and stacked; P-B; P-C fresh / merge / `computing…`; P-D during the parse; P-E clean, after a save-back, and with 30 problems; the quit question. **Owner:** orchestrator (E13 at Inc 6, the first new surface) · `ux-reviewer` at P4. |
| C-UX-6 | MINOR | §5.6 Inc 6, LED .25 (`#result_ok` "Close (esc)") | A visible change from pe_B ("OK (enter)"). It is the fix for my P2 C-1, and it adds no glyph, column or pane. | `png/pe_B.pe-latest.118.png`; LED .25. | No new round. Include it in the C-UX-5 captures for the operator's sight. **Owner:** Inc 6 · P4. |
| C-UX-7 | MINOR | §5.14 Inc 12 ("the bar … hidden when idle"); pd_A ("No ocupa filas nuevas") | If hiding the bar removes its row, the four log lines shift by one row at every start and end of an action. pd_A's promise was no new rows. | Page §P-D A; `png/pd_A.pd.118.png` (the bar row sits above the log lines). | Hide the bar without collapsing its row (`visibility: hidden`, or an empty track). TC-B100-50 asserts the log lines' regions do not move between idle and busy. **Owner:** Inc 12. |
| C-UX-8 | MINOR | LLR-173.4 (a recent row shows "path, size and last-seen time from the store"); LLR-172.1 (the store holds `{"path", "kind"}` only); VS-PA-5 ("`●` for every row kind (… recent)") | Two contract inconsistencies the design inherits. (a) The store does not hold size or last-seen time, and a stat before `enter` is forbidden, so the row cannot paint them. (b) VS-PA-5 promises `●` on recent rows, while LLR-173.4 and LLR-173.6 give them nothing beyond the store fields and "checked when loaded". | LLR-172.1, LLR-173.4, LLR-173.6 and VS-PA-5 text. | One ledger entry: either the store gains `size` and `seen` (written at record time), or LLR-173.4 drops them; and VS-PA-5 says recent rows carry no `●`. **Owner:** P1 author by ledger · before Inc 9a. |
| C-UX-9 | MINOR | §5.11 Inc 9b | pa_C's hint lines are now wrong for the shipped keys. "or type a path (tab)" no longer holds, because the focus starts on the path field and `tab` goes to the list. The D10 line is banned by LLR-173.7. The proposal does not say what the hint line says. | `png/pa_C.pa.118.png` (hint lines). | Define the dialog's hint line from the shipped keys (for example "tab: list · enter loads · esc closes"). TC-B100-41's "every shown key pressed" covers it. **Owner:** Inc 9b. |

## Visible elements the round did not show

| Element | Increment | Status |
|---|---|---|
| `computing…` rows, and the early-`alt+s` state | 11 | **New status word.** Operator sees a capture before the merge (C-UX-3). |
| Quit question (pb_A form, new text and verbs) | 10 / 12 | **New use of a shown component.** Captured, and the button labels are parameterized (C-UX-4). |
| "Close (esc)" on pe_B | 6 | **Changed label.** Captured at P4 (C-UX-6). |
| P-A stacked below 100 columns | 9b | **Layout never captured.** P4 at 99×54 (C-UX-5). |
| `●` on MAC/A2L and on file rows | 9b | Same glyph pa_C showed, extended to the set the operator asked for ("el símbolo de cuál es el set"). **Not a re-open.** |
| Refusal and problem tokens; "details: p" | 2, 7, 9b, 11, 12 | Text in slots the round showed (`#load_reason`, the status log, the summary), with wording approved at P2 (§3 token table). **Not a re-open.** |

No new pane or column is introduced.

## Checklist

| Check | Result |
|---|---|
| Per-increment interaction matches the chosen variants (pa_C ●, pb_A, pc_B from the plan, pd_A, pe_B) | ✓ by design. pd_A's within-step progress: ✗ for the parse (C-UX-1). |
| Panel "Close (esc)", `escape` from anywhere, `enter` only on OK (C-1) | ✓ (§5.6, LED .25). Capture owed (C-UX-6). |
| Load dialog focus starts on the path field; `tab` path → list → preview → buttons | ✓ for `l` and `ctrl+l`. ✗ for `p` (C-UX-2). Hint text (C-UX-9). |
| alt+letter in modals with text fields (`alt+l`, `alt+s`); single letters in pb_A and pe_B | ✓ (§5.11, §5.13; contract §3 *Keys*). |
| `computing…` rows and `alt+s` waiting (C-2) | ✓ for the freeze (worker, first frame first, 2 s budget measured at Inc 11). ✗ for the visible behaviour (C-UX-3). |
| Width rule: ATs at 118×54 and 220×60 with notifications on (E10); P-A stacking below 100 with a 99/100 arm | ✓ in tests. ✗ visual check of the stacked layout not planned (C-UX-5). |
| Phase-4 expert inspection in a real terminal | ✗ not in the proposal (C-UX-5). |
| New glyph, status word, column or pane | `computing…` (status word) and the quit question → operator sight, conditions C-UX-3 and C-UX-4. No new glyph, column or pane. |
| Every UX test non-vacuous (mutation declared) | ✓ for the listed TCs. TC-B100-50's synthetic chunk arm cannot see the parse step (C-UX-1). |

### The three acts (ISO 9241-210)

- **Automated walkthrough:** `not performed`. This is the PDR, and nothing ships yet. It is planned through the ATs at the two reference sizes (E10).
- **Expert inspection:** `performed` here against the proposal and the round's captures, and owed at P4 in a real terminal (C-UX-5).
- **Evaluation with users:** `not performed`. The team is one person and this surface has no user outside it.

## Not covered

- The architecture, test and security lenses of the proposal, except where they change what the user sees.
- The 220×60 captures of the round (only 118×54 was read).
- Measuring the 2 s digest budget: it is owed at Inc 11 by LED .26.
