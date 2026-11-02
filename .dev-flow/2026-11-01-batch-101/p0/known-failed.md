# Known failed checks — batch-101 P0 (UI rows left out of scope)

- **Ruling (operator, 2026-11-01, relayed by the orchestrator):** every triage row marked "UI change = yes" (37 rows) leaves batch-101's scope and goes to the backlog, to be reviewed in the next iteration. Batch-101 plans **no increment and no prototype round** for them.
- **What this file is:** each row is a **known failed check**: what the check expects, and what the app does today. It does not say the app is broken. The `class` and `harm` columns are notes for the next review.
- **Class** (from the operator's earlier ruling, kept as a note):
  - **a** = the app does not match its approved design or requirement.
  - **b** = a proposal to change an approved design.
  - **c** = new UI that no approved design covers.
- **Harm scale:** `none` · `cosmetic` · `blocks a task` · `wrong result` · `data loss`. "Wrong result (displayed)" means the screen states something false. It does not mean stored data is wrong.
- **Sources:** `docs/user-guide/DOSSIER.md` §5 (F-xx), `.dev-flow/2026-10-26-batch-100/04-ux-inspection.md` (UX-I-xx), the triage tables `p0/triage-A…E-*.md`.
- **Backlog row ids:** the eight `KF-101-*` grouped rows. Their texts are proposed in the P0 reply to the orchestrator; the orchestrator writes them into `BACKLOG-CODE.md`.

## Rows flagged for the operator (harm above cosmetic)

No row causes **data loss**. These rows may cause a wrong result or block a task, so the operator may want to rule on them before v1.0.0:

| Id | Harm | Why it is flagged |
|---|---|---|
| F-15 | blocks a task | On the shipped 10 MB demo image, the Memory Map is blank until a key is pressed, and each key press takes several seconds (6365 widgets). |
| F-25 | wrong result (risk) | The A2B Diff A and B dropdowns paint no value at 118 or 220 columns. The user cannot see which variants the diff will compare. |
| F-36 | blocks a task | The Flow Builder cannot add a REPORT block. The only way is to edit the flow file by hand (the guide did that in ch21.4). |
| UX-I-13 | wrong result (displayed) | The Load preview marks `broken.s19`, but loading installs `firmware.s19` (HLR-173a is unmet). |
| UX-I-10 | wrong result (displayed) | After a save-back, `#status_text` names the old variant, while the right segment names the new one. |
| UX-I-12 | wrong result (risk) | Two recent sources with the same name look identical, and the path tail is cut off. The user can open the wrong file. |
| UX-I-03 | wrong result (displayed), minor | The A2L-only panel says "first variant by name" with 0 variants, and still offers `Select variant (v)`. |
| F-10, F-11 | blocks a task at 118 columns (to verify) | Controls and columns are clipped at the reference width. Paging still works through `pageup`/`pagedown` (`app.py:2709-2710`). Whether a key reaches In-Memory, the find field or the hidden MAC columns is not verified. |

## Table

| Id | What the check expects | What the app does | Class | Harm | Backlog row |
|---|---|---|---|---|---|
| F-04 | After **Apply loaded changes** on any Patch Editor tab, the "Save patched image as" prompt is visible | The prompt row sits inside the JSON tab pane (`screens_directionb.py:5080-5105`). On Inspector or Checks nothing shows it | a | cosmetic (the prompt is on the JSON tab) | KF-101-P |
| F-22 | Patch Editor **Save** asks for a file name | Save writes `changes.json` (dedup suffix `_N`) without a prompt, as the approved scoped-home design does | b | none | KF-101-P |
| F-08 | At 118 columns the search/goto and A2L filter inputs show the typed text | The inputs are 1–3 cells wide (`styles.tcss:501-507, 655-669`, `1fr` with no floor) | a | cosmetic (input still works) | KF-101-V |
| F-09 | A2L tag table columns are readable apart | `cell_padding=0` (`app.py:7697`): `0x00803DE064` reads as address + length | a | cosmetic (misread risk) | KF-101-V |
| F-10 | The A2L filter row fits 118 columns | In-Memory, the find field and the page buttons are clipped (`#a2l_tags_filters`, `app.py:7674-7687`) | a | blocks a task at 118 (to verify key paths) | KF-101-V |
| F-11 | MAC View at 118 columns shows its record columns, page buttons, title bar and `?` chip | Only Tag and a clipped Address show. The page buttons stack invisibly. There is no `WindowSection` header (`app.py:7742-7816`) | a | blocks a task at 118 (to verify) | KF-101-V |
| F-12 | Workspace Loaded panel shows the PROJ, S19, MAC, A2L slots and `[U]` at 118×54 | The `width-narrow` rule caps `#loaded_slots` at 2 rows (`styles.tcss:283-290`) | a | cosmetic (the slot list scrolls) | KF-101-V |
| F-25 | A2B Diff A/B variant dropdowns paint their value | Compaction gives the Selects a 1-column content width (`styles.tcss:1187-1212`, carry C-78-iv) | a | wrong result (risk): the chosen variant is not visible | KF-101-V |
| F-32 | CRC Designer bench fits 118×54, or shows that it scrolls | Store placement, Custom vector, Template and Load/Save sit below the fold, with no cue (`styles.tcss:2293-2326`) | a | cosmetic if the panel scrolls (to verify) | KF-101-V |
| F-15 | Memory Map paints on first show and answers a key press promptly on the demo image | Blank until a key is pressed (no `on_show` on `MemoryMapPanel`, `screens_directionb.py:2221`). One widget per run, 6365 widgets, seconds per key | a (first show) · performance | blocks a task | KF-101-M |
| F-17 | "Unsaved changes will be lost" dialog is sized to its content, like the other questions | Buttons are cramped top-left in the shared 70%-wide `.modal-dialog` (`styles.tcss:1589-1596`) | a (to confirm against the approved modal design) | cosmetic | KF-101-Q |
| UX-I-17 | A question's filled emphasis follows its focused default (the operator rule, 2026-11-01) | The replace question focuses `Cancel` but fills `Replace (y)` (`screens.py:1499-1501`) | b (already ruled by the operator) | none (Enter picks the safe answer) | KF-101-Q |
| UX-I-18 | Replace question title states the load decision and its consequence | Title "Replace firmware.s19?" while the body asks "Load project P anyway?" | b | none | KF-101-Q |
| UX-I-20 | Quit text starts upper case and names what `y` does | "still working: … — wait, or quit after it finishes" (`app.py:438`) | b | cosmetic | KF-101-Q |
| F-19 | Viewer settings menu closes (Esc, re-pick, window switch) | Open only (`app.py:9769-9774`). `_toggle_settings_menu` (`app.py:19437`) has no caller | a | cosmetic (a 48×12 box stays until restart) | KF-101-K |
| F-20 | `]` does one thing everywhere | Inside A2B Diff `]` pages the hex windows (`screens_directionb.py:7951`). Outside the panel it opens Flow Execution (`app.py:2698`). The panel comment is stale | a | none | KF-101-K |
| F-31 | Every listed operation runs | `extract` and `split_by_segment` return "placeholder — not yet implemented" (`operations/placeholders.py:90`) | b | none (the result says it is a placeholder) | KF-101-K |
| F-36 | The Flow Builder can add a REPORT block | `_KIND_OPTIONS` has no report kind (`flow_screens.py:1104`) | c | blocks a task (workaround: edit the flow file) | KF-101-F |
| F-48 | A later block can reference an external step's output copy | No `#n` / binding / `${NAME}`. The only way is to type the copy's file name. The docstring (`flow_model.py:476-487`) promises otherwise | c | none (the by-name workaround works once F-49 is fixed in Inc 8) | KF-101-F |
| F-50 | The Flow Builder can confirm an external step; Terminal mode runs the command | The Builder pauses with no Confirm (confirm exists in Flow Execution only). Terminal mode checks that the files exist and never runs the command | c | none (confirm in Flow Execution) | KF-101-F |
| UX-I-01 | HLR-178: the Load-result information stays reachable in the Load dialog's preview of the open project | The preview has no announcement input (`app.py:8472-8591`) | a | none (reloading shows it again) | KF-101-L |
| UX-I-02 | Unreadable-variant reason names the variant | Generic text (`variant_execution_service.py:1734`) | b | none | KF-101-L |
| UX-I-03 | A2L-only Load-result panel is consistent and offers no variant pick with 0 variants | Contradicting reason. `#result_variant` is always yielded (`screens.py:1715`) | a | wrong result (displayed), minor | KF-101-L |
| UX-I-04 | Focus on `#result_body` is visible | Background tint only (`styles.tcss:3761`) | b | cosmetic | KF-101-L |
| UX-I-05 | Problems that share a reason are grouped | One wrapped row per problem (`screens.py:1768-1778`) | b | cosmetic | KF-101-L |
| UX-I-12 | Load preview shows the distinguishing folder of a same-named source; recent rows carry the folder | The path line ends in nowrap + ellipsis (`styles.tcss:1823-1838`). The recent label is name + kind only | a (preview half) · b (label half, the operator sent it to the backlog) | wrong result (risk) | KF-101-L |
| UX-I-13 | HLR-173a: the preview marks the variant that loading installs | The preview recomputes `choose_install_set` from disk (`app.py:8553-8573`) | a | wrong result (displayed) | KF-101-L |
| UX-I-14 | Load dialog hint line (C-UX-9) | No hint widget in `LoadDialog.compose` | b | none | KF-101-L |
| UX-I-15 | 80×30 stacked layout uses its rows | The list shows 2 rows with 4 blank rows. The cited lines (`styles.tcss:1797-1804`) set no heights, so the cause is not located | b | cosmetic | KF-101-L |
| UX-I-16 | The path placeholder fits 118 columns | `…or a` shows and "project folder" is cut (`screens.py:364`) | a | cosmetic | KF-101-L |
| UX-I-06 | Save dialog describes the image file once, without contradiction | "unchanged copy" + "keep", and "0 applied by this save" (`app.py:12643-12656, 11330-11342`) | b | cosmetic (misread) | KF-101-S |
| UX-I-07 | Save dialog has a title naming the action | The only heading is "Project name" (`screens.py:1028`) | b | none | KF-101-S |
| UX-I-08 | A save-back that switches the active variant shows the "active variant … (before: …)" row | The row is computed for merges only (`app.py:11071-11094`) | b | none | KF-101-S |
| UX-I-09 | The Save summary is never an empty strip | Refusal previews carry `rows=()` (`screens.py:1111-1143`) | b | cosmetic | KF-101-S |
| UX-I-10 | After a save-back the status line names the new active variant | `end_busy` hands back the `file_state` captured at `begin_busy` (`app.py:20299-20350`) | a | wrong result (displayed) | KF-101-S |
| UX-I-11 | The save outcome line shows what was saved at 118 columns | It leads with the absolute path and is clipped (`app.py:12191-12195`) | a | cosmetic | KF-101-S |
| UX-I-19 | The idle progress row shows no "0%" track (C-UX-7) | `end_busy` resets the bar to 0 and the label paints "0%" (`app.py:20349`) | b | cosmetic | KF-101-S |

Count: 37 rows (F-04, F-08–F-12, F-15, F-17, F-19, F-20, F-22, F-25, F-31, F-32, F-36, F-48, F-50, UX-I-01–UX-I-20).

## Perf note for the next review (F-15)

The objective asked for an in-scope or deferred decision on F-15. **Decision: deferred** by this ruling (it is a UI row). Proposed measurable target for the review:
- the map paints on first show with no key press, checked by a deterministic arm;
- an arrow-key selection repaints in ≤ 300 ms on the 10 MB demo image, measured on the LAN host as a `serial_timing` arm (Inc 2's marker);
- the mounted widget count is bounded (e.g. ≤ 500), checked by a deterministic arm.

The first-show half alone (re-apportion on show) changes no layout. The review may want it split off as a non-UI fix.

## New-canon rows these checks map to (for the next review)

The strict-EARS canon (it replaces the old canon in batch-101 Inc 1) already holds rows for some of these checks:

| Check | Canon row | Source item |
|---|---|---|
| F-19 | R-SHELL-SETTINGS.5 | `s19w/review/CODE-CHANGES.md` D6-26, D6-12 (second half) |
| F-31 | R-OPS-002.1 | D13-13 |
| F-04 | — | D10-40 (needs prototype) |
| F-11 (title row, `?` chip) | R-WHELP.3 | D7-30 (needs prototype) |

A check whose canon row says the behaviour **shall** exist is class `a` against the new canon. The next review reads it that way.
