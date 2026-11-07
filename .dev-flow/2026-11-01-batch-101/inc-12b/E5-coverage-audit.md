# Inc 12b — E5 coverage audit

Batch 2026-11-01-batch-101, increment 12b, design-first flow (`dev-flow-v3-beta`, E5: "someone who did not write the test cases re-checks their `full`/`partial` marks and coverage"). Mode: **validation** (an audit of marks, oracles and results; no test was run). Auditor: the QA reviewer agent, which wrote no case, no node and no run. Worktree `<HOME>/Github/s19_app-b101-inc12b`, branch `b101-inc12b`, head `092fffd`. Inputs: `01-requirements.md` (2 active rows), `02-test-cases.md` (4 cases), `E1-slice.md` (§5: the 39 re-pointed nodes), `E1-rulings.md`, `E3-rulings.md`, `E4-impl-notes.md`, `E4-integration-notes.md` (int-00 … int-08, I-D1 … I-D14, the mutant table), `E4-tester-g-t3-notes.md`, `E4-tester-g-t4-notes.md`, the transcripts in `../evidence/inc-12b/`, the E1 pilot (`../inc-12/evidence-e1/i12e1-pilot.py` and its transcript), `tests/test_b101_flow_shown_widgets.py`, `git diff 2f54c7d -- tests` (13 re-pointed files and `test_id_registry.py`), the helpers the nodes call (`tests/b97_probes.py` `is_displayed`, `painted_rows`, `settled`; `tests/b97_fixtures.py` `open_flow_builder`, `open_flow_execution`, `import_flow`, `fx_project`) and the product code they enter (`flow_screens.py` `on_button_pressed`, `_refresh_blocks`, `_apply_layout`, `_card_rows`, `_card_annotation`; `app.py` `_compose_screen_flow`, `_compose_screen_flow_execution`; `styles.tcss` `#flow_pipeline`). `02-test-cases.md` is not edited; the marks below are this audit's proposal for it.

## 1. Verdict

**PASS-WITH-NOTES.** No HIGH or MAJOR finding. Three MINOR findings and six NITs (§8).

- **Coverage: 4 `full`, 0 `partial`, 0 `gap`. Marks changed: 0 of 4.** All 4 nodes the cases name exist, each drives a shipped route and asserts its case's values. Two caveats stay `full` with a finding: the walks collect over the panel, not the window the row names (QA-1), and AT-I12b-1's ribbon clause is weaker than its case, pre-ruled at I-D6 and carried by other nodes (QA-6).
- **Row thresholds: 2 of 2 met on Linux** on the commit's tree (int-08): Flow Builder 0 never shown over 49 ids (≥ 45), Flow Execution 0 over 35 (≥ 30).
- **The walks are sound.** The population is pinned, the size is asserted first, every state is driven by the product's controls, and leaving a state out can only add never-shown ids, never hide them. Both walks were RED on base for the row's own reason: exactly the five hidden Flow Builder ids, and `fx_help` (size clause passed first). On the integrated tree they find 0 never shown (§4).
- **The 39 re-pointed nodes: 39 exist, 39 executed and passed** (base `-v`; integrated by file totals on trees whose blobs equal the commit's, §2). 32 carry no finding: 23 the same, 7 stronger, 1 equivalent (TC-356), and 1 narrower and accepted (TC-B100-31, the path tail the ribbon paints). Each reads a visible surface. 7 carry a finding:
  - weaker than on base:
    - AT-B94-15 and TC-B94-20: the width clause is self-referential (QA-3);
    - AT-088b: the span clause pins no style (QA-5);
    - AT-006 report: `REPORT` is also painted by the card's fallback (QA-9);
  - latent: AT-B94-18 reads the hostile payload anywhere in the pipeline (QA-2);
  - over-claiming docstrings: TC-B97-13 and TC-B97-49 (QA-4).
- **Dropped clauses: accepted.** The hidden-is-hidden asserts are carried by the walks for a widget restored **hidden** (proven RED on base). A widget restored **displayed** has no standing guard (QA-4, residual accepted). The canvas glyph checks left with the canvas by design, and each has a pipeline equivalent, except the width bound (QA-3).
- **Negative controls:** executed on the commit's tree: M1 (R-FB-ADD.1/2 RED), M2 and M3 (the 4 markup nodes RED). The rest are `not-run` and owed by the E5 mutants pass: M4 on this tree, M5 one widget at a time, M6, M7 (§7).
- **Windows: the 4 cases executed and passed (win-01, head `092fffd9`, `-v`, `95 passed`, each node named).** win-01 landed during this audit; this audit did not run it. It also ran the whole of `test_b100_project_homes.py`, the one int-01 file holding all 29 Windows-only skips. Of the 14 int-01 files, only it imports `tests/support/b100_links.py`, the module whose `require_junctions` skips off Windows. Those arms and TC-B100-31 passed, and so did I-D7's backslash arm, inside AT-I12b-1. The other 38 re-pointed nodes have no Windows-only skip and were `not-run` on Windows. Three of them, the Inc 9 file, take a real junction on Windows instead of a symlink (`b97_fixtures.make_junction`). 12b's change there is one wait in a helper, which does not touch that path.

## 2. Evidence checks made by this audit

- **The run trees are the commit's.** I recomputed them with git plumbing only (a scratch index and object directory, the repository's objects as alternates, nothing written to the worktree, no `s19_app` import): base `2f54c7d` + `git diff --binary 2f54c7d 092fffd -- s19_app tests docs README.md` = **`29cc1952…`**, the tree of int-07b and int-08. Swapping back single files to their `d915342` (or base) blobs gives exactly the earlier trees:
  - `test_flow_builder_render.py` at `d915342` → **`e7f05497…`** (int-06, int-07);
  - plus `test_b101_flow_shown_widgets.py` at `d915342` → **`e0ec6b20…`** (int-01 … int-05);
  - plus `test_id_registry.py` at base → **`94891ee2…`** (int-00).

  So int-01 ran the commit's product and the commit's blobs of 12 of the 13 re-pointed files. The two files edited at integration (I-D5, I-D7) re-ran on the commit's tree in int-08.
- **Per-node results.** base-01 (G-T3) is `-v`: 54 items (the 39 nodes with their parameters), each `PASSED` by node id on base `2f54c7d`. int-01 and int-08 are `-q`: `491 passed, 29 skipped` and `233 passed`, no failure, no deselection. The 29 skips name their reasons: junctions, trailing-dot names, reserved device names, a case-insensitive volume, `con.json`. They sit at lines of `b100_links.py` and `test_b100_project_homes.py` that none of the 54 items reaches (all 54 ran unskipped in base-01 on the same host). The integrated per-node GREEN is therefore inferred from the totals, not printed (QA-8).
- **Base RED (red-01, G-T4).** `3 failed, 1 passed`:
  - the Builder walk failed at `never == []` with `['flow_blocks', 'flow_canvas', 'flow_ext_session', 'flow_help', 'flow_kind']`, its size clause on the line before having passed;
  - the Execution walk failed with `['fx_help']`;
  - R-FB-ADD.1/2 failed by `InvalidSelectValueError: Illegal select value 'bogus'`;
  - AT-I12b-1 passed (a standing guard).

  The transcript prints base `2f54c7de` and an `s19_app.__file__` in the tester's worktree.
- **I-3 pinned commands, re-run here on `092fffd`** (`git grep <rev>`, no checkout): command (1) over `s19_app tests`, (2a) and (2b): no line, exit 1 each. This matches int-00.
- **Population root.** The walk collects `panel.query("*")` with the panel included (`test_b101_flow_shown_widgets.py:85-92`). The E1 pilot did the same, `root.query("*")` on `#flow_panel` / `#fx_panel` (`i12e1-pilot.py:43-48`), so the row's counts 48 and 34 are the panels' (QA-1).
- **trace_check** (`python -I …/dev-flow-v3-beta/trace_check.py --req …/inc-12b/01-requirements.md --base 2f54c7d --src s19_app`; it reads text and git only): `1 US, 2 active requirements (0 withdrawn), 1 gap(s)`. The gap is `EVID` (no `04-validation.md`), which is expected before the validation record.
- **win-01** (`../evidence/inc-12b/win-01.txt`). It appeared during this audit, which did not run it, and the transcript does not name its executor (the E5 start line of `steps.log` assigns the Windows arms to the orchestrator). What it prints:
  - the Windows PC, head `092fffd9`, an `s19_app.__file__` in this worktree;
  - `LOCALAPPDATA` isolated, the OS clipboard unused;
  - its command (`-p no:xdist -v -rfEs` over `test_b100_project_homes.py` and `test_b101_flow_shown_widgets.py`);
  - Python 3.11.15, `collected 95 items`, one `PASSED` line per node id, and `95 passed`.

  It prints no tree hash. `git status -- s19_app tests` is empty here, so the files it ran are the commit's.
- **The code review landed during this audit** (`E5-review.md`; I read it after writing §3–§6). Its R-1, R-2 and R-3 reach QA-3, QA-2 and QA-5 independently. Its R-4 is a point I had missed. I checked it against `flow_screens.py:847` and adopted it as QA-9. Its R-5, product comments that still name the removed surfaces, belongs to the code review and is not repeated here.
- **Executors.** int-00 … int-08 and int-base-01: the E4 integrator (Opus) on LAN Linux host 2. red-01: tester G-T4 (Sonnet). base-01 and base-01-mutants: tester G-T3 (Sonnet). win-01: not named (above). This audit executed none of them.

## 3. Per case

Node names drop the `test_` prefix. "Std guard" means the node passes on base.

| # | Case | Node | Stimulus route ok | Oracle exact | Evidence | Verdict |
|---|---|---|---|---|---|---|
| 1 | R-TUI-059.25/1 | `r_tui_059_25_1_every_flow_builder_widget_is_shown_in_a_state` | yes: `action_show_screen("flow")` (the case's precondition); the 7 chips by `press()`, each waited on its painted tag **and** its `chip-selected` mark; Variables open and closed; LOAD + empty `#flow_ref` + `+ Add`, waited on the painted `Add needs`; 3 × (`#flow_ref` by value, as the case's Inputs, + `+ Add`), waited on the frame title `chain · n block(s)`, then 3 painted `◉ LOAD` | yes: the size (≥ 45) first, then `never == []`. The population is the panel's, not the window's (QA-1); the walk keys on ids (QA-7) | red-01 (base: the five ids, exactly); int-01; int-06 (49 ids, `[]`); **int-08** (commit tree); win-01 | full · executed, passed (linux, int-08; windows, win-01); M5 not-run |
| 2 | R-FX-SCR.4/1 | `r_fx_scr_4_1_every_flow_execution_widget_is_shown_in_a_state` | yes: `action_show_screen("flow_execution")`; Import… + picker + OK (`import_flow`, the shipped controls; the case names `import_lanes`, which calls it); `#fx_run` press, waited until `#fx_required` is displayed; `#fx_set_name` = `s` by value, Save Set, waited on `flowsets/s.json` and a displayed `#fx_notice` | yes: ≥ 30 first, then `[]` (the same QA-1 / QA-7 caveats) | red-01 (`['fx_help']`); int-01; int-06 (35, `[]`); int-08; win-01 | full · executed, passed (linux, int-08; windows, win-01); M6 not-run |
| 3 | R-FB-ADD.1/2 | `r_fb_add_1_2_a_press_naming_no_kind_changes_nothing` | yes: the CHECK chip pressed; `Button(id="flow_palette_bogus")` mounted into `#flow_palette` and pressed; a spy on `on_button_pressed` proves delivery (precondition only); ref by value; `+ Add` | yes, and stronger than the case: tag `✓ CHECK`; the marked set before == `[flow_palette_check]` == after; the shown set unchanged; gating shown; notice hidden; then title `chain · 1 block` and exactly one `✓ CHECK` in the painted pipeline. "No exception" holds through `run_test`, which re-raises (base RED proves it) | red-01 (base RED by the select's exception, not the case's mechanism); **int-07b M1**: RED at the tag (`· BOGUS`), the other 3 GREEN; int-08; win-01 | full · executed, passed (linux, int-08; windows, win-01); control executed (int-07b) |
| 4 | AT-I12b-1 | `at_i12b_1_kind_chip_add_and_ribbon_by_keys` | yes, keys only: `8`; `tab` (≤ 150) to the CHECK chip; `space`; `tab` to `#flow_ref`; typed characters; `tab` to `+ Add`; `enter` | tag, gating shown, one CHECK card: yes. Ribbon: `session` plus a ≥ 8-character **substring** of the project path. The case says "the project folder's **tail**" (QA-6; pre-ruled I-D6; the tail rule is carried by TC-B97-37 at 118×54 and TC-B97-49[project]) | red-01 (std guard, as the case says); int-06 (ribbon `…/workarea/proj1`); **int-08** (after I-D7); win-01 (I-D7's backslash arm) | full · executed, passed (linux, int-08; windows, win-01); M7 not-run |

## 4. The walks (R-TUI-059.25, R-FX-SCR.4)

- **Population pinned.** It is the union, over the walked states, of the ids mounted under the panel. The node asserts its size before the never-shown clause (`:190-191`, `:246-247`), so a walk over a wrong or empty root fails. A state left out cannot pass vacuously: the widgets it would show stay mounted, stay in the population, and turn up never shown. The only way to shrink the population is to change the root, which the floor guards.
- **Shown predicate.** `is_displayed` (`b97_probes.py:123-130`) requires `display` on the widget and on every ancestor up to the screen, so `#screen_flow` hidden means nothing is shown. This matches CTX-SHELL's "displayed … up to its window". It does not read `visibility` or the region's size (QA-7).
- **RED on base for the right reason.** The size clause passed (red-01 line 70 is reached; the failure is line 71). The never-shown set is exactly the row's negative control: the five ids, and `fx_help`. The detection is per id, so restoring any single one of them (M5, M6) must leave that id never shown; the per-widget runs remain E5's.
- **0 never shown on the integrated tree.** int-06 prints both populations in full: 49 = the graph's 48 + Textual's `label`, and 35 = 34 + `label`. int-08 passes both nodes on the commit's tree.
- **Root (QA-1).** The window `#screen_flow` (`app.py:3780-3790`; `#screen_flow_execution` at `:3835-3845`) holds a header with `#window_help_flow` and `#open_folder_flows` beside the panel, and `#screen_flow_execution` holds `#window_help_flow_execution` and `#open_folder_session`. The six ids (with the two sections) are outside both populations. They are displayed whenever their window is, so no defect hides behind this today.

## 5. The 39 re-pointed nodes

"Same" means the node's own assertions are unchanged and only the driver or the read target moved to a visible surface. Every node `PASSED` in base-01 and in its integrated run (int-01; int-08 for `test_flow_builder_render.py`).

| File (nodes) | Node | Before → now | Oracle vs base |
|---|---|---|---|
| `test_b97_flow_builder.py` (13) | TC-B97-13 | list and canvas `not shown` asserted → dropped (ruling); cards, cables, kind order, empty line kept | ruled drop; docstring still states it (QA-4) |
| | TC-B97-14 | kind select == kind → `selected_kinds(panel) == [kind]` | stronger (only that chip) |
| | TC-B97-15, -17, -58 ×2, -51 space, -49 ribbon, AT-B97-07 | `choose_kind` waits on the chip mark, not the select | same |
| | TC-B97-49 session [2] | `#flow_ext_session` not shown → dropped (ruling); ribbon tail kept | ruled drop; docstring over-claims (QA-4) |
| | TC-B97-51 keyboard | `enter`/`space` set the select → set the chip mark | stronger (exactly one mark) |
| | TC-B97-62 NUL [9] | the select assigned (white-box) → chip clicked | stronger driver; oracle same; M4 RED on base (G-T3), not-run on this tree |
| | AT-B97-08 | via `choose_kind` | same. The card check `clip_tail(payload, inner)` (`…` at the head) cannot be met by the annotation, which clips the head (`flow_screens.py:821`). M2, M3 RED (int-07b) |
| `test_tui_flow_builder_b94.py` (5) | AT-B94-15 | canvas glyphs, `len ≤ 88`, canvas width → cards `╭╮╰╯`, `in · `/`out`, 3 cards / 2 cables, `len ≤ chain_width`, rail ≤ 96 | counts stronger; width clause vacuous (QA-3); stubs, bends, dots gone by design |
| | AT-B94-16 | `#2.out` on the canvas → on the pipeline | same |
| | AT-B94-17 | helper now presses the chip and waits | same |
| | AT-B94-18 | canvas text → pipeline: whole scrubbed payload, sentinel, `_evil[red]`, 0 control bytes, + span clause | stronger than base (base had no span clause); anchored on the whole pipeline (QA-2); no style pin (QA-5); M2, M3 RED |
| | TC-B94-20 | one canvas → one `#flow_pipeline`; cards and cables; widths as AT-15 | same counts; width clause vacuous (QA-3) |
| `test_flow_builder_render.py` (3) | AT-088b | `#flow_blocks` + `spans == []` → the CHECK card's `in · doc` value row (I-D5) + no cutting span and one exact span | weaker on the style axis (QA-5), stronger on the anchor; M2, M3 RED |
| | AT-088 gating | the select → the CHECK chip | same |
| | `flow_block_label_covers_check` | `_flow_block_label(...)` prefix → `pipeline_text` card head + ref | stronger (the ref too); a unit, as on base |
| `test_tui_flow_persistence_ui.py` (3) | AT-006 report | `#flow_blocks` text (`_flow_block_label`'s REPORT arm; fallback `?`) → `#flow_pipeline` text | weaker: the card title falls back to `kind.upper()` (`flow_screens.py:847`), so `REPORT` paints with or without the REPORT entry (QA-9) |
| | AT-006 quarantine, AT-005 | `#flow_blocks` text → `#flow_pipeline` text (before / after equality) | same |
| `test_b101_flow_names_ui.py` (3) | FLOW-FILE.12/1, FB-SAVE.8/1, AT-I9-3 | `_add_load_block` waits on the LOAD chip mark | same |
| `test_b97_chips_help.py` (2) | TC-B97-32, AT-B97-14 [4] | the wait moves to the chip mark | same |
| `test_flow_crc_ribbon.py` (2) | TC-358 | `(no blocks yet)` in the list → `No blocks yet` in the pipeline | same |
| | TC-361 | the select → SOURCE, CRC, CHECK chips; `#flow_gating` display False/False/True | same |
| `test_flow_crc_ui.py` (2) | AT-128 | `.update(_blocks_text())` → `_refresh_blocks()`; reads the pipeline | same (white-box setup, as on base) |
| | TC-356 | `== "CRC  crc.json"` → `⊕ CRC` head, `in · tpl`, `crc.json` in the card | equivalent: the one-line label is gone; a unit, as on base |
| `test_tui_directionb.py` (2) | add blocks and run | `#flow_blocks` → pipeline, + the heads in block order | stronger |
| | markup safe | list containment → the `in · file` value row + span clause | stronger; no style pin (QA-5); M2, M3 RED |
| `test_b100_project_homes.py` (1) | TC-B100-31 | `str(W/Q)` in the session line → the ribbon `endswith("workarea/Q")`, not `…/P` | narrower: the tail, which is what the ribbon paints; accepted |
| `test_b102_flow_file_chooser.py` (1) | TC-B102-FILE-02 | the select = A2B → the A2B chip, waited on `#flow_ref_a` shown | same |
| `test_flow_external_step_b96.py` (1) | TC-1804 | the select; `session: ` line; canvas `TERMINAL` → the chip; ribbon `session` + `proj`; card `terminal · human` | stronger on the session; "rides the kind select" gone by design; the module docstring is stale (QA-4) |
| `test_flow_funnel_b96.py` (1) | TC-1817 | `.value = "source"` → the LOAD chip, waited | same |

**Totals: 39 nodes.**

- **No finding: 32.** 23 the same, 7 stronger (TC-B97-14, TC-B97-51 keyboard, TC-B97-62, `flow_block_label_covers_check`, both directionb nodes, TC-1804), TC-356 equivalent, TC-B100-31 narrower and accepted.
- **Ruled drops: 2** (TC-B97-13, TC-B97-49). Their docstrings over-claim (QA-4).
- **Weaker on one clause: 4** (AT-B94-15, TC-B94-20: QA-3; AT-088b: QA-5; AT-006 report: QA-9).
- **Latent: 1** (AT-B94-18, QA-2).
- **No node reads a removed widget.** The I-3 grep is empty on the commit.

## 6. Dropped clauses: rulings

- **"Hidden widget stays hidden": accepted (E3 ruling, `E1-slice.md` §5).** The clauses are TC-B97-13 (list and canvas), TC-B97-49 (session line) and TC-1804 ("stays mounted, hidden"). The walks are RED for any of the six ids restored **hidden** (red-01). They cannot see one restored **displayed**: a second chain view beside the pipeline, or a session line beside the ribbon. That was the other half of what `not shown(#flow_blocks)` caught on base. No standing node now guards it, since the I-3 grep is a one-off integration check. The removal is by design and no defect is in view, so the residual is accepted; the docstrings must stop claiming it (QA-4).
- **Canvas glyph checks: gone with the canvas, by design.** AT-B94-15 and TC-B94-20 lost stubs `┤├`, bends `┌┐└┘` and grid dots `·`, each under a named supersession comment. Their pipeline equivalents are present: cards, `in · ` / `out` rows, cables `▶`, and exact counts. The one clause that did not move faithfully is the width bound (QA-3). The base's real width bound, `len ≤ 88`, measured the hidden canvas, a painter the operator never saw.
- **`_flow_block_label` unit nodes: rewritten, not removed.** `flow_block_label_covers_check` and TC-356 read `pipeline_text` cards. Neither carried a hostile input. The hostile CHECK ref is AT-088b's, as the G-T3 record names.
- **Security nodes (E3 S-2, S2-2).** All five keep their hostile input whole, with every kind they carried (G-T3's table, checked against the diff). They also keep their painted-text assertion: the NUL nodes keep `FLOW-UNSAFE-REF`, the unchanged chain and Run without `ValueError`. The four markup nodes are RED under M2 and M3 on the commit's tree (int-07b). S-2 holds. QA-2 and QA-5 tighten two of them.

## 7. Negative controls and Windows

| # | Control | Expected RED | State |
|---|---|---|---|
| M1 | S-1 guard removed | R-FB-ADD.1/2 | executed (int-07b, integrator): RED at the tag, 3 GREEN |
| M2 | card refs through `Text.from_markup` (scrub kept) | AT-088b, AT-B94-18, AT-B97-08, directionb markup | executed (int-07b): 4 RED. AT-B94-18 is RED only because the annotation clips the payload (QA-2) |
| M3 | a span over half the value row | the same 4 | executed (int-07b): 4 RED (AT-B97-08 at `_foreign`) |
| M4 | `nul_add_refusal` → `None` | TC-B97-62 [9], AT-B97-08 | executed on **base** only (G-T3): 10 RED; **not-run** on this tree |
| M5 | one of the five widgets restored, hidden at mount | the Builder walk | base RED covers all five at once; **not-run** one by one |
| M6 | `#fx_help` restored, hidden | the Execution walk | base RED; **not-run** on this tree |
| M7 | `flow_add` reads `BLOCK_SOURCE` | AT-I12b-1, R-FB-ADD.1/2, the Add nodes of other kinds | **not-run** |
| QA-3 | card width + 8 | AT-B94-15, TC-B94-20 (after the fix) | planned |
| QA-2 | annotation unclipped | AT-B94-18 (after the fix) | planned |

Windows (win-01, executor not named in the transcript; this audit did not run it): **executed, passed**:
- the 4 cases, I-D7's backslash arm included;
- the whole of `test_b100_project_homes.py`, which holds TC-B100-31 and all 29 Windows-only skips of int-01 (I-D14): `95 passed`, each node named.

The other 38 re-pointed nodes are **not-run** on Windows. They carry no Windows-only skip, so no rule requires that run (§1).

## 8. Findings

| Id | Severity | Finding | Fix |
|---|---|---|---|
| QA-1 | MINOR | **The walks collect over the panel; the rows and the case say the window.** R-TUI-059.25 / R-FX-SCR.4 pin "the union of the ids mounted **in the window**". The State walk fixture says "the window's widgets", and CTX-SHELL defines *shown* "up to its window". The node (`:85-92`) and the E1 pilot (`i12e1-pilot.py:43-48`) both root at `#flow_panel` / `#fx_panel`, so `screen_flow`, `window_help_flow` and `open_folder_flows` (and the three Flow Execution equivalents) are in no population. They are always displayed with their window, so nothing hides today. A hidden widget added to a window header would pass both walks | Choose one and write it once. (a) Collect over `app.query_one("#screen_flow")` / `#screen_flow_execution`, keeping `panel` for driving. Re-measure (expected 52 / 38, still 0 never shown) and update "48 / 34 after the change" in the rows. (b) Change the rows' and the fixture's "window" to "the window's panel" and keep the numbers. (a) matches the definition |
| QA-2 | MINOR | **AT-B94-18 reads the hostile payload anywhere in the pipeline: the defect I-D5 fixed in AT-088b.** `canvas.index(scrubbed)` and the `_SENTINEL` / `_evil[red]` checks run over the whole pipeline (`test_tui_flow_builder_b94.py:425-434`). The origin note `missing: <ref>` paints the ref again through its own sink, head-clipped, under one exact span (`flow_screens.py:820-823`). At 120×30 it clips this 34-cell payload, so M2 is RED today **only by that clip** (int-07b fails at `_evil[red]`). An A2B card ≥ 12 cells wider, or a shorter prefix, puts the whole payload in the note; `index` then lands there and the span clause holds → GREEN under M2 | Anchor as I-D5 did: take the row after `in · B` on the A2B card. Assert the payload, the sentinel and `_evil[red]` in that row, and compute the span window from that row's offset. Show it RED under M2 with the annotation unclipped (a control that widens `_card_annotation`'s `width`) |
| QA-3 | MINOR | **The width clause of AT-B94-15 and TC-B94-20 cannot fail.** `#flow_pipeline` is `width: auto` (`styles.tcss:3314-3317`), so `chain_width` is the longest line's width and `all(len(line) <= chain_width)` holds by construction. `rail_width <= 96` holds whenever the rail fills its parent. The base bound (`len ≤ 88`) was real, if on the hidden canvas. These nodes' "inside the boxed budget" at 120×30 now has no failing oracle. TC-B97-38 checks the fill only at ≥ 160 columns | Bound the lines by the rail's `scrollable_content_region.width` (what `_apply_layout` fits the cards to, `flow_screens.py:1674`). Show it RED under a card-width + 8 mutant. **Measure first.** G-T3 reports a rail of 94 and a pipeline of 92; if 94 is the region, the content width is 94 − 2 border − 2 padding = 90 < 92, which would mean 3 cards already scroll at 120×30. That would be a product question (same on base), not a test defect |
| QA-4 | NIT | **The dropped hidden-is-hidden clauses: the docstrings claim more than the nodes check, and one residual is unguarded** (§6). TC-B97-13's first sentence still says "the numbered list and the grid canvas are not displayed" (`test_b97_flow_builder.py:525-526`). TC-B97-13 and TC-B97-49 say their absence "is guarded by the walks", but the walks guard a **hidden** restore only. `test_flow_external_step_b96.py:11-12` still says the builder exposes the kind on "the kind select" | Rewrite TC-B97-13's docstring to the checks it makes, and word both as "a hidden copy restored is caught by the walks R-TUI-059.25/1". Fix the b96 module docstring. Record the displayed-restore residual as accepted; add no clause without a real defect |
| QA-5 | NIT | **The span clause pins one exact span but not its style.** AT-088b, AT-B94-18 and the directionb markup node assert `cutting == [] and len(exact) == 1`. I-D4 says the clause "pins the one covering span to the card's value style", but no node compares `exact[0].style`. A sink that replaced the value style with a style taken from the input, over exactly the ref, would pass all three. Only AT-B97-08's `_foreign` allow-list would catch a foreign colour. In int-07b the value style shows as `Style(foreground=Color(233, 233, 233))` | Add `assert exact[0].style == value_style`, reading `value_style` from a benign card in the same run (or reuse AT-B97-08's `_foreign`). Correct I-D4's sentence |
| QA-6 | NIT | **AT-I12b-1's ribbon oracle is weaker than its case, and is kept `full`.** It requires a ≥ 8-character substring of the path. The case requires "the project folder's tail". The session one folder up (`…/.s19tool/workarea`), or the path's head, would pass. Pre-ruled (I-D6). Other nodes carry the property: TC-B97-37 asserts at 118×54 (and five more sizes) that the painted ribbon ends with the project folder's name, TC-B97-49[project] the last segment, and TC-B100-31 the right folder | When the file is next touched: `assert ribbon.rstrip().endswith(project_dir.name)` (int-06 paints `proj1` whole; TC-B97-37 already holds it at 118×54). G-T4's end clip came from a hand mutant with extra widgets displayed. If it ever shows on the shipped tree, it breaks the ribbon's tail contract and TC-B97-37 would fail too |
| QA-7 | NIT | **Walk limits.** <ul><li>The walk keys on ids. Textual's internal `label` (one per `Select`) collapses into one entry, so a never-shown internal could hide behind a shown one (I-D9).</li><li>Nothing asserts that the product's ids are unique.</li><li>`is_displayed` reads `display` only: a widget hidden by `visibility: hidden`, or of size 0, counts as shown. That is CTX-SHELL's wording ("displayed"), but the fixture does not say so</li></ul> | Key the population on widget identity (`{id(w): w.id}`), or assert per state that the product's ids are unique, excluding widgets whose class lives in `textual.*`. State in the State walk fixture that *shown* means `display` up to the window, not visibility or size |
| QA-8 | NIT | **Record hygiene.** <ul><li>`02-test-cases.md` line 3 still says "Coverage is `gap` … Result is `not_run` everywhere".</li><li>The Result cells name no executor (E4 integrator, Opus, LAN Linux host 2; red-01 G-T4; base-01 G-T3), and they still read `windows: not_run (E5)` although win-01 passed all 4.</li><li>win-01 names no executor and prints no tree hash.</li><li>The integrated per-node GREEN of the 39 is inferred from the `-q` totals (§2).</li><li>int-07's header calls `e7f05497…` "the final integrated tree"; I-D5 superseded it (int-07b is the final)</li></ul> | <ul><li>Update line 3 to "Written before any test; E4 filled Coverage and Result".</li><li>Name the executor in each Result cell, and re-cite Windows as `windows: verified (win-01)` on the 4 cases.</li><li>Add the executor and the tree to win-01.</li><li>Run E5's own gate run with `-rA` (or `-v`), so each node prints its own line.</li><li>Note in int-07 that it predates I-D5</li></ul> |
| QA-9 | NIT | **AT-006's `"REPORT"` no longer tells the REPORT entry from the fallback.** The base node read `_flow_block_label`'s REPORT arm, whose fallback was `?`. The module docstring keeps that purpose: "the pipeline card's REPORT arm is non-vacuous" (`test_tui_flow_persistence_ui.py:19-20`). The card title is `_KIND_LOOK.get(kind, ("·", kind.upper(), …))` (`flow_screens.py:847`), so a report block paints `REPORT` with the entry and without it. The node still fails if the report block drops out of the loaded chain. Found by the code review (`E5-review.md` R-4); verified here against the code | `assert "≡ REPORT" in blocks_text`, the glyph of `_KIND_LOOK[BLOCK_REPORT]` (`flow_screens.py:557`). Show it RED with the entry removed |

## 9. Not run by this audit

No test was run, and nothing that imports `s19_app` ran on the Windows PC. The only commands were:

- file reads and greps;
- git plumbing in a scratch index and a scratch object directory (`…/scratchpad/i12be5`, this session's own folder, left in place), for the tree recomputation (§2);
- `git grep` of the three I-3 commands against `092fffd`;
- `trace_check.py` under `python -I`, which reads text and git only.

The results above are:

- the E4 runs on LAN Linux host 2 (int-00 … int-08, int-base-01);
- the testers' base runs (red-01, base-01, base-01-mutants);
- win-01 and `E5-review.md`, both of which appeared during this audit;
- the records.

None of them was executed by this audit. Early in the audit, `i12b-e5-mut.md` sat untracked and empty at the worktree root (another E5 agent's file); I did not touch it, and it had gone by the end.

## 10. Totals

| | Before | After |
|---|---|---|
| Active cases | 4 | 4 |
| Coverage `full` / `partial` / `gap` | 4 / 0 / 0 | 4 / 0 / 0 (marks changed: 0) |
| Row thresholds met (Linux, commit tree) | 2 claimed | 2 of 2 (int-08; populations 49 / 35, 0 never shown) |
| Result (linux) | `verified` ×4, citing int-01 / int-08 | executed and passed ×4 on the commit's tree (int-08, recomputed `29cc1952…`) |
| Windows | not_run ×4 | executed and passed ×4 (win-01), with TC-B100-31 and int-01's 29 Windows-only arms; 38 re-pointed nodes not-run (no Windows-only arm) |
| Re-pointed nodes | 39 | 39 exist and passed. 32 with no finding; 2 ruled drops (QA-4); 4 weaker on one clause (QA-3 ×2, QA-5, QA-9); 1 latent (QA-2) |
| Negative controls | M1–M3 executed; M4 on base | M4 (this tree), M5 per widget, M6, M7 not-run; QA-2 and QA-3 controls planned |
| Cases or nodes to add | — | none. QA-2, QA-3, QA-5 and QA-9 tighten existing nodes; QA-1 re-roots two walks or amends two rows |
