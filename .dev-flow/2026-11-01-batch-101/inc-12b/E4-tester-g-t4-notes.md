# Inc 12b E4 tester G-T4 - notes

Node file: `tests/test_b101_flow_shown_widgets.py` (4 nodes, all cases of the group). RED run: base `2f54c7de` (origin/main with Inc 9), LAN Linux host, detached worktree with only the test file copied in, `s19_app.__file__` resolved inside the worktree; transcript `.dev-flow/2026-11-01-batch-101/evidence/inc-12b/red-01-g-t4-base.txt` (one complete run: **3 failed, 1 passed**, 32 s). State: `executed` on base; GREEN on the integrated tree `not-run` (DeepSeek was still editing).

## How the nodes read and drive

- App at 118x54 on `fx_project` (opened through the app's own load); `_drive` runs one `asyncio.run` per node. No fixed sleeps: every step waits through `settled` for its own sign. No OS clipboard.
- The walks (`_Walk`) collect after each driven state the ids of `panel.query("*")` (panel included) and the shown subset (`is_displayed`); population = union over states; the node asserts the size first (Builder >= 45, Execution >= 30), then `never shown == []`, the message listing the ids. States are driven by `press()` on the chips, Variables toggle (open then closed), LOAD + empty ref + `+ Add` (waits for the painted `Add needs` notice), 3 x (`#flow_ref` value + `+ Add`, waits for the frame title `chain . n blocks`); Execution: `open_flow_execution`, `import_flow flash_chain`, `#fx_run` press until `#fx_required` is shown, `#fx_set_name` = `s`, `#fx_save` until `flowsets/s.json` exists and `#fx_notice` is shown.
- R-FB-ADD.1/2 mounts `Button(id="flow_palette_bogus")` into `#flow_palette` and presses it; a spy on `FlowBuilderPanel.on_button_pressed` (a precondition guard only, wraps the original) proves the press reached the panel. It then compares the painted kind tag, the `chip-selected` set, the shown-id set, `#flow_gating` and the notice before/after, then types `baseline.chk.json`, Add, and reads one CHECK card in the painted pipeline, no notice.
- AT-I12b-1: keys only (`8`, bounded `tab` up to 150 to the CHECK chip, `space`, typed characters, `tab` to `#flow_ref` and to `+ Add`, `enter`); reads the painted tag, gating shown, one CHECK card, and the painted ribbon.
- Removed ids and members are never spelled in the file (I-3 grep on the file: empty); RED reasons are quoted in the transcript instead.

## Cases -> nodes, RED on base

| Case | Node | Base result and reason |
|---|---|---|
| R-TUI-059.25/1 | `test_r_tui_059_25_1_every_flow_builder_widget_is_shown_in_a_state` | RED: size assertion passed, `never shown` = the five hidden widgets (help sentence, canvas, numbered list, kind dropdown, session line; ids in the transcript) |
| R-FX-SCR.4/1 | `test_r_fx_scr_4_1_every_flow_execution_widget_is_shown_in_a_state` | RED: `never shown` = the one help sentence of Flow Execution |
| R-FB-ADD.1/2 | `test_r_fb_add_1_2_a_press_naming_no_kind_changes_nothing` | RED: `InvalidSelectValueError: Illegal select value 'bogus'` from the hidden select at the stray press (the R-note of the case, now run) |
| AT-I12b-1 | `test_at_i12b_1_kind_chip_add_and_ribbon_by_keys` | passes on base (standing guard, as the case says "holds on base") |

GREEN-ability check (not a GREEN claim): in the remote scratch worktree only, a hand mutant of `flow_screens.py` (the hide loop and the Flow Execution help hide removed; chip branch guarded with `_KIND_OPTIONS`) gave 4 passed with the final file; the mutant was reverted and the worktree removed. So the walks can reach 0 never shown with the sizes asserted, and the S-1 node accepts a guarded handler.

## Standing guards (pass on base) and why each still has a failure mode

- AT-I12b-1: fails if a chip no longer chooses its kind by `space`, if the gating control stays hidden for CHECK, if Add does not paint exactly one CHECK card (e.g. the kind is lost after the removal of the dropdown, or the S-1 guard rejects valid kinds), if a tab path never reaches the chip, the image field or Add, or if the ribbon loses `session` or its path stretch. It cannot prove the removed widgets gone (the walks do).
- The S-1 negative control "suffix stored unchecked" cannot be shown RED here (needs the new `_kind` holder): base is RED for the other reason (above). It is the E5 mutant of the case; the node's later assertions (one CHECK card, no notice) are what that mutant breaks.

## Findings for the integrator

1. `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` fails with my file present: `270 test modules, not the declared 269` (observed on base + my file; the other 146 nodes of address census, suite hygiene, id registry, doc hygiene pass). The graph already says "`tests/test_id_registry.py`: +1 here": bump `EXPECTED_SCANNED_TEST_FILES` by one (a test edit, not mine; with Inc 12's +2 the merge order decides the final number).
2. AT-I12b-1 asserts the ribbon by "what follows `session` is a stretch (>= 8 chars) of the project folder's path", not by the folder name: the painted ribbon clips the end of the path by cells (seen with extra widgets shown in the hand mutant: `...workarea/pr...`), so a name check would flap. Case wording "the project folder's tail" is satisfied by the path tail; if the reviewer wants the folder name itself, the ribbon width needs a ruling.
3. Test names are the proposed ones; no change.
