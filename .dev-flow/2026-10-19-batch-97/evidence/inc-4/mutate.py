"""Inc-4 mutation battery (the Inc-3 runner, one edit per mutant).

One edit per mutant, one node per run, restore proven by SHA-256 after every arm.
Anchors are written with ``\\n`` and matched in the file's own line endings.
Run from the repo root: python .dev-flow/2026-10-19-batch-97/evidence/inc-4/mutate.py [M1 M2 ...]
Gate fold (2026-10-21): M40-M48 appended (M39 is the first-run retarget of M34).
"""
import hashlib
import os
import pathlib
import subprocess
import sys

SDB = pathlib.Path("s19_app/tui/screens_directionb.py")
APP = pathlib.Path("s19_app/tui/app.py")
CSS = pathlib.Path("s19_app/tui/styles.tcss")
WH = pathlib.Path("s19_app/tui/window_help.py")
TCH = pathlib.Path("tests/test_b97_chips_help.py")
P = "tests/test_b97_patch_editor.py::"
W = "tests/test_b97_width.py::"
H = "tests/test_b97_chips_help.py::"

MUTANTS = [
    ("M1-drop-a-shipped-id", SDB, 'with Horizontal(id="patch_doc_file_line2"):',
     'with Horizontal(id="patch_doc_file_lineB"):',
     [P + "test_tc_b97_01_shipped_ids_and_container_types[size0]"]),
    ("M2-ledger-3-rows", CSS, "#patch_editor_panel #patch_doc_entries_table {\n    height: 1fr;",
     "#patch_editor_panel #patch_doc_entries_table {\n    height: 3;",
     [P + "test_tc_b97_02_ledger_grows_with_the_panel[size0]",
      P + "test_at_b97_01_load_shows_every_entry_and_the_document"]),
    ("M3-unscoped-docked-rule", CSS, "#patch_editor_panel #patch_doc_tally {",
     ".patch-docked-row { padding: 0; }\n\n#patch_editor_panel #patch_doc_tally {",
     [P + "test_tc_b97_04_patch_rules_scoped_and_check_rule_untouched"]),
    ("M4-e3-grid-back", CSS, "#patch_editor_panel #patch_doc_file_line1 {",
     "#patch_editor_panel #patch_doc_controls { layout: grid; }\n\n#patch_editor_panel #patch_doc_file_line1 {",
     [P + "test_tc_b97_04_e3_pairs_absent"]),
    ("M5-no-json-cap", SDB, 'cap_json_lines(document.json_text.rstrip("\\n"))',
     'document.json_text.rstrip("\\n")',
     [P + "test_tc_b97_05_cap_note_and_display_only"]),
    ("M6-parse-reads-the-view", SDB,
     '                    action="parse_paste",\n                    paste_text=self.query_one(\n                        "#patch_paste_text", TextArea',
     '                    action="parse_paste",\n                    paste_text=self.query_one(\n                        "#patch_json_view", TextArea',
     [P + "test_tc_b97_05_cap_note_and_display_only"]),
    ("M7-undo-site-without-document", APP,
     "        # batch-48 (LLR-080.2) — site 2 of 5 (the history/refresh path).\n        panel.refresh_entries(\n"
     "            service.rows(loaded_ranges),\n            mem_map=loaded.mem_map if loaded is not None else None,\n"
     "            document=self._patch_document_view(),\n        )",
     "        # batch-48 (LLR-080.2) — site 2 of 5 (the history/refresh path).\n        panel.refresh_entries(\n"
     "            service.rows(loaded_ranges),\n            mem_map=loaded.mem_map if loaded is not None else None,\n        )",
     [P + "test_tc_b97_06_every_writer_refreshes_the_view_at_once"]),
    ("M8-stamp-by-document-path-only", SDB,
     "        # batch-97 D4: the dirty trigger of the JSON stamp — the four dirty\n"
     "        # writers all end here, so the stamp follows the flag at once.\n        self._refresh_json_stamp()",
     "",
     [P + "test_tc_b97_06_dirty_flag_arms_save_and_typing",
      P + "test_at_b97_02_add_save_empty_and_legacy"]),
    ("M9-equal-payload-repainted", SDB,
     "        if shown is not None and shown[2] == document.json_text:\n            return",
     "        if False:\n            return",
     [P + "test_tc_b97_06_equal_payload_and_fresh_start",
      P + "test_tc_b97_06_dirty_flag_arms_save_and_typing"]),
    ("M10-ribbon-from-markup", SDB,
     "            text = safe_text(clip_tail(safe_text(name).plain, room), VALUE)",
     "            text = Text.from_markup(clip_tail(name, room))",
     [P + "test_tc_b97_07_file_derived_text_renders_literally[name]",
      P + "test_at_b97_03_hostile_name_and_content_read_literally[name]"]),
    ("M11-strip-bound-to-row-0", SDB, "        self._render_before_after_card(event.cursor_row)",
     "        self._render_before_after_card(0)",
     [P + "test_tc_b97_39_strip_follows_the_highlight",
      P + "test_at_b97_17_first_task_from_the_keyboard"]),
    ("M12-bold-on-unchanged-span-byte", SDB,
     "                if not changed:\n                    style = DGRAY",
     "                if not changed:\n                    style = f\"bold {DGRAY}\" if (written and in_span) else DGRAY",
     [P + "test_tc_b97_39_bold_marks_only_changed_span_bytes"]),
    ("M13-bold-on-context-byte", SDB,
     "                if not changed:\n                    style = DGRAY",
     "                if not changed:\n                    style = f\"bold {DGRAY}\" if (written and not in_span) else DGRAY",
     [P + "test_tc_b97_39_bold_marks_only_changed_span_bytes",
      P + "test_tc_b97_39_strip_follows_the_highlight"]),
    ("M14-rows-elided-to-one", SDB, "    rows = -(-len(cells) // per_row) if cells else 0",
     "    rows = 1 if cells else 0",
     [P + "test_tc_b97_39_long_entry_stacks_rows_and_follows_a_resize"]),
    ("M15-strip-not-recomposed-on-resize", SDB,
     "        self._render_before_after_card()\n        self._refresh_ribbon()\n\n    def on_resize",
     "        self._refresh_ribbon()\n\n    def on_resize",
     [P + "test_tc_b97_39_long_entry_stacks_rows_and_follows_a_resize",
      W + "test_tc_b97_34_patch_painted_widths_follow_four_resizes"]),
    ("M16-no-row-cap", SDB, "    shown = min(rows, row_cap)", "    shown = rows",
     [P + "test_tc_b97_39_strip_builder_states_and_cap"]),
    ("M17-control-cannot-focus", SDB,
     "        self._refresh_json_stamp()\n        self.call_after_refresh(self._apply_layout)",
     "        self._refresh_json_stamp()\n        self.query_one(\"#patch_entry_remove_button\").can_focus = False\n"
     "        self.call_after_refresh(self._apply_layout)",
     [P + "test_tc_b97_41_keyboard_order_enter_and_chip_states",
      P + "test_tc_b97_60_every_control_displayed_in_its_home[size0]"]),
    ("M18-second-filled-chip", SDB,
     '"Apply loaded changes", id="patch_doc_apply_button", classes="patch-chip"',
     '"Apply loaded changes", id="patch_doc_apply_button", classes="patch-chip fill-accent"',
     [P + "test_tc_b97_42_save_is_the_one_filled_element"]),
    ("M19-active-chip-filled", SDB, '            self.query_one(f"#{tab_id}").set_class(selected, "chip-selected")\n            if selected:\n                self.query_one("#patch_tab_switcher"',
     '            self.query_one(f"#{tab_id}").set_class(selected, "fill-accent")\n            if selected:\n                self.query_one("#patch_tab_switcher"',
     [P + "test_tc_b97_42_save_is_the_one_filled_element"]),
    ("M20-control-hidden", SDB,
     "        self._refresh_json_stamp()\n        self.call_after_refresh(self._apply_layout)",
     "        self._refresh_json_stamp()\n        self.query_one(\"#patch_execute_run_button\").display = False\n"
     "        self.call_after_refresh(self._apply_layout)",
     [P + "test_tc_b97_60_every_control_displayed_in_its_home[size0]"]),
    ("M21-paste-read-only", SDB,
     '                                    DUMMY_CHANGESET_TEXT, id="patch_paste_text"\n',
     '                                    DUMMY_CHANGESET_TEXT, id="patch_paste_text", read_only=True\n',
     [P + "test_tc_b97_60_every_control_displayed_in_its_home[size0]"]),
    ("M22-vacuous-repaint", SDB,
     "            cells = self._ledger_cells(row, layout)\n            for column in (2, 3, 4):\n"
     "                table.update_cell(\n                    str(index), keys[column], cells[column],\n"
     "                    update_width=(index == 0 and column == 2),\n                )",
     "            table.refresh(layout=True)",
     [W + "test_tc_b97_34_patch_painted_widths_follow_four_resizes"]),
    ("M23-ledger-past-the-panel", CSS, "#patch_editor_panel #patch_main {\n    height: 1fr;",
     "#patch_editor_panel #patch_main {\n    height: 60;",
     [W + "test_tc_b97_36_patch_document_actions_inside_at_scroll_zero[size0]"]),
    ("M24-ribbon-keeps-head", SDB,
     "            text = safe_text(clip_tail(safe_text(name).plain, room), VALUE)",
     "            text = safe_text(_clip_to_cells(safe_text(name).plain, room), VALUE)",
     [W + "test_tc_b97_37_patch_no_wrapped_row_and_clips[size0]"]),
    ("M25-value-fixed-22", SDB, "    value = max(12, usable - 8 - 10 - 7 - status)", "    value = 22",
     [W + "test_tc_b97_38_patch_ledger_takes_its_width[size1]",
      W + "test_tc_b97_34_patch_layout_monotonic_in_its_inputs"]),
    ("M26-panel-overflow-hidden", CSS,
     "#patch_editor_panel {\n    width: 100%;\n    height: 1fr;\n    padding: 0;\n    layout: vertical;\n"
     "    overflow-x: hidden;\n    overflow-y: auto;",
     "#patch_editor_panel {\n    width: 100%;\n    height: 1fr;\n    padding: 0;\n    layout: vertical;\n"
     "    overflow-x: hidden;\n    overflow-y: hidden;",
     [W + "test_tc_b97_59_patch_below_the_range_actions_reachable[size0]"]),
    ("M27-unmapped-outside-vocabulary", SDB,
     "        return CARD_UNMAPPED_TOKEN if value is None else f\"{value:02X}\"",
     "        return \"??\" if value is None else f\"{value:02X}\"",
     [H + "test_tc_b97_33_patch_glyphs_closed_and_in_the_legend"]),
    ("M28-help-line-without-effect", WH, '"Add — appends the entry typed in the form.",',
     '"Add appends the entry typed in the form.",',
     [H + "test_tc_b97_32_patch_help_names_every_label"]),
    ("M29-textarea-in-the-tuple", TCH,
     'if isinstance(app.query_one(f"#{i}"), (Button, _Input, _Select))\n            }',
     'if isinstance(app.query_one(f"#{i}"), (Button, _Input, _Select, __import__("textual.widgets", fromlist=["TextArea"]).TextArea))\n            }',
     [H + "test_tc_b97_32_patch_help_names_every_label"]),
    ("M30-edit-json-one-tab", WH, "on the JSON tab, opens the paste buffer full size",
     "elsewhere, opens the paste buffer full size",
     [H + "test_tc_b97_32_patch_help_names_every_label"]),
    ("M31-blank-row-before-dock", CSS, "#patch_editor_panel #patch_doc_file_line1 {",
     "#patch_editor_panel #patch_doc_controls { margin-top: 1; }\n\n#patch_editor_panel #patch_doc_file_line1 {",
     [W + "test_tc_b97_38_patch_no_blank_row_outside_ledger_and_card[size0]"]),
    ("M32-strip-fixed-8", SDB, "    strip = max(fitting) if fitting else STRIP_ROW_BYTES[0]", "    strip = 8",
     [W + "test_tc_b97_34_patch_layout_monotonic_in_its_inputs",
      P + "test_tc_b97_39_long_entry_stacks_rows_and_follows_a_resize"]),
    ("M34-long-ledger-line", SDB,
     '    EMPTY_STATE_TEXT = "No entries yet: Add one, paste a change-set or Load a file."',
     '    EMPTY_STATE_TEXT = (\n        "No change entries yet - type an address (0x...) plus a string "\n'
     '        "value or a run of hex bytes and press Add, or load a v2 "\n        "change-set JSON file."\n    )',
     [H + "test_tc_b97_58_patch_editor_region_states[ledger_empty]"]),
    ("M35-refusal-not-in-ledger", SDB, '                empty_state.update(safe_text(f"Refused: {lines[0]}"))',
     "                pass",
     [H + "test_tc_b97_58_patch_editor_region_states[ledger_refused]"]),
    ("M36-checks-no-run-line-removed", SDB,
     "                                self.CHECKS_NO_RUN_TEXT,\n                                id=\"patch_checks_status\",",
     "                                \"\",\n                                id=\"patch_checks_status\",",
     [H + "test_tc_b97_58_patch_editor_region_states[checks_no_run]"]),
    ("M37-no-fresh-start-line", SDB, '    JSON_VIEW_EMPTY_TEXT = "No document yet: Load, paste or Add."',
     '    JSON_VIEW_EMPTY_TEXT = ""',
     [P + "test_tc_b97_06_equal_payload_and_fresh_start",
      H + "test_tc_b97_58_patch_editor_region_states[json_no_document]"]),
    # M39 retargets M34 (survived: the CSS no-wrap rule, not the text length,
    # keeps the ledger state line on one row): drop the region's no-wrap rule.
    ("M39-ledger-state-line-wraps", CSS,
     "#patch_editor_panel #patch_identity_ribbon,\n#patch_editor_panel #patch_doc_empty_state,\n",
     "#patch_editor_panel #patch_identity_ribbon,\n",
     [H + "test_tc_b97_58_patch_editor_region_states[ledger_refused]"]),
    ("M38-no-inspector-floor", CSS, "    width: 2fr;\n    min-width: 45;\n", "    width: 2fr;\n",
     [W + "test_tc_b97_35_patch_no_horizontal_overflow[size2]"]),
    # --- Inc-4 gate fold (2026-10-21): one mutant per new behaviour ---------
    ("M40-changed-now-byte-white", SDB, '                    style = f"bold {PATCH_TEAL}"',
     '                    style = f"bold {VALUE}"',
     [P + "test_tc_b97_39_changed_bytes_and_count_paint_teal",
      P + "test_tc_b97_39_strip_follows_the_highlight"]),
    ("M41-count-not-teal", SDB,
     '        f"{changed_count} changed", style=f"bold {PATCH_TEAL}" if changed_count else DGRAY',
     '        f"{changed_count} changed", style=VALUE if changed_count else DGRAY',
     [P + "test_tc_b97_39_changed_bytes_and_count_paint_teal"]),
    ("M42-parse-without-dirty", APP, "                    panel.mark_pasted()",
     "                    panel.mark_loaded()",
     [P + "test_tc_b97_06_paste_parse_marks_the_document_unsaved",
      P + "test_tc_b97_06_every_writer_refreshes_the_view_at_once"]),
    ("M43-heading-never-example", SDB,
     '            "PASTE BUFFER · example"\n            if buffer.text == DUMMY_CHANGESET_TEXT',
     '            "PASTE BUFFER · editable"\n            if buffer.text == DUMMY_CHANGESET_TEXT',
     [P + "test_tc_b97_05_paste_heading_names_the_example"]),
    ("M48-heading-never-editable", SDB,
     '            else "PASTE BUFFER · editable"\n        )',
     '            else "PASTE BUFFER · example"\n        )',
     [P + "test_tc_b97_05_paste_heading_names_the_example"]),
    ("M44-theme-scrollbar", CSS, "    scrollbar-color: #969aad 40%;     /* insight_style.DGRAY */\n", "",
     [P + "test_tc_b97_05_text_area_scrollbars_are_muted"]),
    ("M45-no-spacer-rows", CSS,
     "#patch_editor_panel #patch_doc_entry_inputs .pe-row {\n    margin-bottom: 1;",
     "#patch_editor_panel #patch_doc_entry_inputs .pe-row {\n    margin-bottom: 0;",
     [P + "test_tc_b97_40_labelled_form_and_chips_in_the_inspector[size0]",
      P + "test_tc_b97_40_capped_strip_chips_reachable[size1]"]),
    ("M46-input-background-as-pane", CSS,
     "#patch_editor_panel #patch_entry_bytes_input {\n    background: $rule;",
     "#patch_editor_panel #patch_entry_bytes_input {\n    background: $bg-base;",
     [P + "test_tc_b97_40_labelled_form_and_chips_in_the_inspector[size0]"]),
    ("M47-unscoped-patch-id-rule", CSS, "#patch_editor_panel #patch_doc_tally {",
     "#patch_doc_issues { padding: 0 1; }\n\n#patch_editor_panel #patch_doc_tally {",
     [P + "test_tc_b97_04_no_unscoped_patch_rule_in_the_whole_stylesheet"]),
    # M45's capped-strip arm survived: the chips' row follows the form's fixed
    # height (5), not the row margins; this retarget shrinks the height.
    ("M49-form-height-back-to-3", CSS, "    height: 5;\n    margin-top: 1;",
     "    height: 3;\n    margin-top: 1;",
     [P + "test_tc_b97_40_capped_strip_chips_reachable[size1]",
      P + "test_tc_b97_40_capped_strip_chips_reachable[size0]"]),
]

if len(sys.argv) > 1:
    MUTANTS = [m for m in MUTANTS if m[0].split("-")[0] in sys.argv[1:]]

env = dict(os.environ, PY_COLORS="0", PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
env.pop("NO_COLOR", None)
print("mutants:", len(MUTANTS), "arms:", sum(len(m[4]) for m in MUTANTS), flush=True)
bad = 0
for mid, f, old_s, new_s, nodes in MUTANTS:
    src = f.read_bytes()
    eol = b"\r\n" if b"\r\n" in src else b"\n"
    old = old_s.encode("utf-8").replace(b"\n", eol)
    new = new_s.encode("utf-8").replace(b"\n", eol)
    h0 = hashlib.sha256(src).hexdigest()
    if src.count(old) != 1:
        print(f"{mid}: BAD (anchor found {src.count(old)} times)")
        bad += 1
        continue
    for node in nodes:
        try:
            f.write_bytes(src.replace(old, new, 1))
            if hashlib.sha256(f.read_bytes()).hexdigest() == h0:
                print(f"{mid} {node}: BAD (the edit did not apply)")
                sys.exit(1)
            r = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no", "--tb=line", node],
                env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
        finally:
            f.write_bytes(src)
        h1 = hashlib.sha256(f.read_bytes()).hexdigest()
        assert h1 == h0, "the restore is not proven"
        verdict = {1: "RED (KILLED)", 0: "GREEN (SURVIVED)"}.get(r.returncode)
        bad += verdict is None
        tail = [ln for ln in r.stdout.splitlines() if "Error" in ln or "passed" in ln or "failed" in ln][-2:]
        print(f"{mid} [{f.name}] {node.split('::')[1]}: {verdict or 'CRASH/BAD (exit %d)' % r.returncode}")
        print(f"    restore sha256 {h1} == before {h0}")
        for ln in tail:
            print("    | " + ln.strip()[:300])
        sys.stdout.flush()
sys.exit(1 if bad else 0)
