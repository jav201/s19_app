"""Inc-6 mutation battery (the Inc-3..Inc-5 runner, one edit per mutant).

One edit per mutant (a list of anchors applies every pair, each anchor once),
one test function per run, restore proven by SHA-256 after every arm. Anchors
are written with ``\\n`` and matched in the file's own line endings.
Run from the repo root: python .dev-flow/2026-10-19-batch-97/evidence/inc-6/mutate.py [M1 M2 ...]
"""
import hashlib
import os
import pathlib
import subprocess
import sys

FS = pathlib.Path("s19_app/tui/flow_screens.py")
APP = pathlib.Path("s19_app/tui/app.py")
CSS = pathlib.Path("s19_app/tui/styles.tcss")
WH = pathlib.Path("s19_app/tui/window_help.py")
B = "tests/test_b97_flow_builder.py::"
W = "tests/test_b97_width.py::"
H = "tests/test_b97_chips_help.py::"
X = "tests/test_b97_flow_execution.py::"

MUTANTS = [
    ("M1-waiting-row-checked-after-the-status-rows", FS,
     "    if next_status == BLOCK_STATUS_WAITING:\n        return \"□\"\n",
     "    if next_status == BLOCK_STATUS_WAITING and status not in (BLOCK_STATUS_OK, BLOCK_STATUS_NOTICES, BLOCK_STATUS_ERROR):\n        return \"□\"\n",
     [X + "test_tc_b97_21_cable_glyph_truth_table", X + "test_tc_b97_21_three_lane_run_paints_each_cable"]),
    ("M2-cable-painted-from-the-next-block", FS,
     "        mark = cable_glyph(self._block_status(index, j), self._block_status(index, j + 1))",
     "        mark = cable_glyph(self._block_status(index, j + 1), self._block_status(index, j + 2))",
     [X + "test_tc_b97_21_three_lane_run_paints_each_cable", X + "test_tc_b97_21_wait_third_6_cables"]),
    ("M3-rebind-pair-displaced-out-of-its-card", CSS,
     "#fx_panel .fx-card-edit {\n    height: 2;\n}",
     "#fx_panel .fx-card-edit {\n    height: 2;\n    offset: 24 0;\n}",
     [X + "test_tc_b97_22_rebind_input_and_bind_inside_the_source_card"]),
    ("M4-scroll-step-removed", FS,
     "        if (self._attention, self._attention_block) != (lane_index, block):\n            return\n",
     "        if True:\n            return\n",
     [X + "test_tc_b97_23_waiting_card_past_the_viewport_is_brought_into_view"]),
    ("M5-confirm-auto-focused", FS,
     "            confirm.add_class(\"fx-attention\")\n",
     "            confirm.add_class(\"fx-attention\")\n            confirm.focus()\n",
     [X + "test_tc_b97_23_three_lane_pause_waiting_lane_in_view_focus_kept",
      X + "test_tc_b97_64_stray_enter_on_run_runs_again_and_confirms_nothing"]),
    ("M6-scroll-ignores-the-focused-widget", FS,
     "        if focused is not None and scroll in focused.ancestors:",
     "        if False:",
     [X + "test_tc_b97_23_focus_in_the_lanes_stays_in_view"]),
    ("M7-attention-class-on-every-confirm", FS,
     "        for confirm in self.query(f\"#fx_confirm_{lane_index}\"):",
     "        for confirm in self.query(\".fx-confirm\"):",
     [X + "test_tc_b97_23_two_waiting_lanes_one_attention"]),
    ("M8-a-click-toggles", FS,
     "        if event.x <= self._SEQUENTIAL_LAST_X:",
     "        self.press()\n        return\n        if event.x <= self._SEQUENTIAL_LAST_X:",
     [X + "test_tc_b97_24_mode_click_selects_the_word_keys_toggle_report_records_it"]),
    ("M9-space-unbound-on-the-chip-class", FS,
     "    BINDINGS = [Binding(\"space\", \"press\", \"Press\", show=False)]",
     "    BINDINGS = []",
     [X + "test_tc_b97_24_mode_click_selects_the_word_keys_toggle_report_records_it",
      X + "test_tc_b97_56_every_flow_button_is_a_space_chip",
      X + "test_tc_b97_56_focus_order_keys_and_chip_states",
      B + "test_tc_b97_51_space_presses_every_builder_button_group"]),
    ("M10-rerun-line-back-to-spanish", FS,
     "                f\" · re-run after confirming the external step (block {rerun_block + 1}/{total})\",",
     "                f\" · re-run tras confirmar paso externo (block {rerun_block + 1}/{total})\",",
     [X + "test_tc_b97_25_panel_constants_carry_no_spanish",
      X + "test_tc_b97_25_painted_lanes_log_and_rerun_in_english"]),
    ("M11-chain-name-through-markup", FS,
     "        text.append(safe_text(lane.name).plain, style=\"bold \" + VALUE)",
     "        text.append_text(Text.from_markup(lane.name, style=\"bold \" + VALUE))",
     [X + "test_tc_b97_26_hostile_text_renders_literally"]),
    ("M12-notices-in-the-waiting-colour", FS,
     "    BLOCK_STATUS_NOTICES: (\"◇\", \"notices\", YELLOW),",
     "    BLOCK_STATUS_NOTICES: (\"◇\", \"notices\", _S_WAIT),",
     [X + "test_tc_b97_52_waiting_colour_only_on_waiting_human_elements"]),
    ("M13-crc-card-in-the-waiting-colour", FS,
     "    BLOCK_CRC: (\"⊕\", \"CRC\", CRC_FAMILY, \"stamps a CRC\"),",
     "    BLOCK_CRC: (\"⊕\", \"CRC\", WAITING_HUMAN, \"stamps a CRC\"),",
     [X + "test_tc_b97_52_crc_card_beside_the_waiting_card_keeps_its_colour",
      X + "test_at_b97_09_three_lanes_run_paused_lane_in_view_english_log"]),
    ("M14-blank-row-under-the-ribbon", CSS,
     "#fx_panel #fx_ribbon {\n    height: 1;\n    padding: 0 1;\n}",
     "#fx_panel #fx_ribbon {\n    height: 1;\n    padding: 0 1;\n    margin-bottom: 1;\n}",
     [X + "test_tc_b97_53_no_blank_row_outside_or_between_lanes",
      W + "test_tc_b97_38_execution_height_goes_to_the_lanes"]),
    ("M15-blank-row-between-lanes", CSS,
     "#fx_panel .fx-lane {\n    width: auto;\n    height: auto;\n}",
     "#fx_panel .fx-lane {\n    width: auto;\n    height: auto;\n    margin-bottom: 1;\n}",
     [X + "test_tc_b97_53_no_blank_row_outside_or_between_lanes"]),
    ("M16-a-primary-import", FS,
     "                yield FlowChip(\"Import…\", id=\"fx_import\")",
     "                yield FlowChip(\"Import…\", id=\"fx_import\", variant=\"primary\")",
     [X + "test_tc_b97_54_run_and_each_waiting_confirm_are_the_filled_elements"]),
    ("M17-run-disable-dropped", FS,
     "            control.set_reactive(Widget.disabled, True)\n            control.update_node_styles()\n",
     "            pass\n",
     [X + "test_tc_b97_55_input_queued_during_a_run_starts_no_second_run",
      X + "test_tc_b97_55_confirm_rerun_is_one_run_at_a_time"]),
    ("M18-confirm-left-enabled-during-its-rerun", FS,
     "        controls.extend(confirm for confirm in self.query(\".fx-confirm\") if confirm.display)\n",
     "        pass\n",
     [X + "test_tc_b97_55_confirm_rerun_is_one_run_at_a_time"]),
    ("M19-confirm-handler-without-its-except", APP,
     "        except Exception as exc:  # noqa: BLE001 - every raise becomes one line\n            panel.render_confirm_error(lane_index, fx_run_error_line(exc))\n",
     "        except ZeroDivisionError as exc:  # mutant: the raise escapes\n            panel.render_confirm_error(lane_index, fx_run_error_line(exc))\n",
     [X + "test_tc_b97_55_confirm_rerun_that_raises_leaves_the_entry_unconfirmed"]),
    ("M20-run-handler-without-its-except", APP,
     "        except Exception as exc:  # noqa: BLE001 - every raise becomes one line\n            panel.render_run_error(fx_run_error_line(exc))\n",
     "        except ZeroDivisionError as exc:  # mutant: the raise escapes\n            panel.render_run_error(fx_run_error_line(exc))\n",
     [X + "test_tc_b97_55_a_run_that_raises_paints_one_english_line"]),
    ("M21-error-painter-keeps-the-block-confirmed", FS,
     "            if lane.paused_block is not None:\n                lane.confirmed = tuple(b for b in lane.confirmed if b != lane.paused_block)\n            self._repaint_lane(lane_index)\n",
     "            self._repaint_lane(lane_index)\n",
     [X + "test_tc_b97_55_confirm_rerun_that_raises_leaves_the_entry_unconfirmed"]),
    ("M22-no-dwell", FS,
     "        if since is None or _fx_clock() - since < CONFIRM_DWELL_S or not self._post_confirm(lane_index):",
     "        if not self._post_confirm(lane_index):",
     [X + "test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one",
      X + "test_tc_b97_64_two_external_steps_end_ok"]),
    ("M23-dwell-base-from-an-earlier-event", FS,
     "        self._attention_since = None\n        required = self.query_one(\"#fx_required\", Static)\n",
     "        self._attention_since = 0.0\n        required = self.query_one(\"#fx_required\", Static)\n",
     [X + "test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one",
      X + "test_tc_b97_64_two_external_steps_end_ok"]),
    ("M24-c-reaches-only-a-focus-inside-the-screen", APP,
     "            return self._active_screen_key == \"flow_execution\"\n",
     "            return self._active_screen_key == \"flow_execution\" and self.focused is not None and self.query_one(\"#screen_flow_execution\") in self.focused.ancestors_with_self\n",
     [X + "test_tc_b97_64_arriving_with_bracket_c_confirms"]),
    ("M25-check-action-arm-removed", APP,
     "        if action == \"confirm_attention\":\n",
     "        if False:\n",
     [X + "test_tc_b97_64_c_confirms_nothing_out_of_scope"]),
    ("M26-rerun-forgets-the-next-wait", FS,
     "        self._take_outcome(lane, outcome)\n        if lane.paused_block is None:\n",
     "        self._take_outcome(lane, outcome)\n        lane.paused_block = None\n        if lane.paused_block is None:\n",
     [X + "test_tc_b97_64_two_external_steps_end_ok"]),
    ("M27-rerun-carries-the-current-block-only", APP,
     "            for index in confirmed\n",
     "            for index in (block_index,)\n",
     [X + "test_tc_b97_64_two_external_steps_end_ok"]),
    ("M28-card-width-per-lane", FS,
     "        card_w, spare = self._layout\n        height = self._lane_height(index)\n        inner = card_w - 4\n        lane_widget",
     "        card_w, spare = lane_layout(self._viewport_w, len(lane.flow.blocks))\n        height = self._lane_height(index)\n        inner = card_w - 4\n        lane_widget",
     [W + "test_tc_b97_34_execution_cards_follow_four_resizes_in_columns"]),
    ("M29-reserve-only-while-a-lane-waits", FS,
     ["        layout = lane_layout(viewport, n_max)\n",
      "        self._attention = None\n        self._attention_block = None\n        self._rearm_attention()\n"],
     ["        layout = lane_layout(viewport, n_max) if any(l.paused_block is not None for l in self._lanes) else LaneLayout(*pipeline_layout(viewport, n_max))\n",
      "        self._attention = None\n        self._attention_block = None\n        self._rearm_attention()\n        self._layout_key = None\n        self.call_after_refresh(self._apply_layout)\n"],
     [W + "test_tc_b97_34_execution_card_width_holds_when_a_lane_starts_waiting"]),
    ("M30-layout-triggers-removed", FS,
     "    def on_resize(self) -> None:\n        self.call_after_refresh(self._apply_layout)\n\n    def on_show(self) -> None:\n        self.call_after_refresh(self._apply_layout)\n\n    def _apply_layout(self) -> None:\n        \"\"\"Derive the card width once per set",
     "    def on_resize(self) -> None:\n        pass\n\n    def on_show(self) -> None:\n        pass\n\n    def _apply_layout(self) -> None:\n        \"\"\"Derive the card width once per set",
     [W + "test_tc_b97_34_execution_cards_follow_four_resizes_in_columns",
      W + "test_tc_b97_34_execution_resize_while_hidden_rederives_on_show"]),
    ("M31-panel-overflow-hidden", CSS,
     "#fx_panel {\n    padding: 0;\n}",
     "#fx_panel {\n    padding: 0;\n    overflow: hidden hidden;\n}",
     [W + "test_tc_b97_59_execution_below_the_range_actions_reachable"]),
    ("M32-log-20-cells-and-wrapping", CSS,
     "#fx_panel #fx_log {\n    height: auto;\n    max-height: 8;\n    padding: 0 1;\n    text-wrap: nowrap;\n",
     "#fx_panel #fx_log {\n    height: auto;\n    max-height: 8;\n    padding: 0 1;\n    width: 20;\n",
     [W + "test_tc_b97_37_execution_no_wrapped_row"]),
    ("M33-cards-fixed-at-21", FS,
     "    card_w, spare = pipeline_layout(viewport_w - CONFIRM_RESERVE, max(1, n_max))\n    return LaneLayout(card_w, spare)\n",
     "    return LaneLayout(CARD_MIN_W)\n",
     [W + "test_tc_b97_38_execution_cards_take_their_width",
      X + "test_tc_b97_34_lane_layout_is_the_builder_rule_minus_the_confirm_reserve"]),
    ("M34-lanes-frame-not-the-growing-region", CSS,
     "#fx_panel #fx_lanes_scroll {\n    height: 1fr;\n",
     "#fx_panel #fx_lanes_scroll {\n    height: auto;\n",
     [W + "test_tc_b97_38_execution_height_goes_to_the_lanes",
      X + "test_tc_b97_53_no_blank_row_outside_or_between_lanes"]),
    ("M35-pending-glyph-back-to-warning", FS,
     "FX_PENDING_GLYPH = \"▪\"",
     "FX_PENDING_GLYPH = \"⚠\"",
     [H + "test_tc_b97_33_flow_execution_glyphs_are_narrow_in_windows_terminal",
      H + "test_tc_b97_33_flow_execution_glyphs_closed_and_in_the_legend",
      X + "test_tc_b97_23_three_lane_pause_waiting_lane_in_view_focus_kept"]),
    ("M36-help-line-without-its-effect", WH,
     "            \"Bind — binds the typed image file to this lane only; the next \"\n            \"Run reads it.\",\n",
     "            \"Bind\",\n",
     [H + "test_tc_b97_32_flow_execution_help_names_every_label"]),
    ("M37-header-session-chip-removed", APP,
     "                \"Flow Execution\",\n                OpenFolderChip(\"session\"),\n",
     "                \"Flow Execution\",\n",
     [H + "test_tc_b97_31_flow_execution_header_carries_both_chips",
      X + "test_tc_b97_56_focus_order_keys_and_chip_states"]),
    ("M38-an-unscoped-shared-rule", CSS,
     "#fx_panel #fx_legend {\n    height: 1;\n    padding: 0 1;\n    text-wrap: nowrap;\n    text-overflow: ellipsis;\n}",
     "#fx_panel #fx_legend {\n    height: 1;\n    padding: 0 1;\n    text-wrap: nowrap;\n    text-overflow: ellipsis;\n}\n\n.flow-name-strip {\n    margin-bottom: 0;\n}",
     [X + "test_tc_b97_flow_execution_css_section_is_scoped"]),
    ("M39-a-button-put-back", FS,
     "                yield FlowChip(\"Import…\", id=\"fx_import\")",
     "                yield Button(\"Import…\", id=\"fx_import\")",
     [X + "test_tc_b97_56_every_flow_button_is_a_space_chip"]),
    ("M40-empty-lanes-line-removed", FS,
     "        yield Static(self._lanes_empty_text(), id=\"fx_empty\", classes=\"nowrap-pipeline\")",
     "        yield Static(\"\", id=\"fx_empty\", classes=\"nowrap-pipeline\")",
     [X + "test_tc_b97_53_no_lanes_one_line_and_no_blank_row_outside",
      H + "test_tc_b97_58_flow_execution_region_states"]),
    ("M41-refusal-without-its-code", FS,
     "    return f\"[{code}] {finding.message}\" if code else finding.message",
     "    return finding.message",
     [H + "test_tc_b97_58_flow_execution_region_states",
      X + "test_at_b97_11_hostile_and_nul_inputs_render_literally_or_are_refused"]),
    ("M42-bound-nul-detail-without-its-code", FS,
     "                coded = next((d for d in block_result.diagnostics if d.startswith(\"[\")), None)",
     "                coded = None",
     [H + "test_at_b97_23_each_failed_region_says_so_in_one_line"]),
    ("M43-required-line-not-cleared", FS,
     "            required.update(\"\")\n            required.display = False\n            return\n",
     "            return\n",
     [X + "test_tc_b97_23_three_lane_pause_waiting_lane_in_view_focus_kept",
      X + "test_tc_b97_64_c_after_the_dwell_confirms_the_attention_lane"]),
    ("M44-head-without-its-worst-status-mark", FS,
     "        text = Text(mark, style=\"bold \" + colour)",
     "        text = Text(\"·\", style=\"bold \" + colour)",
     [X + "test_tc_b97_63_three_lane_head_marks",
      X + "test_tc_b97_63_wide_lanes_scroll_inside_the_lanes_area"]),
    ("M45-log-cap-raised", FS,
     "FX_LOG_MAX_ROWS = 8",
     "FX_LOG_MAX_ROWS = 80",
     [X + "test_tc_b97_53_run_log_paints_at_most_eight_lines"]),
]

wanted = set(sys.argv[1:])
if wanted:
    MUTANTS = [m for m in MUTANTS if m[0].split("-")[0] in wanted]
env = dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
env.pop("NO_COLOR", None)
print("mutants:", len(MUTANTS), "arms:", sum(len(m[4]) for m in MUTANTS), flush=True)
bad = 0
for mid, f, old_s, new_s, nodes in MUTANTS:
    src = f.read_bytes()
    eol = b"\r\n" if b"\r\n" in src else b"\n"
    pairs = list(zip(old_s, new_s)) if isinstance(old_s, list) else [(old_s, new_s)]
    pairs = [(o.encode("utf-8").replace(b"\n", eol), n.encode("utf-8").replace(b"\n", eol)) for o, n in pairs]
    h0 = hashlib.sha256(src).hexdigest()
    counts = [src.count(old) for old, _new in pairs]
    if counts != [1] * len(pairs):
        print(f"{mid}: BAD (anchor found {counts} times)")
        bad += 1
        continue
    mutated = src
    for old, new in pairs:
        mutated = mutated.replace(old, new, 1)
    for node in nodes:
        try:
            f.write_bytes(mutated)
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
