"""Inc-5 mutation battery (the Inc-3 / Inc-4 runner, one edit per mutant).

One edit per mutant, one node per run, restore proven by SHA-256 after every arm.
Anchors are written with ``\\n`` and matched in the file's own line endings.
Run from the repo root: python .dev-flow/2026-10-19-batch-97/evidence/inc-5/mutate.py [M1 M2 ...]

Gate fold (2026-10-22): M40..M52 appended, plus M29b — the one two-edit
mutant (both layout triggers removed, code-reviewer F1); a mutant whose
anchor / replacement are lists applies every pair, each anchor once.
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
CHIP = pathlib.Path("s19_app/tui/open_folder_chip.py")
O = "tests/test_open_folder_chips.py::"
R = "tests/test_flow_builder_render.py::"
P = "tests/test_tui_flow_persistence_ui.py::"
B = "tests/test_b97_flow_builder.py::"
W = "tests/test_b97_width.py::"
H = "tests/test_b97_chips_help.py::"
X = "tests/test_b97_flow_execution.py::"

MUTANTS = [
    ("M1-nul-check-removed-from-add", FS, "            if refusal is not None:",
     "            if False:",
     [B + "test_tc_b97_62_nul_pasted_into_the_add_form_is_refused[source.image_ref]",
      B + "test_tc_b97_62_nul_pasted_into_the_add_form_is_refused[a2b.image_a.ref]",
      B + "test_tc_b97_62_nul_pasted_into_the_add_form_is_refused[external_step.output_path]",
      B + "test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject"]),
    ("M2-helper-reads-flow-ref-only", FS, '        if "\\x00" in values.get(input_id, ""):',
     '        if input_id == "#flow_ref" and "\\x00" in values.get(input_id, ""):',
     [B + "test_tc_b97_62_nul_refusal_helper_names_kind_and_field[a2b.image_a.ref]",
      B + "test_tc_b97_62_nul_refusal_helper_names_kind_and_field[external_step.log_ref]",
      B + "test_tc_b97_62_nul_pasted_into_the_add_form_is_refused[a2b.image_b.ref]"]),
    ("M3-error-glyph-back-to-heavy-x", FS, '    BLOCK_STATUS_ERROR: "✗",     # ✗ error',
     '    BLOCK_STATUS_ERROR: "✖",     # ✗ error',
     [H + "test_tc_b97_33_flow_glyphs_are_narrow_in_windows_terminal"]),
    ("M4-crc-card-in-waiting-colour", FS, '    BLOCK_CRC: ("⊕", "CRC", CRC_FAMILY, "stamps a CRC"),',
     '    BLOCK_CRC: ("⊕", "CRC", "#e8ad3d", "stamps a CRC"),',
     [B + "test_tc_b97_18_crc_card_painted_in_the_crc_colour"]),
    ("M5-crc-card-in-fbA-amber", FS, '    BLOCK_CRC: ("⊕", "CRC", CRC_FAMILY, "stamps a CRC"),',
     '    BLOCK_CRC: ("⊕", "CRC", "#d9a35b", "stamps a CRC"),',
     [B + "test_tc_b97_18_crc_card_painted_in_the_crc_colour"]),
    ("M6-tcss-mirror-swapped", CSS, "$crc-family: #c9562b;", "$crc-family: #e8ad3d;",
     [B + "test_tc_b97_18_tcss_mirrors_equal_their_tokens"]),
    ("M7-card-line-from-markup", FS, "        line.append(text, style=style)",
     "        line.append_text(Text.from_markup(text, style=style))",
     [B + "test_tc_b97_20_hostile_refs_render_literally",
      B + "test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject"]),
    ("M8-command-keeps-tail", FS,
     '            keep = clip_head if ext and name in ("cmd", "instr") else clip_tail',
     "            keep = clip_tail",
     [B + "test_tc_b97_16_cards_clip_every_line_to_the_card"]),
    ("M9-clip-tail-keeps-head", FS,
     '    return "…" + text[len(text) - max(0, width - 1):]',
     '    return text[: max(0, width - 1)] + "…"',
     [B + "test_tc_b97_16_clip_head_and_clip_tail",
      B + "test_tc_b97_16_cards_clip_every_line_to_the_card"]),
    ("M10-second-filled-chip", FS, '            yield Button("Clear", id="flow_clear")',
     '            yield Button("Clear", id="flow_clear", classes="fill-accent")',
     [B + "test_tc_b97_17_run_is_the_one_filled_action_on_one_foot_row"]),
    ("M11-selected-kind-filled", FS,
     '            chip.set_class(chip.id == f"flow_palette_{kind}", "chip-selected")',
     '            chip.set_class(chip.id == f"flow_palette_{kind}", "fill-accent")',
     [B + "test_tc_b97_17_run_is_the_one_filled_action_on_one_foot_row"]),
    ("M12-kind-chip-unfocusable", FS,
     '    BINDINGS = [Binding("space", "press", "Press", show=False)]\n',
     '    BINDINGS = [Binding("space", "press", "Press", show=False)]\n    can_focus = False\n',
     [B + "test_tc_b97_51_keyboard_order_keys_and_chip_states"]),
    ("M13-kind-chip-space-removed", FS,
     '    BINDINGS = [Binding("space", "press", "Press", show=False)]', "    BINDINGS = []",
     [B + "test_tc_b97_51_keyboard_order_keys_and_chip_states"]),
    ("M14-run-requests-a-variant-scope", FS,
     "            self.post_message(self.RunRequested(self.current_flow, FLOW_SCOPE_SINGLE))",
     '            self.post_message(self.RunRequested(self.current_flow, "all"))',
     [B + "test_tc_b97_50_run_requests_the_single_image_scope"]),
    ("M15-variables-count-dropped", FS, '        toggle.label = f"Variables ({len(self._funnel)})"',
     '        toggle.label = "Variables"',
     [B + "test_tc_b97_48_variables_chip_counts_and_toggles"]),
    ("M16-ribbon-keeps-path-head", FS,
     '        right.append(clip_tail(path, right_w - len("session ")), style=_S_OUT)',
     '        right.append(clip_head(path, right_w - len("session ")), style=_S_OUT)',
     [B + "test_tc_b97_49_session_on_the_ribbon[project]",
      W + "test_tc_b97_37_builder_no_wrapped_row_and_tail_kept_ribbon[size0]"]),
    ("M17-ext-session-displayed", FS,
     '        for hidden in ("#flow_help", "#flow_canvas", "#flow_blocks", "#flow_kind", "#flow_ext_session"):',
     '        for hidden in ("#flow_help", "#flow_canvas", "#flow_blocks", "#flow_kind"):',
     [B + "test_tc_b97_49_session_on_the_ribbon[project]"]),
    ("M18-numbered-list-displayed", FS,
     '        for hidden in ("#flow_help", "#flow_canvas", "#flow_blocks", "#flow_kind", "#flow_ext_session"):',
     '        for hidden in ("#flow_help", "#flow_canvas", "#flow_kind", "#flow_ext_session"):',
     [B + "test_tc_b97_13_pipeline_cards_and_cables_replace_list_and_canvas"]),
    ("M19-cable-left-out", FS, '                    line.append("─" * (CABLE_W - 1) + "▶", style=_S_CABLE)',
     '                    line.append(" " * CABLE_W)',
     [B + "test_tc_b97_13_pipeline_cards_and_cables_replace_list_and_canvas",
      B + "test_at_b97_06_chain_on_screen_and_run_writes_the_image[118x54]"]),
    ("M20-palette-kind-left-out", FS, "            for _label, kind in self._KIND_OPTIONS:",
     "            for _label, kind in self._KIND_OPTIONS[:-1]:",
     [B + "test_tc_b97_14_palette_offers_every_kind_in_order"]),
    ("M21-ext-row-hidden", FS, '        self.query_one("#flow_ext_row").display = ext',
     '        self.query_one("#flow_ext_row").display = False',
     [B + "test_tc_b97_15_add_form_shows_exactly_the_kind_inputs"]),
    ("M22-gating-for-every-kind", FS,
     '        self.query_one("#flow_gating", Select).display = kind == BLOCK_CHECK',
     '        self.query_one("#flow_gating", Select).display = True',
     [B + "test_tc_b97_15_add_form_shows_exactly_the_kind_inputs"]),
    ("M23-clip-status-fixed-wide", CSS, "#flow_panel #flow_clip_status {\n    width: 1fr;",
     "#flow_panel #flow_clip_status {\n    width: 120;",
     [B + "test_tc_b97_47_copy_paste_strip_on_one_row_inside"]),
    ("M24-pegado-left", FS, '        self._refresh_clip_status(f"pasted: {block.kind}")',
     '        self._refresh_clip_status(f"pegado: {block.kind}")',
     [B + "test_tc_b97_19_builder_constants_carry_no_spanish"]),
    ("M25-paused-banner-reverted", FS, '    FLOW_STATUS_PAUSED: ("PAUSED - WAITING FOR A HUMAN", "sev-warning"),',
     '    FLOW_STATUS_PAUSED: ("PAUSED - ESPERANDO HUMANO", "sev-warning"),',
     [X + "test_tc_b97_25_module_constant_in_english",
      B + "test_at_b97_19_first_task_from_the_keyboard"]),
    ("M26-pipeline-frame-1fr", CSS, "#flow_panel #flow_pipeline_scroll {\n    height: auto;",
     "#flow_panel #flow_pipeline_scroll {\n    height: 1fr;",
     [W + "test_tc_b97_38_builder_height_goes_to_the_result[before_run-size0]"]),
    ("M27-cards-fixed-at-24", FS,
     "    return PipelineLayout(max(CARD_MIN_W, (avail_w - CABLE_W * (n_cards - 1)) // n_cards))",
     "    return PipelineLayout(24)",
     [W + "test_tc_b97_34_pipeline_layout_monotonic_in_its_inputs",
      W + "test_tc_b97_38_builder_cards_and_ext_inputs_take_their_width[size1]"]),
    ("M28-resize-trigger-removed", FS,
     "    def on_resize(self) -> None:\n        self.call_after_refresh(self._apply_layout)",
     "    def on_resize(self) -> None:\n        pass",
     [W + "test_tc_b97_34_builder_painted_widths_follow_four_resizes"]),
    ("M29-show-trigger-removed", FS,
     "    def on_show(self) -> None:\n        self.call_after_refresh(self._apply_layout)",
     "    def on_show(self) -> None:\n        pass",
     [W + "test_tc_b97_34_builder_resize_while_hidden_rederives_on_show"]),
    ("M30-panel-overflow-hidden", CSS, "#flow_panel #flow_ribbon {",
     "#flow_panel {\n    overflow: hidden;\n}\n\n#flow_panel #flow_ribbon {",
     [W + "test_tc_b97_59_builder_below_the_range_run_reachable[size0]"]),
    ("M31-shared-name-strip-edited", CSS,
     ".flow-name-strip {\n    text-style: bold;\n    width: auto;\n    padding: 0 1;\n    margin-bottom: 1;",
     ".flow-name-strip {\n    text-style: bold;\n    width: auto;\n    padding: 0 1;\n    margin-bottom: 0;",
     [B + "test_tc_b97_flow_css_shared_rules_byte_equal_and_section_scoped"]),
    ("M32-unscoped-flow-result-rule", CSS, "/* batch-97 flow_builder",
     "#flow_result {\n    padding: 0;\n}\n\n/* batch-97 flow_builder",
     [B + "test_tc_b97_flow_css_shared_rules_byte_equal_and_section_scoped"]),
    ("M33-glyph-outside-vocabulary", FS, '    BLOCK_SOURCE: ("◉", "LOAD", HILITE, "reads an image"),',
     '    BLOCK_SOURCE: ("✪", "LOAD", HILITE, "reads an image"),',
     [H + "test_tc_b97_33_flow_glyphs_closed_and_in_the_legend[patch_chain]"]),
    ("M34-help-line-without-effect", WH, '            "Copy — copies that block to the clipboard.",',
     '            "Copy copies that block to the clipboard.",',
     [H + "test_tc_b97_32_flow_help_names_every_label"]),
    ("M35-flows-chip-off-the-header", APP, '                OpenFolderChip("flows"),\n',
     "",
     [H + "test_tc_b97_31_flow_builder_header_carries_both_chips"]),
    ("M36-refusal-line-off-the-frame", FS,
     '            f"load refused: flows/{flow_name}.json — this chain is kept"',
     '            ""',
     [H + "test_tc_b97_58_flow_builder_region_states[load_refused]"]),
    ("M37-result-empty-line-removed", FS,
     '        container.mount(Static(line, classes="flow-result-empty"))',
     "        pass",
     [W + "test_tc_b97_38_builder_height_goes_to_the_result[before_run-size0]"]),
    ("M38-quarantine-line-without-code", FS,
     '                    safe_text(f"[{finding.code}] {finding.message}"),',
     "                    safe_text(finding.message),",
     [B + "test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject"]),
    ("M39-pipeline-empty-line-removed", FS, '        text.append("No blocks yet", style="bold " + VALUE)',
     '        text.append("", style="bold " + VALUE)',
     [H + "test_tc_b97_58_flow_builder_region_states[pipeline_empty]",
      B + "test_tc_b97_13_pipeline_cards_and_cables_replace_list_and_canvas"]),
    # ---- gate fold 2026-10-22 ------------------------------------------
    ("M29b-both-layout-triggers-removed", FS,
     ["    def on_resize(self) -> None:\n        self.call_after_refresh(self._apply_layout)",
      "    def on_show(self) -> None:\n        self.call_after_refresh(self._apply_layout)"],
     ["    def on_resize(self) -> None:\n        pass",
      "    def on_show(self) -> None:\n        pass"],
     [W + "test_tc_b97_34_builder_resize_while_hidden_rederives_on_show"]),
    ("M40-chip-announces-at-mount", CHIP, "            newly_disabled = announce and not self.disabled",
     "            newly_disabled = not self.disabled",
     [H + "test_tc_b97_29_no_status_line_at_startup_without_a_project",
      H + "test_tc_b97_29_no_project_chips_disabled_with_their_own_reason",
      H + "test_tc_b97_65_no_project_session_chip_disabled_with_exact_reason",
      O + "test_tc704_reports_without_project_disabled_status_reason_zero_opens"]),
    ("M41-chip-never-announces", CHIP, "            newly_disabled = announce and not self.disabled",
     "            newly_disabled = False",
     [H + "test_tc_b97_29_no_project_chips_disabled_with_their_own_reason",
      H + "test_tc_b97_65_no_project_session_chip_disabled_with_exact_reason",
      O + "test_tc704_reports_without_project_disabled_status_reason_zero_opens"]),
    ("M42-spare-cells-dropped", FS, "    return PipelineLayout(card_w, room - card_w * n_cards)",
     "    return PipelineLayout(card_w)",
     [W + "test_tc_b97_38_pipeline_spare_cells_go_to_the_cables[4]",
      W + "test_tc_b97_38_builder_cards_and_ext_inputs_take_their_width[size1]",
      W + "test_tc_b97_38_builder_cards_and_ext_inputs_take_their_width[size3]"]),
    ("M43-spare-on-the-cards-not-drawn", FS, "                cable_w = CABLE_W + (1 if i < spare else 0)",
     "                cable_w = CABLE_W",
     [W + "test_tc_b97_38_pipeline_spare_cells_go_to_the_cables[4]",
      W + "test_tc_b97_38_builder_cards_and_ext_inputs_take_their_width[size3]"]),
    ("M44-add-empty-says-nothing", FS,
     '                self._show_wiring_notice(f"Add needs {field} — nothing added")',
     "                pass",
     [B + "test_tc_b97_58_add_with_an_empty_field_says_what_it_needs[source-image file]"]),
    ("M45-unsaved-word-grey", FS,
     '    state, state_style = ("· unsaved", YELLOW) if dirty else ("· saved", DGRAY)',
     '    state, state_style = ("· unsaved", DGRAY) if dirty else ("· saved", DGRAY)',
     [B + "test_tc_b97_49_ribbon_saved_state_is_a_word",
      B + "test_tc_b97_49_ribbon_paints_saved_then_unsaved"]),
    ("M46-ribbon-glyphs-back", FS,
     '    state, state_style = ("· unsaved", YELLOW) if dirty else ("· saved", DGRAY)',
     '    state, state_style = ("●", YELLOW) if dirty else ("✓", DGRAY)',
     [B + "test_tc_b97_49_ribbon_saved_state_is_a_word",
      P + "test_at002_name_strip_glyph_dirty_then_saved"]),
    ("M47-notices-banner-reverted", FS, "            banner_text, banner_class = _NOTICES_BANNER",
     "            pass",
     [W + "test_tc_b97_38_builder_height_goes_to_the_result[after_run-size0]",
      B + "test_at_b97_06_chain_on_screen_and_run_writes_the_image[118x54]",
      R + "test_at085a_notices_load_shows_warning_gutter"]),
    ("M48-notices-even-with-an-error", FS,
     "            b.status != BLOCK_STATUS_ERROR for b in result.block_results",
     "            True for b in result.block_results",
     [R + "test_at088a_pipeline_ledger_structure_all_three_banners"]),
    ("M49-separator-rows-removed", CSS,
     "#flow_panel #flow_run_row {\n    margin-top: 1;", "#flow_panel #flow_run_row {\n    margin-top: 0;",
     [W + "test_tc_b97_38_builder_height_goes_to_the_result[before_run-size0]"]),
    ("M50-result-rule-row-removed", CSS, "    border-top: solid $rule;\n    padding: 0 1;\n}\n\n#flow_panel .flow-banner",
     "    padding: 0 1;\n}\n\n#flow_panel .flow-banner",
     [W + "test_tc_b97_38_builder_height_goes_to_the_result[before_run-size0]"]),
    ("M51-banner-blank-row-back", CSS, "#flow_panel .flow-banner {\n    margin-bottom: 0;",
     "#flow_panel .flow-banner {\n    margin-bottom: 1;",
     [W + "test_tc_b97_38_builder_height_goes_to_the_result[after_run-size1]"]),
    ("M52-wrote-path-not-tail-clipped", FS,
     '            plain = clip_tail(plain, width - len("wrote "))', "            pass",
     [W + "test_tc_b97_38_builder_height_goes_to_the_result[after_run-size0]"]),
    ("M53-nul-line-names-the-block-field", FS,
     '            kind_label = _KIND_LOOK.get(kind, ("", kind.upper(), "", ""))[1]',
     "            kind_label = kind",
     [B + "test_tc_b97_62_nul_refusal_helper_names_kind_and_field[write_out.output_name]",
      B + "test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject"]),
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
