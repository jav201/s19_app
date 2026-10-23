"""Inc-8 mutation battery (batch-97, the two-row key bar).

Each mutant is ONE textual edit of an Inc-8 source file; the anchor must occur
exactly once and the edit is asserted applied. The named test nodes run
against the mutant; a non-zero pytest exit is KILLED. Every source file is
restored and its SHA-256 re-checked against the GREEN digest before the next
mutant.

    python mutate.py <tree>            # all mutants
    python mutate.py <tree> M3 M7      # a subset
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

PY = r"C:\Users\jjgh8\anaconda3\envs\s19env\python.exe"
KB = "tests/test_b97_key_bar.py::"
WH, APP, CSS = "s19_app/tui/window_help.py", "s19_app/tui/app.py", "s19_app/tui/styles.tcss"

MUTANTS = [
    ("M1", "check_action: no ',' / '.' arm (they page the hidden hex view again)", APP,
     'if action in ("hex_page_prev", "hex_page_next"):\n            return self._active_screen_key == "workspace"',
     'if False:\n            return self._active_screen_key == "workspace"',
     [KB + "test_tc_b97_69_page_keys_do_nothing_where_disabled", KB + "test_at_b97_26_keys_only_help_and_hidden_view"]),
    ("M2", "check_action: no '+' / '-' arm", APP,
     'if action in ("page_next_context", "page_prev_context"):',
     'if False:',
     [KB + "test_tc_b97_69_page_keys_do_nothing_where_disabled"]),
    ("M3", "packer crops instead of dropping whole tokens", WH,
     "    if sum(widths) <= width:\n        kept = set(range(len(tokens)))",
     "    if True:\n        kept = set(range(len(tokens)))",
     [KB + "test_tc_b97_70_pack_key_row_keeps_a_whole_display_order_prefix",
      KB + "test_tc_b97_70_every_painted_row_is_whole_tokens"]),
    ("M4", "greedy packer (skips a wide token, keeps a later short one)", WH,
     "            if token_width > budget:\n                break",
     "            if token_width > budget:\n                continue",
     [KB + "test_tc_b97_70_pack_key_row_keeps_a_whole_display_order_prefix"]),
    ("M5", "no '? more' tail on an overflowing row", WH,
     "    if dropped and more is not None:",
     "    if False:",
     [KB + "test_tc_b97_70_pack_key_row_keeps_a_whole_display_order_prefix",
      KB + "test_tc_b97_70_every_painted_row_is_whole_tokens"]),
    ("M6", "a click simulates the key (the Footer's path)", WH,
     "                await bar.run_token(self._painted[key])",
     "                self.app.simulate_key(self._painted[key].key)",
     [KB + "test_tc_b97_72_clicks_run_the_action_and_type_nothing",
      KB + "test_tc_b97_72_owner_click_runs_on_its_widget_not_the_focus",
      KB + "test_tc_b97_72_confirm_click_with_the_focus_in_an_input"]),
    ("M7", "hit ranges offset by 4 cells", WH,
     "        (hits if token.enabled else dimmed).append((start, text.cell_len, token.key))",
     "        (hits if token.enabled else dimmed).append((start + 4, text.cell_len + 4, token.key))",
     [KB + "test_tc_b97_72_hit_ranges_are_the_painted_cells",
      KB + "test_tc_b97_72_owner_click_runs_on_its_widget_not_the_focus"]),
    ("M8", "dimmed tokens clickable", WH,
     "        (hits if token.enabled else dimmed).append(",
     "        (hits if True else dimmed).append(",
     [KB + "test_tc_b97_72_clicks_run_the_action_and_type_nothing"]),
    ("M9", "the tag painted in the description pair", WH,
     '            text.append(_token_text(token), styles.get("tag", plain))',
     '            text.append(_token_text(token), styles.get("description", plain))',
     [KB + "test_tc_b97_68_row_two_tag_tokens_and_colours"]),
    ("M10", "a key bar of height 3", CSS,
     "#key_bar {\r\n    dock: bottom;\r\n    height: 2;",
     "#key_bar {\r\n    dock: bottom;\r\n    height: 3;",
     [KB + "test_tc_b97_71_the_bar_replaces_the_footer_and_costs_one_row"]),
    ("M11", "action_show_screen does not refresh the bar", APP,
     "        # batch-97 Inc-8 (D29): the key bar's row 2 follows the window.\r\n        self.refresh_bindings()",
     "        # batch-97 Inc-8 (D29): the key bar's row 2 follows the window.\r\n        pass",
     [KB + "test_tc_b97_68_go_separator_switch_and_modal"]),
    ("M12", "current_file changes without a refresh", APP,
     "        # batch-97 Inc-8 (PC-23): the key bar dims the image keys by this.\r\n        self.refresh_bindings()",
     "        # batch-97 Inc-8 (PC-23): the key bar dims the image keys by this.\r\n        pass",
     [KB + "test_tc_b97_69_dimmed_entries_follow_their_condition"]),
    ("M13", "the patch document's four refresh_entries callers without their refresh (F4)", APP,
     "# document's source, which this refresh may have changed.\r\n",
     "# document's source, which this refresh may have changed.\r\n#",
     [KB + "test_tc_b97_69_dimmed_entries_follow_their_condition", KB + "test_at_b97_26_keys_only_help_and_hidden_view"], 4),
    ("M14", "the variant set changes without a refresh", APP,
     "        self._variant_set_value = value\r\n        self.refresh_bindings()",
     "        self._variant_set_value = value",
     [KB + "test_tc_b97_69_dimmed_entries_follow_their_condition"]),
    ("M15", "'.' displayed as 'period' again", APP,
     'Binding("period", "hex_page_next", "Hex+", key_display="."),',
     'Binding("period", "hex_page_next", "Hex+"),',
     [KB + "test_tc_b97_70_every_painted_row_is_whole_tokens"]),
    ("M16", "a keys block whose label differs from the binding", WH,
     '    return "\\n".join(f"{token.key_display} — {token.label}" for token in tokens)',
     '    return "\\n".join(f"{token.key_display} — {token.label}." for token in tokens)',
     [KB + "test_tc_b97_66_help_keys_block_is_generated_from_the_table"]),
    ("M17", "an unbound key resolves instead of raising", WH,
     '    raise KeyError(f"key {key!r} is not bound in {where}")',
     '    return Binding(key, "noop", key)',
     [KB + "test_tc_b97_66_unbound_key_or_empty_description_raises_at_mount"]),
    ("M18", "an empty description is accepted", WH,
     '            if not binding.description:\r\n                raise ValueError',
     '            if False:\r\n                raise ValueError',
     [KB + "test_tc_b97_66_unbound_key_or_empty_description_raises_at_mount"]),
    ("M19", "the hand-typed 'c — Confirm' line put back", WH,
     '            "space — on a chip or a button, presses it; on the mode switch, "\r\n            "switches the mode.",',
     '            "space — on a chip or a button, presses it; on the mode switch, "\r\n            "switches the mode.",\r\n            "c — Confirm: confirms the attention lane.",',
     [KB + "test_tc_b97_66_help_keys_block_is_generated_from_the_table"]),
    ("M20", "a label typed into the table", WH,
     '    "flow": (),\r\n    "flow_execution": (KeyEntry("c"),),',
     '    "flow": tuple(KeyEntry(k) for k in ("Legend",)[:0]),\r\n    "flow_execution": (KeyEntry("c"),),',
     [KB + "test_tc_b97_66_table_stores_no_labels"]),
    ("M21", "a hex colour in the key-bar code", WH,
     '_OPEN_ACTIONS: Mapping[str, str] = {"split_join": "open_split_join_export"}',
     '_OPEN_ACTIONS: Mapping[str, str] = {"split_join": "open_split_join_export"}\r\n_TAG = "#91abec"',
     [KB + "test_tc_b97_68_no_hex_literal_in_the_key_bar_code"]),
    ("M22", "a derived row gains a key with no guard (j on A2L)", WH,
     '        KeyEntry("d"), KeyEntry("k"),\r\n    ),',
     '        KeyEntry("d"), KeyEntry("k"), KeyEntry("j"),\r\n    ),',
     [KB + "test_tc_b97_69_derived_rows_follow_their_guards"]),
    ("M23", "an owned key runs on the focused widget", WH,
     "            await widget.run_action(token.action)",
     "            await self.app.screen.focused.run_action(token.action)",
     [KB + "test_tc_b97_72_owner_click_runs_on_its_widget_not_the_focus"]),
    ("M24", "row-2 descriptions in the row-1 colour", CSS,
     "#key_bar #key_bar_window > .key-bar--description {\r\n    color: $accent-calm;",
     "#key_bar #key_bar_window > .key-bar--description {\r\n    color: $footer-description-foreground;",
     [KB + "test_tc_b97_68_row_two_tag_tokens_and_colours"]),
    ("M25", "the go separator always ' · go'", WH,
     '            go_tokens[0] = replace(go_tokens[0], lead=" · go" if tokens else " go")',
     '            go_tokens[0] = replace(go_tokens[0], lead=" · go")',
     [KB + "test_tc_b97_68_go_separator_switch_and_modal"]),
    ("M26", "row 1 shows Textual's Footer set (keys not from GLOBAL_KEYS order)", WH,
     '    "ctrl+k", "ctrl+d", "ctrl+l", "ctrl+s", "x", "question_mark", "q",\r\n)',
     '    "ctrl+k", "ctrl+d", "ctrl+l", "ctrl+s", "question_mark", "x", "q",\r\n)',
     [KB + "test_tc_b97_67_row_one_at_80x24_drops_palette_whole"]),
    # ---- Inc-8 gate fold (operator decisions asked at the Inc-8 gate 2026-10-23) ----
    ("M28", "the Map region list back to a 2-row floor", CSS,
     "    height: 1fr;\r\n    min-height: 1;\r\n}",
     "    height: 1fr;\r\n    min-height: 2;\r\n}",
     ["tests/test_tui_directionb.py::test_at074_single_click_repositions_hex"]),
    ("M29", "row 1 says `^l Load` again", APP,
     'Binding("ctrl+l", "load_file", "Load file", priority=True),',
     'Binding("ctrl+l", "load_file", "Load", priority=True),',
     [KB + "test_tc_b97_67_row_one_at_80x24_drops_palette_whole"]),
    ("M30", "owned keys ignore the focus", WH,
     "        if focused is None or (focused is not container and container not in focused.ancestors):\r\n            return False",
     "        if False:\r\n            return False",
     [KB + "test_tc_b97_69_owned_keys_dim_outside_their_window"]),
    ("M31", "owned keys ignore the owner's check_action", WH,
     "        return owner.check_action(name, params) is True",
     "        return True",
     [KB + "test_tc_b97_69_owned_keys_dim_outside_their_window"]),
    ("M32", "the dim colour on the key only (the description keeps its colour)", WH,
     '            text.append(f" {token.key_display} {token.label} ", dim)',
     '            text.append(f" {token.key_display}", dim)\r\n            text.append(f" {token.label} ", styles.get("description", plain) + Style(dim=True))',
     [KB + "test_tc_b97_69_a_dimmed_token_paints_whole_in_one_colour",
      KB + "test_tc_b97_70_pack_key_row_dims_and_does_not_hit_disabled"]),
    ("M33", "the bar does not listen to the bindings signal (no repaint on focus)", WH,
     "        self.screen.bindings_updated_signal.subscribe(self, self._bindings_changed)",
     "        pass",
     [KB + "test_tc_b97_69_owned_keys_dim_outside_their_window"]),
    ("M34", "the Map help quotes `g` again", WH,
     '"The inspector shows the highlighted region\'s details.",',
     '"The inspector shows the highlighted region\'s details; `g` jumps.",',
     [KB + "test_tc_b97_66_map_help_names_only_keys_that_act_on_the_map"]),
    ("M35", "the dim style dropped (a disabled token painted like an enabled one)", CSS,
     "#key_bar KeyRow > .key-bar--dim {\r\n    color: $foreground-disabled;",
     "#key_bar KeyRow > .key-bar--dim {\r\n    color: $accent-calm;",
     [KB + "test_tc_b97_69_a_dimmed_token_paints_whole_in_one_colour"]),
    ("M27", "the Footer kept beside the bar (the bar does not replace it)", APP,
     '        yield KeyBar(id="key_bar")',
     '        yield KeyBar(id="key_bar")\r\n        from textual.widgets import Footer\r\n        yield Footer()',
     [KB + "test_tc_b97_71_the_bar_replaces_the_footer_and_costs_one_row"]),
]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    tree = Path(sys.argv[1]).resolve()
    wanted = set(sys.argv[2:])
    files = {rel: tree / rel for rel in (WH, APP, CSS)}
    green = {rel: sha(p) for rel, p in files.items()}
    print("GREEN digests:", {rel: d[:16] for rel, d in green.items()})
    env = dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    env.pop("NO_COLOR", None)
    tally = {"KILLED": 0, "SURVIVED": 0, "BAD": 0}
    for mutant in MUTANTS:
        mid, what, rel, old, new, nodes = mutant[:6]
        sites = mutant[6] if len(mutant) > 6 else 1
        if wanted and mid not in wanted:
            continue
        path = files[rel]
        original = path.read_bytes()
        text = original.decode("utf-8")
        if "\r\n" in text:
            old = old.replace("\r\n", "\n").replace("\n", "\r\n")
            new = new.replace("\r\n", "\n").replace("\n", "\r\n")
        if text.count(old) != sites:
            print(f"{mid} BAD anchor count {text.count(old)} — {what}")
            tally["BAD"] += 1
            continue
        mutated = text.replace(old, new)
        assert mutated != text
        path.write_bytes(mutated.encode("utf-8"))
        try:
            for node in nodes:
                proc = subprocess.run(
                    [PY, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "--tb=line", node],
                    cwd=tree, env=env, capture_output=True, text=True, encoding="utf-8",
                )
                last = [line for line in proc.stdout.splitlines() if line.strip()][-1:] or ["?"]
                verdict = "KILLED" if proc.returncode != 0 else "SURVIVED"
                tally[verdict] += 1
                reason = next((l for l in proc.stdout.splitlines() if "Error" in l or "assert" in l), "")
                print(f"{mid} {verdict} {node.split('::')[-1]} | {last[0]} | {reason[-160:]} — {what}")
        finally:
            path.write_bytes(original)
            assert sha(path) == green[rel], f"{mid}: restore failed"
    print("RESTORED digests:", {rel: sha(p)[:16] for rel, p in files.items()})
    print("TALLY", tally)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
