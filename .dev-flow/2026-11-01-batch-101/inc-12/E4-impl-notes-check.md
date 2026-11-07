# Inc 12 — E4 implementation notes (G3 Check Editor)
Batch 2026-11-01-batch-101, increment 12. Implementer G3 Check Editor (E4). Files touched: `s19_app/tui/screens_directionb.py`.

## 1. Functions changed
| File | Function | Graph node | Change |
|---|---|---|---|
| `s19_app/tui/screens_directionb.py` | `CheckEditorPanel.compose` | `CheckEditorPanel.compose` | Removed the `Addendum preview` button `#check_preview_toggle_button` (the `toggle` Button, its `classes`, its `display = False` and its `yield`) from `#check_actions_row2`; the row now holds `#check_fields_count` alone. Removed the docstring sentence "``#check_preview_toggle_button`` stays mounted and hidden, its function carried by the Addendum tab chip." |
| `s19_app/tui/screens_directionb.py` | `CheckEditorPanel.on_button_pressed` | `CheckEditorPanel.on_button_pressed` | Removed the branch `if button_id == "check_preview_toggle_button": event.stop(); self._show_tab("check_tab_addendum"); return`. The tab chips keep `_show_tab`; unknown ids still fall through to `actions.get(...)` → `None`. |

No other node or file was touched. `CheckEditorPanel._show_tab` is unchanged (the Addendum tab chip carries the removed button's function).

## 2. Deviations from the graph (each with its reason) — none

## 3. Open questions for the integrator — none

## 4. Checks
py_compile per edited file:

```
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/screens_directionb.py
```

Output: (empty) — exit code 0.

I-3 grep over `s19_app` (the pinned command of `codewire/graph-inc12.md` I-3, run over the `s19_app` half of the scope):

```
git grep -n -w -e VariantHelpScreen -e VARIANT_HELP_TEXT -e action_view_main -e action_view_alt -e action_view_mac -e action_a2l_tag_find_next -e _jump_to_validation_issue -e _jump_to_validation_issue_object -e _format_validation_issue_line -e check_preview_toggle_button -- s19_app
```

Output (snapshot after my edit; other groups G1/G2 work the same tree in parallel):

```
s19_app/tui/screens.py:1078:VARIANT_HELP_TEXT: str = "\n\n".join(
s19_app/tui/screens.py:1091:class VariantHelpScreen(ModalScreen[None]):
s19_app/tui/screens.py:1098:        :data:`VARIANT_HELP_TEXT` — what the selector does (picks which
s19_app/tui/screens.py:1110:          ``#variant_help_body`` ``Static`` seeded from ``VARIANT_HELP_TEXT``,
s19_app/tui/screens.py:1117:            - :data:`VARIANT_HELP_TEXT`
s19_app/tui/screens.py:1123:        >>> screen = VariantHelpScreen()  # doctest: +SKIP
s19_app/tui/screens.py:1130:                VARIANT_HELP_TEXT,
s19_app/tui/screens.py:1152:            logger.info("VariantHelpScreen dismissed by close.")
s19_app/tui/window_help.py:12:The modal is the shipped :class:`~s19_app.tui.screens.VariantHelpScreen`
s19_app/tui/window_help.py:627:    sequence. Joined with blank paragraphs, the VariantHelpScreen voice.
s19_app/tui/window_help.py:661:        Generalizes the shipped :class:`VariantHelpScreen` pattern from
```

Notes on this output:
- `check_preview_toggle_button` (G3's removed id) no longer appears anywhere under `s19_app` — verified with `git grep -n -w check_preview_toggle_button -- s19_app` (no hits).
- The eight `screens.py` hits are G1's `VariantHelpScreen` / `VARIANT_HELP_TEXT`, not yet removed (G1 runs in parallel).
- The three `window_help.py` hits are the BL-I12-1 docstrings, expected to remain (the pinned I-3 expected output).
- `app.py` is already clean of the removed names (G2, parallel).

Test hits (expected until testers G-T1/G-T2 finish): the full pinned scope `-- s19_app tests` still returns 12 lines under `tests/` at snapshot time — `check_preview_toggle_button` in `tests/b97_fixtures.py:139` and `tests/test_b97_check_editor.py:987/997/1042` (G-T2's), and the other groups' names in `tests/test_tui_app.py`, `tests/test_tui_goto_marker.py`, `tests/test_tui_variants.py`, `tests/test_window_usage_help.py` (G-T1's).
