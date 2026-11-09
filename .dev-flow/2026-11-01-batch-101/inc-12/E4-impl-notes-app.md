# Inc 12 — E4 implementation notes (G2 app)

Batch 2026-11-01-batch-101, increment 12. Implementer G2 app (E4). Files touched: `s19_app/tui/app.py`.

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| s19_app/tui/app.py | `S19TuiApp.action_view_main` | removed (D-2 A) | removed |
| s19_app/tui/app.py | `S19TuiApp.action_view_alt` | removed (D-2 A) | removed |
| s19_app/tui/app.py | `S19TuiApp.action_view_mac` | removed (D-2 A) | removed |
| s19_app/tui/app.py | `S19TuiApp.action_a2l_tag_find_next` | removed (E3A-R2-1, as D-2 A) | removed |
| s19_app/tui/app.py | `S19TuiApp._handle_a2l_tag_find_next` | changed (docstring only) | "Used by" drops ``action_a2l_tag_find_next``, keeps ``on_button_pressed`` for ``a2l_tag_find_next`` |
| s19_app/tui/app.py | `S19TuiApp._jump_to_validation_issue` | removed (D-2 A, D3-7) | removed |
| s19_app/tui/app.py | `S19TuiApp._jump_to_validation_issue_object` | removed (D-2 A, D3-7; I-6) | removed |
| s19_app/tui/app.py | `S19TuiApp._format_validation_issue_line` | removed (D-2 A, D3-7) | removed |
| s19_app/tui/app.py | `S19TuiApp._update_issues_hex_pane` | changed (docstring and comment only) | "Used by" names ``on_issue_row_selected`` in place of ``_jump_to_validation_issue_object``; comment "a headless unit-test call to the jump path" reworded to "a call with no mounted screen" |

No module-level change. `ListItem`, `ValidationIssue`, `ValidationSeverity` imports left untouched (still used elsewhere). No Inc 10a / 10b function changed.

## 2. Deviations from the graph — none

## 3. Open questions for the integrator — none

## 4. Checks

py_compile (exact command and output):

```
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/app.py
```

Output: empty; exit code 0.

Pinned I-3 grep over `s19_app` (mid-parallel state; G1's `screens.py` and the three BL-I12-1 `window_help.py` docstring lines remain, G3's `screens_directionb.py` is already clean, and `app.py` has zero hits):

```
git grep -n -w -e VariantHelpScreen -e VARIANT_HELP_TEXT -e action_view_main -e action_view_alt -e action_view_mac -e action_a2l_tag_find_next -e _jump_to_validation_issue -e _jump_to_validation_issue_object -e _format_validation_issue_line -e check_preview_toggle_button -- s19_app
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

`app.py` contributes no line to this grep (the removed names are gone; the kept button id `a2l_tag_find_next` and `_handle_a2l_tag_find_next` are not in the pattern).
