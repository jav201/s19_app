# Inc 12 — E4 implementation notes (G1 dialogs)

Batch 2026-11-01-batch-101, increment 12. Implementer G1 dialogs (E4). Files touched:
- `s19_app/tui/screens.py`
- `docs/user-guide/ch16-reports.md`
- `docs/user-guide/ch18-flow-execution.md`
- `docs/user-guide/DOSSIER.md`

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| s19_app/tui/screens.py | `VARIANT_HELP_TEXT` | `[Data: VARIANT_HELP_TEXT]` | removed with `VariantHelpScreen` (D-1 A) |
| s19_app/tui/screens.py | `VariantHelpScreen` | `VariantHelpScreen` | removed (D-1 A) |
| s19_app/tui/screens.py | `ReportViewerScreen.BINDINGS` | `[Data: ReportViewerScreen.BINDINGS]` | added plain, non-priority `Binding("escape", "close_reports", "Close", show=False)` (I-1) |
| s19_app/tui/screens.py | `ReportViewerScreen.action_close_reports` | `ReportViewerScreen.action_close_reports` | new (D-7 A; I-1): logs `ReportViewerScreen dismissed by Esc.` and calls `self.dismiss(None)`; posts no message |
| docs/user-guide/ch16-reports.md | Features table (last row) | `[I/O: docs/user-guide/ch16-reports.md]` | row `Open reports/, `?`, Close · chips, button · 16.1` split into `Open reports/, `?` · chips · 16.1` and `Close · button / `esc` · 16.1`; line 26 unchanged |
| docs/user-guide/ch18-flow-execution.md | step 5 | `[I/O: docs/user-guide/ch18-flow-execution.md]` | `Close it with **Close** — `esc` does not close this viewer (finding F-51).` → `Close it with **Close** or `esc`.` |
| docs/user-guide/DOSSIER.md | rows F-33, F-34, F-35, F-51 | `[I/O: docs/user-guide/DOSSIER.md §5]` | each Kind cell gains ` · fixed in 1.0.0` (F-35 marked because Inc 12b is already merged) |

## 2. Deviations from the graph (each with its reason) — or "none"

None.

## 3. Open questions for the integrator — or "none"

None.

## 4. Checks

py_compile per file (exact command and output):

- `s19_app/tui/screens.py` — `<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/screens.py` → no output, exit 0.
- The three Markdown docs are not compiled.

Pinned I-3 grep (`git grep -n -w …` exactly as written in the graph), output as of this run (test hits expected until the testers finish):

```
s19_app/tui/window_help.py:12:The modal is the shipped :class:`~s19_app.tui.screens.VariantHelpScreen`
s19_app/tui/window_help.py:627:    sequence. Joined with blank paragraphs, the VariantHelpScreen voice.
s19_app/tui/window_help.py:661:        Generalizes the shipped :class:`VariantHelpScreen` pattern from
tests/test_tui_app.py:658:    line = app._format_validation_issue_line(filtered[0])
tests/test_tui_app.py:685:    app._jump_to_validation_issue(FakeItem())  # type: ignore[arg-type]
tests/test_tui_goto_marker.py:502:            app.action_view_alt()
tests/test_tui_goto_marker.py:504:            app.action_view_mac()
tests/test_tui_goto_marker.py:506:            app.action_view_main()
tests/test_tui_variants.py:607:            from s19_app.tui.screens import VariantHelpScreen
tests/test_tui_variants.py:610:            app.push_screen(VariantHelpScreen())
tests/test_window_usage_help.py:8:``VariantHelpScreen`` pattern: a per-window modal with numbered steps in plain
```
