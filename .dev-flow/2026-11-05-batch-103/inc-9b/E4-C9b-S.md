# Inc 9b E4 C9b-S hand-back (2026-11-15T10:26:42Z)

Files: `s19_app/tui/app/patch.py`, `s19_app/tui/screens_directionb/patch_editor/panel.py` (8 nodes). Model Sonnet.

Examples run on rtx (HT-02 env, quiet host, load ~0.5, `s19_app.__file__` = <runner>/tree/s19_app/__init__.py, base tree + my two files only), throwaway probe (not in the repo), 4 passed:
- EX-BC6 (VAL_BLK_DEF_0001, Set 10, alt+s): order document_view 0.01, refresh_entries 0.16, refresh_sheet_document 0.32, refresh_bindings 0.48, update_checks_view 0.48, record_done 0.48 (once, last); 1 entry.
- EX-BC14: Undo fired after step 2 -> steps 3-4 skipped, record_done once (0.35 s), 0 entries.
- EX-BC9 (Set 60): record_done once at 0.004 s, no refresh call.
- exactly-once: ok chain 3 steps done=1; first step raising: calls=[0], done=1, re-raised.
- Existing test_b103_inc9_w_jobs R-PE-BENCH.82/1: PASSED after the panel guard (below); FAILED before it.

## Deviations from the graph (to rule)
1. Extra node `PatchMixin._patch_refresh_tail` holds step 4's body (keeps functions small, original comments kept).
2. `_run_refresh_steps` also skips the rest when `#patch_editor_panel` is not queryable (app closing / screen gone): without it a pending timer step raised NoMatches at teardown (82/1 failed). Pending add to node text.
3. `_patch_document_token` uses `tuple(sorted(history_depths().items()))` (dict is unhashable-as-token).
4. Raise on a LATER step (inside a timer callback) is not exercised: it would crash the app in Textual; on_done still runs once before the re-raise.
