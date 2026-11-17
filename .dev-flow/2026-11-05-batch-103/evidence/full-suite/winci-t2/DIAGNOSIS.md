# WinCI T2 driver diagnosis

## Baseline

- Source revision: `90f451bf3ed5193eca72371aa0b62a403e1529d6` (`main`).
- Failed run: `44183525998`.
- JUnit tally: 260 tests; 199 passed, 17 failed, 44 skipped, 0 errors.
- Gate tally: 94/108 obligations; AT 14/28 (P1 7/14, P2 7/14).
- Original pytest, JUnit, gate and artifact-safety outputs are preserved under `baseline-run-44183525998/`.

## Reproduced symptoms

Fourteen `AT-I1b-{1..7}/{3,4}` cells fail in `_prepare_target` before either paste route: `app.focused` is `PatchEditorPanel`, not `JsonHighlightTextArea#patch_paste_text`. The three failing `multi` clipboard cases share the same JSON-tab preparation and then right-click a buffer that was not made visible/really focused. Their outcomes are empty fallback, unchanged dummy text, or expected text not arriving.

## Ranked hypotheses and result

1. A bare click misses the JSON chip or paste buffer in the new scrollable Patch Editor. Confirmed by comparison with the Inc8/Inc8b canon: `show_tab` and `click_visible` call `scroll_visible` before clicking; the clipboard drivers did not.
2. Fixed pause counts do not establish layout, hit-testing or focus. Confirmed by the focus assertion and by the canonical wait for `region.area > 0`.
3. The multiline right-click can use the single-line row and race the paste tail. Addressed with row 1 for `multi`, `wait_for_hit=True`, and the existing bounded `_wait_for_box` oracle.
4. A product handler resets focus to the panel. Not supported: `PatchEditorPanel._show_tab` only changes the selected pane, classes, title and subtitle. No product change was made.

## Minimal driver correction

- `tests/support/b103_clipboard.py`: `show_patch_paste` now uses canonical `show_tab`/`click_visible`, waits for a non-zero paste-buffer region and for real focus.
- `tests/test_b103_copy_paste_matrix.py`: JSON activation uses `show_tab`; T2 preparation requires a laid-out buffer, reveals/clicks it, and checks focus before and after F7.
- `tests/test_b103_clipboard_windows.py`: only the three failed right-click arms use an explicit single/multi row and wait for a real hit; the two non-timing fallback cases wait for expected content instead of a fixed 0.2 s pause. Existing equality and timing oracles remain intact.

No payloads, first-line/multiline expectations, AT cell cardinality, manifest obligations, timing bounds, or product files changed.

## Local verification (no real clipboard access)

- `python tests/support/b103_winci_gate.py --validate-manifest`: `WINCI_MANIFEST_OK tests=260 obligations=108 at_p1=14 at_p2=14`.
- `python -m pytest -q tests/test_b103_winci_gate.py`: 214 passed.
- `python -m pytest --collect-only -q tests/test_b103_clipboard_windows.py tests/test_b103_copy_paste_matrix.py`: 106 collected, including all 28 AT cells and the manual case; no test body or fixture executed.
- `python -m py_compile` on all three changed Python files: passed.
- `git diff --check`: passed.

The real clipboard end-to-end feedback loop is exclusively the isolated hosted Windows workflow. No local clipboard probe, `GITHUB_ACTIONS` override, product assumption, merge, or G3 closure is part of this change.
