# E4 handoff — Inc 1a implementer (DeepSeek v4 Pro): clipboard core, instant paste

## 1. Reference (dev-flow v3 + Code-Wire v3.1; latest as of 2026-11-07)
s19_app (Textual 8.2.8 / rich 15), batch `batch-103`, records under `.dev-flow/2026-11-05-batch-103/` (start with `PLAN.md`, the Inc 1a row and amendment A1). Versions: **dev-flow v3 beta** `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` (commit `d858a9a`; read stage E4 whole); **Code-Wire v3.1.0** `C:\Users\jjgh8\Github\code-wire` tag `v3.1.0` = `e436a08` (core only: examples from the requirements; `tools/codewire_extract.py` finds callers and drift; testers turn examples into failing tests). **tui-design:** not used (the right-click handlers add no visible element or render).

## 2. Role
**E4 implementer: implement the approved graph's 1a nodes; do not write tests.** An independent tester writes the tests in parallel in another worktree.

## 3. Where you work
- Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc1a-code` (branch `b103-inc1a-code`), created from `batch-103`. Only there.
- Your files (the slice's 2 source files + 1 config file; under the 4-source-file cap):
  - **G1** `s19_app/tui/os_clipboard_input.py` — the single-line box and the read/write layers. **Removed:** `_create_tk_root`, `_TkRootSingleton` (`__init__`, `get_or_create`, `get_existing`), `_destroy_tk_root_singleton`, `_prime_tk_root`, `_read_via_tk`, `_write_via_tk`, `_TK_ROOT`, `_TK_RETRIES`, `_TK_RETRY_DELAY_S`, the `atexit` import. **Changed:** `_read_via_ctypes`, `_read_via_powershell`, `_write_via_powershell`, `read_os_clipboard`, `write_os_clipboard` (docstring only), `_mirror_and_write_os_clipboard`, `OsClipboardInput.action_paste`, `_STRATEGIES`, `_WRITE_STRATEGIES`, `_POWERSHELL_WRITE_COMMAND`, the module and class docstrings. **New:** `_system_directory`, `_system_powershell`, `_strip_paste_controls`, `_UNSAFE_PASTE`, `OsClipboardInput._on_paste`, `.focus_on_click`, `._on_mouse_down`, `._on_click`, `OsClipboardInput._press_cursor`.
  - **G2** `s19_app/tui/capped_text_area.py` — the multi-line box. **Changed:** `CappedTextArea.action_paste`, `CappedTextArea._on_paste` (both call G1's `_strip_paste_controls` through I-1a), the module docstring. **New:** `CappedTextArea._on_mouse_down`, `._on_click`.
  - **G3** `.github/workflows/clipboard-windows.yml` (config, new) — the text pinned in the graph's "Pinned workflow" section. `tui-ci.yml` stays byte-equal to `e07fb00`'s (D-6 B).
- Touch nothing else: no test, no record, no other source. `s19_app/tui/a2l.py` is not in this increment. The graph has 39 nodes (under the 40-node cap) and 2 source files (under the 4-file cap). If the graph needs another file, stop and write it down as a deviation.
- **Do not commit** (the orchestrator commits; the tester works in a separate worktree).

## 4. Read, in this order
1. `.dev-flow/2026-11-05-batch-103/inc-1a/codewire/graph-inc1a.md` — the design. Its "Groups for E4 (file ownership)" section says which files you own (G1, G2, G3) and its "Interfaces" section pins I-1 (items 1–7) and I-1a. **Implement only the 1a nodes**; Inc 1b's copy-from-views and copy notice (P-1 … P-4) are PROPOSED for Inc 1b's E2, not written now — do not stub them.
2. `inc-1a/01-requirements.md` — the 40 active rows and the Definitions; the right-click rows R-PASTE.24 … .33 and the E3 rows R-PASTE.34 / .35 / .36.
3. `inc-1a/E3-rulings.md` — every section (rounds 1–4). Where a ruling and the graph disagree, the ruling wins; write the deviation down. The E3A/E3S findings (strip set and NUL-out rule, `restrict` boxes refused whole, the `GlobalSize` read bound, the copy tail calling the toolkit base `App.copy_to_clipboard`, the suite guard) are binding.
4. `inc-1a/E1-slice.md` (the function map, §5 the tests E4 re-points, §7 the right-click addendum), `inc-1a/E1-rulings.md` (D-1 … D-11 with the orchestrator's and operator's rulings; §5 and A5 interfaces), `inc-1a/E2-rulings.md`.
5. Base code you change: `s19_app/tui/os_clipboard_input.py` and `s19_app/tui/capped_text_area.py` (as at `e07fb00`); the helper you import: `_CONTROL_SCRUB` in `s19_app/utils.py` (read only); the toolkit lines the graph cites (textual 8.2.8 `widgets/_input.py:786-791`, `widgets/_text_area.py:1948-1957`, `message_pump.py:743-800`, `screen.py:1933-1939`).
6. `CLAUDE.md`, `PROJECT_RULES.md` (style, type hints, docstrings with Summary / Args / Returns / Raises / Data Flow / Dependencies).

## 5. Rules
- English code, comments, docstrings; match the repo's style. The new layers use the standard library (`ctypes`, `subprocess`, `os`/`shutil` as the graph names) and the module's existing Textual imports; no new dependency. The removed Tk layer must leave no `tkinter` import behind in either file.
- **On this PC you may run only** `python -m py_compile <your file>` and `python C:\Users\jjgh8\Github\code-wire\tools\codewire_extract.py`. **Do not run pytest, the app, or any Python that imports or loads your module or `s19_app`** (not even through `importlib`; a previous run did that and it was a rule breach). The orchestrator runs every test on the Linux runner.
- Never push, merge, force, `reset --hard`, delete a branch, or commit. Never write the operator's name. No secrets. Never write the operator's clipboard (nothing on this PC opens one).
- If the graph or a requirement looks wrong, write it down as a deviation. Never change a requirement or a pinned interface to match your code.

## 6. Stop and report (≤ 300 words)
What you implemented (node → function, one line each); the file and its line count; commands run with exit codes; deviations (node, what, why); open questions.
