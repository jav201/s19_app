# Code-Wire graph — Inc 1a (clipboard core: a paste lands at once; right-click in text boxes), batch-103

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree; the extractor marks went into a throwaway copy under the session scratchpad (`i1a-e2-extract.sh`). Base: branch `batch-103` (`332f8ca3`), product tree `e07fb00`; every product line number is `e07fb00`'s. Records: `../01-requirements.md` (36 active rows), `../02-test-cases.md` (171 cases), `../E1-rulings.md` (orchestrator rulings D-1 A … D-8 A and I-1; operator rulings 2; the right-click addendum and its rulings D-9 A, D-10 B, D-11 A), `../E1-slice.md`. Notation: Code-Wire v3.1.0 (`e436a08`), layout as batch-101 `inc-12/codewire/graph-inc12.md`. Toolkit lines are textual 8.2.8, read on cachyos-rtx (`~/miniconda3/envs/s19ci/lib/python3.11/site-packages/textual/`).

How to read it:
- Every node's `func:` starts with **unchanged**, **changed** ("was: … / now: …"), **new** or **removed** ("was: … / now: absent"). The **baseline** is the unchanged, changed and removed nodes as they stand at `e07fb00`: the extractor checked their contracts against the code and listed their real callers (`i1a-e2-extract-transcript.txt`, run 1, exit 0). The **prototype** is the "now:" of the changed nodes plus the new nodes; no changed node changes its signature. Unchanged nodes are context: a changed or new node calls them, or their examples are a row's oracle.
- Example sources: the case ids of `02-test-cases.md` (`R-…/n`, `AT-I1a-n`); B = the E1 pilots (`../evidence-e1/i1a-pilot*-transcript.txt`, P1 … P16, L1 … L4); C = the E1 census; F = `prototypes/b103_ux/findings/C-hotfixes-1-3.md` (the operator-PC probes of 2026-11-05); R = read (product code, toolkit, documentation); X = this stage's extractor run. Each example states the target after Inc 1a unless it says "base" or "holds on base"; "neg" marks the row's negative control.
- Fixture words are those of `02-test-cases.md` §Common fixtures: Box A (`#a2l_tags_filter_input`), Box M (`#patch_paste_text`), Box A' (`#diff_path_a`), Box M' (`#sje_manual`), Box 1 / Box 2 (one-box app), P1 = `COPY-1 Ñoño Ж 漢字 😀`, P2 = `L1 Ñ€\nL2 漢`, P1000, P70k, Select, Clear, Unfocus, Right-click (App route), Other-program write / read, Own read, Held clipboard (t), Empty Unicode text, Typed-key time, Tick lateness, OSC 52 spy, Process spy, Notices, Log capture. `bound(x)` = `tests/support/timing.timing_bound(x)`: x locally, 2x on CI.
- Platforms (D-2 A): behaviour that reads or writes the Windows clipboard is exemplified on **WinCI** (the hosted Windows job); the **LinuxH** arms exemplify the app-clipboard path (R-TUI-043.6, R-PASTE.9); **LinuxX** cases stay blocked (E1-rulings §7).

### Groups for E4 (file ownership)

| Group | Files | Owns |
|---|---|---|
| G1 single-line box and the layers | `s19_app/tui/os_clipboard_input.py` | removed `_create_tk_root`, `_TkRootSingleton.__init__`, `.get_or_create`, `.get_existing`, `_destroy_tk_root_singleton`, `_prime_tk_root`, `_read_via_tk`, `_write_via_tk`, `[Data: _TK_ROOT]`; changed `_read_via_powershell`, `_write_via_powershell`, `read_os_clipboard`, `write_os_clipboard` (docstring), `_mirror_and_write_os_clipboard`, `OsClipboardInput.action_paste`, `[Data: _STRATEGIES]`, `[Data: _WRITE_STRATEGIES]`, `[Data: _POWERSHELL_WRITE_COMMAND]`, the module and class docstrings; new `_system_directory`, `_system_powershell`, `OsClipboardInput._on_paste`, `.focus_on_click`, `._on_mouse_down`, `._on_mouse_up`, `._on_click`, `[Data: OsClipboardInput._press_cursor]` |
| G2 multi-line box | `s19_app/tui/capped_text_area.py` | changed `CappedTextArea.action_paste`, the module docstring; new `CappedTextArea._on_mouse_down`, `._on_mouse_up`, `._on_click` |
| G3 CI | `.github/workflows/clipboard-windows.yml` (config, new) | `[I/O: .github/workflows/clipboard-windows.yml]`, pinned below |
| G-T testers | `tests/support/b103_clipboard.py` (new); the test files of `../E1-slice.md` §6 (`tests/test_b103_clipboard_core.py`, `_windows.py`, `_matrix.py`; E4 fixes the names); the retirements and re-points of `../E1-slice.md` §5 | `require_isolated_clipboard`, `clipboard_probe`, `os_clipboard_ready` |

G1 and G2 are 2 source files (budget 4) and can be one implementer; G2 uses G1 only through I-1a. Order inside E4: G1 ∥ G2 ∥ G3; testers in parallel.

### Interfaces

| Id | Pinned form | Producer → consumers |
|---|---|---|
| I-1 OS clipboard read / write and the copy tail (PLAN I-1; `../E1-rulings.md` §5, A5; orchestrator ruling I-1) | items 1 … 7 below | G1, G2 → Inc 1b, Inc 7 (paste modal: a `CappedTextArea`), Inc 8 / 9 (editors: their boxes are `OsClipboardInput` / `CappedTextArea`) |
| I-1a inside Inc 1a | `capped_text_area.py` imports `_CLIPBOARD_CAP_CHARS`, `_PASTE_FAIL_NOTIFICATION` and `_mirror_and_write_os_clipboard` from `os_clipboard_input` (`:99-103`, unchanged) and reads through the module, `_os_clipboard_input.read_os_clipboard` (`:213`, the seam a single monkeypatch covers for both classes); it no longer calls `_os_clipboard_input._prime_tk_root` (`:211`, removed) | G1 → G2 |

**I-1, what Inc 1a exposes** (Inc 1b's app-level seam calls these and must not write twice):
1. `read_os_clipboard(strategies: Optional[tuple[tuple[str, Callable[[], Optional[str]]], ...]] = None) -> Optional[str]`. Blocking: callers run it in the default executor. Windows: the Win32 read (5 × 20 ms retries), then the system PowerShell (one start, ≤ 2.0 s); a layer's `''` counts as no text; the first text is cut to 65,536 characters; `None` when no layer gives text, with one WARNING `read_os_clipboard: every strategy failed (cascade=['ctypes-win32', 'powershell'])`. Off Windows: `None` at once, no process started. Never raises.
2. `write_os_clipboard(text: str, strategies: Optional[tuple[tuple[str, Callable[[str], bool]], ...]] = None) -> bool`. Blocking (executor). Cuts `text` to 65,536 first; Windows: Win32, then the system PowerShell (payload on stdin, ≤ 2.0 s); `True` at the first success; `False` with one WARNING `write_os_clipboard: every strategy failed (cascade=['win32', 'powershell'])`. Off Windows `False` at once. Never raises; shows no notice; does not touch the app clipboard.
3. `async _mirror_and_write_os_clipboard(app: App, text: str) -> None`: **the one copy tail**. Every copy of Inc 1a (Ctrl+C, Ctrl+X with a selection, the multi-line line cut, the right-click copy) calls it exactly once. Per call: exactly one `app.copy_to_clipboard(text[:65536])` (the app clipboard and one OSC 52 request, stock `App.copy_to_clipboard`, textual `app.py:1770-1786`), exactly one `write_os_clipboard(text[:65536])` in the default executor, and on `False` exactly one notice (`_WRITE_FAIL_NOTIFICATION`, `severity="warning"`, `timeout=6.0`) and one WARNING `OS clipboard write failed; retained Textual internal clipboard only`; on `True` no notice (Inc 1a adds none, ruling I-1).
4. Constants unchanged: `_CLIPBOARD_CAP_CHARS = 65536`, `_CLIPBOARD_READ_CAP_CHARS` (alias), `_PASTE_FAIL_NOTIFICATION` = `Clipboard read failed — try Ctrl+Shift+V or type the path manually.`, `_WRITE_FAIL_NOTIFICATION` = `Clipboard write failed — copied inside the app only.`, `_POWERSHELL_TIMEOUT_S = 2.0`.
5. Classes: `OsClipboardInput(Input)` and `CappedTextArea(TextArea)` keep their names, bases and constructors; `action_copy`, `action_cut`, `action_paste` keep their names (reached by the toolkit bindings `ctrl+c`, `ctrl+x`, `ctrl+v`). Callers outside the slice import only `OsClipboardInput`, `_CLIPBOARD_CAP_CHARS`, `_CLIPBOARD_READ_CAP_CHARS` (`../E1-slice.md` §3): no importer changes.
6. Removed names (no product caller outside the two files; X, `git grep`): `_create_tk_root`, `_TkRootSingleton`, `_destroy_tk_root_singleton`, `_TK_ROOT`, `_prime_tk_root`, `_read_via_tk`, `_write_via_tk`, `_TK_RETRIES`, `_TK_RETRY_DELAY_S`.
7. Right-click ownership (D-11 A, E1 A5): a button-3 `MouseDown`, `MouseUp` and `Click` on a text box are handled by the box and stopped; no ancestor and no App handler receives them. The press acts once; the release and the click act on nothing.

**PROPOSED for Inc 1b's E2** (Inc 1a does not decide them):
- **P-1 Where the one copy notice lives.** The tail is the one call per copy and the only place that knows the result, so the success notice and the write failure warning fit there together. (a) Inc 1b changes `_mirror_and_write_os_clipboard` to show its copy notice on `True` and keeps the warning on `False`: every copy (text boxes, views) gets it with no call-site change. (b) The tail returns `bool` and Inc 1b's app-level seam notifies; then every text-box call site (`action_copy`, `action_cut` × 2 classes, through them the right-click) moves to the seam. Inc 1a ships (neither): the tail returns `None`.
- **P-2 No second OS write.** An `S19TuiApp.copy_to_clipboard` override must not write the OS clipboard while the tail does: the tail calls `app.copy_to_clipboard` first (`:764`), so such an override would write the Windows clipboard twice per text-box copy (and notify twice if it notified). Moving the OS write into `copy_to_clipboard` means removing the tail's executor write in the same change.
- **P-3** A copy from a view calls the tail once (`../E1-rulings.md` §5); on Linux it shows the write failure warning (D-2 A).
- **P-4** Inc 1b's app-level right-click never receives a text box's right-click (item 7); a view that contains a text box needs no exclusion of its own.

### Baseline callers (X, run 1: 23 marks, 23 nodes, 0 findings, exit 0)

The extractor ran on a marked copy of `s19_app/` whose marks replace the blank line above each def, so its sites are `e07fb00` lines (worktree HEAD `cfa63f67`, `git diff e07fb00 -- s19_app` empty). It found **no top-level site**: no function outside these 23 calls one of them by name. Callables passed as values through an attribute, module-level tuples and toolkit dispatch are not seen by it; those rows are R.

| Callee | Callers (base) | How known |
|---|---|---|
| `_mirror_and_write_os_clipboard` | `OsClipboardInput.action_copy` `os_clipboard_input.py:864`, `.action_cut` `:892`; `CappedTextArea.action_copy` `capped_text_area.py:268`, `.action_cut` `:306` | X |
| `read_os_clipboard` | `OsClipboardInput.action_paste` `:906` (passed to `run_in_executor`); `CappedTextArea.action_paste` `capped_text_area.py:213` (as `_os_clipboard_input.read_os_clipboard`) | X; R |
| `write_os_clipboard` | `_mirror_and_write_os_clipboard` `:769` (passed to `run_in_executor`) | X |
| `_bound_clipboard_text` | `read_os_clipboard` `:653` | X |
| `_prime_tk_root` (removed) | `OsClipboardInput.action_paste` `:900`, `_mirror_and_write_os_clipboard` `:767`, `CappedTextArea.action_paste` `capped_text_area.py:211` | X |
| `_TkRootSingleton.get_or_create` (removed) | `_prime_tk_root` `:241`, `_read_via_tk` `:259` | X |
| `_TkRootSingleton.get_existing` (removed) | `_write_via_tk` `:481` | X |
| `_create_tk_root` (removed) | `_TkRootSingleton.get_or_create` `:201` | X |
| `_destroy_tk_root_singleton` (removed) | `_TkRootSingleton.get_or_create` `:207` (passed to `atexit.register`) | X |
| `_TkRootSingleton.__init__` (removed) | the module statement `_TK_ROOT = _TkRootSingleton()` `:228` | R |
| `_read_via_ctypes`, `_read_via_powershell`, `_read_via_tk` | only through `[Data: _STRATEGIES]` (`:547-551`), iterated by `read_os_clipboard` `:645-657` | R |
| `_write_via_ctypes`, `_write_via_powershell`, `_write_via_tk` | only through `[Data: _WRITE_STRATEGIES]` (`:558-562`), iterated by `write_os_clipboard` `:709-716` | R |
| `OsClipboardInput.action_copy`, `.action_cut`, `.action_paste` | the toolkit bindings `ctrl+c`, `ctrl+x`, `ctrl+v` (textual `_input.py:138-140`); after Inc 1a also `OsClipboardInput._on_mouse_down` (copy, paste) | R |
| `CappedTextArea.action_copy`, `.action_cut`, `.action_paste`, `._on_paste` | the `TextArea` bindings (`_text_area.py:374-391`) and the message pump on `events.Paste` (forwarded by `App.on_event`, textual `app.py:4142-4146`); after Inc 1a also `CappedTextArea._on_mouse_down` (copy, paste) | R |
| class `OsClipboardInput` / `CappedTextArea` | 40 / 7 constructions in 8 modules (`JsonHighlightTextArea`, `json_highlight.py:261`, is the one subclass; no subclass defines a mouse handler or `focus_on_click`: `git grep` 0) | C; R |

Tests that name changed or removed names (`../E1-slice.md` §5, re-read here): `tests/test_clipboard_tk_singleton.py` (retired); `tests/test_b102_clipboard.py:590`, `:628-640` and `tests/test_loadfilescreen_input.py:490`, `:528`, `:548`, `:603` call `_read_via_powershell` / `_write_via_powershell` directly (re-pointed through `_system_powershell`; `:603`, the non-Windows no-op, holds unchanged).

### Pinned workflow (G3, R-PASTE.20; D-6 B with the orchestrator's triggers)

```yaml
name: clipboard-windows

# The OS clipboard tests of batch-103 Inc 1a (R-PASTE.20): Windows only, on a
# GitHub-hosted runner, whose clipboard belongs to no person (R-PASTE.21).
# Separate from tui-ci.yml (D-6 B), which stays unchanged.
on:
  workflow_dispatch:
  push:
    paths:
      - "s19_app/tui/os_clipboard_input.py"
      - "s19_app/tui/capped_text_area.py"
      - "tests/support/b103_clipboard.py"
      - "tests/test_b103_clipboard_windows.py"
      - "tests/test_b103_clipboard_matrix.py"
      - ".github/workflows/clipboard-windows.yml"
  pull_request:
    paths:
      - "s19_app/tui/os_clipboard_input.py"
      - "s19_app/tui/capped_text_area.py"
      - "tests/support/b103_clipboard.py"
      - "tests/test_b103_clipboard_windows.py"
      - "tests/test_b103_clipboard_matrix.py"
      - ".github/workflows/clipboard-windows.yml"

permissions:
  contents: read

jobs:
  clipboard-windows:
    runs-on: windows-latest
    timeout-minutes: 30
    steps:
      - name: Check out repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          python -m pip install -r requirements.txt
          python -m pip install pytest
          python -m pip install -e .

      - name: Run the OS clipboard tests (serial, every outcome listed)
        run: pytest -v -rs tests/test_b103_clipboard_windows.py tests/test_b103_clipboard_matrix.py
```

The two test-file names are `../E1-slice.md` §6's proposals; E4 keeps the `paths` list and the run line equal to the names it fixes (R-PASTE.20/1 reads both). No `-n` and no `-m`: the timing arms run serially and nothing is deselected. Actions and versions as `tui-ci.yml` (`actions/checkout@v4`, `actions/setup-python@v5`, Python 3.11). The `-v` replaces the slice's `-q` so that the log lists each test's outcome (R-PASTE.20/2).

### Coverage (every active row → nodes → examples)

| Row | Nodes | Examples (case ids) |
|---|---|---|
| R-TUI-043.10.1 | `read_os_clipboard`, `[Data: _STRATEGIES]`, `_read_via_ctypes`, `OsClipboardInput.action_paste`, `CappedTextArea.action_paste`, `_create_tk_root`, `_read_via_tk` | /1, /2 (WinCI), /3, /4 (LinuxH), the neg (Tk restored); AT-I1a-9 |
| R-TUI-043.10.2 | `_read_via_ctypes`, `_read_via_powershell`, `OsClipboardInput.action_paste`, `CappedTextArea.action_paste` | /1, /2 |
| R-TUI-043.6 | `read_os_clipboard`, `OsClipboardInput.action_paste`, `CappedTextArea.action_paste`, `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down`, `_read_via_ctypes` | /1, /2, /3, /5 (/4 is LinuxX, blocked) |
| R-PASTE.1 | `OsClipboardInput._on_paste` | /1, /2, the double-insert neg; AT-I1a-2, -6 |
| R-PASTE.2 | `OsClipboardInput.action_copy`, `CappedTextArea.action_copy`, `_mirror_and_write_os_clipboard`, `write_os_clipboard`, `_write_via_ctypes`, `_write_via_tk` | /1, /2, both negs |
| R-PASTE.3 | `_mirror_and_write_os_clipboard`, `OsClipboardInput.action_copy`, `CappedTextArea.action_copy` | /1, /2 |
| R-PASTE.4 | `OsClipboardInput.action_copy`, `CappedTextArea.action_copy` | /1, /2 |
| R-PASTE.5 | `OsClipboardInput.action_copy`, `.action_cut`, `CappedTextArea.action_copy` | /1, /2, /3 |
| R-PASTE.6 | `OsClipboardInput.action_cut`, `CappedTextArea.action_cut` | /1, /2 |
| R-PASTE.7 | `OsClipboardInput.action_cut`, `CappedTextArea.action_cut` | /1, /2 |
| R-PASTE.8 | `CappedTextArea.action_cut` | /1 |
| R-PASTE.9 | `_mirror_and_write_os_clipboard`, `write_os_clipboard`, `OsClipboardInput._on_mouse_down` | /1, /2, /4 (/3 LinuxX, blocked) |
| R-PASTE.10 | `_mirror_and_write_os_clipboard`, `write_os_clipboard` | /1, /2 |
| R-PASTE.11 | `_mirror_and_write_os_clipboard`, `[Data: _WRITE_STRATEGIES]`, `_write_via_ctypes`, `_write_via_tk` | /1, /2, /3, both negs |
| R-PASTE.12 | `_mirror_and_write_os_clipboard`, `write_os_clipboard`, `CappedTextArea.action_copy`, `CappedTextArea._on_mouse_down` | /1, /2, /3 |
| R-PASTE.13 | `_write_via_ctypes`, `_write_via_powershell`, `_mirror_and_write_os_clipboard`, `_write_via_tk` | /1, /2 |
| R-PASTE.14 | `_mirror_and_write_os_clipboard` | /1, /2 |
| R-PASTE.15 | `_mirror_and_write_os_clipboard`, `OsClipboardInput.action_copy`, `.action_cut`, `CappedTextArea.action_copy`, `.action_cut`, `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down` | /1 … /7 |
| R-PASTE.16 | `_system_directory`, `_system_powershell`, `_read_via_powershell`, `_write_via_powershell`, `[Data: _POWERSHELL_WRITE_COMMAND]` | /1, /2, /3; the TC-B102-04 / -05 re-points |
| R-PASTE.17 | `_system_directory`, `_system_powershell`, `_read_via_powershell`, `_write_via_powershell` | /1, /2 |
| R-PASTE.18 | `CappedTextArea.action_paste`, `CappedTextArea.action_copy`, `[Interface: text boxes]` | /1 … /8 |
| R-PASTE.19 | `OsClipboardInput.action_copy`, `CappedTextArea.action_copy`, `[Interface: text boxes]` | /1, /2 |
| R-PASTE.20 | `[I/O: .github/workflows/clipboard-windows.yml]` (examples in its `desc:`) | /1, /2 |
| R-PASTE.21 | `require_isolated_clipboard`, `os_clipboard_ready` | /1, /2, /3 |
| R-PASTE.22 | `os_clipboard_ready`, `clipboard_probe` | /1, /2 |
| R-PASTE.23 | `clipboard_probe` | /1, /2 |
| R-PASTE.24 | `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down` | /1, /2, /3; AT-I1a-16 … 27 |
| R-PASTE.25 | `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down` | /1, /2, /3 |
| R-PASTE.26 | `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down`, `OsClipboardInput.focus_on_click` | /1, /2, /3 |
| R-PASTE.27 | `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down` | /1, /2, /3 |
| R-PASTE.28 | `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down` | /1, /2 |
| R-PASTE.29 | `OsClipboardInput.focus_on_click`, `OsClipboardInput._on_mouse_down`, `[Data: OsClipboardInput._press_cursor]`, `[Data: box selection]` | /1, /2, /3, both negs (D-9 B, D-10 A); AT-I1a-12, -14, -24, -26 |
| R-PASTE.30 | `CappedTextArea._on_mouse_down` | /1, /2, the D-10 A neg; AT-I1a-13, -15, -25, -27 |
| R-PASTE.31 | `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down` | /1 … /4; AT-I1a-9 |
| R-PASTE.32 | `OsClipboardInput._on_mouse_down`, `CappedTextArea._on_mouse_down` | /1, /2 |
| R-PASTE.33 | both `_on_mouse_down`, both `_on_mouse_up`, both `_on_click`, `[Interface: text boxes]` | /1, /2 |

Cited canon rows that the changed nodes touch, with examples here: R-TUI-044.2 (D-5 A: `OsClipboardInput._on_paste`, `.action_paste`, `CappedTextArea._on_paste`, `_bound_clipboard_text`, `CappedTextArea._on_mouse_down`, `OsClipboardInput._on_mouse_down`; /1 … /6), R-TUI-043.9 (both `action_paste`; /1, /2), R-TUI-043.4 (/1), R-TUI-044.3 (/1), R-TUI-043.5 (/1 … /3), R-TUI-043.7 and .8 (/1, /2), R-TUI-043.11 (/1, /2), R-TUI-043.12 (/1, /3), R-TUI-043.13 (/1, /2), R-TUI-044.1 (/2, /11, /18), R-TUI-044.4 (/1). The acceptance matrix AT-I1a-1 … 8 sits on the copy and paste nodes it crosses; AT-I1a-10 and AT-I1a-11 are operator-run and have no graph example (they observe the operator's own terminal and clipboard, which no node models). **No active row lacks an example.**

### Size and deviations from the E1 slice

- **Nodes: 36** — 13 new (10 product, 3 test support), 7 changed, 8 removed, 8 unchanged context; 15 entities, 30 edges, 6 findings (lint: `not read=0`). Product: 2 source files (budget 4), 1 config file, 1 test-support module. Under the 40-node cap: no split.
- **Deviations** (each a finding below): `OsClipboardInput._on_focus` (slice §7) is replaced by `OsClipboardInput.focus_on_click` (E2-1); `_system_directory` is added beside `_system_powershell` as the system-folder seam R-PASTE.17/1 points at an empty folder; each class's `_on_mouse_up` and `_on_click` stay two handlers (two message types; the slice allowed folding them); the workflow's run line uses `-v`, not `-q` (R-PASTE.20/2). No slice file is added or dropped.

## Nodes

### Removed (D-1 A, D-3 A): the Tk layers and their root

_create_tk_root
req: R-TUI-043.10.1, R-PASTE.11
in:
out: object? root
func: removed (D-1 A, D-3 A). was: imports tkinter and creates one withdrawn `tk.Tk()`; `None` when tkinter or a display is missing (`os_clipboard_input.py:139-161`). / now: absent; the clipboard code creates no Tk root (the only one left in the process is `LoadFlowScreen._import_external`'s, BL-I1a-3).
module: s19_app/tui/os_clipboard_input.py
examples: (X, holds on base) one caller, `_TkRootSingleton.get_or_create` (`os_clipboard_input.py:201`); no other product caller
examples: (R-TUI-043.10.1/1 neg, base) once a root exists the executor Tk read waits before it fails: Ctrl+V lands after `3,401`–`3,483` ms on Windows (F §1.4 D1) and `3,178.6` ms (median) in the real app on Linux with a stand-in Tcl root (B pilot2), against a typed-key time of `175.4` ms

_TkRootSingleton.__init__
req: R-TUI-043.10.1
in:
out: _TkRootSingleton singleton
func: removed (D-1 A). was: a lock, `_root = None`, the sticky `_unavailable` and `creator_thread` (`:175-183`); one instance, `_TK_ROOT` (`:228`). / now: absent with its class and instance.
module: s19_app/tui/os_clipboard_input.py
examples: (R, holds on base) constructed only by the module statement `_TK_ROOT = _TkRootSingleton()` (`:228`); its tests, `tests/test_clipboard_tk_singleton.py` (4 nodes, TC-1815), are retired (`../E1-slice.md` §5)

_TkRootSingleton.get_or_create
req: R-TUI-043.10.1, R-PASTE.13
in:
out: object? root
func: removed (D-1 A). was: returns the shared root, creating it on the main thread only and registering `_destroy_tk_root_singleton` with `atexit` (`:185-208`). / now: absent.
module: s19_app/tui/os_clipboard_input.py
examples: (X, holds on base) callers `_prime_tk_root` (`:241`) and `_read_via_tk` (`:259`), both removed
examples: (B pilot P1-P3, base) off the main thread before the root exists → `None`; with a root, `clipboard_get` from the executor waits ≈ `1.05` s per attempt (CPython waits for a Tcl main loop)

_TkRootSingleton.get_existing
req: R-PASTE.11, R-PASTE.13
in:
out: object? root
func: removed (D-3 A). was: the shared root or `None`, never creating it (`:210-213`). / now: absent.
module: s19_app/tui/os_clipboard_input.py
examples: (X, holds on base) one caller, `_write_via_tk` (`:481`), removed

_destroy_tk_root_singleton
req: R-TUI-043.10.1
in:
out: None
func: removed (D-1 A). was: destroys the shared root once at process exit (`:216-225`), registered by `get_or_create` (`:207`); with it go the `atexit` import (`:76`) and the registration. / now: absent.
module: s19_app/tui/os_clipboard_input.py
examples: (X, holds on base) referenced only by `_TkRootSingleton.get_or_create` (`:207`, a reference passed to `atexit.register`)

_prime_tk_root
req: R-TUI-043.10.1, R-PASTE.11
in:
out: None
func: removed (D-1 A, D-3 A). was: creates the shared root when called on the main thread (`:231-241`); called by the paste and copy paths before the executor. / now: absent; its three calls go.
module: s19_app/tui/os_clipboard_input.py
examples: (X, holds on base) callers `OsClipboardInput.action_paste` (`:900`), `_mirror_and_write_os_clipboard` (`:767`), `CappedTextArea.action_paste` (`capped_text_area.py:211`)
examples: (R-TUI-043.10.1, after) a Ctrl+V on Linux with a display creates no Tk root: the read in the executor answers `None` in milliseconds (base with a stand-in root: `3,158.5` ms, B pilot P3)

_read_via_tk
req: R-TUI-043.10.1, R-TUI-043.10.2
in:
out: str? text
func: removed (D-1 A). was: read layer 1, `root.clipboard_get()` with 3 attempts × 50 ms (`:244-272`). / now: absent; `[Data: _STRATEGIES]` no longer names it.
module: s19_app/tui/os_clipboard_input.py
examples: (B pilot P3, base) Tcl stand-in root: `152.4` ms on the main thread, `3,155.0` ms in the executor → `None`
examples: (R-TUI-043.10.2, base) a held clipboard with a Tk root: `3 × 1.05` s (Tk) + `0.1` s (Win32) + ≤ `2.0` s (PowerShell) = up to `5.3` s (B pilot P3; F §1.4)

_write_via_tk
req: R-PASTE.2, R-PASTE.11, R-PASTE.13
in: str text
out: bool written
func: removed (D-3 A). was: write layer 2, `clipboard_clear` + `clipboard_append` on the shared root (`:469-490`). / now: absent; `[Data: _WRITE_STRATEGIES]` no longer names it.
module: s19_app/tui/os_clipboard_input.py
examples: (B pilot P3, base) `0.1` ms on the main thread, `1,001.3` ms in the executor → `False`; on Windows `1,093` ms (F §1.4 D2)
examples: (R-PASTE.2 neg, base) on the main thread it reports success while an unpumped Tk window owns the clipboard: another program reads `''` (F §1.4 D2)

### Changed

_read_via_powershell
req: R-PASTE.16, R-PASTE.17, R-TUI-043.10.2, R-TUI-043.11
in:
out: str? text
func: changed (R-PASTE.16, .17). was: `subprocess.run(["powershell", "-NoProfile", "-Command", "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;Get-Clipboard -Raw"], …)` by the bare name, which Windows resolves through the running program's folder, the current folder and PATH before the system folder (R, `:358-368`); `FileNotFoundError` → "not on PATH" (`:372-374`). / now: off Windows `None` (as before); `program = _system_powershell()`; `None` → one DEBUG `_read_via_powershell: system PowerShell not found`, return `None`, start nothing; else `subprocess.run([program, "-NoProfile", "-Command", <the same command>], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=_POWERSHELL_TIMEOUT_S, shell=False, creationflags=CREATE_NO_WINDOW)` under `_POWERSHELL_SUBPROCESS_LOCK`; `TimeoutExpired`, any `OSError` (a file gone between the check and the start included) or an exit code ≠ 0 → `None`; stdout without its trailing line end; `''` → `None`.
module: s19_app/tui/os_clipboard_input.py
modify: [I/O: system PowerShell] (append)
examples: (R-PASTE.16/1) WinCI, Process spy, Other-program write `PS-READ`, Held clipboard (0.3 s) so that the Win32 read fails, `ctrl+v` in Box A → `1` start whose program equals `_system_powershell()` (case-insensitive), `C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe` on the hosted runner; Box A `PS-READ` (base: the program `powershell`, R `:361`)
examples: (R-PASTE.16/3) a decoy `powershell.exe` (a copy of `sys.executable`) in the test's current folder and in a folder first on PATH, as /1 → `0` starts of either decoy path; Box A `PS-READ` (base: the current-folder decoy runs and Box A gets no `PS-READ`)
examples: (R-PASTE.17/1) WinCI, `_system_directory` pointed at an empty temporary folder, Held clipboard (8 s), app clipboard `APP-TEXT`, `ctrl+v` in Box A → `0` process starts; Box A `APP-TEXT` (R-TUI-043.6)
examples: (R-PASTE.17/1 unit, LinuxH) `sys.platform` faked `win32`, `_system_powershell` → `None`, a `subprocess.run` spy → returns `None`; the spy counts `0` calls (base: `1` call, argv[0] `powershell`)
examples: (TC-B102-04 re-point, LinuxH) `sys.platform` faked `win32`, `_system_powershell` → `C:\PS\powershell.exe`, a fake `subprocess.run` with exit `0` and stdout `PATH-1\r\n` → argv[0] `C:\PS\powershell.exe`, `timeout` `2.0`, result `PATH-1`
examples: (R-TUI-043.10.2/1, budget) a held clipboard: the start ends by its own `2.0` s timeout at the latest → `None`

_write_via_powershell
req: R-PASTE.16, R-PASTE.17, R-PASTE.13
in: str text
out: bool written
func: changed (R-PASTE.16, .17). was: `subprocess.run(list(_POWERSHELL_WRITE_COMMAND), input=text, …)` with `"powershell"` as the command's first item (`:520-522`); `FileNotFoundError` → "not on PATH" (`:528-530`). / now: off Windows `False`; `program = _system_powershell()`; `None` → one DEBUG `_write_via_powershell: system PowerShell not found`, `False`, nothing started; else `subprocess.run([program, *_POWERSHELL_WRITE_COMMAND], input=text, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=2.0, shell=False, creationflags=CREATE_NO_WINDOW)` under the lock; `True` only for exit code `0`; timeout, `OSError` or another exit code → `False`. The payload stays on stdin, never in the command line.
module: s19_app/tui/os_clipboard_input.py
modify: [I/O: system PowerShell] (append); [I/O: Windows clipboard] (replace)
examples: (R-PASTE.16/2) WinCI, Process spy, Held clipboard (0.3 s), Box A `PS-WRITE`: Select, `ctrl+c` → `1` start, the system PowerShell's absolute path; Other-program read `PS-WRITE`
examples: (R-PASTE.17/2) WinCI, the system folder an empty temporary folder, Held clipboard (8 s), Box A: Select, `ctrl+c` → `0` process starts; the write failure warning `Clipboard write failed — copied inside the app only.`
examples: (TC-B102-05 re-point, LinuxH) `sys.platform` faked `win32`, `_system_powershell` → `C:\PS\powershell.exe`, fake `subprocess.run` exit `0`, `_write_via_powershell("payload")` → `True`; argv `C:\PS\powershell.exe`, `-NoProfile`, `-Command`, `[Console]::InputEncoding=[System.Text.Encoding]::UTF8;$input | Set-Clipboard`; `input` `payload`; `payload` in no argv item; `shell` `False`; `timeout` `2.0`
examples: (R-PASTE.13/1, budget) a held clipboard: ≤ `2.0` s, then `False`

read_os_clipboard
req: R-TUI-043.6, R-TUI-043.10.1, R-TUI-043.10.2, R-TUI-043.12
in: tuple[tuple[str, Callable[[], Optional[str]]], ...]? strategies = None
out: str? text
func: changed (D-1 A; R-TUI-043.6). was: runs `_STRATEGIES` (tkinter → ctypes-win32 → powershell) and returns the first value that `is not None` (`:652`), so a Win32 `''` (an empty Unicode text, `:324`) ends the cascade as if it were text. / now: runs the cascade (default `[Data: _STRATEGIES]`: ctypes-win32 → powershell); a layer that gives `None` or `''`, or raises, counts as no text and the next layer runs; the first non-empty text goes through `_bound_clipboard_text` and comes back with one DEBUG `read_os_clipboard succeeded via <layer> (len=<n>)`; no text → one WARNING `read_os_clipboard: every strategy failed (cascade=[…])` and `None`. Docstring: the cascade and the budget `0.1` s + `2.0` s.
module: s19_app/tui/os_clipboard_input.py
examples: (R-TUI-043.6/3 unit, LinuxH) `strategies=(("a", lambda: ""), ("b", lambda: "B-TEXT"))` → `B-TEXT` (base: `''`)
examples: (R-TUI-043.6/3 unit, LinuxH) `strategies=(("a", lambda: ""), ("b", lambda: None))` → `None` and one WARNING (base: `''`, no WARNING)
examples: (R-TUI-043.6/3) WinCI, Empty Unicode text, app clipboard `APP-TEXT`, `ctrl+v` in Box A, then in Box M → both `APP-TEXT`; no paste failure warning (base: the warning, and the box text selected, R `capped_text_area.py:213-218`)
examples: (R-TUI-043.10.1/3, LinuxH) the default cascade on Linux → `None`; both layers return at once, no Tk wait (base with a stand-in Tcl root: `3,158.5` ms in the executor, B pilot P3)
examples: (R-TUI-043.12/1) LinuxH, Log capture, app clipboard `APP-TEXT`, `ctrl+v` in Box A, then Box M → per paste ≥ `1` WARNING of `s19_app.tui.os_clipboard_input`: `read_os_clipboard: every strategy failed (cascade=['ctypes-win32', 'powershell'])` (base: the cascade names `tkinter` first, B pilot P8)
examples: (R-TUI-043.13/1) WinCI, Other-program write `SECRET-TEXT-42`, `ctrl+v` → the DEBUG line `read_os_clipboard succeeded via ctypes-win32 (len=14)`; no record holds `SECRET-TEXT-42`
examples: (R-TUI-043.10.1/1 neg) `[Data: _STRATEGIES]` with the Tk pair restored first → Ctrl+V `+3,100` ms → RED wherever a Tk root can be created

write_os_clipboard
req: R-PASTE.2, R-PASTE.9, R-PASTE.10, R-PASTE.12, R-PASTE.13
in: str text; tuple[tuple[str, Callable[[str], bool]], ...]? strategies = None
out: bool written
func: changed (docstring only: the cascade `:671-673`, `:681-683`, `:694-697`). Behaviour as before: `text[:_CLIPBOARD_CAP_CHARS]`, then the cascade (default `[Data: _WRITE_STRATEGIES]`, now win32 → powershell), `True` at the first success with a DEBUG line naming the layer, else one WARNING `write_os_clipboard: every strategy failed (cascade=[…])` and `False`.
module: s19_app/tui/os_clipboard_input.py
modify: [I/O: Windows clipboard] (replace)
examples: (R-PASTE.9/1 unit, LinuxH) `write_os_clipboard("x")` → `False` at once, one WARNING `write_os_clipboard: every strategy failed (cascade=['win32', 'powershell'])` (base: the cascade names `tkinter` too)
examples: (R-PASTE.12/2) WinCI, Box A's value P70k, Select, `ctrl+c` → Other-program read `65536` characters
examples: (R-PASTE.2/1) WinCI, Box A, k = 1 … 5: Clear, type `COPY-<k> Ñ€`, Select, `ctrl+c`, Other-program read → `COPY-1 Ñ€` … `COPY-5 Ñ€` (5/5) through the Win32 layer (F §1.4 F1: `2.6` ms)
examples: (R-PASTE.13/1) WinCI, Held clipboard (8 s) → `False` after Win32 (≈ `0.1` s) and the PowerShell timeout (≤ `2.0` s)
examples: (R-PASTE.10/1) LinuxH, Log capture, a copy of `SECRET-COPY-43` → its WARNING names the layers only; no record holds `SECRET-COPY-43`

_mirror_and_write_os_clipboard
req: R-PASTE.3, R-PASTE.9, R-PASTE.10, R-PASTE.11, R-PASTE.12, R-PASTE.13, R-PASTE.14, R-PASTE.15
in: App app; str text
out: None
func: changed (D-1 A, D-3 A; I-1 item 3). was: cut, `app.copy_to_clipboard`, `_prime_tk_root()` on the UI thread (`:767`), the executor write, the warning and the WARNING line (`:762-782`). / now: the same without the priming: `text = text[:_CLIPBOARD_CAP_CHARS]`; `app.copy_to_clipboard(text)` (the app clipboard and one OSC 52 request; an exception there is logged at DEBUG and the copy goes on); `await loop.run_in_executor(None, write_os_clipboard, text)`; `True` → return; `False` → `app.notify(_WRITE_FAIL_NOTIFICATION, severity="warning", timeout=6.0)` and one WARNING `OS clipboard write failed; retained Textual internal clipboard only`. Docstring: no priming.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: App._clipboard] (replace); [I/O: terminal] (append); [I/O: Windows clipboard] (replace)
examples: (R-PASTE.3/1) LinuxH and WinCI, Box A `COPYME-1`, Select, `ctrl+c` → app clipboard `COPYME-1` (holds on base, B pilot P5)
examples: (R-PASTE.15/1) LinuxH, OSC 52 spy, Box A P1, Select, `ctrl+c` → exactly `1` request, decoding to P1 (base, B pilot P5: `COPYME-1` → `\x1b]52;c;Q09QWU1FLTE=\x07`)
examples: (R-PASTE.9/1) LinuxH, Notices: in Box A and Box M, Select + `ctrl+c`, then Select + `ctrl+x` (4 actions) → 4/4 notices `Clipboard write failed — copied inside the app only.`, severity `warning`, timeout `6.0` (holds on base, B pilot P5)
examples: (R-PASTE.9/2) WinCI, Held clipboard (8 s), Box A then Box M: Select, `ctrl+c` → 2/2 warnings, the exact text
examples: (R-PASTE.10/1) LinuxH, Log capture, Box A `SECRET-COPY-43` then Box M: Select, `ctrl+c` → per copy ≥ `1` WARNING, among them `OS clipboard write failed; retained Textual internal clipboard only`; no record holds `SECRET-COPY-43`
examples: (R-PASTE.11/1, /2) WinCI, real app, Box A (Box M with `f7` and `ctrl+x`): Typed-key time, then 10 × (type `C<k>`, Select, `ctrl+c`) → median end of the copy (Own read sees `C<k>`) ≤ Typed-key time + bound(`0.1`) s
examples: (R-PASTE.11/3) LinuxH, Box A → median time to the write failure warning ≤ Typed-key time + bound(`0.1`) s (base with a Tk root, LinuxX: the warning after `1,001` ms, B pilot P3)
examples: (R-PASTE.12/1) LinuxH and WinCI, OSC 52 spy, Box M holds P70k and Box A's value is P70k: Select, `ctrl+c` in each → the app clipboard `65536` characters; the decoded OSC 52 request `65536` characters (2/2)
examples: (R-PASTE.13/1, /2) WinCI, Held clipboard (8 s), Box A Select + `ctrl+c`; Box M `f7` + `ctrl+x` → the warning ≤ bound(`2.5`) s after the key (base with a Tk root: up to `3.1` s)
examples: (R-PASTE.14/1) WinCI, Held clipboard (8 s), Tick lateness armed, Box A Select + `ctrl+c` → ≥ `10` ticks before the end of the copy, each late by ≤ bound(`0.1`) s (neg: the write on the event loop's thread → ticks stall ≥ `1` s → RED)
examples: (R-PASTE.11 neg) `[Data: _WRITE_STRATEGIES]` led by PowerShell → `+200` ms per copy (F §1.4: `192`–`232` ms) → RED on WinCI
examples: (R-PASTE.2/1 neg) the tail without its executor write (the stock Textual copy) → the Other-program read gives the previous text → RED

OsClipboardInput.action_paste
req: R-TUI-043.6, R-TUI-043.10.1, R-TUI-043.10.2, R-TUI-044.2
in:
out: None
func: changed (D-1 A, D-5 A). was: `_prime_tk_root()` and its comment (`:895-900`); `read_os_clipboard` in the executor; `None` → `self.app.clipboard` uncut (`:908-910`); empty → select all, the paste failure warning, a WARNING; else the first line replaces the selection (`:930-932`). / now: no priming; `text = await loop.run_in_executor(None, read_os_clipboard)`; `None` → `self.app.clipboard[:_CLIPBOARD_CAP_CHARS]` (cut before the first line is taken); empty → as before; else `self.replace(text.splitlines()[0], *self.selection)` — at the cursor when there is no selection, over it otherwise; a box with `max_length`, `restrict` or `type` still refuses a value it does not allow whole (textual `Input.replace`, `_input.py:976-1012`). Gains a caller: `OsClipboardInput._on_mouse_down`.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: Input.selection] (replace)
examples: (R-TUI-044.2/2) LinuxH, Box A empty, app clipboard P70k, `ctrl+v` → Box A `65536` characters (base `70,000`, B pilot P7)
examples: (R-TUI-043.6/1) LinuxH, real app, app clipboard `APP-TEXT`, `ctrl+v` in Box A → `APP-TEXT` (holds on base, B pilot P4a)
examples: (R-TUI-043.4/1) WinCI, Box A `ab`, cursor between, Other-program write `P1 line\nsecond`, `ctrl+v` → `aP1 lineb`
examples: (R-TUI-043.5/1) WinCI, Box A `AAAA-BBBB` with `AAAA` selected, Other-program write `ZZ`, `ctrl+v` → `ZZ-BBBB`
examples: (R-TUI-043.10.1/1) WinCI, real app, Box A, P1000 by Other-program write: Typed-key time; `ctrl+v` × 10 (Clear between) → each time Box A P1000; median end of the paste ≤ Typed-key time + bound(`0.1`) s (base with a Tk root: `3,401`–`3,483` ms, F §1.4 D1)
examples: (R-TUI-043.10.1/3) LinuxH, real app, app clipboard P1000 → the same bound (holds on base without a root: `173.5` against `175.4` ms, B pilot2)
examples: (R-TUI-043.10.2/1) WinCI, app clipboard `APP-TEXT`, Held clipboard (8 s), `ctrl+v` → Box A `APP-TEXT` ≤ bound(`2.5`) s after the key (base with a Tk root: up to `5.3` s)
examples: (R-TUI-043.7/1, R-TUI-043.8/1) LinuxH, empty app clipboard, Box A `KEEP`, `ctrl+v` → one notice `Clipboard read failed — try Ctrl+Shift+V or type the path manually.`, `warning`, `6.0`; selection `(0, 4)`; value `KEEP`
examples: (R-TUI-043.9/1) WinCI, Held clipboard (8 s), Tick lateness armed, `ctrl+v` → ≥ `10` ticks before the end of the paste, each late by ≤ bound(`0.1`) s
examples: (R-TUI-044.1/2, /11) the walk in the A2L Explorer filter box and in the Load dialog `#load_path`: Clear, `ctrl+v` after the copy step → the box holds `W<n>-` + P1 again (the Load path stays under `4,096` characters)
examples: (AT-I1a-1, AT-I1a-5) Box A → Box A' route 1 → Box A' P1; Box M → Box A' route 1 → Box A' `L1 Ñ€` (the first line)

CappedTextArea.action_paste
req: R-TUI-043.6, R-TUI-043.10.1, R-TUI-043.10.2, R-PASTE.18
in:
out: None
func: changed (D-1 A). was: read-only → return; `_os_clipboard_input._prime_tk_root()` (`:208-211`); the read in the executor through the module (`:212-213`); `None` → `self.app.clipboard`; empty → select all, the warning, a WARNING; else cut to 65,536 and `_replace_via_keyboard` over the selection, then `move_cursor` (`:214-237`). / now: the same without the priming and its comment; docstring (`:173-174`, `:191`, `:197`) without the Tk root. Gains a caller: `CappedTextArea._on_mouse_down`.
module: s19_app/tui/capped_text_area.py
modify: [Data: TextArea.selection] (replace)
examples: (R-TUI-043.6/1) LinuxH, real app, app clipboard `APP-TEXT`, `ctrl+v` in Box M → `APP-TEXT` (holds on base)
examples: (R-TUI-044.3/1) WinCI, Box M `ab`, cursor between, Other-program write `P1 line\nsecond`, `ctrl+v` → `aP1 line\nsecondb`
examples: (R-TUI-043.10.1/2, /4) WinCI (P1000 by Other-program write) and LinuxH (app clipboard P1000), Box M: `ctrl+v` × 10 → median end of the paste ≤ Typed-key time + bound(`0.1`) s (base with a Tk root: `3,401` ms, F §1.4 D1)
examples: (R-TUI-043.10.2/2) WinCI, Held clipboard (8 s), app clipboard `APP-TEXT` → Box M `APP-TEXT` ≤ bound(`2.5`) s
examples: (R-TUI-043.6/3) WinCI, Empty Unicode text, app clipboard `APP-TEXT` → Box M `APP-TEXT`, no warning (base: the warning, the whole buffer selected)
examples: (R-PASTE.18/1 … /7) the walk in `#patch_paste_text`, `#sje_manual`, `#changeset_json_text`, `#entry_json_text`, `#bulk_param_text`, `#report_declared_regions`, `#operation_config`: Clear, `ctrl+v` after the copy step → the box holds `W<n>-` + P2 again
examples: (I-1a) a test that patches `os_clipboard_input.read_os_clipboard` to return `PATCHED` → `ctrl+v` in Box M gives `PATCHED` (the module seam, as the batch-67 tests use it)

### New

_system_directory
req: R-PASTE.16, R-PASTE.17
in:
out: str? folder
func: new. Off Windows `None`. On Windows the folder that `GetSystemDirectoryW` (kernel32, through `ctypes`, a 260-character buffer) reports; a result of `0`, a result ≥ the buffer, or any exception → `None`. It reads no environment variable (`SystemRoot`, `PATH`), which a caller could set. The seam that R-PASTE.17/1 points at an empty folder.
module: s19_app/tui/os_clipboard_input.py
examples: (R-PASTE.16/1) WinCI → the runner's system folder, `C:\Windows\system32` (equal, case-insensitively, to the test's own `GetSystemDirectoryW` result)
examples: (LinuxH) `sys.platform` `linux` → `None`

_system_powershell
req: R-PASTE.16, R-PASTE.17
in:
out: str? path
func: new. `folder = _system_directory()`; `None` → `None`; else `os.path.join(folder, "WindowsPowerShell", "v1.0", "powershell.exe")` when that is an existing file (`os.path.isfile`), else `None`. No cache: called at each PowerShell start, so a test can point it elsewhere; the cost is one API call and one file check.
module: s19_app/tui/os_clipboard_input.py
examples: (R-PASTE.16/1) WinCI → `C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe`
examples: (R-PASTE.17/1) `_system_directory` → an empty temporary folder `T` → `None` (`T\WindowsPowerShell\v1.0\powershell.exe` does not exist)
examples: (LinuxH) → `None`

OsClipboardInput._on_paste
req: R-PASTE.1, R-TUI-044.2
in: events.Paste event
out: None
func: new (D-5 A). The terminal route into a single-line box: when `event.text` is longer than `_CLIPBOARD_CAP_CHARS` it is cut in place, nothing else. The stock `Input._on_paste` (textual `_input.py:756-764`) runs after it through the MRO dispatch (`message_pump.py:743-800`): it inserts the first line at the cursor (over the selection when there is one) and stops the event. It must not call `super()._on_paste` (the stock handler would insert twice; the `CappedTextArea._on_paste` rule, `capped_text_area.py:131-165`). Needs `from textual import events` in the module.
module: s19_app/tui/os_clipboard_input.py
examples: (R-PASTE.1/1) LinuxH, Box A empty, Terminal paste `L1\nL2` → Box A `L1` (holds on base, B pilot3)
examples: (R-PASTE.1/2) LinuxH, Terminal paste `Ñoño Ж 漢字 😀\nsecond` → Box A `Ñoño Ж 漢字 😀`
examples: (R-TUI-044.2/1) LinuxH, Box A empty, Terminal paste P70k → Box A `65536` characters (base `70,000`, B pilot3)
examples: (R-TUI-044.2/5) LinuxH, the Load dialog (`ctrl+l`), `#load_path` empty, Terminal paste of 5,000 × `a` → `#load_path` `""`: refused whole by its `max_length=4096` (`screens.py:405`), not cut to 4,096
examples: (R-TUI-043.5/3) LinuxH, Box A `AAAA-BBBB` with `AAAA` selected, Terminal paste `ZZ` → `ZZ-BBBB`
examples: (R-PASTE.1/1 neg) the handler also calls `super()._on_paste(event)` → Box A `L1L1` → RED
examples: (AT-I1a-2, AT-I1a-6) WinCI: the Other-program read of the copy posted as a Terminal paste into Box A' → P1 (from Box A), `L1 Ñ€` (from Box M); LinuxH: the decoded OSC 52 request posted instead → the same

OsClipboardInput.focus_on_click
req: R-PASTE.29, R-PASTE.26
in:
out: bool focus
func: new (D-9 A; the seam E2 picked, finding E2-1). The screen calls it synchronously for every mouse press on the box, before it sets the focus and before it forwards the press (textual `screen.py:1933-1946`; the method is `Widget.focus_on_click`, `widget.py:720-729`, and `screen.py:1937` is its only caller). It writes `[Data: OsClipboardInput._press_cursor]`: `None` when the box has the focus, else `self.cursor_position` (the end of its selection) — the cursor at the press, read before the stock `Input._on_focus` selects the whole text (`_input.py:736-740`). Returns `super().focus_on_click()` (`FOCUS_ON_CLICK`, `True`), so which widget gets the focus is unchanged.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: OsClipboardInput._press_cursor] (replace)
examples: (R-PASTE.29/2) Box 1's value set to `ab` (cursor `2`), Unfocus, a press on `a` → `_press_cursor` `2`, returns `True`; the screen then focuses Box 1 and the stock focus handler selects `(0, 2)` (B pilot4 P13: unfocused `(9, 9)` → `(0, 9)` at the press)
examples: (R-PASTE.29/1) Box 1 `ab`, focused, cursor `1` → `_press_cursor` `None`
examples: (holds on base) a left press on an unfocused Box 1 → it gets the focus, the stock focus handler selects all, then the stock press handler puts the cursor at the click point (the left click as today)

OsClipboardInput._on_mouse_down
req: R-PASTE.24, R-PASTE.25, R-PASTE.26, R-PASTE.27, R-PASTE.28, R-PASTE.29, R-PASTE.31, R-PASTE.32, R-PASTE.33
in: events.MouseDown event
out: None
func: new (operator rulings 2; D-9 A, D-10 B, D-11 A). `press = self._press_cursor`; `self._press_cursor = None` (every button). Button ≠ 3 → return: the stock `Input._on_mouse_down` (cursor to the click point, mouse selection, capture; `_input.py:786-791`) and `Widget._on_mouse_down` run as today. Button 3 (Ctrl or Alt held or not): `event.prevent_default()` (no stock press handler runs, `message_pump.py:758-760`; E1 A1 finding 2) and `event.stop()` (no ancestor, no App handler); then, at the press: if `press is None` and `self.selected_text` is not empty (the box had the focus and showed a selection) → `await self.action_copy()` (the Ctrl+C path, so the one copy tail, A-R2; never `SkipAction` there); otherwise, if `press is not None` (the box had no focus, so it showed no selection) → `self.cursor_position = press` (drops the whole-text selection the press's focus made, D-9 A; the paste goes to the cursor at the press, D-10 B), then → `await self.action_paste()` (the Ctrl+V path: the executor read, the app-clipboard fallback cut to 65,536, the first line at the cursor, the paste failure warning). While the act is awaited the box's next events wait (≤ 2.5 s on a held clipboard; E1 A6).
module: s19_app/tui/os_clipboard_input.py
modify: [Data: OsClipboardInput._press_cursor] (clear); [Data: Input.selection] (replace)
examples: (R-PASTE.25/1) LinuxH and WinCI, Box 1 `AAAA-BBBB`, `AAAA` selected by keys, app clipboard `BEFORE`, Right-click on the first `B` → app clipboard `AAAA` (base `BEFORE`, B pilot4 P10)
examples: (R-PASTE.26/1) as R-PASTE.25/1 → value `AAAA-BBBB`, selection `(0, 4)` (base `(3, 3)`, B pilot4 P10)
examples: (R-PASTE.24/1) WinCI, real app, Box A, k = 1 … 5: Clear, type `RC-<k> Ñ€`, Select, Right-click (App route) on the selection, Other-program read → `RC-1 Ñ€` … `RC-5 Ñ€` (5/5; base: the earlier text)
examples: (R-PASTE.29/1) LinuxH and WinCI, Box 1 `ab`, focused, cursor between (`home`, `right`), the text `P1 line\nsecond` (WinCI: Other-program write; LinuxH: the app clipboard), Right-click on `a` → Box 1 `aP1 lineb` (base `ab`, B pilot4 P16)
examples: (R-PASTE.29/1 neg, D-10 A) the paste put at the click point → `P1 lineab` → RED
examples: (R-PASTE.29/2) Box 1's value set to `ab`, Unfocus, Right-click on `a` → Box 1 `abP1 line`; the focus on Box 1; WinCI: Other-program read still `P1 line\nsecond`; LinuxH: the app clipboard still `P1 line\nsecond`
examples: (R-PASTE.29/2 neg, D-9 B) the selection judged as the handler finds it (after the press's focus selected `(0, 2)`) → `ab` copied, Box 1 still `ab` → RED
examples: (R-PASTE.29/3) Box 1 empty, Right-click → `P1 line`
examples: (R-PASTE.27/1, /3) WinCI (LinuxH), real app, Box A: Typed-key time, then 10 × (Clear, type `C<k>`, Select, Right-click (App route)) → median end of the copy (WinCI: Own read sees `C<k>`; LinuxH: the write failure warning), the clock started just before the press, ≤ Typed-key time + bound(`0.1`) s
examples: (R-PASTE.28/1) WinCI, Held clipboard (8 s), Box A: Select, Right-click (App route) → the warning `Clipboard write failed — copied inside the app only.` ≤ bound(`2.5`) s after the press
examples: (R-PASTE.31/1, /3) WinCI P1000 by Other-program write (LinuxH: the app clipboard P1000), real app, Box A: Typed-key time, then 10 × (Clear, Right-click (App route)) → Box A P1000 each time; median end of the paste ≤ Typed-key time + bound(`0.1`) s
examples: (R-PASTE.32/1) WinCI, Box A empty, app clipboard `APP-TEXT`, Held clipboard (8 s), Right-click (App route) → Box A `APP-TEXT` ≤ bound(`2.5`) s after the press
examples: (R-PASTE.15/6, R-PASTE.9/4) LinuxH, OSC 52 spy, Notices, Box A P1: Select, Right-click → exactly `1` OSC 52 request, decoding to P1; one notice `Clipboard write failed — copied inside the app only.`, `warning`, `6.0`
examples: (R-PASTE.10/2) LinuxH, Log capture, Box A `SECRET-RC-44`: Select, Right-click → ≥ `1` WARNING; no record holds `SECRET-RC-44`
examples: (R-TUI-043.6/5) LinuxH, real app, app clipboard `APP-TEXT`, Box A empty, Right-click → Box A `APP-TEXT`
examples: (R-TUI-043.7/2, R-TUI-043.8/2) LinuxH, empty app clipboard, Box A `KEEP`, no selection, Right-click → one notice `Clipboard read failed — try Ctrl+Shift+V or type the path manually.`; selection `(0, 4)`; value `KEEP`
examples: (R-TUI-044.2/6) LinuxH, app clipboard P70k, Box A empty, Right-click → `65536` characters
examples: (R-TUI-043.9/2, R-PASTE.14/2) WinCI, Held clipboard (8 s), Tick lateness armed, Right-click (App route) in empty Box A (then with a selection) → ≥ `10` ticks before the end of the act, each late by ≤ bound(`0.1`) s
examples: (D-11 A) a recording `on_mouse_down` on Box 1's parent → it receives `0` button-3 presses (base: `1`, the event bubbles, textual `events.py:581`); a left press reaches it as before
examples: (R-PASTE.24 neg) the right-click left to the toolkit (the base) → the press moves the cursor and empties the selection; Other-program read gives the earlier text → RED
examples: (AT-I1a-12, -14, -24, -26) a C1 or C2 copy from Box A (P1) or Box M (P2), then Right-click (App route) in the cleared Box A' → Box A' P1 or `L1 Ñ€`

OsClipboardInput._on_mouse_up
req: R-PASTE.33
in: events.MouseUp event
out: None
func: new (D-11 A). Button 3 → `event.stop()` (the release does not bubble); the stock `Input._on_mouse_up` still runs: it only ends a mouse selection (`_input.py:803-804`), and button 3 never starts one. Other buttons: nothing.
module: s19_app/tui/os_clipboard_input.py
examples: (D-11 A) Right-click on Box 1 → a recording `on_mouse_up` on its parent receives `0` button-3 releases (base `1`)
examples: (holds on base) a left drag from `A` to `B` in Box 1 → the selection ends at the left release as today

OsClipboardInput._on_click
req: R-PASTE.33, R-PASTE.26
in: events.Click event
out: None
func: new (D-11 A). Button 3 → `event.prevent_default()` (the `Widget._on_click` text select on a double or triple click, `widget.py:4695-4703`, does not run) and `event.stop()`. Other buttons: nothing.
module: s19_app/tui/os_clipboard_input.py
examples: (D-11 A) Right-click on Box 1 → a recording `on_click` on its parent receives `0` button-3 clicks (base `1`)
examples: (E1 A6, B pilot4 P14) a double right-click (chain `2`) on Box 1 with `AAAA` selected → the app clipboard `AAAA` (two copies of the same text); selection `(0, 4)`; a spy on `Box 1.text_select_all` counts `0` calls

CappedTextArea._on_mouse_down
req: R-PASTE.24, R-PASTE.25, R-PASTE.26, R-PASTE.27, R-PASTE.28, R-PASTE.30, R-PASTE.31, R-PASTE.32, R-PASTE.33
in: events.MouseDown event
out: None
func: new (operator rulings 2; D-9 A, D-10 B, D-11 A). Button ≠ 3 → return: the stock `TextArea._on_mouse_down` (cursor to the click point, mouse selection, capture, undo checkpoint; `_text_area.py:1948-1957`) runs as today. Button 3: `event.prevent_default()`, `event.stop()`; `self.selected_text` not empty → `await self.action_copy()`; else `await self.action_paste()` (which returns for a read-only box). No focus record: a multi-line box draws its selection with or without the focus and does not select on focus (E1 A1 finding 4; `_text_area.py:1463-1466`), so the selection and cursor the handler finds are those shown at the press.
module: s19_app/tui/capped_text_area.py
modify: [Data: TextArea.selection] (replace)
examples: (R-PASTE.25/2, R-PASTE.26/2) LinuxH, Box 2 `AAAA-BBBB`, `AAAA` selected (`ctrl+home`, `shift+right` × 4), app clipboard `BEFORE`, Right-click on the first `B` → app clipboard `AAAA`; text `AAAA-BBBB`; selection `((0, 0), (0, 4))` (base `((0, 4), (0, 4))`, B pilot4 P11)
examples: (R-PASTE.24/3, R-PASTE.25/3, R-PASTE.26/3) Box 2 as above, then Unfocus, Right-click on the first `B` → WinCI Other-program read `AAAA`; app clipboard `AAAA`; selection `((0, 0), (0, 4))`; the focus on Box 2 (base: collapsed, B pilot4 P13)
examples: (R-PASTE.24/2) WinCI, real app, Box M, k = 1 … 5: Clear, type `RL1-<k>\nRL2-<k>`, `f7`, Right-click (App route) → 5/5 Other-program reads equal the two lines
examples: (R-PASTE.30/1) LinuxH and WinCI, Box 2 `ab`, focused, cursor `(0, 1)`, the text `P1 line\nsecond` → Right-click on `a` → `aP1 line\nsecondb`
examples: (R-PASTE.30/1 neg, D-10 A) the paste at the click point → `P1 line\nsecondab` → RED
examples: (R-PASTE.30/2) Box 2 `ab`, cursor `(0, 1)`, no selection, Unfocus, Right-click on `a` → `aP1 line\nsecondb`; the focus on Box 2
examples: (R-PASTE.27/2, R-PASTE.28/2) WinCI, Box M with `f7`: the right-click copy ends ≤ Typed-key time + bound(`0.1`) s; with Held clipboard (8 s) the write failure warning ≤ bound(`2.5`) s after the press
examples: (R-PASTE.31/2, /4, R-PASTE.32/2) Box M: the right-click paste of P1000 (WinCI OS, LinuxH app clipboard) ends ≤ Typed-key time + bound(`0.1`) s; held → `APP-TEXT` ≤ bound(`2.5`) s
examples: (R-PASTE.15/7) LinuxH, OSC 52 spy, Box M P2: `f7`, Right-click → `1` request, decoding to P2
examples: (R-PASTE.12/3) LinuxH and WinCI, Box M holds P70k: `f7`, Right-click → the app clipboard and the decoded OSC 52 request `65536` characters; WinCI Other-program read `65536`
examples: (R-TUI-043.6/5, R-TUI-044.2/6) LinuxH, empty Box M: app clipboard `APP-TEXT` → `APP-TEXT`; app clipboard P70k → `65536` characters
examples: (D-11 A) a recording `on_mouse_down` on Box 2's parent → `0` button-3 presses; Box 2 has not captured the mouse after the right-click (base: captured by the stock press)
examples: (AT-I1a-13, -15, -25, -27) a C1 or C2 copy from Box A or Box M, then Right-click (App route) in the cleared Box M' → Box M' P1 or P2

CappedTextArea._on_mouse_up
req: R-PASTE.33
in: events.MouseUp event
out: None
func: new (D-11 A). Button 3 → `event.stop()`; the stock `TextArea._on_mouse_up` (`_text_area.py:1974-1976`, ends a mouse selection) still runs and finds none. Other buttons: nothing.
module: s19_app/tui/capped_text_area.py
examples: (D-11 A) Right-click on Box 2 → a recording `on_mouse_up` on its parent receives `0` button-3 releases (base `1`)

CappedTextArea._on_click
req: R-PASTE.33, R-PASTE.26
in: events.Click event
out: None
func: new (D-11 A). Button 3 → `event.prevent_default()` (no `Widget._on_click` text select) and `event.stop()`. Other buttons: nothing.
module: s19_app/tui/capped_text_area.py
examples: (D-11 A) Right-click on Box 2 → a recording `on_click` on its parent receives `0` button-3 clicks (base `1`); a double right-click keeps `((0, 0), (0, 4))` and copies `AAAA` twice

### New, test support (G-T; `tests/support/b103_clipboard.py`)

require_isolated_clipboard
req: R-PASTE.21
in: str kind; Mapping[str, str]? environ = None; str? platform = None
out: None
func: new (test support; D-8 A). The isolation guard. `environ` defaults to `os.environ`, `platform` to `sys.platform`. kind `windows`: isolated iff platform `win32` and `GITHUB_ACTIONS` = `true` and `RUNNER_ENVIRONMENT` = `github-hosted`. kind `x`: isolated iff `DISPLAY` equals the display the session's own Xvfb fixture started (none until it starts; LinuxX, blocked). Not isolated → `pytest.fail("OS clipboard not isolated: <reason>")` (an outcome `failed`, never a skip) before anything opens a clipboard; it opens nothing itself. Callers: every helper that opens a clipboard (Other-program write / read, Own read, Held clipboard, Empty Unicode text, X seed / read) calls it first, and an autouse fixture of `tests/test_b103_clipboard_*.py` calls it with `windows` on every Windows host, because there the product's own Ctrl+V and Ctrl+C open the Windows clipboard (finding E2-4). The message text is design, not a row.
module: tests/support/b103_clipboard.py
examples: (R-PASTE.21/1) kind `windows`, platform `win32`, `GITHUB_ACTIONS` `true`, `RUNNER_ENVIRONMENT` `self-hosted` → the test fails with `OS clipboard not isolated: RUNNER_ENVIRONMENT='self-hosted'`; a spy on the clipboard-opening functions counts `0` calls; the same with `RUNNER_ENVIRONMENT` unset
examples: (R-PASTE.21/2) LinuxH, kind `x`, `DISPLAY` `:99`, no Xvfb started by the session → fails before any open; the spy counts `0`; no X connection is attempted
examples: (R-PASTE.21/3) WinCI, `GITHUB_ACTIONS` `true`, `RUNNER_ENVIRONMENT` `github-hosted` → returns `None`; the test goes on to the probe
examples: (R-PASTE.21 neg) the guard skipped → the spy counts ≥ `1` open → RED

clipboard_probe
req: R-PASTE.22, R-PASTE.23
in:
out: tuple(bool usable, str result)
func: new (test support; D-7 B made loud). Cached once per session. First `require_isolated_clipboard("windows")`; then writes a nonce `b103-probe-<32 hex>` with the test process's own Win32 write (test code, independent of the product under test) and reads it back with a separate system PowerShell `Get-Clipboard -Raw` (UTF-8 output, 10 s timeout); usable iff the read, without its line end, equals the nonce. `result` names each layer and what it gave, for example `win32 write ok, PowerShell read 'b103-probe-…'`, `win32 write ok, PowerShell read ''`, `win32 write failed: OpenClipboard error 5`, `win32 write ok, PowerShell timed out after 10 s`. Seam: a pytester run on LinuxH replaces its one-shot body (`_probe_once`) with a stand-in. The probe test (`test_runner_clipboard_probe`, in the Windows test file) calls it and, when not usable, `pytest.fail(f"runner clipboard unusable: {result}")` (R-PASTE.23); when usable it passes.
module: tests/support/b103_clipboard.py
examples: (R-PASTE.23/1) LinuxH pytester, stand-in `(False, "win32 write ok, PowerShell read ''")` → the probe test's outcome `failed` with the message `runner clipboard unusable: win32 write ok, PowerShell read ''`; the job's conclusion would be `failure`
examples: (R-PASTE.23/2) LinuxH pytester, stand-in `(True, "win32 write ok, PowerShell read 'b103-probe-0123'")` → the probe test `passed`
examples: (R-PASTE.22/2) WinCI, the first run → the job log names the probe's result (usable, or the D-7 ruling applies); also whether a Tk root can be created there (for the RED-on-base runs)
examples: (R-PASTE.23 neg) the probe test skipped or passed on a failed probe → a green job whose OS clipboard tests were all skipped → RED

os_clipboard_ready
req: R-PASTE.21, R-PASTE.22
in:
out: None
func: new (test support): the fixture that every WinCI-arm test requests first. Off Windows → `pytest.skip("Windows only")`. On Windows → `require_isolated_clipboard("windows")` (a host that is not GitHub-hosted fails, never skips); then `clipboard_probe()`; not usable → `pytest.skip(f"runner clipboard unusable: {result}")`, so the dependent cases are `blocked` while the probe test itself fails (R-PASTE.23). The LinuxH arms do not request it; they assert `DISPLAY` and `WAYLAND_DISPLAY` unset instead (`02-test-cases.md` §Platforms).
module: tests/support/b103_clipboard.py
examples: (R-PASTE.22/1) LinuxH pytester, the host check made `True`, the isolation variables set, the probe stand-in `(False, "win32 write ok, PowerShell read ''")`, the OS clipboard test files collected and run → every OS clipboard test `skipped` with the reason `runner clipboard unusable: win32 write ok, PowerShell read ''`; `0` failed besides the probe test
examples: (R-PASTE.22/1) the same with a passing stand-in → `0` tests skipped by it
examples: (R-PASTE.22 neg) the probe result ignored → the OS clipboard tests fail for the runner, not the product → the reason check RED
examples: (R-PASTE.21/1) a Windows host with `RUNNER_ENVIRONMENT` `self-hosted` → the fixture fails the test (outcome `failed`, not `skipped`)

### Unchanged (context)

_read_via_ctypes
req: R-TUI-043.4, R-TUI-043.6, R-TUI-043.10.1, R-TUI-043.10.2, R-TUI-043.11
in:
out: str? text
func: unchanged. Off Windows `None`. `OpenClipboard(NULL)` with 5 × 20 ms retries (`None` when another program holds it), then `CF_UNICODETEXT` → `ctypes.wstring_at` (`:275-328`): `''` for an empty text (`:324`), which `read_os_clipboard` now counts as no text; `None` when the clipboard holds no text format (`:315-318`). Now the first read layer.
module: s19_app/tui/os_clipboard_input.py
examples: (F §1.4) Windows: `0.1`–`0.2` ms on either thread
examples: (R-TUI-043.11/1) WinCI, Other-program write P1 → P1 with every code point equal; Box A and Box M (Clear between) hold P1 exactly
examples: (R-TUI-043.6/3) WinCI, Empty Unicode text → `''`
examples: (R-TUI-043.10.2/1) WinCI, Held clipboard (8 s) → `None` after 5 attempts (≈ `0.1` s)

_write_via_ctypes
req: R-PASTE.2, R-PASTE.11, R-PASTE.13
in: str text
out: bool written
func: unchanged. Off Windows `False`. A movable UTF-16 buffer, `OpenClipboard(NULL)` with 5 × 20 ms retries, `EmptyClipboard`, `SetClipboardData(CF_UNICODETEXT)` (`:389-466`). Now followed only by the PowerShell rescue (`[Data: _WRITE_STRATEGIES]`). E1 risk §8: with no owner window `SetClipboardData` may fail on some PCs; then every copy falls to PowerShell (R-PASTE.11 fails there).
module: s19_app/tui/os_clipboard_input.py
modify: [I/O: Windows clipboard] (replace)
examples: (F §1.4 F1) from the executor: `2.6` ms, read back by PowerShell
examples: (R-PASTE.13/1) WinCI, Held clipboard (8 s) → `False` after ≈ `0.1` s
examples: (R-PASTE.2/2) WinCI, Box M, k = 1 … 5: Clear, type `L1-<k>\nL2-<k>`, `f7`, `ctrl+c` → 5/5 Other-program reads equal the two lines

_bound_clipboard_text
req: R-TUI-044.2
in: str? text
out: str? bounded
func: unchanged. `None` → `None`; else `text[:65536]` (`:565-598`); called by `read_os_clipboard` at its one success exit.
module: s19_app/tui/os_clipboard_input.py
examples: (R-TUI-044.2/4) WinCI, Other-program write P70k, `ctrl+v` in Box A, then Box M → `65536` characters each
examples: (unit) `None` → `None`; `abc` → `abc`

OsClipboardInput.action_copy
req: R-PASTE.2, R-PASTE.3, R-PASTE.4, R-PASTE.5, R-PASTE.15, R-PASTE.19
in:
out: None
func: unchanged. Empty `selected_text` → `SkipAction` (the key goes on to the ancestors and the App: A-R1, Inc 1b's quit dialog); else `await _mirror_and_write_os_clipboard(self.app, selected_text)`; the value and the selection stay (`:839-864`). Gains a caller: `OsClipboardInput._on_mouse_down`, which calls it only with a selection.
module: s19_app/tui/os_clipboard_input.py
examples: (R-PASTE.3/1, R-PASTE.4/1) Box A `COPYME-1`: Select, `ctrl+c` → app clipboard `COPYME-1`; Box A `COPYME-1`
examples: (R-PASTE.5/1) LinuxH and WinCI, app clipboard `BEFORE`, WinCI Other-program write `OS-BEFORE`, Box A `KEEP`, cursor at the end, no selection, `ctrl+c` → app clipboard `BEFORE`; WinCI Other-program read `OS-BEFORE`
examples: (R-PASTE.19/1) census: `40` single-line boxes, all `OsClipboardInput` (C); (R-PASTE.19/2) the walk's copy step in the 17 single-line places → 17/17 copies checked
examples: (AT-I1a-1 … -4) a C1 copy of P1 from Box A, pasted into Box A' or Box M' by route 1 or 2 → P1

OsClipboardInput.action_cut
req: R-PASTE.5, R-PASTE.6, R-PASTE.7, R-PASTE.15
in:
out: None
func: unchanged. Empty selection → `SkipAction`; else `delete_selection()` and the copy tail (`:866-892`).
module: s19_app/tui/os_clipboard_input.py
examples: (R-PASTE.7/1) LinuxH, Box A `DE AD BE EF`, `home`, `shift+right` × 5, `ctrl+x` → Box A ` BE EF`; app clipboard `DE AD`
examples: (R-PASTE.6/1) Box A `CUTME-1`: Select, `ctrl+x` → app clipboard `CUTME-1`; WinCI Other-program read `CUTME-1`
examples: (R-PASTE.5/3) app clipboard `BEFORE`, Box A `KEEP`, no selection, `ctrl+x` → Box A `KEEP`; app clipboard `BEFORE`; WinCI Other-program read `OS-BEFORE`
examples: (R-PASTE.15/2) LinuxH, OSC 52 spy, Box A P1: Select, `ctrl+x` → `1` request, decoding to P1

CappedTextArea._on_paste
req: R-TUI-044.2, R-TUI-044.4
in: events.Paste event
out: None
func: unchanged. Cuts `event.text` to 65,536 in place; the stock `TextArea._on_paste` inserts it all at the selection (`:131-165`).
module: s19_app/tui/capped_text_area.py
examples: (R-TUI-044.2/3) LinuxH, Box M empty, Terminal paste P70k → `65536` characters (holds on base, B pilot3)
examples: (R-TUI-044.4/1) LinuxH, Box M empty, Terminal paste `L1\nL2` → `L1\nL2`, once (holds on base; B pilot P6: posted to the box itself it would be inserted twice)

CappedTextArea.action_copy
req: R-PASTE.2, R-PASTE.3, R-PASTE.4, R-PASTE.5, R-PASTE.12, R-PASTE.15, R-PASTE.18, R-PASTE.19
in:
out: None
func: unchanged. Empty `selected_text` → `SkipAction`; else the copy tail; the document stays (`:239-268`). Gains a caller: `CappedTextArea._on_mouse_down`.
module: s19_app/tui/capped_text_area.py
examples: (R-PASTE.3/2, R-PASTE.4/2) Box M `COPYME-2`, `f7`, `ctrl+c` → app clipboard `COPYME-2`; Box M `COPYME-2`
examples: (R-PASTE.5/2) app clipboard `BEFORE`, Box M `KEEP`, no selection, `ctrl+c` → app clipboard `BEFORE`
examples: (R-PASTE.15/3) LinuxH, OSC 52 spy, Box M P2, `f7`, `ctrl+c` → `1` request, decoding to P2
examples: (R-PASTE.18/8, R-PASTE.19/1) census: `7` multi-line boxes, all `CappedTextArea` or a subclass (`JsonHighlightTextArea`); `0` editable stock `TextArea`; a planted stock `TextArea` is reported (C)
examples: (AT-I1a-5 … -8) a C1 copy of P2 from Box M → Box A' `L1 Ñ€` or Box M' P2

CappedTextArea.action_cut
req: R-PASTE.6, R-PASTE.7, R-PASTE.8, R-PASTE.15
in:
out: None
func: unchanged. Read-only → return; no selection → `_delete_cursor_line()`; else `_delete_via_keyboard`; the replaced text goes to the copy tail (`:270-306`).
module: s19_app/tui/capped_text_area.py
examples: (R-PASTE.7/2) LinuxH, Box M `DE AD BE EF`, `ctrl+home`, `shift+right` × 5, `ctrl+x` → Box M ` BE EF`; app clipboard `DE AD`
examples: (R-PASTE.8/1) LinuxH, Box M `first\nline_to_cut\nthird`, cursor `(1, 2)`, no selection, `ctrl+x` → Box M `first\nthird`; app clipboard `line_to_cut` with or without one line end, never `''`
examples: (R-PASTE.6/2) Box M `CUT\nME-2`, `f7`, `ctrl+x` → app clipboard `CUT\nME-2`; WinCI Other-program read equal
examples: (R-PASTE.15/4, /5) LinuxH, OSC 52 spy: `f7` + `ctrl+x` on P2 → `1` request, P2; the line cut of `line_to_cut` → `1` request, decoding to the cut line

## Entities

[Data: _STRATEGIES]
desc: changed (D-1 A). `os_clipboard_input.py:547-551`, the default read cascade. was: `(("tkinter", _read_via_tk), ("ctypes-win32", _read_via_ctypes), ("powershell", _read_via_powershell))`. now: `(("ctypes-win32", _read_via_ctypes), ("powershell", _read_via_powershell))`. Read by `read_os_clipboard` (`:645`) only; tests inject their own cascades (the loop contract, `../E1-slice.md` §5). Example (R-TUI-043.10.1 neg): the Tk pair restored first → Ctrl+V `+3,100` ms → RED where a Tk root exists; a PowerShell-first order → `+200` ms → RED on WinCI.

[Data: _WRITE_STRATEGIES]
desc: changed (D-3 A). `:558-562`. was: `(("win32", _write_via_ctypes), ("tkinter", _write_via_tk), ("powershell", _write_via_powershell))`. now: `(("win32", _write_via_ctypes), ("powershell", _write_via_powershell))`. Read by `write_os_clipboard` (`:709`) only. Example (R-PASTE.11 neg): a PowerShell-first order → `+200` ms per copy → RED on WinCI; (R-PASTE.2 neg) the Tk write kept as owner after a Win32 failure → a later read `''` → RED.

[Data: _POWERSHELL_WRITE_COMMAND]
desc: changed (R-PASTE.16). `:130-136`. was: `("powershell", "-NoProfile", "-Command", "[Console]::InputEncoding=[System.Text.Encoding]::UTF8;$input | Set-Clipboard")`. now: the same tuple without its first item; `_write_via_powershell` puts `_system_powershell()` before it at each call. Name kept: no reader outside the module (`git grep` of `s19_app/` and `tests/`: 0), so a rename would be free but is not needed.

[Data: _TK_ROOT]
desc: removed (D-1 A, D-3 A). The module's `_TkRootSingleton()` instance (`:228`), with `_TK_RETRIES` and `_TK_RETRY_DELAY_S` (`:100-101`) and their budget line (`:97`), the `atexit` import (`:76`) and its registration (`:207`). After Inc 1a the clipboard code holds no Tk state and imports no `tkinter`.

[Data: OsClipboardInput._press_cursor]
desc: new (D-9 A). `int?`, a class-level default `None` that each instance overrides: the cursor at the press when the box had no focus at the press, else `None`. Written by `OsClipboardInput.focus_on_click` at every press the screen forwards; read and cleared by `OsClipboardInput._on_mouse_down` for every button, so it never outlives the press that wrote it. A `MouseDown` posted to the box directly (not through the screen) finds `None` (finding E2-6). No `__init__` is added.

[Data: Input.selection]
desc: the single-line box's `Selection(start, end)`; the cursor is its end (`cursor_position`, textual `_input.py:256-263`). Drawn only while the box has the focus (`_input.py:656-661`); the stock `Input._on_focus` sets `(0, len(value))` (`select_on_focus`, `_input.py:736-740`; no box of `s19_app/` changes it).
sequence:
  rightPressUnfocused: OsClipboardInput.focus_on_click (records the cursor) → Screen.set_focus (posts Focus) → Input._on_focus (selects the whole text) → OsClipboardInput._on_mouse_down wins (the cursor back, then the paste at it)
  rightPressFocused: OsClipboardInput.focus_on_click (records None) → OsClipboardInput._on_mouse_down wins (a shown selection is copied and kept; none: the paste at the cursor)
  leftPress: OsClipboardInput.focus_on_click → Input._on_focus (only when unfocused) → OsClipboardInput._on_mouse_down (returns) → Input._on_mouse_down wins (the cursor at the click point)

[Data: TextArea.selection]
desc: the multi-line box's `Selection(start, end)` of `(row, column)` pairs; drawn with or without the focus (`_text_area.py:1463-1466`); the toolkit's focus changes it not.
sequence:
  rightPress: Screen.set_focus (when unfocused; no selection change) → CappedTextArea._on_mouse_down wins (copy, or the paste at the cursor)
  leftPress: CappedTextArea._on_mouse_down (returns) → TextArea._on_mouse_down wins (the cursor at the click point)

[Data: App._clipboard]
desc: Textual's app clipboard (`App.clipboard`), written only by the stock `App.copy_to_clipboard` (textual `app.py:1780`), which the copy tail calls once per copy; read by both `action_paste` fallbacks. Example (R-PASTE.3/1): after a Ctrl+C of `COPYME-1`, `app.clipboard == "COPYME-1"`.

[I/O: Windows clipboard]
desc: the OS clipboard (CTX-PASTE): Windows only (D-2 A). Read by `_read_via_ctypes` and the system PowerShell's `Get-Clipboard -Raw`; written by `_write_via_ctypes` and `Set-Clipboard`. Off Windows the system has none and its rows meet their `If` rows. In tests it is opened only when it is an isolated clipboard (R-PASTE.21).

[I/O: terminal]
desc: the terminal. Receives the OSC 52 request `ESC ] 5 2 ; c ; <base64> BEL` that `App.copy_to_clipboard` writes through `App._driver.write` (textual `app.py:1781-1786`); sends terminal pastes (`events.Paste`, forwarded by `App.on_event` to the focused box, textual `app.py:4142-4146`) and mouse reports (SGR, button 3 for the right button; B pilot4 P15).

[I/O: system PowerShell]
desc: `<the folder GetSystemDirectoryW reports>\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\…` on a default install. The only program the clipboard code starts (R-PASTE.16); none is started when it is missing (R-PASTE.17).

[I/O: .github/workflows/clipboard-windows.yml]
desc: new (D-6 B as ruled; R-PASTE.20). The text pinned in the preamble ("Pinned workflow"). Examples. (R-PASTE.20/1, static, LinuxH) the file read as text with `tests/test_suite_hygiene.py`'s parsers (`_workflow_jobs`, `_job_steps`, `_step_run`) → jobs `["clipboard-windows"]`; its `runs-on:` `windows-latest`; the `on:` block holds `workflow_dispatch:`, `push:` and `pull_request:`, each event's `paths:` names `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py`, the OS clipboard test files and `.github/workflows/clipboard-windows.yml`, and no `branches:` line; `permissions:` `contents: read`; the checkout step has `persist-credentials: false`; one run line runs the OS clipboard test files with no `-n` and no `-m`; `_script_injections(text)` → `[]`; no `pull_request_target` or `workflow_run`; `tui-ci.yml` byte-equal to `e07fb00`'s. (R-PASTE.20/1 neg) `runs-on: ubuntu-latest` → RED; the `push:` trigger removed → RED. (R-PASTE.20/2, WinCI first run) the job log lists each OS clipboard test as `PASSED`, `FAILED` or `SKIPPED` (with the reason `runner clipboard unusable: <probe result>`), `0` deselected, and the probe test's outcome names the probe result.

[Outside: keys]
desc: the keys a text box binds through the toolkit: `ctrl+v` → `action_paste`, `ctrl+c` → `action_copy`, `ctrl+x` → `action_cut` (textual `_input.py:138-140`, `_text_area.py:374-391`). Where Windows Terminal binds Ctrl+V to its own paste, Ctrl+V arrives as a terminal paste instead (CTX-PASTE, F §1.4 F2).

[Outside: right button]
desc: mouse button 3 over a text box, as the terminal reports it once the app turned mouse reporting on: a `MouseDown`, a `MouseUp` and the `Click` the App makes from them (textual `app.py:4060-4117`; `Pilot.click(button=3)` posts the same three, B pilot4 P12). A Shift+right-click in Windows Terminal is the terminal's own and does not arrive (E1 A1 finding 7).

[Interface: text boxes]
desc: the 47 text boxes of `s19_app/` (40 `OsClipboardInput`, 7 `CappedTextArea` with `JsonHighlightTextArea` among them; C) in the 24 places of the walk (9 rail windows, the command palette, 7 dialogs; Patch Editor paste buffer, Split / Join / Export, 5 dialogs). Census (R-TUI-044.1/18, R-PASTE.18/8, R-PASTE.19/1, R-PASTE.33/1): `0` stock `Input`, `0` editable stock `TextArea`, `47/47` of the two classes; a planted stock `Input` is reported. Walk (R-PASTE.19/2, R-PASTE.33/2): 24/24 places, a Ctrl+C / Ctrl+V round trip and a right-click round trip each.
offers: (R-TUI-044.1/2) "ctrl+v" → OsClipboardInput.action_paste
offers: (R-PASTE.18/1) "ctrl+v" → CappedTextArea.action_paste
offers: (R-PASTE.19/2) "ctrl+c" → OsClipboardInput.action_copy
offers: (R-PASTE.19/2) "ctrl+c" → CappedTextArea.action_copy
offers: (R-PASTE.33/2) "right-click" → OsClipboardInput._on_mouse_down
offers: (R-PASTE.33/2) "right-click" → CappedTextArea._on_mouse_down

## Edges

[Outside: keys] ──▶ OsClipboardInput.action_paste
when: `ctrl+v` reaches a focused single-line box
[Outside: keys] ──▶ CappedTextArea.action_paste
when: `ctrl+v` reaches a focused multi-line box
[Outside: keys] ──▶ OsClipboardInput.action_copy
when: `ctrl+c` in a single-line box (`SkipAction` with no selection: the key goes on)
[Outside: keys] ──▶ CappedTextArea.action_cut
when: `ctrl+x` in a multi-line box (the cursor line when there is no selection)
[I/O: terminal] ──▶ OsClipboardInput._on_paste
when: a terminal paste forwarded by the App to a focused single-line box
[I/O: terminal] ──▶ CappedTextArea._on_paste
when: a terminal paste forwarded by the App to a focused multi-line box
[Outside: right button] ──▶ OsClipboardInput.focus_on_click
when: any press over a single-line box, before the screen sets the focus
[Outside: right button] ──▶ OsClipboardInput._on_mouse_down
when: the button-3 press, after the box handled any Focus the press caused
[Outside: right button] ──▶ CappedTextArea._on_mouse_down
when: the button-3 press over a multi-line box
OsClipboardInput.focus_on_click ──▶ [Data: OsClipboardInput._press_cursor]
[Data: OsClipboardInput._press_cursor] ──▶ OsClipboardInput._on_mouse_down
OsClipboardInput._on_mouse_down ──▶ OsClipboardInput.action_copy
when: `_press_cursor` was `None` and the box shows a selection
OsClipboardInput._on_mouse_down ──▶ OsClipboardInput.action_paste
when: otherwise (after the cursor is put back when the press gave the focus)
CappedTextArea._on_mouse_down ──▶ CappedTextArea.action_copy
when: the box shows a selection
CappedTextArea._on_mouse_down ──▶ CappedTextArea.action_paste
when: the box shows none
OsClipboardInput.action_copy ──▶ _mirror_and_write_os_clipboard
CappedTextArea.action_copy ──▶ _mirror_and_write_os_clipboard
_mirror_and_write_os_clipboard ──▶ [Data: App._clipboard]
_mirror_and_write_os_clipboard ──▶ [I/O: terminal]
_mirror_and_write_os_clipboard ──▶ write_os_clipboard
[Data: _WRITE_STRATEGIES] ──▶ write_os_clipboard
write_os_clipboard ──▶ [I/O: Windows clipboard]
when: Windows; off Windows both layers return `False` at once
[Data: _STRATEGIES] ──▶ read_os_clipboard
[I/O: Windows clipboard] ──▶ read_os_clipboard
when: Windows; off Windows both layers return `None` at once
[Data: App._clipboard] ──▶ OsClipboardInput.action_paste
when: `read_os_clipboard` gave `None` (cut to 65,536 before the first line)
[Data: App._clipboard] ──▶ CappedTextArea.action_paste
when: `read_os_clipboard` gave `None`
_system_powershell ──▶ _read_via_powershell
_system_powershell ──▶ _write_via_powershell
_read_via_powershell ──▶ [I/O: system PowerShell]
when: `_system_powershell()` is not `None`
[I/O: .github/workflows/clipboard-windows.yml] ──▶ os_clipboard_ready
when: the hosted Windows job runs the OS clipboard test files

## Findings

finding E2-1 the E1 seam for D-9 cannot tell a press-made focus
anchor: OsClipboardInput.focus_on_click
seen: (R) the screen posts `Focus` to the box and then forwards a copy of the press made by `MouseEvent._apply_offset` (textual `screen.py:1933-1946`, `events.py:554-568`); every message takes its `time` when it is made (`message.py:53`), so the `MouseDown` the box receives is always younger than the `Focus` that the same press caused
cause: `../E1-slice.md` §7 and E1 A3 D-9 proposed an `_on_focus` record judged by comparing the `Focus` time with the press time; the box never sees the driver's press, only the copy made after the focus
effect: that comparison would judge every press-made focus as an earlier one, so a right-click on an unfocused single-line box would copy its whole text over the operator's clipboard: the D-9 B behaviour, the negative control of R-PASTE.29/2
decision: E2 takes `focus_on_click()`, which the screen calls for every press on the box before `set_focus` (its only caller, `screen.py:1937`), to record whether the box had the focus and its cursor; no `_on_focus` handler and no clock. Left out: an `_on_focus` that records the time it is handled, judged against the copy's creation time (correct by the event loop's ordering, but it rests on a clock and that argument). For E3 to confirm

finding E2-2 a Ctrl+V with no text on the Windows clipboard waits for a PowerShell start
anchor: read_os_clipboard
seen: (R) `_read_via_ctypes` returns `None` both when the clipboard is held and when it opened but holds no text (an image, files copied in Explorer: no `CF_UNICODETEXT`, `os_clipboard_input.py:315-318`), and now its `''` also counts as no text; the cascade then starts the system PowerShell (`192`–`232` ms warm, up to `2.0` s cold, F §1.4) before the app-clipboard fallback
cause: the Win32 layer does not tell "opened, no text" (an answer) from "could not open" (worth a rescue); the base does the same, after its Tk wait
effect: such a Ctrl+V or right-click paste ends 0.2 to 2 s after the key; no row bounds it (R-TUI-043.10.1 measures a 1,000-character text) and R-TUI-043.6/3 pays it on WinCI
decision: not changed here (`_read_via_ctypes` is unchanged in the slice, and a new return value would reach the loop-contract tests). For E3: keep, or let the Win32 layer end the cascade on "opened, no text"; if kept, a backlog row (proposed BL-I1a-7)

finding E2-3 a second OS write if Inc 1b moves it into copy_to_clipboard
anchor: _mirror_and_write_os_clipboard
seen: (R) the tail calls the stock `app.copy_to_clipboard(text)` (`:764`) and then `write_os_clipboard` in the executor (`:768-769`), once each
cause: Inc 1b's app-level seam for the one copy notice (orchestrator ruling I-1) is designed at Inc 1b's E2
effect: an `S19TuiApp.copy_to_clipboard` override that also wrote the OS clipboard would write it twice for every text-box copy, and notify twice if it notified
decision: I-1 item 3 pins one app-clipboard write, one OS write and at most one notice per tail call; P-1 and P-2 are PROPOSED for Inc 1b's E2

finding E2-4 on a Windows host every product-driving test opens the clipboard
anchor: require_isolated_clipboard
seen: (R) after Inc 1a a Ctrl+V or a Ctrl+C in a real `OsClipboardInput` or `CappedTextArea` opens the Windows clipboard (`_read_via_ctypes`, `_write_via_ctypes`), and the LinuxH cases of the new test files drive the product unstubbed
cause: R-PASTE.21 speaks of a test about to open the OS clipboard; on a Windows host that is not GitHub-hosted, every product-driving test of the new files is one, not only the helpers
effect: a run of the new files on a person's Windows PC would read and overwrite that person's clipboard
decision: the guard is also an autouse fixture of `tests/test_b103_clipboard_*.py` on every Windows host and fails the test (never skips) unless the host is GitHub-hosted; the existing clipboard tests stub the cascade and need nothing

finding E2-5 a tag push also runs the Windows job
anchor: [I/O: .github/workflows/clipboard-windows.yml]
seen: (R, GitHub's workflow-syntax page, docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax, read 2026-11-07) "Path filters are not evaluated for pushes of tags."; with neither a branch nor a tag filter "the workflow will run for events affecting either branches or tags."
cause: the ruled trigger set: `push` and `pull_request` with a `paths` filter and no branch filter
effect: a tag push (for example `v1.0.0`) would run the job once; it writes nothing (read-only token, no secrets), so the cost is runner minutes on a public repository
decision: kept as ruled; a `tags-ignore` would add a filter that R-PASTE.20/1 does not name, so it is the orchestrator's call at E3

finding E2-6 a press posted to the box itself has no focus record
anchor: OsClipboardInput._on_mouse_down
seen: (R) `_press_cursor` is written only by `focus_on_click`, which only the screen's press forwarding calls (`screen.py:1937`)
cause: the record belongs to the screen's press path, the path the terminal and `Pilot.click` use
effect: a test that posts a `MouseDown` straight to an unfocused single-line box finds `None` and judges the selection it then holds; no product route does that
decision: the G-T testers use `Right-click` (Pilot) or `Right-click (App route)`, as `02-test-cases.md` §Common fixtures says; recorded for E4
