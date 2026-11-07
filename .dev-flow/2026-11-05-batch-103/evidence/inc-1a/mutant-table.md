# E5 mutant table — Inc 1a clipboard core (R-PASTE.1 … .36, R-TUI-043.6/.10, R-LOADDLG.20)

Base: HEAD `e7d157f6`, read-only tree `/home/javiergr/work/b103-int1a` on cachyos-rtx, copied to
`/tmp/b103-e5-1a-mut/work`. Each mutant is the smallest edit to the product file the row's Negative
control names, applied to the copy, reverted after the run (`git checkout`). Tests run with
`/home/javiergr/miniconda3/envs/s19ci/bin/python -I -m pytest -q -p no:cacheprovider
tests/test_b103_clipboard_core.py -k "<ids>"` under an isolated HOME/XDG/LOCALAPPDATA
(`zq_iso_user`), `PYTHONDONTWRITEBYTECODE=1`, `DISPLAY`/`WAYLAND_DISPLAY`/`CI` unset. Timing rows
(`serial_timing`) run one `-k` selector at a time, so they are serial by construction. Evidence
(diff + pytest tail) in `evidence-e5/mutants/out/M-*.txt`. Rows whose tests live only in
`tests/test_b103_clipboard_windows.py` (skip `Windows only`) are `not realisable (Windows CI pending)`.

| Mutant | Row | Control (as written) | Edit made | Tests run | Result | Failing test(s) |
|---|---|---|---|---|---|---|
| M-043.10.1 | R-TUI-043.10.1 | a delay mutant — the answering layer sleeps past the bound | `time.sleep(1.0)` at the top of `read_os_clipboard` | .10.1/3-4 | killed | .10.1/3-4 (single, multi) |
| M-043.6 | R-TUI-043.6 | the fallback removed → (a) RED | delete the `text is None → app.clipboard` fallback in both `action_paste` | .6/1 | killed | .6/1 |
| M-PASTE.1 | R-PASTE.1 | the last line inserted | `event.text.splitlines()[0]` → `[-1]` in `_on_paste` | .1/1, .1/2 | killed | .1/1, .1/2 |
| M-044.2 | R-TUI-044.2 | the single-line terminal-paste cut removed | delete the 65,536 cut in `OsClipboardInput._on_paste` | .2/1 | killed | .2/1 |
| M-044.2b | R-TUI-044.2 | the `wstring_at` size argument dropped | `ctypes.wstring_at(pointer, min(…))` → `wstring_at(pointer)` | .2/8 | killed | .2/8 |
| M-PASTE.34 | R-PASTE.34 | the strip step removed | strip → identity in `_on_paste` and `action_paste` (single-line) | .34/1, /3, /4 | killed | .34/1, .34/3, .34/4 |
| M-LOADDLG.20 | R-LOADDLG.20 | the `restrict` branch without the unsafe-character check → inserted | remove the `restricted()` refusal in `_on_paste` and `action_paste` | .20/1, /2, /3 | killed | .20/1, .20/2, .20/3 |
| M-PASTE.35 | R-PASTE.35 | the strip step removed (multi-line) | strip → identity in `CappedTextArea._on_paste` and `.action_paste` | .35/1, /3, /4 | killed | .35/1, .35/3, .35/4 |
| M-PASTE.3 | R-PASTE.3 | the app-clipboard mirror removed | `App.copy_to_clipboard(app, text)` → `pass` in the copy tail | .3 | killed | .3 |
| M-PASTE.4 | R-PASTE.4 | copy acting as cut | add `delete_selection()` / `_delete_via_keyboard` to both `action_copy` | .4 | killed | .4 |
| M-PASTE.5 | R-PASTE.5 | an empty selection copied as `''` | remove the `SkipAction` guard in `action_copy` and `action_cut` | .5 | killed | .5[c], .5[x] |
| M-PASTE.6 | R-PASTE.6 | the cut writes only the app clipboard (the stock cut) → WinCI RED | cut tail → `self.app.copy_to_clipboard(...)` (no OS write) | .6 | survived | — (WinCI-only control; the LinuxH arm passes) |
| M-PASTE.7 | R-PASTE.7 | the cut leaves the text (acts as copy) | remove `delete_selection()` from `action_cut` | .7 | killed | .7 |
| M-PASTE.8 | R-PASTE.8 | the no-selection cut made a no-op | `if start == end: return` in `CappedTextArea.action_cut` | .8 | killed | .8 |
| M-PASTE.9 | R-PASTE.9 | the warning removed | delete the `app.notify(_WRITE_FAIL_NOTIFICATION, …)` block | .9/1 | killed | .9/1 (single, multi) |
| M-PASTE.10 | R-PASTE.10 | the log line removed | delete the `OS clipboard write failed; retained…` WARNING | .10/1 | survived | — (the test asserts ≥1 WARNING; `write_os_clipboard: every strategy failed` still satisfies it) |
| M-PASTE.11 | R-PASTE.11 | a delay mutant — the write layer sleeps past the bound | `time.sleep(1.0)` at the top of `write_os_clipboard` | .11/3 | killed | .11/3 |
| M-PASTE.12 | R-PASTE.12 | the cut removed → 70,000 | drop the `text[:_CLIPBOARD_CAP_CHARS]` cut in the copy tail | .12/1 | killed | .12/1 |
| M-PASTE.15 | R-PASTE.15 | the mirror written to `App._clipboard` without the driver write → 0 requests | `App.copy_to_clipboard(app, text)` → `app._clipboard = text` | .15/1 … /7 | killed | .15/1 … /5, .15/6, .15/7 |
| M-PASTE.25 | R-PASTE.25 | the app-clipboard mirror skipped on the right-click | right-click `await self.action_copy()` → `pass` (both classes) | .25/1 … /3 | killed | .25/1, .25/2, .25/3 |
| M-PASTE.26 | R-PASTE.26 | the toolkit press handler left to run on button 3 | drop `event.prevent_default()` in both `_on_mouse_down` | .26/1, /2 | killed | .26/1, .26/2 |
| M-PASTE.27 | R-PASTE.27 | a delay mutant — the write layer sleeps past the bound | `time.sleep(1.0)` at the top of `write_os_clipboard` | .27/3 | killed | .27/3 |
| M-PASTE.29 | R-PASTE.29 | no right-click paste | right-click `await self.action_paste()` → `pass` | .29/1 … /4 | killed | .29/1, .29/2, .29/3, .29/4 |
| M-PASTE.30 | R-PASTE.30 | no right-click paste (multi-line) | `CappedTextArea._on_mouse_down` paste → `pass` | .30/1, /2 | killed | .30/1, .30/2 |
| M-PASTE.31 | R-PASTE.31 | a delay mutant — the read layer sleeps past the bound | `time.sleep(1.0)` at the top of `read_os_clipboard` | .31/3-4 | killed | .31/3-4 (single, multi) |
| M-044.1 | R-TUI-044.1 | one place's box built as a stock `Input` (the census names it) | `#load_path` `OsClipboardInput(` → `Input(` | .44.1/18 | killed | .44.1/18 |
| M-PASTE.18 | R-PASTE.18 | one place's box built as a stock `TextArea` | `#bulk_param_text` `CappedTextArea(` → `TextArea(` | .18/8 | killed | .18/8 |
| M-PASTE.19 | R-PASTE.19 | one place's box with the stock copy | `#project_name` `OsClipboardInput(` → `Input(` | .19/1 | killed | .19/1 (= .33/1) |
| M-PASTE.33 | R-PASTE.33 | one place built from a class without the right-click | `#entry_json_text` `CappedTextArea(` → `TextArea(` | .33/1 | killed | .33/1 (= .19/1) |
| M-PASTE.20 | R-PASTE.20 | the job `runs-on` set to `ubuntu-latest` | workflow `runs-on: windows-latest` → `ubuntu-latest` | .20/1 | killed | .20/1 |
| M-PASTE.21 | R-PASTE.21 | the guard skipped | `clipboard_isolated` returns `(True, "")` unconditionally | .21/1, /2, /3 | killed | .21/1, .21/2 |
| M-PASTE.22 | R-PASTE.22 | the probe result ignored | `os_clipboard_ready` drops the `if not usable: skip` | .22/1 | killed | .22/1 |
| M-PASTE.23 | R-PASTE.23 | the probe test passes on a failed probe | `clipboard_probe` caches `(True, …)` always | .23/1 | killed | .23/1 |
| M-PASTE.36 | R-PASTE.36 | the gate left on batch-101's folder only | `_redaction_roots` returns batch-101 only | .36/1 | killed | .36/1 |

## Not realisable (Windows CI pending — the row's tests live in `test_b103_clipboard_windows.py`, `skip "Windows only"`)

| Row | Control (as written) |
|---|---|
| R-TUI-043.10.2 | the Win32 read retries until the clipboard is free (unbounded) → ≥8 s RED; / the PowerShell layer without its 2.0 s timeout |
| R-TUI-043.9 | the read called on the event loop's thread (no executor) → ticks stall ≥1 s |
| R-PASTE.2 | the OS write removed (the stock Textual copy) → PowerShell reads the previous text |
| R-PASTE.13 | the Win32 write retries until the clipboard is free → ≥8 s |
| R-PASTE.14 | the write called on the event loop's thread |
| R-PASTE.24 | the right-click left to the toolkit / the copy taken at the release or click |
| R-PASTE.28 | the Win32 write retries until the clipboard is free → ≥8 s |
| R-PASTE.32 | the Win32 read retries until the clipboard is free → ≥8 s |
| R-PASTE.16 | the bare name `powershell` → the decoy in the current folder runs |
| R-PASTE.17 | a fallback to the bare name `powershell` → 1 start |

## Survived mutants (2)

- **M-PASTE.6** — the cut's OS write is unobservable on LinuxH (off Windows the OS write always
  fails by design, D-2 A): the LinuxH arm (`test_r_paste_6`) checks only the app clipboard, which the
  mutant still sets. The WinCI arm (PowerShell read) would kill it; blocked until the Windows job runs.
- **M-PASTE.10** — the row's WARNING line (`OS clipboard write failed; retained Textual internal
  clipboard only`) is not pinned by the test: `test_r_paste_10_1` asserts only `assert warnings`
  (≥1 WARNING of the `s19_app.tui.os_clipboard_input` logger), and the lower layer
  `write_os_clipboard` independently logs `write_os_clipboard: every strategy failed (cascade=…)` as
  a WARNING, which still satisfies the assertion after the copy-tail line is removed. The negative
  control "the log line removed → RED" therefore survives — a test-oracle gap, not a product gap.

Counts: 34 mutants applied (32 killed, 2 survived) + 10 rows not realisable (Windows CI pending) =
the 43 table rows of `01-requirements.md` plus one second control (M-044.2b).
