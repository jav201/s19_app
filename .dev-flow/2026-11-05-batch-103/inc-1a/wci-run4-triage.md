# WCI run 4 triage — 13 failed / 64 passed / 37 skipped

Evidence: `.dev-flow/2026-11-05-batch-103/evidence/inc-1a/wci-run-42515511607-failed.txt`
Products read: `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py`
Tests read: `tests/test_b103_clipboard_windows.py`, `tests/support/b103_clipboard.py`
Rows: R-PASTE.9/.13/.14/.28, R-TUI-043.9/.12; graph `codewire/graph-*.md`.

## Verdict up front

- **1 product fault, 2 test faults.** The hold is now REAL (the parent-side
  `OpenClipboard(None)` verify in `_hold_clipboard` did not raise), so the
  run-2/run-3 C4 "hold ineffective" story is finally dead. With a real hold the
  code paths can be exercised for the first time — and they split:
- **7 failures are a product fault** in the write cascade (R-PASTE.9/.13/.28,
  R-PASTE.10 via the shared write path): the warning path is never reached.
- **6 failures are test faults**: 2 read-warning tests are too impatient
  (R-TUI-043.12), 4 responsiveness tests read a tick oracle that never fires
  (R-TUI-043.9, R-PASTE.14).

## Product fault — `_write_via_powershell` reports success on a held clipboard

`os_clipboard_input.py:461-468` decides success solely by
`result.returncode != 0`:

```python
if result.returncode != 0:
    ...
    return False
return True
```

Windows PowerShell 5.1's `Set-Clipboard` (the layer `_system_powershell()`
resolves) wraps `System.Windows.Forms.Clipboard.SetText`, which retries
`OpenClipboard` ~10×100 ms and then **throws `ExternalException`**. The
`Set-Clipboard` cmdlet catches that and emits a **non-terminating** error via
`WriteError` — the process still **exits 0** with the error on stderr. So on a
held clipboard the write layer returns `True`, `write_os_clipboard` returns
`True`, `_mirror_and_write_os_clipboard` (os_clipboard_input.py:704-720) skips
`app.notify(_WRITE_FAIL_NOTIFICATION)`, and the `"every strategy failed"`
warning is never logged. The copy "succeeds" silently.

Step-by-step for `action_copy` under the hold (write path):

1. `OsClipboardInput.action_copy` / `CappedTextArea.action_copy` →
   `_mirror_and_write_os_clipboard`.
2. `App.copy_to_clipboard` (textual app.py:1770) mirrors + OSC52 — non-blocking.
3. `await loop.run_in_executor(None, write_os_clipboard, text)` — **off the UI
   thread** (thread pool), so the event loop is never blocked here.
4. `write_os_clipboard` → `_write_via_ctypes`: `OpenClipboard(None)` fails
   (real hold) 5×20 ms → returns `False` (~100 ms).
5. `_write_via_powershell`: `Set-Clipboard` fails → non-terminating error →
   **exit 0** → `return True` (false success).
6. `write_os_clipboard` returns `True` → no `app.notify`, no WARNING.

The evidence is the poll tests: `13_1_2` / `28_1_2` poll `app.notify` notices
for **10 s** and still get the `999.0` sentinel (no notice ever), while the
responsiveness tests prove the write DID run to completion
(`marker == {'started': True, 'ended': True}`). Only a false `True` explains
"completed + no warning + no notice for 10 s".

### Minimal fix (per the approved layered-write design)

Make the PowerShell layer fail loudly so the existing `returncode != 0` check
works. In `_POWERSHELL_WRITE_COMMAND` (os_clipboard_input.py:125-130), promote
the non-terminating error to a terminating one:

```python
_POWERSHELL_WRITE_COMMAND = (
    "-NoProfile",
    "-Command",
    "$ErrorActionPreference='Stop';"
    "[Console]::InputEncoding=[System.Text.Encoding]::UTF8;"
    "$input | Set-Clipboard",
)
```

(or `$input | Set-Clipboard -ErrorAction Stop`). Then a held clipboard makes
`Set-Clipboard` terminate → non-zero exit → `_write_via_powershell` returns
`False` → `write_os_clipboard` returns `False` → the warning fires. The command
stays static (no payload interpolation), preserving R-PASTE.16. Optional
hardening of the same class: the read command at `_read_via_powershell`
(os_clipboard_input.py:310-312) already fails correctly (empty stdout → `None`)
but takes the same ~1 s retry; `-ErrorAction Stop` there is cosmetic only.

## Test fault 1 — read-warning tests don't wait for the ~1.1 s async read

`test_r_tui_043_12_2` (test_b103_clipboard_windows.py:611) and `_12_3` (:1530)
fire ctrl+v / right-click, then count WARNINGs after one `pilot.pause()`
(`_12_3` waits `pilot.pause(0.2)`). The read cascade runs off-loop in the
executor for **100 ms (ctypes) + ~1 s (PowerShell `Get-Clipboard` retry)** and
logs `"read_os_clipboard: every strategy failed"` only when it finishes — long
after the test has already counted. Result: `n == 0`. With a real hold the read
path is correct (both layers return `None`, the WARNING *does* fire — just late).
Fix (test): poll `records` (or `marker["ended"]`) with a deadline like the
passing `13_1_2` driver, instead of a fixed short pause.

## Test fault 2 — tick oracle never fires (responsiveness tests)

`test_r_tui_043_9_1/2`, `test_r_paste_14_1/2` fail `assert len(lateness) >= 10`
with `lateness == []`, while `marker == {'started': True, 'ended': True}`
proves the wrapped read/write ran to completion. The operation takes ≥100 ms
(ctypes retries alone), so a working 50 ms interval would record ≥2 ticks, and
~20 for the full ~1.1 s cascade. Zero ticks in all four tests means
`arm_tick_lateness`'s `screen.set_interval(0.05, _tick)` timer never fires
under `run_test` + the Pilot poll loop — a **measurement-harness fault**, not a
UI freeze. The hypothesis "the Win32 open/retry runs on the UI thread and
blocks the event loop" is **refuted by the code**: every OS access goes through
`loop.run_in_executor(None, …)` (os_clipboard_input.py:956, 975; capped_text_area.py:216),
so the loop stays free. Fix (test): instrument `arm_tick_lateness` (log timer
arm + each `_tick`); if `set_interval` callbacks don't run under `run_test`,
drive ticks from the poll loop itself (count `pilot.pause()` iterations as the
liveness signal) or use `app.set_timer` with an explicit `await`.

## Table (13 rows)

| test | failure | cause | fix |
|---|---|---|---|
| `r_paste_9_2[single]` `[multi]` | `warnings == []` | product (write false-success) | `-ErrorAction Stop` in write cmd |
| `r_paste_13_1_2[single]` `[multi]` | `999.0` (no notice in 10 s) | product | same |
| `r_paste_28_1_2[single]` `[multi]` | `999.0` | product | same |
| `r_paste_10_2` | `n == 0` | product | same |
| `r_tui_043_12_2` | `n == 0` | test (impatience) | poll until read ends |
| `r_tui_043_12_3` | `n == 0` | test (impatience) | poll until read ends |
| `r_tui_043_9_1` `r_tui_043_9_2` | `only 0 ticks` | test (tick oracle) | fix/instrument `arm_tick_lateness` |
| `r_paste_14_1` `r_paste_14_2` | `only 0 ticks` | test (tick oracle) | fix/instrument `arm_tick_lateness` |

## Notes for the next increment

- The one product fix is a one-line change to `_POWERSHELL_WRITE_COMMAND`
  (plus the analogous hardening of the read command if desired). It is in the
  inc-1a file `os_clipboard_input.py`, so it needs the normal unfreeze flow for
  that module (it is NOT in the `_ENGINE_PATHS` frozen set — verify against
  `tests/test_engine_unchanged.py` before editing).
- Re-run the four poll tests (`13_1_2`, `28_1_2`) first after the product fix;
  they are the cleanest oracle (10 s poll, no ambiguity).
- The two read-warning tests and the four responsiveness tests need test-side
  fixes only; the product read path and the off-loop executor design are both
  confirmed correct by this run.
