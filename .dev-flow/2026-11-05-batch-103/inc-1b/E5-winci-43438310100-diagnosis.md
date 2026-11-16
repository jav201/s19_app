# Inc 1b E5 rework — WinCI run 43438310100 diagnosis

Run 43438310100 (`clipboard-windows`, branch `b103-inc1b` at 541a3d50): `4 failed, 208 passed, 44 skipped`; the artifact scanner failed with `PERSONAL_PATH` x6.
Diagnosis by claude-opus-5-5 (orchestrator, read-only over the run log and the tree), 2026-11-13.
All three are **test defects** (class (a) of the approved-design rule: the test does not implement the approved design). No product change.

## F-1 — R-PASTE.14/101 … /103 "responsive writer exceeded its tick bound"

| Node | max lateness | bound (`timing_bound(0.1)`, CI x2) |
|---|---|---|
| R-PASTE.14/101 (key) | 0.372 s | 0.200 s |
| R-PASTE.14/102 (view right-click) | 0.341 s | 0.200 s |
| R-PASTE.14/103 (row right-click) | 0.466 s | 0.200 s |
| R-PASTE.14/1, /2 (Inc 1a, one-box app) | 0.012–0.013 s | 0.200 s |

- **Cause.** `arm_tick_lateness` records every tick from the moment it is armed, and the Inc 1b driver arms it before the key or click. The full app's own dispatch of that key or click (selection, render, notices) counts as "lateness while writing".
- The row says "**While** the system writes the OS clipboard … responsive" (R-PASTE.14). Inc 1a already pinned the measurement to that state (E3A-11 (c); `inc-1a/02-test-cases.md` R-PASTE.14/1: "≥ 10 ticks due after the write has started, before its end"). E3A-11 (c) also predicted this failure: the real app's key dispatch reached 377 ms in pilot2.
- **Not a product defect.** The writer ran off the UI thread (that check passed before the bound check). The held clipboard made the cascade fail as designed (`every strategy failed`), and the failure notice was correct.
- **Not a bound calibration.** The bound stays at `timing_bound(0.1)`. Only the window changes.
- **Fix.** The pass-through write/read wrappers stamp `t_start` / `t_end` (`time.monotonic()`). `arm_tick_lateness` keeps only ticks due inside `[t_start, t_end]`. A wrapper without stamps records nothing, so the ≥ 10-tick check fails loud. The negative arm still holds: a write on the event loop's thread stalls the first tick due inside the window, which then fires late → RED.

## F-2 — AT-I1b-5/1-T1-P1 "Copied 1 line to the clipboard." missing (0 == 1)

- **Cause.** In Textual 8.2.8, `App.notify` only **posts** a `Notify` message. The notice reaches `app._notifications` when the app handles that message.
- `_mirror_and_write_os_clipboard` calls `notify` and returns; the test's marker then sets `ended`. `wait_for_copy_tail` returns on `ended`, and `_assert_copy_notice` read `app._notifications` immediately. The message can still be queued: a race.
- Evidence. The cell copied the right payload (`tail_payloads == [expected]` passed). There was no write-failure WARNING, so the write returned `True` and `notify` ran. `current == []` means no notice of any kind was in the list yet. The other three cells of source 5 passed.
- **Fix.** `_assert_copy_notice` is now async. It polls (5 ms + `pilot.pause()`, at most 2.0 s, well inside the notice's 5 s life) until a `Copied` notice appears, pauses once more, then asserts exactly one with the expected text. A missing notice still fails after 2 s; a duplicate is still counted.

## F-3 — artifact scanner `PERSONAL_PATH` (`windows-user-path`, `macos-user-path`)

- **Cause.** The failing tests' tracebacks and captured logs print pytest's `tmp_path`, which lives under the GitHub-hosted runner's fixed account. `windows-user-path` matched the backslash form. `macos-user-path` (`/users/<name>`) matched the forward-slash form inside `WindowsPath('C:/Users/<runner>/…')`. A passing run prints no `tmp_path`, which is why earlier green runs never hit this.
- The account names no person. Hiding it would also hide the failure context exactly when the artifact is needed.
- **Fix.** A single exact exception, `HOSTED_RUNNER_ACCOUNT`: a negative lookahead for that account name as a whole path segment, in the two Windows-reachable patterns. Every other account is still RED.
- **Negative controls** (`tests/test_b103_winci_gate.py`):
  - The same text with a person account → `windows-user-path` + `macos-user-path` RED.
  - A prefix-extended runner name (`…2`, `…s`) → RED.
  - The forward-slash `WindowsPath('C:/Users/<user>/…')` → RED.
- Rejected alternative: `--basetemp` under `RUNNER_TEMP`. It needs a workflow change and a WinCI round to prove, and other user-profile paths (logs, caches) could still leak the same account.
