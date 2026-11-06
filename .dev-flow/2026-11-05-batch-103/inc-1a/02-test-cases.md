# Inc 1a — test cases (ISO/IEC/IEEE 29119-3), E1

One case per coverage item `<requirement id>/<n>` of `01-requirements.md`, for its 25 active rows and the 12 cited canon rows that get cases here, plus the acceptance cases `AT-I1a-1` … `AT-I1a-10`. Written at E1, before any test: **Tests** is empty, **Coverage** is `gap` and **Result** is `not_run` everywhere (testers fill them at E4). Proposed files: G-T1 `tests/test_b103_clipboard_core.py`, G-T2 `tests/test_b103_clipboard_windows.py`, G-T3 `tests/test_b103_clipboard_matrix.py`, fixtures in `tests/support/b103_clipboard.py` (`E1-slice.md` §6). The "base" in an expected result is what `e07fb00` does (C / B / F / R as in `01-requirements.md`).

## Common fixtures

**Platforms.**
- **WinCI** — the Windows job (`E1-rulings.md` D-6) on a GitHub-hosted runner. Every WinCI case first passes the isolation guard (R-PASTE.21) and is skipped by the probe rule when the probe fails (R-PASTE.22). **Blocked until** a branch is pushed (operator approval) and the probe passes.
- **LinuxH** — cachyos-rtx headless or the `ubuntu-latest` CI job: `DISPLAY` and `WAYLAND_DISPLAY` unset (the test asserts it), no OS clipboard reachable. Runs now.
- **LinuxX** — cachyos-rtx with a private Xvfb display started by the test session (`-nolisten tcp`, a private auth file) and `xclip`. **Blocked until** the operator installs `xorg-server-xvfb` and `xclip`.

**Apps and boxes.**
- **Real app** — `S19TuiApp(base_dir=<tmp>)` under `run_test(size=(160, 48))`; `LOCALAPPDATA` isolated by `tests/conftest.py`.
- **Box A** (single-line) — A2L Explorer `#a2l_tags_filter_input` (rail key `2`). **Box M** (multi-line) — Patch Editor `#patch_paste_text` (rail key `6`, its JSON tab chip). **Box A'** — A↔B diff `#diff_path_a` (key `7`). **Box M'** — Split / Join / Export `#sje_manual` (its opener, `S19TuiApp.action_open_split_join_export`). A box gets the focus by a click on it (`pilot.click`), not by `.focus()` (tui-design NAVIGATION: `.focus()` is not evidence that a box can be reached).
- **Select** — single-line: `end`, then `shift+home`; multi-line: `f7` (select all) or `shift` + arrows for a part.
- **Clear** — select, then `delete`.

**Clipboard helpers (only after the isolation guard).**
- **Other-program write / read** — a separate system PowerShell process: `Set-Clipboard` with the text on stdin as UTF-8, or `Get-Clipboard -Raw` with UTF-8 output. It stands for "another Windows program".
- **Own read** — the test process's own Win32 read (test code, not the product's), polled every 5 ms for "end of a copy".
- **Held clipboard (t)** — a helper process that opens the Windows clipboard and keeps it open for t seconds (8 s unless the case says otherwise), started and confirmed holding before the key.
- **Empty Unicode text** — the test process writes a `CF_UNICODETEXT` of zero characters.
- **X seed / X read** (LinuxX) — `xclip -selection clipboard -i` / `-o` on the private display.

**Route and measurement helpers.**
- **Terminal paste (text)** — `app.post_message(events.Paste(text))`: to the App, as Textual's driver posts it (the App forwards it once to the focused box). Never posted to the box itself: a multi-line box then gets it twice (B, pilot P6 against pilot3).
- **Typed-key time** — 10 warm presses of `a` into the cleared box (2 discarded first), median from the press to the `a` showing (pilot2 L1 shape).
- **End of a paste / copy** — the clock starts just before the key; it stops at the first 5 ms poll that sees the expected box text / Own read / notice.
- **Tick lateness** — a 50 ms interval timer set on the screen before the key; lateness = actual time − due time of each tick; at least 10 ticks while the action is pending (a vacuous run fails).
- **OSC 52 spy** — a pass-through wrapper on `app._driver.write` that keeps every `ESC ] 52 ; c ; <b64> BEL` and decodes it.
- **Process spy** — a pass-through wrapper on process creation that records each program path and then starts it unchanged.
- **Notices** — the toasts the app shows, read with their text, severity and timeout.
- **Log capture** — a handler on the `s19_app` logger at DEBUG, records kept as (logger, level, message).
- Timing cases are `@pytest.mark.serial_timing` arms; every bound goes through `tests/support/timing.timing_bound` (×2 on CI) and `report_margin` (R-TST-002, R-TST-040/041).

**Payloads.** P1 = `COPY-1 Ñoño Ж 漢字 😀` (one line). P2 = `L1 Ñ€\nL2 漢` (two lines). P1000 = one line of 1,000 characters (`0123456789` × 100). P70k = 70,000 × `x`. `APP-TEXT`, `BEFORE`, `OS-BEFORE`: markers.

## Paste: time and fallback

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-TUI-043.10.1/1 | Verify that a Ctrl+V in a single-line box through the OS clipboard ends within the typed-key time plus 100 ms | normal | WinCI; real app; Box A clicked; P1000 by Other-program write | Typed-key time; then `ctrl+v` × 10 (Clear between) | each paste: the box holds P1000; median end of the paste ≤ median typed-key time + `timing_bound(0.1)` s (base: 3,401–3,483 ms on Windows with a Tk root, F) | | gap | not_run |
| R-TUI-043.10.1/2 | Verify the same for a multi-line box | normal | as /1, Box M | as /1 | as /1 for Box M | | gap | not_run |
| R-TUI-043.10.1/3 | Verify that a Ctrl+V in a single-line box on Linux ends within the typed-key time plus 100 ms | normal | LinuxH; real app; Box A; the app clipboard set to P1000 by an in-app copy (R-PASTE.3) | Typed-key time; `ctrl+v` × 10 | the box holds P1000; median ≤ typed-key time + bound (base: holds, 173.5 vs 175.4 ms, B pilot2; the Tk-mutant RED needs LinuxX) | | gap | not_run |
| R-TUI-043.10.1/4 | Verify the same for a multi-line box on Linux | normal | as /3, Box M | as /3 | as /3 | | gap | not_run |
| R-TUI-043.10.2/1 | Verify that a Ctrl+V in a single-line box ends within 2.5 s when another program holds the clipboard | robustness | WinCI; real app; Box A; app clipboard `APP-TEXT`; Held clipboard (8 s) | `ctrl+v` | the box holds `APP-TEXT` ≤ `timing_bound(2.5)` s after the key (base with a Tk root: up to 5.3 s, B/F) | | gap | not_run |
| R-TUI-043.10.2/2 | Verify the same for a multi-line box | robustness | as /1, Box M | `ctrl+v` | as /1 | | gap | not_run |
| R-TUI-043.9/1 | Verify that the screen stays responsive while a read waits on a held clipboard | robustness | WinCI; real app; Box A; Held clipboard (8 s); Tick lateness armed | `ctrl+v` | ≥ 10 ticks before the end of the paste; every tick late by ≤ `timing_bound(0.1)` s (negative control: the read on the event loop's thread → ticks stall ≥ 1 s → RED) | | gap | not_run |
| R-TUI-043.6/1 | Verify that on Linux a Ctrl+V pastes the app clipboard | robustness | LinuxH; real app; app clipboard `APP-TEXT` | `ctrl+v` in Box A, then in Box M | Box A `APP-TEXT`; Box M `APP-TEXT` (base: holds, B pilot P4a/P9) | | gap | not_run |
| R-TUI-043.6/2 | Verify that a held clipboard pastes the app clipboard | robustness | WinCI; as R-TUI-043.10.2/1 | `ctrl+v` in Box A, then Box M | both hold `APP-TEXT`; no paste failure warning | | gap | not_run |
| R-TUI-043.6/3 | Verify that an empty OS text pastes the app clipboard | robustness | WinCI; app clipboard `APP-TEXT`; Empty Unicode text | `ctrl+v` in Box A, then Box M | both hold `APP-TEXT`; no paste failure warning (base: the warning and the box selected, R) | | gap | not_run |
| R-TUI-043.6/4 | Verify that on Linux the X clipboard is not read (D-2 A) | robustness | LinuxX; real app; X seed `X-TEXT`; app clipboard `APP-TEXT` | `ctrl+v` in Box A, then Box M | both hold `APP-TEXT`, neither `X-TEXT` | | gap | not_run |
| R-TUI-043.4/1 | Verify that a Ctrl+V in a single-line box inserts the first line of the OS text at the cursor | normal | WinCI; Box A holds `ab`, cursor between `a` and `b`; Other-program write `P1 line\nsecond` | `ctrl+v` | Box A `aP1 lineb` | | gap | not_run |
| R-TUI-044.3/1 | Verify that a Ctrl+V in a multi-line box inserts all of the OS text at the cursor | normal | WinCI; Box M holds `ab`, cursor between; Other-program write `P1 line\nsecond` | `ctrl+v` | Box M `aP1 line\nsecondb` (base: yes since batch-102; the S7 review's "No", D7-24, is out of date) | | gap | not_run |
| R-TUI-043.5/1 | Verify that a Ctrl+V replaces the selection, single-line | normal | WinCI; Box A `AAAA-BBBB`, `AAAA` selected; Other-program write `ZZ` | `ctrl+v` | `ZZ-BBBB` | | gap | not_run |
| R-TUI-043.5/2 | Verify the same, multi-line | normal | as /1, Box M | `ctrl+v` | `ZZ-BBBB` | | gap | not_run |
| R-TUI-043.5/3 | Verify that a terminal paste replaces the selection, both classes | normal | LinuxH; Box A and Box M `AAAA-BBBB`, `AAAA` selected | Terminal paste (`ZZ`) in each | both `ZZ-BBBB` (base: holds, B pilot3) | | gap | not_run |
| R-TUI-043.7/1 | Verify the paste failure warning when neither clipboard holds text | robustness | LinuxH; app clipboard empty; Box A `KEEP`, then Box M `KEEP` | `ctrl+v` in each | a warning notice "Clipboard read failed — try Ctrl+Shift+V or type the path manually.", severity warning, 6 s, once per paste | | gap | not_run |
| R-TUI-043.8/1 | Verify that the box text is selected when neither clipboard holds text | robustness | as R-TUI-043.7/1 | `ctrl+v` in each | the selection covers `KEEP` whole in both boxes; the text unchanged | | gap | not_run |
| R-TUI-043.11/1 | Verify that characters outside the code page arrive unchanged | normal | WinCI; Other-program write P1 | `ctrl+v` in Box A, then Box M (Clear between) | both hold P1 exactly (code points compared) | | gap | not_run |
| R-TUI-043.12/1 | Verify a WARNING line when no text is read (Linux) | robustness | LinuxH; Log capture; app clipboard `APP-TEXT` | `ctrl+v` in Box A, then Box M | ≥ 1 WARNING record of `s19_app.tui.os_clipboard_input` per paste (base: holds, B pilot P8) | | gap | not_run |
| R-TUI-043.12/2 | Verify a WARNING line when the clipboard is held | robustness | WinCI; Log capture; Held clipboard (8 s) | `ctrl+v` in Box A | ≥ 1 WARNING record | | gap | not_run |
| R-TUI-043.13/1 | Verify that no clipboard text reaches the log | normal | LinuxH and WinCI; Log capture | a paste of `SECRET-TEXT-42` (app clipboard on LinuxH, Other-program write on WinCI) and a copy of `SECRET-COPY-43` from Box A | no record holds either string (base: holds for the paste, B pilot P8) | | gap | not_run |

## Paste: the terminal route and the limit

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-PASTE.1/1 | Verify that a terminal paste into a single-line box inserts its first line | normal | LinuxH; Box A empty | Terminal paste (`L1\nL2`) | Box A `L1` (base: holds, B pilot3) | | gap | not_run |
| R-PASTE.1/2 | Verify the first line with characters outside the code page | normal | LinuxH; Box A empty | Terminal paste (`Ñoño Ж 漢字 😀\nsecond`) | Box A `Ñoño Ж 漢字 😀` | | gap | not_run |
| R-TUI-044.4/1 | Verify that a terminal paste into a multi-line box inserts every line, once | normal | LinuxH; Box M empty | Terminal paste (`L1\nL2`) | Box M `L1\nL2` (base: holds, B pilot3) | | gap | not_run |
| R-TUI-044.2/1 | Verify the limit on a terminal paste into a single-line box | robustness | LinuxH; Box A empty | Terminal paste (P70k) | Box A holds 65,536 characters (base: 70,000, B pilot3; D-5) | | gap | not_run |
| R-TUI-044.2/2 | Verify the limit on the app-clipboard fallback into a single-line box | robustness | LinuxH; Box A empty; app clipboard P70k | `ctrl+v` | 65,536 characters (base: 70,000, B pilot P7; D-5) | | gap | not_run |
| R-TUI-044.2/3 | Verify the limit on a terminal paste into a multi-line box | robustness | LinuxH; Box M empty | Terminal paste (P70k) | 65,536 characters (base: holds, B pilot3) | | gap | not_run |
| R-TUI-044.2/4 | Verify the limit on a Ctrl+V of an OS text | robustness | WinCI; Other-program write P70k | `ctrl+v` in Box A, then Box M | 65,536 characters each | | gap | not_run |
| R-TUI-044.2/5 | Verify that the Load dialog's path box keeps its own limit after the change | robustness | LinuxH; Load dialog open (`ctrl+l`), `#load_path` empty | Terminal paste (5,000 × `a`) | `#load_path` empty (R-LOADDLG.19: the text is refused, not cut; D-5 must not cut it to 4,096) | | gap | not_run |

## Copy and cut

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-PASTE.2/1 | Verify that five Ctrl+C in a row from a single-line box each reach another program | normal | WinCI; real app; Box A | for k in 1…5: Clear, type `COPY-<k> Ñ€`, Select, `ctrl+c`, Other-program read | 5/5 reads equal `COPY-<k> Ñ€` (negative control: the stock copy → the earlier text → RED) | | gap | not_run |
| R-PASTE.2/2 | Verify the same from a multi-line box | normal | WinCI; Box M | as /1 with `L1-<k>\nL2-<k>` and `f7` | 5/5 reads equal the two lines | | gap | not_run |
| R-PASTE.3/1 | Verify that Ctrl+C puts the selection on the app clipboard, single-line | normal | LinuxH and WinCI; Box A `COPYME-1` | Select, `ctrl+c` | the app clipboard `COPYME-1` (base: holds, B pilot P5) | | gap | not_run |
| R-PASTE.3/2 | Verify the same, multi-line | normal | as /1, Box M `COPYME-2` | `f7`, `ctrl+c` | the app clipboard `COPYME-2` | | gap | not_run |
| R-PASTE.4/1 | Verify that Ctrl+C leaves a single-line box unchanged | normal | as R-PASTE.3/1 | as R-PASTE.3/1 | Box A `COPYME-1` | | gap | not_run |
| R-PASTE.4/2 | Verify the same, multi-line | normal | as R-PASTE.3/2 | as R-PASTE.3/2 | Box M `COPYME-2` | | gap | not_run |
| R-PASTE.5/1 | Verify that Ctrl+C with no selection in a single-line box changes no clipboard | normal | LinuxH and WinCI; app clipboard `BEFORE`; WinCI: Other-program write `OS-BEFORE`; Box A `KEEP`, cursor at the end, no selection | `ctrl+c` | the app clipboard `BEFORE`; WinCI: Other-program read `OS-BEFORE` (base: holds for the app clipboard, B pilot P5) | | gap | not_run |
| R-PASTE.5/2 | Verify the same in a multi-line box | normal | as /1, Box M | `ctrl+c` | as /1 | | gap | not_run |
| R-PASTE.5/3 | Verify that Ctrl+X with no selection in a single-line box changes no clipboard | normal | as /1 | `ctrl+x` | as /1; Box A `KEEP` | | gap | not_run |
| R-PASTE.6/1 | Verify that Ctrl+X copies the selection, single-line | normal | LinuxH and WinCI; Box A `CUTME-1` | Select, `ctrl+x` | the app clipboard `CUTME-1`; WinCI: Other-program read `CUTME-1` | | gap | not_run |
| R-PASTE.6/2 | Verify the same, multi-line | normal | as /1, Box M `CUT\nME-2` | `f7`, `ctrl+x` | the app clipboard `CUT\nME-2`; WinCI: the read equals it | | gap | not_run |
| R-PASTE.7/1 | Verify that Ctrl+X removes the selected part, single-line | normal | LinuxH; Box A `DE AD BE EF` | `home`, `shift+right` × 5, `ctrl+x` | Box A ` BE EF`; the app clipboard `DE AD` | | gap | not_run |
| R-PASTE.7/2 | Verify the same, multi-line | normal | LinuxH; Box M `DE AD BE EF` | `ctrl+home`, `shift+right` × 5, `ctrl+x` | Box M ` BE EF`; the app clipboard `DE AD` | | gap | not_run |
| R-PASTE.8/1 | Verify that Ctrl+X with no selection cuts the cursor's line in a multi-line box | normal | LinuxH; Box M `first\nline_to_cut\nthird`, cursor at (1, 2), no selection | `ctrl+x` | Box M `first\nthird`; the app clipboard `line_to_cut` with or without one line end, never empty | | gap | not_run |
| R-PASTE.9/1 | Verify the write failure warning on Linux after every copy and cut | robustness | LinuxH; Notices | Box A and Box M: Select, `ctrl+c`; Select, `ctrl+x` (4 actions) | 4/4: a warning "Clipboard write failed — copied inside the app only.", severity warning, 6 s (base: holds, B pilot P5) | | gap | not_run |
| R-PASTE.9/2 | Verify the warning when another program holds the clipboard | robustness | WinCI; Held clipboard (8 s); Notices | Box A, then Box M: Select, `ctrl+c` | 2/2 warnings, exact text | | gap | not_run |
| R-PASTE.9/3 | Verify that on Linux a copy leaves the X clipboard as it was (D-2 A) | robustness | LinuxX; X seed `X-BEFORE` | Box A `COPY-X`: Select, `ctrl+c` | X read `X-BEFORE`; the warning shows | | gap | not_run |
| R-PASTE.10/1 | Verify a WARNING line per failed copy, without the copied text | robustness | LinuxH; Log capture | Box A `SECRET-COPY-43`, then Box M: Select, `ctrl+c` | ≥ 1 WARNING record per copy; no record holds `SECRET-COPY-43` (base: holds, B pilot stderr) | | gap | not_run |
| R-PASTE.11/1 | Verify that a Ctrl+C from a single-line box ends within the typed-key time plus 100 ms | normal | WinCI; real app; Box A | Typed-key time; then 10 × (type `C<k>`, Select, `ctrl+c`) | median end of the copy (Own read sees `C<k>`) ≤ typed-key time + `timing_bound(0.1)` s | | gap | not_run |
| R-PASTE.11/2 | Verify the same from a multi-line box (Ctrl+X) | normal | WinCI; Box M | as /1 with `f7`, `ctrl+x` | as /1 | | gap | not_run |
| R-PASTE.11/3 | Verify that on Linux the copy ends within the typed-key time plus 100 ms | normal | LinuxH; Box A; Notices | as /1 | median time to the write failure warning ≤ typed-key time + bound (base: holds without a Tk root; with one, 1,001 ms, B pilot P3 — the RED needs LinuxX) | | gap | not_run |
| R-PASTE.12/1 | Verify that a copy over the limit keeps its first 65,536 characters | robustness | LinuxH and WinCI; Box M holds P70k; Box A's value set to P70k; OSC 52 spy | in each box: Select, `ctrl+c` | the app clipboard 65,536 characters; the decoded OSC 52 request 65,536 characters (2/2 boxes) | | gap | not_run |
| R-PASTE.12/2 | Verify the same on the OS clipboard | robustness | WinCI; as /1 | as /1 | Other-program read: 65,536 characters (2/2) | | gap | not_run |
| R-PASTE.13/1 | Verify that a copy ends within 2.5 s when another program holds the clipboard, single-line | robustness | WinCI; Held clipboard (8 s); Notices | Box A: Select, `ctrl+c` | the warning shows ≤ `timing_bound(2.5)` s after the key | | gap | not_run |
| R-PASTE.13/2 | Verify the same, multi-line, Ctrl+X | robustness | as /1, Box M | `f7`, `ctrl+x` | as /1 | | gap | not_run |
| R-PASTE.14/1 | Verify that the screen stays responsive while a write waits on a held clipboard | robustness | WinCI; Held clipboard (8 s); Tick lateness armed | Box A: Select, `ctrl+c` | ≥ 10 ticks before the end of the copy; every tick late by ≤ `timing_bound(0.1)` s | | gap | not_run |
| R-PASTE.15/1 | Verify one OSC 52 request for a Ctrl+C, single-line | normal | LinuxH; OSC 52 spy; Box A P1 | Select, `ctrl+c` | exactly 1 request; it decodes to P1 (base: holds, B pilot P5) | | gap | not_run |
| R-PASTE.15/2 | Verify the same for a Ctrl+X, single-line | normal | as /1 | Select, `ctrl+x` | 1 request, P1 | | gap | not_run |
| R-PASTE.15/3 | Verify the same for a Ctrl+C, multi-line | normal | LinuxH; OSC 52 spy; Box M P2 | `f7`, `ctrl+c` | 1 request, P2 | | gap | not_run |
| R-PASTE.15/4 | Verify the same for a Ctrl+X, multi-line | normal | as /3 | `f7`, `ctrl+x` | 1 request, P2 | | gap | not_run |
| R-PASTE.15/5 | Verify the same for a line cut | normal | LinuxH; OSC 52 spy; Box M `first\nline_to_cut\nthird`, cursor in line 2 | `ctrl+x` | 1 request, decoding to the cut line (as R-PASTE.8/1) | | gap | not_run |

## PowerShell by its system path

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-PASTE.16/1 | Verify that the read rescue starts the system PowerShell by its full path | normal | WinCI; Process spy; Other-program write `PS-READ`; Held clipboard (0.3 s), so the Win32 read fails and the PowerShell read finds it free | `ctrl+v` in Box A | the spy records 1 start whose program is the system PowerShell's absolute path; Box A `PS-READ` (base: the bare name `powershell`, R) | | gap | not_run |
| R-PASTE.16/2 | Verify the same for the write rescue | normal | WinCI; Process spy; Held clipboard (0.3 s) | Box A `PS-WRITE`: Select, `ctrl+c` | 1 start, absolute path; Other-program read `PS-WRITE` | | gap | not_run |
| R-PASTE.16/3 | Verify that a decoy `powershell.exe` in the current folder and first on PATH never runs | robustness | WinCI; a copy of a program that is not PowerShell (e.g. `sys.executable`) named `powershell.exe` in the test's current folder and in a folder put first on PATH; Process spy; as /1 | `ctrl+v` in Box A | Box A `PS-READ` (the real PowerShell answered); 0 starts of either decoy path (base: the decoy in the current folder runs — Windows searches the current folder before the system folder for a bare name — and Box A gets no `PS-READ`) | | gap | not_run |
| R-PASTE.17/1 | Verify that no program starts when the system PowerShell is missing, read | robustness | WinCI; the system-folder lookup pointed at an empty temporary folder; Process spy; app clipboard `APP-TEXT`; Held clipboard (8 s) | `ctrl+v` in Box A | 0 process starts; Box A `APP-TEXT` (R-TUI-043.6) | | gap | not_run |
| R-PASTE.17/2 | Verify the same, write | robustness | as /1; Notices | Box A: Select, `ctrl+c` | 0 process starts; the write failure warning | | gap | not_run |

## Every window: the walk (one round trip per place)

Each walk case: open the place by its own key or control; click the box; Clear; type `W<n>-` + P1 (single-line) or `W<n>-` + P2 (multi-line); Select; `ctrl+c`; check the copy (WinCI: Other-program read equals the text; LinuxH: the app clipboard equals it) — this check is the place's case of R-PASTE.19/2; Clear; `ctrl+v`; the box holds the text again (single-line: the one line). Class normal. Platforms: LinuxH and WinCI. Fixtures for the places that need a project, a flow or an A2L: `tests/b97_fixtures` (`make_project`, `load_project`, `open_check_editor`, `open_flow_builder`, `fx_project`). The places and boxes are the census's (C).

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-TUI-044.1/1 | Verify copy and paste in the Workspace find box | normal | rail `1`; `/` (find) | walk | `#search_input` (`app.py:3505`) round trip | | gap | not_run |
| R-TUI-044.1/2 | Verify the A2L Explorer filter box | normal | rail `2` | walk | `#a2l_tags_filter_input` (`app.py:8498`) | | gap | not_run |
| R-TUI-044.1/3 | Verify the MAC View search box | normal | rail `3`; `/` | walk | `#mac_search_input` (`app.py:8619`) | | gap | not_run |
| R-TUI-044.1/4 | Verify the Patch Editor address box | normal | rail `6` | walk | `#patch_entry_address_input` (`screens_directionb.py:4996`) | | gap | not_run |
| R-TUI-044.1/5 | Verify the Check Editor memory-address box | normal | rail `=` | walk | `#check_mem_address_input` (`screens_directionb.py:7748`) | | gap | not_run |
| R-TUI-044.1/6 | Verify the A↔B diff path box | normal | rail `7` | walk | `#diff_path_a` (`screens_directionb.py:8401`) | | gap | not_run |
| R-TUI-044.1/7 | Verify the Flow Builder reference box | normal | rail `8`; a project open | walk | `#flow_ref` (`flow_screens.py:1632`) | | gap | not_run |
| R-TUI-044.1/8 | Verify the Flow Execution set-name box | normal | rail `]`; FX project | walk | `#fx_set_name` (`flow_screens.py:3329`) | | gap | not_run |
| R-TUI-044.1/9 | Verify a CRC Designer field | normal | rail `0` | walk | `#crc_field_width` (`crc_designer_view.py:546`) | | gap | not_run |
| R-TUI-044.1/10 | Verify the command palette box | normal | `ctrl+k` | walk | `#palette_input` (`command_bar.py:147`) | | gap | not_run |
| R-TUI-044.1/11 | Verify the Load dialog path box | normal | `ctrl+l` | walk | `#load_path` (`screens.py:401`); the text stays under 4,096 characters | | gap | not_run |
| R-TUI-044.1/12 | Verify the Save project name box | normal | an image loaded; `ctrl+s` | walk | `#project_name` (`screens.py:1260`) | | gap | not_run |
| R-TUI-044.1/13 | Verify the Save flow name box | normal | Flow Builder with a block; its Save | walk | `#flow_save_name` (`screens.py:1519`) | | gap | not_run |
| R-TUI-044.1/14 | Verify the file-reference chooser path box | normal | Flow Builder; its file chooser | walk | `#flow_external_path_input` (`screens.py:1774`) | | gap | not_run |
| R-TUI-044.1/15 | Verify the Edit block reference box | normal | Flow Builder with a block; Edit | walk | the reference box of `FlowBlockEditScreen._ref_row` (`screens.py:2062`) | | gap | not_run |
| R-TUI-044.1/16 | Verify the Reports filter path box | normal | a project open; `t` | walk | `#report_filter_path` (`screens.py:3328`) | | gap | not_run |
| R-TUI-044.1/17 | Verify the Operations config path box | normal | `x` | walk | `#operation_config_path` (`screens.py:3722`) | | gap | not_run |
| R-TUI-044.1/18 | Verify that every single-line box is built with the paste | normal | the tree under test | AST census of `s19_app/` (the shape of `evidence-e1/i1a-census.py` part A) | 0 constructions of a stock `Input`; every single-line box an `OsClipboardInput` (40 at base, C); the census reports a planted stock `Input` (positive control) | | gap | not_run |
| R-PASTE.18/1 | Verify copy and paste in the Patch Editor paste buffer | normal | rail `6`; the JSON tab chip | walk | `#patch_paste_text` (`screens_directionb.py:5056`) | | gap | not_run |
| R-PASTE.18/2 | Verify the Split / Join / Export manual ranges | normal | its opener (`action_open_split_join_export`) | walk | `#sje_manual` (`segment_split_view.py:1556`) | | gap | not_run |
| R-PASTE.18/3 | Verify the change-set JSON popup | normal | rail `6`; Edit JSON under the paste buffer | walk | `#changeset_json_text` (`screens.py:771`) | | gap | not_run |
| R-PASTE.18/4 | Verify the entry JSON popup | normal | rail `6`; a pasted document with one entry; its JSON edit | walk | `#entry_json_text` (`screens.py:858`) | | gap | not_run |
| R-PASTE.18/5 | Verify the Add list popup | normal | Check Editor with the demo A2L; `Add list` | walk | `#bulk_param_text` (`screens.py:975`) | | gap | not_run |
| R-PASTE.18/6 | Verify the Reports declared-regions box | normal | a project open; `t` | walk | `#report_declared_regions` (`screens.py:3301`) | | gap | not_run |
| R-PASTE.18/7 | Verify the Operations config box | normal | `x` | walk | `#operation_config` (`screens.py:3727`) | | gap | not_run |
| R-PASTE.18/8 | Verify that every multi-line box is built with the paste | normal | the tree under test | AST census | 0 constructions of a stock `TextArea` that is not read-only; every multi-line box a `CappedTextArea` or a subclass (7 at base, C); a planted stock `TextArea` is reported | | gap | not_run |
| R-PASTE.19/1 | Verify that every text box is built with the copy | normal | the tree under test | the censuses of R-TUI-044.1/18 and R-PASTE.18/8 | 47/47 text boxes are `OsClipboardInput` or `CappedTextArea` (C: 40 + 7) | | gap | not_run |
| R-PASTE.19/2 | Verify the copy step of every place | normal | as the 24 walk cases | the walk's copy step | 24/24 copies checked (WinCI: Other-program read; LinuxH: the app clipboard) | | gap | not_run |

## Test arrangement

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-PASTE.20/1 | Verify that the workflows run the OS clipboard tests on a hosted Windows runner | normal | the tree under test | the workflow file of D-6, read as text | 1 job with `runs-on: windows-latest`; triggers `pull_request` and `push` on `main`, `main-tui` (and `workflow_dispatch` under D-6 B); `permissions: contents: read`; checkout with `persist-credentials: false`; a step that runs the OS clipboard test files serially; no run line matching the R-TST-010 injection ratchet; negative control: `runs-on: ubuntu-latest` → RED | | gap | not_run |
| R-PASTE.20/2 | Verify on the first run that the tests ran | normal | WinCI, the job's first run | the job log | the OS clipboard tests are listed as passed, failed or skipped by R-PASTE.22, none deselected; the log names the probe's result | | gap | not_run |
| R-PASTE.21/1 | Verify that a Windows clipboard that is not GitHub-hosted stops the test before it opens | robustness | a guard check with `sys.platform` = `win32` and `RUNNER_ENVIRONMENT` = `self-hosted` (and, again, unset); a spy on the clipboard-opening functions | the guard | the test fails with the guard's message; the spy counts 0 opens | | gap | not_run |
| R-PASTE.21/2 | Verify that an X display the session did not start stops the test | robustness | LinuxH; `DISPLAY=:99` set, no Xvfb started by the session; the spy | the guard | fails before any open; the spy counts 0 (no X connection is attempted) | | gap | not_run |
| R-PASTE.21/3 | Verify that an isolated clipboard lets the test go on | normal | WinCI (and LinuxX, blocked) | the guard | the test goes on; the probe runs | | gap | not_run |
| R-PASTE.22/1 | Verify that a failed probe skips the OS clipboard tests with the reason | robustness | LinuxH; a probe result stand-in that reports a read differing from the nonce (`<probe result>` = e.g. `win32 write ok, PowerShell read ''`) | collect and run the OS clipboard test files (a `pytester` run) | every OS clipboard test is skipped with the reason `runner clipboard unusable: <probe result>`; 0 failed; a passing stand-in skips none | | gap | not_run |
| R-PASTE.22/2 | Verify whether the hosted runner exposes a usable clipboard (the PLAN's open risk) | normal | WinCI, first run | the clipboard probe; also: can a Tk root be created there (for the RED-on-base runs) | the probe's result recorded in the job log: usable, or the D-7 ruling applies | | gap | not_run |

## Acceptance (black box, through the keys)

Matrix sources: Box A (P1) and Box M (P2). Targets: Box A' and Box M'. Route 1: `ctrl+v` in the target. Route 2: the terminal reads the clipboard and pastes — WinCI: Other-program read, then Terminal paste of that text; LinuxH: the decoded OSC 52 request of the copy, then Terminal paste (a terminal that honours OSC 52). Each cell: click the source, Clear, type the payload, Select, `ctrl+c`, click the target, Clear, paste by the route. Platforms: WinCI (the OS route, full) and LinuxH (the app clipboard and OSC 52 route).

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests (full / partial) | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| AT-I1a-1 | Verify copy from a single-line box, paste into a single-line box by Ctrl+V (US-103-01) | normal | real app | Box A → Box A', route 1 | Box A' P1 — rows R-PASTE.2, .3, R-TUI-043.4 | | gap | not_run |
| AT-I1a-2 | … single-line → single-line by terminal paste | normal | real app | Box A → Box A', route 2 | Box A' P1 — R-PASTE.2, .15, R-PASTE.1 | | gap | not_run |
| AT-I1a-3 | … single-line → multi-line by Ctrl+V | normal | real app | Box A → Box M', route 1 | Box M' P1 — R-PASTE.2, R-TUI-044.3 | | gap | not_run |
| AT-I1a-4 | … single-line → multi-line by terminal paste | normal | real app | Box A → Box M', route 2 | Box M' P1 — R-PASTE.2, .15, R-TUI-044.4 | | gap | not_run |
| AT-I1a-5 | … multi-line → single-line by Ctrl+V | normal | real app | Box M → Box A', route 1 | Box A' `L1 Ñ€` (the first line) — R-PASTE.2, R-TUI-043.4 | | gap | not_run |
| AT-I1a-6 | … multi-line → single-line by terminal paste | normal | real app | Box M → Box A', route 2 | Box A' `L1 Ñ€` — R-PASTE.1 | | gap | not_run |
| AT-I1a-7 | … multi-line → multi-line by Ctrl+V | normal | real app | Box M → Box M', route 1 | Box M' P2 — R-TUI-044.3 | | gap | not_run |
| AT-I1a-8 | … multi-line → multi-line by terminal paste | normal | real app | Box M → Box M', route 2 | Box M' P2 — R-TUI-044.4 | | gap | not_run |
| AT-I1a-9 | Verify through the keys that a paste lands at once (US-103-01) | normal | WinCI; real app; Other-program write P1000 | in Box A, then Box M: Typed-key time; `ctrl+v` × 10; then Terminal paste (P1000) × 10 | both routes, both boxes: median end of the paste ≤ typed-key time + `timing_bound(0.1)` s — rows R-TUI-043.10.1, R-PASTE.1, R-TUI-044.4 (base: route 1 ≈ 3.4 s with a Tk root, F; route 2 holds, F §1.4) | | gap | not_run |
| AT-I1a-10 | Verify on the operator's work PC that Ctrl+V lands as fast as Ctrl+Shift+V and that a copy reaches Notepad (US-103-01; PROPOSED, D-7) | normal | operator-run, on his own PC and clipboard, by his choice (no agent touches it); the merged build; Windows Terminal (and conhost, if he uses it) | in the A2L filter box and the Patch Editor paste buffer: Ctrl+V, then Ctrl+Shift+V, of a path copied in Explorer; then Ctrl+C of a selection and Ctrl+V in Notepad | both keys paste with no wait the operator can notice; Notepad shows the copied text; his verdict recorded (base: Ctrl+V slow on the work PC per the story; the acceptance hint of F §1.5 H1) | | gap | not_run |

**Counts:** 111 cases: 101 coverage items over the 25 active rows and the 12 cited rows (R-TUI-043.10.1 4, .10.2 2, .9 1, .6 4, .4 1, R-TUI-044.3 1, R-TUI-043.5 3, .7 1, .8 1, .11 1, .12 2, .13 1; R-PASTE.1 2, R-TUI-044.4 1, R-TUI-044.2 5; R-PASTE.2 2, .3 2, .4 2, .5 3, .6 2, .7 2, .8 1, .9 3, .10 1, .11 3, .12 2, .13 2, .14 1, .15 5; R-PASTE.16 3, .17 2; R-TUI-044.1 18, R-PASTE.18 8, .19 2; R-PASTE.20 2, .21 3, .22 2) and 10 acceptance cases. By platform (a case "as /1" takes /1's platform): 32 LinuxH only (runnable now); 44 on both LinuxH and WinCI (their LinuxH arm runnable now; the 24 walk cases, AT-I1a-1 … 8, the copy rules); 32 WinCI only (blocked until a push and the probe); 2 LinuxX only (R-TUI-043.6/4, R-PASTE.9/3; blocked until Xvfb and xclip, as are the X half of R-PASTE.21/3 and the Linux RED-on-base runs of R-TUI-043.10.1 and R-PASTE.11); 1 operator-run (AT-I1a-10). Negative controls (the mutant of each row, run at E5 in a copy of the tree): `01-requirements.md`, column "Negative control".
