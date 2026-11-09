# Inc 1a — E3 round 1 rulings (2026-11-06T19:14:01-06:00, orchestrator Opus 5.5)

Round 1: `E3-architect.md` **FAIL** (3 MAJOR, 5 MEDIUM, 3 MINOR, 1 LOW, 2 INFO); `E3-security.md` **FAIL** (2 MAJOR, 3 MEDIUM, 2 LOW, 5 INFO). The core design stands (Tk read and write removed; public names stable). Every finding is **accepted with its fix column**, with these rulings:

| Finding | Ruling |
|---|---|
| E3A-01 MAJOR (I-1 unusable by Inc 1b) | accept the recommendation, split by increment: **Inc 1a** — the copy tail calls the toolkit base `App.copy_to_clipboard(app, …)` (never an override), then writes the OS clipboard once; I-1 pins that an app-level override must call the tail, never the reverse. **Inc 1b** — its override calls the tail; it adds the copy notice to the tail, so `os_clipboard_input.py` joins Inc 1b's files (`app.py` + `os_clipboard_input.py`). Supersedes P-2's wording in `E2-rulings.md`. |
| E3A-02 MAJOR (E2-2) | accept the design fix: the Win32 read returns `''` when the clipboard opens but holds no text, and `''` ends the cascade (no PowerShell start). Cases: a file-drop clipboard and an image clipboard; a "0 PowerShell starts" control. |
| E3A-03 MAJOR (timing negative controls) | accept: LinuxH controls use a `tkinter.Tcl()` stand-in root that reproduces the Tk-on-executor delay (as E1's pilot did); WinCI controls use a delay mutant; every timing row and the copy rows get a control that goes RED with margin. |
| E3A-05 (`screen.focused`, not `has_focus`) | accept. |
| E3S-01 MAJOR (pasted escape sequences) | accept: one strip step with the repo's `_CONTROL_SCRUB` set at the four paste entry points of the two slice files; boxes with their own `restrict` filter keep it (R-LOADDLG.20 holds). New rows **R-PASTE.34** and **R-PASTE.35** as the fix column words them. |
| E3S-02 MAJOR (guard covers only the new tests) | accept: a suite-wide guard in `tests/conftest.py` (beside the `LOCALAPPDATA` one): no test writes the OS clipboard unless the isolation term holds; R-PASTE.21 says "every test". |
| E3S-03 MEDIUM | accept: the isolation term also requires the logged-on account `<user>` (read with `GetUserNameW`), so an environment variable alone never isolates a developer PC. |
| E3S-04 MEDIUM | accept: the Win32 read is bounded by `GlobalSize`. |
| E3S-05 MEDIUM (records the push would publish) | accept, batch-wide: before any push the orchestrator redacts the batch-103 records (the LAN host login and address, the Windows user-profile path, the runner home path) by a scripted replace, recorded with its command; this increment's tests extend the redaction gate (`tests/test_suite_hygiene.py` ~:2017) to the batch-103 folder. Host details move to a local, git-excluded note that briefs reference. |
| E2-1 | `focus_on_click()` confirmed (with E3A-05). |
| E2-5 | keep tag runs; never `tags-ignore` alone. |
| all other findings (E3A-04, -06 … -12; E3S-06, -07) | accept with their fix columns. INFO noted. |

**Next:** one correction pass (rows and cases; graph), then a round-2 re-check of the blocking findings by both reviewers.

## Round 2 rulings (2026-11-06T19:46:20-06:00, orchestrator Opus 5.5)

Round 2: architect **FAIL** (round-1 MAJORs closed; new MAJOR E3A-15, E3A-16 introduced by the correction pass); security **FAIL** (E3S-02/-03/-04 closed; E3S-01 open through new MAJORs E3S-13 … E3S-16; E3S-05 open as E3S-19). All accepted with their fix columns:

- **E3A-15 = E3S-13 (strip before the first-line split):** order of the paste step is fixed: a single-line box first takes the first line, then strips; a multi-line box keeps TAB, LF and CR and strips the rest of the set. R-PASTE.1, R-TUI-043.4, R-TUI-044.3, R-PASTE.29, .30 hold as written.
- **E3A-16 = E3S-14 (`restrict` boxes):** a box with its own `restrict` filter is not stripped; its restrict check runs on the raw pasted text and keeps refusing (R-LOADDLG.20 holds). A case pastes `a\x00.s19` into `#load_path` → refused.
- **E3S-15:** the strip set is the CTX term's (C0 and C1 controls, ESC, lone surrogates, bidi controls); the graph uses the same set. A lone surrogate is removed (it would kill Textual's Windows writer thread).
- **E3S-16:** case oracles assert the widget's value (no ESC, no surrogate in the value), never the painted line (the renderer adds its own style codes).
- **E3S-19 (E3S-05):** a row and a case in this increment: the redaction gate (`tests/test_suite_hygiene.py`) scans the batch-103 folder.
- All other round-2 findings: accept with their fix columns.

**Model change (skill: "when a model's work costs an extra pass, move that task up a class"):** the round-1 DeepSeek pass introduced E3A-15/16. This round's correction is done by **Opus**, one agent, targeted edits. Then round 3 by both reviewers, blocking findings only.

## Round 3 rulings (2026-11-06T20:24:44-06:00, orchestrator Opus 5.5)

Round 3: security **PASS-WITH-NOTES** (all round-2 MAJORs closed; MEDIUM E3S-24, E3S-25); architect **FAIL** (E3A-15, -16 closed; new MAJOR **E3A-25**: the strip removes the NUL that 12 existing tests paste into Flow Builder / Flow Execution path boxes, so a NUL path is added instead of refused — a silent transform; MEDIUM E3A-26, MINOR E3A-27, LOW E3A-28).

| Finding | Ruling |
|---|---|
| E3A-25 MAJOR | accept the recommended fix: **NUL leaves the strip set**; a pasted NUL reaches the box and its consumer refuses it, as today (the 12 tests hold unchanged). Principle for the set: strip only what is dangerous to draw (ESC and the other controls that start terminal sequences, C1, lone surrogates, bidi controls); never silently transform what a consumer already refuses. |
| E3S-24 MEDIUM | accept, fail closed: a `restrict` box (the Load path box) **refuses** a paste that holds a lone surrogate or a bidi control (paste refused, box unchanged, the existing refusal notice), instead of inserting it — a lone surrogate would freeze the Windows display. |
| E3S-25 MEDIUM | accept: the suite-wide guard also covers the module's low-level Win32 write, so no direct call can write a non-isolated clipboard. |
| E3A-26, E3A-27, E3A-28 | accept with their fix columns. E3A-24 (LOW) stays open until Inc 1b's E2. |

**Correction by Opus** (narrow, targeted edits), then a **round-4 architect check** limited to E3A-25 and the parts touched; security has passed and re-checks only if the pass touches the strip set's dangerous members.

## Round 4 rulings (2026-11-06T20:58:14-06:00, orchestrator Opus 5.5) — E3 done

Round 4 architect **PASS-WITH-NOTES** (E3A-25 … -28 closed; E3S-24/-25 closed; MINOR E3A-29, LOW E3A-30, 2 INFO); round 3 security **PASS-WITH-NOTES**. **E3 is done for Inc 1a.** Addenda applied by the orchestrator: cases R-LOADDLG.20/3 (right-click route, E3A-29) and /4 (DEL payload, keeps batch-100 mutant M04 killed, E3A-30); R-LOADDLG.20's threshold 4/4. E3A-24 (LOW) goes to Inc 1b's E2. **E4 blockers to clear:** Xvfb + xclip on <runner> for the 2 LinuxX cases (operator's `sudo pacman`); the WinCI arms need the approved branch push after the records are redacted (host login, LAN address, user-profile paths).
