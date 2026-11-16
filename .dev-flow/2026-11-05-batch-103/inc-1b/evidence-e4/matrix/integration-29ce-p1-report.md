# Matrix integration 29ce6448 — Linux P1 verification

Verdict: **14/14 Linux P1 cells passed**. This is not full-matrix or WinCI coverage: 14 P2 cells remain `not_run`, and manual AT-I1b-8 remains `not_run`.

The run collected 29 nodes and produced **14 passed, 0 failed, 0 errors, 15 skipped**, `PYTEST_EXIT=0`, in 263.37 s. JUnit timestamp: `2026-11-12T10:28:49.620398-06:00`.

## Fixture correction

Only `tests/test_b103_copy_paste_matrix.py` changed, in `_prepare_target` for T1. After the existing `2`, `/` navigation and `#a2l_tags_filter_input` lookup, the fixture now calls `widget.focus()` and settles twice before the unchanged assertions:

- `widget.value == ""`;
- `app.focused is widget`;
- the real right-click copy equals the independent source;
- Ctrl+V pastes the first line exactly once into T1 or every line exactly once into T2.

The previous premise that `/` focuses `#a2l_tags_filter_input` was stale: current integration focuses `#alt_search_input`. The correction explicitly focuses the required target after navigation. It does not replace the target, inject paste text, skip the failing cell, or weaken any expected value.

## Exact integration and isolation

- Scratch: `<HOME>/work/b103-inc1b-matrix-29ce-TM4GTv`.
- The scratch was cloned with `git clone --shared /tmp/b103-inc6-merge-final <scratch>/tree`, then fetched `<HOME>/work/inc1b-integration.bundle` and checked out detached at `29ce6448e49cc8a67ecf7a5a7c38a4f31833368c`.
- Only the corrected matrix test was overlaid. Post-run HEAD remained `29ce6448`; post-run status listed only `M tests/test_b103_copy_paste_matrix.py`; `git diff --check` was empty.
- Python `<HOME>/miniconda3/envs/s19ci/bin/python -I -B`, Python 3.11.18, host `<HOST>`, Linux. `.` was inserted into `sys.path` before importing `s19_app`; its resolved scratch path is the first transcript line.
- Fresh neutral `TMPDIR`, `HOME`, all four XDG/LOCALAPPDATA paths, stdin `/dev/null`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, pytest cache disabled, and `DISPLAY`/`WAYLAND_DISPLAY` unset.
- No product or other test file was edited, no commit/push occurred, and no operator clipboard was accessed.
- Linux performed no PowerShell seed/read and no separate OS read. The executed route is the permitted app-clipboard route, not a substitute OS artifact or a WinCI claim.

## What each P1 pass proves

Every P1 cell executed all of the following, rather than stopping at the earlier base RED:

1. The seven real sources were armed independently and right-clicked through back-to-back driver `MouseDown`/`MouseUp` events.
2. `app.clipboard` was read and asserted exactly equal to the independent selection or canonical row name.
3. The requested target was prepared. T1 used explicit target focus after `2`, `/`; T2 used the JSON tab, clicked `#patch_paste_text`, and selected its template with F7.
4. Ctrl+V was pressed with that target focused.
5. T1's value equaled exactly the source's first line once; T2's text equaled the complete source, every selected line exactly once.

## Per-case results

`partial/pass` means full Linux P1 execution through the app clipboard, without the WinCI-only separate OS read. `gap/not_run` means pytest skipped before app construction and no copy/read/paste phase ran.

| Case | Target / route | Linux coverage | Result | Executed assertion |
|---|---|---|---|---|
| AT-I1b-1/1 | T1 / P1 | partial | pass | three-line hex copy → app read → Ctrl+V → first line once (16.515 s) |
| AT-I1b-1/2 | T1 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-1/3 | T2 / P1 | partial | pass | three-line hex copy → app read → Ctrl+V → all three lines once (18.629 s) |
| AT-I1b-1/4 | T2 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-2/1 | T1 / P1 | partial | pass | five-line stats copy → app read → Ctrl+V → first line once (17.625 s) |
| AT-I1b-2/2 | T1 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-2/3 | T2 / P1 | partial | pass | five-line stats copy → app read → Ctrl+V → all five lines once (18.844 s) |
| AT-I1b-2/4 | T2 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-3/1 | T1 / P1 | partial | pass | selected A2L summary copy → app read → Ctrl+V → first line once (18.113 s) |
| AT-I1b-3/2 | T1 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-3/3 | T2 / P1 | partial | pass | selected A2L summary copy → app read → Ctrl+V → complete selection once (19.194 s) |
| AT-I1b-3/4 | T2 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-4/1 | T1 / P1 | partial | pass | full A2L third-row name → app read → Ctrl+V → exact name once (17.173 s) |
| AT-I1b-4/2 | T1 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-4/3 | T2 / P1 | partial | pass | full A2L third-row name → app read → Ctrl+V → exact name once (18.892 s) |
| AT-I1b-4/4 | T2 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-5/1 | T1 / P1 | partial | pass | `Curve_ExternalAxis` copy → app read → Ctrl+V → exact name once (17.762 s) |
| AT-I1b-5/2 | T1 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-5/3 | T2 / P1 | partial | pass | `Curve_ExternalAxis` copy → app read → Ctrl+V → exact name once (18.629 s) |
| AT-I1b-5/4 | T2 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-6/1 | T1 / P1 | partial | pass | two JSON lines → app read → Ctrl+V → first line once (20.495 s) |
| AT-I1b-6/2 | T1 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-6/3 | T2 / P1 | partial | pass | two JSON lines → app read → Ctrl+V → both lines once (21.298 s) |
| AT-I1b-6/4 | T2 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-7/1 | T1 / P1 | partial | pass | Workspace-help selection → app read → Ctrl+V → first line once (19.320 s) |
| AT-I1b-7/2 | T1 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-7/3 | T2 / P1 | partial | pass | Workspace-help selection → app read → Ctrl+V → complete selection once (20.792 s) |
| AT-I1b-7/4 | T2 / P2 | gap | not_run / skipped | WinCI separate OS read required; no phases executed |
| AT-I1b-8 | manual Windows Terminal | manual gap | not_run / skipped | six operator-only steps; no agent clipboard access |

## Coverage and remaining blockers

- Linux P1 executed and passed: **14/14 attempted cells**, or **14/28 matrix cells** with documented partial coverage.
- P2 terminal-paste cells: **14/14 not_run**. They still require the isolated WinCI copy → separate OS read → `events.Paste(read_text)` chain.
- Full separate-OS-artifact coverage remains **0/28** in this Linux run; no such coverage is inferred from P1 passes or P2 skips.
- AT-I1b-8 remains manual `not_run` until the operator performs and reports all six steps.
- The historical base RED evidence is preserved separately in `red-*`; this report covers only integration `29ce6448` with the corrected fixture.

## SHA-256

| File | SHA-256 |
|---|---|
| `tests/test_b103_copy_paste_matrix.py` | `68066bcce992de8a49e475b3f6eee8060a1518fbc1f8966572deeea905279038` |
| `integration-29ce-p1-transcript.txt` | `41ea3823fb1f918d3d6f4ebdeb28de79a0b6de904f3b3bd443ce4162a6f6653e` |
| `integration-29ce-p1-junit.xml` | `e8e19577db2c96cd0a289c6cc5e4cdd33a57583b8ab5ce4c666d2f274412e22f` |

Local and remote hashes match. The complete transcript has 74 lines / 6,533 bytes and ends with the integration HEAD, the test-only status, empty diff check, and `PYTEST_EXIT=0`.
