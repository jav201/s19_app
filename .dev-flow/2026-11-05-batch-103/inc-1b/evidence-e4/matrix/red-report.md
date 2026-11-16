# E4 matrix — Linux RED report

Verdict: **RED on the unmodified base; not GREEN**. The run collected 29 nodes: 28 acceptance cells plus manual AT-I1b-8. It produced **0 passed, 14 failed, 0 errors, 15 skipped**, exit code 1, in 196.31 s. The 15 skips are exactly 14 WinCI-only terminal-paste cells and AT-I1b-8. No skip is claimed as verification or WinCI coverage.

## Base and isolation

- Local design base: `e2e935482646553a34242e524af5ac5bc57af82b`.
- Linux clone HEAD before and after the run: `c062293be6c122ecceca5701ea8afd0c6700f008`.
- `git diff --quiet e2e93548 c062293b -- s19_app tests` returned 0 locally, confirming the brief's product/test equivalence.
- Fresh scratch: `<HOME>/work/b103-inc1b-e4-matrix-cq9kSP`; clone command: `git clone --shared /tmp/b103-inc6-merge-final <scratch>/tree`.
- Only `tests/test_b103_copy_paste_matrix.py` was overlaid. Remote `git status --short` before collection and after the final run listed only that file as untracked.
- Python: `<HOME>/miniconda3/envs/s19ci/bin/python -I -B`, Python 3.11.18, host `<HOST>`, Linux. `.` was inserted in `sys.path` before importing `s19_app`; the transcript starts with the resolved `s19_app.__file__` inside the scratch.
- stdin was `/dev/null`; `PYTHONDONTWRITEBYTECODE=1`; `PYTHONIOENCODING=utf-8`; pytest used `-p no:cacheprovider` and wrote JUnit XML.
- Fresh neutral `TMPDIR`, `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, and `LOCALAPPDATA` under the scratch. `DISPLAY` and `WAYLAND_DISPLAY` were unset.
- No OS clipboard recorder, successful writer shim, direct `_on_paste` injection, or fabricated separate read was used. The only separate-reader implementation is absolute-path system PowerShell `Get-Clipboard -Raw`, guarded by `sys.platform == "win32"`, `GITHUB_ACTIONS == "true"`, and `RUNNER_ENVIRONMENT == "github-hosted"` before any OS write.
- Linux performed zero separate OS reads and zero PowerShell seed writes. No clipboard on the operator PC was read or written. AT-I1b-8 never starts an app or accesses a clipboard.
- JUnit timestamp: `2026-11-12T09:06:27.902885-06:00`.

## Coverage accounting

- Full copy → separate OS read → paste cells verified: **0/28**. WinCI was not run.
- Linux P1 cells executed to the independent-copy assertion: **14/28**, all RED. Their coverage is **partial**, because the failing base leaves `app.clipboard == "SEED-1b"` and the test stops before target preparation and Ctrl+V.
- Linux P2 cells: **14/28 not_run**, coverage **gap**. No app, copy, OS read, or paste was executed for these cells.
- AT-I1b-8: **manual not_run**, coverage **gap**, six operator steps pending by design.
- Paste-consumer results (T1 first line exactly once; T2 every line exactly once) therefore remain unverified on this base; they are encoded in every cell but were not reached in the final Linux RED run.

## Per-case results

`partial/RED` below means the source fixture and driver-route right-click executed, then the independent app-clipboard assertion failed; it does not mean the paste executed. `gap/not_run` means pytest skipped before app construction. The complete failure text and skip reasons are in `red-transcript.txt` and `red-junit.xml`.

| Case | On-disk pytest node parameter | Linux coverage | Result | Exact observed boundary |
|---|---|---|---|---|
| AT-I1b-1/1 | `AT-I1b-1/1-T1-P1` | partial | RED / failed | three-line hex source captured; clipboard remained `SEED-1b`; T1 paste not reached |
| AT-I1b-1/2 | `AT-I1b-1/2-T1-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-1/3 | `AT-I1b-1/3-T2-P1` | partial | RED / failed | three-line hex source captured; clipboard remained `SEED-1b`; T2 paste not reached |
| AT-I1b-1/4 | `AT-I1b-1/4-T2-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-2/1 | `AT-I1b-2/1-T1-P1` | partial | RED / failed | five-line stats source captured; clipboard remained `SEED-1b`; T1 paste not reached |
| AT-I1b-2/2 | `AT-I1b-2/2-T1-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-2/3 | `AT-I1b-2/3-T2-P1` | partial | RED / failed | five-line stats source captured; clipboard remained `SEED-1b`; T2 paste not reached |
| AT-I1b-2/4 | `AT-I1b-2/4-T2-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-3/1 | `AT-I1b-3/1-T1-P1` | partial | RED / failed | two-line A2L summary selection, not whole view; clipboard remained `SEED-1b`; T1 paste not reached |
| AT-I1b-3/2 | `AT-I1b-3/2-T1-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-3/3 | `AT-I1b-3/3-T2-P1` | partial | RED / failed | two-line A2L summary selection, not whole view; clipboard remained `SEED-1b`; T2 paste not reached |
| AT-I1b-3/4 | `AT-I1b-3/4-T2-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-4/1 | `AT-I1b-4/1-T1-P1` | partial | RED / failed | canonical full A2L third-row name; clipboard remained `SEED-1b`; T1 paste not reached |
| AT-I1b-4/2 | `AT-I1b-4/2-T1-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-4/3 | `AT-I1b-4/3-T2-P1` | partial | RED / failed | canonical full A2L third-row name; clipboard remained `SEED-1b`; T2 paste not reached |
| AT-I1b-4/4 | `AT-I1b-4/4-T2-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-5/1 | `AT-I1b-5/1-T1-P1` | partial | RED / failed | canonical MAC third record `Curve_ExternalAxis`; clipboard remained `SEED-1b`; T1 paste not reached |
| AT-I1b-5/2 | `AT-I1b-5/2-T1-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-5/3 | `AT-I1b-5/3-T2-P1` | partial | RED / failed | canonical MAC third record `Curve_ExternalAxis`; clipboard remained `SEED-1b`; T2 paste not reached |
| AT-I1b-5/4 | `AT-I1b-5/4-T2-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-6/1 | `AT-I1b-6/1-T1-P1` | partial | RED / failed | two JSON lines selected before dispatch; clipboard remained `SEED-1b`; T1 paste not reached |
| AT-I1b-6/2 | `AT-I1b-6/2-T1-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-6/3 | `AT-I1b-6/3-T2-P1` | partial | RED / failed | two JSON lines selected before dispatch; clipboard remained `SEED-1b`; T2 paste not reached |
| AT-I1b-6/4 | `AT-I1b-6/4-T2-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-7/1 | `AT-I1b-7/1-T1-P1` | partial | RED / failed | two non-empty Workspace-help lines plus their selected blank separator; clipboard remained `SEED-1b`; T1 paste not reached |
| AT-I1b-7/2 | `AT-I1b-7/2-T1-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-7/3 | `AT-I1b-7/3-T2-P1` | partial | RED / failed | two non-empty Workspace-help lines plus their selected blank separator; clipboard remained `SEED-1b`; T2 paste not reached |
| AT-I1b-7/4 | `AT-I1b-7/4-T2-P2` | gap | not_run / skipped | requires real WinCI separate read; no phases executed |
| AT-I1b-8 | `test_manual_windows_terminal_operator_acceptance` | manual gap | not_run / skipped | operator-only six-step Windows Terminal acceptance; no agent clipboard access |

## Why the RED is discriminating

All 14 executed cells fail at the same missing Inc1b boundary: a valid back-to-back button-3 `MouseDown`/`MouseUp` posted to `App.post_message` does not replace the independently seeded app clipboard. This is the expected base behavior, not a collection error, an OS-clipboard substitution, or a paste-only failure.

Mutation targets encoded by the matrix:

1. **N3 capture/release:** removing the right-click route, or reading the selection only after toolkit dispatch clears it, leaves the seed instead of the pre-dispatch source (all 14 executed cells; especially JSON and help).
2. **N2 whole selection:** copying only a clicked fragment or a withdrawn whole view fails the independently captured selection equality (AT-I1b-1/2/3/6/7).
3. **N2 full row name:** using the highlighted row, shortened painted cell, glyph prefix, tab, or internal key fails the canonical model/ledger values (AT-I1b-4 and AT-I1b-5; cursor initially on row 0, click on row 2).
4. **N1/C1 mirror and OS artifact:** omitting the app mirror leaves `SEED-1b`; omitting the writer or writing a projected value fails the separate `Get-Clipboard -Raw` equality on WinCI. The latter is implemented but **not_run here**.
5. **T1 paste cardinality:** inserting every line or inserting the first line twice fails exact equality with `expected.split("\n", 1)[0]`.
6. **T2 paste cardinality:** dropping a line, duplicating text, or retaining the selected template fails exact equality with the complete independently copied source.
7. **Artifact bypass:** P2 accepts only text returned by the separate WinCI process after the real copy. Direct `events.Paste(expected)` without that artifact is not implemented and would not discharge the acceptance chain.

No mutants were run, as permitted by the brief.

## Files and SHA-256

| File | SHA-256 |
|---|---|
| `tests/test_b103_copy_paste_matrix.py` | `fb90c860abbe8afd953cf63e7693cf028a084f888345ad92932bdbff4102c11b` |
| `red-transcript.txt` | `0a05e765f74f3d017f7663474c5ec66315e7446352c2bec47980faf8b78a941a` |
| `red-junit.xml` | `dbaf47388e8b42d50b26b8d2c6d0bb2d66fd84e465397d1666146f57e8c74135` |

The copied local transcript and JUnit hashes match the remote hashes. The transcript has 3,095 lines / 144,294 bytes and includes the final HEAD, status, and `PYTEST_EXIT=1`.

## Remaining blockers

- All 28 full OS-artifact chains require the existing isolated WinCI route; none has WinCI coverage from this run.
- The 14 terminal-paste cells are precisely `not_run`, not skipped-as-passed.
- The 14 Linux P1 cells stop before Ctrl+V on the base because right-click copy is absent; their paste assertions need the integrated implementation run.
- AT-I1b-8 remains manual `not_run` until the operator chooses to execute and report all six steps.
- Integration owns GREEN. This report claims neither GREEN nor coverage from skips.
