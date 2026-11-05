# Inc 3 — E5 security review

Batch 2026-11-01-batch-101, increment 3. Reviewer: security-reviewer (independent). Tree: `b101-inc3` at `6355565`, base `9f9f6af`. Product diff: `s19_app/tui/services/project_gather_service.py` (composition limb, `:655-660`: an exact-text once-per-name set and `Path(os.path.normpath(resolved_project / name)).is_file()` in place of `.resolve()`) and `s19_app/tui/app.py` (the two `project_dir.mkdir(parents=True, exist_ok=True)` calls removed before `validate_project_files` at `:14939` and `:15061`). Records read: `01-requirements.md`, `E3-security.md`, `E3-rulings.md` (incl. round 2), `E3-r2.md`, `E4-integration-notes.md`. Code read: the gather limb and `_schedule` (`project_gather_service.py:636-675`), both syncs (`app.py:14933-15091`), the gather's issue logging (`app.py:12170-12171`), `_append_log_line` (`app.py:20696-20710`), `place_into_workarea` (`workspace.py:1049-1210`), `_reject_unsafe_entry` / `serialize_manifest` (`manifest_writer.py:208-432`), the reader's lexical fold (`manifest_writer.py:782`) and `_manifest_key_refusal` / `_entry_text` (`variant_execution_service.py:499-711`), `_collect_composition` (`screens.py:1417`).

## Verdict

**OK to ship (PASS-WITH-NOTES)** for Inc 3's change. No HIGH or MEDIUM finding is introduced by the diff. On the four subjects:

1. **Escape / outside gather: none.** The in-project path yields one boolean; True skips the name (nothing read, copied or written), False falls to `common_patches_dir / Path(name).name` (a bare name inside the library). Every copy still goes through `_gather_copy` with the app's work-area root. Probe: 17 hostile names, 0 outside bytes in the project, on head and base.
2. **Link loops: no `RuntimeError`, no hang.** `normpath` is lexical (no filesystem call); `is_file()` swallows ELOOP (POSIX) and WinError 1921 (Windows, executed at E3). Self-loop and two-link cycle: head returns in ≤ 2 ms; base raises `RuntimeError`.
3. **Removed `mkdir`: no new write path; one fewer.** A deleted folder is now refused at `iterdir` and not re-created (base re-created it and placed the file). A folder replaced by a link (outside, or to another project), a dangling link, a file, or a loop is refused (head at `validate_project_files` or at the placement's reparse walk; base at `mkdir` or the same walk). The mid-sync race is the accepted residual O-3 (E3 S-2).
4. **Logging: no injection.** The only text the diff affects is the `GATHER-SOURCE-MISSING` message, which embeds `{name!r}`: CR/LF, NUL and ESC appear escaped (probe). It goes to `self.logger` only (`app.py:12171`), not to the panel. The dedupe halves repeated lines.

## Findings

| Id | Tag | Severity | Where | Scenario | Recommendation |
|---|---|---|---|---|---|
| E5S-1 | design-gap (pre-existing; = E3 S-3, backlog) | LOW | `project_gather_service.py:660-661` | A name with a component > 255 bytes, or a path > 4096 bytes, makes `is_file()` raise `OSError [Errno 36]` (ENAMETOOLONG is not in pathlib's ignored set) out of a gather documented `Raises: None`. **Executed on POSIX, head and base identical** — not a regression. Reach: dialog names are real file names (`_collect_composition`); a carried manifest name passes the reader's lstat walk first. Windows maps the long-name errors to ENOENT / WinError 123, which `is_file()` swallows (not probed). | Fold into the existing S-3 backlog row (catch `OSError` around the check → treat as not home). No Inc 3 change. |
| E5S-2 | impl (pre-existing, outside the slice) | INFO | `project_gather_service.py:643-646` (`_schedule`) | `_schedule` catches `OSError` around `source.resolve()` but not `RuntimeError`, which Python 3.11/3.12 raise on a loop. Reachable only if the common candidate is replaced by a loop between its `is_file()` (`:664`) and `_schedule` — a concurrent same-user write to the library. Inc 3 does not touch it. | Backlog note with S-3/S-4: catch `(OSError, RuntimeError)` there. |
| E5S-3 | design-gap (pre-existing; = E3 S-5) | LOW | `project_gather_service.py:660` | `..`, absolute, drive-relative and UNC names still reach `is_file()` as an existence oracle (UNC: SMB contact on Windows). `normpath` keeps absolute / drive / UNC joins exactly as the base join did; the answer for `../../outside/secret.json` and an absolute outside path is the same on head and base (executed POSIX; Windows executed at E3 r2 on 16 names). The once-per-name set now makes at most one contact per distinct name. | No change; S-5 backlog row stands (lexical filter before any filesystem call). |
| E5S-4 | impl (pre-existing placement) | INFO | `workspace.py:1189-1200`, `manifest_writer.py:648` | The sync's remaining writes run after the placement guard: a folder deleted or replaced by a link **between** the guard and the write is re-created / followed. Needs a concurrent same-user write inside the work area; the guard compares inside the work area. Removing the sync's `mkdir` neither opens nor widens this. | Already O-3; no action. |
| E5S-5 | impl | INFO | `project_gather_service.py:660` | POSIX `lnk/../x.json` with `lnk` → outside: head judges `P/x.json` (missing → library `x.json` gathered); base followed the link and judged the outside parent's `x.json` (present → skipped). No outside bytes either way (executed). This is I-1's listed third input, and the head now agrees with the writer and reader, which also fold lexically (`manifest_writer.py:782`). | None. Confirms E3 r2 N-1 / I-1. |

No HIGH, no MEDIUM. Nothing owes a fix in Inc 3.

## Probes

LAN Linux host, Python 3.11.18 (`s19ci` env), run with `-I` on a detached worktree of `9f9f6af` with the source diff `git diff 9f9f6af 6355565 -- s19_app/` applied (head), and a copy of the unpatched tree (base). Each scenario in a fresh `mkdtemp`; the worktree, the copy and every temp folder were removed afterwards. Script: session scratchpad `e5sec_probe.py` (not committed). Fixture: work area `work/` with library `work/patches/{x,loop,secret}.json`, project `work/proj` holding a self-symlink `loop.json`, a two-cycle `a2`↔`b2`, and `lnk` → an `outside/` folder holding `secret.json` with a marker; the marker is also in `outside/../x.json`. Each name was passed twice. After each run every regular file under the project was scanned for the marker.

| Name | Head | Base |
|---|---|---|
| `loop.json` (self loop) | gathered `patches/loop.json` (library), no raise | `RuntimeError: Symlink loop` |
| `a2` (two-link cycle) | 1 `GATHER-SOURCE-MISSING` | `RuntimeError: Symlink loop` |
| `loop.json/../x.json` | gathered `patches/x.json` (library) | same |
| `../../outside/secret.json` | skipped, nothing read | same |
| absolute outside path | skipped, nothing read | same |
| `lnk/secret.json` | skipped, nothing read | same |
| `lnk/../x.json` | gathered library `x.json` (E5S-5) | skipped |
| `a\x00b.json` | 1 `GATHER-SOURCE-MISSING`, message escaped | `ValueError: embedded null byte` |
| 300-char component | `OSError [Errno 36]` (E5S-1) | same |
| 4206-char path | `OSError [Errno 36]` (E5S-1) | same |
| `x.json/..`, `..`, `""`, `C:x.json`, `\\host\share\secret.json` | 1 `GATHER-SOURCE-MISSING` each | 2 each (no dedupe) |
| `x.json\nFAKE LOG LINE`, `x\x1b[31mred.json` | 1 finding, `\n` / `\x1b` escaped in the message | 2 findings, same escaping |

Outside marker found in the project: **0 of 17 names, head and base.**

Sync sequence (head: `validate_project_files` → `place_into_workarea(…, workarea_root=work)`; base: `mkdir` first):

| Project folder | Head | Base |
|---|---|---|
| deleted | refused (`FileNotFoundError`), path absent after | re-created and the file placed |
| link → outside | refused at placement (reparse walk); nothing written outside | same |
| link → another project in the work area | refused at placement; nothing written in the other project | same |
| dangling link | refused (`FileNotFoundError`); target not created | refused (`FileExistsError`) |
| a file | refused (`NotADirectoryError`) | refused (`FileExistsError`) |
| self loop | refused (`OSError` ELOOP) | refused (`FileExistsError`) |

**Not probed (Windows-only, reasoned from code and E3 records):** junction loop at a name (E3 executed: `is_file` False on WinError 1921); junction to outside at a name (E3 executed: skipped, writer refuses); 8.3 short names and case folding (`is_file` answers for the same file the long / other-case name names, inside the project only; only the boolean changes, as on base; the exact-text dedupe treats them as distinct names — cost only); reserved device names (`CON`, `NUL.json`: `is_file` False, library lookup False, one finding; the writer refuses device components); long names (Windows maps to ENOENT / WinError 123, swallowed).

## Evidence states

| Item | State |
|---|---|
| No outside gather, 17 names, POSIX | `executed` (head and base) |
| Loops: no `RuntimeError`, no hang, POSIX | `executed` |
| Loops, Windows junction | `executed` at E3 (`E3-security.md`); `not-run` here (operator rule) |
| Removed `mkdir`: 6 folder scenes, POSIX | `executed` (sync sequence reproduced outside the app; the app's `except OSError` → refusal line by code reading `app.py:14939-14953`, `:15061-15075`) |
| Log escaping | `executed` (message text); panel path by code reading (`_append_log_line` → `safe_text`, markup off) |
| E5S-1 ENAMETOOLONG | `executed` POSIX; Windows `not-run` |
| E5S-2, E5S-4 | code reading; `not-run` |
| Mitigations | `n/a — no HIGH or MEDIUM` |

## Evidence checklist

- ✓ Each finding has what, where, why, recommendation: table above.
- ✓ Each finding has a severity and a tag.
- ✓ No secret values: none handled; the probe marker is synthetic.
- ✓ Verdict explicit: OK to ship (PASS-WITH-NOTES); no HIGH.
- n/a New tool or integration: none in this increment.
