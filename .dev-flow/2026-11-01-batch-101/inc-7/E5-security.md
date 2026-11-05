# Inc 7 — E5 security review (implementation)

Batch 2026-11-01-batch-101, increment 7, branch `b101-inc7` at `90ea8ae` (base `main`). Reviewer: security-reviewer, independent of the authors. Stage E5 of `dev-flow-v3-beta`. Read only: this file is the one file written. Probes ran outside the repository, in a temporary folder, with `LOCALAPPDATA` redirected there. They ran one at a time, and none touched the OS clipboard.

**Verdict: PASS-WITH-NOTES.** No HIGH finding is open, so no BLOCK-UNTIL is owed. The injection surface is closed in both files. The atomic write and the orphan removal never overwrite or delete a file the app did not create, with one narrow Windows exception (S5-1, LOW). SR-1 widens the placement guard only by indirection (S5-2, LOW). The A-6 memory and disk blow-up is real, but it is almost entirely **pre-existing**: base already writes the same HTML file and reaches the same peak memory. Inc 7 adds the uncapped Markdown hex blocks, about 7 % of the output (S5-3, MEDIUM, design-gap, backlog). This review clears risk only. It does not authorise a merge or a release.

## Scope reviewed

- `git diff main...HEAD -- s19_app`: `diff_report_service.py`, `before_after_service.py`, `flow_execution_service.py`, `app.py`.
- Guards: `tests/test_b99_staging.py` (LLR-155.3 census and SR-1 allow-list), the R-CMP-004.9.1/.15, R-CMP-005.16/.17 and Mode-B cases in `tests/test_diff_report_service.py` and `tests/test_before_after_report.py`.
- Records: `01-requirements.md`, `E3-security.md`, `E3-rulings.md`, `E4-integration-notes.md` (SR-1, A-6 / `int-05`).

## Rulings on the four questions

### (1) Injection into the Markdown and HTML reports: closed

- **Markdown.** Every file-derived field now goes through `_md_text` (`md_safe`, Mode A, with visible-text normalisation) or `_md_path` (`md_code`, Mode B, inside a code span). That covers labels, variant ids, symbols in Runs, linkage and flow, document refs, the refusal message (`diff_report_service.py:1307`, limit 500), and the filter name. The system's own tokens stay on `_md_cell`. E3 S-1 is fixed.
- **HTML.** `_strip_ctl` is now `markdown_safety._normalise` (`:239`). Every HTML sink passes `_esc(_strip_ctl(x))`, or goes through `_md_unescape` and then `_esc` for lines rebuilt from Markdown. E3 S-2 is fixed: the two files agree.
- **No double escaping.** The flow-A2B producer no longer pre-escapes (`flow_execution_service.py` A2B arm). The label goes raw to the one escaper.
- **Probe P1** planted one payload in all 14 sink kinds of a full before/after report in both files. The payload held `<script>`, backticks, `|`, `[l](javascript:…)`, `![i](http://…)`, `www.h.com`, U+202E, U+2066, U+200B, U+0085, U+0001, U+007F, U+2028, tab, CRLF, `a&lt;b`, `x_y` and `*s*`. The sinks were labels, variant id, paths, provenance, A2L and MAC symbols, linkage, flow record, refusal symbol and message, and filter name. Result: a markdown-it reader (HTML and links on) found 0 `html_inline` / `html_block` / `link_open` / `image` tokens. Neither file holds a raw Cc/Cf/Zl/Zp character (the Markdown file has 94 U+FFFD, the HTML file 89). The HTML file holds no raw `<script` or `<img`. `<` became `&lt;` once (0 `&amp;lt;script`). A literal `&lt;` in the input became `&amp;lt;`, which is correct single escaping. `x_y` became `x\_y` once in the Markdown file, never `x\\\_y`.

### (2) Atomic write and orphan removal: safe, with one Windows exception

- `_write_report` (`:314`) creates `<name>.part` with `open(…, "x")` (`:341`) before its `try`. Its cleanup therefore removes only a `.part` file this call created.
- A pre-existing `.part` file stays untouched, and the call raises `FileExistsError` (probe P2.1).
- A symlink at the final name, live or dangling, is **replaced as a directory entry**. The file it points to is not written through (P2.2, P2.5). This is an improvement over base: base `write_text` followed a dangling link, because `exists()` reads False for one, so base wrote the report into the link's target (P2.6).
- A failed `os.replace` leaves neither the target nor the `.part` (P2.4).
- **Orphan removal.** `_remove_orphan_markdown` (`before_after_service.py:183`) and `_drop_orphan_md` (`app.py:7925`) unlink only `md.path`. That path is set only after `md.written` (`app.py:7948`), and it names a file this report has just moved onto a name `_diff_report_filename` found free. The one residual is a same-second writer between the name check and the move. That window was the same on base, where `write_text` overwrote in it, and E4 recorded it as N-1.
- The exception is S5-1 below.

### (3) SR-1: no widening to other writers; one indirection gap

The allow-list gains exactly three names: `_write_report` (`test_b99_staging.py:2173`), `_remove_orphan_markdown` (`:2176`) and `_drop_orphan_md` (`:2138`). Each has one call path today. `_write_report` is called only from the two generators (`:1885`, `:2773`), and the orphan removals receive only `md.path`. Those generators were already allowed to write the same names with `write_text`. The census passes at head (P4). The indirection gap is S5-2.

### (4) A-6 as a denial of service: real, mostly pre-existing, bounded only by the input

See S5-3. Probe P3 ran head and base side by side.

## Findings

| Id | Tag | Severity | Where | Finding and scenario | Smallest mitigation |
|---|---|---|---|---|---|
| S5-1 | impl | LOW | `diff_report_service.py:341` | **A dangling symlink named `<name>.part` is followed on Windows.** `open(part, "x")` maps to `CreateFile(CREATE_NEW)`, which follows a reparse point. POSIX `O_EXCL` refuses a symlink; Windows does not. Probe P2.3: a planted dangling link `r3.md.part` → `elsewhere.txt`. `_write_report` **created `elsewhere.txt`** holding the report, and `os.replace` left `r3.md` as a symlink pointing outside the folder. Preconditions: write access to `reports/`, the right to create symlinks (Developer Mode or administrator), and a guess of the second-resolution timestamped name. The effect is creating a new file at a chosen path. It cannot overwrite: `CREATE_NEW` fails on an existing target. | Use an unpredictable staging name in the same folder, `tempfile.mkstemp(dir=target.parent, prefix=target.name + ".", suffix=".part")`. N-1 still holds, because a stale `.part` is never touched. Alternatively, refuse when `part.is_symlink()` before the open. Add one case that skips when symlinks are unavailable. Backlog, or this increment if the cap allows. |
| S5-2 | design-gap | LOW | `tests/test_b99_staging.py:2173` | **The census no longer sees overwrites made through the helper.** The guard looks at primitive calls only (`unlink`, `os.replace`, `write_text`, and so on). Allow-listing `_write_report` means a future function anywhere in the module that calls `_write_report(existing_name, …)` overwrites a final name without being flagged. A direct `write_text` in the same new function would have been flagged on base. `_drop_orphan_md` is matched by bare name, so any function of that name in `app.py` passes. That is the file's existing pattern (INFO). | Add one census limb: the callers of `_write_report` (and of `_remove_orphan_markdown`) must be within a pinned set (`generate_diff_report`, `generate_diff_report_html`, and `compose_before_after_report` respectively). Plant a stray caller as the failing control. |
| S5-3 | design-gap | MEDIUM | `_window_rows` (`:1373`), G-9; both generators | **Memory, disk and CPU exhaustion from an ordinary or crafted image pair.** Nothing bounds the input, and every window row is built in a list, joined into one string (about 4–5 times the file in peak memory), then written. Ordinary input: a fully changed 4 MiB pair gives 5.2 GB peak memory, a 1.13 GiB HTML file and about 32 s (`int-05`). A 16 MiB full-flash pair extrapolates to about 20 GB peak and 4.5 GB of HTML; on a typical laptop this ends in page-file thrash and commit-limit failures that also hit other processes, before Python raises `MemoryError`. Crafted input: isolated changed bytes 256 apart give **3,154 B of Markdown and 2,233 B of HTML per changed byte**, about 150 times the per-byte cost of a full change. Run time grows faster than the run count (4,096 runs 2.5 s; 8,192 runs 6.9 s; 16,384 runs 21 s; about n^1.6). A ~4.5 MB S19 pair holding 262,144 such bytes would write about 1.4 GB of reports, and extrapolation from the measured points puts its run time well above an hour. **Attribution:** at base the HTML size, the peak memory and the super-linear time are the same (P3: base 71.8 MiB of HTML and 386 MiB peak at 256 KiB; head 71.8 MiB and 385 MiB). Inc 7 adds only the uncapped Markdown blocks (0.2 → 5.1 MiB at 256 KiB, about 20 B per changed byte). Effects are local and the user triggers them; the before/after and A↔B paths run in workers. A failure leaves no partial file (R-CMP-005.16, P2.4), except after a hard kill: a GiB-sized `.part` then stays in `reports/`, unlisted and never cleaned. The flow A2B arm runs on the UI thread (OBS-7-5), so there the same input freezes the TUI. | Smallest: a **pre-flight size refusal** in both generators, before any row is built. Estimate the output from the window row count (sum of window spans / 16, plus a per-run cost) and refuse above a fixed limit with a diagnostic naming the estimate. A refusal is not truncation, so G-9 holds. Next: stream rows into the `.part` handle (`_write_report` takes an iterable), which removes the 4–5 times join peak. Last: the OBS-7-4 shared CSS class for the HTML pane, and a backlog row for the super-linear per-run cost. Backlog row with an orchestrator ruling. Not blocking. |
| S5-4 | impl | INFO | `diff_report_service.py:239`, `:1307` | Positive findings. E3 S-1 (refusal message) and S-2 (C1/bidi in HTML) are fixed and verified by probe. S-5 (whole-value scan) is resolved: `_md_text` is now `md_safe` alone, which slices before normalising. Replacing a symlink at the final name now removes the write-through that base had. | none |

E3 S-4 (absolute paths in reports) is unchanged by Inc 7 and stays in the backlog. A grep found no home folder, account or host in the changed goldens.

## Probes

All probes ran in a temporary folder outside the repository, using the `s19env` interpreter with `PYTHONPATH` set to the worktree. The probe scripts are not committed.

| Id | What | Result | State |
|---|---|---|---|
| P1 | Hostile payload in 14 sink kinds; markdown-it token census; Cc/Cf/Zl/Zp scan of both files; double-escape counts | 0 live tokens; 0 raw control or format characters; 0 `&amp;lt;script`; `x\_y` written once | `executed` |
| P2.1 | Stale `<name>.part` present | `FileExistsError`; the `.part` content is unchanged; no target | `executed` |
| P2.2 | Symlink at the target, pointing to an existing outside file | The outside file is intact; the target is now a regular file | `executed` |
| P2.3 | Dangling symlink at `<name>.part` (Windows) | The link target was **created** with the report; the final name became a symlink (S5-1) | `failed` (finding) |
| P2.4 | `os.replace` raises | No target and no `.part` remain | `executed` |
| P2.5 | Dangling symlink at the final name | No write-through; the link is replaced by a regular file | `executed` |
| P2.6 | Base `write_text` onto a dangling link | Wrote through to the link target (base defect, fixed at head) | `executed` |
| P3 | Amplification, head vs base, one process each: fully changed 256 KiB pair; isolated changed bytes ×4,096 / 8,192 / 16,384 | head: Markdown 5.1 MiB, HTML 71.8 MiB, peak 385 MiB at 256 KiB; sparse 3,154 / 2,233 B per byte, 2.5 / 6.9 / 21.1 s. base: Markdown 0.2 MiB, HTML 71.8 MiB, peak 386 MiB; sparse identical, 2.7 / 7.2 / 22.3 s | `executed` |
| P4 | `pytest -p no:cacheprovider`: LLR-155.3 census, R-CMP-004.9.x / .15 / 005.16 / .17 / Mode-B cases, `test_before_after_report.py` | 21 passed, 77 deselected | `executed` |

## Evidence states

| Item | State |
|---|---|
| E3 S-1, S-2, S-5 fixes | `approved` (applied at head and verified by P1 and code read) |
| E3 S-3 (b) atomic write and orphan removal | `approved` (P2.1, P2.2, P2.4, P2.5; R-CMP-005.16/.17 cases in P4) |
| S5-1, S5-2, S5-3 mitigations | `planned` (backlog rows; S5-3 needs an orchestrator ruling) |
| S5-3 at 16 MiB and crafted 262,144 runs | `not-run` (extrapolated from P3 and `int-05`; too heavy for a shared host) |

## Evidence checklist

- [x] Each finding has what, where, why and a recommendation: table columns, with file:line.
- [x] Each finding has a severity and a tag: MEDIUM ×1, LOW ×2, INFO ×1; `impl` / `design-gap`.
- [x] No secret, home folder, account name, host or LAN address appears in this file. Probe paths are given only as "a temporary folder".
- [x] The verdict is explicit: PASS-WITH-NOTES. No HIGH is open; no BLOCK-UNTIL is owed. This review is not merge or release authority.
- [x] New tool or integration: n/a. Inc 7 adds no external tool, connector or network path.
