# Inc 1a E5: three DeepSeek roles (code review, security review, mutants)

**Common rules.** Read in full `C:\Users\<user>\Github\s19_app-b103\.dev-flow\2026-11-05-batch-103\design\E5-brief-common.md`, with N = `1a`.
- **Code worktree:** `C:\Users\<user>\Github\s19_app-b103-inc1a-code`, branch `b103-inc1a-code`, HEAD `e7d157f6`. The diff to validate is `git diff e07fb00 HEAD -- s19_app .github tests`, limited to Inc 1a's files (`E1-slice.md`). Changes from batch-101 and Inc 2a/4 arrived through merges and are out of scope.
- **Runner tree:** `/home/<user>/work/b103-int1a`, at the same HEAD. It is read-only: run `cp -a` into `/tmp/b103-e5-1a-<role>/` before using it.
- **Records:** in `inc-1a/`, read `01-requirements.md`, `02-test-cases.md`, every section of `E1/E2/E3-rulings.md`, `E1-slice.md`, `codewire/graph-*.md` and `evidence-e4/int-green2-*.txt`.
- **Runner settings:** <runner> only. Use the Python at `/home/<user>/miniconda3/envs/s19ci/bin/python` (absolute path). Set HOME, XDG and LOCALAPPDATA to `…/<user>`. Use stdin `/dev/null`. Run every clipboard test inside `xvfb-run -a`, never against the host display or clipboard. Kill processes by PID only. Delete your `/tmp` folder at the end.
- **On this PC:** run only git and ssh. Run no Python and do not commit. Never write the operator's name.
- **Every finding** carries a severity, `file:line`, the row or case it concerns, a fix, and a tag: `impl` or `design-gap`.

## Role CR: code review → `inc-1a/E5-code-review.md`
Check the code against each row and graph node of Inc 1a: contracts, examples, and the order of the read cascade. Check simplicity and reuse: no dead code, no second copy of a helper. Confirm the Tk layer is gone. Check the workflow `clipboard-windows.yml` against its pinned text. Check that the tests encode intent. Open with a verdict (PASS / PASS-WITH-NOTES / FAIL), then the findings table.

## Role SEC: security review → `inc-1a/E5-security.md`
Cover:
- The paste control filter `_strip_paste_controls` / `_UNSAFE_PASTE`: control characters, ESC, C1, bidi, NUL, very large inputs, the multiline rules.
- The PowerShell path `_system_powershell` / `_system_directory`: no PATH lookup, no injection, the timeout.
- The right-click paths.
- OSC 52.
- The CI workflow's permissions and secrets.
- What the redaction law catches.

Probe on the runner under Xvfb. Open with the verdict, then the findings.

## Role MUT: mutants → `inc-1a/evidence-e5/mutant-table.md` + `mutants/`
For each row of `inc-1a/01-requirements.md`, take its **Negative control** cell, plus any second control the rulings name. Apply the smallest edit to the product file it names, on a copy. Run the row's tests (find them in the Tests column). The mutant is **killed** if any test fails and **survived** if all pass. Run timing rows serially. Rows whose tests are Windows-only are `not realisable (Windows CI pending)`.

For each mutant, save the diff and the pytest tail to `out/M-<row>.txt`, then copy them back to `inc-1a/evidence-e5/mutants/`. The table has one row per mutant: id, row, control, edit, tests, result, failing ids.
