# Inc 1a E4: test-fix pass (DeepSeek v4 Pro, tester role)

Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc1a-code` (branch `b103-inc1a-code`). The integration run found 53 + 3 failures, and its report classed each as a **test fault** (see `pi-1a-int` in `inc-1a/evidence-e4/int-green-*.txt` and below). Fix **only test files**. Never touch `s19_app/` or `.github/`. Your rules are those of `inc-1a/E4-handoff-tests-1a.md`; read it whole.

Faults to fix:
1. About 30 right-click, matrix and walk tests fail. The helper `right_click_app_route` calls `await app._process_messages()`, which re-composes and raises `MountError` or does nothing. Drive the app through the Pilot API instead (`pilot.click`, `pilot.pause`), as the repo's other TUI tests do.
2. Four tests set the selection before `focus()`, and `Input` selects all on focus. Focus first, then set the selection.
3. Two tests do not clear `#patch_paste_text` before pasting. Clear it first.
4. One test builds a `MouseDown` without `widget`. One test's fake `OpenClipboard` lacks `.argtypes`. Two tests come from the isolation pytester. Fix each as its traceback shows.
5. Laws:
   - The matrix test uses `query_one(subscript)`; use a valid selector.
   - In R-TST-002, `timing_bound` and `report_margin` must sit on one line, as `report_margin(timing_bound(...))`.
   - The redaction law (E3S-05) fails because the batch records still hold account paths. That is **expected until the pre-push redaction**. Leave it failing and mark it in the transcript. Do not weaken the law.

Then re-run on cachyos-rtx in the existing tree `~/work/b103-int1a`:
- Update the tree with a bundle of the branch after your local edits. Commit your edits first: `batch-103 Inc 1a E4: test fixes after integration (DeepSeek tester)`, with a `Co-Authored-By: DeepSeek V4 Pro` line.
- Run (a), (b) and (c) of `inc-1a/E4-integration-brief.md`, under `xvfb-run -a` with isolation.
- Save the transcripts as `inc-1a/evidence-e4/int-green2-{a,b,laws}.txt` and commit them.

If a failure turns out to be in the product, stop and report it; do not change product code. Kill processes by PID only. On this PC run only git and ssh.

Report in at most 120 words: counts per run, and anything still failing with its cause.
