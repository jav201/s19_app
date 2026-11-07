# Pre-push redaction sweep for batch-103 (DeepSeek v4 Pro)

Worktree `C:\Users\jjgh8\Github\s19_app-b103`, branch `batch-103`, HEAD after the Inc 1a merge (`6ed9e317`). The redaction law fails: `tests/test_suite_hygiene.py::test_r_tst_070_2`, from Inc 1a, R-PASTE.36 / E3S-05. Make it pass by redacting, never by weakening the law.

1. **Read the law first.** Read `test_r_tst_070_2`, its roots and patterns, and the `_redaction_*` helpers in `tests/` to learn exactly which strings it flags and in which files: local account names, the host login, the LAN IP, and home paths that hold an account name.
2. **Replace only the flagged strings,** and only in tracked text files under `.dev-flow/2026-11-05-batch-103/` plus any other root the law scans. Use neutral placeholders the law accepts:
   - `C:\Users\<user>` for a Windows home path;
   - `/home/<user>` for a Linux home path;
   - `<user>@<runner>` for the ssh login;
   - `<runner-ip>` for the LAN IP.
   Use the same placeholder everywhere. Do not change any other text, and keep every line count the same. Never touch product code or test code. Never touch the corpus.
3. **Work on this PC with git and a text-replace tool only.** Use Python only for plain file I/O; do not import `s19_app`.
4. **Verify on cachyos-rtx.** Send the branch over with a bundle and a `--shared` clone in `/tmp`. Use an isolated HOME named `zq_iso_user`, with the Python path written in full. Run `tests/test_suite_hygiene.py tests/test_id_registry.py`. Both must pass, with **0 leak files**. Save the result to `.dev-flow/2026-11-05-batch-103/evidence/redaction-sweep-transcript.txt`. Delete the `/tmp` folder afterward.
5. **Commit once:** `batch-103: pre-push redaction sweep (R-PASTE.36)`, with a `Co-Authored-By: DeepSeek V4 Pro` line. **Never push.**

**Report** (at most 100 words): the number of files changed, the placeholders used, the law's result, and anything the law flags that you could not redact safely.
