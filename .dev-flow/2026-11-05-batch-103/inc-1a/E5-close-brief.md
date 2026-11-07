# Inc 1a E5 close: write `04-validation.md` (DeepSeek v4 Pro)

Worktree `C:\Users\<user>\Github\s19_app-b103-inc1a-code`, folder `.dev-flow/2026-11-05-batch-103/inc-1a/`.

1. **Write `inc-1a/04-validation.md`** with the sections and tone of Inc 4's record. That record is read-only: `C:\Users\<user>\Github\s19_app-b103\.dev-flow\2026-11-05-batch-103\inc-4\04-validation.md`. Take every fact from these sources in this folder:
   - `E5-rulings.md`
   - `E5-code-review.md`
   - `E5-security.md`
   - `evidence-e5/mutant-table.md`: 32 of 34 killed and 10 not realisable (Windows). M-PASTE.10 is now killed (`fix-green-mut10.txt`). M-PASTE.6 is pending on Windows CI.
   - `evidence-e5/fix-green-{a,b,laws}.txt`, the final GREEN: (a) 122 passed, 75 skipped; (b) 54 passed; laws 219 passed, 1 failed (the redaction gate, expected until the pre-push sweep).
   - `evidence-e4/int-green*`

   Give the verdict and its reason. List the open notes: BD-1A-1 (routed to Inc 12), BL-I1A-1, the Windows CI arms (54) and M-PASTE.6, which wait for the push, the redaction gate, and AT-I1a-10/-11 for the operator. Do not invent any number.
2. **Evidence for the trace checker.** The checker links only paths that contain an `evidence/` folder segment.
   - Copy the decisive transcripts into the batch folder `.dev-flow/2026-11-05-batch-103/evidence/inc-1a/`: `fix-green-{a,b,laws,mut10}.txt`, `mutant-table.md` and `int-mutant-tcl.txt`.
   - Cite them from `04-validation.md` as `` `../evidence/inc-1a/<file>` ``.
   - Never write any other backticked path that holds `evidence/` followed by `…`, `...` or a bare folder: the checker treats it as a citation.
3. **SLICE check.** Make sure `inc-1a/01-requirements.md` names every source file changed since `e07fb00` in the slice: `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py` and `.github/workflows/clipboard-windows.yml`. Add any that is missing as one header line.
4. Add one line to `inc-1a/steps.log`. Do not commit. Run no tests and nothing that imports `s19_app`. Never write the operator's name.

Report in at most 100 words: the files you wrote and the verdict.
