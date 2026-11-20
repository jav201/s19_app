# FA-PRIV — privacy redaction of the alp delta (orchestrator script; DeepSeek v4-pro CHK-ds mechanical check)

Runs last, after every record-writing unit and after the merge with `main`, then again right before any push. No agent edits `~/.claude/skills`. Never print a needle.

## Facts
- **Hits.** R3-F7: 558 account-name hits in 46 files. R4-F11: 46 files / 324 lines.
  - Examples: `canon_fold.py:9` `ROOT = Path(r"<LOCAL_HOME>/…")`; `inc-*/evidence-e4/mutant_runner.py`, `mutant_rerun.py`, `probe_d12*.py` interpreter/ROOT paths; pytest transcripts with Windows home paths.
  - No remote holds `e6aed198` or later yet.
- **Precedent:** the forward fix on main, `3afebf90` (record `evidence/privacy-forward-fix-2026-11-19.md` on main), done with the operator's choice «Corregir hacia adelante».
- **Tools:**
  - scanner `~\clde\s19-relevo14-work\pp02_scan.py` (token column, planted self-check);
  - needles `~\.config\s19-redact.txt` (PP-02/PP-03; never copied into the repo).

## Steps
1. **List the scope:** `git diff --name-only f44e8bc4..<tip>` plus all of `E4R/`.
   - Usage is `python -I -B pp02_scan.py <worktree> <branch> <base-ref>`. It scans `git log -p` over the **whole range**, history included, counting added lines only, and it never prints hits.
   - Record its counts. Locate the hit files with a per-file count script that also prints no text.
2. **Redact by script** (outside the repo, reading the needle file).
   - Replace each token with its placeholder: the needle file's second column, i.e. the PP-03 form (`~`, `<user>`, `<host>`, `<runner-home>`).
   - **Scripts must stay runnable**, so no placeholder in code:
     - `canon_fold.py:9` → `ROOT = Path(__file__).resolve().parents[3]` (check the depth against the file's location);
     - interpreter paths → `sys.executable`;
     - absolute ROOTs in evidence scripts → `Path(__file__)`-relative.
3. **Substitution-only check.** For every changed line, applying the placeholder→token map (in memory, never printed) to the new line must give back the original line. The only exceptions are the code lines listed in step 2, which are reviewed by eye. This is the sanctioned edit of inherited records: content otherwise byte-identical (PP-06 note in `E4R-rulings.md`).
4. **Oracles:**
   - Build a throwaway probe commit holding the tip's tree on the merge base, without moving any branch: `git commit-tree <tip>^{tree} -p <merge-base> -m probe`, then create the local branch `zq-priv-probe` at that sha. Run `pp02_scan.py <wt> zq-priv-probe <merge-base>`: patterns = 0 and needles = 0. Then delete `zq-priv-probe`. The real range scan cannot reach 0 before the squash in step 6, because older commits carry the tokens;
   - on the laptop, `tests/test_no_private_tokens.py`, `tests/test_suite_hygiene.py -k "070"`: no node worse than the base-red set of FA-0 `laws.txt`;
   - `python -I -B canon_fold.py --check` (or a dry run), if it has one: it still runs.
5. **CHK-ds:** a DeepSeek v4-pro session that did not run the redaction re-runs steps 3–4 on a copy and writes `CHECK.md` (counts only).
6. **History.** Commits `7402840c`…`25161a00` and early E4R commits still hold tokens.
   - **At push time, with the operator's OK for that push (PP-01):** create the local ref `archive/a2l-load-performance-pre-squash` at the tip, then squash the branch onto its merge base with `main` into one commit. Run step 4 on that commit.
   - The original commits stay only in the local archive ref, never pushed.
