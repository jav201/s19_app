# check-FA-PRIV — privacy redaction of the Front A delta (steps 1–4)

Orchestrator Opus 5.5 (relevo-29). Redaction by an Opus agent with scripts kept outside the repo that print counts only; scripted mechanical check (MD-11) on the reference Linux host (rtx), 1-min load 0.59–1.64; Opus intent review. No matched text is written here.

## Scope and change
- Delta `origin/main..367258ae`: 506 files. Hits: 46 files, all under `.dev-flow/2026-11-18-a2l-load-performance/` (evidence transcripts, mutant runners/reruns, `probe_d12*.py`, `canon_fold.py`, `E3-integration.md`); the other 460 files (Front B's included) 0 hits.
- Before: PP-02 pattern 558, needles 257 (two needle forms: the Windows home path with either slash). All hits were the account-name alternative of the pattern.
- Replacements: 248 → `<LOCAL_HOME>` (needle placeholder), 301 → `<user>` (pattern-only forms: `pytest-of-…`, escaped home path, POSIX-style drive path), 9 code lines rewritten so the scripts stay runnable: `canon_fold.py` ROOT → `Path(__file__).resolve().parents[2]` (the brief's `parents[3]` was one level too deep); the three `mutant_runner.py` REPO → `Path(__file__).resolve().parents[4]` and PY → `sys.executable`; the two `mutant_rerun.py` prefixes → `str(Path(__file__).resolve().parents[4]) + "/.dev-flow/"` (+ `from pathlib import Path`). Behaviour change accepted: the mutant runners use the running interpreter instead of a pinned one.
- No `MANIFEST.tsv` in the batch, and no digest of a scope file appears in any tracked file: nothing to refresh (unlike the 3afebf90 precedent).
- `diffs/FA-PRIV.diff` (md5 ef7322bf): 46 files, +326/−324, 0 CR; added lines: needle scan 0.

## Agent checks (static, on the PC)
- Substitution-only: 324 original lines changed; 315 verified as pure placeholder substitution (placeholder → token in memory gives back the original line); 11 exceptions = exactly the 9 rewritten + 2 inserted code lines above.
- Probe commit (redacted tree on `origin/main`, temporary index, branch deleted): patterns 0, needles 0, CR-added lines 0. Negative control (unredacted tip tree, same procedure): patterns 558, needles 257 — the scanner can fail.
- `ast.parse` of the 12 edited `.py` files; new path expressions evaluated against the real file locations (ROOT/REPO = repository root; each rerun finds its sibling runner); `canon_fold` dry import: 30 of 30 rows already in the canon, 0 to insert.

## Mechanical check (rtx)
| Step | Result |
|---|---|
| Apply on 367258ae | 46 files, 0 outside the batch folder, 0 CR |
| `test_no_private_tokens.py`, base (RED control) | 1 failed, 1 passed (`test_no_tracked_file_holds_a_private_token`) |
| `test_no_private_tokens.py`, patched | 2 passed |
| `py_compile` of the 12 edited scripts | 12 compiled, 0 failed |
| Six laws, `-n 0`, patched | **116 passed, 2 skipped, 0 failed** |
| Law 070_2 offender lines | 0 |

## Not in this unit
- History: commits before the squash still hold the tokens. FA-PRIV step 6 (local archive ref + squash onto the merge base with `main`, then step 4 again on the squash commit) happens at push time, with the operator's OK for that push (PP-01).
- PP-06 note: the edits to inherited evidence are the sanctioned substitution-only redaction (step 3), content otherwise byte-identical.

## Verdict
MECH-GO. Opus intent: GO.
