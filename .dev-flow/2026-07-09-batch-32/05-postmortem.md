# 05 — Post-mortem · batch-32 · CRC multi-region single-CRC groups

## What worked
- **Parallel-lane requirements drafting.** The architect draft was produced in a worktree agent while batch-31 was still in flight — Phase 1 opened with a fully evidence-cited draft, and the Phase-1 QA fold + Phase-2 triple review converged in one iteration each.
- **Phase-2 caught two would-be Phase-3 bugs pre-code:** the phantom `to_json_dict` symbol (a test would have been authored against a nonexistent surface — C-15 class) and the S-7/AT-044a contradiction (unscoped overlap warnings would have broken the compat pin via the self-overlapping dummy config). Both were one-line spec folds; both would have been expensive at Phase 3.
- **The C-18 reconciliation earned its keep again** (2nd batch since encoding): five ATs were realized "in parts" across Inc-1..4 and only the Phase-4 single-node audit surfaced them → closed in the test-only Inc-5. Same failure shape as its origin (batch-29 AT-043-c17).
- **Golden double-proof (m-4/batch-24 control) executed to the letter:** the increment reviewer independently re-derived `0x156424B4` from a detached worktree at the pre-change origin/main — three-way agreement (zlib oracle ≡ pre-change engine ≡ HEAD).
- **Normalizer-as-single-seam design** (`normalized_targets`) held: check, inject, diagnostics, and the screens re-inject all consume one ordering/widening decision point; the reviewer found the `screens.py:1912` re-inject consumer independently PROVES width-on-result was mandatory, not stylistic.

## What didn't
- **Increment-1 committed before reading ruff output** (the `|| echo` swallowed the exit code) → a style follow-up commit. Mechanical hygiene: run the linter as a gate, not a fire-and-forget.
- **Two test-fixture arithmetic slips** (gap offset 0x05 vs 0x15; a range covering its own gap) cost two red-green cycles — both caught immediately by the tests themselves.
- **Tooling friction:** heredoc escaping twice corrupted test payloads (a shell-quoting break; `\x00` escapes collapsing to real null bytes). Mitigation adopted mid-batch: write test blocks via the file-writer tool + `cat`-append, byte-level repair where needed.
- **Numbering divergence** (0-based parser errors vs 1-based diagnostics) shipped in Inc-1 and was caught only by the Inc-2/3 review (F5) — a spec-level "operator-facing indices are 1-based" convention would have prevented it.

## Scope drift
None. The four Q-defaults stood un-overridden; out-of-scope list (§7) intact; 0 engine-frozen diffs.

## Metrics
- Iterations per phase: P0 1 · P1 1 · P2 1 · P3 5 increments (4 planned + Inc-5 C-18 reconciliation) · P4 1.
- Findings: Phase-1 QA 7 (all folded) · Phase-2 13 (0 blockers, all folded) · Inc-1 review 1 HIGH + 3 (fixed) · Inc-2/3 review 0 HIGH + 6 (fixed/foldered). Nothing left open.
- Tests: CRC-file base 49 → 110 (+61, −0, 2 rewrite-in-place); suite 1191 → gate-run total.
- RED evidence: 3 trigger-absent stash captures + 1 golden double-proof + per-AT counterfactual directions.

## Root causes (multi-iteration items)
Only Phase 3 exceeded one pass, by design (increments) plus Inc-5 (C-18). The C-18 gap root cause matches its origin: no increment *owned* an AT's whole-chain realization, so clauses landed where convenient. The control worked as designed; no new control proposed for this.

## Proposed for next batches
- **P-1 (cheap, next CRC touch):** align operator-facing index bases repo-wide (1-based) as a stated convention in PROJECT_RULES.
- **P-2:** repo-wide ruff debt (11 pre-existing errors in untouched files) — one hygiene PR.
- **P-3 (operator decision on file):** Q1 pad-fill alternative (`0xFF`) as an opt-in group field if a real build tool needs it — schema is a two-way door.
- **B-02 / B-33 lanes** from the baseline backlog proceed as dispatched.

## Control-encode proposals
NONE self-encoded (guardrail honored). Candidate worth operator consideration: **C-CAND-D — "lint gate per increment"**: an increment commit is preceded by a linter run whose exit code gates the commit (would have prevented the Inc-1 style follow-up). Propose-only.
