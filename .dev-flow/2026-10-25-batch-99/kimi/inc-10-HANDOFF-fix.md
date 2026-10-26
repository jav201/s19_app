# HANDOFF-fix — batch-99 Increment 10 · review round 1 (F1–F4 + LOWs)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc10` (branch b99-inc10). Working
tree only — **no commit**, per the brief. The orchestrator commits.

## What the review found and what changed

Independent review returned **Block** (F1/F2 HIGH). All findings fixed:

- **F1 [HIGH]** — `s19_app/tui/a2l.py` `_reverse_table_lookup`: the TAB_INTP
  encode no longer picks the nearest table ENTRY. It inverse-interpolates the
  typed physical between the bracketing entries to a fractional raw, rounds
  to the nearest integer raw, forward-decodes it, and flags the written
  physical only when it differs (50 on 0→0/100→100 → raw 50, no flag).
  Out-of-range still refuses naming the range; TAB_NOINTP stays exact.
- **F1 corpus gap** — `tests/fixtures/synth/generate.py` + manifest gained a
  SPARSE TAB_INTP symbol (`TAB_INTP_SPARSE_SYM`: raw 0→0.0, 25→10.0,
  100→100.0; image bytes extended to 14). `a2l_expect` pins interior exact
  (40.0 → raw 50, no flag), interior fractional (3.9 → raw 10, flag names
  the written 4.0), both endpoints and a refused value. Corpus regenerated;
  `generate.py --check` → `checked 16 files`.
- **F2 [HIGH]** — `tests/test_b99_a2l_encode.py` AT-B99-09 rewritten
  black-box: loads through the shipped Load file dialog (`l` → `#load_path` →
  `#load_ok`; the same dialog serves .s19 and .a2l), asserts PAINTED text
  only (wide table rows at 118; at BOTH widths the describe-modal lines and
  the narrow list's selected tag). `_physical_cells_plain` deleted; no
  private services, no stored cells.
- **F3 [MEDIUM]** — exact error text asserted: `[0.0, 62.5]`, `[0.0, 100.0]`,
  `the nearest table values are 10.0 and 15.0`.
- **F4 [MEDIUM]** — census completed: the three engine-freeze guards
  (`test_tc031_*` ×2, `test_tc_b94_18*`) are RED **by requirement** (each
  diffs `s19_app/tui/a2l.py` vs main; the b94 test was read in full — it
  asserts the same freeze, not something else) — see
  `red-engine-freeze-guards.txt`; the census grep now covers `MOD_COMMON`;
  impact reproduced (`example_impact.py` → `example-impact.txt`): **71,513**
  multi-byte case_06 tags now decode big-endian and **1,640** software_a
  RAT_FUNC tags change direction — both match the reviewer's counts;
  `green-full.txt` is now the whole affected set (238 passed, 3 skipped,
  2 xfailed).
- **LOW (a)** — `extract_a2l_tags` applies each MODULE's own
  `MOD_COMMON BYTE_ORDER` (module-scoped walk context; the first-module
  pre-pass deleted). New TC-B99-42 (two-module A2L in tmp).
- **LOW (b)** — `_invert_rat_func` rejects roots where d·P²+e·P+f ≈ 0 (and
  the linear limb checks too); all-spurious → decode failure. New TC-B99-43.
- **LOW backlog (NOT fixed, per brief)** — axis-point RAT_FUNC decodes get no
  limits (axis limits are not parsed); recorded in packet §6.

## Verification status (all in stored transcripts under evidence/inc-10/)

- New module: 7 passed (`green-fix-new-module.txt`). Whole affected set:
  238 passed, 3 skipped, 2 xfailed (`green-full.txt`, 158 s). Census
  companion `test_a2l_alignment_sizing.py` (MOD_COMMON hit): 17 passed
  (`green-alignment-sizing.txt`). Corpus: `checked 16 files`.
- Mutations (7, all KILLED, all reverted): LLR-158.1 re-run, LLR-158.2
  re-run, LLR-158.3 re-run, F1 nearest-entry restore, LOW-a first-module,
  LOW-b denominator check removal, F2 Physical-column clipping. After the
  last revert `a2l.py` = `6d12c964…`, `app.py` = `03eacc66…`
  (`fix-baseline-hashes.txt`, re-verified).
- Packet updated: "Review round 1 fixes" subsection (§4a) with fix table,
  mutation verdicts, fix-round evidence table (SHA-256 per artifact);
  §2/§3/Acceptance rows and §6 backlog note updated; §4b left
  `pending — orchestrator`.
- CRLF preserved in every edited file (CRLF == LF counts); corpus fixtures
  are LF by the generator's `newline="\n"` (unchanged convention).

## Open questions / notes for the orchestrator

- The three engine-freeze guards stay RED until merge — expected: LLR-158.x
  crosses the frozen engine BY REQUIREMENT (same status the increment
  shipped with; now documented in §4a with the transcript).
- `green-full.txt` replaced the increment-round file (F4 item d); its
  SHA256SUMS entry and the §4a table carry the new digest.
- Full suite (~2 h 20) not run — the orchestrator's gate.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/a2l.py (F1 inverse interpolation, LOW-a per-module MOD_COMMON, LOW-b zero-denominator root filter); tests/fixtures/synth/generate.py + regenerated manifest.json/synth_a2l.a2l/synth_a2l.s19 (sparse TAB_INTP corpus); tests/test_b99_a2l_encode.py (black-box AT-B99-09, exact-text F3, sparse arms, TC-B99-42/27); packet §4a + HANDOFF-fix.md. app.py carries no net fix-round change.
Tests added: 2 new nodes (TC-B99-42 per-module byte order, TC-B99-43 zero-denominator root); TC-B99-25 grew 4 sparse-table arms; AT-B99-09 fully rewritten (7 nodes total, was 5).
RED/GREEN: 7 mutations all KILLED (transcripts mut-*.txt); GREEN 7 passed new module, 238 passed/3 skipped/2 xfailed whole affected set (green-full.txt), 17 passed alignment-sizing companion, corpus check 16 files; 3 engine-freeze guards RED by requirement.
Mutations: 7 run — LLR-158.1/158.2/158.3 re-runs, F1 nearest-entry, LOW-a first-module, LOW-b denominator, F2 clipping — all reverted, a2l.py restored to 6d12c964…, app.py to 03eacc66….
Open questions: engine-freeze guards (tc031 ×2, tc_b94_18) stay RED until the orchestrator merges (LLR-158 crosses the frozen engine by requirement); axis-point RAT_FUNC no-limits decode filed as backlog (packet §6, not fixed per brief); full suite is the orchestrator's gate.
