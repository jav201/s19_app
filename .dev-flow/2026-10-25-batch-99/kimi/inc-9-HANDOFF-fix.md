# HANDOFF-fix — batch-99 Increment 9 · review round 1 (code-reviewer F1–F4)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc9` (branch `b99-inc9`). Working
tree only — NOTHING committed (orchestrator commits).

## What the reviewer found and what was done

- **F1 [HIGH] — HEX with a binary tail failed to load.** `IntelHexFile._load`
  (`s19_app/hexfile.py`) now opens the file `"rb"`: lines are decoded strictly
  only up to and including the first EOF record; after it, non-empty lines are
  counted by stripping the BYTES, never decoded. A non-UTF-8 line before the
  EOF now records one per-line `format` issue instead of aborting the load.
  S19 side left as-is per the brief (not a small change inside `_load`'s
  post-terminator branch; the locale-codec weakness predates the batch →
  backlog, orchestrator files it). New arm: the reviewer's case (272-byte HEX +
  50 000 newlines + `0xFF` padding) → loads with ONE `HEX-AFTER-EOF` notice.
- **F2 [MEDIUM] — the S6 mismatch was never tested.** New arm
  `test_tc_b99_08_s6_mismatch_wide_image`: >65 535 generated data records +
  wrong S6 count → exactly one `S19-COUNT-MISMATCH`. Mutation (S6 comparison
  deleted) → RED; the matching-count control stays GREEN under the mutation.
- **F3 [MEDIUM] — AT-B99-03's flow arm not fully black-box.** Rewritten:
  project folder (with flow file) prepared on disk only; project loaded via
  the Load project dialog (`p` → `#project_list` pick → `#project_ok`);
  Flow Execution opened by rail key `]`; flow imported via its picker;
  run started with `pilot.click("#fx_run")`; assertions on painted text
  (`#status_context`, `#fx_log`) + filesystem only. No
  `_handle_load_project` / `action_show_screen` / `Button.press()` /
  b97 drive helpers. Stability: 8/8 runs green (`stability-at03.txt`).
- **F4 [LOW]** — (a) status assertion is now `startswith` (UX-C7 "leads
  with"); (b) the parsed-record tally reuses `_is_data_record` (predicate
  de-duplicated, semantics identical); (c) the S5/S6 tally counts parsed data
  records + unparseable `S1`/`S2`/`S3`-prefixed lines, so a damaged data line
  gives its own parse issue and no false `S19-COUNT-MISMATCH` — new arm +
  mutation; (d) the packet's re-pin record now cites LLR-154.1, not HLR-154.

## Files changed (fix round)

- `s19_app/hexfile.py` (SOURCE) — binary read + byte-strip post-EOF count.
- `s19_app/core.py` (SOURCE) — `_is_data_record` tally reuse; unparseable
  data-line tally; `_load` docstring.
- `tests/test_b99_truncation.py` — +3 TC arms (binary tail, S6 mismatch,
  damaged line), AT-B99-03 flow arm rewritten black-box, `startswith`
  assertion, module docstring updated.
- `.dev-flow/2026-10-25-batch-99/03-increments/increment-009.md` — "Review
  round 1 fixes" subsection + F4d citation correction.
- `.dev-flow/2026-10-25-batch-99/evidence/inc-9/` — fix-round transcripts
  (hashes in the packet subsection).

CRLF verified preserved (hexfile.py 245/245, core.py 819/819 `\r\n` after
edits; counts match line totals).

## Evidence (all under `.dev-flow/2026-10-25-batch-99/evidence/inc-9/`)

- RED on unmodified tree: `red-fix-tests.txt` — binary-tail arm raises
  `UnicodeDecodeError`; damaged-line arm sees the false `S19-COUNT-MISMATCH`;
  the S6 arm + rewritten flow arm pass there (coverage / test-quality gaps).
- GREEN: `green-fix-full.txt` 23 passed (was 20; +3 arms);
  `green-fix-loaders.txt` 68 passed + 1 EXPECTED failure —
  `test_engine_unchanged.py::test_tc027` fails loud naming exactly
  `core.py`+`hexfile.py`, the engine crossing named in LLR-154.1/154.2
  (predates this fix round; guard working as designed, not re-pinned);
  `green-fix-final.txt` 24 passed (post-mutation restore confirmation,
  truncation + `test_b97_load_project_dialog`).
- Stability: `stability-at03.txt` — AT-B99-03 ×8, 3 passed each.
- Mutations (all KILLED, reverts hash-verified against
  `fix-baseline-hashes.txt`): `mut-F1.txt` (decode the tail),
  `mut-F2.txt` (S6 comparison deleted), `mut-F4c.txt` (damaged-line tally
  deleted). Restores: core.py `5b286130…`, hexfile.py `c26a7540…`.

## Reverse census (fix round)

- `_is_data_record`: no direct test pins (`grep -rl tests/` empty); F4b is a
  semantics-identical refactor; all behaviour pins re-validated by the green
  runs above.
- `S19-COUNT-MISMATCH` / S5 / S6 assertions: only in
  `tests/test_b99_truncation.py` (all green) — no foreign re-pins.
- `IntelHexFile` consumers: dedicated `tests/test_hexfile.py` green in the
  loader census; the only `UnicodeDecodeError` mention in tests is an
  unrelated subprocess-reader pin in `test_tui_patch_history_strip.py`.
- Behaviour change to note: a non-UTF-8 line BEFORE the HEX EOF previously
  aborted the whole load with `UnicodeDecodeError`; it now records one
  per-line `format` issue (per-record error collection per the class
  docstring). No test pinned the old raise.

## Known items for the orchestrator / reviewer

- `test_tc027_engine_modules_unchanged_vs_main` fails in this worktree by
  design (uncommitted engine changes vs `main`); the increment's packet gate
  item 8 already names this engine crossing. Recorded in the packet subsection.
- S19 locale-codec (pre-EOF text read) weakness: left in place per the fix
  brief; goes to the backlog.
- Full suite NOT run (per brief); orchestrator runs it.

__KIMI_UNIT_DONE__
Files changed: s19_app/hexfile.py, s19_app/core.py (SOURCE); tests/test_b99_truncation.py (+3 arms, AT-B99-03 flow arm rewritten, startswith assertion); packet increment-009.md (Review round 1 fixes subsection + LLR-154.1 citation fix); fix-round evidence transcripts under evidence/inc-9/.
Tests added: 3 new TC arms — test_tc_b99_09_binary_tail_after_eof (F1), test_tc_b99_08_s6_mismatch_wide_image (F2), test_tc_b99_08_damaged_data_line_no_false_count_mismatch (F4c).
RED/GREEN: RED fix round 2 failed / 4 passed on the unmodified tree; GREEN 23 passed (truncation), 68+1 expected (loader census), 24 passed (final post-mutation), AT-B99-03 8/8 stable.
Mutations: 3 (F1 decode-the-tail, F2 S6-comparison-deleted, F4c tally-deleted) — all KILLED, all reverts sha256-verified (core.py 5b286130…, hexfile.py c26a7540…).
Open questions: none blocking; test_tc027 engine-unchanged guard fails loud by design (named engine crossing, uncommitted changes); S19 locale-codec weakness routed to backlog per brief.
