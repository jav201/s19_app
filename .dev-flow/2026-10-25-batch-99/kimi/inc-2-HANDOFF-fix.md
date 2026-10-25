# HANDOFF — batch-99 Increment 2 · review round 1 fixes (F1–F6)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc2` (branch `b99-inc2`). No commit
made. Worktree import proven: `s19_app.__file__` =
`C:\Users\jjgh8\Github\s19_app-b99-inc2\s19_app\__init__.py`.

## What the review asked vs what was done

- **F1 [HIGH]** — AT-B99-02's Memory-Map check was vacuous (`startswith` vs the
  band-glyph rows). Fixed: `not any(re.search(r"\b0x00000000\b", r) for r in rows)`;
  the `app.update_memory_map()` call dropped. S0 re-admit mutation re-run against
  **step 4 alone** (steps 3/5 temporarily commented): control PASS, mutant RED on
  the painted `░ 0x00000000 12 B …` row — `mut-F1-step4.txt`.
- **F2 [MED]** — AT-B99-02 now fully key/click-driven (`pilot.click` focus +
  `pilot.press(*text)`, `pilot.click` on buttons, painted status-line / painted
  SVG waits; `#patch_tab_json` click before the save-back prompt; viewport
  120×54). 8/8 stability — `stability-at02.txt`.
- **F3 [MED]** — all three freeze guards listed in packet §4/§6 (added
  `tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main`);
  none edited; reason recorded (working-tree-vs-`main` diff, passes once on
  `main`, LLR-153.1 names the crossing).
- **F4 [MED]** — AT-040a colour branch rebuilt on a real temporary S19 (valid S3
  block, gap, bad-checksum S3 block); asserts loader-computed ranges/validity
  before the painted-bar oracle.
- **F5 [MED]** — TC-B99-06 defective-source arm now bounds extra written bytes to
  the defective records' addresses (`_defective_record_addresses`). S0 mutation
  RED on **both** checksum-defective copies (two arms) — `mut-F5.txt`.
- **F6 [MED]** — sealed batch-92 record restored (`git checkout a52e2be -- …`,
  sha256 `061ee94c…` == its `.pre-b99-inc2` backup); S0-free capture lives at
  `tests/goldens/batch99/at288-pre-move-report.bin`; `test_report_service.py`
  re-pointed (re-pin #9 recorded). Packet §2 lists every changed file; the
  65-digit `red-tc_b99_07.txt` row corrected; **every** evidence row re-hashed.

## Evidence (all under `.dev-flow/2026-10-25-batch-99/evidence/inc-2/`)

GREEN: `green-fix-b99_s0.txt` (6), `green-fix-census-companions.txt`
(28 corpus+census / 40 hexview+entropy / 15 before-after), `green-fix-at288.txt`
(1), `green-fix-snapshot.txt` (33, colours on), `green-fix-directionb.txt`
(182; the only 2 failures are the freeze guards, RED by design pre-merge),
`stability-at02.txt` (8/8).
RED/mutations: `mut-F1-step4.txt` (control PASS + step-4 RED), `mut-F5.txt`
(both defective files RED), `mut-LLR-153.1.txt` refreshed (6/6 RED; restore
digest `6821f378…` re-proven). `core.py` and `test_b99_s0.py` hash-verified
byte-identical to their pre-mutation state; full file re-run green after the
revert (6 passed).

## Tree state / notes for the orchestrator

- Changed by this fix round: `tests/test_b99_s0.py`, `tests/test_tui_directionb.py`,
  `tests/test_report_service.py`, new `tests/goldens/batch99/`, the packet, and
  the evidence folder. The 3 re-pinned test files, 16 SVGs and 2 batch35 goldens
  carry over from `fc81767` and are all listed in packet §2.
- The sealed-record restore is **staged** (`git checkout <commit> -- path`
  updates the index) — the fix brief explicitly ordered that command; relative
  to batch base `a52e2be` the file is unchanged.
- Lesson: one fix-round batch accidentally ran with `NO_COLOR` set (29 snapshot
  failures, environmental); re-run with colours on gave 33/33. Transcripts kept
  are the colour-on ones.
- §4b stays `pending — orchestrator`. Open decisions unchanged: the three
  freeze-guard classifications (requirement decision) and the checksum-policy
  note for defective sources (packet §6).

__KIMI_UNIT_DONE__
Files changed: tests/test_b99_s0.py, tests/test_tui_directionb.py, tests/test_report_service.py, new tests/goldens/batch99/at288-pre-move-report.bin, increment-002.md, evidence/inc-2 transcripts; sealed batch-92 record restored.
Tests added: none (review fixes rewrite pinned probes in place; node ledger unchanged at 6 = 0 − 0 + 6).
RED/GREEN: green 6 + 28/40/15 + 1 + 33 + 182(+2 by-design guard failures) + 8/8 stability; mutation RED on step-4-only, both defective files, and the full file 6/6.
Mutations: one declared negative control (S0 re-admission in _is_data_record) run on three instruments, all reverted, core.py hash back to 6821f378….
Open questions: freeze-guard classification (3 guards) is the orchestrator's requirement decision; TC-B99-06 checksum-policy note for defective sources stands in packet §6.
