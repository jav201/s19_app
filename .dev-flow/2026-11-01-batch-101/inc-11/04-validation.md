# Inc 11 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The A2L block-name and IF_DATA rules, the anchored MEMORY_SEGMENT reader, the CURVE index note and the severity-ordered Issues screen meet their rows: every new and re-pinned test passes, 32/32 requirement mutants are killed, and the owed snapshot baselines are re-recorded in the CI recipe. No HIGH or MAJOR is open. Two notes stay open: the OR-3 freeze guards are RED on the branch by design, and the clean-up on LAN Linux host 2 is not done (§Owed). Branch `b101-inc11` at `fa35466` plus this close commit (4 snapshot baselines, the `snap-*` transcripts, this record, the packet `03-increments/increment-011.md`, `steps.log`). Product files: `s19_app/validation/rules.py`, `s19_app/tui/a2l.py`, `s19_app/tui/issues_view.py`, `s19_app/tui/app.py` (4 / 4). Nothing ran on the Windows PC.

## Runs

| Run | Platform | Result | Evidence |
|---|---|---|---|
| RED on base: the tester's new files on `origin/main` (no difference from `b7b77c4` in the touched modules) | LAN Linux host 2 | G1 **102 failed, 50 passed**; G2 **10 failed, 1 passed**; acceptance 3 failed (×2), 4 failed, 1 passed; `test_segment_split_window.py` 56 passed (pins, by design) | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/red-01-tester-base.txt` |
| E4 integration: 3 new files, re-pinned files, guards (`-n 6`) | LAN Linux host 2 | **2 failed, 326 passed** — TC-027 and TC-B94-18's freeze arm (OR-3) | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-07-new-repinned-guards-final.txt` |
| E4 serial lane (`-m serial_timing`) | LAN Linux host 2 | **30 passed**, 1114 deselected | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-06-serial-lane.txt` |
| E4 app / directionb / snapshot (`-n 6`; snapshot plugin then absent, module skipped) | LAN Linux host 2 | **2 failed, 245 passed**, 29 skipped, 1 xfailed — TC-031 ×2 (OR-3) | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-09-app-directionb-snapshot-rerun.txt` |
| E4 the 28 importer files, third run (`-n 6`) | LAN Linux host 2 | **490 passed**, 17 skipped, 2 xfailed (int-08 had one load timeout, `tc_b100_52[case_06]`, passed alone on both trees) | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-15-importers-third.txt` |
| E5 corrective: new + re-pinned + guards (`-n 8 -m "not serial_timing"`) | LAN Linux host 2 | **2 failed, 331 passed** — OR-3 only; +5 nodes over E4 | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-01-new-repinned-guards.txt` |
| E5 corrective serial lane | LAN Linux host 2 | **1 passed**, 333 deselected | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-02-serial-lane.txt` |
| E5 corrective importers + app + directionb + snapshot (`-n 8`) | LAN Linux host 2 | **8 failed, 758 passed**, 17 skipped, 3 xfailed — TC-031 ×2 (OR-3) + 6 tc016s snapshot nodes (4 owed re-record, 2 known on base); `tc_b100_52[case_06]` passed | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-03-importers-app-directionb-snapshot.txt` |
| Snapshot suite, CI recipe, `origin/main` alone | laptop host (LAN Linux) | **2 failed, 27 passed** — the 2 known `patch-comfortable` nodes | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-01-base-origin-main.txt` |
| Snapshot suite, Inc 11 tree, before the re-record | laptop host (LAN Linux) | **6 failed, 23 passed** — `a2l-compact/comfortable-160x40`, `map-comfortable-80x24/120x30` + the 2 known | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-02-inc11-before-rerecord.txt` |
| Re-record, one node per run (`--snapshot-update`) | laptop host (LAN Linux) | 4 × **1 passed**; per-node diff: Region `unknown` → `flash` on the 9 in-memory rows (a2l ×2), `60` → `59` issues (map ×2); no other text, colour or layout change | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-03-rerecord-four-nodes.txt`, `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-04-svgdiff-per-node.txt`, `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-00-summary.txt` |
| Snapshot suite, Inc 11 tree, after the re-record | laptop host (LAN Linux) | **2 failed, 27 passed** — only the 2 known `patch-comfortable` nodes | `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-05-inc11-after-rerecord.txt` |

The E4 notes owed "six `a2l-*` baselines"; only the two 160×40 `a2l-*` nodes show the Region column and change. The other four `a2l-*` nodes pass unchanged.

## Mutant score

**32/32 KILLED** — one mutant per negative control of the 28 active rows (`E5-mutants.md`, `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-*.txt`; restore checked by the sha256 of the four source files). The corrective pass added **9 mutants** for the 21 base-passing cases and the colour assertion: **8 KILLED, 1 SURVIVED as equivalent** (`m-042b-1-enc`: the filtered list is already sorted by rank before the panel sees it, R-TUI-042b.5) — `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-*.txt`. Totals: 41 mutants, 40 KILLED, 1 equivalent, 0 real survivors.

## Reviews

- **E3 design:** round 1 `architect` **FAIL** (1 HIGH, 3 MAJOR, 8 MINOR) and `security-reviewer` **PASS-WITH-NOTES** (S-1, S-2 MEDIUM) → round 2 **PASS-WITH-NOTES** (A-1 … A-4, S-1, S-2 closed; N-1 … N-4 folded at E4/E5) — `E3-architect.md`, `E3-security.md`, `E3-rulings.md`.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES** — no BLOCKER or MAJOR; F1, F2 (MINOR) and F3 … F5 (NIT) closed by the corrective pass (F5 partial, reason given) — `E5-code-review.md`, `E5-corrective-notes.md`.
- **E5 security:** `security-reviewer` **PASS-WITH-NOTES** — no HIGH; E5-1 MEDIUM (Split / Join fill size cap) routed to the backlog; E5-4 hostile-name arm strengthened (C-8) — `E5-security.md`.
- **Coverage audit** (independent `qa-reviewer`): 77 cases, 20 changed substantively (26.0 %); after the corrective pass **78 cases, 76 covered, 2 partial, 0 gap** (partial: R-A2L-036.7/1, R-SEG-SRC.6/2) — `E5-coverage-audit.md`, `E5-corrective-notes.md`.

## Freeze guards (OR-3)

TC-027 (`test_engine_unchanged.py`), TC-B94-18's freeze arm and TC-031 ×2 (`test_tui_directionb.py`) compare `rules.py` / `a2l.py` with `main` and **fail on the branch by design**. They must pass on the merged tree before the push.

## Owed

- **Clean-up on LAN Linux host 2** (the host stopped answering ssh after the corrective pass): remove the worktree `<HOME>/work/s19_c11` (`git -C <HOME>/work/s19_app worktree remove --force <HOME>/work/s19_c11 && git -C <HOME>/work/s19_app worktree prune`) and `rm -rf /tmp/c11e5_* /tmp/pytest-s19c11`.
- The OR-3 guards on the merged tree (above); the batch-end review shows the snapshot before/after (`.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-00-summary.txt`).
- Partial cases R-A2L-036.7/1 and R-SEG-SRC.6/2; backlog rows in `.dev-flow/BACKLOG-CODE.md` (E5-1 fill cap, E5-2, E5-5/O-6, E5-6, O-4, O-5).
- Kept on the laptop host: the venv `<HOME>/work/venv-snap311` (its editable install pointed at the removed worktree; re-run `pip install -e ".[dev]"` from a new worktree to reuse it). The snapshot worktree and `/tmp` files were removed.
- `trace_check.py` and the flow validator were run at close; their summary lines are in the increment packet.
