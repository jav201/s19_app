# Implementer brief — batch-100 Increment 6 · save-back active variant, manifest carry, the Load-result panel (PH-4, D2, O-1, O-10, P-E)

Read `BRIEF-COMMON.md` first; every rule there applies (the file name says Kimi, but since 2026-10-29 the implementer is a Claude `software-dev` agent; the rules are unchanged). The orchestrator gives you the worktree and the base commit at launch; the base is `main` with Inc 1–5 and hotfix 3b merged. Your packet is `.dev-flow/2026-10-26-batch-100/03-increments/increment-006.md`. If it is missing, copy the seed shape from `increment-005.md` (its §2–§4 structure, evidence table header `| Evidence artifact | Path — under ... | SHA-256 |`).

**Work in two parts.** At the end of Part A, write `HANDOFF.md` with what is done, then continue. At about 200k context, write `HANDOFF.md` and end; the orchestrator resumes you.

**Design authority:** `design/design-proposal-b100.md` §5.6 (read it whole: lines 286–320).

**Contract (`01-requirements.md`):** HLR-168 (LLR-168.1, -168.2, -168.3), HLR-178 (LLR-178.1, -178.2, -178.3), US-158, US-168. ATs written here: AT-B100-06, AT-B100-19, AT-B100-20. AT-B100-04 and AT-B100-05 gain their Inc 6 arms (§5.3 index rows: AT-B100-04 "dismiss the panel first"; AT-B100-05 "panel oracle"). TC-B100-12 gains its Inc 6 arms (panel `enter`, panel `esc` → focus on the window's target; LLR-166.1). TC-B100-55 here keeps the reasons and the counts only; the "first variant by name" mutation arm moves to Inc 7 (ledger entry citing ARCH-PDR-3; grep `TC-B100-55` in the ledger).

**Ledger entries to read:** grep the ledger for `Inc 6` and for LED .50, .53, .59 (focus: no widget type is exempt), .61 to .66 (Inc 5 outcomes; especially .63, the partial save plan: the plan's `gathered` key is excluded from `_save_manifest_keys()` until the gather has plan rows; you freeze B100-I2 `gathered` in the READER here; do not add `gathered` to the Save project plan keys unless the contract for Inc 6 says so — if unsure, STOP and write it in HANDOFF).

**Interfaces** (`docs/architecture.md` §11): freezes B100-I2 (`gathered`) and B100-I7; consumes B100-I13 (`place_into_workarea`) and the Inc 5 helpers (`_write_and_verify_manifest`, `_save_manifest_keys()`).

**SOURCE files (4, ⚠ at cap):**
- `s19_app/tui/app.py`
- `s19_app/tui/services/variant_execution_service.py`
- `s19_app/tui/screens.py`
- `s19_app/tui/styles.tcss`

## Part A — the reader, the save-back, the carry

1. **The reader parses `gathered`** (LLR-168.1, TC-B100-18).
2. **The save-back becomes the active variant**, in the session and in `project.json` (LLR-168.2, TC-B100-19). RED was executed at `1d677ba` (P-3): `active_variant 'firmware'`.
3. **Every in-project writer rewrites the manifest, carrying every key it does not own** (LLR-168.3, TC-B100-20): the variant append and the MAC and A2L syncs place through `place_into_workarea` (with `workarea_root`), then rewrite through `_write_and_verify_manifest`, converting the reader's absolute paths back to project-relative POSIX strings. Mutations: remove the seam call from the variant append; pass the reader's absolute `batch` (`serialize_manifest` refuses, no manifest written — the A-03 probe).
4. AT-B100-06 and AT-B100-20 (black-box, both sizes).

**Checkpoint:** `HANDOFF.md`.

## Part B — the announcement and the Load-result panel (P-E, verdict B)

5. **`compose_load_announcement`** — pure, in `variant_execution_service.py` (LLR-178.1, TC-B100-55: reasons and counts).
6. **The summary line and the final `#status_text`** painted with markup off (LLR-178.2, TC-B100-56; every name from disk renders through `safe_text`, `utils.py`).
7. **The Load-result panel** in `screens.py` with its layout rules in `styles.tcss` (LLR-178.3, TC-B100-67), on the `pe_B` ids. The operator chose variant **B**. Its prototype is `prototypes/load_projects/variants/pe_B.py` + `_pe_common.py`, with captures in `prototypes/load_projects/png/pe_B.*.png` — read them, port the shape into the shipped screen, never import from or edit `prototypes/`, never commit it.
   - the focus starts on the problem list;
   - `#result_ok` is labelled "Close (esc)";
   - `escape` dismisses it from anywhere, `enter` only on the button;
   - `v` runs `select_variant`;
   - after it closes, focus lands on the current window's target (`_FOCUS_TARGETS`, LED .59) — TC-B100-12's panel arms.
   - The "patched" line against `derived_from` arrives at Inc 7; do not build it here.
8. AT-B100-19 (black-box, both sizes), plus the AT-B100-04 and AT-B100-05 Inc 6 arms.
9. **Enabler E4:** `p02` A/B project fixtures with the default and the `_1` save-back names (design proposal §5 enablers).

**Snapshot cells:** this increment adds a new screen. A snapshot cell may change ONLY if the panel appears in an existing snapshot scenario; if any cell changes, STOP and write it in `HANDOFF.md` with the text diff — do not regenerate.

**RED must be behavioural at base** (P-3 transcripts for AT-B100-06/-19/-20; the A-03 carry probe).

**Reverse census (trigger B1) — run all three greps and re-run every file found:**
- `grep -rln "active_variant\|_write_and_verify_manifest\|serialize_manifest\|read_project_manifest\|gathered" tests/ --include=*.py`
- `grep -rln "Loaded project\|_handle_load_project\|select_variant\|LoadResult\|result_ok" tests/ --include=*.py`
- `grep -rln "b97_fixtures" tests/` (LED .60 lesson: the batch-97 files drive whole-app flows and are where Inc 3's regression hid).
Save the list as `evidence/inc-6/reverse-census-grep.txt` and the runs as `census-*.txt`. For each failure, run it on base too (`git worktree add` a detached base checkout under your scratch, PYTHONPATH pointing at it) and record base-vs-tree; remove that base worktree at the end.

**Lessons from Inc 1–5** (`03-increments/review-increment-00*.md`):
- RED is behavioural, never a missing module or symbol.
- Every failure path that runs after a folder or file exists must roll back what it created (Inc 5 F1); every read of a user file before the first write must handle `OSError` without crashing the app (Inc 5 F2).
- Each ordering rule the contract states ("only after X") needs an arm whose mutant moves the call (Inc 5 F4).
- Test scenarios must SET every state they claim to check. Polling, never a single pause.
- Status-line assertions read the full `set_status` message when the line can carry a path (Inc 5 R2-1); the painted check is for what must be visible.
- Every §2 row carries a closed-six `Kind` and a real LLR/HLR `Traces to`.
- Evidence uses full repo paths so `devflow-evidence --check` matches; transcript headers name the command, the tree, the source hashes, `PYTHONPATH` and `NO_COLOR`.
- Docstrings on new public functions follow `PROJECT_RULES.md` (Summary/Args/Returns plus Data Flow, Dependencies, Used by) — match the neighbours.

Finish with the guards (`guards.txt`, `guards-census.txt`) and packet §1–§7 (§4b `pending — orchestrator`). End `HANDOFF.md` with `__KIMI_UNIT_DONE__` and the 5-line summary.
