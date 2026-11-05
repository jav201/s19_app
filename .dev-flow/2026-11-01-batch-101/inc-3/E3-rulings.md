# Inc 3 — E3 round 1 rulings and addenda

Batch 2026-11-01-batch-101, increment 3. Reviews: `E3-architect.md` (FAIL: F1 HIGH, F2 MAJOR, F3–F11 MINOR) and `E3-security.md` (FAIL, `BLOCK-UNTIL: S-1`; S-1 HIGH = F1; S-2, S-3, S-5 MINOR; S-4 MAJOR, pre-existing, non-blocking), both at `99696fa`. Both reviews uphold the core change: dropping `resolve()` opens no containment escape, and removing the sync's `mkdir` is correct. The orchestrator ruled on every finding (2026-11-02, re-issued 2026-11-05). This corrective pass applies the rulings to the records with targeted edits; no code and no tests change. A re-review checks F1/S-1 and F2.

Records edited: `01-requirements.md`, `02-test-cases.md`, `E1-rulings.md`, `E1-slice.md`, `E1-profile.md`, `codewire/graph-inc3.md`. Each edit carries its finding id in brackets. New evidence: `evidence/inc-3/sync-end-lines-script.py` and `sync-end-lines-base.txt` (F8; base tree, Windows, 2026-11-02).

## Rulings and what changed

| Finding | Ruling | What changed |
|---|---|---|
| **F1 / S-1** (HIGH) | Restate R-PROJ-GATHER.13 at the right level. (a) Gather level: a link loop at a composition name does not raise, and the common library file is gathered by bare name. (b) Save level: the save ends with canon R-PROJ-ROLLBACK.9's refusal, with 0 unexpected-error lines and no `patches/x.json` after the rollback. Admit the painted-line change; correct the profile; state the out-of-slice functions. Add F6's POSIX arm. | **R-PROJ-GATHER.13** now reads "… then the system shall look that name up in the common patches library by its last part". Threshold: gather level, 2/2 (Windows junction, POSIX self-symlink), `outcome.gathered == {"patches": ["patches/x.json"]}`, no raise. Two canon rows are added as verified, text unchanged. **R-PROJ-ROLLBACK.9**: exactly once `Project NOT saved: could not save — project.json was not written. check the folder.` (the text as `app.py:11995-11996` paints it, equal to the canon), 0 lines holding `an unexpected error stopped the save`, 0 lines `Project saved + manifest verified`. **R-PROJ-ROLLBACK.2**: no `patches/x.json` and no `patches/` after the rollback. Cases: R-PROJ-GATHER.13/1 (Windows, gather level), /2 (POSIX), R-PROJ-ROLLBACK.9/1, R-PROJ-ROLLBACK.2/1. The save-level node is renamed `test_r_proj_rollback_9_2_a_link_loop_at_a_composition_name_ends_in_the_rollback_refusal`. The painted-line change (R-PROJ-ROLLBACK.18's unexpected-error line at base → R-PROJ-ROLLBACK.9's line) is admitted in the `01-requirements.md` header and in `E1-rulings.md` §1. `E1-profile.md` §1.3 is corrected ("the save goes on" was written without running the writer). Out of the slice, must not change: `_reject_unsafe_entry`, `_EntryWalk`, `_entry_text` (`E1-rulings.md` §1, `E1-slice.md` §1, graph header). Mutants M-10 (a writer that accepts the link; E5 copy only) and M-11 (gather `written` not handed to the rollback) added. |
| **F2** (MAJOR) | Specify the R-TST-111/112 verifier: arms record through `report_margin`; a class-level observer (wrappers on install, `push_screen`, `load_from_path`, `set_status`) stamps on its own, apart from `_watch_panel_paint`; equality within 0.001 s; `serial_timing`; M-6/M-7 must turn it RED. | Graph: new node `_StampObserver` (class-level `monkeypatch.setattr(S19TuiApp, …)` on the 4 methods, installed before the arm builds its app; shares no state with the arm) and new node `test_r_tst_111_112_arm_values_equal_the_product_stamps[all-bad|cap|scene]`, with examples for GREEN, M-6 and M-7. New interfaces I-6 (margin recorder: the module attribute `report_margin` replaced by a recorder that delegates to the real one) and I-7 (the observer's fields). R-TST-111/112 thresholds name the verifier; cases R-TST-111/1–/3 and R-TST-112/1 give the mechanism; M-6/M-7 rows say the verifier turns RED. Addendum A-1 below (`math.isclose`, census classification). |
| **F3** (MINOR) | `query` with a length check, not `query_one`; assert stamps non-empty; state the `batch_update` caveat in the definition. | Definition "Panel paint stamp" reworded: once per layout pass, the `batch_update` caveat, diagnosed on `textual==8.2.8`. `_watch_panel_paint` uses `len(screen.query("#result_summary")) > 0`. The arms assert `stamps` is non-empty with `the Load-result panel was never laid out with a summary`; the reason is that `Signal.publish` swallows callback errors. Example R-TST-111/1c added. |
| **F4** (MINOR) | Record the problem-row count at the stamp; assert it equals the arm's final rows. | `_watch_panel_paint` returns `list[tuple[float, int]]` (I-4): stamp and `.result-problem` count. Each panel arm asserts `stamps[0][1] == rows`. R-TST-111 threshold and cases carry it. |
| **F5** (MINOR) | Fold `..` in the name before the check, as the writer's walk does (preferred over admitting it in I-1). | Design: `Path(os.path.normpath(resolved_project / name)).is_file()` (`E1-slice.md` §1, graph node). `normpath` keeps absolute, drive and UNC names as the base join did. New E1-D8 records the decision and the rejected alternative. I-1 lists the three inputs whose outcome changes. New case R-PROJ-GATHER.12/3 (`missing/../x.json` is already home on both platforms) and mutant M-9 (fold removed; RED on POSIX only, expected to survive on Windows). |
| **F6** (MINOR) | POSIX self-symlink arm in the gather-level case. | R-PROJ-GATHER.13/2 and node `test_r_proj_gather_13_a_posix_self_symlink_at_a_composition_name_is_not_raised`. It is the deterministic M-1 catch on the LAN host. Definition "Link loop" covers both platforms. |
| **F7 / S-2** (MINOR) | Accepted residual: a folder deleted mid-sync (or mid-save) is re-created inside the work area by the placement. | `E1-rulings.md` §5 O-3, with `workspace.py:1183` (`:1200` on origin/main) and `manifest_writer.py:648`; R-PROJ-CONTAIN.1 holds. No row change. |
| **F8** (MINOR) | As proposed. | Measured on base (`sync-end-lines-base.txt`): the MAC load ends `Loaded other.mac` in both scenes. Written into R-PROJ-002.12/4 and /6, with the base lines for the deleted scene (`Project saved + manifest verified`, then `Loaded other.mac`, folder re-created). The same run confirms base for S19 and HEX (deleted: folder re-created, `Added variant 'other' …`; file in place: the refusal, as today). The TC-B100-54 docstring update is listed for E4 (`E1-slice.md` §2 row 15, §3). |
| **F9** (MINOR) | "Inc 2 is in main" is an E4 entry check (PR #212 not merged yet). | `E1-slice.md` §0 and §4, graph header: E4 does not start until Inc 2's merge commit is an ancestor of `origin/main`. Checked 2026-11-05: not yet (`origin/b101-inc2` is not an ancestor of `f11b3f4`). Graph G2 rule: each edited function keeps its `report_margin` call count. |
| **F10** (MINOR) | As proposed. | E5 census grep adds `current_project = ` and `current_project_dir = ` (`E1-slice.md` §3). |
| **F11** (MINOR) | As proposed. | Definition "Composition document name": two names are the same only when their texts are equal. E1-D9 records the exact-text key. |
| **S-3** (MINOR) | Backlog row. | Exact text in `E1-rulings.md` §5. |
| **S-4** (MAJOR, pre-existing) | Security backlog row. | Exact text in `E1-rulings.md` §5. |
| **S-5** (MINOR, pre-existing) | Backlog row. | Exact text in `E1-rulings.md` §5. |

Besides the findings: the D-4 backlog row (orchestrator ruling (a)) is also written with its exact text in `E1-rulings.md` §5, so all four rows can be pasted together.

## Drift check against origin/main (orchestrator request of 2026-11-05)

batch-102 (`f11b3f4`, merged 2026-11-04) changed `s19_app/tui/app.py` (+621 lines), `workspace.py`, `screens.py` and 7 other files. The slice still holds:
- The bodies of `_sync_loaded_file_to_project` and `_sync_loaded_a2l_to_project` are byte-identical (a diff of the two ranges shows nothing).
- `project_gather_service.py`, `manifest_writer.py`, `variant_execution_service.py` and the 4 test files the increment edits are unchanged.
- `validate_project_files` still lists with `iterdir()`.
- `LoadResultScreen` still composes `#result_summary`.

Only line numbers moved; the map is `E1-slice.md` §0. Nothing was merged here.

## Addenda for E4 (minor points carried, no further round)

- **A-1 [F2].** The verifier's equality is `math.isclose(recorded, observed, abs_tol=0.001)`, not an ordering assert, so Inc 2's margin guard (R-TST-041) does not read it as a raw upper timing bound. It reaches the arms' bounds through the arms, so Inc 2's census (R-TST-005, transitive same-module calls) reads it as a timing arm. That is why it carries `serial_timing` (R-TST-002/003). It must not add a `report_margin` call (R-TST-049).
- **A-2 [F2].** The verifier runs each scene once per node run; the "3/3" of R-TST-111/112 is three runs of the node at E5. That keeps the serial lane's cost to about 3 scene runs (about 4 s each on the E1 host) per lane run.
- **A-3 [S-1].** The save-level node and the gather-level Windows node remove the junction with `os.rmdir`, never a recursive delete through it (the rule of `b100_projects.create_junction_loop`).
- **A-4 [F1].** R-PROJ-ROLLBACK.9/1's expected line depends on the writer's link refusal in `variant_execution_service.py`, which Inc 4 edits next. If Inc 4 changes that refusal, it re-derives this case.

## Status after the pass

`trace_check.py --base e266395`: `3 US, 12 active requirements (0 withdrawn), 11 gap(s)` — 10 TEST (tests at E4), 1 EVID (`04-validation.md` at E5). With `--base main` it also lists 8 SLICE gaps: the local `main` is now `f11b3f4`, so batch-102's files show as changed until the rebase. `codewire_lint`: `nodes=15 entities=4 edges=0 findings=0 not read=0`.

## Round 2 (2026-11-05)

Re-review (E3-r2.md): PASS-WITH-NOTES — F1 = S-1 and F2 closed; the F5 fold lets no name reach outside the project. E4 addenda:
- N-1: correct E1-D8's stated reason (the writer accepts `lnk/../x.json`; the design stands).
- N-2: add the NUL-character name to I-1's list of inputs whose outcome changes (base raises ValueError; now a missing-file finding and the writer refuses the entry).
- N-3: in each arm, take every paired stamp first, before any logging or query; the install stamp is the last stamp before the paint.
- Cosmetic: remove the blank line splitting the interface table (graph-inc3.md:27).
