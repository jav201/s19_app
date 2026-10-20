# Increment 001 — HLR-148 · `Chip families flows/session, real-directory guard, folder labels`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-001.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `001` |
| Lane (if the batch forked) | `none — one lane (design-proposal §8)` |
| Requirement(s) | `HLR-148 / LLR-148.1, LLR-148.2, LLR-148.3, LLR-148.4 (id_suffix mechanism only), LLR-148.8, LLR-148.10 (4 shipped instances + LED-.6 no-project arm)` |
| Acceptance | AT: none owned at Inc-1 (AT-B97-12/13/14/23 land at Inc-6) · white-box `TC-B97-27, 28, 29, 30 (Inc-1 arm), 57, 65` · unit (layer 0) `TC-B97-27/28/29/57` arms over `resolve_chip_target`, `no_project_reason`, `chip_family_root`, `is_openable_chip_dir` |
| Agent | `software-dev` (spawned sub-agent) |
| Date | `2026-10-20` |
| Design refs | `PDR-2026-10-19-batch-97#D9`, I-1 (amended PC-20), D18; Code-Wire H-C1/H-C2/H-C3 |

---

## 1 · What changed

Every open-folder chip now names the folder it opens, and it opens a folder only after checking that the target is a real directory inside its family root. Two new families, `flows` and `session`, are ready for the flow screens to mount (Inc-5/6).

- `folder_open_service`: `CHIP_FAMILY_FLOWS` (= the imported `FLOWS_SUBDIR`, no `"flows"` literal) and `CHIP_FAMILY_SESSION`; `CHIP_FAMILIES` = 6. `resolve_chip_target` maps `flows` → `project_dir / FLOWS_SUBDIR` and `session` → `project_dir`, each `None` without a project. `create_chip_home` creates `flows` only when its resolved path lies inside the resolved project, and raises for `session` (never created). NEW pure functions: `chip_label(family, target)` (`📂 Open <leaf>/`, or `📂 Open session`), `no_project_reason(family)` (`REPORTS_NO_PROJECT_REASON` is now `no_project_reason("reports")`), `chip_family_root(project_dir, base_dir)` (the one trust-anchor producer), and `is_openable_chip_dir(target, root)` (is_dir → no reparse point via `_path_traverses_reparse_point(target, stop_at=root.parent)` → `resolve()` containment; `OSError`/`ValueError` → False). The dead `_CREATABLE_FAMILIES` is removed (H-C2).
- Gate fold: a missing session project dir gets the tooltip `project folder is missing` (F2). The guard boundary is pinned by two nodes (F1).
- `OpenFolderChip(family, *, id_suffix=None)`: the id is `open_folder_<family>[_<suffix>]`. The label is recomputed in every `refresh_target`, so the no-project Checks chip reads `📂 Open patches/` and switches to `📂 Open checks/` once a project loads (LED-.6). A `None` target disables the chip and puts that family's own reason on the status line. Press path: create-on-press runs for any missing target except `session`. The guard then refuses with `Refused to open <target>: not a real folder inside <root>/` and 0 seam calls; otherwise the seam is called once and keeps its `Opened folder: <path>` status.
- Shipped surface reached by the user: the Patch Editor, Checks, CRC Designer and Reports chips (new labels, guard). The flows and session chips have no mount point until Inc-5/6.

---

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/folder_open_service.py` | source | HLR-148, LLR-148.1, LLR-148.2, LLR-148.3, LLR-148.8, LLR-148.10 | families, targets, create limbs, `chip_label`, `no_project_reason`, `chip_family_root`, `is_openable_chip_dir`; `_CREATABLE_FAMILIES` removed |
| `s19_app/tui/open_folder_chip.py` | source | HLR-148, LLR-148.3, LLR-148.4, LLR-148.8, LLR-148.10 | `id_suffix`; label in `refresh_target`; per-family reason; session never creates; guard before the seam |
| `tests/test_b97_chips_help.py` | test | HLR-148, LLR-148.1, LLR-148.2, LLR-148.3, LLR-148.4, LLR-148.8, LLR-148.10 | NEW — 17 functions / 24 nodes (TC-B97-27, 28, 29, 30, 57, 65; 2 boundary nodes from gate F1) |
| `tests/b97_fixtures.py` | fixture | HLR-144, HLR-145, HLR-146, HLR-147, HLR-148 | NEW — A.2 frozen literals with their len guards; `make_project`, `load_project` (app's own load), `make_junction` |
| `tests/b97_probes.py` | fixture | HLR-148 | NEW — `settle`, `mount_chip`, `last_status`, `chip_label`, `CHIP_TEST_SIZE` |
| `tests/test_id_registry.py` | test | LLR-148.1 (D18 registry re-measure) | `EXPECTED_SCANNED_TEST_FILES` 189 → 192, measured |
| `docs/architecture.md` | doc | | §11 "Batch-97 interface amendments" — design-proposal §4 table copied verbatim (10 lines) |

| Count | Value |
|---|---|
| **SOURCE files** | **`2` / 4** |
| Test files | `4` (uncapped: 1 test module, 2 helpers, 1 registry edit) |
| Doc files | `1` (outside the count) |

---

## 3 · How to test

```bash
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1; unset NO_COLOR
python -m pytest tests/test_b97_chips_help.py tests/test_open_folder_chips.py tests/test_id_registry.py -rA -p no:cacheprovider --color=no
python .dev-flow/2026-10-19-batch-97/evidence/inc-1/mutate.py      # mutation battery, restores by hash
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `test_tc_b97_27_flows_family_targets_project_flows_dir`, `test_tc_b97_28_session_family_targets_project_dir`, `test_tc_b97_29_no_project_reason_names_each_family_folder`, `test_tc_b97_57_family_root_is_project_dir_else_tool_root`, `test_tc_b97_57_guard_unit_arms`, `test_tc_b97_27_flows_folder_name_imported_never_redeclared` | 6 of the 50 passed in `evidence/inc-1/green.txt` |
| **A · white-box** | `core` · `full` | the other 18 `test_tc_b97_*` nodes (integration, pilot app, `SeamSpy`; incl. the two gate-F1 boundary nodes `test_tc_b97_57_reparse_point_above_the_root_is_not_the_guards` / `…_at_the_root_is_refused`) + 13 nodes of `tests/test_open_folder_chips.py` (P-59, stay green) | 24 b97 + 13 shipped chip nodes + 13 registry nodes = **50 passed** (`evidence/inc-1/green.txt`, after the gate fold) |
| **B · black-box** | `core` · `full` | none at Inc-1 — AT-B97-12/13/14/23 are owned by Inc-6 (design-proposal §5) | n/a — not this increment |

The P-59 premise counts 11 test *functions* in `test_open_folder_chips.py`. They collect as 13 nodes because one is parametrized ×3; all 13 pass.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source: the new tests run against the unchanged Inc-0 source (HEAD `42655eb`, `git diff -- s19_app` empty at the time) |
| Instrument | pytest, one complete run |
| Where it ran | the main worktree `C:\Users\jjgh8\Github\s19_app`, run by the `software-dev` sub-agent (the orchestrator may re-run it per §Phase 3) |
| Transcript | `evidence/inc-1/red.txt` — **19 failed, 3 passed** |
| Restore proven by | n/a for the RED run (no source edit); restore hashes for the mutation battery are printed per arm in `mutations.txt` |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider` |
| Arms resolved at baseline | 22 nodes (15 functions; one function parametrized 4×2 = 8) — expected 22, collected 22 |
| Verdict granularity | per node (`-rfE` short summary in `red.txt`) |
| Arms that stayed GREEN | 3, all **preservation arms** expected green on main: `chip_press_guarded[real-checks]`, `chip_press_guarded[missing-checks]`, `no_project_patch_common_home_opens`. They guard against the new guard over-refusing, and M8 proves they can fail |

**PC-11 classification:** all 19 failures are `AssertionError` at the named, main-observable first clause (`"flows" in CHIP_FAMILIES`, `len(CHIP_FAMILIES) >= 6`, `"id_suffix" in signature`, `hasattr(fos, …)`, the label `📂 Open folder`, `the seam must not be called`). None is `ImportError`, `NoMatches` or a collection error, so all 19 are **RED at the named assertion**. The `checks` file and junction arms are the P-34 executed RED: the shipped `exists()` check called the seam.

| Field | Value |
|---|---|
| **RED counterfactual** | 19 of 22 new nodes RED at their named assertion on the unchanged source (no mutation needed — the tree lacked the families and the guard); transcript `.dev-flow/2026-10-19-batch-97/evidence/inc-1/red.txt` (sha256 `545b6c9d…77b3`); no source edit, so no restore. The 2 gate-fold boundary nodes (F1) and the F2 tooltip clause were added after that run; their RED is by mutation (M11, M12, M13), not on base |

| Field | Value |
|---|---|
| **Mutation verdicts** | `mutations.txt` holds three runs: (1) the original 18 arms on the pre-fold tree — 17 KILLED / 1 SURVIVED; (2) the same 18 arms re-run on the folded tree (my first edit adding M11–M13 had not applied, so the script ran in full) — same 17 / 1 verdicts; (3) gate fold `M11 stop_at=None` → KILLED by `…above_the_root_is_not_the_guards`, `M12 stop_at=root` → KILLED by `…at_the_root_is_refused`, `M13` session tooltip branch dropped → KILLED by tc28 (`folder does not exist yet`). Total 37 KILLED lines, 2 SURVIVED lines (the same declared M3 arm, twice), 0 CRASH, 0 BAD. Details of run 1, unchanged in run 2: M1 `chip_label` → `"📂 Open folder"`: 3/3 KILLED (tc65 shipped, no-project checks, session). M2 label line removed from `refresh_target`: KILLED (no-project checks). M3 reparse walk → `if False:`: KILLED by `guard_unit_arms` (leaf junction pointing *inside* the root); **SURVIVED** on `chip_press_guarded[junction-checks]` — declared in that test's docstring, because a junction pointing outside is also refused by containment. M4 containment → `return True`: KILLED. M5 chip guard → `target.exists()`: 4/4 KILLED (file/junction × checks/flows). M6 chip reason → `no_project_reason("reports")`: 2/2 KILLED. M7 service reason → reports label: KILLED. M8 root → `.s19tool/workarea`: 2/2 KILLED (incl. the no-project templates arm, H-C3). M9 drop the session create exclusion: KILLED. M10 `CHIP_FAMILY_FLOWS = "flows"`: KILLED. Every arm restored by sha256 (39 restore lines). Final source digests after the fold: `open_folder_chip.py 6ceb4f9b…cdfb558`, `folder_open_service.py 5d4e1bd7…27ee38`, equal to the "before" of runs 2 and 3 |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `tests/test_b97_chips_help.py` | the unchanged base source | 19 failed (`red.txt`) |
| `mutate.py` battery | 21 one-edit mutants (18 + M11–M13) | 37 `RED (KILLED)` lines over three runs (`mutations.txt`) — it reports kills, and it also reports the M3 survivor rather than hiding it |
| `make_junction` (fixture) | — | the guard unit arm's `leaf_in` junction is refused only while the reparse walk exists (M3 KILLED), so the fixture made a real reparse point and not a plain directory |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 3 instruments, each shown RED before its first PASS was believed (red.txt, mutations.txt) |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | none — this increment emits no artifact file. Its outputs are a widget label and a status line, which the tests read from the chip and from `app.log_lines` (the painted status buffer) at 220×60, so the full path is not clipped |

### Evidence files

| Evidence artifact | Path — under `.dev-flow/2026-10-19-batch-97/evidence/inc-1/` | SHA-256 |
|---|---|---|
| RED transcript | `red.txt` | `545b6c9d29284acdffce3c6f0f2702a35d0b99e73d50077e16a29b07467d47b3` |
| GREEN transcript (final tree, after gate fold) | `green.txt` | `ab941c0b1c5ec7bbd67bd8a2b54fee3ede671bfc3e5b4df0514e854b7e2449cf` |
| Reverse-census greps | `census.txt` | `46e01f0f141f485dc4c9db37cef267a9adbe9013cc6576e9bdf9fb23a06d5117` |
| Reverse-census run | `census-run.txt` | `b82059891bfe645b8afe86bfdd7223ed2dd74610ffb893b5b8b30c4c8285585a` |
| Flake probe (2 census nodes ×5) | `flake-probe.txt` | `b10ce4df4418018f3f805eb53d8bb1207d55a4f900033a3b0a8c63b619fdaad8` |
| Docs guard | `docs-canon.txt` | `27c18183445f87f090934c29e37790c2326e4a226b136e4547ea119b952daca2` |
| Mutation battery transcript (3 runs) | `mutations.txt` | `9cd7fb5d4acafc0fe8c2c5edf6b6e8b849134bb9c834359549f099bed2e8be55` |
| Mutation battery script (with M11–M13) | `mutate.py` | `a8484cc39131400d190846286981e5b978fad01a2553b32782df03b08afde71e` |

| Field | Value |
|---|---|
| **Evidence files** | 8 artifacts at `artifact_homes.evidence`/inc-1, each with the digest of its stored bytes |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | yes: "no test asserts the old label / `REPORTS_NO_PROJECT_REASON` / `_CREATABLE_FAMILIES` / `CHIP_FAMILIES`" (census), and "no snapshot baseline paints the chip" (B3) |
| If the result is an ABSENCE, what made the search wide enough | `grep -rl` over all of `tests/` (all extensions for B3: 109 SVGs + `__snapshots__`), not a list of files |
| Guard labelled as protecting a CONCLUSION | the census is a one-time probe; no standing guard is added |
| Conjunctive criteria: one mutation per conjunct | guard conjuncts: is_dir (M5 file arms), reparse (M3), containment (M4), exception→False (`guard_unit_arms` raising arm; not separately mutated — see §6) |
| Synthetic instance of the absent case | the leaf junction pointing inside the root and the intermediate junction (`guard_unit_arms`) — cases the shipped tree never had |
| **Positive control** | B1 greps return hits for `📂 Open folder` (2 files, docstrings) and `OpenFolderChip` (3 files), so the probe does see present symbols; B3 `grep "Open"` returns 0 on SVGs while the same grep hits `tests/test_open_folder_chips.py` |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by other tests | `grep -rl <sym> tests/` for `📂 Open folder`, `REPORTS_NO_PROJECT_REASON`, `_CREATABLE_FAMILIES`, `CHIP_FAMILIES`, `OpenFolderChip`, `resolve_chip_target`, `create_chip_home`, `no active project`, `Opened folder` (`census.txt`) | hits only in docstrings (`test_open_folder_chips.py`, `test_window_usage_help.py`) or as constructors/text that still hold; 0 assertions on the changed constants. Files re-run: `census-run.txt` — **336 passed, 3 failed, 29 xfailed** (+ `test_open_folder_chips.py` in green.txt) |
| B2 file moved | — | none moved |
| B3 golden captures | `grep -l "Open" tests/__snapshots__/**/*.svg` + all 109 `*.svg` | 0 hits; the 29 "mismatched snapshots" in census-run are the 29 xfailed cells of the live `xfail(strict=False)` envelope (baseline 32 xfail suite-wide), not this change |
| B4 artifact consumed elsewhere | — | no artifact is written; `create_chip_home` writes the same folders the savers use |
| A3 interface used outside the owning modules | `grep -rn` in `s19_app/` (`census.txt`) | `OpenFolderChip("checks"/"templates"/"patch")` at `app.py:2321/2476/3048`, `screens.py:1668` — positional calls still valid; `📂 Open folder` appears only in docstrings at `app.py:2281, 2458, 3028`, `window_help.py:5, 410` (outside the file set, §6) |

**Census-run failures vs baseline** (`comm -13` over baseline-pytest-51ee191): `test_at_056e…` is a baseline failure. `test_before_after_report.py::test_at_061a…` and `::test_tc330…` are new in that run and are **pre-existing flakes, not regressions**. Run against the HEAD versions of both source files (restored by hash), `tc330` failed and `061a` passed. On the Inc-1 tree, 5 isolated runs each gave `061a` 1 fail in 5 and `tc330` 0 fails in 5 (`flake-probe.txt`). Neither test touches a chip.

| Field | Value |
|---|---|
| **Reverse census** | 5 probes: B1 (9 symbols, hits re-validated by the census run), B2 none, B3 0 hits, B4 none, A3 4 constructor sites + 5 docstring sites; census run 336 passed / 3 failed (1 baseline + 2 pre-existing flakes, flake-probe.txt) |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | 1 — the label `📂 Open folder`: enumerated by `grep -rn "📂 Open folder" s19_app/ tests/` (census.txt) before editing; the sites in my two files were corrected (docstrings + `__init__`); the 5 docstring sites in `app.py` / `window_help.py` and 2 test docstrings were left, because they are outside the file set and only prose (§6) |

### Signed-balance test ledger

`post = base − deleted + added` → test nodes in the gate set: `50 = 26 − 0 + 24` ✓ (base 26 = 13 chip + 13 registry nodes, verified at toolchain entry; +24 new b97 nodes, 22 at first GREEN + 2 from gate fold F1).

---

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a named agent (agents/code-reviewer.md) · approve (round 1 approve-with-conditions F1 major, F2–F5 minor; F1/F2 fixed, F1 re-checked by the same reviewer with both boundary mutants killed; F3/F4 routed to Inc-3/Inc-4). security-reviewer — spawned as a named agent · LOW, 0 HIGH (probes executed: 7 escape shapes refused; residuals S3 TOCTOU accepted, S4 comma, S5 search order) |

---

## 5 · Risks

- **Guard boundary (decided at the gate):** the walk checks the root and everything below it, and ancestors above the root are not the guard's (`stop_at=root.parent`). The orchestrator amends LLR-148.8's prose via LED-.7. Two nodes pin it: a junctioned base dir still opens, and a junctioned `.s19tool` is refused (M11 and M12 KILLED). An operator whose `.s19tool` is itself a junction will see the no-project chips refuse.
- **Security lens (gate):** LOW, 0 HIGH. Residuals:
  - S3 — TOCTOU between the guard and `Popen`: same-user only, accepted.
  - S4 — a comma in the project path vs `explorer` switch parsing: not run.
  - S5 — `explorer` is resolved by search order: pre-existing.
- **Label length in headers.** `📂 Open templates/` is wider than `📂 Open folder`. Header fit at 118×54 is LLR-148.10's boundary and LLR-149.2's job, measured at Inc-3..7 and not here.
- **Status-line cap.** The refusal and open lines carry full paths. At `max(50, width)` cells they clip on narrow terminals, a shipped behaviour.
- `flows` / `session` chips are exercised only by test-mounted instances until Inc-5/6 mount them in headers.

## 6 · Pending items / spec deviations

- **LLR-148.8 ambiguity — resolved at the gate:** the boundary stays `stop_at=root.parent`. The orchestrator amends the prose (LED-.7); requirement files were not edited here.
- **Gate fold applied in this increment:**
  - F1: two boundary nodes, with M11/M12 KILLED.
  - F2: the `session` chip whose project dir is gone now shows its own tooltip, `project folder is missing` (`TOOLTIP_PROJECT_MISSING`), instead of the create-offer one. Pinned in tc28 by M13.
- **F3/F4 → Inc-3 / Inc-4 (LLR-148.6):** stale `📂 Open folder` in docstrings at `app.py:2281, 2458, 3028` and `window_help.py:5, 410`, and in the help bodies at `window_help.py:78, 117, 136`. All are outside this increment's file set.
- **Deviation from the I-1 wording, none in the signatures:** `CHIP_FAMILY_FLOWS = FLOWS_SUBDIR`, so the family token is the imported constant. That is how "0 `"flows"` literals" (LLR-148.1) is met. The refusal text is mine: `Refused to open <target>: not a real folder inside <root-leaf>/`.
- Stale prose `📂 Open folder` in the module docstrings of `tests/test_open_folder_chips.py` / `test_window_usage_help.py` — fix alongside F3/F4.
- The `OSError`/`ValueError` conjunct of the guard is covered by `guard_unit_arms` (patched `Path.resolve` raising, NUL path) but was not run as a separate mutant.
- Pre-existing flakes `test_before_after_report.py::test_at_061a…` / `::test_tc330…` (both fail intermittently on base and on this tree) → backlog.
- The 220×60 test size is a probe choice so full paths are not clipped (documented in `b97_probes.CHIP_TEST_SIZE`).

## 7 · Suggested next task

Inc-2 — flow foundations (NUL refusal, English service strings, `WAITING_HUMAN` / `CRC_FAMILY` tokens), with the security-reviewer at the gate. The orchestrator should first run the full suite node by node against the baseline, then the code-reviewer and security lens for this increment (the chip guard is security-relevant, §6.2).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files | all | ✓ | §2: 2 / 4 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b97_chips_help.py` (22 nodes) |
| 3 | Layer 0 where the criterion applies | `core` · `full` | ✓ | 6 layer-0 nodes (§4); `is_openable_chip_dir` cc ≥ 3, `resolve_chip_target` boundary |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red.txt` 19/22 RED at named assertions |
| 5 | Reverse census declared | `core` · `full` | ✓ | `census.txt`, `census-run.txt`, `flake-probe.txt` |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | approve after F1/F2 fold (§4b) |
| 7 | No file from another lane touched | all | ✓ | one lane |
| 8 | Frozen interfaces untouched (or returned to trunk) | all | ✓ | I-1 implemented as frozen (amended PC-20); §6 notes the `FLOWS_SUBDIR` token and the stop_at ambiguity |
| 9 | Coverage claims verified on disk | all | ✓ | node ids listed in `green.txt` (`-rA` PASSED lines) |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 table |
| 11 | Mutation verdicts per arm | all | ✓ | `mutations.txt` 17 KILLED / 1 SURVIVED (declared) |
| 12 | Instrument RED-proof | all | ✓ | §4, 3 instruments |
| 13 | Correction population | all | ✓ | 1 correction, enumerated by grep |
| 14 | Emitted-form assertion | all | ✓ | none — no artifact emitted |
| 15 | Independent review names somebody | all | ✓ | code-reviewer + security-reviewer (§4b) |
| 16 | Evidence files with digests | all | ✓ | 8 files, §4 |

## Gate — full suite, node by node against the baseline (orchestrator, 2026-10-20)

- **Run:** `evidence/inc-1/full-suite.txt` — 9 failed, 3124 passed, 3 skipped, 32 xfailed in 1:11:47. It started before the F1/F2 gate fold, so it measured the pre-fold tree; the fold (one tooltip constant + its use, three test nodes) is covered by the gate set in `evidence/inc-1/green.txt` (50 passed).
- **Comparison** (PC-12 command, `comm` over `FAILED`/`ERROR` node ids vs `evidence/baseline-pytest-51ee191.txt`):
  - not in the baseline (4): `test_before_after_report.py::test_tc330_…`, `test_tui_diff_screen.py::test_tc024_…`, `test_tui_patch_editor_v2.py::test_at058b_…`, `::test_saveback_width_32_…`. Re-run in isolation (`evidence/inc-1/new-fail-rerun.txt`): 3 pass; `tc330` failed once with `WorkerFailed: NoMatches('#log_line_1')` (a worker timing race), then passed 3/3 on this tree and 3/3 on a clean worktree at `42655eb` (no Inc-1 source). None touches a chip, a family constant or the guard. **Verdict: no regression; the four are order/timing-dependent flakes.**
  - baseline nodes green in this run (5): `at057b`, `at064c`, `at_batch41_escape`, `at077c`, `undo_redo ac1` — recorded, not claimed as fixed (same flake class; Inc-4 re-examines the patch_editor_v2 nodes).
  - counts reconciled: xfailed 32 = baseline 32, skipped 3 = 3, XPASS 0.
- **Routed:** the order-dependent flakes above → backlog at close (suite hygiene), not this batch's scope.

