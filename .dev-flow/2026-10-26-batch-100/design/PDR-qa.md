# PDR — qa-reviewer — batch 2026-10-26-batch-100

**Mode: plan.** This is the tester's lens on `design/design-proposal-b100.md` at `a1cad7e`, checked against the approved `01-requirements.md` (ledger up to LED .34). The rules come from `stations/p3-implementation.md` §PDR. Nothing outside this file was edited.

**How the probes ran.** Every probe was executed by **qa-reviewer** on `git archive 1d677ba` snapshots, using `s19env` Python 3.11.15 and Textual 8.2.8 with `NO_COLOR` unset:
- `<scratch>/snap1d677ba` (plain).
- `<scratch>/snapgit1d677ba`: a scratch `git init` of the same tree, with `.dev-flow/` dropped because of path length, committed as branch `main`. It exists so that the registry and freeze guards, which need `.git` plus `pyproject.toml`, can run.

The import probe printed `s19_app.__file__` as each snapshot's `s19_app\__init__.py`. `git diff --stat 4e9c8f1 a1cad7e -- s19_app tests` is empty.

## Verdict

**`approved with conditions`.** There is **no HIGH**. Every condition below can be discharged on its own and has an owner and an increment. Three are MAJOR: if left open, each would surface as a test that cannot pass, a polluted user store, or a whole-tree guard that misses its target.

| Condition | Severity | Owner · increment | Discharged when |
|---|---|---|---|
| C-QA-1 | MAJOR | author + architect · before Inc 12 | The parse step's in-step progress has a source file, or the threshold moves to a measurable step, through a ledger entry. |
| C-QA-2 | MAJOR | author · Inc 9a | An autouse `LOCALAPPDATA` isolation fixture is in `tests/conftest.py`, plus a guard showing the real store is untouched. |
| C-QA-3 | MAJOR | orchestrator · from Inc 1 | The gate command also runs `-k census`, or each packet records an actual full-suite run with its elapsed time. |
| C-QA-4 | MINOR | author · Inc 4 onward (E4) | E4 states which builders may write `project.json`. Output-then-consume (C-12) gate ATs use the shipped handler. |
| C-QA-5 | MINOR | author · Inc 11 | The host of the 2 s measurement is named. |
| C-QA-6 | MINOR | author · every increment | Platform-skipped arms are counted in the packet, never silent. |
| C-QA-7 | MINOR | orchestrator · each brief | Each Kimi brief lists the re-pins and arm extensions that the contract's §5.3 assigns to its increment. |
| C-QA-8 | MINOR | author · Inc 1 | The §5.1 LLR-163.4 row says `…bin_pair_placed_under_one_suffix` stays unchanged. |

## Findings

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| C-QA-1 | MAJOR | §5.14 (Inc 12 = `app.py`, `styles.tcss`); HLR-176 threshold "the case_06 A2L parse → the bar value increases ≥ 2 times within the parse step"; LLR-176.1 "from `done/total` when the step reports bytes (… parse)"; AT-B100-17 "the bar moves during the parse" | **Inc 12 cannot make the bar move during the parse.** The parser is one opaque call, `parse_a2l_file(path) -> dict` (`s19_app/tui/a2l.py:2627`), with no progress parameter. Nothing in Inc 12's two files can observe bytes parsed inside it, so the within-parse arm of TC-B100-50 and AT-17's "bar moves during the parse" cannot pass. The mutation LLR-176.1 declares ("bar from step index only → the within-step arm RED") has no GREEN to start from. | `grep -n "def parse_a2l_file\|progress\|callback" s19_app/tui/a2l.py` → only `2627: def parse_a2l_file(path: Path) -> dict:`. `a2l.py` is **not** frozen (`tests/test_engine_unchanged.py:125-133`, unfrozen in batch-56), so either way out is allowed. | Either (a) add `s19_app/tui/a2l.py` to Inc 12 (3 files) with a progress callback (bytes consumed) and a TC arm, or (b) report a measurable *read* step (bytes read) plus an indivisible parse step, through a ledger entry amending HLR-176's threshold and AT-17's outcome. Decide before Inc 12's brief. |
| C-QA-2 | MAJOR | E5 (`LOCALAPPDATA` monkeypatched only in the new tests); LLR-172.1 (`recent_store_path()` = `%LOCALAPPDATA%\s19_app\recent_sources.json`) | **From Inc 9a, existing tests write to the real per-user store.** Every successful outside load records a recent. 17 existing test files drive `load_from_path` / `load_a2l_from_path` / `#load_path`, and `tests/conftest.py` has no autouse isolation. From Inc 9a, a local suite run writes into the developer's real `%LOCALAPPDATA%\s19_app\recent_sources.json`, and the recents TCs become order-dependent. The Linux CI hides this: `LOCALAPPDATA` is unset there, so the store is disabled. | `grep -rlE --include=*.py "load_from_path\(\|load_a2l_from_path\(\|#load_path" tests` → 17; `grep -n "LOCALAPPDATA\|autouse" tests/conftest.py` → 0 hits; `tui-ci.yml:25,59` `runs-on: ubuntu-latest`. | In Inc 9a, add an autouse fixture to `tests/conftest.py` (a test file, so not counted against the SOURCE cap) that points `LOCALAPPDATA` at a per-test `tmp_path`. Add one guard that the real store's mtime and size are unchanged across a session. |
| C-QA-3 | MAJOR | §5.16 whole-tree guards | **The six-file guard set misses most whole-tree censuses.** The set covers both of batch-99's misses: `test_tc653_safe_text_import_census` is in `test_import_census.py`, and the `patch-comfortable-120x30` cell is in `test_tui_snapshot.py`. But **20 other test files** hold census tests that read the whole tree. Examples: `test_tui_patch_editor_v2.py`, `test_tui_patch_json.py`, `test_flow_persistence.py` (LLR-169.8 touches its resolver), `test_report_field_census.py`, `test_universal_paste.py`. This batch changes `safe_text` use, labels, the manifest resolver and the Patch Editor panel, which is exactly what those censuses guard. §5.16 also lists "full suite at every gate", but batch-99 adopted the named set because a full run costs about 2 h 20. If the full run is not actually made at each gate, these censuses wait for the close again. | Six-file command on `snapgit1d677ba` → `75 passed in 127.58s`, `29 snapshots passed`, exit 0. `pytest -k census tests` → `84 passed, 3689 deselected in 79.30s`. `grep -rlE "def test_[a-z0-9_]*census" tests` → 23 files, 20 outside the set. | Add `pytest -q -k census tests` (84 nodes, about 80 s) to the gate command. Alternatively, record in each packet a full-suite run made at that gate with its elapsed time. |
| C-QA-4 | MINOR | E4 `tests/support/b100_projects.py` (builders for the `p02` A/B save-backs, the `p04` cases, a legacy project …) vs the §3 preface C-12 rule | The builders' contract is not stated. The gate ATs AT-05, -06, -07, -08, -10 and -20 must produce `project.json` through the shipped handler, driven by keys. A builder that writes `project.json` directly may only serve TCs, or the AT arms whose subject *is* a hand-made manifest (AT-07's hostile `files` arm, legacy, damaged). | The text of E4 and of the §3 preface. | State in E4: builders lay down data files only, and a builder that writes `project.json` is named and used only where the subject is a hand-made manifest. The QC-AT grep in each packet also checks this. |
| C-QA-5 | MINOR | LLR-175.4 / LED .26 ("within 2 s **on the CI host** … measured at Inc 11") | The budget is correctly declared as an assumption, to be measured at Inc 11. But "the CI host" is `ubuntu-latest`, while the increments run in Windows worktrees. | Pre-measurement on this Windows host: streamed SHA-256 of the 37 742 888-byte case_06 A2L → `0.024 s` (warm cache), well inside 2 s. The emitted-image digest and the plan come on top of that. | Name the host (Windows dev host, and CI if run there) and record both cold-cache and warm figures in the Inc 11 packet. |
| C-QA-6 | MINOR | E1 (`make_junction`, `make_file_link`); the case-insensitive `_2` arm (LLR-163.1); the Windows path arms | Windows-only arms will skip on the Ubuntu CI. A file symlink also needs a privilege (Developer Mode or admin) that another Windows host may lack. A silent skip is a fail-loud breach. | On this host `_winapi.CreateJunction`, a directory symlink, a file symlink and a hard link all succeeded. The CI is `ubuntu-latest`. Python 3.11 has no `os.path.isjunction`, so the code keeps `_is_reparse_point`. | E1 uses `_winapi.CreateJunction` (no privilege) on Windows. A file-link arm that cannot get its link skips with a named reason, and each packet reports its skip count per platform. |
| C-QA-7 | MINOR | §5.1–§5.14 vs contract §5.3 | The per-increment tables list the ATs *written* in each increment. The *re-pins and arm extensions* live only in the contract's §5.3, while the briefs quote the design's §5.x. Examples: AT-03 at 9b and 10, AT-04 at 6 and 9b, AT-05 at 6, AT-19 at 7, AT-20 at 7 and 8a, and the `#project_parent_path` nodes at 11. | The two tables compared: the AT written-at columns agree, and §5.15 says extensions are in §5.3. | Each `kimi/BRIEF-inc-<N>.md` carries its rows from contract §5.3 and §5.4. |
| C-QA-8 | MINOR | §5.1 LLR-163.4 row ("re-pinned nodes: …changed_bytes…, …bin_pair_placed_under_one_suffix") | The bin-pair node stays unchanged (P-22; LLR-163.4 lists it among the nodes that stay). Listing it as "re-pinned" invites an edit. | LLR-163.4 statement. | Reword the row as "re-pinned: `…changed_bytes…`; kept green: `…bin_pair…`". |

## What was checked and holds

- **Non-vacuous, with mutations that turn RED.** A sample of declared REDs and mutations was executed, in this round or in P2 rounds 1–3, on `1d677ba`:
  - P-1/2/3/4/5/6/10..20 probes reproduce.
  - LLR-167.1: P-37 (`save_patched(check doc): ok = False`) and the data-decision emulation (check → copy, same bytes → copy, real change → emit).
  - LLR-169.7: race 8/80 written → RED.
  - LLR-172.6 / LLR-173.3: markup on → 1 span; `safe_text` → 0.
  - LLR-174.1: 24 cells, 11 ask / 13 load; mutations D 5, F 1, W 1, attach 4.
  - LLR-176.2: AST → 24 sites, 12 functions. The declared steps `:4951` (55), `:6210` (55), `:8769` (50) and `:8841` (50) are mid-values, as the threshold assumes.
  - LLR-165.2: snapshot emulation; cold vs cold differs only in the stat-keyed cache, which the contract now normalises.
  - LLR-172.2: 1 000 distinct entries = 40 034 bytes.
  - Every other TC and AT has a declared mutation or executed RED.
- **AT private access.** The §3 preface bans `app._…` access and private calls, setup included. The one declared exception is `SaveProjectScreen.plan`, which LED .31 (PDR-QA-1) makes a frozen dataclass read after `alt+s`. The proposal adds no other exception. Watch-items: E4 (C-QA-4), and the Inc 10 "dirty Flow Builder through the panel API", which may only be used in TCs.
- **Enablers buildable on Windows:**
  - E1 junctions and links: executed, see C-QA-6.
  - E2 hostile names: all exist on NTFS (round 3).
  - E6 case_06: 37 742 888 bytes, present in the archive.
  - E10 size helper: `App.run_test(*, headless, size, tooltips, notifications, message_hook)` in Textual 8.2.8 accepts `size=(118, 54)` / `(220, 60)` and `notifications=True`.
  - E9: the 1 000-entry file fits.
- **Placement per increment** matches §5.3 for written-at. Arm moves are declared (LLR-166.1 → 6/9b/10, LLR-167.6 → 7/8a/8b, LLR-171.4 → 1/7/8b, LLR-173.6 function at 7), with C-QA-7 for the briefs.
- **The whole-tree guard command runs.** It needs a git checkout with `pyproject.toml`, which the Kimi worktrees are. In a plain archive, `test_batch91_registry_hygiene.py` stops collection with "could not locate the repository root". The command covers the import census, snapshot cells, id registry, address census and freeze guard, and both batch-99 misses. Gap: C-QA-3.
- **UX C-2 (2 s):** declared as an assumption, measured at Inc 11 (LED .26, LLR-175.4, §6 risks). Host: C-QA-5.
- **The three re-pins** (§5.1, LLR-163.3/163.4, contract §5.4):
  - TC-018: two pairs (identical → same path, 1 file; different → `cs_1.json`).
  - AT-031b: two `save_doc` of an unchanged document → 1 file; after an added entry → 2 distinct files.
  - `test_tc_b99_31_changed_bytes_take_the_next_free_name`: the third export reuses `t_isle_1.s19` with action `reused`, leaving 2 files. It lands with `segment_split_view.py` in Inc 1.
  - The old values are RED at base: P-7, `FF`. Each is named old → new in its packet's reverse census.

## Evidence checklist (qa-reviewer, PDR)

- [✓] **Mode declared:** plan.
- [✓] **Every proposed TC/AT is observable and has a declared mutation or executed RED.** Exception: TC-B100-50 / AT-17's in-parse arm, which cannot pass as planned (C-QA-1).
- [✓] **Edge cases (empty, boundary, invalid, error)** are carried from the contract's catalogs. The enablers build them: E2, E8, E9, E1.
- [✓] **Regression:** the reverse census (contract §5.4) and the guard command (§5.16) were executed (75 passed + 29 snapshots). Census coverage gap: C-QA-3.
- [✓] **Exit criteria:** contract §5.2.
- [✓] **No real PII or secrets.** The real per-user store is exposed to the suite until C-QA-2 is discharged.
- [✓] **Plan mode:** the batch's results are `planned`. These probes are `executed` (executor: qa-reviewer, on the `1d677ba` snapshots).
- [✓] **Layer B black-box:** one declared exception, frozen and read-only. C-QA-4 is a watch-item.
- [✓] **Bidirectional surface-reachability:** carried from P2 round 3 (all four load routes go through one seam).
- [✓] **No unfilled template:** none in the proposal.

Probe scripts and outputs (scratch, not committed): `<scratch>/qa-p2r1-scripts/links_probe.py`, `<scratch>/qa-p2r1/pdr_guards.txt`, plus the earlier round scripts.
