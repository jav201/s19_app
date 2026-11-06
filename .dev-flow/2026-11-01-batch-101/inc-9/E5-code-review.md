# Inc 9 — E5 code review

Batch 2026-11-01-batch-101, increment 9. Reviewer: code-reviewer (independent of the implementers, the testers and the integrator). Scope: `git diff e07fb00 -- s19_app docs` and `git diff e07fb00 -- tests` at head `b204c7d` of branch `b101-inc9` (worktree `C:/Users/jjgh8/Github/s19_app-b101-inc9`). That is 4 source files (`flow_persistence_service.py` +268, `flow_execution_service.py`, `app.py`, and `flow_screens.py`, which changes its module docstring only), `docs/user-guide/ch18-flow-execution.md`, `docs/user-guide/DOSSIER.md`, 2 new test files (`tests/test_b101_flow_saves.py`, `tests/test_b101_flow_names_ui.py`) and 3 edited test files. I read all of it in full against `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc9.md` (I-1 … I-7), `E1-rulings.md`, `E3-rulings.md` (rounds 1 and 2), `E4-rulings.md` (E4-R1 … E4-R3), `E4-integration-notes.md` and the implementer and tester notes. I read the callers and helpers the change relies on: `workspace._guarded_destination`, `_is_reparse_point`, `contained_in_workarea`, `place_into_workarea`, `_placed_name_candidates`, `sanitize_project_name`, the loader name rules (`flow_persistence_service.py:419`, `:1495`), every reader of the chain-run mode, and `tests/b97_fixtures.make_junction` / `write_flow`.

I ran nothing that imports `s19_app` (operator rule). Every statement about a test run comes from the integrator's transcripts `evidence/inc-9/int-01` … `int-09` and the testers' base runs. To tie them to this head I rebuilt the staged tree with a temporary index (`git read-tree e07fb00`, then `git diff --binary e07fb00 HEAD -- s19_app tests docs README.md | git apply --cached`): it gives `d1b3f7dd551f…`, the tree int-09 ran (`int-09-e4r3.txt`), and the working tree equals HEAD for `s19_app`, `tests` and `docs`. The UI file last ran in int-01 / int-07, on the tree before E4-R3; E4-R3 adds one `os.open` argument and one service node, nothing the UI file reads.

To settle the Windows questions without importing `s19_app`, I ran a stdlib-only probe (`-I`, files only in my session scratchpad, no clipboard, no app state) of the exact primitives `_create_new_json` uses, on this PC under Python 3.11.15 (the `s19env` interpreter), 3.12.7 and 3.14.4. Results are in check 4.

## Verdict

**PASS-WITH-NOTES.** There is no HIGH or MAJOR finding. The product code is correct against every active row and honours I-1 … I-7 exactly as ruled (E4-R1's real-parent clause, E4-R3's `0o666`). Every error path of `_create_new_json` closes the descriptor before it unlinks (needed on Windows), unlinks only what the call created on the check-failure path, and writes no byte before the check after the claim. On Windows the primitives behave as the design assumes (check 4).

There are ten MINOR findings, all recommendations:
- CR-01: the 64-character cut can write a name that is another saved file's stem, which contradicts US-I9-2's "so that".
- CR-02, CR-03: the same-file (`samestat`) clause and the error arms of the claim have no node; a mutant that drops either survives.
- CR-04: the file-link and emulation nodes call `os.symlink` raw, so a Windows run without the privilege fails instead of skipping.
- CR-05, CR-06: docstrings drift (two handlers, the `Raises` of the saves and the helper; three leftover single-edge claims in `flow_screens.py`).
- CR-07 … CR-10: small robustness, simplicity, test-strength and record-wording points.

## Checks

| # | Check | Result | Evidence state |
|---|---|---|---|
| 1 | Code = graph, I-1 … I-7 | **I-1:** `CHAIN_RUN_CONFIRM_RERUN = "confirm re-run"` (`flow_execution_service.py:1751`); `CHAIN_RUN_MODES` stays the two switch modes (`:1745`); any other token raises the same `ValueError` (`:2007-2008`); dispatch runs every non-`parallel` mode in lane order (`:2092-2097`); `ChainSetRunRecord(mode=mode)` keeps the token (`:2011`) and `compose_chain_set_report` prints it verbatim (`:2155`). The three E3A-07 docstrings name the token. **I-2:** both signatures character for character (`flow_persistence_service.py:1147-1153`, `:1663-1669`); the `None` arms come first, then `_guarded_destination` before the `mkdir` (`:1217`, `:1708`), so a home refusal creates nothing (D-10); both causes raise `WorkareaContainmentError`. **I-3:** after joining the implicit concatenation, the two texts equal I-3 (`app.py:4022-4025`, `:4584-4587`); only `set_status`, no `mark_saved`, and the FX handler also skips `_prefill_flow_execution_sets`. **I-4:** withdrawn; `flow_screens.py` changes its module docstring only. **I-5:** `workspace.py` not edited. **I-6:** untouched. **I-7:** signature (`:984-989`), `O_CREAT\|O_EXCL\|O_WRONLY\|O_BINARY` with `0o666` (`:1072-1076`), the fill through that descriptor (`:1135`), the E4-R1 clause `Path(os.path.realpath(candidate)).parent == resolved_home` (`:1114`); `contained_in_workarea` is no longer imported. | executed (read) |
| 2 | Error paths of `_create_new_json` | **Name check:** `lexists`, so a dangling link is taken (`:1059`). **Race:** `FileExistsError` → next (`:1077-1081`); another `OSError` → next only when the name now exists, else re-raise (`:1082-1089`); the loop cannot spin, since some `_<N>` is always free. **Payload:** rendered before the claim (`:1066`), so a serialiser raise creates nothing. **lstat failure in (d):** close, best-effort unlink, raise (`:1097-1109`). **Check failure:** close, unlink only when `owned` (regular and same stat), raise (`:1110-1128`). **Write failure:** the `with` closes before the `except` unlinks and re-raises (`:1134-1142`). Close precedes unlink on every path, which Windows needs (Python's `os.open` grants no `FILE_SHARE_DELETE`). Gaps: CR-07. | executed (read) |
| 3 | Descriptor leaks | None on the handled paths. `os.fstat(fd)` and `os.path.realpath(candidate)` sit outside any `try` (`:1110`, `:1114`): a raise there leaks `fd` and leaves the empty claim (CR-07). | executed (read) |
| 4 | Windows vs POSIX | Stdlib probe on this PC, Python 3.11.15 / 3.12.7 / 3.14.4, local NTFS. **`samestat(fstat(fd), lstat(candidate))`:** True on all three; `st_dev` is the 32-bit serial on 3.11 and the 64-bit one on 3.12+, equal within each version. **Real parent:** `Path(realpath(candidate)).parent == resolved_home` is True with `resolved_home` resolved before the `mkdir` (the save's order), and True for an upper-case spelling of the home (`PureWindowsPath` equality is case-insensitive). **Bytes:** `O_BINARY` + `fdopen("w")` give the bytes `write_text` gives (`\r\n`). **Home swapped for a junction:** the claim is regular and same-stat, the real parent differs, so it is refused, and the unlink removes the claim from the outside folder. **`\\?\`:** both sides come from `ntpath.realpath`, which keeps the prefix only when the input had it, so they agree; a path over `MAX_PATH` without long-path support fails at `os.open` as the base's `write_text` did. **POSIX:** `O_EXCL` refuses a final-component link (EEXIST), which /14/3's spy relies on. Not probed: non-NTFS, network or virtual volumes. The work area is `<cwd>/.s19tool/workarea` (`app.py:2819`), so it can sit on any volume. A false refusal there would block every save with the I-3 text; E5's Windows arm should run one plain save on the operator's real volume type. | executed (stdlib probe; no `s19_app` import) |
| 5 | The 64-character cut | `stem[:64]` counts code points, as the loaders' `len(name) > 64` does (`:419`, `:1495`). The sanitiser keeps only alphanumerics, `-` and `_`, so `Path.stem` is the whole stem. Meets R-FLOW-FILE.13 and R-FLOW-SET.10 as written; see CR-01 for what the cut writes on a clash. | executed (read) |
| 6 | Confirm re-run mode | The only reader of `record.mode` is the report's Mode line (grep of `s19_app`); `apply_confirmed_run` never reads it. The confirm handler's `except Exception` covers a `ValueError`. TC-B97-55 passed in int-02. | executed (read, grep) |
| 7 | Callers | `save_flow_json` / `save_chain_set` are called only by the two app handlers. A `project_dir` with no `.s19tool/workarea` anchor now raises; only test callers exist, and int-02 / int-03 are green. `self.workarea` is the app's work-area root (`app.py:2821`); `_active_project_dir` returns the folder unresolved (`app.py:3192-3222`), as the guard needs. | executed (read, grep) |
| 8 | Tests: oracles, base RED, can they fail | Service nodes assert on raises, bytes on disk, listings and load findings; UI nodes on the painted status line, the ribbon, report lines and files, each after the action's own sign. Base RED is behavioural for 15 + 9 nodes; the five home rows were RED on base by `TypeError`, and int-06 shows them behaviourally. **Correction to the E4 mutant table:** M14 (`owned` always true) is *not* equivalent. /14/4 and /8/4 kill it: the owned branch unlinks the link, and their "still the link" / `_entries(home) == ["z.json"]` assertions fail. A mutant that drops only `samestat` survives every node (CR-02). Gaps: CR-02, CR-03, CR-04, CR-09. | executed (read) |
| 9 | Edited existing nodes | `_FIXED` 11 → 13 by named supersession; `EXPECTED_SCANNED_TEST_FILES` 267 → 269 with its history comment; the TC-B99-13 census moves the two saves from declared exceptions to one allow-listed helper whose `os.unlink` calls sit in its own body. No assertion is weakened. | executed (read) |
| 10 | Docs | ch18:111-113 and DOSSIER F-45 / F-46 match the change. No other sentence in `docs/user-guide/*.md` or `README.md` describes the old Mode or the stale name (grep of `F-45`, `F-46`, `Mode:**`, `"name"`). The `flow_screens.py` module docstring has 0 occurrences of the three E5 check phrases; the same file still has leftover claims (CR-06). | executed (read, grep) |
| 11 | Reuse and simplicity | Reused as they are: the shared guard, `_is_reparse_point`, `WorkareaContainmentError`. The house name walk `_placed_name_candidates` starts at `_1` while the saves keep `_2` (D-9), so a local walk is justified. One helper serves both saves, as the graph ruled (E3-1). Minor repetition: CR-08. | executed (read) |
| 12 | Mutant table | Not run by me; it is E5's runner. | not-run |

## Findings

### CR-01 — the cut can write a name that is another saved file's stem  [MINOR · design-gap (requirement)]
- **Where:** `flow_persistence_service.py:1222`, `:1714`; case R-FLOW-FILE.13/2 and its node `tests/test_b101_flow_saves.py` `test_r_flow_file_13_2_clash_suffix_is_cut`.
- **Failure scenario:**
  - `flows/<"C"×64>.json` exists, and the operator saves another flow as `"C"×64`. The new file is `<"C"×64>_2.json`, and its `name` is `"C"×64`, which is the stem of the first file. A lane run from the second file titles its flow report with the first flow's name.
  - A shorter stem gives the same effect: with a 61-character stem, the 100th clash `<61>_100` (65 characters) is cut to `<61>_10`, which is the stem of the 10th clash file.
  - The same holds for chain sets.
- **Why it matters:** the code does what R-FLOW-FILE.13 / R-FLOW-SET.10 say, and the approved case pins it. US-I9-2's purpose, though, is "so that no file or lane report shows the name of another flow" — the F-46 class this increment closes. D-3 weighed only loadability, not clashes.
- **Fix (needs a ruling):** cut the clean part and keep the suffix, e.g. `name = stem if len(stem) <= 64 else clean[:64 - len(suffix)] + suffix`. This keeps every name unique and at most 64 characters, and changes the two rows and case /13/2. If the ruling keeps the cut, add the limitation to US-I9-2's notes or to BL-I9-1.

### CR-02 — the same-file clause of the check after the claim has no node  [MINOR · test-gap]
- **Where:** `flow_persistence_service.py:1110` (`os.path.samestat(os.fstat(fd), st)`); `tests/test_b101_flow_saves.py` (no node).
- **Failure scenario (Windows, a double race):**
  - A dangling link is put in at the free name after the `lexists` check.
  - The exclusive create follows it (house S-F1): `fd` now writes to the link's target outside.
  - The link is then replaced by a regular file before (d).
  - Without `samestat`, (d) sees a regular file, no reparse point, and a real parent equal to the home. The flow's JSON goes through `fd` into the outside file. The owned branch would also unlink the stranger's file on a later failure.
- **Why it matters:** S_ISREG is redundant once `samestat` holds, but `samestat` is the one clause that closes this scenario. In /14/4 `owned` is false through S_ISREG; in /14/5 the claim is genuinely ours. So a mutant that removes only `samestat` stays GREEN everywhere. E3 S-2 asked for one negative control per defence, and R2-1 added /14/5 for the same reason.
- **Fix:** add one emulation node per save, beside `_windows_follow`. Its `os.open` wrapper creates `<O>/followed.json`, opens it, puts a regular file at the candidate, and returns the `followed.json` descriptor. Expect `WorkareaContainmentError`, `<O>/followed.json` 0 bytes, and the planted file's bytes unchanged.

### CR-03 — the error arms of the claim have no node  [MINOR · test-gap]
- **Where:** `flow_persistence_service.py:1066` (render before the claim), `:1082-1089` (another `OSError`, then `lexists`), `:1097-1109` (lstat failure), `:1134-1142` (write failure).
- **Failure scenario:** a mutant that drops the unlink in (e) stays GREEN. On a full disk, the save then leaves an empty or cut-off `z.json` under the claimed name: Load lists a flow that refuses to load, and the next save goes to `z_2`. A mutant that moves `render` after the `os.open` leaves an empty file when serialisation raises. Both survive. The integrator left S-3 to E5 ("no row and no node").
- **Fix:** four monkeypatch nodes on Linux:
  - `os.fdopen` returns a writer whose `write` raises `OSError(ENOSPC)` → `OSError` re-raised and the home holds no new entry.
  - `os.lstat` raises once for the candidate → `WorkareaContainmentError` and no entry.
  - The module's `flow_to_dict` raises → the Create spy records 0 calls and nothing is created.
  - `os.open` creates a directory at the candidate and raises `PermissionError` → the next `_<N>` is claimed.

### CR-04 — file-link and emulation nodes fail on Windows instead of skipping  [MINOR · test hygiene]
- **Where:** `tests/test_b101_flow_saves.py:294-296` (`_link_file`), `:98` (`_windows_follow`), `:115` (`_swap_home_for_link`): nodes /14/1 … /14/5 and /8/1 … /8/4.
- **Failure scenario:** on a Windows account without the symlink privilege, `os.symlink` raises.
  - In `_link_file` the node errors.
  - In `_windows_follow` the `OSError` comes out of the patched `os.open`. The product's `except OSError` (`:1082`) finds no entry and re-raises it, so `pytest.raises(WorkareaContainmentError)` fails with an `OSError`. That reads as a product defect. The descriptor the wrapper opened also leaks.
- **Why it matters:** the house pattern is a named skip (`_symlink_or_skip`, `tests/test_b100_load_dialog.py:381`; Inc 6 I-D5). E3A-08 runs the Windows arms at E5 on this PC.
- **Fix:** use `_symlink_or_skip` in `_link_file`. In the two emulations, probe the privilege once before patching `os.open` (make and remove a scratch link; `pytest.skip("os.symlink is unavailable here (reported not run): …")` on failure).

### CR-05 — docstrings of the handlers and the saves miss the new behaviour  [MINOR · impl (doc)]
- **Where:**
  - `app.py:3992-3999` (Builder save Summary: "a no-project state renders the error card, an un-sanitisable name a status message") and `:4544-4552` (FX save Summary): neither names the refusal and its status.
  - `flow_persistence_service.py:1027-1031`, `:1182-1185`, `:1697-1700`: the `Raises` of `_create_new_json` and both saves omit the `OSError` the helper re-raises on purpose (`:1089`, `:1142`).
  - `:1205-1206`: `Used by: the app Save handler (later increment)`.
  - `save_chain_set` still has no `Data Flow` / `Dependencies` sections, though it now calls the guard and the helper.
  - `flow_execution_service.py:2004-2005`: `run_chain_set` `Used by` omits the confirm handler, the only caller of the new token.
- **Why it matters:** this is the repo's docstring contract (`PROJECT_RULES.md` §Function Docstring Contract; `CLAUDE.md`), and Inc 6 E5 raised the same class as its F2.
- **Fix:** add "a home that passes through a link or lies outside the work area refuses the save with the I-3 status (R-FB-SAVE.8 / R-FX-SET.15)" to both Summaries. Add `OSError: the create fails for a reason other than a taken name, or the write fails (the claim is removed first)` to the three `Raises`. Name `S19TuiApp.on_flow_builder_panel_save_requested` / `on_flow_execution_panel_save_requested` and `on_flow_execution_panel_external_step_confirmed` in `Used by`. Give `save_chain_set` the two sections that `save_flow_json` has.

### CR-06 — `flow_screens.py` still states the retired single-edge rule outside the module docstring  [MINOR · impl (doc)]
- **Where:**
  - `flow_screens.py:3074-3076` (`FxLaneSpec`): "the panel never imports the execution/persistence modules (the declared `flow_screens → services/flow_model` edge stays read-only dataclasses)".
  - `:1411-1413` (`FlowBuilderPanel` `Uses`): only `flow_model`, "read-only per the R8 declared edge", though the panel calls `fps.FLOW_UNSAFE_REF`, `fps.flow_to_dict` and `fps.dict_to_flow` (`:827`, `:2238`, `:2270`, `:2276`).
  - `:3204` (`FlowExecutionPanel` `Uses`): "the declared R8 edge".
  - `:43-44`: the module docstring itself still says "That is the second declared `flow_screens → services` edge", just after saying that no `docs/architecture.md` section is cited for an import rule.
- **Why it matters:** D-8 / A16-4 retired exactly this claim. The graph scoped the rewrite to `:1-42`, and the E5 phrase check passes, but the same file still tells a reader the opposite.
- **Fix:** docstring-only edits. In `FxLaneSpec`: "the panel never calls the executor; the app translates it". In the `FlowBuilderPanel` `Uses`, add `flow_persistence_service` (serializer, loader, unsafe-ref code). Drop "declared" / "R8 declared edge" at `:44`, `:1413`, `:3204`.

### CR-07 — part of the check after the claim runs outside a `try`, and the lstat arm unlinks without the ownership test  [MINOR · impl]
- **Where:** `flow_persistence_service.py:1110`, `:1114` (`os.fstat`, `os.path.realpath`); `:1101-1105` against the Summary at `:1006-1007` ("the claim is removed (only when it is ours)").
- **Failure scenario:**
  - An `OSError` from `fstat`, or from `ntpath.realpath` (a winerror outside its allowed list), leaks `fd` and leaves an empty file under the claimed name, which takes the name for every later save.
  - The lstat-failure arm unlinks whatever is at the name with no same-stat test, although the docstring promises otherwise.
  - Both are improbable; the house's `place_into_workarea` has the same unconditional unlink.
- **Fix:** compute `owned`, the reparse test and the real parent inside one `try … except OSError` that routes to the refusal (close, unlink if owned, raise). Alternatively, reword the Summary to "removed best-effort when the check cannot even read the entry".

### CR-08 — the "next candidate" step is written three times  [MINOR · simplicity]
- **Where:** `flow_persistence_service.py:1060-1062`, `:1079-1081`, `:1086-1088`.
- **Fix (optional):** iterate one walk — `for candidate in (home / n for n in itertools.chain([f"{clean}.json"], (f"{clean}_{k}.json" for k in itertools.count(2))))` — and `continue` in place of the three copies. The numbering (`_2` first, D-9) is unchanged.

### CR-09 — two nodes assert less than their row  [MINOR · test]
- **Where:** `tests/test_b101_flow_saves.py` `test_r_flow_set_8_1_dangling_link_gets_no_file`, `test_r_flow_file_14_5_swapped_home_gets_no_byte`.
- **What:**
  - **/8/1:** R-FLOW-SET.8's threshold is "as R-FLOW-FILE.14", which includes "the link unchanged", and /14/1 asserts `is_symlink()`. /8/1 does not, so a set save that replaced the link would pass it.
  - **/14/5:** the node accepts an empty `z.json` left in Folder O. The code removes it (owned), so a mutant that drops that unlink survives. BL-I9-4 permits the empty file, so this is a strength note, not a defect.
- **Fix:** add `assert (project / "flowsets" / "s.json").is_symlink()` to /8/1. Optionally, assert `not landed.exists()` in /14/5 and record in its docstring that the stricter form is the code's, not the row's.

### CR-10 — BL-I9-4 names an empty file as the only residual; an empty folder is possible too  [MINOR · record]
- **Where:** `E1-rulings.md` BL-I9-4; graph entity `[I/O: outside folder]`; `flow_persistence_service.py:1218`.
- **Failure scenario:** `flows/` does not exist yet, and the project folder is swapped for a link to Folder O between the guard and the `mkdir`. `mkdir(parents=True)` then creates `<O>/flows/`. The claim inside it is refused and removed, but the empty folder stays. Still no content.
- **Fix:** add "or an empty `flows/` / `flowsets/` folder" to BL-I9-4 and to the entity's residual sentence.

## Carried, not findings

- The Windows arms (junction homes, dangling-junction arm of /14/1 and /8/1) are `not_run` until E5 runs them on this PC (E3A-08, I-D8). My probe covers the stdlib primitives only, not the nodes.
- BL-I9-5 (the default mode of `_keep_previous_manifest`), BL-I9-6 (device stems, no length cap; an `OSError` past the handlers as on base, E2-3) and BL-I9-7 (`reports/` unguarded) are outside the slice.
- The I-3 text is the same for a post-claim refusal as for a refused home (E3 S-1: I-3 does not change), so a swapped file link reports "the flows folder is a link".

## Evidence checklist

- [x] Diff read in full: `flow_persistence_service.py` (`:40-95`, `:981-1229`, `:1663-1720`), `flow_execution_service.py` (`:1744-1752`, `:1843-1850`, `:1969-2008`), `app.py` (`:4013-4028`, `:4466-4533`, `:4576-4592`), `flow_screens.py:1-45`, ch18:110-113, DOSSIER:754-755, both new test files (431 and 656 lines), the three edited test files.
- [x] Correctness pass: every error path of `_create_new_json` (check 2), descriptor leaks (check 3, CR-07), Windows vs POSIX (check 4, probed), the cut (check 5, CR-01), the confirm mode (check 6), callers (check 7).
- [x] Simplicity pass: one helper for both saves, as ruled; the triple repeat is CR-08.
- [x] Reuse checked against the shared guard, `_is_reparse_point`, `place_into_workarea` and `_placed_name_candidates` (check 11).
- [x] Tests reviewed for intent: oracles, base RED, discriminating negatives, the M14 correction, and the gaps CR-02, CR-03, CR-04, CR-09.
- [x] Verdict explicit: PASS-WITH-NOTES. No HIGH or MAJOR to resolve.

## §4b Independent review cell

`code-reviewer · PASS-WITH-NOTES · no HIGH (none to resolve); open as recommendations, all MINOR: CR-01 cut name can equal another file's stem (US-I9-2 vs R-FLOW-FILE.13/2, needs a ruling); CR-02 samestat clause has no node; CR-03 claim error arms have no node; CR-04 raw os.symlink, no named skip on Windows; CR-05 handler and save docstrings (Summary, Raises OSError, Used by); CR-06 leftover single-edge claims in flow_screens.py; CR-07 part of check (d) outside try; CR-08 triple "next candidate" step; CR-09 /8/1 and /14/5 assert less than their row; CR-10 BL-I9-4 omits the empty-folder residual`
