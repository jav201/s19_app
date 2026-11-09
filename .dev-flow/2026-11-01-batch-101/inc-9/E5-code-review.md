# Inc 9 — E5 code review

Batch 2026-11-01-batch-101, increment 9. Reviewer: code-reviewer (independent of the implementers, the testers and the integrator). Scope: `git diff e07fb00 -- s19_app docs` and `git diff e07fb00 -- tests` at head `b204c7d` of branch `b101-inc9` (worktree `<HOME>/Github/s19_app-b101-inc9`). That is 4 source files (`flow_persistence_service.py` +268, `flow_execution_service.py`, `app.py`, and `flow_screens.py`, which changes its module docstring only), `docs/user-guide/ch18-flow-execution.md`, `docs/user-guide/DOSSIER.md`, 2 new test files (`tests/test_b101_flow_saves.py`, `tests/test_b101_flow_names_ui.py`) and 3 edited test files. I read all of it in full against `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc9.md` (I-1 … I-7), `E1-rulings.md`, `E3-rulings.md` (rounds 1 and 2), `E4-rulings.md` (E4-R1 … E4-R3), `E4-integration-notes.md` and the implementer and tester notes. I read the callers and helpers the change relies on: `workspace._guarded_destination`, `_is_reparse_point`, `contained_in_workarea`, `place_into_workarea`, `_placed_name_candidates`, `sanitize_project_name`, the loader name rules (`flow_persistence_service.py:419`, `:1495`), every reader of the chain-run mode, and `tests/b97_fixtures.make_junction` / `write_flow`.

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

## Re-review of the corrective (code + security)

Reviewer: code-reviewer, the author of CR-01 … CR-10; I wrote none of the corrective. Scope: `git diff b204c7d 3f8b9e9 -- s19_app tests`, plus the records the commit changed: `01-requirements.md`, `02-test-cases.md`, `E1-rulings.md`, `E3-rulings.md`, `E4-rulings.md` and `codewire/graph-inc9.md`. I read them against `E5-rulings.md`, `E5-corrective-notes.md`, `E5-security.md`, `E5-coverage-audit.md`, the transcripts `e5c-01` … `e5c-07` and `win-02`. Head `d6f1801`; `d6f1801` adds evidence only, so `s19_app/`, `tests/` and `docs/` equal `3f8b9e9` (`git diff --quiet`), and the working tree is clean for both. Lens: code, and security on the changed items only. Severity uses the flow scale: LOW = MINOR, INFO = note.

I ran nothing that imports `s19_app`. Tree check: a scratch index (`read-tree e07fb00` + `git diff --binary e07fb00 3f8b9e9 -- s19_app tests docs README.md | git apply --cached`) gives **`608f5e91…`**, the tree that e5c-02, e5c-03 and e5c-07 ran. Windows: two stdlib-only probes under `-I`, with files only in my session scratchpad (removed afterwards), `LOCALAPPDATA` pointed at the scratchpad and no clipboard, on Python 3.12.7. Probe 1 replays /14/9's swap, close and re-point sequence and the cleanup's two clauses. Probe 2 checks the `os.readlink` prefix that `_link_points_at` strips.

### Verdict

**PASS-WITH-NOTES.** Every ruling is met as ruled, and there is no HIGH or MEDIUM finding.
- **Code:** I found no new defect in `_create_new_json` or `_unlink_own_claim`: every error path closes the descriptor before any unlink, and every cleanup unlink passes the ownership rule.
- **Mutants:** each new node fails under its named mutant on the final tree.
- **Census:** the TC-B99-13 allow-list move is exact.
- **The corrective's own calls:** E-1 … E-7 are sound.
- **Four notes, none blocking:**
  - RR-1 (records): the empty-folder residual now understates what is left.
  - RR-2 (carried, volume): the new one-link clause widens the false-refusal surface on unprobed volumes.
  - RR-3 (test): /14/9 does not assert its own premise.
  - RR-4 (INFO, records): `02-test-cases.md` does not cite `win-02` yet.

### Rulings, checked on the diff

| Ruling | Met? | Evidence (file:line on `3f8b9e9`) | State |
|---|---|---|---|
| CR-02 | yes | `/14/10` `[flow, set]` (S:662): a planted regular file, so only `samestat` (P:1174) can refuse. M22 → both ids `DID NOT RAISE` (e5c-02). The planted file is neither written nor removed. | executed (cited) · approved |
| CR-03 + QA-4 | yes, as ruled (flow only) | `/14/8[render, write, lstat, taken-by-folder]` (S:561). Each mutant fails only its own arm: M26 (render after the claim), M27 (write-arm cleanup dropped), M28 (`except OSError` narrowed), M29 (re-raise every non-`FileExistsError`). The `lstat` arm asserts the sentinel `state["failed"]`, so it cannot pass vacuously. `WorkareaContainmentError` is a `ValueError`, so the write arm's `pytest.raises(OSError)` plus its `errno` check discriminates. | executed (cited) · approved |
| CR-04 (+ QA-6) | yes | `_symlink_or_skip` (S:87) uses the house text. `_require_symlinks` (S:97) runs before any wrapper is patched, in `_windows_follow` (S:151) and `_swap_home_for_link` (S:160). `_repoint_home_at_close` (S:187) is used only after `_swap_home_for_link` has probed. `_link_file` (S:365) uses the skip. U makes links only through `make_junction` (U:130). The probe's dangling file link needs the same Windows privilege as a directory link (E-5). | executed (read) · approved |
| CR-05 | yes | `_create_new_json`, `save_flow_json` and `save_chain_set` gain `Raises: OSError`. `save_flow_json` Used by (P:1270). `save_chain_set` gains Data Flow and Dependencies (P:1769-1785). `run_chain_set` Used by names `on_flow_execution_panel_external_step_confirmed` (`flow_execution_service.py:2006`; the handler is at `app.py:4448`). Both handler Summaries name the refusal (`app.py:4000-4002`, `:4555-4558`). | executed (read, grep) · approved |
| CR-06 | yes | `flow_screens.py:44`, `:1412-1416`, `:3077-3078`, `:3206`. A grep for `declared R8`, `R8 declared`, `never imports the execution`, `single edge` and `declared edge` finds nothing. The new `Uses` entry matches `fps.*` at `:827`, `:2241`, `:2273`, `:2279`. | executed (grep) · approved |
| CR-07 + SE5-2 | yes | All reads of the check sit in one `try` (P:1168-1179): `fstat`, `lstat`, the reparse test and `realpath`. `_unlink_own_claim` (P:985-1035) unlinks only when `claim` is not `None`, `samestat(claim, lstat(candidate))` holds and `realpath(candidate).parent == resolved_home`. It is called on the refusal path (P:1182, after the close at P:1181) and on the write failure (P:1202, after the `with` has closed the handle). SE5-2's case is `/14/9` (S:635); M24 → victim deleted → RED (e5c-02). | executed (read; cited) · approved |
| SE5-1 (nlink half) | yes | `st.st_nlink == 1` (P:1173). `/14/11` `[flow, set]` (S:686); M23 → `DID NOT RAISE` (e5c-02). BL-I9-10 is recorded (`E1-rulings.md:74`). | executed (cited) · approved |
| SE5-3 + CR-10 | yes, except RR-1 | The docstring (P:1102-1114), BL-I9-4 (`E1-rulings.md:69`), the R-FLOW-FILE.14 note (`01-requirements.md:56`), the annotation on E3 S-1 and the graph entity now state the residual under a concurrent writer: an empty file, content only under a double swap (BL-I9-10), never an overwrite, and no junction followed at the free name. Each clause matches the code, except the parent-swap clause (RR-1). | executed (read) · RR-1 |
| CR-08 | yes | One walk (P:1126-1130): `<clean>.json`, then `_2`, `_3`, …, with `next(names)` per pass and no other change. The numbering nodes are GREEN (e5c-07) and `/14/8[taken-by-folder]` → `z_2`. | executed (read; cited) · approved |
| CR-09, QA-2, QA-8 | yes (with E-1) | `/8/1` checks the link unchanged (S:450). `/14/1`, `/14/2`, `/8/1` and `/8/2` check the link through `_link_points_at`. `/14/2` and `/8/2` also check the parent. `re.fullmatch` replaces `startswith`. `20/2` asserts that no line reads `- **Mode:** sequential`, placed before the positive line (U:342); M30 fails there (e5c-03). M31 fails the new link lines (e5c-02). | executed (cited) · approved |
| QA-3 | yes | `/14/7` `[flow, set]` (S:518) links to a sibling inside the home, so the real-parent clause passes and only the link clauses can refuse. M14b (S_ISREG, `samestat` and the reparse test dropped) → `DID NOT RAISE` (e5c-02). The form of M14b is E-4's, the closest one to QA-3's once `owned` no longer exists. | executed (cited) · approved |
| CR-04 named skips on Windows | run, path not taken | `win-02` (head `3f8b9e98`): 46 passed, 2 skipped (the POSIX-mode skip of /14/6). This account holds the symlink privilege, so no named skip fired and the skip path itself is unexercised. That is expected. | executed (cited) |

### The corrective's own calls

- **E-1 (CR-09 against SE5-2 on /14/5): sound, and I accept the supersession as CR-09's author.**
  - CR-09 asked for an oracle as exact as the code. Its premise, "the code removes the claim", was true only before SE5-2.
  - Under the ruled rule, a claim whose real parent is not the approved home is never unlinked. Folder O holding exactly the empty `z.json` is therefore the exact oracle.
  - M25 (the cleanup's real-parent clause dropped) fails /14/5 alone (e5c-02), so the clause has an isolating node. BL-I9-4 permits the empty file.
- **The extra cases /14/11 (and 8/9) and /14/10 (and 8/8): sound.**
  - "A clause no node can fail is unproven" (the rulings, CR-02) applies to SE5-1's new clause, and the coverage audit's §5 owed P4 a case.
  - Each node isolates one clause:
    - /14/10: the entry is a regular file, `nlink` 1, inside the home and not the same file as the claim, so only `samestat` refuses.
    - /14/11: the entry is the same file as the claim and inside the home, but has 2 links, so only `nlink` refuses.
  - By reading, the cleanup's `samestat` clause on its own is also killed by /14/7 and /14/10: both have a real parent equal to the home and an entry that is not ours, so a cleanup without `samestat` would unlink the link or the planted file. No single-clause mutant was run for it; M24 drops both clauses.
- **E-3 (`_unlink_own_claim` removes the hard-link name in /14/11): safe.**
  - `samestat` with the descriptor of an `O_CREAT|O_EXCL` create can only match a file this call created. On Windows the followed create also creates a new file.
  - So the cleanup can never unlink a name that is a hard link to a file that existed before the save. Removing the name in the home only drops the new empty file's link count to 1.
- **E-5, E-6, E-7: sound.**
  - E-6: e5c-07 runs the gate set in a `--shared` clone whose `main` is `e07fb00`: 297 passed, with the command line printed. The TC-027 failure in e5c-04 is explained by the stale local `main`.

### New-defect search: `_create_new_json` / `_unlink_own_claim`

- **Every error path:**
  - A taken name → next (P:1133); `FileExistsError` → next (P:1149); any other `OSError` → next if the name now exists, else re-raise (P:1152-1157). No descriptor is open yet on any of these.
  - A `render` raise (P:1138) happens before the claim.
  - A failed read in the check → close, cleanup, `WorkareaContainmentError` chained `from failure` (P:1180-1187).
  - A failed check → close, cleanup, raise (P:1188-1192).
  - A failed write → the `with` closes first, and a flush error at the close still closes the raw fd. Then cleanup and re-raise (P:1198-1203).
  - `claim is None` (the `fstat` failed) → nothing unlinked, so the empty claim keeps the name. That is the ruled outcome.
- **Descriptor leaks:** none. After P:1144, every path either closes at P:1181 or hands the fd to `fdopen` at P:1199. The only raise not guarded is `os.close` itself (EIO on NFS), unchanged from the code before the corrective.
- **Windows:**
  - Every cleanup runs after the close, which Windows needs (no `FILE_SHARE_DELETE`).
  - `samestat` across the close and `st_nlink` both hold on NTFS:
    - `win-02` (3.11.15): /14/8[write] removed the claim after the close, /14/11 removed the hard-link name, and /14/10 kept the planted file.
    - Probe 1 (3.12.7): `nlink 1`, and `samestat(fstat, lstat)` is true through a directory link.
  - Both `realpath` sides come from `ntpath.realpath` / `Path.resolve()`, so the real-parent comparison is the one E4-R1 already used.
- **`_link_points_at` (S:105):** the source literal `"\\\\?\\"` is the 4-character `\\?\` at run time (byte dump). Probe 2: Windows `os.readlink` of an absolute file link returns the `\\?\` prefix, and the stripped path compares equal to the target. A target without the prefix (POSIX, or a print name) falls through unchanged. A UNC target would not strip correctly, but no node uses one.
- **Security, on the changed items:**
  - The new nodes create everything under `tmp_path`, including `victim/`, and `_require_symlinks` leaves no entry behind in O.
  - No new writer and no clipboard use.
  - The refusal text is not painted (I-3).

### TC-B99-13 allow-list move: exact

The census (`tests/test_b99_staging.py:2210-2265`) flags `.unlink`, `write_text`, `write_bytes`, `os.replace` and `shutil.copy2`. In the module on `3f8b9e9`, the only such call is `os.unlink(candidate)` at P:1033, inside `_unlink_own_claim`. On `b204c7d` the three calls (`:1103`, `:1121`, `:1139`) were all inside `_create_new_json`. The allow-list now names exactly `{"_unlink_own_claim"}` (Q:2163-2165). Keeping `_create_new_json` in it would allow a future unlink there, so removing it is the stricter and exact form. e5c-07 passes the census.

### Findings

| Id | Severity · tag | Where | Scenario | Fix |
|---|---|---|---|---|
| RR-1 | LOW · records | P:1107-1109 (docstring); `E1-rulings.md:69` (BL-I9-4); `01-requirements.md:56` (R-FLOW-FILE.14 note); `codewire/graph-inc9.md:266`, `:293` | **"An empty `flows/` / `flowsets/` folder" understates the parent-swap residual after SE5-2.** The project folder is swapped for a link to O between the guard (P:1281) and the `mkdir` (P:1282). The `mkdir` creates `O/flows/`, and the claim lands at `O/flows/z.json`. The check refuses it on the real parent, and `_unlink_own_claim` will not unlink it either (its real parent `O/flows` ≠ `resolved_home`). So `O/flows/` keeps an **empty `z.json`**. CR-10's wording was right for the code before SE5-2, which removed the claim. The corrective applied both rulings without reconciling them, the same kind of conflict it settled for /14/5 (E-1). Still no content and never an overwrite. | In the five places, "an empty `flows/` / `flowsets/` folder **holding the empty claim**". No code change. |
| RR-2 | LOW · carried (volume) | P:1173 (`st.st_nlink == 1`); check 4 above | **One more volume-reported property every save depends on.** A filesystem that reports `st_nlink` ≠ 1 for a newly created file would refuse every save with the I-3 status. That is a false refusal, not a leak. Only local NTFS (`win-02`, probe 1) and Linux (e5c-07) are evidenced. Network, virtual and cloud-sync volumes are not probed, and the work area is `<cwd>/.s19tool/workarea`, so it can sit on any of them. | No code change. Add `st_nlink` to check 4's carry: E5's or the batch-end Windows run does one plain save on the operator's real volume type. |
| RR-3 | LOW · test strength | `tests/test_b101_flow_saves.py:635-658`; helper `:175-189` | **/14/9 never asserts that the re-point ran.** If the `os.close` wrapper does not fire (say a future close path, or `home.is_symlink()` reading false on some platform), the node still passes: the real-parent clause leaves the claim in O and V is untouched. /14/9 then silently becomes /14/5 and SE5-2's case goes unexercised. On Linux, M24's failure (`FileNotFoundError` on `victim/z.json`, e5c-02) shows the re-point fires. On Windows, `win-02`'s PASS alone does not; my stdlib replay (probe 1, 3.12.7) shows that it does on this PC. | One line after the `raises` block: `assert Path(os.path.realpath(home)) == victim.resolve()` (or have the helper return its `state` and assert `state["done"]`). Show it RED with the wrapper disabled. |
| RR-4 | INFO · records | `02-test-cases.md` Windows column (rows /14/7 … /11, 8/6 … /9, and the 32 rows citing `win-01, b204c7d`) | `win-02` (head `3f8b9e98`, the same `s19_app`/`tests` as `d6f1801`, with a command line) ran all 46 nodes: 46 passed, 2 skipped by design. The 9 new rows still read `windows: not_run (… owed)`. | Re-cite the 34 non-skipped rows as `verified (win-02, 3f8b9e9)`. Executor: the orchestrator. |

### Carried, not findings

- The `fstat` and `realpath` failure arms of the check have no node. Only `lstat` does, which is what the ruling named. A mutant that moves `fstat` out of the `try` would survive. Both reads are improbable failures, and the arm exists to keep the outcome a refusal.
- DeepSeek's M11 … M14 name the old step (d) and must be re-mapped before they are ruled (corrective notes §3). BL-I9-9 and BL-I9-10 are recorded. The `os.close` EIO path is unchanged.

### Evidence states

- Rulings CR-02 … CR-09, SE5-1, SE5-2, SE5-3, QA-2, QA-3, QA-4, CR-04: `executed` by reading, with the cited runs e5c-02, e5c-03, e5c-07 and win-02 (not mine); `approved`, except SE5-3's parent-swap clause (RR-1).
- Tree `608f5e91` = `3f8b9e9` (scratch index): `executed`.
- Windows probes 1 and 2 (stdlib only): `executed`.
- The census move: `executed` (read and grep).
- RR-1: `executed` (read). RR-2: `not-run` (no non-NTFS volume probed). RR-3: `executed` (read; probe 1). RR-4: `executed` (read). The fixes are `planned`.

### Evidence checklist

- [x] Diff read in full: `git diff b204c7d 3f8b9e9 -- s19_app tests` (`flow_persistence_service.py`, the 3 test files, `app.py`, `flow_screens.py`, `flow_execution_service.py`) and the changed records.
- [x] Correctness pass: every error path, descriptor ownership, close before unlink, `claim is None`, the parent-swap residual (RR-1).
- [x] Simplicity pass: one walk (CR-08); one cleanup helper shared by two call sites; no speculative parameters.
- [x] Reuse: `_is_reparse_point` and `_guarded_destination` are reused as they are; the skip text follows the house pattern of `test_b100_load_dialog.py:385`.
- [x] Tests reviewed for intent: one isolating mutant per clause, sentinels, discriminating negatives; RR-3 is the gap.
- [x] Verdict explicit: PASS-WITH-NOTES. No HIGH is open.

### §4b Independent review cell (re-review)

`code-reviewer · PASS-WITH-NOTES · no HIGH (none to resolve); the corrective 3f8b9e9 meets every E5 ruling as ruled (CR-02…CR-09, SE5-1 nlink, SE5-2/CR-07 ownership rule, SE5-3, QA-2/3/4, CR-04), E-1 settlement sound, census move exact, mutants M14b/M22–M31 each RED on target; open as recommendations: RR-1 LOW parent-swap residual now leaves the empty claim inside the outside flows/ (records say "empty folder"); RR-2 LOW nlink clause widens the unprobed-volume false-refusal carry; RR-3 LOW /14/9 does not assert its re-point ran; RR-4 INFO 02-test-cases Windows column not yet re-cited to win-02`
