# Kimi brief — common rules for every batch-100 increment

You are the IMPLEMENTER (`software-dev` role, `C:\Users\jjgh8\.claude\skills\dev-flow\agents\software-dev.md`) for one increment of dev-flow batch `2026-10-26-batch-100` of `s19_app` ("Load + projects"). Model: Kimi K2.8. An orchestrator plans the work and gates each increment. An independent reviewer checks your work afterwards. You never review your own work, and you never decide a requirement.

## What to read for your increment
- Your increment brief, `kimi/BRIEF-inc-<N>.md`.
- The design proposal section for your increment, `design/design-proposal-b100.md` §5.<k>. It gives the SOURCE files, the design characteristics, the interfaces, the enablers, and the test plus mutation table.
- The LLRs and ATs it names in `01-requirements.md`. The contract is about 240k characters, so read by `grep -n "LLR-163\."` and line ranges, never the whole file.
- `docs/architecture.md` §11, the B100-I rows your increment freezes or consumes.

## Where you work
- An isolated git worktree is your current directory. It is a detached checkout of `main` at the commit your increment brief names.
- Interpreter: `C:\Users\jjgh8\anaconda3\envs\s19env\python.exe` (Python 3.11, Textual 8.2.8).
- In every shell call, set `PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8` and `PYTHONPATH=<this worktree>`, and **unset `NO_COLOR`** (`env -u NO_COLOR …`). Your shell exports `NO_COLOR=1`, and that breaks Textual colour and snapshot tests.
- Before the first test run, prove that you import THIS worktree: `python -c "import s19_app; print(s19_app.__file__)"` must print a path inside the worktree. Paste that line into the packet.

## Hard rules
- Change only the SOURCE files your brief names: max 4 SOURCE files. Tests and fixtures are not capped. If you need another source file, STOP and write why in `HANDOFF.md`; do not edit it.
- Source files are CRLF. Preserve `\r\n` in any file you edit. Check with `python -c "print(open(p,'rb').read().count(b'\r\n'))"` before and after.
- Do **not** run `git commit`, `git push`, `git stash`, `git reset`, `git checkout -- <file>` or a rebase. Leave your changes in the working tree; the orchestrator commits.
- Never write the operator's name anywhere. Use `username_subject` if a person placeholder is ever needed.
- The repo is public. Describe region extraction only as memory-region extraction, and never attribute a security purpose to any feature in code, tests or records. A SHA-256 is a "file digest".
- Never touch `prototypes/`, and never edit `prototypes/cambios_10_12_2026/help_sections.md`.
- English in code, UI strings, tests and records.
- Match the surrounding code: comment density, docstring style (the repo uses `Summary:` / `Args:` / `Returns:` docstrings on public functions), naming, idiom.
- Token economy: read large files by line range or grep. `app.py` is over 13 000 lines. Stop at about 200k context: write `HANDOFF.md` in the worktree root with what is done and what is left, then end.
- **Test ids:** use exactly the `TC-B100-NN` / `AT-B100-NN` ids the contract assigns to your LLRs. Never invent a number. An extra arm is a sub-node (`test_tc_b100_01_<arm>`). If you truly need a new TC, write `TC-B100-NEW-<n>` in the packet, and the orchestrator assigns the number.
- **New test module:** bump `EXPECTED_SCANNED_TEST_FILES` in `tests/test_id_registry.py` by the measured count, with a one-line comment, and run the registry tests.
- **Black-box ATs:**
  - Never call `_handle_load_project`, `_handle_save_dialog`, `load_from_path`, `action_show_screen` or `Button.press()`, and never read internal attributes, in an AT node.
  - Use the rail keys, `pilot.click("#id")`, `pilot.press(...)`, the painted status (`#log_line_4`, `#status_text`) and files on disk.
  - The one declared exception is `SaveProjectScreen.plan`, a read-only accessor, for AT-B100-21 only.
  - ATs run at 118×54 and 220×60 (enabler E-size in the proposal), with notifications on.
- **Windows-only arms** (junctions, links, case-insensitive names): create junctions with `_winapi.CreateJunction`. On other platforms these arms `pytest.skip` with a named reason, and the packet counts them (PDR C-QA-6).
- **Byte oracles:** every byte comparison uses `tests/support/independent_reader.py` or a fixture manifest, never `s19_app`'s own loader.

## What "done" means for your increment
1. **RED first.** Run every new or re-pinned TC/AT against the unmodified worktree and keep the failing transcript. A test that passes before the fix is vacuous: fix the test, not the oracle. Transcripts go under `.dev-flow/2026-10-26-batch-100/evidence/inc-<N>/` (`red-*.txt`, then `green-*.txt`), each with a first line naming the command and the tree.
2. **Implement** the smallest change that makes the requirement true.
3. **Mutation check (C-40).** For each LLR, apply the mutation the proposal's table declares and show the TC going RED (`mut-<LLR>.txt`). Then revert the mutation. Never leave a mutant in place.
4. **Reverse census (trigger B1).** For every symbol you change, run `grep -rln <symbol> tests/ --include=*.py` and re-validate every assertion found. The contract's §5.4 lists the known ones. Re-pin a test ONLY when your requirement changes that behaviour, and record each re-pin as `test::node — old → new — requirement`.
5. **Whole-tree guards (batch-99 lesson, mandatory at every increment).** Run the six guard files in one command and save the transcript as `evidence/inc-<N>/guards.txt`:
   `python -m pytest -q -p no:cacheprovider tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py tests/test_batch91_registry_hygiene.py tests/test_address_census.py tests/test_engine_unchanged.py`
   then the census sweep (PDR C-QA-3), saved as `evidence/inc-<N>/guards-census.txt`:
   `python -m pytest -q -p no:cacheprovider -k census tests`
   A snapshot cell that your increment changes on purpose is regenerated ONLY when your brief says so, and with a text diff proving that only the intended rows changed. Any other guard failure: STOP and write it in `HANDOFF.md`.
6. **Run every test file your change touches** plus the files the reverse census found, and save the transcripts. Do NOT run the full suite; the orchestrator runs it at the checkpoints.
7. **Fill the increment packet** `.dev-flow/2026-10-26-batch-100/03-increments/increment-<NNN>.md`. Copy the template from `increment-001.md` if your packet does not exist yet. Use `.dev-flow/2026-10-25-batch-99/03-increments/increment-007.md` as a filled example.
   - §2: the file table, with `File` · `Kind` (one of `source` · `test` · `doc` · `config` · `generated` · `fixture`) · `Traces to`. Every source/test/fixture row names an existing LLR or HLR id, and every file you touch has a row (validator V59).
   - §4: the RED counterfactual, the Instrument RED-proof, the Evidence files table (full repo path plus SHA-256 of each transcript), the Reverse census and the test ledger.
   - Leave §4b (Independent review) as `pending — orchestrator`.
   - Every `N passed` figure you write must be present in a transcript cited in the Evidence files table (V56).
8. **End** by writing `__KIMI_UNIT_DONE__` as a line of `HANDOFF.md`, followed by a 5-line summary: files changed, tests added, RED/GREEN counts, mutations run, open questions.
