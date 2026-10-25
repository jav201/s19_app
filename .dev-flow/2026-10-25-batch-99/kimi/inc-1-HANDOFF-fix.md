# HANDOFF — batch-99 Increment 1 · review round 1 fixes (F1–F5)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc1` (branch `b99-wip`, base commit `e4c4324`).
No commits made — all changes are in the working tree for the orchestrator.
Interpreter: `C:\Users\jjgh8\anaconda3\envs\s19env\python.exe`; worktree import proven:
`s19_app.__file__` = `C:\Users\jjgh8\Github\s19_app-b99-inc1\s19_app\__init__.py`.

## What was done (exactly per BRIEF-inc-1-fix.md)

- **F1 [HIGH]** — `tests/fixtures/synth/generate.py`: `LINEAR_MUL_2` declares
  `BYTE_ORDER MSB_LAST` (ASAM token) instead of the non-ASAM `LSB_FIRST`; the
  manifest `a2l_expect.byte_order` for that symbol is `MSB_LAST`; the symbol
  stays little-endian (`0F 00`) under the `MSB_FIRST` module. Matches amended
  contract LED-2026-10-25-batch-99.4 / LLR-158.1.
- **F2 [MEDIUM]** — both COMPU_TAB blocks re-laid-out on the
  `examples/case_00_public/ASAP2_Demo_V171.a2l:2965` model: name, quoted long
  identifier, conversion type, pair count, pairs, then quoted
  `DEFAULT_VALUE "0"`; stray `"%6.2" ""` Format/Unit pair removed.
- **F3 [MEDIUM]** — `TAB_INTP_SYM` limits `0 62.5` → `-10 100`;
  `TAB_NOINTP_SYM` limits `10 20` → `0 30` (strictly beyond the table ranges).
  No recorded `a2l_expect` value depended on the old limits.
- **F4 [LOW]** — new node `test_tc_b99_04_hex_extents_literal` in
  `tests/test_b99_corpus.py`: hand-written literal `(start, end)` extents for
  all four HEX files from the Intel HEX spec (type-02 wrap + type-04 64 KiB
  boundary included), read with the independent reader.
- **F5 [LOW]** — `SHA256SUMS.txt` rewritten: LF endings, self excluded,
  unchanged files hashed as committed (`git show HEAD:`), the eight fix-round
  files hashed as working-tree bytes (noted explicitly in the packet).
- Corpus regenerated; `generate.py --check` → `checked 16 files` (exit 0).
- GREEN: `tests/test_b99_corpus.py` 5 passed (`green-fix-corpus.txt`);
  `tests/test_address_census.py` 23 passed (`green-fix-address-census.txt`).
- Mutations re-run on the fixed tree: LLR-152.1/152.2/152.3 all KILLED
  (`mut-LLR-152.1/2/3.txt`) + F4 mutation (reader segment wrap broken →
  TC-B99-04 RED, `mut-F4.txt`); every mutant restored by SHA-256.
- Packet `.dev-flow/2026-10-25-batch-99/03-increments/increment-001.md`
  updated: "Review round 1 fixes" subsection (F1–F5), canary text fixed,
  evidence table now 19 artifacts with refreshed digests, ledger `5 = 0−0+5`,
  mutation verdicts/restore digests refreshed. §4b left `pending — orchestrator`.

## Notes for the orchestrator

- One surviving mutant caught in this round: the first re-run of the
  LLR-152.2 mutation dropped `mac.pair` from `generate.py` only and SURVIVED
  (TC-B99-02 reads the committed manifest from disk); the mutation must land
  in `manifest.json`. Documented in the packet's Mutation verdicts.
- The new literal-extents test first failed on my own hand-written
  expectation (unsorted run order); the dict was corrected to address-sorted
  order — the test is not vacuous (also proven by the F4 mutation).
- `01-requirements.md` / `01-requirements-ledger.md` were already modified in
  the working tree before this fix round (orchestrator's contract amendment);
  not touched here.
- CRLF preserved in `generate.py` and `test_b99_corpus.py` (526/526 and
  171/171 CRLF); corpus files stay LF per `.gitattributes`.
- Files changed: `tests/fixtures/synth/generate.py`,
  `tests/fixtures/synth/manifest.json`, `tests/fixtures/synth/synth_a2l.a2l`,
  `tests/test_b99_corpus.py`, packet + 9 evidence files (see `git status`).
- Open questions: none. Next: orchestrator re-review (§4b) and commit.

__KIMI_UNIT_DONE__
Files changed: tests/fixtures/synth/{generate.py,manifest.json,synth_a2l.a2l}, tests/test_b99_corpus.py, increment-001.md + evidence (SHA256SUMS, baseline-hashes, emitted-a2l-pins, 3 mut re-runs, green-fix x2, mut-F4).
Tests added: 1 node (test_tc_b99_04_hex_extents_literal) — corpus file now 5 nodes, 5 passed; test_address_census 23 passed.
RED/GREEN: GREEN 5+23 (green-fix-*.txt); 4 mutations all KILLED (3 C-40 re-runs + F4 seg-wrap), each restored by SHA-256.
Mutations run: timestamp-into-S0, mac.pair drop (manifest.json), S0-payload-into-data, reader segment-wrap break.
Open questions: none — §4b independent review pending orchestrator; no commit made (working tree left for orchestrator).
