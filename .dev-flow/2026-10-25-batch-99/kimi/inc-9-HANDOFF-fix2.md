# HANDOFF — batch-99 Increment 9 · review round 2 fix (fix2)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc9` (branch b99-inc9). Not committed, per brief.

## What the brief asked (BRIEF-inc-9-fix2.md)

1. **N1 [MEDIUM]** — HEX file with CR-only line endings loaded 0 bytes + false
   `HEX-NO-EOF`. Fix: iterate `data.splitlines()`; add TC-B99-09 sub-arms
   (CR/LF/CRLF parity; CR-only + binary tail → one `HEX-AFTER-EOF`);
   mutation: `\n`-only split → CR-only arm RED.
2. **LOW** — AT-B99-03 picked the project row via `listing.index = …`; use keys
   or a click.
3. Run `tests/test_b99_truncation.py`, every HEX-loader test
   (`grep -rln "IntelHexFile\|hexfile" tests/` → 15 files),
   `tests/test_address_census.py`, `tests/test_id_registry.py`, AT-B99-03 ×8.
   Update packet; finish with this file.

## Worktree proof

`python -c "import s19_app; print(s19_app.__file__)"` →
`C:\Users\jjgh8\Github\s19_app-b99-inc9\s19_app\__init__.py` (this worktree).

## What was done

### N1 — `s19_app/hexfile.py` (only SOURCE file touched)

`IntelHexFile._load` now reads the file bytes once
(`data = handle.read()`) and iterates `data.splitlines(), 1` instead of
iterating the binary handle (`\n`-only splitting). Bytes `splitlines` splits
on `\r`, `\n` and `\r\n` alike. The round-1 rule is untouched: lines are
decoded strictly only up to and including the first EOF record; after it,
non-empty lines are counted by stripping the BYTES and are never decoded.
Docstring updated to say so. CRLF preserved (254 `\r\n` lines before/after;
file was pure CRLF).

### New TC-B99-09 sub-arms (`tests/test_b99_truncation.py`)

- `test_tc_b99_09_line_endings_cr_lf_crlf` — same HEX content saved CR-only,
  LF-only, CRLF: same 272-byte image (independent-reader oracle on the corpus
  original), ZERO notices per encoding.
- `test_tc_b99_09_cr_only_binary_tail_after_eof` — CR-only HEX + 4096 bytes of
  `0xFF` padding: exactly ONE `HEX-AFTER-EOF: 1 record(s)…` notice, oracle image.

### LOW — AT-B99-03 flow arm (`tests/test_b99_truncation.py`)

`test_at_b99_03_pilot_flow_source_fails` now picks the project row with a
CLICK on the painted `#project_list ListItem` (found by its rendered label —
the flow-picker idiom used later in the same test). The direct
`listing.index` assignment and the `ListView` local import are gone. Docstring
updated.

### Registry guard (`tests/test_id_registry.py`)

`EXPECTED_SCANNED_TEST_FILES` 199 → 205, measured by
`scanned_test_files()` and independently by
`shopt -s globstar; ls tests/*.py tests/**/*.py | sort -u | wc -l` (both 205).
The guard was RED before the bump (205 scanned vs 199 declared — it caught
batch-99 Inc-1/2's five unbumped modules plus this increment's
`test_b99_truncation.py`). One comment block above the constant records this.

## RED / GREEN / mutation

- RED first: both new arms fail on the pre-fix tree (`red-fix2.txt`,
  2 failed) — CR-only file read as ONE 627-char line → length issue +
  false `HEX-NO-EOF`, exactly the review's observation. (The LF/CRLF variants
  inside the parity arm pass there — only CR-only was broken.)
- GREEN: `tests/test_b99_truncation.py` 25 passed (`green-fix2-full.txt`;
  23 → 25 nodes).
- Mutation (C-40): `data.splitlines()` → `data.split(b"\n")` → KILLED —
  both CR-only arms RED, the other 5 TC-B99-09 nodes GREEN (`mut-N1.txt`);
  reverted, fixed-tree hexfile.py digest `a51ec5d9…`, CRLF intact.
- HEX-loader census (15 grep files): 522 passed, 1 xfailed, 6 failed — all 6
  declared: 4 engine/test-file guards vs main (uncommitted increment changes;
  guard working as designed), `test_at031b` fails identically on pristine main
  (pre-existing, HEX-loader-independent), `test_at068b` green in isolation
  (crowded-batch flake) (`green-fix2-hexloaders.txt`).
- `test_address_census.py` + `test_id_registry.py`: 36 passed
  (`green-fix2-census-registry.txt`).
- AT-B99-03 stability: 8/8 runs × 3 passed (`stability-fix2-at03.txt`).

## Baseline hashes (pre-mutation digests)

`fix2-baseline-hashes.txt`: hexfile.py `c26a7540…`, test file `11bde2cd…`
(pre-fix-2 forms; hexfile.py's fixed-tree digest is `a51ec5d9…`).

## Packet

`.dev-flow/2026-10-25-batch-99/03-increments/increment-009.md` — new
"Review round 2 fixes (code-reviewer N1 + LOW)" section with evidence table.

## Source-file budget

4/4 unchanged this round: only `s19_app/hexfile.py` touched (plus 2 test
files, uncapped). No commit made; changes left in the working tree.

## Open questions

- None for the findings themselves. Note for the orchestrator: the registry
  bump to 205 folds five batch-99 Inc-1/2 modules that were committed on this
  base without a bound bump; other lanes' bumps may collide at merge.
- `test_engine_unchanged` / `test_tui_directionb` tc031/032 fail loud in the
  census (expected — the engine crossing NAMED in LLR-154.1/154.2 plus the
  round-1 re-pin; declared since round 1).
- `test_at031b_two_saves_are_distinct_no_clobber` fails identically on the
  pristine `main` checkout — pre-existing on main, unrelated to this
  increment (it never loads a HEX file); routed to the orchestrator.
- `test_at068b_per_entry_json_popup_edits_only_selected_entry` failed only in
  the crowded census and passed in isolation — same crowded-batch flake class
  declared in round 1.

__KIMI_UNIT_DONE__
Files changed: s19_app/hexfile.py (SOURCE); tests/test_b99_truncation.py, tests/test_id_registry.py (tests).
Tests added: 2 TC-B99-09 arms (line_endings_cr_lf_crlf, cr_only_binary_tail_after_eof); AT-B99-03 flow arm re-picked by click.
RED/GREEN: RED 2 failed pre-fix; GREEN 25 passed (truncation), 36 passed (census+registry), HEX-loader census 522 passed + 6 declared failures; AT-B99-03 8/8 green.
Mutations: 1 (splitlines → split(b"\n")) KILLED, reverted by hash a51ec5d9….
Open questions: registry bump 199→205 absorbs five unbumped batch-99 Inc-1/2 modules; merge collision with other lanes possible.
