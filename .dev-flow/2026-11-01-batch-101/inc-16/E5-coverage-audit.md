# Inc 16 — E5 coverage audit

**Mode: validation (an independent audit of the test-case marks).** The auditor (qa-reviewer, E5) did not write the test cases or the tests. It audits the case table of `02-test-cases.md` against `tests/test_b101_doc_hygiene.py`, the widened node `tests/test_docs_canon.py::test_at285_no_live_cdfx_or_s19tool_console_script_token`, the Inc 14 node `tests/test_b101_help_legend_docs.py::test_r_doc_readme_4_2_linked_documents_exist`, and the transcripts in `.dev-flow/2026-11-01-batch-101/evidence/inc-16/`. The audit is at branch `b101-inc16`, commit `d461d0f`; the worktree is clean apart from `steps.log`, which was not touched. `02-test-cases.md` is not edited here: every change is a proposal.

The Result column uses the record's own words. `verified` means executed and passing, with the executor named; `not_run` means no transcript exists.

## 1. Verdict

- **52 cases audited**: 48 are backed by a test and 4 by an E5 transcript (E5-T).
- **The record is stale.** `02-test-cases.md` still holds its E1 placeholders: Coverage is `gap` on 51 cases and `partial` on 1, and Result is `not_run` on all 52. E4 did not update it. On the evidence, 48 cases should read `verified` (int-06), and 47 of them `covered`. These are bookkeeping changes, not judgment changes.
- **Judgment changes affect 5 of 52 cases (9.6 %). Three of them change a full/partial or coverage mark (5.8 %):**
  - README.4/4: the N test drops from full to partial, and coverage rises from partial to covered.
  - REF.5/1: the A node drops from full to partial, and coverage becomes partial.
  - ARCH.1/2: coverage becomes `conflict`.
  - Two cases change only their case text: DEV.1/1 and ARCHIVE.2/2.
- **Gaps:**
  - ARCH.1/2 cannot reach its expected result. V8 prints a root NOTICE for `setup.py`, so the expected "SKIP … no orphan files" line can never appear, at base or at HEAD.
  - The verdict of ARCHIVE.2/2 depends on an id grammar the case does not state.
  - The 4 E5-T cases have no transcript. The auditor's inspections show that ARCHIVE.1/2 and ARCHIVE.2/1 hold at `d461d0f`.
- **Negative controls:**
  - Only 3 of 32 rows are exercised by a cited RED on the integrated tree: DEV.2, DEV.3 and DEV.9 (int-04 M-1, M-2, M-3, M-5). The other 29 are **pending mutants**.
  - Four cases have no behavioural RED of their own in any transcript: REF.2/1, ARCH.1/1, the clauses specific to ARCH.5/2, and ARCHIVE.4/1. For these, the mutant battery is the only proof that the test can fail.

## 2. Evidence and executors

| Transcript | Executor | Tree | What it shows |
|---|---|---|---|
| `red-01-tester-base.txt` | E4 tester (Sonnet), LAN Linux host 2 | base `c2cba35` plus the two test files (the tester's version, before integration fixes I-1 and I-6) | §A: 38 RED, 7 PASS. §B: base counts with the retired folder excluded. §C: derived tree. §D: 68 synthetic cases OK; 14 instrument-mutant kills, 0 survivors (summary only, no line per mutant). §E: ARCHIVE.4 scanner probe. |
| `int-01.txt` | E4 integrator, LAN Linux host 2 | staged index tree `1d1a365` (77 paths) | 6 files, 156 passed |
| `int-04.txt` | E4 integrator | `1d1a365` | 44 collected nodes in the new file and 2 in `test_docs_canon.py`. Mutants M-1 … M-5 all RED. |
| `int-06.txt` | E4 integrator | final staged index tree `52f12b19` (83 paths) | 8 files, including all three audited test files: **228 passed**, with no failed, skipped or deselected test |

- **How int-06 relates to the commit.** `git diff --name-only c2cba35 d461d0f` lists 84 paths: int-06's 83 plus `int-06.txt`. That matches the integration notes, which say only that record and its notes row changed after int-06. Neither changed file is read by a guard of these cases. The remote tree ids `52f12b19` and `1d1a365` are not in the local object store, so the match rests on the path count and the notes, not on a hash.
- **How a per-node pass is inferred.** int-06 prints `-q` output only. A per-node pass is inferred from three facts: 0 failed, 0 skipped and 0 deselected; the node counts int-04 lists; and the absence of any `pytest.mark` or `pytestmark` in the three audited files.
- **Appendix A** holds inspections by the auditor. They are read-only git and text parsing on Windows: nothing imported `s19_app` and no pytest ran.

## 3. Per-case audit

N = `tests/test_b101_doc_hygiene.py::<the case's test>`; A = the widened AT-285 node; G14 = Inc 14's `test_r_doc_readme_4_2_linked_documents_exist`. Arrows show record → audit; `=` means unchanged. "Pending" in the last column means pending mutants (E5-mutants.md), keyed by requirement in §5.

### US-DOC-HYG-1 — references

| Case | Asserts the expected result? | Mark | Coverage | Result (evidence) | RED on base (red-01) | Negative control |
|---|---|---|---|---|---|---|
| REF.1/1 | yes | full = | gap → covered | not_run → verified (int-06) | RED: 33 = 22 + 11 inside the retired folder (tester F-1) | REF.1 pending |
| REF.1/2 | yes, 4/4 | full = | gap → covered | → verified (int-06) | PASS (instrument) | instrument: §D aggregate; REF.1 pending |
| REF.2/1 | yes; also guards `checked > 100` | full = | gap → covered | → verified (int-06) | RED **only through the retired folder**; PASS on the derived tree (a standing property) | REF.2 pending; **the only RED on the real corpus** (F-1) |
| REF.2/2 | yes | full = | gap → covered | → verified (int-06) | RED (5 links) | REF.2 pending |
| REF.3/1 | yes | full = | gap → covered | → verified (int-06) | RED | REF.3 pending |
| REF.3/2 | yes; the plain words pass | full = | gap → covered | → verified (int-06) | RED (11 + 1) | REF.3 pending |
| REF.3/3 | yes; also catches each exempt line once its exemption is off | full = | gap → covered | → verified (int-06) | PASS (instrument) | §D aggregate |
| REF.4/1 | yes | full = | gap → covered | → verified (int-06) | RED | REF.4 pending |
| REF.4/2 | yes | full = | gap → covered | → verified (int-06) | PASS (instrument) | §D aggregate |
| REF.5/1 | **partly**: a whole line is excused when any shape matches, but CTX-DOCHYG defines five shapes per occurrence (C-3) | A full → **partial** | gap → **partial** | → verified (int-06) | RED (7 lines) | REF.5: the control's text is an instrument line of the node (judged 1 on every GREEN run); the file mutant is pending |
| REF.5/2 | yes: 5/5, plus 4 CDFX control lines | full = | gap → covered | → verified (int-06) | the instrument block passed on base; the node turned RED at the scan (`:172`) | — |
| REF.6/1 | yes: only a removal mark excuses CDFX (tester F-2) | full = | gap → covered | → verified (int-06) | RED (27 lines) | REF.6 pending |
| README.4/4 | N asserts 2 of the 3 clauses (0 diagrams row, 1 architecture row); G14 asserts the third (every linked file exists) | N full → **partial**; G14 partial = | partial → **covered** (N and G14 together) | → verified (int-06 runs both files) | N RED; G14 is not in red-01 | README.4 pending |

### US-DOC-HYG-2 — developer documents

| Case | Asserts the expected result? | Mark | Coverage | Result (evidence) | RED on base (red-01) | Negative control |
|---|---|---|---|---|---|---|
| DEV.1/1 | yes, as the requirement states it; the case's second clause is broader than both the test and the requirement (C-6) | full = | gap → covered | → verified (int-06) | RED; the message lists `s19tool` | DEV.1 pending (the base RED names the control's token) |
| DEV.2/1 | yes (form corrected at I-1) | full = | gap → covered | → verified (int-06) | RED (earlier test; the corrected test is RED under M-1 and M-2) | **exercised**: int-04 M-1, M-2 |
| DEV.3/1 | yes | full = | gap → covered | → verified (int-06) | RED | **exercised**: int-04 M-3 |
| DEV.4/1 | yes | full = | gap → covered | → verified (int-06) | RED (names `CLAUDE.md`) | DEV.4 pending (the base RED names the file) |
| DEV.4/2 | yes; the bullet is found by renderer function names (tester F-7) | full = | gap → covered | → verified (int-06) | RED on the first clause; the bullet clause was never RED (F-4) | DEV.4 pending |
| DEV.5/1 | yes; the probe asserts the whole token | full = | gap → covered | → verified (int-06) | RED | DEV.5 pending |
| DEV.6/1 | yes; it joins every paragraph that names `project.toml` | full = | gap → covered | → verified (int-06) | RED on the first clause | DEV.6 pending |
| DEV.7/1 | yes | full = | gap → covered | → verified (int-06) | RED | DEV.7 pending (the base RED names the token) |
| DEV.8/1 | yes | full = | gap → covered | → verified (int-06) | RED (1/3; `markdown-it-py` missing) | DEV.8 pending (the base RED shows the control's effect) |
| DEV.9/1 | yes; entries come from the tree (12 at HEAD, per the M-5 message) | full = | gap → covered | → verified (int-06) | RED (7 of 14) | **exercised**: int-04 M-5 |
| DEV.9/2 | yes | full = | gap → covered | → verified (int-06) | PASS (instrument) | §D aggregate |
| DEV.10/1 | yes | full = | gap → covered | → verified (int-06) | RED on the heading clause; the tally clause was never RED | DEV.10 pending |
| DEV.11/1 | yes; reads the labels from source and asserts exactly 12 | full = | gap → covered | → verified (int-06) | RED (names `Check Editor`) | DEV.11 pending (the base RED names the token) |
| DEV.12/1 | yes | full = | gap → covered | → verified (int-06) | RED (the K clause is shown; the count lines are cut off by `--tb=line`) | DEV.12 pending |
| DEV.12/2 | yes: 8/8, plus a fifth line | full = | gap → covered | → verified (int-06) | PASS (instrument) | §D aggregate |
| DEV.13/1 | yes | full = | gap → covered | → verified (int-06) | RED | DEV.13 pending |
| DEV.14/1 | yes; accepts any bullet that names both operations | full = | gap → covered | → verified (int-06) | RED (names the base bullet) | DEV.14 pending |
| DEV.15/1 | yes; asserts 15, with a deletion control inside the test | full = | gap → covered | → verified (int-06) | RED (names `case_08_release_demo`) | DEV.15 pending (the base RED names the token) |

### US-DOC-HYG-2 — the architecture map

| Case | Asserts the expected result? | Mark | Coverage | Result (evidence) | RED on base (red-01) | Negative control |
|---|---|---|---|---|---|---|
| ARCH.1/1 | yes | full = | gap → covered | → verified (int-06) | PASS (a standing property) | ARCH.1 pending; **the only RED** (F-1) |
| ARCH.1/2 | — (E5-T): the expected SKIP line cannot be reached (C-4) | — | gap → **conflict** | not_run = (static V8 derivation, A.4) | — | n/a |
| ARCH.2/1 | yes | full = | gap → covered | → verified (int-06) | RED (names `prototypes`) | ARCH.2 pending (the base RED names the token) |
| ARCH.3/1 | yes | full = | gap → covered | → verified (int-06) | RED | ARCH.3 pending |
| ARCH.3/2 | yes | full = | gap → covered | → verified (int-06) | RED | ARCH.3 pending |
| ARCH.3/3 | yes | full = | gap → covered | → verified (int-06) | RED | ARCH.3 pending |
| ARCH.4/1 | yes for the case; but the case checks that cells are non-empty, not that the facts are true (F-3) | full = | gap → covered | → verified (int-06) | RED (no sub-module table) | ARCH.4 pending; its cell was never RED |
| ARCH.4/2 | yes; the citation clause is not vacuous (the docstring cites §10, A.5) | full = | gap → covered | → verified (int-06) | RED on the first clause | ARCH.4 pending |
| ARCH.5/1 | yes | full = | gap → covered | → verified (int-06) | RED (6 tables) | ARCH.5 pending |
| ARCH.5/2 | yes | full = | gap → covered | → verified (int-06) | RED **only through the shared one-table precondition**, which is ARCH.5/1's clause | ARCH.5 pending; its own clauses need mutants (F-1) |
| ARCH.6/1 | yes | full = | gap → covered | → verified (int-06) | RED on the first clause | ARCH.6 pending |

### US-DOC-HYG-3 — archive and removal

| Case | Asserts the expected result? | Mark | Coverage | Result (evidence) | RED on base (red-01) | Negative control |
|---|---|---|---|---|---|---|
| ARCHIVE.1/1 | yes | full = | gap → covered | → verified (int-06) | RED | ARCHIVE.1 pending; it targets the "earlier path" clause, which was never RED |
| ARCHIVE.1/2 | — (E5-T) | — | gap = (→ covered once a transcript is filed, C-7) | not_run = (inspection A.1: 3/3) | — | n/a |
| ARCHIVE.2/1 | — (E5-T) | — | gap = (→ covered once a transcript is filed, C-7) | not_run = (inspection A.2: 366/366) | — | ARCHIVE.2 pending (an E5-T check) |
| ARCHIVE.2/2 | — (E5-T): under-specified (C-5) | — | gap = | not_run = (A.3: the verdict depends on the id grammar) | — | — |
| ARCHIVE.3/1 | yes | full = | gap → covered | → verified (int-06) | RED (33) | ARCHIVE.3 pending |
| ARCHIVE.3/2 | yes | full = | gap → covered | → verified (int-06) | RED | ARCHIVE.3 pending |
| ARCHIVE.3/3 | yes | full = | gap → covered | → verified (int-06) | RED | ARCHIVE.3 pending |
| ARCHIVE.3/4 | yes | full = | gap → covered | → verified (int-06) | RED (names `s19_sample.txt`) | ARCHIVE.3 pending (the base RED names the token) |
| ARCHIVE.4/1 | yes | full = | gap → covered | → verified (int-06) | RED **by emptiness only** (tester F-4) | ARCHIVE.4 pending; **the only behavioural RED** (F-1) |
| ARCHIVE.4/2 | yes: 1, 1, 0 | full = | gap → covered | → verified (int-06) | PASS (instrument) | §D aggregate, run before the I-6 probe change (F-2) |

## 4. Proposed changes (old → new, and why)

**C-1 — bookkeeping (E4 never made it).**
- **Coverage:**
  - `gap` → `covered` on the 46 test-backed cases other than REF.5/1 and README.4/4.
  - README.4/4: see C-2.
- **Result:** `not_run` → `verified` on the 48 test-backed cases. Evidence: `evidence/inc-16/int-06.txt`, executor the E4 integrator on LAN host 2. int-01 is supporting evidence.
- **Summary table:** update it to the totals in §6.

**C-2 — README.4/4.** Severity: low.
- **Marks:** N `test_r_doc_ref_2_2_…` changes from `(full)` to `(partial: the two row clauses)`. G14 stays `(partial: existence)`.
- **Coverage:** `partial` → `covered`.
- **Why:** the expected result has three clauses. N asserts that no row links the diagrams file and that exactly one row links `docs/architecture.md`. Only G14 asserts "every linked document exists" (REF.2/1 does too). The two tests together assert all three clauses, and both ran GREEN in int-06.

**C-3 — REF.5/1.** Severity: low (latent).
- **Marks:** A changes from `(full)` to `(partial)`, and coverage from `gap` to `partial`.
- **Why the test falls short:** CTX-DOCHYG defines `.s19tool/`, `.s19tool\`, `s19tool/`, `s19tool.egg-info` and `` `pip <verb> s19tool` `` as shapes of **an occurrence**. `_live_token_findings` instead excuses the **whole line** when any `_S19TOOL_OK` pattern matches. So a line that holds one shape and one bare command passes, for example "`` `.s19tool/` `` is created by `s19tool firmware.s19 info`".
- **Impact today:** inspection A.5 finds 0 such lines at HEAD, so the result does not change.
- **Fix, for the test author:** remove the occurrence-shape matches before searching for `\bs19tool\b`, and add that example as a control line judged 1.
- **Or rule it accepted:** record it as a per-line rule in CTX-DOCHYG, as E3 A16-15 did for removal marks. The mark then returns to `full`.

**C-4 — ARCH.1/2.** Severity: minor (record).
- **Coverage:** `gap` → `conflict`.
- **Expected result, old:** "V8 SKIP line `N modules, no orphan files`, 0 NOTICE `under no declared module`".
- **Expected result, new:** "0 NOTICE `under no declared module`; exactly 1 root NOTICE, for `setup.py`, which lies outside every prefix by construction (CTX-DOCHYG)". The alternative is for the map to declare the `` `**` `` sentinel.
- **Why the old result cannot be met:**
  - `_v8_outcome` in `devflow-validate.py` emits a root NOTICE for every root `.py` file when the map declares no `` `**` `` sentinel. It prints the SKIP line only when the list of notices is empty.
  - `setup.py` is tracked at the root, and the map declares no sentinel, at base or at HEAD.
  - The static derivation (A.4) gives 0 stale-module notices and 1 root notice (`setup.py`) on both trees.
- **Result:** stays `not_run`, because the validator was not run.
- **Side note:** V8 reads every `` `x/**` `` token anywhere in the map. At HEAD that set includes `path`, which comes from prose, and `s19_app/tui/changes`. ARCH.2 reads only the module table, so the two prefix sets differ. That is harmless here.

**C-5 — ARCHIVE.2/2.** Severity: minor (record).
- **Coverage:** stays `gap`, but the case text must change before the E5 transcript runs, because the expected result depends on the id grammar (A.3):
  - **Whole-token ids:** the new set is {`US-141..US-151`}. Elsewhere under `.dev-flow/` that token appears only in two `.json` files, not in any `.md` file, so the check fails as written.
  - **Digits-and-dots ids** (`(US|HLR|LLR)-[\d.]+`, trailing dots stripped), with the increment's own folder excluded: the new set is {`LLR-155.1..155.4`}. This reproduces E1.
  - **Single ids:** the new set is ∅.
- **Self-reference:** `01-requirements.md`, `02-test-cases.md` and `E1-rulings.md` quote `LLR-155.1..155.4`. Unless they are excluded, the expected id counts as "found elsewhere".
- **Proposed case text:**
  - **Grammar:** digits-and-dots.
  - **Corpus:** the tracked `.md` files under `.dev-flow/`, except the archive file and `.dev-flow/2026-11-01-batch-101/inc-16/`.
  - **Expected:** the new ids ⊆ {`LLR-155.1..155.4`}.

**C-6 — DEV.1/1.** Severity: low. This changes the case text only; the mark stays `full`.
- **Old:** "0 list items naming `s19tool` (base 1)".
- **New:** "0 entry-point list items (`` `<name>` → `<module>:<func>` `` under "Project layout") naming `s19tool` (base 1)".
- **Why:** the requirement says "0 lines present `s19tool` as an entry point", and the test reads exactly the entry-point items (tester F-7). The current wording would also forbid an honest "module-only" mention. Node A (REF.5/1) catches any other `s19tool` without a shape in `CLAUDE.md`.

**C-7 — ARCHIVE.1/2 and ARCHIVE.2/1.**
- **Proposed:** Coverage `gap` → `covered` and Result `not_run` → `verified`, once the orchestrator files a transcript.
- **What the inspection shows:** both cases hold at `d461d0f` (A.1, A.2).
- **How to file it:** the orchestrator can cite Appendix A as that transcript (executor: qa-reviewer, read-only git) or re-run the checks into `evidence/inc-16/`.

**C-8 — the document count.** Severity: record.
- **The gap:** the common inputs say "E4 records the measured number", but neither E4 note records it.
- **Inspection:** there are **49** repository documents at `d461d0f`. That is 56 − 7: the 3 moved notes, the diagrams file, the 2 example `.txt` files and `REQ-crc.md`. This equals the expected value.

### Flags (no mark change)

- **F-1 — Four cases have no behavioural RED of their own.** Their E1 mutants must land in E5-mutants.md:
  - **REF.2/1:** the base RED comes only through the retired folder.
  - **ARCH.1/1:** a standing property that passes on base.
  - **ARCH.5/2:** its base RED comes from the shared exactly-one-table precondition. Add mutants for its own clauses: the rail row says "ten", the `B100-I9` Shape cell lacks "saved file", and a `Frozen?` cell reads "yes".
  - **ARCHIVE.4/1:** RED by emptiness only. The base hit came from a probe script, not from the node.
- **F-2 — instrument controls.** For REF.1/2, REF.3/3, REF.4/2, DEV.9/2, DEV.12/2 and ARCHIVE.4/2, the oracle controls were exercised only in aggregate: red-01 §D reports 14 kills and 0 survivors, with no line per mutant. ARCHIVE.4/2's probe changed at integration (I-6, drive letter `X:`) after §D ran.
- **F-3 — ARCH.4/1 checks presence, not truth.** R-DOC-ARCH.4 says "exactly the facts of CTX-SUBMOD", but the case checks only that the cells are non-empty. Integration I-3 found the `render/format.py` Exposes cell understated and fixed it by hand, which is exactly the kind of rot this case cannot see. A later candidate: a text census showing that the names imported from `render/format.py` are a subset of the Exposes cell.
- **F-4 — later clauses with no RED.** Several multi-clause tests went RED on base through their first clause only: DEV.4/2 (bullet), DEV.6/1 (paragraph), DEV.10/1 (tally), DEV.12/1 (count lines), ARCH.4/2 (citation), ARCH.6/1 (old cap) and ARCHIVE.1/1 (earlier path). The E1 mutants of DEV.10, DEV.12, ARCH.6 and ARCHIVE.1 target exactly those later clauses, so they add evidence beyond the base RED.
- **F-5 — latent weaknesses, accepted.**
  - ARCH.5/1 matches named contracts as substrings of the joined first column; at HEAD each one lands on its own row (A.5).
  - `_read` and `_retired_candidates` skip absent or undecodable files silently.
  - DEV.6/1 joins every paragraph that names `project.toml`.

## 5. Negative controls by requirement (32 rows)

| Requirement | E1 negative control | Status |
|---|---|---|
| R-DOC-REF.1 | restore `s19_app/tui/hexview.py` at `PROJECT_RULES.md:135` | pending mutants |
| R-DOC-REF.2 | delete the diagrams file and keep the `README.md` row | pending mutants (the only real-corpus RED of REF.2/1) |
| R-DOC-REF.3 | restore the `prototypes/` path in the `project_gather_service.py` docstring | pending mutants |
| R-DOC-REF.4 | restore the line at `docs/engineering-rules.md:11` | pending mutants |
| R-DOC-REF.5 | add `s19tool firmware.s19 info` to `CLAUDE.md` | pending mutants (the same text is judged 1 by the node's instrument block on every GREEN run) |
| R-DOC-REF.6 | restore `cdfx/` package in `docs/README.md` | pending mutants |
| R-DOC-README.4 | keep the diagrams row with the file deleted, which should turn G14 RED | pending mutants |
| R-DOC-DEV.1 | add the `s19tool` arrow item back | pending mutants (the base RED names the token) |
| R-DOC-DEV.2 | `s19tool firmware.s19 verify`; `<file> <command>` order | **exercised**: int-04 M-1, M-2, plus the base RED |
| R-DOC-DEV.3 | delete `main` from the sentence | **exercised**: int-04 M-3 |
| R-DOC-DEV.4 | restore `s19_app/tui/hexview.py` in `CLAUDE.md` | pending mutants (the base RED names `CLAUDE.md`) |
| R-DOC-DEV.5 | restore `~5k-line` | pending mutants |
| R-DOC-DEV.6 | restore `workspace.py:508` | pending mutants |
| R-DOC-DEV.7 | restore the memory-file sentence | pending mutants (the base RED names the token) |
| R-DOC-DEV.8 | delete the `markdown-it-py>=3` line | pending mutants (the base RED shows its effect) |
| R-DOC-DEV.9 | delete the `engineering-rules.md` link | **exercised**: int-04 M-5 |
| R-DOC-DEV.10 | restore `Tests: 762 pass …` | pending mutants (the tally clause was never RED) |
| R-DOC-DEV.11 | delete `Check Editor` from §3 | pending mutants (the base RED names the token) |
| R-DOC-DEV.12 | restore "ten single-context screens" | pending mutants |
| R-DOC-DEV.13 | restore "Roughly 2760 tests" | pending mutants |
| R-DOC-DEV.14 | restore the base bullet | pending mutants (the base RED names it) |
| R-DOC-DEV.15 | delete the `case_08_release_demo` entry | pending mutants (the base RED names it; the in-test deletion control runs on every run) |
| R-DOC-ARCH.1 | delete the `tools` row | pending mutants (the only RED; a synthetic analogue appears only in red-01 §D's summary) |
| R-DOC-ARCH.2 | restore the `prototypes` row | pending mutants (the base RED names it) |
| R-DOC-ARCH.3 | restore the batch-100 interface block | pending mutants |
| R-DOC-ARCH.4 | delete the no-`s19_app.tui` fact of `render/format.py` | pending mutants (that cell was never RED) |
| R-DOC-ARCH.5 | delete the `B100-I16` row | pending mutants (plus ARCH.5/2's own clauses, F-1) |
| R-DOC-ARCH.6 | restore "capped at ≤ 5 files" | pending mutants (that clause was never RED) |
| R-DOC-ARCHIVE.1 | copy `PENDIENTES-batch96.md` back to the root | pending mutants (that clause was never RED) |
| R-DOC-ARCHIVE.2 | drop the batch-99 table from the archive, which should turn the E5 check RED | pending mutants (an E5-T check) |
| R-DOC-ARCHIVE.3 | restore `examples/case_00_public/s19_sample.txt` | pending mutants (the base RED names it) |
| R-DOC-ARCHIVE.4 | restore the base text of `PENDIENTES-batch96.md:3` in the archived copy | pending mutants (the only behavioural RED) |

## 6. Totals

| Item | Record (E1) | Audit |
|---|---|---|
| Cases | 52 | 52 audited |
| Test-backed cases with a `full` test | 48 (README.4/4's N is full) | 46. README.4/4 is covered by two partial tests; REF.5/1 is partial. |
| Coverage | gap 51, partial 1 | **covered 47**, partial 1 (REF.5/1), conflict 1 (ARCH.1/2), gap 3 (ARCHIVE.1/2 and 2/1 become covered once a transcript is filed; ARCHIVE.2/2 is under-specified) |
| Result | not_run 52 | **verified 48** (int-06), not_run 4 (E5-T) |
| Marks changed by judgment | — | 3 / 52 = **5.8 %** (README.4/4, REF.5/1, ARCH.1/2) |
| Cases with any judgment change, case text included | — | 5 / 52 = **9.6 %** (adds DEV.1/1 and ARCHIVE.2/2) |
| Stale E1 placeholders (bookkeeping) | — | 48 / 52 cases (92 %) |
| Negative controls exercised by a cited RED | — | 3 / 32 (DEV.2, DEV.3, DEV.9); **29 pending mutants** |
| Test names in the record against the file | — | 44 / 44 match. The A and G14 nodes exist. |

## 7. Evidence checklist

- ✓ The mode is declared (validation; audit of marks), in the header.
- ✓ Every case carries a result state: `verified` (48, with int-06 named and the executor named) or `not_run` (4 E5-T, with the reason given), in §3.
- ✓ Each executed result names its executor: the E4 tester, the E4 integrator, or qa-reviewer for the Appendix A inspections (§2).
- ✓ No claim of running the gate suite; the inspections are labelled as inspections, and A.4 is not a validator run.
- ✓ No real PII or secrets. Transcripts are cited, not copied; no home path, account or host name is written here.
- n/a The Given/When/Then, regression and exit-criteria items: this is an audit of an existing case table, not a new plan.
- n/a Layer B black-box: a documentation increment with no surface that produces output; the guards read the shipped documents themselves.

## Appendix A — inspections

Executor: qa-reviewer (E5 audit), on Windows. Read-only `git show`, `git log`, `git diff`, `git ls-files` and `git ls-tree`, plus text parsing in `python -I`. Nothing imported `s19_app` and no pytest ran. Blobs were read at `d461d0f` unless a base is named.

- **A.1 — ARCHIVE.1/2.** Command: `git log --follow --format=%h HEAD -- <archive path>`.
  - `PENDIENTES-batch96.md` → `f65d23a1 ad10fb5c 121feaaa`
  - `crc-algorithm-designer-requirements-draft-2026-07-20.md` → `f65d23a1 b167828e 84180b4c`
  - `synth-case08-release-demo-VERIFY.md` → `f65d23a1 41ed7c55 9fd3638b`

  Each lists 2 commits before the increment's first commit `f65d23a`, so 3/3 hold. **Holds.**
- **A.2 — ARCHIVE.2/1.** Method:
  - `git diff -U0 --no-renames c2cba35 HEAD -- docs/architecture.md` removes 475 base lines.
  - On the base file, a removed line is in scope when it falls in §10 or §11 (from the `## 10.` or `## 11.` heading up to the next `## `) or inside a `> **Amended at` / `> **Post-gate amendment` blockquote. That gives 463 lines, 366 of them non-blank (§10: 236, §11: 89, notes: 41).
  - All 366 occur in `.dev-flow/design/archive/architecture-batch-declarations-88-100.md`, compared stripped: as an equal line, or else as a substring.
  - 7 removed non-blank lines fall outside the scope; the case does not require them.

  **Holds (100 %).**
- **A.3 — ARCHIVE.2/2.** Ids in the archive, compared with every other tracked `.md` file under `.dev-flow/` (1,745 files):

  | Id grammar | Own folder included | Own folder excluded |
  |---|---|---|
  | whole-token `(US\|HLR\|LLR)-[0-9A-Za-z][\w.\-]*` (53 ids) | new = {`US-141..US-151`} | new = {`LLR-155.1..155.4`, `US-141..US-151`} |
  | digits-and-dots `(US\|HLR\|LLR)-[\d.]+` (49 ids) | new = ∅ | new = {`LLR-155.1..155.4`} |
  | single id `(US\|HLR\|LLR)-\d+(\.\d+)?` (48 ids) | new = ∅ | new = ∅ |

  Elsewhere under `.dev-flow/`, `US-141..US-151` appears only in `2026-10-25-batch-99/decisions-log.json` and `state-snapshot-at-close.json`. **The verdict depends on the grammar** (C-5).
- **A.4 — ARCH.1/2.** This re-derives `_v8_outcome` and `v8_module_map` from `~/.claude/docs/tools/devflow-validate.py`; it is not a run of the validator.
  - Prefixes are the `` `x/**` `` tokens anywhere in the map; the sentinel is a bare `` `**` ``; a file counts when it is tracked and ends in `.py`, `.ts`, `.tsx` or `.js`.
  - At `c2cba35`: 10 prefixes, `prototypes` among them; no sentinel; root notice `setup.py`; 0 stale notices.
  - At HEAD: 7 prefixes (`.dev-flow`, `docs`, `path`, `s19_app`, `s19_app/tui/changes`, `tests`, `tools`); no sentinel; root notice `setup.py`; 0 stale notices.

  The outcome on both trees is a NOTICE, never the SKIP line (C-4).
- **A.5 — other probes.**
  - **REF.5, mixed lines:** these are lines in repository documents that hold an occurrence shape, still hold a bare `s19tool` once the shape is removed, and carry no phrase shape or removal mark. There are **0** at HEAD.
  - **ARCH.5, row matching:** the §11 table has 57 rows. Each of the 11 named-contract strings hits its own row first (`chain-set` hits 2 rows, its own first).
  - **ARCH.4/2, the citation:** the module docstring of `flow_screens.py`, read with `ast` as text only, cites `docs/architecture.md` §10, and the test's regex finds it.
  - **Document count:** 49 repository documents at HEAD, against 56 at base with `.fast-dev-flow/` excluded.
  - **Test names:** the record's 44 N names equal the 44 `def test_r_doc_*` in the file.

**What these inspections cannot cover:** they are not pytest runs and not the validator run. They read committed blobs, so they say nothing about an uncommitted working-tree change; the only uncommitted change is `steps.log`.

## Re-audit

**Mode: validation (a re-audit of the changed items only).** The auditor (qa-reviewer, E5) re-checks only what the corrective pass touched: C-2 (DEV.8/1, the new DEV.8/2), C-3 (DEV.8/1, DEV.15/1), C-4 (DEV.11/1), C-5 (ARCH.4/2), C-8 (REF.5/1 and the instrument line it adds to REF.5/2, ARCH.1/2, DEV.1/1, ARCHIVE.2/2), C-9 (ARCH.1/2, ARCHIVE.1/2, ARCHIVE.2/1, ARCHIVE.2/2), and whether C-1 moved every other mark to the audited value with a cited run and a control. Commit `5b45b1b` on branch `b101-inc16`; the worktree is clean. Inputs: `E5-rulings.md`, `E5-corrective-notes.md`, `E5-mutants.md`, `01-requirements.md`, `02-test-cases.md`, the diff `b843fc6..5b45b1b`, and `evidence/inc-16/e5c-01.txt` … `e5c-10.txt` and `mut-NN.txt`. No pytest ran and nothing imported `s19_app`; the inspections of Appendix B are labelled as inspections.

### R.1 Verdict

**PASS-WITH-NOTES. Marks I would change: none.**

- **Every touched case carries the right mark and cites a transcript.** The new and changed guard nodes have their own controls in `e5c-01` … `e5c-04`, and each fix is shown twice: RED under the corrected guard, and GREEN (or RED, for a hard-coded count) under the guard of `b843fc6`. The four E5-T cases cite `e5c-05` … `e5c-08`, and their oracles cite `e5c-09`.
- **The E5 transcripts ran on the corrective tree before the commit.** Appendix B re-derives the four E5-T results at `5b45b1b` itself, and they match the transcripts exactly.
- **C-1 is complete.** 53 of 53 cases read `covered` and `verified`. Each one names its run (`e5c-10`, or its own E5-T transcript) and a control. The 29 controls the first audit marked pending now cite their `mut-NN` row, mapped by requirement; I checked all 33 rows of `E5-mutants.md` against the case cells.
- **ARCH.5/2 should not become `partial`.** Reasons are in R.3.

### R.2 Per case

| Case | Ruling | Mark / coverage | Result and control | Re-audit |
|---|---|---|---|---|
| DEV.8/1 | C-2, C-3 | full / covered | `e5c-10`; `mut-16`; `e5c-01` M-1 RED, P-1 GREEN, P-1/old RED (`4 == 3`) | right. The hard count is gone, and `assert declared` keeps the set from being empty. |
| DEV.8/2 (new) | C-2 | full / covered | `e5c-10`; `e5c-01` M-2, M-3, M-4 RED, P-1 GREEN | right. The case text matches the node (one sentence, set equality on both sets). The requirement row and its control column were widened, and the base 2/3 and 2/3 hold (B.3). |
| DEV.15/1 | C-3 | full / covered | `e5c-10`; `mut-23`; `e5c-01` M-5, M-6 RED, P-2 GREEN, P-2/old RED (`16 == 15`) | right. |
| DEV.11/1 | C-4 | full / covered | `e5c-10`; `mut-19`; `e5c-02` M-7 RED (and GREEN under the E4 guard, so F-3 is shown), M-8, M-9, M-10 RED | right. The 13th label is read as text from `app.py`, and the check is bound to the one shell item. The base "9/13" holds inside that item too (B.3). |
| ARCH.4/2 | C-5 | full / covered | `e5c-10`; `e5c-03` M-11 RED, P-3 GREEN, P-3/old RED | right. The node no longer reads the docstring, and R-DOC-ARCH.4 never stated that clause, so dropping it leaves the row whole. Backlog row I-7 tells Inc 9. Its second clause (`flow_screens → services/flow_model`) has no RED of its own; the literal occurs once at base (B.4). |
| REF.5/1 | C-8 | A full / covered | `e5c-10`; `mut-05`; `e5c-04` M-12 RED and GREEN under the E4 test, M-13 RED | right. A shape excuses only its own occurrence, and the phrase shapes stay per line, as CTX-DOCHYG defines them ("or on a line that holds …"). |
| REF.5/2 | C-8 (added line) | A full / covered | `e5c-10`; `e5c-04` M-14 RED | right. |
| ARCH.1/2 | C-8, C-9 | E5-T / covered | `e5c-05` PASS; `e5c-09` O-1 FAIL as expected | right. The expected text equals the V8 output. The validator hash in `e5c-05` equals the installed validator's. V8's inputs do not change between the transcript and the commit (B.2). |
| DEV.1/1 | C-8 | full / covered | `e5c-10`; `mut-08` | right. The text is the wording proposed in C-6 of the first audit. |
| ARCHIVE.1/2 | C-9 | E5-T / covered | `e5c-06` 3/3; `e5c-09` O-2 | right. It holds at `5b45b1b` (B.2). |
| ARCHIVE.2/1 | C-9 | E5-T / covered | `e5c-07` 368/368; `mut-31`; `e5c-09` O-3 | right. 478 lines removed, 368 in scope, all 368 found at `5b45b1b` (B.2). |
| ARCHIVE.2/2 | C-8, C-9 | E5-T / covered | `e5c-08`; `e5c-09` O-4 | right. The case states the grammar, corpus and expected set of C-5 in the first audit. At `5b45b1b`: 1,733 files, 49 ids, new = {`LLR-155.1..155.4`} (B.2). |
| README.4/4 | C-1 (audit C-2) | N partial + G14 partial / covered | `e5c-10`; `mut-07` (G14) | right. |

**Controls carried over from `mut-NN` onto changed nodes.** `mut-NN` ran on the E4 tree. For every node the corrective pass changed, a re-run in `e5c-01` … `e5c-04` replaces it. Two cells still rest on code reading:

- **REF.6/1 (`mut-06`).** The CDFX branch of `_live_token_findings` is unchanged and returns before the changed s19tool step.
- **ARCHIVE.4/1 (`mut-33`).** The F-9 edit only removes `root` from the name set. The `mut-33` hit is the drive-letter path form (R-DOC-ARCHIVE.4 "No: 1 — the drive-letter cloud-folder path"), and that edit does not touch it.

### R.3 ARCH.5/2: keep `full` / `covered`

- **What `partial` means here.** In this record, `partial` means the test asserts only part of the expected result. The node asserts all three clauses: twelve present and ten absent, `saved file` in 5/5 Shape cells, and every `Frozen?` cell either `no` or the `batch_id`. `_interfaces_table` fixes the five-column header, so `row[3]` is Shape and `row[4]` is `Frozen?`.
- **What is actually missing.** The case lacks a cited negative control for its own clauses. That is a gap in control evidence, not in assertion coverage. Marking it `partial` would mix the two, and would also be inconsistent with other cases in the same class: the second clauses of ARCH.4/2 and ARCH.6/1 have no RED of their own either, and `mut-29` fires ARCH.6/1's first clause.
- **What the inspection shows.** Calling the committed node in-process on mutated map text, as an inspection (B.1), turns every assertion RED.
- **How to close it.** Choose one:
  - Run the four text mutations of B.1 as cited rows on the LAN host. This is cheap and matches C-1's standard that a control cites a run.
  - Have the orchestrator rule that inspection B.1 is accepted.

  Until one of these happens, the Result cell's disclosure ("its own three clauses were not mutated") is accurate and should stay.

### R.4 Notes (no mark change)

- **N-1, record.** The `02-test-cases.md` header names the runs but not who executed them. The executors are named only in `E5-corrective-notes.md` §4 (the E5 corrective pass for `e5c-*`) and `E5-mutants.md` (the E5 mutant worker for `mut-NN`). One phrase in the header would close it.
- **N-2, evidence binding.** `e5c-10`'s tree binds to `5b45b1b` by path count and the notes, not by hash:
  - It staged 133 paths. The commit has 134 against `c2cba35`; the extra one is `e5c-10.txt`.
  - The controls staged 124 paths. The extra 9 are `e5c-01` … `e5c-09`.
  - Every assertion message quoted in `e5c-01` … `e5c-04` occurs in the committed guards.

  The index trees `1ec14f22` and `e661d717` are not in the local object store. Printing the blob ids of the guard files would make the binding checkable.
- **N-3, carried over (not this pass's scope).** C-7 of the corrective notes leaves Inc 15's helper copy in `tests/test_suite_hygiene.py` still exposed to `root`. That item is correctly recorded as open there.

### Appendix B — inspections (re-audit)

Executor: qa-reviewer, on Windows with Python 3.12. The methods were read-only `git` and text parsing under `python -I -B`, and the guard module was loaded from its file. That module imports only the standard library, so no `conftest` loaded and no pytest ran; each script asserts that `s19_app` is absent from `sys.modules`. The worktree status stayed empty throughout. The helper scripts lived outside the repository.

- **B.1 — ARCH.5/2 under in-memory mutations.** Method: call `test_r_doc_arch_5_2_rail_saved_files_and_frozen_cells` with `_architecture` replaced by mutated text. Baseline GREEN.

  | Mutation | Result | Assertion that fired |
  |---|---|---|
  | K-1: rail row, `twelve` → `ten` | RED | "does not say twelve" |
  | K-2: rail row keeps `twelve` and adds "(formerly ten)" | RED | "still says ten" |
  | K-3: `B100-I9` Shape cell without `saved file` | RED | "Shape cell lacks 'saved file'" |
  | K-4: the `B97-I-1` `Frozen?` cell reads `yes` | RED | "neither 'no' nor …" |

  This is not a cited run on the LAN host.
- **B.2 — the E5-T results at `5b45b1b`.**
  - **ARCHIVE.1/2.** `git log --follow` gives `f65d23a1 ad10fb5c 121feaaa`, `f65d23a1 b167828e 84180b4c` and `f65d23a1 41ed7c55 9fd3638b`. `git diff b843fc6 5b45b1b -- .dev-flow/design/archive/` is empty.
  - **ARCHIVE.2/1.** Method A.2 against `5b45b1b`: 478 removed, 368 in scope, 368/368 in the archive.
  - **ARCHIVE.2/2.** The digits-and-dots grammar over `git grep` at `5b45b1b`, with the archive file and the inc-16 folder excluded: 1,733 files, 49 ids, not found = {`LLR-155.1..155.4`}.
  - **ARCH.1/2.** No `.py`, `.ts`, `.tsx` or `.js` path is added between `b843fc6` and `5b45b1b`; only the two existing test files are modified. No `` `x/**` `` token changes in `docs/architecture.md`. The installed validator's sha256 equals the `b197fda5…` printed in `e5c-05`.
- **B.3 — base figures.** The committed helpers were run on the `c2cba35` blobs.
  - **DEV.11/1:** 12 rail labels and the palette label are read. Exactly 1 shell item; 9/13 are named in it, and also in the whole §3.
  - **DEV.8/2:** the base `pyproject.toml` markers are {`serial_timing`, `slow`, `snapshot`}. The base §8 bullets are {`slow`, `snapshot`}, and its dependency sentence names `rich` and `textual`.
- **B.4 — literals with no RED of their own.** `flow_screens → services/flow_model` occurs once in the base map, and `≤ 5 files` occurs once. Both checks would match the base text, so neither is vacuous by construction. `mut-29` fired ARCH.6/1's first clause, not its second.

**What these inspections cannot cover:** they are not pytest runs and not runs on the LAN host. B.1 shows that the node's assertions can fail, but it is not a cited control under C-1's standard.

### Evidence checklist (re-audit)

- ✓ The mode is declared (validation; re-audit of changed items), in the header of this section.
- ✓ Every touched case carries a result state and a cited transcript (R.2). Executors: the E5 corrective pass (`e5c-*`), the E5 mutant worker (`mut-NN`), and qa-reviewer for the inspections (Appendix B).
- ✓ No claim of running the suite or the controls; the inspections are labelled.
- ✓ No real PII or secrets: no local path, account or host name is written here.
- n/a Given/When/Then, regression and exit criteria: this is a re-audit of an existing case table.
- n/a Layer B: a documentation increment; the guards read the shipped documents themselves.
