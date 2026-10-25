# Increment 002 — HLR-153 · `S0 is not image data`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `002` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-142 / HLR-153 / LLR-153.1 · LLR-153.2 · LLR-153.3 · LLR-153.4` |
| Acceptance | `AT-B99-02` · white-box `TC-B99-04 · TC-B99-05 · TC-B99-06 · TC-B99-07` · unit `core._is_data_record` |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: one data-record predicate now gates every S19 image walk.
`s19_app/core.py` gains `_is_data_record(record)` — True for `S1`/`S2`/`S3`
only (ARCHITECTURE R18, the B99-I1 contract change). `S19File.get_memory_map`,
`get_record_for_address` and `_build_overlap_map` filter through it;
`get_memory_ranges` derives from `get_memory_map` and inherits it.
`s19_app/render/hexview.py` imports the same predicate in
`build_mem_map_s19` and `build_range_validity_s19`. The S0 header text stays
available untouched: `load_service.py:62` already captures it into
`LoadedFile.source_s0_header`, save-back / flow WRITE-OUT already forward it to
`emit_s19_from_mem_map`, and TC-B99-06 proves the written S19 carries the S0
text as an S0 record with zero data at the S0 payload addresses, for S19 and
Intel HEX output. A change entry at an address covered only by the S0 payload
now classifies `skipped-outside` (the apply engine's existing OUTSIDE →
`skipped-outside` mapping, `apply.py:117`), so a patch at `0x0` can no longer
land on header bytes.

Record walks deliberately left alone (grep census `for record in
.*records` over `s19_app/`): `_autodetect_endian` (plausibility scoring over
raw bytes, not an image walk); `print_header` (its job is the S0 text);
`S19File.__iter__` / `validate_all` / `get_invalid_records` (generic accessors
and validation, no image feeding); `get_out_of_order_records` (already
S1/S2/S3-only); `cli.py` `_write_s19` / `patch-hex` save-as (1:1 whole-file
record copies — the S0 stays an S0 record, LLR-153.3-consistent) and
`update-checksums` (checksum repair, not image data);
`load_service.py:62`/`:66` (deliberate S0 / terminator extraction);
`validation/rules.py` (findings, not image walks); `hexfile.py` (Intel HEX has
no S-record types).

Shipped surface the user reaches: the Memory Map (rail `4`), the hex view,
Patch Editor (rail `6`) containment and save-back (`#patch_saveback_*`), flow
WRITE-OUT.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/core.py` | SOURCE | HLR-153, LLR-153.1 | new `_is_data_record` predicate; `get_memory_map` / `get_record_for_address` / `_build_overlap_map` filter through it (CRLF preserved: 717 `\r\n` before and after) |
| `s19_app/render/hexview.py` | SOURCE | HLR-153, LLR-153.2 | import the predicate; `build_mem_map_s19` / `build_range_validity_s19` filter through it (CRLF preserved: 397 `\r\n` before and after) |
| `tests/test_b99_s0.py` | test | HLR-153 | new: TC-B99-04 (+ boundary node), TC-B99-05, TC-B99-06, TC-B99-07, AT-B99-02; review round 1: AT-B99-02 fully key/click-driven (F2), Memory-Map row assertion fixed (F1), TC-B99-06 defective-source arm bounded to defective-record addresses (F5) |
| `tests/test_entropy_service.py` | test (re-pin) | LLR-153.1 | phantom S0-header window counts re-pinned (re-pin #1) |
| `tests/test_tui_directionb.py` | test (re-pin) | LLR-153.1 | case_02 coverage literals re-pinned (re-pins #2/#3); AT-040a colour branch rebuilt on a real two-range fixture (F4, re-pin #4) |
| `tests/test_tui_hexview.py` | test (re-pin) | LLR-153.2 | stub records gain `type="S1"` (re-pins #5/#6) |
| `tests/test_report_service.py` | test (re-pin) | LLR-153.1 | AT-288 capture pin re-pointed to `tests/goldens/batch99/` (F6) — capture content re-pinned (re-pin #7), sealed batch-92 evidence record restored |
| `tests/goldens/batch35/at054b-before-after-report.md` | golden (re-pin) | LLR-153.1 | phantom 0x0-0xF diff region removed (re-pin #8); pre-pin bytes backed up |
| `tests/goldens/batch35/at054b-before-after-report.html` | golden (re-pin) | LLR-153.1 | same re-pin, html arm |
| `tests/goldens/batch99/at288-pre-move-report.bin` | golden (re-pin, new home) | LLR-153.1 | the S0-free AT-288 capture, moved out of the sealed batch-92 evidence folder (F6) |
| `tests/__snapshots__/test_tui_snapshot/*.svg` | snapshots (16 re-pins) | LLR-153.1 | 16 density-layout cells regenerated — every delta is the disappeared 6-byte S0 range (multiset proof `repin-snapshot-svg-multiset.txt`); pre-update SVGs backed up in `snapshot-pre-b99-inc2/` (16 files) |
| `.dev-flow/2026-10-11-batch-92/evidence/at288-pre-move-report.bin` | sealed record | — | **restored** to its batch-92 bytes (`sha256 061ee94c…`, byte-equal to the `.pre-b99-inc2` backup) — a sealed record is never edited (F6); the edit that had been committed in `fc81767` is reverted in the working tree |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-002.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-2/*` | doc | — | transcripts, hashes, probes (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 4** |
| Test files | 5 (uncapped: 1 new + 4 re-pinned) |
| Snapshot cells | 16 re-pinned SVGs (uncapped) |
| Golden captures | 3 re-pinned (2 batch35 + 1 new batch99 home) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched; no `git commit`.

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # C:\Users\jjgh8\Github\s19_app-b99-inc2\s19_app\__init__.py
pytest tests/test_b99_s0.py -v                        # -> 6 passed
pytest tests/test_b99_s0.py -k tc_b99_04              # -> 2 passed, 4 deselected
pytest tests/test_b99_s0.py -k tc_b99_05              # -> 1 passed, 5 deselected
pytest tests/test_b99_s0.py -k tc_b99_06              # -> 1 passed, 5 deselected
pytest tests/test_b99_s0.py -k tc_b99_07              # -> 1 passed, 5 deselected
pytest tests/test_b99_s0.py -k at_b99_02              # -> 1 passed, 5 deselected
pytest tests/test_b99_corpus.py tests/test_address_census.py -q   # census companions
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `_is_data_record` (via TC-B99-04 walks) | exercised by TC-B99-04/05 |
| **A · white-box** `TC-B99-04..07` ↔ LLR-153.1..153.4 | `core` · `full` | `test_tc_b99_04_predicate_feeds_every_walk` · `test_tc_b99_04_boundary_s0_alongside_data_at_zero` · `test_tc_b99_05_hexview_builders_use_same_predicate` · `test_tc_b99_06_written_images_carry_s0_as_header_only` · `test_tc_b99_07_patch_at_s0_address_is_outside` | 5 passed |
| **B · black-box** `AT-B99-02` ↔ US-142, through the Textual pilot | `core` · `full` | `test_at_b99_02_save_back_excludes_s0` | 1 passed |

Regression companions: `tests/test_b99_corpus.py` 4 passed;
`tests/test_address_census.py` 23 passed; census batch (27 files, first run):
743 passed, 15 failed, 2 xfailed — every failure triaged (§4 Reverse census);
re-pinned/flake nodes + both companions, final idle run: 39 passed
(`census-repinned.txt`); snapshot suite: 33 passed (`green-snapshot.txt`).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | re-admit `S0` in `_is_data_record` (`return record.type in {"S0", "S1", "S2", "S3"}`) — the declared negative control for LLR-153.1/153.2/153.3; LLR-153.4's control is the P-2 baseline RED |
| Instrument | project code: the implementer's own hand via the Edit tool, restore checked by SHA-256 |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc2`), run by the implementer |
| Transcript | `evidence/inc-2/mut-LLR-153.1.txt` — **6 failed** (every node RED) |
| Restore proven by | `s19_app/core.py` SHA-256 returned to `6821f378a150290e42d20f17b2c5865a423d99f5fd752fa31a0ce75c3148f683` (pre-mutation value, recorded before the mutation) |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | 6 per-node RED transcripts on the unmodified tree, one per new node |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | none under the mutation |

| Field | Value |
|---|---|
| **RED counterfactual** | every new node ran RED on the unmodified tree before the fix: `red-tc_b99_04_predicate.txt`, `red-tc_b99_04_boundary.txt`, `red-tc_b99_05.txt`, `red-tc_b99_06.txt`, `red-tc_b99_07.txt`, `red-at_b99_02.txt` (AT oracle failure: `bytes at 0x0..0xB: [0..11]` — the P-1 premise verbatim). The AT harness needed one genuine drive fix during RED (the Load dialog is a pushed screen: query inside `app.screen`, matching `tests/test_loadfilescreen_input.py`) — after that fix the AT fails only on the oracle. `red-full.txt` is the tail summary of the first full-file RED run. |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-153.1 · TC-B99-04/05/06/07 + AT-B99-02: re-admit S0 · KILLED (6/6 nodes RED) · arms GREEN: none · transcript `mut-LLR-153.1.txt` · restore `6821f378…` ‖ LLR-153.4 · TC-B99-07: the unmodified-tree baseline (`red-tc_b99_07.txt`, disposition `applied` — P-2) is the executed negative control |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | each new node on the unmodified tree | 6 per-node RED transcripts (see RED counterfactual) |
| `pytest` + mutation | `_is_data_record` re-admitting S0 | 6/6 nodes FAILED (`mut-LLR-153.1.txt`) |
| independent reader (oracle) | the AT's saved-back file on the unmodified tree | extra bytes at `0x0..0xB` (`red-at_b99_02.txt`) |
| TC-B99-06 strict arm | a written S19 carrying bytes the source never declared | well-formed sources assert `written.data == oracle.data` exactly — under the mutation the written map regains `0x0..0xB` and the node goes RED |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the save-back / WRITE-OUT S19 text (emitted by `save_patched_image`) | re-parsed with `tests/support/independent_reader.read_s19` | written data == source data (well-formed sources, exact), S0 text == source S0 text, EOF present — 22 sources × 2 output formats (`green-tc_b99_06.txt`) |
| the WRITE-OUT Intel HEX text (emitted by `save_patched_image`, HEX branch) | re-parsed with `read_hex` | written data == source data, EOF record present — 22 sources (`green-tc_b99_06.txt`) |
| the AT's on-disk save-back | re-parsed with `read_s19` | no byte at `0x0..0xB`, data identical to the source, header preserved (`green-at_b99_02.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-2/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED baseline, TC-B99-04 | `red-tc_b99_04_predicate.txt` | `e769259c837c4b7aa46fc52681574b1b47f52c050185279748bc046129b5cbb1` |
| RED baseline, TC-B99-04 boundary | `red-tc_b99_04_boundary.txt` | `5316fafba632a23c74015e4beeda943fd7bf4eb5b666b3d46d963426cab2e605` |
| RED baseline, TC-B99-05 | `red-tc_b99_05.txt` | `0ca95d139ff03c9db49ee64911d818450a049714eea49642ca1db4707439bcd6` |
| RED baseline, TC-B99-06 | `red-tc_b99_06.txt` | `ecc40d35b68de4dcd60f2d812273eb5a7bb91454b0f4870ec090c523047d10ce` |
| RED baseline, TC-B99-07 | `red-tc_b99_07.txt` | `c1bfd46ced020de781d1795e5a3b724048fb18c0d616956e8cec199fde5985a7` |
| RED baseline, AT-B99-02 (P-1 oracle) | `red-at_b99_02.txt` | `1d7478cdfdac43761cf62c30637d59b89fb70b3dc53d7ca81b49a06a7145f582` |
| RED full-file tail summary | `red-full.txt` | `95e5e1b5bd38b9bf8ff507c3740121fe6248b1009d1f8ed73631aa7e23111765` |
| GREEN full run (6 passed) | `green-full.txt` | `d4f5beb22c3a44a7b94a8ec572b6c15d2d53ec67f0d5c37dda29541b2847135d` |
| GREEN TC-B99-04 | `green-tc_b99_04_predicate.txt` | `316c38791acb58dcaf28b84195c5b6a7754a4b05d1221a47250c939549486579` |
| GREEN TC-B99-04 boundary | `green-tc_b99_04_boundary.txt` | `8329bd375c9333fe68c117a55fbc740943334e9dbdbcc94b8bb4e28d881622bf` |
| GREEN TC-B99-05 | `green-tc_b99_05.txt` | `21f28740d7290c5ba8e90d23c57105c5e441b2859bc89cd3fb30633efbf69efd` |
| GREEN TC-B99-06 | `green-tc_b99_06.txt` | `935d4787a0882ae19fdcdee7d63e600caba44f7af7e21e3a6f8e9582be320132` |
| GREEN TC-B99-07 | `green-tc_b99_07.txt` | `f58eaf76b58f479c6050e7c32ca24c2878492a3bf811fde09ff3186ff5ef75f2` |
| GREEN AT-B99-02 | `green-at_b99_02.txt` | `666906028fdaf81e3a6a5ccc30d02c6c6ae9ad9874c30d7403df6d62a78d1dbf` |
| Mutation LLR-153.1, original verdict KILLED 6/6 — transcript refreshed in review round 1 after the F1/F2/F5 test rewrite (6/6 RED re-verified; restore digest `6821f378…` re-proven) | `mut-LLR-153.1.txt` | `9be2a805bb2f03b8f27664c7c35c17e08b9e848e320a21da34e7b86b99fde39b` |
| Census batch (27 files, first run: 15 failed / 743 passed) | `green-census.txt` | `f0464258da59f6a2ce5b496e301242851f2f1fa6b54a296cc7eadd097ed86081` |
| Census failed-node re-run (idle machine) | `census-failed-rerun.txt` | `bdf85ae11edaf32f5718b6b8392795c36dfdd4be2d705d30ac059fa0b21fe388` |
| Census re-pinned nodes (final, idle — 39 passed) | `census-repinned.txt` | `72a365d68d0cef0427bc49572c449e785a91c305ba2bdf5c9e3c110b04b1e610` |
| Snapshot suite (round 1, 33 passed) | `green-snapshot.txt` | `66e86483a65f067a3d3641bc75c171d424312477a149c3f2091009fadd9b3e56` |
| Re-pin proof: 16 snapshot SVG text-element diffs | `repin-snapshot-svg-multiset.txt` | `758318724a8f0d27db658f9c4541ea0b8d1ee254668ed917f93bea9bacbd4865` |
| Re-pin proof: 16 snapshot SVG raw diffs | `repin-snapshot-svg-diffs.txt` | `3ba7d28cd6d72b4827dae19ab3339fa67377b1a29b472a1405c9fe744f9a3c76` |
| Pre-update snapshot SVGs (16 cells) | `snapshot-pre-b99-inc2/` (16 files; listing hash `72ae5579075f…86a08682c`) | declared home, bytes preserved |
| Re-pin diff: AT-288 capture | `repin-at288-diff.txt` | `d81b28dcf32f33b4f7a857531999a20a8e520f4a930af42f186546d67c67355c` |
| Re-pin diff: AT-054b md golden | `repin-at054b-md-diff.txt` | `e398ba2bbb320d241b58bb7352a793bc8fd31c9c6f0b4411752d8b1439525764` |
| Re-pin diff: AT-054b html golden | `repin-at054b-html-diff.txt` | `c37c50ce980cfdd78239e5043b4ca9a49428aa972dc2bc48bb0b248db6b680a6` |
| Pre-mutation / HEAD hashes | `baseline-hashes.txt` | `318d3f512af9b6133c282b4b2a50f51d3c11a7af66697f62bdaa48cc9452aacd` |
| Pre-pin byte backups (AT-288, AT-054b md+html) | `*.pre-b99-inc2` (3 files) | `061ee94c…` (at288) · `9c885004…` (at054b md) · `3e1f0ad8…` (at054b html) |
| **Review round 1 (F1–F6) transcripts** | | |
| AT-B99-02 stability, 8 consecutive runs (8/8 passed) | `stability-at02.txt` | `f9350d6b892720391cdab28d9829baea6dc850787d0e4c566a034efa8093704b` |
| GREEN fix round: corpus+census (28), hexview+entropy (40), before/after (15) | `green-fix-census-companions.txt` | `90b9732d93252a80897c506e4377ac06c22d6c8ecbedb7e371e5055a15a40169` |
| GREEN fix round: `test_b99_s0.py` (6 passed) | `green-fix-b99_s0.txt` | `26de0e7bb4df9567f4aa0d4fbd159bd4352fee839a171916043e970a79fd1ed0` |
| GREEN fix round: AT-288 on the batch99 golden (1 passed) | `green-fix-at288.txt` | `28f78c73388cc9fc22aa2874be8907e82173340b7c13e240cf76b0ae94a10348` |
| GREEN fix round: snapshot suite, colours on (33 passed) | `green-fix-snapshot.txt` | `3fcec9ed4bdeb0ba01739b987fe6649aa6faf62049cf196c2bbcca33e013d105` |
| GREEN fix round: `test_tui_directionb.py` full file (182 passed; the 2 failures are the freeze guards, RED by design) | `green-fix-directionb.txt` | `4eb29851c8fe29e2153706b42d62fb0a2f0e7c49320edbb56c0cfc1db1c47665` |
| Mutation F1: S0 re-admit vs **step 4 alone** (control PASS, then step-4 RED on the painted S0 row) | `mut-F1-step4.txt` | `92fead926cf8b82afade2cb8bde8cca219bbe46295fc305effaf1b7ed5c2be21` |
| Mutation F5: S0 re-admit vs TC-B99-06 on **both** checksum-defective files (two arms, both RED) | `mut-F5.txt` | `c839991045b099747caba69cd6a9b1fdd0cfc4712d368157f409e5d58e59ab47` |
| AT-288 capture, new home outside the sealed batch-92 evidence folder | `tests/goldens/batch99/at288-pre-move-report.bin` | `4efafaddddc85e5a33295ba7d261c46666fc92a62b9569a1f4f23d4b6be58121` |

| Field | Value |
|---|---|
| **Evidence files** | 33 artifacts + the `snapshot-pre-b99-inc2/` SVG backup directory (16 files), each at the declared home and cited with the digest of its stored bytes — every row re-hashed in review round 1 (the round-1 `red-tc_b99_07.txt` row carried 65 hex digits; corrected to the digest of the stored bytes) |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — the image holding ZERO bytes at S0-payload addresses; the overlap map holding ZERO S0 addresses |
| If the result is an ABSENCE, what made the search wide enough | the walks are checked over every S0-bearing corpus S19 (4), every well-formed corpus S19 (6), every `examples/**/*.s19` (16) and a crafted S0+data-at-0x0 boundary file — not a sample |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b99_04_predicate_feeds_every_walk` — the S0-only disjointness is its own named node |
| Conjunctive criteria: one mutation per conjunct | one mutation (re-admit S0) flips every absence at once — declared as the shared negative control for LLR-153.1/153.2/153.3; LLR-153.4 carries its own baseline RED (P-2) |
| Synthetic instance of the absent case | the mutation IS the synthetic S0-bearing image walk; TC-B99-04 boundary crafts the S0-alongside-data-at-0x0 case |
| **Positive control for every probe that returned an ABSENCE** | under the mutation the identical probes return extra keys at `0x0..0xB`, a record at `0x0`, disposition `applied` — 6/6 nodes RED (`mut-LLR-153.1.txt`) |

### Reverse census — trigger family B, and A3

Population run (all transcripts in `evidence/inc-2/`): the 18 files grepping for
`get_memory_ranges|get_memory_map|build_mem_map_s19|build_range_validity_s19|get_record_for_address|_build_overlap_map`, the 7 additional files grepping for `S0`, plus `tests/test_address_census.py` and `tests/test_b99_corpus.py` — 27 files, one batch (`green-census.txt`: 743 passed, 15 failed, 2 xfailed). Every failure was re-run on an idle machine (`census-failed-rerun.txt`) and the deterministic set was baselined against a pristine `git archive HEAD` tree: exactly one failure (`test_at031b_two_saves_are_distinct_no_clobber`) exists at HEAD and is **pre-existing, not caused by this increment**. Four more were CPU-contention flakes from concurrent probes (they pass idle: `test_saveback_width_32…`, `test_saveback_width_16…`, `test_at057b…`, `test_at064c…`). Two freeze-guard failures are STOP-and-report (below). The remaining eight are S0-phantom re-pins.

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "get_memory_ranges\|…\|_build_overlap_map" tests/` (18 files) + `grep -rln "S0" tests/*.py` (7 more) | 27-file census run; every failure triaged below |
| B2 file moved on disk | n/a — no pre-existing file moved | no readers lost |
| B3 byte-identical golden captures this source | `grep -rln "get_memory_map\|…" tests/goldens/ docs/` | 1 hit: `docs/architecture.md` — a dated plan artifact ("PDR, before Inc 2") whose cited line numbers shift by +24 in `core.py`; left as a dated record, noted in §5 |
| B4 artifact produced here is consumed elsewhere | builders consumed by load/flow/compare/report services (architecture.md §B99-I1 census) | consumers re-validated by the 27-file census |
| A3 interface consumed by another module changed | B99-I1 is the named A3 crossing (LLR-153.1 names it) | names/parameters unchanged; meaning changed by requirement |

Re-pins (each: `test::node — old → new — LLR-153.x`):

| # | Test node | Old → New | LLR | Evidence |
|---|---|---|---|---|
| 1 | `tests/test_entropy_service.py::test_stress_guard_large_s19_window_count` — ranges 201 → 200, windows 3201 → 3200, low-confidence windows 1 → 0 (the 1 was the 6-byte S0 header window at 0x0) | phantom count | LLR-153.1 | `green-census.txt`, re-pinned node in final census transcript |
| 2 | `tests/test_tui_directionb.py::test_tc041_8_coverage_stats_exact_case_02_literals` — `_CASE_02_IMAGE_SPAN` 2147549504 → 320, `_CASE_02_COVERED_BYTES` 93 → 82, `_CASE_02_GAP_COUNT` 3 → 2, `_CASE_02_LARGEST_GAP` 2147549173 → 144, `_CASE_02_VALID_COUNT` 4 → 3 (the 4th range was the S0 header) | phantom span/bytes/gaps | LLR-153.1 | literals re-verified by driving `coverage_stats` on the loaded file |
| 3 | `tests/test_tui_directionb.py::test_at037_stats_strip_matches_case_02_coverage` — expected strip recomputed from the re-pinned shared literals (`Mapped 82 B / 320 B span (25.6250%) · 3 ranges (3 valid) · 2 gaps · 0 issues`) | phantom counts | LLR-153.1 | same |
| 4 | `tests/test_tui_directionb.py::test_at040a_per_range_micro_bar_colour_and_width` — width rows 4 → 3; the colour branch's "valid" row WAS the 13-byte S0 range — re-pinned to pin both rows explicitly from case_04's real addresses (valid first record vs the block holding the checksum-invalid record); oracle (sev-ok ≠ sev-error) unchanged | phantom row | LLR-153.1 | re-pinned node GREEN |
| 5 | `tests/test_tui_hexview.py::test_build_mem_map_s19_flattens_record_bytes` — stub records gain `type="S1"` (builders now read `record.type`; stubs modeled only address/data) | interface, not behaviour | LLR-153.2 | re-pinned node GREEN |
| 6 | `tests/test_tui_hexview.py::test_build_range_validity_s19_marks_invalid_ranges` — same stub update | interface, not behaviour | LLR-153.2 | re-pinned node GREEN |
| 7 | `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` — pinned capture regenerated: the ONLY diff is the deleted entropy-summary line `**low**: 1 window(s) (1 low-confidence)` — that window was the S0 header at 0x0; pre-pin bytes backed up (`at288-pre-move-report.bin.pre-b99-inc2`, sha256 `061ee94c…`) | phantom window | LLR-153.1 | `repin-at288-diff.txt` |
| 8 | `tests/test_before_after_report.py::test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden` — md + html goldens regenerated: the ONLY diff is the disappeared diff region 0x0-0xF (`only in B \| 1 \| 15` and its hex windows) — the save-back S0 header text mapped at 0x0; pre-pin bytes backed up (`at054b-before-after-report.{md,html}.pre-b99-inc2`) | phantom region | LLR-153.1 | `repin-at054b-md-diff.txt` · `repin-at054b-html-diff.txt` |
| 9 | `tests/test_report_service.py::_AT288_CAPTURE` — capture HOME re-pointed (review finding F6): `.dev-flow/2026-10-11-batch-92/evidence/at288-pre-move-report.bin` → `tests/goldens/batch99/at288-pre-move-report.bin`; the sealed batch-92 record was restored to its batch-92 bytes (`061ee94c…`) — a sealed record is never edited. The capture CONTENT stays as re-pin #7 | sealed-record hygiene | LLR-153.1 | `green-fix-at288.txt`; restored record sha256 == `.pre-b99-inc2` backup |

STOP-and-report (not fixed, per the increment rule) — **all three freeze guards** (review finding F3: the third guard, TC-027, was missing from this list). Every one diffs the working tree against `main`; each passes as soon as the batch-99 change lands on `main`, and LLR-153.1 names this engine-layer crossing (B99-I1) as sanctioned — whitelisting any of them is a requirement decision the implementer cannot make:

| Test node | Why it fails | Disposition |
|---|---|---|
| `tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main` | pins `git diff main` empty over the frozen engine paths; LLR-153.1 is the named engine-layer crossing (B99-I1), so the guard fires BY DESIGN — its own docstring says an engine touch "forces the change to be classified by hand" | orchestrator decision: classify the named crossing (whitelisting it is a requirement decision the implementer cannot make) |
| `tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main` | the `--name-only` cross-check of the same guard | same |
| `tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` | the repo-standing TC-027 executable guard: `git diff --name-only main` over `core.py` / `hexfile.py` / `range_index.py` / `validation/` / `tui/mac.py` — `s19_app/core.py` legitimately carries the LLR-153.1 predicate | same — same mechanism (working-tree-vs-`main` diff), same resolution (passes once the change is on `main`) |

Pre-existing, NOT this increment (pristine-`HEAD` baseline: fails identically on the unmodified tree):

| Test node | Baseline evidence |
|---|---|
| `tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber` | re-run in a `git archive HEAD` tree: same failure (one `changes.json`, no dedup sibling) |

Snapshot cells (`tests/test_tui_snapshot.py`, 33 nodes): all 33 pass at pristine HEAD; 16 cells changed under the fix and were regenerated with `--snapshot-update` scoped to exactly those 16 node ids. Per-cell proof: pre-update SVGs backed up (`snapshot-pre-b99-inc2/`, 16 files) and a per-cell text-element MULTISET diff (`repin-snapshot-svg-multiset.txt`) shows every delta is the disappeared 6-byte S0 range ("STRESS" header at 0x0): `5 → 4 regions/rng`, coverage `0.0008% → 57.1429%`, the `0x00000000` hex-window row replaced by one more real data row, the map inspector/band switching to the first real region, and scrollbar-glyph churn. No unexplained text in any cell. Final full-suite re-run: see `green-snapshot.txt` (33 passed).

| Field | Value |
|---|---|
| **Reverse census** | 5 probes (B1, B3, B4, A3 executed; B2 n/a) — 15 census failures triaged to 8 S0-phantom re-pins, 2 freeze-guard STOPs in the census population (+1 standing guard listed at F3: `tests/test_engine_unchanged.py::test_tc027…` fails by the same working-tree-vs-`main` mechanism but was not in the 27-file census population), 1 pre-existing failure, 4 contention flakes; 16 snapshot cells re-pinned with per-cell SVG multiset proof; B3 hit re-validated as a dated plan artifact |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| S0 payload bytes entered the image/ranges/lookup/overlap | every S19 record walk feeding the image | grep `for record in .*records` over `s19_app/` + the six named walks of LLR-153.1/153.2 | 6 walks across 2 SOURCE files | 6 | all other walks audited and named in §1 with reasons |

| Field | Value |
|---|---|
| **Correction population** | one behaviour, six walk sites, two SOURCE files |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|----------------------------|----------------------|
| none — no marker superseded | n/a | n/a | n/a |

### Signed-balance test ledger

`post = base − deleted + added` → `6 = 0 − 0 + 6`  ✓ reconciles
(`tests/test_b99_s0.py`: 0 baseline nodes — new file — 0 deleted, 6 added:
TC-B99-04 + its boundary node, TC-B99-05, TC-B99-06, TC-B99-07, AT-B99-02.
Re-pins — 8 census nodes, 16 snapshot cells, 2 golden captures (AT-288,
AT-054b md+html) — mutate pinned values, not node counts. Review round 1
(F1/F2/F5) rewrites AT-B99-02 and TC-B99-06 in place — no node added or
deleted; F4 rewrites the AT-040a colour branch in place; F6 re-points one
constant in `tests/test_report_service.py`.)

### Review round 1 fixes (code-reviewer F1–F6)

All six findings fixed; no SOURCE file touched in the fix round (tests,
goldens and evidence only). No test node was added or deleted — the fixes
rewrite pinned probes inside the existing nodes.

| # | Finding | Fix | Evidence |
|---|---|---|---|
| F1 [HIGH] | AT-B99-02's Memory-Map check was vacuous: every row starts with a band glyph (`░ 0x00000000 …`), so `startswith("0x00000000")` could never fire | assertion replaced with `not any(re.search(r"\b0x00000000\b", r) for r in rows)`; the unneeded `app.update_memory_map()` call dropped (the rows fill without it). Re-ran the S0 re-admit mutation against **step 4 alone** (steps 3 and 5 temporarily commented out of the drive): step 4 goes RED — the mutated walk paints an S0 row carrying `0x00000000`, the exact case the old probe stayed GREEN on | `mut-F1-step4.txt` |
| F2 [MED] | AT-B99-02 drove internals: `Input.value = …`, `Button.press()`, reads of `app.current_file` and `has_class` | the whole drive is now keys/clicks: `pilot.click("#id")` to focus, `pilot.press(*text)` to type, `pilot.click` for every button; the load wait observes the painted status line (`Loaded firmware.s19`); the save-back prompt wait observes the painted screen (`export_screenshot` text elements — the snapshot idiom); the guard-modal wait likewise. The drive is also more realistic: the prompt lives in the editor's JSON pane, so the drive clicks `#patch_tab_json` first (the b97 idiom); viewport 120×54 so the docked prompt row is actually painted and clickable. Stability: 8/8 consecutive runs pass | `stability-at02.txt`, `green-fix-b99_s0.txt` |
| F3 [MED] | the freeze-guard STOP list named only two guards | all three listed now (§4 STOP table + §6): `test_tc031…no_diff_vs_main`, `test_tc031…no_name_only_diff_vs_main`, `tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` — all diff the working tree against `main`, all pass once the change is on `main`, LLR-153.1 names the crossing. No test edited | this packet |
| F4 [MED] | AT-040a's colour branch split case_04's single invalid range by hand and assigned made-up ranges/validity | the branch now builds a temporary S19 — S0, a 16 B valid S3 block at `0x80030000`, a 16 B gap, a 32 B bad-checksum S3 block at `0x80030020`, S9 — and asserts the loader's own computed `ranges == [(0x80030000, 0x80030010), (0x80030020, 0x80030040)]` / `range_validity == [True, False]` before observing the painted bars; the sev-ok ≠ sev-error oracle is unchanged | `green-fix-directionb.txt` |
| F5 [MED] | TC-B99-06 could not catch the mutation on the two checksum-defective files: the defective-source arm only asserted reader-byte preservation, which the S0 re-admission mutation also satisfies | the defective-source arm now asserts `set(written.data) - set(oracle.data)` ⊆ the addresses of the file's checksum-defective records, parsed straight from the defective lines (`_defective_record_addresses`). Under the S0 re-admission mutation the two defective files gain `0x0..0xB` → the arm is RED | `mut-F5.txt`, refreshed `mut-LLR-153.1.txt` |
| F6 [MED] | packet §2 file list incomplete; a sealed batch-92 evidence record was overwritten; the `red-tc_b99_07.txt` SHA-256 row had 65 hex digits | §2 now lists every changed file (5 test files incl. the 3 re-pinned ones, 16 SVGs, 3 golden captures, 2 SOURCE, docs). `.dev-flow/2026-10-11-batch-92/evidence/at288-pre-move-report.bin` restored to its batch-92 bytes (`git checkout a52e2be -- …`, sha256 `061ee94c…`, byte-equal to the `.pre-b99-inc2` backup); the S0-free capture now lives at `tests/goldens/batch99/at288-pre-move-report.bin` and `tests/test_report_service.py::_AT288_CAPTURE` points there (re-pin recorded: batch-92 evidence path → batch99 golden — LLR-153.1). Every evidence-table row re-hashed | `green-fix-at288.txt` |

Fix-round transcripts: `stability-at02.txt` (8/8 passed),
`green-fix-census-companions.txt` (corpus+census 28 passed; hexview+entropy
40 passed; before/after 15 passed), `green-fix-pilot.txt` (b99_s0 6 passed;
AT-288 1 passed; snapshot 33 passed; directionb full file), `mut-F1-step4.txt`,
`mut-F5.txt`, refreshed `mut-LLR-153.1.txt` (6/6 nodes RED under the re-run
mutation). Digests in the evidence table below.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: changes required (F1 HIGH: the Memory Map assertion in AT-B99-02 was vacuous; F2–F6 MEDIUM: pilot-driven AT, third freeze guard unlisted, made-up ranges in at040a, TC-06 hole on checksum-defective files, packet file list and a sealed batch-92 evidence file rewritten) · round 2: OK to advance, F1–F6 closed; two LOW hash typos re-computed by the orchestrator from the files. The orchestrator also fixed a LoadGuardScreen compose race in AT-B99-02 before review (8/8 stable). The three freeze guards (`test_tc031_*` ×2, `test_tc027_*`) diff the working tree against `main` and pass once merged |

---

## 5 · Risks

- The checksum-defective examples (`case_04_bad_checksums`, both copies) carry
  a data record whose checksum fails. The app loads its bytes into the image
  (record flagged invalid); the independent reader skips them. TC-B99-06
  asserts exact reader equality only for well-formed sources and reader-byte
  preservation for the two defective ones. If the batch intends
  "written == independent reader" literally for checksum-defective sources,
  that needs a checksum-policy decision (outside this increment's 2-file
  budget) — declared in §6.
- `emit_s19_from_mem_map` always writes an S0 record (empty when no header is
  forwarded). A source without an S0 therefore round-trips with a legacy empty
  S0 — data addresses are unaffected, but byte-level identity with the source
  is not claimed for the header line.
- `docs/architecture.md` §B99-I1/R18 cites pre-increment line numbers for the
  six walks (the doc is dated "PDR, before Inc 2"); the predicate insertion
  shifted `core.py` lines by 24. Left as a dated plan artifact.

## 6 · Pending items / spec deviations

- **STOP — freeze guards (orchestrator decision required; all three, F3):**
  `tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main`,
  `tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main`
  and `tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main`
  fail BY DESIGN of the named engine-layer crossing (LLR-153.1 names the
  crossing; B99-I1 records the contract change). All three diff the working
  tree against `main`, so each passes as soon as this change lands on `main`.
  The tests' own docstrings say an engine touch "forces the change to be
  classified by hand" — the implementer classified it as the sanctioned
  crossing and did NOT modify any guard (whitelisting is a requirement
  decision, not an implementer decision).
- **Pre-existing failure (not this increment):**
  `tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber`
  fails identically on a pristine `git archive HEAD` tree (one `changes.json`,
  no dedup sibling) — re-verified in the baseline worktree.
- TC-B99-06 oracle semantics for the two checksum-defective examples:
  strict reader equality is impossible without deciding whether a
  checksum-defective data record declares its addresses (the loader says yes,
  the reader says no). This increment asserts: written == loaded image
  exactly, and every reader-accepted byte preserved. The AT (case_01,
  well-formed) asserts the strict form end-to-end.
- Brief vs app discrepancy (declared): the brief says "Open the Patch Editor
  (`p`)", but binding `p` is Load project (`app.py:1401`); Patch Editor is
  rail key `6` (`app.py:1422`), Memory Map is `4` (`app.py:1420`). AT-B99-02
  drives the real bindings and records them in its comments.
- Four pilot nodes (`test_saveback_width_32…`, `test_saveback_width_16…`,
  `test_at057b…`, `test_at064c…`) failed only under CPU contention from
  concurrent diagnostic probes; they pass on idle re-runs. Final idle
  transcript: `census-repinned.txt`.

## 7 · Suggested next task

Batch-99 Increment 3a (HLR-155 / `tests/test_b99_staging.py`): private staging
placement for `copy_into_workarea` / `save_patched_image` (B99-I2).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 SOURCE files (`git status`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_s0.py` (6 nodes, this increment) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | `_is_data_record` exercised by TC-B99-04/05 |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: 6 per-node baseline REDs + mutation KILLED 6/6, restore digest `6821f378…` |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 27-file census, 8 phantom re-pins with old → new records, 2 STOPs in the census population + TC-027 standing guard (F3), 1 pre-existing, 4 flakes; 16 SVG cells proven S0-only |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — 2 SOURCE + 1 test + evidence |
| 8 | Frozen interfaces untouched | all | ✓ | names/parameters unchanged (B99-I1: "Names and parameters unchanged"); the crossing is named in LLR-153.1 |
| 9 | Coverage claims verified **on disk** | all | ✓ | TC-B99-04/05 read the manifest + corpus from disk; TC-B99-06 round-trips 22 on-disk sources; AT reads the written file from disk |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive control (the mutation) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: KILLED 6/6, arms GREEN: none |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 4 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: one behaviour, six walks, two files |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 3 emitted artifacts asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` |
| 16 | **Evidence files** declared | all | ✓ | §4: 33 artifacts + the snapshot SVG backup directory, every row re-hashed (round-1 65-digit row corrected) |
