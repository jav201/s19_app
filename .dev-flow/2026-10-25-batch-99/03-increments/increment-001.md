# Increment 001 — HLR-152 · `Synthetic corpus + independent reader`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `001` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-141 / HLR-152 / LLR-152.1 · LLR-152.2 · LLR-152.3` |
| Acceptance | `AT-B99-01` · white-box `TC-B99-01 · TC-B99-02 · TC-B99-03` · unit `none (no shipped source)` |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: the batch's external oracle now exists. A new independent reader
(`tests/support/independent_reader.py`) parses S19 and Intel HEX into
address→byte images plus header/terminator/EOF facts, importing nothing from
`s19_app`. A new deterministic generator
(`tests/fixtures/synth/generate.py`) writes a 16-file corpus (S19, Intel HEX,
MAC, A2L) plus `manifest.json` with per-file SHA-256, coverage classes, data
bytes as contiguous runs, verdicts and load facts. `generate.py --check`
re-generates into a temp dir, compares byte for byte with the committed
corpus, then reads every S19/HEX file with the independent reader and
compares against the manifest — printing `checked 16 files` and exiting 0,
or printing the first differing file name and exiting 1.

The A2L pair pins every PQ-4 item: `MOD_COMMON BYTE_ORDER MSB_FIRST`; a
2-byte symbol whose RECORD_LAYOUT declares no `BYTE_ORDER` (only `MOD_COMMON`
supplies it); `RAT_FUNC_DIV_10` with ASAM COEFFS `0 10 0 0 0 1` (INT = 10·PHYS,
raw 300 ↔ phys 30, stored `01 2C`); `TAB_INTP` with step 2.5/raw over the
physical range 0..62.5 (strictly inside (−50, 500)), a grid value (5.0 → raw 2)
and an in-range off-grid non-tie value (3.4 → nearest raw 1, written physical
2.5, flag names "2.5"); `TAB_NOINTP` holding 10.0 with the next entry 15.0
and none at 13.0 (typed 13.0 refused, naming 10.0 and 15.0); a LINEAR control
`LINEAR_MUL_2` (PHYS = 2·RAW) declaring `BYTE_ORDER MSB_LAST` explicitly —
the ASAM little-endian token; `LSB_FIRST` is not an ASAM `BYTE_ORDER` token
(`s19_app/tui/a2l.py` returns `None` for it) — so it stays little-endian
(`0F 00`) under the `MSB_FIRST` module (encode 30 → `0F 00`). Expected values live in the manifest under
`a2l_expect`.

Shipped surface the user reaches: the maintainer's command line —
`python tests/fixtures/synth/generate.py --check`.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `.gitattributes` | config | — | append `tests/fixtures/synth/** -text` (corpus bytes are hashed; no EOL conversion either direction) |
| `tests/support/__init__.py` | test | — | new (package marker for `tests.support`) |
| `tests/support/independent_reader.py` | test | HLR-152, LLR-152.3 | new: `read_s19` / `read_hex` → `Image`, zero `s19_app` imports |
| `tests/fixtures/synth/generate.py` | fixture | HLR-152, LLR-152.1 | new: deterministic corpus generator, `--out` / `--check [--corpus]` |
| `tests/fixtures/synth/manifest.json` | generated | LLR-152.2 | new: 16 entries, sha256 + classes + data runs + verdict + load facts + `a2l_expect` |
| `tests/fixtures/synth/*.s19` (10 files) | generated | LLR-152.2 | new corpus: S1/S2/S3 width edges, S0, S5, S7/S8/S9 non-zero entries, S0-only empty image, MAC pair, A2L pair, 3 S19 defects, overlap |
| `tests/fixtures/synth/*.hex` (4 files) | generated | LLR-152.2 | new corpus: types 00/01/02/04/05, 64 KiB-boundary record, segment wrap, 2 HEX defects |
| `tests/fixtures/synth/synth_mac.mac` | generated | LLR-152.2 | new: one address inside the image, one outside |
| `tests/fixtures/synth/synth_a2l.a2l` | generated | LLR-152.2, PQ-4 | new: A2L pinning MOD_COMMON byte order, RAT_FUNC, TAB_INTP/TAB_NOINTP geometry, MSB_LAST LINEAR control |
| `tests/test_b99_corpus.py` | test | HLR-152 | new: TC-B99-01..03 + AT-B99-01 |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-001.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-1/*` | doc | — | transcripts, hashes, probes (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **0 / 4** |
| Test files | 3 (uncapped) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; no file under `s19_app/` touched; `prototypes/` untouched.

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # must print a path inside the worktree
python tests/fixtures/synth/generate.py --check        # -> "checked 16 files", exit 0
pytest tests/test_b99_corpus.py -v                     # -> 5 passed
pytest tests/test_b99_corpus.py -k tc_b99_01           # -> 1 passed, 4 deselected
pytest tests/test_b99_corpus.py -k tc_b99_02           # -> 1 passed, 4 deselected
pytest tests/test_b99_corpus.py -k tc_b99_03           # -> 1 passed, 4 deselected
pytest tests/test_b99_corpus.py -k tc_b99_04           # -> 1 passed, 4 deselected
pytest tests/test_b99_corpus.py -k at_b99_01           # -> 1 passed, 4 deselected
pytest tests/test_address_census.py -q                 # -> 23 passed
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | none — this increment ships no shipped-source node (tests/fixtures only); LLR-152.1–152.3 are unit-layer and are verified by the TCs below | n/a |
| **A · white-box** `TC-B99-01..04` ↔ LLR-152.1..152.3 | `core` · `full` | `test_tc_b99_01_deterministic` · `test_tc_b99_02_coverage_classes` · `test_tc_b99_03_reader_independence_and_exact` · `test_tc_b99_03b_hex_extents_literal` | 4 passed |
| **B · black-box** `AT-B99-01` ↔ US-141, through `generate.py --check` | `core` · `full` | `test_at_b99_01_check_mode` | 1 passed |

Regression companion: `tests/test_address_census.py` — 23 passed.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | three, one per LLR (see Mutation verdicts below): timestamp into the S0 text · drop one coverage class from the manifest · copy the S0 payload into the reader's data map — all re-applied on the review-round-1 fixed tree (see Review round 1 fixes) |
| Instrument | project code: the implementer's own hand via the Edit tool / a JSON edit, restore checked by SHA-256 |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc1`), run by the implementer |
| Transcript | `evidence/inc-1/mut-LLR-152.1.txt` · `mut-LLR-152.2.txt` · `mut-LLR-152.3.txt` (each: node FAILED) |
| Restore proven by | file hash returned to its pre-mutation value (review-round-1 fixed tree; see Review round 1 fixes): generate.py → `9bcdc26d145fd177d50092eb13f6f3699d89b5cdfa78e648b9d7a26e66b7f059`; manifest.json → `f5fa3eb77d9d05348c1c323dab4c9fbfa89212b32e4a03e617739206cf2ecd7f`; independent_reader.py → `b9a172e21a3e215b9e455515fb7b2d61fc4326d8705f2f87797ddd40970ccb76` (also recorded in `baseline-hashes.txt`) |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46); `__pycache__` never created under `tests/support` or `tests/fixtures` |
| Arms resolved at baseline | 1 per mutation run (each `-k` run resolves exactly 1 node + 3 deselected) — asserted: 1 |
| Verdict granularity | per resolved node id: `test_tc_b99_01_deterministic`, `test_tc_b99_02_coverage_classes`, `test_tc_b99_03_reader_independence_and_exact` |
| Arms that stayed GREEN | none |

| Field | Value |
|---|---|
| **RED counterfactual** | the LLR-152.1 mutation (`_s19_content` in `generate.py` appends `datetime.now().isoformat()` to the S0 payload) makes THIS increment's own determinism assertion fail — `evidence/inc-1/mut-LLR-152.1.txt` shows `test_tc_b99_01_deterministic FAILED`; restore digest `9bcdc26d…` returned `generate.py` to its pre-mutation bytes. Baseline RED (tests absent): `red-initial-collection.txt` (module not found), `red-no-corpus.txt` (4 failed). |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-152.1 · TC-B99-01: timestamp into S0 text · KILLED (re-run on the fixed tree) · arms GREEN: none · transcript `mut-LLR-152.1.txt` · restore `9bcdc26d…` ‖ LLR-152.2 · TC-B99-02: `mac.pair` dropped from the `synth_mac.mac` manifest entry · KILLED (re-run on the fixed tree; first fix-round attempt applied the drop to `generate.py` only and SURVIVED — TC-B99-02 reads the committed manifest from disk, so the mutation must land in `manifest.json`) · arms GREEN: none · transcript `mut-LLR-152.2.txt` · restore `f5fa3eb7…` ‖ LLR-152.3 · TC-B99-03: `read_s19` copies the S0 payload into `data` at 0x0 · KILLED (re-run on the fixed tree) · arms GREEN: none · transcript `mut-LLR-152.3.txt` · restore `b9a172e2…` ‖ F4 negative control · TC-B99-03b: `read_hex` segment wrap broken (`seg + ((addr + i) & 0xFFFF)` → `seg + addr + i`) · KILLED — `test_tc_b99_03b_hex_extents_literal FAILED` (TC-B99-03 also failed: the manifest on disk no longer matched) · transcript `mut-F4.txt` · restore `b9a172e2…` |

**Surviving-mutant caught and fixed during this increment (declared):** the first
LLR-152.2 attempt dropped `mac.pair` while it was tagged on BOTH the `.mac` and
the paired `.s19` entry — the mutant SURVIVED (transcript overwritten by the
re-run; the run showed `test_tc_b99_02_coverage_classes PASSED` under the
mutation). Root cause: a coverage class with two owners can lose one silently.
Fix folded into this increment: every coverage class has exactly ONE owner
entry (`mac.pair` → `synth_mac.mac`, `a2l.pair` → `synth_a2l.a2l`). The
mutation was then re-applied and KILLED (`mut-LLR-152.2.txt`).

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the tree before the new modules exist (`tests/support` absent) | `ModuleNotFoundError: No module named 'tests.support'` — collection ERROR (`red-initial-collection.txt`) |
| `pytest` + TC-B99-01 | `generate.py` with `datetime.now()` injected into the S0 text | `test_tc_b99_01_deterministic FAILED` — differing files (`mut-LLR-152.1.txt`) |
| `generate.py --check` | corpus copy with one byte flipped in `synth_s1.s19` | printed `synth_s1.s19` and exited 1 (`instrument-redproof-check.txt`: `exit=1`) |
| AST import census (in TC-B99-03) | same census run on `tests/test_b97_width.py`, which does import `s19_app` | census roots include `s19_app` → `s19_app present: True` (`emitted-a2l-pins.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the corpus + `manifest.json` (emitted by `generate.py --out`) | `generate.py --check` regenerates and compares byte-for-byte, verifies each file's SHA-256 against the manifest, and reads every S19/HEX with the independent reader | `checked 16 files`, exit 0 (`emitted-check.txt`) |
| `synth_a2l.a2l` (emitted fixture text) | `grep -n "BYTE_ORDER\|COEFFS\|COMPU_TAB_REF\|DEFAULT_VALUE\|VALUE 0x" tests/fixtures/synth/synth_a2l.a2l` | `BYTE_ORDER MSB_FIRST` at line 9; `COEFFS 0 10 0 0 0 1` at line 29; `COEFFS_LINEAR 2.0 0.0` at line 33; both `COMPU_TAB_REF`s; both COMPU_TABs in ASAM field order (name, long identifier, conversion type, pair count, pairs, then quoted `DEFAULT_VALUE "0"`); the five `VALUE 0x…` lines with the COMPU_TAB symbols' limits strictly beyond their table ranges; `BYTE_ORDER MSB_LAST` at line 101 (`emitted-a2l-pins.txt`, refreshed in review round 1) |
| `generate.py --check` stdout (emitted report line) | direct CLI run against the committed corpus | `checked 16 files` (`emitted-check.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-1/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| GREEN after the TC-B99-03b id rename (5 passed) | `green-rename-corpus.txt` | `e9557167349a0232287fed6e7fa3828d4b65a5ad52933e0fc1486cba31baff8e` |
| RED baseline (no modules) | `red-initial-collection.txt` | `522c5af7776e027b57e0a8952aee6f06c91612517ab0374e165c95bb613b7252` |
| RED baseline (tests in, corpus out) | `red-no-corpus.txt` | `056ffc76d366234d42df4c75d361345856ef279daaba2c38ccf5647559c55c81` |
| GREEN full run (4 passed) | `green-full.txt` | `b28d9d4fb54d74b63124f2024c47009c5cddaa4129ea97ebfecce25a91710dd7` |
| GREEN TC-B99-01 | `green-tc_b99_01.txt` | `a87c8fdcd1adc97fb4896fec636a9c21290a12055b2dacdc6a123725b5e002e1` |
| GREEN TC-B99-02 | `green-tc_b99_02.txt` | `b8cee2de486a9c2554ffb75e4976e539658f961a4b80432b6d43af28b4dc030` |
| GREEN TC-B99-03 | `green-tc_b99_03.txt` | `8681a192f056bf31e90a2cd453fde92d8d1ddae8d5b435c4363c5cb16915b344` |
| GREEN AT-B99-01 | `green-at_b99_01.txt` | `5d7737e4af54944c920852c0cae5b67a03caf5df3e8f1de683191d35fa8a1e1d` |
| GREEN regression companion | `green-address-census.txt` | `5bfd63c88ad09be005ee5395614b41ba9589df552c4c236225972bc26704bfd7` |
| GREEN fix round: full corpus run (5 passed) | `green-fix-corpus.txt` | `8c4eeafae8e2da99f51a7676528b809e32ed4d577b918d7f0d7743cfac497585` |
| GREEN fix round: regression companion (23 passed) | `green-fix-address-census.txt` | `18f40c11abf28277250594db308f6d424485f711f140895410969cc73a77fc0e` |
| Mutation LLR-152.1 (KILLED, re-run on fixed tree) | `mut-LLR-152.1.txt` | `e47e0daa0d141ea0024f64ee7c10b32f237e32008efb390b5af08781b8aea569` |
| Mutation LLR-152.2 (KILLED, re-run on fixed tree; first attempt survived) | `mut-LLR-152.2.txt` | `bb240893fc9600dfcc4890a157a852ac6439a0b9159caacaf795afdc1bf517a1` |
| Mutation LLR-152.3 (KILLED, re-run on fixed tree) | `mut-LLR-152.3.txt` | `db5da9c647a57878b972557c899a33c238dcb4da5d8a5b9498861f7d626a8b5f` |
| Mutation F4 negative control (KILLED — reader segment wrap broken) | `mut-F4.txt` | `7dfa176171c503c74a6329c11467a5785ce4a46f2cb2945db3ab5b6cfbb12a37` |
| Instrument RED-proof (`--check` tampered arm) | `instrument-redproof-check.txt` | `90345b598cae08ecd7de0a580aa471db076587d392bfd11d4d8bcb71dc9d4039` |
| Emitted-form: `--check` stdout | `emitted-check.txt` | `471f79851d60478ad5d383855ce2cfd5152cab10bc0d1929435045215ee18d5f` |
| Emitted-form: A2L pins + census positive control (refreshed in review round 1) | `emitted-a2l-pins.txt` | `86688d47b32399e3db8088e00f6bc008a66ab56f675c1989930dc46ce526de48` |
| Reverse census probes | `reverse-census.txt` | `5b4cc3d301b5f80ab4a00e1b91ee9f4f8a3f7110032c7a7781bd534fbe57d83d` |
| Pre-mutation hashes (fixed tree) | `baseline-hashes.txt` | `7f0f7ec42c4df6d6eadd5fd2782ee15d0fecfed372bcdefa1a06718d16935abe` |

`SHA256SUMS.txt` is the folder's own digest list: LF line endings, the sums
file excluded from its own list. Digests are of the bytes as committed at
HEAD for files unchanged since Inc-1 (`git show HEAD:<path> | sha256sum`);
the eight marked working-tree (WT) files — the fix-round transcripts
(`green-fix-*`, `mut-*`) and the refreshed `baseline-hashes.txt` /
`emitted-a2l-pins.txt` — are hashed as working-tree bytes because they are
new or re-generated in review round 1 and are committed by the orchestrator
with this packet.

| Field | Value |
|---|---|
| **Evidence files** | 19 artifacts, each at the declared home and cited with the digest of its stored bytes |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) the reader holding ZERO `s19_app` imports; (2) the generated bytes holding NO timestamp or host path |
| If the result is an ABSENCE, what made the search wide enough | (1) the AST census walks every `Import`/`ImportFrom` node at any depth and takes the module ROOT, so `from s19_app.x import y`, `import s19_app`, and relative-parent tricks all surface; (2) determinism is checked as byte-identity of two full `--out` runs (every file, not a sample) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b99_03_reader_independence_and_exact` — the census assertion is its own named test node; `test_tc_b99_01_deterministic` — the byte-identity assertion is its own named test node |
| Conjunctive criteria: one mutation per conjunct | no conjunctive criterion — each guard is a single assertion with its own mutation (LLR-152.3 mutates the reader's data map; LLR-152.1 mutates the S0 text with a timestamp) |
| Synthetic instance of the absent case | the LLR-152.3 mutant IS a reader that does the forbidden thing (mixes S0 payload into `data`) — it exists only as a transient mutation, reverted by hash; the timestamp mutant is the synthetic non-determinism instance |
| **Positive control for every probe that returned an ABSENCE** | (1) the same census over `tests/test_b97_width.py` returns `s19_app present: True` (non-absent output of the identical probe, `emitted-a2l-pins.txt`); (2) the timestamp-injected generator makes the identical determinism probe return differing files (`mut-LLR-152.1.txt`) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "independent_reader\|read_s19\|read_hex" tests/` | 3 hits — `tests/test_b99_corpus.py`, `tests/fixtures/synth/generate.py`, `tests/support/independent_reader.py` — all this increment's own; no foreign consumer to re-validate |
| B2 file moved on disk | n/a — no pre-existing file moved; new files only (probe declared, nothing to glob) | no readers found — nothing lost |
| B3 byte-identical golden captures this source | `grep -rl synth tests/goldens/` | 1 hit: `tests/goldens/batch64/addendum-below-bound.md` — re-validated: the word "synthetic" in old CHG-SYNTAX prose lines, unrelated to this corpus; **no re-pin** |
| B4 artifact produced here is consumed elsewhere | `grep -rln "fixtures/synth\|synth_a2l\|synth_mac\|manifest.json" tests/` | 3 hits — all this increment's own; later increments (Inc-2+) are the declared future consumers and read only the manifest/reader APIs documented in §1 |
| A3 interface consumed by another module changed | n/a — no `s19_app/` symbol changed (0 SOURCE files); the frozen engine layer is untouched | no hits possible |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes declared (B1, B3, B4 executed; B2, A3 named n/a) — 1 B3 hit, re-validated as unrelated; no test re-pinned |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| none — this increment corrects no behaviour; it adds fixtures, tests and tooling only | n/a | n/a | 0 | 0 | n/a |

| Field | Value |
|---|---|
| **Correction population** | none — no correction |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| none — no marker superseded | n/a | n/a | n/a |

### Signed-balance test ledger

`post = base − deleted + added` → `5 = 0 − 0 + 5`  ✓ reconciles
(`tests/test_b99_corpus.py`: 0 baseline nodes — new file — 0 deleted, 5 added:
TC-B99-01..03, TC-B99-03b + AT-B99-01; TC-B99-03b added in review round 1, finding F4)

### Review round 1 fixes (code-reviewer findings F1–F5)

The independent review returned **changes required**; all five findings are
fixed in this tree (working tree only, no commit). SOURCE files touched: 0
(fixture generator + tests only).

| Finding | Severity | What changed |
|---|---|---|
| F1 — `LSB_FIRST` is not an ASAM `BYTE_ORDER` token | HIGH | `tests/fixtures/synth/generate.py` (`_a2l_text`, `_a2l_expect`): `LINEAR_MUL_2` now declares `BYTE_ORDER MSB_LAST` (ASAM little-endian token; stays `0F 00` under the `MSB_FIRST` module); manifest `byte_order` for that symbol is `MSB_LAST`; matches amended contract LED-2026-10-25-batch-99.4 / LLR-158.1. Corpus regenerated; this packet's canary text updated. |
| F2 — COMPU_TAB blocks must follow the ASAM grammar | MEDIUM | Both COMPU_TAB blocks re-laid-out on the `examples/case_00_public/ASAP2_Demo_V171.a2l:2965` model: name, quoted long identifier, conversion type, pair count, the pairs, then a quoted `DEFAULT_VALUE "0"`. The stray `"%6.2" ""` Format/Unit pair is gone. |
| F3 — limits must not equal the table ranges | MEDIUM | `TAB_INTP_SYM` limits `0 62.5` → `-10 100`; `TAB_NOINTP_SYM` limits `10 20` → `0 30` — strictly beyond the table ranges, so a later test can tell "outside the table range" from "outside the limits". No recorded `a2l_expect` value depended on the old limits (refused probes −50/500 stay outside; typed-refused 13.0 stays inside the limits but outside the table). |
| F4 — HEX manifest check is common-mode | LOW | New node `test_tc_b99_03b_hex_extents_literal` in `tests/test_b99_corpus.py`: pins every HEX file's address extents LITERALLY — hand-written `(start, end)` runs from the Intel HEX spec, including the type-02 segment-wrap case and the type-04 64 KiB-boundary case — read with the independent reader, computed by neither the generator nor the reader. RED proof: the F4 mutation (break the reader's segment wrap) turns it RED (`mut-F4.txt`). |
| F5 — evidence hygiene | LOW | `SHA256SUMS.txt` rewritten: LF line endings, the sums file excluded from its own list, one line per evidence file. Files unchanged since Inc-1 are hashed as committed (`git show HEAD:<path>`); the eight fix-round files are hashed as working-tree bytes (they are new or re-generated in this round and are committed by the orchestrator with this packet) — noted explicitly in the Evidence files section. |

Post-fix verification: corpus regenerated, `generate.py --check` →
`checked 16 files` (exit 0); `tests/test_b99_corpus.py` 5 passed
(`green-fix-corpus.txt`); `tests/test_address_census.py` 23 passed
(`green-fix-address-census.txt`); the three C-40 mutations re-applied on the
fixed tree, all KILLED and restored by SHA-256 (`mut-LLR-152.1/2/3.txt`), plus
the F4 mutation (`mut-F4.txt`). One surviving mutant caught in this round: the
first re-run of the LLR-152.2 mutation dropped `mac.pair` from `generate.py`
only and SURVIVED, because TC-B99-02 reads the committed manifest from disk —
the mutation must land in `manifest.json` (documented in Mutation verdicts
above).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: changes required (F1 HIGH `LSB_FIRST` not an ASAM token; F2, F3 MEDIUM; F4, F5 LOW) · round 2: OK to advance, F1–F5 closed; one MEDIUM (test id `TC-B99-04` collided with LLR-153.1) fixed by the orchestrator: renamed `test_tc_b99_03b_hex_extents_literal` (TC-B99-03b, part of LLR-152.3), re-run `green-rename-corpus.txt` (5 passed). F1 traced to the contract: LED-2026-10-25-batch-99.4 |

---

## 5 · Risks

- The corpus is the byte oracle for every later increment. If one needs a class
  this corpus lacks (e.g. an S6 count record, a HEX type 03, a wider A2L
  table), its increment must extend `generate.py` + the manifest and re-run
  all four TCs — fixture files are uncapped, but the extension is a packet-visible change.
- Convention risk: the reader reports a HEX type 05 record as
  `terminator == ("HEX05", address)`. Later ATs must reuse that shape; it is
  documented in the reader docstring and exercised by TC-B99-03 on
  `synth_hex_basic.hex`.
- `a2l_expect` pins the LLR-158.3 semantics ("nearest raw + a flag naming the
  written physical") and LLR-158.2's ASAM RAT_FUNC direction (INT = f(PHYS)).
  If Phase 3 settles a different rounding rule for in-range TAB_INTP values,
  the manifest's `off_grid` block is amended by ledger, not silently.
- `tests/fixtures/synth/** -text` keeps corpus bytes verbatim; a CI job that
  re-normalizes line endings would break every recorded SHA-256. The
  `.gitattributes` rule is the guard.
- The TAB_NOINTP/limits pins assume the app's A2L parser accepts
  `BYTE_ORDER` inside a CHARACTERISTIC block (it does at HEAD,
  `s19_app/tui/a2l.py:2390-2392`); if a later refactor moves that, AT-B99-09's
  MSB_LAST control is the canary.

## 6 · Pending items / spec deviations

- None blocking. Declared: the first LLR-152.2 mutation attempt survived
  because `mac.pair` had two owner entries; fixed in-increment (single-owner
  classes) — see §4 Mutation verdicts.
- The committed corpus is 17 artifacts, 14 505 bytes total (limit: 200 KB).

## 7 · Suggested next task

Batch-99 Increment 2 (HLR-153 / LLR-153.x, `tests/test_b99_s0.py`): the S0
phantom fix. Its oracle arms consume `tests/support/independent_reader.py`
and the S0-bearing corpus files (`synth_s1.s19`, `synth_s2.s19`,
`synth_s3.s19`, `synth_s0_only.s19`) this increment ships.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 0 SOURCE files (`git status` — no `s19_app/` change) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_corpus.py` (5 nodes, this increment — TC-B99-03b added in review round 1, F4) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — no shipped-source node in this increment; unit-layer LLRs verified by TC-B99-01..03 |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: mutations with transcripts + restore digests; baseline RED `red-initial-collection.txt` / `red-no-corpus.txt` |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 5 probes, B3 hit re-validated unrelated, no re-pin |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — only new files + `.gitattributes` |
| 8 | Frozen interfaces untouched | all | ✓ | 0 files under `s19_app/`; ARCHITECTURE §7 engine untouched |
| 9 | Coverage claims verified **on disk** | all | ✓ | TC-B99-02 reads `tests/fixtures/synth/manifest.json` from disk; TC-B99-03 reads all 14 S19/HEX files from disk |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (census on `test_b97_width.py`; timestamp mutant) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: per-arm KILLED, inert arms named (first 152.2 attempt survived → fixed → re-run KILLED) |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 4 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: none — no correction |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 3 artifacts asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` (the one published form for a not-yet-reviewed packet) |
| 16 | **Evidence files** declared | all | ✓ | §4: 19 artifacts with stored-byte SHA-256 digests |
