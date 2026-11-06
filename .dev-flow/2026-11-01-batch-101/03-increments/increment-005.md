# Increment 005 — Inc 5 · R-CRC-PREVIEW-002.x, R-CHKED-010, -025…-027, -041.x, -054…-057 · CRC Designer refreshes after in-place writes; Check Editor keeps picks, names and spec bytes; validation results clear after a write

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-5/`: `01-requirements.md` (US-CRC-FRESH-2, US-CHK-KEEP-1, US-CHK-SPEC-1; R-CRC-PREVIEW-002.1/-002.5, R-CHKED-010, -025, -026, -027, -041.1/.2/.3, -054, -055, -056, -057), `02-test-cases.md` (40 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md`, `E3-rulings.md`, `E3-security.md`, `E4-impl-notes-{app,ched}.md`, `E4-tester1-notes.md`, `E4-tester2-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc5.md`, `evidence-e1/`, and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-5/`. Branch `b101-inc5` from `main` (base `c2cba35`), head `87b429af` plus the uncommitted E5 records and this packet.

Models per stage (from `steps.log` and the orchestrator's assignment): Opus — E1–E3 (requirements, rulings, both design reviews, the E3 corrective), the E4 integration step, the E5 code and security reviews and the E5 corrective pass; DeepSeek v4 Pro — the E4 implementers (2 units), the E5 mutant battery, and this record; Sonnet — the E4 independent testers (×2); qa-reviewer (Opus) — the coverage audit and re-audit.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `005` |
| Lane (if the batch forked) | none — single lane |
| Requirement(s) | R-CRC-PREVIEW-002.1 · -002.5 · R-CHKED-010 · -025 · -026 · -027 · -041.1 · -041.2 · -041.3 · -054 · -055 · -056 · -057 (stories US-CRC-FRESH-2, US-CHK-KEEP-1, US-CHK-SPEC-1) |
| Acceptance | the 40 cases of `02-test-cases.md`; black-box by keys and dialogs: AT-I5-1 … AT-I5-4; white-box: the 58 nodes of the two new test files plus the re-pinned symbol-reads node; unit: the 18 functions of `E1-slice.md` §2 (codewire graph nodes) |
| Agent | `software-dev` |
| Date | 2026-11-06 |

---

## 1 · What changed

The three in-place writes into the loaded image — a Patch Editor apply (whatever its status), a Patch Editor save-back (whatever its outcome) and a Save project commit — now tell the CRC Designer that the image's bytes were written, so the coverage preview recomputes after the quiet time while the designer is displayed and turns stale while it is hidden, recomputing once on its next display. The Check Editor keeps the operator's included parameters across a ledger repopulation when the loaded A2L still lists them, resolves each entry of a picked spec to its named parameter from the loaded A2L (or loads it as an unlabelled memory row), keeps a spec's declared bytes keyed by (name, address, size) so Write and Validate never re-baseline a spec field from the image, demotes a parameter the new A2L moved, renamed or resized into an unlabelled memory row at the spec entry's own address with the spec's bytes, and clears its validation results after an in-place write (the new row R-CHKED-057). The mechanism is one `app.py` helper (`_note_image_bytes_written`) called at the three write sites, delegating to `CrcDesignerPanel.note_image_bytes_written` (Inc 13's `_on_image_changed`) and `CheckEditorPanel.clear_check_results` (each queried separately, a missing panel skipped).

## 2 · Files modified

Committed: `git diff --stat main...HEAD` (77 files, +11 494 / −50). Uncommitted: the E5 re-audit/re-review records, the STEP 1 refresh of R-CHKED-056's Base column in `01-requirements.md`, the `steps.log` E5-end line, and the two new records below (`04-validation.md`, this packet). SOURCE files: **3 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | US-CRC-FRESH-2 · US-CHK-KEEP-1 · US-CHK-SPEC-1 | new `_note_image_bytes_written` (tells the CRC Designer and, at E5 C-10, clears the Check Editor's validation results); hook calls after the apply `try`/`except` (`:4913`), after `save_patched` whatever `result.ok` (`:5046`), and after `adopt_rederived` when `request.image` is set (`:12642`); spec-pick items carry `expected` and `symbol`; `_check_items_to_document` declares a spec field's bytes without reading the image; docstrings fixed (C-7) |
| `s19_app/tui/crc_designer_view.py` | source | US-CRC-FRESH-2 | new public `note_image_bytes_written`, a one-statement delegate to Inc 13's `_on_image_changed`; `Data Flow` added (C-9) |
| `s19_app/tui/screens_directionb.py` | source | US-CHK-KEEP-1 · US-CHK-SPEC-1 | `_spec_bytes` keyed by (name, address, size); memory rows become 4-tuples; `set_a2l_parameters` re-includes earlier picks the new ledger still lists and demotes the rest; `load_spec` resolves each entry through `_named_parameter`; new `_named_parameter`, `_prune_spec_bytes`, `_demote_moved_spec_params` and public `clear_check_results` (E5 C-10) |
| `tests/test_b101_designer_writes.py` | test | US-CRC-FRESH-2 | new file: 10 designer nodes (002.1/6, 002.5/3 … /9) with `zlib.crc32` oracle and the recompute counter; E5 corrective AT-I5-4 and the snapshot-before-trigger moves (C-3) |
| `tests/test_b101_check_spec_keep.py` | test | US-CHK-KEEP-1 · US-CHK-SPEC-1 | new file: 26 Check Editor nodes (010, 054, 055, 041.1–.3, 025–027, 056, 057) plus AT-I5-1 … AT-I5-3; E5 corrective preconditions, deciding cases and the 3/3 runs |
| `tests/test_b101_symbol_reads.py` | test | US-CHK-SPEC-1 | the `test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` node re-pinned (F-27: the symbol tag is now included as a parameter) |
| `tests/test_id_registry.py` | test | US-CHK-KEEP-1 · US-CHK-SPEC-1 | `EXPECTED_SCANNED_TEST_FILES` 262 → 264 (two new test modules, measured) |
| `docs/user-guide/ch10-check-editor.md` | doc |  | §10.6–§10.8 state the admitted visible changes (§1 (5)–(7)); the stale F-01 sentence deleted (C-8) |
| `.dev-flow/2026-11-01-batch-101/inc-5/01-requirements.md` | doc |  | 13 active + 1 withdrawn EARS rows over the three stories, amended Definitions, and the Base columns |
| `.dev-flow/2026-11-01-batch-101/inc-5/02-test-cases.md` | doc |  | 40 ISO 29119-3 cases; audited and re-audited at E5 |
| `.dev-flow/2026-11-01-batch-101/inc-5/E1-rulings.md` | doc |  | E1 scope census, canon changes, decisions D-1 … D-5 / E1-D1 … E1-D9, §6 backlog rows |
| `.dev-flow/2026-11-01-batch-101/inc-5/E1-slice.md` | doc |  | the implementation slice: 18 functions in 3 source files (13 changed, 5 new) |
| `.dev-flow/2026-11-01-batch-101/inc-5/E3-architect.md` | doc |  | E3 design review: FAIL, A-1 MAJOR, A-2 … A-6 MINOR |
| `.dev-flow/2026-11-01-batch-101/inc-5/E3-rulings.md` | doc |  | E3 orchestrator rulings SEC5-1 … SEC5-6 / A-1 … A-6 and round 2 (R2-1) |
| `.dev-flow/2026-11-01-batch-101/inc-5/E3-security.md` | doc |  | E3 design security review: FAIL — BLOCK-UNTIL SEC5-1, then round 2 PASS-WITH-NOTES |
| `.dev-flow/2026-11-01-batch-101/inc-5/E4-impl-notes-app.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, app unit) |
| `.dev-flow/2026-11-01-batch-101/inc-5/E4-impl-notes-ched.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, Check Editor + guide unit) |
| `.dev-flow/2026-11-01-batch-101/inc-5/E4-integration-notes.md` | doc |  | E4 integration (Opus): GREEN, I-D1 … I-D7, §4 runs, the E4 mutant table |
| `.dev-flow/2026-11-01-batch-101/inc-5/E4-tester1-notes.md` | doc |  | E4 tester 1 (Sonnet, designer writes) notes: RED on base |
| `.dev-flow/2026-11-01-batch-101/inc-5/E4-tester2-notes.md` | doc |  | E4 tester 2 (Sonnet, Check Editor) notes: RED on base |
| `.dev-flow/2026-11-01-batch-101/inc-5/E5-code-review.md` | doc |  | E5 code review: PASS-WITH-NOTES, F1 MAJOR, F2–F3 MINOR, F4–F6 NIT |
| `.dev-flow/2026-11-01-batch-101/inc-5/E5-corrective-notes.md` | doc |  | E5 corrective pass C-1 … C-11, sites, M25–M30, the 3/3 runs |
| `.dev-flow/2026-11-01-batch-101/inc-5/E5-coverage-audit.md` | doc |  | E5 coverage audit (29.4 %) + re-audit (PASS, 0 marks to change) |
| `.dev-flow/2026-11-01-batch-101/inc-5/E5-mutants.md` | doc |  | E5 mutant table M1 … M24, 24/24 KILLED |
| `.dev-flow/2026-11-01-batch-101/inc-5/E5-rulings.md` | doc |  | E5 orchestrator rulings C-1 … C-11 and the re-review/re-audit residuals RA-1 … RA-5 |
| `.dev-flow/2026-11-01-batch-101/inc-5/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES, E5-S1 MEDIUM, E5-S2/S3 INFO, + re-review |
| `.dev-flow/2026-11-01-batch-101/inc-5/codewire/graph-inc5.md` | doc |  | Code-wire graph: 18 nodes (incl. `clear_check_results`), 3 entities |
| `.dev-flow/2026-11-01-batch-101/inc-5/steps.log` | doc |  | Stage log, models and UTC stamps (E5 end appended at close) |
| `.dev-flow/2026-11-01-batch-101/inc-5/04-validation.md` | doc |  | This increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-005.md` | doc |  | This packet (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-5/evidence-e1/i5e1-pilot-transcript.txt` | generated | US-CRC-FRESH-2 · US-CHK-KEEP-1 · US-CHK-SPEC-1 | the E1 confirmation pilot: D-4 reproduced, F-27 and D9-11 reproduced, F-26 not |
| `.dev-flow/2026-11-01-batch-101/inc-5/evidence-e1/i5e1-pilot.py` | fixture | US-CRC-FRESH-2 · US-CHK-KEEP-1 · US-CHK-SPEC-1 | the pilot instrument that produced the transcript |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-01.txt` … `int-09.txt` | generated | US-CRC-FRESH-2 · US-CHK-KEEP-1 · US-CHK-SPEC-1 | E4 integration runs (int-01 58 passed; int-02 2428 passed/2 known; int-03, int-05 base; int-04 488 passed/2 known; int-06 117 passed; int-07 58 passed serial; int-08 399 passed; int-09 52 passed) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-5/e5c-01.txt` … `e5c-12.txt` | generated | US-CRC-FRESH-2 · US-CHK-KEEP-1 · US-CHK-SPEC-1 | E5 corrective runs (e5c-01 RED 9/1; e5c-02 68 passed; e5c-03/e5c-04 33 passed; e5c-05 … e5c-10 M25–M30; e5c-11 103 passed; e5c-12 2 passed) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-5/mut-01.txt` … `mut-24.txt` | generated | US-CRC-FRESH-2 · US-CHK-KEEP-1 · US-CHK-SPEC-1 | the DeepSeek mutant battery, one transcript per mutant, 24/24 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-5/red-01-tester1-base.txt` | generated | US-CRC-FRESH-2 | tester 1 RED on base: 8 failed, 2 standing guards |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-5/red-01-tester2-base.txt` | generated | US-CHK-KEEP-1 · US-CHK-SPEC-1 | tester 2 RED on base: 21 failed, 6 standing guards |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** |
| Test files | 4 (2 new, 2 changed; uncapped) |
| Config files | 0 |
| Doc files | 23 (`.dev-flow` records, the guide chapter, this packet; outside the count) |
| Generated | 49 transcripts/scripts under `evidence/inc-5/` and `inc-5/evidence-e1/` |

## 3 · How to test

```bash
# the three guard files, non-timing lane (LAN Linux host, s19ci Python 3.11)
python -m pytest -q -p no:cacheprovider -n 8 -m "not serial_timing" \
  tests/test_b101_designer_writes.py tests/test_b101_check_spec_keep.py tests/test_b101_symbol_reads.py
# serial-timing lane, quiet host
python -m pytest -q -s -m serial_timing \
  tests/test_b101_designer_writes.py tests/test_b101_check_spec_keep.py tests/test_b101_symbol_reads.py
# the law guards
python -m pytest -q -n 8 -m "not serial_timing" \
  tests/test_address_census.py tests/test_suite_hygiene.py tests/test_id_registry.py \
  tests/test_engine_unchanged.py tests/test_requirements_canon.py tests/test_docs_canon.py \
  tests/test_filename_markup_safety.py tests/test_import_census.py
```

All of these ran on the LAN Linux host only (operator rule); nothing that imports `s19_app` ran on the Windows PC. Transcripts: `evidence/inc-5/int-01.txt` … `int-09.txt` (E4), `e5c-01.txt` … `e5c-12.txt` (E5 corrective).

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | `tests/test_b101_designer_writes.py` (10) + `tests/test_b101_check_spec_keep.py` (26) + `test_b101_symbol_reads.py` (22 non-serial) | **58 passed** (`int-01`), **68 passed** after the E5 additions (`e5c-02`); **2 passed** serial (`e5c-12`); 40 cases, 36 covered / 4 partial / 0 gap after the re-audit |
| **A · neighbours** | QC-BC set (51 files) + the 24 other importers of `screens_directionb` / `crc_designer_view` | **2428 passed, 2 failed, 107 skipped, 1 xfailed** (`int-02`) + **488 passed, 2 failed** (`int-04`); the 4 failures identical on base (`int-03`, `int-05`) |
| **B · black-box** (keys and dialogs) | AT-I5-1 (Add + Write), AT-I5-2 (apply + pick + Write + Validate), AT-I5-3 (moved A2L + Write), AT-I5-4 (save-back confirm by keys) | passed in `e5c-02`; all four RED on base (`e5c-01`) |
| **Guards** | `test_address_census`, `test_suite_hygiene`, `test_id_registry`, `test_engine_unchanged`, `test_requirements_canon`, `test_docs_canon`, `test_filename_markup_safety`, `test_import_census` | **117 passed** (`int-06`), **103 passed** (`e5c-11`); serial **58 passed, 2 skipped** (`int-07`), **52 passed, 2 skipped** (`int-09`) |

Details: `inc-5/04-validation.md`.

### RED counterfactual

| Field | Value |
|---|---|
| **RED counterfactual** | The two new test files on base `c2cba35`: tester 1 (designer) **8 failed, 2 passed** (`red-01-tester1-base.txt`) and tester 2 (Check Editor) **21 failed, 6 passed** (`red-01-tester2-base.txt`); every failure behavioural, the passes the design's holds-on-base standing guards. The E5 corrective's own nodes went RED on base **9 failed, 1 passed** (`e5c-01`, the pass being 002.5/9's declared standing guard), and each corrective mutant M25–M30 turned its guard nodes RED (`e5c-05` … `e5c-10`). |

| Field | Value |
|---|---|
| **Mutation verdicts** | 30 mutants, per-node verdicts in `E5-mutants.md` (M1–M24) and `E5-corrective-notes.md` (M25–M30): **30 KILLED, 0 SURVIVED, 0 BAD** (24/24 DeepSeek at `8fc3cd3` + 6/6 in the corrective). The security-reviewer subset in `E5-security.md` adds **12/12 KILLED** over the E3 mitigations' named controls. Transcripts `evidence/inc-5/mut-01.txt` … `mut-24.txt` and `e5c-05.txt` … `e5c-10.txt`. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 3 instruments shown RED before their PASS was believed: the new test files on base (8 + 21 failed — `red-01-tester1-base.txt`, `red-01-tester2-base.txt`); the mutant harness (unmutated copy GREEN, every mutant non-zero — `E5-mutants.md` baseline 30 passed, 24/24 KILLED); the coverage audit (first pass changed 10 of 34 cases and named the four owed black-box ATs — `E5-coverage-audit.md`). |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts asserted against the form the product emits: the written `.chk.json` read back with the independent S19 reader and matched entry-for-entry against the spec's declared bytes (R-CHKED-026, -056, -025); the CRC preview and window line 2 matched against `zlib.crc32` of the session range bytes (R-CRC-PREVIEW-002.5/*, -002.1/6); the painted Check Editor status/Fields/verdict lines, exact (R-CHKED-057's cleared state and the `Checks: …` lines). All passed in `int-01` / `e5c-02`. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 (`sha256sum`) of the bytes at the cited path, taken 2026-11-06. The transcripts live in `.dev-flow/2026-11-01-batch-101/`, the home `artifact_homes.evidence` declares.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| int-01.txt | evidence/inc-5/int-01.txt | 47a325e7e7736b01780270a9b1232b8e9c5bfd0036384cdd38a453d337bd6b3c |
| int-02.txt | evidence/inc-5/int-02.txt | d1cc0d2b45e90f10435ad378993846462a64885341ca57cbdcff5abbcd7746f4 |
| int-03.txt | evidence/inc-5/int-03.txt | e09ed0d6c51f016e8953ce526bad118f7e9ed111aa19bf5f607545c3d45ff382 |
| int-04.txt | evidence/inc-5/int-04.txt | 62bdcc948c71f6d6035abe66b9267cba5b422459b1ff283ca1c0ab65437f42d4 |
| int-05.txt | evidence/inc-5/int-05.txt | 325f660178b9f138c9563699ed661f3332d43d93747c996693387368f92e19c2 |
| int-06.txt | evidence/inc-5/int-06.txt | d67cbb3499162181c28c1dbc04af35177bef1c5bd5e6d4777d153882ee69e30d |
| int-07.txt | evidence/inc-5/int-07.txt | 4f1f50583797a46cbe712e53cb1011ce9b7c496687a68010e163ea29161f53ca |
| int-08.txt | evidence/inc-5/int-08.txt | 607885b99504f042c28850bd6f778ca50767759d04e57e34f5101f7d82d6ea3b |
| int-09.txt | evidence/inc-5/int-09.txt | 9cc113d0b13284478066633d23bda385c1fcc15751b681848d5014b30c9dea1c |
| e5c-01.txt | evidence/inc-5/e5c-01.txt | a143f55b842efa342a81943cf4d710a01c41091380d310c633c980c7471dc82e |
| e5c-02.txt | evidence/inc-5/e5c-02.txt | ceefc95870382eb821ce4df2290ba0ed477961c03809910fbc7adec331ad9026 |
| e5c-03.txt | evidence/inc-5/e5c-03.txt | 5eb620d1b78b653908084ab7ad6e4fa6adbb4c6ac4851bca869e79aa49ac97fd |
| e5c-04.txt | evidence/inc-5/e5c-04.txt | c248d7250e4abde3e3ca84c8803a4c2711939c83a233dbda03b8b9ab0f945ed4 |
| e5c-05.txt | evidence/inc-5/e5c-05.txt | a38bc9b1940d80a931fd956ac698f0793ec536ecf2fb1062245e158b864d6d37 |
| e5c-06.txt | evidence/inc-5/e5c-06.txt | adb62dd1cb734747bfcd71624acb7c40754d2a0d3a5cc19797dceea38a6a5563 |
| e5c-07.txt | evidence/inc-5/e5c-07.txt | 36dbe1e3efcf1b5b29a249a1e64e3b3a8255d14a0fc2b2a04a9a3180bf2618ba |
| e5c-08.txt | evidence/inc-5/e5c-08.txt | db244f3cfb519e149bf0bdfd206916399c06d0cfe8f746bfd1069377349229bd |
| e5c-09.txt | evidence/inc-5/e5c-09.txt | b4e0e7f4a5fd13fa24bd2ea267d05ba8fc7d54d4be58665b76a3fa49b67bd01b |
| e5c-10.txt | evidence/inc-5/e5c-10.txt | 22b2a20d0abd1c3e4ac00a5476933c680955f20cef6aa82fbd6f55dc95f04d16 |
| e5c-11.txt | evidence/inc-5/e5c-11.txt | 1488c931db2588757096c11cbd493410648f8c638424aafebd89836191b5f28e |
| e5c-12.txt | evidence/inc-5/e5c-12.txt | 0087097e434aa2e82318c85d12ad0024bc6936f0b11db42d31fbcd1e3ae6e111 |
| mut-01.txt | evidence/inc-5/mut-01.txt | b55d78fa9920cc7fb047bf37bf962a9ab5f4ad06f11a7be92159b304ea1a7662 |
| mut-02.txt | evidence/inc-5/mut-02.txt | 2acbae7e3f7b7c9ae8c85dd50cbb1ee1ecef7e3986a32abe180df4f4eabd1764 |
| mut-03.txt | evidence/inc-5/mut-03.txt | 09b02ec739fdf3cc4edfaefeb0affe010de6127a4454d55d669acc96b0462180 |
| mut-04.txt | evidence/inc-5/mut-04.txt | 228b5743bce742909b363a875345fe9efb8cc73d590b664f6a170c425967e6d3 |
| mut-05.txt | evidence/inc-5/mut-05.txt | 1ebafa28ca8659563c388563ebde803205a45166a66f14db82c7fead504a937a |
| mut-06.txt | evidence/inc-5/mut-06.txt | da5b282d2b8b8a0cd85d0fe7bf530cff8c23db4f2284d28eef7625c727e0f07f |
| mut-07.txt | evidence/inc-5/mut-07.txt | 51c474380d98a41ce2a0fc63743625fd92e9f4a45aa9392425bfb0c06c80d1e0 |
| mut-08.txt | evidence/inc-5/mut-08.txt | 6cb5f2b2dce473cea0d698826efc1737874448bdd7a72fcccc2e33dbaf4ebed5 |
| mut-09.txt | evidence/inc-5/mut-09.txt | 8f36d89fe2e33edf81c90ae63891c68753b57a6b2e6ec174ba979035b94f3983 |
| mut-10.txt | evidence/inc-5/mut-10.txt | c0ba8274cf9ddcfa66f112292efc1debb6c3202302db3e5ced95d40f0e0158a5 |
| mut-11.txt | evidence/inc-5/mut-11.txt | 10551685db02ec8804111f4a3ab666264d848ac95b913e53a736ec3f5670d19f |
| mut-12.txt | evidence/inc-5/mut-12.txt | 5f073c5cb340b759341cb527f5377d97612d925d6891b2b1afecbf6ad2c97790 |
| mut-13.txt | evidence/inc-5/mut-13.txt | cc053eec95d8d55fc750e2d5140488f506126951cae93ba28ff11cefbb56d98b |
| mut-14.txt | evidence/inc-5/mut-14.txt | eb49ee2be0b22f6249f9c2f68934d6a081a752c74e4d3a543b3a21e9b76ab1cf |
| mut-15.txt | evidence/inc-5/mut-15.txt | 1ef57cc50dd4afb6728927a6322acec843e1aa341d65c2ac7d3fbc0a5b1e6c08 |
| mut-16.txt | evidence/inc-5/mut-16.txt | adcf714d224d4f030ef0ed128f829210c3738ededede452b19f6ba279b084178 |
| mut-17.txt | evidence/inc-5/mut-17.txt | c1ffe24e6792fbdd9c701b1d57c3b10c517f4f3783201821d270249c27939ef3 |
| mut-18.txt | evidence/inc-5/mut-18.txt | 69e639af5c6e8b844626365b049369b1ec8f980830ddc31e0e7e1c493d3e6dde |
| mut-19.txt | evidence/inc-5/mut-19.txt | fa37e6161dba14a800fb8d9d1456e91f1ffb20e6bca204deb1acaf380b71d48a |
| mut-20.txt | evidence/inc-5/mut-20.txt | c7104b095a8328ee4c1e2a279f93efdbea8ab94ed70fc770549044c91e8aabc2 |
| mut-21.txt | evidence/inc-5/mut-21.txt | dcde23096dfdfcc0fd5337a1c90ae9887153599bb09dbf7098b53c338a23a444 |
| mut-22.txt | evidence/inc-5/mut-22.txt | 1e493d6057c8d4992341918499d3d3d29f8dc7e5aabe4eee739e8857fc78b764 |
| mut-23.txt | evidence/inc-5/mut-23.txt | fada22ec348e86c98a097ae48dd0f34818ab96202e2b592517c05e3211b2abb9 |
| mut-24.txt | evidence/inc-5/mut-24.txt | a8bda88caaff9e41d90a94a1ef1ce004ea9bf1012cdb1c17e4054f3e37a7c72d |
| red-01-tester1-base.txt | evidence/inc-5/red-01-tester1-base.txt | 06b2c27b76b58ea3fcf0b366186cb05171c736dd37aa3dc11b3013e55043f89e |
| red-01-tester2-base.txt | evidence/inc-5/red-01-tester2-base.txt | 457fdd4846a3bdef5487b843b87e1619e53211e5e0494a89c051c48e4a338752 |
| i5e1-pilot-transcript.txt | inc-5/evidence-e1/i5e1-pilot-transcript.txt | 819600b0a585421f00b6e33ab8100b8394009d8eb83dc80e380f0052fb1733e4 |

| Field | Value |
|---|---|
| **Evidence files** | 48 transcripts, each cited with the digest of its stored bytes, all under the home `artifact_homes.evidence` names |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: "the census of in-place writers is complete" (exactly three code paths write the session map) and "no other read missed the A2L parameter" |
| If the result is an ABSENCE, what made the search wide enough | the write census `grep -rnE "mem_map\[…\] *="` plus the callers of `apply_change_document`, `_restore_journal`, `adopt_rederived`, `save_patched` over `s19_app` (E1 §1, re-run by the architect and the code reviewer) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | the three hook-site tests (002.5/3 … /8) that pin each write path; `test_control_other_patch_actions_do_not_mark_the_coverage_stale` |
| Conjunctive criteria: one mutation per conjunct | R-CHKED-057's clear has the status line and the 0-rows conjuncts; M29 removes the call and kills all three alternatives at once |
| Synthetic instance of the absent case | the planted moved / renamed / resized A2Ls written by the test, and the fixture image with the `zlib.crc32` oracle constants |
| **Positive control for every probe that returned an ABSENCE** | M1–M3, M5–M7 each removed one hook site and turned its nodes RED (`E5-mutants.md`), proving the three write sites are the only ones |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | the QC-BC set (51 files) and the 24 other importers of `screens_directionb` / `crc_designer_view` | 2428 passed / 2 known failures (`int-02`) and 488 passed / 2 known (`int-04`); all 4 failures identical on base (`int-03`, `int-05`) |
| B2 file moved on disk | no file moved; no product function deleted — the three source files are edited in place | 0 product readers of a moved path |
| B3 byte-identical golden captures this source | `grep -rl "crc_designer_view\|screens_directionb\|app.py" tests/goldens/` | no hit — no golden captures the three changed sources |
| B4 artifact produced here is consumed elsewhere | the written `.chk.json` the Check Editor emits | read back by the R-CHKED-025/026/056 tests with the independent S19 reader |
| A3 interface consumed by another module changed | `CrcDesignerPanel.note_image_bytes_written`, `CheckEditorPanel.clear_check_results` (new public methods); `_named_parameter`, `_prune_spec_bytes`, `_demote_moved_spec_params`, `_note_image_bytes_written` (new private) | no existing public signature changed; the two new public methods have their only callers inside `_note_image_bytes_written` / the app |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict: B1 re-validated every hit by running it (the 4 failures are the batch's known ones, identical on base); B2 no move/deletion; B3 no goldens; B4 the test readers; A3 additive methods only. |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| case records that no longer matched the strengthened tests or the audit | every `02-test-cases.md` row whose Tests / Coverage / Result no longer matches its test | the coverage audit's row-by-row read (`E5-coverage-audit.md` §1–§3, C-1 … C-6) | 10 substantive mark/coverage changes + the record-wide Result and header fixes + 6 cases added at E5 (R-CHKED-057/1–/3, 041.2/4, 010/4, 002.5/9) | all, by the E5 corrective pass (rulings C-1 … C-11) | none; re-audit: 40 cases, 36 covered, 4 partial, 0 gap |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated by the audit (§1–§3, C-1 … C-6) before the corrective pass edited its first site: 10 substantive mark/coverage changes (29.4 %) + the record-wide Result/header fixes + the 6 cases added at E5. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `264 = 262 − 0 + 2` (`tests/test_id_registry.py`, measured, I-D4). Test cases `40 = 26 + 8 + 6` (E1 26, E3 +8, E5 +6). No test node deleted; 36 nodes added in the two new files and one node body re-pinned in `test_b101_symbol_reads.py` (E1-D5).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** (0 HIGH; F1 MAJOR design-gap on the R-CHKED-056 bytes clause, F2–F3 MINOR, F4–F6 NIT — all folded by the corrective pass C-1 … C-11 and re-read in the re-review) — `inc-5/E5-code-review.md`. `security-reviewer` · **PASS-WITH-NOTES** (HIGH 0; E5-S1 MEDIUM design-gap folded in as R-CHKED-057 through C-10, E5-S2/S3 INFO; re-review closed E5-S1 and F1, HIGH 0, MEDIUM 0) — `inc-5/E5-security.md`. `qa-reviewer` coverage audit (10 of 34 = 29.4 %, 4 owed black-box ATs) and re-audit (**PASS**, 40 cases, 36 covered, 4 partial, 0 gap) — `inc-5/E5-coverage-audit.md`. **Design reviews (E3, code-free):** `architect` **FAIL** (A-1 MAJOR, A-2 … A-6 MINOR, folded by `E3-rulings.md`) · `security-reviewer` **FAIL — BLOCK-UNTIL SEC5-1** (1 HIGH, 2 MAJOR, 2 MINOR, 1 INFO) then round 2 **PASS-WITH-NOTES** (SEC5-1, SEC5-2, SEC5-3, A-1 closed; R2-1 backlog) — `inc-5/E3-architect.md`, `inc-5/E3-security.md`. The independent `testers` (E4, Sonnet ×2) wrote the 36 nodes from the design records only and ran them RED on base — `inc-5/E4-tester1-notes.md`, `inc-5/E4-tester2-notes.md`. |

## 5 · Risks

- **The Check Editor can now write a spec its own pick refuses** (R2-1, MINOR, backlog): after a relayout A2L a session field can land on a demoted row's range and Write reports success for a colliding spec the pick would refuse. No false pass reaches a run; the root is pre-existing (a memory row over an included parameter).
- **Spec-held bytes are only kept while the ledger lists the name at the spec entry's range** (SEC5-4 limitation): a fast exclude-then-include handled before the bubbled `SelectionChanged` reaches the panel keeps the spec's bytes when the operator meant to re-baseline. No wrong value reaches a saved file.
- **Bidi/format characters in A2L names survive `safe_text`** (SEC5-5, pre-existing): Inc 5 now paints an A2L name the operator did not choose, at a spec pick. No spec-file string reaches a painted surface.
- **A raise inside `save_patched` after the adopt ends the app loudly**, so a missed notice cannot go unseen (the integrator's observation; the code reviewer's check 3a).

## 6 · Pending

- **The merge-time full suite** — this increment ran its slice, the QC-BC importers, the law guards and the serial lanes, but not all nodes in one lane.
- **The Inc 10 LAN check** of the A2L explorer's value column and the Split/Join window after an in-place write (D-4 / SEC5-6), before Inc 10's E1.
- **The canon-fold wording of R-CRC-PREVIEW-002.5/8** — reword the precondition to "the `0x8003` entry removed and a `0x9000` entry added" (I-D3).
- **E5-rulings RA-1 … RA-5 residuals** (none blocking): the batch-end mutant battery re-runs on the merged tree (RA-1); future units print `diff -u` in mutant transcripts (RA-2); backlog line for R-CHKED-041.2/4 and 041.3/1 controls and 010/4's base failure (RA-3); AT-I5-4's clipped-row visibility (RA-4); R-CHKED-057's refused/raising paths via the shared hook (RA-5).
- **Backlog rows** — R2-1 (Write/Validate run the collision rule), the E5-S1 remainder (clear verdicts on the other changes), SEC5-5 (bidi scrub), SEC5-3 (a visible provenance cue), D-3 (carry memory-row labels in `.chk.json`).
- **Uncommitted records** — this packet, `04-validation.md`, the R-CHKED-056 Base-column refresh in `01-requirements.md` (RR-3) and the `steps.log` E5-end line are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 5; run the full suite at batch end; hand the R-CHKED-056/Base and 002.5/8 wordings to the canon fold; run the Inc 10 LAN probe of the A2L explorer and Split/Join staleness before Inc 10's E1.

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 source files (`app.py`, `crc_designer_view.py`, `screens_directionb.py`); `E1-slice.md` §1 |
| 2 | Tests written in this same increment | all | ✓ | 2 new files + 1 re-pinned node + `test_id_registry.py` |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the 18 slice functions; `E1-slice.md` §2 |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | 8 + 21 failed on base (`red-01-tester1/2-base.txt`); e5c-01 9/1 |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | B1–B4, A3 above |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | `code-reviewer` PASS-WITH-NOTES, 0 HIGH (`E5-code-review.md`) |
| 7 | No file from another lane touched | all | ✓ | the 3 source files are this increment's slice |
| 8 | Frozen interfaces untouched | all | ✓ | no engine file edited; `test_engine_unchanged` passed (int-06) |
| 9 | Coverage claims verified **on disk** | all | ✓ | re-audit PASS, 40 cases (`E5-coverage-audit.md`) |
| 10 | Load-bearing emptiness declared | all | ✓ | the write census above |
| 11 | **Mutation verdicts** declared | all | ✓ | 30 KILLED, per-arm in `E5-mutants.md` / `E5-corrective-notes.md` |
| 12 | **Instrument RED-proof** declared | all | ✓ | 3 instruments above |
| 13 | **Correction population** declared | all | ✓ | the audit's 10 marks + 6 cases above |
| 14 | **Emitted-form assertion** declared | all | ✓ | 3 artifacts above |
| 15 | **Independent review** names somebody | all | ✓ | `code-reviewer` · `security-reviewer` · `qa-reviewer` · `architect` · `testers` |
| 16 | **Evidence files** declared | all | ✓ | 48 transcripts with digests above |
