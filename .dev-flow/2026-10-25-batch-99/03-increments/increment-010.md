# Increment 010 — HLR-158 · `A2L values encode and decode as the A2L declares`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `010` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict); map row `B99-I4` |
| Requirement(s) | `US-147 / US-152 / HLR-158 / LLR-158.1 · LLR-158.2 · LLR-158.3` |
| Acceptance | `AT-B99-09` (US-147, pilot) · `AT-B99-14` (US-152, codec API) · white-box `TC-B99-23 · TC-B99-24 · TC-B99-25` (+ review-fix `TC-B99-42 · TC-B99-43`) |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: the frozen A2L engine (`s19_app/tui/a2l.py`) now converts between
physical values and raw bytes **as the A2L declares**, on three limbs, and the
A2L window says `n/a` — with the reason — when it cannot decode.

1. **Effective byte order (LLR-158.1).** The fallback chain in
   `extract_a2l_tags` is now tag → RECORD_LAYOUT → tag endian →
   `MOD_COMMON BYTE_ORDER` → little. A new tree pre-pass
   (`_extract_mod_common_byte_order`) takes the first `MOD_COMMON` byte order;
   the tag's explicit `BYTE_ORDER` (ASAM tokens `MSB_FIRST`/`BIG_ENDIAN` → big,
   `MSB_LAST`/`LITTLE_ENDIAN` → little) still wins. Both the encode
   (`encode_physical_to_raw_bytes`) and the decode (enrichment) already read
   the resolved `effective_byte_order`, so one resolution serves both
   directions. On the corpus (module `MSB_FIRST`, layout `RL_U16_NO_BO`
   declaring none): `SYM_U16_MSB` encodes 4113 → `10 11` and decodes `10 11` →
   4113; the `MSB_LAST`-declared `LINEAR_MUL_2` keeps `0F 00` under the
   `MSB_FIRST` module.
2. **RAT_FUNC direction (LLR-158.2).** ASAP2 declares INT = f(PHYS) =
   (a·P² + b·P + c)/(d·P² + e·P + f). The **encode** now computes INT = f(PHYS)
   directly (`_eval_rat_func`); the **decode** solves f(P) = raw for P
   (`_invert_rat_func`, quadratic (a − r·d)P² + (b − r·e)P + (c − r·f) = 0),
   taking the root inside the tag's declared physical limits when exactly one
   is, else the smaller-magnitude root; no real root is a returned decode
   failure. `_apply_compu_method` gained an optional `limits` parameter; the
   enrichment and the E9 FNC-values limb pass the tag's limits. Corpus:
   `RAT_FUNC_DIV_10` (COEFFS `0 10 0 0 0 1`) encodes 30 → raw 300, 25 → 250 and
   decodes raw 300 → 30.0. LINEAR is untouched (raw 15 → 30.0 both ways).
3. **COMPU_TAB inversion (LLR-158.3).** `_reverse_table_lookup` now refuses
   instead of silently approximating: `TAB_NOINTP` rejects a value that is not
   exactly a table value, naming the two nearest (13.0 → "10.0 and 15.0");
   `TAB_INTP` rejects a value outside the table's physical range, naming the
   range (500.0 / −50.0 → "[0.0, 62.5]"); an in-range value encodes the nearest
   table entry's raw and returns a **flag** naming the physical value that will
   actually be written when it differs from the typed one (3.4 → raw 1, flag
   "the value 3.4 is not a table value - the write proceeds as 2.5"); a grid
   value encodes with no flag (5.0 → raw 2). `_invert_physical_to_raw` now
   returns `(raw, error, flags)`; both encode paths (scalar + R5 curve record)
   merge the conversion flags into their flag lists.
4. **`n/a` with the reason (US-147, UX-C8/UX-C10).** The A2L window's Physical
   cell shows `n/a` when the bytes are present but the conversion refused them,
   and stays blank when the tag has no bytes (app.py cell builder). The E9
   description modal reads `Scalar value: n/a (<reason>)` where the reason is a
   short enum-derived token from a fixed mapping (`rat_func_no_real_root`,
   `lookup_table_missing`, …) — never A2L text (UX-C10). The undecodable case
   renders e.g. `Scalar value: n/a (rat_func_no_real_root)`.

Shipped surfaces: the A2L window's Physical column + the E9 modal (US-147);
the codec API `encode_physical_to_raw_bytes` (US-152, P-22's declared
exception — no shipped TUI path calls the encoder).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/a2l.py` | SOURCE | HLR-158, LLR-158.1 | `_extract_mod_common_byte_order` + the `MOD_COMMON` step in the `extract_a2l_tags` fallback chain |
| `s19_app/tui/a2l.py` | SOURCE | HLR-158, LLR-158.2 | `_eval_rat_func` (encode direction) · `_invert_rat_func` re-purposed to the decode solve with root-in-limits selection · `_apply_compu_method` `limits` parameter + RAT_FUNC limb · limits threaded at the enrichment and E9 FNC call sites |
| `s19_app/tui/a2l.py` | SOURCE | HLR-158, LLR-158.3 | `_reverse_table_lookup` refuses naming nearest/range, flags off-grid writes · `_invert_physical_to_raw` returns `(raw, error, flags)` · both encode paths merge conversion flags |
| `s19_app/tui/a2l.py` | SOURCE | HLR-158, UX-C8/UX-C10 | `_DECODE_REASON_TOKENS` / `_short_decode_reason` · `describe_curve_tag` `scalar_reason` · `render_curve_description` `Scalar value: n/a (<reason>)` |
| `s19_app/tui/app.py` | SOURCE | HLR-158, UX-C8 | the A2L Physical cell: `n/a` when raw bytes are present but the conversion failed; blank when there are no bytes |
| `tests/test_b99_a2l_encode.py` | test | HLR-158 | new: TC-B99-23/24/25 + AT-B99-09 (pilot, both widths) + AT-B99-14 |
| `tests/fixtures/synth/generate.py` | fixture | LLR-158.3 | corpus gains the sparse TAB_INTP symbol `TAB_INTP_SPARSE_SYM` (`0x200C`); the file is created in increment-001 |
| `tests/fixtures/synth/manifest.json` | generated | LLR-158.3 | corpus gains the sparse TAB_INTP symbol `TAB_INTP_SPARSE_SYM` (`0x200C`); the file is created in increment-001 |
| `tests/fixtures/synth/synth_a2l.a2l` | generated | LLR-158.3 | corpus gains the sparse TAB_INTP symbol `TAB_INTP_SPARSE_SYM` (`0x200C`); the file is created in increment-001 |
| `tests/fixtures/synth/synth_a2l.s19` | generated | LLR-158.3 | corpus gains the sparse TAB_INTP symbol `TAB_INTP_SPARSE_SYM` (`0x200C`); the file is created in increment-001 |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-010.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-10/*` | doc | — | transcripts, hashes, probes (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 4** (`a2l.py`, `app.py`) |
| Test files | 1 (uncapped) |
| Doc files | 2 (outside the count) |

Review round 1 additions (same budget — still 2 SOURCE files): `s19_app/tui/a2l.py`
(F1 inverse interpolation, LOW-a per-module `MOD_COMMON`, LOW-b denominator-zero
root filter), `tests/fixtures/synth/generate.py` + the regenerated corpus trio
(`manifest.json`, `synth_a2l.a2l`, `synth_a2l.s19` — fixtures, uncapped) and
`tests/test_b99_a2l_encode.py` (sparse arms, TC-B99-42/27, black-box AT-B99-09,
exact-text assertions). `s19_app/tui/app.py` carries no fix-round change (the
clipping mutation was applied and reverted).

- ✓ No file from another lane touched; `prototypes/` untouched; the modal shell
  `s19_app/tui/a2l_describe.py` needed no change (it renders
  `render_curve_description`'s output verbatim).

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # must print a path inside the worktree
pytest tests/test_b99_a2l_encode.py -v                 # -> 7 passed (review round 1)
pytest tests/test_b99_a2l_encode.py -k tc_b99_23       # -> 1 passed, 6 deselected
pytest tests/test_b99_a2l_encode.py -k tc_b99_24       # -> 1 passed, 6 deselected
pytest tests/test_b99_a2l_encode.py -k tc_b99_25       # -> 1 passed, 6 deselected
pytest tests/test_b99_a2l_encode.py -k tc_b99_42       # -> 1 passed, 6 deselected (review fix LOW a)
pytest tests/test_b99_a2l_encode.py -k tc_b99_43       # -> 1 passed, 6 deselected (review fix LOW b)
pytest tests/test_b99_a2l_encode.py -k at_b99_09       # -> 1 passed, 6 deselected
pytest tests/test_b99_a2l_encode.py -k at_b99_14       # -> 1 passed, 6 deselected
python tests/fixtures/synth/generate.py --check        # -> checked 16 files
pytest tests/test_address_census.py -q                 # -> 23 passed
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-B99-23..25` ↔ LLR-158.1..158.3 | `core` · `full` | `test_tc_b99_23_byte_order_falls_back_to_mod_common` · `test_tc_b99_24_rat_func_direction_and_root_selection` · `test_tc_b99_25_compu_tab_refusals_and_flags` | 3 passed |
| **B · black-box** `AT-B99-09` ↔ US-147 (Textual pilot, 118x40 + 80x24) | `core` · `full` | `test_at_b99_09_a2l_window_physical_column` | 1 passed |
| **B · codec API** `AT-B99-14` ↔ US-152 (P-22 declared exception) | `core` · `full` | `test_at_b99_14_codec_api_encode_surface` | 1 passed |

Regression companions (all GREEN after the change, no re-pins):
`tests/test_tui_a2l.py test_a2l_enriched.py test_a2l_curve_description.py
test_a2l_record_layout_walker.py test_a2l_f841_cleanup.py
test_a2l_multiline_headers.py test_changes_symbol_entries.py
test_tui_public_api.py test_address_census.py` + the new module —
**158 passed, 3 skipped, 1 xfailed** (`green-affected.txt`);
`tests/test_tui_app.py` — **62 passed, 1 xfailed** (`green-tui-app.txt`);
`tests/test_tui_a2l_detail.py test_tui_a2l_issue_recolor.py
test_help_toggle_and_a2l_panel.py` — **16 passed** (`green-a2l-pilot.txt`);
`tests/test_tui_snapshot.py` — **33 passed, 29 snapshots passed**
(`green-snapshots.txt`).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none for the baseline RED — the tests ran against the **unmodified** tree (`red-initial.txt`, 5 failed): TC-23 saw `effective_byte_order == "little"` (P-7); TC-24 saw raw 300 → `3000.0`-class wrong-direction values (P-17); TC-25 saw silent nearest/clamp `err=None flags=[]` (P-8); AT-09's painted row showed `112650.0` for `RAT_FUNC_SYM` (P-17) and no `n/a` cell existed (P-7/P-17) |
| Instrument | project code: the implementer's own hand via the Edit tool; restore checked by SHA-256 |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc10`), run by the implementer |
| Transcript | `red-initial.txt` (5 failed) · per-LLR mutations: `mut-LLR-158.1.txt` · `mut-LLR-158.2.txt` · `mut-LLR-158.3.txt` (each: the resolved node FAILED) |
| Restore proven by | `s19_app/tui/a2l.py` returned to digest `3d88647a9c4c53a6b59a5799ba36d11aa22fdc48f701897c90f34ef61734ec85` after each mutation (`baseline-hashes.txt`, re-checked after the third revert) |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | 1 per mutation run (each `-k` run resolves exactly 1 node + 4 deselected) — asserted: 1 |
| Verdict granularity | per resolved node id: `test_tc_b99_23_byte_order_falls_back_to_mod_common`, `test_tc_b99_24_rat_func_direction_and_root_selection`, `test_tc_b99_25_compu_tab_refusals_and_flags` |
| Arms that stayed GREEN | none |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-158.1 · TC-B99-23: fallback chain reverted to skip `MOD_COMMON` (the `module_byte_order` step deleted) · KILLED — `test_tc_b99_23… FAILED` (`effective_byte_order` back to `"little"`) · transcript `mut-LLR-158.1.txt` · restore `3d88647a…` ‖ LLR-158.2 · TC-B99-24: RAT_FUNC direction swapped back to the old one (decode evaluates f directly, encode quadratic-inverts) · KILLED — `test_tc_b99_24… FAILED` (encode 30 no longer yields raw 300) · transcript `mut-LLR-158.2.txt` · restore `3d88647a…` ‖ LLR-158.3 · TC-B99-25: refusals reverted to silent nearest/clamp with no flag (P-8's exact behaviour) · KILLED — `test_tc_b99_25… FAILED` (`err=None`, no named values, no flag) · transcript `mut-LLR-158.3.txt` · restore `3d88647a…` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC/AT runner) | the unmodified tree (premises P-7/P-8/P-17 still true) | 5 failed — TC-23/24/25 + AT-09/14 all RED (`red-initial.txt`) |
| `pytest` + TC-B99-23 | `extract_a2l_tags` fallback skipping `MOD_COMMON` | `test_tc_b99_23… FAILED` (`mut-LLR-158.1.txt`) |
| `pytest` + TC-B99-24 | RAT_FUNC direction swapped | `test_tc_b99_24… FAILED` (`mut-LLR-158.2.txt`) |
| `pytest` + TC-B99-25 | silent nearest/clamp, no flag | `test_tc_b99_25… FAILED` (`mut-LLR-158.3.txt`) |
| independent reader oracle | a deliberately byte-swapped expectation for the corpus S19 | `FAILURE REPORTED (expected): deliberately wrong (byte-swapped) expectation` (`instrument-redproof-oracle.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 5 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| `encode_physical_to_raw_bytes` raw bytes | the returned tuple itself, against the manifest pins | 4113 → `(16, 17)` (`10 11`) · 30 → `(1, 44)` (`01 2C`, raw 300) · LINEAR 30 → `(15, 0)` (`0F 00`) (`emitted-form.txt`) |
| the refusal / flag strings (PQ-5: CONTENT, not presence) | the returned `error` / `flags` strings, verbatim | 13.0 → `the value 13.0 is not a table value - the nearest table values are 10.0 and 15.0` · 500 → `the value 500.0 is outside the table range [0.0, 62.5]` · 3.4 → `['the value 3.4 is not a table value - the write proceeds as 2.5']` (`emitted-form.txt`) |
| the enriched decode values | `physical_value` against `a2l_expect` (read from `manifest.json` on disk; image bytes via the independent reader) | `RAT_FUNC_SYM` → 30.0 (raw 300) · `SYM_U16_MSB` → 4113 (bytes `10 11`) (`emitted-form.txt`, `green-tc_b99_23/24.txt`) |
| the modal's rendered text (markup=False Static) | the painted screen text and the Static content at 118x40 AND 80x24 | `Scalar value: n/a (rat_func_no_real_root)` — full string paints at both widths (`green-at_b99_09.txt`) |
| the A2L table cells | `Text.plain` of the Physical cell per row (AT-069c idiom), both widths | `SYM_U16_MSB→4113 · RAT_FUNC_SYM→30.0 · TAB_INTP_SYM→5.0 · TAB_NOINTP_SYM→15.0 · LINEAR_MUL_2→30.0 · NO_ROOT_SYM→n/a · OUTSIDE_SYM→(blank)` (`green-at_b99_09.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 5 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-10/`
(digests also in the folder's own `SHA256SUMS.txt`, LF line endings, the sums
file excluded from its own list)

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| Import proof (this worktree) | `import-proof.txt` | `9399a89d6ecf992b95c307334d525fe67ce65f212ced17045bc3193ee5e44040` |
| RED baseline (unmodified tree) | `red-initial.txt` | `ee7063b0781a108cfb41972f18736b2d65f4988f1a61ac35003d5b508d192596` |
| GREEN full run (5 passed) | `green-full.txt` | `bd40e8c7519b38ed6a5be29c233e55ef5645356b93fbc4493f5ccc3dbb873b55` |
| GREEN TC-B99-23 | `green-tc_b99_23.txt` | `0f7610ecf362bc8aa97a9e30a90764b8fcf256c63c991e3e505a18856cf48663` |
| GREEN TC-B99-24 | `green-tc_b99_24.txt` | `6adbb2afda277812b68b4b637419842cb27e23314d71d9b8a17a13c4767c2892` |
| GREEN TC-B99-25 | `green-tc_b99_25.txt` | `c312e7495a4971dd61aea6488b8ffc2b9e0c925f20bab34c8e3c6e76983cefc2` |
| GREEN AT-B99-09 | `green-at_b99_09.txt` | `8ce1a83fd2cc8bc6d15f971009caf3bd130cd9fab7e5355eb98513ffcc03f729` |
| GREEN AT-B99-14 | `green-at_b99_14.txt` | `7a5ae4c961452666baafe2961b07c6a3eb70340b5b6ea8f2a071dbfaf37b7445` |
| GREEN affected files + census (158 passed) | `green-affected.txt` | `d53ec579ef6e8ad1b7a700b4eac5d8430edea19f5eb8a25c68345e183a9c7956` |
| GREEN tests/test_tui_app.py (62 passed) | `green-tui-app.txt` | `ba253a7604f94f8d6ceaac1c33f0cb5b347d7e754742fdfbe59cbc9820b4c9bf` |
| GREEN A2L pilot companions (16 passed) | `green-a2l-pilot.txt` | `6ce4354291bbb42e640db5ac663599dc7515d82e83c3c2eb0ba18b3e07108ad0` |
| GREEN snapshots (33 passed / 29 snapshots) | `green-snapshots.txt` | `73270cbedd1484f958bae9d101469fdbf3cbecb16d34f381fe27d89d058abe34` |
| Mutation LLR-158.1 (KILLED) | `mut-LLR-158.1.txt` | `728603f553dd3df73623749c88ca1504dd3b881043005dc5081652fc4d85a446` |
| Mutation LLR-158.2 (KILLED) | `mut-LLR-158.2.txt` | `3cb59a9851621a574377f08efb5202e33d5bd27fcb5bca2ee336666156055ff8` |
| Mutation LLR-158.3 (KILLED) | `mut-LLR-158.3.txt` | `dc02a5288630b1bc52c490c9d89035b8fab469f0973fb63ae7c8fb16afc45b34` |
| Instrument RED-proof (independent oracle) | `instrument-redproof-oracle.txt` | `763cf6141560a820526446eee8388e136da65f6da2e412aebccc54b45daf1a8a` |
| Emitted-form assertions | `emitted-form.txt` | `23849e0c31d2ea165ca1ae1e226b49685331cceaf4d7792b2eff790d84a4d5c1` |
| Reverse census probes | `reverse-census.txt` | `0d24dcef6a0926e90faa3b6f1dc0a89efb628d978b55ca3c98e0764776893743` |
| Pre-mutation hashes | `baseline-hashes.txt` | `bbcc7ddf472d0fd3297099d246863f110994a6eeb96617518c528acab22d3865` |

Import proof (C-46/precondition): `python -c "import s19_app; print(s19_app.__file__)"`
printed `C:\Users\jjgh8\Github\s19_app-b99-inc10\s19_app\__init__.py` — a path
inside this worktree.

| Field | Value |
|---|---|
| **Evidence files** | 16 stored artifacts (+ the import proof line above), each at the declared home and cited with the digest of its stored bytes |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) AT-B99-09's painted arm "`n/a` not in the OUTSIDE_SYM row" rests on NO other cell of that row painting the substring `n/a`; (2) the blank-cell limb rests on the enrichment holding NO physical value for a tag whose bytes are absent |
| If the result is an ABSENCE, what made the search wide enough | (1) the assertion scans the whole painted row string of the 118-wide viewport (every painted cell of that row); (2) the OUTSIDE_SYM tag is parked at 0x9000, outside the 0x2000..0x200B image, so its raw bytes are genuinely absent — not truncated by the parser |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_at_b99_09_a2l_window_physical_column` — the `cells == {… "OUTSIDE_SYM": "" …}` map assertion is the blank-vs-n/a conclusion guard; the painted `n/a`-not-in-row check is a separate named assertion |
| Conjunctive criteria: one mutation per conjunct | no conjunctive criterion — each guard is a single assertion family with its own mutation (the three LLR mutations each kill exactly one TC) |
| **Positive control for every probe that returned an ABSENCE** | (1) the NO_ROOT_SYM row — same table, same width — DOES paint `n/a` (positive instance of the substring in a sibling row); every other row does not contain it; (2) the NO_ROOT_SYM cell plain is `n/a` where OUTSIDE_SYM is `""` — the two limbs differ exactly as specified |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "effective_byte_order\|_apply_compu_method\|_invert_rat_func\|encode_physical_to_raw_bytes\|COMPU_TAB\|RAT_FUNC\|physical_value" tests/` | 11 hits — 3 are this increment's own (new test + Inc-1 corpus); the other 8 (`test_a2l_curve_description.py`, `test_a2l_record_layout_walker.py`, `test_changes_symbol_entries.py`, `test_tui_a2l.py`, `test_tui_a2l_detail.py`, `test_tui_app.py`, `test_tui_public_api.py` + the corpus trio) were each re-run GREEN — see §4 regression companions. **No re-pin**: no existing test pinned the old RAT_FUNC direction (P-17), the MOD_COMMON-less fallback (P-7), or the silent nearest/clamp (P-8) — all three were RED-today premises. TC-712/TC-1811/TC-622 pin LINEAR / IDENTICAL / exact-TAB limbs, which are behaviourally unchanged, so they pass unmodified (`reverse-census.txt`) |
| B2 file moved on disk | n/a — no pre-existing file moved | no readers lost |
| B3 byte-identical golden captures this source | `grep -rl synth tests/goldens/` | 1 hit: `tests/goldens/batch64/addendum-below-bound.md` — re-validated: the word "synthetic" in old CHG-SYNTAX prose lines, unrelated to this increment; **no re-pin** |
| B4 artifact produced here is consumed elsewhere | `grep -rln "fixtures/synth\|synth_a2l\|manifest.json" tests/` | 4 hits — the Inc-1 corpus consumed by `test_b99_corpus.py` (green in `green-affected.txt`) and this increment's new test; no foreign consumer |
| A3 interface consumed by another module changed | `grep -rn "_apply_compu_method\|_invert_physical_to_raw\|_reverse_table_lookup\|_invert_rat_func" s19_app/` | the changed helpers' only shipped callers are inside `tui/a2l.py` (enrichment, E9 describe, both encoders) — all re-validated by the GREEN runs above; `encode_physical_to_raw_bytes`'s shipped caller is `change_service.resolve_symbol_entry` (P-22), covered by `test_changes_symbol_entries.py` (GREEN) |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes declared (B1, B3, B4, A3 executed; B2 n/a) — 1 B3 hit re-validated unrelated; **0 re-pins** |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| Effective byte order must read MOD_COMMON (LLR-158.1) | every tag whose layout + tag declare no byte order, under a module declaring one | the corpus A2L + manifest `a2l_expect.byte_order` (Inc-1, PQ-4) | 1 site | `extract_a2l_tags` fallback chain + new `_extract_mod_common_byte_order` | — |
| RAT_FUNC decode direction + root selection (LLR-158.2) | every RAT_FUNC COMPU_METHOD decode + encode | HLR-158 numeric pass threshold + `RAT_FUNC_DIV_10` pin (raw 300 ↔ 30) | 2 sites (decode limb, encode limb) | `_apply_compu_method` + `_invert_rat_func` (solve) + `_eval_rat_func` (direct) | axis-point decode call sites (`describe_curve_tag` axes, external axis points) pass NO limits — axis limits are not parsed; documented smaller-magnitude fallback |
| COMPU_TAB refusals + in-range flag (LLR-158.3) | every TAB_NOINTP / TAB_INTP inversion | manifest `TAB_*_SYM` blocks: `typed_refused`/`named_nearest`, `refused`, `grid`, `off_grid` | 1 site | `_reverse_table_lookup` + `_invert_physical_to_raw` return contract | decode-direction `_table_lookup` untouched (decode clamps/interpolates as shipped — LLR-158.3 governs the encode direction) |
| Undecodable → `n/a` with reason (UX-C8/C10) | every A2L-window Physical cell + the E9 scalar line | the two render sinks in app.py / a2l.py | 2 sites | app.py cell builder; `describe_curve_tag` + `render_curve_description` + `_short_decode_reason` | — |

| Field | Value |
|---|---|
| **Correction population** | 3 corrections (LLR-158.1/158.2/158.3) + 1 display correction (UX-C8), population enumerated from the requirement rows and the Inc-1 manifest pins before editing |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| old RAT_FUNC direction (`_invert_rat_func(physical, …)` encode-side inversion) | no surviving caller inverts f for the encode; `_invert_rat_func` is the decode solver, `_eval_rat_func` the encode | yes — `_invert_physical_to_raw` RAT_FUNC limb calls `_eval_rat_func`; docstrings updated (`a2l.py`, the `_eval_rat_func` / `_invert_rat_func` / `encode_physical_to_raw_bytes` doc blocks) | `s19_app/tui/a2l.py` — see the LLR-158.2 edit region |
| silent nearest/clamp (`_reverse_table_lookup` returning nearest/clamped raw with `""`) | the only returns with `""` are exact-table-value and in-range-without-flag limbs | yes — refusals return reasons naming values/range; the off-grid limb returns a flag | same file, `_reverse_table_lookup` |

### Signed-balance test ledger

`post = base − deleted + added` → `5 = 0 − 0 + 5` ✓ reconciles
(`tests/test_b99_a2l_encode.py`: 0 baseline nodes — new file — 0 deleted, 5 added:
TC-B99-23, TC-B99-24, TC-B99-25, AT-B99-09, AT-B99-14). No existing test node
was modified (0 re-pins, see Reverse census).

---

## 4a · Review round 1 fixes (code-reviewer F1–F4 + LOWs)

The independent review returned **Block** (two HIGH). All findings fixed and
re-verified in the same worktree; no commit (orchestrator's job).

| Finding | Fix | Where |
|---|---|---|
| **F1 [HIGH]** — `TAB_INTP` encode picked the nearest TABLE ENTRY, not the nearest raw value (ASAM-breaking regression) | `_reverse_table_lookup` now inverse-interpolates the typed physical between the bracketing entries to a fractional raw, rounds it to the nearest integer raw, decodes that raw forward and flags the written physical only when it differs (typed 50 on 0→0/100→100 → raw 50, no flag). Out of range still refuses naming the range; `TAB_NOINTP` stays exact | `s19_app/tui/a2l.py` `_reverse_table_lookup` TAB_INTP limb |
| **F1 corpus gap** — every corpus table had one raw step per entry, so no test could see the regression | `tests/fixtures/synth/generate.py` + manifest gained a SPARSE `TAB_INTP` symbol (`TAB_INTP_SPARSE_SYM`, raw 0→0.0, 25→10.0, 100→100.0, image bytes `00 32` at 0x200C): `a2l_expect` pins an interior exact value (40.0 → raw 50, no flag), an interior fractional one (3.9 → raw 10, flag names the written 4.0), both endpoints and a refused value naming `[0.0, 100.0]`. Corpus regenerated; `generate.py --check` → `checked 16 files` | `tests/fixtures/synth/generate.py`, `manifest.json`, `synth_a2l.a2l`, `synth_a2l.s19` |
| **F2 [HIGH]** — AT-B99-09 was not black-box (private `_parse_loaded_file`/`_prepare_load_payload`/`_apply_prepared_load`, hand-set `current_a2l_path`, stored-cell `Text.plain` at 80x24) | AT-B99-09 rewritten: both files load through the shipped Load file dialog (`l` → `#load_path` → `#load_ok`, the same dialog handles `.s19` and `.a2l`); assertions read PAINTED text only — the wide table rows at 118, and at BOTH widths the describe-modal lines (`Scalar value: 4113` / `Scalar value: 30 ` / `Scalar value: n/a (rat_func_no_real_root)`) and the narrow list's selected tag. `_physical_cells_plain` deleted | `tests/test_b99_a2l_encode.py` `_load_through_dialog` / `_run_at_09` |
| **F3 [MEDIUM]** — PQ-5 half-checked (`"0.0" in error` also matches `-50.0`, `500.0`, `100.0`) | Exact range text asserted: `"[0.0, 62.5]"` (TC-B99-25 + AT-B99-14), `"[0.0, 100.0]"` (sparse arm); `TAB_NOINTP` asserts the exact neighbour text `the nearest table values are 10.0 and 15.0` | `tests/test_b99_a2l_encode.py` |
| **F4 [MEDIUM]** — incomplete census | (a) Three engine-freeze guards are RED **by requirement**: `test_tui_directionb::test_tc031_engine_modules_have_no_diff_vs_main`, `…_have_no_name_only_diff_vs_main` and `test_tui_issues_triage_b94::test_tc_b94_18_curated_set_and_engine_freeze` each diff `s19_app/tui/a2l.py` against `main` (read in full: the b94 test asserts the SAME engine freeze, not something else) — LLR-158.1–158.3 cross the frozen engine BY REQUIREMENT, so these stay RED until the orchestrator merges (`red-engine-freeze-guards.txt`). (b) The census grep now also covers `MOD_COMMON` — hits `tests/conftest.py` (fixture builder), `tests/test_a2l_alignment_sizing.py` (alignment prose, pins length 25 — re-run GREEN, `green-alignment-sizing.txt` 17 passed) and `tests/test_tui_issues_triage_b94.py` (curated vocabulary count — the freeze guard above). (c) User-visible impact reproduced with `example_impact.py` → `example-impact.txt`: **71,513** multi-byte tags (the (figure withdrawn: not in the evidence) tags decode endian-free) in `examples/case_06_large_nested_a2l/firmware.a2l` now decode big-endian vs the pre-inc-10 resolution, and **1,640** RAT_FUNC tags in `examples/case_00_public/software_a.a2l` decode in the corrected direction — both match the reviewer's measurements. (d) `green-full.txt` is now the WHOLE affected set | evidence below |
| **LOW (a)** — first module's `MOD_COMMON` applied to all modules | `extract_a2l_tags` walk now carries the enclosing MODULE's own `MOD_COMMON BYTE_ORDER` (module-scoped context, inherited down; the first-module tree pre-pass is deleted). New TC-B99-42: a two-module A2L in tmp — `BIG_SYM` encodes 4113 → `10 11`, `LITTLE_SYM` → `11 10` | `s19_app/tui/a2l.py` `extract_a2l_tags`; `tests/test_b99_a2l_encode.py` `_TWO_MODULE_A2L` |
| **LOW (b)** — RAT_FUNC root at a zero denominator accepted | `_invert_rat_func` drops candidate roots where d·P² + e·P + f ≈ 0 (they are artifacts of multiplying by the denominator, not roots of the declared conversion); the linear limb checks too. Both candidates spurious → decode failure. New TC-B99-43: INT = (P²−4)/(P−2) at raw 5 decodes to 3.0 (not the spurious 2.0); INT = (P²−4)/(P²−4) at raw 5 fails naming the denominator | `s19_app/tui/a2l.py` `_invert_rat_func` |

Tests after the fixes: the new module runs **7 passed** (`green-fix-new-module.txt`;
nodes TC-B99-23/24/25/26/27 + AT-B99-09/14 — TC-B99-42/27 are new this round and
TC-B99-25 grew the four sparse-table arms). `green-full.txt`: the whole affected
set — `tests/test_b99_a2l_encode.py test_tui_a2l.py test_a2l_enriched.py
test_a2l_curve_description.py test_a2l_record_layout_walker.py
test_a2l_f841_cleanup.py test_a2l_multiline_headers.py test_changes_symbol_entries.py
test_tui_public_api.py test_b99_corpus.py test_tui_a2l_detail.py
test_tui_a2l_issue_recolor.py test_help_toggle_and_a2l_panel.py test_tui_app.py
test_address_census.py` — **238 passed, 3 skipped, 2 xfailed** in 158 s.
Corpus: `generate.py --check` → `checked 16 files`.

Mutation verdicts (each applied, run, reverted; `a2l.py` restored to
`6d12c964…` and `app.py` to `03eacc66…` after the last revert —
`fix-baseline-hashes.txt`):

| Mutation | Guard it kills | Verdict | Transcript |
|---|---|---|---|
| LLR-158.1 re-run: the fallback skips `MOD_COMMON` (`module_byte_order` step nulled) | TC-B99-23 | KILLED — `effective_byte_order` back to `little` | `mut-LLR-158.1.txt` |
| LLR-158.2 re-run: decode evaluates f directly again | TC-B99-24 | KILLED — raw 300 → 3000.0-class value | `mut-LLR-158.2.txt` |
| LLR-158.3 re-run: silent nearest/clamp, no refusal, no flag (P-8) | TC-B99-25 | KILLED — `err=None flags=[]` on 13.0 | `mut-LLR-158.3.txt` |
| F1: the nearest-ENTRY limb restored (inverse interpolation removed) | TC-B99-25 sparse arms | KILLED — 40.0 → raw 25-class nearest entry, not interpolated raw 50 | `mut-F1-nearest-entry.txt` |
| LOW (a): first module's `MOD_COMMON` forced on all tags | TC-B99-42 | KILLED — `LITTLE_SYM` resolves big | `mut-LOWa-first-module-wins.txt` |
| LOW (b): the denominator-zero root filter removed | TC-B99-43 | KILLED — raw 5 decodes to the spurious 2.0 | `mut-LOWb-denominator-check.txt` |
| F2 clipping: the Physical cell text truncated to 3 chars (column shrink) | AT-B99-09 | KILLED — painted rows lose `30.0`/`4113`/`40.0` | `mut-F2-clipping.txt` |

### Evidence files — review round 1 (all under `artifact_homes.evidence`)

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED engine-freeze guards (3, by-requirement) | `red-engine-freeze-guards.txt` | `8917f363e7fa1e947116984cafd592deb3c48ac0a91a108b04b3b03366d83be4` |
| Example impact measurement | `example-impact.txt` | `c87b7fa1677fb85c24ac52c8a72933dc325d57cdf13f995d95f243a2c7cb810c` |
| Example impact script | `example_impact.py` | `1c428cf29b08aa49705fcef0d6a982ae4134b9ae2acf78cd2e5afb4f927464b6` |
| Fix-round baseline hashes | `fix-baseline-hashes.txt` | `206d12eaecb9906aaf377fc9df16f1a5e9167d57ba319650283c53a8225a7a3f` |
| GREEN whole affected set (238 passed) | `green-full.txt` | `4e70b5adc06a01b10d46d898b572a1a6d99013ca25d486bdb31de8658d423865` |
| GREEN census companion (MOD_COMMON hit) | `green-alignment-sizing.txt` | `8588d83f8628d0e18495b9121b887f2c23c8b06ae591ef4f2042063d41b61495` |
| GREEN new module (7 passed) | `green-fix-new-module.txt` | `34a2a1247c30374badf5a65b9d5f45632a3c1c2cba042f722e27fcd7b3a9a7cc` |
| Mutation LLR-158.1 re-run (KILLED) | `mut-LLR-158.1.txt` | `ba0a31a51c50b616197760479aa5820e79915546255e2ad4dbca8b01be8b77db` |
| Mutation LLR-158.2 re-run (KILLED) | `mut-LLR-158.2.txt` | `c2f5f505f2a227f1dcb0e0a2eac6b11f7a65de1f9a8d5d97b0c7a853924ec908` |
| Mutation LLR-158.3 re-run (KILLED) | `mut-LLR-158.3.txt` | `1600c3fd9a58162bbfa3cdabeac91e3aeb99a2bb584aebd8ca9f02928a3d66af` |
| Mutation F1 nearest-entry (KILLED) | `mut-F1-nearest-entry.txt` | `2763aef5bf22015952ee3a314580572f5720213fc0bfd6b7dc4de9c66db772b0` |
| Mutation LOW-a first-module (KILLED) | `mut-LOWa-first-module-wins.txt` | `dbef9676ed14156243f07dfe77192800b8c197dd7210e692d227fcf14d7ca00a` |
| Mutation LOW-b denominator (KILLED) | `mut-LOWb-denominator-check.txt` | `2dbd8937165715a614ead8bd77685302bcf750e8e23ee8fc292957e7fb1fe2a2` |
| Mutation F2 clipping (KILLED) | `mut-F2-clipping.txt` | `2cf980fad176f6d18f3aa806513ef3d48faa0a67be4a3865a96f36d1fd1e106c` |
| AT-B99-09 black-box flow probe (development aid) | `probe_at09_flow.py` | `41e1dd402524e541afbfefbd4f8c37871e0a1c3754b309267f60498c32cb799e` |

Signed-balance test ledger after the fix round: `post = base − deleted + added`
→ `7 = 5 − 0 + 2` ✓ (TC-B99-42 and TC-B99-43 added; TC-B99-25 and AT-B99-09
extended in place — same node ids).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: Block (F1 HIGH TAB_INTP encode picked the nearest table entry instead of inverse interpolation — a regression; F2 HIGH AT-B99-09 used private load calls and stored cell text; F3, F4 MEDIUM) · round 2: OK to advance, F1–F4 and LOW-a/b closed. The orchestrator renamed two colliding new test ids to TC-B99-42/43. Remaining LOWs routed to BACKLOG-CODE (zero-denominator decode reason token; axis-point limits; the unsupported "(figure withdrawn: not in the evidence)" figure is withdrawn here) |

---

## 5 · Risks

- **Frozen engine crossed** (declared in LLR-158.1..158.3): three engine
  behaviours changed by requirement. The blast radius is bounded by the
  reverse census (11 test files re-run GREEN, 0 re-pins) but the full suite
  (~2 h 20) is the orchestrator's gate.
- **RAT_FUNC root selection with unparsed axis limits**: curve/MAP axis-point
  decodes pass no limits (axis limits are not extracted), so a two-root
  RAT_FUNC on an axis picks the smaller-magnitude root. Documented in
  `_invert_rat_func`; no shipped fixture exercises it.
- **`_invert_physical_to_raw` return contract changed** (2-tuple → 3-tuple
  with flags). Its only shipped callers are the two encode paths in the same
  file; the change is packet-visible for any out-of-tree caller.
- **Physical cell `""` → `n/a`**: rows whose raw bytes are present but whose
  conversion fails (FORM, missing table, RAT_FUNC without inverse) now paint
  `n/a` instead of blank. Snapshot suite (33 passed) and the A2L pilot
  companions (16 passed) confirm no pinned screen relied on the blank.
- The TAB_INTP nearest-entry tie-break is table order (stable `min`) — a
  mid-tie value picks the lower raw. The corpus avoids ties by construction
  (Inc-1 PQ-4: 3.4 is a non-tie).

## 6 · Pending items / spec deviations

- **Backlog, deliberately NOT fixed (review LOW, recorded per the fix
  brief):** axis-point RAT_FUNC decodes get no limits — the E9 curve-axis and
  external-axis-point call sites pass no tag limits (axis limits are not
  parsed), so a two-root RAT_FUNC on an axis still takes the
  smaller-magnitude root there. Filed as backlog; no fixture ships it.
- Declared: the modal reason tokens are a fixed enum
  (`_DECODE_REASON_TOKENS`); a NEW refusal string from a future conversion
  limb falls back to the conversion status token — extending the enum is a
  packet-visible change.
- The encode limbs remain TC/API-only under the P-22 recorded exception (no
  shipped TUI path calls the encoder); AT-B99-14 observes the codec API, not a
  UI flow.

## 7 · Suggested next task

Batch-99 Increment 11 (per `BRIEF-inc-11.md` — HLR-159/LLR-159.x,
`tests/test_b99_crc_region.py`): the empty-region CRC refusal. It consumes the
corpus + independent reader this batch already ships; no dependency on this
increment's engine changes.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 SOURCE files (`git status` — `s19_app/tui/a2l.py`, `s19_app/tui/app.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_a2l_encode.py` (5 nodes, this increment) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — no new layer-0 (engine-internal) node; LLR-158.1..158.3 are verified by TC-B99-23..25 against the shipped engine |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: baseline RED `red-initial.txt` (5 failed on the unmodified tree) + 3 mutations with transcripts + restore digest `3d88647a…` |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 5 probes, B3 hit re-validated unrelated, 0 re-pins |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — only the 2 SOURCE files + 1 new test + `.dev-flow/` artifacts |
| 8 | Frozen interfaces untouched | all | ✓ | LLR-158.1..158.3 cross the frozen engine layer BY REQUIREMENT (named in the LLR rows); no other frozen interface touched; `prototypes/` untouched |
| 9 | Coverage claims verified **on disk** | all | ✓ | every value oracle is `tests/fixtures/synth/manifest.json` on disk or the independent reader over the corpus S19; image bytes never come from `s19_app`'s loader |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (sibling NO_ROOT row paints `n/a`; NO_ROOT `n/a` vs OUTSIDE blank) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: per-arm KILLED, inert arms named |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 5 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: 3 corrections + 1 display correction, enumerated before editing |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 5 artifacts asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` (the one published form for a not-yet-reviewed packet) |
| 16 | **Evidence files** declared | all | ✓ | §4: 16 artifacts with stored-byte SHA-256 digests |
