# Increment 006 — HLR-160 · `Exports stay inside their destination and invent no byte`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md`.
> **Where this lives:** `.dev-flow/2026-10-25-batch-99/03-increments/increment-006.md`.

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `006` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-149 / HLR-160 / LLR-160.1 · LLR-160.2 · LLR-160.3 · LLR-160.4 · LLR-160.5` |
| Acceptance | `AT-B99-11` · white-box `TC-B99-28 · TC-B99-29 · TC-B99-30 · TC-B99-31 · TC-B99-41` · unit `sanitize_export_segment` / `build_export_basename` arms inside TC-B99-28 |
| Agent | `software-dev` |
| Date | `2026-10-25` |
| Design refs | `PDR-2026-10-25-batch-99` conditions **C3/PQ-1, PQ-2, PQ-3, UX-C10, UX-C11** (discharged here); design-proposal §4 rows B99-I2a and B99-I6; D8 (`sufijo`, operator verdict 2026-10-25) |

---

## 1 · What changed

BLUF: the Split/Join/Export writer now plans every final name (BIN `.addr`
sidecars included) before any byte is written, places every file through the
work-area placement seams, and refuses the whole export — naming the
colliding segments or the refused name — on a case-folded collision, an
over-long full path, a destination that escapes the work-area root, or a
link/reparse point at a final name. Bytes come only from the image's
declared ranges, so a MAC-only session exports header-only S19/HEX. A
changed re-export takes the next free `_<N>`; a BIN and its `.addr` sidecar
are claimed as one pair under one `_<N>` before either is written; an
identical file (or pair) is reused. The status leads with the outcome and
names the actual files, with the words `wrote` / `reused`.

Six pieces, in brief order:

1. **One sanitiser (LLR-160.1).** `sanitize_export_segment` keeps
   `[A-Za-z0-9_-]` only (every other character maps to `_`), prefixes `_`
   to Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`,
   `LPT0`–`LPT9` including the superscript digits `¹²³`, `CONIN$`, `CONOUT$`,
   case-insensitive, compared before any extension, on the
   superscript-normalised raw name), caps the segment part at 100 characters
   and clips the stem so the final basename (`_<N>` and extension included)
   is ≤ 200; an empty result becomes `segment_<index>`.
   `build_export_basename` composes `‹stem›_‹segment›‹ext›` from it, and the
   same name builds the BIN `.addr` sidecar.
2. **Plan-time pass (LLR-160.5).** `write_split_join_export` computes every
   final name and payload in Phase A, then — before any folder or file is
   created — checks each full path length against the platform limit and
   compares all final names case-folded. Any refusal raises
   `ExportRefusedError` naming the colliding segments or the refused name,
   with the raw → sanitised pair rendered literally; 0 bytes are written.
3. **Containment (LLR-160.2).** Before any `mkdir`, the destination home
   passes the shipped guard `_check_home_contained`
   (`project_gather_service.py:200`), anchored to the work-area root. Each
   final path resolves inside it; an existing link or reparse point at a
   final name refuses the whole export. The refusal renders the segment
   name literally (`safe_text`, `notify(..., markup=False)`), clipped to 80
   characters, next to the sanitised name (UX-C10).
4. **Byte source (LLR-160.3).** A new `declared_ranges` parameter rides the
   loaded image's declared ranges through `_filter_declared_ranges`: bytes
   come only from declared ranges, never from MAC placeholder entries — a
   MAC-only session writes header-only S19/HEX. `None` keeps the legacy
   whole-map behaviour the shipped engine-purity tests pin.
5. **Group placement B99-I2a (LLR-160.4).** New
   `workspace.place_group_into_workarea(sources, destination, *, max_size_bytes=None) -> list[Path]`
   (C3/PQ-1): one private staging dir, one `_<N>` claimed with `O_EXCL` for
   EVERY name of the group before any write, then `os.replace` per file;
   reuse only when every file is byte-identical and non-empty; on any
   failure it rolls back every own claim and placed file and raises
   `WorkareaPlacementError`. `segment_ops` is untouched and never imports
   `tui.workspace`; `segment_split_view` calls the group function for the
   BIN/`.addr` pair and `copy_into_workarea` for single files. The returned
   paths carry the action (`path.action in {"wrote", "reused"}`).
6. **Status (UX-C11).** The export status leads with the outcome
   (`Export refused: …` / `Exported 3 files: …`), uses the words `wrote` /
   `reused`, names the actual `_<N>` names, and on a part-way failure names
   the files already written.

**Tests — `tests/test_b99_export.py` (new module, 17 nodes):** TC-B99-28
(sanitiser over HLR-160's full hostile set and the 100/200-char bounds);
TC-B99-29 (junction destination refused via `mklink /J`; existing symlink at
a final name refused; the hostile set writes nothing outside the
destination; the hostile segment name renders literally with 0 markup
spans — UX-C10); TC-B99-30 (MAC-only → 0 data records, read with the
independent reader); TC-B99-31 (`_<N>`: changed bytes → `_1` for the pair;
**PQ-2** orphan `_1.addr` fixture → the pair takes `_2` for both;
mismatched-sidecar never reuses the pair; forced failure rolls back every
own claim; identical bytes → reused); TC-B99-41 (case-folded `SegA`/`sega`
collision refused before any write; one refused name refuses the whole set;
an over-long full path → 0 files); AT-B99-11 (pilot: hostile A2L
`x/../../../ESCAPED` lands inside the destination under a sanitised name;
MAC-only export writes no data record; a second export after a patch takes
`<name>_1`, the status names it, the first file is intact).

**PQ-3:** TC-B99-39's delete census (`tests/test_b99_staging.py`) now covers
`place_group_into_workarea` as a sixth placement writer.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/segment_split_view.py` | source | HLR-160, LLR-160.1–160.5, UX-C10, UX-C11 | `sanitize_export_segment`, `build_export_basename`, `_refusal_text`, `_export_reuse_target`, `_filter_declared_ranges`, `ExportRefusedError`, `_PlacedExportPath`; `write_split_join_export` gains the `declared_ranges` parameter, the Phase A plan pass (names, payloads, path-length and case-folded collision checks), the containment guard and reparse-point refusal before `mkdir`, and placement through the work-area seams; the export action's status and refusal notify lead with the outcome and render names literally |
| `s19_app/tui/workspace.py` | source | LLR-160.4 (B99-I2a), C3/PQ-1 | NEW `place_group_into_workarea` (+330 lines): one private staging dir, one `_<N>` claimed `O_EXCL` for every group name before any write, `os.replace` per file, byte-identical non-empty reuse, full rollback + `WorkareaPlacementError` on failure |
| `tests/test_b99_export.py` | test | HLR-160 | NEW module: TC-B99-28/29/30/31/41 + AT-B99-11 (17 nodes) + `_export_capture` helper |
| `tests/test_b99_staging.py` | test | LLR-155.7, PQ-3 | TC-B99-39 census: `place_group_into_workarea` added to `_CENSUS_TARGETS` (sixth writer) + docstring |
| `tests/test_segment_split_window.py` | test | HLR-160 | re-pins only (see §4 reverse census): BIN export returns the placed pair; the A2L quoted-name expectation rides the sanitiser; direct-call scratch destinations move under a work-area-shaped home |
| `tests/test_id_registry.py` | test | registry convention | `EXPECTED_SCANNED_TEST_FILES` 209 → 210 (this increment's module, measured) |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-006.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-6/*` | doc | — | transcripts and hashes (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 3**: `segment_split_view.py`, `workspace.py` (`segment_ops.py` needed no change — the view composes the engine's emitters) |
| Test files | 3 modified + 1 new module (17 nodes) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched; `segment_ops.py` untouched (B99-I2a boundary: the headless engine never imports `tui.workspace`).

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter; NO_COLOR unset:
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8
export PYTHONPATH=<this worktree>
python -c "import s19_app; print(s19_app.__file__)"   # must print a worktree path
python -m pytest tests/test_b99_export.py -q                       # 17 passed
python -m pytest tests/test_b99_staging.py -q                      # 23 passed
python -m pytest tests/test_segment_split_window.py -q             # 56 passed
python -m pytest tests/test_address_census.py -q                   # 23 passed
python -m pytest tests/test_id_registry.py -q                      # 13 passed
python -m pytest tests/test_segment_ops.py -q                      # 23 passed (companion)
```

---

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| RED counterfactual (unmodified tree) | `tests/test_b99_export.py` whole | **17 failed** (`red-full.txt`); first node `ImportError: cannot import name 'build_export_basename'` (`red-initial.txt`) |
| White-box (new module) | TC-B99-28/29/30/31/41 | **17 passed** (`green-full.txt`); per-TC: 28 → 1, 29 → 4, 30 → 1, 31 → 5, 41 → 3 (`green-tc_b99_*.txt`) |
| Black-box | AT-B99-11 ×3 arms | **3 passed** (`green-at_b99_11.txt`) |
| Companions | `test_b99_staging.py` (TC-B99-39 with PQ-3) | **23 passed** (`green-b99-staging.txt`) |
| Companions | `test_segment_split_window.py` (re-pinned) | **56 passed** (`green-segment-split-window.txt`) |
| Companions | `test_address_census.py` | **23 passed** (`green-address-census.txt`) |
| Companions | `test_id_registry.py` (210 bump) | **13 passed** (`green-id-registry.txt`) |
| Companions | `test_segment_ops.py` | **23 passed** (`green-segment-ops.txt`) |
| Full suite | — | **not run** (orchestrator, per the brief) |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source. The 17 new nodes ran first on the unmodified increment-base tree |
| Transcript | `red-full.txt`: **17 failed in 75.06s**, every node, with the failure at the main-observable clause (sanitised names absent, junction followed, placeholder byte emitted, overwrite instead of `_1`, collision not detected, escape outside the destination). `red-initial.txt`: the first node's `ImportError` |
| Instrument | pytest `-q` |
| Where it ran | this worktree at the increment base (pre-implementation tree) |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` |
| Arms resolved at baseline | 17 RED |
| Verdict granularity | per node |

| Field | Value |
|---|---|
| **RED counterfactual** | 17 RED on the unmodified tree (`red-full.txt`, `red-initial.txt`) |

### Mutation verdicts (C-40) — 5 mutants, 5 KILLED, 0 survived

| Mutant | LLR | Targeted run | Verdict |
|---|---|---|---|
| Sanitiser bypass (`mapped = name[:100]`, charset mapping skipped) | LLR-160.1 | TC-B99-28 (`mut-LLR-160.1.txt`) | **KILLED** — `../` survived; expected `___` |
| Destination-rooted containment check (`home = dest_dir.resolve()`) | LLR-160.2 | TC-B99-29 junction arm (`mut-LLR-160.2.txt`) | **KILLED** — the junction arm sees a late, wrapped `ExportWriteError` instead of the plan-time `WorkareaContainmentError` (the placement seam still contained the escape; the TC pins the guard-at-plan-time contract) |
| MAC placeholders as data (declared-range filter bypassed) | LLR-160.3 | TC-B99-30 (`mut-LLR-160.3.txt`) | **KILLED** — `{2147483648: 0}` became data |
| Per-file `_<N>` (pair routed per file through `copy_into_workarea`) | LLR-160.4 | TC-B99-31 (`mut-LLR-160.4.txt`) | **KILLED** — 3 arms RED (`bin_pair_placed_under_one_suffix`, `orphan_sidecar_claims_the_pair_suffix` — RED only with the PQ-2 orphan `_1.addr` fixture, `mismatched_sidecar_never_reuses_the_pair`) |
| Collision check inside the write loop | LLR-160.5 | TC-B99-41 collision arm (`mut-LLR-160.5.txt`) | **KILLED** — the export refused only after the first file was written: `home.exists()` was True |

Every mutant was reverted and the SHA-256 of the touched file verified equal
to the pre-mutation hash (`baseline-hashes.txt`: `segment_split_view.py
6e278ace…`, `workspace.py 51df7a45…` — workspace was not mutated). No mutant
is left in place.

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `tests/support/independent_reader.py` | the MAC-only export under the LLR-160.3 mutant | 1 placeholder data record (`{2147483648: 0}` ≠ `{}`) (`mut-LLR-160.3.txt`) |
| the worktree import check | every run | `s19_app.__file__` inside the worktree (`import-check.txt`) |
| `tests/b97_fixtures.py` `make_junction` | the junction destination under HEAD and under the LLR-160.2 mutant | file lands outside / late wrapped refusal (`red-full.txt`, `mut-LLR-160.2.txt`) |
| Textual pilot (AT-B99-11) | hostile `x/../../../ESCAPED` A2L name | escape + overwrite at HEAD (`red-full.txt`); sanitised landing + `_1` + intact first file after |
| TC-B99-39 AST census | `place_group_into_workarea` source | would fail if any delete call targets a name not bound to the private staging dir (`green-b99-staging.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | each instrument shown failing on a known-bad input |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | Every claim is read from what the app writes or paints, never from the code that produces it. Export bytes are re-parsed with the independent reader (`read_s19` / `read_hex`) or compared byte-level against the engine's own plan output. Filenames are read from the destination directory listing. The AT reads painted status lines (`#log_line_4`) and the files on disk. The refusal message is read from the raised exception's rendered text. The status wording (`wrote` / `reused`, outcome-first) is read from the painted log line in the pilot |

### Evidence files

All paths are under `.dev-flow/2026-10-25-batch-99/evidence/inc-6/`.

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| mutation (orchestrator, review round 2): `safe_text` removed from the collision reason → the new in-range ESC arm FAILS, the old arm still passes (1 failed, 1 passed); source restored, hash a7559269… | `mut-review2-esc.txt` | `a272f92c06ad3a4e4ec88cbf6aa4aee21565971abe923d706a2d154751033836` |
| GREEN after the in-range ESC arm (25 passed, 3.11) | `green-review2.txt` | `2e3744124e37b893a5ffa2293607d9fab202ff8eb970614a622fabf46176a981` |
| Worktree import check | `import-check.txt` | `70a9806f79dd7d1569d6529e4e5829ba1ffd2b7a789d6e005208f57433634600` |
| RED first node (ImportError) | `red-initial.txt` | `2954fb5c15f102f75509767038e6acb0817f373cfb85592e2aa6752b5f03ace1` |
| RED whole module (17 failed) | `red-full.txt` | `f49d10d945c9bb2041efb1949932bf16d501cd6126971ca0ded4c5f721bcf632` |
| GREEN whole module (17 passed) | `green-full.txt` | `84edb92669a4d2114606e83a379ea0c57d7868dc15c69fbf814f81abda664ed3` |
| GREEN TC-B99-28 (1 passed) | `green-tc_b99_28.txt` | `889dc047aa1aa92bc08f3ca19883a47540e43805a11f4912ec4960c813e14984` |
| GREEN TC-B99-29 (4 passed) | `green-tc_b99_29.txt` | `15d977f6015cbd33c89a1d040f286fa71268c03ee1ca334d3ee35199a9cfab7c` |
| GREEN TC-B99-30 (1 passed) | `green-tc_b99_30.txt` | `b297260081c48d7bda318862b8cf6befb3935a3664a642be65a8673c7fd947fa` |
| GREEN TC-B99-31 (5 passed) | `green-tc_b99_31.txt` | `ea9bd738f4885de9b8f7cc65d668e9d99822f8c70f9a35a450bb1538046746a8` |
| GREEN TC-B99-41 (3 passed) | `green-tc_b99_41.txt` | `daf4fb062dc326fa06feffe7d822101dedd62fba292aa978d2ce741e5428cff3` |
| GREEN AT-B99-11 (3 passed) | `green-at_b99_11.txt` | `92310cc50357ae0a7340aca17b23537e7019bfe56a810c5b969766479faf4132` |
| GREEN test_b99_staging.py (23 passed, PQ-3 census) | `green-b99-staging.txt` | `80c92d254a5f94b62327eda567f40b1fa06bfbc200906a8feecf0feb31f3f3bf` |
| GREEN test_segment_split_window.py (56 passed) | `green-segment-split-window.txt` | `96c8bfe5d1dda2d0a6c815a590129f3144496fa542c036d4d7536390b8168f4c` |
| GREEN test_address_census.py (23 passed) | `green-address-census.txt` | `da36b683c4312c4f60e21e6a7c920dbd350e92133757cbf67aecabea15335f55` |
| GREEN test_id_registry.py (13 passed) | `green-id-registry.txt` | `ae46853d102a482b576d66868bd68c86c82ad1d080184936f2e20249279bf20b` |
| GREEN test_segment_ops.py (23 passed) | `green-segment-ops.txt` | `415991b5ddcd5a2c6d6b83002ae0d2f77fcef6b4362098cc192e616852dbcfdc` |
| Mutant LLR-160.1 (KILLED) | `mut-LLR-160.1.txt` | `a9496227429972ae5ec07f4b8d5d32c74a441dcc012a3ee94485dc425d69e716` |
| Mutant LLR-160.2 (KILLED) | `mut-LLR-160.2.txt` | `bc1cb5bb623685d435aac1cffabcac41699e6a535bd2852935df7430bef0f36b` |
| Mutant LLR-160.3 (KILLED) | `mut-LLR-160.3.txt` | `1d951a0daf3ddc15addabd0f91db31d8dd49a6f00e3d5fec58deb7c8d1b81808` |
| Mutant LLR-160.4 (KILLED) | `mut-LLR-160.4.txt` | `a68c9588aa7b49e3b6efacb5385d19f8b8e59e4c98f7992b05adf26cb03d5b2a` |
| Mutant LLR-160.5 (KILLED) | `mut-LLR-160.5.txt` | `dcc79d0354146087ea5f55eb08c4c38bc720d1565854f12b93908c5df1d684aa` |
| Reverse census probe | `reverse-census.txt` | `75d53766d50ecb6b4706e7eec19a8c01f38f45caafe58de811a093f8b3fadc98` |
| Pre-mutation baseline hashes | `baseline-hashes.txt` | `ddcb2be15c4a470ec9f0e46640b950517deb0c32f3b04734fe15c51d56165236` |

| Field | Value |
|---|---|
| **Evidence files** | the transcripts above, each with its SHA-256. Every "N passed" figure in this packet appears in the cited transcript |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | Yes: 0 files outside the destination over HLR-160's full hostile set (TC-B99-29 hostile arm); 0 data records in a MAC-only export (TC-B99-30 and AT-B99-11, independent reader); 0 files written by a refused export — collision, over-long path, junction, link at a final name (TC-B99-41, TC-B99-29); 0 own files left after a forced-failure rollback (TC-B99-31); 0 markup spans in the rendered refusal (TC-B99-29 literal arm, UX-C10) |
| What made the search wide enough | every member of the hostile set; the full destination tree compared before/after; the re-parsed image compared against `{}` |
| Positive control | mutants LLR-160.1–160.5 each create exactly the forbidden instance and are caught |

### Reverse census — trigger family B

Probe: `grep -rln "segment_split_view\|write_split_join_export\|write_bin_with_sidecar\|segment_ops\|splits" tests/` → 23 files (`reverse-census.txt`). Every hit re-validated; the prose matches ("splits" in prose, file paths in audit lists, palette pins, BINDINGS keys) are unaffected. The assertion-bearing files re-ran green.

**Re-pins** (each: `test::node — old → new — requirement`):

- `test_segment_split_window.py::test_export_formats_split_byte_level[bin]` — `len(written) == 1` → the placed pair `["t_isle.addr", "t_isle.bin"]` — HLR-160 (a BIN export writes the pair; the old shape returned only the `.bin`, hiding the sidecar).
- `test_segment_split_window.py::test_export_formats_join_byte_level[concat-bin, fill-bin]` — `[p.name for p in written] == ["t_joined.bin"]` → `["t_joined.addr", "t_joined.bin"]` — HLR-160 (same pair shape).
- `test_segment_split_window.py::test_split_fill_pads_only_inside_the_files_own_span` — `[p.name for p in written] == ["t_a.bin", "t_b.bin"]` → the four-name pair list — HLR-160.
- `test_segment_split_window.py::test_tc710_split_from_each_source_naming` — `prg_'PrgCode'.addr/.bin` → `prg__PrgCode_.addr/.bin` — LLR-160.1 (the A2L quoted identifier rides the one sanitiser like every other name).
- `test_segment_split_window.py` direct-call writers (7 nodes: `test_split_skip_writes_only_the_covered_sub_ranges`, `test_split_fill_pads_only_inside_the_files_own_span`, `test_join_concat_packs_ascending_from_the_lowest_base`, `test_join_fill_keeps_original_offsets_and_ctx_cells`, `test_pad_byte_defaults_to_zero_and_is_configurable`, `test_export_formats_split_byte_level`, `test_export_formats_join_byte_level`) — `dest_dir=tmp_path` → `dest_dir=_export_home(tmp_path)` (a `.s19tool/workarea/splits` scratch home) — LLR-160.2 (the containment guard now anchors destinations to a work-area root). Byte assertions unchanged.

No other test pins the changed behaviour. Foreign greps for the old status wording ("exported … file(s)") found no pins.

| Field | Value |
|---|---|
| **Reverse census** | 23 files probed; 5 re-pin groups, all re-pinned only where HLR-160 changes the pinned behaviour; `test_segment_split_window.py` re-ran 56 passed |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | the 5 re-pin groups above; 0 old-behaviour assertions left (the 7 dest_dir re-pins keep their byte assertions; the pair re-pins keep the byte-level oracle comparisons). `tests/test_b99_staging.py` and `tests/test_id_registry.py` edits are additive (census row, count bump), not corrections |

### Signed-balance test ledger

- **Balance:** `post = base − 0 deleted + 17 added`. The 17 are the new module's nodes (TC-B99-28/29/30/31/41 + AT-B99-11 ×3).
- **Rewritten in place:** 5 re-pin groups in `test_segment_split_window.py` (8 test functions, 15 parametrized nodes — `test_export_formats_split_byte_level` ×3 and `test_export_formats_join_byte_level` ×6 re-pin `dest_dir` in every arm); `EXPECTED_SCANNED_TEST_FILES` 209 → 210.
- **No tests deleted.**

---

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: BLOCK (F1 HIGH `Path` subclass crashes every export on Python 3.12+; F2–F4 MEDIUM; F5 LOW) · round 2: OK to advance, F1–F5 closed, verified on 3.11 and 3.12; its MEDIUM (the ESC arm could not fail: the byte sat past the clip) fixed by the orchestrator with an in-range ESC arm, mutation-checked · security-reviewer — spawned as a generic agent with agents/security-reviewer.md · round 1: changes required (F1 HIGH 3.12 crash; F2, F3 MEDIUM; F4, F5 LOW) · round 2: approve, probes re-run on 3.12. Residual LOWs (doubled "Export failed: Export stopped" prefix, `_100`+ beyond the 200 cap, `_refusal_text` reason unscrubbed for future callers) routed to BACKLOG-CODE |

---

## 5 · Risks

- **The LLR-160.2 mutant's kill is defence-in-depth aided.** Under the destination-rooted mutant the placement seam still contained the actual escape; the TC detected the late, wrapped refusal rather than an escaped file. The plan-time guard contract (refusal class, `not home.exists()`, nothing written) is what the test pins.
- **Windows case-insensitive filesystem.** `SegA`/`sega` names are distinct strings but the same file on disk; the plan-time case-folded check refuses before the filesystem would alias them.
- **The `_<N>` reuse contract compares at the requested name only** (C3(e) semantics): a pair is reused only when every member at the requested base is byte-identical and non-empty; a drifted sidecar forces a fresh `_<N>` pair.
- **`declared_ranges=None` keeps legacy whole-map behaviour** for the shipped engine-purity tests; the UI always passes the loaded image's declared ranges.

## 6 · Pending items / spec deviations

1. **Full suite:** owed (orchestrator).
2. **Independent review (§4b):** pending — orchestrator.
3. No deviations from the increment brief. PDR conditions discharged here: **C3/PQ-1** (`place_group_into_workarea` declared in full — signature, building increment = Inc 6 with `workspace.py` as the 3rd source within budget, rollback, census, engine-import boundary), **PQ-2** (orphan `_1.addr` fixture + mismatched-sidecar + forced-failure arms; the per-file mutant goes RED only with the fixture), **PQ-3** (TC-B99-39 census covers the new writer), **UX-C10** (one hostile-name TC per new file-derived sink: the export refusal renders `[red]x[/red]` / `[@click=app.quit]` literally, 0 markup spans), **UX-C11** (outcome-first status with `wrote`/`reused` and the actual `_<N>` names, pinned by AT-B99-11 arm 3 and TC-B99-31).

## 6b · Review round 1 fixes (code-reviewer + security-reviewer)

Seven findings (F1–F7) from the independent review of this increment were
fixed in the same worktree, on top of the reviewed tree (uncommitted).
Source budget unchanged: `segment_split_view.py`, `workspace.py`
(`segment_ops.py` untouched). No new test module — all arms extend
`tests/test_b99_export.py` and `tests/test_segment_split_window.py`, so
`EXPECTED_SCANNED_TEST_FILES` stays 210.

| Finding | Fix | Proof |
|---|---|---|
| F1 (HIGH) `_PlacedExportPath`, a `Path` subclass whose `__init__` skips `super()`, crashes on Python 3.12+ (`_raw_paths` unset, `.name` → `AttributeError`) | Subclass removed; `PlacedExport` is a plain `@dataclass` with `path` + `action`; the handler reads `p.path.name` / `p.action`; `ExportWriteError.written` carries only `wrote`-action paths | `red-fix-f1-py312.txt` (AttributeError on 3.12 before the fix), `green-fix-export-py312.txt` (24 passed on 3.12.13), mutant F1 (`mut-F1-py312.txt`, subclass restored → 3.12 RED + direct probe of the crash) |
| F2 (MED) collision reason embedded raw segment names, unscrubbed and unclipped; index 0 passed instead of the row's index | Reason now names the sanitised final names plus each raw name through `safe_text` clipped to 80; the pairs carry the row's own `other_part` | `test_tc_b99_41_collision_reason_is_scrubbed_clipped_and_indexed` (ESC byte + 300-char name in the colliding pair; 0 spans, no ESC in reason or notice) |
| F3 (MED) part-way message contradicted itself ("Nothing written. — files already written: X", X possibly reused) | Message reworded truthfully: `Export stopped: <reason>. Already written: A, B; reused: C`; `written=` only `wrote` paths | `test_tc_b99_41_part_way_failure_reports_written_and_reused` (forced second-file failure; reused file named under `reused:`) and `test_at_b99_11_part_way_failure_status_names_the_first_file` (painted `#log_line_4` names the first file; wide terminal so the tail is not clipped) |
| F4 (MED/LOW) the 260 check skipped the `_<N>` suffix and the longer staging paths; `_<N>` with N ≥ 10 yielded a 201-char basename | Plan-time pass measures every final path with the worst-case `_99` suffix AND every private staging path (`<root>/temp/.staging/stage-XXXXXXXX/<name>`); `_EXPORT_SUFFIX_ROOM` reserves two digits (`_EXPORT_SUFFIX_DIGITS = 2`) so N up to 99 stays inside the 200 cap | `test_tc_b99_41_over_long_second_segment_refuses_before_any_write` (300-char second name refuses before the mkdir; base path exactly 260 would have passed the old check), TC-B99-28 boundary re-pinned to `193 + ".s19" + "_99" == 200` |
| F5 (LOW, security) payload staged in system `%TEMP%` | Phase B stages through `workspace._private_stage_dir(workarea_root)` (LLR-155.1); the `tempfile` import is gone from the view | `test_tc_b99_41_payload_is_staged_inside_the_workarea` (spy on the seam; staging path asserted under `<root>/temp/.staging`) |
| F6 (LOW, security) `_dest_dir()` called outside the try — a junctioned project home crashed the app | Call moved inside the try; `WorkareaContainmentError` renders as the painted refusal | `test_at_b99_11_junctioned_project_home_shows_refusal` (project dir swapped for an escaping junction post-load; pilot paints "Export refused", nothing written outside) |
| F7 (LOW) cleanup loops rebound `claim_path`, so failure messages named the group's last claim | Each failure branch pins `failed_path = claim_path` before its rollback loop and names `failed_path` in the message (the TC-B99-39 source census binds `claim_path` to the `O_EXCL` claim, so the loop variable keeps its name) | `test_tc_b99_31_fill_failure_names_the_failing_member` (first fill of the pair forced to fail → message names `t_isle_1.bin`, not the last claim `_1.addr`) |

### Fix-round verification

- RED counterfactual: F1 RED on 3.12 before the fix (`red-fix-f1-py312.txt`);
  every new arm's docstring records its RED shape (each asserts behaviour the
  reviewed tree did not have).
- GREEN (3.11, s19env): `test_b99_export.py` **24 passed**
  (`green-fix-export-py311.txt`), `test_b99_staging.py` **23 passed**,
  `test_segment_split_window.py` **56 passed**, `test_address_census.py`
  **23 passed**, `test_id_registry.py` **13 passed**.
- GREEN (3.12.13, mapperenv, Textual 8.2.8): `test_b99_export.py` **24
  passed** (`green-fix-export-py312.txt`) — the F1 proof; `requires-python
  >= 3.11` holds. (pytest 8.4.2 installed into mapperenv to run the suite.)
- Mutations (C-40): F1 mutant (subclass restored) KILLED on 3.12
  (`mut-F1-py312.txt`); LLR-160.1 sanitiser bypass re-run, KILLED
  (`mut-fix-LLR-160.1.txt`); LLR-160.5 collision-check-in-write-loop re-run,
  KILLED by both collision arms (`mut-fix-LLR-160.5.txt`); LLR-160.4
  per-file `_<N>` re-run (the touched group-placement seam), KILLED by the
  same 3 arms (`mut-fix-LLR-160.4.txt`). LLR-160.2 and LLR-160.3 mutants
  were not re-run: the fix changed neither the containment guard call nor
  the declared-ranges filter. Every mutant reverted; SHA-256 of both source
  files equals the fix-round baseline (`baseline-hashes-fix.txt` /
  `revert-fix-muts.txt`, `a7559269…` / `de756402…`).
- Reverse census: `write_split_join_export`'s return items were
  `Path`-shaped with an `action` attribute; consumers in
  `tests/test_segment_split_window.py` (8 nodes) and `tests/test_b99_export.py`
  were re-pinned to the `PlacedExport` dataclass surface
  (`p.path.name`, `p.action`) — requirement: F1 (the subclass broke on
  3.12). Re-pins: TC-B99-28 boundary 194 → 193 with `_1` → `_99` — F4
  (two-digit suffix room). `test_tc_b99_39_delete_calls_delete_only_owned_staging`
  pins the census idiom (`claim_path` bound by the `O_EXCL` claim): kept
  green by pinning the failing name in `failed_path` instead of renaming
  the loop variable — F7.
- Evidence: sha256 of every fix-round transcript in
  `evidence/inc-6/sha256-fix.txt`.

## 7 · Suggested next task

1. The Inc-6 gate: `code-reviewer`, `security-reviewer` (the P2 plan names the hostile-name set and the containment test), `ux-reviewer`.
2. The orchestrator's full suite.

---

## Increment gate checklist

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | ≤4 source files | ✓ | 2 / 3 (§2) |
| 2 | Tests written in this same increment | ✓ | 17 new nodes (§4) |
| 3 | RED counterfactual declared | ✓ | 17 RED (`red-full.txt`) |
| 4 | Reverse census declared | ✓ | §4, 5 re-pin groups |
| 5 | Mutation check (C-40) | ✓ | 5 mutants, 5 KILLED, hash-verified reverts |
| 6 | Oracle = independent reader | ✓ | §4 emitted-form assertion |
| 7 | Acceptance tests black-box | ✓ | AT-B99-11 drives the pilot with keys/clicks, reads painted status and disk |
| 8 | Evidence files with sha256 | ✓ | §4 table |
| 9 | Load-bearing emptiness declared | ✓ | §4 |
| 10 | Correction population | ✓ | §4 |
| 11 | Signed-balance ledger | ✓ | §4 |
| 12 | §4b left as pending — orchestrator | ✓ | §4b |
