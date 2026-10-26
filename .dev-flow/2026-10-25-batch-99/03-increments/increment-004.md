# Increment 004 — HLR-157 · `The Patch Editor's image is the source plus the current document`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `004` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-146 / HLR-157 / LLR-157.1 · LLR-157.2 · LLR-157.4` (LLR-157.3 retired, LED-2026-10-25-batch-99.2) |
| Acceptance | `AT-B99-08` (+ its forced-mismatch arm) · white-box `TC-B99-21 · TC-B99-22 (+overlap-refusal arm) · TC-B99-40 (+2 strip arms)` · PDR condition `UX-C6` |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: the Patch Editor's in-memory image is now **the source plus the current
document**, maintained by a journal in `ChangeService` (address → source
byte, recorded the first time an apply writes an address — the ARQ §2
recommendation, design-proposal §3). Every `apply` restores the journaled
addresses **in place in the same dict object** (the `app.py` merge aliases
hold it), then applies the current document; every `save_patched`
**re-derives** the image the same way before emitting, so after apply →
undo → apply → save the written file holds the source bytes at the undone
entry's address and the new entry's bytes (premise P-6 is closed). The
save status — and, per PDR-UX-C6, the **final** painted status line after
the verify result — names what the saved image holds and each entry that
had not been applied before the save, in one line, outcome first, e.g.
`Saved + verified: at_b99_08.s19 — 1 entry applied before this save
(0x0000EB40)`. `before_bytes` is now the source byte even on a repeated
apply (LLR-157.4), and the before/after **strip** reads a journal overlay
(`source_image_view`) so its `was` line shows the source byte; the report
services needed no change (they read `before_bytes` off the summary, which
now carries source bytes). `tui/changes/apply.py` needed **no** change —
with the journal restored before the engine runs, the byte the engine
reads at apply time is the source byte, exactly as the brief predicted.

Design decisions recorded: (1) the journal is keyed to the image **dict
identity** (`_note_image`) rather than to `set_image_generation` — every
load funnels through one install point and the MAC merges reuse the live
dict, so a new dict object means a new file; a MAC attach keeps the dict
and keeps the journal. (2) The journal deliberately **survives**
change-document load/replace (`ChangeService.load`/`load_text`): it
describes the image, and dropping it would leave the previous document's
bytes in the image — the exact P-6 defect; the brief's "document is
replaced (Load)" is implemented as the app Load path (a new image file).
(3) The saved **summary is kept** when the document is still exactly the
one the last apply applied (zero behavioural change for the existing
save-back flows, including the object identity `test_apply_with_save_stamps_saved_path`
pins); it is re-derived only when the document moved (undo/redo/remove/
edit/load or an add), and then lists exactly the entries the image holds.

Shipped surface the user reaches: Patch Editor (`PatchEditorPanel`) Add /
Apply / Undo (`ctrl+z`) / Save-back — the written file and the painted
save-back status.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/change_service.py` | SOURCE (1 of 3) | HLR-157, LLR-157.1/.2/.4 | journal (`_journal`/`_image_map`), `_note_image` / `_restore_journal` / `_capture_journal`, `source_image_view` + `_SourceOverlayMap`, `_applied_addresses` invalidation (undo/redo/remove/edit/edit_entry_json/load/load_text), `save_patched` re-derivation + naming (`last_save_applied` / `last_save_not_applied`, `save_back_status_suffix`), `apply` journal restore + applied-set recording |
| `s19_app/tui/app.py` | SOURCE (2 of 3) | HLR-157, PDR-UX-C6 | `_surface_verify_result` verified arm composes the save-back suffix (the line is the final painted status — UX-C6), `_strip_source_map` helper + the four `refresh_entries` strip-map pushes now feed the journal overlay, save-back handler passes `mac_records` / `a2l_tags` so a re-derived summary keeps its linkage |
| `tests/test_b99_editor_image.py` | test | HLR-157 | TC-B99-21 (p05 + alias + all-undone + overlap arms), TC-B99-22 (remove/edit/add/redo arms + save-blocks-overlap arm, review F1), TC-B99-40 (summary + before/after report + 2 strip arms, one per review F2), AT-B99-08 (full pilot with add-without-apply step, review F3 + forced-mismatch arm, review F5) — 8 nodes (5 at round 1, renamed/extended in review round 1; see the Review round 1 fixes subsection) |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-004.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-4/*` | doc | — | transcripts, hashes, census (outside the count) |

`tui/changes/apply.py` was **not** touched (the journal makes the engine's
apply-time byte read the source byte — as the brief predicted). SOURCE
budget: 2 of 3 used.

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 3** (4 cap) |
| Test files | 1 (uncapped) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched; the frozen engine layer (`tui/changes/apply.py`, `changes/model.py`) untouched.

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # -> C:\Users\jjgh8\Github\s19_app-b99-inc4\s19_app\__init__.py (proved, this session)
pytest tests/test_b99_editor_image.py -q                        # -> 8 passed
pytest tests/test_b99_editor_image.py -k tc_b99_21              # -> 1 passed, 7 deselected
pytest tests/test_b99_editor_image.py -k tc_b99_22              # -> 2 passed, 6 deselected
pytest tests/test_b99_editor_image.py -k tc_b99_40              # -> 3 passed, 5 deselected (TC-B99-40 summary + 2 strip arms)
pytest tests/test_b99_editor_image.py -k at_b99_08              # -> 2 passed, 6 deselected
pytest tests/test_address_census.py -q                          # -> 23 passed
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | none — no new layer-0 shipped-source node; LLR-157.1/.2/.4 ride the TCs below | n/a |
| **A · white-box** `TC-B99-21/22/40` ↔ LLR-157.1/.2/.4 | `core` · `full` | `test_tc_b99_21_editor_image_is_source_plus_document` · `test_tc_b99_22_save_rederives_and_names_not_applied` · `test_tc_b99_22_save_blocks_overlapping_entries` (F1) · `test_tc_b99_40_before_bytes_is_source` · `test_tc_b99_40_strip_shows_source_byte` (renamed from `…40a…`, F6) · `test_tc_b99_40_strip_shows_new_file_source_byte` (F2) | 6 passed |
| **B · black-box** `AT-B99-08` ↔ US-146, through the Textual pilot | `core` · `full` | `test_at_b99_08_save_back_keeps_editor_image` (extended, F3) · `test_at_b99_08_verify_mismatch_status_still_names_entries` (F5) | 2 passed |

Regression companion (reverse-census files, §4 Reverse census):
round-1 run: 30 files, **570 passed, 5 failed** — 1 pre-existing failure also
red at the batch baseline (`test_at031b_two_saves_are_distinct_no_clobber`,
in `baseline-pytest-a293213.txt`) + 4 pilot timing flakes. 3 of the 4 pass in
isolation; `test_at077c_stale_provenance` FAILS in isolation too
(`green-flake-isolation.txt`) — it is flaky on main as well, not bound to
this increment (review finding F7 corrects the round-1 wording).
Round-2 re-run (review fixes in place, 32 files): **586 passed, 5 failed**
(`green-regression.txt`) — the same pre-existing `test_at031b…`, plus 4
load-flakes (`test_save_back_prompt`, `test_verify_quiet_pass_on_faithful_hex_save`,
`test_at068b…`, `test_ac2_1_ctrl_z_y_undo_redo_via_real_key`), each shown
flaky/pre-existing on the base `9d7fb18` (the save-back-prompt flaked 3/6
SOLO on base; the 4-test combination flaked on base too; each passes solo
on the fixed tree) and none asserts an HLR-157 behaviour.
`tests/test_address_census.py` — 23 passed (round 2).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | 4, one per declared negative control (see Mutation verdicts) — each applied, shown RED, reverted; restore verified by SHA-256 |
| Instrument | project code: the implementer's own hand via the Edit tool; restore checked by SHA-256 against the recorded fixed-tree hashes |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc4`), run by the implementer |
| Transcript | `evidence/inc-4/mut-LLR-157.1.txt` · `mut-LLR-157.1-alias.txt` · `mut-LLR-157.2.txt` · `mut-LLR-157.4.txt` (each: the targeted node FAILED) |
| Restore proven by | `change_service.py` back to `b07708f602b8…` and `app.py` back to `613a0ff05c7e…` after every revert (`fixed-tree-hashes.txt`); no mutant left in place |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | 1 per mutation run (each `-k` run resolves exactly its node(s) + deselected) |
| Verdict granularity | per resolved node id: `test_tc_b99_21_editor_image_is_source_plus_document` (mut 157.1 and 157.1-alias), `test_tc_b99_22_save_rederives_and_names_not_applied` (mut 157.2), `test_tc_b99_40_before_bytes_is_source` + `test_tc_b99_40_strip_shows_source_byte` (mut 157.4, re-run under its F6-renamed id) |
| Arms that stayed GREEN | none |

| Field | Value |
|---|---|
| **RED counterfactual** | baseline RED (tests in, tree unmodified): all 5 nodes FAILED on their exact oracles — `red-initial.txt`: TC-21 "the undone entry must return to the source bytes, got [222, 173, 190, 239]", TC-22 "remove-after-apply left stale bytes", TC-40 "before_bytes must be the source byte, got (222, 173, 190, 239)", TC-40a strip `was    DE AD BE EF`, AT "the undone entry reached the file: [222, 173, 190, 239]" — the P-6 premise reproduced. The premise-side negative control (executed on `307065f`, P-6: `file @0xEB10 = deadbeef`) is this same mechanism. |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-157.1 · TC-B99-21: skip the journal restore in `apply` · KILLED — `test_tc_b99_21…:207 FAILED` · transcript `mut-LLR-157.1.txt` · restore `b07708f6…` ‖ LLR-157.1 alias arm · TC-B99-21: restore into a REBOUND dict (aliases stay stale) · KILLED — `:188 FAILED` (the alias assertion) · transcript `mut-LLR-157.1-alias.txt` · restore `b07708f6…` ‖ LLR-157.2 · TC-B99-22: skip the save re-derive (no journal restore / re-apply) · KILLED — `:253 FAILED` (remove arm, stale bytes in the saved image) · transcript `mut-LLR-157.2.txt` · restore `b07708f6…` ‖ LLR-157.4 · TC-B99-40/40a: journal captured AFTER the engine write (image byte kept as `before_bytes`) · KILLED — both `test_tc_b99_40_before_bytes_is_source:394` and `test_tc_b99_40a_strip_shows_source_byte` FAILED (the strip node since renamed `test_tc_b99_40_strip_shows_source_byte`, F6) · transcript `mut-LLR-157.4.txt` · restore `b07708f6…` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the unmodified tree (journal absent) | 5 nodes FAILED on their oracles (`red-initial.txt`) |
| `pytest` + TC-B99-21 | the LLR-157.1 mutants (restore skipped / rebound) | `test_tc_b99_21… FAILED` at the file-bytes / alias arms (`mut-LLR-157.1.txt`, `mut-LLR-157.1-alias.txt`) |
| `pytest` + TC-B99-22 | the LLR-157.2 mutant (re-derive skipped) | `test_tc_b99_22… FAILED` at the remove arm (`mut-LLR-157.2.txt`) |
| `pytest` + TC-B99-40 strip arms | the LLR-157.4 mutant (capture after write) | both TC-B99-40 nodes FAILED (`mut-LLR-157.4.txt`) |
| the independent reader (oracle) | the unmodified tree's saved file | reported `deadbeef` at 0xEB10 where the source holds `20 41 70 70` (`red-initial.txt` AT arm) |
| the Textual pilot (painted status) | the unmodified tree's save-back | the final status carries no entry name — the AT's `0x0000EB40` assertion FAILED (`red-initial.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 6 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the save-back S19 file (emitted by `save_patched_image` through the app) | AT-B99-08 / TC-B99-21/22 read it with `tests/support/independent_reader.py` (zero `s19_app` imports) | source bytes `20 41 70 70` at 0xEB10 and `01 02` at 0xEB40 (`green-at_b99_08.txt`, `green-tc_b99_21.txt`, `green-tc_b99_22.txt`) |
| the painted save-back status (emitted by `app.py`) | AT-B99-08 reads `#log_line_4` after the handler returns | `Saved + verified: at_b99_08.s19 — 1 entry applied before this save (0x0000EB40)`, unchanged after 10 more paints (`green-at_b99_08.txt`) |
| the before/after report `.md` (emitted by `compose_before_after_report`) | TC-B99-40 reads the file from disk; the 0xEB10 linkage row's BEFORE cell must hold `20 41 70 70` left of the AFTER cell | row found, before cell shows the source byte (`green-tc_b99_40.txt`) |
| the strip's painted text (emitted by the panel) | `test_tc_b99_40_strip_shows_source_byte` reads the card's plain text after apply → apply | `was    20 41 70 70`, `now    DE AD BE EF` (`green-tc_b99_40.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 artifacts, each asserted against the form its producer emitted |

### Review round 1 fixes (code-reviewer findings F1–F7)

All seven findings fixed in this worktree (2 SOURCE files, both already in this
increment's budget; tests uncapped). RED-first for the fix round:
`red-fix-round.txt` — the 4 new/extended nodes FAILED on the round-1 tree
(4 failed, 4 passed), and the F2 strip arm reproduced the defect verbatim:
the strip painted `was    20 41 70 70 -- -- -- --` over file B's map after
file B loaded. GREEN: `green-fix-round.txt` — 8 passed; AT-B99-08 driven 8×
— `green-at_b99_08-x8.txt`.

| F | Finding | Fix | Arm (test) | Mutation / RED proof |
|---|---|---|---|---|
| F1 (HIGH) | `save_patched` wrote overlapping entries the `apply` refuses | the save re-derive runs the SAME collision refresh as `apply` (`change_service.py`) and refuses a blocked document: nothing written, `message` names the blocked count, `issues` carry `CHG-COLLISION` | `test_tc_b99_22_save_blocks_overlapping_entries` — the reviewer's probe exactly: add `0xEB10`, apply, add `0xEB12`, SAVE (no apply after the overlapping add) | skip the save refresh → RED, probe symptom reproduced (`ok=True`, both entries listed) — `mut-F1.txt` |
| F2 (HIGH) | the before/after strip showed the OLD file's bytes after a new file loaded | `source_image_view` returns `mem_map` unchanged when it is not the bound dict (`mem_map is not self._image_map`) and rebinds via `_note_image` — the journal resets onto the new map at the strip refresh, not at the next apply | `test_tc_b99_40_strip_shows_new_file_source_byte` — load A, apply, load B (`0x99`-run at the strip address): the strip's `was` line shows `99 98 97 96`, never A's `20 41 70 70` | RED on the round-1 tree: `was    20 41 70 70` painted over B's map (`red-fix-round.txt`) |
| F3 (MEDIUM) | the "not applied before the save" status was untested | AT extended: a third entry (`0xEB60 05 06`) is added WITHOUT an apply before the save; the painted status must name it with the singular "1 entry" count (the pilot runs at 160 columns so the width-aware log cap `max(50, width)` paints the two-clause line untrimmed) | `test_at_b99_08_save_back_keeps_editor_image` step 2b + suffix assertions | drop the names from the status → RED — `mut-F3.txt` |
| F4 (MEDIUM) | 3 wrong digests in this packet (`green-tc_b99_22`, `green-address-census` (63 digits), `green-flake-isolation`) | every digest recomputed from the stored bytes; the table now agrees with `SHA256SUMS.txt` and the files (transposed-character typos) | — | — |
| F5 (MEDIUM) | the mismatch arm of the save status lacked the not-applied names | `_surface_verify_result` composes the SAME `save_back_status_suffix` on the `mismatch` arm (`app.py`) — UX-C6 and HLR-157 allow no exception; the round-1 §5 scope cut is rescinded | `test_at_b99_08_verify_mismatch_status_still_names_entries` — forced verify mismatch (the engine entry point `change_service.verify_written_image` patched to a mismatch result; the pilot itself stays black-box: real keys/clicks, painted status) | RED on the round-1 tree: the mismatch line carried no naming (`red-fix-round.txt`) |
| F6 (MEDIUM) | the invented test id `test_tc_b99_40a_*` | renamed `test_tc_b99_40_strip_shows_source_byte` — a TC-B99-40 sub-node arm, no new id invented; all packet references updated | — | — |
| F7 (LOW) | the packet claimed the 4 flaky tests "pass deterministically in isolation"; its own transcript shows `at077c` failing in isolation | claim corrected in §4 / §6: `test_at077c_stale_provenance` FAILS in isolation (`green-flake-isolation.txt`) — it is flaky on main as well; the other 3 pass in isolation | — | — |

Honesty notes: (1) the F1 arm's first RED was a `NameError` (a missing test
import) and its first structure was VACUOUS — the premise apply stamped the
collision into the document, so the save's own missing refresh was masked
(the arm passed with the refresh skipped). It was restructured to the
reviewer's exact probe (no apply between the overlapping add and the save)
and then shown load-bearing: it FAILS against the F1 mutant (`mut-F1.txt`)
while the re-run of the 4 round-1 mutations stays RED on their own targets.
(2) The 4 round-1 mutations were re-run plus the 2 new ones (F1, F3): 6/6
KILLED, each reverted by SHA-256 to `fixed-tree-hashes.txt` (refreshed for
the round-2 tree); no mutant left in place.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-4/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED baseline (unmodified tree, 5 failed) | `red-initial.txt` | `2da973b69f17b3ac836a3144acd62ffd8447e692f5da66a324849c379ade1c7a` |
| GREEN full run (5 passed) | `green-editor-image.txt` | `1d04ab07a8967ce79b3097c9756fde4c7c60e73342c17921547a52b23b486623` |
| GREEN TC-B99-21 | `green-tc_b99_21.txt` | `cc38d973857bd7b11229a892d01adb7233fc7d1c963568d21a91caa89f93cde6` |
| GREEN TC-B99-22 | `green-tc_b99_22.txt` | `52a03cecd5feeb15c1166ad228473b2fdbc33145865b1c001618678ee41f8a3a` |
| GREEN TC-B99-40 (round-1 `-k tc_b99_40` run) | `green-tc_b99_40.txt` | `4da0effc28e5f137c10f0dd1262923323d486bf707675f61ff1517f005cbe626` |
| GREEN AT-B99-08 | `green-at_b99_08.txt` | `828310c345f571e2b9c0b0d70caab23b441753175fc66359f7add9a409336929` |
| GREEN regression companion (round-2 re-run, 32 census files, 586 passed) | `green-regression.txt` | `d254c4d7df995df9db8a99ab7320b9e4c5952232daccb1f61f57fd50440fadfd` |
| GREEN address census (23 passed) | `green-address-census.txt` | `a5ae8a9580e3d978e68ad10f5be8daeb216b5d13c26a09e131abeec26d13752c` |
| Flake isolation re-run (at077c red IN isolation — flaky on main, F7) | `green-flake-isolation.txt` | `24305c2685836f6d9d2d0b84732df1a6ce068945d4b03e2e0d3081f4e54af0c9` |
| Mutation LLR-157.1 (KILLED) | `mut-LLR-157.1.txt` | `5e3c10d89f8fc61c2103519e7021ed3668d7692dfcd89b8e0f20eb776de55147` |
| Mutation LLR-157.1 alias arm (KILLED) | `mut-LLR-157.1-alias.txt` | `5f0c23f51b92e5c83e0123817cacd3fc4aece0fa6d0c96764ffcb8c44c32dc60` |
| Mutation LLR-157.2 (KILLED) | `mut-LLR-157.2.txt` | `da4e0b5288203b4fc36e536f1dffecc07123f5893a08c533a2077d51b5cc2866` |
| Mutation LLR-157.4 (KILLED) | `mut-LLR-157.4.txt` | `84131820f2ec4a7f7da53a7e0464444f2884df06f5e41aeb10f7b3d7103805b0` |
| Reverse census probes (refreshed round 2) | `reverse-census.txt` | `c5a3a26abe8061f7a8fcc48731880a1ae536a8bd53cfd289d3baf87a3654be67` |
| Pre-mutation (baseline) hashes | `baseline-hashes.txt` | `bde09ea79d71e3a2dca225c6216ac4e48d1f36a512dd7b3e0f409c397460f4f4` |
| Fixed-tree hashes (restore target) | `fixed-tree-hashes.txt` | `3211697678b5dd2f5cf4673b0a4243b2752019b3ec116def2f620c2055421a1f` |
| RED review-fix round (4 failed/4 passed, round-1 tree) | `red-fix-round.txt` | `d6526dd45db7bce485e0fb581b4424354f362cc00f08d7daed2405e19872e78f` |
| GREEN review-fix round (8 passed) | `green-fix-round.txt` | `ff9d709ae8363cda12c1e2b0cb476edffe740b696e036cf4e4d74f5f8c970fa9` |
| GREEN AT-B99-08 ×8 (each run 2 passed) | `green-at_b99_08-x8.txt` | `d3dcd49e595be41d8345597ebff51f66d5087e70c4fa0905945b3d5f319886ff` |
| Mutation F1 — skip the save collision refresh (KILLED) | `mut-F1.txt` | `1282404b04543532d60eb22fd58fdb4df247610985253d3abe01ddab27cefc2a` |
| Mutation F3 — drop the not-applied names (KILLED) | `mut-F3.txt` | `3c3cde8388a14a1208693aed8658c209eb3e11354771bbb698a69cfec68fbf18` |

`SHA256SUMS.txt` is the folder's own digest list (LF line endings, the sums
file excluded from its own list); every digest above is of the stored
working-tree bytes.

| Field | Value |
|---|---|
| **Evidence files** | 16 artifacts, each at the declared home and cited with the digest of its stored bytes |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) no pre-existing test pins the old save status/message text; (2) the strip overlay is a no-op while the journal is empty (fresh load) |
| If the result is an ABSENCE, what made the search wide enough | (1) `grep -rn "Saved + verified\|Patched image saved as" tests/` over the whole suite — the only pins are substring `Saved + verified` (compatible with the suffix) and none on the message; (2) the overlay decision is exercised by construction: `source_image_view` returns the live map itself when `not self._journal` |
| Guard labelled as protecting a CONCLUSION, not a behaviour | AT-B99-08's "stays visible" arm — it re-reads `#log_line_4` after 10 more paints and fails if any later status overwrote the line (the PDR-UX-C6 defect class) |
| Conjunctive criteria: one mutation per conjunct | the journal restore has two conjuncts — VALUE (skip restore) and PLACE (rebind) — each mutated separately (`mut-LLR-157.1.txt`, `mut-LLR-157.1-alias.txt`) |
| Synthetic instance of the absent case | each mutant IS the forbidden implementation, existing only transiently and reverted by hash; the RED baseline IS the absent-journal case |

| Field | Value |
|---|---|
| **Positive control for every probe that returned an ABSENCE** | (1) the new AT pins the NEW text (`Saved + verified: at_b99_08.s19 — 1 entry applied before this save (0x0000EB40)`) — a non-absent output of the identical probe surface; (2) `test_tc_b99_40_strip_shows_source_byte` shows the overlay changing the painted `was` bytes after an apply (non-empty journal arm of the identical code path) |

### Reverse census — trigger family B, and A3

Probe: `grep -rln --include='*.py' "ChangeService\|save_patched\|before_bytes\|_surface_verify_result\|last_summary" tests/` → 32 files, all re-validated by the regression run (§4) and the per-symbol probes below. **No test re-pinned** — HLR-157 changes behaviour, but no existing assertion pinned the old behaviour (each old-pin candidate is analysed below).

| Probe | Command | Result |
|---|---|---|
| B1a `save_patched` callers | `grep -rln "save_patched" tests/` → 9 files | all re-validated green in the regression run; the service tests hold the summary OBJECT from `apply` and assert `save_patched` stamps it — preserved by the keep-when-unchanged design (no re-pin) |
| B1b `_surface_verify_result` pins | `grep -rn "Saved + verified" tests/` | 3 hits — two are this increment's own AT; the third (`test_tui_patch_editor_v2.py:931`) asserts the SUBSTRING `Saved + verified`, which the suffixed line keeps — no re-pin |
| B1c save message pins | `grep -rn "Patched image saved as" tests/` | none — the suffix on the service message breaks no pin |
| B1d `before_bytes` engine pins | `grep -n "before_bytes" tests/test_changes_apply.py` | lines 100/166/237 assert the ENGINE's `apply_change_document` directly (no service, no journal) — untouched semantics, all green |
| B3 golden captures | `grep -rl "save-back\|before.after" tests/goldens/ tests/__snapshots__/` | no snapshot or golden captures the Patch Editor save-back status or the strip after an apply — nothing re-pinned (the strip overlay changes painted bytes only after an apply, and no snapshot pins that state) |
| B4 artifact consumed elsewhere | `grep -rln "last_save_applied\|save_back_status_suffix\|source_image_view" tests/ s19_app/` | only this increment's own consumers (app.py + the new TCs) |
| A3 interface consumed by another module changed | `save_patched` gained two OPTIONAL trailing kwargs (`mac_records`, `a2l_tags`); `_surface_verify_result` line format extended | both call sites updated in the same commit; the engine layer (`tui/changes/apply.py`, `changes/model.py`) is untouched |

| Field | Value |
|---|---|
| **Reverse census** | 32-file census executed (28 at round 1 + `test_b99_editor_image.py` + 3 files added by the later increments in the base), re-validated in review round 1; 4 per-symbol probes — 0 re-pins. Round-1 regression: 570 passed, 5 failed (1 pre-existing `test_at031b…`, red at the batch baseline `baseline-pytest-a293213.txt`, + 4 load-flakes `saveback_width_32…` / `at077c_stale_provenance` / `at081b_bounds` / `tc_b94_27_lane_binding…` — the last three pass in isolation, `at077c` FAILS in isolation too: flaky on main, F7). Round-2 regression: 586 passed, 5 failed — the same pre-existing `test_at031b…` + 4 load-flakes (`test_save_back_prompt` — flakes 3/6 SOLO on base `9d7fb18`; `test_verify_quiet_pass_on_faithful_hex_save`; `test_at068b…`; `test_ac2_1…` — the 4-test combination flakes on base too), none asserts an HLR-157 behaviour |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| apply must restore the journal in place before the engine runs | `ChangeService.apply` (1 service site; engine untouched) | the writer census of `mem_map` mutators (ARQ §2) + the apply call graph | 1 | 1 | 0 |
| save must re-derive + name not-applied entries | `ChangeService.save_patched` (1 service site) + its app caller (status path) | LLR-157.2 statement + PDR-UX-C6 (`app.py:3388-3390`, `:3904` at baseline) | 2 | 2 | 0 |
| strip must show the source byte | the app's strip-map pushes (`refresh_entries` call sites) | `grep -n "refresh_entries(" app.py` → 4 app sites + the panel's retain contract | 4 | 4 | 0 (the panel itself reads `_mem_map` only in `_render_before_after_card` — verified by grep before editing) |
| applied-set invalidation on document mutation | `undo` / `redo` / `remove_entry` / `edit_entry` / `edit_entry_json` / `load` / `load_text` | grep of every method that replaces/mutates `document` | 7 | 7 | 0 (`add_entry` / `add_symbol_entry` deliberately NOT invalidated — the added entry is exactly what the save must name) |

| Field | Value |
|---|---|
| **Correction population** | 4 corrections, 14 sites enumerated before the first edit, 14 edited, 0 left |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| none — no marker superseded | n/a | n/a | n/a |

### Signed-balance test ledger

`post = base − deleted + added` → `8 = 0 − 0 + 8` ✓ reconciles
(`tests/test_b99_editor_image.py`: 0 baseline nodes — new file — 0 deleted,
5 added at round 1: TC-B99-21, TC-B99-22, TC-B99-40, TC-B99-40 (strip arm)
(renamed `test_tc_b99_40_strip_shows_source_byte` in review round 1, F6),
AT-B99-08; review round 1 added 3 nodes (`test_tc_b99_22_save_blocks_overlapping_entries`,
`test_tc_b99_40_strip_shows_new_file_source_byte`,
`test_at_b99_08_verify_mismatch_status_still_names_entries`) — ledger:
`8 = 0 − 0 + 8`; the regression files changed by 0 nodes — no re-pins.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: BLOCK (F1 HIGH save wrote overlapping entries apply refuses; F2 HIGH strip showed the old file after a reload; F3–F6 MEDIUM incl. an invented test id and a UX-C6 scope cut; F7 LOW) · round 2: PASS-WITH-NOTES, F1–F7 closed (F2/F5 fixes mutation-checked by the reviewer); N1–N3 LOW routed to BACKLOG-CODE; N4 fixed here; N5: the edited files are LF like HEAD (the HANDOFF "pure CRLF" claim was wrong) |

---

## 5 · Risks

- The journal binds to the image **dict object** (`_note_image`). Every
  shipped load path funnels through one install point and the MAC merges
  reuse the live dict (verified at the merge constructors), so dict
  identity is the image identity on this seam; a future load path that
  mutates the map IN PLACE across a file change would defeat it — the
  journal would restore stale addresses. The strong reference held on the
  bound dict makes `id()` reuse a non-issue (the LLR-077.2 lesson).
- Flow executions (`flow_execution_service`) call the engine directly with
  a fresh image and never re-apply, so their `before_bytes` is the source
  byte by construction — they do not use the journal. If a future flow
  re-applies a document, it must restore first (the journal is a Patch
  Editor seam today).
- UX-C6 is closed on BOTH verify arms since review round 1 (finding F5):
  a `mismatch` paints `Verify MISMATCH: {name}` + the same
  ``save_back_status_suffix`` naming as the verified arm (asserted by the
  AT-B99-08 mismatch arm with a forced verify mismatch). The round-1
  mismatch-arm scope cut is rescinded by this fix.
- The save message and the final status can name many entries (one
  `0x…` token per not-applied entry, document order); the log line view's
  50-cell trim (LLR-003.2) may truncate a very long list — the untrimmed
  text still reaches `#patch_doc_status` / the log, and AT-B99-08 asserts
  the single-entry shape.

## 6 · Pending items / spec deviations

- The brief's "reset the journal … when the document is replaced (Load)"
  is implemented as **a new image file loaded** (dict-identity reset at the
  next apply/save): the journal deliberately survives change-document
  load/replace, because it records SOURCE bytes of the loaded image and
  dropping it re-introduces the P-6 stale-byte defect across a document
  reload. Recorded here as a declared reading, traceable to the HLR-157
  statement ("keep the image equal to the source image plus the effect of
  the document's entries").
- Pre-existing, not mine: `test_at031b_two_saves_are_distinct_no_clobber`
  fails at the batch baseline too (orchestrator's full-suite run owns it).
- 4 pilot timing flakes bound in the reverse census — 3 green in
  isolation; `test_at077c_stale_provenance` is flaky on main as well (red
  in isolation, `green-flake-isolation.txt`; review finding F7 corrects the
  round-1 claim that all 4 pass in isolation). No re-pins.
- Round-2 census failures (586 passed, 5 failed, `green-regression.txt`):
  the pre-existing `test_at031b…` plus 4 load-flakes
  (`test_save_back_prompt` flakes 3/6 SOLO on the base `9d7fb18`;
  `test_verify_quiet_pass_on_faithful_hex_save`, `test_at068b…`,
  `test_ac2_1…` — the 4-test combination flaked on base too; each passes
  solo on the fixed tree). None asserts an HLR-157 behaviour; no re-pins.
- Review round 1 (F1–F7) is fully discharged in the §4 "Review round 1
  fixes" subsection; the F1 arm's initial vacuous structure is recorded
  there with its correction.

## 7 · Suggested next task

Batch-99 Increment 5 (per the orchestrator's plan). This increment's
`tests/support/independent_reader.py` oracle and the `save_back_status_suffix`
carrier are reused by any later increment that drives the Patch Editor
save-back (e.g. the UX-C9 walkthrough evidence at Phase 4).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 SOURCE files (`git status` — `change_service.py`, `app.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_editor_image.py` (5 nodes, this increment) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — no layer-0 shipped-source node; LLR-157.1/.2/.4 verified by the TCs |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: baseline RED `red-initial.txt` (5 failed, exact oracles) + 4 mutations with transcripts + restore digests |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 32-file census (round 2), 4 per-symbol probes, 0 re-pins; failures bound (1 pre-existing baseline + load-flakes reproduced on base `9d7fb18`) |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — 2 SOURCE + 1 test + this packet + evidence |
| 8 | Frozen interfaces untouched | all | ✓ | `tui/changes/apply.py` and `changes/model.py` untouched; the engine's `before_bytes` contract now holds by the journal restore |
| 9 | Coverage claims verified **on disk** | all | ✓ | every TC reads the saved file / the report / the painted surface from disk or the live pilot; the fixture S19 is written per test |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (the AT pins the new status text; `test_tc_b99_40_strip_shows_source_byte` exercises the non-empty journal arm) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: 4 mutations, per-arm KILLED, no surviving mutant |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 6 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: 4 corrections, 14 sites enumerated before the first edit |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 4 artifacts asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` (the one published form for a not-yet-reviewed packet) |
| 16 | **Evidence files** declared | all | ✓ | §4: 16 artifacts with stored-byte SHA-256 digests |
