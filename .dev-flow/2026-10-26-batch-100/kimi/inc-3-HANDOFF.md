# HANDOFF — batch-100 Increment 3 (kimi, worktree s19_app-b100-inc3)

## What is done

- **HLR-165 / LLR-165.1–165.4 implemented** in the ONE named SOURCE file
  `s19_app/tui/app.py` (1/4, CRLF preserved, syntax-clean):
  - `_reset_project_session()` — the one reset seam: S1–S13 + A-07's 11 probe
    names, `ChangeService` rebind + `set_image_generation` re-push, Patch
    panel `refresh_entries` repaint + the panel's public `mark_loaded()`
    (LED .55(b)), returns the outgoing entry count.
    Called once in `_handle_load_project`, after `validate_project_files`,
    before the first install; the LED .55(a) notice
    `Closed the Patch Editor document (N entries); unsaved changes were
    not kept` paints as the freshest status line when N > 0.
  - `_session_snapshot()` + `_SESSION_SNAPSHOT_NAMES` (68-name domain) — the
    B100-I19 seam; QA R2-07 normalisation of the three keyed caches.
  - `_apply_unload("all"|"a2l")` clears `current_a2l_data` (LLR-165.4, P-25).
- **Tests**: `tests/test_b100_session_reset.py` — 16 nodes (TC-B100-08 ×3,
  TC-B100-09 ×4, TC-B100-10 ×4 incl. the LED .51 arms, TC-B100-11 ×3,
  AT-B100-03 ×2 sizes). `tests/test_id_registry.py` 216 → 217.
- **RED**: 14 failed / 2 passed at base (red-01 first shaping, red-02 AT
  through the UI, red-03 corrected file vs base `git show` restore) + the
  executed p03 premise cited.
- **GREEN**: all 16 nodes (green-03, 121 s). The two earlier green runs
  (green-01/02) show three test-file bugs found and fixed along the way
  (missing P1 seed, AST walk order, AT wait target).
- **Mutations**: all 5 declared mutants KILLED, each restored and
  hash-verified (`mutations-all.txt`; harness kept at
  `evidence/inc-3/mutation_harness.py`).
- **Reverse census** (39 files, 4 batches): A 218 ✓, B 328 ✓ + 1 pre-existing
  failure (`test_at_b78_03`, fails identically at base —
  `preexisting-at-b78-03.txt`), C 221 ✓ + 1 pre-existing deterministic
  (`test_at_056e_a2b…`, fails at base — `preexisting-batch-c.txt`) + 3 timing
  flakes of the repo's documented single-pause family (`test_at078b_zero_total`
  proven flaky AT BASE with the identical empty-strip shape —
  `preexisting-at078b-flake.txt`; passes 3 consecutive isolation runs on this
  tree — `green-06c`; the two `test_tui_patch_editor_v2` nodes pass in
  isolation — `green-06b`), D 194 ✓.
- **Guards**: `guards.txt` 75 passed, 0 failed, NO snapshot cell changed;
  `guards-census.txt` 87 passed. Registry bump verified inside the guards.
- **Packet**: `.dev-flow/2026-10-26-batch-100/03-increments/increment-003.md`
  complete (§1–§7; §4b `pending — orchestrator`), evidence table with 21
  SHA-256 digests.

## State

- Working tree: `s19_app/tui/app.py` + `tests/test_id_registry.py` modified,
  `tests/test_b100_session_reset.py` + `.dev-flow/...` untracked. NOT
  committed (orchestrator commits). app.py final sha256
  `ca8e539b4c8c3c812e9460ac88d72c32e62e9a79c180646d29c3f6d9b62f6c45`, pure
  CRLF (14460/14460).

## Open questions / routed items

1. **Empty declared exclusion list** (LLR-165.2 wants Textual internals
   "each with its reason"): the live AST census finds none in the source at
   this commit; the list is declared empty with the classification arm
   enforcing 0-unclassified (mutant m3 proves a silent drop is RED). For the
   orchestrator to confirm as compliant.
2. **S13's `_mac_view_cache_*` count**: RESOLVED in fix pass 1 (finding
   F10) — the seam comment now says "all eight" (matching the invalidator's
   census; the ARQ §2.2 inventory text predates `widths`). For the
   orchestrator: mirror the 8 (and the two Inc-era classifications:
   `_last_manifest_verify_result` install-owned, `_variant_set_value` the
   `_variant_set` backing store) into the ARQ §2.2 inventory text itself.
3. **Pre-existing failures found by the reverse census, NOT caused by this
   increment** (each probed at base by swapping only app.py): the batch-78
   frozen palette artifact (`test_at_b78_03`, 2 actions stale) and
   `test_at_056e_a2b_diff_report_byte_identical_despite_selection` need an
   owner; the `test_at078b_zero_total` single-pause race joins Inc 1's
   documented flake family. If the orchestrator's gate wants these green,
   they need their own fix increments (out of this increment's 1-file scope).
4. ~~Interim discard notice counts document entries~~ RESOLVED by LED
   .55(a) (fix pass 1, review finding F2): the line now reads `Closed the
   Patch Editor document (N entries); unsaved changes were not kept` — it
   states only what Inc 3 can know and never calls saved/loaded entries
   "unsaved". Inc 10's question (keyed on the panel's dirty flag) replaces
   it.
5. TC-B100-09's load-over comparison arm is relative by design — an order
   mutation that damages both sessions equally (m1) escapes it; the
   direct-state and order arms carry that kill (named per verdict in §4).

## Fix pass 1 — DONE (code-review F1–F11 + LED .55)

All 11 findings addressed; §4b left `pending — orchestrator` for the reviewer's
re-read (F1's stated discharge: the re-read plus his own R6 re-run — my executed
re-run goes RED naming `_last_template_path`).

- **F1 (HIGH, the BLOCK):** both TC-B100-09 arms seed non-default values for the
  full S5–S12 + A-07 inventory (`_seed_p1_derived_state`). The reviewer's **R6
  re-run: KILLED — 2 failed/15 passed** (`mut-fix1-r6-drop-s7-s11.txt`), the
  relative arm's LEAK line names `_last_template_path` (the S7 name) with S8–S11
  alongside. R6 SURVIVED 16/16 at round 1.
- **F2 + LED .55(a):** the notice reads exactly `Closed the Patch Editor document
  (N entries); unsaved changes were not kept`, painted when the outgoing document
  holds N > 0 entries. All four arms re-pinned (3 white-box + the AT at both
  sizes); RED-first evidence vs the round-1 tree kept (`red-fix1-notice-and-marker.
  txt`, 5 failed/12 passed — the re-pinned notice arms + AT sizes, plus one
  test-side bug the new direct inventory caught: `_validation_report is None` was
  wrong because P2's own install writes a fresh report — corrected to "P1's seeded
  report is gone" before the GREEN run).
- **F3 + LED .55(b):** the seam calls the panel's public `mark_loaded()` after the
  `refresh_entries` repaint (screens_directionb.py NOT edited). The AT now asserts
  by keys: `●` painted after the entry add (vacuity guard), `0 entries` with no
  `●` after the load-over, both sizes.
- **F4:** new mutant m6 (the count read AFTER the rebind → N=0, no line) KILLED
  all four notice arms (`mut-fix1-m6-notice-after-rebind.txt`, 4 failed). The m4
  and m1 rows corrected against FULL-MODULE re-runs (`mut-fix1-m4-service.txt` 6
  failed — the notice arms stay GREEN under m4, the reviewer's correction;
  `mut-fix1-m1-order.txt` 4 failed — now evidencing the 2 AT kills the round-1
  record omitted).
- **F5:** batch-C record rewritten to match the transcripts — `at030c` FAILED in
  `green-06b` (flake, 3/3 green on both trees in the reviewer's probe); the three
  un-dispositioned first-run nodes in `green-06` named
  (`at078a_counts`, `save_back_prompt`,
  `saveback_width_16_caps_records_and_empties_s0` — all 3/3 green on both trees).
  Reviewer's 3-runs-per-tree probe copied as `preexist-base-3runs.txt` /
  `preexist-fixed-3runs.txt` (provenance headers).
- **F6:** LLR-165.3 boundary arm added — `test_tc_b100_10_outgoing_service_
  finishes_after_rebind`: a worker holding the outgoing service finishes across
  the load-over (no exception) and the rebound service is untouched; killed by m4.
- **F7:** R10 executed (`mut-fix1-r10-no-key-normaliser.txt`, KILLED — the two
  snapshot arms) recorded as LLR-165.2's third negative control; the 3 base
  failures labeled missing-method (`AttributeError: _session_snapshot`) in the RED
  table, with m2/m3/R10 named as their behavioural RED.
- **F8:** the AT asserts `#patch_doc_entries_table` has 0 rows and
  `#patch_doc_empty_state` shows `EMPTY_STATE_TEXT` after the load-over.
- **F9:** dicts reduce to `(len, sorted keys, sha256 of the normalised values)`;
  the image digest feeds `address:byte` pairs.
- **F10:** the "seven" comment says eight (matching the invalidator's census); the
  two Inc-era names classified in the domain comment (install-owned /
  `_variant_set` backing store) — for the orchestrator to mirror into the ARQ
  §2.2 inventory text.
- **F11:** evidence rows re-derived with `devflow-evidence.py --write … --rederive`
  (32 rows, FULL repo paths); `--check` reports 0 unbound rows (exit 1 only on the
  not-staged index limb).

**Re-ran:** the module (17 passed, 94 s), the reverse-census files that own the
panel (`test_b97_patch_editor` + `test_tui_patch_editor_b94` +
`test_tui_patch_variant`: 66 passed), the six guards (**75 passed, 29 snapshots
passed, no snapshot cell changed**), the census sweep (87 passed), and the five
fix-pass mutants above (each restored, hash-verified; final app.py
`18ee4d450529d0cb…`, pure CRLF). Packet §1/§2/§4/§5/§6 updated; §4b `pending —
orchestrator`. Nothing committed.

Files changed this pass: `s19_app/tui/app.py` (1 SOURCE — notice wording, mark_loaded
call, F9 normaliser, F10 comment/classification) + `tests/test_b100_session_reset.py`
(seeding, re-pins, 1 new node, AT assertions) + packet/evidence records.

__KIMI_UNIT_DONE_FIX1__
Files changed: s19_app/tui/app.py (1 SOURCE: LED .55(a) notice wording, mark_loaded in the seam, F9 dict/address-byte normaliser, F10 eight-caches comment + 2 Inc-era classifications) + tests/test_b100_session_reset.py (F1 seeding in both TC-B100-09 arms, 3 notice arms + AT re-pinned to LED .55(a), F6 worker boundary arm, F8 + LED .55(b) AT assertions) + increment-003.md packet + 12 new evidence transcripts.
Tests: 16 → 17 nodes; RED-first for the re-pinned arms (5 failed/12 passed vs round-1 tree); GREEN 17/17 in 94 s; reverse census 66 passed; guards 75 passed (29 snapshots, no cell changed); census sweep 87.
RED/GREEN: base RED 14/2 (round 1, unchanged) with the 3 missing-method failures now labeled (F7); fix-pass RED 5/12; GREEN 17/17 + all guard layers green.
Mutations: 8 verdicts — round-1 m1/m2/m3/m4/m5 + fix-pass R6 (KILLED, F1 discharged, S7 in the LEAK line), R10 (KILLED, LLR-165.2's third negative control), m6 (KILLED, the notice arms' first killing mutant); every mutant restored and SHA-256-verified; evidence rows re-derived with full paths (F11), --check binds all 32.
Open questions: §4b awaits the reviewer's re-read (F1 discharge per his wording); orchestrator to mirror the 8-cache count + 2 Inc-era classifications into the ARQ §2.2 inventory text and to keep owning the 2 pre-existing base failures (at_b78_03 palette artifact, at_056e_a2b).

## Fix pass 2 — DONE (review round 2: R2-1 MAJOR, R2-2 MINOR)

- **R2-1 (MAJOR, LED .55(b) paste buffer):** fix pass 1's `panel.mark_loaded()` cleared
  only the dirty flag — P1's draft text survived in the paste buffer, now marked clean,
  so "Parse pasted" could have applied P1's draft to P2 (ARQ §2.2 U1; PH-2 break). The
  seam now clears the buffer through its own widget
  (`self.query_one("#patch_paste_text", TextArea).text = ""`) and calls
  `panel.mark_loaded()` DEFERRED — `self.call_after_refresh(panel.mark_loaded)` — so
  the buffer's `TextArea.Changed` message (whose panel handler re-sets the dirty flag,
  writer w2) is handled BEFORE the marker is cleared. `screens_directionb.py` NOT
  edited; the seam's comment now describes exactly this (round 2 had flagged the
  comment as claiming `mark_loaded` clears the buffer).
- **Test (AT-B100-03, both sizes, by keys):** the AT clicks the panel's JSON tab chip,
  clicks `#patch_paste_text`, types `P1 DRAFT` (vacuity guard: draft IS in the buffer
  pre-load), clicks back to the Inspector tab, then loads P2. Post-load assertions
  (polled): the buffer is EMPTY and the SCRIPT subtitle is `0 entries` with no `●`.
  One test-side bug found on the way: the buffer lives in the JSON view
  (`display: none` until the tab chip), so a bare click missed it — the AT drives the
  shipped tab chip instead.
- **RED-first:** `red-fix2-paste-buffer.txt` — both sizes FAIL on the fix-pass-1 tree
  (`timed out waiting for the paste buffer cleared by the reset`). GREEN: the full
  module on the fix-2 tree — **17 passed in 108 s** (`green-fix2-session-reset.txt`).
- **R2-2 (MINOR):** the AT's ledger comment now states the check pins HLR-165's
  OBSERVABLE, not LLR-165.1's repaint clause, and the reviewer's R8b (the seam's
  `refresh_entries` call deleted) is recorded in packet §4 as an EQUIVALENT mutant:
  re-run by me on the fix-2 tree it SURVIVES **17/17** (`mut-fix2-r8b-no-repaint.txt`)
  — the install's deferred chain repaints the ledger anyway. The seam's repaint stays
  (the contract requires it).
- **Mutants (fix pass 2):** m7 (the buffer clear skipped) KILLED — **2 failed/15
  passed**, both AT sizes, `mut-fix2-m7-no-buffer-clear.txt`; R8b SURVIVED 17/17
  (equivalent, recorded); m1 (order) re-run on the fix-2 tree: KILLED **4
  failed/13 passed**, the same kill set as fix pass 1 (`mut-fix2-m1-order.txt`). m2/m3/
  m4/m6/R6/R10 touch code paths unchanged by this pass; their fix-pass-1 verdicts
  stand. Every mutant restored, SHA-256-verified (final app.py `ddc64e18…`, pure CRLF
  14511/14511); harness at `evidence/inc-3/mutation_harness_fix2.py`.
- **Re-ran:** the full module (17 passed), the panel-owning reverse-census files
  (`test_b97_patch_editor` + `test_tui_patch_editor_b94` + `test_tui_patch_variant`:
  **66 passed** — `green-fix2-reverse-census.txt`), the six guards (**75 passed, 29
  snapshots passed, NO snapshot cell changed** — `guards.txt`) and the census sweep
  (**87 passed** — `guards-census.txt`).
- **Packet:** §1/§2/§4/§6 updated (fix-pass-2 rows in the RED table, the mutation
  verdicts incl. the R8b equivalent-mutant record, the emitted-form paste-buffer row,
  the instrument RED-proof row, the node ledger); evidence re-derived with
  `devflow-evidence.py --write … --rederive` — **39 rows, `--check` reports 0 unbound**
  (exit 1 only on the not-staged index limb). §4b left `pending — orchestrator`.
  Nothing committed.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/app.py (1 SOURCE: the seam clears #patch_paste_text and defers mark_loaded via call_after_refresh — R2-1) + tests/test_b100_session_reset.py (AT types a paste-buffer draft pre-load, asserts buffer empty + no ● post-load; the ledger comment reworded — R2-2) + increment-003.md packet + 7 new evidence transcripts.
Tests: 17 nodes (unchanged count — the two AT arms extended, no new function); RED-first 2 failed (both sizes vs the fix-pass-1 tree); GREEN 17/17 in 108 s; reverse census 66 passed; guards 75 passed (29 snapshots, no cell changed); census sweep 87.
RED/GREEN: fix-2 RED 2/2 AT arms; GREEN 17/17 + every guard layer green on the fix-2 tree.
Mutations: 3 verdicts this pass — m7 buffer-clear KILLED (2 failed, both AT sizes), R8b EQUIVALENT (17/17 survived, recorded per R2-2), m1 order re-run KILLED (4 failed, same kill set); all restored, SHA-256-verified; evidence digests re-derived, 39 rows bind.
Open questions: §4b awaits the reviewer's round-2 re-read; orchestrator still owns the ARQ §2.2 inventory mirror (8 caches + 2 Inc-era names), HANDOFF.md placement at commit (kimi/inc-3-HANDOFF.md), and the 2 pre-existing base failures (at_b78_03, at_056e_a2b).

__KIMI_UNIT_DONE_ROUND1__
Files changed: s19_app/tui/app.py (1 SOURCE: reset seam, snapshot, unload A2L clear) + tests/test_b100_session_reset.py (16 nodes) + tests/test_id_registry.py (217 bump).
Tests added: TC-B100-08/09/10/11 (14 white-box nodes incl. LED .51 arms) + AT-B100-03 at 118x54 and 220x60 — all 16 pass (green-03); RED 14/16 at base.
RED/GREEN: RED 14 failed/2 passed at base (3 transcripts + executed p03 premise); GREEN 16/16, census batches 218+328+221+194 passed, guards 75 + census sweep 87, snapshot cells unchanged.
Mutations: 5/5 KILLED (order, reset-line, domain set, service rebind, unload clear), each restored with SHA-256 proof — no mutant left.
Open questions: empty exclusion-list compliance (orchestrator), 8-vs-7 mac-cache name count, 2 pre-existing base failures + 1 base-proven flake routed for an owner, interim notice N semantics until Inc 10.
