# Increment 003 — HLR-165 / LLR-165.1–165.4 · `A project load starts clean (PH-2)`

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `003` |
| Lane | `main` · `s19_app/tui/app.py` (1 SOURCE file) |
| Requirement(s) | `HLR-165 · LLR-165.1 · LLR-165.2 · LLR-165.3 · LLR-165.4` · LED-2026-10-26-batch-100.51 (interim notice, WORDING AMENDED by LED .55(a)) · LED .55(a)/(b) · consumes LED .50 (app paths stay unresolved; this increment adds no placement call) |
| Acceptance | `AT-B100-03` · white-box `TC-B100-08 · TC-B100-09 · TC-B100-10 · TC-B100-11` (the interim-notice arms live under TC-B100-10) |
| Agent | `software-dev` |
| Date | `2026-10-27` (fix pass 1 same day: code-review F1–F11 + LED .55; fix pass 2 same day: review round 2, R2-1/R2-2) |

---

## 1 · What changed

BLUF: a project load now starts from an empty session. `S19TuiApp._reset_project_session()`
(NEW, `app.py`) is the ONE reset seam: `_handle_load_project` calls it once per load,
after `validate_project_files` succeeds and before `build_variant_set` / the first
`load_selected_file` install — so the primary parse's MAC merge sees no existing file
and the A2L parse fallbacks see no outgoing path or payload (the six P-2 leaks:
`mac_path`, `mac_records`, `a2l_path`, `a2l_dir`, `a2l_tags`, `change_entries`). It
resets ARQ §2.2 rows S1–S13: the loaded image (`current_file`, S1), the A2L path and
parsed data (`current_a2l_path` / `current_a2l_data`, S2/S3), the variant ids
(`_variant_set`, `_pending_variant_id`, S5 — the caller adopts the manifest's set
afterwards), the declared regions (S6), the last CRC template (S7), the last
comparison/check spec (S8), the last flow run and execution (S9/S10), the report
filter (S11), the A2L derived views and find state (S12), and — through
`_invalidate_mac_view_cache()` plus four named assignments — S13 and the architect
probe A-07's names: all eight `_mac_view_cache_*` (the ARQ §2.2 inventory text still
says "seven" — it predates `_mac_view_cache_widths`; the seam clears all eight through
`_invalidate_mac_view_cache()`, finding F10), `_validation_report`,
`_validation_issues`, `_mac_row_key_to_address`, `_a2l_row_key_to_tag`. The monotonic
counters `_image_generation` / `_diff_compare_generation` (K1) and the view
preferences, the log deque, the active rail screen and the path-keyed A2L parse cache
(K2) are KEPT.

The change service (S4) is **rebound**, not reset: `self._change_service =
ChangeService()` and a re-push of `set_image_generation(self._image_generation)` —
nothing outside `app.py` holds the old object (P-26), so the new object is complete by
construction, and no `reset()` method is added to the service (the rejected
alternative would have added `change_service.py` to this increment). The seam repaints
the Patch panel through `refresh_entries` (the empty-session call shape
`_refresh_patch_history_view` uses), so a load-over can never leave the panel painting
the outgoing project's document; the repaint is followed by the LED .55(b) cleanup —
the paste buffer is cleared through its own `#patch_paste_text` widget and the panel's
public `mark_loaded()` is then deferred (`call_after_refresh`) until after the buffer's
`TextArea.Changed` message has been handled: that message's panel handler re-sets the
dirty flag (writer w2), so an immediate `mark_loaded()` would be undone and the panel
would paint `0 entries ●` over the empty ledger. `screens_directionb.py` is NOT edited
for either change (its dirty-flag reader remains Inc 10's). Fix pass 2 (review round 2,
finding R2-1): fix pass 1 called `mark_loaded()` alone, which cleared only the dirty
flag — P1's draft text survived in the paste buffer, now marked clean, so "Parse
pasted" could have applied P1's draft to P2 (the ARQ §2.2 U1 row). The seam now clears
the buffer itself; AT-B100-03 types a draft into the buffer before the load-over and
asserts it is empty after it, at both sizes. It returns the outgoing document's entry
count, and the handler paints the interim notice with it — as amended by
LED .55(a): `Closed the Patch Editor document (N entries); unsaved changes were not
kept`, painted when the outgoing document holds N > 0 entries. Inc 3 cannot read the
panel's dirty flag, so the line states only what is known (the document held N
entries; unsaved changes were not kept) and never calls them "unsaved" (review finding
F2: saved and loaded documents were reported as unsaved). The count is read from the
app-held `ChangeService.document.entries` before the rebind; no other file is touched
for it.

`_apply_unload("all" | "a2l")` gains the parsed A2L's clearing writer (LLR-165.4,
P-25): `current_a2l_data = None` beside `current_a2l_path`. Until now the payload had
two writers and no clearer, so after an unload the next bare-S19 reload re-attached the
old tags through the parse fallback (`else self.current_a2l_data`).

`S19TuiApp._session_snapshot()` (NEW, `app.py`; B100-I19 frozen here) returns the
normalised projection of every name the class's own source assigns — the
`_SESSION_SNAPSHOT_NAMES` domain (68 names at this commit), which the TEST re-derives
from the live source by an AST census and fails the classification arm on any drift
(C-31). The normaliser: paths → relative to `base_dir` (strings carrying the base
prefix included); `current_file` → `("LoadedFile", relative path, sha256 of
address:byte pairs)`; the change service → its public counts `(entries, undo back,
redo forward)`; plain dicts → `(len, sorted keys, sha256 of the normalised values in
key order)` — a content reduction, NOT keys alone (review finding F9: the A2L payloads
are dicts with fixed section keys, so a keys-only reduction compared two different
payloads EQUAL); other objects → element-wise normalisation, else a type name; and the
three keyed caches get named reductions per QA R2-07 — `_mac_view_cache_key`
(identity-keyed, drops the `id()` components, keeps
`len(records)/file_type/ranges/mem_map_len`), `_a2l_cache_key` (stat-keyed, drops the
mtime, keeps relative path + size), `_a2l_enriched_key` (identity-keyed, keeps the
memory-map size). The declared exclusion list (Textual internals) is EMPTY at this
commit — the census proves the source assigns none — and stays declared in the test so
a future one lands with its reason instead of breaking cold-vs-cold equality. Two
Inc-era names carry an explicit classification in the domain's comment because ARQ
§2.2 has no row for them (review finding F10): `_last_manifest_verify_result` is
INSTALL-OWNED (every manifest verify rewrites it before its only reader, so the seam
must not clear it) and `_variant_set_value` is the backing store of the `_variant_set`
property (row S5 covers it).

The user-visible outcome (AT-B100-03): load P1, add one Patch Editor entry, load P2,
save — P2's folder holds `prg.s19` + `project.json` only, the Loaded panel shows no
MAC and no A2L, and the status names the discarded entry.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | HLR-165 · LLR-165.1 · LLR-165.2 · LLR-165.3 · LLR-165.4 · B100-I4 (frozen) · B100-I19 (frozen) | `_reset_project_session()` (NEW): the one reset seam — S1–S13 + A-07's 11 names, `ChangeService` rebind + `set_image_generation` re-push, Patch panel `refresh_entries` repaint + the panel's public `mark_loaded()` (LED .55(b)), returns the outgoing entry count. `_session_snapshot()` (NEW): the normalised projection over `_SESSION_SNAPSHOT_NAMES` (68-name domain constant; the two Inc-era names classified in its comment) with the QA R2-07 keyed-cache reductions, the F9 dict content digest and the address:byte image digest. `_SESSION_SNAPSHOT_NAMES` (NEW module constant). `_handle_load_project`: one `self._reset_project_session()` call after validation, before the first install; the interim notice painted as the freshest status line in the LED .55(a) wording. `_apply_unload("all" \| "a2l")`: `current_a2l_data = None` beside the path (LLR-165.4). `import hashlib` |
| `tests/test_b100_session_reset.py` | test | HLR-165 · LLR-165.1–165.4 | TC-B100-08 (3 nodes), TC-B100-09 (4 — both load-over arms now seed non-default S5–S12 + A-07 state, finding F1), TC-B100-10 (5 — rebind, the worker boundary arm F6, the LED .55(a) notice arms re-pinned), TC-B100-11 (3), AT-B100-03 (2 parametrized sizes — notice re-pinned, plus the F8 ledger-empty and the LED .55(b) assertions: no-`●` subtitle AND the paste buffer empty after the load-over, both with pre-load vacuity guards; the ledger comment reworded in fix pass 2, finding R2-2) — 17 nodes; the live AST source census, the declared (empty) exclusion list and the K1/K2 allow-list live here |
| `tests/test_id_registry.py` | config | HLR-165 (registry hygiene for the new scanned file) | `EXPECTED_SCANNED_TEST_FILES` 216 → 217 (measured; one new scanned test module; `tests/support` stays excluded) |

| Count | Value |
|---|---|
| **SOURCE files** | **1 / 4** |
| Test files | 2 (1 new + 1 config bump) |
| Doc files | 0 (outside the count) |

---

## 3 · How to test

```bash
# interpreter: C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<this worktree>
unset NO_COLOR
python -m pytest -q -p no:cacheprovider tests/test_b100_session_reset.py
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | `TC-B100-08` (3: order-and-count arm, loose-file no-reset arm, AST call-site census) · `TC-B100-09` (4: derived-domain classification, cold-vs-cold equality — the stat-key normaliser proof, load-over vs cold within the K1/K2 allow-list with P1 seeded non-default over the whole S5–S12 + A-07 inventory, the direct P-2 leak-name arm over the same seeded inventory) · `TC-B100-10` (5: rebind + empty document/history + generation re-push, the worker boundary arm — a captured outgoing service finishes across the rebind with no exception and the rebound service untouched, interim notice N=1 in the LED .55(a) wording, no notice when nothing outgoing, exact count N=3) · `TC-B100-11` (3: unload `all`, unload `a2l` alone, bare-S19 reload shows 0 tags) | 15 passed |
| **B · black-box** `AT-NNN` ↔ story, through the shipped surface | `core` · `full` | `AT-B100-03` at (118×54) and (220×60), notifications on — Load project dialog (`p`), Patch Editor entry through the panel inputs, load-over, Save project dialog; asserts the painted closed-document notice, the empty ledger (0 rows + the empty-state line, F8), the SCRIPT window subtitle without the dirty `●` (LED .55(b), with a pre-load vacuity guard asserting the marker WAS painted), the Loaded panel slots, and P2's on-disk file set | 2 passed |

Round 1 closed at 16/16 in 121 s (`green-03-session-reset-final.txt`); fix pass 1
re-pins and extends the suite to 17 nodes — **all 17 pass in 94 s
(`green-fix1-session-reset.txt`)**, after a RED-first run of the re-pinned/new arms
against the round-1 tree (5 failed / 12 passed, `red-fix1-notice-and-marker.txt`: the
two notice arms + both AT sizes on the old LED .51 wording, and the direct arm's
unseeded-inventory gap found and corrected along the way). Fix pass 2 (review round 2,
R2-1/R2-2) extends the AT's arms again — a typed paste-buffer draft plus its
post-load empty assertion — and re-pins nothing else: **all 17 pass in 108 s on the
fix-pass-2 tree (`green-fix2-session-reset.txt`)**, after a RED-first run of the new
arms against the fix-pass-1 tree (2 failed, both sizes, `red-fix2-paste-buffer.txt`).

### RED counterfactual — executed, not predicted

| Kind | Transcript | Command (first line of the transcript names it) | Result |
|---|---|---|---|
| RED (full new module at base, first shaping) | `red-01-new-module.txt` | `pytest tests/test_b100_session_reset.py` before any app.py change | 14 failed / 2 passed — **11 behavioural failures** (the LEAK/unload/rebind/notice/AT assertions) + **3 missing-method failures, NOT a behavioural RED** (finding F7): `test_tc_b100_09_domain_matches_the_live_source_census`, `…_two_cold_loads_have_equal_snapshots` and `…_load_over_matches_cold_outside_the_allow_list` fail on `AttributeError: … no attribute '_session_snapshot'` — a missing symbol; their behavioural RED is carried by mutants m2/m3 and the R10 negative control below. The two passes are the guard arms that hold at base by design (loose-file no-reset; no-notice-when-nothing-unsaved) |
| RED (AT through the shipped surface at base) | `red-02-at-b100-03.txt` | the AT node, base tree | 2 failed — the Loaded panel paints P1's `firmware.mac` / `firmware.a2l` in P2's slots after the load-over (`PROJ P2 S19 prg.s19 … MAC firmware.mac 2 records A2L firmware.a2l 3 tags`) and the interim discard line never appears |
| RED (corrected test file vs base, the recorded counterfactual) | `red-03-corrected-tests-vs-base.txt` | full module, base `app.py` restored via `git show dad6423:…` | 14 failed / 2 passed — incl. the direct LEAK assertions (`LEAK mac_records`, `LEAK a2l_data`, `LEAK change_entries`), the unload arms (tags survive, P-25), the rebind arms, and the AT's painted-panel leak; the same 3 missing-method failures as `red-01` (F7 labeling above) |
| RED (fix pass 1: re-pinned + new arms vs the round-1 tree) | `red-fix1-notice-and-marker.txt` | full module on the round-1 tree (pre-fix-pass `app.py`, fix-pass test file) | 5 failed / 12 passed — the two re-pinned notice arms + both AT sizes fail on the old LED .51 wording (and the AT's LED .55(b) no-`●` assertion), the fix-pass RED-first for F2; plus `test_tc_b100_09_load_over_leaves_no_p1_state`, whose new direct inventory assertion caught a test-side bug (`_validation_report is None` — P2's own install writes a fresh report after the reset; corrected to "P1's seeded report is gone" before the GREEN run) |
| RED (fix pass 2: the new paste-buffer AT arms vs the fix-pass-1 tree, finding R2-1) | `red-fix2-paste-buffer.txt` | the AT node on the fix-pass-1 tree (pre-fix-pass-2 `app.py`, fix-pass-2 test file) | 2 failed — both sizes time out on `the paste buffer cleared by the reset`: `mark_loaded()` alone left P1's draft (`P1 DRAFT`, typed through the buffer's own widget) in the paste buffer, marked clean — the RED-first for R2-1 |
| RED (executed premise, cited) | `evidence/p0-premises/proj-p03_load_over_open_project.txt` | the orchestrator's p03 probe at `1d677ba` | `LEAK mac_path/mac_records/a2l_path/a2l_dir/a2l_tags/change_entries` + `P2 files after re-save: ['firmware.a2l', 'firmware.mac', 'prg.s19', 'project.json']` — the contract's declared negative control for AT-B100-03 |

| Field | Value |
|---|---|
| **Mutation applied** | Round 1: the 5 declared mutations from the proposal's §5.3 table (transcript `mutations-all.txt`). Fix pass 1 (findings F4/F7 + F1's discharge): the reviewer's R6 and R10 re-run on the F1-seeded suite, a NEW notice mutant m6 (the count read AFTER the rebind → N=0, no line), and full-module re-runs of m1/m4 so the "arms that stayed GREEN" claims are evidenced (round 1 ran selected nodes only). Fix pass 2 (review round 2): a NEW buffer mutant m7 (the seam's paste-buffer clear skipped, killing finding R2-1), the reviewer's R8b recorded as an EQUIVALENT mutant (finding R2-2), and an m1 re-run on the fix-pass-2 tree. All applied by the instrument (own hand via `evidence/inc-3/mutation_harness.py` / `mutation_harness_fix1.py` / `mutation_harness_fix2.py`, position + operation, never pasted requirement text); restore from a byte copy, verified by SHA-256 in every transcript |
| Instrument | `evidence/inc-3/mutation_harness.py` (round 1) · `evidence/inc-3/mutation_harness_fix1.py` (fix pass 1; re-used in fix pass 2 for the m1 re-run) · `evidence/inc-3/mutation_harness_fix2.py` (fix pass 2: m7 + R8b) |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b100-inc3`), implementer agent |
| Transcript | round 1: `evidence/inc-3/mutations-all.txt` (all five sections, each with pre/mutant/restored hashes) · fix pass 1: `evidence/inc-3/mut-fix1-r6-drop-s7-s11.txt`, `…-r10-no-key-normaliser.txt`, `…-m6-notice-after-rebind.txt`, `…-m4-service.txt`, `…-m1-order.txt` (each the FULL module, with pre/mutant/restored hashes) · fix pass 2: `evidence/inc-3/mut-fix2-m7-no-buffer-clear.txt`, `…-r8b-no-repaint.txt`, `…-m1-order.txt` (each the FULL module, with pre/mutant/restored hashes) |
| Restore proven by | `RESTORE OK` + the restored hash in every transcript — round 1 restores `ca8e539b…` (the round-1 implemented state), fix pass 1 restores `18ee4d45…` (the fix-pass-1 implemented state), fix pass 2 restores `ddc64e18…` (the fix-pass-2 implemented state); the final tree re-checked after the whole sequence |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` in every run (C-46) |
| Arms resolved at baseline | 17 nodes in `tests/test_b100_session_reset.py` (2 parametrized AT arms) — counts asserted per transcript; round-1 mutants ran selected nodes, every fix-pass mutant runs the FULL module (finding F11c) |
| Verdict granularity | per node id, per transcript |
| Arms that stayed GREEN | named per mutation verdict below |

| Field | Value |
|---|---|
| **Mutation verdicts** | `LLR-165.1` (order) — the reset moved after the first install → FULL-MODULE fix-pass re-run `mut-fix1-m1-order.txt`: 4 failed — `test_tc_b100_08_reset_runs_once_before_the_first_install` (`events[0]` is `install`), `test_tc_b100_09_load_over_leaves_no_p1_state` (the post-install reset wipes the freshly installed P2 primary), and **both AT sizes** (the painted P2 slots leak — the 2 kills the round-1 record omitted, finding F4). `LLR-165.2` (reset line) — `self.current_a2l_path = None` dropped → `test_tc_b100_09_load_over_matches_cold_outside_the_allow_list` AND `test_tc_b100_09_load_over_leaves_no_p1_state` KILLED (2 differing names outside the allow-list: the stale A2L re-attaches through the parse fallback) · `mutations-all.txt` §m2 · restore ✓. `LLR-165.2` (set mutation) — `"_last_template_path"` dropped from `_SESSION_SNAPSHOT_NAMES` without an exclusion → `test_tc_b100_09_domain_matches_the_live_source_census` KILLED (1 unclassified census name) · §m3 · restore ✓. `LLR-165.2` (**third negative control, finding F7**) — the reviewer's R10: the three keyed-cache reductions bypassed → `test_tc_b100_09_two_cold_loads_have_equal_snapshots` AND `test_tc_b100_09_load_over_matches_cold_outside_the_allow_list` KILLED (`mut-fix1-r10-no-key-normaliser.txt`, 2 failed/15 passed — the un-normalised stat/identity keys differ cold-vs-cold) · restore ✓. `LLR-165.3` (rebind) — the rebind dropped (old service kept) → FULL-MODULE fix-pass re-run `mut-fix1-m4-service.txt`: 6 failed — `test_tc_b100_10_change_service_is_rebound`, `test_tc_b100_09_load_over_matches_cold_outside_the_allow_list`, `test_tc_b100_09_load_over_leaves_no_p1_state`, **the new boundary arm `test_tc_b100_10_outgoing_service_finishes_after_rebind`** (the kept object IS the live one — the finishing worker's entry lands in it) and **both AT sizes**; the two notice arms stay GREEN under m4 — the count is read BEFORE the rebind, so no rebind mutation can affect it (finding F4's correction of the round-1 m4 row). `LLR-165.3` (**new notice mutant, finding F4**) — m6: the count read moved AFTER the rebind (new service holds 0 → no line) → 4 failed: `test_tc_b100_10_interim_discard_notice`, `test_tc_b100_10_notice_names_every_discarded_entry` and both AT sizes (`mut-fix1-m6-notice-after-rebind.txt`) — the notice arms now carry an executed killing mutant. **F1's discharge** — the reviewer's R6 (the 7 S7–S11 reset lines deleted) on the F1-seeded suite → `mut-fix1-r6-drop-s7-s11.txt`: **KILLED, 2 failed/15 passed** — `test_tc_b100_09_load_over_matches_cold_outside_the_allow_list` (`LEAK _last_template_path: cold=None warm='…/P1/templates/crc.tpl'` — the S7 name in the LEAK line, the reviewer's stated discharge condition, with S8–S11 alongside) and `test_tc_b100_09_load_over_leaves_no_p1_state` (the direct inventory). Round 1 it SURVIVED 16/16. `LLR-165.4` — the unload clear removed → all three `test_tc_b100_11_*` nodes KILLED · §m5 · restore ✓. **Fix pass 2 (review round 2).** `LED .55(b)` (**new buffer mutant, finding R2-1**) — m7: the seam's paste-buffer clear skipped (the deferred `mark_loaded` kept) → `mut-fix2-m7-no-buffer-clear.txt`: **KILLED, 2 failed/15 passed — both AT sizes** die on the buffer-empty wait (`timed out waiting for the paste buffer cleared by the reset`); the no-`●` assertion stays green under m7 (the deferred `mark_loaded` still clears the marker — m7 isolates the buffer clear) · restore ✓. `LLR-165.1` (**order, re-run on the fix-pass-2 tree**) — the reset moved after the first install → `mut-fix2-m1-order.txt`: **KILLED, 4 failed/13 passed** — `test_tc_b100_08_reset_runs_once_before_the_first_install` (`events[0]` is `install`), `test_tc_b100_09_load_over_leaves_no_p1_state` (the post-install reset wipes the freshly installed P2 primary) and both AT sizes (the painted P2 slots leak) — the same kill set as the fix-pass-1 re-run, as expected: this pass touched only the seam's panel block. **Equivalent mutant (finding R2-2)** — the reviewer's R8b: the seam's `refresh_entries` repaint deleted → `mut-fix2-r8b-no-repaint.txt`: **SURVIVED, 17 passed** — deleting the seam's repaint changes no assertion, because the install's deferred chain repaints the ledger anyway; the AT's ledger check therefore pins HLR-165's observable, not LLR-165.1's repaint clause (the AT comment now says exactly this). The seam's repaint stays: the contract requires it. · restore ✓. Fix pass 2 re-ran the full current mutant set whose code paths this pass's diff touches (m1, m7, R8b); m2/m3/m4/m6/R6/R10 operate on code paths unchanged by this pass (the snapshot domain, the rebind, the notice count, the S7–S11 lines) and their fix-pass-1 verdicts stand |
| Arms that stayed GREEN under each mutant | §m1 (full-module): 13 nodes — the notice arms, both unload arms, the census arms, the rebind arm and the boundary arm stay green (an order break does not touch them). §m2: 15 nodes. §m3: the deselected arms untouched. R10: 15 nodes — only the two snapshot-comparison arms die. m4 (full-module): 11 nodes — the notice arms and the no-notice arm stay green (recorded: the count is read before the rebind, so a rebind mutation cannot reach it — the reason F4 needed a dedicated notice mutant, m6). m6: 13 nodes — the discard only silences the notice. R6: 15 nodes — everything outside the two seeded load-over arms. §m5: the deselected arms untouched. **Fix pass 2:** m7: 15 nodes — only the two AT sizes die (the buffer-empty wait); R8b: all 17 — the equivalent mutant survives by definition (recorded, finding R2-2); m1 (fix2 re-run): 13 nodes — the notice arms, both unload arms, the census arms, the rebind arm and the boundary arm stay green, the same set as the fix-pass-1 full-module run |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest tests/test_b100_session_reset.py` at base | the unmodified tree (no seam, no snapshot, no clearing writer) | 14 failed / 2 passed, `red-03` — collection fine, the LEAK/unload/rebind/AT assertions fail |
| the AT's painted-panel oracle at base | P2 loaded over P1 with an unsaved entry | the Loaded panel's painted text contains `MAC firmware.mac 2 records A2L firmware.a2l 3 tags` — `red-02` |
| the order oracle of TC-B100-08 | mutant m1 (reset after the first install) | `events == ['install', 'reset', 'install', …]` — `mutations-all.txt` §m1 |
| the domain-classification oracle of TC-B100-09 | mutant m3 (one census name dropped) | `unclassified census names: ['_last_template_path']` — §m3 |
| the allow-list oracle of TC-B100-09 | mutant m2 (`current_a2l_path` reset line dropped) | `LEAK current_a2l_path: cold=None warm='…/P1/firmware.a2l'` — §m2 |
| the notice oracle of TC-B100-10 (fix pass 1, finding F4) | mutant m6 (the count read after the rebind → N=0, no line) | 4 failed — both notice arms + both AT sizes paint/wait on a line that never comes — `mut-fix1-m6-notice-after-rebind.txt` |
| the S7-S11 seeding oracle of TC-B100-09 (fix pass 1, finding F1) | the reviewer's mutant R6 on the seeded suite | 2 failed — `LEAK _last_template_path: cold=None warm='…/P1/templates/crc.tpl'` (with S8–S11 alongside) + the direct inventory arm — `mut-fix1-r6-drop-s7-s11.txt` (SURVIVED 16/16 at round 1) |

| the paste-buffer oracle of AT-B100-03 (fix pass 2, finding R2-1) | mutant m7 (the seam's buffer clear skipped) | 2 failed — both AT sizes time out on `the paste buffer cleared by the reset` — `mut-fix2-m7-no-buffer-clear.txt` (RED-first against the fix-pass-1 tree in `red-fix2-paste-buffer.txt` precedes it) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 8 instruments, each shown RED before its first PASS was believed (5 at round 1 + the fix-pass m6 and R6 rows + the fix-pass-2 m7 row) |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| P2's project folder on disk after Save project | `sorted(p.name for p in workarea/"P2").iterdir()) == ["prg.s19", "project.json"]` (filesystem listing, not the app's loader) | the equality held at both sizes — `green-03` |
| the Painted Loaded panel after the load-over | `"firmware.mac" not in loaded_text and "firmware.a2l" not in loaded_text` over `#loaded_slots Static` renders | absent at (118, 54) and (220, 60) — `green-03` |
| the painted status line | `"Closed the Patch Editor document (1 entries); unsaved changes were not kept" in #log_line_4` after the load-over, at both sizes (the LED .55(a) wording; round 1 asserted the LED .51 wording) | found — `green-fix1-session-reset.txt` |
| the painted SCRIPT window subtitle after the load-over | `"0 entries" in subtitle and "●" not in subtitle` over `#patch_win_script`'s border subtitle, at both sizes — with the pre-load vacuity guard `"●" in subtitle` right after the entry add (LED .55(b)) | marker painted before, absent after — `green-fix1-session-reset.txt` |
| the paste buffer after the load-over (fix pass 2, finding R2-1) | `#patch_paste_text` (a `TextArea`) `.text == ""` after the load-over, at both sizes — with the pre-load vacuity guard: a draft typed through the buffer's own widget (`"P1 DRAFT"` via the JSON tab chip → click → keys) IS in the buffer before the load | draft in before, empty after — `green-fix2-session-reset.txt` |
| the painted Patch Editor ledger after the load-over | `#patch_doc_entries_table` `row_count == 0` AND `#patch_doc_empty_state` without its `hidden` class carrying `PatchEditorPanel.EMPTY_STATE_TEXT`, at both sizes (finding F8 — HLR-165's "the Patch Editor ledger is empty") | 0 rows + the empty-state line — `green-fix1-session-reset.txt` |
| the snapshot the app emits | `app._session_snapshot()` diffed cold-vs-cold and load-over-vs-cold | 0 differing names / 0 outside the allow-list — `green-03` |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 7 artifacts, each asserted against the form its producer emitted (4 at round 1 + the painted subtitle and the painted ledger rows added in fix pass 1 + the paste buffer in fix pass 2) |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-3/` | SHA-256 |
|---|---|---|
| import-proof.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/import-proof.txt | 829f35c8d63fefad331297121a41961e3e9e733a7cbc6693d9a55f94c8b740fe |
| red-01-new-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/red-01-new-module.txt | ffb8df60d5671b218029a734557ba1ea8f826c07d3c2b8b1d9a653c086ad74c8 |
| red-02-at-b100-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/red-02-at-b100-03.txt | e82f21e1506d467f86c9327916845a8c877189501580eb2f24d0878f7d3f9397 |
| red-03-corrected-tests-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/red-03-corrected-tests-vs-base.txt | afe42c1b33aae8aba633b0937020176f7e5c406b74e3339c7373494819521fca |
| red-fix1-notice-and-marker.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/red-fix1-notice-and-marker.txt | e14b81c729e60a1fce75a8a74b8279f31239d0abbd49f8577b2f2056a5693a81 |
| green-01-session-reset.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-01-session-reset.txt | e58329c04d3449ac37a455699bedb8d1b7c6b987c41824d09985c7f3ce8de798 |
| green-02-session-reset.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-02-session-reset.txt | 510e8cfab557c9df9d2481951ede2683c8ea836c7b46b458825df972b7f35f53 |
| green-03-session-reset-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-03-session-reset-final.txt | 4c5d9b10ec1d22f60f35505045eeba9237116ab071b858bcae2468f21b620def |
| green-fix1-session-reset.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-fix1-session-reset.txt | b5c6becf3d0bcc25244153340a13942a8c94aa983bb234d22ccda60c89ab0828 |
| green-fix1-reverse-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-fix1-reverse-census.txt | b5b01f73881aba3ceedb221c4de76de6f26ccbabdccf0828589d90b47644beff |
| mutations-all.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mutations-all.txt | 4c404513496f4f9660118d224a654d1ae646b710354b35ee3a6424411af89a4c |
| mutation_harness.py | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mutation_harness.py | 9257896994a30494010526ea4664211ebd0c4930e933f03fafeefa521a9db6b4 |
| mutation_harness_fix1.py | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mutation_harness_fix1.py | 4a47ba935b07bd24983d8f8e9dc6cb48081ceb586824b1a6830ca7d9af5bf98f |
| mut-fix1-r6-drop-s7-s11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mut-fix1-r6-drop-s7-s11.txt | a90c222860c08857f86d558a3e63b9350d904554a7d669780d41326e48e9a7ad |
| mut-fix1-r10-no-key-normaliser.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mut-fix1-r10-no-key-normaliser.txt | 0075edc5b3078f91a02367adc54dc160b137fb189bbac564f47458ce18ed58a9 |
| mut-fix1-m6-notice-after-rebind.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mut-fix1-m6-notice-after-rebind.txt | c9aae3899f1d5db37cd9a44b64950aaead0fa301ae2bb36f57fb8f739a35ea5d |
| mut-fix1-m4-service.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mut-fix1-m4-service.txt | 12bdd06e895e15841028aa8eeb9f424256c216320de3a696c2b5da489b87dc49 |
| mut-fix1-m1-order.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mut-fix1-m1-order.txt | 9ee4ec516955de660ad06b9c7cb92cddd7defc986646b8a83282531499f198ef |
| reverse-census-grep.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/reverse-census-grep.txt | d160bee873aa6a24bf097725fb2270f6d656703a2c0a6119e98bcdfaa38bf3f2 |
| green-04-census-batch-a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-04-census-batch-a.txt | ce165783f3d5c97f1d8a51db49ae020de5a7502815d09811fc1b901d9a1a3405 |
| green-05-census-batch-b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-05-census-batch-b.txt | 162fb484e6b7218534479db69a381557973996c28c8f032d622199faf568dca5 |
| green-06-census-batch-c.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-06-census-batch-c.txt | 7a5228bc4a89863b7b74fd8daa12c946b0eef35c0ffa186b3b13c6a76a8d88b4 |
| green-06b-batch-c-flake-isolation.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-06b-batch-c-flake-isolation.txt | 736a0b4f0400e44e47132ec436fdb468cbcf215dcbc2269768dfbb861dea7b1f |
| green-06c-at078b-retry.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-06c-at078b-retry.txt | 709125fa6e99dc8b5d7c0487dbb69ea3e9c43c3fd2d98cac97359567213d55a8 |
| green-07-census-batch-d.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-07-census-batch-d.txt | 86fedb1a90fa9f8c15b10db7fe592821f00e0682aebcb07e12e58a4c6561165d |
| preexisting-at-b78-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/preexisting-at-b78-03.txt | efe2f0863653505d4881325dd7245787cb9e8bc42820fa02bfb62d692ed661dc |
| preexisting-batch-c.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/preexisting-batch-c.txt | f7cde1fe0cd29c65499a8c46ca1dca5f4c0dd1d1ce5fb94f2051cdecd6841186 |
| preexisting-at078b-flake.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/preexisting-at078b-flake.txt | 89cefa0d729953718ada3d2a590a798babec65b627b96e33f32d071a4dde48ed |
| preexist-base-3runs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/preexist-base-3runs.txt | 7d4e75877f64780f1d6aca4863ec8f233862216a0884d7280d29f67c70dcea02 |
| preexist-fixed-3runs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/preexist-fixed-3runs.txt | f7772a745043badef77aeb38c1b9752abed71b31b56b2168394c52513e1e6a36 |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/guards.txt | c99689c900b2e974e77fc69d74b1e93c80011200cbfe7d69f055159cb8f5ec3b |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/guards-census.txt | 7841c81497d4cf5f922aa99f346fa60c7587c95fea85c8bb33ead11143ce7342 |
| green-fix2-reverse-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-fix2-reverse-census.txt | c4d3f6ec80153b950e0c3c35ee86fdda10c4f9f05cc932d5be0b684cd5674690 |
| green-fix2-session-reset.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/green-fix2-session-reset.txt | 4e9075777a2a2e20e425fd3c5eb2571583244003fdd21512be34a2a68eaaedaf |
| mut-fix2-m1-order.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mut-fix2-m1-order.txt | 0900deacef499243dbed88c5cea312a05868b68bca986eaa774f5a8fa25c184b |
| mut-fix2-m7-no-buffer-clear.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mut-fix2-m7-no-buffer-clear.txt | a0d32e5ffef66feacece062eaa34d0e6217b2278d4eedddd75d680a4705b3787 |
| mut-fix2-r8b-no-repaint.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mut-fix2-r8b-no-repaint.txt | 15f335073a0e8fa44f21d1210b26ce46df2fd53f9142a3b20852c7dbc0585a03 |
| mutation_harness_fix2.py | .dev-flow/2026-10-26-batch-100/evidence/inc-3/mutation_harness_fix2.py | 24ca11af7e77eef0d78bbb274285fc94148aa4e3fbd98e09efa9c13f9f288ca4 |
| red-fix2-paste-buffer.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/red-fix2-paste-buffer.txt | 1692107ca1b789eadf7db35fbf25606f723f45a366441eab5a287721cb18fc66 |
| orchestrator-gate.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/orchestrator-gate.txt | 669ff381c15a05423d47135cff10ec1259e64c150590f01edff9d51d0ad38981 |
| at058b-isolation.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3/at058b-isolation.txt | 937a755dd50f5faea1f39d27a6cdbad0cd016a15cb53ab0b6bfe4e1de771899e |

| Field | Value |
|---|---|
| **Evidence files** | `41 artifact(s), each at the declared home, with the digest of its bytes on disk` |

Finding F11 (record hygiene), resolved in fix pass 1: the rows above were re-derived
mechanically — `python C:/Users/jjgh8/.claude/docs/tools/devflow-evidence.py --root .
.dev-flow/2026-10-26-batch-100/evidence/inc-3/* --write
.dev-flow/2026-10-26-batch-100/03-increments/increment-003.md --rederive` — so the path
column holds FULL repo paths (round 1 held bare names, so `--check` could not bind any
row). The verification run `devflow-evidence.py --root . --check
.dev-flow/2026-10-26-batch-100/evidence/inc-3/*` reports **0** "packet records no
digest" lines (every row binds disk ⇄ packet) and exits 1 only on the git-index-blob
limb — 32 × "not staged", the expected state for an uncommitted worktree the
orchestrator commits at the checkpoint (the check transcript itself is a meta-artifact
and is deliberately not a cited row: it cannot contain its own digest).

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | Yes — one: the declared exclusion list is EMPTY. TC-B100-09's classification arm rests on the source census holding no Textual-internal `self.<name> =` assignment. That is an ABSENCE claim. |
| If the result is an ABSENCE, what made the search wide enough | the test's `_source_census()` AST-parses the WHOLE live `app.py` and walks every node of the `S19TuiApp` class body — the over-broad property (any self-assignment, anywhere in the class, any syntax form `=` / annotated `=`) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | none — every arm is behavioural except `test_tc_b100_08_call_site_census`, which pins the ONE-caller conclusion (LLR-165.1: "No other caller shall call it"); its docstring says so |
| Conjunctive criteria: one mutation per conjunct | LLR-165.1's order conjunct (m1, re-run on the fix-pass-2 tree) and one-caller conjunct (census arm) each carry a verdict; LLR-165.2's reset-line conjunct (m2) and set/domain conjunct (m3) are two mutations, two verdicts; LLR-165.2's normaliser conjunct (R10, fix pass 1's third negative control); LLR-165.3's rebind conjunct (m4) and notice conjunct (m6, fix pass 1 — the count read after the rebind); the S7–S11 inventory conjunct (R6, killed only after F1's seeding); LLR-165.4's clearing-writer conjunct (m5); LED .55(b)'s buffer conjunct (m7, fix pass 2) with R8b recorded as the equivalent mutant for the repaint clause (fix pass 2, finding R2-2) |
| Synthetic instance of the absent case | mutant m3 IS the synthetic introduction of an unclassified census name — the classification arm goes RED on it (§m3); a future Textual-internal self-assignment would surface the same way |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by other tests | `grep -rln "_handle_load_project\|_apply_unload\|current_a2l_data\|_change_service" tests/ --include=*.py` (`reverse-census-grep.txt`) | 39 files (38 test modules + `tests/b97_fixtures.py`, whose own tests live in the `test_b97_*` modules) — every hit re-validated in `green-04`…`green-07` |
| B2 file moved on disk | n/a — no file moved | no readers |
| B3 byte-identical golden captures this source | `grep -rn "app.py" tests/goldens/ tests/__snapshots__/ 2>/dev/null` | no hits (snapshot SVGs are exercised by the guards below) |
| B4 artifact produced here is consumed elsewhere | `_session_snapshot` / `_reset_project_session` consumed by `tests/test_b100_session_reset.py` only; the LED .51 line observed through `#log_line_4` | re-validated in the module run |
| A3 interface consumed by another module changed | B100-I4 and B100-I19 FREEZE here (the reset seam's shape and the snapshot's contract); `ChangeService` untouched; no new import edge | the one-caller census pins the seam |
| §5.4 named population | `test_tui_patch_variant.py` calls `_handle_load_project` with a project already open (`:338`, `:343`, `:782`, `:788`) | re-validated in batch B — the load-over now resets first, which is the required behaviour for a load-over; its assertions hold |

| Field | Value |
|---|---|
| **Reverse census** | 6 probes run (B1, B2, B3, B4, A3, §5.4). The B1 grep found 39 files (38 test modules + `tests/b97_fixtures.py`, whose own tests live in the `test_b97_*` modules); every hit re-validated in four batches: **A** (b97/b99 + change-service, 10 files) 218 passed — `green-04` · **B** (tui core, 7 files) 328 passed + 1 xfailed, 1 failed — `green-05`; the failure `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` (the frozen batch-78 palette artifact holds 2 fewer actions than main paints) **fails identically at base** (`preexisting-at-b78-03.txt`) — pre-existing, not this increment's · **C** (tui rest, 13 files) 221 passed + 1 skipped, 4 failed — `green-06`; dispositions: `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection` **fails at base** (`preexisting-batch-c.txt`) — pre-existing; `test_tui_patch_checks_strip.py::test_at078b_zero_total` is the repo's documented single-fixed-pause race (batch-95 anti-pattern) — it **fails at base with the identical `strip == ''` shape** (`preexisting-at078b-flake.txt`, base run 1) and passes 3 consecutive solo runs on this tree (`green-06c`); `test_tui_patch_editor_v2.py::test_paste_parse_then_apply_matches_file_loaded` and `test_at030c_directly_dropped_file_is_listed_and_loadable` pass in isolation on this tree (`green-06b`) — the same order/timing flake family Inc 1 documented for that module · **D** (remaining 8 files) 194 passed — `green-07`. `test_tui_patch_variant.py`'s §5.4 direct `_handle_load_project` callers (`:338`, `:343`, `:782`, `:788`) re-validated in batch B — the load-over now resets first, which is the required behaviour; their assertions hold. **Whole-tree guards: 75 passed, 0 failed, snapshot cells unchanged — `guards.txt`; census sweep (PDR C-QA-3): 87 passed — `guards-census.txt`.** Fix pass 1 re-ran the guards and the census sweep on the fix-pass tree with the same result — **guards 75 passed, 0 failed, 29 snapshots passed, NO snapshot cell changed; census sweep 87 passed** (new `guards.txt` / `guards-census.txt`), and re-ran the reverse-census files that own the panel the seam now calls `mark_loaded()` on plus the §5.4 population (`tests/test_b97_patch_editor.py`, `tests/test_tui_patch_editor_b94.py`, `tests/test_tui_patch_variant.py`) — **66 passed — `green-fix1-reverse-census.txt`**. **Fix pass 2 re-ran the same three panel-owning files on the fix-pass-2 tree — 66 passed — `green-fix2-reverse-census.txt`** (the seam now writes the panel's paste buffer and defers `mark_loaded`), and re-ran the guards and census sweep with the same result — **guards 75 passed, 0 failed, 29 snapshots passed, NO snapshot cell changed (`guards.txt`); census sweep 87 passed (`guards-census.txt`)**. |

**Re-pins recorded:** round 1: none. Fix pass 1 (the requirement's wording changed — LED .55(a) amends LED .51, orchestrator ruling): `test_tc_b100_10_interim_discard_notice` — `Discarded 1 unsaved Patch Editor entries` → `Closed the Patch Editor document (1 entries); unsaved changes were not kept` — LED .55(a); `test_tc_b100_10_no_discard_notice_when_nothing_unsaved` — absence check re-pointed at the new wording — LED .55(a); `test_tc_b100_10_notice_names_every_discarded_entry` — `Discarded 3 …` → `(3 entries)` — LED .55(a); `test_at_b100_03_project_load_over_unsaved_work_saves_only_p2[both sizes]` — the painted-line wait and the log assertion re-pointed at the new wording — LED .55(a). No product behaviour other than the notice wording and the panel marker (LED .55(b)) changed, so no other existing assertion moved.

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the reset must clear every session-state row, not only the leaked six | the self-assigned attribute census | `grep -oE "self\.(_?[a-z][a-z_0-9]*)(: [^=]+)? = " s19_app/tui/app.py` (ARQ §2.1's derivation, re-run) | 68 names (67 at ARQ time + `_variant_set_value`) | 1 (`app.py`) | 0 — every name is either reset by the seam, kept by K1/K2 by design, or app infrastructure the caller owns (`current_project`, `current_project_dir`, set after the reset) |
| the parsed A2L must be cleared wherever the path is | every clearing writer of `current_a2l_path` | `grep -n "current_a2l_path = None" s19_app/tui/app.py` | 2 sites (the seam, `_apply_unload`) | 2 | 0 — `current_a2l_data = None` now sits beside each |
| no second caller of the seam | every `_reset_project_session` call | the TC-B100-08 AST census over `s19_app/**/*.py` | 1 | 1 | 0 |

| Field | Value |
|---|---|
| **Correction population** | 3 corrections, each enumerated with its command before the first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| the six-leak partial cleanup (a hand-rolled reset of only the P-2 names) | 0 hits — no such code ever landed; the seam resets the full inventory from the first pass | yes | `app.py` `_reset_project_session` |
| the silent discard | the interim notice `Discarded N unsaved Patch Editor entries` is the only discard surface until Inc 10 | yes | `app.py` `_handle_load_project`; `test_tc_b100_10_interim_discard_notice` |

### Signed-balance test ledger

Scanned-file ledger (what `EXPECTED_SCANNED_TEST_FILES` pins):
`post = base − deleted + added` → `217 = 216 − 0 + 1` ✓ reconciles
(`tests/test_b100_session_reset.py` is the one added scanned file;
`tests/test_id_registry.py` bumps the bound by the measured count; nothing deleted.)

Node ledger (test functions collected in the new module): **17 nodes** (16 at round 1 + 1 added in fix pass 1) —
`test_tc_b100_08_reset_runs_once_before_the_first_install`,
`test_tc_b100_08_loose_file_load_performs_no_reset`,
`test_tc_b100_08_call_site_census`,
`test_tc_b100_09_domain_matches_the_live_source_census`,
`test_tc_b100_09_two_cold_loads_have_equal_snapshots`,
`test_tc_b100_09_load_over_matches_cold_outside_the_allow_list` (F1: P1 seeded non-default over S5–S12 + A-07),
`test_tc_b100_09_load_over_leaves_no_p1_state` (F1: same seeding + the full direct inventory),
`test_tc_b100_10_change_service_is_rebound`,
`test_tc_b100_10_outgoing_service_finishes_after_rebind` (F6: LLR-165.3's boundary arm, added in fix pass 1),
`test_tc_b100_10_interim_discard_notice` (re-pinned to the LED .55(a) wording in fix pass 1, finding F2),
`test_tc_b100_10_no_discard_notice_when_nothing_unsaved` (same re-pin),
`test_tc_b100_10_notice_names_every_discarded_entry` (same re-pin),
`test_tc_b100_11_unload_all_clears_the_parsed_a2l`,
`test_tc_b100_11_unload_a2l_alone_clears_the_parsed_a2l`,
`test_tc_b100_11_bare_s19_reload_after_unload_shows_no_a2l_tags`,
`test_at_b100_03_project_load_over_unsaved_work_saves_only_p2[size0]` (F8 + LED .55(b) assertions added; fix pass 2: paste-buffer draft typed pre-load + buffer-empty assertion post-load, R2-1),
`test_at_b100_03_project_load_over_unsaved_work_saves_only_p2[size1]` (same).
Deleted: none. Windows-only arms: none (all arms run on every platform).
Node count unchanged in fix pass 2 (17) — the pass extends the two existing AT arms'
assertions; it adds no new test function.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · PASS after 3 rounds (r1 BLOCK-UNTIL F1 HIGH: the snapshot scenario never set S7–S11; r2 PASS-WITH-NOTES, R2-1 MAJOR paste buffer kept; r3 PASS, 0 HIGH / 0 MAJOR) — `review-increment-003.md`. Orchestrator re-run on the final tree: 109 passed (Inc 1–3 files + patch-variant), guards 75 passed + 29 snapshots, census sweep 86 passed + 1 failed (`test_at058b`) — the failure is the known `test_tui_patch_editor_v2.py` timing family: 5/5 alone on this tree and on main, and a census re-run 87/87 — `evidence/inc-3/orchestrator-gate.txt`, `evidence/inc-3/at058b-isolation.txt`. Rulings LED .55. |

---

## 5 · Risks

- The snapshot's `_SESSION_SNAPSHOT_NAMES` is a hand-maintained list — the C-31 tripwire: the test's live source census fails the classification arm the moment a new `self.<name> =` appears in the source without landing in the domain or the exclusion list (mutant m3 demonstrates the arm kills exactly that drift).
- The load-over comparison arm is RELATIVE: it compares two sessions that both ran the same code, so a mutation that breaks both equally (m1's order break) escapes it — the direct-state arm (`load_over_leaves_no_p1_state`) and the order arm carry that kill, and the packet names the green arm per verdict. This is deliberate: the relative arm answers "does a load-over equal a cold load", which only relative comparison can.
- The interim notice is fresh painted surface pinned by TC-B100-10 and AT-B100-03 (re-pinned to the LED .55(a) wording in fix pass 1); Inc 10 replaces the line with the load question and re-pins both (declared in the contract's §5.3 and LED .51 as amended by LED .55(a)).
- `Closed the Patch Editor document (N entries); unsaved changes were not kept` (LED .55(a) wording) counts the outgoing DOCUMENT's entries (the app-side record readable before the rebind). Code-review F2 proved the round-1 wording false: `save_doc` writes the document and `mark_loaded` marks loaded documents, so saved/loaded entries were reported as "unsaved". LED .55(a) rules the interim line states only what Inc 3 can know — it never claims the N entries were unsaved; a saved-state record (`differs_from_last_saved`) arrives at Inc 5, and Inc 10's question (keyed on the panel's dirty flag, its public reader) replaces the line.
- The snapshot digest (`sha256` over the image's `address:byte` pairs) is an app-side projection for leak comparison, not a byte oracle: the AT's file-set assertion uses the filesystem listing, and byte oracles elsewhere stay on `tests/support/independent_reader.py`.

## 6 · Pending items / spec deviations

- **R2-1 (paste buffer, review round 2) — FIXED in fix pass 2**: the seam now clears `#patch_paste_text` through its own widget and defers the panel's public `mark_loaded()` via `call_after_refresh`, so the buffer's `TextArea.Changed` message (whose panel handler re-sets the dirty flag, writer w2) is handled before the marker is cleared. `screens_directionb.py` is NOT edited. AT-B100-03 types a draft into the buffer pre-load and asserts it empty post-load, both sizes (RED-first `red-fix2-paste-buffer.txt`; killing mutant m7).
- **R2-2 (AT comment, review round 2) — FIXED in fix pass 2**: the ledger comment now states the check pins HLR-165's observable, not LLR-165.1's repaint clause, and the reviewer's R8b (the seam's `refresh_entries` deleted) is recorded in §4 as an EQUIVALENT mutant — it survives 17/17 (`mut-fix2-r8b-no-repaint.txt`) because the install's deferred chain repaints the ledger anyway. The seam's repaint stays (the contract requires it).
- **Declared exclusion list is empty** (LLR-165.2 asks for a list of Textual internals "each with its reason"): at this commit the AST census finds no Textual-internal `self.<name> =` in `S19TuiApp`'s source, so the list is declared empty with the mechanism and the reason-slot intact. For the orchestrator to confirm as compliant (the classification arm still enforces 0-unclassified, and m3 proves a silent drop is RED).
- **S13's `_mac_view_cache_*` count**: FIXED in fix pass 1 (finding F10) — the seam comment now says "all eight" (matching the invalidator's census: `key`, `rows`, `meta`, `summary`, `coverage_line`, `widths`, `cell_rows`, `cell_styles`; the ARQ §2.2 inventory text predates `widths`). The two Inc-era names (`_last_manifest_verify_result`, `_variant_set_value`) are classified in the domain constant's comment: install-owned and the `_variant_set` backing store respectively — so the inventory now matches the census. For the orchestrator: record the 8 and the two classifications in the ARQ §2.2 inventory text itself (a design doc, outside this increment's 1-file source scope).
- **AT-B100-03's `p` route**: the project pick goes through the app-level `p` binding (the Workspace button `#ws_load_project_button` is hidden in the empty state before any file loads — the dialog-by-`p` drive matches the §5.3 note "Its project loads go through `p`"; the Inc 9b re-pin to the highlighted row + `enter` is already the drive used here). From Inc 10 on, this AT answers the load question with `y` (contract §5.3).
- Windows-only arms: none — no junction/link arms in this increment (PDR C-QA-6 count: 0).
- Snapshot cells: none regenerated — no SVG cell changed (the guard run proves it: `guards.txt`).
- **Reverse-census dispositions (finding F5 — rewritten to match the transcripts; all 8 batch-B/C nodes cited against the reviewer's 3-runs-per-tree probe `preexist-base-3runs.txt` / `preexist-fixed-3runs.txt`, copied verbatim from the reviewer's scratchpad with provenance headers):**
  - `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` — **pre-existing at base**: fails identically at base and on the round-1 tree, 3/3 runs each (`preexist-base-3runs.txt`, `preexist-fixed-3runs.txt`; round-1 `preexisting-at-b78-03.txt`). Routed to the orchestrator — either the golden needs regenerating under its own increment's authority or a later batch owns the palette census.
  - `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection` — **pre-existing at base**: fails identically at base and on the round-1 tree, 3/3 runs each (same two transcripts; round-1 `preexisting-batch-c.txt`).
  - `test_tui_patch_checks_strip.py::test_at078b_zero_total` — **flake shown at base**: fails at base with the identical empty-strip shape (`preexisting-at078b-flake.txt`); passes 3 consecutive isolation runs on this tree (`green-06c`).
  - `test_tui_patch_editor_v2.py::test_paste_parse_then_apply_matches_file_loaded` — **flake**: passes 3/3 on both trees in the reviewer's probe; round-1 `green-06b` first run FAILED it (order/timing flake under batch order — the round-1 packet's "passes in isolation (`green-06b`)" line was wrong about the transcript, corrected here).
  - `test_tui_patch_editor_v2.py::test_at030c_directly_dropped_file_is_listed_and_loadable` — **flake**: the round-1 packet claimed it "passes in isolation (`green-06b`)" — `green-06b` actually shows it FAILED (`3 failed, 1 passed`; the orchestrator's transcript, finding F5(a)). The reviewer's probe passes it 3/3 on both trees, so it is the same order/timing flake family, not a regression.
  - `green-06` first run named three first-run failures with no disposition (finding F5): `test_tui_patch_checks_strip.py::test_at078a_counts`, `test_tui_patch_editor_v2.py::test_save_back_prompt`, `test_tui_patch_editor_v2.py::test_saveback_width_16_caps_records_and_empties_s0` — all three **pass 3/3 on both trees** in the reviewer's probe (flakes of the same family; no base transcript needed beyond the probe's base runs, which show them green).
  - `test_tui_patch_variant.py`'s §5.4 direct `_handle_load_project` callers re-validated in batch B at round 1; **fix pass 1 re-ran the file** (`green-fix1-reverse-census.txt`) because the seam now calls `mark_loaded()` on the panel.

## 7 · Suggested next task

Increment 4 (LLR-166.x — focus after a load), per the proposal's hard order; it consumes the load tails this increment's seam sits between.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 1 source file (`app.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b100_session_reset.py` (17 nodes — 16 at round 1 + the fix-pass boundary arm) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the AST censuses (call-site census; the derived-domain classification) and the behavioural arms — `green-03` |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 RED table (3 transcripts + the executed p03 premise) + 5 mutation sections |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 reverse census, 6 probes, re-validated in `green-04`…`green-07` |
| 6 | `code-reviewer` passed | `core` · `full` | pending | §4b |
| 7 | No file from another lane touched | all | ✓ | only `app.py` + the 2 test/config files |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | B100-I4 and B100-I19 are FROZEN here, not changed; `ChangeService` untouched; no placement call added (LED .50's `workarea_root` rule unaffected) |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | every `N passed` appears in a cited transcript |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 load-bearing emptiness (empty exclusion list; m3 is the synthetic instance) |
| 11 | **Mutation verdicts** declared — **per arm** | all | ✓ | §4 mutation verdicts (5 mutants, per-node kills, green arms named) |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 instrument table (5 instruments) |
| 13 | **Correction population** declared | all | ✓ | §4 correction population (3 corrections) |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 emitted-form table (4 artifacts) |
| 15 | **Independent review** names somebody | all | ✓ | §4b: code-reviewer |
| 16 | **Evidence files** declared | all | ✓ | §4 evidence table (paths + SHA-256, filled at close) |
