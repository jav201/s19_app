# Inc 5 — E5 code review

Batch 2026-11-01-batch-101, increment 5. Reviewer: code-reviewer (independent of the implementers, the testers and the integrator). Scope: `git diff c2cba35 8fc3cd3 -- s19_app tests docs` (3 source files, 2 new test files, 2 edited test files, 1 guide chapter), read in full against `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `E3-rulings.md` (both rounds), `codewire/graph-inc5.md` and the E4 notes, including `E4-integration-notes.md`. I ran nothing that imports `s19_app` (operator rule). Every run-based statement below comes from the integrator's transcripts `evidence/inc-5/int-01` … `int-09` and the testers' base runs `red-01-tester1-base.txt` and `red-01-tester2-base.txt`.

## Verdict

**PASS-WITH-NOTES.** No BLOCKER or HIGH findings. The product code is correct against every row I traced, and it matches the graph node for node. One MAJOR finding (F1, a design gap in the tests) leaves the "expected bytes" clause of R-CHKED-056 with no discriminating case. The code meets that clause today, but no test would catch a regression. I recommend folding F1 before merge: it needs one precondition in the case, one call in a test helper, and one mutant row. The other findings are MINOR or NIT. Every finding is a recommendation.

## Checks

| # | Check | Result | Evidence state |
|---|---|---|---|
| 1 | Code = graph | All 17 slice nodes match their `func:` "now" text in `codewire/graph-inc5.md`. The hook helper's `try` wraps only the query, and the call sits outside it (`app.py:17935-17939`). The designer delegate is one statement (`crc_designer_view.py:704-724`). `kept` is captured before the no-op check (`screens_directionb.py:7294`). Demotion happens at the spec entry's own address, size and bytes, in `kept` order (`:7408-7437`). The prune reads the current picks, not `event.names` (`:7439-7448`, `:7871`). `_named_parameter` has no address fallback after a listed symbol at another range (`:7371-7405`). `_collected_items` has the range test (`:7492-7497`). `_check_items_to_document` has the exact-length branch (`app.py:7324-7332`). | executed (read) |
| 2 | Census of in-place writes still complete | I re-grepped `mem_map[...] =`, `.update/.clear/.pop/del` on image maps and the callers of `apply_change_document`, `_restore_journal`, `adopt_rederived` and `save_patched` over `s19_app`. Three code paths write the session map: `ChangeService.apply` (`change_service.py:1984` restore, then the engine), `save_patched` → `adopt_rederived` (`:2583`), and `_on_project_saved` → `adopt_rederived` (`app.py:12630`). `rederive_for_save` writes a copy (`:2244-2246`). Flow and variant runs build their own maps (`flow_execution_service.py:526`, `variant_execution_service.py:2573`). The loaders (`core.py:619`, `render/hexview.py:67`) are covered by the `current_file` watcher. No site was missed. | executed (read) |
| 3 | No hook is gated on `ok` or `applied > 0` | Apply: `app.py:4913-4914`, after the `try`/`except`, keyed only on `event.action == "apply_doc"`. It is outside the arm's `if counts["applied"] > 0`, so /6 (raise after the write) and /8 (0 applied after a journal restore) both reach it. Save-back: `app.py:5046`, unconditional right after `save_patched` returns and before `_report_change_result`, whatever `result.ok`. Project save: `app.py:12636`, inside `if request.image is not None:` after `adopt_rederived`. That condition is "the commit wrote the image" (slice #4), not a result gate. The declined and no-image save-back paths return before any write and send no notice, which is correct. | executed (read) |
| 3a | A raise inside `save_patched` after the adopt (the integrator's open observation) | `emit_and_verify` → `save_patched_image` catches `WorkareaContainmentError` and `OSError` (`changes/apply.py:829`, `:862`) and returns `ok=False`, so the hook runs. Any other exception is uncaught by the app handler and ends the run loudly, so a missed notice cannot go unseen. No finding. | executed (read) |
| 4 | No focus or visibility side effect, no `refresh_window` | The helper → `note_image_bytes_written` → Inc 13 `_on_image_changed`, which either schedules a recompute while on screen or sets `_coverage_dirty`. Grep of `crc_designer_view.py` for `focus(` and `refresh_window`: 0 hits. The helper does not use `mutate_reactive` (E1-D2 (a) rejected it). | executed (read) |
| 5 | Reuse | Inc 13's watcher logic is reused through a one-line public delegate (I-1). Inc 4's resolver is reused through its output, `entry.symbol` (I-3). The picker API (`set_parameters`, `clear_picks`, `include_names`, `picked_params`, `param_rows`) is used as it is; `a2l_parameter_picker.py` is not in the diff. `include_names` ignores unknown names and dedups (`a2l_parameter_picker.py:920-1000`), which is what R-CHKED-055 relies on. | executed (read) |
| 6 | `app.py` edits are local | +64 lines: one helper, three one-line hook calls with comments, two item keys and one `expected` branch. No other function body changed. | executed (read) |
| 7 | Named-parameter rule = the Definition | Symbol listed: named only at the entry's `(address, size)` and only if not taken; otherwise `None`, with no address fallback (A-6). Symbol absent or unlisted: exactly one ledger name at `(address, size)` and not taken. Ambiguous → `None` (E1-D4). Duplicate → `None`, so the field count stays the entry count (R-CHKED-043). | executed (read) |
| 8 | Consumers of the 4-tuple memory row | Grep for `_memory_rows`: two unpacking loops (`:7466`, `:7507`), `pop(cursor)` (`:7928`) and three appends. All handle the fourth element. No test or other module reads it. | executed (read) |
| 9 | Tests assert the case's expected result from product output, can fail, and do not end on a bare pause | Oracles are the status log, painted Fields lines, memory-table cells, ledger `✓` cells, Validate rows, the written `.chk.json` read back, and `zlib.crc32` of `app.current_file.mem_map` against the painted preview and window line 2. Waits use `wait_until` / `wait_designer_recompute` (count advanced and none pending). A count that must not move is read after 3–6 short pauses, never after one. Base runs: 8/10 designer nodes and 21/27 Check Editor nodes RED for behavioural reasons; the rest are declared standing guards or integrity nodes. The positive controls in 041.3/3, /4, /6 keep those cases from passing vacuously. Gaps: F1, F4. | executed (read); verified (linux, int-01: 58 passed) |
| 10 | Guide text (`ch10` §10.6–§10.8) | States `E1-rulings.md` §1 (5)–(7). One sentence that contradicts the new text is left in place: F3. | executed (read) |

## Findings

### F1 — the "expected bytes" clause of R-CHKED-056 has no discriminating case  [MAJOR · design-gap]
- **What:** R-CHKED-056 says the demoted memory row has "the address, byte count **and expected bytes** of its spec entry". The cases R-CHKED-056/1–/3, and the `0x0 6C` entry of R-CHKED-025/3, run on an unpatched case-08 image, where the spec's byte at `0x0` equals the image byte (`6C`). The requirement's own Base column already notes this: "its written entries match only because the image still holds the spec's bytes".
- **Where:** `tests/test_b101_check_spec_keep.py:1196` (`relayout_and_write`, shared by 056/1–/3) and the 025/3 scenario; product `screens_directionb.py:7433-7435`; `02-test-cases.md` rows R-CHKED-056/1–/3; `E4-integration-notes.md` mutant table (M22–M24 do not cover this).
- **Why it matters:** mutant M25 = `_demote_moved_spec_params` appends `(spec[0], label, spec[1], None)`. The demoted row then has `expected=None`, so `_check_items_to_document` reads the image at `0x0`. That gives `6C` on the unpatched image, and every 056 node and 025/3 stays GREEN. Yet that mutant is the D9-11 defect again for demoted fields: Write silently re-baselines from the image, and Validate compares the image with itself, which always passes. This is the integrity class SEC5-1 was ruled on ("dropping the bytes would lose the operator's declaration"). The code today carries `spec[2]` correctly; the gap is in the regression protection only.
- **Suggested fix (requirement and test change):** amend R-CHKED-056's Threshold precondition to "case 08 and its A2L loaded; a Patch Editor apply set the image byte at `0x0` to `93`; the pilot spec picked; …". Expected results stay unchanged: the entry at `0x0` is still `6C`. This mirrors R-CHKED-026/4. Update the three cases in `02-test-cases.md` and add M25 to `E5-mutants.md` (expected RED: C 056_1, 056_2, 056_3). In the test, one line in `relayout_and_write` between `open_session` and `pick_spec`:
  ```python
  await apply_bytes(pilot, app, log, tmp_path, f.v1.address, bytes([PATCH_BYTE]))
  ```
  `assert_declared_entry_kept` already pins `(f.v1.address, image_bytes(...))` = `6C`, so it then discriminates. For 056/3, keep the "no 2-byte entry at `0x0`" assertion.

### F2 — two `app.py` docstrings now contradict the code  [MINOR · impl]
- **What:** `_check_items_to_document`'s Summary still says every field's expected bytes are read from the image and "with no image loaded every field is skipped and the EMPTY spec still writes". `on_check_editor_panel_action_requested` still says "(expected bytes from the loaded image)". Both are false for a field loaded from a spec (R-CHKED-026, R-CHKED-027/2).
- **Where:** `app.py:7300-7310`, `app.py:7366-7368`.
- **Why it matters:** PROJECT_RULES' docstring contract (I/O meaning). This function's next editor would read it as the rule and could "fix" the new branch away.
- **Suggested fix:** add to the Summary: "A field loaded from a spec carries its spec entry's bytes in ``expected`` (a tuple of exactly ``size`` ints); they are declared as they are and the image is not read, so such a field is never skipped for lack of an image (amended *declared field*, R-CHKED-026/027)." In the handler, change it to "(expected bytes from the spec for a field loaded from one, else from the loaded image)".

### F3 — guide §10.8 contradicts itself within the edited paragraph  [MINOR · impl (doc)]
- **What:** the rewritten paragraph says each entry comes back as a `✓` parameter. Its last sentence still says "A spec with `symbol` entries (`demo_check.chk.json`) is refused the same way as in the Patch Editor (F-01)". R-CHKED-041.2/2 (the re-pinned `test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols`) loads `demo_check` and includes its symbol tag. Separately, "Each entry whose parameter the loaded A2L lists" is looser than the rule: the entry's address and byte count must name exactly one parameter, or its symbol must name one at that range.
- **Where:** `docs/user-guide/ch10-check-editor.md:84-88`.
- **Why it matters:** an operator who reads the guide gets two opposite statements in one paragraph. The integration notes route the F-01 sentence to the batch-end doc pass (Inc 14 ruling D-8). That is an accepted routing, but this increment rewrote the sentences around it.
- **Suggested fix:** either delete the F-01 sentence here and tell the batch-end doc list it is done, or leave it and make sure the D-8 list names `ch10:88` explicitly. Optionally reword the first sentence to "Each entry whose address and byte count name one parameter of the loaded A2L (or whose symbol names it there) comes back as a `✓` parameter with its name".

### F4 — the designer nodes snapshot the recompute count after the write, not before it  [NIT · impl (test)]
- **What:** in 002.5/3, /4, /6, /7 and /8, `before = designer_recomputes()` is taken after the write's status line and its settle pauses (e.g. `test_b101_designer_writes.py:432`). So "0 recomputes before key `0`" does not cover the instant of the write. Under mutant M4 (the hook schedules while hidden, Q = 0.05 s), the hidden recompute can land before the snapshot. The node still turns RED, but only through the post-key-`0` timeout ("never recomputed"), not through the requirement's own negative control ("1 recompute before key `0`").
- **Where:** `tests/test_b101_designer_writes.py` lines 432, 472, 555, 606, 651. 002.5/5 (`:510`) and 002.1/6 (`:676`) already snapshot before the write.
- **Suggested fix:** take `before` before the Apply click / save-back confirm (pass it into `_apply` / `_save_back`, or snapshot just before calling them), and keep the existing assertions. The RED message then names the right defect.

### F5 — four checks guard one invariant; three are unreachable after the demotion  [NIT · design-gap]
- **What:** "spec bytes are used only at their entry's range" is enforced by `_demote_moved_spec_params` (`:7430`), by the range clause of `_prune_spec_bytes` (`:7447`), by `_collected_items` (`:7494`) and by the length check in `_check_items_to_document` (`app.py:7325`). After the demotion, the second and third cannot see a moved name. The graph and E1-D6 pin them as backstops, so this is ruled design, not drift.
- **Why it matters:** no behaviour impact. For E5's mutant runner, a mutant that removes only one backstop clause is **equivalent** and is expected to survive. It is not a test gap.
- **Suggested fix:** none in this increment. If the canon fold wants fewer moving parts, the graph change is to drop the `_prune_spec_bytes` range clause and the `_collected_items` range test and keep the demotion and the length backstop.

### F6 — conventions on the new public method and the new attribute  [NIT · impl]
- **What:** `CrcDesignerPanel.note_image_bytes_written` is a new public method with no `Data Flow` section, which `CLAUDE.md:80` says is not optional on new public functions. `self._spec_bytes: dict = {}` drops the element type pinned in the graph's `__init__` node (`dict[str, tuple[int, int, tuple[int, ...]]]`), although its comment states the schema in words.
- **Where:** `crc_designer_view.py:704-724`; `screens_directionb.py:7231-7233`.
- **Suggested fix:** add `Data Flow: - delegates to _on_image_changed (schedule while displayed, else mark stale); no compute here.` and annotate `self._spec_bytes: dict[str, tuple[int, int, Optional[tuple[int, ...]]]] = {}` (`Optional`, because a seam caller may pass no `expected`).

## What I looked for and did not find

- The apply hook fires on any `apply_doc`, even one that wrote nothing (no image, or a refused document). The cost is at most one extra recompute on the next display. No row forbids it, and `test_control_other_patch_actions_do_not_mark_the_coverage_stale` pins that non-apply actions send no notice.
- A stale queued `SelectionChanged` cannot remove a fresh spec entry, because the prune reads the current picks. The fast exclude-then-include race is the recorded limitation SEC5-4, and no wrong value reaches a file.
- `set_a2l_parameters` runs before mount with an empty `_spec_bytes`, so no demotion and no `query_one` on an unmounted table.
- Unloading the A2L demotes spec-loaded picks into memory rows at their own addresses and drops session picks. That is consistent with *still lists*.
- In the re-pinned symbol-reads node, the test computes the named-parameter count from the product's ledger with the Definition. That mirrors the rule. The node's independent oracle is `check_entry["symbol"] in picked`, which was RED on base (`VALUE_0185` not included).

## Review report (packet §4b `Independent review` cell)

`code-reviewer · PASS-WITH-NOTES · no HIGH; F1 MAJOR design-gap (R-CHKED-056 bytes clause undiscriminated: patched-image precondition + M25 recommended before merge); F2–F3 MINOR, F4–F6 NIT; no fix applied by the reviewer`

## Evidence checklist

- [x] Diff read in full: `app.py` 4906-4915, 5039-5046, 7321-7332, 7511-7515, 12630-12636, 17901-17939; `crc_designer_view.py` 701-724; `screens_directionb.py` 7226-7233, 7285-7346, 7368-7448, 7463-7517, 7862-7872, 7985; both new test files in full; the `test_b101_symbol_reads.py` and `test_id_registry.py` hunks; `ch10` 60-88.
- [x] Correctness pass: edge, None and error paths (checks 2, 3, 3a, 7, 8; "What I looked for").
- [x] Simplicity pass: F5; no speculative abstraction; the helper and delegate are one statement each.
- [x] Reuse and duplication checked against Inc 13's watcher, Inc 4's resolver and the picker API (check 5).
- [x] Tests reviewed for intent: F1, F4; base-RED evidence read.
- [x] Verdict explicit: PASS-WITH-NOTES; no HIGH open.
