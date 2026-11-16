# Inc 10 E5 — review (one reviewer, one pass: code + security)

Reviewer X10 (claude-opus-5-5), sole writer of `b103-inc10`; brief `brief-X10-inc10-e5.md` (relevo-12). Base `439860c4`; reviewed tip `28a5c82f` (after L10's law fixes). Scope: Inc 10's own diff (`git log --first-parent 439860c4..28a5c82f`; the merge `16d93b56` of `b103-inc8` brought records only, `git diff 16d93b56^1 16d93b56 -- s19_app` is empty): 7 product files — `changes/io.py`, `changes/apply.py`, `services/change_service.py`, `app/patch.py`, `screens_directionb/patch_editor/actions.py`, `.../panel.py`, `styles.tcss` (293+/85-) — and the Inc 10 tests and shared retargets. Rules: DF-03, DF-04 (the requirement wins over the code), P-059 (operator items decided provisionally).

## Verdict

No BLOCKER, no MAJOR. 1 finding fixed in this pass (test only), 3 MINOR to PENDING (one of them pre-existing on base, outside Inc 10's delta), 1 load-sensitive pair kept visible, 1 suspected defect disproved by a run. Captures hold every requirement they show (`E5-captures.md`).

## Findings

| Id | Tag | Sev | Finding | Disposition |
|---|---|---|---|---|
| F-X10-1 | impl (test) | MINOR | No test bounds the HEX row walk: mutant MU24c (the boundary `(row_start \| 0xFFFF)` without `+ 1`) makes `row_end == row_start` for a row starting at low 16 bits `0xFFFF`; the loop never advances and appends empty records until the runner's 300 s timeout (`E4-mutants.md`). A CI without that timeout hangs, and memory grows. | **Fixed, test first** (`f256579c`): `test_b103_inc10_g3_engine.py::test_r_hex_emit_001_11_a_row_starting_at_low_ffff_ends_at_the_boundary_and_the_walk_advances` counts the emitter's record writer and stops at 64; expected lines hand-computed. Tree GREEN (0.06 s), MU24c copy RED in 0.10 s (`assert 65 <= 64`), base RED (`:02FFFF00AABB9B` crosses the boundary). `evidence/e5/logs/bound-{tree,mut24c,base}.txt`. |
| F-X10-2 | impl | MINOR | `changes/apply.py::_render_named_by_landing` holds `assert payload is not None`; `save_patched_image`'s own comment (review F9) says the refusal path proves the payload "— no assert downstream". The assert is dead (an `"s19"` render never returns `None`) and vanishes under `python -O`; no behaviour changes. | PENDING (style, batch close). Not fixed here: a product edit with no behaviour to make RED. |
| F-X10-3 | design-gap | MINOR | An ASCII control character typed or pasted into the save name passes `_sanitize_s19_filename` and reaches the written file name and the S0 header data (`R-S19-S0HEADER-001.2` removes only non-ASCII). Probe P2: `'fw\x1bx.s19'` → name `'fw\x1bx.s19'`, header `b'fw\x1bx.s19'`, no issue. Pre-existing on base (the typed text went into the header); Inc 10 narrows it to the bare name. The E1 hostile-input rule (control characters for every outside input) has no `If` requirement for the save name. On Windows the placement refuses such a name (OSError → `MF_WRITE_CONTAINMENT`); on Linux it is written. | PENDING (new requirement, DF-04 c: defer). Status lines stay safe: `set_status` scrubs through `safe_text`. |
| F-X10-4 | test (not Inc 10's delta) | MINOR | Whole-file runs of three shared files T10/I10 retargeted fail outside the brief's expected list, **identically on base `439860c4`**: `test_b100_load_question.py` 4 failed (TC-B100-44, -12, -70, AT-B100-15: `pilot.click("#patch_entry_address_input")` misses — the landing pane opens on Patch script since Inc 8, the D-F8-2 / P-075 class not applied to this file); `test_b100_save_image.py` 9 failed on base (TC-B100-15 mac/a2l, -58 mac attach `#sections_list` NoMatches, -70 ×5, AT-B100-05 ×2); `test_b100_workers.py` times out at 300 s with `-n 2` on both trees. Consequence: Inc 10's edit of TC-B100-44 (`output_format="s19"`) is not reached by any run (it fails at the click first). The other Inc 10 sites pass on the tree run one by one: TC-B100-14 ×8, -15 ×8, -58 ×3 (save-back/save-project), -69 ×4, -53 ×2. | PENDING (Inc 8 retarget owner / batch close); not fixed here (not Inc 10's files, DF-03). |
| (L-1) | — | — | `test_tc_b100_59_open_project_unchanged` and `…_pending_patch_in_the_open_project` FAILED on the tree in two loaded runs (load 8; `timed out waiting for the save into the open project`) and passed on base in the same set. | **Load-sensitive, not a regression and not called flaky** (HT-07: no 10-run rate measured): standalone diagnosis passes on both trees (`diag59-*`); at load ~5.5 the two nodes alone pass (2 passed, 7 s) and the whole `-k tc_b100_59` set passes on tree (30 passed) and base (30 passed). Kept visible here. |
| (P3) | — | — | Suspected: a byte-identical file under another name makes the S0 rounds oscillate and the header name a file other than the landing. | **Disproved** by probe P3 (`evidence/e5/probes/probe.txt`): `foo.s19` = the render with header `bar.s19`; saving `bar.s19` lands `bar.s19` with header `bar.s19`. No finding. |

## Security lens (each claim with its run)

- **Paths written outside the program.** The destination is unchanged (open project or work area); `_guarded_destination` runs before the new S0 rounds, and `predict_placement` / `place_into_workarea` both get the same `dest_dir` and the sanitized bare `safe_name`. Staging stays under the guard's root. Runs: `test_changes_apply.py` and the Inc 10 write files (`04-validation.md` § Runs).
- **S0 header from the name (P-022 fix `be8fd66c`).** The handler passes the rule, never the typed text; the engine applies it to the predicted landing name. `test_b103_inc10_s0_written_name.py` 5 passed (typed `C:\Users\<user>\Desktop\fw.s19`, `~/fw.s19`, a numbered landing). Captured: `numbered.*` lands `firmware-patched_1.s19`.
- **Untrusted names in notices.** The apply line holds counts only and is painted as `Text(...)` in a `Static(markup=False)`; the `Nothing applied` notice passes `markup=False` (law `test_filename_markup_safety` GREEN; node `…nothing_applied_notice_is_shown_literally…`). The Format label is from constants. Bidi/escape: no file name is put into a new notice by Inc 10; the header drops non-ASCII (bidi controls included); status lines go through `safe_text` (pre-existing). Residual: F-X10-3.
- **Extension rule (R-PE-EXPORT.14/.15).** `_SUFFIX_RE = \.(s19|hex)\s*\Z`, IGNORECASE. Probe P1: over all 0x110000 code points the regex whitespace class equals `str.isspace()` (0 differences), so the box agrees with the engine's `strip()`; `fw.s19` + U+3000 → `fw.hex`. Other text kept (cases .15/1, /2 GREEN).
- **Stage hide (R-PE-EXPORT.17/5).** `hide_save_prompt` only when the stage `result.ok`; add/edit/remove hide after the service call (an exception leaves the document and the prompt as they were); `_apply_entry_json_edit` hides on `ok`. Cases 17/1…/5 GREEN.
- **Format with no default (I-10.2, E3-5).** A confirm without `output_format` gives `kind None` → the engine refuses (`CHG-HEX-SAVE-UNSUPPORTED`); no silent S19.

## Known items (brief §2)

1. **Wording list** (`E4-integration.md` §4, 5 items) — fixed to the built text in `4fc94f36`; none changes the meaning of a requirement sentence, threshold or id: (1) `01-requirements.md` Acceptance and AT-I10-1: the Inspector chip is pressed once (landing pane = Patch script, R-TUI-063.3); (2) R-CHG-003.1/1 expected result: the prompt a shown widget, `Write file` at its place (= the threshold's own text); (3) graph E2-3: longest label + the Button's line-pad (19); (4) `02-test-cases.md` header sentence and .2/5 base note: D8-28 closed by `be8fd66c`, three `conflict` cases remain; (5) `E4-impl.md` U2: the width check read the label, not the paint.
2. **MU24c** — a test bound was missing; added (F-X10-1).
3. **R-S19-S0HEADER-001.1/3 and R-S19-EMIT.11/1, /2 stay `conflict`** (P-068, D-6 A): owed by D8-27 (the source's S0 data at width 16) and D8-29 (the terminator address); not implemented in Inc 10; batch-close backlog (P-026). trace_check counts them as expected.

## Test cases (card rule 4)

Re-checked the coverage marks: 121 `full`, 9 `partial` (R-S19-S0HEADER-001.1/2, .2/2…/5, .3/1…/4: the save is reached by posting the confirm message, not by a click — `partial` is right), 3 `conflict` (above). No mark changed.

## Operator items (provisional, P-059)

Decided provisionally by this review, with the reason; they go to the final page for the operator's confirmation. **Not approved.**

| Id | Option kept (provisional) | Reason |
|---|---|---|
| O-1 | A′ — `Apply: <a> applied, <s> skipped, <b> blocked · changed in memory only — Write file saves it` | Captured on one row at 118×54 (`applied.118x54`); counts only, so no file-derived text enters the line (B′ paints the file name, R-PE-005); `✓` on green stays reserved for verdicts in this panel. |
| O-2 | D-3 A — Width hidden for Intel HEX, its place kept | Captures show `Write file` / `Don't save` on the same cells for S19 and Intel HEX at both sizes (x=49/62 at 118, x=67/80 at 220): R-PE-EXPORT.12 holds; collapsing it would move the commit button under the pointer between presses. |
| O-3 | The Format chip (`Format: S19` / `Format: Intel HEX`, a press switches) | Fits the existing chip row; the whole label paints at width 19 (captured); a radio line costs one more row against the 4-row I-8.3 dock budget (F-R8-1). |
| O-4 | No key | Every dock control is reached by focus + Enter in the captures (real keys); a new key needs the Windows Terminal check and the R-SHELL-KEYS / R-DLG rules, and no defect shows a need. |
| O-5 | No frame | A titled frame costs two rows over the 4-row dock budget at 118×54; the dock sits directly under the document row, which already groups it (captured). |
| O-6 | Only a final `.s19` / `.hex` is replaced | Any other text stays as typed (R-PE-EXPORT.15) and the engine appends the suffix (`x.bin.hex`), so the operator's name is never silently cut; replacing any extension would eat parts of names such as `release_v2.1`. |

## Checks not run, and why

- Full suite: batch end (DF-08).
- No timing decision (HT-08): the runner had other load; nothing here is a timing result.
- Captures of the HEX-source S0-from-name path (R-S19-S0HEADER-001.2 with a numbered name) were not taken: case01 has S0 data, so `numbered.*` shows R-.1's header; .2/5 is proven by tests only.
- No mutant battery re-run (E4 MU10 stands; only MU24c was re-run, on a copy).
