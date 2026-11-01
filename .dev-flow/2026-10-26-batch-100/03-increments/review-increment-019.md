# Code review — batch-100 Inc 10 (increment 019), stage E5

**Verdict: PASS-WITH-NOTES** (0 HIGH · 0 MAJOR · 1 MINOR · 4 NIT)

Reviewer: code-reviewer. Prefix CR10-. I worked separately from the authors and did not edit the tree.
Scope: `git diff e4bfd6a..1747479 -- s19_app tests`, which is Inc 10 only. That covers `s19_app/tui/app.py` (+413/−…), `screens.py` (+86), `screens_directionb.py` (+23/−…), `tests/test_b100_load_question.py` (new, 2740 lines, 52 nodes), and the re-pins in `tests/test_b100_session_reset.py`, `tests/test_b99_editor_image.py` and `tests/test_id_registry.py`. I read the whole diff.
Design read: `E1-requirements-draft.md`, `E1-`/`E2-`/`E3-rulings.md` (round-2 addenda included), `codewire/interfaces-10.md`, the `E4-*-notes.md` files, `E4-integration-notes.md` (SR-1, SR-2) and the tail of `E4-mutant-candidates.md`. As instructed, the C60 / S10-04 test gap (SR-2) is not reported.

## Findings

| Id | Sev | Tag | Where | Defect | Evidence | Fix |
|---|---|---|---|---|---|---|
| CR10-01 | MINOR | design-gap | `s19_app/tui/app.py:13768`, `:13778` (`_load_path_from_user_input`); `s19_app/tui/workspace.py:2028` | The kind of a typed or recent `data` path (MAC attach vs image replacement) comes from the suffix of the **typed** text. The classifier (`_typed_load_route`, relative branch) and `load_from_path` both act on the path `resolve_input_path` returns. Its relative fallback calls `.resolve()`, which follows a link, so the two suffixes can differ. **Scenario:** an unsaved patch on `fw.s19` (D true); `<base_dir>/cal.mac` is a link to a `.s19` file; the engineer types the relative `cal.mac` (the cwd does not hold it). The classifier says `("data", "")`, Inc 10 picks `attach`, so no question is asked. `load_from_path` then installs the `.s19` as a new image, and the patched image is replaced silently. That breaks HLR-174 / LLR-174.4b. Interfaces Q-4 compared typed-suffix options only, and treated "agree on every path the classifier accepts" as "agree with the loader". It did not consider the case where the resolved path differs from the typed one. | **Probe, executed** (`rev10-code-reviewer/lad/probe_mac_link.py` on 1747479): `D before: True`, `route: ('data', '')`, `pushed: []`, `current file: b.s19`, `mac_path: None`, `patched byte kept: False`. | Take the kind from the path the loader will read. In `_load_path_from_user_input`, compute `normalized = resolve_input_path(path, self.base_dir)` and use `kind = "attach" if normalized is not None and normalized.suffix.lower() in MAC_EXTENSIONS else "image"`, with the target taken from `normalized.name`. Alternatively, have `_typed_load_route` return `("mac", "")` apart from `("data", "")`. Add one arm to TC-B100-72 (a relative `*.mac` link to a data file → 1 question). Reachability is narrow (it needs a link with a misleading suffix that is reached only through the relative fallback), so MINOR. |
| CR10-02 | NIT | impl | `.dev-flow/2026-10-26-batch-100/evidence/inc-10/green-01-new.txt`, `green-02-repinned.txt`, `guards-01.txt` (headers) | The E4 GREEN evidence names `741cc07 + working tree` (`app.py` sha `ac5b417b8c3e6b47`). The commit under review is the merge `1747479` (`app.py` sha `4303b54269923270`). Nothing on record shows the 52 new nodes and the 5 re-pins running on the merged tree, or the corrected 9b files running against Inc 10's seam. | By reading the headers; then **executed** on 1747479 (see Checked and fine): everything is green. | Before the gate, re-record GREEN on `1747479`, or cite this review's runs. |
| CR10-03 | NIT | impl | `s19_app/tui/screens_directionb.py:4812-4814` (the `_dirty` comment), `:5866-5873` (`is_dirty` docstring) | Both texts say the flag is read outside the module "only" by "the app's load guard and `_handle_save_dialog`". The Inc 10 dropdown guard (`app.py:6211`, `on_patch_editor_panel_change_file_selected`) is a third reader. The next reader of the census would undercount. | By reading. | List the dropdown guard (LLR-174.2t) as the third outside reader. |
| CR10-04 | NIT | impl | `s19_app/tui/app.py:7563` (`_confirm_then_load` Data Flow) | The docstring says the answer arrives as "`False` / `None` (Cancel, escape, enter on `#confirm_no`)". Contract S-a says the modal is `ModalScreen[bool]` and never dismisses `None`, so `None` cannot occur. The callback is annotated `replace: bool`. | By reading (`screens.py` `_close` only dismisses `True`/`False`). | Drop "/ `None`". |
| CR10-05 | NIT | impl | `tests/test_id_registry.py:161` | The `230 -> 231` history line went into the old comment block (which ends at Inc-8a). Since Inc 8b, every bump is recorded in the docstring under `EXPECTED_SCANNED_TEST_FILES` ("MEASURED, not incremented …"). The history is now split across two places. | By reading. | Move the line into the docstring in the 8b–9b form. |

## Checked and fine

- **Correctness against the graph.** `_confirm_then_load`, `_load_would_lose` and `_load_question_text` match S-b, S-e and the composer text exactly:
  - attach reads no flag;
  - the item order is image, document, flow;
  - `call_after_refresh(go)` runs on Replace;
  - Cancel only re-homes the focus;
  - no `try/except` (A10-02);
  - the scrub is done once, in the composer (Q-2).
  `ConfirmQuestionScreen` matches S-a: `AUTO_FOCUS`, three bindings, `Text` labels, markup off, `_dismissed` as the first line of `_close`, and no imports from app, services or workspace. `is_dirty` is a read-only property.
- **Every load route meets the seam exactly once.** Traced on 1747479:
  - Load dialog router → `_route_load_project` / `_load_workarea_file` / `_load_path_from_user_input` (project arm defers to `_route_load_project`; a2l/data arms each call the seam once; refuse asks nothing);
  - `#files_list` → `_load_from_item` → `_load_workarea_file`;
  - `v` and the Load-result panel's `v` → `action_select_variant` → `_handle_select_variant`;
  - `on_mount` → `_load_path_from_user_input`.
  No other module calls a loader (grep over `s19_app/`). `_handle_load_project` holds no seam or push. The only other writer of `current_file` is `_apply_unload`, which is out of scope (Q7).
- **The merge with the corrected 9b broke no route.** The Inc 10 delta is byte-identical on both sides of the merge: `e4bfd6a..1747479` equals `741cc07..7644fa4`. The 9b correction delta is identical too: `7644fa4..1747479` equals `741cc07..e4bfd6a`. The 9b `_typed_load_route` change (resolve first, the new `link file` refusal) reaches Inc 10's refuse arm, which paints it with no question. **Executed on 1747479** (`LOCALAPPDATA` and temp under my scratch folder, `-p no:cacheprovider`):
  - `tests/test_b100_load_question.py`: 51 passed plus 1 path-length failure under my long `--basetemp` (`Project NOT saved: path too long`). The same node passes with the default temp → 52 of 52.
  - `tests/test_b100_load_dialog.py` + `tests/test_b100_project_homes.py`: 240 passed, 4 skipped, plus 2 `WinError 206` failures in `test_tc_b100_31_depth_ceiling[32|33]` caused by the same basetemp length. Both pass with the default temp.
  - The 5 re-pins: 4 + 1 passed.
- **S10-01 / S10-05 order in `_handle_load_project`.** `check_project_files`, the A2L read (`_load_a2l_data_with_cache` only writes the A2L cache, which the reset does not clear, so nothing is parsed twice) and the all-`None` refusal all run before `_reset_project_session()`. Only `_declared_regions` (a write) follows it. No moved line references a name created after the reset.
- **An attach keeps D.** `_merge_mac_with_existing_primary` keeps `mem_map` identity, and `_apply_prepared_load` calls `mark_saved` only for a new dict, so D survives a MAC attach. Confirmed by `test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch`.
- **The dropdown guard (S10-02, A10-R2-3).** It matches the Load-button guard's status line. `Select.NULL` reset does not re-fire, because the panel returns early on `NULL` (`screens_directionb.py:5951`).
- **A question over another modal.** I probed it, because the 9b guard does not stop `ctrl+l` over `SaveProjectScreen`. `App.query_one` queries the default screen (`textual/app.py:941`), so `_load_would_lose("project")` does not raise. **Probe executed** (`probe_modal_under.py`): the same behaviour on 1747479 and on e4bfd6a.
- **The 52 new tests assert intent and can fail.**
  - Every 0-question arm has a live-guard control in the same session.
  - Oracles are observable: stack, focus id, painted text, session digest, entries / flags, recent-store sha.
  - Negative controls are concrete (enumerated cells, order spy on push vs reset, the AST seam census with `go` closures).
  - The Windows-only A2L arm kills the base reset order (M68/M69).
  - The TC-B100-12 arm uses the confirmed SR-1 spy.
- **The 5 re-pins.** TC-B100-10 ×2 now assert 0 closed-document lines and the summary as the freshest line; they fail if the interim block returns (M72). AT-B100-03 waits for the question and asserts it names `Patch Editor entries` before `y`. The b99 re-pin waits for the question before answering.
- **Simplicity, reuse, conventions.** No speculative code. The modal is generic only as far as LLR-174.2a needs. The kind rules are two short expressions. The new `app.py` functions carry Summary / Args / Returns / Data Flow / Dependencies. CRLF is kept. `styles.tcss` is unchanged (Q-6) and the layout arms pass at 99, 118 and 220 columns.
- **Declared and not re-reported:** S10-03 (an in-flight worker), the `W\temp\x.mac.` residual (Q-4), M29 / M30 / M32 / M33 / M71 / M79 (E4 gaps), and C60 (SR-2).

## Evidence states

- CR10-01: `executed` (probe).
- CR10-02: `executed` (runs on 1747479).
- CR10-03 … CR10-05: `n/a — by reading`.
- Full suite: `not-run` (outside my remit).
