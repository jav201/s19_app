# Code Review — Increment 002 (batch-92, Inc-B)

`code-reviewer — spawned as a generic agent with agents/code-reviewer.md · OK to advance`

## Scope reviewed

Inc-B delta only (whole batch uncommitted at base `410cde5`; Inc-A's packet already approved — its
files excluded from judgment, noted where they appear inside shared diffs):

- `s19_app/utils.py` · `s19_app/tui/screens_directionb.py` · `s19_app/tui/insight_style.py` ·
  `s19_app/tui/checks_view.py` · `s19_app/tui/issues_view.py` · `s19_app/tui/app.py` ·
  `s19_app/tui/services/validation_service.py` (7 source rows of packet §2)
- `tests/test_import_census.py` (new) · `tests/test_tui_hostile_map.py` ·
  `tests/test_a2l_multiline_headers.py` · `tests/test_tui_directionb.py` (4 test rows)
- Read for judgment: packet `increment-002.md` in full; `tests/test_import_census.py` in full;
  contract lines cited in the brief.
- Governing: `01-requirements.md` LLR-003.1–003.3 · LLR-004.2/004.3 · TC-653/654 · AT-290/291 ·
  §5.2 rule; PDR D4/D5 + frozen render surfaces D1/D2.

## Checks executed (all `executed`; none taken from the packet on trust)

1. **Byte-exact transfer — MATCH.** Recomputed both spans independently:
   `git show 410cde5:s19_app/tui/screens_directionb.py` :869–936 →
   `103da22077f27c2d9733c962dbcc77c44602e8f2f1f80b669445b0ec32262974`;
   `s19_app/utils.py` :32–99 → `103da22077f27c2d9733c962dbcc77c44602e8f2f1f80b669445b0ec32262974`.
   Equal to each other and to the packet's claim. `_CONTROL_SCRUB` moved WITH the function:
   0 occurrences remain in screens_directionb.py (its :869 is now `from ..utils import safe_text`);
   exactly 1 definition in utils.py (:41); not duplicated anywhere (TC-653's AST pass agrees).
   utils.py stays stdlib + `rich.text` only (`typing.List`, `from rich.text import Text`).
2. **C-17 contract verbatim at the new address.** Own probe in a fresh interpreter:
   `safe_text("a\x9b31mb[red]")` → `.plain == "a31mb[red]"` and `.spans == []`. The byte-class
   table (C0/DEL/C1, closed at U+009F) is the moved table, byte-identical.
3. **Shim is identity, not copy — 8/8.** Own run:
   `insight_style.{CYAN, DGRAY, GREEN, LABEL, MICROBAR_EMPTY, MICROBAR_FILLED, VALUE, microbar}`
   are all `render.format`'s identical objects. The retained palette/helpers stay canonical in
   insight_style: `human_bytes` :131, `label_value` :182, `threshold_style` :225,
   `cap_gauge_style` :267 (TC-654 pins all 14 RETAINED_SYMBOLS too).
4. **The 7 view consumers are byte-untouched.** `git diff 410cde5` over app.py /
   screens_directionb.py shows 0 `insight_style` lines; over checks_view.py / issues_view.py the
   only `insight_style` diff-lines are CONTEXT lines inside the safe_text-repoint hunk
   (verified by prefix inspection) — the consumption lines (:40, :39) are unchanged;
   `crc_designer_view.py` / `json_highlight.py` whole-file diffs are EMPTY. Import lines sit at
   the claimed numbers (:80, :40, :39, :81, :82, :90).
5. **Repoint correctness.** `app.py:39` = `from ..utils import safe_text` ✓;
   `checks_view.py:41` ✓ / `issues_view.py:40` ✓ (only ± lines in each diff);
   `validation_service.py:17` = `from ...render.format import GREEN, LABEL, VALUE, microbar` ✓.
   Closure greps: 0 live `safe_text` imports from the retired screens address in `s19_app/` +
   `tests/` (the 2 surviving mentions are the packet's pre-declared C4 prose:
   test_tui_hostile_map.py:65 docstring, and a census comment); 0 `insight_style` imports under
   `s19_app/tui/services/`; the 3 test importers repointed at the claimed lines
   (hostile_map :83–84 module split, a2l_multiline_headers :360 local, directionb :3225 local —
   the latter two files' diffs also carry Inc-A's pre-approved `hexview`→`render.hexview` locals,
   consistent with the signed-balance ledger); no insight_style test consumer repointed (by design).
6. **TC-653/654 as oracles — C-31-proof.** `tests/test_import_census.py` is a runtime AST census:
   it walks EVERY `.py` under `s19_app/` and `tests/` (aliased/plain, module-level and local,
   name-aware), derives the importer/definer sets from the live tree, and asserts SET-EQUALITY
   against the measured sets — drift in either direction fails. Not hand lists. Reviewer ran the
   5-node TC module: **5 passed**. Reviewer then executed his OWN mutation arm: flipped
   `checks_view.py:41` back to `from .screens_directionb import safe_text` →
   `test_tc653_safe_text_import_census` FAILED with
   `missing=['s19_app.tui.checks_view']` — the census catches a consumer at the retired address
   even though it still resolves at runtime. Restore proven byte-exact: the working file returned
   to `badbba330a6d3fd504034df82abea752b60063e6af6b866a6c007ec5c41404fd` (== the packet's restore
   digest; reviewer's sed round-trip had normalized CRLF→LF and was repaired to the original
   bytes before the hash was taken — the packet's content claim independently reproduced).
7. **Frozen + frozen-surface discipline.** Frozen-set diff (`color_policy.py`, `range_index.py`,
   `core.py`, `hexfile.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`) is EMPTY. `s19_app/render/*`
   carries ZERO Inc-B edits: 0 render paths in the tracked diff (the dir is untracked-from-Inc-A),
   all render file mtimes fall inside Inc-A's creation window (09:55–10:10), and the render
   content is behaviorally pinned by TC-654/655 value pins + `getsource` equality, which pass in
   the reviewer's own 5-node run.
8. **Evidence integrity.** All 13 cited artifacts re-hashed on disk — **13/13 digests match** the
   packet's table. Reviewer re-ran the AT-290 hostile oracle family + AT-291 strip nodes
   (the 8 named nodes): **14 passed, 0 failed** (18.52 s). The 242.05 s full guard host was
   accepted from its hash-verified transcript — exit line `183 passed in 242.05s (0:04:02)` —
   being at the re-run cost threshold and covered independently by the reviewer's own
   census/identity/hostile runs plus the reviewer's verified import-line-only diff of the guard
   file; repointed-files transcript tail `72 passed in 42.34s` and dual-guard tails
   (`1 passed` / `3 passed`) match the claims. Cold-probes artifact reads 5/5.
9. **V59 reverse trace.** Every Inc-B row in packet §2 carries ≥1 `Traces-to`
   (LLR-003.1/003.2/003.3/004.2/004.3 as mapped); PDR condition C1 (the >4-source-file budget,
   7 modified) is restated in §2 and accepted — the increment is repoint-only over measured,
   census-policed closed sets.

## Findings

None. No HIGH, no MEDIUM, no LOW.

- Correctness: the move is byte-exact (independent hash), the scrub contract is verbatim at the
  new address (own hostile probe), the shim is object identity (own run), all repoints land at
  the contract's named lines, closure greps are empty.
- Simplicity: no premature abstraction — a move, a shim, and repoints; nothing else.
- Reuse/duplication: zero duplication of the moved unit or the shimmed symbols (census-enforced).
- Convention conformance: transfer preserves the original docstring/comments/style; the shim
  carries an accurate ownership note.
- Tests verify intent: the censuses are live-tree set-equality (can fail on any drift), the C-17
  oracle re-derives the control class instead of importing it, and the RED arms were witnessed
  RED by the reviewer, not only by the author.

## Verdict

- [x] **OK to advance** — no HIGH, and every fix asked for is N/A (none needed)
- [ ] BLOCK-UNTIL: —
- [ ] Block — HIGH findings open

## Evidence states

- Diff read in full — `executed` (7 source + 4 test files; Inc-A files skimmed only to separate deltas)
- Body-hash recompute — `executed` (match, both spans)
- Hostile scrub probe — `executed` (`a31mb[red]`, spans empty)
- Shim identity 8/8 — `executed`
- Frozen surfaces — `executed` (frozen-set diff empty; render/ zero Inc-B touch; pins pass)
- TC module run — `executed` (5 passed, reviewer-run)
- Mutation arm — `executed` (TC-653 reddened by reviewer's own flip; restore hash-verified)
- AT family run — `executed` (14 passed, reviewer-run)
- Evidence re-hash — `executed` (13/13 match)
- Guard host — `approved` (cited transcript, hash-verified bytes + exit line; re-run declined at the 4-minute cost threshold, mechanism independently covered)
- V59 reverse trace — `executed`
