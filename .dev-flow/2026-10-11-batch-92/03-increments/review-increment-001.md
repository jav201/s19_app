# Code Review — Increment 001 (batch 2026-10-11-batch-92, Inc-A)

code-reviewer — spawned as a generic agent with agents/code-reviewer.md · **OK to advance**

Standalone copy of the review recorded in the packet's §4b cell
(`03-increments/increment-001.md`), written at the Phase-3 increment gate. Every check below was
**executed by the reviewer in the worktree** `C:/Users/jjgh8/Github/s19_app-b92` (2026-10-12), not
read from the packet's claims.

## Scope reviewed

The uncommitted Inc-A diff vs base `410cde5` (`git status` / `git diff 410cde5 --name-only`):
`s19_app/render/{__init__.py,hexview.py,format.py}` (new), `s19_app/tui/hexview.py` (deleted),
repoints in `s19_app/tui/{__init__.py,app.py,screens.py,screens_directionb.py,services/{load,report,diff_report}_service.py}`,
new tests `tests/test_render_hexview.py` (TC-651/652) + `tests/test_render_format.py` (TC-655),
AT-288 node + repoints across 8 test files. Governing contract: `01-requirements.md`
(LLR-001.1–001.4 · LLR-002.1–002.3 · LLR-004.1-as-folded · TC-651/652/655 · AT-288 re-chartered
block · §5.2 gate rule).

## Executed verification

- **Byte-exact move — recomputed by me.** Base `s19_app/tui/hexview.py` @410cde5 minus base lines
  61–143 (the 3 `range_index` wrappers, AST-contiguous 61–141, + 2 trailing blanks 142–143) minus
  base lines 16–17 (the two `tui` style imports) plus the single line
  `from .format import CYAN, DGRAY, VALUE, FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE`
  ⇒ SHA-256 **`fe6921c79b8f44776e2350db317b8f01150f341b9280f36f26b25ac4a2185f3b`** ==
  `s19_app/render/hexview.py` == the packet's recorded hash. MATCH. Zero `s19_app.tui.*` imports
  under `render/` (grep + TC-651/TC-655 AST probes).
- **Contract repoint claims vs diff — all hold.** 8/8 product consumers at the contract lines;
  `tui/__init__` drops exactly the 3 wrapper names from import block and `__all__`, keeps the
  12-name renderer surface (`tui.X is render_hexview.X` asserted 12/12 by TC-652);
  `app.py` = `from ..range_index import address_in_sorted_ranges, build_sorted_range_index` +
  `from ..render.hexview import build_row_bases, find_string_in_mem, render_hex_view_text`
  (LLR-002.3 verbatim). 8/8 old-address test importers (3 forms) + `test_report_service.py:595`
  census string repointed — read directly on disk, and independently asserted by the passing
  TC-651 census.
- **New TCs are real oracles.** TC-651: live-tree AST census, two-way set-equality
  (`extra=`/`missing=`), covers aliased/plain/module-local forms + retired-path absence in product,
  tests, and on disk + tui-free rule + service-layer grep + all 3 test import forms. TC-652:
  positive-absence (`hasattr`, `__all__`, `import_module` → ImportError) + 12/12 identity. TC-655:
  literal values + equality to frozen origins both directions + `inspect.getsource`
  verbatim-equality of `microbar`. Reviewer-run: **3 passed** in 1.93 s.
- **Reviewer-executed RED arm.** Scratch consumer `s19_app/tui/_review_scratch.py` importing
  `from s19_app.tui.hexview import build_row_bases` → TC-651 **RED**
  (`s19_app.tui.hexview still imported by ['s19_app.tui._review_scratch']`). Scratch removed →
  TC-651 green; `git status` over `s19_app/` identical to the pre-mutation set. The packet's own
  4 RED arms' transcripts re-hash to their recorded digests.
- **AT-288 integrity.** Capture present (7 739 B), sha256 `061ee94c…4c39` == sidecar == retained
  `.PRE`. Driveable set verified in the node source: non-default `context_bytes=0x200` asserted on
  the emitted bytes (`- Context bytes: 512`); window asserted
  `low < range0_end < range1_start < high` across the unmapped gap with the all-dots gap row and a
  mapped range-1 row. Reviewer-run now: **1 passed** (byte-equality with the pinned capture).
- **Evidence artifacts.** All 15 cited files re-hashed: **15/15 match** the packet's recorded
  digests (incl. sidecar self-digest `c00f0c19…`, first-run transcript `7356482a…`). The §5.2 data
  `evidence/baseline-failing-set.txt` untouched: 44 ids, `a16` at line 18, mtime 2026-10-12 07:04
  predates every increment transcript (10:08–10:38); tc024 outside the union, a16 inside.
- **Scope discipline.** Product diff == exactly the §2-listed files, each with ≥1 Traces-to id.
  Inc-B set and frozen set (`color_policy.py`, `range_index.py`, `core.py`, `hexfile.py`,
  `validation/`, `a2l.py`, `mac.py`): **0 diff entries**. C1 waiver restated in §2 ✓.
- **tc024 flake characterization.** Standalone loop on the Inc-A tree: **8/8 passed**. Mechanism =
  the worker-thread race the test's own comment admits (batch-68 N5); monkeypatch targets
  (`app_mod.generate_diff_report`, `compare_images`) are identical objects at both addresses and
  not among the repointed lines. **Pre-existing load-sensitive flake; no causal path from the
  diff.** Sits outside the 44-id union, so the §5.2 rule reads a flip as functionality loss —
  orchestrator ruling (flaky registry / pinned-union addition) owed at close, as §5 requests.

## Findings

### F1 — unused range imports retained in the moved module  [Severity: LOW]
- **What:** `s19_app/render/hexview.py` still imports `RangeIndex` + the 3 aliased range
  primitives from `..range_index`, unused after the wrapper deletion.
- **Where:** `s19_app/render/hexview.py:10-15`
- **Why it matters:** dead imports; but LLR-001.1's byte-identity threshold names exactly two
  permitted deviations, so the bytes stay by charter. Declared in packet §5.
- **Suggested fix:** none for this gate; drop at close or next batch (own increment, own evidence).

### F2 — TC-023 census now vacuous  [Severity: LOW]
- **What:** `tests/test_tui_hexview.py:345` matches modules ending `tui.hexview`; post-move it
  matches nothing, so it passes vacuously.
- **Where:** `tests/test_tui_hexview.py:345,360`
- **Why it matters:** the protecting conclusion now rides on TC-651/TC-652 (declared in packet §5
  as load-bearing emptiness). Suggest extending the census string to the render address at close.

### F3 — flow-bookkeeping files absent from §2's table  [Severity: LOW]
- **What:** the uncommitted diff also touches `AT-TC-REGISTRY.jsonl` (TC-651…655 / AT-288…291
  reservations), `.gitattributes` (evidence `-text` line), `docs/architecture.md` (attributed
  "Amended at DOC" batch-92 amendment), `.dev-flow/state.json`, `.dev-flow/_derived/ATLAS-*`.
- **Where:** repo root / `.dev-flow/`
- **Why it matters:** none of it is implementation scope (id authority, doc amendment, flow
  state) — but §2's reverse trace does not name them. Record them at close for completeness.

### F4 — tc024 load-sensitive flake disposition  [Severity: LOW — orchestrator ruling owed]
- **What:** `tests/test_tui_diff_screen.py::test_tc024_report_trigger_invalid_dest_refused` flips
  under load (worker-thread race, admitted in the test's own comment).
- **Where:** `tests/test_tui_diff_screen.py::test_tc024_report_trigger_invalid_dest_refused`
- **Why it matters:** outside the 44-id pinned union, so a flip fails the §5.2 gate by rule (1)
  despite being pre-existing and unrelated to the move (evidence: 8/8 standalone now; monkeypatch
  targets identical objects; no moved symbol in the path).
- **Suggested fix:** orchestrator adds it to the flaky registry / pinned union at close, per
  packet §5's own recommendation.

## Verdict
- [x] **OK to advance** — no HIGH, and every fix asked for is n/a (no HIGHs open)
- [ ] BLOCK-UNTIL: —
- [ ] Block — HIGH findings open

## Evidence states
- Byte-hash recomputation: `executed` (match)
- Repoint/census spot checks: `executed`
- TC-651/652/655 run: `executed` (3 passed) · reviewer RED arm: `executed` (RED → restored → hash-verified)
- AT-288 capture hash + node run: `executed` (1 passed)
- Evidence re-hash (15 files): `executed` (15/15 match) · baseline union untouched: `executed`
- Scope reverse trace: `executed` · tc024 loop: `executed` (8/8 pass standalone)
- F1–F4: `executed` observations; none blocks. No finding is `planned`/`not-run`.
