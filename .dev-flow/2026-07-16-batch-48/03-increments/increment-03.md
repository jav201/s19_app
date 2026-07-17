# Increment 03 — batch-48 · Patch Editor BIG · the check glyph (R-TUI-077 / HLR-077)

> Branch `feat/batch-48-patch-big` @ base **`ac3ba35` (Inc-2b)**. Scope: **HLR-077 (LLR-077.1…077.6)**.
> Out of scope, untouched: strip (Inc-4/5) · JSON (Inc-6) · card (Inc-7).
>
> ⚠ **Base correction:** the increment brief states HEAD = `b8d9ce3` (Inc-2). The real HEAD is
> **`ac3ba35`** — an **Inc-2b** commit landed on top, and it is not incidental to this increment:
> it exists **because of it** (§4.10).

---

## 1. What changed

**BLUF (1) — the BL-3 free signal is CLEAN: `git diff main -- tests/test_tui_patch_editor_v2.py`
is 0 lines.** The fold was implemented as a fold; the 32-hit census file needed no edit and
passes unmodified.

**BLUF (2) — the BL-4 provenance stamp needed a SECOND mechanism the spec did not name, and
the AT found it, not me.** The `(document_signature, image_generation)` stamp alone leaves
AT-077e **RED**: the service invalidates correctly while the **table keeps painting image A's
verdicts**, because nothing re-renders the entries table on an image load. That was the first
red of the increment and it was not predicted. A render call at the load seam closes it (M-7).

**BLUF (3) — 01b's own prescribed AT-077d fixture does not discriminate the mutation it is
named for.** Measured, not argued (§4.3).

1. **LLR-077.1 — index-aligned derivation.** `ChangeEntryRow` gains a defaulted
   `check_glyph: str = "·"`; `ChangeService.rows()` joins `last_check_result.entries[i]` to
   `document.entries[i]` **by position**. No address comparison exists in the path.
2. **LLR-077.2 ★ — the two-part provenance stamp.** `ChangeService` records
   `(document_signature, image_generation)` at run time; `rows()` emits verdicts only while
   **both** parts still match, else every glyph degrades to `·`. `document_signature` is the
   ordered `(entry_type, address, encoded_bytes)` tuple (**content, not count**).
   `image_generation` is an `app.py`-owned monotonic `int`, bumped per install and pushed via
   the new `set_image_generation`. `id(mem_map)` is **not** used (id reuse after GC → a false
   "same image" match). `mac_records`/`a2l_tags` are **not** covered (they drive `linkage`,
   not `result`) — asserted, so no later batch over-builds it.
3. **LLR-077.3 — the vocabulary.** `✓`/`✗`/`◐`/`·` → `GREEN`/`RED`/`YELLOW`/`DGRAY`; an
   unrecognised token → `◐`, mirroring `_CHECK_RESULT_SEVERITY`'s WARNING default rather than
   inventing a second policy.
4. **LLR-077.4 ★ — the FOLD.** `_ENTRIES_COLUMNS` stays a 5-tuple; `_kind_cell` builds cell 0
   as `Text(style=PURPLE)` + a glyph span + the kind text — the A2L (`app.py:9548`) / MAC
   (`app.py:9223-9226`) idiom verbatim.

**Not a deviation (Inc-1's lesson — don't over-report either):** the glyph→style map lives in
`screens_directionb.py` while the token→glyph map lives in `change_service.py`. LLR-077.1
specifies `check_glyph: str` on the row and LLR-077.4 puts the styling in `refresh_entries`, so
this is the split the spec describes, and it is what keeps C-7 intact (the panel imports nothing
from the service). The cost — two maps keyed on the same four characters in two modules — is
closed **mechanically** by TC-077.3's totality clause, not by hoping.

### ⚠ Three deviations, all reported rather than absorbed

**D-1 (mechanism, LOAD-BEARING) — the `image_generation` bump is in `_apply_prepared_load`,
not `_apply_loaded_file`.** The spec names `_apply_loaded_file` (BL-4 fold, LLR-077.2, 01b's
AT-077e note). **Measured: `_apply_loaded_file` (`app.py:7873`) is only the SYNCHRONOUS
wrapper** — it delegates to `_apply_prepared_load`, and the worker path reaches
`_apply_prepared_load` **directly** via `call_from_thread` (`app.py:8278`, `_start_load_worker`).
A bump at the spec's named site would therefore **miss every real async load** — i.e. it would
have shipped the exact BL-4 defect the fold exists to close, at the site the fold chose. The
bump is placed at the one install point both paths converge on (the same point F-09/LLR-056.3
already names as the funnel).

**D-2 (a FIFTH `refresh_entries` call site — contradicts LLR-077.5's headline).** LLR-077.5
states *"**none** of the four `refresh_entries` call sites shall require a signature change for
the glyph"*. That remains **exactly true and is verified** (§4.6): the signature is unchanged
and all four sites are untouched. But its underlying claim — *"the glyph is therefore correct at
every one of them by construction"* — is **incomplete in the same way §2.5 A1 was**, and for the
same reason: it reasons about the sites that *do* refresh and never asks **whether anything
refreshes at all** on the image axis. It does not: all four sites hang off a Patch-Editor action,
an undo/redo, or the panel's own mount. **Loading an image triggers none of them.** So a fifth
call site — a render-only call at the load seam — is required for AT-077e to be true at the
surface. This is the render half of BL-4; the stamp is only the model half.

**D-3 (AT-077c arm (c) ingress).** 01b names `#patch_entry_edit_json_button` for the in-place
edit. That button is **disabled for a file-backed document** by the batch-38 A-01 guard
(`app.py`, `set_entry_edit_json_enabled`), and every AT-077c fixture is file-backed — so the
spec's ingress is unreachable for its own fixture. Arm (c) drives **`#patch_entry_edit_button`**
instead: same address, new bytes, **count unchanged** — the identical count-equality
counterfactual, through an ingress that is actually reachable. M-3 confirms it discriminates.

### Recorded, deliberate, conservative

The generation bumps on **every** install, including a MAC/A2L attach that leaves the image bytes
alone. Over-refusing costs a re-run and shows `·` (honest); under-refusing renders a lie.
Narrowing the trigger would mean inferring here whether an install "really" changed the image —
the class of inference that produced BL-4. Recorded in-line so it does not read as an oversight.

---

## 2. Files modified — **4** (cap 5 ✓)

| File | Change |
|---|---|
| `s19_app/tui/services/change_service.py` | glyph vocabulary + `_CHECK_RESULT_GLYPH`; `ChangeEntryRow.check_glyph` (defaulted); `image_generation` + `_last_check_stamp`; `set_image_generation` / `_document_signature` / `_check_glyphs`; stamp write in `run_checks`; glyph join in `rows()` |
| `s19_app/tui/screens_directionb.py` | `_GLYPH_STYLE`; NEW `_kind_cell`; `refresh_entries` cell 0 → `_kind_cell`; palette imports; docstrings |
| `s19_app/tui/app.py` | `_image_generation` init; bump + push + **the fifth `refresh_entries`** in `_apply_prepared_load` |
| `tests/test_tui_patch_glyphs.py` | **NEW** — AT-077a/b/c★/d/e★ + TC-077.1/.2★/.3/.4/.6 + the measured RED ledger |

`tests/test_tui_snapshot.py` **unchanged** — 0 new cells drift (§4.4). `REQUIREMENTS.md`
**unchanged** — BL-3 retired Amendment C and no locked requirement's element is removed, so no
§6.5 amendment is owed and none is claimed. **Zero SVG baselines touched** (local regen forbidden).
`tests/test_tui_patch_editor_v2.py` **unchanged — 0 lines** (the BL-3 signal, §4.1).

---

## 3. How to test

```bash
pytest -q tests/test_tui_patch_glyphs.py                 # AT-077a/b/c/d/e + TC-077.*
pytest -q tests/test_tui_patch_editor_v2.py              # the 32-hit census file, UNMODIFIED
pytest -q tests/test_tui_snapshot.py                     # C-22
pytest -q tests/test_engine_unchanged.py                 # C-27 arm 1
pytest -q tests/test_tui_directionb.py -k "test_tc031 or test_tc032"   # C-27 arm 2
git diff main -- tests/test_tui_patch_editor_v2.py | wc -l             # BL-3 signal: must be 0
python -m ruff check s19_app/tui/services/change_service.py \
    s19_app/tui/screens_directionb.py s19_app/tui/app.py tests/test_tui_patch_glyphs.py
```

The mutations of §4.3 are reproducible from the ledger in the test module's docstring.

---

## 4. Test results — executed, pasted verbatim

### 4.1 ★ THE HEADLINE — the BL-3 free signal, MEASURED

```
$ git diff --stat main -- tests/test_tui_patch_editor_v2.py
$ git diff main -- tests/test_tui_patch_editor_v2.py | wc -l
0
```

**0 lines. The fold is a fold.** The census file's index-readers (`:2578` — its docstring pins
the column order as contract — and `:3208-3209`) read `Coordinate(row,1)` and `(row,2)` only;
column 0 is unasserted, so the glyph rides in without touching them. It also **passes
unmodified** (§4.5, 331-test census). Had this gone non-zero, the design — not the test —
would have been wrong.

### 4.2 ★★ Index alignment — the evidence

Three independent nets, each measured against a positional mutation (§4.3 M-4):

- **AT-077d** — the FULL ORDERED list over an asymmetric 4-entry fixture: `['✓','✗','◐','✓']`.
- **TC-077.1** — two entries at the **same start address** with **different verdicts**. An
  address-keyed join cannot tell them apart; the index join does.
- **AT-077a** — the three branches land on rows 0/1/2 by exact glyph content.

⚠ **TC-077.1's premise was nearly wrong, and checking it changed the test.** `add_entry`
**refuses** a duplicate address (`change_service.py:696`, "use Edit") — so through that ingress
the colliding-address case looks *unreachable*, which is a comfortable reading that would have
retired the strongest anti-address-matching argument for the wrong reason. The **file** ingress
does construct colliding entries (it flags `CHG-COLLISION` and carries on — the engine's own
taint-attribution path exists because they reach the document). The test is built through
`load_text`, and asserts the precondition that both entries survived.

### 4.3 ★★ The mutation ledger — SEVEN mutations, all applied, run, read, reverted

**Three of my own written claims were falsified by these runs and are corrected at source.**

| # | Mutation | Measured result |
|---|---|---|
| M-1 | drop the `image_generation` stamp arm | **AT-077e FAILED** `['✓','✓']` after loading image B — the BL-4 defect, rendered. **TC-077.2 also FAILED.** ⚠ my note *"the ONLY test that moved"* was **wrong** |
| M-2 | drop the `document_signature` arm | AT-077c FAILED; 11 passed |
| M-3 | signature → `len(entries)` | **AT-077c FAILED on arm (c) ALONE** — verified by *reading the failure message*, not inferred: arms (a)/(b) ran and passed, the loop reached (c). Arm (c) IS the count-equality counterfactual |
| M-4 | `glyphs[::-1]` | AT-077d FAILED (+ AT-077a, AT-077c, TC-077.1) |
| **M-4b** | **the same reversal vs 01b's OWN AT-077d fixture** | **PASSED — `1 passed in 1.31s`** (see below) |
| M-5 | panel ignores `check_glyph` | AT-077a/c/d/e all FAILED |
| M-6 | rename a service glyph out of `_GLYPH_STYLE` | TC-077.3 FAILED **and AT-077a FAILED**. ⚠ my note *"every AT still PASSED"* was **wrong** |
| M-7 | keep the stamp, drop the refresh-on-load | **AT-077e FAILED**, 11 passed — the unpredicted first red |

**⚠ M-4b — 01b's prescribed AT-077d fixture does not discriminate a reversal.** 01b specifies
*"exactly 3 entries where only the MIDDLE (index 1) fails"* → `['✓','✗','✓']`, and calls it
**"The off-by-one killer."** It does kill a ±1 shift. But the glyph list is a **palindrome**, so
a full reversal leaves it identical. I rebuilt the test to the spec's own 3-entry shape, applied
`glyphs[::-1]`, and ran it:

```
=== SPEC's 3-entry ['pass','fail','pass'] fixture + REVERSED glyphs ===
.                                                                        [100%]
1 passed in 1.31s
```

This file therefore uses an **asymmetric 4-entry** fixture (`['✓','✗','◐','✓']`), which fails
under both reversal and shift (M-4). 01b's stated obligation — assert the FULL ORDERED list — is
discharged **more strongly**, not weakened. *(Reported for 01b correction, pending 1.)*

**M-7 verbatim, re-run against the FINAL shipped shape** (not just the draft — the guard added
in §4.7 changed the code, so the ledger was re-measured against what actually ships):

```
=== M-7 re-verified on the final guarded shape ===
FAILED tests/test_tui_patch_glyphs.py::test_at077e_image_generation_invalidates
1 failed, 11 passed in 11.84s
=== reverted ===
12 passed in 10.46s
```

### 4.4 C-22 — per-cell prediction MEASURED; **nothing new marked**

Predicted: the snapshot scaffold loads **no change document** ⇒ 0 entry rows ⇒ the table is
hidden ⇒ the glyph paints **nothing** ⇒ **0 new cells**. Measured:

```
$ python -m pytest -q tests/test_tui_snapshot.py -rxX   (within the census run)
27 snapshots passed. 2 snapshots unused.
XFAIL ...[patch-comfortable-80x24]  - batch-48 Inc-1 R-TUI-075 US-P1 ...
XFAIL ...[patch-comfortable-120x30] - batch-48 Inc-1 R-TUI-075 US-P1 ...
```

**0 FAILED.** Only the 2 patch cells carry a mark, so any other cell's drift would surface as
**FAILED**, not xfail — the inference is decisive, not optimistic. The 2 mismatches are the same
2 cells drifting since Inc-1. `test_tui_snapshot.py` is **untouched**; regen stays the single
batch-end canonical-CI follow-up PR. **Local regen NOT performed** (forbidden).

**C-28 clean** — no App-level binding, footer, header, or rail changed.

### 4.5 C-26 reverse census — censused on what I TOUCHED, one invocation

Touched: `ChangeEntryRow` · `ChangeService.rows` / `run_checks` / `last_check_result` ·
`_document_signature` / `_check_glyphs` / `set_image_generation` (NEW) · `PatchEditorPanel.
refresh_entries` / `_kind_cell` (NEW) / `_ENTRIES_COLUMNS` / `_GLYPH_STYLE` (NEW) ·
`S19TuiApp.__init__` · **`_apply_prepared_load` (the NEW seam)**.

Per Inc-2's lesson the seed table was **not** reused. The seeds' blast radius is also **too
small here**: `_apply_prepared_load` now calls `refresh_entries` on **every file load**, so the
real consumer set is *"every test that loads a file into an app"* — far wider than any symbol
grep returns. The 19-file census below is the grep result; **the full-suite run (§4.11) is the
census that actually covers this seam**, and it is reported as such rather than as a formality.

```
$ python -m pytest -q tests/test_change_service.py tests/test_memory_changelist.py \
    tests/test_tui_memory_patch.py tests/test_checks_engine.py tests/test_tui_patch_editor_v2.py \
    tests/test_tui_patch_layout.py tests/test_undo_redo_ux.py tests/test_tui_patch_big.py \
    tests/test_tui_patch_chips.py tests/test_tui_patch_glyphs.py tests/test_tui_snapshot.py \
    tests/test_tui_a2l_detail.py tests/test_tui_a2l_issue_recolor.py tests/test_tui_app.py \
    tests/test_tui_goto_marker.py tests/test_validation_service_supplemental.py \
    tests/test_tui_evidence_packs.py tests/test_tui_manifest_save.py tests/test_tui_variants.py
333 passed, 3 xfailed, 1 warning in 298.25s (0:04:58)
```

**19/19 files pass; 0 needed an edit.** `test_tui_patch_editor_v2.py` (32 hits) passes
**unmodified** — the BL-3 signal, from the consumer side. The third xfail is a pre-existing,
unrelated engine-gap carry (`TestCrossFileCompatibilityPanelRender`).

⚠ **The FIRST census run caught 2 real regressions I had introduced** — see §4.7.

### 4.6 LLR-077.5 — the four writer sites, verified MECHANICALLY

```
$ grep -rn "refresh_entries(" s19_app/tui/app.py s19_app/tui/screens_directionb.py
s19_app/tui/app.py:2057:        panel.refresh_entries(service.rows(loaded_ranges))     <- unchanged
s19_app/tui/app.py:2263:        panel.refresh_entries(service.rows(loaded_ranges))     <- unchanged
s19_app/tui/app.py:3892:        panel.refresh_entries(service.rows(loaded_ranges))     <- unchanged
s19_app/tui/app.py:7979:            panel.refresh_entries(...rows(loaded.ranges))      <- NEW (D-2)
s19_app/tui/screens_directionb.py:3259:        self.refresh_entries([])               <- unchanged (MJ-1's 4th site)

$ git diff main -- s19_app/tui/screens_directionb.py | grep -E "^[-+].*def refresh_entries"
(empty — the signature is UNCHANGED)

$ grep -rc "ChangeEntryRow(" tests/*.py | grep -v ":0"
(none — 0 direct constructions; the defaulted field breaks no caller)

$ grep -rn "id(mem_map)" s19_app/
s19_app/tui/services/change_service.py:392:  #: Object identity (``id(mem_map)``) is deliberately NOT used ...
(the ONLY hit is the comment explaining its absence — TC-077.2's threshold)
```

**4/4 original sites unchanged for the glyph; the signature is unchanged.** The MJ-1 4th site
(`screens_directionb.py:3259`) passes `[]` — benign for the glyph, as LLR-077.5 predicted. A
**fifth** site is added (D-2).

### 4.7 ⚠ The regression mutation testing did NOT catch — my own, caught by the census

My guard-free `query_one("#patch_editor_panel", ...)` at the load seam rested on a probe:

```
$ python -c "... async with app.run_test(): print(len(app.query('#patch_editor_panel')))"
panel mounted before show_screen: 1
```

**I probed the mounted case and generalised from it.** The census then failed **2 real tests**:

```
FAILED tests/test_tui_app.py::test_load_selected_file_attaches_mac_to_loaded_binary
FAILED tests/test_tui_app.py::test_apply_prepared_load_chains_updates_via_call_later
E   textual.app.ScreenStackError: No screens on stack
```

Both drive the load pipeline on a **bare `S19TuiApp()`** with no screen stack. Fixed with the
house idiom already documented **fifteen lines below** in the same file — `_apply_empty_state`'s
*"A missing widget tree (app not yet mounted) is tolerated"* (`app.py:4896-4897`). `try/except/
**else**` (not `try/except` around the call) so the tolerance cannot swallow a real error inside
`refresh_entries`. This is the guessed-premise shape the brief named, reached through a probe
rather than an attribute.

⚠ **And the comment I first wrote for that guard was itself false** — it claimed the panel
*"renders correctly from `rows()` the moment it does mount"*. Checked: the panel's own mount
self-call is `self.refresh_entries([])` (`screens_directionb.py:3259`) — an **empty** list. It
renders nothing. Corrected to state what is actually true (the unmounted case is headless-test-
only; in the real app the panel mounts at compose, before any load).

### 4.8 C-18 — the spec's OWN executed-verification commands, run verbatim

Not "the tests pass" — **01b's node ids resolve**. A node named closely enough to read right but
not to *run* silently turns 01b's `Executed verification` column into fiction, which is the BL-2
failure class one level down. Caught by listing my node names against 01b's commands:
`test_tc077_2_provenance_stamp_covers_exactly_two_axes` does **not** match 01b's
`::test_tc077_2_provenance` — pytest node ids are exact, so the spec's command would have
reported "no tests ran". Renamed; then every 01b command was executed as written:

```
test_at077a_branches                          1 passed in 1.24s
test_at077b_no_run                            1 passed in 1.28s
test_at077c_stale_provenance                  1 passed in 5.37s
test_at077d_index_alignment                   1 passed in 1.36s
test_at077e_image_generation_invalidates      1 passed in 1.28s
test_tc077_1_index_alignment                  1 passed in 0.22s
test_tc077_2_provenance                       1 passed in 0.22s
test_tc077_3_glyph_map                        1 passed in 0.22s
test_tc077_4_glyph_folded_into_kind           1 passed in 0.95s
```

**9/9 resolve and pass.** Two companion nodes sit alongside them for boundaries 01b files under
an existing TC rather than a node of its own (`test_tc077_1_short_result_does_not_raise`,
`test_tc077_2_linkage_inputs_do_not_invalidate`); they add coverage without displacing a
spec-named id. `test_tc077_6_*` is the LLR-077.6 disposition, asserted rather than inspected.

### 4.9 C-27 dual-guard — 0 frozen diff

```
$ python -m pytest -q tests/test_engine_unchanged.py
1 passed
$ python -m pytest -q tests/test_tui_directionb.py -k "test_tc031 or test_tc032"
6 passed, 168 deselected
$ git diff --name-only main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
      s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```

### 4.10 ⚠ Inc-2b — this increment's hues were reserved for it, one commit earlier

Found by reading the real HEAD rather than trusting the brief's `b8d9ce3`. **Inc-2b
(`ac3ba35`, an operator decision) exists because of THIS increment**: Inc-2's chip family had
claimed `GREEN #54efae` + `YELLOW #f6ff8f` as a **function** cue while Inc-3 was concurrently
claiming the same hues, in the same panel, as a **verdict** cue — *green = "apply-path button"
AND "check passed"*. Inc-2b moved the chips to `PURPLE`/`CYAN` and **reserved GREEN/YELLOW/RED
for verdicts inside `PatchEditorPanel`**. Verified against the shipped tree, not assumed:

```
$ grep -B3 "#54efae|#fd8383|#f6ff8f" styles.tcss   ->  .sev-ok / .sev-error / .sev-warning ONLY
$ chip hues shipped by Inc-2b: $accent-calm · #b565f3 PURPLE · #7dd3fc CYAN
```

**0 collision: no glyph hue is reused by any chip rule.** So the LLR-077.3 palette lands exactly
where Inc-2b cleared space for it, and the verdict cue in this panel is now unambiguous.

**Why the hue agreement with `.sev-*` is coherence, not Inc-2's error repeated.** Inc-2's defect
was a **function** cue borrowing a **verdict** hue. The glyph *is* a verdict, and its mapping
already exists upstream: `_CHECK_RESULT_SEVERITY` (`change_service.py:78`) maps
pass→OK / fail→ERROR / uncheckable→WARNING, and LLR-077.3 mandates the matching
GREEN/RED/YELLOW. Same meaning ⇒ same hue is the *point*. And the glyph reaches its colour as an
**inline Rich span style**, never through a `sev-*` CSS class — so Inc-2's correct rejection of
class reuse stands, and frozen `color_policy.py` is untouched (§4.9).

**Observation, NOT a re-litigation (Inc-2b is operator-approved and I am not re-opening it).**
Inc-2b's declared residual is `CYAN` ≡ `.sev-info`. There is a second, undeclared adjacency in
the same move: within this panel `PURPLE` now means both *"kind cell"* and *"apply-path button"*,
and `CYAN` both *"address cell"* and *"checks-group button"* (LLR-075.2's role accents, shipped
Inc-1). It is **materially weaker than the one Inc-2b fixed** — a role accent on a table cell and
a group hue on a `Button` are different widget classes that are never mistakable for one another,
and **neither is a verdict**, which is the cue Inc-2b correctly says must never be ambiguous.
Recorded for the record only; no action proposed.

### 4.11 ruff + full suite

```
$ python -m ruff check s19_app/tui/services/change_service.py s19_app/tui/screens_directionb.py \
      s19_app/tui/app.py tests/test_tui_patch_glyphs.py
All checks passed!
```

**Full suite — ONE complete run (C-19), against a frozen tree:**

```
$ python -m pytest -q -m "not slow"
1487 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning in 1069.36s (0:17:49)
$ grep -cE "^FAILED|^ERROR" full5.out
0
```

**0 failed. 0 regressions.**

⚠ **Two earlier runs were KILLED and are not reported as measurements — declared, not quietly
dropped.**
- **Run A** — I edited `app.py` (a comment) **while it was in flight**. A count from a run whose
  inputs changed underneath it is not a measurement of the shipped tree. Exactly the Inc-2 §4.9
  trap, walked into again; killed at ~43%.
- **Run B** — killed at ~43% **on purpose**, because §4.8 found a node-id mismatch and renaming
  a test would have invalidated it. Better to spend one run than to report a stale one.
- **Run C (above)** is the clean one: the source/test tree was verified frozen before it started
  and again after it finished (only `.dev-flow/` markdown moved, which pytest does not collect).

**Reconciliation — EXACT, against Inc-2's measured base:**

| | collected | passed | skipped | xfailed |
|---|---|---|---|---|
| base `b8d9ce3` (Inc-2, measured) | 1482 | 1475 | 2 | 5 |
| branch (Inc-3) | **1494** | **1487** | 2 | **5** |
| delta | **+12** | **+12** | 0 | **0** |

1487 + 2 + 5 = **1494** ✓. **+12 collected == exactly my 12 new nodes**, and **+12 passed** — so
no existing test changed state. **xfail is UNCHANGED at 5**: this increment marked nothing and
un-marked nothing, which is precisely the §4.4 C-22 prediction. Nothing else moved.

---

## 5. Risks

| # | Risk | Sev | Disposition |
|---|---|---|---|
| **R-3-1** ⚠ | **The stamp alone did not deliver BL-4** — the table kept painting the stale image's verdicts (§1 BLUF-2, M-7) | **high** | **CLOSED** — fifth `refresh_entries` at the load seam; M-7 mutation-verified. **The durable lesson: a "provenance stamp" is a MODEL-side fix; a requirement about what the analyst SEES also needs a render trigger, and LLR-077.5 reasoned only about the sites that already refresh** |
| **R-3-2** ⚠ | **My unguarded `query_one` broke 2 existing tests** (§4.7) | **high** | **CLOSED** — house-idiom tolerance + `try/else`; both green. Found by the census, NOT by mutation testing — the two are not substitutes |
| **R-3-3** ⚠ | **Three of my own ledger claims were false** (M-1 / M-4b / M-6, §4.3) | med | **CLOSED** — every mutation re-run and the ledger rewritten to the measured output; M-7 additionally re-measured against the final shipped shape |
| R-3-4 | Positional off-by-one — the silent-mislabel class (spec R5) | high | **CLOSED by measurement** — 3 nets (AT-077d asymmetric-4, TC-077.1 colliding-address, AT-077a), all RED under M-4 |
| R-3-5 | 01b's AT-077d fixture is blind to a reversal | med | **Fixed here** (asymmetric fixture, M-4b evidence); **reported for 01b correction** (pending 1). The spec's obligation is over-, not under-, delivered |
| R-3-6 | Over-invalidation on a MAC/A2L attach | low | **Deliberate + recorded in-line.** Over-refusal → `·` (honest); under-refusal → a lie. Narrowing needs the exact inference that produced BL-4 |
| R-3-7 | `_GLYPH_STYLE` / `_CHECK_RESULT_GLYPH` drift (two modules, four chars) | low | **CLOSED mechanically** — TC-077.3's totality clause; M-6 RED. C-7 is why they are split at all |
| R-3-8 | The 5th call site widens the load path's blast radius | med | **Held** — the full suite (§4.11) is the real census for it and is green; it is a render call over data already held, applying nothing. It also refreshes each row's containment `status_text`, which was stale-until-next-action **before** this batch — a strict improvement, not a behaviour change |
| R-3-9 | A test node id that reads right but does not RUN under 01b's command | low | **CLOSED** — §4.8; found by executing 01b's commands verbatim rather than reading them. One real mismatch (`TC-077.2`), renamed; 9/9 now resolve |

---

## 6. Pending items

1. **01b correction — AT-077d's fixture** (§4.3 M-4b): the prescribed 3-entry middle-fails shape
   is a palindrome and PASSES a glyph-list reversal. Not edited from here (01b is the
   qa-reviewer's artifact).
2. **`01-requirements.md` LLR-077.2 / 01b AT-077e — the bump site** (D-1): both name
   `_apply_loaded_file`, which is the **synchronous wrapper only**; the async worker path
   bypasses it. The correct site is `_apply_prepared_load`. Not edited from here.
3. **`01-requirements.md` LLR-077.5 — the "correct at all four by construction" claim** (D-2):
   true for the signature, incomplete for the image axis. A fifth (render-only) site is
   required. Not edited from here.
4. **`01b` AT-077c arm (c) ingress** (D-3): `#patch_entry_edit_json_button` is disabled for the
   file-backed fixture it is prescribed against; `#patch_entry_edit_button` is used.
5. **Snapshot regen follow-up PR** (canonical CI, batch end) — still exactly the 2 patch cells;
   this increment added **0**.
6. **Inc-2 pendings 1/2/4 carry unchanged** (PLAN.md's 21-buttons/8-roots recon correction ·
   §6.5 Amendment A's stale "Deleted — none" line · Inc-1's items + the batch-47
   `sensor[unclosed` false-counterfactual carry + Inc-1b's `OptionList` sweep).

---

## 7. Suggested next task

**Inc-4 — HLR-078, the CHECKS pass/fail strip** (`change_service.check_aggregates()` accessor +
an extended `refresh_check_results` + a NEW strip Static in `#patch_win_checks_body`), per the
US-P1 → {P2,P3,P4,P6} → P5 order. It reuses this increment's glyph vocabulary for its
`✓P · ✗F · ◐U` counts, and `microbar(floor=False)` (batch-47: `floor=True` is only for bars
meaning *"this exists"*; a proportional bar stays unfloored). Watch the **A3 zero-total
boundary** (AT-078b) and note that the strip's clear-on-undo arm rides `last_check_result`'s
existing reset — **not** this increment's stamp.

---

## Evidence checklist

- [x] **BL-3 free signal CLEAN** — `git diff main -- tests/test_tui_patch_editor_v2.py` = **0 lines**; the file also passes **unmodified** in the census (§4.1, §4.5)
- [x] **Index alignment evidenced** — 3 independent nets, all RED under M-4; TC-077.1's colliding-address premise **re-verified against the real ingress** rather than assumed away (§4.2)
- [x] **BL-4 provenance stamp** — `(document_signature, image_generation)`; M-1 + M-7 both RED; `id(mem_map)` absent from code (§4.3, §4.6)
- [x] **Tests/lint pass** — full suite **1487 passed / 0 failed / 2 skipped / 5 xfailed** from **ONE clean run** against a verified-frozen tree (§4.11; two earlier runs killed and **declared**, not dropped); `test_tui_patch_glyphs.py` **12 passed**; C-26 census **333 passed / 0 failed** across 19 files in ONE invocation; snapshots **0 FAILED**, 2 marked cells only; ruff **All checks passed!** on all 4 files
- [x] **RED mutation-verified on every new oracle** — **7 mutations**, each applied/run/read/reverted; M-7 re-measured against the final shipped shape (§4.3)
- [x] **No secrets** — no `.env`, key, or token read or printed; fixtures synthetic
- [x] **No destructive commands** — read-only + in-worktree edits; every mutation reverted and re-verified green; no branch switch, **no local snapshot regen**, no commit, no push
- [x] **File count within cap** — **4** of 5 (3 modified + 1 new)
- [x] **C-27 dual-guard: 0 frozen diff** — all three arms (§4.9)
- [x] **C-18 node paths verified by EXECUTION** — 01b's 9 executed-verification commands run verbatim, 9/9 resolve and pass; one real id mismatch found and fixed (§4.8)
- [x] **C-26 census run + reported** — §4.5, censused on touched symbols; the seed table's blast radius **stated as too small** for the new load seam, with the full suite named as the real census
- [x] **C-22 per-cell drift predicted + MEASURED** — §4.4; 0 new cells; `test_tui_snapshot.py` untouched
- [x] **Uncertainty surfaced, not hidden** — **R-3-1/R-3-2/R-3-3 are my own errors**, reported with the runs that caught them; **three deviations declared** (D-1/D-2/D-3), each contradicting a named spec line; **a false comment I wrote was found and corrected** (§4.7); M-4b reports a **spec** defect rather than quietly fixing it; the map-placement choice is explained as a **non-deviation** rather than inflated
