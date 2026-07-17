# Increment 07 — batch-48 · Patch Editor BIG · the live before/after card (R-TUI-080 / HLR-080) — the HEADLINE

**Status: COMPLETE.** 4 code/test files + this record (**5 of 5, cap held**). Scope US-P5 / HLR-080 —
LLR-080.1 (the card widget) · 080.2 (`mem_map` threaded, sentinel-retain) · 080.3 (before/after derivation,
positional) · 080.4 (no-image / no-selection) · 080.5 (read-only) · 080.6 (C-29 geometry / B2) · 080.7 (C-17
mechanical gate). This is the last story of Batch B.

⚠ **The brief's HLR id was RIGHT this time (HLR-080 = the card).** Verified against `01-requirements.md:291`
before starting — `:733` records that this id clash misfired twice, so I checked rather than trusted.

---

## 0. Tree-clean verification + measured baseline

- **Tree at start:** clean, `f856934` on `feat/batch-48-patch-big`. Verified with `git status --porcelain`
  (empty) before any edit.
- **Baseline — MEASURED, not derived** (`-m "not slow"`, the REDUCED variant, `-p no:randomly`):
  ```
  1514 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning in 940.88s (0:15:40)
  ```
  Exactly Inc-6's reference figure; the 2 "mismatched snapshots" are the expected `xfail` patch cells. I waited
  ~57 min of confusion for this (see §11) rather than deriving it, per the standing rule.

---

## 1. What changed

**`ChangeEntryRow` gains two RAW-int fields (`change_service.py`)** — `address: int = 0` and
`encoded_bytes: Tuple[int, ...] = ()`, set in `rows()` from `entry.address` / `entry.encoded_bytes`. The card
needs the ints: `address_text` is `0x`-formatted and `value_text` is an ELIDED preview (`.. (N bytes)`), so
neither can reconstruct the span. **D-5 seam:** these ride the ROW (per-entry data `rows()` already holds),
free at every call site — the `check_glyph` precedent. `mem_map` (per-IMAGE, needed at selection time) cannot
and is threaded separately.

**`BeforeAfterCard(Static)` + `before_after_card_text(...)` (NEW, `screens_directionb.py`)** — a read-only card
mounted INSIDE `#patch_win_script_body`, directly under the entries table. The builder is a **pure module
function**: it reads no widget/service/app, returns a `Text`, and touches nothing (LLR-080.5). Selecting an
entry row shows the image's bytes at that entry's span beside the bytes the entry would write; **differing
positions are brightened.**

**The `refresh_entries` seam (`screens_directionb.py`)** — gains `mem_map: Union[Mapping[int, int], None,
_Unset] = _UNSET`. Sentinel default ⇒ **preserve** the retained map; explicit `None` ⇒ **clear** ("no image");
a mapping ⇒ replace. Retains `mem_map` + the row list; re-renders the card. `Mapping` (not `Dict`) keeps the
parameter read-only by type.

**`on_data_table_row_highlighted` + `_render_before_after_card` (`screens_directionb.py`)** — highlight drives
the card (the `A2LDetailCard` precedent: live read-out, no commit keystroke). The join is **POSITIONAL** — the
cursor row index IS the document-order index — never address-matched.

**All FIVE `refresh_entries` sites wired (`app.py`)** — see §2.

**No new colour.** Differing byte = `VALUE` (bright — "the datum a label describes"); identical = `DGRAY`
(secondary). Those two constants' documented meaning already IS "matters" vs "context", so the diff cue adds
**zero** new claimants inside `#patch_editor_panel`. GREEN/YELLOW/RED stay verdict-reserved (Inc-2b ruling);
MAGENTA is scoped to budget/capacity and its hue is a measured optimum against a census, so a second claimant
would invalidate that measurement — the restraint is load-bearing, not stylistic.

## 2. ★ The writer census, DONE BEFORE CODE — and it found a real defect the spec's census would ship

**The spec's Phase-2 census (`01-requirements.md` §6.4 / `01b` MJ-1) names FOUR `refresh_entries` sites. The
live tree has FIVE.** I counted the tree directly (C-15.1, before writing any card code):

| # | Site | In Phase-2 census? | Supplies `mem_map`? |
|---|---|---|---|
| 1 | `app.py:2064` (action handler) | ✓ | yes (`mem_map` bound at `:1953`, same scope — verified) |
| 2 | `app.py:2282` (history/refresh) | ✓ | yes |
| 3 | `app.py:3928` (change-file load) | ✓ | yes |
| 4 | **`app.py:8056`** (image-install point) | **MISSED** | **yes** |
| 5 | `screens_directionb.py:3393` (`on_mount` self-call) | ✓ | **no** → sentinel-preserve |

**Site 4 is the only LOAD-triggered site, so it is the one the card most depends on** — a new image means new
before-bytes. Under sentinel-preserve, omitting it leaves the card holding the PREVIOUS image's map and painting
stale before-bytes — the exact BL-4 staleness defect this site was created to fix (the glyph half), one seam
over. **MJ-1's shape, third sighting this batch.**

**⚠ CORRECTION to my own first reading — recorded because attaching a false charge to a teammate weakens the
finding.** I first wrote that Inc-3's comment at `app.py:8011` (*"the four existing `refresh_entries` sites"*)
*"described four while adding a fifth."* **That is wrong, and I withdraw it.** Read in context, *"the four
EXISTING sites"* names the four that pre-dated Inc-3 and explains why a fifth was needed — an accurate
description of the pre-existing set. **Inc-3 documented its addition honestly.** The stale artifact is the
**Phase-2 census**, which asserts four and has no edge binding it to the code, so Inc-3's correct addition could
not update it. **Nobody miscounted; the census simply had no code↔requirement edge.** That is the operator's
traceability candidate and the "input set is itself an oracle" candidate arriving from a third direction.

**The census test is DERIVED, not hand-listed** (`test_writer_census_every_app_site_pushes_mem_map`). A
hand-list of "these 5 sites" would reproduce the very defect I found — a census with nothing binding it to the
code, silently blind to a sixth site. So the test walks `app.py`'s AST for every `.refresh_entries` call and
asserts each passes `mem_map`, guarded against a vacuous empty set. M-4 proves it: dropping `mem_map` from site
4 fails HERE with `app.py:8054` named — the edge the Phase-2 census lacked.

## 3. ★ Index-alignment — proven with the same-address fixture

**The join is positional; an off-by-one previews the WRONG entry's bytes, the worst failure here.** Two tests:

- **AT-080a** selects row index **1** (never 0) and asserts the card shows THAT entry's bytes AND that row 0's
  bytes (`DE AD`) do NOT leak. An off-by-one previewing entry 0 fails the leak clause.
- **AT-080a same-address** (`test_at080a_same_address_entries_are_index_joined`) — **two entries at 0x300 with
  DIFFERENT content** (`11 11` vs `22 22`). An address-keyed join structurally CANNOT pass: both key to 0x300,
  so it returns one entry for both rows. The Inc-3 TC-077.1 precedent, reused because it is the one fixture that
  makes the wrong implementation FAIL rather than merely be unproven. **M-1 confirms:** replacing the index join
  with `{r.address: r ...}[address]` fails ONLY this test — AT-080a (distinct addresses) passed the mutation.

## 4. ★ C-29 — measured with the card mounted, both axes, both sizes; cross-check FIRST

**Cross-check against the house record (reported first, per the brief):** my rig independently reproduced
Inc-6's recorded `patch_history_controls` content `64×1` and the enabled history strip painted `h=2` at 80×24.
The rig agrees with the house record, so its numbers are trustworthy.

**Measured (`#patch_win_script_body` + the card + every docked row, card mounted, row selected):**

| regime | body content | **card content (the real budget)** | card region | widest painted line | B2 trapped | B2 unreachable |
|---|---|---|---|---|---|---|
| **80×24** | 64×42 | **62** | 64×4 | 19 | `[]` | `[]` |
| **120×30** | 38×42 | **36** ← binding | 38×4 | 19 | `[]` | `[]` |

- **B2 does NOT recur — MEASURED, not asserted.** All 17 named buttons reachable-under-scroll at both regimes,
  WITH the card mounted, AFTER Inc-6's extra docked row. So **AT-080d takes FORM 1** (no relaxation) and **no
  §6.5 amendment is owed.** The hypothesis held: the card mounts inside the scrollable body, so it costs SCROLL;
  the docked rows are siblings of the body (batch-46's B2 fix), so the card structurally cannot push a button
  below the fold. AT-080d asserts the card is mounted AND non-zero-area, so it cannot pass by the card vanishing.
- **⚠ The C-29 trap bit even here, 2 cells deep.** The card's real budget is **36**, not the body's 38 — the
  card's own `padding: 0 1` costs 2. Had I inherited Inc-6's measured 38 (a CORRECT figure, for the docked
  strip), I'd have been wrong by exactly the padding of the container I'm actually in. Same class as the errors
  handed to Inc-4/Inc-6, one scale smaller. The measured table is recorded in `CARD_BYTES_MAX`'s docstring;
  TC-080.6 asserts the painted width against the measured container at both regimes.
- **Widest content is 19 (`before  AA BB CC DD`); worst-case reachable header is 34** (`0xFFFFFFFF · 65536
  bytes (first 8)`) — both clear the binding 36. TC-080.6 exercises the worst case, not a comfortable one.

## 5. ★ C-17 — the mechanical grep result (LLR-080.7 / MJ-7)

**RESULT: CLEAN. N/A HOLDS. `AT-080e` is NOT owed.** The card builder's entire input set is `int` /
`Optional[int]` / `Sequence[int]` / `Sequence[Optional[int]]` — no `str`, no non-int. And
`_render_before_after_card` reads only `row.address` / `row.encoded_bytes` (both int) — **zero** file-derived
row attributes (`kind_text`/`value_text`/`status_text`/`linkage_text`/`address_text`).

This was a **design constraint, not just a check**: LLR-080.7 predicts *"a card header naming its entry is the
natural design"*, and it is — but naming the entry would void the N/A and cost a gate-blocking `AT-080e`. So the
card shows **address + before-bytes + after-bytes + author-fixed labels only**, keeping the N/A honest rather
than argued. Two AST-walked tests enforce it (`test_tc080_7_card_inputs_are_ints` on the builder signature;
`test_tc080_7_card_renders_no_file_derived_row_text` on the caller path). **M-5 confirms:** adding
`_ = row.value_text` to the card path fails the caller-path gate on `value_text` — the check that converts to a
gate-stop + `AT-080e` the moment someone adds the natural header.

## 6. Files

| File | State |
|---|---|
| `s19_app/tui/services/change_service.py` | M — `ChangeEntryRow.address`/`.encoded_bytes` + `rows()` sets them |
| `s19_app/tui/screens_directionb.py` | M — `BeforeAfterCard` + `before_after_card_text` + `_Unset`/`_UNSET` + card mount + `refresh_entries(mem_map=…)` retain + `on_data_table_row_highlighted` + `_render_before_after_card` + panel state |
| `s19_app/tui/app.py` | M — 4 `refresh_entries` sites push `mem_map` (site 5 is the panel self-call, correctly unwired) |
| `tests/test_tui_patch_card.py` | **NEW** — AT-080a/b/c/d + TC-080.1/.2/.2a/.3/.3b/.4/.5/.6/.7 + writer census (AST-derived) |
| `.dev-flow/…/increment-07.md` | Mandated — this record |

**5 of 5. No 6th file taken.** `styles.tcss` NOT needed — the card's geometry rides `DEFAULT_CSS` on the widget
(the `A2LDetailCard` precedent), so no app-wide CSS claim (C-30 stays N/A). `REQUIREMENTS.md` NOT touched — no
locked requirement is amended (AT-080d Form 1, no relaxation). `test_tui_patch_layout.py`'s `_MUST_PRESERVE_IDS`
NOT touched — the card id is ADDED, the 48 preserved ids untouched.

## 7. Test results — invocation NAMED, pasted verbatim

**Reduced suite: `python -m pytest -q -m "not slow" -p no:randomly`** — the REDUCED variant, per the brief.
`pytest -q` unfiltered is the FULL suite and was **NOT** run (it takes >1h here; CI owns it pre-merge).

```
27 snapshots passed. / 2 mismatched snapshots (the batch-48 xfail patch cells)
1540 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning in 1129.09s (0:18:49)
EXIT=0
```

Baseline was **1514** → **+26 = the new card tests, 0 failed.** `xfailed` steady at **5** (no pre-existing
mark flipped, none added); `27 snapshots passed`, the 2 "mismatched" are the marked `xfail` patch cells the
card repaints (C-22, they ABSORB — not evidence). ⚠ **This is the REDUCED suite** (`-m "not slow"`, 20
deselected). The full unfiltered suite is CI's job and was not run here.

**New file alone:** `26 passed` (`tests/test_tui_patch_card.py`).

**Smoke (affected suites, before the full gate):** `117 passed` across `test_tui_patch_layout.py`,
`test_tui_patch_editor_v2.py`, `test_change_service.py`, `test_tui_patch_history_strip.py`,
`test_tui_patch_big.py`.

**ruff — clean on all 4 touched code/test files:**
```
All checks passed!
```
`a2l.py:926` F841 remains the known **frozen** carry — not mine, unfixable while `a2l.py` is engine-frozen.

**C-27 dual-guard — raw frozen diff vs `main` = EMPTY:**
```
$ git diff main --stat -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
    s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```

**C-22 snapshot disposition:** the 2 `patch-comfortable-{80x24,120x30}` cells ride
`_batch48_patch_drift_marks` (`xfail(strict=False)`, from Inc-1) and **ABSORB** the card's repaint — **their
passing is NOT evidence.** Containment argued: every change is inside `#patch_editor_panel`; no CSS rule added
to `styles.tcss` (the card's CSS is `DEFAULT_CSS` on the widget); no App-level `Binding` changed. `xfail` count
unmoved at 5 ⇒ no unmarked cell drifted, no pre-existing mark flipped. **Regen = canonical CI, post-merge.
NEVER local.**

## 8. ★ MUTATION LEDGER — applied to the tree, RUN, output READ, reverted by INVERSE EDIT

**7 mutations, 7 REDs, every prediction held.** Each reverted by exact inverse edit; `grep MUTATION` over all
touched files = 0 after reverts; card suite green post-revert (`26 passed`).

| # | Mutation | Predicted | Measured |
|---|---|---|---|
| M-1 | index join → address join (`{r.address: r}[address]`) | RED on same-address only | **RED** — `test_at080a_same_address…` only; AT-080a (distinct addrs) PASSED. Proves the same-address fixture is load-bearing |
| M-2 | `mem_map.get(addr, 0)` (fabricate zero) | RED on unmapped | **RED** — AT-080c: card painted `AA BB 00 00`, inventing 2 bytes |
| M-3 | unconditional retain (`None if _Unset else mem_map`) | RED on retain semantics | **RED** — both TC-080.2a arms, incl. the real-`on_mount` drive (the MJ-1 defect itself) |
| M-4 | drop `mem_map` from site 4 (the census-missed site) | RED on census | **RED** — writer census names `app.py:8054`. The edge the Phase-2 census lacked |
| M-5 | `_ = row.value_text` reaches the card path | RED on C-17 gate | **RED** — caller-path gate on `value_text`. The gate has teeth |
| M-6 | `display: none` on the card CSS | RED on geometry | **RED** — 4 tests (both AT-080d + both TC-080.6). ⚠ **the 22 CONTENT tests all PASSED** — Inc-4's F2 reproduced exactly: content oracles are blind to visibility; only the geometry arm catches an invisible card |
| M-7 | delete `encoded_bytes` from the REAL dataclass (stub keeps it) | RED on input-set oracle | **RED** — TC-080.3b (stub↔dataclass bind). The Inc-5b HIGH-1 class code-mutation cannot reach |

## 9. Risks

- **The card re-renders on every `refresh_entries` and every row highlight.** It reads at most `CARD_BYTES_MAX`
  (8) `mem_map.get` calls per render — O(1), no scan of the sparse map. Not a perf concern.
- **`on_data_table_row_highlighted` does NOT stop the event.** `S19TuiApp.on_data_table_row_highlighted` also
  listens (for the A2L card) and filters by table id, so bubbling costs nothing; stopping it would couple this
  panel to that handler. If a future handler assumes it owns the event, this is where to look — loud, not silent
  (both filter by id).
- **The card's `max-height: 4` is a CSS constant, not a measured `fr`.** It is asserted-against (TC-080.6 reads
  the painted region), so a layout move fails loud with the real height rather than silently clipping.
- **Sentinel-preserve depends on the panel state surviving between calls.** It does (instance attr); a future
  refactor that reconstructs the panel per action would lose the retained map — but that would also lose every
  other retained field (`_active_variant`, `_execute_scope`), so it is not a card-specific risk.

## 10. Pending items

1. **Batch-48 canonical-CI snapshot regen** (post-merge follow-up) — the 2 patch cells' repaint (now including
   the card) must be baked into the SVG baselines and the `_batch48_patch_drift_marks` xfail RETIRED, per the
   `_batch45/46/47` pattern. **NEVER local.**
2. **No §6.5 amendment owed** — AT-080d took Form 1; no locked requirement changed.
3. **LLR-080.2's "four call sites" is now FALSE (there are FIVE)** — same class as Inc-6's LLR-081.3 "three
   sites". Whether erratum or amendment is the orchestrator's call; the code and the AST-derived census test
   both say five, and the test fails loud if a sixth appears.
4. **Batch B is COMPLETE** — US-P5 was the last story. Batch-48 closeout: delete `prototypes/screen_upgrades.*`
   + `prototypes/out/` (handoff §10.4, absorb-then-delete), now that all six stories have shipped.

## 11. ★ My own errors this increment — all disclosed

1. **I misread `ps -W` columns** and named PID 45318 (a cygwin PID) as my running pytest. It was an unrelated
   job's `runfixed.py`. A PID's EXISTENCE was never evidence; the COMMAND LINE is. I'd asserted liveness from an
   unvalidated proxy — the same shape as asserting an unmeasured geometry budget. Corrected by reading the
   actual command lines (`Win32_Process`), which showed my pytest was PID 18632, healthy, ~10 min in.
2. **I nearly killed an unrelated process.** The "57-min/98%-CPU" alarm was a real measurement bound to the
   WRONG process — job `5a3412e4`'s `runfixed.py` (a Textual bpytop clone with an `asyncio.sleep(0.05)`
   spin-wait over `app.workers`). Not mine, not pytest. Had I followed "kill the full-suite run", I'd have swept
   up an unrelated job — the exact failure the brief warns about. Flagging separately: that spin-wait is a
   genuine bug and had run ~1h, but it is job `5a3412e4`'s, out of this batch's scope.
3. **My measurement rig used `Static.renderable`** (does not exist — Inc-5 recorded this exact accessor trap).
   Fixed to `.render()`. The rig's cross-check arm against the house record (§4) is what let me trust the fixed
   rig.
4. **My TC-080.1 first draft used the WRONG oracle** (`vars(card) & dir(Widget)`). MEASURED: it returns the
   IDENTICAL 12 names for the shipped `A2LDetailCard` — all metaclass-injected, none authored. Filtering to
   private names would have been vacuous (the card authors none). Anchored the threshold to what the app already
   demonstrates: the card may collide only where a shipped, booting widget already collides. Caught by the test
   failing on its first run.
5. **A stray `</content>` tag** from my Write broke collection once (SyntaxError). Removed; re-ran.

Measurement or a first test run caught every one. Recorded because every increment this batch disclosed its
errors and every packet was stronger for it.

---

## Evidence checklist

- [✓] **Tests/type checks/lint pass** — reduced suite (`-m "not slow"`) result in §7 (pasted verbatim); new file
  `26 passed`; smoke `117 passed`; ruff clean on all 4 files (`a2l.py:926` = known frozen carry). ⚠ The full
  (unfiltered) suite was NOT run (>1h; CI owns it) — stated, not claimed. Baseline was MEASURED (§0).
- [✓] **No secrets** — synthetic addresses / byte literals only.
- [✓] **No destructive commands** — no `git checkout`/`stash`/`reset`; every mutation reverted by inverse edit;
  no process killed (§11 discloses the one I nearly, wrongly, would have).
- [✓] **File count within cap** — **5 of 5**. `styles.tcss`, `REQUIREMENTS.md`, `_MUST_PRESERVE_IDS` each
  considered and shown unnecessary.
- [✓] **Review packet attached** — in-conversation + this record.
