# Phase-2 Review — qa-reviewer — batch 2026-07-30-batch-72

> Reviewer: `qa-reviewer` · Artifact under review: `.dev-flow/2026-07-30-batch-72/01-requirements.md`
> (Phase-1 approved draft). Scope: **testability of each requirement and viability of the chosen
> validation method**. Every finding below cites executed command output or `file:line`. Claims I
> could not execute are labelled `UNVERIFIED`.

## BLUF

**Verdict: 5 blockers / 5 majors / 4 minors — ITERATE back to Phase 1.** The story choices are
sound and the CRC/Legend defects are real (I measured both). The *acceptance layer* is not.

The single worst finding: **AT-214 (G-1) cannot be authored as written, in either reading.** I ran
the derivation the requirement implies — walk `#crc_designer_panel`, filter `can_focus`, sort by
`region.y`, compute abutment — and got **16 vertically-abutting focusable pairs on the shipped
screen**. Exactly **one** is the refin/refout pair this batch fixes. Under the geometric reading
the AT stays RED after a perfect implementation (15 innocent pairs still abut); under the
"interleaved label" reading it is **already GREEN today** (both shipped switch rows carry
`Label("Reflect in")` / `Label("Reflect out")`), so it is invariant under the change it gates —
a textbook **C-40 limb-1** failure. G-1 must be re-scoped to *same-widget-type* adjacency before
any AT is written against it.

Second: **AT-216's oracle is vacuous twice over.** The literal `Pale yellow` is real
(`legend.py:142`) — not a phantom — but the **first** widget matching it is a *card* caption
(`"Orange vs Pale yellow — two paint pipelines, one severity"`), i.e. the widget in the pane the
assertion is supposed to be looking *away* from. And the harness the shipped legend tests use,
`render().plain`, is geometry-blind: I proved that **today**, with the key row at
`Region(x=22, y=27)` entirely outside `body.region=Region(22, 6, 76, 15)`, that harness still
returns `"Pale yellow" in text == True`. The clause AT-216 exists to certify — *without
scrolling* — is exactly the clause that harness cannot see.

Third, mechanically: **the test ledger base is stale.** `pytest --collect-only -q` reads **2379**,
not the 2358 in §Test ledger. A wrong base corrupts `post = base − D + A` at every later gate.

Good news, so the iterate is narrow: AT-217 is the healthiest AT in the set and needs only a
scroll-vs-visible clarification; AT-213 and AT-215 are both *reachable* and I have named the exact
values that make them go RED; C-27 is clear; the ID census is clean; and premise P-2/P-3
(no snapshot capture) re-verified TRUE.

---

## Findings

### Q-1 AT-214 (G-1) is unauthorable as written — the rule is false of 15 out-of-scope pairs, or invariant under the change — blocker

**Claim.** HLR-072-3's G-1 ("for every pair of vertically-adjacent focusable controls in the CRC
form, their regions do not abut without a ≥1-row gap, border, or interleaved label") admits two
readings, and **both** break the AT.

**Evidence.** Executed pilot probe at `size=(120,30)`, driving the shipped surface via key `0`
(scratchpad `probe_at214.py`). Derived set = `#crc_designer_panel` → `query("*")` → `can_focus` →
sorted by `region.y` → pairs where `a.y + a.height == b.y` and the x-bands overlap:

```
vertically-ABUTTING focusable pairs (gap == 0): 16
    ('crc_preset_select', 'crc_field_width')       ('crc_coverage_pad_byte', 'crc_coverage_on_gap_conflict')
    ('crc_coverage_ranges', 'crc_coverage_intra_gap')   ('crc_field_refin', 'crc_field_refout')   <-- the ONLY in-scope pair
    ('crc_custom_vector_mode', 'crc_custom_vector')     ('crc_field_name', 'crc_field_aliases')
    ('crc_coverage_intra_gap', 'crc_coverage_join')     ('crc_field_refout', 'crc_field_xorout')
    ('crc_coverage_join', 'crc_coverage_pad_byte')      ('crc_field_xorout', 'crc_field_check')
    ('crc_field_width', 'crc_field_poly')               ('crc_load_path', 'crc_load_btn')
    ('crc_field_poly', 'crc_field_init')                ('crc_field_output_address', 'crc_field_store_width')
    ('crc_field_init', 'crc_field_refin')               ('crc_field_store_width', 'crc_field_store_endianness')

Switch rows: [(y=32, x=39, h=1, w=8, 'Switch', 'crc_field_refin'),
              (y=33, x=39, h=1, w=8, 'Switch', 'crc_field_refout')]
```

- **Geometric reading** ("regions do not abut"): 15 of the 16 pairs are `Input`↔`Input`,
  `Input`↔`Select`, `Select`↔`Select`, `Input`↔`Button` — all shipped, all abutting at gap 0, none
  in this batch's scope. After a *perfect* pair-row implementation, refin/refout leave the derived
  set entirely (same `region.y` ⇒ not vertically adjacent), leaving **15 abutting pairs and a RED
  AT**. The only way to green it is a hand-carved exception list — which reintroduces precisely the
  hand-listed input set **C-31** forbids and makes the AT vacuous by construction.
- **"Interleaved label" reading**: `crc_designer_view.py:465-469` — `_switch_row` already returns
  `Horizontal(Label(label, classes="crc-field-label"), Switch(...))`. Both shipped switch rows
  carry a distinct label today (`:301-302`, `"Reflect in"` / `"Reflect out"`). So the disjunct is
  **already satisfied pre-batch** and the predicate **cannot go RED** — C-40 limb 1: the declared
  subject (the fused switch pair) is not discriminated by the expression.

**Impact.** P-9 is currently `❓ UNDECIDABLE` and this review resolves it **❌ FALSE as scoped**:
the guard is not encodable against the stated rule. Writing AT-214 to the current text guarantees
either a permanently-RED gate or a permanently-GREEN non-gate. Phase 3 would discover this
mid-increment, which is the expensive place to discover it.

**Proposed disposition.** Re-scope G-1 at Phase 1 to the defect actually being fixed — *no two
vertically-adjacent focusable controls **of the same widget class** abut without an interleaved
widget between them*. Executed against the same derived set, that rule has exactly **one**
violating pair today (`crc_field_refin`/`crc_field_refout`; every other abutting pair is a
mixed-class pair or `Input`↔`Input` in distinct labelled rows — confirm the `Input`↔`Input` count
at authoring and, if non-zero, tighten to *same class AND same `.crc-field-row` sibling group*).
Keep the set **derived**, never hand-listed (C-31): the census must come from
`panel.query("*")`/`can_focus`, and the AT must assert the derived set is non-empty so a broken
walk cannot pass vacuously.

---

### Q-2 AT-214's RED counterfactual is physically runnable, but has two wrong-reason failure modes — major

**Claim.** The counterfactual is runnable; the risk is that it goes RED for a reason unrelated to
the CSS.

**Evidence.** The mutation target is a 4-line rule:

```
s19_app/tui/styles.tcss:1952-1955
.crc-field-switch {
    border: none;
    height: 1;
}
```

`.crc-field-switch` is a **tracked** file, so the C-40 discharge ritual applies in its tracked form
(not the untracked move-aside variant). Concretely, and without touching the working tree any other
session reads:

```bash
git worktree add /tmp/b72-cf HEAD          # a private copy of the FIXED tree
# in the copy ONLY: restore the pre-batch rule + revert compose to two _switch_row calls
git -C /tmp/b72-cf checkout origin/main -- s19_app/tui/styles.tcss s19_app/tui/crc_designer_view.py
python -m pytest /tmp/b72-cf/tests/test_crc_designer_view.py -k at214   # expect RED, paste transcript
git worktree remove /tmp/b72-cf
```

**Impact.** Two ways the RED is worthless:
1. **The AT errors instead of asserting.** If the counterfactual reverts `crc_designer_view.py`
   wholesale, the new pair-row container id will not exist and the test dies on `NoMatches` — an
   *error*, not a failed assertion. Per the project's counterfactual rule (memory:
   `feedback_counterfactual_must_fail_on_its_assertion`), a test that errors on the old tree proves
   nothing. Revert **only** the CSS rule and keep the new compose, or assert on ids that exist in
   both trees.
2. **Reverting only `styles.tcss` may not move the geometry at all.** The fusion the story blames on
   CSS is at least partly a *compose* fact: the two switches are two separate `Horizontal` rows
   (`:301-302`), which is why they land at `y=32` and `y=33`. Removing `border: none; height: 1`
   makes each switch taller — it does not un-stack them. So the CSS-only counterfactual may go
   GREEN under the geometric reading. **Measure which artifact actually owns the observable before
   declaring the counterfactual target**, and state it in the AT.

**Proposed disposition.** Name the counterfactual artifact explicitly in §5.3 (CSS rule *and/or*
the two-`_switch_row` compose), and add the acceptance clause: *the counterfactual must fail on the
AT's own assertion line, not on a query error* — evidenced by the pasted transcript showing an
`assert` failure.

---

### Q-3 AT-217 (floor stacking, key first) is falsifiable and is the healthiest AT in the set — minor

**Claim.** `region.y` comparison at 80x24 is a sound, falsifiable oracle. It needs one clarification.

**Evidence.** Measured on the shipped single-pane legend (scratchpad `probe_legend.py`,
`size=(80,24)`, mac view):

```
dialog region: Region(x=13, y=2, width=54, height=19)
body region:   Region(x=16, y=6, width=48, height=9)
container_size: Size(width=48, height=9)   virtual_size: Size(width=46, height=49)   max_scroll_y: 40
first card row   (legend-card-sub)  y=7
first key row    (legend-artifact)  y=43
```

Today card `y=7` < key `y=43`, so `key.y < card.y` is **FALSE** → the assertion is RED pre-batch.
It goes RED again if the narrow stacking rule fails to apply and the panes stay side-by-side (both
panes share a `region.y` ⇒ `<` is false). It is GREEN only when the panes actually stack key-first.
Falsifiable in both directions — C-40 both limbs discharged.

**Impact.** Low, but one trap: **the key does not fit the floor budget**, so "both reachable" must
stay *reachable-under-scroll* and must not silently harden into *visible*. Measured floor content
budget is **9 rows** (`container_size.height=9`) while the MAC key alone occupies 11 rows
(`y=43..53`, heights `1,3,3,1,2,2`). Per project **C-29** this is the exact shape that produced a
physically-impossible AT in batch-46.

**Proposed disposition.** Keep AT-217 as written; add the explicit words *reachable under scroll,
not required visible* to HLR-072-6, and cite the measured `container_size.height = 9` as the reason.

---

### Q-4 AT-216 — `Pale yellow` is REAL (not a C-36 phantom), but the assertion matches the WRONG pane — blocker

**Claim.** The literal exists verbatim, so this is not a phantom-literal blocker. It is a worse
one: the string is **ambiguous across the two panes the AT is trying to distinguish**.

**Evidence.**

```
$ grep -rn "Pale yellow" s19_app/
s19_app/tui/legend.py:142:        "Pale yellow": (
s19_app/tui/legend.py:143:            "Pale yellow",
s19_app/tui/legend.py:202:    "Pale yellow": ValidationSeverity.WARNING,
s19_app/tui/legend.py:718:            "Orange vs Pale yellow — two paint pipelines, one severity",

$ python -c "from s19_app.tui.legend import LEGEND_TABLE; print(list(LEGEND_TABLE['MAC']))"
['Red', 'Pale yellow', 'Green', 'White', 'Grey']
```

`legend.py:718` is a **card** line — confirmed by executed probe:

```
CARD line, role= sub :: Orange vs Pale yellow — two paint pipelines, one severity
```

and it is the **first** widget my scan matched. So `assert "Pale yellow" in <key-pane text>` written
against anything broader than the key pane's own subtree passes by matching the **card**, which
after this batch lives in the *other* pane. Vacuous.

**Impact.** AT-216 is the only acceptance for HLR-072-5. As written it would go green on an
implementation that renders the key pane empty.

**Proposed disposition.** Anchor the assertion on the key **row widget**, not the string —
e.g. the `Static` carrying classes `{legend-row, sev-warning}` inside the key pane's container id —
and compare its text to `LEGEND_TABLE["MAC"]["Pale yellow"][1]` (the *meaning*, derived from the
data layer, which is what `tests/test_legend_n8.py:356` already does). Derived, not literal.

---

### Q-5 AT-216's visibility clause is invisible to the shipped harness (C-32) — blocker

**Claim.** "shows the row **without scrolling**" cannot be observed by `render()`/`render().plain`,
which is the accessor every shipped legend test uses. An AT written on that harness is vacuous on
exactly the axis it exists to certify.

**Evidence.** Executed (scratchpad `probe_vacuity.py`), mirroring
`tests/test_legend_n8.py:280-286 _legend_body_text`, on the **shipped** single-pane legend at
`size=(120,30)`:

```
=== 'Pale yellow' found by render().plain harness? ===
    True
    row text: 'Orange vs Pale yellow — two paint pipelines, one severity'
=== geometry ===
    body.region          : Region(x=22, y=6, width=76, height=15)
    body.scroll_offset   : Offset(x=0, y=0)
    body.max_scroll_y    : 24
    row.region           : Region(x=22, y=27, width=74, height=1)
    row overlaps body vp : False
    row fully in body vp : False
```

The row is **21 rows below the top of a 15-row viewport, at scroll offset 0** — i.e. exactly the
defect US-072-2 describes — and the content harness reports it as present anyway. Project **C-32**
(`docs/engineering-rules.md:125-140`) is this control verbatim, earned in batch-48 across three
sightings in one batch.

Two supporting traps, both executed:
- **`renderable` is the wrong accessor on textual 8.2.8.** My first probe used
  `str(w.renderable)` and matched **0** widgets while `render().plain` matched them. `Static`
  exposes `.content`; `Widget.visible_region` **does not exist** in this version
  (`hasattr(Widget,'visible_region') → False`; `window_region`, `container_viewport`,
  `scroll_offset` → `True`). A C-42-style false-fail waiting to happen.
- **`run_test(size=(120,30))` yields `screen.size == Size(118, 28)`** under the modal. Do not derive
  expected coordinates from the requested tuple.

**Impact.** Both HLR-072-5 acceptances (this and Q-4) are unsound. The story could ship with the key
pane clipped to zero height and pass.

**Proposed disposition.** Write AT-216's visibility limb as a **region-containment** assertion —
`key_pane.region.contains_region(pale_row.region)` (or `body.region.overlaps(...)` with
`scroll_offset == (0,0)` asserted) — and, per C-32's own discharge clause, **mutate the new oracle**:
set the key pane `display: none` and confirm it goes RED before trusting the green.

---

### Q-6 AT-213 is reachable, but the artifact never names the value — and the default is the OPPOSITE of what the AT implies — major

**Claim.** The C-10 limb is satisfiable and the observable does change. But `refin` defaults to
**True**, not False, and the artifact states neither the direction nor the expected delta.

**Evidence.** The seed is `SEED_ALGORITHM`, not `PRESETS[0]` (`crc_designer_view.py:273`):

```
SEED: CRC-32/ISO-HDLC  refin True  refout True  check 0xcbf43926  width 32  store_bytes 4
default compute: 0xcbf43926  kat_ok True
flip refin  : 0x1898913f  kat_ok False
flip refout : 0x649c2fd3  kat_ok False
```

So "toggle `#crc_field_refin` to a NON-default value" means toggling to **False**, and
`#crc_custom_vector_result` moves `0xCBF43926 → 0x1898913F`. The custom-vector field is **not**
empty by default — it is seeded `"123456789"` (`crc_designer_view.py:348`), and
`_custom_vector_text` (`:744-753`) reads `#crc_custom_vector` live and digests it with the
switch-derived `algo` (`:651`). The C-10 defect I was asked to check for **does not occur**: the
observable genuinely changes. `0xCBF43926` is also the externally-published CRC-32 check value —
the KAT anchor is intact.

**Impact.** Medium. An implementer who assumes `refin` defaults False writes the toggle in the
wrong direction; the switch still flips and the value still changes, so the AT passes — but it is
then not testing the non-default branch it claims to. Naming the value converts the AT from
"something changed" to "this exact transition happened".

**Proposed disposition.** Amend AT-213 to state: *`#crc_field_refin` is seeded `True`
(CRC-32/ISO-HDLC); drive it to `False` through the surface; assert
`#crc_custom_vector_result` transitions `0xCBF43926 → 0x1898913F`* — an exact-string transition,
not a `!=`.

---

### Q-7 AT-215's MATCH→MISMATCH flip is reachable — name the value, and avoid two near-miss states — major

**Claim.** Reachable. Two adjacent values produce a *different* verdict token and would false-pass
or false-fail.

**Evidence.** `_current_algorithm` (`crc_designer_view.py:644-645`):
`check = int(check_text, 16) if check_text else None`. `_verdict_text` (`:716-721`) maps
`kat_ok()` through `_VERDICT_TOKENS` (`:131-133`): `True → "✓ MATCH"`, `False → "✗ MISMATCH"`,
`None → "○ NO-EXPECTED"`. `on_input_changed` (`:593-603`) calls `_recompute` on **any** input edit,
so the real `Input.Changed` path is driven by setting `.value`. Seed check text is
`_format_hex(0xCBF43926, 4)` → verdict `✓ MATCH` (executed: `kat_ok True`).

Two traps:
- **Clearing the field gives `○ NO-EXPECTED`, not MISMATCH** (`check_text` empty → `check=None`).
- **A non-hex keystroke raises `ValueError`** → `_recompute`'s except arm (`:1127-1135`) writes
  `"Invalid parameters: …"` into `#crc_kat_verdict`. A substring test for `"MISMATCH"` is then
  false; a test for `not "MATCH"` would false-pass on the *error* string.

The clean drive: set `#crc_field_check` to **`0x00000000`** → `check=0 != 0xCBF43926` →
`✗ MISMATCH`. This is the same shape `tests/test_crc_designer_view.py` already uses for
`#crc_field_xorout` at `:1296-1298`, so there is precedent in-file.

**Impact.** Medium — the AT is verifiable, but "flips the verdict MATCH→MISMATCH" without a value is
an instruction an implementer can satisfy three different ways, one of which (clear the field) does
not produce MISMATCH at all.

**Proposed disposition.** Amend AT-215: *set `#crc_field_check` to `0x00000000`; assert
`#crc_kat_verdict` text transitions from containing `MATCH` (and not `MISMATCH`) to containing
`MISMATCH`* — asserting the **transition**, per the existing `before != after` pattern at
`tests/test_crc_designer_view.py:1305`.

---

### Q-8 HLR-072-4's acceptance is a C-18 violation — an acceptance realized in parts and smuggled into another AT's node — blocker

**Claim.** Yes, it is. §3 HLR-072-4 reads *"Acceptance: **TC-level** (white-box CSS + a pilot height
assertion **inside AT-213's run**)"* (`01-requirements.md:127`). That is "covered by X + Y combined"
plus a second subject inserted into a different AT's node — both halves of what C-18 forbids.

**Evidence.** C-18: *each AT maps to exactly one distinct on-disk test node exercising the full
chain; "covered in parts" = unrealized.* HLR-072-4 has **no `AT-NNN` of its own** — it is the only
HLR in §3 without one, and §5.2's traceability table consequently cannot bind it to any AT column.
Compounding it, AT-213 is already carrying **four** subjects (equal `region.y`; an interleaved
label; the refin→vector transition; and now a Select height) — and the catalog's own note is that
*a two-subject acceptance is where an earlier batch lost a threshold*.

The requirement is measurable and worth keeping. Executed at 120x30:

```
Select (id -> (y, height)): {'crc_preset_select': (23, 6), 'crc_coverage_intra_gap': (24, 3),
 'crc_coverage_join': (27, 4), 'crc_coverage_on_gap_conflict': (32, 4),
 'crc_field_store_endianness': (45, 4), 'crc_custom_vector_mode': (23, 3)}
```

**4 of 6** Selects exceed height 3 today (one at 6, three at 4), so a `height == 3` assertion is
RED pre-batch and GREEN post — genuinely falsifiable. (Minor: the artifact's rationale says
"wrapped to 5-6 rows"; measured max is 6 and the modal value is 4. Re-derive the figure or drop it.)

**Impact.** As written, HLR-072-4 is **UNREALIZED** in the C-18 sense — no node owns it — and its
evidence would be entangled with AT-213's, so a failure could not be attributed.

**Proposed disposition.** Allocate **AT-219** (the block is free — see Q-10) to HLR-072-4 as its own
node: *pilot at 120x30, derive the Select set from `panel.query(Select)` (C-31 — do not hand-list
the six ids), assert `every s.region.height == 3`, and assert the derived set is non-empty.* Split
the G-2 clause out of AT-213 too, or state plainly in §3 that AT-213's node asserts exactly the
HLR-072-1 pair-row promise and nothing else.

---

### Q-9 Test ledger base is stale — 2379, not 2358 — blocker

**Claim.** §Test ledger's base is wrong by 21.

**Evidence.**

```
$ python -m pytest --collect-only -q 2>&1 | tail -3
tests/test_workspace_variants.py::test_build_variant_set_rejects_unknown_active_id
tests/test_workspace_variants.py::test_build_variant_set_empty_project_has_no_active_variant

2379 tests collected in 1.69s
```

**Impact.** `post = base − D + A` is the project's signed-balance ledger, and the catalog records
that a constant offset between expected and observed post-count is the signature of a units bug
that once hid a 32-test discrepancy. A base that is already 21 off guarantees the Phase-3 and
Phase-4 ledger reconciliations either fail spuriously or get "reconciled" by adjusting the wrong
term.

**Proposed disposition.** Set base = **2379**, and record the command + date beside it so the next
gate can tell staleness from drift.

---

### Q-10 ID census re-run — AT-213..218 and TC-510..519 are FREE — informational (no action)

**Claim.** No parallel batch has consumed the allocated ids. AT-219 (proposed in Q-8) is also free.

**Evidence.** Census re-executed excluding this batch's own directory (which self-matches its
reservation text) and excluding `__pycache__`:

```
$ grep -rhoE "AT-[0-9]+" REQUIREMENTS.md tests/ .dev-flow/ --include="*.py" --include="*.md" \
    --exclude-dir=2026-07-30-batch-72 | sort -u -V | tail -3
AT-210
AT-211
AT-212

$ grep -rhoE "TC-[0-9]+" ... --exclude-dir=2026-07-30-batch-72 | sort -u -V | tail -3
TC-508
TC-509
TC-1728
```

Prior max = **AT-212** / **TC-509** — matching §5.2's claim. `TC-1728` is a separate legacy series,
not a collision. AT-213..219 and TC-510..519 are unclaimed.

*(Note: the naive census the artifact describes returns `TC-510/514/515/519` as "taken" — those are
this document's own reservation strings at `01-requirements.md:179-180,184`. Exclude self at
Phase 3 or the census will report a false collision.)*

---

### Q-11 C-27 — no new test lands in a frozen test file — informational (no action)

**Claim.** Clear.

**Evidence.** `tests/test_tui_directionb.py:5494-5505` `_ENGINE_TEST_FILES`:

```
tests/test_core_srecord_validation.py   tests/test_hexfile.py    tests/test_range_index.py
tests/test_validation_a2l.py            tests/test_validation_engine.py
tests/test_validation_mac.py            tests/test_tui_a2l.py    tests/test_tui_mac.py
tests/test_color_policy_round_trip.py
```

The batch's ATs land in `tests/test_crc_designer_view.py`, `tests/test_tui_legend.py`,
`tests/test_legend_n8.py`, `tests/test_legend_scope_and_logwidth.py` — **none** is in the frozen
set. `_ENGINE_PATHS` (`:5479-5490`) contains no touched source file either
(`crc_designer_view.py`, `screens.py`, `styles.tcss` are all outside it). C-27 discharged.

---

### Q-12 Derived-focusable census picks up 6 phantom zero-area `SelectOverlay` widgets — minor

**Claim.** A naive `can_focus` walk is polluted.

**Evidence.**

```
zero-size focusables (region present but unpainted): 6
    (0, 0, 0, 0, 'SelectOverlay', None)   x6
```

They survived my adjacency computation only because zero width made the x-overlap test false — luck,
not design. A census keyed on `region.y` alone would treat all six as mutually abutting at `y=0`.

**Proposed disposition.** The derived set must filter `w.region.area > 0` (and ideally `w.display`),
and the AT should assert the filtered count against a floor so a broken filter cannot silently empty
the set (C-31: guard the derived set's completeness).

---

## Per-AT falsifiability table (C-40)

| AT | Declared subject | Subject in the expression? | Mutation that reddens it | Verdict |
|---|---|---|---|---|
| **AT-213** (pair row) | refin/refout share one row; toggling refin moves the CRC | ✅ yes — `region.y` equality names the switches; `#crc_custom_vector_result` names the computed surface | Revert compose to two `_switch_row` calls (`:301-302`) → `y=32` vs `y=33` → equality FALSE. Independently: stub `_current_algorithm` to ignore `refin` → vector text frozen at `0xCBF43926` | **SOUND** once the direction + expected values are stated (Q-6). Currently carries 4 subjects — split per Q-8 |
| **AT-214** (G-1) | "no two vertically-adjacent focusable controls abut" | ❌ **NO under the label reading** — `_switch_row` already emits a `Label` per row, so the predicate is TRUE pre-batch; ⚠️ under the geometric reading the subject is in the expression but so are 15 out-of-scope pairs | *None exists.* Geometric reading: RED before **and** after (15 innocent pairs). Label reading: GREEN before **and** after | **VACUOUS / UNAUTHORABLE — blocker** (Q-1). Re-scope to same-widget-class adjacency |
| **AT-215** (KAT demoted) | `#crc_kat_verdict` under `#crc_algorithm_fields`; verdict flips through the real `Input.Changed` path | ✅ yes — both the ancestor id and the verdict widget are named | Leave `verdict_group` in `#crc_top_right` → ancestor walk FALSE. Independently: break `on_input_changed` → verdict stays `✓ MATCH` | **SOUND** once the value `0x00000000` is named and the `NO-EXPECTED` / `Invalid parameters` near-misses are excluded (Q-7) |
| **AT-216** (two-pane) | key pane shows the `Pale yellow` row **without scrolling** | ❌ **NO** — the string matches a *card* caption in the other pane (`legend.py:718`), and `render().plain` is geometry-blind: proven present today at `y=27` outside a `y=6..21` viewport | *None as written* — passes on a clipped/empty key pane. With a region-containment oracle: `display: none` on the key pane → RED | **VACUOUS ×2 — blocker** (Q-4, Q-5) |
| **AT-217** (floor stacking) | key pane `region.y` < card pane `region.y` at 80x24 | ✅ yes — both panes named, `<` is asymmetric so side-by-side (equal `y`) also fails | Drop the narrow CSS rule → panes stay side-by-side or card-first → `<` FALSE (today: card `y=7`, key `y=43`) | **SOUND** — the strongest AT in the set. Add "reachable under scroll, not visible" (Q-3) |
| **AT-218** (pipeline preserved) | warning sample + inline orange; map band-key rows; 3 legend files green | ⚠️ partial — the sample id is named, but "inline orange" needs the **span**, not `render_line`, per project C-37 (`docs/engineering-rules.md:145`) | Drop the `_MAC_WARNING_SAMPLE_STYLE` wrapper (`screens.py:1117`) → span style absent | **REGRESSION PIN, not a gate** — label it so per C-40's corollary. Must read `render().spans`, not `render_line(0)`, or it reads the theme foreground `#e9e9e9` |
| **HLR-072-4** | Select height 3 | — **no AT node exists** | Revert `#crc_designer_panel Select { height: 3 }` → measured `6/4/4/4/3/3` → RED | **UNREALIZED (C-18) — blocker** (Q-8). Allocate AT-219 |

---

## C-26 reverse-grep result

Command (executed over the whole `tests/` tree; `__pycache__` hits omitted as non-source):

```bash
for s in <symbol>; do grep -rl -- "$s" tests/; done
```

| Symbol | Files pinning it | P-6 held? |
|---|---|---|
| `crc_field_refin` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| `crc_field_refout` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| `crc_kat_verdict` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| `crc_live_verify` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| `crc_top_right` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| `crc_bench_c1 / c2 / c3` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| `crc-hero` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| `crc_field_check` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| `crc_custom_vector_result` | `tests/test_crc_designer_view.py` | ✅ 1 file |
| **`crc_algorithm_fields`** | **(none)** | ⚠️ **0 files** — AT-215's ancestor assertion is a brand-new pin, not a preserved one |
| **`crc-field-switch`** | **(none)** | ⚠️ **0 files** — the CSS class AT-214's counterfactual mutates has **no** existing regression coverage |
| **`_switch_row`** | **(none)** | ⚠️ **0 files** — private helper; LLR-072-1.1's "drop if orphaned" is unguarded by any test |
| `legend_dialog` | `tests/test_tui_legend.py` | ⚠️ 1 file, not 3 |
| `legend_body` | `test_legend_n8.py`, `test_legend_scope_and_logwidth.py`, `test_tui_legend.py` | ✅ 3 files |
| `legend_close` | `tests/test_tui_legend.py` | ⚠️ 1 file, not 3 |
| `legend_mac_warning_sample` | `tests/test_legend_n8.py` | ⚠️ 1 file, not 3 |

**P-6 verdict: ⚠️ HOLDS DIRECTIONALLY, but the wording is imprecise and hides a real gap.**
The CRC half is exactly right — every pinned CRC id lives in one file, so
`tests/test_crc_designer_view.py` is the whole CRC blast radius. The legend half is right only as a
**union**: the three legend symbols collectively touch 3 files, but no single symbol is pinned in
3, and `legend_dialog` / `legend_close` / `legend_mac_warning_sample` are each single-pinned. The
gap P-6 does not mention: **three touched symbols are pinned nowhere** —
`crc_algorithm_fields`, `crc-field-switch`, `_switch_row`. That is not a blocker (nothing breaks),
but it means the batch cannot claim existing tests protect the switch styling or the algorithm-group
id; those are new obligations, not preserved ones. Amend P-6's disposition line accordingly.

---

## Evidence checklist

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then | ✗ | The artifact uses HLR + `AT-NNN` prose (`01-requirements.md:100-152`). **Acceptable** — this is the project's V-model AT/TC convention (`docs/engineering-rules.md`), and conformance beats my house style (global rule 11). Not raised as a finding |
| 2 | Test cases have explicit Expected, not vague "works" | ✗ | AT-213 "changes the computed CRC surfaces" and AT-215 "flips the verdict" name no value — Q-6, Q-7. AT-216 names a string that matches the wrong pane — Q-4 |
| 3 | Edge cases include empty, boundary, invalid, error | ✗ | No AT covers the `check` field's **empty** state (`○ NO-EXPECTED`, `crc_designer_view.py:645`) or its **invalid-hex** state (`"Invalid parameters: …"`, `:1128`), both of which AT-215 can hit by accident — Q-7. No AT covers the legend at a **non-mac** view except AT-218's map branch |
| 4 | Regression checklist exists | ✓ | §5.3 items 2-4: frozen guards both arms, the 4 P-6 files, `pytest -q -m "not slow"`. Extended by my C-26 table above |
| 5 | Exit criteria stated | ✓ | §5.3 six numbered criteria (`01-requirements.md:188-197`), incl. the "if any snapshot fails, STOP" clause — a good premise-guard |
| 6 | No real PII / secrets | ✓ | Reviewed artifact + probes: only CRC constants, widget ids, fixture paths under `tmp_path`. No credentials, no host paths beyond the worktree |
| 7 | Test results section left blank for the human | ✓ | This review reports only what I executed (probes + greps + collect-only). No AT is marked passed — none exists yet |
| 8 | **Layer B (black-box):** deliverables observed through the SHIPPED surface with boundary + negative evidence | ✗ | §5.1 correctly mandates `App.run_test()` for all ATs. But the *observation* is unsound for AT-216 (content harness is geometry-blind — Q-5) and AT-218 (`render_line` reads the theme colour, not the span — project C-37). **Negative evidence is absent throughout**: no AT asserts a discriminating negative except AT-215's `query("#crc_live_verify")` is empty — which is the one good one |
| 9 | **Bidirectional surface-reachability:** every named input AND every named output exercised through the handler | ✗ | Inputs: `refin` ✓ (Q-6), `check` ✓ (Q-7). Outputs: `#crc_custom_vector_result` ✓, `#crc_kat_verdict` ✓ — but **four of the six ids `_recompute` requires** (`#crc_json_preview`, `#crc_warnings`, `#crc_coverage_preview`, `#crc_coverage_window`, `crc_designer_view.py:1115-1121`) are named in constraint §2.4 as must-stay-mounted and are observed by **no AT**. P-4 is the premise; nothing verifies it post-change |
| 10 | **No unfilled template:** no remaining placeholders | ⚠️ | No `<...>` or `TC-NNN` placeholders. But §5.2's TC column reads `TC-510..TC-514 (reserved)` / `TC-515..TC-519 (reserved)` — a **range**, not assignments. The catalog's measured lesson is that fixing ranges without per-id **semantics** produced 9-10 of 12 ids bound to different observables across two lanes. Assign each TC its observable before Phase 3 |

---

## Verdict

**5 blockers · 5 majors · 4 minors → ITERATE back to Phase 1.**

**Blockers (must close before Phase 3):**

| # | Blocker | Fix |
|---|---|---|
| Q-1 | AT-214 / G-1 unauthorable in both readings — 16 abutting pairs measured, 15 out of scope | Re-scope G-1 to same-widget-class adjacency; keep the set DERIVED |
| Q-4 | AT-216's `Pale yellow` matches a **card** caption in the other pane | Anchor on the key-row widget + `LEGEND_TABLE["MAC"]["Pale yellow"][1]` |
| Q-5 | AT-216's "without scrolling" is invisible to `render().plain` (proven: present at `y=27`, viewport `y=6..21`) | Region-containment oracle + mutate it with `display: none` |
| Q-8 | HLR-072-4 has no AT node — "TC-level + an assertion inside AT-213's run" (C-18) | Allocate **AT-219**; derive the Select set from `panel.query(Select)` |
| Q-9 | Test-ledger base stale: **2379** collected, not 2358 | Correct the base; record the command + date |

**Majors:** Q-2 (counterfactual must fail on its own assertion, and `styles.tcss` may not own the
observable) · Q-6 (`refin` defaults **True**; name `0xCBF43926 → 0x1898913F`) · Q-7 (name
`0x00000000`; exclude the `NO-EXPECTED` and `Invalid parameters` near-misses) · AT-218 must read
`render().spans` per project C-37, and is a **pin, not a gate** · checklist #9 — the four other
`_recompute` ids (P-4's subject) are observed by no AT.

**Minors:** Q-3 (AT-217 → say *reachable under scroll*; floor budget measured at 9 rows) ·
Q-12 (filter zero-area `SelectOverlay` phantoms) · P-6's wording (three touched symbols pinned
**nowhere** — Q/C-26 table) · the "5-6 rows" Select figure (measured `6/4/4/4/3/3`).

**What I verified and found sound — do not re-litigate:** P-2 and P-3 (no CRC or legend snapshot
cells — re-probed, 0 matches) · P-4 (`_recompute`'s six ids, `crc_designer_view.py:1115-1121`) ·
P-5 (AT-B59-03/08's teeth are a computed 3-column comparison at
`tests/test_crc_designer_view.py:928,1312`; Variant B keeps `#crc_bench_c1/c2/c3`) · C-27 (no
frozen test file touched) · the ID census (AT-213..219, TC-510..519 free) · and both defect premises,
which I measured directly: the switches ARE fused (`y=32`/`y=33`, `h=1`, no border) and the legend
key IS below the fold (`max_scroll_y=24` at 120x30, `40` at 80x24).

**Recommended Phase-1 iterate scope:** rewrite G-1 (Q-1), rewrite AT-216's two limbs (Q-4/Q-5), add
AT-219 (Q-8), correct the ledger base (Q-9), and inline the concrete values into AT-213/AT-215
(Q-6/Q-7). That is five edits to one document — no re-architecture. The stories themselves are
`READY` and the operator's variant verdict stands.
