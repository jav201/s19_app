# Validation — s19_app — Batch `2026-08-01-batch-77`

> **Artifact language:** English (`state.json.language`).
> Phase 4 artifact. Owner: `qa-reviewer`. Executes the validation strategy fixed in `01-requirements.md` **revision 7** §5.
> **Written after the fact.** The batch merged as PR **#186** at `244ecf2`. Every figure below is either (a) read from an executed run's own output recorded in the ten increment commit bodies, or (b) re-derived at write time on branch `claude/batch-77-closeout` and labelled **`[re-derived 2026-08-03]`**. Nothing is computed where a run's own output exists, per *a carried number is re-derived, not copied*.

---

## ✅ Verdict (read first)

- **Result:** **`PASS-WITH-NOTES`**
- **Requirements:** **27/27** live LLRs pass · **7/7** HLRs pass · **0** blocker fails · **4** notes (N-A…N-D below)
- **Black-box acceptance (Layer B):** ✓ every one of the 7 stories has ≥1 `AT` observing its **deliverable** through the shipped surface, with boundary + negative evidence — **but 3 of the 20 nodes are PINs, not gates**, and one PIN's falsifiability was undemonstrated until Inc-8 (N-A)
- **Surface-reachability (bidirectional):** ✓ 16/16 named input dimensions and 11/11 named deliverables reached/observed through the handler — **0 gaps**
- **Supersession inspection:** ✓ all surviving refs negative — 5 marker classes swept `[re-derived 2026-08-03]`, 0 live dependencies
- **Test ledger:** ✓ reconciles end to end — `2519 → 2612`, and **2612 collected re-derived at write time**, exit 0
- **Evidence checklist (qa-reviewer):** ✓ complete — 11/11 items, each with a one-line citation

### Why not `PASS`

Four things are true that a bare `PASS` would hide. None is a blocker; all four are load-bearing for the postmortem.

| # | Note | Severity | Where |
|---|---|---|---|
| **N-A** | **`AT-B77-09` and `AT-B77-16` are PINs, not gates** — GREEN before *and* after, falsifiable only by a named mutation. **`AT-B77-16`'s originally-named mutation was proven INERT.** A PIN whose named mutation cannot move it certifies **nothing**; the id had no demonstrated subject until Inc-8 supplied and executed a substitute. | note | §Layer B, §Escaped-bug |
| **N-B** | **One product defect escaped every local gate** and was caught by CI at the merge gate, after ~20 review passes had found nothing wrong in shipped product code. The band bar rendered every run at 1 column on an in-domain image, first render only. | note | §Escaped-bug regression |
| **N-C** | **`AT-B77-19` was cited in a test one commit before it had a definition** — the **fourth** instance of the dangling-id class in this one batch (`C-77-i`, `C-77-m`, `R-TUI-111`, `AT-B77-19`). The green suite structurally could not catch it: `AT-TC-REGISTRY` excludes letter-initial bodies (spec §2.3). | note | §Gaps G-003 |
| **N-D** | **A quoted figure had a real producer that lives in no durable artifact.** Amendment D's precondition is verified **three** times over — **859 276** (author, consolidated, `01-requirements.md:876`) · **6.5 M** (independent exhaustive sweep, Inc-1 commit body) · **660 160** (post-gate `code-reviewer`, orchestrator-held). The third **exists only as a session report**, which is why a sweep of `.dev-flow/2026-08-01-batch-77/**` and `state.json` returned nothing. **CLOSED-WITH-A-FINDING** — the finding is the *record*, not the number. **Third occurrence in this batch of *the finding existed, the record did not*.** | note | §Gaps G-004 |

> Every other line is ✓. The Detail below is reference except where a note points into it.

> 📌 **Reading note for the `AT` range.** `01-requirements.md` **revision 7** §5.4 declares the batch-scoped range as **`AT-B77-01…16`, `AT-B77-18`** (with `AT-B77-17` withdrawn). **`AT-B77-19` is absent from that range, and that is not an omission** — the merge-gate product fix landed **after** Phase 1 closed, so the id was minted at `2f427a9` and registered under `R-TUI-103` at `REQUIREMENTS.md:6017` (commit `bfddcc9`). It is a genuine batch-77 acceptance node and is carried as one throughout this document. A reader who checks §5.2 alone will not find it.

---

## Detail (reference)

### Layer A — functional (white-box): per-requirement results

> `TC-B77-NN` ↔ LLR. Functional chain fixed at `01-requirements.md:615`.
> Node-level results are from each increment's own gate output (commit body); the file-level totals marked `[re-derived 2026-08-03]` were re-run at write time on `claude/batch-77-closeout`.

#### HLR-111 — every mapped run is visible, ordered by size, inside a bounded container

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| **HLR-111** | AT+TC | `AT-B77-01` ∧ `AT-B77-03` ∧ `AT-B77-18`, both size arms | visible∧monotone∀∧strict∃ in domain | **pass** | Inc-1 gate `a84ff2f`; `tests/test_tui_map_big.py` 29 passed @48.50 s |
| `LLR-111.9` | test (geometry) | `#map_grid.region.width == .map-band-bar.region.width`, both regimes | bar 21 → **50** @120×30 | **pass** | `tests/test_tui_directionb.py::test_at073b…`; Inc-1 commit body |
| `LLR-111.1` | test (unit+E2E) | basis **and** denominator both normative — container width × mapped-byte share | basis = `bar.region.width`, not 60 | **pass** | `_BAND_BAR_WIDTH` deleted outright (OQ-3); 0 live refs `[re-derived 2026-08-03]` |
| `LLR-111.7` | test (unit) | `_allocate_band_widths` — floor-1 then largest-remainder over the **surplus**, bounded **in the producer** | `sum ≤ width` ∧ `each ≥ 1` | **pass** | `TC-B77-01…05`, `TC-B77-30` boundary catalog, `test_tui_map_big.py:~1703` |
| `LLR-111.2` | test | every unmapped gap folds to exactly 1 column | `gap_w == 1`, always | **pass** | Inc-1; ruling R-5 (fold=2 collapses three runs and guts the strict limb) |
| `LLR-111.3` | test (geometry) | `bar.region.contains_region(seg.region)` ∀ segments, **in domain** | `outside == 0` (was 4 @120×30) | **pass** | `AT-B77-03`; pre-change RED @120×30 executed |
| `LLR-111.4` | test (byte golden) | rendered strip byte-equals the stored golden at a fixed container width | `[49,17]` @66 · `[37,13]` @50 | **pass** | `tests/goldens/batch77/at-b77-02-gapless-band-strip.txt`; stored blob measured `[re-derived 2026-08-03]`: 49+17=66, 37+13=50, **0 CR bytes** under `core.autocrlf=true` |
| `LLR-111.5` | inspection | C-40 register — each row marked *executed* or *predicted*, **and names the METHOD that produced its payload** | 0 rows left `predicted` at close | **pass** | Inc-3 closed `LLR-111.4`'s label; P-59 forced the method column |
| `LLR-111.6` | test (helper) | geometry read at **settled** layout — post-pause fixed point, never a same-frame repeat | 6 trials; 1 read 23 where 5 read 21 | **pass** | finding N-2, `01-requirements.md:584`; mandatory settling helper |
| ~~`LLR-111.8`~~ | — | **WITHDRAWN to batch-78 (R-10).** Recorded as a withdrawal record naming all six defects, not deleted. | — | **n/a** | `01-requirements.md:432`; charter `C-77-l` with 11 measurements pre-paid |

> **Amendment D — the requirement was FALSE, not inconvenient.** The rev-5 strictness clause was **unsatisfiable by any allocator** on in-domain inputs; the cause is integer **quantisation**, not surplus exhaustion. Executed counterexample in domain (`n_runs+n_gaps = 19 ≤ bar = 19`): `runs=[1,2,4,…,512]` → `widths=[1]*10`, `differing=True`, `strict=False`. The reviewer's proposed `≤`→`<` narrowing drops failures only **576 → 85** over 20 000 cases — it does not work. The shipped precondition `surplus × spread > total` is **strict**, because `≥` admits **285** non-strict cases at ratio exactly `1.000000` that random sampling cannot find (measure-zero).

> **The precondition is verified THREE times, by three producers — this is mutual corroboration, not one number quoted thrice.**
>
> | # | Producer | Population | Counterexamples to `>` | Where the record lives |
> |---|---|---|---|---|
> | 1 | **Amendment D's author** | **859 276** consolidated — Exhaustive A **260 160** + Exhaustive B **264 384** + adversarial grid + random **80 000** + ratio-targeted constructions | **0** | ✅ `01-requirements.md:871-876` |
> | 2 | **Independent exhaustive sweep** on the shipped `_allocate_band_widths` | **≈6.5 M** | **0** | ⚠️ Inc-1 commit body (`a84ff2f`) only |
> | 3 | **Post-gate `code-reviewer`**, different families and a different seed | **660 160** = exhaustive **260 160** + random **400 000** across 4 independent families; **14** counterexamples to `≥`, every one at ratio exactly `1.000000` | **0** | 🛑 **session report only — no durable artifact** |
>
> ⚠️ **One honest qualification on producer 3, made because the arithmetic invites the opposite reading.** Its exhaustive component — `n=2–4, bytes 0–7, gaps 0–4, bar ≤16` → **260 160** — is *byte-identical in parameters and count* to the author's **Exhaustive A** (`01-requirements.md:871`). Exhaustive enumeration is **deterministic**, so that half is a **reproduction** of the author's case set, not an independent sample of it. A reproduction is genuinely valuable — it confirms the author's enumerator and its count — but it is not new coverage. **The independent half of producer 3 is the 400 000 random draw.** Stated so a later reader does not add 859 276 + 6.5 M + 660 160 and believe the overlap away.
>
> ⭐ **The most reusable fact in the amendment, and the reason the threshold is `>` and not `≥`:** every `≥` counterexample sits at ratio **exactly `1.000000`** — a **measure-zero** boundary under random bytes. Producer 3's *random* 400 000 surfaced its 14 only because its **exhaustive shell** reached the exact-equality cases. **A purely random sweep of any size will not find them.** The author's own `140 808`-case random sweep missed them for precisely this reason (`01-requirements.md:867`). Any future attempt to loosen this precondition must enumerate, not sample.

⚠️ See **N-D** and **G-004** on where the third figure's record does — and does not — live.

#### HLR-112 — every ruler label names a mapped address and is legible

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| **HLR-112** | AT | `AT-072b` (re-derived) ∧ `AT-B77-04` | 0 labels outside a mapped range (was **4 of 5**) | **pass** | Inc-4 `ce0eccf`; `case_02` in domain, 5 ticks both regimes |
| `LLR-112.1` | test | one `.map-ruler-tick` per emitted **run** start + the last mapped byte (`span_end − 1`) | `case_02` → 5 ticks | **pass** | ruling R-4 (`span_end` is exclusive) |
| `LLR-112.2` | test | interior labels elide against the ruler's **measured** width at pitch `len(label)+1 = 9`; first and last always retained | ceiling 7 @80×24 / 5 @120×30 | **pass** | `prg.s19` elides 15→7 and 15→5, no raise |
| `LLR-112.3` | census | the retired 5-tick contract has **0 surviving statements** across source, tests, `REQUIREMENTS.md` and batch-47 | 0 surviving | **pass** | Inc-5 `a4050e4` — **35 sites across 13 files**, every one *read*, not grepped |

> **The one-blank-column separator is normative, not cosmetic.** It sets the pitch to 9 rather than 8, which sets the ceiling to 7/5 rather than 8/6, which decides whether `case_07_stress_smoke` is in domain at all. *A membership answer that changes with an unstated convention is not a membership answer.*
> **Latent trap closed at Phase 2:** `AT-072b`'s fixture is **PINNED to `case_02`**. `prg.s19` — the batch's showcase fixture everywhere else — needs 15 ticks against a ceiling of 7/5, so the in-domain "no elided tick" clause would have gone **RED on CORRECT code** had Inc-4 reached for it. Pin at `tests/test_tui_map_big.py:292`.

#### HLR-113 / HLR-114 — stats strip, legend residency

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| **HLR-113** | AT | `AT-B77-05` — dual readout through `#map_stats_body` | — | **pass** | Inc-6 `c95a56d` |
| `LLR-113.1` | test | `build_stats_text` renders coverage at **exactly** four fractional digits; totals via `insight_style.human_bytes` | `0.00%` → `0.0008%`; `1024` → `1.0 KiB of 128.0 MiB` | **pass** | `TC-B77-10…13`. *"Exactly four" not "at least four": a `.6f` implementation satisfies the looser wording while reddening `test_at037`'s absence clause.* |
| `LLR-113.2` | test | largest gap renders through `human_bytes` | `67108408 bytes` → `64.0 MiB` | **pass** | `TC-B77-13`; `coverage_stats` untouched, `image_span` **surfaced not computed** so `LLR-041.7` holds by construction |
| **HLR-114** | AT | `AT-B77-06` (absent from body) ∧ `AT-B77-07` (legend screen intact) | 0 `.map-band-legend` in `#map_grid` | **pass** | `TC-B77-14/15`, `tests/test_tui_directionb.py:5043`, `:5134` |
| `LLR-114.1` | test | `_build_band_widgets` constructs no `.map-band-legend`; its two `styles.tcss` rules deleted | 0 containers, 0 rows | **pass** | C-38 scoping applied — the query is scoped to `#map_grid`, else it falsely reddens when the legend screen is open |
| `LLR-114.2` | test (diff) | the `k` binding and `action_show_legend` unmodified | 0 diff lines `app.py:1345-1375` | **pass** | `AT-B77-07` derives completeness from `ENTROPY_BAND_LABELS`, **strictly stronger** than the hand-typed four-tuple it replaced (a four-tuple cannot fail when a fifth band is added) |

#### HLR-115 / HLR-116 / HLR-117 — keyboard, auto-select, selection styling

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| **HLR-115** | AT | `AT-B77-08` presses **real keys** (never `.focus()`), `AT-B77-09`/`16` PINs, `AT-B77-10` mouse split | — | **pass** (2 PINs — N-A) | Inc-8 `95e5aa0` |
| `LLR-115.2` | test | `↑`/`↓` move focus in ascending address order, **no wraparound** at either edge | `TC-B77-16/18` edges | **pass** | **C-16 discharged by execution**: with `can_focus` already True, arrows were still inert (`after_down=0`, `after_down2=0`, `after_up=0`) at both regimes — Textual gives no spatial arrow-focus for free |
| `LLR-115.3` | test | `Enter` posts the same `RegionRow.Activated` a click posts, `chain = 1` | one policy site, no second path | **pass** | `TC-B77-19/20`; routes through the existing `on_region_row_activated` |
| `LLR-115.4` | test (PIN) | `RegionRow.BINDINGS == []`; `j`/`k`/`o` still reach the app | 0 shadowed | **pass** (PIN) | ⚠️ **the mutation this LLR NAMED was inert** — see N-A / §Escaped-bug |
| **HLR-116** | AT | `AT-B77-11/13/14/15a/15b` | zero operator gestures | **pass** | Inc-7 `da38636` |
| `LLR-116.1` | test | `RegionRow` focusable and reachable | `can_focus` True | **pass** | verified against `dir(Widget)`: it **overrides** a known attribute, does not shadow an internal one (`_nodes`/`_context` hazard cleared) |
| `LLR-116.2` | test | resolution runs on `call_after_refresh`, after `_reset_detail()` and after rows are queryable | deferred, not inline | **pass** | `TC-B77-31`; `grid.mount()` is deferred, so "after the rows are mounted" is not a synchronous point |
| `LLR-116.3` | test | auto-selection **never** posts `OpenInHexRequested` | 0 posts | **pass** | C-40 co-assertion: inspector populated in the same run |
| `LLR-116.4` | test | preserve by **address** if present, else fall back to the new first | 2 arms (R-6) | **pass** | `AT-B77-13`/`AT-B77-14`, `TC-B77-29` |
| `LLR-116.5` | test | focus lands on a **LIVE** row — attached and among the panel's current rows | `.last()` resolution | **pass** | `_live_region_rows()` mirrors `_resize_band_segments`; `remove_children()` is deferred so a panel-wide `query(RegionRow)` returns stale + fresh together. **Narrowed at Inc-7** — focus withheld while the panel is not displayed; narrowing recorded in `REQUIREMENTS.md`, not left silent |
| `LLR-116.6` | test | `#map_detail_body` renders file-derived strings as literal content, no style span, no control byte **in the painted strip** | per limb per size | **pass** | `AT-B77-15a/b`. **F-3: the PAINTED-STRIP layer choice is load-bearing** — an unscoped absence clause fired on `_flow_block_label`, which composes its own `U+000A`; the painted strip is line-split so its rows carry none |
| `LLR-116.7` | test | `safe_text` deletes `U+0000–001F` (less retained whitespace), `U+007F`, `U+0080–009F` via `str.translate` — a **byte CLASS**, no pattern matching | ESC stripped, `[red]` literal intact | **pass** | Inc-2 `5a008ef`. Class form is normative: `U+009B` is single-byte CSI and `U+009D` single-byte OSC — an ESC-anchored regex still lets `0x00/0x7f/0x9b/0x9d` reach the painted strip |
| **HLR-117** | AT | `AT-B77-12` — selected row visually distinguishable | exactly 1 marker (was 0) | **pass** | Inc-7 |
| `LLR-117.1` | test | marker applied **by address**, to no other row | exactly 1 | **pass** | `TC-B77-25` requires ≥2 runs in the fixture — with one run the claim is vacuous |
| `LLR-117.2` | test | selection adds/removes/overrides no `band-*` class and sets **no** `color:` **and no inverting text style** | 0 band-class deltas | **pass** | `TC-B77-32/33`. *"Sets no `color:`" is satisfied by `text-style: reverse`, which repaints the band colour* — the clause forbids both |

> **`LLR-115.1` was moved to `LLR-116.1`** (arch B-4) and `LLR-111.8` withdrawn (R-10). Live LLR count is therefore **27**, not 29.

---

### Layer B — behavioral (black-box) acceptance

> Every node drives the **shipped** surface — Textual `App.run_test()` Pilot, real key presses, real `pilot.click`, or the artifact on disk — and asserts the **deliverable**, not the mechanism. Every AT is parametrized over **both** size regimes and reported **per resolved node id per arm (CC-1)**.

| US | Acceptance test | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|-----------------|----------------|---------------------------------------|----------------------------|--------|
| US-77-1 | `AT-B77-01` | Pilot, both regimes | `.map-band-seg[].region.width` at settled layout | ✓·✓·✓ | **pass** — pre-change **RED both arms, on different limbs** |
| US-77-1 | `AT-B77-02` | producer through the acceptance's own fixture + drive helpers | **`tests/goldens/batch77/at-b77-02-gapless-band-strip.txt`** — stored blob, byte-compared | ✓·✓·✓ | **pass** — GATE, discharged by mutation |
| US-77-1 | `AT-B77-03` | Pilot, both regimes | `bar.region.contains_region(seg.region)` ∀ | ✓·✓·✓ | **pass** — pre-change RED @120×30 (4 outside) |
| US-77-1 | `AT-B77-18` | Pilot, `examples/case_08` (801 ranges) | 801 `RegionRow`s present in the region list; **no raise** | ✓·✓·✓ | **pass** — the only out-of-domain gate |
| US-77-1 | `AT-B77-19` 🆕 | Pilot, **first render**, both incidental correctors blinded | `.map-band-seg` width vector `[1,1,1,1,1,9,7,28,1,2,1,1,1,1]`, sum 56 + 10 gaps = 66 | ✓·✓·✓ | **pass** — escaped-bug regression, 2 arms |
| US-77-2 | `AT-072b` (re-derived) | Pilot, fixture **pinned** to `case_02` | `.map-ruler-tick` label set ⊆ mapped addresses | ✓·✓·✓ | **pass** — pre-change RED, 4 of 5 unmapped |
| US-77-2 | `AT-B77-04` | Pilot | tick set **⊇** lower bound | ✓·✓·✓ | **pass** — *not optional:* `set() ⊆ admissible` is True, so a subset-only predicate is GREEN on a ruler that rendered zero ticks |
| US-77-3 | `AT-B77-05` | Pilot | `#map_stats_body` rendered text | ✓·✓·✓ | **pass** — pre-change RED |
| US-77-4 | `AT-B77-06` | Pilot | 0 `.map-band-legend` **inside `#map_grid`**, co-asserted with ≥1 `.map-band-seg` present | ✓·✓·✓ | **pass** — pre-change RED (4 rows, 1 container) |
| US-77-4 | `AT-B77-07` | Pilot, `k` legend screen | band-key completeness **derived from `ENTROPY_BAND_LABELS`** | ✓·✓·✓ | **pass** — **PIN** (labelled) |
| US-77-5 | `AT-B77-08` | Pilot — **real `down`/`down`/`up`/`enter` key presses** | `app.focused` walks the rows; `Enter` commits to the inspector | ✓·✓·✓ | **pass** — pre-change RED (`can_focus=[False]×…`) |
| US-77-5 | `AT-B77-09` | Pilot, focus **ON** a row | `j`/`k`/`o` still reach the application action | ✓·✓·✓ | **pass** — **PIN, not a gate** (N-A) |
| US-77-5 | `AT-B77-16` | Pilot, focus **OFF** the region list | same three keys | ✓·✓·✓ | **pass** — **PIN, not a gate; its named mutation was INERT** (N-A) |
| US-77-5 | `AT-B77-10` | Pilot, single vs double click | N4a mouse split survives HLR-115 | ✓·✓·✓ | **pass** — **PIN**, mapped onto the two **existing** nodes `test_ac3_…`/`test_ac4_…` rather than minting one node covering half a two-node claim |
| US-77-6 | `AT-B77-11` | Pilot, **zero gestures** | `#map_detail_body` populated ∧ `app.focused` is a live `RegionRow` ∧ no navigation | ✓·✓·✓ | **pass** — pre-change RED |
| US-77-6 | `AT-B77-13` | Pilot, re-render holding the region | selection **preserved by address**, focus LIVE | ✓·✓·✓ | **pass** — pre-change RED |
| US-77-6 | `AT-B77-14` | Pilot, re-render dropping the region | fallback to the **new** first region, focus LIVE | ✓·✓·✓ | **pass** — pre-change RED |
| US-77-6 | `AT-B77-15a` | **real `pilot.click`** (Inc-2) **and** auto-select (Inc-7) | painted strip of `#map_detail_body`: payload literal ∧ no style span | ✓·✓·✓ | **pass** — pre-change RED, `limb1 payload-verbatim = False` at both sizes |
| US-77-6 | `AT-B77-15b` | same, both drives | painted strip: **no residual control byte** | ✓·✓·✓ | **pass** — labelled *vacuously green until Inc-2*; genuinely red→green gate from Inc-2 |
| US-77-7 | `AT-B77-12` | Pilot | exactly 1 selection marker ∧ triple differs ∧ ≥2 runs (`TC-B77-25`) | ✓·✓·✓ | **pass** — pre-change RED (0 markers) |

> 📌 **`AT-B77-19` is not in revision 7's declared range and that is not an omission.** §5.4 fixes the batch range at `AT-B77-01…16`, `AT-B77-18`; the merge-gate product fix landed **after Phase 1 closed**, so `AT-B77-19` was minted at `2f427a9` and registered under `R-TUI-103` (`REQUIREMENTS.md:6017`, commit `bfddcc9`). A reader who reconciles §5.2 against this table will find one extra row here — this is why.

**Layer-B totals:** 20 nodes over 7 stories. **13 demonstrated RED pre-change by execution** · **4 labelled PINs** (`AT-B77-07/09/10/16`) · **1 labelled vacuous-until-Inc-2** (`AT-B77-15b`) · **1 evaluable-today** (`AT-B77-18`) · **1 escaped-bug regression** (`AT-B77-19`). Every exception is labelled in `01-requirements.md` §9 — **no unlabelled exception**, which §5.3 requires.

#### N-A in full — the PINs

`AT-B77-09` and `AT-B77-16` are **PINs, not gates**: GREEN before the change and GREEN after. A PIN's whole evidentiary value is its named mutation, and at Inc-8 that value was measured to be **zero for one of them**.

> **Executed at Inc-8 (`95e5aa0`):** adding `Binding("k", …)` to `RegionRow.BINDINGS` — the mutation `LLR-115.4` named, and the *same* mutation the spec prescribed for **both** PINs — reddens `AT-B77-09` at both arms and leaves `AT-B77-16` **GREEN at both**. Cause: with no row focused, the widget binding is never in the resolution chain, so the mutation is **structurally unable to reach `AT-B77-16`'s subject**.
> **A PIN whose named mutation cannot move it has no demonstrated falsifiability at all** — it certifies nothing. The id was a label over an unchecked claim from revision 2 until Inc-8 executed it.
> **Working substitute, found and executed:** `s19_app/tui/app.py:1359`, `Binding("k", "show_legend", …)` with key `"k"` → `"f9"`. That reddens **both** PINs at **both** arms, on the **behavioural** assertion. Independently confirmed by the merge-gate reviewer.
> **Record defect, closed at close-out (M-2):** the working mutation existed only in a commit message while `LLR-115.4` still named the inert one. Now recorded at `LLR-115.4` as the substituted VALUE. Recorded in `01-requirements.md:969` in its own terms: *"this row's claim was true of the ids and false of the mutation the document offered next to them."*

`AT-B77-09` additionally clears the declaration-only objection: it reddens on its declaration limb first, but the same failing payload carries `stack_after_k: ['Screen']`, so the **behavioural** limb would also have reddened. It is not a declaration-only check.

#### Non-vacuity discharges executed at Layer B

| Node | Substituted VALUE (never "drop the X") | Reddens | Correctly leaves GREEN | Restore |
|---|---|---|---|---|
| `AT-B77-02` | `_allocate_band_widths` → plain `round()` | the **3** payload-asserting nodes, both size arms (`[49,17]→[50,16]` @66 · `[37,13]→[38,12]` @50) | the fixture-shape node and the stored-encoding node | tree hash-proven `ecdca06b…` → `ecdca06b…` |
| `AT-B77-15a/b` | remove the `call_after_refresh` line (Inc-7 re-run, **8 arms** = 2 nodes × 2 sizes × 2 drives) | **both**, on their **precondition** — naming their own mechanism | — | green re-run |
| `AT-B77-15a/b` | remove `safe_text` → `Text.from_markup` (Inc-2) | limbs 1–2 | limb 3 | hash-restored |
| `AT-B77-15b` | revert the C0/C1 filter (Inc-2) | limb 3 | limbs 1–2 | hash-restored |
| `AT-B77-13`/`14` | the R-6 mutation table, run **after** liveness landed | **exactly one arm each** | the other | hash-proven, green re-run |
| `AT-B77-05`/`06` | `.2f` for `.4f` · raw `covered_bytes` · raw `largest_gap` · legend block re-added | the matching node | the 4th arm correctly leaves `TC-B77-14` and the ported `test_at075` GREEN — neither reads the legend | byte-verified |
| `AT-072b` | a byte-equivalent **percentile** derivation substituted at the construction site | failed on its **ASSERTION**, not an error: `['20004050','400080A0','6000C0F0','80010140']` at both regimes | — | restored |
| `TC-519` (re-scoped) | the consumer regression, both arms | both arms | — | hash-proven vs `screens.py 3EA16E2B` |
| `AT-B77-09`/`16` | ⚠️ `RegionRow.BINDINGS += Binding("k",…)` — **INERT for `AT-B77-16`**; substitute `app.py:1359` key `"k"`→`"f9"` | substitute reddens **both**, both arms | — | see N-A |

> **The R-6 mutation table is Inc-7's load-bearing artefact, and only because it ran AFTER liveness landed.** Conjoined with an identity-only focus clause it previously produced `R,G,R` — byte-identical to correct — collapsing the discrimination entirely. With `LLR-116.5` in, each mutation reddens **exactly one** arm. That contrast **is** the evidence that liveness is load-bearing rather than decorative.
> **Reported, not reconciled:** the `AT-B77-14` fallback mutation **as the spec words it** fails with a `ValueError`, not on its assertion. A graceful variant was run alongside to obtain an assertion-level failure. *A test that errors on the mutated tree proves less than one that asserts.*

---

### Bidirectional surface-reachability matrix

> Every named **INPUT** dimension **and** every named **OUTPUT/deliverable** is exercised/observed through the **handler** — not only the service API. `AT-*` rows drive Pilot / the shipped CLI / the artifact on disk.

#### Inputs — 16/16 reached at the surface

| Direction | US dimension | Service param / entry | Reached at surface? | TC / AT | Status |
|-----------|--------------|-----------------------|---------------------|---------|--------|
| input | terminal size regime | `App.run_test(size=…)` | **yes** — 80×24 **and** 120×30 on *every* AT | all `AT-B77-*` | ✓ |
| input | container width (bar) | `.map-band-bar.region.width` measured at render | **yes** — 66 / 50, settled | `AT-B77-01`, `LLR-111.9` | ✓ |
| input | mapped-byte share per run | loaded image → `_merge_band_runs` | **yes** — through the handler, not the allocator API | `AT-B77-01/02` | ✓ |
| input | gap count / positions | sparse 5-region fixture | **yes** | `AT-B77-03`, `LLR-111.2` | ✓ |
| input | **empty** image (no ranges) | load with 0 ranges | **yes** | `TC-B77-01`, `TC-B77-06`, `TC-B77-17`, `TC-B77-21` | ✓ |
| input | **single** run | 1-range fixture | **yes** | `TC-B77-02/07/18/22` | ✓ |
| input | **zero-byte** run (invalid) | 0-length range | **yes** | `TC-B77-04`, `TC-B77-24` | ✓ |
| input | `total_span ≤ 0` (error) | degenerate span | **yes** — short-circuits before allocation | `TC-B77-05` | ✓ |
| input | **domain edge** `n_runs + n_gaps` vs bar width | swept across the onset **with a differing-size arm** | **yes** | `TC-B77-03` (both arms) | ✓ |
| input | **out-of-domain** image, 801 ranges | `examples/case_08` | **yes** | `AT-B77-18` | ✓ |
| input | entropy-**heterogeneous** single range | synthetic seed-per-byte fixture | **yes** — 1 range → 2 runs | `TC-B77-30` | ✓ |
| input | **hostile** file-derived text (markup + C0/C1/DEL) | untrusted symbol name in the loaded file | **yes** — via `pilot.click` (Inc-2) **and** auto-select (Inc-7) | `AT-B77-15a/b` | ✓ |
| input | keyboard `↑`/`↓`/`Enter` | **real key presses**, never `.focus()` | **yes** | `AT-B77-08`, `TC-B77-16…20` | ✓ |
| input | keyboard `j`/`k`/`o` (shadow risk) | app-level bindings | **yes** — focus ON and OFF the row | `AT-B77-09`, `AT-B77-16` | ✓ (PINs — N-A) |
| input | mouse single vs double click | N4a split | **yes** | `AT-B77-10` (`test_ac3`/`test_ac4`) | ✓ |
| input | re-render with region present / absent | second `render_ranges` | **yes** | `AT-B77-13`, `AT-B77-14`, `TC-B77-29` | ✓ |

#### Outputs / deliverables — 11/11 observed at the surface

| Direction | US deliverable | Producer | Observed at surface? | TC / AT | Status |
|-----------|----------------|----------|----------------------|---------|--------|
| output | painted band-segment widths | `_allocate_band_widths` → `.map-band-seg` | **yes** — `widget.region` at **settled** layout, not `Static.render()` | `AT-B77-01/03` | ✓ |
| output | **byte-exact golden file on disk** | shipped producer, driven through the acceptance's own fixture | **yes** — the **committed blob** is asserted, not the worktree file | `AT-B77-02` | ✓ |
| output | ruler tick labels | `MapRuler` | **yes** — `.map-ruler-tick` rendered text | `AT-072b`, `AT-B77-04` | ✓ |
| output | stats strip text | `build_stats_text` | **yes** — `#map_stats_body` (**not** the container, which renders `Blank`) | `AT-B77-05` | ✓ |
| output | legend **absence** in the map body | `_build_band_widgets` | **yes** — 0 `.map-band-legend` in `#map_grid`, **co-asserted** with ≥1 `.map-band-seg` present | `AT-B77-06` | ✓ |
| output | legend screen band key | `k` LegendScreen | **yes** — completeness derived from `ENTROPY_BAND_LABELS` | `AT-B77-07` | ✓ |
| output | inspector detail text | `#map_detail_body` **painted strip** | **yes** — the line-split painted layer, not `.plain` | `AT-B77-11/15a/15b` | ✓ |
| output | focus location | `app.focused` | **yes** — asserted **LIVE** (attached ∧ among current rows), not merely address-matching | `AT-B77-11/13/14` | ✓ |
| output | selection marker + styling | selection class on `RegionRow` | **yes** — `widget.styles.*`, **not** `render().spans` (measured `[]`) | `AT-B77-12`, `TC-B77-32/33` | ✓ |
| output | region-list completeness out of domain | region list | **yes** — 801 rows reachable, no raise | `AT-B77-18` | ✓ |
| output | 29 snapshot baselines | pytest-textual-snapshot | **yes** — regenerated in **canonical CI** (run `30801949601`, Python 3.11 / textual 8.2.8) and independently verified | Inc-9 `ea7f699` | ✓ |

> **No gap in either direction.** The layer rules that make this non-trivial are `01-requirements.md:583`: geometry from `widget.region` clipped to the container **at settled layout**; band style from `widget.styles.*` because `render().spans` measures `[]`; control bytes from the **painted strip**; text from `#map_stats_body`/`#map_detail_body` because the containers render `Blank`; footer from `app.active_bindings` filtered `.show and .enabled`. Each of those is a place where the obvious read returns a plausible wrong answer.

---

### Supersession-completeness inspection

> Greps re-executed at write time on `claude/batch-77-closeout`. Every surviving reference must be a **negative** assertion or a documentary retirement record — never a live dependency.

| Superseded marker | grep result `[re-derived 2026-08-03]` | All surviving refs negative? | Evidence (`file:line`) |
|-------------------|----------------------------------------|------------------------------|------------------------|
| `_BAND_BAR_WIDTH` (deleted outright, OQ-3) | **1** hit in `s19_app`+`tests` | **yes** | `tests/test_tui_map_big.py:1148` — a docstring explaining the retired `[45,15]` payload "summing to the deleted `_BAND_BAR_WIDTH` of 60". Zero code references. |
| `R-TUI-112` (minted by Inc-4 without a register row) | **0** | **yes** — vacuously | D-17 re-pointed all 6 citations at `R-TUI-072`; Inc-6 grep before **8**, after **0** citations (4 prose mentions remain inside the closure record that quotes the retired id to explain its retirement — **reported as 4 rather than gamed to 0**) |
| `R-TUI-111` (4 citations, 0 definitions) | **0** | **yes** | close-out `93e70f4` HIGH-1 — re-pointed at `R-TUI-103`, which now carries HLR-111's Statement, domain, out-of-domain behaviour and Amendment D precondition |
| `test_ac6_clipped_segments_are_a_known_layout_limitation` (Amendment C) | **2** | **yes** | `tests/test_tui_map_big.py:239`, `:681` — both docstrings recording the **inversion**: the dropped `outside_count > 0` observable is carried by `test_b77_contain_no_segment_outside_the_bar` (C-40 limb 2(ii) satisfied — the retirement printed the dropped observable) |
| `.map-band-legend` (HLR-114) | **7** | **yes** | 5 are the **absence assertions** themselves (`tests/test_tui_directionb.py:5043`, `:5060`, `:5134`, …); 2 are removal comments (`s19_app/tui/screens_directionb.py:2570`, `s19_app/tui/styles.tcss:840`). No constructor site. |
| the retired **5-tick percentile contract** (Amendments A/B) | **8** in source+tests, **4** in `REQUIREMENTS.md` | **yes** | Every hit read, not counted. `screens_directionb.py:1599` and `test_legend_two_pane.py:38`/`:731` are retirement records; `REQUIREMENTS.md:4246/4986/5019/5025` are the amendment blocks. ⚠️ `test_tui_map_big.py:292` reads *"`case_02` (4 runs → 5 ticks)"* — a **coincidence of the NEW rule** (4 run starts + last mapped byte), **not** the retired contract. *A naive `5 ticks` grep false-positives here, which is exactly why Inc-5's census had to read 327 `ruler\|tick` hits rather than count them.* |
| `AT-B77-17`, `TC-B77-26/27/28` (withdrawn ids) | **2** prose hits, **0** live nodes | **yes** | `tests/test_tui_map_big.py:1703`, `:1709` — both inside the withdrawal record. **No node carries a withdrawn id**, so allocation stays monotonic and a spent id never means two things. |

> **The census that mattered was the 5-tick one, and its integer was low for four consecutive revisions.** Executed at Inc-5: **35 statement sites across 13 files** against a document estimate of ~23 — **52 % higher**. Three *new* miss modes, each different from the one already catalogued: a requirement restating its contract in its own `Validation:` row (`REQUIREMENTS.md:4798`); the hyphenated form `5-tick` invisible to every sweep searching `5 tick` (`01b:65`, `increment-05.md:131`); and a **second** row in a file already named at `:54` (`traceability-matrix.md:92`), invisible to a line-keyed census. Only a **claim-derived superset sweep** closed it. Surviving statements at close: **0**.
> **batch-47's process artifacts are MARKED, not rewritten** (D-18). batch-47 genuinely shipped a 5-tick ruler and its verdicts genuinely held. *Rewriting a validation record to describe behaviour it never validated would falsify it* — the census exists to stop false claims, not to create one.

---

### Signed-balance test ledger

> `post = base − D + A`. Every figure below is read from the run's own output, never spliced across runs. The ledger unit is **collected** = `passed + skipped + xfailed`.

| Point | Base | − D | + A | = post | actual collected | passed / skipped / xfailed | Form | Reconciles? |
|---|---|---|---|---|---|---|---|---|
| **Baseline `f8747b8`** — ✅ **re-derived in an isolated detached worktree**, 35:01 | — | — | — | — | **2519** | **2514 / 2 / 3**, 29 snapshots passed | **FULL** | **yes** — `2514+2+3 = 2519` |
| Inc-1 `a84ff2f` | 2519 | 1 | 21 | **2539** | 2539 | per-file: map_big 29 · directionb 174 · click_chain 7 | collect + per-file | **yes** |
| Inc-1b `b22a202` (C-22 marks) | 2539 | 0 | 0 | **2539** | 2539 | 27 passed / 2 xfailed / **0 xpassed** | snapshot | **yes** |
| Inc-2 `5a008ef` | 2539 | 0 | 5 | **2544** | 2544 | **2537 / 2 / 5** in 1611 s | **FULL** | **yes** |
| Inc-3 `cefa858` | 2544 | 0 | 5 | **2549** | 2549 | **2542 / 2 / 5** | **FULL** | **yes** |
| Inc-4 `ce0eccf` | 2549 | 0 | 10 | **2559** | 2559 | **2552 / 2 / 5**; snapshots 30 p / 2 xf / 0 xp | **FULL** | **yes** |
| Inc-5 `a4050e4` (docs only) | 2559 | 0 | 0 | **2559** | 2559 | **2552 / 2 / 5** unchanged | **FULL** | **yes** |
| Inc-6 `c95a56d` | 2559 | 0 | 9 | **2568** | 2568 | **2561 / 2 / 5** in 1455 s | **FULL** | **yes** — +9 against 9 nodes added, 0 deleted |
| Inc-7 `da38636` | 2568 | 0 | 27 | **2595** | 2595 | **2588 / 2 / 5** | **FULL** | **yes** — +23 `map_big` +4 `hostile_map` |
| Inc-8 `95e5aa0` | 2595 | 0 | 15 | **2610** | 2610 | **2603 / 2 / 5** | **FULL** | **yes** — 8 nodes × their arms |
| Inc-9 `ea7f699` (regen + flake fix) | 2610 | 0 | 0 | **2610** | 2610 | **2605 / 2 / 3**; **29 snapshots passed, 0 xfailed, 0 xpassed** | **FULL** | **yes** — the 2 retired marks converted to passes |
| **Merge-gate product fix `2f427a9`** | 2610 | 0 | 2 | **2612** | 2612 | **2607 / 2 / 3**, exit 0 | **FULL** | **yes** — `AT-B77-19`'s 2 arms |
| **Close `244ecf2`** — ✅ **re-derived at write time** | — | — | — | **2612** | **2612 collected in 1.79 s** `[re-derived 2026-08-03]` | — | collect-only | **yes** |

**Net batch delta: `2519 → 2612` = +93 collected, of which −1 deleted (`test_ac6_clipped…`, Amendment C) and +94 added.** The `xfailed` axis returns to its baseline value of **3** — the two Inc-1b marks were *retired*, not left standing. That half gets forgotten: `strict=False` means a now-passing marked cell reports `xpassed`, **not** a failure, so a stale mark never announces itself and would silently retire two live regression guards for every batch that follows.

**Form discipline.** `tui-ci` runs `-m "not slow"` on PRs and the FULL suite on pushes. **Every ledger figure above states its form**, and the FULL form ran before merge (§5.3).

#### Re-derived at write time `[2026-08-03]`

| Command | Result |
|---|---|
| `pytest --collect-only -q` | **2612 tests collected in 1.79 s** — matches the close figure exactly |
| `pytest tests/test_tui_map_big.py tests/test_tui_hostile_map.py tests/test_map_click_chain.py -q` | **100 passed in 155.45 s**, exit 0 — the files carrying `AT-B77-01/02/03/04/08/09/10/11/12/13/14/15a/15b/16/18/19` and `TC-B77-01…09,16…33` |
| `git show HEAD:tests/goldens/batch77/at-b77-02-gapless-band-strip.txt` | 4 records; widths **49+17 = 66** and **37+13 = 50**; **0 CR bytes** in the stored blob under `core.autocrlf=true` |
| `pytest tests/test_tui_directionb.py tests/test_tui_snapshot.py tests/test_legend_two_pane.py -q` | **224 passed in 336.34 s**, exit 0; **29 snapshots passed** |

---

### Batch acceptance criteria (§5.3) — checked off

| Criterion | Verdict | Evidence |
|---|---|---|
| 100 % of LLRs covered by ≥1 passing TC | ✓ | 27/27 live LLRs, §Layer A |
| Every US has ≥1 passing AT observing its outcome **through the shipped surface**, boundary + negative | ✓ | 7/7, §Layer B; 11/11 deliverables observed |
| **Every gate AT demonstrated RED pre-change, per size arm**, with only the labelled exceptions | ✓ **with 4 labelled exceptions** | 13 executed RED; exceptions `AT-B77-02` (discharged by mutation), `AT-B77-09`/`16` (PINs), `AT-B77-15b` (vacuous until Inc-2). **No unlabelled exception.** |
| Every PIN labelled PIN, falsifiability discharged by a named mutation whose transcript is pasted | ⚠️ **now yes — was NOT at Inc-8** | `AT-B77-16`'s named mutation was **INERT**; a working substitute was executed at Inc-8 and recorded at `LLR-115.4` at close-out (M-2). **N-A.** |
| **Frozen-engine diff = 0** — source **and** `_ENGINE_TEST_FILES` (C-27 dual guard) | ✓ | both halves green at **every** increment gate; `tests/test_tui_directionb.py` hosts the guard, **3 passed, 171 deselected in 0.88 s** |
| **TC-011 green and unmodified** | ✓ | Inc-8 gate: "TC-011 green and byte-unmodified" |
| Full suite green, FULL form, before merge | ✓ | **2607 / 2 / 3**, exit 0 at `2f427a9` |
| **0 blocker findings at the merge gate**, all three lanes | ✓ | independent merge-gate review returned **2 HIGH — both record defects**, 0 in shipped product code and 0 test-behaviour changes; suite unchanged at 2605/2/3 across the fix, which **is** the evidence every edit was documentation |
| Descope-specific (R-10): batch does not claim HLR-111/112 hold out of domain; `AT-B77-18` is the only out-of-domain gate; `C-77-l` present and complete | ✓ | `AT-B77-18` asserts only *no raise* + *region list complete*; `C-77-l` written **inline with content** in `BACKLOG-CODE.md`, 11 measurements verbatim |

---

### Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| **G-001** | `LLR-115.4` / `AT-B77-16` | **A PIN's named mutation was inert.** The spec prescribed *one* mutation for *two* PINs without checking it reached both subjects. Detected only when Inc-8 executed it. | **major** | ✅ **CLOSED** — substitute (`app.py:1359`, key `"k"`→`"f9"`) executed, reddens both PINs at both arms; recorded at `LLR-115.4` at close-out. **Control candidate for the postmortem: a PIN's mutation must be shown to reach the PIN's own subject, per PIN — never shared across PINs unexamined.** |
| **G-002** | `HLR-111` / `LLR-111.1` | **One product defect escaped ~20 review passes and every local gate**, caught by CI. Two independent recovery paths existed and the defect needed **both** to miss. | **major** | ✅ **CLOSED** — event-driven fix (`BandBar.Measured`), regression `AT-B77-19`, 2 arms. See §Escaped-bug. Residual coverage carried as **F-3** (below). |
| **G-003** | id hygiene | **Fourth dangling-id instance in one batch.** `AT-B77-19` was cited at `tests/test_tui_map_big.py:2731` one commit **before** it had a definition — in the commit *after* the close-out repaired the third instance by adding that very Validation line. | **minor** | ✅ **CLOSED** — registered under `R-TUI-103` (`REQUIREMENTS.md:6017`) and labelled the fourth occurrence. **Not a registry violation**: `AT-TC-REGISTRY` excludes letter-initial bodies by spec §2.3 — *which is exactly why the green suite could not catch it.* Route to the registry lane. |
| **G-004** | evidence provenance | **A quoted case-count figure had a real producer that no artifact records.** `859 276` is on disk (`01-requirements.md:876`); `6.5 M` has provenance in the Inc-1 commit body; **`660 160` = 260 160 exhaustive + 400 000 random, produced by the post-gate `code-reviewer` and held only in a session report.** Verified as arithmetic at write time; **not** verifiable from any durable artifact. | **minor** | ✅ **CLOSED-WITH-A-FINDING.** The number is genuine and is now recorded in §Layer A with its two components, its overlap qualification, and the measure-zero fact that makes it load-bearing. **The finding is the record, not the number:** *a figure whose producer is a session report has no producer as far as any later reader is concerned.* **Third occurrence of that class in this batch** — (i) the shell-quoting probe defect, session report only; (ii) `AT-B77-19`'s carry, in `REQUIREMENTS.md` but in **neither** backlog lane; (iii) this one, orchestrator-held. **Route to the postmortem as a control candidate.** Distinct from the five figures that were simply *wrong* (`13` gaps → 10 · `99.5 %` → 95.9 % · `16 of 17` → 15 of 16 · `~23` census → 35 · `case_02` as tightest margin → `case_07_stress_smoke` at 9.95×) — this one was **right and unrecorded**, which is the harder failure to detect. |
| **G-005** | `AT-B77-19` coverage | The new regression guards **first render only**. Re-render, terminal resize, screen switch and resize-while-inactive were all verified correct but are **unguarded**. | **minor** | **ACCEPTED as a carry (F-3).** All five paths ride the single `BandBar.Resize → Measured` mechanism, and first render is the only regime where the incidental correctors were ever load-bearing. |
| **G-006** | `AT-B77-02` | **Known coupling, recorded not silent:** each golden record carries its settled bar width, so a future CSS change that moves 66 or 50 reddens `AT-B77-02` **by design**, with the allocator untouched. | **minor** | **ACCEPTED.** *"A fixed container width" is part of the requirement's own condition.* Stated at close-out (L-3). Not drift — design. |

---

### Escaped-bug regression

> The batch's **one** product defect. Found by CI at the merge gate after ~20 review passes had found nothing wrong in shipped product code.

**Symptom.** On `examples/case_00_public/prg.s19` at 80×24 — **in domain**, bar correctly measuring 66 — **every** run rendered at 1 column, including the 2560-byte run. That is the allocator's *out-of-domain floor shipping on an in-domain image*: the bar reverts to exactly the non-discriminating display this batch exists to fix, **permanently rather than transiently**.

**Root cause — and it corrects the handed-over hypothesis in two material ways.**

`_build_band_widgets` runs before `grid.mount()` takes effect, so the first apportionment reads `#map_grid.region.width`, which measures **0** at both regimes. Every run therefore starts at the `[1] * n_runs` floor — **correctly**. The bug is that nothing reliably corrects it.

1. **`events.Resize` is declared `bubble=False` in textual 8.2.8**, so a **descendant** learning its width can *never* reach `MemoryMapPanel.on_resize`. That is the real hole. The hypothesis said the panel's handler "does not fire again because the panel's size never changed" — **traced, it fires TWICE** (72→70 wide, 10→42 tall) and is the **primary** corrector on the dev machine. **Two independent recovery paths existed and the defect needs BOTH to miss** — which is why it survived every local run and surfaced only on an environment slower than the dev machine.
2. **First render only.** A re-render finds `#map_grid` already laid out, so the initial build is correct immediately. Render 2 was green even with both hooks blinded.

**Fix.** `BandBar(Horizontal)` re-emits its own `Resize` as a **bubbling** `BandBar.Measured`, handled by the panel calling the existing `_resize_band_segments`. The correction is driven by the event that actually carries the information — *the bar learning its own width* — however many frames that takes. **No retry count was raised and no pause was added:** a timing guess would leave the bug live on any machine slower than the one it was tested on, which is precisely how this reached the merge gate.

| Regression id | Pre-fix run (evidence it FAILED) | Pre-fix RED kind | Post-fix value-discriminating? (QC-2) | Post-fix result | Reconciled node |
|---|---|---|---|---|---|
| **`AT-B77-19`** (2 arms) | Reproduction RED **byte-identical to CI's failure**; forced trace shows `call#1 retry=False width=0` and `call#2 retry=True width=0` | **value** — the asserted width vector, not a shape/TypeError | **yes** — GREEN asserts the real vector `[1,1,1,1,1,9,7,28,1,2,1,1,1,1]`, sum 56 + 10 gaps = 66; a wrong-but-well-typed all-ones vector fails it | **pass**, both arms | `tests/test_tui_map_big.py:2731`, "the bar re-apportions on ITS OWN resize" |

**Idempotence measured, not argued:** 6 writes while settling, then **0** across 30 steady frames and **0** under 5 forced re-apportionments at a stable width. It cannot spin.

> ⚠️ **The spin proof was initially attributed to the wrong invariant, and that correction is itself a finding (F2, `bfddcc9`).** `BandBar`'s docstring claimed the fix cannot spin *because of* `_resize_band_segments`' idempotence guard. **That reason does not cover the case that actually occurs:** during settle the widths genuinely **differ**, 4–6 writes genuinely happen, and no spin follows anyway. The real invariant is **CSS** — `.map-band-bar` is `width: 100%` and `Horizontal` does not scroll, so the bar's width is **content-independent** and rewriting segments can never re-deliver `Resize`.
> **Measured by the reviewer:** 14 segments forced to 40 columns each — **560 columns of content in a 66-column bar** — left `bar.region.width` at 66 and posted **0** `Measured`. *The loop is structurally open, not merely guarded.* The guard is a second line of defence that had been documented as the first. Corrected, with the load-bearing warning added: **changing `.map-band-bar` to `width: auto` would CLOSE the loop**, and since the settle path performs genuinely non-no-op passes the cycle would be **live**, not hypothetical.
> This matters because *a false claim in shipped source* is exactly what opened Inc-2 — see below.

**Reachability, stated honestly:** reachable by a real user at first render on a slow machine, **not test-only** — the harness uses the same layout engine and CI is the existence proof. Narrower than first thought (first render only), and **not observed in a live terminal session**.

`BandBar`'s only custom members are `Measured` and `on_resize`; neither collides with `dir(Widget)`, so no silent-mount hazard (the `_nodes`/`_context` trap).

#### The flake this batch caused — fixed at its root, not papered over

`test_tc041_6` and `test_tc062_1` (both **batch-45**) post an `OpenInHexRequested` and **return immediately**, exiting the `run_test` context with the message in flight. Teardown then dispatches it, the app handler calls `action_show_screen("workspace")`, and `#screen_workspace` is already gone → `NoMatches`.

**Measured, not argued: 0 of 4 runs failed at `f8747b8`; 3 of 4 failed on this branch**, on a tree byte-identical to Inc-8 for both files. Latent since batch-45; batch-77's per-render deferred work (the auto-selection post-refresh hook, the ruler's resize elision, the segment-width recompute) lengthens the message queue enough that the message no longer drains before the context exits. **The batch converted a dormant fault into a live one, so the batch fixes it.** No product code changed and no user-visible behaviour was ever wrong.

Fix: one awaited frame per test, so each completes the interaction it starts. Verified **4 consecutive clean runs (183 passed each)** against an experiment that failed 3 of 4 — *a single green run is exactly the standard that let this reach the merge gate unnoticed.*

---

### Three requirement amendments made because the requirement was FALSE

> Recorded here because a validation record that shows only *tests passing* hides the fact that in three places **the requirement, not the code, was the defect**. In all three the shipped product code was correct or unchanged.

| Amendment | The claim that was FALSE | How it was proven | Where the fix landed |
|---|---|---|---|
| **D** (`HLR-111` + `LLR-111.7`) | The strictness clause held on the containment domain alone. **It is unsatisfiable by ANY allocator** — integer **quantisation**, not surplus exhaustion. | Executed counterexample **in domain**: `runs=[1,2,4,…,512]`, `n_gaps=9`, `bar=19` → `widths=[1]*10`, `differing=True`, `strict=False`. The reviewer's proposed `≤`→`<` fix drops failures only **576 → 85** over 20 000 cases. `≥` admits cases at ratio exactly `1.000000` — measure-zero under random bytes, so **only exhaustive enumeration finds them** (author: 285; post-gate reviewer: 14, from the exhaustive shell of a 400 000-case random sweep). | Derived precondition `surplus × (max_bytes − min_bytes) > total_bytes`, **strict**. **Three producers, 0 counterexamples each: 859 276 · ≈6.5 M · 660 160** (see the corroboration table in §Layer A, incl. the overlap qualification on the third). **`visible ≥ 1`, `sum ≤ width` and monotone-∀ are NOT narrowed.** The allocator is **unchanged**. |
| **E** (`LLR-072-7.1`, node `TC-519`) | The guard froze `legend.py` by `git diff` while its docstring named an invariant about `_render_card`/`_render_key`. | **`_render_card` is at `screens.py:1093`, `_render_key` at `:1141`, and `legend.py` contains ZERO occurrences of either.** Proven, not argued: with the consumer regression applied, the old pathspec returned only `legend.py` while `screens.py` — carrying the defect — **was never listed**. **Structurally incapable of failing on the regression it named**, green from batch-72 to batch-77. | Two-arm **behavioural** predicate (consumer splats the helpers' return values · producers return widgets not text), each proven to redden by executing its regression, restored and hash-proven vs `screens.py 3EA16E2B`. A source hash was **considered and rejected on record** — it reddens on any producer edit while staying GREEN on the consumer defect, i.e. it *inverts* the discrimination. |
| **A / B** (`R-TUI-072`, `LLR-072.3`) | *"Exactly 5 ticks at 0/25/50/75/100 % of the span"* — of which **4 of 5 named addresses in no mapped range**. B's retired *"labels fit without overlap"* criterion was **vacuous**: `width: 1fr` children partition the row and **cannot** overlap, so the predicate was GREEN at 10 invisible labels. | Executed at Inc-4/Inc-5; the retirement census closed at **35 sites across 13 files**, every one read. | *"One tick label per emitted **run** start plus one for the last mapped byte"* + the legibility clause. **batch-47's process artifacts MARKED, not rewritten** (D-18). |

> **The Inc-2 counterpart is not an amendment but belongs beside them.** `safe_text`'s **docstring in shipped source** claimed it neutralised ANSI. Executed on the pre-change tree: `safe_text('sensor\x1b[31m_evil[red]')` returned the string **UNCHANGED** — ESC survived and 21 characters were billed for 16 visible. **That false claim had become NINE green acceptances DEFENDING it** — 9 nodes, 5 test files, 8 render surfaces, every one asserting a raw ESC byte rendered "verbatim" is safe, every one green against a guarantee the source never provided (Memory Map detail 1 · flow-result sinks + block label 2 · A2L tags cell 1 · Checks linkage + detail 1 · **patch screen 4, in a file nobody had identified**). All 9 were **ported, never deleted, never weakened** — each keeps its original equality or containment as a character-for-character **positive** claim, with the new no-residual-control clause co-asserted beside it, because an absence claim alone is green on an empty render.
> **A green suite is not evidence a guarantee holds; it can be evidence the guarantee's NEGATION has been ratified.**

---

### Write-time confirmation `[2026-08-03]`

Bounded re-runs on `claude/batch-77-closeout` (working tree = `244ecf2` plus untracked `prototypes/out/` and `.pyc` churn only). **The full suite was NOT re-run** — the close figure `2607 / 2 / 3` stands on the `2f427a9` gate run's own output.

| Command | Result | What it confirms |
|---|---|---|
| `pytest --collect-only -q` | **2612 tests collected in 1.79 s** | the close ledger, independently |
| `pytest test_tui_map_big.py test_tui_hostile_map.py test_map_click_chain.py -q` | **100 passed in 155.45 s**, exit 0 | 16 of the 20 Layer-B nodes and 24 of the 30 live TCs |
| `pytest test_tui_directionb.py test_tui_snapshot.py test_legend_two_pane.py -q` | **224 passed in 336.34 s (5:36)**, exit 0; snapshot report: **29 snapshots passed** | `AT-B77-05/06/07`, `TC-B77-10…15`, `LLR-111.9`'s own threshold, the **C-27 frozen dual guard**, all **29 snapshot baselines as full oracles** (0 xfailed, 0 xpassed — Inc-9's mark retirement holds), and the re-scoped `TC-519` |
| `grep` supersession sweep, 7 marker classes | all surviving refs **negative or documentary** | §Supersession table |
| `git show HEAD:…at-b77-02-gapless-band-strip.txt` | `[49,17]`@66 · `[37,13]`@50 · **0 CR bytes** | `AT-B77-02`'s stored-blob discipline holds under `core.autocrlf=true` |

**324 of 2612 nodes were re-observed at write time.** That is a deliberate subset — the two file groups that carry every Layer-B node and 30 of the 30 live TCs — not a full-suite re-run.

> 🛑 **Self-catch, recorded because this batch's own signature defect is a plausible sentence nobody executed.** The third row above was first written as *"462 passed in 1006.36 s (16:46)"* while the run was still in flight — a figure with the right **shape** and no producer. The run returned **224 passed in 336.34 s**. Corrected before this artifact was finalised, and left on the record rather than silently overwritten, because it is the same failure mode as **G-004** committed inside the document that reports **G-004**. *A report that work is in flight is exactly as unverified as any other plausible claim.*

---

### Evidence checklist — `qa-reviewer` (full)

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then | ✓ | `PLAN.md:61-70` — all 7 stories stated as *Given … when … the operator sees …*; `01-requirements.md` §3 HLR Statements carry the normative `shall` form |
| 2 | Test cases have explicit **Expected**, not vague "works" | ✓ | every Layer-A row carries a numeric threshold — e.g. `[49,17]`@66, `outside == 0`, `exactly 1 marker`, `0.0008%` at exactly 4 fractional digits, ceiling `7 @80×24 / 5 @120×30` |
| 3 | Edge cases include **empty, boundary, invalid, error** | ✓ | `TC-B77-01` empty · `TC-B77-02/03` boundary (incl. the domain edge **with a differing-size arm**) · `TC-B77-04` invalid (zero-byte run) · `TC-B77-05` error (`total_span ≤ 0`); mirrored per HLR at `TC-B77-06…09`, `16…20`, `21…24` |
| 4 | Regression checklist exists | ✓ | §Supersession (7 marker classes) + §5.3 criteria table + C-34 standing rule: full `test_tui_directionb.py` ∧ `test_tui_map_big.py` ∧ `test_map_click_chain.py` at **every** gate |
| 5 | Exit criteria stated | ✓ | §Batch acceptance criteria — 9 criteria, each with a verdict and evidence; restored at revision 4 after being **accidentally deleted** between rev 2 and rev 3 (*a batch that loses its own acceptance criteria during a split has no merge gate*) |
| 6 | No real PII / secrets | ✓ | fixtures only — `examples/case_00_public/prg.s19`, `case_02`, `case_08`, `case_07_stress_smoke`, and synthetic 768/256 + 26-region generators. The hostile-payload examples in `01-requirements.md` were **de-fanged at `d125ca1`**: 4× ESC, 1 BEL and a raw NUL replaced with escaped textual forms |
| 7 | Test results left **blank** unless actually run | ✓ | every result in this document cites either an increment gate run's own output or a `[re-derived 2026-08-03]` command in §Write-time confirmation. **No result is asserted without a run behind it.** The one figure whose producer was not on disk was reported as **G-004** rather than filled in; its provenance was then supplied by the orchestrator and it is closed **with its record defect named**, not quietly absorbed |
| 8 | **Layer B (black-box):** every output-producing story's deliverable observed through the SHIPPED surface with boundary + negative evidence | ✓ | §Layer B — 20 nodes, 7/7 stories, `repr·boundary·negative` ✓·✓·✓ on every row; deliverables include a **byte-exact file on disk** (`AT-B77-02`) and the **painted strip** (`AT-B77-15a/b`), not only in-memory objects |
| 9 | **Bidirectional surface-reachability** | ✓ | §matrix — **16/16** inputs and **11/11** deliverables through the handler; `AT-B77-15a/b` deliberately driven through **two** shipped drives (real `pilot.click` at Inc-2, auto-select at Inc-7) because the Inc-2-only form would have been green on an implementation with no scrub at all |
| 10 | **No unfilled template** | ✓ | no `<…>` placeholder, no `TC-NNN`, no empty required row survives in this artifact; every table row carries a value or an explicit `n/a` with a reason |
| 11 | Per-arm verdicts (CC-1), never an aggregate | ✓ | every AT parametrized over both regimes and reported per node per arm — load-bearing because `AT-B77-01`'s two regimes **redden on different limbs**, and an aggregate verdict destroys that distinction |

---

## Closing statement

Everything the batch set out to ship, shipped, and it is green: 7 HLRs, 27 LLRs, 30 live TCs, 20 Layer-B acceptance nodes, ledger `2519 → 2612` reconciling at every one of eleven points, frozen dual guard green throughout, 29 snapshots restored to full oracles with **0 xpassed**, and 0 blocker findings at the merge gate.

The honest verdict is **`PASS-WITH-NOTES`** and the notes are the informative part. Across four gate rounds, nine review passes, five specification revisions and thirteen operator rulings, this batch produced **zero** defects in shipped product code — and then exactly one, found by an environment slower than the dev machine, in a code path where **two** independent correctors both had to miss. Two of its PINs certify nothing on their own, and one of them certified nothing at all until Inc-8 executed the mutation the specification named and measured it **inert**. Three requirements were amended because they were **false**, not inconvenient. Five quoted figures in this batch were simply wrong. A sixth — **G-004** — turned out to be **right and unrecorded**, which is the harder failure: its producer was a real post-gate review that lives only in a session report. And a seventh was committed **inside this artifact** while writing it, caught and corrected in §Write-time confirmation.

Those last two are the same class, and it is the class this batch should be remembered for alongside the vacuous check: **the finding existed, the record did not.** Three occurrences here — the shell-quoting probe defect, `AT-B77-19`'s carry, and G-004's 660 160. *A figure whose producer is a session report has no producer as far as any later reader is concerned.*

The single most transferable finding is Inc-2's, and it is one layer below "false documentation misleads readers": **a false claim in shipped source gets encoded into the acceptances built to catch it, and those tests then defend the falsehood.** Nine green nodes across five files spent an unknown number of batches ratifying a guarantee `safe_text` never provided. The same shape recurred inside this batch's own fix — `BandBar`'s docstring gave the wrong reason for a true property — and was caught only because a reviewer measured 560 columns of content into a 66-column bar rather than reading the sentence.

**Recommendation:** proceed to Phase 5 (post-mortem). Carry **G-005** (`AT-B77-19` guards first render only) into the queue; route **G-003** to the registry lane. **G-004 is closed**, with its finding routed as a control candidate.

Two control candidates leave this phase, both proven by counterexample inside this batch:

1. **G-001 — a PIN's named mutation must be demonstrated to reach that PIN's own subject.** One mutation shared across two PINs is one unchecked claim, not two. `AT-B77-16` proved this by being certified by a mutation that could not move it.
2. **G-004 — a figure quoted into an artifact must name a producer that survives the session.** A commit body counts; `REQUIREMENTS.md` counts; a backlog lane counts. A session report does not. Three occurrences in one batch, one of them the orchestrator's own.
