# batch-77 — Phase-0 measurements & premise evaluation (C-43)

**Batch:** `2026-08-01-batch-77` · **Charter INPUT:** `prototypes/memmap_variant_a.HANDOFF.md`
**Base:** `origin/main` @ `f8747b8` · **Branch:** `claude/batch-77-memmap-variant-a`
**Flow:** `2026.07.28-rev1`, controls C-1…C-45 (currency verified below)

---

## BLUF

**The charter's engineering direction survives execution; two of its acceptance-layer claims do not, and one real defect it never names was found.**

- ❌ **S-2 cites `LLR-072.3`, an id that does not exist in `REQUIREMENTS.md`.** The clause lives in `R-TUI-072` and is guarded by a **shipped, passing** acceptance `AT-072b` that asserts *exactly 5 ticks*. S-2 is therefore not a wording amendment — it **invalidates a live acceptance test**.
- ❌ **Draft acceptance #1 is VACUOUS.** *"every region ≥1 visible bar column"* is **already TRUE** on the pre-change tree: `screens_directionb.py:2066` floors every run at `max(1, …)`. Measured: all five regions render at exactly 1 column **today**. The predicate is invariant under the change it gates (**C-40 limb 1**).
- 🆕 **NEW defect, uncharted: the band bar OVERFLOWS its own budget.** Measured **64 columns emitted against `_BAND_BAR_WIDTH = 60`**, because all 9 segments independently floor at `max(1, …)`. Any S-1 design must state its column budget and whether it can overflow.
- ✅ The charter's headline measurement reproduces **exactly**: 5 regions, **1030 B** mapped, **128.0 MiB** span, **59** gap-hatch columns.

**The real S-1 defect, precisely stated (the charter states it imprecisely):** the bar does not fail to *show* the regions — it fails to **discriminate** them. Runs of **256 / 256 / 256 / 200 / 62 B** all render at **exactly 1 column**, and 59 of 64 columns (92 %) are gap hatch. "Every region ≥1 column" is the wrong acceptance; **"a region's width orders with its mapped size"** is the property that is actually absent.

---

## §1 Base currency & flow currency

| Check | Verdict | Executed evidence |
|---|---|---|
| RC-1 merge-base == `origin/main` tip | ✅ | `git rev-list --left-right --count main...origin/main` → `0	0`; tip `f8747b8` |
| Batch number free | ✅ **77** | highest on disk `.dev-flow/2026-07-31-batch-76`; `git branch -r` has no `batch-77`. Derived from disk + origin, **not memory** (two prior collisions) |
| Prior batch terminal | ✅ | `state.json` `phase_status: synced`, `obsidian_synced: true` |
| Toolchain entry gate | ✅ | Python **3.14.4** · pytest **8.4.2** · ruff **0.15.17** |
| Flow currency (C-45 PULL) | ⚠️ **mismatch, scoped, NON-BLOCKING** | aggregate `896dcca61cf68d78` vs manifest `0127a2767ff11c8a`. **Per-file re-executed:** all 11 control-bearing command/template files **byte-exact**. Sole divergence `skills/dev-flow-lessons/SKILL.md` local `01d608bb14069613`/641 lines vs stamped `5c47db86ac2cf4ae`/620 — local is **AHEAD**. The enforceable surface is current. |

The flow-currency verdict was **re-executed**, not inherited from batch-76's identical note — a citation of another document is not evidence (C-43).

---

## §2 Premise table — charter claims executed against disk

Tier: **1** axiom (validated+verified) · **2** hypothesis (this batch/charter introduces) · **3** premise (claim about the world).

| # | Premise (as the charter states it) | Tier | Verdict | Executed evidence |
|---|---|---|---|---|
| P-1 | Band widths scale over the full address span, `round(60·run/total_span)` at `screens_directionb.py:2066` | 3 | ✅ **TRUE** | `:2066` = `seg_width = max(1, round(_BAND_BAR_WIDTH * run_bytes / total_span))`; `_BAND_BAR_WIDTH = 60` at `:230`. The `60` is a **named constant**, not a literal. |
| P-2 | Shipped demo: 5 regions, 1 030 B, ~128 MiB span → ≈59 `╱` columns | 3 | ✅ **TRUE** | Executed render: `mapped=1030 B, span=134217534 B (128.0 MiB), GAP columns = 59`. Reproduces exactly. |
| P-3 | "…with all five regions in a **1-column sliver**" | 3 | ⚠️ **IMPRECISE** | Measured `per-run widths = [1, 1, 1, 1, 1]` = **5 columns**, one per region — not a collective 1-column sliver. The defect is non-discrimination, not invisibility. |
| P-4 | **Draft acceptance #1** — "every region ≥1 visible bar column (today: 1-col sliver total)" | 2 | ❌ **FALSE / VACUOUS** | `min run width = 1 → every region >=1 col? **True**` on the **pre-change** tree. The `max(1, …)` floor guarantees it unconditionally. **Cannot go RED**; violates C-40 limb 1. |
| P-5 | S-2 "amends **LLR-072.3**" | 3 | ❌ **FALSE** | `LLR-072.3` has **0** definitions in `origin/main:REQUIREMENTS.md`; the only `LLR-072.x` hits are inside the *range string* `LLR-072.1–074.3`. The clause is in **`R-TUI-072`** (`REQUIREMENTS.md:4787`). The id is cited in `tests/test_tui_map_big.py:118` — a **dangling reference**, which is where the charter took it from. |
| P-6 | Ruler amendment is a wording change | 2 | ❌ **FALSE — understated** | `R-TUI-072` mandates *"exactly 5 tick labels at 0/25/50/75/100 %"*, guarded by **live** `AT-072b` (`tests/test_tui_map_big.py::test_at072b_ruler`, asserts `len(ticks) == 5`). S-2 **breaks a shipped acceptance** → requires a §6.5 Before/After amendment **and** an AT re-derivation. |
| P-7 | Draft acceptance #3 — "3 of 5 ruler labels name an unmapped address" | 2 | ✅ **TRUE** | ticks `['00000000','01FFFFCF','03FFFF9F','05FFFF6E','07FFFF3E']`; ticks 2/3/4 fall in gaps. |
| P-8 | S-3 — stats shows "Coverage: 0.00%" + raw-byte readouts | 3 | ✅ **TRUE** | `#map_stats_body` renders `Coverage: 0.00%  Bytes covered: 1030 / … / Largest gap: 67108408 bytes`. True coverage is `0.000767 %`; `f"{…:.2f}%"` (`:2304`) flattens it to `0.00%`. Largest gap is raw, un-humanized. |
| P-9 | S-4 — a 4-row always-on legend sits in the map body | 3 | ✅ **TRUE** | `legend rows = 4` (`.map-legend-row`), built at `:2084-2104` into `.map-band-legend`. |
| P-10 | S-5 — region rows are not keyboard-reachable | 3 | ✅ **TRUE** | `focusable_rows = 0` of 5 `RegionRow`s; `app.focused` is `RailItem`, never the map. |
| P-11 | S-6 — inspector is empty until a click | 3 | ✅ **TRUE** | `#map_detail_body` = `"Click a region to inspect it - double-click to open in hex."` with a file fully loaded. |
| P-12 | S-7 — no selection class on rows | 3 | ✅ **TRUE** | `row_classes = [['map-region-row','band-constant'], ['map-region-row','band-medium'], …]` — band + base only, no selection marker. |
| P-13 | Fold markers must not be `RegionRow`s; `BandSegment` is the sibling precedent | 1 | ✅ **TRUE** | `class RegionRow(Static)` `:1088`, `class BandSegment(Static)` `:1172` — **siblings**, neither subclasses the other. `tests/test_tui_map_big.py:177,226` do `app.query(RegionRow)`. Charter's `:1185-1190` has **drifted** (backlog warns line numbers are stale in both directions). |
| P-14 | Gaps are already inert `Static`s | 3 | ✅ **TRUE** | measured `segments=9`, `BandSegment=5`, `RegionRow=5` → the 4 gaps are plain `Static`s already. The invariant is **preserved by construction**, not newly imposed. |
| P-15 | 🆕 **NOT IN THE CHARTER** — the bar fits its 60-column budget | 3 | ❌ **FALSE** | Measured `TOTAL columns = 64` vs `_BAND_BAR_WIDTH = 60`. Nine segments each floored at `max(1, …)` sum past the budget. **Identical at 80×24 and 120×30.** |

**Score: 15 evaluated · 9 TRUE · 4 FALSE · 1 IMPRECISE · 1 new defect found.**

---

## §3 The executed measurement

Fixture (re-derived, not copied from the prototype): 5 regions at
`0x00000000/0x01000000/0x02000000/0x04000000/0x07FFFF00`, sizes `256/256/256/200/62` B,
alternating constant-`0xFF` and pseudo-random fills so ≥2 entropy bands are present.
Driven through the **shipped** surface (`App.run_test` → `action_show_screen("map")` →
`update_memory_map`), never by calling the builder directly (C-35).

```
FIXTURE: 5 regions, mapped=1030 B, span=134217534 B (128.0 MiB), coverage=0.000767%

=== size=(80, 24) ===                    === size=(120, 30) ===
  segments=9  BandSegment=5                segments=9  BandSegment=5
  RegionRow=5  focusable_rows=0            RegionRow=5  focusable_rows=0
  GAP columns  = 59                        GAP columns  = 59
  RUN columns  = 5   widths=[1,1,1,1,1]    RUN columns  = 5   widths=[1,1,1,1,1]
  TOTAL columns= 64  (_BAND_BAR_WIDTH=60)  TOTAL columns= 64  (_BAND_BAR_WIDTH=60)
  min run width= 1  -> every region >=1 col? True
  ruler ticks  = 5: ['00000000','01FFFFCF','03FFFF9F','05FFFF6E','07FFFF3E']
  legend rows  = 4
```

**Both regimes are byte-identical** — the defect is width-independent, so a
narrow-vs-wide split buys nothing here.

---

## §4 Self-caught probe defect (recorded, not hidden)

My first stats/inspector probe queried `#map_stats` and `#map_detail` and got back
`<textual.renderables.blank.Blank object …>` for both. Those ids are **containers**;
the text lives in `#map_stats_body` / `#map_detail_body`. Had I taken the `Blank`
result at face value I would have recorded "stats pane renders nothing" as a finding —
a **false** one.

This is **C-32/C-37 in its exact shape** (*read the render layer that HOLDS the fact*),
landing in my own Phase-0 probe rather than in a test. It is also the reason the probe
prints raw `render()` output rather than a boolean: an impossible-looking value is
visible, whereas a plausible one would not have been. Consistent with the project's own
finding that the probes which get caught are the ones returning *impossible* values.

---

## §5 Consequences for Phase 1 (not decided here — Phase 1 owns them)

1. **Draft acceptance #1 must be re-authored.** The property with discriminating power is
   *width monotonicity*: for runs `a`, `b` with `bytes(a) > bytes(b)`, `cols(a) ≥ cols(b)`,
   **and** at least one strict inequality across the sparse fixture. Today all widths are
   equal, so this goes **RED** on the pre-change tree — which #1 provably cannot.
2. **S-2 needs a §6.5 Before/After amendment against `R-TUI-072`**, plus a re-derived
   `AT-072b`. The dangling `LLR-072.3` citation in `tests/test_tui_map_big.py:118` should be
   corrected in the same edit.
3. **The 64-vs-60 overflow (P-15) needs a scope ruling**: fold it into S-1 (it is the same
   `max(1, …)` arithmetic) or register it as a carry. Recommendation: **fold** — S-1 rewrites
   exactly this expression, and leaving a known overflow in code being rewritten is how a
   defect becomes someone else's premise.
4. **`tests/test_tui_map_big.py` is the blast-radius centre**: it hosts `AT-072a`, `AT-072b`,
   the `query(RegionRow)` counts, and `AT-073`/`AT-074`. Per **C-26** every touched symbol
   (`RegionRow`, `.map-band-seg`, `.map-ruler-tick`, `.map-legend-row`, `#map_stats_body`)
   gets a reverse-grep across the whole `tests/` tree before any increment lands.

---

## §6 Working files (C-44 — reconciled at close)

| File | State |
|---|---|
| `prototypes/memmap_variant_a.*` (5) + `memmap_redesign.proposals.html` | 📋 untracked, **to be committed in this batch's PR** (charter §1, `legend_n8.*` precedent) |
| `prototypes/out/` | 📋 untracked, **PRE-DATES this session** — reported as found, not swept (C-44) |
| `.dev-flow/2026-08-01-batch-77/**` | 📋 in progress |
| scratchpad `measure_sparse.py`, `measure_stats.py` | 🗑️ throwaway probes outside the repo tree; their **output is transcribed above**, which is the artifact that matters |
