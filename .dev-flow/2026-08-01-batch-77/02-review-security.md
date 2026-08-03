# Security Review — batch-77 Memory Map Variant A (Phase 2)

**Reviewer:** security lane · **Date:** 2026-08-01
**Subject:** `.dev-flow/2026-08-01-batch-77/01-requirements.md` (578 lines)
**Branch:** `claude/batch-77-memmap-variant-a` @ `37a83e1`
**Context read:** `00-measurements.md`, `docs/engineering-rules.md`, `prototypes/memmap_variant_a.HANDOFF.md`
**Probes:** read-only, `PYTHONDONTWRITEBYTECODE=1` (C-46). No file in the repo was modified by this review.

---

## BLUF

**Block on one finding, and it is an acceptance gap, not a code defect.**

The batch's four **new label surfaces** — fold marker, ruler labels, stats line, selection style — are
**provably free of file-derived text**. I verified each producer by execution; §6.3 **R-5's claim ("B3
holds by construction") is TRUE and I could not falsify it.** That is the clean half of this review.

The blocker is elsewhere. **`HLR-116` converts `#map_detail_body` — the map's only sink for A2L symbol
names and `ValidationIssue.code/.message/.symbol` — from click-gated to automatically populated on
every render**, on the core untrusted-firmware load path. R-5 does not cover this, because it is not a
*new label*; it is an **existing untrusted-text sink made newly reachable with zero operator input**.
The document's only treatment is one line in HLR-116's boundary catalog: *"N/A: reuses
`build_detail_text`, already C-17-hardened"*. Executed: that is **true for markup and false for ANSI**.

| # | Finding | Class |
|---|---|---|
| **B-1** | HLR-116 promotes the untrusted-text sink to the load path with **no hostile-input acceptance** | **BLOCKER** |
| **M-1** | `LLR-112.2`'s collapse acceptance is **vacuous**, and the ruler is the batch's one unbounded-cardinality surface | **MAJOR** |
| **M-2** | **C-42** — the spec's own grep census returns **0 hits** on a seventh site (`legend.py:613`) in a file absent from the whole document | **MAJOR** |
| m-1 | `LLR-117.2`'s "no `color:` property" is satisfiable by `text-style: reverse` | minor |
| m-2 | "executed census, six sites" under-counts its own prescribed grep (10 lines) | minor |
| — | C-27 frozen boundary · deleted test · colour discipline · secrets · supply chain · deploy | **CLEAN** |

**There is no secret, credential, network, dependency, external-tool or deploy surface in this batch.**
Everything below is C-17 / C-42 / resource-bound work on an untrusted-input render path.

---

## Scope reviewed

Requirements §1–§9; the seven HLRs and their 20 LLRs; the increment plan §7; Amendments A/B/C §6.5.
Code read on disk at `37a83e1`: `s19_app/tui/screens_directionb.py` (`safe_text:688`, `RegionRow:1088`,
`MapRuler:1234`, `_build_band_widgets:1988`, `build_stats_text:2275`, `build_detail_text:2338`,
`on_region_row_activated:2422`), `s19_app/tui/insight_style.py`, `s19_app/tui/legend.py`,
`s19_app/tui/styles.tcss`, `tests/test_map_click_chain.py:342-389`, `tests/test_tui_directionb.py`
(`_ENGINE_TEST_FILES:5494`), `tests/test_engine_unchanged.py` (`_ENGINE_PATHS:120`).

The six operator rulings (R1–R6) are **not re-litigated**. B-1 and M-1 are security *consequences* of
R-6 and R4 respectively, which is what I was asked to surface.

---

## Findings

### B-1 — HLR-116 makes the untrusted-text sink fire on load, with no hostile-input acceptance  [BLOCKER]

**What.** `HLR-116` / `LLR-116.2` require the panel to select a region and populate the inspector
**"without operator input"** on every render. The selection route is
`on_region_row_activated → build_detail_text → body.update(detail)`
(`s19_app/tui/screens_directionb.py:2464-2476`), and `build_detail_text` is the **one place on the
Memory Map that renders file-derived strings**: A2L symbol names via `symbol_list_text` (`:2397-2400`)
and `ValidationIssue.code` / `.symbol` / `.message` (`:2410-2417`).

Today that text reaches the screen only when the operator deliberately clicks a region row. After
batch-77 it reaches the screen **as a consequence of loading the file**. That is the change in
reachability, and it lands on the project's primary untrusted-input path.

**Where.**
- Requirement: `01-requirements.md:238` (HLR-116 Statement), `:396` (`LLR-116.2`), `:268` (the boundary catalog line that disposes of it as `N/A`)
- Risk register: `01-requirements.md:475` — `R-5 | Markup injection | B3 holds by construction — every new label is a count, an address or a constant`
- Sink: `s19_app/tui/screens_directionb.py:2397-2417`, reached from `:2464-2476`

**Why it matters — executed.** I ran the sink with a hostile A2L symbol set and a `ValidationIssue`
payload. Two different results, and the spec's `N/A` covers only one of them:

```
=== build_detail_text (the surface HLR-116 auto-populates) ===
type: Text
plain repr: 'Status: VALID\nCell: 0x80000000-0x800000FF\nRegion: 0x80000000-0x800000FF
 (256 bytes, valid) - sensor[red], x[link=file:///C:/Windows/System32]click[/link],
 boom\x1b[31mRED\x1b[0m\n0 issue(s) in this cell\n0 issue(s) in region'
spans: []

LITERAL? '[red]' present verbatim: True          <- markup guard HOLDS
LITERAL? link payload verbatim   : True          <- OSC-8 route HOLDS
ANSI ESC byte still in plain     : True          <- NOT scrubbed
```

Markup safety is real: `spans == []`, no `MarkupError`, `sensor[red]` and the `file://` link render
literally. **The batch-27 B-1 class does not reproduce here** — `safe_text` (`:688`) does its job, and
the spec is right that no new label flips `markup=False → True`.

The residue is ANSI, and it survives all the way to the **painted** layer, not just a Rich console:

```
=== Textual render_line strip (the painted layer, textual 8.2.8, 80x24) ===
segment texts: ['sym\x1b[31mRED\x1b[0m and [red]brk[/red]']
ESC byte present in painted strip: True
literal '[red]' present in painted strip: True
strip cell_length: 32          <- 25 visible cells; the 7 ESC chars are counted as width
```

Two consequences: a style leak into the terminal, and a **width miscount** — Textual bills the escape
bytes as cells, so a hostile symbol name also distorts the layout arithmetic that this entire batch
exists to reconcile.

The docstring at `screens_directionb.py:694-697` claims `safe_text` neutralises *"raw ANSI bytes carried
in the never-scrubbed `ValidationIssue.symbol` — no MarkupError, no style/ANSI leak"*. **The
markup half of that claim is true; the ANSI half is not.** Per the review brief:
`validation/model._scrub_issue_message` strips control chars but never touches `.symbol`, and the A2L
**name** path never reaches that scrubber at all.

**This is pre-existing.** Batch-77 does not introduce it. What batch-77 does is remove the click that
currently gates it. That is exactly the situation where an acceptance is owed rather than a
code change, and per the Phase-1 rule a hostile-input acceptance on a newly-reachable untrusted sink
is **mandatory at Phase 1, not deferrable**.

**Recommendation — one LLR and one AT, both cheap. Do not fix the code in this batch.**

1. Add **`LLR-116.6 — the auto-populated inspector is markup- and control-char-safe`** under HLR-116:
   > On a render that auto-selects a region, `#map_detail_body` **shall** render every file-derived
   > string (A2L symbol names, `ValidationIssue.code`/`.message`/`.symbol`) as literal content —
   > `render().spans == []`, no `MarkupError`, no OSC-8 hyperlink — and **shall not** emit any
   > `C0`/`C1` control byte into the painted strip.

2. Add **`AT-B77-15`** to HLR-116's acceptance list, parametrized over both sizes like every other AT:
   load a fixture whose A2L carries `sensor[red]`, `x[link=file:///…]click[/link]` and a raw
   `\x1b[31m`; render with **zero clicks and zero key presses**; assert on the painted layer:
   - the bracket and link payloads appear **verbatim** in `body.render().plain`;
   - `body.render().spans == []` (no style leak);
   - `"\x1b" not in "".join(s.text for s in body.render_line(row)._segments)` for every row — **this
     arm is RED today**, which is what makes the node a gate rather than a pin;
   - the render did not raise.

   Read the **painted strip**, not `render().plain`, for the control-char limb — `.plain` is where the
   byte lives, the strip is where it escapes.

3. **Correct the R-5 row** (`:475`). As written it certifies the *new labels*, which is true and which
   I confirmed, but it reads as if it certifies the batch. Restate it as: *"B3 holds for every new
   label surface (executed). **Separately**, HLR-116 promotes `build_detail_text` from click-gated to
   load-path-automatic — covered by `LLR-116.6` / `AT-B77-15`."*

4. **Carry the ANSI scrub itself** (Lane-A). Note for the carry: the fix site is **not frozen** —
   `safe_text` lives in `screens_directionb.py:688`, outside `_ENGINE_PATHS`. `_scrub_issue_message`
   in `validation/model.py` **is** frozen and is *not* the fix site here anyway, since the A2L name
   path never reaches it. A one-line control-char filter in `safe_text` would close it, but it drifts
   snapshot baselines and belongs in its own batch, not in Inc-5.

---

### M-1 — `LLR-112.2`'s collapse acceptance is vacuous, and the ruler is the batch's one unbounded-cardinality surface  [MAJOR]

**What.** R4 changes the ruler from a **constant 5** ticks (`MapRuler._TICK_COUNT = 5`,
`screens_directionb.py:1274`) to **one tick per mapped region start** (`LLR-112.1`, `:353`). Region
count is attacker-controlled. `LLR-112.2` (`:358`) requires overlapping labels to collapse, and its
numeric threshold is *"0 overlapping column ranges at both regimes; ≥2 labels retained"* (`:361`).

**That predicate cannot distinguish a collapsed ruler from an uncollapsed one.** Executed against a
`width: 1fr` ruler matching `MapRuler.DEFAULT_CSS` (`:1276-1286`) at 120 columns:

```
  N=   5 mounted=   5 zero-width=   0 max_w=24 OVERLAPS=  0  wall= 0.09s
  N=  50 mounted=  50 zero-width=   0 max_w= 3 OVERLAPS=  0  wall= 0.09s
  N= 300 mounted= 300 zero-width= 180 max_w= 1 OVERLAPS=  0  wall= 0.23s
```

At N=300 both limbs of the stated threshold are **GREEN**: `overlaps == 0`, and `300 >= 2` retained —
on a renderer that collapsed **nothing** and mounted every attacker-supplied address. `1fr` never
produces overlap; it produces **zero-width** children. Note also that at N=50 the 8-hex labels are
already truncated to 3 cells and the predicate is still green, so it does not even detect illegibility.

**Cardinality is unbounded and confirmed 1:1 with a hostile file.** `options.declared_regions` has no
count cap anywhere in the project (`DECLARED_REGION_NAME_MAX = 80` bounds a *name*), and runs come from
`_merge_band_runs` (`:435`) over `compute_entropy` windows with no cap either:

```
    100 scattered 1-byte ranges -> windows=   100  runs=   100  gaps=    99
   1000 scattered 1-byte ranges -> windows=  1000  runs=  1000  gaps=   999
   5000 scattered 1-byte ranges -> windows=  5000  runs=  5000  gaps=  4999
```

**Where.** `01-requirements.md:353` (`LLR-112.1`), `:358-361` (`LLR-112.2` + its threshold), `:176`
(`TC-B77-08`, "more regions than ruler columns → collapse"), `:146` (`TC-B77-03`, "more runs than
container columns").

**Why it matters.** Three things, in descending order:

1. **The acceptance is vacuous** — the dominant defect class in this project, and it lands here on a
   *spec*, as usual. `TC-B77-08` exists and is correctly *scoped*, but the predicate it inherits from
   `LLR-112.2` cannot fail on the case it names.
2. **The ruler goes O(1) → O(N)** in mounted widgets, on the one axis an attacker controls. The map
   was already O(N) in `BandSegment` + `RegionRow` + gap `Static`, so this is roughly `3N+5 → 4N` —
   an increase in an existing exposure, not a new class. That is why this is major, not a blocker.
3. **`LLR-111.2`'s 1-column fold marker is fine and needs no change.** Gap markers are already
   O(gaps) today and R-5 fixes each at 1 column; the fold *reduces* painted area. No finding.

**Recommendation.** Add an explicit **upper bound** to `LLR-112.2`'s threshold and to `TC-B77-08`, so
the collapse claim is falsifiable:

- `LLR-112.2` threshold, add: *"and `len(query('.map-ruler-tick')) <= bar_width // MIN_LABEL_CELLS`,
  where `MIN_LABEL_CELLS` is the 8-hex label width plus its separator"* — at the measured 21-column
  regime (P-31) that caps the ruler at ~2 ticks, which is also why the `≥2 retained` floor and this
  ceiling must be asserted **in the same node** (C-40: a floor alone is green on 300 ticks, a ceiling
  alone is green on zero).
- `TC-B77-08` must use a fixture with **runs ≫ container columns** (≥100), assert the widget-count
  ceiling, and assert **no tick has `region.width == 0`**. A zero-width tick is the observable that
  distinguishes "collapsed" from "mounted and squashed", and it is the one the current predicate misses.
- Read `LLR-112.1`'s *"one `.map-ruler-tick` per **retained** address"* as normative: **collapse before
  mount, not after.** Worth stating explicitly in the LLR so Phase 3 cannot satisfy it by mounting N
  and letting `1fr` squash them — which is precisely what the transcript above shows passing.

---

### M-2 — C-42: the spec's prescribed grep returns 0 hits on a seventh site, in a file absent from the whole document  [MAJOR]

**What.** `LLR-112.3` (`:363-367`) prescribes
`grep -rn 'LLR-072\.3\|exactly 5 tick\|_TICK_COUNT' s19_app tests REQUIREMENTS.md`
with the threshold *"0 surviving assertions of 'exactly 5 ticks'; 6 sites reconciled"*.

I ran the spec's own pattern, then ran a pattern that also catches the **word-spelled** form:

```
=== SPEC'S OWN PATTERN — misses it entirely ===
$ grep -c 'LLR-072\.3\|exactly 5 tick\|_TICK_COUNT' s19_app/tui/legend.py
0

=== WORD-SPELLED SWEEP — finds it ===
s19_app/tui/legend.py:613:  "address ruler — 5 ticks at 0/25/50/75/100 % of span (8-hex, no 0x prefix)"
tests/test_tui_snapshot.py:702:  "span-proportional widths + 5-tick address ruler + enriched "
s19_app/tui/screens_directionb.py:1238:  A single-row ruler of exactly five evenly-spaced tick labels at
s19_app/tui/screens_directionb.py:1294:  """Yield the five markup-safe tick labels across the span.
s19_app/tui/screens_directionb.py:1303:  ComposeResult: five ``.map-ruler-tick`` ``Static`` widgets.

=== legend.py anywhere in the 578-line requirements document? ===
$ grep -c "legend.py" .dev-flow/2026-08-01-batch-77/01-requirements.md
0
```

`s19_app/tui/legend.py:608-615` holds **two** stale artifacts, not one: a hardcoded sample ruler line
`"80000000      80004000      80008000      8000C000      8000FFFF"` (five evenly-spaced addresses),
and the caption `"address ruler — 5 ticks at 0/25/50/75/100 % of span"`.

**Where.** `01-requirements.md:365` (the six-site census), `:366` (the grep + threshold);
`s19_app/tui/legend.py:608-615`; the file appears **0 times** in the requirements document and **0
times** in the §7 increment plan.

**Why it matters.** This is a textbook C-42 miss — *the pattern was written against the readable form,
not against how the producers actually spell it*. Two concrete consequences:

1. **`AT-B77-07` will pass green while the legend screen lies to the operator.** HLR-114 (`:210`) PINs
   the legend screen with *"`pilot.press('k')` still pushes the legend screen and its body lists every
   band label"*. Band labels are exactly what will still be correct. The ruler caption — describing a
   contract Inc-3 retires — is not asserted by anything, so nothing reddens. The user-facing help for
   this very feature ends the batch describing the pre-batch behaviour.
2. **The `0 surviving assertions` threshold is unmeetable by the tool it names.** A reviewer running
   the spec's grep gets a clean board and misses the site.

**Also stale on the same screen and worth folding into the same edit** (not separate findings — same
file, same missed sweep): `legend.py:616` `"Region row (click to inspect + jump to hex)"` becomes
incomplete once HLR-115 adds arrows+Enter and HLR-116 auto-selects; the `↵ open hex` caption at
`:621-625` interacts with carry **C-77-f** (`o` descoped).

**Recommendation.**
- **Widen the pattern** in `LLR-112.3` to catch the word-spelled and hyphenated forms, e.g.
  `-iE 'LLR-072\.3|_TICK_COUNT|(exactly )?(5|five)[- ]tick|tick.{0,20}\b(5|five)\b|0/25/50/75/100'`.
  Re-run it and **re-derive the census count from the run** — do not carry "six".
- **Add `s19_app/tui/legend.py` to Inc-3's file list** (it is at 5 files today: `screens_directionb.py`,
  `REQUIREMENTS.md`, the batch-47 artifact, `test_tui_map_big.py`, `test_tui_snapshot.py`). It is **not
  frozen**, so this is in-scope; the ≤5-file cap needs the operator's call on how to split.
- **Give `AT-B77-07` a limb that reddens**: assert the legend body does **not** contain the retired
  contract string, co-asserted with the existing band-label presence clause (C-40 — the absence limb
  alone is green on a legend screen that failed to open).

---

### m-1 — `LLR-117.2`'s inspection arm admits `text-style: reverse`  [minor]

**What.** `LLR-117.2` (`:408`) requires the selection style to leave the band channel intact, and its
threshold is *"the CSS rule sets no `color:` property"*. Textual's `text-style: reverse` swaps
foreground and background **without declaring `color:`**, so it passes the inspection arm, and
`AT-B77-12`'s resolved triple would report the band colour unchanged in `styles.color` while the band
is visually inverted on screen.

**Where.** `01-requirements.md:408` (`LLR-117.2` threshold), `:282` (`AT-B77-12`'s companion
`inspection` arm); band rules `s19_app/tui/styles.tcss:665-679`.

**Why it matters — and why it is only minor.** C-10 designates the **glyph** (`· ░ ▒ ▓`) as the
colour-blind cue, and the glyph survives `reverse` untouched. The accessibility guarantee therefore
holds either way; only the colour channel's *meaning* is at risk. Colour discipline is otherwise
correct in this batch: `styles.tcss:665-679` sets `color:` and nothing else, and the spec correctly
routes selection through a class rather than an inline style.

**Recommendation.** Widen the inspection arm from *"sets no `color:`"* to *"sets no `color:` and no
`text-style` containing `reverse`"*, or assert the resolved `(background, color)` pair is
band-token-invariant across selected/unselected rows of the **same** band.

### m-2 — the "executed census, six sites" under-counts its own grep  [minor]

`01-requirements.md:365` lists six sites. The prescribed grep returns **10** text-file lines: the six
listed, plus `screens_directionb.py:1274/:1312/:1313` (the constant and its two uses) and
`tests/test_tui_map_big.py:140` (`assert len(ticks) == 5`, the live assertion). The last is covered
elsewhere by Amendment A (`:509`) and the code sites are the subject of `LLR-112.1`, so nothing is
actually unowned — but the *"6 sites reconciled"* threshold is not the number its own command produces.
Re-derive it from the widened run in M-2 rather than editing the figure.

---

## Checks that came back CLEAN

**C-17 — every new label surface is count/address/constant. Executed, could not falsify.**
This was the highest-value check and R-5's claim survives it. No new surface flips `markup=False → True`
and none interpolates file-derived text into a markup-parsed string.

| New surface | Producer | Evidence |
|---|---|---|
| Fold marker (`LLR-111.2`) | `_MAP_GAP_HATCH * 1`, `screens_directionb.py:253`/`:2062` | module constant × int; no file-derived input |
| Ruler labels (`LLR-112.1`, R4) | `safe_text(f"{addr:08X}")`, `:1318` | `f"{addr:08X}"` over `0`, `0x07FFFF3D`, `2**32-1`, `2**64`, `-1`, `-2**31` → **illegal chars `[]` in all 6** |
| Stats line (`HLR-113`) | `Text.append` + `human_bytes(int)`, `:2303-2310`, `insight_style.py:124` | `human_bytes` over `0…2**80` and `-1` → **illegal chars `[]` in all 9**; every `CoverageStats` field is `int`/`float` (`:966-986`) |
| Stats sink | `Text.append(str)` | `Text().append("[red]64.0 MiB[/red]")` → `spans == []`, literal. **`append` never markup-parses** |
| Selection style (`HLR-117`) | CSS class token | style-only; no text sink |
| `RegionRow` focusability (`HLR-115`) | `can_focus` / `BINDINGS` | no render surface; adds no tooltip |

**C-42 — emitted-form discipline is otherwise correct.** `LLR-111.4` (`:331`) explicitly forbids
comparing the golden against snapshot-export bytes (`&#160;`) and against a raw console `print`
(the cp1252 `UnicodeEncodeError` self-catch at F-1(a)), and requires `-text` in `.gitattributes` —
all three traps correctly pre-empted. `HLR-113` (`:189`) requires expected strings be **computed**
via `human_bytes(...)` rather than hand-typed. I also probed the one remaining trap in `AT-B77-05`
and it is **not** a trap: `#map_stats_body.render()` returns a `Text`, and Rich `Text` implements
`__contains__` correctly (`"Coverage: 0.00%" in t` → `True`, `"NOT PRESENT" in t` → `False`), so the
substring clauses work as written. The only C-42 failure in the batch is M-2.

**C-27 frozen-engine boundary — clean on both halves.** No file in the §7 increment plan intersects
either set. Verified against the live lists, not the brief:
- `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120-130`): `core.py`, `hexfile.py`, `range_index.py`,
  `validation/`, `tui/a2l.py`, `tui/mac.py` — **0 intersections**.
- `_ENGINE_TEST_FILES` (`tests/test_tui_directionb.py:5494-5504`, 9 files) — **0 intersections**. The
  batch's three test hosts (`test_tui_map_big.py`, `test_map_click_chain.py`, `test_tui_directionb.py`)
  and `test_tui_snapshot.py` are all non-frozen siblings. `AT-B77-15` (B-1) routes to
  `test_tui_map_big.py`, also non-frozen.
- `s19_app/tui/legend.py` (M-2) and `safe_text` in `screens_directionb.py` (B-1's carry) are **not**
  frozen — both fixes are in-scope when the operator wants them.

**Deleted test carries no security observable.** `tests/test_map_click_chain.py:342-389` asserts exactly
two things: `bar_width < _BAND_BAR_WIDTH` and `outside_count > 0` — a pure geometry premise pin. Its own
docstring sanctions the deletion verbatim (`:380-384`), and `outside_count` survives **inverted** in
`AT-B77-03`. Amendment C (`:517-527`) handles this correctly, including the C-40 limb-2 replacement
table. Nothing security-relevant is dropped.

**No other attack surface exists in this batch.** No secret, credential, token, `.env`, key or signed
URL is touched or introduced. No MCP / Composio / n8n / third-party connector. No network call, no new
outbound action, no new dependency or lockfile change, no destructive command, no auth flow, no
migration, no deploy or release surface. Snapshot regen (Inc-7) is correctly confined to canonical CI.
No client data leaves the local system — LFPDPPP is not engaged; fixtures are the public `examples/`
triple plus deterministic in-test builders (`tests/test_tui_map_big.py:10`).

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Each finding has what · where · why · recommendation | ✓ | B-1, M-1, M-2, m-1, m-2 all four-part |
| Each finding has a severity rating | ✓ | 1 blocker · 2 major · 2 minor |
| No secret values appear in this output | ✓ | No secret exists in scope; nothing redacted because nothing was found |
| Verdict is explicit | ✓ | §Verdict — Block, with the mitigation listed |
| New tool/integration scope + blast radius addressed | ✓ | **N/A, stated:** batch adds no external integration; blast radius assessed for the one *reachability* change instead (B-1) |
| Untrusted-render-mode check executed, not asserted | ✓ | 6 producers probed; `build_detail_text` probed with bracket/link/ANSI payloads; painted strip read via `render_line` |
| C-42 emitted-form check executed | ✓ | Spec's own grep re-run (`legend.py` → 0 hits); `Text.__contains__` probed |
| Resource/DoS surface measured, not assumed | ✓ | Run cardinality 100/1000/5000; ruler predicate N=5/50/300 |
| Frozen boundary verified against the live lists | ✓ | `_ENGINE_PATHS:120-130`, `_ENGINE_TEST_FILES:5494-5504` |
| Deleted test inspected for dropped observables | ✓ | `test_map_click_chain.py:342-389` read in full |
| Probes read-only, no repo file modified | ✓ | `PYTHONDONTWRITEBYTECODE=1`; scratch scripts only; `git status` unchanged |

---

## Verdict

- [ ] OK to ship
- [ ] OK to ship with the listed mitigations applied first
- [x] **Block — B-1 must be closed before Phase 3 opens**

**B-1 blocks.** Not because the code is unsafe — the markup guard holds and I proved it — but because
`HLR-116` moves an untrusted-text sink onto the load path and the document carries **no acceptance for
it**. Under the Phase-1 rule a hostile-input AT on a newly-reachable untrusted sink is mandatory now,
and it is genuinely cheap: one LLR (`LLR-116.6`), one AT (`AT-B77-15`) in a non-frozen file, and a
three-word correction to the R-5 risk row. **No code change is required in this batch** — the ANSI
scrub is a Lane-A carry with a non-frozen fix site.

**M-1 and M-2 do not block but should land in Phase 1**, because both are cheapest to fix in the
document and both are the *vacuous check in a spec* pattern this project keeps paying for. M-1 is one
extra clause in `LLR-112.2`'s threshold plus a real fixture in `TC-B77-08`. M-2 is a widened grep, one
extra file in Inc-3, and one reddening limb on `AT-B77-07`.

**m-1 and m-2 are recommendations only.**

**On re-review:** send back only the diff to §3 HLR-116, §4 `LLR-112.2` / `LLR-117.2`, §6.3 R-5, and
`LLR-112.3`'s pattern + census. I do not need to re-read the document.
