# 01b — Validation Strategy — 2026-07-06-batch-26

> **Scope:** Feature #12(b) — entropy / data-classification viewer.
> US-035 (headless entropy/classification service) · US-037 (per-variant entropy section in the project report) · US-036 (entropy viewer modal).
> Author: qa-reviewer (Phase 1, concurrent with the architect's HLR/LLR in `01-requirements.md` — I do NOT edit that file). `AT-035*/037*/036*` (Layer B) + `TC-035*/037*/036*` (Layer A) numbering binds to the architect's §4 LLRs at Phase 2; all ids **provisional per V-5**.
>
> **Harness facts honoured throughout:** **pytest-asyncio is NOT installed** → every Pilot AT is a sync test wrapping `asyncio.run(_run())` (idiom `tests/test_tui_patch_layout.py:71-96`). Gate asserts are black-box (public return value / rendered widget text / disk file content); private-attr reads are diagnostics only; drive-level private-method calls are the ratified idiom (batch-23/24 precedent). Textual is pinned `textual==8.2.8` (batch-25) → Pilot geometry + SVG snapshots are reproducible.
>
> **Entropy is a pure arithmetic transform (eng-rule 5) → deterministic, no RNG.** This is the load-bearing testability fact of the whole batch: the service's outputs are *exact*, so ATs assert exact `H` values and exact band strings, never "non-empty". That is what makes the C-10 anti-vacuity discipline achievable here.

---

## 0. Substrate the strategy keys on (from `01-requirements.md` §2.0/§2.6, disk-verified)

- **`compute_entropy(mem_map)` does not exist yet** — US-035 introduces `tui/services/entropy_service.py` (outside the engine-frozen set). Its shipped surface is the public function/return type. Counterfactual for every `AT-035*` is therefore an **`ImportError` / `AttributeError` on the pre-fix tree** (the symbol is absent).
- **Windows are walked per contiguous range**, 256 bytes each; `ranges` are half-open `(start, end_exclusive)` and gaps are unmapped (`core.py:676-678`) — a window must NEVER straddle a gap. `ENTROPY_WINDOW_BYTES=256` + `ENTROPY_BANDS` are named constants (spike §2.6).
- **Estimator:** `H = -Σ p·log2(p)` over the 256-bin byte histogram, bits/byte on a 0–8 scale.
- **Bands (default cutoffs, DoR-approved):** `constant/padding H<1.0` · `low 1.0≤H<5.0` · `medium 5.0≤H<7.2` · `high/random H≥7.2`.
- **Low-sample policy:** the final partial window computes on the actual bytes present and is **tagged low-confidence when <64 bytes — never dropped**.
- **US-037 reuse (report):** `_entropy_lines(result) -> List[str]` appended in the per-variant loop **after `_hexdump_section`** (verified `report_service.py:1139-1147`; the loop body ends at `:1145-1147` and the file is written once at `:1157-1158`). New `ReportOptions.include_entropy: bool = True` following the `include_legend` precedent (verified guard at `report_service.py:1137`). Consumes `result.mem_map` (already flows via `capture_mem_map=True`).
- **US-036 surface:** `ModalScreen[None]` following `LegendScreen` (verified `screens.py:475`), pushed from an app action + key binding (`k`-key legend precedent). Geometry MEASURED (spike): **48 cols content @80×24 · 76 @120×30 — fits, no fallback rung**. Band colours are a NEW 4-colour map (grey/green/yellow/red) — **NOT** the severity `sev-*` classes (`color_policy.py` is severity-semantic; do not reuse).

---

## 1. Validation-method table (requirement → method → layer → rationale)

| Requirement area | Method | Layer | Rationale |
|---|---|---|---|
| US-035 per-window entropy + band classification (the AC) | **test** — pytest unit on `compute_entropy(mem_map)` with purpose-built `mem_map` | B (`AT-035a..e` GATE) | Deterministic arithmetic → exact `H` and exact band assertable through the public call. |
| US-035 window walk / range-per-range / gap non-straddle | **test** — unit | A (`TC-035.1`) | Structural invariant of the walk; unit over multi-range `mem_map`. |
| US-035 low-sample (<64B) confidence tag | **test** — unit | B (`AT-035d`) + A (`TC-035.3`) | Boundary policy; observed on the returned window's tag. |
| US-035 band cutoffs / boundary straddle | **test** — unit at the exact thresholds | A (`TC-035.2`, QC-3 catalog) | Off-by-`<`/`≤` at 1.0 / 5.0 / 7.2 is the highest-risk defect; pin each edge. |
| US-035 empty / no-mapped-bytes input | **test** — unit | B (`AT-035e` edge) + A (`TC-035.4`) | Degenerate input must return `[]` (or documented empty), no crash / no div-by-zero. |
| US-037 entropy section present in the WRITTEN report | **test** — Pilot/handler e2e → **re-read the written file from disk** (C-12) | B (`AT-037a` GATE) | Output-then-consume: the gate observes the shipped report handler's on-disk artifact, never a direct `_entropy_lines()` call. |
| US-037 `include_entropy=False` → section ABSENT | **test** — same handler, flag off, re-read disk | B (`AT-037b` GATE, per-branch C-10) | Both branches of the option must be observed; the absent-branch is load-bearing (proves the flag actually gates). |
| US-037 `_entropy_lines` formatting internals / budget / band-line shape | **test** — unit on the builder | A (`TC-037.1..3`) | White-box formatting; a GUARD, never the gate. |
| US-036 modal opens, strip renders coloured cells, jump list shows addresses | **test** — Textual `Pilot` `run_test(size=(W,H))` | B (`AT-036a` GATE) | The shipped surface is the modal; observe rendered cells + jump rows through Pilot. |
| US-036 non-default interaction (jump/select changes focus/scroll) | **test** — Pilot, drive off the default state | B (`AT-036b`, C-10 off-default) | C-10 requires exercising a non-initial state, not just first paint. |
| US-036 empty / single-window edge (no file / one window) | **test** — Pilot | B (`AT-036c` edge) | Degenerate render must not crash and must show the empty/edge affordance. |
| US-036 band→colour map (4 colours, distinct from `sev-*`) | **test** — unit on the colour map + **SVG snapshot** cells @80×24/120×30 | A (`TC-036.1`) + demo-artifact (snapshot) | Colour mapping is pure; snapshot is a regression artifact (batch-25 snapshot suite), non-gating for behavior. |
| Layout / geometry fit @80/@120 | **inspection/analysis** — spike MEASURED (Pilot), no fallback rung | — | C-13 discharged at spike (48/76 cols); no new arithmetic needed unless the prototype diverges. |
| Manual checks | **manual (non-gating)** — optional Phase-4 operator smoke: load an `examples/` case, open the entropy modal, eyeball band colours | manual | Nothing is manual-ONLY; all behavior is test-verified. |

**Two-layer split (explicit):**
- **Layer A (white-box, `TC-NNN` ↔ LLR):** unit tests of `entropy_service` internals (histogram, estimator, band cutoffs, window walk), the `_entropy_lines` report-builder, and the modal compose / colour map.
- **Layer B (black-box, `AT-NNN` ↔ story):** exercised through the SHIPPED surface — the public `compute_entropy(mem_map)` return value (US-035, a library so its surface IS the call), the handler-written report file re-read from disk (US-037, C-12), and the Pilot-driven modal (US-036).

---

## 2. Layer B — black-box AT catalog (provisional per V-5)

> Format per AT: **surface · inputs (incl. boundary + negative) · observed deliverable · counterfactual (RED-on-pre-fix-tree)**.
> Fixtures: US-035 uses **purpose-built in-memory `mem_map` dict literals** (preferred for exact-H — see §5); US-037/036 use tiny S19 images whose entropy profile is known (built from the same dict via `emit_s19_from_mem_map`).

### US-035 — entropy/classification service (surface = public `compute_entropy(mem_map)`)

**AT-035a — GATE — constant-fill run → band `constant/padding`, exact `H≈0.0`.**
- **Surface:** `entropy_service.compute_entropy(mem_map)` public return (list of window records).
- **Input:** `mem_map` = 256 addresses `0x1000..0x10FF` all mapped to the same byte, e.g. `{0x1000+i: 0xFF for i in range(256)}`. Single full window, one distinct symbol.
- **Observed deliverable:** exactly one window; its band == `constant/padding`; its `H == 0.0` (single-symbol histogram → `-1·log2(1) = 0`). Assert **exact 0.0** (or `abs(H) < 1e-9`), not merely `< 1.0`.
- **Counterfactual:** `compute_entropy` does not exist on the pre-fix tree → `ImportError` / `AttributeError`. The AT cannot even import → demonstrably fails today.

**AT-035b — GATE — maximum-entropy run → band `high/random`, exact `H==8.0`.**
- **Input:** `mem_map` = a 256-byte window containing **each byte value 0..255 exactly once**: `{0x2000+i: i for i in range(256)}`. Uniform histogram (256 bins × 1/256).
- **Observed deliverable:** one window; band == `high/random`; `H == 8.0` **exactly** (`-Σ (1/256)·log2(1/256) = log2(256) = 8.0`). Assert exact 8.0 (`abs(H-8.0) < 1e-9`). This is the anchor case — a hand-computable exact maximum.
- **Counterfactual:** same ImportError on pre-fix tree.

**AT-035c — GATE — mixed image with a known constant run AND a known high-entropy run (the US-035 AC verbatim).**
- **Input:** two contiguous ranges in one `mem_map`: range 1 = 256×`0x00` at `0x3000` (constant), range 2 = the 0..255 permutation at `0x4000` (max-entropy), with a **gap** between them (addresses `0x3100..0x3FFF` unmapped).
- **Observed deliverable:** exactly TWO windows (one per range — proves the gap is NOT straddled); window@`0x3000` band `constant/padding` H≈0.0; window@`0x4000` band `high/random` H==8.0. Each window record carries its own start address.
- **Counterfactual:** ImportError pre-fix. Post-fix, a *gap-straddling* bug would yield 1 window or a wrong H at the boundary → this AT discriminates it.

**AT-035d — GATE (boundary + low-sample) — final partial window <64B → low-confidence tag, computed on actual bytes.**
- **Input:** a range of 256+40 = 296 mapped bytes (`0x5000..0x5127`): one full 256B window + a **40-byte final window** (<64). Give the 40-byte tail a known composition (e.g. 20×`0xAA` + 20×`0xBB` → 2 symbols equiprobable → `H==1.0` exactly).
- **Observed deliverable:** two windows; window 2 covers exactly 40 bytes, its `H==1.0` (computed on the 40 present bytes, NOT padded to 256), and it carries the **low-confidence tag** (window 1, 256B, does NOT). Assert the tag field explicitly true/false on both.
- **Counterfactual:** ImportError pre-fix. Post-fix, a "drop short windows" bug loses window 2 (count would be 1) → discriminated; a "pad to 256" bug shifts H → discriminated by the exact `H==1.0`.

**AT-035e — edge — empty / no-mapped-bytes input → empty result, no crash.**
- **Input:** `compute_entropy({})` and `compute_entropy` over a `mem_map` with zero windows' worth of bytes.
- **Observed deliverable:** returns an empty list (documented empty), raises no exception, no division-by-zero. Positive assert on the empty return (load-bearing so it can't pass vacuously against a raised error).
- **Counterfactual:** ImportError pre-fix.

### US-037 — entropy section in the project report (surface = shipped report handler → written file)

**AT-037a — GATE (C-12 output-then-consume) — `include_entropy=True` → section present in the RE-READ file.**
- **Surface:** the shipped report generation handler with `ReportOptions(include_entropy=True)`; then **re-read the WRITTEN report file from disk** (`target.write_text` at `report_service.py:1158` returns the path — read THAT path back, never glob-reconstruct, never call `_entropy_lines` directly).
- **Input:** an active project + one variant. The drive **MUST run the real variant execution with `capture_mem_map=True`** over the AT-035c mixed image (a `constant/padding` region and a `high/random` region), so the shipped chain populates `VariantExecutionResult.mem_map` (the same source `_hexdump_section` reads) — the fixture does NOT hand-populate `mem_map`.
- **Precondition assert (capture-chain proof):** BEFORE generating the report, assert `result.mem_map` is **non-empty** on the executed variant result. This proves the capture plumbing (`capture_mem_map=True` → populated `mem_map`) end-to-end, so a fixture that populated `mem_map` OFF the shipped chain can't false-pass — the test verifies the plumbing, not just the formatter. (Cross-ref QR-4.)
- **Observed deliverable:** the re-read file text contains the per-variant entropy section heading under the correct `## Variant: <id>` block, with **band line(s) naming the expected bands** for the known profile (at least one `constant/padding` line and one `high/random` line, as the per-band **count summary** per the `_entropy_lines` format — LLR-037.2 band-count shape, NOT the address/`H=` form which is the US-036 modal jump-list shape). Assert on the disk text, per-variant-scoped.
- **Counterfactual — RED today:** with no entropy code, the handler writes no entropy section → the disk-read assertion (section heading + band lines) **fails on the pre-fix tree** (the deliverable is simply absent). Capture the failing run at Phase-2 authoring before Inc lands.

**AT-037b — GATE (per-branch C-10) — `include_entropy=False` → section ABSENT from the re-read file.**
- **Surface/input:** same handler + same fixture, `ReportOptions(include_entropy=False)`; re-read the written file.
- **Observed deliverable:** the entropy section heading is **absent** from the disk text; and the `include_entropy=False` report is **byte-for-byte equal** to a pre-feature reference report generated over the same project/fixture (matching LLR-037.3's byte-identical threshold — proves the flag suppresses ONLY entropy and adds zero incidental drift). This is not vacuous because the byte-equality against the reference asserts the surrounding sections are positively, exactly present.
- **Counterfactual:** pre-fix there is no section either way, so this branch passes trivially TODAY — therefore AT-037b is **paired with AT-037a** and only meaningful once the feature exists; the US-037 counterfactual is carried by AT-037a alone (absent deliverable). Flag AT-037b as the branch-completeness assert, not the sole gate.

### US-036 — entropy viewer modal (surface = Textual Pilot-driven `ModalScreen`)

**AT-036a — GATE — open modal via key binding → strip renders coloured cells + jump list shows addresses.**
- **Surface:** `S19TuiApp.run_test(size=(80,24))` (and `(120,30)`) inside `asyncio.run`; load a known image through the shipped load chain (`_parse_loaded_file` per artifact + apply, idiom `test_tui_app.py:1145-1194`); invoke the entropy action via its key binding (the `k`-legend precedent — key provisional per P-6, binds at Phase-1 assembly); `await pilot.pause()`.
- **Input:** the AT-035c mixed image (≥2 windows spanning ≥2 bands) so the strip must render at least two distinct band colours and the jump list must list ≥2 addresses.
- **Observed deliverable:** (1) the strip widget renders per-window cells whose Rich styles map to the entropy band colour map (assert the rendered cell style equals the entropy-colour for that window's band — semantic, not a raw `"red"` literal); (2) the jump-to-address list shows rows for the expected window start addresses (`0x3000`, `0x4000`) with their band + `H=` text (read-back from the jump list widget's rows).
- **Counterfactual:** the modal / action does not exist pre-fix → the key binding is unbound / `action_show_entropy` missing → the AT fails to open the surface today (`push_screen` target absent). Capture at Phase-2.

**AT-036b — GATE (C-10 off-default) — non-default interaction: jump/select a window → focus/scroll changes.**
- **Surface/input:** same modal, mixed image; after open, drive a **non-initial** interaction — select the second jump-list row (or press the jump key for `0x4000`) and `pilot.pause()`.
- **Observed deliverable:** the surface's observable state moved off the default — e.g. the focused/selected jump row index changed to the target, or the strip's highlighted/scrolled cell corresponds to `0x4000`. Assert the CHANGED state (before ≠ after), so a modal that renders but ignores interaction fails.
- **Counterfactual:** modal absent pre-fix (fails to open). Post-fix, a "renders but jump is a no-op" bug is discriminated by the before≠after assert.

**AT-036c — edge — no file loaded (or single-window image) → graceful empty/edge render.**
- **Surface/input:** (a) open the entropy modal with **no image loaded**; (b) open it with a single-window image (one 256B constant range → exactly one cell/one jump row).
- **Observed deliverable:** (a) the modal opens and shows an explicit empty affordance (no cells, no crash, no traceback) — positive assert on the empty-state text so it can't pass vacuously; (b) exactly one cell + one jump row rendered.
- **Counterfactual:** modal absent pre-fix.

**Snapshot artifact (non-gating):** SVG snapshot cells for the entropy modal @80×24 and @120×30, added to the batch-25 snapshot suite (`textual==8.2.8` pinned → reproducible). These are regression artifacts, xfail-until-baseline if the baseline is generated in-batch; the behavioral proof is AT-036a/b, not the snapshot (no fabricated local pass — batch-22 lesson).

---

## 3. Layer A — white-box TC skeleton (numbering binds to §4 LLRs at Phase 2)

### US-035 — `entropy_service` internals

| TC (prov.) | LLR (binds §4) | Asserts | Anchor / fixture |
|---|---|---|---|
| `TC-035.1` | window-walk LLR | Windows are cut **per contiguous range**, 256B each, and NEVER straddle a gap; a 3-range `mem_map` with gaps yields the exact expected window count + start addresses. | in-memory multi-range `mem_map`; gap semantics `core.py:676-678` |
| `TC-035.2` | band-cutoff LLR (QC-3) | Band assignment is correct AND correctly-sided at each threshold. **Direct band-classify injection (decoupled from histogram construction):** call the band-classification function with literal float inputs to pin the `[lo,hi)` cutoff side exactly — `0.9999→constant/padding`, `1.0→low`, `1.0001→low`; `4.9999→low`, `5.0→medium`, `5.0001→medium`; `7.1999→medium`, `7.2→high/random`, `7.2001→high/random`. Plus the histogram-derived cases: `H` just-below 1.0 → `constant/padding`, `H==1.0` → `low`; just-below 5.0 → `low`, `H==5.0` → `medium`; just-below 7.2 → `medium`. (`≤`/`<` per §0 cutoffs; the side-of-cutoff is now pinned by direct float injection, not "nearest constructible".) | literal float inputs to the band-classify fn + constructed histograms with hand-computed H (see §4 catalog) |
| `TC-035.3` | low-sample LLR | Window <64B carries the low-confidence tag; ≥64B does not; H is computed on actual bytes present (no zero-padding). | 40B + 256B windows |
| `TC-035.4` | degenerate-input LLR | `{}` → `[]`; a range shorter than 1 byte / no mapped bytes → empty, no div-by-zero; single-byte range → one window, tagged low-confidence, H==0.0. | empty + 1-byte `mem_map` |
| `TC-035.5` | constants LLR | `ENTROPY_WINDOW_BYTES==256` and `ENTROPY_BANDS` are the named constants with the documented cutoffs (pin the constant, guard against silent drift). | module constants |
| `TC-035.6` | estimator LLR | `H = -Σ p·log2(p)` matches a reference computation for a known multi-symbol histogram (e.g. 128×A+128×B → H==1.0; 4 symbols equiprobable → H==2.0). | constructed histogram |
| `TC-035.7` | LLR-035.5 (purity) | **Purity probe:** `rg -n "import textual\|from textual" s19_app/tui/services/entropy_service.py` returns **0 hits** — the service imports no Textual/UI symbol, keeping it a headless pure-arithmetic module. | grep over `entropy_service.py` |

### US-037 — `_entropy_lines` report builder (GUARD, never the gate)

| TC (prov.) | LLR (binds §4) | Asserts | Anchor |
|---|---|---|---|
| `TC-037.1` | `_entropy_lines` format LLR | Given a `result` with a known `mem_map`, `_entropy_lines(result)` returns a markdown heading + per-band **count summary** lines (band + window count, low-confidence flagged) per LLR-037.2 — NOT address/`H=` (that is the US-036 modal shape); **direct-call GUARD** (consumer-contract), explicitly NOT the gate (C-12: the gate re-reads the written file). | `report_service.py:1139-1147` insertion point |
| `TC-037.2` | `include_entropy` guard LLR | `ReportOptions(include_entropy=False)` → `_entropy_lines` not emitted into the line list; default `True` (mirrors `include_legend` `__post_init__` validation precedent). | `include_legend` guard `report_service.py:1137` |
| `TC-037.3` | budget LLR | Entropy lines consume the shared line budget like `_hexdump_section` (no unbudgeted growth; truncation appendix note if trimmed). | `budget.consume` `report_service.py:1132,1145-1147` |
| `TC-037.4` | confidentiality LLR | The entropy section reports bands/H only (no raw memory bytes beyond what the hexdump already emits); report still lands ONLY under the gitignored `.s19tool/<project>/reports/`; no new logging in the module. | F-S-07 precedent |

### US-036 — modal compose + colour map

| TC (prov.) | LLR (binds §4) | Asserts | Anchor |
|---|---|---|---|
| `TC-036.1` | band-colour-map LLR | The entropy 4-colour map (grey/green/yellow/red for constant/low/medium/high) is a pure function distinct from `color_policy.SEVERITY_CLASS_MAP`; each band → its own colour; **no `sev-*` class is consulted** (grep-guard). | `color_policy.py` NOT reused |
| `TC-036.2` | strip-compose LLR | Given N window records, the strip composes N cells with per-cell band styling + the documented cost caps (hexview cost-cap precedent `hexview.py:294-353`). | render precedent |
| `TC-036.3` | jump-list LLR | The jump list builds one row per window (`0xADDR  band  H=…`) ≈30 cols, fitting the 48-col @80 budget (spike geometry). | spike §2.6 (48/76) |
| `TC-036.4` | LLR-036.4 (e-binding) | **White-box registration guard (silent-unbind class, PRs #37/#38):** `"e" in S19TuiApp.BINDINGS` (or the app's binding registry) AND that key maps to `action_show_entropy` — pins the binding at registration, not just at open. **Complements AT-036a** (the black-box open through the key); AT-036a stays the gate. | `app.py` BINDINGS registry |
| `TC-036.5` | LLR-036.6 (cost cap) | **Cost cap:** on the `large_s19` stress fixture, the strip renders **at most `ENTROPY_STRIP_MAX_CELLS`** cells and the jump list **at most `ENTROPY_MAX_ROWS`** rows, and a truncation indicator is shown when the window count exceeds either cap. Assert the rendered cell/row counts are `<=` the caps (not merely the service window-count window). | `large_s19` (`conftest.py:301`); caps mirror `MAX_HEX_ROWS` |

---

## 4. QC-3 boundary / negative catalog (entropy thresholds — the highest-risk defect surface)

The band cutoffs are the off-by-`<`/`≤` trap. Each row below is a **hand-computable H** constructed from a byte histogram, so the assert is exact. `H(hist)` for a 256-byte window with symbol counts `c_i` is `-Σ (c_i/256)·log2(c_i/256)`.

| Case | Construction (256-byte window unless noted) | Exact H | Expected band | Which edge it pins |
|---|---|---|---|---|
| **B-min (constant)** | 256× one symbol | `0.0` | `constant/padding` | below the 1.0 floor |
| **B-just-under-1.0** | ~231× A + 25× B (H≈0.49) — any 2-symbol split with H<1.0 | `<1.0` | `constant/padding` | `H<1.0` lower band |
| **B-at-1.0** | 128× A + 128× B (2 symbols equiprobable) | `1.0` exactly | `low` | `1.0≤H` → `low` (the `≤` side) |
| **B-mid-low** | 4 symbols equiprobable (64 each) | `2.0` | `low` | interior of `low` |
| **B-just-under-5.0** | histogram tuned so H≈4.99 (e.g. skewed 24-symbol) | `<5.0` | `low` | upper edge of `low` |
| **B-at-5.0** | 32 symbols equiprobable (8 each) → `log2(32)` | `5.0` exactly | `medium` | `5.0≤H` → `medium` |
| **B-mid-medium** | 64 symbols equiprobable (4 each) | `6.0` | `medium` | interior of `medium` |
| **B-just-under-7.2** | tuned skew, H≈7.19 | `<7.2` | `medium` | upper edge of `medium` |
| **B-at-7.2** | **direct band-classify injection at literal `7.1999 / 7.2 / 7.2001`** (TC-035.2) pins the cutoff side; the histogram-derived just-below-7.2 case complements it | `7.2` (injected) | `high/random` | `7.2≤H` → `high` (side pinned by direct injection, no longer "nearest constructible") |
| **B-max (uniform)** | 256 symbols ×1 (0..255 permutation) → `log2(256)` | `8.0` exactly | `high/random` | above the 7.2 ceiling / max. *(8.0 < 8.000001 ceiling → inside `[7.2, 8.000001)` high band — deliberate headroom sentinel.)* |
| **N-low-sample** | 40 bytes (20×A+20×B) | `1.0` | `low` **+ low-confidence tag** | <64B tagging, no padding |
| **N-single-byte** | 1 byte | `0.0` | `constant/padding` + low-confidence | degenerate window |
| **N-empty** | `{}` mem_map | — | — (empty result) | no crash / no div-by-zero |
| **N-gap-straddle** | 2 ranges + gap | per-range | 2 windows, not 1 | window walk must not cross gaps |

> **Note on "just-under" rows:** the side-of-cutoff assertion is now pinned by **direct float injection** into the band-classify function (`TC-035.2`: literal `7.1999 / 7.2 / 7.2001`, and likewise at 1.0 and 5.0) — no longer "nearest constructible". The histogram-derived just-below rows remain as complementary end-to-end coverage, and the estimator TC (`TC-035.6`) independently pins H arithmetic. This decouples the cutoff-side proof from whether an exact-boundary histogram is constructible.

---

## 5. Fixture note (what each layer uses)

**Decision: US-035 exact-H layer uses purpose-built in-memory `mem_map` dict literals — NOT `large_s19`.** Verified against `tests/conftest.py`:
- `make_large_s19` fills every byte with `rng.randrange(0,256)` (`conftest.py:117`) → runs are *statistically* high-entropy but the histogram is **not uniform**, so H is ≈7.9-something, **not an exact assertable value**. Unusable for exact-H gates.
- **No existing fixture has a known constant-fill run** and none has a known-exact-H run. Confirmed by reading every generator.
- Therefore the exact-H ATs/TCs build a small `Dict[int,int]` literal inline (e.g. `{0x1000+i: 0xFF for i in range(256)}`, `{0x2000+i: i for i in range(256)}`). **This is the preferred, sanctioned approach** (the task brief and the deterministic-arithmetic property both call for it) — it is not an "ad-hoc large-file builder" (the CLAUDE.md prohibition is about *large stress* files; these are tiny exact-value dicts, same spirit as the existing `MEMORY_OVERLAP_PAIR` / `memory_change_factory` in-memory literals).

| Layer / need | Fixture | Verdict |
|---|---|---|
| US-035 exact-H (constant, max, mixed, low-sample, boundary catalog) | **AUTHOR** tiny in-memory `mem_map` dict literals per §2/§4 | AUTHOR (preferred — exact values) |
| US-035 multi-range / gap-non-straddle | in-memory `mem_map` with two ranges + gap, mirroring `RANGED_S19_RANGES` shape (`conftest.py:573-576`) | AUTHOR (in-memory) / optionally load `make_ranged_s19` for a real-parser variant |
| US-037 report over a known profile | build the mixed image via `emit_s19_from_mem_map` (`tui/changes/io.py`, builder idiom `test_tui_patch_editor_v2.py:101-107`) from the AT-035c dict, load through the shipped chain so `capture_mem_map=True` populates `result.mem_map` | REUSE emitter + load chain |
| US-036 modal render | same mixed image loaded via `_parse_loaded_file` + apply (`test_tui_app.py:1145-1194`) | REUSE load chain |
| Sync Pilot wrapper (no pytest-asyncio) | `tests/test_tui_patch_layout.py:71-96` (`asyncio.run(_run())`) | REUSE |
| Modal-open / key-binding drive precedent | `LegendScreen` open path (`k` key), `screens.py:475` | REUSE pattern |
| Stress guard (service must stay fast on a real image) | `large_s19` (`conftest.py:301`) — assert `compute_entropy` completes + returns the right window COUNT (not exact H) on 200×4KB; **AND (TC-036.5) the rendered strip is capped at `ENTROPY_STRIP_MAX_CELLS` cells / jump list at `ENTROPY_MAX_ROWS` rows with a truncation indicator — not just the service window-count window** | REUSE — no ad-hoc large builder |
| SVG snapshot baseline | batch-25 snapshot suite (`textual==8.2.8` pinned) | REUSE harness |

---

## 6. Testability risks (`QR-*`)

- **QR-1 — exact-H requires purpose-built fixtures, not `large_s19`.** RESOLVED by §5: random-fill gives non-exact H; the exact-value ATs use in-memory dicts. Do not attempt to assert exact H on any `make_large_*` output.
- **QR-2 — boundary at exactly 7.2 may not be constructible** from an integer 256-histogram. **RESOLVED by direct injection:** `TC-035.2` calls the band-classify function with literal floats (`7.1999 / 7.2 / 7.2001`, and at 1.0 / 5.0) so the cutoff side is pinned exactly — no longer "nearest constructible". The histogram-derived cases + estimator TC remain as complementary coverage; no irrational-exact-7.2 fixture is fabricated.
- **QR-3 — US-037 C-12 masking risk:** the gate MUST re-read the file written by the handler (`target` at `report_service.py:1158`), never call `_entropy_lines` directly and never glob-reconstruct the path. A direct-call test is `TC-037.1` GUARD only. Flagged so Phase-2 authoring can't collapse the gate into the guard.
- **QR-4 — `capture_mem_map` must be on** for US-037/036: the report/modal see `result.mem_map` only when `capture_mem_map=True` (`variant_execution_service.py:753-754`). If the drive loads without it, the entropy section is legitimately empty and the AT would false-pass on "no windows". Mitigation (strengthened): AT-037a drives the **real variant execution with `capture_mem_map=True`** and asserts `result.mem_map` is **non-empty as a precondition BEFORE report generation** (fixture must not hand-populate `mem_map` off the shipped chain), then asserts the *expected bands are present* (positive) in the re-read file. So both an empty-mem_map drive and an off-chain-populated fixture fail loudly — the AT proves the capture plumbing, not just the formatter.
- **QR-5 — Pilot geometry/timing:** missing `pilot.pause()` after open/interaction is the likely flake source (batch-24 QR-4 lineage). Every modal AT pauses after open and after each interaction. Snapshot cells only meaningful on pinned `textual==8.2.8`.
- **QR-6 — entropy colour map must NOT reuse `sev-*`:** `color_policy.py` is severity-semantic (`01-requirements.md` §2.6; frozen set). `TC-036.1` grep-guards that no `sev-*` / `css_class_for_severity` is consulted by the entropy render; the map is its own module symbol.
- **QR-7 — engine-frozen guard:** `entropy_service.py` is NEW and outside the frozen set; US-037 edits `report_service.py` (TUI-side, not frozen); US-036 edits `screens.py`/app (not frozen). Any diff in `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` trips `tests/test_engine_unchanged.py`. Confirm zero frozen-set diff at Phase-4.
- **QR-8 — pre-fix counterfactual capture:** `AT-035*` fail by ImportError, `AT-037a` by absent disk section, `AT-036a` by unbound action. Capture each failing run BEFORE the implementing increment merges (Phase-2 authoring), record into the batch evidence pack — an AT that can't be shown to fail today may not gate.

---

## 7. QA evidence checklist (Phase-1 state — C-10/C-12 discipline applied)

- [✓] **Acceptance criteria use Given/When/Then equivalents** — each AT states surface (Given the shipped call/handler/modal) / input incl. boundary+negative (When) / exact observed deliverable (Then), §2.
- [✓] **Test cases have explicit Expected, not vague "works"** — exact H (`0.0`, `1.0`, `2.0`, `5.0`, `6.0`, `8.0`), exact band strings, exact window counts, exact addresses named per AT/TC (§2, §3, §4).
- [✓] **Edge cases include empty, boundary, invalid, error** — empty `mem_map` (AT-035e/TC-035.4), the full band-cutoff boundary catalog (§4, QC-3), low-sample <64B (AT-035d), gap-straddle, single-byte, no-file-loaded modal (AT-036c).
- [✓] **Regression checklist exists** — engine-frozen guard (QR-7, `test_engine_unchanged.py`), `sev-*`-not-reused grep-guard (QR-6/TC-036.1), service purity probe (TC-035.7, `rg` import-textual → 0), `e`-binding registration guard (TC-036.4, silent-unbind class PRs #37/#38), strip/jump cost caps (TC-036.5, `ENTROPY_STRIP_MAX_CELLS`/`ENTROPY_MAX_ROWS`), `include_entropy` default+precedent (TC-037.2), stress-guard window count + capped strip on `large_s19` (§5), no-new-logging confidentiality (TC-037.4).
- [✓] **Exit criteria stated** — all GATE ATs (`AT-035a/b/c/d/e`, `AT-037a/b`, `AT-036a/b/c`) pass on the post-fix tree AND their counterfactuals demonstrably failed on the pre-fix tree (captured evidence, QR-8); full `pytest -q` green; 0 frozen-set diffs.
- [✓] **No real PII / secrets** — synthetic byte patterns (`0x00`/`0xFF`/permutations) and public `examples/` data only.
- [✓] **Test results section left blank** — nothing executed in Phase 1; no fabricated results (§8 below is empty by design).
- [✓] **Layer B black-box** — every output-producing story gated through the SHIPPED surface: the public `compute_entropy` return (US-035), the handler-WRITTEN report re-read from disk (US-037, C-12), the Pilot-driven modal (US-036); each with boundary + negative + counterfactual.
- [✓] **Bidirectional surface-reachability** — inputs (`mem_map`, project/variant, loaded image, key binding) exercised through the surface; outputs (window records, report file, strip cells, jump list) observed through the shipped surface, not the service API alone (US-037 observes the written FILE, not `_entropy_lines`; US-036 observes rendered cells, not the compose function).
- [✓] **No unfilled template** — one deliberate, named placeholder remains: `TC-035.x`/`037.x`/`036.x` ↔ LLR numbering binds to the architect's §4 at Phase 2 (V-5). The US-036 action key is provisional per P-6 (binds at Phase-1 assembly). Nothing else is templated; every AT/TC has concrete inputs + expected values.

## 8. Test-results section (blank — filled at Phase 3/4 by execution)

| AT/TC | Run | Result | Evidence |
|---|---|---|---|
| AT-035a (constant, H≈0.0) | | | |
| AT-035b (max, H==8.0) | | | |
| AT-035c (mixed, 2 bands, gap) | | | |
| AT-035d (low-sample <64B) | | | |
| AT-035e (empty) | | | |
| AT-037a (report section present, disk re-read) — pre-fix counterfactual | | | |
| AT-037a (post-fix) | | | |
| AT-037b (include_entropy=False → absent) | | | |
| AT-036a (modal opens, cells + jump) — pre-fix counterfactual | | | |
| AT-036b (non-default jump/select) | | | |
| AT-036c (no-file / single-window edge) | | | |
| TC-035.2 (band cutoffs — direct float injection 1.0/5.0/7.2) | | | |
| TC-035.7 (service purity — rg import-textual → 0) | | | |
| TC-036.4 (`e`-binding registration → action_show_entropy) | | | |
| TC-036.5 (strip/jump cost caps on `large_s19`) | | | |
| AT-037b (byte-for-byte equality vs pre-feature reference) | | | |
| Layer A suite (TC-035.*/037.*/036.*) | | | |
