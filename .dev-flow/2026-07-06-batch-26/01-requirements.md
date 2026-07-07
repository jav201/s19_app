# 01 — Requirements — 2026-07-06-batch-26

> **Batch objective:** Feature #12(b) — Entropy / data-classification viewer. Closes feature #12 (a+c shipped batch-24).
>
> Language: **en** · Flow: `/dev-flow` · Branch: `claude/hungry-burnell-b75534` off `origin/main 6341fd7` (RC-1 PASS; per-story already-shipped grep PASS — net-new).

## 2.0 Substrate (Phase-0 spike, verified)

- `LoadedFile.mem_map: Dict[int,int]` — sparse address→byte (`models.py:44`). `ranges: List[Tuple[int,int]]` contiguous, **half-open `(start, end_exclusive)`** (`models.py:46`; built `core.py:503-514` as `(start, prev+1)`). Iterating `range(start, end)` → every address present in `mem_map`.
- **Gaps between ranges are unmapped** (`core.py:676-678`). Windows MUST be walked *per contiguous range*, never over the whole address span.
- Report consumer already carries the data: `VariantExecutionResult.mem_map` (`variant_execution_service.py:597`), populated from `loaded.mem_map` when `capture_mem_map=True` (`:753-754`) — the exact source `_hexdump_section` reads (`report_service.py:907`). No new capture plumbing.
- Entropy = pure arithmetic transform → deterministic, no RNG (eng-rule 5). New `tui/services/entropy_service.py` is **outside** the engine-frozen set.

## 2.6 Story intake & refinement (Phase 0)

**US-035 — Entropy/classification service, headless (b-1) — `SPIKE → READY` (spike resolved)**
> A service computes per-window Shannon entropy over the loaded image's mapped ranges and classifies each window into a band (constant/padding · low · medium · high/random-encrypted).
- INVEST: independent ✓ · small ✓ (1 inc) · testable ✓ (deterministic → exact-H assertions on `large_s19`/`make_large_s19` fixtures) · valuable ✓ (prereq for US-036/037).
- **Spike-resolved algorithm:** 256-byte windows walked per contiguous range; `H = -Σ p·log2(p)` over the 256-bin byte histogram, bits/byte on a 0–8 scale; 4 bands with default cutoffs `constant/padding H<1.0 · low 1.0≤H<5.0 · medium 5.0≤H<7.2 · high/random H≥7.2` (encode as named `ENTROPY_WINDOW_BYTES` + `ENTROPY_BANDS` constants). Partial final window: compute on actual bytes present; **tag windows below a min sample count (~64) as low-confidence, do not drop**.
- **AC (black-box):** given a fixture with a known constant-fill run and a known high-entropy run, the service returns windows whose bands are `constant/padding` and `high/random` respectively, with H values matching the hand-computed expectation.

**US-037 — Entropy section in the project report (b-3) — `READY` (blocked by US-035)**
> The project report gains a per-variant entropy/classification section.
- INVEST: small ✓ (1 inc) · zero geometry · testable ✓. Depends on US-035.
- **Reuse:** `_entropy_lines(result) -> List[str]` appended in the per-variant loop (`report_service.py:1139-1147`, after `_hexdump_section`); new `ReportOptions.include_entropy: bool = True` following the `include_legend` precedent (`:197` + `__post_init__` validation `:231-235`); consumes `result.mem_map` (already flows).
- **AC (C-12 output-then-consume):** drive the shipped report handler → re-read the WRITTEN report file → assert the per-variant entropy section is present with band lines. Not a direct service call.

**US-036 — Entropy viewer surface (b-2) — `READY` (geometry MEASURED 2026-07-06 — fits, no fallback)**
> An operator opens an entropy view of the loaded image (strip per window, colour by band, jump-to-address).
- **Surface:** `ModalScreen[None]` following `LegendScreen` (`screens.py:475`), pushed from an app action + key binding (the `k`-key legend precedent) — a modal owns a full canvas, sidestepping the contended 3-pane main layout (batch-17 off-screen-pane failure mode). Reject a persistent main-layout pane.
- **C-13 geometry MEASURED (Pilot, textual 8.2.8, real `LegendScreen` `.modal-dialog` box model):** usable content width = **48 cols @80×24 · 76 cols @120×30** (`70%·W` outer − round border 2 − padding `1 2` 4; scrollbar overlays, steals no column). Jump list row `0xXXXXXXXX  band  H=7.63` ≈ 30 cols → **18-col margin @80**. Strip @1–2 cols/cell wraps into 48 → ≥24 cells/line. **Verdict: fits both regimes, no `column-span`/fallback rung needed.** Draft LLRs against **48 / 76**.
- Render precedent: `hexview.py:294-353` (per-cell Rich `Text` styling + cost caps). Entropy bands need their **own** 4-colour map (grey/green/yellow/red) — NOT the severity `sev-*` classes (`color_policy.py:5-11` is severity-semantic).

### Spike defaults ADOPTED (recommended, low-risk — confirm or override at DoR)
- **D-a Window anchoring:** `range.start` (simpler, correct) rather than 16-byte row-aligned. Revisit only if the US-036 prototype needs jump alignment.
- **D-b Low-sample policy:** tag windows <~64 samples as low-confidence, do not drop.
- **D-c Report granularity:** per-variant section (matches the story); a consolidated overview row is optional polish, out of scope unless requested.
- **D-d Band colours:** constant/padding=grey · low=green · medium=yellow · high=red (new entropy colour map).

### DoR decisions (open — resolve at gate)
- **R1 (scope, HIGH): bands-only vs semantic code/data classification.** Spike recommends **bands-only** — deterministic, defensible, no ground-truth needed; semantic is a heuristic with accuracy risk + its own validation story. THE scope-gating call.
- **US-036 approach:** modal + in-batch `/prototype` measurement pre-step (recommended) vs report-section-first only vs defer US-036 to its own batch.

### Out of scope (this batch)
- Any edit to the engine-frozen set. Semantic classification beyond entropy bands (unless R1 decides otherwise). Report retention/rotation policy changes. A persistent main-layout entropy pane.

### Phase-0 evidence checklist (architect spike)
- ✓ Substrate verified against disk — `models.py:44/46`, `core.py:503-514/676-678`, `variant_execution_service.py:597/753-754`.
- ✓ Algorithm concrete + deterministic — window/estimator/bands with numbers.
- ✓ Ambition alternatives weighed (bands vs semantic) → recommendation tied to constraints.
- ✓ Surface alternatives weighed (4 options) → modal + `/prototype`; geometry flagged `assumed — measure`.
- ✓ Reuse path cited for US-037 — `report_service.py:1139-1147`, `include_legend` precedent.
- ✓ Risks R1–R5 + open DoR questions listed.

### DoR resolution (gate, 2026-07-06 — operator)
- **R1 RESOLVED → bands-only.** Deterministic 4-band Shannon classification; no semantic code/data heuristic (its accuracy risk + validation story are out of scope). All three stories are scoped bands-only.
- **US-036 approach RESOLVED → modal + measured geometry.** Geometry already MEASURED (48@80 / 76@120, §2.6 C-13), fits both regimes — no in-batch `/prototype` step, no `column-span` fallback rung. `ModalScreen[None]` per `LegendScreen`.
- **Slice = all three (US-035 → US-037 → US-036).** US-035 is the prereq; US-037 (zero-geometry report section) and US-036 (measured modal) both consume it.

---

## 3. High-level requirements (HLR)

> EARS regime. `shall` is the sole normative keyword and appears ONLY in HLR/LLR statements. Priorities: US-035 is the prereq (high); US-037 report section (high); US-036 viewer (medium). All targets confirmed OUTSIDE the engine-frozen set (`entropy_service.py` NEW; `report_service.py`, `screens.py`, `app.py`, `styles.tcss` all non-frozen — the frozen set is `core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`, none touched).

### HLR-035 — Headless entropy/band classification service
- **Traceability:** US-035
- **Statement:** When invoked with a sparse memory map and its contiguous half-open ranges, the entropy service shall compute the per-window Shannon entropy (bits/byte, 0–8 scale) of every 256-byte window walked per contiguous range and shall classify each window into exactly one of the four bands defined by the `ENTROPY_BANDS` cutoffs (LLR-035.1).
- **Band reference (informative):** the four bands are `constant/padding` (H<1.0) · `low` (1.0≤H<5.0) · `medium` (5.0≤H<7.2) · `high/random` (7.2≤H≤8.0); the closed upper edge is realised by the `8.000001` headroom sentinel in LLR-035.1, which is the single normative source for the cutoffs.
- **Rationale (informative):** A pure arithmetic transform (deterministic, no RNG — eng-rule 5) that both the report section (US-037) and the viewer (US-036) consume. Kept headless (no Textual import) so it is unit-testable to exact-H precision and reusable across surfaces, mirroring the `before_after_service.py` purity precedent (zero `textual` imports confirmed).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_entropy_service.py` (NEW test module — created in Phase 3)
- **Numeric pass threshold:** all TCs pass; hand-computed reference H values match to `abs(H_actual − H_expected) < 1e-9` on a constant-fill window (H=0.0) and a known distribution.
- **Priority:** high
- **Acceptance (black-box) — the WHAT:**
  - **Observable outcome:** Given a fixture with a known constant-fill run and a known high-entropy run, `compute_entropy(mem_map)` returns `EntropyWindow` records whose bands are `constant/padding` and `high/random` respectively, with H matching the hand-computed expectation, and windows never spanning a gap between ranges.
  - **Shipped surface:** the module-level `compute_entropy(mem_map)` public function of `s19_app/tui/services/entropy_service.py` (headless — this IS the shipped surface for US-035; US-036/037 are its consumers).
  - **Deliverable + observation:** a `list[EntropyWindow]` return value observed directly from the public function; each record carries `(start, end, sample_count, entropy, band, low_confidence)`.
  - **Acceptance test(s):** `AT-035` *(qa authors the body — drives `compute_entropy` over a `make_large_s19`-derived fixture with an embedded constant run + high-entropy run; asserts bands + H + no cross-range window; FAILS if the service returns wrong bands or spans a gap)*
  - **Boundary catalog (QC-3):** ☑ empty (mem_map with zero mapped bytes → empty list) · ☑ boundary (a range shorter than one window; a partial final window with 64≤n<256; a low-sample <64 window tagged `low_confidence`) · ☑ invalid (band-cutoff boundary values H exactly 1.0 / 5.0 / 7.2 land in the higher band per half-open `[lo,hi)`) · ☑ error (N/A for out-of-domain input — mem_map is a validated in-memory structure, not user text; a malformed mem_map is a programming error, not a spec-handled input — reason recorded).

### HLR-037 — Per-variant entropy section in the project report
- **Traceability:** US-037
- **Statement:** Where `ReportOptions.include_entropy` is true, the project report generator shall append a per-variant entropy section — derived from `HLR-035` over `result.mem_map` — after the variant's hexdump section, listing each variant's band summary.
- **Rationale (informative):** The report already carries `VariantExecutionResult.mem_map` (`variant_execution_service.py:597`, the exact source `_hexdump_section` reads — `report_service.py:907`), so no new capture plumbing is needed. The `include_entropy` flag mirrors the proven `include_legend` opt-out precedent (`report_service.py:197` + `__post_init__` validation `:231-235`).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_report_service.py` (entropy-section cases — provisional node ids reconciled Phase 4)
- **Numeric pass threshold:** all TCs pass; the WRITTEN report file contains the per-variant entropy heading + ≥1 band line for a variant with mapped bytes; byte-identical to the pre-feature report when `include_entropy=False`.
- **Priority:** high
- **Acceptance (black-box, C-12 output-then-consume) — the WHAT:**
  - **Observable outcome:** After the shipped report handler runs on a project with mapped image bytes, the WRITTEN report file contains a per-variant entropy section with band lines.
  - **Shipped surface:** `generate_project_report` (the report handler that writes the file at `report_service.py:1157-1159`) — NOT a direct `_entropy_lines` call.
  - **Deliverable + observation:** the report file at `<project>/reports/<report>.md` — re-read from disk after generation; assert the entropy heading text + ≥1 band line are present under the variant. FAILS if the section is silently absent.
  - **Acceptance test(s):** `AT-037` *(qa authors — drives `generate_project_report`, re-reads the written file, asserts the entropy section; plus an `include_entropy=False` case asserting the section is absent and the file is otherwise byte-identical)*
  - **Boundary catalog (QC-3):** ☑ empty (variant with no mapped bytes → section states no data, no crash) · ☑ boundary (`include_entropy=False` → section omitted, byte-identical baseline) · ☑ invalid (`include_entropy` non-bool → `__post_init__` ValueError per the `include_legend` precedent) · ☑ error (report byte-budget already exhausted by hexdumps → entropy lines respect the existing `_ByteBudget`, no overflow — reason: budget is a pre-existing report invariant).

### HLR-036 — Entropy viewer modal (strip + jump-to-address)
- **Traceability:** US-036
- **Statement:** When the operator triggers the entropy-viewer action, the application shall push a `ModalScreen[None]` that renders — from `HLR-035` over the loaded image — a per-window strip coloured by band and a jump-to-address list, laid out to fit the measured 48-col (@80×24) and 76-col (@120×30) content widths.
- **Rationale (informative):** A modal owns a full canvas, sidestepping the contended 3-pane main layout (the batch-17 off-screen-pane failure mode); it follows the `LegendScreen` precedent (`screens.py:475`) pushed via `push_screen` (idiom at `app.py:3612`) from an app action + key binding (the `k`-legend precedent at `app.py:683`). Bands need their own 4-colour map — the `sev-*` classes are severity-semantic and must not be reused.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py` (Pilot e2e — NEW module) + snapshot cells @80×24 / @120×30 (added Phase 3, baseline per batch-25 regen policy).
- **Numeric pass threshold:** all Pilot TCs pass; strip + jump list render within the modal at both regimes with no horizontal overflow (content ≤ 48 cols @80, ≤ 76 cols @120).
- **Priority:** medium
- **Acceptance (black-box) — the WHAT:**
  - **Observable outcome:** With an image loaded, pressing the entropy key opens a modal showing a band-coloured strip and a jump-to-address list; selecting a jump entry moves focus to that address; the modal dismisses on close without disturbing app state.
  - **Shipped surface:** `EntropyViewerScreen(ModalScreen[None])` pushed by `S19TuiApp.action_show_entropy` bound to the `e` key (verified unused — no `"e"` in `BINDINGS` `app.py:666-692`).
  - **Deliverable + observation:** the rendered modal screen — observed via Textual Pilot (`App.run_test`): assert the strip widget and the jump list are present and populated with band cells; assert dismiss returns to the prior screen.
  - **Acceptance test(s):** `AT-036` *(qa authors — Pilot: load image → press `e` → assert strip + jump list present with band-coloured cells → activate a jump entry → assert address focus → dismiss → assert prior screen restored)*
  - **Boundary catalog (QC-3):** ☑ empty (no image loaded → action is a no-op notify or an empty-state modal, never a crash) · ☑ boundary (single-window image → one strip cell + one jump row; @80 vs @120 both fit) · ☑ invalid (N/A — the modal takes no free-text input; jump targets come from computed windows) · ☑ error (a `low_confidence` window is visually distinguished, not dropped — reason: low-sample policy from §2.6 D-b).

---

## 4. Low-level requirements (LLR)

> Same EARS regime; `shall` only. NEW symbols flagged `NEW — created in Phase 3`; existing symbols carry grep-verified `file:line`. Layout constants cite the §2.6 C-13 measurement.

### HLR-035 → LLRs (entropy_service.py — NEW, headless)

#### LLR-035.1 — Named window/band constants
- **Traceability:** HLR-035
- **Statement:** The entropy service shall define module-level constants `ENTROPY_WINDOW_BYTES = 256`, a low-sample floor `ENTROPY_MIN_SAMPLES = 64`, and `ENTROPY_BANDS` as an ordered tuple of `(label, lo, hi)` cutoffs `("constant/padding", 0.0, 1.0)`, `("low", 1.0, 5.0)`, `("medium", 5.0, 7.2)`, `("high/random", 7.2, 8.000001)` — half-open `[lo, hi)` lookup so a value equal to a cutoff falls in the higher band. *(All NEW — created in Phase 3.)*
- **Note (top-band closure):** the `8.000001` upper bound is a headroom sentinel, not a reachable entropy value; it guarantees the maximum H==8.0 (uniform 256-value window) falls inside `[7.2, 8.000001)` = `high/random`. `ENTROPY_BANDS` is therefore the single source of the cutoffs referenced by HLR-035.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_entropy_service.py -k constants_and_bands`
- **Numeric pass threshold:** band lookup returns the expected label for each of H = 0.0, 0.99, 1.0, 4.99, 5.0, 7.19, 7.2, 8.0.
- **Acceptance criteria:** cutoff-boundary values map to the higher band; the four labels match §2.6 exactly.

#### LLR-035.2 — Per-range window walk (half-open, gap-safe)
- **Traceability:** HLR-035
- **Statement:** The service shall walk 256-byte windows independently within each contiguous `range` `(start, end_exclusive)` (`models.py:46`), stepping `start → end` in `ENTROPY_WINDOW_BYTES` strides, and shall never form a window that spans the unmapped gap between two ranges (`core.py:676-678`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_entropy_service.py -k window_walk`
- **Numeric pass threshold:** for a two-range fixture, every returned window's `[start, end)` is a subset of exactly one input range; window count = Σ ceil(len(range_i)/256).
- **Acceptance criteria:** no window crosses a gap; a final partial window covers the residual bytes only.

#### LLR-035.3 — Shannon entropy over the 256-bin byte histogram
- **Traceability:** HLR-035
- **Statement:** For each window the service shall build a 256-bin byte-value histogram over the bytes present in `mem_map` for that window's addresses and shall compute `H = -Σ p·log2(p)` (bits/byte) over the non-zero bins, yielding H=0.0 for a constant-fill window.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_entropy_service.py -k shannon_h`
- **Numeric pass threshold:** `abs(H_actual − H_expected) < 1e-9` for a constant window (0.0), a uniform 256-value window (8.0), and one hand-computed mixed distribution.
- **Acceptance criteria:** H is bounded 0.0 ≤ H ≤ 8.0; only occupied bins contribute.

#### LLR-035.4 — Low-sample confidence tag (tag, never drop)
- **Traceability:** HLR-035
- **Statement:** If a window's `sample_count` is below `ENTROPY_MIN_SAMPLES` (64), then the service shall set `EntropyWindow.low_confidence = True` and shall still return the window with its computed band (never drop it).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_entropy_service.py -k low_confidence`
- **Numeric pass threshold:** a fixture whose final window has <64 bytes returns that window with `low_confidence is True` and a non-None band.
- **Acceptance criteria:** windows ≥64 bytes are `low_confidence is False`; no window is omitted for being small (§2.6 D-b).

#### LLR-035.5 — `EntropyWindow` result dataclass + `compute_entropy` entry point
- **Traceability:** HLR-035
- **Statement:** The service shall expose a frozen dataclass `EntropyWindow(start: int, end: int, sample_count: int, entropy: float, band: str, low_confidence: bool)` and a public `compute_entropy(mem_map: Dict[int, int]) -> list[EntropyWindow]` that derives ranges from the map and returns one record per window in ascending address order. *(Both NEW — created in Phase 3.)*
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_entropy_service.py -k compute_entropy`
- **Numeric pass threshold:** an empty `mem_map` returns `[]`; a populated map returns records sorted by `start`, each with all six fields set.
- **Acceptance criteria:** the module imports no `textual` symbol (purity — `rg -n "import textual|from textual" s19_app/tui/services/entropy_service.py` → 0 hits, mirroring `before_after_service.py`).

### HLR-037 → LLRs (report_service.py — non-frozen)

#### LLR-037.1 — `include_entropy` option field + validation
- **Traceability:** HLR-037
- **Statement:** `ReportOptions` shall gain `include_entropy: bool = True`, and `ReportOptions.__post_init__` shall raise `ValueError` if `include_entropy` is not a bool — following the `include_legend` field/validation precedent (`report_service.py:197`, `:231-235`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_report_service.py -k include_entropy_option`
- **Numeric pass threshold:** `ReportOptions(include_entropy="x")` raises ValueError; default is `True`.
- **Acceptance criteria:** the default preserves current behavior (section emitted by default); the guard message follows the reject-not-clamp F-S-05 style.

#### LLR-037.2 — `_entropy_lines(result)` Markdown builder
- **Traceability:** HLR-037
- **Statement:** The report module shall add `_entropy_lines(result) -> List[str]` (NEW — created in Phase 3) that computes windows via `compute_entropy(result.mem_map)` (`result.mem_map` source confirmed `report_service.py:907`) and returns a Markdown entropy heading plus a per-variant band summary (count per band, with low-confidence windows flagged).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_report_service.py -k entropy_lines`
- **Numeric pass threshold:** for a variant with a known constant run + high-entropy run the returned lines contain the entropy heading and ≥1 line each for the `constant/padding` and `high/random` bands.
- **Acceptance criteria:** a variant with empty `result.mem_map` returns a heading + a "no data" line (no crash); output respects the `_ByteBudget` idiom.

#### LLR-037.3 — Per-variant emission wired into the report loop
- **Traceability:** HLR-037
- **Statement:** While `options.include_entropy` is true, `generate_project_report` shall append the entropy section by passing `_entropy_lines(result)` through the `emit()` helper (`report_service.py:1130-1132`, which consumes `budget`), inserted inside the per-variant loop immediately after the `_hexdump_section` block (`report_service.py:1145-1147`) — NOT via a raw `lines.extend` mimicking the hexdump block at `:1146` — so the written file carries the entropy section per variant and the section is charged against the report byte budget.
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest tests/test_report_service.py -k report_contains_entropy` (drives `generate_project_report`, re-reads the written file)
- **Numeric pass threshold:** the WRITTEN report file contains the per-variant entropy heading + ≥1 band line; with `include_entropy=False` the section is absent and the rest of the file is byte-identical to the pre-feature baseline.
- **Acceptance criteria:** emission order is after the hexdump; the `include_entropy=False` path is byte-identical (drives `AT-037`).

### HLR-036 → LLRs (screens.py / app.py / styles.tcss — non-frozen)

#### LLR-036.1 — Band→colour map (own constant, not `sev-*`)
- **Traceability:** HLR-036
- **Statement:** The viewer shall define its own band→colour map `ENTROPY_BAND_COLOUR` (NEW — created in Phase 3) — `constant/padding`=grey · `low`=green · `medium`=yellow · `high/random`=red (§2.6 D-d) — and shall NOT reference the severity `sev-*` classes (`color_policy.py:5-11` is severity-semantic and is in the frozen set, read-only).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py -k band_colour_map` — `TC-036.1` asserts the pure-dict `ENTROPY_BAND_COLOUR` contents (four band→colour entries) and grep-guards no `sev-*` reuse in the band-cell path (`rg -n "sev-" s19_app/tui/screens.py` in the new screen block → 0 hits for band colouring).
- **Numeric pass threshold:** four distinct band colour classes exist; zero reuse of `sev-*` for band cells.
- **Acceptance criteria:** each band maps to its D-d colour; low-confidence cells are visually distinguished (e.g. dim/hatch class).

#### LLR-036.2 — `EntropyViewerScreen(ModalScreen[None])` compose (strip + jump list)
- **Traceability:** HLR-036
- **Statement:** The application shall add `EntropyViewerScreen(ModalScreen[None])` (NEW — created in Phase 3) following `LegendScreen` (`screens.py:475`), composing a per-window band-coloured strip (per-cell Rich `Text` styling, cost-capped — precedent `hexview.py:317-320`) and a jump-to-address list, dismissed self-handled with `None`.
- **Statement (box-model reuse):** `EntropyViewerScreen` shall reuse the shared `.modal-dialog` box model — the same container class measured at 48/76 (§2.6 C-13) — so the measured content-width budget holds by construction rather than by re-derivation.
- **Statement (snapshot semantics):** The viewer shall render a snapshot of the entropy windows captured at push time and shall NOT live-track subsequent `mem_map` changes for the lifetime of the open modal.
- **Non-goal (informative):** live-tracking a reloaded image while the modal is open is explicitly out of scope; the operator dismisses and re-opens the viewer to see a re-loaded image's entropy.
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py -k compose`
- **Numeric pass threshold:** on a loaded image the modal contains a non-empty strip and a jump list with one row per window; dismiss returns `None`.
- **Acceptance criteria:** strip cells carry band colours; jump rows read `0xXXXXXXXX  <band>  H=<h>` (≈30 cols, within the 48-col @80 budget — §2.6 C-13); the screen uses the `.modal-dialog` class (box-model reuse); the rendered content reflects push-time state.

#### LLR-036.3 — Strip fits the measured 48/76 content widths
- **Traceability:** HLR-036
- **Statement:** The strip shall wrap band cells into the measured usable content width — 48 cols @80×24 and 76 cols @120×30 (measured Pilot, textual 8.2.8, real `LegendScreen` `.modal-dialog` box model; §2.6 C-13) — with no horizontal overflow.
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py -k geometry` at `App.run_test(size=(80,24))` and `(120,30)`.
- **Numeric pass threshold:** rendered strip content width ≤ 48 cols @80 and ≤ 76 cols @120; no line exceeds the modal inner width. *(Measured regime: 70%·W outer − round-border 2 − padding `1 2` 4; scrollbar overlays. The `.modal-dialog` box-model reuse mandated in LLR-036.2 holds this budget by construction; re-measure per regime ONLY as a fallback if that reuse proves impossible.)*
- **Acceptance criteria:** at 1–2 cols/cell, ≥24 cells/line fit @80; no fallback rung needed (§2.6 C-13 verdict).

#### LLR-036.4 — App action + `e` key binding
- **Traceability:** HLR-036
- **Statement:** The application shall add `action_show_entropy` (NEW — created in Phase 3) that pushes `EntropyViewerScreen` via `push_screen` (idiom `app.py:3612`), bound to the `e` key in `BINDINGS` (`app.py:666-692`; `"e"` verified absent — `git grep '"e"' app.py` → 0 hits), following the `k`-legend binding precedent (`app.py:683`).
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py -k binding_opens` (Pilot: `press("e")` → screen pushed)
- **Numeric pass threshold:** pressing `e` with an image loaded pushes exactly one `EntropyViewerScreen`; with no image it is a safe no-op (notify, no crash).
- **Acceptance criteria:** the binding is registered; the action reads the loaded image's `mem_map`. *(C-15 note: the `e` binding is a plain Textual key string `"e"`, same form as `k`/`b` at `app.py:683-684` — no framework sentinel/constant is compared, so no `Select.BLANK`-class identity trap applies here.)*

#### LLR-036.5 — Jump-to-address moves focus
- **Traceability:** HLR-036
- **Statement:** When the operator activates a jump-list entry, the viewer shall move the operator's focus/selection to that window's `start` address (in the modal, or by dismissing with the target for the host to focus — implementer's choice, recorded Phase 3).
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py -k jump_to_address`
- **Numeric pass threshold:** activating a jump row for window W results in the observable focus/selection at W.start (asserted via Pilot).
- **Acceptance criteria:** each jump row targets its window's start; activation is observable through the shipped surface (drives `AT-036`).

#### LLR-036.6 — Strip/jump-list render cost cap
- **Traceability:** HLR-036
- **Statement:** The viewer shall render at most `ENTROPY_STRIP_MAX_CELLS` strip cells and `ENTROPY_MAX_ROWS` jump rows (NEW module-level constants — created in Phase 3) and, where the computed window count exceeds either cap, shall truncate the excess and render an on-screen truncation indicator — mirroring the `MAX_HEX_ROWS`/`MAX_HEX_BYTES` cost-cap precedent (`hexview.py:19-23`).
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py -k cost_cap` on the `large_s19` stress fixture.
- **Numeric pass threshold:** for a `large_s19` image whose window count exceeds `ENTROPY_STRIP_MAX_CELLS`/`ENTROPY_MAX_ROWS`, rendered strip cells ≤ `ENTROPY_STRIP_MAX_CELLS` and jump rows ≤ `ENTROPY_MAX_ROWS`, and the truncation indicator is present.
- **Acceptance criteria:** the caps bound rendering cost regardless of image size; truncation is signalled on-screen, never silent (drives `TC-036.5`).

---

## 5. Validation strategy

*(Layer-A `TC-NNN` bodies + Layer-B `AT-NNN` bodies are authored by `qa-reviewer` in `01b-validation-strategy.md`. This section fixes the method per requirement and the dual-traceability skeleton; the qa file fills the test-case bodies + numeric assertions against the placeholders below.)*

### 5.1 Methods
- **US-035 / HLR-035:** Layer A = `test (unit)` (exact-H, band, walk, low-sample) · Layer B = `AT-035` observing `compute_entropy` return.
- **US-037 / HLR-037:** Layer A = `test (unit)` (option, `_entropy_lines`) + `test (e2e)` (report loop) · Layer B = `AT-037` C-12 (re-read written report file).
- **US-036 / HLR-036:** Layer A = `test (e2e)` Pilot (compose, geometry, binding, jump, cost-cap) + `test (unit)` (band-colour map `ENTROPY_BAND_COLOUR` — `TC-036.1`, pure dict) + snapshot cells @80×24/@120×30 (Phase 3) · Layer B = `AT-036` Pilot through the `e` key.

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? |
|----|--------------------|-----------------|----------------------------|-----------|
| US-035 | Constant run → `constant/padding`, high run → `high/random`, exact H, no cross-range window | `compute_entropy(mem_map)` | AT-035 | qa |
| US-037 | Written report file carries per-variant entropy section with band lines | `generate_project_report` → report file on disk (C-12) | AT-037 | qa |
| US-036 | `e` opens modal with band strip + jump list; jump moves focus; dismiss restores | `EntropyViewerScreen` via `action_show_entropy`/`e` key | AT-036 | qa |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-035 | test (unit) | *qa* | service contract |
| LLR-035.1 | test (unit) | *qa* | constants + band cutoffs |
| LLR-035.2 | test (unit) | *qa* | per-range half-open walk |
| LLR-035.3 | test (unit) | *qa* | Shannon H < 1e-9 |
| LLR-035.4 | test (unit) | *qa* | low-sample tag |
| LLR-035.5 | test (unit) | *qa* | dataclass + entry point |
| LLR-035.5 | test (unit) | TC-035.7 *(qa)* | purity probe (`rg import textual` → 0) |
| HLR-037 | test (e2e) | *qa* | report file content |
| LLR-037.1 | test (unit) | *qa* | option + validation |
| LLR-037.2 | test (unit) | *qa* | `_entropy_lines` |
| LLR-037.3 | test (e2e) | *qa* | loop emission + byte-identical off |
| HLR-036 | test (e2e) | *qa* | Pilot modal |
| LLR-036.1 | test (unit) | TC-036.1 *(qa)* | band colour map (pure dict), no `sev-*` |
| LLR-036.2 | test (e2e) | *qa* | compose strip + jump; `.modal-dialog` reuse; push-time snapshot |
| LLR-036.3 | test (e2e) | *qa* | geometry 48/76 |
| LLR-036.4 | test (e2e) | *qa* (black-box AT-036) + TC-036.4 *(qa)* | `e` binding opens; TC-036.4 pins `"e" in BINDINGS` → `action_show_entropy` |
| LLR-036.5 | test (e2e) | *qa* | jump moves focus |
| LLR-036.6 | test (e2e) | TC-036.5 *(qa)* | strip/jump cost cap on `large_s19` |

### 5.3 Batch acceptance criteria
- Every LLR covered by ≥1 passing `TC`; 0 blocker fails.
- Every US has ≥1 passing `AT` observing its outcome through the shipped surface, with boundary + negative evidence (AT-037 includes the `include_entropy=False` byte-identical negative; AT-036 includes the no-image no-op).
- `entropy_service.py` imports no `textual` symbol (purity probe = 0 hits).
- 0 diffs to the engine-frozen set (engine-unchanged guards green).
- US-036 snapshot cells @80×24 / @120×30 baselined per the batch-25 regen policy.

---

## 6. Appendices

### 6.3 Open risks
- **R-1 (H-precision / float):** `log2` float error vs the `< 1e-9` threshold — mitigated by asserting exact endpoints (0.0, 8.0) and a hand-computed mid value; widen tolerance only with recorded justification.
- **R-2 (report byte-budget):** entropy lines add to the per-report `_ByteBudget`; a large image could push truncation — mitigated by band-summary-only output (counts, not per-window dumps) so the section is O(bands), not O(windows).
- **R-3 (geometry regime drift):** the 48/76 measurement holds for the `LegendScreen` `.modal-dialog` box model at textual 8.2.8; if the new screen uses a different container the measurement is `assumed per-regime` and must be re-measured (LLR-036.3 note).
- **R-4 (band-cell cost @large image):** many windows → many strip cells; mitigated by the `hexview` cost-cap precedent (`MAX_HEX_*`) — the strip must cap rendered cells, confirmed in Phase 3.
- **R-5 (`e` key collision, future):** `e` is free today (verified); a future binding must not reclaim it — recorded so the census catches it.

### 6.4 Phase-1 reconciliation log
*(No LLR threshold/statement changed after first draft — all LLRs authored fresh this phase from the §2.0/§2.6 spike decisions. No parent-HLR re-read required for the first draft. Phase-2 review folds (pre-lock, no §6.5 amendment) recorded below, body-first: what changed · why (finding) · parent-HLR re-read result.)*

**Phase-2 review folds (2026-07-06, pre-lock):**

- **Added LLR-036.6 (strip/jump cost cap, normative).** Promoted the batch's cost-cap risk (R-4) from a prose note to a `shall`-gated LLR with named caps `ENTROPY_STRIP_MAX_CELLS`/`ENTROPY_MAX_ROWS` + on-screen truncation indicator, covered by `TC-036.5` on `large_s19`. *Why:* finding **M1** (architect + security F5) — a prose-only cap can be silently dropped and a large image yields unbounded cells. *Parent-HLR re-read:* HLR-036 already carries R-4 and the `hexview` cost-cap precedent in Rationale; derivation unchanged — this LLR makes the existing intent normative, no new obligation on HLR-036.
- **LLR-036.2 gained push-time snapshot semantics + non-goal.** Added a `shall` that the viewer renders a snapshot captured at push time and does NOT live-track `mem_map`; recorded live-tracking a reloaded image as an explicit non-goal. *Why:* finding **M2** (architect) — mid-view `mem_map` reload/clear behaviour was unspecified. *Parent-HLR re-read:* HLR-036 says "renders … the loaded image"; snapshot-at-push is a refinement of "loaded image", not a change of scope — derivation unchanged.
- **LLR-036.2 gained `.modal-dialog` box-model reuse mandate.** Added a `shall` that `EntropyViewerScreen` reuse the shared `.modal-dialog` box model measured at 48/76, so the geometry budget holds by construction. *Why:* finding **m3** (architect) — the `assumed per-regime` hedge under-committed and voids 48/76 if a different box model is used. *Parent-HLR re-read:* HLR-036 already fixes the measured 48/76 widths; reuse is the mechanism that guarantees them — derivation unchanged.
- **LLR-036.3 hedge downgraded to fallback-only.** The `assumed per-regime` re-measure note now applies ONLY if the mandated `.modal-dialog` reuse (LLR-036.2) proves impossible. *Why:* finding **m3** (architect), same axis. *Parent-HLR re-read:* unchanged — this tightens the fallback condition, not the requirement.
- **HLR-035 statement now references the `ENTROPY_BANDS` cutoffs (LLR-035.1) as the single source; LLR-035.1 gained a headroom-sentinel note.** Replaced the open-ended `H≥7.2` restatement with a reference to the LLR-035.1 cutoffs; the human-readable band list moved to informative text; LLR-035.1 notes `8.000001` guarantees H==8.0 ∈ `high/random`. *Why:* finding **m1** (architect) — the HLR (open-ended) vs LLR (closed) top-band phrasings diverged cosmetically. *Parent-HLR re-read:* HLR-035 classifies into "exactly one of four bands"; single-sourcing the cutoffs removes the divergence without changing the band semantics — derivation unchanged.
- **LLR-037.3 reworded to emit via the `emit()` helper.** Entropy lines are now appended through `emit()` (`report_service.py:1130-1132`, which consumes `budget`), inserted after the `_hexdump_section` block (`:1145-1147`), explicitly NOT mimicking the raw `lines.extend` at `:1146`. *Why:* finding **m2** (architect) — the hexdump block bypasses `budget`; entropy must route through `emit()` to actually be budget-charged (as the LLR's own threshold requires). *Parent-HLR re-read:* HLR-037's boundary catalog already requires respecting `_ByteBudget`; routing through `emit()` is how that is satisfied — derivation unchanged. *(Cited line numbers re-verified on disk 2026-07-06: `emit()` `:1130-1132`, `_hexdump_section` call + raw extend `:1145-1147` — accurate, no drift.)*
- **LLR-036.1 + §5.1 validation method `inspection` → `test`.** The band→colour map is a pure dict, so `TC-036.1` unit-asserts its contents and grep-guards no `sev-*` reuse; the `inspection` label is dropped. *Why:* finding **m6** (qa) — §5.1 said `inspection` while §2/TC-036.1 implied `test`; the pure-dict map is unit-testable. *Parent-HLR re-read:* HLR-036 validation is `test`; reconciling the LLR to `test` aligns it with the parent — derivation unchanged.
- **Traceability additions (§5.2 functional chain).** Added rows LLR-036.6 → `TC-036.5` (cost cap), LLR-036.4 → `TC-036.4` (white-box `e`-binding registration, alongside the existing black-box AT-036), and LLR-035.5 → `TC-035.7` (purity probe, unbinding the prose probe to a TC id). *Why:* findings **M1 / M3 / m4** — keep the functional chain complete for the new/split nodes. *Parent-HLR re-read:* no HLR text changed; these rows attach TC ids to existing LLR obligations — derivation unchanged. TC bodies authored by qa (placeholder convention retained).

---

## Evidence checklist (Phase-1 architect)
- ✓ Constraints stated — bands-only (R1 resolved), engine-frozen off-limits, measured 48/76 geometry (§2.6 + DoR resolution).
- ✓ `shall`-only normative — every HLR/037/036 + all 17 LLRs use `shall`; no `should` inside any statement (only in informative Rationale/notes). Self-grepped post-fold: 0 `should`-as-modal in statements.
- ✓ Every HLR → US, every LLR → parent HLR — traceability lines present on all (HLR-035→US-035, HLR-037→US-037, HLR-036→US-036; LLR-035.1–.5 / 037.1–.3 / 036.1–.6).
- ✓ EARS patterns — Ubiquitous/Event-driven/State-driven/Unwanted used (HLR-035 event-driven; HLR-037 optional-feature `Where`; HLR-036 event-driven; LLR-035.4/037.3/036.5 unwanted/state-driven).
- ✓ Per-story Acceptance blocks with `AT-NNN` — AT-035/037/036 placeholders, each naming observable outcome + shipped surface + deliverable/observation; qa fills bodies.
- ✓ Output-producing reqs name deliverable + observation — HLR-037 (report file at `<project>/reports/*.md`, C-12 re-read); HLR-036 (rendered modal via Pilot).
- ✓ C-12 output-then-consume on US-037 — AT-037 observes `generate_project_report`'s WRITTEN file (`report_service.py:1157-1159`), not a `_entropy_lines` direct call.
- ✓ Draft-time verification — `include_legend` precedent `report_service.py:197`/`:231-235`; per-variant loop `:1139-1147`; `_hexdump_section`/`result.mem_map` `:907`,`:1145`; `LegendScreen` `screens.py:475`; `push_screen` `app.py:3612`; `BINDINGS` `app.py:666-692`; `k`-binding `:683`; `action_show_legend` `:3589`; hexview per-cell styling `hexview.py:317-320`; ranges half-open `models.py:46`+`core.py:503-514/676-678`; `mem_map` source `variant_execution_service.py:597`. NEW symbols flagged `NEW — created in Phase 3` (constants, `EntropyWindow`, `compute_entropy`, `_entropy_lines`, `include_entropy`, `EntropyViewerScreen`, `action_show_entropy`, `ENTROPY_BAND_COLOUR`).
- ✓ C-15 symbol-identity — `e` key is a plain Textual key string (same form as `k`/`b` `app.py:683-684`); no framework sentinel/constant compared, no `Select.BLANK`-class trap; `"e"` absence verified `git grep '"e"' app.py` → 0 hits (LLR-036.4).
- ✓ Frozen-set confirmed off-limits — all targets (`entropy_service.py` NEW, `report_service.py`, `screens.py`, `app.py`, `styles.tcss`) outside the frozen set (`core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`); `color_policy` referenced read-only in LLR-036.1.
- ✓ Every `test` LLR carries Executed verification + Numeric pass threshold — all 17 LLRs + 3 HLRs.
- ✓ Boundary catalog per story — empty/boundary/invalid/error enumerated for all three (N/A classes carry a one-line reason).
- ✓ Dual traceability — both chains present (§5.2 behavioral US→AT + functional US→HLR→LLR→TC).
- ✓ Purity precedent — `before_after_service.py` verified 0 `textual` imports (LLR-035.5 purity probe basis).
- ✓ `assumed — verify` items — geometry regime flagged `assumed per-regime` if the modal box model differs (LLR-036.3); no other assumed items (all symbols cited or NEW-flagged).
