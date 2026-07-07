# Entropy / Data-Classification Viewer — Functional Description

> **Audience:** technical stakeholder (a developer, tool operator, or reviewing engineer) who wants to understand *what* the entropy feature does and *how* its surfaces behave — without reading the code.
> **Purpose:** understand. **Batch:** 2026-07-06-batch-26, feature #12(b) (closes feature #12). **Language:** English.

---

## 1. What it does (BLUF)

The entropy feature classifies a loaded firmware image by **how random each region of its bytes is**, and surfaces that classification three ways. It answers a practical question at a glance: *which parts of this image look like constant fill / padding, which look like ordinary code or data, and which look compressed, encrypted, or otherwise high-entropy?*

It does this with **Shannon entropy** computed over fixed 256-byte windows, then buckets each window into one of **four bands**. It is a pure, deterministic arithmetic transform — same image in, same bands out, no randomness, no heuristics, no ground-truth model. Scope was deliberately fixed at **bands only** (DoR decision R1): the tool reports an entropy band, it does **not** claim "this is code" vs "this is data" — that semantic call carries accuracy risk and is out of scope.

The classification is exposed on three surfaces, all reading the same in-memory byte map (`mem_map`) the rest of the tool already carries:

| Surface | Story | Where | What you see |
|---------|-------|-------|--------------|
| **Headless service** | US-035 | `entropy_service.compute_entropy(mem_map)` | A `list[EntropyWindow]` — the raw per-window result other surfaces consume. |
| **Report section** | US-037 | project report file (`### Entropy` per variant) | A per-band **count summary** written into the generated Markdown report. |
| **Viewer modal** | US-036 | `EntropyViewerScreen`, opened with the `e` key | A colour-coded band **strip** + a **jump-to-address** list you can click to move the hex view. |

---

## 2. The algorithm, in plain terms

**Step 1 — find the mapped ranges.** A loaded image is a sparse `mem_map: Dict[int, int]` (address → byte). Consecutive addresses form contiguous **ranges**; the gaps between ranges are unmapped. The service derives those ranges from `sorted(mem_map)` exactly the way the parser does — `(start, prev+1)`, half-open — so range boundaries match the rest of the tool.

**Step 2 — walk 256-byte windows, per range.** Inside each contiguous range, the service steps through in **256-byte windows**. Windows are walked *within one range at a time* — a window **never spans the unmapped gap** between two ranges. The last window of a range covers only its residual bytes (it is not padded out to 256).

**Step 3 — measure the entropy of each window.** For a window it builds a 256-bin histogram of the byte values present and computes **Shannon entropy**:

```
H = -Σ p·log2(p)     (summed over the occupied histogram bins only)
```

`H` is in **bits per byte on a 0.0–8.0 scale**. The endpoints are exact and hand-checkable:
- A window of a single repeated byte (constant fill) → **H = 0.0**.
- A window containing each byte value 0..255 exactly once (uniform) → **H = 8.0** (the maximum, `log2(256)`).

**Step 4 — assign a band.** `H` is looked up against the band cutoffs (below) and the window gets a band label.

**Step 5 — tag low-confidence windows.** A window with fewer than **64 present bytes** (a short final window, or a tiny range) is flagged `low_confidence = True` — its entropy is computed on the bytes actually present and the window is **kept, never dropped**. This keeps the coverage honest: small regions still appear, just marked as statistically weak.

Each window becomes one immutable `EntropyWindow(start, end, sample_count, entropy, band, low_confidence)` record, returned in ascending address order.

---

## 3. The band model

Four bands, with **half-open `[lo, hi)` cutoffs** — a value exactly equal to a cutoff falls into the **higher** band:

| Band | Entropy range (bits/byte) | Typical meaning | Viewer colour |
|------|---------------------------|-----------------|---------------|
| `constant/padding` | **H < 1.0** | constant fill, padding, mostly-zero regions | grey |
| `low` | **1.0 ≤ H < 5.0** | structured code / data with repetition | green |
| `medium` | **5.0 ≤ H < 7.2** | mixed / denser data | yellow |
| `high/random` | **7.2 ≤ H ≤ 8.0** | compressed, encrypted, or random-looking | red |

Two precise points worth knowing:

- **The cutoffs are the single source of truth.** They live in one named constant, `ENTROPY_BANDS`, an ordered tuple of `(label, lo, hi)`. The human-readable ranges above are informative; the tuple is normative. The window size and low-sample floor are likewise named constants: `ENTROPY_WINDOW_BYTES = 256`, `ENTROPY_MIN_SAMPLES = 64`.
- **The top band closes at a headroom sentinel `8.000001`, not `8.0`.** This is a deliberate implementation detail so the maximum reachable value `H == 8.0` lands *inside* `[7.2, 8.000001)` = `high/random`. `8.000001` is not a reachable entropy value; it just guarantees the closed upper edge.

Band cutoffs are the highest-risk part of the feature (an off-by-`<`/`≤` at 1.0 / 5.0 / 7.2 would silently misclassify), so they are pinned by direct-injection tests at each boundary — see the traceability matrix (`TC-035.2`).

---

## 4. The three surfaces in detail

### 4.1 Headless service (US-035) — the shared engine

`compute_entropy(mem_map) -> list[EntropyWindow]` is the one public entry point. It is **headless**: it imports no Textual / UI symbol (verified by a purity probe), so both consumers can use it without pulling UI into their test surface. It is deterministic (no RNG), so its outputs are *exact* and unit-testable to `abs(H − expected) < 1e-9`. An empty map returns `[]` cleanly (no crash, no division-by-zero). It is a **new module outside the engine-frozen set** — it derives ranges itself and never touches the parser.

### 4.2 Report section (US-037) — bands in the project report

When a project report is generated with `ReportOptions.include_entropy = True` (the default), each variant's section gains an `### Entropy` block **after** its hexdump. The block is a **per-band count summary** — one bullet per band that has at least one window, e.g.:

```
### Entropy

- **constant/padding**: 12 window(s)
- **low**: 40 window(s) (3 low-confidence)
- **high/random**: 5 window(s)
```

Design points a reviewer should know:
- **Summary, not a dump.** It reports counts per band (and how many are low-confidence), never raw bytes. Output is O(bands), not O(windows) — so a large image cannot blow the report byte budget. No new confidentiality surface beyond what the hexdump already emits, and no new logging.
- **Charged against the report budget.** The section is appended through the report's budget-charged `emit()` helper — it participates in the same truncation budget as every other section, rather than bypassing it.
- **Clean opt-out.** `include_entropy = False` omits the section entirely and produces a report **byte-identical** to the pre-feature baseline. The flag is validated (`__post_init__` rejects a non-bool with a `ValueError`), mirroring the existing `include_legend` precedent.
- **Empty variant.** A variant with no mapped bytes gets the heading plus `No mapped bytes - entropy not computed.` — no crash.

### 4.3 Viewer modal (US-036) — the interactive surface

Pressing **`e`** opens `EntropyViewerScreen`, a full-canvas modal (`ModalScreen`). A modal was chosen over a persistent main-layout pane on purpose: it owns the whole canvas and sidesteps the contended 3-pane layout (the batch-17 off-screen-pane failure mode).

It shows two things:
1. **A band strip** — one `█` cell per window, coloured by band. Colours come from the viewer's **own** map, `ENTROPY_BAND_COLOUR` (`constant/padding`=grey, `low`=green, `medium`=yellow, `high/random`=red). This is a deliberately separate 4-colour map — it does **not** reuse the severity `sev-*` classes, which are severity-semantic and frozen. Low-confidence windows are visually distinguished with a `dim` style without changing their band hue.
2. **A jump-to-address list** — one row per window reading `0xADDR  <band>  H=<h>`.

Interaction:
- **Jump.** Activating a jump row **dismisses the modal with that window's start address** as the payload; the host then routes the address through the existing `_apply_goto` guard and moves the main hex view there. No new focus plumbing was added — the modal returns a target, the app focuses it.
- **Close.** Closing without a selection dismisses with no target; app state is undisturbed.

Two correctness properties:
- **Push-time snapshot.** The modal renders the entropy of the image **as it was when the modal opened**. It does **not** live-track a `mem_map` that changes underneath it — reloading an image while the modal is open is an explicit non-goal; dismiss and re-open to see a re-loaded image.
- **Measured to fit.** The strip and jump list fit the measured content widths of **48 columns @80×24** and **76 columns @120×30** (the shared `.modal-dialog` box model, textual 8.2.8), with no horizontal overflow — no fallback layout rung was needed.

---

## 5. Limits, cost caps, and non-goals

**Cost caps.** For a large image the window count can be huge. The viewer renders **at most `ENTROPY_STRIP_MAX_CELLS = 512` strip cells** and **`ENTROPY_MAX_ROWS = 512` jump rows**; when the window count exceeds either cap it truncates the excess and shows an **on-screen truncation indicator** (never a silent drop) — mirroring the `hexview` `MAX_HEX_ROWS` / `MAX_HEX_BYTES` precedent. The headless service and the report summary are **not** capped (the report is O(bands) by design); only the interactive render is bounded.

**Assumptions.**
- The `mem_map` is a validated in-memory structure (a `LoadedFile.mem_map` / `VariantExecutionResult.mem_map`); a malformed map is a programming error, not a spec-handled input.
- The report section needs `mem_map` populated on the variant result — that already flows when variant execution runs with `capture_mem_map=True` (no new capture plumbing was added).
- Viewer geometry is validated at textual **8.2.8** (pinned); a different container box model would require re-measuring the 48/76 widths.

**Non-goals (explicitly out of scope this batch).**
- **Semantic code/data classification.** The tool reports an entropy *band*, not "this is code / this is data" — that heuristic carries accuracy risk and its own validation story (DoR R1 → bands-only).
- **Live-tracking a reloaded image** while the viewer modal is open (push-time snapshot only).
- **Any edit to the engine-frozen set** — the entropy code is entirely new/TUI-side; the frozen parsers/validation are untouched (0 diff).
- **A persistent main-layout entropy pane** — rejected in favour of the modal.
- **Per-window raw-byte output in the report** — band summary only.

---

## 6. Where it sits (one-line map)

```
mem_map ──► entropy_service.compute_entropy ──► list[EntropyWindow]
                                              ├─► report_service._entropy_lines ──► ### Entropy in the report file
                                              └─► EntropyViewerScreen (strip + jump list) ──► hex focus
```

`entropy_service.py` is a **new, headless, pure** module outside the engine-frozen boundary; the report and modal are its two consumers. See `diagrams/diagrams.md` for the architecture, US-036 sequence, and US-037 data-flow diagrams, and `traceability-matrix.md` for the full requirement → test coverage.
