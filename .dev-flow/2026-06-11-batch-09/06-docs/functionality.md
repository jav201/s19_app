# Functionality — s19_app — Batch 2026-06-11-batch-09 (US-006 hex compare)

> **Audience:** technical stakeholders (firmware/calibration engineers, the s19tool maintainer).
> **Purpose:** understand what batch-09 adds functionally and how to exercise it.
> **Story delivered:** US-006 — "compare two HEX/S19 images (in-project or external), checked against the shared A2L/MAC, with a note of which artifacts each image uses, producing a diff report."

This batch turns the long-standing A↔B Diff rail placeholder into a working image comparison mode. Three pieces ship together: a headless **compare engine**, a two-format **diff report**, and the completed **A↔B Diff TUI screen**.

---

## 1. The compare engine — what a diff actually is

The engine (`s19_app/compare.py`, headless — imports no Textual, no parser class) takes two already-parsed sparse memory maps (`Dict[int, int]`) and produces a deterministic comparison.

**A diff is a set of classified byte runs.** A *run* is a maximal contiguous half-open address range `[start, end)` whose every address shares one classification:

- **`changed`** — the address is mapped in BOTH images but the byte differs.
- **`only_a`** — mapped in image A only.
- **`only_b`** — mapped in image B only.

Addresses present in both with the **same** byte produce no run (they are not "differences"). Two adjacent addresses share a run if and only if they have the same classification — so a classification change always forces a run boundary. Runs come back ordered by ascending start address.

Alongside the runs the engine returns **statistics**: per-classification run count and byte count, where each byte count equals the summed length of that classification's runs (verified by TC-005). Identical inputs (including two empty maps) yield zero runs; repeated calls over the same inputs return equal output (determinism, TC-004). On a large-fixture pair the diff compute completes in ~1.4 s, well inside the 2.0 s slow-test budget (TC-006).

**Artifact-usage notes** ride on the same comparison result. For each compared image, against the project's shared A2L and shared MAC (at most one of each), the service records:

- a **mechanical coverage count** — how many artifact addresses fall inside that image's mapped ranges (computed via binary-search range membership, never a linear scan); and
- a derived per-image **`both` / `one (a2l)` / `one (mac)` / `none`** summary (coverage ≥ 1 ⇒ "used").

If a project supplies no A2L and/or no MAC — or no project is active — the missing artifact is recorded `absent` and the summary degrades to `none` without failing (TC-015). This is the "which artifacts does each image use?" answer the story asked for, made mechanical and honest: the tool reports coverage, it does not judge intent.

**The comparison result contract** (the C-9 field set, one dataclass) is exactly: `image_a`, `image_b`, `runs`, `stats`, `notes`, `diagnostics`, `refused`. The engine fills `runs`/`stats`; the service fills the rest. A refused comparison (unresolvable path, parse failure, fewer than two valid images) comes back as a result object carrying diagnostics and `refused=True` — **never** as a raised exception (TC-008, TC-010).

---

## 2. The diff report — complete file, two formats

The report generator (`s19_app/tui/services/diff_report_service.py`) writes the comparison to disk in **two formats from the one comparison result**.

**The persisted file is COMPLETE — never truncated.** Every run is present; there is no run cap, no byte truncation, and no `TRUNCATED` marker anywhere in the file (TC-026 for Markdown, TC-028 for HTML). This is the binding correction from decision G-9: the batch-07 caps (`REPORT_MAX_TOTAL_BYTES = 2 MB`, the 128-region-per-variant cap) were wrongly bounding the file; they are RE-LOCATED to the TUI **display** path only — they limit what the screen shows, never what is written. The authoritative deliverable is the file.

**Markdown** carries, in order: a header (both image identities + source kinds, the artifact-usage notes, generation UTC instant, tool version), a statistics table, a classified run table with best-effort symbol annotation, and per-run bounded hex windows for A and B. Each `changed` run additionally renders as a fenced ` ```diff ` block with image A's bytes as `-`-prefixed lines and image B's bytes as `+`-prefixed lines — so it shows red/green on GitHub, VS Code, and Obsidian, and degrades gracefully to plain text elsewhere (TC-027).

**HTML** is a self-contained second export of the same content, hardened against content injection: every embedded value (addresses, bytes, source paths, diagnostics) is escaped via stdlib `html.escape`; the three run kinds are distinguished by **inline CSS colour**; and the file contains **no `<script>`, no external resource, font, CDN, stylesheet link, or network reference of any kind** (TC-028 verifies 0 script tags, 0 external-resource matches, and that an injected `<script>` payload round-trips as `&lt;script&gt;`). Not every operator opens HTML, which is why both cues exist.

**Where it is written:**

- **Project active** → the project's existing `reports/` directory inside the gitignored `.s19tool/` tree (sibling of the batch-07 project report, listed by the existing report viewer).
- **No project active** → an **operator-supplied** destination directory. There is no implicit default — no Downloads guess (decision G-8). The path is normalized via `Path(...).expanduser().resolve()` (collapsing `..` and symlinks) and must be an existing directory; an empty, blank, invalid, or non-existent path is **refused** with a diagnostic and zero files written (TC-025).

Both branches are **collision-safe**: the filename is tool-generated (`<UTC %Y%m%dT%H%M%SZ>(-NN)?-diff-report.md|.html`), and a same-second collision produces a `-01` sibling rather than overwriting — a pre-existing file is left byte-unchanged (TC-016, TC-025). No operator-supplied string ever forms any part of the filename. The diff report owns its own filename regexes; the shared `report_service.REPORT_FILENAME_REGEX` is **not** edited (G-4, confirmed byte-for-byte unchanged). The module also performs no logging of the report body or memory bytes (confidentiality precedent F-S-07, TC-020).

---

## 3. The A↔B Diff TUI screen

The diff screen (rail entry `"A2B Diff"`, `rail.py:85` — no new rail entry was added) is no longer a placeholder. `AbDiffPanel` now:

- lets the operator **select two sources inline** within the screen (prefilled project-variant list from `ProjectVariantSet` + external-path entry; inline, not a modal, per G-6);
- runs the comparison **exclusively through the service** — the view computes no run classification, no coverage, no report content; it calls `compare_service.compare_images` and the two report generators and nothing else (TC-021, verified: the view never imports or calls `diff_mem_maps`);
- renders the **classified run list** plus, for the selected run, **bounded hex windows of A and B** (respecting the `hexview` caps), with the artifact-usage notes shown (TC-022). The on-screen run dump is bounded by the relocated display caps while the persisted file stays complete (TC-029);
- on a **refused** request surfaces the diagnostic in the status line and keeps running, leaving the screen in its pre-request state (TC-023);
- on a **report trigger** shows the written Markdown and HTML destination paths in the status line on success, or the refusal diagnostic (and writes 0 files) on an invalid destination (TC-024).

### How to try it

```bash
s19tui                       # launch the TUI
# press 7  (or the rail "D" shortcut) to open the A2B Diff screen
```

Open a project containing ≥ 2 variants (or point the external-path entry at two files), select the two images, run the comparison, and observe the run list + per-run hex windows + the artifact-usage notes. Trigger a report and read the destination path(s) from the status line. *(Untested as a literal transcript here — this is the documented operator path; the behavior is covered by TC-021..024, TC-029.)*

---

## 4. What it does NOT do yet

- **N-way (N > 2) comparison.** 2-way only by decision (D-1). The "N-way if feasible" clause of US-006 was answered, not dropped: feasible at the engine level, deferred for surface cost.
- **Interactive run-picker.** The screen currently assumes first-run + overview rendering; a clickable run selector is a carried item (CARRY-1 in the traceability matrix), not a gap against any LLR.
- **PDF export.** Dropped from scope. Dormant note: if ever revived, use `fpdf2` — never weasyprint.
- **Side-by-side synchronized-scroll visual diff, HEX save-back/edit/patch from the diff screen, and comparison of MAC/A2L artifacts themselves** — all explicitly out of scope (read-only diff; artifacts provide annotation context only).

---

## 5. Extension points

The **compare engine is a reusable substrate**, deliberately headless and parser-free. Its first downstream consumer beyond this batch is **batch-10's verify-on-save** flow, which will reuse `diff_mem_maps` / the `ComparisonResult` contract to diff a save-back against its source. The service seam (`compare_images`) and the two report generators are likewise injectable (engine, resolver, and loaders are all parameters), so future surfaces can consume them without touching the TUI.

---

## Assumptions · risks · next steps

- **Assumptions:** at most one A2L + one MAC per project (artifact-context cardinality, enforced by `validate_project_files`); two full memory maps fit in RAM simultaneously (the variant layer already holds one at a time).
- **Risks:** the no-project write lands firmware-derived bytes OUTSIDE the gitignored `.s19tool/` tree — mitigated by the normalize-then-confirm directory validation and the tool-generated filename (risk R-9, reviewed in Phase 2). HTML injection surface mitigated by `html.escape` + no-script (R-10).
- **Next steps:** interactive run-picker (CARRY-1); batch-10 verify-on-save consuming the engine; optional purity-probe wording tightening (DEV-5).
