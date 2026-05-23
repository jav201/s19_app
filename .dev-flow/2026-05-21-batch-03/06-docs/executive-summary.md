# Executive summary — `s19_app` Patch Editor + calibration-file exchange, batch 2026-05-21-batch-03

**Date:** 2026-05-21
**Audience:** non-technical stakeholders (project owner, partner, manager)
**Detail artefacts:** `.dev-flow/2026-05-21-batch-03/05-postmortem.md`, `.dev-flow/2026-05-21-batch-03/04-validation.md`, `.dev-flow/2026-05-21-batch-03/01-requirements.md`

---

## 1. Context

`s19_app` is an internal tool for embedded/automotive firmware engineering. It lets calibration engineers inspect and cross-check firmware memory images, A2L calibration descriptions, and MAC tag tables, through a command-line tool and a terminal-based interface (a "TUI").

The previous batch (batch-02) redesigned that terminal interface and introduced a new "Patch Editor" screen — but shipped it as a non-functional placeholder: the screen was visible in the navigation rail, with no working behavior behind it. This batch was about making that screen a real tool.

## 2. Problem

Calibration engineers need to do two concrete things the tool could not yet support. First, they need to **build a list of parameter changes** — a record of exactly which calibration values they intend to change and to what. Second, they need to **exchange that list with vCDM**, Vector's calibration data management system, which the wider team uses as its source of truth for calibration data.

vCDM does not accept an arbitrary file. It expects the **ASAM CDFX** format — an industry-standard XML file for calibration data exchange (file extension `.cdfx`). Without support for that format, a change list built in `s19_app` was a dead end: it could not be handed off, reviewed, or re-loaded later. The placeholder screen made the gap visible but did nothing to close it.

A second, quieter problem: a `.cdfx` file received from outside is **untrusted input**. XML files can carry well-known attack patterns that, if parsed naively, can hang the tool or make it read files it should not. Loading one had to be safe.

## 3. Solution

We applied GRNDIA's V-model dev-flow over five phases. The work was scoped strictly — building the change list and reading/writing the calibration file — and broken into **11 supervised increments** (each capped at 5 files, each closed with a review packet).

What shipped:

- **A working Patch Editor.** The placeholder screen is now a functional editor: engineers can add, edit and remove change-list entries, each one identified by an A2L parameter name and an array position (for example, `PARAMETER[0] : 23`).
- **Type-aware value display.** Each value is shown in the form that suits its parameter — plain decimal, hexadecimal, signed numbers, decimals for floating-point, or quoted text — so engineers can read and verify values without converting them by hand.
- **Save to a standard calibration file.** The change list saves to a structurally valid ASAM CDF 2.0 `.cdfx` file — the standard format vCDM consumes.
- **Load a calibration file back.** A `.cdfx` file produced earlier or elsewhere loads back into the editor for review or continued editing. Anything wrong with the file is reported as a clear list of issues rather than crashing the tool, and a loaded file is also cross-checked against the current A2L to flag stale or mismatched entries.
- **Safe handling of untrusted files.** Known XML attack patterns are rejected before they can do harm, and saved files are confined to the tool's own work area. This was reviewed and cleared by a dedicated security review.

Unlike batch-02 — which deliberately changed nothing in how the tool processes data — this batch added a genuinely new data-processing capability. It did so as a self-contained new component, while keeping the existing firmware-processing engine completely frozen.

| Phase | Iterations | Key result |
|---|---|---|
| 1 — Requirements | 3 | 7 user stories, 8 high-level + 44 low-level requirements |
| 2 — Cross-agent review | 2 | 28 review findings raised (3 blocking), all closed before build |
| 3 — Implementation | 11 increments | +192 tests, firmware engine verified unchanged |
| 4 — Validation | 1 | 611 pass / 0 fail; verdict = pass-with-gaps |
| 5 — Post-mortem | 1 | batch-04 and follow-up work scoped |

## 4. Outcomes

- **All requirements met.** All 8 high-level and 44 low-level requirements verified as passing, with all 11 batch acceptance criteria met. No requirement was left partial or failed.
- **The firmware engine is provably unchanged.** The firmware parsing and validation code was verified byte-for-byte identical to the previous version — zero bytes changed. The new calibration-file capability was added entirely as new files, so it cannot have introduced a regression in the existing engine.
- **A larger, fully green test suite.** Automated tests grew from **419 to 611** (+192) with **zero failures and zero regressions** at every step. This includes a strict round-trip test that confirms a value saved and re-loaded comes back exactly equal.
- **One security review passed.** The one new surface with security relevance — handling untrusted `.cdfx` files and confining where saved files are written — was reviewed and cleared.

| Metric | Before batch | After batch |
|---|---|---|
| Passing automated tests | 419 | **611** |
| Test failures / regressions | — | **0** |
| Firmware-engine code changed | baseline | **0 bytes** |
| Requirements met | baseline | **8 of 8 high-level · 44 of 44 low-level** |
| Security reviews passed | — | **1** |

Detail: `.dev-flow/2026-05-21-batch-03/04-validation.md` §1–§9.

## 5. What's next

The Patch Editor now builds and exchanges a parameter change list. The next step — **batch-04** — has already been requested by the project owner:

- **Edit raw memory values.** Extend the Patch Editor so it can also edit values directly by memory address, not only named A2L parameters.
- **A unified change-set.** Hold both kinds of change — named parameters and raw memory fields — in a single file.
- **Selective export.** Export the named-parameter changes as a `.cdfx` file (the format vCDM expects) and the raw memory changes to a separate, simpler file, since memory-address edits have no natural place in the calibration format.

Two smaller follow-up items are also recommended: a **real round-trip check against a live vCDM installation** — confirming a file produced by `s19_app` opens correctly in vCDM, which can only be done on the client side — and a minor automated-pipeline hygiene fix (adding a code-style lint check).

## 6. Risk and confidence

- **Confidence is high.** Every requirement and acceptance criterion was met with independently verified evidence; the firmware engine was proven unchanged; no blocker-level issue was found at any gate. One real defect surfaced during the build — an ambiguity in how single values versus array values were represented — and was caught, scoped and resolved within the build phase before any release.
- **Residual items are minor and non-code.** Validation closed with a `pass-with-gaps` verdict — the "gaps" are documentary or environmental, not defects: confirmation against a live vCDM installation is a client-side check that cannot be automated in our repository; a short on-terminal visual check (the test environment is headless, so behavior was confirmed via automated tests rather than a person watching a live terminal); and adding the `ruff` lint tool to the automated pipeline. None affects correctness or blocks further work.
