# Executive summary — `s19_app` Patch Editor: raw memory editing + unified change-set, batch 2026-05-21-batch-04

**Date:** 2026-05-22
**Audience:** non-technical stakeholders (project owner, partner, manager)
**Detail artefacts:** `.dev-flow/2026-05-21-batch-04/05-postmortem.md`, `.dev-flow/2026-05-21-batch-04/04-validation.md`, `.dev-flow/2026-05-21-batch-04/01-requirements.md`

---

## 1. Context

`s19_app` is an internal tool for embedded/automotive firmware engineering. It lets calibration engineers inspect and cross-check firmware memory images, A2L calibration descriptions, and MAC tag tables, through a command-line tool and a terminal-based interface (a "TUI").

The previous batch (batch-03) made the tool's "Patch Editor" screen a real working tool: engineers could build a list of **A2L calibration-parameter changes** — named, high-level changes — and exchange that list with vCDM (Vector's calibration data management system) as a standard `.cdfx` calibration file. This batch extends the Patch Editor to handle a second, lower-level kind of change.

## 2. Problem

Working with named calibration parameters covers only part of the engineer's job. Two concrete gaps remained:

- **Engineers also edit raw memory directly.** Not every intended change has a named A2L parameter behind it — sometimes the engineer needs to change specific bytes at a specific memory address. The Patch Editor could not capture that.
- **The two kinds of change had no common home.** A parameter change list and a raw memory change list are different things, kept separately. But an engineer's intended patch set is usually a mix of both — and they need to save, load and exchange that whole patch set as **one file**, not two disconnected ones.

Without this, an engineer's full set of intended changes could not be recorded, stored, or handed off as a single working document.

## 3. Solution

We applied GRNDIA's V-model dev-flow over five phases. The work was scoped strictly — the memory-change model, one unified file, and a selective export — and broken into **9 supervised increments** (each capped at 5 files, each closed with a review packet).

What shipped:

- **Raw memory editing in the Patch Editor.** Engineers can now add, edit and remove memory changes — each one identified by a memory address and the new bytes for that address — alongside the existing parameter changes, in the same screen. Each memory value is shown in hexadecimal, ASCII text and decimal, so engineers can read and verify the bytes without converting them by hand.
- **Memory changes are checked against the loaded firmware.** Each memory change is checked against the addresses the loaded firmware image actually covers, and flagged if it falls fully or partly outside that range — reported as a clear warning, never a crash.
- **One unified change-set file.** Both kinds of change — named parameters and raw memory fields — are now held together in a single container and saved to a single file. That one file is the working document the engineer saves, loads and exchanges for the whole patch set.
- **Selective export to the right format for each consumer.** From that one unified file, the tool exports two separate files: a `.cdfx` calibration file for the parameter half (the format vCDM expects) and a separate, simpler file for the raw memory half (which has no natural place in the calibration format).
- **Safe handling of untrusted files.** The unified file can come from outside, so it is treated as untrusted input: oversized files, malformed content and unsafe file paths are rejected or flagged before they can do harm. This was reviewed and cleared by a dedicated security review.

This batch added the new capability entirely as new, self-contained files, while keeping the existing firmware-processing engine — and the batch-03 calibration-file writer — completely frozen.

| Phase | Iterations | Key result |
|---|---|---|
| 1 — Requirements | 2 | 5 user stories, 9 high-level + 37 low-level requirements |
| 2 — Cross-agent review | 2 | 22 review findings raised (1 blocking), all closed before build |
| 3 — Implementation | 9 increments | +131 tests, firmware engine verified unchanged |
| 4 — Validation | 1 | 762 pass / 0 fail; verdict = pass-with-gaps |
| 5 — Post-mortem | 1 | follow-up work scoped, recommendation: close batch |

## 4. Outcomes

- **All requirements met.** All 9 high-level and 37 low-level requirements verified as passing, with all 10 batch acceptance criteria met. No requirement was left partial or failed.
- **The firmware engine and the calibration-file writer are provably unchanged.** The firmware data-processing code was verified byte-for-byte identical to the previous version — zero bytes changed — and the batch-03 calibration-file writer was likewise confirmed unchanged. The new capability was added entirely as new files, so it cannot have introduced a regression.
- **A larger, fully green test suite.** Automated tests grew from **631 to 762** (+131) with **zero failures and zero regressions** at every step. This includes a strict round-trip test confirming that a value saved to the unified file and re-loaded comes back exactly equal.
- **One security review passed.** The new surface with security relevance — handling untrusted unified-change-set files and confining where saved files are written — was reviewed and cleared.

| Metric | Before batch | After batch |
|---|---|---|
| Passing automated tests | 631 | **762** |
| Test failures / regressions | — | **0** |
| Firmware-engine code changed | baseline | **0 bytes** |
| Requirements met | baseline | **9 of 9 high-level · 37 of 37 low-level** |
| Security reviews passed | — | **1** |

Detail: `.dev-flow/2026-05-21-batch-04/04-validation.md` §1–§9.

## 5. What's next

The Patch Editor now records both kinds of change and exchanges them as one file. The natural next step is the long-deferred core of the original Patch Editor vision:

- **Apply the change-set to the firmware image.** Take the unified change-set and actually apply it to the firmware, producing a modified S19/HEX firmware file. This batch deliberately built the data model this step consumes, but the apply step itself was kept out of scope and is deferred to a future batch. Because it modifies firmware images, it will require a full security review.
- **Undo / redo of edits.** A convenience improvement to the editing experience, also deferred from this and the previous batch.

Two smaller follow-up items are also recommended: a **real round-trip check against a live vCDM installation** — confirming a file produced by `s19_app` opens correctly in vCDM, which can only be done on the client side — and a minor automated-pipeline hygiene fix (adding a code-style lint check).

## 6. Risk and confidence

- **Confidence is high.** Every requirement and acceptance criterion was met with independently verified evidence; the firmware engine and the calibration-file writer were proven unchanged; no blocker-level issue was found at any gate. One specification defect surfaced during planning — a mismatch in how the parameter export connected to the calibration-file writer — and was caught and resolved in the review phase, before any code was written. Notably, this is the same class of defect that the previous batch caught only mid-build; catching it a full phase earlier this time made it far cheaper to fix.
- **Residual items are minor and non-code.** Validation closed with a `pass-with-gaps` verdict — the "gaps" are documentary or environmental, not defects: confirmation against a live vCDM installation is a client-side check that cannot be automated in our repository; a short on-terminal visual check (the test environment is headless, so behavior was confirmed via automated tests rather than a person watching a live terminal); and adding the `ruff` lint tool to the automated pipeline. None affects correctness or blocks further work.
