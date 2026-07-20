# Executive summary — array calibration objects are now coverage-checkable (batch-55)

> **Audience:** project stakeholders and non-specialist reviewers. **Purpose:** what shipped, why it matters, and what comes next — no code required.

## The short version

Calibration engineers use the s19_app tool to confirm that a firmware image actually contains every calibration object an A2L description file says it should. Until now, the tool could verify simple single-value objects, but it **could not verify array objects** (the tables and curves that make up most of a real calibration dataset) — those always showed up **grey**, meaning "coverage unknown."

batch-55 closes that gap for the common case. The tool now computes the exact byte size of curve and map objects whose axes are stored **inline**, turning them from grey ("unknown") into a real coverage check (green when the bytes are present). Just as important, it stays **honestly grey** for the cases it genuinely cannot size — it never invents a size that would let an object *falsely* pass the check.

On the reference demo file, **8 of 12** array objects that were previously uncheckable are now coverage-checkable; the other 4 remain honestly grey; **none** got a wrong size. Zero regressions, zero side effects on anything else in the tool.

---

## Context — what the tool does

An ECU firmware image is a block of bytes. An A2L file is the "map" that says which calibration objects live at which addresses. The engineer's core question is: **does this firmware actually contain the objects the map promises, at the addresses it claims?** The tool answers that by checking, for each object, whether its full byte range is present in the loaded image — a memory-coverage check.

To run that check on an object, the tool needs two things: the object's **address** and its **byte length**. Address is easy to read from the A2L. Length is easy for a single value, but for an array — a curve (1-D table) or a map (2-D table) — the length depends on the size of the table plus its axis points, which requires assembling several pieces of the A2L description together.

## The problem

Before this batch, the tool did not assemble those pieces, so array objects had **no length**. With no length, the coverage check cannot run, and the object renders grey — "not checked." Because arrays are the majority of a real calibration dataset, this was a meaningful blind spot: an engineer could not confirm coverage for exactly the objects they most often tune.

## What shipped

- **Correct sizes for inline-axis curves and maps.** The tool now derives the exact byte length for curve/map objects whose axes are stored inline with the object, and those rows become coverage-checkable (green when the firmware covers them).
- **Honest grey — never a false pass.** For objects whose axes live in a separate record (and therefore cannot be sized from the object alone), the tool deliberately leaves the length blank and keeps the row grey. This is a safety choice: on a firmware-verification tool, a *wrong* size that lets an object falsely pass the check is far more dangerous than an honest "unknown." The design guarantees the tool derives a size **only when it can size the object completely** — otherwise it stays grey.
- **Robust against bad input.** A malformed or hostile A2L cannot crash the tool or make it hang: unparseable sizes fall back to grey, and an absurdly large declared size is refused by a built-in 1 MiB safety cap.

## The outcome

| Measure | Result |
|---------|--------|
| Demo array objects now coverage-checkable | **8 of 12** (were all grey) |
| Objects deliberately kept honest-grey | 4 of 12 (axes stored externally) |
| Objects given a *wrong* size | **0** |
| Regressions elsewhere in the tool | **0** |
| Test suite | 1670 tests pass, +18 new, 0 failures |
| Rework cycles during development | **0** — the correct sizes were proven against the real demo before any code was written |

The result is safety-first by construction: more objects are now verifiable, and the ones that can't be verified are marked honestly rather than passed on a guess.

## Next steps

- **batch-56 — extended coverage.** A small category of real-world curves/maps use byte-alignment padding that this batch does not yet model; today those stay honest-grey. batch-56 will model that padding so they too get a correct size — turning "safe" into "covered."
- **Routine housekeeping.** A follow-up maintenance change re-locks the A2L parser file to read-only status (a standard post-change step), and the new test file is committed alongside the change.

---

*Consistent with the batch-55 requirements, validation, review, and post-mortem records under `.dev-flow/2026-07-20-batch-55/`.*
