# Executive Summary — s19tool — Batch 2026-06-14-batch-11

**Audience:** operator / stakeholders (technical, may be shared with clients or partners)
**Date:** 2026-06-15
**Scope of this work:** writing the project manifest (`project.json`) and verify-on-write for the s19tool TUI.

---

## Context

s19tool is the desktop tool the operator uses to load, inspect, edit, and save firmware
images. Each piece of work is organized as a *project* — a named bundle that records which
firmware image, which supporting files, and which active variant belong together. That
record lives in a single file, `project.json`, often called the project manifest.

Until this batch the tool could only **read** the manifest. The manifest itself had to be
written by hand, in a text editor, outside the tool. The tool understood the file but could
never produce or update one.

## Problem

Two concrete limitations followed from that read-only state:

1. **Hand-authored manifests are error-prone.** A file the tool relies on but cannot create
   has to be typed by a person, where a small slip — a wrong path, a mismatched name — goes
   unnoticed until something downstream breaks. There was no way to create or update the
   manifest from inside the tool itself.
2. **A written file needs a guarantee.** Even once the tool could write the manifest, a saved
   file is only useful if it faithfully captures what the operator intended. Without an
   automatic check, a saved manifest would be trusted on faith.

## Solution

This batch gives the tool the missing **write** side of the manifest, built on the
write-then-verify foundation laid in the previous batch (batch-10):

1. **The tool now writes `project.json`.** It takes the project's composition in memory,
   turns it into the manifest format the tool already knows how to read, and saves it. The
   write is done safely: it replaces the existing file in place — no stray duplicate files
   left behind — and before it writes anything it refuses outright any path that would point
   outside the project's own folder.

2. **Verify-on-write.** Immediately after writing, the tool re-reads the file it just wrote
   and compares it against what was intended. When the save is faithful, the tool stays quiet
   and shows a single confirmation. When it is not, it raises a clear notice that names
   exactly what drifted, so the operator sees the problem instead of discovering it later.
   This reuses the same write → re-read → compare pattern batch-10 introduced for firmware
   images, applied here to the manifest — no new mechanism was invented for it.

The net result: the operator can now create and update the project manifest from the tool,
with an automatic guarantee that the saved file matches intent.

## Outcomes

All figures below are taken directly from the validation report and post-mortem for this
batch.

- **Specification fully met.** 4 high-level and 14 low-level requirements — **100%
  validated**.
- **23 new tests** added; **all 23 pass** with 0 failures.
- **Full regression suite: 807 passed / 0 failed** (plus 29 intentionally skipped, 3 known
  expected-fail). Nothing existing was broken.
- **Delivered in 4 small increments** with **zero new third-party dependencies**.
- **Security review passed with mitigations folded in early.** Two findings — refuse any path
  that would escape the project folder, and replace the existing manifest safely in place
  rather than leaving duplicate files — were written into the requirements *before* coding,
  not patched in afterward.

**Quality highlight.** Before any code was written, the internal review caught a flaw in a
primary acceptance test: the way the tool was set to compare the written file against intent
would have been impossible to pass, because the two sides were being measured in different
forms. It was fixed at the specification stage by pinning a single, consistent form for the
comparison — so the defect never reached implementation.

## Next steps

The write-then-verify capability is reusable, and the path forward is clear:

- **Complete the manifest composition.** Today the save persists the project's **active
  variant** selection. The fuller part — writing the complete list of supporting files into
  the manifest — is **already built and tested in the underlying engine**, but is not yet
  connected to the save action in the interface. Wiring it through is the lead item for the
  next batch (batch-12). This is an honest scope boundary, not a defect: what shipped works
  correctly; the remaining piece is connecting proven machinery to the save button.
- **The first real special operation (CRC)** remains queued, pending its formal definition
  from the operator before work begins.

---

*Sources: `01-requirements.md` (§1–2, scope), `04-validation.md` (final verdict, outcomes),
`05-postmortem.md` (quality story, SCOPE-1, batch-12 slate). No figures invented; all trace
to these.*
