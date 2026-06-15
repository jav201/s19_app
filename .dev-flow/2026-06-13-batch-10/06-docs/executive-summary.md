# Executive Summary — s19tool — Batch 2026-06-13-batch-10

**Audience:** operator / stakeholders (technical, may be shared with clients or partners)
**Date:** 2026-06-14
**Scope of this work:** Intel HEX writing (US-008) and verify-on-save (US-009) for the s19tool TUI.

---

## Context

s19tool is the desktop tool the operator uses to load, inspect, edit, and save firmware
images in the two standard formats the work requires: Motorola S19 and Intel HEX.

Until this batch the tool had an asymmetry. It could **read** Intel HEX firmware images,
but it could not **write** them — only the older S19 format could be saved back to disk.
An operator who opened a HEX image, edited it, and tried to save was simply refused.

There was also a second, quieter gap. When a file *was* saved, nothing checked that the
file written to disk faithfully matched what the operator meant to save. A subtle encoding
error or a dropped byte would persist silently, and the operator would only discover it
later — if at all.

## Problem

Two concrete limitations:

1. **No Intel HEX writer.** HEX images could be opened but never saved — a daily-workflow
   dead end for any operator working in that format.
2. **No save-time certainty.** A saved file was trusted on faith. There was no automatic
   check that the persisted bytes equalled the intended ones, for either format.

## Solution

This batch delivered two capabilities, both reusing machinery the tool already had rather
than adding anything new to maintain:

1. **An Intel HEX writer.** HEX images can now be saved, not just read. The save path that
   previously refused HEX images now persists them correctly, using the same safe-write
   safeguards (no silent overwrites, writes stay inside the project work area) that S19
   saving already used.

2. **Verify-on-save.** After *every* save — S19 or Intel HEX — the tool automatically
   re-reads the file it just wrote and compares it byte-for-byte against what was meant to
   be saved. The comparison reuses the comparison engine built in the previous batch
   (batch-09), so no new code path was invented for it. The behaviour is deliberately
   undramatic: when the save is faithful, the tool stays quiet and shows a single
   "saved + verified" line; when it is not, it raises a clear, prominent notice that names
   the file and summarises the differences — and crucially, it leaves the written file in
   place so the operator can inspect it rather than deleting it out from under them.

The net result for the operator: **certainty that the persisted file is correct**, for both
S19 and Intel HEX.

## Outcomes

All figures below are taken directly from the validation report and post-mortem for this
batch.

- **Specification fully met.** 2 user stories, decomposed into 5 high-level and 14 low-level
  requirements — **100% validated** (5/5 and 14/14 pass).
- **34 new test cases** added; **35/35** targeted checks pass with 0 failures and 0 skips.
- **Full regression suite: 784 passed / 0 failed** (plus 29 intentionally skipped, 3 known
  expected-fail). Nothing existing was broken.
- **Delivered in 4 increments** with **zero new third-party dependencies** — the Intel HEX
  writer is hand-rolled, consistent with how the existing S19 writer was built.
- **Security review passed.** The verify check and its mismatch notice report only
  difference *counts* and the file name — no raw firmware bytes leak into logs or
  on-screen notices.
- **First reuse of the batch-09 comparison engine, as planned.** Verify-on-save is the first
  downstream consumer of that engine outside the comparison feature itself — confirming the
  prior batch's investment pays forward.

**Quality highlight.** Partway through implementation, a decision about *where* to place the
new HEX writer would have edited a module the project deliberately keeps frozen (the parsing
engine, which is held byte-identical to protect read correctness). This was caught at an
internal checkpoint — before any of it shipped — and corrected by relocating the new code to
the correct module. The frozen-engine rule held; the safeguard worked as designed.

## Next steps

The write-then-verify capability built here is reusable substrate, and two follow-on items
are queued for the next batch:

- **A project-manifest writer** (`project.json`) — which can itself be checked by the new
  verify-on-save mechanism, so saved project files inherit the same correctness guarantee.
- **The first real special operation (CRC)** — remains queued, pending its formal definition
  from the operator before work begins.

---

*Sources: `01-requirements.md` (§1–2, design decisions), `04-validation.md` (final verdict),
`05-postmortem.md` (lessons + batch-11 slate). No figures invented; all trace to these.*
