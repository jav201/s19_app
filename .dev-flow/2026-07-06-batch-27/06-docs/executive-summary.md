# Executive Summary — Interactive Memory Map (batch-27)

**Date:** 2026-07-06 · **Scope:** s19tool firmware inspection tool

---

## Bottom line

We replaced the tool's plain-text "Memory Map" view with an **interactive,
color-coded map** that lets an engineer see at a glance which parts of a
firmware image are healthy, which have problems, and which are empty — and jump
straight to the details. All three planned pieces shipped. Every capability was
proven by automated tests running against the real screen, a genuine security
flaw was caught and fixed **before** release, and none of the tool's trusted
core logic was touched. Two small finishing items remain before the change is
merged.

## Context

The s19tool is an internal utility that engineers use to open and inspect
firmware files — the software images that get loaded onto a device. One of its
screens, the **Memory Map**, shows how the device's memory is used: which
address ranges the firmware fills, and whether those ranges pass the tool's
built-in validity checks. ("Address" here just means a numbered location in
memory; a firmware image covers many such locations.)

## Problem

The old Memory Map was a **monochrome text list** — one line per range, no
color, no interaction. That made it hard to answer the questions engineers
actually care about:

- Where are the coverage gaps and the problem areas? (You had to read the whole
  list to find out.)
- What exactly is at this spot, and does it have any issues? (You couldn't drill
  in.)
- Take me to those bytes. (No way to jump.)

In short: the screen displayed data but didn't help the user *find* anything.

## Solution

A **spatial minimap**: the memory is drawn as a grid of tiles, each tile
representing a slice of the address space, color-coded so the state is obvious
without reading:

- **Green** — valid, covered memory.
- **Red** — memory that is present but fails a validity check (a problem area).
- **Grey** — an uncovered gap (nothing there).

The screen is fully interactive. **Click a tile or move to it with the arrow
keys** and a detail pane shows exactly what that slice contains — the region it
belongs to, its size and bounds, and any validation issues flagged there — plus
a one-action **jump straight to those bytes** in the tool's hex view. A
**coverage stats summary** along the bottom reports the overall picture (how
much is covered, how many gaps, the largest gap, and so on).

Importantly, the design was **approved by the operator via a working prototype
first**, before any production code was written — so we built against a target
everyone had already agreed on.

## Outcomes

- **All three planned pieces shipped**: the color-coded grid, the click/keyboard
  detail pane with jump-to-bytes, and the coverage stats summary.
- **Every capability was verified by automated tests driving the real screen** —
  not just internal helper functions. The tests open the actual map, select
  tiles, and read what the finished screen displays, including the edge cases
  (empty files, gaps, problem tiles, invalid data).
- **A real security issue was caught and fixed before release.** A maliciously
  crafted firmware file could have fed hostile text into the newly color-enabled
  screen and corrupted or crashed its display. Review caught this *before the
  code shipped*, and it was closed with no rework to surrounding logic.
- **Zero changes to the frozen core.** The tool's parsing and validation
  engine — the trusted part that decides what's valid — was left completely
  untouched. The new screen only *displays* results the core already computes.

## Next steps

1. **Finalize the visual baseline images in CI.** The automated system keeps
   reference "snapshot" images of each screen to detect accidental visual
   changes. Two images for the new map are intentionally marked as pending and
   will be regenerated in the controlled build environment; that must land
   before the change merges.
2. **Merge** once those baselines are in place.
3. **Queued polish (non-blocking):** a small tweak to how the coverage
   percentage is displayed, plus two previously deferred features — a bookmarks
   screen and human-readable names for memory regions — are logged for a future
   round.
