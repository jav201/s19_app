# Executive Summary — s19_app Batch 2026-05-26-batch-05

**Headline:** Three usability defects in the firmware inspection tool's hex viewer were fixed, validated, and shipped with no regressions — and the engineering process caught a flawed requirement before any code was written.

**Audience:** Project stakeholder / manager · **Date:** 2026-05-28 · **Status:** Complete, pending the standard pre-merge CI check on Python 3.11.

---

## Context

`s19_app` is a tool for inspecting firmware files — the S19, HEX, A2L, and MAC formats engineers work with during automotive/embedded development. It runs in a terminal with a text-based user interface (the "TUI"), and its central feature is a hex viewer: a panel that shows the raw contents of a firmware image so an engineer can read, search, and navigate it.

This batch was a focused, small-scope correction. It addressed three specific defects that surfaced from real use of the prior build — not new features. The goal was to make the hex viewer behave the way engineers already expect it to.

## Problem

Three independent issues degraded day-to-day use of the hex viewer:

1. **Search stopped working after scrolling.** When an engineer used text search to find something in the firmware and then scrolled to a different page, the next search would look from the old location instead of where they were now looking — so it often missed matches or wrongly reported "not found."
2. **The MAC view's hex panel was too narrow to read.** Inside the MAC tab, the embedded hex panel was sized too small to fit a full line of data, so content wrapped or got clipped — making it more of a teaser than a usable viewer.
3. **Jumping to an address gave no feedback.** When an engineer typed an address to jump to, a bad or missing address produced no message at all, and even a valid one gave no clear indication of which line it landed on.

## Solution

Each issue was corrected directly, without changing the underlying firmware-parsing logic:

1. **Search now follows the page.** After scrolling, the next search resumes from where the engineer is currently looking — the intuitive "find from here" behavior — across all three views where search is available.
2. **The MAC hex panel was widened** to comfortably show a full line of data on standard-width terminals, and it now fills the available height. Narrow-terminal layouts were deliberately left exactly as they were.
3. **Address jumps now give clear feedback.** An invalid or out-of-range address produces a plain message (e.g. "Address 0x… not in loaded file."), and a valid address gets a simple `>` marker placed on the target line. The marker is plain text by design, so it cannot interfere with the existing color-coding the tool uses to flag validation results.

## Outcomes

- **All three issues resolved** and independently verified.
- **25 new automated tests** were added to lock in the fixes and prevent them from regressing in future.
- **The full test suite is green:** 772 tests passing on the standard path, **0 failures**, **0 regressions**. (An additional heavier set of 19 longer-running tests also passed.)
- **The validation color scheme was provably left untouched** — confirmed by a byte-for-byte comparison of the relevant code — so the new address marker introduces no risk to how validation results are displayed.
- **Process rigor paid off:** the structured engineering workflow caught a defect in the *requirements themselves* — a referenced piece of the system that did not actually exist — at the review stage, before any implementation began. Catching it then, rather than mid-build, avoided wasted implementation and debugging effort.

## Next Steps

- **Pre-merge check (required):** confirm the official continuous-integration job on Python 3.11 is green before merging. Local testing ran on a newer interpreter; the change is expected to behave identically, but the official 3.11 run is the authoritative gate.
- **Documentation reconciliation (done/minor):** a small amount of internal specification wording was updated to match the as-built code. No behavior changed — these were text-only corrections.
- **Process improvement adopted:** a "name-the-real-symbol" checklist rule was added to the engineering workflow. It requires every requirement that names a specific internal component to be verified against the actual code as it is written, preventing the recurring class of specification error this batch surfaced.

---

*Prepared for non-technical review. Source evidence: batch-05 requirements, Phase-4 validation report, and Phase-5 post-mortem.*
