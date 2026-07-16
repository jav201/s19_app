# Executive summary — s19_app — Batch 47 (screen upgrades, Batch A)

> Phase 6 artifact. Owner: `presentation-builder`. Audience: non-technical stakeholder. Language: English.
> Sources: `05-postmortem.md`, `04-validation.md`, `01-requirements.md` §1.1/§1.2/§2.6.

## 🔑 Bottom line (read first)

- **What we delivered:** a visual "insight layer" across five screens of the `s19tui` firmware-analysis tool, so the analyst can *see* a file's structure, health, and coverage instead of inferring it from raw numbers.
- **Business outcome:** the information the tool already calculated is now visible where the analyst is looking — delivered with 1,416 automated tests passing, zero failures, and no change whatsoever to how firmware files are read or checked.
- **Next step:** one short housekeeping change (refreshing the reference screenshots, expected because the new look changes every screen), then **Batch B — the Patch Editor upgrade**.

---

## Context (reference)

### Context

`s19tui` is the terminal application our firmware analysts use to inspect a firmware image — the binary that runs on an embedded device — alongside two companion files that describe it: a symbol file (which names the variables inside the image) and an address map (which lists specific addresses of interest).

The tool was already correct: it read the files properly and flagged the problems. What it did *not* do was help the analyst **interpret** what it showed. Screens presented accurate data and left the reader to do the work.

### Problem

**The application was computing far more than it was showing.**

Behind the screens it already calculated: how "random" versus "empty" each part of the image looks (a strong signal for where real code sits versus unused padding), how much of the address map is actually covered by the image, whether the file's records arrived out of order, where the firmware starts executing, and roughly fourteen extra descriptive fields per symbol. None of that reached the analyst's eyes. Load errors were written to a log file nobody opened. To judge a file's health, the analyst read columns of hexadecimal numbers and formed a mental picture.

The cost was time and inconsistency: two analysts looking at the same screen could reach different conclusions, and neither could do it at a glance.

### Solution

We built a **visual insight layer** on top of the existing screens. It changes only how information is *presented* — the way files are parsed and validated is untouched. Nothing new is calculated; what was already known is now shown.

Across five screens:

- **Workspace** — the main overview now states the file's load health in plain terms (errors found, out-of-order records, the firmware's starting address), shows a colour-coded strip representing the whole memory image so structure is visible in one line, gives each section a size and density cue, and colour-codes the raw byte view.
- **Symbol Explorer (A2L)** — the symbol table is colour-coded with a per-symbol marker showing whether that symbol actually exists in the loaded image, plus a detail card that surfaces the previously hidden descriptive fields for whichever symbol is selected.
- **Address Map (MAC)** — every record now carries a small health marker (present · outside the image · unreadable · not yet checked) and the view shows an overall coverage line.
- **Memory Map** — an address ruler, colour bands showing density across the image, a per-region count of how many symbols live there, and an inspector that previews the actual bytes at any region the analyst opens.
- **Whole application** — one consistent navy/pastel visual identity, so all five screens read as a single system.

### Outcomes / results

| What we can state | Evidence |
|---|---|
| **Nothing broke.** | 1,416 automated tests pass, **0 failures**. |
| **The new screens genuinely work — not just in theory.** | 20 acceptance tests drive the *real* screens the analyst uses, each one run at both a cramped terminal size (80×24) and a comfortable one (120×30). |
| **Hostile content in a firmware file cannot hijack the display.** | 4 dedicated security tests feed deliberately malicious text through the new surfaces and prove it renders as harmless plain characters. |
| **The reading/checking engine was provably untouched.** | The core files are byte-identical to the previous release — verified automatically at every step. |
| **One real defect was caught before a single line of code was written.** | A design review found that the new load-health line would have silently shown stale values once an address map was attached to an already-loaded file. Fixed in the design, never shipped. |
| **Delivered under control.** | 8 small increments, each touching at most 5 files, no scope creep, every review gate approved on the first pass. |

The practical result: an analyst can now judge a firmware file's structure and health from the screen itself, rather than reconstructing it mentally from raw values.

### Next steps

1. **Now — housekeeping (small, expected).** The new visual identity changes what every screen looks like, so 29 reference screenshots used for automated comparison are out of date. They are refreshed in a short follow-up change. This is planned bookkeeping, not a defect — the tests correctly flagged the change rather than hiding it.
2. **Next — Batch B: the Patch Editor upgrade.** The same insight treatment applied to the screen where analysts modify firmware: a live before/after view of the bytes being changed, visible check status, and edit history. It reuses the helpers and visual language built in this batch rather than rebuilding them.
3. **Two small decisions for the owner.** (a) Whether to adopt one process rule this batch validated — apply an app-wide restyle *last*, so each functional step keeps its own safety net. (b) Whether a minor colour idea, currently overridden by the existing severity colour rules, should be adopted or dropped.
