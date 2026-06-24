# Functionality — s19_app — Batch 2026-06-24-batch-15

> **Artifact language:** English.
> Phase 6 artifact. Owner: `docs-writer`. Audience: TUI operators (firmware engineers running A<->B compares).

## 🔑 At a glance (read first)

- **What this batch fixed (US-016):** the A<->B Diff compare no longer shows a clean GREEN verdict when one of the two images silently failed to load. If a side's file has content on disk but the parser produces no valid records, the panel now shows a RED `sev-error` diagnostic naming the failed side instead of a misleading "success".
- **The one behavior that changed:** a non-empty file that maps to an empty image is now treated as a **load failure**, not as "nothing to differ".
- **How to use it:** A<->B Diff screen -> type a path into the A field and the B field -> press **Compare** -> read the status line + run list.

> US-015 was deferred. US-016 is the only story in this batch.

---

## The change (before / after)

**Before** — comparing two images by absolute path, where one image was a non-empty file the parser could not turn into any valid records (it parsed to an EMPTY memory map without raising — the parser's collect-don't-abort degenerate case), the compare service did **not** refuse. The panel showed a GREEN `sev-ok` verdict, e.g.:

```
Compared degenerate.s19 vs full.s19: 1 runs.
```

A silent load failure was presented as a clean compare. An engineer could mistake "one file silently failed to load" for "these are the real differences."

**After** — the compare detects that a side's source file has content on disk yet maps to nothing, and surfaces a RED `sev-error` diagnostic naming the failed side instead of the silent green verdict:

```
Compare failed: degenerate.s19 loaded no image (file has content but no valid records).
```

A legitimately small but valid image (maps >=1 byte) is **not** flagged — it compares normally.

---

## The three outcomes you now see

| Outcome | Verdict | What the status line shows |
|---------|---------|----------------------------|
| (a) Two valid, different images | `sev-ok` (green) | The compare summary + the list of differing runs |
| (b) A side that loaded no image (file has content, zero valid records) | `sev-error` (red) | `Compare failed: <side> loaded no image (file has content but no valid records).` — **names the failed side** |
| (c) An unresolvable / unreadable path | `sev-error` (red) | Refusal, as before (path could not be resolved or read) |

**Guard:** a valid *small* image (maps at least one byte) is **not** a load failure — it falls into outcome (a) and compares normally. The trigger for outcome (b) is specifically "non-empty file on disk -> empty memory map".

---

## How to use it

1. Open the **A<->B Diff** screen in the TUI.
2. Type the path of the first image into the **A** path field and the second into the **B** path field (absolute paths work; in/out of project both accepted).
3. Press **Compare**.
4. Read the **status line** first (it tells you whether the compare is trustworthy), then the **run list** below it.
   - Green `sev-ok` -> the listed runs are the real differences.
   - Red `sev-error` naming a side -> that file has content but produced no valid records; fix or re-export that file before trusting any diff.
   - Red `sev-error` refusal -> the path could not be resolved or read.

---

## Why it matters

The whole point of an A<->B compare is to **trust the clean verdict**. Before this fix, "1 runs" could mean either "here is one genuine difference" or "one of your files quietly failed to load and everything looks different by accident." Those are very different situations, and the engineer had no way to tell them apart from the panel. After this fix, a silent load failure can never wear the green badge — it is always called out in red, by name, so you never mistake a load failure for a diff.

---

## Safety / scope notes

- **Read-only, display-side change.** Only the verdict/diagnostic shown in the compare panel changes. No files are written or modified.
- **Diagnostic text is plain.** The side name is rendered as plain text in the status line — no markup is injected from file contents or paths.
- **Comparison engine unchanged.** The run-diff computation and the report path are untouched; the fix only adds a load-failure check ahead of rendering the verdict.
- **Engine-frozen parsers untouched.** The git-frozen parsing-layer modules (`core.py`, `hexfile.py`, etc.) are not modified by this batch.

---

## Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `tui/app.py::on_ab_diff_panel_compare_requested` | Compare handler — adds the load-failure check and emits the `sev-error` diagnostic naming the failed side, instead of the unconditional `sev-ok` verdict |

---

## Diagrams

- [`diagrams/batch-15-flows.md`](diagrams/batch-15-flows.md) — flowchart of the fixed compare handler, with the new load-failure decision marked distinctly.

---

## Evidence checklist — docs-writer

| Item | ✓/✗ | Evidence |
|------|-----|----------|
| Audience and purpose declared at the top of the doc | ✓ | "Audience: TUI operators…" + At-a-glance section |
| Structure follows the relevant template (`functionality.md` skeleton) | ✓ | At-a-glance / Detail / modules / usage / diagrams sections preserved |
| Code/CLI snippets actually run (or marked) | ✓ | The two status strings are the literal verdicts; no commands invented |
| Assumptions listed | ✓ | "US-015 deferred; US-016 only story"; absolute-path inputs assumed |
| Risks / limitations called out | ✓ | "Safety / scope notes" + the small-valid-image guard |
| Next steps stated | ✓ | Per-outcome operator action in "How to use it" step 4 |
| Diagrams included where flow is non-trivial | ✓ | `diagrams/batch-15-flows.md` linked |
| No invented APIs / version numbers / metrics | ✓ | Only the named handler `on_ab_diff_panel_compare_requested` (from batch brief) is referenced |
