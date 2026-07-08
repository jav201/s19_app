# Prototype verdict — s19tui view enhancements

**Question:** How far can we push the existing (non-entropy) views?

**Prototype:** [view-enhancements.prototype.html](view-enhancements.prototype.html) — 4 views × 3 directions
(A Baseline+, B Dense Cockpit, C Guided Focus). Layout/hierarchy exploration only; interaction
and untrusted-input safety deferred to dev-flow AT (repo controls C-16 / C-17).

**Decision (operator, 2026-07-07):** ship 4 view enhancements —

| View            | Direction | What                                                                    |
|-----------------|-----------|-------------------------------------------------------------------------|
| A2L Explorer    | **C**     | master/detail — scannable tag list + readable record card (kills 16-col crush) |
| Issues Report   | **C**     | worst-first worklist of cards; plain-language msg + Open-in actions      |
| Workspace       | **B**     | per-range coverage micro-bars, whole-image memory strip, stat + entropy right pane |
| MAC View        | **B**     | leading status glyphs (OK/warn/oor read at a glance)                     |

**Out of this pass:** Patch Editor, A2B Diff (still placeholder), Bookmarks (dead placeholder).

**Next:** taken into `/dev-flow` as the batch requirements. Delete this prototype dir once the
winning treatments are folded into the real TUI.
