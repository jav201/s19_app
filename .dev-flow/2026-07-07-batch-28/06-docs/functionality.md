# Functionality · batch-28 view enhancements

## What a user sees

Three s19tui screens got more legible/scannable. All changes are display-only — the tool parses,
validates, and computes coverage exactly as before; only how it's *shown* changed.

### A2L Explorer (key `2`)
The symbol table is denser (more rows on screen) and its column header stays put while you scroll
the rows, so you never lose the meaning of a column in a long symbol list. Row severity colouring is
unchanged.

### Issues Report (key `5`)
Instead of one flat table, validation issues are now grouped by severity — **Errors**, then
**Warnings**, then **Info** — each group led by a header showing how many issues it holds
(counting the whole filtered list, not just the visible page). Each issue shows its code as a compact
coloured "chip". The live hex-peek pane on the right is kept: selecting an issue (click or Enter)
shows the bytes at that issue's address. The existing severity filter and paging still work. A page
with many issues shows a capped preview with a "more" note (so the screen stays fast even on a badly
broken image with thousands of findings).

### Workspace (key `1`)
The home screen now surfaces coverage health inline, without opening the Memory Map:
- **Per-range bar** — each data range shows a small bar whose colour is its validity (green valid /
  red invalid) and whose width reflects the range's relative size.
- **Memory strip** — a one-row colour band across the whole image (valid / invalid / gap), a
  bird's-eye coverage shape.
- **Stat pane** — coverage %, and range / error / warning counts, at a glance.

## How it's built (for a technical reader)
- **Render-only over the existing model.** Every surface reads already-computed data on the UI
  thread — `LoadedFile.ranges` / `range_validity`, the enriched A2L tags, and `_validation_issues` —
  and performs no new parsing/validation. The parsers (`core.py`, `a2l.py`, `mac.py`, the
  `validation/` engine) are untouched (git-frozen; 0 diffs).
- **Colour single-source.** All severity colour flows through the frozen
  `color_policy.css_class_for_severity` — no hard-coded hex anywhere.
- **Untrusted-input safe.** File-derived strings (issue code/symbol/message, A2L symbol names) are
  rendered as literal `rich.text.Text` (never markup-parsed), so a malicious symbol like
  `sensor[red]` or an embedded terminal escape renders literally instead of corrupting the screen.
- **Bounded.** The Issues grouped view caps mounted rows (`_GROUP_DISPLAY_MAX`), and the memory
  strip caps its cell count to the band width — a hostile file can't blow up the widget tree.
- **New module:** `s19_app/tui/issues_view.py` (the grouped-issues widgets). Everything else is
  additive edits to `app.py` (renderers) and `styles.tcss` (layout).

## Provenance
Designed via a throwaway prototype (`prototypes/view-enhancements.prototype.html`); the operator
selected the shipped direction per view at the Phase-1 gate (A2L Baseline+, Issues Dense Cockpit,
Workspace Dense Cockpit; MAC left as-is). Design intent only came from the prototype — every
interaction and the untrusted-input handling were re-verified in Textual.
