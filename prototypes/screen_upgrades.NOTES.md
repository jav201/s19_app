# Prototype v2 — per-screen upgrade sets by effort tier (2026-07-15)

**Question:** for EACH existing screen (Workspace · A2L Explorer · MAC View · Memory Map ·
Issues Report · Patch Editor), what does an in-place upgrade look like at each effort tier —
keeping the screen's CURRENT layout skeleton/presence, only enriching visual data-insight
cues? (Patch Editor's skeleton = batch-46's NEW 3-window layout; its BIG tier surfaces the
live before/after bytes that today exist only in generated reports.)

(v1 asked "what should the app look like" with 3 global redesign variants — operator
verdict: **REJECTED**, "big step back, deviates without improving". v2 keeps skeletons.)

**Prototype:** [screen_upgrades.prototype.py](screen_upgrades.prototype.py) — real data
(prg.s19 + ASAP2_Demo_V161.a2l + synthetic_update_test1.mac via real parsers).

- Live: `python prototypes/screen_upgrades.prototype.py` (1-6 screen · `[`/`]` tier · q)
- Headless: `--check` → 24 SVGs (18 @120×30 + 6 BIG @160×42) + [out/screen_upgrades.compare.html](out/screen_upgrades.compare.html)
  (per-screen TODAY→EASY→MID→BIG strips, fixed-size images, click for full SVG)

**Tiers (cumulative):** EASY = markup/colors/border-titles only · MID = + micro-visuals
inside existing panes · BIG = + one structural addition within the same screen.
Style system: dolphie idiom — muted label/bright value, soft pastel semantics
(#54efae/#f6ff8f/#fd8383), navy depth stack (#0a0e1b→#0f1525→#131a2c), humanized numbers,
threshold coloring, hotkey superscripts in border titles.

**Research grounding:** Textual docs sweep (border_title/subtitle, keyline, hatch,
Sparkline, Rich cells in DataTable, tooltips, FREE built-in keys/help panel +
command-palette providers) + dolphie repo study (no font trick — its screenshots are a
maximized ~240×80 terminal at ~11pt; layouts calibrated for that canvas → recommendation:
raise s19tui's 120-col layout caps + run maximized small-font).

**VERDICT (operator, 2026-07-15): APPROVED** — Workspace **MID** · A2L Explorer **MID** ·
MAC View **MID** · Memory Map **BIG** · Patch Editor **BIG** · Issues Report **parked**.
Implementation plan for the executing session: [screen_upgrades.HANDOFF-PLAN.md](screen_upgrades.HANDOFF-PLAN.md).
Still open (ask at batch kickoff): theme scope (app-wide vs 5 screens) · ≥160-col canvas
batch (separate decision).

## Engineering gotcha captured (cost ~1h of deadlock hunting)
**Never name Textual widget attributes/methods after framework internals.** Two hits in
one session: `self._nodes` (shadows `Widget._nodes` NodeList → mount crash) and
`def _context()` (shadows `MessagePump._context()` context manager used by every widget's
message pump → the pump dies silently before app-ready → **idle deadlock at boot, no
traceback**). Check `set(dir(Widget)) & {your private names}` when a Textual app hangs at
startup with ~0 CPU. Also: `run_test` boot deadlocks reproduce with `app.run(headless=True)`
— it is not pilot-specific.
