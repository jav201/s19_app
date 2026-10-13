# CHUNK — Kimi — batch-93 increment 001 (the cockpit core: chrome kit + layout + peek + stats)

You implement batch-93's increment 001 in C:/Users/jjgh8/Github/s19_app: the Memory
Map cohesion pass — variant C's core. The contract is authoritative:
`.dev-flow/2026-10-11-batch-93/01-requirements.md` — HLR-125 (the chrome kit),
HLR-126 (the cockpit layout), HLR-127 (the aligned rows), HLR-128 (the 8-byte
peek), HLR-129 (the one-line stats + chips). Read those LLR blocks fully before
writing code. The charter: `prototypes/memmap2.HANDOFF.md` + the captures
(`prototypes/memmap2_map_C_160x48.120w.svg` = the chosen variant C frame at 120w,
`prototypes/memmap2_baseline_map.120w.svg` = the shipped baseline) — re-derive,
don't copy.

## SANDBOX
- Never write outside the project tree. No git. Use the house env for every run:
  `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest ...`
- batch-92 (the refactor) has MERGED: `hexview` now lives at `s19_app/render/hexview.py`,
  `safe_text` at `s19_app/utils.py`. Import from the new homes; do not re-create
  the old paths.

## THE WORK — the Memory Map surface: `s19_app/tui/screens_directionb.py` (the
## MemoryMap panel + its cohesion kit), the map renderer in `s19_app/tui/app.py`
## (~line 2203 `render_...map`), and the FOUR memmap test modules
## (`tests/test_tui_map_big.py`, `tests/test_map_click_chain.py`,
## `tests/test_memmap_entropy_merge.py`, `tests/test_legend_n8.py`) — adapt them
## to the new contract (the P1 findings name the DOM adaptations; behavior oracles
## are pinned by LLR-126.4/127.4). New tests as the contract's TCs demand.

1. **HLR-125 — the chrome kit**: every Memory Map surface renders inside a
   bordered, titled pane (the shared kit), consistent with the rest of the app.
2. **HLR-126 — the cockpit layout**: a scrollable region list beside a
   full-height inspector; the inspector carries an aligned field block and a clean
   multi-row hex peek; the glance block retires to one line of chips (R-TUI-061's
   amendment); the stats move to ONE always-visible adaptive line (HLR-113's
   amendment); the subtitle reads `{N} regions · ░▒▓ k` per the capture.
3. **HLR-127 — the aligned rows**: region-row columns aligned (fixed-width fields
   per R-TUI-073's amendment); no authored line wrapping at any tested geometry.
4. **HLR-128 — the 8-byte peek**: the inspector's hex peek shows 8-byte rows,
   exactly 33 cells wide (re-measure from the shipped formatter; the P1 premise
   P-1 has the method), never the wrapped soup.
5. **HLR-129 — the one-line stats + chips**: the seven statistics in the
   contract's fixed field order on one line; the chips carry the mapped-byte
   share (the P1 correction — counts are run tallies; share% is the mapped-byte
   share, the only reading under which the capture's chips sum to 100).
6. **The pilot measurements (C-29)**: the two panel-column thresholds the P1
   left open (~84 stack/stats-compact, ~43 microbar-drop) — measure them
   pilot-style against the captures + the shipped renderer and record the values
   IN the code where the thresholds live (named constants with the measurement
   note), not as magic numbers.
7. **The scrollbar** is asserted behaviorally (the 120×36 capture does not
   glyph-render it — the contract declares this; assert the region list's
   scrollable behavior, not a painted glyph).
8. **Tests**: adapt the four modules (their current DOM expectations pin the OLD
   layout); add the contract's TC arms for the new layout/stats/peek; the suite
   stays green. The snapshot baselines (`tests/__snapshots__/`) — if a snapshot
   arm covers the Memory Map surface, its baseline changes by design (the layout
   changed): regenerate the affected baselines and NAME them in your report (the
   CI lane is the source of truth for snapshots; local font drift is declared).

## DISCIPLINE
- First run the four memmap modules + the map-related tests to see the current
  green state; adapt them as you go (never weaken an assertion — replace the old
  DOM expectation with the new contract's truth).
- Run: `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_tui_map_big.py tests/test_map_click_chain.py tests/test_memmap_entropy_merge.py tests/test_legend_n8.py <your new test files> -q -p no:cacheprovider` — green.
- Then the FULL suite once: `... -m pytest tests -q -p no:cacheprovider` — report
  the count and the failure census; the known environmental families (snapshot
  baselines vs CI fonts, the order-sensitive popup arms) are declared, not yours.
- English comments, shipped voice, S1 (user strings escaped via the shipped seams).

## REPORT BACK
Per HLR: what changed (file:line), the pilot-measured thresholds with their
method, the test adaptations (which DOM expectations changed to what contract
truth), the snapshot baselines regenerated (named), the full-suite count and
failure census, anything punted.
