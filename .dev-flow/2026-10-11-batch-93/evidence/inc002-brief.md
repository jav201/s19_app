# CHUNK — Kimi — batch-93 increment 002 (the wrap audit + the responsive regimes)

You implement batch-93's increment 002 in C:/Users/jjgh8/Github/s19_app. Read the
contract first: `.dev-flow/2026-10-11-batch-93/01-requirements.md` — HLR-130 (the
wrap audit: NO authored line wrapping at any tested geometry) and HLR-131 (the
responsive regimes: the layout stacks on narrow panels and re-apportions on
resize, 80×24 to 160×48). Increment 001 (the cockpit core) has LANDED in the
working tree — build on it, do not re-do it.

## SANDBOX
- Never write outside the project tree. No git. House env for every run:
  `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest ... -q -p no:cacheprovider`

## THE WORK
1. **HLR-130**: audit every authored line the Memory Map surface paints (region
   rows, the stats line, the chips, the inspector fields, the peek, the
   subtitle) — at the contract's tested geometries (80×24, 100×30, 120×36,
   160×48) none wraps mid-content. Where the shipped code wraps (the P1 premise
   P-1 measured a 237-cell row wrapping into soup), fix the authorship
   (clip/shorten at a word/cell boundary per the house seams), never the
   assertion. The audit's arms: a TC per surface asserting the painted line
   count and the no-wrap law at all four geometries.
2. **HLR-131**: the regimes — below the measured stack threshold (inc-001's
   pilot constants) the panels stack (list over inspector); on resize the
   regions/inspector re-apportion per the contract's law; the microbar-drop
   threshold governs what the compact stats line sheds. Arms: a TC per regime
   transition at the threshold boundaries (exactly-at vs one-below/above).
3. Tests: new file(s) as the contract's TCs demand; adapt nothing that inc-001
   already adapted unless the wrap law changes its expectation (replace, never
   weaken).

## DISCIPLINE
- The four memmap modules + your new tests green, then the full suite once —
  report the count and the failure census (the known environmental families are
  declared). Snapshot baselines: only regenerate if the wrap/regime work
  changes the map surface's pixels, and NAME them.
- English comments, shipped voice, S1.

## REPORT BACK
Per HLR: what changed (file:line), the wrap defects found and their fixes, the
regime arms, the suite counts, anything punted.
