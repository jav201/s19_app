# CHUNK — Kimi — batch-93 increment 003 (legend A — the spec sheet + the interlock arm)

You implement batch-93's increment 003 in C:/Users/jjgh8/Github/s19_app. Read the
contract first: `.dev-flow/2026-10-11-batch-93/01-requirements.md` — HLR-132 (the
map's `k`-legend rebuilt as a GROUPED SPEC SHEET with a live-sourced band key —
legend A from the operator's 2026-08-06 ruling) and HLR-133 (the command-bar
interlock: a do-not-resurrect law with an arm). Increments 001+002 have landed —
build on them.

## SANDBOX
- Never write outside the project tree. No git. House env:
  `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest ... -q -p no:cacheprovider`

## THE WORK
1. **HLR-132**: rebuild the `k`-legend (the classification legend the map
   renders) as the spec sheet per legend A's capture
   (`prototypes/memmap2_legend_A.120w.svg` — re-derive, don't copy): grouped
   sections, the band key sourced LIVE from the band domain (the entropy
   bands the loaded image actually has — never a hard-coded list, so the
   legend cannot drift from the map), no prose walls. The `k` key's existing
   consumers and the legend tests (`tests/test_legend_n8.py` et al.) adapt to
   the new structure (replace, never weaken).
2. **HLR-133**: the interlock arm — assert `#command_bar_row` does not exist in
   the shipped surface (it survives only in comments per the P1 premise P-2;
   the arm guards the do-not-resurrect law). Where the arm lives and what it
   scans is your choice per the contract's LLR-133.1; the arm must be able to
   fail (a planted `#command_bar_row` row in a scanned file reddens it).
3. Tests: the contract's TC arms for the legend structure + the band-key
   liveness; the interlock arm with its plant.

## DISCIPLINE
- Legend modules + your new tests green, then the full suite once — report the
  count and the failure census (known environmental families declared).
  Snapshot baselines: regenerate only if the legend's pixels change; NAME them.
- English comments, shipped voice, S1.

## REPORT BACK
Per HLR: what changed (file:line), the band-key liveness mechanism, the
interlock arm's scan + plant, the suite counts, anything punted.
