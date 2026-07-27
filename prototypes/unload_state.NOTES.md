# Unload state prototype — notes

**Run:** `python prototypes/unload_state.prototype.py` (press the bracketed keys; `q` quits).

## Question
The three artifacts (S19/HEX primary + MAC + A2L) coexist in one `LoadedFile` /
`current_file`, built up by `_merge_primary_with_existing_mac` /
`_merge_mac_with_existing_primary`. There's no unload. What should unload DO to
this coexisting-artifacts model — per-artifact vs all-at-once, and how does the
state rebuild behave (especially the derived loader facts)?

## Answer (validated by driving the prototype)
- **Per-artifact unload is the right granularity.** `unload_primary`,
  `unload_mac`, `unload_a2l` each = the INVERSE of the merges: clear ONE
  artifact's fields, keep the others. Plus `unload_all` → empty.
- **`current_file` becomes `None` exactly when the last artifact is unloaded**
  (`is_empty`). MAC-only and A2L-only are valid intermediate states (the app
  already supports MAC-only load).
- **Surviving artifacts' derived facts MUST carry forward.** Unloading the MAC
  keeps the primary image's `entropy_windows` / `out_of_order_count` /
  `entry_point`. This is the SAME seam as the Memory-Map bug: the merge
  functions today drop `entropy_windows`; the unload rebuild must not repeat
  that mistake. The prototype's `unload_mac` shows entropy surviving (MemMap
  still "RENDERS"); `unload_primary` correctly zeroes it (no image).
- **`memory_map_would_render`** in the prototype mirrors the real
  `render_ranges` gate — a handy invariant to assert in the real tests:
  *an image present ⇒ the Memory Map renders.*

## Implications for the real implementation (the liftable seam)
- Add `unload_primary / unload_mac / unload_a2l / unload_all` as pure rebuilds
  next to the merges in `app.py` (they're the inverse; share the "carry derived
  facts" list — and FIX that list to include `entropy_windows`).
- After any unload, set/clear `current_file` and call the same post-load
  renderer sequence (`update_*`) so every view refreshes (including the Memory
  Map, Hex, A2L, MAC, project labels).
- Empty state (`current_file is None`) already has renderers (each `update_*`
  handles the no-file branch) — unload just needs to reach them.

## UI surface — DEFERRED to `/tui-design`
The prototype answered the STATE question, not the visual one. Open questions
for tui-design: keybinding(s) vs a menu vs a workspace affordance; how the user
picks WHICH artifact to unload (a single "unload" key that opens a small
picker? per-artifact keys? a Workspace panel with an [x] per loaded artifact?);
confirmation (unload is reversible by reloading — likely no modal needed).

## Disposition
Throwaway. Once the unload feature ships (via a dev-flow batch), delete this +
the `.prototype.py`. The validated decisions above are the keepers.
