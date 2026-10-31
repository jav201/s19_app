# Inc 8b — E13 captures (real Windows Terminal, truecolor)

Scenario added: `pe-a2l-only` in `tools/e13/run.py` (P holds only `firmware.a2l` with its `files` record) and in `tools/e13/capture_all.ps1` (open + closed). Captures: `evidence/inc-8b/e13/pe-a2l-only{,-closed}.{118x54,220x60,99x54}.png` — 6 of 6, failures=0.

## Result
- D-5 (AT-B100-10) renders at 220x60: the Loaded panel paints `A2L  firmware.a2l  3 tags`, `S19 (none)`, `MAC (none)`, `[u] unload all`.
- At 118x54 and 99x54 the panel is in its compact two-row form (PROJ + S19), the same form Inc 8a's captures show (`inc-8a/e13/pe-saveback-closed.118x54.png`); the A2L appears only in the status bar (`P | firmware.a2l`).

## Observations (MINOR, routed to BACKLOG-CODE — no corrective pass; skill E5: one pass)
- OBS-8b-1 (design-gap): compact panel with no image shows `S19 (none)` and hides the session A2L; an A2L-only project at <=118 columns shows no A2L in the panel.
- OBS-8b-2 (impl): the Load-result panel for an A2L-only project paints `Opened (no image)` followed by the reason "the first variant by name (the manifest records no active variant)" and offers `Select variant (v)` with 0 variants — the reason row contradicts "0 in the project".
- OBS-8b-3 (pre-existing, impl): the Workspace empty state "No file loaded - press Ctrl+L ..." stays painted while an A2L is loaded (status bar names it). `_apply_empty_state` keys on `current_file` (LLR-002.3), so a standalone A2L Load file reaches the same state — not introduced by 8b (read from code, not captured).
