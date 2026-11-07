# Probe: Patch Editor apply and save-back on `main` `e07fb00` (2026-11-06)

Why: the operator (US-103-06): "I saw the Apply button, but I did not see the change applied. When I saved the file with the button, only the JSON was saved." Model: Sonnet; headless Pilot on <runner> at 118x54 and 220x60, isolated HOME/XDG/LOCALAPPDATA, no clipboard. Scripts and transcripts: `pe-probe/` (`s19_app.__file__` at line 1 of each transcript).

**Verdict: the apply works; the save-back prompt appears in a tab the operator is not looking at.**

1. `Apply loaded changes` (`#patch_doc_apply_button`, `screens_directionb.py:5269`) is shown and clickable at both sizes. After it: the status line `Apply: 1 applied, 0 skipped, 0 blocked`, no notice; the image in memory changes (0x8000007C 0x3C → 0xDE).
2. The save-back prompt `#patch_saveback_row` loses `hidden` (`app.py:4854-4871`), but it sits inside `#patch_win_json` (`screens_directionb.py:5018`, row ~5118). The default tab is the Inspector, so the JSON window is not displayed: the row's region is 0×0 and a click on its Width button misses. Nothing tells the operator to switch tabs. After `#patch_tab_json` the row is visible: name `firmware-patched.s19`, `Width: 32 bytes/line` (toggles 16), `Write file`, `Don't save`.
3. `Write file` → `Saved + verified: firmware-patched.s19 — 1 entry applied before this save (0x8000007C)`; written to `<base>/.s19tool/workarea/` with no project, the project folder with one (`app.py:5035`). The output format follows the source (`apply.py:667-674`, `_SAVE_BACK_EMITTERS`): S19 → S19, HEX → HEX; no format choice, no folder choice. The width applies to S19 only; the Width button is still shown for a HEX source and does nothing.
4. `Save` (`#patch_doc_save_button`) writes only the change document (`patches/changes.json`), by design.
5. Refusals seen: no image → `0 applied, 1 skipped`, no prompt; save-back only when applied > 0 and the source is S19 or HEX; busy refuses (R-PE-110). Not probed: symbol entry, project vs loose file, A2L-only, S10.9 scope, flows.
6. Not removed by a batch: save-back since US-015 (`ff3ad12f`), apply since `0cd31118`; the layout rewrite of batch-97 Inc-4 (`09e44ded`, ledger + inspector + JSON tabs) is the likely point where the row landed under the JSON tab (not confirmed).

**Gap for US-103-06:** (a) the prompt must be reachable where the apply happens (a defect against R-CHG-003.1 "show the save-back prompt": it is shown in an undisplayed window); (b) an output-format choice, S19 (16/32 bytes per line) or Intel HEX, independent of the source (new); (c) the Width control only for S19; (d) a visible cue that the apply happened (only a status line today).
