# CHECK U-MM

- Unit: U-MM
- Tree: ~/work/zq-ta/U-MM/repo
- HEAD sha: 4f76d9144890fe86c31a3c9400d7781267bb5dd2
- Start: Thu Nov 19 04:41:34 PM CST 2026

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-ta/U-MM/repo ~/work/zq-ta/chk-U-MM`; in the copy `git diff > ~/work/zq-ta/chk-U-MM.diff`.

- Files changed (3): `s19_app/tui/screens_directionb/memory_map.py`, `tests/test_b101_help_legend_docs.py`, `tests/test_tui_map_big.py`. All within the brief's "Files (exactly 3)" list. OK.
- CR count: `tr -cd '\r' < chk-U-MM.diff | wc -c` -> 0. OK.
- Added skip/skipif/xfail/sleep( lines: `grep -cE '^\+.*\b(skip|skipif|xfail)\b|^\+.*sleep\(' chk-U-MM.diff` -> 0. OK.
- `def test_` removed and not re-added: 0 (no `^-.*def test_` lines). Added: exactly the 2 new tests the brief orders. OK.

## Step 6 (early) — diff saved
`cp ~/work/zq-ta/chk-U-MM.diff ~/work/zq-ta/U-MM/CHECK.diff`

## Step 2 — GREEN vs base

Node set (brief step 5; serial, no `-n`): the 2 new nodes, TC-656, and the 3 `test_r_tui_062_10_1_*` nodes.

Command (from the copy root `~/work/zq-ta/chk-U-MM`):
```
S=$HOME/work/zq-ta/chk-U-MM-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q tests/test_b101_help_legend_docs.py::test_r_tui_062_10_2_1_inspector_subtitle_names_only_handled_keys tests/test_b101_help_legend_docs.py::test_r_tui_062_10_3_1_row_glyph_is_enter_and_enter_inspects tests/test_tui_map_big.py::test_tc656_chrome_pane_titles_and_subtitles tests/test_b101_help_legend_docs.py::test_r_tui_062_10_1_1_map_key_line_text tests/test_b101_help_legend_docs.py::test_r_tui_062_10_1_2_named_actions_are_the_handled_ones tests/test_b101_help_legend_docs.py::test_r_tui_062_10_1_3_k_paints_the_map_keys_line < /dev/null
```
Summary: `6 passed in 26.01s`

Base transcript (from the unit brief + REPORT/pi.log):
- Base-RED: `test_r_tui_062_10_2_1_inspector_subtitle_names_only_handled_keys` (RED on unchanged product, subtitle was `↑↓ · ↵ hex`). Result now: PASSED (GREEN). OK.
- Base-GREEN: `test_tc656_chrome_pane_titles_and_subtitles` (asserted the old subtitle, product had old subtitle), the 3 `test_r_tui_062_10_1_*` nodes, and `test_r_tui_062_10_3_1_row_glyph_is_enter_and_enter_inspects`. Result now: all PASSED. No base-passing node fails now. OK.

## Step 3 — Negative controls are real

Copy: `cp -a ~/work/zq-ta/chk-U-MM ~/work/zq-ta/chk-U-MM-nc`.

### NC-1 (R-TUI-062.10.2): restore old subtitle
Mutation: `memory_map.py:454` -> `self.query_one("#map_detail").border_subtitle = "↑↓ · ↵ hex"`.
Command (from nc copy): `... -m pytest -p no:cacheprovider -q tests/test_b101_help_legend_docs.py::test_r_tui_062_10_2_1_inspector_subtitle_names_only_handled_keys < /dev/null`
Result: `1 failed in 4.56s`. RED line:
```
E       assert '↑↓ · ↵ hex' == '↑↓ move · ↵ inspect'
tests/test_b101_help_legend_docs.py:2020: AssertionError
```

### NC-2 (R-TUI-062.10.3): Enter no longer handled
Mutation: `map_parts.py:940` `if event.key == "enter":` -> `if event.key == "ctrl+enter":`.
Command (from nc copy): `... -m pytest -p no:cacheprovider -q tests/test_b101_help_legend_docs.py::test_r_tui_062_10_3_1_row_glyph_is_enter_and_enter_inspects < /dev/null`
Result: `1 failed in 4.33s`. RED line:
```
E       AssertionError: {'enter_inspects': False, 'glyph_ends': [True, True, True, True], 'navs': [], 'screen': 'map'}
tests/test_b101_help_legend_docs.py:2058: AssertionError
```

Both controls go RED. OK.
## Step 4 — Laws

Command (serial `-n 0`, from the copy root `~/work/zq-ta/chk-U-MM`):
```
S=$HOME/work/zq-ta/chk-U-MM-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -n 0 -q tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
```
Summary: `116 passed, 2 skipped in 533.92s (0:08:53)`. Matches base (116 passed, 2 skipped). No RED. OK.

## Step 5 — Worker claims (re-verified)

1. Claim: HEAD = `4f76d914` (matches launch note). `git rev-parse --short HEAD` -> `4f76d914`. **TRUE**.
2. Claim: `git diff --stat` = 3 files / `81 insertions(+), 3 deletions(-)`. Verified: `memory_map.py | 4 +-`, `test_b101_help_legend_docs.py | 78 ++++`, `test_tui_map_big.py | 2 +-`. **TRUE**.
3. Claim: NC-1 (R-TUI-062.10.2) RED line = `E assert '↑↓ · ↵ hex' == '↑↓ move · ↵ inspect'`. Re-reproduced in Step 3: `E assert '↑↓ · ↵ hex' == '↑↓ move · ↵ inspect'` at `test_b101_help_legend_docs.py:2020`. **TRUE**.
4. Claim: NC-2 (R-TUI-062.10.3) RED line = `AssertionError: {'enter_inspects': False, 'glyph_ends': [True, True, True, True], 'navs': [], 'screen': 'map'}`. Re-reproduced in Step 3 at `test_b101_help_legend_docs.py:2058`. **TRUE**.
5. Claim: final run of the unit's 6 nodes = `6 passed`. Re-run in Step 2: `6 passed in 26.01s`. **TRUE** (timing differs slightly from the reported 23.02s; that is machine noise, not a discrepancy).

Deviations (extra): both TRUE — `styles.tcss:973` still quotes `↵ hex`; the `test_tc016s_...[map-comfortable-120x30].svg` snapshot still paints `↵&#160;hex&#160;` (left for the orchestrator's snapshot regen, as the brief orders).

## Verdict

Steps 1–5 all pass: diff hygiene clean (3 allowed files, CR 0, no skip/skipif/xfail/sleep, no removed tests), the 6-node set is GREEN with the base-RED node now GREEN and no base-GREEN node failing, both negative controls go RED, the six law files are GREEN (116 passed, 2 skipped), and the worker's claims re-verify TRUE.

CHECK_DONE U-MM MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. Operator Q-MM = A (PENDING P-200): the Memory Map inspector subtitle now names what its keys do (`↑↓ move · ↵ inspect`), matching the key line R-TUI-062.10.1 already pins and the Enter handler (`RegionRow.on_key` posts `Activated(chain=1)`, inspect without navigating). Product change is the one string plus its docstring echo; TC-656 is re-pinned (the requirement it checks is live, only the text changed; TR-01). New tests: `test_r_tui_062_10_2_1` drives Down (focus moves) and Enter (the inspector shows the region, no navigation) — RED on the old text; `test_r_tui_062_10_3_1` names the row-glyph row, which was met but untested. Known and accepted: the `map-comfortable-120x30` snapshot drifts and is regenerated only by the canonical CI (HT-09); the `styles.tcss:973` comment still quotes the old text (comment only). D4-21 (Enter opens hex) stays in the backlog.
