# Security Review — batch-78 (`cmdbar` deletion + A2B diff master–detail)

**Lane:** Phase-2 security · **Subject:** `.dev-flow/2026-08-06-batch-78/01-requirements.md` (805 lines)
**Branch:** `claude/batch-78-cmdbar-a2bdiff` @ `544f16b` · **Base:** `origin/main` @ `f6ff1d3`
**Environment:** textual **8.2.8** (the CI pin), Windows 11, Python 3.14
**Repo mutations:** none. `git status --porcelain` shows **zero** tracked-file changes; all probes ran from the scratchpad against an unmodified tree.

---

## BLUF

**Nothing blocks.** 0 blocker · **1 major** · **1 minor**.

The one finding that matters: **HLR-120's normative clause mandates `markup=False`, and `markup=False` is provably not control-character safe.** Executed at both render layers — a `markup=False` `Label` passes `U+009B` (single-byte C1 CSI), `U+009D` (single-byte C1 OSC), `U+007F`, `NUL` and `ESC` straight through to the painted strip, while `safe_text` removes all of them. `U+009B`/`U+009D`/`U+007F` are **legal Windows filename characters** (created on this machine), so the payload is reachable on the operator's own platform via a hostile A2L filename or project directory name.

It is **major, not blocker**, because for `#workspace_status_bar` the posture is *carried, not introduced* — the `#cmdbar_project`/`#cmdbar_a2l` labels this batch deletes had the identical control at the identical 10-screen reach. Only the `#loaded_panel` project row is net-new weakness. The fix is textual: three clauses in the requirement, before Phase 3 starts.

The two things I was most suspicious of going in — the batch-77 "newly reachable sink" pattern in the hex windows, and file-derived content in the run list — **both came back clean under execution**, and I record the payloads below so the clean result is auditable.

---

## Scope reviewed

`01-requirements.md` §2.3, §2.7 (P-35/P-36/P-38c/P-50), HLR-118…HLR-126, LLR-118.x…LLR-126.1, §6.4 R-8; against disk: `s19_app/tui/app.py`, `command_bar.py`, `screens_directionb.py`, `hexview.py`, `services/compare_service.py`, `docs/engineering-rules.md`, `tests/test_tui_hostile_map.py`.

Threat model applied: no network, no auth, no credential path — the untrusted input is the **loaded files themselves** (A2L symbol names, filenames, validation messages), and the realised attack class is **markup / control-character injection into a Textual render surface**.

---

## Findings

### F1 — the requirement mandates a control that is not control-character safe, and equates it with one that is  [Severity: MAJOR]

**What.** Two independent defects in the same clause:

1. **HLR-120's Statement** (`01-requirements.md:235`) reads: *"any widget receiving file-derived text **shall** be constructed with `markup=False`"*. That is the batch's only normative markup-safety clause, and it names the **weaker** of the repo's two controls.
2. **LLR-120.4** (`:420`) reads: *"**shall** be constructed with `markup=False`, **or** the text **shall** be routed through `safe_text`"* — presenting the two as interchangeable. They are not.

**Where.** `01-requirements.md:235` (HLR-120 Statement) · `:420` (LLR-120.4) · `:245` (TC-B78-12 payload) · sinks: `s19_app/tui/app.py:1916` (the cited precedent), `screens_directionb.py:1984-1987` (`_build_slot_row`, the panel LLR-120.2 adds a row to).

**Executed evidence — the two controls are not equivalent.** Payload = `b78probe` + `\x1b[31m` + `_evil[red]` + `\x9b1m` + `\x9d8;;file:///etc/passwd\x07` + `\x00\x7f`, read at both layers the project uses (C-32/C-37):

| Arm | `render().plain` / `render_line(0).text` | C0/C1 surviving |
|---|---|---|
| `Label(hostile, markup=False)` — **the precedent, at construction** | `'b78probe\x1b[31m_evil[red]\x9b1m\x9d8;;file:///etc/passwd\x00\x7f'` | `0x0 0x1b 0x7f 0x9b 0x9d` |
| `Label(markup=False).update(hostile)` — **the refresh path** | identical | `0x0 0x1b 0x7f 0x9b 0x9d` |
| `Static(safe_text(hostile))` — **the map control** | `'b78probe[31m_evil[red]1m8;;file:///etc/passwd'` | **NONE** |
| `Static(escape(hostile), markup=True)` — the run-list form | `'b78probe\x1b[31m_evil\\[red]\x9b1m\x9d8;;…\x00\x7f'` | `0x0 0x1b 0x7f 0x9b 0x9d` |

Both `markup=False` arms are byte-identical to the payload. `markup=False` closes the **markup** half of C-17 and **nothing** of the control half.

**Executed evidence — the payload is reachable on the operator's platform.** File creation on this Windows 11 machine:

```
CREATED  U+009B C1 CSI -> 'evil\x9b1m.a2l'
CREATED  U+009D C1 OSC -> 'evil\x9d8;;x.a2l'
CREATED  U+007F DEL    -> 'evil\x7f.a2l'
CREATED  U+0085 NEL    -> 'evil\x85.a2l'
REFUSED  ESC 0x1B      -> OSError 22
```

Windows reserves `< 0x20`; it does **not** reserve `U+007F` or `U+0080`–`U+009F`. This is precisely the case `_CONTROL_SCRUB`'s own comment (`screens_directionb.py:866-874`) says the byte-class filter exists for — a single-byte CSI carrying no `\x1b` at all. **Nothing in this finding depends on raw ESC**, which Windows refuses.

**Executed evidence — end-to-end on the shipped path, both surfaces in one run.** Hostile A2L filename + project name driven through `app.update_project_labels()` (the exact function LLR-120.1 re-points) and `app._refresh_loaded_panel()`:

```
--- #cmdbar_a2l       [Label(markup=False)]   <- the surface batch-78 DELETES
    strip   = 'A2L: cal\x9b31m\x9d8;;http:x\x7fevil[red].a2l'
    CONTROL survives -> ['0x7f', '0x9b', '0x9d']

--- #cmdbar_project   [Label(markup=False)]
    strip   = 'Project: proj\x9b1m[bold]'
    CONTROL survives -> ['0x9b']

--- #loaded_slots A2L cell  [Static(safe_text(...))]  <- the surface batch-78 ADDS a row to
    strip   = 'cal31m8;;http:xevil[red].a2l  0 tags'
    CONTROL survives -> NONE
```

Same payload, same run, adjacent surfaces, opposite outcomes.

**Why it matters.**
- A hostile A2L filename or project directory name emits **SGR recolouring and OSC-8 hyperlinks** into the operator's terminal, on **all 10 screens** (`#workspace_status_bar`, P-36). OSC-8 in particular renders arbitrary clickable link targets under attacker-chosen anchor text.
- **`#loaded_panel` is a genuine regression.** Every existing file-derived cell in that panel goes through `safe_text` (`_build_slot_row`, `screens_directionb.py:1984-1987`, docstring: *"`name` (str): File-derived name (escaped here via `safe_text`)"*). LLR-120.2 adds a **project row** to that same panel, and under HLR-120's Statement it would be `markup=False` only — a scrub-inconsistent cell sitting beside scrubbed ones.
- **Nothing would catch it.** `grep -rln "loaded_slots\|_build_slot_row" tests/` returns **zero files** — the Loaded panel has no test naming those symbols, and there is no repo-wide markup-sink census that covers it.
- **The batch's own acceptance cannot detect it.** TC-B78-12's payload is `[red]evil[/].a2l` (`:245`) — markup only, no control character. It is **GREEN under both arms of LLR-120.4's disjunction**, so it certifies the markup axis and says nothing about the control axis. This is the same shape as the batch's own F-6 self-catch: a predicate that cannot separate the two implementations it is meant to discriminate.

**Why it is not a blocker.** For `#workspace_status_bar` the control-char hole is **carried, not introduced**: the deleted `#cmdbar_project`/`#cmdbar_a2l` are `Label(..., markup=False)` (`command_bar.py:141-143`) rendering the same two strings at the same 10-screen reach. Post-batch posture equals pre-batch posture on that surface. The net-new weakness is one row on one panel, and the correction is three edits to the requirement text.

**Recommendation** (requirement-text only; no code in this batch yet):
1. HLR-120 Statement (`:235`) — replace *"shall be constructed with `markup=False`"* with *"shall render that text through `safe_text`, or be constructed `markup=False` **and** have the text scrubbed of the C0/C1 class (`_CONTROL_SCRUB`)"*.
2. LLR-120.4 (`:420`) — **delete the disjunction.** `markup=False` alone is not a sufficient alternative; if the alternative is kept, it must carry the scrub explicitly.
3. TC-B78-12 (`:245`) — extend the payload to `evil31m8;;http:x[red].a2l` and add the discriminating limb: **no codepoint in `C0 ∪ {DEL} ∪ C1` appears in the painted strip.** Re-derive the class in the test rather than importing `_CONTROL_SCRUB` (the discipline `tests/test_tui_hostile_map.py:86-89` already states).

*Out of scope, same root, recorded for the backlog only:* `#status_text` and `#log_line_1..4` carry the identical `markup=False`-only posture on `main`, and `set_status` reaches them with path-bearing text (e.g. `f"{type(exc).__name__}: {exc}"`, `app.py:5550`). Not this batch's to fix; noted so the class is not mistaken for two labels.

---

### F2 — the "insufficient terminal" notice has no normative bound on its content  [Severity: MINOR]

**What.** LLR-124.4 (`:529`) requires the notice to name *"the unsatisfied axis and the value required"*. As specified that is author-constant text plus an integer from a module constant — inert. But the requirement never states **normatively** that the notice composes no file-derived text, and "make the error message more helpful" is the obvious Phase-3 temptation (naming the loaded image, the two compared paths, or the A2L).

**Where.** `01-requirements.md:300` (HLR-124 Statement), `:529` (LLR-124.4). Sink: `#diff_status` is `Static(..., markup=False)` (`screens_directionb.py:6759-6764`) — so an interpolated filename would land in a surface with exactly F1's gap.

**Why it matters.** Low blast radius and entirely preventable at zero cost, but it is a **new** author surface being specified now, and the batch is writing its clause from scratch — the cheapest possible moment to bound it.

**Recommendation.** Add one clause to LLR-124.4: *the notice **shall** compose only author-constant text and integers derived from the terminal geometry and the regime constants, and **shall not** interpolate any file-derived string.* One sentence; makes the inertness a requirement rather than an accident.

---

## Probed and found CLEAN

A clean result is only worth the pushing behind it, so here is what I actually threw at each surface.

**Payload forms used throughout:** ESC-introduced CSI `\x1b[31m` · single-byte C1 CSI `U+009B` · single-byte C1 OSC-8 hyperlink `U+009D 8;;file:///etc/passwd` + `BEL` · `NUL` · `DEL` · `U+0085 NEL` · Rich markup `[red]` / `[bold]` / `[/]` · `rich.markup.escape`-processed markup · a firmware image whose **bytes are the control set**. Read at both layers: `render().plain` **and** `render_line(0).text` (never `.spans` alone — C-32/C-37).

### 1. The batch-77 pattern — a click-gated sink becoming load-reachable — does **not** recur here. ✓

This was my primary hypothesis. `_render_run_windows` has a **single call site with the literal `0`** (`screens_directionb.py:6921`); HLR-123 makes indices `1..N` reachable by arrow key and mouse. If the hex windows carried file-derived text, that would be batch-77 repeating exactly.

They do not. `render_hex_view` clamps its ASCII gutter at both producers — `chr(b) if 32 <= b <= 126 else "."` (`hexview.py:355` and `:474`). Executed against a `mem_map` whose bytes **are** the hostile set:

```
mm bytes: 1B 5B 33 31 6D 9B 9D 07 00 7F 1B 5D 38 3B 3B 78
emitted:  '0x00000000  1B 5B 33 31 6D 9B 9D 07 00 7F 1B 5D 38 3B 3B 78  |.[31m......]8;;x|'
controls in emitted -> NONE
widest row: 79
```

Every control byte becomes `.`; the surviving `[31m` / `]8;;x` are introducer-less and land in a `markup=False` `Static` (`:6767-6768`), so they are inert on both axes. **Bonus:** the widest row measured **79**, independently reproducing P-31/F-1 from a third lane.

The window **header** (`:7032`) is `f"Run #{run_index} 0x{start:08X}-0x{end:08X}"` — integers only; LLR-123.3 adds `_KIND_LABEL`, a 3-entry constant dict (`:6637-6641`). No file-derived component. ✓

### 2. The run list carries no file-derived text at all. ✓

`_render_run_list` (`:6958`) composes: `f"Runs: {int}"`, `f"A artifacts: {escape(summary_a)}"`, per-run rows of integers + `_KIND_LABEL`, and the cap notice's two integers. The `summary` values come from `result.notes["image_a"].summary` → `_build_usage` → `_summarize`, which returns one of **four module constants** (`compare_service.py:54-58`: `SUMMARY_BOTH`, `SUMMARY_ONE_A2L`, `SUMMARY_ONE_MAC`, `SUMMARY_NONE`).

So LLR-122.1's C-17 note (`:462`, *"shall preserve that escape or render `markup=False`"*) is **precautionary** — with a closed constant set on the input, either option is adequate, and unlike F1 the disjunction here is harmless. No new reachability either: the `Static` already painted **every displayed run**; selection changes which row is highlighted, not what content exists. ✓

### 3. Deletion sweep — nothing deleted removes a scrub, a bound, or a `markup=False` a survivor depends on. ✓

- `on_command_bar_find` (`app.py:5995`) / `on_command_bar_goto` (`:6025`) are **pure adapters**: they copy the typed text into the existing local input and call the unchanged `_handle_search` / `_handle_goto`. They add no validation, no parse, no bound of their own — both docstrings say so explicitly (*"No new search or string-decoding code is introduced"*). Deleting them removes no control.
- The deleted `#cmdbar_project` / `#cmdbar_a2l` are `Label(..., markup=False)` (`command_bar.py:142-143`). HLR-120 preserves the markup half normatively on the successors; the control half was never present (F1).
- `_append_log_line`'s cap survives untouched — `cap = max(50, self.size.width)` (`app.py:11655-11656`), width-aware with a floor of 50. HLR-119's notice path (7 of 10 screens) stays bounded.
- The CSS span was corrected to `:66-102` by P-49; `#command_bar_slot` `:51`, `#command_bar` `:61-64` and `#command_palette` `:104` all survive. Phase-0's `:55-102` would have deleted the surviving `#command_bar` block — already caught, correctly.
- `CommandBar.PaletteAction` explicitly preserved (LLR-121.1); the two App actions preserved and re-pointed. ✓

### 4. Re-homing `/` and `g` cannot hijack focus mid-typing. ✓

`slash` and `g` are **plain tuples**, not `priority=True` — only `ctrl+k`, `ctrl+d`, `ctrl+l`, `ctrl+s` carry priority (`app.py:1339-1342`). A focused `Input` therefore swallows both as literal characters, so re-pointing them cannot steal focus while the operator is typing a path into `#diff_path_a` / `#diff_report_dest` (both `OsClipboardInput`). TC-B78-08's palette-open negative (`:229`) is the right discriminating case and is sufficient. ✓

### 5. HLR-119 **fixes** an integrity defect rather than adding one. ✓

P-40's executed evidence: with an image loaded and the A2L screen active, a find writes `'BOOT'` into the **workspace** `#search_input` and the search actually executes against the workspace map. Acting on the pane the operator is not looking at is a real wrong-target defect; re-pointing on `_active_screen_key` closes it. Net security-positive.

### 6. R-8's posture claim holds. ✓

No new file I/O, no network, no subprocess, no credential path, no external-tool/MCP surface, no new dependency, no deploy or migration surface. Verified against the LLR symbol lists — every new symbol is a widget, a constant, a CSS class or a mapping. The only new data path is display text reaching a rendered label, exactly as §2.3 states. R-8's judgement is **correct on scope**; F1 is a defect in the *control it names*, not in its scoping.

---

## Verdict

- [x] **OK to ship with the listed mitigations applied first** — F1's three requirement-text edits should land in `01-requirements.md` before Phase 3 begins.
- [ ] OK to ship
- [ ] Block

**Nothing blocks.** No HIGH finding, no regression against `origin/main` on any surface except one row of one panel, and no new external, credential, network or destructive surface anywhere in the batch. F1 must be corrected in the requirement text rather than deferred, for one specific reason: once implemented as currently worded, the hole is certified green by TC-B78-12 and invisible to every other guard in the repo — which is the exact failure mode this project's control catalog calls the vacuous check.

---

## Evidence checklist

- [x] Each finding has what · where · why · recommendation — F1 and F2 above.
- [x] Each finding has a severity rating — F1 MAJOR, F2 MINOR.
- [x] No secret values appear in this output — n/a, no credential surface exists in this batch; nothing redacted because nothing sensitive was encountered.
- [x] Verdict is explicit — OK-with-mitigations, stated above.
- [x] New tool/integration scope and blast radius addressed — **no new integration exists.** Verified against the LLR symbol lists: zero new I/O, network, subprocess, dependency or external-tool surface (§6 above).
- [x] Claims executed, not reasoned — every table and transcript above is real output from textual 8.2.8 against the unmodified tree.
- [x] Repo integrity — `git status --porcelain` shows zero tracked-file modifications; `prototypes/memmap2.*` (the parallel session's) untouched.
