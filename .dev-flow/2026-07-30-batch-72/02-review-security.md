# Phase-2 Review — security-reviewer — batch 2026-07-30-batch-72

## BLUF

**One major, three minors, zero blockers. Iterate back to Phase 1 — the fixes are all to the
document, not to code.**

The batch introduces **no new I/O, no network, no new file writes, no new dependency, no new
external tool**. The only security-relevant surface is the one this project has been burned by
before: **C-17 markup-injection sinks**. On that axis the *shipped code* is currently correct —
all six `_recompute` surfaces are `markup=False` today — but **§2.4's claim "every existing
`markup=False` sink stays `markup=False`" is an unverified assertion for 2 of the 6 sinks**
(`#crc_custom_vector_result`, `#crc_coverage_preview`). No test would go RED if the rewrite
dropped the kwarg on those two, and this batch *rewrites the `compose` that sets them*. That is
S-1.

Two things that could have been findings are **not**, and I state them explicitly rather than
inflating them:

- **The Legend re-parent is safe by construction.** `_render_key` / `_render_card` return
  constructed `List[Widget]` (`screens.py:1160-1192`, `:1112-1130`) — not markup strings. A
  Textual `Static`'s `markup=` is a per-widget constructor flag, not inherited from its parent,
  so moving those widgets into a new pane container cannot flip any of them. The *only* way
  LLR-072-5.1/7.1 breaks this is if the "grouping helper allowed in `screens.py`" reconstructs
  rows from text instead of re-parenting the returned widgets — see S-2b.
- **No untrusted text reaches a markup-parsed sink anywhere in scope.** File-derived and
  user-typed values (`name`, `aliases`, width/poly/check) land only in `markup=False` sinks.

## Render-sink census (C-17)

All `markup=` values below are read off the live tree, not inferred.

### CRC Designer — the six `_recompute` surfaces (`crc_designer_view.py:1115-1142`)

| Sink (id / widget) | File:line | `markup=` today | Touched by §4? | Text provenance | Risk |
|---|---|---|---|---|---|
| `#crc_kat_verdict` `Static` | `crc_designer_view.py:397` | **False** (explicit) | **YES — re-parented.** LLR-072-2.1 deletes `verdict_group` and rebuilds it as a `Self-test` row inside `#crc_algorithm_fields` | `_verdict_text` → `Text` (`:716-721`); **error path** `_recompute:1129` writes the plain **str** `f"Invalid parameters: {exc}"` | **Pinned** — `tests/test_crc_designer_view.py:347,355` asserts `_render_markup is False` |
| `#crc_warnings` `Static` | `crc_designer_view.py:403` | **False** (explicit) | **YES — re-parented.** `#crc_top_right` becomes Warnings-only | `_live_warnings_text` → `Text`; error path str | **Pinned** — `test_crc_designer_view.py:605,613` |
| `#crc_json_preview` `Static` | `crc_designer_view.py:367` | **False** (explicit) | Not structurally moved (stays the full-width strip) | `emit_template` incl. **file-derived** `name`/`aliases` — the highest-risk sink per LLR-V5.3 F1 | **Pinned** — `test_crc_designer_view.py:486,494` |
| `#crc_coverage_window` `Static` | `crc_designer_view.py:411` | **False** (explicit) | Stays in `#crc_hero_row` | `_render_coverage_window` → `Text`; error path str | **Pinned** — `:1084,1112`, `:1169`, `:1202`, `:1383` |
| `#crc_custom_vector_result` `Static` | `crc_designer_view.py:351-356` | **False** (explicit) | Not moved, but **shares the `_recompute` error write** (`:1130`) | `_custom_vector_text` → **str**; error path str echoing user-typed values | **NOT pinned** — see S-1 |
| `#crc_coverage_preview` `Static` | `crc_designer_view.py:341` | **False** (explicit) | Not moved, but **shares the `_recompute` error write** (`:1133`) | `_coverage_preview_text` → **str**; error path str echoing user-typed values | **NOT pinned** — see S-1 |

### CRC Designer — other sinks in the edited `compose`

| Sink | File:line | `markup=` today | Touched by §4? | Provenance | Risk |
|---|---|---|---|---|---|
| `#crc_designer_help` `Static` | `crc_designer_view.py:275-280` | **False** | No | author literal | none |
| `#crc_loadsave_status` `Static` | `crc_designer_view.py:391` | **False** | No | echoes `OSError` / sanitized filename (`:1215,1218,1220`) | none this batch (pre-existing, correct) |
| `_switch_row` `Label` (`"Reflect in"` / `"Reflect out"`) | `crc_designer_view.py:466` | `Label` default = **True** | **YES — the pair row replaces both calls** (`:301-302`) | author literals `"Reflection"` / `"in"` / `"out"` | none — no untrusted text; the new row's labels are author constants |
| `Select` option labels (`#crc_preset_select`, `_select_row`) | `crc_designer_view.py:288-293`, `:488-493` | Textual 8.2.8 **parses raw `Select` labels as markup** (the C-15 probe, cf. `screens.py:1468` which escapes them) | HLR-072-4 changes **CSS height only** | `PRESETS` names + `ENDIANNESS/INTRA_GAP/JOIN/ON_GAP_CONFLICT` vocabularies — all author constants | none — no dynamic label; capping height cannot introduce one |

### Legend modal — every widget the two-pane split re-parents

| Sink | File:line | `markup=` today | Touched by §4? | Provenance | Risk |
|---|---|---|---|---|---|
| Card rows `Static(line.text, classes=…)` | `screens.py:1124-1129` | default = **True** (deliberate — card lines carry `[b]…[/]`) | re-parented into the card pane | `LEGEND_EXAMPLES` author data with pre-escaped `\[` | flag travels with the widget — safe re-parent |
| Warning sample `Static(f"[{style}]{escape_markup(...)}[/]", id="legend_mac_warning_sample")` | `screens.py:1116-1122` | default = **True**, payload explicitly `escape_markup`'d (`screens.py:8`) | re-parented | author data | safe **only if re-parented, not re-wrapped** — see S-2b |
| Map band rows | `screens.py:1166-1172` | **False** (explicit — each row carries a literal `[lo,hi)`) | re-parented into the **key pane** | derived from `ENTROPY_BANDS` via `build_band_key_rows` | flag travels; **not pinned by any test** — see S-2 |
| `BAND_GAP_HATCH_NOTE` row | `screens.py:1174` | **False** (explicit) | re-parented | author constant | as above |
| `BAND_DOMAIN_NOTE` row | `screens.py:1176` | default = **True** | re-parented | author constant, bracket-free | none |
| `Label("Entropy bands")` / `Label(artifact)` | `screens.py:1162`, `:1182` | default = **True** | re-parented | `LEGEND_TABLE` keys (author) | none |
| Severity key rows `Static(f"{classification} — {meaning}")` | `screens.py:1191` | default = **True** | re-parented into the key pane | `LEGEND_TABLE`, bracket-free **by rule S-01** (`legend.py:86-88`) | none |

**Answer to the live question:** no planned change flips a sink from `markup=False` to
markup-parsed, and no file-derived text (A2L symbol names, MAC tags, validation messages) is
moved into a markup-parsed sink. Legend key/card content is author-static; CRC untrusted content
is confined to the six `markup=False` sinks. The exposure is **regression risk during the
rewrite**, not a design flaw — which is exactly what S-1 asks the batch to close.

## Findings

### S-1 — §2.4's C-17 claim is unverifiable for 2 of the 6 CRC sinks — **major**

**Claim:** `#crc_custom_vector_result` and `#crc_coverage_preview` are `markup=False` today but
**no test asserts it**. Four of the six sinks have a `_render_markup is False` arm; these two
have only content assertions. §2.4 states the invariant as fact; nothing enforces it. This batch
rewrites the very `compose` that sets these kwargs (LLR-072-1.1/2.1), so a dropped
`markup=False` during the re-nesting ships green.

**Evidence:**
- Sinks declared `markup=False`: `s19_app/tui/crc_designer_view.py:341` (`#crc_coverage_preview`),
  `:351-356` (`#crc_custom_vector_result`).
- Test coverage that exists: `tests/test_crc_designer_view.py:347,355` (kat_verdict),
  `:486,494` (json_preview), `:605,613` (warnings), `:1084,1112` / `:1169` / `:1202` / `:1383`
  (coverage_window).
- Test coverage that does **not** exist: `grep _render_markup tests/test_crc_designer_view.py`
  returns no hit for either id. The two are read only for content at `:279`, `:288`, `:676`.
- The reachable payload path (this is not hypothetical): `_current_algorithm` parses the form with
  `int(width_text)` (`crc_designer_view.py:643`), `int(check_text, 16)` (`:645`) and `_hex_field`
  (`:660`). A non-numeric entry raises `ValueError: invalid literal for int() with base 16:
  '<the user's literal text>'`. `_recompute` catches it at `:1127` and writes
  `f"Invalid parameters: {exc}"` into **all six** sinks — `:1130` is `#crc_custom_vector_result`,
  `:1133` is `#crc_coverage_preview`. So user-typed text is echoed verbatim into both.
- The batch drives exactly this field: AT-215 requires "editing `#crc_field_check` through the
  surface".

**Impact:** With the flag intact this renders literally and is harmless. With the flag dropped,
a `[` typed into Check/Width/Polynomial is parsed as markup: at best the bracketed text silently
disappears from the operator's error message (a corrupted diagnostic on the surface whose entire
job is to report a bad parameter); at worst a malformed tag raises `MarkupError` inside
`Static.update`. Note `_recompute:1136-1142` has **no `try/except` around the `.update()` calls** —
only around the query block and `_current_template` — so a raised `MarkupError` propagates on the
UI thread. Blast radius is local (a single-user local TUI, no network, no persistence of the
payload), which is why this is major and not a blocker.

**Proposed disposition (qa lane authors the test; this is a Phase-1 document fix):**
Add one structural TC from the reserved `TC-510..TC-519` block and cite it in §5.2, asserting
`_render_markup is False` for **all six** ids. Make it a live oracle rather than a hand-list so it
cannot drift: hoist `_recompute`'s six queried ids into a module-level tuple in
`crc_designer_view.py` and have the test iterate *that*, so a seventh live surface added later is
covered automatically (the C-31 live-oracle pattern already used by
`tests/test_legend_n8.py:445-459`). Failing that, at minimum extend `_RIGHT_COLUMN_IDS`
(`tests/test_crc_designer_view.py:1399-1409`) with a markup arm. Also amend §2.4 to say the
invariant is *enforced by TC-5xx*, not merely asserted.

### S-2 — TC-N8-11 gives the Legend **render** layer zero markup protection; §2.4 cites it as if it did — **minor**

**Claim:** §2.4 says the legend "escaping rules (S-01 / TC-N8-11) are reused verbatim". TC-N8-11
is a **data-level** test: it iterates `LEGEND_EXAMPLES` *strings* through `Content.from_markup`
and never touches a widget. It stays green no matter what `compose` does. The `markup=False`
flags on the map band-key rows — the ones that must survive being moved into the new key pane —
are pinned by nothing.

**Evidence:** `tests/test_legend_n8.py:247-272` (`_all_lines()` yields `line.text`;
`Content.from_markup(text)` — no widget in the loop) and `:468-471`. The unpinned flags are
`s19_app/tui/screens.py:1166-1172` and `:1174`. `tests/test_legend_scope_and_logwidth.py:88-89,121`
selects `.legend-row` / `.legend-card-sub` by class only — no markup arm. `tests/test_tui_legend.py:60,338,407`
reads rendered text only.

**Impact:** Low. The band-row content is derived from `ENTROPY_BANDS`, not from a loaded file, so
the worst case is the range text `[5,7.2)` being eaten as a style tag — a wrong legend, not an
injection. But it is precisely the regression the two-pane move could cause, and the requirement
currently claims coverage it does not have.

**Proposed disposition:** Add a flag arm to **AT-218** (already the "data-pipeline preservation"
AT): assert the band rows and `BAND_GAP_HATCH_NOTE` row in the key pane still report
`_render_markup is False`, and that `#legend_mac_warning_sample` still renders its bracket payload
literally. Reword §2.4 to distinguish the data guard (TC-N8-11, unaffected) from the render-flag
guard (new, owed).

### S-2b — LLR-072-7.1's "grouping helper" is the one way the safe re-parent becomes unsafe — **minor**

**Claim:** LLR-072-7.1 permits "a grouping helper in `screens.py` if needed". The re-parent is
safe *because* `_render_card`/`_render_key` hand back constructed widgets carrying their own
flags. A helper that instead re-derives rows from text would silently relocate the markup decision
into new, unreviewed code — and would put the `escape_markup`-wrapped warning sample at risk of a
double-escape or a lost escape.

**Evidence:** `s19_app/tui/screens.py:1132` (`_render_key(self) -> List[Widget]`), `:1084`
(`_render_card(self) -> List[Static]`), consumed as widget lists at `:1195`. The escape-sensitive
construction is `:1116-1122`.

**Impact:** None today; it is a requirement-wording hole, not a code defect.

**Proposed disposition:** One sentence in LLR-072-7.1: *the helper may only wrap the widget lists
returned by `_render_card()` / `_render_key()` in containers; it must not reconstruct rows from
text or re-wrap `#legend_mac_warning_sample`'s markup.*

### S-3 — `#legend_body` is omitted from HLR-072-7's preserved-id list but carries 7 assertion sites — **minor** (not a security defect; handing to qa/architect)

**Claim:** HLR-072-7 preserves `#legend_dialog`, `#legend_close`, `#legend_mac_warning_sample`.
It does **not** name `#legend_body`, yet all three blast-radius test files select through it. A
two-pane split that replaces the single `ScrollableContainer(id="legend_body")` with two panes
falsifies AT-218's own "existing legend test files stay green" clause.

**Evidence:** current construction `s19_app/tui/screens.py:1198`. Assertion sites:
`tests/test_legend_n8.py:284`, `:387`; `tests/test_legend_scope_and_logwidth.py:34`, `:88`, `:89`,
`:121`; `tests/test_tui_legend.py:60`, `:338`, `:407`.

**Impact:** A late Phase-3 surprise — 6+ tests break on an id the requirement never promised to
keep. No security consequence.

**Proposed disposition:** Add `#legend_body` to HLR-072-7's preserved-id list and decide now
whether it becomes the *outer* container holding both panes (cheapest — every existing selector
keeps resolving) or is retired with the selectors updated. Architect/qa lane owns the call.

### S-4 — the `.sev-*` / `.band-*` colour **values** live in the non-frozen `styles.tcss` this batch edits — **minor** (scoping guard)

**Claim:** §2.4's frozen-set reasoning is correct — no IN-scope file is frozen — but it may read
as "severity colours are protected by the freeze". They are not. `color_policy.py` (frozen) owns
the class *names* and the severity→class mapping; the actual hues are declared in
`s19_app/tui/styles.tcss`, which is IN scope for LLR-072-2.2 and LLR-072-6.1.

**Evidence:** `.sev-ok/error/warning/info/neutral` at `styles.tcss:628-648`; `.band-*` at
`:665-679`; the file's own note at `:620-621` records that retuning `.sev-warning` here is what
moved the documented row cue orange→yellow. The legend correctly *reads* the mapping —
`screens.py:1186` calls `css_class_for_severity`, and `legend.py:27` imports the two overlay-style
constants from the frozen `color_policy` — so **the batch reads severity colours rather than
redefining them**, as required. Confirmed: LLR-072-7.1 forbids any `legend.py` edit.

**Impact:** None as planned; a one-line drift in the wrong CSS block would silently re-colour
every severity row app-wide, and no snapshot would catch it (P-2/P-3: neither screen is
snapshot-captured).

**Proposed disposition:** Add to §1.2 OUT: *no edit to the `.sev-*`, `.band-*` or `.legend-card-*`
blocks in `styles.tcss`; the batch adds layout rules only.* Cheap, and it makes batch acceptance
criterion 6 ("if any snapshot fails, STOP") meaningful for the one axis snapshots cannot see.

### No finding on these axes

Checked and clean — reported explicitly rather than padded into findings:

- **Secrets / credentials.** No `.env`, key, token, credential or signed URL anywhere in scope.
  No new logging of user data; the only legend log line is a static string
  (`screens.py:1212-1214`). `_save_template`'s status echoes a **sanitized** basename only
  (`crc_designer_view.py:1193-1220`, `sanitize_project_name` → fixed directory, F2/F3) and is
  untouched by this batch.
- **New external tool / MCP / Composio / n8n / third-party API.** **None added.** Nothing to
  scope-review; no new outbound action surface, no data leaving the local system (so no LFPDPPP
  client-data flag).
- **Auth flows.** None present in the s19_app TUI; nothing in scope.
- **Destructive command surface.** No `rm`/`Remove-Item`/force-push/schema-migration in scope. The
  batch writes no firmware and no files (`US-V8` preserved: the CRC bench remains preview-only).
- **Dependencies / supply chain.** No new package, no lockfile change, no install script.
- **Deploy / release.** No production deploy; the change is a local TUI layout. Rollback = revert
  the PR. Migrations: none.
- **Path handling.** `#crc_load_path` / `resolve_input_path` / `ensure_template_lib` are untouched.
- **Prototype teardown.** `prototypes/p1_design_defects.*` are reference-only inputs, not runtime
  dependencies (§2.5), and §6.3 already mandates a rewrite rather than a copy-paste of
  `VariantB` — no prototype code path can reach the shipped tree.

## Frozen-set check

Frozen set per `CLAUDE.md`: `core.py`, `hexfile.py`, `range_index.py`, `validation/`,
`tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`.

§1.2 IN-scope files: `s19_app/tui/crc_designer_view.py`, `s19_app/tui/screens.py`,
`s19_app/tui/styles.tcss`, `tests/`, `REQUIREMENTS.md`.

**Intersection: empty. ✓ No unfreeze needed, matching §1.2's claim.**

Severity-colour handling: the Legend key pane **reads** the severity mapping through the frozen
module (`screens.py:1186` → `css_class_for_severity`; `legend.py:27` imports
`FOCUS_HIGHLIGHT_STYLE` / `MAC_ADDRESS_OVERLAY_STYLE` READ-only) and does not redefine it.
LLR-072-7.1 forbids editing `legend.py` at all. ✓ — with the S-4 caveat that the hue *values*
sit in the editable `styles.tcss`.

Batch acceptance criterion 2 (`git diff origin/main -- <frozen set>` empty, both guard arms green)
is the right enforcement and is already in the requirement. ✓

## Evidence checklist

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Each finding has what · where · why · recommendation | ✓ | S-1..S-4 each carry Claim / Evidence / Impact / Proposed disposition |
| 2 | Each finding has a severity rating | ✓ | S-1 major; S-2, S-2b, S-3, S-4 minor; 0 blockers |
| 3 | No secret values appear in this output | ✓ | No secrets exist in scope; nothing quoted. Payload examples are described (a literal `[`), never a credential |
| 4 | Verdict is explicit | ✓ | see Verdict below |
| 5 | New tool/integration scope + blast radius addressed | ✓ (n/a) | None added — verified against §1.2 IN list and §4 LLRs; no network, no new I/O, no new dependency |
| 6 | Every `markup=` claim cited at `file:line` | ✓ | Census table, all rows |
| 7 | Frozen-set intersection computed, not assumed | ✓ | Frozen-set check section |

## Verdict

**0 blockers / 1 major / 3 minors — iterate back to Phase 1.**

Nothing here blocks the design. All four findings are fixed by editing
`01-requirements.md` before Phase 3 — no code decision changes:

1. **S-1 (major)** — add a six-sink `markup=False` census TC from the reserved
   `TC-510..TC-519` block, ideally driven off a live id tuple; cite it in §5.2; downgrade §2.4's
   C-17 line from an assertion to an enforced invariant.
2. **S-2 (minor)** — add a render-flag arm to AT-218; stop citing TC-N8-11 as render coverage.
3. **S-2b (minor)** — one constraint sentence on LLR-072-7.1 (helper may wrap, not reconstruct).
4. **S-3 (minor)** — add `#legend_body` to HLR-072-7's preserved-id list (qa/architect owns the
   keep-vs-retire call).
5. **S-4 (minor)** — add the `.sev-*` / `.band-*` / `.legend-card-*` CSS blocks to §1.2 OUT.

With S-1's TC authored and the four wording fixes applied, this batch is **OK to ship** from a
security standpoint.
