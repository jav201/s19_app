# Inc-7 — entry gate (premise sweep + mechanism decision). **IMPLEMENTATION NOT STARTED.**

**Batch:** `2026-08-07-batch-79` · **Base:** `ed11626` (Inc-6) · **Tree state:** clean, nothing staged

---

## 0 · BLUF

**`HLR-120`'s symbol citations are stale as a CLASS — 13 of 15 — and the offsets are not uniform, so
they cannot be repaired by addition. Every symbol must be resolved by NAME.** One premise that looked
false on first measurement is **TRUE**; it is recorded as verified rather than as a finding.

**This increment is deliberately NOT started.** The entry-gate work below is complete and standalone.
The implementation is a 4-file change carrying 5 LLRs, 5 ATs and 6 TCs, and starting it without room to
finish the counterfactuals would leave the tree in a state no one could gate. Stopped at a coherent
boundary per the flow's interruption protocol.

---

## 1 · Premise sweep (C-43), executed against `ed11626`

| # | Premise | Verdict | Evidence |
|---|---|---|---|
| Q-1 | `HLR-120`'s 15 cited symbol addresses are current | ❌ **FALSE — 13 of 15 miss** | Every symbol **exists**; only the addresses are wrong. See §2 |
| Q-2 | `set_context_labels` has **exactly one** call site | ✅ **TRUE** | `app.py:11420`. A raw grep returns two hits, but `:11390` is a **docstring** line in the `Dependencies:` block, not a call. My first pattern counted prose — recorded because that is the same "an unstated grep pattern is an unstated definition" trap, hit again |
| Q-3 | `#workspace_status_bar` is **116×7 on all 10 screens** and carries neither name (P-36) | ✅ **TRUE** | Executed at 120×30 across all 10 `SCREEN_CONTAINER_IDS`: every screen `(7, 116)`, distinct heights `[7]`. Children = **6**: `status_text`, `progress_bar`, `log_line_1..4` |
| Q-4 | The project label has **two** display forms, plain gated on `> 1` (P-38c) | ✅ **TRUE** | `app.py:11397` plain default; `:11399-11403` guard, `len(variant_set.variants) > 1`; `:11415-11418` the suffixed composition |
| Q-5 | `update_project_labels` writes to the command bar and nothing else | ✅ **TRUE** | `app.py:11359-11421`; the write is `:11420`, followed only by `_refresh_patch_variant_select()` |

## 2 · Q-1 in full — why "add the offset" does not work

batch-78's Lane 2 added +73 lines to `app.py`, so a citation written before it landed is shifted. But the
shift is **not constant**, which is what makes this a finding rather than an inconvenience:

| Symbol | Cited | Actual | Offset |
|---|---|---|---|
| `update_project_labels` | `app.py:11290` | **`:11359`** | +69 |
| the `set_context_labels` call | `app.py:11351` | **`:11420`** | +69 |
| the multi-variant guard | `app.py:11333` | **`:11402`** | +69 |
| `_refresh_loaded_panel` | `app.py:8649` | **`:8715`** | +66 |
| `on_command_bar_find` | `app.py:5995` | **`:6036`** | +41 |
| `#workspace_status_bar` | `app.py:1930` | **`:1945`** | +15 |
| `#status_text` | `app.py:1916` | **`:1931`** | +15 |
| `LoadedArtifactsPanel` | `sdb.py:1738` | **`:1741`** | +3 |
| `safe_text` | `sdb.py:878` | **`:881`** | +3 |
| `set_context_labels` (def) | `cb.py:216` | `:216` | **0 — held** |

Offsets of +69, +66, +41, +15, +3 and 0 in one requirement. **Any single correction constant is wrong
for most of the set**, so the disposition is: **resolve by name, never by line, and do not chase
individual corrections back into the spec** — that would be re-deriving a spec the charter says to
execute. The addresses are navigation aids that have expired; the symbol names have not.

> This is the same class as Inc-6's `P-1`, one level broader. There it was one range that was wrong when
> written; here it is a whole citation set invalidated by an edit elsewhere in the file. **A line number
> is not a durable reference to a symbol, and this batch has now paid for that twice.**

## 3 · Mechanism decision for `LLR-120.3` (the row budget)

`LLR-120.3` leaves the mechanism deliberately unspecified and names *"sharing a row with `#status_text`"*
as the obvious candidate, flagged `assumed — re-measure at Phase 3`. Re-measured: **6 children, height 7,
identical on all 10 screens.**

**Decision: `#status_text` and a new `#status_context` Label become siblings inside a `Horizontal`.**

| Option | Expected result | Consequence |
|---|---|---|
| A new Label as a 7th child | context is visible | ❌ height 7 → 8. `LLR-120.3` forbids it, and the diff pane has 2 content rows to spare |
| Write the context **into** `#status_text` | no new row | ❌ `set_status` / `set_file_status` own that widget and would clobber the context on the next write |
| ✅ **`Horizontal(#status_text, #status_context)`** | no new row; two independently-written widgets | Needs a `styles.tcss` rule — which is **in Inc-7's declared file set**, so the 4-file budget holds |

`AT-B78-11`'s threshold is `1 <= height <= 7`, both bounds normative: `== 7` false-fails a conforming
*reduction*, and a bare `<= 7` passes a **collapsed** bar. Asserted in the same run as `AT-B78-08`.

## 4 · What Inc-7 still owes

- `LLR-120.1` one entry point drives both surfaces · `120.2` the Loaded-panel project row · `120.3` the
  row budget · `120.4` `safe_text` on both new sinks · `120.5` both display forms on both surfaces.
- `AT-B78-08`, `-09`, `-10`, `-11`, `-30` · `TC-B78-09…13`, `-42`, `-43`.
- ⚠️ **`tests/test_tui_app.py` goes BLIND, not RED** — it monkeypatches `update_project_labels` at three
  sites, so its green is **not evidence** at this gate (P-38b).
- ⚠️ `TC-B78-12`'s payload **must carry control characters**. The previous payload `[red]evil[/].a2l`
  contains **zero**, so it certifies the markup axis and is blind to the control axis. `U+009B` and
  `U+009D` are single-byte C1 introducers carrying no `\x1b`, and are **legal Windows filename
  characters**. The control class is re-derived in the test, never imported from `_CONTROL_SCRUB`.

## 5 · Carried from Inc-6, still open

- The three painted-Footer-children arms (**8** @80×24 · **13** @120×30 · **15** @160×40).
- Stale citation, non-blocking: `action_show_help_panel` is `app.py:5877`, cited `:5836`.
