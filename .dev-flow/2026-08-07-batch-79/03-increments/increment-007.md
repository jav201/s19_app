# Inc-7 — `HLR-120` context on both surfaces (`LLR-120.1` … `120.5`)

**Batch:** `2026-08-07-batch-79` · **Files:** 4 (declared: 4) · **Nodes:** 10 (11 ATs/TCs, `AT-B78-08`
and `AT-B78-11` share one node by design)

---

## 1 · BLUF

**Lane 1 opens. Both context surfaces exist, fed by one composer — and three of the spec's own
acceptance claims turned out to be false against shipped behaviour.** Two were corrected by re-authoring
the node; one was made true, because it was an acceptance criterion of the requirement being built.

## 2 · Files modified

| File | Change |
|---|---|
| `s19_app/tui/app.py` | `_compose_project_label()` extracted · `#status_line` Horizontal · the `#status_context` write · pre-mount guard · `_refresh_loaded_panel(project)` |
| `s19_app/tui/screens_directionb.py` | `render_slots(loaded, project)` · `_build_project_row` · `_PROJECT_ABSENT` |
| `s19_app/tui/styles.tcss` | `#status_line` · `#status_context` |
| `tests/test_tui_commandbar.py` | 10 nodes + 5 helpers + the re-derived control class |

## 3 · The three false acceptance claims

| # | Claim | Executed result | Disposition |
|---|---|---|---|
| 1 | `LLR-120.1`: the new writes **replace** the command-bar write | Deleting it reddens **10 shipped tests** (`test_tui_variants`, `test_tui_patch_variant`) — `_project_label()` reads `#cmdbar_project`. §7's Inc-8 row says the sites are re-pointed *"while both surfaces exist"*, which the deletion makes false | **Kept the bar write.** "Replacing" is discharged across Inc-7 + Inc-10, where `HLR-118` deletes the bar anyway |
| 2 | `TC-B78-13`: `update_project_labels` before mount → **no raise** | **False on the base tree too.** At `829adc6` it raises `ScreenStackError: No screens on stack`. The catalog named a tolerance the code never had | **Made true** — it is an acceptance criterion of this very requirement. The guard wraps **all three** sinks; guarding only the new one would have moved the raise one line down |
| 3 | `TC-B78-43`: unload-all → **both surfaces return to `(none)`** | **False of both halves.** `_apply_unload("all")` clears `current_file` and touches neither `current_project` nor `current_a2l_path`; measured, the context is unchanged at `'demoproj  \|  ctx.a2l'` | **Node re-authored** to the contract that exists: the artifact slots empty, the context persists. Making the spec's version true would change what unload-all *means*, which is nowhere in `HLR-120` |

Claims 1 and 3 would each have **false-failed a correct implementation**. Owed upstream as §6.5
Before/After amendments.

## 4 · Test results

| Gate | Result |
|---|---|
| `tests/test_tui_commandbar.py` | **24 passed** (was 14) |
| `test_tui_variants` + `test_tui_patch_variant` + `test_tui_commandbar` | **46 passed** |
| C-27 frozen dual guard | `test_engine_unchanged` **1 passed** · `tc032` **3 passed** |
| `ruff` | clean apart from a **pre-existing** `F821 Undefined name Dict` (present at HEAD) |
| Status-bar height, 10 screens | **`[7]`** — baseline `[7]`, `LLR-120.3` holds |

**Ledger:** 2657 → **2667**, **+10**, exactly the ten nodes.

### Counterfactuals (C-40) — executed, applied-checked, restored by hash

| Mutation | Nodes that reddened |
|---|---|
| **A —** `safe_text` bypassed on the status-bar sink | `TC-B78-12`, naming the leaked codepoints: **`0x1b`, `0x7f`, `0x9b`, `0x9d`** — including the two single-byte C1 introducers that carry no `ESC` and are legal Windows filename characters |
| **B —** the suffixed display form flattened to the plain name | `AT-B78-30`, `AT-B78-10`, `TC-B78-42` — all three form-sensitive nodes |

Both restored; `app.py` `sha256` back to `c88080fb…f6e04`, verified by hash rather than by `git status`.

### Two vacuities caught in my own nodes

1. **`TC-B78-43`'s fixture could not discriminate an unload from a no-op.** With only a project loaded,
   the A2L half read `(none)` before *and* after. Its own *"something must have moved"* clause caught it;
   the fixture, not the assertion, was the weak part. An A2L is now loaded so there is something to clear.
2. **`TC-B78-12` needed its presence co-assertion first.** An absence clause over an empty strip is
   vacuously true, so the node proves the hostile name reached the surface before asserting what is
   missing from it.

## 5 · Risks / notes

- ⚠️ **Measured platform bound:** `TC-B78-12`'s full payload is **not creatable as a Windows filename**
  (`\x1b`, `\x7f` are illegal path characters), so the state is set on the app attribute and the shipped
  `update_project_labels` driven. The sink is LLR-120.4's subject; the loader is not. The subset
  reachable through a real file here — `\x9b`, `\x9d`, markup brackets — is exactly what the spec's own
  rationale calls out.
- ⚠️ `tests/test_tui_app.py`'s green is **not evidence** for this increment (P-38b): it monkeypatches
  `update_project_labels` at three sites, so it goes **blind, not red**.
- **Registered, not taken:** the stylesheet's palette is a closed six-token set with no muted foreground;
  `#status_context` uses `$fg-base` and separates by position and alignment.

## 6 · Pending / reported as found

- **8 `.pyc` files are TRACKED in git** despite `.gitignore` listing `__pycache__/` and `*.pyc` — they
  predate the ignore rule, and `.gitignore` does not untrack. They are Python **3.9 / 3.10** bytecode in
  a project now running **3.14**. Restored rather than committed; **removal needs operator approval** and
  is outside this increment.
- The three painted-Footer-children arms, carried from Inc-6.
- Two §6.5 amendments owed upstream (claims 1 and 3 above).

## 7 · Suggested next task

**Inc-8 — `LLR-121.4`:** re-point the 14 `_project_label()` call sites off `#cmdbar_project` and onto the
new surfaces, **while all three surfaces are live**. 3 test files, no production change. Gate:
`grep -rn 'cmdbar_project' tests/` → **0** (currently **10**).
