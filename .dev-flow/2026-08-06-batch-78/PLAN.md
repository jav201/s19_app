# batch-78 — PLAN (living compendium)

> Updated at every gate and significant checkpoint. `state.json` is the machine record; this file
> is the human-readable mirror. **Phase 0 · awaiting gate.**

## 0 · Where we are

| | |
|---|---|
| **Batch** | `2026-08-06-batch-78` |
| **Phase** | **1 — requirements engineering · IN PROGRESS** (Phase 0 approved 2026-08-06 under the kickoff grant; no exit-criteria axis was unmet) |
| **Branch** | `claude/batch-78-cmdbar-a2bdiff` @ `f6ff1d3` |
| **RC-1** | ✅ PASS — merge-base == `origin/main` tip `f6ff1d3`; charter's base `061a97e` is an ancestor, 1 intervening commit, `state.json` only, **no source drift** |
| **Flow revision** | `2026.07.28-rev1` · controls C-1…C-45 · **11/11 command+template files byte-exact**; aggregate mismatch is the `dev-flow-lessons` catalog only, where local is AHEAD → **NON-BLOCKING** (D-5) |
| **Toolchain** | Python 3.14.4 · pytest 8.4.2 · ruff 0.15.17 ✅ |
| **Language** | English artifacts, Spanish conversation (project convention, `state.json.language = "en"`) |
| **Charter INPUT** | `prototypes/cmdbar_a2bdiff.HANDOFF.md` (operator-approved 2026-08-06) — **input, not spec** |
| **Measurements** | [`00-measurements.md`](00-measurements.md) — 20 premises: 16 TRUE · 1 FALSE · 3 INCOMPLETE |
| **Ids minted** | **NONE.** Phase 0 mints no ids |

## 1 · Objective

Delete the Direction-B command bar row and re-home what it carried; rebuild the A2B diff panel as
a keyboard- and mouse-navigable master–detail so every run and every byte is reachable. Lane 3
(operations staged removal, S-10…S-13) is **out of this batch** and is chartered as a handoff at
close, per the operator's kickoff ruling.

## 2 · Kickoff authorization (asked fresh 2026-08-06 — never inherited)

| | Operator's answer |
|---|---|
| **Autonomy + merge** | **"Autónomo + merge autorizado"** — self-approve gates and merge. **Precondition:** after the PR is open and CI green, a **final independent `qa-reviewer` pass over the whole diff vs `main`** (dual traceability intact · 0 engine-frozen diffs · no cross-increment regression · every gate carry discharged). **A HIGH finding blocks the merge and returns to the operator.** |
| **Decision recording** | **"Sí, registra en los 4 lugares"** — PLAN.md §8 · `state.json.decisions_log` · `05-postmortem.md` · vault at `/dev-flow-sync`. Autonomy is never silent. |
| **Scope** | **"Lane 1 + Lane 2 as recommended but at the end prepare a plan for other session to kick off what was left out."** → S-1…S-9 here; **a Lane-3 handoff charter is a required deliverable of this batch's close.** |
| **Numbering** | **"Este charter = batch-78, agregación se renumera"** → the `C-77-l` aggregation carry moves to batch-79 in `BACKLOG-CODE.md`, edited in Phase 0. |

*The accepted autonomy option names the independent `qa-reviewer` merge pass explicitly, so
subagent use is authorized by the answer itself (overrides the session default of not calling the
Agent tool).*

## 3 · Story intake — INVEST + Definition of Ready

**7 READY · 2 READY-WITH-DECISION · 0 REFINE · 0 SPIKE · 0 OUT.** No story is satisfied on
`origin/main` (§6 of the measurements).

| # | Story | I | N | V | E | S | T | Class |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| S-1 | Delete the bar row (`#command_bar_row`); Ctrl+K keeps working everywhere | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | **READY** |
| S-2 | Re-home `/`·`g` to the active screen's local inputs; notice where none; `Esc` returns focus | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | **READY** |
| S-3 | Re-home the Project/A2L context labels | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | **READY** ⚠️ scope consequence, §4 |
| S-4 | Delete the dead surface (CSS, messages, adapters, `focus_*`) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | **READY** — depends on S-1…S-3 |
| S-5 | `#diff_range_list` `Static` → selectable list, every run reachable | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **READY** |
| S-6 | Windows follow selection; context rows derived from pane height | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | **READY** — depends on S-5 |
| S-7 | Width regimes: ≥~130 full, **120-col fallback required** | ❌ | ✅ | ✅ | ⚠️ | ✅ | ✅ | **READY-WITH-DECISION** — Phase 1 picks one of three measured options |
| S-8 | Compact the A/B selection + action rows to one line each | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **READY** |
| S-9 | Discoverability: Footer + `?` keymap; Enter posts open-in-hex | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | **READY-WITH-DECISION** — charter marks it optional and **forbids silent absorption** |

**Independence (implementation ordering, not readiness):** S-4 must land after S-1…S-3; S-6 after
S-5. Lane 1 and Lane 2 touch disjoint source (`command_bar.py`/`app.py`/`styles.tcss` vs
`screens_directionb.py`/`styles.tcss`) but **share `tests/test_tui_directionb.py`** — increments
must not collide there.

**Testability (the black-box outcome each story owes, stated at behaviour level):** every one is
observable through the shipped surface and, per §4, several are demonstrably RED today. Acceptance
ids are minted at Phase 1, not here.

## 4 · What Phase 0 found that the charter does not say

Four items, each of which changes the work rather than merely annotating it.

| Finding | Consequence |
|---|---|
| ❌ **P-10 FALSE — nothing unmounts.** `action_show_screen` swaps a `hidden` class; all eight find/goto inputs resolve on every screen | S-2 **cannot** route by asking which inputs exist. It must key on `_active_screen_key` (`app.py:5817`). A presence-based implementation would be green on a wrong design |
| 🆕 **The bar acts on the wrong pane.** Executed: with A2L active, `CommandBar.Find` writes into the *workspace* `#search_input` and leaves `alt_search_input` empty | Lane 1 is not cosmetic: **S-2 fixes a latent wrong-pane defect on 9 of 10 screens**, and that yields an acceptance that is genuinely RED today |
| ⚠️ **P-12 — the "no local find/goto" notice is the MAJORITY path.** 10 screens exist; 3 own find/goto | The notice is a first-class arm of S-2's acceptance, not an edge case |
| ⚠️ **P-11 — `Esc` does not return focus today.** Executed: `/` → `find_input`, `escape` → still `find_input` | S-2's `Esc` clause is **net-new work**, not a preserved behaviour. It must not be written as a control |
| ⚠️ **P-13 — S-3 reduces availability.** `#loaded_panel` is composed inside `#screen_workspace` only | The labels go from visible on **10** screens to **1**. Surfaced for the operator rather than absorbed — see the gate question |
| 💣 **29 of 29 snapshot goldens drift.** The bar is app-level chrome in every full-screen capture | Largest mechanical cost in the batch; **CI-only regen** (textual 8.2.8 pin) |
| ✅ **P-20 — the frozen keymap guard does not pin `/` or `g`** | Re-homing them cannot trip `_PRE_BATCH_BINDINGS`. Verified, not assumed |
| ⏳ **P-19 UNVERIFIED — the width ceiling is a hypothesis** | The 81-cell row / ≥130 / 120-wrap figures come from the design prototype and are **re-derived at Phase 1** before they may bound S-7's acceptance (C-39: *a carried number is re-derived, not copied*) |

## 5 · Roadmap (indicative — the increment cut is owned by Phase 1, not by this section)

Phase 1 requirements → Phase 2 tri-lane review → Phase 3 increments (≤5 files each) → Phase 4
validation → Phase 5 post-mortem → Phase 6 docs + PR + merge gate + Lane-3 handoff charter.

Expected footprint: `command_bar.py`, `app.py`, `styles.tcss`, `screens_directionb.py`,
`tests/test_tui_commandbar.py`, `tests/test_tui_directionb.py`, `tests/test_tui_diff_screen.py`,
`tests/test_loadfilescreen_input.py`, 29 snapshot SVGs, `AT-TC-REGISTRY.jsonl`.

## 6 · Invariants this batch must not break (charter §3, to be re-verified per increment)

C-17 markup safety via `safe_text`; hex windows `markup=False` · the diff panel stays
presentational (runs from `compare_service`/`diff_mem_maps` only) · display caps bound the **panel,
never the report** (G-9) · snapshot regen **CI-only** · no `_nodes`/`_context` members on new
widgets · `styles.tcss` id selectors beat subclass `DEFAULT_CSS` · new ATs/TCs pass the G1–G7
registry guard · **`x` is not rebound** (it does not even become free this batch — S-13 is out of
scope).

## 7 · Risks / watch-items

| # | Risk | Handling |
|---|---|---|
| R-1 | 29-golden drift makes any local test run diverge from CI | Regen in canonical CI only; state which suite form produced any ledger figure |
| R-2 | Both lanes edit `tests/test_tui_directionb.py` | Sequence increments; C-26 reverse-grep before each lands |
| R-3 | P-19's width figures are unverified and S-7 rests on them | Re-derive at Phase 1 with an executed transcript before they bound an acceptance |
| R-4 | S-3 silently reduces label availability 10 → 1 screen | Escalated at the Phase-0 gate (§9) |
| R-5 | Keyboard ATs that blur with `escape` are unsound | Any focus AT must `set_focus(None)` and **assert** the blur, per §7 of the measurements |
| R-6 | The palette must keep working on all 10 screens after the row goes | S-1's acceptance drives Ctrl+K on every screen, with the command set asserted unchanged |

## 8 · Decision log

| # | Phase | Decision | Basis |
|---|---|---|---|
| D-1 | 0 | Autonomous + merge authorized, with the independent `qa-reviewer` merge pass as precondition | Operator, kickoff |
| D-2 | 0 | Record every autonomous decision in all four places | Operator, kickoff |
| D-3 | 0 | Scope = Lane 1 + Lane 2 (S-1…S-9); **a Lane-3 handoff charter is a deliverable of this close** | Operator, kickoff |
| D-4 | 0 | This charter is **batch-78**; the `C-77-l` aggregation carry renumbers to **batch-79** | Operator, kickoff |
| D-5 | 0 | Flow-currency mismatch ruled NON-BLOCKING | Taken autonomously — re-executed per-file: 11/11 enforceable files byte-exact; the sole divergence is the catalog, where local is ahead |
| D-6 | 0 | Use subagents as the flow specifies (`code-reviewer` per increment gate, `qa-reviewer` at Phase 4 and the merge gate), with C-33 liveness polling | Taken autonomously — the accepted kickoff option names the qa-reviewer merge pass, so it is authorized by the answer itself |
| D-7 | 0 | **Batch-scoped ids** `AT-B78-nn` / `TC-B78-nn` — no reservation PR needed | `docs/engineering-rules.md:48` prefers batch-scoped; the registry's `_meta.governed` puts letter-initial bodies outside its authority by spec §2.3, so they cannot collide by construction. Global `next_free` re-derived from the registry as **AT-282 / TC-613** (1 373 rows) and left untouched |
| D-8 | 0 | Probe defect recorded, not hidden: revision 1 of the focus probe blurred with `escape` and produced a false `g → find_input` reading on every screen | Same class as batch-77's four self-caught lane probes; the corrected probe asserts the blur |
| **D-9** | 0 | **S-3 destination = BOTH the Loaded panel AND `#workspace_status_bar` (option C)** | **Operator ruling**, overriding my autonomous recommendation of B (status bar only). Measured basis: `LoadedArtifactsPanel` **already** renders the A2L filename, and `#workspace_status_bar` is app-level chrome on all 10 screens at zero new rows. **Consequence Phase 1 owns: two update paths ⇒ two discriminating acceptances**, since one AT observing one surface is green on an implementation that updates only that one |
| **D-10** | 0 | **A parallel session is active in this repo; its files are reported as found and left untouched (C-44)** | Eight `prototypes/memmap2.*` files appeared at mtime **10:18** — the same minute as my own `00-measurements.md` — and were absent from my Phase-0 `git status`. They were written **during** this session, by another. **Operator confirmed** they are a memory-map prototype set belonging elsewhere. Standing hazard: `state.json` is last-writer-wins with no owner field — re-read before every edit |
| **D-11** | 1 | **P-19 re-derived before any agent was dispatched** | Taken autonomously (C-39). Handing a hypothesis to a sub-agent as a measurement is how a false figure propagates into a spec. **81-cell hex row: EXACT.** Rail is **22, not 24** (4 at 80×24, a regime the charter omits). The shipped 3-column diff **wraps at every realistic width**, not "below ~170" — it would need a ~282-column terminal. Derived and absent from the charter: each bordered box costs **+5** cells. **Reframes S-7: the regime split is about whether the list shares the row with the window, not about the window** |

## 9 · Pending at this gate — one question for the operator

**S-3's home reduces availability from 10 screens to 1** (P-13, measured). The charter says *"re-home
to the Loaded panel"*; `#loaded_panel` is composed inside `#screen_workspace`, so on the other nine
screens the operator would no longer see which project / A2L is loaded. Options are laid out at the
gate; this is a scope decision the charter's own *"do not silently absorb"* rule says I must not
take alone.
