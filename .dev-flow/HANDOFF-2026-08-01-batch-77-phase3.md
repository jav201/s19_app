# HANDOFF — batch-77, Phase 3 (implementation)

**Written:** 2026-08-01 · **From:** the session that ran Phases 0–2
**To:** a fresh `/dev-flow` session with a full context window
**Repo:** `C:\Users\jjgh8\Github\s19_app` — **NOT** the OneDrive path (the repo moved out of OneDrive)
**Branch:** `claude/batch-77-memmap-variant-a`, cut off `origin/main` @ `f8747b8`
**Run python as:** `PYTHONPATH=/c/Users/jjgh8/Github/s19_app python …` (`sys.path[0]` is the script dir otherwise)

---

## BLUF

**Phases 0–2 are COMPLETE and APPROVED. Zero lines of production code are written. Phase 3 has NOT started.**

Read `.dev-flow/2026-08-01-batch-77/01-requirements.md` (819 lines) — it is the plan, and it is **revision 5**. Do not re-author it. `PLAN.md` §1–§9 is the living record; `state.json` is canonical.

⚠️ **THERE IS NO Inc-0.** An earlier indicative roadmap in `PLAN.md` §4 had one; **revision 5's §7 supersedes it** and runs **Inc-1 … Inc-9**. The golden capture moved to **Inc-3**, deliberately: *"a golden captured before the basis settles pins the retired arithmetic — precisely how `[45,15]` got into revision 1."* **Capturing a golden before Inc-1 lands is a known defect, not a head start.**

---

## 1 · First actions, in order

1. **ASK THE OPERATOR FOR THE AUTHORIZATION MODEL.** It is per-batch and **never inherited** — not from this document, not from `state.json`. The previous session held *autonomous + merge authorized*; **that grant does not transfer.**
2. **RC-1 base currency:** `git fetch origin`; assert the branch's merge-base equals the `origin/main` tip. Rebase if not.
3. **Flow currency (C-45):** re-run the aggregate hash from `~/.claude/docs/FLOW-VERSION.md`. Expect a **scoped, non-blocking** mismatch — 11/11 control-bearing files byte-exact, only `dev-flow-lessons/SKILL.md` diverges (local **ahead**). Re-execute it; do not inherit this verdict.
4. **Toolchain:** Python 3.14.4 · pytest 8.4.2 · ruff 0.15.17 (verified 2026-08-01).
5. **Read `§6.4a`** of the requirements — the propagation sweep. It is a **standing obligation**, not a one-off: re-run it for any domain/scope/withdrawal/wording change you make.

---

## 2 · What this batch is, after eleven operator rulings

The charter (`prototypes/memmap_variant_a.HANDOFF.md`) diagnosed a **symptom**: sparse images render as ~59 columns of gap hatch, so it prescribed gap-folding. Execution found two deeper causes:

1. **`_BAND_BAR_WIDTH = 60` was never reconciled with its container.** `.map-band-bar` measures **66 cols @80×24** but only **21 @120×30** — so segments painted outside it and **2 of 5 regions were invisible at the wide regime**. R-1 reconciles the basis; R-7 widens the bar (21→50) via CSS.
2. **The allocation had no bound at all.** Widening alone still left 5 runs invisible on `prg.s19`. `LLR-111.7` (floor-1 + largest-remainder) is what makes it fit.

**Gap-folding is now the smallest part of the fix.**

### The eleven rulings (all in `state.json.phase1_operator_rulings`)

| # | Ruling |
|---|---|
| R-1 | Bar width **reconciles to the real container**, not the constant |
| R-2 | Dense golden **re-bases** after the width fix; unequal-run fixture (equal runs are vacuous) |
| R-3 | Keyboard = **↑↓ + Enter only**; `j`/`k`/`o` dropped (all bound; `o`/`j` frozen under live `TC-011`) |
| R-4 | Ruler labels the **last mapped byte**, not the exclusive `span_end` |
| R-5 | Fold marker is **1 column, always** |
| R-6 | Re-render **preserves** selection, else falls back to first |
| R-7 | **Widen the bar, then aggregate** — widen kept, aggregate split out by R-10 |
| R-8 | Accept the deepened stats-line scroll (carry **C-77-k**) |
| R-9 | `+N more` renders in the region list — **superseded by R-10**, carried to batch-78 |
| R-10 | **Aggregation split out to batch-78** |
| R-11 | **ANSI scrub pulled INTO batch-77** |

### Two chartered features descoped, both **registered not dropped**
- **C-77-f** — `o` = open-hex *keyboard* affordance (mouse double-click still reaches hex)
- **C-77-g** — 2-column fold marker + humanized size label

---

## 3 · Increment plan — §7 of the requirements is authoritative

`Inc-1 … Inc-9`. Four ordering constraints, **all forced by execution**:

1. **Inc-1 is INDIVISIBLE.** Container basis alone leaves both its ATs RED **and regresses 80×24** from `outside=0` to `outside=2` (gap widths `[8,8,16,33]` = 65 of 66 columns). Basis + bound + fold land together or the increment cannot pass its own gate.
2. **Inc-2's gate must DRIVE the sink, not wait for it.** Before Inc-7 there is no auto-select, so `#map_detail_body` shows `_DETAIL_HINT` — no file-derived text. Use a **real `pilot.click`** on a region row.
3. **Inc-3 after Inc-1** (golden pins retired arithmetic otherwise).
4. **Inc-7 → Inc-8** (`row.focus()` is a no-op until `can_focus` is True).

**Two open questions are yours to decide in Phase 3:** `OQ-3` (delete `_BAND_BAR_WIDTH` outright, or retain as a pre-layout fallback — Inc-1) and `OQ-4` (focus-entry mechanism: screen-scoped binding, auto-focus, or extending the ⚠️ *shared* rail tab chain — Inc-7).

---

## 4 · Five traps that will bite you, all measured

1. **`AT-072b` will go RED on CORRECT code if Inc-4 uses `prg.s19`.** It carries an in-domain "no elided tick" clause, and **`prg.s19` is OUTSIDE `HLR-112`'s domain at both regimes** (15 ticks vs a ceiling of 7 @80×24 / 5 @120×30). `case_02` qualifies. The fixture is pinned in the AT and in Inc-4's cell — **do not swap it.**
2. **`LLR-116.7` mandates a byte-CLASS filter, not a pattern.** `U+009B` (single-byte CSI) and `U+009D` (single-byte OSC) carry **no `\x1b`** and pass any `\x1b[…`-shaped regex. Substituting a regex reopens the hole **with every test still green**. The C1 codepoints are named normatively — keep them.
3. **Map geometry is NOT settled after one `pilot.pause()`.** 17/97 traces show a transient first read (e.g. 23 where the settled value is 21), and **never twice in succession**. `LLR-111.6` counts **pauses**. Without it every geometry acceptance flakes.
4. **`safe_text` is a no-op on ESC today, and its docstring says otherwise.** That false claim in shipped source became revision 1's premise. Inc-2 fixes it.
5. **Textual layer traps:** `#map_stats`/`#map_detail` are **containers** rendering `Blank` — the text is in `#map_stats_body`/`#map_detail_body`. `RegionRow.render().spans == []`, so the selection fact lives in `widget.styles`. Geometry is at `widget.region`; colour is **not**.

---

## 5 · Baseline

- **Collection:** `2519` tests on `f8747b8` (reconciles with batch-76's close: `2508 − 0 + 11 = 2519`).
- **Full suite:** launched at handoff; read its own output (C-19 — one complete run, never spliced).
- **`tui-ci` runs `-m "not slow"` on PRs and the FULL suite on pushes** (21 slow tests). **State which form produced any ledger figure, and run the full form before merge.**
- **Engine-frozen set is OFF-LIMITS**, both halves (source **and** `_ENGINE_TEST_FILES`) — C-27 dual guard.
- **Snapshot regen: canonical CI only** (textual 8.2.8 pin); local regen corrupts unrelated baselines. Inc-9.

---

## 6 · Figures that were WRONG and are now derived — do not re-inherit the old ones

| Claim | Wrong value | Derived value |
|---|---|---|
| Shipped fixture corpus | "16 of 17" *(4 revisions + reported to the operator)* | **15 of 16** — `find examples -name '*.s19' \| wc -l` = **16** |
| `case_08` unseen, batch-77 | 99.5 % / 99.9 % *(pristine producer, gaps unfolded)* | **768/801 = 95.9 % @80×24** and **776/801 = 96.9 % @120×30** — **quote BOTH or neither** |
| `LLR-111.4` golden | `[45,15]` then `[50,16]` (plain rounding) | **`[49,17]` @66 · `[37,13]` @50** (the mandated allocator) |
| `LLR-072.3` | "does not exist" | **Exists** — batch-47 `01-requirements.md:508`, cited at 4 shipped-source sites |

**Every one had the same provenance: inherited rather than derived.** That is this batch's defect signature.

---

## 7 · The batch's own lesson, stated once

**Three times a design was validated against the fixture its author chose and failed on one that ships in the repo** — the charter on `prg.s19`, revision 2's aggregation on `case_08`, and `HLR-112`'s domain (never measured until the final gate, which is how `prg.s19` fell out of it unnoticed).

**Four times a check's INPUT SET was hand-listed rather than derived** — including §6.4a itself, the control built to fix this. It is now derived and returns **42/42**, having caught three genuine residues.

**Not one defect was found in shipped product code across nine review passes.** Every one was in analysis, specification, or acceptance design.

---

## 8 · Working-file reconciliation (C-44)

| File | State |
|---|---|
| `.dev-flow/2026-08-01-batch-77/**` (11 artifacts) | ✅ committed through `d125ca1` |
| `.dev-flow/state.json`, `BACKLOG-CODE.md` | ✅ committed |
| `prototypes/memmap_variant_a.*` + `memmap_redesign.proposals.html` | ✅ committed (`065bb95`) per charter §1 |
| `prototypes/out/` | 📋 **untracked, PRE-DATES this session** — reported as found, never swept |
| Branch `claude/batch-77-memmap-variant-a` | ✅ **PUSHED** to `origin` (16 commits, 0 unpushed). **No PR opened yet** — the resuming session owns that. |
| Scratchpad probes | 🗑️ outside the repo tree; all output transcribed into the artifacts |

**Lane B owes one item** (`BACKLOG-PROCESS.md`, not yet written): **C-33's prescribed liveness discharge is obsolete.** `TaskOutput` is deprecated for agent tasks and its own docs forbid the C-33 usage; transcript files stay 0 bytes with frozen mtime (verified by sampling). There is currently **no in-band progress signal** for a subagent — only a wall-clock bound.

---

## 9 · Do not redo

Requirements (revision 5 is final and gate-approved) · the 11 rulings · the three lanes' review artifacts · the premise tables. **Verify the tree before extending, and never regenerate work recorded as done — briefings under-credit.**
