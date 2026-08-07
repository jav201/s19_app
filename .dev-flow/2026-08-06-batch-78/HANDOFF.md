# batch-78 — HANDOFF at the Lane-2 / Lane-1 boundary

**Date:** 2026-08-06 · **Cut by:** operator ruling (token cost) · **Branch:** `claude/batch-78-cmdbar-a2bdiff`
**Status:** Lane 2 complete and gated. Lane 1 not started. **Two follow-on batches chartered below.**

---

## 0 · BLUF — what a resuming session needs in one paragraph

Six increments shipped **Lane 2 in full**: the A2B diff panel now has a selectable run list, hex
windows that follow the selection, report completeness observed through the written file, and three
width/height regimes with an explicit insufficient-terminal notice. **The charter's original defect is
closed** — `_render_run_windows` was only ever called with the literal `0`, so runs 1..N were
unreachable; they are reachable now, by keyboard and by mouse. **Lane 1 (deleting the command bar) has
not been started at all** and is chartered as **batch-79** below. **Lane 3 (operations) was out of
scope from kickoff** and is chartered as **batch-80**.

**Two defects reached shipped product code across six increments; both were found and fixed inside
their own increment's gate.** Every other finding — roughly thirty — was in an acceptance, a metric, a
driver, a citation, or the requirements document.

---

## 1 · Where the work actually stands

| Inc | Content | Gate | Commits |
|---|---|---|---|
| 0 | Pre-change artifact capture | ✅ PASS · 0H/1M/2L | `6823352` `8b77ea9` `b3b97f7` |
| 1 | `HLR-125` compact the control rows | ✅ PASS · 0H/2M/3L | `c09c699` `d771ab8` |
| 2 | `HLR-122` selectable run list | ✅ PASS at round 3 · **2 HIGH** | `297990c` `f9b9629` `c59e794` `438fda3` `7d034db` |
| 3 | `AT-B78-31` report completeness | ✅ PASS · 0H/2M/4L | `c88b0ad` `24d812f` |
| 4 | `HLR-123` windows follow selection | ✅ PASS after 1 HIGH | `8e728a3` `7c587a9` `4425080` |
| **5** | `HLR-124` three regimes + notice |  ✅ PASS after 1 HIGH | `3789a92` `9015b7f` `70e2361` `e24faae` |
| 6–12 | Lane 1 + discoverability + snapshot regen | ❌ **NOT STARTED** | — |

**Ledger:** baseline `2607 / 2 / 3` → Inc-5 `2647`. Honestly one fewer passing plus the single drifted
`[diff-comfortable-120x30]` snapshot cell, which **Inc-12 owns and regenerates in canonical CI only**
(textual==8.2.8 pin; local regen drifts unrelated baselines).

---

## 2 · ✅ Inc-5's HIGH — CLOSED before the cut

> ✅ **CLOSED before the cut — `70e2361` (fix) and `e24faae` (spec fold). Nothing is owed here.**
> This section is kept because the defect is instructive and **one consequence binds Inc-10**:
> **`AT-B78-26`'s *"≥ 1 hex row at 120×30"* must inherit the `>= 2` painted form.** Read as painted
> content height it is the identical defect, sitting in the increment that closes the batch's headline
> case. `_DIFF_MIN_H` is **28**; `TC-B78-54` asserts both sides of the floor.

**F-1 (HIGH) — the height floor declares two terminal sizes deliverable that paint zero hex rows.**
`_render_run_windows` writes `f"Image A — {header}\n{text_a}"`, so **line 0 of each window is the
header**, and `_DIFF_MIN_H` was defined as *"paints a content row"* — a row that buys **zero bytes**.

| H | Regime | hex rows |
|---|---|---|
| 25 | notice | 0 — **and the operator is told why** |
| **26** | fallback | **0** |
| **27** | fallback | **0** |
| 28 | fallback | 1 |
| 30 | fallback | 2 ✓ |

At 26–27 the panel declares the terminal usable, **hides the notice**, and shows a header and nothing
else — **strictly worse than 25**. A regime worse than the one below it is not a degradation ladder.

**Root cause: a spec conflict resolved silently.** `D-1` says *"at least one visible content row"* → 26.
**Normative `LLR-125.2`** says *"at least one **hex row** of content"* → **28**. `LLR-125.2` governs;
**the floor is 28.**

**It blocks rather than carries because Inc-10's file set excludes `screens_directionb.py`** — no later
increment can move the constant.

**The durable fix is not the constant.** `F-1`, `F-3` (`AT-B78-23`'s `hex_a_painted >= 1` counts the
header, so it is green at zero bytes) and **the entirely absent height-floor node** are **one defect at
three layers**. `TC-B78-31` does the width floor **on both sides** and asserts the consequence; nothing
does that for the axis Inc-5 changed. **Mint a node asserting both sides:** at `H = _DIFF_MIN_H − 1` the
notice is present; at `H = _DIFF_MIN_H` it is absent **and at least one hex row is painted**.

**F-2 (MEDIUM) — a capability inversion.** `check_action` gates `[`/`]` on the fallback regime. Measured:
at **160×40 and 139×40 capacity is 1**, a 66-row run emits 66, paging is **disabled** — **65 of 66 rows
unreachable on the widest supported terminal**, while 132×44 reaches all. The fix **removes** a condition.

**✅ FOLDED:** `01-requirements.md` §5.6.1, §3 **and §2.8's D-1** now all read **28**, and D-1's metric was corrected from "content row" to "HEX row" — leaving it would have kept the contradiction alive. They previously
recorded **26**. That file is the orchestrator's; the increment agents are
forbidden to touch it.

---

## 3 · The state of the requirements document

`01-requirements.md` is at **revision 4 + four in-flight amendments**, and it is the authority — §7's
increment table more so than any brief.

**Amendments already folded:** **A/B/C** (Phase 1) · **D** — `HLR-123`'s two exactness clauses had an
**empty intersection at the size §7 names for its own gate**, so `AT-B78-22` would have false-failed a
correct implementation at 132×44. Split into an exact arm at content height 0 and a containment arm at
132×44, the containment arm **declared inert under M2** and not counted as a discharge.

**Corrections folded at Inc-5:** `_DIFF_MIN_H` **29 → 26 → 28** (the 26 was itself wrong — see §2; D-1's metric corrected too, since it was the weaker of the two clauses that produced
it) · **`A-2`'s premise is FALSE** — see §4.

**`enum.py` is a gating control, not a report.** `.dev-flow/2026-08-06-batch-78/enum.py` scans all ~1030
lines of the requirements document for 20 tracked terms and 15 stale forms, and **exits non-zero** on any
undispositioned hit. **Run it before every commit that touches the spec, and read its exit code
directly — never through a pipe.** It caught two live defects the human review had missed, and the
orchestrator once committed over a FAILING gate because `enum.py | tail && git commit` takes the
*pipeline's* status (`C-78-xx`).

---

## 4 · Findings that reach into the UNBUILT increments — do not rediscover these

| Finding | Reaches | What it means |
|---|---|---|
| ❌ **The command palette has NO `escape`-to-close** | **Inc-9** | `command_bar.py` declares **no `BINDINGS`** and handles no `escape`; executed, `ctrl+k` then `escape` leaves `palette_is_open` **True**. `LLR-119.3` / `AT-B78-07` asserted a constraint *"must not shadow the palette's escape"* — **there was nothing to shadow**, and both Phase-2 lanes accepted it because it sounded like a property the widget would obviously have. **Inc-9 must choose a disposition in writing rather than inherit one.** |
| ⚠️ **`C-78-vi` — §5.1 rule 1's painted-height metric is wrong** | **BLOCKS Inc-10** | It measures the **border box** and does not clip through intermediate ancestors. `AT-B78-26`'s 120×30 "≥1 hex row" clause would pass with **three rows of border and zero hex**. Use Inc-1's corrected helper: `content_region` intersected through the **full ancestor chain**. |
| 💣 **29 of 29 snapshot goldens drift on the bar deletion** | **Inc-10, Inc-12** | The command bar is app-level chrome in every full-screen capture. **Regen is CI-only.** This is the single largest mechanical cost in Lane 1 and the reason Lane 2 went first. |
| ✅ **`_PRE_BATCH_BINDINGS` does not pin `/` or `g`** | Inc-9 | 14 frozen tuples, neither key among them — re-homing cannot trip the guard. Verified, not assumed. |
| ⚠️ **Lane-1 blast radius is 6 test files, not 3** | Inc-7, Inc-8 | `#cmdbar_project` is the observable for `_project_label()` (**14** call sites), which guards the LLR-005.5 multi-variant display form — **so S-3 owes the display FORM, not just the name.** `tests/test_tui_app.py` goes **blind, not red**: it monkeypatches `update_project_labels`, so **its green is not evidence**. |
| ⚠️ **The bar acts on the WRONG PANE today** | Inc-9 | With A2L active, `CommandBar.Find` writes into the **workspace** `#search_input`. Nothing unmounts (`action_show_screen` swaps a `hidden` class), so **`/`·`g` must route on `_active_screen_key`**, never on which inputs exist. This makes S-2's acceptance genuinely RED today. |
| ⚠️ **10 screens, 3 own find/goto** | Inc-9 | The "no local find/goto → one notice" path is **7 of 10 — the majority case.** And `set_status` writes the **log tail**, not `#status_text`: an AT reading `#status_text` is vacuous (it stays `'Ready.'` through nine searches). |
| ⚠️ **The deletable CSS span is `:66-102`, not `:55-102`** | Inc-10 | `#command_bar_slot` (`:51`) and `#command_bar` (`:61-64`) **survive** to host the palette. Deleting `:55-102` removes the styling of the container that stays. |
| ⚠️ **`Widget.focusable` ignores `display`** | any regime change | Inc-5's regime shift made 132×44 the fallback side, and **`AT-B78-15`/`-17` stayed GREEN against a `display: none` list.** A geometry change three increments later can empty an acceptance without touching it. |

---

## 5 · The controls this batch bought — read before writing any acceptance

Twenty-three carries are in `state.json` under `phase3_carries`. These are the ones that changed how the
work was done, stated generally:

| # | Lesson |
|---|---|
| `C-78-x` | **Analysing the right mechanism and deriving the wrong CONSEQUENCE CLASS is a distinct failure mode from not having looked.** Inc-2's packet named the async-clear mechanism, then bounded it with *"no such caller exists"* — the hazard was a stale **mount**, not a stale **read**, and the caller was the shipped Compare button. |
| `C-78-xiii` | **Put the guard in the DRIVER and make it raise** — then the broken state is unreachable by nodes **not yet written**. Padding buys margin; a completion signal buys determinism. |
| `C-78-xii` | **`pause()` is not a completion wait.** It waits for queue *idleness*, and a handler parked on an `await` has already dequeued its message. Cost 14 nodes. |
| `C-78-xvi` | A completion wait must be armed on an **edge** — **and so must every clause that consumes its result.** Inc-3 shipped that defect twice, ten lines apart. |
| `C-78-xv` | **A declared mutation must type-check, or it is a wish.** A mutation that raises goes red *in the driver*, so the assertion never runs and it is not a discharge. |
| `C-78-xxii` | The same defect in a declared **discharge** is worse: marking an `assumed` item discharged removes it from scrutiny **permanently**. **An `assumed — verify at Phase 3` item is closed by a NODE, or it is not closed.** |
| `C-78-xxiii` | **A mutation that reddens proves only that the one you picked was visible.** When a clause tests a **mapping**, mutate to the **identity**, not to nothing. |
| `C-78-viii` | An applied-check proves a substitution happened, **never that it is the one you meant.** The missing limb is *"the OLD token is absent after the write"*. |
| `C-78-xxiv` | **A sweep its own threshold can veto measures nothing.** Inc-5's first `_DIFF_MIN_H` sweep read 0 below the constant *because* of the constant. |
| `C-78-xx` | **⏳ OWED AN OWNER, and it is process work.** Every gate invoked through a pipe takes the **pipeline's** exit status, and fails in the **safe-looking** direction. Preferred fix: move the gate into the RC-1 pre-commit hook so shell plumbing cannot arbitrate a verdict. |
| — | **A census reports a SAMPLE, not a set.** Arm A gave 12/14/15/15/14 across five runs on one host. The verdict rests on *control ≫ 0* and *discharge ≡ 0*, never on the count. |
| — | **A register you fill in by hand measures attention, not propagation.** `enum.py` fixed 15 sites a recalled register had missed, **including all three it had claimed as swept**. |
| — | **A reconciliation audited in one direction is not audited.** The reverse fold audit found two lost architect criteria; one was the cause of a symptom the QA lane had found independently. |
| — | **Proximity to a corrected citation confers nothing.** A wrong line number was copied from the spec *in the same paragraph that corrected its neighbour*. |

---

## 6 · Process notes for the resuming session

- **Authorization is per-batch and is NOT inherited.** Ask at kickoff. This batch ran *autonomous + merge
  authorized*, and that **does not transfer**.
- **`origin/main` was `f6ff1d3`** at the cut. RC-1 before deriving anything.
- **A PARALLEL SESSION is live in this repo**, writing `prototypes/memmap2.*` — a full charter set
  (`HANDOFF.md`, `NOTES.md`, prototype, 9 SVGs). **Reported as found, never touched.** `state.json` is
  last-writer-wins with no owner field: **re-read it immediately before every edit.**
- **⚠️ Batch numbering:** `C-77-l` in `BACKLOG-CODE.md` was renumbered **78 → 79** at this batch's Phase 0.
  If the memmap2 session claims a number, **79 is taken by the aggregation carry** unless someone
  re-reconciles. Derive from disk **and** `git ls-remote`, never from memory — this project has had two
  collisions.
- **Reported as found, not swept (C-44):** `prototypes/out/`, `build/`, `prototypes$f.png`, and two idle
  python processes from 10:54/10:57 (152 min wall, 1.3 s CPU — probably leaked `run_test` contexts, but
  the parallel session's provenance could not be excluded).

---

## 7 · The two chartered follow-ons

### batch-79 — Lane 1: command-bar deletion (`Inc-6` … `Inc-12` of this spec)

**Everything is already specified.** `01-requirements.md` §7 rows Inc-6…Inc-12 carry the file sets, the
ATs and the gates; `HLR-118`…`HLR-121` and `HLR-126` are written, reviewed through three Phase-2 rounds
and amended. **Do not re-derive the spec — execute it**, honouring §4's findings above.

Order, with the reason: **Inc-6** (discoverability, `AT-B78-28`) · **Inc-7** (`HLR-120`, context onto
both surfaces) · **Inc-8** (re-point the 14 `_project_label()` sites *while both surfaces exist*) ·
**Inc-9** (`HLR-119`, re-home `/`·`g`, the notice at the log tail, the `Esc` release) · **Inc-10**
(`HLR-118`, delete `#command_bar_row` + CSS `:66-102`) · **Inc-11** (`HLR-121`, delete the messages,
adapters, helpers; reconcile the registry) · **Inc-12** (snapshot regen, **canonical CI only, one PR**).

**Inc-0's committed artifacts are the oracles Inc-10 and Inc-11 need** —
`tests/goldens/batch78/at-b78-12-search-goto-payload.json` (9 rows) and
`at-b78-03-palette-actions.json` (37 actions). **They must be re-read from disk, never regenerated:**
`AT-B78-03` was provably inert before Inc-0, because `CommandBar` is constructed as
`CommandBar(self._build_palette_entries())` — observed and expected were the same producer, and the
predicate stayed GREEN at `36 == 36` with a whole `Binding` removed. **What breaks the circularity is
the temporal freeze**, and `TC-B78-44`'s AST census reddens if any test module tries to rebuild one.

### batch-80 — Lane 3: operations staged removal (`S-10` … `S-13`)

**Never in scope for batch-78** (operator ruling at kickoff), and **this charter is a required
deliverable of this batch's close.** Source: `prototypes/cmdbar_a2bdiff.HANDOFF.md` §2 Lane 3, still
untracked at the repo root and **committed in this batch's PR**.

| # | Item |
|---|---|
| S-10 | Encode the modal's known CRC as a saved Designer `.crc.json`: width 32, poly `0x04C11DB7`, init `0xFFFFFFFF`, refin=refout=true (mapping the op's coupled `reverse`), xorout `0xFFFFFFFF`. **Open decision:** op configs allow multiple regions with per-region output addresses; Designer serialization is single-output — per-region template files vs a model extension. **Do not silently pick.** |
| S-11 | The Designer gains an execute/apply-to-image path — **the FIRST firmware write the Designer performs**, so it amends `US-V6` (preview-only) and **owes an explicit Before/After amendment**. Inherits the modal's verify-after-write, dispatch-token and bounded-write guards. |
| S-12 | **Equivalence by test, not by UI** (operator ruling): **no** dedicated check/KAT surface. The proof is byte-identical output between Designer execution and the modal's check+Write CRC path on a fixture image. **This test must exist BEFORE S-13 deletes the modal**, then survive as the Designer-vs-`crc32_stream` oracle. |
| S-13 | **Second increment, gated on S-10..S-12 merged and green.** Delete `OperationsScreen`, the `x` binding, the placeholder ops, their registry entries, the palette entry, dead tests. |

**Carry the charter did not resolve:** the deferred `wire-kernel-into-crc.py` item intersects S-10..S-12.
Phase 1 must state the relationship **explicitly** — supersedes / defers / absorbs — rather than
silently absorbing it. **`x` does not become free until S-13; do not rebind it in the same batch.**

---

## 8 · What is owed at this batch's own close

- [x] Inc-5's HIGH closed and committed — `70e2361` + `e24faae`
- [x] `01-requirements.md` folded — `_DIFF_MIN_H` **28**, and §2.8 D-1's height metric corrected from "content row" to "HEX row" so the two clauses no longer contradict
- [x] `BACKLOG-CODE.md` reconciled: batch-78 section rewritten from `IN FLIGHT` to its true state, Lane 1
      and Lane 3 registered, header refresh line + `origin/main` tip bumped
- [ ] **Branch PUSHED** — 26+ commits exist only locally, and *a commit that never lands is not a
      terminal state* (C-44)
- [ ] PR opened against `origin/main`
- [ ] `prototypes/cmdbar_a2bdiff.*` committed (charter §6) — **not** deleted: they are deleted in the
      close-out of the **last** batch of this charter, which is batch-80
