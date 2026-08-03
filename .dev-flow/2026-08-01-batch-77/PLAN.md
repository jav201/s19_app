# batch-77 — PLAN (living compendium)

> Updated at every gate and significant checkpoint. The operator reads **this**, not the file tree.

**Batch:** `2026-08-01-batch-77` · **Objective:** Memory Map redesign — Variant A (gap-fold band bar) + cross-cutting fixes S-1…S-7
**Charter INPUT:** `prototypes/memmap_variant_a.HANDOFF.md` (operator-approved 2026-08-01) — *input, not spec; everything re-derived*
**Branch:** `claude/batch-77-memmap-variant-a` · **Base:** `origin/main` @ `f8747b8`
**RC-1:** ✅ merge-base == tip (`0	0`) · **flow: `2026.07.28-rev1`** (hash mismatch scoped to the `dev-flow-lessons` catalog, local AHEAD — enforceable surface byte-exact; re-executed, not inherited)
**Lane:** A — `.dev-flow/BACKLOG-CODE.md` (per `docs/engineering-rules.md:17`)
**Language:** English (`state.json.language = "en"`)

---

## 1 · Where we are

**Phase 3 — IMPLEMENTATION, Inc-1 in flight.** Resumed 2026-08-01 by a fresh session from
`.dev-flow/HANDOFF-2026-08-01-batch-77-phase3.md`, at a clean phase boundary. Phases 0, 1 and 2
are **complete and approved**; requirements are at **revision 5** (819 lines) after 4 gate rounds,
9 review passes and 11 operator rulings. **Zero lines of production code existed at resume.**

⚠️ **There is no Inc-0.** §4's indicative roadmap below is **superseded by requirements §7**, which
runs **Inc-1 … Inc-9**. The golden capture is **Inc-3 by design** — a golden captured before the
width basis settles pins the retired arithmetic, which is exactly how `[45,15]` entered revision 1.

### Phase-3 entry gate — re-executed at resume, not inherited

| Check | Result |
|---|---|
| **RC-1 base currency** | ✅ merge-base of `claude/batch-77-memmap-variant-a` == `origin/main` tip `f8747b8`; 0 unpushed; no PR yet |
| **Flow currency (C-45)** | ⚠️ **scoped MISMATCH, non-blocking.** Aggregate `896dcca61cf68d78` vs manifest `0127a2767ff11c8a`. All 11 control-bearing command/template files byte-exact (`commands/dev-flow.md` = `307e5cd9b0eb879a` ✓). Sole divergence: `skills/dev-flow-lessons/SKILL.md` at 641 lines / `01d608bb14069613` vs the stamped 620 / `5c47db86ac2cf4ae` — **local is AHEAD**. The enforceable surface is current. Lane B already carries the re-stamp. |
| **Toolchain** | ✅ Python 3.14.4 · pytest 8.4.2 · ruff 0.15.17 |
| **Working tree** | ✅ clean except `prototypes/out/` — untracked, **pre-dates the batch**, reported as found and never swept (C-44) |
| **Authorization** | ✅ **asked fresh** (per-batch, never inherited): *autonomous + merge authorized*, decision-recording *confirmed* |

⚠️ **Concurrency.** A second session is live on this same branch, finishing the pre-implementation
full-suite baseline. Its intended push is an artifact edit; this session's is code. **Rebase before
pushing.** Do not start a competing full-suite run — two concurrent pytest runs contend for CPU and
flake the timing-sensitive Textual geometry assertions this increment depends on.

---

## 2 · Objective

Make the Memory Map's hero — the entropy band bar — legible for sparse S-record images,
and close six cross-cutting usability gaps around it, **without** perturbing the shipped
band/colour contract or the frozen engine.

**Measured problem (executed, not asserted):** at 5 regions / 1 030 B / 128 MiB span the bar emits
**64 columns against a 60-column budget**, of which **59 are gap hatch**; runs of
256/256/256/200/62 B all render at **exactly 1 column**. The bar does not fail to *show* regions —
it fails to **discriminate** them, and it **overflows its own budget** doing so.

---

## 3 · Story intake (Definition of Ready) — Phase-0 artifact

Each story states an outcome observable through the **shipped** surface. `AT` ids are **not**
minted here — `AT-TC-REGISTRY.jsonl` is the sole authority and reservation happens in Phase 1
on its own PR (per `docs/engineering-rules.md:46`).

| US | Story (observable outcome) | INVEST | Status |
|---|---|---|---|
| **US-77-1** | Given a sparse multi-region image, when the map renders, the operator sees **each region's bar width order with its mapped size**, gaps folded to fixed markers, **and the bar within its column budget**. A dense no-gap image renders **byte-identical to today**. | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-2** | When the map renders, **every ruler label names a mapped address** (region starts + span end), overlaps collapsed, fold labels carrying gap size. | I·N·V·E·S·**T** | 🟡 **READY-WITH-AMENDMENT** |
| **US-77-3** | The stats line shows a **dual mapped/span readout** with a real percentage and a **humanized** largest gap, replacing `Coverage: 0.00%` + raw bytes. | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-4** | The always-on 4-row legend block is **absent from the map body**; a footer hint points to the existing `k` LegendScreen, which is **unaffected**. | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-5** | The operator can reach and act on regions **with the keyboard only**: focus a row, ↑↓/j/k to move, `Enter` inspects, `o` opens hex — surfaced in Footer + `?`. Mouse N4a split (single=inspect, double=hex) preserved. | I·N·V·E·**S**·T | 🟡 **READY — C-16 FLAGGED** |
| **US-77-6** | With a file loaded, the inspector is **populated with zero clicks** (first region auto-selected). | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-7** | The selected region row is **visually distinguishable** from unselected rows. | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-8** | *(charter "optional")* log-scale microbar denominator + column-aligned region rows, ported from Variant C. | — | 🔴 **OUT** |

### Status reasons

- **US-77-1 — the drafted acceptance is replaced, not inherited.** Charter draft #1
  (*"every region ≥1 visible bar column"*) is **already TRUE today** (P-4): `:2066` floors every run at
  `max(1, …)`. It is invariant under the change it gates → **C-40 limb 1**. The discriminating property is
  **width monotonicity** (`bytes(a) > bytes(b) ⇒ cols(a) ≥ cols(b)`, with ≥1 strict inequality on the sparse
  fixture), which is **RED today** because all five widths are equal. The charter's **byte-identical dense
  control** (draft #2) is kept — it is the strongest thing in the drafted set.
  **Absorbs the new P-15 overflow defect** (64 > 60): same `max(1, …)` expression, rewritten by this story.
  Folding it in rather than carrying it is a **recorded autonomous decision (D-2)**.
- **US-77-2 — amendment, not wording.** S-2's cited `LLR-072.3` **does not exist** (P-5). The clause is
  `R-TUI-072`, guarded by the **live, passing** `AT-072b` asserting *exactly 5 ticks* (P-6). Proceeding
  requires a **§6.5 Before/After amendment** to `R-TUI-072` + a re-derived `AT-072b`, and correction of the
  dangling `LLR-072.3` citation at `tests/test_tui_map_big.py:118`. Ready to derive; the amendment is
  Phase-1 work and is **not** a blocker.
- **US-77-5 — C-16 prototype-fidelity flag.** The keyboard path is demonstrated only in a throwaway
  prototype. **Textual performs no spatial arrow-focus by default** — this is the literal origin of C-16
  (batch-27, where `MapCell.on_key` was Enter-only and an `.focus()`-based AT shipped the gap GREEN).
  Carried as **`assumed — verify in target framework at Phase 3`**, and its AT **must press real keys**,
  never call `.focus()`. Story stays READY; the risk is on the mechanism, not the outcome.
- **US-77-8 — OUT, with reason.** No measured defect motivates either idea; the charter explicitly forbids
  silent absorption; and both are visual-design changes that would widen an already 7-story batch past the
  ≤5-files-per-increment discipline. **Registered as a Lane-A carry, not dropped.** Reversible on request.

### Explicitly out of scope (charter §2, honored)
- **Variant B** (two-lane map) — its own batch if ever; registered as a backlog candidate.
- **The CC-1 encoding decision** owed to the operator — unrelated, not absorbed here.

---

## 4 · Roadmap — ⛔ **SUPERSEDED. Do not execute this table.**

> **The authoritative increment cut is requirements §7 (`Inc-1 … Inc-9`).** The table below is the
> Phase-0 *indicative* sketch, kept only so the supersession is legible. **Its `Inc-0` does not exist**
> in the approved plan: the golden capture moved to **Inc-3**, deliberately, because a golden captured
> before the width basis settles pins the **retired** arithmetic — precisely how `[45,15]` (which sums
> to the retired constant 60) got into revision 1. **Capturing a golden before Inc-1 lands is a known
> defect, not a head start.** The numbering below also does not correspond to §7's: this table's
> "Inc-2" is §7's Inc-4, and so on.

| Inc | Content | Files (≤5) |
|---|---|---|
| ~~Inc-0~~ | ~~Byte-golden of the **dense no-gap** render~~ — **⛔ REMOVED; became §7's Inc-3, after the basis settles** | tests |
| Inc-1 | US-77-1 gap-fold widths + budget bound | `screens_directionb.py`, `styles.tcss`, tests |
| Inc-2 | US-77-2 ruler + `R-TUI-072` amendment + `AT-072b` re-derivation | `screens_directionb.py`, `REQUIREMENTS.md`, tests |
| Inc-3 | US-77-3 stats + US-77-4 legend demotion | `screens_directionb.py`, `styles.tcss`, tests |
| Inc-4 | US-77-5 keyboard + US-77-6 auto-select + US-77-7 selection style | `screens_directionb.py`, `styles.tcss`, `app.py`, tests |

Snapshot goldens **will** drift → regenerate **only in canonical CI** (textual 8.2.8 pin).
`tui-ci` runs `-m "not slow"` on PRs and the **full** suite on pushes — the **full** form runs before merge,
and every ledger figure states which form produced it.

---

## 5 · Risks & watch-items

| # | Risk | Mitigation |
|---|---|---|
| R-1 | `tests/test_tui_map_big.py` is the blast-radius centre (`AT-072a/b`, `AT-073`, `AT-074`, two `query(RegionRow)` sites) | **C-26 reverse-grep** every touched symbol across all of `tests/` before any increment lands |
| R-2 | Fold markers accidentally becoming `RegionRow`s would corrupt those counts | Keep them inert `Static`s — the `BandSegment` sibling precedent (P-13); gaps are **already** inert (P-14) |
| R-3 | Textual gives no spatial arrow-focus for free (C-16) | AT presses **real keys**; `assumed — verify at Phase 3` |
| R-4 | Snapshot drift mismarked | C-22 per-cell reasoning; C-28 for any Footer binding added by US-77-5 |
| R-5 | Markup/injection via new label paths | **B3 holds**: no file-derived text in bar/rows. Any new label is a count/address/constant. C-17 re-check at Phase 2 |
| R-6 | Charter numbers copied rather than re-derived | Every figure in `00-measurements.md` carries its executed transcript |
| R-7 | **C-33's prescribed liveness discharge is OBSOLETE under this harness** — see finding F-0 below | Deliverable-file monitor armed with a bounded 30-min timeout as the backstop; finding routed to Lane B |

### F-0 — a control whose prescribed discharge no longer executes (found Phase 1, routed to Lane B)

**C-33 says:** discharge sub-agent liveness *"either \[by] an active blocking wait (`TaskOutput block=true`, re-polling on timeout) OR \[by] poll\[ing] a genuine progress signal (touched-file mtime for an implementer; `TaskOutput` status)."* **Both named mechanisms are now unavailable**, measured rather than assumed:

1. **`TaskOutput` is DEPRECATED for `local_agent` tasks** and its own documentation forbids the C-33 usage: the `.output` path *"is a symlink to the full subagent conversation transcript (JSONL) and will overflow your context window."* The sanctioned replacement is the Agent tool's completion notification — i.e. exactly the passive wait C-33 was written to forbid.
2. **The transcript-size signal is dead, verified by sampling:** both lanes' `.output` files sat at **0 bytes with mtime frozen at dispatch** (`17:05:11` / `17:05:46`) across a 45 s interval. This is the batch-49 condition reproduced — and the reason the standing rule is *verify the signal moves before trusting it*, which is what caught it here.
3. **My own first monitor was also inadequate** and I state it plainly: it watched the **deliverable file**, which is written once at the END of the agent's work, so a 0 B reading cannot distinguish "reading hard" from "hung". It is a completion detector wearing a liveness detector's label — the same shape of defect this batch found in the charter's acceptance #1.

**Net:** for a `local_agent` under this harness there is currently **no in-band progress signal**, so C-33's *"STOP + take over once liveness cannot be confirmed"* branch is the only honest discharge, and it must be driven by a **wall-clock bound**, not by a signal. Bound adopted here: **30 min**, enforced by the monitor's timeout.

#### ⚠️ F-0 is TOO STRONG, and Phase 3 measured the correction — amend it before it carries to Lane B

**The claim *"there is no in-band progress signal for a subagent"* is FALSE for an implementer, and
that matters because it is the half of C-33 that still works.** Measured this session against the
Inc-1 implementer: a monitor polling **target-file mtime** at a 3-minute cadence tracked the agent
through its phases and moved on a real schedule —

```
t+3m/+6m  mtime frozen at the checkout value   -> reading the 819-line spec  (correctly NOT read as a hang)
t+9m      screens_directionb.py written        -> edit phase began
t+12m     screens_directionb.py written again
t+15m     test_map_click_chain.py written      -> Amendment C
t+18m/+21m mtime frozen, 8-9 python procs live -> test phase (C-34 mandates ~3 min for one file alone)
t+24m     test_map_click_chain.py written      -> post-run edit; liveness POSITIVELY re-confirmed
t+27m     written again
```

> 🛑 **RETRACTION — the `python procs` column above is VACUOUS and every inference I drew from it is
> withdrawn.** Executed at t+33m: `Get-CimInstance Win32_Process -Filter "Name='python.exe'"` returns
> **`taskboard.exe` ×2, `desk.exe`, and five `python -m http.server` instances** — the operator's
> ambient tooling. **There was never a single `pytest` process in any of the six samples.** The count
> drifting 8↔10 was noise from unrelated servers, and I narrated it as *"processes went from 8 to 10,
> which is a test run starting."* **That was a story told over noise.**
>
> **This is the project's own standing rule — *verify the signal actually moves before trusting it* —
> and I invoked that rule against the transcript-size signal in the paragraph directly above, then
> failed to apply it to the signal I had just built.** Same shape as `F-1(f)` (the starvation probe
> that committed the starvation it existed to detect) and as the Phase-0 stats probe that queried
> containers. **Fourth occurrence of a probe defect in this batch, first one that is mine this session.**
>
> **A second, independent defect in the same measurement:** I compared a **Git Bash** `stat -c %Y`
> mtime against a **PowerShell** `Get-Date -UFormat %s` "now" and got `mtime_age = −352 min`, i.e. a
> file modified ~6 h in the future. The mtime is fine; PS 5.1's `-UFormat %s` returns local-time-as-epoch
> and ignores the `-0600` offset, so the two producers use **different epoch conventions**. Had I not
> checked, "the file is in the future" was one step from a fabricated alarm. **This is C-42 in its purest
> form — never compare a value across two producers without reconciling their encodings.**
>
> **What survives:** mtime alone, read from **one** producer. **What does not:** the process count, and
> with it my claim at t+30m that the corrected takeover rule "correctly did not fire" — it did not fire
> for the *wrong reason*, because its process-activity limb was reading noise.
>
> ✅ **SEQUEL — the sharpened instrument answered the question within one interval, and the answer was
> the opposite of my inference.** The monitor was re-armed to count **`pytest`-specific** processes
> (`Win32_Process` filtered on a `pytest` command line) instead of every `python.exe`. First reading:
> **`pytest procs: 1`**, sustained across the next interval. **The implementer IS running tests**; my
> t+33m census simply landed in a gap between runs, moments after it finished an edit. So *"I cannot
> confirm any pytest has run"* was true of **my sample** and false of **the world**.
>
> **The lesson is the one worth carrying, and it is not "I was wrong twice."** A blunt instrument
> produced a *false positive* (10 processes ⇒ "tests are running" — they were `http.server`) and then,
> once distrusted, tempted a *false negative* (no pytest in one sample ⇒ "no tests have run"). **Both
> errors came from treating a point sample as a state.** The fix was never to reason harder about the
> readings — it was to **make the instrument name the thing it claims to measure**, after which the
> question dissolved in three minutes. That is C-40 limb 1 (*is the declared subject actually in the
> expression?*) applied to a monitoring probe rather than to an acceptance predicate.

**This is exactly C-33's own prescribed implementer signal (*"touched-file mtime for an
implementer"*) and it is alive and well** — *the mtime half only; see the retraction above.* What is
dead is the *transcript-size* signal, `TaskOutput`, **and a naive process-name count**. So the
correct scope of F-0 is narrower and more useful:

| Agent kind | In-band signal | Status |
|---|---|---|
| **Implementer** (known target files) | target-file **mtime** | ✅ **WORKS** — verified above |
| **Reviewer / analyst** (writes one deliverable at the very end) | none | ❌ genuinely absent — a deliverable-file watch is a *completion* detector wearing a liveness detector's label |

**Consequence for the takeover rule, and it is not a relaxation.** A fixed wall-clock cutoff applied
to an agent that has *just demonstrably progressed* would be acting on a signal that pattern-matches
a known failure while having a different cause. The trigger is therefore **stalled mtime AND no
process activity**, with wall-clock as the fallback **only where no signal exists** — i.e. for
reviewers, not implementers. **The 30-minute bound stays as written for the reviewer case.**

**Not a batch-77 defect and not app code — this is a process/control item. It is written into `.dev-flow/BACKLOG-PROCESS.md` at this batch's close (Lane B), per the routing rule that a carry belonging to the other lane is written there, never left as a pointer.**

---

## 5b · Inc-1 gate — independent predictions, recorded BEFORE the implementer reported

> Written by the orchestrator at dispatch time, from the project's own controls and precedent, so
> they can be **checked against** the increment's report instead of agreeing with it after the fact.
> This is the batch-24 golden-double-proof discipline applied to a gate: a prediction made after
> reading the answer proves transcription, not provenance.

**① C-30 does NOT apply — the CSS change is map-scoped, and Inc-1 correctly leads the batch.**
C-30 sequences an *app-wide* restyle **last**, because it drifts every snapshot cell and would
suppress regression coverage for the rest of the batch. Executed check: `.map-band-row`,
`.map-band-bar` and `.at-a-glance` are constructed **only** in `screens_directionb.py`
(`:2098`, `:2101`, `:2226`) and styled **only** at `styles.tcss:779-818`. No other screen
constructs them. `LLR-111.9` is therefore a **per-screen** change, which is precisely the shape
C-30 *wants* — each functional increment drifts and marks only its own cells. **Inc-1 leading is
correct and does not need re-sequencing.**

**② C-22 per-cell snapshot-drift prediction — UPPER BOUND 2 cells, both `map`.**
Stated per-cell with a reason, never as a flat exact count (C-22), and as a bound because a cell
can render a change below a scroll fold and not drift at all.

| Cell | Predicted | Why |
|---|---|---|
| `map-comfortable-120x30` | **drifts** | The band row goes horizontal → vertical, the bar widens **21 → 50**, the glance panel moves beneath it. Layout *and* content change. |
| `map-comfortable-80x24` | **drifts** | Layout is unchanged (80×24 already stacks via `width-narrow`, bar stays 66) — but the **content** changes: the width basis moves 60 → 66, the denominator moves address-span → mapped-bytes, and gaps fold from `[8,8,16,33]` to 1 column each. ⚠️ **A prediction of "80×24 is unaffected" would be wrong** — it is unaffected in *geometry* only. |
| every other cell | **0** | The repo's own precedent, restated twice in `tests/test_tui_snapshot.py` (`:454-455`, `:672-679`): *"no other screen renders the map body."* |

**Do not regenerate these locally** — regen is canonical-CI-only under the textual 8.2.8 pin and is
Inc-9's job. Drift is expected and reported at this gate, not fixed here.

> ✅ **RESULT — MEASURED AT Inc-1b, AND THE PREDICTION HELD ON BOTH LIMBS.** Executed at `a84ff2f`
> on a quiet machine, *before* any mark was applied:
> ```
> 2 failed, 27 passed, 3 deselected in 73.64s
> FAILED …test_tc016s_density_layout_snapshot[map-comfortable-80x24]
> FAILED …test_tc016s_density_layout_snapshot[map-comfortable-120x30]
> ```
> 1. **BOTH map cells drift — the two-cell prediction is CONFIRMED and the parallel session's
>    one-cell report is FALSIFIED.** The load-bearing half was `80x24`: the obvious call is that it is
>    unaffected (it already stacked, its bar stays 66), and that call is **wrong**. Its *geometry* is
>    unchanged and its *content* is not — basis 60→66, denominator address-span→mapped-bytes, gaps
>    `[8,8,16,33]`→1 each. A content-only drift on an unchanged-geometry cell is exactly what this looks
>    like. **Recorded in advance specifically so it could be falsified; it wasn't.**
> 2. **No unpredicted cell drifted** — 27 of 29 passed, so nothing outside the map moved. The repo's
>    long-standing claim (`tests/test_tui_snapshot.py:454-455`, `:672-679`) that *"no other screen
>    renders the map body"* **HELD**, and Inc-1's map-scoped CSS did not leak into shared chrome
>    (**C-28 clean**). This also retro-validates ①: had `LLR-111.9` been app-wide, C-30 would have
>    forced it to sequence last.
> 3. **Marked, not suppressed: 27 passed / 2 xfailed / 0 xpassed.** Zero `xpassed` is the check that
>    no cell was over-marked — over-marking silently retires a live regression guard, which is the cost
>    C-30 exists to avoid. Ledger delta **0**.
>
> ⚠️ **Process finding, and it is the session's recurring one a third time:** Inc-1b's pre-run
> "is the machine quiet?" check returned 0, and a parallel `pytest tests/ -q` started **between** its
> measurement and verification runs. **A point-in-time sample is not a lock.** It blocked on that
> process rather than measuring under contention — correct — but the check itself cannot prevent what
> it only observes. Same shape as the process-count probe and the single-`pilot.pause()` read: *an
> instantaneous observation being trusted as a sustained state.*

**③ C-34 is in force.** Inc-1 changes a TUI render module, so its gate must run the **FULL**
`tests/test_tui_directionb.py` — not a `-k` subset. That file is the cross-cutting guard host
(markup-safety source scans, rail/screen census, shared-chrome footer census). A `-k`-only gate is
a C-19 partial-run violation in its render-specific form. The brief mandates full × 3.

**④ 🆕 FINDING — `LLR-111.7`'s allocator is UNDER-SPECIFIED, and the wrong reading is silent.**
Found mid-flight by an independent arithmetic oracle (pure Python, no app import — so it is a real
second source, not a re-run of the code under test). Sent to the implementer before it wrote the
allocator. **Every numeric figure in the requirement reproduced; the defect is a missing definition,
not a wrong number.**

`LLR-111.7` mandates *"floor-1 per run + largest remainder on mapped bytes"*. That admits **two
honest readings**, and the requirement never says which:

| Reading | Gapless 768/256 @bar=66 | @bar=50 |
|---|---|---|
| **(A)** floor 1 first, then apportion the **SURPLUS** (`avail − n_runs`) by largest remainder | **`[49,17]`** ✅ the mandated payload | **`[37,13]`** ✅ |
| **(B)** apportion the **WHOLE** `avail` by largest remainder, then clamp up to 1 | `[50,16]` ❌ | `[38,12]` ❌ |
| *plain `round()`* — the method the requirement explicitly calls WRONG | `[50,16]` | `[38,12]` |

⚠️ **(B) is numerically identical to plain `round()` on this fixture.** So an implementer who reads
(B) writes what looks like a principled largest-remainder allocator, produces exactly the payload
the requirement spent a revision retiring, and **Inc-3 then captures a golden pinning it** — with
every test green. This is the batch's own signature failure (an unstated definition is not
re-derivable, only re-inventable) sitting in the one clause the whole increment turns on.

**(A) also needs no tie-break on this fixture** — the quotas land on exactly `48.0` and `16.0`, so
there is no fractional tie. *If an implementation needs a tie-break to reach `[49,17]`, it is (B)
with a tie-break bolted on, not (A).* That is a cheap, decisive discriminator.

**Independently confirmed by the same oracle:** out-of-domain `avail` = **−734 / −750**, 801 widths,
content **1601**, no raise (✅ matches the requirement's row (b)) · onset **26 @bar=50, 34 @bar=66**
(P-50 ✅) · the gapless payload is **fold-invariant** at fold 1/2/5/60, confirming P-58 that the
retired "substitute the fold denominator" mutation was a provable no-op and that `AT-B77-02`'s
discharging mutation must be **allocator → plain `round()`**.

> 🛑 **CORRECTION — my `prg.s19` width vectors were WRONG, and the cause was mine.** I originally wrote
> `[1,1,1,1,1,9,6,26,1,2,1,1,1,1]` @66 and `[1,1,1,1,1,6,4,16,1,1,1,1,1,1]` @50, "independently
> confirmed." **The algorithm was right; the INPUT was not.** I fed my oracle the requirement's
> `n_gaps = 13` instead of deriving it. **Executed by the implementer: `prg.s19` has 10 gaps, not 13** —
> `_merge_band_runs` splits on band change **or** address discontinuity, and four of the 14 runs are
> band changes at *contiguous* addresses, which emit no gap
> (`gap_before = [F,T,T,T,T,T,F,F,F,T,T,T,T,T]`). Re-running my oracle at `n_gaps = 10` reproduces the
> implementer's measured vectors **exactly at both regimes**:
>
> | | @bar=66 | @bar=50 |
> |---|---|---|
> | ❌ mine, at the spec's 13 gaps | `[…,9,6,26,…]` sum 53 + 13 = 66 | `[…,6,4,16,…]` sum 37 + 13 = 50 |
> | ✅ **measured, at 10 gaps** | **`[…,9,7,28,…]` sum 56 + 10 = 66** | **`[…,6,4,18,…]` sum 40 + 10 = 50** |
>
> **Both totals hit the bar exactly, which is why a wrong gap count survived four revisions and my own
> check** — the bound is computed from the *emitted* count, so the increment is correct either way and
> only the per-run vector moves. **P-49's CONCLUSION holds; its FIGURES do not.**
>
> ⚠️ **The irony is exact and belongs on the record.** The requirement's `13` is precisely `n_runs − 1`
> (14 − 1) — **the assumption finding ⑤ was written to forbid.** I sent ⑤ warning the implementer never
> to infer `n_gaps` from the run count, and then, in the same session, inherited that very inference
> from the spec into my own oracle without deriving it. **⑤ was right, and it caught the spec; it did
> not catch me, because I never turned it on myself.** Second self-inflicted probe defect this session
> (after the process-count signal), and the same root both times: **I derived the method carefully and
> accepted the inputs on trust.**

**Scope of the oracle, stated so it is not over-credited:** it is arithmetic only. It says nothing
about the container-measurement path, the CSS widen, the settling helper, or whether the real
producer feeds these run lists at all. Those remain to be established by execution against the app.

**⑤ 🆕 FINDING — `n_gaps` is NOT `n_runs − 1`, and the showcase fixture hides it.**
Sent to the implementer during its edit phase. Read from the shipped emission rule: a gap is emitted
only `if start > cursor`, with `cursor` initialised to `span_start`. Therefore

- a **LEADING** gap is possible (when `runs[0].start > span_start`) → `n_gaps` can reach `n_runs`;
- there is **NO TRAILING** gap (the loop ends at the last run, nothing spans `cursor → span_end`).

So `n_gaps ∈ [0, n_runs]` and must be **counted from the same predicate that emits it**. ⚠️ `prg.s19`
is 14 runs / 13 gaps — every inter-run position gapped, no leading gap — **precisely the shape that
makes `n_runs − 1` look correct on the showcase fixture.** Both the domain predicate
(`n_runs + n_gaps ≤ bar_width`) and the allocation (`avail = bar_width − n_gaps × fold`) consume it,
so under-counting by one makes `avail` one too large and **the bar overflows its container — which is
P-15, the exact budget-overflow defect this increment exists to close.** It would also **evade
`AT-B77-01`** (all runs still visible, monotone and strict) and surface only in `AT-B77-03`'s
containment clause. Mitigation asked for: compute the gap positions **once** and let the allocator
call and the widget emission consume that same list, so the two counts cannot diverge; and report
measured `n_gaps` per fixture at the gate, not just totals.

**⑥ CHECKED AND CLEAR — `LLR-111.9`'s threshold is NOT red-on-correct.** The threshold reads
`bar.region.width == #map_grid.region.width`. That equality would be **false under a correct
implementation** if `#map_grid` carried padding or a border, because the bar would then equal the
grid's *content* width, not its *region* width — a red-on-correct acceptance of exactly the kind
this batch has already hit twice (`AT-072b`'s fixture, `AT-B77-15a`'s "verbatim" wording). Executed:
`#map_grid` (`styles.tcss:769-773`) is `width: 1fr; height: auto; layout: vertical;` — **no padding,
no border**, so `region.width == content_region.width` and the threshold is satisfiable as written.
**A negative result, recorded because a check that came back clean is evidence, not a non-event.**

**⑦ CHECKED AND CLEAR — Amendment C's 160×48 → 120×30 revert keeps a non-first segment reachable.**
The two AC-6 pointer tests ran at 160×48 for a *measured* reason: at 120×30 the bar was 21 columns,
so segments past it were clipped and therefore unclickable, and the tests' whole rigor is that they
click a **non-first** segment. Reverting them is only safe if the widened bar restores reachability.
Derived from the fixture (`_two_band_loaded`, `tests/test_tui_directionb.py:3844` — outside Inc-1's
file set, so stable): **two 256-byte ranges separated by a `0x10000` gap**, first run starting at
`span_start` ⇒ **2 runs, 1 gap, no leading gap**. Through the (A) allocator: `bar=50 → [25,24] + 1
gap = 50`; `bar=66 → [33,32] + 1 gap = 66`. **Both segments are ~24–33 columns wide and fully inside
the bar at both regimes** — a non-first segment is comfortably clickable, so the revert is sound and
the coverage it restores at the repaired regime is real. *(Note in passing: this fixture has EQUAL
runs, which is exactly the vacuity R-2 forbids for the `LLR-111.4` golden — harmless here, because
these tests assert click→address threading, not width discrimination. It must not be borrowed for
Inc-3.)*

> **Both ④ and ⑤ are the same species and neither is a code defect:** a quantity the specification
> names but never defines, where the batch's own showcase fixture happens to satisfy the wrong
> reading. That is this batch's signature failure — *a design validated against the fixture its
> author chose* — recurring for a fourth time, now at the implementation boundary rather than in
> the document.

---

## 6 · Invariants that must survive (verified against `f8747b8`)

**B3** no file-derived text in bar/rows · **colour only via `band-*`** (`entropy_style` + `styles.tcss:665-679`), glyphs `· ░ ▒ ▓` are the colour-blind cue (C-10) · **LLR-041.7** panel is presentational · **remount discipline** classes never ids · **fold markers are not `RegionRow`s** · **N4a click split** + `width-narrow` regimes · **no `_nodes`/`_context`** on new widgets · **engine-frozen set off-limits** (source **and** `_ENGINE_TEST_FILES` — C-27 dual guard).

---

## 7 · Test ledger

| Point | Base | −D | +A | Post | Form |
|---|---|---|---|---|---|
| batch-76 close (`fd9124a`) | — | — | — | **2514 passed / 2 skipped / 3 xfailed** | FULL |
| batch-77 Phase-3 entry, **collection** on `f8747b8` | — | — | — | **2519 collected** (reconciles: `2508 − 0 + 11 = 2519`) | collect-only |
| batch-77 Phase-3 entry, **pass/fail** — ✅ **RE-DERIVED** | — | — | — | **2514 passed · 2 skipped · 3 xfailed · 29 snapshots passed** in 2101 s (35:01) | **FULL** |
| **Inc-1** (`a84ff2f`) | 2519 | 1 | 21 | **2539** collected | per-file |
| **Inc-1b** (`b22a202`) | 2539 | 0 | 0 | **2539** — marks, not tests | snapshot |
| **Inc-2** — ✅ **orchestrator-owned gate run** | 2539 | 0 | 5 | **2537 passed · 2 skipped · 5 xfailed** = **2544** in 1611 s (26:51) | **FULL** |

> ✅ **Inc-2's full suite is GREEN and the ledger reconciles exactly.** `2537 + 2 + 5 = 2544 = 2539 + 5`,
> and the baseline chain closes end-to-end: `2519 → 2539 → 2544`. **`xfailed` moved 3 → 5** — precisely
> the two map snapshot cells Inc-1b marked, and **27 snapshots passed** with the 2 mismatches being
> exactly those marked cells. Nothing unmarked drifted.
>
> 🛑 **PROCESS FAILURE — C-25 violated, by me, and it is the control written for this exact event.**
> The Inc-2 implementer reported *"clean full suite is running in the background … I'll report when it
> lands"* and then **ended its turn**. A subagent's background processes end with its task, so that run
> **never survived and could never have reported**. I relayed its claim onward as though the run were in
> flight. **C-25 exists because this happened twice before** (batches 35 and 36) and says plainly that
> the orchestrator launches and collects the long gate run *because a sub-agent that launched it will END
> before it finishes.* I delegated it anyway.
> **Caught only because the operator asked "working or stuck"** — a liveness question I had no signal
> for, since I was watching file mtimes and not the existence of a promised run. **A report that work is
> in flight is exactly as unverified as any other plausible claim**, and this batch's whole defect
> signature is a plausible claim nobody executed. Re-run under orchestrator ownership; the figures above
> are from that run's own output.
| **Inc-1 + review-fix pass, collection** | 2519 | 1 | 21 | **2539 collected** (reconciles: `2519 − 1 + 21 = 2539`) | collect-only |
| **Inc-1 + review-fix pass, gate files** *(quiet machine — 0 competing pytest processes verified immediately before)* | — | — | — | `test_tui_map_big.py` **29 passed in 48.50s** · `test_tui_directionb.py` **174 passed in 254.35s (4:14)** · `test_map_click_chain.py` **7 passed in 13.91s** | FULL, per file |
| **Frozen dual guard (C-27), both halves** | — | — | — | **3 passed, 171 deselected in 0.88s** — the `git diff --name-only main` byte-identity guard over `_ENGINE_TEST_FILES` **and** `test_tc032_no_engine_test_function_is_skipped` | `-k` on the guard host |

**Ledger notes (review-fix pass).** The `−1` is the retired `test_ac6_clipped_segments_are_a_known_layout_limitation` (Amendment C) — verified absent, **0 occurrences** in `tests/test_map_click_chain.py`. The `+21` is Inc-1's 19 new nodes **plus the 2 parametrizations of Amendment D's `TC-B77-03` differing-size arm**. **2539 is READ from a `--collect-only` run, not computed**; the arithmetic is shown only as a reconciliation, per *a carried number is re-derived, not copied*. Every pass/fail figure above is read from that run's own output — **none is spliced across runs** — and all three gate files were run after confirming the `bl77` baseline had drained to 0 pytest processes, because a contended run flakes the timing-sensitive geometry assertions and cannot serve as gate evidence (D-9).

> ✅ **The pre-implementation baseline is now DERIVED, not inherited (D-15 discharged).** Executed in an
> isolated detached worktree at `f8747b8` (`C:\Users\jjgh8\bl77`), touching neither the branch nor the
> working tree, so nothing about Inc-1 could contaminate it. **Three things it settles:**
> 1. **It reconciles exactly with collection:** `2514 + 2 + 3 = 2519` ✓.
> 2. **It matches batch-76's close figure exactly** — so the inherited number was *right*, and is now
>    *re-derived*. The provenance was the defect, not the value. **This is the first figure in this
>    session that I can say that about without a retraction attached.**
> 3. ⭐ **All 29 snapshots PASSED at baseline.** That is the load-bearing one: it means the snapshot
>    matrix was **fully green before Inc-1**, so any snapshot failure now is **attributable to Inc-1 by
>    construction** rather than by argument. It confirms the parallel session's attribution premise and
>    gives **Inc-1b** a clean basis for its C-22 per-cell marks — including the falsification test of my
>    own two-cell prediction.
>
> ⚠️ **The risk D-9 named did not materialise: there were NO pre-existing failures.** The tree was green
> at `f8747b8`, so nothing in Inc-1's gate can be a pre-existing failure wearing Inc-1's name. The
> deferral cost a 35-minute re-run and bought certainty; recorded as the price actually paid.
>
> 📋 **C-44:** the worktree at `C:\Users\jjgh8\bl77` is **outside the repo tree**, registered via
> `git worktree`. It is retained only until Inc-1b's snapshot attribution is settled, then removed with
> `git worktree remove`. Recorded here so it cannot be forgotten.

---

## 8 · Decision log

| # | Decision | Authority | Note |
|---|---|---|---|
| D-1 | Batch numbered **77** | autonomous | Derived from disk + `git branch -r`, not memory — two prior collisions in this project |
| D-2 | **Fold P-15** (64 > 60 budget overflow) into US-77-1 rather than carry it | **autonomous** | Same `max(1, …)` expression the story rewrites; leaving a known overflow inside code being rewritten is how a defect becomes the next batch's premise |
| D-3 | **Replace** charter draft acceptance #1 with width-monotonicity | **autonomous** | Draft #1 measured GREEN on the pre-change tree (P-4) — vacuous per C-40 limb 1 |
| D-4 | **US-77-8 OUT**, registered as a carry | **autonomous** | No measured defect; charter forbids silent absorption; batch already at 7 stories |
| D-5 | Flow-currency mismatch ruled **NON-BLOCKING** | **autonomous** | Re-executed per-file: 11/11 control-bearing files byte-exact; divergence is the catalog only, local AHEAD |
| D-6 | Use subagents per the flow (`code-reviewer` per increment, `qa-reviewer` Phase 4 + merge gate) with C-33 liveness polling | **autonomous** | The accepted kickoff option explicitly names the independent `qa-reviewer` merge pass; overrides the session-harness default |
| D-7 | **Use batch-scoped ids `AT-B77-nn` / `TC-B77-nn`; NO reservation PR** | **autonomous** | `docs/engineering-rules.md:48` prefers them, and the registry's own `_meta.governed` puts letter-initial bodies **outside its authority** (spec §2.3). They cannot collide by construction, and the global pool never has to carry them. **Exception:** `AT-072b` is an *existing* global id being re-derived, not minted — it keeps its number. This removes a whole PR from the critical path. |
| D-8 | **Corrected my own stale carried number** — registry `next_free` is `AT-282 / TC-613`, not `TC-611` | **autonomous** | I had copied batch-76's `state.json` figure instead of re-deriving from the registry. It was stale: batch-76's *own* merge-gate closure minted `TC-611`/`TC-612` after that line was written. **I broke "a carried number is re-derived, never copied" in the very file that records the rule.** Corrected and recorded, not silently overwritten. |
| **R-1** | **Bar width RECONCILES to the real container**, not the constant 60 | **OPERATOR** 2026-08-01 | The batch's central defect: `.map-band-bar` is 21 cols @120×30 vs a 60 budget → **2 of 5 regions invisible**. Reddens the live PIN `test_map_click_chain.py::test_ac6_clipped_segments_are_a_known_layout_limitation`; **deleting it is sanctioned by its own docstring** (*"If the constant and the container were reconciled, DELETE this test"*). Retirement must print an explicit line naming the dropped observable (C-40 limb 2(ii)). |
| **R-2** | **Dense control RE-BASES** after the width fix | **OPERATOR** 2026-08-01 | Byte-identity with *today's* dense render is abandoned deliberately — R-1 changes it by design. New control: **gap-folding is a strict no-op on gapless images at fixed container width**. Golden fixture must use **unequal** runs (768/256 → `[45,15]`); equal 512/512 → `[30,30]` is invariant under any monotone re-weighting and would be vacuous (QA B-5). |
| **R-3** | **Keyboard = ↑↓ + Enter only; `j`/`k`/`o` DROPPED** | **OPERATOR** 2026-08-01 | All three are already bound app-wide (`o`→`open_workarea`, `j`→`dump_a2l_json`, `k`→`show_legend`); `o`/`j` are frozen in `_PRE_BATCH_BINDINGS` under live `TC-011`. Keeps `k` as the legend key so US-77-4's hint stays true. ⚠️ **Scope reduction: the charter's `o` = open-hex keyboard affordance is DESCOPED** — registered as a carry. The **N4a mouse split is unchanged** and remains the route to hex. |
| **R-4** | **Ruler labels the LAST MAPPED BYTE**, not the exclusive `span_end` | **OPERATOR** 2026-08-01 | `span_end` is exclusive (`0x07FFFF3E`; last mapped byte `0x07FFFF3D`), so *"every label names a mapped address"* ∧ *"label at span end"* were mutually unsatisfiable. Also corrects my P-7: **4 of 5** ticks name unmapped addresses today, not 3. |
| **R-5** | **Fold marker is 1 column, always** | **OPERATOR** 2026-08-01 | Measured at the reconciled 21-col container: `fold=1` → `[4,4,4,3,1]`; `fold=2` → `[3,3,3,3,1]`, which collapses three runs to equal width and **guts the strict limb** — the load-bearing half of `AT-B77-01` at 80×24 (finding N-1). ⚠️ **DESCOPES the charter's "2-col marker + humanized size label at/above a fold threshold"** (S-1) → carry **C-77-g**. Second chartered feature descoped this batch, and like the first it is registered, not dropped. |
| **R-6** | **Re-render PRESERVES the selection** if the region still exists, else falls back to the first | **OPERATOR** 2026-08-01 | No input document stated a policy. Needs **two** acceptance arms: a single "preserved" arm is green on an implementation that never re-selects, and a single "fallback" arm is green on one that always resets — neither alone distinguishes the spec from its two failure modes. Interacts with HLR-116: **focus must follow selection** or the keyboard story silently regresses. |
| — | **Autonomy: autonomous + merge authorized**; merge gated on green CI **and** a clean final independent `qa-reviewer` pass over the whole diff vs `main`. A HIGH finding blocks and returns to the operator. | **OPERATOR** 2026-08-01, `AskUserQuestion` at kickoff — asked fresh, not inherited | |
| — | **Decision recording confirmed** — every un-asked decision recorded in PLAN.md §8, `state.json.decisions_log`, `05-postmortem.md`, and carried to the vault at `/dev-flow-sync` | **OPERATOR** 2026-08-01 | |
| **R-7…R-11** | Widen-then-aggregate · accept the stats fold (`C-77-k`) · `+N more` in the region list · **aggregation SPLIT to batch-78** · **ANSI scrub PULLED IN** | **OPERATOR** 2026-08-01 | Full texts in `state.json.phase1_operator_rulings`. R-10 and R-11 are what took the batch from *blocked in three lanes* to approved. |
| — | **Authorization RE-ASKED at the Phase-3 resume** — *autonomous + merge authorized*, decision recording *confirmed* | **OPERATOR** 2026-08-01, `AskUserQuestion` at resume | Per-batch and **never inherited**. The prior session held the same grant; that grant did **not** transfer, and the handoff document explicitly said so. Asked fresh from the operator, not read from `state.json`. |
| **D-9** | **Do NOT launch a competing full-suite baseline** while the parallel session's FULL run is in flight | **autonomous** | Two concurrent pytest runs contend for CPU and flake the timing-sensitive Textual geometry assertions Inc-1 is measured by — the same `N-2` transient (17/97 traces) `LLR-111.6` exists to defend against. The collection figure (2519) is already verified; only pass/fail is pending, and nothing in Inc-1 blocks on it. **Cost of the choice, stated: a pre-existing failure would surface mid-increment and could be mistaken for one Inc-1 caused** — mitigated because Inc-1's own gate runs the three affected files in full and the counterfactual is captured pre-change. |
| **D-10** | **Rebase before pushing**; a second session is live on this branch | **autonomous** | The parallel session intends to push an artifact edit to `claude/batch-77-memmap-variant-a`. Its change and this session's code are mergeable, but a blind push loses one of them. Recorded because `state.json` is a known last-writer-wins hazard in this project with a near miss already on record. |
| **R-12** | **Inc-2 approved at 7 files**, then **extended to 9** — the cap waived for this increment ONLY, twice, on the indivisibility argument | **OPERATOR** 2026-08-02, `AskUserQuestion` ×2 | The scrub cannot land without porting the acceptances it invalidates — they assert the premise it refutes. **Explicitly NOT standing:** the operator declined the offered "treat port-growth as standing for the batch" option, so a later increment that invalidates acceptances elsewhere **stops and asks again**. The implementer halted at the boundary **both** times rather than assuming; that is the behaviour to preserve. |
| **F-2** 🆕 | **THE INCREMENT'S HEADLINE FINDING — a false claim in shipped source became NINE green acceptances defending it** | measured at Inc-2 | `safe_text`'s docstring asserted it neutralised ANSI. It does not. The requirement recorded that as **one** false claim misleading **one** spec revision. Measured: **9 nodes · 5 test files · 8 render surfaces**, every one green against a guarantee the source never provided — Memory Map detail (1), flow-result sinks + block label (2), A2L tags cell (1), Checks linkage + detail (1), **patch screen (4, in a file nobody had identified)**. **The lesson is one layer deeper than "a false docstring misleads readers": it gets ENCODED INTO THE ACCEPTANCES BUILT TO CATCH IT, and those tests then DEFEND the falsehood.** A green suite is not evidence the guarantee holds; it can be evidence the guarantee's negation has been ratified. Discovered only because the fix forced the full suite to run. |
| **F-3** 🆕 | **`LLR-116.6`'s choice of the PAINTED STRIP over `.plain` is load-bearing, and Inc-2 accidentally proved it** | measured at Inc-2 | An unscoped "no control byte" clause fired on `_flow_block_label`, which composes its own `U+000A`. **The painted strip is line-split, so its rows carry no newline** — the requirement's layer choice avoids the false failure by construction. Recorded as a **confirmation of the requirement**, not as a workaround: the spec picked the right layer for a reason it never stated, and executing found the reason. |
| **F-4** 🆕 | **`EXPECTED_SCANNED_TEST_FILES` is NOT the vacuous-input-set defect — checked, not assumed** | verified at Inc-2 | I asked whether the 152→153 bump was a hand-maintained census (this batch's registered C-31 defect) or a real measurement. **Both limbs answered by execution:** 153 is *measured* (`scanned_test_files()` = 153, and an independently re-written glob agrees), and the guard **derives** its corpus by globbing `tests/**/*.py` minus four excluded dirs — the constant is a **budget threshold** compared against that derived set, built to redden when the corpus widens. **That is the healthy INVERSE of a hand-listed input set: the list is computed and only the bound is a human decision.** A clean negative, recorded because a check that came back clean is evidence. |
| **R-13** | **`test_tc519` RE-SCOPED from file identity to its stated invariant** — 5th file in Inc-4 | **OPERATOR** 2026-08-02, `AskUserQuestion` | The guard froze `s19_app/tui/legend.py` by `git diff`; Inc-4's charter and `LLR-112.3` both mandate editing it. Escalated because the alternatives were *weaken a shipped guard* or *silently drop a normative clause*, and neither is a subagent's call. **Approved with one hard condition: prove the re-scoped guard still fires by executing the regression it names.** It did — both arms, mutations restored and hash-proven. |
| **F-5** 🆕 | 🛑 **THE GUARD WAS WATCHING THE WRONG FILE — too strict AND too weak, and the second half is the serious one** | measured at Inc-4 | Its docstring named the invariant: *"`_render_card()` / `_render_key()` … must not reconstruct rows from text."* Its expression was `git diff --name-only origin/main -- s19_app/tui/legend.py`. **Executed: `_render_card` is at `screens.py:1093`, `_render_key` at `screens.py:1141`, and `legend.py` contains ZERO occurrences of either.** Proven, not argued: with the consumer-side regression applied, the old guard's pathspec returned only `legend.py` while `screens.py` — carrying the defect — **was never listed**. **A path-filtered diff on one file cannot ever surface another file's defect, so the node was structurally incapable of failing on the regression it existed to prevent.** This is **C-40 limb 1 in its purest form**: the declared subject does not appear in the predicate's expression. It survived from batch-72 to batch-77 green, and it was found only because a *different* requirement forced someone to edit the file it guarded. **A guard that has never been made to redden is a guard whose subject nobody has checked.** The replacement asserts the invariant behaviourally in two arms (consumer re-parents · producers return widgets); a source hash was considered and **rejected on record** — it reddens on any producer edit while staying GREEN on the consumer defect, which is where the regression actually lives. |
| **F-6** 🆕 | **Source-reading tests are corrupted by concurrent edits, and the corruption is INDISTINGUISHABLE from a real failure** | demonstrated at Inc-4 | Two full-suite failures (`test_tc078_4`, `test_tc080_5`) were artifacts of docstring edits landing **while the run was in flight**. Both nodes read their subject via `inspect.getsource` + `ast.parse`; a line-number shift makes `getsource` return the **wrong region** on an already-imported module, so the AST walk finds **zero** calls. Demonstrated rather than asserted: `BEFORE getsource ok=True, AST calls=['SENTINEL_CALL']` → `AFTER ok=False, calls=[]`, the source actually returned being `'"""A module docstring added later."""'`. **The agent invalidated its OWN run and reported it rather than reconciling to it.** Standing rule: *never edit a file while a suite that reads its source is running.* Note this file's `test_tc031`/`test_tc032` and the re-scoped `TC-519` are all source-readers. |
| **D-12** | **The 5th file IS authorized for Inc-1** (`tests/test_tui_directionb.py`, 2 edits, 3 tests) | **autonomous** | The project cap is **≤5**, so this is *at* the cap, not over it — no waiver needed. The implementer stopped at 4 and reported rather than taking it silently, which was correct. **The blast radius was UNRECORDED in requirements §7** — Inc-1's file list names 4 files and the document logs only `test_at075_e_key…` (Inc-6) for this file. That is a **C-26 reverse-census miss in the SPEC**: nobody grepped the touched CSS classes across `tests/`. Two of the three failures are `LLR-111.9`'s accepted row-growth (R-8) breaking `pilot.click` targeting; one pins the retired horizontal dock. **Port, never delete** — instructed explicitly. |
| **D-13** | **Snapshot C-22 marks land as their OWN single-file micro-increment, NOT inside Inc-1** | **autonomous** | Marking requires `tests/test_tui_snapshot.py` — a **6th** file for Inc-1, which *would* breach the cap and need an operator waiver. Splitting it needs no waiver, keeps Inc-1's diff reviewable, matches this project's own precedent (`_batch45_map_drift_marks` / `_batch47_map_drift_marks` — scoped helpers added during the batch and retired after regen), and satisfies **C-30**: each increment marks only its own cells so every untouched cell stays live as a regression guard. **Regen itself remains Inc-9, canonical CI only.** |
| **D-14** | **Inc-1's gate evidence is PROVISIONAL until re-run on a quiet machine** | **autonomous**, prompted by the parallel session | Contention is **evidenced, not suspected**: the implementer's three runs over the same file set took **329 s / 288 s / 252 s**, and its first run surfaced **2** failures where runs 2–3 surfaced **3** (`test_b01…` "not yet surfaced"). These are the timing-sensitive geometry tests `LLR-111.6` exists to defend, and a parallel full-suite run overlapped. **Only an uncontended run's own output becomes the gate figure (C-19).** |
| **D-15** | **A TRUE pre-implementation baseline is captured from a DETACHED WORKTREE at `f8747b8`** | **autonomous** | The parallel session's baseline is **void** (its output file never held more than a header), and the working tree now contains Inc-1, so a baseline can no longer be taken here. The only surviving figure is batch-76's close — **inherited, which is the provenance this batch exists to punish**. A detached worktree touches neither the branch nor the working tree and can run during code review. ⚠️ **Consequence of D-9 now realised and owned:** deferring the baseline cost a re-derivation, exactly the risk D-9 named. |
| **D-11** | **Inc-1 delegated to `software-dev`; OQ-3 delegated with it, decided on executed evidence** | **autonomous** | Per D-6 and the flow's Phase-3 agent assignment. My prior analysis (that `#map_grid` is measurable *before* the mount, which would remove the need for any `_BAND_BAR_WIDTH` fallback) was handed over **as a hypothesis to verify, not as an instruction** — the batch's own signature failure is a plausible sentence nobody executed. The implementer is told to report what its clean allocator actually produces for the 768/256 payload and to **surface a mismatch with the predicted `[49,17]`/`[37,13]` rather than tune the code to the document.** |

---

## 9 · Out-of-scope carries (registered, not dropped)

- **US-77-8** — log-scale microbar denominator + column-aligned region rows (Variant C ports).
- **Variant B** — two-lane map; its own batch if the operator wants it.
- **Dangling id `LLR-072.3`** cited at `tests/test_tui_map_big.py:118` with no definition in
  `REQUIREMENTS.md` — to be corrected inside US-77-2 if that story lands, otherwise a carry.
  (Note: `LLR-*` is **not** covered by the AT/TC registry — operator scoping ruling 2026-07-31.)
