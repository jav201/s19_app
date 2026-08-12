# batch-79 — HANDOFF at the Inc-11 boundary

**Date:** 2026-08-07 · **Branch:** `claude/batch-79-cmdbar-deletion` (pushed, 14 commits, tree clean)
**Base:** `origin/main` @ **`829adc6`** · **Status:** Inc-6…Inc-10 complete · Inc-11 half · Inc-12 not started

---

## 0 · BLUF — what a resuming session needs in one paragraph

**The command bar is gone.** Its row, its six ids, its CSS span, its two messages, its two app-side
adapters and its three helpers are all deleted, and the class-qualified AST census closes **7 → 0**.
Everything it used to do is done somewhere better: the context labels on `#status_context` and the
Loaded panel's project row, the `/`·`g` keys on each screen's own inputs, the palette still in
`CommandBar` at **37 entries**. **Nothing was deleted before its replacement existed AND was observed** —
that ordering is the whole reason five increments landed green in a batch whose point is a deletion.

**Two things are owed and one of them cannot be done locally.** Inc-11 owes `AT-B78-12/13/14`. Inc-12
owes the snapshot regen, which is **canonical-CI-only** and is why **29 tests are RED right now, by
design**. Read §2 before you look at a test report.

**An independent code review returned BLOCK mid-batch and found three HIGH that three rounds of my own
review had not.** All seven findings are closed (§5). If you do nothing else differently, run that
review.

---

## 1 · Where the work stands

| Inc | Content | State | Commits |
|---|---|---|---|
| — | Phase 0 — premise evaluation, numbering conflict | ✅ | `b232a87` |
| 6 | `HLR-126` discoverability + `AT-B78-32` re-authored | ✅ | `ed11626` |
| 7 | `HLR-120` both context surfaces | ✅ | `8956074` `a1ab35c` `05777fb` |
| — | Independent review: 3 HIGH / 2 MEDIUM / 2 LOW | ✅ closed | `622d045` `234c6f0` |
| 8 | `LLR-121.4` re-point the project observable | ✅ | `6ed78f9` |
| 9 | `HLR-119` keys act on the active screen | ✅ | `ae71bd6` |
| 10 | `HLR-118` delete the row + six acceptances | ✅ | `2a062d2` `aa1aa72` `1154bd8` |
| **11** | `HLR-121` delete the seven symbols | ⚠️ **deletion done, `AT-B78-12/13/14` OWED** | `23af21f` |
| **12** | Snapshot regen | ❌ **NOT STARTED — CI only** | — |
| — | Five carries registered mid-batch | ✅ | `682df07` |

**Ledger:** base `829adc6` = **2653** → now **2683**. **+30**, every one accounted for: Inc-6 +4,
Inc-7 +10, Inc-9 +10, Inc-10 +6, Inc-8 +0 (a re-point adds no nodes).

---

## 2 · ⚠️ READ THIS BEFORE YOU RUN THE SUITE

**29 tests fail. They are supposed to.** `test_tc016s_density_layout_snapshot[*]` — all 29 golden SVGs
paint the command bar's `Project:` / `A2L:` / `Find` / `Go-to` labels, and `HLR-118` deleted the row that
drew them. The threshold was **pre-executed before the deletion** (Inc-10 entry gate) at 29 of 29, and
the run after the deletion reported exactly 29. **It is not a regression and it is not yours to debug.**

They regenerate **only** in the canonical CI environment (ubuntu / py3.11 / **textual 8.2.8**) via the
`snapshot-regen` workflow → download the `snapshot-baselines` artifact → commit. **Local regen drifts
unrelated baselines.** That is Inc-12, in its own PR.

Everything else is green: `test_tui_commandbar` 37 · `test_tui_diff_screen` 53 ·
`test_tui_directionb` 183 · `test_id_registry` 13 · `ruff` clean on every file this batch touched.

---

## 3 · What Inc-11 still owes

`AT-B78-12`, `-13`, `-14`. The one that matters is **`AT-B78-12`**: the **9-row behaviour payload**
re-read from `tests/goldens/batch78/at-b78-12-search-goto-payload.json` and compared against a fresh
live capture, proving the workspace / A2L / MAC search and go-to behaviour is unchanged by the deletion.

**Re-read that artifact from disk. Never regenerate it.** The digest recipe, if you need it: the payload
row is `(screen, query, goto, log_line_4_after_search, last_search_address, log_line_4_after_goto,
per_view_goto_focus_address)`; the artifact is the 9 rows as sorted-key JSON with `ensure_ascii=True`;
the digest is `blake2b(digest_size=8)` over its UTF-8 bytes. **The digest is a convenience — the oracle
is the row-by-row comparison.**

⚠️ **A second mutation is owed on `_handle_goto`'s address parse.** `find_string_in_mem` is the
module-level import all three `_handle_search*` paths use, so the recorded mutation reaches only the
**search** half; the go-to half is uncovered.

---

## 4 · Findings that reach forward — do not rediscover these

| Finding | Where it bites |
|---|---|
| **The spec's line citations are stale as a CLASS, and the offsets are NOT uniform** | `HLR-120`'s 15 cited addresses: 13 missed, at offsets +69, +66, +41, +15, +3 and 0 **within one requirement**. No correction constant repairs the set. **Resolve every symbol by NAME.** A line number is not a durable reference to a symbol, and this batch paid for that twice |
| **`len(app.log_lines)` cannot measure what `LLR-119.2` asserts** | `log_lines` is a `deque(maxlen=4)`, so its LENGTH saturates. Driving all 7 notice screens with a CORRECT implementation gives `1,1,1,1,0,0,0`. Count emitted notices instead |
| **A bare grep counted the wrong thing FOUR times** | `.pyc` binaries inflating a gate figure 4→10 · a docstring line counted as a call site · DOM ids searched in a pixel artefact · `focus_find` matching the preserved `action_focus_find`. **A plausible-looking count is the dangerous outcome; an impossible one gets checked** |
| **`.first()` RAISES on an empty query** | `bar.query("#x").first() is not None` cannot express absence — useless in an increment that deletes something. Use `len(...)` |
| **The palette outlives Lane 1** | `#command_bar_slot` and `#command_bar` survive `HLR-118` to host it. So the spec's suggested justification for deferring the palette's missing `escape` — *"the bar is deleted anyway"* — **is false**. It was deferred for a different, real reason (§6) |

---

## 5 · The independent review, and why it is the single most valuable thing in this batch

Run mid-batch over Inc-6 + Inc-7. Verdict **BLOCK**: 3 HIGH, 2 MEDIUM, 2 LOW. **All seven closed**
(`622d045`, `234c6f0`). Every finding was mine, and my own three rounds of self-review had missed all of
them — because I was reviewing my own framing.

- **F1** — `#status_text {width:auto}` let a routine status message size to **93 columns on a 78-column
  bar**, leaving `#status_context` 1 column wide and painting **nothing** at 80×24. I had reasoned
  carefully about the vertical axis and never looked at the horizontal one.
- **F2** — the four gates asserted over `render()`, so they were **structurally incapable** of seeing F1:
  `render()` returned the full string while the painted strip was empty. The correct oracle already
  existed **27 lines above them**, written for a different node and not reused. And all four ran only at
  120×30 — the one size where F1 does not reproduce.
- **F3** — the affordance advertised *"Enter opens"*; `Enter` is a no-op and the spec **excludes** that
  capability three times. My own AT **required** the false claim, so the guard would have resisted its
  own correction.
- Fixing F2 immediately exposed a sixth defect `render()` had hidden: `"project"` clipped to `"projec"`
  in a 6-column cell.

**Do this again.** `Agent(subagent_type="code-reviewer")` over the increment diff, with the brief telling
it to be adversarial about the author's claims and to verify the increment record rather than trust it.

---

## 6 · Decisions taken without asking — reconstruct them from here

| # | Decision | Why it was mine to take |
|---|---|---|
| 1 | Phases 1–2 **inherited** from batch-78; Phase 0 discharges the spec by premise evaluation instead | The charter says *execute, do not re-derive* |
| 2 | Merge precondition set by the orchestrator: an independent qa-reviewer pass over the whole diff | The operator granted merge authority without specifying one. **Still unwaived** |
| 3 | `AT-B78-32` re-authored (class-resolved) rather than its range corrected | A corrected range is one insertion above the block away from failing the same silent way |
| 4 | The affordance rides in the list BODY, not `border_title` | `styles.tcss:1623` gives the list `border: none` in the fallback regime — a border-hosted affordance is absent at 120×30 |
| 5 | `LLR-120.1`'s *"replacing"* discharged across **Inc-7 + Inc-10**, not inside Inc-7 | Deleting the bar write at Inc-7 reddened 10 shipped tests, and §7's Inc-8 row requires *"both surfaces exist"* |
| 6 | `TC-B78-13`'s pre-mount tolerance **made true** rather than descoped | It is an acceptance criterion of the requirement being built |
| 7 | `TC-B78-43` re-authored twice — the second reversing part of the first | The catalog was **half** right. Ask per half |
| 8 | The palette's `escape` **deferred**, with the spec's justification rejected | It is a new capability on a different widget, outside `HLR-119` |

**File-set deviations, all recorded, none silent:** Inc-9 declared 2 files and touched 3; Inc-10 declared
4 and touched 5. `HANDOFF` §4 of batch-78 predicted this — *"Lane 1's blast radius is 6 test files, not
3."*

---

## 7 · Open, and owed to the operator

Five carries are registered in **`.dev-flow/BACKLOG-CODE.md`** (Lane A) — pushed at `682df07`, with the
reasoning that is expensive to re-derive:

1. **8 `.pyc` files tracked in git** despite `.gitignore`. Python 3.9/3.10 bytecode in a 3.14 project.
   **Operator decision owed.**
2. **`LLR-119.2`'s threshold** — §6.5 amendment owed.
3. **`TC-B78-43`'s project half** — §6.5 amendment owed.
4. **The palette's missing `escape`.**
5. **The three painted-Footer-children arms** (8 / 13 / 15), carried from Inc-6.

---

## 8 · Process notes

- **Authorization is per-batch and is NOT inherited.** This batch ran *autonomous + merge authorized*;
  ask again. The merge precondition in §6 row 2 is **unwaived**.
- **`state.json` is single-batch, last-writer-wins, no owner field.** Re-read it immediately before every
  edit. It currently holds `2026-08-07-batch-79`, `current_phase: 0`, `phase_status: approved` — the
  Phase-3 progress lives in the increment records, not in it.
- **A parallel session may be live** writing `prototypes/memmap2.*`. Untracked, reported as found, never
  touched — along with `build/`, `prototypes/out/`, `prototypes$f.png`.
- **Bash heredocs mangle backslashes in this environment.** `\\n` inside a `<<'PY'` heredoc reached
  Python as a real newline three times and broke a string literal each time. Write the script to a file,
  or use the Edit tool.
- **Every mutation in this batch was restored and confirmed by `sha256`**, never by `git status` — which
  is vacuous for an untracked file and was insufficient here at least once.
