# batch-79 — PLAN (living compendium)

**Batch:** `2026-08-07-batch-79` · **Objective:** Lane 1 — command-bar deletion (`Inc-6` … `Inc-12` of
the batch-78 spec) · **Language:** en · **Route:** `/dev-flow`, entering at Phase 3 with Phases 1–2
**inherited** from batch-78.

---

## 0 · BLUF — where we are

**Phase 0 complete. One inherited premise is FALSE and it changes `Inc-6`'s work; everything else held.**

The spec for this batch already exists: `.dev-flow/2026-08-06-batch-78/01-requirements.md` §7 rows
`Inc-6`…`Inc-12`, with `HLR-118`…`HLR-121` and `HLR-126` written, reviewed through three Phase-2 rounds
and amended. **The charter is explicit: execute it, do not re-derive it.** What Phase 0 owes is not a new
spec — it is the **premise evaluation (C-43)** of an inherited one, because a requirement written down by
an earlier batch is a *hypothesis*, not law, until it passes its own verification.

Nine premises were executed against the current tree. **Eight held exactly. One is false**, and it fails
in the safe-looking direction: `AT-B78-32`'s line range watches 38 of the block's 55 lines and would
leave **six real bindings unguarded** while reporting "untouched".

---

## 1 · RC-1 and flow currency

| Check | Result |
|---|---|
| `origin/main` tip | **`829adc6`** — batch-78's `phase_status` fix |
| Working branch merge-base | local `main` **0/0** vs `origin/main`, tree clean apart from the parallel session's untracked `memmap2.*`, `build/`, `prototypes/out/`, `prototypes$f.png` |
| Flow currency (C-45 PULL) | `~/.claude` clean, **0/0** vs its remote · `flow_version 2026.07.28-rev1` · `flow_hash 0127a2767ff11c8a` · controls C-1…C-45 |
| Backlog lane (per `docs/engineering-rules.md`) | **Lane A — `.dev-flow/BACKLOG-CODE.md`** (production code + its dev flow) |
| Batch number | **79**, free on disk **and** `git ls-remote`. See §2 — it was contested |

## 2 · The numbering conflict, and how it was resolved

**Two claimants existed for 79 and one of them was an operator ruling.** `BACKLOG-CODE.md:168` carries
`C-77-l` labelled **"BATCH-79 CHARTER: the aggregation path"**, renumbered 78 → 79 by operator ruling on
2026-08-06 and marked P1 / **LOAD-BEARING** — it is the sole reason batch-77's ruling R-10 counts as a
*scope reduction* rather than a *silent drop*. Meanwhile batch-78's `HANDOFF.md` §7 charters its Lane-1
follow-on as "batch-79", while **§6 of that same document warns that 79 is taken by the aggregation
carry**. The handoff contradicts itself.

**Operator ruling 2026-08-07: Lane 1 takes 79.** The aggregation path (`C-77-l`) is renumbered to **80**,
and Lane 3 (operations, previously chartered as batch-80) moves to **81**. Reconciled in
`BACKLOG-CODE.md` as a Phase-0 close step rather than left as two claimants — this project has had two
numbering collisions already.

## 3 · Authorization (asked fresh — never inherited)

| Item | Ruling, 2026-08-07 |
|---|---|
| Autonomy | **Autonomous** end-to-end |
| Merge authority | **Granted** |
| Merge precondition | **Set by the orchestrator, not by the operator:** a final independent `qa-reviewer` pass over the whole merged diff vs `main` before merging. This batch deletes app-level chrome and drifts 29 snapshot goldens. The operator may waive it; a waiver is recorded as their decision |
| Decision recording | Every un-asked decision lands in this file's §8 log, `state.json.decisions_log`, the post-mortem and the vault at sync |

## 4 · Premise evaluation (C-43) — executed against the tree at `829adc6`

Tier 3 (premises about the world) unless noted. **Evidence is an executed probe; a citation of another
document is not evidence.**

| # | Proposition | Verdict | Executed evidence |
|---|---|---|---|
| P-1 | The App `BINDINGS` block is `app.py:1338-1375`, and `AT-B78-32`'s zero-line `git diff` over that range certifies it untouched | ❌ **FALSE** | Block is **`app.py:1338-1392`** — 55 lines, **31** `Binding(…)` entries. `:1375` is `("minus", "page_prev_context", "Page-")`, **mid-block**. See §5 |
| P-2 | `styles.tcss`: `#command_bar_slot` at `:51`, `#command_bar` at `:61-64` **survive**; the deletable span is `:66-102` | ✅ TRUE | `:51 #command_bar_slot`, `:61 #command_bar`, `:66 #command_bar_row` — all three exact |
| P-3 | `_project_label()` has **14** call sites, and re-pointing them is `Inc-8`'s work | ✅ TRUE | 14 calls + 2 definitions = 16 raw matches. **Zero production call sites** — it is a *test helper* defined in `test_tui_patch_variant.py:82` and `test_tui_variants.py:76`. Pattern: `grep -rn '_project_label(' tests/ \| grep -vc 'def _project_label'` |
| P-4 | `_PRE_BATCH_BINDINGS` does not pin `/` or `g`, so re-homing them cannot trip the freeze guard | ✅ TRUE | **14** frozen tuples at `test_tui_directionb.py:6058`: `l r o s p j 1 2 3 q plus minus comma period`. Neither key present |
| P-5 | 29 snapshot goldens drift on the bar deletion; regen is CI-only | ✅ TRUE (count) | **29** SVGs under `tests/__snapshots__/test_tui_snapshot/`. The *drift* claim is a prediction and is `Inc-12`'s to measure — **not** asserted here (C-39) |
| P-6 | `set_status` writes the **log tail**, not `#status_text`; an AT reading `#status_text` is vacuous | ✅ TRUE | `app.py:11707` `set_status` → `_append_log_line`. `#status_text` is written only by `set_file_status` (`:11710`) |
| P-7 | The `Inc-0` oracles exist on disk and must be **re-read, never regenerated** | ✅ TRUE | `at-b78-03-palette-actions.json` = **37** actions · `at-b78-12-search-goto-payload.json` = **9** rows |
| P-8 | The command palette has **no** `escape`-to-close; `Inc-9` must choose a disposition in writing | ✅ TRUE (inherited, batch-78-executed) | `command_bar.py` declares no `BINDINGS`; `ctrl+k` then `escape` leaves `palette_is_open` True. **Re-execution owed at `Inc-9`** before the disposition is written |
| P-9 | batch-78's Lane 2 shifted the line numbers the Lane-1 spec cites | ❌ **FALSE** | Hypothesis tested and refuted: at `f6ff1d3` (pre-batch-78) the block was **already** `1338-1392` with 31 entries. Batch-78 added **zero** `Binding(` lines. The defect in P-1 is older than Lane 2 |

## 5 · P-1 — the one that blocks, stated in full

**`AT-B78-32` as specced is a PIN whose predicate cannot see 17 of the 55 lines it claims to certify.**

The spec (`01-requirements.md:679`) defines `AT-B78-32` as *"the App `BINDINGS` block is untouched — a
zero-line `git diff` over `app.py:1338-1375`"*, owed at `Inc-6`, with the mutation *"add any binding to
the block"*.

Measured: the block runs `1338`→`1392`. Lines `1376-1392` hold **six real bindings** —
`comma`/`period` (hex paging), `pagedown`/`pageup` (batch-31 AC-3), `ctrl+z`/`ctrl+y` (batch-40 S2).
**A binding added or removed among those six leaves the predicate GREEN**, so the guard reports
"untouched" for a block that was touched. It fails safe-looking, which is the expensive direction.

**It is not a drift.** At `f6ff1d3` the block was already `1338-1392`; batch-78 added no bindings. The
range was **wrong when it was written**, and it survived three Phase-2 rounds and two independent review
lanes — because a line range *looks* like a measurement.

**This is C-40 limb 1:** the declared subject ("the App `BINDINGS` block") is not fully inside the
predicate's expression. And the prescribed mutation hides it — *"add any binding to the block"* reddens
the predicate if you happen to add it above `:1375`, which is where anyone would add one.

**Disposition (Inc-6 owns it):** the durable fix is not a corrected range. A hardcoded line range is
invalidated by any edit **above** the block, so a corrected `1338-1392` is one insertion away from being
wrong again in the same silent direction. `Inc-6` shall assert over the **extracted block** — anchored on
its delimiters or parsed from the AST — and the mutation shall be executed **in the tail** (`1376-1392`),
not the head, because a mutation in the head passes for the wrong reason.

## 6 · Increment plan (inherited — spec §7, unchanged in content)

| Inc | Content | ATs | Files | Gate notes |
|---|---|---|---|---|
| **6** | `HLR-126` — discoverability | `AT-B78-28`, `AT-B78-32` | `screens_directionb.py`, `tests/test_tui_diff_screen.py` (2) | **`AT-B78-32` re-authored per §5** — extracted block, tail mutation |
| **7** | `HLR-120` — context onto both surfaces, both display forms, `safe_text` on both *(Lane 1 opens)* | `AT-B78-08…11`, `AT-B78-30` | `app.py`, `screens_directionb.py`, `styles.tcss`, `tests/test_tui_commandbar.py` (4) | `TC-B78-12` control-char limb green on both surfaces. ⚠️ `test_tui_app.py`'s stubs are **not** evidence — it monkeypatches `update_project_labels`, so it goes **blind, not red** |
| **8** | `LLR-121.4` — re-point the 14 `_project_label()` sites **while both surfaces exist** | (protects `AT-B78-30`) | `test_tui_patch_variant.py`, `test_tui_variants.py`, `test_tui_directionb.py` (3) | three suites green; `grep -rn 'cmdbar_project' tests/` → **0** (currently **10**) |
| **9** | `HLR-119` — re-home `/`·`g`; the notice at the log tail; the `Esc` release | `AT-B78-04…07` | `app.py`, `tests/test_tui_commandbar.py` (2) | `_PRE_BATCH_BINDINGS` unchanged; `OWNING` asserted **set-equal, not by length**; **P-8 disposition written, not inherited**; route on `_active_screen_key`, never on which inputs exist |
| **10** | `HLR-118` — delete `#command_bar_row` + CSS `:66-102`; **plus the four arms BL-2 moved here** | `AT-B78-01…03`, `AT-B78-24…26` | `command_bar.py`, `styles.tcss`, `tests/test_tui_commandbar.py`, `tests/test_tui_diff_screen.py` (4) | palette **10/10**, **37** entries **re-read from the Inc-0 artifact**; per-arm verdicts at 80×24 / 120×30 / 132×44 / 160×40. `AT-B78-26`'s "≥1 hex row" inherits the **painted** form |
| **11** | `HLR-121` — delete messages, adapters, helpers; reconcile the registry | `AT-B78-12…14` | `command_bar.py`, `app.py`, `test_tui_commandbar.py`, `test_tui_directionb.py`, `AT-TC-REGISTRY.jsonl` (5) | `test_id_registry.py` G1–G7; seven-symbol class-qualified AST census; `git diff` over the six handlers = 0; **second mutation owed on `_handle_goto`'s address parse** |
| **12** | Snapshot regen — **canonical CI only**, one PR | — | 29 snapshot SVGs | full suite (**FULL** form); C-22 per-cell |

## 7 · Risks / watch-items

1. **The Lane-1 blast radius is 6 test files, not 3.** `#cmdbar_project` is the observable for the
   `LLR-005.5` multi-variant display form, so `Inc-7` owes the display **FORM**, not just the name.
2. **`Widget.focusable` ignores `display`.** A geometry change can empty an acceptance without touching
   it — `AT-B78-15`/`-17` stayed GREEN against a `display: none` list at batch-78.
3. **§5.1 rule 1's painted-height metric measures the border box** and does not clip through intermediate
   ancestors — `AT-B78-26`'s 120×30 clause would pass at three rows of border and zero hex. **Blocks
   `Inc-10`**; use `Inc-1`'s corrected helper (`content_region` through the full ancestor chain).
4. **29 goldens regen in CI only.** Local regen drifts unrelated baselines (textual==8.2.8 pin).
5. **A parallel session is live in this repo** writing `prototypes/memmap2.*`. `state.json` is
   last-writer-wins with no owner field — **re-read it immediately before every edit**.

## 8 · Decision log

| # | Date | Decision | Recorded because it was taken without asking |
|---|---|---|---|
| 1 | 2026-08-07 | Batch number **79** for Lane 1; `C-77-l` → **80**; Lane 3 → **81** | — operator ruling, asked |
| 2 | 2026-08-07 | Autonomous + merge authorized | — operator ruling, asked |
| 3 | 2026-08-07 | **Merge precondition set by the orchestrator**: independent `qa-reviewer` pass over the whole diff before merge | ✅ un-asked — the operator left it unspecified and may waive it |
| 4 | 2026-08-07 | Phases 1–2 **inherited** from batch-78 rather than re-run; Phase 0 discharges the inherited spec via premise evaluation instead | ✅ un-asked — follows the charter's "execute, do not re-derive" |
| 5 | 2026-08-07 | `AT-B78-32` **re-authored** at `Inc-6` (extracted block + tail mutation) rather than its range corrected to `1338-1392` | ✅ un-asked — a corrected range is one insertion away from failing the same silent way |

## 9 · Test ledger

| Point | Value |
|---|---|
| Baseline (batch-78 close, Inc-5) | **2647** |
| Current | to be measured at `Inc-6` entry |

## 10 · Out-of-scope carries

- **batch-80** — the aggregation path (`C-77-l`), renumbered here.
- **batch-81** — Lane 3, operations staged removal (`S-10`…`S-13`).
- `C-78-xx` — a gate invoked through a pipe takes the *pipeline's* status. **Owed an owner; process lane.**
- `C-78-xxiv` — cited in batch-78's HANDOFF §5, never registered in `phase3_carries`.
