# batch-79 — HANDOFF #2, at the seventh-gate boundary

**Date:** 2026-08-13 · **Branch:** `claude/batch-79-cmdbar-deletion` (pushed through `b7cb966`)
**Base:** `origin/main` @ **`829adc6`** · **Supersedes:** `HANDOFF.md` (written at the Inc-11 boundary, still accurate for Inc-6…Inc-10)

---

## 0 · BLUF — read this paragraph before anything else

**Inc-11 is complete, including all three of `HLR-121`'s acceptances. The branch has NOT merged.**
Seven independent merge-gate passes have run; **six returned BLOCK and none of the six was
manufactured.** The seventh was still running when this was written — **check its verdict first**
(see §6).

**The single most important fact for whoever picks this up:** passes 1–2 found defects in *shipped
code* — including a production regression that broke six tests in two files this batch had never run.
Passes 3–7 found **zero** runtime defects and, every single time, a false statement in the record.
That is not the gate being pedantic. It is the batch's defect class living in the one region its 2 657
passing tests have no oracle for.

**Do not merge without a clean gate.** The merge precondition was put to the operator explicitly on
2026-08-11 and they **declined the waiver**. It is their decision, not an inherited default.

---

## 1 · State of the tree

| | |
|---|---|
| Branch HEAD (pushed) | **`b7cb966`** |
| Uncommitted | `tests/test_tui_commandbar.py` — `TC-B79-05` hardening (§4). **Commit it.** |
| Full suite | **29 failed · 2657 passed · 2 skipped · 3 xfailed** — all 29 are `test_tc016s_density_layout_snapshot[*]`, Inc-12's canonical-CI-only regen. **Zero other failures.** |
| Ledger | **2691** — pattern: `python -m pytest tests/ --collect-only -q` from the repo root |
| ruff | **7 errors over `ruff check s19_app tests`, identical at base and HEAD.** `ruff check .` gives 66; the extra 59 are a PARALLEL session's untracked `build/` and `prototypes/` |
| Flow currency | **`2026.08.10-rev12` / `41144ca54e8b944a`**, `~/.claude` 0/0 vs `jav201/claude-config` @ `b3cef32` |
| `phase_status` | Phase 3, Inc-6…Inc-11 complete; **Inc-12 owed** |

⚠️ **The parallel session's untracked files** (`build/`, `prototypes/memmap2.*`, `prototypes/out/`,
`prototypes$f.png`) are not ours. Never touch them, and **scope every repo-wide figure to exclude
them** — that mistake has already inflated one ruff count from 7 to 66.

---

## 2 · What shipped in Inc-11

`HLR-121`'s three acceptances, then five rounds of gate response.

| Node | What it does |
|---|---|
| `AT-B78-12` (PIN) | the 9-row behaviour payload re-read from disk vs a fresh live capture |
| `AT-B78-13` (GATE) | class-qualified AST census, 7 symbols → 0, plus the CSS selector census |
| `AT-B78-14` (PIN) | every LIVE registry row resolves — **recorded as a PIN, not the GATE the spec predicted** (§5) |
| `TC-B79-01…04` | the `#status_context` bound: eviction, budget/stylesheet coupling, `_FIND_GOTO_INPUTS` completeness, apportionment |
| `TC-B79-05` | **every cited `Class.member` anchor resolves against the AST** |

**Production changes:** the Loaded-panel project row's own marker class; `_compose_context_line` /
`_clip_to` / four constants; the `on_resize` recompose. Nothing else.

**24+ counterfactual arms across the increment, 0 survivors** — except where noted in §4.

---

## 3 · The findings that reach forward — do NOT rediscover these

| Finding | Why it still matters |
|---|---|
| **`F-8` — a FIX is where this defect class reproduces. THIRTEEN instances this session.** | Registered P1 in `BACKLOG-PROCESS.md`. **Four of them (10–13) are inside `TC-B79-05`, the node written to CLOSE the class** — it reproduced the class three times before it held. **The counterfactual is the only instrument that caught several of them** |
| **Explanatory prose inside the corpus is INPUT to the check it describes** | Twice, one comment apart: documenting a dead exclusion entry cited it and made it live; documenting a bad anchor example made it a real bad anchor. **Prose inside a scanned corpus must carry no backticked class-qualified names of its own** |
| **A line-oriented sweep cannot see a wrapped phrase** | The sweep that corrected four copies of a wrong figure claimed **zero survivors** and missed a fifth, split across a line break — inside a block headed "Correction". *Reporting a sweep as exhaustive is worse than not sweeping* |
| **A symbol anchor trades staleness for permanent incorrectness** | Registered P2. A stale `file.py:279` fails *visibly*; a wrong symbol lands the reader in a real, plausible method forever. **Execute anchors against the tree** — `TC-B79-05` now does |
| **A figure is only as honest as the corpus it names** | Hit three times: ruff (touched files / `s19_app tests` / `.`), the validator notice count, the B78/B79 node count |
| **`git log -S<name>` reports occurrence-count changes, not region edits** | It returns nothing for a re-point that kept the name. Use `git log -L a,b:file` |
| **A gate invoked through a pipe takes the PIPELINE's exit status** | Cost one 45-minute suite run here (`exit 4`, empty output). Read the exit code from the gate itself |
| **`_CONTEXT_BAR_INSET = 4` and the bar's cached size is STALE mid-resize** | `App.size` is current inside `on_resize`; `#workspace_status_bar.size` is not. This is why the recompose goes through `call_after_refresh` and budgets off the terminal width |

---

## 4 · ⚠️ UNCOMMITTED WORK — commit this first

`tests/test_tui_commandbar.py` carries a hardening of `TC-B79-05` that is **not** in `b7cb966`.
All 5 `-k b79` nodes pass with it. What it adds:

1. **The exclusion set's entries must be CITED.** The first version listed six symbols, three of
   which the corpus never cites — dead entries in a hand-maintained list. **A counterfactual removing
   one came back GREEN**, which is the `_B78_NON_WRITING_CALLS` vacuous-input-set shape a third time.
2. ⚠️ **The correction then oscillated, and this is the durable lesson.** The comment documenting the
   three dead entries **cited one of them in backticks**, which made it cited — so dropping it from
   the set immediately reddened the "must resolve" clause, and rewording the comment made it dead
   again. **The input set was coupled to the prose describing it, in the same file.** *Writing down
   that a symbol is not referenced is itself a reference.* Settled at exactly what the corpus cites in
   negative context, with the comment carrying no backticked class-qualified names of its own.
3. Counterfactual: adding an uncited exclusion → **RED on its own assertion**.

**`TC-B79-05` deliberately does NOT close the class**, and says so: it proves a symbol *resolves*, not
that it is the *right* symbol for its sentence, and it only sees dotted citations. The sixth gate's
blocking finding was a **bare** symbol against a line range — outside its regex by construction.

---

## 5 · Decisions taken without asking — reconstruct them from here

| # | Decision | Why it was mine |
|---|---|---|
| 1 | `AT-B78-14` recorded as a **PIN**, contradicting spec §5.3's "GATE — RED after deletion" | Measured: **zero** test nodes deleted across the batch. No reconciliation was ever owed, so a GATE label would ship a vacuous gate |
| 2 | `TC-B79-01…05` minted in the **B79** namespace | `TC-B78-45` is **taken** (it belongs to `HLR-123`) — checked before allocating |
| 3 | `TC-B78-12`'s payload moved onto the **project name** | It is the one value that provably reaches both surfaces, and it is `LLR-120.4`'s unasserted limb |
| 4 | The budget derives from the **terminal** width, not the bar's | The bar's cached size is stale mid-resize; measured `bar=156` while `App.size.width=80` |

**Operator rulings this session:** authorization re-asked fresh (2026-08-11) · scope Inc-11 only ·
merge precondition **kept, waiver declined** · full suite before every commit · fix H-1/H-2/H-4, carry
M-4 · F-6 as a Lane A carry only · Inc-8/9/10 packets stay absent · gates 5, 6 and 7 each authorised
individually with the criterion unchanged.

---

## 6 · What to do next, in order

1. **Check the seventh gate's verdict.** It ran against `b7cb966` and therefore does **not** include
   the §4 hardening. If it blocked on something already fixed there, say so explicitly rather than
   reporting a clean pass.
2. **Commit the §4 hardening**, full suite first (operator rule).
3. **If the gate passed:** merge under the standing authorization.
   **If it blocked on prose again:** put the closing decision to the operator. The pattern across
   passes 3–7 is that each pass reads prose the last one did not reach, and this session added prose
   every round. That criterion may not converge.
4. **Then Inc-12** — the 29-golden snapshot regen. **Canonical CI only** (ubuntu / py3.11 /
   textual 8.2.8) via the `snapshot-regen` workflow → download the `snapshot-baselines` artifact →
   commit. **Local regen drifts unrelated baselines.** Its own PR.
5. **Vault sync** — `obsidian_synced` is still `false`.

---

## 7 · Open and owed — every one registered, none silent

**Lane A (`BACKLOG-CODE.md`):** 8 tracked `.pyc` files · `LLR-119.2`'s unmeasurable threshold ·
`TC-B78-43`'s project half · the palette's missing `escape` · three painted-Footer-children arms ·
**F-6** (the registry is blind to 108 batch-78/79 nodes — `_FUNC_ID_RE` cannot parse `at_b78_09`) ·
**M-4** (`_apply_unload` clearing `current_a2l_path`, untested on the save path) · **N-7** (degenerate
widths) · **8 sibling `subprocess.run(text=True)` calls** · **the Inc-8/9/10 packet gap**.

**Lane B (`BACKLOG-PROCESS.md`):** **`F-8`** (P1) and **the symbol-anchor control** (P2), both
*registered, not encoded* — encoding needs its own `AskUserQuestion`.

⚠️ **The Inc-8/9/10 gap has a known price, and it is not hypothetical.** `H-3` — a factual error
about **Inc-9's own work**, shipped into a docstring that then contradicted a comment five lines above
it — is the one claim a missing Inc-9 packet let through.

---

## 8 · Process notes for the next session

- **Authorization is per-batch AND per-session. Ask again.** It was re-asked on 2026-08-11 and every
  subsequent gate was authorised individually.
- **Run `python ~/.claude/docs/tools/devflow-validate.py <root>` at every gate** — it is required by
  flow rev12 and did not exist at this batch's Phase 0. Current: 14 BLOCK / 227 NOTICE, and **all 14
  BLOCK belong to batch-01 (May 2026)**, none to batch-78/79.
- **`C-47` changed the file cap:** ≤4 **SOURCE** files, tests uncapped, `.dev-flow/**` outside the
  count. Every commit this session was within it.
- **PowerShell here-strings mangle embedded quotes** — write commit messages to a file and use
  `git commit -F`. Cost two failed commits here.
- **Verify a restored mutation by CONTENT (`git diff`), not by `sha256` of a file Python rewrote** —
  `write_text` translates newlines on Windows and the hash will differ on a correctly restored file.
- **`state.json` is single-batch, last-writer-wins, no owner field.** Re-read it immediately before
  every edit.
