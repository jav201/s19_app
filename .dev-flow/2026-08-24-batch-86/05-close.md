# 05 — Close · batch-86 · IFC surface #2 (`screen_workspace`), clean start

**Status: CLOSED COMPLETE.** First batch run end-to-end under flow rev42–rev44 (Atlas + V20 ·
selector taxonomy · coherence V21–V23), autonomous with no-merge authorization. Every station
gated on evidence; one P2 iteration (by design of the review, not by drift).

## 1 · What changed

Zero product code (source-scope diff empty vs merge-base `a112eeb`, verified at every gate).
What landed: the corpus's SECOND IFC record (`screen_workspace`, 30 outputs, pair-based
census under the M-10 search-width guard, `SURFACE:` field), the canon mirror `R-TUI-114`
in `REQUIREMENTS.md` (12 ids, G6 12/12), and the Atlas regenerated at every gate (V20 green
throughout, census 2).

**Headline result: the pilot's `PARENT` is balanced — V12's `:334` "NOT checked" notice is
GONE, replaced by a real verdict** (M5's copy-run shows the BLOCK the rule now can produce).
The honest recursion is recorded: `workspace_body` is the next undeclared PARENT.

## 2 · New controls, and which of C-45's four landings happened

**One new control candidate, NOT yet encoded — registered as a lane-B carry, deliberately:**
*an evidence transcript is corpus input* (Inc-1 review F2: the packet quoted the RED-arm's
corrupted id and range shorthand; the Atlas id-scanner adopted three phantom ids; a
regeneration would have baked a mutation artifact into the committed derived plane). Landings:
command ❌ · template ❌ · catalog ❌ · pushed ❌ — the batch discharged the instance (packet
fixed, fixpoint proven) and the RULE is owed to the flow at rev45; carrying it half-encoded
is stated here so it cannot masquerade as done.

## 3 · C-44 reconciliation

| File set | State |
|---|---|
| batch-86 artifacts (01/01b/02/00-measurements/03-increments/04/05/PLAN/state.json) | ✅ committed on `claude/batch-82-lane-a-scoping` |
| `REQUIREMENTS.md` (R-TUI-114) · `.dev-flow/_derived/ATLAS-*` | ✅ committed (derived plane V20-green) |
| `BACKLOG-CODE.md` / `BACKLOG-PROCESS.md` | ✅ reconciled at this close (see §4) |
| mutation copies (mktemp) | 🗑️ discarded by protocol; live tree porcelain-clean after each |
| orchestrator probe outputs (`$CLAUDE_JOB_DIR/tmp/*`) | 🗑️ job-scoped temp; the figures they establish are transcribed in 04-validation.md |

## 4 · Backlog (reconciled at close)

**Lane A gains:** the 6 order-dependent flaky suite nodes (diagnosed pre-existing, each
passes isolated on pristine `main`; ids + repro in `04-validation.md`) · `workspace_body` =
next undeclared PARENT (surface #3 candidate by the same V12-liveness criterion) · the
batch-51 matrix's pre-existing phantom range (dotted-range tokens of the zero-padded -086
LLR family in its `traceability-matrix.md:115` — tokens not reproduced here: they are
scannable, the very defect being carried) · V22 canon-mirror packing (two ids per line — per-id greps
stay primary). **Lane B gains:** the evidence-transcript control candidate (§2) · the P0
finding that a scaffolded batch without its own `01-requirements.md` is judged on batch-01's
frozen doc (17 V4 blocks measured — the §2.6 artifact must be born with the batch).

## 5 · Metrics

| key | value |
|---|---|
| stations | P0 · P1 · P2 (×2) · P3 (1 increment, fix-first ×1) · P4 · P5 — all gated, all green |
| review findings | P2: 1 blocker + 6 major + 7 minor (14/14 discharged, re-measured) · Inc-1: 2 HIGH + 1 MED + 1 LOW (4/4) |
| kill mutations | 5 executed on copies (M-9 ×2 in-memory + M4/M5/M7 full-path); M7 refuted its own prediction (+2 not +1) and repaired it with a surgical arm |
| validator | `0 block · 254 notice · 15 n/a` at close; V20 `atlas current (4 files, census 2)` at every gate |
| suite | 2702 passed · 6 failed (pre-existing order-dependent, dispositioned) · 3 skipped · 3 xfailed / 2714 selected — one complete 39:49 run, C-19/C-25 honored |
| source files changed | **0** (pin held at every gate) |
| V22 seeding delta | 288 → **276** (12 ids mirrored; one BELOW the 277 batch-open baseline) |

### Per-surface cost — figure #6 and the dispersion note (closes HLR-86.3 / LLR-86.8)

**Figure 6 — authoring effort:** batch wall-span **1h15m** (P0 scaffold `257922c` 05:02 →
P4 close `c0c1d27` 06:17), ~7 agent dispatches (2 authoring, 3 review, 1 fix cycle each for
P1/P3). Pilot analogue: one full session, two BLOCK review rounds, **closed unfinished** —
so the pilot's effort figure is right-censored, not comparable as a number.

**Dispersion (n=2), per figure — ranges, never means:** OUTPUTS 5→30 (×6) · consumer
entries 15→91 (×6.1) · dependant files 6→15 (×2.5) · greppable addresses 5/5→29/30 ·
stray pairs 4→36 (×9). **Non-extrapolation caveat, restated:** two points bound nothing —
the workspace is plausibly the LARGEST surface (it composes three panes); the 25 remaining
surfaces are not sized by these ranges, and the surface count itself (27 by `compose()`,
31 by widget-base) is still the unmeasured figure batch-85 declared. What n=2 does
establish: the per-surface cost is **not constant** (×2.5–×9 spread), so the retrofit plan
must budget per surface measured, not per surface assumed.

## 6 · The trial's verdict on the flow itself (what batch-86 was FOR)

The rev42–44 machinery earned its keep in one batch: V20 caught every corpus drift including
one the increment's own packet caused; the UNPARSED census caught a live absorption during
authoring; V12's new verdict is the batch's product; V22 measured the seeding debt shrinking;
the review layer caught a C-55 emptiness, two false evidence citations, and a mutation
artifact one regeneration away from being permanent. Two orchestrator probe defects (a
tail-pipe that destroyed run evidence, an ANSI-blind grep) were caught by the same
discipline the flow teaches — both are the C-53 probe family. **The flow works; its cost
for a spec-only batch was ~1h15m wall.**
