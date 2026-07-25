# PLAN — s19_app — batch-62: `report_service` markdown escaping

> Living compendium. Updated at every gate and significant checkpoint.

## Where we are — ⏸ PAUSED AT A CLEAN CHECKPOINT (2026-07-25, operator-agreed)

**Phase 0 CLOSED (`approve`). Phase 1 CLOSED (`approve`). Phase 2 GATE FAILED → `iterate-to-refine`, iteration 1 of 3.**

### RESUME HERE (read in this order, then act)

1. **`02-review.md`** — the consolidated verdict and **the fold list**. This is the entry point; it names every blocker with evidence and says what survived.
2. `01-requirements.md` — the canonical registry + rulings D-1…D-9. **Four rulings are measured WRONG** (E-1…E-4 in `02-review.md`) and must be re-issued, not patched over.
3. The three source reviews (`02-review-architect.md`, `02-review-qa.md`, `02-review-security.md`) only if a specific finding needs its full evidence.

**The task on resume is the Phase-1 refinement fold**, not re-derivation. Do NOT re-run Phase 0/1 or re-dispatch the reviewers — the expensive work is done and on disk. Discharge the 14 blockers + ~20 majors listed in `02-review.md`, record each as a **§6.5 Before/After amendment** (never a silent edit of a locked requirement), then re-run Phase 2.

**Do not re-litigate what survived:** D-4 (leaf module), D-5's `_MD_ESCAPE` ordering, D-6, R-1/Mode B sufficiency, the field inventory (independently re-derived complete), and the negative controls. Two reviewers attacked these and could not refute them.

**C-21 already fired** — the AT set changed (`AT-163` is new), so the increment cut in `02-review.md` §"Increment cut" is the re-derived one. Use it.

### State at pause

- Branch `claude/batch-62-report-escaping` @ base `8d3c504` (RC-1 PASS, merge-base == `origin/main` tip at cut).
- **Zero production code written.** Only `.dev-flow/2026-07-25-batch-62/` artifacts exist. Nothing to un-do.
- `state.json`: `current_phase: 2`, `phase_status: awaiting-gate`, `iterations_per_phase["2"]: 1`.
- No PR open for batch-62.
- Authorization: AUTONOMOUS + self-merge — **but per `feedback_standing_auth_per_batch` this is per-BATCH and the resuming session must re-confirm it at kickoff.** Do not assume it carries.

### Why we paused here (recorded so the next session does not repeat it)

Token budget for the session was exceeded (engineering rule 6 — surfaced, not silently overrun): this session ran batch-61 end-to-end, two closeout PRs, the vault sync, and batch-62 phases 0–2. The remaining fold is large and touches the AT/TC registry, the assertion helper, the payload set and four of my own rulings. Executing it on a nearly-exhausted context risks exactly the failure these reviews just caught — sampling once what is emitted twice.

## Objective

Project reports embed file-derived text with no grammar-level escaping. Close that, at the composer (the layer that travels with the `.md` file), for every file-derived field — not one field, not one row.

## Authorization (per-batch, NEVER carried)

- **Date:** 2026-07-25. **Operator phrasing, verbatim:** *"arranca /dev-flow con report_service escaping, autónomo con self-merge"*.
- **Autonomy:** AUTONOMOUS end-to-end + **SELF-MERGE**. Gates self-approved with a named Coverage/Certainty/Evidence axis; packets presented in-conversation.
- **Merge remains gated:** PR open + CI green, then a final independent `qa-reviewer` **and** `security-reviewer` pass over the whole diff vs `main`; 0-HIGH authorizes merge; a HIGH blocks and returns to the operator.
- **Decision-recording:** ACK — every un-asked decision lands in this PLAN's decision log, `state.json.decisions_log`, `05-postmortem.md`, and the vault at sync.

## RC-1 (base currency)

**PASS @ `8d3c504`** (2026-07-25). Branch `claude/batch-62-report-escaping` cut off `origin/main`; merge-base == tip, verified. Chain consumed this session: #133 `4cac228` (batch-61 snapshot regen) → #134 `bf2004e` (closeout) → #135 `8d3c504` (vault-sync record).

## Ground truth — measured at Phase 0, not assumed

The backlog said "no escaping at all". Measured reality is more nuanced **and worse**:

1. **Partial escaping exists.** Batch-39 added `_md_table_cell` for `linkage_symbol` (`tests/test_report_symbol_escape.py`). It escapes `|`, `\`, control chars — **table shape, not grammar** — and covers **one field**.
2. **The hardened viewer is not sufficient.** Batch-60 set `MarkdownIt("gfm-like", {"linkify": False, "html": False})` (`screens.py:112`) and its own docstring names project reports as a carried follow-up. Token-stream probe through **that** parser:

   | Payload | Token | Verdict |
   |---|---|---|
   | `~~REVOKED~~` | `s_open` | renders |
   | `**fake**` | `strong_open` | renders |
   | `[click](http://x)` | `link_open` | **live link** — linkify OFF kills only *bare* URLs |
   | bare `http://evil.tld/x` | — | mitigated |
   | `<b>x</b>` | — | mitigated |

3. **Unescaped fields, executed probe through `generate_project_report`:** `project_name` → `# Project report: proj ~~REVOKED~~ **fake**`; `variant_id` → raw in table cells and in a `## Variant:` heading; a `|` in `variant_id` → **7 structural pipes vs 5** (two phantom columns).

## Stories (Phase 0 — all READY)

- **US-062-1** — report text renders literally **in the app viewer**; no `s_open`/`strong_open`/`em_open`/`link_open` originates from file-derived text.
- **US-062-2** — the **exported `.md`** carries no live constructs when parsed by a DEFAULT `gfm-like` parser (linkify + html ON), i.e. the file is safe once it leaves the app. (C-12 output-then-consume.)
- **US-062-3** — table rows keep their **column shape** regardless of file-derived content.

## Open design question (Phase 1/2 resolves by execution, not analogy)

`_md_safe` is private to `flow_report_service`. Reuse across services is a smell; promoting it to a shared module touches two generators. Batch-60 ruled "create new" **then** because `diff_report_service._md_cell` targeted a different, un-audited sink — that reasoning does **not** transfer here (same sink). Decide by probing, and record the ruling.

## Controls prioritized this batch

- **C-31 (input-set-is-an-oracle)** — derive the payload set from the grammar/code. Batch-60's TC-004 had 11 payloads and **zero** fuzzy-linkify cases (`www.x`, `x.com`, `a@b`, IDN); the input set was the vacuous oracle.
- **Assert-the-emitted-encoding** (candidate, 3rd occurrence) — assert on the real parser's **token stream**, never a character list or the rendered form.
- **C-35 (draft-time execution probe)** — already applied at Phase 0; keep applying.
- **C-26 (touched-symbol reverse census)** — batch-39 fixed one field and never swept the siblings. Reverse-grep every touched symbol across `tests/`.
- **Budget/caps pinned** — batch-60's byte budget was entirely unpinned because the fixture sat 2.8× under the limit. Any cap gets a test that goes RED when the guard is deleted.

## Constraints

Engine-frozen set OFF-LIMITS (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) plus `_ENGINE_TEST_FILES` — run **both** guards (C-27). ≤5 files per increment. Every behavioral change ships a black-box `AT-NNN` shown RED pre-fix.

## Out of scope (carried, not dropped)

- `report_service` renders no `diagnostics` (batch-60 carry) — a functionality gap, not security; would dilute this batch.
- Killing `~~` at the parser: it is a gfm-like plugin, not an option. The composer is the correct layer.

## Decision log

| # | Phase | Decision | Rationale |
|---|---|---|---|
| 1 | 0 | Route confirmed as full `/dev-flow` | Security-relevant, derivable requirements, real black-box ATs — unlike batch-61, which was correctly routed to `/fast-dev-flow`. |
| 2 | 0 | 3 stories READY; `diagnostics` OUT | Each story carries a defect measured RED on the current tree. `diagnostics` is a distinct concern. |
| 3 | 0 | RC-1 deferred until #135 merged | Cutting earlier would have derived against a tree one merge stale. |

## Test ledger

| Stage | Base | −D | +A | Post |
|---|---|---|---|---|
| Phase 0 | TBD at Inc-1 | — | — | — |
