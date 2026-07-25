# PLAN — s19_app — batch-62: `report_service` markdown escaping

> Living compendium. Updated at every gate and significant checkpoint.

## Where we are — Phase-1 fold DONE, Phase-2 re-gate PASSED (2026-07-25)

**Phase 0 CLOSED. Phase 1 CLOSED → re-opened for `iterate-to-refine` iteration 1 → CLOSED again.
Phase 2 re-gate: PASS. Next action: Phase 3, Inc-1.**

### What the fold did

`01-requirements.md` is **revision 2**. It discharges all 14 blockers and ~20 majors from
`02-review.md` through a **§6.5 amendment log of 40 entries (A-01…A-40)**, each with explicit
Before → After. No locked requirement was silently edited. §11 is the blocker → amendment matrix.

**Every threshold this fold states was executed, not predicted** — that is the whole point of the
iteration, since three of the four gate failures were predictions promoted to acceptance criteria:

| Threshold | Measured result |
|---|---|
| Golden drift (`at055b`) | **exactly lines 14, 15, 51** — and the enlarged escape set adds **zero** further drift |
| Flow-report blast radius of the escape-set change | **1 test of 52** (`test_flow_report_service.py:415`), **0 goldens moved** — the security review predicted the goldens would move; they do not |
| `<in-memory document>` → `(in-memory document)` | **zero** test/golden impact — the literal exists only at `report_service.py:894`, `:1093` |
| `&` at `MD_ESCAPE` index 1 | backslash-first ordering preserved (`x\&y` → `x\\\&y`); `\&vert;` renders literally, live tokens `[]` |
| U+FFFD as the Mode-B loss marker | category `So`, survives the C0 filter, inert bare in both grammars |
| A-16 residue predicate inside `canonical_report_bytes` | all **3** existing goldens pass it **today** — breaks no consumer on day one |

**The fold caught one error in itself** (§7 C-6): A-26 first named `Cc`/`Cf` and claimed to close the
surviving-character list — **U+2028 is `Zl`** and passes both that filter and the newline collapse.
Corrected to `Cc`/`Cf`/`Zl`/`Zp` with U+2028 named in the counterfactual. Fourth instance of this
batch's recurring class, and it surfaced only because the fold's own thresholds were executed.

### Two findings resolved rather than annotated

- **The oracle was blind.** `&` unescaped meant `SYM_A&vert;PASSED` renders a forged table fragment
  while every token stays `text`, so `assert_field_inert` scored it GREEN. Closed **structurally in
  both directions**: A-10 escapes `&` so the attack fails, and A-20's fidelity clause gives the
  oracle a way to fail on the class. Either fix alone leaves one direction open.
- **The lost severity criterion.** batch-60 raised absolute-path exposure LOW → MAJOR on
  shareability grounds; batch-62 never mentioned `_redact_absolute_paths`. **Operator-ruled
  (D-11/A-24): partial fold** — redaction applied to `issue.message`, Mode-B path fields stay raw by
  design (CN-6 depends on the raw bytes), the divergence recorded as accepted, and RR-2 carried to
  `BACKLOG.md` at MAJOR.

### State

- Branch `claude/batch-62-report-escaping` @ base `8d3c504`. **Still zero production code.**
- Authorization re-confirmed at this session's kickoff: **AUTONOMOUS + self-merge** (per-batch, not
  inherited). Operator also ruled D-11 directly.
- No PR open for batch-62.

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
| 4 | 1 (iter 1) | **Mode A escapes the backtick; Mode B declared lossy with a U+FFFD marker** (D-12) | Removal silently falsifies an audit record — `` FOO`BAR `` was written as `FOOBAR`, a different symbol. The "context-free" premise died when Mode B was introduced. **Measured** cost: 1 test, 0 goldens. |
| 5 | 1 (iter 1) | **`&` added to `MD_ESCAPE`** + the oracle gains a fidelity clause (D-13, D-14) | Both were needed. Escaping `&` kills the attack; the fidelity clause gives the oracle a way to **fail** on the class. Either alone leaves one direction open. |
| 6 | 1 (iter 1) | **Operator ruling D-11** — redact `issue.message`, Mode-B paths stay raw | Closes the severity criterion lost between batches, in writing, in both directions. RR-2 carried to `BACKLOG.md` at MAJOR. |
| 7 | 1 (iter 1) | **`$`/`:`/`=` escape extension DECLINED** (D-22) | `:` appears in every address-bearing string; the constructs are outside the modelled grammar and are carried as RR-1 instead. Recorded so it is a decision, not an omission. |
| 8 | 2 (iter 2) | **Re-gate self-approved; no independent reviewer re-dispatched** | Operator instruction. The weakness is stated in `02-review.md`, and the independent qa + security pass at the **merge** gate is unchanged. |

## Test ledger

| Stage | Base | −D | +A | Post |
|---|---|---|---|---|
| Phase 0 | TBD at Inc-1 | — | — | — |
