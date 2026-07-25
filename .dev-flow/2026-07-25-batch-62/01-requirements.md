# 01 — Requirements (canonical registry + reconciliation) — batch-62

> **This file is the authoritative registry.** The full derivations live in two source artifacts and are not duplicated here:
> - `01-requirements-architect.md` — HLR/LLR derivation, field inventory, design ruling (authoritative for the **spec**).
> - `01b-qa-catalog.md` — validation methods, payload-set derivation, assertion helper (authoritative for **how each requirement is proven**).
>
> Where the two collide, this file rules. Base ref `8d3c504`. Language: English.

## 0. Orchestrator reconciliation (rulings made under the autonomy grant)

The two Phase-1 agents ran in parallel and **converged independently** on the two load-bearing facts — that table-cell acceptance must assert *positional cell content* (not pipe/column counts), and that path-shaped fields cannot take the same escaping as prose. Independent convergence on both is the strongest signal this batch has. They also **collided on identifiers**, which is resolved here rather than averaged.

| # | Ruling | Evidence / rationale |
|---|---|---|
| **D-1** | **US ids renamed `US-062-*` → `US-B62-1 / -2 / -3`.** | Collision CONFIRMED on disk: `US-062` is already taken by batch-37 (`REQUIREMENTS.md:3686`, `:3749`, entropy-viewer paging). A C-26 reverse census grepping `US-062` would hit both and silently mis-attribute. |
| **D-2** | **AT registry = the architect's `AT-157…162` (6).** qa's `AT-157/158/159` map onto the same three stories; the architect's `AT-160/161/162` are additional surface (incl. the hexdump-fence regression). | Range verified FREE (max AT in source = `AT-129`). Semantic 1:1 match of 157/158/159 to be confirmed at Phase 2. |
| **D-3** | **TC registry = the architect's `TC-376…387` (12). qa's additional cases renumber to `TC-388+`.** | Range verified FREE (max TC in source = `TC-361`; the earlier `TC-396/397/398` sighting came from `.dev-flow/` docs and `.pyc`, not the source registry — a false positive from my own over-broad grep). |
| **D-4** | **Design ruling ADOPTED: a new leaf module `s19_app/tui/services/markdown_safety.py` exporting `md_safe` (Mode A) + `md_code` (Mode B).** | Decisive and non-obvious: `flow_report_service.py:63` and `diff_report_service.py:97` both import **from** `report_service` — `report_service` is the base of the service import DAG, so importing `_md_safe` back into it is a **hard circular import**. Neither option I framed at Phase 0 was correct; the measured answer is a third. All three service files verified outside both frozen guards. |
| **D-5** | **The `_md_table_cell` call (`report_service.py:978`) and its deferred circular-import import (`:974-976`) are REMOVED.** | `_MD_ESCAPE` already contains `|` at index 1 with `\` at index 0 — the exact ordering property `_md_table_cell` existed to provide. Chaining measured double-escaping: `a|b` → `a\\\|b` (a literal backslash renders). Table-shape is therefore **not** a separate concern under Mode A. |
| **D-6** | **Mode B is forbidden in table cells** (static guard, LLR-097.2). | Measured: a raw `|` inside a code span still splits the cell. Mode B protects grammar, not table structure. |
| **D-7** | **Golden re-capture is IN scope, with double-proof.** | `md_safe` is **not** a byte no-op (`.`, `/`, `_`, `@` are ubiquitous in paths/codes): 5/12 values drift in `tests/goldens/batch35/at055b-project-report.md`. Predicted drift **exactly 2 lines** — that prediction is itself the acceptance (C-22-style per-cell prediction); an unpredicted 3rd line blocks. |
| **D-8** | **`diff_report_service._md_cell` / `_md_table_cell` DEFERRED**, carried explicitly to the backlog. | Own goldens, own un-audited HTML sink. Fixing them here would widen a security batch into an untested surface. Deferred ≠ dropped. |
| **D-9** | **`diagnostics` rendering stays OUT** (batch-60 carry). | Functionality gap, not a security one. |

## 1. Stories (Phase-0 READY, renamed per D-1)

- **US-B62-1** — file-derived text renders **literally in the app viewer**: no `s_open` / `strong_open` / `em_open` / `link_open` originates from it.
- **US-B62-2** — the **exported `.md`** is inert under a **default** `gfm-like` reader (linkify + html ON) — the file is safe once it leaves the app.
- **US-B62-3** — table rows preserve **positional cell content** regardless of file-derived input.

## 2. Derived structure

**5 HLR** (`HLR-095…099`, EARS, `shall`-only — zero `should` in any normative statement, verified) · **13 LLR** · **6 AT** (`AT-157…162`) · **TC-376…387** + qa's extended cases at `TC-388+`. Both traceability chains present.

## 3. Blockers carried into Phase 2 (each needs an explicit ruling)

1. **`_MD_ESCAPE` leaks block starters** — no `-`, `+`, `=`. Measured through `_md_safe`: `- item` → `bullet_list_open`, `---` → `hr`. It is safe in `flow_report_service` **only because that module collapses newlines first** — a load-bearing coupling that is currently **unpinned**. Pin it, or fix the escape set.
2. **Code-span breakout at `report_service.py:901`** — the value sits inside backticks; ``a` **PWNED** `b`` measured emitting `code_inline`, `strong_open`, `code_inline`. No batch has covered this class.
3. **`md_safe` is not idempotent** (`a.s19` → `a\.s19` → `a\\\.s19`) — exactly-once application becomes a design obligation with a negative control.
4. **Truncation defect, found at draft time:** `_DEFAULT_MESSAGE_MAX_LENGTH = 500` (`validation/model.py:22`) vs `MAX_REPORT_CELL_CHARS = 240` — using the default limit would silently truncate a 500-char issue message. Now normative.
5. **Golden canonicaliser (R-1, highest risk):** `canonical_report_bytes` (`tests/conftest.py:1009-1016`) substitutes the **raw** `str(run_root)`; escaping a path before it reaches the file makes that substitution miss and **leaks an absolute operator path into the golden**. Mode B is the mitigation; Phase 3 must assert `RUN_ROOT_TOKEN` still appears and no drive letter survives.

## 4. Field inventory — 33 sites

**24 need escaping** (21 Mode A + 3 Mode B) · 7 trusted · 2 out-of-scope-but-pinned. The exhaustive grep surfaced **4 fields the kickoff hint did not name** — `issue.message` (`:1026`, parsed file text, the highest-risk field, ctl-scrubbed only), `issue.related_artifacts` (`:1032`), the filter file name (`:729`), and the **hexdump ASCII gutter** (`:1197-1200`; `hexview.py:355` emits a raw backtick for byte `0x60`). That the hint's field list was incomplete is the point of C-31: **the field set is itself an oracle**, and hand-listing it would have shipped four holes.

Hexdump fence proven **unbreakable** rather than silently excluded: an all-`0x60` image yields exactly **1 `fence` token** in both grammars, because every gutter line carries the `0x%08X` prefix (`hexview.py:356`). Scope exclusion ships **with** a regression test (`AT-161`).

## 5. Payload set (qa-authoritative)

**30 active + 2 negative controls, derived from the parser's own rule table** — not hand-listed. Guarded five ways: G-1 total rule coverage vs `get_active_rules()`; G-2 vs `linkify._schemas` + `_opts`; G-3 pinned floor ≥ 30; **G-4 non-vacuity** (every payload must produce a live token on the raw string); G-5 negative controls stay inert.

G-4 earned its place immediately: it caught that **`evil.tld` is not a real TLD**, so fuzzy linkify never fires on it — a payload set built on `.tld` domains is vacuous against exactly the class batch-60 missed. My own Phase-0 probe used `evil.tld`. The guard, not the reviewer, caught it.

## 6. Assertion discipline

`assert_field_inert(md, text, marker, payload)` walks `md.parse()` including `.children`. **Provenance-based, never baseline-subtraction**: a benign report already emits `heading_open`, `bullet_list_open`, `strong_open`, so subtracting a baseline is blind — measured, an injected `# PWNED` heading reports *"no change"* under subtraction. A second clause requires the payload characters to still be **present**, forbidding "sanitise by deleting". No character-membership checks; no `md.render()`.

## 7. Correction to Phase-0 evidence

Phase 0 recorded that a raw `|` in `variant_id` "opens two phantom columns" (5 → 7 structural pipes). The pipe count was right; **the consequence was wrong**. markdown-it caps a row at the header width, so nothing grows — data is **silently dropped**: `['BENIGN','a.s19','s19','yes']` → `['EVIL','INJECTED','COL','a.s19']`, losing `file_type` and the active flag, with the token cell count unchanged at 4. A pipe-count or column-count assertion is therefore **GREEN on this input**, which also means batch-39's surviving guard (`structural == 7`, `tests/test_report_symbol_escape.py:151`) is **blind to this class**. `AT-159` asserts cell contents verbatim.

## 8. Test targets (C-27)

New: `tests/test_report_markup_safety.py`, `tests/test_report_field_census.py`. Extended: `tests/test_report_symbol_escape.py` (its hostile arm asserts removed `_md_table_cell` output; the benign no-op arm still holds). Frozen files (`_ENGINE_TEST_FILES`, `tests/test_tui_directionb.py:5443-5454`) — no collision.
