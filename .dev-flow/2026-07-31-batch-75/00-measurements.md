# batch-75 — Phase-0 measurements (executed, not inherited)

> **Every number below was produced by running something against `origin/main` = `232eb0a` in this
> worktree.** batch-74's figures are quoted alongside as a cross-check, never as a substitute (C-39).
> Where mine disagree with the charter's, **mine govern** and the delta is stated.
>
> Probe scripts: `probe_p0.py`, `probe_f4.py` (scratchpad; reproduced verbatim in §7).

---

## 1. RC-1 — base currency

| Check | Result |
|---|---|
| `git fetch origin` | clean |
| `origin/main` tip | `232eb0a4400ce5e48199bee17d4b6e8de562946e` |
| `HEAD` | `232eb0a` |
| merge-base == `origin/main` tip | ✅ **equal** |
| branch | `claude/batch-75-s19-app-a6fd1e` (fresh, cut off the tip) |
| `git status --short` | clean |

## 2. Flow currency (C-45 PULL obligation)

**Aggregate MISMATCH — scoped, and NOT blocking.** Local aggregate `896dcca61cf68d78`
vs manifest `flow_hash 0127a2767ff11c8a` (`~/.claude/docs/FLOW-VERSION.md`, `flow_version 2026.07.28-rev1`).

Per-file derivation says **all 11 control-bearing files are byte-exact** against the manifest:

| File | local SHA256(16) | manifest | match |
|---|---|---|---|
| `commands/dev-flow.md` | `307e5cd9b0eb879a` | `307e5cd9b0eb879a` | ✅ |
| `commands/fast-dev-flow.md` | `327335a180b58478` | `327335a180b58478` | ✅ |
| `commands/dev-flow-init.md` | `78bbd58234aa68f9` | `78bbd58234aa68f9` | ✅ |
| `commands/dev-flow-sync.md` | `4bdcd9840945667d` | `4bdcd9840945667d` | ✅ |
| all 7 `templates/dev-flow/*.md` | — | — | ✅ 7/7 |
| `skills/dev-flow-lessons/SKILL.md` | `01d608bb14069613` | `5c47db86ac2cf4ae` | ❌ |

**Direction: local is AHEAD, the manifest stamp is STALE.** Local `SKILL.md` is **641 lines** vs the
manifest's recorded **620** (+21). `~/.claude/.gitignore:3` is `/*` and `git ls-files skills/` returns
**0 files** — the catalog is untracked here; its canonical home is `jav201/claude-skills`.

**Verdict — the flow's ENFORCEABLE surface is current.** The divergence is confined to the distilled
lessons *catalog*, a reference document; every command and template that carries a control is exact.
Running batch-75 on this flow inherits no solved-problem-as-open. **Carry to Lane B**
(`BACKLOG-PROCESS.md`): re-stamp `FLOW-VERSION.md` for the 641-line catalog, or record why the catalog
is deliberately outside the hash.

## 3. Line numbers — the charter's are STALE in the way it warned

`report_service.py` lives at **`s19_app/tui/services/report_service.py`** (the charter writes it bare;
the `services/` segment is elided throughout). It measures **2592 lines** at `232eb0a`.

| Symbol | charter says | **re-derived** | delta |
|---|---|---|---|
| `emit()` / `budget.consume` | `:2215-2217` | **`:2545-2547`** | +330 |
| `emit(_modifications_lines(...))` | `:2243` | **`:2573`** | +330 |
| `_modified_files_lines` call | `:2242` | **`:2572`** | +330 |
| `_declaration_error_lines` call | `:2244` | **`:2574`** | +330 |
| `_entropy_lines` call | `:2250` | **`:2580`** | +330 |
| `_addendum_lines` call | `:2252` | **`:2582`** | +330 |
| `_applied_regions` def | `:1288` | **`:1618`** | +330 |
| Length inline expression | (no line given) | **`:1356`** and **`:1582`** | — |

Uniform +330. **Cite symbols, not addresses, in every batch-75 artifact.**

## 4. F4 — the load-bearing finding, CONFIRMED and SHARPER than charted

### 4.1 `_ByteBudget` gates exactly ONE section (executed census)

```
GATES      (.fits):   1
    :1785  if not budget.fits(_line_bytes(block)):     <- inside _hexdump_section's block loop
ACCOUNTING (.consume): 2
    :1750  budget.consume(_line_bytes(batch))          <- _hexdump_section.put
    :2547  budget.consume(_line_bytes(batch))          <- generate_project_report.emit
```

**`emit()` accounts and never gates.** `_ByteBudget.fits()` exists (`:680`) and `emit` never calls it.
By the time `consume` runs at `:2547`, the producer passed to it at `:2573` has been fully evaluated.
So *"charge the tables to `_ByteBudget`"* — which `BACKLOG-CODE.md` recommends twice — closes
**nothing**, on either axis. ✅ Charter premise **TRUE**.

**The code already says so.** `report_service.py:89`: *"``_ByteBudget`` is consumed at hexdump-block
granularity only, so the declaration-error section sits OUTSIDE the whole-document accounting."* The
docstring was honest; the backlog's recommendation was the false part.

### 4.2 Producers on the ungated path

Six emissions bypass any gate. Two (`_modifications_lines`, `_checklist_lines`) are row-capped by
batch-74's `MAX_REPORT_ROWS_PER_VARIANT = 200`; **cardinality caps are not byte caps**.

| Producer | call site | own cap | byte-gated? |
|---|---|---|---|
| `_modified_files_lines` | `:2572` | none | ❌ |
| `_modifications_lines` | `:2573` | rows (200, batch-74) | ❌ |
| `_declaration_error_lines` | `:2574` | issues (200) | ❌ |
| `_checklist_lines` | `:2575` | rows (200, batch-74) | ❌ |
| `_hexdump_section` | `:2576` | regions (128) + **bytes** | ✅ **the only one** |
| `_entropy_lines` | `:2580` | none | ❌ |
| `_addendum_lines` | `:2582` | hits/class/region (200) | ❌ |
| `## Truncation appendix` | `:2584` | none | ❌ |

### 4.3 NEW, and it is why a row cap cannot be a byte bound — `md_safe`'s `limit` bounds the INPUT

```
md_safe('\'*600, limit=500) -> len(emitted) = 1013     # expansion factor 2.03x
```

**Every per-cell "cap" in this module caps input characters, not emitted bytes**, and markdown escaping
can double them. This is not in the charter. It means any byte bound written against
`REPORT_CELL_CHARS`/`limit=` arithmetic is wrong by up to 2.03× unless it measures the emitted form —
the project's own C-42 lesson ("assert the EMITTED form"), reappearing on the sizing axis.

### 4.4 Document floor — re-derived, and it DISAGREES with the charter

`_declaration_error_lines` at its 200-issue cap, worst-case in-domain fields
(`message` 500, `symbol`/`code` 512, address present):

| scenario | measured B/variant |
|---|---|
| benign (short fields) | 14,425 |
| 500-char msg + 512 symbol/code | **311,625** |

| | charter | **re-derived** | delta |
|---|---|---|---|
| B/variant | 315,912 | **311,625** | −4,287 (−1.4%) |
| floor at V=1 | 1.15× | **1.15×** | — |
| floor at V=10 | 2.51× | **2.49×** | −0.02 |
| floor at V=100 | 16.06× | **15.86×** | −0.20 |

Floor as `REPORT_MAX_TOTAL_BYTES + V × 311,625`:

| V | floor (B) | × budget |
|---:|---:|---:|
| 1 | 2,408,777 | 1.15× |
| 2 | 2,720,402 | 1.30× |
| 10 | 5,213,402 | 2.49× |
| 100 | 33,259,652 | 15.86× |
| 1000 | 313,722,152 | 149.59× |

The shape holds; the charter's figures run ~1.4% high. **Use the re-derived ones.** The gate at
`:1785` can only ever remove *hexdump blocks* — it cannot remove any of this.

### 4.5 An over-claim of MY OWN, caught before it reached the spec — recorded deliberately

I measured `related_artifacts` as an uncapped **cardinality** axis: at 100 elements × 512 chars,
`_declaration_error_lines` costs **10,573,225 B/variant = 5.04× the whole document budget** from one
variant — 34× the headline figure. **It is NOT wire-reachable and I am striking it.** Every
construction site in shipped code passes a short literal list (`validation/engine.py:96,108,134,146,171,182,193`
→ `["mac","s19"]`, `["a2l","mac","s19"]`); the field is engine-generated, not document-derived. It is
constructor-domain hardening — the *same* class as D2's original headline, and the same trap the
charter warns about. Recorded so the next reader does not re-discover it as a threat.

## 5. F4 companion — V and F

`R-TUI-101` caps rows **per variant summed across check files**, which bounds `F × CAP` rows. It does
**not** bound the structural lines each check file emits regardless of its row count, and neither `V`
(variant count) nor `F` (check files per variant) is capped anywhere. ⏳ **The "7 structural lines"
figure is UNVERIFIED at this point** — I have not yet counted them against `_checklist_lines`. It is
carried into Phase 1 as `assumed — measure`, not asserted.

## 6. D2 — the charter's correction to the backlog headline is CONFIRMED

```
sys.get_int_max_str_digits()          = 4300
int('0x'+'F'*100000,16)               parses OK, bit_length = 400000
_format_address(huge)                 -> OK, len(rendered) = 45      <- renders FINE
f-string on Length 10**4298           -> OK (len 4302)
f-string on Length 10**4300           -> ValueError: Exceeds the limit (4300 digits) ...
```

| Proposition | Verdict |
|---|---|
| *"a schema-legal **address** denies the report"* (backlog headline) | ❌ **FALSE** — renders in 45 chars |
| the `raise` keys on **`Length`**'s decimal digits | ✅ **TRUE** |
| `_format_length` exists | ❌ **FALSE** — **0 hits** across `s19_app/` + `tests/`; must be CREATED |
| the two sites are inline `{entry.address_end - entry.address_start}` | ✅ **TRUE** — `:1356`, `:1582` |
| the boundary literal is not stable | ✅ **TRUE** — derives from `sys.get_int_max_str_digits()`, = 4300 here |
| the two sites take disjoint inputs | ✅ **TRUE** — `change_summaries[].entries` vs `check_results[].entries` |

`_format_address` already caps at `REPORT_ADDRESS_HEX_DIGITS = 16` + a truncation cue
(`REPORT_ADDRESS_TRUNCATION_CUE_FMT`, `REPORT_ADDRESS_MAX_ELIDED_DIGITS`) — that is batch-74's
shipped `Address` work, and it is **the template the `Length` cell should follow**.

### 6.1 The `app.py` re-attribution site

`app.py:4164` — `self.call_from_thread(self.set_status, f"Report rejected: {exc}")`, inside
`except ValueError as exc:`. The `try` spans both `plan_variant_executions` **and**
`generate_project_report`, so an internal CPython `ValueError: Exceeds the limit (4300 digits)`
surfaces to the operator in the **operator-input-rejection** branch, worded as though their input
were invalid. Fails **closed** (no partial file) — any fix must preserve that.

## 7. Constants actually on disk (no phantoms — C-36)

| Constant | value | note |
|---|---|---|
| `REPORT_MAX_TOTAL_BYTES` | 2,097,152 | `:334` |
| `MAX_REPORT_ROWS_PER_VARIANT` | 200 | `:122` — batch-74's shipped cap |
| `MAX_REPORT_ISSUES_PER_VARIANT` | 200 | `:98` |
| `REPORT_MAX_REGIONS_PER_VARIANT` | 128 | `:85` |
| `REPORT_CELL_CHARS` | 512 | `:202` |
| `REPORT_ADDRESS_HEX_DIGITS` | 16 | `:261` |
| `REPORT_ADDRESS_MAX_ELIDED_DIGITS` | `READ_SIZE_CAP_BYTES - 16` | `:296` |
| `MF_ENTRY_COUNT_CEILING` | 100,000 | `changes/io.py:226` |
| `MF_RUN_LENGTH_CEILING` | 1,048,576 | `changes/io.py:232` |
| `MAX_ROWS_PER_VARIANT` | **ABSENT** | ← the name is `MAX_REPORT_ROWS_PER_VARIANT` |

## 8. Id ranges — re-derived independently

```
AT high-water on main = AT-249      TC high-water on main = TC-551
```
Matches the reservation. **batch-75 uses AT-250…AT-279 and TC-552…TC-599 only.**

### 8.1 The namespace I did NOT derive, and it cost a Phase-2 blocker

**`HLR`/`LLR` are a SEPARATE counter from `R-TUI-`, and revision 1 assumed they tracked it.** Both
Phase-2 lanes found this independently. Executed at Phase 2:

```
grep -rhoE "HLR-[0-9]{3}" s19_app/ REQUIREMENTS.md              -> high-water HLR-106
grep -rhoE "HLR-[0-9]{3}" ... .dev-flow/ tests/ (excl. batch-75) -> high-water HLR-107
same for LLR                                                     -> LLR-106 / LLR-107
```

| id | already means | cited at |
|---|---|---|
| `LLR-102.1` | `document_bytes` is the single encoder seam (batch-63) | **`report_service.py:622`** |
| `LLR-102.2` | `_line_bytes` is partition-invariant; redefining it is **prohibited** | **`report_service.py:608`** |
| `HLR-102`, `LLR-102.3/.4` | batch-63 / `R-TUI-097` | `REQUIREMENTS.md:4945` |
| `HLR-107`, `LLR-107.x` | **batch-74's split-out `Length` draft** — review artifacts only, never shipped | `.dev-flow/2026-07-31-batch-74/02-review.md` |

`LLR-102.4` was the sharpest collision: it already means **golden neutrality**, and batch-75's golden PIN
sat beside it.

**Resolution: `HLR-108`/`109`/`110`, `LLR-108.x`/`109.x`/`110.x`.** `HLR-107` is **not** reused despite
being batch-75's own inherited `Length` draft — reusing an id whose draft content differs is the very
defect this section records.

> **Lesson for the next batch: derive EVERY id namespace the batch will write, not only the one the
> charter names.** The operator's instruction covered `AT`/`TC` and I derived exactly those. An
> instruction to derive one namespace is not a statement that the others are safe.
