# Functionality — s19_app — Batch 2026-06-10-batch-07

**Audience:** technical stakeholder (firmware/test engineer, QA-responsible operator, tech lead). Not a code walkthrough.
**Purpose:** understand the four capabilities delivered this batch as the operator uses them — the single JSON change system, declarative check files, multi-variant projects, and the project report — plus what was removed (the entire cfdx/.cdfx flow) and why that removal is safe.
**Scope:** the change/check/report/variant feature set in `s19tui`. The parsers (`core.py`, `hexfile.py`), the range/validation engine, and the MAC/A2L view layouts are untouched — pinned byte-identical by a standing guard test.

This batch closes four user stories (US-002..US-005). The common thread: everything the operator declares lives in **one JSON file format**, everything that runs is **headless-capable**, and everything that happened is **auditable in a Markdown report**.

---

## 1. One JSON file is now the source of all changes (US-002)

### What the operator writes

A change file is a single JSON document — hex-first, address-only. The v2 schema (verbatim from the requirements, §6.2 C-1):

```json
{
  "format": "s19app-changeset",
  "version": "2.0",
  "kind": "change",
  "encoding": "utf-8",
  "value_mode": "text",
  "entries": [
    { "type": "string", "address": "0x80001000", "value": "687000123" },
    { "type": "bytes",  "address": "0x800020",   "bytes": "FF" },
    { "type": "bytes",  "address": "0x80002F00", "bytes": "DE AD BE EF" }
  ]
}
```

- **String patches** write an encoded string at an address; **byte patches** write explicit hex bytes. Nothing else exists — no symbolic addressing, no parameter names. MAC/A2L knowledge never decides *where* a write lands; it only annotates *what* the write touched (section 4).
- **`encoding`** is any Python *text* codec (`utf-8`, `ascii`, `latin-1`, …). Non-text codecs such as `zlib_codec` are rejected at metadata level — a hardening found by live verification during review.
- **`value_mode`** declares how string values are read: `"text"` = the literal string is encoded; `"codes"` = the value is an array of code points (e.g. `[54, 56, 55]`) joined and encoded.
- **Collisions are errors.** Two entries whose encoded target ranges intersect — or that name the same address — each get an ERROR finding (`CHG-COLLISION`), and an erroring document applies **nothing** (all-or-nothing gate). Collision math uses *encoded* length, so multi-byte encodings are handled correctly.
- **In files, the `bytes` grammar is strict** (whitespace-separated two-hex-digit tokens). The Patch Editor's input fields stay permissive (commas, `0x` prefixes, decimals) and normalize to the strict form on save — convenience in the TUI, one unambiguous grammar on disk.
- **Old v1 unified-JSON files are now rejected** with exactly one clear ERROR naming the v2 format token (`CHG-V1-FORMAT`). There is no read shim and no migrator — an operator-confirmed hard break (the format was retired precisely to avoid maintaining two formats).

The reader collects every finding (schema, metadata, per-entry, collision, resource ceilings) without ever raising — the established collect-don't-abort contract of the parsers, extended to change files. Declaration faults are rendered **persistently** in the Patch Editor (per-entry status + issue count, surviving unrelated UI actions until re-validated clean) and travel into the project report's error section.

### How a change is applied

In the Patch Editor (single section now: entries table, both-kind inputs, Load / Validate / Apply / Save / Run checks), Apply on a clean document writes only entries fully inside the loaded image. Each entry gets a disposition — `applied`, `skipped-partial`, `skipped-outside`, `skipped-no-image`, or `blocked` — and the engine captures the **prior bytes of every written range before mutation**, so the report can show true before→after values. Note: apply mutates the in-memory snapshot; `before_bytes` in the summary is the only prior-state record, and re-loading the file is the only undo.

### Save-back of the patched image

When an apply lands ≥1 entry on an S19 image, the app prompts to persist the patched image into the project work area, with an **editable filename** pre-filled as `<variant_id>-patched.s19`. The typed name passes a containment sanitizer (traversal, absolute paths, and Windows reserved device names like `CON.s19` are neutralized; the write is staged and verified to stay inside `.s19tool/workarea/<project>/`). The emitter is new mem_map-based S19 serialization whose acceptance test is "the written file re-parses to the identical memory map". **HEX images decline:** Intel HEX has no writer in the codebase yet, so the app states save-back is not supported for HEX and records `saved_path = None` (an Intel HEX emitter is a batch-08 candidate).

---

## 2. Check files — declarative expected values (US-003)

A check file is the **same v2 document with `kind: "check"`**; its entries are *expected* values instead of writes. One reader, one schema family, identical rules (including collision = ERROR — duplicated expectations are declaration defects, an operator decision at the gate).

Running a check compares the expected encoded bytes against the loaded memory and yields exactly one result per entry:

| Result | Meaning |
|---|---|
| `pass` | actual bytes equal expected bytes |
| `fail` | range readable, bytes differ (actual captured for the report) |
| `uncheckable` | range not fully inside the loaded image, or no image loaded |

Checks mutate nothing. In the TUI, results render row-per-entry with the standard severity colours (fail → error class, uncheckable → warning class) and an aggregate pass/fail/uncheckable count in the status line. Critically for automation, the engine is **headless**: `run_checks_for_project(check_path, image_path, mac_path, a2l_path)` parses the project files and returns the full results object — including the check document's own declaration faults — with no TUI constructed. That object is the carrier that brings check evidence into the project report.

---

## 3. Multi-variant projects — N S19 files, one A2L, one MAC (US-005)

A project under `.s19tool/workarea/<project>/` may now hold **N S19/HEX files** (variants of the same software) sharing **one** A2L and **one** MAC — the previous 1-S19 limit is gone; the single-MAC/single-A2L limits remain. Variants enumerate in deterministic name order; exactly one variant is rendered at a time, parsed on the worker thread exactly as before (the load thread contract is untouched).

Operator surface:

- **Key `v`** opens the variant selector (modal list, same pattern as project load). The project label shows `«project»:«variant» (i/N)` when N > 1 — single-variant projects look exactly as they did before this batch.
- Loading a project activates the **first variant** by default; a project manifest can override that.
- **`project.json`** (one per project, **hand-authored this batch** — a writer is queued for batch-08) declares `active_variant`, per-variant `assignments` of change/check files, and a `batch` list applied to every variant. No manifest = batch mode over all variants. Manifest paths resolve strictly inside the project directory — escapes, absolute paths, and reparse points are rejected per entry.
- **Execution** runs from the Patch Editor's scope selector — {active variant | all variants | per assignment} — on a worker thread with live per-variant status lines. Each variant is parsed fresh and sequentially; one variant's failure never aborts the rest (the result count always equals the variant count, with the failure carried as a diagnostic).

---

## 4. The project report (US-004)

**Key `t`** opens the report viewer; the generation dialog asks for the hexdump context (**±64 bytes by default, adjustable per invocation**, valid range 0–4096 — out-of-range values error rather than silently clamp) and writes `.s19tool/workarea/<project>/reports/<UTC-timestamp>-report.md`. Generation is also fully headless for automation.

What each section shows:

- **Header** — project, UTC timestamp, tool version, context setting, and the execution mode (batch / per-assignment / active-only).
- **Variant inventory** and a **consolidated overview** (variant × changes applied × check pass/fail/uncheckable × status) — the one-glance answer to "did everything land everywhere".
- **Per-variant sections** — modified files (including the saved patched image path when save-back ran), a **before→after modification table** (address, length, before bytes, after bytes, linkage, symbol), a **declaration-error subsection** (every fault collected from the change/check documents — nothing is silently dropped), the executed checklists with per-entry results, and a **hexdump of every modified region ±context** (16-byte aligned; adjacent/overlapping windows merge so no row prints twice; gaps render with the standard blank/`.` convention).
- **Truncation appendix** — if the size caps fire, the report says exactly how many regions/bytes were omitted; never silent truncation.

The **linkage column** (standalone / MAC-linked / A2L-linked / both, with the symbol name) deserves its own explanation, in the operator's own rationale (recorded at the 2026-06-10 gate, HLR-007): the before→after report exists so the operator can judge **whether a change makes sense** — e.g. spotting that a write landed on an A2L *multiplier* instead of a *quantity*. That sense-check is deliberately **observed in the report, never blocked by rules**: changes are address-only against the hex/S19, and no A2L/MAC change rules exist because only the image is modified. The report is where that human validation happens.

The viewer itself is hardened: it renders Markdown read-only with **link navigation disabled** (`open_links=False` — a clicked link in a tampered report can never open a browser), refuses files above a size cap with a neutral message, and lists reports newest-first. Reports contain raw memory bytes, so they live only under the gitignored `.s19tool/` tree and their content is never echoed to the log.

---

## 5. What was removed — and why it is safe

The entire cfdx/.cdfx parameter flow is **gone**: the CDFX XML reader/writer, the parameter-by-name change list, the selective `.cdfx` export, the multi-window Patch Editor sections, and the v1 unified JSON format. That is 12 production modules, 15 whole test files, and a net −16,212 lines, enacted against a 355-row measured test-disposition table that reconciled exactly in the suite-count ledger.

This is safe for the operator because:

- Every retired path **fails loud with a named alternative**: loading a `.cdfx` file or a v1 JSON yields one clear ERROR finding that names the v2 format — never a crash, never silent acceptance.
- The capability did not shrink — it consolidated. Address-only byte/string patches cover what the parameter flow did (the operator's own decision: the A2L name never drives addressing; it informs the report instead).
- The engine layers were proven untouched (`core.py`/`hexfile.py`/`range_index.py`/`validation/*` byte-identical to `main`, guarded by a standing test), and the surviving 87-test memory/unified stack still passes against the new modules.

---

## Assumptions, risks, next steps

**Assumptions**
- One operator, no external consumers of the v1 JSON format (basis of the hard break, confirmed at the gate).
- Operators hand-author `project.json` this batch; the manifest is read-only.
- Report size constants (128 regions/variant, 2 MiB total) were measured against the large-project fixtures and hold (106,848 B / 0.011 s at default context).

**Risks / limitations**
- **Apply is destructive to the in-memory snapshot** — after Apply, re-validation sees patched bytes; the summary's `before_bytes` is the only prior-state record and re-load is the only undo.
- **HEX save-back does not exist yet** — the app states it and skips; patched HEX images live only in memory and in the report evidence this batch.
- CI confirmation on Python 3.11 plus the new two-tier CI gate (CI-1) land **with the batch PR** — all local evidence is from Python 3.14.4. One snapshot baseline (`patch-comfortable-120x30`) stays xfail until the canonical CI env regenerates it.
- No single end-to-end pilot covers load→execute→generate→view as one flow (each seam is covered pairwise); recommended as one pilot in batch-08.

**Next steps**
- Batch-08 candidates (post-mortem A-7): **manifest writer** (persist `active_variant`/assignments from the TUI), **Intel HEX emitter** (unlocks HEX save-back), **US-006 hex compare mode** (queued operator story), the **E2E pilot**, and the carried MAC-layout knee test.
- Phase-6 doc reconciliation (A-4): REQUIREMENTS.md §8–9 supersession notes; LLR-002.7/007.2/HLR-008 wording fixes (DEV-1/7/8).
- After commit/push/merge: run `dev-flow-sync` to the canonical G: vault.
