# Functionality — Manifest write + verify-on-write — Batch 2026-06-14-batch-11

**Audience:** s19tool operators and technical stakeholders.
**Purpose:** understand what batch-11 delivers, how to exercise it, where the seams are, and what it does NOT do yet.

---

## 1. What batch-11 delivers

Until now the per-project manifest `project.json` was **read-only**: the tool could parse it (`read_project_manifest`) but the file had to be **hand-authored**. Batch-11 adds the missing WRITE side, with an integrity check on every write.

In one sentence: **the tool can now write `project.json` itself, and it re-reads what it just wrote to prove the write is correct before trusting it.**

This mirrors the discipline batch-10 introduced for firmware images (write image → re-read → diff). Here the artifact is a JSON manifest instead of a memory map, so the check is a key-wise comparison instead of a byte diff — but the shape is the same: **write → re-read the canonical file → diff against intent → quiet "verified" on success, loud mismatch notice on drift.**

### What the write produces
A `project.json` with exactly four keys — `schema_version`, `active_variant`, `batch`, `assignments` — in the canonical form the existing reader accepts. The reader is the single source of truth for the schema: correctness is defined as "the reader reads it back with the same composition and zero findings," not against a separate schema document. This is the same round-trip-to-oracle design batch-10 used (the image emitter is correct iff `IntelHexFile` reads it back identically).

### What verify-on-write does
After writing, the tool re-reads `project.json` **by its canonical fixed name** (never by a path the writer happened to return), parses it through the same reader an operator's next session would use, and compares the parse against what was intended:

- **Verified** — all three composed fields (`active_variant`, `batch`, `assignments`) match intent and the reader reported zero issues. The operator sees a quiet "Project saved + manifest verified" status line.
- **Mismatch** — one or more fields drifted, OR the reader flagged the file (e.g. a size cap, a parse fault, a path escape). The operator sees a prominent error notice **naming what drifted** (the specific keys and/or the reader's issue messages). A write the reader cannot use is surfaced as a mismatch, not a false success.

A reader-rejected write counts as a mismatch even when the surviving keys happen to match — this closes the hole where a file "lands on disk" but the reader silently degrades it.

---

## 2. How to exercise it

**From the TUI (the only surface this batch):**

1. Load / compose a project in the TUI as usual.
2. Trigger the project save.
3. The save now does two extra things after the existing file-copy save:
   - writes `project.json` into the project directory under the work area, and
   - re-reads + verifies it.
4. Observe the result:
   - a clean save shows **"Project saved + manifest verified"**;
   - if you then tamper with `project.json` on disk and re-run the verify path, you get a **mismatch notice naming the drifting key** (e.g. `active_variant`).

There is **no CLI surface** for the manifest write this batch (batch-10 was TUI-only; this batch follows that).

**Headless / programmatic (for future non-TUI callers and for tests):**

The serialize / write / verify functions are plain functions in a headless service module — no running app required. The test suite drives them directly with explicit `batch=` / `assignments=` compositions, which is also how a future caller would compose a full manifest.

---

## 3. The seams (how it is built)

All the manifest logic lives in **one headless service module**, `s19_app/tui/services/manifest_writer.py`, beside the manifest reader's service. The TUI only orchestrates — it calls the service and renders the outcome; it holds no serialize/write/verify logic of its own.

| Seam | Function | What it guarantees |
|------|----------|--------------------|
| **Serialize** | `serialize_manifest` | Builds the 4-key envelope and emits it via the stdlib `json` encoder (never string assembly). Paths are normalized to forward-slash POSIX so they round-trip on Windows and POSIX alike. Deterministic: the same composition serializes to byte-identical output, so a no-change re-save is a no-op. |
| **Write** | `write_project_manifest` | Stages the bytes under `.s19tool/workarea/temp/`, re-runs the work-area containment CHECKS against the final destination, then performs an **atomic `os.replace`** onto the fixed `project.json` name. No dedup: two saves leave exactly one `project.json` (the second wins) — never `project_1.json`. The staged temp file is always cleaned up. |
| **Verify** | `verify_written_manifest` -> `ManifestVerifyResult` | Re-reads the **canonical** `project_dir / project.json`, resolves intent into the same comparison form, compares key-wise, and honors any reader issue as a mismatch. Returns a small result object (status / drift / issues / written_path) modeled on batch-10's `VerifyResult` — but it does NOT reuse `diff_mem_maps`, because a manifest is a JSON dict, not an address->byte map. |

### Guard-rails worth calling out
- **Atomic, no-dedup write (M-1 / M-2).** The destination is never observed half-written. A crash mid-write leaves either the old manifest or the new one intact, never a truncated file. Because the name is fixed and the placement is an atomic replace, a re-save overwrites in place — there is no silent `project_1.json` that the reader (which opens only the canonical name) would never see.
- **Escape-refusal (LLR-001.5).** The serializer **refuses up front** any `batch`/`assignments` entry that is absolute or escapes the project directory: it returns `(None, [finding])` and writes nothing, reusing the reader's own rejection predicate (no second, divergent path-safety implementation). A refused composition never reaches the write step.
- **Containment + collect-don't-abort.** A destination that fails the work-area containment checks, or an `OSError` during staging / replace, returns a finding rather than raising — the same contract the reader and the change-document writer follow.
- **Canonical-name re-read + reader-issues => mismatch (M-1 / R-1).** Verify always opens the canonical fixed name, so a stale stray file can never produce a false verify; and any reader issue on the re-read forces a mismatch.
- **Headless + no logging.** The module imports no `textual` and configures no logging — it stays reusable and testable without a running app, matching the batch-10 verify sibling.

---

## 4. Extension points — what it does NOT do yet

> Stated honestly so the next batch starts from the real boundary, not an assumed one.

- **SCOPE-1 — the TUI save composes `active_variant` only, today.**
  The save handler calls the writer with no `batch` / `assignments` arguments, so a save from the UI persists the active-variant selection with **empty** `batch` and `assignments`. This is a save-flow composition gap, **not** a writer limitation: the **writer fully supports and tests** `batch` and `assignments` composition — the test suite passes explicit `batch=` / `assignments=` compositions through serialize -> write -> verify, all passing. US-010's benefit is therefore met at the **active-variant level** today; wiring the file-list composition (`batch` / `assignments`) from the loaded project state into the save UI is a **batch-12 candidate** and is recorded as SCOPE-1 in the validation report and routed to the Phase-5 post-mortem.

- **CRC first-operation fill-in — still QUEUED.**
  Unchanged by this batch; pending the operator's CRC definition (postponed across batches 08->10->11).

- **No CLI surface.**
  Manifest write/verify is TUI-only this batch, consistent with batch-10.

- **No retained backup.**
  A re-save overwrites in place (atomically). A timestamped backup of the prior manifest is a possible future hardening, not a requirement this batch — atomicity already rules out a truncated/partial file.

- **The reader/schema is not changed.**
  The reader remains the oracle; the writer round-trips against it. If the reader's schema ever evolves, the writer must follow — a deliberate single-oracle tradeoff (one new module to update).
