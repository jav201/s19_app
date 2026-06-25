# Functionality — Per-variant File-Assignment at Project Save (US-017)

**Audience:** operator (engineer saving a multi-variant project) + maintainer.
**Purpose:** understand + operate the new save-time assignment feature.
**Batch:** `2026-06-25-batch-16` (US-017). Closes batch-11 SCOPE-1.

---

## What this gives you (BLUF)

When you re-save an existing multi-variant project, you can now **assign change/check `.json` documents per variant and a project-wide batch list at save time**, and those assignments are **persisted in `project.json`** and **applied by variant-execution**. Before this batch the save wrote only `active_variant`, so per-variant files could not be saved through the UI at all — the writer supported them, but nothing fed it through the shipped surface.

- **Project-wide `batch`** → applied to every in-scope variant.
- **Per-variant `assignments`** → applied only to the variant you assign them to, keyed by that variant's `variant_id`.
- Both round-trip on disk with **zero drift** (verify-on-write) and are picked up by `plan_variant_executions`.

---

## Walkthrough — assign files and save

1. **Open an existing multi-variant project** (one whose variant set is already built). The assignment UI is for **re-saving** a known-variant project — see *Scope* below.
2. **Trigger the save** (`action_save_project`). The `SaveProjectScreen` opens with, in addition to the project-name field:
   - a **project-wide batch** input, and
   - **one assignment row per variant**, labelled by `variant_id`.
3. **Pick files.** Each field offers **only the project-relative `.json` change/check documents** enumerated from the project directory — files already inside the work-area. Files outside the work-area and `project.json` itself are not offered.
   - Example: assign `doc.json` to the project-wide batch, and `extra.json` to variant `b`.
4. **Save.** The screen collects the composition into the `SaveProjectPayload` (`batch` + `assignments`, as project-relative strings — no pre-resolution to absolute). The save handler threads both into `write_project_manifest` **and** `verify_written_manifest`.
5. **Result on disk:** `project.json` now carries:
   - `active_variant` (as before),
   - `batch: ["doc.json"]`,
   - `assignments: {"b": ["extra.json"]}`.
   The handler re-reads the file and verifies it reproduces `active_variant`/`batch`/`assignments` with **0 drift** before reporting success.
6. **At variant execution:** `plan_variant_executions(variant_set, manifest, scope="all")` yields, for each variant, the tuple `batch + assignments[variant_id]`. With the example above:
   - variant `b` → `("doc.json", "extra.json")` (resolved),
   - an unassigned variant `a` → `("doc.json",)` (batch only).

---

## Two important rules to know

### Workarea restriction (where files come from)
Only files **already in the project work-area** are assignable — the UI offers a pick-from-list of project-relative `.json` documents. This is convenience UX (no external-file copy handling). It is **not** the security boundary: the writer's `_reject_unsafe_entry` is the sole path-safety authority. If an absolute or escaping entry is ever driven through the handler, the save is **refused** — you get a "Manifest write failed" notice and **`project.json` is not written** (no partial/escaping entry persists, no crash).

### `variant_id` keying (how an assignment finds its variant)
Each assignment is keyed by the variant's **`variant_id`**, sourced directly from `ProjectVariantSet.variants[*].variant_id` — never recomputed as `Path.stem`.

- Normally `variant_id` **is** the filename stem (e.g. `fw_a`).
- On a **stem-collision** — two variants whose filenames share a stem, e.g. `fw.s19` and `fw.hex` — each variant's id is the **full filename** (`fw.s19`, `fw.hex`). The assignment is keyed and picked up under that full filename, so the two variants never clash. This is the D-KEY contract; a wrong key (recomputed stem) would silently drop the assignment at the consumer, which is exactly why the UI reads the id from the variant set.

---

## Scope (what is and isn't covered)

- **In scope:** re-saving an **existing** multi-variant project — its variant set is known, so the per-variant rows can be rendered and keyed.
- **Out of scope (zero-selection path):** a **brand-new** project save opens before the variant set exists. It writes **empty** `batch`/`assignments` (the prior active-variant-only behaviour is preserved — no regression). Assign files by re-saving once the project's variants exist.
- **Unchanged:** the manifest schema, the execution semantics (`plan_variant_executions` is consumed as-is), and the primary-image copy. This batch only adds the save-time assignment surface and the persistence/threading that feeds the existing consumer.

---

## Assumptions · risks · next steps

- **Assumption:** the project's variant set is built before the assignment UI is shown (true for re-save; the new-project path falls through to zero-selection by design — D-NEWPROJ).
- **Risk (mitigated):** a wrong assignment key would be silently dropped by the consumer — mitigated by sourcing keys from `variant_id` and proven by the stem-collision acceptance test (AT-017.5).
- **Next steps:** none required for US-017 (SCOPE-1 closed). If a future batch lets you assign files **during** a brand-new project save (after the primary image copy builds the variant set), it would extend the D-NEWPROJ scope; out of scope here.
