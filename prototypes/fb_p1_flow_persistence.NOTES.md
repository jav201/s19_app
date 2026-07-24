# FB-P1 (batch-53) — flow.json persistence: design + prototype notes

**Prototype:** [fb_p1_flow_persistence.prototype.py](fb_p1_flow_persistence.prototype.py)
— run `python prototypes/fb_p1_flow_persistence.prototype.py`. Throwaway; the real
implementation lands in a new `s19_app/tui/services/flow_persistence_service.py`.

**Question on trial:** is the untrusted `flow.json` loader safe-by-construction when
every embedded ref re-validates through the SAME `_resolve_manifest_entry` guard
(`variant_execution_service.py:205`, reuse — never fork) with a whole-flow
fail-closed reject?

**Verdict (2026-07-24 run): ALL CASES HELD** — 5-kind round-trip byte-faithful;
all 13 battery cases REJECTED-CLOSED with readable findings (incl. a REAL NTFS
junction); external import lands via `copy_into_workarea` and a non-workarea
destination is REFUSED (`WorkareaContainmentError`).

---

## 1. The JSON envelope (schema v1 — exact)

`Flow.schema_version` already defaults to `1` (`flow_model.py:189`); the envelope
is the model's shape verbatim:

```json
{
  "schema_version": 1,
  "name": "nightly-release",
  "blocks": [
    { "kind": "source",    "image_ref": "prg.s19", "file_type": "s19" },
    { "kind": "patch",     "change_doc_ref": "calib_patch.json" },
    { "kind": "check",     "check_doc_ref": "post_checks.json", "gating": "block-own-op" },
    { "kind": "crc",       "config_ref": "crc32_blocks.json" },
    { "kind": "write_out", "output_name": "prg_patched.s19", "fmt": "s19" }
  ]
}
```

- `kind` ∈ {`source`,`patch`,`check`,`crc`,`write_out`} (the shipped `BLOCK_*` tags).
- Enums: `file_type`/`fmt` ∈ {`s19`,`hex`}; `gating` ∈ {`advisory`,`block-own-op`}.
  Optional in the file (dataclass defaults fill in); invalid values reject.
- **Strict keys**: unknown fields on a block reject the flow (schema_version gates
  evolution — any additive field is a version bump, never silent tolerance).
- **Identity = the filename** (`flows/<name>.json`, name via `sanitize_project_name`,
  `workspace.py:362`); the embedded `name` is display-only, ≤64 chars, rendered
  through `safe_text` at the UI (the batch-27/43 markup-sink rule).
- Caps: file ≤ 1 MiB (`FLOW_SIZE_CAP_BYTES` — deliberately tight, NOT the manifest's
  256 MB copy-cap), ≤ 64 blocks, ≥ 1 block.

## 2. Load-time validation order (fail CLOSED, collect-don't-abort, never raises)

File gate (mirrors `read_project_manifest`, `variant_execution_service.py:427-454`):

| Stage | Check | Finding code |
|---|---|---|
| F1 | `stat` size ≤ 1 MiB BEFORE parse | `FLOW-SIZE-CAP` |
| F2 | `json.load` catching `JSONDecodeError`/`RecursionError`/`UnicodeDecodeError`/`OSError` | `FLOW-JSON-PARSE` |

Envelope gate (`dict_to_flow`):

| Stage | Check | Finding code |
|---|---|---|
| V1 | top level is an object | `FLOW-BAD-STRUCTURE` |
| V2 | `schema_version` is EXACTLY int `1` (future/string/absent → reject) | `FLOW-SCHEMA-UNSUPPORTED` |
| V3 | `name` non-empty str ≤ 64 (display-only) | `FLOW-BAD-FIELD` |
| V4 | `blocks` is a list, 1..64 entries | `FLOW-BAD-STRUCTURE` |
| V5 | per block: object; known `kind`; strict keys; required ref non-empty str; enums valid | `FLOW-UNKNOWN-KIND` / `FLOW-BAD-FIELD` |
| V6 | per READ ref (`image_ref`/`change_doc_ref`/`check_doc_ref`/`config_ref`): **`_resolve_manifest_entry(project_dir, ref, …)`** — absolute / escape-root / reparse triad; NO filesystem open; existence NOT required (missing files surface at RUN, the manifest precedent) | `MANIFEST-PATH-ESCAPE` / `MANIFEST-BAD-STRUCTURE` (travel with the reused guard — OQ-1) |
| V7 | `output_name` (WRITE target): plain-filename shape only (no separators/`..`/absolute/hidden); runtime authority stays `save_patched_image` F-S-01 | `FLOW-UNSAFE-OUTPUT-NAME` |

**Aggregate: ANY finding ⇒ `(None, findings)`** — an executable pipeline is never
partially loaded (unlike the manifest, which degrades to empty batch). Note the
refs are ALSO re-validated at run time by `run_flow` (`flow_execution_service.py:128`
etc.) — load-time validation is defense-in-depth + early readable feedback, not a
replacement for the run-time guard.

## 3. Security-rejection battery (all REJECTED-CLOSED in the run)

| Case | Input | Result / finding |
|---|---|---|
| (a) | `image_ref: C:\Windows\System32\evil.s19` | ✓ `MANIFEST-PATH-ESCAPE` (absolute, pre-filesystem) |
| (a2) | `change_doc_ref: /etc/passwd` | ✓ `MANIFEST-PATH-ESCAPE` (posix absolute caught on Windows too — `PurePosixPath` arm) |
| (b) | `config_ref: ../../other_project/secrets.json` | ✓ `MANIFEST-PATH-ESCAPE` (escape after resolve) |
| (c) | `change_doc_ref: jdir/patch.json` where `jdir` is a REAL NTFS junction → outside | ✓ `MANIFEST-PATH-ESCAPE` — `resolve()` follows the junction, the escape arm fires; the reparse-walk arm backstops the stays-inside case. Path never opened. |
| (d) | `kind: "shell"` | ✓ `FLOW-UNKNOWN-KIND` |
| (e) | `schema_version: 99` | ✓ `FLOW-SCHEMA-UNSUPPORTED` |
| (e2) | `schema_version: "1"` (string) | ✓ `FLOW-SCHEMA-UNSUPPORTED` (type-strict; bool also rejected) |
| (f) | missing `image_ref` | ✓ `FLOW-BAD-FIELD` |
| (f2) | `gating: "chain-kill"` | ✓ `FLOW-BAD-FIELD` (enum) |
| (f3) | `output_name: ..\..\escape.s19` | ✓ `FLOW-UNSAFE-OUTPUT-NAME` |
| (f4) | unknown extra field `extra_hook` | ✓ `FLOW-BAD-FIELD` (strict keys) |
| (f5) | top level `["not","a","dict"]` | ✓ `FLOW-BAD-STRUCTURE` |
| (g) | file `{not json` | ✓ `FLOW-JSON-PARSE` |
| import-hostile | `copy_into_workarea` dest outside any workarea | ✓ REFUSED `WorkareaContainmentError` |

## 4. UI design — Save / Load / Import on FlowBuilderPanel (rail-8)

Grounding: existing panel `screens_directionb.py:2588` (Add-row → blocks list →
Run/Clear row → `#flow_result` ledger); modal patterns `screens.py:438`
(SaveProjectScreen: `OsClipboardInput` name + sanitiser hint) and `screens.py:646`
(LoadProjectScreen: `ListView` + confirm/cancel); browse pattern `screens.py:615-629`
(tkinter `filedialog`, same as `save_browse`). Tokens: **inherited only** — Calm-Dark
navy/pastel, `.modal-dialog`, `sev-*` classes, `safe_text` on every file-derived
string. No new colors (C-30: no restyle). Glyph-primary, colour-secondary (C-10):
state reads from `●`/`✓`/`✗` glyphs before hue.

### Affordances

1. **Name strip** (new, above the add-row): `Flow: <name> ●` — `●` = dirty
   (blocks changed since save/load), cleared glyph `✓` after save. Name via
   `safe_text`, class `sev-neutral`/`sev-warning` secondary cue.
2. **Save** (button in the run-row): opens `SaveFlowScreen` — one
   `OsClipboardInput` prefilled with the current name (so Save and Save-As are ONE
   modal; editing the prefill = Save-As), hint `letters, numbers, - _`, a live
   `(overwrites existing)` notice when `flows/<sanitized>.json` exists, Save/Cancel.
   Writes `flows/<name>.json`; status `✓ saved flows/<name>.json`.
3. **Load** (button in the run-row): opens `LoadFlowScreen` — `ListView` of
   `flows/*.json` stems + **Import…** / Load / Cancel. Import… = tkinter file
   pick → **`copy_into_workarea(picked, project_dir/"flows")`** (containment +
   1 MiB-appropriate size arg + dedup `_<N>`), list refreshes with the imported
   entry highlighted — an external file is NEVER loaded in place.
4. **Rejection = the "quarantine card"** (signature element — it renders, not
   labels): a rejected load mounts a bordered `sev-error` card into `#flow_result`
   listing every finding (`safe_text`, `markup=False` per line, the LLR-088.6
   sweep); the current blocks are UNTOUCHED and the name strip keeps the old name.
   Nothing about the hostile file ever reaches the blocks list.

### 80×24 rendering (floor)

```
┌ Flow Builder ────────────────────────────────────────────────────────────────┐
│ Flow: nightly-release ●                                     [dirty — unsaved]│
│ Pick a block kind, enter its project-relative ref, Add; then Run.            │
│ ┌kind────────────┐ ┌ref──────────────────────────────────┐ ┌────┐            │
│ │ Load (image) ▾ │ │ prg.s19                             │ │Add │            │
│ └────────────────┘ └─────────────────────────────────────┘ └────┘            │
│ 1. source  prg.s19                                                           │
│ 2. patch   calib_patch.json                                                  │
│ 3. crc     crc32_blocks.json                                                 │
│ 4. write   prg_patched.s19                                                   │
│ ┌─────┐ ┌───────┐ ┌────────┐ ┌────────┐                                      │
│ │ Run │ │ Clear │ │ Save…  │ │ Load…  │                                      │
│ └─────┘ └───────┘ └────────┘ └────────┘                                      │
│ ┌ result ─────────────────────────────────────────────────────────────────┐  │
│ │ ✗ LOAD REJECTED — flows/vendor_flow.json (2 findings)   [quarantine]    │  │
│ │  [MANIFEST-PATH-ESCAPE] blocks[1].change_doc_ref entry escapes the      │  │
│ │    project directory - entry skipped: '../../other/secrets.json'        │  │
│ │  [FLOW-UNKNOWN-KIND] blocks[5] has unknown kind 'shell'                 │  │
│ │  Current flow unchanged.                                                │  │
│ └─────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

Load modal at the floor (shared `.modal-dialog`, centered ~46×14):

```
        ┌ Load flow ─────────────────────────────┐
        │ Saved flows (protoproj):               │
        │ ┌────────────────────────────────────┐ │
        │ │ NightlyRelease                     │ │
        │ │ vendor_flow          (imported)    │ │
        │ │ smoke_check                        │ │
        │ └────────────────────────────────────┘ │
        │ ┌──────┐ ┌─────────┐ ┌────────┐        │
        │ │ Load │ │ Import… │ │ Cancel │        │
        │ └──────┘ └─────────┘ └────────┘        │
        └────────────────────────────────────────┘
```

### 120-col regime

Same widgets — the run-row gains room and the name strip absorbs the save-state
detail inline (no second design, responsive only):

```
│ Flow: nightly-release ✓ saved flows/NightlyRelease.json · 5 blocks · schema v1                                        │
│ ┌kind────────────┐ ┌gating──────┐ ┌ref──────────────────────────────────────────────────┐ ┌────┐                     │
│ │ Check (list) ▾ │ │ advisory ▾ │ │ post_checks.json                                    │ │Add │                     │
│ └────────────────┘ └────────────┘ └─────────────────────────────────────────────────────┘ └────┘                     │
│ ┌─────┐ ┌───────┐ ┌────────┐ ┌────────┐                                                                              │
│ │ Run │ │ Clear │ │ Save…  │ │ Load…  │              …ledger + twin ribbon unchanged below…                          │
│ └─────┘ └───────┘ └────────┘ └────────┘                                                                              │
```

Critique pass (per skill): no new tokens (pass — restyle-LAST, C-30); the
signature *renders* (a quarantine card is a visible state, not a toast); one
accessory removed — an earlier draft had a per-flow "block-count badge" in the
Load list; dropped (the list stays name-only, count shows after load).

## 5. Open design questions (operator)

- **OQ-1 codes:** findings from the reused `_resolve_manifest_entry` carry
  `MANIFEST-*` codes inside a flow-load report. Keep verbatim (truthful reuse;
  zero fork risk) or wrap in `FLOW-REF-*` at the collection boundary (nicer
  taxonomy; codes are public/test contract either way)? Prototype keeps verbatim.
- **OQ-2 existence:** load-time containment WITHOUT existence check (manifest
  precedent; a flow can be authored before its inputs exist). Confirm, or add an
  advisory (non-rejecting) "ref not present yet" WARN at load?
- **OQ-3 dirty guard:** Load over unsaved edits — confirm-discard modal
  (recommended) or silent replace?
- **OQ-4 caps:** 64 blocks / 64-char name / 1 MiB — arbitrary but generous;
  confirm before they become test-asserted contract.

## 6. Production landing map (batch-53, no frozen files touched)

- NEW `s19_app/tui/services/flow_persistence_service.py`: `flow_to_dict`,
  `dict_to_flow`, `load_flow_json`, `save_flow_json`, `list_saved_flows`,
  the `FLOW_*` codes/caps. Imports `_resolve_manifest_entry` (consider promoting
  it to a public name in `variant_execution_service` rather than importing the
  underscore), `sanitize_project_name`, `copy_into_workarea`. No Textual (C-7).
- `screens.py`: `SaveFlowScreen` + `LoadFlowScreen` (patterns above).
- `screens_directionb.py` FlowBuilderPanel: name strip + Save/Load buttons +
  `SaveRequested`/`LoadRequested` messages + quarantine-card render; panel gains
  `set_blocks(flow)` for the app to mount a loaded flow.
- `app.py`: two handlers (mirror `on_flow_builder_panel_run_requested`,
  `app.py:2277`), base dir = `_active_project_dir()` (`app.py:1760`); no-project
  → error card, same as Run.
- `workspace.py` is NOT edited: `flows/` is a subdirectory, and
  `validate_project_files` already skips subdirectories (`workspace.py:376-378`)
  so project cardinality rules are unaffected.
