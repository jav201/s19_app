# Inc 8 — E1 rulings: scope, canon changes, decisions

Base `e266395`. Author: E1/E2 agent (architect, Opus). Every code claim below was read on the base tree; every number marked (B) comes from a probe run at E1 from the session scratchpad (read-only on the worktree).

## 1. Scope

**In.**
- **F-28** — the Flow CRC block given a file the CRC Designer saved. Root cause (read): the CRC block parses the file with the flat CRC-config parser (`flow_execution_service.py:810` → `crc_config.parse_crc_config`), whose `_build_config` reads `data["reverse"]` first (`crc_config.py:487`); a Designer template (`crc_designer_model.emit_template`, `:769-813`) holds `{schema_version, name, aliases, operation, algorithm{…}}`, so the `KeyError('reverse')` becomes `CRC config is structurally invalid: 'reverse'`. Fixed as **recognise and name** (D-1).
- **D13-23** (co-located) — the CRC config reader names the field in its "missing" and "not a number" reasons (R-CRC-CONFIG-001.10, .11). The template-reader half is deferred (D-4).
- **D13-20** (P0 ruling) — the CRC operation engine seeds its register with the bit-reversed init when `reverse` is true (`crc.py:211`). The model of CTX-CRC ("init: register value before the first byte, not reflected"), the CRC Designer engine (`crc_kernel.py:131`, `reg = init & mask`) and the catalogue disagree with it. Fixed by seeding with init as given.
- **F-49** — a later block that names an external step's output reads the first copy after a later run copied a different output as `_1`. Fixed by **reading this run's copy** for refs that name the output file name (D-2).
- **D15-17** (co-located) — a relative output path of a confirmed external step is read against the working directory (`flow_execution_service.py:1092`, `Path(confirmation.source_path)` with no join; the log is joined at `:1090-1091`). Fixed by joining it under the project folder like the log.

**Out (not in this increment).**
- F-48 (a `#n` / binding reference to an external output): stays in the backlog; D-2 does not add a reference syntax.
- A CRC block that **uses** a Designer template's algorithm (D-1, alternative B): needs a place for the regions and output addresses that a template does not hold, which is a builder field or a new file shape — UI or format work for a later batch with a prototype round.
- The Flow Builder field label `CRC template` (`flow_screens.py:569`) and the help line `CRC template — the CRC configuration a CRC block stamps.` (`window_help.py:234`): visible text that keeps the name collision (backlog row BL-I8-2; Inc 14 owns `window_help.py`).
- D13-21, D13-22, D13-24 (other CRC config rules), D15-8 (fused run).

**No UI change.** Only the text of reasons that already appear in the same places changes (the Operations result area, the flow block summary/cause). No widget, layout, key or style changes.

## 2. Plan deviations (source files)

| Plan (`PLAN-draft.md` row 8) | E1 | Reason |
|---|---|---|
| `flow_execution_service.py` | kept | F-28 cause path is unchanged code; F-49, D15-17 live in `run_flow` |
| `crc_config.py` | kept | D13-23, R-CRC-CONFIG-001.16 |
| `workspace.py` | **dropped** | D-2 keeps the placement function as it is; no writer changes |
| `variant_execution_service.py` (if needed) | **not needed** | the rebinding sits in a new `run_flow` helper around `_resolve_manifest_entry`; **no dependency on Inc 4** |
| — | **`operations/crc.py` added** | D13-20 lives in `crc32_stream` (`crc.py:211`), not in `crc_config.py` / `crc_designer_model.py` as P0 assumed ("same CRC files"). No other increment of the plan owns `crc.py` |

Total: **3 source files** (cap 4).

## 3. Changes to existing canon rows

| Id | Change | Reason |
|---|---|---|
| C-1 · R-FLOW-CRC.1, .3, .4 | "template" → "CRC config file" (`.1`: "from the CRC config file the block names, read as S13 CTX-CRCCONFIG"; `.3`: "If the CRC config file is refused or does not exist"; `.4`: "If the CRC config file is not a valid CRC config"). Behaviour unchanged. | CTX-DESIGNER defines *template* as a CRC Designer algorithm, and CTX-CRC says a template is not a CRC config. The rows used the same word for the CRC config file — the ambiguity (ISO/IEC/IEEE 29148 "unambiguous") that F-28 shows a user falling into. |
| C-2 · CTX-CRCCONFIG | Adds *required field*, *number field*, `<name>`, `<value>`, *Designer template shape* and the template rule text. | R-CRC-CONFIG-001.10/.11 named `<name>` and `<value>` without a definition; "a required field" had no list. Terms only (E6). |
| C-3 · CTX-CRC | Adds *KAT message* and *bit-symmetric init*. | Terms the D13-20 rows and cases use. |
| C-4 · CTX-FLOW | Adds *output file name*, *the copy*, *names*, *in place of*. | Terms of R-FLOW-EXT.9 … .11. |

No canon row's behaviour is weakened. R-CRC-ENGINE-001.1, R-CRC-CONFIG-001.10, .11 and R-FLOW-EXT.2 keep their text; the code is brought to them.

## 4. Decisions

**D-1 · F-28: recognise and refuse, do not read (needs orchestrator ratification).** The plan's title says the CRC block "reads" Designer templates. A template holds an algorithm only — no region, no group, no output address — so a CRC block cannot compute or write anything from it alone, and the Designer's algorithms (width 8 … 64, refin ≠ refout) do not fit the operation's 32-bit engine either. Alternatives:
- **A (chosen)** — the CRC config reader recognises the Designer template shape and gives one reason that says what the file is and what is missing (R-CRC-CONFIG-001.16); the Flow CRC block shows it through R-FLOW-CRC.4. One check in `_build_config`; the Operations dialog gets the same reason when a template is loaded into its config editor. Consistent with CTX-CRC ("a CRC Designer template is not a CRC config, and the CRC operation cannot use one").
- B — a CRC config may carry a Designer `algorithm` object (or a reference to a template) in place of its four flat parameters: a new file shape on an untrusted input (PLAN B4/C6), an up-conversion limited to width 32 and refin = refout, and still no UI to add regions. Rejected for this batch: scope and surface, and the user still edits JSON by hand.
- C — a CRC block field for the regions: a builder UI change (operator ruling: no UI work in batch-101).
What would change the recommendation: the operator wants templates usable in flows in v1.0.0 → B in a later batch with a prototype round (backlog BL-I8-1).

**D-2 · F-49: read this run's copy ("rebind"), not "rotate" or "overwrite" (E3 rules; P0 recommended rotate).**

| | Rebind (chosen) | Rotate (P0) | Overwrite |
|---|---|---|---|
| What happens | the copy lands as today (`_1` for different content, reuse for the same); later refs that name the output file name read that copy | the earlier copy is renamed to `_<N>`, the new output lands under the output file name | the new output replaces the earlier copy |
| Placement immutability (LLR-155.3 as amended by LED .7: "no in-app writer replaces or deletes a placed file"; the basis of the placement's race-freeness, `workspace.py:1112-1115`) | kept | **broken** (rename of a placed file) | **broken** |
| Earlier reports (B2 fired: "reader census owed") | each report still names a file with the bytes it used | every earlier report and manifest entry that names the output file name now points at newer bytes | same as rotate, and the old bytes are gone |
| Backlog A-01 (writers bypass the manifest writer) | no new writer | a new rename writer into the project folder | a new overwrite writer |
| Files | `flow_execution_service.py` only | + `workspace.py` (shared by 15 call sites in 7 files) | + `workspace.py` |
| User-visible cost | on disk the output file name still holds the first copy; the block summary names the copy (`output copied to step.changes_1.json`), and the report names it (R-FLOW-EXT.10) | the folder looks "current" by name | the folder looks current; history lost |
| Matches the model's own contract | yes: `flow_model.ExternalStepBlock` says "the confirmation records the copied path so downstream blocks reference THAT copy" | — | — |

Risks of rebind: (1) a file opened by hand outside the flow under the output file name is the first copy, not the newest — mitigated by the block summary and R-FLOW-EXT.10, and the guide text of 18.9 must change (docs, outside `s19_app/`; backlog BL-I8-3); (2) the rule is by name only — a later ref that names the numbered copy (`_1`) explicitly reads that file, unbound. R-FLOW-EXT.11 pins the decision so that E3 can overrule it with one row flip.

**D-3 · D13-20: no runtime notice for configs whose meaning changes.** A finding in every CRC result that has `reverse: true` and an init that is not bit-symmetric would be new visible text on every such run forever, for a case no shipped file or test has. Instead: a release-note line for v1.0.0 (outside `s19_app/`, the orchestrator's batch-end page) saying which configs change and how to keep the old value (init := bit-reversed old init; exact for every input, B: 200/200 random inputs). Overrule if the operator knows of deployed configs with such an init.

**D-4 · D13-23: the CRC template reader's half is deferred.** CODE-CHANGES D13-23 names "CRC config and CRC template readers". The template reader (`crc_designer_model.parse_template` / `_build_algorithm`) has no canon row with a fixed text (CTX-DESIGNER gives only `CRC template is structurally invalid: <rule>`), its message reaches the Designer's Load / Save status, and it is a fourth file. Kept out; backlog BL-I8-4 (D13-23 status: "partly done: config reader, batch-101 Inc 8").

**D-5 · D15-17: a relative output path is joined, not contained.** The output is joined under the project folder exactly as the log is (`:1090-1091`); `..` is not refused. An absolute output path anywhere is already accepted by design (the output lives outside the project, `flow_model.py:483`), the file is only read, and the copy's destination keeps the placement guard. A containment check would refuse less than an absolute path can already do.

**D-6 · D13-20: one-line seed fix, not delegation to the Designer engine.** `crc32_stream` keeps its zlib fast path and its loop; only the seed changes (`reg = init & 0xFFFFFFFF` in both branches). Delegating to `crc_kernel.crc_lut` would single-source the two engines (and speed up non-default parameters) but touches a hot path for no requirement; R-CRC-ENGINE-002.2 holds the two engines together by test instead.

**D-7 · `<name>` is the key only.** For a nested field the reason says `field 'start' is missing`, without `region 2`. That is the canon text; a `<where>` prefix would change R-CRC-CONFIG-001.10/.11 for every field. Noted for the requirements session, not changed here.

## 5. Observations for E3 (not in scope)

- **O-1 (C6, untrusted input).** The Flow CRC block reads the config with `path.read_text(encoding="utf-8")` (`flow_execution_service.py:810-812`): no read limit (CTX-CRCCONFIG "read limit 256 MiB") and a non-UTF-8 file raises inside the block's `try`. The Operations dialog uses `read_crc_config_text`, which applies both. A one-line reuse would close it; not taken without a row (backlog BL-I8-5).
- **O-2.** `<value>` (R-CRC-CONFIG-001.11) has no length bound: a 1 MB string in a number field gives a 1 MB reason in the result area. The canon has no bound; E3 may add one.
- **O-3.** `_build_config` numbers a non-object region from 0 (`region 0 must be a JSON object`) — D13-21, out of scope.

## 6. Interfaces with other increments

| Increment | Shared | Interface |
|---|---|---|
| Inc 9 (F-45, F-46) | `flow_execution_service.py` (Inc 9 waits for Inc 8, PLAN) | disjoint functions: Inc 8 changes `run_flow` and adds `_resolve_block_ref`; Inc 9 is expected in `run_chain_set` / `write_chain_set_report`. Inc 9's chain-set report reads `ChainRunOutcome.change_records[*].change_doc_ref`, whose value R-FLOW-EXT.10 changes for a rebound PATCH (a file name instead of the typed ref) |
| Inc 7 (D14-10, Markdown escaping) | `diff_report_service.py` reads `FlowChangeRecord.change_doc_ref` (`:1166`, `:1243`) | value only: a plain project file name; Inc 7's escaping applies unchanged |
| Inc 4 | `variant_execution_service.py` | **none**: `_resolve_manifest_entry` is called, not changed |
| Inc 13 | CRC Designer view | none: the Designer engine (`crc_kernel`) is not changed |
| Inc 14 | `window_help.py:234` help line for the CRC template field | text only; BL-I8-2 is a candidate for Inc 14 if it stays text |

## 7. Backlog rows proposed

- **BL-I8-1** — Flow CRC block that uses a CRC Designer template's algorithm with regions from a CRC config or the block (D-1 B/C); needs a prototype round.
- **BL-I8-2** — Flow Builder field label `CRC template` and help line `window_help.py:234` say "template" for a CRC config file (UI text; known-failed family KF-101).
- **BL-I8-3** — user guide ch17.11 / ch18.9 text: "the later block still reads the first copy" becomes "reads this run's copy"; remove the workaround sentence (docs).
- **BL-I8-4** — D13-23 template-reader half (`crc_designer_model._build_algorithm`): name the field in "missing" / "not a number"; needs a CTX-DESIGNER row.
- **BL-I8-5** — O-1: Flow CRC block reads its config through `read_crc_config_text` (read limit, decode error as a reason).

## Orchestrator rulings after E1/E2 (2026-11-02)

- D-1 accepted: F-28 is fixed by recognising a CRC Designer template and refusing it with its own reason (R-CRC-CONFIG-001.16). Reading templates in flows is new format/UI work: BL-I8-1, a later batch with a prototype round.
- D-2 accepted for E3 to challenge: rebind (a later block reads this run's copy) over rotate, for the reasons recorded (immutability of placements, report integrity, no new writer).
- D-3 accepted: no runtime notice for saved configs whose CRC changes (reverse true with a non-bit-symmetric init); a v1.0.0 release note states the change and the exact migration (set init to the bit-reversed old value). The operator is told.
- D-4 accepted: the template-reader half of D13-23 is deferred (BL-I8-4).
- Interfaces: Inc 9 and Inc 7 are told that R-FLOW-EXT.10 changes `change_doc_ref`'s value; Inc 14 owns the help line (BL-I8-2).
- Slice change accepted: crc.py replaces workspace.py (3 source files).
