# C-54 — the Information Flow Contract (IFC)

**Status:** DESIGN INCREMENT — awaiting operator approval before any edit to the global flow
**Date:** 2026-08-13 · **Lane:** B (process) · **Origin:** batch-79's `LLR-120.2` defect
**Encodes into:** `~/.claude/commands/dev-flow.md` + `fast-dev-flow.md` (global, versioned, shared asset)

---

## 1 · The defect this exists to prevent, measured

`LLR-120.2` (batch-78 spec) reads:

> **Statement:** `LoadedArtifactsPanel` **shall** render a row naming the active project, and **shall
> not** alter the existing three artifact slots.
> **Numeric pass threshold:** project name present (today absent); the three slot rows' text
> unchanged (**set equality**)

The implementation gave the new row the `loaded-detail` class — the class the three artifact slots
carry. Two shipped readers select on it and index **positionally** as `[primary, mac, a2l]`. The
query began returning four cells with the project at index 0.

**Apply the threshold as written:** the three slot rows' text is *identical*. Set equality **holds**.
Six shipped tests broke anyway.

### Why the requirement could not catch it

| | |
|---|---|
| What the requirement declared | the **value** displayed |
| What the failure changed | the **address** by which the value is reached |
| The oracle it chose | **set equality** — the operation that discards order, which is precisely where the failure lived |

This is **not** a vacuous check. The predicate could fail; it measured a property that is *true in the
failing case*. Call it a **misaddressed observable**. It needs a different fix from a vacuous one.

**And the missing information is nameable:** the requirement never states the panel's contract with
its consumers. *"Shall not alter X"* — altered **for whom**? For a human reading the panel, nothing
was altered. That information existed (`test_unload_feature.py::_detail_texts` documents itself as
"the through-surface reader") and the requirement had no field to hold it.

> A `shall not alter X` is not verified by observing X. It is verified by observing **the contract by
> which others depend on X** — and that contract has to be written down, with its consumers named.

---

## 2 · The generalisation — operator ruling, 2026-08-13

The first draft of this control was scoped to UI/UX. **The operator rejected that framing and it was
right to.** Restated:

> *"Es una estructura para modelar la entrada y salida de información a un sistema. Entonces UI/UX
> ES un sistema."*

The same mechanism serves **data acquisition, sensor arrays, and any bounded subsystem that ingests
or emits information**. Scoping it to UI would have made the global flow stack-aware — violating the
standing rule that flows stay project-agnostic — and would have missed most of its range.

### Two distinct structures, not one

| | Structure | Applies |
|---|---|---|
| **Part A** | **Flow** — sources → transforms → sinks, each node bound to a requirement | **ALWAYS.** *"Los flujos de información siempre existen"* |
| **Part B** | **Boundary decomposition** — nested components with `⊆` containment, address and consumers | **CONDITIONAL** |

**Both terminate in their own HLRs and LLRs.** They are not layers of one artifact; they are two
artifacts with different obligations, and a project may owe only the first.

### The trigger for Part B — agnostic, one question

> **Does the system's boundary have components that a consumer can address independently?**

| System | Part B? | Why |
|---|---|---|
| TUI with screens and panels | ✅ | a consumer selects `#loaded_panel` and indexes its children |
| Sensor array | ✅ | channel 3 is addressable independently of channel 4 |
| DAQ card with per-channel calibration | ✅ | each channel has its own I/O and its own transform chain |
| Headless library, one entry point | ❌ | no decomposable boundary — Part A alone |
| CLI emitting one report to stdout | ❌ | one sink, no addressable sub-components |

**If a project has no addressable boundary components, it owes Part A and nothing else.** That is the
modularity condition the operator asked for, stated so a validator can apply it.

---

## 3 · Schema

### Part A — Flow (mandatory)

```
FLOW: <id>
  SOURCE  : <where information enters the system boundary>
  NODES   :
    - fn        : <the function that performs this transform>
      owner     : <LLR that owns this transform>
      in  / out : <shape in, shape out>
  SINK    : <where information leaves the system boundary>
```

**Two obligations that make it more than documentation:**
- a node with **no `owner`** is unowned work — it exists in code and no requirement asked for it;
- an LLR that claims a transform with **no node** is unimplemented.

Both are mechanically checkable and neither is checkable today.

### Part B — Boundary decomposition (conditional)

```
COMPONENT: <id>
  PARENT : <parent component | SYSTEM>
  INPUTS : ⊆ PARENT.INPUTS
  OUTPUTS:
    - id        : <name>
      value     : <what it carries>
      address   : <HOW A CONSUMER REACHES IT — selector, index, channel, offset>
      cardinality: <expected count, when the address selects a set>
      consumers : <who depends on this address>
      owner     : <LLR>
```

**`address` and `consumers` are the two fields the flow has never had, and the two that would have
caught `LLR-120.2`.**

- **`address`** — changing it is a breaking change *even when the value is unchanged*. That is
  exactly the batch-79 failure, and it becomes a declared contract change rather than an accident.
- **`consumers`** — turns `shall not alter X` from unverifiable prose into a mechanical question:
  *do these consumers still resolve?*
- **`⊆ PARENT`** — a component cannot consume or emit what its parent does not declare. This is the
  contractual relationship the operator specified.

---

## 4 · Worked example — the actual defect, before and after

### Before (what `LLR-120.2` said)

```
shall render a row naming the active project
shall not alter the existing three artifact slots
threshold: the three slot rows' text unchanged (set equality)
```

→ satisfied by the implementation that broke six tests.

### After (Part B)

```
COMPONENT: loaded_panel
  PARENT : screen_workspace
  INPUTS : current_file: LoadedFile|None ; project_label: str
  OUTPUTS:
    - id: artifact_slots
      value      : slot texts for primary, mac, a2l
      address    : query(".loaded-detail"), INDEXED POSITIONALLY
      cardinality: 3
      consumers  : test_unload_feature.py::_detail_texts
                   test_help_toggle_and_a2l_panel.py
      owner      : LLR-120.2
    - id: project_row
      value      : project string in its LLR-120.5 display form
      address    : query(".loaded-project-detail")
      cardinality: 1
      consumers  : AT-B78-09
      owner      : LLR-120.2
```

**Adding a fourth `.loaded-detail` cell now violates `cardinality: 3` on a declared contract.** The
value is untouched; the *address* moved; the validator sees it. The eventual real fix — a separate
`loaded-project-detail` class — is what the schema forces you to write down in advance.

### The generalisation holds on a different system

```
COMPONENT: thermocouple_array
  PARENT : SYSTEM
  INPUTS : raw_counts: int16[8] ; cjc_temp: float
  OUTPUTS:
    - id: channel_temps
      value      : °C per channel
      address    : channels[0..7], INDEXED POSITIONALLY
      cardinality: 8
      consumers  : trend_logger, alarm_evaluator
      owner      : LLR-SENSE-4

FLOW: channel_temps
  SOURCE: ADC raw counts
  NODES :
    - fn: apply_gain_offset   owner: LLR-SENSE-2   in: int16 → out: mV
    - fn: cjc_compensate      owner: LLR-SENSE-3   in: mV    → out: mV
    - fn: type_k_polynomial   owner: LLR-SENSE-4   in: mV    → out: °C
  SINK  : channel_temps
```

Adding a ninth channel breaks `cardinality: 8` and every positional consumer — **the identical defect
shape, in a system with no UI at all.** That is the evidence the generalisation is real and not a
retrofit.

---

## 5 · Global vs project split — required by standing rule

> *Global flows stay project-agnostic — stack-specific controls go to the project's
> `docs/engineering-rules.md`, never the global command.*

| Layer | Owns |
|---|---|
| **Global** (`~/.claude/commands/`) | The **obligation** and the **semantics**: Part A always; Part B when the trigger question is yes; the field set (`address`, `cardinality`, `consumers`, `owner`); `⊆` containment; every node bound to a requirement |
| **Project** (`docs/engineering-rules.md`) | The **vocabulary**: what an `address` looks like in this stack (`query(".cls")`, `channels[n]`, a register offset), the file format, and the validator rules |

Nothing in the global layer names Textual, CSS, pytest or a widget. **The trigger question and the
field set are stack-free by construction** — which is what the operator's reframe bought.

---

## 6 · Validator rules (proposed — `devflow-validate.py`)

Prose alone would reproduce this session's dominant defect class. Proposed rules, in the existing
`V*` idiom:

| Rule | Severity | Checks |
|---|---|---|
| `V10` | BLOCK | every `FLOW` node declares an `owner`, and that requirement id exists |
| `V11` | BLOCK | every `OUTPUT` declares `address` **and** `consumers` (an explicit `consumers: none` is legal and must be written, not omitted) |
| `V12` | BLOCK | `COMPONENT.INPUTS ⊆ PARENT.INPUTS` and `OUTPUTS ⊆ PARENT.OUTPUTS` |
| `V13` | NOTICE | a requirement of type `test` touching a declared surface with no `IFC` entry |
| `V14` | BLOCK | every `consumers` entry resolves to a node that exists (the `G2` shape, reused) |

**Each rule must demonstrate RED in `--selftest`**, per the validator's own C-40 clause. A rule that
cannot go red is a vacuous check with CI authority.

---

## 7 · Where it enters the flow

- **Phase 1 (requirements):** Part A is authored with the HLR/LLR set. Part B when the trigger fires.
- **PDR / DDR (C-49 stations):** the contract is reviewed as a first-class artifact, not as prose
  inside a requirement.
- **Every gate:** `devflow-validate.py` runs `V10`–`V14` with the rest.
- **`fast-dev-flow`:** Part A only, and only for surfaces the increment touches — the fast flow
  cannot carry the full decomposition without becoming the slow one.

---

## 8 · Decisions — RESOLVED 2026-08-13

### D-1 · File format → `IFC.jsonl` at the repo root

One JSON object per line, matching `AT-TC-REGISTRY.jsonl`'s house idiom, which the validator already
reads. **Nesting is expressed by REFERENCE, never by embedding** — each record carries a `parent`
field rather than containing its children.

```
{"kind":"component","id":"loaded_panel","parent":"screen_workspace","inputs":[…],"outputs":[…]}
{"kind":"flow","id":"project_row","source":"…","nodes":[{"fn":"…","owner":"LLR-120.5"}],"sink":"…"}
```

**Why flat over nested:** a nested tree produces whole-subtree diffs on a one-field change, and the
`⊆` check needs to resolve parents by id anyway. Flat records diff per component and let the
validator build the tree itself.

### D-2 · Retrofit scope → **FULL retrofit**, operator ruling, and the framing changes

The design proposed new-and-modified surfaces only. **The operator overruled it and the reason
reframes the work:**

> *"Aunque me duela, si tenemos que hacer el retrofit… parece que hay mucho potencial para
> requerimientos ambiguos y comportamientos perfilados a medias."*

**So the retrofit's deliverable is not the file — it is the findings.** Authoring an `address` and a
`consumers` list for a surface that has never declared one forces the question *"who depends on this,
and how do they reach it?"* on ~40 surfaces that have never been asked. `LLR-120.2` is one instance
found by accident, at the cost of a production regression. The retrofit is the systematic version of
that same search.

**Staged so it cannot block the queue:** the control ships enforcing only NEW and MODIFIED surfaces
(`V13` as NOTICE), and the retrofit lands per-screen behind it. Existing surfaces are `NOTICE` until
their screen's stage completes, then `BLOCK`. **A big retrofit does not gate unrelated work.**

### D-3 · `C-55` → registered, NOT encoded — the operator's earlier ruling stands

Asked at the control-encode gate, the operator chose **C-54 alone**. That choice is honoured here
rather than quietly widened. `C-55` — *a threshold whose oracle NORMALISES something (set equality
discards order, containment discards arity, concatenation discards structure) must state explicitly
that the failure mode does not live in what it discarded* — stays a registered candidate in
`BACKLOG-PROCESS.md`.

**Re-litigate it after the retrofit**, which is the single best evidence generator this project will
have for it: every normalising threshold it surfaces is a data point.

### D-4 · C-45 propagation → in scope, with its own before/after record

The flow is a shared, versioned asset. batch-82 owes, as declared steps:

1. edit `~/.claude/commands/dev-flow.md` + `fast-dev-flow.md`;
2. add `~/.claude/templates/dev-flow/ifc-template.md`;
3. add rules `V10`–`V14` to `~/.claude/docs/tools/devflow-validate.py`, **each demonstrating RED in
   `--selftest`**;
4. bump `~/.claude/docs/FLOW-VERSION.md` — version, `flow_hash`, control count `C-10…C-54`;
5. **push to `jav201/claude-config`** and verify the mirror;
6. **record before/after in the batch artifacts** — the global command lives OUTSIDE this repo and is
   not covered by its PR flow, so the repo's PR is not evidence that the flow leg landed.

⚠️ Step 6 is the one that gets skipped. `BACKLOG-PROCESS.md`'s own header warns about exactly this.

---

## 9 · What this increment did NOT do

No file outside this document was touched. The global flow, the validator, `FLOW-VERSION.md` and the
project's `engineering-rules.md` are **unchanged**. Implementation is its own batch and needs the four
decisions in §8 resolved first.
