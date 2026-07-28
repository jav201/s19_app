# batch-64 — What changed, functionally

**For a technical reader who did not run the batch. Nothing in the application changed; what changed is
the set of rules that govern how future batches are gated.**

---

## The problem

batch-63 shipped a correct fix and, in the process, produced **five acceptance criteria that verified
nothing** — for a single defect, three of them written *after* the batch had already identified
vacuity as its own theme. Every one was *correct*: valid arithmetic, complete input set, measured
threshold. They failed for a reason none of the existing controls reaches.

The controls in place mutate different things: **C-10** mutates the code, **C-31** mutates the input
set, **C-39** executes the threshold. A predicate can satisfy all three, be arithmetically exact,
quantify over a derived complete set, carry a measured number — **and still never mention the component
under test.** Those five predicates each related two pure functions of the same input while the thing
being fixed, the file writer, never appeared in the expression at all.

## What now exists

### C-40 — falsifiability before correctness (global, Phase 1)

*"Can this predicate go RED?"* is a **separate gate question** from *"is this predicate correct?"*, and
it is answered at authoring time, by execution. Every acceptance-bearing predicate — an `AT`, an `LLR`
acceptance clause, a `TC`, **and any measurement probe a gate is keyed on** — must satisfy two limbs:

- **Limb 1 — the declared subject must appear in the expression.** Name the subject the predicate
  *itself declares* it certifies, then confirm that subject is in the predicate's own expression. A
  predicate whose value is **invariant under the change it gates** cannot gate it, however exact its
  arithmetic. *Corollary:* when the declared subject is not the subject of the change, the predicate is
  a **regression PIN, not a gate** — keep it and label it so.
- **Limb 2 — a quantified set must come from the RULE, not the implementation.** A set drawn from what
  the code currently handles makes the check a tautology certifying a completeness the code lacks.

Two named instances are absorbed inside it rather than encoded separately: **(i)** a positive control
shaped to the implementation instead of the rule; **(ii)** a consolidation that drops observables.

Discharge for both limbs: name the mutation, **execute it, paste the transcript** — and **run it where
no other session is reading, then restore it before the next gate, confirming the restore in the same
transcript.**

### The C-35 rider — assert against what the producer emits (global, Phase 1)

Executing the producer is not enough if the predicate is then written against the **rendered** form.
Producers escape, encode, wrap and substitute, so confirming a named output *exists* passes while a
search for its readable form **false-fails a correct implementation**. Prefer a predicate over the
producer's own structured output — its parser's token stream, a language-aware parse — to a substring
search over serialized text, because a substring search cannot tell a value from its own encoding.

*(Encoded as a rider rather than the originally-planned new control `C-41`, because it measured ~70 %
overlap with the existing C-35. The id `C-41` remains free.)*

### C-42 — the same rule, made concrete for this stack (`docs/engineering-rules.md`)

Five mechanics, each with its own discharge: markup **token types** over substring presence, including
entity spoofing of a structural delimiter; **the escaped form of a character is not the character**; a
heading emitted inside a code-span wrapper; entity-bearing snapshot export text; and a language-aware
source parse over a line regex.

### `tui-design` skill — `VERIFY.md` extended, not appended to

The skill already said *"assert on a runtime value, never on the presence of a label."* That is
**necessary but not sufficient**, and this batch has the counterexample: a substring search over SVG
source **is** a runtime value, satisfies the rule completely, and returns **0/29** against a correct
implementation while the emitted entity form returns **29/29**. The extension is one step deeper: pin
the truth **in the form the producer emits it**. General knowledge only — zero project identifiers.

### Registry hygiene

The lineage record now registers C-40, C-42 and the rider, back-registers **C-29** (which had been
encoded but unregistered), and records P-6/P-7 as **ABSORBED**, P-3 as **DECOMPOSED**, and **C-41 as
not consumed**. `BACKLOG.md`'s footer, which had claimed `C-1..C-36`, now carries the measured space.

## How it was validated

Not by checking the text is present — that is the prose-presence check this batch exists to prevent.
Acceptance was keyed on whether the encoded rule **discriminates** over a labelled corpus: batch-63's
documented vacuous predicates as the positive arm, its genuinely load-bearing ones as the negative arm.

**Result: 9/9 positive, 1/6 negative under the CI-normative domain (0/5 reclassified).** Deleting limb 2
drops it to 4/6, losing exactly the absorbed P-6/P-7 content. Keying limb 1 on the wrong subject
produces a false positive. Both arms can fail, and both did under mutation.

## What this cost, and what it found

**+26 334 bytes across five files. Zero production code, zero test changes.** The suite is unchanged at
2 201 passing.

Applying the candidate control to batch-63's corpus surfaced **two tautological assertions live on
`main`** — one asserting `raw == raw.decode().encode()`, an identity for any valid UTF-8, behind a
docstring claiming to be *"the clause that fails on a text-mode writer."* Both passed three 0-HIGH
gates. C-10, C-31 and C-39 all miss them. They are carried to the backlog, not fixed here.
