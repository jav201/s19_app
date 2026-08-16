# Blind spot — the assembled selector

> **Written 2026-08-16, at the close of batch-83.** Cut against `origin/main` = `65f3dde`.
>
> **This document states a PROBLEM and a MEASUREMENT PLAN. It does not state state.**
> Every figure below is reproducible by a command that is named next to it. If a number here
> disagrees with what the command prints today, **the command is right and this file is stale** —
> that is the failure mode this project has now found seven times, and the reason nothing here is
> copied from a previous document.

---

## 0 · Verify before reading further

```bash
python tools/address_census.py
python -m pytest tests/test_address_census.py -q
```

Expected at the cut: 23 guards green · `literal 1335 · name 183 · fstring 56` · 16 loose ·
0 indirect. **A mismatch is not necessarily drift** — the tree moves. It means re-derive, not
that something broke.

---

## 1 · What the blind spot IS, stated precisely

batch-83 shipped a detector that recognises **the site** of an address it cannot resolve. It has
three nets, and **all three key on the SHAPE of the selector**:

| Net | Catches | Anchored on |
|---|---|---|
| `census_source` | `query_one(f"#{x}")` | f-string in an address argument, shape starts `#`/`.` |
| loose rows | `msg = f"#{x} is wrong"` | selector-shaped f-string anywhere |
| `find_indirect_addresses` (`AT-B83-10`) | `sel = f"#{x}"` → `query_one(sel)` | selector-shaped f-string assigned, then used |

**A selector assembled from parts, where no part has selector shape, escapes all three.** Two
distinct escapes, and they are not the same bug:

```python
# ESCAPE 1 — f-string with no selector shape
prefix = "#panel_"
sel = f"{prefix}{name}"      # shape is "{}{}" -> SELECTOR_RE does not match
app.query_one(sel)           # argument is a bare Name -> form "name"

# ESCAPE 2 — concatenation assigned before use
sel = "#" + widget_id        # a BinOp, but NOT in an address argument
app.query_one(sel)           # argument is a bare Name -> form "name"
```

⚠ **`AT-B83-08` does NOT cover escape 2, and it is easy to think it does.** That guard fires on
`query_one("#" + name)` — a `BinOp` **directly in the argument**. Assign it to a variable first and
the argument becomes a `Name`; the guard stays green. **Executed at the cut, not reasoned:**

```
query_one("#" + wid)                    forms=['other:BinOp']  loose=0  indirect=0   <- caught
sel = "#" + wid   ; query_one(sel)      forms=['name']         loose=0  indirect=0   <- ESCAPES
sel = f"{p}{s}"   ; query_one(sel)      forms=['name']         loose=0  indirect=0   <- ESCAPES
```

Reproduce it with `census_source` and `find_indirect_addresses` on those three snippets before
planning anything. If it no longer holds, the size of this work changed.

**Where they land:** both become an argument of form `name`, **indistinguishable from
`query_one(Input)`** — type-addressing, which the report calls resolvable and dismisses.

---

## 2 · Why this is worth measuring rather than assuming

The census currently reports **56** computed addresses and that number has held across eight
measurements and four different API sets. **It is a lower bound, not a total.** Every assembled
selector is a computed address the report does not count, and batch-82 is about to size a retrofit
from it.

The honest framing: *we know the detector under-reports; we do not know by how much.* A retrofit
scoped on a number known to be incomplete is scoped wrong in one direction only.

---

## 3 · The measurement, and it is BOUNDED

**Do not scan the tree for assembled selectors.** The population is already known and it is small:

> **41 address arguments are a bare name that is NOT class-like.** Every assembled selector must
> be one of them, because both escapes end as a bare-name argument.

Reproduce the list:

```bash
python -c "
from pathlib import Path
from tools.address_census import census, resolves_to_class_like
d = census(Path('.'))
for s in d.sites:
    if s.form == 'name' and not resolves_to_class_like(s.shape or ''):
        print(f'{s.file}:{s.line}  {s.api}({s.shape})')
"
```

At the cut, grouped by identifier — **`_B78_RUN_ENTRY` 12 · `selector` 8 · `target` 4 ·
`select_id` 3 · `row` 3 · `_B78_RUN_NOTE` 2**, plus nine singletons (`widget_id`, `container_id`,
`layout_id`, `gap`, `row_id`, `item`, `note`, `wid`, `button_id`).

**The work is: for each of the 41, resolve where the value comes from.** Four outcomes, and the
classification IS the deliverable:

| Outcome | Meaning | Action |
|---|---|---|
| **A · module constant bound to a literal** | e.g. `_B78_RUN_ENTRY = "#run_entry"` | resolvable by grep — **not** a blind spot |
| **B · assembled** (f-string without selector shape, `+`, `.format()`, `%`) | the blind spot, confirmed | count it; it belongs in the 56 |
| **C · function parameter** | the caller decides | follow one hop to the call sites, or declare it unresolved |
| **D · something else** | subscript, call, comprehension | classify individually, do not lump |

**A prediction, written so it can be wrong:** most of the 41 will be **A** — `_B78_RUN_ENTRY` and
`_B78_RUN_NOTE` are 14 of them and look like module constants. If that holds, the blind spot is
small and the 56 is nearly complete. **If it does not hold, the 56 is materially wrong and
batch-82's sizing changes.** Either result is worth having; only the assumption is not.

---

## 4 · What NOT to do — every one of these cost time in batch-83

1. **Do not write a fourth net keyed on shape.** That is what leaves the hole. If a detector is
   built, it must key on *where the value comes from*, not on what it looks like.
2. **Do not quote a total without its definition.** `2503` and `2499` were both correct — they
   differed by 4 `double_click` arguments because they used different API sets. A total without
   its API set is not a measurement.
3. **Do not trust a criterion that has not been run against real code.** A criterion of "starts
   with `#` or `.`" swept in markdown headings, prose ellipsis, hex colours and **Python format
   specs** (`f"{v:#x}"` parses its `:#x` as a nested `JoinedStr` — 12 of those exist), and inflated
   the population by 2.5×.
4. **Do not let one filter live in two places.** batch-83's candidate filter ran in one derivation
   pass and not the other; three private methods walked back in and nothing failed. It surfaced
   only because the rule predicted 40 and the output showed 43.
5. **Do not assert a count over the tree in a guard.** `== 56` breaks on every legitimate change
   and proves nothing. Assert shape, membership, completeness.
6. **Re-derive, never copy.** Four figures in batch-83's own spec were wrong, and every one was a
   number carried in prose from the script that produced it.

---

## 5 · Success criterion

The batch is done when **each of the 41 has a classification with its evidence**, and the report
either counts the confirmed assembled selectors alongside the 56 or states why it cannot. **A
number with a definition beats a detector without one** — and if the measurement shows the blind
spot is empty, that finding closes the P2 and is worth exactly as much.

**What this batch is NOT:** it is not the batch-82 retrofit, and it is not a licence to refactor
the 41 sites into a registry. Measure first. The registry question (the operator's own proposal:
a dictionary of ids with a naming convention plus an existence check) is batch-82's, and it is
better decided with this number in hand.

---

## 6 · Where things live

| | |
|---|---|
| the tool | `tools/address_census.py` |
| its guards | `tests/test_address_census.py` (`AT-B83-01`..`AT-B83-12`) |
| batch-83's spec, CLOSED, with its risks and reopening criteria | `.fast-dev-flow/spec.md` §9 |
| this item, registered P2 | `.dev-flow/BACKLOG-CODE.md`, section `batch-83 close` |
| id allocation | batch-scoped (`AT-B84-*`), **no registry reservation owed** — spec §2.3 |

**Flow state at the cut:** `rev33` · `flow_hash d851576cfe8f60b3` · three checkouts clean. Verify
with `python ~/.claude/docs/tools/devflow-validate.py --map --fetch`, do not trust this line.
