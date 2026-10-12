# CHUNK — Kimi K2.7-code — batch-91 increment 001 (the foundation adoption)

You implement batch-91's increment 001 in `C:/Users/jjgh8/Github/s19_app`:
the foundation engines' contract adoption — docstring tokens in the existing test
modules + the LIVE registry entries.

## READ FIRST
- The contract: `.dev-flow/2026-10-08-batch-91/01-requirements.md` — HLR-122 and
  LLR-122.1..122.5: each LLR names its TC range AND the adopting test modules.
- The registry grammar: `.dev-flow/AT-TC-REGISTRY-SPEC.md` and
  `tools/id_registry.py` (the shared library — READ how LIVE entries are shaped:
  the `_meta` record's token pattern, an existing LIVE entry's fields
  (`id, space, status, conforming, origin, statement, nodes`)).
- The reserved block: `AT-284..287`, `TC-617..650` already RESERVED in
  `AT-TC-REGISTRY.jsonl` (origin/reserved_by: batch-91) — your LIVE entries REPLACE
  the RESERVED ones for the ids you adopt (same id, status LIVE, the statement from
  the contract, nodes = the adopting test module's functions).

## SANDBOX
- NEVER write or run outside the project tree: no /tmp, no site-packages. Scratch
  under `.dev-flow/2026-10-08-batch-91/evidence/`. No git.

## THE WORK — `tests/*.py` docstring lines + `AT-TC-REGISTRY.jsonl` ONLY.

For EACH TC in the LLR-122.1..122.5 lists (TC-617..TC-648), and its adopting
module(s):

1. **Docstring token**: in each adopting module, the module docstring gains the
   TC's DASH-form id and a one-line mapping, e.g. `# TC-617` inside the docstring
   (the registry's token pattern reads the dash form — check `tools/id_registry.py`'s
   tokenizer, `iter_tokens`, before writing). NEVER touch a test's code, fixtures,
   or assertions — docstring/comment lines only.
2. **Registry entry**: append the LIVE entry for the TC: statement = the LLR's
   pinned law (short, from the contract), `nodes` = the module's test functions in
   the registry's `file::function` shape (derive them per `tools/id_registry.py`'s
   `derive_named_nodes` — read it and derive exactly its way; a node that doesn't
   exist on disk is a lie), `origin: batch-91`, `conforming: true`.
3. **AT-284** (the adoption-completeness acceptance): a NEW test
   `tests/test_id_registry.py`-style arm is NOT yours — write instead
   `tests/test_batch91_adoption.py`: asserts every TC in the batch's reserved range
   TC-617..TC-648 (a) is LIVE in the registry with a non-empty nodes list, and
   (b) every named node exists on disk (parse the file::function pairs and verify
   the function is defined). Docstring carries `AT-284` (dash form). This is the
   batch's only new test file.

## DISCIPLINE
- Before writing any node: derive it with the library, not by hand. A hand-written
  node path that disagrees with `derive_named_nodes` fails the batch.
- Run after each area: `python -m pytest <the modules you just touched> -q -p no:cacheprovider`
  — byte-identical green (you only added docstring lines).
- Then: `python -m pytest tests/test_id_registry.py tests/test_batch91_adoption.py -q -p no:cacheprovider`.
- Do NOT run the full suite (the coordinator owns it).
- The reserved entries you convert to LIVE: REPLACE the RESERVED line in place
  (same id, no duplicates) — do not append a second line for the same id.

## REPORT BACK
The TC→module map you wrote (one line each), the registry entries' count
(RESERVED→LIVE conversions), the per-area suite runs, anything punted.
