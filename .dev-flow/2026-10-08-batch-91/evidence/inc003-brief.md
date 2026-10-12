# CHUNK — Kimi K2.7-code — batch-91 increment 003 (the registry hygiene)

You implement batch-91's increment 003 in `C:/Users/jjgh8/Github/s19_app`:
the registry's hygiene. Read the contract first:
`.dev-flow/2026-10-08-batch-91/01-requirements.md` — HLR-124 / LLR-124.1/.2.

## SANDBOX
- NEVER write or run outside the project tree: no /tmp, no site-packages. Scratch
  under `.dev-flow/2026-10-08-batch-91/evidence/`. No git.

## THE WORK — `AT-TC-REGISTRY.jsonl` + docstring/comment lines in the named test
## files ONLY. NEVER a test's code, fixtures, or assertions.

1. **LLR-124.1 — AT-043 resolves.** `AT-043` is declared in `REQUIREMENTS.md`
   (find where — grep it) and appears in `tests/test_tui_a2l_issue_recolor.py`, but
   is ABSENT from the registry. Read the declaration and the verifier; then write
   the registry's entry per its grammar (`.dev-flow/AT-TC-REGISTRY-SPEC.md`):
   LIVE with its `nodes` (the verifier's `file::function` pairs, derived per
   `tools/id_registry.py`'s `derive_named_nodes` — NEVER hand-written) — OR RETIRED
   with a real `retired_reason` IF the declaration is superseded (check: does the
   section's text describe a shipped behavior the verifier pins? If yes → LIVE).
   State your decision and why in your report.
2. **LLR-124.2 — the 44 token-invisible LIVE ids carry their tokens.** The registry
   lists them LIVE with `nodes` (already verified). A plain grep can't see the id in
   the verifier's file (spellings like `test_tc016s_*` for `TC-016-S`, `TC-46.1` vs
   `TC-046.1`). For EACH of the 44 (derive the list yourself: every LIVE registry id
   whose dash-form token does NOT occur in the file its nodes name — script it with
   the library, under the evidence dir): add the dash-form id to the verifier
   function's docstring (or the module docstring if the verifier is a module-level
   cluster), one line, e.g. `# TC-016-S` — nothing else touched. The renames are
   NOT function renames — docstring tokens only (the registry reads content tokens;
   a function rename risks a stale node).
3. **AT-286** — the hygiene's acceptance: `tests/test_batch91_registry_hygiene.py`
   (new, the batch's only new test file besides inc-001's): (a) every LIVE registry
   id's dash token occurs in the file its nodes name; (b) AT-043's entry exists with
   a status the grammar accepts; (c) no id in the registry is declared in
   REQUIREMENTS.md and absent (the cross-artifact census: grep REQUIREMENTS.md for
   AT/TC dash tokens, compare against the registry). Docstring carries `AT-286`.

## DISCIPLINE
- `python -m pytest tests/test_id_registry.py tests/test_batch91_registry_hygiene.py -q -p no:cacheprovider`
  green at the end. Do NOT run the full suite.
- The registry file: only the AT-043 entry line changes (add or mark) — the 44
  invisible ids' entries stay as shipped (their nodes are already right).

## REPORT BACK
The AT-043 decision (LIVE or RETIRED + why), the 44-token adoption list (one line
each: id → file), the hygiene test's arms, anything punted.
