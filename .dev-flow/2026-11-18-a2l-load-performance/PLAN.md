# A2L load performance — batch plan

Base: `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c` (`main` at batch opening).
Flow: dev-flow v0.3.0 / dev-flow v3; Code-Wire v3.2.0.
Code-Wire home: `$HOME/Github/code-wire`, commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05`.
Flow currency: local `SKILL.md` and `trace_check.py` equal the v0.3.0 blobs after CRLF/LF normalization; normalized SHA-256 respectively `6d70ab35791599ea054cadb6522d211fe1271ee4c596cdf45dd9cb335406d344` and `d9a28719bc623e5d9406f2c0ae164d5eb9b64a2869f4412b0d1495d1532f5e92`.

## Commission

Make real and large A2L loads usable: remove quadratic occupancy work, keep the UI responsive throughout post-parse preparation, and preserve reading, aliases, homonyms, definitions, formats and write safety. Prove the result through the real load routes before promotion.

The approved design input is the exploratory prototype: the current global candidate scan is quadratic on disjoint objects; a compact interval index that returns the next overlap in file order processed all 220,040 `case_06` entries in the isolated experiment. That experiment is not integrated-product evidence. E1 must provide a repeatable script and durable generated evidence.

No visual or interaction change is commissioned. If such a change appears, the affected increment stops before E1 for a UI prototype round and operator verdict.

## Stories

### US-ALP-01 — large A2L loads remain usable

As the operator, I want a large A2L to load within a measured budget while the application continues responding, so that I can work without a blocked interface.

Existing stories whose contracts remain binding:

- US-103-02: every A2L-dependent view shows the current generation without manual refresh.
- US-103-04: the shared picker reports true declared sizes and formats.
- US-103-05: editing by definition preserves arrays, axes, masks and overlap safety.
- US-103-07: the reader reads the A2L as written.

## Increment list and order

| Inc | User-visible boundary | Stories | Scope | Source budget | Depends |
|---|---|---|---|---|---|
| 1 | Describing a large A2L no longer performs a global span scan per object | US-ALP-01, US-103-05 | A central compact occupancy index; next overlap in `position` order; existing lazy final-span materialization; equivalent `Definition.shared_with`, refusals and encode outcomes. Expected owner file: `s19_app/tui/a2l_definition.py`. | 1 source | none |
| 2 | A direct A2L attach stays responsive during post-parse preparation | US-ALP-01, US-103-02, US-103-04 | Reuse the attach worker for pure enrichment/summary/definition preparation; immutable generation-bound snapshots; UI-only view mutation; common refresh before success. E1 must name and count the exact slice. | at most 4 source | Inc 1 |
| 3 | Image+A2L and project+A2L loads have the same responsiveness without a second implementation | US-ALP-01, US-103-02 | Reuse Inc 2's prepared interface on prepared-load routes; final-pair publication; same-path content reload; stale-generation discard. If the existing routes already meet the requirements without a source edit, close as unnecessary with executed evidence. | at most 4 source | Inc 2 |

Each increment passes E1 requirements, E2 graph, E3 design review, E4 independent implementation/tests and E5 validation before the next source increment starts. Records for all increments live beside this plan.

## Shared interfaces and frozen contracts

1. `Definition.shared_with` keeps its type and meaning. `describe_definition` / `describe_definitions` keep their public signatures and one result per requested name.
2. Object identity in the occupancy index is its section-walk `position`, never name or address alone. Homonyms remain fail-closed under R-A2L-DEF.139.
3. Unknown final length remains a point at the declared address. Final spans, including over-cap and earlier-starting spans, remain candidates.
4. The occupancy structure does not expand a span into every 16-byte page and does not eagerly describe every candidate for a narrow query.
5. `R-PICKER-CORRECT.018/.019` remain: one bulk describe per changed generation per picker and no describes during filter/page rebuilds.
6. Worker requests and results are immutable data with expected A2L/image generations. Workers never access widgets or mutable app state. Every common-refresh view mutation stays on the UI thread.
7. The existing `a2l.py` reader is not edited. No parser rule, alias, homonym, refusal or message is weakened.

## Preserved requirement families

- R-A2L-DEF.58.1/.58.2, .136, .138, .139, .140, .148 and .149.
- R-PICKER-CORRECT.018/.019 and R-PE-DEF.10/.11/.12.
- R-A2L-READ.52.
- R-A2L-REFRESH.001 through .028.
- R-A2L-004.10/.11/.12 and R-BUSY-RUN.1.

E1 adds scale and post-parse responsiveness coverage without replacing existing thresholds. E1 also records the disposition of the existing performance cases against large final spans so an index cannot reintroduce the retired eager/page expansion design.

## Mechanical model allocation

DeepSeek-class workers and the Qwen CLI may perform mechanical censuses, graph extraction/lint, generated transcripts, test execution and mutation runs. Qwen runs headless with a closed stdin, explicit time/tool limits, plan/read-only mode for censuses, and no approval to mutate product. Design decisions, requirements authorship, interface rulings and integration remain with the main conductor and the designated stronger design/review workers. No worker is attributed to a model or command that was not actually executed.

## E2 tooling

Use Code-Wire v3.2.0 directly from its local repository. Layer the applicable batch-100 and batch-103 graphs oldest first, then the new graph. Marks and extraction run only in a throwaway clone. `codewire_lint.py` must return no unread graph line. Each requirement has a concrete graph example and a named owner group; each shared edit has exactly one owner.

## Gates and evidence

- E1: strict EARS, numeric thresholds, negative controls, executed premises and a counted slice.
- E2: graph-only design, lint and extraction findings ruled; no source marks outside a throwaway clone.
- E3: independent design/security review; no open BLOCKER/MAJOR.
- E4: RED on base for every fix, GREEN on the integrated tree, real TUI acceptance and every negative control executed; no unruled survivor or BAD mutation.
- E5: targeted and law-guard suites, independent code/security review, `04-validation.md`, evidence at its declared home and no `trace_check.py` gap.
- Batch end: one orchestrator-owned full suite in sequential chunks, whole-batch extraction, canon fold, operator review page and decision. Push only on approval, then compare remote CI with the previous run.

All evidence records commit, platform and exact command. A guard, skip, inherited failure or unexecuted probe is not a PASS. No real clipboard access and no Windows clipboard arm outside the isolated GitHub-hosted WinCI runner.
