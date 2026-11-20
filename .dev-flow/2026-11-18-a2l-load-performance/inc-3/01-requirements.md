# Inc 3 — Image/project A2L load parity: requirements (E1)

Batch `2026-11-18-a2l-load-performance`, increment 3. E0 commit `d658dfeaa336dea54b99001b52df52fa1fd434d0`; product base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; branch `a2l-load-performance`. Authority: `../PLAN.md` Inc 3, US-ALP-01 and US-103-02, and shared contracts 5–7. Flow: dev-flow v0.3.0. Code-Wire: local commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05`, README status v3.2.

This is a design record, not an execution report. The only executed observations are the separately identified probes under `evidence-e1/`; all requirement cases and negative controls in `02-test-cases.md` are planned and have no result at E1.

## User stories

### US-ALP-01 — large A2L loads remain usable

As the operator, I want a large A2L to load within a measured budget while the application continues responding, so that I can work without a blocked interface.

### US-103-02 — every A2L-dependent view shows the current generation

As the operator, I want every A2L-dependent view to show the current generation after an image or project load, with no manual refresh, so that I never act on a stale or mixed image/A2L state.

## Scope and dependency

**In:** loose image load/reload with an attached A2L; project install with both a primary image and A2L, including an accompanying MAC; project install with A2L only; post-parse responsiveness; use of Inc 2's prepared snapshot; same-path changed-content reload; one final publication; and whole-load stale-snapshot rejection.

**Out:** Inc 1's occupancy index; Inc 2's direct-attach producer and its internal design; parser/reader changes; picker APIs; visual or interaction changes; project-file replacement semantics; clipboard access; and new persistence formats. Existing admission, busy, refusal, read, alias, homonym, definition, format and write-safety contracts remain unchanged.

**Sequential dependency:** the prepared-snapshot interface does not exist on the E0 product base and no premise says that it does. Inc 2 must finish and pin that interface before Inc 3's E2 delta or E4 implementation. Inc 3 specifies only the consumer obligations below, not provider names or provider internals:

1. UI-thread capture supplies explicit source/cache inputs and the required post-install A2L/image generation pair, so the worker reads no live session counters or current artifacts.
2. Worker preparation returns one generation-bound snapshot containing enriched tags, summary lines and prepared definition data; snapshot fields cannot be reassigned after return and payload data is treated as read-only.
3. The direct attach, image and project routes call that same producer interface; Inc 3 adds no second enrichment/summary/definition pipeline.
4. The consumer either installs the whole fresh snapshot or discards the whole candidate; neither a stale snapshot nor a preparation exception permits a synchronous UI-preparation fallback.

## Definitions

```text
prepared snapshot  The immutable generation-bound data value supplied by Inc 2, carrying
                   enriched tags, summary lines, prepared definition data and the expected
                   post-install A2L/image generation pair.
post-parse preparation
                   Enrichment, summary, definition, MAC, validation and render-cache data
                   work after source parsing and before final publication.
final publication  One common A2L-dependent-view refresh against the fully installed state,
                   followed by the route's successful outcome.
image+A2L route    A loose primary-image load or reload while an A2L is attached.
project pair route
                   A project install whose final state contains a primary image and A2L;
                   a MAC may also be present.
A2L-only route     A project install whose final state contains A2L and no primary image/MAC.
same-path changed-content reload
                   A second load of one lexical source path after its bytes change, with no
                   intervening clear; path equality is not content equality.
responsive       Every screen timer fires at most 100 ms after its due time, as canon
                   CTX-PASTE defines it.
```

## Premise evaluation

**Premise evaluation:** six static/disk premises and one fixture premise were executed at E0 `d658dfea`. `TRUE` below means only the stated observation, never runtime compliance or a performance result. Evidence: `evidence-e1/premise-census.txt` and `evidence-e1/case06-probe.txt`.

| Id | Verdict | Premise and executed disk evidence |
|---|---|---|
| P01 | TRUE | HEAD is `d658dfeaa336dea54b99001b52df52fa1fd434d0` and `f44e8bc4` is its ancestor (`premise-census.txt:1`). |
| P02 | TRUE | Canon contains exactly one row for each of REFRESH.002/.003/.004/.005/.014/.023/.026/.028 and no collision with .039–.048 (`premise-census.txt:2`). |
| P03 | TRUE | The file worker currently reads `current_a2l_path`, `current_a2l_data`, `current_file` and both live generation counters (`file_load.py:1240-1248`, `:1518-1522`; `premise-census.txt:36`). |
| P04 | TRUE | `_prepare_project_load` makes zero `_prepare_load_payload` calls, while `_install_prepared_project` constructs non-precomputed image/MAC bundles at `project_load.py:1590` and `:1593` (`premise-census.txt:37`). |
| P05 | TRUE | `_apply_prepared_load` starts executable work with generation preflight at `loaded_state.py:589`, before its `current_file` write at `:619` (`premise-census.txt:38`). |
| P06 | TRUE | Project reset calls the A2L writer at `project_load.py:963`, and every prepared apply increments image generation at `loaded_state.py:642`; project snapshots therefore need stage-specific expectations (`premise-census.txt:39`). |
| P07 | TRUE | Parsing the committed 37,742,888-byte case_06 A2L from this tree produced 220,040 tags, 220,040 distinct names and 0 errors; SHA-256 is `45243458427f43da695f4e01e494d69444c1b921588bcd040cfcaf025fed43d9` (`case06-probe.txt:1-9`). This is a fixture probe, not a load-route timing measurement. |

The AST census covered all 132 `s19_app/**/*.py` files and lists every call to the six load/preparation/publication symbols (`premise-census.txt:3-34`). Its known-present and known-absent controls both discharged (`:35`); three instrument limitations were regenerated through explicit RED cases as `premise-census-initial-red.txt`, `premise-census-second-red.txt` and `premise-census-route-red.txt`, with source redaction. A further reference census covered 498 SOURCE/test files and includes callbacks and exact monkeypatch strings (`premise-census.txt:40-410`). Qwen supplied no census: its initial read-only run aborted with exit 55 after exceeding eight tool calls and subsequent retries also failed (`qwen-census.txt`). Both censuses are the direct AST probe's work. DeepSeek's independent F1–F5 audit was produced through `pi` at `../evidence/deepseek-e1-audit-inc3.txt`; it is an audit input, not a locally executed CLI claim.

## Requirements

Form uses the five EARS forms of dev-flow. Each row has one `shall`, one response and one sentence. Every negative control is a planned reachable mutation with a named wrong observable; none has been executed at E1.

| Id | Form | Requirement | Numeric pass threshold | Negative control | US | Status |
|---|---|---|---|---|---|---|
| R-A2L-REFRESH.039 | U | The system shall prepare A2L enrichment, summary and definition data for direct A2L attach, image+A2L load, project image+A2L load and project A2L-only load through one immutable generation-bound prepared-snapshot interface. | 5/5 routes: direct attach, image+A2L, project pair with MAC, project image+A2L without MAC, A2L-only; exactly one Inc 2 producer-interface call per load, a non-reassignable snapshot, the expected stage-specific generation pair reaching the consumer, and 0 UI enrichment/summary/definition constructions. | Bypass the producer in each parameterized route and call the existing enrichment service directly → that route has 0 producer calls and fails the interface/snapshot assertions → RED. | US-ALP-01, US-103-02 | new |
| R-A2L-REFRESH.040 | When | When the system loads a primary image with case_06 A2L attached, the system shall complete the image+A2L load with a median total duration of at most 80 s over 3 runs and no individual run of 100 s or more on the E1 host (D-14, executed E4 budget) while keeping the screen responsive. | 3/3 serial-timing runs on the E1 host: total runs independently from product-route request before admission/copy to final outcome with parse included, median ≤80 s and every run <100 s (D-14, executed E4 budget); record admission/copy, parse, post-parse preparation and install/publication as 4 separately named phases. The existing timer is unchanged: 50 ms from preparation entry through final publication, every tick ≤100 ms late locally (`timing_bound` on CI), the 0.20 s worker hold supplies ≥3 ticks, and the final pair is current. | Move real preparation and its hold onto UI → timer RED; independently hold an otherwise responsive worker for 105 s → total-run bound RED even when all ticks pass; start total after parse → phase-boundary assertion RED. | US-ALP-01 | new |
| R-A2L-REFRESH.041 | When | When the system loads a project containing a primary image and case_06 A2L, the system shall complete the project load with a median total duration of at most 80 s over 3 runs and no individual run of 100 s or more on the E1 host (D-14, executed E4 budget) while keeping the screen responsive. | 2/2 project shapes, with MAC and without MAC, × 3/3 runs each = 6/6 runs on the E1 host: each shape has median ≤80 s and every run <100 s (D-14, executed E4 budget), with request-to-outcome total including parse and the same 4 separately measured phases as .040. The .040 50 ms/100 ms timer, ≥3 ticks and 0.20 s worker hold are unchanged for every run; each final pair is current. | Leave bundles non-precomputed or move preparation and its hold onto UI → timer/thread RED; independently hold either shape for 105 s with a responsive UI → its total-run bound RED; omit parse or one project shape → phase/shape census RED. | US-ALP-01 | new |
| R-A2L-REFRESH.042 | When | When the system loads an A2L-only project containing case_06, the system shall complete the project load with a median total duration of at most 80 s over 3 runs and no individual run of 100 s or more on the E1 host (D-14, executed E4 budget) while keeping the screen responsive. | 3/3 runs on the E1 host: request-to-outcome total includes parse, median ≤80 s and every run <100 s (D-14, executed E4 budget), with admission, parse, post-parse preparation and install/publication recorded separately (no copy phase for an in-place project). The .040 50 ms/100 ms timer, ≥3 ticks and 0.20 s worker hold are unchanged; final A2L-only state is current and no image/MAC appears. | Move A2L-only preparation and its hold onto UI → timer/thread RED; independently hold a responsive worker for 105 s → total-run bound RED even with passing ticks; exclude parse from total → phase-boundary assertion RED. | US-ALP-01 | new |
| R-A2L-REFRESH.043 | If | If prepared-snapshot creation fails during an image+A2L or project load, then the system shall end the load through its existing failure route without installing the candidate or running A2L preparation synchronously on the UI thread. | 4/4 routes: image+A2L, project pair with MAC, project image+A2L without MAC, A2L-only; inject `ValueError("PREPARE_CONTROL")` at the producer, then assert previous state/views/project hashes unchanged, 0 candidate installs, 0 UI preparation calls and 0 success outcomes. | Restore the image route's minimal `PreparedLoad` fallback or add a project UI fallback → the candidate installs or UI preparation count becomes 1 → RED. | US-ALP-01, US-103-02 | new |
| R-A2L-REFRESH.044 | When | When an image+A2L load completes, the system shall publish the prepared final image+A2L state exactly once before showing the successful load outcome. | 3/3: first image with attached A2L, different-path image replacement, equal-size different-content image replacement; exactly 1 final common publication, 0 publications before both final generations install, and outcome follows publication. | Publish before image installation, omit final publication, or publish a second time → the ordered timeline respectively shows mixed generations, no final state, or 2 publications → RED. | US-103-02 | new |
| R-A2L-REFRESH.045 | When | When a project containing both a primary image and an A2L completes installation, the system shall publish the prepared final pair exactly once before showing the project-load outcome. | 3/3: empty session, outgoing different image+MAC+A2L project, and image+A2L without MAC; exactly 1 final common publication, 0 reset/image-stage publications, and no outgoing/intermediate pair is painted at a UI yield. | Publish on reset or between image/MAC installation, omit the no-MAC final publication, or publish twice → an intermediate/missing/duplicate publication is observed → RED. | US-103-02 | new |
| R-A2L-REFRESH.046 | When | When an A2L-only project completes installation, the system shall publish the prepared A2L-only state exactly once before showing the project-load outcome. | 2/2: empty session and outgoing image+A2L session; exactly 1 final publication with current A2L, unchanged image generation, no `current_file`, no phantom MAC/image and no intermediate reset publication. | Require a synthetic `LoadedFile`, publish the reset, or skip the prepared A2L-only publication → phantom state, intermediate publication or stale final views → RED. | US-103-02 | new |
| R-A2L-REFRESH.047 | When | When the operator reloads changed content from the same source path without an intervening clear through an image+A2L or project route, the system shall publish the changed content under a new generation for each changed artifact. | 6/6 equal-size/different-content cases: loose image reload; project-pair A2L reload; project-pair image reload; A2L-only project A2L reload; no-MAC project A2L reload; no-MAC project image reload; pinned NEW markers replace OLD markers, each changed artifact's generation strictly increases, unchanged source content/bytes remain byte-identical, and writer/reset/reinstallation stages may increment an unchanged artifact's generation according to the stage matrix. | Key preparation or installation by path alone → the equal-size second load retains OLD markers or the old generation → RED; requiring an unchanged artifact's generation to stay fixed despite its stage reinstallation → the stage-pair assertion RED. | US-103-02 | new |
| R-A2L-REFRESH.048 | If | If a prepared snapshot's expected post-install A2L or image generation differs from the generation required at its installation stage, then the system shall discard the whole prepared load before any candidate cache, session, view, project or publication mutation. | 12/12: six original route/dimension arms; keyless P-PAIR image-stage A2L/image mismatches; live P-PAIR A2L/image changes after capture; and no-MAC A2L/image mismatches. Every project arm rejects before reset, previous state/view/project hashes remain equal, 0 candidate/widget/sync/publication calls occur, and REFRESH.028's exact superseded outcome remains binding. | Move project preflight after reset, ignore keyless pairs, use captured rather than live P5 counters, omit no-MAC mismatches, or install a stale field before rejection → the named arm observes reset/candidate mutation or wrong-stage acceptance → RED. | US-103-02 | new |

## Preserved contracts and route reconciliation

- REFRESH.002, .003 and .004 remain the functional image/project refresh contracts; .040–.046 add prepared-work, responsiveness and exactly-once measurements without weakening them.
- REFRESH.005 remains the unload contract; Inc 3 changes no unload route.
- REFRESH.014 remains the direct same-path A2L contract; .047 adds the image/project routes and equal-size content arms rather than moving that coverage.
- REFRESH.023 remains the confirmed project-A2L replacement route through the normal worker; Inc 3 does not redesign its question or persistence behavior.
- REFRESH.026 remains the worker/UI separation contract; .039–.043 make the prepared interface and post-parse timing measurable on every route.
- REFRESH.028 remains the whole-prepared-load stale-discard and exact-outcome contract; .048 adds project stage and A2L-only arms.
- The project preflight compares each snapshot with its own stage, not a single final generation pair: reset adds one A2L generation, image apply adds the next A2L/image generations, and MAC apply after image adds one further pair. `E1-rulings.md` D-3 gives the exact examples.

## Counts

**10 new requirements**, R-A2L-REFRESH.039 through R-A2L-REFRESH.048; **0 changed canon rows; 0 retired rows**. Numeric thresholds and discriminating negative controls: **10/10**. Planned ledger: **39 cases across 10 requirements (19 normal + 4 performance + 16 robustness)**, with **0 execution results**. Planned changed SOURCE files: **4 of at most 4**, including the existing `PreparedLoad` handoff needed for Inc 2's picker snapshots; the exact slice is `E1-slice.md`.
