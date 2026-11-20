# Inc 3 E2 Code-Wire delta — L+S (`loaded_state.py` / `shared.py`)

Stage E2, Code-Wire v3.2.0. Product/E1 commit: `85e689572f7ae97a467354a960750436a7ba3877`. Requirements: `../01-requirements.md`; planned cases: `../02-test-cases.md`; counted slice and stage rules: `../E1-slice.md`; rulings: `../E1-rulings.md`; baseline: `baseline.md`; frozen contracts: `../../interfaces.md`.

Owner group G-I3-L+S owns only L1 (`LoadedStateMixin._apply_prepared_load`) and S1 (the `PreparedLoad` data contract). S1 is an entity rather than a callable node; the baseline extractor deliberately does not extract dataclasses. No product source, test, canon, root interface or other lane artifact is changed by this graph.

The delta consumes frozen I-ALP-2.2/I-ALP-2.3 and the accepted I-ALP-3 carrier without applying an interface edit. The concurrent `../../inc-2/codewire/graph-inc2.md` supplies the snapshot member names used here and its lint reports zero unread; root now pins those names and every L+S proposal. No product marks/layered extraction or completed Inc2 product-tree claim is made in this integration phase.

All examples below are planned E4 oracles, not recordings, functional results or timing measurements. `A` and `I` are the UI-captured generations before worker launch. `F` is the existing common A2L-dependent-view publication; `OUTCOME` is the route outcome. `P-PAIR` contains image+MAC+A2L; `P-PAIR-NOMAC` contains image+A2L; `P-ONLY` contains A2L only.

| Route/stage | Required pair at L1 or the bypassing owner | A2L snapshot at that stage | L1 publication |
|---|---|---|---|
| Direct attach, Inc2 A4 | `(A+1,I)` | yes, installed by Inc2 | not an L1 route |
| Loose image+A2L | `(A+1,I+1)` | yes | one F when accepted |
| Project image+MAC+A2L, image after reset | `(A+2,I+1)` | no; legacy generation pair still present | `publish_a2l=False` |
| Project image+MAC+A2L, MAC after image | `(A+3,I+2)` | yes | `publish_a2l=False` |
| Project image+A2L without MAC | `(A+2,I+1)` | yes | `publish_a2l=False` |
| Project A2L-only, P5 after reset | `(A+2,I)` | yes, carried by P2 and installed by P5 | not an L1 route |

L1's preflight collects every supplied expectation. A snapshot supplies a complete pair even when both legacy fields are `None`; a legacy supply with either field present requires both fields. If legacy and snapshot pairs coexist they must be equal. Every supplied pair must equal the live stage pair `(current_A2L + int(bool(prepared.loaded.a2l_data)), current_image + 1)`. Any missing member, disagreement or stale value returns `False` before candidate cache, session, widget or outcome work. Only the legacy arm with no snapshot and both legacy generations `None` bypasses preflight.

**Stage invariant (agent84/D-10):** P5's preflight, reset and direct L1 calls form one synchronous UI sequence with no await/yield, and runtime generation increments occur only in UI writers (`evidence-e3/stage-invariant.txt`). Therefore the former STAGE_RACE inputs are unreachable and removed. New live-change cases occur before P5 entry; keyless and no-MAC mismatches reject before reset. There is no rollback, and any future yield between P5 preflight and L1 must block and reopen design.

## Nodes

LoadedStateMixin._apply_prepared_load
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.041, R-A2L-REFRESH.044, R-A2L-REFRESH.045, R-A2L-REFRESH.048
in: PreparedLoad prepared; Path path; float load_started; bool publish_a2l = True
out: bool accepted
func: changed. Preflight every complete legacy or S1 snapshot generation pair, including a keyless generation-only bundle; reject an incomplete, mutually inconsistent or stale pair before any candidate mutation. Preserve the accepted install and finalization behavior; when S1 is present its enrichment key/tags/summary are authoritative, with one shallow list conversion of each tuple to preserve the existing cache types, and its independent read-only check/patch mapping replaces the accepted picker mapping without a copy before any common refresh. Keep the no-snapshot/two-None legacy constructor arm and publish only under publish_a2l; L1 never enriches or describes.
module: s19_app/tui/app/loaded_state.py
modify: [Data: Prepared load candidate] (replace); [Data: S19TuiApp._accepted_a2l_picker_snapshots] (replace); [Data: A2L-dependent publication] (append)
volatile: path, load_started
oracle: ../01-requirements.md R-A2L-REFRESH.039 through .045 and .048; ../E1-rulings.md D-3 through D-5
examples: (EX-I3-039-A, DIRECT) direct attach with captured A=`7`, I=`4` supplies Inc2 pair `(8, 4)` and independent `check`/`patch` snapshots through A4 → expect none
examples: (EX-I3-039-B) loose image with captured A=`7`, I=`4` carries snapshot pair `(8, 5)` and read-only `check`/`patch` entries → accepted `True`; that exact mapping is installed before F and UI preparation calls=`0`
examples: (EX-I3-039-C) P-PAIR with captured A=`7`, I=`4` has keyless image pair `(9, 5)`, then MAC snapshot pair `(10, 6)` → both accepted `True`; the image stage leaves the mapping unchanged, the MAC stage installs it once, and route producer calls=`1`
examples: (EX-I3-039-D, A2L_ONLY) P-ONLY with captured A=`7`, I=`4` supplies P2/P5 snapshot pair `(9, 4)` without a synthetic PreparedLoad or current_file → expect none
examples: (EX-I3-039-E) P-PAIR-NOMAC with captured A=`7`, I=`4` carries image snapshot pair `(9, 5)` → accepted `True` with publish_a2l=`False`; its mapping precedes P5's sole F and route producer calls=`1`
examples: (EX-I3-040-A) case_06 with `220040` tags, captured A=`7`, I=`4` and snapshot pair `(8, 5)` → accepted `True`; each of `3` serial request-to-outcome runs includes parse and `4` named phases, has total <`60` s and median ≤`45` s; the `0.20` s worker hold yields ≥`3` ticks each ≤`100` ms late and final current pair `(8, 5)`
examples: (EX-I3-041-A) P-PAIR with captured A=`7`, I=`4`, keyless image pair `(9, 5)` and MAC snapshot pair `(10, 6)` → accepted `True` at both stages; each of `3` runs includes parse and `4` phases, has total <`60` s and median ≤`45` s, every tick is ≤`100` ms late, and no intermediate F occurs
examples: (EX-I3-041-B) P-PAIR-NOMAC with captured A=`7`, I=`4` and image snapshot pair `(9, 5)` → accepted `True`; each of `3` runs has total <`60` s and median ≤`45` s with parse included, every tick is ≤`100` ms late, and no MAC or intermediate F appears
examples: (EX-I3-042-A, INSTALL) P-ONLY case_06 uses P2/P5 pair `(9, 4)`, has no current_file/image/MAC, records admission/parse/preparation/install-publication with no copy phase, and each of `3` totals is <`60` s with median ≤`45` s → expect none
examples: (EX-I3-043-A, PREPARE) image-route producer raises ValueError("PREPARE_CONTROL") → expect none; candidate installs=`0`, UI preparation calls=`0`, success outcomes=`0`, and the existing image failure route keeps previous state
examples: (EX-I3-043-B, PREPARE) P-PAIR producer raises ValueError("PREPARE_CONTROL") → expect none; resets=`0`, candidate installs=`0`, UI preparation calls=`0`, and previous project files/state remain equal
examples: (EX-I3-043-C, PREPARE) P-ONLY producer raises ValueError("PREPARE_CONTROL") → expect none; resets=`0`, A2L/cache/widget mutations=`0`, UI preparation calls=`0`, and no success occurs
examples: (EX-I3-044-A) first loose image over attached OLD A2L with matching pair `(8, 5)` → accepted `True`; timeline is final install → mapping/cache install → F count=`1` → OUTCOME, with no pre-install F
examples: (EX-I3-044-B) different-path NEW image over outgoing image+OLD A2L with matching pair `(9, 6)` → accepted `True`; exactly `1` F sees NEW image and current A2L before OUTCOME and no outgoing pair is published
examples: (EX-I3-044-C) same-path equal-size different-content NEW image replacement with matching pair `(10, 7)` → accepted `True`; exactly `1` F sees NEW raw values/definitions, OLD values are absent, and OUTCOME follows F
examples: (EX-I3-045-A) empty session accepts P-PAIR image pair `(9, 5)` then MAC pair `(10, 6)` with publish_a2l=`False` → accepted `True` twice and L1 F count=`0`; P5 publishes final image+MAC+A2L/project identity exactly `1` time before OUTCOME
examples: (EX-I3-045-B) outgoing P-PAIR replaced by incoming P-PAIR accepts final stage pair `(12, 8)` with publish_a2l=`False` → accepted `True`; no reset/image-only/MAC-stage F occurs and P5's sole F precedes OUTCOME
examples: (EX-I3-048-A) loose image requires pair `(8, 5)` but snapshot records A2L generation `7` → accepted `False`; candidate cache/session/widget/sync/publication calls=`0`, previous state is equal, and OUTCOME is `Load superseded — current state kept.`
examples: (EX-I3-048-B) loose image requires pair `(8, 5)` but snapshot records image generation `4` → accepted `False`; no candidate image, enrichment, picker mapping or success is installed and OUTCOME is `Load superseded — current state kept.`
examples: (EX-I3-048-C, PRE_RESET) P-PAIR MAC stage requires `(10, 6)` but its snapshot A2L generation is `9` → expect none; P5 rejects before reset/project/widget/publication with `Load superseded — current state kept.`
examples: (EX-I3-048-D, PRE_RESET) P-PAIR MAC stage requires `(10, 6)` but its snapshot image generation is `5` → expect none; P5 rejects before reset/install/sync/publication with previous project hashes equal
examples: (EX-I3-048-E, PRE_RESET) P-ONLY requires `(9, 4)` but its P2 snapshot A2L generation is `8` → expect none; P5 rejects before reset/A2L/cache/view/project/publication and keeps the exact superseded outcome
examples: (EX-I3-048-F, PRE_RESET) P-ONLY requires `(9, 4)` after a test-controlled live-image change but its snapshot image generation is `3` → expect none; P5 rejects before reset/publication even though no candidate image exists
examples: (EX-I3-048-A, INCOMPLETE_PAIR) loose image has legacy A2L generation `8`, legacy image generation `None`, and no snapshot → accepted `False` before candidate mutation; an either-field guard may not compare or install a partial pair
examples: (EX-I3-048-B, DISAGREEING_PAIRS) loose image legacy pair `(8, 5)` coexists with snapshot pair `(8, 4)` while the stage requires `(8, 5)` → accepted `False`; no representation may select a different generation truth

## Entities

[Data: PreparedLoad]
in: PreparedLoad
desc: S1 changed data contract. Retain every existing field, default, positional order and the mutable legacy dataclass; append a2l_preparation after a2l_cache with type Optional[A2LAttachSnapshot] and default None. A type-checking-only import of A2LAttachSnapshot from file_load.py plus the existing deferred annotations avoids a runtime shared.py to file_load.py to shared.py cycle. The nested Inc2 snapshot is frozen and its payloads remain read-only; None preserves legacy non-prepared construction and is never product-worker evidence.

[Data: A2LAttachSnapshot]
in: A2LAttachSnapshot
desc: unchanged Inc2 dependency. Its expected_a2l_generation, expected_image_generation, enrichment_key, enriched_tags, summary_lines and picker_snapshots names match the concurrent Inc2 graph and are accepted by root I-ALP-2.2. The complete pair and all A2L payloads are consumed only after L1 preflight; the snapshot is authoritative, so legacy duplicate fields cannot select different content.

[Data: S19TuiApp._accepted_a2l_picker_snapshots]
in: Mapping[str, A2LPickerSnapshot]
desc: latest accepted Inc2 mapping, stored as MappingProxyType with independent check and patch entries. L1 replaces rather than merges it when S1 is present, before common refresh; stale candidates and keyless generation-only stages do not replace it. Existing adapter generation/signature/source invalidation remains unchanged.

[Data: Prepared load candidate]
in: current artifacts, generations, caches and project/session/widget state
desc: all candidate-side effects of L1 remain after the complete stage preflight. False means none of these candidate mutations occurred in L1; project-level pre-reset rejection is separately owned by P5.

[Data: A2L-dependent publication]
in: ordered F and OUTCOME observations
desc: L1 retains the optional existing common refresh only after accepted state and picker mapping installation. Project bundle stages pass publish_a2l=False so P5 alone performs the final publication before success.

## Edges

[Data: PreparedLoad].a2l_view_generation ──▶ LoadedStateMixin._apply_prepared_load
[Data: PreparedLoad].a2l_image_generation ──▶ LoadedStateMixin._apply_prepared_load
[Data: PreparedLoad].a2l_preparation ──▶ LoadedStateMixin._apply_prepared_load
[Data: A2LAttachSnapshot] ──▶ LoadedStateMixin._apply_prepared_load
LoadedStateMixin._apply_prepared_load ──▶ [Data: S19TuiApp._accepted_a2l_picker_snapshots]
when: a complete legacy/snapshot generation preflight matched and prepared.a2l_preparation is not None
LoadedStateMixin._apply_prepared_load ──▶ [Data: Prepared load candidate]
when: every supplied generation representation is complete, mutually equal and equal to the live installation-stage pair
LoadedStateMixin._apply_prepared_load ──▶ [Data: A2L-dependent publication]
when: accepted is True and publish_a2l is True, after candidate and accepted-picker-mapping installation

## Findings

finding E2-LS-1 keyless generation expectations bypass the baseline guard
anchor: LoadedStateMixin._apply_prepared_load
seen: static baseline loaded_state.py:589-599 and baseline.md L1 show preflight conditioned on a2l_enriched_key rather than on either expected generation; this is a disk observation, not an executed defect
cause: the baseline uses enrichment presence as a proxy for generation-bearing preparation, while Inc3 adds a keyless project image stage
effect: without the delta a stale generation-only image bundle could reach candidate installation without the required stage comparison
decision: CLOSED — trigger on a snapshot or either legacy generation, require complete coherent pairs, and keep rejection before the first candidate mutation; P5 rejects keyless image-stage mismatches before reset. D-10's synchronous UI invariant removes STAGE_RACE as unreachable and adds no rollback.

finding E2-LS-2 a runtime snapshot import would close a module cycle
anchor: PreparedLoad
seen: static imports at shared.py:13-30 and file_load.py:34-39 already include file_load.py importing PreparedLoad from shared.py
cause: importing A2LAttachSnapshot from file_load.py at shared.py runtime would make each module depend on the other during import
effect: a runtime import risks import failure and violates the no-cycle handoff requirement
decision: retain deferred annotations and import A2LAttachSnapshot only under TYPE_CHECKING; append the defaulted field after every existing field

finding E2-LS-3 A2L-only preparation does not traverse L1 or S1
anchor: LoadedStateMixin._apply_prepared_load
seen: E1-slice.md section 3 and static project_load.py:1618-1623 place A2L-only installation in P5 through the A2L writer with no current_file; no runtime route was executed
cause: an A2L-only project has no LoadedFile bundle for PreparedLoad to carry
effect: treating S1 as the A2L-only carrier or requiring L1 would fabricate phantom image state and violate REFRESH.042/.046
decision: keep P2.a2l_only and P5 as that route's carrier/installer; EX-I3-039-D, EX-I3-042-A and the P-ONLY stale arms are explicit L1 expect-none boundaries

finding E2-LS-4 Inc2 interface ruling and product extraction remain integration dependencies
anchor: A2LAttachSnapshot
seen: root I-ALP-2.2/I-ALP-2.3/I-ALP-3 now accept all six A7 consumer members, S1's optional carrier, coherent generation pairs and accepted-installation mapping rule; no product extraction is permitted in this integration phase
cause: the L+S proposals required conductor reconciliation, while product extraction requires an implemented Inc2 tree
effect: interface uncertainty is closed without claiming product-layered extraction or runtime success
decision: CLOSED for interface/design — adopt every accepted root rule verbatim; any later product extraction remains a throwaway-clone prerequisite, not work claimed here
