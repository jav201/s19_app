# Increment 002 — HLR-003/HLR-004 (LLR-003.1–003.3 · LLR-004.2 · LLR-004.3) · `safe_text move to s19_app/utils + insight_style 8-symbol re-export shim`

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development
> language — the **prose**, and never a label. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`. The normative RULES below are
> language-independent.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/increment-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `SOURCE files` · `Instrument RED-proof` · `Correction population` · `Mutation verdicts` · `Emitted-form assertion` · `Reverse census` · `RED counterfactual` · `Independent review` · `Evidence files` · `Traces to` · `File` · `Kind` · `source` · `test` · `doc` · `config` · `generated` · `fixture` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one
> and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

> **Where this lives:** the **repo**, next to the diff it describes —
> `.dev-flow/2026-10-11-batch-92/03-increments/increment-002.md`. It is not synced to the vault.

> **Notice convention.** `⚠` yellow = notice: does not block, obliges you to DECLARE the reason here.
> `✗` red = block. `✓` green = satisfied **with its evidence cited**.

| Field | Value |
|---|---|
| Batch | `2026-10-11-batch-92` |
| Increment | `002` |
| Lane (if the batch forked) | `none — sequential Inc-A → Inc-B (module-map §5, ARQ Exit-1)` |
| Requirement(s) | `HLR-003 · HLR-004 · LLR-003.1 · LLR-003.2 · LLR-003.3 · LLR-004.2 · LLR-004.3` |
| Acceptance | `AT-290 · AT-291` · white-box `TC-653 · TC-654` (+ `TC-651 · TC-652 · TC-655` re-run — shim-affected regression) |
| Agent | `software-dev` |
| Date | `2026-10-12` |

---

## 1 · What changed

BLUF: `safe_text` + its private `_CONTROL_SCRUB` byte-class table now live at `s19_app/utils.py`
(`_CONTROL_SCRUB` :41, `def safe_text` :44 — a byte-preserving 68-line transfer from base
`tui/screens_directionb.py:869-936`, verified by SHA-256 body-hash equality
`103da22077f27c2d9733c962dbcc77c44602e8f2f1f80b669445b0ec32262974`). `tui/screens_directionb.py`
no longer defines either symbol — it imports `from ..utils import safe_text` (:869) and its ~80
internal call sites became consumer references. `tui/insight_style.py` gained the declared 8-symbol
re-export shim (`from ..render.format import CYAN, DGRAY, GREEN, LABEL, MICROBAR_EMPTY,
MICROBAR_FILLED, VALUE, microbar` at :52) — identical objects, never copies — and dropped its own
definitions of those symbols; the palette remainder and the four view-side helpers (`human_bytes`,
`label_value`, `threshold_style`, `cap_gauge_style`) stay canonical there. The three named
`safe_text` consumers repointed (`tui/app.py:39`, `tui/checks_view.py:41`, `tui/issues_view.py:40`)
and `tui/services/validation_service.py:17` now reads `GREEN, LABEL, VALUE, microbar` from
`s19_app.render.format`. The 7 measured view consumers of `insight_style` (`app.py:80-90`,
`checks_view.py:40`, `issues_view.py:39`, `crc_designer_view.py:81`, `json_highlight.py:82`,
`screens_directionb.py:90` — the 7th is the shim's own module) are UNTOUCHED on their
`insight_style` consumption lines: they ride the shim, 0 snapshot risk (module-map R4). TC-653 and
TC-654 mint the live-tree AST censuses that police both moves; the hostile-input oracle
(`test_tui_hostile_map.py`, batch-77 C-17 mutation record at :259) and the MAC-coverage strip
oracle (AT-291 nodes) pass unchanged through the moved/shimmed addresses.

Mechanism, in the chartered order: (1) the `safe_text` unit moved byte-exact (comment block +
`_CONTROL_SCRUB` + the full C-17 docstring + body; `utils.py` stays stdlib + `rich.text` only, now
importing `Text`). (2) In `screens_directionb.py` the definition span was replaced in place by the
`from ..utils import safe_text` import. (3) The shim block replaced the 8 symbol definitions in
`insight_style.py` (constants `LABEL`/`VALUE`/`GREEN`/`DGRAY`/`CYAN`, the `MICROBAR_*` glyphs, and
`def microbar` — 62 lines deleted; the shim import sits at :52). (4) Repoints per the measured sets
(LLR-003.3 / LLR-004.3): the 3 product `safe_text` consumers + the 3 old-address TEST importers,
and the single `validation_service` edge. (5) NEW census module `tests/test_import_census.py`
hosting TC-653 + TC-654 (judgment call stated: a NEW module, not an extension of Inc-A's
`tests/test_render_hexview.py` / `tests/test_render_format.py` — TC-653's subject is the
`utils.safe_text` address, which belongs to neither Inc-A module's theme, and one module carrying
both new nodes keeps the census helpers shared without touching Inc-A's closed packets).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

One row per file. `Kind` is one of `source` · `test` · `doc` · `config` · `generated` · `fixture`; `Traces to` names the US/HLR/LLR (or `R-<AREA>-<NNN>`) ids the file serves, and `doc` rows leave it empty.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/utils.py` | source | LLR-003.1 · LLR-003.2 | gains `safe_text` + `_CONTROL_SCRUB` (byte-preserving 68-line move from base `tui/screens_directionb.py:869-936`, body-hash verified) + the `from rich.text import Text` import |
| `s19_app/tui/screens_directionb.py` | source | LLR-003.1 · LLR-003.3 | base `:869-936` (`_CONTROL_SCRUB` table + `def safe_text`) replaced by `from ..utils import safe_text` (:869); ~80 internal call sites become consumer references |
| `s19_app/tui/insight_style.py` | source | LLR-004.2 | 8-symbol re-export shim from `..render.format` (:52, identical objects); own definitions of the 8 symbols removed (5 palette constants, `MICROBAR_*` glyphs, `def microbar` 62 lines); retained palette + 4 helpers stay canonical; module docstring amended (5 helpers → 4 + shim note) |
| `s19_app/tui/checks_view.py` | source | LLR-003.3 | `from .screens_directionb import safe_text` → `from ..utils import safe_text` (:41) |
| `s19_app/tui/issues_view.py` | source | LLR-003.3 | `from .screens_directionb import safe_text` → `from ..utils import safe_text` (:40) |
| `s19_app/tui/app.py` | source | LLR-003.3 | `safe_text` dropped from the `.screens_directionb` import block; `from ..utils import safe_text` added (:39); the `insight_style` consumption block (:80-90) untouched |
| `s19_app/tui/services/validation_service.py` | source | LLR-004.3 | `:17` `from ..insight_style import GREEN, LABEL, VALUE, microbar` → `from ...render.format import GREEN, LABEL, VALUE, microbar` |
| `tests/test_import_census.py` | test | LLR-003.1 · LLR-003.3 · LLR-004.2 · LLR-004.3 | NEW — TC-653 (safe_text live-tree AST census) + TC-654 (format census + 8-symbol `is`-identity + value pins) |
| `tests/test_tui_hostile_map.py` | test | LLR-003.2 (AT-290 mechanism) · LLR-003.3 | module import split (:83-84): `MemoryMapPanel, RegionRow` stay at screens_directionb, `safe_text` repointed to `s19_app.utils` |
| `tests/test_a2l_multiline_headers.py` | test | LLR-003.3 | local import repointed (:360) |
| `tests/test_tui_directionb.py` | test | LLR-003.3 | local import repointed (:3225) |

| Count | Value |
|---|---|
| **SOURCE files** | **7 / 4** (7 modified, 0 new, 0 deleted) |
| Test files | 4 (1 new + 3 import-line-only repoints; uncapped) |
| Doc files | 0 (outside the count) |

- ⚠ **Above 4 source files:** the measured repoint set is closed and authoritative (module-map §5
  F-2; LLR-003.3 names 3 consumers + the owning module, LLR-004.3 names the service edge), and the
  two ownership moves cannot be cut smaller without leaving a consumer at an old address (the
  TC-653/TC-654 censuses exist precisely to police those sets). **Waiver: PDR condition C1 —
  the >4 source-file budget is waived for this repoint-only increment** (operator-ratified at the
  P1 gate; restated here per the increment brief; the same mechanical-repoint reason as Inc-A,
  which the waiver was granted for).
- ✗ The 6 measured view consumers of `insight_style` (`app.py:80-90`, `checks_view.py:40`,
  `issues_view.py:39`, `crc_designer_view.py:81`, `json_highlight.py:82`, `screens_directionb.py:90`)
  carry ZERO Inc-B edits on their `insight_style` lines — verified by
  `git diff 410cde5 -- <each file> | grep insight_style` → "(insight_style lines unchanged)" for
  the 4 touched consumers, and `git diff 410cde5 --stat -- s19_app/tui/crc_designer_view.py
  s19_app/tui/json_highlight.py` → EMPTY (whole-file untouched) — and by the passing TC-654 census.
- ✗ `s19_app/render/*` surfaces carry ZERO Inc-B edits (hard bound, D1/D2) — no render row exists
  in this table; byte-consistency with Inc-A is proven by the re-run TC-655/TC-654 pins (5-passed
  transcript below).
- ⚠ **§2 addendum — close-out reconciliation, 2026-10-12 (V59):** three files in the batch's
  final diff belong to this increment's lane of work but were omitted from the table above at
  authoring; they are NAMED here with their true changes, and the Count block above stays as
  sealed (tests are uncapped, so no tally changes).

| File | Kind | Traces to | Change |
|---|---|---|---|
| `tests/test_tui_checks_view.py` | test | HLR-003 (AT-290 C-18 binding) | docstring-only: binds the hostile-tokens node as AT-290's realized black-box node |
| `tests/test_tui_issues_view.py` | test | HLR-003 (AT-290 C-18 binding) | docstring-only: the same AT-290 binding on the issues-view variant node |
| `tests/test_tui_mac_coverage.py` | test | HLR-004 (AT-291 C-18 binding) | docstring-only: binds `test_at071_strip` + its two companions as AT-291's realized nodes |

---

## 3 · How to test

```bash
# The census TC modules — one complete run (TC-653/654 new; TC-651/652/655 regression)
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_import_census.py tests/test_render_hexview.py tests/test_render_format.py -q > .dev-flow/2026-10-11-batch-92/evidence/increment-002-tc-modules.transcript 2>&1
# The repointed + affected test files — one complete run
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_tui_hostile_map.py tests/test_tui_checks_view.py tests/test_tui_issues_view.py tests/test_tui_mac_coverage.py tests/test_tui_insight_style.py tests/test_a2l_multiline_headers.py -q --tb=short -rf > .dev-flow/2026-10-11-batch-92/evidence/increment-002-repointed-files.transcript 2>&1
# The AT-290 hostile oracle family + AT-291 strip nodes — named-node run
PYTHONDONTWRITEBYTECODE=1 python -m pytest \
  "tests/test_tui_checks_view.py::test_c17_seed_hostile_linkage_and_reason_render_literal" \
  "tests/test_tui_issues_view.py::test_at082f_hostile_issue_tokens_render_literal" \
  "tests/test_tui_mac_coverage.py::test_at071_strip" \
  "tests/test_tui_mac_coverage.py::test_build_mac_coverage_strip_counts" \
  "tests/test_tui_mac_coverage.py::test_zero_total_no_divzero" \
  "tests/test_tui_hostile_map.py::test_b77_hostile_symbol_is_literal_and_carries_no_span" \
  "tests/test_tui_hostile_map.py::test_b77_hostile_symbol_emits_no_control_byte_into_the_strip" \
  "tests/test_tui_hostile_map.py::test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity" \
  -q > .dev-flow/2026-10-11-batch-92/evidence/increment-002-at-family.transcript 2>&1
# The FULL render-module guard host (never a -k subset)
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_tui_directionb.py -q > .dev-flow/2026-10-11-batch-92/evidence/increment-002-directionb-guard.transcript 2>&1
# Frozen dual-guard (C-27): SOURCE guard + the TC-031 pair/TC-032 (color_policy freeze coverage)
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_engine_unchanged.py -q > .dev-flow/2026-10-11-batch-92/evidence/increment-002-dual-guard-source.transcript 2>&1
PYTHONDONTWRITEBYTECODE=1 python -m pytest "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main" "tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main" -q > .dev-flow/2026-10-11-batch-92/evidence/increment-002-dual-guard-testfile.transcript 2>&1
# Body-hash verification of the move (the comparator is the base file at 410cde5, lines 869-936)
cat .dev-flow/2026-10-11-batch-92/evidence/increment-002-body-hash.txt
# Cold-import probes (5 probes, each in a fresh interpreter)
cat .dev-flow/2026-10-11-batch-92/evidence/increment-002-cold-probes.transcript
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | TC-654 value pins + `microbar` clamp arms at the new address (`microbar(0.5, 8)` fill count, `microbar(1.0, 0)` empty) + the `test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity` table (65/65 control codepoints over the node's own source table) | all green inside the two cited runs (5-passed TC run; 14-passed AT run) |
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | `test_tc653_safe_text_import_census` · `test_tc654_format_census_and_shim_identity` (+ `test_tc651_*` / `test_tc652_*` / `test_tc655_*` regression) | 5 passed, 0 failed, exit 0 — one complete run (`increment-002-tc-modules.transcript`, 3.84 s) |
| **B · black-box** `AT-NNN` ↔ story, through the shipped surface | `core` · `full` | AT-290: `test_c17_seed_hostile_linkage_and_reason_render_literal` (checks_view) + `test_at082f_hostile_issue_tokens_render_literal` (issues_view); AT-291: `test_at071_strip` + `test_build_mac_coverage_strip_counts` + `test_zero_total_no_divzero` (mac_coverage); plus the `test_b77_*` hostile-map family | 14 passed, 0 failed, exit 0 — one complete named-node run (`increment-002-at-family.transcript`, 17.64 s) |

Repointed + affected files (one complete run, read from its own transcript):
72 collected — 72 passed, 0 failed, exit 0 (`increment-002-repointed-files.transcript`, 42.34 s).
Zero failures anywhere: no union-flip to record, no stable-pass→fail stop.

Full guard host `tests/test_tui_directionb.py` (one complete run, C-19/C-34 — never a `-k` subset):
183 passed, 0 failed, exit 0 (`increment-002-directionb-guard.transcript`, 242.05 s) — every node
outside the 44-id pinned union passed, and no in-union node even flipped (count-identical to Inc-A's
guard result; the cited transcript is a clean re-run taken after all mutation-restores were
hash-verified).

Frozen dual-guard: TC-027 source guard 1 passed (`increment-002-dual-guard-source.transcript`,
0.09 s); TC-031 pair + TC-032 3 passed (`increment-002-dual-guard-testfile.transcript`, 0.81 s).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | TC-653's own census: `tui/checks_view.py:41` `from ..utils import safe_text` flipped back to `from .screens_directionb import safe_text` (the retired address — which still resolves at runtime since screens_directionb re-exports the same object, so ONLY the census can catch it) |
| Instrument | project code: my own hand (python edit); the restore proven by SHA-256, not `git status` |
| Where it ran | **my own worktree** `C:/Users/jjgh8/Github/s19_app-b92` |
| Transcript | `evidence/increment-002-tc653-red.transcript` — `AssertionError: safe_text importer set drifted from the measured set: extra=[] missing=['s19_app.tui.checks_view']` |
| Restore proven by | **file hash returned to its pre-mutation value**: `s19_app/tui/checks_view.py` `badbba330a6d3fd504034df82abea752b60063e6af6b866a6c007ec5c41404fd` (pre == post) |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` on every run (C-46) |
| Arms resolved at baseline | 1 (the TC-653 census node) |
| Verdict granularity | per resolved node id — `test_tc653_safe_text_import_census` FAILED |
| Arms that stayed GREEN | none — the single armed node went RED |

| Field | Value |
|---|---|
| **RED counterfactual** | one consumer (`s19_app/tui/checks_view.py:41`) flipped back to `from .screens_directionb import …` made THIS increment's own TC-653 census fail (`missing=['s19_app.tui.checks_view']`) · transcript `evidence/increment-002-tc653-red.transcript` (SHA-256 `25f0e3a2d401f24469be4d29285ece0ae5008252f42ce6a0af5c28145a906f24`) · restore digest `badbba330a6d3fd504034df82abea752b60063e6af6b866a6c007ec5c41404fd` |

| Field | Value |
|---|---|
| **Mutation verdicts** | 4 arms, all KILLED (each per resolved node id, inert arms: none): **(1)** TC-653 arm above → KILLED · **(2)** TC-654 service-edge arm: `validation_service.py:17` flipped back to `from ..insight_style import GREEN, LABEL, VALUE, microbar` → `test_tc654_format_census_and_shim_identity` FAILED (`tui/services/* must not import s19_app.tui.insight_style: ['s19_app.tui.services.validation_service']`), transcript `increment-002-tc654-red.transcript`, restore digest `1051e23f371de8189e834582a08281e1edaffa46f34a1db898286ba7837b3482` → KILLED · **(3)** TC-654 identity arm: the shim block replaced with literal copies (same values + a copied `def microbar`) → the node FAILED (its census arm fired first: `render.format importer set drifted: missing=['s19_app.tui.insight_style']`; transcript `increment-002-shim-copy-red.transcript`) AND the identity mechanism itself was witnessed under the mutated tree by a dedicated probe: `insight_style.microbar is render_format.microbar -> False` (probe transcript `increment-002-shim-copy-identity-probe.txt`) — the `is` assertion discriminates, restore digest `130674ba744004672c3616069be78c98e9ae895c4b4ff5c0f4154be7ac713d8c` → KILLED · **(4)** LLR-003.2 C-17 arm (the contract's named Phase-3 re-run of the batch-77 mutation at the new address): `utils.safe_text` body mutated `Text(...)` → `Text.from_markup(...)` → `tests/test_tui_hostile_map.py` run: 5 failed, 4 passed (`test_b77_hostile_symbol_is_literal_and_carries_no_span` ×4 parametrizations + `test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity`), transcript `increment-002-from-markup-red.transcript`, restore digest `28b8096d4a2f3551ea2dc87f3d53207aeeff749a7ecb461b34e740a3760858ef` → KILLED |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| TC-653 AST census (`tests/test_import_census.py`) | one consumer flipped back to the retired screens address | census RED naming the flipped consumer (`missing=['s19_app.tui.checks_view']`) |
| TC-654 service-edge census (`tests/test_import_census.py`) | the validation_service edge flipped back to insight_style | positive-absence assertion fired (`tui/services/* must not import s19_app.tui.insight_style: ['s19_app.tui.services.validation_service']`) |
| TC-654 `is`-identity (`tests/test_import_census.py`) | shim replaced with literal copies | `insight_style.microbar is render_format.microbar -> False` under the mutated tree (dedicated probe; the node itself went RED on the same mutation) |
| The C-17 hostile oracle (`tests/test_tui_hostile_map.py`, repointed) | `safe_text` body mutated to `Text.from_markup` at the new address | 5 nodes RED (literal/span + scrub-table arms) — the batch-77 mechanism still fires post-move |
| TC-655 value pin (`tests/test_render_format.py`, Inc-A instrument re-run) | (Inc-A arm: `CYAN` drifted one hex digit — transcript in increment-001) | in THIS increment the instrument is a regression witness only: it stays green on the shimmed tree, including `inspect.getsource(insight_style.microbar) == inspect.getsource(render_format.microbar)` — identical objects, one source |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 5 instruments, each shown RED (or, for the carried TC-655, previously shown RED in increment-001) before its first PASS was believed |

Fixture discrimination (C-57): the hostile-map oracle re-derives the C0/DEL/C1 class itself
(`_CONTROL = frozenset(range(0x00, 0x20)) | frozenset(range(0x7F, 0xA0))`, :92) instead of
importing `_CONTROL_SCRUB` — importing the table would make the oracle agree with the
implementation by construction; the fixture makes a wrong class produce a wrong expectation and a
wrong result that AGREE, which is precisely what re-derivation prevents. The AT-291 strip nodes
drive the strip through the shipped service path with a `0 of 0` divide-by-zero edge
(`test_zero_total_no_divzero`) — a default-only strip cannot satisfy the census node.

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| The moved `safe_text` unit | SHA-256 of base `410cde5:s19_app/tui/screens_directionb.py` lines 869-936 vs the same span in `s19_app/utils.py` | `103da22077f27c2d9733c962dbcc77c44602e8f2f1f80b669445b0ec32262974` == `103da22077f27c2d9733c962dbcc77c44602e8f2f1f80b669445b0ec32262974` → BYTE-IDENTITY: True (`increment-002-body-hash.txt`) |
| The hostile payload through the moved primitive | `safe_text(hostile).plain` / `.spans` rendered through the shipped map/click surface (the b77 nodes) | verbatim `.plain`, `spans == []` — unchanged behavior at the new address (14-passed AT run) |
| The MAC coverage strip through the repointed service | `build_mac_coverage_strip` counts + `Text` payload via `validation_service` (AT-291 nodes) | `mac_in_s19 of mac_total` + microbar strip byte-consistent with the pre-move oracle (14-passed AT run) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts, each asserted against the form its producer emits (source span via SHA-256; rendered `Text` via `.plain`/`.spans`; strip via the service `Text` payload) |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| New/changed TC modules run (5 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-tc-modules.transcript` | `215b3b010544ddfef77ac890ee673b7f55e9b6085bb1a94f45a246b725f6affe` |
| Repointed + affected test files run (72 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-repointed-files.transcript` | `2db189ad5f9fe54b24e3628c4a5e152ef26cfbed3952d4367b0548d126828b45` |
| AT-290 hostile oracle family + AT-291 strip nodes run (14 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-at-family.transcript` | `6e66d4b3edb1defea08e60721d8eec77e16d5a360aa00f281c4b13d9858879bf` |
| Full directionb guard host run (183 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-directionb-guard.transcript` | `dc8c9e075a9330280514454ebe5f3d31a8c4e7c8d37512dbdbd7ba61ea6221ac` |
| Frozen SOURCE guard TC-027 run (1 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-dual-guard-source.transcript` | `73125e61db100c1ebd63fcf1c7ccee177256680c846838f79b6e5a67ec59e11e` |
| Frozen TEST-file guard TC-031 pair + TC-032 run (3 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-dual-guard-testfile.transcript` | `59fa80a4c102a421215cb6aa34e9bd7235f35ac025459f5a5c693bba9187faa6` |
| Cold-import probes (5/5) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-cold-probes.transcript` | `3b2b8da539fdf6b9d75e133c9b58075fc5cd972f32acb52aba149c7e85b23491` |
| Body-hash verification of the move | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-body-hash.txt` | `7beb20c3418a6ff48fdd6f182ca940628e5cc9d5c3a420ce93e5ce2989c78f7d` |
| TC-653 RED counterfactual | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-tc653-red.transcript` | `25f0e3a2d401f24469be4d29285ece0ae5008252f42ce6a0af5c28145a906f24` |
| TC-654 RED arm (service edge) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-tc654-red.transcript` | `aa106ce8074986dd538f4295558f0503787bd317fa9794d24fb50b92d1f334b5` |
| TC-654 RED arm (copy shim) | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-shim-copy-red.transcript` | `55a3e2d5d60886c09569daaef0a67590ad3419b842169f87ef9b33adec87529b` |
| Copy-shim `is`-identity probe | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-shim-copy-identity-probe.txt` | `a6d4d8dfbb0419d18cd8022c586f53bf9080b088cf392bb1cb58bf521459913b` |
| C-17 `from_markup` RED arm at the new address | `.dev-flow/2026-10-11-batch-92/evidence/increment-002-from-markup-red.transcript` | `815e8d911c8f3bd942cd2d1232173f64d253a44ff9501058a97d8562d3160df5` |

| Field | Value |
|---|---|
| **Evidence files** | 13 artifacts at the declared home, each cited with the digest of its stored bytes; `.gitattributes` marks `evidence/**` `-text` (mixed line endings stored verbatim — the cold-probes transcript carries one console-encoded punctuation glyph, stored as captured). |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (a) "no live import of `safe_text` from the retired `screens_directionb` address" (TC-653); (b) "no `tui/services/* → insight_style` edge" (TC-654, set-equality against the EMPTY set); (c) "every `render.format` importer is in the 3-name measured set" (TC-654) |
| If the result is an ABSENCE, what made the search wide enough | (a)+(b)+(c) AST walks over ALL of `s19_app/` (every `Import`/`ImportFrom`, aliased/plain, module-level and function-local, NAME-aware for safe_text) + a tests/-side census — derived from the live tree at run time, not a marker list |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc653_safe_text_import_census` (conclusion: the measured consumer set is exactly the declared set and the retired address carries zero safe_text imports); `test_tc654_format_census_and_shim_identity` (conclusions: the service-layer shim-consumer set is empty; the shim is a re-export, not a copy) |
| Conjunctive criteria: one mutation per conjunct | 4 arms, one per conjunct: consumer-at-old-address (TC-653) · service-edge-restored (TC-654 census) · copy-shim (TC-654 identity) · C-17-breaker at the new address (b77 family) — each verdict reported separately above |
| Synthetic instance of the absent case | (a) the flipped checks_view consumer IS the synthetic instance — the same unmodified census probe then reported it (`missing=['s19_app.tui.checks_view']`, RED transcript); (b) the flipped validation_service edge IS the synthetic instance (RED transcript); (c) the copy-shim IS the synthetic instance for both the census arm (insight_style vanished from the render.format importer set) and the identity arm (`is -> False`) |
| **Positive control for every probe that returned an ABSENCE** | TC-653: the same name-aware probe returns NON-absent output in the same run — the 4 measured consumers ARE found at `s19_app.utils` (set-equality both directions) and the 3 test importers ARE found. TC-654: the 3-name render.format importer set is exactly the measured set (non-empty, matching), the 6 view insight_style consumers remain (B4 probe below), and the identity arm asserts presence of the identical objects 8/8 |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl "safe_text" tests/ --include="*.py"` | 11 files assert the touched symbol (10 pre-existing: test_a2l_multiline_headers, test_flow_builder_render, test_tui_a2l_detail, test_tui_a2l_issue_recolor, test_tui_checks_screen, test_tui_checks_view, test_tui_directionb, test_tui_hostile_map, test_tui_issues_view, test_tui_patch_big + the new test_import_census) — all green in the cited runs; `grep -rl "insight_style import\|import insight_style" tests/ --include="*.py"` → 9 pre-existing test files import insight_style (directionb, hexview_classed, insight_style, issues_view, patch_checks_strip, patch_glyphs, patch_history_strip, patch_json, theme) + test_tui_snapshot.py:717 prose-only + the new test_import_census — none repointed (shim by design), all green |
| B2 file moved on disk | `grep -rn "screens_directionb import safe_text\|screens_directionb\.safe_text" s19_app/ tests/ --include="*.py"` | 0 live readers of the retired safe_text address. Surviving prose: `tests/test_tui_hostile_map.py:65` (module docstring listing the oracle's covered symbols), `s19_app/tui/services/validation_service.py:195` (docstring naming the IssueRow safe_text path) — C4-class text, recorded in the Correction population; `grep -n "def microbar\|MICROBAR_FILLED =\|MICROBAR_EMPTY =\|^CYAN =\|^DGRAY =\|^GREEN =\|^LABEL =\|^VALUE =" s19_app/tui/insight_style.py` → 0 (all 8 shimmed) |
| B3 byte-identical golden captures this source | `grep -rln "safe_text\|microbar\|MICROBAR" tests/goldens/ tests/__snapshots__/` | 0 hits — no golden/snapshot captures the touched sources; AT-288 (Inc-A) remains the batch's sole byte-identity oracle |
| B4 artifact produced here is consumed elsewhere | who reads `s19_app.utils` / the `insight_style` shim / `render.format` | `utils.safe_text` product consumers = exactly the 4 measured (TC-653 set-equality); `render.format` consumers = exactly the 3 measured (TC-654 set-equality); the shim's consumers = the 6 measured view modules (probe below) + 9 test files |

| A3 | interface consumed by another module changed | `grep -rn "insight_style import" s19_app/ --include="*.py"` | consumers = the 6 measured view modules only (app.py:80, checks_view.py:40, crc_designer_view.py:81, issues_view.py:39, json_highlight.py:82, screens_directionb.py:90) — validation_service:17 GONE from the set (repointed). No consumer outside the declared sets (F-QA-2 censuses) |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3 — B1: 11+10 asserting files, all green in the cited runs · B2: 0 live readers (3 C4-declared prose mentions) · B3: 0 goldens · B4/A3: consumer sets == measured sets, closed |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| safe_text import edges (product) | every module importing/defining `safe_text` in `s19_app/` | pre-state `grep -n "safe_text" s19_app/ --include="*.py"` (5 files: app block :61-79, checks_view :41, issues_view :40, screens_directionb def :869-936 + ~80 call sites, validation_service docstring :195) | 4 import/def sites / 4 files | all 4 (app, checks_view, issues_view, screens_directionb def→import) | validation_service.py:195 — docstring prose, not an import edge (C4-class, recorded in B2) |
| safe_text import edges (tests) | every test importing the `safe_text` NAME, in all forms | pre-state census `grep -n "safe_text" tests/ --include="*.py"` over the 10 files — importers distinguished from prose/AST-name references per file (the P2 code-lens list) | 3 importers / 3 files (hostile_map module :83; a2l_multiline_headers local :360; directionb local :3225) | all 3 | prose/assertion references in 7 files left, verified needing no repoint: flow_builder_render (AST name-census over `FlowBuilderPanel.render_result` — no import), a2l_detail, checks_screen, a2l_issue_recolor, checks_view, issues_view, patch_big (all docstring/prose); hostile_map.py:65 docstring names the retired address (C4-class, B2) |
| insight_style 8-symbol ownership | the definition sites of the 8 moved symbols in `insight_style.py` | pre-state `grep -n "def microbar\|MICROBAR_FILLED\|^GREEN\|^LABEL\|^VALUE\|^CYAN\|^DGRAY" s19_app/tui/insight_style.py` → definitions at :43-61 (constants), :117-118 (glyphs), :216-277 (microbar) | 8 definition sites | all 8 removed (shim import at :52) | 0 left; retained palette/helpers positively asserted present (RETAINED_SYMBOLS, 14/14) |
| validation_service :17 edge | the single service→insight_style import line | pre-state `sed -n '14,18p' s19_app/tui/services/validation_service.py` (contract's executed probe) | 1 site | 1 (repointed to `...render.format`) | 0 left |

| Field | Value |
|---|---|
| **Correction population** | 4 corrections, each enumerated with its method before its first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| `from .screens_directionb import safe_text` / `from ..screens_directionb import safe_text` (old forms) | 0 hits in `s19_app/` and `tests/` | yes | B2 probe output; TC-653 asserts the retired address carries zero safe_text imports |
| `from ..insight_style import GREEN, LABEL, VALUE, microbar` (the service edge) | 0 hits in `s19_app/` | yes | B4/A3 probe; TC-654's set-equality asserts the service-layer set EMPTY |
| the 8 symbol definitions in `insight_style.py` | 0 (`def microbar` gone; no constant assignments) | yes | B2b probe; TC-654 asserts the `is`-identity + `def microbar` absence from the shim source |

### Signed-balance test ledger

`post = base − deleted + added` → the repointed 6-file set: `72 = 72 − 0 + 0` ✓ reconciles
(import-line-only edits — the `git diff 410cde5` over the 3 edited test files shows ONLY import
lines changed; no test def touched). Guard host: `183 = 183 − 0 + 0` ✓ (test_tui_directionb.py's
diff is import-line-only: this increment's one local + Inc-A's two form-3 hexview locals). New TC
modules: `5 = 3 − 0 + 2` ✓ (Inc-A's TC-651/652/655 carried + TC-653/654 minted). AT named run:
`14 = 14 − 0 + 0` ✓ (8 named nodes, several parametrized; no node added/removed).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer — spawned as a generic agent with agents/code-reviewer.md · OK to advance`. Reviewer: independent `code-reviewer` (read-only toward the diff; every check below executed, none taken from the packet on trust). **Byte-exactness: MATCH** — recomputed independently: `git show 410cde5:s19_app/tui/screens_directionb.py` :869–936 and `s19_app/utils.py` :32–99 both sha256 to `103da22077f27c2d9733c962dbcc77c44602e8f2f1f80b669445b0ec32262974`; `_CONTROL_SCRUB` moved WITH the function (0 occurrences left in screens_directionb, defined exactly once in utils.py, not duplicated). **C-17 contract verbatim at the new address:** own probe `safe_text("a\x9b31mb[red]")` → `.plain == "a31mb[red]"`, `.spans == []`. **Shim is identity, not copy:** all 8 symbols `is`-identical to `render.format` (own cold interpreter run); the 6 view consumers' `insight_style` lines carry 0 edits (diff hits are context-only; crc_designer_view/json_highlight whole-file untouched); `human_bytes`/`label_value`/`threshold_style`/`cap_gauge_style` all still defined in insight_style. **Repoints:** `app.py:39`, `checks_view.py:41`, `issues_view.py:40` → `from ..utils import safe_text`; `validation_service.py:17` → `from ...render.format import GREEN, LABEL, VALUE, microbar`; closure greps: 0 live `safe_text` imports from the retired address (only the 2 pre-declared C4 prose mentions), 0 `insight_style` imports under `tui/services/`, the 3 test importers repointed at the claimed lines, test diffs import-line-only. **TC-653/654 are live-tree-derived set-equality oracles** (runtime AST census over all of `s19_app/` + `tests/`, drift in either direction fails) — C-31-proof, not hand lists; reviewer re-ran the 5-node TC module green and executed his OWN mutation arm: `checks_view.py:41` flipped back to the retired address → TC-653 RED (`missing=['s19_app.tui.checks_view']`) → restored byte-exact to `badbba330a6d…04fd` (the packet's restore digest; reviewer-side sed LF/CRLF artifact repaired, final bytes == pre-mutation bytes). **Frozen + frozen-surface discipline:** frozen-set diff empty; zero `s19_app/render/*` in the Inc-B delta (`render/` untracked-from-Inc-A, mtimes all inside Inc-A's creation window; render content behaviorally pinned by the TC-654/655 pins that pass in the reviewer's own run). **Evidence integrity:** all 13 cited digests re-verified on disk, 13/13 match; reviewer re-ran the AT-290/291 named family himself — 14 passed, 0 failed; the 242.05 s guard host was accepted from its hash-verified transcript (exit line `183 passed in 242.05s (0:04:02)`, at the re-run cost threshold; the reviewer's own census/identity/hostile runs cover the increment's mechanism) — repointed-files (72 passed) and dual-guard (1+3 passed) transcript tails match the claims. **V59 reverse trace:** every §2 row carries ≥1 Traces-to; PDR C1 >4-source waiver restated in §2 and accepted. **Findings: none HIGH, none MEDIUM, none LOW** — the increment is clean. Full report: `03-increments/review-increment-002.md`. |

---

## 5 · Risks

- **C4 stale prose mentions of the retired addresses** (recorded, no live edges): `tests/test_tui_hostile_map.py:65` (module docstring naming `s19_app.tui.screens_directionb.safe_text`), `s19_app/tui/services/validation_service.py:195` (docstring naming the IssueRow safe_text path), `tests/test_tui_commandbar.py:1169` (`_CONTROL_SCRUB` discipline comment). Same disposition as Inc-A's C4 items: routed to BACKLOG-CODE lane A at close, named here so the drift does not read as a surprise.
- **tc024-class load sensitivity** (Inc-A's open gate question): not observed in any Inc-B run — the 6-file run, the AT named run, and the 247.89 s guard host all ran clean on a quiet machine. No new flip to record; the orchestrator's tc024 ruling from Inc-A still stands.
- **`test_import_census.py`'s own imports**: the census instruments import `insight_style` / `render.format` / `s19_app` — by design they cannot pollute their own verdicts: the product-tree census walks only `s19_app/` (the instrument lives in `tests/`), the tests-side census counts only real `Import`/`ImportFrom` AST nodes (never the module's string literals), and the TC module itself imports `safe_text` nowhere.
- **`render/*` frozen surfaces**: zero Inc-B edits (hard bound D1/D2); there is no render row in §2. Byte-consistency with Inc-A is proven behaviorally — TC-655's pins (values, frozen-origin equalities, `inspect.getsource` equality of microbar) and TC-654's census/identity all pass on the untouched files.
- **Cross-cutting**: nothing remains for a later increment — US-92-3 and US-92-4 are fully landed; the declared residual (`change_service → color_policy`, US-92-5 OUT) survives by declaration.

---

## 6 · Pending items / spec deviations

- §4b independent review — awaiting the orchestrator's `code-reviewer` (cell left empty per the increment brief).
- §5 C4 prose mentions — backlog candidates at close (same lane-A route as Inc-A's).
- No deviations from the chartered LLR texts; the node names (`test_tc653_safe_text_import_census`, `test_tc654_format_census_and_shim_identity`) are provisional per V-5 and reconcile at Phase 4.
- The P4 full-suite gate (2765 tests vs the 44-id pinned union) remains orchestrator-owned; this increment's evidence is the guard host + the affected-file runs per the §5.2 gate rule.

---

## 7 · Suggested next task

**Phase-4 reconciliation + close**: mint TC-653/TC-654 + AT-290/AT-291 in `AT-TC-REGISTRY.jsonl`
(status flip from RESERVED), reconcile node names (V-5), run the P4 full-suite gate against the
44-id pinned union, then the close station: ledger entries (LED-…92.14+), the C4 stale-text carries
to BACKLOG-CODE lane A, the `ATLAS-*` regeneration, and the post-gate `docs/architecture.md`
amendment (color_policy freeze + render/ sub-module declarations per module-map F-1/§6.3).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ⚠ | 7 source files (7 modified, 0 new, 0 deleted) — >4 waiver per PDR condition C1, restated in §2; repoint-only increment over the measured closed sets |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_import_census.py` (TC-653/654) — 5-passed transcript (with TC-651/652/655 regression) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` ‹one complete run owned by the orchestrator ~ Layer 0› | ✓ | TC-654 value pins + microbar clamp arms at the new address; the `test_b77_safe_text_scrubs_*` 65/65 control-class table — all green in the cited runs |
| 4 | **RED counterfactual** declared — the mutation that made this increment's OWN new assertion fail, where its transcript is stored, and the restore digest, or `none` (C-20/C-40; read by `V44`) | `core` · `full` ‹RED counterfactual mandatory ~ RED counterfactual› | ✓ | §4 RED row: TC-653 census reddened by one flipped consumer; transcript `increment-002-tc653-red.transcript`; restore digest `badbba330a6d3fd504034df82abea752b60063e6af6b866a6c007ec5c41404fd` |
| 5 | **Reverse census** declared — the five probes run with their commands and verdicts, the ones that did NOT fire named with their probe, or `none` (C-26/C-48; read by `V43`) | `core` · `full` ‹reverse census of the touched symbol ~ Reverse census› | ✓ | §4 Reverse census: 5 probes (B1 11+10 files · B2 0 live readers · B3 0 goldens · B4 measured-set consumers · A3 closed set) |
| 6 | `code-reviewer` passed — a HIGH blocks; the verdict, the reviewer and each HIGH's resolution are declared in **§4b** (`ABSENT` is the empty state there, not a value) | `core` · `full` ‹RED counterfactual mandatory ~ code-reviewer› | ⚠ | §4b intentionally left EMPTY for the orchestrator's reviewer (per the increment brief) |
| 7 | No file from another lane touched | all | ✓ | sequential batch (module-map §5 Exit-1): `git diff 410cde5 --name-only` over Inc-B's set = exactly the §2 rows (+ Inc-A's already-landed files, disjoint line ranges per the ARQ Exit-2 analysis); the 6 view consumers' insight_style lines carry 0 edits |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `git diff 410cde5 --name-only -- s19_app/tui/color_policy.py s19_app/range_index.py s19_app/core.py s19_app/hexfile.py s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/render/` → 0 Inc-B edits (render/ untracked-from-Inc-A, untouched by this increment); TC-027 1 passed + TC-031 pair/TC-032 3 passed |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | every §4 figure names its stored transcript under `evidence/` with SHA-256 of the stored bytes |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | §4 Load-bearing emptiness: 3 absence claims, synthetic instances + positive controls named |
| 11 | **Mutation verdicts** declared — **per arm**, inert arms named, registry ids cited, or `none` (C-40 rider; read by `V37`) | all | ✓ | §4 Mutation verdicts: 4 arms, all KILLED, per-node verdicts, restore digests, no inert arms |
| 12 | **Instrument RED-proof** declared — every instrument shown able to report a FAILURE before its first PASS was believed, or `none` (C-57) | all | ✓ | §4 Instrument RED-proof: 4 instruments fed mechanism corruptions in this increment (+ TC-655's Inc-A RED history) |
| 13 | **Correction population** declared — enumerated with its method before the first site was edited, or `none` (C-14) | all | ✓ | §4 Correction population: 4 corrections (product safe_text edges, test safe_text edges, the 8 insight_style definitions, the validation_service edge) enumerated before editing |
| 14 | **Emitted-form assertion** declared — per artifact emitted, the assertion run against the EMITTED form and what it returned, or `none` (C-42; read by `V38`) | all | ✓ | §4 Emitted-form assertion: 3 artifacts (moved source span via SHA-256; hostile payload via `.plain`/`.spans`; strip via the service `Text`) |
| 15 | **Independent review** names somebody — in one of the forms §4b publishes; a cell naming nobody is empty (`V36`). §4b is the grammar's one home | all | ⚠ | §4b empty by the orchestrator's instruction — the reviewer fills it at the gate |
| 16 | **Evidence files** declared — every cited artifact at the home `artifact_homes.evidence` names, cited with the digest of its STORED bytes, or `none` (C-59; read by `V41`) | all | ✓ | §4 Evidence files: 13 artifacts, each with the digest of its stored bytes |
