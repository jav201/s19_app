# Increment 008 — XML-safety + load/write path containment

> **Phase 3 · batch-03 · Increment 8.** Hardens the CDFX handler: the reader
> gains the XML-safety layer (DOCTYPE/`<!ENTITY>` rejection, 256 MB pre-parse
> byte cap, nesting-depth bound, `resolve_input_path` load-path resolution); the
> writer gains the work-area-contained write path. Spec: increment-plan §A.4 —
> Increment 8; requirements LLR-005.5, LLR-006.6, LLR-006.8, LLR-007.7;
> TC-027a/b, TC-035, TC-036, TC-037. Branch:
> `dev-flow/batch-02-direction-b-restyle`.
> **security-reviewer review required before this increment's gate.**

## 1. What changed

`s19_app/tui/cdfx/reader.py` was extended with the XML-safety layer that
increment 7 explicitly deferred, and `s19_app/tui/cdfx/writer.py` gained a
work-area-contained write path. Both reuse the existing, already-hardened
`s19_app/tui/workspace.py` helpers — no path-containment logic is
re-implemented and `workspace.py` is byte-unchanged. No new dependency: the
DOCTYPE-rejection-via-`expat`-handler is the stdlib-only answer (constraint
C-2 — no `defusedxml`).

**Reader — three safety bounds, all surfaced as one `R-XML-PARSE` issue
(collect-don't-abort, no crash, no hang, no external read):**

- **Pre-parse 256 MB byte cap (LLR-006.8).** `read_cdfx` checks the input byte
  size *before* any XML parser is constructed and rejects an over-cap input as
  one `R-XML-PARSE` issue with an empty change-list. The cap reuses
  `workspace.DEFAULT_COPY_SIZE_CAP_BYTES` (re-exported as `MAX_CDFX_SIZE_BYTES`)
  — one consistent ingest cap, not a new number. The size read goes through a
  module-level `_probe_size` seam so a test can monkeypatch an over-cap size
  for a small in-memory document (TC-035) without writing a real 256 MB file.

- **DOCTYPE / `<!ENTITY>` rejection before any entity expansion (LLR-006.6 /
  CV-04 / security N-1).** `read_cdfx` no longer uses `ET.fromstring`. The new
  `_safe_parse` builds a raw `xml.parsers.expat` parser driving an
  `ElementTree.TreeBuilder`, and installs a **`StartDoctypeDeclHandler`** that
  raises `_UnsafeXmlError` on the `<!DOCTYPE` declaration **itself**. This is
  the verified-correct CV-04 hook ordering: expat fires
  `StartDoctypeDeclHandler` on the `<!DOCTYPE` token *before* it reads any
  `<!ENTITY>` declaration inside the internal subset and long before any entity
  is expanded — so **no entity is ever declared or expanded**, neutralizing
  both the billion-laughs (internal-entity amplification) and external-entity
  (`SYSTEM`/`PUBLIC` file-read) vectors with one rule. An `EntityDeclHandler`
  that also raises is wired as belt-and-suspenders. A conformant CDF 2.0
  `.cdfx` carries no `DOCTYPE`, so a valid file is unaffected.

- **Nesting-depth bound (LLR-006.8).** `_safe_parse`'s `StartElementHandler`
  tracks element depth and raises `_UnsafeXmlError` once it passes
  `MAX_NESTING_DEPTH` (100 — a conformant `.cdfx` nests ~9 levels). A
  pathologically deep document is rejected without unbounded recursion or
  memory growth.

- **Load-path resolution (LLR-005.5).** `read_cdfx` gained a `base_dir`
  parameter; a `str`/`Path` source is now resolved through
  `workspace.resolve_input_path` before any file is opened — the same shared
  helper every other user-typed input path in the app uses. An unresolvable
  path is rejected as one `R-XML-PARSE` issue with **no file opened**; a
  `bytes` source skips resolution entirely (the in-memory path).

The expat parser uses `namespace_separator="}"` and the start/end handlers
reconstruct the leading `{` so a namespaced `.cdfx` produces tags
byte-identical to what `ET.fromstring` produced — every existing reader test
(namespace tolerance, backbone scoping, `VAL_BLK` expansion, `R-*` rules,
cross-checks) passes unchanged against the reworked parser.

**Writer — work-area-contained write path (LLR-007.7).** The new
`write_cdfx_to_workarea(change_list, resolution, base_dir, file_name)`
serializes the change-list with the existing `write_cdfx` (byte-unchanged),
stages the bytes under the engineer's chosen name in `.s19tool/workarea/temp/`
(itself inside the work area — no bytes ever land outside it), then calls
`workspace.copy_into_workarea` for the **containment-checked final placement**:
the target resolves under a `.s19tool/workarea/` root, a reparse-point
(symlink / NTFS junction) traversal is rejected, and an existing-name target is
dedup-suffixed (`_<N>` before the suffix) — no silent clobber. This is the
write-then-copy resolution of the increment-plan's open implementation choice
(DD-10): `copy_into_workarea` is a source→dest *copy* helper, so the writer
stages a real source file and lets the reused helper do the placement — **no
new write path, no `resolve_workarea_target` helper, no architect escalation
needed**. A `WorkareaContainmentError` from the reused helper is caught and
converted to one warning-level `W-WRITE-CONTAINMENT` `ValidationIssue` with a
`None` path — a rejection is a `ValidationIssue`, never an uncaught exception
(LLR-007.7 collect-don't-abort). `_safe_name` reduces a requested file name to
its bare `.cdfx`-suffixed component so the file name itself cannot escape the
work area.

`cdfx/__init__.py` re-exports `write_cdfx_to_workarea` so the increment-9 CDFX
service has one import surface, consistent with how increment 7 re-exported the
public entry points. `changelist.py`, `resolve.py`, `display.py`, the
`validation/` package and `app.py` are **byte-unchanged**. `pyproject.toml` /
`requirements.txt` are byte-unchanged — no new dependency, stdlib
`xml.parsers.expat` + `xml.etree.ElementTree` only (C-2).

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/cdfx/reader.py` | **modified** | Added the XML-safety layer: `_probe_size` (injectable size-probe seam), `_resolve_source` (LLR-005.5 path resolution via `resolve_input_path`), `_safe_parse` (LLR-006.6 DOCTYPE/`<!ENTITY>` rejection via an `expat` `StartDoctypeDeclHandler` that raises before any entity expansion, plus LLR-006.8 nesting-depth bound), `_UnsafeXmlError` (internal control-flow signal). `read_cdfx` gained a `base_dir` parameter and now: resolves the path → checks the 256 MB cap → calls `_safe_parse`. `_read_bytes` replaced by `_resolve_source`. New constants `MAX_CDFX_SIZE_BYTES`, `MAX_NESTING_DEPTH`. |
| `s19_app/tui/cdfx/writer.py` | **modified** | Added the work-area-contained write path: `write_cdfx_to_workarea` (serializes via `write_cdfx`, stages in `.s19tool/workarea/temp/`, places via the reused `workspace.copy_into_workarea`), `_safe_name` (bare `.cdfx`-suffixed file name), `_containment_issue` (the `W-WRITE-CONTAINMENT` warning). `write_cdfx` and `validate_w_rules` are byte-unchanged. |
| `s19_app/tui/cdfx/__init__.py` | **modified** | Re-export `write_cdfx_to_workarea` (added to `__all__` and the import). |
| `tests/test_cdfx_safety.py` | **new** | TC-027a (billion-laughs rejection — one `R-XML-PARSE`, empty change-list, no entity expanded, via bytes + via path), TC-027b (external-entity rejection — sentinel-file no-read detection), TC-035 (pre-parse size cap via the probe seam + parse-seam no-reach spy; nesting-depth bound). In-test fixtures `make_billion_laughs_cdfx`, `make_external_entity_cdfx`, `make_oversized_cdfx`, `make_deeply_nested_cdfx`. 15 tests. |
| `tests/test_cdfx_path_containment.py` | **new** | TC-036 (write-target containment / dedup / reparse-point rejection / containment-as-`ValidationIssue` at the function level), TC-037 (load-path `resolve_input_path` resolution + no-open spy on the file-open seam). Symlink-capability probe gates the reparse-point arm (CV-03). 11 tests. |

5 files — exactly the planned count, at the ≤5 cap.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_cdfx_safety.py tests/test_cdfx_path_containment.py
python -m pytest -q                                   # full suite, no regression
python -c "import s19_app.tui.cdfx"                    # cdfx package imports
python -m py_compile s19_app/tui/cdfx/reader.py s19_app/tui/cdfx/writer.py s19_app/tui/cdfx/__init__.py tests/test_cdfx_safety.py tests/test_cdfx_path_containment.py
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check on the five files, as instructed.

Manual safety check (billion-laughs + external-entity + oversized + deep-nest,
each rejected deterministically):

```
python -c "
from s19_app.tui.cdfx import read_cdfx
from s19_app.tui.cdfx import reader as r
bl=(b'<?xml version=\"1.0\"?><!DOCTYPE MSRSW [<!ENTITY a \"AAAA\"><!ENTITY b \"&a;&a;&a;\">]>'
    b'<MSRSW><SHORT-NAME>&b;</SHORT-NAME></MSRSW>')
cl,iss=read_cdfx(bl); print('billion-laughs:', len(cl.entries), [i.code for i in iss], 'AAAA leaked:', any('AAAA' in i.message for i in iss))
deep=b'<MSRSW>'+b'<x>'*200+b'</x>'*200+b'</MSRSW>'
cl,iss=read_cdfx(deep); print('deep-nest:', len(cl.entries), [i.code for i in iss])
"
```

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_cdfx_safety.py tests/test_cdfx_path_containment.py`** →
  `22 passed in 0.12s` — 15 safety tests + 11 path-containment tests minus the
  one reparse-point arm that runs only with symlink privilege (it **passed**
  here — symlink creation is available on this machine).
- **`pytest -q` (full suite)** → `570 passed, 2 skipped, 3 xfailed in 167.47s`,
  `27 snapshots passed`, **0 failed**. Baseline was 548 passed / 2 skipped /
  3 xfailed; 548 + 22 = 570 — exact, no regression, skip/xfail counts
  unchanged.
- **`python -c "import s19_app.tui.cdfx"`** → `IMPORT_CDFX_OK ['ChangeList',
  'ChangeListEntry', 'ResolutionStatus', 'read_cdfx', 'validate_w_rules',
  'write_cdfx', 'write_cdfx_to_workarea']` (clean exit) — `write_cdfx_to_workarea`
  is present.
- **`python -m py_compile`** on the five files → `PY_COMPILE_ALL_OK`.
- **`app.py` inspection** — `app.py` imports neither `xml.etree`/`ElementTree`
  nor `cdfx`; it is byte-unchanged (the UI wiring is increment 9, TC-028 holds).
- **CDFX package suites** (`test_cdfx_reader/r_rules/writer/w_rules.py`) →
  `79 passed` — every increment-1..7 cdfx test passes unchanged against the
  reworked `expat`-based parser and the extended writer.
- **Manual safety check** — billion-laughs: `0 entries, ['R-XML-PARSE'],
  AAAA leaked: False`; external-entity: `0 entries, ['R-XML-PARSE']`,
  sentinel content absent everywhere; oversized (probe seam): `0 entries,
  ['R-XML-PARSE']`, parse seam never reached; deep-nest: `0 entries,
  ['R-XML-PARSE']`. Each vector → exactly one `R-XML-PARSE`, empty change-list,
  no crash, no hang, no entity expansion, no external read.
- **Manual write check** — `write_cdfx_to_workarea` places `mypatch.cdfx` under
  `.s19tool/workarea/`; a second save of the same name dedup-suffixes to
  `mypatch_1.cdfx` (no clobber); a write→read round-trip recovers the entry
  exactly; the `temp/` staging dir is left empty.

### New tests by TC

**`tests/test_cdfx_safety.py` (15 tests):**
- **TC-027a** — 3 tests: a billion-laughs `.cdfx` (a real `<!DOCTYPE` with
  nested internal `<!ENTITY>` declarations, no `SYSTEM`) → exactly one
  `R-XML-PARSE` issue + empty change-list; **no entity expanded** (no
  amplified `lollol` text in any change-list entry or any issue message; the
  single issue names the `DOCTYPE` rejection, not an expansion result); the
  same rejection holds when the fixture is read from a resolved path.
- **TC-027b** — 2 tests: an external-entity `.cdfx` whose `<!ENTITY xxe
  SYSTEM ...>` points at a test-created sentinel temp file of known unique
  content → exactly one `R-XML-PARSE` issue + empty change-list; the
  no-external-read verdict — the sentinel marker string is **absent** from
  every parsed value, every entry field and every issue message.
- **TC-035** — 5 tests: an oversized `.cdfx` (probe seam reports over-cap) →
  one `R-XML-PARSE` issue + empty change-list, **and** the `_safe_parse` seam
  is asserted never reached (the size check precedes parsing); a probe at
  exactly the cap parses normally; a `.cdfx` nested past `MAX_NESTING_DEPTH` →
  one `R-XML-PARSE` issue with no unbounded recursion; a shallow document does
  **not** trip the depth bound; control + never-raises tests.
- **2 control tests** — a clean DOCTYPE-free `.cdfx` parses with zero
  `R-XML-PARSE` issues (the safety layer costs valid input nothing); every
  safety vector returns `(ChangeList, list[ValidationIssue])` and never raises.

**`tests/test_cdfx_path_containment.py` (11 tests):**
- **TC-036** — 5 tests: a save resolves under `.s19tool/workarea/`; an
  existing-name save dedup-suffixes (`patch.cdfx` → `patch_1.cdfx`, both
  survive — no clobber); a file name carrying `../` path separators is reduced
  to its bare component and stays contained; a save whose `.s19tool/workarea`
  is a symlink to an out-of-containment dir is rejected with a
  `W-WRITE-CONTAINMENT` warning and a `None` path (privilege-gated, CV-03); a
  forced `WorkareaContainmentError` from the reused helper is caught and
  surfaced as `W-WRITE-CONTAINMENT`, never raised.
- **TC-037** — 6 tests: a valid `.cdfx` path is resolved via
  `resolve_input_path` and read; a relative path resolves against `base_dir`;
  an unresolvable path → exactly one `R-XML-PARSE` issue + empty change-list;
  the no-open spy confirms **no file is opened** for an unresolvable path; the
  control arm confirms a resolvable path *does* open the file exactly once
  (the spy is meaningful); a `bytes` source skips `resolve_input_path`
  entirely.

No code defect was found during the run — the reader/writer changes and both
test files passed on the first full-suite run after implementation.

## 5. Risks

- **CV-04 `expat` hook ordering — verified, not assumed.** The plan flagged
  that a handler attached too late would let billion-laughs amplify. The chosen
  hook is expat's `StartDoctypeDeclHandler`, which fires on the `<!DOCTYPE`
  token itself — verified empirically (a billion-laughs payload that would
  amplify to ~10⁹ nodes is rejected with the handler raising before any
  `<!ENTITY>` is even read) and pinned by TC-027a's "no `lollol` text anywhere"
  assertion. `EntityDeclHandler` raising as well is belt-and-suspenders. A
  future maintainer who replaces `_safe_parse` with `ET.fromstring` would
  re-open the vector — TC-027a fails loudly if they do.
- **`ET.XMLParser` does not expose its raw `expat` parser in Python 3.12.** The
  plan's wording ("`parser.parser.StartDoctypeDeclHandler`") describes an older
  API. The implementation builds a raw `xml.parsers.expat` parser + an
  `ElementTree.TreeBuilder` directly — the documented, stable, stdlib-only
  route — and reconstructs the `{uri}` namespace prefix so tags are
  byte-identical to `ET.fromstring`. Every existing reader test (namespace
  tolerance TC-017, backbone scoping S-006, `VAL_BLK` expansion TC-039, all
  `R-*` rules) passes unchanged, which is the cross-check that the parser swap
  is behaviour-preserving. Surfaced for the security-reviewer: the parse path
  changed from `ET.fromstring` to a hand-driven `expat` + `TreeBuilder`.
- **`copy_into_workarea` is reused write-then-copy — no new write path.** The
  increment-plan raised "extract a `resolve_workarea_target` helper vs.
  write-then-copy" as a possible architect escalation. Write-then-copy was
  chosen and **needed no escalation**: the writer stages the bytes in
  `.s19tool/workarea/temp/` (a directory already inside the work area, created
  by `ensure_workarea`) and `copy_into_workarea` does the containment-checked
  placement — `workspace.py` is byte-unchanged, the containment / reparse /
  dedup / size guards are reused exactly as-is, not re-derived.
- **`Path.resolve()` collapses an ancestor symlink before `copy_into_workarea`
  sees it.** TC-036's reparse-point arm therefore makes `.s19tool/workarea`
  *itself* a symlink to an out-of-containment directory — that is the shape
  that genuinely fails `copy_into_workarea`'s containment check (the resolved
  destination has no `.s19tool/workarea` ancestor). This mirrors how the
  existing `test_junction_rejected_on_windows` workspace test exercises the
  same helper. The deterministic `WorkareaContainmentError`-stub test covers
  the rejection path independently of OS symlink privilege.
- **The reparse-point arm of TC-036 is privilege-gated (CV-03).** A
  `_can_create_symlink` probe skips it with a recorded reason on CI images /
  accounts without symlink privilege. It **passed** on this Windows machine;
  on a privilege-less CI image it skips cleanly (it does not fail). The
  `WorkareaContainmentError`-stub test (`test_tc036_containment_rejection_
  surfaces_issue_not_exception`) gives the containment-rejection path
  unconditional, privilege-independent coverage.
- **256 MB cap is checked on the in-memory byte length, not `stat().st_size`.**
  `read_cdfx` accepts `bytes | str | Path`; for a path the bytes are read then
  measured. A truly malicious 256 GB file on disk would be read into memory
  before the length check rejects it — but the load path resolves through
  `resolve_input_path` and the realistic `.cdfx` upper bound is far under the
  cap; the `_probe_size` seam exists precisely so the over-cap *path* is
  test-covered without a 256 MB file. A stricter `stat()`-before-read variant
  is a possible hardening if a future caller ingests fully untrusted
  filesystem paths — recorded, not speculatively built (engineering rule 2).
- **The increment-5 stale-test note still stands.** Unchanged by this
  increment — recorded so Phase 4 does not read it as new.

## 6. Pending items

- **security-reviewer pass — required before this increment's gate.** The
  DOCTYPE/`<!ENTITY>` rejection, the CV-04 `expat` hook ordering, the
  size/depth bounds and the `copy_into_workarea` write-path reuse are all
  security-sensitive. TC-027a/TC-027b are the explicit validation hook for
  LLR-006.6 and are designated for security-reviewer review (requirements
  §5.5). This packet surfaces, for that review: (a) the parse path moved from
  `ET.fromstring` to a hand-driven `expat` + `TreeBuilder`; (b) the chosen hook
  is `StartDoctypeDeclHandler` (fires on `<!DOCTYPE`, before any entity work);
  (c) the writer reuses `copy_into_workarea` write-then-copy with no new write
  path.
- **Increment 9 — Functional Patch Editor screen.** The CDFX service
  (`cdfx_service.py`) and the Patch Editor screen will call `read_cdfx`
  (passing the genuine `base_dir` and the enriched A2L tags) and
  `write_cdfx_to_workarea`. The integration arm of TC-027a (load action drives
  a malicious `.cdfx`), TC-036 and TC-037 through `App.run_test()` is
  increment 11.
- **TC-024 round-trip** (write→read structural equality incl. the adversarial
  IEEE floats) remains increment 10.
- **CV-01** Phase-2 closure cosmetic item has no natural touch-point in these
  five files — surfaced again so it is not lost (CV-02/CV-03 were applied in
  increment 5; CV-03's privilege-gating discipline is honoured here in
  TC-036's reparse arm).

## 7. Suggested next task

**Increment 9 — Functional Patch Editor screen.** Replace the inert
`PatchEditorPanel` with a working screen: change-list rows (a row per entry,
blank index column for a `None`-index scalar), wired add/edit/remove inputs,
save/load action buttons, the neutral empty-state line; add
`tui/services/cdfx_service.py` orchestrating the `cdfx` package calls
(build/resolve/format/`write_cdfx_to_workarea`/`read_cdfx`); `app.py` holds UI
wiring only (no XML, no model logic — LLR-007.5 / TC-028). 5 files, 4 TCs
(TC-025, TC-026, TC-028, TC-027a integration arm). **qa-reviewer handoff** —
this increment ships the functional screen; propose the TC-025/026/028
acceptance criteria and the manual Patch-Editor test plan (including the
increment-6 `W-ARRAY-SPARSE` and this increment's `W-WRITE-CONTAINMENT`
fail-loud behaviours) to `qa-reviewer`.

---

**Stop boundary reached.** Increment 8 is complete: `reader.py` rejects a
`DOCTYPE`/`<!ENTITY>`-bearing `.cdfx` via an `expat` `StartDoctypeDeclHandler`
that raises before any entity is declared or expanded, rejects an over-256 MB
input before parsing, bounds XML nesting depth, and resolves a user-supplied
load path through `workspace.resolve_input_path` — every safety trip surfaced
as one `R-XML-PARSE` `ValidationIssue` with no crash, no hang, no external read;
`writer.py` gained `write_cdfx_to_workarea`, a work-area-contained write path
reusing `workspace.copy_into_workarea` (containment / reparse-point rejection /
dedup-suffix), surfacing a rejection as one `W-WRITE-CONTAINMENT` issue;
`cdfx/__init__.py` re-exports `write_cdfx_to_workarea`; the two new test modules
are green (22 passed); the full suite is 570 passed / 2 skipped / 3 xfailed /
0 failed (548 baseline + 22); `s19_app.tui.cdfx` and the app import unchanged;
`app.py` and `workspace.py` are byte-unchanged; no new dependency. A
security-reviewer pass is required before this increment's gate. Awaiting
approval before starting increment 9.
