# s19_app — S19 / Intel HEX / A2L / MAC workbench

An **offline terminal workbench for automotive firmware artefacts**. It parses a
flash image (Motorola S-record or Intel HEX), the ASAM **A2L** file that
describes the calibration symbols inside it, and the **MAC** (`TAG=hexaddr`)
symbol map — then cross-checks all three against one another and shows you every
place they disagree.

No GUI, no daemon, no network calls, no external services. Everything runs
locally in a terminal against files on disk.

Distribution name `s19tool`; the terminal UI is `s19tui`.

<p align="center">
  <img src="docs/images/s19tui-rail-tour.gif" alt="s19tui cycling through the Workspace, A2L Explorer, MAC View, Memory Map and Issues Report screens" width="900">
</p>

<sub>Real capture: each frame is a native Textual SVG export from a headless
`S19TuiApp` loaded with `examples/case_07_stress_smoke/`. Regenerate with
`python docs/images/capture_readme_media.py`.</sub>

---

## Why it exists

An ECU flash image, its A2L description and its MAC symbol map are produced by
different tools at different times. They routinely drift apart: a symbol moves,
an A2L is regenerated against a build that never shipped, a MAC is hand-edited.
Individually each file looks fine. The damage only shows up when you fuse them
into one address space and ask which claims actually hold.

That fusion is what this tool does.

![How the cross-artefact validation works](docs/images/cross-artefact-pipeline.png)

<sub>Open the image full size to read it. Every name, address, issue code and
count above is taken from running the code over
`examples/case_07_stress_smoke/`.</sub>

The three parsers each collect failures rather than aborting, so a malformed
record never costs you the rest of the file. The results converge on
`s19_app/validation/engine.py::validate_artifact_consistency`, which returns a
`ValidationReport` of `ValidationIssue` records. Issue codes
(`CROSS_MAC_S19_OUT_OF_RANGE`, `TRIPLE_NAME_ADDRESS_MISMATCH`, …) are a public
contract — the test suite asserts on them.

---

## Install

Requires **Python 3.11 or newer** — that is what CI runs, and it is the only
version the suite is verified on. `pyproject.toml` declares
`requires-python = ">=3.11"` to match. (The packaged tree's *mechanical* floor
is 3.10: 39 `@dataclass(slots=True)` sites and the PEP 604 union at
`s19_app/cli.py:220`. Nothing in CI exercises 3.10, so the declared floor stays
at the tested version.)

```bash
git clone https://github.com/jav201/s19_app.git
cd s19_app
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Windows;  source .venv/bin/activate on Linux/macOS
pip install -e .
```

This installs one console script, **`s19tui`**. For the snapshot-testing extra:

```bash
pip install -e ".[dev]"
```

---

## The TUI — `s19tui`

```bash
s19tui
s19tui --load examples/case_07_stress_smoke/firmware.s19
```

A left activity rail switches between ten single-context screens, bound to keys
`1`–`0`.

| Key | Screen |
|----|--------|
| `1` | Workspace — sections · hex · context |
| `2` | A2L Explorer — symbol table + hex pane |
| `3` | MAC View — record table + hex pane |
| `4` | Memory Map — coverage + entropy bands |
| `5` | Issues Report — validation findings |
| `6` | Patch Editor — change-set authoring, checks, patched-image emit |
| `7` | A2B Diff — compare two images, emit a diff report |
| `8` | Flow Builder — ordered operation chains over project images |
| `9` | Checks — every check result, grouped by outcome |
| `0` | CRC Designer — parametric CRC authoring + known-answer proof |

Every other bound key (the full set lives in `S19TuiApp.BINDINGS`,
`s19_app/tui/app.py`):

| Key | Action |
|-----|--------|
| `Ctrl+K` | command palette |
| `Ctrl+D` | cycle layout density |
| `Ctrl+L` / `l` | load a file |
| `Ctrl+S` / `s` | save project |
| `p` | load project |
| `U` | unload everything (images, A2L, MAC) |
| `r` | refresh the workarea file list |
| `o` | open the workarea folder |
| `v` | select the active variant |
| `x` | Operations modal |
| `j` | dump the enriched A2L as JSON |
| `t` | report viewer |
| `b` | before/after report for the applied change-set |
| `/` | find in memory |
| `g` | go-to address |
| `k` | legend (scoped to the active screen) |
| `?` | help — lists every active binding, including the hidden ones |
| `+` / `-` | page the focused table/viewer forward / back (also `PgDn` / `PgUp`) |
| `,` / `.` | page the hex pane back / forward |
| `Ctrl+Z` / `Ctrl+Y` | undo / redo the Patch Editor change-set |
| `q` | quit |

Most of these are `show=False` bindings — the footer stays uncrowded, and
`?` is the in-app way to discover all of them.

### Workspace

Sections list with per-range validity, the hex/ASCII view, and live coverage
stats.

![Workspace screen](docs/images/workspace.png)

### A2L Explorer

Each A2L symbol resolved against the loaded image. Green rows are present in
memory; grey rows are not — here `MEAS_000000` at `0x08001400` falls outside
every S19 range, so it reads `no` under **InMem**.

![A2L Explorer screen](docs/images/a2l-explorer.png)

### MAC View

The MAC map cross-checked against both the image and the A2L. Note
`MEAS_000000` appearing twice with two different addresses, and the malformed
lines flagged rather than dropped.

![MAC View screen](docs/images/mac-view.png)

### Memory Map

Region coverage with entropy banding — a quick read on which regions look like
code, calibration data or padding.

![Memory Map screen](docs/images/memory-map.png)

### Issues Report

Everything the validation engine found, grouped by severity. For this fixture:
32 issues, 8 errors, 24 warnings.

![Issues Report screen](docs/images/issues-report.png)

### Patch Editor

Authors a **change-set**: address-keyed entries of new bytes, validated
against the loaded image's ranges, checkable, undoable (`Ctrl+Z`/`Ctrl+Y`).
The change-set saves and loads as a versioned JSON document
(`"format": "s19app-changeset"`, `"version": "2.0"` — the v2 change-set
engine in `s19_app/tui/changes/`); the retired v1 envelope is recognised
only to be rejected with a `CHG-V1-FORMAT` finding. **Apply** writes the
entries into a working copy of the image, and **Save patched** emits the
result as a real `.s19` / `.hex` file into the workarea — the change-set
JSON plus the patched image emit are the shipped hand-off.

### A↔B Diff

Loads a second image and diffs the two memory maps into classified runs
(`changed` / `only_a` / `only_b`), then emits a diff report as Markdown or
self-contained HTML.

### Flow Builder

Composes an ordered chain of typed blocks (`SOURCE` → `PATCH` → `WRITE-OUT`,
plus CRC) and runs it over a project image — or over every variant of a
project, producing one fused report rather than one file per variant. Flows
persist to `flow.json`.

### Checks

A read-only rail mirror of the Patch Editor's check results: every entry of
the last check run, grouped by outcome (fail → uncheckable → pass) with
per-group counts.

### CRC Designer

Tailors a CRC from the parametric (Rocksoft) building blocks — width 8–64,
polynomial, init, reflection, final XOR — seeded from a catalogue of named
presets. A live known-answer verdict (`MATCH` / `MISMATCH` / `NO-EXPECTED`)
recomputes on every keystroke, and the algorithm saves/loads as a
`*.crc.json` template.

### Operations modal

`x` lists the registered operations (the deterministic registry in
`s19_app/tui/operations/registry.py`: `crc`, `extract`, `split_by_segment`)
and executes the selected one against the loaded image, in-app.

### Projects and variants

A saved project is a directory under the workarea holding a `project.json`
manifest. The manifest can declare **variants** — named image/A2L/MAC
assignments — with one active variant (`v` switches it). Flows and
change-set runs can execute variant-scoped: each variant's image is parsed
in isolation, one failing variant never aborts the rest, and the run leaves
a single fused report.

### Workarea

The TUI keeps its own on-disk area next to where you launched it:

| Path | Holds |
|------|-------|
| `.s19tool/workarea/temp/` | transient loads |
| `.s19tool/workarea/<project>/` | saved projects — a `project.json` manifest plus the image / MAC / A2L artefacts it references, optionally per-variant |
| `.s19tool/logs/s19tui.log` | TUI log, 5 MB rotating |

---

## The CLI — legacy, module-only

> **This is not the interface to build on. `s19tui` — the TUI — is the product
> surface.** The CLI is the library's legacy command line and is **slated for
> removal**: its console script was deleted from `pyproject.toml`, so there is no
> `s19tool` command — what remains runs only as a module. It is documented here so
> that anyone who finds a reference to it knows what it is and what replaced it —
> not as a supported surface.

```bash
python -m s19_app.cli <subcommand> <file>
```

The subcommand comes *before* the file path — the reverse of what older docs show.

<details>
<summary>Remaining subcommands, for reference</summary>

```bash
# General info
python -m s19_app.cli info examples/case_01_basic_valid/firmware.s19

# Checksums, overlaps, record ordering
python -m s19_app.cli verify examples/case_01_basic_valid/firmware.s19

# Memory layout
python -m s19_app.cli layout examples/case_01_basic_valid/firmware.s19
python -m s19_app.cli ranges examples/case_01_basic_valid/firmware.s19
python -m s19_app.cli gaps   examples/case_01_basic_valid/firmware.s19

# Hex dump
python -m s19_app.cli dump examples/case_01_basic_valid/firmware.s19 --start 0x80000000 --length 48
python -m s19_app.cli dump-all      examples/case_01_basic_valid/firmware.s19
python -m s19_app.cli dump-by-range examples/case_01_basic_valid/firmware.s19 --output memory.txt

# Patching
python -m s19_app.cli patch-str examples/case_01_basic_valid/firmware.s19 \
    --addr 0x80000000 --text "HELLO" --save-as modified.s19
python -m s19_app.cli patch-hex examples/case_02_gaps_and_patch_targets/firmware.s19 \
    --addr 0x80010080 --bytes "DE AD BE EF" --save-as modified.s19

# Version
python -m s19_app.cli version
```

`dump` produces:

```
0x80000000  53 31 39 54 4F 4F 4C 5F 42 41 53 49 43 00 01 02  | S19TOOL_BASIC...
0x80000010  03 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E  | ................
0x80000020  0F                                               | .
```

Full subcommand list: `info`, `layout`, `ranges`, `gaps`, `version`, `verify`,
`update-checksums`, `dump`, `dump-by-range`, `dump-all`, `patch-str`,
`patch-hex`, `save`.

</details>

Every one of these has an equivalent in the TUI, which is where the work has gone.

---

## Formats

All open, publicly specified formats. None of them is vendor-private.

| Format | Owner / standard | Also seen as | Parser |
|--------|------------------|--------------|--------|
| Motorola S-record | Motorola, mid-1970s | `.s19` `.s28` `.s37` `.s` `.s1` `.s2` `.s3` `.sx` `.srec` `.mot` `.exo` `.mxt` | `s19_app/core.py` |
| Intel HEX | Intel | `.hex` `.ihex` | `s19_app/hexfile.py` |
| A2L | **ASAM MCD-2 MC**, also called ASAP2 | `.a2l`, plus its `.aml` companion | `s19_app/tui/a2l.py` |
| MAC symbol map | no branded standard — see below | `.mac` and equivalents | `s19_app/tui/mac.py` |
| Change-set JSON (v2) | this project | `"format": "s19app-changeset"`, `"version": "2.0"` | `s19_app/tui/changes/io.py` |

The earlier CDF 2.0 (ASAM MCD-2 CAL, `.cdfx`) import/export was **removed** —
the `s19_app/tui/cdfx/` package no longer exists. The shipped replacement for
the calibration-change hand-off is the v2 change-set JSON above plus the
patched S19/HEX image emit from the Patch Editor.

**On the S-record family.** `S19`, `S28` and `S37` are the same format at three
address widths — 16-bit (up to 64 KB), 24-bit (16 MB) and 32-bit (4 GB). The many
extensions above are conventions, not different formats.

**Extensions do not gate anything here.** Neither `core.py` nor the load service
inspects the filename; the parsers key on record structure. A `.mot` or `.srec`
file loads exactly like a `.s19`.

**On MAC.** This is the one entry that is a *shape* rather than a named standard:
a flat text listing of `TAG=hexaddr` lines. Different toolchains emit an
equivalent symbol→address map under different names and extensions, and the
parser reads the shape rather than claiming a particular vendor's format.

*Not to be confused with a tuning "map pack".* The aftermarket world has richer,
vendor-owned equivalents — EVC Electronic's WinOLS uses `.kp` / `.olsx`, and the
Bosch-lineage DAMOS files appear as `.damos` / `.kp` / `.dcm`. Those carry
conversion factors, axis definitions and folder structure, and are proprietary.
**This tool does not read any of them.** What it reads is the plain
`TAG=hexaddr` text form and nothing more.

**A2L belongs to ASAM, not to any tool vendor.** ASAM MCD-2 MC has been public
since 1999 (current revision 1.7.1, 2018). Vendor tools such as Vector CANape
and vCDM *consume* A2L; they do not own it, and this project is written
against the published standards rather than against any vendor's implementation.

### Provenance

This tool was built from **public specifications and public documentation only**.
Every fixture under `examples/` is synthetic and generated in-repo, and the
screenshots and GIF in this README are rendered from those fixtures — see
[`docs/images/capture_readme_media.py`](docs/images/capture_readme_media.py),
whose stated policy is that it may only ever read from `examples/`.

**No employer, customer or otherwise proprietary artefact appears anywhere in
this repository**, and none was used to build it.

One clarification, since the wording invites misreading: the batch records under
`.dev-flow/` repeatedly discuss keeping "client artefacts" and "operator
firmware" out of the repository. That language is **preventive, not
confessional** — it states what a *user* of this tool must never commit, and
documents the controls that enforce it, such as the rule that snapshot baselines
may render only from the public synthetic fixtures. It is not a record of
proprietary data having been used here.

---

## Example fixtures

`examples/` carries synthetic S19 / A2L / MAC triples, each built to exercise a
different failure mode. They are also the inputs the test suite and the
screenshots above use.

| Case | Exercises |
|------|-----------|
| `case_01_basic_valid` | clean baseline — verify passes, no overlaps |
| `case_02_gaps_and_patch_targets` | gaps plus explicit patch targets |
| `case_03_overlapping_records` | records writing the same addresses |
| `case_04_bad_checksums` | checksum failures |
| `case_05_dense_mixed_content` | dense mixed content |
| `case_06_large_nested_a2l` | deeply nested / large A2L |
| `case_07_stress_smoke` | the full end-to-end pipeline — every cross-artefact rule |
| `case_00_public` | public A2L samples (ASAP2 demo files) + `MANIFEST.md` |

`examples/professional_validation/` holds a second suite of seven cases
(baseline, patch targets, overlaps, bad checksums, out-of-order records,
cross-reference inconsistencies, heavy fragmentation).

---

## Tests

```bash
pytest -q                    # everything
pytest -q -m "not slow"      # skip the perf smoke tests
pytest -q -m "not snapshot"  # skip the layout-drift SVG baselines
```

`pytest --collect-only -q` reports **2760 collected tests** (measured
2026-10-11). CI
(`.github/workflows/tui-ci.yml`) runs the lean suite on pull requests and the
full suite on pushes to `main` / `main-tui`, on Python 3.11.

---

## Known rough edges

Things you will hit if you follow this README, stated plainly rather than
papered over:

- `project.toml` at the repo root is a pre-PEP-621 leftover. The build reads
  `pyproject.toml` only.

**On the deprecated CLI**, kept here for anyone who still runs it. These are not
TUI defects and are not being fixed — the surface is going away:

- **No `s19tool` console script.** `pyproject.toml` registers only `s19tui`
  (deliberately — commit `3a55416`). Use `python -m s19_app.cli`.
- **`verify` crashes on a non-UTF-8 console when it has failures to print.**
  `cli.py` writes a `❌` and Windows `cp1252` consoles raise
  `UnicodeEncodeError` — so it fails exactly when it has something to tell you.
  Workaround: `PYTHONIOENCODING=utf-8`.
- **`dump` at an unmapped address prints blank rows** instead of saying nothing
  is mapped there. Check `ranges` first.
- **`dump-by-range --output` writes ANSI colour escapes into the file.**

---

## Documentation

| Document | Covers |
|----------|--------|
| [docs/overview.md](docs/overview.md) | what it is, who it is for, current capabilities |
| [docs/architecture.md](docs/architecture.md) | the three layers, TUI shell, `changes/` + `operations/` packages, safety contracts |
| [docs/diagrams/architecture.md](docs/diagrams/architecture.md) | living Mermaid architecture diagrams |
| [REQUIREMENTS.md](REQUIREMENTS.md) | `R-*` requirement traceability |
| [CLAUDE.md](CLAUDE.md) | conventions, commands, layer rules |
| [PROJECT_RULES.md](PROJECT_RULES.md) | docstring and function-design contract |

---

## Licence

MIT, declared in `pyproject.toml`. There is no `LICENSE` file in the repository
yet.
