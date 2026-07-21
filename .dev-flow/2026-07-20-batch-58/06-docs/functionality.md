# Functionality — CRC Algorithm Designer (Variant B view)

## What it is
A new TUI screen (**rail key `0`, glyph `⊕`**, `#screen_crc_designer`) that lets an operator *tailor* a CRC variant from parametric building blocks, **prove it correct against a known-answer vector live**, preview its result over a loaded firmware image under different gap policies, and save/load it as a reusable JSON template — **without ever writing firmware** (preview-only).

## The engine underneath (E4/E5/E6, headless, `s19_app/tui/operations/`)
Built on the batch-57 keel (`crc_kernel.py` width-general 8–64 engine + LUT; `crc_designer_model.py` template/job/coverage/gap-safety). batch-58 completed:
- **E4 word codec** (`crc.py`): `encode_word`/`decode_word` with big-endian + wider store-width; the legacy `encode_le`/`decode_le` stay byte-identical wrappers.
- **E5 template facade** (`crc_template.py`): a thin object-identity re-export of the `*.crc.json` loader (collect-don't-abort, size-capped, never raises).
- **E6 job up-converter + `emit_job`** (`crc_designer_model.py`): parses today's flat `crc_config` (poly/init/reverse/final_xor + regions/groups) AND the evolved algorithm-ref/targets shape into one internal `CrcJob`; serializes a whole job back.

## The view (§7 R-CRC-DSN-001..011)
- **Parameter form**: preset selector (7 catalogue CRCs) + algorithm fields (width, poly, init, refin, refout, xorout, check) + serialization (output address, store width, store endianness). Selecting a preset populates the form read-only (never mutates the catalogue).
- **Live known-answer verdict** (centerpiece): on any field change, recomputes CRC of `"123456789"` and shows **MATCH / MISMATCH / NO-EXPECTED** — no Run button. Out-of-range params render a markup-safe fault notice instead of crashing.
- **Custom test vector**: hex or ASCII input → its CRC under the current algorithm.
- **Live JSON preview**: renders the current template; the shown text round-trips (parses back identically).
- **Load / Save**: Save writes to a bounded template library (`.s19tool/templates/<sanitized>.crc.json`); Save validates the standard KAT and warns on mismatch; an all-symbol name writes nothing. Load reads through the collect-don't-abort facade — a bad file surfaces one error, never crashes. All file-derived text renders literally (markup-safe — no injection).
- **Coverage strip**: an ordered list of memory ranges + independent gap policies (intra-range skip/fill, inter-range concat/fill) + pad byte. With an image loaded, it **previews the CRC over the real bytes for both policies side by side**.
- **Gap safety**: for a `join="fill"` target, it checks the loaded image for data in the "erased" span it's about to pad; per `on_gap_conflict`, an `abort` policy refuses the preview (with the conflicting address), `warn` proceeds with a diagnostic, `ignore` is silent.
- **Preview-only guard**: the screen only reads the loaded image; it never mutates memory or writes firmware. The one write it performs is the bounded template file.

## Boundaries
Placement (inject/write CRC into firmware) stays in the existing work-area-contained CRC operation / Flow-Builder CRC block, which consume the saved job. The `crc.py` operation still uses its shipped 32-bit path (wiring the width-general kernel into it is a deferred follow-up).
