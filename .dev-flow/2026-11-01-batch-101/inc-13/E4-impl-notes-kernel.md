# Inc 13 — E4 implementation notes (G3 kernel)

Unit: G3 — `s19_app/tui/operations/crc_kernel.py`. Implementer unit of batch-101 Inc 13, design-first flow. Graph nodes owned: `_REFLECT8`, `crc_lut` (interface I-7).

## Functions / constants changed

`s19_app/tui/operations/crc_kernel.py`:

- `_REFLECT8` — new module constant, placed after `reflect` as the graph directs:
  `_REFLECT8: bytes = bytes(reflect(b, 8) for b in range(256))`. Length 256,
  `_REFLECT8[b] == reflect(b, 8)` for every `b` in `0..255`. Sphinx `#:` comment
  states the invariant and the consumer.
- `crc_lut` — changed. Before the byte loop, when `refin` is set, the input is
  translated once: `data = bytes(memoryview(data)).translate(_REFLECT8)` (E3
  A-8 / SEC-5). The loop now runs the table step with no per-byte branch. When
  `refin` is false the input is iterated exactly as on base. The
  `bytes(memoryview(data))` normalisation keeps `bytes` / `bytearray` /
  `memoryview` accepted and makes an `int` argument raise `TypeError` (as base's
  `for byte in data` did), instead of `bytes(int)` producing zero bytes.
  Docstring `Data Flow` and `Dependencies` updated to name `_REFLECT8` and the
  one-shot translate; no other docstring text changed.

## Deviation from the graph

None. `_REFLECT8` and the `crc_lut` rewrite match `codewire/graph-inc13.md` I-7
and the `crc_lut` node (including the `bytes(memoryview(data)).translate(_REFLECT8)`
expression and the placement of `_REFLECT8` after `reflect`). Results are
identical to the base by construction (`_REFLECT8[b] == reflect(b, 8)`), pinned by
`tests/test_crc_kernel.py` differential tests (not run here, operator rule).

## py_compile result

`python -m py_compile s19_app/tui/operations/crc_kernel.py` — exit 0 (OK).

## Notes

- Only `s19_app/tui/operations/crc_kernel.py` was edited.
- Line endings preserved: file stays CRLF (438 CRLF, 0 LF-not-preceded-by-CR).
- No test file, REQUIREMENTS.md, AT-TC-REGISTRY.jsonl, or tests/test_id_registry.py
  was touched. No pytest run, no `s19_app` import (operator rule).
