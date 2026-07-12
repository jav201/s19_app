# Project report: proj

- Project: proj
- Generated (UTC): 2026-07-10T12:00:00+00:00
- Tool version: 0.1.0
- Context bytes: 64
- Execution mode: active-only
- Assignment source: manifest

## Variant inventory

| Variant | File | Type | Active |
|---|---|---|---|
| a | a.s19 | s19 | yes |
| b | b.s19 | s19 | no |

## Consolidated overview

| Variant | Status | Changes applied | Checks passed | Checks failed | Checks uncheckable |
|---|---|---|---|---|---|
| a | ok | 1 | 0 | 0 | 0 |

## Legend

### A2L
- **Red** — schema/structural failure: malformed required field, invalid required reference, or hard-error duplicate symbol
- **Green** — memory checked — tag/range fully found in the loaded S19/HEX image
- **White** — valid A2L record with no hard inconsistency, including valid records not present in the image
- **Grey** — memory not checked yet, or no primary S19/HEX context loaded

### MAC
- **Red** — parse failed, invalid/missing name or hex address, or A2L↔MAC same-name address mismatch
- **Orange** — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity
- **Green** — exact name + address match with A2L
- **White** — structurally valid MAC entry, no hard inconsistency, not positively cross-confirmed
- **Grey** — no A2L loaded, or validation context missing

### Issues
- **Errors** (Red) — parse/structure errors, empty name, invalid/missing address, duplicate symbol, broken GROUP/FUNCTION references, or A2L↔MAC same-name mismatch
- **Warnings** (Orange) — address/range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias
- **Optional info** (Cyan) — valid-but-not-image-backed, not-checked-without-primary-image, or virtual/dependent non-memory-backed objects

### Hex
- **Yellow** — search / goto-focus highlight: the byte span matched by the last in-memory search or goto-address jump in the hex view
- **Orange3** — MAC address overlay: a hex byte at an address referenced by a loaded MAC record

## Variant: a

### Modified files

- <RUN-ROOT>/.s19tool/workarea/proj/chg.json (applied entries: 1) - saved as `<RUN-ROOT>/.s19tool/workarea/proj/a-patched.s19`

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00001000 | 1 | 01 | AA | standalone | - |

### Declaration errors

None.

### Checklists

No checklists were executed for this variant.

### Memory regions

Window 0x00000FC0-0x00001010:

```text
0x00000FC0                                                   |................|
0x00000FD0                                                   |................|
0x00000FE0                                                   |................|
0x00000FF0                                                   |................|
0x00001000  AA 02 03 04                                      |................|
```

### Entropy

- **low**: 1 window(s) (1 low-confidence)
