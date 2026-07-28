<!-- batch-64 Inc-1 byte-identity golden (LLR-103.4 / AT-196 / TC-491).
     Captured from the SHIPPED _addendum_lines at base revision 082ada9,
     BEFORE the producer was touched (C-12). Every shape is BELOW the
     per-(region, class) bound, which is the only regime in which
     LLR-103.4 promises byte identity. Regenerate ONLY by re-running
     tests/test_report_addendum_bound.py::_capture_golden against the
     pre-batch-64 producer — never after the rewrite. -->

<!-- s19tool-golden-shape: R1V1E1 -->
# Project report: proj

- Project: proj
- Generated (UTC): 2026-07-27T12:00:00+00:00
- Tool version: 0.1.0
- Context bytes: 64
- Execution mode: batch
- Assignment source: default

## Variant inventory

| Variant | File | Type | Active |
|---|---|---|---|
| v0 | v0\.s19 | s19 | yes |

## Consolidated overview

| Variant | Status | Changes applied | Checks passed | Checks failed | Checks uncheckable |
|---|---|---|---|---|---|
| v0 | ok | 1 | 0 | 0 | 0 |

## Legend

### A2L
- **Red** — schema/structural failure: malformed required field, invalid required reference, or hard-error duplicate symbol
- **Green** — memory checked — tag/range fully found in the loaded S19/HEX image
- **White** — valid A2L record with no hard inconsistency, including valid records not present in the image
- **Grey** — memory not checked yet, or no primary S19/HEX context loaded

### MAC
- **Red** — parse failed, invalid/missing name or hex address, or A2L↔MAC same-name address mismatch
- **Pale yellow** — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity
- **Green** — exact name + address match with A2L
- **White** — structurally valid MAC entry, no hard inconsistency, not positively cross-confirmed
- **Grey** — no A2L loaded, or validation context missing

### Issues
- **Errors** (Red) — parse/structure errors, empty name, invalid/missing address, duplicate symbol, broken GROUP/FUNCTION references, or A2L↔MAC same-name mismatch
- **Warnings** (Pale yellow) — address/range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias
- **Optional info** (Cyan) — valid-but-not-image-backed, not-checked-without-primary-image, or virtual/dependent non-memory-backed objects

### Hex
- **Yellow** — search / goto-focus highlight: the byte span matched by the last in-memory search or goto-address jump in the hex view
- **Orange3** — MAC address overlay: a hex byte at an address referenced by a loaded MAC record

## Variant: v0

### Modified files

- `chg_v0.json` (applied entries: 1)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00001000 | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1001
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1002

### Checklists

#### Checklist: `chk_v0.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Addendum: declared regions

### zone 0 (0x1000-0x2000)
- modification @ 0x1000 (variant v0)
- issue [CHG-SYNTAX] @ 0x1001 (variant v0)
- issue [CHK-MISMATCH] @ 0x1002 (variant v0)
<!-- s19tool-golden-shape: R3V2E5 -->
# Project report: proj

- Project: proj
- Generated (UTC): 2026-07-27T12:00:00+00:00
- Tool version: 0.1.0
- Context bytes: 64
- Execution mode: batch
- Assignment source: default

## Variant inventory

| Variant | File | Type | Active |
|---|---|---|---|
| v0 | v0\.s19 | s19 | yes |
| v1 | v1\.s19 | s19 | no |

## Consolidated overview

| Variant | Status | Changes applied | Checks passed | Checks failed | Checks uncheckable |
|---|---|---|---|---|---|
| v0 | ok | 5 | 0 | 0 | 0 |
| v1 | ok | 5 | 0 | 0 | 0 |

## Legend

### A2L
- **Red** — schema/structural failure: malformed required field, invalid required reference, or hard-error duplicate symbol
- **Green** — memory checked — tag/range fully found in the loaded S19/HEX image
- **White** — valid A2L record with no hard inconsistency, including valid records not present in the image
- **Grey** — memory not checked yet, or no primary S19/HEX context loaded

### MAC
- **Red** — parse failed, invalid/missing name or hex address, or A2L↔MAC same-name address mismatch
- **Pale yellow** — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity
- **Green** — exact name + address match with A2L
- **White** — structurally valid MAC entry, no hard inconsistency, not positively cross-confirmed
- **Grey** — no A2L loaded, or validation context missing

### Issues
- **Errors** (Red) — parse/structure errors, empty name, invalid/missing address, duplicate symbol, broken GROUP/FUNCTION references, or A2L↔MAC same-name mismatch
- **Warnings** (Pale yellow) — address/range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias
- **Optional info** (Cyan) — valid-but-not-image-backed, not-checked-without-primary-image, or virtual/dependent non-memory-backed objects

### Hex
- **Yellow** — search / goto-focus highlight: the byte span matched by the last in-memory search or goto-address jump in the hex view
- **Orange3** — MAC address overlay: a hex byte at an address referenced by a loaded MAC record

## Variant: v0

### Modified files

- `chg_v0.json` (applied entries: 5)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00001000 | 1 | 01 | AA | standalone | - |
| 0x00001004 | 1 | 01 | AA | standalone | - |
| 0x00001008 | 1 | 01 | AA | standalone | - |
| 0x0000100C | 1 | 01 | AA | standalone | - |
| 0x00001010 | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1001
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1005
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1009
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x100D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1011
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1002
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1006
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1012

### Checklists

#### Checklist: `chk_v0.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Variant: v1

### Modified files

- `chg_v1.json` (applied entries: 5)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00001000 | 1 | 01 | AA | standalone | - |
| 0x00001004 | 1 | 01 | AA | standalone | - |
| 0x00001008 | 1 | 01 | AA | standalone | - |
| 0x0000100C | 1 | 01 | AA | standalone | - |
| 0x00001010 | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1001
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1005
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1009
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x100D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1011
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1002
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1006
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1012

### Checklists

#### Checklist: `chk_v1.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Addendum: declared regions

### zone 0 (0x1000-0x2000)
- modification @ 0x1000 (variant v0)
- modification @ 0x1004 (variant v0)
- modification @ 0x1008 (variant v0)
- modification @ 0x100C (variant v0)
- modification @ 0x1010 (variant v0)
- issue [CHG-SYNTAX] @ 0x1001 (variant v0)
- issue [CHG-SYNTAX] @ 0x1005 (variant v0)
- issue [CHG-SYNTAX] @ 0x1009 (variant v0)
- issue [CHG-SYNTAX] @ 0x100D (variant v0)
- issue [CHG-SYNTAX] @ 0x1011 (variant v0)
- issue [CHK-MISMATCH] @ 0x1002 (variant v0)
- issue [CHK-MISMATCH] @ 0x1006 (variant v0)
- issue [CHK-MISMATCH] @ 0x100A (variant v0)
- issue [CHK-MISMATCH] @ 0x100E (variant v0)
- issue [CHK-MISMATCH] @ 0x1012 (variant v0)
- modification @ 0x1000 (variant v1)
- modification @ 0x1004 (variant v1)
- modification @ 0x1008 (variant v1)
- modification @ 0x100C (variant v1)
- modification @ 0x1010 (variant v1)
- issue [CHG-SYNTAX] @ 0x1001 (variant v1)
- issue [CHG-SYNTAX] @ 0x1005 (variant v1)
- issue [CHG-SYNTAX] @ 0x1009 (variant v1)
- issue [CHG-SYNTAX] @ 0x100D (variant v1)
- issue [CHG-SYNTAX] @ 0x1011 (variant v1)
- issue [CHK-MISMATCH] @ 0x1002 (variant v1)
- issue [CHK-MISMATCH] @ 0x1006 (variant v1)
- issue [CHK-MISMATCH] @ 0x100A (variant v1)
- issue [CHK-MISMATCH] @ 0x100E (variant v1)
- issue [CHK-MISMATCH] @ 0x1012 (variant v1)

### zone 1 (0x1000-0x3000)
- modification @ 0x1000 (variant v0)
- modification @ 0x1004 (variant v0)
- modification @ 0x1008 (variant v0)
- modification @ 0x100C (variant v0)
- modification @ 0x1010 (variant v0)
- issue [CHG-SYNTAX] @ 0x1001 (variant v0)
- issue [CHG-SYNTAX] @ 0x1005 (variant v0)
- issue [CHG-SYNTAX] @ 0x1009 (variant v0)
- issue [CHG-SYNTAX] @ 0x100D (variant v0)
- issue [CHG-SYNTAX] @ 0x1011 (variant v0)
- issue [CHK-MISMATCH] @ 0x1002 (variant v0)
- issue [CHK-MISMATCH] @ 0x1006 (variant v0)
- issue [CHK-MISMATCH] @ 0x100A (variant v0)
- issue [CHK-MISMATCH] @ 0x100E (variant v0)
- issue [CHK-MISMATCH] @ 0x1012 (variant v0)
- modification @ 0x1000 (variant v1)
- modification @ 0x1004 (variant v1)
- modification @ 0x1008 (variant v1)
- modification @ 0x100C (variant v1)
- modification @ 0x1010 (variant v1)
- issue [CHG-SYNTAX] @ 0x1001 (variant v1)
- issue [CHG-SYNTAX] @ 0x1005 (variant v1)
- issue [CHG-SYNTAX] @ 0x1009 (variant v1)
- issue [CHG-SYNTAX] @ 0x100D (variant v1)
- issue [CHG-SYNTAX] @ 0x1011 (variant v1)
- issue [CHK-MISMATCH] @ 0x1002 (variant v1)
- issue [CHK-MISMATCH] @ 0x1006 (variant v1)
- issue [CHK-MISMATCH] @ 0x100A (variant v1)
- issue [CHK-MISMATCH] @ 0x100E (variant v1)
- issue [CHK-MISMATCH] @ 0x1012 (variant v1)

### zone 2 (0x1000-0x4000)
- modification @ 0x1000 (variant v0)
- modification @ 0x1004 (variant v0)
- modification @ 0x1008 (variant v0)
- modification @ 0x100C (variant v0)
- modification @ 0x1010 (variant v0)
- issue [CHG-SYNTAX] @ 0x1001 (variant v0)
- issue [CHG-SYNTAX] @ 0x1005 (variant v0)
- issue [CHG-SYNTAX] @ 0x1009 (variant v0)
- issue [CHG-SYNTAX] @ 0x100D (variant v0)
- issue [CHG-SYNTAX] @ 0x1011 (variant v0)
- issue [CHK-MISMATCH] @ 0x1002 (variant v0)
- issue [CHK-MISMATCH] @ 0x1006 (variant v0)
- issue [CHK-MISMATCH] @ 0x100A (variant v0)
- issue [CHK-MISMATCH] @ 0x100E (variant v0)
- issue [CHK-MISMATCH] @ 0x1012 (variant v0)
- modification @ 0x1000 (variant v1)
- modification @ 0x1004 (variant v1)
- modification @ 0x1008 (variant v1)
- modification @ 0x100C (variant v1)
- modification @ 0x1010 (variant v1)
- issue [CHG-SYNTAX] @ 0x1001 (variant v1)
- issue [CHG-SYNTAX] @ 0x1005 (variant v1)
- issue [CHG-SYNTAX] @ 0x1009 (variant v1)
- issue [CHG-SYNTAX] @ 0x100D (variant v1)
- issue [CHG-SYNTAX] @ 0x1011 (variant v1)
- issue [CHK-MISMATCH] @ 0x1002 (variant v1)
- issue [CHK-MISMATCH] @ 0x1006 (variant v1)
- issue [CHK-MISMATCH] @ 0x100A (variant v1)
- issue [CHK-MISMATCH] @ 0x100E (variant v1)
- issue [CHK-MISMATCH] @ 0x1012 (variant v1)
<!-- s19tool-golden-shape: R2V3E66 -->
# Project report: proj

- Project: proj
- Generated (UTC): 2026-07-27T12:00:00+00:00
- Tool version: 0.1.0
- Context bytes: 64
- Execution mode: batch
- Assignment source: default

## Variant inventory

| Variant | File | Type | Active |
|---|---|---|---|
| v0 | v0\.s19 | s19 | yes |
| v1 | v1\.s19 | s19 | no |
| v2 | v2\.s19 | s19 | no |

## Consolidated overview

| Variant | Status | Changes applied | Checks passed | Checks failed | Checks uncheckable |
|---|---|---|---|---|---|
| v0 | ok | 66 | 0 | 0 | 0 |
| v1 | ok | 66 | 0 | 0 | 0 |
| v2 | ok | 66 | 0 | 0 | 0 |

## Legend

### A2L
- **Red** — schema/structural failure: malformed required field, invalid required reference, or hard-error duplicate symbol
- **Green** — memory checked — tag/range fully found in the loaded S19/HEX image
- **White** — valid A2L record with no hard inconsistency, including valid records not present in the image
- **Grey** — memory not checked yet, or no primary S19/HEX context loaded

### MAC
- **Red** — parse failed, invalid/missing name or hex address, or A2L↔MAC same-name address mismatch
- **Pale yellow** — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity
- **Green** — exact name + address match with A2L
- **White** — structurally valid MAC entry, no hard inconsistency, not positively cross-confirmed
- **Grey** — no A2L loaded, or validation context missing

### Issues
- **Errors** (Red) — parse/structure errors, empty name, invalid/missing address, duplicate symbol, broken GROUP/FUNCTION references, or A2L↔MAC same-name mismatch
- **Warnings** (Pale yellow) — address/range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias
- **Optional info** (Cyan) — valid-but-not-image-backed, not-checked-without-primary-image, or virtual/dependent non-memory-backed objects

### Hex
- **Yellow** — search / goto-focus highlight: the byte span matched by the last in-memory search or goto-address jump in the hex view
- **Orange3** — MAC address overlay: a hex byte at an address referenced by a loaded MAC record

## Variant: v0

### Modified files

- `chg_v0.json` (applied entries: 66)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00001000 | 1 | 01 | AA | standalone | - |
| 0x00001004 | 1 | 01 | AA | standalone | - |
| 0x00001008 | 1 | 01 | AA | standalone | - |
| 0x0000100C | 1 | 01 | AA | standalone | - |
| 0x00001010 | 1 | 01 | AA | standalone | - |
| 0x00001014 | 1 | 01 | AA | standalone | - |
| 0x00001018 | 1 | 01 | AA | standalone | - |
| 0x0000101C | 1 | 01 | AA | standalone | - |
| 0x00001020 | 1 | 01 | AA | standalone | - |
| 0x00001024 | 1 | 01 | AA | standalone | - |
| 0x00001028 | 1 | 01 | AA | standalone | - |
| 0x0000102C | 1 | 01 | AA | standalone | - |
| 0x00001030 | 1 | 01 | AA | standalone | - |
| 0x00001034 | 1 | 01 | AA | standalone | - |
| 0x00001038 | 1 | 01 | AA | standalone | - |
| 0x0000103C | 1 | 01 | AA | standalone | - |
| 0x00001040 | 1 | 01 | AA | standalone | - |
| 0x00001044 | 1 | 01 | AA | standalone | - |
| 0x00001048 | 1 | 01 | AA | standalone | - |
| 0x0000104C | 1 | 01 | AA | standalone | - |
| 0x00001050 | 1 | 01 | AA | standalone | - |
| 0x00001054 | 1 | 01 | AA | standalone | - |
| 0x00001058 | 1 | 01 | AA | standalone | - |
| 0x0000105C | 1 | 01 | AA | standalone | - |
| 0x00001060 | 1 | 01 | AA | standalone | - |
| 0x00001064 | 1 | 01 | AA | standalone | - |
| 0x00001068 | 1 | 01 | AA | standalone | - |
| 0x0000106C | 1 | 01 | AA | standalone | - |
| 0x00001070 | 1 | 01 | AA | standalone | - |
| 0x00001074 | 1 | 01 | AA | standalone | - |
| 0x00001078 | 1 | 01 | AA | standalone | - |
| 0x0000107C | 1 | 01 | AA | standalone | - |
| 0x00001080 | 1 | 01 | AA | standalone | - |
| 0x00001084 | 1 | 01 | AA | standalone | - |
| 0x00001088 | 1 | 01 | AA | standalone | - |
| 0x0000108C | 1 | 01 | AA | standalone | - |
| 0x00001090 | 1 | 01 | AA | standalone | - |
| 0x00001094 | 1 | 01 | AA | standalone | - |
| 0x00001098 | 1 | 01 | AA | standalone | - |
| 0x0000109C | 1 | 01 | AA | standalone | - |
| 0x000010A0 | 1 | 01 | AA | standalone | - |
| 0x000010A4 | 1 | 01 | AA | standalone | - |
| 0x000010A8 | 1 | 01 | AA | standalone | - |
| 0x000010AC | 1 | 01 | AA | standalone | - |
| 0x000010B0 | 1 | 01 | AA | standalone | - |
| 0x000010B4 | 1 | 01 | AA | standalone | - |
| 0x000010B8 | 1 | 01 | AA | standalone | - |
| 0x000010BC | 1 | 01 | AA | standalone | - |
| 0x000010C0 | 1 | 01 | AA | standalone | - |
| 0x000010C4 | 1 | 01 | AA | standalone | - |
| 0x000010C8 | 1 | 01 | AA | standalone | - |
| 0x000010CC | 1 | 01 | AA | standalone | - |
| 0x000010D0 | 1 | 01 | AA | standalone | - |
| 0x000010D4 | 1 | 01 | AA | standalone | - |
| 0x000010D8 | 1 | 01 | AA | standalone | - |
| 0x000010DC | 1 | 01 | AA | standalone | - |
| 0x000010E0 | 1 | 01 | AA | standalone | - |
| 0x000010E4 | 1 | 01 | AA | standalone | - |
| 0x000010E8 | 1 | 01 | AA | standalone | - |
| 0x000010EC | 1 | 01 | AA | standalone | - |
| 0x000010F0 | 1 | 01 | AA | standalone | - |
| 0x000010F4 | 1 | 01 | AA | standalone | - |
| 0x000010F8 | 1 | 01 | AA | standalone | - |
| 0x000010FC | 1 | 01 | AA | standalone | - |
| 0x00001100 | 1 | 01 | AA | standalone | - |
| 0x00001104 | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1001
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1005
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1009
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x100D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1011
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1015
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1019
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x101D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1021
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1025
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1029
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x102D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1031
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1035
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1039
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x103D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1041
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1045
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1049
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x104D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1051
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1055
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1059
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x105D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1061
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1065
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1069
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x106D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1071
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1075
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1079
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x107D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1081
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1085
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1089
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x108D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1091
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1095
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1099
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x109D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10AD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10BD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10CD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10DD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10ED
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10FD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1101
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1105
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1002
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1006
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1012
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1016
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x101A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x101E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1022
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1026
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x102A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x102E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1032
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1036
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x103A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x103E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1042
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1046
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x104A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x104E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1052
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1056
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x105A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x105E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1062
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1066
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x106A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x106E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1072
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1076
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x107A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x107E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1082
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1086
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x108A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x108E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1092
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1096
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x109A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x109E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10A2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10A6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10AA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10AE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10B2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10B6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10BA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10BE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10C2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10C6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10CA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10CE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10D2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10D6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10DA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10DE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10E2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10E6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10EA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10EE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10F2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10F6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10FA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10FE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1102
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1106

### Checklists

#### Checklist: `chk_v0.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Variant: v1

### Modified files

- `chg_v1.json` (applied entries: 66)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00001000 | 1 | 01 | AA | standalone | - |
| 0x00001004 | 1 | 01 | AA | standalone | - |
| 0x00001008 | 1 | 01 | AA | standalone | - |
| 0x0000100C | 1 | 01 | AA | standalone | - |
| 0x00001010 | 1 | 01 | AA | standalone | - |
| 0x00001014 | 1 | 01 | AA | standalone | - |
| 0x00001018 | 1 | 01 | AA | standalone | - |
| 0x0000101C | 1 | 01 | AA | standalone | - |
| 0x00001020 | 1 | 01 | AA | standalone | - |
| 0x00001024 | 1 | 01 | AA | standalone | - |
| 0x00001028 | 1 | 01 | AA | standalone | - |
| 0x0000102C | 1 | 01 | AA | standalone | - |
| 0x00001030 | 1 | 01 | AA | standalone | - |
| 0x00001034 | 1 | 01 | AA | standalone | - |
| 0x00001038 | 1 | 01 | AA | standalone | - |
| 0x0000103C | 1 | 01 | AA | standalone | - |
| 0x00001040 | 1 | 01 | AA | standalone | - |
| 0x00001044 | 1 | 01 | AA | standalone | - |
| 0x00001048 | 1 | 01 | AA | standalone | - |
| 0x0000104C | 1 | 01 | AA | standalone | - |
| 0x00001050 | 1 | 01 | AA | standalone | - |
| 0x00001054 | 1 | 01 | AA | standalone | - |
| 0x00001058 | 1 | 01 | AA | standalone | - |
| 0x0000105C | 1 | 01 | AA | standalone | - |
| 0x00001060 | 1 | 01 | AA | standalone | - |
| 0x00001064 | 1 | 01 | AA | standalone | - |
| 0x00001068 | 1 | 01 | AA | standalone | - |
| 0x0000106C | 1 | 01 | AA | standalone | - |
| 0x00001070 | 1 | 01 | AA | standalone | - |
| 0x00001074 | 1 | 01 | AA | standalone | - |
| 0x00001078 | 1 | 01 | AA | standalone | - |
| 0x0000107C | 1 | 01 | AA | standalone | - |
| 0x00001080 | 1 | 01 | AA | standalone | - |
| 0x00001084 | 1 | 01 | AA | standalone | - |
| 0x00001088 | 1 | 01 | AA | standalone | - |
| 0x0000108C | 1 | 01 | AA | standalone | - |
| 0x00001090 | 1 | 01 | AA | standalone | - |
| 0x00001094 | 1 | 01 | AA | standalone | - |
| 0x00001098 | 1 | 01 | AA | standalone | - |
| 0x0000109C | 1 | 01 | AA | standalone | - |
| 0x000010A0 | 1 | 01 | AA | standalone | - |
| 0x000010A4 | 1 | 01 | AA | standalone | - |
| 0x000010A8 | 1 | 01 | AA | standalone | - |
| 0x000010AC | 1 | 01 | AA | standalone | - |
| 0x000010B0 | 1 | 01 | AA | standalone | - |
| 0x000010B4 | 1 | 01 | AA | standalone | - |
| 0x000010B8 | 1 | 01 | AA | standalone | - |
| 0x000010BC | 1 | 01 | AA | standalone | - |
| 0x000010C0 | 1 | 01 | AA | standalone | - |
| 0x000010C4 | 1 | 01 | AA | standalone | - |
| 0x000010C8 | 1 | 01 | AA | standalone | - |
| 0x000010CC | 1 | 01 | AA | standalone | - |
| 0x000010D0 | 1 | 01 | AA | standalone | - |
| 0x000010D4 | 1 | 01 | AA | standalone | - |
| 0x000010D8 | 1 | 01 | AA | standalone | - |
| 0x000010DC | 1 | 01 | AA | standalone | - |
| 0x000010E0 | 1 | 01 | AA | standalone | - |
| 0x000010E4 | 1 | 01 | AA | standalone | - |
| 0x000010E8 | 1 | 01 | AA | standalone | - |
| 0x000010EC | 1 | 01 | AA | standalone | - |
| 0x000010F0 | 1 | 01 | AA | standalone | - |
| 0x000010F4 | 1 | 01 | AA | standalone | - |
| 0x000010F8 | 1 | 01 | AA | standalone | - |
| 0x000010FC | 1 | 01 | AA | standalone | - |
| 0x00001100 | 1 | 01 | AA | standalone | - |
| 0x00001104 | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1001
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1005
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1009
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x100D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1011
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1015
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1019
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x101D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1021
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1025
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1029
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x102D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1031
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1035
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1039
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x103D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1041
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1045
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1049
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x104D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1051
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1055
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1059
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x105D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1061
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1065
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1069
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x106D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1071
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1075
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1079
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x107D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1081
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1085
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1089
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x108D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1091
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1095
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1099
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x109D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10AD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10BD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10CD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10DD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10ED
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10FD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1101
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1105
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1002
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1006
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1012
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1016
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x101A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x101E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1022
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1026
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x102A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x102E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1032
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1036
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x103A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x103E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1042
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1046
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x104A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x104E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1052
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1056
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x105A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x105E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1062
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1066
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x106A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x106E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1072
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1076
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x107A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x107E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1082
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1086
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x108A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x108E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1092
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1096
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x109A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x109E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10A2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10A6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10AA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10AE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10B2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10B6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10BA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10BE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10C2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10C6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10CA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10CE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10D2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10D6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10DA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10DE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10E2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10E6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10EA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10EE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10F2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10F6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10FA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10FE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1102
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1106

### Checklists

#### Checklist: `chk_v1.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Variant: v2

### Modified files

- `chg_v2.json` (applied entries: 66)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00001000 | 1 | 01 | AA | standalone | - |
| 0x00001004 | 1 | 01 | AA | standalone | - |
| 0x00001008 | 1 | 01 | AA | standalone | - |
| 0x0000100C | 1 | 01 | AA | standalone | - |
| 0x00001010 | 1 | 01 | AA | standalone | - |
| 0x00001014 | 1 | 01 | AA | standalone | - |
| 0x00001018 | 1 | 01 | AA | standalone | - |
| 0x0000101C | 1 | 01 | AA | standalone | - |
| 0x00001020 | 1 | 01 | AA | standalone | - |
| 0x00001024 | 1 | 01 | AA | standalone | - |
| 0x00001028 | 1 | 01 | AA | standalone | - |
| 0x0000102C | 1 | 01 | AA | standalone | - |
| 0x00001030 | 1 | 01 | AA | standalone | - |
| 0x00001034 | 1 | 01 | AA | standalone | - |
| 0x00001038 | 1 | 01 | AA | standalone | - |
| 0x0000103C | 1 | 01 | AA | standalone | - |
| 0x00001040 | 1 | 01 | AA | standalone | - |
| 0x00001044 | 1 | 01 | AA | standalone | - |
| 0x00001048 | 1 | 01 | AA | standalone | - |
| 0x0000104C | 1 | 01 | AA | standalone | - |
| 0x00001050 | 1 | 01 | AA | standalone | - |
| 0x00001054 | 1 | 01 | AA | standalone | - |
| 0x00001058 | 1 | 01 | AA | standalone | - |
| 0x0000105C | 1 | 01 | AA | standalone | - |
| 0x00001060 | 1 | 01 | AA | standalone | - |
| 0x00001064 | 1 | 01 | AA | standalone | - |
| 0x00001068 | 1 | 01 | AA | standalone | - |
| 0x0000106C | 1 | 01 | AA | standalone | - |
| 0x00001070 | 1 | 01 | AA | standalone | - |
| 0x00001074 | 1 | 01 | AA | standalone | - |
| 0x00001078 | 1 | 01 | AA | standalone | - |
| 0x0000107C | 1 | 01 | AA | standalone | - |
| 0x00001080 | 1 | 01 | AA | standalone | - |
| 0x00001084 | 1 | 01 | AA | standalone | - |
| 0x00001088 | 1 | 01 | AA | standalone | - |
| 0x0000108C | 1 | 01 | AA | standalone | - |
| 0x00001090 | 1 | 01 | AA | standalone | - |
| 0x00001094 | 1 | 01 | AA | standalone | - |
| 0x00001098 | 1 | 01 | AA | standalone | - |
| 0x0000109C | 1 | 01 | AA | standalone | - |
| 0x000010A0 | 1 | 01 | AA | standalone | - |
| 0x000010A4 | 1 | 01 | AA | standalone | - |
| 0x000010A8 | 1 | 01 | AA | standalone | - |
| 0x000010AC | 1 | 01 | AA | standalone | - |
| 0x000010B0 | 1 | 01 | AA | standalone | - |
| 0x000010B4 | 1 | 01 | AA | standalone | - |
| 0x000010B8 | 1 | 01 | AA | standalone | - |
| 0x000010BC | 1 | 01 | AA | standalone | - |
| 0x000010C0 | 1 | 01 | AA | standalone | - |
| 0x000010C4 | 1 | 01 | AA | standalone | - |
| 0x000010C8 | 1 | 01 | AA | standalone | - |
| 0x000010CC | 1 | 01 | AA | standalone | - |
| 0x000010D0 | 1 | 01 | AA | standalone | - |
| 0x000010D4 | 1 | 01 | AA | standalone | - |
| 0x000010D8 | 1 | 01 | AA | standalone | - |
| 0x000010DC | 1 | 01 | AA | standalone | - |
| 0x000010E0 | 1 | 01 | AA | standalone | - |
| 0x000010E4 | 1 | 01 | AA | standalone | - |
| 0x000010E8 | 1 | 01 | AA | standalone | - |
| 0x000010EC | 1 | 01 | AA | standalone | - |
| 0x000010F0 | 1 | 01 | AA | standalone | - |
| 0x000010F4 | 1 | 01 | AA | standalone | - |
| 0x000010F8 | 1 | 01 | AA | standalone | - |
| 0x000010FC | 1 | 01 | AA | standalone | - |
| 0x00001100 | 1 | 01 | AA | standalone | - |
| 0x00001104 | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1001
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1005
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1009
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x100D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1011
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1015
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1019
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x101D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1021
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1025
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1029
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x102D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1031
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1035
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1039
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x103D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1041
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1045
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1049
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x104D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1051
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1055
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1059
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x105D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1061
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1065
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1069
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x106D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1071
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1075
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1079
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x107D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1081
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1085
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1089
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x108D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1091
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1095
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1099
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x109D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10AD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10BD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10CD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10DD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10ED
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10FD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1101
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1105
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1002
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1006
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x100E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1012
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1016
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x101A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x101E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1022
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1026
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x102A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x102E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1032
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1036
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x103A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x103E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1042
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1046
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x104A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x104E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1052
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1056
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x105A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x105E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1062
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1066
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x106A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x106E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1072
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1076
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x107A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x107E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1082
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1086
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x108A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x108E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1092
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1096
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x109A
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x109E
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10A2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10A6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10AA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10AE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10B2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10B6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10BA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10BE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10C2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10C6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10CA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10CE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10D2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10D6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10DA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10DE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10E2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10E6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10EA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10EE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10F2
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10F6
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10FA
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x10FE
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1102
- [CHK-MISMATCH] error: CHK-MISMATCH synthetic message @ 0x1106

### Checklists

#### Checklist: `chk_v2.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Addendum: declared regions

### zone 0 (0x1000-0x2000)
- modification @ 0x1000 (variant v0)
- modification @ 0x1004 (variant v0)
- modification @ 0x1008 (variant v0)
- modification @ 0x100C (variant v0)
- modification @ 0x1010 (variant v0)
- modification @ 0x1014 (variant v0)
- modification @ 0x1018 (variant v0)
- modification @ 0x101C (variant v0)
- modification @ 0x1020 (variant v0)
- modification @ 0x1024 (variant v0)
- modification @ 0x1028 (variant v0)
- modification @ 0x102C (variant v0)
- modification @ 0x1030 (variant v0)
- modification @ 0x1034 (variant v0)
- modification @ 0x1038 (variant v0)
- modification @ 0x103C (variant v0)
- modification @ 0x1040 (variant v0)
- modification @ 0x1044 (variant v0)
- modification @ 0x1048 (variant v0)
- modification @ 0x104C (variant v0)
- modification @ 0x1050 (variant v0)
- modification @ 0x1054 (variant v0)
- modification @ 0x1058 (variant v0)
- modification @ 0x105C (variant v0)
- modification @ 0x1060 (variant v0)
- modification @ 0x1064 (variant v0)
- modification @ 0x1068 (variant v0)
- modification @ 0x106C (variant v0)
- modification @ 0x1070 (variant v0)
- modification @ 0x1074 (variant v0)
- modification @ 0x1078 (variant v0)
- modification @ 0x107C (variant v0)
- modification @ 0x1080 (variant v0)
- modification @ 0x1084 (variant v0)
- modification @ 0x1088 (variant v0)
- modification @ 0x108C (variant v0)
- modification @ 0x1090 (variant v0)
- modification @ 0x1094 (variant v0)
- modification @ 0x1098 (variant v0)
- modification @ 0x109C (variant v0)
- modification @ 0x10A0 (variant v0)
- modification @ 0x10A4 (variant v0)
- modification @ 0x10A8 (variant v0)
- modification @ 0x10AC (variant v0)
- modification @ 0x10B0 (variant v0)
- modification @ 0x10B4 (variant v0)
- modification @ 0x10B8 (variant v0)
- modification @ 0x10BC (variant v0)
- modification @ 0x10C0 (variant v0)
- modification @ 0x10C4 (variant v0)
- modification @ 0x10C8 (variant v0)
- modification @ 0x10CC (variant v0)
- modification @ 0x10D0 (variant v0)
- modification @ 0x10D4 (variant v0)
- modification @ 0x10D8 (variant v0)
- modification @ 0x10DC (variant v0)
- modification @ 0x10E0 (variant v0)
- modification @ 0x10E4 (variant v0)
- modification @ 0x10E8 (variant v0)
- modification @ 0x10EC (variant v0)
- modification @ 0x10F0 (variant v0)
- modification @ 0x10F4 (variant v0)
- modification @ 0x10F8 (variant v0)
- modification @ 0x10FC (variant v0)
- modification @ 0x1100 (variant v0)
- modification @ 0x1104 (variant v0)
- issue [CHG-SYNTAX] @ 0x1001 (variant v0)
- issue [CHG-SYNTAX] @ 0x1005 (variant v0)
- issue [CHG-SYNTAX] @ 0x1009 (variant v0)
- issue [CHG-SYNTAX] @ 0x100D (variant v0)
- issue [CHG-SYNTAX] @ 0x1011 (variant v0)
- issue [CHG-SYNTAX] @ 0x1015 (variant v0)
- issue [CHG-SYNTAX] @ 0x1019 (variant v0)
- issue [CHG-SYNTAX] @ 0x101D (variant v0)
- issue [CHG-SYNTAX] @ 0x1021 (variant v0)
- issue [CHG-SYNTAX] @ 0x1025 (variant v0)
- issue [CHG-SYNTAX] @ 0x1029 (variant v0)
- issue [CHG-SYNTAX] @ 0x102D (variant v0)
- issue [CHG-SYNTAX] @ 0x1031 (variant v0)
- issue [CHG-SYNTAX] @ 0x1035 (variant v0)
- issue [CHG-SYNTAX] @ 0x1039 (variant v0)
- issue [CHG-SYNTAX] @ 0x103D (variant v0)
- issue [CHG-SYNTAX] @ 0x1041 (variant v0)
- issue [CHG-SYNTAX] @ 0x1045 (variant v0)
- issue [CHG-SYNTAX] @ 0x1049 (variant v0)
- issue [CHG-SYNTAX] @ 0x104D (variant v0)
- issue [CHG-SYNTAX] @ 0x1051 (variant v0)
- issue [CHG-SYNTAX] @ 0x1055 (variant v0)
- issue [CHG-SYNTAX] @ 0x1059 (variant v0)
- issue [CHG-SYNTAX] @ 0x105D (variant v0)
- issue [CHG-SYNTAX] @ 0x1061 (variant v0)
- issue [CHG-SYNTAX] @ 0x1065 (variant v0)
- issue [CHG-SYNTAX] @ 0x1069 (variant v0)
- issue [CHG-SYNTAX] @ 0x106D (variant v0)
- issue [CHG-SYNTAX] @ 0x1071 (variant v0)
- issue [CHG-SYNTAX] @ 0x1075 (variant v0)
- issue [CHG-SYNTAX] @ 0x1079 (variant v0)
- issue [CHG-SYNTAX] @ 0x107D (variant v0)
- issue [CHG-SYNTAX] @ 0x1081 (variant v0)
- issue [CHG-SYNTAX] @ 0x1085 (variant v0)
- issue [CHG-SYNTAX] @ 0x1089 (variant v0)
- issue [CHG-SYNTAX] @ 0x108D (variant v0)
- issue [CHG-SYNTAX] @ 0x1091 (variant v0)
- issue [CHG-SYNTAX] @ 0x1095 (variant v0)
- issue [CHG-SYNTAX] @ 0x1099 (variant v0)
- issue [CHG-SYNTAX] @ 0x109D (variant v0)
- issue [CHG-SYNTAX] @ 0x10A1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10A5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10A9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10AD (variant v0)
- issue [CHG-SYNTAX] @ 0x10B1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10B5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10B9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10BD (variant v0)
- issue [CHG-SYNTAX] @ 0x10C1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10C5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10C9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10CD (variant v0)
- issue [CHG-SYNTAX] @ 0x10D1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10D5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10D9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10DD (variant v0)
- issue [CHG-SYNTAX] @ 0x10E1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10E5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10E9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10ED (variant v0)
- issue [CHG-SYNTAX] @ 0x10F1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10F5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10F9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10FD (variant v0)
- issue [CHG-SYNTAX] @ 0x1101 (variant v0)
- issue [CHG-SYNTAX] @ 0x1105 (variant v0)
- issue [CHK-MISMATCH] @ 0x1002 (variant v0)
- issue [CHK-MISMATCH] @ 0x1006 (variant v0)
- issue [CHK-MISMATCH] @ 0x100A (variant v0)
- issue [CHK-MISMATCH] @ 0x100E (variant v0)
- issue [CHK-MISMATCH] @ 0x1012 (variant v0)
- issue [CHK-MISMATCH] @ 0x1016 (variant v0)
- issue [CHK-MISMATCH] @ 0x101A (variant v0)
- issue [CHK-MISMATCH] @ 0x101E (variant v0)
- issue [CHK-MISMATCH] @ 0x1022 (variant v0)
- issue [CHK-MISMATCH] @ 0x1026 (variant v0)
- issue [CHK-MISMATCH] @ 0x102A (variant v0)
- issue [CHK-MISMATCH] @ 0x102E (variant v0)
- issue [CHK-MISMATCH] @ 0x1032 (variant v0)
- issue [CHK-MISMATCH] @ 0x1036 (variant v0)
- issue [CHK-MISMATCH] @ 0x103A (variant v0)
- issue [CHK-MISMATCH] @ 0x103E (variant v0)
- issue [CHK-MISMATCH] @ 0x1042 (variant v0)
- issue [CHK-MISMATCH] @ 0x1046 (variant v0)
- issue [CHK-MISMATCH] @ 0x104A (variant v0)
- issue [CHK-MISMATCH] @ 0x104E (variant v0)
- issue [CHK-MISMATCH] @ 0x1052 (variant v0)
- issue [CHK-MISMATCH] @ 0x1056 (variant v0)
- issue [CHK-MISMATCH] @ 0x105A (variant v0)
- issue [CHK-MISMATCH] @ 0x105E (variant v0)
- issue [CHK-MISMATCH] @ 0x1062 (variant v0)
- issue [CHK-MISMATCH] @ 0x1066 (variant v0)
- issue [CHK-MISMATCH] @ 0x106A (variant v0)
- issue [CHK-MISMATCH] @ 0x106E (variant v0)
- issue [CHK-MISMATCH] @ 0x1072 (variant v0)
- issue [CHK-MISMATCH] @ 0x1076 (variant v0)
- issue [CHK-MISMATCH] @ 0x107A (variant v0)
- issue [CHK-MISMATCH] @ 0x107E (variant v0)
- issue [CHK-MISMATCH] @ 0x1082 (variant v0)
- issue [CHK-MISMATCH] @ 0x1086 (variant v0)
- issue [CHK-MISMATCH] @ 0x108A (variant v0)
- issue [CHK-MISMATCH] @ 0x108E (variant v0)
- issue [CHK-MISMATCH] @ 0x1092 (variant v0)
- issue [CHK-MISMATCH] @ 0x1096 (variant v0)
- issue [CHK-MISMATCH] @ 0x109A (variant v0)
- issue [CHK-MISMATCH] @ 0x109E (variant v0)
- issue [CHK-MISMATCH] @ 0x10A2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10A6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10AA (variant v0)
- issue [CHK-MISMATCH] @ 0x10AE (variant v0)
- issue [CHK-MISMATCH] @ 0x10B2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10B6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10BA (variant v0)
- issue [CHK-MISMATCH] @ 0x10BE (variant v0)
- issue [CHK-MISMATCH] @ 0x10C2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10C6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10CA (variant v0)
- issue [CHK-MISMATCH] @ 0x10CE (variant v0)
- issue [CHK-MISMATCH] @ 0x10D2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10D6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10DA (variant v0)
- issue [CHK-MISMATCH] @ 0x10DE (variant v0)
- issue [CHK-MISMATCH] @ 0x10E2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10E6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10EA (variant v0)
- issue [CHK-MISMATCH] @ 0x10EE (variant v0)
- issue [CHK-MISMATCH] @ 0x10F2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10F6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10FA (variant v0)
- issue [CHK-MISMATCH] @ 0x10FE (variant v0)
- issue [CHK-MISMATCH] @ 0x1102 (variant v0)
- issue [CHK-MISMATCH] @ 0x1106 (variant v0)
- modification @ 0x1000 (variant v1)
- modification @ 0x1004 (variant v1)
- modification @ 0x1008 (variant v1)
- modification @ 0x100C (variant v1)
- modification @ 0x1010 (variant v1)
- modification @ 0x1014 (variant v1)
- modification @ 0x1018 (variant v1)
- modification @ 0x101C (variant v1)
- modification @ 0x1020 (variant v1)
- modification @ 0x1024 (variant v1)
- modification @ 0x1028 (variant v1)
- modification @ 0x102C (variant v1)
- modification @ 0x1030 (variant v1)
- modification @ 0x1034 (variant v1)
- modification @ 0x1038 (variant v1)
- modification @ 0x103C (variant v1)
- modification @ 0x1040 (variant v1)
- modification @ 0x1044 (variant v1)
- modification @ 0x1048 (variant v1)
- modification @ 0x104C (variant v1)
- modification @ 0x1050 (variant v1)
- modification @ 0x1054 (variant v1)
- modification @ 0x1058 (variant v1)
- modification @ 0x105C (variant v1)
- modification @ 0x1060 (variant v1)
- modification @ 0x1064 (variant v1)
- modification @ 0x1068 (variant v1)
- modification @ 0x106C (variant v1)
- modification @ 0x1070 (variant v1)
- modification @ 0x1074 (variant v1)
- modification @ 0x1078 (variant v1)
- modification @ 0x107C (variant v1)
- modification @ 0x1080 (variant v1)
- modification @ 0x1084 (variant v1)
- modification @ 0x1088 (variant v1)
- modification @ 0x108C (variant v1)
- modification @ 0x1090 (variant v1)
- modification @ 0x1094 (variant v1)
- modification @ 0x1098 (variant v1)
- modification @ 0x109C (variant v1)
- modification @ 0x10A0 (variant v1)
- modification @ 0x10A4 (variant v1)
- modification @ 0x10A8 (variant v1)
- modification @ 0x10AC (variant v1)
- modification @ 0x10B0 (variant v1)
- modification @ 0x10B4 (variant v1)
- modification @ 0x10B8 (variant v1)
- modification @ 0x10BC (variant v1)
- modification @ 0x10C0 (variant v1)
- modification @ 0x10C4 (variant v1)
- modification @ 0x10C8 (variant v1)
- modification @ 0x10CC (variant v1)
- modification @ 0x10D0 (variant v1)
- modification @ 0x10D4 (variant v1)
- modification @ 0x10D8 (variant v1)
- modification @ 0x10DC (variant v1)
- modification @ 0x10E0 (variant v1)
- modification @ 0x10E4 (variant v1)
- modification @ 0x10E8 (variant v1)
- modification @ 0x10EC (variant v1)
- modification @ 0x10F0 (variant v1)
- modification @ 0x10F4 (variant v1)
- modification @ 0x10F8 (variant v1)
- modification @ 0x10FC (variant v1)
- modification @ 0x1100 (variant v1)
- modification @ 0x1104 (variant v1)
- issue [CHG-SYNTAX] @ 0x1001 (variant v1)
- issue [CHG-SYNTAX] @ 0x1005 (variant v1)
- issue [CHG-SYNTAX] @ 0x1009 (variant v1)
- issue [CHG-SYNTAX] @ 0x100D (variant v1)
- issue [CHG-SYNTAX] @ 0x1011 (variant v1)
- issue [CHG-SYNTAX] @ 0x1015 (variant v1)
- issue [CHG-SYNTAX] @ 0x1019 (variant v1)
- issue [CHG-SYNTAX] @ 0x101D (variant v1)
- issue [CHG-SYNTAX] @ 0x1021 (variant v1)
- issue [CHG-SYNTAX] @ 0x1025 (variant v1)
- issue [CHG-SYNTAX] @ 0x1029 (variant v1)
- issue [CHG-SYNTAX] @ 0x102D (variant v1)
- issue [CHG-SYNTAX] @ 0x1031 (variant v1)
- issue [CHG-SYNTAX] @ 0x1035 (variant v1)
- issue [CHG-SYNTAX] @ 0x1039 (variant v1)
- issue [CHG-SYNTAX] @ 0x103D (variant v1)
- issue [CHG-SYNTAX] @ 0x1041 (variant v1)
- issue [CHG-SYNTAX] @ 0x1045 (variant v1)
- issue [CHG-SYNTAX] @ 0x1049 (variant v1)
- issue [CHG-SYNTAX] @ 0x104D (variant v1)
- issue [CHG-SYNTAX] @ 0x1051 (variant v1)
- issue [CHG-SYNTAX] @ 0x1055 (variant v1)
- issue [CHG-SYNTAX] @ 0x1059 (variant v1)
- issue [CHG-SYNTAX] @ 0x105D (variant v1)
- issue [CHG-SYNTAX] @ 0x1061 (variant v1)
- issue [CHG-SYNTAX] @ 0x1065 (variant v1)
- issue [CHG-SYNTAX] @ 0x1069 (variant v1)
- issue [CHG-SYNTAX] @ 0x106D (variant v1)
- issue [CHG-SYNTAX] @ 0x1071 (variant v1)
- issue [CHG-SYNTAX] @ 0x1075 (variant v1)
- issue [CHG-SYNTAX] @ 0x1079 (variant v1)
- issue [CHG-SYNTAX] @ 0x107D (variant v1)
- issue [CHG-SYNTAX] @ 0x1081 (variant v1)
- issue [CHG-SYNTAX] @ 0x1085 (variant v1)
- issue [CHG-SYNTAX] @ 0x1089 (variant v1)
- issue [CHG-SYNTAX] @ 0x108D (variant v1)
- issue [CHG-SYNTAX] @ 0x1091 (variant v1)
- issue [CHG-SYNTAX] @ 0x1095 (variant v1)
- issue [CHG-SYNTAX] @ 0x1099 (variant v1)
- issue [CHG-SYNTAX] @ 0x109D (variant v1)
- issue [CHG-SYNTAX] @ 0x10A1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10A5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10A9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10AD (variant v1)
- issue [CHG-SYNTAX] @ 0x10B1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10B5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10B9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10BD (variant v1)
- issue [CHG-SYNTAX] @ 0x10C1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10C5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10C9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10CD (variant v1)
- issue [CHG-SYNTAX] @ 0x10D1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10D5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10D9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10DD (variant v1)
- issue [CHG-SYNTAX] @ 0x10E1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10E5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10E9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10ED (variant v1)
- issue [CHG-SYNTAX] @ 0x10F1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10F5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10F9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10FD (variant v1)
- issue [CHG-SYNTAX] @ 0x1101 (variant v1)
- issue [CHG-SYNTAX] @ 0x1105 (variant v1)
- issue [CHK-MISMATCH] @ 0x1002 (variant v1)
- issue [CHK-MISMATCH] @ 0x1006 (variant v1)
- issue [CHK-MISMATCH] @ 0x100A (variant v1)
- issue [CHK-MISMATCH] @ 0x100E (variant v1)
- issue [CHK-MISMATCH] @ 0x1012 (variant v1)
- issue [CHK-MISMATCH] @ 0x1016 (variant v1)
- issue [CHK-MISMATCH] @ 0x101A (variant v1)
- issue [CHK-MISMATCH] @ 0x101E (variant v1)
- issue [CHK-MISMATCH] @ 0x1022 (variant v1)
- issue [CHK-MISMATCH] @ 0x1026 (variant v1)
- issue [CHK-MISMATCH] @ 0x102A (variant v1)
- issue [CHK-MISMATCH] @ 0x102E (variant v1)
- issue [CHK-MISMATCH] @ 0x1032 (variant v1)
- issue [CHK-MISMATCH] @ 0x1036 (variant v1)
- issue [CHK-MISMATCH] @ 0x103A (variant v1)
- issue [CHK-MISMATCH] @ 0x103E (variant v1)
- issue [CHK-MISMATCH] @ 0x1042 (variant v1)
- issue [CHK-MISMATCH] @ 0x1046 (variant v1)
- issue [CHK-MISMATCH] @ 0x104A (variant v1)
- issue [CHK-MISMATCH] @ 0x104E (variant v1)
- issue [CHK-MISMATCH] @ 0x1052 (variant v1)
- issue [CHK-MISMATCH] @ 0x1056 (variant v1)
- issue [CHK-MISMATCH] @ 0x105A (variant v1)
- issue [CHK-MISMATCH] @ 0x105E (variant v1)
- issue [CHK-MISMATCH] @ 0x1062 (variant v1)
- issue [CHK-MISMATCH] @ 0x1066 (variant v1)
- issue [CHK-MISMATCH] @ 0x106A (variant v1)
- issue [CHK-MISMATCH] @ 0x106E (variant v1)
- issue [CHK-MISMATCH] @ 0x1072 (variant v1)
- issue [CHK-MISMATCH] @ 0x1076 (variant v1)
- issue [CHK-MISMATCH] @ 0x107A (variant v1)
- issue [CHK-MISMATCH] @ 0x107E (variant v1)
- issue [CHK-MISMATCH] @ 0x1082 (variant v1)
- issue [CHK-MISMATCH] @ 0x1086 (variant v1)
- issue [CHK-MISMATCH] @ 0x108A (variant v1)
- issue [CHK-MISMATCH] @ 0x108E (variant v1)
- issue [CHK-MISMATCH] @ 0x1092 (variant v1)
- issue [CHK-MISMATCH] @ 0x1096 (variant v1)
- issue [CHK-MISMATCH] @ 0x109A (variant v1)
- issue [CHK-MISMATCH] @ 0x109E (variant v1)
- issue [CHK-MISMATCH] @ 0x10A2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10A6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10AA (variant v1)
- issue [CHK-MISMATCH] @ 0x10AE (variant v1)
- issue [CHK-MISMATCH] @ 0x10B2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10B6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10BA (variant v1)
- issue [CHK-MISMATCH] @ 0x10BE (variant v1)
- issue [CHK-MISMATCH] @ 0x10C2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10C6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10CA (variant v1)
- issue [CHK-MISMATCH] @ 0x10CE (variant v1)
- issue [CHK-MISMATCH] @ 0x10D2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10D6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10DA (variant v1)
- issue [CHK-MISMATCH] @ 0x10DE (variant v1)
- issue [CHK-MISMATCH] @ 0x10E2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10E6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10EA (variant v1)
- issue [CHK-MISMATCH] @ 0x10EE (variant v1)
- issue [CHK-MISMATCH] @ 0x10F2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10F6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10FA (variant v1)
- issue [CHK-MISMATCH] @ 0x10FE (variant v1)
- issue [CHK-MISMATCH] @ 0x1102 (variant v1)
- issue [CHK-MISMATCH] @ 0x1106 (variant v1)
- modification @ 0x1000 (variant v2)
- modification @ 0x1004 (variant v2)
- modification @ 0x1008 (variant v2)
- modification @ 0x100C (variant v2)
- modification @ 0x1010 (variant v2)
- modification @ 0x1014 (variant v2)
- modification @ 0x1018 (variant v2)
- modification @ 0x101C (variant v2)
- modification @ 0x1020 (variant v2)
- modification @ 0x1024 (variant v2)
- modification @ 0x1028 (variant v2)
- modification @ 0x102C (variant v2)
- modification @ 0x1030 (variant v2)
- modification @ 0x1034 (variant v2)
- modification @ 0x1038 (variant v2)
- modification @ 0x103C (variant v2)
- modification @ 0x1040 (variant v2)
- modification @ 0x1044 (variant v2)
- modification @ 0x1048 (variant v2)
- modification @ 0x104C (variant v2)
- modification @ 0x1050 (variant v2)
- modification @ 0x1054 (variant v2)
- modification @ 0x1058 (variant v2)
- modification @ 0x105C (variant v2)
- modification @ 0x1060 (variant v2)
- modification @ 0x1064 (variant v2)
- modification @ 0x1068 (variant v2)
- modification @ 0x106C (variant v2)
- modification @ 0x1070 (variant v2)
- modification @ 0x1074 (variant v2)
- modification @ 0x1078 (variant v2)
- modification @ 0x107C (variant v2)
- modification @ 0x1080 (variant v2)
- modification @ 0x1084 (variant v2)
- modification @ 0x1088 (variant v2)
- modification @ 0x108C (variant v2)
- modification @ 0x1090 (variant v2)
- modification @ 0x1094 (variant v2)
- modification @ 0x1098 (variant v2)
- modification @ 0x109C (variant v2)
- modification @ 0x10A0 (variant v2)
- modification @ 0x10A4 (variant v2)
- modification @ 0x10A8 (variant v2)
- modification @ 0x10AC (variant v2)
- modification @ 0x10B0 (variant v2)
- modification @ 0x10B4 (variant v2)
- modification @ 0x10B8 (variant v2)
- modification @ 0x10BC (variant v2)
- modification @ 0x10C0 (variant v2)
- modification @ 0x10C4 (variant v2)
- modification @ 0x10C8 (variant v2)
- modification @ 0x10CC (variant v2)
- modification @ 0x10D0 (variant v2)
- modification @ 0x10D4 (variant v2)
- modification @ 0x10D8 (variant v2)
- modification @ 0x10DC (variant v2)
- modification @ 0x10E0 (variant v2)
- modification @ 0x10E4 (variant v2)
- modification @ 0x10E8 (variant v2)
- modification @ 0x10EC (variant v2)
- modification @ 0x10F0 (variant v2)
- modification @ 0x10F4 (variant v2)
- modification @ 0x10F8 (variant v2)
- modification @ 0x10FC (variant v2)
- modification @ 0x1100 (variant v2)
- modification @ 0x1104 (variant v2)
- issue [CHG-SYNTAX] @ 0x1001 (variant v2)
- issue [CHG-SYNTAX] @ 0x1005 (variant v2)
- issue [CHG-SYNTAX] @ 0x1009 (variant v2)
- issue [CHG-SYNTAX] @ 0x100D (variant v2)
- issue [CHG-SYNTAX] @ 0x1011 (variant v2)
- issue [CHG-SYNTAX] @ 0x1015 (variant v2)
- issue [CHG-SYNTAX] @ 0x1019 (variant v2)
- issue [CHG-SYNTAX] @ 0x101D (variant v2)
- issue [CHG-SYNTAX] @ 0x1021 (variant v2)
- issue [CHG-SYNTAX] @ 0x1025 (variant v2)
- issue [CHG-SYNTAX] @ 0x1029 (variant v2)
- issue [CHG-SYNTAX] @ 0x102D (variant v2)
- issue [CHG-SYNTAX] @ 0x1031 (variant v2)
- issue [CHG-SYNTAX] @ 0x1035 (variant v2)
- issue [CHG-SYNTAX] @ 0x1039 (variant v2)
- issue [CHG-SYNTAX] @ 0x103D (variant v2)
- issue [CHG-SYNTAX] @ 0x1041 (variant v2)
- issue [CHG-SYNTAX] @ 0x1045 (variant v2)
- issue [CHG-SYNTAX] @ 0x1049 (variant v2)
- issue [CHG-SYNTAX] @ 0x104D (variant v2)
- issue [CHG-SYNTAX] @ 0x1051 (variant v2)
- issue [CHG-SYNTAX] @ 0x1055 (variant v2)
- issue [CHG-SYNTAX] @ 0x1059 (variant v2)
- issue [CHG-SYNTAX] @ 0x105D (variant v2)
- issue [CHG-SYNTAX] @ 0x1061 (variant v2)
- issue [CHG-SYNTAX] @ 0x1065 (variant v2)
- issue [CHG-SYNTAX] @ 0x1069 (variant v2)
- issue [CHG-SYNTAX] @ 0x106D (variant v2)
- issue [CHG-SYNTAX] @ 0x1071 (variant v2)
- issue [CHG-SYNTAX] @ 0x1075 (variant v2)
- issue [CHG-SYNTAX] @ 0x1079 (variant v2)
- issue [CHG-SYNTAX] @ 0x107D (variant v2)
- issue [CHG-SYNTAX] @ 0x1081 (variant v2)
- issue [CHG-SYNTAX] @ 0x1085 (variant v2)
- issue [CHG-SYNTAX] @ 0x1089 (variant v2)
- issue [CHG-SYNTAX] @ 0x108D (variant v2)
- issue [CHG-SYNTAX] @ 0x1091 (variant v2)
- issue [CHG-SYNTAX] @ 0x1095 (variant v2)
- issue [CHG-SYNTAX] @ 0x1099 (variant v2)
- issue [CHG-SYNTAX] @ 0x109D (variant v2)
- issue [CHG-SYNTAX] @ 0x10A1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10A5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10A9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10AD (variant v2)
- issue [CHG-SYNTAX] @ 0x10B1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10B5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10B9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10BD (variant v2)
- issue [CHG-SYNTAX] @ 0x10C1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10C5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10C9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10CD (variant v2)
- issue [CHG-SYNTAX] @ 0x10D1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10D5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10D9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10DD (variant v2)
- issue [CHG-SYNTAX] @ 0x10E1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10E5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10E9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10ED (variant v2)
- issue [CHG-SYNTAX] @ 0x10F1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10F5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10F9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10FD (variant v2)
- issue [CHG-SYNTAX] @ 0x1101 (variant v2)
- issue [CHG-SYNTAX] @ 0x1105 (variant v2)
- issue [CHK-MISMATCH] @ 0x1002 (variant v2)
- issue [CHK-MISMATCH] @ 0x1006 (variant v2)
- issue [CHK-MISMATCH] @ 0x100A (variant v2)
- issue [CHK-MISMATCH] @ 0x100E (variant v2)
- issue [CHK-MISMATCH] @ 0x1012 (variant v2)
- issue [CHK-MISMATCH] @ 0x1016 (variant v2)
- issue [CHK-MISMATCH] @ 0x101A (variant v2)
- issue [CHK-MISMATCH] @ 0x101E (variant v2)
- issue [CHK-MISMATCH] @ 0x1022 (variant v2)
- issue [CHK-MISMATCH] @ 0x1026 (variant v2)
- issue [CHK-MISMATCH] @ 0x102A (variant v2)
- issue [CHK-MISMATCH] @ 0x102E (variant v2)
- issue [CHK-MISMATCH] @ 0x1032 (variant v2)
- issue [CHK-MISMATCH] @ 0x1036 (variant v2)
- issue [CHK-MISMATCH] @ 0x103A (variant v2)
- issue [CHK-MISMATCH] @ 0x103E (variant v2)
- issue [CHK-MISMATCH] @ 0x1042 (variant v2)
- issue [CHK-MISMATCH] @ 0x1046 (variant v2)
- issue [CHK-MISMATCH] @ 0x104A (variant v2)
- issue [CHK-MISMATCH] @ 0x104E (variant v2)
- issue [CHK-MISMATCH] @ 0x1052 (variant v2)
- issue [CHK-MISMATCH] @ 0x1056 (variant v2)
- issue [CHK-MISMATCH] @ 0x105A (variant v2)
- issue [CHK-MISMATCH] @ 0x105E (variant v2)
- issue [CHK-MISMATCH] @ 0x1062 (variant v2)
- issue [CHK-MISMATCH] @ 0x1066 (variant v2)
- issue [CHK-MISMATCH] @ 0x106A (variant v2)
- issue [CHK-MISMATCH] @ 0x106E (variant v2)
- issue [CHK-MISMATCH] @ 0x1072 (variant v2)
- issue [CHK-MISMATCH] @ 0x1076 (variant v2)
- issue [CHK-MISMATCH] @ 0x107A (variant v2)
- issue [CHK-MISMATCH] @ 0x107E (variant v2)
- issue [CHK-MISMATCH] @ 0x1082 (variant v2)
- issue [CHK-MISMATCH] @ 0x1086 (variant v2)
- issue [CHK-MISMATCH] @ 0x108A (variant v2)
- issue [CHK-MISMATCH] @ 0x108E (variant v2)
- issue [CHK-MISMATCH] @ 0x1092 (variant v2)
- issue [CHK-MISMATCH] @ 0x1096 (variant v2)
- issue [CHK-MISMATCH] @ 0x109A (variant v2)
- issue [CHK-MISMATCH] @ 0x109E (variant v2)
- issue [CHK-MISMATCH] @ 0x10A2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10A6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10AA (variant v2)
- issue [CHK-MISMATCH] @ 0x10AE (variant v2)
- issue [CHK-MISMATCH] @ 0x10B2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10B6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10BA (variant v2)
- issue [CHK-MISMATCH] @ 0x10BE (variant v2)
- issue [CHK-MISMATCH] @ 0x10C2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10C6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10CA (variant v2)
- issue [CHK-MISMATCH] @ 0x10CE (variant v2)
- issue [CHK-MISMATCH] @ 0x10D2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10D6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10DA (variant v2)
- issue [CHK-MISMATCH] @ 0x10DE (variant v2)
- issue [CHK-MISMATCH] @ 0x10E2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10E6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10EA (variant v2)
- issue [CHK-MISMATCH] @ 0x10EE (variant v2)
- issue [CHK-MISMATCH] @ 0x10F2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10F6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10FA (variant v2)
- issue [CHK-MISMATCH] @ 0x10FE (variant v2)
- issue [CHK-MISMATCH] @ 0x1102 (variant v2)
- issue [CHK-MISMATCH] @ 0x1106 (variant v2)

### zone 1 (0x1000-0x3000)
- modification @ 0x1000 (variant v0)
- modification @ 0x1004 (variant v0)
- modification @ 0x1008 (variant v0)
- modification @ 0x100C (variant v0)
- modification @ 0x1010 (variant v0)
- modification @ 0x1014 (variant v0)
- modification @ 0x1018 (variant v0)
- modification @ 0x101C (variant v0)
- modification @ 0x1020 (variant v0)
- modification @ 0x1024 (variant v0)
- modification @ 0x1028 (variant v0)
- modification @ 0x102C (variant v0)
- modification @ 0x1030 (variant v0)
- modification @ 0x1034 (variant v0)
- modification @ 0x1038 (variant v0)
- modification @ 0x103C (variant v0)
- modification @ 0x1040 (variant v0)
- modification @ 0x1044 (variant v0)
- modification @ 0x1048 (variant v0)
- modification @ 0x104C (variant v0)
- modification @ 0x1050 (variant v0)
- modification @ 0x1054 (variant v0)
- modification @ 0x1058 (variant v0)
- modification @ 0x105C (variant v0)
- modification @ 0x1060 (variant v0)
- modification @ 0x1064 (variant v0)
- modification @ 0x1068 (variant v0)
- modification @ 0x106C (variant v0)
- modification @ 0x1070 (variant v0)
- modification @ 0x1074 (variant v0)
- modification @ 0x1078 (variant v0)
- modification @ 0x107C (variant v0)
- modification @ 0x1080 (variant v0)
- modification @ 0x1084 (variant v0)
- modification @ 0x1088 (variant v0)
- modification @ 0x108C (variant v0)
- modification @ 0x1090 (variant v0)
- modification @ 0x1094 (variant v0)
- modification @ 0x1098 (variant v0)
- modification @ 0x109C (variant v0)
- modification @ 0x10A0 (variant v0)
- modification @ 0x10A4 (variant v0)
- modification @ 0x10A8 (variant v0)
- modification @ 0x10AC (variant v0)
- modification @ 0x10B0 (variant v0)
- modification @ 0x10B4 (variant v0)
- modification @ 0x10B8 (variant v0)
- modification @ 0x10BC (variant v0)
- modification @ 0x10C0 (variant v0)
- modification @ 0x10C4 (variant v0)
- modification @ 0x10C8 (variant v0)
- modification @ 0x10CC (variant v0)
- modification @ 0x10D0 (variant v0)
- modification @ 0x10D4 (variant v0)
- modification @ 0x10D8 (variant v0)
- modification @ 0x10DC (variant v0)
- modification @ 0x10E0 (variant v0)
- modification @ 0x10E4 (variant v0)
- modification @ 0x10E8 (variant v0)
- modification @ 0x10EC (variant v0)
- modification @ 0x10F0 (variant v0)
- modification @ 0x10F4 (variant v0)
- modification @ 0x10F8 (variant v0)
- modification @ 0x10FC (variant v0)
- modification @ 0x1100 (variant v0)
- modification @ 0x1104 (variant v0)
- issue [CHG-SYNTAX] @ 0x1001 (variant v0)
- issue [CHG-SYNTAX] @ 0x1005 (variant v0)
- issue [CHG-SYNTAX] @ 0x1009 (variant v0)
- issue [CHG-SYNTAX] @ 0x100D (variant v0)
- issue [CHG-SYNTAX] @ 0x1011 (variant v0)
- issue [CHG-SYNTAX] @ 0x1015 (variant v0)
- issue [CHG-SYNTAX] @ 0x1019 (variant v0)
- issue [CHG-SYNTAX] @ 0x101D (variant v0)
- issue [CHG-SYNTAX] @ 0x1021 (variant v0)
- issue [CHG-SYNTAX] @ 0x1025 (variant v0)
- issue [CHG-SYNTAX] @ 0x1029 (variant v0)
- issue [CHG-SYNTAX] @ 0x102D (variant v0)
- issue [CHG-SYNTAX] @ 0x1031 (variant v0)
- issue [CHG-SYNTAX] @ 0x1035 (variant v0)
- issue [CHG-SYNTAX] @ 0x1039 (variant v0)
- issue [CHG-SYNTAX] @ 0x103D (variant v0)
- issue [CHG-SYNTAX] @ 0x1041 (variant v0)
- issue [CHG-SYNTAX] @ 0x1045 (variant v0)
- issue [CHG-SYNTAX] @ 0x1049 (variant v0)
- issue [CHG-SYNTAX] @ 0x104D (variant v0)
- issue [CHG-SYNTAX] @ 0x1051 (variant v0)
- issue [CHG-SYNTAX] @ 0x1055 (variant v0)
- issue [CHG-SYNTAX] @ 0x1059 (variant v0)
- issue [CHG-SYNTAX] @ 0x105D (variant v0)
- issue [CHG-SYNTAX] @ 0x1061 (variant v0)
- issue [CHG-SYNTAX] @ 0x1065 (variant v0)
- issue [CHG-SYNTAX] @ 0x1069 (variant v0)
- issue [CHG-SYNTAX] @ 0x106D (variant v0)
- issue [CHG-SYNTAX] @ 0x1071 (variant v0)
- issue [CHG-SYNTAX] @ 0x1075 (variant v0)
- issue [CHG-SYNTAX] @ 0x1079 (variant v0)
- issue [CHG-SYNTAX] @ 0x107D (variant v0)
- issue [CHG-SYNTAX] @ 0x1081 (variant v0)
- issue [CHG-SYNTAX] @ 0x1085 (variant v0)
- issue [CHG-SYNTAX] @ 0x1089 (variant v0)
- issue [CHG-SYNTAX] @ 0x108D (variant v0)
- issue [CHG-SYNTAX] @ 0x1091 (variant v0)
- issue [CHG-SYNTAX] @ 0x1095 (variant v0)
- issue [CHG-SYNTAX] @ 0x1099 (variant v0)
- issue [CHG-SYNTAX] @ 0x109D (variant v0)
- issue [CHG-SYNTAX] @ 0x10A1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10A5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10A9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10AD (variant v0)
- issue [CHG-SYNTAX] @ 0x10B1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10B5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10B9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10BD (variant v0)
- issue [CHG-SYNTAX] @ 0x10C1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10C5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10C9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10CD (variant v0)
- issue [CHG-SYNTAX] @ 0x10D1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10D5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10D9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10DD (variant v0)
- issue [CHG-SYNTAX] @ 0x10E1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10E5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10E9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10ED (variant v0)
- issue [CHG-SYNTAX] @ 0x10F1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10F5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10F9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10FD (variant v0)
- issue [CHG-SYNTAX] @ 0x1101 (variant v0)
- issue [CHG-SYNTAX] @ 0x1105 (variant v0)
- issue [CHK-MISMATCH] @ 0x1002 (variant v0)
- issue [CHK-MISMATCH] @ 0x1006 (variant v0)
- issue [CHK-MISMATCH] @ 0x100A (variant v0)
- issue [CHK-MISMATCH] @ 0x100E (variant v0)
- issue [CHK-MISMATCH] @ 0x1012 (variant v0)
- issue [CHK-MISMATCH] @ 0x1016 (variant v0)
- issue [CHK-MISMATCH] @ 0x101A (variant v0)
- issue [CHK-MISMATCH] @ 0x101E (variant v0)
- issue [CHK-MISMATCH] @ 0x1022 (variant v0)
- issue [CHK-MISMATCH] @ 0x1026 (variant v0)
- issue [CHK-MISMATCH] @ 0x102A (variant v0)
- issue [CHK-MISMATCH] @ 0x102E (variant v0)
- issue [CHK-MISMATCH] @ 0x1032 (variant v0)
- issue [CHK-MISMATCH] @ 0x1036 (variant v0)
- issue [CHK-MISMATCH] @ 0x103A (variant v0)
- issue [CHK-MISMATCH] @ 0x103E (variant v0)
- issue [CHK-MISMATCH] @ 0x1042 (variant v0)
- issue [CHK-MISMATCH] @ 0x1046 (variant v0)
- issue [CHK-MISMATCH] @ 0x104A (variant v0)
- issue [CHK-MISMATCH] @ 0x104E (variant v0)
- issue [CHK-MISMATCH] @ 0x1052 (variant v0)
- issue [CHK-MISMATCH] @ 0x1056 (variant v0)
- issue [CHK-MISMATCH] @ 0x105A (variant v0)
- issue [CHK-MISMATCH] @ 0x105E (variant v0)
- issue [CHK-MISMATCH] @ 0x1062 (variant v0)
- issue [CHK-MISMATCH] @ 0x1066 (variant v0)
- issue [CHK-MISMATCH] @ 0x106A (variant v0)
- issue [CHK-MISMATCH] @ 0x106E (variant v0)
- issue [CHK-MISMATCH] @ 0x1072 (variant v0)
- issue [CHK-MISMATCH] @ 0x1076 (variant v0)
- issue [CHK-MISMATCH] @ 0x107A (variant v0)
- issue [CHK-MISMATCH] @ 0x107E (variant v0)
- issue [CHK-MISMATCH] @ 0x1082 (variant v0)
- issue [CHK-MISMATCH] @ 0x1086 (variant v0)
- issue [CHK-MISMATCH] @ 0x108A (variant v0)
- issue [CHK-MISMATCH] @ 0x108E (variant v0)
- issue [CHK-MISMATCH] @ 0x1092 (variant v0)
- issue [CHK-MISMATCH] @ 0x1096 (variant v0)
- issue [CHK-MISMATCH] @ 0x109A (variant v0)
- issue [CHK-MISMATCH] @ 0x109E (variant v0)
- issue [CHK-MISMATCH] @ 0x10A2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10A6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10AA (variant v0)
- issue [CHK-MISMATCH] @ 0x10AE (variant v0)
- issue [CHK-MISMATCH] @ 0x10B2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10B6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10BA (variant v0)
- issue [CHK-MISMATCH] @ 0x10BE (variant v0)
- issue [CHK-MISMATCH] @ 0x10C2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10C6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10CA (variant v0)
- issue [CHK-MISMATCH] @ 0x10CE (variant v0)
- issue [CHK-MISMATCH] @ 0x10D2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10D6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10DA (variant v0)
- issue [CHK-MISMATCH] @ 0x10DE (variant v0)
- issue [CHK-MISMATCH] @ 0x10E2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10E6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10EA (variant v0)
- issue [CHK-MISMATCH] @ 0x10EE (variant v0)
- issue [CHK-MISMATCH] @ 0x10F2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10F6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10FA (variant v0)
- issue [CHK-MISMATCH] @ 0x10FE (variant v0)
- issue [CHK-MISMATCH] @ 0x1102 (variant v0)
- issue [CHK-MISMATCH] @ 0x1106 (variant v0)
- modification @ 0x1000 (variant v1)
- modification @ 0x1004 (variant v1)
- modification @ 0x1008 (variant v1)
- modification @ 0x100C (variant v1)
- modification @ 0x1010 (variant v1)
- modification @ 0x1014 (variant v1)
- modification @ 0x1018 (variant v1)
- modification @ 0x101C (variant v1)
- modification @ 0x1020 (variant v1)
- modification @ 0x1024 (variant v1)
- modification @ 0x1028 (variant v1)
- modification @ 0x102C (variant v1)
- modification @ 0x1030 (variant v1)
- modification @ 0x1034 (variant v1)
- modification @ 0x1038 (variant v1)
- modification @ 0x103C (variant v1)
- modification @ 0x1040 (variant v1)
- modification @ 0x1044 (variant v1)
- modification @ 0x1048 (variant v1)
- modification @ 0x104C (variant v1)
- modification @ 0x1050 (variant v1)
- modification @ 0x1054 (variant v1)
- modification @ 0x1058 (variant v1)
- modification @ 0x105C (variant v1)
- modification @ 0x1060 (variant v1)
- modification @ 0x1064 (variant v1)
- modification @ 0x1068 (variant v1)
- modification @ 0x106C (variant v1)
- modification @ 0x1070 (variant v1)
- modification @ 0x1074 (variant v1)
- modification @ 0x1078 (variant v1)
- modification @ 0x107C (variant v1)
- modification @ 0x1080 (variant v1)
- modification @ 0x1084 (variant v1)
- modification @ 0x1088 (variant v1)
- modification @ 0x108C (variant v1)
- modification @ 0x1090 (variant v1)
- modification @ 0x1094 (variant v1)
- modification @ 0x1098 (variant v1)
- modification @ 0x109C (variant v1)
- modification @ 0x10A0 (variant v1)
- modification @ 0x10A4 (variant v1)
- modification @ 0x10A8 (variant v1)
- modification @ 0x10AC (variant v1)
- modification @ 0x10B0 (variant v1)
- modification @ 0x10B4 (variant v1)
- modification @ 0x10B8 (variant v1)
- modification @ 0x10BC (variant v1)
- modification @ 0x10C0 (variant v1)
- modification @ 0x10C4 (variant v1)
- modification @ 0x10C8 (variant v1)
- modification @ 0x10CC (variant v1)
- modification @ 0x10D0 (variant v1)
- modification @ 0x10D4 (variant v1)
- modification @ 0x10D8 (variant v1)
- modification @ 0x10DC (variant v1)
- modification @ 0x10E0 (variant v1)
- modification @ 0x10E4 (variant v1)
- modification @ 0x10E8 (variant v1)
- modification @ 0x10EC (variant v1)
- modification @ 0x10F0 (variant v1)
- modification @ 0x10F4 (variant v1)
- modification @ 0x10F8 (variant v1)
- modification @ 0x10FC (variant v1)
- modification @ 0x1100 (variant v1)
- modification @ 0x1104 (variant v1)
- issue [CHG-SYNTAX] @ 0x1001 (variant v1)
- issue [CHG-SYNTAX] @ 0x1005 (variant v1)
- issue [CHG-SYNTAX] @ 0x1009 (variant v1)
- issue [CHG-SYNTAX] @ 0x100D (variant v1)
- issue [CHG-SYNTAX] @ 0x1011 (variant v1)
- issue [CHG-SYNTAX] @ 0x1015 (variant v1)
- issue [CHG-SYNTAX] @ 0x1019 (variant v1)
- issue [CHG-SYNTAX] @ 0x101D (variant v1)
- issue [CHG-SYNTAX] @ 0x1021 (variant v1)
- issue [CHG-SYNTAX] @ 0x1025 (variant v1)
- issue [CHG-SYNTAX] @ 0x1029 (variant v1)
- issue [CHG-SYNTAX] @ 0x102D (variant v1)
- issue [CHG-SYNTAX] @ 0x1031 (variant v1)
- issue [CHG-SYNTAX] @ 0x1035 (variant v1)
- issue [CHG-SYNTAX] @ 0x1039 (variant v1)
- issue [CHG-SYNTAX] @ 0x103D (variant v1)
- issue [CHG-SYNTAX] @ 0x1041 (variant v1)
- issue [CHG-SYNTAX] @ 0x1045 (variant v1)
- issue [CHG-SYNTAX] @ 0x1049 (variant v1)
- issue [CHG-SYNTAX] @ 0x104D (variant v1)
- issue [CHG-SYNTAX] @ 0x1051 (variant v1)
- issue [CHG-SYNTAX] @ 0x1055 (variant v1)
- issue [CHG-SYNTAX] @ 0x1059 (variant v1)
- issue [CHG-SYNTAX] @ 0x105D (variant v1)
- issue [CHG-SYNTAX] @ 0x1061 (variant v1)
- issue [CHG-SYNTAX] @ 0x1065 (variant v1)
- issue [CHG-SYNTAX] @ 0x1069 (variant v1)
- issue [CHG-SYNTAX] @ 0x106D (variant v1)
- issue [CHG-SYNTAX] @ 0x1071 (variant v1)
- issue [CHG-SYNTAX] @ 0x1075 (variant v1)
- issue [CHG-SYNTAX] @ 0x1079 (variant v1)
- issue [CHG-SYNTAX] @ 0x107D (variant v1)
- issue [CHG-SYNTAX] @ 0x1081 (variant v1)
- issue [CHG-SYNTAX] @ 0x1085 (variant v1)
- issue [CHG-SYNTAX] @ 0x1089 (variant v1)
- issue [CHG-SYNTAX] @ 0x108D (variant v1)
- issue [CHG-SYNTAX] @ 0x1091 (variant v1)
- issue [CHG-SYNTAX] @ 0x1095 (variant v1)
- issue [CHG-SYNTAX] @ 0x1099 (variant v1)
- issue [CHG-SYNTAX] @ 0x109D (variant v1)
- issue [CHG-SYNTAX] @ 0x10A1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10A5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10A9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10AD (variant v1)
- issue [CHG-SYNTAX] @ 0x10B1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10B5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10B9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10BD (variant v1)
- issue [CHG-SYNTAX] @ 0x10C1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10C5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10C9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10CD (variant v1)
- issue [CHG-SYNTAX] @ 0x10D1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10D5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10D9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10DD (variant v1)
- issue [CHG-SYNTAX] @ 0x10E1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10E5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10E9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10ED (variant v1)
- issue [CHG-SYNTAX] @ 0x10F1 (variant v1)
- issue [CHG-SYNTAX] @ 0x10F5 (variant v1)
- issue [CHG-SYNTAX] @ 0x10F9 (variant v1)
- issue [CHG-SYNTAX] @ 0x10FD (variant v1)
- issue [CHG-SYNTAX] @ 0x1101 (variant v1)
- issue [CHG-SYNTAX] @ 0x1105 (variant v1)
- issue [CHK-MISMATCH] @ 0x1002 (variant v1)
- issue [CHK-MISMATCH] @ 0x1006 (variant v1)
- issue [CHK-MISMATCH] @ 0x100A (variant v1)
- issue [CHK-MISMATCH] @ 0x100E (variant v1)
- issue [CHK-MISMATCH] @ 0x1012 (variant v1)
- issue [CHK-MISMATCH] @ 0x1016 (variant v1)
- issue [CHK-MISMATCH] @ 0x101A (variant v1)
- issue [CHK-MISMATCH] @ 0x101E (variant v1)
- issue [CHK-MISMATCH] @ 0x1022 (variant v1)
- issue [CHK-MISMATCH] @ 0x1026 (variant v1)
- issue [CHK-MISMATCH] @ 0x102A (variant v1)
- issue [CHK-MISMATCH] @ 0x102E (variant v1)
- issue [CHK-MISMATCH] @ 0x1032 (variant v1)
- issue [CHK-MISMATCH] @ 0x1036 (variant v1)
- issue [CHK-MISMATCH] @ 0x103A (variant v1)
- issue [CHK-MISMATCH] @ 0x103E (variant v1)
- issue [CHK-MISMATCH] @ 0x1042 (variant v1)
- issue [CHK-MISMATCH] @ 0x1046 (variant v1)
- issue [CHK-MISMATCH] @ 0x104A (variant v1)
- issue [CHK-MISMATCH] @ 0x104E (variant v1)
- issue [CHK-MISMATCH] @ 0x1052 (variant v1)
- issue [CHK-MISMATCH] @ 0x1056 (variant v1)
- issue [CHK-MISMATCH] @ 0x105A (variant v1)
- issue [CHK-MISMATCH] @ 0x105E (variant v1)
- issue [CHK-MISMATCH] @ 0x1062 (variant v1)
- issue [CHK-MISMATCH] @ 0x1066 (variant v1)
- issue [CHK-MISMATCH] @ 0x106A (variant v1)
- issue [CHK-MISMATCH] @ 0x106E (variant v1)
- issue [CHK-MISMATCH] @ 0x1072 (variant v1)
- issue [CHK-MISMATCH] @ 0x1076 (variant v1)
- issue [CHK-MISMATCH] @ 0x107A (variant v1)
- issue [CHK-MISMATCH] @ 0x107E (variant v1)
- issue [CHK-MISMATCH] @ 0x1082 (variant v1)
- issue [CHK-MISMATCH] @ 0x1086 (variant v1)
- issue [CHK-MISMATCH] @ 0x108A (variant v1)
- issue [CHK-MISMATCH] @ 0x108E (variant v1)
- issue [CHK-MISMATCH] @ 0x1092 (variant v1)
- issue [CHK-MISMATCH] @ 0x1096 (variant v1)
- issue [CHK-MISMATCH] @ 0x109A (variant v1)
- issue [CHK-MISMATCH] @ 0x109E (variant v1)
- issue [CHK-MISMATCH] @ 0x10A2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10A6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10AA (variant v1)
- issue [CHK-MISMATCH] @ 0x10AE (variant v1)
- issue [CHK-MISMATCH] @ 0x10B2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10B6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10BA (variant v1)
- issue [CHK-MISMATCH] @ 0x10BE (variant v1)
- issue [CHK-MISMATCH] @ 0x10C2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10C6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10CA (variant v1)
- issue [CHK-MISMATCH] @ 0x10CE (variant v1)
- issue [CHK-MISMATCH] @ 0x10D2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10D6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10DA (variant v1)
- issue [CHK-MISMATCH] @ 0x10DE (variant v1)
- issue [CHK-MISMATCH] @ 0x10E2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10E6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10EA (variant v1)
- issue [CHK-MISMATCH] @ 0x10EE (variant v1)
- issue [CHK-MISMATCH] @ 0x10F2 (variant v1)
- issue [CHK-MISMATCH] @ 0x10F6 (variant v1)
- issue [CHK-MISMATCH] @ 0x10FA (variant v1)
- issue [CHK-MISMATCH] @ 0x10FE (variant v1)
- issue [CHK-MISMATCH] @ 0x1102 (variant v1)
- issue [CHK-MISMATCH] @ 0x1106 (variant v1)
- modification @ 0x1000 (variant v2)
- modification @ 0x1004 (variant v2)
- modification @ 0x1008 (variant v2)
- modification @ 0x100C (variant v2)
- modification @ 0x1010 (variant v2)
- modification @ 0x1014 (variant v2)
- modification @ 0x1018 (variant v2)
- modification @ 0x101C (variant v2)
- modification @ 0x1020 (variant v2)
- modification @ 0x1024 (variant v2)
- modification @ 0x1028 (variant v2)
- modification @ 0x102C (variant v2)
- modification @ 0x1030 (variant v2)
- modification @ 0x1034 (variant v2)
- modification @ 0x1038 (variant v2)
- modification @ 0x103C (variant v2)
- modification @ 0x1040 (variant v2)
- modification @ 0x1044 (variant v2)
- modification @ 0x1048 (variant v2)
- modification @ 0x104C (variant v2)
- modification @ 0x1050 (variant v2)
- modification @ 0x1054 (variant v2)
- modification @ 0x1058 (variant v2)
- modification @ 0x105C (variant v2)
- modification @ 0x1060 (variant v2)
- modification @ 0x1064 (variant v2)
- modification @ 0x1068 (variant v2)
- modification @ 0x106C (variant v2)
- modification @ 0x1070 (variant v2)
- modification @ 0x1074 (variant v2)
- modification @ 0x1078 (variant v2)
- modification @ 0x107C (variant v2)
- modification @ 0x1080 (variant v2)
- modification @ 0x1084 (variant v2)
- modification @ 0x1088 (variant v2)
- modification @ 0x108C (variant v2)
- modification @ 0x1090 (variant v2)
- modification @ 0x1094 (variant v2)
- modification @ 0x1098 (variant v2)
- modification @ 0x109C (variant v2)
- modification @ 0x10A0 (variant v2)
- modification @ 0x10A4 (variant v2)
- modification @ 0x10A8 (variant v2)
- modification @ 0x10AC (variant v2)
- modification @ 0x10B0 (variant v2)
- modification @ 0x10B4 (variant v2)
- modification @ 0x10B8 (variant v2)
- modification @ 0x10BC (variant v2)
- modification @ 0x10C0 (variant v2)
- modification @ 0x10C4 (variant v2)
- modification @ 0x10C8 (variant v2)
- modification @ 0x10CC (variant v2)
- modification @ 0x10D0 (variant v2)
- modification @ 0x10D4 (variant v2)
- modification @ 0x10D8 (variant v2)
- modification @ 0x10DC (variant v2)
- modification @ 0x10E0 (variant v2)
- modification @ 0x10E4 (variant v2)
- modification @ 0x10E8 (variant v2)
- modification @ 0x10EC (variant v2)
- modification @ 0x10F0 (variant v2)
- modification @ 0x10F4 (variant v2)
- modification @ 0x10F8 (variant v2)
- modification @ 0x10FC (variant v2)
- modification @ 0x1100 (variant v2)
- modification @ 0x1104 (variant v2)
- issue [CHG-SYNTAX] @ 0x1001 (variant v2)
- issue [CHG-SYNTAX] @ 0x1005 (variant v2)
- issue [CHG-SYNTAX] @ 0x1009 (variant v2)
- issue [CHG-SYNTAX] @ 0x100D (variant v2)
- issue [CHG-SYNTAX] @ 0x1011 (variant v2)
- issue [CHG-SYNTAX] @ 0x1015 (variant v2)
- issue [CHG-SYNTAX] @ 0x1019 (variant v2)
- issue [CHG-SYNTAX] @ 0x101D (variant v2)
- issue [CHG-SYNTAX] @ 0x1021 (variant v2)
- issue [CHG-SYNTAX] @ 0x1025 (variant v2)
- issue [CHG-SYNTAX] @ 0x1029 (variant v2)
- issue [CHG-SYNTAX] @ 0x102D (variant v2)
- issue [CHG-SYNTAX] @ 0x1031 (variant v2)
- issue [CHG-SYNTAX] @ 0x1035 (variant v2)
- issue [CHG-SYNTAX] @ 0x1039 (variant v2)
- issue [CHG-SYNTAX] @ 0x103D (variant v2)
- issue [CHG-SYNTAX] @ 0x1041 (variant v2)
- issue [CHG-SYNTAX] @ 0x1045 (variant v2)
- issue [CHG-SYNTAX] @ 0x1049 (variant v2)
- issue [CHG-SYNTAX] @ 0x104D (variant v2)
- issue [CHG-SYNTAX] @ 0x1051 (variant v2)
- issue [CHG-SYNTAX] @ 0x1055 (variant v2)
- issue [CHG-SYNTAX] @ 0x1059 (variant v2)
- issue [CHG-SYNTAX] @ 0x105D (variant v2)
- issue [CHG-SYNTAX] @ 0x1061 (variant v2)
- issue [CHG-SYNTAX] @ 0x1065 (variant v2)
- issue [CHG-SYNTAX] @ 0x1069 (variant v2)
- issue [CHG-SYNTAX] @ 0x106D (variant v2)
- issue [CHG-SYNTAX] @ 0x1071 (variant v2)
- issue [CHG-SYNTAX] @ 0x1075 (variant v2)
- issue [CHG-SYNTAX] @ 0x1079 (variant v2)
- issue [CHG-SYNTAX] @ 0x107D (variant v2)
- issue [CHG-SYNTAX] @ 0x1081 (variant v2)
- issue [CHG-SYNTAX] @ 0x1085 (variant v2)
- issue [CHG-SYNTAX] @ 0x1089 (variant v2)
- issue [CHG-SYNTAX] @ 0x108D (variant v2)
- issue [CHG-SYNTAX] @ 0x1091 (variant v2)
- issue [CHG-SYNTAX] @ 0x1095 (variant v2)
- issue [CHG-SYNTAX] @ 0x1099 (variant v2)
- issue [CHG-SYNTAX] @ 0x109D (variant v2)
- issue [CHG-SYNTAX] @ 0x10A1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10A5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10A9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10AD (variant v2)
- issue [CHG-SYNTAX] @ 0x10B1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10B5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10B9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10BD (variant v2)
- issue [CHG-SYNTAX] @ 0x10C1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10C5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10C9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10CD (variant v2)
- issue [CHG-SYNTAX] @ 0x10D1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10D5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10D9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10DD (variant v2)
- issue [CHG-SYNTAX] @ 0x10E1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10E5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10E9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10ED (variant v2)
- issue [CHG-SYNTAX] @ 0x10F1 (variant v2)
- issue [CHG-SYNTAX] @ 0x10F5 (variant v2)
- issue [CHG-SYNTAX] @ 0x10F9 (variant v2)
- issue [CHG-SYNTAX] @ 0x10FD (variant v2)
- issue [CHG-SYNTAX] @ 0x1101 (variant v2)
- issue [CHG-SYNTAX] @ 0x1105 (variant v2)
- issue [CHK-MISMATCH] @ 0x1002 (variant v2)
- issue [CHK-MISMATCH] @ 0x1006 (variant v2)
- issue [CHK-MISMATCH] @ 0x100A (variant v2)
- issue [CHK-MISMATCH] @ 0x100E (variant v2)
- issue [CHK-MISMATCH] @ 0x1012 (variant v2)
- issue [CHK-MISMATCH] @ 0x1016 (variant v2)
- issue [CHK-MISMATCH] @ 0x101A (variant v2)
- issue [CHK-MISMATCH] @ 0x101E (variant v2)
- issue [CHK-MISMATCH] @ 0x1022 (variant v2)
- issue [CHK-MISMATCH] @ 0x1026 (variant v2)
- issue [CHK-MISMATCH] @ 0x102A (variant v2)
- issue [CHK-MISMATCH] @ 0x102E (variant v2)
- issue [CHK-MISMATCH] @ 0x1032 (variant v2)
- issue [CHK-MISMATCH] @ 0x1036 (variant v2)
- issue [CHK-MISMATCH] @ 0x103A (variant v2)
- issue [CHK-MISMATCH] @ 0x103E (variant v2)
- issue [CHK-MISMATCH] @ 0x1042 (variant v2)
- issue [CHK-MISMATCH] @ 0x1046 (variant v2)
- issue [CHK-MISMATCH] @ 0x104A (variant v2)
- issue [CHK-MISMATCH] @ 0x104E (variant v2)
- issue [CHK-MISMATCH] @ 0x1052 (variant v2)
- issue [CHK-MISMATCH] @ 0x1056 (variant v2)
- issue [CHK-MISMATCH] @ 0x105A (variant v2)
- issue [CHK-MISMATCH] @ 0x105E (variant v2)
- issue [CHK-MISMATCH] @ 0x1062 (variant v2)
- issue [CHK-MISMATCH] @ 0x1066 (variant v2)
- issue [CHK-MISMATCH] @ 0x106A (variant v2)
- issue [CHK-MISMATCH] @ 0x106E (variant v2)
- issue [CHK-MISMATCH] @ 0x1072 (variant v2)
- issue [CHK-MISMATCH] @ 0x1076 (variant v2)
- issue [CHK-MISMATCH] @ 0x107A (variant v2)
- issue [CHK-MISMATCH] @ 0x107E (variant v2)
- issue [CHK-MISMATCH] @ 0x1082 (variant v2)
- issue [CHK-MISMATCH] @ 0x1086 (variant v2)
- issue [CHK-MISMATCH] @ 0x108A (variant v2)
- issue [CHK-MISMATCH] @ 0x108E (variant v2)
- issue [CHK-MISMATCH] @ 0x1092 (variant v2)
- issue [CHK-MISMATCH] @ 0x1096 (variant v2)
- issue [CHK-MISMATCH] @ 0x109A (variant v2)
- issue [CHK-MISMATCH] @ 0x109E (variant v2)
- issue [CHK-MISMATCH] @ 0x10A2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10A6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10AA (variant v2)
- issue [CHK-MISMATCH] @ 0x10AE (variant v2)
- issue [CHK-MISMATCH] @ 0x10B2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10B6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10BA (variant v2)
- issue [CHK-MISMATCH] @ 0x10BE (variant v2)
- issue [CHK-MISMATCH] @ 0x10C2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10C6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10CA (variant v2)
- issue [CHK-MISMATCH] @ 0x10CE (variant v2)
- issue [CHK-MISMATCH] @ 0x10D2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10D6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10DA (variant v2)
- issue [CHK-MISMATCH] @ 0x10DE (variant v2)
- issue [CHK-MISMATCH] @ 0x10E2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10E6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10EA (variant v2)
- issue [CHK-MISMATCH] @ 0x10EE (variant v2)
- issue [CHK-MISMATCH] @ 0x10F2 (variant v2)
- issue [CHK-MISMATCH] @ 0x10F6 (variant v2)
- issue [CHK-MISMATCH] @ 0x10FA (variant v2)
- issue [CHK-MISMATCH] @ 0x10FE (variant v2)
- issue [CHK-MISMATCH] @ 0x1102 (variant v2)
- issue [CHK-MISMATCH] @ 0x1106 (variant v2)
<!-- s19tool-golden-shape: R1V1E0 -->
# Project report: proj

- Project: proj
- Generated (UTC): 2026-07-27T12:00:00+00:00
- Tool version: 0.1.0
- Context bytes: 64
- Execution mode: batch
- Assignment source: default

## Variant inventory

| Variant | File | Type | Active |
|---|---|---|---|
| v0 | v0\.s19 | s19 | yes |

## Consolidated overview

| Variant | Status | Changes applied | Checks passed | Checks failed | Checks uncheckable |
|---|---|---|---|---|---|
| v0 | ok | 0 | 0 | 0 | 0 |

## Legend

### A2L
- **Red** — schema/structural failure: malformed required field, invalid required reference, or hard-error duplicate symbol
- **Green** — memory checked — tag/range fully found in the loaded S19/HEX image
- **White** — valid A2L record with no hard inconsistency, including valid records not present in the image
- **Grey** — memory not checked yet, or no primary S19/HEX context loaded

### MAC
- **Red** — parse failed, invalid/missing name or hex address, or A2L↔MAC same-name address mismatch
- **Pale yellow** — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity
- **Green** — exact name + address match with A2L
- **White** — structurally valid MAC entry, no hard inconsistency, not positively cross-confirmed
- **Grey** — no A2L loaded, or validation context missing

### Issues
- **Errors** (Red) — parse/structure errors, empty name, invalid/missing address, duplicate symbol, broken GROUP/FUNCTION references, or A2L↔MAC same-name mismatch
- **Warnings** (Pale yellow) — address/range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias
- **Optional info** (Cyan) — valid-but-not-image-backed, not-checked-without-primary-image, or virtual/dependent non-memory-backed objects

### Hex
- **Yellow** — search / goto-focus highlight: the byte span matched by the last in-memory search or goto-address jump in the hex view
- **Orange3** — MAC address overlay: a hex byte at an address referenced by a loaded MAC record

## Variant: v0

### Modified files

No files were modified for this variant.

### Modifications

No change entries were executed for this variant.

### Declaration errors

None.

### Checklists

#### Checklist: `chk_v0.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

No modified regions.

### Entropy

No mapped bytes - entropy not computed.

## Addendum: declared regions

### zone 0 (0x1000-0x2000)
None.
<!-- s19tool-golden-shape: R1V1E200 -->
# Project report: proj

- Project: proj
- Generated (UTC): 2026-07-27T12:00:00+00:00
- Tool version: 0.1.0
- Context bytes: 64
- Execution mode: batch
- Assignment source: default

## Variant inventory

| Variant | File | Type | Active |
|---|---|---|---|
| v0 | v0\.s19 | s19 | yes |

## Consolidated overview

| Variant | Status | Changes applied | Checks passed | Checks failed | Checks uncheckable |
|---|---|---|---|---|---|
| v0 | ok | 200 | 0 | 0 | 0 |

## Legend

### A2L
- **Red** — schema/structural failure: malformed required field, invalid required reference, or hard-error duplicate symbol
- **Green** — memory checked — tag/range fully found in the loaded S19/HEX image
- **White** — valid A2L record with no hard inconsistency, including valid records not present in the image
- **Grey** — memory not checked yet, or no primary S19/HEX context loaded

### MAC
- **Red** — parse failed, invalid/missing name or hex address, or A2L↔MAC same-name address mismatch
- **Pale yellow** — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity
- **Green** — exact name + address match with A2L
- **White** — structurally valid MAC entry, no hard inconsistency, not positively cross-confirmed
- **Grey** — no A2L loaded, or validation context missing

### Issues
- **Errors** (Red) — parse/structure errors, empty name, invalid/missing address, duplicate symbol, broken GROUP/FUNCTION references, or A2L↔MAC same-name mismatch
- **Warnings** (Pale yellow) — address/range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias
- **Optional info** (Cyan) — valid-but-not-image-backed, not-checked-without-primary-image, or virtual/dependent non-memory-backed objects

### Hex
- **Yellow** — search / goto-focus highlight: the byte span matched by the last in-memory search or goto-address jump in the hex view
- **Orange3** — MAC address overlay: a hex byte at an address referenced by a loaded MAC record

## Variant: v0

### Modified files

- `chg_v0.json` (applied entries: 200)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00001000 | 1 | 01 | AA | standalone | - |
| 0x00001004 | 1 | 01 | AA | standalone | - |
| 0x00001008 | 1 | 01 | AA | standalone | - |
| 0x0000100C | 1 | 01 | AA | standalone | - |
| 0x00001010 | 1 | 01 | AA | standalone | - |
| 0x00001014 | 1 | 01 | AA | standalone | - |
| 0x00001018 | 1 | 01 | AA | standalone | - |
| 0x0000101C | 1 | 01 | AA | standalone | - |
| 0x00001020 | 1 | 01 | AA | standalone | - |
| 0x00001024 | 1 | 01 | AA | standalone | - |
| 0x00001028 | 1 | 01 | AA | standalone | - |
| 0x0000102C | 1 | 01 | AA | standalone | - |
| 0x00001030 | 1 | 01 | AA | standalone | - |
| 0x00001034 | 1 | 01 | AA | standalone | - |
| 0x00001038 | 1 | 01 | AA | standalone | - |
| 0x0000103C | 1 | 01 | AA | standalone | - |
| 0x00001040 | 1 | 01 | AA | standalone | - |
| 0x00001044 | 1 | 01 | AA | standalone | - |
| 0x00001048 | 1 | 01 | AA | standalone | - |
| 0x0000104C | 1 | 01 | AA | standalone | - |
| 0x00001050 | 1 | 01 | AA | standalone | - |
| 0x00001054 | 1 | 01 | AA | standalone | - |
| 0x00001058 | 1 | 01 | AA | standalone | - |
| 0x0000105C | 1 | 01 | AA | standalone | - |
| 0x00001060 | 1 | 01 | AA | standalone | - |
| 0x00001064 | 1 | 01 | AA | standalone | - |
| 0x00001068 | 1 | 01 | AA | standalone | - |
| 0x0000106C | 1 | 01 | AA | standalone | - |
| 0x00001070 | 1 | 01 | AA | standalone | - |
| 0x00001074 | 1 | 01 | AA | standalone | - |
| 0x00001078 | 1 | 01 | AA | standalone | - |
| 0x0000107C | 1 | 01 | AA | standalone | - |
| 0x00001080 | 1 | 01 | AA | standalone | - |
| 0x00001084 | 1 | 01 | AA | standalone | - |
| 0x00001088 | 1 | 01 | AA | standalone | - |
| 0x0000108C | 1 | 01 | AA | standalone | - |
| 0x00001090 | 1 | 01 | AA | standalone | - |
| 0x00001094 | 1 | 01 | AA | standalone | - |
| 0x00001098 | 1 | 01 | AA | standalone | - |
| 0x0000109C | 1 | 01 | AA | standalone | - |
| 0x000010A0 | 1 | 01 | AA | standalone | - |
| 0x000010A4 | 1 | 01 | AA | standalone | - |
| 0x000010A8 | 1 | 01 | AA | standalone | - |
| 0x000010AC | 1 | 01 | AA | standalone | - |
| 0x000010B0 | 1 | 01 | AA | standalone | - |
| 0x000010B4 | 1 | 01 | AA | standalone | - |
| 0x000010B8 | 1 | 01 | AA | standalone | - |
| 0x000010BC | 1 | 01 | AA | standalone | - |
| 0x000010C0 | 1 | 01 | AA | standalone | - |
| 0x000010C4 | 1 | 01 | AA | standalone | - |
| 0x000010C8 | 1 | 01 | AA | standalone | - |
| 0x000010CC | 1 | 01 | AA | standalone | - |
| 0x000010D0 | 1 | 01 | AA | standalone | - |
| 0x000010D4 | 1 | 01 | AA | standalone | - |
| 0x000010D8 | 1 | 01 | AA | standalone | - |
| 0x000010DC | 1 | 01 | AA | standalone | - |
| 0x000010E0 | 1 | 01 | AA | standalone | - |
| 0x000010E4 | 1 | 01 | AA | standalone | - |
| 0x000010E8 | 1 | 01 | AA | standalone | - |
| 0x000010EC | 1 | 01 | AA | standalone | - |
| 0x000010F0 | 1 | 01 | AA | standalone | - |
| 0x000010F4 | 1 | 01 | AA | standalone | - |
| 0x000010F8 | 1 | 01 | AA | standalone | - |
| 0x000010FC | 1 | 01 | AA | standalone | - |
| 0x00001100 | 1 | 01 | AA | standalone | - |
| 0x00001104 | 1 | 01 | AA | standalone | - |
| 0x00001108 | 1 | 01 | AA | standalone | - |
| 0x0000110C | 1 | 01 | AA | standalone | - |
| 0x00001110 | 1 | 01 | AA | standalone | - |
| 0x00001114 | 1 | 01 | AA | standalone | - |
| 0x00001118 | 1 | 01 | AA | standalone | - |
| 0x0000111C | 1 | 01 | AA | standalone | - |
| 0x00001120 | 1 | 01 | AA | standalone | - |
| 0x00001124 | 1 | 01 | AA | standalone | - |
| 0x00001128 | 1 | 01 | AA | standalone | - |
| 0x0000112C | 1 | 01 | AA | standalone | - |
| 0x00001130 | 1 | 01 | AA | standalone | - |
| 0x00001134 | 1 | 01 | AA | standalone | - |
| 0x00001138 | 1 | 01 | AA | standalone | - |
| 0x0000113C | 1 | 01 | AA | standalone | - |
| 0x00001140 | 1 | 01 | AA | standalone | - |
| 0x00001144 | 1 | 01 | AA | standalone | - |
| 0x00001148 | 1 | 01 | AA | standalone | - |
| 0x0000114C | 1 | 01 | AA | standalone | - |
| 0x00001150 | 1 | 01 | AA | standalone | - |
| 0x00001154 | 1 | 01 | AA | standalone | - |
| 0x00001158 | 1 | 01 | AA | standalone | - |
| 0x0000115C | 1 | 01 | AA | standalone | - |
| 0x00001160 | 1 | 01 | AA | standalone | - |
| 0x00001164 | 1 | 01 | AA | standalone | - |
| 0x00001168 | 1 | 01 | AA | standalone | - |
| 0x0000116C | 1 | 01 | AA | standalone | - |
| 0x00001170 | 1 | 01 | AA | standalone | - |
| 0x00001174 | 1 | 01 | AA | standalone | - |
| 0x00001178 | 1 | 01 | AA | standalone | - |
| 0x0000117C | 1 | 01 | AA | standalone | - |
| 0x00001180 | 1 | 01 | AA | standalone | - |
| 0x00001184 | 1 | 01 | AA | standalone | - |
| 0x00001188 | 1 | 01 | AA | standalone | - |
| 0x0000118C | 1 | 01 | AA | standalone | - |
| 0x00001190 | 1 | 01 | AA | standalone | - |
| 0x00001194 | 1 | 01 | AA | standalone | - |
| 0x00001198 | 1 | 01 | AA | standalone | - |
| 0x0000119C | 1 | 01 | AA | standalone | - |
| 0x000011A0 | 1 | 01 | AA | standalone | - |
| 0x000011A4 | 1 | 01 | AA | standalone | - |
| 0x000011A8 | 1 | 01 | AA | standalone | - |
| 0x000011AC | 1 | 01 | AA | standalone | - |
| 0x000011B0 | 1 | 01 | AA | standalone | - |
| 0x000011B4 | 1 | 01 | AA | standalone | - |
| 0x000011B8 | 1 | 01 | AA | standalone | - |
| 0x000011BC | 1 | 01 | AA | standalone | - |
| 0x000011C0 | 1 | 01 | AA | standalone | - |
| 0x000011C4 | 1 | 01 | AA | standalone | - |
| 0x000011C8 | 1 | 01 | AA | standalone | - |
| 0x000011CC | 1 | 01 | AA | standalone | - |
| 0x000011D0 | 1 | 01 | AA | standalone | - |
| 0x000011D4 | 1 | 01 | AA | standalone | - |
| 0x000011D8 | 1 | 01 | AA | standalone | - |
| 0x000011DC | 1 | 01 | AA | standalone | - |
| 0x000011E0 | 1 | 01 | AA | standalone | - |
| 0x000011E4 | 1 | 01 | AA | standalone | - |
| 0x000011E8 | 1 | 01 | AA | standalone | - |
| 0x000011EC | 1 | 01 | AA | standalone | - |
| 0x000011F0 | 1 | 01 | AA | standalone | - |
| 0x000011F4 | 1 | 01 | AA | standalone | - |
| 0x000011F8 | 1 | 01 | AA | standalone | - |
| 0x000011FC | 1 | 01 | AA | standalone | - |
| 0x00001200 | 1 | 01 | AA | standalone | - |
| 0x00001204 | 1 | 01 | AA | standalone | - |
| 0x00001208 | 1 | 01 | AA | standalone | - |
| 0x0000120C | 1 | 01 | AA | standalone | - |
| 0x00001210 | 1 | 01 | AA | standalone | - |
| 0x00001214 | 1 | 01 | AA | standalone | - |
| 0x00001218 | 1 | 01 | AA | standalone | - |
| 0x0000121C | 1 | 01 | AA | standalone | - |
| 0x00001220 | 1 | 01 | AA | standalone | - |
| 0x00001224 | 1 | 01 | AA | standalone | - |
| 0x00001228 | 1 | 01 | AA | standalone | - |
| 0x0000122C | 1 | 01 | AA | standalone | - |
| 0x00001230 | 1 | 01 | AA | standalone | - |
| 0x00001234 | 1 | 01 | AA | standalone | - |
| 0x00001238 | 1 | 01 | AA | standalone | - |
| 0x0000123C | 1 | 01 | AA | standalone | - |
| 0x00001240 | 1 | 01 | AA | standalone | - |
| 0x00001244 | 1 | 01 | AA | standalone | - |
| 0x00001248 | 1 | 01 | AA | standalone | - |
| 0x0000124C | 1 | 01 | AA | standalone | - |
| 0x00001250 | 1 | 01 | AA | standalone | - |
| 0x00001254 | 1 | 01 | AA | standalone | - |
| 0x00001258 | 1 | 01 | AA | standalone | - |
| 0x0000125C | 1 | 01 | AA | standalone | - |
| 0x00001260 | 1 | 01 | AA | standalone | - |
| 0x00001264 | 1 | 01 | AA | standalone | - |
| 0x00001268 | 1 | 01 | AA | standalone | - |
| 0x0000126C | 1 | 01 | AA | standalone | - |
| 0x00001270 | 1 | 01 | AA | standalone | - |
| 0x00001274 | 1 | 01 | AA | standalone | - |
| 0x00001278 | 1 | 01 | AA | standalone | - |
| 0x0000127C | 1 | 01 | AA | standalone | - |
| 0x00001280 | 1 | 01 | AA | standalone | - |
| 0x00001284 | 1 | 01 | AA | standalone | - |
| 0x00001288 | 1 | 01 | AA | standalone | - |
| 0x0000128C | 1 | 01 | AA | standalone | - |
| 0x00001290 | 1 | 01 | AA | standalone | - |
| 0x00001294 | 1 | 01 | AA | standalone | - |
| 0x00001298 | 1 | 01 | AA | standalone | - |
| 0x0000129C | 1 | 01 | AA | standalone | - |
| 0x000012A0 | 1 | 01 | AA | standalone | - |
| 0x000012A4 | 1 | 01 | AA | standalone | - |
| 0x000012A8 | 1 | 01 | AA | standalone | - |
| 0x000012AC | 1 | 01 | AA | standalone | - |
| 0x000012B0 | 1 | 01 | AA | standalone | - |
| 0x000012B4 | 1 | 01 | AA | standalone | - |
| 0x000012B8 | 1 | 01 | AA | standalone | - |
| 0x000012BC | 1 | 01 | AA | standalone | - |
| 0x000012C0 | 1 | 01 | AA | standalone | - |
| 0x000012C4 | 1 | 01 | AA | standalone | - |
| 0x000012C8 | 1 | 01 | AA | standalone | - |
| 0x000012CC | 1 | 01 | AA | standalone | - |
| 0x000012D0 | 1 | 01 | AA | standalone | - |
| 0x000012D4 | 1 | 01 | AA | standalone | - |
| 0x000012D8 | 1 | 01 | AA | standalone | - |
| 0x000012DC | 1 | 01 | AA | standalone | - |
| 0x000012E0 | 1 | 01 | AA | standalone | - |
| 0x000012E4 | 1 | 01 | AA | standalone | - |
| 0x000012E8 | 1 | 01 | AA | standalone | - |
| 0x000012EC | 1 | 01 | AA | standalone | - |
| 0x000012F0 | 1 | 01 | AA | standalone | - |
| 0x000012F4 | 1 | 01 | AA | standalone | - |
| 0x000012F8 | 1 | 01 | AA | standalone | - |
| 0x000012FC | 1 | 01 | AA | standalone | - |
| 0x00001300 | 1 | 01 | AA | standalone | - |
| 0x00001304 | 1 | 01 | AA | standalone | - |
| 0x00001308 | 1 | 01 | AA | standalone | - |
| 0x0000130C | 1 | 01 | AA | standalone | - |
| 0x00001310 | 1 | 01 | AA | standalone | - |
| 0x00001314 | 1 | 01 | AA | standalone | - |
| 0x00001318 | 1 | 01 | AA | standalone | - |
| 0x0000131C | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1001
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1005
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1009
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x100D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1011
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1015
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1019
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x101D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1021
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1025
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1029
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x102D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1031
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1035
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1039
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x103D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1041
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1045
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1049
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x104D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1051
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1055
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1059
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x105D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1061
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1065
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1069
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x106D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1071
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1075
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1079
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x107D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1081
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1085
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1089
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x108D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1091
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1095
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1099
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x109D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10A9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10AD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10B9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10BD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10C9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10CD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10D9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10DD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10E9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10ED
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10F9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x10FD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1101
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1105
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1109
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x110D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1111
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1115
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1119
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x111D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1121
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1125
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1129
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x112D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1131
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1135
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1139
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x113D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1141
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1145
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1149
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x114D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1151
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1155
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1159
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x115D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1161
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1165
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1169
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x116D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1171
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1175
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1179
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x117D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1181
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1185
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1189
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x118D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1191
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1195
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1199
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x119D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11A1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11A5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11A9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11AD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11B1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11B5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11B9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11BD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11C1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11C5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11C9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11CD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11D1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11D5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11D9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11DD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11E1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11E5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11E9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11ED
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11F1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11F5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11F9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x11FD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1201
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1205
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1209
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x120D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1211
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1215
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1219
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x121D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1221
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1225
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1229
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x122D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1231
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1235
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1239
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x123D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1241
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1245
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1249
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x124D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1251
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1255
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1259
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x125D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1261
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1265
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1269
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x126D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1271
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1275
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1279
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x127D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1281
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1285
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1289
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x128D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1291
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1295
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1299
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x129D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12A1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12A5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12A9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12AD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12B1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12B5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12B9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12BD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12C1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12C5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12C9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12CD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12D1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12D5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12D9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12DD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12E1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12E5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12E9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12ED
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12F1
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12F5
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12F9
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x12FD
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1301
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1305
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1309
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x130D
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1311
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1315
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1319
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x131D
> TRUNCATED: 200 of 400 declaration errors omitted (cap: 200 issues per variant).

### Checklists

#### Checklist: `chk_v0.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Addendum: declared regions

### zone 0 (0x1000-0x2000)
- modification @ 0x1000 (variant v0)
- modification @ 0x1004 (variant v0)
- modification @ 0x1008 (variant v0)
- modification @ 0x100C (variant v0)
- modification @ 0x1010 (variant v0)
- modification @ 0x1014 (variant v0)
- modification @ 0x1018 (variant v0)
- modification @ 0x101C (variant v0)
- modification @ 0x1020 (variant v0)
- modification @ 0x1024 (variant v0)
- modification @ 0x1028 (variant v0)
- modification @ 0x102C (variant v0)
- modification @ 0x1030 (variant v0)
- modification @ 0x1034 (variant v0)
- modification @ 0x1038 (variant v0)
- modification @ 0x103C (variant v0)
- modification @ 0x1040 (variant v0)
- modification @ 0x1044 (variant v0)
- modification @ 0x1048 (variant v0)
- modification @ 0x104C (variant v0)
- modification @ 0x1050 (variant v0)
- modification @ 0x1054 (variant v0)
- modification @ 0x1058 (variant v0)
- modification @ 0x105C (variant v0)
- modification @ 0x1060 (variant v0)
- modification @ 0x1064 (variant v0)
- modification @ 0x1068 (variant v0)
- modification @ 0x106C (variant v0)
- modification @ 0x1070 (variant v0)
- modification @ 0x1074 (variant v0)
- modification @ 0x1078 (variant v0)
- modification @ 0x107C (variant v0)
- modification @ 0x1080 (variant v0)
- modification @ 0x1084 (variant v0)
- modification @ 0x1088 (variant v0)
- modification @ 0x108C (variant v0)
- modification @ 0x1090 (variant v0)
- modification @ 0x1094 (variant v0)
- modification @ 0x1098 (variant v0)
- modification @ 0x109C (variant v0)
- modification @ 0x10A0 (variant v0)
- modification @ 0x10A4 (variant v0)
- modification @ 0x10A8 (variant v0)
- modification @ 0x10AC (variant v0)
- modification @ 0x10B0 (variant v0)
- modification @ 0x10B4 (variant v0)
- modification @ 0x10B8 (variant v0)
- modification @ 0x10BC (variant v0)
- modification @ 0x10C0 (variant v0)
- modification @ 0x10C4 (variant v0)
- modification @ 0x10C8 (variant v0)
- modification @ 0x10CC (variant v0)
- modification @ 0x10D0 (variant v0)
- modification @ 0x10D4 (variant v0)
- modification @ 0x10D8 (variant v0)
- modification @ 0x10DC (variant v0)
- modification @ 0x10E0 (variant v0)
- modification @ 0x10E4 (variant v0)
- modification @ 0x10E8 (variant v0)
- modification @ 0x10EC (variant v0)
- modification @ 0x10F0 (variant v0)
- modification @ 0x10F4 (variant v0)
- modification @ 0x10F8 (variant v0)
- modification @ 0x10FC (variant v0)
- modification @ 0x1100 (variant v0)
- modification @ 0x1104 (variant v0)
- modification @ 0x1108 (variant v0)
- modification @ 0x110C (variant v0)
- modification @ 0x1110 (variant v0)
- modification @ 0x1114 (variant v0)
- modification @ 0x1118 (variant v0)
- modification @ 0x111C (variant v0)
- modification @ 0x1120 (variant v0)
- modification @ 0x1124 (variant v0)
- modification @ 0x1128 (variant v0)
- modification @ 0x112C (variant v0)
- modification @ 0x1130 (variant v0)
- modification @ 0x1134 (variant v0)
- modification @ 0x1138 (variant v0)
- modification @ 0x113C (variant v0)
- modification @ 0x1140 (variant v0)
- modification @ 0x1144 (variant v0)
- modification @ 0x1148 (variant v0)
- modification @ 0x114C (variant v0)
- modification @ 0x1150 (variant v0)
- modification @ 0x1154 (variant v0)
- modification @ 0x1158 (variant v0)
- modification @ 0x115C (variant v0)
- modification @ 0x1160 (variant v0)
- modification @ 0x1164 (variant v0)
- modification @ 0x1168 (variant v0)
- modification @ 0x116C (variant v0)
- modification @ 0x1170 (variant v0)
- modification @ 0x1174 (variant v0)
- modification @ 0x1178 (variant v0)
- modification @ 0x117C (variant v0)
- modification @ 0x1180 (variant v0)
- modification @ 0x1184 (variant v0)
- modification @ 0x1188 (variant v0)
- modification @ 0x118C (variant v0)
- modification @ 0x1190 (variant v0)
- modification @ 0x1194 (variant v0)
- modification @ 0x1198 (variant v0)
- modification @ 0x119C (variant v0)
- modification @ 0x11A0 (variant v0)
- modification @ 0x11A4 (variant v0)
- modification @ 0x11A8 (variant v0)
- modification @ 0x11AC (variant v0)
- modification @ 0x11B0 (variant v0)
- modification @ 0x11B4 (variant v0)
- modification @ 0x11B8 (variant v0)
- modification @ 0x11BC (variant v0)
- modification @ 0x11C0 (variant v0)
- modification @ 0x11C4 (variant v0)
- modification @ 0x11C8 (variant v0)
- modification @ 0x11CC (variant v0)
- modification @ 0x11D0 (variant v0)
- modification @ 0x11D4 (variant v0)
- modification @ 0x11D8 (variant v0)
- modification @ 0x11DC (variant v0)
- modification @ 0x11E0 (variant v0)
- modification @ 0x11E4 (variant v0)
- modification @ 0x11E8 (variant v0)
- modification @ 0x11EC (variant v0)
- modification @ 0x11F0 (variant v0)
- modification @ 0x11F4 (variant v0)
- modification @ 0x11F8 (variant v0)
- modification @ 0x11FC (variant v0)
- modification @ 0x1200 (variant v0)
- modification @ 0x1204 (variant v0)
- modification @ 0x1208 (variant v0)
- modification @ 0x120C (variant v0)
- modification @ 0x1210 (variant v0)
- modification @ 0x1214 (variant v0)
- modification @ 0x1218 (variant v0)
- modification @ 0x121C (variant v0)
- modification @ 0x1220 (variant v0)
- modification @ 0x1224 (variant v0)
- modification @ 0x1228 (variant v0)
- modification @ 0x122C (variant v0)
- modification @ 0x1230 (variant v0)
- modification @ 0x1234 (variant v0)
- modification @ 0x1238 (variant v0)
- modification @ 0x123C (variant v0)
- modification @ 0x1240 (variant v0)
- modification @ 0x1244 (variant v0)
- modification @ 0x1248 (variant v0)
- modification @ 0x124C (variant v0)
- modification @ 0x1250 (variant v0)
- modification @ 0x1254 (variant v0)
- modification @ 0x1258 (variant v0)
- modification @ 0x125C (variant v0)
- modification @ 0x1260 (variant v0)
- modification @ 0x1264 (variant v0)
- modification @ 0x1268 (variant v0)
- modification @ 0x126C (variant v0)
- modification @ 0x1270 (variant v0)
- modification @ 0x1274 (variant v0)
- modification @ 0x1278 (variant v0)
- modification @ 0x127C (variant v0)
- modification @ 0x1280 (variant v0)
- modification @ 0x1284 (variant v0)
- modification @ 0x1288 (variant v0)
- modification @ 0x128C (variant v0)
- modification @ 0x1290 (variant v0)
- modification @ 0x1294 (variant v0)
- modification @ 0x1298 (variant v0)
- modification @ 0x129C (variant v0)
- modification @ 0x12A0 (variant v0)
- modification @ 0x12A4 (variant v0)
- modification @ 0x12A8 (variant v0)
- modification @ 0x12AC (variant v0)
- modification @ 0x12B0 (variant v0)
- modification @ 0x12B4 (variant v0)
- modification @ 0x12B8 (variant v0)
- modification @ 0x12BC (variant v0)
- modification @ 0x12C0 (variant v0)
- modification @ 0x12C4 (variant v0)
- modification @ 0x12C8 (variant v0)
- modification @ 0x12CC (variant v0)
- modification @ 0x12D0 (variant v0)
- modification @ 0x12D4 (variant v0)
- modification @ 0x12D8 (variant v0)
- modification @ 0x12DC (variant v0)
- modification @ 0x12E0 (variant v0)
- modification @ 0x12E4 (variant v0)
- modification @ 0x12E8 (variant v0)
- modification @ 0x12EC (variant v0)
- modification @ 0x12F0 (variant v0)
- modification @ 0x12F4 (variant v0)
- modification @ 0x12F8 (variant v0)
- modification @ 0x12FC (variant v0)
- modification @ 0x1300 (variant v0)
- modification @ 0x1304 (variant v0)
- modification @ 0x1308 (variant v0)
- modification @ 0x130C (variant v0)
- modification @ 0x1310 (variant v0)
- modification @ 0x1314 (variant v0)
- modification @ 0x1318 (variant v0)
- modification @ 0x131C (variant v0)
- issue [CHG-SYNTAX] @ 0x1001 (variant v0)
- issue [CHG-SYNTAX] @ 0x1005 (variant v0)
- issue [CHG-SYNTAX] @ 0x1009 (variant v0)
- issue [CHG-SYNTAX] @ 0x100D (variant v0)
- issue [CHG-SYNTAX] @ 0x1011 (variant v0)
- issue [CHG-SYNTAX] @ 0x1015 (variant v0)
- issue [CHG-SYNTAX] @ 0x1019 (variant v0)
- issue [CHG-SYNTAX] @ 0x101D (variant v0)
- issue [CHG-SYNTAX] @ 0x1021 (variant v0)
- issue [CHG-SYNTAX] @ 0x1025 (variant v0)
- issue [CHG-SYNTAX] @ 0x1029 (variant v0)
- issue [CHG-SYNTAX] @ 0x102D (variant v0)
- issue [CHG-SYNTAX] @ 0x1031 (variant v0)
- issue [CHG-SYNTAX] @ 0x1035 (variant v0)
- issue [CHG-SYNTAX] @ 0x1039 (variant v0)
- issue [CHG-SYNTAX] @ 0x103D (variant v0)
- issue [CHG-SYNTAX] @ 0x1041 (variant v0)
- issue [CHG-SYNTAX] @ 0x1045 (variant v0)
- issue [CHG-SYNTAX] @ 0x1049 (variant v0)
- issue [CHG-SYNTAX] @ 0x104D (variant v0)
- issue [CHG-SYNTAX] @ 0x1051 (variant v0)
- issue [CHG-SYNTAX] @ 0x1055 (variant v0)
- issue [CHG-SYNTAX] @ 0x1059 (variant v0)
- issue [CHG-SYNTAX] @ 0x105D (variant v0)
- issue [CHG-SYNTAX] @ 0x1061 (variant v0)
- issue [CHG-SYNTAX] @ 0x1065 (variant v0)
- issue [CHG-SYNTAX] @ 0x1069 (variant v0)
- issue [CHG-SYNTAX] @ 0x106D (variant v0)
- issue [CHG-SYNTAX] @ 0x1071 (variant v0)
- issue [CHG-SYNTAX] @ 0x1075 (variant v0)
- issue [CHG-SYNTAX] @ 0x1079 (variant v0)
- issue [CHG-SYNTAX] @ 0x107D (variant v0)
- issue [CHG-SYNTAX] @ 0x1081 (variant v0)
- issue [CHG-SYNTAX] @ 0x1085 (variant v0)
- issue [CHG-SYNTAX] @ 0x1089 (variant v0)
- issue [CHG-SYNTAX] @ 0x108D (variant v0)
- issue [CHG-SYNTAX] @ 0x1091 (variant v0)
- issue [CHG-SYNTAX] @ 0x1095 (variant v0)
- issue [CHG-SYNTAX] @ 0x1099 (variant v0)
- issue [CHG-SYNTAX] @ 0x109D (variant v0)
- issue [CHG-SYNTAX] @ 0x10A1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10A5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10A9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10AD (variant v0)
- issue [CHG-SYNTAX] @ 0x10B1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10B5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10B9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10BD (variant v0)
- issue [CHG-SYNTAX] @ 0x10C1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10C5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10C9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10CD (variant v0)
- issue [CHG-SYNTAX] @ 0x10D1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10D5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10D9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10DD (variant v0)
- issue [CHG-SYNTAX] @ 0x10E1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10E5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10E9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10ED (variant v0)
- issue [CHG-SYNTAX] @ 0x10F1 (variant v0)
- issue [CHG-SYNTAX] @ 0x10F5 (variant v0)
- issue [CHG-SYNTAX] @ 0x10F9 (variant v0)
- issue [CHG-SYNTAX] @ 0x10FD (variant v0)
- issue [CHG-SYNTAX] @ 0x1101 (variant v0)
- issue [CHG-SYNTAX] @ 0x1105 (variant v0)
- issue [CHG-SYNTAX] @ 0x1109 (variant v0)
- issue [CHG-SYNTAX] @ 0x110D (variant v0)
- issue [CHG-SYNTAX] @ 0x1111 (variant v0)
- issue [CHG-SYNTAX] @ 0x1115 (variant v0)
- issue [CHG-SYNTAX] @ 0x1119 (variant v0)
- issue [CHG-SYNTAX] @ 0x111D (variant v0)
- issue [CHG-SYNTAX] @ 0x1121 (variant v0)
- issue [CHG-SYNTAX] @ 0x1125 (variant v0)
- issue [CHG-SYNTAX] @ 0x1129 (variant v0)
- issue [CHG-SYNTAX] @ 0x112D (variant v0)
- issue [CHG-SYNTAX] @ 0x1131 (variant v0)
- issue [CHG-SYNTAX] @ 0x1135 (variant v0)
- issue [CHG-SYNTAX] @ 0x1139 (variant v0)
- issue [CHG-SYNTAX] @ 0x113D (variant v0)
- issue [CHG-SYNTAX] @ 0x1141 (variant v0)
- issue [CHG-SYNTAX] @ 0x1145 (variant v0)
- issue [CHG-SYNTAX] @ 0x1149 (variant v0)
- issue [CHG-SYNTAX] @ 0x114D (variant v0)
- issue [CHG-SYNTAX] @ 0x1151 (variant v0)
- issue [CHG-SYNTAX] @ 0x1155 (variant v0)
- issue [CHG-SYNTAX] @ 0x1159 (variant v0)
- issue [CHG-SYNTAX] @ 0x115D (variant v0)
- issue [CHG-SYNTAX] @ 0x1161 (variant v0)
- issue [CHG-SYNTAX] @ 0x1165 (variant v0)
- issue [CHG-SYNTAX] @ 0x1169 (variant v0)
- issue [CHG-SYNTAX] @ 0x116D (variant v0)
- issue [CHG-SYNTAX] @ 0x1171 (variant v0)
- issue [CHG-SYNTAX] @ 0x1175 (variant v0)
- issue [CHG-SYNTAX] @ 0x1179 (variant v0)
- issue [CHG-SYNTAX] @ 0x117D (variant v0)
- issue [CHG-SYNTAX] @ 0x1181 (variant v0)
- issue [CHG-SYNTAX] @ 0x1185 (variant v0)
- issue [CHG-SYNTAX] @ 0x1189 (variant v0)
- issue [CHG-SYNTAX] @ 0x118D (variant v0)
- issue [CHG-SYNTAX] @ 0x1191 (variant v0)
- issue [CHG-SYNTAX] @ 0x1195 (variant v0)
- issue [CHG-SYNTAX] @ 0x1199 (variant v0)
- issue [CHG-SYNTAX] @ 0x119D (variant v0)
- issue [CHG-SYNTAX] @ 0x11A1 (variant v0)
- issue [CHG-SYNTAX] @ 0x11A5 (variant v0)
- issue [CHG-SYNTAX] @ 0x11A9 (variant v0)
- issue [CHG-SYNTAX] @ 0x11AD (variant v0)
- issue [CHG-SYNTAX] @ 0x11B1 (variant v0)
- issue [CHG-SYNTAX] @ 0x11B5 (variant v0)
- issue [CHG-SYNTAX] @ 0x11B9 (variant v0)
- issue [CHG-SYNTAX] @ 0x11BD (variant v0)
- issue [CHG-SYNTAX] @ 0x11C1 (variant v0)
- issue [CHG-SYNTAX] @ 0x11C5 (variant v0)
- issue [CHG-SYNTAX] @ 0x11C9 (variant v0)
- issue [CHG-SYNTAX] @ 0x11CD (variant v0)
- issue [CHG-SYNTAX] @ 0x11D1 (variant v0)
- issue [CHG-SYNTAX] @ 0x11D5 (variant v0)
- issue [CHG-SYNTAX] @ 0x11D9 (variant v0)
- issue [CHG-SYNTAX] @ 0x11DD (variant v0)
- issue [CHG-SYNTAX] @ 0x11E1 (variant v0)
- issue [CHG-SYNTAX] @ 0x11E5 (variant v0)
- issue [CHG-SYNTAX] @ 0x11E9 (variant v0)
- issue [CHG-SYNTAX] @ 0x11ED (variant v0)
- issue [CHG-SYNTAX] @ 0x11F1 (variant v0)
- issue [CHG-SYNTAX] @ 0x11F5 (variant v0)
- issue [CHG-SYNTAX] @ 0x11F9 (variant v0)
- issue [CHG-SYNTAX] @ 0x11FD (variant v0)
- issue [CHG-SYNTAX] @ 0x1201 (variant v0)
- issue [CHG-SYNTAX] @ 0x1205 (variant v0)
- issue [CHG-SYNTAX] @ 0x1209 (variant v0)
- issue [CHG-SYNTAX] @ 0x120D (variant v0)
- issue [CHG-SYNTAX] @ 0x1211 (variant v0)
- issue [CHG-SYNTAX] @ 0x1215 (variant v0)
- issue [CHG-SYNTAX] @ 0x1219 (variant v0)
- issue [CHG-SYNTAX] @ 0x121D (variant v0)
- issue [CHG-SYNTAX] @ 0x1221 (variant v0)
- issue [CHG-SYNTAX] @ 0x1225 (variant v0)
- issue [CHG-SYNTAX] @ 0x1229 (variant v0)
- issue [CHG-SYNTAX] @ 0x122D (variant v0)
- issue [CHG-SYNTAX] @ 0x1231 (variant v0)
- issue [CHG-SYNTAX] @ 0x1235 (variant v0)
- issue [CHG-SYNTAX] @ 0x1239 (variant v0)
- issue [CHG-SYNTAX] @ 0x123D (variant v0)
- issue [CHG-SYNTAX] @ 0x1241 (variant v0)
- issue [CHG-SYNTAX] @ 0x1245 (variant v0)
- issue [CHG-SYNTAX] @ 0x1249 (variant v0)
- issue [CHG-SYNTAX] @ 0x124D (variant v0)
- issue [CHG-SYNTAX] @ 0x1251 (variant v0)
- issue [CHG-SYNTAX] @ 0x1255 (variant v0)
- issue [CHG-SYNTAX] @ 0x1259 (variant v0)
- issue [CHG-SYNTAX] @ 0x125D (variant v0)
- issue [CHG-SYNTAX] @ 0x1261 (variant v0)
- issue [CHG-SYNTAX] @ 0x1265 (variant v0)
- issue [CHG-SYNTAX] @ 0x1269 (variant v0)
- issue [CHG-SYNTAX] @ 0x126D (variant v0)
- issue [CHG-SYNTAX] @ 0x1271 (variant v0)
- issue [CHG-SYNTAX] @ 0x1275 (variant v0)
- issue [CHG-SYNTAX] @ 0x1279 (variant v0)
- issue [CHG-SYNTAX] @ 0x127D (variant v0)
- issue [CHG-SYNTAX] @ 0x1281 (variant v0)
- issue [CHG-SYNTAX] @ 0x1285 (variant v0)
- issue [CHG-SYNTAX] @ 0x1289 (variant v0)
- issue [CHG-SYNTAX] @ 0x128D (variant v0)
- issue [CHG-SYNTAX] @ 0x1291 (variant v0)
- issue [CHG-SYNTAX] @ 0x1295 (variant v0)
- issue [CHG-SYNTAX] @ 0x1299 (variant v0)
- issue [CHG-SYNTAX] @ 0x129D (variant v0)
- issue [CHG-SYNTAX] @ 0x12A1 (variant v0)
- issue [CHG-SYNTAX] @ 0x12A5 (variant v0)
- issue [CHG-SYNTAX] @ 0x12A9 (variant v0)
- issue [CHG-SYNTAX] @ 0x12AD (variant v0)
- issue [CHG-SYNTAX] @ 0x12B1 (variant v0)
- issue [CHG-SYNTAX] @ 0x12B5 (variant v0)
- issue [CHG-SYNTAX] @ 0x12B9 (variant v0)
- issue [CHG-SYNTAX] @ 0x12BD (variant v0)
- issue [CHG-SYNTAX] @ 0x12C1 (variant v0)
- issue [CHG-SYNTAX] @ 0x12C5 (variant v0)
- issue [CHG-SYNTAX] @ 0x12C9 (variant v0)
- issue [CHG-SYNTAX] @ 0x12CD (variant v0)
- issue [CHG-SYNTAX] @ 0x12D1 (variant v0)
- issue [CHG-SYNTAX] @ 0x12D5 (variant v0)
- issue [CHG-SYNTAX] @ 0x12D9 (variant v0)
- issue [CHG-SYNTAX] @ 0x12DD (variant v0)
- issue [CHG-SYNTAX] @ 0x12E1 (variant v0)
- issue [CHG-SYNTAX] @ 0x12E5 (variant v0)
- issue [CHG-SYNTAX] @ 0x12E9 (variant v0)
- issue [CHG-SYNTAX] @ 0x12ED (variant v0)
- issue [CHG-SYNTAX] @ 0x12F1 (variant v0)
- issue [CHG-SYNTAX] @ 0x12F5 (variant v0)
- issue [CHG-SYNTAX] @ 0x12F9 (variant v0)
- issue [CHG-SYNTAX] @ 0x12FD (variant v0)
- issue [CHG-SYNTAX] @ 0x1301 (variant v0)
- issue [CHG-SYNTAX] @ 0x1305 (variant v0)
- issue [CHG-SYNTAX] @ 0x1309 (variant v0)
- issue [CHG-SYNTAX] @ 0x130D (variant v0)
- issue [CHG-SYNTAX] @ 0x1311 (variant v0)
- issue [CHG-SYNTAX] @ 0x1315 (variant v0)
- issue [CHG-SYNTAX] @ 0x1319 (variant v0)
- issue [CHG-SYNTAX] @ 0x131D (variant v0)
- issue [CHK-MISMATCH] @ 0x1002 (variant v0)
- issue [CHK-MISMATCH] @ 0x1006 (variant v0)
- issue [CHK-MISMATCH] @ 0x100A (variant v0)
- issue [CHK-MISMATCH] @ 0x100E (variant v0)
- issue [CHK-MISMATCH] @ 0x1012 (variant v0)
- issue [CHK-MISMATCH] @ 0x1016 (variant v0)
- issue [CHK-MISMATCH] @ 0x101A (variant v0)
- issue [CHK-MISMATCH] @ 0x101E (variant v0)
- issue [CHK-MISMATCH] @ 0x1022 (variant v0)
- issue [CHK-MISMATCH] @ 0x1026 (variant v0)
- issue [CHK-MISMATCH] @ 0x102A (variant v0)
- issue [CHK-MISMATCH] @ 0x102E (variant v0)
- issue [CHK-MISMATCH] @ 0x1032 (variant v0)
- issue [CHK-MISMATCH] @ 0x1036 (variant v0)
- issue [CHK-MISMATCH] @ 0x103A (variant v0)
- issue [CHK-MISMATCH] @ 0x103E (variant v0)
- issue [CHK-MISMATCH] @ 0x1042 (variant v0)
- issue [CHK-MISMATCH] @ 0x1046 (variant v0)
- issue [CHK-MISMATCH] @ 0x104A (variant v0)
- issue [CHK-MISMATCH] @ 0x104E (variant v0)
- issue [CHK-MISMATCH] @ 0x1052 (variant v0)
- issue [CHK-MISMATCH] @ 0x1056 (variant v0)
- issue [CHK-MISMATCH] @ 0x105A (variant v0)
- issue [CHK-MISMATCH] @ 0x105E (variant v0)
- issue [CHK-MISMATCH] @ 0x1062 (variant v0)
- issue [CHK-MISMATCH] @ 0x1066 (variant v0)
- issue [CHK-MISMATCH] @ 0x106A (variant v0)
- issue [CHK-MISMATCH] @ 0x106E (variant v0)
- issue [CHK-MISMATCH] @ 0x1072 (variant v0)
- issue [CHK-MISMATCH] @ 0x1076 (variant v0)
- issue [CHK-MISMATCH] @ 0x107A (variant v0)
- issue [CHK-MISMATCH] @ 0x107E (variant v0)
- issue [CHK-MISMATCH] @ 0x1082 (variant v0)
- issue [CHK-MISMATCH] @ 0x1086 (variant v0)
- issue [CHK-MISMATCH] @ 0x108A (variant v0)
- issue [CHK-MISMATCH] @ 0x108E (variant v0)
- issue [CHK-MISMATCH] @ 0x1092 (variant v0)
- issue [CHK-MISMATCH] @ 0x1096 (variant v0)
- issue [CHK-MISMATCH] @ 0x109A (variant v0)
- issue [CHK-MISMATCH] @ 0x109E (variant v0)
- issue [CHK-MISMATCH] @ 0x10A2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10A6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10AA (variant v0)
- issue [CHK-MISMATCH] @ 0x10AE (variant v0)
- issue [CHK-MISMATCH] @ 0x10B2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10B6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10BA (variant v0)
- issue [CHK-MISMATCH] @ 0x10BE (variant v0)
- issue [CHK-MISMATCH] @ 0x10C2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10C6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10CA (variant v0)
- issue [CHK-MISMATCH] @ 0x10CE (variant v0)
- issue [CHK-MISMATCH] @ 0x10D2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10D6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10DA (variant v0)
- issue [CHK-MISMATCH] @ 0x10DE (variant v0)
- issue [CHK-MISMATCH] @ 0x10E2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10E6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10EA (variant v0)
- issue [CHK-MISMATCH] @ 0x10EE (variant v0)
- issue [CHK-MISMATCH] @ 0x10F2 (variant v0)
- issue [CHK-MISMATCH] @ 0x10F6 (variant v0)
- issue [CHK-MISMATCH] @ 0x10FA (variant v0)
- issue [CHK-MISMATCH] @ 0x10FE (variant v0)
- issue [CHK-MISMATCH] @ 0x1102 (variant v0)
- issue [CHK-MISMATCH] @ 0x1106 (variant v0)
- issue [CHK-MISMATCH] @ 0x110A (variant v0)
- issue [CHK-MISMATCH] @ 0x110E (variant v0)
- issue [CHK-MISMATCH] @ 0x1112 (variant v0)
- issue [CHK-MISMATCH] @ 0x1116 (variant v0)
- issue [CHK-MISMATCH] @ 0x111A (variant v0)
- issue [CHK-MISMATCH] @ 0x111E (variant v0)
- issue [CHK-MISMATCH] @ 0x1122 (variant v0)
- issue [CHK-MISMATCH] @ 0x1126 (variant v0)
- issue [CHK-MISMATCH] @ 0x112A (variant v0)
- issue [CHK-MISMATCH] @ 0x112E (variant v0)
- issue [CHK-MISMATCH] @ 0x1132 (variant v0)
- issue [CHK-MISMATCH] @ 0x1136 (variant v0)
- issue [CHK-MISMATCH] @ 0x113A (variant v0)
- issue [CHK-MISMATCH] @ 0x113E (variant v0)
- issue [CHK-MISMATCH] @ 0x1142 (variant v0)
- issue [CHK-MISMATCH] @ 0x1146 (variant v0)
- issue [CHK-MISMATCH] @ 0x114A (variant v0)
- issue [CHK-MISMATCH] @ 0x114E (variant v0)
- issue [CHK-MISMATCH] @ 0x1152 (variant v0)
- issue [CHK-MISMATCH] @ 0x1156 (variant v0)
- issue [CHK-MISMATCH] @ 0x115A (variant v0)
- issue [CHK-MISMATCH] @ 0x115E (variant v0)
- issue [CHK-MISMATCH] @ 0x1162 (variant v0)
- issue [CHK-MISMATCH] @ 0x1166 (variant v0)
- issue [CHK-MISMATCH] @ 0x116A (variant v0)
- issue [CHK-MISMATCH] @ 0x116E (variant v0)
- issue [CHK-MISMATCH] @ 0x1172 (variant v0)
- issue [CHK-MISMATCH] @ 0x1176 (variant v0)
- issue [CHK-MISMATCH] @ 0x117A (variant v0)
- issue [CHK-MISMATCH] @ 0x117E (variant v0)
- issue [CHK-MISMATCH] @ 0x1182 (variant v0)
- issue [CHK-MISMATCH] @ 0x1186 (variant v0)
- issue [CHK-MISMATCH] @ 0x118A (variant v0)
- issue [CHK-MISMATCH] @ 0x118E (variant v0)
- issue [CHK-MISMATCH] @ 0x1192 (variant v0)
- issue [CHK-MISMATCH] @ 0x1196 (variant v0)
- issue [CHK-MISMATCH] @ 0x119A (variant v0)
- issue [CHK-MISMATCH] @ 0x119E (variant v0)
- issue [CHK-MISMATCH] @ 0x11A2 (variant v0)
- issue [CHK-MISMATCH] @ 0x11A6 (variant v0)
- issue [CHK-MISMATCH] @ 0x11AA (variant v0)
- issue [CHK-MISMATCH] @ 0x11AE (variant v0)
- issue [CHK-MISMATCH] @ 0x11B2 (variant v0)
- issue [CHK-MISMATCH] @ 0x11B6 (variant v0)
- issue [CHK-MISMATCH] @ 0x11BA (variant v0)
- issue [CHK-MISMATCH] @ 0x11BE (variant v0)
- issue [CHK-MISMATCH] @ 0x11C2 (variant v0)
- issue [CHK-MISMATCH] @ 0x11C6 (variant v0)
- issue [CHK-MISMATCH] @ 0x11CA (variant v0)
- issue [CHK-MISMATCH] @ 0x11CE (variant v0)
- issue [CHK-MISMATCH] @ 0x11D2 (variant v0)
- issue [CHK-MISMATCH] @ 0x11D6 (variant v0)
- issue [CHK-MISMATCH] @ 0x11DA (variant v0)
- issue [CHK-MISMATCH] @ 0x11DE (variant v0)
- issue [CHK-MISMATCH] @ 0x11E2 (variant v0)
- issue [CHK-MISMATCH] @ 0x11E6 (variant v0)
- issue [CHK-MISMATCH] @ 0x11EA (variant v0)
- issue [CHK-MISMATCH] @ 0x11EE (variant v0)
- issue [CHK-MISMATCH] @ 0x11F2 (variant v0)
- issue [CHK-MISMATCH] @ 0x11F6 (variant v0)
- issue [CHK-MISMATCH] @ 0x11FA (variant v0)
- issue [CHK-MISMATCH] @ 0x11FE (variant v0)
- issue [CHK-MISMATCH] @ 0x1202 (variant v0)
- issue [CHK-MISMATCH] @ 0x1206 (variant v0)
- issue [CHK-MISMATCH] @ 0x120A (variant v0)
- issue [CHK-MISMATCH] @ 0x120E (variant v0)
- issue [CHK-MISMATCH] @ 0x1212 (variant v0)
- issue [CHK-MISMATCH] @ 0x1216 (variant v0)
- issue [CHK-MISMATCH] @ 0x121A (variant v0)
- issue [CHK-MISMATCH] @ 0x121E (variant v0)
- issue [CHK-MISMATCH] @ 0x1222 (variant v0)
- issue [CHK-MISMATCH] @ 0x1226 (variant v0)
- issue [CHK-MISMATCH] @ 0x122A (variant v0)
- issue [CHK-MISMATCH] @ 0x122E (variant v0)
- issue [CHK-MISMATCH] @ 0x1232 (variant v0)
- issue [CHK-MISMATCH] @ 0x1236 (variant v0)
- issue [CHK-MISMATCH] @ 0x123A (variant v0)
- issue [CHK-MISMATCH] @ 0x123E (variant v0)
- issue [CHK-MISMATCH] @ 0x1242 (variant v0)
- issue [CHK-MISMATCH] @ 0x1246 (variant v0)
- issue [CHK-MISMATCH] @ 0x124A (variant v0)
- issue [CHK-MISMATCH] @ 0x124E (variant v0)
- issue [CHK-MISMATCH] @ 0x1252 (variant v0)
- issue [CHK-MISMATCH] @ 0x1256 (variant v0)
- issue [CHK-MISMATCH] @ 0x125A (variant v0)
- issue [CHK-MISMATCH] @ 0x125E (variant v0)
- issue [CHK-MISMATCH] @ 0x1262 (variant v0)
- issue [CHK-MISMATCH] @ 0x1266 (variant v0)
- issue [CHK-MISMATCH] @ 0x126A (variant v0)
- issue [CHK-MISMATCH] @ 0x126E (variant v0)
- issue [CHK-MISMATCH] @ 0x1272 (variant v0)
- issue [CHK-MISMATCH] @ 0x1276 (variant v0)
- issue [CHK-MISMATCH] @ 0x127A (variant v0)
- issue [CHK-MISMATCH] @ 0x127E (variant v0)
- issue [CHK-MISMATCH] @ 0x1282 (variant v0)
- issue [CHK-MISMATCH] @ 0x1286 (variant v0)
- issue [CHK-MISMATCH] @ 0x128A (variant v0)
- issue [CHK-MISMATCH] @ 0x128E (variant v0)
- issue [CHK-MISMATCH] @ 0x1292 (variant v0)
- issue [CHK-MISMATCH] @ 0x1296 (variant v0)
- issue [CHK-MISMATCH] @ 0x129A (variant v0)
- issue [CHK-MISMATCH] @ 0x129E (variant v0)
- issue [CHK-MISMATCH] @ 0x12A2 (variant v0)
- issue [CHK-MISMATCH] @ 0x12A6 (variant v0)
- issue [CHK-MISMATCH] @ 0x12AA (variant v0)
- issue [CHK-MISMATCH] @ 0x12AE (variant v0)
- issue [CHK-MISMATCH] @ 0x12B2 (variant v0)
- issue [CHK-MISMATCH] @ 0x12B6 (variant v0)
- issue [CHK-MISMATCH] @ 0x12BA (variant v0)
- issue [CHK-MISMATCH] @ 0x12BE (variant v0)
- issue [CHK-MISMATCH] @ 0x12C2 (variant v0)
- issue [CHK-MISMATCH] @ 0x12C6 (variant v0)
- issue [CHK-MISMATCH] @ 0x12CA (variant v0)
- issue [CHK-MISMATCH] @ 0x12CE (variant v0)
- issue [CHK-MISMATCH] @ 0x12D2 (variant v0)
- issue [CHK-MISMATCH] @ 0x12D6 (variant v0)
- issue [CHK-MISMATCH] @ 0x12DA (variant v0)
- issue [CHK-MISMATCH] @ 0x12DE (variant v0)
- issue [CHK-MISMATCH] @ 0x12E2 (variant v0)
- issue [CHK-MISMATCH] @ 0x12E6 (variant v0)
- issue [CHK-MISMATCH] @ 0x12EA (variant v0)
- issue [CHK-MISMATCH] @ 0x12EE (variant v0)
- issue [CHK-MISMATCH] @ 0x12F2 (variant v0)
- issue [CHK-MISMATCH] @ 0x12F6 (variant v0)
- issue [CHK-MISMATCH] @ 0x12FA (variant v0)
- issue [CHK-MISMATCH] @ 0x12FE (variant v0)
- issue [CHK-MISMATCH] @ 0x1302 (variant v0)
- issue [CHK-MISMATCH] @ 0x1306 (variant v0)
- issue [CHK-MISMATCH] @ 0x130A (variant v0)
- issue [CHK-MISMATCH] @ 0x130E (variant v0)
- issue [CHK-MISMATCH] @ 0x1312 (variant v0)
- issue [CHK-MISMATCH] @ 0x1316 (variant v0)
- issue [CHK-MISMATCH] @ 0x131A (variant v0)
- issue [CHK-MISMATCH] @ 0x131E (variant v0)
<!-- s19tool-golden-shape: FIXGOLD -->
# Project report: proj

- Project: proj
- Generated (UTC): 2026-07-27T12:00:00+00:00
- Tool version: 0.1.0
- Context bytes: 64
- Execution mode: batch
- Assignment source: default

## Variant inventory

| Variant | File | Type | Active |
|---|---|---|---|
| variant\_a | variant\_a\.s19 | s19 | yes |
| v-2\.1 | v-2\.1\.s19 | s19 | no |

## Consolidated overview

| Variant | Status | Changes applied | Checks passed | Checks failed | Checks uncheckable |
|---|---|---|---|---|---|
| variant\_a | ok | 3 | 0 | 0 | 0 |
| v-2\.1 | ok | 3 | 0 | 0 | 0 |

## Legend

### A2L
- **Red** — schema/structural failure: malformed required field, invalid required reference, or hard-error duplicate symbol
- **Green** — memory checked — tag/range fully found in the loaded S19/HEX image
- **White** — valid A2L record with no hard inconsistency, including valid records not present in the image
- **Grey** — memory not checked yet, or no primary S19/HEX context loaded

### MAC
- **Red** — parse failed, invalid/missing name or hex address, or A2L↔MAC same-name address mismatch
- **Pale yellow** — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity
- **Green** — exact name + address match with A2L
- **White** — structurally valid MAC entry, no hard inconsistency, not positively cross-confirmed
- **Grey** — no A2L loaded, or validation context missing

### Issues
- **Errors** (Red) — parse/structure errors, empty name, invalid/missing address, duplicate symbol, broken GROUP/FUNCTION references, or A2L↔MAC same-name mismatch
- **Warnings** (Pale yellow) — address/range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias
- **Optional info** (Cyan) — valid-but-not-image-backed, not-checked-without-primary-image, or virtual/dependent non-memory-backed objects

### Hex
- **Yellow** — search / goto-focus highlight: the byte span matched by the last in-memory search or goto-address jump in the hex view
- **Orange3** — MAC address overlay: a hex byte at an address referenced by a loaded MAC record

## Variant: variant\_a

### Modified files

- `chg_0_0.json` (applied entries: 2)
- `chg_0_1.json` (applied entries: 1)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00002000 | 1 | 01 | AA | standalone | - |
| 0x00003000 | 1 | 01 | AA | standalone | - |
| 0x00005000 | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-COLLISION] error: CHG-COLLISION synthetic message @ 0x2010
- [CHG \> TRUNCATED] error: CHG \> TRUNCATED synthetic message @ 0x2011
- [CHG-NULL] error: CHG-NULL synthetic message
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1800
- [CHK-FAIL] error: CHK-FAIL synthetic message @ 0x2000

### Checklists

#### Checklist: `chk_0.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Variant: v-2\.1

### Modified files

- `chg_1_0.json` (applied entries: 2)
- `chg_1_1.json` (applied entries: 1)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x00002001 | 1 | 01 | AA | standalone | - |
| 0x00003000 | 1 | 01 | AA | standalone | - |
| 0x00005001 | 1 | 01 | AA | standalone | - |

### Declaration errors

- [CHG-COLLISION] error: CHG-COLLISION synthetic message @ 0x2010
- [CHG \> TRUNCATED] error: CHG \> TRUNCATED synthetic message @ 0x2011
- [CHG-NULL] error: CHG-NULL synthetic message
- [CHG-SYNTAX] error: CHG-SYNTAX synthetic message @ 0x1800
- [CHK-FAIL] error: CHK-FAIL synthetic message @ 0x2000

### Checklists

#### Checklist: `chk_1.json`

Passed: 0 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Addendum: declared regions

### outer zone (0x1000-0x9000)
- modification @ 0x2000 (variant variant\_a)
- modification @ 0x3000 (variant variant\_a)
- issue [CHG-COLLISION] @ 0x2010 (variant variant\_a)
- issue [CHG \> TRUNCATED] @ 0x2011 (variant variant\_a)
- modification @ 0x5000 (variant variant\_a)
- issue [CHG-SYNTAX] @ 0x1800 (variant variant\_a)
- issue [CHK-FAIL] @ 0x2000 (variant variant\_a)
- modification @ 0x2001 (variant v-2\.1)
- modification @ 0x3000 (variant v-2\.1)
- issue [CHG-COLLISION] @ 0x2010 (variant v-2\.1)
- issue [CHG \> TRUNCATED] @ 0x2011 (variant v-2\.1)
- modification @ 0x5001 (variant v-2\.1)
- issue [CHG-SYNTAX] @ 0x1800 (variant v-2\.1)
- issue [CHK-FAIL] @ 0x2000 (variant v-2\.1)

### inner zone (0x2000-0x2010)
- modification @ 0x2000 (variant variant\_a)
- issue [CHG-COLLISION] @ 0x2010 (variant variant\_a)
- issue [CHK-FAIL] @ 0x2000 (variant variant\_a)
- modification @ 0x2001 (variant v-2\.1)
- issue [CHG-COLLISION] @ 0x2010 (variant v-2\.1)
- issue [CHK-FAIL] @ 0x2000 (variant v-2\.1)

### edge zone (0x3000-0x3000)
- modification @ 0x3000 (variant variant\_a)
- modification @ 0x3000 (variant v-2\.1)

### empty zone (0xF000-0xF0FF)
None.
