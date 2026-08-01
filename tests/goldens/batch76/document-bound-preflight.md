# Project report: proj

- Project: proj
- Generated (UTC): 2026-07-31T12:00:00+00:00
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
| v0 | ok | 4 | 2 | 2 | 0 |
| v1 | ok | 4 | 2 | 2 | 0 |
| v2 | ok | 4 | 2 | 2 | 0 |

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

- `chg.json` (applied entries: 4)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x80000000 | 1 | 10 | A0 | standalone | - |
| 0x80000010 | 2 | 10 11 | A0 A1 | a2l | SYM\_0\_1 |
| 0x80000020 | 3 | 10 11 12 | A0 A1 A2 | standalone | - |
| 0x80000030 | 4 | 10 11 12 13 | A0 A1 A2 A3 | a2l | SYM\_0\_3 |
| 0x80000040 | 1 | 10 | A0 | standalone | - |
| 0x80000050 | 2 | 10 11 | A0 A1 | a2l | SYM\_0\_5 |

### Declaration errors

None.

### Checklists

#### Checklist: `chk.json`

Passed: 2 - Failed: 2 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|
| 0x90000000 | 1 | 20 | 20 | fail |
| 0x90000010 | 2 | 20 21 | 20 21 | pass |
| 0x90000020 | 3 | 20 21 22 | 20 21 22 | fail |
| 0x90000030 | 1 | 20 | 20 | pass |

### Memory regions

Window 0x7FFFFFD0-0x80000080:

```text
0x7FFFFFD0                                                   |................|
0x7FFFFFE0                                                   |................|
0x7FFFFFF0                                                   |................|
0x80000000  00 07 0E 15 1C 23 2A 31 38 3F 46 4D 54 5B 62 69  |.....#*18?FMT[bi|
0x80000010  70 77 7E 85 8C 93 9A A1 A8 AF B6 BD C4 CB D2 D9  |pw~.............|
0x80000020  E0 E7 EE F5 FC 03 0A 11 18 1F 26 2D 34 3B 42 49  |..........&-4;BI|
0x80000030  50 57 5E 65 6C 73 7A 81 88 8F 96 9D A4 AB B2 B9  |PW^elsz.........|
0x80000040  C0 C7 CE D5 DC E3 EA F1 F8 FF 06 0D 14 1B 22 29  |..............")|
0x80000050  30 37 3E 45 4C 53 5A 61 68 6F 76 7D 84 8B 92 99  |07>ELSZahov}....|
0x80000060  A0 A7 AE B5 BC C3 CA D1 D8 DF E6 ED F4 FB 02 09  |................|
0x80000070  10 17 1E 25 2C 33 3A 41 48 4F 56 5D 64 6B 72 79  |...%,3:AHOV]dkry|
```

### Entropy

- **medium**: 1 window(s)

## Variant: v1

### Modified files

- `chg.json` (applied entries: 4)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x80001000 | 1 | 10 | A0 | standalone | - |
| 0x80001010 | 2 | 10 11 | A0 A1 | a2l | SYM\_1\_1 |
| 0x80001020 | 3 | 10 11 12 | A0 A1 A2 | standalone | - |
| 0x80001030 | 4 | 10 11 12 13 | A0 A1 A2 A3 | a2l | SYM\_1\_3 |
| 0x80001040 | 1 | 10 | A0 | standalone | - |
| 0x80001050 | 2 | 10 11 | A0 A1 | a2l | SYM\_1\_5 |

### Declaration errors

None.

### Checklists

#### Checklist: `chk.json`

Passed: 2 - Failed: 2 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|
| 0x90001000 | 1 | 20 | 20 | fail |
| 0x90001010 | 2 | 20 21 | 20 21 | pass |
| 0x90001020 | 3 | 20 21 22 | 20 21 22 | fail |
| 0x90001030 | 1 | 20 | 20 | pass |

### Memory regions

Window 0x80000FD0-0x80001080:

```text
0x80000FD0                                                   |................|
0x80000FE0                                                   |................|
0x80000FF0                                                   |................|
0x80001000  01 08 0F 16 1D 24 2B 32 39 40 47 4E 55 5C 63 6A  |.....$+29@GNU\cj|
0x80001010  71 78 7F 86 8D 94 9B A2 A9 B0 B7 BE C5 CC D3 DA  |qx..............|
0x80001020  E1 E8 EF F6 FD 04 0B 12 19 20 27 2E 35 3C 43 4A  |......... '.5<CJ|
0x80001030  51 58 5F 66 6D 74 7B 82 89 90 97 9E A5 AC B3 BA  |QX_fmt{.........|
0x80001040  C1 C8 CF D6 DD E4 EB F2 F9 00 07 0E 15 1C 23 2A  |..............#*|
0x80001050  31 38 3F 46 4D 54 5B 62 69 70 77 7E 85 8C 93 9A  |18?FMT[bipw~....|
0x80001060  A1 A8 AF B6 BD C4 CB D2 D9 E0 E7 EE F5 FC 03 0A  |................|
0x80001070  11 18 1F 26 2D 34 3B 42 49 50 57 5E 65 6C 73 7A  |...&-4;BIPW^elsz|
```

### Entropy

- **medium**: 1 window(s)

## Variant: v2

### Modified files

- `chg.json` (applied entries: 4)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x80002000 | 1 | 10 | A0 | standalone | - |
| 0x80002010 | 2 | 10 11 | A0 A1 | a2l | SYM\_2\_1 |
| 0x80002020 | 3 | 10 11 12 | A0 A1 A2 | standalone | - |
| 0x80002030 | 4 | 10 11 12 13 | A0 A1 A2 A3 | a2l | SYM\_2\_3 |
| 0x80002040 | 1 | 10 | A0 | standalone | - |
| 0x80002050 | 2 | 10 11 | A0 A1 | a2l | SYM\_2\_5 |

### Declaration errors

None.

### Checklists

#### Checklist: `chk.json`

Passed: 2 - Failed: 2 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|
| 0x90002000 | 1 | 20 | 20 | fail |
| 0x90002010 | 2 | 20 21 | 20 21 | pass |
| 0x90002020 | 3 | 20 21 22 | 20 21 22 | fail |
| 0x90002030 | 1 | 20 | 20 | pass |

### Memory regions

Window 0x80001FD0-0x80002080:

```text
0x80001FD0                                                   |................|
0x80001FE0                                                   |................|
0x80001FF0                                                   |................|
0x80002000  02 09 10 17 1E 25 2C 33 3A 41 48 4F 56 5D 64 6B  |.....%,3:AHOV]dk|
0x80002010  72 79 80 87 8E 95 9C A3 AA B1 B8 BF C6 CD D4 DB  |ry..............|
0x80002020  E2 E9 F0 F7 FE 05 0C 13 1A 21 28 2F 36 3D 44 4B  |.........!(/6=DK|
0x80002030  52 59 60 67 6E 75 7C 83 8A 91 98 9F A6 AD B4 BB  |RY`gnu|.........|
0x80002040  C2 C9 D0 D7 DE E5 EC F3 FA 01 08 0F 16 1D 24 2B  |..............$+|
0x80002050  32 39 40 47 4E 55 5C 63 6A 71 78 7F 86 8D 94 9B  |29@GNU\cjqx.....|
0x80002060  A2 A9 B0 B7 BE C5 CC D3 DA E1 E8 EF F6 FD 04 0B  |................|
0x80002070  12 19 20 27 2E 35 3C 43 4A 51 58 5F 66 6D 74 7B  |.. '.5<CJQX_fmt{|
```

### Entropy

- **medium**: 1 window(s)
