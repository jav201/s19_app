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

## Consolidated overview

| Variant | Status | Changes applied | Checks passed | Checks failed | Checks uncheckable |
|---|---|---|---|---|---|
| v0 | ok | 5 | 4 | 0 | 0 |
| v1 | ok | 5 | 4 | 0 | 0 |

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

- `chg.json` (applied entries: 5)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x80000000 | 1 | 10 | A0 | standalone | - |
| 0x80000010 | 2 | 10 11 | A0 A1 | a2l | SYM\_0\_1 |
| 0x80000020 | 3 | 10 11 12 | A0 A1 A2 | standalone | - |
| 0x80000030 | 4 | 10 11 12 13 | A0 A1 A2 A3 | a2l | SYM\_0\_3 |
| 0x80000040 | 1 | 10 | A0 | standalone | - |

### Declaration errors

None.

### Checklists

#### Checklist: `chk.json`

Passed: 4 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|
| 0x90000000 | 1 | 20 | 20 | pass |
| 0x90000010 | 2 | 20 21 | 20 21 | pass |
| 0x90000020 | 3 | 20 21 22 | 20 21 22 | pass |
| 0x90000030 | 1 | 20 | 20 | pass |

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.

## Variant: v1

### Modified files

- `chg.json` (applied entries: 5)

### Modifications

| Address | Length | Before | After | Linkage | Symbol |
|---|---|---|---|---|---|
| 0x80001000 | 1 | 10 | A0 | standalone | - |
| 0x80001010 | 2 | 10 11 | A0 A1 | a2l | SYM\_1\_1 |
| 0x80001020 | 3 | 10 11 12 | A0 A1 A2 | standalone | - |
| 0x80001030 | 4 | 10 11 12 13 | A0 A1 A2 A3 | a2l | SYM\_1\_3 |
| 0x80001040 | 1 | 10 | A0 | standalone | - |

### Declaration errors

None.

### Checklists

#### Checklist: `chk.json`

Passed: 4 - Failed: 0 - Uncheckable: 0

| Address | Length | Expected | Actual | Result |
|---|---|---|---|---|
| 0x90001000 | 1 | 20 | 20 | pass |
| 0x90001010 | 2 | 20 21 | 20 21 | pass |
| 0x90001020 | 3 | 20 21 22 | 20 21 22 | pass |
| 0x90001030 | 1 | 20 | 20 | pass |

### Memory regions

Post-change memory map unavailable - hexdumps omitted.

### Entropy

No mapped bytes - entropy not computed.
