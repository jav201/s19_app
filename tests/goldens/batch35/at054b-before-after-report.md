# Diff report

- Generated (UTC): 2026-07-10T12:00:00+00:00
- Tool version: 0.1.0
- Image A: img.s19 [external] path=`<RUN-ROOT>/img.s19` parse-errors=0
- Image B: img-patched.s19 [external] path=`<RUN-ROOT>/.s19tool/workarea/proj/img-patched.s19` parse-errors=0
- Image A artifacts: summary=none; a2l=absent; mac=absent
- Image B artifacts: summary=none; a2l=absent; mac=absent

## Before/after provenance

- Original image (before): `<RUN-ROOT>/img.s19`
- Saved patched image (after): `<RUN-ROOT>/.s19tool/workarea/proj/img-patched.s19`
- Applied (UTC): 2026-07-10T12:00:00+00:00
- Change document: (in-memory document)

## Change-entry linkage

| # | Type | Start | End | Disposition | Linkage | Symbol | Before | After |
|---|---|---|---|---|---|---|---|---|
| 1 | bytes | 0x00000100 | 0x00000102 | applied | standalone | - | 00 00 \|..\| | AA BB \|..\| |

## Statistics

| Classification | Runs | Bytes |
|---|---|---|
| changed | 1 | 2 |
| only in A | 0 | 0 |
| only in B | 0 | 0 |

## Runs

| Start | End | Length | Classification | Symbols |
|---|---|---|---|---|
| 0x00000100 | 0x00000102 | 2 | changed | - |

## Hex windows

### Run 0x00000100-0x00000102 (changed)

```diff
-0x000000C0                                                   |................|
-0x000000D0                                                   |................|
-0x000000E0                                                   |................|
-0x000000F0                                                   |................|
-0x00000100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
+0x000000C0                                                   |................|
+0x000000D0                                                   |................|
+0x000000E0                                                   |................|
+0x000000F0                                                   |................|
+0x00000100  AA BB 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```

Image A window 0x000000C0-0x00000110:

```text
0x000000C0                                                   |................|
0x000000D0                                                   |................|
0x000000E0                                                   |................|
0x000000F0                                                   |................|
0x00000100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```

Image B window 0x000000C0-0x00000110:

```text
0x000000C0                                                   |................|
0x000000D0                                                   |................|
0x000000E0                                                   |................|
0x000000F0                                                   |................|
0x00000100  AA BB 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```
