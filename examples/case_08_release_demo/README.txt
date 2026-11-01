Case 08: Synthetic release demo (deterministic, fully generated).
Every byte is produced locally by tools/synth/make_release_case.py - no
real firmware, no downloads, no names, no PKI.

What this case exercises:
  - A ~10 MiB S19 image: boot + application + calibration + config/ID
    regions separated by gaps, with pseudo-code, 0xFF erased runs, 0x00
    runs, structured calibration tables, and an ASCII ID/version block.
  - firmware.hex is the SAME image as Intel HEX (identical compare pair).
  - firmware_v2.s19 differs only in a 512-byte changed window inside
    the calibration region and a 4096-byte extension of that region.
  - firmware.a2l: 358 CHARACTERISTICs and 104 MEASUREMENTs, COMPU_METHODs
    of every decoded kind (IDENTICAL, LINEAR, RAT_FUNC, TAB_INTP, TAB_NOINTP;
    TAB_INTP/TAB_NOINTP reference a COMPU_TAB/COMPU_VTAB, the latter declared
    with the TAB_VERB keyword) - 104 objects use a table conversion.
    Arrays: 60 CURVE, 20 MAP (both with AXIS_DESCR, in-image),
    60 VAL_BLK, 10 ASCII.
  - firmware.mac: 200 clean NAME=0xADDRESS lines matching A2L objects.
  - demo_patch.changes.json: 7-entry v2 change document (bytes, string, and
    bytes+symbol entry kinds) with visible changes in cal + config regions.
  - demo_check.chk.json / demo_check_fails.chk.json: one entry per check kind;
    the first all-PASS, the second all-FAIL on the clean image.
  - firmware_issues.a2l / firmware_issues.mac: the clean files plus injected
    faults (outside image, span-over, duplicate, missing compu method,
    value-out-of-limits, absent names, bad hex, no '=') for the Issues window.

Layout:
  boot   0x00000000  size 0x010000
  app    0x00040000  size 0x2C9FA0
  cal    0x00800000  size 0x131FC0
  config 0x00C00000  size 0x001000
  v2 changed window: 0x008E57D0 .. 0x008E59CF
  v2 extension:      0x00931FC0 .. 0x00932FBF

Seed: 20260001
Regeneration command:
  python tools/synth/make_release_case.py --out examples/case_08_release_demo --seed 20260001 --size-mb 10
