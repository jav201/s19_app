# Synthetic S19 / A2L / MAC Validation Suite

This suite was generated to stress-test S19Tool and related parsers.

## Cases
1. **case_01_basic_valid**  
   Small valid dataset. Good for smoke tests.

2. **case_02_gaps_and_patch_targets**  
   Multiple used ranges with gaps. Includes string and hex patch targets.

3. **case_03_overlapping_records**  
   Intentional record overlap. Useful to test verify and patch protection.

4. **case_04_bad_checksums**  
   One corrupted S-record checksum. Useful to test checksum verification.

5. **case_05_dense_mixed_content**  
   Mixed ASCII and raw bytes. Good for patch-str and patch-hex.

6. **case_06_large_nested_a2l**  
   Large nested A2L (~35 MB). Designed to stress parsing, indexing, and memory use.

## Notes
- Files are synthetic and not tied to any OEM, ECU, or vendor.
- `.mac` files are simple symbol listings intended to mimic symbol-address mapping.
- `.a2l` files are ASAM-like and deliberately varied; they are not guaranteed to satisfy every commercial parser, but they are suitable for stress and structure testing.
