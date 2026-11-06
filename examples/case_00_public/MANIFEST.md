# Synthetic S19 / A2L / MAC Validation Suite

This suite was generated to stress-test `s19_app` and related parsers.

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

7. **case_07_stress_smoke**  
   Small S19/A2L/MAC stress-smoke triple (relocated from `tmp/stress_smoke/` in
   batch-36). Quick parser-and-service smoke case.

8. **case_08_release_demo**  
   Deterministic, fully generated release demo (~10 MiB S19 image, an identical
   Intel HEX pair, A2L/MAC, patch and check documents). Only `README.txt` is
   tracked; generate the files with
   `python tools/synth/make_release_case.py --out examples/case_08_release_demo`.

## Professional validation cases

1. **professional_validation/case_01_baseline_valid**  
   Clean baseline; verify passes with no errors or overlaps.

2. **professional_validation/case_02_patch_targets_and_gaps**  
   Patch-str / patch-hex targets with visible gaps.

3. **professional_validation/case_03_overlapping_records**  
   Intentional overlap; verify reports it and patching overlapped addresses fails.

4. **professional_validation/case_04_bad_checksums**  
   Corrupt checksums; verify fails checksum validation.

5. **professional_validation/case_05_out_of_order_and_mixed**  
   Out-of-order records with mixed content; parser and dump-by-range robustness.

6. **professional_validation/case_07_cross_reference_inconsistencies**  
   Intentional S19/MAC/A2L cross-reference inconsistencies for cross-artefact validation.

7. **professional_validation/case_08_heavy_fragmentation**  
   Heavy fragmentation; ranges, gaps, dump-by-range and performance.

## Notes
- Files are synthetic and not tied to any OEM, ECU, or vendor.
- `.mac` files are simple symbol listings intended to mimic symbol-address mapping.
- `.a2l` files are ASAM-like and deliberately varied; they are not guaranteed to satisfy every commercial parser, but they are suitable for stress and structure testing.
