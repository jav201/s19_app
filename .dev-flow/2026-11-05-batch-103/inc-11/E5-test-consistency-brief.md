# Inc 11 E5: P13 oracle/golden and file-count consistency (DeepSeek)

Baseline `21a0c56b`. Run 7 has 3 failures: the reference and golden wrongly expect `length=None` for `ASAM.C.CUBOID.ROW_DIR`, and the new E5 module makes the scanned count 276. You are the tester. Do not edit product code and do not commit.

Read `inc-11/E5-rulings.md`'s "P13 test-oracle and golden consistency" section and preserve the product behavior: the full CUBOID layout span is 36 bytes.

Make these targeted updates:

- `tests/support/b103_a2l_ref.py`: inline axis-count/span logic covers the full `_CURVE_MAP_FAMILY` (CUBOID, CUBE_4 and CUBE_5 too), not only CURVE/MAP, so the independent reference agrees with the required 36-byte span.
- `tests/fixtures/b103_i11/e07fb00_tags.jsonl`: only the `ASAM.C.CUBOID.ROW_DIR` entry becomes `class="D8"`, `length=36`; preserve its address 8455472 and every other tag.
- `tests/test_b103_a2l_reader.py`: READ.49/1 expects 228 defect tags and 234,426 identical tags; READ.49/2 becomes 8/8 classes with a hand-written CUBOID reduction whose full layout span is 36. Do not derive the expected value from the product.
- `tests/test_id_registry.py`: `EXPECTED_SCANNED_TEST_FILES = 276`, with a short comment that Inc 11 E5 added `test_b103_a2l_reader_e5.py` and the count is measured.
- `inc-11/01-requirements.md`: READ.49 threshold and the defect-class/count text add D8, 228 defects and 234,426 identical tags. Add the CUBOID row to the defect table.
- `inc-11/02-test-cases.md`: READ.49/1 and /2 add D8, 228/234,426 and the hand-written 36-byte CUBOID reduction. Do not change other case results in this pass.

On this PC run only `python -m py_compile` on changed Python files. Run on the Linux runner with the absolute s19ci Python, isolated environment and closed stdin:

- `tests/test_b103_a2l_reader.py::test_r_a2l_read_48_tracked_files_equal_ref`
- `tests/test_b103_a2l_reader.py::test_r_a2l_read_49_no_regression`
- `tests/test_b103_a2l_reader.py::test_r_a2l_read_49_2_defect_classes_hand_written`
- `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound`

Save the complete transcript and exit code to `inc-11/evidence-e5/test-consistency-green.txt`. If other CUBOID/CUBE differences remain, report them rather than editing more expectations. Do not run the full suite in this task, edit product, push, merge, write the OS clipboard or use proprietary A2L material.
