#!/bin/bash
S=$HOME/work/zq-mw9
cd $S
./run.sh $S/fin f-new.txt 2 900 tests/test_b103_inc9_w_mutants.py tests/test_b103_inc9_i.py tests/test_b103_inc9_a9.py tests/test_b103_inc9_w_keys.py tests/test_b103_inc9_w_select.py tests/test_b103_inc9_w_stage.py -q
./run.sh $S/fin f-jobs.txt 2 900 tests/test_b103_inc9_w_jobs.py -m "not serial_timing and not slow" -q
./run.sh $S/fin f-law.txt 2 900 tests/test_id_registry.py tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_address_census.py tests/test_deps_seam_law.py tests/test_no_private_tokens.py tests/test_engine_unchanged.py -q
./run.sh $S/fin f-i8.txt 2 900 tests/test_b103_inc8_p_layout.py -q
touch out/final.done
