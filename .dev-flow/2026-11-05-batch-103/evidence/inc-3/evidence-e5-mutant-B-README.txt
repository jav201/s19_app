Inc 3a mutant-B driver — run_mutants.py
========================================

Role
----
This is the ``mutB`` (negative-control) half of the Inc 3a E5 mutation pass.
It realises, one at a time, the *negative control* each covered row names in
``inc-3/01-requirements.md`` (column "Negative control") and
``inc-3/02-test-cases.md``, applies it to an **isolated copy** of the
integrated tree, and runs only that row's **discriminating non-timing test**.
Verdicts:

* ``KILLED``   — the discriminating test turned RED under the mutant (the row
  has a working guard).
* ``SURVIVED`` — the test stayed green (the row's negative control is not
  actually guarded; a test gap to close before E5).
* ``CRASH``    — the mutant crashed the code (unhandled exception / timeout /
  pytest INTERNALERROR) before any assertion saw it.
* ``BAD``      — the guarded replacement could not be applied (anchor matched
  0 or 2+ times) or the baseline was not green, so nothing is credited.

Base / interpreter / isolation
------------------------------
* Integrated tree: ``/tmp/b103-e4-3a-int/tree`` (override with ``B103_INT_TREE``).
* Interpreter: ``/home/<runner>/miniconda3/envs/s19ci/bin/python -I -B``.
  ``-I`` (isolated) plus the repo's own ``pyproject.toml`` ``pythonpath = ["."]``
  makes pytest insert the *copy's* root onto ``sys.path`` at collection, so
  ``import s19_app`` always resolves to the mutated copy — never to the editable
  ``s19tool`` install in the env (its meta-path finder is appended after
  ``PathFinder``, so the copy on ``sys.path[0]`` wins).
* ``HOME``/``XDG_CONFIG_HOME``/``XDG_CACHE_HOME``/``XDG_DATA_HOME``/
  ``LOCALAPPDATA`` → ``/tmp/b103-e4-3a-mutB/zq_iso_user/<label>/…`` (fresh per
  mutant; no real home, no corpus cache, no shared pytest history).
* The real worktree is only ever **read** (to copy and to anchor-match). Every
  pytest run uses the copy as cwd; ``-B`` and ``-p no:cacheprovider`` keep even
  the copy free of bytecode/cache side effects.

Hard rules enforced by the driver
---------------------------------
1. One fresh ``copytree`` per mutant (``.git``/``.dev-flow``/``zq_iso_user``/
   caches are excluded: none is read by a discriminating test).
2. Guarded replacement: the anchor must match **exactly once**; otherwise the
   mutant is ``BAD`` and never run.
3. Only the listed discriminating test(s) run — no full suite.
4. No timing-only mutant, no assertion edit. Every selected test asserts an
   exact value / message / refusal code / identity; none is a ``serial_timing``
   wall-clock arm.
5. The driver refuses to run while a serial-timing window is open
   (``B103_SERIAL_TIMING=1`` or ``--no-run``).

Coverage — 29 mutants
---------------------
Areas: **S2.7g decoding** (20), **S2.7i synth** (4), **cited rows + keyed-read /
exact-scaling** (5).

S2.7g decoding (edit ``s19_app/tui/a2l_definition.py``)
    | Id     | Row          | Control realised (one guarded edit)                | Discriminating test (in ``tests/test_b103_a2l_definition_arrays_decode.py`` unless noted) |
    |--------|--------------|----------------------------------------------------|------------------------|
    | M-105  | R-A2L-DEF.105| LINEAR element decoded as IDENTICAL                | ``::test_r_a2l_def_105_3_converted_elements`` |
    | M-106  | R-A2L-DEF.106| ROW_DIR read with the COLUMN_DIR rule              | ``::test_r_a2l_def_106_1_row_dir_2d`` |
    | M-107  | R-A2L-DEF.107| COLUMN_DIR read with the ROW_DIR rule              | ``::test_r_a2l_def_107_1_column_dir_2d`` |
    | M-108  | R-A2L-DEF.108| INDEX_INCR points read INDEX_DECR                  | ``::test_r_a2l_def_108_1_index_incr_points`` |
    | M-109  | R-A2L-DEF.109| INDEX_DECR points read INDEX_INCR                  | ``::test_r_a2l_def_109_1_index_decr_asam_axis_object`` |
    | M-110  | R-A2L-DEF.110| FIX_AXIS_PAR as o + k·s (not o + k·2^s)            | ``::test_r_a2l_def_110_1_fix_axis_par`` |
    | M-111  | R-A2L-DEF.111| FIX_AXIS_PAR_DIST as the point index               | ``::test_r_a2l_def_111_1_par_dist_1_1_6`` |
    | M-112  | R-A2L-DEF.112| FIX_AXIS_PAR_LIST as the point index               | ``::test_r_a2l_def_112_1_fix_axis_par_list`` |
    | M-113  | R-A2L-DEF.113| COM_AXIS points read from the curve's own record   | ``::test_r_a2l_def_113_1_two_curves_one_axis_object`` |
    | M-114  | R-A2L-DEF.114| axis object's own BYTE_ORDER ignored (curve's used)| ``::test_r_a2l_def_114_1_axis_object_own_byte_order`` |
    | M-115  | R-A2L-DEF.115| NO_AXIS_PTS count ignored (point count always used)| ``::test_r_a2l_def_116_2_1_count_0`` (the .116 case gives points) |
    | M-116.1| R-A2L-DEF.116.1| FIX_NO count 0/over-max ignored at describe      | ``::test_r_a2l_def_116_1_3_fix_no_axis_pts_x_0`` |
    | M-116.2| R-A2L-DEF.116.2| count below 1 / above max read as full at decode   | ``::test_r_a2l_def_116_2_1_count_0`` |
    | M-117.1| R-A2L-DEF.117.1| partial FIX_NO record accepted at describe         | ``::test_r_a2l_def_117_1_2_partial_record_by_fix_no`` |
    | M-117.2| R-A2L-DEF.117.2| partial NO_AXIS_PTS record read as full at decode  | ``::test_r_a2l_def_117_2_1_partial_record_in_image`` |
    | M-118  | R-A2L-DEF.118| missing axis-object bytes read as 0                | ``::test_r_a2l_def_118_1_axis_object_outside_image`` |
    | M-119  | R-A2L-DEF.119| whole decode refused at the first failing element  | ``::test_r_a2l_def_119_1_one_failing_element`` |
    | M-120  | R-A2L-DEF.120| first element decoded as the single value          | ``::test_r_a2l_def_120_1_single_decode_refusal`` |
    | M-121  | R-A2L-DEF.121| element refusal names the object, not the element  | ``::test_r_a2l_def_121_3_name_in_decode_refusal`` |
    | M-146  | R-A2L-DEF.146| scalar ``decode_values`` yields no element         | ``::test_r_a2l_def_146_1_scalar_decode_values`` |

S2.7i synth (edit ``tools/synth/make_release_case.py``)
    | Id    | Row         | Control realised                                   | Discriminating test |
    |-------|-------------|----------------------------------------------------|---------------------|
    | M-133 | R-A2L-DEF.133| shared AXIS_PTS count component written as 0       | ``decode::test_r_a2l_def_133_1_definitions_case_common_axis`` |
    | M-134 | R-A2L-DEF.134| MAP COLUMN_DIR values packed ROW_DIR               | ``decode::test_r_a2l_def_134_1_definitions_case_map`` |
    | M-135 | R-A2L-DEF.135| VAL_BLK MATRIX_DIM made square (3 3)               | ``decode::test_r_a2l_def_135_1_definitions_case_val_blk`` |
    | M-59  | R-A2L-DEF.59 | one extra VALUE in ``app`` (case-08 digests move)  | ``test_b103_synth_definitions.py::test_r_a2l_def_59_1_case08_at_1_mib_equals_its_pin`` |

Cited rows + keyed-read / exact-scaling (edit ``s19_app/tui/a2l_definition.py``)
    | Id    | Row                  | Control realised                                  | Discriminating test (in ``test_b103_a2l_definition_arrays_coverage.py`` unless noted) |
    |-------|----------------------|---------------------------------------------------|---------------------|
    | M-136 | R-A2L-DEF.136 (keyed read, .136/arr-4 vi) | layout read form keyed by bare ``id()``        | ``::test_r_a2l_def_136_arr_4_k1_k3_and_poison_shapes_equal_fresh`` |
    | M-139 | R-A2L-DEF.139        | duplicate-name refusal dropped (first tag used)   | ``decode::test_r_a2l_def_139_arr_1_name_declared_twice`` |
    | M-148 | R-A2L-DEF.148 (exact scaling, .148/19) | COMPU_TAB form rebuilt per method record        | ``::test_r_a2l_def_148_19_tab_through_own_method_one_form`` |
    | M-150 | R-A2L-DEF.150 (decode/element, .150/arr-11) | text table value not refused (raises in display_text) | ``::test_r_a2l_def_150_arr_11_table_text_value_refused_not_raised`` |
    | M-151 | R-A2L-DEF.151        | 256-char cap + U+FFFD rule dropped                | ``decode::test_r_a2l_def_151_arr_2_256_character_cut`` |

``decode`` above abbreviates ``tests/test_b103_a2l_definition_arrays_decode.py``
and ``coverage`` abbreviates ``tests/test_b103_a2l_definition_arrays_coverage.py``.

Controls **not realisable under the stated constraints** (and why)
--------------------------------------------------------------------
* **Timing-only arms of .136 / .148 / .150** — the wall-clock scaling ratios
  (``serial_timing``: .148's ×1.5/×2.0 bounds, .136's 2.0 s describe budget,
  .150's decode scaling) are realisable as *tests* but are **timing-only
  mutants**, which the brief forbids, and they must not run during serial
  timing. This driver selects only the **functional** arms of those rows (the
  one-form identity for .148/19, the K1–K3 equality for .136/arr-4, the
  not-a-number refusal for .150/arr-11), which assert exact values, never a
  clock.
* **Immutability control (.136/arr-4, E3S3-19 / E3S3-36)** — "every stored read
  form refuses mutation; no read form / definition field holds a list or dict"
  is realisable (e.g. store the section's own ``lines`` list in a read form),
  but it is the **second** negative control of the one row the brief lists as a
  single ``M-136``. The keyed-read arm is the one realised; the immutability arm
  is guarded by the same ``.136/arr-4`` family
  (``test_r_a2l_def_136_arr_4_read_forms_immutable_no_list_dict``) and would be
  a separate mutant if a second control is requested.
* **M-137 (R-A2L-DEF.137 control characters)** — not in the brief's id list.
  In Inc 3a the ``/arr`` cases echo file words through R-A2L-DEF.151's ``_echo``
  (CTX placeholders), so a ``_clean``-only mutant (Inc 2's M-137) would leave
  them green; the guard for those messages is **M-151** (``_echo``), which this
  driver realises.
* **M-63 (R-A2L-DEF.63 determinism)** — not in the brief's id list; Inc 2
  already carried M-63, and the S2.7i synth objects are deterministic by
  construction (no wall clock in ``_definition_array_objects`` /
  ``emit_definitions_a2l``).
* **3b rows (.122–.132, .140)** — the encode/write side waits for Inc 2b and
  Inc 11; out of Inc 3a scope, so no mutant here. The encode arms of
  R-A2L-DEF.120/2 and .121/1, /2 wait for 3b with them.

Usage
-----
    # plan only (no execution)
    /home/<runner>/miniconda3/envs/s19ci/bin/python -I -B run_mutants.py --list

    # run everything (refuses while B103_SERIAL_TIMING=1)
    /home/<runner>/miniconda3/envs/s19ci/bin/python -I -B run_mutants.py

    # one mutant
    /home/<runner>/miniconda3/envs/s19ci/bin/python -I -B run_mutants.py --only M-105

Per-mutant transcript: ``/tmp/b103-e4-3a-mutB/<label>/out.txt`` (applied diff +
pytest summary + verdict).
