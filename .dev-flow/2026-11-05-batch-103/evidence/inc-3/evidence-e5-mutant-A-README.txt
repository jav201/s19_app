Inc 3a (batch-103) E5 mutant-A driver — arrays & axes, describe side
=========================================================================

What this is
------------
A mutation-testing driver for the Inc 3a read side (S2.7e / S2.7f of
`inc-3/01-requirements.md`).  It validates the array/curve/map model in
`s19_app/tui/a2l_definition.py` by applying each requirement's *Negative
control* as an exact, guarded source edit on an isolated copy of the
integrated tree, then running only that mutant's discriminating test node(s).

Files (only these two are written)
----------------------------------
  /tmp/b103-e4-3a-mutA/run_mutants.py   the driver (read it before running)
  /tmp/b103-e4-3a-mutA/README.txt       this file

Do NOT run it while the law (engine-frozen) guards are active.  The driver
never runs the guard tests and never writes to the integrated tree
(`/tmp/b103-e4-3a-int/tree`); it only clones it.

How it works
------------
1. Clones the integrated tree once into `work/base` (skips `.git`,
   `.dev-flow`, `.pytest_cache`, `zq_iso_user`, `__pycache__`, egg-info and
   `.pyc` — the tests only need `s19_app/`, `tests/`, `examples/`, `tools/`,
   and the packaging files).
2. For each arm `M-*`, clones `work/base` to a unique isolated directory
   `work/<id>/tree`, applies the arm's `anchor -> mutation` replacement to
   `s19_app/tui/a2l_definition.py` in that copy (asserting the anchor occurs
   exactly once and the bytes change), and runs only the arm's test nodes.
3. Runs each test with:
     /data/miniconda3/envs/s19ci/bin/python -I -B -m pytest \
         -p no:cacheprovider -q <node ids...>
   with `cwd = work/<id>/tree`, an isolated `zq_iso_user` HOME/XDG/
   LOCALAPPDATA/TMPDIR (`work/zq_iso_user/…`), `PYTHONDONTWRITEBYTECODE=1`,
   and `PYTHONPATH`/`PYTHONHOME`/`DISPLAY`/`WAYLAND_DISPLAY`/`CI` unset.
4. Classifies from the pytest summary line (never the exit code alone) and
   writes `work/<id>/transcript.txt` + `work/<id>/diff.txt`, and
   `work/runner-summary.txt` at the end.  The real tree is never edited and
   never restored — there is nothing to restore.

Classification
--------------
  KILLED    >=1 selected test failed (assertion) — the mutant is dead.
  SURVIVED  every selected test passed — a real test-oracle gap to report.
  CRASH     the run errored (unhandled exception) rather than merely failing;
            still a kill of a removed guard, reported separately.
  BAD       anchor absent / not unique / no test collected — a wiring defect,
            never a product verdict.

Invocation
----------
  cd /tmp/b103-e4-3a-mutA
  python3 run_mutants.py --list          # list arms + their test nodes
  python3 run_mutants.py --baseline      # first: prove the cloned tree GREEN
  python3 run_mutants.py                 # run every arm
  python3 run_mutants.py --only M-147    # run one arm

Exact coverage (61 arms)
------------------------
S2.7e (19 rows) — all covered:

  R-A2L-DEF.64  M-64 (VAL_BLK->number), M-64b (MEASUREMENT leading-1)
  R-A2L-DEF.65  M-65  (CURVE refused)
  R-A2L-DEF.66  M-66  (MAP->curve)
  R-A2L-DEF.67  M-67  (trailing 1s kept)
  R-A2L-DEF.68  M-68  (NUMBER ignored)
  R-A2L-DEF.69  M-69  (length taken as element count)
  R-A2L-DEF.70  M-70  (shape rounded down)
  R-A2L-DEF.71  M-71  (0 accepted), M-71b (malformed MEASUREMENT read scalar)
  R-A2L-DEF.72  M-72  (axes reversed, Y first)
  R-A2L-DEF.73  M-73  (first shape number only), M-73b (default 1)
  R-A2L-DEF.74  M-74  (tag length used)
  R-A2L-DEF.75  M-75  (span incl. axis-object bytes used)
  R-A2L-DEF.76  M-76  (LENGTH preferred over shape)
  R-A2L-DEF.77  M-77  (first layout datatype word used)
  R-A2L-DEF.78  M-78  (LAYOUT ignored -> ROW_DIR)
  R-A2L-DEF.79  M-79  (default COLUMN_DIR)
  R-A2L-DEF.80  M-80  (3-D COLUMN_DIR read with 2-D rule)
  R-A2L-DEF.81  M-81  (Inc 2 conversion checks skipped), M-81b (unreadable mask
                       word -> no mask)
  R-A2L-DEF.145 M-145 (MATRIX_DIM on curve/map ignored), M-145b (on VALUE
                       decoded as its first value)

S2.7f (29 rows) — 28 covered, .148 excluded (timing-only):

  R-A2L-DEF.82  M-82  (undeclared layout not refused)
  R-A2L-DEF.83  M-83  (axis points read as values)
  R-A2L-DEF.84  M-84  (unknown layout line skipped)
  R-A2L-DEF.85  M-85  (ALTERNATE mode admitted)
  R-A2L-DEF.86  M-86  (float count datatype admitted), M-86b (BYTE admitted),
                       M-86c (missing datatype word -> IndexError)
  R-A2L-DEF.87  M-87  (line order used on position tie)
  R-A2L-DEF.88  M-88  (ALIGNMENT ignored), M-88b (line order in placement)
  R-A2L-DEF.89  M-89  (MOD_COMMON alignment check skipped)
  R-A2L-DEF.90  M-90  (FIX_NO_* refused as unknown part)
  R-A2L-DEF.91  M-91  (axis count not checked)
  R-A2L-DEF.92  M-92  (RES_AXIS/CURVE_AXIS read as readable), M-92b (H3e:
                       header read from section lines only)
  R-A2L-DEF.93  M-93  (FIX_AXIS_PAR count word used as point count)
  R-A2L-DEF.94  M-94  (AXIS_DESCR count used for COM_AXIS)
  R-A2L-DEF.95  M-95  (max 0 accepted)
  R-A2L-DEF.96  M-96  (dangling ref guard removed), M-96b (address read via
                       int(word, 0))
  R-A2L-DEF.97  M-97  (axis object FNC_VALUES read as its points)
  R-A2L-DEF.98  M-98  (index points 0..n-1 for a parameterless FIX_AXIS)
  R-A2L-DEF.99  M-99  (FIX count mismatch not refused)
  R-A2L-DEF.100 M-100 (STD_AXIS always given points)
  R-A2L-DEF.101 M-101 (in-record points used for non-STD axis)
  R-A2L-DEF.102 M-102 (wrong axis conversion source)
  R-A2L-DEF.103 M-103 (object name used in axis refusal)
  R-A2L-DEF.104 M-104 (axes checked before the layout)
  R-A2L-DEF.141 M-141 (list words via _to_float), M-141b (PAR_DIST words via
                       _to_float), M-141c (count via int())
  R-A2L-DEF.142 M-142 (1,048,576 cap removed) — behavioral arms /1…/4 only
  R-A2L-DEF.143 M-143 (axis-object span bounds removed)
  R-A2L-DEF.144 M-144 (unreadable MOD_COMMON alignment left out)
  R-A2L-DEF.147 M-147 (shift bound 62->63), M-147b (exact magnitude bound
                       removed on FIX_AXIS_PAR_DIST)
  R-A2L-DEF.148 EXCLUDED — every case is a timing/scaling measure (no source
                       mutant; "no timing-only mutants").

Cited rows the array model must meet (span):
  R-A2L-DEF.7.2 M-span (array computed byte length >1 MiB bound removed),
                exercised through tests/…_decode.py::test_r_a2l_def_7_2_arr_1.

Special notes (the named priorities)
------------------------------------
- F1 / exact FIX bounds: the FIX rule (`_read_fixed_rule`) and its exact
  bounds are covered by M-98, M-99, M-141/141b/141c, M-147 and M-147b.
- span: array span bound (M-span) + axis-object span bounds (M-143) + the
  address/span refusal block those mutants remove.
- H3e: R-A2L-DEF.92/4's header-on-its-/begin-line control is M-92b.
- count datatype: R-A2L-DEF.86/3 and /4 are M-86, M-86b, M-86c.
- axis guards: R-A2L-DEF.96/.97 (axis-object ref/layout), .141/.142/.143/.144.

Not realisable / excluded controls (exact list)
-----------------------------------------------
1. R-A2L-DEF.148 (all 19 cases) — timing/scaling only; no source mutant
   ("no timing-only mutants").  Excluded.
2. R-A2L-DEF.142/5 and .142/6 — timing arms (describe speed at the cap; the
   linear-time FIX_AXIS_PAR_LIST read).  Excluded as timing-only; the
   behavioural arms /1…/4 are covered by M-142.
3. R-A2L-DEF.96/2 "dangling reference read as an axis of index points" —
   not realisable as the literal "index points" definition without
   restructuring the COM_AXIS block.  Realised as the guard-removal M-96,
   which CRASHes (TypeError) instead of producing a definition; the test still
   catches it, but it is reported as CRASH, not a clean index-point axis.
4. R-A2L-DEF.141/3–/4 "words read by _to_float and the points computed
   unchecked (a definition with inf points)" — not realisable as a clean
   definition because the current design stores exact integer ratios (no
   unchecked point computation path exists to mutate).  Realised as M-141b
   (_finite_number -> _to_float), which CRASHes (OverflowError on `inf`,
   ValueError on `nan`) instead of producing inf points; the tests still catch
   it, reported as CRASH.  The /5 list arm (M-141) and /6 count arm (M-141c)
   are realised cleanly.

No timing-only mutants and no assertion/test edits: every arm mutates only
`s19_app/tui/a2l_definition.py`, and no test file or requirement record is
changed.
