"""Ruled re-run: the corrected 039-bypass-producer mutant (all .039 arms,
no NameError) and the added 048-l1-accept-stale mutant."""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "mr3",
    str(Path(__file__).resolve().parents[4]) + "/.dev-flow/"
    r"2026-11-18-a2l-load-performance/inc-3/evidence-e4/mutant_runner.py",
)
mr3 = importlib.util.module_from_spec(spec)
sys.modules["mr3"] = mr3
spec.loader.exec_module(mr3)

WANTED = {"039-bypass-producer", "048-l1-accept-stale"}
mr3.MUTANTS = [m for m in mr3.MUTANTS if m[0] in WANTED]
mr3.OUT = mr3.OUT.with_name("mutant-run-ruled.txt")
raise SystemExit(mr3.main())
