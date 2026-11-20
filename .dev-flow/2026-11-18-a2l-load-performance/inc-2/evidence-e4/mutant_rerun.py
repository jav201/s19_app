"""Ruled re-run: the three survivor mutants after the test fixes
(census covers the D-13 _inner helper; .031 observes the key at refresh
entry; 036-drop-cache mutant repositioned before the refresh)."""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "mr",
    str(Path(__file__).resolve().parents[4]) + "/.dev-flow/"
    r"2026-11-18-a2l-load-performance/inc-2/evidence-e4/mutant_runner.py",
)
mr = importlib.util.module_from_spec(spec)
sys.modules["mr"] = mr
spec.loader.exec_module(mr)

WANTED = {"030-forbidden-read", "031-partial-install", "036-drop-cache"}
mr.MUTANTS = [m for m in mr.MUTANTS if m[0] in WANTED]
mr.OUT = mr.OUT.with_name("mutant-run-ruled.txt")
raise SystemExit(mr.main())
