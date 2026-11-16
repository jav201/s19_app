"""keys.py: print every mutation key of mutants.py, one per line."""
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutants import M  # noqa: E402

print("\n".join(M))
