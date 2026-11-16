"""FX9f stall controls (HT-09: applied to a copy only). mutate.py <tree> <mode> <seconds>.
paint:   ArrayBenchSheet._paint sleeps <seconds> on the UI thread while a bench job runs (FX9's stall mutant, parameterised).
arrival: the preview result's arrival (_job_done, kind 'preview') holds the UI thread <seconds> (X9's arrival mutant)."""
import sys
from pathlib import Path

tree, mode, secs = sys.argv[1], sys.argv[2], sys.argv[3]
p = Path(tree) / "s19_app/tui/screens_directionb/patch_editor/bench_sheet.py"
s = p.read_text(encoding="utf-8").replace("\r\n", "\n")
if mode == "paint":
    old = "    def _paint(self) -> None:\n"
    new = old + "        if self._active_job is not None:\n            __import__('time').sleep(%s)  # FX9f MUTANT\n" % secs
else:
    old = "    def _job_done(self, kind, name, generation, result, derived):\n"
    new = old + "        if kind == 'preview':\n            __import__('time').sleep(%s)  # FX9f MUTANT\n" % secs
assert s.count(old) == 1
p.write_text(s.replace(old, new), encoding="utf-8", newline="\n")
print("mutant applied", mode, secs)
