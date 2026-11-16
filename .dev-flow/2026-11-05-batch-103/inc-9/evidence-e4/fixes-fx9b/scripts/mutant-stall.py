# FX9 stall mutant (mutant-stall.diff) as a script, line-ending neutral (HT-09: applied to a copy only):
# ArrayBenchSheet._paint sleeps 0.8 s on the UI thread while a bench job runs.
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "s19_app/tui/screens_directionb/patch_editor/bench_sheet.py"
s = p.read_text(encoding="utf-8").replace("\r\n", "\n")
old = "    def _paint(self) -> None:\n"
assert s.count(old) == 1
s = s.replace(old, old + "        if self._active_job is not None:\n            __import__(\"time\").sleep(0.8)  # FX9 MUTANT: UI-thread work while a bench job runs\n")
p.write_text(s, encoding="utf-8", newline="\n")
print("mutant applied")
