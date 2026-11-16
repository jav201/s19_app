# X9 arrival mutant (HT-09: applied to a copy only): the preview result's arrival holds the UI thread 0.8 s,
# a stand-in for R-PE-BENCH.29/2's negative control "the diff and lo/hi done on the UI thread when the result arrives".
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "s19_app/tui/screens_directionb/patch_editor/bench_sheet.py"
s = p.read_text(encoding="utf-8")
old = "    def _job_done(self, kind, name, generation, result, derived):\n"
assert s.count(old) == 1
s = s.replace(old, old + "        if kind == 'preview':\n            __import__('time').sleep(0.8)  # X9 MUTANT\n")
p.write_text(s, encoding="utf-8", newline="\n")
print("mutant applied")
