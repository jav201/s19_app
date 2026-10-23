"""Inc-9 mutants: each must turn tests/test_b97_load_project_dialog.py RED."""
import subprocess, sys
from pathlib import Path
P = Path("s19_app/tui/screens.py")
ORIG = P.read_bytes()
MUTANTS = {
    "M1 first entry": (b"self.dismiss(self.projects[index])", b"self.dismiss(self.projects[0])"),
    "M3 old str(Label)": (b"self.dismiss(self.projects[index])", b"self.dismiss(str(self.query_one('#project_list').highlighted_child.query_one('Label')))"),
}
try:
    for name, (a, b) in MUTANTS.items():
        assert ORIG.count(a) == 1, name
        P.write_bytes(ORIG.replace(a, b))
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_b97_load_project_dialog.py"], capture_output=True, text=True)
        last = r.stdout.strip().splitlines()[-1]
        print(f"{name}: {'KILLED' if r.returncode else 'SURVIVED'} ({last})")
finally:
    P.write_bytes(ORIG)
