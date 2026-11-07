"""pytest plugin (copied to <scratch>/plug/d3_plugin.py by d3-run.sh; loaded with -p d3_plugin): installs the d3
pilot (d3-pilot.py) before collection, so the test modules import the piloted build_label_index and rank reaches the
piloted fuzzy tier. Env: D3_PILOT (path of d3-pilot.py), D3_BUDGET (an int, or off), D3_ASCII (1 or 0).
THROWAWAY EVIDENCE, NOT PRODUCT CODE."""
import hashlib
import importlib.util
import os
from pathlib import Path

import s19_app
from s19_app.tui.services import label_match as lm

_spec = importlib.util.spec_from_file_location("d3_pilot", os.environ["D3_PILOT"])
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_B = os.environ.get("D3_BUDGET", "off")
_A = os.environ.get("D3_ASCII", "0") == "1"
PILOT = _mod.Pilot(lm)
PILOT.install(None if _B == "off" else int(_B), _A)
print(f"d3_plugin: s19_app.__file__ = {s19_app.__file__}; label_match sha256 {hashlib.sha256(Path(lm.__file__).read_bytes()).hexdigest()}; {PILOT.state}", flush=True)


def pytest_report_header(config):
    sha = hashlib.sha256(Path(lm.__file__).read_bytes()).hexdigest()
    return [f"s19_app.__file__ = {s19_app.__file__}", f"label_match = {lm.__file__} sha256 {sha}",
            f"d3 pilot installed: {PILOT.state}; HOME = {os.environ.get('HOME')}"]
