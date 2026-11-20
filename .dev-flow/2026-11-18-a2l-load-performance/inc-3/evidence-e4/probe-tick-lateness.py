"""Probe (G-T-I3-repair, evidence-e4): one case_06 image run's tick-lateness
distribution, to tell transient host contention from structural UI blocking
behind the tick_failures == 0 oracle. Read-only; imports the perf test's
own helpers. Transcript: probe-tick-lateness.txt."""

import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from tests.test_alp_inc3_load_responsiveness import _one_image_run  # noqa: E402

monkeypatch = pytest.MonkeyPatch()
with monkeypatch.context():
    run = _one_image_run(Path(tempfile.mkdtemp(prefix="tick-probe-")), monkeypatch, "probe")
obs = [lateness for _due, _fired, lateness in run["tick_observations"]]
obs.sort()
n = len(obs)
print(f"observations={n} total={run['total']:.3f}s phases={run['phases']}")
print(f"failures={run['tick_failures']} gate_ticks={run['gate_ticks']} gate_elapsed={run['gate_elapsed']:.3f}")
if n:
    print(f"lateness: min={obs[0]:.4f} p50={obs[n // 2]:.4f} p90={obs[int(n * 0.9)]:.4f} max={obs[-1]:.4f}")
    late = [l for l in obs if l > 0.1]
    print(f"late(>0.100s)={len(late)}; of those >0.2s: {sum(1 for l in late if l > 0.2)}; >1s: {sum(1 for l in late if l > 1)}")
    print(f"late lateness: min={min(late):.4f} p50={late[len(late)//2]:.4f} max={max(late):.4f}")
