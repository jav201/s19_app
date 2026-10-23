"""Probe (pre-Inc-6, not product): a lane with two EXT-STEP blocks, confirmed one entry
at a time the way the app handler does it today ({block_index: confirmation} only)."""
import sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import s19_app
from s19_app.tui.services import flow_execution_service as fes
from s19_app.tui.services.flow_model import (EXTERNAL_MODE_TERMINAL, ExternalStepBlock,
    ExternalStepConfirmation, Flow, FlowContext, SourceBlock, WriteOutBlock)
S19 = "S107100001020304DE\nS9030000FC\n"
tmp = Path(tempfile.mkdtemp())
proj = tmp / ".s19tool" / "workarea" / "proj"; proj.mkdir(parents=True)
(proj / "base.s19").write_text(S19); ext = tmp / "ext"; ext.mkdir()
for n in (1, 2):
    (proj / f"run{n}.log").write_text("ok\n"); (ext / f"out{n}.s19").write_text(S19)
b1 = ExternalStepBlock(mode=EXTERNAL_MODE_TERMINAL, instruction="one", log_ref="run1.log", output_path=str(ext / "out1.s19"))
b2 = ExternalStepBlock(mode=EXTERNAL_MODE_TERMINAL, instruction="two", log_ref="run2.log", output_path=str(ext / "out2.s19"))
flow = Flow(name="ext2", blocks=[SourceBlock("base.s19"), b1, b2, WriteOutBlock("out.s19")])
conf = lambda i, b: ExternalStepConfirmation(i, b.log_ref, b.output_path)
def run(confs):
    rec = fes.run_chain_set([fes.ChainSpec("ext2", "ext2", flow, {})], FlowContext(project_dir=proj, external_confirmations=confs), mode="sequential", set_name="p")
    o = rec.outcomes[0]
    return o.status, [(r.index, r.status) for r in o.block_results]
print("S19_APP_FROM", s19_app.__file__)
print("no confirmation       ", run({}))
print("{1} (first confirm)   ", run({1: conf(1, b1)}))
print("{2} (second, as today)", run({2: conf(2, b2)}))
print("{1,2} (accumulated)   ", run({1: conf(1, b1), 2: conf(2, b2)}))
