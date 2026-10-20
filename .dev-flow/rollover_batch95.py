"""Rollover 2026-09-06-batch-90 (HELD at P1) -> batch-91 (the contract-gap closure),
per the operator's commission 2026-10-08. Uses devflow-init.py's own template helpers.

NOTE: batch-90 stays HELD (phase_status awaiting-gate) — its hold reason (rev60's
increment template) is satisfied long ago, and it may resume later as its own step.
This batch does NOT mark it closed; the assertion below records the hold instead."""
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys

ROOT = r"C:\Users\jjgh8\Github\s19_app"
BUNDLE = r"C:\Users\jjgh8\.claude\skills\dev-flow"
TODAY = "2026-10-13"
OUTGOING = "2026-10-13-batch-94"
OBJECTIVE = ("The cambios_10_12_2026 batch: (1) the Split / Join / Export screen -- the "
             "grafted terminal design (V1 chassis + V2's width-118 band + split-mode "
             "per-file gantt), the color/glyph preview visor, split/join/export S19+HEX+BIN "
             "with skip/fill gaps (pad 0x00), the span guard, palette-first; (2) project "
             "save gathers all used files, artifacts project-scoped (no project -> common "
             "homes); (3) open-folder buttons on patch/checks/CRC/reports (cross-platform); "
             "(4) per-window usage help sections")

spec = importlib.util.spec_from_file_location(
    "devflow_init", os.path.join(BUNDLE, "scripts", "devflow-init.py"))
di = importlib.util.module_from_spec(spec)
spec.loader.exec_module(di)

state_path = os.path.join(ROOT, ".dev-flow", "state.json")
doc = json.loads(open(state_path, encoding="utf-8").read())
assert doc["batch_id"] == OUTGOING, doc["batch_id"]
assert doc["phase_status"] == "closed", doc["phase_status"]

# 1. Archive the outgoing decisions_log (moved, never copied).
archive = os.path.join(ROOT, ".dev-flow", OUTGOING, "decisions-log.json")
with open(archive, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(doc["decisions_log"], fh, indent=2, ensure_ascii=False)
    fh.write("\n")

# The repo's convention: globally-numbered batches; the bundle computes per-date.
# batch-92 is the OTHER lane's (the layer-inversions refactor, opened in its own
# checkout -- its dir is not in this tree); this batch is the next global number.
nn = max(int(re.match(r"\d{4}-\d{2}-\d{2}-batch-(\d+)$", d).group(1))
         for d in os.listdir(os.path.join(ROOT, ".dev-flow"))
         if re.match(r"\d{4}-\d{2}-\d{2}-batch-\d+$", d)) + 1
batch = "%s-batch-%02d" % (TODAY, nn)
assert batch == "2026-10-13-batch-95", batch

def git(*args):
    return subprocess.run(["git", "-C", ROOT] + list(args),
                          capture_output=True, text=True).stdout.strip()

base_ref = git("rev-parse", "HEAD")
owner = git("rev-parse", "--show-toplevel")
found = di._found(ROOT)

homes = {k: v.replace("<batch_id>", batch).replace("<project>", doc["project"])
         for k, v in di.ARTIFACT_HOMES}

doc.update({
    "batch_id": batch,
    "batch_objective": OBJECTIVE,
    "owner": owner,
    "current_station": "P0",
    "phase_status": "not-started",
    "stations_active": ["P0", "P1", "P2", "P3", "P4", "P5"],
    "iterations_per_station": {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0},
    "triggers": {"evaluated_at": None, "fired": [], "not_fired": [],
                 "record": di.TRIGGERS_RECORD},
    "artifact_homes": homes,
    "base_ref": base_ref,
    "artifacts": {},
    "decisions_log": [],
    "standing_authorization": {"autonomous": True, "merge": False, "asked_on": TODAY,
                               "operator_words": ""},
    "obsidian_synced": False,
    "created_at": datetime.datetime.now().isoformat(),
})
doc["mode"] = "core"
doc["mode_history"].append({
    "from": None, "to": "core", "date": TODAY,
    "reason": "batch %s opened by rollover from %s (HELD at P1, not closed -- its hold reason, "
              "rev60's packet template, is long satisfied; it resumes as its own step); mode "
              "core declared by the commission" % (batch, OUTGOING)})
doc["standing_authorization"]["operator_words"] = (
    "Operator (Javier), 2026-10-13: the prototype round for the cambios of 2026-10-12 "
    "CLOSED -- all four changes + the six rulings accepted, the join preview visor added, "
    "the TUI-native pass shipped the graft as the final screen, a color, both verdicts "
    "accepted (veredicto-ronda1 / veredicto-tui-pass / veredicto-final in the round's "
    "dir). Implement the batch. Read with the established chain: Gates -- autonomous with "
    "the two exceptions; Git -- the COORDINATOR commits and pushes at each close; Kimi "
    "agents under coordinator briefs do NOT commit/push/stash. This batch runs in the "
    "MAIN checkout.")

with open(state_path, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(doc, fh, indent=2, ensure_ascii=False)
    fh.write("\n")

# 2. Seed the batch record from the flow's templates.
flow = di._flow_home()
bdir = os.path.join(ROOT, ".dev-flow", batch)
os.makedirs(bdir)
req = di._template(flow, "req-template.md")
ledger = di._ledger_seed(req)
written = []
for name, dest in di.SEEDS:
    text = di._template(flow, name)
    text = (text.replace("<PROJECT>", doc["project"]).replace("<BATCH_ID>", batch)
            .replace("<YYYY-MM-DD>", TODAY))
    if dest == "PLAN.md":
        text = text.replace(di.OBJECTIVE_TOKEN, OBJECTIVE)
    if di.FOUND_LABEL in text:
        text = di._fill_found(text, found)
    with open(os.path.join(bdir, dest), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    written.append(dest)
with open(os.path.join(bdir, "01-requirements-ledger.md"), "w", encoding="utf-8",
          newline="\n") as fh:
    fh.write(ledger.replace("<PROJECT>", doc["project"]).replace("<BATCH_ID>", batch)
             .replace("<YYYY-MM-DD>", TODAY))
written.append("01-requirements-ledger.md")
os.makedirs(os.path.join(bdir, "03-increments"))
os.makedirs(os.path.join(bdir, "evidence"))
packet = di._template(flow, di.PACKET_SEED[0])
packet = "\n".join(
    (line.replace("<batch_id>", batch).replace("<NNN>", di.PACKET_SEED[2])
     .replace("<YYYY-MM-DD>", TODAY) if line.startswith(di.PACKET_HEADER_LINES) else line)
    for line in packet.split("\n") if not line.startswith(di.PACKET_EXAMPLE_ROW))
with open(os.path.join(bdir, "03-increments", di.PACKET_SEED[1]), "w", encoding="utf-8",
          newline="\n") as fh:
    fh.write(packet)
written.append("03-increments/" + di.PACKET_SEED[1])

# 3. The evidence home is marked -text.
ga = os.path.join(ROOT, ".gitattributes")
mark = ".dev-flow/%s/evidence/** -text" % batch
existing = open(ga, encoding="utf-8", errors="replace").read() if os.path.isfile(ga) else ""
if mark not in existing:
    with open(ga, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(("" if existing.endswith("\n") or not existing else "\n") + mark + "\n")

print("batch:", batch)
print("archived:", os.path.relpath(archive, ROOT), "(%d entries)" % len(json.load(open(archive, encoding='utf-8'))))
print("base_ref:", base_ref)
print("seeded:", ", ".join(sorted(written)))
print("found:", [n for n, _ in found] or "none")
