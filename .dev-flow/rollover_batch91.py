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
TODAY = "2026-10-08"
OUTGOING = "2026-09-06-batch-90"
OBJECTIVE = ("Contract-gap closure: the shipped foundation gets the contract it never had -- "
             "(1) the S19/HEX/A2L/MAC parsing+validation engines (REQUIREMENTS.md SS1/SS2, "
             "prose-only strata) get real US/HLR/LLR/TC ids, adopting the existing 41 "
             "unpinned test modules as the TCs' nodes; (2) the doc drift closes (README's "
             "CDFX export is gone, docs/overview+architecture describe the batch-02..04 "
             "state) -- README and docs/ catch up to the shipped 10-screen app; (3) the "
             "registry hygiene: AT-043 declared-but-unregistered resolves, and the 44 "
             "LIVE ids whose verifiers are token-invisible get renamed to carry their "
             "tokens. Agents: Kimi K2.7-code via opencode under coordinator briefs.")

spec = importlib.util.spec_from_file_location(
    "devflow_init", os.path.join(BUNDLE, "scripts", "devflow-init.py"))
di = importlib.util.module_from_spec(spec)
spec.loader.exec_module(di)

state_path = os.path.join(ROOT, ".dev-flow", "state.json")
doc = json.loads(open(state_path, encoding="utf-8").read())
assert doc["batch_id"] == OUTGOING, doc["batch_id"]
assert doc["phase_status"] == "awaiting-gate", doc["phase_status"]  # batch-90 HELD, not closed

# 1. Archive the outgoing decisions_log (moved, never copied).
archive = os.path.join(ROOT, ".dev-flow", OUTGOING, "decisions-log.json")
with open(archive, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(doc["decisions_log"], fh, indent=2, ensure_ascii=False)
    fh.write("\n")

# The repo's convention: globally-numbered batches; the bundle computes per-date.
nn = max(int(re.match(r"\d{4}-\d{2}-\d{2}-batch-(\d+)$", d).group(1))
         for d in os.listdir(os.path.join(ROOT, ".dev-flow"))
         if re.match(r"\d{4}-\d{2}-\d{2}-batch-\d+$", d)) + 1
batch = "%s-batch-%02d" % (TODAY, nn)
assert batch == "2026-10-08-batch-91", batch

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
    "Operator (Javier), 2026-10-08: 'revisa la funcionalidad de la app y cierra los gaps de "
    "user stories, requerimientos y test cases que falten... usa /dev-flow' + 'despliegues "
    "agentes kimi 2.8 o 2.7 segun convenga'. Read with the established chain: Gates -- "
    "autonomous with the two exceptions; Git -- the COORDINATOR commits and pushes at each "
    "close (no PR); data safeguard -- fixture boards only, never the operator's real files "
    "without a copy; implementing agents (Kimi K2.7-code via opencode, per the commission) "
    "do NOT commit/push/stash. This batch runs in the MAIN checkout.")

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
