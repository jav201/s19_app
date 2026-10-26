"""Rollover 2026-10-25-batch-99 (closed at P6, synced) -> batch-100 (the Load + projects
batch), per the operator's kickoff answers of 2026-10-26. Uses devflow-init.py's own
template helpers. Differences from rollover_batch99.py: no `standing_authorization` key in
state.json (the PLAN header cell is the one record, V55), and `module_map` names the tracked
file `docs/architecture.md`."""
import datetime
import importlib.util
import json
import os
import subprocess

ROOT = r"C:\Users\jjgh8\Github\s19_app"
BUNDLE = r"C:\Users\jjgh8\.claude\skills\dev-flow"
TODAY = "2026-10-26"
OUTGOING = "2026-10-25-batch-99"
BATCH = "2026-10-26-batch-100"
OBJECTIVE = ("The Load + projects batch: one Load dialog that offers what is already loaded and "
             "opens projects, and a project that restores what was saved or says what it could "
             "not. Scope: the project round-trip findings of "
             "INVESTIGATION-project-roundtrip-2026-10-23 still open (PH-1 Save project drops a "
             "pending patch, PH-2 load over a project leaks its A2L/MAC/patches, PH-4 save-back "
             "opens the unpatched original, PH-5 manifest problems ignored; M-1..M-7, L-2..L-4), "
             "the Load dialog requests (a picker of work-area files and recent sources, Load opens "
             "projects, Enter-to-load D10), the G-005 save naming (byte-identical reuse, tests "
             "re-pinned), the Code-Wire UI items CW-U-2, CW-U-5, CW-U-12, CW-U-13, the reserved "
             "project name, and the progress indicator for long actions (N5 reopened). UI changes "
             "go through a prototype round with the operator's verdict before implementation.")

spec = importlib.util.spec_from_file_location(
    "devflow_init", os.path.join(BUNDLE, "scripts", "devflow-init.py"))
di = importlib.util.module_from_spec(spec)
spec.loader.exec_module(di)

state_path = os.path.join(ROOT, ".dev-flow", "state.json")
doc = json.loads(open(state_path, encoding="utf-8").read())
assert doc["batch_id"] == OUTGOING, doc["batch_id"]
assert doc["obsidian_synced"] is True and doc["current_station"] == "P6", doc["phase_status"]

archive = os.path.join(ROOT, ".dev-flow", OUTGOING, "decisions-log.json")
assert not os.path.exists(archive)
with open(archive, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(doc["decisions_log"], fh, indent=2, ensure_ascii=False)
    fh.write("\n")
with open(os.path.join(ROOT, ".dev-flow", OUTGOING, "state-snapshot-at-close.json"), "w",
          encoding="utf-8", newline="\n") as fh:
    json.dump(doc, fh, indent=2, ensure_ascii=False)
    fh.write("\n")

assert not os.path.exists(os.path.join(ROOT, ".dev-flow", BATCH))


def git(*args):
    return subprocess.run(["git", "-C", ROOT] + list(args),
                          capture_output=True, text=True).stdout.strip()


base_ref = git("rev-parse", "HEAD")
owner = git("rev-parse", "--show-toplevel")
found = di._found(ROOT)
homes = {k: v.replace("<batch_id>", BATCH).replace("<project>", doc["project"])
         for k, v in di.ARTIFACT_HOMES}
homes["module_map"] = "repo:docs/architecture.md"
doc.pop("standing_authorization", None)

stations = ["P0", "ARQ", "P1", "P2", "PDR", "P3", "DDR", "P4", "P5", "P6"]
doc.update({
    "batch_id": BATCH,
    "batch_objective": OBJECTIVE,
    "owner": owner,
    "current_station": "P0",
    "phase_status": "not-started",
    "stations_active": stations,
    "iterations_per_station": {s: 0 for s in stations},
    "triggers": {"evaluated_at": None, "fired": [], "not_fired": [],
                 "record": di.TRIGGERS_RECORD},
    "artifact_homes": homes,
    "base_ref": base_ref,
    "artifacts": {},
    "decisions_log": [],
    "obsidian_synced": False,
    "created_at": datetime.datetime.now().isoformat(),
})
doc["mode"] = "full"
doc["mode_history"].append({
    "from": None, "to": "full", "date": TODAY,
    "reason": "batch %s opened by rollover from %s (closed at P6, synced); mode full, as "
              "batch-99, by the operator's kickoff answers of 2026-10-26" % (BATCH, OUTGOING)})

with open(state_path, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(doc, fh, indent=2, ensure_ascii=False)
    fh.write("\n")

flow = di._flow_home()
bdir = os.path.join(ROOT, ".dev-flow", BATCH)
os.makedirs(bdir)
req = di._template(flow, "req-template.md")
ledger = di._ledger_seed(req)
written = []
for name, dest in di.SEEDS:
    text = di._template(flow, name)
    text = (text.replace("<PROJECT>", doc["project"]).replace("<BATCH_ID>", BATCH)
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
    fh.write(ledger.replace("<PROJECT>", doc["project"]).replace("<BATCH_ID>", BATCH)
             .replace("<YYYY-MM-DD>", TODAY))
written.append("01-requirements-ledger.md")
os.makedirs(os.path.join(bdir, "03-increments"))
os.makedirs(os.path.join(bdir, "evidence"))
packet = di._template(flow, di.PACKET_SEED[0])
packet = "\n".join(
    (line.replace("<batch_id>", BATCH).replace("<NNN>", di.PACKET_SEED[2])
     .replace("<YYYY-MM-DD>", TODAY) if line.startswith(di.PACKET_HEADER_LINES) else line)
    for line in packet.split("\n") if not line.startswith(di.PACKET_EXAMPLE_ROW))
with open(os.path.join(bdir, "03-increments", di.PACKET_SEED[1]), "w", encoding="utf-8",
          newline="\n") as fh:
    fh.write(packet)
written.append("03-increments/" + di.PACKET_SEED[1])

ga = os.path.join(ROOT, ".gitattributes")
mark = ".dev-flow/%s/evidence/** -text" % BATCH
existing = open(ga, encoding="utf-8", errors="replace").read() if os.path.isfile(ga) else ""
if mark not in existing:
    with open(ga, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(("" if existing.endswith("\n") or not existing else "\n") + mark + "\n")

print("batch:", BATCH)
print("archived:", os.path.relpath(archive, ROOT))
print("base_ref:", base_ref)
print("seeded:", ", ".join(sorted(written)))
