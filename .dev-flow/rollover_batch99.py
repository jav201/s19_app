"""Rollover 2026-10-19-batch-97 (closed at P6, synced) -> batch-99 (the read/write
integrity batch), per the operator's commission 2026-10-25. Uses devflow-init.py's
own template helpers. batch-98 is reserved for the flow-report batch (operator
decisions 2026-10-25), so this batch takes 99."""
import datetime
import importlib.util
import json
import os
import subprocess

ROOT = r"C:\Users\jjgh8\Github\s19_app"
BUNDLE = r"C:\Users\jjgh8\.claude\skills\dev-flow"
TODAY = "2026-10-25"
OUTGOING = "2026-10-19-batch-97"
BATCH = "2026-10-25-batch-99"
OBJECTIVE = ("The read/write integrity batch: every written image, report and run record "
             "says what was and was not applied. Scope: the ten HIGH findings of "
             "INVESTIGATION-read-write-integrity-2026-10-22 (H-1 S0 as image data, H-2 PATCH "
             "always ok, H-3 shared staging race, H-4 editor undo vs image, H-5 A2L encode "
             "byte order, H-6 COMPU_TAB nearest/clamp, H-7 CRC over an empty region, H-8 "
             "truncated images load ok, H-9 export path containment, H-10 run records drop "
             "dispositions); project round-trip PH-3 (save-back deletes the work copy, Save "
             "project crashes); the Code-Wire data HIGHs CW-D-4 (Bytes field decimal tokens), "
             "CW-D-7 (MAC-only export phantom byte), CW-D-10 (RAT_FUNC direction); deeper "
             "tests of the CW-U-1 fix (Load project dialog) and its sibling; and a generated "
             "synthetic fixture corpus with an independent reader as the oracle.")

spec = importlib.util.spec_from_file_location(
    "devflow_init", os.path.join(BUNDLE, "scripts", "devflow-init.py"))
di = importlib.util.module_from_spec(spec)
spec.loader.exec_module(di)

state_path = os.path.join(ROOT, ".dev-flow", "state.json")
doc = json.loads(open(state_path, encoding="utf-8").read())
assert doc["batch_id"] == OUTGOING, doc["batch_id"]
assert doc["obsidian_synced"] is True and doc["current_station"] == "P6", doc["phase_status"]

archive = os.path.join(ROOT, ".dev-flow", OUTGOING, "decisions-log.json")
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
    "standing_authorization": {"autonomous": True, "merge": True, "asked_on": TODAY,
                               "operator_words": ""},
    "obsidian_synced": False,
    "created_at": datetime.datetime.now().isoformat(),
})
doc["mode"] = "full"
doc["mode_history"].append({
    "from": None, "to": "full", "date": TODAY,
    "reason": "batch %s opened by rollover from %s (closed at P6, synced); mode full by the "
              "operator's commission (dev-flow full: P0/P1 requirements, P2 review)" % (BATCH, OUTGOING)})
doc["standing_authorization"]["operator_words"] = (
    "Operator, 2026-10-25: start the read/write integrity batch (RW H-1..H-10, PH-3, the "
    "Code-Wire data HIGHs, deeper tests of CW-U-1, the synthetic fixture corpus as the "
    "oracle). The orchestrator plans (dev-flow full: P0/P1 requirements, P2 review, the "
    "plan as an HTML page with the open backlog ordered); the IMPLEMENTATION of each "
    "increment is delegated to Kimi CLI with the Kimi K2.8 model, in an isolated worktree; "
    "an independent review (code-reviewer / qa) checks what Kimi delivers. Authorization: "
    "autonomous with exceptions (stop on a HIGH finding or an operator decision); commit "
    "and push to main at each close; max 4 source files per increment; no operator name "
    "and region extraction described only as memory-region extraction; do not commit prototypes/.")

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
