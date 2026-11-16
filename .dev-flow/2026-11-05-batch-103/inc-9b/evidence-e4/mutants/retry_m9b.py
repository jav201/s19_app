"""Retry only invalid M9b baselines in new copies, preserving every first attempt."""

import json
import os
from pathlib import Path
import shutil
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path.home() / "work" / "zq-m9b"
sys.path.insert(0, str(ROOT))
import m9b_driver as driver  # noqa: E402

GROUPS = ("G03", "G10", "G19")


def strict_preflight(group_id, phase):
    deadline = time.monotonic() + 1200
    while True:
        load = driver.load_one()
        jobs = driver.other_test_jobs()
        if load < 0.2 and not jobs:
            return {"load_one": load, "other_test_jobs": 0, "uptime": driver.uptime()}
        if time.monotonic() >= deadline:
            raise driver.HostUnavailable(f"retry preflight did not clear for {group_id} {phase}")
        time.sleep(15)


def preserve_first_attempt(group_id):
    old_group = ROOT / "groups" / group_id
    saved_group = ROOT / "groups" / f"{group_id}-attempt1"
    if saved_group.exists():
        raise RuntimeError(f"retry target already exists for {group_id}")
    old_group.rename(saved_group)
    for phase in ("baseline", "mutant"):
        source = driver.OUT / f"{group_id}-{phase}.txt"
        if source.exists():
            source.rename(driver.OUT / f"{group_id}-attempt1-{phase}.txt")


def main():
    if not (driver.OUT / "DONE").exists():
        raise RuntimeError("primary battery is not complete")
    if not (ROOT / "driver.pid").exists():
        raise RuntimeError("primary driver record is absent")
    payload = json.loads((driver.OUT / "results.json").read_text(encoding="utf-8"))
    driver.write_text(
        driver.OUT / "results-attempt1.json",
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
    )
    shutil.copyfile(driver.OUT / "summary.tsv", driver.OUT / "summary-attempt1.tsv")
    driver.require_quiet_exclusive = strict_preflight
    lines = [f"DATE {driver.now()}", "RETRY_GROUPS G03 G10 G19", "PREFLIGHT_LOAD_LT 0.20"]
    for group_id in GROUPS:
        preserve_first_attempt(group_id)
        result = driver.run_group(group_id)
        payload["results"] = [
            result if old["group"] == group_id else old
            for old in payload["results"]
        ]
        driver.write_summary(payload["results"])
        verdicts = [c["verdict"] for c in result["controls"]]
        lines.append(f"{group_id} RETRY_VERDICTS {','.join(verdicts)}")
        print(f"RETRY_DONE {group_id} {verdicts}", flush=True)
    driver.write_text(driver.OUT / "retries.txt", "\n".join(lines) + "\n")
    driver.write_text(driver.OUT / "RETRIES-DONE", f"DATE {driver.now()}\nGROUPS {len(GROUPS)}\n")


if __name__ == "__main__":
    main()
