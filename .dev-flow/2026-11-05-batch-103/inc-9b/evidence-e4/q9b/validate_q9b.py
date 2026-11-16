from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REQUIRED_GAP = {
    "key",
    "action_move",
    "selection_changed",
    "enqueue_decode",
    "active_job",
    "run_job",
    "paint_busy",
}


def validate_text(text: str, family: str, label: str, run: str) -> list[str]:
    errors: list[str] = []
    if len(re.findall(r"(?m)^Q9B_RC=(\d+)$", text)) != 1:
        errors.append("missing or repeated process exit marker")
    elif not re.search(r"(?m)^Q9B_RC=0$", text):
        errors.append("pytest process did not exit 0")
    if not re.search(r"(?m)=+ 1 passed in [0-9.]+s.*=+$", text):
        errors.append("missing one-test pytest PASS summary")
    if "Q9B_NOT_MEASURED_LOAD" in text:
        errors.append("host never became quiet")
    if not re.search(r"(?m)^Q9B_LOAD1=[0-9.]+$", text):
        errors.append("missing pre-run one-minute load")

    if family == "gap":
        payloads = re.findall(r"Q9BGAP (\{.*\})", text)
        if len(payloads) != 1:
            errors.append(f"expected one Q9BGAP payload, found {len(payloads)}")
        else:
            try:
                payload = json.loads(payloads[0])
            except json.JSONDecodeError as exc:
                errors.append(f"invalid Q9BGAP JSON: {exc}")
            else:
                if payload.get("scenario") != label or payload.get("run") != run:
                    errors.append("Q9BGAP identity does not match the run")
                if payload.get("error") is not None or payload.get("missing"):
                    errors.append("Q9BGAP reports an error or missing markers")
                markers = set(payload.get("markers", []))
                event_markers = {event.get("m") for event in payload.get("events", [])}
                if not REQUIRED_GAP <= markers or not REQUIRED_GAP <= event_markers:
                    errors.append("Q9BGAP lacks one or more required event markers")
    elif family == "fx9c":
        payloads = re.findall(r"FX9CPARTS (\{.*\})", text)
        if len(payloads) != 1:
            errors.append(f"expected one FX9CPARTS payload, found {len(payloads)}")
        else:
            try:
                payload = json.loads(payloads[0])
            except json.JSONDecodeError as exc:
                errors.append(f"invalid FX9CPARTS JSON: {exc}")
            else:
                parts = payload.get("parts", [])
                if not parts or not any(part[0] == "_stage_bench_record" for part in parts):
                    errors.append("FX9CPARTS lacks the stage block and refresh parts")
                if run == "02":
                    block = payload.get("refresh_block")
                    if not isinstance(block, (int, float)) or block < 0:
                        errors.append("corrected FX9CPARTS lacks the whole refresh block")
                    names = {part[0] for part in parts}
                    required = {"record_done", "refresh_entries", "serialize_change_document", "set_document"}
                    if "Q9B_SIDE=tip" in text:
                        required.add("_patch_refresh_tail")
                    if not required <= names:
                        errors.append(f"corrected FX9CPARTS lacks {sorted(required - names)}")
    elif family in {"oe", "timing"} and label != "97_1":
        requirement = label.replace("_", "/", 1)
        pattern = (
            r"(?m)^(?:LOW )?-?[0-9.]+%  [0-9.]+ s / [0-9.]+ s  "
            + re.escape("R-PE-BENCH." + requirement)
            + r"(?: |$)"
        )
        if not re.search(pattern, text):
            errors.append("missing the node's QC-TM measured margin")
    return errors


def self_test() -> int:
    bad = [
        ("", "oe", "29_1", "01"),
        ("Q9B_RC=124\nQ9B_LOAD1=0.10\n", "oe", "29_1", "01"),
        (
            "Q9B_RC=0\nQ9B_LOAD1=0.10\n===== 1 passed in 1.00s =====\n"
            "Q9BGAP {\"scenario\":\"a\",\"run\":\"01\",\"error\":null,"
            "\"missing\":[],\"markers\":[],\"events\":[]}\n",
            "gap",
            "a",
            "01",
        ),
    ]
    for index, args in enumerate(bad, 1):
        errors = validate_text(*args)
        if not errors:
            print(f"VALIDATOR_RED_{index}=SURVIVED")
            return 1
        print(f"VALIDATOR_RED_{index}=KILLED: {errors[0]}")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()
    path = Path(sys.argv[1])
    errors = validate_text(path.read_text(encoding="utf-8"), *sys.argv[2:5])
    if errors:
        for error in errors:
            print(f"Q9B_VALID_ERROR={error}")
        print("Q9B_VALID=FAIL")
        return 1
    print("Q9B_VALID=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
