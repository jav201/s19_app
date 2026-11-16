import copy
import json
from pathlib import Path
import shutil
import sys

from run_distributed import aggregate_run


def fixture_manifest():
    files = [f"tests/test_fixture_{number:02d}.py" for number in range(1, 17)]
    return {
        "schema": 1,
        "commit": "a" * 40,
        "tree": "b" * 40,
        "test_files": files,
        "chunks": {str(number): files[2 * (number - 1):2 * number] for number in range(1, 9)},
        "hosts": {"1": [1, 2, 3, 4], "2": [5, 6, 7, 8]},
    }


def install_fixture(root, manifest, host_results, summaries):
    for host_index in (1, 2):
        host_dir = root / f"host-{host_index}"
        host_dir.mkdir(parents=True)
        (host_dir / "host.log").write_text("fixture host log\n", encoding="utf-8")
        (host_dir / "environment.txt").write_text("fixture environment\n", encoding="utf-8")
        (host_dir / "completion.txt").write_text("fixture completion\n", encoding="utf-8")
        (host_dir / "launcher.txt").write_text("fixture launcher\n", encoding="utf-8")
        (host_dir / "full_suite_exit.txt").write_text(
            f"{host_results[host_index - 1]['returncode']}\n", encoding="ascii"
        )
        (host_dir / "summary.json").write_text(
            json.dumps(summaries[host_index - 1], indent=2) + "\n", encoding="utf-8"
        )
        for number in manifest["hosts"][str(host_index)]:
            (host_dir / f"chunk-{number:02d}.txt").write_text(
                "fixture chunk log\n", encoding="utf-8"
            )


def complete_fixture(manifest):
    summaries = []
    host_results = []
    for host_index in (1, 2):
        chunks = []
        for number in manifest["hosts"][str(host_index)]:
            files = manifest["chunks"][str(number)]
            chunks.append({
                "chunk": number,
                "test_files": files,
                "tests_files": len(files),
                "returncode": 0,
                "seconds": 0.01,
                "log": f"chunk-{number:02d}.txt",
            })
        summaries.append({
            "schema": 1,
            "host": host_index,
            "commit": manifest["commit"],
            "tree": manifest["tree"],
            "assigned_chunks": manifest["hosts"][str(host_index)],
            "complete": True,
            "returncode": 0,
            "chunks": chunks,
        })
        host_results.append({"host": host_index, "returncode": 0, "retrieval": {}})
    return host_results, summaries


def scenario(root, name, manifest, host_results, summaries, expected):
    scenario_root = root / name
    scenario_root.mkdir()
    install_fixture(scenario_root, manifest, host_results, summaries)
    aggregate = aggregate_run(scenario_root, manifest, host_results)
    actual = aggregate["global_returncode"]
    print(f"{name}: expected_exit={expected} actual_exit={actual} status={aggregate['status']}")
    if actual != expected:
        raise AssertionError(f"{name}: expected {expected}, got {actual}")
    if name == "pass_complete" and aggregate["errors"]:
        raise AssertionError(f"complete PASS fixture has errors: {aggregate['errors']}")
    if name == "pass_complete" and any(
        chunk["status"] != "PASS" for chunk in aggregate["chunks"]
    ):
        raise AssertionError("complete PASS fixture has a non-PASS chunk")
    if expected and not aggregate["errors"]:
        raise AssertionError(f"{name}: FAIL has no diagnostic")


def main():
    output = Path.cwd() / "distributed-self-test-fixtures"
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    output.mkdir()
    try:
        manifest = fixture_manifest()

        host_results, summaries = complete_fixture(manifest)
        scenario(output, "pass_complete", manifest, host_results, summaries, 0)

        host_results, summaries = complete_fixture(manifest)
        summaries[0]["chunks"].append(copy.deepcopy(summaries[0]["chunks"][1]))
        scenario(output, "known_bad_duplicate", manifest, host_results, summaries, 1)

        host_results, summaries = complete_fixture(manifest)
        del summaries[0]["chunks"][1]
        scenario(output, "known_bad_omission", manifest, host_results, summaries, 1)

        host_results, summaries = complete_fixture(manifest)
        summaries[0]["chunks"][2]["returncode"] = 1
        summaries[0]["returncode"] = 1
        host_results[0]["returncode"] = 1
        scenario(output, "known_bad_chunk_fail", manifest, host_results, summaries, 1)

        host_results, summaries = complete_fixture(manifest)
        summaries[1]["returncode"] = 1
        host_results[1]["returncode"] = 1
        scenario(output, "known_bad_host_fail", manifest, host_results, summaries, 1)

        host_results, summaries = complete_fixture(manifest)
        summaries[0]["chunks"][0]["test_files"] = []
        summaries[0]["chunks"][0]["tests_files"] = 0
        summaries[0]["chunks"][0]["returncode"] = 5
        summaries[0]["returncode"] = 1
        host_results[0]["returncode"] = 1
        scenario(output, "known_bad_empty_collection", manifest, host_results, summaries, 1)
    finally:
        shutil.rmtree(output)
    print("All aggregator fixtures behaved as required; no SSH, SCP, pytest, or app code was run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
