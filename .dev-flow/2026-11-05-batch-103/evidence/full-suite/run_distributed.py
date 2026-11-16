from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from collections import Counter
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[4]
SOURCE_REF = "origin/b103-final-integration"
BUNDLE_REF = "refs/remotes/origin/b103-final-integration"
CHUNK_COUNT = 8
HOST_COUNT = 2
HOST_FILES = (
    "summary.json",
    "environment.txt",
    "completion.txt",
    "full_suite_exit.txt",
    "launcher.txt",
)


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def git(repo, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(repo), *arguments],
        text=True,
        encoding="utf-8",
        errors="strict",
        stdin=subprocess.DEVNULL,
    ).strip()


def partition_files(files):
    ordered = sorted(files)
    if len(ordered) < CHUNK_COUNT or len(ordered) != len(set(ordered)):
        raise RuntimeError("whole-suite census must contain unique files for eight chunks")
    size = (len(ordered) + CHUNK_COUNT - 1) // CHUNK_COUNT
    chunks = [ordered[index:index + size] for index in range(0, len(ordered), size)]
    if len(chunks) != CHUNK_COUNT or any(not chunk for chunk in chunks):
        raise RuntimeError("could not construct exactly eight non-empty chunks")
    flattened = [name for chunk in chunks for name in chunk]
    if Counter(flattened) != Counter(ordered):
        raise RuntimeError("chunking does not preserve exact whole-suite coverage")
    return chunks


def build_manifest(repo, revision):
    source_commit = git(repo, "rev-parse", "--verify", SOURCE_REF + "^{commit}")
    commit = git(repo, "rev-parse", "--verify", revision + "^{commit}")
    ancestry = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, source_commit],
        stdin=subprocess.DEVNULL,
    ).returncode
    if ancestry != 0:
        raise RuntimeError(f"requested commit is not contained in {SOURCE_REF}")
    tree = git(repo, "rev-parse", commit + "^{tree}")
    names = git(repo, "ls-tree", "-r", "--name-only", commit, "--", "tests").splitlines()
    files = sorted(
        name for name in names
        if PurePosixPath(name).name.startswith("test_") and name.endswith(".py")
    )
    chunks = partition_files(files)
    manifest = {
        "schema": 1,
        "source_ref": SOURCE_REF,
        "commit": commit,
        "tree": tree,
        "test_files": files,
        "chunks": {str(number): chunk for number, chunk in enumerate(chunks, 1)},
        "hosts": {"1": [1, 2, 3, 4], "2": [5, 6, 7, 8]},
    }
    return manifest


def is_tmp_path(path):
    resolved = Path(path).resolve()
    return resolved == Path("/tmp") or Path("/tmp") in resolved.parents


def validate_remote_root(value):
    path = PurePosixPath(value)
    if not value or value.startswith("~") or "\n" in value or "\r" in value:
        raise ValueError("remote root must be a literal path without tilde expansion")
    if ".." in path.parts:
        raise ValueError("remote root cannot contain '..'")
    if path.is_absolute() and (path == PurePosixPath("/tmp") or PurePosixPath("/tmp") in path.parents):
        raise ValueError("remote root cannot be under /tmp")
    return path


def create_bundle(repo, output, manifest):
    bundle = output / "source.bundle"
    with (output / "bundle-create.txt").open("wb") as stream:
        subprocess.run(
            ["git", "-C", str(repo), "bundle", "create", str(bundle), SOURCE_REF],
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=True,
        )
    heads = subprocess.check_output(
        ["git", "-C", str(repo), "bundle", "list-heads", str(bundle)],
        text=True,
        encoding="utf-8",
        stdin=subprocess.DEVNULL,
    ).splitlines()
    if not any(line.split()[0] == manifest["commit"] for line in heads if line.split()):
        raise RuntimeError("bundle does not contain the requested commit")
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (output / "source.bundle.sha256").write_text(
        f"{digest}  source.bundle\n", encoding="ascii"
    )
    return bundle, digest


def run_logged(command, log, append=False):
    with log.open("ab" if append else "wb") as stream:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
        ).returncode


def ssh_command(target, script):
    return ["ssh", "-o", "BatchMode=yes", target, script]


def scp_command(target, sources, remote_destination):
    return ["scp", "-p", "--", *map(str, sources), f"{target}:{remote_destination}"]


def retrieve(target, remote_run, host_dir, chunk_numbers):
    retrieval = {}
    with (host_dir / "retrieval.txt").open("wb") as stream:
        for name in HOST_FILES + tuple(f"chunk-{number:02d}.txt" for number in chunk_numbers):
            remote = f"{shlex.quote(str(PurePosixPath(remote_run) / 'out' / name))}"
            command = ["scp", "-p", "--", f"{target}:{remote}", str(host_dir / name)]
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.STDOUT,
            )
            retrieval[name] = completed.returncode
    return retrieval


def run_host(target, python, host_index, remote_run, repo, output, manifest, bundle, digest):
    host_dir = output / f"host-{host_index}"
    host_dir.mkdir()
    host_log = host_dir / "host.log"
    worker = Path(__file__).resolve().with_name("distributed_remote.py")
    quoted_root = shlex.quote(str(PurePosixPath(remote_run).parent))
    quoted_run = shlex.quote(str(remote_run))
    prepare = (
        "set -eu; umask 077; "
        f"mkdir -p -- {quoted_root}; mkdir -- {quoted_run}"
    )
    result = {"host": host_index, "returncode": 255, "retrieval": {}}
    try:
        returncode = run_logged(ssh_command(target, prepare), host_log)
        if returncode == 0:
            returncode = run_logged(
                scp_command(
                    target,
                    (bundle, output / "manifest.json", worker),
                    shlex.quote(str(remote_run)) + "/",
                ),
                host_log,
                append=True,
            )

        if returncode == 0:
            q = shlex.quote
            run = str(remote_run)
            command = (
                "set -u; umask 077; "
                f"cd -- {q(run)} || exit 65; "
                f"printf '%s  source.bundle\\n' {q(digest)} | sha256sum -c - || exit 65; "
                "git init --quiet repo || exit 65; "
                "git -C repo remote add origin \"$PWD/source.bundle\" || exit 65; "
                f"git -C repo fetch --quiet origin {q(BUNDLE_REF)} || exit 65; "
                f"git -C repo checkout --detach --quiet {q(manifest['commit'])} || exit 65; "
                "mkdir -p out/tmp isolation/home/config isolation/home/data "
                "isolation/home/cache isolation/home/local || exit 65; "
                "env -i "
                "PATH=/usr/local/bin:/usr/bin:/bin "
                "LANG=C.UTF-8 LC_ALL=C.UTF-8 "
                "HOME=\"$PWD/isolation/home\" "
                "XDG_CONFIG_HOME=\"$PWD/isolation/home/config\" "
                "XDG_DATA_HOME=\"$PWD/isolation/home/data\" "
                "XDG_CACHE_HOME=\"$PWD/isolation/home/cache\" "
                "LOCALAPPDATA=\"$PWD/isolation/home/local\" "
                "TMPDIR=\"$PWD/out/tmp\" "
                "PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONUTF8=1 "
                "GIT_TERMINAL_PROMPT=0 "
                f"{q(python)} -I -B distributed_remote.py "
                "--repo \"$PWD/repo\" --out \"$PWD/out\" --manifest \"$PWD/manifest.json\" "
                f"--host-index {host_index} "
                "> out/launcher.txt 2>&1 < /dev/null; "
                "rc=$?; exit \"$rc\""
            )
            returncode = run_logged(ssh_command(target, command), host_log, append=True)
        result["returncode"] = returncode
    except Exception as error:
        (host_dir / "host-exception.txt").write_text(
            f"{type(error).__name__}: {error}\n", encoding="utf-8"
        )
        result["returncode"] = 255
    try:
        result["retrieval"] = retrieve(
            target, remote_run, host_dir, manifest["hosts"][str(host_index)]
        )
    except Exception as error:
        names = HOST_FILES + tuple(
            f"chunk-{number:02d}.txt" for number in manifest["hosts"][str(host_index)]
        )
        result["retrieval"] = {name: 255 for name in names}
        with (host_dir / "host-exception.txt").open("a", encoding="utf-8") as stream:
            stream.write(f"retrieval {type(error).__name__}: {error}\n")
    write_json(host_dir / "host-result.json", result)
    return result


def aggregate_run(output, manifest, host_results):
    errors = []
    entries = []
    hosts = []
    expected_chunks = manifest["chunks"]
    for result in host_results:
        host_index = result["host"]
        host_dir = output / f"host-{host_index}"
        host_errors = []
        if result["returncode"] != 0:
            host_errors.append(f"host {host_index} exited {result['returncode']}")
        for name, returncode in result.get("retrieval", {}).items():
            if returncode != 0:
                host_errors.append(f"host {host_index} could not retrieve {name}")
        if not (host_dir / "host.log").is_file():
            host_errors.append(f"host {host_index} has no launcher log")

        summary_path = host_dir / "summary.json"
        summary = None
        if not summary_path.is_file():
            host_errors.append(f"host {host_index} has no summary")
        else:
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                host_errors.append(f"host {host_index} summary is unreadable: {error}")
        if summary is not None:
            if summary.get("host") != host_index:
                host_errors.append(f"host {host_index} summary has wrong identity")
            if summary.get("commit") != manifest["commit"] or summary.get("tree") != manifest["tree"]:
                host_errors.append(f"host {host_index} ran a different commit or tree")
            if summary.get("complete") is not True:
                host_errors.append(f"host {host_index} summary is incomplete")
            if summary.get("returncode") != result["returncode"]:
                host_errors.append(f"host {host_index} returncode disagrees with its summary")
            chunks = summary.get("chunks")
            if not isinstance(chunks, list):
                host_errors.append(f"host {host_index} summary has no chunk list")
            else:
                if len(chunks) != 4:
                    host_errors.append(f"host {host_index} summary does not contain four chunks")
                for item in chunks:
                    if isinstance(item, dict):
                        entries.append((host_index, item))
                    else:
                        host_errors.append(f"host {host_index} has a malformed chunk entry")
        exit_path = host_dir / "full_suite_exit.txt"
        try:
            recorded_exit = int(exit_path.read_text(encoding="ascii").strip())
            if recorded_exit != result["returncode"]:
                host_errors.append(f"host {host_index} exit file disagrees with SSH")
        except (OSError, ValueError):
            host_errors.append(f"host {host_index} has no valid exit file")
        errors.extend(host_errors)
        hosts.append({**result, "errors": host_errors})

    by_chunk = {}
    for host_index, item in entries:
        number = item.get("chunk")
        if isinstance(number, int) and not isinstance(number, bool):
            by_chunk.setdefault(number, []).append((host_index, item))
        else:
            errors.append(f"host {host_index} has a chunk with invalid identity")

    aggregate_chunks = []
    for number in range(1, CHUNK_COUNT + 1):
        matches = by_chunk.get(number, [])
        row = {"chunk": number, "returncode": None, "status": "FAIL"}
        if not matches:
            errors.append(f"chunk {number} is missing")
        elif len(matches) > 1:
            errors.append(f"chunk {number} is duplicated")
            row["hosts"] = [host for host, _ in matches]
        else:
            host_index, item = matches[0]
            error_count = len(errors)
            row.update({
                "host": host_index,
                "returncode": item.get("returncode"),
                "tests_files": item.get("tests_files"),
                "test_files": item.get("test_files"),
                "seconds": item.get("seconds"),
                "log": f"host-{host_index}/chunk-{number:02d}.txt",
            })
            expected_files = expected_chunks[str(number)]
            if number not in manifest["hosts"][str(host_index)]:
                errors.append(f"chunk {number} was reported by the wrong host")
            if item.get("test_files") != expected_files:
                errors.append(f"chunk {number} file coverage differs from the manifest")
            if item.get("tests_files") != len(expected_files) or not expected_files:
                errors.append(f"chunk {number} has an empty or invalid collection census")
            returncode = item.get("returncode")
            if not isinstance(returncode, int) or isinstance(returncode, bool):
                errors.append(f"chunk {number} has no integer returncode")
            elif returncode != 0:
                errors.append(f"chunk {number} exited {returncode}")
            if item.get("log") != f"chunk-{number:02d}.txt":
                errors.append(f"chunk {number} has an invalid log name")
            if not (output / row["log"]).is_file():
                errors.append(f"chunk {number} log is missing")
            if len(errors) == error_count:
                row["status"] = "PASS"
        aggregate_chunks.append(row)

    for number in sorted(set(by_chunk) - set(range(1, CHUNK_COUNT + 1))):
        errors.append(f"unexpected chunk {number} was reported")
    status = "PASS" if not errors else "FAIL"
    global_returncode = 0 if not errors else 1
    aggregate = {
        "schema": 1,
        "commit": manifest["commit"],
        "tree": manifest["tree"],
        "expected_test_files": len(manifest["test_files"]),
        "hosts": hosts,
        "chunks": aggregate_chunks,
        "errors": errors,
        "status": status,
        "global_returncode": global_returncode,
    }
    write_json(output / "summary.json", aggregate)
    return aggregate


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Run the exact eight-chunk suite on two Linux SSH hosts. "
            "Each host runs four chunks sequentially; both hosts run concurrently. "
            "No whole-suite timeout is applied."
        )
    )
    parser.add_argument(
        "--host",
        dest="hosts",
        action="append",
        nargs=2,
        metavar=("SSH_TARGET", "PYTHON"),
        required=True,
        help="SSH target and absolute remote Python; repeat exactly twice",
    )
    parser.add_argument("--commit", default=SOURCE_REF, help="commit contained in " + SOURCE_REF)
    parser.add_argument("--output", type=Path, required=True, help="new local evidence directory, outside /tmp")
    parser.add_argument("--remote-root", default="b103-distributed-runs", help="new run's parent on each remote")
    parser.add_argument("--run-id", help="collision-resistant run name; default: UTC time plus random suffix")
    parser.add_argument("--repo", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if len(args.hosts) != HOST_COUNT:
        parser.error("exactly two --host SSH_TARGET PYTHON pairs are required")
    targets = [item[0] for item in args.hosts]
    if len(set(targets)) != HOST_COUNT:
        parser.error("SSH targets must be distinct")
    for target, python in args.hosts:
        if not target or target.startswith("-") or any(char in target for char in "\r\n"):
            parser.error("invalid SSH target")
        if not PurePosixPath(python).is_absolute() or any(char in python for char in "\r\n"):
            parser.error("remote Python paths must be absolute")
    try:
        args.remote_root = validate_remote_root(args.remote_root)
    except ValueError as error:
        parser.error(str(error))
    if is_tmp_path(args.output):
        parser.error("local output cannot be under /tmp")
    if args.output.exists():
        parser.error("local output already exists; refusing to overlap runs")
    args.run_id = args.run_id or (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    )
    if not args.run_id.replace("-", "").replace("_", "").replace(".", "").isalnum():
        parser.error("run id may contain only alphanumerics, dot, underscore, and dash")
    return args


def main():
    args = parse_args()
    repo = args.repo.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = build_manifest(repo, args.commit)
    write_json(args.output / "manifest.json", manifest)
    bundle, digest = create_bundle(repo, args.output, manifest)
    remote_run = args.remote_root / args.run_id

    with ThreadPoolExecutor(max_workers=HOST_COUNT) as executor:
        futures = [
            executor.submit(
                run_host,
                target,
                python,
                host_index,
                remote_run,
                repo,
                args.output,
                manifest,
                bundle,
                digest,
            )
            for host_index, (target, python) in enumerate(args.hosts, 1)
        ]
        host_results = [future.result() for future in futures]
    aggregate = aggregate_run(args.output, manifest, host_results)
    print(json.dumps({
        "status": aggregate["status"],
        "global_returncode": aggregate["global_returncode"],
        "summary": str(args.output / "summary.json"),
    }))
    return aggregate["global_returncode"]


if __name__ == "__main__":
    raise SystemExit(main())
