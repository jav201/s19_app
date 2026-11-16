from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time


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


def verify_repo(repo, manifest):
    head = git(repo, "rev-parse", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    status = git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if head != manifest["commit"]:
        raise RuntimeError("HEAD mismatch")
    if tree != manifest["tree"]:
        raise RuntimeError("tree mismatch")
    if status:
        raise RuntimeError("clone is not clean")

    code = (
        "import sys; sys.path.insert(0, '.'); import s19_app; "
        "print(s19_app.__file__, flush=True)"
    )
    app_file = subprocess.check_output(
        [sys.executable, "-I", "-B", "-c", code],
        cwd=repo,
        env=os.environ,
        text=True,
        encoding="utf-8",
        errors="strict",
        stdin=subprocess.DEVNULL,
    ).strip()
    expected_app = (repo / "s19_app" / "__init__.py").resolve()
    imported_app = Path(app_file)
    if not imported_app.is_absolute():
        imported_app = repo / imported_app
    if imported_app.resolve() != expected_app:
        raise RuntimeError("s19_app was imported outside the checkout")
    return {"head": head, "tree": tree, "app_file": app_file}


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Internal per-host worker for run_distributed.py")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--host-index", type=int, choices=(1, 2), required=True)
    args = parser.parse_args()

    repo = args.repo.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    assigned = manifest["hosts"][str(args.host_index)]
    summary = {
        "schema": 1,
        "host": args.host_index,
        "commit": manifest["commit"],
        "tree": manifest["tree"],
        "assigned_chunks": assigned,
        "complete": False,
        "returncode": 1,
        "chunks": [],
    }
    summary_path = out / "summary.json"
    write_json(summary_path, summary)
    (out / "host-error.txt").write_text("", encoding="utf-8")

    try:
        if len(assigned) != 4 or len(set(assigned)) != 4:
            raise RuntimeError("each host must own four distinct chunks")
        all_chunks = [str(number) for number in range(1, 9)]
        if sorted(manifest["chunks"]) != all_chunks:
            raise RuntimeError("manifest does not contain exactly eight chunks")
        manifest_files = [name for number in all_chunks for name in manifest["chunks"][number]]
        if not manifest_files or sorted(manifest_files) != sorted(manifest["test_files"]):
            raise RuntimeError("manifest coverage mismatch")
        if len(manifest_files) != len(set(manifest_files)):
            raise RuntimeError("manifest contains duplicate test files")

        checkout_files = sorted(
            str(path.relative_to(repo))
            for path in (repo / "tests").rglob("test_*.py")
            if path.is_file()
        )
        if checkout_files != sorted(manifest["test_files"]):
            raise RuntimeError("checkout test-file census mismatch")

        verified = verify_repo(repo, manifest)
        python_version = subprocess.check_output(
            [sys.executable, "--version"],
            text=True,
            encoding="utf-8",
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        ).strip()
        environment = (
            f"date={datetime.now(timezone.utc).isoformat()}\n"
            f"HEAD={verified['head']}\n"
            f"tree={verified['tree']}\n"
            "status=clean\n"
            f"python={python_version}\n"
            f"s19_app.__file__={verified['app_file']}\n"
            f"chunks={','.join(str(number) for number in assigned)} sequential_per_host=yes "
            "stdin=DEVNULL bytecode=disabled pytest_cache=disabled whole_suite_timeout=none\n"
            "isolation=HOME,XDG_CONFIG_HOME,XDG_DATA_HOME,XDG_CACHE_HOME,LOCALAPPDATA,TMPDIR; "
            "DISPLAY,WAYLAND_DISPLAY unset; UTF-8 enabled\n"
        )
        (out / "environment.txt").write_text(environment, encoding="utf-8")

        for number in assigned:
            chunk = manifest["chunks"][str(number)]
            if not chunk:
                raise RuntimeError(f"chunk {number} is empty")
            log = out / f"chunk-{number:02d}.txt"
            code = (
                "import sys; sys.path.insert(0, '.'); import s19_app; "
                "print(s19_app.__file__, flush=True); import pytest; "
                f"raise SystemExit(pytest.main(['-q', '-p', 'no:cacheprovider', *{chunk!r}]))"
            )
            started = time.monotonic()
            with log.open("wb") as stream:
                completed = subprocess.run(
                    [sys.executable, "-I", "-B", "-c", code],
                    cwd=repo,
                    env=os.environ,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                )
            item = {
                "chunk": number,
                "test_files": chunk,
                "tests_files": len(chunk),
                "returncode": completed.returncode,
                "seconds": round(time.monotonic() - started, 2),
                "log": log.name,
            }
            summary["chunks"].append(item)
            summary["returncode"] = 0 if all(
                entry["returncode"] == 0 for entry in summary["chunks"]
            ) else 1
            write_json(summary_path, summary)

        verify_repo(repo, manifest)
        summary["complete"] = True
        summary["returncode"] = 0 if all(
            entry["returncode"] == 0 for entry in summary["chunks"]
        ) else 1
        write_json(summary_path, summary)
    except Exception as error:
        summary["complete"] = False
        summary["returncode"] = 1
        write_json(summary_path, summary)
        (out / "host-error.txt").write_text(
            f"{type(error).__name__}: {error}\n", encoding="utf-8"
        )

    (out / "full_suite_exit.txt").write_text(f"{summary['returncode']}\n", encoding="utf-8")
    (out / "completion.txt").write_text(
        f"date={datetime.now(timezone.utc).isoformat()}\n"
        f"HEAD={git(repo, 'rev-parse', 'HEAD')}\n"
        f"full_suite_exit={summary['returncode']}\n",
        encoding="utf-8",
    )
    print(json.dumps({"host": args.host_index, "returncode": summary["returncode"]}), flush=True)
    return summary["returncode"]


if __name__ == "__main__":
    raise SystemExit(main())
