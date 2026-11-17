from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime


def redact(text: str, repo: Path, runtime: Path) -> str:
    home = Path.home().resolve()
    replacements = [
        (repo, "[WORKTREE]"),
        (runtime, "[RUNTIME]"),
        (home, "[USER_HOME]"),
    ]
    for path, label in replacements:
        for value in dict.fromkeys((str(path), path.as_posix(), str(path).replace("\\", "\\\\"))):
            text = text.replace(value, label)
    text = text.replace(home.name, "[ACCOUNT]")
    text = re.sub(r"\s+hostname=\"[^\"]*\"", "", text)
    text = re.sub(r"pytest-of-[^/\\\s]+", "pytest-tmp", text)
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("nodes", nargs="+")
    args = parser.parse_args()
    repo = args.repo.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    python = Path.home() / "anaconda3" / "python.exe"
    started = datetime.now().astimezone().isoformat(timespec="seconds")
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="b103s0-") as temporary:
        runtime = Path(temporary).resolve()
        for name in ("home", "config", "data", "cache", "local", "tmp", "cases"):
            (runtime / name).mkdir()
        env = os.environ.copy()
        for name in (
            "CI", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "B103_HOST_PLATFORM", "DISPLAY",
            "PYTEST_ADDOPTS", "NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE",
        ):
            env.pop(name, None)
        env.update({
            "HOME": str(runtime / "home"),
            "XDG_CONFIG_HOME": str(runtime / "config"),
            "XDG_DATA_HOME": str(runtime / "data"),
            "XDG_CACHE_HOME": str(runtime / "cache"),
            "LOCALAPPDATA": str(runtime / "local"),
            "TMPDIR": str(runtime / "tmp"),
            "TMP": str(runtime / "tmp"),
            "TEMP": str(runtime / "tmp"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "TERM": "xterm-256color",
            "COLORTERM": "truecolor",
        })
        raw_log = runtime / "pytest.log"
        raw_junit = runtime / "junit.xml"
        command = [
            str(python), "-I", "-B", "-m", "pytest", "-n0", "-p", "no:cacheprovider",
            "--color=no", "--basetemp", str(runtime / "cases"), "--junitxml", str(raw_junit),
            *args.nodes,
        ]
        with raw_log.open("wb") as stream:
            completed = subprocess.run(
                command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                stdout=stream, stderr=subprocess.STDOUT, check=False,
            )
        log = redact(raw_log.read_text(encoding="utf-8", errors="replace"), repo, runtime)
        (out / "pytest.log").write_text(log, encoding="utf-8", newline="\n")
        if raw_junit.exists():
            junit = redact(raw_junit.read_text(encoding="utf-8", errors="replace"), repo, runtime)
            (out / "junit.xml").write_text(junit, encoding="utf-8", newline="\n")
        finished = datetime.now().astimezone().isoformat(timespec="seconds")
        environment = (
            f"started={started}\nfinished={finished}\nHEAD={head}\n"
            "platform=Windows local; Python 3.12.7\n"
            "command=$HOME/anaconda3/python.exe -I -B -m pytest -n0 -p no:cacheprovider "
            "--color=no --basetemp=<RUNTIME>/cases --junitxml=<artifact> <nodes>\n"
            f"nodes={' '.join(args.nodes)}\nstdin=closed\n"
            "bytecode=PYTHONDONTWRITEBYTECODE=1 and -B; pytest cacheprovider disabled\n"
            "isolation=fresh short runtime for HOME,XDG_CONFIG_HOME,XDG_DATA_HOME,XDG_CACHE_HOME,"
            "LOCALAPPDATA,TMPDIR,TMP,TEMP and pytest basetemp\n"
            "clipboard=CI,GITHUB_ACTIONS,RUNNER_ENVIRONMENT,B103_HOST_PLATFORM,DISPLAY unset\n"
            "colour=NO_COLOR,CLICOLOR,CLICOLOR_FORCE unset; TERM=xterm-256color; COLORTERM=truecolor\n"
            f"exit_code={completed.returncode}\n"
        )
        (out / "environment.txt").write_text(environment, encoding="utf-8", newline="\n")
        (out / "exit_code.txt").write_text(f"{completed.returncode}\n", encoding="ascii")
        print(f"HEAD={head} exit={completed.returncode} out={out}")
        print("\n".join(log.splitlines()[-12:]))
        return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
