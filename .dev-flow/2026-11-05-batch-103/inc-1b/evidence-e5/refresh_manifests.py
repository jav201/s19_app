from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).resolve().parent
MANIFEST_NAME = "SHA256SUMS.txt"
ENTRY = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)$")


def manifest_paths() -> list[Path]:
    paths = {EVIDENCE / MANIFEST_NAME}
    paths.update(
        path
        for path in EVIDENCE.rglob("SHA256SUMS*")
        if path.is_file()
    )
    return sorted(paths)


def expected_entries(directory: Path) -> list[tuple[str, str]]:
    entries = []
    for path in sorted(directory.iterdir(), key=lambda path: path.name):
        if not path.is_file() or path.name.startswith("SHA256SUMS"):
            continue
        entries.append((path.name, hashlib.sha256(path.read_bytes()).hexdigest()))
    return entries


def expected_bytes(directory: Path) -> bytes:
    return (
        "\n".join(f"{digest}  {name}" for name, digest in expected_entries(directory))
        + "\n"
    ).encode("utf-8")


def _validate_existing(manifest: Path) -> None:
    if not manifest.is_file():
        return
    seen = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = ENTRY.fullmatch(line)
        if not match:
            raise ValueError(f"invalid manifest entry: {manifest}")
        name = match.group(2)
        target = manifest.parent / name
        if name in seen or target.parent != manifest.parent or not target.is_file():
            raise FileNotFoundError(f"invalid or missing manifest target: {manifest}: {name}")
        seen.add(name)


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def verify_all() -> bool:
    valid = True
    total_files = 0
    manifests = manifest_paths()
    for manifest in manifests:
        if not manifest.is_file():
            print(f"MANIFEST_VERIFY FAIL {_relative(manifest)} missing")
            valid = False
            continue
        expected = expected_entries(manifest.parent)
        expected_map = dict(expected)
        actual_map = {}
        malformed = False
        for line in manifest.read_text(encoding="utf-8").splitlines():
            match = ENTRY.fullmatch(line)
            if not match:
                malformed = True
                break
            digest, name = match.groups()
            if name in actual_map:
                malformed = True
                break
            target = manifest.parent / name
            if target.parent != manifest.parent or not target.is_file():
                malformed = True
                break
            actual_map[name] = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual_map[name] != digest:
                valid = False
        exact_bytes = manifest.read_bytes() == expected_bytes(manifest.parent)
        if malformed or actual_map != expected_map or not exact_bytes:
            valid = False
            print(
                f"MANIFEST_VERIFY FAIL {_relative(manifest)} "
                f"expected_files={len(expected_map)} actual_files={len(actual_map)}"
            )
        else:
            print(
                f"MANIFEST_VERIFY PASS {_relative(manifest)} "
                f"files={len(expected_map)} sha256={hashlib.sha256(manifest.read_bytes()).hexdigest()}"
            )
        total_files += len(expected_map)
    print(
        f"MANIFEST_VERIFY_RESULT {'PASS' if valid else 'FAIL'} "
        f"manifests={len(manifests)} files={total_files}"
    )
    return valid


def refresh_all() -> bool:
    manifests = manifest_paths()
    for manifest in manifests:
        _validate_existing(manifest)
    for manifest in manifests:
        data = expected_bytes(manifest.parent)
        manifest.write_bytes(data)
        print(
            f"MANIFEST_WRITE {_relative(manifest)} "
            f"files={len(expected_entries(manifest.parent))} "
            f"sha256={hashlib.sha256(data).hexdigest()}"
        )
    return verify_all()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify stored bytes without writing")
    args = parser.parse_args()
    return 0 if (verify_all() if args.check else refresh_all()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
