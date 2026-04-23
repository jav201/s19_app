from __future__ import annotations

from pathlib import Path

from s19_app import cli


def test_version_command_does_not_load_file(monkeypatch):
    called = {"load": False}

    def _fail_load(_path: str):
        called["load"] = True
        raise AssertionError("version command should not load an S19 file")

    monkeypatch.setattr(cli, "_load_s19", _fail_load)
    exit_code = cli.main(["version"])
    assert exit_code == 0
    assert called["load"] is False


def test_build_parser_wires_save_and_patch_flags():
    parser = cli.build_parser()
    save_args = parser.parse_args(["save", "firmware.s19", "--output", "patched.s19"])
    patch_args = parser.parse_args(
        ["patch-str", "firmware.s19", "--addr", "0x1000", "--text", "AB", "--save-as", "out.s19"]
    )

    assert save_args.command == "save"
    assert save_args.file == "firmware.s19"
    assert save_args.output == "patched.s19"
    assert patch_args.command == "patch-str"
    assert patch_args.save_as == "out.s19"


def test_write_s19_serializes_records(tmp_path: Path):
    class FakeRecord:
        def __str__(self) -> str:
            return "S107000001020304EE"

    class FakeS19:
        records = [FakeRecord(), FakeRecord()]

    out = tmp_path / "patched.s19"
    cli._write_s19(str(out), FakeS19())  # type: ignore[arg-type]
    assert out.read_text(encoding="utf-8").splitlines() == [
        "S107000001020304EE",
        "S107000001020304EE",
    ]
