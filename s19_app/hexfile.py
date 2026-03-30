from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict


@dataclass
class HexRecord:
    record_type: int
    address: int
    data: List[int]
    checksum: int
    valid: bool
    raw_line: str


class IntelHexFile:
    def __init__(self, path: str):
        self.path = path
        self.records: List[HexRecord] = []
        self.load_errors: List[dict] = []
        self.memory: Dict[int, int] = {}
        self._load()

    def _load(self) -> None:
        upper_address = 0
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line_number, raw_line in enumerate(handle, 1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    if not line.startswith(":"):
                        self._add_error(line_number, line, "format", "Missing ':' prefix")
                        continue

                    try:
                        byte_count = int(line[1:3], 16)
                        address = int(line[3:7], 16)
                        record_type = int(line[7:9], 16)
                        data_end = 9 + (byte_count * 2)
                        data = [
                            int(line[i:i + 2], 16)
                            for i in range(9, data_end, 2)
                        ]
                        checksum = int(line[data_end:data_end + 2], 16)
                    except ValueError as exc:
                        self._add_error(line_number, line, "parse", str(exc))
                        continue

                    expected_len = 11 + (byte_count * 2)
                    if len(line) != expected_len:
                        self._add_error(
                            line_number,
                            line,
                            "length",
                            f"Length mismatch: expected {expected_len}, found {len(line)}",
                        )
                        continue

                    calc = (
                        byte_count
                        + (address >> 8)
                        + (address & 0xFF)
                        + record_type
                        + sum(data)
                        + checksum
                    ) & 0xFF
                    valid = calc == 0

                    record = HexRecord(
                        record_type=record_type,
                        address=address,
                        data=data,
                        checksum=checksum,
                        valid=valid,
                        raw_line=line,
                    )
                    self.records.append(record)

                    if not valid:
                        self._add_error(
                            line_number,
                            line,
                            "checksum",
                            "Checksum mismatch",
                        )

                    if record_type == 0x00:
                        base = (upper_address << 16) + address
                        for offset, value in enumerate(data):
                            self.memory[base + offset] = value
                    elif record_type == 0x01:
                        break
                    elif record_type == 0x04:
                        if len(data) != 2:
                            self._add_error(
                                line_number,
                                line,
                                "type",
                                "Invalid extended linear address record length",
                            )
                            continue
                        upper_address = (data[0] << 8) | data[1]
                    else:
                        self._add_error(
                            line_number,
                            line,
                            "type",
                            f"Unsupported record type: {record_type:02X}",
                        )
        except FileNotFoundError:
            raise

    def _add_error(self, line_number: int, line: str, segment: str, error: str) -> None:
        self.load_errors.append(
            {
                "line_number": line_number,
                "line": line,
                "segment": segment,
                "error": error,
            }
        )

    def get_errors(self) -> List[dict]:
        return self.load_errors

    def get_ranges(self) -> List[tuple[int, int]]:
        addresses = sorted(self.memory.keys())
        if not addresses:
            return []
        ranges = []
        start = addresses[0]
        prev = addresses[0]
        for addr in addresses[1:]:
            if addr == prev + 1:
                prev = addr
            else:
                ranges.append((start, prev + 1))
                start = addr
                prev = addr
        ranges.append((start, prev + 1))
        return ranges
