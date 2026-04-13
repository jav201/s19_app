from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


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
        segment_base = 0
        use_segment = False
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
                        base = segment_base if use_segment else (upper_address << 16)
                        base += address
                        for offset, value in enumerate(data):
                            self.memory[base + offset] = value
                    elif record_type == 0x01:
                        break
                    elif record_type == 0x02:
                        if len(data) != 2:
                            self._add_error(
                                line_number,
                                line,
                                "type",
                                "Invalid extended segment address record length",
                            )
                            continue
                        segment_base = ((data[0] << 8) | data[1]) << 4
                        use_segment = True
                        logger.debug(
                            "HEX segment base update: path=%s line=%d segment_base=0x%08X",
                            self.path,
                            line_number,
                            segment_base,
                        )
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
                        use_segment = False
                        logger.debug(
                            "HEX upper linear update: path=%s line=%d upper_address=0x%04X",
                            self.path,
                            line_number,
                            upper_address,
                        )
                    elif record_type in {0x03, 0x05}:
                        # Start segment/linear address records: informational only.
                        continue
                    else:
                        self._add_error(
                            line_number,
                            line,
                            "type",
                            f"Unsupported record type: {record_type:02X}",
                        )
        except FileNotFoundError:
            logger.error("HEX file not found: path=%s", self.path)
            raise
        logger.info(
            "HEX load summary: path=%s records=%d addresses=%d errors=%d",
            self.path,
            len(self.records),
            len(self.memory),
            len(self.load_errors),
        )

    def _add_error(self, line_number: int, line: str, segment: str, error: str) -> None:
        logger.debug(
            "HEX parse issue: path=%s line=%d segment=%s error=%s",
            self.path,
            line_number,
            segment,
            error,
        )
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
