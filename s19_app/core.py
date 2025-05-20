from typing import List, Optional
import logging
from rich.console import Console
from rich.text import Text

"""
S19 RECORD STRUCTURE REFERENCE
==============================

Structure:
    S[type][byte_count][address][data][checksum]

type: one of '0' through '9'

Record Type Overview:
----------------------------------------------------------
| Record | Address Size | Use Case Description            |
|--------|--------------|---------------------------------|
| S0     | 2 bytes      | Header / file description       |
| S1     | 2 bytes      | Data record (16-bit address)    |
| S2     | 3 bytes      | Data record (24-bit address)    |
| S3     | 4 bytes      | Data record (32-bit address)    |
| S5     | 2 bytes      | Count of S1/S2/S3 records       |
| S7     | 4 bytes      | Start address (for S3 data)     |
| S8     | 3 bytes      | Start address (for S2 data)     |
| S9     | 2 bytes      | Start address (for S1 data)     |

Summary Table of S-Record Types:
---------------------------------------------------------------------
| Type | Purpose           | Address Length | Data Allowed | Notes               |
|------|-------------------|----------------|--------------|---------------------|
| S0   | Header            | 2 bytes        | ✅           | Often contains text |
| S1   | Data (16-bit)     | 2 bytes        | ✅           | For 64KB targets    |
| S2   | Data (24-bit)     | 3 bytes        | ✅           | For 16MB targets    |
| S3   | Data (32-bit)     | 4 bytes        | ✅           | For 4GB targets     |
| S5   | Record count      | 2 bytes        | ✅ (count)   | For S1/S2/S3 lines  |
| S7   | Execution address | 4 bytes        | ❌           | Entry point for S3  |
| S8   | Execution address | 3 bytes        | ❌           | Entry point for S2  |
| S9   | Execution address | 2 bytes        | ❌           | Entry point for S1  |

byte_count:
    byte_count = len(address in bytes) + len(data in bytes) + 1 (for checksum byte)
"""
console = Console()

class SRecord:
    """
    Represents a single S-record line in an S19 file, with parsing and validation methods.
    """

    # Mapping from S-record type to address byte size
    ADDRESS_LENGTH_MAP = {
        'S0': 2,
        'S1': 2,
        'S2': 3,
        'S3': 4,
        'S5': 2,
        'S7': 4,
        'S8': 3,
        'S9': 2,
    }

    def __init__(self, raw_line: str):
        """
        Parses an S-record line from raw string input.
        :param raw_line: A single line from the S19 file.
        """
        self.raw_line = raw_line.strip()
        self.valid = False
        self.validation_errors: List[str] = []

        # Invalid per start key character 
        if not self.raw_line.startswith("S") or len(self.raw_line) < 4:
            raise ValueError(f"Invalid S-record format: {raw_line}")

        self.type = self.raw_line[:2]  # e.g., 'S1'
        # Invalid per S record type
        if self.type not in self.ADDRESS_LENGTH_MAP:
            raise ValueError(f"Unsupported S-record type: {self.type}")

        # Parse byte count field (2 hex digits)
        self.byte_count = int(self.raw_line[2:4], 16)

        # Determine address length in bytes
        self.address_length = self.ADDRESS_LENGTH_MAP[self.type]
        address_field_end = 4 + self.address_length * 2

        # Parse address field
        self.address = int(self.raw_line[4:address_field_end], 16)

        # Parse data bytes (excluding checksum)
        data_field_end = len(self.raw_line) - 2
        self.data = [
            int(self.raw_line[i:i + 2], 16)
            for i in range(address_field_end, data_field_end, 2)
        ]

        # Parse checksum (last 2 hex digits)
        self.checksum = int(self.raw_line[-2:], 16)

        # Validate structure
        self.valid = self._validate()

    def _calculate_checksum(self) -> int:
        """
        Calculates the checksum based on byte count, address, and data.
        :return: The calculated checksum byte.
        """
        address_bytes = [(self.address >> (8 * i)) & 0xFF for i in reversed(range(self.address_length))]
        total = self.byte_count + sum(address_bytes) + sum(self.data)
        return (~total) & 0xFF  # One’s complement of LSB

    def _validate(self) -> bool:
        """
        Validates the record’s byte count and checksum.
        Populates `validation_errors` with specific messages if invalid.
        :return: True if valid, False otherwise.
        """
        self.validation_errors = []
        expected_byte_count = self.address_length + len(self.data) + 1

        if self.byte_count != expected_byte_count:
            self.validation_errors.append(
                f"Byte count mismatch: expected {expected_byte_count}, found {self.byte_count}"
            )

        expected_checksum = self._calculate_checksum()
        if self.checksum != expected_checksum:
            self.validation_errors.append(
                f"Checksum mismatch: expected {expected_checksum:02X}, found {self.checksum:02X}"
            )

        return len(self.validation_errors) == 0

    def as_dict(self) -> dict:
        """
        Returns the S-record as a dictionary for easy inspection or export.
        """
        return {
            'type': self.type,
            'byte_count': self.byte_count,
            'address': self.address,
            'data': self.data,
            'checksum': self.checksum,
            'valid': self.valid
        }
    # Endianess
    def get_record_for_address(self, address: int) -> tuple["SRecord", int]:
        """
        Finds the SRecord and offset corresponding to a given memory address.
        :param address: Absolute address in memory.
        :return: (SRecord, offset_in_data)
        :raises: ValueError if no matching record is found.
        """
        for record in self.records:
            record_start = record.address
            record_end = record.address + len(record.data)
            if record_start <= address < record_end:
                offset = address - record_start
                return record, offset
        raise ValueError(f"No record contains address: 0x{address:X}")


    def get_word_at(self, address: int, size: int = 2, endian: str = 'big') -> int:
        """
        Reads a word from the S19 file at the given absolute address.
        :param address: Absolute memory address to read from.
        :param size: Number of bytes to read.
        :param endian: Byte order ('big' or 'little').
        :return: Integer value
        """
        record, offset = self.get_record_for_address(address)
        return record.get_word(offset, size=size, endian=endian)


    def set_word_at(self, address: int, value: int, size: int = 2, endian: str = 'big'):
        """
        Writes a word into the S19 file at the given absolute address.
        This function works better to write numbers
        :param address: Absolute memory address to write to.
        :param value: Integer value to write.
        :param size: Number of bytes to write.
        :param endian: Byte order ('big' or 'little').
        """
        record, offset = self.get_record_for_address(address)
        record.set_word(offset, value=value, size=size, endian=endian)


    # Representation
    def __str__(self):
        """
        Reconstructs the S-record line from the internal fields.
        """
        address_format = f"{{:0{self.address_length * 2}X}}"
        address_str = address_format.format(self.address)
        data_str = ''.join(f"{b:02X}" for b in self.data)
        byte_count = self.address_length + len(self.data) + 1
        checksum = self._calculate_checksum()
        return f"{self.type}{byte_count:02X}{address_str}{data_str}{checksum:02X}"


class S19File:
    """
    Represents an entire S19 file, including logging, loading, validation,
    and access to all records.
    """

    def __init__(self, path: str, endian: Optional[str] = None):
        self.path = path
        self.records: List["SRecord"] = []
        self.load_errors: List[dict] = []
        self.endian = endian
        self._load()

        if self.endian is None:
            self.endian = self._autodetect_endian()
            logger.info(f"Endian auto-detected as: {self.endian}")

        logger.info(f"File loaded: {self.path}")
        logger.info(f"{len(self.records)} records parsed.")
        valid_count = sum(1 for r in self.records if r.valid)
        logger.info(f"{valid_count} valid out of {len(self.records)} total records.")
        self.print_header()

    def _load(self):
        """
        Loads the file and parses all records line by line.
        Collects all errors (parse and validation) into a unified error list.
        """
        try:
            with open(self.path, 'r') as f:
                for line_number, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = SRecord(line)
                        self.records.append(record)

                        # Collect validation errors if any
                        if not record.valid:
                            for err in record.validation_errors:
                                self.load_errors.append({
                                    'line_number': line_number,
                                    'line': line,
                                    'segment': 'validation',
                                    'error': err
                                })

                    except ValueError as e:
                        self.load_errors.append({
                            'line_number': line_number,
                            'line': line,
                            'segment': 'SRecord constructor',
                            'error': str(e)
                        })
                        logger.warning(f"Skipping line {line_number}: {line} -> {e}")
        except FileNotFoundError:
            logger.error(f"File not found: {self.path}")
            raise
        except Exception as e:
            logger.exception(f"Unexpected error while loading file: {e}")
            raise

    def _autodetect_endian(self) -> str:
        """
        Tries to autodetect file endianess based on readable strings and value plausibility.
        Returns 'little' or 'big'.
        """
        sample_size = min(10, len(self.records))
        big_score = 0
        little_score = 0

        for record in self.records[:sample_size]:
            data = record.data
            if len(data) < 2:
                continue

            for i in range(0, len(data) - 1, 2):
                # Read 2-byte words both ways
                big_val = (data[i] << 8) | data[i + 1]
                little_val = (data[i + 1] << 8) | data[i]

                # ASCII test: check if characters fall in printable ASCII range
                if 32 <= data[i] <= 126 and 32 <= data[i + 1] <= 126:
                    big_score += 1
                if 32 <= data[i + 1] <= 126 and 32 <= data[i] <= 126:
                    little_score += 1

                # "Natural-looking" values (low byte not always 0 or FF)
                if 0 < big_val < 0xFFFF:
                    big_score += 1
                if 0 < little_val < 0xFFFF:
                    little_score += 1
        logger.debug(f"[Autodetect] big score: {big_score}, little score: {little_score}")
        return 'little' if little_score > big_score else 'big'

    def validate_all(self) -> bool:
        """
        Returns True only if all records are valid.
        """
        return all(r.valid for r in self.records)

    def get_invalid_records(self) -> dict:
        """
        Deprecated: use get_errors() instead.
        Returns detailed information about invalid records.
        Format:
        {
            'raw_line_string': {
                'record': SRecord,
                'errors': [list of error strings]
            },
            ...
        }
        """
        invalid = {}
        for record in self.records:
            if not record.valid:
                invalid[record.raw_line] = {
                    'record': record,
                    'errors': record.validation_errors
                }
        return invalid

    def print_header(self):
        """
        Looks for the S0 header record and prints its ASCII text payload.
        """
        for record in self.records:
            if record.type == 'S0':
                try:
                    text = bytes(record.data).decode('ascii', errors='replace')
                    logger.info(f"Header text: {text}")
                except Exception as e:
                    logger.warning(f"Could not decode S0 data: {e}")
                return
        logger.info("No S0 header record found.")

    def __iter__(self):
        return iter(self.records)
    
    def get_errors(self) -> List[dict]:
        """
        Returns all recorded errors in a unified format.
        Each error is a dict with keys: line, segment, error
        """
        return self.load_errors

    def set_string_at(self, address: int, text: str, encoding: str = 'ascii'):
        """
        Encodes and writes a string into the memory at the specified address.
        Assumes contiguous space exists in existing records.
        Raises ValueError if any address is written by multiple records.
        """
        byte_data = list(text.encode(encoding))
        overlap_map = self._build_overlap_map()

        for i in range(len(byte_data)):
            addr = address + i
            writers = overlap_map.get(addr, [])
            if len(writers) > 1:
                raise ValueError(f"Cannot patch address 0x{addr:08X}: written by multiple records.")

        # proceed with patch
        size = len(byte_data)
        remaining = size
        offset = 0

        while remaining > 0:
            record, rec_offset = self.get_record_for_address(address + offset)

            available = len(record.data) - rec_offset
            to_write = min(available, remaining)

            record.data[rec_offset:rec_offset + to_write] = byte_data[offset:offset + to_write]

            offset += to_write
            remaining -= to_write

    def set_bytes_at(self, address: int, byte_list: list[int]):
        """
        Writes raw byte values into memory at a given address.
        Performs overlap check before applying patch.
        """
        overlap_map = self._build_overlap_map()

        for i in range(len(byte_list)):
            addr = address + i
            writers = overlap_map.get(addr, [])
            if len(writers) > 1:
                raise ValueError(f"Cannot patch address 0x{addr:08X}: written by multiple records.")

        # Proceed with patching
        size = len(byte_list)
        remaining = size
        offset = 0

        while remaining > 0:
            record, rec_offset = self.get_record_for_address(address + offset)
            available = len(record.data) - rec_offset
            to_write = min(available, remaining)

            record.data[rec_offset:rec_offset + to_write] = byte_list[offset:offset + to_write]

            offset += to_write
            remaining -= to_write


    def get_record_for_address(self, address: int) -> tuple["SRecord", int]:
        """
        Finds the record that contains the given memory address.

        :param address: The absolute memory address to locate
        :return: A tuple of (record, offset within record)
        :raises ValueError: if no record contains the given address
        """
        for record in self.records:
            start = record.address
            end = start + len(record.data)
            if start <= address < end:
                offset = address - start
                return record, offset
        raise ValueError(f"No record found for address 0x{address:08X}")

    def _build_overlap_map(self) -> dict[int, list["SRecord"]]:
        """
        Builds a mapping of memory addresses to the list of records that write to them.
        If any address maps to more than one record, it’s an overlap.
        """
        addr_map = {}
        for record in self.records:
            for i, byte in enumerate(record.data):
                addr = record.address + i
                addr_map.setdefault(addr, []).append(record)
        return addr_map

    
    # Visualization
    def visualize_memory(self, start: int, length: int = 64, encoding: str = 'ascii', width: int = 16, output_stream=None):
        from rich.console import Console
        from rich.text import Text

        console = Console(file=output_stream, highlight=False)

        mem_map = {}
        for record in self.records:
            addr = record.address
            for offset, byte in enumerate(record.data):
                mem_map[addr + offset] = byte

        console.print("[bold underline]Memory View[/bold underline]")
        for row_addr in range(start, start + length, width):
            line = Text()
            line.append(f"0x{row_addr:08X}  ", style="bold cyan")

            hex_part = Text()
            ascii_part = Text()

            for i in range(width):
                addr = row_addr + i
                byte = mem_map.get(addr)
                if byte is None:
                    hex_part.append("   ")
                    ascii_part.append(" ", style="dim")
                else:
                    hex_part.append(f"{byte:02X} ", style="white")
                    try:
                        char = bytes([byte]).decode(encoding)
                        ascii_part.append(char if 32 <= ord(char) <= 126 else ".", style="green" if 32 <= ord(char) <= 126 else "dim")
                    except Exception:
                        ascii_part.append("�", style="red")

            line.append(hex_part)
            line.append(" | ")
            line.append(ascii_part)
            console.print(line)


    def visualize_all(self, encoding: str = 'ascii', width: int = 16):
        """
        Displays the entire memory map using rich colorized hex+ASCII format.
        """
        mem_map = {}
        for record in self.records:
            addr = record.address
            for offset, byte in enumerate(record.data):
                mem_map[addr + offset] = byte

        all_addresses = sorted(mem_map.keys())
        if not all_addresses:
            console.print("[yellow]No memory content found.[/yellow]")
            return

        start_addr = all_addresses[0] - (all_addresses[0] % width)
        end_addr = all_addresses[-1] + (width - all_addresses[-1] % width)

        self.visualize_memory(start=start_addr, length=(end_addr - start_addr), encoding=encoding, width=width)

    def visualize_by_ranges(self, encoding: str = 'ascii', width: int = 16, output_stream=None):
        """
        Dumps memory contents per used memory range using rich hex visualization.
        If output_stream is provided, writes to that stream (e.g., file).
        """
        from rich.console import Console

        console = Console(file=output_stream, highlight=False)
        console.print("[bold underline]Memory Dump by Used Ranges[/bold underline]\n")
        ranges = self._get_memory_ranges()

        if not ranges:
            console.print("[yellow]No memory data found.[/yellow]")
            return

        for i, (start, end) in enumerate(ranges):
            console.print(f"\n[bold cyan]Range {i + 1}: 0x{start:08X} - 0x{end - 1:08X} ({end - start} bytes)[/bold cyan]\n")
            self.visualize_memory(start=start, length=end - start, encoding=encoding, width=width, output_stream=output_stream)

    # Read memory layout
    def _get_memory_ranges(self) -> List[tuple[int, int]]:
        """
        Collects all bytes written by records and returns a list of contiguous memory ranges.
        :return: List of (start_addr, end_addr) pairs where end_addr is exclusive.
        """
        addresses = sorted({
            record.address + i
            for record in self.records
            for i in range(len(record.data))
        })

        if not addresses:
            return []

        # Group into contiguous ranges
        ranges = []
        start = addresses[0]
        prev = addresses[0]

        for addr in addresses[1:]:
            if addr == prev + 1:
                prev = addr
            else:
                ranges.append((start, prev + 1))  # end is exclusive
                start = addr
                prev = addr

        ranges.append((start, prev + 1))  # last range
        return ranges

    def show_memory_ranges(self):
        """
        Displays contiguous memory ranges covered by S-records.
        """
        ranges = self._get_memory_ranges()
        print("[INFO] Memory Ranges Used:")
        for start, end in ranges:
            print(f"  0x{start:08X} - 0x{end - 1:08X} ({end - start} bytes)")

    def show_memory_gaps(self):
        """
        Displays memory address gaps between used ranges.
        """
        ranges = self._get_memory_ranges()
        print("[INFO] Memory Gaps Between Ranges:")
        for i in range(len(ranges) - 1):
            gap_start = ranges[i][1]
            gap_end = ranges[i + 1][0]
            print(f"  0x{gap_start:08X} - 0x{gap_end - 1:08X} ({gap_end - gap_start} bytes)")

    def show_memory_layout(self):
        """
        Displays both used memory ranges and the gaps between them in order.
        """
        ranges = self._get_memory_ranges()
        print("[INFO] Memory Layout (Ranges and Gaps):")
        for i in range(len(ranges)):
            start, end = ranges[i]
            print(f"  [USED] 0x{start:08X} - 0x{end - 1:08X} ({end - start} bytes)")
            if i < len(ranges) - 1:
                next_start = ranges[i + 1][0]
                print(f"  [GAP]  0x{end:08X} - 0x{next_start - 1:08X} ({next_start - end} bytes)")


# Configure the root logger
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

logger = logging.getLogger(__name__)