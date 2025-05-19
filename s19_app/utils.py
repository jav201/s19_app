from typing import List


def format_bytes(byte_list: List[int], width: int = 16) -> str:
    """
    Formats a list of bytes into a hex + ASCII line (like a hex dump).
    :param byte_list: List of integers (0–255)
    :param width: Number of bytes per line
    :return: Formatted string
    """
    hex_str = ' '.join(f"{b:02X}" for b in byte_list)
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in byte_list)
    return f"{hex_str:<{width * 3}} | {ascii_str}"


def is_printable(byte: int) -> bool:
    """
    Returns True if byte is a printable ASCII character.
    """
    return 32 <= byte <= 126


def safe_decode(byte_data: bytes, encoding: str = 'ascii') -> str:
    """
    Safely decode bytes to a string, replacing undecodable characters.
    """
    return byte_data.decode(encoding, errors='replace')
