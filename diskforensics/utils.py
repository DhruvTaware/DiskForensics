"""
Utility functions for DiskForensics.

Provides common helpers used across all parsers:
- Byte formatting
- GUID parsing
- Timestamp conversion
- Hex dump display
- Partition type lookup tables
"""

import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Partition type lookup tables
# ---------------------------------------------------------------------------

MBR_PARTITION_TYPES: dict[int, str] = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32MB",
    0x05: "Extended",
    0x06: "FAT16",
    0x07: "NTFS/HPFS/exFAT",
    0x0B: "FAT32",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16 <32MB",
    0x16: "Hidden FAT16",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32",
    0x1C: "Hidden FAT32 (LBA)",
    0x27: "Windows Recovery",
    0x42: "Windows Dynamic",
    0x82: "Linux Swap",
    0x83: "Linux",
    0x85: "Linux Extended",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA9: "NetBSD",
    0xAF: "macOS HFS+",
    0xBE: "Solaris Boot",
    0xBF: "Solaris",
    0xEB: "BeFS",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System",
    0xFB: "VMware VMFS",
    0xFC: "VMware VMKCORE",
    0xFD: "Linux RAID",
    0xFE: "IBM IML",
    0xFF: "XENIX BBT",
}

# Well-known GPT partition type GUIDs
GPT_PARTITION_TYPE_GUIDS: dict[str, str] = {
    "00000000-0000-0000-0000-000000000000": "Unused Entry",
    "024DEE41-33E7-11D3-9D69-0008C781F39F": "MBR Partition Scheme",
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition",
    "21686148-6449-6E6F-744E-656564454649": "BIOS Boot Partition",
    "D3BFE2DE-3DAF-11DF-BA40-E3A556D89593": "Intel Fast Flash (iFFS)",
    "F4019732-066E-4E12-8273-346C5641494F": "Sony Boot Partition",
    "BFBFAFE7-A34F-448A-9A5B-6213EB736C22": "Lenovo Boot Partition",
    # Windows
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM Metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM Data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery Environment",
    "37AFFC90-EF7D-4E96-91C3-2D7AE055B174": "IBM GPFS",
    "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Windows Storage Spaces",
    # Linux
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Filesystem",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux Swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "8DA63339-0007-60C0-C436-083AC8230908": "Linux Reserved",
    # macOS
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "55465300-0000-11AA-AA11-00306543ECAC": "Apple UFS",
    "52414944-0000-11AA-AA11-00306543ECAC": "Apple RAID",
    "52414944-5F4F-11AA-AA11-00306543ECAC": "Apple RAID (Offline)",
    "426F6F74-0000-11AA-AA11-00306543ECAC": "Apple Boot",
    "4C616265-6C00-11AA-AA11-00306543ECAC": "Apple Label",
    "5265636F-7665-11AA-AA11-00306543ECAC": "Apple TV Recovery",
    "53746F72-6167-11AA-AA11-00306543ECAC": "Apple Core Storage",
    # FreeBSD
    "83BD6B9D-7F41-11DC-BE0B-001560B84F0F": "FreeBSD Boot",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD Data",
    "516E7CB5-6ECF-11D6-8FF8-00022D09712B": "FreeBSD Swap",
    "516E7CB6-6ECF-11D6-8FF8-00022D09712B": "FreeBSD UFS",
    "516E7CB8-6ECF-11D6-8FF8-00022D09712B": "FreeBSD Vinum/RAID",
    "516E7CBA-6ECF-11D6-8FF8-00022D09712B": "FreeBSD ZFS",
}


def get_mbr_partition_type_name(type_id: int) -> str:
    """Return human-readable name for MBR partition type byte."""
    return MBR_PARTITION_TYPES.get(type_id, f"Unknown (0x{type_id:02X})")


def get_gpt_partition_type_name(type_guid: str) -> str:
    """Return human-readable name for GPT partition type GUID."""
    return GPT_PARTITION_TYPE_GUIDS.get(type_guid.upper(), f"Unknown ({type_guid})")


def parse_gpt_guid(data: bytes) -> str:
    """
    Parse a mixed-endian GPT GUID from 16 bytes.

    GPT GUIDs are stored in a mixed-endian format:
      - First 4 bytes: little-endian DWORD
      - Next 2 bytes: little-endian WORD
      - Next 2 bytes: little-endian WORD
      - Last 8 bytes: big-endian
    """
    if len(data) < 16:
        return "00000000-0000-0000-0000-000000000000"
    part1 = struct.unpack_from("<IHH", data, 0)
    part2 = data[8:16]
    guid_str = (
        f"{part1[0]:08X}-{part1[1]:04X}-{part1[2]:04X}-"
        f"{part2[0]:02X}{part2[1]:02X}-"
        f"{''.join(f'{b:02X}' for b in part2[2:])}"
    )
    return guid_str


def fat_timestamp_to_datetime(date_val: int, time_val: int, time_tenth: int = 0) -> Optional[datetime]:
    """
    Convert FAT32 packed date/time integers to a Python datetime.

    FAT Date (2 bytes):
      Bits 15-9: Year offset from 1980 (0-127)
      Bits  8-5: Month (1-12)
      Bits  4-0: Day (1-31)

    FAT Time (2 bytes):
      Bits 15-11: Hours (0-23)
      Bits 10-5:  Minutes (0-59)
      Bits  4-0:  2-second count (0-29) -> seconds = value * 2

    time_tenth: 10ms units (0-199) added to creation time only.
    """
    if date_val == 0:
        return None
    try:
        year = ((date_val >> 9) & 0x7F) + 1980
        month = (date_val >> 5) & 0x0F
        day = date_val & 0x1F
        hour = (time_val >> 11) & 0x1F
        minute = (time_val >> 5) & 0x3F
        second = (time_val & 0x1F) * 2 + (time_tenth // 100 if time_tenth else 0)
        # Clamp values to valid ranges
        month = max(1, min(12, month))
        day = max(1, min(31, day))
        hour = min(23, hour)
        minute = min(59, minute)
        second = min(59, second)
        return datetime(year, month, day, hour, minute, second)
    except (ValueError, OverflowError):
        return None


def ntfs_timestamp_to_datetime(ts: int) -> Optional[datetime]:
    """
    Convert NTFS timestamp (100-nanosecond intervals since Jan 1, 1601) to datetime.

    NTFS epoch: January 1, 1601 00:00:00 UTC
    Unix epoch:  January 1, 1970 00:00:00 UTC
    Difference:  116444736000000000 intervals (= 11644473600 seconds)
    """
    if ts == 0:
        return None
    try:
        # Convert to microseconds since Unix epoch
        unix_micros = (ts - 116444736000000000) // 10
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=unix_micros)
    except (ValueError, OverflowError, OSError):
        return None


def datetime_to_ntfs_timestamp(dt: datetime) -> int:
    """Convert a datetime to an NTFS timestamp."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    return int(delta.total_seconds() * 10_000_000)


def datetime_to_fat_date(dt: datetime) -> int:
    """Convert datetime to FAT date integer."""
    year_offset = dt.year - 1980
    return ((year_offset & 0x7F) << 9) | ((dt.month & 0x0F) << 5) | (dt.day & 0x1F)


def datetime_to_fat_time(dt: datetime) -> int:
    """Convert datetime to FAT time integer."""
    return ((dt.hour & 0x1F) << 11) | ((dt.minute & 0x3F) << 5) | ((dt.second // 2) & 0x1F)


def format_bytes(num_bytes: int) -> str:
    """Format a byte count into a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:,.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} EB"


def format_hex(data: bytes, columns: int = 16, offset: int = 0) -> str:
    """
    Return a formatted hex dump of bytes.

    Args:
        data: Bytes to display.
        columns: Number of bytes per row (default 16).
        offset: Starting offset for address display.

    Returns:
        Multi-line string with address, hex, and ASCII columns.
    """
    lines = []
    for i in range(0, len(data), columns):
        chunk = data[i:i + columns]
        addr = f"{offset + i:08X}"
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(columns * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def decode_utf16le_name(data: bytes, max_chars: Optional[int] = None) -> str:
    """Decode a UTF-16LE encoded name, stopping at null terminator."""
    try:
        if max_chars is not None:
            data = data[: max_chars * 2]
        # Find null terminator pair
        result = []
        for i in range(0, len(data) - 1, 2):
            char_val = struct.unpack_from("<H", data, i)[0]
            if char_val == 0:
                break
            result.append(chr(char_val))
        return "".join(result)
    except (UnicodeDecodeError, struct.error):
        return "<invalid>"


def sectors_to_bytes(sectors: int, sector_size: int = 512) -> int:
    """Convert sector count to byte count."""
    return sectors * sector_size


def lba_to_offset(lba: int, sector_size: int = 512) -> int:
    """Convert LBA address to byte offset."""
    return lba * sector_size


def chs_to_str(chs_bytes: bytes) -> str:
    """
    Convert 3-byte CHS (Cylinder-Head-Sector) to human-readable string.

    Byte 0: Head
    Byte 1: Sector (bits 0-5), Cylinder high bits (bits 6-7)
    Byte 2: Cylinder low bits
    """
    if len(chs_bytes) < 3:
        return "0/0/0"
    head = chs_bytes[0]
    sector = chs_bytes[1] & 0x3F
    cylinder = ((chs_bytes[1] & 0xC0) << 2) | chs_bytes[2]
    return f"{cylinder}/{head}/{sector}"
