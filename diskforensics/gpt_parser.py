"""
GUID Partition Table (GPT) Parser for DiskForensics.

Parses GPT disk layouts, including the protective MBR at sector 0,
the primary GPT header at sector 1, and all partition entries.

GPT Header Layout (at LBA 1, 92 bytes minimum):
  Offset  0-7:   Signature "EFI PART" (8 bytes)
  Offset  8-11:  Revision (e.g., 0x00010000 = v1.0)
  Offset 12-15:  Header size (usually 92)
  Offset 16-19:  CRC32 of header (with this field zeroed)
  Offset 20-23:  Reserved
  Offset 24-31:  My LBA (this header's location)
  Offset 32-39:  Alternate LBA (backup header location)
  Offset 40-47:  First usable LBA
  Offset 48-55:  Last usable LBA
  Offset 56-71:  Disk GUID (16 bytes, mixed-endian)
  Offset 72-79:  Partition entries start LBA
  Offset 80-83:  Number of partition entries
  Offset 84-87:  Size of each partition entry (usually 128)
  Offset 88-91:  CRC32 of partition entries array

Partition Entry Layout (128 bytes each):
  Offset   0-15: Partition Type GUID (16 bytes)
  Offset  16-31: Unique Partition GUID (16 bytes)
  Offset  32-39: Starting LBA
  Offset  40-47: Ending LBA (inclusive)
  Offset  48-55: Attribute flags
  Offset  56-127: Partition name (UTF-16LE, 72 bytes = 36 chars)

Author: Edward Marez
License: MIT
"""

import struct
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

from .image_reader import ImageReader
from .utils import (
    parse_gpt_guid,
    get_gpt_partition_type_name,
    decode_utf16le_name,
    format_bytes,
)


GPT_HEADER_LBA = 1
GPT_SIGNATURE = b"EFI PART"
GPT_REVISION_1_0 = 0x00010000
GPT_HEADER_MIN_SIZE = 92


@dataclass
class GPTPartitionEntry:
    """Represents one 128-byte GPT partition entry."""

    index: int
    type_guid: str           # Partition type GUID string
    unique_guid: str         # Unique partition GUID string
    lba_start: int           # First sector
    lba_end: int             # Last sector (inclusive)
    attributes: int          # Attribute flags
    name: str                # UTF-16LE partition name
    raw_bytes: bytes = field(repr=False, default=b"")

    @property
    def is_empty(self) -> bool:
        return self.type_guid == "00000000-0000-0000-0000-000000000000"

    @property
    def type_name(self) -> str:
        return get_gpt_partition_type_name(self.type_guid)

    @property
    def sector_count(self) -> int:
        if self.lba_end >= self.lba_start:
            return self.lba_end - self.lba_start + 1
        return 0

    @property
    def size_bytes(self) -> int:
        return self.sector_count * 512

    @property
    def size_human(self) -> str:
        return format_bytes(self.size_bytes)

    @property
    def is_required(self) -> bool:
        """Attribute bit 0: Required partition."""
        return bool(self.attributes & 0x01)

    @property
    def no_auto_mount(self) -> bool:
        """Attribute bit 63 (Windows): No auto-mount."""
        return bool(self.attributes & (1 << 63))

    def to_dict(self) -> dict:
        return {
            "index": self.index + 1,
            "name": self.name,
            "type_guid": self.type_guid,
            "type_name": self.type_name,
            "unique_guid": self.unique_guid,
            "lba_start": self.lba_start,
            "lba_end": self.lba_end,
            "sector_count": self.sector_count,
            "size_bytes": self.size_bytes,
            "size_human": self.size_human,
            "attributes": f"0x{self.attributes:016X}",
        }


@dataclass
class GPTHeader:
    """Parsed GPT header."""

    signature: bytes
    revision: int
    header_size: int
    header_crc32: int
    my_lba: int
    alternate_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: str
    partition_entry_lba: int
    num_partition_entries: int
    partition_entry_size: int
    partition_array_crc32: int

    @property
    def revision_str(self) -> str:
        major = (self.revision >> 16) & 0xFFFF
        minor = self.revision & 0xFFFF
        return f"{major}.{minor}"

    @property
    def is_valid_signature(self) -> bool:
        return self.signature == GPT_SIGNATURE

    def to_dict(self) -> dict:
        return {
            "signature": self.signature.decode("ascii", errors="replace").strip("\x00"),
            "revision": self.revision_str,
            "header_size": self.header_size,
            "my_lba": self.my_lba,
            "alternate_lba": self.alternate_lba,
            "first_usable_lba": self.first_usable_lba,
            "last_usable_lba": self.last_usable_lba,
            "disk_guid": self.disk_guid,
            "partition_entry_lba": self.partition_entry_lba,
            "num_partition_entries": self.num_partition_entries,
            "partition_entry_size": self.partition_entry_size,
        }


@dataclass
class GPTResult:
    """Result of parsing a GPT disk."""

    header: Optional[GPTHeader]
    partitions: List[GPTPartitionEntry]
    header_crc_valid: bool
    partition_crc_valid: bool
    has_backup_header: bool

    @property
    def active_partitions(self) -> List[GPTPartitionEntry]:
        """Return non-empty partition entries."""
        return [p for p in self.partitions if not p.is_empty]

    @property
    def usable_sectors(self) -> int:
        if self.header:
            return self.header.last_usable_lba - self.header.first_usable_lba + 1
        return 0

    def to_dict(self) -> dict:
        result = {
            "header": self.header.to_dict() if self.header else None,
            "header_crc_valid": self.header_crc_valid,
            "partition_crc_valid": self.partition_crc_valid,
            "partition_count": len(self.active_partitions),
            "partitions": [p.to_dict() for p in self.active_partitions],
        }
        return result


class GPTParser:
    """
    Parses GUID Partition Table (GPT) from a raw disk image.

    Usage:
        reader = ImageReader("evidence.dd")
        parser = GPTParser(reader)
        result = parser.parse()
        for partition in result.active_partitions:
            print(partition.name, partition.type_name)
    """

    def __init__(self, reader: ImageReader):
        """
        Initialize parser with an open ImageReader.

        Args:
            reader: An open ImageReader instance.
        """
        self.reader = reader

    def parse(self) -> GPTResult:
        """
        Parse the primary GPT header and all partition entries.

        Returns:
            GPTResult with header metadata and partition list.
        """
        header = self._parse_header(GPT_HEADER_LBA)
        if header is None:
            return GPTResult(
                header=None,
                partitions=[],
                header_crc_valid=False,
                partition_crc_valid=False,
                has_backup_header=False,
            )

        header_crc_valid = self._verify_header_crc(header)
        partitions, partition_crc_valid = self._parse_partition_entries(header)
        has_backup = header.alternate_lba > 0 and header.alternate_lba != header.my_lba

        return GPTResult(
            header=header,
            partitions=partitions,
            header_crc_valid=header_crc_valid,
            partition_crc_valid=partition_crc_valid,
            has_backup_header=has_backup,
        )

    def _parse_header(self, lba: int) -> Optional[GPTHeader]:
        """Parse the GPT header at the given LBA."""
        sector = self.reader.read_sector(lba)
        if len(sector) < GPT_HEADER_MIN_SIZE:
            return None

        signature = sector[0:8]
        if signature != GPT_SIGNATURE:
            return None

        (
            revision,
            header_size,
            header_crc32,
            _reserved,
            my_lba,
            alternate_lba,
            first_usable_lba,
            last_usable_lba,
        ) = struct.unpack_from("<IIII QQQQ", sector, 8)

        disk_guid = parse_gpt_guid(sector[56:72])

        (
            partition_entry_lba,
            num_partition_entries,
            partition_entry_size,
            partition_array_crc32,
        ) = struct.unpack_from("<QIIQ", sector, 72)

        # Fix alignment - the struct above had wrong offsets, re-parse cleanly
        revision, = struct.unpack_from("<I", sector, 8)
        header_size, = struct.unpack_from("<I", sector, 12)
        header_crc32, = struct.unpack_from("<I", sector, 16)
        my_lba, = struct.unpack_from("<Q", sector, 24)
        alternate_lba, = struct.unpack_from("<Q", sector, 32)
        first_usable_lba, = struct.unpack_from("<Q", sector, 40)
        last_usable_lba, = struct.unpack_from("<Q", sector, 48)
        disk_guid = parse_gpt_guid(sector[56:72])
        partition_entry_lba, = struct.unpack_from("<Q", sector, 72)
        num_partition_entries, = struct.unpack_from("<I", sector, 80)
        partition_entry_size, = struct.unpack_from("<I", sector, 84)
        partition_array_crc32, = struct.unpack_from("<I", sector, 88)

        return GPTHeader(
            signature=signature,
            revision=revision,
            header_size=header_size,
            header_crc32=header_crc32,
            my_lba=my_lba,
            alternate_lba=alternate_lba,
            first_usable_lba=first_usable_lba,
            last_usable_lba=last_usable_lba,
            disk_guid=disk_guid,
            partition_entry_lba=partition_entry_lba,
            num_partition_entries=num_partition_entries,
            partition_entry_size=partition_entry_size,
            partition_array_crc32=partition_array_crc32,
        )

    def _verify_header_crc(self, header: GPTHeader) -> bool:
        """Verify the header CRC32 checksum."""
        try:
            sector = self.reader.read_sector(GPT_HEADER_LBA)
            # Zero out the CRC field (bytes 16-19) before computing
            header_bytes = bytearray(sector[: header.header_size])
            header_bytes[16:20] = b"\x00\x00\x00\x00"
            computed = zlib.crc32(bytes(header_bytes)) & 0xFFFFFFFF
            return computed == header.header_crc32
        except Exception:
            return False

    def _parse_partition_entries(
        self, header: GPTHeader
    ) -> tuple[List[GPTPartitionEntry], bool]:
        """
        Parse all GPT partition entries.

        Returns:
            (list of entries, crc_valid flag)
        """
        entry_size = header.partition_entry_size
        num_entries = min(header.num_partition_entries, 128)  # sanity cap
        total_bytes = entry_size * num_entries

        # Read all entry data in one shot for CRC verification
        start_offset = header.partition_entry_lba * self.reader.sector_size
        all_entry_data = self.reader.read_bytes(start_offset, total_bytes)

        # Verify partition array CRC
        computed_crc = zlib.crc32(all_entry_data) & 0xFFFFFFFF
        crc_valid = computed_crc == header.partition_array_crc32

        partitions: List[GPTPartitionEntry] = []
        for i in range(num_entries):
            entry_offset = i * entry_size
            entry_data = all_entry_data[entry_offset: entry_offset + entry_size]
            if len(entry_data) < 128:
                continue
            entry = self._parse_single_entry(i, entry_data)
            partitions.append(entry)

        return partitions, crc_valid

    def _parse_single_entry(self, index: int, data: bytes) -> GPTPartitionEntry:
        """Parse one 128-byte partition entry."""
        type_guid = parse_gpt_guid(data[0:16])
        unique_guid = parse_gpt_guid(data[16:32])
        lba_start, = struct.unpack_from("<Q", data, 32)
        lba_end, = struct.unpack_from("<Q", data, 40)
        attributes, = struct.unpack_from("<Q", data, 48)
        name = decode_utf16le_name(data[56:128], max_chars=36)

        return GPTPartitionEntry(
            index=index,
            type_guid=type_guid,
            unique_guid=unique_guid,
            lba_start=lba_start,
            lba_end=lba_end,
            attributes=attributes,
            name=name,
            raw_bytes=bytes(data),
        )

    def print_summary(self, result: Optional[GPTResult] = None) -> None:
        """Print a formatted summary of the GPT to stdout."""
        if result is None:
            result = self.parse()

        print("=" * 70)
        print("GUID PARTITION TABLE (GPT) ANALYSIS")
        print("=" * 70)

        if result.header is None:
            print("No valid GPT header found at LBA 1.")
            return

        h = result.header
        print(f"Image:              {self.reader.filename}")
        print(f"Revision:           {h.revision_str}")
        print(f"Disk GUID:          {h.disk_guid}")
        print(f"My LBA:             {h.my_lba}")
        print(f"Alternate LBA:      {h.alternate_lba}")
        print(f"First Usable LBA:   {h.first_usable_lba:,}")
        print(f"Last Usable LBA:    {h.last_usable_lba:,}")
        print(f"Usable Space:       {format_bytes(result.usable_sectors * 512)}")
        print(f"Header CRC Valid:   {'Yes' if result.header_crc_valid else 'NO - CORRUPTED'}")
        print(f"Partition CRC Valid:{'Yes' if result.partition_crc_valid else 'NO - CORRUPTED'}")
        print(f"Backup Header:      {'Present (LBA ' + str(h.alternate_lba) + ')' if result.has_backup_header else 'Unknown'}")
        print()

        active = result.active_partitions
        if not active:
            print("No partition entries found.")
            return

        print(f"{'#':<3} {'Name':<20} {'Type':<30} {'LBA Start':>12} {'LBA End':>12} {'Size':>10}")
        print("-" * 90)
        for p in active:
            print(
                f"{p.index + 1:<3} {p.name[:20]:<20} {p.type_name[:30]:<30} "
                f"{p.lba_start:>12,} {p.lba_end:>12,} {p.size_human:>10}"
            )
        print()
