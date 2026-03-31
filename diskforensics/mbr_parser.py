"""
Master Boot Record (MBR) Parser for DiskForensics.

Parses the 512-byte MBR at sector 0 of a raw disk image.
Extracts the partition table (4 entries × 16 bytes each),
boot signature, and bootstrap code metadata.

MBR Layout (512 bytes total):
  Bytes   0-445:  Bootstrap code (loaded and executed by BIOS)
  Bytes 446-461:  Partition Entry 1 (16 bytes)
  Bytes 462-477:  Partition Entry 2 (16 bytes)
  Bytes 478-493:  Partition Entry 3 (16 bytes)
  Bytes 494-509:  Partition Entry 4 (16 bytes)
  Bytes 510-511:  Boot signature (0x55, 0xAA)

Author: Edward Marez
License: MIT
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .image_reader import ImageReader
from .utils import (
    get_mbr_partition_type_name,
    chs_to_str,
    format_bytes,
    lba_to_offset,
    sectors_to_bytes,
)


MBR_SECTOR = 0
MBR_SIZE = 512
PARTITION_TABLE_OFFSET = 446
PARTITION_ENTRY_SIZE = 16
NUM_PARTITION_ENTRIES = 4
BOOT_SIGNATURE = 0xAA55  # little-endian at offset 510

# Partition type IDs of note
TYPE_EMPTY = 0x00
TYPE_EXTENDED = 0x05
TYPE_EXTENDED_LBA = 0x0F
TYPE_GPT_PROTECTIVE = 0xEE
TYPE_NTFS = 0x07
TYPE_FAT32 = 0x0B
TYPE_FAT32_LBA = 0x0C


@dataclass
class PartitionEntry:
    """Represents one 16-byte MBR partition table entry."""

    index: int                   # 0-3
    boot_indicator: int          # 0x80 = bootable, 0x00 = not
    chs_first: str               # CHS of first sector (C/H/S)
    partition_type: int          # Partition type byte
    chs_last: str                # CHS of last sector (C/H/S)
    lba_start: int               # LBA address of first sector
    sector_count: int            # Total number of sectors
    raw_bytes: bytes = field(repr=False, default=b"")

    @property
    def is_bootable(self) -> bool:
        return self.boot_indicator == 0x80

    @property
    def is_empty(self) -> bool:
        return self.partition_type == TYPE_EMPTY and self.lba_start == 0 and self.sector_count == 0

    @property
    def is_extended(self) -> bool:
        return self.partition_type in (TYPE_EXTENDED, TYPE_EXTENDED_LBA)

    @property
    def is_gpt_protective(self) -> bool:
        return self.partition_type == TYPE_GPT_PROTECTIVE

    @property
    def type_name(self) -> str:
        return get_mbr_partition_type_name(self.partition_type)

    @property
    def size_bytes(self) -> int:
        return self.sector_count * 512  # MBR always uses 512-byte sectors

    @property
    def size_human(self) -> str:
        return format_bytes(self.size_bytes)

    @property
    def lba_end(self) -> int:
        """Last sector LBA (inclusive)."""
        if self.sector_count > 0:
            return self.lba_start + self.sector_count - 1
        return self.lba_start

    def to_dict(self) -> dict:
        return {
            "index": self.index + 1,
            "bootable": self.is_bootable,
            "type_id": f"0x{self.partition_type:02X}",
            "type_name": self.type_name,
            "lba_start": self.lba_start,
            "lba_end": self.lba_end,
            "sector_count": self.sector_count,
            "size_bytes": self.size_bytes,
            "size_human": self.size_human,
            "chs_first": self.chs_first,
            "chs_last": self.chs_last,
        }


@dataclass
class MBRResult:
    """Result of parsing a Master Boot Record."""

    valid_signature: bool
    partitions: List[PartitionEntry]
    has_gpt: bool
    raw_mbr: bytes = field(repr=False, default=b"")
    bootstrap_code: bytes = field(repr=False, default=b"")

    @property
    def active_partitions(self) -> List[PartitionEntry]:
        """Return non-empty partition entries."""
        return [p for p in self.partitions if not p.is_empty]

    @property
    def bootable_partition(self) -> Optional[PartitionEntry]:
        """Return the partition marked as bootable, if any."""
        for p in self.partitions:
            if p.is_bootable:
                return p
        return None

    def to_dict(self) -> dict:
        return {
            "valid_signature": self.valid_signature,
            "has_gpt": self.has_gpt,
            "partition_count": len(self.active_partitions),
            "partitions": [p.to_dict() for p in self.active_partitions],
        }


class MBRParser:
    """
    Parses the Master Boot Record of a raw disk image.

    Usage:
        reader = ImageReader("evidence.dd")
        parser = MBRParser(reader)
        result = parser.parse()
        for partition in result.active_partitions:
            print(partition.type_name, partition.size_human)
    """

    def __init__(self, reader: ImageReader):
        """
        Initialize parser with an open ImageReader.

        Args:
            reader: An open ImageReader instance.
        """
        self.reader = reader

    def parse(self) -> MBRResult:
        """
        Parse the MBR at sector 0.

        Returns:
            MBRResult with all partition entries and validity flags.

        Raises:
            ValueError: If sector 0 cannot be read.
        """
        mbr_data = self.reader.read_sector(MBR_SECTOR)
        if len(mbr_data) < MBR_SIZE:
            raise ValueError(f"Sector 0 too short: got {len(mbr_data)} bytes, expected {MBR_SIZE}")

        # Check boot signature at offset 510 (little-endian 0xAA55)
        sig_bytes = mbr_data[510:512]
        valid_sig = (sig_bytes == b"\x55\xAA")

        # Bootstrap code (first 446 bytes)
        bootstrap = mbr_data[0:446]

        # Parse 4 partition entries
        partitions: List[PartitionEntry] = []
        for i in range(NUM_PARTITION_ENTRIES):
            entry_offset = PARTITION_TABLE_OFFSET + i * PARTITION_ENTRY_SIZE
            entry_data = mbr_data[entry_offset: entry_offset + PARTITION_ENTRY_SIZE]
            entry = self._parse_partition_entry(i, entry_data)
            partitions.append(entry)

        has_gpt = any(p.is_gpt_protective for p in partitions)

        return MBRResult(
            valid_signature=valid_sig,
            partitions=partitions,
            has_gpt=has_gpt,
            raw_mbr=mbr_data,
            bootstrap_code=bootstrap,
        )

    def _parse_partition_entry(self, index: int, data: bytes) -> PartitionEntry:
        """
        Parse one 16-byte partition table entry.

        Entry format (little-endian):
          Offset 0:    Status/Boot indicator (1 byte)
          Offset 1-3:  CHS of first sector (3 bytes)
          Offset 4:    Partition type (1 byte)
          Offset 5-7:  CHS of last sector (3 bytes)
          Offset 8-11: LBA of first sector (4 bytes, uint32 LE)
          Offset 12-15: Number of sectors (4 bytes, uint32 LE)
        """
        if len(data) < PARTITION_ENTRY_SIZE:
            data = data + b"\x00" * (PARTITION_ENTRY_SIZE - len(data))

        boot_indicator = data[0]
        chs_first_bytes = data[1:4]
        partition_type = data[4]
        chs_last_bytes = data[5:8]
        lba_start, sector_count = struct.unpack_from("<II", data, 8)

        return PartitionEntry(
            index=index,
            boot_indicator=boot_indicator,
            chs_first=chs_to_str(chs_first_bytes),
            partition_type=partition_type,
            chs_last=chs_to_str(chs_last_bytes),
            lba_start=lba_start,
            sector_count=sector_count,
            raw_bytes=bytes(data),
        )

    def print_summary(self, result: Optional[MBRResult] = None) -> None:
        """Print a formatted summary of the MBR to stdout."""
        if result is None:
            result = self.parse()

        print("=" * 60)
        print("MASTER BOOT RECORD ANALYSIS")
        print("=" * 60)
        print(f"Image:           {self.reader.filename}")
        print(f"Image Size:      {format_bytes(self.reader.image_size)}")
        print(f"Boot Signature:  {'VALID (0x55AA)' if result.valid_signature else 'INVALID'}")
        print(f"GPT Protected:   {'Yes' if result.has_gpt else 'No'}")
        print(f"Active Parts:    {len(result.active_partitions)}")
        print()

        if not result.active_partitions:
            print("No active partition entries found.")
            return

        # Table header
        print(f"{'#':<3} {'Boot':<6} {'Type':<35} {'LBA Start':>12} {'LBA End':>12} {'Size':>12}")
        print("-" * 85)
        for p in result.active_partitions:
            boot_flag = "Yes" if p.is_bootable else "No"
            type_str = f"{p.type_name} (0x{p.partition_type:02X})"
            print(
                f"{p.index + 1:<3} {boot_flag:<6} {type_str:<35} "
                f"{p.lba_start:>12,} {p.lba_end:>12,} {p.size_human:>12}"
            )
        print()
