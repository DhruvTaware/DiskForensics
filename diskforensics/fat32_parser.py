"""
FAT32 Filesystem Parser for DiskForensics.

Parses FAT32 filesystem structures from a partition within a disk image.
Supports directory traversal, file metadata extraction, and deleted entry detection.

FAT32 Boot Sector (BPB - BIOS Parameter Block):
  Offset  0-2:    Jump instruction + NOP
  Offset  3-10:   OEM Name (8 bytes)
  Offset 11-12:   Bytes per sector (little-endian)
  Offset 13:      Sectors per cluster
  Offset 14-15:   Reserved sector count (before FAT)
  Offset 16:      Number of FATs (usually 2)
  Offset 17-18:   Root entry count (0 for FAT32)
  Offset 19-20:   Total sectors 16 (0 if > 65535)
  Offset 21:      Media descriptor type
  Offset 22-23:   Sectors per FAT (FAT12/16 only; 0 for FAT32)
  Offset 24-25:   Sectors per track
  Offset 26-27:   Number of heads
  Offset 28-31:   Hidden sectors
  Offset 32-35:   Total sectors 32

FAT32 Extended (offset 36+):
  Offset 36-39:   Sectors per FAT32
  Offset 40-41:   Flags
  Offset 42-43:   FAT version
  Offset 44-47:   Root cluster (usually 2)
  Offset 48-49:   FSInfo sector
  Offset 50-51:   Backup boot sector
  Offset 64:      Drive number
  Offset 66:      Boot signature (0x29)
  Offset 67-70:   Volume ID
  Offset 71-81:   Volume label (11 bytes)
  Offset 82-89:   Filesystem type ("FAT32   ")

Directory Entry (32 bytes):
  Offset  0-7:   Short filename (8 bytes)
  Offset  8-10:  Extension (3 bytes)
  Offset 11:     Attributes
  Offset 12:     Reserved
  Offset 13:     Creation time (10ms units)
  Offset 14-15:  Creation time
  Offset 16-17:  Creation date
  Offset 18-19:  Last access date
  Offset 20-21:  First cluster high
  Offset 22-23:  Last modification time
  Offset 24-25:  Last modification date
  Offset 26-27:  First cluster low
  Offset 28-31:  File size

Author: Edward Marez
License: MIT
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Iterator

from .image_reader import ImageReader
from .utils import fat_timestamp_to_datetime, format_bytes
from datetime import datetime


# Directory entry attribute bits
ATTR_READ_ONLY  = 0x01
ATTR_HIDDEN     = 0x02
ATTR_SYSTEM     = 0x04
ATTR_VOLUME_ID  = 0x08
ATTR_DIRECTORY  = 0x10
ATTR_ARCHIVE    = 0x20
ATTR_LONG_NAME  = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID  # 0x0F

# Special first-byte markers
DIR_ENTRY_FREE   = 0xE5   # Entry is deleted
DIR_ENTRY_END    = 0x00   # No more entries
DIR_ENTRY_DOT    = 0x2E   # "." or ".." entry

# FAT32 cluster values
FAT32_FREE_CLUSTER   = 0x00000000
FAT32_BAD_CLUSTER    = 0x0FFFFFF7
FAT32_EOC_START      = 0x0FFFFFF8  # End of chain
FAT32_EOC_END        = 0x0FFFFFFF
FAT32_CLUSTER_MASK   = 0x0FFFFFFF

DIRENT_SIZE = 32


@dataclass
class FAT32DirectoryEntry:
    """Represents one parsed FAT32 directory entry (32 bytes)."""

    name_short: str          # 8.3 format short name
    name_long: str           # Long filename (from LFN entries) or empty
    attributes: int
    is_deleted: bool
    is_directory: bool
    first_cluster: int
    file_size: int
    created: Optional[datetime]
    modified: Optional[datetime]
    accessed: Optional[datetime]
    path: str = ""           # Full path from root
    raw_entry: bytes = field(repr=False, default=b"")

    @property
    def name(self) -> str:
        """Return long name if available, else short name."""
        return self.name_long if self.name_long else self.name_short

    @property
    def size_human(self) -> str:
        return format_bytes(self.file_size)

    @property
    def attr_string(self) -> str:
        """Return attribute flags as a readable string."""
        flags = []
        if self.attributes & ATTR_READ_ONLY:
            flags.append("R")
        if self.attributes & ATTR_HIDDEN:
            flags.append("H")
        if self.attributes & ATTR_SYSTEM:
            flags.append("S")
        if self.attributes & ATTR_DIRECTORY:
            flags.append("D")
        if self.attributes & ATTR_ARCHIVE:
            flags.append("A")
        return "".join(flags) if flags else "-"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "name_short": self.name_short,
            "path": self.path,
            "is_directory": self.is_directory,
            "is_deleted": self.is_deleted,
            "file_size": self.file_size,
            "size_human": self.size_human,
            "first_cluster": self.first_cluster,
            "attributes": self.attr_string,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
        }


@dataclass
class FAT32BootSector:
    """Parsed FAT32 Boot Sector (BPB)."""

    oem_name: str
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    total_sectors: int
    sectors_per_fat: int
    root_cluster: int
    fsinfo_sector: int
    backup_boot_sector: int
    volume_id: int
    volume_label: str
    fs_type: str

    @property
    def fat_start_sector(self) -> int:
        """LBA of first FAT (relative to partition start)."""
        return self.reserved_sectors

    @property
    def fat_size_sectors(self) -> int:
        """Size of each FAT in sectors."""
        return self.sectors_per_fat

    @property
    def data_start_sector(self) -> int:
        """LBA of first data cluster (cluster 2) relative to partition start."""
        return self.reserved_sectors + self.num_fats * self.sectors_per_fat

    @property
    def bytes_per_cluster(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    def cluster_to_sector(self, cluster: int) -> int:
        """Convert cluster number to sector number (relative to partition start)."""
        return self.data_start_sector + (cluster - 2) * self.sectors_per_cluster

    def to_dict(self) -> dict:
        return {
            "oem_name": self.oem_name,
            "volume_label": self.volume_label,
            "fs_type": self.fs_type,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "bytes_per_cluster": self.bytes_per_cluster,
            "reserved_sectors": self.reserved_sectors,
            "num_fats": self.num_fats,
            "sectors_per_fat": self.sectors_per_fat,
            "total_sectors": self.total_sectors,
            "root_cluster": self.root_cluster,
            "fat_start_sector": self.fat_start_sector,
            "data_start_sector": self.data_start_sector,
        }


@dataclass
class FAT32Result:
    """Result of parsing a FAT32 filesystem."""

    boot_sector: Optional[FAT32BootSector]
    files: List[FAT32DirectoryEntry]
    deleted_files: List[FAT32DirectoryEntry]
    valid: bool
    error: str = ""

    @property
    def all_entries(self) -> List[FAT32DirectoryEntry]:
        return self.files + self.deleted_files

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "error": self.error,
            "boot_sector": self.boot_sector.to_dict() if self.boot_sector else None,
            "file_count": len(self.files),
            "deleted_count": len(self.deleted_files),
            "files": [f.to_dict() for f in self.files],
            "deleted_files": [f.to_dict() for f in self.deleted_files],
        }


class FAT32Parser:
    """
    Parses a FAT32 filesystem from a partition within a raw disk image.

    Usage:
        reader = ImageReader("evidence.dd")
        parser = FAT32Parser(reader, partition_lba_start=2048)
        result = parser.parse()
        for f in result.files:
            print(f.name, f.modified)
    """

    MAX_CLUSTER_FOLLOW = 65536  # Safety limit for cluster chain traversal

    def __init__(self, reader: ImageReader, partition_lba_start: int = 0):
        """
        Initialize with an ImageReader and partition start LBA.

        Args:
            reader: Open ImageReader instance.
            partition_lba_start: LBA of the partition's first sector.
        """
        self.reader = reader
        self.partition_lba_start = partition_lba_start
        self._boot_sector: Optional[FAT32BootSector] = None
        self._fat_cache: Optional[bytes] = None

    def _read_partition_sector(self, sector_offset: int, count: int = 1) -> bytes:
        """Read sectors relative to the partition start."""
        lba = self.partition_lba_start + sector_offset
        return self.reader.read_sectors(lba, count)

    def parse_boot_sector(self) -> Optional[FAT32BootSector]:
        """Parse the FAT32 BPB from the partition's first sector."""
        data = self._read_partition_sector(0)
        if len(data) < 512:
            return None

        # Validate FAT32 filesystem type signature
        fs_type = data[82:90].decode("ascii", errors="replace").strip()

        oem_name = data[3:11].decode("ascii", errors="replace").strip()
        bytes_per_sector, = struct.unpack_from("<H", data, 11)
        sectors_per_cluster = data[13]
        reserved_sectors, = struct.unpack_from("<H", data, 14)
        num_fats = data[16]
        total_sectors_16, = struct.unpack_from("<H", data, 19)
        total_sectors_32, = struct.unpack_from("<I", data, 32)
        sectors_per_fat, = struct.unpack_from("<I", data, 36)
        root_cluster, = struct.unpack_from("<I", data, 44)
        fsinfo_sector, = struct.unpack_from("<H", data, 48)
        backup_boot_sector, = struct.unpack_from("<H", data, 50)
        volume_id, = struct.unpack_from("<I", data, 67)
        volume_label = data[71:82].decode("ascii", errors="replace").strip()
        total_sectors = total_sectors_32 if total_sectors_16 == 0 else total_sectors_16

        if bytes_per_sector == 0:
            return None

        return FAT32BootSector(
            oem_name=oem_name,
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            reserved_sectors=reserved_sectors,
            num_fats=num_fats,
            total_sectors=total_sectors,
            sectors_per_fat=sectors_per_fat,
            root_cluster=root_cluster,
            fsinfo_sector=fsinfo_sector,
            backup_boot_sector=backup_boot_sector,
            volume_id=volume_id,
            volume_label=volume_label,
            fs_type=fs_type,
        )

    def _load_fat(self) -> bytes:
        """Load the first FAT into memory."""
        if self._fat_cache is not None:
            return self._fat_cache
        bs = self._boot_sector
        if bs is None:
            return b""
        fat_data = self._read_partition_sector(bs.fat_start_sector, bs.sectors_per_fat)
        self._fat_cache = fat_data
        return fat_data

    def get_fat_entry(self, cluster: int) -> int:
        """Read FAT entry for the given cluster number."""
        fat = self._load_fat()
        offset = cluster * 4
        if offset + 4 > len(fat):
            return FAT32_EOC_END
        value, = struct.unpack_from("<I", fat, offset)
        return value & FAT32_CLUSTER_MASK

    def is_end_of_chain(self, cluster: int) -> bool:
        return cluster >= FAT32_EOC_START

    def follow_cluster_chain(self, start_cluster: int) -> List[int]:
        """Follow a cluster chain from start_cluster, returning all cluster numbers."""
        if start_cluster < 2:
            return []
        chain = []
        current = start_cluster
        seen = set()
        for _ in range(self.MAX_CLUSTER_FOLLOW):
            if current < 2 or self.is_end_of_chain(current):
                chain.append(current) if not self.is_end_of_chain(current) else None
                break
            if current in seen:
                break  # Circular chain - corrupted FAT
            seen.add(current)
            chain.append(current)
            current = self.get_fat_entry(current)
        return chain

    def read_cluster(self, cluster: int) -> bytes:
        """Read all sectors in a cluster."""
        bs = self._boot_sector
        if bs is None:
            return b""
        sector = bs.cluster_to_sector(cluster)
        return self._read_partition_sector(sector, bs.sectors_per_cluster)

    def read_cluster_chain_data(self, start_cluster: int) -> bytes:
        """Read all data for a cluster chain (up to MAX_CLUSTER_FOLLOW clusters)."""
        chain = self.follow_cluster_chain(start_cluster)
        return b"".join(self.read_cluster(c) for c in chain)

    def _parse_directory_data(
        self, data: bytes, parent_path: str = "/"
    ) -> tuple[List[FAT32DirectoryEntry], List[FAT32DirectoryEntry]]:
        """
        Parse directory entries from raw directory data.

        Handles Long Filename (LFN) entries (attribute 0x0F) by accumulating
        name parts in reverse order before the 8.3 entry they belong to.

        Returns:
            (active_entries, deleted_entries)
        """
        active: List[FAT32DirectoryEntry] = []
        deleted: List[FAT32DirectoryEntry] = []
        lfn_parts: List[str] = []  # Accumulated LFN parts (reverse order)

        i = 0
        while i + DIRENT_SIZE <= len(data):
            raw = data[i: i + DIRENT_SIZE]
            i += DIRENT_SIZE

            first_byte = raw[0]
            attrs = raw[11]

            # End of directory marker
            if first_byte == DIR_ENTRY_END:
                break

            # Long Filename entry
            if attrs == ATTR_LONG_NAME:
                lfn_text = self._parse_lfn_entry(raw)
                lfn_parts.insert(0, lfn_text)
                continue

            # Volume ID (skip)
            if attrs & ATTR_VOLUME_ID and not (attrs & ATTR_DIRECTORY):
                lfn_parts.clear()
                continue

            # Assemble long filename
            long_name = "".join(lfn_parts).rstrip("\x00\uffff")
            lfn_parts.clear()

            is_deleted = first_byte == DIR_ENTRY_FREE
            entry = self._parse_dir_entry(raw, long_name, is_deleted, parent_path)

            # Skip "." and ".." entries
            if entry.name_short in (".", ".."):
                continue

            if is_deleted:
                deleted.append(entry)
            else:
                active.append(entry)

        return active, deleted

    def _parse_lfn_entry(self, data: bytes) -> str:
        """Parse one LFN (Long Filename) entry and return its name fragment."""
        # LFN entry name is spread across 3 fields (UTF-16LE):
        # Offset 1-10:  5 chars (10 bytes)
        # Offset 14-25: 6 chars (12 bytes)
        # Offset 28-31: 2 chars (4 bytes)
        name_bytes = data[1:11] + data[14:26] + data[28:32]
        chars = []
        for j in range(0, len(name_bytes) - 1, 2):
            val, = struct.unpack_from("<H", name_bytes, j)
            if val == 0xFFFF or val == 0x0000:
                break
            chars.append(chr(val))
        return "".join(chars)

    def _parse_dir_entry(
        self, data: bytes, long_name: str, is_deleted: bool, parent_path: str
    ) -> FAT32DirectoryEntry:
        """Parse one 32-byte FAT32 directory entry."""
        raw_name = data[0:8]
        raw_ext = data[8:11]
        attrs = data[11]
        create_time_tenth = data[13]
        create_time, = struct.unpack_from("<H", data, 14)
        create_date, = struct.unpack_from("<H", data, 16)
        access_date, = struct.unpack_from("<H", data, 18)
        first_cluster_hi, = struct.unpack_from("<H", data, 20)
        modify_time, = struct.unpack_from("<H", data, 22)
        modify_date, = struct.unpack_from("<H", data, 24)
        first_cluster_lo, = struct.unpack_from("<H", data, 26)
        file_size, = struct.unpack_from("<I", data, 28)

        first_cluster = (first_cluster_hi << 16) | first_cluster_lo

        # Build 8.3 name
        name_bytes = raw_name.decode("ascii", errors="replace")
        ext_bytes = raw_ext.decode("ascii", errors="replace").rstrip()

        if is_deleted:
            # First character is replaced with 0xE5; use "_" as placeholder
            name_str = "_" + name_bytes[1:].rstrip()
        else:
            name_str = name_bytes.rstrip()

        if ext_bytes:
            short_name = f"{name_str}.{ext_bytes}"
        else:
            short_name = name_str

        # Parse timestamps
        created = fat_timestamp_to_datetime(create_date, create_time, create_time_tenth)
        modified = fat_timestamp_to_datetime(modify_date, modify_time)
        accessed = fat_timestamp_to_datetime(access_date, 0)

        is_directory = bool(attrs & ATTR_DIRECTORY)
        path = f"{parent_path.rstrip('/')}/{long_name if long_name else short_name}"

        return FAT32DirectoryEntry(
            name_short=short_name,
            name_long=long_name,
            attributes=attrs,
            is_deleted=is_deleted,
            is_directory=is_directory,
            first_cluster=first_cluster,
            file_size=file_size,
            created=created,
            modified=modified,
            accessed=accessed,
            path=path,
            raw_entry=bytes(data),
        )

    def _walk_directory(
        self,
        cluster: int,
        path: str,
        active_out: List[FAT32DirectoryEntry],
        deleted_out: List[FAT32DirectoryEntry],
        visited: set,
        depth: int = 0,
    ) -> None:
        """Recursively walk directory structure."""
        if depth > 20 or cluster in visited or cluster < 2:
            return
        visited.add(cluster)

        data = self.read_cluster_chain_data(cluster)
        active, deleted = self._parse_directory_data(data, path)

        active_out.extend(active)
        deleted_out.extend(deleted)

        # Recurse into subdirectories
        for entry in active:
            if entry.is_directory and entry.first_cluster >= 2:
                self._walk_directory(
                    entry.first_cluster,
                    entry.path,
                    active_out,
                    deleted_out,
                    visited,
                    depth + 1,
                )

    def parse(self) -> FAT32Result:
        """
        Parse the complete FAT32 filesystem.

        Returns:
            FAT32Result with boot sector metadata and all file entries.
        """
        try:
            boot_sector = self.parse_boot_sector()
        except Exception as e:
            return FAT32Result(boot_sector=None, files=[], deleted_files=[], valid=False, error=str(e))

        if boot_sector is None:
            return FAT32Result(
                boot_sector=None, files=[], deleted_files=[], valid=False,
                error="Not a valid FAT32 filesystem (boot sector parse failed)"
            )

        self._boot_sector = boot_sector
        self._fat_cache = None  # Reset cache

        active_files: List[FAT32DirectoryEntry] = []
        deleted_files: List[FAT32DirectoryEntry] = []
        visited: set = set()

        try:
            self._walk_directory(
                boot_sector.root_cluster,
                "/",
                active_files,
                deleted_files,
                visited,
            )
        except Exception as e:
            return FAT32Result(
                boot_sector=boot_sector,
                files=active_files,
                deleted_files=deleted_files,
                valid=True,
                error=f"Partial parse: {e}",
            )

        return FAT32Result(
            boot_sector=boot_sector,
            files=active_files,
            deleted_files=deleted_files,
            valid=True,
        )

    def print_summary(self, result: Optional[FAT32Result] = None) -> None:
        """Print a formatted summary of FAT32 filesystem contents."""
        if result is None:
            result = self.parse()

        print("=" * 70)
        print("FAT32 FILESYSTEM ANALYSIS")
        print("=" * 70)

        if not result.valid:
            print(f"Error: {result.error}")
            return

        bs = result.boot_sector
        if bs:
            print(f"Volume Label:    {bs.volume_label}")
            print(f"OEM Name:        {bs.oem_name}")
            print(f"FS Type:         {bs.fs_type}")
            print(f"Bytes/Sector:    {bs.bytes_per_sector}")
            print(f"Sectors/Cluster: {bs.sectors_per_cluster}")
            print(f"Cluster Size:    {format_bytes(bs.bytes_per_cluster)}")
            print(f"Total Sectors:   {bs.total_sectors:,}")
            print(f"Root Cluster:    {bs.root_cluster}")
            print()

        print(f"Active Files:    {len(result.files)}")
        print(f"Deleted Files:   {len(result.deleted_files)}")
        print()

        if result.files:
            print(f"{'Name':<40} {'Size':>10} {'Modified':<22} {'Del?'}")
            print("-" * 80)
            for f in result.files + result.deleted_files:
                del_flag = "[DELETED]" if f.is_deleted else ""
                mod = f.modified.strftime("%Y-%m-%d %H:%M:%S") if f.modified else "N/A"
                print(f"{f.name[:40]:<40} {f.size_human:>10} {mod:<22} {del_flag}")
        print()
