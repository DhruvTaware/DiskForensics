"""
NTFS Filesystem Parser for DiskForensics.

Parses NTFS filesystem structures including:
- NTFS Boot Sector (BPB)
- Master File Table (MFT) records
- $STANDARD_INFORMATION attribute (0x10): MAC timestamps + flags
- $FILE_NAME attribute (0x30): filename + parent dir + timestamps
- $DATA attribute (0x80): file data info

NTFS Boot Sector (Offset 3 = "NTFS    "):
  Offset  0-2:   Jump instruction
  Offset  3-10:  OEM ID ("NTFS    ")
  Offset 11-12:  Bytes per sector
  Offset 13:     Sectors per cluster
  Offset 14-15:  Reserved sectors
  Offset 28-31:  Hidden sectors
  Offset 40-47:  Total sectors
  Offset 48-55:  MFT cluster number ($MFT LCN)
  Offset 56-63:  MFT mirror cluster number ($MFTMirr LCN)
  Offset 64:     Clusters per MFT record (signed: if < 0, record size = 2^|val|)
  Offset 68:     Clusters per index block

MFT Record Header (at every MFT record):
  Offset  0-3:   Signature "FILE" (or "BAAD")
  Offset  4-5:   Update sequence offset
  Offset  6-7:   Update sequence count
  Offset  8-15:  $LogFile sequence number
  Offset 16-17:  Sequence number
  Offset 18-19:  Hard link count
  Offset 20-21:  Attribute offset
  Offset 22-23:  Flags (0x01 = in use, 0x02 = directory)
  Offset 24-27:  Used size
  Offset 28-31:  Allocated size
  Offset 32-39:  Base file record
  Offset 40-41:  Next attribute ID
  Offset 44-47:  MFT record number (v3.1+)

Attribute Header (each attribute within MFT record):
  Offset  0-3:   Attribute type
  Offset  4-7:   Attribute length (including header)
  Offset  8:     Non-resident flag (0 = resident)
  Offset  9:     Name length
  Offset 10-11:  Name offset
  Offset 12-13:  Flags
  Offset 14-15:  Attribute ID
  For resident (non-resident=0):
    Offset 16-19: Value length
    Offset 20-21: Value offset
  For non-resident:
    Offset 16-23: Starting VCN
    Offset 24-31: Ending VCN
    Offset 32-33: Data run offset
    ...

Author: Edward Marez
License: MIT
"""

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from .image_reader import ImageReader
from .utils import ntfs_timestamp_to_datetime, decode_utf16le_name, format_bytes


# MFT record constants
MFT_SIGNATURE = b"FILE"
BAAD_SIGNATURE = b"BAAD"
MFT_RECORD_FLAG_IN_USE     = 0x0001
MFT_RECORD_FLAG_DIRECTORY  = 0x0002

# Attribute type codes
ATTR_STANDARD_INFORMATION  = 0x10
ATTR_ATTRIBUTE_LIST        = 0x20
ATTR_FILE_NAME             = 0x30
ATTR_VOLUME_VERSION        = 0x40
ATTR_SECURITY_DESCRIPTOR   = 0x50
ATTR_VOLUME_NAME           = 0x60
ATTR_VOLUME_INFORMATION    = 0x70
ATTR_DATA                  = 0x80
ATTR_INDEX_ROOT            = 0x90
ATTR_INDEX_ALLOCATION      = 0xA0
ATTR_BITMAP                = 0xB0
ATTR_SYMBOLIC_LINK         = 0xC0
ATTR_EA_INFORMATION        = 0xD0
ATTR_EA                    = 0xE0
ATTR_END                   = 0xFFFFFFFF

# File attribute flags (in $STANDARD_INFORMATION)
FILE_ATTR_READONLY     = 0x0001
FILE_ATTR_HIDDEN       = 0x0002
FILE_ATTR_SYSTEM       = 0x0004
FILE_ATTR_DIRECTORY    = 0x0010
FILE_ATTR_ARCHIVE      = 0x0020
FILE_ATTR_DEVICE       = 0x0040
FILE_ATTR_NORMAL       = 0x0080
FILE_ATTR_TEMPORARY    = 0x0100
FILE_ATTR_SPARSE       = 0x0200
FILE_ATTR_REPARSE      = 0x0400
FILE_ATTR_COMPRESSED   = 0x0800
FILE_ATTR_OFFLINE      = 0x1000
FILE_ATTR_ENCRYPTED    = 0x4000


@dataclass
class NTFSStandardInfo:
    """Parsed $STANDARD_INFORMATION attribute (0x10)."""
    created: Optional[datetime]
    modified: Optional[datetime]
    mft_modified: Optional[datetime]
    accessed: Optional[datetime]
    file_attributes: int

    @property
    def attr_string(self) -> str:
        flags = []
        if self.file_attributes & FILE_ATTR_READONLY:  flags.append("R")
        if self.file_attributes & FILE_ATTR_HIDDEN:    flags.append("H")
        if self.file_attributes & FILE_ATTR_SYSTEM:    flags.append("S")
        if self.file_attributes & FILE_ATTR_DIRECTORY: flags.append("D")
        if self.file_attributes & FILE_ATTR_ARCHIVE:   flags.append("A")
        if self.file_attributes & FILE_ATTR_ENCRYPTED: flags.append("E")
        if self.file_attributes & FILE_ATTR_COMPRESSED:flags.append("C")
        return "".join(flags) if flags else "-"

    def to_dict(self) -> dict:
        return {
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "mft_modified": self.mft_modified.isoformat() if self.mft_modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
            "file_attributes": f"0x{self.file_attributes:08X}",
            "attr_string": self.attr_string,
        }


@dataclass
class NTFSFileName:
    """Parsed $FILE_NAME attribute (0x30)."""
    parent_ref: int          # MFT reference of parent directory
    created: Optional[datetime]
    modified: Optional[datetime]
    mft_modified: Optional[datetime]
    accessed: Optional[datetime]
    allocated_size: int
    real_size: int
    file_attributes: int
    name_type: int           # 0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS
    name: str

    @property
    def name_type_str(self) -> str:
        return {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}.get(self.name_type, "Unknown")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "name_type": self.name_type_str,
            "parent_ref": self.parent_ref,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "mft_modified": self.mft_modified.isoformat() if self.mft_modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
            "allocated_size": self.allocated_size,
            "real_size": self.real_size,
            "size_human": format_bytes(self.real_size),
        }


@dataclass
class MFTRecord:
    """Parsed MFT record (file or directory metadata)."""

    record_number: int
    sequence_number: int
    flags: int
    hard_link_count: int
    in_use: bool
    is_directory: bool
    standard_info: Optional[NTFSStandardInfo]
    file_names: List[NTFSFileName]
    data_size: int = 0         # Size from $DATA attribute
    is_nonresident_data: bool = False

    @property
    def primary_name(self) -> str:
        """Return the best filename (prefer Win32/Win32&DOS namespace)."""
        # Priority: Win32&DOS (3) > Win32 (1) > POSIX (0) > DOS (2)
        priority = {3: 4, 1: 3, 0: 2, 2: 1}
        if not self.file_names:
            return f"[MFT#{self.record_number}]"
        best = max(self.file_names, key=lambda fn: priority.get(fn.name_type, 0))
        return best.name

    @property
    def created(self) -> Optional[datetime]:
        if self.standard_info:
            return self.standard_info.created
        if self.file_names:
            return self.file_names[0].created
        return None

    @property
    def modified(self) -> Optional[datetime]:
        if self.standard_info:
            return self.standard_info.modified
        if self.file_names:
            return self.file_names[0].modified
        return None

    @property
    def accessed(self) -> Optional[datetime]:
        if self.standard_info:
            return self.standard_info.accessed
        if self.file_names:
            return self.file_names[0].accessed
        return None

    def to_dict(self) -> dict:
        fn = self.file_names[0].to_dict() if self.file_names else {}
        return {
            "record_number": self.record_number,
            "name": self.primary_name,
            "in_use": self.in_use,
            "is_deleted": not self.in_use,
            "is_directory": self.is_directory,
            "sequence_number": self.sequence_number,
            "hard_link_count": self.hard_link_count,
            "data_size": self.data_size,
            "size_human": format_bytes(self.data_size),
            "standard_info": self.standard_info.to_dict() if self.standard_info else None,
            "file_names": [fn_obj.to_dict() for fn_obj in self.file_names],
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
        }


@dataclass
class NTFSBootSector:
    """Parsed NTFS Boot Sector."""

    oem_id: str
    bytes_per_sector: int
    sectors_per_cluster: int
    total_sectors: int
    mft_cluster_number: int
    mft_mirror_cluster_number: int
    clusters_per_mft_record: int
    clusters_per_index_block: int

    @property
    def bytes_per_cluster(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def mft_record_size(self) -> int:
        """MFT record size in bytes."""
        if self.clusters_per_mft_record < 0:
            # Negative value: record size = 2^|value|
            return 1 << (-self.clusters_per_mft_record)
        else:
            return self.clusters_per_mft_record * self.bytes_per_cluster

    @property
    def mft_offset(self) -> int:
        """Byte offset of $MFT from partition start."""
        return self.mft_cluster_number * self.bytes_per_cluster

    def to_dict(self) -> dict:
        return {
            "oem_id": self.oem_id,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "bytes_per_cluster": self.bytes_per_cluster,
            "total_sectors": self.total_sectors,
            "mft_cluster_number": self.mft_cluster_number,
            "mft_record_size": self.mft_record_size,
            "mft_offset": self.mft_offset,
        }


@dataclass
class NTFSResult:
    """Result of parsing an NTFS filesystem."""

    boot_sector: Optional[NTFSBootSector]
    records: List[MFTRecord]
    valid: bool
    error: str = ""

    @property
    def active_records(self) -> List[MFTRecord]:
        return [r for r in self.records if r.in_use]

    @property
    def deleted_records(self) -> List[MFTRecord]:
        return [r for r in self.records if not r.in_use]

    @property
    def files(self) -> List[MFTRecord]:
        return [r for r in self.records if not r.is_directory]

    @property
    def directories(self) -> List[MFTRecord]:
        return [r for r in self.records if r.is_directory]

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "error": self.error,
            "boot_sector": self.boot_sector.to_dict() if self.boot_sector else None,
            "total_records": len(self.records),
            "active_records": len(self.active_records),
            "deleted_records": len(self.deleted_records),
            "records": [r.to_dict() for r in self.records],
        }


class NTFSParser:
    """
    Parses an NTFS filesystem from a partition within a raw disk image.

    Reads the MFT sequentially (not via data runs), which works on
    synthetic images and simple real images where MFT starts at a
    known cluster offset.

    Usage:
        reader = ImageReader("evidence.dd")
        parser = NTFSParser(reader, partition_lba_start=2048)
        result = parser.parse(max_records=1000)
        for rec in result.deleted_records:
            print(rec.primary_name, rec.modified)
    """

    # Well-known MFT record numbers (reserved by NTFS)
    SYSTEM_RECORDS = {
        0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume",
        4: "$AttrDef", 5: ".", 6: "$Bitmap", 7: "$Boot",
        8: "$BadClus", 9: "$Secure", 10: "$UpCase", 11: "$Extend",
    }

    def __init__(self, reader: ImageReader, partition_lba_start: int = 0):
        self.reader = reader
        self.partition_lba_start = partition_lba_start
        self._boot_sector: Optional[NTFSBootSector] = None

    def _partition_offset(self) -> int:
        """Byte offset of this partition in the image."""
        return self.partition_lba_start * self.reader.sector_size

    def parse_boot_sector(self) -> Optional[NTFSBootSector]:
        """Parse NTFS boot sector from partition start."""
        partition_off = self._partition_offset()
        data = self.reader.read_bytes(partition_off, 512)
        if len(data) < 84:
            return None

        oem_id = data[3:11].decode("ascii", errors="replace").strip()
        if "NTFS" not in oem_id:
            return None

        bytes_per_sector, = struct.unpack_from("<H", data, 11)
        sectors_per_cluster = data[13]
        total_sectors, = struct.unpack_from("<Q", data, 40)
        mft_cluster, = struct.unpack_from("<Q", data, 48)
        mft_mirror_cluster, = struct.unpack_from("<Q", data, 56)
        clusters_per_mft_raw = struct.unpack_from("<b", data, 64)[0]  # signed byte
        clusters_per_index = struct.unpack_from("<b", data, 68)[0]    # signed byte

        if bytes_per_sector == 0:
            return None

        return NTFSBootSector(
            oem_id=oem_id,
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            total_sectors=total_sectors,
            mft_cluster_number=mft_cluster,
            mft_mirror_cluster_number=mft_mirror_cluster,
            clusters_per_mft_record=clusters_per_mft_raw,
            clusters_per_index_block=clusters_per_index,
        )

    def _read_mft_record_raw(self, boot: NTFSBootSector, record_number: int) -> bytes:
        """Read one raw MFT record by its record number."""
        record_size = boot.mft_record_size
        partition_off = self._partition_offset()
        mft_byte_offset = boot.mft_offset
        record_offset = mft_byte_offset + record_number * record_size
        absolute_offset = partition_off + record_offset
        return self.reader.read_bytes(absolute_offset, record_size)

    def _parse_mft_record(self, data: bytes, record_number: int) -> Optional[MFTRecord]:
        """Parse one MFT record from raw bytes."""
        if len(data) < 48:
            return None

        sig = data[0:4]
        if sig != MFT_SIGNATURE:
            return None

        update_seq_offset, = struct.unpack_from("<H", data, 4)
        update_seq_count, = struct.unpack_from("<H", data, 6)
        sequence_number, = struct.unpack_from("<H", data, 16)
        hard_link_count, = struct.unpack_from("<H", data, 18)
        attr_offset, = struct.unpack_from("<H", data, 20)
        flags, = struct.unpack_from("<H", data, 22)
        used_size, = struct.unpack_from("<I", data, 24)

        in_use = bool(flags & MFT_RECORD_FLAG_IN_USE)
        is_directory = bool(flags & MFT_RECORD_FLAG_DIRECTORY)

        # Apply update sequence (fixup)
        data = self._apply_fixup(bytearray(data), update_seq_offset, update_seq_count)

        standard_info: Optional[NTFSStandardInfo] = None
        file_names: List[NTFSFileName] = []
        data_size = 0
        is_nonresident = False

        # Walk attributes
        offset = attr_offset
        while offset + 8 <= len(data):
            attr_type, = struct.unpack_from("<I", data, offset)
            if attr_type == ATTR_END or attr_type == 0:
                break

            attr_len, = struct.unpack_from("<I", data, offset + 4)
            if attr_len == 0 or offset + attr_len > len(data):
                break

            non_resident = data[offset + 8]
            name_len = data[offset + 9]
            attr_id = struct.unpack_from("<H", data, offset + 14)[0] if offset + 16 <= len(data) else 0

            # Get attribute value
            if non_resident == 0:
                # Resident attribute
                if offset + 24 > len(data):
                    offset += attr_len
                    continue
                value_len, = struct.unpack_from("<I", data, offset + 16)
                value_offset, = struct.unpack_from("<H", data, offset + 20)
                value_start = offset + value_offset
                value_end = value_start + value_len
                if value_end <= len(data):
                    attr_value = data[value_start:value_end]
                else:
                    attr_value = data[value_start:] if value_start < len(data) else b""
            else:
                attr_value = b""  # Non-resident: we don't follow data runs in this parser

            if attr_type == ATTR_STANDARD_INFORMATION:
                standard_info = self._parse_standard_information(attr_value)
            elif attr_type == ATTR_FILE_NAME:
                fn = self._parse_file_name(attr_value)
                if fn:
                    file_names.append(fn)
            elif attr_type == ATTR_DATA:
                if non_resident == 0:
                    data_size = len(attr_value)
                else:
                    is_nonresident = True
                    # Try to read real size from non-resident header
                    if offset + 56 <= len(data):
                        real_size, = struct.unpack_from("<Q", data, offset + 48)
                        data_size = real_size

            offset += attr_len

        return MFTRecord(
            record_number=record_number,
            sequence_number=sequence_number,
            flags=flags,
            hard_link_count=hard_link_count,
            in_use=in_use,
            is_directory=is_directory,
            standard_info=standard_info,
            file_names=file_names,
            data_size=data_size,
            is_nonresident_data=is_nonresident,
        )

    def _apply_fixup(self, data: bytearray, usn_offset: int, usn_count: int) -> bytes:
        """
        Apply NTFS update sequence number (fixup) to a sector.

        The update sequence replaces the last 2 bytes of each 512-byte
        sector with original values stored in the update sequence array.
        """
        try:
            if usn_offset < 4 or usn_count < 2:
                return bytes(data)
            # USN array: first entry is the sequence number, rest are original values
            sector_size = 512
            for i in range(1, usn_count):
                sector_end = i * sector_size - 2
                if sector_end + 2 > len(data):
                    break
                orig_offset = usn_offset + i * 2
                if orig_offset + 2 > len(data):
                    break
                data[sector_end]     = data[orig_offset]
                data[sector_end + 1] = data[orig_offset + 1]
        except (IndexError, struct.error):
            pass
        return bytes(data)

    def _parse_standard_information(self, data: bytes) -> Optional[NTFSStandardInfo]:
        """Parse $STANDARD_INFORMATION attribute value."""
        if len(data) < 48:
            return None
        try:
            created_ts, = struct.unpack_from("<Q", data, 0)
            modified_ts, = struct.unpack_from("<Q", data, 8)
            mft_modified_ts, = struct.unpack_from("<Q", data, 16)
            accessed_ts, = struct.unpack_from("<Q", data, 24)
            file_attrs, = struct.unpack_from("<I", data, 32)
            return NTFSStandardInfo(
                created=ntfs_timestamp_to_datetime(created_ts),
                modified=ntfs_timestamp_to_datetime(modified_ts),
                mft_modified=ntfs_timestamp_to_datetime(mft_modified_ts),
                accessed=ntfs_timestamp_to_datetime(accessed_ts),
                file_attributes=file_attrs,
            )
        except struct.error:
            return None

    def _parse_file_name(self, data: bytes) -> Optional[NTFSFileName]:
        """Parse $FILE_NAME attribute value."""
        if len(data) < 66:
            return None
        try:
            parent_ref, = struct.unpack_from("<Q", data, 0)
            created_ts, = struct.unpack_from("<Q", data, 8)
            modified_ts, = struct.unpack_from("<Q", data, 16)
            mft_modified_ts, = struct.unpack_from("<Q", data, 24)
            accessed_ts, = struct.unpack_from("<Q", data, 32)
            alloc_size, = struct.unpack_from("<Q", data, 40)
            real_size, = struct.unpack_from("<Q", data, 48)
            file_attrs, = struct.unpack_from("<I", data, 56)
            # Bytes 60-63: Reparse tag or EAs
            name_len = data[64]
            name_type = data[65]
            name_bytes = data[66: 66 + name_len * 2]
            name = decode_utf16le_name(name_bytes, max_chars=name_len)
            return NTFSFileName(
                parent_ref=parent_ref & 0x0000FFFFFFFFFFFF,  # lower 48 bits
                created=ntfs_timestamp_to_datetime(created_ts),
                modified=ntfs_timestamp_to_datetime(modified_ts),
                mft_modified=ntfs_timestamp_to_datetime(mft_modified_ts),
                accessed=ntfs_timestamp_to_datetime(accessed_ts),
                allocated_size=alloc_size,
                real_size=real_size,
                file_attributes=file_attrs,
                name_type=name_type,
                name=name,
            )
        except (struct.error, IndexError):
            return None

    def parse(self, max_records: int = 10000) -> NTFSResult:
        """
        Parse the NTFS filesystem, reading MFT records sequentially.

        Args:
            max_records: Maximum number of MFT records to parse.

        Returns:
            NTFSResult with boot sector and all MFT records.
        """
        boot_sector = self.parse_boot_sector()
        if boot_sector is None:
            return NTFSResult(
                boot_sector=None, records=[], valid=False,
                error="Not a valid NTFS filesystem (OEM ID mismatch)"
            )

        self._boot_sector = boot_sector
        records: List[MFTRecord] = []

        consecutive_invalid = 0
        max_consecutive_invalid = 32  # Stop after 32 consecutive non-FILE records

        for record_num in range(max_records):
            try:
                raw = self._read_mft_record_raw(boot_sector, record_num)
                if not raw or len(raw) < 4:
                    break

                # If the signature is not FILE or BAAD, skip this record but keep going.
                # The MFT can have gaps of allocated-but-unused records with null bytes.
                if raw[0:4] not in (MFT_SIGNATURE, BAAD_SIGNATURE):
                    consecutive_invalid += 1
                    if consecutive_invalid > max_consecutive_invalid:
                        break
                    continue

                consecutive_invalid = 0
                record = self._parse_mft_record(raw, record_num)
                if record is not None:
                    records.append(record)
            except Exception:
                consecutive_invalid += 1
                if consecutive_invalid > max_consecutive_invalid:
                    break
                continue

        return NTFSResult(
            boot_sector=boot_sector,
            records=records,
            valid=True,
        )

    def print_summary(self, result: Optional[NTFSResult] = None) -> None:
        """Print formatted NTFS summary to stdout."""
        if result is None:
            result = self.parse()

        print("=" * 70)
        print("NTFS FILESYSTEM ANALYSIS")
        print("=" * 70)

        if not result.valid:
            print(f"Error: {result.error}")
            return

        bs = result.boot_sector
        if bs:
            print(f"OEM ID:           {bs.oem_id}")
            print(f"Bytes/Sector:     {bs.bytes_per_sector}")
            print(f"Sectors/Cluster:  {bs.sectors_per_cluster}")
            print(f"Cluster Size:     {format_bytes(bs.bytes_per_cluster)}")
            print(f"Total Sectors:    {bs.total_sectors:,}")
            print(f"MFT Cluster:      {bs.mft_cluster_number}")
            print(f"MFT Record Size:  {bs.mft_record_size} bytes")
            print()

        print(f"Total MFT Records: {len(result.records)}")
        print(f"Active:            {len(result.active_records)}")
        print(f"Deleted:           {len(result.deleted_records)}")
        print()

        all_records = result.records
        if all_records:
            print(f"{'#':<8} {'Name':<35} {'Size':>10} {'Modified':<22} {'Del?'}")
            print("-" * 85)
            for r in all_records[:100]:  # Limit display
                del_flag = "[DELETED]" if not r.in_use else ""
                mod = r.modified.strftime("%Y-%m-%d %H:%M:%S") if r.modified else "N/A"
                size = format_bytes(r.data_size) if r.data_size else "-"
                print(f"{r.record_number:<8} {r.primary_name[:35]:<35} {size:>10} {mod:<22} {del_flag}")
        print()
