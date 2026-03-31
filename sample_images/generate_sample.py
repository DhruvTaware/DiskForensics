"""
Synthetic Disk Image Generator for DiskForensics.

Creates small raw disk images with valid binary filesystem structures
that can be parsed by DiskForensics. Uses only Python's struct module.

Images created:
  1. demo_fat32.dd  — 2 MB: MBR + FAT32 partition with files and deleted entries
  2. demo_gpt.dd    — 1 MB: GPT header + protective MBR + partition entries
  3. demo_ntfs.dd   — 4 MB: MBR + NTFS partition with MFT records

All binary structures are constructed using struct.pack at exact byte offsets.

Author: Edward Marez
License: MIT
"""

import struct
import zlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SAMPLE_DIR = Path(__file__).parent


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def fat_date(dt: datetime) -> int:
    """Pack datetime into FAT date word."""
    return ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day


def fat_time(dt: datetime) -> int:
    """Pack datetime into FAT time word."""
    return (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)


def ntfs_ts(dt: datetime) -> int:
    """Convert datetime to NTFS timestamp (100-ns intervals since 1601-01-01)."""
    epoch_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - epoch_1601
    return int(delta.total_seconds() * 10_000_000)


# ---------------------------------------------------------------------------
# MBR construction helpers
# ---------------------------------------------------------------------------

def make_partition_entry(
    boot: bool,
    ptype: int,
    lba_start: int,
    num_sectors: int,
) -> bytes:
    """
    Build a 16-byte MBR partition entry.

    Args:
        boot:       True if partition is bootable (0x80).
        ptype:      Partition type byte.
        lba_start:  LBA address of first sector.
        num_sectors: Total sector count.
    """
    status = 0x80 if boot else 0x00

    # CHS encoding (capped at 1023/255/63 for large disks)
    def lba_to_chs(lba):
        heads_per_cyl = 255
        sects_per_track = 63
        c = lba // (heads_per_cyl * sects_per_track)
        temp = lba % (heads_per_cyl * sects_per_track)
        h = temp // sects_per_track
        s = temp % sects_per_track + 1
        c = min(c, 1023)
        return bytes([h, (s & 0x3F) | ((c >> 8) << 6), c & 0xFF])

    chs_first = lba_to_chs(lba_start)
    chs_last  = lba_to_chs(lba_start + num_sectors - 1)

    entry = bytearray(16)
    entry[0]   = status
    entry[1:4] = chs_first
    entry[4]   = ptype
    entry[5:8] = chs_last
    struct.pack_into("<I", entry, 8,  lba_start)
    struct.pack_into("<I", entry, 12, num_sectors)
    return bytes(entry)


def make_mbr(partition_entries: list[tuple]) -> bytes:
    """
    Build a complete 512-byte MBR.

    Args:
        partition_entries: List of up to 4 tuples (boot, type, lba_start, num_sectors).

    Returns:
        512-byte MBR bytes.
    """
    mbr = bytearray(512)

    # Bootstrap code: a simple x86 instruction (INT 18h for "no bootable disk")
    # JMP SHORT $+2; NOP; ... INT 18h; HLT
    mbr[0:4] = bytes([0xEB, 0x58, 0x90, 0x00])  # jmp short + nop

    # Build partition table entries at offset 446
    for i, args in enumerate(partition_entries[:4]):
        entry = make_partition_entry(*args)
        offset = 446 + i * 16
        mbr[offset:offset + 16] = entry

    # Boot signature
    mbr[510] = 0x55
    mbr[511] = 0xAA

    return bytes(mbr)


# ---------------------------------------------------------------------------
# FAT32 construction
# ---------------------------------------------------------------------------

def make_fat32_boot_sector(
    total_sectors: int,
    sectors_per_cluster: int = 1,
    reserved_sectors: int = 4,
    num_fats: int = 2,
    sectors_per_fat: int = 1,
    root_cluster: int = 2,
    volume_label: str = "EVIDENCE   ",
) -> bytes:
    """Build a 512-byte FAT32 boot sector."""
    sector = bytearray(512)

    # Jump + NOP
    sector[0:3] = bytes([0xEB, 0x58, 0x90])

    # OEM Name (8 bytes)
    oem = b"MSDOS5.0"
    sector[3:11] = oem

    # BPB
    struct.pack_into("<H", sector, 11, 512)                # Bytes per sector
    sector[13] = sectors_per_cluster                        # Sectors per cluster
    struct.pack_into("<H", sector, 14, reserved_sectors)   # Reserved sectors
    sector[16] = num_fats                                   # Number of FATs
    struct.pack_into("<H", sector, 17, 0)                  # Root entry count (0 for FAT32)
    struct.pack_into("<H", sector, 19, 0)                  # Total sectors 16 (0 = use 32-bit field)
    sector[21] = 0xF8                                       # Media descriptor (fixed disk)
    struct.pack_into("<H", sector, 22, 0)                  # Sectors per FAT 16 (0 for FAT32)
    struct.pack_into("<H", sector, 24, 63)                 # Sectors per track
    struct.pack_into("<H", sector, 26, 255)                # Number of heads
    struct.pack_into("<I", sector, 28, 0)                  # Hidden sectors
    struct.pack_into("<I", sector, 32, total_sectors)      # Total sectors 32

    # FAT32 Extended BPB
    struct.pack_into("<I", sector, 36, sectors_per_fat)    # Sectors per FAT32
    struct.pack_into("<H", sector, 40, 0)                  # Flags
    struct.pack_into("<H", sector, 42, 0)                  # FAT version (0.0)
    struct.pack_into("<I", sector, 44, root_cluster)       # Root cluster
    struct.pack_into("<H", sector, 48, 1)                  # FSInfo sector
    struct.pack_into("<H", sector, 50, 6)                  # Backup boot sector
    sector[64] = 0x80                                       # Drive number
    sector[65] = 0x00                                       # Reserved
    sector[66] = 0x29                                       # Extended boot signature
    struct.pack_into("<I", sector, 67, 0xDEADBEEF)        # Volume ID
    label_bytes = volume_label[:11].ljust(11).encode("ascii", errors="replace")
    sector[71:82] = label_bytes                             # Volume label
    sector[82:90] = b"FAT32   "                            # Filesystem type

    # Boot signature
    sector[510] = 0x55
    sector[511] = 0xAA

    return bytes(sector)


def make_fat32_fat(
    total_fat_entries: int,
    cluster_chains: dict[int, list[int]],
    free_clusters: list[int],
) -> bytes:
    """
    Build a FAT32 File Allocation Table.

    Args:
        total_fat_entries: Number of 4-byte FAT entries to allocate.
        cluster_chains: Dict mapping start cluster -> list of clusters in chain.
        free_clusters: Explicit list of clusters to mark free.

    Returns:
        FAT bytes (total_fat_entries * 4 bytes).
    """
    fat = bytearray(total_fat_entries * 4)

    # Entry 0: Media descriptor
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)
    # Entry 1: End of chain marker
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)

    # Write cluster chains
    for chain in cluster_chains.values():
        for i, cluster in enumerate(chain):
            if i < len(chain) - 1:
                next_cluster = chain[i + 1]
                struct.pack_into("<I", fat, cluster * 4, next_cluster)
            else:
                struct.pack_into("<I", fat, cluster * 4, 0x0FFFFFFF)  # EOC

    # Free clusters are already 0 (bytearray default), but explicitly mark them
    for cluster in free_clusters:
        struct.pack_into("<I", fat, cluster * 4, 0x00000000)

    return bytes(fat)


def make_fat32_dir_entry(
    name: str,          # 8.3 short name (8 + 3, no dot)
    ext: str,           # Extension (3 chars)
    attrs: int,
    first_cluster: int,
    file_size: int,
    created: datetime,
    modified: datetime,
    accessed: datetime,
    deleted: bool = False,
) -> bytes:
    """Build a 32-byte FAT32 directory entry."""
    entry = bytearray(32)

    # Short name: pad to 8 chars, uppercase
    name_padded = name[:8].upper().ljust(8)
    ext_padded  = ext[:3].upper().ljust(3)

    name_bytes = name_padded.encode("ascii", errors="replace")
    ext_bytes  = ext_padded.encode("ascii", errors="replace")

    if deleted:
        entry[0] = 0xE5
        entry[1:8] = name_bytes[1:8]
    else:
        entry[0:8] = name_bytes

    entry[8:11]  = ext_bytes
    entry[11]    = attrs

    entry[13]    = 0  # Creation time tenths
    struct.pack_into("<H", entry, 14, fat_time(created))
    struct.pack_into("<H", entry, 16, fat_date(created))
    struct.pack_into("<H", entry, 18, fat_date(accessed))
    struct.pack_into("<H", entry, 20, (first_cluster >> 16) & 0xFFFF)  # Cluster high
    struct.pack_into("<H", entry, 22, fat_time(modified))
    struct.pack_into("<H", entry, 24, fat_date(modified))
    struct.pack_into("<H", entry, 26, first_cluster & 0xFFFF)         # Cluster low
    struct.pack_into("<I", entry, 28, file_size)

    return bytes(entry)


def make_dot_entries(this_cluster: int, parent_cluster: int, dt: datetime) -> bytes:
    """Create . and .. directory entries."""
    dot    = make_fat32_dir_entry(".", "", 0x10, this_cluster, 0, dt, dt, dt)
    dotdot = make_fat32_dir_entry("..", "", 0x10, parent_cluster, 0, dt, dt, dt)
    return dot + dotdot


# ---------------------------------------------------------------------------
# GPT construction
# ---------------------------------------------------------------------------

def make_gpt_partition_type_guid_bytes(guid_str: str) -> bytes:
    """Convert a standard GUID string to mixed-endian GPT bytes."""
    parts = guid_str.replace("-", "")
    # First 3 components are little-endian
    p1 = int(parts[0:8], 16)
    p2 = int(parts[8:12], 16)
    p3 = int(parts[12:16], 16)
    p4 = bytes.fromhex(parts[16:20])
    p5 = bytes.fromhex(parts[20:32])
    return struct.pack("<IHH", p1, p2, p3) + p4 + p5


def make_gpt_partition_entry(
    type_guid_str: str,
    unique_guid: bytes,
    lba_start: int,
    lba_end: int,
    attributes: int,
    name: str,
) -> bytes:
    """Build a 128-byte GPT partition entry."""
    entry = bytearray(128)
    type_guid_bytes = make_gpt_partition_type_guid_bytes(type_guid_str)
    entry[0:16]  = type_guid_bytes
    entry[16:32] = unique_guid[:16]
    struct.pack_into("<Q", entry, 32, lba_start)
    struct.pack_into("<Q", entry, 40, lba_end)
    struct.pack_into("<Q", entry, 48, attributes)
    # Name: UTF-16LE, max 36 chars (72 bytes)
    name_bytes = name[:36].encode("utf-16-le")
    entry[56:56 + len(name_bytes)] = name_bytes
    return bytes(entry)


def make_gpt_header(
    my_lba: int,
    alternate_lba: int,
    first_usable_lba: int,
    last_usable_lba: int,
    disk_guid: bytes,
    partition_entry_lba: int,
    num_entries: int,
    partition_array: bytes,
) -> bytes:
    """Build a 512-byte sector containing a GPT header."""
    sector = bytearray(512)

    # Build the header (92 bytes) with zeroed CRC field
    header = bytearray(92)
    header[0:8]  = b"EFI PART"                              # Signature
    struct.pack_into("<I", header, 8,  0x00010000)          # Revision 1.0
    struct.pack_into("<I", header, 12, 92)                  # Header size
    struct.pack_into("<I", header, 16, 0)                   # CRC32 (placeholder)
    struct.pack_into("<I", header, 20, 0)                   # Reserved
    struct.pack_into("<Q", header, 24, my_lba)              # My LBA
    struct.pack_into("<Q", header, 32, alternate_lba)       # Alternate LBA
    struct.pack_into("<Q", header, 40, first_usable_lba)    # First usable LBA
    struct.pack_into("<Q", header, 48, last_usable_lba)     # Last usable LBA
    header[56:72] = disk_guid[:16]                          # Disk GUID
    struct.pack_into("<Q", header, 72, partition_entry_lba) # Partition entries start LBA
    struct.pack_into("<I", header, 80, num_entries)         # Number of entries
    struct.pack_into("<I", header, 84, 128)                 # Entry size
    # CRC32 of partition array
    part_crc = zlib.crc32(partition_array) & 0xFFFFFFFF
    struct.pack_into("<I", header, 88, part_crc)

    # Compute header CRC (over first 92 bytes, with CRC field zeroed)
    header_crc = zlib.crc32(bytes(header)) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, header_crc)

    sector[0:92] = header
    return bytes(sector)


# ---------------------------------------------------------------------------
# NTFS construction
# ---------------------------------------------------------------------------

def make_ntfs_boot_sector(
    total_sectors: int,
    mft_cluster: int = 4,
    sectors_per_cluster: int = 8,
    bytes_per_sector: int = 512,
) -> bytes:
    """Build a 512-byte NTFS boot sector."""
    sector = bytearray(512)

    # Jump + NOP
    sector[0:3] = bytes([0xEB, 0x52, 0x90])

    # OEM ID
    sector[3:11] = b"NTFS    "

    # BPB
    struct.pack_into("<H", sector, 11, bytes_per_sector)
    sector[13] = sectors_per_cluster
    struct.pack_into("<H", sector, 14, 0)    # Reserved sectors
    sector[16] = 0                            # FAT count (0 for NTFS)
    struct.pack_into("<H", sector, 17, 0)    # Root entry count
    struct.pack_into("<H", sector, 19, 0)    # Total sectors 16
    sector[21] = 0xF8                         # Media
    struct.pack_into("<H", sector, 22, 0)    # Sectors per FAT
    struct.pack_into("<H", sector, 24, 63)   # Sectors per track
    struct.pack_into("<H", sector, 26, 255)  # Heads
    struct.pack_into("<I", sector, 28, 0)    # Hidden sectors
    struct.pack_into("<I", sector, 32, 0)    # Total sectors 32 (0 for NTFS)

    # NTFS Extended fields (offset 40+)
    struct.pack_into("<Q", sector, 40, total_sectors)         # Total sectors
    struct.pack_into("<Q", sector, 48, mft_cluster)           # $MFT cluster
    struct.pack_into("<Q", sector, 56, mft_cluster * 2)       # $MFTMirr cluster
    struct.pack_into("<b", sector, 64, -10)                   # Clusters per MFT record (2^10 = 1024 bytes)
    struct.pack_into("<b", sector, 65, 0)
    struct.pack_into("<b", sector, 66, 0)
    struct.pack_into("<b", sector, 67, 0)
    struct.pack_into("<b", sector, 68, 1)                     # Clusters per index block
    struct.pack_into("<Q", sector, 72, 0x1234567890ABCDEF)    # Volume serial number

    # Boot signature
    sector[510] = 0x55
    sector[511] = 0xAA

    return bytes(sector)


def make_ntfs_standard_information(
    created: datetime,
    modified: datetime,
    mft_modified: datetime,
    accessed: datetime,
    file_attrs: int = 0x20,  # Archive
) -> bytes:
    """Build $STANDARD_INFORMATION attribute value (48 bytes minimum)."""
    si = bytearray(48)
    struct.pack_into("<Q", si, 0,  ntfs_ts(created))
    struct.pack_into("<Q", si, 8,  ntfs_ts(modified))
    struct.pack_into("<Q", si, 16, ntfs_ts(mft_modified))
    struct.pack_into("<Q", si, 24, ntfs_ts(accessed))
    struct.pack_into("<I", si, 32, file_attrs)
    return bytes(si)


def make_ntfs_file_name(
    parent_ref: int,
    created: datetime,
    modified: datetime,
    mft_modified: datetime,
    accessed: datetime,
    allocated_size: int,
    real_size: int,
    file_attrs: int,
    name: str,
    name_type: int = 1,  # Win32
) -> bytes:
    """Build $FILE_NAME attribute value."""
    name_utf16 = name.encode("utf-16-le")
    name_len = len(name)
    fn = bytearray(66 + len(name_utf16))
    struct.pack_into("<Q", fn, 0, parent_ref)                # Parent MFT reference
    struct.pack_into("<Q", fn, 8,  ntfs_ts(created))
    struct.pack_into("<Q", fn, 16, ntfs_ts(modified))
    struct.pack_into("<Q", fn, 24, ntfs_ts(mft_modified))
    struct.pack_into("<Q", fn, 32, ntfs_ts(accessed))
    struct.pack_into("<Q", fn, 40, allocated_size)
    struct.pack_into("<Q", fn, 48, real_size)
    struct.pack_into("<I", fn, 56, file_attrs)
    struct.pack_into("<I", fn, 60, 0)                       # EA reparse
    fn[64] = name_len & 0xFF
    fn[65] = name_type
    fn[66:66 + len(name_utf16)] = name_utf16
    return bytes(fn)


def make_ntfs_attr_header_resident(
    attr_type: int,
    attr_id: int,
    value: bytes,
) -> bytes:
    """
    Build a resident NTFS attribute with header.

    Total size is padded to 8-byte alignment.
    """
    value_len = len(value)
    value_offset = 24  # Header is 24 bytes for resident
    # Total length: header + value, padded to 8 bytes
    total = value_offset + value_len
    total = (total + 7) & ~7

    header = bytearray(total)
    struct.pack_into("<I", header, 0, attr_type)             # Type
    struct.pack_into("<I", header, 4, total)                 # Length
    header[8]  = 0                                            # Non-resident flag
    header[9]  = 0                                            # Name length
    struct.pack_into("<H", header, 10, 0)                    # Name offset
    struct.pack_into("<H", header, 12, 0)                    # Flags
    struct.pack_into("<H", header, 14, attr_id)              # Attribute ID
    struct.pack_into("<I", header, 16, value_len)            # Value length
    struct.pack_into("<H", header, 20, value_offset)         # Value offset
    header[22] = 0                                            # Indexed flag
    header[23] = 0                                            # Padding
    header[value_offset:value_offset + value_len] = value
    return bytes(header)


def make_ntfs_mft_record(
    record_number: int,
    in_use: bool,
    is_directory: bool,
    attributes: bytes,
    record_size: int = 1024,
) -> bytes:
    """
    Build a complete NTFS MFT record.

    Args:
        record_number: MFT record number.
        in_use:        True if the file is active.
        is_directory:  True for directory records.
        attributes:    Raw bytes of concatenated attribute structures.
        record_size:   Total MFT record size (default 1024).
    """
    record = bytearray(record_size)

    # Signature
    record[0:4] = b"FILE"

    # Update sequence offset and count (USN array at offset 48)
    usn_offset = 48
    usn_count  = 3  # 1 current + 2 fixup values (for 2 sectors in 1024-byte record)
    struct.pack_into("<H", record, 4, usn_offset)
    struct.pack_into("<H", record, 6, usn_count)

    # Log file sequence number (arbitrary)
    struct.pack_into("<Q", record, 8, record_number * 100)

    # Sequence number
    struct.pack_into("<H", record, 16, 1)

    # Hard link count
    struct.pack_into("<H", record, 18, 1)

    # Attribute offset — past the USN array
    attr_start = usn_offset + usn_count * 2
    attr_start = (attr_start + 7) & ~7  # Align to 8
    struct.pack_into("<H", record, 20, attr_start)

    # Flags
    flags = 0
    if in_use:
        flags |= 0x0001
    if is_directory:
        flags |= 0x0002
    struct.pack_into("<H", record, 22, flags)

    # Write attributes
    attr_end = attr_start + len(attributes)
    record[attr_start:attr_end] = attributes

    # End of attributes marker (0xFFFFFFFF)
    if attr_end + 4 <= record_size:
        struct.pack_into("<I", record, attr_end, 0xFFFFFFFF)

    # Used size and allocated size
    used = attr_end + 4
    struct.pack_into("<I", record, 24, used)
    struct.pack_into("<I", record, 28, record_size)

    # Base file record (0 for base records)
    struct.pack_into("<Q", record, 32, 0)

    # Next attribute ID
    struct.pack_into("<H", record, 40, 10)

    # Record number (NTFS 3.1)
    if record_size >= 48:
        struct.pack_into("<I", record, 44, record_number)

    # Update sequence number array (at offset 48)
    # USN value = 0x0001, fixup values = last 2 bytes of each 512-byte sector
    usn_value = 0x0001
    struct.pack_into("<H", record, usn_offset, usn_value)
    # Sector 1 fixup: last 2 bytes of first 512-byte sector (offset 510-511)
    # Store original values in USN array and write USN at sector ends
    if record_size >= 512:
        orig_510 = struct.unpack_from("<H", record, 510)[0]
        orig_1022 = struct.unpack_from("<H", record, 1022)[0] if record_size >= 1024 else 0
        struct.pack_into("<H", record, usn_offset + 2, orig_510)
        struct.pack_into("<H", record, usn_offset + 4, orig_1022)
        struct.pack_into("<H", record, 510, usn_value)
        if record_size >= 1024:
            struct.pack_into("<H", record, 1022, usn_value)

    return bytes(record)


# ---------------------------------------------------------------------------
# IMAGE 1: FAT32
# ---------------------------------------------------------------------------

def create_fat32_image(output_path: str = None) -> str:
    """
    Create a 2 MB FAT32 disk image with MBR.

    Structure:
      - Sector 0:       MBR with one FAT32 partition (type 0x0B)
      - Sector 2048:    FAT32 partition start
        - Sector 2048:  FAT32 boot sector
        - Sector 2052:  FAT (2 sectors)
        - Sector 2054:  FAT copy 2
        - Sector 2056:  Root directory (cluster 2)
        - Sector 2057:  File data clusters (clusters 3-7)

    Files created:
      - REPORT.TXT    (active, cluster 3)
      - EVIDENCE.BIN  (active, cluster 4-5)
      - NOTES.TXT     (deleted, cluster 6 — now free)
      - PASSWD.TXT    (deleted, cluster 7 — overwritten)
    """
    if output_path is None:
        output_path = str(SAMPLE_DIR / "demo_fat32.dd")

    SECTOR_SIZE       = 512
    IMAGE_SECTORS     = 4096          # 2 MB
    PARTITION_LBA     = 2048          # Partition starts at 2048
    PARTITION_SECTORS = IMAGE_SECTORS - PARTITION_LBA
    RESERVED_SECTORS  = 4
    SECTORS_PER_FAT   = 2
    NUM_FATS          = 2
    ROOT_CLUSTER      = 2

    # Dates for our synthetic files
    dt_2026_01 = datetime(2026, 1, 10, 9, 30, 0)
    dt_2026_02 = datetime(2026, 2, 14, 14, 0, 0)
    dt_2026_03 = datetime(2026, 3, 1, 10, 15, 0)
    dt_deleted_old = datetime(2025, 12, 5, 23, 59, 59)

    image = bytearray(IMAGE_SECTORS * SECTOR_SIZE)

    # --- MBR ---
    mbr = make_mbr([(True, 0x0B, PARTITION_LBA, PARTITION_SECTORS)])
    image[0:512] = mbr

    # --- FAT32 Boot Sector ---
    bs = make_fat32_boot_sector(
        total_sectors=PARTITION_SECTORS,
        sectors_per_cluster=1,
        reserved_sectors=RESERVED_SECTORS,
        num_fats=NUM_FATS,
        sectors_per_fat=SECTORS_PER_FAT,
        root_cluster=ROOT_CLUSTER,
        volume_label="EVIDENCE   ",
    )
    part_off = PARTITION_LBA * SECTOR_SIZE
    image[part_off:part_off + 512] = bs

    # Cluster layout (relative to data region):
    # Data region start = PARTITION_LBA + RESERVED_SECTORS + NUM_FATS * SECTORS_PER_FAT
    data_start_lba = PARTITION_LBA + RESERVED_SECTORS + NUM_FATS * SECTORS_PER_FAT  # 2048 + 4 + 4 = 2056
    # cluster 2 = root dir  -> sector data_start_lba + 0
    # cluster 3 = REPORT.TXT
    # cluster 4 = EVIDENCE.BIN part 1
    # cluster 5 = EVIDENCE.BIN part 2
    # cluster 6 = NOTES.TXT (deleted, cluster freed -> FAT entry = 0)
    # cluster 7 = PASSWD.TXT (deleted, cluster reallocated -> FAT entry = EOC in a new chain)

    def cluster_sector(cluster):
        return data_start_lba + (cluster - ROOT_CLUSTER)

    # --- FAT ---
    # Build cluster chains
    # chain for EVIDENCE.BIN: cluster 4 -> 5 -> EOC
    fat_data = make_fat32_fat(
        total_fat_entries=128,
        cluster_chains={
            ROOT_CLUSTER: [ROOT_CLUSTER],   # Root dir: single cluster
            3: [3],                          # REPORT.TXT: single cluster
            4: [4, 5],                       # EVIDENCE.BIN: 2 clusters
            # Cluster 6: free (NOTES.TXT deleted, data might be recoverable)
            # Cluster 7: reallocated to a new fake chain (PASSWD.TXT data overwritten)
            7: [7],                          # "New" file occupying cluster 7
        },
        free_clusters=[6],  # Cluster 6 is free
    )
    fat_off = part_off + RESERVED_SECTORS * SECTOR_SIZE
    # Write FAT 1
    image[fat_off:fat_off + len(fat_data)] = fat_data
    # Write FAT 2 (copy)
    fat2_off = fat_off + SECTORS_PER_FAT * SECTOR_SIZE
    image[fat2_off:fat2_off + len(fat_data)] = fat_data

    # --- Root Directory (cluster 2) ---
    root_off = cluster_sector(ROOT_CLUSTER) * SECTOR_SIZE

    entries = bytearray()
    # . and .. entries
    entries += make_dot_entries(ROOT_CLUSTER, ROOT_CLUSTER, dt_2026_01)

    # REPORT.TXT (active)
    report_content = b"FORENSIC INVESTIGATION REPORT\nCase: 2026-001\nAnalyst: Edward Marez\n"
    entries += make_fat32_dir_entry(
        "REPORT", "TXT", 0x20, 3, len(report_content),
        dt_2026_01, dt_2026_01, dt_2026_01
    )

    # EVIDENCE.BIN (active, 2 clusters)
    evidence_size = 600  # Needs 2 sectors (512 * 2 > 600)
    entries += make_fat32_dir_entry(
        "EVIDENCE", "BIN", 0x20, 4, evidence_size,
        dt_2026_02, dt_2026_02, dt_2026_02
    )

    # NOTES.TXT (DELETED — cluster 6 is free, data might be recoverable)
    notes_content = b"Interview notes: suspect accessed system at 23:45\n"
    entries += make_fat32_dir_entry(
        "NOTES", "TXT", 0x20, 6, len(notes_content),
        dt_2026_03, dt_2026_03, dt_2026_03,
        deleted=True
    )

    # PASSWD.TXT (DELETED — cluster 7 was reallocated, data overwritten)
    entries += make_fat32_dir_entry(
        "PASSWD", "TXT", 0x20, 7, 256,
        dt_deleted_old, dt_deleted_old, dt_deleted_old,
        deleted=True
    )

    image[root_off:root_off + len(entries)] = entries

    # --- File Data ---
    # REPORT.TXT at cluster 3
    clus3_off = cluster_sector(3) * SECTOR_SIZE
    image[clus3_off:clus3_off + len(report_content)] = report_content

    # EVIDENCE.BIN data at clusters 4-5
    clus4_off = cluster_sector(4) * SECTOR_SIZE
    evidence_data = bytes(range(256)) * 3  # 768 bytes of known pattern
    image[clus4_off:clus4_off + 512] = evidence_data[:512]
    clus5_off = cluster_sector(5) * SECTOR_SIZE
    image[clus5_off:clus5_off + len(evidence_data) - 512] = evidence_data[512:]

    # NOTES.TXT data at cluster 6 (still present, cluster is free)
    clus6_off = cluster_sector(6) * SECTOR_SIZE
    image[clus6_off:clus6_off + len(notes_content)] = notes_content

    # Cluster 7 is occupied by a new file (overwriting old PASSWD.TXT data)
    clus7_off = cluster_sector(7) * SECTOR_SIZE
    image[clus7_off:clus7_off + 512] = b"New data occupying reallocated cluster 7\n" + b"\x00" * 471

    Path(output_path).write_bytes(bytes(image))
    return output_path


# ---------------------------------------------------------------------------
# IMAGE 2: GPT
# ---------------------------------------------------------------------------

def create_gpt_image(output_path: str = None) -> str:
    """
    Create a 1 MB GPT disk image.

    Structure:
      - Sector 0:       Protective MBR
      - Sector 1:       Primary GPT header
      - Sectors 2-33:   GPT partition entries (128 entries × 128 bytes = 32 sectors)
      - Sector 34+:     Usable space (partitions)
      - Sector -33..-2: Backup partition entries
      - Sector -1:      Backup GPT header
    """
    if output_path is None:
        output_path = str(SAMPLE_DIR / "demo_gpt.dd")

    SECTOR_SIZE   = 512
    IMAGE_SECTORS = 2048   # 1 MB
    GPT_HEADER_LBA = 1
    PART_ENTRY_LBA = 2
    NUM_PART_ENTRIES = 128
    PART_ENTRY_SIZE  = 128
    PART_ENTRY_SECTORS = (NUM_PART_ENTRIES * PART_ENTRY_SIZE) // SECTOR_SIZE  # 32
    FIRST_USABLE_LBA = GPT_HEADER_LBA + 1 + PART_ENTRY_SECTORS  # 34
    LAST_USABLE_LBA  = IMAGE_SECTORS - 1 - PART_ENTRY_SECTORS - 1  # 2014
    ALT_HEADER_LBA   = IMAGE_SECTORS - 1

    image = bytearray(IMAGE_SECTORS * SECTOR_SIZE)

    # --- Protective MBR ---
    pmbr = make_mbr([(False, 0xEE, 1, IMAGE_SECTORS - 1)])
    image[0:512] = pmbr

    # --- GPT Disk GUID ---
    disk_guid_bytes = make_gpt_partition_type_guid_bytes("A2345678-1234-5678-ABCD-EF0123456789")

    # --- Partition definitions ---
    # 1. EFI System Partition: LBA 34 to 300 (~134 KB)
    efi_type  = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
    efi_guid  = make_gpt_partition_type_guid_bytes("B2345678-1234-5678-ABCD-EF0123456789")
    efi_entry = make_gpt_partition_entry(
        efi_type, efi_guid, 34, 300, 0, "EFI System Partition"
    )

    # 2. Microsoft Basic Data: LBA 301 to 1500 (~600 KB)
    mbd_type  = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
    mbd_guid  = make_gpt_partition_type_guid_bytes("C2345678-1234-5678-ABCD-EF0123456789")
    mbd_entry = make_gpt_partition_entry(
        mbd_type, mbd_guid, 301, 1500, 0, "Windows Evidence"
    )

    # 3. Linux Filesystem: LBA 1501 to 2014
    linux_type  = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
    linux_guid  = make_gpt_partition_type_guid_bytes("D2345678-1234-5678-ABCD-EF0123456789")
    linux_entry = make_gpt_partition_entry(
        linux_type, linux_guid, 1501, 2014, 0, "Linux Home"
    )

    # Fill partition array (128 entries × 128 bytes)
    part_array = bytearray(NUM_PART_ENTRIES * PART_ENTRY_SIZE)
    part_array[0:128]   = efi_entry
    part_array[128:256] = mbd_entry
    part_array[256:384] = linux_entry

    # --- Primary GPT Header ---
    gpt_header_bytes = make_gpt_header(
        my_lba=GPT_HEADER_LBA,
        alternate_lba=ALT_HEADER_LBA,
        first_usable_lba=FIRST_USABLE_LBA,
        last_usable_lba=LAST_USABLE_LBA,
        disk_guid=disk_guid_bytes,
        partition_entry_lba=PART_ENTRY_LBA,
        num_entries=NUM_PART_ENTRIES,
        partition_array=bytes(part_array),
    )
    image[SECTOR_SIZE:SECTOR_SIZE * 2] = gpt_header_bytes

    # --- Partition Entries (primary) at LBA 2-33 ---
    part_entries_off = PART_ENTRY_LBA * SECTOR_SIZE
    image[part_entries_off:part_entries_off + len(part_array)] = part_array

    # --- Backup Partition Entries (at LBA IMAGE_SECTORS - 33 to IMAGE_SECTORS - 2) ---
    backup_part_lba  = IMAGE_SECTORS - 1 - PART_ENTRY_SECTORS
    backup_part_off  = backup_part_lba * SECTOR_SIZE
    image[backup_part_off:backup_part_off + len(part_array)] = part_array

    # --- Backup GPT Header (at last sector) ---
    backup_header_bytes = make_gpt_header(
        my_lba=ALT_HEADER_LBA,
        alternate_lba=GPT_HEADER_LBA,
        first_usable_lba=FIRST_USABLE_LBA,
        last_usable_lba=LAST_USABLE_LBA,
        disk_guid=disk_guid_bytes,
        partition_entry_lba=backup_part_lba,
        num_entries=NUM_PART_ENTRIES,
        partition_array=bytes(part_array),
    )
    image[ALT_HEADER_LBA * SECTOR_SIZE:(ALT_HEADER_LBA + 1) * SECTOR_SIZE] = backup_header_bytes

    Path(output_path).write_bytes(bytes(image))
    return output_path


# ---------------------------------------------------------------------------
# IMAGE 3: NTFS
# ---------------------------------------------------------------------------

def create_ntfs_image(output_path: str = None) -> str:
    """
    Create a 4 MB NTFS disk image with MBR.

    Structure:
      - Sector 0:       MBR
      - Sector 2048:    NTFS partition start (boot sector)
      - Sector 2080:    $MFT starts (cluster 4, 8 sectors/cluster = LBA 2048 + 32)
      - Each MFT record = 1024 bytes (2 sectors)

    MFT records:
      0: $MFT         (system, in use)
      1: $MFTMirr     (system, in use)
      2: $LogFile     (system, in use)
      3: $Volume      (system, in use)
      4: $AttrDef     (system, in use)
      5: . (root dir) (in use, directory)
      16: report.txt  (in use)
      17: evidence.bin (in use)
      18: notes.txt   (in use)
      19: suspects.txt (NOT in use — deleted)
      20: passwords.db (NOT in use — deleted)
    """
    if output_path is None:
        output_path = str(SAMPLE_DIR / "demo_ntfs.dd")

    SECTOR_SIZE       = 512
    IMAGE_SECTORS     = 8192          # 4 MB
    PARTITION_LBA     = 2048
    PARTITION_SECTORS = IMAGE_SECTORS - PARTITION_LBA
    MFT_CLUSTER       = 4             # $MFT starts at cluster 4
    SECTORS_PER_CLUSTER = 8
    MFT_RECORD_SIZE   = 1024

    # MFT byte offset within partition
    MFT_OFFSET = MFT_CLUSTER * SECTORS_PER_CLUSTER * SECTOR_SIZE  # 4 * 8 * 512 = 16384

    # Timestamps
    ts_system   = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    ts_report   = datetime(2026, 1, 10, 9, 30, 0, tzinfo=timezone.utc)
    ts_evidence = datetime(2026, 2, 14, 14, 0, 0, tzinfo=timezone.utc)
    ts_notes    = datetime(2026, 3, 1, 10, 15, 0, tzinfo=timezone.utc)
    ts_deleted1 = datetime(2025, 11, 20, 21, 0, 0, tzinfo=timezone.utc)
    ts_deleted2 = datetime(2025, 12, 5, 23, 45, 0, tzinfo=timezone.utc)

    image = bytearray(IMAGE_SECTORS * SECTOR_SIZE)

    # --- MBR ---
    mbr = make_mbr([(True, 0x07, PARTITION_LBA, PARTITION_SECTORS)])
    image[0:512] = mbr

    # --- NTFS Boot Sector ---
    bs = make_ntfs_boot_sector(
        total_sectors=PARTITION_SECTORS,
        mft_cluster=MFT_CLUSTER,
        sectors_per_cluster=SECTORS_PER_CLUSTER,
    )
    part_off = PARTITION_LBA * SECTOR_SIZE
    image[part_off:part_off + 512] = bs

    # --- MFT Records ---
    mft_abs_off = part_off + MFT_OFFSET

    def write_mft(record_number: int, in_use: bool, is_dir: bool, attrs: bytes):
        off = mft_abs_off + record_number * MFT_RECORD_SIZE
        rec = make_ntfs_mft_record(record_number, in_use, is_dir, attrs, MFT_RECORD_SIZE)
        image[off:off + MFT_RECORD_SIZE] = rec

    def file_attrs(si_value: bytes, fn_value: bytes) -> bytes:
        attrs = bytearray()
        attrs += make_ntfs_attr_header_resident(0x10, 0, si_value)  # $STANDARD_INFORMATION
        attrs += make_ntfs_attr_header_resident(0x30, 1, fn_value)  # $FILE_NAME
        return bytes(attrs)

    ROOT_DIR_REF = 5 | (1 << 48)  # MFT ref: record 5, seq 1

    # Record 0: $MFT
    si = make_ntfs_standard_information(ts_system, ts_system, ts_system, ts_system, 0x06)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_system, ts_system, ts_system, ts_system, 0, 0, 0x06, "$MFT", 2)
    write_mft(0, True, False, file_attrs(si, fn))

    # Record 1: $MFTMirr
    si = make_ntfs_standard_information(ts_system, ts_system, ts_system, ts_system, 0x06)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_system, ts_system, ts_system, ts_system, 0, 0, 0x06, "$MFTMirr", 2)
    write_mft(1, True, False, file_attrs(si, fn))

    # Record 2: $LogFile
    si = make_ntfs_standard_information(ts_system, ts_system, ts_system, ts_system, 0x06)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_system, ts_system, ts_system, ts_system, 0, 0, 0x06, "$LogFile", 2)
    write_mft(2, True, False, file_attrs(si, fn))

    # Record 3: $Volume
    si = make_ntfs_standard_information(ts_system, ts_system, ts_system, ts_system, 0x06)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_system, ts_system, ts_system, ts_system, 0, 0, 0x06, "$Volume", 2)
    write_mft(3, True, False, file_attrs(si, fn))

    # Record 4: $AttrDef
    si = make_ntfs_standard_information(ts_system, ts_system, ts_system, ts_system, 0x06)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_system, ts_system, ts_system, ts_system, 0, 0, 0x06, "$AttrDef", 2)
    write_mft(4, True, False, file_attrs(si, fn))

    # Record 5: . (root directory)
    si = make_ntfs_standard_information(ts_system, ts_system, ts_system, ts_system, 0x16)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_system, ts_system, ts_system, ts_system, 0, 0, 0x16, ".", 3)
    write_mft(5, True, True, file_attrs(si, fn))

    # Skip records 6-15 (other system files) — write empty records
    for r in range(6, 16):
        off = mft_abs_off + r * MFT_RECORD_SIZE
        image[off:off + 4] = b"\x00\x00\x00\x00"  # Not FILE signature

    # Record 16: report.txt (active)
    si = make_ntfs_standard_information(ts_report, ts_report, ts_report, ts_report, 0x20)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_report, ts_report, ts_report, ts_report, 512, 420, 0x20, "report.txt", 1)
    data_attr = make_ntfs_attr_header_resident(0x80, 2, b"FORENSIC REPORT\nCase: 2026-001\nAnalyst: Edward Marez\nStatus: Active\n")
    write_mft(16, True, False, file_attrs(si, fn) + data_attr)

    # Record 17: evidence.bin (active)
    si = make_ntfs_standard_information(ts_evidence, ts_evidence, ts_evidence, ts_evidence, 0x20)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_evidence, ts_evidence, ts_evidence, ts_evidence, 1024, 800, 0x20, "evidence.bin", 1)
    data_attr = make_ntfs_attr_header_resident(0x80, 2, bytes(range(256)))
    write_mft(17, True, False, file_attrs(si, fn) + data_attr)

    # Record 18: notes.txt (active)
    si = make_ntfs_standard_information(ts_notes, ts_notes, ts_notes, ts_notes, 0x20)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_notes, ts_notes, ts_notes, ts_notes, 512, 180, 0x20, "notes.txt", 1)
    data_attr = make_ntfs_attr_header_resident(0x80, 2, b"Interview notes: suspect accessed system at 23:45\n")
    write_mft(18, True, False, file_attrs(si, fn) + data_attr)

    # Record 19: suspects.txt (DELETED — in_use=False)
    si = make_ntfs_standard_information(ts_deleted1, ts_deleted1, ts_deleted1, ts_deleted1, 0x20)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_deleted1, ts_deleted1, ts_deleted1, ts_deleted1, 512, 230, 0x20, "suspects.txt", 1)
    data_attr = make_ntfs_attr_header_resident(0x80, 2, b"Name: John Doe\nAge: 34\nStatus: Person of interest\n")
    write_mft(19, False, False, file_attrs(si, fn) + data_attr)

    # Record 20: passwords.db (DELETED — in_use=False)
    si = make_ntfs_standard_information(ts_deleted2, ts_deleted2, ts_deleted2, ts_deleted2, 0x22)
    fn = make_ntfs_file_name(ROOT_DIR_REF, ts_deleted2, ts_deleted2, ts_deleted2, ts_deleted2, 1024, 512, 0x22, "passwords.db", 1)
    data_attr = make_ntfs_attr_header_resident(0x80, 2, b"SQLite database header\x00" + b"\xCC" * 40)
    write_mft(20, False, False, file_attrs(si, fn) + data_attr)

    Path(output_path).write_bytes(bytes(image))
    return output_path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    print("Generating sample disk images...")

    fat32_path = create_fat32_image()
    print(f"  FAT32 image: {fat32_path} ({Path(fat32_path).stat().st_size:,} bytes)")

    gpt_path = create_gpt_image()
    print(f"  GPT image:   {gpt_path} ({Path(gpt_path).stat().st_size:,} bytes)")

    ntfs_path = create_ntfs_image()
    print(f"  NTFS image:  {ntfs_path} ({Path(ntfs_path).stat().st_size:,} bytes)")

    print("Done.")
