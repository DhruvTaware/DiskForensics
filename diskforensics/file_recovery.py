"""
Deleted File Recovery for DiskForensics.

Scans FAT32 directory entries and NTFS MFT records for evidence of
deleted files. Reports metadata (filename, timestamps, size, starting
cluster) and assesses whether data may still be recoverable on disk.

FAT32 deletion mechanics:
  When a file is deleted in FAT32, the OS sets the first byte of its
  directory entry to 0xE5 (the "deleted" marker). The FAT cluster chain
  entries are zeroed (marking clusters as free), but the actual data
  sectors are not overwritten until the clusters are reused.

  Recovery is possible if:
  1. The directory entry still exists (not overwritten)
  2. The FAT clusters are still free (not reallocated)
  3. The cluster chain can be reconstructed (from file size / cluster size)

NTFS deletion mechanics:
  When a file is deleted in NTFS, the In Use flag in the MFT record
  header is cleared (0x0001 bit). The MFT record itself remains intact
  until the record is reused for a new file. This makes NTFS recovery
  highly reliable for recently deleted files.

  The $STANDARD_INFORMATION and $FILE_NAME attributes are typically
  preserved in deleted MFT records, giving full timestamp evidence.

Author: Edward Marez
License: MIT
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from .fat32_parser import FAT32Parser, FAT32DirectoryEntry, FAT32Result
from .ntfs_parser import NTFSParser, MFTRecord, NTFSResult
from .utils import format_bytes


@dataclass
class RecoveredFile:
    """
    A recovered file entry with forensic metadata.

    Represents a deleted file detected from either FAT32 or NTFS.
    """

    filesystem: str             # "FAT32" or "NTFS"
    filename: str               # Best-available filename
    filename_partial: bool      # True if first char is unknown (FAT32)
    file_size: int              # File size in bytes
    first_cluster: int          # Starting cluster (FAT32) or MFT record number (NTFS)
    created: Optional[datetime]
    modified: Optional[datetime]
    accessed: Optional[datetime]
    is_directory: bool
    likely_recoverable: bool    # Based on cluster state check
    recovery_notes: str = ""    # Explanation of recoverability assessment

    # Source reference
    source_entry: object = field(repr=False, default=None)

    @property
    def size_human(self) -> str:
        return format_bytes(self.file_size)

    def to_dict(self) -> dict:
        return {
            "filesystem": self.filesystem,
            "filename": self.filename,
            "filename_partial": self.filename_partial,
            "is_directory": self.is_directory,
            "file_size": self.file_size,
            "size_human": self.size_human,
            "first_cluster": self.first_cluster,
            "likely_recoverable": self.likely_recoverable,
            "recovery_notes": self.recovery_notes,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
        }


@dataclass
class RecoveryResult:
    """Result of a deleted file recovery scan."""

    filesystem: str
    recovered_files: List[RecoveredFile]
    scan_notes: str = ""

    @property
    def count(self) -> int:
        return len(self.recovered_files)

    @property
    def likely_recoverable_count(self) -> int:
        return sum(1 for f in self.recovered_files if f.likely_recoverable)

    def to_dict(self) -> dict:
        return {
            "filesystem": self.filesystem,
            "total_deleted": self.count,
            "likely_recoverable": self.likely_recoverable_count,
            "scan_notes": self.scan_notes,
            "recovered_files": [f.to_dict() for f in self.recovered_files],
        }


class FileRecovery:
    """
    Scans FAT32 and NTFS filesystems for deleted file entries.

    Usage:
        # FAT32 recovery
        fat_parser = FAT32Parser(reader, partition_lba_start=2048)
        fat_result = fat_parser.parse()
        recovery = FileRecovery()
        result = recovery.recover_fat32(fat_parser, fat_result)

        # NTFS recovery
        ntfs_parser = NTFSParser(reader, partition_lba_start=2048)
        ntfs_result = ntfs_parser.parse()
        result = recovery.recover_ntfs(ntfs_result)
    """

    def recover_fat32(
        self, parser: FAT32Parser, result: Optional[FAT32Result] = None
    ) -> RecoveryResult:
        """
        Scan a FAT32 filesystem for deleted file entries.

        For each deleted entry (first byte = 0xE5), checks whether its
        starting cluster is still marked as free in the FAT, which
        indicates data may be recoverable.

        Args:
            parser: FAT32Parser instance (with boot sector parsed).
            result: Pre-parsed FAT32Result (or None to parse now).

        Returns:
            RecoveryResult with all deleted file entries and recoverability notes.
        """
        if result is None:
            result = parser.parse()

        recovered: List[RecoveredFile] = []

        for entry in result.deleted_files:
            recoverable, notes = self._assess_fat32_recovery(parser, entry)
            rf = RecoveredFile(
                filesystem="FAT32",
                filename=entry.name,
                filename_partial=True,  # FAT32 always loses first character
                file_size=entry.file_size,
                first_cluster=entry.first_cluster,
                created=entry.created,
                modified=entry.modified,
                accessed=entry.accessed,
                is_directory=entry.is_directory,
                likely_recoverable=recoverable,
                recovery_notes=notes,
                source_entry=entry,
            )
            recovered.append(rf)

        notes = (
            f"FAT32 recovery: {len(recovered)} deleted entries found. "
            f"Note: First character of each filename is replaced with '_' (original unknown)."
        )
        return RecoveryResult(filesystem="FAT32", recovered_files=recovered, scan_notes=notes)

    def _assess_fat32_recovery(
        self, parser: FAT32Parser, entry: FAT32DirectoryEntry
    ) -> tuple[bool, str]:
        """
        Assess whether a FAT32 deleted file's data is likely recoverable.

        Returns:
            (likely_recoverable, explanation_string)
        """
        if entry.first_cluster < 2:
            return False, "Invalid starting cluster (< 2); data likely not recoverable."

        if parser._boot_sector is None:
            return False, "Boot sector not available for cluster check."

        try:
            fat_entry = parser.get_fat_entry(entry.first_cluster)
        except Exception as e:
            return False, f"Could not read FAT for cluster {entry.first_cluster}: {e}"

        if fat_entry == 0x00000000:
            # Cluster is free — data might still be on disk
            if entry.file_size == 0:
                return True, "Starting cluster is free; zero-byte file."
            # Estimate if multiple clusters needed
            bs = parser._boot_sector
            bytes_per_cluster = bs.bytes_per_cluster
            clusters_needed = max(1, (entry.file_size + bytes_per_cluster - 1) // bytes_per_cluster)
            if clusters_needed == 1:
                return True, (
                    f"Starting cluster {entry.first_cluster} is free. "
                    f"Single-cluster file ({format_bytes(entry.file_size)}); likely fully recoverable."
                )
            else:
                return True, (
                    f"Starting cluster {entry.first_cluster} is free. "
                    f"File requires ~{clusters_needed} clusters; chain may be partially recoverable."
                )
        else:
            return False, (
                f"Starting cluster {entry.first_cluster} is no longer free (FAT entry = 0x{fat_entry:08X}); "
                f"data has likely been overwritten."
            )

    def recover_ntfs(
        self, result: Optional[NTFSResult] = None, parser: Optional[NTFSParser] = None
    ) -> RecoveryResult:
        """
        Scan NTFS MFT records for deleted file entries.

        NTFS deletes a file by clearing the In Use flag in the MFT record.
        The $STANDARD_INFORMATION and $FILE_NAME attributes are preserved,
        making timestamp recovery very reliable.

        Args:
            result: Pre-parsed NTFSResult (or None to parse with parser).
            parser: NTFSParser instance (used if result is None).

        Returns:
            RecoveryResult with all deleted MFT records.
        """
        if result is None:
            if parser is None:
                raise ValueError("Must provide either result or parser")
            result = parser.parse()

        recovered: List[RecoveredFile] = []

        for record in result.deleted_records:
            # Skip system records (0-11)
            if record.record_number < 12 and not record.primary_name.startswith("["):
                continue
            if not record.primary_name or record.primary_name.startswith("[MFT#"):
                if not record.file_names:
                    continue  # No filename data at all

            notes = self._assess_ntfs_recovery(record)
            rf = RecoveredFile(
                filesystem="NTFS",
                filename=record.primary_name,
                filename_partial=False,  # NTFS preserves full filename
                file_size=record.data_size,
                first_cluster=record.record_number,  # Use MFT record# as reference
                created=record.created,
                modified=record.modified,
                accessed=record.accessed,
                is_directory=record.is_directory,
                likely_recoverable=True,  # MFT metadata is intact
                recovery_notes=notes,
                source_entry=record,
            )
            recovered.append(rf)

        notes = (
            f"NTFS recovery: {len(recovered)} deleted MFT records found. "
            f"Full filenames and timestamps preserved in MFT."
        )
        return RecoveryResult(filesystem="NTFS", recovered_files=recovered, scan_notes=notes)

    def _assess_ntfs_recovery(self, record: MFTRecord) -> str:
        """Build recovery notes for a deleted NTFS MFT record."""
        notes_parts = [f"MFT Record #{record.record_number} marked as not-in-use."]

        if record.standard_info:
            notes_parts.append("$STANDARD_INFORMATION timestamps preserved.")
        else:
            notes_parts.append("$STANDARD_INFORMATION not available.")

        if record.file_names:
            names_str = ", ".join(f"'{fn.name}' ({fn.name_type_str})" for fn in record.file_names)
            notes_parts.append(f"$FILE_NAME entries: {names_str}.")
        else:
            notes_parts.append("No $FILE_NAME attribute found.")

        if record.data_size > 0:
            notes_parts.append(
                f"Last known file size: {format_bytes(record.data_size)}. "
                "Data may be recoverable if clusters not reallocated."
            )
        elif record.is_directory:
            notes_parts.append("Directory entry; no data to recover.")
        else:
            notes_parts.append("File size unknown or zero.")

        return " ".join(notes_parts)

    def print_summary(self, result: RecoveryResult) -> None:
        """Print a formatted recovery summary to stdout."""
        print("=" * 70)
        print(f"DELETED FILE RECOVERY — {result.filesystem}")
        print("=" * 70)
        print(f"Deleted entries found:   {result.count}")
        print(f"Likely recoverable:      {result.likely_recoverable_count}")
        if result.scan_notes:
            print(f"Notes: {result.scan_notes}")
        print()

        if not result.recovered_files:
            print("No deleted files found.")
            return

        print(f"{'Filename':<40} {'Size':>10} {'Modified':<22} {'Recover?'}")
        print("-" * 85)
        for f in result.recovered_files:
            mod = f.modified.strftime("%Y-%m-%d %H:%M:%S") if f.modified else "N/A"
            rec = "YES" if f.likely_recoverable else "No"
            partial = "*" if f.filename_partial else ""
            print(f"{f.filename[:39]+partial:<40} {f.size_human:>10} {mod:<22} {rec}")

        if any(f.filename_partial for f in result.recovered_files):
            print()
            print("* = First character of filename is unknown (replaced with '_') in FAT32.")
        print()
