"""
Forensic Timeline Generator for DiskForensics.

Collects all filesystem timestamps from parsed FAT32 and NTFS data and
produces a chronological timeline of filesystem activity. This is a
core deliverable in any digital forensic investigation.

Timeline event types:
  FILE_CREATED    — File/directory creation time ($STANDARD_INFORMATION or FAT32 create)
  FILE_MODIFIED   — Last write time ($STANDARD_INFORMATION or FAT32 modify)
  FILE_ACCESSED   — Last access time (read or execute)
  MFT_MODIFIED    — MFT record modification ($MFT entry changed, NTFS only)
  FILE_DELETED    — Entry detected as deleted (approximate; actual deletion time unknown)
  VOLUME_CREATED  — Derived from filesystem metadata

Timeline analysis considerations:
  - Timestamps can be manipulated by anti-forensic tools (timestomping)
  - $STANDARD_INFORMATION is user-accessible and easiest to modify
  - $FILE_NAME timestamps in NTFS are harder to manipulate
  - Discrepancies between $SI and $FN timestamps are a red flag
  - UTC timezone should be assumed unless locale evidence exists

Author: Edward Marez
License: MIT
"""

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime, date
from typing import List, Optional, Iterator

from .fat32_parser import FAT32Result, FAT32DirectoryEntry
from .ntfs_parser import NTFSResult, MFTRecord
from .file_recovery import RecoveryResult


# Timeline event type constants
EVENT_CREATED      = "FILE_CREATED"
EVENT_MODIFIED     = "FILE_MODIFIED"
EVENT_ACCESSED     = "FILE_ACCESSED"
EVENT_MFT_MODIFIED = "MFT_MODIFIED"
EVENT_DELETED      = "FILE_DELETED"


@dataclass(order=True)
class TimelineEvent:
    """
    A single event in the forensic timeline.

    Sortable by timestamp (None timestamps go to end).
    """

    timestamp: Optional[datetime]
    event_type: str             # One of the EVENT_* constants
    filename: str
    file_size: int
    filesystem: str             # "FAT32" or "NTFS"
    source: str                 # Attribute source (e.g., "$STANDARD_INFORMATION")
    is_deleted: bool = False
    path: str = ""
    extra: str = ""

    # For sorting: put None timestamps after all real timestamps
    sort_key: datetime = field(init=False, compare=True)

    def __post_init__(self):
        if self.timestamp is not None:
            self.sort_key = self.timestamp
        else:
            self.sort_key = datetime.max

    @property
    def timestamp_str(self) -> str:
        if self.timestamp:
            return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return "N/A"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "filename": self.filename,
            "path": self.path,
            "file_size": self.file_size,
            "filesystem": self.filesystem,
            "source": self.source,
            "is_deleted": self.is_deleted,
            "extra": self.extra,
        }

    def to_csv_row(self) -> list:
        return [
            self.timestamp_str,
            self.event_type,
            self.filesystem,
            self.filename,
            self.path or "",
            str(self.file_size),
            "Y" if self.is_deleted else "N",
            self.source,
            self.extra or "",
        ]


@dataclass
class TimelineResult:
    """Result of timeline generation."""

    events: List[TimelineEvent]
    filesystem: str
    start_date: Optional[date] = None
    end_date: Optional[date] = None

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def sorted_events(self) -> List[TimelineEvent]:
        return sorted(self.events)

    @property
    def date_range(self) -> tuple[Optional[datetime], Optional[datetime]]:
        """Return (earliest, latest) timestamps across all events."""
        dated = [e.timestamp for e in self.events if e.timestamp]
        if not dated:
            return None, None
        return min(dated), max(dated)

    def filter_by_date(
        self, start: Optional[date] = None, end: Optional[date] = None
    ) -> "TimelineResult":
        """Return a new TimelineResult filtered to the given date range."""
        filtered = []
        for event in self.events:
            if event.timestamp is None:
                continue
            event_date = event.timestamp.date()
            if start and event_date < start:
                continue
            if end and event_date > end:
                continue
            filtered.append(event)
        return TimelineResult(
            events=filtered,
            filesystem=self.filesystem,
            start_date=start,
            end_date=end,
        )

    def to_csv(self) -> str:
        """Export timeline to CSV string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Timestamp", "Event Type", "Filesystem", "Filename",
            "Path", "File Size (bytes)", "Deleted", "Source", "Notes"
        ])
        for event in self.sorted_events:
            writer.writerow(event.to_csv_row())
        return output.getvalue()

    def to_text(self) -> str:
        """Export timeline to formatted text string."""
        lines = [
            "FORENSIC TIMELINE REPORT",
            "=" * 80,
            f"Filesystem:   {self.filesystem}",
            f"Total Events: {self.count}",
        ]
        if self.start_date:
            lines.append(f"Start Date:   {self.start_date}")
        if self.end_date:
            lines.append(f"End Date:     {self.end_date}")

        earliest, latest = self.date_range
        if earliest:
            lines.append(f"Earliest:     {earliest.strftime('%Y-%m-%d %H:%M:%S')}")
        if latest:
            lines.append(f"Latest:       {latest.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        lines.append("")

        # Column headers
        lines.append(
            f"{'Timestamp':<22} {'Event':<16} {'FS':<6} {'Del':<4} "
            f"{'Source':<25} {'Filename'}"
        )
        lines.append("-" * 120)

        for event in self.sorted_events:
            del_flag = "[D]" if event.is_deleted else "   "
            source_short = event.source[:24]
            name_display = event.filename
            if event.path and event.path != event.filename:
                name_display = event.path
            lines.append(
                f"{event.timestamp_str:<22} {event.event_type:<16} "
                f"{event.filesystem:<6} {del_flag:<4} "
                f"{source_short:<25} {name_display}"
            )

        return "\n".join(lines)

    def to_list(self) -> List[dict]:
        return [e.to_dict() for e in self.sorted_events]


class TimelineGenerator:
    """
    Generates a forensic timeline from parsed filesystem data.

    Collects all timestamps (created, modified, accessed, MFT-modified)
    from FAT32 directory entries and NTFS MFT records, deduplicated
    per file+timestamp combination.

    Usage:
        gen = TimelineGenerator()
        gen.add_fat32_result(fat32_result)
        gen.add_ntfs_result(ntfs_result)
        timeline = gen.build()
        print(timeline.to_text())
    """

    def __init__(self):
        self._events: List[TimelineEvent] = []

    def clear(self) -> None:
        """Clear all accumulated events."""
        self._events.clear()

    def add_fat32_result(self, result: FAT32Result) -> None:
        """Add timeline events from a parsed FAT32 result."""
        all_entries = result.files + result.deleted_files
        for entry in all_entries:
            self._add_fat32_entry(entry)

    def _add_fat32_entry(self, entry: FAT32DirectoryEntry) -> None:
        """Extract all timestamps from a FAT32 directory entry."""
        name = entry.name
        path = entry.path
        size = entry.file_size
        deleted = entry.is_deleted

        if entry.created:
            self._events.append(TimelineEvent(
                timestamp=entry.created,
                event_type=EVENT_CREATED,
                filename=name,
                file_size=size,
                filesystem="FAT32",
                source="Directory Entry (create)",
                is_deleted=deleted,
                path=path,
            ))

        if entry.modified:
            self._events.append(TimelineEvent(
                timestamp=entry.modified,
                event_type=EVENT_MODIFIED,
                filename=name,
                file_size=size,
                filesystem="FAT32",
                source="Directory Entry (modify)",
                is_deleted=deleted,
                path=path,
            ))

        if entry.accessed:
            self._events.append(TimelineEvent(
                timestamp=entry.accessed,
                event_type=EVENT_ACCESSED,
                filename=name,
                file_size=size,
                filesystem="FAT32",
                source="Directory Entry (access)",
                is_deleted=deleted,
                path=path,
            ))

        if deleted:
            # The "deleted" event is approximate — we list the modified time
            ts = entry.modified or entry.created
            if ts:
                self._events.append(TimelineEvent(
                    timestamp=ts,
                    event_type=EVENT_DELETED,
                    filename=name,
                    file_size=size,
                    filesystem="FAT32",
                    source="Directory Entry (0xE5 marker)",
                    is_deleted=True,
                    path=path,
                    extra="Approximate — timestamp is last-modified, not deletion time",
                ))

    def add_ntfs_result(self, result: NTFSResult) -> None:
        """Add timeline events from a parsed NTFS result."""
        for record in result.records:
            self._add_ntfs_record(record)

    def _add_ntfs_record(self, record: MFTRecord) -> None:
        """Extract all timestamps from an NTFS MFT record."""
        # Skip unfilled records with no useful data
        if not record.file_names and not record.standard_info:
            return

        name = record.primary_name
        size = record.data_size
        deleted = not record.in_use
        path = ""
        if record.file_names:
            path = record.file_names[0].name

        # $STANDARD_INFORMATION timestamps (user-visible, potentially tampered)
        if record.standard_info:
            si = record.standard_info
            if si.created:
                self._events.append(TimelineEvent(
                    timestamp=si.created,
                    event_type=EVENT_CREATED,
                    filename=name,
                    file_size=size,
                    filesystem="NTFS",
                    source="$STANDARD_INFORMATION",
                    is_deleted=deleted,
                    path=path,
                ))
            if si.modified:
                self._events.append(TimelineEvent(
                    timestamp=si.modified,
                    event_type=EVENT_MODIFIED,
                    filename=name,
                    file_size=size,
                    filesystem="NTFS",
                    source="$STANDARD_INFORMATION",
                    is_deleted=deleted,
                    path=path,
                ))
            if si.accessed:
                self._events.append(TimelineEvent(
                    timestamp=si.accessed,
                    event_type=EVENT_ACCESSED,
                    filename=name,
                    file_size=size,
                    filesystem="NTFS",
                    source="$STANDARD_INFORMATION",
                    is_deleted=deleted,
                    path=path,
                ))
            if si.mft_modified:
                self._events.append(TimelineEvent(
                    timestamp=si.mft_modified,
                    event_type=EVENT_MFT_MODIFIED,
                    filename=name,
                    file_size=size,
                    filesystem="NTFS",
                    source="$STANDARD_INFORMATION",
                    is_deleted=deleted,
                    path=path,
                ))

        # $FILE_NAME timestamps (harder to manipulate)
        for fn in record.file_names:
            source = f"$FILE_NAME ({fn.name_type_str})"
            if fn.created:
                self._events.append(TimelineEvent(
                    timestamp=fn.created,
                    event_type=EVENT_CREATED,
                    filename=name,
                    file_size=size,
                    filesystem="NTFS",
                    source=source,
                    is_deleted=deleted,
                    path=fn.name,
                ))
            if fn.modified:
                self._events.append(TimelineEvent(
                    timestamp=fn.modified,
                    event_type=EVENT_MODIFIED,
                    filename=name,
                    file_size=size,
                    filesystem="NTFS",
                    source=source,
                    is_deleted=deleted,
                    path=fn.name,
                ))

        if deleted:
            ts = record.modified or record.created
            if ts:
                self._events.append(TimelineEvent(
                    timestamp=ts,
                    event_type=EVENT_DELETED,
                    filename=name,
                    file_size=size,
                    filesystem="NTFS",
                    source="MFT Record (not-in-use flag)",
                    is_deleted=True,
                    path=path,
                    extra="In-use flag cleared; deletion time inferred from $SI modify time",
                ))

    def add_recovery_result(self, recovery: RecoveryResult) -> None:
        """Add timeline events from a file recovery result."""
        for rf in recovery.recovered_files:
            if rf.modified:
                self._events.append(TimelineEvent(
                    timestamp=rf.modified,
                    event_type=EVENT_DELETED,
                    filename=rf.filename,
                    file_size=rf.file_size,
                    filesystem=rf.filesystem,
                    source="Deleted Entry (recovered)",
                    is_deleted=True,
                    path="",
                    extra=rf.recovery_notes[:60],
                ))

    def build(
        self,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        filesystem: str = "MIXED",
    ) -> TimelineResult:
        """
        Build and return the finalized timeline.

        Args:
            start_date: Earliest date to include (inclusive).
            end_date: Latest date to include (inclusive).
            filesystem: Label for the filesystem source.

        Returns:
            TimelineResult with sorted events.
        """
        result = TimelineResult(
            events=list(self._events),
            filesystem=filesystem,
            start_date=start_date,
            end_date=end_date,
        )
        if start_date or end_date:
            result = result.filter_by_date(start_date, end_date)
        return result
