"""
Forensic Hash Engine for DiskForensics.

Computes cryptographic hashes of disk images, individual partitions,
and individual files for chain-of-custody documentation.

Forensic hashing serves two purposes:
  1. Integrity verification: Confirm the evidence image has not been
     modified since acquisition (hash matches acquisition hash).
  2. Evidence identification: Provide unique identifiers for disk images
     and artifacts that can be cited in forensic reports.

Standard hash algorithms used in digital forensics:
  - MD5 (128-bit): Fast; still used for legacy compatibility and quick checks.
     Note: Cryptographically broken for collision resistance, but still
     useful for integrity verification where collision attacks are unlikely.
  - SHA-1 (160-bit): Deprecated for security; still seen in older cases.
  - SHA-256 (256-bit): Current standard for evidence integrity in most labs.
  - SHA-512 (512-bit): Highest assurance; used for critical evidence.

Author: Edward Marez
License: MIT
"""

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict

from .image_reader import ImageReader
from .mbr_parser import PartitionEntry
from .utils import format_bytes


@dataclass
class HashResult:
    """
    A forensic hash result for a specific data range.

    Records the target, algorithm, digest, byte range, and timing.
    """

    target: str                 # Description of what was hashed
    algorithm: str
    digest: str                 # Hexadecimal hash value
    start_offset: int           # Byte offset of start
    length: int                 # Bytes hashed
    computed_at: datetime       # UTC timestamp of computation
    elapsed_seconds: float      # Wall clock time for hashing

    @property
    def size_human(self) -> str:
        return format_bytes(self.length)

    @property
    def throughput_mbps(self) -> float:
        """Hashing throughput in MB/s."""
        if self.elapsed_seconds > 0:
            return (self.length / (1024 * 1024)) / self.elapsed_seconds
        return 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "algorithm": self.algorithm,
            "digest": self.digest,
            "start_offset": self.start_offset,
            "length_bytes": self.length,
            "size_human": self.size_human,
            "computed_at": self.computed_at.isoformat(),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "throughput_mbps": round(self.throughput_mbps, 2),
        }

    def to_report_line(self) -> str:
        """Format as a single line suitable for a forensic report."""
        return (
            f"{self.algorithm.upper():<8} {self.digest}  "
            f"{self.target} ({self.size_human})"
        )


@dataclass
class ImageHashReport:
    """Collection of all hashes computed for a disk image."""

    image_path: str
    image_size: int
    full_image_hashes: List[HashResult] = field(default_factory=list)
    partition_hashes: List[HashResult] = field(default_factory=list)
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def image_size_human(self) -> str:
        return format_bytes(self.image_size)

    def to_dict(self) -> dict:
        return {
            "image_path": self.image_path,
            "image_size_bytes": self.image_size,
            "image_size_human": self.image_size_human,
            "computed_at": self.computed_at.isoformat(),
            "full_image_hashes": [h.to_dict() for h in self.full_image_hashes],
            "partition_hashes": [h.to_dict() for h in self.partition_hashes],
        }

    def print_summary(self) -> None:
        """Print hash report to stdout."""
        print("=" * 70)
        print("FORENSIC HASH REPORT")
        print("=" * 70)
        print(f"Image:    {self.image_path}")
        print(f"Size:     {self.image_size_human} ({self.image_size:,} bytes)")
        print(f"Computed: {self.computed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()

        if self.full_image_hashes:
            print("FULL IMAGE HASHES:")
            print("-" * 70)
            for h in self.full_image_hashes:
                print(f"  {h.algorithm.upper():<10} {h.digest}")
                print(f"  {'':10} Computed in {h.elapsed_seconds:.2f}s "
                      f"({h.throughput_mbps:.1f} MB/s)")
            print()

        if self.partition_hashes:
            print("PARTITION HASHES:")
            print("-" * 70)
            for h in self.partition_hashes:
                print(f"  {h.target}")
                print(f"  {h.algorithm.upper():<10} {h.digest}")
                print(f"  {'':10} {h.size_human} | Computed in {h.elapsed_seconds:.2f}s")
                print()


class HashEngine:
    """
    Computes forensic hashes for disk images, partitions, and files.

    Usage:
        reader = ImageReader("evidence.dd")
        engine = HashEngine(reader)

        # Hash full image
        report = engine.hash_image()
        report.print_summary()

        # Hash specific partitions
        engine.hash_partitions(partitions, report)
    """

    DEFAULT_ALGORITHMS = ["md5", "sha256"]
    FULL_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]

    def __init__(self, reader: ImageReader):
        """
        Initialize with an open ImageReader.

        Args:
            reader: Open ImageReader instance.
        """
        self.reader = reader

    def hash_image(
        self, algorithms: Optional[List[str]] = None
    ) -> ImageHashReport:
        """
        Compute hashes of the full disk image.

        Args:
            algorithms: List of algorithm names. Defaults to ['md5', 'sha256'].

        Returns:
            ImageHashReport with hash results.
        """
        if algorithms is None:
            algorithms = self.DEFAULT_ALGORITHMS

        report = ImageHashReport(
            image_path=str(self.reader.image_path),
            image_size=self.reader.image_size,
        )

        for algo in algorithms:
            result = self._compute_hash(
                algorithm=algo,
                start_offset=0,
                length=self.reader.image_size,
                target=f"Full Image ({self.reader.filename})",
            )
            report.full_image_hashes.append(result)

        return report

    def hash_partitions(
        self,
        partitions: List[PartitionEntry],
        report: Optional[ImageHashReport] = None,
        algorithms: Optional[List[str]] = None,
    ) -> ImageHashReport:
        """
        Compute hashes for each partition in the list.

        Args:
            partitions: List of PartitionEntry objects (from MBRParser or GPTParser).
            report: Existing ImageHashReport to append to (or None to create new).
            algorithms: Hash algorithms to use.

        Returns:
            ImageHashReport with partition hash results appended.
        """
        if algorithms is None:
            algorithms = self.DEFAULT_ALGORITHMS

        if report is None:
            report = ImageHashReport(
                image_path=str(self.reader.image_path),
                image_size=self.reader.image_size,
            )

        for partition in partitions:
            if partition.is_empty:
                continue
            start_offset = partition.lba_start * 512  # MBR partitions always use 512-byte sectors
            length = partition.sector_count * 512

            for algo in algorithms:
                target = (
                    f"Partition {partition.index + 1} "
                    f"({partition.type_name}, LBA {partition.lba_start}-{partition.lba_end})"
                )
                result = self._compute_hash(
                    algorithm=algo,
                    start_offset=start_offset,
                    length=length,
                    target=target,
                )
                report.partition_hashes.append(result)

        return report

    def hash_partition_by_lba(
        self,
        lba_start: int,
        sector_count: int,
        label: str = "Partition",
        algorithms: Optional[List[str]] = None,
    ) -> List[HashResult]:
        """
        Hash a partition defined by LBA range.

        Args:
            lba_start: First sector of the partition.
            sector_count: Number of sectors.
            label: Human-readable label for reporting.
            algorithms: Algorithms to use.

        Returns:
            List of HashResult objects (one per algorithm).
        """
        if algorithms is None:
            algorithms = self.DEFAULT_ALGORITHMS

        results = []
        start_offset = lba_start * self.reader.sector_size
        length = sector_count * self.reader.sector_size

        for algo in algorithms:
            result = self._compute_hash(
                algorithm=algo,
                start_offset=start_offset,
                length=length,
                target=f"{label} (LBA {lba_start}, {sector_count} sectors)",
            )
            results.append(result)

        return results

    def _compute_hash(
        self,
        algorithm: str,
        start_offset: int,
        length: int,
        target: str,
        chunk_size: int = 65536,
    ) -> HashResult:
        """
        Core hash computation with timing.

        Reads in chunks to support arbitrarily large regions.

        Args:
            algorithm: Hash algorithm name.
            start_offset: Start byte offset.
            length: Number of bytes to hash.
            target: Description string for the report.
            chunk_size: Read chunk size (default 64 KB).

        Returns:
            HashResult with digest and timing data.
        """
        try:
            h = hashlib.new(algorithm)
        except ValueError:
            raise ValueError(f"Unsupported hash algorithm: {algorithm!r}")

        start_time = time.monotonic()

        if self.reader._file is None or self.reader._file.closed:
            self.reader._open()
        self.reader._file.seek(start_offset)

        remaining = min(length, self.reader.image_size - start_offset)
        actual_length = remaining

        while remaining > 0:
            to_read = min(chunk_size, remaining)
            chunk = self.reader._file.read(to_read)
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)

        elapsed = time.monotonic() - start_time

        return HashResult(
            target=target,
            algorithm=algorithm,
            digest=h.hexdigest(),
            start_offset=start_offset,
            length=actual_length,
            computed_at=datetime.now(timezone.utc),
            elapsed_seconds=elapsed,
        )

    def verify_hash(
        self,
        expected_digest: str,
        algorithm: str = "sha256",
        start_offset: int = 0,
        length: Optional[int] = None,
    ) -> tuple[bool, str]:
        """
        Verify that the image matches an expected hash digest.

        Args:
            expected_digest: Expected hexadecimal hash digest.
            algorithm: Hash algorithm.
            start_offset: Start byte offset (default 0 = full image).
            length: Bytes to hash (default None = full image).

        Returns:
            (matches, actual_digest) tuple.
        """
        actual_length = length if length is not None else self.reader.image_size
        result = self._compute_hash(
            algorithm=algorithm,
            start_offset=start_offset,
            length=actual_length,
            target="Verification",
        )
        matches = result.digest.lower() == expected_digest.lower().strip()
        return matches, result.digest

    @staticmethod
    def format_hash_for_report(hash_results: List[HashResult]) -> str:
        """Format a list of hash results as a text block for a forensic report."""
        lines = []
        for hr in hash_results:
            lines.append(f"  Algorithm:  {hr.algorithm.upper()}")
            lines.append(f"  Digest:     {hr.digest}")
            lines.append(f"  Target:     {hr.target}")
            lines.append(f"  Size:       {hr.size_human}")
            lines.append(f"  Computed:   {hr.computed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            lines.append("")
        return "\n".join(lines)
