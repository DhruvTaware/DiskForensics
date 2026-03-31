"""
Disk Image Reader for DiskForensics.

Provides sector-level and byte-level access to raw disk image files (dd/raw format).
Designed for large files — never loads the entire image into memory.
Supports hashing while reading for chain-of-custody integrity verification.

Author: Edward Marez
License: MIT
"""

import hashlib
import io
import os
import struct
from pathlib import Path
from typing import Optional, Iterator


class ImageReader:
    """
    Low-level reader for raw/dd disk image files.

    Provides:
    - Sector-level read operations
    - Byte-offset read operations
    - On-the-fly hash computation
    - Image metadata (size, sector count)
    - Iterator over all sectors
    """

    DEFAULT_SECTOR_SIZE = 512

    def __init__(self, image_path: str, sector_size: int = DEFAULT_SECTOR_SIZE):
        """
        Open a disk image file for reading.

        Args:
            image_path: Path to the raw/dd disk image file.
            sector_size: Logical sector size in bytes (default 512).

        Raises:
            FileNotFoundError: If the image file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If sector_size is not a positive power of 2.
        """
        self.image_path = Path(image_path)
        if not self.image_path.exists():
            raise FileNotFoundError(f"Disk image not found: {image_path}")
        if not self.image_path.is_file():
            raise ValueError(f"Path is not a regular file: {image_path}")
        if sector_size <= 0 or (sector_size & (sector_size - 1)) != 0:
            raise ValueError(f"Sector size must be a positive power of 2, got {sector_size}")

        self.sector_size = sector_size
        self._file: Optional[io.BufferedReader] = None
        self._file_size: Optional[int] = None
        self._open()

    def _open(self) -> None:
        """Open the image file handle."""
        self._file = open(self.image_path, "rb")
        self._file.seek(0, os.SEEK_END)
        self._file_size = self._file.tell()
        self._file.seek(0)

    def close(self) -> None:
        """Close the image file handle."""
        if self._file and not self._file.closed:
            self._file.close()

    def __enter__(self) -> "ImageReader":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def image_size(self) -> int:
        """Total image size in bytes."""
        return self._file_size or 0

    @property
    def sector_count(self) -> int:
        """Total number of sectors in the image (rounded down)."""
        return self.image_size // self.sector_size

    @property
    def filename(self) -> str:
        """Base filename of the image."""
        return self.image_path.name

    # ------------------------------------------------------------------
    # Core read operations
    # ------------------------------------------------------------------

    def read_sector(self, lba: int) -> bytes:
        """
        Read one sector by LBA (Logical Block Address).

        Args:
            lba: Logical block address (0-indexed).

        Returns:
            Exactly sector_size bytes, zero-padded if near end of image.

        Raises:
            ValueError: If LBA is out of range.
        """
        if lba < 0:
            raise ValueError(f"LBA must be non-negative, got {lba}")
        offset = lba * self.sector_size
        return self.read_bytes(offset, self.sector_size)

    def read_sectors(self, lba: int, count: int) -> bytes:
        """
        Read multiple contiguous sectors starting at LBA.

        Args:
            lba: Starting logical block address.
            count: Number of sectors to read.

        Returns:
            Exactly count * sector_size bytes.
        """
        if count <= 0:
            return b""
        offset = lba * self.sector_size
        return self.read_bytes(offset, count * self.sector_size)

    def read_bytes(self, offset: int, length: int) -> bytes:
        """
        Read arbitrary bytes at a specific byte offset.

        Args:
            offset: Byte offset from the start of the image.
            length: Number of bytes to read.

        Returns:
            Bytes read (possibly shorter than length if near EOF),
            zero-padded to requested length.

        Raises:
            ValueError: If offset is negative.
        """
        if offset < 0:
            raise ValueError(f"Offset must be non-negative, got {offset}")
        if length <= 0:
            return b""
        if self._file is None or self._file.closed:
            self._open()
        self._file.seek(offset)
        data = self._file.read(length)
        # Zero-pad if we hit EOF early
        if len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data

    def read_at(self, offset: int, fmt: str) -> tuple:
        """
        Read and unpack a struct format at a specific byte offset.

        Args:
            offset: Byte offset from start of image.
            fmt: struct format string (e.g., '<HHL').

        Returns:
            Tuple of unpacked values.
        """
        size = struct.calcsize(fmt)
        data = self.read_bytes(offset, size)
        return struct.unpack(fmt, data)

    # ------------------------------------------------------------------
    # Iteration
    # ------------------------------------------------------------------

    def iter_sectors(self, start_lba: int = 0, end_lba: Optional[int] = None) -> Iterator[tuple[int, bytes]]:
        """
        Iterate over sectors, yielding (lba, data) tuples.

        Args:
            start_lba: First LBA to read (inclusive, default 0).
            end_lba: Last LBA to read (exclusive, default = sector_count).

        Yields:
            (lba, sector_data) tuples.
        """
        if end_lba is None:
            end_lba = self.sector_count
        for lba in range(start_lba, end_lba):
            yield lba, self.read_sector(lba)

    # ------------------------------------------------------------------
    # Hash computation
    # ------------------------------------------------------------------

    def compute_hash(
        self,
        algorithm: str = "sha256",
        start_offset: int = 0,
        length: Optional[int] = None,
        chunk_size: int = 65536,
    ) -> str:
        """
        Compute a cryptographic hash of the image (or a range within it).

        Reads the file in chunks to support arbitrarily large images
        without loading them into memory.

        Args:
            algorithm: Hash algorithm name ('md5', 'sha1', 'sha256', 'sha512').
            start_offset: Byte offset to start hashing (default 0 = full image).
            length: Number of bytes to hash (default None = to end of image).
            chunk_size: Read chunk size in bytes (default 64 KB).

        Returns:
            Lowercase hexadecimal hash digest string.

        Raises:
            ValueError: If algorithm is not supported.
        """
        try:
            h = hashlib.new(algorithm)
        except ValueError:
            raise ValueError(
                f"Unsupported hash algorithm '{algorithm}'. "
                f"Supported: {sorted(hashlib.algorithms_available)}"
            )

        if self._file is None or self._file.closed:
            self._open()

        self._file.seek(start_offset)
        remaining = length if length is not None else (self.image_size - start_offset)

        while remaining > 0:
            to_read = min(chunk_size, remaining)
            chunk = self._file.read(to_read)
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)

        return h.hexdigest()

    def compute_all_hashes(
        self, start_offset: int = 0, length: Optional[int] = None
    ) -> dict[str, str]:
        """
        Compute MD5, SHA-1, and SHA-256 hashes simultaneously in one pass.

        Returns:
            Dict with keys 'md5', 'sha1', 'sha256', 'sha512'.
        """
        hashes = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
            "sha512": hashlib.sha512(),
        }

        if self._file is None or self._file.closed:
            self._open()

        self._file.seek(start_offset)
        remaining = length if length is not None else (self.image_size - start_offset)
        chunk_size = 65536

        while remaining > 0:
            to_read = min(chunk_size, remaining)
            chunk = self._file.read(to_read)
            if not chunk:
                break
            for h in hashes.values():
                h.update(chunk)
            remaining -= len(chunk)

        return {name: h.hexdigest() for name, h in hashes.items()}

    def compute_partition_hash(
        self, lba_start: int, sector_count: int, algorithm: str = "sha256"
    ) -> str:
        """
        Compute hash of a specific partition by LBA range.

        Args:
            lba_start: First sector of the partition.
            sector_count: Number of sectors in the partition.
            algorithm: Hash algorithm to use.

        Returns:
            Hexadecimal hash digest string.
        """
        start_offset = lba_start * self.sector_size
        length = sector_count * self.sector_size
        return self.compute_hash(algorithm=algorithm, start_offset=start_offset, length=length)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        from .utils import format_bytes
        return (
            f"ImageReader("
            f"path={self.image_path.name!r}, "
            f"size={format_bytes(self.image_size)}, "
            f"sector_size={self.sector_size}, "
            f"sectors={self.sector_count:,})"
        )

    def info(self) -> dict:
        """Return image metadata as a dictionary."""
        from .utils import format_bytes
        return {
            "path": str(self.image_path),
            "filename": self.image_path.name,
            "size_bytes": self.image_size,
            "size_human": format_bytes(self.image_size),
            "sector_size": self.sector_size,
            "sector_count": self.sector_count,
        }
