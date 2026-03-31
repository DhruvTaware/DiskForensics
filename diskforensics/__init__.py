"""
DiskForensics - A professional disk image analysis tool for forensic investigations.

Author: Edward Marez
License: MIT
Version: 1.0.0

This package provides tools to:
- Parse disk image files (raw/dd format): MBR and GPT partition tables
- Parse FAT32 and NTFS filesystem metadata
- Recover deleted file entries from filesystem metadata
- Extract file timestamps for timeline analysis
- Generate forensic timelines of all file system activity
- Calculate forensic hashes of disk images and partitions
- Produce forensic reports suitable for investigation documentation
"""

__version__ = "1.0.0"
__author__ = "Edward Marez"
__license__ = "MIT"

from .image_reader import ImageReader
from .mbr_parser import MBRParser
from .gpt_parser import GPTParser
from .fat32_parser import FAT32Parser
from .ntfs_parser import NTFSParser
from .file_recovery import FileRecovery
from .timeline_generator import TimelineGenerator
from .hash_engine import HashEngine
from .report_generator import ReportGenerator

__all__ = [
    "ImageReader",
    "MBRParser",
    "GPTParser",
    "FAT32Parser",
    "NTFSParser",
    "FileRecovery",
    "TimelineGenerator",
    "HashEngine",
    "ReportGenerator",
]
