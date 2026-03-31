"""
Tests for File Recovery module.

Verifies:
- FAT32 deleted file detection and recoverability assessment
- NTFS deleted MFT record detection
- Recovery notes generation
- RecoveredFile and RecoveryResult properties
"""

import tempfile
import os
import unittest
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from diskforensics.image_reader import ImageReader
from diskforensics.fat32_parser import FAT32Parser
from diskforensics.ntfs_parser import NTFSParser
from diskforensics.file_recovery import FileRecovery, RecoveredFile, RecoveryResult
from sample_images.generate_sample import create_fat32_image, create_ntfs_image


class TestFAT32FileRecovery(unittest.TestCase):
    """Test deleted file recovery on a FAT32 filesystem."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_fat32.dd")
        create_fat32_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.fat_parser = FAT32Parser(cls.reader, partition_lba_start=2048)
        cls.fat_result = cls.fat_parser.parse()
        cls.recovery = FileRecovery()
        cls.result = cls.recovery.recover_fat32(cls.fat_parser, cls.fat_result)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_filesystem_label(self):
        """Recovery result should be labeled FAT32."""
        self.assertEqual(self.result.filesystem, "FAT32")

    def test_deleted_files_found(self):
        """Should find at least 2 deleted files."""
        self.assertGreaterEqual(self.result.count, 2)

    def test_filename_partial(self):
        """All FAT32 recovered files should have filename_partial=True."""
        for f in self.result.recovered_files:
            self.assertTrue(f.filename_partial,
                            f"'{f.filename}' should have partial flag (FAT32 loses first char)")

    def test_notes_cluster_free_recovered(self):
        """_OTES.TXT (cluster 6, free) should be likely recoverable."""
        notes = next(
            (f for f in self.result.recovered_files if "OTES" in f.filename.upper()),
            None
        )
        self.assertIsNotNone(notes, "Should find deleted NOTES.TXT entry")
        self.assertTrue(notes.likely_recoverable,
                        f"NOTES.TXT cluster 6 is free; should be recoverable. Notes: {notes.recovery_notes}")

    def test_passwd_cluster_reallocated_not_recoverable(self):
        """_ASSWD.TXT (cluster 7, reallocated) should NOT be recoverable."""
        passwd = next(
            (f for f in self.result.recovered_files if "ASSWD" in f.filename.upper()),
            None
        )
        self.assertIsNotNone(passwd, "Should find deleted PASSWD.TXT entry")
        self.assertFalse(passwd.likely_recoverable,
                         f"PASSWD.TXT cluster 7 was reallocated; should not be recoverable. Notes: {passwd.recovery_notes}")

    def test_timestamps_preserved(self):
        """Recovered FAT32 files should have timestamps."""
        for f in self.result.recovered_files:
            # At least one timestamp should be present
            has_ts = f.created or f.modified or f.accessed
            self.assertTrue(has_ts, f"File '{f.filename}' should have at least one timestamp")

    def test_scan_notes_present(self):
        """Scan notes should be a non-empty string."""
        self.assertIsInstance(self.result.scan_notes, str)
        self.assertGreater(len(self.result.scan_notes), 0)

    def test_to_dict_structure(self):
        d = self.result.to_dict()
        self.assertIn("filesystem", d)
        self.assertIn("total_deleted", d)
        self.assertIn("likely_recoverable", d)
        self.assertIn("recovered_files", d)
        self.assertEqual(d["filesystem"], "FAT32")

    def test_likely_recoverable_count(self):
        """At least 1 file should be likely recoverable."""
        self.assertGreaterEqual(self.result.likely_recoverable_count, 1)


class TestNTFSFileRecovery(unittest.TestCase):
    """Test deleted file recovery on an NTFS filesystem."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_ntfs.dd")
        create_ntfs_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.ntfs_parser = NTFSParser(cls.reader, partition_lba_start=2048)
        cls.ntfs_result = cls.ntfs_parser.parse(max_records=50)
        cls.recovery = FileRecovery()
        cls.result = cls.recovery.recover_ntfs(cls.ntfs_result)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_filesystem_label(self):
        self.assertEqual(self.result.filesystem, "NTFS")

    def test_deleted_files_found(self):
        """Should find at least 2 deleted files (suspects.txt, passwords.db)."""
        self.assertGreaterEqual(self.result.count, 2)

    def test_suspects_txt_recovered(self):
        """suspects.txt should be in recovered files."""
        suspects = next(
            (f for f in self.result.recovered_files if "suspects" in f.filename.lower()),
            None
        )
        self.assertIsNotNone(suspects, "suspects.txt should be recovered")

    def test_passwords_db_recovered(self):
        """passwords.db should be in recovered files."""
        passwords = next(
            (f for f in self.result.recovered_files if "password" in f.filename.lower()),
            None
        )
        self.assertIsNotNone(passwords, "passwords.db should be recovered")

    def test_ntfs_filename_not_partial(self):
        """NTFS recovered files should NOT have partial filenames."""
        for f in self.result.recovered_files:
            self.assertFalse(f.filename_partial,
                             f"NTFS '{f.filename}' should have complete filename")

    def test_ntfs_all_likely_recoverable(self):
        """NTFS deleted MFT records are always marked as likely recoverable (metadata intact)."""
        for f in self.result.recovered_files:
            self.assertTrue(f.likely_recoverable,
                            f"NTFS '{f.filename}' metadata should be recoverable")

    def test_ntfs_timestamps_preserved(self):
        """NTFS deleted files should have full timestamps."""
        for f in self.result.recovered_files:
            self.assertIsNotNone(f.modified,
                                 f"NTFS '{f.filename}' should have modified timestamp")

    def test_suspects_txt_timestamp(self):
        """suspects.txt should have 2025 timestamp."""
        suspects = next(
            (f for f in self.result.recovered_files if "suspects" in f.filename.lower()),
            None
        )
        if suspects and suspects.modified:
            self.assertEqual(suspects.modified.year, 2025)

    def test_recovery_notes_mention_mft(self):
        """Recovery notes should mention MFT."""
        for f in self.result.recovered_files:
            self.assertIn("MFT", f.recovery_notes, f"Notes for '{f.filename}' should mention MFT")

    def test_to_dict_structure(self):
        d = self.result.to_dict()
        self.assertIn("filesystem", d)
        self.assertIn("total_deleted", d)
        self.assertIn("recovered_files", d)
        self.assertEqual(d["filesystem"], "NTFS")


class TestRecoveredFile(unittest.TestCase):
    """Unit tests for RecoveredFile properties."""

    def _make_file(self, name, fs, size, recoverable, partial=False):
        dt = datetime(2026, 3, 1, 10, 0, 0)
        return RecoveredFile(
            filesystem=fs,
            filename=name,
            filename_partial=partial,
            file_size=size,
            first_cluster=3,
            created=dt,
            modified=dt,
            accessed=dt,
            is_directory=False,
            likely_recoverable=recoverable,
            recovery_notes="Test notes.",
        )

    def test_size_human(self):
        f = self._make_file("test.txt", "FAT32", 2048, True)
        self.assertIn("2.0 KB", f.size_human)

    def test_to_dict(self):
        f = self._make_file("test.txt", "FAT32", 2048, True, partial=True)
        d = f.to_dict()
        self.assertEqual(d["filename"], "test.txt")
        self.assertEqual(d["filesystem"], "FAT32")
        self.assertTrue(d["filename_partial"])
        self.assertTrue(d["likely_recoverable"])
        self.assertIsNotNone(d["modified"])

    def test_size_zero(self):
        f = self._make_file("empty.txt", "NTFS", 0, True)
        self.assertEqual(f.size_human, "0.0 B")


class TestRecoveryResult(unittest.TestCase):
    """Unit tests for RecoveryResult."""

    def _make_result(self, fs, count, recoverable_count):
        dt = datetime(2026, 1, 1)
        files = []
        for i in range(count):
            files.append(RecoveredFile(
                filesystem=fs,
                filename=f"file{i}.txt",
                filename_partial=fs == "FAT32",
                file_size=1024,
                first_cluster=i + 3,
                created=dt, modified=dt, accessed=dt,
                is_directory=False,
                likely_recoverable=(i < recoverable_count),
                recovery_notes="",
            ))
        return RecoveryResult(filesystem=fs, recovered_files=files)

    def test_count(self):
        r = self._make_result("FAT32", 5, 3)
        self.assertEqual(r.count, 5)

    def test_likely_recoverable_count(self):
        r = self._make_result("NTFS", 4, 2)
        self.assertEqual(r.likely_recoverable_count, 2)

    def test_to_dict_counts(self):
        r = self._make_result("FAT32", 5, 3)
        d = r.to_dict()
        self.assertEqual(d["total_deleted"], 5)
        self.assertEqual(d["likely_recoverable"], 3)
        self.assertEqual(len(d["recovered_files"]), 5)


if __name__ == "__main__":
    unittest.main()
