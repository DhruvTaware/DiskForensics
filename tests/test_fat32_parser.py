"""
Tests for FAT32 Parser.

Verifies:
- Boot sector parsing (bytes per sector, cluster size, volume label)
- FAT entry reading and cluster chain following
- Directory entry parsing (name, timestamps, attributes)
- Deleted entry detection (0xE5 first byte)
- Long filename (LFN) support
- Full filesystem walk
"""

import tempfile
import os
import unittest
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from diskforensics.image_reader import ImageReader
from diskforensics.fat32_parser import FAT32Parser, FAT32DirectoryEntry
from sample_images.generate_sample import create_fat32_image


class TestFAT32ParserWithSyntheticImage(unittest.TestCase):
    """Test FAT32 parser against a synthesized FAT32 disk image."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_fat32.dd")
        create_fat32_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.parser = FAT32Parser(cls.reader, partition_lba_start=2048)
        cls.result = cls.parser.parse()

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # --- Boot Sector ---

    def test_parse_valid(self):
        """Parser should successfully parse the FAT32 filesystem."""
        self.assertTrue(self.result.valid, f"Parse error: {self.result.error}")

    def test_boot_sector_not_none(self):
        self.assertIsNotNone(self.result.boot_sector)

    def test_bytes_per_sector(self):
        self.assertEqual(self.result.boot_sector.bytes_per_sector, 512)

    def test_sectors_per_cluster(self):
        self.assertEqual(self.result.boot_sector.sectors_per_cluster, 1)

    def test_bytes_per_cluster(self):
        self.assertEqual(self.result.boot_sector.bytes_per_cluster, 512)

    def test_volume_label(self):
        label = self.result.boot_sector.volume_label
        self.assertIn("EVIDENCE", label)

    def test_fs_type_fat32(self):
        self.assertIn("FAT32", self.result.boot_sector.fs_type)

    def test_num_fats(self):
        self.assertEqual(self.result.boot_sector.num_fats, 2)

    def test_root_cluster(self):
        self.assertEqual(self.result.boot_sector.root_cluster, 2)

    def test_fat_start_sector(self):
        # reserved_sectors = 4
        self.assertEqual(self.result.boot_sector.fat_start_sector, 4)

    def test_data_start_sector(self):
        # reserved + 2 FATs × sectors_per_fat = 4 + 2*2 = 8
        self.assertEqual(self.result.boot_sector.data_start_sector, 8)

    # --- Active Files ---

    def test_active_file_count(self):
        """Should find 2 active files (REPORT.TXT and EVIDENCE.BIN)."""
        # Plus . and .. are skipped
        active_names = [f.name_short.strip() for f in self.result.files]
        files_only = [n for n in active_names if n not in (".", "..")]
        self.assertGreaterEqual(len(files_only), 2)

    def test_report_txt_exists(self):
        """REPORT.TXT should be in active files."""
        names = [f.name_short.strip() for f in self.result.files]
        self.assertTrue(any("REPORT" in n for n in names), f"Files: {names}")

    def test_evidence_bin_exists(self):
        """EVIDENCE.BIN should be in active files."""
        names = [f.name_short.strip() for f in self.result.files]
        self.assertTrue(any("EVIDENCE" in n for n in names), f"Files: {names}")

    def test_active_files_not_deleted(self):
        """All active files should have is_deleted=False."""
        for f in self.result.files:
            self.assertFalse(f.is_deleted, f"File {f.name} should not be deleted")

    # --- Deleted Files ---

    def test_deleted_file_count(self):
        """Should find 2 deleted files (NOTES.TXT and PASSWD.TXT)."""
        self.assertGreaterEqual(len(self.result.deleted_files), 2)

    def test_deleted_files_marked(self):
        """All deleted entries should have is_deleted=True."""
        for f in self.result.deleted_files:
            self.assertTrue(f.is_deleted, f"Entry {f.name} should be marked deleted")

    def test_deleted_name_prefix(self):
        """Deleted files should have '_' as first character (0xE5 replaced)."""
        for f in self.result.deleted_files:
            short_name = f.name_short.strip()
            if short_name not in (".", ".."):
                self.assertTrue(
                    short_name.startswith("_"),
                    f"Deleted entry '{short_name}' should start with '_'"
                )

    def test_deleted_notes_found(self):
        """_OTES.TXT (was NOTES.TXT) should be in deleted files."""
        names = [f.name_short.strip() for f in self.result.deleted_files]
        self.assertTrue(any("OTES" in n for n in names), f"Deleted files: {names}")

    # --- Timestamps ---

    def test_timestamps_are_datetime(self):
        """All non-None timestamps should be datetime objects."""
        for f in self.result.files + self.result.deleted_files:
            if f.created:
                self.assertIsInstance(f.created, datetime)
            if f.modified:
                self.assertIsInstance(f.modified, datetime)
            if f.accessed:
                self.assertIsInstance(f.accessed, datetime)

    def test_report_txt_timestamp(self):
        """REPORT.TXT should have a 2026 timestamp."""
        report = next(
            (f for f in self.result.files if "REPORT" in f.name_short),
            None
        )
        self.assertIsNotNone(report)
        self.assertIsNotNone(report.created)
        self.assertEqual(report.created.year, 2026)

    # --- to_dict ---

    def test_to_dict_structure(self):
        d = self.result.to_dict()
        self.assertIn("valid", d)
        self.assertIn("files", d)
        self.assertIn("deleted_files", d)
        self.assertIn("boot_sector", d)
        self.assertTrue(d["valid"])

    def test_file_to_dict(self):
        """Individual file to_dict should have expected keys."""
        if self.result.files:
            d = self.result.files[0].to_dict()
            self.assertIn("name", d)
            self.assertIn("file_size", d)
            self.assertIn("first_cluster", d)
            self.assertIn("is_deleted", d)


class TestFAT32ClusterChain(unittest.TestCase):
    """Test FAT cluster chain traversal."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_fat32.dd")
        create_fat32_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.parser = FAT32Parser(cls.reader, partition_lba_start=2048)
        # Need to parse to populate boot sector
        cls.result = cls.parser.parse()

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_single_cluster_chain(self):
        """Single-cluster file should have chain of length 1."""
        chain = self.parser.follow_cluster_chain(3)  # REPORT.TXT at cluster 3
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0], 3)

    def test_multi_cluster_chain(self):
        """EVIDENCE.BIN spans clusters 4-5."""
        chain = self.parser.follow_cluster_chain(4)
        self.assertEqual(len(chain), 2)
        self.assertIn(4, chain)
        self.assertIn(5, chain)

    def test_free_cluster(self):
        """Cluster 6 should be free (NOTES.TXT was deleted)."""
        fat_entry = self.parser.get_fat_entry(6)
        self.assertEqual(fat_entry, 0x00000000)

    def test_fat_entries_valid(self):
        """FAT entries 0 and 1 should be media descriptor and EOC."""
        entry0 = self.parser.get_fat_entry(0)
        entry1 = self.parser.get_fat_entry(1)
        self.assertEqual(entry0 & 0x0FFFFFFF, 0x0FFFFFF8)
        self.assertEqual(entry1 & 0x0FFFFFFF, 0x0FFFFFFF)


class TestFAT32DirectoryEntry(unittest.TestCase):
    """Unit tests for FAT32DirectoryEntry properties."""

    def _make_entry(self, name, ext, attrs, size, deleted=False):
        from datetime import datetime
        dt = datetime(2026, 1, 10, 9, 30, 0)
        return FAT32DirectoryEntry(
            name_short=f"{name}.{ext}" if ext else name,
            name_long="",
            attributes=attrs,
            is_deleted=deleted,
            is_directory=bool(attrs & 0x10),
            first_cluster=3,
            file_size=size,
            created=dt,
            modified=dt,
            accessed=dt,
        )

    def test_attr_string_archive(self):
        e = self._make_entry("FILE", "TXT", 0x20, 100)
        self.assertIn("A", e.attr_string)

    def test_attr_string_directory(self):
        e = self._make_entry("DIR", "", 0x10, 0)
        self.assertIn("D", e.attr_string)

    def test_size_human(self):
        e = self._make_entry("FILE", "TXT", 0x20, 1024)
        self.assertIn("1.0 KB", e.size_human)

    def test_to_dict_has_timestamps(self):
        e = self._make_entry("FILE", "TXT", 0x20, 512)
        d = e.to_dict()
        self.assertIsNotNone(d["created"])
        self.assertIsNotNone(d["modified"])


if __name__ == "__main__":
    unittest.main()
