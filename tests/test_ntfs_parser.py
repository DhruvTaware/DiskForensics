"""
Tests for NTFS Parser.

Verifies:
- Boot sector parsing (OEM ID, bytes/sector, MFT location)
- MFT record parsing (signature, flags, in-use detection)
- $STANDARD_INFORMATION timestamps
- $FILE_NAME attribute (name, parent reference, timestamps)
- $DATA attribute
- Deleted record detection
"""

import tempfile
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from diskforensics.image_reader import ImageReader
from diskforensics.ntfs_parser import NTFSParser, MFTRecord, NTFSBootSector
from sample_images.generate_sample import create_ntfs_image


class TestNTFSParserBootSector(unittest.TestCase):
    """Test NTFS boot sector parsing."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_ntfs.dd")
        create_ntfs_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.parser = NTFSParser(cls.reader, partition_lba_start=2048)
        cls.boot_sector = cls.parser.parse_boot_sector()

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_boot_sector_not_none(self):
        self.assertIsNotNone(self.boot_sector)

    def test_oem_id(self):
        """OEM ID should be 'NTFS    '."""
        self.assertIn("NTFS", self.boot_sector.oem_id)

    def test_bytes_per_sector(self):
        self.assertEqual(self.boot_sector.bytes_per_sector, 512)

    def test_sectors_per_cluster(self):
        self.assertEqual(self.boot_sector.sectors_per_cluster, 8)

    def test_bytes_per_cluster(self):
        self.assertEqual(self.boot_sector.bytes_per_cluster, 512 * 8)

    def test_mft_cluster_number(self):
        self.assertEqual(self.boot_sector.mft_cluster_number, 4)

    def test_mft_record_size(self):
        """Record size is 2^10 = 1024 bytes (clusters_per_mft_record = -10)."""
        self.assertEqual(self.boot_sector.mft_record_size, 1024)

    def test_mft_offset(self):
        """MFT byte offset should be cluster * sectors_per_cluster * bytes_per_sector."""
        expected = 4 * 8 * 512  # 16384
        self.assertEqual(self.boot_sector.mft_offset, expected)

    def test_total_sectors(self):
        partition_sectors = 8192 - 2048  # 6144
        self.assertEqual(self.boot_sector.total_sectors, partition_sectors)

    def test_to_dict_keys(self):
        d = self.boot_sector.to_dict()
        self.assertIn("oem_id", d)
        self.assertIn("bytes_per_sector", d)
        self.assertIn("mft_cluster_number", d)
        self.assertIn("mft_record_size", d)


class TestNTFSParserMFTRecords(unittest.TestCase):
    """Test MFT record parsing."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_ntfs.dd")
        create_ntfs_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.parser = NTFSParser(cls.reader, partition_lba_start=2048)
        cls.result = cls.parser.parse(max_records=50)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_parse_valid(self):
        self.assertTrue(self.result.valid, f"Error: {self.result.error}")

    def test_records_found(self):
        """Should find at least 10 MFT records."""
        self.assertGreater(len(self.result.records), 9)

    def test_active_records(self):
        """Should have active records."""
        self.assertGreater(len(self.result.active_records), 0)

    def test_deleted_records(self):
        """Should have at least 2 deleted records (suspects.txt, passwords.db)."""
        self.assertGreaterEqual(len(self.result.deleted_records), 2)

    def test_system_records_in_use(self):
        """System MFT records (0-5) should be in use."""
        system_records = [r for r in self.result.records if r.record_number <= 5]
        for r in system_records:
            self.assertTrue(r.in_use, f"Record {r.record_number} should be in use")

    def test_mft_record_0_name(self):
        """MFT record 0 should be $MFT."""
        rec0 = next((r for r in self.result.records if r.record_number == 0), None)
        self.assertIsNotNone(rec0)
        self.assertIn("MFT", rec0.primary_name)

    def test_root_directory_record(self):
        """MFT record 5 should be a directory."""
        rec5 = next((r for r in self.result.records if r.record_number == 5), None)
        self.assertIsNotNone(rec5)
        self.assertTrue(rec5.is_directory)

    def test_report_txt_active(self):
        """report.txt (record 16) should be active."""
        rec = next((r for r in self.result.records if r.record_number == 16), None)
        self.assertIsNotNone(rec)
        self.assertTrue(rec.in_use)
        self.assertIn("report", rec.primary_name.lower())

    def test_evidence_bin_active(self):
        """evidence.bin (record 17) should be active."""
        rec = next((r for r in self.result.records if r.record_number == 17), None)
        self.assertIsNotNone(rec)
        self.assertTrue(rec.in_use)
        self.assertIn("evidence", rec.primary_name.lower())

    def test_suspects_txt_deleted(self):
        """suspects.txt (record 19) should be deleted (not in use)."""
        rec = next((r for r in self.result.records if r.record_number == 19), None)
        self.assertIsNotNone(rec)
        self.assertFalse(rec.in_use, "suspects.txt should be deleted")
        self.assertIn("suspects", rec.primary_name.lower())

    def test_passwords_db_deleted(self):
        """passwords.db (record 20) should be deleted (not in use)."""
        rec = next((r for r in self.result.records if r.record_number == 20), None)
        self.assertIsNotNone(rec)
        self.assertFalse(rec.in_use, "passwords.db should be deleted")
        self.assertIn("password", rec.primary_name.lower())

    def test_standard_information_timestamps(self):
        """Active files should have $STANDARD_INFORMATION with timestamps."""
        rec16 = next((r for r in self.result.records if r.record_number == 16), None)
        self.assertIsNotNone(rec16)
        self.assertIsNotNone(rec16.standard_info)
        self.assertIsNotNone(rec16.standard_info.created)
        self.assertIsInstance(rec16.standard_info.created, datetime)

    def test_timestamps_year_2026(self):
        """Active files should have 2026 timestamps."""
        rec16 = next((r for r in self.result.records if r.record_number == 16), None)
        self.assertIsNotNone(rec16)
        ts = rec16.standard_info.created
        self.assertEqual(ts.year, 2026)

    def test_deleted_timestamps_preserved(self):
        """Deleted records should still have timestamps."""
        rec19 = next((r for r in self.result.records if r.record_number == 19), None)
        self.assertIsNotNone(rec19)
        self.assertIsNotNone(rec19.standard_info)
        self.assertIsNotNone(rec19.standard_info.modified)

    def test_file_names_present(self):
        """Records 16-20 should have $FILE_NAME entries."""
        for num in (16, 17, 18, 19, 20):
            rec = next((r for r in self.result.records if r.record_number == num), None)
            if rec:
                self.assertGreater(len(rec.file_names), 0,
                                   f"Record {num} should have $FILE_NAME attributes")

    def test_data_attribute_size(self):
        """report.txt should have data size > 0."""
        rec16 = next((r for r in self.result.records if r.record_number == 16), None)
        self.assertIsNotNone(rec16)
        self.assertGreater(rec16.data_size, 0)

    def test_to_dict(self):
        d = self.result.to_dict()
        self.assertIn("valid", d)
        self.assertIn("records", d)
        self.assertIn("total_records", d)
        self.assertIn("deleted_records", d)


class TestNTFSParserInvalidImage(unittest.TestCase):
    """Test NTFS parser on non-NTFS images."""

    def test_non_ntfs_returns_invalid(self):
        with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as f:
            f.write(b"\x00" * 1024)
            path = f.name
        try:
            reader = ImageReader(path)
            parser = NTFSParser(reader, partition_lba_start=0)
            result = parser.parse()
            self.assertFalse(result.valid)
            reader.close()
        finally:
            os.unlink(path)


class TestMFTRecord(unittest.TestCase):
    """Unit tests for MFTRecord properties."""

    def _make_record(self, record_num, in_use, is_dir, names=None):
        from diskforensics.ntfs_parser import NTFSStandardInfo, NTFSFileName
        dt = datetime(2026, 1, 10, 9, 30, 0, tzinfo=timezone.utc)
        si = NTFSStandardInfo(
            created=dt, modified=dt, mft_modified=dt, accessed=dt,
            file_attributes=0x20
        )
        file_names = []
        for name in (names or []):
            fn = NTFSFileName(
                parent_ref=5, created=dt, modified=dt, mft_modified=dt,
                accessed=dt, allocated_size=512, real_size=256,
                file_attributes=0x20, name_type=1, name=name
            )
            file_names.append(fn)
        return MFTRecord(
            record_number=record_num,
            sequence_number=1,
            flags=(0x01 if in_use else 0) | (0x02 if is_dir else 0),
            hard_link_count=1,
            in_use=in_use,
            is_directory=is_dir,
            standard_info=si,
            file_names=file_names,
            data_size=256,
        )

    def test_primary_name(self):
        rec = self._make_record(16, True, False, ["report.txt"])
        self.assertEqual(rec.primary_name, "report.txt")

    def test_primary_name_no_file_names(self):
        rec = self._make_record(99, False, False, [])
        rec.file_names = []
        self.assertIn("99", rec.primary_name)

    def test_in_use(self):
        rec = self._make_record(16, True, False, ["test.txt"])
        self.assertTrue(rec.in_use)

    def test_not_in_use(self):
        rec = self._make_record(19, False, False, ["deleted.txt"])
        self.assertFalse(rec.in_use)

    def test_is_directory(self):
        rec = self._make_record(5, True, True, ["docs"])
        self.assertTrue(rec.is_directory)

    def test_created_from_standard_info(self):
        rec = self._make_record(16, True, False, ["test.txt"])
        self.assertEqual(rec.created.year, 2026)

    def test_to_dict(self):
        rec = self._make_record(16, True, False, ["test.txt"])
        d = rec.to_dict()
        self.assertEqual(d["record_number"], 16)
        self.assertTrue(d["in_use"])
        self.assertFalse(d["is_deleted"])
        self.assertIn("standard_info", d)
        self.assertIn("file_names", d)


if __name__ == "__main__":
    unittest.main()
