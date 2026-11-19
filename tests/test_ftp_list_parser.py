import unittest

from core.sftp_client import FTPClient


class FTPListParserTests(unittest.TestCase):
    def setUp(self):
        self.client = FTPClient("example.invalid", 21, "test-user")

    def parse_one(self, line):
        entries = self.client._parse_list([line])
        self.assertEqual(1, len(entries))
        return entries[0]

    def test_iis_directory_with_two_digit_year(self):
        entry = self.parse_one("07-24-21  12:13PM       <DIR>          assets")
        self.assertEqual("assets", entry["name"])
        self.assertTrue(entry["is_dir"])
        self.assertEqual(0, entry["size"])
        self.assertGreater(entry["mtime"], 0)

    def test_iis_file(self):
        entry = self.parse_one("09-01-26  03:28AM                 3685 index.html")
        self.assertEqual("index.html", entry["name"])
        self.assertFalse(entry["is_dir"])
        self.assertEqual(3685, entry["size"])
        self.assertGreater(entry["mtime"], 0)

    def test_iis_filename_with_spaces(self):
        entry = self.parse_one("09-01-26  03:28AM                   42 file name with spaces.txt")
        self.assertEqual("file name with spaces.txt", entry["name"])
        self.assertEqual(42, entry["size"])

    def test_iis_zero_byte_file(self):
        entry = self.parse_one("07-24-21  12:13PM                    0 empty.txt")
        self.assertEqual("empty.txt", entry["name"])
        self.assertFalse(entry["is_dir"])
        self.assertEqual(0, entry["size"])

    def test_iis_four_digit_year_and_whitespace_variation(self):
        entry = self.parse_one(" 09-01-2026   3:28 AM   42   spaced.txt")
        self.assertEqual("spaced.txt", entry["name"])
        self.assertEqual(42, entry["size"])
        self.assertGreater(entry["mtime"], 0)

    def test_unix_directory(self):
        entry = self.parse_one("drwxr-xr-x 2 owner group 4096 Sep  1 03:26 config")
        self.assertEqual("config", entry["name"])
        self.assertTrue(entry["is_dir"])
        self.assertEqual(4096, entry["size"])
        self.assertEqual(0, entry["mtime"])

    def test_unix_file(self):
        entry = self.parse_one("-rw-r--r-- 1 owner group 3685 Sep  1 03:28 index.html")
        self.assertEqual("index.html", entry["name"])
        self.assertFalse(entry["is_dir"])
        self.assertEqual(3685, entry["size"])
        self.assertEqual(0, entry["mtime"])

    def test_malformed_and_invalid_date_are_ignored(self):
        self.assertEqual([], self.client._parse_list(["not a valid FTP listing"]))
        self.assertEqual([], self.client._parse_list(["99-99-99  99:99PM <DIR> invalid"]))


if __name__ == "__main__":
    unittest.main()
