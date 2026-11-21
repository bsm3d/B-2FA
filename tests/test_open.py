"""open_folder: creates a missing folder, retries, falls back, never raises."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from b2fa import app  # noqa: E402


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class OpenFolderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / "gone" / "backups"

    def test_missing_folder_is_created_then_opened(self):
        with mock.patch.object(app.os, "startfile", create=True) as start:
            self.assertTrue(app.open_folder(self.folder))
        self.assertTrue(self.folder.is_dir())
        start.assert_called_once_with(os.path.normpath(str(self.folder)))

    def test_one_failure_is_retried(self):
        with mock.patch.object(app.os, "startfile", create=True, side_effect=[OSError("shell"), None]) as start, \
                mock.patch.object(app.time, "sleep"):
            self.assertTrue(app.open_folder(self.folder))
        self.assertEqual(start.call_count, 2)

    def test_falls_back_to_explorer(self):
        with mock.patch.object(app.os, "startfile", create=True, side_effect=OSError("shell")), \
                mock.patch.object(app.time, "sleep"), \
                mock.patch.object(app.subprocess, "Popen") as popen:
            self.assertTrue(app.open_folder(self.folder))
        self.assertEqual(popen.call_args[0][0][0], "explorer.exe")

    def test_total_failure_returns_false(self):
        with mock.patch.object(app.os, "startfile", create=True, side_effect=OSError("shell")), \
                mock.patch.object(app.time, "sleep"), \
                mock.patch.object(app.subprocess, "Popen", side_effect=OSError("no explorer")):
            self.assertFalse(app.open_folder(self.folder))

    def test_uncreatable_folder_returns_false(self):
        blocker = Path(self.tmp.name) / "file"
        blocker.write_text("x")
        self.assertFalse(app.open_folder(blocker / "backups"))  # a file where a folder should be


if __name__ == "__main__":
    unittest.main()
