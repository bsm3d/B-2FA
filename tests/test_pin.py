"""PIN quick unlock tests (Windows only: DPAPI)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from b2fa import pinlock  # noqa: E402

MASTER = "correct horse battery"


@unittest.skipUnless(sys.platform == "win32", "DPAPI needs Windows")
class PinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = pinlock.PinStore(Path(self.tmp.name) / "pin.b2fa")

    def left(self):
        return json.loads(self.store.path.read_text())["attempts_left"]

    def test_roundtrip_and_no_plaintext(self):
        self.store.enable("4821", MASTER)
        self.assertTrue(self.store.enabled)
        raw = self.store.path.read_text()
        self.assertNotIn(MASTER, raw)
        self.assertEqual(self.store.unlock("4821"), MASTER)

    def test_wrong_pin_counts_and_wipes(self):
        self.store.enable("4821", MASTER)
        for expected in (4, 3, 2, 1):
            with self.assertRaises(pinlock.WrongPin) as ctx:
                self.store.unlock("0000")
            self.assertEqual(ctx.exception.attempts_left, expected)
        with self.assertRaises(pinlock.PinDisabled):
            self.store.unlock("0000")  # fifth failure
        self.assertFalse(self.store.enabled)
        with self.assertRaises(pinlock.PinDisabled):
            self.store.unlock("4821")  # even the right PIN no longer works: master password only

    def test_success_resets_counter(self):
        self.store.enable("4821", MASTER)
        for _ in range(3):
            with self.assertRaises(pinlock.WrongPin):
                self.store.unlock("1111")
        self.assertEqual(self.left(), 2)
        self.assertEqual(self.store.unlock("4821"), MASTER)
        self.assertEqual(self.left(), pinlock.MAX_ATTEMPTS)

    def test_attempt_is_counted_before_trying(self):
        """Killing the app in the middle of a try must not give a free guess."""
        self.store.enable("4821", MASTER)
        with mock.patch.object(pinlock, "_unprotect", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.store.unlock("4821")
        self.assertEqual(self.left(), pinlock.MAX_ATTEMPTS - 1)

    def test_bad_formats(self):
        for bad in ("123", "12345678901", "abcd", "12 4", "١٢٣٤"):
            with self.assertRaises(pinlock.PinError):
                self.store.enable(bad, MASTER)
        self.assertFalse(self.store.enabled)
        self.store.enable("4821", MASTER)
        with self.assertRaises(pinlock.WrongPin):
            self.store.unlock("48")  # malformed input is just a wrong try
        self.assertEqual(self.left(), pinlock.MAX_ATTEMPTS - 1)

    def test_damaged_file_is_removed(self):
        self.store.enable("4821", MASTER)
        self.store.path.write_text("not json")
        with self.assertRaises(pinlock.PinDisabled):
            self.store.unlock("4821")
        self.assertFalse(self.store.enabled)

    def test_tampered_salt_fails(self):
        self.store.enable("4821", MASTER)
        doc = json.loads(self.store.path.read_text())
        doc["salt"] = "AAAAAAAAAAAAAAAAAAAAAA=="
        self.store.path.write_text(json.dumps(doc))
        with self.assertRaises(pinlock.WrongPin):
            self.store.unlock("4821")


if __name__ == "__main__":
    unittest.main()
