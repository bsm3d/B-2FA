"""About dialog tests (needs a display)."""

import os
import sys
import tempfile
import tkinter as tk
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from b2fa import APP_NAME, AUTHOR, __version__, app as appmod  # noqa: E402


def all_text(widget):
    out = []
    for w in widget.winfo_children():
        try:
            out.append(str(w.cget("text")))
        except tk.TclError:
            pass
        out.extend(all_text(w))
    return out


class AboutTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        old = os.environ.get("B2FA_HOME")
        os.environ["B2FA_HOME"] = self.home.name
        self.addCleanup(lambda: os.environ.pop("B2FA_HOME") if old is None else os.environ.update(B2FA_HOME=old))
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest("no display")
        self.addCleanup(self.root.destroy)
        self.root.withdraw()

    def test_about_is_short_and_shows_version_author_and_licence(self):
        dlg = appmod.AboutDialog(self.root)
        self.addCleanup(dlg.destroy)
        text = "\n".join(all_text(dlg))
        self.assertIn(APP_NAME, text)
        self.assertIn("Version " + __version__, text)
        self.assertIn(AUTHOR, text)
        self.assertIn("GNU General Public License", text)
        self.assertNotIn("Claude", text)


if __name__ == "__main__":
    unittest.main()
