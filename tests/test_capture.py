"""Screen capture protection tests (Windows 10 2004+ with a display)."""

import sys
import time
import tkinter as tk
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from b2fa import captureguard  # noqa: E402


@unittest.skipUnless(captureguard.supported(), "needs Windows 10 build 19041 or later")
class CaptureGuardTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest("no display")
        self.addCleanup(self.root.destroy)
        self.root.geometry("300x200+50+50")
        self.root.update()
        self.guard = captureguard.CaptureGuard(self.root)

    def test_enable_excludes_the_window_and_adds_a_shield(self):
        self.assertFalse(captureguard.is_excluded(self.root))
        self.assertTrue(self.guard.enable())
        self.assertTrue(captureguard.is_excluded(self.root))
        self.assertIsNotNone(self.guard.shield)
        self.assertEqual(self.guard.shield.winfo_children()[0].winfo_children()[0].cget("text"),
                         captureguard.MESSAGE)

    def _pump(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self.root.update()
            time.sleep(0.02)

    def test_shield_is_hidden_while_the_window_moves(self):
        self.guard.enable()
        self._pump(0.4)
        self.assertEqual(self.guard.shield.state(), "normal")
        self.root.geometry("+200+160")
        seen = set()
        for _ in range(5):  # the move reaches Tk a moment later, and the shield comes back after 150 ms
            self.root.update()
            seen.add(self.guard.shield.state())
            time.sleep(0.02)
        self.assertIn("withdrawn", seen)  # no black strip behind a moving window
        self._pump(0.4)
        self.assertEqual(self.guard.shield.state(), "normal")     # and back once it stopped

    def _inside_visible_window(self):
        """True when the shield lies inside what the user sees, so no black rim shows around the app."""
        import ctypes
        from ctypes import wintypes
        rect = wintypes.RECT()
        ctypes.windll.dwmapi.DwmGetWindowAttribute(
            wintypes.HWND(captureguard.toplevel_hwnd(self.root)), 9, ctypes.byref(rect), ctypes.sizeof(rect))
        s = self.guard.shield
        return (s.winfo_x() >= rect.left and s.winfo_y() >= rect.top
                and s.winfo_x() + s.winfo_width() <= rect.right
                and s.winfo_y() + s.winfo_height() <= rect.bottom), rect

    def test_shield_follows_the_window_without_a_rim(self):
        self.guard.enable()
        self.root.geometry("320x240+120+90")
        self._pump(0.5)
        self.assertEqual(self.guard.shield.state(), "normal")
        ok, rect = self._inside_visible_window()
        self.assertTrue(ok, "shield sticks out of the visible window")
        # and it is still close to the window, so a capture shows (almost) all of it
        self.assertLessEqual(abs(self.guard.shield.winfo_x() - rect.left), 4)
        self.assertLessEqual(abs(self.guard.shield.winfo_y() - rect.top), 4)

    def test_disable_restores_capture_and_removes_the_shield(self):
        self.guard.enable()
        self.guard.disable()
        self.assertFalse(captureguard.is_excluded(self.root))
        self.assertIsNone(self.guard.shield)

    def test_dialogs_are_excluded_only_while_enabled(self):
        dlg = tk.Toplevel(self.root)
        dlg.update_idletasks()
        self.guard.protect(dlg)  # not enabled yet: nothing happens
        self.assertFalse(captureguard.is_excluded(dlg))
        self.guard.enable()
        self.guard.protect(dlg)
        self.assertTrue(captureguard.is_excluded(dlg))

    def test_minimised_window_hides_the_shield(self):
        self.guard.enable()
        self.root.iconify()
        self.root.update()
        self.assertEqual(self.guard.shield.state(), "withdrawn")


if __name__ == "__main__":
    unittest.main()
