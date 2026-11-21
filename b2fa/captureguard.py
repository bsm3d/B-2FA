"""Screen capture protection (Windows 10 build 19041 and later).

The window is excluded from every capture the system makes (Print Screen, Snipping Tool, screen
sharing, recorders, Windows Recall) with SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE).
Windows then leaves the window out of the picture, which would only show whatever is behind it.
So a "shield" window sits exactly behind the real one: you never see it (the real window covers
it), but a capture shows it instead, with the text "No screen capture allowed".

Limits: a photo of the screen, or a capture made by something running inside the same session
with enough rights to read another process, is not stopped by this.
"""

import ctypes
import sys
import tkinter as tk
from ctypes import wintypes

WDA_NONE = 0x0
WDA_EXCLUDEFROMCAPTURE = 0x11
MIN_BUILD = 19041
MESSAGE = "No screen capture allowed"
SUBMESSAGE = "B-2FA hides its window from screenshots, recordings and screen sharing."


def supported() -> bool:
    return sys.platform == "win32" and sys.getwindowsversion().build >= MIN_BUILD


def _user32():
    u = ctypes.WinDLL("user32", use_last_error=True)
    u.GetParent.argtypes, u.GetParent.restype = [wintypes.HWND], wintypes.HWND
    u.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
    u.SetWindowDisplayAffinity.restype = wintypes.BOOL
    u.GetWindowDisplayAffinity.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    u.GetWindowDisplayAffinity.restype = wintypes.BOOL
    return u


def toplevel_hwnd(widget) -> int:
    """The real top-level window handle of a Tk window (Tk wraps its client area in a frame)."""
    u = _user32()
    return u.GetParent(widget.winfo_id()) or widget.winfo_id()


def set_excluded(widget, on: bool = True) -> bool:
    if not supported():
        return False
    try:
        widget.update_idletasks()
        return bool(_user32().SetWindowDisplayAffinity(
            toplevel_hwnd(widget), WDA_EXCLUDEFROMCAPTURE if on else WDA_NONE))
    except Exception:
        return False


def is_excluded(widget) -> bool:
    if not supported():
        return False
    value = wintypes.DWORD(0)
    try:
        ok = _user32().GetWindowDisplayAffinity(toplevel_hwnd(widget), ctypes.byref(value))
    except Exception:
        return False
    return bool(ok) and value.value == WDA_EXCLUDEFROMCAPTURE


class CaptureGuard:
    """Protects the main window and keeps the shield right behind it."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.enabled = False
        self.shield: tk.Toplevel | None = None
        self._geo = ""
        self._settle_job = None
        root.bind("<Configure>", self._sync, add="+")
        root.bind("<Map>", self._sync, add="+")
        root.bind("<Unmap>", self._hide, add="+")

    # ---- on / off ----------------------------------------------------------
    def enable(self) -> bool:
        if not supported():
            return False
        if not set_excluded(self.root, True):
            return False
        self.enabled = True
        if self.shield is None:
            self.shield = self._make_shield()
        self._sync()
        return True

    def disable(self) -> None:
        self.enabled = False
        set_excluded(self.root, False)
        if self.shield is not None:
            self.shield.destroy()
            self.shield = None

    def protect(self, window) -> None:
        """Dialogs show secrets too: exclude them as well (no shield needed)."""
        if self.enabled:
            set_excluded(window, True)

    # ---- shield ------------------------------------------------------------
    def _make_shield(self) -> tk.Toplevel:
        self._geo = ""
        s = tk.Toplevel(self.root)
        s.withdraw()
        s.overrideredirect(True)          # no frame, no taskbar button, never takes focus
        s.configure(bg="#000000")
        box = tk.Frame(s, bg="#000000")
        box.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(box, text=MESSAGE, bg="#000000", fg="#ffffff", font=("Segoe UI Light", 22)).pack()
        tk.Label(box, text=SUBMESSAGE, bg="#000000", fg="#e10600", font=("Segoe UI", 9),
                 wraplength=380).pack(pady=(10, 0))
        return s

    def _hide(self, event=None) -> None:
        if self.shield is not None and (event is None or event.widget is self.root):
            self.shield.withdraw()

    def _sync(self, event=None) -> None:
        """Put the shield exactly under the window (frame and title bar included)."""
        if not self.enabled or self.shield is None:
            return
        if event is not None and event.widget is not self.root:
            return
        try:
            if self.root.state() in ("iconic", "withdrawn"):
                self.shield.withdraw()
                return
            x, y, w, h = self._visible_bounds()
            geo = "%dx%d+%d+%d" % (w, h, x, y)
            if geo != self._geo:
                # The window is moving or being resized. The shield follows one frame late, so a
                # black strip showed on the trailing side and the app seemed to blink. Hide it
                # while the window moves and bring it back 150 ms after the last move.
                if self._geo:
                    self.shield.withdraw()
                self._geo = geo
                self.shield.geometry(geo)
                if self._settle_job is not None:
                    self.root.after_cancel(self._settle_job)
                self._settle_job = self.root.after(150, self._settle)
                return
            if self._settle_job is None:   # same place and no move in progress
                self._settle()
        except tk.TclError:
            pass

    def _settle(self) -> None:
        self._settle_job = None
        if not self.enabled or self.shield is None:
            return
        try:
            if self.root.state() in ("iconic", "withdrawn"):
                return
            if self.shield.state() != "normal":
                self.shield.deiconify()
            self.shield.lower(self.root)   # always BELOW the real window
        except tk.TclError:
            pass

    def _visible_bounds(self):
        """The part of the window the user really sees, as (x, y, w, h), shrunk by 2 px.

        Windows 10 gives a window invisible resize borders (about 7 px) that Tk counts in its
        frame, so a shield cut to the Tk frame showed as a black rim around the app. DWM knows the
        visible rectangle (DWMWA_EXTENDED_FRAME_BOUNDS); the 2 px margin hides rounding."""
        r = self.root
        try:
            rect = wintypes.RECT()
            hr = ctypes.windll.dwmapi.DwmGetWindowAttribute(
                wintypes.HWND(toplevel_hwnd(r)), 9, ctypes.byref(rect), ctypes.sizeof(rect))
            if hr == 0 and rect.right > rect.left and rect.bottom > rect.top:
                m = 2
                return (rect.left + m, rect.top + m,
                        rect.right - rect.left - 2 * m, rect.bottom - rect.top - 2 * m)
        except Exception:
            pass
        return r.winfo_rootx() + 2, r.winfo_rooty() + 2, max(1, r.winfo_width() - 4), max(1, r.winfo_height() - 4)

    def keep_behind(self) -> None:
        """Called from the app's timer: lower the shield only if it is no longer right under the
        window. Lowering it blindly four times a second made the window blink."""
        if self.enabled and self.shield is not None:
            try:
                if self.shield.state() != "normal":
                    return
                u = _user32()
                u.GetWindow.argtypes, u.GetWindow.restype = [wintypes.HWND, wintypes.UINT], wintypes.HWND
                below = u.GetWindow(toplevel_hwnd(self.root), 2)  # GW_HWNDNEXT
                if below != toplevel_hwnd(self.shield):
                    self.shield.lower(self.root)
            except tk.TclError:
                pass
