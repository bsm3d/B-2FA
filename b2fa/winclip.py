"""Windows clipboard helpers.

Tk's clipboard cannot tell Windows to keep a value out of the clipboard history (Win+V) and the
cloud clipboard. set_text() can: it adds the three documented opt-out formats. Everything falls
back gracefully (returns False) so the caller can use Tk's clipboard instead.
"""

import ctypes
import sys
import time
from ctypes import wintypes

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
OPT_OUT_FORMATS = ("ExcludeClipboardContentFromMonitorProcessing",
                   "CanIncludeInClipboardHistory",
                   "CanUploadToCloudClipboard")


def _apis():
    u = ctypes.WinDLL("user32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    u.OpenClipboard.argtypes, u.OpenClipboard.restype = [wintypes.HWND], wintypes.BOOL
    u.CloseClipboard.argtypes, u.CloseClipboard.restype = [], wintypes.BOOL
    u.EmptyClipboard.argtypes, u.EmptyClipboard.restype = [], wintypes.BOOL
    u.SetClipboardData.argtypes, u.SetClipboardData.restype = [wintypes.UINT, ctypes.c_void_p], ctypes.c_void_p
    u.RegisterClipboardFormatW.argtypes, u.RegisterClipboardFormatW.restype = [wintypes.LPCWSTR], wintypes.UINT
    k.GlobalAlloc.argtypes, k.GlobalAlloc.restype = [wintypes.UINT, ctypes.c_size_t], ctypes.c_void_p
    k.GlobalLock.argtypes, k.GlobalLock.restype = [ctypes.c_void_p], ctypes.c_void_p
    k.GlobalUnlock.argtypes, k.GlobalUnlock.restype = [ctypes.c_void_p], wintypes.BOOL
    k.GlobalFree.argtypes, k.GlobalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    return u, k


def _open(u) -> bool:
    for _ in range(20):
        if u.OpenClipboard(None):
            return True
        time.sleep(0.02)
    return False


def _put(u, k, fmt: int, data: bytes) -> bool:
    handle = k.GlobalAlloc(GMEM_MOVEABLE, len(data))
    if not handle:
        return False
    ptr = k.GlobalLock(handle)
    if not ptr:
        k.GlobalFree(handle)
        return False
    ctypes.memmove(ptr, data, len(data))
    k.GlobalUnlock(handle)
    if not u.SetClipboardData(fmt, handle):
        k.GlobalFree(handle)
        return False
    return True


def set_text(text: str) -> bool:
    """Put text on the clipboard, excluded from history and cloud sync. False if it failed."""
    if sys.platform != "win32":
        return False
    try:
        u, k = _apis()
        if not _open(u):
            return False
        try:
            u.EmptyClipboard()
            if not _put(u, k, CF_UNICODETEXT, (text + "\0").encode("utf-16-le")):
                return False
            for name in OPT_OUT_FORMATS:
                fmt = u.RegisterClipboardFormatW(name)
                if fmt:
                    _put(u, k, fmt, (0).to_bytes(4, "little"))
            return True
        finally:
            u.CloseClipboard()
    except Exception:
        return False


def clear() -> bool:
    if sys.platform != "win32":
        return False
    try:
        u, _ = _apis()
        if not _open(u):
            return False
        try:
            return bool(u.EmptyClipboard())
        finally:
            u.CloseClipboard()
    except Exception:
        return False
