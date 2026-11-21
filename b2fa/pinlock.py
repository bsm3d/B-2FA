"""Quick unlock with a short PIN, on top of the strong master password.

A 4 digit PIN has only 10 000 values, so it can never protect a file that someone can copy:
anybody could try every PIN offline in minutes. This module therefore does NOT protect the
vault with the PIN. The vault stays protected by the master password. The PIN only unlocks a
small side file that holds the master password wrapped by Windows DPAPI:

- DPAPI ties the file to this Windows account on this PC (a copy on another machine or another
  account is useless), and the PIN (stretched with scrypt) is added as DPAPI entropy.
- Attempts are counted before each try and the side file is deleted after MAX_ATTEMPTS wrong
  PINs, after which only the master password works.

What it does not stop: malware already running as you, which can read the side file and try the
PINs itself. The same malware could also read the screen and the keyboard, so the master password
remains the real protection. The PIN is a convenience for an unattended PC, not a second lock.
"""

import base64
import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import paths

MAX_ATTEMPTS = 5
PIN_MIN, PIN_MAX = 4, 8
CRYPTPROTECT_UI_FORBIDDEN = 0x1


class PinError(Exception):
    pass


class PinDisabled(PinError):
    """No PIN is set (or it was wiped): use the master password."""


class WrongPin(PinError):
    def __init__(self, attempts_left: int):
        super().__init__("Wrong PIN. %d tr%s left." % (attempts_left, "y" if attempts_left == 1 else "ies"))
        self.attempts_left = attempts_left


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt32():
    c = ctypes.WinDLL("crypt32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    ptr = ctypes.POINTER(_Blob)
    c.CryptProtectData.argtypes = [ptr, wintypes.LPCWSTR, ptr, ctypes.c_void_p, ctypes.c_void_p,
                                   wintypes.DWORD, ptr]
    c.CryptProtectData.restype = wintypes.BOOL
    c.CryptUnprotectData.argtypes = [ptr, ctypes.c_void_p, ptr, ctypes.c_void_p, ctypes.c_void_p,
                                     wintypes.DWORD, ptr]
    c.CryptUnprotectData.restype = wintypes.BOOL
    k.LocalFree.argtypes, k.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    return c, k


def _make_blob(data: bytes):
    buf = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(data or b"\0")
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))), buf


def _take(blob: _Blob, k) -> bytes:
    out = ctypes.string_at(blob.pbData, blob.cbData)
    k.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))
    return out


def _protect(data: bytes, entropy: bytes) -> bytes:
    c, k = _crypt32()
    din, keep1 = _make_blob(data)
    ent, keep2 = _make_blob(entropy)
    out = _Blob()
    if not c.CryptProtectData(ctypes.byref(din), "B-2FA PIN", ctypes.byref(ent), None, None,
                              CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise PinError("Windows could not protect the PIN data (error %d)" % ctypes.get_last_error())
    return _take(out, k)


def _unprotect(data: bytes, entropy: bytes) -> bytes | None:
    c, k = _crypt32()
    din, keep1 = _make_blob(data)
    ent, keep2 = _make_blob(entropy)
    out = _Blob()
    if not c.CryptUnprotectData(ctypes.byref(din), None, ctypes.byref(ent), None, None,
                                CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        return None
    return _take(out, k)


def _entropy(pin: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(pin.encode("utf-8"))


def check_pin_format(pin: str) -> None:
    if not (pin.isascii() and pin.isdigit() and PIN_MIN <= len(pin) <= PIN_MAX):
        raise PinError("The PIN must be %d to %d digits" % (PIN_MIN, PIN_MAX))


class PinStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else paths.data_dir() / "pin.b2fa"

    @staticmethod
    def available() -> bool:
        return sys.platform == "win32"

    @property
    def enabled(self) -> bool:
        return self.available() and self.path.exists()

    def _write(self, doc: dict) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def disable(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def enable(self, pin: str, master_password: str) -> None:
        if not self.available():
            raise PinError("A PIN needs Windows")
        check_pin_format(pin)
        salt = os.urandom(16)
        blob = _protect(master_password.encode("utf-8"), _entropy(pin, salt))
        self._write({"version": 1, "salt": base64.b64encode(salt).decode(),
                     "blob": base64.b64encode(blob).decode(), "attempts_left": MAX_ATTEMPTS})

    def unlock(self, pin: str) -> str:
        """Return the master password for a correct PIN. Counts every attempt."""
        if not self.enabled:
            raise PinDisabled("No PIN is set")
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            salt, blob = base64.b64decode(doc["salt"]), base64.b64decode(doc["blob"])
            left = int(doc["attempts_left"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.disable()
            raise PinDisabled("The PIN file is damaged and was removed. Use the master password.") from exc
        if left <= 0:
            self.disable()
            raise PinDisabled("Too many wrong PINs. Use the master password.")
        doc["attempts_left"] = left - 1  # counted BEFORE the try, so killing the app does not help
        self._write(doc)
        try:
            check_pin_format(pin)
            secret = _unprotect(blob, _entropy(pin, salt))
        except PinError:
            secret = None
        if secret is None:
            if left - 1 <= 0:
                self.disable()
                raise PinDisabled("Too many wrong PINs. Use the master password.")
            raise WrongPin(left - 1)
        doc["attempts_left"] = MAX_ATTEMPTS
        self._write(doc)
        return secret.decode("utf-8")
