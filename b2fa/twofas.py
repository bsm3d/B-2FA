"""Read and write 2FAS backup files (.2fas).

Format, taken from the 2FAS Android and iOS sources:
- a JSON object with services, groups, updatedAt, schemaVersion, appOrigin...
- plain backup: "services" holds the list.
- encrypted backup: "services" is empty, "servicesEncrypted" and "reference" are strings
  "base64(ciphertext+tag):base64(salt):base64(iv)". Key = PBKDF2-HMAC-SHA256(password, salt,
  10000 iterations, 32 bytes). Cipher = AES-256-GCM, no associated data. The salt is 256 bytes,
  shared by both fields. "reference" decrypts to a fixed string, which proves the password.

The 10 000 iterations are imposed by the format: it is a weak point for short passwords, which is
why B-2FA only uses it for the manual export, with a long password.
"""

import base64
import hashlib
import json
import os
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REFERENCE = (
    "tRViSsLKzd86Hprh4ceC2OP7xazn4rrt4xhfEUbOjxLX8Rc3mkISXE0lWbmnWfggogbBJhtYgpK6fMl1D6m"
    "tsy92R3HkdGfwuXbzLebqVFJsR7IZ2w58t938iymwG4824igYy1wi6n2WDpO1Q1P69zwJGs2F5a1qP4MyIiD"
    "SD7NCV2OvidXQCBnDlGfmz0f1BQySRkkt4ryiJeCjD2o4QsveJ9uDBUn8ELyOrESv5R5DMDkD4iAF8TXU7Ky"
    "oJujd"
)
SCHEMA_VERSION = 4
PBKDF2_ITERATIONS = 10_000
SALT_BYTES = 256
IV_BYTES = 12
MIN_SALT_BYTES = 8
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_SERVICES = 10_000


class BackupError(Exception):
    """The file is not a usable 2FAS backup."""


class WrongPassword(BackupError):
    """Bad backup password (or corrupted data)."""


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, 32)


def _split(field) -> tuple[bytes, bytes, bytes]:
    if not isinstance(field, str):
        raise BackupError("Unexpected encrypted field")
    parts = field.split(":")
    if len(parts) != 3:
        raise BackupError("Unexpected encrypted field layout")
    try:
        data, salt, iv = (base64.b64decode(p, validate=True) for p in parts)
    except Exception as exc:
        raise BackupError("Encrypted field is not valid base64") from exc
    if len(data) <= 16:
        raise BackupError("Encrypted field is too short")
    if len(iv) != IV_BYTES:
        raise BackupError("Unexpected initialisation vector size")
    if len(salt) < MIN_SALT_BYTES:
        raise BackupError("Unexpected salt size")
    return data, salt, iv


def _decrypt_field(field, password: str) -> bytes:
    data, salt, iv = _split(field)
    try:
        return AESGCM(derive_key(password, salt)).decrypt(iv, data, None)
    except InvalidTag as exc:
        raise WrongPassword("Wrong password") from exc
    except ValueError as exc:
        raise BackupError("The encrypted data is damaged") from exc


def _encrypt_field(plain: bytes, key: bytes, salt: bytes) -> str:
    iv = os.urandom(IV_BYTES)
    data = AESGCM(key).encrypt(iv, plain, None)
    return ":".join(base64.b64encode(x).decode("ascii") for x in (data, salt, iv))


def _reject_constant(name):
    raise ValueError("Unexpected JSON constant " + name)


def read_backup(path: str) -> dict:
    """Load a backup file as a dict (still encrypted if it was exported with a password)."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            raise BackupError("File is too big to be a 2FAS backup")
        with open(path, "r", encoding="utf-8-sig") as fh:
            content = json.load(fh, parse_constant=_reject_constant)
    except BackupError:
        raise
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        raise BackupError("Cannot read this file as a backup (%s)" % type(exc).__name__) from exc
    if not isinstance(content, dict) or not (
            "services" in content or "servicesEncrypted" in content):
        raise BackupError("This does not look like a 2FAS backup")
    if content.get("servicesEncrypted") and not content.get("reference"):
        raise BackupError("The encrypted backup has no reference field (damaged file)")
    return content


def is_encrypted(content: dict) -> bool:
    return bool(content.get("reference")) and bool(content.get("servicesEncrypted"))


def decrypt_backup(content: dict, password: str) -> dict:
    """Return the backup with services in clear. Raises WrongPassword."""
    if not is_encrypted(content):
        services = content.get("services")
        if not isinstance(services, list):
            raise BackupError("The services of this backup are not a list")
        return content
    reference = _decrypt_field(content["reference"], password)
    if reference.decode("utf-8", "replace") != REFERENCE:
        raise WrongPassword("Wrong password")
    try:
        services = json.loads(_decrypt_field(content["servicesEncrypted"], password),
                              parse_constant=_reject_constant)
    except (ValueError, RecursionError, MemoryError) as exc:
        raise BackupError("The decrypted services are not valid JSON") from exc
    if not isinstance(services, list):
        raise BackupError("Decrypted services are not a list")
    out = dict(content)
    out["services"] = services
    out["servicesEncrypted"] = None
    out["reference"] = None
    return out


def build_backup(services: list, groups: list, password: str) -> dict:
    """Create an encrypted backup dict ready to be written as a .2fas file."""
    salt = os.urandom(SALT_BYTES)
    key = derive_key(password, salt)
    plain_services = json.dumps(services, ensure_ascii=False, separators=(",", ":"))
    return {
        "services": [],
        "groups": groups,
        "updatedAt": int(time.time() * 1000),
        "schemaVersion": SCHEMA_VERSION,
        "appVersionCode": 0,
        "appVersionName": "B-2FA",
        "appOrigin": "android",
        "servicesEncrypted": _encrypt_field(plain_services.encode("utf-8"), key, salt),
        "reference": _encrypt_field(REFERENCE.encode("utf-8"), key, salt),
    }


def write_backup(path: str, services: list, groups: list, password: str) -> None:
    content = build_backup(services, groups, password)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(content, fh, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
