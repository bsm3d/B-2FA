"""The local vault: accounts stored in 2FAS service format, encrypted with a master password.

File: vault.b2fa (JSON header + AES-256-GCM payload, key from scrypt, header bound to the
ciphertext as associated data). Writes are atomic. The previous version is kept as
vault.b2fa.bak. Automatic backups are copies of the vault file (so they keep the scrypt
protection), written a few seconds after a change. Only the manual export produces a .2fas
file (PBKDF2 with 10 000 iterations, imposed by the 2FAS format), with a long password.

Anything that copies the old data (the .bak and the automatic backups) is purged when the
master password changes or an account is deleted, so a stale copy cannot outlive the change.
"""

import base64
import contextlib
import copy
import json
import os
import shutil
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import paths
from .totp import OtpError, check_secret, validate_params

FORMAT = "b2fa-vault"
VERSION = 2
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 17, 8, 1          # 128 MiB
MIN_N, MAX_N = 2 ** 14, 2 ** 18
MAX_KDF_MEMORY = 256 * 1024 * 1024
MIN_MASTER_CHARS = 12
MIN_EXPORT_CHARS = 12
KEEP_BACKUPS = 10
BACKUP_DELAY = 15.0  # seconds: coalesce a burst of changes into one backup
MAX_TEXT = 256
MAX_SERVICES = 10_000
DEFAULT_ICON_COLLECTION = "a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad"
AUTO_PREFIX = "B-2FA-auto-"


class VaultError(Exception):
    pass


class WrongMasterPassword(VaultError):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _kdf(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def _check_kdf_params(n, r, p) -> None:
    """Refuse parameters that would exhaust memory or time (the file is untrusted input)."""
    ok = all(isinstance(x, int) and not isinstance(x, bool) for x in (n, r, p))
    ok = ok and n & (n - 1) == 0 and MIN_N <= n <= MAX_N and 1 <= r <= 16 and 1 <= p <= 4
    ok = ok and 128 * n * r * p <= MAX_KDF_MEMORY
    if not ok:
        raise VaultError("The vault file has unsupported key settings")


def _aad(version: int, kdf: dict) -> bytes:
    if version == 1:  # first release: constant associated data
        return b"b2fa-vault-1"
    head = {"format": FORMAT, "version": version,
            "kdf": {k: kdf[k] for k in ("name", "n", "r", "p", "salt")}}
    return json.dumps(head, sort_keys=True, separators=(",", ":")).encode("ascii")


def now_ms() -> int:
    return int(time.time() * 1000)


def check_master_password(password: str) -> None:
    if len(password) < MIN_MASTER_CHARS:
        raise VaultError("The master password needs at least %d characters" % MIN_MASTER_CHARS)


def _text(value, default="") -> str:
    if value is None:
        return default
    return str(value)[:MAX_TEXT]


def _position(service) -> int:
    try:
        pos = (service.get("order") or {}).get("position", 0)
        return pos if isinstance(pos, int) and not isinstance(pos, bool) else 0
    except AttributeError:
        return 0


def make_service(name: str, secret: str, issuer: str = "", account: str = "",
                 token_type: str = "TOTP", digits: int = 6, period: int = 30,
                 algorithm: str = "SHA1", counter: int = 0, position: int = 0) -> dict:
    """Build a complete 2FAS service entry (all fields the phone apps expect)."""
    secret = check_secret(secret)
    params = validate_params(token_type, digits, period, algorithm, counter)
    issuer, account = _text(issuer).strip(), _text(account).strip()
    name = _text(name).strip() or issuer or account or "Account"
    label = ("%s:%s" % (issuer, account)) if issuer and account else (account or issuer or name)
    kind = params["type"]
    return {
        "name": name,
        "secret": secret,
        "updatedAt": now_ms(),
        "type": None,
        "serviceTypeID": None,
        "otp": {
            "link": None,
            "label": label,
            "account": account,
            "issuer": issuer or name,
            "digits": params["digits"],
            "period": params["period"] if kind != "HOTP" else None,
            "algorithm": params["algorithm"],
            "counter": params["counter"] if kind == "HOTP" else None,
            "tokenType": kind,
            "source": "Manual",
        },
        "order": {"position": position},
        "badge": None,
        "icon": {
            "selected": "Label",
            "brand": None,
            "label": {"text": name[:2].upper(), "backgroundColor": "Indigo"},
            "iconCollection": {"id": DEFAULT_ICON_COLLECTION},
        },
        "groupId": None,
    }


def normalize_service(raw) -> dict:
    """Validate a service coming from an imported file. Raises OtpError if unusable.

    Types and ranges are enforced; fields we do not use are kept when they have the right shape.
    """
    if not isinstance(raw, dict):
        raise OtpError("Entry is not an object")
    s = dict(raw)
    s["secret"] = check_secret(raw.get("secret"))
    otp = dict(raw["otp"]) if isinstance(raw.get("otp"), dict) else {}
    params = validate_params(otp.get("tokenType") or "TOTP", otp.get("digits") or 6,
                             otp.get("period") or 30, otp.get("algorithm") or "SHA1",
                             otp.get("counter") or 0)
    otp["tokenType"], otp["digits"], otp["algorithm"] = params["type"], params["digits"], params["algorithm"]
    otp["period"] = params["period"] if params["type"] != "HOTP" else otp.get("period")
    otp["counter"] = params["counter"] if params["type"] == "HOTP" else otp.get("counter")
    for key in ("link", "label", "account", "issuer", "source"):
        otp[key] = None if otp.get(key) is None else _text(otp[key])
    s["otp"] = otp
    s["name"] = _text(raw.get("name"), "Account") or "Account"
    s["order"] = {"position": _position(raw)}
    for key in ("icon", "badge"):
        if not isinstance(raw.get(key), dict):
            s[key] = None
    if s.get("icon") is None:
        s["icon"] = make_service(s["name"], s["secret"])["icon"]
    for key in ("groupId", "serviceTypeID", "type"):
        if not isinstance(raw.get(key), str):
            s[key] = None
    ts = raw.get("updatedAt")
    s["updatedAt"] = ts if isinstance(ts, int) and not isinstance(ts, bool) else now_ms()
    return s


def normalize_group(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not isinstance(raw.get("name"), str):
        return None
    ts = raw.get("updatedAt")
    return {"id": raw["id"][:64], "name": raw["name"][:MAX_TEXT],
            "isExpanded": bool(raw.get("isExpanded", False)),
            "updatedAt": ts if isinstance(ts, int) and not isinstance(ts, bool) else 0}


class Vault:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else paths.vault_path()
        self.backups_dir = paths.backups_dir() if path is None else self.path.parent / "backups"
        self._key: bytes | None = None
        self._password: str | None = None
        self._header: dict | None = None
        self._sig = None
        self._backup_due: float | None = None
        self.last_backup_error = ""
        self.services: list[dict] = []
        self.groups: list[dict] = []

    # ---- state -------------------------------------------------------------
    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def lock(self) -> None:
        self.flush_backup(0)
        self._key = None
        self._password = None
        self._sig = None
        self.services = []
        self.groups = []

    def master_password(self) -> str:
        """The current master password (only for wrapping it behind the PIN)."""
        if not self.unlocked:
            raise VaultError("The vault is locked")
        return self._password

    def check_password(self, password: str) -> bool:
        return self.unlocked and password == self._password

    def _file_sig(self):
        try:
            st = self.path.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    @contextlib.contextmanager
    def _rollback(self):
        """Undo in-memory changes if the write to disk fails."""
        services, groups = copy.deepcopy(self.services), copy.deepcopy(self.groups)
        try:
            yield
        except BaseException:
            self.services, self.groups = services, groups
            raise

    # ---- create / unlock ---------------------------------------------------
    def _derive(self, password: str) -> tuple[dict, bytes]:
        salt = os.urandom(16)
        header = {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)}
        return header, _kdf(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)

    def create(self, password: str) -> None:
        if self.exists:
            raise VaultError("A vault already exists")
        check_master_password(password)
        self._header, self._key = self._derive(password)
        self._password = password
        self.services, self.groups = [], []
        try:
            self.save(backup=False)
        except BaseException:
            self.lock()
            raise

    def unlock(self, password: str) -> None:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict) or doc.get("format") != FORMAT:
                raise VaultError("This file is not a B-2FA vault")
            version = doc.get("version")
            if version not in (1, VERSION):
                raise VaultError("This vault was made by a newer B-2FA")
            kdf = doc["kdf"]
            n, r, p = kdf["n"], kdf["r"], kdf["p"]
            _check_kdf_params(n, r, p)
            salt = _unb64(kdf["salt"])
            key = _kdf(password, salt, n, r, p)
            plain = AESGCM(key).decrypt(_unb64(doc["nonce"]), _unb64(doc["data"]), _aad(version, kdf))
            data = json.loads(plain)
            services, groups = data.get("services", []), data.get("groups", [])
            if not isinstance(services, list) or not isinstance(groups, list):
                raise ValueError("bad payload")
        except InvalidTag as exc:
            raise WrongMasterPassword("Wrong master password") from exc
        except VaultError:
            raise
        except (OSError, KeyError, ValueError, TypeError, RecursionError) as exc:
            raise VaultError("The vault file is damaged (%s). Your backups are in %s"
                             % (type(exc).__name__, self.backups_dir)) from exc
        self._header = {k: kdf[k] for k in ("name", "n", "r", "p", "salt")}
        self._key, self._password = key, password
        self._sig = self._file_sig()
        self.services = [s for s in services if isinstance(s, dict)]
        self.groups = [g for g in groups if isinstance(g, dict)]
        for s in self.services:
            s["_id"] = uuid.uuid4().hex
        if version != VERSION or n < SCRYPT_N:
            self._upgrade(password)

    def _upgrade(self, password: str) -> None:
        """Move an older vault to the current format and key settings, then drop old copies."""
        previous = (self._header, self._key)
        self._header, self._key = self._derive(password)
        try:
            self.save(backup=False)
        except BaseException:
            self._header, self._key = previous
            raise
        self._purge_copies()
        self._backup_due = time.monotonic()

    # ---- save --------------------------------------------------------------
    def save(self, backup: bool = True) -> None:
        if not self.unlocked:
            raise VaultError("The vault is locked")
        payload = json.dumps({"services": self.services, "groups": self.groups},
                             ensure_ascii=False).encode("utf-8")
        nonce = os.urandom(12)
        kdf = dict(self._header)
        doc = {
            "format": FORMAT, "version": VERSION, "kdf": kdf,
            "nonce": _b64(nonce),
            "data": _b64(AESGCM(self._key).encrypt(nonce, payload, _aad(VERSION, kdf))),
        }
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
                fh.flush()
                os.fsync(fh.fileno())
            if self.path.exists():
                if self._sig is not None and self._file_sig() != self._sig:
                    raise VaultError("The vault was changed by another program. "
                                     "Close and reopen B-2FA before editing it.")
                try:
                    shutil.copy2(self.path, self.path.with_name(self.path.name + ".bak"))
                except OSError:
                    pass
            os.replace(tmp, self.path)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
        self._sig = self._file_sig()
        if backup and self._backup_due is None:
            self._backup_due = time.monotonic()

    def change_password(self, old: str, new: str) -> None:
        if not self.check_password(old):
            raise WrongMasterPassword("Wrong master password")
        check_master_password(new)
        previous = (self._header, self._key, self._password)
        self._header, self._key = self._derive(new)
        self._password = new
        try:
            self.save(backup=False)
        except BaseException:
            self._header, self._key, self._password = previous
            raise
        self._purge_copies()
        self._backup_due = time.monotonic()
        self.flush_backup(0)

    # ---- backups -----------------------------------------------------------
    def _auto_backups(self) -> list[Path]:
        return sorted(self.backups_dir.glob(AUTO_PREFIX + "*.b2fa"), key=lambda p: p.stat().st_mtime)

    def _purge_copies(self) -> None:
        """Delete every copy that may hold older data: the .bak and all automatic backups,
        including the .2fas ones written by the first release."""
        doomed = [self.path.with_name(self.path.name + ".bak")]
        if self.backups_dir.exists():
            doomed += self.backups_dir.glob(AUTO_PREFIX + "*.b2fa")
            doomed += self.backups_dir.glob("B-2FA-????????-??????.2fas")
        for f in doomed:
            try:
                f.unlink()
            except OSError:
                pass

    def flush_backup(self, delay: float = BACKUP_DELAY) -> None:
        """Write the pending automatic backup once `delay` seconds passed since the first change."""
        if self._backup_due is None or not self.unlocked:
            return
        if time.monotonic() - self._backup_due < delay:
            return
        self._backup_due = None
        try:
            self.auto_backup()
            self.last_backup_error = ""
        except OSError as exc:
            self.last_backup_error = str(exc)

    def auto_backup(self) -> Path | None:
        """Copy the vault file into the backups folder (encrypted, same scrypt protection)."""
        if not self.services or not self.exists:
            return None
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target, i = self.backups_dir / ("%s%s.b2fa" % (AUTO_PREFIX, stamp)), 1
        while target.exists():
            target = self.backups_dir / ("%s%s-%d.b2fa" % (AUTO_PREFIX, stamp, i))
            i += 1
        tmp = target.with_suffix(".tmp")
        shutil.copy2(self.path, tmp)
        os.replace(tmp, target)
        for old in self._auto_backups()[:-KEEP_BACKUPS]:
            if old != target:
                try:
                    old.unlink()
                except OSError:
                    pass
        return target

    def exportable_services(self) -> list[dict]:
        """Services as 2FAS expects them: no internal keys, positions renumbered."""
        out = []
        for i, s in enumerate(self.sorted_services()):
            clean = {k: v for k, v in s.items() if not k.startswith("_")}
            clean["order"] = {"position": i}
            out.append(clean)
        return out

    def export_backup(self, path: str, password: str) -> None:
        """Write a .2fas file the 2FAS phone apps can import."""
        from . import twofas
        if len(password) < MIN_EXPORT_CHARS:
            raise VaultError("The backup password needs at least %d characters" % MIN_EXPORT_CHARS)
        if self.check_password(password):
            raise VaultError("Use a password different from the master password: the .2fas "
                             "format protects it far less than the vault does")
        twofas.write_backup(str(path), self.exportable_services(), self.groups, password)

    # ---- accounts ----------------------------------------------------------
    def sorted_services(self) -> list[dict]:
        return sorted(self.services, key=_position)

    def _next_position(self) -> int:
        return max((_position(s) for s in self.services), default=-1) + 1

    def add(self, service: dict) -> dict:
        with self._rollback():
            service["_id"] = uuid.uuid4().hex
            service["order"] = {"position": self._next_position()}
            self.services.append(service)
            self.save()
        return service

    def update(self, service: dict) -> None:
        with self._rollback():
            for i, s in enumerate(self.services):
                if s.get("_id") == service.get("_id"):
                    service["updatedAt"] = now_ms()
                    self.services[i] = service
                    break
            else:
                raise VaultError("This account no longer exists")
            self.save()

    def delete(self, service: dict) -> None:
        with self._rollback():
            self.services = [s for s in self.services if s.get("_id") != service.get("_id")]
            self.save(backup=False)
        self._purge_copies()  # old copies still hold the deleted account
        self._backup_due = time.monotonic()
        self.flush_backup(0)

    def bump_counter(self, service: dict) -> None:
        otp = service.setdefault("otp", {})
        before, stamp = otp.get("counter"), service.get("updatedAt")
        counter = int(before or 0) + 1
        if counter > 2 ** 64 - 1:
            raise OtpError("Counter out of range")
        otp["counter"], service["updatedAt"] = counter, now_ms()
        try:
            self.save()
        except BaseException:
            otp["counter"], service["updatedAt"] = before, stamp
            raise

    def merge(self, content: dict) -> tuple[int, int]:
        """Add the services of a decrypted 2FAS backup that are not here yet.

        A service counts as already present when its secret matches (case-insensitive), the
        rule the 2FAS apps use. Malformed entries are skipped. Returns (added, skipped).
        """
        incoming = content.get("services")
        if not isinstance(incoming, list):
            raise VaultError("The backup has no list of services")
        if len(incoming) > MAX_SERVICES:
            raise VaultError("The backup has too many services")
        added = skipped = 0
        with self._rollback():
            known = set()
            for s in self.services:
                try:
                    known.add(check_secret(s.get("secret")))
                except OtpError:
                    pass
            known_groups = {g.get("id") for g in self.groups}
            raw_groups = content.get("groups")
            for g in raw_groups if isinstance(raw_groups, list) else []:
                g = normalize_group(g)
                if g and g["id"] not in known_groups:
                    self.groups.append(g)
                    known_groups.add(g["id"])
            for raw in sorted(incoming, key=_position):
                try:
                    s = normalize_service(raw)
                except OtpError:
                    skipped += 1
                    continue
                if s["secret"] in known:
                    skipped += 1
                    continue
                s["_id"] = uuid.uuid4().hex
                s["order"] = {"position": self._next_position()}
                self.services.append(s)
                known.add(s["secret"])
                added += 1
            if added:
                self.save()
        return added, skipped
