"""Core tests: python -m unittest discover -s tests"""

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from b2fa import totp, twofas, vault  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

DATA = Path(__file__).resolve().parent / "data"
S1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                      # "12345678901234567890"
S256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"  # 32 bytes
S512 = ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=")
PW = "correct horse battery"
PW2 = "another passphrase!"

_REAL_N = vault.SCRYPT_N


def setUpModule():
    vault.SCRYPT_N = 2 ** 14  # fast keys for tests (the bounds allow it)


def tearDownModule():
    vault.SCRYPT_N = _REAL_N


def svc(name="GitHub", secret="JBSWY3DPEHPK3PXP"):
    return vault.make_service(name, secret, name, "me")


class TotpTests(unittest.TestCase):
    def test_hotp_rfc4226(self):
        for i, code in enumerate(["755224", "287082", "359152", "969429", "338314"]):
            self.assertEqual(totp.hotp(S1, i), code)

    def test_totp_rfc6238(self):
        self.assertEqual(totp.totp(S1, 59, 30, 8, "SHA1"), "94287082")
        self.assertEqual(totp.totp(S256, 59, 30, 8, "SHA256"), "46119246")
        self.assertEqual(totp.totp(S512, 59, 30, 8, "SHA512"), "90693936")
        self.assertEqual(totp.totp(S1, 1111111109, 30, 8, "SHA1"), "07081804")

    def test_secret_cleanup(self):
        self.assertEqual(totp.totp("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq", 59, 30, 8), "94287082")

    def test_otpauth(self):
        r = totp.parse_otpauth("otpauth://totp/Example:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8")
        self.assertEqual((r["issuer"], r["account"], r["digits"], r["type"]),
                         ("Example", "alice@google.com", 8, "TOTP"))
        r = totp.parse_otpauth("otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=7")
        self.assertEqual((r["type"], r["counter"]), ("HOTP", 7))
        for bad in ("https://example.com", "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&digits=abc",
                    "otpauth://[/x", "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&digits=1000000000",
                    "otpauth://totp/X?secret=", "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"):
            with self.assertRaises(totp.OtpError, msg=bad):
                totp.parse_otpauth(bad)

    def test_steam_shape(self):
        code = totp.steam("JBSWY3DPEHPK3PXP", 59)
        self.assertEqual(len(code), 5)
        self.assertTrue(all(c in totp.STEAM_ALPHABET for c in code))

    def test_hostile_numbers_only_raise_otperror(self):
        base = {"secret": "JBSWY3DPEHPK3PXP"}
        bad_otps = [
            {"digits": "abc"}, {"digits": 10 ** 9}, {"digits": -3}, {"digits": 3},
            {"period": -30}, {"period": 0.5}, {"period": 1e999}, {"period": 10 ** 9},
            {"tokenType": "HOTP", "counter": -1}, {"tokenType": "HOTP", "counter": 2 ** 64},
            {"algorithm": "MD5"}, {"tokenType": "WAT"}, {"digits": [1]}, {"counter": "x"},
        ]
        for otp in bad_otps:
            with self.assertRaises(totp.OtpError, msg=str(otp)):
                totp.current_code({**base, "otp": otp})
        for bad in ({"secret": ""}, {"secret": None}, {"secret": 123}, {"secret": "!!!"}, {}, None, []):
            with self.assertRaises(totp.OtpError, msg=str(bad)):
                totp.current_code(bad)

    def test_digits_cannot_freeze(self):
        start = time.time()
        with self.assertRaises(totp.OtpError):
            totp.hotp(S1, 0, 10 ** 8)
        self.assertLess(time.time() - start, 1)


class BackupTests(unittest.TestCase):
    @unittest.skipUnless((DATA / "encrypted_test.2fas").is_file(),
                         "optional: needs tests/data/encrypted_test.2fas (see README)")
    def test_third_party_sample(self):
        """A backup made by the real 2FAS app, found in another project's test suite.

        Not shipped with the repository (its licence is not ours): copy encrypted_test.2fas from
        github.com/elliotwutingfeng/2fas-backup-decryptor (tests folder) into tests/data/ to run it.
        The password is "example.com"."""
        content = twofas.read_backup(str(DATA / "encrypted_test.2fas"))
        self.assertTrue(twofas.is_encrypted(content))
        with self.assertRaises(twofas.WrongPassword):
            twofas.decrypt_backup(content, "not the password")
        plain = twofas.decrypt_backup(content, "example.com")
        self.assertGreater(len(plain["services"]), 0)
        for s in plain["services"]:
            self.assertTrue(totp.current_code(s)[0])

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.2fas")
            twofas.write_backup(p, [svc("Example")], [], "pässword é")
            content = twofas.read_backup(p)
            self.assertEqual(content["services"], [])
            plain = twofas.decrypt_backup(content, "pässword é")
            self.assertEqual(plain["services"][0]["secret"], "JBSWY3DPEHPK3PXP")
            with self.assertRaises(twofas.WrongPassword):
                twofas.decrypt_backup(content, "wrong")
            self.assertEqual(os.listdir(d), ["x.2fas"])

    def test_hostile_files(self):
        with tempfile.TemporaryDirectory() as d:
            def write(name, text):
                p = os.path.join(d, name)
                Path(p).write_text(text, encoding="utf-8")
                return p
            cases = {
                "deep.json": "[" * 100000 + "]" * 100000,
                "nan.json": '{"services": [{"secret": NaN}]}',
                "list.json": "[1, 2]",
                "empty.json": "",
                "noref.json": '{"services": [], "servicesEncrypted": "a:b:c"}',
            }
            for name, text in cases.items():
                with self.assertRaises(twofas.BackupError, msg=name):
                    twofas.read_backup(write(name, text))
            with self.assertRaises(twofas.BackupError):
                twofas.read_backup(os.path.join(d, "missing.2fas"))
            # short IV and bad layouts never crash with a raw exception
            good = twofas.build_backup([svc()], [], "a long enough password")
            data, salt, iv = good["servicesEncrypted"].split(":")
            short_iv = base64.b64encode(b"1234").decode()
            for field in (":".join([data, salt, short_iv]), "x", "a:b", ":".join([data, "", iv])):
                tampered = dict(good, servicesEncrypted=field)
                with self.assertRaises(twofas.BackupError):
                    twofas.decrypt_backup(tampered, "a long enough password")


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "vault.b2fa"
        self.addCleanup(self.tmp.cleanup)

    def new(self):
        v = vault.Vault(self.path)
        v.create(PW)
        return v

    def reopen(self, password=PW):
        v = vault.Vault(self.path)
        v.unlock(password)
        return v

    def test_lifecycle_and_encryption(self):
        v = self.new()
        v.add(svc("GitHub", "JBSWY3DPEHPK3PXP"))
        v.add(svc("Mail", "GEZDGNBVGY3TQOJQ"))
        self.assertNotIn("JBSWY3DPEHPK3PXP", self.path.read_text())
        w = vault.Vault(self.path)
        with self.assertRaises(vault.WrongMasterPassword):
            w.unlock("nope nope nope nope")
        w.unlock(PW)
        self.assertEqual(len(w.services), 2)
        self.assertEqual({s["order"]["position"] for s in w.services}, {0, 1})

    def test_master_password_minimum(self):
        with self.assertRaises(vault.VaultError):
            vault.Vault(self.path).create("short")

    def test_debounced_backup_holds_every_change(self):
        v = self.new()
        for i, secret in enumerate(("JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQ", "MFRGGZDFMZTWQ2LK")):
            v.add(svc("S%d" % i, secret))
        self.assertEqual(list(v.backups_dir.glob("*")), [])  # nothing yet: coalescing
        v.flush_backup(delay=1000)
        self.assertEqual(list(v.backups_dir.glob("*")), [])  # not due
        v.flush_backup(delay=0)
        files = list(v.backups_dir.glob("B-2FA-auto-*.b2fa"))
        self.assertEqual(len(files), 1)
        copy = self.dir / "restored.b2fa"
        copy.write_bytes(files[0].read_bytes())
        restored = vault.Vault(copy)
        restored.unlock(PW)
        self.assertEqual(len(restored.services), 3)  # the backup has all three, not just the first
        self.assertEqual(files[0].suffix, ".b2fa")  # scrypt-protected vault copy, not PBKDF2 .2fas

    def test_lock_flushes_pending_backup(self):
        v = self.new()
        v.add(svc())
        v.lock()
        self.assertEqual(len(list(v.backups_dir.glob("B-2FA-auto-*.b2fa"))), 1)

    def test_change_password_purges_old_copies(self):
        v = self.new()
        v.add(svc("A", "JBSWY3DPEHPK3PXP"))
        v.add(svc("B", "GEZDGNBVGY3TQOJQ"))
        v.flush_backup(0)
        legacy = v.backups_dir / "B-2FA-20260101-120000.2fas"  # written by the first release
        twofas.write_backup(str(legacy), v.exportable_services(), [], PW)
        self.assertTrue(v.path.with_name("vault.b2fa.bak").exists())
        with self.assertRaises(vault.WrongMasterPassword):
            v.change_password("wrong wrong wrong", PW2)
        v.change_password(PW, PW2)
        self.assertFalse(legacy.exists())
        self.assertFalse(v.path.with_name("vault.b2fa.bak").exists())
        candidates = [v.path] + list(v.backups_dir.glob("*"))
        self.assertGreaterEqual(len(candidates), 2)  # the vault plus one fresh backup
        for f in candidates:
            probe = self.dir / ("probe-" + f.name)
            probe.write_bytes(f.read_bytes())
            with self.assertRaises(vault.WrongMasterPassword, msg=f.name):
                vault.Vault(probe).unlock(PW)  # nothing opens with the OLD password any more
            vault.Vault(probe).unlock(PW2)

    def test_delete_purges_copies(self):
        v = self.new()
        keep, drop = v.add(svc("Keep", "JBSWY3DPEHPK3PXP")), v.add(svc("Drop", "GEZDGNBVGY3TQOJQ"))
        v.flush_backup(0)
        v.delete(drop)
        for f in [v.path] + list(v.backups_dir.glob("*.b2fa")) + list(self.dir.glob("*.bak")):
            probe = self.dir / ("probe-" + f.name)
            probe.write_bytes(f.read_bytes())
            w = vault.Vault(probe)
            w.unlock(PW)
            self.assertEqual([s["name"] for s in w.services], ["Keep"], f.name)
        self.assertEqual(keep["name"], "Keep")

    def test_failed_write_rolls_back(self):
        v = self.new()
        v.add(svc("A", "JBSWY3DPEHPK3PXP"))
        real_replace = os.replace
        with mock.patch("b2fa.vault.os.replace", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                v.add(svc("B", "GEZDGNBVGY3TQOJQ"))
        self.assertEqual(len(v.services), 1)  # memory matches the disk
        with mock.patch("b2fa.vault.os.replace", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                v.change_password(PW, PW2)
        self.assertTrue(v.check_password(PW))  # still the old password, in memory and on disk
        self.assertEqual(os.replace, real_replace)
        v.add(svc("C", "MFRGGZDFMZTWQ2LK"))
        self.reopen(PW)  # a later save did not silently switch to the new password
        self.assertEqual(sorted(s["name"] for s in self.reopen(PW).services), ["A", "C"])
        self.assertFalse(list(self.dir.glob("*.tmp")))

    def test_hotp_counter_rollback(self):
        v = self.new()
        s = v.add(vault.make_service("H", "JBSWY3DPEHPK3PXP", token_type="HOTP", counter=5))
        v.bump_counter(s)
        self.assertEqual(s["otp"]["counter"], 6)
        with mock.patch("b2fa.vault.os.replace", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                v.bump_counter(s)
        self.assertEqual(s["otp"]["counter"], 6)

    def test_two_writers_are_refused(self):
        a = self.new()
        a.add(svc("FromA", "JBSWY3DPEHPK3PXP"))
        b = self.reopen()
        a.add(svc("More", "GEZDGNBVGY3TQOJQ"))  # a writes after b opened
        with self.assertRaises(vault.VaultError):
            b.add(svc("FromB", "MFRGGZDFMZTWQ2LK"))
        names = sorted(s["name"] for s in self.reopen().services)
        self.assertEqual(names, ["FromA", "More"])  # nothing was lost

    def test_hostile_kdf_parameters(self):
        self.new()
        doc = json.loads(self.path.read_text())
        for n, r, p in ((2 ** 30, 8, 1), ("x", 8, 1), (2 ** 14, 1000, 1), (3, 8, 1), (2 ** 14, 8, 99), (True, 8, 1)):
            doc["kdf"].update(n=n, r=r, p=p)
            self.path.write_text(json.dumps(doc))
            start = time.time()
            with self.assertRaises(vault.VaultError, msg=str((n, r, p))):
                vault.Vault(self.path).unlock(PW)
            self.assertLess(time.time() - start, 2)
        for junk in ("[]", "{}", "not json", '{"format": "b2fa-vault", "version": 9}'):
            self.path.write_text(junk)
            with self.assertRaises(vault.VaultError):
                vault.Vault(self.path).unlock(PW)

    def test_header_is_authenticated(self):
        self.new()
        doc = json.loads(self.path.read_text())
        doc["kdf"]["name"] = "scrypt-tampered"
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(vault.WrongMasterPassword):
            vault.Vault(self.path).unlock(PW)

    def test_upgrade_from_first_release(self):
        """A vault written by the first release (version 1, scrypt 2^15) is converted."""
        n = 2 ** 15
        salt = os.urandom(16)
        key = vault._kdf(PW, salt, n, 8, 1)
        legacy = vault.make_service("Old", "JBSWY3DPEHPK3PXP")
        nonce = os.urandom(12)
        payload = json.dumps({"services": [legacy], "groups": []}).encode()
        doc = {"format": "b2fa-vault", "version": 1,
               "kdf": {"name": "scrypt", "n": n, "r": 8, "p": 1, "salt": base64.b64encode(salt).decode()},
               "nonce": base64.b64encode(nonce).decode(),
               "data": base64.b64encode(AESGCM(key).encrypt(nonce, payload, b"b2fa-vault-1")).decode()}
        self.path.write_text(json.dumps(doc))
        (self.dir / "vault.b2fa.bak").write_text("old copy")
        old_backup = self.dir / "backups" / "B-2FA-20260101-120000.2fas"
        old_backup.parent.mkdir()
        old_backup.write_text("{}")
        with mock.patch.object(vault, "SCRYPT_N", 2 ** 16):
            v = vault.Vault(self.path)
            v.unlock(PW)
        self.assertEqual([s["name"] for s in v.services], ["Old"])
        new = json.loads(self.path.read_text())
        self.assertEqual((new["version"], new["kdf"]["n"]), (2, 2 ** 16))
        self.assertFalse((self.dir / "vault.b2fa.bak").exists())
        self.assertFalse(old_backup.exists())
        self.assertEqual(len(self.reopen().services), 1)

    def test_prune_keeps_the_newest_file_even_with_a_wrong_clock(self):
        v = self.new()
        v.add(svc())
        v.backups_dir.mkdir(exist_ok=True)
        future = time.time() + 10 * 365 * 86400
        for i in range(vault.KEEP_BACKUPS):
            f = v.backups_dir / ("B-2FA-auto-29990101-0000%02d.b2fa" % i)
            f.write_text("x")
            os.utime(f, (future, future))
        mine = v.backups_dir / "B-2FA-2026-my-own-export.2fas"
        mine.write_text("x")
        target = v.auto_backup()
        self.assertTrue(target.exists())
        self.assertTrue(mine.exists())  # a manual export in this folder is never pruned

    def test_merge_skips_hostile_entries(self):
        v = self.new()
        hostile = [
            "text", 5, None, [], {"secret": 5}, {"secret": ""}, {"secret": "!!!"},
            {"secret": "JBSWY3DPEHPK3PXP", "otp": {"digits": "abc"}},
            {"secret": "JBSWY3DPEHPK3PXP", "otp": {"period": -30}},
            {"secret": "JBSWY3DPEHPK3PXP", "otp": {"algorithm": "MD5"}},
            {"secret": "GEZDGNBVGY3TQOJQ", "order": {"position": "x"}, "name": "A" * 10 ** 6, "icon": 3,
             "otp": "not a dict", "badge": [], "groupId": 4},
            {"secret": "gezd gnbv gy3t qojq"},  # same secret as the previous one: duplicate
            {"secret": "MFRGGZDFMZTWQ2LK", "order": ["list"]},
        ]
        added, skipped = v.merge({"services": hostile, "groups": ["x", {"id": 1}, {"id": "g", "name": "G"}]})
        self.assertEqual((added, skipped), (2, len(hostile) - 2))
        self.assertEqual([g["id"] for g in v.groups], ["g"])
        for s in v.services:
            self.assertTrue(totp.current_code(s)[0])
            self.assertLessEqual(len(s["name"]), vault.MAX_TEXT)
        with self.assertRaises(vault.VaultError):
            v.merge({"services": "nope"})
        self.assertEqual(len(self.reopen().services), 2)

    def test_merge_dedupes_by_secret(self):
        v = self.new()
        v.add(svc("GitHub", "JBSWY3DPEHPK3PXP"))
        dup = {"services": [vault.make_service("Dup", "jbswy3dp ehpk3pxp"),
                            vault.make_service("New", "MFRGGZDFMZTWQ2LK")], "groups": []}
        self.assertEqual(v.merge(dup), (1, 1))

    def test_export_password_rules(self):
        v = self.new()
        v.add(svc())
        out = str(self.dir / "x.2fas")
        with self.assertRaises(vault.VaultError):
            v.export_backup(out, "short")
        with self.assertRaises(vault.VaultError):
            v.export_backup(out, PW)  # same as the master password
        v.export_backup(out, "a different long passphrase")
        plain = twofas.decrypt_backup(twofas.read_backup(out), "a different long passphrase")
        self.assertEqual(len(plain["services"]), 1)
        self.assertFalse(any(k.startswith("_") for k in plain["services"][0]))

    def test_empty_secret_refused(self):
        for bad in ("", "   ", "====", "!!!"):
            with self.assertRaises(totp.OtpError):
                vault.make_service("x", bad)


if __name__ == "__main__":
    unittest.main()
