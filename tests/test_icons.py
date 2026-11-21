"""Logo lookup tests with a tiny fake pack (no 2FAS files, no network)."""

import json
import struct
import sys
import tempfile
import tkinter as tk
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from b2fa import icons  # noqa: E402

GH_COLL, GH_LIGHT, GH_DARK = "c0000000-0000-0000-0000-000000000001", "a0000000-0000-0000-0000-00000000000a", "b0000000-0000-0000-0000-00000000000b"
GO_COLL, GO_ICON, GO_SERVICE = "c0000000-0000-0000-0000-000000000002", "a0000000-0000-0000-0000-00000000000c", "d0000000-0000-0000-0000-000000000003"


def tiny_png(size=120) -> bytes:
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * size for _ in range(size))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


SERVICES = [
    {"id": "d0000000-0000-0000-0000-000000000009", "name": "GitHub", "issuers": ["github.com"],
     "icons_collections": [{"id": GH_COLL, "icons": [{"id": GH_DARK, "type": "dark"},
                                                    {"id": GH_LIGHT, "type": "light"}]}]},
    {"id": GO_SERVICE, "name": "Google", "issuers": [],
     "icons_collections": [{"id": GO_COLL, "icons": [{"id": GO_ICON, "type": "light"}]}]},
    {"id": "x", "name": "NoIcon", "icons_collections": []},
    "junk", None, 5,
]


class IconTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        (d / "services.json").write_text(json.dumps(SERVICES), encoding="utf-8")
        for i in (GH_LIGHT, GO_ICON):
            (d / (i + ".png")).write_bytes(tiny_png())
        self.store = icons.IconStore(d)

    def test_by_collection_id_prefers_light(self):
        svc = {"name": "whatever", "icon": {"selected": "IconCollection", "iconCollection": {"id": GH_COLL.upper()}}}
        self.assertEqual(self.store.icon_id(svc), GH_LIGHT)

    def test_by_service_type_id(self):
        self.assertEqual(self.store.icon_id({"name": "x", "serviceTypeID": GO_SERVICE}), GO_ICON)

    def test_by_exact_name_or_issuer(self):
        self.assertEqual(self.store.icon_id({"name": "github", "icon": {"selected": "Label"}}), GH_LIGHT)
        self.assertEqual(self.store.icon_id({"name": "x", "otp": {"issuer": "GitHub.com"}}), GH_LIGHT)

    def test_placeholder_collection_gives_a_letter_tile(self):
        svc = {"name": "Home server", "icon": {"iconCollection": {"id": icons.DEFAULT_COLLECTION}}}
        self.assertIsNone(self.store.icon_id(svc))

    def test_no_partial_match_and_unknown(self):
        self.assertIsNone(self.store.icon_id({"name": "GitHubby"}))
        self.assertIsNone(self.store.icon_id({"name": "Hatch"}))
        self.assertIsNone(self.store.icon_id({"name": "NoIcon"}))

    def test_hostile_accounts_never_raise(self):
        for bad in (None, [], "x", {}, {"icon": 3}, {"icon": {"iconCollection": 5, "brand": []}},
                    {"serviceTypeID": 7, "name": ["a"]}, {"otp": "no", "name": {}},
                    {"icon": {"iconCollection": {"id": "../../../windows/win"}}}):
            self.assertIsNone(self.store.icon_id(bad), msg=str(bad))

    def test_without_a_pack_nothing_happens(self):
        empty = icons.IconStore(Path(self.tmp.name) / "missing")
        self.assertFalse(empty.available)
        self.assertIsNone(empty.icon_id({"name": "GitHub"}))

    def test_damaged_index_is_ignored(self):
        (Path(self.tmp.name) / "services.json").write_text("{not json", encoding="utf-8")
        self.assertIsNone(icons.IconStore(Path(self.tmp.name)).icon_id({"name": "GitHub"}))

    def test_image_is_scaled_and_missing_file_is_none(self):
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("no display")
        self.addCleanup(root.destroy)
        root.withdraw()
        img = self.store.image({"name": "GitHub"})
        self.assertIsNotNone(img)
        self.assertLessEqual(img.width(), icons.TILE + 4)
        (Path(self.tmp.name) / (GO_ICON + ".png")).unlink()
        self.assertIsNone(self.store.image({"name": "Google"}))

    def test_initials(self):
        self.assertEqual(icons.initials("GitHub"), "GI")
        self.assertEqual(icons.initials("Home server"), "HS")
        self.assertEqual(icons.initials(""), "?")
        self.assertEqual(icons.initials("---"), "?")


if __name__ == "__main__":
    unittest.main()
