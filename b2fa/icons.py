"""Service logos, from a local copy of the 2FAS icon pack. Never touches the network.

The pack is the `icons` folder and `services.json` of the 2FAS Android app (github.com/twofasapp),
copied once into %APPDATA%\\BSM\\B-2FA\\icons (services.json and <id>.png side by side) by
tools\\fetch_icons.py. Without it the app simply
draws a letter tile. These graphics are not under the 2FAS GPL (their README says so): keep them
for your own use and do not redistribute them with B-2FA.

An account finds its logo like the 2FAS apps do: through the icon collection id stored in the
backup, then through its service type id, then (for accounts typed by hand) by an exact name match.
"""

import json
import re
import tkinter as tk
from pathlib import Path

from . import paths

UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
TILE = 32
DEFAULT_COLLECTION = "a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad"  # 2FAS "no brand" placeholder


def default_folder() -> Path:
    return paths.data_dir() / "icons"


class IconStore:
    def __init__(self, folder: Path | None = None):
        self.folder = Path(folder) if folder else default_folder()
        self._loaded = False
        self._collections: dict[str, dict] = {}   # collection id -> {"light": icon id, "dark": icon id}
        self._by_service: dict[str, str] = {}      # service type id -> collection id
        self._by_name: dict[str, str] = {}         # lower-case name or issuer -> collection id
        self._images: dict[str, object] = {}       # icon id -> tk.PhotoImage (kept alive here)

    # ---- index -------------------------------------------------------------
    @property
    def available(self) -> bool:
        return (self.folder / "services.json").is_file()

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            services = json.loads((self.folder / "services.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            return
        if not isinstance(services, list):
            return
        for s in services:
            if not isinstance(s, dict):
                continue
            for coll in s.get("icons_collections") or []:
                icons = coll.get("icons") if isinstance(coll, dict) else None
                if not icons or not isinstance(coll.get("id"), str):
                    continue
                entry = {}
                for ic in icons:
                    if isinstance(ic, dict) and isinstance(ic.get("id"), str):
                        entry.setdefault("dark" if ic.get("type") == "dark" else "light", ic["id"])
                entry.setdefault("light", entry.get("dark"))
                if not entry.get("light"):
                    continue
                self._collections.setdefault(coll["id"].lower(), entry)
                if isinstance(s.get("id"), str):
                    self._by_service.setdefault(s["id"].lower(), coll["id"].lower())
                names = [s.get("name")] + list(s.get("issuers") or [])
                for n in names:
                    if isinstance(n, str) and n.strip():
                        self._by_name.setdefault(n.strip().lower(), coll["id"].lower())
                break  # first collection only, like the apps

    def icon_id(self, service: dict) -> str | None:
        """Id of the PNG to show for this account, or None (then a letter tile is drawn)."""
        if not self.available or not isinstance(service, dict):
            return None
        self._load()
        icon = service.get("icon") if isinstance(service.get("icon"), dict) else {}
        coll_ref = icon.get("iconCollection") if isinstance(icon.get("iconCollection"), dict) else {}
        brand = icon.get("brand") if isinstance(icon.get("brand"), dict) else {}
        candidates = []
        key = coll_ref.get("id")
        # the apps' "no brand" collection is a grey placeholder: a letter tile looks better
        if isinstance(key, str) and key.lower() != DEFAULT_COLLECTION:
            candidates.append(key.lower())
        for key in (service.get("serviceTypeID"), brand.get("id")):
            if isinstance(key, str) and key.lower() in self._by_service:
                candidates.append(self._by_service[key.lower()])
        otp = service.get("otp") if isinstance(service.get("otp"), dict) else {}
        for key in (service.get("name"), otp.get("issuer")):
            if isinstance(key, str) and key.strip().lower() in self._by_name:
                candidates.append(self._by_name[key.strip().lower()])
        for coll_id in candidates:
            entry = self._collections.get(coll_id)
            if entry:
                return entry["light"]  # the window is light: use the light variant
        return None

    # ---- images ------------------------------------------------------------
    def image(self, service: dict):
        """A Tk image about TILE px wide for this account, or None."""
        icon_id = self.icon_id(service)
        if not icon_id or not UUID_RE.match(icon_id):
            return None
        if icon_id in self._images:
            return self._images[icon_id]
        img = None
        try:
            img = tk.PhotoImage(file=str(self.folder / (icon_id + ".png")))
            if img.width() >= TILE * 2:
                img = img.subsample(max(1, round(img.width() / TILE)))
        except (tk.TclError, OSError):
            img = None
        self._images[icon_id] = img
        return img


def initials(name: str) -> str:
    words = [w for w in re.split(r"[\s._@-]+", name or "") if w]
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].upper()
    return (words[0][0] + words[1][0]).upper()
