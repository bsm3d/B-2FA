"""Install the 2FAS logo pack for B-2FA (run it once, needs git).

    python -I tools\\fetch_icons.py            download from github.com/twofasapp... and install
    python -I tools\\fetch_icons.py --source DIR   install from a folder that already holds
                                               services.json and icons\\ (no download)

Downloads only parsers/src/main/assets of the 2FAS Android repository (about 13 MB of PNG plus
services.json) into a throw-away temporary folder, then copies services.json and the PNGs to
%APPDATA%\\BSM\\B-2FA\\icons. B-2FA itself never uses the network.

The 2FAS README says their graphics are not under the GPL and have their own terms: keep this
pack for your own use and do not ship it with B-2FA.
"""

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from b2fa import icons  # noqa: E402

REPO = "https://github.com/twofas/2fas-android.git"
ASSETS = "parsers/src/main/assets"
PNG_RE = re.compile(r"^[0-9a-fA-F-]{36}\.png$")


def _force_remove(func, path, _exc) -> None:
    """git marks its objects read-only: clear that, then retry (Windows)."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def download(into: Path) -> Path:
    repo = into / "repo"
    run = lambda *a: subprocess.run(a, check=True, capture_output=True, text=True)  # noqa: E731
    run("git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", REPO, str(repo))
    run("git", "-C", str(repo), "sparse-checkout", "set", ASSETS)
    return repo / ASSETS


def install(source: Path, dest: Path) -> tuple[int, int]:
    services = source / "services.json"
    pngs = [p for p in (source / "icons").glob("*.png") if PNG_RE.match(p.name)]
    data = json.loads(services.read_text(encoding="utf-8"))  # must at least be valid JSON
    if not isinstance(data, list) or not pngs:
        raise SystemExit("The source does not look like the 2FAS asset folder")
    dest.mkdir(parents=True, exist_ok=True)
    for p in pngs:
        shutil.copy2(p, dest / p.name)
    shutil.copy2(services, dest / "services.json")
    return len(data), len(pngs)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--source", type=Path, help="folder with services.json and icons\\")
    args = ap.parse_args()
    dest = icons.default_folder()
    if args.source:
        n_services, n_png = install(args.source, dest)
    else:
        tmp = Path(tempfile.mkdtemp(prefix="b2fa-icons-"))
        try:
            print("Downloading the 2FAS asset folder (about 13 MB)...")
            n_services, n_png = install(download(tmp), dest)
        finally:
            shutil.rmtree(tmp, onexc=_force_remove)
    print("Installed %d logos for %d services into %s" % (n_png, n_services, dest))


if __name__ == "__main__":
    main()
