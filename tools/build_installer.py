"""Build the B-2FA installer: PyInstaller folder, then Inno Setup.

    python -I tools\\build_installer.py [--skip-tests]

Run it with the same Python that has `cryptography` and `pyinstaller` (and Pillow for the icon).
Steps: tests, icon, PyInstaller (onedir, windowed), a bundle check, Inno Setup, portable zip.
Everything goes to Python\\distributions\\B-2FA\\. Intermediate folders are in build\\ (ignored).
"""

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from b2fa import __version__  # noqa: E402

BUILD = ROOT / "build"
DIST = BUILD / "dist"
APP_DIR = DIST / "B-2FA"
OUT = ROOT.parent / "distributions" / "B-2FA"
ICON = ROOT / "packaging" / "b2fa.ico"

# what the packaged program must contain, or it fails on a machine without Python
REQUIRED = [
    "B-2FA.exe",
    "_internal/python3*.dll",
    "_internal/_tkinter*.pyd",
    "_internal/tcl86t.dll",
    "_internal/tk86t.dll",
    "_internal/_tcl_data/init.tcl",
    "_internal/_tk_data/tk.tcl",
    "_internal/cryptography/hazmat/bindings/_rust*.pyd",
    "_internal/_ctypes*.pyd",
    "_internal/_hashlib*.pyd",
]


def run(cmd, **kw):
    print(">", " ".join(str(c) for c in cmd))
    subprocess.check_call([str(c) for c in cmd], **kw)


def find_iscc() -> Path:
    for r in (os.environ.get("LOCALAPPDATA", ""), os.environ.get("ProgramFiles(x86)", ""),
              os.environ.get("ProgramFiles", "")):
        for sub in ("Programs/Inno Setup 6", "Inno Setup 6"):
            p = Path(r) / sub / "ISCC.exe" if r else None
            if p and p.is_file():
                return p
    raise SystemExit("Inno Setup 6 not found (ISCC.exe)")


def check_bundle() -> None:
    missing = [pat for pat in REQUIRED if not list(APP_DIR.glob(pat))]
    if missing:
        raise SystemExit("bundle check failed, missing: " + ", ".join(missing))
    size = sum(f.stat().st_size for f in APP_DIR.rglob("*") if f.is_file())
    print(f"bundle check ok ({size / 1e6:.1f} MB)")
    # nothing personal or heavy must ride along
    for f in APP_DIR.rglob("*"):
        if f.suffix.lower() in {".b2fa", ".2fas", ".log"} or f.name == "services.json":
            raise SystemExit(f"unexpected file in the bundle: {f}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-tests", action="store_true")
    args = ap.parse_args()

    if not args.skip_tests:
        env = dict(os.environ, B2FA_HOME=str(BUILD / "test-home"))
        shutil.rmtree(BUILD / "test-home", ignore_errors=True)
        run([sys.executable, "-I", "-m", "unittest", "discover", "-s", "tests"], cwd=ROOT, env=env)

    run([sys.executable, "-I", ROOT / "tools" / "make_icon.py"])

    shutil.rmtree(BUILD / "work", ignore_errors=True)
    shutil.rmtree(DIST, ignore_errors=True)
    run([sys.executable, "-I", "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed",
         "--name", "B-2FA", "--icon", ICON,
         "--distpath", DIST, "--workpath", BUILD / "work", "--specpath", BUILD,
         "--paths", ROOT, "--collect-submodules", "b2fa",
         "--hidden-import", "cryptography.hazmat.primitives.ciphers.aead",
         "--hidden-import", "cryptography.hazmat.primitives.kdf.scrypt",
         "--hidden-import", "cryptography.hazmat.primitives.kdf.pbkdf2",
         "--exclude-module", "PIL", "--exclude-module", "numpy",
         ROOT / "B-2FA.pyw"], cwd=ROOT)
    check_bundle()

    OUT.mkdir(parents=True, exist_ok=True)
    run([find_iscc(), f"/DAppVersion={__version__}", f"/DSourceDir={APP_DIR}", f"/DOutDir={OUT}",
         ROOT / "packaging" / "B-2FA.iss"])

    zip_path = OUT / f"B-2FA-{__version__}-portable.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(APP_DIR.rglob("*")):
            if f.is_file():
                z.write(f, Path("B-2FA") / f.relative_to(APP_DIR))
        z.write(ROOT / "LICENSE", Path("B-2FA") / "LICENSE")
    print("written", zip_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
