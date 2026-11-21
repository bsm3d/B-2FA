"""Where B-2FA keeps its data: one folder, %APPDATA%\\BSM\\B-2FA.

B2FA_HOME overrides it (tests, portable mode).
"""

import os
from pathlib import Path

from . import APP_NAME


def data_dir() -> Path:
    env = os.environ.get("B2FA_HOME")
    if env:
        path = Path(env)
    else:
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        path = Path(base) / "BSM" / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def vault_path() -> Path:
    return data_dir() / "vault.b2fa"


def backups_dir() -> Path:
    path = data_dir() / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path
