# B-2FA

**Your 2FAS codes on your PC, without your phone.**

B-2FA is a small native Windows program (C++, plain Win32, 0.6 MB, nothing to install first) that
reads a [2FAS](https://2fas.com) backup and shows the one-time codes (TOTP, HOTP, Steam Guard) in a
window. It keeps the accounts in an encrypted vault on your PC, so you can get a code when the phone is
not at hand, and it can export a backup that the 2FAS phone app imports back.

![B-2FA main window](docs/screenshot.png)

> **Security warning.** A code generator on the same computer as your passwords is, by design, a weaker
> second factor than a separate phone: anyone who gets your unlocked PC and your master password gets
> your codes. B-2FA has **not been audited by a human security professional** (see
> [Security](#security)). Keep your phone as the reference copy, use a long master password, and do not
> rely on this software for anything where losing the account would be serious without understanding
> these limits. It comes with no warranty (see [License](#license)).

> **Transparency note.** B-2FA was designed, directed and tested by hand by Benoit Saint-Moulin, and
> written with the help of an AI coding assistant. The code is also covered by automated tests and was
> reviewed by an independent automated AI audit, whose findings were fixed. It may nevertheless contain
> errors. Read the code before you trust it with secrets that matter.

> **Not affiliated with 2FAS.** B-2FA is an independent project. It is not made, endorsed or supported
> by 2FAS. "2FAS" is the name of their product.

## Features

- Import a 2FAS backup (`.2fas`, encrypted or not). Accounts already present (same secret) are skipped.
- Codes for TOTP (SHA1, SHA256, SHA512, 4 to 10 digits, any period), HOTP and Steam Guard, with the
  seconds left shown in small text under each code.
- Click an account to copy its code. The clipboard is cleared after 30 s and on exit.
- Add, edit and delete accounts, by hand or from an `otpauth://` link. The technical settings (type,
  algorithm, digits, period) sit behind "Advanced options" because nearly every service uses the defaults.
- Export an encrypted `.2fas` backup for the 2FAS phone app (long password required, different from the
  master password).
- **On-screen shuffled keypad** on demand for the PIN and the passwords, against keyloggers (see below).
- Optional PIN (4 to 8 digits) for quick unlock on this PC.
- Automatic backups of the vault, locking after 5 minutes of inactivity, and screen capture protection.
- Service logos from the official 2FAS pack, installed on demand (see [Logos](#logos)).
- No network access: the program never connects to the internet.
- One static executable: no Python, no .NET, no Visual C++ runtime, no DLL to ship.

## On-screen keypad (anti-keylogger)

A keylogger records the keys you press. B-2FA lets you enter the PIN, and any password, with the mouse on a
keypad whose keys are in a random order:

- The PIN is typed on the keyboard by default. A "Virtual keyboard" link under the field shows the PIN
  keypad whenever you want it (for example on a PC you do not trust): its keys are reshuffled after **every**
  digit and the physical keyboard is ignored while it is shown. To use it every time, tick
  More > Always use the keypad for the PIN.
- Every password prompt has a "Virtual keyboard" link: three pages (lower case, upper case, digits and
  symbols), reshuffled each time a page is shown, with the physical keyboard switched off while it is open.
  Paste still works, so a password manager can fill the field.
- The window is excluded from screen capture, so a program that records mouse clicks cannot photograph the
  layout to learn which key sits where.

This is **not** what products like KeyScrambler do. They install a keyboard driver that encrypts keystrokes
inside the system, which an ordinary program cannot do. The keypad protects against loggers that only record
the keyboard (hooks, hardware keyloggers). It does not protect against malware that reads the program's
memory, reads the field's text, or controls the whole session. Typing the password on the physical keyboard
is of course still exposed to a keylogger.

## Download

Windows 10 or 11, 64-bit. Get the files from the [Releases](https://github.com/bsm3d/B-2FA/releases) page:

| File | Use |
|---|---|
| `B-2FA-<version>-Setup.exe` | Installer (needs administrator rights, installs in `Program Files`). |
| `B-2FA-<version>-portable.zip` | Portable version: unzip and run `B-2FA.exe`. |

The programs are not code-signed, so Windows SmartScreen may warn on the first launch. Check the SHA-256
checksum given with each release before you run it.

## Using it

1. First launch: choose a **master password** (12 characters minimum). It cannot be recovered.
2. **Import** your 2FAS backup (in the phone app: Settings, Backup, export to a file), or **+ Add** an
   account by hand.
3. Click an account to copy its code. Right-click for Edit and Delete.
4. Optional: **More > Set or change PIN** for a quicker unlock. The master password stays the real key.

## Security

What protects your data:

- The vault is encrypted with AES-256-GCM, with a key derived from the master password by scrypt
  (128 MiB of memory, N = 2^17). The header is authenticated, writes are atomic, and a save is refused if
  another program changed the vault file.
- Backups made by the program are copies of the vault (same protection). Changing the master password or
  deleting an account deletes the old copies so none outlives the change.
- The 2FAS backup format is weaker than the vault: it uses PBKDF2-HMAC-SHA256 with only 10 000
  iterations. That is the phone app's format, so an exported `.2fas` is only as strong as its password.
  B-2FA asks for at least 12 characters, different from the master password.
- The PIN does not protect the vault file (4 to 8 digits are too few against a copied file). It only
  opens a small side file that holds the master password wrapped by Windows DPAPI (this Windows account
  only) with the PIN as extra entropy. It is erased after 5 wrong PINs and when the master password
  changes.
- The window is excluded from screen captures (Print Screen, Snipping Tool, screen sharing, recorders):
  they get a black picture saying "No screen capture allowed". Switch it off for the session with
  More > Block screen capture (or start with `--allow-capture`). Windows 10 build 19041 or later.
- Codes go to the clipboard excluded from Windows clipboard history and cloud sync.
- The cryptography comes from Windows (CNG), except scrypt, which Windows does not have and which is
  written in this project and checked against the RFC 7914 test vectors.
- Passwords, keys and decrypted data are wiped from the program's memory as soon as it is done with them.

Known limits:

- Traces of a secret can still exist in memory the program does not control (the text box of the
  window, the system's own buffers, a swap file).
- Malware already running as you can read what you can read: the PIN, the clipboard, the screen.
- A photo of the screen is not stopped by the capture protection.
- An old copy of the vault restored over a newer one is not detected (no rollback protection).
- The program has had no review by a human security professional.

To report a security problem, open an issue on GitHub without publishing a working exploit, or contact
the author through [www.bsm3d.com](https://www.bsm3d.com).

## Your data

Everything lives in `%APPDATA%\BSM\B-2FA` (override with the `B2FA_HOME` environment variable):

- `vault.b2fa`: the accounts, encrypted with the master password.
- `vault.b2fa.bak`: the previous version of the vault.
- `backups\`: the last 10 automatic copies of the vault. To restore one, copy it over `vault.b2fa`.
- `pin.b2fa`: the PIN side file, if you set a PIN.
- `settings.json`: the few settings (nothing secret).
- `icons\`: the logo pack, if you installed it.

Install, update and uninstall never touch this folder. The master password cannot be recovered.

## Logos

The service logos belong to 2FAS and are **not** under the GPL (their repository says so), so they are not
part of this project. To show them on your own PC, run once (needs `git`, about 13 MB):

    powershell -ExecutionPolicy Bypass -File tools\fetch_icons.ps1

It downloads the logo pack from the 2FAS Android repository into `%APPDATA%\BSM\B-2FA\icons`. Keep it
for your own use and do not redistribute it. Without the pack, B-2FA shows a letter tile.

## Build

Needs the Visual Studio 2022 Build Tools (C++ workload), CMake, and, for the installer only,
[Inno Setup 6](https://jrsoftware.org/isinfo.php).

    powershell -ExecutionPolicy Bypass -File tools\build.ps1

It builds the program, runs the tests, checks that the executable imports no runtime DLL, then builds
`B-2FA-<version>-Setup.exe` and the portable zip into `..\distributions\B-2FA\` and prints their SHA-256.
For the program alone:

    cmake -S . -B build -G "Visual Studio 17 2022" -A x64
    cmake --build build --config Release

## Tests

    build\Release\b2tests.exe

About 280 checks: the RFC 4226, 6238, 4231 and 7914 vectors, a NIST AES-GCM vector, the JSON reader, the
vault (create, unlock, change password, export, merge, damaged files, a vault changed behind its back),
the 2FAS format, the PIN (attempt counting, wiping), the settings and the keypad shuffle. They also open
files made by an earlier Python prototype of B-2FA (`tests/vectors`) and check that the codes match.

The backup format is the one of the 2FAS apps ([github.com/twofas](https://github.com/twofas)):
PBKDF2-HMAC-SHA256 (10 000 iterations), AES-256-GCM, fields `base64(ciphertext+tag):base64(salt):base64(iv)`.

## Contributing

Issues and pull requests are welcome. Please keep the program free of network access and of telemetry, and
add a test with each fix.

## License

Copyright (C) 2026 Benoit Saint-Moulin ([www.bsm3d.com](https://www.bsm3d.com)).

B-2FA is free software: you can redistribute it and modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
any later version. It is distributed in the hope that it will be useful, but **without any warranty**,
without even the implied warranty of merchantability or fitness for a particular purpose. See
[LICENSE](LICENSE) for the full text.

It uses only what Windows provides (Win32, CNG, DPAPI, WIC) and has no third-party library.
