# B-2FA

Your 2FAS codes on your PC, without your phone.

A small Windows program (C++, Win32) that reads a [2FAS](https://2fas.com) backup and shows the one-time codes:
TOTP, HOTP and Steam Guard. The accounts are kept in an encrypted vault, and you can export a backup that the
2FAS phone app imports back.

![B-2FA main window](docs/screenshot.png)

## Before you use it

- A code generator on the same computer as your passwords is a weaker second factor than a separate phone. Keep
  your phone as the reference copy.
- B-2FA has **not been audited by a human security professional**. I designed and tested it, with the help of an AI
  coding assistant and two automated AI audits. Read the code before you trust it with secrets that matter.
- It is an independent project, not affiliated with or supported by 2FAS.
- It comes without any warranty.

## What it does

- Imports a `.2fas` backup, encrypted or not. Accounts you already have are skipped.
- Click an account to copy its code. The clipboard is cleared after 30 s.
- Add, edit and delete accounts, by hand or from an `otpauth://` link.
- Exports an encrypted `.2fas` backup for your phone.
- On-screen keypad with shuffled keys, optional PIN, automatic vault backups, automatic locking.
- Never connects to the internet. One executable, nothing else to install.

## Download

Windows 10 or 11, 64-bit, from the [Releases](https://github.com/bsm3d/B-2FA/releases) page:

- `B-2FA-<version>-Setup.exe`: installer.
- `B-2FA-<version>-portable.zip`: unzip and run `B-2FA.exe`.

The programs are not code-signed, so Windows SmartScreen may warn you. Check the SHA-256 given with the release.

## First steps

1. Choose a master password of 16 characters or more (4 or 5 random words work well). It cannot be recovered.
2. Import your 2FAS backup (in the phone app: Settings, Backup, export to a file), or add an account by hand.
3. Click an account to copy its code. Right-click to edit or delete it.

## Security

- The vault is encrypted with AES-256-GCM, with a key derived from your master password by scrypt (256 MiB).
- By default the vault is **bound to this PC**: a copy of the file does not open anywhere else, even with the right
  password. If you lose your Windows profile or the PC, the way back is the recovery export (`.2fas`) or your
  phone. Untick "Bind to this PC" when you create the vault if it must restore elsewhere.
- The **PIN** is a convenience, not a second lock. A program running under your Windows account can copy the PIN
  file and try PINs offline (about 8 days on one core for 6 digits, hours with many cores, about 2 years for 8). If
  that is not acceptable, do not set one.
- After 3 wrong tries at the unlock screen, the next one waits 30 s.
- An exported `.2fas` uses the phone app's format, which is weaker than the vault: give it a long password.
- The window is hidden from screen captures, codes stay out of the clipboard history, and the vault locks after 2
  minutes without input and when Windows locks or sleeps.
- The on-screen keypad stops loggers that only record the keyboard. It does not stop malware that reads the
  program's memory.

### Limits

- Malware running as you can read what you can read: the clipboard, the screen, the PIN file and the memory.
- Some traces of a secret can remain in memory that the program does not control, or in the swap file.
- Message boxes and menus can still be captured and may show an account name. A photo of the screen is not stopped.
- Screen capture protection needs Windows 10 build 19041 or later.
- Deleting an account also deletes the automatic backups: there is no undo.
- Restoring an old copy of the vault over a newer one is not detected.
- No Spectre mitigations.

To report a security problem, open an issue without publishing a working exploit, or contact me through
[www.bsm3d.com](https://www.bsm3d.com).

## Your data

Everything is in `%APPDATA%\BSM\B-2FA` (or the folder named by `B2FA_HOME`): the vault (`vault.b2fa`), its previous
version, the last automatic copies in `backups\`, the device key, the PIN file and the settings. To restore a
backup, copy it over `vault.b2fa`. Installing and updating never touch this folder. Uninstalling asks whether to
remove it: the default is No. Answering Yes deletes the vault and its backups for good, so export a recovery file
first. A silent uninstall keeps the folder.

## Logos

The installer and the portable zip include the 2FAS logo pack. To build with logos, run this once (needs `git`):

    powershell -ExecutionPolicy Bypass -File tools\fetch_icons.ps1

The pack is not part of this repository: the 2FAS graphics are not under the GPL.

## Build

Visual Studio 2022 Build Tools (C++), CMake, and [Inno Setup 6](https://jrsoftware.org/isinfo.php) for the installer.

    powershell -ExecutionPolicy Bypass -File tools\build.ps1

It builds the program, runs the tests, then creates the installer and the portable zip in `<distributions>\B-2FA\`
and prints their SHA-256. `<distributions>` is the folder named by `BSM_DISTRIBUTIONS`. Without it, an existing
`..\..\distributions` folder (two levels above the project) is used, else `out\` in the project.

For the program alone, then the tests:

    cmake -S . -B build -G "Visual Studio 17 2022" -A x64
    cmake --build build --config Release
    build\Release\b2tests.exe

## Contributing

Issues and pull requests are welcome. Please add no network access and no telemetry, and add a test with each fix.

## License

© 2026 Benoit Saint-Moulin ([www.bsm3d.com](https://www.bsm3d.com)). Free software under the
[GNU GPL v3](LICENSE) or later. It uses only what Windows provides.
