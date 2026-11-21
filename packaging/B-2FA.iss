; B-2FA installer (Inno Setup 6), driven by tools/build_installer.py (defines AppVersion, SourceDir, OutDir).
; Installs the PyInstaller folder (Python, tkinter and cryptography included) in Program Files.
; User data (vault, backups, PIN file, logos) lives in %APPDATA%\BSM\B-2FA and is never touched
; by install, update or uninstall.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #error SourceDir is not defined, run python -I tools\build_installer.py
#endif
#ifndef OutDir
  #define OutDir "."
#endif

[Setup]
AppId={{3C6F1D52-8A47-4E0B-9B1E-72D5A4C0B2F8}
AppName=B-2FA
AppVersion={#AppVersion}
AppPublisher=BSM3D
VersionInfoVersion={#AppVersion}.0
DefaultDirName={autopf}\B-2FA
DefaultGroupName=B-2FA
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile={#SourcePath}\b2fa.ico
LicenseFile={#SourcePath}\..\LICENSE
UninstallDisplayIcon={app}\B-2FA.exe
OutputDir={#OutDir}
OutputBaseFilename=B-2FA-{#AppVersion}-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourcePath}\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\B-2FA"; Filename: "{app}\B-2FA.exe"
Name: "{autodesktop}\B-2FA"; Filename: "{app}\B-2FA.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\B-2FA.exe"; Description: "{cm:LaunchProgram,B-2FA}"; Flags: nowait postinstall skipifsilent
