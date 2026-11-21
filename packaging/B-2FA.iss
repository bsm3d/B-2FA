; B-2FA installer (Inno Setup 6), driven by tools\build.ps1 (defines AppVersion, SourceDir, OutDir).
; The program is one static executable: nothing else to install (no runtime, no DLL).
; User data (vault, backups, PIN file, settings, logos) lives in %APPDATA%\BSM\B-2FA and is never
; touched by install, update or uninstall.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #error SourceDir is not defined, run tools\build.ps1
#endif
#ifndef OutDir
  #define OutDir "."
#endif

[Setup]
; same id as the installer of the earlier Python prototype, so this one installs over it
AppId={{3C6F1D52-8A47-4E0B-9B1E-72D5A4C0B2F8}
AppName=B-2FA
AppVersion={#AppVersion}
AppPublisher=BSM3D
VersionInfoVersion={#AppVersion}.0
DefaultDirName={autopf}\B-2FA
DefaultGroupName=B-2FA
DisableProgramGroupPage=yes
PrivilegesRequired=admin
; /CURRENTUSER or /ALLUSERS on the command line may override it (silent tests, per-user installs)
PrivilegesRequiredOverridesAllowed=commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile={#SourcePath}\..\res\b2fa.ico
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

[InstallDelete]
; the Python prototype shipped a runtime in this folder: remove what this edition does not use
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "{#SourceDir}\B-2FA.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\B-2FA"; Filename: "{app}\B-2FA.exe"
Name: "{autodesktop}\B-2FA"; Filename: "{app}\B-2FA.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\B-2FA.exe"; Description: "{cm:LaunchProgram,B-2FA}"; Flags: nowait postinstall skipifsilent
