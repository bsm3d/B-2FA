; B-2FA
; © Benoit Saint-Moulin - 2026
; Version du fichier : 1.0.1
; Fonction du fichier : Inno Setup 6 installer script for B-2FA, driven by build.ps1, that installs the single executable and leaves user data alone.

; Installer driven by tools\build.ps1 (defines AppVersion, SourceDir, OutDir). One static executable, nothing else to install.
; User data (vault, backups, PIN file, settings) lives in %APPDATA%\BSM\B-2FA and is never touched by install, update or uninstall.

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

[Files]
Source: "{#SourceDir}\B-2FA.exe"; DestDir: "{app}"; Flags: ignoreversion
#ifdef IconsDir
Source: "{#IconsDir}\*"; DestDir: "{app}\icons"; Flags: ignoreversion
#endif
Source: "{#SourcePath}\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\B-2FA"; Filename: "{app}\B-2FA.exe"
Name: "{autodesktop}\B-2FA"; Filename: "{app}\B-2FA.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\B-2FA.exe"; Description: "{cm:LaunchProgram,B-2FA}"; Flags: nowait postinstall skipifsilent

; ---- user data question (added by the audit, group 2) ----
[CustomMessages]
english.DataAsk=Remove all the user data of %1?%n%nFolder(s):%n%2%nContent: %3 (%4 MB).%n%nYes: the folder(s) are deleted, for good.%nNo: they are kept, you get them back if you reinstall %1.%n%nThe vault holds your keys: export a backup first if you may need it.
english.DataWhat=your vault, its backups, the PIN file, the settings and the logos
french.DataAsk=Retirer toutes les données utilisateur de %1 ?%n%nDossier(s) :%n%2%nContenu : %3 (%4 Mo).%n%nOui : le ou les dossiers sont supprimés, définitivement.%nNon : ils sont conservés, tu les retrouves si tu réinstalles %1.%n%nLe coffre contient tes clés : exporte une sauvegarde avant si tu peux en avoir besoin.
french.DataWhat=ton coffre, ses sauvegardes, le fichier du PIN, les réglages et les logos

[Code]
// Size of a folder in bytes: the dialog tells the user what "Yes" removes.
function FolderBytes(const Dir: String): Int64;
var
  Rec: TFindRec;
begin
  Result := 0;
  if FindFirst(Dir + '\*', Rec) then
  try
    repeat
      if (Rec.Name <> '.') and (Rec.Name <> '..') then
      begin
        if (Rec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
          Result := Result + FolderBytes(Dir + '\' + Rec.Name)
        else
          Result := Result + (Int64(Rec.SizeHigh) * 4294967296) + Rec.SizeLow;
      end;
    until not FindNext(Rec);
  finally
    FindClose(Rec);
  end;
end;

procedure AddIfExists(var Dirs: TArrayOfString; const Dir: String);
var
  N: Integer;
begin
  if DirExists(Dir) then
  begin
    N := GetArrayLength(Dirs);
    SetArrayLength(Dirs, N + 1);
    Dirs[N] := Dir;
  end;
end;

// One question, Yes or No, No by default: remove all the user data? The program and its technical leftovers are always removed.
// A silent uninstall (/SILENT, /VERYSILENT) asks nothing and keeps the data: /SUPPRESSMSGBOXES does not answer a MsgBox of
// this script, so the uninstaller would wait for a click nobody can make.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Dirs: TArrayOfString;
  Where: String;
  Bytes: Int64;
  I: Integer;
begin
  if CurUninstallStep <> usPostUninstall then Exit;
  if UninstallSilent then Exit;
  SetArrayLength(Dirs, 0);
  AddIfExists(Dirs, ExpandConstant('{userappdata}\BSM\B-2FA'));
  if GetArrayLength(Dirs) = 0 then Exit;
  Where := '';
  Bytes := 0;
  for I := 0 to GetArrayLength(Dirs) - 1 do
  begin
    if Where <> '' then Where := Where + #13#10;
    Where := Where + Dirs[I];
    Bytes := Bytes + FolderBytes(Dirs[I]);
  end;
  if MsgBox(FmtMessage(CustomMessage('DataAsk'), ['B-2FA', Where, CustomMessage('DataWhat'), IntToStr(Integer(Bytes div 1048576))]),
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
  begin
    for I := 0 to GetArrayLength(Dirs) - 1 do
      DelTree(Dirs[I], True, True, True);
    RemoveDir(ExpandConstant('{userappdata}\BSM'));       // only when empty
  end;
end;
