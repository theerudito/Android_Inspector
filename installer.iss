#define MyAppName "Android Inspector"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Between Bytes Software"
#define MyAppExeName "android_inspector.exe"
#define ReleaseDir "build\bin"
#define AppIcon "build\windows\icon.ico"

#if !FileExists(AddBackslash(SourcePath) + ReleaseDir + "\" + MyAppExeName)
  #error "The Windows release executable is missing. Run 'wails build -platform windows/amd64' before compiling this installer."
#endif

#if !FileExists(AddBackslash(SourcePath) + AppIcon)
  #error "The installer icon is missing: build\windows\icon.ico"
#endif

[Setup]
AppId={{D87591BF-2D22-4EAA-BA14-FAA01EDCAE57}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}

; Developer / Publisher
AppPublisher={#MyAppPublisher}

; Install in:
; Uses the architecture-appropriate Program Files directory.
//DefaultDirName={autopf}\{#MyAppPublisher}\Android Inspector
DefaultDirName={commonpf32}\{#MyAppPublisher}\Android Inspector

DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

OutputDir=build\installer
OutputBaseFilename=AndroidInspector-Setup-{#MyAppVersion}

SetupIconFile={#AppIcon}
UninstallDisplayIcon={app}\{#MyAppExeName}

Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

VersionInfoVersion=1.0.0.1
VersionInfoProductVersion=1.0.0.1
VersionInfoProductName={#MyAppName}
VersionInfoDescription={#MyAppName} Installer
VersionInfoCompany={#MyAppPublisher}

[Tasks]
Name: "desktopicon"; \
    Description: "Create a &desktop shortcut"; \
    GroupDescription: "Additional shortcuts:"; \
    Flags: unchecked

[Files]
Source: "{#ReleaseDir}\{#MyAppExeName}"; \
     DestDir: "{app}"; \
     Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; \
    Filename: "{app}\{#MyAppExeName}"; \
    WorkingDir: "{app}"

Name: "{autodesktop}\{#MyAppName}"; \
    Filename: "{app}\{#MyAppExeName}"; \
    WorkingDir: "{app}"; \
    Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; \
    Description: "Launch {#MyAppName}"; \
    WorkingDir: "{app}"; \
    Flags: nowait postinstall skipifsilent

[Code]
const
  FirewallTcpRule = 'Android Inspector Wi-Fi pairing (TCP)';
  FirewallUdpRule = 'Android Inspector Wi-Fi pairing (UDP)';
  FirewallMdnsRule = 'Android Inspector mDNS (UDP 5353)';

function RunNetsh(const Params: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\netsh.exe'), Params, '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure DeleteFirewallRules;
begin
  RunNetsh('advfirewall firewall delete rule name="' + FirewallTcpRule + '"');
  RunNetsh('advfirewall firewall delete rule name="' + FirewallUdpRule + '"');
  RunNetsh('advfirewall firewall delete rule name="' + FirewallMdnsRule + '"');
end;

procedure AddFirewallRules;
var
  AppPath: String;
begin
  AppPath := ExpandConstant('{app}\{#MyAppExeName}');
  DeleteFirewallRules;
  RunNetsh('advfirewall firewall add rule name="' + FirewallTcpRule +
    '" dir=in action=allow program="' + AppPath +
    '" enable=yes profile=any protocol=tcp');
  RunNetsh('advfirewall firewall add rule name="' + FirewallUdpRule +
    '" dir=in action=allow program="' + AppPath +
    '" enable=yes profile=any protocol=udp');
  RunNetsh('advfirewall firewall add rule name="' + FirewallMdnsRule +
    '" dir=in action=allow protocol=udp localport=5353 enable=yes profile=any');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    WizardForm.StatusLabel.Caption :=
      'Allowing Wi-Fi pairing through Windows Firewall...';
    AddFirewallRules;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    DeleteFirewallRules;
end;
