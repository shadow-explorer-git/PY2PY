[Setup]
AppId={{B5186DB5-74E8-4D14-9E48-26A3B20476F2}
AppName=PY2PY
AppVersion=0.1.0
AppPublisher=shadow-explorer
DefaultDirName={autopf}\PY2PY
DefaultGroupName=PY2PY
DisableProgramGroupPage=yes
PrivilegesRequired=admin
SetupIconFile=assets\final.ico
UninstallDisplayIcon={app}\assets\final.ico
OutputDir=installer
OutputBaseFilename=PY2PY-Setup
WizardStyle=modern

[Files]
Source: "dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "assets\final.ico"; DestDir: "{app}\assets"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\PY2PY"; Filename: "{app}\PY2PY.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\final.ico"

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""PY2PY TCP"""; Flags: runhidden waituntilterminated; RunOnceId: "DeletePY2PYTCPFirewallRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""PY2PY UDP (Discovery)"""; Flags: runhidden waituntilterminated; RunOnceId: "DeletePY2PYUDPFirewallRule"
