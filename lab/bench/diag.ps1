$out = 'C:\Users\Public\diag-out.txt'
Set-Content -Path $out -Value "whoami: $(whoami)"
Add-Content $out "elevated-admin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Add-Content $out "ps-version: $($PSVersionTable.PSVersion)"
$null = New-Item -ItemType Directory -Force -Path 'C:\bench\tools'
Add-Content $out "bench-dir: $(Test-Path 'C:\bench\tools')"
cmd /c 'dir C:\Users\lab' 2>&1 | Select-Object -First 4 | ForEach-Object { Add-Content $out "dir: $_" }
Add-Content $out "sysmon-log: $(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Winevt\Channels\Microsoft-Windows-Sysmon/Operational')"
Add-Content $out "mp-cmdlet: $([bool](Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue))"
Add-Content $out "csc: $(Test-Path (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'))"
Add-Content $out "diag-complete"
