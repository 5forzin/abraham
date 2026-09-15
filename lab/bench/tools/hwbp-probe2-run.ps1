try {
  Add-Type -TypeDefinition (Get-Content C:\bench\tools\hwbp-probe2.cs -Raw) -ErrorAction Stop
  [HwbpProbe2]::Run() | Out-File C:\bench\tools\hwbp-probe2.txt -Encoding ascii
} catch {
  $_ | Out-String | Out-File C:\bench\tools\hwbp-probe2-err.txt -Encoding ascii
}
