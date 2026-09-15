Add-Type -TypeDefinition (Get-Content C:\bench\tools\hwbp-probe.cs -Raw)
[HwbpProbe]::Run() | Out-File C:\Users\Public\hwbp-probe.txt -Encoding ascii
