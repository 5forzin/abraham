$out = 'C:\Users\Public\vbs-check.txt'
Add-Content $out "hypervisor-present: $((Get-CimInstance Win32_ComputerSystem).HypervisorPresent)"
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
if ($dg) { Add-Content $out "vbs-status: $($dg.VirtualizationBasedSecurityStatus) services: $($dg.SecurityServicesRunning -join ',')" } else { Add-Content $out "vbs-status: <no deviceguard namespace>" }
Add-Content $out "done"
