$out = 'C:\Users\Public\cand-check.txt'
Set-Content $out "candidates:"
foreach ($dll in @('colorui.dll','dbgcore.dll','devobj.dll','dhcpcmonitor.dll','dbgeng.dll','framedyn.dll','mshtmled.dll','shsetup.dll')) {
  $p = "C:\Windows\System32\$dll"
  if (Test-Path $p) {
    $len = (Get-Item $p).Length
    Add-Content $out ("{0}: exists, {1} bytes" -f $dll, $len)
  } else {
    Add-Content $out ("{0}: MISSING" -f $dll)
  }
}
