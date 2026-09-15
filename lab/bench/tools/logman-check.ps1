logman query -ets 2>&1 | Out-File C:\Users\Public\logman-state.txt -Encoding utf8
logman query 2>&1 | Out-File C:\Users\Public\logman-state.txt -Append -Encoding utf8
