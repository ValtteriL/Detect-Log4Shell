# Detect-Log4Shell
Powershell script to check log files for Log4Shell exploitation

Recursively checks all files in given paths and checks if ${jndi:ldap: among many other indicators of compromise is found in a line

This is a powershell implementation of [https://github.com/Neo23x0/log4shell-detector](https://github.com/Neo23x0/log4shell-detector)
Now using more advanced regex from [https://github.com/back2root/log4shell-rex](https://github.com/back2root/log4shell-rex) to detect exploitation attempts even more exhaustively 

# Usage
# Import the script and run
```
. .\Detect-Log4Shell.ps1
Detect-Log4Shell -Paths path-to-log-file-or-directory-with-logs, path-to-second-log-file-or-directory-with-logs
```

## Help
`Get-Help Detect-Log4Shell`
