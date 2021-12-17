# Detect-Log4Shell
Powershell script to check log files for Log4Shell exploitation

Recursively checks all files in given paths and checks if ${jndi:ldap: among many other indicators of compromise is found in a line

This is a powershell implementation of [https://github.com/Neo23x0/log4shell-detector](https://github.com/Neo23x0/log4shell-detector)

Now using more advanced regex from [https://github.com/back2root/log4shell-rex](https://github.com/back2root/log4shell-rex) to detect exploitation attempts even more exhaustively 

# Usage

# Run
**Warning**: will use C:\ as the default path. It will take a very long time to scan it all through!
```
.\Detect-Log4Shell.ps1 -Paths path-to-log-file-or-directory-with-logs, path-to-second-log-file-or-directory-with-logs
```

## Get help
```
Get-Help .\Detect-Log4Shell.ps1
```
