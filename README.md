# Detect-Log4Shell
Powershell script to check log files for Log4Shell exploitation

Recursively checks all files line-by-line in given paths for substring '${jndi:ldap:', among many other indicators of compromise

This is a powershell implementation of [https://github.com/Neo23x0/log4shell-detector](https://github.com/Neo23x0/log4shell-detector)

Now using more advanced regex from [https://github.com/back2root/log4shell-rex](https://github.com/back2root/log4shell-rex) to detect exploitation attempts even more exhaustively 

# Usage

## Run
By default will scan through all files under 100MB that have been modified since the Log4J vulnerability was disclosed (9/12/2021)

**Warning**: will use C:\ as the default path. It will take a very long time to scan it all through!

Scan files under 100MB:
```
PS> .\Detect-Log4Shell.ps1 -Paths path-to-log-file-or-directory-with-logs
```

Scan files regardless of size:
```
PS> .\Detect-Log4Shell.ps1 -Paths path-to-log-file-or-directory-with-logs -AllSizes
```

## Get help
```
PS> Get-Help .\Detect-Log4Shell.ps1

NAME
    C:\Users\valtteri\Desktop\Detect-Log4Shell.ps1

SYNOPSIS
    This is a powershell implementation of https://github.com/Neo23x0/log4shell-detector
    Now using more advanced regex from https://github.com/back2root/log4shell-rex


SYNTAX
    C:\Users\valtteri\Desktop\Detect-Log4Shell.ps1 [[-Paths] <String[]>] [-AllSizes] [<CommonParameters>]


DESCRIPTION
    Recursively checks all files in given paths and checks if ${jndi:ldap: is found in a line
    
    To detect even obfuscated attacks, we are using special regex from https://github.com/back2root/log4shell-rex

    By default will look for files under 100MB that have been modified since the exploit was disclosed (9/12/2021)


RELATED LINKS

REMARKS
    To see the examples, type: "get-help C:\Users\valtteri\Desktop\Detect-Log4Shell.ps1 -examples".
    For more information, type: "get-help C:\Users\valtteri\Desktop\Detect-Log4Shell.ps1 -detailed".
    For technical information, type: "get-help C:\Users\valtteri\Desktop\Detect-Log4Shell.ps1 -full".

```

# Contributors

Thanks [@ptMuta](https://github.com/ptMuta) :slightly_smiling_face: