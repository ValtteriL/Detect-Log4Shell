<#

    .SYNOPSIS
    This is a powershell implementation of https://github.com/Neo23x0/log4shell-detector
    Now using more advanced regex from https://github.com/back2root/log4shell-rex

    .DESCRIPTION
    Recursively checks all files in given paths and checks if ${jndi:ldap: is found in a line
    To detect even obfuscated attacks, we are using special regex from https://github.com/back2root/log4shell-rex
    
    .PARAMETER Paths
    Paths to start recursively scanning for files
    WARNING: By default the path is C:\ - This will take a very long time

    .EXAMPLE
    PS> Detect-Log4Shell -Paths .\test\, .\test2
    [.] Searching for exploitation attempts recursively from .\test\
    [.] Checking items in .\test\
    [.] Checking C:\Users\valtteri\test\dsadsadsa.txt
    [.] Checking C:\Users\valtteri\test\obfu.txt
    [!!] Log4J exploitation attempt found on line 7: ${jndi:dns://addr}
    [.] Checking C:\Users\valtteri\teeest\obfu2.txt
    [!!] Log4J exploitation attempt found on line 28: ${${eh:wDUdos:jKY:-j}${xksV:Xgi:-n}<snip>${FMRAKM:-b}${wiu:vKIVuh:-j}}
    [.] Checking C:\Users\valtteri\teeest\obfu3.txt
    [!!] Log4J exploitation attempt found on line 24: ${jndi:ld${ozI:Kgh:Qn:TXM:-a}<snip>ob${E:yJDsbq:-j}}
    [.] Checking items in .\test2\

#>


param(
    [String[]] $Paths = 'C:\'
)

Write-Output "[.] Searching for exploitation attempts recursively from $Paths"

# string we are looking for: '${jndi:ldap:' with any characters in-between and without case sensitivity
#$matchRegex = '.*\$.*\{.*j.*n.*d.*i.*\:.*l.*d.*a.*p.*\:.*'
$matchRegex = '(?:\$|%(?:25)*24|\\(?:0024|0{0,2}44))(?:{|%(?:25)*7[Bb]|\\(?:007[Bb]|0{0,2}173)).{0,30}?((?:[Jj]|%(?:25)*[46][Aa]|\\(?:00[46][Aa]|0{0,2}1[15]2)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72)).{0,30}?((?:[Ll]|%(?:25)*[46][Cc]|\\(?:00[46][Cc]|0{0,2}1[15]4)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)))?|(?:[Rr]|%(?:25)*[57]2|\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Mm]|%(?:25)*[46][Dd]|\\(?:00[46][Dd]|0{0,2}1[15]5)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı)|(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:.{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı)){2}.{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))|(?:[Cc]|%(?:25)*[46]3|\\(?:00[46]3|0{0,2}1[04]3)).{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Rr]|%(?:25)*[57]2|\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Bb]|%(?:25)*[46]2|\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1))|(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:[Hh]|%(?:25)*[46]8|\\(?:00[46]8|0{0,2}1[15]0))(?:.{0,30}?(?:[Tt]|%(?:25)*[57]4|\\(?:00[57]4|0{0,2}1[26]4))){2}.{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)))?).{0,30}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72)).{0,30}?(?:\/|%(?:25)*2[Ff]|\\(?:002[Ff]|0{0,2}57)|\${)|(?:[Bb]|%(?:25)*[46]2|\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)).{0,30}?(?:[Ee]|%(?:25)*[46]5|\\(?:00[46]5|0{0,2}1[04]5)).{2,60}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72))(JH[s-v]|[\x2b\x2f-9A-Za-z][CSiy]R7|[\x2b\x2f-9A-Za-z]{2}[048AEIMQUYcgkosw]ke[\x2b\x2f-9w-z]))'

# Check all files in paths for the regex
foreach ($path in $Paths) {
    Write-Output "[.] Checking items in $path"
    Get-ChildItem $path -File -Recurse | ForEach-Object {
        Write-Output "[.] Checking $($_.FullName)"
        Get-Content $_.FullName | Select-String -Pattern $matchRegex -AllMatches | ForEach-Object {
            Write-Output "[!!] Log4J exploitation attempt found on line $($_.LineNumber): $($_)"
        }
    }
}
